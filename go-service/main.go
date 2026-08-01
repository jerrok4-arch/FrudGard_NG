package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/oschwald/geoip2-golang"
)

// ============================================================
// CONFIGURATION
// ============================================================

type Config struct {
	MaxMindDBPath     string        `json:"maxmind_db_path"`
	RedisAddr         string        `json:"redis_addr"`
	EdgeNodes         []EdgeNode    `json:"edge_nodes"`
	Thresholds        Thresholds    `json:"thresholds"`
	IPQualityScoreKey string        `json:"ipqualityscore_key"`
	AbuseIPDBKey      string        `json:"abuseipdb_key"`
	NigerianASNs      []int         `json:"nigerian_asns"`
	ServerPort        string        `json:"server_port"`
	KafkaBrokers      string        `json:"kafka_brokers"`
}

type EdgeNode struct {
	Name        string        `json:"name"`
	Location    string        `json:"location"`
	Host        string        `json:"host"`
	ExpectedRTT time.Duration `json:"expected_rtt_ms"`
}

type Thresholds struct {
	AllowMax     int           `json:"allow_max"`
	ChallengeMin int           `json:"challenge_min"`
	BlockMin     int           `json:"block_min"`
	LatencyDelta time.Duration `json:"latency_delta_ms"`
}

// ============================================================
// DATA MODELS
// ============================================================

type LoginRequest struct {
	UserID          string    `json:"user_id"`
	Email           string    `json:"email"`
	IP              string    `json:"ip"`
	DeviceID        string    `json:"device_id"`
	UserAgent       string    `json:"user_agent"`
	Timezone        string    `json:"timezone"`
	Language        string    `json:"language"`
	CarrierMCC      string    `json:"carrier_mcc"`
	CarrierMNC      string    `json:"carrier_mnc"`
	WebRTCIP        string    `json:"webrtc_ip"`
	LocalIP         string    `json:"local_ip"`
	GPSLat          float64   `json:"gps_lat"`
	GPSLng          float64   `json:"gps_lng"`
	PreviousLoginIP string    `json:"previous_login_ip"`
	PreviousLoginAt time.Time `json:"previous_login_at"`
}

type RiskAssessment struct {
	UserID         string            `json:"user_id"`
	IP             string            `json:"ip"`
	TotalScore     int               `json:"total_score"`
	Decision       string            `json:"decision"`
	Confidence     float64           `json:"confidence"`
	Detections     []DetectionResult `json:"detections"`
	GeoLocation    *GeoResult        `json:"geo_location"`
	LatencyResults []LatencyResult   `json:"latency_results"`
	Timestamp      time.Time         `json:"timestamp"`
}

type DetectionResult struct {
	Layer      string  `json:"layer"`
	Signal     string  `json:"signal"`
	Score      int     `json:"score"`
	Details    string  `json:"details"`
	Confidence float64 `json:"confidence"`
}

type GeoResult struct {
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         int     `json:"asn"`
	ISP         string  `json:"isp"`
	IsAnonymous bool    `json:"is_anonymous"`
	IsVPN       bool    `json:"is_vpn"`
	IsProxy     bool    `json:"is_proxy"`
	IsTOR       bool    `json:"is_tor"`
}

type LatencyResult struct {
	NodeName     string        `json:"node_name"`
	NodeLocation string        `json:"node_location"`
	RTT          time.Duration `json:"rtt_ms"`
	ExpectedRTT  time.Duration `json:"expected_rtt_ms"`
	Delta        time.Duration `json:"delta_ms"`
	Suspicious   bool          `json:"suspicious"`
}

// ============================================================
// FRAUD ENGINE
// ============================================================

type FraudEngine struct {
	config      *Config
	geoDB       *geoip2.Reader
	redisClient *redis.Client
	httpClient  *http.Client
	mu          sync.RWMutex
}

func NewFraudEngine(cfg *Config) (*FraudEngine, error) {
	db, err := geoip2.Open(cfg.MaxMindDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind DB: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: "",
		DB:       0,
	})

	return &FraudEngine{
		config:      cfg,
		geoDB:       db,
		redisClient: rdb,
		httpClient:  &http.Client{Timeout: 3 * time.Second},
	}, nil
}

func (fe *FraudEngine) Close() {
	fe.geoDB.Close()
	fe.redisClient.Close()
}

// --- Layer 1: IP Intelligence ---

func (fe *FraudEngine) lookupGeoIP(ipStr string) (*GeoResult, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	result := &GeoResult{}

	city, err := fe.geoDB.City(ip)
	if err == nil && city != nil {
		result.Country = city.Country.IsoCode
		result.City = city.City.Names["en"]
		result.Latitude = city.Location.Latitude
		result.Longitude = city.Location.Longitude
	}

	anon, err := fe.geoDB.AnonymousIP(ip)
	if err == nil && anon != nil {
		result.IsAnonymous = anon.IsAnonymous
		result.IsVPN = anon.IsVPN
		result.IsProxy = anon.IsProxy
		result.IsTOR = anon.IsTorExitNode
	}

	asn, err := fe.geoDB.ASN(ip)
	if err == nil && asn != nil {
		result.ASN = int(asn.AutonomousSystemNumber)
		result.ISP = asn.AutonomousSystemOrganization
	}

	return result, nil
}

func (fe *FraudEngine) checkIPQualityScore(ipStr string) (int, bool, error) {
	if fe.config.IPQualityScoreKey == "" {
		return 0, false, nil
	}

	cacheKey := fmt.Sprintf("ipqs:%s", ipStr)
	cached, err := fe.redisClient.Get(context.Background(), cacheKey).Result()
	if err == nil {
		var score int
		fmt.Sscanf(cached, "%d", &score)
		return score, score > 80, nil
	}

	url := fmt.Sprintf(
		"https://ipqualityscore.com/api/json/ip/%s/%s?strictness=1&allow_public_access_points=false",
		fe.config.IPQualityScoreKey, ipStr)

	resp, err := fe.httpClient.Get(url)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	var result struct {
		FraudScore int  `json:"fraud_score"`
		VPN        bool `json:"vpn"`
		Proxy      bool `json:"proxy"`
		TOR        bool `json:"tor"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, false, err
	}

	fe.redisClient.Set(context.Background(), cacheKey, result.FraudScore, time.Hour)
	return result.FraudScore, result.FraudScore > 80, nil
}

func (fe *FraudEngine) checkAbuseIPDB(ipStr string) (bool, error) {
	if fe.config.AbuseIPDBKey == "" {
		return false, nil
	}

	cacheKey := fmt.Sprintf("abuseipdb:%s", ipStr)
	cached, err := fe.redisClient.Get(context.Background(), cacheKey).Result()
	if err == nil {
		return cached == "1", nil
	}

	req, _ := http.NewRequest("GET", "https://api.abuseipdb.com/api/v2/check", nil)
	q := req.URL.Query()
	q.Add("ipAddress", ipStr)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Key", fe.config.AbuseIPDBKey)
	req.Header.Add("Accept", "application/json")

	resp, err := fe.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	isMalicious := result.Data.AbuseConfidenceScore > 50
	cacheVal := "0"
	if isMalicious {
		cacheVal = "1"
	}
	fe.redisClient.Set(context.Background(), cacheKey, cacheVal, time.Hour)
	return isMalicious, nil
}

func (fe *FraudEngine) isNigerianASN(asn int) bool {
	for _, n := range fe.config.NigerianASNs {
		if n == asn {
			return true
		}
	}
	return false
}

// --- Layer 2: Latency Triangulation ---

func (fe *FraudEngine) measureLatency(ipStr string) []LatencyResult {
	var results []LatencyResult
	var wg sync.WaitGroup
	resultChan := make(chan LatencyResult, len(fe.config.EdgeNodes))

	for _, node := range fe.config.EdgeNodes {
		wg.Add(1)
		go func(n EdgeNode) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", n.Host+":80", 2*time.Second)
			if err != nil {
				resultChan <- LatencyResult{
					NodeName: n.Name, NodeLocation: n.Location,
					RTT: 0, ExpectedRTT: n.ExpectedRTT, Delta: 0, Suspicious: false,
				}
				return
			}
			defer conn.Close()
			rtt := time.Since(start)
			delta := rtt - n.ExpectedRTT
			if delta < 0 {
				delta = -delta
			}
			resultChan <- LatencyResult{
				NodeName: n.Name, NodeLocation: n.Location,
				RTT: rtt, ExpectedRTT: n.ExpectedRTT, Delta: delta,
				Suspicious: delta > fe.config.Thresholds.LatencyDelta,
			}
		}(node)
	}

	wg.Wait()
	close(resultChan)

	for r := range resultChan {
		results = append(results, r)
	}
	return results
}

// --- Layer 3: WebRTC Leak ---

func (fe *FraudEngine) detectWebRTCLeak(req *LoginRequest) (bool, string) {
	if req.WebRTCIP == "" {
		return false, "No WebRTC data provided"
	}
	if req.WebRTCIP != req.IP && req.WebRTCIP != "" {
		return true, fmt.Sprintf("WebRTC IP (%s) differs from request IP (%s)", req.WebRTCIP, req.IP)
	}
	if strings.HasPrefix(req.LocalIP, "10.") || strings.HasPrefix(req.LocalIP, "172.16.") {
		return true, fmt.Sprintf("Local IP (%s) suggests VPN tunnel", req.LocalIP)
	}
	return false, "No leak detected"
}

// --- Layer 4: Mobile Network ---

func (fe *FraudEngine) checkMobileMismatch(req *LoginRequest, geo *GeoResult) (bool, string) {
	if req.CarrierMCC == "" {
		return false, "No carrier data"
	}
	if req.CarrierMCC == "621" {
		if geo != nil && geo.Country != "NG" && geo.Country != "" {
			return true, fmt.Sprintf("Nigerian carrier (MCC=%s) but IP geolocates to %s", req.CarrierMCC, geo.Country)
		}
	}
	return false, "Carrier consistent with geo"
}

// --- Layer 5: Behavioral ---

func (fe *FraudEngine) checkBehavioralAnomalies(req *LoginRequest, geo *GeoResult) []DetectionResult {
	var detections []DetectionResult

	if req.Timezone != "" && geo != nil {
		expectedTZ := getTimezoneForCountry(geo.Country)
		if expectedTZ != "" && req.Timezone != expectedTZ && req.Timezone != "Africa/Lagos" {
			detections = append(detections, DetectionResult{
				Layer: "Behavioral", Signal: "Timezone Mismatch", Score: 10,
				Details: fmt.Sprintf("Client TZ: %s, Expected: %s", req.Timezone, expectedTZ),
				Confidence: 0.85,
			})
		}
	}

	if req.Language != "" && geo != nil {
		if geo.Country == "NG" && !strings.Contains(req.Language, "en") &&
			!strings.Contains(req.Language, "ha") &&
			!strings.Contains(req.Language, "yo") &&
			!strings.Contains(req.Language, "ig") {
			detections = append(detections, DetectionResult{
				Layer: "Behavioral", Signal: "Language Mismatch", Score: 5,
				Details: fmt.Sprintf("Client lang: %s, Expected: en/ha/yo/ig for Nigeria", req.Language),
				Confidence: 0.70,
			})
		}
	}

	if req.PreviousLoginIP != "" && !req.PreviousLoginAt.IsZero() {
		prevGeo, _ := fe.lookupGeoIP(req.PreviousLoginIP)
		if prevGeo != nil && geo != nil {
			distance := haversine(prevGeo.Latitude, prevGeo.Longitude, geo.Latitude, geo.Longitude)
			timeDelta := time.Since(req.PreviousLoginAt).Hours()
			if timeDelta > 0 {
				speed := distance / timeDelta
				if speed > 900 {
					detections = append(detections, DetectionResult{
						Layer: "Behavioral", Signal: "Impossible Travel", Score: 25,
						Details: fmt.Sprintf("%.0f km in %.1f hours = %.0f km/h", distance, timeDelta, speed),
						Confidence: 0.95,
					})
				}
			}
		}
	}

	return detections
}

func getTimezoneForCountry(code string) string {
	m := map[string]string{"NG": "Africa/Lagos", "GB": "Europe/London", "US": "America/New_York", "RU": "Europe/Moscow", "CN": "Asia/Shanghai"}
	return m[code]
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371
	phi1 := lat1 * math.Pi / 180
	phi2 := lat2 * math.Pi / 180
	dphi := (lat2 - lat1) * math.Pi / 180
	dlambda := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dphi/2)*math.Sin(dphi/2) + math.Cos(phi1)*math.Cos(phi2)*math.Sin(dlambda/2)*math.Sin(dlambda/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

// ============================================================
// MAIN ASSESSMENT
// ============================================================

func (fe *FraudEngine) AssessRisk(req *LoginRequest) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		UserID: req.UserID, IP: req.IP,
		Timestamp: time.Now().UTC(), Detections: []DetectionResult{},
	}

	// Layer 1
	geo, err := fe.lookupGeoIP(req.IP)
	if err != nil {
		log.Printf("GeoIP lookup failed for %s: %v", req.IP, err)
	}
	assessment.GeoLocation = geo

	if geo != nil {
		if geo.IsVPN {
			assessment.Detections = append(assessment.Detections, DetectionResult{
				Layer: "IP Intelligence", Signal: "MaxMind VPN Flag", Score: 25,
				Details: fmt.Sprintf("IP %s flagged as VPN by MaxMind", req.IP), Confidence: 0.95,
			})
		}
		if geo.IsProxy {
			assessment.Detections = append(assessment.Detections, DetectionResult{
				Layer: "IP Intelligence", Signal: "MaxMind Proxy Flag", Score: 20,
				Details: fmt.Sprintf("IP %s flagged as proxy by MaxMind", req.IP), Confidence: 0.90,
			})
		}
		if geo.IsTOR {
			assessment.Detections = append(assessment.Detections, DetectionResult{
				Layer: "IP Intelligence", Signal: "MaxMind TOR Flag", Score: 30,
				Details: fmt.Sprintf("IP %s is a TOR exit node", req.IP), Confidence: 0.98,
			})
		}
		if geo.Country == "NG" && !fe.isNigerianASN(geo.ASN) && geo.ASN != 0 {
			assessment.Detections = append(assessment.Detections, DetectionResult{
				Layer: "IP Intelligence", Signal: "ASN Mismatch", Score: 15,
				Details: fmt.Sprintf("IP claims Nigeria but ASN %d (%s) is not a known Nigerian ISP", geo.ASN, geo.ISP),
				Confidence: 0.80,
			})
		}
	}

	ipqsScore, ipqsFlag, err := fe.checkIPQualityScore(req.IP)
	if err != nil {
		log.Printf("IPQualityScore check failed: %v", err)
	}
	if ipqsFlag {
		assessment.Detections = append(assessment.Detections, DetectionResult{
			Layer: "IP Intelligence", Signal: "IPQualityScore High Risk", Score: 20,
			Details: fmt.Sprintf("Fraud score: %d/100", ipqsScore), Confidence: float64(ipqsScore) / 100.0,
		})
	}

	abuseFlag, err := fe.checkAbuseIPDB(req.IP)
	if err != nil {
		log.Printf("AbuseIPDB check failed: %v", err)
	}
	if abuseFlag {
		assessment.Detections = append(assessment.Detections, DetectionResult{
			Layer: "IP Intelligence", Signal: "AbuseIPDB Reported", Score: 15,
			Details: "IP reported as malicious in last 90 days", Confidence: 0.85,
		})
	}

	// Layer 2
	latencyResults := fe.measureLatency(req.IP)
	assessment.LatencyResults = latencyResults
	for _, lr := range latencyResults {
		if lr.Suspicious {
			assessment.Detections = append(assessment.Detections, DetectionResult{
				Layer: "Latency Triangulation", Signal: fmt.Sprintf("RTT Mismatch (%s)", lr.NodeName), Score: 15,
				Details: fmt.Sprintf("Expected %v, got %v (delta: %v)", lr.ExpectedRTT, lr.RTT, lr.Delta), Confidence: 0.80,
			})
			break
		}
	}

	// Layer 3
	webrtcLeak, webrtcDetails := fe.detectWebRTCLeak(req)
	if webrtcLeak {
		assessment.Detections = append(assessment.Detections, DetectionResult{
			Layer: "WebRTC Leak", Signal: "IP Leak Detected", Score: 15,
			Details: webrtcDetails, Confidence: 0.90,
		})
	}

	// Layer 4
	mobileMismatch, mobileDetails := fe.checkMobileMismatch(req, geo)
	if mobileMismatch {
		assessment.Detections = append(assessment.Detections, DetectionResult{
			Layer: "Mobile Network", Signal: "Carrier Mismatch", Score: 10,
			Details: mobileDetails, Confidence: 0.85,
		})
	}

	// Layer 5
	behavioral := fe.checkBehavioralAnomalies(req, geo)
	assessment.Detections = append(assessment.Detections, behavioral...)

	// Score & Decision
	totalScore := 0
	for _, d := range assessment.Detections {
		totalScore += d.Score
	}
	if totalScore > 100 {
		totalScore = 100
	}
	assessment.TotalScore = totalScore

	switch {
	case totalScore >= fe.config.Thresholds.BlockMin:
		assessment.Decision = "BLOCK"
	case totalScore >= fe.config.Thresholds.ChallengeMin:
		assessment.Decision = "CHALLENGE"
	default:
		assessment.Decision = "ALLOW"
	}

	if len(assessment.Detections) > 0 {
		var weightedSum float64
		var totalWeight int
		for _, d := range assessment.Detections {
			weightedSum += d.Confidence * float64(d.Score)
			totalWeight += d.Score
		}
		if totalWeight > 0 {
			assessment.Confidence = weightedSum / float64(totalWeight)
		}
	}

	assessmentJSON, _ := json.Marshal(assessment)
	fe.redisClient.Set(context.Background(),
		fmt.Sprintf("risk:%s:%d", req.UserID, time.Now().Unix()),
		assessmentJSON, 24*time.Hour)

	return assessment, nil
}

// ============================================================
// HTTP HANDLERS
// ============================================================

func (fe *FraudEngine) handleAssess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var req LoginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		req.IP = getClientIP(r)
	}
	assessment, err := fe.AssessRisk(&req)
	if err != nil {
		http.Error(w, "Assessment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assessment)
}

func (fe *FraudEngine) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy", "timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	xri := r.Header.Get("X-Real-Ip")
	if xri != "" {
		return xri
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ============================================================
// MAIN
// ============================================================

func main() {
	latencyDelta, _ := strconv.Atoi(os.Getenv("LATENCY_DELTA_MS"))
	if latencyDelta == 0 {
		latencyDelta = 50
	}

	config := &Config{
		MaxMindDBPath:     getEnv("MAXMIND_DB_PATH", "./GeoIP2-City.mmdb"),
		RedisAddr:         getEnv("REDIS_ADDR", "localhost:6379"),
		IPQualityScoreKey: os.Getenv("IPQUALITYSCORE_KEY"),
		AbuseIPDBKey:      os.Getenv("ABUSEIPDB_KEY"),
		ServerPort:        getEnv("SERVER_PORT", ":8080"),
		KafkaBrokers:      os.Getenv("KAFKA_BROKERS"),
		EdgeNodes: []EdgeNode{
			{Name: "lagos-1", Location: "Lagos, NG", Host: "lagos-edge.fraudguard.ng", ExpectedRTT: 15 * time.Millisecond},
			{Name: "abuja-1", Location: "Abuja, NG", Host: "abuja-edge.fraudguard.ng", ExpectedRTT: 25 * time.Millisecond},
			{Name: "london-1", Location: "London, UK", Host: "london-edge.fraudguard.ng", ExpectedRTT: 140 * time.Millisecond},
			{Name: "amsterdam-1", Location: "Amsterdam, NL", Host: "ams-edge.fraudguard.ng", ExpectedRTT: 150 * time.Millisecond},
		},
		Thresholds: Thresholds{
			AllowMax:     29,
			ChallengeMin: 30,
			BlockMin:     70,
			LatencyDelta: time.Duration(latencyDelta) * time.Millisecond,
		},
		NigerianASNs: []int{29465, 37148, 37282, 328309, 328414},
	}

	engine, err := NewFraudEngine(config)
	if err != nil {
		log.Fatalf("Failed to initialize fraud engine: %v", err)
	}
	defer engine.Close()

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/assess", engine.handleAssess).Methods("POST")
	router.HandleFunc("/health", engine.handleHealth).Methods("GET")

	log.Printf("🛡️ FraudGuard NG starting on %s", config.ServerPort)
	log.Printf("📡 Edge nodes: %d", len(config.EdgeNodes))

	server := &http.Server{
		Addr:         config.ServerPort,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
