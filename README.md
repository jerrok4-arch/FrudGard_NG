<div align="center">

# 🛡️ FraudGuard NG

**Real-time Fraud Detection for Nigerian Financial Systems**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)

</div>

---

## 🎯 What is FraudGuard NG?

FraudGuard NG is a production-ready, open-source fraud detection system designed specifically for **Nigerian banks and fintechs**. It detects malicious login attempts, VPN/proxy usage, impossible travel, and behavioral anomalies in real-time.

Built for the Nigerian financial ecosystem — integrated with **NIBSS**, **CBN reporting**, and **Nigerian mobile carriers** (MTN, Airtel, Glo, 9mobile).

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Go Engine   │────▶│   Kafka      │────▶│  ML Server  │
│ (Rule-based) │     │ login.events │     │(ML Models)  │
└─────────────┘     └──────────────┘     └─────────────┘
       │                                        │
       ▼                                        ▼
┌─────────────┐                          ┌─────────────┐
│   Redis     │                          │ ClickHouse  │
│  (Cache)    │                          │(Analytics)  │
└─────────────┘                          └─────────────┘
```

| Component | Tech | Purpose |
|-----------|------|---------|
| **Fraud Engine** | Go 1.22 | Real-time rule-based detection (P99 < 50ms) |
| **ML Inference** | Python 3.11 + XGBoost | Deep pattern detection & anomaly scoring |
| **Event Bus** | Apache Kafka | Async communication between services |
| **Cache** | Redis | Session store, rate limiting, feature cache |
| **Analytics** | ClickHouse | OLAP fraud analytics & dashboards |
| **Monitoring** | Prometheus + Grafana | Metrics, alerts, observability |

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Git
- MaxMind GeoIP2 database (free registration)
- (Optional) IPQualityScore & AbuseIPDB API keys

### 1. Clone & Setup

```bash
git clone https://github.com/YOUR_USERNAME/fraudguard-ng.git
cd fraudguard-ng

# Copy environment template
cp .env.example .env
# Edit .env with your API keys
```

### 2. Download MaxMind Database

```bash
mkdir -p data
# Download GeoIP2-City.mmdb from https://www.maxmind.com/
# Place it in: ./data/GeoIP2-City.mmdb
```

### 3. Start All Services

```bash
docker-compose up -d

# Verify everything is running
docker-compose ps
```

### 4. Test the API

```bash
# Test Go fraud engine
curl -X POST http://localhost:8080/api/v1/assess \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-123",
    "ip": "102.89.47.12",
    "device_id": "abc123",
    "timezone": "Africa/Lagos",
    "language": "en-NG",
    "carrier_mcc": "621"
  }'

# Test ML inference
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-123",
    "ip": "185.220.101.44",
    "device_id": "abc123",
    "country": "RU",
    "is_vpn": true,
    "latency_mismatch": true
  }'
```

## 🔍 Detection Layers

| Layer | Method | Catches |
|-------|--------|---------|
| **1. IP Intelligence** | MaxMind + IPQualityScore + AbuseIPDB | Known VPNs, proxies, TOR, malicious IPs |
| **2. Latency Triangulation** | RTT to Lagos/Abuja/London/Amsterdam edge nodes | VPNs with Nigerian exit nodes |
| **3. WebRTC Leak** | Browser STUN requests | Consumer VPNs (NordVPN, ExpressVPN) |
| **4. Mobile Network** | MCC/MNC carrier codes | Nigerian carrier + foreign IP mismatch |
| **5. Behavioral** | Impossible travel, timezone, language | Sophisticated account takeovers |
| **6. ML Ensemble** | XGBoost + Isolation Forest | Novel attack patterns, residential proxies |

## 🇳🇬 Nigeria-Specific Features

- **BVN (Bank Verification Number)** validation via NIBSS API
- **NIN (National Identification Number)** verification
- **MCC 621** detection for Nigerian mobile carriers
- **Known Nigerian ASNs:** MTN (29465), Airtel (37148), Glo (37282), 9mobile (328309)
- **CBN compliance** reporting pipeline
- **NITDA** cybersecurity alert integration

## 📁 Project Structure

```
fraudguard-ng/
├── go-service/           # Go fraud detection engine
│   ├── main.go
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
├── ml-service/           # Python ML pipeline
│   ├── inference_server.py
│   ├── model.py
│   ├── features.py
│   ├── train.py
│   ├── data_loader.py
│   ├── config.py
│   ├── Dockerfile
│   └── requirements.txt
├── infra/                # Infrastructure as Code
│   └── terraform/
├── docs/                 # Documentation
├── docker-compose.yml    # Local development stack
├── .env.example          # Environment template
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## 🧠 ML Model Training

```bash
# Enter ML service
cd ml-service

# Install dependencies
pip install -r requirements.txt

# Train on historical data (from ClickHouse)
python train.py --days 90

# Models are saved to ./models/
# - xgboost_fraud.json
# - isolation_forest.pkl
# - scaler.pkl
```

## 📊 Monitoring

Access Grafana at `http://localhost:3000` (admin/admin)

Pre-configured dashboards:
- **Fraud Detection Overview** — blocked logins, risk distribution, top threats
- **System Health** — API latency, throughput, error rates
- **ML Model Performance** — prediction accuracy, drift detection

## 🔐 Security

- **TLS 1.3** for all communications
- **AES-256** encryption at rest
- **Field-level encryption** for PII
- **CBN Cybersecurity Framework** compliant
- **NDPR (Nigeria Data Protection Regulation)** compliant

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

MIT License — see [LICENSE](LICENSE)

## 🙏 Acknowledgments

- Built for the Nigerian financial technology community
- Inspired by CBN cybersecurity directives and NDPR
- MaxMind GeoIP2 for geolocation data
