"""Feature engineering pipeline for fraud detection."""
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from pydantic import BaseModel


class RawLoginEvent(BaseModel):
    """Raw login event from the fraud engine."""
    user_id: str
    ip: str
    timestamp: datetime
    device_id: str
    user_agent: str
    timezone: str
    language: str
    carrier_mcc: Optional[str] = None
    carrier_mnc: Optional[str] = None
    gps_lat: Optional[float] = None
    gps_lng: Optional[float] = None

    # GeoIP data
    country: str
    city: str
    latitude: float
    longitude: float
    asn: int
    isp: str
    is_vpn: bool
    is_proxy: bool
    is_tor: bool

    # Previous login data
    prev_login_ip: Optional[str] = None
    prev_login_lat: Optional[float] = None
    prev_login_lng: Optional[float] = None
    prev_login_time: Optional[datetime] = None

    # Detection signals
    latency_mismatch: bool
    webrtc_leak: bool
    carrier_mismatch: bool

    # Label (for training)
    is_fraud: Optional[int] = None


class FeatureEngineer:
    """Engineers features from raw login events for ML models."""

    def __init__(self, config):
        self.config = config

    def engineer_features(self, event: RawLoginEvent) -> pd.DataFrame:
        """Convert a single login event into a feature vector."""
        features = {}

        # === IP REPUTATION FEATURES ===
        features["ip_is_vpn"] = int(event.is_vpn)
        features["ip_is_proxy"] = int(event.is_proxy)
        features["ip_is_tor"] = int(event.is_tor)
        features["ip_any_anonymous"] = int(event.is_vpn or event.is_proxy or event.is_tor)

        # === GEOGRAPHIC FEATURES ===
        features["geo_latitude"] = event.latitude
        features["geo_longitude"] = event.longitude
        features["geo_is_nigeria"] = int(event.country == "NG")
        features["geo_is_known_city"] = int(event.city.lower() in {
            "lagos", "abuja", "kano", "ibadan", "port harcourt", 
            "kaduna", "benin city", "maiduguri", "zaria", "owerri"
        })

        # ASN features
        features["asn_is_nigerian"] = int(event.asn in self.config.nigerian_asns)
        features["asn_mismatch"] = int(event.country == "NG" and event.asn not in self.config.nigerian_asns)

        # === VELOCITY & IMPOSSIBLE TRAVEL ===
        features["has_prev_login"] = int(event.prev_login_time is not None)

        if event.prev_login_time and event.prev_login_lat is not None:
            distance_km = self._haversine(
                event.prev_login_lat, event.prev_login_lng or 0,
                event.latitude, event.longitude
            )
            time_diff_hours = (event.timestamp - event.prev_login_time).total_seconds() / 3600

            features["geo_distance_km"] = distance_km
            features["time_since_last_login_hours"] = time_diff_hours

            if time_diff_hours > 0:
                speed_kmh = distance_km / time_diff_hours
                features["travel_speed_kmh"] = speed_kmh
                features["impossible_travel"] = int(speed_kmh > 900)
            else:
                features["travel_speed_kmh"] = 0
                features["impossible_travel"] = 0
        else:
            features["geo_distance_km"] = 0
            features["time_since_last_login_hours"] = -1
            features["travel_speed_kmh"] = 0
            features["impossible_travel"] = 0

        # === DEVICE & BEHAVIORAL FEATURES ===
        features["device_id_hash"] = self._hash_device(event.device_id)
        features["user_agent_length"] = len(event.user_agent)
        features["user_agent_has_mobile"] = int("mobile" in event.user_agent.lower())

        # Time-based features
        features["hour_of_day"] = event.timestamp.hour
        features["day_of_week"] = event.timestamp.weekday()
        features["is_weekend"] = int(event.timestamp.weekday() >= 5)
        features["is_night_time"] = int(event.timestamp.hour < 6 or event.timestamp.hour > 23)

        # Timezone mismatch
        features["timezone_is_nigeria"] = int(event.timezone == self.config.nigerian_timezone)
        features["timezone_mismatch"] = int(
            event.country == "NG" and event.timezone != self.config.nigerian_timezone
        )

        # Language features
        features["language_is_english"] = int("en" in event.language.lower())
        features["language_is_hausa"] = int("ha" in event.language.lower())
        features["language_is_yoruba"] = int("yo" in event.language.lower())
        features["language_is_igbo"] = int("ig" in event.language.lower())

        # === MOBILE NETWORK FEATURES ===
        features["has_carrier_data"] = int(event.carrier_mcc is not None)
        features["carrier_is_nigerian"] = int(event.carrier_mcc == self.config.nigerian_mcc)
        features["carrier_mismatch"] = int(event.carrier_mismatch)

        # === TECHNICAL DETECTION FEATURES ===
        features["latency_mismatch"] = int(event.latency_mismatch)
        features["webrtc_leak"] = int(event.webrtc_leak)
        features["technical_red_flags"] = (
            int(event.latency_mismatch) + int(event.webrtc_leak) + 
            int(event.carrier_mismatch)
        )

        # === GPS FEATURES (if available) ===
        features["has_gps"] = int(event.gps_lat is not None)
        if event.gps_lat is not None:
            features["gps_lat"] = event.gps_lat
            features["gps_lng"] = event.gps_lng
            gps_distance = self._haversine(
                event.gps_lat, event.gps_lng,
                event.latitude, event.longitude
            )
            features["gps_ip_distance_km"] = gps_distance
            features["gps_spoofing"] = int(gps_distance > 100)
        else:
            features["gps_lat"] = 0
            features["gps_lng"] = 0
            features["gps_ip_distance_km"] = 0
            features["gps_spoofing"] = 0

        # === AGGREGATE RISK SCORES ===
        features["detection_score_sum"] = (
            features["ip_any_anonymous"] * 25 +
            features["asn_mismatch"] * 15 +
            features["impossible_travel"] * 25 +
            features["timezone_mismatch"] * 10 +
            features["carrier_mismatch"] * 10 +
            features["latency_mismatch"] * 15 +
            features["webrtc_leak"] * 15
        )

        return pd.DataFrame([features])

    def engineer_batch(self, events: List[RawLoginEvent]) -> pd.DataFrame:
        """Engineer features for a batch of events."""
        dfs = [self.engineer_features(e) for e in events]
        return pd.concat(dfs, ignore_index=True)

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km."""
        R = 6371
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)

        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c

    @staticmethod
    def _hash_device(device_id: str) -> int:
        """Simple hash for device ID."""
        return hash(device_id) % 10000
