"""Data loading from ClickHouse for model training."""
import logging
from datetime import datetime, timedelta
from typing import List

import clickhouse_connect
import pandas as pd

from config import ModelConfig
from features import RawLoginEvent

logger = logging.getLogger(__name__)


class ClickHouseDataLoader:
    """Loads historical login data from ClickHouse for training."""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.client = clickhouse_connect.get_client(
            host=config.clickhouse_host,
            port=config.clickhouse_port,
            database=config.clickhouse_db,
        )

    def load_training_data(self, days: int = 90) -> List[RawLoginEvent]:
        """Load labeled login events from the past N days.

        Labels:
            - is_fraud = 1: Confirmed fraud (blocked + user reported)
            - is_fraud = 0: Confirmed legitimate (user verified via MFA)
        """
        since = datetime.utcnow() - timedelta(days=days)

        query = f"""
        SELECT 
            user_id,
            ip,
            timestamp,
            device_id,
            user_agent,
            timezone,
            language,
            carrier_mcc,
            carrier_mnc,
            gps_lat,
            gps_lng,
            country,
            city,
            latitude,
            longitude,
            asn,
            isp,
            is_vpn,
            is_proxy,
            is_tor,
            prev_login_ip,
            prev_login_lat,
            prev_login_lng,
            prev_login_time,
            latency_mismatch,
            webrtc_leak,
            carrier_mismatch,
            is_fraud
        FROM login_events
        WHERE timestamp >= '{since.strftime('%Y-%m-%d')}'
          AND is_fraud IS NOT NULL
          AND decision IN ('BLOCK', 'ALLOW')
        ORDER BY timestamp DESC
        LIMIT 500000
        """

        logger.info("Loading training data from ClickHouse (last %d days)...", days)
        df = self.client.query_df(query)
        logger.info("Loaded %d labeled events", len(df))

        events = []
        for _, row in df.iterrows():
            try:
                event = RawLoginEvent(
                    user_id=str(row["user_id"]),
                    ip=str(row["ip"]),
                    timestamp=row["timestamp"],
                    device_id=str(row["device_id"]),
                    user_agent=str(row.get("user_agent", "")),
                    timezone=str(row.get("timezone", "")),
                    language=str(row.get("language", "")),
                    carrier_mcc=str(row.get("carrier_mcc")) if pd.notna(row.get("carrier_mcc")) else None,
                    carrier_mnc=str(row.get("carrier_mnc")) if pd.notna(row.get("carrier_mnc")) else None,
                    gps_lat=float(row["gps_lat"]) if pd.notna(row.get("gps_lat")) else None,
                    gps_lng=float(row["gps_lng"]) if pd.notna(row.get("gps_lng")) else None,
                    country=str(row.get("country", "")),
                    city=str(row.get("city", "")),
                    latitude=float(row["latitude"]) if pd.notna(row.get("latitude")) else 0.0,
                    longitude=float(row["longitude"]) if pd.notna(row.get("longitude")) else 0.0,
                    asn=int(row["asn"]) if pd.notna(row.get("asn")) else 0,
                    isp=str(row.get("isp", "")),
                    is_vpn=bool(row.get("is_vpn", False)),
                    is_proxy=bool(row.get("is_proxy", False)),
                    is_tor=bool(row.get("is_tor", False)),
                    prev_login_ip=str(row.get("prev_login_ip")) if pd.notna(row.get("prev_login_ip")) else None,
                    prev_login_lat=float(row["prev_login_lat"]) if pd.notna(row.get("prev_login_lat")) else None,
                    prev_login_lng=float(row["prev_login_lng"]) if pd.notna(row.get("prev_login_lng")) else None,
                    prev_login_time=row["prev_login_time"] if pd.notna(row.get("prev_login_time")) else None,
                    latency_mismatch=bool(row.get("latency_mismatch", False)),
                    webrtc_leak=bool(row.get("webrtc_leak", False)),
                    carrier_mismatch=bool(row.get("carrier_mismatch", False)),
                    is_fraud=int(row["is_fraud"]) if pd.notna(row.get("is_fraud")) else None,
                )
                events.append(event)
            except Exception as e:
                logger.warning("Failed to parse row: %s", e)
                continue

        return events

    def store_prediction(self, user_id: str, ip: str, prediction: dict):
        """Store model prediction back to ClickHouse for audit."""
        query = f"""
        INSERT INTO ml_predictions
        (user_id, ip, timestamp, fraud_probability, anomaly_score, 
         ensemble_score, is_fraud, confidence, model_version)
        VALUES
        ('{user_id}', '{ip}', now(), {prediction['fraud_probability']},
         {prediction['anomaly_score']}, {prediction['ensemble_score']},
         {int(prediction['is_fraud'])}, {prediction['confidence']},
         '{prediction['model_version']}')
        """
        self.client.command(query)
