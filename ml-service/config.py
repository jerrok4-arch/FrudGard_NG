"""Configuration for FraudGuard NG ML Pipeline."""
import os
from dataclasses import dataclass
from typing import List


@dataclass
class ModelConfig:
    """ML model configuration."""

    # Data sources
    clickhouse_host: str = os.getenv("CLICKHOUSE_HOST", "localhost")
    clickhouse_port: int = int(os.getenv("CLICKHOUSE_PORT", "8123"))
    clickhouse_db: str = os.getenv("CLICKHOUSE_DB", "fraud_analytics")

    redis_host: str = os.getenv("REDIS_HOST", "localhost")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))

    # Feature store
    feast_repo_path: str = os.getenv("FEAST_REPO_PATH", "./feature_repo")

    # Model paths
    model_dir: str = os.getenv("MODEL_DIR", "./models")
    xgboost_model_path: str = os.getenv("XGB_MODEL_PATH", "./models/xgboost_fraud.json")
    isolation_model_path: str = os.getenv("ISO_MODEL_PATH", "./models/isolation_forest.pkl")
    scaler_path: str = os.getenv("SCALER_PATH", "./models/scaler.pkl")

    # Training params
    retrain_interval_hours: int = int(os.getenv("RETRAIN_INTERVAL_HOURS", "168"))  # Weekly
    lookback_days: int = int(os.getenv("LOOKBACK_DAYS", "90"))

    # Feature engineering
    geo_velocity_window_hours: int = 1
    device_history_window_days: int = 30

    # Nigerian-specific
    nigerian_mcc: str = "621"
    nigerian_timezone: str = "Africa/Lagos"
    nigerian_asns: List[int] = None

    def __post_init__(self):
        if self.nigerian_asns is None:
            self.nigerian_asns = [29465, 37148, 37282, 328309, 328414]
        os.makedirs(self.model_dir, exist_ok=True)
