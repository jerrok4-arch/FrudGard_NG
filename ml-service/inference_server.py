"""FastAPI inference server for real-time fraud scoring."""
import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from config import ModelConfig
from features import RawLoginEvent
from model import FraudDetectionModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FraudGuard NG ML Inference", version="2.1.0")

# Global model instance
model: Optional[FraudDetectionModel] = None


class InferenceRequest(BaseModel):
    """Request body for fraud prediction."""
    user_id: str = Field(..., description="Unique user identifier")
    ip: str = Field(..., description="Client IP address")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    device_id: str = Field(..., description="Device fingerprint hash")
    user_agent: str = Field(default="")
    timezone: str = Field(default="")
    language: str = Field(default="")
    carrier_mcc: Optional[str] = Field(default=None)
    carrier_mnc: Optional[str] = Field(default=None)
    gps_lat: Optional[float] = Field(default=None)
    gps_lng: Optional[float] = Field(default=None)

    # GeoIP-enriched fields (populated by Go service)
    country: str = Field(default="")
    city: str = Field(default="")
    latitude: float = Field(default=0.0)
    longitude: float = Field(default=0.0)
    asn: int = Field(default=0)
    isp: str = Field(default="")
    is_vpn: bool = Field(default=False)
    is_proxy: bool = Field(default=False)
    is_tor: bool = Field(default=False)

    # Detection signals from Go service
    latency_mismatch: bool = Field(default=False)
    webrtc_leak: bool = Field(default=False)
    carrier_mismatch: bool = Field(default=False)

    # Historical context
    prev_login_ip: Optional[str] = Field(default=None)
    prev_login_lat: Optional[float] = Field(default=None)
    prev_login_lng: Optional[float] = Field(default=None)
    prev_login_time: Optional[datetime] = Field(default=None)


class InferenceResponse(BaseModel):
    """Response with fraud prediction."""
    user_id: str
    fraud_probability: float
    anomaly_score: float
    ensemble_score: float
    is_fraud: bool
    confidence: float
    model_version: str
    timestamp: str
    explanation: list


@app.on_event("startup")
async def startup_event():
    global model
    config = ModelConfig()
    logger.info("Loading ML models from %s...", config.model_dir)
    model = FraudDetectionModel(config)

    if model.xgb_model is None:
        logger.warning("XGBoost model not loaded — predictions will use fallback")
    if model.iso_model is None:
        logger.warning("Isolation Forest not loaded — anomaly detection disabled")

    logger.info("Inference server ready")


@app.post("/predict", response_model=InferenceResponse)
async def predict(request: InferenceRequest):
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # Convert to internal event format
    event = RawLoginEvent(
        user_id=request.user_id,
        ip=request.ip,
        timestamp=request.timestamp,
        device_id=request.device_id,
        user_agent=request.user_agent,
        timezone=request.timezone,
        language=request.language,
        carrier_mcc=request.carrier_mcc,
        carrier_mnc=request.carrier_mnc,
        gps_lat=request.gps_lat,
        gps_lng=request.gps_lng,
        country=request.country,
        city=request.city,
        latitude=request.latitude,
        longitude=request.longitude,
        asn=request.asn,
        isp=request.isp,
        is_vpn=request.is_vpn,
        is_proxy=request.is_proxy,
        is_tor=request.is_tor,
        prev_login_ip=request.prev_login_ip,
        prev_login_lat=request.prev_login_lat,
        prev_login_lng=request.prev_login_lng,
        prev_login_time=request.prev_login_time,
        latency_mismatch=request.latency_mismatch,
        webrtc_leak=request.webrtc_leak,
        carrier_mismatch=request.carrier_mismatch,
    )

    # Run prediction
    prediction = model.predict(event)
    explanation = model.explain_prediction(event)

    return InferenceResponse(
        user_id=request.user_id,
        fraud_probability=prediction["fraud_probability"],
        anomaly_score=prediction["anomaly_score"],
        ensemble_score=prediction["ensemble_score"],
        is_fraud=prediction["is_fraud"],
        confidence=prediction["confidence"],
        model_version=prediction["model_version"],
        timestamp=prediction["timestamp"],
        explanation=explanation,
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None and model.xgb_model is not None,
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
