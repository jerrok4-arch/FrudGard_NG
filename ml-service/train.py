"""Training script for FraudGuard NG ML models."""
import argparse
import logging
import sys

from config import ModelConfig
from data_loader import ClickHouseDataLoader
from model import FraudDetectionModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train FraudGuard NG ML models")
    parser.add_argument("--days", type=int, default=90, help="Days of historical data to use")
    parser.add_argument("--dry-run", action="store_true", help="Validate without saving")
    args = parser.parse_args()

    config = ModelConfig()
    logger.info("Starting training pipeline...")
    logger.info("Config: lookback=%d days, model_dir=%s", args.days, config.model_dir)

    # Load data
    loader = ClickHouseDataLoader(config)
    events = loader.load_training_data(days=args.days)

    if len(events) < 1000:
        logger.error("Insufficient data: %d events (minimum 1000 required)", len(events))
        sys.exit(1)

    fraud_count = sum(1 for e in events if e.is_fraud == 1)
    legit_count = sum(1 for e in events if e.is_fraud == 0)
    logger.info("Dataset: %d total (%d fraud, %d legit)", len(events), fraud_count, legit_count)

    if fraud_count < 50:
        logger.warning("Very few fraud samples (%d). Model may be biased.", fraud_count)

    # Train
    model = FraudDetectionModel(config)
    metrics = model.train(events)

    logger.info("=" * 50)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 50)
    logger.info("Samples: %d", metrics["training_samples"])
    logger.info("Fraud: %d | Legit: %d", metrics["fraud_samples"], metrics["legit_samples"])
    logger.info("Top 5 features:")
    for feat, imp in list(metrics["top_features"].items())[:5]:
        logger.info("  - %s: %.4f", feat, imp)

    if not args.dry_run:
        logger.info("Models saved to: %s", config.model_dir)
    else:
        logger.info("Dry run complete. Models NOT saved.")


if __name__ == "__main__":
    main()
