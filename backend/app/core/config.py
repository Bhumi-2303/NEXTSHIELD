"""Application configuration using pydantic-settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global application settings, loaded from environment variables."""

    APP_NAME: str = "NEXTSHIELD"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # CORS
    FRONTEND_ORIGIN: str = "http://localhost:3000"

    # Model paths (each module owns its own model, but paths live here)
    PHISHING_MODEL_PATH: str = "models/phishing_classifier.pkl"
    ANOMALY_MODEL_PATH: str = "models/anomaly_detector.pkl"

    # Anomaly sub-model paths
    ANOMALY_IFOREST_PATH: str = "models/anomaly_iforest.joblib"
    ANOMALY_XGBOOST_PATH: str = "models/anomaly_xgboost.joblib"
    ANOMALY_FEATURE_SCALER_PATH: str = "models/anomaly_scaler.joblib"
    ANOMALY_LABEL_ENCODER_PATH: str = "models/anomaly_label_encoder.joblib"

    # Ensemble weights for anomaly scoring
    UNSUPERVISED_WEIGHT: float = 0.4
    SUPERVISED_WEIGHT: float = 0.6
    ZERO_DAY_SUPERVISED_THRESHOLD: float = 0.3

    # Thresholds
    CONFIDENCE_THRESHOLD: float = 0.5

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
