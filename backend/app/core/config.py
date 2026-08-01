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

    # Thresholds
    CONFIDENCE_THRESHOLD: float = 0.5

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
