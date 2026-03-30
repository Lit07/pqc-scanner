from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "PQC Scanner"
    API_VERSION: str = "v1"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Database connection
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/pqc_scanner"

    # Security & CORS
    SECRET_KEY: str = "your-super-secret-default-key-change-in-prod"
    CORS_ORIGINS: List[str] = ["*"]

    # Celery & Workers
    REDIS_URL: str = "redis://localhost:6379/0"
    WORKER_CONCURRENCY: int = 4

    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        case_sensitive=True,
        extra="ignore"
    )
