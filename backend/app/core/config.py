"""
Sentinel AI — Centralized Configuration via pydantic-settings
All secrets load from environment variables. Never hardcode values here.
"""
from functools import lru_cache
from typing import Optional

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # === Application ===
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_LOG_LEVEL: str = "INFO"
    FRONTEND_URL: str = "http://localhost:5173"

    # === JWT ===
    JWT_SECRET: str = ""  # auto-generated at boot if empty
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # === GitHub OAuth2 ===
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/github/callback"

    # === Database ===
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"

    # === Gemini / Google AI ===
    GEMINI_API_KEY: str = ""

    # === LLM Model Routing ===
    LLM_MODEL_PRO: str = "gemini-3.6-flash"
    LLM_MODEL_FLASH: str = "gemini-3.6-flash"
    LLM_MODEL_FLASH_LITE: str = "gemini-3.5-flash-lite"

    # === External Intel APIs ===
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    NVD_API_KEY: str = ""

    # === Rate Limiting (Sentinel AI own API) ===
    RATE_LIMIT_SCAN_PER_MINUTE: int = 10
    RATE_LIMIT_GLOBAL_PER_MINUTE: int = 100

    # === Outbound Rate Limits ===
    VIRUSTOTAL_REQUESTS_PER_MINUTE: int = 4
    SHODAN_REQUESTS_PER_SECOND: int = 1
    NVD_REQUESTS_PER_30S: int = 50

    # === Cache TTLs ===
    IOC_CACHE_TTL_SECONDS: int = 86400
    CVE_CACHE_TTL_SECONDS: int = 604800

    # === Reporting ===
    REPORTS_OUTPUT_DIR: str = "./data/reports"

    # === MITRE ATT&CK ===
    MITRE_DATA_PATH: str = "./data/mitre/enterprise-attack.json"

    # === Compliance Mappings ===
    COMPLIANCE_MAPPINGS_DIR: str = "./data/compliance_mappings"

    # === Dev Auth Bypass ===
    ENABLE_LOCAL_AUTH: bool = True

    # === Pipeline Confidence Threshold ===
    CLASSIFICATION_CONFIDENCE_THRESHOLD: float = 0.6

    @computed_field
    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
