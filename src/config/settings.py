"""
Sentinel3 Settings Module
==========================

Centralized configuration management using environment variables.
"""

import os
from pathlib import Path
from typing import Optional


class Settings:
    """Application settings loaded from environment variables."""
    
    def __init__(self):
        # Database
        self.DATABASE_URL: str = os.getenv(
            "DATABASE_URL",
            "postgresql://postgres:postgres@localhost:5432/web3_xdr"
        )
        
        # Redis
        self.REDIS_URL: str = os.getenv(
            "REDIS_URL",
            "redis://localhost:6379/0"
        )
        
        # Runtime Security Plane
        self.RUNTIME_ENABLED: bool = os.getenv("RUNTIME_ENABLED", "false").lower() == "true"
        self.MEMPOOL_SOURCE: str = os.getenv("MEMPOOL_SOURCE", "pseudo")
        self.BLOXROUTE_AUTH_HEADER: Optional[str] = os.getenv("BLOXROUTE_AUTH_HEADER")
        
        # API Keys
        self.OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
        self.INFURA_API_KEY: Optional[str] = os.getenv("INFURA_API_KEY")
        self.COINGECKO_API_KEY: Optional[str] = os.getenv("COINGECKO_API_KEY")
        
        # Alerting
        self.TELEGRAM_BOT_TOKEN: Optional[str] = os.getenv("TELEGRAM_BOT_TOKEN")
        self.SLACK_WEBHOOK_URL: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
        self.PAGERDUTY_API_KEY: Optional[str] = os.getenv("PAGERDUTY_API_KEY")
        
        # Authentication
        self.JWT_SECRET_KEY: str = os.getenv(
            "JWT_SECRET_KEY",
            "dev-secret-key-change-in-production"
        )
        
        # Cloud Run
        self.PORT: int = int(os.getenv("PORT", "9090"))
        
        # Environment
        self.ENV: str = os.getenv("ENV", "development")
        self.DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
        
        # Paths
        self.BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
        self.DATA_DIR: Path = self.BASE_DIR / "data"
        self.CONFIG_DIR: Path = self.BASE_DIR / "config"


# Global settings instance
settings = Settings()
