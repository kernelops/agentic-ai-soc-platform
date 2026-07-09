"""
Centralized configuration for the Agentic AI SOC Platform.

All settings are loaded from environment variables with sensible defaults
for local Docker development. Every service imports from here.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Platform-wide settings loaded from environment variables."""

    # --- Service identity ---
    service_name: str = "agentic-soc"

    # --- Redis ---
    redis_url: str = Field(default="redis://redis:6379/0", description="Redis connection URL")
    redis_queue_key: str = "alerts:incoming"
    redis_dlq_key: str = "alerts:dlq"

    # --- MongoDB ---
    mongo_url: str = Field(default="mongodb://mongodb:27017", description="MongoDB connection URL")
    mongo_db_name: str = "soc_platform"

    # --- Ingestion ---
    ingestion_auth_token: str = Field(default="soc-ingest-token-dev", description="Bearer token for the ingestion webhook")

    # --- Groq LLM ---
    groq_api_key: str = Field(default="", description="Groq API key for Llama 3.3 70B")
    groq_model: str = "llama-3.3-70b-versatile"

    # --- AlienVault OTX ---
    otx_api_key: str = Field(default="", description="AlienVault OTX API key")
    otx_base_url: str = "https://otx.alienvault.com"

    # --- Slack ---
    slack_webhook_url: str = Field(default="", description="Slack incoming webhook URL")

    # --- ChromaDB ---
    chroma_persist_dir: str = "/app/data/chromadb"

    # --- Correlation ---
    correlation_window_minutes: int = 30
    brute_force_threshold: int = 3
    brute_force_window_minutes: int = 5
    priv_esc_window_minutes: int = 10

    # --- Worker ---
    worker_poll_interval: float = 1.0  # seconds between Redis BRPOP calls

    model_config = {
        "env_prefix": "SOC_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton instance — import this everywhere
settings = Settings()
