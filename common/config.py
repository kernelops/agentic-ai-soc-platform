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
    groq_api_key: str = Field(default="", description="Groq API key")
    # 8B default: much higher free-tier rate limits than 70B, and fast. Override
    # with SOC_GROQ_MODEL (e.g. llama-3.3-70b-versatile for stronger reasoning).
    groq_model: str = "llama-3.1-8b-instant"

    # --- Agentic layer ---
    agent_llm_temperature: float = 0.0  # deterministic reasoning for reproducible triage/verdicts
    agent_llm_max_tokens: int = 1024  # cap per-agent output to keep latency/rate-limit cost down
    agent_max_retries: int = 5  # attempts for Groq rate-limit / transient errors (we drive backoff)
    # Accounts we never auto-remediate against — verification hard-rejects these,
    # routing the case to human review. Overridable via SOC_AGENT_NO_AUTOREMEDIATE_USERS.
    agent_no_autoremediate_users: set[str] = Field(
        default_factory=lambda: {"admin", "root"},
        description="Privileged accounts that require human review (verification policy gate)",
    )

    # --- AlienVault OTX ---
    otx_api_key: str = Field(default="", description="AlienVault OTX API key")
    otx_base_url: str = "https://otx.alienvault.com"
    otx_cache_ttl_seconds: int = 3600  # Redis cache TTL for successful OTX lookups (1 hour)
    otx_failure_cache_ttl_seconds: int = 120  # negative-cache TTL when OTX is unreachable/errors
    # OTX read timeout. The /general endpoint can be slow for heavily-referenced
    # IPs (large pulse payloads), so this is generous; the cost is paid once per
    # IP then cached. Connect timeout is separate/short (see otx_connect_timeout).
    otx_timeout_seconds: float = 15.0
    otx_connect_timeout_seconds: float = 5.0  # fail fast if the host is unreachable

    # --- Slack ---
    slack_webhook_url: str = Field(default="", description="Slack incoming webhook URL")

    # --- RAG / Qdrant ---
    qdrant_host: str = Field(default="qdrant", description="Qdrant service hostname")
    qdrant_port: int = 6333  # REST API port
    rag_embedding_model: str = "BAAI/bge-small-en-v1.5"  # FastEmbed model (local, ONNX)
    rag_vector_size: int = 384  # embedding dimension for bge-small-en-v1.5
    rag_embedding_cache_dir: str = "/app/models"  # pre-baked model cache (see Dockerfile)
    rag_n_results: int = 3  # default number of documents returned per query

    # --- Correlation ---
    correlation_window_minutes: int = 30  # broad lookback for prior-alert fetch
    recent_alerts_retention_minutes: int = 35  # TTL for the recent_alerts store (>= lookback + buffer)
    brute_force_threshold: int = 3
    brute_force_window_minutes: int = 5
    brute_force_then_login_window_minutes: int = 10
    priv_esc_window_minutes: int = 10

    # --- Enrichment: asset criticality ---
    # Hostname -> criticality (critical | high | medium | low). Hosts not listed
    # here resolve to "unknown". Overridable via the SOC_ASSET_CRITICALITY_MAP
    # env var as a JSON object, e.g. '{"prod-db-01": "critical"}'.
    asset_criticality_map: dict[str, str] = Field(
        default_factory=lambda: {
            "prod-db-01": "critical",
            "prod-web-01": "high",
            "victim-kali": "high",
            "staging-01": "medium",
            "dev-vm-03": "low",
        },
        description="Hostname to asset-criticality mapping for enrichment",
    )

    # --- Worker ---
    worker_poll_interval: float = 1.0  # seconds between Redis BRPOP calls
    worker_heartbeat_key: str = "worker:heartbeat"  # Redis key the worker refreshes each loop
    worker_heartbeat_stale_seconds: int = 20  # worker considered down if heartbeat older than this

    # --- API / UI ---
    api_cors_origins: list[str] = Field(
        default_factory=lambda: ["*"],
        description="CORS allowed origins for the read API (dev default: all)",
    )
    ingestion_health_url: str = "http://ingestion:8000/api/v1/health"

    model_config = {
        "env_prefix": "SOC_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton instance — import this everywhere
settings = Settings()
