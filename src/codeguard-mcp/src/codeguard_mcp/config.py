"""Configuration via environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _project_root() -> Path:
    """Resolve the cosai-project-codeguard repo root from src/codeguard-mcp/src/codeguard_mcp/."""
    return Path(__file__).resolve().parent.parent.parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CODEGUARD_")

    HOST: str = "0.0.0.0"
    PORT: int = Field(default=8080, ge=1, le=65535)
    LOG_LEVEL: str = "INFO"
    TRANSPORT: str = "streamable-http"
    RULES_DIR: str = str(_project_root() / "sources" / "core")

    APP_VERSION: str = "0.1.0"


settings = Settings()
