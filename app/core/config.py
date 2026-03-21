"""App configuration — loads from .env file."""

from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Groq
    groq_api_key: str #required from .env no default
    groq_model: str = "openai/gpt-oss-120b"

    # Batfish
    batfish_host: str = "localhost"
    batfish_port: int = 9996
    batfish_network: str = "nl2firewall"

    # App
    app_name: str = "NL2Firewall"
    debug: bool = False
    log_level: str = "INFO"

    # Networks directory (scanned for .yaml context files on startup)
    networks_dir: str = "data/networks"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # silently ignore stale .env keys


@lru_cache
def get_settings() -> Settings:
    return Settings()