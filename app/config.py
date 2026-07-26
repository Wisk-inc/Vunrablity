"""Runtime configuration, read from the environment / .env file."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Ollama
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    ollama_num_ctx: int = 8192

    # Crawler
    crawl_max_pages: int = 400
    crawl_max_assets: int = 1500
    crawl_max_depth: int = 4
    crawl_max_file_mb: int = 8
    crawl_concurrency: int = 8
    crawl_timeout: int = 20
    crawl_follow_subdomains: bool = True
    crawl_respect_robots: bool = True

    # Sandbox
    sandbox_backend: str = "auto"   # auto | llm-sandbox | docker | none
    sandbox_image: str = "python:3.11-slim"
    sandbox_network: str = "none"
    sandbox_memory: str = "1g"
    sandbox_cpus: str = "1.0"
    sandbox_workdir_size: str = "2g"
    sandbox_timeout: int = 120

    # Analysis
    analysis_chunk_lines: int = 120
    analysis_chunk_overlap: int = 15
    analysis_max_files: int = 400
    agent_max_steps: int = 25

    data_dir: str = "./data"
    host: str = "127.0.0.1"
    port: int = 8000

    @property
    def data_path(self) -> Path:
        p = Path(self.data_dir).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    def scan_path(self, scan_id: str) -> Path:
        p = self.data_path / "scans" / scan_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def max_file_bytes(self) -> int:
        return self.crawl_max_file_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# Keep the sandbox off the host network unless the operator opted in.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
