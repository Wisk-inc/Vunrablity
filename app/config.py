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
    ollama_model: str = "qwen2.5-coder:3b"
    ollama_num_ctx: int = 8192

    # Crawler — the mirror takes *everything*, whether or not it looks risky.
    crawl_max_pages: int = 5000
    crawl_max_assets: int = 20000
    crawl_max_depth: int = 12
    crawl_max_file_mb: int = 32
    crawl_concurrency: int = 12
    crawl_timeout: int = 25
    crawl_follow_subdomains: bool = True
    crawl_respect_robots: bool = False
    # Third-party bundles are still your attack surface: pull assets from any
    # host they are referenced from, not just the registrable domain.
    crawl_external_assets: bool = True

    # Sandbox. `local` needs no Docker, which is what makes Replit work.
    sandbox_backend: str = "auto"   # auto | local | docker | llm-sandbox | none
    sandbox_image: str = "python:3.11-slim"
    sandbox_network: str = "bridge"  # the agent may fetch from GitHub/PyPI
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2.0"
    sandbox_workdir_size: str = "4g"
    sandbox_timeout: int = 300
    sandbox_preview_ports: str = "8080,8081,3000,5000"

    # Analysis
    analysis_chunk_lines: int = 120
    analysis_chunk_overlap: int = 15
    analysis_max_files: int = 2000
    # Files are independent, so the deep read runs several at once. This is the
    # difference between "reads one file at a time" and finishing in minutes.
    analysis_concurrency: int = 6
    # A fresh scan does the fast pass only, so the chat opens immediately;
    # the deep read happens when you ask for it.
    analysis_deep_on_scan: bool = False
    agent_max_steps: int = 40

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
    def on_replit(self) -> bool:
        return bool(os.environ.get("REPL_ID") or os.environ.get("REPLIT_DEV_DOMAIN"))

    @property
    def bind_host(self) -> str:
        """Replit (and most PaaS) only route traffic to 0.0.0.0."""
        if os.environ.get("HOST"):
            return os.environ["HOST"]
        return "0.0.0.0" if self.on_replit else self.host

    @property
    def bind_port(self) -> int:
        return int(os.environ.get("PORT") or self.port)

    @property
    def preview_ports(self) -> list[int]:
        out = []
        for chunk in str(self.sandbox_preview_ports).split(","):
            chunk = chunk.strip()
            if chunk.isdigit():
                out.append(int(chunk))
        return out

    @property
    def max_file_bytes(self) -> int:
        return self.crawl_max_file_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# Keep the sandbox off the host network unless the operator opted in.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
