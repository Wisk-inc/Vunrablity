#!/usr/bin/env python3
"""Start Vunrablity."""
from __future__ import annotations

import argparse

import uvicorn

from app.config import settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Vunrablity — website vulnerability assessor")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--reload", action="store_true", help="auto-reload on code changes")
    args = parser.parse_args()

    print(f"""
  ┌──────────────────────────────────────────────┐
  │  Vunrablity                                  │
  │  http://{args.host}:{args.port}{' ' * max(0, 29 - len(args.host) - len(str(args.port)))}│
  │                                              │
  │  model    {settings.ollama_model:<34.34}│
  │  ollama   {settings.ollama_host:<34.34}│
  │  sandbox  {settings.sandbox_image:<34.34}│
  └──────────────────────────────────────────────┘
""")

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
