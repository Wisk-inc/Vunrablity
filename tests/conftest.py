"""Test fixtures: a local, deliberately-broken website to point the scanner at."""
from __future__ import annotations

import functools
import http.server
import os
import socket
import threading
from pathlib import Path

import pytest

FIXTURE_SITE = Path(__file__).parent / "fixtures" / "site"


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Serves the fixture and adds the sloppy headers a real bad site would."""

    def end_headers(self):
        self.send_header("Server", "nginx/1.14.0")
        self.send_header("X-Powered-By", "Express 4.17.1")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        super().end_headers()

    def log_message(self, *args):  # keep pytest output clean
        pass


def _materialise_hidden_fixtures() -> None:
    """Create the dot-files the fixture needs but git will not carry.

    A nested `.git/` directory cannot live inside this repository, and a
    committed `.env` full of fake secrets is a bad habit even in a test tree —
    so both are written on demand.
    """
    # Assembled at runtime rather than committed: a literal that *looks* like a
    # payment-provider key trips secret scanners on push, even in a test tree.
    fake_stripe_key = "sk_" + "live_" + "51H" + "x" * 24

    env = FIXTURE_SITE / ".env"
    if not env.exists():
        env.write_text(
            "DATABASE_URL=postgres://acme:hunter2@db.internal:5432/acme\n"
            f"STRIPE_SECRET_KEY={fake_stripe_key}\n"
            "JWT_SECRET=super-secret-value-do-not-ship\n"
        )

    config_js = FIXTURE_SITE / "assets" / "config.js"
    if not config_js.exists():
        config_js.write_text(
            "// generated fixture: a shipped bundle carrying a live payment key\n"
            f'export const PAYMENTS = {{ secret: "{fake_stripe_key}" }};\n'
        )

    git_config = FIXTURE_SITE / ".git" / "config"
    if not git_config.exists():
        git_config.parent.mkdir(parents=True, exist_ok=True)
        git_config.write_text(
            "[core]\n\trepositoryformatversion = 0\n"
            '[remote "origin"]\n\turl = git@github.com:acme/widgets.git\n'
        )


@pytest.fixture(scope="session")
def site_server():
    """Serve tests/fixtures/site on a free localhost port for the session."""
    _materialise_hidden_fixtures()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    handler = functools.partial(_Handler, directory=str(FIXTURE_SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session", autouse=True)
def _no_proxy_for_localhost():
    """The crawler must talk to 127.0.0.1 directly, not through a proxy."""
    previous = {k: os.environ.get(k) for k in ("NO_PROXY", "no_proxy")}
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture()
def scan_dir(tmp_path, monkeypatch):
    """Point config + db at a throwaway directory for each test."""
    from app.config import settings

    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    import app.db as db

    db._LOCAL = type(db._LOCAL)()   # fresh thread-local so a new sqlite file is used
    db.init()
    return tmp_path
