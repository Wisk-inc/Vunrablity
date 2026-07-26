"""The HTTP + WebSocket surface."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import db
from app.config import settings
from app.main import app


@pytest.fixture()
def client(scan_dir):
    with TestClient(app) as c:
        yield c


def test_pages_are_served(client):
    assert "Vunrablity" in client.get("/").text
    assert "Workspace" in client.get("/chat").text
    assert client.get("/static/css/app.css").status_code == 200


def test_health_reports_both_dependencies(client):
    body = client.get("/api/health").json()
    assert "ollama" in body and "sandbox" in body
    assert body["settings"]["model"]
    # Ollama is probably absent in CI — the endpoint must still answer.
    assert isinstance(body["ollama"]["ok"], bool)


def test_a_bad_address_is_rejected(client):
    assert client.post("/api/scan", json={"url": "not a website"}).status_code == 400


def test_scan_detail_and_report(client, scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    db.add_files(scan_id, [{"path": "site/app.js", "kind": "code",
                            "language": "javascript", "bytes": 10, "lines": 2}])
    db.add_finding(scan_id, {
        "file_path": "site/app.js", "line_start": 2, "severity": "critical",
        "confidence": 0.9, "title": "Hard-coded token", "category": "secrets",
        "cwe": "CWE-798", "evidence": 'const t = "ghp_x"',
        "explanation": "Shipped to every visitor.", "fix": "Rotate and proxy it.",
        "source": "rule:SEC-GITHUB-PAT",
    })
    db.update_scan(scan_id, status="complete", summary=json.dumps(
        {"verdict": "Not safe.", "risk": "critical", "summary": "Secrets are public."}))

    detail = client.get(f"/api/scan/{scan_id}").json()
    assert detail["counts"]["critical"] == 1
    assert detail["file_count"] == 1
    assert detail["findings"][0]["title"] == "Hard-coded token"
    assert detail["labels"]["high"] == "Dangerous"

    md = client.get(f"/api/scan/{scan_id}/report.md").text
    assert "# Vunrablity report" in md
    assert "Hard-coded token" in md
    assert "Rotate and proxy it." in md


def test_unknown_scan_is_404(client):
    assert client.get("/api/scan/does-not-exist").status_code == 404


def test_file_endpoint_will_not_serve_outside_the_mirror(client, scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    root = settings.scan_path(scan_id)
    (root / "site").mkdir(parents=True, exist_ok=True)
    (root / "site" / "a.js").write_text("one\ntwo\nthree\n")

    ok = client.get(f"/api/scan/{scan_id}/file", params={"path": "site/a.js"}).json()
    assert ok["total_lines"] == 3
    assert ok["content"].splitlines()[1] == "two"

    for evil in ("../../../etc/passwd", "/etc/passwd"):
        assert client.get(f"/api/scan/{scan_id}/file",
                          params={"path": evil}).status_code in (400, 404)


def test_scan_websocket_greets_with_current_state(client, scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    with client.websocket_connect(f"/ws/scan/{scan_id}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["scan"]["url"] == "https://acme.test"


def test_chat_websocket_rejects_unknown_scans(client):
    with client.websocket_connect("/ws/chat/nope") as ws:
        assert ws.receive_json()["type"] == "error"


def test_action_fences_are_distinguished_from_code_samples():
    """The unified agent has no modes: it decides to act by opening a
    ```tool: fence. An ordinary ```python block must never execute."""
    from app.agent.protocol import StreamParser

    def parse(text):
        parser = StreamParser()
        events = []
        for ch in text:          # one character at a time: the real stream case
            events += parser.feed(ch)
        return events + parser.flush()

    events = parse(
        'Here is what that code does:\n'
        '```python\n'
        'os.system("rm -rf /")\n'
        '```\n'
        'Now let me actually check:\n'
        '```tool:run\n'
        'ls site\n'
        '```\n'
    )
    opened = [p for k, p in events if k == "tool_open"]
    closed = [p for k, p in events if k == "tool_close"]
    prose = "".join(p for k, p in events if k == "text")

    assert len(opened) == 1 and opened[0]["tool"] == "run"
    assert closed[0]["body"].strip() == "ls site"
    # the illustrative snippet stayed prose and was never executed
    assert "os.system" in prose
    assert "rm -rf" not in closed[0]["body"]
