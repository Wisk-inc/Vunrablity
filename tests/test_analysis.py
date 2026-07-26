"""Rule engine, header checks, memory, and the full audit pipeline.

The model is replaced with a scripted stand-in so the pipeline is testable
without a GPU — but the plumbing under test is the real plumbing.
"""
from __future__ import annotations

import json

import pytest

from app import db
from app.analysis import headers as header_checks, severity as sev, static_rules
from app.analysis.analyzer import Analyzer
from app.analysis.llm import extract_json
from app.analysis.memory import ScanMemory
from app.config import settings
from app.crawler import SiteDownloader


# --------------------------------------------------------------------------- rules
def test_rules_catch_the_obvious_things():
    code = """
        const key = "AKIAIOSFODNN7EXAMPLE";
        const pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        el.innerHTML = userInput;
        const q = "SELECT * FROM users WHERE id = " + req.params.id;
        exec("tar czf out.tgz " + req.query.dir);
        requests.get(url, verify=False)
        crypto.createHash("md5").update(pw);
        localStorage.setItem("auth_token", jwt);
    """
    ids = {h.rule.id for h in static_rules.scan_text(code, "javascript")}
    assert "SEC-AWS-KEY" in ids
    assert "SEC-GITHUB-PAT" in ids
    assert "XSS-INNERHTML" in ids
    assert "INJ-SQL" in ids
    assert "INJ-CMD" in ids
    assert "CRY-TLS-OFF" in ids
    assert "CRY-WEAK-HASH" in ids
    assert "AUT-LOCALSTORAGE-TOKEN" in ids


def test_rules_report_the_right_line():
    code = "line one\nline two\nel.innerHTML = evil;\nline four\n"
    hits = [h for h in static_rules.scan_text(code, "javascript")
            if h.rule.id == "XSS-INNERHTML"]
    assert len(hits) == 1
    assert hits[0].line_no == 3


def test_minified_lines_are_skipped():
    long_line = "var a=1;" * 500 + "el.innerHTML=x;"
    assert not static_rules.scan_text(long_line, "javascript")


def test_score_orders_by_danger():
    critical = static_rules.scan_text('k="AKIAIOSFODNN7EXAMPLE"', "javascript")
    trivial = static_rules.scan_text('// TODO: validate input properly', "javascript")
    assert static_rules.score_file(critical) > static_rules.score_file(trivial)


# --------------------------------------------------------------------------- severity
def test_plain_words_map_onto_the_scale():
    assert sev.normalize("dangerous") == "high"
    assert sev.normalize("small") == "low"
    assert sev.normalize("CRITICAL") == "critical"
    assert sev.normalize("nonsense") == "info"
    assert sev.worst(["low", "critical", "medium"]) == "critical"


# --------------------------------------------------------------------------- headers
def test_missing_security_headers_are_reported():
    found = header_checks.analyze({
        "acme.test": {"url": "https://acme.test/", "status": 200, "headers": {
            "Server": "nginx/1.14.0",
            "Set-Cookie": "session=abc; Path=/",
        }},
    })
    titles = " ".join(f["title"] for f in found)
    assert "Content-Security-Policy" in titles
    assert "Strict-Transport-Security" in titles
    assert "Cookie missing" in titles
    assert "version disclosed" in titles


def test_present_headers_are_not_reported():
    found = header_checks.analyze({
        "acme.test": {"url": "https://acme.test/", "status": 200, "headers": {
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        }},
    })
    titles = " ".join(f["title"] for f in found)
    assert "No Content-Security-Policy" not in titles
    assert "No framing protection" not in titles


def test_exposed_env_file_is_critical():
    found = header_checks.analyze_exposures([
        {"url": "https://acme.test/.env", "status": 200, "bytes": 210,
         "content_type": "text/plain", "preview": "DATABASE_URL=..."},
    ])
    assert found and found[0]["severity"] == "critical"


# --------------------------------------------------------------------------- memory
def test_memory_survives_a_reload(scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    mem = ScanMemory(scan_id)
    mem.remember_fact("auth", "JWT kept in localStorage")
    mem.remember_file("app.js", "bundle with the API client")
    mem.remember_finding("Hard-coded Stripe key")

    reloaded = ScanMemory(scan_id)
    assert "JWT kept in localStorage" in reloaded.context_block()
    assert reloaded.file_summary("app.js") == "bundle with the API client"
    assert reloaded.has_seen_finding("hard-coded stripe key")
    assert not reloaded.has_seen_finding("something else entirely")


def test_context_block_respects_its_budget(scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    mem = ScanMemory(scan_id)
    for i in range(200):
        mem.remember_fact(f"k{i}", "x" * 200)
    assert len(mem.context_block(budget=1000)) <= 1000


# --------------------------------------------------------------------------- json
def test_model_json_is_recovered_from_messy_replies():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here you go:\n{"a": [1,2,],}\nHope that helps') == {"a": [1, 2]}
    assert extract_json('{"a": "b"} trailing words') == {"a": "b"}
    assert extract_json("not json at all") is None


# --------------------------------------------------------------------------- pipeline
class ScriptedLLM:
    """Stands in for Ollama: reports one finding on any chunk containing eval()."""

    def __init__(self):
        self.model = "scripted"
        self.calls = 0

    async def json_chat(self, messages, **kwargs):
        self.calls += 1
        prompt = messages[-1]["content"]

        if "executive summary" in prompt or "REPORT" in prompt or "verdict" in prompt:
            return {"verdict": "Not safe to run in production.", "risk": "critical",
                    "summary": "Secrets are shipped to the browser.",
                    "themes": ["client-side trust"],
                    "priorities": [{"order": 1, "action": "Rotate the keys",
                                    "why": "they are public", "files": ["assets/app.js"],
                                    "effort": "minutes"}]}

        if "You just finished reading" in prompt:
            return {"summary": "front-end bundle", "facts": ["uses fetch for the API"]}

        if "eval(" in prompt:
            line = next(
                (int(l.split("|")[0].strip())
                 for l in prompt.splitlines() if "|" in l and "eval(" in l),
                1,
            )
            return {
                "summary": "plugin loader",
                "facts": ["plugins are evaluated as source"],
                "findings": [{
                    "title": "Arbitrary code execution via eval",
                    "severity": "critical", "confidence": 0.9,
                    "category": "injection", "cwe": "CWE-95",
                    "line_start": line, "line_end": line,
                    "evidence": "return eval(source);",
                    "explanation": "Plugin source is executed verbatim.",
                    "fix": "Remove eval; dispatch to a registry of known plugins.",
                    "verify": "grep -n 'eval(' assets/app.js",
                }],
            }

        return {"summary": "nothing notable", "facts": [], "findings": []}

    async def chat(self, messages, **kwargs):
        return json.dumps(await self.json_chat(messages))


@pytest.mark.asyncio
async def test_full_audit_finds_real_problems(site_server, scan_dir, monkeypatch):
    monkeypatch.setattr(settings, "crawl_respect_robots", False)
    monkeypatch.setattr(settings, "analysis_chunk_lines", 60)

    scan_id = db.create_scan(site_server, "127.0.0.1")
    dest = settings.scan_path(scan_id)

    crawl = await SiteDownloader(site_server, dest).run()
    db.add_files(scan_id, crawl.files)

    llm = ScriptedLLM()
    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=llm).run()

    findings = db.list_findings(scan_id)
    titles = " | ".join(f["title"] for f in findings)
    sources = {f["source"] for f in findings}

    # deterministic rules fired on the fixture's planted bugs
    assert "rule:SEC-GITHUB-PAT" in sources or "GitHub personal access token" in titles
    assert any("innerHTML" in t or "HTML sink" in t for t in titles.split(" | "))

    # header checks and exposure probes contributed
    assert "header-check" in sources
    assert any(".env" in f["title"] for f in findings)

    # the model's finding was recorded, with a line number and a fix
    ai = [f for f in findings if f["source"] == "ai"]
    assert ai, "the model's findings were not stored"
    assert all(f["fix"] for f in ai)
    assert all(f["severity"] in sev.ORDER for f in findings)

    # the source map's recovered server code was read, not just the bundle
    read_paths = {f["file_path"] for f in findings}
    assert any(p.startswith("sources/") for p in read_paths), read_paths

    # the report is coherent
    assert report["risk"] == "critical"
    assert report["counts"]["critical"] >= 1
    assert report["total"] == len(findings)
    assert llm.calls > 0


@pytest.mark.asyncio
async def test_audit_still_works_without_a_model(site_server, scan_dir, monkeypatch):
    """Ollama down must degrade to rules, not crash."""
    from app.analysis.llm import OllamaUnavailable

    monkeypatch.setattr(settings, "crawl_respect_robots", False)

    class DeadLLM:
        model = "dead"

        async def json_chat(self, *a, **k):
            raise OllamaUnavailable("connection refused")

        async def chat(self, *a, **k):
            raise OllamaUnavailable("connection refused")

    scan_id = db.create_scan(site_server, "127.0.0.1")
    dest = settings.scan_path(scan_id)
    crawl = await SiteDownloader(site_server, dest).run()
    db.add_files(scan_id, crawl.files)

    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=DeadLLM()).run()

    assert report["total"] > 0
    assert report["llm_error"]
    assert "Rule-based" in report["verdict"]
    assert db.list_findings(scan_id)


def test_duplicate_findings_are_collapsed(scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    analyzer = Analyzer(scan_id, scan_dir, {"headers": {}, "exposures": [], "forms": []})

    base = {"file_path": "a.js", "line_start": 10, "title": "Hard-coded API key",
            "severity": "medium", "confidence": 0.6, "source": "rule:X"}
    assert analyzer._record(dict(base)) is True
    assert analyzer._record(dict(base)) is False
    assert analyzer._record({**base, "severity": "critical"}) is False

    # the surviving copy kept the worse severity
    assert analyzer.findings[0]["severity"] == "critical"
    assert len(analyzer.findings) == 1
