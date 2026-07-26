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


def test_json_extraction_survives_realistic_local_model_quirks():
    # a chain-of-thought preamble with no fence at all
    chatty = (
        "Looking at this code carefully, line by line:\n\n"
        "The function concatenates user input directly into a SQL string, "
        "which is a classic injection point.\n\n"
        '{"summary": "SQL built from request params", "findings": '
        '[{"title": "SQL injection", "severity": "critical"}]}\n\n'
        "Let me know if you would like more detail on the fix."
    )
    parsed = extract_json(chatty)
    assert parsed["findings"][0]["title"] == "SQL injection"

    # a coder model drifting into Python literals instead of JSON ones
    pythonic = '{"findings": [], "vulnerable": False, "reviewed": True, "note": None}'
    assert extract_json(pythonic) == {
        "findings": [], "vulnerable": False, "reviewed": True, "note": None,
    }

    # fence with trailing commentary after the closing ```
    fenced_then_chatty = (
        '```json\n{"summary": "looks fine", "findings": []}\n```\n\n'
        "That covers this chunk — nothing else stood out."
    )
    assert extract_json(fenced_then_chatty) == {"summary": "looks fine", "findings": []}


@pytest.mark.asyncio
async def test_json_chat_asks_ollama_to_constrain_output_to_json():
    """format:"json" (grammar-constrained decoding) is what makes the model's
    findings reliably parseable — this must be requested, not left implicit."""
    from app.analysis.llm import Ollama

    seen_json_mode = []

    class Stub:
        model = "stub-model"

        async def chat(self, messages, *, temperature=0.05, json_mode=False, **kw):
            seen_json_mode.append(json_mode)
            return json.dumps({"ok": True})

    result = await Ollama.json_chat(Stub(), [{"role": "user", "content": "x"}])
    assert result == {"ok": True}
    assert seen_json_mode == [True]


@pytest.mark.asyncio
async def test_json_chat_falls_back_when_the_server_rejects_json_mode():
    """Older Ollama builds, or models without grammar support, may reject the
    format constraint outright — that must degrade gracefully, not lose the
    model's answer entirely."""
    from app.analysis.llm import Ollama, OllamaUnavailable

    calls = []

    class Stub:
        model = "stub-model"

        async def chat(self, messages, *, temperature=0.05, json_mode=False, **kw):
            calls.append(json_mode)
            if json_mode:
                raise OllamaUnavailable("400 Bad Request: unknown field 'format'")
            return json.dumps({"recovered": True})

    result = await Ollama.json_chat(Stub(), [{"role": "user", "content": "x"}])
    assert result == {"recovered": True}
    assert calls == [True, False]


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
    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=llm).run(deep=True)

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

    # coverage proves the model, not just the rules, did the reading
    cov = report["coverage"]
    assert cov["ai_available"] is True
    assert cov["ai_model"] == "scripted"
    assert cov["chunks_sent_to_ai"] > 0
    assert cov["chunks_ai_answered"] == cov["chunks_sent_to_ai"]  # scripted LLM never fails
    assert cov["files_ai_reviewed"] > 0
    assert cov["files_ai_reviewed"] <= cov["files_queued_for_ai"]
    assert cov["findings_from_ai"] == len(ai)
    assert cov["findings_from_ai"] + cov["findings_from_rules"] \
        + cov["findings_from_headers_and_probes"] == cov["findings_from_ai"] + len(
            [f for f in findings if f["source"] != "ai"])

    # every file the model actually answered for is marked analyzed in the DB
    files = {r["path"]: r["analyzed"] for r in db.list_files(scan_id)}
    ai_touched_paths = {f["file_path"] for f in ai if f["file_path"] in files}
    assert ai_touched_paths, "expected at least one AI finding inside a mirrored file"
    for path in ai_touched_paths:
        assert files[path] == 1, f"{path} produced an AI finding but was not marked analyzed"


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

    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=DeadLLM()).run(deep=True)

    assert report["total"] > 0
    assert report["llm_error"]
    assert "Rule-based" in report["verdict"]
    assert db.list_findings(scan_id)

    # no finding may be mislabelled as the AI's when the AI never answered
    assert all(f["source"] != "ai" for f in db.list_findings(scan_id))

    cov = report["coverage"]
    assert cov["ai_available"] is False
    assert cov["files_ai_reviewed"] == 0
    assert cov["chunks_ai_answered"] == 0
    assert cov["findings_from_ai"] == 0
    # nothing in the mirror was ever marked as AI-analyzed
    assert all(r["analyzed"] == 0 for r in db.list_files(scan_id))


@pytest.mark.asyncio
async def test_coverage_never_credits_a_file_the_model_failed_to_answer(
    site_server, scan_dir, monkeypatch,
):
    """A file sent to the model but never successfully parsed must not be
    reported as AI-reviewed — being asked is not the same as being read."""
    monkeypatch.setattr(settings, "crawl_respect_robots", False)

    class GarbageLLM:
        model = "garbage"

        def __init__(self):
            self.calls = 0

        async def json_chat(self, messages, **kwargs):
            self.calls += 1
            raise ValueError("model never produces parseable JSON in this test")

        async def chat(self, messages, **kwargs):
            return "not json"

    scan_id = db.create_scan(site_server, "127.0.0.1")
    dest = settings.scan_path(scan_id)
    crawl = await SiteDownloader(site_server, dest).run()
    db.add_files(scan_id, crawl.files)

    llm = GarbageLLM()
    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=llm).run(deep=True)

    assert llm.calls > 0, "the model must actually have been sent chunks"

    cov = report["coverage"]
    assert cov["ai_available"] is True          # the model was reachable
    assert cov["chunks_sent_to_ai"] > 0          # and it was asked
    assert cov["chunks_ai_answered"] == 0        # but it never gave a usable answer
    assert cov["files_ai_reviewed"] == 0         # so no file counts as AI-reviewed
    assert cov["findings_from_ai"] == 0

    # every finding on the board came from rules/headers/probes, not the model
    findings = db.list_findings(scan_id)
    assert findings, "the fixture's planted bugs should still be caught by rules"
    assert all(f["source"] != "ai" for f in findings)

    # the DB agrees: nothing is marked analyzed despite being queued
    assert all(r["analyzed"] == 0 for r in db.list_files(scan_id))


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
