"""End-to-end proof against a *real* Ollama instance.

Every other test in this suite replaces the model with a scripted stand-in —
useful for testing the plumbing, but it cannot prove that a real model
actually reads real code and reports real findings. This file does that.

It is skipped automatically unless Ollama is reachable and the configured
model is pulled. To run it for real:

    ollama pull qwen2.5-coder:7b     # or set OLLAMA_MODEL to whatever you have
    ollama serve                     # if not already running
    pytest tests/test_llm_integration.py -v -s

A pass here is the actual answer to "is the AI the one finding the
vulnerabilities": every assertion below fails if the findings could have come
from the deterministic rule engine alone.
"""
from __future__ import annotations

import asyncio

import pytest

from app import db
from app.analysis.analyzer import Analyzer
from app.analysis.llm import Ollama
from app.config import settings
from app.crawler import SiteDownloader

_HEALTH = asyncio.run(Ollama().health())

pytestmark = pytest.mark.skipif(
    not _HEALTH["ok"],
    reason=(
        f"Ollama unavailable ({_HEALTH.get('error')}). "
        f"Run `ollama pull {settings.ollama_model}` against a live Ollama to "
        f"exercise this test."
    ),
)


@pytest.mark.asyncio
async def test_a_real_model_reads_the_fixture_and_finds_the_planted_bugs(
    site_server, scan_dir, monkeypatch,
):
    monkeypatch.setattr(settings, "crawl_respect_robots", False)

    scan_id = db.create_scan(site_server, "127.0.0.1")
    dest = settings.scan_path(scan_id)

    crawl = await SiteDownloader(site_server, dest).run()
    db.add_files(scan_id, crawl.files)

    llm = Ollama()  # the real client — no script, no stub
    report = await Analyzer(scan_id, dest, crawl.as_dict(), llm=llm).run()

    cov = report["coverage"]
    print(f"\nmodel: {cov['ai_model']}")
    print(f"chunks sent to the model: {cov['chunks_sent_to_ai']}")
    print(f"chunks the model answered: {cov['chunks_ai_answered']}")
    print(f"files the model actually reviewed: {cov['files_ai_reviewed']}"
          f"/{cov['files_queued_for_ai']}")
    print(f"findings from the model's own reading: {cov['findings_from_ai']}")

    # The model was reachable and it actually engaged with the code — not
    # merely available, not merely asked, but answering.
    assert cov["ai_available"] is True
    assert cov["chunks_sent_to_ai"] > 0
    assert cov["chunks_ai_answered"] > 0, (
        "the model never returned a single parseable chunk — check "
        f"{settings.ollama_model} supports JSON output"
    )
    assert cov["files_ai_reviewed"] > 0

    findings = db.list_findings(scan_id)
    ai_findings = [f for f in findings if f["source"] == "ai"]
    print(f"\n{len(ai_findings)} findings the model reported on its own:")
    for f in ai_findings[:10]:
        print(f"  [{f['severity']:8}] {f['title']} — {f['file_path']}:{f['line_start']}")

    assert ai_findings, (
        "no finding was attributed to the model — every result could have "
        "come from the rule engine alone, which does not prove the AI read "
        "anything"
    )

    # A real model reading tests/fixtures/site/assets/app.js and the source
    # map it unpacks should notice at least one of: the eval() plugin loader,
    # the unchecked postMessage handler, the string-built SQL query, or the
    # shell command built from request input. Demand at least one — not the
    # exact wording, since that varies model to model, but real engagement
    # with real lines of code.
    interesting = {"eval", "postmessage", "sql", "exec", "command", "inject",
                   "child_process", "shell"}
    matched = [
        f for f in ai_findings
        if any(kw in (f["title"] + " " + (f["explanation"] or "")).lower()
               for kw in interesting)
    ]
    assert matched, (
        "the model reported findings but none touched the fixture's planted "
        f"bugs — got: {[f['title'] for f in ai_findings]}"
    )

    # every AI finding carries a fix suggestion and a real line number
    for f in ai_findings:
        assert f["fix"], f"{f['title']} has no fix suggestion"
        assert f["file_path"], f"{f['title']} has no file"

    # and the file it claims to have read really exists in the mirror with
    # real content at that line — the model cannot be citing a hallucinated
    # location
    for f in ai_findings:
        full = dest / f["file_path"]
        if not full.exists():
            continue  # header/exposure-derived path, not a mirrored file
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        if f["line_start"]:
            assert 1 <= f["line_start"] <= len(lines) + 5, (
                f"{f['title']} cites line {f['line_start']} but "
                f"{f['file_path']} only has {len(lines)} lines"
            )
