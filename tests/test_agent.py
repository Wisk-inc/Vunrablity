"""The agent loop and its tools.

The model is scripted so the loop itself is what gets tested: does it parse
actions, dispatch tools, feed observations back, record findings, and stop?
"""
from __future__ import annotations

import json

import pytest

from app import db
from app.agent import Investigator, ToolBox
from app.analysis.memory import ScanMemory
from app.config import settings


@pytest.fixture()
def workspace(scan_dir):
    scan_id = db.create_scan("https://acme.test", "acme.test")
    root = settings.scan_path(scan_id)
    (root / "site").mkdir(parents=True, exist_ok=True)
    (root / "site" / "app.js").write_text(
        'const token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";\n'
        "function render(x) { el.innerHTML = x; }\n"
        "function plugin(s) { return eval(s); }\n"
    )
    (root / "site" / "style.css").write_text("body { color: #000 }\n")
    db.add_files(scan_id, [
        {"path": "site/app.js", "kind": "code", "language": "javascript",
         "bytes": 180, "lines": 3},
        {"path": "site/style.css", "kind": "code", "language": "css",
         "bytes": 24, "lines": 1},
    ])
    return scan_id, root


# --------------------------------------------------------------------------- tools
@pytest.mark.asyncio
async def test_read_grep_and_list(workspace):
    scan_id, root = workspace
    tools = ToolBox(scan_id, root, ScanMemory(scan_id))

    listing = await tools.call("list_files", {"pattern": "**/*.js"})
    assert "site/app.js" in listing
    assert "style.css" not in listing

    body = await tools.call("read_file", {"path": "site/app.js"})
    assert "innerHTML" in body
    assert "    1 |" in body, "reads must be line-numbered so citations are checkable"

    hits = await tools.call("grep", {"pattern": r"eval\(", "glob": "*.js"})
    assert "site/app.js:3" in hits


@pytest.mark.asyncio
async def test_tools_fail_helpfully(workspace):
    scan_id, root = workspace
    tools = ToolBox(scan_id, root, ScanMemory(scan_id))

    missing = await tools.call("read_file", {"path": "site/nope.js"})
    assert missing.startswith("ERROR")

    bad_regex = await tools.call("grep", {"pattern": "([unclosed"})
    assert "bad regex" in bad_regex

    unknown = await tools.call("teleport", {})
    assert "Unknown tool" in unknown


@pytest.mark.asyncio
async def test_reads_cannot_escape_the_scan_directory(workspace):
    scan_id, root = workspace
    tools = ToolBox(scan_id, root, ScanMemory(scan_id))

    for attempt in ("../../etc/passwd", "/etc/passwd", "site/../../../etc/passwd"):
        out = await tools.call("read_file", {"path": attempt})
        assert out.startswith("ERROR"), f"{attempt} was not blocked"
        assert "root:" not in out


@pytest.mark.asyncio
async def test_findings_are_recorded_and_deduped(workspace):
    scan_id, root = workspace
    memory = ScanMemory(scan_id)
    tools = ToolBox(scan_id, root, memory)

    first = await tools.call("add_finding", {
        "title": "Arbitrary code execution via eval",
        "severity": "dangerous",           # plain word, not our vocabulary
        "file_path": "site/app.js", "line_start": 3,
        "evidence": "return eval(s);",
        "explanation": "Plugin source is executed verbatim.",
        "fix": "Dispatch through a registry instead of eval.",
    })
    assert "Recorded" in first

    stored = db.list_findings(scan_id)
    assert len(stored) == 1
    assert stored[0]["severity"] == "high"      # 'dangerous' was normalised
    assert stored[0]["source"] == "agent"

    again = await tools.call("add_finding", {
        "title": "Arbitrary code execution via eval", "severity": "high"})
    assert "Already recorded" in again
    assert len(db.list_findings(scan_id)) == 1


@pytest.mark.asyncio
async def test_remember_persists(workspace):
    scan_id, root = workspace
    tools = ToolBox(scan_id, root, ScanMemory(scan_id))
    await tools.call("remember", {"fact": "the API lives on api.acme.test"})
    assert "api.acme.test" in ScanMemory(scan_id).context_block()


# --------------------------------------------------------------------------- loop
class ScriptedAgentLLM:
    """Plays a fixed sequence of actions, ignoring what the loop says back."""

    def __init__(self, script):
        self.script = list(script)
        self.seen: list[str] = []
        self.json_modes: list[bool] = []

    async def chat(self, messages, *, json_mode=False, **kwargs):
        self.seen.append(messages[-1]["content"])
        self.json_modes.append(json_mode)
        return json.dumps(self.script.pop(0)) if self.script else json.dumps(
            {"thought": "done", "tool": "finish", "args": {"answer": "fallback"}}
        )


@pytest.mark.asyncio
async def test_loop_runs_tools_then_finishes(workspace):
    scan_id, root = workspace
    events = []

    async def on_event(kind, payload):
        events.append((kind, payload))

    llm = ScriptedAgentLLM([
        {"thought": "find the js", "tool": "list_files", "args": {"pattern": "**/*.js"}},
        {"thought": "look for eval", "tool": "grep", "args": {"pattern": "eval"}},
        {"thought": "read it", "tool": "read_file",
         "args": {"path": "site/app.js", "start": 1, "end": 5}},
        {"thought": "log it", "tool": "add_finding",
         "args": {"title": "eval on plugin source", "severity": "critical",
                  "file_path": "site/app.js", "line_start": 3}},
        {"thought": "that settles it", "tool": "finish",
         "args": {"answer": "`site/app.js:3` evaluates plugin source."}},
    ])

    result = await Investigator(scan_id, root, "check for code execution",
                                llm=llm, on_event=on_event).run()

    assert result["steps"] == 5
    assert "site/app.js:3" in result["answer"]
    assert len(result["findings"]) == 1
    assert [s["tool"] for s in result["transcript"]] == [
        "list_files", "grep", "read_file", "add_finding", "finish"]

    kinds = [k for k, _ in events]
    assert "agent_step" in kinds and "agent_observation" in kinds and "agent_done" in kinds

    # observations really were fed back to the model
    assert any("OBSERVATION from grep" in m for m in llm.seen)

    # every action turn asked Ollama to constrain its output to JSON
    assert all(llm.json_modes), "the agent must request grammar-constrained JSON"


@pytest.mark.asyncio
async def test_loop_stops_retrying_json_mode_after_first_rejection(workspace):
    """If the server rejects format:"json" once, the loop should not pay that
    cost again on every remaining turn of the same run."""
    scan_id, root = workspace

    from app.analysis.llm import OllamaUnavailable

    class RejectsJsonMode:
        def __init__(self):
            self.json_modes: list[bool] = []
            self.step = 0

        async def chat(self, messages, *, json_mode=False, **kwargs):
            self.json_modes.append(json_mode)
            if json_mode:
                raise OllamaUnavailable("400: unknown parameter 'format'")
            self.step += 1
            if self.step >= 3:
                return json.dumps({"thought": "done", "tool": "finish",
                                   "args": {"answer": "done without json mode"}})
            return json.dumps({"thought": "again", "tool": "list_files", "args": {}})

    llm = RejectsJsonMode()
    result = await Investigator(scan_id, root, "task", llm=llm, max_steps=10).run()

    assert result["answer"] == "done without json mode"
    # exactly one rejected attempt, not one per step
    assert llm.json_modes.count(True) == 1
    assert llm.json_modes.count(False) == 3  # the retry plus two clean turns


@pytest.mark.asyncio
async def test_loop_survives_non_json_replies(workspace):
    scan_id, root = workspace

    class Rambler:
        def __init__(self):
            self.n = 0

        async def chat(self, messages, **kwargs):
            self.n += 1
            if self.n < 3:
                return "Let me think about this for a moment..."
            return json.dumps({"thought": "ok", "tool": "finish",
                               "args": {"answer": "recovered"}})

    result = await Investigator(scan_id, root, "task", llm=Rambler()).run()
    assert result["answer"] == "recovered"


@pytest.mark.asyncio
async def test_loop_stops_at_the_step_budget(workspace):
    scan_id, root = workspace

    class Looper:
        async def chat(self, messages, **kwargs):
            if "step budget" in messages[-1]["content"]:
                return "I ran out of steps before I could confirm it."
            return json.dumps({"thought": "again", "tool": "list_files", "args": {}})

    result = await Investigator(scan_id, root, "task", llm=Looper(), max_steps=4).run()
    assert result["steps"] == 4
    assert "ran out of steps" in result["answer"]


@pytest.mark.asyncio
async def test_model_outage_is_reported_not_raised(workspace):
    from app.analysis.llm import OllamaUnavailable

    scan_id, root = workspace

    class Dead:
        async def chat(self, *a, **k):
            raise OllamaUnavailable("connection refused")

    result = await Investigator(scan_id, root, "task", llm=Dead()).run()
    assert "unreachable" in result["answer"]
    assert result["steps"] == 0
