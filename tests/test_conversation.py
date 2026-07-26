"""The unified conversation: streaming, tool execution, and the no-modes rule.

The model is scripted, but the parser, the action runner and the sandbox under
test are the real ones — a `write` here really writes, a `run` really runs.
"""
from __future__ import annotations

import pytest

from app import db
from app.agent.conversation import Conversation
from app.agent.protocol import StreamParser, parse_args
from app.config import settings


@pytest.fixture()
def workspace(scan_dir, monkeypatch):
    monkeypatch.setattr(settings, "sandbox_backend", "local")
    scan_id = db.create_scan("https://acme.test", "acme.test")
    root = settings.scan_path(scan_id)
    (root / "site").mkdir(parents=True, exist_ok=True)
    (root / "site" / "app.js").write_text(
        'const token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";\n'
        "function render(x) { el.innerHTML = x; }\n"
    )
    db.add_files(scan_id, [{"path": "site/app.js", "kind": "code",
                            "language": "javascript", "bytes": 120, "lines": 2}])
    return scan_id, root


class Scripted:
    """Streams fixed replies, one character at a time, like Ollama does."""

    model = "scripted"

    def __init__(self, *turns):
        self.turns = list(turns)
        self.seen: list[list[dict]] = []

    async def stream_chat(self, messages, **kwargs):
        self.seen.append(messages)
        reply = self.turns.pop(0) if self.turns else "All done."
        for ch in reply:
            yield ch


async def run(scan_id, root, llm, message="do the thing"):
    events = []

    async def emit(kind, payload):
        events.append((kind, payload))

    result = await Conversation(scan_id, root, llm=llm, emit=emit).send(message)
    return result, events


# --------------------------------------------------------------------------- protocol
def test_args_parse_quoted_values():
    assert parse_args('path="a b.py" mode=w') == {"path": "a b.py", "mode": "w"}
    args = parse_args("scripts/x.py")
    assert args["path"] == "scripts/x.py"


def test_partial_fences_never_leak_into_prose():
    """Backticks arriving one token at a time must not surface as text."""
    parser = StreamParser()
    events = []
    for ch in 'ok\n```tool:run\nls\n```\nbye':
        events += parser.feed(ch)
    events += parser.flush()
    prose = "".join(v for k, v in events if k == "text")
    assert "`" not in prose
    assert prose.replace("\n", "") == "okbye"


# --------------------------------------------------------------------------- turns
@pytest.mark.asyncio
async def test_a_question_is_answered_without_touching_the_sandbox(workspace):
    scan_id, root = workspace
    llm = Scripted("Cross-site scripting means untrusted input reaches an HTML sink.")
    result, events = await run(scan_id, root, llm, "what is XSS?")

    assert "Cross-site scripting" in result["answer"]
    assert result["actions"] == 0
    assert not [k for k, _ in events if k.startswith("action_")]


@pytest.mark.asyncio
async def test_an_instruction_writes_and_runs_for_real(workspace):
    scan_id, root = workspace
    llm = Scripted(
        'Writing it now.\n'
        '```tool:write path="probe/check.py"\n'
        'print("executed for real")\n'
        '```\n',
        'Running it.\n```tool:run\npython3 probe/check.py\n```\n',
        'It printed what I expected.',
    )
    result, events = await run(scan_id, root, llm, "write a probe and run it")

    assert result["actions"] == 2
    results = [p for k, p in events if k == "action_result"]
    assert results[0]["ok"] and "probe/check.py" in results[0]["observation"]
    assert "executed for real" in results[1]["observation"]

    # the file really exists in the workspace
    assert (root / "workspace" / "probe" / "check.py").is_file()

    # and the body streamed rather than arriving in one lump
    assert len([k for k, _ in events if k == "action_delta"]) > 3


@pytest.mark.asyncio
async def test_the_models_output_is_fed_back_before_it_continues(workspace):
    scan_id, root = workspace
    llm = Scripted(
        '```tool:run\necho hello-from-the-sandbox\n```\n',
        'The command printed its greeting.',
    )
    await run(scan_id, root, llm)

    # the second request must contain the real observation
    second = llm.seen[1]
    joined = "\n".join(m["content"] for m in second)
    assert "hello-from-the-sandbox" in joined


@pytest.mark.asyncio
async def test_a_code_sample_is_not_executed(workspace):
    """```python is documentation. Only ```tool: blocks act."""
    scan_id, root = workspace
    llm = Scripted(
        'You could fix it like this:\n'
        '```python\n'
        'import os; os.system("rm -rf /")\n'
        '```\n'
        'That is the idea.'
    )
    result, events = await run(scan_id, root, llm)

    assert result["actions"] == 0
    assert not [k for k, _ in events if k == "action_result"]
    assert "rm -rf" in result["answer"]      # shown to the user, never run


@pytest.mark.asyncio
async def test_creating_a_directory_tree_of_any_file_type(workspace):
    scan_id, root = workspace
    llm = Scripted(
        '```tool:write path="reports/2024/summary.md"\n# Report\nAll clear.\n```\n',
        '```tool:write path="reports/2024/data.csv"\na,b\n1,2\n```\n',
        'Both files are in place.',
    )
    result, _ = await run(scan_id, root, llm)
    assert result["actions"] == 2
    ws = root / "workspace" / "reports" / "2024"
    assert (ws / "summary.md").read_text().startswith("# Report")
    assert (ws / "data.csv").read_text().strip() == "a,b\n1,2"


@pytest.mark.asyncio
async def test_history_and_findings_survive_the_turn(workspace):
    scan_id, root = workspace
    llm = Scripted(
        '```tool:finding title="Hard-coded GitHub token" severity="critical" '
        'path="site/app.js" line="1" cwe="CWE-798"\n'
        'The token ships to every visitor.\n```\n',
        'Recorded it.',
    )
    await run(scan_id, root, llm)

    findings = db.list_findings(scan_id)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["source"] == "agent"

    # the conversation itself is persisted, so a refresh can replay it
    messages = db.list_messages(scan_id)
    assert [m["role"] for m in messages] == ["user", "assistant"]
    assert messages[1]["meta"]["actions"] == 1


@pytest.mark.asyncio
async def test_model_outage_mid_turn_is_reported_not_raised(workspace):
    from app.analysis.llm import OllamaUnavailable

    scan_id, root = workspace

    class Dead:
        model = "dead"

        async def stream_chat(self, messages, **kwargs):
            raise OllamaUnavailable("connection refused")
            yield ""      # pragma: no cover — makes this an async generator

    result, _ = await run(scan_id, root, Dead())
    assert "lost the model" in result["answer"]


# --------------------------------------------------------------------------- editing
@pytest.mark.asyncio
async def test_edit_changes_only_the_matched_region(workspace):
    """Rewriting a whole file to change three lines is how a small model
    destroys the other three hundred — edit patches in place."""
    scan_id, root = workspace
    llm = Scripted(
        '```tool:edit path="site/app.js"\n'
        'function render(x) { el.innerHTML = x; }\n'
        '===\n'
        'function render(x) { el.textContent = x; }\n'
        '```\n',
        'Patched the sink.',
    )
    result, events = await run(scan_id, root, llm, "fix the xss")

    assert result["actions"] == 1
    assert [p for k, p in events if k == "action_result"][0]["ok"]

    after = (root / "workspace" / "site" / "app.js").read_text()
    assert "textContent" in after
    assert "innerHTML" not in after
    # the rest of the file survived
    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" in after


@pytest.mark.asyncio
async def test_edit_refuses_when_the_old_text_is_not_there(workspace):
    """Silently appending — or worse, replacing the wrong thing — would be
    much harder to notice than an error."""
    scan_id, root = workspace
    llm = Scripted(
        '```tool:edit path="site/app.js"\n'
        'this text does not exist in the file\n'
        '===\n'
        'replacement\n'
        '```\n',
        'Could not apply it.',
    )
    _, events = await run(scan_id, root, llm)
    result = [p for k, p in events if k == "action_result"][0]
    assert not result["ok"]
    assert "not in" in result["observation"]

    unchanged = (root / "workspace" / "site" / "app.js").read_text()
    assert "innerHTML" in unchanged


@pytest.mark.asyncio
async def test_the_agent_can_build_something_new(workspace):
    """Replit-shaped: ask for a feature, get files written and run."""
    scan_id, root = workspace
    llm = Scripted(
        'Adding a contact page.\n'
        '```tool:write path="site/contact.html"\n'
        '<!doctype html><title>Contact</title><h1>Contact us</h1>\n'
        '```\n',
        '```tool:run\nls site\n```\n',
        'Added `site/contact.html`.',
    )
    result, events = await run(scan_id, root, llm, "add a contact page")

    assert result["actions"] == 2
    assert (root / "workspace" / "site" / "contact.html").is_file()
    listing = [p for k, p in events if k == "action_result"][1]["observation"]
    assert "contact.html" in listing
