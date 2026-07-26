"""The sandbox has to be a real container with the real mirror inside it.

These tests are skipped when Docker (or the configured image) is unavailable.
Set VUNRABLITY_TEST_IMAGE to run them against something other than the default.
"""
from __future__ import annotations

import os

import pytest

from app.config import settings
from app.sandbox import Sandbox, SandboxUnavailable
from app.sandbox.runner import _docker_available, _image_present

IMAGE = os.environ.get("VUNRABLITY_TEST_IMAGE", settings.sandbox_image)

pytestmark = pytest.mark.skipif(
    not _docker_available() or not _image_present(IMAGE),
    reason=f"docker or image {IMAGE!r} unavailable",
)


@pytest.fixture()
def box(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "sandbox_image", IMAGE)
    # Drive the docker CLI directly: llm-sandbox builds its own template image,
    # which needs registry access these tests should not depend on.
    monkeypatch.setattr(settings, "sandbox_backend", "docker")
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "app.js").write_text(
        'const key = "sk_live_deadbeef";\nfunction go(x) { return eval(x); }\n'
    )
    (tmp_path / "notes.txt").write_text("hello from the mirror\n")

    sandbox = Sandbox("test-scan", tmp_path)
    try:
        yield sandbox
    finally:
        sandbox.stop()


def test_container_starts_and_runs_commands(box):
    box.start()
    assert box.running
    assert box.backend in ("docker", "llm-sandbox")

    result = box.exec("echo hello")
    assert result.exit_code == 0
    assert "hello" in result.stdout


def test_the_downloaded_site_is_inside_the_container(box):
    listing = box.exec("ls /work && cat /work/notes.txt")
    assert "notes.txt" in listing.output
    assert "hello from the mirror" in listing.output

    grep = box.exec("grep -rn 'sk_live' /work")
    assert "app.js" in grep.output


def test_agent_can_execute_a_flagged_file(box):
    """The point of the sandbox: run the code you flagged and watch it behave."""
    result = box.run_python(r"""
import re, pathlib
src = pathlib.Path("/work/site/app.js").read_text()
print("EVAL_PRESENT", bool(re.search(r"\beval\(", src)))
print("SECRET", re.findall(r"sk_live_\w+", src))
""")
    assert result.exit_code == 0
    assert "EVAL_PRESENT True" in result.stdout
    assert "sk_live_deadbeef" in result.stdout


def test_writes_land_in_the_container(box):
    box.write_file("probe/check.py", "print('written and executed')")
    result = box.exec("python3 /work/probe/check.py")
    assert "written and executed" in result.output


def test_failing_commands_report_their_exit_code(box):
    result = box.exec("exit 3")
    assert result.exit_code == 3
    assert not result.ok


def test_the_container_has_no_network(box):
    """A no-network sandbox cannot be turned on the live site."""
    if settings.sandbox_network != "none":
        pytest.skip("sandbox network isolation disabled by config")
    result = box.exec(
        "python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), 3)\""
    )
    assert result.exit_code != 0


def test_registry_reuses_one_container_per_scan(tmp_path):
    a = Sandbox.get("same-scan", tmp_path)
    b = Sandbox.get("same-scan", tmp_path)
    assert a is b
    Sandbox.shutdown_all()


def test_missing_docker_raises_a_useful_error(tmp_path, monkeypatch):
    monkeypatch.setattr("app.sandbox.runner._docker_available", lambda: False)
    sandbox = Sandbox("no-docker", tmp_path)
    with pytest.raises(SandboxUnavailable) as exc:
        sandbox.start()
    assert "Docker" in str(exc.value)
