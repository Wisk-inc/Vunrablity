"""The Docker-free sandbox — the backend Replit actually uses.

No skips here: these run anywhere Python does, which is the point of the
backend existing.
"""
from __future__ import annotations

import time

import pytest

from app.config import settings
from app.sandbox import Sandbox


@pytest.fixture()
def box(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "sandbox_backend", "local")
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "app.js").write_text('const k = "sk_live_deadbeef";\n')
    sandbox = Sandbox(f"local-{time.time_ns()}", tmp_path)
    try:
        yield sandbox
    finally:
        sandbox.stop()


def test_it_starts_without_docker(box):
    box.start()
    assert box.running
    assert box.backend == "local"
    assert box.exec("echo hello").stdout.strip() == "hello"


def test_the_mirror_is_seeded_into_the_workspace(box):
    box.start()
    assert "app.js" in box.exec("ls site").output
    assert "sk_live_deadbeef" in box.exec("grep -rn sk_live site").output


def test_the_original_download_is_never_modified(box):
    """The agent works on a copy; the evidence on disk stays pristine."""
    box.start()
    box.exec("echo 'tampered' > site/app.js")
    assert "tampered" in box.read_file("site/app.js")
    original = (box.host_dir / "site" / "app.js").read_text()
    assert "sk_live_deadbeef" in original and "tampered" not in original


def test_it_creates_directories_and_runs_what_it_wrote(box):
    box.write_file("deep/nested/probe.py", "print('nested run works')")
    assert "nested run works" in box.exec("python3 deep/nested/probe.py").output


def test_any_file_format_is_allowed(box):
    for path, body in [("a.rs", "fn main(){}"), ("b.toml", "x = 1"),
                       ("c/d.yaml", "k: v"), ("weird.what", "anything")]:
        assert box.write_file(path, body).ok
    tree = {t["path"] for t in box.tree()}
    assert {"a.rs", "b.toml", "c/d.yaml", "weird.what"} <= tree


def test_paths_cannot_escape_the_workspace(box):
    box.start()
    with pytest.raises(ValueError):
        box._local._resolve("../../etc/passwd")


def test_a_runaway_command_is_killed(box):
    result = box.exec("sleep 30", timeout=2)
    assert result.exit_code != 0
    assert "killed" in result.stderr.lower() or result.exit_code == 124


def test_exit_codes_are_reported(box):
    assert box.exec("exit 7").exit_code == 7
    assert not box.exec("exit 7").ok


def test_it_can_serve_and_be_stopped(box):
    import urllib.request

    box.write_file("public/index.html", "<h1>served</h1>")
    service = box.start_service("python3 -m http.server 8794 --directory public",
                                name="prev", port=8794)
    assert service["running"]
    try:
        deadline = time.time() + 8
        body = ""
        while time.time() < deadline:
            try:
                body = urllib.request.urlopen(
                    "http://127.0.0.1:8794/index.html", timeout=2).read().decode()
                break
            except Exception:
                time.sleep(0.25)
        assert "served" in body, "the agent's server never came up"
    finally:
        assert box.kill_service("prev")


def test_service_output_is_captured(box):
    box.start_service("echo starting-up; sleep 5", name="noisy")
    time.sleep(0.6)
    assert "starting-up" in box.service_log("noisy")
    box.kill_service("noisy")


def test_info_states_its_isolation_honestly(box):
    box.start()
    info = box.info()
    assert info["backend"] == "local"
    # The weaker isolation is disclosed rather than glossed over.
    assert "not a container" in info["isolation"]
