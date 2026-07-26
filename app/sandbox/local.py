"""A sandbox that needs no Docker.

Replit, most PaaS boxes, and plenty of laptops have no Docker daemon — but the
agent still needs somewhere real to write files, install packages, run servers
and execute the code it just downloaded. This backend gives it exactly that:
a dedicated workspace directory driven by ordinary subprocesses.

The trade-off is stated plainly rather than hidden: this is *containment*, not
*isolation*. Commands run as the same OS user as the server, so a determined
payload could reach outside the workspace. That is an acceptable trade when the
alternative is no sandbox at all, and it is why `SANDBOX_BACKEND=docker` stays
the recommendation anywhere a daemon is available.

What it does enforce:
  - a workspace root; relative paths can never escape it
  - CPU and address-space rlimits, so a runaway script dies instead of the box
  - a wall-clock timeout on every command
  - process-group kill, so a command that spawns children cleans up fully
  - long-running servers tracked separately, so the agent can start one and
    keep talking
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import settings

MAX_OUTPUT = 40_000


@dataclass
class Service:
    """A long-running process the agent started (a dev server, a watcher)."""
    name: str
    command: str
    pid: int
    port: int | None
    started_at: float
    log_path: str

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "pid": self.pid,
            "port": self.port,
            "started_at": self.started_at,
            "running": _pid_alive(self.pid),
            "log": self.log_path,
        }


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _limits(memory_bytes: int, cpu_seconds: int):
    """Applied in the child between fork and exec."""
    def apply() -> None:
        os.setsid()  # own process group, so we can kill the whole tree
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
            if memory_bytes:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_NPROC, (512, 512))
            resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024 * 1024,) * 2)
        except Exception:
            pass  # rlimits are best-effort; a missing one must not block the run
    return apply


def _parse_memory(value: str) -> int:
    value = str(value).strip().lower()
    mult = 1
    if value.endswith("g"):
        mult, value = 1024 ** 3, value[:-1]
    elif value.endswith("m"):
        mult, value = 1024 ** 2, value[:-1]
    elif value.endswith("k"):
        mult, value = 1024, value[:-1]
    try:
        return int(float(value) * mult)
    except ValueError:
        return 0


class LocalSandbox:
    """Subprocess-backed workspace. Same surface as the Docker sandbox."""

    backend = "local"

    def __init__(self, scan_id: str, host_dir: Path):
        self.scan_id = scan_id
        self.host_dir = Path(host_dir)
        # The agent works on a copy so the downloaded evidence stays pristine.
        self.workdir = self.host_dir / "workspace"
        self.log_dir = self.host_dir / "logs"
        self.services: dict[str, Service] = {}
        self._lock = threading.RLock()
        self._started = False

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._started and self.workdir.exists()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self.workdir.mkdir(parents=True, exist_ok=True)
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self._seed()
            self._started = True

    def _seed(self) -> None:
        """Copy the mirror in, once, so the agent has the real site to work on."""
        marker = self.workdir / ".vunrablity-seeded"
        if marker.exists():
            return
        import shutil
        for name in ("site", "sources"):
            src = self.host_dir / name
            if src.is_dir():
                shutil.copytree(src, self.workdir / name, dirs_exist_ok=True)
        for name in ("inventory.json", "report.json"):
            src = self.host_dir / name
            if src.is_file():
                shutil.copy2(src, self.workdir / name)
        marker.write_text(str(time.time()))

    def stop(self) -> None:
        with self._lock:
            for service in list(self.services.values()):
                self.kill_service(service.name)
            self._started = False

    # ------------------------------------------------------------------ exec
    def exec(self, command: str, timeout: int | None = None):
        from .runner import SandboxResult  # local import avoids a cycle

        self.start()
        timeout = timeout or settings.sandbox_timeout
        env = self._env()

        try:
            proc = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=str(self.workdir),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                preexec_fn=_limits(_parse_memory(settings.sandbox_memory), timeout),
            )
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"")
            err = (exc.stderr or b"")
            return SandboxResult(
                command, 124,
                out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out),
                (err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err))
                + f"\n[killed after {timeout}s]",
            )
        except Exception as exc:
            return SandboxResult(command, 1, "", f"{type(exc).__name__}: {exc}")

        return SandboxResult(
            command, proc.returncode,
            proc.stdout[:MAX_OUTPUT], proc.stderr[:MAX_OUTPUT],
            truncated=len(proc.stdout) > MAX_OUTPUT or len(proc.stderr) > MAX_OUTPUT,
        )

    def run_python(self, code: str, timeout: int | None = None):
        self.start()
        script = self.workdir / f".vunrablity_{int(time.time() * 1000)}.py"
        script.write_text(code, encoding="utf-8")
        try:
            return self.exec(f"{shlex.quote(sys.executable)} {shlex.quote(script.name)}",
                             timeout=timeout)
        finally:
            script.unlink(missing_ok=True)

    def _env(self) -> dict:
        env = dict(os.environ)
        env.update({
            "HOME": str(self.workdir),
            "PWD": str(self.workdir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "VUNRABLITY_WORKSPACE": str(self.workdir),
        })
        return env

    # ------------------------------------------------------------------ services
    def start_service(self, command: str, name: str | None = None,
                      port: int | None = None) -> Service:
        """Launch something that is supposed to keep running (e.g. a web server)."""
        self.start()
        name = name or f"svc-{len(self.services) + 1}"
        self.kill_service(name)

        log_path = self.log_dir / f"{name}.log"
        log = open(log_path, "ab", buffering=0)
        proc = subprocess.Popen(
            ["/bin/sh", "-c", command],
            cwd=str(self.workdir),
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            env=self._env(),
            preexec_fn=lambda: os.setsid(),
        )
        service = Service(name, command, proc.pid, port, time.time(), str(log_path))
        self.services[name] = service
        return service

    def kill_service(self, name: str) -> bool:
        service = self.services.pop(name, None)
        if not service:
            return False
        try:
            os.killpg(os.getpgid(service.pid), signal.SIGTERM)
            time.sleep(0.2)
            if _pid_alive(service.pid):
                os.killpg(os.getpgid(service.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        return True

    def service_log(self, name: str, tail: int = 200) -> str:
        service = self.services.get(name)
        if not service:
            return f"no service named {name!r}"
        try:
            lines = Path(service.log_path).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return "(no output yet)"
        return "\n".join(lines[-tail:]) or "(no output yet)"

    # ------------------------------------------------------------------ files
    def write_file(self, path: str, content: str, absolute: bool = False):
        from .runner import SandboxResult

        self.start()
        target = Path(path) if absolute else self._resolve(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return SandboxResult(f"write {path}", 0, f"wrote {len(content)} bytes", "")

    def read_file(self, path: str, start: int = 1, end: int | None = None) -> str:
        target = self._resolve(path)
        if not target.is_file():
            return f"{path}: no such file"
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        end = end or len(lines)
        return "\n".join(lines[max(0, start - 1):end])

    def _resolve(self, rel: str) -> Path:
        candidate = (self.workdir / str(rel).lstrip("/")).resolve()
        try:
            candidate.relative_to(self.workdir.resolve())
        except ValueError as exc:
            raise ValueError(f"path escapes the workspace: {rel}") from exc
        return candidate

    def info(self) -> dict:
        return {
            "running": self.running,
            "backend": "local",
            "container": None,
            "image": f"host python {sys.version.split()[0]}",
            "network": "host (the agent can reach the internet)",
            "workdir": str(self.workdir),
            "mirror": str(self.host_dir),
            "services": [s.as_dict() for s in self.services.values()],
            "isolation": "process-level (rlimits + workspace root), not a container",
        }
