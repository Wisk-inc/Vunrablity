"""A real container holding the downloaded copy of the site.

Preferred backend is llm-sandbox (https://github.com/vndee/llm-sandbox), which
gives us managed sessions, language runtimes and artifact capture. If it is not
installed — or its API has drifted — we fall back to driving `docker` directly,
because "the sandbox is real" is not negotiable.

Isolation defaults, all overridable in .env:
  --network none      the copy is offline; the agent cannot touch the live site
  --memory 1g         a runaway script cannot take the host down
  --cpus 1.0
  --pids-limit 256    fork bombs stop at the wall
  read-only root      with a writable /work and /tmp
  --cap-drop ALL, --security-opt no-new-privileges
"""
from __future__ import annotations

import os
import shlex
import shutil
import sys
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..config import settings

WORKDIR = "/work"      # writable copy the agent may modify
MIRRORDIR = "/mirror"  # read-only original, mounted from the host


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class SandboxResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        parts = [p for p in (self.stdout.strip(), self.stderr.strip()) if p]
        return "\n".join(parts) or "(no output)"

    def as_dict(self) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
        }


MAX_OUTPUT = 40_000


class Sandbox:
    """One container per scan, started lazily, reused across chat turns."""

    _registry: dict[str, "Sandbox"] = {}
    _lock = threading.Lock()

    def __init__(self, scan_id: str, host_dir: Path):
        self.scan_id = scan_id
        self.host_dir = Path(host_dir)
        self.container: str | None = None
        self.backend: str | None = None
        self._session = None       # llm-sandbox session, when that path is used
        self._local = None         # LocalSandbox, when running without Docker
        # Reentrant: start() seeds the workspace via exec(), which calls
        # start() again to guarantee the container is up.
        self._start_lock = threading.RLock()

    # ------------------------------------------------------------------ registry
    @classmethod
    def get(cls, scan_id: str, host_dir: Path) -> "Sandbox":
        with cls._lock:
            box = cls._registry.get(scan_id)
            if box is None:
                box = cls(scan_id, host_dir)
                cls._registry[scan_id] = box
            return box

    @classmethod
    def shutdown_all(cls) -> None:
        with cls._lock:
            for box in list(cls._registry.values()):
                box.stop()
            cls._registry.clear()

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        if self.backend == "local":
            return self._local is not None and self._local.running
        if self.backend == "llm-sandbox":
            return self._session is not None
        if not self.container:
            return False
        out = _docker("inspect", "-f", "{{.State.Running}}", self.container, check=False)
        return out.stdout.strip() == "true"

    def start(self) -> None:
        """Bring the sandbox up. SANDBOX_BACKEND picks how.

        auto         Docker if a daemon is reachable, else the local backend
        docker       drive the docker CLI directly
        llm-sandbox  require vndee/llm-sandbox
        local        subprocess workspace, no daemon needed (Replit, plain hosts)
        none         refuse; sandbox features are disabled
        """
        backend = (settings.sandbox_backend or "auto").lower()
        if backend == "none":
            raise SandboxUnavailable(
                "Sandbox features are disabled (SANDBOX_BACKEND=none)."
            )

        with self._start_lock:
            if self.running:
                return

            if backend == "local":
                self._start_local()
                return

            if backend in ("auto", "llm-sandbox", "docker") and _docker_available():
                if backend in ("auto", "llm-sandbox") and self._try_llm_sandbox():
                    return
                if backend == "llm-sandbox":
                    raise SandboxUnavailable(
                        "llm-sandbox could not open a session. Install it "
                        "(`pip install 'llm-sandbox[docker]'`) or set "
                        "SANDBOX_BACKEND=local."
                    )
                self._start_docker()
                return

            if backend == "auto":
                # No daemon — this is the Replit/plain-host path, and it is a
                # supported configuration rather than a failure.
                self._start_local()
                return

            raise SandboxUnavailable(
                "Docker is not reachable. Start the daemon, or set "
                "SANDBOX_BACKEND=local to run without one."
            )

    def _start_local(self) -> None:
        from .local import LocalSandbox

        self._local = LocalSandbox(self.scan_id, self.host_dir)
        self._local.start()
        self.backend = "local"

    def _try_llm_sandbox(self) -> bool:
        """Use vndee/llm-sandbox when it is importable and its API matches."""
        try:
            from llm_sandbox import SandboxSession  # type: ignore
        except Exception:
            return False
        try:
            kwargs = {
                "lang": "python",
                "image": settings.sandbox_image,
                "keep_template": True,
                "verbose": False,
            }
            try:
                from llm_sandbox import SandboxBackend  # type: ignore
                kwargs["backend"] = SandboxBackend.DOCKER
            except Exception:
                pass

            session = SandboxSession(**kwargs)
            session.open()
            self._session = session
            self.backend = "llm-sandbox"
            self.container = getattr(getattr(session, "container", None), "id", None)
            self._seed_llm_sandbox()
            return True
        except Exception:
            self._session = None
            return False

    def _seed_llm_sandbox(self) -> None:
        """Copy the mirror into the managed session."""
        session = self._session
        for name in ("copy_to_runtime", "copy_to_container"):
            fn = getattr(session, name, None)
            if not fn:
                continue
            try:
                fn(str(self.host_dir), WORKDIR)
                return
            except Exception:
                continue
        # If the helper is missing, fall back to `docker cp`.
        if self.container:
            _docker("cp", f"{self.host_dir}/.", f"{self.container}:{WORKDIR}", check=False)

    def _start_docker(self) -> None:
        name = f"vunrablity-{self.scan_id}-{uuid.uuid4().hex[:6]}"
        image = settings.sandbox_image

        if not _image_present(image):
            pull = _docker("pull", image, check=False, timeout=600)
            if pull.returncode != 0:
                raise SandboxUnavailable(
                    f"Could not pull `{image}`: {pull.stderr.strip()[:300]}"
                )

        # The host copy is mounted read-only at /mirror and duplicated into a
        # writable tmpfs at /work. The agent gets a full read-write workspace it
        # can break freely, while the downloaded evidence stays pristine.
        args = [
            "run", "-d", "--name", name,
            "--network", settings.sandbox_network,
            "--memory", settings.sandbox_memory,
            "--cpus", str(settings.sandbox_cpus),
            "--pids-limit", "256",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,exec,size=256m",
            "--tmpfs", f"{WORKDIR}:rw,exec,size={settings.sandbox_workdir_size}",
            "-v", f"{self.host_dir}:{MIRRORDIR}:ro",
            "-w", WORKDIR,
            image, "sleep", "infinity",
        ]
        proc = _docker(*args, check=False)
        if proc.returncode != 0:
            raise SandboxUnavailable(f"docker run failed: {proc.stderr.strip()[:300]}")

        self.container = name
        self.backend = "docker"
        self._seed_workdir()

    def _seed_workdir(self) -> None:
        """Copy the read-only mirror into the writable workspace."""
        seeded = self.exec(
            f"cp -a {MIRRORDIR}/. {WORKDIR}/ 2>/dev/null; ls -A {WORKDIR} | head -1"
        )
        if seeded.stdout.strip():
            return
        # Bind mount unavailable (remote daemon?) — stream a tar in over stdin.
        self._copy_in_via_tar()

    def _copy_in_via_tar(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
            tar_path = tmp.name
        try:
            with tarfile.open(tar_path, "w") as tar:
                for entry in sorted(self.host_dir.iterdir()):
                    tar.add(entry, arcname=entry.name)
            with open(tar_path, "rb") as fh:
                _docker_stdin(
                    ["exec", "-i", str(self.container), "sh", "-lc",
                     f"tar -xf - -C {WORKDIR}"],
                    fh.read(),
                )
        finally:
            os.unlink(tar_path)

    def stop(self) -> None:
        if self._local is not None:
            self._local.stop()
            self._local = None
            self.backend = None
            return
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None
        if self.container and self.backend == "docker":
            _docker("rm", "-f", self.container, check=False)
        self.container = None
        self.backend = None

    # ------------------------------------------------------------------ exec
    def exec(self, command: str, timeout: int | None = None) -> SandboxResult:
        """Run a shell command inside the sandbox."""
        self.start()
        timeout = timeout or settings.sandbox_timeout

        if self.backend == "local" and self._local is not None:
            return self._local.exec(command, timeout)

        if self.backend == "llm-sandbox" and self._session is not None:
            result = self._exec_llm_sandbox(command, timeout)
            if result is not None:
                return result

        if not self.container:
            raise SandboxUnavailable("sandbox container is not running")

        proc = _docker(
            "exec", self.container, "sh", "-lc", command,
            check=False, timeout=timeout,
        )
        return _clip_result(command, proc.returncode, proc.stdout, proc.stderr)

    def _exec_llm_sandbox(self, command: str, timeout: int) -> SandboxResult | None:
        session = self._session
        fn = getattr(session, "execute_command", None)
        if fn is None:
            return None
        try:
            raw = fn(command)
        except Exception as exc:
            return SandboxResult(command, 1, "", f"{type(exc).__name__}: {exc}")
        exit_code = getattr(raw, "exit_code", 0) or 0
        stdout = getattr(raw, "stdout", None)
        stderr = getattr(raw, "stderr", "") or ""
        if stdout is None:
            stdout = getattr(raw, "text", None) or str(raw)
        return _clip_result(command, int(exit_code), str(stdout), str(stderr))

    def run_python(self, code: str, timeout: int | None = None) -> SandboxResult:
        """Execute a Python program inside the sandbox."""
        self.start()
        if self.backend == "local" and self._local is not None:
            return self._local.run_python(code, timeout)
        script = f"/tmp/vunrablity_{uuid.uuid4().hex[:8]}.py"
        self.write_file(script, code, absolute=True)
        return self.exec(f"python3 {shlex.quote(script)}", timeout=timeout)

    # ------------------------------------------------------------------ files
    def write_file(self, path: str, content: str, absolute: bool = False) -> SandboxResult:
        """Write a file inside the container by streaming it over stdin.

        `docker cp` is refused when the container's root filesystem is
        read-only, so the bytes go in through the shell instead.
        """
        self.start()
        if self.backend == "local" and self._local is not None:
            return self._local.write_file(path, content, absolute)

        target = path if absolute else f"{WORKDIR}/{path.lstrip('/')}"
        parent = os.path.dirname(target) or "/"

        if not self.container:
            fn = getattr(self._session, "copy_to_runtime", None)
            if fn is None:
                return SandboxResult(f"write {target}", 1, "",
                                     "no write path available for this backend")
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                             encoding="utf-8") as tmp:
                tmp.write(content)
                local = tmp.name
            try:
                fn(local, target)
                return SandboxResult(f"write {target}", 0,
                                     f"wrote {len(content)} bytes", "")
            finally:
                os.unlink(local)

        proc = _docker_stdin(
            ["exec", "-i", self.container, "sh", "-lc",
             f"mkdir -p {shlex.quote(parent)} && cat > {shlex.quote(target)}"],
            content.encode("utf-8"),
        )
        if proc.returncode != 0:
            return SandboxResult(f"write {target}", proc.returncode, "",
                                 proc.stderr or "write failed")
        return SandboxResult(f"write {target}", 0, f"wrote {len(content)} bytes", "")

    def read_file(self, path: str, start: int = 1, end: int | None = None) -> str:
        # Without this the backend is still unset on the first call, so a local
        # sandbox would be read through the container path and find nothing.
        self.start()
        if self.backend == "local" and self._local is not None:
            return self._local.read_file(path, start, end)
        target = f"{WORKDIR}/{path.lstrip('/')}"
        end = end or start + 400
        cmd = f"sed -n '{max(1, start)},{max(start, end)}p' {shlex.quote(target)}"
        return self.exec(cmd).output

    # ------------------------------------------------------------------ services
    def start_service(self, command: str, name: str | None = None,
                      port: int | None = None) -> dict:
        """Run something that keeps running — a dev server, a watcher.

        The agent uses this to actually *serve* the mirrored site so it can be
        previewed and clicked through, instead of only reading it as text.
        """
        self.start()
        if self.backend == "local" and self._local is not None:
            return self._local.start_service(command, name, port).as_dict()

        # Container backends: run it detached inside the container.
        name = name or f"svc-{int(time.time())}"
        log = f"/tmp/{name}.log"
        self.exec(f"nohup sh -lc {shlex.quote(command)} > {log} 2>&1 & echo $!")
        return {"name": name, "command": command, "port": port,
                "running": True, "log": log, "pid": None}

    def kill_service(self, name: str) -> bool:
        if self.backend == "local" and self._local is not None:
            return self._local.kill_service(name)
        self.exec(f"pkill -f {shlex.quote(name)} || true")
        return True

    def service_log(self, name: str, tail: int = 200) -> str:
        if self.backend == "local" and self._local is not None:
            return self._local.service_log(name, tail)
        return self.exec(f"tail -n {tail} /tmp/{name}.log 2>/dev/null").output

    def services(self) -> list[dict]:
        if self.backend == "local" and self._local is not None:
            return [s.as_dict() for s in self._local.services.values()]
        return []

    # ------------------------------------------------------------------ packages
    def install(self, packages: str, manager: str = "pip") -> SandboxResult:
        """Install dependencies the agent decides it needs."""
        self.start()
        pkgs = " ".join(shlex.quote(p) for p in packages.split() if p)
        if not pkgs:
            return SandboxResult("install", 1, "", "no packages given")
        commands = {
            "pip": f"{shlex.quote(sys.executable)} -m pip install --quiet {pkgs}",
            "npm": f"npm install --no-fund --no-audit {pkgs}",
            "apt": f"apt-get install -y {pkgs}",
        }
        cmd = commands.get(manager, commands["pip"])
        return self.exec(cmd, timeout=600)

    # ------------------------------------------------------------------ tree
    def tree(self, sub: str = "", depth: int = 4, limit: int = 4000) -> list[dict]:
        """List the workspace so the UI can render a real file explorer."""
        self.start()
        root = self.workspace_path
        if root is None:
            listing = self.exec(
                f"find {WORKDIR}/{sub} -maxdepth {depth} -printf '%y\\t%s\\t%P\\n' "
                f"2>/dev/null | head -{limit}"
            )
            out = []
            for line in listing.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 3:
                    out.append({"type": "dir" if parts[0] == "d" else "file",
                                "bytes": int(parts[1] or 0), "path": parts[2]})
            return out

        base = (root / sub).resolve() if sub else root
        try:
            base.relative_to(root)
        except ValueError:
            return []
        out = []
        for path in sorted(base.rglob("*")):
            rel = path.relative_to(root)
            if len(rel.parts) > depth:
                continue
            if any(part in (".git", "__pycache__", "node_modules") for part in rel.parts):
                continue
            try:
                out.append({
                    "type": "dir" if path.is_dir() else "file",
                    "bytes": path.stat().st_size if path.is_file() else 0,
                    "path": str(rel),
                })
            except OSError:
                continue
            if len(out) >= limit:
                break
        return out

    @property
    def workspace_path(self):
        """Host-side path of the agent's workspace, when there is one."""
        if self.backend == "local" and self._local is not None:
            return self._local.workdir
        return None

    def info(self) -> dict:
        if self.backend == "local" and self._local is not None:
            return self._local.info()
        return {
            "running": self.running,
            "backend": self.backend,
            "container": self.container,
            "image": settings.sandbox_image,
            "network": settings.sandbox_network,
            "workdir": WORKDIR,
            "mirror": MIRRORDIR,
        }


# --------------------------------------------------------------------------- docker
def _docker(*args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", *args],
            capture_output=True, text=True, timeout=timeout, check=check,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", f"timed out after {timeout}s")
    except FileNotFoundError as exc:
        raise SandboxUnavailable("`docker` is not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(args, exc.returncode, exc.stdout, exc.stderr)


def _docker_stdin(args: list[str], payload: bytes,
                  timeout: int = 300) -> subprocess.CompletedProcess:
    """Run `docker ...` feeding `payload` to the container process' stdin.

    Used instead of `docker cp`, which the daemon refuses when the container
    root filesystem is read-only.
    """
    try:
        proc = subprocess.run(
            ["docker", *args],
            input=payload, capture_output=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", f"timed out after {timeout}s")
    except FileNotFoundError as exc:
        raise SandboxUnavailable("`docker` is not on PATH") from exc
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return _docker("info", "--format", "{{.ServerVersion}}",
                   check=False, timeout=20).returncode == 0


def _image_present(image: str) -> bool:
    return _docker("image", "inspect", image, check=False, timeout=30).returncode == 0


def _clip_result(command: str, code: int, stdout: str, stderr: str) -> SandboxResult:
    truncated = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
    return SandboxResult(
        command=command,
        exit_code=code,
        stdout=stdout[:MAX_OUTPUT],
        stderr=stderr[:MAX_OUTPUT],
        truncated=truncated,
    )
