"""Execution of the streamed action blocks.

One class, one method per tool. Everything runs against the sandbox workspace,
so the agent can create directories, write files in any format, run them,
install packages, start servers, and pull code off GitHub — the same shape of
capability a Replit-style agent has, pointed at auditing.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
from pathlib import Path

from .. import db
from ..analysis import severity as sev
from ..analysis.memory import ScanMemory
from ..config import settings
from ..sandbox import Sandbox, SandboxUnavailable

MAX_OBSERVATION = 8_000


class ActionRunner:
    def __init__(self, scan_id: str, root: Path, memory: ScanMemory):
        self.scan_id = scan_id
        self.root = Path(root)
        self.memory = memory
        self.sandbox = Sandbox.get(scan_id, self.root)
        self.new_findings: list[dict] = []
        self.touched: list[str] = []

    # ------------------------------------------------------------------ dispatch
    async def run(self, tool: str, args: dict, body: str) -> dict:
        """Returns {ok, observation, meta} — meta drives the UI chip."""
        handler = getattr(self, f"_do_{tool}", None)
        if handler is None:
            return self._err(f"unknown action {tool!r}")
        try:
            return handler(args or {}, body or "")
        except SandboxUnavailable as exc:
            return self._err(f"sandbox unavailable: {exc}")
        except Exception as exc:
            return self._err(f"{type(exc).__name__}: {exc}")

    def _ok(self, observation: str, **meta) -> dict:
        return {"ok": True, "observation": _clip(observation), "meta": meta}

    def _err(self, message: str, **meta) -> dict:
        return {"ok": False, "observation": f"ERROR: {message}", "meta": meta}

    # ------------------------------------------------------------------ files
    def _do_write(self, args: dict, body: str) -> dict:
        path = args.get("path")
        if not path:
            return self._err('write needs path="..."')
        result = self.sandbox.write_file(path, body)
        if not result.ok:
            return self._err(result.output, path=path)
        self.touched.append(path)
        lines = body.count("\n") + 1
        return self._ok(f"wrote {path} ({len(body)} bytes, {lines} lines)",
                        path=path, bytes=len(body), lines=lines, action="write")

    def _do_append(self, args: dict, body: str) -> dict:
        path = args.get("path")
        if not path:
            return self._err('append needs path="..."')
        existing = self.sandbox.read_file(path)
        if existing.endswith("no such file"):
            existing = ""
        merged = (existing.rstrip("\n") + "\n" + body) if existing else body
        self.sandbox.write_file(path, merged)
        self.touched.append(path)
        return self._ok(f"appended {len(body)} bytes to {path}",
                        path=path, action="append")

    def _do_read(self, args: dict, body: str) -> dict:
        path = args.get("path") or body.strip()
        if not path:
            return self._err('read needs path="..."')
        start = _int(args.get("start"), 1)
        end = _int(args.get("end"), start + 300)
        text = self.sandbox.read_file(path, start, end)
        numbered = "\n".join(
            f"{start + i:>5} | {line}" for i, line in enumerate(text.splitlines())
        )
        return self._ok(numbered or "(empty)", path=path, action="read")

    def _do_mkdir(self, args: dict, body: str) -> dict:
        path = args.get("path") or body.strip()
        if not path:
            return self._err("mkdir needs a path")
        result = self.sandbox.exec(f"mkdir -p {shlex.quote(path)}")
        return self._ok(f"created directory {path}" if result.ok else result.output,
                        path=path, action="mkdir")

    def _do_move(self, args: dict, body: str) -> dict:
        src, dst = args.get("path"), args.get("to")
        if not src or not dst:
            return self._err('move needs path="..." to="..."')
        result = self.sandbox.exec(
            f"mkdir -p $(dirname {shlex.quote(dst)}) && "
            f"mv {shlex.quote(src)} {shlex.quote(dst)}")
        self.touched.append(dst)
        return self._ok(f"moved {src} -> {dst}" if result.ok else result.output,
                        path=dst, action="move")

    def _do_copy(self, args: dict, body: str) -> dict:
        src, dst = args.get("path"), args.get("to")
        if not src or not dst:
            return self._err('copy needs path="..." to="..."')
        result = self.sandbox.exec(
            f"mkdir -p $(dirname {shlex.quote(dst)}) && "
            f"cp -r {shlex.quote(src)} {shlex.quote(dst)}")
        return self._ok(f"copied {src} -> {dst}" if result.ok else result.output,
                        path=dst, action="copy")

    def _do_delete(self, args: dict, body: str) -> dict:
        path = args.get("path") or body.strip()
        if not path or path in ("/", "."):
            return self._err("refusing to delete the workspace root")
        result = self.sandbox.exec(f"rm -rf {shlex.quote(path)}")
        return self._ok(f"deleted {path}" if result.ok else result.output,
                        path=path, action="delete")

    # ------------------------------------------------------------------ search
    def _do_list(self, args: dict, body: str) -> dict:
        pattern = args.get("pattern") or body.strip() or "**/*"
        rows = db.list_files(self.scan_id)
        matched = [r["path"] for r in rows
                   if fnmatch.fnmatch(r["path"], pattern)
                   or fnmatch.fnmatch(r["path"].rsplit("/", 1)[-1], pattern)]
        if not matched:
            matched = [t["path"] for t in self.sandbox.tree()
                       if fnmatch.fnmatch(t["path"], pattern)]
        return self._ok("\n".join(matched[:300]) or f"nothing matches {pattern}",
                        action="list")

    def _do_tree(self, args: dict, body: str) -> dict:
        entries = self.sandbox.tree(args.get("path", ""), _int(args.get("depth"), 3))
        lines = [("📁 " if e["type"] == "dir" else "   ") + e["path"]
                 for e in entries[:400]]
        return self._ok("\n".join(lines) or "(empty workspace)", action="tree")

    def _do_grep(self, args: dict, body: str) -> dict:
        pattern = args.get("pattern") or body.strip()
        if not pattern:
            return self._err("grep needs a pattern")
        glob = args.get("glob", "*")
        result = self.sandbox.exec(
            f"grep -rn --binary-files=without-match --include={shlex.quote(glob)} "
            f"-E {shlex.quote(pattern)} . 2>/dev/null | head -80"
        )
        return self._ok(result.stdout or f"no match for {pattern}", action="grep")

    # ------------------------------------------------------------------ execute
    def _do_run(self, args: dict, body: str) -> dict:
        command = body.strip() or args.get("_positional", "")
        if not command:
            return self._err("run needs a command")
        result = self.sandbox.exec(command, _int(args.get("timeout"), 0) or None)
        return self._ok(f"$ {command}\n(exit {result.exit_code})\n{result.output}",
                        action="run", exit_code=result.exit_code)

    _do_bash = _do_sh = _do_run

    def _do_python(self, args: dict, body: str) -> dict:
        if not body.strip():
            return self._err("python needs code")
        result = self.sandbox.run_python(body)
        return self._ok(f"(exit {result.exit_code})\n{result.output}",
                        action="python", exit_code=result.exit_code)

    def _do_node(self, args: dict, body: str) -> dict:
        path = f".vunrablity_{abs(hash(body)) % 10**8}.js"
        self.sandbox.write_file(path, body)
        result = self.sandbox.exec(f"node {shlex.quote(path)}")
        self.sandbox.exec(f"rm -f {shlex.quote(path)}")
        return self._ok(f"(exit {result.exit_code})\n{result.output}", action="node")

    def _do_install(self, args: dict, body: str) -> dict:
        packages = (args.get("_positional") or body).strip()
        manager = args.get("manager", "pip")
        if not packages:
            return self._err("install needs package names")
        result = self.sandbox.install(packages, manager)
        return self._ok(f"{manager} install {packages}\n(exit {result.exit_code})\n"
                        f"{result.output[-1500:]}", action="install")

    def _do_fetch(self, args: dict, body: str) -> dict:
        """Pull something off the internet — a GitHub repo, a reference file."""
        url = args.get("url") or args.get("path") or body.strip()
        if not url:
            return self._err("fetch needs a url")
        dest = args.get("to", "")
        if url.endswith(".git") or "github.com" in url and not url.endswith((".py", ".js", ".json", ".txt", ".md")):
            target = dest or re.sub(r"\W+", "-", url.rstrip("/").split("/")[-1])
            result = self.sandbox.exec(
                f"git clone --depth 1 {shlex.quote(url)} {shlex.quote(target)}",
                timeout=300)
            return self._ok(f"cloned into {target}\n{result.output[-1200:]}",
                            path=target, action="fetch")
        target = dest or url.rstrip("/").split("/")[-1] or "download"
        result = self.sandbox.exec(
            f"curl -fsSL {shlex.quote(url)} -o {shlex.quote(target)} && "
            f"wc -c {shlex.quote(target)}", timeout=180)
        return self._ok(result.output, path=target, action="fetch")

    # ------------------------------------------------------------------ services
    def _do_serve(self, args: dict, body: str) -> dict:
        """Start a server so the mirrored site can actually be clicked through."""
        port = _int(args.get("port"), settings.preview_ports[0]
                    if settings.preview_ports else 8080)
        directory = args.get("path", ".")
        name = args.get("name", f"preview-{port}")
        command = body.strip() or (
            f"python3 -m http.server {port} --directory {shlex.quote(directory)}")
        service = self.sandbox.start_service(command, name=name, port=port)
        return self._ok(
            f"started `{name}` on port {port}\n{command}\n"
            f"Open the Preview panel to click through it.",
            action="serve", port=port, name=name, service=service)

    def _do_stop(self, args: dict, body: str) -> dict:
        name = args.get("name") or body.strip()
        if not name:
            return self._err('stop needs name="..."')
        return self._ok(f"stopped {name}" if self.sandbox.kill_service(name)
                        else f"no service named {name}", action="stop")

    def _do_logs(self, args: dict, body: str) -> dict:
        name = args.get("name") or body.strip()
        if not name:
            return self._err('logs needs name="..."')
        return self._ok(self.sandbox.service_log(name, _int(args.get("tail"), 120)),
                        action="logs")

    # ------------------------------------------------------------------ editing
    def _do_edit(self, args: dict, body: str) -> dict:
        """Change part of a file instead of rewriting the whole thing.

        Body is `<<<OLD ... === ... >>>` — everything before the `===` marker is
        matched literally and replaced by what follows. Rewriting a whole file
        to change three lines is how a small model destroys the other 300.
        """
        path = args.get("path")
        if not path:
            return self._err('edit needs path="..."')

        current = self.sandbox.read_file(path, 1, 1_000_000)
        if current.strip().endswith("no such file"):
            return self._err(f"{path} does not exist — use write to create it")

        if "===" not in body:
            return self._err(
                "edit body must be:  <old text>\n===\n<new text>")
        old, _, new = body.partition("\n===\n")
        old = old.strip("\n")
        new = new.strip("\n")

        if old and old not in current:
            return self._err(
                f"that exact text is not in {path}. Read it first, and copy the "
                f"lines you want to change verbatim.")

        updated = current.replace(old, new, 1) if old else current + "\n" + new
        result = self.sandbox.write_file(path, updated)
        if not result.ok:
            return self._err(result.output, path=path)
        self.touched.append(path)
        delta = updated.count("\n") - current.count("\n")
        return self._ok(
            f"edited {path} ({delta:+d} lines)\n\n--- was ---\n{old[:400]}"
            f"\n--- now ---\n{new[:400]}",
            path=path, action="edit")

    # ------------------------------------------------------------------ deep read
    def _do_audit(self, args: dict, body: str) -> dict:
        """Kick off (or report on) the model reading every mirrored file.

        This is the expensive pass, so it is never implicit — it happens when
        the user asks for it, and it runs in the background so the conversation
        stays usable while it works.
        """
        from ..deepread import status, start

        want = (args.get("_positional") or body or "").strip().lower()
        if want in ("status", "progress"):
            return self._ok(_format_status(status(self.scan_id)), action="audit")

        state = start(self.scan_id, self.root,
                      only=args.get("glob") or args.get("pattern"))
        if state.get("already_running"):
            return self._ok("A full read is already running.\n"
                            + _format_status(status(self.scan_id)), action="audit")
        return self._ok(
            f"Reading all {state['queued']} files with the model, "
            f"{state['concurrency']} at a time, in the background.\n"
            f"Ask me anything meanwhile — I'll fold findings in as they land.",
            action="audit", queued=state["queued"])

    # ------------------------------------------------------------------ audit
    def _do_finding(self, args: dict, body: str) -> dict:
        title = args.get("title") or body.strip().split("\n")[0][:200]
        if not title:
            return self._err("finding needs a title")
        if self.memory.has_seen_finding(title):
            return self._ok(f"already recorded: {title}", action="finding")
        finding = {
            "file_path": args.get("path"),
            "line_start": _int(args.get("line"), 0) or None,
            "severity": sev.normalize(args.get("severity")),
            "confidence": 0.85,
            "title": title[:200],
            "category": args.get("category", "other")[:40],
            "cwe": args.get("cwe"),
            "evidence": args.get("evidence", "")[:1000],
            "explanation": body.strip()[:3000],
            "fix": args.get("fix", "")[:3000],
            "source": "agent",
            "verified": "agent-confirmed",
        }
        fid = db.add_finding(self.scan_id, finding)
        finding["id"] = fid
        self.new_findings.append(finding)
        self.memory.remember_finding(title)
        return self._ok(f"recorded [{finding['severity']}] {title}",
                        action="finding", severity=finding["severity"])

    def _do_remember(self, args: dict, body: str) -> dict:
        fact = body.strip() or args.get("_positional", "")
        if not fact:
            return self._err("remember needs something to remember")
        self.memory.note(fact)
        return self._ok(f"remembered: {fact[:200]}", action="remember")


def _format_status(state: dict) -> str:
    if not state or state.get("state") == "idle":
        return "No full read has been started yet."
    if state["state"] == "running":
        return (f"Reading: {state['done']}/{state['total']} files · "
                f"{state['findings']} findings so far.")
    return (f"Finished: read {state['done']}/{state['total']} files, "
            f"{state['findings']} findings.")


def _clip(text: str) -> str:
    text = text if isinstance(text, str) else str(text)
    if len(text) <= MAX_OBSERVATION:
        return text
    return (text[: MAX_OBSERVATION - 800] +
            f"\n… [{len(text) - MAX_OBSERVATION} chars omitted] …\n" + text[-600:])


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
