"""The agent's hands.

Reads come off the host copy of the mirror (fast, no container round-trip);
writes and executions go into the sandbox (real, isolated). Every path is
resolved and checked against the scan directory, so a traversal in a model-
generated path cannot walk out of the mirror.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from .. import db
from ..analysis.memory import ScanMemory
from ..sandbox import Sandbox, SandboxUnavailable

MAX_READ_LINES = 400
MAX_TOOL_OUTPUT = 12_000


class ToolError(RuntimeError):
    pass


class ToolBox:
    def __init__(self, scan_id: str, root: Path, memory: ScanMemory):
        self.scan_id = scan_id
        self.root = Path(root).resolve()
        self.memory = memory
        self.sandbox = Sandbox.get(scan_id, self.root)
        self.new_findings: list[dict] = []

    # ------------------------------------------------------------------ dispatch
    async def call(self, name: str, args: dict) -> str:
        handler = getattr(self, f"_t_{name}", None)
        if handler is None:
            return (f"Unknown tool '{name}'. Available: list_files, read_file, grep, "
                    f"run, write_file, python, add_finding, remember, finish.")
        try:
            out = handler(args or {})
        except SandboxUnavailable as exc:
            return f"SANDBOX UNAVAILABLE: {exc}"
        except ToolError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:
            return f"ERROR: {type(exc).__name__}: {exc}"
        return _clip(out)

    # ------------------------------------------------------------------ reads
    def _t_list_files(self, args: dict) -> str:
        pattern = str(args.get("pattern") or "**/*")
        limit = _int(args.get("limit"), 100, 1, 500)
        rows = db.list_files(self.scan_id)
        matched = [
            r for r in rows
            if fnmatch.fnmatch(r["path"], pattern)
            or fnmatch.fnmatch(r["path"].rsplit("/", 1)[-1], pattern)
        ]
        if not matched:
            return f"No files match {pattern!r}. {len(rows)} files exist in the mirror."
        lines = [
            f"{r['path']}  [{r['language']}, {r['lines']} lines, {r['bytes']}B]"
            for r in matched[:limit]
        ]
        more = len(matched) - len(lines)
        return "\n".join(lines) + (f"\n… and {more} more" if more > 0 else "")

    def _t_read_file(self, args: dict) -> str:
        path = self._resolve(str(args.get("path") or ""))
        start = _int(args.get("start"), 1, 1, 10_000_000)
        end = _int(args.get("end"), start + MAX_READ_LINES - 1, start, 10_000_000)
        end = min(end, start + MAX_READ_LINES - 1)

        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        window = lines[start - 1:end]
        if not window:
            return f"{path.name}: no lines in range {start}-{end} (file has {len(lines)})."
        body = "\n".join(f"{start + i:>5} | {l}" for i, l in enumerate(window))
        return f"{self._rel(path)} lines {start}-{start + len(window) - 1} of {len(lines)}\n{body}"

    def _t_grep(self, args: dict) -> str:
        raw = str(args.get("pattern") or "")
        if not raw:
            raise ToolError("grep needs a 'pattern'")
        try:
            rx = re.compile(raw, re.I)
        except re.error as exc:
            raise ToolError(f"bad regex: {exc}") from exc

        glob = str(args.get("glob") or "*")
        limit = _int(args.get("limit"), 60, 1, 300)
        out: list[str] = []

        for row in db.list_files(self.scan_id):
            if row["kind"] == "binary":
                continue
            rel = row["path"]
            if not (fnmatch.fnmatch(rel, glob)
                    or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], glob)):
                continue
            full = self.root / rel
            if not full.exists():
                continue
            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), start=1):
                if len(line) > 3000:
                    line = line[:3000]
                if rx.search(line):
                    out.append(f"{rel}:{n}: {line.strip()[:240]}")
                    if len(out) >= limit:
                        return "\n".join(out) + "\n(limit reached)"
        return "\n".join(out) if out else f"No match for /{raw}/ in {glob}"

    # ------------------------------------------------------------------ sandbox
    def _t_run(self, args: dict) -> str:
        command = str(args.get("command") or "").strip()
        if not command:
            raise ToolError("run needs a 'command'")
        result = self.sandbox.exec(command)
        return f"$ {command}\n(exit {result.exit_code})\n{result.output}"

    def _t_python(self, args: dict) -> str:
        code = str(args.get("code") or "")
        if not code.strip():
            raise ToolError("python needs 'code'")
        result = self.sandbox.run_python(code)
        return f"(exit {result.exit_code})\n{result.output}"

    def _t_write_file(self, args: dict) -> str:
        path = str(args.get("path") or "").strip().lstrip("/")
        content = str(args.get("content") or "")
        if not path or ".." in path.split("/"):
            raise ToolError("write_file needs a relative path inside the workspace")
        result = self.sandbox.write_file(path, content)
        return f"{result.output} -> /work/{path}"

    # ------------------------------------------------------------------ bookkeeping
    def _t_add_finding(self, args: dict) -> str:
        from ..analysis import severity as sev

        title = str(args.get("title") or "").strip()
        if not title:
            raise ToolError("add_finding needs a 'title'")
        if self.memory.has_seen_finding(title):
            return f"Already recorded: {title}"

        finding = {
            "file_path": str(args.get("file_path") or "").strip() or None,
            "line_start": _opt_int(args.get("line_start")),
            "line_end": _opt_int(args.get("line_end")) or _opt_int(args.get("line_start")),
            "severity": sev.normalize(args.get("severity")),
            "confidence": 0.8,
            "title": title[:200],
            "category": str(args.get("category") or "other")[:40],
            "cwe": str(args["cwe"])[:20] if args.get("cwe") else None,
            "evidence": str(args.get("evidence") or "")[:1000],
            "explanation": str(args.get("explanation") or "")[:3000],
            "fix": str(args.get("fix") or "")[:3000],
            "source": "agent",
            "verified": "agent-confirmed",
        }
        fid = db.add_finding(self.scan_id, finding)
        finding["id"] = fid
        self.new_findings.append(finding)
        self.memory.remember_finding(title)
        return f"Recorded [{finding['severity']}] {title} ({fid})"

    def _t_remember(self, args: dict) -> str:
        fact = str(args.get("fact") or args.get("note") or "").strip()
        if not fact:
            raise ToolError("remember needs a 'fact'")
        self.memory.note(fact)
        return f"Remembered: {fact[:160]}"

    # ------------------------------------------------------------------ paths
    def _resolve(self, rel: str) -> Path:
        rel = rel.strip().lstrip("/")
        if not rel:
            raise ToolError("a path is required")
        candidate = (self.root / rel).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ToolError("path escapes the scan directory") from exc
        if not candidate.exists():
            near = self._suggest(rel)
            raise ToolError(f"{rel} not found." + (f" Did you mean: {near}?" if near else ""))
        if candidate.is_dir():
            raise ToolError(f"{rel} is a directory; use list_files")
        return candidate

    def _suggest(self, rel: str) -> str:
        name = rel.rsplit("/", 1)[-1].lower()
        hits = [r["path"] for r in db.list_files(self.scan_id)
                if name and name in r["path"].lower()]
        return ", ".join(hits[:3])

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)


def _clip(text: str) -> str:
    text = text if isinstance(text, str) else str(text)
    if len(text) <= MAX_TOOL_OUTPUT:
        return text
    head = text[: MAX_TOOL_OUTPUT - 2000]
    tail = text[-1500:]
    return f"{head}\n\n… [{len(text) - MAX_TOOL_OUTPUT} chars omitted] …\n\n{tail}"


def _int(value, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _opt_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
