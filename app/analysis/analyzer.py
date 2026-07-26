"""The line-by-line auditor.

Reading order matters. The auditor does not walk the mirror alphabetically; it
walks it the way a human would:

  1. original source recovered from source maps (real, readable app code)
  2. inline scripts lifted out of pages
  3. first-party JS/TS, then HTML, then config and JSON
  4. everything else

Within a file it reads fixed-size overlapping windows, each labelled with
absolute line numbers, and carries `ScanMemory` forward so chunk 14 knows what
chunk 3 established. Static rule hits inside the window are passed along as
hints — the model confirms, rejects, or upgrades them.
"""
from __future__ import annotations

import fnmatch
import json
import time
from pathlib import Path
from typing import Awaitable, Callable

from .. import db
from ..config import settings
from . import headers as header_checks, prompts, severity as sev, static_rules
from .llm import Ollama, OllamaUnavailable
from .memory import ScanMemory

ProgressFn = Callable[[str, float, str], Awaitable[None]]
EventFn = Callable[[str, dict], Awaitable[None]]

# Files that are never worth an LLM pass.
SKIP_GLOBS = [
    "*.min.js", "*.min.css", "*.map", "*.png", "*.jpg", "*.jpeg", "*.gif",
    "*.webp", "*.ico", "*.svg", "*.woff*", "*.ttf", "*.otf", "*.eot",
    "*.mp4", "*.webm", "*.mp3", "*.pdf", "*.zip", "*.gz", "*.wasm",
]
VENDOR_HINTS = ("node_modules/", "/vendor/", "jquery", "bootstrap", "polyfill",
                "react-dom", "lodash", "moment.min", "chunk-vendors")

PRIORITY_KIND = {"sourcemap-original": 0, "inline-script": 1, "code": 2, "binary": 9}
PRIORITY_LANG = {
    "javascript": 0, "typescript": 0, "vue": 0, "svelte": 0, "python": 0,
    "php": 0, "ruby": 0, "go": 0, "java": 0, "csharp": 0,
    "html": 1, "json": 2, "yaml": 2, "graphql": 2, "sql": 2, "shell": 2,
    "css": 4, "xml": 4, "text": 5, "binary": 9,
}

MAX_LINE_LEN = 400          # longer => minified; truncate for the prompt
MINIFIED_RATIO = 300        # avg chars/line above this means "bundle"


class Analyzer:
    def __init__(
        self,
        scan_id: str,
        root_dir: Path,
        crawl: dict,
        *,
        llm: Ollama | None = None,
        on_progress: ProgressFn | None = None,
        on_event: EventFn | None = None,
    ):
        self.scan_id = scan_id
        self.root = Path(root_dir)
        self.crawl = crawl
        self.llm = llm or Ollama()
        self.memory = ScanMemory(scan_id)
        self.on_progress = on_progress
        self.on_event = on_event
        self.findings: list[dict] = []
        self.llm_available = True
        self.llm_error: str | None = None

        # Coverage accounting: proof of how much of the reading was actually
        # done by the model, as opposed to the deterministic rule pass. A file
        # only enters `files_ai_reviewed` once the model has returned at least
        # one successfully parsed chunk for it — being *sent* to the model is
        # not enough to count as "read".
        self.files_considered = 0
        self.files_vendor_skipped: list[str] = []
        self.files_queued = 0
        self.files_ai_reviewed: set[str] = set()
        self.chunks_sent = 0
        self.chunks_answered = 0

    # ------------------------------------------------------------------ run
    async def run(self) -> dict:
        await self._emit("analyzing", 0.46, "Opening the mirror")

        deterministic = self._deterministic_pass()
        for finding in deterministic:
            self._record(finding)
        await self._emit(
            "analyzing", 0.50,
            f"{len(deterministic)} issues from headers and exposed paths",
        )

        queue = self._reading_queue()
        self.files_queued = len(queue)
        await self._emit("analyzing", 0.52,
                         f"{len(queue)} files queued for line-by-line review")

        total = max(1, len(queue))
        for idx, item in enumerate(queue):
            stats = await self._read_file(item)
            # A file only counts as AI-reviewed once the model actually
            # returned a parsed chunk for it — not merely because it was sent.
            if stats["chunks_ok"] > 0:
                self.files_ai_reviewed.add(item["path"])
                db.mark_analyzed(self.scan_id, item["path"])
            pct = 0.52 + 0.42 * ((idx + 1) / total)
            await self._emit(
                "analyzing", pct,
                f"Read {idx + 1}/{total} · {item['path']} "
                f"({len(self.findings)} findings so far)",
            )

        report = await self._write_report()
        await self._emit("done", 1.0, "Audit complete")
        return report

    # ------------------------------------------------------------------ pass 1
    def _deterministic_pass(self) -> list[dict]:
        out = header_checks.analyze(self.crawl.get("headers", {}))
        out += header_checks.analyze_exposures(self.crawl.get("exposures", []))

        forms = self.crawl.get("forms", [])
        for form in forms:
            if form["method"] == "POST" and not form["has_csrf_field"]:
                out.append({
                    "file_path": f"forms/{_slug(form['page'])}",
                    "severity": "medium",
                    "confidence": 0.6,
                    "title": "POST form with no CSRF token field",
                    "category": "csrf",
                    "cwe": "CWE-352",
                    "evidence": f"{form['method']} {form['action']} on {form['page']}",
                    "explanation": "Nothing in the markup ties this submission to the "
                                   "user's session, so another site can submit it on "
                                   "their behalf. (A SameSite cookie or a header-based "
                                   "token would also cover this — verify which applies.)",
                    "fix": "Emit a per-session CSRF token as a hidden field and verify "
                           "it server-side; set SameSite=Lax on the session cookie.",
                    "source": "form-check",
                })
            if form["action"].startswith("http://"):
                out.append({
                    "file_path": f"forms/{_slug(form['page'])}",
                    "severity": "high",
                    "confidence": 0.95,
                    "title": "Form submits over plaintext HTTP",
                    "category": "transport",
                    "cwe": "CWE-319",
                    "evidence": f"{form['method']} {form['action']}",
                    "explanation": "Everything typed into this form crosses the network "
                                   "in the clear.",
                    "fix": "Point the action at https:// and redirect HTTP to HTTPS.",
                    "source": "form-check",
                })
            for field in form["inputs"]:
                if field.get("type") == "password" and form["action"].startswith("http://"):
                    out.append({
                        "file_path": f"forms/{_slug(form['page'])}",
                        "severity": "critical",
                        "confidence": 0.98,
                        "title": "Password submitted over plaintext HTTP",
                        "category": "transport",
                        "cwe": "CWE-319",
                        "evidence": f"input[name={field.get('name')}] -> {form['action']}",
                        "explanation": "Credentials are transmitted unencrypted.",
                        "fix": "Serve and submit the login form exclusively over HTTPS.",
                        "source": "form-check",
                    })
        return out

    # ------------------------------------------------------------------ queue
    def _reading_queue(self) -> list[dict]:
        rows = db.list_files(self.scan_id)
        scored: list[tuple[tuple, dict]] = []

        for row in rows:
            path = row["path"]
            if row["kind"] == "binary":
                continue
            name = path.rsplit("/", 1)[-1]
            if any(fnmatch.fnmatch(name, g) for g in SKIP_GLOBS):
                continue

            full = self.root / path
            if not full.exists() or full.stat().st_size == 0:
                continue

            text = _read(full)
            if not text.strip():
                continue

            self.files_considered += 1

            lines = text.count("\n") + 1
            minified = len(text) / max(1, lines) > MINIFIED_RATIO
            vendor = any(v in path.lower() for v in VENDOR_HINTS)

            hits = static_rules.scan_text(text, row["language"] or "text")
            score = static_rules.score_file(hits)

            # Vendored/minified code only earns a read if a rule fired hard.
            if (minified or vendor) and score < 6.0:
                for hit in hits:
                    self._record(static_rules.hit_to_finding(hit, path))
                self.files_vendor_skipped.append(path)
                continue

            rank = (
                PRIORITY_KIND.get(row["kind"], 5),
                PRIORITY_LANG.get(row["language"], 6),
                -score,
                path,
            )
            scored.append((rank, {
                "path": path,
                "language": row["language"] or "text",
                "url": row["url"],
                "text": text,
                "lines": lines,
                "hits": hits,
                "minified": minified,
            }))

        scored.sort(key=lambda t: t[0])
        return [item for _, item in scored[: settings.analysis_max_files]]

    # ------------------------------------------------------------------ per file
    async def _read_file(self, item: dict) -> dict:
        """Send every line of `item` to the model, one window at a time.

        Returns `{"chunks_sent": N, "chunks_ok": M}` so the caller can tell
        whether the model actually engaged with this file — a file whose
        every chunk failed to parse, or that was never sent because the model
        was down, must not be reported as AI-reviewed.
        """
        path, text = item["path"], item["text"]
        lines = text.splitlines() or [""]
        chunk_size = settings.analysis_chunk_lines
        overlap = min(settings.analysis_chunk_overlap, chunk_size - 1)
        step = chunk_size - overlap

        # Every rule hit becomes a finding regardless of what the model says;
        # the model's job is to confirm and enrich, not to be the only voice.
        for hit in item["hits"]:
            self._record(static_rules.hit_to_finding(hit, path))

        stats = {"chunks_sent": 0, "chunks_ok": 0}

        if not self.llm_available:
            return stats

        chunk_notes: list[str] = []
        file_findings: list[dict] = []

        for start in range(0, len(lines), step):
            window = lines[start:start + chunk_size]
            if not any(w.strip() for w in window):
                continue
            first, last = start + 1, start + len(window)

            listing = "\n".join(
                f"{first + i:>5} | {_clip(line)}" for i, line in enumerate(window)
            )
            hints = _hints_for(item["hits"], first, last)

            prompt = prompts.CHUNK_TEMPLATE.format(
                memory=self.memory.context_block(),
                path=path,
                language=item["language"],
                origin=item.get("url") or "—",
                start=first,
                end=last,
                total=len(lines),
                hints=hints,
                code=listing,
            )

            stats["chunks_sent"] += 1
            self.chunks_sent += 1
            try:
                result = await self.llm.json_chat([
                    {"role": "system", "content": prompts.AUDITOR_SYSTEM},
                    {"role": "user", "content": prompt},
                ])
            except OllamaUnavailable as exc:
                self.llm_available = False
                self.llm_error = str(exc)
                await self._emit("analyzing", 0.6,
                                 f"Model unavailable — rules only. {exc}")
                return stats
            except ValueError:
                continue  # unparseable reply for this window; keep going

            if not isinstance(result, dict):
                continue

            # A response the model actually produced and we could parse —
            # this is the concrete evidence that it read this stretch of code.
            stats["chunks_ok"] += 1
            self.chunks_answered += 1

            if summary := str(result.get("summary") or "").strip():
                chunk_notes.append(f"lines {first}-{last}: {summary}")

            for fact in _as_list(result.get("facts")):
                self.memory.remember_fact(f"{path}:{first}", str(fact))

            for raw in _as_list(result.get("findings")):
                if not isinstance(raw, dict):
                    continue
                finding = self._normalize(raw, path, first, last, lines)
                if finding and self._record(finding):
                    file_findings.append(finding)
                    await self._event("finding", finding)

            if last >= len(lines):
                break

        if stats["chunks_ok"] > 0:
            await self._summarize_file(path, len(lines), chunk_notes, file_findings)
        return stats

    async def _summarize_file(self, path: str, line_count: int,
                              notes: list[str], found: list[dict]) -> None:
        if not notes:
            return
        prompt = prompts.FILE_SUMMARY_TEMPLATE.format(
            memory=self.memory.context_block(budget=1200),
            path=path,
            lines=line_count,
            chunk_notes="\n".join(f"- {n}" for n in notes[:25]) or "- (none)",
            findings="\n".join(
                f"- [{f['severity']}] {f['title']} (line {f.get('line_start')})"
                for f in found
            ) or "- none",
        )
        try:
            result = await self.llm.json_chat([
                {"role": "system", "content": prompts.AUDITOR_SYSTEM},
                {"role": "user", "content": prompt},
            ], retries=1)
        except (OllamaUnavailable, ValueError):
            self.memory.remember_file(path, notes[0][:200])
            return
        if isinstance(result, dict):
            self.memory.remember_file(path, str(result.get("summary", ""))[:400])
            for fact in _as_list(result.get("facts"))[:3]:
                self.memory.remember_fact(path, str(fact))

    # ------------------------------------------------------------------ report
    async def _write_report(self) -> dict:
        counts = {s: 0 for s in sev.ORDER}
        for f in self.findings:
            counts[sev.normalize(f["severity"])] += 1

        top = sorted(self.findings, key=lambda f: (sev.rank(f["severity"]),
                                                   -float(f.get("confidence", 0))))[:25]

        ai_findings = sum(1 for f in self.findings if f.get("source") == "ai")
        rule_findings = sum(1 for f in self.findings
                            if str(f.get("source", "")).startswith("rule:"))

        # Proof of work: how much of the mirror the model actually engaged
        # with, as opposed to what the deterministic rules alone produced.
        # `files_ai_reviewed` only counts a file once the model returned at
        # least one chunk it could parse — see Analyzer._read_file.
        coverage = {
            "ai_model": self.llm.model,
            "ai_available": self.llm_available,
            "files_total": self.files_considered,
            "files_vendor_skipped": len(self.files_vendor_skipped),
            "files_queued_for_ai": self.files_queued,
            "files_ai_reviewed": len(self.files_ai_reviewed),
            "chunks_sent_to_ai": self.chunks_sent,
            "chunks_ai_answered": self.chunks_answered,
            "findings_from_ai": ai_findings,
            "findings_from_rules": rule_findings,
            "findings_from_headers_and_probes": len(self.findings) - ai_findings - rule_findings,
        }

        base = {
            "url": self.crawl.get("root_url"),
            "counts": counts,
            "total": len(self.findings),
            "files_read": len(self.memory._files),
            "hosts": self.crawl.get("hosts", []),
            "risk": sev.worst([f["severity"] for f in self.findings]) if self.findings else "info",
            "generated_at": time.time(),
            "llm_error": self.llm_error,
            "coverage": coverage,
        }

        if not self.llm_available:
            base.update({
                "verdict": "Rule-based results only — the model was unreachable.",
                "summary": (
                    f"Collected {len(self.findings)} findings from pattern rules, "
                    "response headers, and exposed-path probes. Start Ollama and "
                    "re-run to get the line-by-line review."
                ),
                "themes": [],
                "priorities": _fallback_priorities(top),
            })
            return base

        prompt = prompts.REPORT_TEMPLATE.format(
            memory=self.memory.context_block(budget=2500),
            url=self.crawl.get("root_url"),
            file_count=len(self.memory._files),
            hosts=", ".join(self.crawl.get("hosts", [])[:20]) or "—",
            severity_counts=json.dumps(counts),
            findings="\n".join(
                f"- [{f['severity']}] {f['title']} — {f.get('file_path')}"
                f":{f.get('line_start') or '?'}" for f in top
            ) or "- none",
            headers=json.dumps(
                {h: list((v.get('headers') or {}).keys())[:20]
                 for h, v in list(self.crawl.get("headers", {}).items())[:5]}
            )[:1500],
            exposures="\n".join(
                f"- {e['url']} ({e['status']}, {e['bytes']}B)"
                for e in self.crawl.get("exposures", [])[:20]
            ) or "- none",
        )

        try:
            result = await self.llm.json_chat([
                {"role": "system", "content": prompts.AUDITOR_SYSTEM},
                {"role": "user", "content": prompt},
            ], retries=1)
        except (OllamaUnavailable, ValueError) as exc:
            base.update({
                "verdict": "Summary unavailable.",
                "summary": f"The model could not produce a summary ({exc}). "
                           "The findings list below is still complete.",
                "themes": [],
                "priorities": _fallback_priorities(top),
            })
            return base

        if isinstance(result, dict):
            base.update({
                "verdict": str(result.get("verdict", "")),
                "summary": str(result.get("summary", "")),
                "themes": _as_list(result.get("themes")),
                "priorities": _as_list(result.get("priorities")) or _fallback_priorities(top),
            })
            if result.get("risk"):
                base["risk"] = sev.normalize(str(result["risk"]))
        return base

    # ------------------------------------------------------------------ helpers
    def _normalize(self, raw: dict, path: str, first: int, last: int,
                   lines: list[str]) -> dict | None:
        title = str(raw.get("title") or "").strip()
        if not title:
            return None

        severity = sev.normalize(raw.get("severity"))
        try:
            confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.6))))
        except (TypeError, ValueError):
            confidence = 0.6

        # Low-confidence noise is not worth the owner's attention.
        if confidence < 0.35 and severity in ("low", "info"):
            return None

        line_start = _clamp_line(raw.get("line_start"), first, last)
        line_end = _clamp_line(raw.get("line_end"), first, last) or line_start

        evidence = str(raw.get("evidence") or "").strip()
        if not evidence and line_start and line_start <= len(lines):
            evidence = lines[line_start - 1].strip()[:400]

        return {
            "file_path": path,
            "line_start": line_start,
            "line_end": line_end,
            "severity": severity,
            "confidence": confidence,
            "title": title[:200],
            "category": str(raw.get("category") or "other")[:40],
            "cwe": (str(raw["cwe"])[:20] if raw.get("cwe") not in (None, "null", "") else None),
            "evidence": evidence[:1000],
            "explanation": str(raw.get("explanation") or "")[:3000],
            "fix": str(raw.get("fix") or "")[:3000],
            "source": "ai",
            "verified": None,
            "verify_hint": str(raw.get("verify") or "")[:500] or None,
        }

    def _record(self, finding: dict) -> bool:
        """Store a finding unless we already have the same thing in the same place."""
        key = (finding.get("file_path"), finding.get("line_start"),
               _norm_title(finding.get("title", "")))
        for existing in self.findings:
            ekey = (existing.get("file_path"), existing.get("line_start"),
                    _norm_title(existing.get("title", "")))
            if ekey == key:
                # Keep the more alarming of the two.
                if sev.rank(finding["severity"]) < sev.rank(existing["severity"]):
                    existing.update(finding)
                return False
        fid = db.add_finding(self.scan_id, finding)
        finding["id"] = fid
        self.findings.append(finding)
        self.memory.remember_finding(finding["title"])
        return True

    async def _emit(self, stage: str, pct: float, message: str) -> None:
        if self.on_progress:
            await self.on_progress(stage, pct, message)

    async def _event(self, kind: str, payload: dict) -> None:
        if self.on_event:
            await self.on_event(kind, payload)


# --------------------------------------------------------------------------- utils
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_LEN else line[:MAX_LINE_LEN] + " …[truncated]"


def _hints_for(hits: list, first: int, last: int) -> str:
    inside = [h for h in hits if first <= h.line_no <= last]
    if not inside:
        return ""
    body = "\n".join(
        f"  line {h.line_no}: {h.rule.id} — {h.rule.title}" for h in inside[:20]
    )
    return (
        "\nPATTERN SCANNER FLAGGED THESE LINES (confirm, downgrade, or reject each "
        "one — it has no understanding of context):\n" + body + "\n"
    )


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clamp_line(value, first: int, last: int) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return first
    return max(first, min(n, last))


def _norm_title(title: str) -> str:
    return "".join(c for c in title.lower() if c.isalnum())[:50]


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in text)[-60:]


def _fallback_priorities(top: list[dict]) -> list[dict]:
    out = []
    for i, f in enumerate(top[:5], start=1):
        out.append({
            "order": i,
            "action": f["title"],
            "why": (f.get("explanation") or "")[:200],
            "files": [f.get("file_path")],
            "effort": "hours",
        })
    return out
