"""Scan memory.

The auditor reads a site one chunk at a time, so it needs somewhere to keep
what it learned two thousand lines ago. Memory has four shelves:

  facts      — durable observations ("auth is a JWT in localStorage")
  files      — a one-line summary per file it finished
  findings   — running list of confirmed issues (titles only, for dedupe)
  notes      — free-form scratch the agent writes to itself

`context_block()` renders the shelves into the prompt preamble, newest first,
trimmed to a character budget so it never blows the context window.
"""
from __future__ import annotations

import json
from collections import OrderedDict

from .. import db


class ScanMemory:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._facts: "OrderedDict[str, str]" = OrderedDict()
        self._files: "OrderedDict[str, str]" = OrderedDict()
        self._findings: list[str] = []
        self._notes: list[str] = []
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        for row in db.list_memory(self.scan_id):
            kind, key, content = row["kind"], row["key"], row["content"]
            if kind == "fact":
                self._facts[key or content[:60]] = content
            elif kind == "file":
                self._files[key or content[:60]] = content
            elif kind == "finding":
                self._findings.append(content)
            elif kind == "note":
                self._notes.append(content)

    # ------------------------------------------------------------------ write
    def remember_fact(self, key: str, value: str) -> None:
        key = key.strip()[:80]
        value = value.strip()
        if not value or self._facts.get(key) == value:
            return
        self._facts[key] = value
        db.add_memory(self.scan_id, "fact", value, key)

    def remember_file(self, path: str, summary: str) -> None:
        summary = summary.strip()
        if not summary:
            return
        self._files[path] = summary
        db.add_memory(self.scan_id, "file", summary, path)

    def remember_finding(self, title: str) -> None:
        title = title.strip()
        if title and title not in self._findings:
            self._findings.append(title)
            db.add_memory(self.scan_id, "finding", title)

    def note(self, text: str) -> None:
        text = text.strip()
        if text:
            self._notes.append(text)
            db.add_memory(self.scan_id, "note", text)

    # ------------------------------------------------------------------ read
    def has_seen_finding(self, title: str) -> bool:
        needle = _key(title)
        return any(_key(t) == needle for t in self._findings)

    def file_summary(self, path: str) -> str | None:
        return self._files.get(path)

    def context_block(self, budget: int = 3000) -> str:
        sections: list[str] = []

        if self._facts:
            lines = [f"- {k}: {v}" for k, v in list(self._facts.items())[-30:]]
            sections.append("What I know about this application:\n" + "\n".join(lines))

        if self._findings:
            recent = self._findings[-25:]
            sections.append(
                "Issues already recorded (do not repeat them):\n"
                + "\n".join(f"- {t}" for t in recent)
            )

        if self._files:
            recent = list(self._files.items())[-20:]
            sections.append(
                "Files already read:\n"
                + "\n".join(f"- {p}: {s}" for p, s in recent)
            )

        if self._notes:
            sections.append("My notes:\n" + "\n".join(f"- {n}" for n in self._notes[-10:]))

        block = "\n\n".join(sections)
        if len(block) > budget:
            block = block[-budget:]
            block = block[block.find("\n") + 1:]
        return block

    def snapshot(self) -> dict:
        return {
            "facts": dict(self._facts),
            "files": len(self._files),
            "findings": len(self._findings),
            "notes": self._notes[-10:],
        }

    def __str__(self) -> str:
        return json.dumps(self.snapshot(), indent=2)


def _key(title: str) -> str:
    return "".join(ch for ch in title.lower() if ch.isalnum())[:60]
