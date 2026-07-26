"""Chat over a finished audit.

Two modes:

  answer   — stream a reply grounded in the audit context (findings, memory,
             file inventory, plus any files the question names).
  agent    — hand the turn to the Investigator, which plans, runs commands in
             the sandbox, and reports back.

The mode is chosen by the caller (a toggle in the UI) or inferred from the
question: anything that asks to *do* something rather than *explain* something
goes to the agent.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import AsyncIterator

from . import db
from .agent import Investigator
from .analysis import prompts, severity as sev
from .analysis.llm import Ollama, OllamaUnavailable
from .analysis.memory import ScanMemory
from .config import settings

AGENT_TRIGGERS = re.compile(
    r"\b(run|execute|exploit|prove|verify|confirm|test|check if|reproduce|"
    r"grep|search for|open the sandbox|shell|command|install|build|"
    r"investigate|dig into|find out|scan again|write a script|poc)\b",
    re.I,
)

MAX_FILE_CONTEXT = 12_000


def wants_agent(message: str) -> bool:
    return bool(AGENT_TRIGGERS.search(message or ""))


class ChatService:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.scan = db.get_scan(scan_id) or {}
        self.root = settings.scan_path(scan_id)
        self.memory = ScanMemory(scan_id)
        self.llm = Ollama()

    # ------------------------------------------------------------------ answer
    async def stream_answer(self, message: str) -> AsyncIterator[str]:
        messages = [
            {"role": "system", "content": prompts.CHAT_SYSTEM},
            {"role": "user", "content": self._context(message)},
        ]
        for turn in db.list_messages(self.scan_id)[-10:]:
            if turn["role"] in ("user", "assistant") and turn["content"]:
                messages.append({"role": turn["role"], "content": turn["content"][:4000]})
        messages.append({"role": "user", "content": message})

        try:
            async for piece in self.llm.stream_chat(messages, temperature=0.25):
                yield piece
        except OllamaUnavailable as exc:
            yield (f"\n\n_I can't reach the model right now: {exc}_\n\n"
                   f"The findings list is still available on the left — it comes "
                   f"from the rule engine and the header checks, which don't need "
                   f"the model.")

    # ------------------------------------------------------------------ agent
    async def investigate(self, task: str, on_event) -> dict:
        agent = Investigator(
            self.scan_id, self.root, task,
            llm=self.llm, memory=self.memory, on_event=on_event,
        )
        return await agent.run()

    # ------------------------------------------------------------------ context
    def _context(self, question: str) -> str:
        findings = db.list_findings(self.scan_id)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        blocks = [
            f"TARGET: {self.scan.get('url')}",
            f"STATUS: {self.scan.get('status')}",
            f"FILES MIRRORED: {len(db.list_files(self.scan_id))}",
            f"FINDINGS: {len(findings)} — " + ", ".join(
                f"{sev.LABEL.get(k, k)} {v}" for k, v in counts.items()
            ),
            "",
            "AUDIT MEMORY:",
            self.memory.context_block(budget=2500) or "(empty)",
            "",
            "FINDINGS:",
        ]
        for f in findings[:40]:
            blocks.append(
                f"[{f['id']}] [{f['severity']}] {f['title']}\n"
                f"    where: {f['file_path']}:{f['line_start'] or '?'}\n"
                f"    why:   {(f['explanation'] or '')[:400]}\n"
                f"    fix:   {(f['fix'] or '')[:400]}"
            )
        if len(findings) > 40:
            blocks.append(f"… and {len(findings) - 40} more.")

        cited = self._files_mentioned(question)
        if cited:
            blocks += ["", "FILES THE QUESTION REFERS TO:"]
            for path, body in cited:
                blocks.append(f"--- {path} ---\n{body}\n--- end ---")

        return "\n".join(blocks)

    def _files_mentioned(self, question: str) -> list[tuple[str, str]]:
        """Pull in any file the user names, so answers cite real lines."""
        rows = db.list_files(self.scan_id)
        wanted: list[tuple[str, str]] = []
        lowered = (question or "").lower()
        budget = MAX_FILE_CONTEXT

        for row in rows:
            name = row["path"].rsplit("/", 1)[-1].lower()
            if len(name) < 4:
                continue
            if name in lowered or row["path"].lower() in lowered:
                full = Path(self.root) / row["path"]
                if not full.exists():
                    continue
                text = full.read_text(encoding="utf-8", errors="replace")
                take = text[:budget]
                numbered = "\n".join(
                    f"{i:>5} | {l}" for i, l in enumerate(take.splitlines(), start=1)
                )
                wanted.append((row["path"], numbered))
                budget -= len(take)
                if budget <= 0:
                    break
        return wanted
