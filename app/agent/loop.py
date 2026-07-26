"""The investigator loop.

Think -> one tool -> observe -> repeat, in the spirit of gpt-engineer: the model
plans its own steps, writes its own scripts, and runs them in a real container
until it can answer. The loop's only opinions are about safety and termination.
"""
from __future__ import annotations

from pathlib import Path
from typing import Awaitable, Callable

from .. import db
from ..analysis import prompts
from ..analysis.llm import Ollama, OllamaUnavailable, extract_json
from ..analysis.memory import ScanMemory
from ..config import settings
from .tools import ToolBox

EventFn = Callable[[str, dict], Awaitable[None]]

MAX_HISTORY_CHARS = 14_000


class Investigator:
    def __init__(
        self,
        scan_id: str,
        root: Path,
        task: str,
        *,
        llm: Ollama | None = None,
        memory: ScanMemory | None = None,
        on_event: EventFn | None = None,
        max_steps: int | None = None,
    ):
        self.scan_id = scan_id
        self.task = task
        self.llm = llm or Ollama()
        self.memory = memory or ScanMemory(scan_id)
        self.tools = ToolBox(scan_id, root, self.memory)
        self.on_event = on_event
        self.max_steps = max_steps or settings.agent_max_steps
        self.transcript: list[dict] = []
        self._json_mode_supported = True

    async def run(self) -> dict:
        scan = db.get_scan(self.scan_id) or {}
        context = _brief(scan, self.memory)

        history: list[dict] = [
            {"role": "system", "content": prompts.AGENT_SYSTEM},
            {"role": "user", "content": f"{context}\n\nTASK: {self.task}\n\n"
                                        f"Begin. Reply with one JSON object."},
        ]

        for step in range(1, self.max_steps + 1):
            try:
                raw = await self._chat_for_action(history)
            except OllamaUnavailable as exc:
                await self._event("agent_error", {"error": str(exc)})
                return {"answer": f"The model is unreachable: {exc}", "steps": step - 1,
                        "transcript": self.transcript, "findings": self.tools.new_findings}

            action = extract_json(raw)
            if not isinstance(action, dict) or "tool" not in action:
                history.append({"role": "assistant", "content": raw[:1200]})
                history.append({"role": "user", "content":
                    "Reply with one JSON object containing 'thought', 'tool' and "
                    "'args'. Nothing else."})
                continue

            thought = str(action.get("thought") or "").strip()
            tool = str(action.get("tool") or "").strip()
            args = action.get("args") if isinstance(action.get("args"), dict) else {}

            await self._event("agent_step", {"step": step, "thought": thought,
                                             "tool": tool, "args": args})

            if tool == "finish":
                answer = str(args.get("answer") or thought or "Done.")
                self.transcript.append({"step": step, "thought": thought,
                                        "tool": "finish", "args": args,
                                        "observation": answer})
                await self._event("agent_done", {"answer": answer, "steps": step})
                return {"answer": answer, "steps": step,
                        "transcript": self.transcript,
                        "findings": self.tools.new_findings}

            observation = await self.tools.call(tool, args)
            self.transcript.append({"step": step, "thought": thought, "tool": tool,
                                    "args": args, "observation": observation})
            await self._event("agent_observation", {"step": step, "tool": tool,
                                                    "observation": observation})

            history.append({"role": "assistant", "content": raw[:2000]})
            history.append({"role": "user", "content":
                f"OBSERVATION from {tool}:\n{observation}\n\n"
                f"Step {step}/{self.max_steps}. Next JSON object."})
            history = _trim(history)

        summary = await self._forced_answer(history)
        await self._event("agent_done", {"answer": summary, "steps": self.max_steps})
        return {"answer": summary, "steps": self.max_steps,
                "transcript": self.transcript, "findings": self.tools.new_findings}

    async def _chat_for_action(self, history: list[dict]) -> str:
        """One turn's worth of chat, constrained to JSON when the server allows it.

        Every turn is supposed to be exactly one JSON action — grammar-
        constrained decoding is what makes that reliable instead of hoped-for.
        If this server/model rejects the `format` field outright, fall back to
        plain decoding for the rest of the run rather than treating a feature
        gap as "the model is unreachable".
        """
        if self._json_mode_supported:
            try:
                return await self.llm.chat(history, temperature=0.15, json_mode=True)
            except OllamaUnavailable:
                self._json_mode_supported = False
        return await self.llm.chat(history, temperature=0.15, json_mode=False)

    async def _forced_answer(self, history: list[dict]) -> str:
        history = history + [{"role": "user", "content":
            "You have used your step budget. Write your conclusion now in markdown: "
            "what you checked, what you found, and what is still unverified."}]
        try:
            return await self.llm.chat(history, temperature=0.2)
        except OllamaUnavailable as exc:
            return f"Ran out of steps and the model went away: {exc}"

    async def _event(self, kind: str, payload: dict) -> None:
        if self.on_event:
            await self.on_event(kind, payload)


def _brief(scan: dict, memory: ScanMemory) -> str:
    scan_id = scan.get("id", "")
    findings = db.list_findings(scan_id)[:15]
    listed = [
        f"- [{f['severity']}] {f['title']} — {f['file_path']}:{f['line_start'] or '?'}"
        for f in findings
    ] or ["- none"]
    return "\n".join([
        f"TARGET: {scan.get('url')}",
        f"MIRROR: /work (the downloaded copy, {len(db.list_files(scan_id))} files)",
        "",
        memory.context_block(budget=2000) or "(no memory yet)",
        "",
        "Findings so far:",
        *listed,
    ])


def _trim(history: list[dict]) -> list[dict]:
    """Keep the system prompt, the task, and the tail that fits."""
    if len(history) <= 4:
        return history
    head, tail = history[:2], history[2:]
    total = sum(len(m["content"]) for m in tail)
    while total > MAX_HISTORY_CHARS and len(tail) > 4:
        dropped = tail.pop(0)
        total -= len(dropped["content"])
    return head + tail
