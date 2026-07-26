"""One conversation. No modes.

The user talks; the model answers or acts, and decides which for itself. Ask it
a question and it answers. Tell it to run a userscript and it writes the file,
runs it, reads the output and tells you what happened — in the same reply,
streamed, without anyone flipping a switch.

The loop:
    stream tokens -> parser -> prose goes to the browser
                            -> an action block executes the moment it closes
                            -> its result is appended and the model continues
until the model finishes a turn without opening a new action.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Awaitable, Callable

from .. import db
from ..analysis.llm import Ollama, OllamaUnavailable
from ..analysis.memory import ScanMemory
from ..config import settings
from .actions import ActionRunner
from .protocol import StreamParser
from .prompt import build_system_prompt, build_context

EmitFn = Callable[[str, dict], Awaitable[None]]

MAX_ROUNDS = 12          # action->continue cycles inside a single user turn
MAX_HISTORY_CHARS = 18_000


class Conversation:
    def __init__(self, scan_id: str, root: Path, *, llm: Ollama | None = None,
                 emit: EmitFn | None = None):
        self.scan_id = scan_id
        self.root = Path(root)
        self.llm = llm or Ollama()
        self.memory = ScanMemory(scan_id)
        self.actions = ActionRunner(scan_id, self.root, self.memory)
        self.emit = emit

    async def send(self, message: str) -> dict:
        """Handle one user message end to end, streaming as it goes."""
        db.add_message(self.scan_id, "user", message)

        history = self._history()
        history.append({"role": "user", "content": message})

        transcript: list[dict] = []
        full_text: list[str] = []
        used_actions = 0

        for _ in range(MAX_ROUNDS):
            parser = StreamParser()
            round_text: list[str] = []
            pending: dict | None = None

            try:
                stream = self.llm.stream_chat(history, temperature=0.3)
                async for token in stream:
                    for kind, payload in parser.feed(token):
                        pending = await self._handle(kind, payload, round_text,
                                                     transcript)
                        if pending is not None:
                            break
                    if pending is not None:
                        # Stop consuming: the action must run before the model
                        # can say anything sensible about its result.
                        await _close(stream)
                        break
                else:
                    for kind, payload in parser.flush():
                        pending = await self._handle(kind, payload, round_text,
                                                     transcript)
                        if pending is not None:
                            break
            except OllamaUnavailable as exc:
                text = (f"\n\n_I lost the model: {exc}_\n\n"
                        f"The findings list is still on the left — it comes from "
                        f"the rule engine and header checks, which don't need it.")
                await self._say(text)
                round_text.append(text)
                full_text.extend(round_text)
                break

            full_text.extend(round_text)
            assistant_turn = "".join(round_text)

            if pending is None:
                break  # the model finished talking

            used_actions += 1
            result = await self._execute(pending)
            transcript.append(result)

            history.append({"role": "assistant",
                            "content": (assistant_turn + pending["raw"])[:6000]})
            history.append({"role": "user", "content":
                            f"[result of {pending['tool']}]\n{result['observation']}\n\n"
                            f"Continue. If the task is done, say so plainly — do not "
                            f"repeat an action that already succeeded."})
            history = _trim(history)

        answer = "".join(full_text).strip()
        db.add_message(self.scan_id, "assistant", answer,
                       meta={"kind": "chat", "actions": used_actions,
                             "transcript": transcript[-20:]})
        await self._send("turn_end", {"content": answer, "actions": used_actions})
        return {"answer": answer, "actions": used_actions,
                "transcript": transcript,
                "findings": self.actions.new_findings}

    # ------------------------------------------------------------------ events
    async def _handle(self, kind: str, payload, round_text: list,
                      transcript: list) -> dict | None:
        if kind == "text":
            round_text.append(payload)
            await self._say(payload)
            return None

        if kind == "tool_open":
            await self._send("action_open", {
                "tool": payload["tool"], "args": payload["args"],
                "path": payload["args"].get("path"),
            })
            return None

        if kind == "tool_delta":
            # This is what makes a file appear to be written live.
            await self._send("action_delta", {"text": payload["text"]})
            return None

        if kind == "tool_close":
            raw = _reconstruct(payload)
            return {"tool": payload["tool"], "args": payload["args"],
                    "body": payload["body"], "raw": raw}
        return None

    async def _execute(self, pending: dict) -> dict:
        result = await self.actions.run(pending["tool"], pending["args"],
                                        pending["body"])
        await self._send("action_result", {
            "tool": pending["tool"],
            "args": pending["args"],
            "ok": result["ok"],
            "observation": result["observation"],
            "meta": result.get("meta", {}),
        })
        return {"tool": pending["tool"], "args": pending["args"], **result}

    async def _say(self, text: str) -> None:
        await self._send("token", {"content": text})

    async def _send(self, kind: str, payload: dict) -> None:
        if self.emit:
            await self.emit(kind, payload)

    # ------------------------------------------------------------------ context
    def _history(self) -> list[dict]:
        messages = [{"role": "system", "content": build_system_prompt()},
                    {"role": "user", "content": build_context(self.scan_id,
                                                              self.memory)}]
        for turn in db.list_messages(self.scan_id)[-12:]:
            if turn["role"] in ("user", "assistant") and turn["content"]:
                messages.append({"role": turn["role"],
                                 "content": turn["content"][:4000]})
        return _trim(messages)


async def _close(stream) -> None:
    aclose = getattr(stream, "aclose", None)
    if aclose:
        try:
            await aclose()
        except Exception:
            pass


def _reconstruct(payload: dict) -> str:
    args = " ".join(f'{k}="{v}"' for k, v in payload["args"].items()
                    if not k.startswith("_"))
    header = f"```tool:{payload['tool']}" + (f" {args}" if args else "")
    return f"\n{header}\n{payload['body']}```\n"


def _trim(history: list[dict]) -> list[dict]:
    """Keep the system prompt and context, drop the oldest middle turns."""
    if len(history) <= 3:
        return history
    head, tail = history[:2], history[2:]
    total = sum(len(m["content"]) for m in tail)
    while total > MAX_HISTORY_CHARS and len(tail) > 2:
        total -= len(tail.pop(0)["content"])
    return head + tail
