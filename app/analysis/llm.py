"""Ollama client.

Two entry points: `chat` (buffered, used by the auditor and the agent) and
`stream_chat` (token-by-token, used by the chat UI). Plus `json_chat`, which
insists on a parseable object and repairs the usual model mistakes.
"""
from __future__ import annotations

import json
import re
from typing import AsyncIterator, Iterable

import httpx

from ..config import settings


class OllamaUnavailable(RuntimeError):
    """Raised when the daemon is not reachable or the model is missing."""


class Ollama:
    def __init__(self, host: str | None = None, model: str | None = None):
        self.host = (host or settings.ollama_host).rstrip("/")
        self.model = model or settings.ollama_model

    # ------------------------------------------------------------------ status
    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                resp = await c.get(f"{self.host}/api/tags")
                resp.raise_for_status()
                tags = [m["name"] for m in resp.json().get("models", [])]
        except Exception as exc:
            return {
                "ok": False,
                "host": self.host,
                "model": self.model,
                "error": f"{type(exc).__name__}: {exc}",
                "hint": f"Start Ollama, then: ollama pull {self.model}",
            }
        base = self.model.split(":")[0]
        installed = any(t == self.model or t.split(":")[0] == base for t in tags)
        return {
            "ok": installed,
            "host": self.host,
            "model": self.model,
            "models": tags,
            "error": None if installed else f"model '{self.model}' not pulled",
            "hint": None if installed else f"ollama pull {self.model}",
        }

    # ------------------------------------------------------------------ chat
    async def chat(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.1,
        num_ctx: int | None = None,
        timeout: float = 300.0,
        stop: Iterable[str] | None = None,
        json_mode: bool = False,
    ) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx or settings.ollama_num_ctx,
            },
        }
        if stop:
            payload["options"]["stop"] = list(stop)
        if json_mode:
            # Ollama's grammar-constrained decoding: the model is only allowed
            # to sample tokens that keep the output valid JSON. This is what
            # actually makes the auditor's structured findings reliable —
            # without it we are just hoping a chatty local model remembers to
            # skip the markdown fence and the "Sure, here's the analysis:".
            payload["format"] = "json"
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                resp = await c.post(f"{self.host}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json().get("message", {}).get("content", "")
        except httpx.HTTPError as exc:
            raise OllamaUnavailable(
                f"Ollama at {self.host} did not answer ({exc}). "
                f"Is it running, and is '{self.model}' pulled?"
            ) from exc

    async def stream_chat(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.2,
        num_ctx: int | None = None,
        timeout: float = 600.0,
    ) -> AsyncIterator[str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx or settings.ollama_num_ctx,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as c:
                async with c.stream("POST", f"{self.host}/api/chat", json=payload) as r:
                    r.raise_for_status()
                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except ValueError:
                            continue
                        piece = chunk.get("message", {}).get("content", "")
                        if piece:
                            yield piece
                        if chunk.get("done"):
                            return
        except httpx.HTTPError as exc:
            raise OllamaUnavailable(
                f"Ollama at {self.host} closed the stream ({exc})."
            ) from exc

    # ------------------------------------------------------------------ json
    async def json_chat(self, messages: list[dict], *, temperature: float = 0.05,
                        retries: int = 2) -> dict | list:
        """Ask for JSON and keep asking until something parses.

        Grammar-constrained decoding (`format: "json"`) is tried first — it is
        the difference between the model reliably reporting what it found and
        a free-text reply our parser has to gamble on. If a build or model
        rejects the constraint outright, we fall back to plain decoding plus
        text extraction rather than losing the finding entirely.
        """
        last = ""
        constrained = True
        for attempt in range(retries + 1):
            try:
                raw = await self.chat(messages, temperature=temperature,
                                      json_mode=constrained)
            except OllamaUnavailable:
                if not constrained:
                    raise
                constrained = False
                raw = await self.chat(messages, temperature=temperature,
                                      json_mode=False)
            last = raw
            parsed = extract_json(raw)
            if parsed is not None:
                return parsed
            messages = messages + [
                {"role": "assistant", "content": raw[:1500]},
                {"role": "user", "content":
                    "That was not valid JSON. Reply with the JSON object only — "
                    "no prose, no markdown fence, no trailing commas."},
            ]
        raise ValueError(f"model never produced JSON; last reply: {last[:400]}")


# --------------------------------------------------------------------------- helpers
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def extract_json(text: str):
    """Pull the first JSON object/array out of a model reply."""
    if not text:
        return None
    text = text.strip()

    for candidate in _fence_candidates(text):
        try:
            return json.loads(candidate)
        except ValueError:
            cleaned = _repair(candidate)
            try:
                return json.loads(cleaned)
            except ValueError:
                continue
    return None


def _fence_candidates(text: str) -> list[str]:
    out = []
    for m in _FENCE.findall(text):
        out.append(m.strip())
    out.append(text)
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            out.append(text[start:end + 1])
    return out


def _repair(text: str) -> str:
    text = re.sub(r",\s*([}\]])", r"\1", text)          # trailing commas
    text = re.sub(r"//[^\n]*", "", text)                 # line comments
    text = text.replace("“", '"').replace("”", '"')
    text = text.replace("‘", "'").replace("’", "'")
    # A model trained mostly on Python sometimes drifts into Python literals
    # instead of JSON ones — cheap enough to fix, common enough to bother.
    text = re.sub(r"\bTrue\b", "true", text)
    text = re.sub(r"\bFalse\b", "false", text)
    text = re.sub(r"\bNone\b", "null", text)
    return text.strip()
