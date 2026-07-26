"""The streaming tool protocol.

The model talks in ordinary prose and, whenever it wants to *do* something,
opens a fenced action block:

    ```tool:run
    npm install
    ```

    ```tool:write path="scripts/probe.py"
    import sys
    print("hello")
    ```

Why fences instead of Ollama's JSON tool-calling: a 3B model streams prose far
more reliably than it emits well-formed tool JSON, and a fence can be parsed
*incrementally*. That is what makes it possible to show a file being written
character by character in the UI rather than waiting for a complete tool call.

`StreamParser.feed()` is fed raw tokens and yields typed events as soon as they
are unambiguous:

    ("text",        str)                prose to render
    ("tool_open",   {tool, args})       a block just started — draw the chip
    ("tool_delta",  {text})             more body arrived — stream it live
    ("tool_close",  {tool, args, body}) block finished — go execute it
"""
from __future__ import annotations

import re
import shlex

FENCE = "```"

# ```tool:<name> key="value" key2="value2"
#
# The `tool:` prefix matters: without it a plain ```python markdown block
# would be indistinguishable from the `python` action, and the model's
# ordinary code samples would get executed.
OPEN_RE = re.compile(r"^```tool:([a-zA-Z_][\w-]*)[ \t]*(.*)$")

# Tools whose body is the payload (a file's contents, a shell script, code).
BODY_TOOLS = {"run", "python", "write", "append", "node", "bash", "sh"}

# Everything the model is allowed to open a fence with.
KNOWN_TOOLS = BODY_TOOLS | {
    "read", "list", "tree", "grep", "mkdir", "move", "copy", "delete",
    "install", "serve", "stop", "logs", "finding", "remember", "fetch",
}


def parse_args(raw: str) -> dict:
    """`path="a b.py" mode=w` -> {"path": "a b.py", "mode": "w"}"""
    args: dict[str, str] = {}
    raw = (raw or "").strip()
    if not raw:
        return args
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    positional: list[str] = []
    for token in tokens:
        if "=" in token:
            key, _, value = token.partition("=")
            key = key.strip()
            if key.isidentifier():
                args[key] = value.strip().strip("\"'")
                continue
        positional.append(token.strip().strip("\"'"))
    if positional and "path" not in args:
        args["path"] = positional[0]
    if positional:
        args.setdefault("_positional", " ".join(positional))
    return args


class StreamParser:
    """Incremental fence parser. Feed it tokens, get events."""

    def __init__(self) -> None:
        self._buf = ""
        self.in_tool = False
        self.tool: str | None = None
        self.args: dict = {}
        self._body = ""

    def feed(self, chunk: str) -> list[tuple[str, object]]:
        self._buf += chunk
        events: list[tuple[str, object]] = []

        while True:
            if not self.in_tool:
                # Outside a block: emit prose up to a potential fence start.
                idx = self._buf.find(FENCE)
                if idx == -1:
                    # Hold back a partial fence so ``` never leaks as prose.
                    # Longest prefix first: with "``" buffered, matching the
                    # 1-char prefix would emit the first backtick as text.
                    safe = self._buf
                    keep = 0
                    for n in range(len(FENCE) - 1, 0, -1):
                        if safe.endswith(FENCE[:n]):
                            keep = n
                            break
                    if keep:
                        emit, self._buf = safe[:-keep], safe[-keep:]
                    else:
                        emit, self._buf = safe, ""
                    if emit:
                        events.append(("text", emit))
                    return events

                if idx > 0:
                    events.append(("text", self._buf[:idx]))
                    self._buf = self._buf[idx:]

                newline = self._buf.find("\n")
                if newline == -1:
                    return events  # opening line still arriving

                header = self._buf[:newline]
                match = OPEN_RE.match(header)
                if not match or match.group(1) not in KNOWN_TOOLS:
                    # An ordinary markdown fence — emit the header and let the
                    # body flow through as prose on the next iterations.
                    events.append(("text", self._buf[:newline + 1]))
                    self._buf = self._buf[newline + 1:]
                    continue

                self.in_tool = True
                self.tool = match.group(1)
                self.args = parse_args(match.group(2))
                self._body = ""
                self._buf = self._buf[newline + 1:]
                events.append(("tool_open", {"tool": self.tool, "args": self.args}))
                continue

            # Inside a block: look for the closing fence at a line start.
            close = self._find_close(self._buf)
            if close is None:
                # Stream everything except a possible partial terminator.
                cut = self._safe_body_cut(self._buf)
                if cut:
                    body, self._buf = self._buf[:cut], self._buf[cut:]
                    self._body += body
                    events.append(("tool_delta", {"text": body}))
                return events

            body = self._buf[:close]
            self._body += body
            if body:
                events.append(("tool_delta", {"text": body}))
            events.append(("tool_close", {
                "tool": self.tool, "args": self.args, "body": self._body,
            }))
            # Skip past the closing fence and its newline.
            rest = self._buf[close:]
            rest = rest[len(FENCE):] if rest.startswith(FENCE) else rest
            self._buf = rest.lstrip("\n") if rest.startswith("\n") else rest
            self.in_tool = False
            self.tool = None
            self.args = {}
            self._body = ""

    @staticmethod
    def _find_close(buf: str) -> int | None:
        if buf.startswith(FENCE):
            return 0
        idx = buf.find("\n" + FENCE)
        return idx + 1 if idx != -1 else None

    @staticmethod
    def _safe_body_cut(buf: str) -> int:
        """How much of the body is safe to emit without swallowing a terminator."""
        for n in range(min(len(buf), len(FENCE) + 1), 0, -1):
            tail = buf[-n:]
            if ("\n" + FENCE).startswith(tail) or FENCE.startswith(tail):
                return len(buf) - n
        return len(buf)

    def flush(self) -> list[tuple[str, object]]:
        """End of stream: emit whatever is left, closing an unterminated block."""
        events: list[tuple[str, object]] = []
        if self.in_tool:
            if self._buf:
                self._body += self._buf
                events.append(("tool_delta", {"text": self._buf}))
            events.append(("tool_close", {
                "tool": self.tool, "args": self.args, "body": self._body,
            }))
            self.in_tool = False
        elif self._buf:
            events.append(("text", self._buf))
        self._buf = ""
        return events
