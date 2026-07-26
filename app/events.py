"""In-process pub/sub so a WebSocket can watch a background scan.

Each scan gets a list of subscriber queues plus a replay buffer, so a browser
that connects late (or reloads mid-scan) still sees what it missed.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from typing import AsyncIterator

REPLAY = 300


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=REPLAY))
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, event: dict) -> None:
        async with self._lock:
            self._history[topic].append(event)
            targets = list(self._subs.get(topic, []))
        for q in targets:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, topic: str, replay: bool = True) -> AsyncIterator[dict]:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self._lock:
            if replay:
                for event in self._history[topic]:
                    q.put_nowait(event)
            self._subs[topic].append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if q in self._subs.get(topic, []):
                    self._subs[topic].remove(q)

    def history(self, topic: str) -> list[dict]:
        return list(self._history.get(topic, []))


bus = EventBus()
