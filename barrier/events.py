"""In-process event bus -> Server-Sent Events.

Every decision, ruling, withdrawal, posture flip and self-training step is
published here the moment it happens, and the dashboard listens on
GET /v1/events. During a live demo nothing waits for a poll: an agent writes,
the verdict appears.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from typing import Any, Iterator


class EventBus:
    def __init__(self, history: int = 200) -> None:
        self._subscribers: list[queue.Queue] = []
        self._history: deque[dict[str, Any]] = deque(maxlen=history)
        self._lock = threading.Lock()
        self._seq = 0

    def publish(self, kind: str, payload: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "ts": time.time(), "kind": kind, **(payload or {})}
            self._history.append(event)
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # a stalled listener never blocks the product

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)[-limit:]

    def stream(self) -> Iterator[str]:
        """SSE frames. Replays a little history so a fresh tab has context."""
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            backlog = list(self._history)[-20:]
            self._subscribers.append(q)
        try:
            for event in backlog:
                yield f"data: {json.dumps(event)}\n\n"
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with self._lock:
                if q in self._subscribers:
                    self._subscribers.remove(q)


bus = EventBus()
