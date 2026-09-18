"""Event records and the fan-out bus between the monitor and its consumers.

The monitor thread does blocking ioctls and must never wait on a slow
consumer, so publishing is non-blocking: every subscriber gets a bounded
queue, and a subscriber that falls behind drops events rather than back-
pressuring the supervisor. Violations are the exception -- they are never
dropped, because the whole point of the tool is that you see them.
"""

from __future__ import annotations

import itertools
import json
import queue
import threading
import time
from dataclasses import asdict, dataclass, field


@dataclass
class Event:
    seq: int
    ts: float
    kind: str  # syscall | violation | state | lifecycle | stats
    severity: str  # info | suspicious | violation
    syscall: str | None = None
    pid: int | None = None
    rule: str | None = None
    summary: str = ""
    action: str | None = None
    detail: dict = field(default_factory=dict)
    latency_us: float | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


class EventBus:
    def __init__(self, history: int = 500):
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        self._history: list[Event] = []
        self._history_max = history
        self.dropped = 0

    def make(self, kind: str, severity: str = "info", **kw) -> Event:
        return Event(seq=next(self._counter), ts=time.time(),
                     kind=kind, severity=severity, **kw)

    def publish(self, event: Event) -> Event:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._history_max:
                del self._history[: len(self._history) - self._history_max]
            subs = list(self._subscribers)
        critical = event.severity == "violation" or event.kind in ("state", "lifecycle")
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                if critical:
                    # Make room by discarding the oldest routine event rather
                    # than losing the one that matters.
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except (queue.Empty, queue.Full):
                        self.dropped += 1
                else:
                    self.dropped += 1
        return event

    def emit(self, kind: str, severity: str = "info", **kw) -> Event:
        return self.publish(self.make(kind, severity, **kw))

    def subscribe(self, maxsize: int = 2048) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def history(self) -> list[Event]:
        with self._lock:
            return list(self._history)
