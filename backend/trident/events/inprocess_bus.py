"""In-process event fan-out — desktop mode's replacement for Redis pub/sub.

A single process has no need for cross-process pub/sub: each job gets an
in-memory `asyncio.Queue` per subscriber. `publish` is called from worker
threads (scans run via `asyncio.to_thread`), so it hands off to the main event
loop with `call_soon_threadsafe` rather than touching the queue directly from
a non-loop thread.
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from typing import Any

_lock = threading.Lock()
_subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


def subscribe(job_id: str) -> asyncio.Queue:
    """Call from the event-loop thread (a websocket handler). Returns a queue
    that receives every event published for this job until `unsubscribe`."""
    q: asyncio.Queue = asyncio.Queue()
    with _lock:
        _subscribers[job_id].append(q)
    return q


def unsubscribe(job_id: str, q: asyncio.Queue) -> None:
    with _lock:
        subs = _subscribers.get(job_id)
        if subs and q in subs:
            subs.remove(q)
            if not subs:
                _subscribers.pop(job_id, None)


def publish(job_id: str, payload: dict[str, Any]) -> None:
    """Call from any thread (worker threads included) — safe by design."""
    with _lock:
        subs = list(_subscribers.get(job_id, ()))
    if not subs or _main_loop is None:
        return
    for q in subs:
        _main_loop.call_soon_threadsafe(q.put_nowait, payload)
