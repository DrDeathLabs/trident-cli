"""Per-job LLM-call budget — a thread-safe hard cap shared across the scan loop.

Metered in real time: every LLM call takes 1 before it runs (including each step
of an agent loop, from worker threads), so `max_llm_calls` is an actual ceiling —
not a reservation reconciled after the fact.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class LLMBudget:
    limit: int | None = None
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def take(self, n: int = 1) -> bool:
        """Reserve n calls if they fit under the limit. Thread-safe. False if they don't."""
        with self._lock:
            if self.limit is not None and self.used + n > self.limit:
                return False
            self.used += n
            return True

    def charge(self, n: int = 1) -> None:
        """Count n calls that already happened (essential calls that can't be gated)."""
        with self._lock:
            self.used += n

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self.limit is not None and self.used >= self.limit
