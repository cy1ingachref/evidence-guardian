"""Rate limiter for polite scanning mode."""
from __future__ import annotations

import time
import threading
from collections import defaultdict
from typing import Any


class RateLimiter:
    """Token-bucket rate limiter for polite scanning."""

    def __init__(self, requests_per_second: float = 5.0, burst: int = 10):
        self.rate = requests_per_second
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.time()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Acquire a token. Returns wait time if rate limited."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return 0.0
            else:
                wait_time = (1.0 - self.tokens) / self.rate
                return wait_time

    def wait(self):
        """Wait until a token is available."""
        wait_time = self.acquire()
        if wait_time > 0:
            time.sleep(wait_time)


class DomainRateLimiter:
    """Per-domain rate limiter."""

    def __init__(self, requests_per_second: float = 5.0):
        self.rate = requests_per_second
        self.limiters: dict[str, RateLimiter] = defaultdict(
            lambda: RateLimiter(requests_per_second, burst=5)
        )

    def wait(self, domain: str):
        """Wait for the given domain."""
        self.limiters[domain].wait()
