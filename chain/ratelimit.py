"""Per-target egress throttle: a token bucket (requests/sec) plus a concurrency
semaphore, so a scan can't hammer — or knock over — a fragile in-scope target.

Clock and sleep are injectable for deterministic tests.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Awaitable, Callable


class RateLimiter:
    def __init__(
        self,
        rps: float = 5.0,
        concurrency: int = 4,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.rps = float(rps)
        self.capacity = float(burst if burst is not None else max(1, int(self.rps)))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max(1, int(concurrency)))

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rps)
        self._updated = now

    async def _take(self) -> None:
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rps
                await self._sleep(wait)
                self._refill()
            self._tokens -= 1

    @asynccontextmanager
    async def slot(self):
        """Acquire one request slot: wait for a token, hold a concurrency seat."""
        await self._take()
        await self._sem.acquire()
        try:
            yield
        finally:
            self._sem.release()
