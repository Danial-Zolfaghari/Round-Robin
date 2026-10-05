"""Token-bucket rate limiters — per key and global."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class TokenBucket:
    def __init__(self, rate: float, capacity: float | None = None) -> None:
        self.rate = max(rate, 0.01)
        self.capacity = capacity if capacity is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                need = tokens - self.tokens
                wait = need / self.rate
            await asyncio.sleep(wait)


class RateLimiter:
    """Bounded multi-dimensional rate limiting."""

    def __init__(
        self,
        global_rps: float = 20.0,
        per_resolver_rps: float = 5.0,
        per_hostname_rps: float = 8.0,
        per_source_rps: float = 2.0,
    ) -> None:
        self.global_bucket = TokenBucket(global_rps)
        self._resolver = defaultdict(lambda: TokenBucket(per_resolver_rps))
        self._hostname = defaultdict(lambda: TokenBucket(per_hostname_rps))
        self._source = defaultdict(lambda: TokenBucket(per_source_rps))
        self._custom: dict[str, TokenBucket] = {}

    def named(self, name: str, rps: float) -> TokenBucket:
        if name not in self._custom:
            self._custom[name] = TokenBucket(rps)
        return self._custom[name]

    async def acquire(
        self,
        *,
        resolver: str | None = None,
        hostname: str | None = None,
        source: str | None = None,
        named: str | None = None,
    ) -> None:
        await self.global_bucket.acquire()
        if resolver:
            await self._resolver[resolver].acquire()
        if hostname:
            await self._hostname[hostname].acquire()
        if source:
            await self._source[source].acquire()
        if named:
            bucket = self._custom.get(named)
            if bucket:
                await bucket.acquire()
