from __future__ import annotations

import asyncio
import socket

import httpx

from ..failures import FailureSink
from ..models import NetworkInfo
from ..rate_limit import RateLimiter


class IpEnricher:
    def __init__(self, rate_limiter: RateLimiter, failures: FailureSink, semaphore: asyncio.Semaphore | None = None) -> None:
        self.rate = rate_limiter
        self.failures = failures
        self.sem = semaphore or asyncio.Semaphore(6)

    async def enrich(self, ip: str) -> NetworkInfo:
        async with self.sem:
            await self.rate.acquire(source="enrichment")
            rdns = None
            try:
                rdns = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
            except Exception:
                pass
            info = NetworkInfo(reverse_dns=rdns)
            try:
                async with httpx.AsyncClient(timeout=7.0) as client:
                    r = await client.get(f"https://ipwho.is/{ip}")
                    data = r.json()
                    if data.get("success") is not False:
                        conn = data.get("connection") or {}
                        info.asn = str(conn.get("asn")) if conn.get("asn") is not None else None
                        info.organization = conn.get("org")
                        info.isp = conn.get("isp")
                        info.country = data.get("country_code")
                        info.source = "ipwho.is"
            except Exception as e:
                self.failures.record("enrichment", "ipwhois", e)
            return info
