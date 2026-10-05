from __future__ import annotations

import httpx

from ..failures import FailureSink
from ..rate_limit import RateLimiter


class CrtShSource:
    def __init__(self, rate: RateLimiter, failures: FailureSink) -> None:
        self.rate = rate; self.failures = failures

    async def related_hostnames(self, domain: str) -> set[str]:
        await self.rate.acquire(source="ct")
        try:
            async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent":"dns-discovery-engine/2.0"}) as client:
                r = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output":"json"})
                r.raise_for_status(); rows=r.json()
            out=set()
            for row in rows:
                for name in str(row.get("name_value","")).splitlines():
                    name=name.strip().lower().lstrip("*.").rstrip(".")
                    if name==domain or name.endswith("."+domain): out.add(name)
            return out
        except Exception as e:
            self.failures.record("ct", "crtsh", e, hostname=domain); return set()
