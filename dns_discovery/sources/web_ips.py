from __future__ import annotations

import httpx

from ..dns import is_ipv4
from ..failures import FailureSink


class WebIpSource:
    def __init__(self, failures: FailureSink, user_agent: str = "dns-discovery-engine/2.0") -> None:
        self.failures=failures; self.user_agent=user_agent; self.available=True

    async def lookup(self, hostname: str) -> list[str]:
        if not self.available: return []
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
                resp=await client.get("https://api.hackertarget.com/dnslookup/", params={"q":hostname}, headers={"User-Agent":self.user_agent})
            text=resp.text.strip()
            if resp.status_code==429 or "rate limit" in text.lower():
                self.available=False; self.failures.record("web","dnslookup","rate limited",hostname=hostname,error_type="RateLimit"); return []
            ips=[]
            for line in text.splitlines():
                for p in line.replace(":"," ").split():
                    if is_ipv4(p): ips.append(p)
            return ips
        except Exception as e:
            self.failures.record("web","dnslookup",e,hostname=hostname); return []
