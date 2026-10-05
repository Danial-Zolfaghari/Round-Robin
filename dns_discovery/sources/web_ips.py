"""Public web sources for historically registered domain→IP mappings (real APIs only)."""

from __future__ import annotations

from typing import Any

import httpx

from ..failures import FailureSink
from ..ip_store import is_ipv4
from ..rate_limit import RateLimiter


class WebIpSource:
    """
    Pull candidate IPv4s that appear in public passive/historical indexes.
    These are CANDIDATES until TLS/SNI validation confirms they still serve the hostname.
    """

    HACKERTARGET_HOSTSEARCH = "https://api.hackertarget.com/hostsearch/"
    HACKERTARGET_DNSLOOKUP = "https://api.hackertarget.com/dnslookup/"

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        user_agent: str = "dns-discovery-engine/2.0",
    ) -> None:
        self.client = client
        self.rate = rate_limiter
        self.failures = failures
        self.user_agent = user_agent
        self.rate.named("web_passive", 0.35)
        self.available = True

    async def candidates_for(self, hostname: str) -> list[dict[str, Any]]:
        """Return unique IPv4 candidates claimed for this exact hostname."""
        if not self.available:
            return []

        hostname = hostname.lower().strip().rstrip(".")
        labels = hostname.split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else hostname

        found: dict[str, dict[str, Any]] = {}

        # 1) hostsearch on registrable-ish parent, keep exact hostname rows only
        for row in await self._hostsearch(base):
            if row["hostname"] == hostname and is_ipv4(row["ip"]):
                found[row["ip"]] = row

        # 2) also try hostsearch keyed by full hostname (sometimes returns self)
        if base != hostname:
            for row in await self._hostsearch(hostname):
                if row["hostname"] == hostname and is_ipv4(row["ip"]):
                    found[row["ip"]] = row

        # 3) dnslookup A records (current according to that service — still validate)
        for ip in await self._dnslookup_a(hostname):
            if is_ipv4(ip):
                found.setdefault(
                    ip,
                    {
                        "hostname": hostname,
                        "ip": ip,
                        "provider": "hackertarget",
                        "endpoint": f"{self.HACKERTARGET_DNSLOOKUP}?q={hostname}",
                        "kind": "dnslookup_a",
                    },
                )

        return list(found.values())

    async def _hostsearch(self, query: str) -> list[dict[str, Any]]:
        await self.rate.acquire(named="web_passive", source="web")
        url = self.HACKERTARGET_HOSTSEARCH
        try:
            resp = await self.client.get(
                url,
                params={"q": query},
                headers={"User-Agent": self.user_agent},
                timeout=30.0,
            )
            text = resp.text.strip()
            if resp.status_code == 429 or "rate limit" in text.lower():
                self.available = False
                self.failures.record("web", "hackertarget_hostsearch", "rate limited", hostname=query, error_type="RateLimit")
                return []
            if text.lower().startswith("error"):
                self.failures.record("web", "hackertarget_hostsearch", text[:200], hostname=query)
                return []
            out = []
            for line in text.splitlines():
                line = line.strip()
                if "," not in line:
                    continue
                host, ip = line.split(",", 1)
                host = host.strip().lower().rstrip(".")
                ip = ip.strip()
                if host and ip:
                    out.append(
                        {
                            "hostname": host,
                            "ip": ip,
                            "provider": "hackertarget",
                            "endpoint": f"{url}?q={query}",
                            "kind": "hostsearch",
                        }
                    )
            return out
        except Exception as e:
            self.failures.record("web", "hackertarget_hostsearch", e, hostname=query)
            return []

    async def _dnslookup_a(self, hostname: str) -> list[str]:
        await self.rate.acquire(named="web_passive", source="web")
        try:
            resp = await self.client.get(
                self.HACKERTARGET_DNSLOOKUP,
                params={"q": hostname},
                headers={"User-Agent": self.user_agent},
                timeout=30.0,
            )
            text = resp.text.strip()
            if resp.status_code == 429 or "rate limit" in text.lower():
                self.available = False
                self.failures.record("web", "hackertarget_dnslookup", "rate limited", hostname=hostname, error_type="RateLimit")
                return []
            ips: list[str] = []
            # Lines like: "A : 1.2.3.4" or "A\t1.2.3.4"
            for line in text.splitlines():
                low = line.lower()
                if low.startswith("a ") or low.startswith("a:") or low.startswith("a\t") or " a " in f" {low}":
                    parts = line.replace(":", " ").split()
                    for p in parts:
                        if is_ipv4(p):
                            ips.append(p)
            return ips
        except Exception as e:
            self.failures.record("web", "hackertarget_dnslookup", e, hostname=hostname)
            return []
