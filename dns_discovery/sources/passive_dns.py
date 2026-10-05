"""Passive / historical DNS adapters — only real public endpoints; no fabrication."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from ..failures import FailureSink
from ..models import utc_now_iso
from ..rate_limit import RateLimiter


class PassiveDnsResult:
    def __init__(self) -> None:
        self.status = "ok"  # ok | unavailable | partial
        self.records: list[dict[str, Any]] = []
        self.providers_tried: list[dict[str, Any]] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "PASSIVE_DNS": self.status if self.status != "ok" or self.records else (
                "unavailable" if not self.providers_tried else self.status
            ),
            "records": self.records,
            "providers": self.providers_tried,
        }


class HackerTargetPassive:
    """
    https://api.hackertarget.com/hostsearch/?q=<domain>
    Free, no key, strict rate limits (~1/req/sec-ish, daily caps).
    Returns hostname,ip pairs — treat as HISTORICALLY_OBSERVED / CANDIDATE, not live proof.
    """

    ENDPOINT = "https://api.hackertarget.com/hostsearch/"

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        user_agent: str,
        rps: float = 0.4,
    ) -> None:
        self.client = client
        self.rate = rate_limiter
        self.failures = failures
        self.user_agent = user_agent
        self.rate.named("passive_hackertarget", rps)
        self.available = True

    async def lookup(self, domain: str) -> dict[str, Any]:
        if not self.available:
            return {
                "provider": "hackertarget",
                "status": "unavailable",
                "endpoint": self.ENDPOINT,
                "records": [],
            }
        await self.rate.acquire(source="passive_dns", named="passive_hackertarget", hostname=domain)
        try:
            resp = await self.client.get(
                self.ENDPOINT,
                params={"q": domain},
                headers={"User-Agent": self.user_agent},
                timeout=30.0,
            )
            text = resp.text.strip()
            if resp.status_code == 429 or "rate limit" in text.lower():
                self.available = False
                self.failures.record(
                    "passive_dns",
                    "hackertarget",
                    "rate limited",
                    hostname=domain,
                    error_type="RateLimit",
                )
                return {
                    "provider": "hackertarget",
                    "status": "rate_limited",
                    "endpoint": f"{self.ENDPOINT}?q={domain}",
                    "records": [],
                }
            if "error" in text.lower() and "," not in text.split("\n", 1)[0]:
                self.failures.record("passive_dns", "hackertarget", text[:300], hostname=domain)
                return {
                    "provider": "hackertarget",
                    "status": "error",
                    "endpoint": f"{self.ENDPOINT}?q={domain}",
                    "records": [],
                    "message": text[:300],
                }
            records = []
            for line in text.splitlines():
                line = line.strip()
                if not line or "," not in line:
                    continue
                host, ip = line.split(",", 1)
                host = host.strip().lower().rstrip(".")
                ip = ip.strip()
                if not host or not ip:
                    continue
                records.append(
                    {
                        "hostname": host,
                        "ip": ip,
                        "source": "passive_dns",
                        "provider": "hackertarget",
                        "endpoint": f"{self.ENDPOINT}?q={domain}",
                        "first_seen": None,  # API does not provide timestamps
                        "last_seen": None,
                        "timestamp": utc_now_iso(),
                        "note": "HackerTarget hostsearch does not expose first/last seen; times are UNKNOWN",
                    }
                )
            return {
                "provider": "hackertarget",
                "status": "ok",
                "endpoint": f"{self.ENDPOINT}?q={domain}",
                "records": records,
            }
        except Exception as e:
            self.failures.record("passive_dns", "hackertarget", e, hostname=domain)
            return {
                "provider": "hackertarget",
                "status": "error",
                "endpoint": self.ENDPOINT,
                "records": [],
                "error_type": type(e).__name__,
            }


class SecurityTrailsPassive:
    """Optional — requires SECURITYTRAILS_API_KEY. Skipped if unset."""

    ENDPOINT = "https://api.securitytrails.com/v1/history/{domain}/dns/a"

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        api_key: str | None,
        user_agent: str,
        rps: float = 0.5,
    ) -> None:
        self.client = client
        self.rate = rate_limiter
        self.failures = failures
        self.api_key = api_key
        self.user_agent = user_agent
        self.rate.named("passive_securitytrails", rps)

    async def lookup(self, domain: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "provider": "securitytrails",
                "status": "skipped",
                "reason": "SECURITYTRAILS_API_KEY not set",
                "records": [],
            }
        await self.rate.acquire(source="passive_dns", named="passive_securitytrails", hostname=domain)
        url = self.ENDPOINT.format(domain=domain)
        try:
            resp = await self.client.get(
                url,
                headers={
                    "APIKEY": self.api_key,
                    "User-Agent": self.user_agent,
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
            if resp.status_code == 429:
                self.failures.record("passive_dns", "securitytrails", "rate limited", hostname=domain, error_type="RateLimit")
                return {"provider": "securitytrails", "status": "rate_limited", "records": []}
            if resp.status_code >= 400:
                self.failures.record(
                    "passive_dns",
                    "securitytrails",
                    f"HTTP {resp.status_code}",
                    hostname=domain,
                )
                return {"provider": "securitytrails", "status": "error", "records": []}
            data = resp.json()
            records = []
            for item in data.get("records") or []:
                values = item.get("values") or []
                first_seen = item.get("first_seen")
                last_seen = item.get("last_seen")
                for v in values:
                    ip = v.get("ip") if isinstance(v, dict) else None
                    if not ip:
                        continue
                    records.append(
                        {
                            "hostname": domain,
                            "ip": ip,
                            "source": "passive_dns",
                            "provider": "securitytrails",
                            "endpoint": url,
                            "first_seen": first_seen,
                            "last_seen": last_seen,
                            "timestamp": utc_now_iso(),
                        }
                    )
            return {"provider": "securitytrails", "status": "ok", "endpoint": url, "records": records}
        except Exception as e:
            self.failures.record("passive_dns", "securitytrails", e, hostname=domain)
            return {"provider": "securitytrails", "status": "error", "records": [], "error_type": type(e).__name__}


class PassiveDnsAggregator:
    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        user_agent: str,
        securitytrails_key: str | None = None,
        rps: float = 0.4,
    ) -> None:
        self.ht = HackerTargetPassive(client, rate_limiter, failures, user_agent, rps=rps)
        self.st = SecurityTrailsPassive(
            client, rate_limiter, failures, securitytrails_key, user_agent, rps=rps
        )
        self.failures = failures

    async def lookup(self, domain: str) -> PassiveDnsResult:
        result = PassiveDnsResult()
        # Use registrable-ish parent (last two labels) for hostsearch scope
        labels = domain.lower().strip(".").split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else domain

        providers = await asyncio.gather(
            self.ht.lookup(base),
            self.st.lookup(domain),
            return_exceptions=True,
        )
        any_ok = False
        for p in providers:
            if isinstance(p, Exception):
                self.failures.record("passive_dns", "aggregate", p, hostname=domain)
                result.providers_tried.append({"status": "error", "error_type": type(p).__name__})
                continue
            result.providers_tried.append({k: v for k, v in p.items() if k != "records"})
            if p.get("status") == "ok":
                any_ok = True
                result.records.extend(p.get("records") or [])
        if not any_ok and not result.records:
            result.status = "unavailable"
        elif any_ok:
            result.status = "ok"
        else:
            result.status = "partial"
        return result
