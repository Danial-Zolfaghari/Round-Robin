"""Certificate Transparency via crt.sh (public JSON API, no key)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..failures import FailureSink
from ..models import utc_now_iso
from ..rate_limit import RateLimiter

HOSTNAME_RE = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$"
)


def parent_domains(hostname: str) -> list[str]:
    host = hostname.lower().strip().rstrip(".")
    labels = host.split(".")
    out: list[str] = []
    if host:
        out.append(host)
    for i in range(1, max(len(labels) - 1, 1)):
        parent = ".".join(labels[i:])
        if parent and parent not in out and parent.count(".") >= 1:
            out.append(parent)
    return out


def normalize_ct_name(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    if not name or " " in name or "@" in name:
        return None
    if not HOSTNAME_RE.match(name) and not (name.startswith("*.") and HOSTNAME_RE.match(name[2:])):
        return None
    return name


class CrtShSource:
    ENDPOINT = "https://crt.sh/"

    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        user_agent: str,
        rps: float = 0.5,
    ) -> None:
        self.client = client
        self.rate = rate_limiter
        self.failures = failures
        self.user_agent = user_agent
        self.rate.named("ct_crtsh", rps)
        self.available = True
        self._fail_streak = 0

    async def discover_hostnames(self, hostname: str) -> dict[str, Any]:
        if not self.available:
            return {
                "source": "certificate_transparency",
                "provider": "crt.sh",
                "status": "unavailable",
                "hostnames": [],
                "raw_count": 0,
                "queries": [],
            }

        queries = []
        for parent in parent_domains(hostname)[:3]:
            queries.append(parent)
            if parent.count(".") >= 1:
                queries.append(f"%.{parent}")

        seen_q: set[str] = set()
        uniq_queries = []
        for q in queries:
            if q not in seen_q:
                seen_q.add(q)
                uniq_queries.append(q)

        hostnames: set[str] = set()
        raw_count = 0
        query_meta: list[dict[str, Any]] = []

        for q in uniq_queries:
            await self.rate.acquire(source="ct", named="ct_crtsh", hostname=hostname)
            try:
                rows = await self._fetch(q)
                raw_count += len(rows)
                extracted = 0
                for row in rows:
                    nv = row.get("name_value") or ""
                    for part in re.split(r"[\n,\s]+", nv):
                        n = normalize_ct_name(part)
                        if n:
                            hostnames.add(n)
                            extracted += 1
                query_meta.append({
                    "query": q,
                    "endpoint": f"{self.ENDPOINT}?q={q}&output=json",
                    "rows": len(rows),
                    "names_extracted": extracted,
                    "timestamp": utc_now_iso(),
                    "status": "ok",
                })
                self._fail_streak = 0
            except Exception as e:
                self._fail_streak += 1
                self.failures.record("certificate_transparency", f"crt.sh:{q}", e, hostname=hostname)
                query_meta.append({
                    "query": q,
                    "endpoint": f"{self.ENDPOINT}?q={q}&output=json",
                    "rows": 0,
                    "status": "error",
                    "error_type": type(e).__name__,
                    "timestamp": utc_now_iso(),
                })
                if self._fail_streak >= 3:
                    self.available = False
                    self.failures.record(
                        "certificate_transparency",
                        "unavailable",
                        "crt.sh marked unavailable after repeated failures",
                        hostname=hostname,
                        error_type="SourceUnavailable",
                    )
                    break

        concrete = sorted(h for h in hostnames if not h.startswith("*."))
        wildcards = sorted(h for h in hostnames if h.startswith("*."))

        return {
            "source": "certificate_transparency",
            "provider": "crt.sh",
            "status": "ok" if self.available else "unavailable",
            "hostnames": concrete,
            "wildcard_names": wildcards,
            "raw_count": raw_count,
            "queries": query_meta,
            "note": "CT hostnames are candidates only; IPs require subsequent DNS resolution",
        }

    async def _fetch(self, query: str) -> list[dict[str, Any]]:
        resp = await self.client.get(
            self.ENDPOINT,
            params={"q": query, "output": "json"},
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            timeout=60.0,
        )
        if resp.status_code == 429:
            raise RuntimeError("crt.sh rate limited (HTTP 429)")
        if resp.status_code >= 400:
            raise RuntimeError(f"crt.sh HTTP {resp.status_code}")
        text = resp.text.strip()
        if not text:
            return []
        data = json.loads(text)
        if not isinstance(data, list):
            raise RuntimeError(f"crt.sh unexpected JSON type: {type(data).__name__}")
        return data
