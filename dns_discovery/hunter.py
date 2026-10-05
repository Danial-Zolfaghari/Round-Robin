from __future__ import annotations

import asyncio
from pathlib import Path

from .config import DEFAULT_RESOLVERS
from .dns import LiveDnsSource
from .failures import FailureSink
from .ip_store import IpTxtStore
from .rate_limit import RateLimiter


async def hunt_once(hostnames: list[str], output_dir: Path, resolvers: list[str] | None = None, excluded_ips: set[str] | None = None) -> dict[str, list[str]]:
    rate = RateLimiter()
    failures = FailureSink()
    source = LiveDnsSource(resolvers or list(DEFAULT_RESOLVERS), rate, failures, excluded_ips=excluded_ips)
    store = IpTxtStore(output_dir, excluded_ips=excluded_ips)
    result: dict[str, list[str]] = {}
    for hostname in hostnames:
        store.load_existing(hostname)
        obs = await source.query_hostname(hostname)
        result[hostname] = store.add(hostname, {o.ip for o in obs if o.ip})
    return result
