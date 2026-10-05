"""Fast unique IPv4 hunter — live DNS + optional web history (validated) → txt only."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Callable

import httpx

from .config import DEFAULT_RESOLVERS, DEFAULT_EXCLUDED_IPS
from .dns import LiveDnsSource, LegacyToolDnsSource
from .failures import FailureSink
from .ip_store import IpTxtStore, is_ipv4
from .rate_limit import RateLimiter
from .sources.web_ips import WebIpSource
from .validate.active import ActiveValidator

# on_new_batch(domain, new_ips, tool, resolver, domain_count, all_count)
NewBatchCb = Callable[[str, list[str], str, str, int, int], None]
# optional status line for rejected web candidates
StatusCb = Callable[[str], None]


class IpHunter:
    """Continuous DNS + optional web passive IPs (TLS-validated) → unique IPv4 txt."""

    def __init__(
        self,
        domains: list[str],
        output_dir: str | Path,
        resolvers: list[str] | None = None,
        excluded_ips: set[str] | None = None,
        interval: float = 0.12,
        max_concurrent: int = 24,
        max_nslookup: int = 12,
        dns_timeout: float = 5.0,
        use_dnspython: bool = True,
        use_nslookup: bool = True,
        use_web: bool = False,
        web_interval: float = 120.0,
        on_new_batch: NewBatchCb | None = None,
        on_status: StatusCb | None = None,
    ) -> None:
        self.domains = domains
        self.resolvers = resolvers or list(DEFAULT_RESOLVERS)
        self.excluded_ips = excluded_ips if excluded_ips is not None else set(DEFAULT_EXCLUDED_IPS)
        self.interval = interval
        self.dns_timeout = dns_timeout
        self.use_dnspython = use_dnspython
        self.use_nslookup = use_nslookup and bool(shutil.which("nslookup"))
        self.use_web = use_web
        self.web_interval = max(30.0, web_interval)
        self.on_new_batch = on_new_batch
        self.on_status = on_status
        self.stop_event = asyncio.Event()
        self.store = IpTxtStore(output_dir, excluded_ips=self.excluded_ips)
        self.failures = FailureSink()
        self.rate = RateLimiter(
            global_rps=50.0,
            per_resolver_rps=14.0,
            per_hostname_rps=24.0,
            per_source_rps=50.0,
        )
        self.sem_dns = asyncio.Semaphore(max_concurrent)
        self.sem_ns = asyncio.Semaphore(max_nslookup)
        self.dns_queries = 0
        self._web_tried: set[tuple[str, str]] = set()  # (hostname, ip) already validated or failed
        self._client: httpx.AsyncClient | None = None
        self._dns = LiveDnsSource(
            resolvers=self.resolvers,
            rate_limiter=self.rate,
            failures=self.failures,
            timeout=self.dns_timeout,
            semaphore=self.sem_dns,
            excluded_ips=self.excluded_ips,
            ipv4_only=True,
        )
        self._ns: LegacyToolDnsSource | None = None
        if self.use_nslookup:
            self._ns = LegacyToolDnsSource(
                resolvers=self.resolvers,
                tools=["nslookup"],
                rate_limiter=self.rate,
                failures=self.failures,
                timeout=self.dns_timeout,
                semaphore=self.sem_ns,
                excluded_ips=self.excluded_ips,
            )
        self._validator = ActiveValidator(
            self.rate,
            self.failures,
            tcp_timeout=4.0,
            tls_timeout=6.0,
            do_http=False,
            semaphore=asyncio.Semaphore(8),
            rps=4.0,
        )

    @property
    def engines_label(self) -> str:
        parts = []
        if self.use_dnspython:
            parts.append("dns")
        if self.use_nslookup:
            parts.append("nslookup")
        if self.use_web:
            parts.append("web+tls")
        return "+".join(parts) if parts else "none"

    def prepare(self, append: bool = True) -> int:
        total = 0
        for d in self.domains:
            if append:
                total += self.store.load_existing(d)
            else:
                self.store.clear(d)
        return total

    def _emit(self, domain: str, new_ips: list[str], tool: str, resolver: str) -> None:
        if not new_ips:
            return
        if self.on_new_batch:
            self.on_new_batch(
                domain,
                new_ips,
                tool,
                resolver,
                self.store.count(domain),
                self.store.count(),
            )

    def _status(self, msg: str) -> None:
        if self.on_status:
            self.on_status(msg)

    async def _query_dns_one(self, domain: str, resolver: str) -> None:
        if self.stop_event.is_set() or not self.use_dnspython:
            return
        obs = await self._dns.resolve_one(domain, resolver)
        self.dns_queries += 1
        ips = [o.ip for o in obs if o.ip and o.record_type == "A" and is_ipv4(o.ip)]
        new_ips = self.store.add(domain, ips)
        self._emit(domain, new_ips, "dns", resolver)

    async def _query_ns_one(self, domain: str, resolver: str) -> None:
        if self.stop_event.is_set() or not self._ns:
            return
        obs = await self._ns.run_one(domain, "nslookup", resolver)
        self.dns_queries += 1
        ips = [o.ip for o in obs if o.ip and o.record_type == "A" and is_ipv4(o.ip)]
        new_ips = self.store.add(domain, ips)
        self._emit(domain, new_ips, "nslookup", resolver)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def web_pass_once(self) -> None:
        """
        Fetch historically indexed IPs from the public web for each exact hostname,
        then only keep those that still answer TLS with SNI=hostname.
        """
        if not self.use_web or self.stop_event.is_set():
            return
        client = await self._ensure_client()
        web = WebIpSource(client, self.rate, self.failures)

        for domain in self.domains:
            if self.stop_event.is_set():
                return
            self._status(f"[*] web: fetching historical IPs for {domain} ...")
            candidates = await web.candidates_for(domain)
            # only unknown IPs
            todo = [
                c
                for c in candidates
                if c["ip"] not in self.excluded_ips
                and c["ip"] not in self.store.known(domain)
                and (domain, c["ip"]) not in self._web_tried
            ]
            self._status(f"[*] web: {domain} candidates={len(candidates)} new_to_check={len(todo)}")
            if not todo:
                continue

            async def check_one(row: dict) -> None:
                ip = row["ip"]
                key = (domain, ip)
                if key in self._web_tried or self.stop_event.is_set():
                    return
                self._web_tried.add(key)
                result = await self._validator.validate(domain, ip)
                ok = bool(result.tls_hostname_match)
                provider = row.get("provider") or "web"
                if ok:
                    new_ips = self.store.add(domain, [ip])
                    self._emit(domain, new_ips, f"web:{provider}", "tls-ok")
                else:
                    # do not save — stale / wrong CDN edge / unreachable
                    self._status(
                        f"[-] web reject {domain} {ip} "
                        f"(tcp443={result.tcp_443} tls={result.tls} name_match={result.tls_hostname_match})"
                    )

            await asyncio.gather(*[check_one(r) for r in todo], return_exceptions=True)

    async def round_once(self) -> None:
        if self.stop_event.is_set():
            return
        tasks: list[asyncio.Task] = []
        for domain in self.domains:
            for resolver in self.resolvers:
                if self.use_dnspython:
                    tasks.append(asyncio.create_task(self._query_dns_one(domain, resolver)))
                if self.use_nslookup:
                    tasks.append(asyncio.create_task(self._query_ns_one(domain, resolver)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def hunt(self) -> None:
        web_task = None
        if self.use_web:
            web_task = asyncio.create_task(self._web_loop())

        try:
            while not self.stop_event.is_set():
                await self.round_once()
                try:
                    await asyncio.sleep(self.interval)
                except asyncio.CancelledError:
                    break
        finally:
            self.stop_event.set()
            if web_task is not None:
                web_task.cancel()
                try:
                    await web_task
                except Exception:
                    pass
            await self.close()

    async def _web_loop(self) -> None:
        # first pass immediately, then periodically
        while not self.stop_event.is_set():
            try:
                await self.web_pass_once()
            except Exception as e:
                self.failures.record("web", "web_loop", e)
            try:
                await asyncio.sleep(self.web_interval)
            except asyncio.CancelledError:
                break
