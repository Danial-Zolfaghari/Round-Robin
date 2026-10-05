"""Live DNS via dnspython (primary) and optional legacy CLI tools."""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from ..failures import FailureSink
from ..models import DnsObservation, utc_now_iso
from ..rate_limit import RateLimiter
from .parsers import parse_tool_output


def is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


class LiveDnsSource:
    def __init__(
        self,
        resolvers: list[str],
        rate_limiter: RateLimiter,
        failures: FailureSink,
        timeout: float = 6.0,
        semaphore: asyncio.Semaphore | None = None,
        excluded_ips: set[str] | None = None,
        ipv4_only: bool = True,
    ) -> None:
        self.resolvers = resolvers
        self.rate = rate_limiter
        self.failures = failures
        self.timeout = timeout
        self.sem = semaphore or asyncio.Semaphore(16)
        self.excluded_ips = excluded_ips or set()
        self.ipv4_only = ipv4_only

    async def query_hostname(self, hostname: str) -> list[DnsObservation]:
        tasks = [self.resolve_one(hostname, r) for r in self.resolvers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        observations: list[DnsObservation] = []
        for item in results:
            if isinstance(item, Exception):
                self.failures.record("live_dns", "gather", item, hostname=hostname)
                continue
            observations.extend(item)
        return observations

    async def resolve_one(self, hostname: str, resolver_ip: str) -> list[DnsObservation]:
        return await self._resolve_with_resolver(hostname, resolver_ip)

    async def _resolve_with_resolver(self, hostname: str, resolver_ip: str) -> list[DnsObservation]:
        async with self.sem:
            await self.rate.acquire(resolver=resolver_ip, hostname=hostname, source="live_dns")
            observations: list[DnsObservation] = []
            ts = utc_now_iso()
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.lifetime = self.timeout
            resolver.timeout = min(self.timeout, 4.0)

            cname_chain: list[str] = []
            try:
                # Resolve A and capture CNAME chain from response
                try:
                    answer = await resolver.resolve(hostname, "A")
                    chain = _extract_cname_chain(answer)
                    cname_chain = chain
                    for rr in answer:
                        ip = rr.to_text()
                        if ip in self.excluded_ips or not is_ipv4(ip):
                            continue
                        observations.append(
                            DnsObservation(
                                hostname=hostname,
                                record_type="A",
                                value=ip,
                                ip=ip,
                                resolver=resolver_ip,
                                timestamp=ts,
                                source="live_dns",
                                cname_chain=list(cname_chain),
                                tool="dnspython",
                            )
                        )
                    if cname_chain:
                        observations.append(
                            DnsObservation(
                                hostname=hostname,
                                record_type="CNAME",
                                value=cname_chain[-1] if cname_chain else "",
                                resolver=resolver_ip,
                                timestamp=ts,
                                source="live_dns",
                                cname_chain=list(cname_chain),
                                tool="dnspython",
                            )
                        )
                except dns.resolver.NXDOMAIN as e:
                    self.failures.record("live_dns", "A", e, hostname=hostname, error_type="NXDOMAIN")
                except dns.resolver.NoAnswer:
                    pass
                except dns.exception.Timeout as e:
                    self.failures.record("live_dns", "A", e, hostname=hostname, error_type="Timeout")
                except Exception as e:
                    self.failures.record("live_dns", "A", e, hostname=hostname)

                if not self.ipv4_only:
                    try:
                        answer6 = await resolver.resolve(hostname, "AAAA")
                        for rr in answer6:
                            ip = rr.to_text()
                            observations.append(
                                DnsObservation(
                                    hostname=hostname,
                                    record_type="AAAA",
                                    value=ip,
                                    ip=ip,
                                    resolver=resolver_ip,
                                    timestamp=ts,
                                    source="live_dns",
                                    cname_chain=list(cname_chain),
                                    tool="dnspython",
                                )
                            )
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                        pass
                    except dns.exception.Timeout as e:
                        self.failures.record("live_dns", "AAAA", e, hostname=hostname, error_type="Timeout")
                    except Exception as e:
                        self.failures.record("live_dns", "AAAA", e, hostname=hostname)

            except Exception as e:
                self.failures.record("live_dns", "resolve", e, hostname=hostname)

            return observations


def _extract_cname_chain(answer: Any) -> list[str]:
    chain: list[str] = []
    try:
        response = answer.response
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for rr in rrset:
                    chain.append(str(rr.target).rstrip(".").lower())
    except Exception:
        pass
    try:
        cn = str(answer.canonical_name).rstrip(".").lower()
        qn = str(answer.qname).rstrip(".").lower()
        if cn and cn != qn and cn not in chain:
            chain.append(cn)
    except Exception:
        pass
    return chain


# Import dns.resolver for exception types used above
import dns.resolver  # noqa: E402


class LegacyToolDnsSource:
    """Optional subprocess-based tools with protocol-aware parsers and bounded concurrency."""

    TOOLS = ("dig", "host", "nslookup", "drill")

    def __init__(
        self,
        resolvers: list[str],
        tools: list[str],
        rate_limiter: RateLimiter,
        failures: FailureSink,
        timeout: float = 6.0,
        semaphore: asyncio.Semaphore | None = None,
        excluded_ips: set[str] | None = None,
    ) -> None:
        self.resolvers = resolvers
        self.tools = [t for t in tools if t in self.TOOLS and shutil.which(t)]
        self.rate = rate_limiter
        self.failures = failures
        self.timeout = timeout
        self.sem = semaphore or asyncio.Semaphore(8)
        self.excluded_ips = excluded_ips or set()
        for t in tools:
            if t not in self.tools:
                self.failures.record("legacy_dns", "tool_missing", f"tool not found: {t}", error_type="ToolMissing")

    async def query_hostname(self, hostname: str) -> list[DnsObservation]:
        if not self.tools:
            return []
        tasks = [
            self.run_one(hostname, tool, resolver)
            for tool in self.tools
            for resolver in self.resolvers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[DnsObservation] = []
        for item in results:
            if isinstance(item, Exception):
                self.failures.record("legacy_dns", "gather", item, hostname=hostname)
            elif item:
                out.extend(item)
        return out

    async def run_one(self, hostname: str, tool: str, resolver: str) -> list[DnsObservation]:
        return await self._run(hostname, tool, resolver)

    async def _run(self, hostname: str, tool: str, resolver: str) -> list[DnsObservation]:
        async with self.sem:
            await self.rate.acquire(resolver=resolver, hostname=hostname, source="legacy_dns")
            if tool == "dig":
                cmd = ["dig", f"@{resolver}", "+short", "A", hostname]
                short = True
            elif tool == "host":
                cmd = ["host", hostname, resolver]
                short = False
            elif tool == "nslookup":
                cmd = ["nslookup", hostname, resolver]
                short = False
            elif tool == "drill":
                cmd = ["drill", f"@{resolver}", "A", hostname]
                short = False
            else:
                return []

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as e:
                self.failures.record("legacy_dns", tool, e, hostname=hostname, error_type="ToolMissing")
                return []

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError as e:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                self.failures.record("legacy_dns", tool, e, hostname=hostname, error_type="Timeout")
                return []

            output = stdout.decode(errors="ignore")
            if proc.returncode not in (0, None) and not output.strip():
                err = stderr.decode(errors="ignore")[:500]
                self.failures.record(
                    "legacy_dns",
                    tool,
                    err or f"exit {proc.returncode}",
                    hostname=hostname,
                    error_type="ResolverFailure",
                )
                return []

            parsed = parse_tool_output(tool, output, query_name=hostname, short=short)
            ts = utc_now_iso()
            observations: list[DnsObservation] = []
            for ip in parsed.ipv4:
                if ip == resolver or ip in self.excluded_ips:
                    continue
                observations.append(
                    DnsObservation(
                        hostname=hostname,
                        record_type="A",
                        value=ip,
                        ip=ip,
                        resolver=resolver,
                        timestamp=ts,
                        source="live_dns",
                        cname_chain=list(parsed.cnames),
                        tool=tool,
                    )
                )
            for cname in parsed.cnames:
                observations.append(
                    DnsObservation(
                        hostname=hostname,
                        record_type="CNAME",
                        value=cname,
                        resolver=resolver,
                        timestamp=ts,
                        source="live_dns",
                        cname_chain=list(parsed.cnames),
                        tool=tool,
                    )
                )
            return observations
