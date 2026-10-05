"""Discovery engine — orchestrates sources, enrichment, validation, persistence."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

import httpx

from .config import Config
from .dns import LiveDnsSource, LegacyToolDnsSource
from .enrich.cdn import classify_from_evidence
from .enrich.ip_enrich import Enricher
from .failures import FailureSink
from .models import (
    ObservationStatus,
    SourceEvidence,
    utc_now_iso,
)
from .rate_limit import RateLimiter
from .sources.ct_crtsh import CrtShSource
from .sources.passive_dns import PassiveDnsAggregator
from .store import EvidenceStore
from .validate.active import ActiveValidator


class DiscoveryEngine:
    def __init__(
        self,
        config: Config,
        store: EvidenceStore,
        on_new_ip: Callable[[str, str, Any], None] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.on_new_ip = on_new_ip
        self.failures = FailureSink(on_failure=lambda f: store.save_failure(f.to_dict()))
        self.rate = RateLimiter(
            global_rps=config.rate.global_rps,
            per_resolver_rps=config.rate.per_resolver_rps,
            per_hostname_rps=config.rate.per_hostname_rps,
            per_source_rps=config.rate.per_source_rps,
        )
        self._client: httpx.AsyncClient | None = None
        self.stop_event = asyncio.Event()
        self.stats: dict[str, Any] = {
            "dns_queries": 0,
            "new_ips": 0,
            "failures": 0,
        }

    async def __aenter__(self) -> "DiscoveryEngine":
        self._client = httpx.AsyncClient(
            headers={"User-Agent": self.config.user_agent},
            follow_redirects=True,
            timeout=self.config.http_timeout,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        assert self._client is not None, "engine must be used as async context manager"
        return self._client

    def _live_dns(self) -> LiveDnsSource:
        return LiveDnsSource(
            resolvers=self.config.resolvers,
            rate_limiter=self.rate,
            failures=self.failures,
            timeout=self.config.dns_timeout,
            semaphore=asyncio.Semaphore(self.config.concurrency.max_dns),
            excluded_ips=self.config.excluded_ips,
        )

    def _legacy_dns(self) -> LegacyToolDnsSource | None:
        if not self.config.use_legacy_tools:
            return None
        return LegacyToolDnsSource(
            resolvers=self.config.resolvers,
            tools=self.config.legacy_tools or ["nslookup"],
            rate_limiter=self.rate,
            failures=self.failures,
            timeout=self.config.dns_timeout,
            semaphore=asyncio.Semaphore(min(8, self.config.concurrency.max_dns)),
            excluded_ips=self.config.excluded_ips,
        )

    async def discover_once(self, hostname: str) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "hostname": hostname,
            "timestamp": utc_now_iso(),
            "sources_run": [],
            "passive_dns": None,
            "ct": None,
            "new_ips": [],
        }
        if "dns" in self.config.sources:
            summary["sources_run"].append("dns")
            await self._run_live_dns(hostname, summary)

        related_hosts: list[str] = []
        if "ct" in self.config.sources:
            summary["sources_run"].append("ct")
            ct = CrtShSource(
                self.client,
                self.rate,
                self.failures,
                self.config.user_agent,
                rps=self.config.rate.ct_rps,
            )
            ct_result = await ct.discover_hostnames(hostname)
            summary["ct"] = {
                "status": ct_result.get("status"),
                "provider": ct_result.get("provider"),
                "hostname_count": len(ct_result.get("hostnames") or []),
                "wildcard_count": len(ct_result.get("wildcard_names") or []),
                "raw_count": ct_result.get("raw_count"),
                "queries": ct_result.get("queries"),
                "note": ct_result.get("note"),
            }
            related_hosts = list(ct_result.get("hostnames") or [])

        if "passive" in self.config.sources or "passive_dns" in self.config.sources:
            summary["sources_run"].append("passive")
            agg = PassiveDnsAggregator(
                self.client,
                self.rate,
                self.failures,
                self.config.user_agent,
                securitytrails_key=self.config.securitytrails_api_key,
                rps=self.config.rate.passive_rps,
            )
            passive = await agg.lookup(hostname)
            summary["passive_dns"] = passive.to_dict()
            for rec in passive.records:
                ip = rec.get("ip")
                host = rec.get("hostname") or hostname
                if not ip or ip in self.config.excluded_ips:
                    continue
                target = hostname if host == hostname or host.endswith("." + hostname.split(".", 1)[-1]) else hostname
                status = (
                    ObservationStatus.HISTORICALLY_OBSERVED.value
                    if host == hostname
                    else ObservationStatus.CANDIDATE.value
                )
                new = self._ingest_ip(
                    target,
                    ip,
                    status=status,
                    source=SourceEvidence(
                        type="passive_dns",
                        timestamp=rec.get("timestamp") or utc_now_iso(),
                        detail={
                            "provider": rec.get("provider"),
                            "endpoint": rec.get("endpoint"),
                            "passive_hostname": host,
                            "first_seen": rec.get("first_seen"),
                            "last_seen": rec.get("last_seen"),
                            "note": rec.get("note"),
                        },
                    ),
                    related_hostname=host if host != hostname else None,
                )
                if new:
                    summary["new_ips"].append(ip)

        if related_hosts and "dns" in self.config.sources:
            parent = ".".join(hostname.split(".")[-2:])
            prioritized = [hostname] + [
                h for h in related_hosts if h != hostname and (h == parent or h.endswith("." + parent))
            ]
            seen: set[str] = set()
            ordered: list[str] = []
            for h in prioritized:
                if h not in seen:
                    seen.add(h)
                    ordered.append(h)
            live = self._live_dns()
            for rel in ordered[: self.config.max_related_resolve]:
                if self.stop_event.is_set():
                    break
                if rel == hostname:
                    continue
                obs_list = await live.query_hostname(rel)
                self.stats["dns_queries"] += len(self.config.resolvers)
                for obs in obs_list:
                    self.store.save_observation(obs.to_dict())
                    if obs.ip and obs.record_type in ("A", "AAAA"):
                        self._ingest_ip(
                            rel,
                            obs.ip,
                            status=ObservationStatus.CURRENTLY_OBSERVED.value,
                            source=SourceEvidence(
                                type="live_dns",
                                timestamp=obs.timestamp,
                                resolver=obs.resolver,
                                tool=obs.tool,
                                detail={"via": "ct_related_hostname", "cname_chain": obs.cname_chain},
                            ),
                            dns_update={"record_type": obs.record_type, "cname_chain": obs.cname_chain},
                        )
                        self._ingest_ip(
                            hostname,
                            obs.ip,
                            status=ObservationStatus.CANDIDATE.value,
                            source=SourceEvidence(
                                type="related_hostname",
                                timestamp=obs.timestamp,
                                resolver=obs.resolver,
                                tool=obs.tool,
                                detail={
                                    "related_hostname": rel,
                                    "derived_from": "certificate_transparency+live_dns",
                                    "cname_chain": obs.cname_chain,
                                },
                            ),
                            related_hostname=rel,
                            dns_update={"cname_chain": obs.cname_chain},
                        )

        if self.config.do_enrich:
            await self._enrich_hostname(hostname)
        if self.config.do_validate:
            await self._validate_hostname(hostname)

        summary["failure_count"] = len(self.failures.records)
        summary["ip_count"] = len(self.store.known_ips(hostname))
        return summary

    async def hunt_round(self, hostnames: list[str]) -> list[str]:
        live = self._live_dns()
        legacy = self._legacy_dns()
        new_ips: list[str] = []

        async def one(host: str) -> None:
            if self.stop_event.is_set():
                return
            obs_list = await live.query_hostname(host)
            self.stats["dns_queries"] += len(self.config.resolvers)
            if legacy:
                obs_list.extend(await legacy.query_hostname(host))
            for obs in obs_list:
                self.store.save_observation(obs.to_dict())
                if obs.ip and obs.record_type in ("A", "AAAA"):
                    is_new = self._ingest_ip(
                        host,
                        obs.ip,
                        status=ObservationStatus.CURRENTLY_OBSERVED.value,
                        source=SourceEvidence(
                            type="live_dns",
                            timestamp=obs.timestamp,
                            resolver=obs.resolver,
                            tool=obs.tool,
                            detail={"cname_chain": obs.cname_chain},
                        ),
                        dns_update={"record_type": obs.record_type, "cname_chain": obs.cname_chain},
                    )
                    if is_new:
                        new_ips.append(obs.ip)

        await asyncio.gather(*[one(h) for h in hostnames], return_exceptions=True)
        return new_ips

    async def _run_live_dns(self, hostname: str, summary: dict[str, Any]) -> None:
        live = self._live_dns()
        obs_list = await live.query_hostname(hostname)
        self.stats["dns_queries"] += len(self.config.resolvers)
        legacy = self._legacy_dns()
        if legacy:
            obs_list.extend(await legacy.query_hostname(hostname))

        resolver_answers: dict[str, list[str]] = {}
        for obs in obs_list:
            self.store.save_observation(obs.to_dict())
            if obs.ip and obs.record_type in ("A", "AAAA"):
                resolver_answers.setdefault(obs.resolver or "unknown", []).append(obs.ip)
                is_new = self._ingest_ip(
                    hostname,
                    obs.ip,
                    status=ObservationStatus.CURRENTLY_OBSERVED.value,
                    source=SourceEvidence(
                        type="live_dns",
                        timestamp=obs.timestamp,
                        resolver=obs.resolver,
                        tool=obs.tool,
                        detail={"cname_chain": obs.cname_chain, "record_type": obs.record_type},
                    ),
                    dns_update={"record_type": obs.record_type, "cname_chain": obs.cname_chain},
                )
                if is_new:
                    summary["new_ips"].append(obs.ip)
        summary["resolver_answers"] = {k: sorted(set(v)) for k, v in resolver_answers.items()}

    def _ingest_ip(
        self,
        hostname: str,
        ip: str,
        *,
        status: str,
        source: SourceEvidence,
        dns_update: dict[str, Any] | None = None,
        related_hostname: str | None = None,
    ) -> bool:
        if ip in self.config.excluded_ips:
            return False
        rec, is_new = self.store.upsert_ip(
            hostname,
            ip,
            status=status,
            source=source,
            dns_update=dns_update,
            related_hostname=related_hostname,
        )
        if (
            not self.config.do_validate
            and ObservationStatus.VALIDATED.value not in rec.statuses
            and ObservationStatus.UNVERIFIED.value not in rec.statuses
        ):
            self.store.upsert_ip(hostname, ip, status=ObservationStatus.UNVERIFIED.value)
        if is_new:
            self.stats["new_ips"] += 1
            if self.on_new_ip:
                self.on_new_ip(hostname, ip, rec)
        return is_new

    async def _enrich_hostname(self, hostname: str) -> None:
        enricher = Enricher(
            self.client,
            self.rate,
            self.failures,
            self.config.user_agent,
            self.config.resolvers,
            rps=self.config.rate.enrich_rps,
            semaphore=asyncio.Semaphore(self.config.concurrency.max_enrich),
        )
        seen_ip: set[str] = set()
        for rec in self.store.all_records(hostname):
            if rec.ip in seen_ip:
                continue
            seen_ip.add(rec.ip)
            if self.stop_event.is_set():
                break
            network = await enricher.enrich(rec.ip)
            self.store.save_enrichment(rec.ip, network)
            cname = (rec.dns or {}).get("cname_chain") or []
            self.store.save_classification(rec.ip, classify_from_evidence(network=network, cname_chain=cname))

    async def _validate_hostname(self, hostname: str) -> None:
        validator = ActiveValidator(
            self.rate,
            self.failures,
            tcp_timeout=self.config.tcp_timeout,
            tls_timeout=self.config.tls_timeout,
            do_http=self.config.do_http_validate,
            semaphore=asyncio.Semaphore(self.config.concurrency.max_validate),
            rps=self.config.rate.validate_rps,
        )
        records = self.store.all_records(hostname)

        def sort_key(r: Any) -> int:
            if ObservationStatus.CURRENTLY_OBSERVED.value in r.statuses:
                return 0
            if ObservationStatus.HISTORICALLY_OBSERVED.value in r.statuses:
                return 1
            return 2

        for rec in sorted(records, key=sort_key):
            if self.stop_event.is_set():
                break
            result = await validator.validate(hostname, rec.ip)
            self.store.save_validation(hostname, rec.ip, result)


def default_store_for(output_dir: Path, label: str = "discovery") -> EvidenceStore:
    output_dir.mkdir(parents=True, exist_ok=True)
    return EvidenceStore(sqlite_path=output_dir / f"{label}.sqlite3", txt_dir=output_dir)
