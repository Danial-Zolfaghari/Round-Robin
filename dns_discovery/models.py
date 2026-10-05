"""Shared data models. No fabricated defaults — missing fields stay None/empty."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ObservationStatus(str, Enum):
    CURRENTLY_OBSERVED = "CURRENTLY_OBSERVED"
    HISTORICALLY_OBSERVED = "HISTORICALLY_OBSERVED"
    CANDIDATE = "CANDIDATE"
    VALIDATED = "VALIDATED"
    UNVERIFIED = "UNVERIFIED"


class SourceType(str, Enum):
    LIVE_DNS = "live_dns"
    CT = "certificate_transparency"
    PASSIVE_DNS = "passive_dns"
    RELATED_HOSTNAME = "related_hostname"
    ENRICHMENT = "enrichment"
    VALIDATION = "validation"


@dataclass
class FailureRecord:
    source: str
    operation: str
    hostname: str | None
    timestamp: str
    error_type: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DnsObservation:
    hostname: str
    record_type: str
    value: str
    resolver: str | None
    timestamp: str
    source: str = SourceType.LIVE_DNS.value
    cname_chain: list[str] = field(default_factory=list)
    tool: str | None = None
    ip: str | None = None  # set when value is an address

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class SourceEvidence:
    type: str
    timestamp: str
    resolver: str | None = None
    tool: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkInfo:
    asn: str | None = None
    prefix: str | None = None
    organization: str | None = None
    isp: str | None = None
    country: str | None = None
    reverse_dns: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    tcp_443: bool | None = None
    tls: bool | None = None
    tls_hostname_match: bool | None = None
    http: bool | None = None
    http_host_match: bool | None = None
    tcp_80: bool | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Classification:
    provider: str | None = None
    cdn: str | None = None
    confidence: str | None = None  # high | medium | low | None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IpRecord:
    hostname: str
    ip: str
    first_seen: str
    last_seen: str
    statuses: list[str] = field(default_factory=list)
    sources: list[SourceEvidence] = field(default_factory=list)
    dns: dict[str, Any] = field(default_factory=dict)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    validation: ValidationResult = field(default_factory=ValidationResult)
    classification: Classification = field(default_factory=Classification)
    related_hostnames: list[str] = field(default_factory=list)

    def add_status(self, status: str) -> None:
        if status not in self.statuses:
            self.statuses.append(status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "statuses": list(self.statuses),
            "sources": [s.to_dict() for s in self.sources],
            "dns": dict(self.dns),
            "network": self.network.to_dict(),
            "validation": self.validation.to_dict(),
            "classification": self.classification.to_dict(),
            "related_hostnames": list(self.related_hostnames),
        }
