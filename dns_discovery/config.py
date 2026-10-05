"""Configuration — resolvers, rate limits, sources. Secrets only from env / .env."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


DEFAULT_RESOLVERS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "208.67.222.222",
]

# Optional environment-specific DNS poison/captive answers. Keep empty in the public build; provide values with --excluded-ips when needed.
DEFAULT_EXCLUDED_IPS = frozenset()


@dataclass
class RateLimitConfig:
    global_rps: float = 20.0
    per_resolver_rps: float = 5.0
    per_hostname_rps: float = 8.0
    per_source_rps: float = 2.0
    ct_rps: float = 0.5
    passive_rps: float = 0.4
    enrich_rps: float = 2.0
    validate_rps: float = 4.0


@dataclass
class ConcurrencyConfig:
    max_dns: int = 16
    max_http: int = 8
    max_validate: int = 8
    max_enrich: int = 6


@dataclass
class Config:
    resolvers: list[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    excluded_ips: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_IPS))
    sources: list[str] = field(default_factory=lambda: ["dns", "ct", "passive"])
    dns_timeout: float = 6.0
    http_timeout: float = 15.0
    tls_timeout: float = 8.0
    tcp_timeout: float = 5.0
    hunt_interval: float = 0.5
    rate: RateLimitConfig = field(default_factory=RateLimitConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    output_dir: Path = field(default_factory=lambda: Path("output"))
    sqlite_path: Path | None = None
    use_legacy_tools: bool = False
    legacy_tools: list[str] = field(default_factory=list)
    do_enrich: bool = False
    do_validate: bool = False
    do_http_validate: bool = False
    max_related_resolve: int = 40
    user_agent: str = "dns-discovery-engine/2.0 (+evidence-backed; research)"
    securitytrails_api_key: str | None = field(
        default_factory=lambda: os.environ.get("SECURITYTRAILS_API_KEY") or None
    )
    virustotal_api_key: str | None = field(
        default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY") or None
    )

    @classmethod
    def from_cli(
        cls,
        resolvers: str | None = None,
        sources: str | None = None,
        excluded_ips: str | None = None,
        **kwargs,
    ) -> "Config":
        cfg = cls(**{k: v for k, v in kwargs.items() if v is not None and k in cls.__dataclass_fields__})
        if resolvers:
            cfg.resolvers = [r.strip() for r in resolvers.split(",") if r.strip()]
        if sources:
            cfg.sources = [s.strip().lower() for s in sources.split(",") if s.strip()]
        if excluded_ips is not None:
            cfg.excluded_ips = {x.strip() for x in excluded_ips.split(",") if x.strip()}
        return cfg


def parse_resolvers(raw: str | None) -> list[str]:
    if not raw:
        return list(DEFAULT_RESOLVERS)
    return [r.strip() for r in raw.split(",") if r.strip()]
