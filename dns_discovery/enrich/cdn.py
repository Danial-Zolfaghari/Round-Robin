"""
Evidence-based CDN / provider classification.

Never assigns a provider without concrete evidence from enrichment / DNS.
If evidence is insufficient → provider=None (reported as UNKNOWN), confidence=low/None.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..models import Classification, NetworkInfo


_EVIDENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Akamai", re.compile(r"akamai|edgekey\.net|akamaiedge\.net|akamaitechnologies", re.I)),
    ("Cloudflare", re.compile(r"cloudflare|\.cdn\.cloudflare\.net", re.I)),
    ("Fastly", re.compile(r"fastly", re.I)),
    ("Amazon CloudFront", re.compile(r"cloudfront\.net|amazon.?cloudfront|cloudfront", re.I)),
    ("Google", re.compile(r"google(?:usercontent)?|1e100\.net|googlehosted", re.I)),
    ("Microsoft Azure", re.compile(r"azure|azureedge\.net|microsoft", re.I)),
]


def classify_from_evidence(
    *,
    network: NetworkInfo | None,
    cname_chain: Iterable[str] | None = None,
    extra_texts: Iterable[str] | None = None,
) -> Classification:
    evidence: list[str] = []
    hits: dict[str, int] = {}

    texts: list[tuple[str, str]] = []
    if network:
        if network.organization:
            texts.append(("organization", network.organization))
        if network.isp:
            texts.append(("isp", network.isp))
        if network.asn:
            texts.append(("asn", network.asn))
        if network.reverse_dns:
            texts.append(("reverse_dns", network.reverse_dns))
        if network.prefix:
            texts.append(("prefix", network.prefix))
    for c in cname_chain or []:
        texts.append(("cname", c))
    for t in extra_texts or []:
        texts.append(("extra", t))

    for label, value in texts:
        for provider, pat in _EVIDENCE_PATTERNS:
            if pat.search(value):
                hits[provider] = hits.get(provider, 0) + 1
                evidence.append(f"{label} matched /{pat.pattern}/ → {provider}: {value}")

    if not hits:
        return Classification(
            provider=None,
            cdn=None,
            confidence=None,
            evidence=["No CDN/provider evidence found in available fields; provider=UNKNOWN"],
        )

    provider = sorted(hits.items(), key=lambda x: (-x[1], x[0]))[0][0]
    score = hits[provider]
    if score >= 3:
        confidence = "high"
    elif score == 2:
        confidence = "medium"
    else:
        confidence = "low"

    return Classification(
        provider=provider,
        cdn=provider,
        confidence=confidence,
        evidence=evidence,
    )
