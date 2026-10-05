from __future__ import annotations

from ..models import Classification, NetworkInfo

KNOWN = {
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai", "akamai technologies", "akamai international"],
    "fastly": ["fastly"],
    "cloudfront": ["amazon", "aws", "cloudfront"],
    "google": ["google"],
    "azure": ["microsoft", "azure"],
}


def classify(network: NetworkInfo) -> Classification:
    text = " ".join(x for x in [network.organization, network.isp, network.reverse_dns] if x).lower()
    for provider, needles in KNOWN.items():
        if any(n in text for n in needles):
            return Classification(provider=provider, cdn=provider, confidence="medium", evidence=[f"network metadata matched {provider}"])
    return Classification()
