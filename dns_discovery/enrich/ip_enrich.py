"""IP enrichment from real sources: ip-api.com, RDAP, reverse DNS, Team Cymru."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

from ..failures import FailureSink
from ..models import NetworkInfo
from ..rate_limit import RateLimiter


class Enricher:
    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        user_agent: str,
        dns_resolvers: list[str],
        rps: float = 2.0,
        semaphore: asyncio.Semaphore | None = None,
    ) -> None:
        self.client = client
        self.rate = rate_limiter
        self.failures = failures
        self.user_agent = user_agent
        self.dns_resolvers = dns_resolvers
        self.rate.named("enrich", rps)
        self.sem = semaphore or asyncio.Semaphore(6)

    async def enrich(self, ip: str) -> NetworkInfo:
        async with self.sem:
            await self.rate.acquire(named="enrich", source="enrichment")
            ip_api_data = await self._ip_api(ip)
            rdap_data = await self._rdap(ip)
            rdns = await self._reverse_dns(ip)
            cymru = await self._cymru(ip)

            asn = None
            prefix = None
            organization = None
            isp = None
            country = None
            sources: list[str] = []

            if ip_api_data:
                sources.append("ip-api.com")
                as_field = ip_api_data.get("as") or ""
                if as_field.startswith("AS"):
                    asn = as_field.split(" ", 1)[0]
                    if " " in as_field and not organization:
                        organization = as_field.split(" ", 1)[1] or None
                if ip_api_data.get("org"):
                    organization = ip_api_data.get("org")
                isp = ip_api_data.get("isp")
                country = ip_api_data.get("countryCode") or ip_api_data.get("country")
                if not rdns and ip_api_data.get("reverse"):
                    rdns = ip_api_data.get("reverse")
                    sources.append("ip-api.com/reverse")

            if rdap_data:
                sources.append(rdap_data.get("rdap_server") or "rdap")
                if not prefix and rdap_data.get("prefix"):
                    prefix = rdap_data["prefix"]
                if not organization and rdap_data.get("name"):
                    organization = organization or rdap_data.get("org") or rdap_data.get("name")
                if not asn and rdap_data.get("asn"):
                    asn = rdap_data["asn"]

            if cymru:
                sources.append("team_cymru_dns")
                asn = asn or cymru.get("asn")
                prefix = prefix or cymru.get("prefix")
                if not organization and cymru.get("as_org"):
                    organization = cymru["as_org"]

            if rdns and "reverse_dns" not in " ".join(sources):
                sources.append("ptr")

            return NetworkInfo(
                asn=asn,
                prefix=prefix,
                organization=organization,
                isp=isp,
                country=country,
                reverse_dns=rdns,
                source="+".join(sources) if sources else None,
            )

    async def _ip_api(self, ip: str) -> dict[str, Any] | None:
        url = f"http://ip-api.com/json/{ip}"
        params = {"fields": "status,message,country,countryCode,as,asname,org,isp,query,reverse"}
        try:
            resp = await self.client.get(url, params=params, headers={"User-Agent": self.user_agent}, timeout=15.0)
            data = resp.json()
            if data.get("status") != "success":
                self.failures.record("enrichment", "ip-api", data.get("message") or "unsuccessful", error_type="ApiFailure")
                return None
            return data
        except Exception as e:
            self.failures.record("enrichment", "ip-api", e)
            return None

    async def _rdap(self, ip: str) -> dict[str, Any] | None:
        url = f"https://rdap.org/ip/{ip}"
        try:
            resp = await self.client.get(
                url,
                headers={"User-Agent": self.user_agent, "Accept": "application/rdap+json"},
                timeout=20.0,
                follow_redirects=True,
            )
            if resp.status_code >= 400:
                self.failures.record("enrichment", "rdap", f"HTTP {resp.status_code}", error_type="HttpError")
                return None
            data = resp.json()
            prefix = None
            cidrs = data.get("cidr0_cidrs") or []
            if cidrs and isinstance(cidrs, list):
                c0 = cidrs[0]
                if "v4prefix" in c0:
                    prefix = f"{c0['v4prefix']}/{c0.get('length')}"
                elif "v6prefix" in c0:
                    prefix = f"{c0['v6prefix']}/{c0.get('length')}"
            asn = None
            origin = data.get("arin_originas0_originautnums") or []
            if origin:
                asn = f"AS{origin[0]}"
            org = None
            for ent in data.get("entities") or []:
                roles = ent.get("roles") or []
                if "registrant" in roles or "abuse" in roles:
                    vcard = ent.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                                org = item[3]
                                break
                if org:
                    break
            return {
                "prefix": prefix,
                "asn": asn,
                "name": data.get("name"),
                "org": org,
                "rdap_server": str(resp.url),
                "handle": data.get("handle"),
            }
        except Exception as e:
            self.failures.record("enrichment", "rdap", e)
            return None

    async def _reverse_dns(self, ip: str) -> str | None:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = list(self.dns_resolvers[:2]) or ["1.1.1.1"]
        resolver.lifetime = 5.0
        try:
            ans = await resolver.resolve_address(ip)
            names = [str(r.target).rstrip(".").lower() for r in ans]
            return names[0] if names else None
        except Exception as e:
            if "NXDOMAIN" not in type(e).__name__ and "NoAnswer" not in type(e).__name__:
                self.failures.record("enrichment", "ptr", e)
            return None

    async def _cymru(self, ip: str) -> dict[str, Any] | None:
        if ":" in ip:
            return None
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = list(self.dns_resolvers[:2]) or ["1.1.1.1"]
        resolver.lifetime = 6.0
        try:
            ans = await resolver.resolve(rev, "TXT")
            text = ans[0].to_text().strip('"')
            parts = [p.strip() for p in text.split("|")]
            out: dict[str, Any] = {"raw": text}
            if parts:
                out["asn"] = f"AS{parts[0]}" if not parts[0].startswith("AS") else parts[0]
            if len(parts) > 1:
                out["prefix"] = parts[1]
            if len(parts) > 2:
                out["country"] = parts[2]
            try:
                asn_num = parts[0].lstrip("AS")
                desc_ans = await resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                desc = desc_ans[0].to_text().strip('"')
                dparts = [p.strip() for p in desc.split("|")]
                if len(dparts) >= 5:
                    out["as_org"] = dparts[4]
                out["asn_desc_raw"] = desc
            except Exception:
                pass
            return out
        except dns.exception.Timeout as e:
            self.failures.record("enrichment", "team_cymru", e, error_type="Timeout")
            return None
        except Exception as e:
            self.failures.record("enrichment", "team_cymru", e)
            return None
