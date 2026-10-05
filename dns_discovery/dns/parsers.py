"""Protocol-aware DNS CLI output parsers — avoid naive whole-stdout IPv4 scraping."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IPV6_RE = re.compile(
    r"\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"::)\b"
)


@dataclass
class ParsedDns:
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    section: str | None = None


def _valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def parse_dig_short(output: str) -> ParsedDns:
    """dig +short — each non-empty line is a record value (A/AAAA/CNAME)."""
    result = ParsedDns(section="short")
    for line in output.splitlines():
        val = line.strip().rstrip(".")
        if not val:
            continue
        if _valid_ipv4(val):
            result.ipv4.append(val)
        elif _valid_ipv6(val):
            result.ipv6.append(val)
        elif " " not in val and any(c.isalpha() for c in val):
            result.cnames.append(val.lower())
    return result


def parse_dig_full(output: str) -> ParsedDns:
    """Parse dig default output — only ANSWER SECTION."""
    result = ParsedDns(section=None)
    in_answer = False
    for line in output.splitlines():
        if "ANSWER SECTION" in line:
            in_answer = True
            result.section = "ANSWER"
            continue
        if in_answer and line.startswith(";;"):
            break
        if not in_answer:
            continue
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        rtype = parts[3].upper()
        rdata = parts[4].rstrip(".")
        if rtype == "A" and _valid_ipv4(rdata):
            result.ipv4.append(rdata)
        elif rtype == "AAAA" and _valid_ipv6(rdata):
            result.ipv6.append(rdata)
        elif rtype == "CNAME":
            result.cnames.append(rdata.lower())
    return result


def parse_nslookup(output: str, query_name: str | None = None) -> ParsedDns:
    """
    Parse nslookup — prefer Addresses under the answered name.
    Skip the initial 'Server:' / 'Address:' resolver lines.
    """
    result = ParsedDns(section="answer")
    lines = output.splitlines()
    # Drop resolver preamble: first Server/Address block
    i = 0
    while i < len(lines):
        if lines[i].strip().lower().startswith("server:"):
            i += 1
            if i < len(lines) and "address" in lines[i].lower():
                i += 1
            # blank line often follows
            while i < len(lines) and not lines[i].strip():
                i += 1
            break
        i += 1

    body = "\n".join(lines[i:])
    # Non-authoritative / Name: ... Address(es):
    current_name = None
    collecting_addrs = False
    for line in body.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("name:"):
            current_name = stripped.split(":", 1)[1].strip().rstrip(".").lower()
            collecting_addrs = False
            continue
        if "canonical name" in low or low.startswith("cname"):
            # Aliases / canonical name = foo
            if "=" in stripped:
                cname = stripped.split("=", 1)[1].strip().rstrip(".").lower()
                result.cnames.append(cname)
            collecting_addrs = False
            continue
        if low.startswith("address") or low.startswith("addresses"):
            collecting_addrs = True
            # Address: 1.2.3.4  or Addresses: 1.2.3.4
            after = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            for m in IPV4_RE.findall(after):
                if _valid_ipv4(m):
                    result.ipv4.append(m)
            for m in IPV6_RE.findall(after):
                if _valid_ipv6(m):
                    result.ipv6.append(m)
            continue
        if collecting_addrs and stripped:
            for m in IPV4_RE.findall(stripped):
                if _valid_ipv4(m):
                    result.ipv4.append(m)
            for m in IPV6_RE.findall(stripped):
                if _valid_ipv6(m):
                    result.ipv6.append(m)
            if not IPV4_RE.search(stripped) and not IPV6_RE.search(stripped):
                collecting_addrs = False

    # Fallback: if nothing found, do not scrape whole stdout (avoids resolver IP FP)
    _ = current_name, query_name
    return result


def parse_host(output: str) -> ParsedDns:
    """Parse `host` output lines."""
    result = ParsedDns(section="host")
    for line in output.splitlines():
        low = line.lower()
        if " has address " in low:
            ip = line.split("has address", 1)[1].strip()
            if _valid_ipv4(ip):
                result.ipv4.append(ip)
        elif " has IPv6 address " in line or " has ipv6 address " in low:
            ip = line.split("address", 1)[1].strip()
            if _valid_ipv6(ip):
                result.ipv6.append(ip)
        elif " is an alias for " in low:
            cname = line.split("is an alias for", 1)[1].strip().rstrip(".").lower()
            result.cnames.append(cname)
    return result


def parse_drill(output: str) -> ParsedDns:
    """Parse drill output — ANSWER SECTION similar to dig."""
    return parse_dig_full(output)


def parse_tool_output(tool: str, output: str, query_name: str | None = None, short: bool = False) -> ParsedDns:
    tool = tool.lower()
    if tool == "dig":
        return parse_dig_short(output) if short else parse_dig_full(output)
    if tool == "nslookup":
        return parse_nslookup(output, query_name=query_name)
    if tool == "host":
        return parse_host(output)
    if tool == "drill":
        return parse_drill(output)
    return ParsedDns()
