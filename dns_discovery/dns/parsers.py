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
    result = ParsedDns(section="answer")
    seen_answer = False
    for raw in output.splitlines():
        line = raw.strip()
        low = line.lower()
        if not line:
            continue
        if low.startswith("name:"):
            seen_answer = True
            continue
        if query_name and query_name.lower() in low:
            seen_answer = True
        if low.startswith("server:") and not seen_answer:
            continue
        if low.startswith("address:") and not seen_answer:
            continue
        if "canonical name" in low or "aliases:" in low:
            candidate = line.split("=", 1)[-1].split(":", 1)[-1].strip().rstrip(".")
            if candidate and candidate != line:
                result.cnames.append(candidate.lower())
            continue
        if seen_answer or low.startswith("addresses:") or low.startswith("address:"):
            for ip in IPV4_RE.findall(line):
                if _valid_ipv4(ip): result.ipv4.append(ip)
            for ip in IPV6_RE.findall(line):
                if _valid_ipv6(ip): result.ipv6.append(ip)
    return result


def parse_host(output: str) -> ParsedDns:
    result = ParsedDns(section="answer")
    for line in output.splitlines():
        line = line.strip()
        low = line.lower()
        if " has address " in low:
            val = line.rsplit(" ", 1)[-1]
            if _valid_ipv4(val): result.ipv4.append(val)
        elif " has ipv6 address " in low:
            val = line.rsplit(" ", 1)[-1]
            if _valid_ipv6(val): result.ipv6.append(val)
        elif " is an alias for " in low:
            val = line.rsplit(" ", 1)[-1].rstrip(".")
            if val: result.cnames.append(val.lower())
    return result


def parse_drill(output: str) -> ParsedDns:
    return parse_dig_full(output)


def parse_tool_output(tool: str, output: str, query_name: str | None = None, short: bool = False) -> ParsedDns:
    tool = tool.lower()
    if tool == "dig": return parse_dig_short(output) if short else parse_dig_full(output)
    if tool == "nslookup": return parse_nslookup(output, query_name=query_name)
    if tool == "host": return parse_host(output)
    if tool == "drill": return parse_drill(output)
    return ParsedDns()
