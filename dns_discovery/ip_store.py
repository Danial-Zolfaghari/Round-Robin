"""Simple unique-IPv4 text store — no SQLite."""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path


def is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


class IpTxtStore:
    """In-memory dedup + one `{domain}_ips_unique.txt` per hostname (IPv4 only)."""

    def __init__(self, output_dir: Path, excluded_ips: set[str] | None = None) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.excluded_ips = excluded_ips or set()
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def domain_file(self, hostname: str) -> Path:
        return self.output_dir / f"{hostname}_ips_unique.txt"

    def load_existing(self, hostname: str) -> int:
        path = self.domain_file(hostname)
        loaded = set()
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                ip = line.strip()
                if ip and is_ipv4(ip) and ip not in self.excluded_ips:
                    loaded.add(ip)
        with self._lock:
            self._seen.setdefault(hostname, set()).update(loaded)
        return len(loaded)

    def clear(self, hostname: str) -> None:
        with self._lock:
            self._seen[hostname] = set()
        path = self.domain_file(hostname)
        if path.is_file():
            path.unlink()

    def known(self, hostname: str) -> set[str]:
        with self._lock:
            return set(self._seen.get(hostname, set()))

    def count(self, hostname: str | None = None) -> int:
        with self._lock:
            if hostname is None:
                return sum(len(s) for s in self._seen.values())
            return len(self._seen.get(hostname, set()))

    def add(self, hostname: str, ips: list[str] | set[str]) -> list[str]:
        """Add IPv4s only; return newly discovered ones. Rewrites txt only when new."""
        new: list[str] = []
        with self._lock:
            bucket = self._seen.setdefault(hostname, set())
            for ip in ips:
                if not ip or not is_ipv4(ip) or ip in self.excluded_ips or ip in bucket:
                    continue
                bucket.add(ip)
                new.append(ip)
            if new:
                path = self.domain_file(hostname)
                with open(path, "w", encoding="utf-8") as f:
                    for ip in sorted(bucket):
                        f.write(ip + "\n")
        return sorted(new)
