"""Persistence: SQLite evidence store + backward-compatible unique-IP text files."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import IpRecord, NetworkInfo, Classification, ValidationResult, SourceEvidence, utc_now_iso


SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_records (
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    statuses_json TEXT NOT NULL DEFAULT '[]',
    dns_json TEXT NOT NULL DEFAULT '{}',
    related_hostnames_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (hostname, ip)
);

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    resolver TEXT,
    tool TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(hostname, ip, type, resolver, tool, timestamp, detail_json)
);

CREATE TABLE IF NOT EXISTS enrichment (
    ip TEXT PRIMARY KEY,
    asn TEXT,
    prefix TEXT,
    organization TEXT,
    isp TEXT,
    country TEXT,
    reverse_dns TEXT,
    source TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classification (
    ip TEXT PRIMARY KEY,
    provider TEXT,
    cdn TEXT,
    confidence TEXT,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation (
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    result_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (hostname, ip)
);

CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    operation TEXT NOT NULL,
    hostname TEXT,
    timestamp TEXT NOT NULL,
    error_type TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    resolver TEXT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    cname_chain_json TEXT NOT NULL DEFAULT '[]',
    tool TEXT,
    ip TEXT
);
"""


class EvidenceStore:
    def __init__(self, sqlite_path: Path, txt_dir: Path | None = None) -> None:
        self.sqlite_path = Path(sqlite_path)
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.txt_dir = Path(txt_dir) if txt_dir else self.sqlite_path.parent
        self.txt_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.sqlite_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        # In-memory index for fast dedup during a run
        self._records: dict[tuple[str, str], IpRecord] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM ip_records")
            for row in cur.fetchall():
                key = (row["hostname"], row["ip"])
                rec = IpRecord(
                    hostname=row["hostname"],
                    ip=row["ip"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    statuses=json.loads(row["statuses_json"] or "[]"),
                    dns=json.loads(row["dns_json"] or "{}"),
                    related_hostnames=json.loads(row["related_hostnames_json"] or "[]"),
                )
                self._records[key] = rec
            # attach sources
            cur = self._conn.execute("SELECT * FROM sources")
            for row in cur.fetchall():
                key = (row["hostname"], row["ip"])
                if key not in self._records:
                    continue
                self._records[key].sources.append(
                    SourceEvidence(
                        type=row["type"],
                        timestamp=row["timestamp"],
                        resolver=row["resolver"],
                        tool=row["tool"],
                        detail=json.loads(row["detail_json"] or "{}"),
                    )
                )
            cur = self._conn.execute("SELECT * FROM enrichment")
            enrich_map = {r["ip"]: r for r in cur.fetchall()}
            cur = self._conn.execute("SELECT * FROM classification")
            class_map = {r["ip"]: r for r in cur.fetchall()}
            cur = self._conn.execute("SELECT * FROM validation")
            val_map = {(r["hostname"], r["ip"]): r for r in cur.fetchall()}
            for key, rec in self._records.items():
                e = enrich_map.get(rec.ip)
                if e:
                    rec.network = NetworkInfo(
                        asn=e["asn"],
                        prefix=e["prefix"],
                        organization=e["organization"],
                        isp=e["isp"],
                        country=e["country"],
                        reverse_dns=e["reverse_dns"],
                        source=e["source"],
                    )
                c = class_map.get(rec.ip)
                if c:
                    rec.classification = Classification(
                        provider=c["provider"],
                        cdn=c["cdn"],
                        confidence=c["confidence"],
                        evidence=json.loads(c["evidence_json"] or "[]"),
                    )
                v = val_map.get(key)
                if v:
                    data = json.loads(v["result_json"] or "{}")
                    fields = ValidationResult.__dataclass_fields__
                    rec.validation = ValidationResult(
                        **{k: data.get(k) for k in fields if k in data}
                    )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def known_ips(self, hostname: str) -> set[str]:
        return {ip for (h, ip) in self._records if h == hostname}

    def get_record(self, hostname: str, ip: str) -> IpRecord | None:
        return self._records.get((hostname, ip))

    def all_records(self, hostname: str | None = None) -> list[IpRecord]:
        if hostname is None:
            return list(self._records.values())
        return [r for (h, _), r in self._records.items() if h == hostname]

    def upsert_ip(
        self,
        hostname: str,
        ip: str,
        *,
        status: str | None = None,
        source: SourceEvidence | None = None,
        dns_update: dict[str, Any] | None = None,
        related_hostname: str | None = None,
        timestamp: str | None = None,
    ) -> tuple[IpRecord, bool]:
        """Insert or merge IP. Returns (record, is_new_ip)."""
        ts = timestamp or utc_now_iso()
        key = (hostname, ip)
        with self._lock:
            is_new = key not in self._records
            if is_new:
                rec = IpRecord(hostname=hostname, ip=ip, first_seen=ts, last_seen=ts)
                self._records[key] = rec
            else:
                rec = self._records[key]
                rec.last_seen = ts
            if status:
                rec.add_status(status)
            if source:
                # provenance dedup: same type+resolver+tool+detail within same second ok to skip exact dupes
                sig = (source.type, source.resolver, source.tool, json.dumps(source.detail, sort_keys=True))
                existing_sigs = {
                    (s.type, s.resolver, s.tool, json.dumps(s.detail, sort_keys=True))
                    for s in rec.sources
                }
                if sig not in existing_sigs:
                    rec.sources.append(source)
                    self._conn.execute(
                        "INSERT OR IGNORE INTO sources (hostname, ip, type, timestamp, resolver, tool, detail_json) VALUES (?,?,?,?,?,?,?)",
                        (
                            hostname,
                            ip,
                            source.type,
                            source.timestamp,
                            source.resolver,
                            source.tool,
                            json.dumps(source.detail, sort_keys=True),
                        ),
                    )
            if dns_update:
                rec.dns.update(dns_update)
            if related_hostname and related_hostname not in rec.related_hostnames:
                rec.related_hostnames.append(related_hostname)
            self._conn.execute(
                """
                INSERT INTO ip_records (hostname, ip, first_seen, last_seen, statuses_json, dns_json, related_hostnames_json)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(hostname, ip) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    statuses_json=excluded.statuses_json,
                    dns_json=excluded.dns_json,
                    related_hostnames_json=excluded.related_hostnames_json
                """,
                (
                    hostname,
                    ip,
                    rec.first_seen,
                    rec.last_seen,
                    json.dumps(rec.statuses),
                    json.dumps(rec.dns),
                    json.dumps(rec.related_hostnames),
                ),
            )
            self._conn.commit()
            self._write_txt(hostname)
            return rec, is_new

    def save_observation(self, obs: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO observations (hostname, record_type, value, resolver, timestamp, source, cname_chain_json, tool, ip)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    obs.get("hostname"),
                    obs.get("record_type"),
                    obs.get("value"),
                    obs.get("resolver"),
                    obs.get("timestamp"),
                    obs.get("source"),
                    json.dumps(obs.get("cname_chain") or []),
                    obs.get("tool"),
                    obs.get("ip"),
                ),
            )
            self._conn.commit()

    def save_enrichment(self, ip: str, network: NetworkInfo) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO enrichment (ip, asn, prefix, organization, isp, country, reverse_dns, source, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    asn=excluded.asn, prefix=excluded.prefix, organization=excluded.organization,
                    isp=excluded.isp, country=excluded.country, reverse_dns=excluded.reverse_dns,
                    source=excluded.source, updated_at=excluded.updated_at
                """,
                (
                    ip,
                    network.asn,
                    network.prefix,
                    network.organization,
                    network.isp,
                    network.country,
                    network.reverse_dns,
                    network.source,
                    utc_now_iso(),
                ),
            )
            self._conn.commit()
            for (h, i), rec in self._records.items():
                if i == ip:
                    rec.network = network

    def save_classification(self, ip: str, classification: Classification) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO classification (ip, provider, cdn, confidence, evidence_json, updated_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    provider=excluded.provider, cdn=excluded.cdn, confidence=excluded.confidence,
                    evidence_json=excluded.evidence_json, updated_at=excluded.updated_at
                """,
                (
                    ip,
                    classification.provider,
                    classification.cdn,
                    classification.confidence,
                    json.dumps(classification.evidence),
                    utc_now_iso(),
                ),
            )
            self._conn.commit()
            for (h, i), rec in self._records.items():
                if i == ip:
                    rec.classification = classification

    def save_validation(self, hostname: str, ip: str, result: ValidationResult) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO validation (hostname, ip, result_json, timestamp)
                VALUES (?,?,?,?)
                ON CONFLICT(hostname, ip) DO UPDATE SET result_json=excluded.result_json, timestamp=excluded.timestamp
                """,
                (hostname, ip, json.dumps(result.to_dict()), result.timestamp or utc_now_iso()),
            )
            self._conn.commit()
            key = (hostname, ip)
            if key in self._records:
                self._records[key].validation = result
                if result.tls_hostname_match or result.http_host_match:
                    self._records[key].add_status("VALIDATED")
                    self._conn.execute(
                        "UPDATE ip_records SET statuses_json=? WHERE hostname=? AND ip=?",
                        (json.dumps(self._records[key].statuses), hostname, ip),
                    )
                    self._conn.commit()

    def save_failure(self, failure: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO failures (source, operation, hostname, timestamp, error_type, message) VALUES (?,?,?,?,?,?)",
                (
                    failure.get("source"),
                    failure.get("operation"),
                    failure.get("hostname"),
                    failure.get("timestamp"),
                    failure.get("error_type"),
                    failure.get("message"),
                ),
            )
            self._conn.commit()

    def _write_txt(self, hostname: str) -> None:
        path = self.txt_dir / f"{hostname}_ips_unique.txt"
        ips = sorted(ip for (h, ip) in self._records if h == hostname)
        with open(path, "w", encoding="utf-8") as f:
            for ip in ips:
                f.write(ip + "\n")

    def export_json(self, path: Path, hostname: str | None = None) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        records = self.all_records(hostname)
        payload = {
            "generated_at": utc_now_iso(),
            "hostname": hostname,
            "count": len(records),
            "records": [r.to_dict() for r in sorted(records, key=lambda r: r.ip)],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def import_txt_ips(self, hostname: str, path: Path, status: str = "UNVERIFIED") -> int:
        """Load legacy unique-IP text file without inventing provenance."""
        if not path.is_file():
            return 0
        n = 0
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            ip = line.strip()
            if not ip:
                continue
            _, is_new = self.upsert_ip(
                hostname,
                ip,
                status=status,
                source=SourceEvidence(
                    type="legacy_txt",
                    timestamp=utc_now_iso(),
                    detail={"path": str(path), "note": "imported from prior unique-IP file; provenance unknown"},
                ),
            )
            if is_new:
                n += 1
        return n
