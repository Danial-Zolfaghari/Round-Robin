"""CLI — default: live unique-IPv4 hunt (dns + nslookup hybrid)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import Config, DEFAULT_RESOLVERS
from .live_ui import run_live_hunt
from .models import utc_now_iso


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dns_discovery",
        description="Live unique IPv4 hunter for exact domains. Saves only to txt files.",
    )
    p.add_argument("--domain", "-d", action="append", dest="domains", help="Target hostname (repeatable)")
    p.add_argument("--domains-file", "-f", help="Text file with one domain per line")
    p.add_argument(
        "--resolvers",
        default=",".join(DEFAULT_RESOLVERS),
        help="Comma-separated DNS resolvers",
    )
    p.add_argument("--output", "-o", default=None, help="Output directory")
    p.add_argument("--interval", type=float, default=0.12, help="Seconds between hunt rounds")
    p.add_argument("--fresh", action="store_true", help="Delete existing IP txt files first")
    p.add_argument("--append", action="store_true", help="Keep existing IPs (default)")
    p.add_argument("--rounds", type=int, default=0, help="Run N rounds then exit (0 = until Ctrl+C)")
    p.add_argument(
        "--engine",
        choices=["hybrid", "dns", "nslookup"],
        default="hybrid",
        help="hybrid=dns+nslookup (default); dns=dnspython only; nslookup=lookup only",
    )
    p.add_argument(
        "--web",
        action="store_true",
        help="Also pull historical IPs from public web indexes; save only if TLS SNI still matches domain",
    )
    p.add_argument(
        "--web-interval",
        type=float,
        default=120.0,
        help="Seconds between web historical refreshes (default 120)",
    )
    p.add_argument("--interactive", action="store_true", help="Interactive UI")
    p.add_argument("--advanced", action="store_true", help="Optional multi-source discovery")
    p.add_argument("--sources", default="dns,ct,passive")
    p.add_argument("--validate", action="store_true")
    p.add_argument("--enrich", action="store_true")
    p.add_argument("--http-validate", action="store_true")
    p.add_argument("--json-out")
    p.add_argument("--max-related", type=int, default=40)
    return p


def load_domains(args: argparse.Namespace) -> tuple[list[str], Path | None]:
    domains: list[str] = []
    file_path: Path | None = None
    if args.domains:
        domains.extend(args.domains)
    if args.domains_file:
        file_path = Path(args.domains_file)
        for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            d = line.strip()
            if not d or d.startswith("#"):
                continue
            d = d.replace("https://", "").replace("http://", "").split("/")[0].strip().rstrip(".")
            if d and d not in domains:
                domains.append(d)
    return domains, file_path


async def run_advanced(domains: list[str], output_dir: Path, args: argparse.Namespace) -> int:
    from .engine import DiscoveryEngine, default_store_for

    cfg = Config(
        resolvers=[r.strip() for r in args.resolvers.split(",") if r.strip()],
        sources=[s.strip().lower() for s in args.sources.split(",") if s.strip()],
        output_dir=output_dir,
        do_enrich=args.enrich,
        do_validate=args.validate,
        do_http_validate=args.http_validate,
        max_related_resolve=args.max_related,
    )
    if args.fresh:
        db = output_dir / "evidence.sqlite3"
        if db.exists():
            db.unlink()

    store = default_store_for(output_dir, label="evidence")
    summaries = []
    async with DiscoveryEngine(cfg, store) as engine:
        for host in domains:
            print(f"[*] Advanced discovery: {host}")
            summary = await engine.discover_once(host)
            summaries.append(summary)
            print(f"[OK] {host}: ips={summary['ip_count']} new={len(summary['new_ips'])}")

    for host in domains:
        path = output_dir / f"{host}_evidence.json"
        store.export_json(path, hostname=host)
        print(f"[OK] {path}")
        print(f"[OK] {output_dir / (host + '_ips_unique.txt')}")
    if args.json_out:
        store.export_json(Path(args.json_out), hostname=domains[0] if len(domains) == 1 else None)
    (output_dir / "last_run_summary.json").write_text(
        json.dumps({"generated_at": utc_now_iso(), "summaries": summaries}, indent=2),
        encoding="utf-8",
    )
    store.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.interactive or (not args.domains and not args.domains_file):
        from .interactive import run_interactive

        return run_interactive()

    domains, file_path = load_domains(args)
    if not domains:
        print("No domains provided.", file=sys.stderr)
        return 2

    if args.output:
        output_dir = Path(args.output)
    elif file_path:
        output_dir = Path("output") / file_path.stem
    else:
        output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)

    resolvers = [r.strip() for r in args.resolvers.split(",") if r.strip()]

    try:
        if args.advanced:
            return asyncio.run(run_advanced(domains, output_dir, args))
        return asyncio.run(
            run_live_hunt(
                domains,
                output_dir,
                resolvers=resolvers,
                append=not args.fresh,
                interval=args.interval,
                engine_mode=args.engine,
                use_web=args.web,
                web_interval=args.web_interval,
                rounds=args.rounds,
                ask_exit=True,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
