from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table

from .dns import LiveDnsSource
from .failures import FailureSink
from .ip_store import IpTxtStore
from .rate_limit import RateLimiter


async def run_live_hunt(domains: list[str], output_dir: Path, *, resolvers: list[str], append: bool = True, interval: float = 0.12, engine_mode: str = "hybrid", use_web: bool = False, web_interval: float = 120.0, rounds: int = 0, ask_exit: bool = False) -> int:
    store = IpTxtStore(output_dir)
    for host in domains:
        if append: store.load_existing(host)
        else: store.clear(host)
    failures = FailureSink()
    source = LiveDnsSource(resolvers, RateLimiter(), failures)
    console = Console()
    round_no = 0
    try:
        with Live(refresh_per_second=4, console=console) as live:
            while True:
                round_no += 1
                for host in domains:
                    obs = await source.query_hostname(host)
                    store.add(host, {o.ip for o in obs if o.ip})
                table = Table(title=f"Round Robin Hunter — round {round_no}")
                table.add_column("Domain"); table.add_column("Unique IPv4", justify="right")
                for host in domains: table.add_row(host, str(store.count(host)))
                live.update(table)
                if rounds and round_no >= rounds: break
                await asyncio.sleep(max(0.01, interval))
    except KeyboardInterrupt:
        pass
    return 0
