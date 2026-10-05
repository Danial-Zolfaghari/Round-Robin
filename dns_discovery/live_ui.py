"""Shared live hunt UI (spinner + new-IP lines like classic Round Robin Hunter)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from .config import DEFAULT_EXCLUDED_IPS, DEFAULT_RESOLVERS
from .hunter import IpHunter


def format_elapsed(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        parts = [f"{hours}h"]
        if minutes:
            parts.append(f"{minutes}m")
        return " ".join(parts)
    days, hours = divmod(hours, 24)
    parts = [f"{days}d"]
    if hours:
        parts.append(f"{hours}h")
    return " ".join(parts)


def parse_engine_mode(mode: str) -> tuple[bool, bool]:
    """Return (use_dnspython, use_nslookup)."""
    m = (mode or "hybrid").strip().lower()
    if m in ("hybrid", "both", "all"):
        return True, True
    if m in ("dns", "dnspython"):
        return True, False
    if m in ("nslookup", "lookup", "legacy"):
        return False, True
    return True, True


async def run_live_hunt(
    domains: list[str],
    output_dir: Path,
    *,
    resolvers: list[str] | None = None,
    append: bool = True,
    interval: float = 0.12,
    engine_mode: str = "hybrid",
    use_web: bool = False,
    web_interval: float = 120.0,
    rounds: int = 0,
    ask_exit: bool = True,
) -> int:
    from colorama import Fore, Style, init as colorama_init
    from rich.console import Console
    from rich.live import Live
    from rich.spinner import Spinner

    colorama_init(autoreset=True)
    console = Console()
    resolvers = resolvers or list(DEFAULT_RESOLVERS)
    use_dns, use_ns = parse_engine_mode(engine_mode)
    start_time = datetime.now()

    def on_new(
        domain: str,
        new_ips: list[str],
        tool: str,
        resolver: str,
        domain_count: int,
        all_count: int,
    ) -> None:
        elapsed = format_elapsed((datetime.now() - start_time).total_seconds())
        console.print(
            f"[bold green][+][/bold green] {datetime.now().strftime('%H:%M:%S')} - {elapsed} "
            f"[bold white]{domain}[/bold white] "
            f"[yellow]{tool}@{resolver}[/yellow] → "
            f"[cyan]New:[/cyan] [white]{', '.join(new_ips)}[/white] "
            f"[magenta]| Domain: {domain_count} | All: {all_count}[/magenta]"
        )

    def on_status(msg: str) -> None:
        console.print(f"[dim]{msg}[/dim]")

    hunter = IpHunter(
        domains=domains,
        output_dir=output_dir,
        resolvers=resolvers,
        excluded_ips=set(DEFAULT_EXCLUDED_IPS),
        interval=interval,
        use_dnspython=use_dns,
        use_nslookup=use_ns,
        use_web=use_web,
        web_interval=web_interval,
        on_new_batch=on_new,
        on_status=on_status,
    )
    loaded = hunter.prepare(append=append)

    print(f"{Fore.CYAN}[*] Hunting IPs for {len(domains)} domain(s){Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Resolvers: {Fore.WHITE}{', '.join(resolvers)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Engines: {Fore.WHITE}{hunter.engines_label}{Style.RESET_ALL}")
    if use_web:
        print(
            f"{Fore.CYAN}[*] Web: {Fore.WHITE}historical IPs from public indexes, "
            f"saved only after TLS SNI check for that domain{Style.RESET_ALL}"
        )
    print(f"{Fore.CYAN}[*] Output: {Fore.WHITE}{output_dir}{Style.RESET_ALL}")
    print(
        f"{Fore.CYAN}[*] Mode: {Fore.WHITE}{'append' if append else 'fresh'} "
        f"(loaded {loaded} existing){Style.RESET_ALL}"
    )
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop.{Style.RESET_ALL}\n")

    async def worker() -> None:
        try:
            if rounds and rounds > 0:
                # still run one web pass if enabled
                if use_web:
                    await hunter.web_pass_once()
                for i in range(rounds):
                    if hunter.stop_event.is_set():
                        break
                    await hunter.round_once()
                    if i + 1 < rounds:
                        await asyncio.sleep(interval)
                hunter.stop_event.set()
            else:
                await hunter.hunt()
        finally:
            await hunter.close()

    worker_task = asyncio.create_task(worker())

    def make_status():
        total = hunter.store.count()
        return Spinner(
            "dots",
            text=f" Hunting {len(domains)} domain(s)...  Unique IPs: {total}",
            style="cyan",
        )

    try:
        while not hunter.stop_event.is_set():
            try:
                with Live(make_status(), refresh_per_second=12, console=console) as live:
                    while not hunter.stop_event.is_set():
                        live.update(make_status())
                        if worker_task.done():
                            hunter.stop_event.set()
                            break
                        await asyncio.sleep(0.12)
            except (KeyboardInterrupt, asyncio.CancelledError):
                print()
                if not ask_exit:
                    break
                try:
                    answer = input(f"{Fore.YELLOW}Do you want to exit? (y/N): {Style.RESET_ALL}").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    answer = "y"
                if answer == "y":
                    break
                console.print("[bold cyan][*] Resuming...[/bold cyan]\n")
                if worker_task.done():
                    worker_task = asyncio.create_task(worker())
                continue
    finally:
        hunter.stop_event.set()
        if not worker_task.done():
            worker_task.cancel()
            try:
                await asyncio.wait_for(worker_task, timeout=2.0)
            except Exception:
                pass
        await hunter.close()
        total = hunter.store.count()
        console.print(f"\n[bold green][OK] Total unique IPs: {total}[/bold green]")
        for d in domains:
            print(f"    {d}: {hunter.store.count(d)} -> {hunter.store.domain_file(d)}")
    return 0
