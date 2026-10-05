from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt

from .config import DEFAULT_RESOLVERS
from .live_ui import run_live_hunt

console = Console()


def run_interactive() -> int:
    console.print("[bold cyan]Round Robin Hunter[/bold cyan]")
    raw = Prompt.ask("Domain(s), comma separated").strip()
    domains = [x.strip() for x in raw.split(",") if x.strip()]
    if not domains:
        console.print("[red]No domain supplied.[/red]")
        return 2
    out = Path(Prompt.ask("Output directory", default="output"))
    fresh = Confirm.ask("Start fresh?", default=False)
    try:
        return asyncio.run(run_live_hunt(domains, out, resolvers=list(DEFAULT_RESOLVERS), append=not fresh, ask_exit=True))
    except KeyboardInterrupt:
        return 0
