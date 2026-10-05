"""Interactive UX — live hybrid IP hunter (txt only)."""

from __future__ import annotations

import asyncio
import os
import platform
import re
import sys
from pathlib import Path

from .live_ui import run_live_hunt


def clear_screen() -> None:
    os.system("cls" if platform.system().lower() == "windows" else "clear")


def clean_domain(raw: str) -> str | None:
    domain = re.sub(r"^https?://", "", raw.strip(), flags=re.IGNORECASE)
    domain = domain.split("/")[0].split("?")[0].strip().rstrip(".")
    return domain if domain else None


def load_domains_from_text(text: str) -> list[str]:
    domains: list[str] = []
    for p in (x.strip() for x in text.split(",") if x.strip()):
        d = clean_domain(p)
        if d and d not in domains:
            domains.append(d)
    return domains


def load_domains_from_file(filepath: str) -> tuple[list[str] | None, str | None, Path | None]:
    raw = filepath.strip().strip('"').strip("'")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if not path.is_file():
        return None, f"File not found: {path}", None
    domains: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                d = clean_domain(line)
                if d and d not in domains:
                    domains.append(d)
    except Exception as e:
        return None, f"Error reading file: {e}", None
    return domains, None, path


def run_interactive() -> int:
    try:
        from colorama import Fore, Style, init as colorama_init
    except ImportError:
        print("Missing colorama/rich. Install: pip install colorama rich")
        return 1

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    colorama_init(autoreset=True)
    clear_screen()

    print(f"{Fore.YELLOW}How do you want to provide domains?{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1.{Style.RESET_ALL} Enter domain(s) directly (single or comma-separated)")
    print(f"{Fore.GREEN}2.{Style.RESET_ALL} Provide a .txt file containing domains")

    while True:
        try:
            mode = input(f"{Fore.CYAN}Choose 1 or 2: {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}[!] Cancelled by user.{Style.RESET_ALL}")
            return 0
        if mode in ("1", "2"):
            break
        print(f"{Fore.RED}[!] Please enter 1 or 2.{Style.RESET_ALL}")

    domains: list[str] = []
    input_file_path: Path | None = None

    if mode == "1":
        while True:
            try:
                raw = input(
                    f"{Fore.CYAN}Enter domain(s) (example: google.com or google.com,youtube.com): {Style.RESET_ALL}"
                ).strip()
            except (KeyboardInterrupt, EOFError):
                return 0
            if not raw:
                print(f"{Fore.RED}[!] Input cannot be empty.{Style.RESET_ALL}")
                continue
            domains = load_domains_from_text(raw)
            if domains:
                break
            print(f"{Fore.RED}[!] No valid domains found. Try again.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.CYAN}[*] Current directory: {Path.cwd()}{Style.RESET_ALL}")
        while True:
            try:
                raw = input(f"{Fore.CYAN}Enter path to .txt file: {Style.RESET_ALL}").strip()
            except (KeyboardInterrupt, EOFError):
                return 0
            if not raw:
                print(f"{Fore.RED}[!] Path cannot be empty.{Style.RESET_ALL}")
                continue
            domains, err, input_file_path = load_domains_from_file(raw)
            if err:
                print(f"{Fore.RED}[!] {err}{Style.RESET_ALL}")
                continue
            if not domains:
                print(f"{Fore.RED}[!] File is empty or contains no valid domains.{Style.RESET_ALL}")
                continue
            break

    output_dir = Path("output")
    if input_file_path:
        output_dir = Path("output") / input_file_path.stem

    print(f"\n{Fore.GREEN}[OK] Loaded {len(domains)} domain(s):{Style.RESET_ALL}")
    for d in domains:
        print(f"    - {d}")

    print(f"\n{Fore.YELLOW}Engine mode:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1.{Style.RESET_ALL} hybrid (dns + nslookup together)  [recommended]")
    print(f"{Fore.GREEN}2.{Style.RESET_ALL} dns only (dnspython / fast)")
    print(f"{Fore.GREEN}3.{Style.RESET_ALL} nslookup only (classic lookup)")
    while True:
        try:
            eng = input(f"{Fore.CYAN}Choose 1/2/3 (default 1): {Style.RESET_ALL}").strip() or "1"
        except (KeyboardInterrupt, EOFError):
            return 0
        if eng in ("1", "2", "3"):
            break
    engine_mode = {"1": "hybrid", "2": "dns", "3": "nslookup"}[eng]

    print(f"\n{Fore.YELLOW}Also pull historical IPs from the web (validate with TLS/SNI)?{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1.{Style.RESET_ALL} No — only live DNS/nslookup")
    print(f"{Fore.GREEN}2.{Style.RESET_ALL} Yes — web history + TLS check before save")
    while True:
        try:
            web_choice = input(f"{Fore.CYAN}Choose 1 or 2 (default 2): {Style.RESET_ALL}").strip() or "2"
        except (KeyboardInterrupt, EOFError):
            return 0
        if web_choice in ("1", "2"):
            break
    use_web = web_choice == "2"

    print(f"\n{Fore.YELLOW}How should existing output files be handled?{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1.{Style.RESET_ALL} Delete existing files and start fresh")
    print(f"{Fore.GREEN}2.{Style.RESET_ALL} Append new IPs to existing files")
    while True:
        try:
            output_mode = input(f"{Fore.CYAN}Choose 1 or 2: {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            return 0
        if output_mode in ("1", "2"):
            break
        print(f"{Fore.RED}[!] Please enter 1 or 2.{Style.RESET_ALL}")

    try:
        return asyncio.run(
            run_live_hunt(
                domains,
                output_dir,
                append=(output_mode == "2"),
                engine_mode=engine_mode,
                use_web=use_web,
                ask_exit=True,
            )
        )
    except (KeyboardInterrupt, EOFError, SystemExit):
        return 0
