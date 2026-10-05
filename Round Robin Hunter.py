"""
Round Robin Hunter — fast unique-IP collector for exact domains.

Default: continuous DNS queries via dnspython → `{domain}_ips_unique.txt`
No SQLite. No related-host sprawl. Just IPs for the domains you give.

CLI:
  python -m dns_discovery -d lambda.fivem.net
  python -m dns_discovery -f Fivem.txt --fresh
  python -m dns_discovery -d lambda.fivem.net --rounds 20
"""

from dns_discovery.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["--interactive"]))
