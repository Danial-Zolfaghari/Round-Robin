# Round-Robin

<p align="center">
  <strong>Cross-platform DNS discovery, correlation and validation toolkit</strong><br/>
  Passive + active discovery • DNS validation • IP enrichment • SQLite persistence • interactive CLI
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-supported-FCC624?logo=linux&logoColor=black">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-supported-0078D4?logo=windows11&logoColor=white">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-supported-000000?logo=apple&logoColor=white">
  <img alt="CI" src="https://github.com/Danial-Zolfaghari/Round-Robin/actions/workflows/ci.yml/badge.svg">
</p>
<p align="center">
  <a href="https://github.com/Danial-Zolfaghari/Round-Robin/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Danial-Zolfaghari/Round-Robin/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Danial-Zolfaghari/Round-Robin/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Danial-Zolfaghari/Round-Robin?display_name=tag&sort=semver"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Danial-Zolfaghari/Round-Robin"></a>
</p>


---

## Overview

**Round-Robin** is a Python DNS-discovery pipeline built to collect candidate hostnames from multiple sources, validate them, resolve network information, enrich public IPs and persist results for later review.

The public build contains **no organization-specific DNS ranges or private infrastructure targets**. Resolver addresses and service integrations are configurable.

## Platform support

| Platform | Support | Notes |
|---|---|---|
| Linux | ✅ Full | Recommended for server/automation use |
| Windows 10/11 | ✅ Full | PowerShell / CMD supported |
| macOS | ✅ Full | Python 3.10+ required |

## Architecture

```mermaid
flowchart LR
    CLI[CLI / Interactive UI] --> ENGINE[Discovery Engine]
    ENGINE --> CT[Certificate Transparency]
    ENGINE --> PDNS[Passive DNS]
    ENGINE --> WEB[Web / DNS Sources]
    ENGINE --> VALIDATE[Active DNS Validation]
    VALIDATE --> ENRICH[IP / CDN Enrichment]
    ENRICH --> STORE[(SQLite / Result Store)]
    STORE --> UI[Live UI / Reports]
```

## Pipeline

```mermaid
sequenceDiagram
    participant U as User
    participant E as Engine
    participant S as Sources
    participant D as DNS Validators
    participant I as IP Enrichment
    participant DB as Store

    U->>E: domain / discovery target
    E->>S: query passive sources
    S-->>E: hostname candidates
    E->>D: resolve + validate
    D-->>E: confirmed DNS records
    E->>I: enrich public IPs
    I-->>E: ASN / network / CDN context
    E->>DB: persist normalized results
    DB-->>U: live + historical output
```

## Features

- Certificate Transparency discovery via crt.sh
- Passive host discovery sources
- Direct DNS lookups and parser utilities
- Active hostname validation
- Configurable DNS resolver pool
- Retry / failure tracking
- Rate limiting
- Public-IP enrichment
- CDN classification helpers
- SQLite-backed persistence
- Interactive Rich-based terminal UI
- Environment-based optional API configuration
- Cross-platform Python implementation

## Requirements

- Python **3.10+**
- Internet access for public discovery/enrichment sources

Python packages:

```text
colorama>=0.4.6
rich>=13.0.0
dnspython>=2.4.0
httpx>=0.27.0
python-dotenv>=1.0.0
```

## Installation

```bash
git clone https://github.com/Danial-Zolfaghari/Round-Robin.git
cd Round-Robin
python -m venv .venv
```

Linux / macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Windows:

```powershell
Copy-Item .env.example .env
```

Optional provider/API values belong in `.env`; never commit real API keys.

The built-in resolver pool uses well-known public DNS resolvers and can be changed in configuration.

## Run

Module entry point:

```bash
python -m dns_discovery --help
```

Compatibility launcher:

```bash
python "Round Robin Hunter.py"
```

Windows convenience launcher:

```bat
start.bat
```

## Project structure

```text
Round-Robin/
├─ dns_discovery/
│  ├─ dns/
│  ├─ enrich/
│  ├─ sources/
│  ├─ validate/
│  ├─ cli.py
│  ├─ config.py
│  ├─ engine.py
│  ├─ hunter.py
│  ├─ live_ui.py
│  ├─ models.py
│  └─ store.py
├─ Round Robin Hunter.py
├─ .env.example
├─ requirements.txt
└─ start.bat
```

## Security / privacy

Discovery results may reveal hostnames and network metadata. Do not commit result databases, environment files or exports containing private infrastructure.

Use the tool only for domains and infrastructure you own or are authorized to assess.

## Author

**Danial Zolfaghari** — [@Danial-Zolfaghari](https://github.com/Danial-Zolfaghari)
