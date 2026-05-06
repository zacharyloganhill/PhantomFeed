# PhantomFeed

![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Open Source](https://img.shields.io/badge/open%20source-%E2%99%A5-red)

**Real-time threat intelligence aggregation, locally hosted.**

PhantomFeed pulls CVEs, vendor advisories, CISA alerts, malware feeds, and threat intel into a single searchable feed — with a dark-mode dashboard and a local AI analyst powered by Ollama. No SaaS subscriptions, no telemetry, no API bills. Runs entirely on your machine.

---

## Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.12+ | [python.org](https://www.python.org/downloads/) |
| Git | any | [git-scm.com](https://git-scm.com/downloads) |
| Ollama | latest | [ollama.com](https://ollama.com/download) |

> **Windows users:** During Python install, check **"Add Python to PATH"**.

---

## Quickstart

```bat
:: 1. Clone
git clone https://github.com/zacharyloganhill/threatpulse.git phantomfeed
cd phantomfeed

:: 2. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

:: 3. Install dependencies
pip install -r requirements.txt

:: 4. Configure
copy .env.example .env

:: 5. Pull an Ollama model (runs locally, one-time download ~2 GB)
ollama pull llama3.2

:: 6. Start PhantomFeed
python main.py
```

Then open **http://localhost:8000/dashboard.html** in your browser.

On first run, all feeds are polled immediately. The statusbar shows **● CONNECTED** when the API is live and **● AI: llama3.2** when Ollama is detected.

> **Optional:** Add API keys to `.env` for higher rate limits (see [Environment Variables](#environment-variables)).

---

## Feeds Ingested

### Vulnerability Intelligence

| Feed | Source | Interval | Notes |
|------|--------|----------|-------|
| NVD CVE API v2 | nvd.nist.gov | 15 min | Full CVSS, CPE, CWE metadata |
| CISA KEV | cisa.gov | 15 min | Actively exploited CVEs only |
| CISA Cyber Advisories | github.com/cisagov | 60 min | CSAF/IT — joint advisories, BODs |
| CISA ICS Advisories | github.com/cisagov | 60 min | CSAF/OT — SCADA, ICS, OT systems |

### Vendor Security Advisories

| Feed | Vendor | Source |
|------|--------|--------|
| Microsoft MSRC | Microsoft | msrc.microsoft.com |
| Cisco Security | Cisco | sec.cloudapps.cisco.com |
| Fortinet PSIRT | Fortinet | fortiguard.com |
| Palo Alto Networks | Palo Alto | security.paloaltonetworks.com |
| Red Hat Security | Red Hat | access.redhat.com |
| Ubuntu Security | Canonical | ubuntu.com |

### Threat Intelligence & Malware

| Feed | Source | Notes |
|------|--------|-------|
| abuse.ch URLhaus | urlhaus-api.abuse.ch | Live malware URLs and C2 infrastructure |
| abuse.ch Feodo Tracker | feodotracker.abuse.ch | Botnet C2 IP blocklist |
| AlienVault OTX | otx.alienvault.com | Threat pulses (free API key required) |

### Supply Chain

| Feed | Source | Notes |
|------|--------|-------|
| GitHub Advisory (npm) | github.com/advisories | Node.js package vulnerabilities |
| GitHub Advisory (PyPI) | github.com/advisories | Python package vulnerabilities |

---

## REST API

Base URL: `http://localhost:8000/api/v1`
Interactive docs: `http://localhost:8000/docs`

### Endpoints

```
GET    /items                  List items — filterable, searchable, paginated
GET    /items/{id}             Get a single item by ID
POST   /items/{id}/read        Mark item as read
POST   /items/read-all         Mark all items as read
GET    /stats                  Counts by severity, feed, and new/total
GET    /feeds                  List all registered feed IDs
POST   /refresh                Trigger immediate poll of all feeds
POST   /refresh/{feed_id}      Trigger poll of one specific feed
DELETE /items/purge            Delete items older than retention period
```

### Ollama Proxy

```
GET|POST  /api/ollama/{path}   Proxies to http://localhost:11434/{path}
```

Eliminates CORS issues between the dashboard and Ollama. The proxy streams responses so chat completions render token-by-token.

### Query Parameters for `GET /items`

| Param | Example | Description |
|-------|---------|-------------|
| `severity` | `CRITICAL,HIGH` | Comma-separated severity filter |
| `category` | `cve` | `cve` · `kev` · `advisory` · `vendor` · `ics` · `threat` · `malware` · `supply` |
| `feed_id` | `nvd` | Filter to a single source |
| `is_new` | `true` | Unread items only |
| `search` | `ivanti` | Full-text search: title, description, vendor, tags |
| `limit` | `50` | Page size (max 500) |
| `offset` | `0` | Pagination offset |

### Example curl Commands

```bash
# New critical and high items
curl "http://localhost:8000/api/v1/items?severity=CRITICAL,HIGH&is_new=true"

# Search for Ivanti
curl "http://localhost:8000/api/v1/items?search=ivanti"

# All ICS/OT advisories
curl "http://localhost:8000/api/v1/items?category=ics"

# CISA KEV only
curl "http://localhost:8000/api/v1/items?feed_id=cisa_kev"

# Force an immediate refresh of all feeds
curl -X POST "http://localhost:8000/api/v1/refresh"

# Stats
curl "http://localhost:8000/api/v1/stats"

# Check available Ollama models via proxy
curl "http://localhost:8000/api/ollama/api/tags"
```

---

## Quick Actions (AI Analyst)

Each item in the dashboard has four **Quick Actions** that send a pre-built prompt to your local Ollama model:

| Action | What it produces |
|--------|-----------------|
| **Draft Client Advisory** | Non-technical advisory email ready to send to affected clients |
| **Generate Detection Rules** | Splunk SPL, Microsoft Sentinel KQL, and a Sigma rule |
| **Get IOCs & Hunting Queries** | File hashes, IPs, domains, registry keys, YARA snippets |
| **Analyze Client Impact** | Exposure assessment questions and at-risk asset types |

Responses stream in real-time in the AI panel. Everything runs locally via Ollama — **zero cost, zero data sent externally.**

---

## Architecture

```
phantomfeed/
├── main.py                  # FastAPI app, lifespan, CORS, Ollama proxy, static files
├── config.py                # Feed URLs, API keys, severity mappings, settings
├── dashboard.html           # Dark-mode web dashboard (served at /dashboard.html)
├── .env                     # Your local secrets — never commit this
├── .env.example             # Template — copy to .env to get started
├── requirements.txt
│
├── db/
│   └── database.py          # Async SQLite: connect, CRUD, deduplication
│
├── ingest/
│   ├── base.py              # BaseFetcher: HTTP helpers, retries, normalization
│   ├── nvd.py               # NVD CVE API v2
│   ├── cisa.py              # CISA KEV + CSAF advisories (IT + OT)
│   ├── rss_feeds.py         # Generic vendor RSS ingestion
│   ├── threat_intel.py      # abuse.ch, OTX, supply chain
│   └── scheduler.py         # APScheduler: per-feed poll intervals
│
└── api/
    └── routes.py            # All REST endpoints
```

### Adding a New Feed

1. Create a class in `ingest/` that inherits `BaseFetcher`
2. Set `feed_id`, `feed_label`, `category`, and `poll_interval`
3. Implement `async def fetch(self) -> list[dict]`
4. Register it in `ingest/scheduler.py` → `_build_fetchers()`

For simple RSS sources, just add an entry to `VENDOR_RSS_FEEDS` in `config.py` — no code required.

---

## Environment Variables

Copy `.env.example` to `.env` and set values as needed. All variables are optional except the server defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(empty)* | NVD API key — [get one free](https://nvd.nist.gov/developers/request-an-api-key). Raises rate limit from 5 to 50 req/30s |
| `OTX_API_KEY` | *(empty)* | AlienVault OTX key — [get one free](https://otx.alienvault.com). Required for OTX pulses |
| `URLHAUS_API_KEY` | *(empty)* | abuse.ch key — [get one free](https://auth.abuse.ch/). Increases URLhaus access |
| `POLL_INTERVAL_FAST` | `15` | Polling interval for high-priority feeds (minutes) |
| `POLL_INTERVAL_SLOW` | `60` | Polling interval for vendor/intel feeds (minutes) |
| `HOST` | `127.0.0.1` | API bind address |
| `PORT` | `8000` | API port |
| `DB_PATH` | `./phantomfeed.db` | SQLite database file path |
| `RETENTION_DAYS` | `90` | Days of history to retain before purge |
| `NVD_PAGE_SIZE` | `200` | CVEs fetched per NVD API page (max 2000) |

---

## Contributing

PRs and issues are welcome. If you add a new feed source, fix a parser, or improve the dashboard — open a pull request. If a feed is broken or returning bad data, open an issue with the feed ID and a sample of what you're seeing.

---

## License

MIT — do whatever you want with it.
