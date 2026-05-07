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

## Phase 2 Features

### Asset Inventory & Exposure Matching

Upload a CSV of client assets — PhantomFeed automatically matches incoming threat items to affected software using CPE strings, vendor/product tokens, and keyword matching:

```
POST /api/v1/admin/clients/{id}/assets/import    CSV upload
GET  /api/v1/admin/clients/{id}/assets           List all assets
GET  /api/v1/items?client_id={id}&exposed_only=true  Only matched items
```

**CSV format** (columns: `hostname`, `ip_address`, `os`, `os_version`, `software`, `version`, `cpe_string`, `asset_type`):
```csv
hostname,ip_address,os,os_version,software,version
srv01,10.0.0.1,Windows,2019,Microsoft Windows Server,2019
web01,10.0.0.2,Linux,Ubuntu 22.04,Apache HTTP Server,2.4.58
```

Confidence tiers: **1.0** exact CPE · **0.85** CPE prefix · **0.8** vendor+product · **0.7** vendor keyword · **0.5** vendor-only.

### TAXII 2.1 / STIX Ingestion

Polls TAXII 2.1 servers for STIX bundles. Incremental polling via stored `added_after` timestamps.

Pre-configured sources:
- **CISA AIS** — `https://ais2.cisa.dhs.gov/taxii2/` (requires cert — [register at cisa.gov/ais](https://www.cisa.gov/ais))
- **CIRCL MISP** — public OSINT feed
- **AlienVault OTX TAXII** — uses `OTX_API_KEY` as credential

Add `TAXII_USERNAME`, `TAXII_PASSWORD`, `TAXII_CERT_PATH` to `.env`. Fetchers skip gracefully when credentials missing.

```
GET  /api/v1/taxii/sources          List configured servers and connection status
POST /api/v1/taxii/test/{feed_id}   Test connection to a TAXII feed
```

### Remediation SLA Tracking

Track vulnerability remediation with per-client SLA deadlines:

| Severity | Default SLA |
|----------|-------------|
| CRITICAL | 15 days     |
| HIGH     | 30 days     |
| MEDIUM   | 90 days     |
| LOW      | 180 days    |

Override per client in `stack_profile`:
```json
{"sla": {"CRITICAL": 7, "HIGH": 14}}
```

```
GET    /api/v1/clients/{id}/remediation        List remediation items + days remaining
POST   /api/v1/clients/{id}/remediation        Create remediation item
PATCH  /api/v1/clients/{id}/remediation/{rid}  Update status (open/in_progress/patched/accepted_risk/false_positive/wont_fix)
GET    /api/v1/clients/{id}/metrics            MTTR, SLA compliance rate, open/overdue counts
```

SLA overdue check runs daily at 07:00 UTC.

### Analytics Dashboard

Visit **http://localhost:8000/analytics.html** for the executive analytics view:

- **Threat volume trend** — 90-day line chart by severity (CRITICAL/HIGH/MEDIUM)
- **Severity distribution** — doughnut chart
- **Top vendors** — horizontal bar chart by risk volume
- **Category breakdown** — stacked bar by category + severity
- **Remediation MTTR trend** — avg days to patch over time
- **Top risk items** — ranked by composite risk score

Client selector dropdown switches all charts to a specific client's view. Date range: 30 / 60 / 90 days.

### IOC Enrichment Engine

Automatically enriches IPs, domains, URLs, and file hashes from malware/threat feeds. Cached for 24 hours.

```
GET /api/v1/ioc/lookup?value=8.8.8.8      Live enrichment (IP/hash/domain/URL)
GET /api/v1/ioc/cache                      Recent cache entries
```

IOC Lookup widget is also built into the dashboard detail pane — type any value in the Quick Actions section.

| API Key | Source | Enriches |
|---------|--------|---------|
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | IP reputation score + country |
| `GREYNOISE_API_KEY` | [greynoise.io](https://www.greynoise.io) | IP classification (benign/malicious/unknown) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com) | Hash/domain/URL detection ratio |

### SIEM Webhook Push

Configure webhooks per client to push new threat items to your SIEM or alerting platform:

```
POST   /api/v1/admin/clients/{id}/webhooks           Create webhook
GET    /api/v1/admin/clients/{id}/webhooks            List webhooks  
PUT    /api/v1/admin/clients/{id}/webhooks/{wid}      Update
DELETE /api/v1/admin/clients/{id}/webhooks/{wid}      Delete
POST   /api/v1/admin/clients/{id}/webhooks/{wid}/test Send test payload
```

**Supported types:**

| Type | Format | Auth |
|------|--------|------|
| `generic` | Plain JSON body | — |
| `slack` | Block Kit attachment with severity color | Webhook URL |
| `splunk_hec` | `{time, sourcetype:"phantomfeed:threat", event:{...}}` | `Authorization: Splunk {token}` |
| `sentinel` | Azure Monitor Log Analytics, HMAC-SHA256 signed | `{workspace_id}:{workspace_key}` in secret |

**Example — Slack webhook:**
```bash
curl -X POST http://localhost:8000/api/v1/admin/clients/{id}/webhooks \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"webhook_type":"slack","url":"https://hooks.slack.com/T.../...","min_severity":"HIGH"}'
```

**Example — Splunk HEC:**
```bash
curl -X POST http://localhost:8000/api/v1/admin/clients/{id}/webhooks \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"webhook_type":"splunk_hec","url":"https://splunk:8088/services/collector","secret":"your-hec-token","min_severity":"CRITICAL"}'
```

---

## Upload & Export Center

Visit **http://localhost:8000/upload.html** for the full Upload & Export center.

### Supported Upload Formats

| Format | Extension | Parser |
|--------|-----------|--------|
| Nessus scan | `.nessus` | Auto-detected; extracts assets + findings per host |
| Qualys XML | `.xml` | `<HOST>` and `<VULN>` elements |
| Qualys CSV | `.csv` | QID, Title, Severity, CVE ID columns |
| OpenVAS XML | `.xml` | `<report>` root, `<result>` with `<nvt>` children |
| Rapid7/InsightVM CSV | `.csv` | Asset IP Address, Vulnerability Title, Severity columns |
| Generic CSV/XLSX | `.csv`, `.xlsx` | Fuzzy column mapping (auto-detects hostname/IP/severity/CVE columns) |
| IOC list (plain text) | `.txt` | One IOC per line; auto-detects IPs, hashes, domains, URLs |
| IOC list (JSON) | `.json` | Array of `{type, value}` or STIX 2.1 Indicator patterns |
| STIX 2.1 bundle | `.json` | Full bundle; imports Indicator, Malware, Threat-Actor, Vulnerability objects |
| Bulk clients | `.csv` | Columns: name, industry, contact_email, min_severity, vendors, products |

Download templates: `GET /api/v1/upload/templates/{assets|clients|iocs}`

### Upload API

```
POST /api/v1/upload/scan                  Auto-detect and preview scan file
POST /api/v1/upload/scan/{id}/confirm     Confirm and import (with optional field mapping)
POST /api/v1/upload/assets                Preview asset CSV/XLSX
POST /api/v1/upload/assets/{id}/confirm   Confirm asset import
POST /api/v1/upload/iocs                  Import IOC list (enrichment triggered in background)
POST /api/v1/upload/stix                  Import STIX 2.1 bundle directly
POST /api/v1/upload/clients               Bulk client preview
POST /api/v1/upload/clients/{id}/confirm  Confirm bulk client import
GET  /api/v1/upload/history               Upload log (filter by client_id)
GET  /api/v1/upload/templates/{type}      Download CSV template
```

### Export API

```
GET /api/v1/export/items.csv             Threat items as CSV (severity, category, search, days filters)
GET /api/v1/export/items.json            Threat items as JSON
GET /api/v1/export/iocs.txt?days=7       IOC plain text list
GET /api/v1/export/iocs.csv?days=7       IOC list as CSV with enrichment data
GET /api/v1/export/iocs.stix?days=7      IOC list as STIX 2.1 Bundle JSON
GET /api/v1/clients/{id}/export/remediation.csv   Remediation tracker CSV
GET /api/v1/clients/{id}/export/remediation.xlsx  Remediation tracker XLSX (color-coded)
GET /api/v1/clients/{id}/export/detection-rules.zip  SPL + KQL + Sigma ZIP
POST /api/v1/clients/{id}/export/push-rules-github   Push rules to GitHub repo
GET /api/v1/clients/{id}/report.html?days=30  HTML report preview with Download PDF button
```

**Detection Rules ZIP** contains:
- `splunk/` — Splunk SPL searches per CRITICAL/HIGH item
- `sentinel/` — Microsoft Sentinel KQL queries
- `sigma/` — Sigma YAML rules (convert with sigmac or pySigma)

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
