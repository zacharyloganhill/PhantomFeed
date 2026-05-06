# ThreatPulse Intelligence Feed

Real-time threat intelligence aggregation backend. Ingests CVEs, vendor advisories, CISA KEV, ICS alerts, threat actor reports, and supply chain warnings into a unified SQLite database with a REST API.

## Architecture

```
threatpulse/
├── main.py                  # FastAPI app, lifespan, CORS
├── config.py                # All feed URLs, API keys, settings
├── .env                     # Your local secrets (never commit)
├── requirements.txt
├── setup.sh                 # One-command setup
│
├── db/
│   └── database.py          # Async SQLite: connect, CRUD, deduplication
│
├── ingest/
│   ├── base.py              # BaseFetcher: HTTP, retries, helpers
│   ├── nvd.py               # NVD CVE API v2
│   ├── cisa.py              # CISA KEV + Advisories + ICS
│   ├── rss_feeds.py         # All vendor RSS feeds (generic)
│   ├── threat_intel.py      # abuse.ch, OTX, supply chain
│   └── scheduler.py         # APScheduler: poll on interval
│
└── api/
    └── routes.py            # GET /items, POST /refresh, etc.
```

## Quickstart

```bash
git clone <this-repo>
cd threatpulse
chmod +x setup.sh && ./setup.sh
source .venv/bin/activate
python main.py
```

On startup the engine polls all feeds immediately, then continues polling on schedule.

## API Keys (Optional but Recommended)

| Key | Where to get | Benefit |
|-----|-------------|---------|
| `NVD_API_KEY` | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) | 50 req/30s vs 5 req/30s |
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) | Threat pulse subscriptions |

Add to `.env`:
```
NVD_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

## Feeds Ingested

### Vulnerability Intelligence
| Feed | Source | Interval | Notes |
|------|--------|----------|-------|
| NVD CVE API v2 | nvd.nist.gov | 15 min | Full CVSS, CPE, CWE metadata |
| CISA KEV | cisa.gov | 15 min | Actively exploited CVEs |
| CISA Advisories | cisa.gov | 60 min | AA## joint advisories, BODs |
| CISA ICS | cisa.gov | 60 min | OT/SCADA specific |

### Vendor Security Advisories
| Feed | Source | Notes |
|------|--------|-------|
| Microsoft MSRC | msrc.microsoft.com | Patch Tuesday + OOB |
| Cisco Security | sec.cloudapps.cisco.com | IOS, NX-OS, FTD, ASA |
| Fortinet PSIRT | fortiguard.com | FortiOS, FortiProxy, FortiGate |
| Palo Alto Networks | security.paloaltonetworks.com | PAN-OS, GlobalProtect |
| Broadcom / VMware | vmware.com | ESXi, vCenter, NSX |
| Red Hat | access.redhat.com | RHEL, OpenShift |
| Ubuntu / Canonical | ubuntu.com | USN advisories |
| SAP | sap.com | NetWeaver, HANA, S/4HANA |
| Atlassian | atlassian.com | Jira, Confluence, Bitbucket |
| F5 | support.f5.com | BIG-IP, NGINX |

### Threat Intelligence
| Feed | Source | Notes |
|------|--------|-------|
| abuse.ch URLhaus | urlhaus-api.abuse.ch | Live malware URLs / C2 |
| AlienVault OTX | otx.alienvault.com | Threat pulses (API key required) |
| GitHub Advisory (npm) | github.com/advisories | Supply chain: Node.js packages |
| GitHub Advisory (PyPI) | github.com/advisories | Supply chain: Python packages |

## REST API

Base URL: `http://localhost:8000/api/v1`  
Interactive docs: `http://localhost:8000/docs`

### Endpoints

```
GET  /items                      List items (filterable, searchable, paginated)
GET  /items/{id}                 Get single item
POST /items/{id}/read            Mark as read
POST /items/read-all             Mark all as read (optionally by feed)
GET  /stats                      Counts, feed breakdown, ingestion status
GET  /feeds                      List all registered feed IDs
POST /refresh                    Trigger immediate poll of all feeds
POST /refresh/{feed_id}          Trigger poll of one specific feed
DELETE /items/purge              Remove items older than retention period
```

### Query Parameters for `/items`

| Param | Example | Description |
|-------|---------|-------------|
| `severity` | `CRITICAL,HIGH` | Comma-separated severity filter |
| `category` | `cve` | Feed category filter |
| `feed_id` | `nvd` | Filter to one source |
| `is_new` | `true` | Only unread items |
| `search` | `ivanti` | Search title, desc, vendor, tags |
| `limit` | `50` | Page size (max 500) |
| `offset` | `0` | Pagination offset |

### Example Requests

```bash
# New critical/high items today
curl "http://localhost:8000/api/v1/items?severity=CRITICAL,HIGH&is_new=true"

# Search for anything Ivanti
curl "http://localhost:8000/api/v1/items?search=ivanti"

# All ICS/OT advisories
curl "http://localhost:8000/api/v1/items?category=ics"

# Force an immediate refresh
curl -X POST "http://localhost:8000/api/v1/refresh"

# Check stats
curl "http://localhost:8000/api/v1/stats"
```

## Database Schema

SQLite file at `./threatpulse.db` (configurable via `DB_PATH` in `.env`).

```sql
CREATE TABLE threat_items (
    id            TEXT PRIMARY KEY,      -- SHA-256 hash of feed+title+date
    feed_id       TEXT NOT NULL,         -- e.g. 'nvd', 'cisa_kev', 'msrc'
    feed_label    TEXT NOT NULL,         -- Human readable feed name
    category      TEXT NOT NULL,         -- cve, kev, advisory, vendor, ics, ...
    severity      TEXT NOT NULL,         -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss          REAL,                  -- CVSS base score if available
    title         TEXT NOT NULL,
    vendor        TEXT,
    product       TEXT,
    description   TEXT,
    url           TEXT,
    published_at  TEXT,                  -- ISO date YYYY-MM-DD
    fetched_at    TEXT NOT NULL,         -- UTC timestamp
    tags          TEXT,                  -- JSON array
    cve_ids       TEXT,                  -- JSON array of CVE IDs
    is_new        INTEGER DEFAULT 1,     -- 1 = unseen, 0 = read
    is_read       INTEGER DEFAULT 0,
    raw           TEXT                   -- JSON of source-specific data
);
```

## Connecting the Frontend Dashboard

The dashboard widget can call this API directly. Update the widget to fetch from:
```
GET http://localhost:8000/api/v1/items?severity=CRITICAL,HIGH&limit=50
```

Or use the Claude-powered dashboard to draft client advisories using the detail pane's "Quick Actions" which pass items directly to Claude for:
- Client advisory drafting
- Detection rule generation (SIEM/EDR)
- IOC extraction and threat hunting queries

## Adding New Feeds

1. Create a class in `ingest/` that inherits `BaseFetcher`
2. Set `feed_id`, `feed_label`, `category`, `poll_interval`
3. Implement `async def fetch(self) -> list[dict]`
4. Register it in `ingest/scheduler.py` → `_build_fetchers()`

For RSS feeds, just add an entry to `VENDOR_RSS_FEEDS` in `config.py` — no code needed.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | `` | NVD API key (optional) |
| `OTX_API_KEY` | `` | AlienVault OTX key (optional) |
| `POLL_INTERVAL_FAST` | `15` | Fast feed interval (minutes) |
| `POLL_INTERVAL_SLOW` | `60` | Slow feed interval (minutes) |
| `HOST` | `127.0.0.1` | API bind address |
| `PORT` | `8000` | API port |
| `DB_PATH` | `./threatpulse.db` | SQLite file location |
| `RETENTION_DAYS` | `90` | Days before old items are purged |
| `NVD_PAGE_SIZE` | `200` | CVEs per NVD API page |
