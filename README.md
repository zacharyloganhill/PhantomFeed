# HexIntel

Real-time threat intelligence aggregation platform. Ingests CVEs, vendor advisories, CISA KEV, ICS alerts, threat actor reports, and supply chain warnings into a unified SQLite database with a REST API and AI-assisted local dashboard.

## Architecture

```
hexintel/
├── main.py                  # FastAPI app, lifespan, CORS, Ollama proxy
├── config.py                # All feed URLs, API keys, settings
├── dashboard.html           # Local web dashboard (served at /dashboard.html)
├── .env                     # Your local secrets (never commit)
├── requirements.txt
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

## Setup (Windows)

### 1. Install Python 3.11+

Download and install from [python.org](https://www.python.org/downloads/). During install, check **"Add Python to PATH"**.

Verify:
```
python --version
```

### 2. Clone the repo

```
git clone https://github.com/zacharyloganhill/threatpulse.git hexintel
cd hexintel
```

### 3. Create and activate a virtual environment

```
python -m venv .venv
.venv\Scripts\activate
```

### 4. Install dependencies

```
pip install -r requirements.txt
```

### 5. Configure environment

```
copy .env.example .env
```

Open `.env` and fill in any API keys (both are optional — see [API Keys](#api-keys-optional-but-recommended) below).

### 6. Install Ollama and pull a model

Ollama powers the AI analyst panel in the dashboard. It runs entirely locally.

1. Download and install Ollama from [ollama.com](https://ollama.com/download)
2. After install, open a terminal and pull a model:

```
ollama pull llama3.2
```

3. Confirm Ollama is running:

```
ollama list
```

You should see `llama3.2:latest` in the output. Ollama runs as a background service on `http://localhost:11434` — leave it running while using HexIntel.

> **Note:** The dashboard proxies AI requests through `/api/ollama` to avoid CORS issues. Ollama does **not** need to be publicly accessible — `localhost:11434` is sufficient.

### 7. Run HexIntel

With your venv active:

```
python main.py
```

On first startup, the engine polls all feeds immediately, then continues on schedule. You will see ingestion progress in the terminal.

### 8. Open the dashboard

```
http://localhost:8000/dashboard.html
```

- The statusbar shows **● CONNECTED** when the API is reachable and **● AI: llama3.2** when Ollama is detected.
- Use the **Quick Actions** buttons in any item's detail pane to send AI prompts.
- Hit **↺ REFRESH** to trigger an immediate feed poll.

---

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

---

## Feeds Ingested

### Vulnerability Intelligence
| Feed | Source | Interval |
|------|--------|----------|
| NVD CVE API v2 | nvd.nist.gov | 15 min |
| CISA KEV | cisa.gov | 15 min |
| CISA Advisories | cisa.gov | 60 min |
| CISA ICS | cisa.gov | 60 min |

### Vendor Security Advisories
| Feed | Source |
|------|--------|
| Microsoft MSRC | msrc.microsoft.com |
| Cisco Security | sec.cloudapps.cisco.com |
| Fortinet PSIRT | fortiguard.com |
| Palo Alto Networks | security.paloaltonetworks.com |
| Broadcom / VMware | vmware.com |
| Red Hat | access.redhat.com |
| Ubuntu / Canonical | ubuntu.com |
| SAP | sap.com |
| Atlassian | atlassian.com |
| F5 | support.f5.com |

### Threat Intelligence
| Feed | Source |
|------|--------|
| abuse.ch URLhaus | urlhaus-api.abuse.ch |
| AlienVault OTX | otx.alienvault.com |
| GitHub Advisory (npm) | github.com/advisories |
| GitHub Advisory (PyPI) | github.com/advisories |

---

## REST API

Base URL: `http://localhost:8000/api/v1`
Interactive docs: `http://localhost:8000/docs`

### Endpoints

```
GET  /items                      List items (filterable, searchable, paginated)
GET  /items/{id}                 Get single item
POST /items/{id}/read            Mark as read
POST /items/read-all             Mark all as read
GET  /stats                      Counts, feed breakdown, ingestion status
GET  /feeds                      List all registered feed IDs
POST /refresh                    Trigger immediate poll of all feeds
POST /refresh/{feed_id}          Trigger poll of one specific feed
DELETE /items/purge              Remove items older than retention period
```

### Ollama Proxy

```
GET|POST /api/ollama/{path}      Proxies to http://localhost:11434/{path}
```

The dashboard uses this to reach Ollama without CORS issues. You can also hit it directly:

```bash
curl http://localhost:8000/api/ollama/api/tags
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
# New critical/high items
curl "http://localhost:8000/api/v1/items?severity=CRITICAL,HIGH&is_new=true"

# Search for Ivanti
curl "http://localhost:8000/api/v1/items?search=ivanti"

# All ICS/OT advisories
curl "http://localhost:8000/api/v1/items?category=ics"

# Force immediate refresh
curl -X POST "http://localhost:8000/api/v1/refresh"

# Check stats
curl "http://localhost:8000/api/v1/stats"
```

---

## Database Schema

SQLite file at `./hexintel.db` (configurable via `DB_PATH` in `.env`).

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

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | `` | NVD API key (optional) |
| `OTX_API_KEY` | `` | AlienVault OTX key (optional) |
| `POLL_INTERVAL_FAST` | `15` | Fast feed interval (minutes) |
| `POLL_INTERVAL_SLOW` | `60` | Slow feed interval (minutes) |
| `HOST` | `127.0.0.1` | API bind address |
| `PORT` | `8000` | API port |
| `DB_PATH` | `./hexintel.db` | SQLite file location |
| `RETENTION_DAYS` | `90` | Days before old items are purged |
| `NVD_PAGE_SIZE` | `200` | CVEs per NVD API page |

---

## Adding New Feeds

1. Create a class in `ingest/` that inherits `BaseFetcher`
2. Set `feed_id`, `feed_label`, `category`, `poll_interval`
3. Implement `async def fetch(self) -> list[dict]`
4. Register it in `ingest/scheduler.py` → `_build_fetchers()`

For RSS feeds, add an entry to `VENDOR_RSS_FEEDS` in `config.py` — no code needed.
