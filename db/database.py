"""
ThreatPulse — Database Layer
Async SQLite via aiosqlite. Single table with full-text search support.
"""

import json
import hashlib
import aiosqlite
from datetime import datetime, timedelta
from typing import Optional

import config

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS threat_items (
    id              TEXT PRIMARY KEY,
    feed_id         TEXT NOT NULL,
    feed_label      TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'INFO',
    cvss            REAL,
    title           TEXT NOT NULL,
    vendor          TEXT,
    product         TEXT,
    description     TEXT,
    url             TEXT,
    published_at    TEXT,
    fetched_at      TEXT NOT NULL,
    tags            TEXT DEFAULT '[]',
    cve_ids         TEXT DEFAULT '[]',
    is_new          INTEGER DEFAULT 1,
    is_read         INTEGER DEFAULT 0,
    raw             TEXT,
    risk_score      REAL,
    compliance_tags TEXT DEFAULT '[]'
);
"""

MIGRATIONS = [
    "ALTER TABLE threat_items ADD COLUMN risk_score REAL;",
    "ALTER TABLE threat_items ADD COLUMN compliance_tags TEXT DEFAULT '[]';",
]

CREATE_CLIENTS_TABLE = """
CREATE TABLE IF NOT EXISTS clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    contact_email TEXT,
    stack_profile TEXT DEFAULT '{}',
    created_at    TEXT NOT NULL
);
"""

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    client_id     TEXT,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_TAXII_STATE = """
CREATE TABLE IF NOT EXISTS taxii_state (
    feed_id TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""

CREATE_CLIENT_ASSETS = """
CREATE TABLE IF NOT EXISTS client_assets (
    id          TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    hostname    TEXT,
    ip_address  TEXT,
    os          TEXT,
    os_version  TEXT,
    software    TEXT NOT NULL,
    version     TEXT,
    cpe_string  TEXT,
    asset_type  TEXT DEFAULT 'workstation',
    created_at  TEXT,
    updated_at  TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_ASSET_EXPOSURES = """
CREATE TABLE IF NOT EXISTS asset_exposures (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    asset_id     TEXT NOT NULL,
    match_type   TEXT,
    confidence   REAL,
    confirmed_at TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (item_id)   REFERENCES threat_items(id),
    FOREIGN KEY (asset_id)  REFERENCES client_assets(id)
);
"""

CREATE_REMEDIATION = """
CREATE TABLE IF NOT EXISTS remediation_items (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    status       TEXT DEFAULT 'open',
    priority     INTEGER DEFAULT 0,
    assigned_to  TEXT,
    due_date     TEXT,
    patched_date TEXT,
    notes        TEXT,
    created_at   TEXT,
    updated_at   TEXT,
    sla_days     INTEGER,
    is_overdue   INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (item_id)   REFERENCES threat_items(id)
);
"""

CREATE_IOC_CACHE = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    ioc_value                TEXT PRIMARY KEY,
    ioc_type                 TEXT NOT NULL,
    abuseipdb_score          INTEGER,
    abuseipdb_country        TEXT,
    vt_malicious             INTEGER,
    vt_total                 INTEGER,
    vt_name                  TEXT,
    greynoise_classification TEXT,
    greynoise_name           TEXT,
    enriched_at              TEXT,
    expires_at               TEXT
);
"""

CREATE_WEBHOOK_CONFIGS = """
CREATE TABLE IF NOT EXISTS webhook_configs (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    webhook_type TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret       TEXT,
    min_severity TEXT DEFAULT 'HIGH',
    categories   TEXT DEFAULT '[]',
    is_active    INTEGER DEFAULT 1,
    last_fired   TEXT,
    created_at   TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
"""

CREATE_WEBHOOK_ERRORS = """
CREATE TABLE IF NOT EXISTS webhook_errors (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT NOT NULL,
    error        TEXT,
    created_at   TEXT
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_severity   ON threat_items(severity);",
    "CREATE INDEX IF NOT EXISTS idx_category   ON threat_items(category);",
    "CREATE INDEX IF NOT EXISTS idx_feed_id    ON threat_items(feed_id);",
    "CREATE INDEX IF NOT EXISTS idx_published  ON threat_items(published_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_fetched    ON threat_items(fetched_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_is_new     ON threat_items(is_new);",
]

_db: Optional[aiosqlite.Connection] = None


async def connect() -> aiosqlite.Connection:
    global _db
    _db = await aiosqlite.connect(config.DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL;")
    await _db.execute("PRAGMA foreign_keys=ON;")
    await _db.execute(CREATE_TABLE)
    await _db.execute(CREATE_CLIENTS_TABLE)
    await _db.execute(CREATE_USERS_TABLE)
    await _db.execute(CREATE_TAXII_STATE)
    await _db.execute(CREATE_CLIENT_ASSETS)
    await _db.execute(CREATE_ASSET_EXPOSURES)
    await _db.execute(CREATE_REMEDIATION)
    await _db.execute(CREATE_IOC_CACHE)
    await _db.execute(CREATE_WEBHOOK_CONFIGS)
    await _db.execute(CREATE_WEBHOOK_ERRORS)
    for idx in CREATE_INDEXES:
        await _db.execute(idx)
    # Additive migrations — silently ignore if column already exists
    for migration in MIGRATIONS:
        try:
            await _db.execute(migration)
        except Exception:
            pass
    await _db.execute(
        "CREATE INDEX IF NOT EXISTS idx_risk_score ON threat_items(risk_score DESC);"
    )
    await _db.commit()
    return _db


async def close():
    global _db
    if _db:
        await _db.close()
        _db = None


def get_db() -> aiosqlite.Connection:
    if _db is None:
        raise RuntimeError("Database not connected. Call connect() first.")
    return _db


def make_id(feed_id: str, title: str, published: str) -> str:
    """Deterministic ID for deduplication — same item always gets same ID."""
    raw = f"{feed_id}:{title.lower().strip()}:{published}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


async def upsert_item(item: dict) -> bool:
    """
    Insert or ignore a threat item. Returns True if it was a new insertion.
    We never update existing items — the original fetch is canonical.
    """
    db = get_db()
    item_id = item.get("id") or make_id(
        item["feed_id"], item["title"], item.get("published_at", "")
    )
    now = datetime.utcnow().isoformat()

    sql = """
    INSERT OR IGNORE INTO threat_items
        (id, feed_id, feed_label, category, severity, cvss, title,
         vendor, product, description, url, published_at, fetched_at,
         tags, cve_ids, is_new, is_read, raw, risk_score, compliance_tags)
    VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?,?,?)
    """
    params = (
        item_id,
        item.get("feed_id", ""),
        item.get("feed_label", ""),
        item.get("category", "advisory"),
        item.get("severity", "INFO"),
        item.get("cvss"),
        item.get("title", "(no title)"),
        item.get("vendor"),
        item.get("product"),
        item.get("description"),
        item.get("url"),
        item.get("published_at"),
        now,
        json.dumps(item.get("tags", [])),
        json.dumps(item.get("cve_ids", [])),
        json.dumps(item.get("raw")),
        item.get("risk_score"),
        json.dumps(item.get("compliance_tags", [])),
    )
    cursor = await db.execute(sql, params)
    await db.commit()
    return cursor.rowcount > 0


async def update_risk_score(item_id: str, risk_score: float):
    """Update risk_score for an existing item (rescore endpoint)."""
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET risk_score = ? WHERE id = ?",
        (risk_score, item_id),
    )
    await db.commit()


async def update_compliance_tags(item_id: str, tags: list[str]):
    """Update compliance_tags for an existing item."""
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET compliance_tags = ? WHERE id = ?",
        (json.dumps(tags), item_id),
    )
    await db.commit()


async def get_items(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    feed_id: Optional[str] = None,
    is_new: Optional[bool] = None,
    search: Optional[str] = None,
    compliance: Optional[str] = None,
    client_id: Optional[str] = None,
    sort: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    db = get_db()
    conditions = []
    params = []

    if severity:
        sevs = [s.strip().upper() for s in severity.split(",")]
        placeholders = ",".join("?" * len(sevs))
        conditions.append(f"severity IN ({placeholders})")
        params.extend(sevs)
    if category:
        conditions.append("category = ?")
        params.append(category)
    if feed_id:
        conditions.append("feed_id = ?")
        params.append(feed_id)
    if is_new is not None:
        conditions.append("is_new = ?")
        params.append(1 if is_new else 0)
    if search:
        conditions.append(
            "(title LIKE ? OR description LIKE ? OR vendor LIKE ? OR tags LIKE ? OR cve_ids LIKE ?)"
        )
        q = f"%{search}%"
        params.extend([q, q, q, q, q])
    if compliance:
        # compliance_tags is a JSON array; filter items that contain the tag
        tag = compliance.lower().strip()
        conditions.append("LOWER(compliance_tags) LIKE ?")
        params.append(f"%{tag}%")
    if client_id:
        # Reserved: filter by client stack profile (applied via apply_stack_filter)
        pass

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    if sort == "risk":
        order = "ORDER BY COALESCE(risk_score, 0) DESC, published_at DESC"
    else:
        order = """ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            published_at DESC"""

    sql = f"SELECT * FROM threat_items {where} {order} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    async with db.execute(sql, params) as cursor:
        rows = await cursor.fetchall()
    return [_row_to_dict(r) for r in rows]


async def get_item(item_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM threat_items WHERE id = ?", (item_id,)) as cur:
        row = await cur.fetchone()
    return _row_to_dict(row) if row else None


async def mark_read(item_id: str):
    db = get_db()
    await db.execute(
        "UPDATE threat_items SET is_read = 1, is_new = 0 WHERE id = ?", (item_id,)
    )
    await db.commit()


async def mark_all_read(feed_id: Optional[str] = None):
    db = get_db()
    if feed_id:
        await db.execute(
            "UPDATE threat_items SET is_read = 1, is_new = 0 WHERE feed_id = ?",
            (feed_id,),
        )
    else:
        await db.execute("UPDATE threat_items SET is_read = 1, is_new = 0")
    await db.commit()


async def get_stats() -> dict:
    db = get_db()
    stats = {}

    # Counts by severity
    async with db.execute(
        "SELECT severity, COUNT(*) as cnt FROM threat_items GROUP BY severity"
    ) as cur:
        stats["by_severity"] = {r["severity"]: r["cnt"] for r in await cur.fetchall()}

    # Counts by category
    async with db.execute(
        "SELECT category, COUNT(*) as cnt FROM threat_items GROUP BY category"
    ) as cur:
        stats["by_category"] = {r["category"]: r["cnt"] for r in await cur.fetchall()}

    # Counts by feed
    async with db.execute(
        "SELECT feed_id, feed_label, COUNT(*) as cnt FROM threat_items GROUP BY feed_id"
    ) as cur:
        stats["by_feed"] = [
            {"feed_id": r["feed_id"], "label": r["feed_label"], "count": r["cnt"]}
            for r in await cur.fetchall()
        ]

    # New / unread
    async with db.execute("SELECT COUNT(*) as cnt FROM threat_items WHERE is_new = 1") as cur:
        stats["new_count"] = (await cur.fetchone())["cnt"]

    async with db.execute("SELECT COUNT(*) as cnt FROM threat_items") as cur:
        stats["total"] = (await cur.fetchone())["cnt"]

    # Last ingested
    async with db.execute("SELECT MAX(fetched_at) as last FROM threat_items") as cur:
        stats["last_ingested"] = (await cur.fetchone())["last"]

    return stats


async def purge_old_items():
    """Remove items older than RETENTION_DAYS."""
    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(days=config.RETENTION_DAYS)).isoformat()
    cursor = await db.execute(
        "DELETE FROM threat_items WHERE published_at < ? AND is_new = 0", (cutoff,)
    )
    await db.commit()
    return cursor.rowcount


# ── Client CRUD ───────────────────────────────────────────────────────────────

async def create_client(name: str, contact_email: str = "", stack_profile: dict = None) -> dict:
    import uuid
    db = get_db()
    client_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO clients (id, name, contact_email, stack_profile, created_at) VALUES (?,?,?,?,?)",
        (client_id, name, contact_email, json.dumps(stack_profile or {}), now),
    )
    await db.commit()
    return {"id": client_id, "name": name, "contact_email": contact_email,
            "stack_profile": stack_profile or {}, "created_at": now}


async def get_clients() -> list[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM clients ORDER BY created_at DESC") as cur:
        rows = await cur.fetchall()
    return [_client_row(r) for r in rows]


async def get_client(client_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)) as cur:
        row = await cur.fetchone()
    return _client_row(row) if row else None


async def update_client(client_id: str, name: str = None, contact_email: str = None,
                        stack_profile: dict = None) -> Optional[dict]:
    db = get_db()
    sets, params = [], []
    if name is not None:
        sets.append("name = ?"); params.append(name)
    if contact_email is not None:
        sets.append("contact_email = ?"); params.append(contact_email)
    if stack_profile is not None:
        sets.append("stack_profile = ?"); params.append(json.dumps(stack_profile))
    if not sets:
        return await get_client(client_id)
    params.append(client_id)
    await db.execute(f"UPDATE clients SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_client(client_id)


async def delete_client(client_id: str):
    db = get_db()
    await db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    await db.commit()


def _client_row(row) -> dict:
    d = dict(row)
    if d.get("stack_profile"):
        try:
            d["stack_profile"] = json.loads(d["stack_profile"])
        except Exception:
            d["stack_profile"] = {}
    return d


# ── User CRUD ─────────────────────────────────────────────────────────────────

async def create_user(username: str, password_hash: str, role: str = "analyst",
                      client_id: str = None) -> dict:
    import uuid
    db = get_db()
    user_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        "INSERT INTO users (id, username, password_hash, role, client_id, created_at) VALUES (?,?,?,?,?,?)",
        (user_id, username, password_hash, role, client_id, now),
    )
    await db.commit()
    return {"id": user_id, "username": username, "role": role,
            "client_id": client_id, "created_at": now}


async def get_user_by_username(username: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


# ── Asset CRUD ────────────────────────────────────────────────────────────────

async def upsert_asset(client_id: str, software: str, version: str = "",
                       hostname: str = "", ip_address: str = "",
                       os: str = "", os_version: str = "",
                       cpe_string: str = "", asset_type: str = "workstation") -> str:
    import uuid
    db = get_db()
    asset_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO client_assets
           (id, client_id, hostname, ip_address, os, os_version, software, version, cpe_string, asset_type, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (asset_id, client_id, hostname, ip_address, os, os_version, software, version, cpe_string, asset_type, now, now),
    )
    await db.commit()
    return asset_id


async def get_assets(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM client_assets WHERE client_id = ? ORDER BY software", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def delete_asset(asset_id: str):
    db = get_db()
    await db.execute("DELETE FROM client_assets WHERE id = ?", (asset_id,))
    await db.execute("DELETE FROM asset_exposures WHERE asset_id = ?", (asset_id,))
    await db.commit()


async def get_all_assets_for_matching() -> list[dict]:
    """Return all assets grouped by client for CPE matching."""
    db = get_db()
    async with db.execute("SELECT * FROM client_assets") as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def upsert_exposure(client_id: str, item_id: str, asset_id: str,
                           match_type: str, confidence: float) -> str:
    import uuid
    db = get_db()
    # deduplicate on (item_id, asset_id)
    async with db.execute(
        "SELECT id FROM asset_exposures WHERE item_id = ? AND asset_id = ?",
        (item_id, asset_id),
    ) as cur:
        existing = await cur.fetchone()
    if existing:
        return existing[0]
    exp_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO asset_exposures (id, client_id, item_id, asset_id, match_type, confidence, confirmed_at)
           VALUES (?,?,?,?,?,?,?)""",
        (exp_id, client_id, item_id, asset_id, match_type, confidence, now),
    )
    await db.commit()
    return exp_id


async def get_exposures_for_item(item_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        """SELECT ae.*, ca.hostname, ca.software, ca.version, ca.ip_address
           FROM asset_exposures ae
           JOIN client_assets ca ON ae.asset_id = ca.id
           WHERE ae.item_id = ?""",
        (item_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_exposed_item_ids(client_id: str) -> set[str]:
    db = get_db()
    async with db.execute(
        "SELECT DISTINCT item_id FROM asset_exposures WHERE client_id = ?", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return {r[0] for r in rows}


# ── Remediation CRUD ───────────────────────────────────────────────────────────

async def create_remediation(client_id: str, item_id: str, sla_days: int,
                              due_date: str, priority: int = 0) -> dict:
    import uuid
    db = get_db()
    # prevent duplicates
    async with db.execute(
        "SELECT id FROM remediation_items WHERE client_id = ? AND item_id = ?",
        (client_id, item_id),
    ) as cur:
        existing = await cur.fetchone()
    if existing:
        return {"id": existing[0], "exists": True}
    rem_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO remediation_items
           (id, client_id, item_id, status, priority, due_date, sla_days, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (rem_id, client_id, item_id, "open", priority, due_date, sla_days, now, now),
    )
    await db.commit()
    return {"id": rem_id, "exists": False, "due_date": due_date}


async def get_remediations(client_id: str, status: Optional[str] = None) -> list[dict]:
    db = get_db()
    if status:
        q = "SELECT * FROM remediation_items WHERE client_id = ? AND status = ? ORDER BY due_date"
        args = (client_id, status)
    else:
        q = "SELECT * FROM remediation_items WHERE client_id = ? ORDER BY due_date"
        args = (client_id,)
    async with db.execute(q, args) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def update_remediation(rem_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"status", "assigned_to", "notes", "patched_date", "priority", "is_overdue"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return None
    sets.append("updated_at = ?")
    params.append(datetime.utcnow().isoformat())
    params.append(rem_id)
    await db.execute(f"UPDATE remediation_items SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    async with db.execute("SELECT * FROM remediation_items WHERE id = ?", (rem_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def get_overdue_remediations() -> list[dict]:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    db = get_db()
    async with db.execute(
        "SELECT * FROM remediation_items WHERE status = 'open' AND due_date < ?", (today,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ── IOC Cache CRUD ────────────────────────────────────────────────────────────

async def get_ioc_cache(ioc_value: str) -> Optional[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM ioc_cache WHERE ioc_value = ?", (ioc_value,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    # Check expiry
    if d.get("expires_at") and d["expires_at"] < datetime.utcnow().isoformat():
        return None
    return d


async def upsert_ioc_cache(data: dict):
    db = get_db()
    await db.execute(
        """INSERT OR REPLACE INTO ioc_cache
           (ioc_value, ioc_type, abuseipdb_score, abuseipdb_country,
            vt_malicious, vt_total, vt_name,
            greynoise_classification, greynoise_name,
            enriched_at, expires_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data.get("ioc_value"), data.get("ioc_type"),
            data.get("abuseipdb_score"), data.get("abuseipdb_country"),
            data.get("vt_malicious"), data.get("vt_total"), data.get("vt_name"),
            data.get("greynoise_classification"), data.get("greynoise_name"),
            data.get("enriched_at"), data.get("expires_at"),
        ),
    )
    await db.commit()


async def list_ioc_cache(limit: int = 100) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM ioc_cache ORDER BY enriched_at DESC LIMIT ?", (limit,)
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ── Webhook CRUD ───────────────────────────────────────────────────────────────

async def create_webhook(client_id: str, webhook_type: str, url: str,
                          secret: str = "", min_severity: str = "HIGH",
                          categories: list = None) -> dict:
    import uuid
    db = get_db()
    wh_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    await db.execute(
        """INSERT INTO webhook_configs
           (id, client_id, webhook_type, url, secret, min_severity, categories, is_active, created_at)
           VALUES (?,?,?,?,?,?,?,1,?)""",
        (wh_id, client_id, webhook_type, url, secret, min_severity,
         json.dumps(categories or []), now),
    )
    await db.commit()
    return await get_webhook(wh_id)


async def get_webhooks(client_id: str) -> list[dict]:
    db = get_db()
    async with db.execute(
        "SELECT * FROM webhook_configs WHERE client_id = ? ORDER BY created_at", (client_id,)
    ) as cur:
        rows = await cur.fetchall()
    return [_wh_row(r) for r in rows]


async def get_webhook(wh_id: str) -> Optional[dict]:
    db = get_db()
    async with db.execute("SELECT * FROM webhook_configs WHERE id = ?", (wh_id,)) as cur:
        row = await cur.fetchone()
    return _wh_row(row) if row else None


async def update_webhook(wh_id: str, **fields) -> Optional[dict]:
    db = get_db()
    allowed = {"webhook_type", "url", "secret", "min_severity", "categories", "is_active", "last_fired"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(json.dumps(v) if k == "categories" else v)
    if not sets:
        return await get_webhook(wh_id)
    params.append(wh_id)
    await db.execute(f"UPDATE webhook_configs SET {', '.join(sets)} WHERE id = ?", params)
    await db.commit()
    return await get_webhook(wh_id)


async def delete_webhook(wh_id: str):
    db = get_db()
    await db.execute("DELETE FROM webhook_configs WHERE id = ?", (wh_id,))
    await db.commit()


async def get_active_webhooks_for_severity(severity: str, category: str) -> list[dict]:
    """Return all active webhooks that match this item's severity and category."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    item_sev = sev_order.get(severity, 4)
    db = get_db()
    async with db.execute("SELECT * FROM webhook_configs WHERE is_active = 1") as cur:
        rows = await cur.fetchall()
    result = []
    for row in rows:
        wh = _wh_row(row)
        min_sev = sev_order.get(wh.get("min_severity", "HIGH"), 1)
        if item_sev > min_sev:
            continue
        cats = wh.get("categories") or []
        if cats and category not in cats:
            continue
        result.append(wh)
    return result


def _wh_row(row) -> dict:
    d = dict(row)
    if d.get("categories"):
        try:
            d["categories"] = json.loads(d["categories"])
        except Exception:
            d["categories"] = []
    return d


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("tags", "cve_ids", "raw", "compliance_tags"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
        elif field == "compliance_tags":
            d[field] = []
    d["is_new"] = bool(d.get("is_new"))
    d["is_read"] = bool(d.get("is_read"))
    return d
