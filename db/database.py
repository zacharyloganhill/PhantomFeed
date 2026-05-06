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
