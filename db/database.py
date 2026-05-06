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
    id            TEXT PRIMARY KEY,
    feed_id       TEXT NOT NULL,
    feed_label    TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'INFO',
    cvss          REAL,
    title         TEXT NOT NULL,
    vendor        TEXT,
    product       TEXT,
    description   TEXT,
    url           TEXT,
    published_at  TEXT,
    fetched_at    TEXT NOT NULL,
    tags          TEXT DEFAULT '[]',
    cve_ids       TEXT DEFAULT '[]',
    is_new        INTEGER DEFAULT 1,
    is_read       INTEGER DEFAULT 0,
    raw           TEXT
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
    for idx in CREATE_INDEXES:
        await _db.execute(idx)
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
         tags, cve_ids, is_new, is_read, raw)
    VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?)
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
    )
    cursor = await db.execute(sql, params)
    await db.commit()
    return cursor.rowcount > 0


async def get_items(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    feed_id: Optional[str] = None,
    is_new: Optional[bool] = None,
    search: Optional[str] = None,
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

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT * FROM threat_items
        {where}
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH'     THEN 2
                WHEN 'MEDIUM'   THEN 3
                WHEN 'LOW'      THEN 4
                ELSE 5
            END,
            published_at DESC
        LIMIT ? OFFSET ?
    """
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


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("tags", "cve_ids", "raw"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    d["is_new"] = bool(d.get("is_new"))
    d["is_read"] = bool(d.get("is_read"))
    return d
