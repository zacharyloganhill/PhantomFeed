"""
PhantomFeed — Upload Log

DB table and CRUD for tracking file upload history.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

CREATE_UPLOAD_LOG = """
CREATE TABLE IF NOT EXISTS upload_log (
  id               TEXT PRIMARY KEY,
  filename         TEXT NOT NULL,
  file_type        TEXT NOT NULL,
  client_id        TEXT,
  status           TEXT DEFAULT 'pending',
  records_total    INTEGER DEFAULT 0,
  records_imported INTEGER DEFAULT 0,
  records_skipped  INTEGER DEFAULT 0,
  error_message    TEXT,
  uploaded_at      TEXT,
  completed_at     TEXT
);
"""


def _row(r) -> dict:
    return dict(r) if r else {}


async def create_upload_log(
    filename: str,
    file_type: str,
    client_id: Optional[str] = None,
    status: str = "pending",
) -> dict:
    from db.database import get_db
    db = get_db()
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    await db.execute(
        """INSERT INTO upload_log
           (id, filename, file_type, client_id, status, uploaded_at)
           VALUES (?,?,?,?,?,?)""",
        (uid, filename, file_type, client_id, status, now),
    )
    await db.commit()
    return await get_upload_log(uid)


async def get_upload_log(upload_id: str) -> dict:
    from db.database import get_db
    db = get_db()
    async with db.execute("SELECT * FROM upload_log WHERE id=?", (upload_id,)) as cur:
        row = await cur.fetchone()
    return _row(row)


async def update_upload_log(
    upload_id: str,
    status: Optional[str] = None,
    records_total: Optional[int] = None,
    records_imported: Optional[int] = None,
    records_skipped: Optional[int] = None,
    error_message: Optional[str] = None,
    completed: bool = False,
) -> dict:
    from db.database import get_db
    db = get_db()
    fields = []
    vals = []
    if status is not None:
        fields.append("status=?"); vals.append(status)
    if records_total is not None:
        fields.append("records_total=?"); vals.append(records_total)
    if records_imported is not None:
        fields.append("records_imported=?"); vals.append(records_imported)
    if records_skipped is not None:
        fields.append("records_skipped=?"); vals.append(records_skipped)
    if error_message is not None:
        fields.append("error_message=?"); vals.append(error_message[:1000])
    if completed:
        fields.append("completed_at=?"); vals.append(datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
    if not fields:
        return await get_upload_log(upload_id)
    vals.append(upload_id)
    await db.execute(f"UPDATE upload_log SET {', '.join(fields)} WHERE id=?", vals)
    await db.commit()
    return await get_upload_log(upload_id)


async def list_upload_logs(client_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    from db.database import get_db
    db = get_db()
    if client_id:
        async with db.execute(
            "SELECT * FROM upload_log WHERE client_id=? ORDER BY uploaded_at DESC LIMIT ?",
            (client_id, limit),
        ) as cur:
            rows = await cur.fetchall()
    else:
        async with db.execute(
            "SELECT * FROM upload_log ORDER BY uploaded_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]
