"""
PhantomFeed — MISP Integration
Pull from configured MISP instance, push new CRITICAL items back.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from rich.console import Console

import config

console = Console()

# TLP restriction level for client visibility
TLP_RESTRICTED = {"tlp:red", "tlp:amber", "tlp:amber+strict"}


def _is_available() -> bool:
    return bool(config.MISP_API_KEY and config.MISP_URL)


def _headers() -> dict:
    return {
        "Authorization": config.MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _severity_from_threat_level(level: int) -> str:
    return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(level, "MEDIUM")


def _threat_level_from_severity(sev: str) -> int:
    return {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(sev, 3)


async def pull_misp_events(days: int = 1) -> int:
    """Pull recent MISP events and store as threat_items."""
    if not _is_available():
        return 0

    from db import database as db
    from compliance.mappings import tag_item

    since = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)).strftime("%Y-%m-%d")
    params = {
        "returnFormat": "json",
        "limit": 100,
        "page": 1,
        "from": since,
        "published": True,
    }

    verify = config.MISP_VERIFY_SSL
    imported = 0

    try:
        async with httpx.AsyncClient(
            base_url=config.MISP_URL,
            headers=_headers(),
            verify=verify,
            timeout=30,
        ) as client:
            resp = await client.post("/events/restSearch", json=params)
            if resp.status_code != 200:
                console.print(f"[yellow]MISP pull failed: {resp.status_code}[/]")
                return 0
            data = resp.json()
    except Exception as e:
        console.print(f"[yellow]MISP connection error: {e}[/]")
        return 0

    events = data.get("response", [])
    if isinstance(events, dict):
        events = [events]

    for event_wrapper in events:
        event = event_wrapper.get("Event", event_wrapper)
        event_id = str(event.get("id", ""))
        title = event.get("info", "MISP Event")

        # Check TLP
        tags = [t.get("name", "").lower() for t in event.get("Tag", [])]
        tlp_restricted = any(t in TLP_RESTRICTED for t in tags)

        # Extract IOCs / attributes
        attrs = event.get("Attribute", [])
        cve_ids = []
        ioc_values = []
        for attr in attrs:
            atype = attr.get("type", "")
            val = attr.get("value", "")
            if atype == "vulnerability" and val.startswith("CVE-"):
                cve_ids.append(val)
            elif atype in ("ip-src", "ip-dst", "domain", "url", "md5", "sha256"):
                ioc_values.append(val)

        severity = _severity_from_threat_level(int(event.get("threat_level_id", 3)))
        published_date = event.get("date", datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d"))

        item = {
            "feed_id": "misp_pull",
            "feed_label": f"MISP / {config.MISP_URL.split('//')[1].split('/')[0]}",
            "category": "threat" if not cve_ids else "cve",
            "severity": severity,
            "title": title[:250],
            "description": f"MISP Event #{event_id}. IOCs: {len(ioc_values)}. Tags: {', '.join(tags[:5])}",
            "vendor": "", "product": "",
            "url": f"{config.MISP_URL}/events/view/{event_id}",
            "published_at": published_date,
            "cve_ids": cve_ids[:10],
            "tags": [t for t in tags if not t.startswith("tlp:")] + (["TLP:RESTRICTED"] if tlp_restricted else []),
            "raw": {"misp_event_id": event_id, "tlp_restricted": tlp_restricted},
            "compliance_tags": [],
        }
        item["compliance_tags"] = tag_item(item)
        try:
            inserted = await db.upsert_item(item)
            if inserted:
                imported += 1
        except Exception:
            pass

    if imported:
        console.print(f"[cyan]MISP[/] pulled {imported} events from {config.MISP_URL}")
    return imported


async def push_item_to_misp(item_id: str) -> dict:
    """Push a specific PhantomFeed item to MISP as a new event."""
    if not _is_available():
        return {"error": "MISP not configured"}

    from db import database as db
    items = await db.get_items(limit=1)
    item = None
    async with db.get_db().execute("SELECT * FROM threat_items WHERE id = ?", (item_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        return {"error": "Item not found"}
    from db.database import _row_to_dict
    item = _row_to_dict(row)

    # Only push trusted feeds
    trusted_feeds = {"nvd", "cisa_kev", "cisa_advisory", "cisa_ics"}
    if not any(item.get("feed_id", "").startswith(f) for f in trusted_feeds):
        return {"error": "Only NVD/CISA items are pushed to MISP"}

    cve_ids = item.get("cve_ids") or []
    threat_level = _threat_level_from_severity(item.get("severity", "MEDIUM"))

    event_payload = {
        "Event": {
            "info": item.get("title", "PhantomFeed Export")[:255],
            "threat_level_id": str(threat_level),
            "analysis": "1",
            "distribution": "0",
            "Attribute": [
                {"type": "vulnerability", "value": cve, "category": "External analysis"}
                for cve in cve_ids
            ] + [
                {"type": "text", "value": item.get("url", ""), "category": "External analysis"}
                if item.get("url") else {}
            ],
        }
    }

    try:
        verify = config.MISP_VERIFY_SSL
        async with httpx.AsyncClient(
            base_url=config.MISP_URL,
            headers=_headers(),
            verify=verify,
            timeout=30,
        ) as client:
            resp = await client.post("/events/add", json=event_payload)
            if resp.status_code == 200:
                data = resp.json()
                return {"pushed": True, "misp_event_id": data.get("Event", {}).get("id")}
            return {"error": f"MISP returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def get_misp_status() -> dict:
    """Check MISP connection status."""
    if not _is_available():
        return {"configured": False, "url": None}

    try:
        verify = config.MISP_VERIFY_SSL
        async with httpx.AsyncClient(
            base_url=config.MISP_URL,
            headers=_headers(),
            verify=verify,
            timeout=10,
        ) as client:
            resp = await client.get("/servers/getVersion")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "configured": True,
                    "connected": True,
                    "url": config.MISP_URL,
                    "version": data.get("version"),
                }
            return {"configured": True, "connected": False, "url": config.MISP_URL,
                    "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"configured": True, "connected": False, "url": config.MISP_URL, "error": str(e)}
