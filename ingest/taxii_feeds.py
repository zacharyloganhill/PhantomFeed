"""
PhantomFeed — STIX/TAXII 2.1 Feed Ingestion

TAXIIFetcher polls a TAXII 2.1 server for STIX bundles and normalises:
  - Indicator    → IOC pattern extraction (ip-addr, domain, file hash, url)
  - Malware      → malware intelligence card
  - Threat-Actor → actor profile
  - Vulnerability→ CVE enrichment
  - Course-of-Action → remediation guidance

Uses incremental polling: stores last fetched timestamp per feed_id in DB
so restarts only fetch new objects.

Gracefully skips if credentials missing (logs a yellow warning).
"""

import re
from datetime import datetime, timezone
from typing import Optional
from rich.console import Console

import config
from ingest.base import BaseFetcher

console = Console()

# ── Pattern extractors ────────────────────────────────────────────────────────

_IP_RE      = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.I)
_DOMAIN_RE  = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.I)
_URL_RE     = re.compile(r"url:value\s*=\s*'([^']+)'", re.I)
_MD5_RE     = re.compile(r"file:hashes\.MD5\s*=\s*'([^']+)'", re.I)
_SHA1_RE    = re.compile(r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'", re.I)
_SHA256_RE  = re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'", re.I)
_CVE_RE     = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _extract_ioc(pattern: str) -> tuple[str, str]:
    """Return (ioc_type, ioc_value) from a STIX pattern string."""
    for regex, ioc_type in [
        (_SHA256_RE, "sha256"), (_MD5_RE, "md5"), (_SHA1_RE, "sha1"),
        (_IP_RE, "ip"), (_DOMAIN_RE, "domain"), (_URL_RE, "url"),
    ]:
        m = regex.search(pattern or "")
        if m:
            return ioc_type, m.group(1)
    return "unknown", pattern[:120] if pattern else ""


def _sev_from_labels(labels: list) -> str:
    label_str = " ".join(str(l).lower() for l in (labels or []))
    if "critical" in label_str:  return "CRITICAL"
    if "high"     in label_str:  return "HIGH"
    if "medium"   in label_str:  return "MEDIUM"
    if "low"      in label_str:  return "LOW"
    return "MEDIUM"


def _date_str(ts) -> str:
    if not ts:
        return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d")
    try:
        if hasattr(ts, "strftime"):
            return ts.strftime("%Y-%m-%d")
        return str(ts)[:10]
    except Exception:
        return datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d")


# ── STIX object normalizers ───────────────────────────────────────────────────

def _norm_indicator(obj, feed_id: str, feed_label: str) -> Optional[dict]:
    pattern = obj.get("pattern", "")
    ioc_type, ioc_value = _extract_ioc(pattern)
    if not ioc_value:
        return None
    name = obj.get("name", "") or f"{ioc_type}: {ioc_value[:60]}"
    labels = list(obj.get("labels") or [])
    cves = _CVE_RE.findall(pattern + " " + name)
    tags = ["TAXII", "STIX", "Indicator", ioc_type] + labels[:3]
    return {
        "feed_id": feed_id,
        "feed_label": feed_label,
        "category": "threat",
        "severity": _sev_from_labels(labels),
        "cvss": None,
        "title": f"[IOC:{ioc_type.upper()}] {name[:100]}",
        "vendor": "",
        "product": "",
        "description": f"STIX Indicator\nPattern: {pattern[:400]}\nIOC Value: {ioc_value}\nLabels: {', '.join(labels)}",
        "url": "",
        "published_at": _date_str(obj.get("created")),
        "tags": tags[:8],
        "cve_ids": list(set(cves)),
        "raw": {"stix_type": "indicator", "ioc_type": ioc_type, "ioc_value": ioc_value, "pattern": pattern[:200]},
    }


def _norm_malware(obj, feed_id: str, feed_label: str) -> Optional[dict]:
    name = obj.get("name", "Unknown Malware")
    families = list(obj.get("malware_types") or [])
    desc = obj.get("description") or ""
    cves = _CVE_RE.findall(desc + " " + name)
    tags = ["TAXII", "STIX", "Malware"] + families[:3]
    return {
        "feed_id": feed_id,
        "feed_label": feed_label,
        "category": "malware",
        "severity": "HIGH",
        "cvss": None,
        "title": f"Malware: {name[:100]}",
        "vendor": "",
        "product": name,
        "description": f"STIX Malware object.\nName: {name}\nTypes: {', '.join(families)}\n{desc[:800]}",
        "url": "",
        "published_at": _date_str(obj.get("created")),
        "tags": tags[:8],
        "cve_ids": list(set(cves)),
        "raw": {"stix_type": "malware", "malware_types": families},
    }


def _norm_threat_actor(obj, feed_id: str, feed_label: str) -> Optional[dict]:
    name = obj.get("name", "Unknown Actor")
    roles = list(obj.get("roles") or [])
    aliases = list(obj.get("aliases") or [])
    goals = list(obj.get("goals") or [])
    desc = obj.get("description") or ""
    tags = ["TAXII", "STIX", "Threat Actor"] + roles[:2] + aliases[:2]
    return {
        "feed_id": feed_id,
        "feed_label": feed_label,
        "category": "threat",
        "severity": "HIGH",
        "cvss": None,
        "title": f"Threat Actor: {name[:100]}",
        "vendor": "",
        "product": "",
        "description": f"STIX Threat Actor profile.\nName: {name}\nAliases: {', '.join(aliases)}\nGoals: {', '.join(goals)}\n{desc[:600]}",
        "url": "",
        "published_at": _date_str(obj.get("created")),
        "tags": tags[:8],
        "cve_ids": [],
        "raw": {"stix_type": "threat-actor", "roles": roles, "aliases": aliases},
    }


def _norm_vulnerability(obj, feed_id: str, feed_label: str) -> Optional[dict]:
    name = obj.get("name", "")
    desc = obj.get("description") or ""
    cves = _CVE_RE.findall(name + " " + desc)
    ext = dict(obj.get("external_references") or []) if not isinstance(obj.get("external_references"), list) else {}
    for ref in (obj.get("external_references") or []):
        if isinstance(ref, dict) and ref.get("source_name") == "cve":
            cve_id = ref.get("external_id", "")
            if cve_id:
                cves.append(cve_id)
    cves = list(set(cves))
    title = cves[0] if cves else name or "STIX Vulnerability"
    tags = ["TAXII", "STIX", "Vulnerability"] + cves[:3]
    return {
        "feed_id": feed_id,
        "feed_label": feed_label,
        "category": "cve",
        "severity": "HIGH",
        "cvss": None,
        "title": f"{title}: {desc[:80]}" if desc else title,
        "vendor": "",
        "product": "",
        "description": f"STIX Vulnerability.\n{desc[:800]}",
        "url": "",
        "published_at": _date_str(obj.get("created")),
        "tags": tags[:8],
        "cve_ids": cves,
        "raw": {"stix_type": "vulnerability", "name": name},
    }


def _norm_course_of_action(obj, feed_id: str, feed_label: str) -> Optional[dict]:
    name = obj.get("name", "Remediation")
    desc = obj.get("description") or ""
    tags = ["TAXII", "STIX", "Course of Action", "Remediation"]
    return {
        "feed_id": feed_id,
        "feed_label": feed_label,
        "category": "advisory",
        "severity": "INFO",
        "cvss": None,
        "title": f"Remediation: {name[:100]}",
        "vendor": "",
        "product": "",
        "description": f"STIX Course of Action (remediation guidance).\n{desc[:800]}",
        "url": "",
        "published_at": _date_str(obj.get("created")),
        "tags": tags[:8],
        "cve_ids": [],
        "raw": {"stix_type": "course-of-action"},
    }


_NORMALIZERS = {
    "indicator":        _norm_indicator,
    "malware":          _norm_malware,
    "threat-actor":     _norm_threat_actor,
    "vulnerability":    _norm_vulnerability,
    "course-of-action": _norm_course_of_action,
}


# ── TAXII Fetcher ─────────────────────────────────────────────────────────────

class TAXIIFetcher(BaseFetcher):
    """
    Polls a TAXII 2.1 collection for STIX 2.1 bundles.
    Incremental: stores last_fetched timestamp so restarts only fetch new objects.
    Skips gracefully when credentials or certs are missing.
    """

    category = "threat"
    poll_interval = config.POLL_SLOW

    def __init__(self, feed_cfg: dict):
        super().__init__()
        self._cfg   = feed_cfg
        self.feed_id    = feed_cfg["id"]
        self.feed_label = feed_cfg["label"]
        self._url       = feed_cfg["url"]
        self._collection = feed_cfg.get("collection", "default")
        self._requires_cert = feed_cfg.get("requires_cert", False)

    def _credentials_ok(self) -> bool:
        if self._requires_cert and not config.TAXII_CERT_PATH:
            console.print(
                f"[yellow][{self.feed_id}] Skipping — TAXII_CERT_PATH not set "
                f"({self._cfg.get('notes', '')})[/]"
            )
            return False
        return True

    async def _get_last_fetched(self) -> Optional[str]:
        """Retrieve stored added_after timestamp from a lightweight meta table."""
        try:
            from db import database as db_mod
            database = db_mod.get_db()
            async with database.execute(
                "SELECT value FROM taxii_state WHERE feed_id = ?", (self.feed_id,)
            ) as cur:
                row = await cur.fetchone()
            return row[0] if row else None
        except Exception:
            return None

    async def _save_last_fetched(self, ts: str):
        try:
            from db import database as db_mod
            database = db_mod.get_db()
            await database.execute(
                "INSERT OR REPLACE INTO taxii_state (feed_id, value) VALUES (?,?)",
                (self.feed_id, ts),
            )
            await database.commit()
        except Exception:
            pass

    def _connect(self):
        """Return a (server, collection) pair or raise."""
        from taxii2client.v21 import Server, Collection

        kwargs = {"verify": True}
        if config.TAXII_USERNAME and config.TAXII_PASSWORD:
            kwargs["user"] = config.TAXII_USERNAME
            kwargs["password"] = config.TAXII_PASSWORD
        elif self.feed_id == "otx_taxii" and config.OTX_API_KEY:
            kwargs["user"] = config.OTX_API_KEY
            kwargs["password"] = ""
        if self._requires_cert and config.TAXII_CERT_PATH:
            kwargs["cert"] = config.TAXII_CERT_PATH

        server = Server(self._url, **kwargs)
        for api_root in server.api_roots:
            for coll in api_root.collections:
                if coll.id == self._collection or coll.title == self._collection:
                    return coll
        # Fallback: return first writable collection
        for api_root in server.api_roots:
            if api_root.collections:
                return api_root.collections[0]
        raise ValueError("No collections found on TAXII server")

    async def fetch(self) -> list[dict]:
        if not self._credentials_ok():
            return []

        try:
            import asyncio
            loop = asyncio.get_event_loop()
            # TAXII client is sync — run in executor to avoid blocking
            added_after = await self._get_last_fetched()
            items = await loop.run_in_executor(None, self._fetch_sync, added_after)
            # Update timestamp
            await self._save_last_fetched(datetime.now(timezone.utc).isoformat())
            return items
        except Exception as exc:
            console.print(f"[yellow][{self.feed_id}] TAXII fetch failed: {exc}[/]")
            return []

    def _fetch_sync(self, added_after: Optional[str]) -> list[dict]:
        """Synchronous TAXII fetch (runs in executor)."""
        from taxii2client.v21 import Server

        kwargs = {"verify": True}
        if config.TAXII_USERNAME and config.TAXII_PASSWORD:
            kwargs["user"] = config.TAXII_USERNAME
            kwargs["password"] = config.TAXII_PASSWORD
        elif self.feed_id == "otx_taxii" and config.OTX_API_KEY:
            kwargs["user"] = config.OTX_API_KEY
            kwargs["password"] = ""
        if self._requires_cert and config.TAXII_CERT_PATH:
            kwargs["cert"] = config.TAXII_CERT_PATH

        try:
            server = Server(self._url, **kwargs)
        except Exception as e:
            raise ValueError(f"Cannot connect to TAXII server {self._url}: {e}")

        target_coll = None
        for api_root in server.api_roots:
            for coll in api_root.collections:
                if coll.id == self._collection or coll.title == self._collection or not self._collection:
                    target_coll = coll
                    break
            if target_coll:
                break
        if not target_coll:
            for api_root in server.api_roots:
                if api_root.collections:
                    target_coll = api_root.collections[0]
                    break

        if not target_coll:
            raise ValueError("No collections found")

        get_kwargs = {}
        if added_after:
            get_kwargs["added_after"] = added_after

        items = []
        envelope = target_coll.get_objects(**get_kwargs)
        for obj in (envelope.get("objects") or []):
            stix_type = obj.get("type", "")
            norm_fn = _NORMALIZERS.get(stix_type)
            if norm_fn:
                normalized = norm_fn(obj, self.feed_id, self.feed_label)
                if normalized:
                    items.append(normalized)
            # Limit to 200 per poll
            if len(items) >= 200:
                break

        return items


def build_taxii_fetchers() -> list[TAXIIFetcher]:
    """Instantiate one TAXIIFetcher per configured TAXII feed."""
    return [TAXIIFetcher(cfg) for cfg in config.TAXII_FEEDS]


async def get_taxii_status() -> list[dict]:
    """Return connection status for each configured TAXII feed."""
    import asyncio

    results = []
    for cfg in config.TAXII_FEEDS:
        status = {
            "id": cfg["id"],
            "label": cfg["label"],
            "url": cfg["url"],
            "requires_cert": cfg.get("requires_cert", False),
            "notes": cfg.get("notes", ""),
            "status": "unknown",
            "collections": [],
        }

        if cfg.get("requires_cert") and not config.TAXII_CERT_PATH:
            status["status"] = "skipped_no_cert"
            results.append(status)
            continue

        try:
            from taxii2client.v21 import Server

            kwargs = {"verify": True}
            if config.TAXII_USERNAME and config.TAXII_PASSWORD:
                kwargs["user"] = config.TAXII_USERNAME
                kwargs["password"] = config.TAXII_PASSWORD
            elif cfg["id"] == "otx_taxii" and config.OTX_API_KEY:
                kwargs["user"] = config.OTX_API_KEY
                kwargs["password"] = ""

            def _test():
                server = Server(cfg["url"], **kwargs)
                colls = []
                for ar in server.api_roots:
                    for c in ar.collections:
                        colls.append({"id": c.id, "title": c.title})
                return colls

            loop = asyncio.get_event_loop()
            colls = await asyncio.wait_for(
                loop.run_in_executor(None, _test), timeout=10
            )
            status["status"] = "connected"
            status["collections"] = colls[:10]
        except asyncio.TimeoutError:
            status["status"] = "timeout"
        except Exception as exc:
            status["status"] = "error"
            status["error"] = str(exc)[:200]

        results.append(status)
    return results
