"""
PhantomFeed — abuse.ch Feed Fetchers

ThreatFoxFetcher     — IOCs for active malware families (free key required)
FeodoTrackerFetcher  — botnet C2 IP blocklist (public, no auth)
MalwareBazaarFetcher — recent malware sample hashes (free key required)

Free keys for all abuse.ch services: https://auth.abuse.ch/
"""

from typing import Optional
from rich.console import Console

import config
from ingest.base import BaseFetcher

console = Console()


class ThreatFoxFetcher(BaseFetcher):
    """
    abuse.ch ThreatFox — IOC feed for active malware families.
    Requires a free API key from https://auth.abuse.ch/
    """

    feed_id = "threatfox"
    feed_label = "abuse.ch ThreatFox"
    category = "threat"
    poll_interval = config.POLL_FAST

    async def fetch(self) -> list[dict]:
        if not config.THREATFOX_API_KEY:
            console.print(
                "[yellow][threatfox] No THREATFOX_API_KEY — skipping. "
                "Get a free key at https://auth.abuse.ch/[/]"
            )
            return []

        data = await self.fetch_json_post(
            config.ABUSE_CH_THREATFOX,
            json_body={"query": "get_iocs", "days": 1},
            headers={"Auth-Key": config.THREATFOX_API_KEY},
        )
        if not data or data.get("query_status") != "ok":
            return []

        items = []
        for ioc in (data.get("data") or [])[:50]:
            item = self._normalize(ioc)
            if item:
                items.append(item)
        return items

    def _normalize(self, ioc: dict) -> Optional[dict]:
        ioc_value = ioc.get("ioc_value", "")
        ioc_type = ioc.get("ioc_type", "")
        malware = ioc.get("malware", "Unknown") or "Unknown"
        threat_type = ioc.get("threat_type", "") or ""
        confidence = int(ioc.get("confidence_level") or 50)
        tags_raw = ioc.get("tags") or []
        first_seen = (ioc.get("first_seen", "") or "")[:10]

        if not ioc_value:
            return None

        tags = ["ThreatFox", malware, ioc_type]
        if isinstance(tags_raw, list):
            tags.extend([t for t in tags_raw if isinstance(t, str)][:3])

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "HIGH" if confidence >= 75 else "MEDIUM",
            "cvss": None,
            "title": f"{malware} IOC — {ioc_type}: {ioc_value[:80]}",
            "vendor": "abuse.ch",
            "product": malware,
            "description": self.truncate(
                f"ThreatFox IOC for {malware}.\n"
                f"Type: {ioc_type}\n"
                f"Value: {ioc_value}\n"
                f"Threat type: {threat_type}\n"
                f"Confidence: {confidence}%\n"
                f"Tags: {', '.join(str(t) for t in tags_raw)}"
            ),
            "url": f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}/",
            "published_at": first_seen,
            "tags": [t for t in tags if t][:8],
            "cve_ids": self.extract_cves(f"{ioc_value} {malware}"),
            "raw": {"ioc_type": ioc_type, "confidence": confidence},
        }


class FeodoTrackerFetcher(BaseFetcher):
    """
    abuse.ch Feodo Tracker — botnet C2 server IP blocklist.
    Public endpoint — no API key required.
    Tracks Emotet, QakBot, AsyncRAT, Cobalt Strike and similar families.
    """

    feed_id = "feodo"
    feed_label = "abuse.ch Feodo Tracker"
    category = "malware"
    poll_interval = config.POLL_SLOW

    async def fetch(self) -> list[dict]:
        data = await self.fetch_json(config.ABUSE_CH_FEODO)
        if not isinstance(data, list):
            return []
        items = []
        for entry in data[:60]:
            item = self._normalize(entry)
            if item:
                items.append(item)
        return items

    def _normalize(self, entry: dict) -> Optional[dict]:
        ip = entry.get("ip_address", "")
        if not ip:
            return None

        malware = entry.get("malware", "Unknown") or "Unknown"
        status = entry.get("status", "unknown") or "unknown"
        port = entry.get("port", "") or ""
        country = entry.get("country", "") or ""
        as_name = entry.get("as_name", "") or ""
        first_seen = (entry.get("first_seen", "") or "")[:10]
        last_online = entry.get("last_online", "") or ""

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "HIGH" if status == "online" else "MEDIUM",
            "cvss": None,
            "title": f"Botnet C2 [{malware}]: {ip}:{port}",
            "vendor": "abuse.ch",
            "product": malware,
            "description": self.truncate(
                f"Botnet C2 server tracked by Feodo Tracker.\n"
                f"IP: {ip}  Port: {port}\n"
                f"Malware: {malware}  Status: {status}\n"
                f"Country: {country} ({as_name})\n"
                f"Last seen online: {last_online}"
            ),
            "url": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            "published_at": first_seen,
            "tags": ["Feodo Tracker", "C2", "Botnet", malware],
            "cve_ids": [],
            "raw": {"ip": ip, "port": port, "status": status, "malware": malware},
        }


class MalwareBazaarFetcher(BaseFetcher):
    """
    abuse.ch MalwareBazaar — recent malware sample hashes.
    Requires a free API key from https://auth.abuse.ch/
    """

    feed_id = "malwarebazaar"
    feed_label = "abuse.ch MalwareBazaar"
    category = "malware"
    poll_interval = config.POLL_FAST

    async def fetch(self) -> list[dict]:
        if not config.MALWARE_BAZAAR_KEY:
            console.print(
                "[yellow][malwarebazaar] No MALWARE_BAZAAR_KEY — skipping. "
                "Get a free key at https://auth.abuse.ch/[/]"
            )
            return []

        data = await self.fetch_json_post(
            config.ABUSE_CH_MALWAREBAZAAR,
            data={"query": "get_recent", "selector": "time"},
            headers={"Auth-Key": config.MALWARE_BAZAAR_KEY},
        )
        if not data or data.get("query_status") != "ok":
            return []

        items = []
        for sample in (data.get("data") or [])[:30]:
            item = self._normalize(sample)
            if item:
                items.append(item)
        return items

    def _normalize(self, s: dict) -> Optional[dict]:
        sha256 = s.get("sha256_hash", "")
        if not sha256:
            return None

        file_type = s.get("file_type", "unknown") or "unknown"
        signature = s.get("signature") or "Unknown Malware"
        tags_raw = s.get("tags") or []
        first_seen = (s.get("first_seen", "") or "")[:10]
        reporter = s.get("reporter", "") or ""
        file_size = s.get("file_size", 0) or 0

        tags = ["MalwareBazaar", "Sample", file_type]
        if isinstance(tags_raw, list):
            tags.extend([t for t in tags_raw if isinstance(t, str)][:3])

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "HIGH",
            "cvss": None,
            "title": f"Malware Sample [{signature}] — {file_type}",
            "vendor": "abuse.ch",
            "product": signature,
            "description": self.truncate(
                f"Malware sample submitted to MalwareBazaar.\n"
                f"SHA256: {sha256}\n"
                f"Signature: {signature}\n"
                f"File type: {file_type}  Size: {file_size} bytes\n"
                f"Reporter: {reporter}\n"
                f"Tags: {', '.join(str(t) for t in tags_raw)}"
            ),
            "url": f"https://bazaar.abuse.ch/sample/{sha256}/",
            "published_at": first_seen,
            "tags": [t for t in tags if t][:8],
            "cve_ids": [],
            "raw": {"sha256": sha256, "file_type": file_type, "signature": signature},
        }
