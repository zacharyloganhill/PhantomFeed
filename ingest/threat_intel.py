"""
ThreatPulse — Threat Intelligence Fetchers

Covers:
- abuse.ch URLhaus (malicious URLs / C2) — requires free API key from auth.abuse.ch
- abuse.ch Feodo Tracker (botnet C2 IPs)
- AlienVault OTX (if API key configured)
- Supply chain advisories (npm, PyPI via GitHub Advisory REST API)
"""

from datetime import datetime, timezone
from typing import Optional
from rich.console import Console

import config
from ingest.base import BaseFetcher

console = Console()


class URLHausFetcher(BaseFetcher):
    """
    abuse.ch URLhaus — tracks malware distribution and C2 URLs.
    Requires a free API key from https://auth.abuse.ch/
    """

    feed_id = "urlhaus"
    feed_label = "abuse.ch URLhaus"
    category = "malware"
    poll_interval = config.POLL_FAST

    async def fetch(self) -> list[dict]:
        if not config.URLHAUS_API_KEY:
            console.print(
                "[yellow][urlhaus] No URLHAUS_API_KEY — skipping. "
                "Get a free key at https://auth.abuse.ch/[/]"
            )
            return []

        data = await self.fetch_json_post(
            config.ABUSE_CH_URLHAUS,
            data={"query": "get_urls", "limit": "30"},
            headers={"Auth-Key": config.URLHAUS_API_KEY},
        )
        if not data:
            return []

        query_status = data.get("query_status", "is_available")
        if query_status not in ("is_available", "no_results"):
            console.print(f"[yellow][urlhaus] Unexpected query_status: {query_status}[/]")
            return []

        urls = data.get("urls", [])
        items = []
        for u in urls[:30]:
            item = self._normalize(u)
            if item:
                items.append(item)
        return items

    def _normalize(self, u: dict) -> Optional[dict]:
        url = u.get("url", "")
        if not url:
            return None

        url_status = u.get("url_status", "online")
        tags_raw = u.get("tags", []) or []
        threat = u.get("threat", "malware_download")
        host = u.get("host", "")
        date_added = (u.get("date_added", "") or "")[:10]

        tags = ["URLhaus", "Malware"]
        if isinstance(tags_raw, list):
            tags.extend([t for t in tags_raw if isinstance(t, str)][:4])
        tags.append(threat.replace("_", " ").title())

        severity = "HIGH" if url_status == "online" else "MEDIUM"

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": None,
            "title": f"Malware URL [{url_status.upper()}]: {host}",
            "vendor": "abuse.ch",
            "product": threat.replace("_", " ").title(),
            "description": (
                f"Active malware distribution URL detected by URLhaus.\n"
                f"URL: {url}\n"
                f"Host: {host}\n"
                f"Threat type: {threat}\n"
                f"Status: {url_status}\n"
                f"Tags: {', '.join(str(t) for t in tags_raw)}"
            ),
            "url": f"https://urlhaus.abuse.ch/url/{u.get('id', '')}",
            "published_at": date_added,
            "tags": tags[:8],
            "cve_ids": [],
            "raw": {"host": host, "url_status": url_status},
        }


class OTXFetcher(BaseFetcher):
    """
    AlienVault OTX — threat pulse subscriptions.
    Requires free API key from https://otx.alienvault.com
    """

    feed_id = "otx"
    feed_label = "AlienVault OTX"
    category = "threat"
    poll_interval = config.POLL_SLOW

    async def fetch(self) -> list[dict]:
        if not config.OTX_API_KEY:
            console.print(
                "[yellow][otx] No OTX_API_KEY — skipping. "
                "Get a free key at https://otx.alienvault.com[/]"
            )
            return []

        headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
        data = await self.fetch_json(
            config.OTX_PULSES_URL,
            params={"limit": 20, "page": 1},
            headers=headers,
        )
        if not data:
            return []

        items = []
        for pulse in data.get("results", []):
            item = self._normalize(pulse)
            if item:
                items.append(item)
        return items

    def _normalize(self, pulse: dict) -> Optional[dict]:
        title = pulse.get("name", "").strip()
        if not title:
            return None

        desc = pulse.get("description", "")
        tags_raw = pulse.get("tags", [])
        tlp = pulse.get("tlp", "white")
        created = (pulse.get("created", "") or "")[:10]
        references = pulse.get("references", [])
        industries = pulse.get("industries", [])
        malware_families = pulse.get("malware_families", [])
        adversary = pulse.get("adversary", "")

        cve_ids = self.extract_cves(title + " " + desc + " " + " ".join(references))
        tags = ["OTX", f"TLP:{tlp.upper()}"]
        tags.extend([t for t in tags_raw if isinstance(t, str)][:3])
        if adversary:
            tags.append(adversary)
        tags.extend([m.get("display_name", "") for m in malware_families[:2] if isinstance(m, dict)])

        indicator_count = pulse.get("indicator_count", 0)
        full_desc = (
            f"{desc}\n\n"
            f"Adversary: {adversary or 'Unknown'}\n"
            f"Industries: {', '.join(industries) or 'Not specified'}\n"
            f"IOC Count: {indicator_count}\n"
            f"References: {chr(10).join(references[:3])}"
        )

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "HIGH",
            "cvss": None,
            "title": title,
            "vendor": adversary or "Unknown Threat Actor",
            "product": ", ".join(industries[:2]) or "Multiple",
            "description": self.truncate(full_desc, 2000),
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            "published_at": created,
            "tags": [t for t in tags if t][:8],
            "cve_ids": cve_ids,
            "raw": {"adversary": adversary, "indicator_count": indicator_count},
        }


class FeodoFetcher(BaseFetcher):
    """
    abuse.ch Feodo Tracker — botnet C2 server IP blocklist.
    Public endpoint, no API key required.
    Tracks Emotet, QakBot, AsyncRAT, Cobalt Strike, and similar botnet infrastructure.
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

        malware = entry.get("malware", "Unknown")
        status = entry.get("status", "unknown")
        port = entry.get("port", "")
        country = entry.get("country", "")
        as_name = entry.get("as_name", "")
        first_seen = (entry.get("first_seen", "") or "")[:10]
        last_online = entry.get("last_online", "") or ""

        severity = "HIGH" if status == "online" else "MEDIUM"

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": None,
            "title": f"C2 Infrastructure [{malware}]: {ip}:{port}",
            "vendor": "abuse.ch",
            "product": malware,
            "description": (
                f"Botnet C2 server tracked by Feodo Tracker.\n"
                f"IP: {ip}  Port: {port}\n"
                f"Malware family: {malware}\n"
                f"Status: {status}\n"
                f"Country: {country} ({as_name})\n"
                f"Last seen online: {last_online}"
            ),
            "url": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            "published_at": first_seen,
            "tags": ["Feodo Tracker", "C2", "Botnet", malware],
            "cve_ids": [],
            "raw": {"ip": ip, "port": port, "status": status, "malware": malware},
        }


class _GitHubAdvisoryFetcher(BaseFetcher):
    """Base class for GitHub Advisory Database fetchers (REST API)."""

    category = "supply"
    poll_interval = config.POLL_SLOW

    _ecosystem: str = ""
    _label_prefix: str = ""
    _vendor: str = ""
    _tags_extra: list = []

    _GH_HEADERS = {"Accept": "application/vnd.github+json"}

    async def fetch(self) -> list[dict]:
        data = await self.fetch_json(
            "https://api.github.com/advisories",
            params={"ecosystem": self._ecosystem, "per_page": "20"},
            headers=self._GH_HEADERS,
        )
        if not isinstance(data, list):
            return []
        items = []
        for advisory in data:
            item = self._normalize(advisory)
            if item:
                items.append(item)
        return items

    def _normalize(self, advisory: dict) -> Optional[dict]:
        title = advisory.get("summary", "").strip()
        if not title:
            return None

        desc = advisory.get("description", "") or ""
        url = advisory.get("html_url", "") or advisory.get("url", "")
        published = (advisory.get("published_at", "") or "")[:10]
        cve_id = advisory.get("cve_id", "")
        cve_ids = [cve_id] if cve_id else self.extract_cves(title + " " + desc)
        raw_severity = advisory.get("severity", "moderate")
        cvss_score = (advisory.get("cvss") or {}).get("score")

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": config.normalize_severity(raw=raw_severity, cvss=cvss_score),
            "cvss": cvss_score,
            "title": f"[{self._label_prefix}] {title}",
            "vendor": self._vendor,
            "product": f"{self._ecosystem} package",
            "description": self.truncate(desc, 2000),
            "url": url,
            "published_at": published,
            "tags": ["Supply Chain"] + self._tags_extra + cve_ids[:2],
            "cve_ids": cve_ids,
            "raw": {"ghsa_id": advisory.get("ghsa_id", "")},
        }


class NPMAdvisoryFetcher(_GitHubAdvisoryFetcher):
    """npm supply chain advisories via GitHub Advisory REST API."""

    feed_id = "npm_advisory"
    feed_label = "GitHub Advisory (npm)"
    _ecosystem = "npm"
    _label_prefix = "npm Supply Chain"
    _vendor = "npm / GitHub"
    _tags_extra = ["npm", "Open Source"]


class PyPIAdvisoryFetcher(_GitHubAdvisoryFetcher):
    """PyPI / Python supply chain advisories via GitHub Advisory REST API."""

    feed_id = "pypi_advisory"
    feed_label = "GitHub Advisory (PyPI)"
    _ecosystem = "pip"
    _label_prefix = "PyPI Supply Chain"
    _vendor = "PyPI / GitHub"
    _tags_extra = ["PyPI", "Python"]
