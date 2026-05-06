"""
ThreatPulse — Vendor RSS Feed Fetcher
Handles all vendor security advisory RSS feeds generically.
Vendor-specific severity parsing is handled per feed.
"""

import re
import feedparser
from datetime import datetime, timezone
from typing import Optional

import config
from ingest.base import BaseFetcher


class VendorRSSFetcher(BaseFetcher):
    """Generic RSS fetcher. One instance per vendor feed definition."""

    poll_interval = config.POLL_SLOW

    def __init__(self, feed_def: dict):
        super().__init__()
        self.feed_id = feed_def["id"]
        self.feed_label = feed_def["label"]
        self.category = feed_def.get("category", "vendor")
        self.vendor_name = feed_def.get("vendor", "Unknown")
        self.rss_url = feed_def["url"]
        self.color = feed_def.get("color", "#636e72")

    async def fetch(self) -> list[dict]:
        text = await self.fetch_text(self.rss_url)
        if not text:
            return []

        feed = feedparser.parse(text)
        items = []
        for entry in feed.entries[:30]:
            item = self._normalize(entry)
            if item:
                items.append(item)
        return items

    def _normalize(self, entry) -> Optional[dict]:
        title = entry.get("title", "").strip()
        if not title:
            return None

        desc = (
            entry.get("summary", "")
            or entry.get("description", "")
            or entry.get("content", [{}])[0].get("value", "")
        )
        # Strip HTML tags from description
        desc = re.sub(r"<[^>]+>", " ", desc)
        desc = re.sub(r"\s+", " ", desc).strip()

        url = entry.get("link", "")
        published = self._parse_date(entry)
        cve_ids = self.extract_cves(title + " " + desc)

        severity = self._detect_severity(title, desc, entry)
        tags = self._build_tags(title, desc, cve_ids)

        # Try to extract product from title
        product = self._extract_product(title)

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": self._extract_cvss(desc),
            "title": title,
            "vendor": self.vendor_name,
            "product": product,
            "description": self.truncate(desc, 2000),
            "url": url,
            "published_at": published,
            "tags": tags[:8],
            "cve_ids": cve_ids,
            "raw": {"url": url},
        }

    def _detect_severity(self, title: str, desc: str, entry) -> str:
        combined = (title + " " + desc).lower()

        # Check entry tags/category first
        for tag in entry.get("tags", []):
            term = tag.get("term", "").lower()
            sev = config.normalize_severity(term)
            if sev != "INFO":
                return sev

        # CVSS extraction
        cvss = self._extract_cvss(desc)
        if cvss:
            return config.normalize_severity(cvss=cvss)

        # Keyword heuristics
        if any(w in combined for w in ["critical", "remote code execution", "rce", "unauthenticated"]):
            return "CRITICAL"
        if any(w in combined for w in ["high", "important", "privilege escalation", "authentication bypass"]):
            return "HIGH"
        if any(w in combined for w in ["medium", "moderate", "cross-site", "csrf", "xss"]):
            return "MEDIUM"
        if any(w in combined for w in ["low", "minimal", "informational"]):
            return "LOW"

        return "MEDIUM"  # Vendor advisories default to MEDIUM — they published it for a reason

    def _extract_cvss(self, text: str) -> Optional[float]:
        patterns = [
            r"CVSS(?:\s+v\d)?\s+(?:Base\s+)?Score[:\s]+(\d+\.?\d*)",
            r"cvss[:\s]+(\d+\.?\d*)",
            r"base\s+score[:\s]+(\d+\.?\d*)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                try:
                    score = float(m.group(1))
                    if 0.0 <= score <= 10.0:
                        return score
                except ValueError:
                    pass
        return None

    def _extract_product(self, title: str) -> str:
        """Best-effort product extraction from advisory title."""
        # Common advisory title patterns:
        # "Cisco IOS XE Software Vulnerability" → "IOS XE"
        # "Microsoft Windows Kernel RCE" → "Windows Kernel"
        # "FortiOS SSL-VPN Auth Bypass" → "FortiOS SSL-VPN"
        vendor_lower = self.vendor_name.lower().split("/")[0].strip()
        title_clean = title
        # Remove vendor name prefix
        for variant in [self.vendor_name, vendor_lower, "advisory", "security"]:
            title_clean = re.sub(variant, "", title_clean, flags=re.IGNORECASE).strip()

        # Take first meaningful segment (up to first dash or vulnerability keyword)
        product = re.split(r"\s*[-–—|]\s*|\s+(?:vulnerability|advisory|security|cve|patch)", title_clean, maxsplit=1)[0].strip()
        return product[:80] if product else "Multiple Products"

    def _build_tags(self, title: str, desc: str, cve_ids: list) -> list:
        tags = [self.vendor_name]
        combined = (title + " " + desc).lower()

        tag_keywords = {
            "RCE": ["remote code execution", " rce ", "arbitrary code"],
            "Auth Bypass": ["authentication bypass", "auth bypass", "unauthenticated"],
            "Privilege Escalation": ["privilege escalat", "local privilege", "lpe"],
            "DoS": ["denial of service", " dos ", "availability"],
            "XSS": ["cross-site scripting", " xss "],
            "SQL Injection": ["sql injection"],
            "Path Traversal": ["path traversal", "directory traversal"],
            "SSRF": ["server-side request", " ssrf "],
            "Zero-Day": ["zero-day", "0-day", "actively exploited", "in the wild"],
        }

        for tag, keywords in tag_keywords.items():
            if any(kw in combined for kw in keywords):
                tags.append(tag)

        tags.extend(cve_ids[:2])
        return tags


def build_all_vendor_fetchers() -> list[VendorRSSFetcher]:
    """Instantiate a fetcher for every configured vendor feed."""
    return [VendorRSSFetcher(feed_def) for feed_def in config.VENDOR_RSS_FEEDS]
