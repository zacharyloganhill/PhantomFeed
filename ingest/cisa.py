"""
ThreatPulse — CISA Feed Fetchers
- Known Exploited Vulnerabilities (KEV) catalog (JSON, still active)
- Cybersecurity Advisories via CSAF JSON (CISA killed RSS in May 2025)
- ICS / SCADA Advisories via CSAF JSON

CSAF source: https://github.com/cisagov/CSAF
"""

import json
from datetime import datetime, timezone
from typing import Optional

import config
from ingest.base import BaseFetcher


class CISAKEVFetcher(BaseFetcher):
    """
    CISA Known Exploited Vulnerabilities — the gold standard list.
    These are actively weaponized CVEs; always CRITICAL/HIGH priority.
    """

    feed_id = "cisa_kev"
    feed_label = "CISA KEV"
    category = "kev"
    poll_interval = config.POLL_FAST

    async def fetch(self) -> list[dict]:
        data = await self.fetch_json(config.CISA_KEV_URL)
        if not data:
            return []

        items = []
        for vuln in data.get("vulnerabilities", []):
            item = self._normalize(vuln)
            if item:
                items.append(item)

        items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
        return items[:100]

    def _normalize(self, v: dict) -> Optional[dict]:
        cve_id = v.get("cveID", "")
        if not cve_id:
            return None

        vendor = v.get("vendorProject", "Unknown")
        product = v.get("product", "Unknown")
        name = v.get("vulnerabilityName", "")
        desc = v.get("shortDescription", "")
        action = v.get("requiredAction", "")
        date_added = v.get("dateAdded", "")
        due_date = v.get("dueDate", "")
        ransomware = v.get("knownRansomwareCampaignUse", "")

        tags = [cve_id, "KEV", "Active Exploit"]
        if ransomware and ransomware.lower() != "unknown":
            tags.append("Ransomware")
        if "zero" in name.lower() or "zero" in desc.lower():
            tags.append("Zero-Day")

        full_desc = desc
        if action:
            full_desc += f"\n\nRequired Action: {action}"
        if due_date:
            full_desc += f"\nFederal Due Date: {due_date}"

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "CRITICAL" if ransomware and ransomware.lower() != "unknown" else "HIGH",
            "cvss": None,
            "title": f"{cve_id} — {name} [{vendor} {product}]",
            "vendor": vendor,
            "product": product,
            "description": self.truncate(full_desc, 2000),
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published_at": date_added,
            "tags": tags[:8],
            "cve_ids": [cve_id],
            "raw": v,
        }


class CISAAdvisoriesFetcher(BaseFetcher):
    """
    CISA Cybersecurity Advisories via CSAF JSON.
    CISA discontinued RSS in May 2025; advisories are now published as
    CSAF files in the cisagov/CSAF GitHub repository.
    """

    feed_id = "cisa_advisory"
    feed_label = "CISA Advisories"
    category = "advisory"
    poll_interval = config.POLL_SLOW

    _CSAF_DIR = config.CISA_CSAF_CYBER_DIR
    _ADVISORY_BASE = "https://www.cisa.gov/news-events/cybersecurity-advisories/"

    _GH_HEADERS = {"Accept": "application/vnd.github+json"}

    async def fetch(self) -> list[dict]:
        year = datetime.now().year
        file_list = await self.fetch_json(
            self._CSAF_DIR.format(year=year),
            headers=self._GH_HEADERS,
        )
        if not isinstance(file_list, list):
            return []

        # Newest advisories sort highest by filename (they embed the date)
        recent = sorted(file_list, key=lambda f: f.get("name", ""), reverse=True)[:15]

        items = []
        for f in recent:
            raw_url = f.get("download_url")
            if not raw_url:
                continue
            text = await self.fetch_text(raw_url)
            if not text:
                continue
            try:
                csaf = json.loads(text)
            except Exception:
                continue
            item = self._normalize_csaf(csaf)
            if item:
                items.append(item)
        return items

    def _normalize_csaf(self, csaf: dict) -> Optional[dict]:
        doc = csaf.get("document", {})
        title = doc.get("title", "").strip()
        if not title:
            return None

        tracking = doc.get("tracking", {})
        advisory_id = tracking.get("id", "")
        published = (tracking.get("initial_release_date", "") or "")[:10]

        advisory_url = self._ADVISORY_BASE + advisory_id.lower()
        for ref in doc.get("references", []):
            if ref.get("category") == "self":
                advisory_url = ref.get("url", advisory_url)
                break

        vulns = csaf.get("vulnerabilities", [])
        cve_ids = [v["cve"] for v in vulns if v.get("cve")]
        cvss = self._max_cvss(vulns)
        severity = config.normalize_severity(cvss=cvss) if cvss else "HIGH"

        desc = self._extract_desc(doc, vulns)

        tags = ["CISA"]
        if advisory_id:
            tags.append(advisory_id)
        title_low = title.lower()
        if "binding operational directive" in title_low or "bod " in title_low:
            tags += ["BOD", "Federal Mandate"]
        elif "emergency directive" in title_low:
            severity = "CRITICAL"
            tags.append("Emergency Directive")
        elif "joint advisory" in title_low or "aa2" in title_low:
            tags.append("Joint Advisory")
        tags.extend(cve_ids[:3])

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": cvss,
            "title": title,
            "vendor": "CISA",
            "product": "Multiple",
            "description": self.truncate(desc, 2000),
            "url": advisory_url,
            "published_at": published,
            "tags": tags[:8],
            "cve_ids": cve_ids,
            "raw": {"advisory_id": advisory_id},
        }

    @staticmethod
    def _max_cvss(vulns: list) -> Optional[float]:
        best = None
        for v in vulns:
            for score_block in v.get("scores", []):
                for key in ("cvss_v3", "cvss_v2"):
                    s = (score_block.get(key) or {}).get("baseScore")
                    if s is not None and (best is None or s > best):
                        best = float(s)
        return best

    @staticmethod
    def _extract_desc(doc: dict, vulns: list) -> str:
        pieces = []
        for note in doc.get("notes", []):
            if note.get("category") in ("description", "summary", "general"):
                text = note.get("text", "").strip()
                if text:
                    pieces.append(text)
                    break
        for v in vulns[:2]:
            for note in v.get("notes", []):
                if note.get("category") in ("description", "summary"):
                    text = note.get("text", "").strip()
                    if text:
                        pieces.append(text)
                        break
        return "\n\n".join(pieces)


class CISAICSFetcher(CISAAdvisoriesFetcher):
    """
    CISA ICS / SCADA advisories via CSAF (OT advisory files).
    """

    feed_id = "cisa_ics"
    feed_label = "CISA ICS Advisories"
    category = "ics"

    _CSAF_DIR = config.CISA_CSAF_ICS_DIR
    _ADVISORY_BASE = "https://www.cisa.gov/news-events/ics-advisories/"

    def _normalize_csaf(self, csaf: dict) -> Optional[dict]:
        item = super()._normalize_csaf(csaf)
        if item:
            item["category"] = "ics"
            item["feed_id"] = self.feed_id
            item["feed_label"] = self.feed_label
            tags = item.get("tags", [])
            if "ICS" not in tags:
                tags.insert(0, "ICS")
            if "OT" not in tags:
                tags.insert(1, "OT")
            item["tags"] = tags[:8]
        return item
