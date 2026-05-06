"""
ThreatPulse — NVD CVE API v2 Fetcher
Docs: https://nvd.nist.gov/developers/vulnerabilities

Pulls recent CVEs, normalizes CVSS scores, and extracts key metadata.
Rate limit: 5 req/30s w/o key, 50 req/30s w/ key.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

import config
from ingest.base import BaseFetcher


class NVDFetcher(BaseFetcher):
    feed_id = "nvd"
    feed_label = "NVD / NIST"
    category = "cve"
    poll_interval = config.POLL_FAST

    def __init__(self, lookback_hours: int = 24):
        super().__init__()
        self.lookback_hours = lookback_hours

    async def fetch(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=self.lookback_hours)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": config.NVD_PAGE_SIZE,
            "startIndex": 0,
        }
        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        all_items = []
        start_index = 0

        while True:
            params["startIndex"] = start_index
            data = await self.fetch_json(config.NVD_API_BASE, params=params, headers=headers)
            if not data:
                break

            vulns = data.get("vulnerabilities", [])
            for entry in vulns:
                item = self._normalize(entry)
                if item:
                    all_items.append(item)

            total = data.get("totalResults", 0)
            start_index += config.NVD_PAGE_SIZE
            if start_index >= total:
                break

            # Respect rate limits
            await asyncio.sleep(config.NVD_RATE_DELAY)

        return all_items

    def _normalize(self, entry: dict) -> Optional[dict]:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description — prefer English
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS score — try v3.1, then v3.0, then v2
        cvss_score = None
        severity = "INFO"
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                raw_sev = cvss_data.get("baseSeverity", "")
                severity = config.normalize_severity(raw_sev, cvss_score)
                break

        # Affected products / CPE
        affected = []
        configs = cve.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        parts = cpe.split(":")
                        if len(parts) > 4:
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            version = parts[5] if len(parts) > 5 else ""
                            entry_str = f"{vendor} {product}"
                            if version and version not in ("*", "-"):
                                entry_str += f" {version}"
                            if entry_str not in affected:
                                affected.append(entry_str)

        # Published / modified dates
        published = cve.get("published", "")[:10] if cve.get("published") else ""

        # References
        refs = [r["url"] for r in cve.get("references", [])[:5]]

        # Vendor + product from CPE
        vendor = affected[0].split(" ")[0] if affected else "Various"
        product = " ".join(affected[0].split(" ")[1:]) if affected else "Multiple"

        # Tags
        tags = [cve_id]
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for desc_entry in w.get("description", []):
                cwe = desc_entry.get("value", "")
                if cwe.startswith("CWE-"):
                    tags.append(cwe)

        if cvss_score and cvss_score >= 9.0:
            tags.append("Critical Severity")
        if "remote" in desc.lower() or "rce" in desc.lower():
            tags.append("RCE")
        if "authentication" in desc.lower() and "bypass" in desc.lower():
            tags.append("Auth Bypass")
        if "privilege" in desc.lower():
            tags.append("Privilege Escalation")

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": cvss_score,
            "title": f"{cve_id} — {self.truncate(desc, 120)}",
            "vendor": vendor,
            "product": product,
            "description": self.truncate(desc, 2000),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": published,
            "tags": tags[:8],
            "cve_ids": [cve_id],
            "raw": {"cve_id": cve_id, "refs": refs, "affected": affected[:10]},
        }
