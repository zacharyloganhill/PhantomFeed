"""
PhantomFeed — Free Public Feed Fetchers (no API key required unless noted)

EPSSFetcher               — FIRST EPSS top exploitability scores (public)
VulnCheckKEVFetcher       — VulnCheck KEV (free community token required)
CIRCLCVEFetcher           — CIRCL CVE enrichment, last 30 CVEs (public)
GitHubAdvisoryGoFetcher   — Go ecosystem advisories via GitHub REST API
GitHubAdvisoryRustFetcher — Rust ecosystem advisories via GitHub REST API
GitHubAdvisoryMavenFetcher— Maven/Java advisories via GitHub REST API
GitHubAdvisoryNugetFetcher— NuGet/.NET advisories via GitHub REST API

Note: Shadowserver and Google Project Zero endpoints are no longer publicly
accessible (404/migrated) and are not implemented.
"""

from typing import Optional
from rich.console import Console

import config
from ingest.base import BaseFetcher
from ingest.threat_intel import _GitHubAdvisoryFetcher

console = Console()


class EPSSFetcher(BaseFetcher):
    """
    FIRST EPSS — Exploit Prediction Scoring System.
    Fetches the top 100 CVEs by current EPSS score and surfaces those
    with a score >= 0.70 (HIGH probability of exploitation within 30 days).
    Public API, no auth required.
    """

    feed_id = "epss"
    feed_label = "FIRST EPSS"
    category = "cve"
    poll_interval = config.POLL_SLOW

    async def fetch(self) -> list[dict]:
        data = await self.fetch_json(
            config.FIRST_EPSS_API,
            params={"limit": 100, "order": "!epss"},
        )
        if not data or data.get("status") != "OK":
            return []

        items = []
        for entry in data.get("data", []):
            try:
                epss = float(entry.get("epss", 0))
            except (TypeError, ValueError):
                continue
            if epss < 0.70:
                continue
            item = self._normalize(entry, epss)
            if item:
                items.append(item)
        return items

    def _normalize(self, entry: dict, epss: float) -> Optional[dict]:
        cve = entry.get("cve", "")
        if not cve:
            return None

        try:
            percentile = float(entry.get("percentile", 0))
        except (TypeError, ValueError):
            percentile = 0.0
        date = (entry.get("date", "") or "")[:10]

        severity = "CRITICAL" if epss > 0.90 else "HIGH"

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": severity,
            "cvss": None,
            "title": f"{cve} — EPSS {epss:.1%} exploitability risk",
            "vendor": "",
            "product": "",
            "description": self.truncate(
                f"EPSS (Exploit Prediction Scoring System) high-risk score for {cve}.\n"
                f"EPSS score: {epss:.4f} ({epss:.1%})\n"
                f"Percentile: {percentile:.1%} of all scored CVEs\n\n"
                f"This CVE has a {epss:.1%} probability of being exploited in the wild "
                f"within the next 30 days based on FIRST's model.\n"
                f"Score date: {date}"
            ),
            "url": f"https://www.first.org/epss/api/v1?cve={cve}",
            "published_at": date,
            "tags": ["EPSS", "High Exploitability", cve],
            "cve_ids": [cve],
            "raw": {"epss": epss, "percentile": percentile},
        }


class VulnCheckKEVFetcher(BaseFetcher):
    """
    VulnCheck KEV — Known Exploited Vulnerabilities with enriched data.
    Requires a free community token from https://vulncheck.com/token
    """

    feed_id = "vulncheck_kev"
    feed_label = "VulnCheck KEV"
    category = "kev"
    poll_interval = config.POLL_SLOW

    async def fetch(self) -> list[dict]:
        if not config.VULNCHECK_TOKEN:
            console.print(
                "[yellow][vulncheck_kev] No VULNCHECK_TOKEN — skipping. "
                "Get a free community token at https://vulncheck.com/token[/]"
            )
            return []

        data = await self.fetch_json(
            config.VULNCHECK_KEV_URL,
            headers={"Authorization": f"Bearer {config.VULNCHECK_TOKEN}"},
        )
        if not data:
            return []

        items = []
        for entry in (data.get("data") or [])[:50]:
            item = self._normalize(entry)
            if item:
                items.append(item)
        return items

    def _normalize(self, entry: dict) -> Optional[dict]:
        cve_id = entry.get("cve_id", "") or entry.get("cveID", "")
        if not cve_id:
            return None

        vendor = entry.get("vendorProject", "") or ""
        product = entry.get("product", "") or ""
        date_added = (entry.get("dateAdded", "") or "")[:10]
        known_exploited = entry.get("knownExploited", False)
        vuln_name = entry.get("vulnerabilityName", "") or ""

        title = f"{cve_id} — VulnCheck KEV: {vendor} {product}".strip()
        if vuln_name:
            title = f"{cve_id} — {vuln_name}"

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": "CRITICAL",
            "cvss": None,
            "title": title,
            "vendor": vendor,
            "product": product,
            "description": self.truncate(
                f"Known exploited vulnerability tracked by VulnCheck KEV.\n"
                f"CVE: {cve_id}\n"
                f"Vendor: {vendor}  Product: {product}\n"
                f"Known exploited in the wild: {known_exploited}\n"
                f"Date added: {date_added}"
            ),
            "url": f"https://vulncheck.com/browse/cve/{cve_id}",
            "published_at": date_added,
            "tags": ["VulnCheck", "KEV", "Known Exploited"],
            "cve_ids": [cve_id],
            "raw": {"cve_id": cve_id, "known_exploited": known_exploited},
        }


class CIRCLCVEFetcher(BaseFetcher):
    """
    CIRCL CVE enrichment — last 30 published CVEs with CVSS, CPE, and references.
    Public API, no auth required.
    Data is in CVE 5.x schema format.
    """

    feed_id = "circl_cve"
    feed_label = "CIRCL CVE"
    category = "cve"
    poll_interval = config.POLL_SLOW

    async def fetch(self) -> list[dict]:
        data = await self.fetch_json(config.CIRCL_CVE_URL)
        if not isinstance(data, list):
            return []
        items = []
        for rec in data:
            item = self._normalize(rec)
            if item:
                items.append(item)
        return items

    def _normalize(self, rec: dict) -> Optional[dict]:
        meta = rec.get("cveMetadata", {})
        cve_id = meta.get("cveId", "")
        if not cve_id:
            return None

        date_pub = (meta.get("datePublished", "") or "")[:10]
        cna = rec.get("containers", {}).get("cna", {})

        # Description — prefer English
        desc = ""
        for d in cna.get("descriptions", []):
            if d.get("lang", "").startswith("en"):
                desc = d.get("value", "")
                break
        if not desc:
            all_descs = cna.get("descriptions", [])
            desc = all_descs[0].get("value", "") if all_descs else ""

        # CVSS score — check v3.1 first, then v4.0, v3.0, v2.0
        cvss_score = None
        severity_raw = ""
        for metric in cna.get("metrics", []):
            for key in ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"):
                if key in metric:
                    cvss_score = metric[key].get("baseScore")
                    severity_raw = metric[key].get("baseSeverity", "")
                    break
            if cvss_score is not None:
                break

        # Vendor / product
        affected = cna.get("affected", [])
        vendor = (affected[0].get("vendor", "") or "").strip() if affected else ""
        product = (affected[0].get("product", "") or "").strip() if affected else ""

        # First reference URL
        refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
        ref_url = refs[0] if refs else f"https://cve.circl.lu/cve/{cve_id}"

        title = f"{cve_id}: {desc[:120]}" if desc else cve_id

        return {
            "feed_id": self.feed_id,
            "feed_label": self.feed_label,
            "category": self.category,
            "severity": config.normalize_severity(raw=severity_raw, cvss=cvss_score),
            "cvss": cvss_score,
            "title": title,
            "vendor": vendor,
            "product": product,
            "description": self.truncate(desc),
            "url": ref_url,
            "published_at": date_pub,
            "tags": ["CIRCL", "CVE", cve_id],
            "cve_ids": [cve_id],
            "raw": {"cve_id": cve_id, "cvss": cvss_score},
        }


# ── GitHub Advisory REST API fetchers (public, no auth) ──────────────────────
# These reuse the base class from threat_intel.py which calls
# https://api.github.com/advisories?ecosystem=<eco>

class GitHubAdvisoryGoFetcher(_GitHubAdvisoryFetcher):
    """Go module supply chain advisories via GitHub Advisory REST API."""

    feed_id = "gh_advisory_go"
    feed_label = "GitHub Advisory (Go)"
    _ecosystem = "go"
    _label_prefix = "Go"
    _vendor = "Go / GitHub"
    _tags_extra = ["Go", "Supply Chain"]


class GitHubAdvisoryRustFetcher(_GitHubAdvisoryFetcher):
    """Rust crate supply chain advisories via GitHub Advisory REST API."""

    feed_id = "gh_advisory_rust"
    feed_label = "GitHub Advisory (Rust)"
    _ecosystem = "rust"
    _label_prefix = "Rust"
    _vendor = "Rust / GitHub"
    _tags_extra = ["Rust", "Supply Chain"]


class GitHubAdvisoryMavenFetcher(_GitHubAdvisoryFetcher):
    """Maven/Java supply chain advisories via GitHub Advisory REST API."""

    feed_id = "gh_advisory_maven"
    feed_label = "GitHub Advisory (Maven)"
    _ecosystem = "maven"
    _label_prefix = "Maven"
    _vendor = "Maven / GitHub"
    _tags_extra = ["Java", "Maven", "Supply Chain"]


class GitHubAdvisoryNugetFetcher(_GitHubAdvisoryFetcher):
    """NuGet/.NET supply chain advisories via GitHub Advisory REST API."""

    feed_id = "gh_advisory_nuget"
    feed_label = "GitHub Advisory (NuGet)"
    _ecosystem = "nuget"
    _label_prefix = "NuGet"
    _vendor = "NuGet / GitHub"
    _tags_extra = [".NET", "NuGet", "Supply Chain"]
