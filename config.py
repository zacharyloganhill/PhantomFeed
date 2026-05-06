"""
ThreatPulse — Central Configuration
All feed definitions, severity mappings, and app settings live here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Server ────────────────────────────────────────────────────────────────────
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))
DB_PATH = os.getenv("DB_PATH", "./threatpulse.db")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 90))

# ── API Keys ──────────────────────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# ── Poll Intervals (minutes) ──────────────────────────────────────────────────
POLL_FAST = int(os.getenv("POLL_INTERVAL_FAST", 15))   # KEV, NVD, zero-days
POLL_SLOW = int(os.getenv("POLL_INTERVAL_SLOW", 60))   # Vendor RSS, threat intel

# ── NVD ───────────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = int(os.getenv("NVD_PAGE_SIZE", 200))
# Rate limits: 5 req/30s w/o key, 50 req/30s with key
NVD_RATE_DELAY = 6.5 if not NVD_API_KEY else 0.7

# ── CISA ──────────────────────────────────────────────────────────────────────
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA killed RSS feeds in May 2025; advisories now come from CSAF on GitHub
CISA_CSAF_CYBER_DIR = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/IT/white/{year}"
CISA_CSAF_ICS_DIR   = "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white/{year}"

# ── Vendor RSS Feeds ──────────────────────────────────────────────────────────
VENDOR_RSS_FEEDS = [
    {
        "id": "msrc",
        "label": "Microsoft MSRC",
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "category": "vendor",
        "vendor": "Microsoft",
        "color": "#00b4d8",
    },
    {
        "id": "cisco",
        "label": "Cisco Security",
        "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "category": "vendor",
        "vendor": "Cisco",
        "color": "#1dd1a1",
    },
    {
        "id": "fortinet",
        "label": "Fortinet PSIRT",
        "url": "https://www.fortiguard.com/rss/ir.xml",
        "category": "vendor",
        "vendor": "Fortinet",
        "color": "#e84393",
    },
    {
        "id": "palo",
        "label": "Palo Alto Networks",
        "url": "https://security.paloaltonetworks.com/rss.xml",
        "category": "vendor",
        "vendor": "Palo Alto Networks",
        "color": "#a29bfe",
    },
    {
        "id": "redhat",
        "label": "Red Hat Security",
        "url": "https://security.access.redhat.com/data/metrics/rhsa.rss",
        "category": "vendor",
        "vendor": "Red Hat",
        "color": "#ff4757",
    },
    {
        "id": "ubuntu",
        "label": "Ubuntu Security",
        "url": "https://ubuntu.com/security/notices/rss.xml",
        "category": "vendor",
        "vendor": "Canonical",
        "color": "#fdcb6e",
    },
]

# ── Threat Intel Feeds ────────────────────────────────────────────────────────
ABUSE_CH_URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
ABUSE_CH_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")  # free key at https://auth.abuse.ch/

# ── Severity Normalization ─────────────────────────────────────────────────────
# Map various source severities → our standard levels
SEVERITY_MAP = {
    # CVSS numeric → label
    "cvss": {
        (9.0, 10.0): "CRITICAL",
        (7.0, 8.9):  "HIGH",
        (4.0, 6.9):  "MEDIUM",
        (0.1, 3.9):  "LOW",
        (0.0, 0.0):  "INFO",
    },
    # String mappings from various sources
    "strings": {
        "critical":   "CRITICAL",
        "high":       "HIGH",
        "important":  "HIGH",      # Microsoft uses "Important"
        "medium":     "MEDIUM",
        "moderate":   "MEDIUM",    # Red Hat uses "Moderate"
        "low":        "LOW",
        "informational": "INFO",
        "info":       "INFO",
        "none":       "INFO",
    }
}

def normalize_severity(raw: str = "", cvss: float = None) -> str:
    """Normalize severity from any source to CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    if cvss is not None and cvss > 0:
        for (lo, hi), label in SEVERITY_MAP["cvss"].items():
            if lo <= cvss <= hi:
                return label
    if raw:
        return SEVERITY_MAP["strings"].get(raw.lower().strip(), "INFO")
    return "INFO"

# ── Category Definitions ──────────────────────────────────────────────────────
CATEGORIES = {
    "cve":      {"label": "CVE / Vulnerability", "color": "#ff4757"},
    "kev":      {"label": "CISA KEV",            "color": "#ffa502"},
    "advisory": {"label": "Gov Advisory",        "color": "#ffa502"},
    "vendor":   {"label": "Vendor Advisory",     "color": "#00b4d8"},
    "ics":      {"label": "ICS / OT / SCADA",    "color": "#fdcb6e"},
    "threat":   {"label": "Threat Intel",        "color": "#1dd1a1"},
    "malware":  {"label": "Malware / C2",        "color": "#fd79a8"},
    "supply":   {"label": "Supply Chain",        "color": "#fd79a8"},
    "cloud":    {"label": "Cloud / SaaS",        "color": "#55efc4"},
    "darkweb":  {"label": "Dark Web / OSINT",    "color": "#6c5ce7"},
    "osint":    {"label": "CTI / OSINT Share",   "color": "#b2bec3"},
}
