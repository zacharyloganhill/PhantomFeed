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
# Comma-separated list of allowed CORS origins; defaults to localhost only
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        f"http://localhost:{os.getenv('PORT', '8000')},http://127.0.0.1:{os.getenv('PORT', '8000')}",
    ).split(",")
    if o.strip()
]

# ── API Keys ──────────────────────────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

# ── Auth ──────────────────────────────────────────────────────────────────────
SECRET_KEY     = os.getenv("SECRET_KEY", "change-me-in-production-use-a-long-random-string")
ALGORITHM      = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 480))  # 8 hours
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "phantomfeed-admin")

# ── TAXII 2.1 Feeds ──────────────────────────────────────────────────────────
TAXII_USERNAME  = os.getenv("TAXII_USERNAME", "")
TAXII_PASSWORD  = os.getenv("TAXII_PASSWORD", "")
TAXII_CERT_PATH = os.getenv("TAXII_CERT_PATH", "")

TAXII_FEEDS = [
    {
        "id": "cisa_ais",
        "label": "CISA AIS",
        "url": "https://ais2.cisa.dhs.gov/taxii2/",
        "collection": "default",
        "requires_cert": True,
        "notes": "Requires CISA AIS registration at cisa.gov/ais",
    },
    {
        "id": "circl_misp",
        "label": "CIRCL MISP Feed",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "collection": "default",
        "requires_cert": False,
        "notes": "CIRCL OSINT MISP feed — public",
    },
    {
        "id": "otx_taxii",
        "label": "AlienVault OTX TAXII",
        "url": "https://otx.alienvault.com/taxii/discovery",
        "collection": "user_AlienVault",
        "requires_cert": False,
        "notes": "Requires OTX_API_KEY as password",
    },
]

# ── IOC Enrichment API Keys ───────────────────────────────────────────────────
ABUSEIPDB_API_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")
GREYNOISE_API_KEY    = os.getenv("GREYNOISE_API_KEY", "")
ADMIN_SLACK_WEBHOOK  = os.getenv("ADMIN_SLACK_WEBHOOK", "")

# ── Dark Web Monitoring ────────────────────────────────────────────────────────
HIBP_API_KEY         = os.getenv("HIBP_API_KEY", "")
TELEGRAM_BOT_TOKEN   = os.getenv("TELEGRAM_BOT_TOKEN", "")
GITHUB_TOKEN         = os.getenv("GITHUB_TOKEN", "")

RANSOMWARE_FEEDS = [
    {
        "name": "RansomWatch",
        "url": "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
        "type": "json",
    },
]

# ── MISP Integration ──────────────────────────────────────────────────────────
MISP_URL           = os.getenv("MISP_URL", "")
MISP_API_KEY       = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL    = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"
MISP_SHARING_GROUP = os.getenv("MISP_SHARING_GROUP", "")

PUBLIC_MISP_FEEDS = [
    {"name": "CIRCL OSINT", "url": "https://www.circl.lu/doc/misp/feed-osint/", "format": "misp"},
    {"name": "abuse.ch MISP", "url": "https://urlhaus.abuse.ch/downloads/misp/", "format": "misp"},
]

# ── FedRAMP 20x — Encryption Key ─────────────────────────────────────────────
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
PHANTOMFEED_ENCRYPTION_KEY = os.getenv("PHANTOMFEED_ENCRYPTION_KEY", "")

# ── MSP Contact (for report footers) ─────────────────────────────────────────
MSP_NAME    = os.getenv("MSP_NAME", "PhantomFeed MSP")
MSP_EMAIL   = os.getenv("MSP_EMAIL", "")
MSP_PHONE   = os.getenv("MSP_PHONE", "")

# ── SMTP (for email digests) ──────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "")

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
ABUSE_CH_URLHAUS    = "https://urlhaus.abuse.ch/downloads/json_recent/"
ABUSE_CH_FEODO      = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
ABUSE_CH_THREATFOX  = "https://threatfox-api.abuse.ch/api/v1/"
ABUSE_CH_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
OTX_PULSES_URL      = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# abuse.ch API keys (all free at https://auth.abuse.ch/)
URLHAUS_API_KEY     = os.getenv("URLHAUS_API_KEY", "")
THREATFOX_API_KEY   = os.getenv("THREATFOX_API_KEY", "")
MALWARE_BAZAAR_KEY  = os.getenv("MALWARE_BAZAAR_KEY", "")

# ── Enrichment / Scoring APIs ─────────────────────────────────────────────────
# FIRST EPSS — public, no auth
FIRST_EPSS_API      = "https://api.first.org/data/v1/epss"
# CIRCL CVE enrichment — public, no auth
CIRCL_CVE_URL       = "https://cve.circl.lu/api/last/30"
# VulnCheck KEV — requires free community token at https://vulncheck.com/token
VULNCHECK_TOKEN     = os.getenv("VULNCHECK_TOKEN", "")
VULNCHECK_KEV_URL   = "https://api.vulncheck.com/v3/index/vulncheck-kev"

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
