"""
PhantomFeed — Compliance Mapping Engine

Maps threat items to CMMC 2.0, NIST 800-53, and CIS Controls v8 domains
by examining category, keywords in title/description, and CWE IDs extracted
from tags or raw fields.

tag_item(item: dict) -> list[str]
  Returns a deduplicated list of compliance tag strings, e.g.:
  ["CMMC-AC", "CMMC-SI", "NIST-SI-2", "NIST-RA-5", "CIS-7"]
"""

import re
from typing import Optional

# ── Keyword → Compliance tag mappings ────────────────────────────────────────

_CMMC_KEYWORD_MAP: list[tuple[list[str], str]] = [
    # Access Control
    (["authentication", "privilege", "access control", "unauthorized access",
      "credential", "password", "ldap", "kerberos", "oauth", "saml"], "CMMC-AC"),
    # Audit & Accountability
    (["log", "audit", "syslog", "event log", "logging", "monitoring"], "CMMC-AU"),
    # Configuration Management
    (["misconfiguration", "default credential", "hardcoded", "configuration",
      "hardening", "baseline"], "CMMC-CM"),
    # Identification & Authentication
    (["mfa", "multi-factor", "2fa", "identity", "token", "certificate",
      "pki", "x.509"], "CMMC-IA"),
    # Incident Response
    (["incident", "response", "playbook", "ioc", "malware", "ransomware",
      "botnet", "c2", "command and control"], "CMMC-IR"),
    # Risk Assessment
    (["cve", "cvss", "epss", "vulnerability", "exploit", "kev", "patch",
      "zero-day", "0-day"], "CMMC-RA"),
    # System & Communications Protection
    (["tls", "ssl", "encryption", "network", "firewall", "vpn",
      "man-in-the-middle", "mitm", "injection"], "CMMC-SC"),
    # System & Information Integrity
    (["remote code execution", "rce", "code injection", "buffer overflow",
      "heap", "memory corruption", "supply chain", "npm", "pypi",
      "update", "patch"], "CMMC-SI"),
]

_NIST_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["access control", "privilege escalation", "unauthorized access",
      "authentication bypass"], "NIST-AC-3"),
    (["audit", "log", "syslog", "event"], "NIST-AU-2"),
    (["configuration", "misconfiguration", "hardening", "baseline"], "NIST-CM-6"),
    (["multi-factor", "mfa", "identity", "credential"], "NIST-IA-5"),
    (["incident", "malware", "ransomware", "botnet", "c2"], "NIST-IR-4"),
    (["vulnerability", "cve", "epss", "kev", "cvss", "exploit",
      "zero-day", "0-day"], "NIST-RA-5"),
    (["patch", "update", "software update", "firmware update"], "NIST-SI-2"),
    (["remote code execution", "rce", "code injection", "sql injection",
      "buffer overflow", "heap", "memory corruption"], "NIST-SI-3"),
    (["supply chain", "npm", "pypi", "maven", "nuget", "dependency",
      "package"], "NIST-SR-3"),
    (["tls", "ssl", "encryption", "network", "vpn", "firewall",
      "man-in-the-middle", "mitm"], "NIST-SC-8"),
    (["data loss", "exfiltration", "dlp"], "NIST-SI-12"),
]

_CIS_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["inventory", "asset", "hardware", "software inventory"], "CIS-1"),
    (["software", "inventory", "authorized software", "unauthorized software"], "CIS-2"),
    (["data protection", "data loss", "encryption", "sensitive data"], "CIS-3"),
    (["secure configuration", "hardening", "misconfiguration", "baseline",
      "default credential"], "CIS-4"),
    (["account", "credential", "password", "privilege", "admin",
      "authentication", "mfa", "multi-factor"], "CIS-5"),
    (["access control", "privilege escalation", "unauthorized access"], "CIS-6"),
    (["vulnerability", "cve", "cvss", "epss", "patch", "update",
      "zero-day", "0-day", "kev", "exploit"], "CIS-7"),
    (["audit", "log", "syslog", "monitoring", "event"], "CIS-8"),
    (["email", "phishing", "attachment", "macro", "spam"], "CIS-9"),
    (["malware", "ransomware", "antivirus", "endpoint protection",
      "c2", "botnet"], "CIS-10"),
    (["network", "firewall", "vpn", "tls", "ssl", "port"], "CIS-12"),
    (["remote access", "vpn", "rdp", "ssh", "remote desktop"], "CIS-12"),
    (["supply chain", "npm", "pypi", "maven", "nuget", "dependency",
      "package", "third-party"], "CIS-15"),
    (["incident", "response", "playbook", "ioc"], "CIS-17"),
    (["penetration test", "pentest", "red team", "simulation"], "CIS-18"),
]

# Category → always-on tags (regardless of keywords)
_CATEGORY_TAGS: dict[str, list[str]] = {
    "kev":    ["CMMC-RA", "NIST-RA-5", "CIS-7"],
    "cve":    ["CMMC-RA", "NIST-RA-5", "CIS-7"],
    "supply": ["CMMC-SI", "NIST-SR-3", "CIS-15"],
    "malware":["CMMC-IR", "NIST-IR-4", "CIS-10"],
    "threat": ["CMMC-IR", "NIST-IR-4", "CIS-10"],
    "ics":    ["CMMC-SC", "NIST-SC-8", "CIS-12"],
}


def _haystack(item: dict) -> str:
    """Build a single lowercase string for keyword searching."""
    parts = [
        item.get("title", ""),
        item.get("description", ""),
        item.get("vendor", ""),
        item.get("product", ""),
        " ".join(item.get("tags", [])),
        " ".join(item.get("cve_ids", [])),
    ]
    return " ".join(p for p in parts if p).lower()


def _match_keywords(haystack: str, mapping: list[tuple[list[str], str]]) -> list[str]:
    found = []
    for keywords, tag in mapping:
        if any(kw in haystack for kw in keywords):
            if tag not in found:
                found.append(tag)
    return found


def tag_item(item: dict) -> list[str]:
    """
    Return compliance tags for a threat item.
    Combines category-level defaults with keyword-driven mappings.
    """
    tags: list[str] = []

    # Category-level defaults
    category = item.get("category", "")
    tags.extend(_CATEGORY_TAGS.get(category, []))

    haystack = _haystack(item)

    tags.extend(_match_keywords(haystack, _CMMC_KEYWORD_MAP))
    tags.extend(_match_keywords(haystack, _NIST_KEYWORD_MAP))
    tags.extend(_match_keywords(haystack, _CIS_KEYWORD_MAP))

    # Deduplicate while preserving order
    seen = set()
    result = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result
