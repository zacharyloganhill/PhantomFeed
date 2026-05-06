"""
ThreatPulse — Feed Diagnostics
Run this to see exactly which feeds are working and which are failing.

Usage:
    python test_feeds.py
"""

import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')
import httpx
import feedparser

FEEDS_TO_TEST = [
    # (label, url, type)
    # ── CISA ─────────────────────────────────────────────────────────────────
    ("CISA KEV JSON",              "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "json"),
    ("CISA CSAF Cyber (GitHub)",   "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/IT/white/2026",  "json"),
    ("CISA CSAF ICS (GitHub)",     "https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white/2026", "json"),
    # ── Vendor RSS ────────────────────────────────────────────────────────────
    ("Microsoft MSRC RSS",         "https://api.msrc.microsoft.com/update-guide/rss",                          "rss"),
    ("Cisco Security RSS",         "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "rss"),
    ("Fortinet PSIRT RSS",         "https://www.fortiguard.com/rss/ir.xml",                                    "rss"),
    ("Palo Alto RSS",              "https://security.paloaltonetworks.com/rss.xml",                            "rss"),
    ("Red Hat RSS",                "https://security.access.redhat.com/data/metrics/rhsa.rss",                 "rss"),
    ("Ubuntu Security RSS",        "https://ubuntu.com/security/notices/rss.xml",                              "rss"),
    # ── Threat Intel ─────────────────────────────────────────────────────────
    ("abuse.ch URLhaus",           "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/10/",                    "json"),
    ("GitHub Advisory npm",        "https://api.github.com/advisories?ecosystem=npm&per_page=5",               "json"),
    ("GitHub Advisory PyPI",       "https://api.github.com/advisories?ecosystem=pip&per_page=5",               "json"),
]

HEADERS = {
    "User-Agent": "ThreatPulse/1.0",
    "Accept": "application/json, application/xml, text/xml, */*",
}

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

async def test_feed(label, url, ftype):
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=15.0, follow_redirects=True, verify=True) as client:
            r = await client.get(url)
            r.raise_for_status()

            if ftype == "json":
                data = r.json()
                count = len(data) if isinstance(data, list) else len(data.get("vulnerabilities", data.get("urls", data.get("results", []))))
                print(f"  {GREEN}✓ PASS{RESET}  {label:<35} HTTP {r.status_code}  {count} items")
            else:
                feed = feedparser.parse(r.text)
                count = len(feed.entries)
                if count > 0:
                    print(f"  {GREEN}✓ PASS{RESET}  {label:<35} HTTP {r.status_code}  {count} entries")
                else:
                    print(f"  {YELLOW}⚠ EMPTY{RESET} {label:<35} HTTP {r.status_code}  0 entries (feed may be empty or changed format)")

    except httpx.ConnectError as e:
        print(f"  {RED}✗ SSL  {RESET}  {label:<35} Connect/SSL error — trying without verify...")
        await test_feed_no_ssl(label, url, ftype)
    except httpx.TimeoutException:
        print(f"  {RED}✗ TIMEOUT{RESET}{label:<35} Timed out after 15s")
    except httpx.HTTPStatusError as e:
        print(f"  {RED}✗ HTTP {e.response.status_code}{RESET} {label:<35} {e.response.status_code}")
    except Exception as e:
        print(f"  {RED}✗ ERROR{RESET}  {label:<35} {type(e).__name__}: {e}")


async def test_feed_no_ssl(label, url, ftype):
    """Retry with SSL verification disabled — fixes some Windows cert issues."""
    try:
        async with httpx.AsyncClient(headers=HEADERS, timeout=15.0, follow_redirects=True, verify=False) as client:
            r = await client.get(url)
            r.raise_for_status()
            print(f"    {YELLOW}→ Works with SSL verify=False — will patch config to fix this{RESET}")
    except Exception as e:
        print(f"    {RED}→ Still fails without SSL verify: {e}{RESET}")
        print(f"    {YELLOW}→ This feed may be blocked by your firewall or network{RESET}")


async def main():
    print(f"\n{BOLD}{CYAN}ThreatPulse — Feed Connectivity Test{RESET}")
    print(f"{'─'*65}")
    print(f"Testing {len(FEEDS_TO_TEST)} feeds...\n")

    tasks = [test_feed(label, url, ftype) for label, url, ftype in FEEDS_TO_TEST]
    await asyncio.gather(*tasks, return_exceptions=True)

    print(f"\n{'─'*65}")
    print(f"{CYAN}Done.{RESET} If feeds show SSL errors, run: {BOLD}python fix_ssl.py{RESET}")
    print(f"If feeds show TIMEOUT or ERROR, they may be blocked by your network.\n")


if __name__ == "__main__":
    asyncio.run(main())
