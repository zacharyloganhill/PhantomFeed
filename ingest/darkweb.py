"""
PhantomFeed — Dark Web & Paste Site Monitoring
Scans Pastebin, GitHub Gists, ransomware leak feeds, and HIBP for client exposure.
"""
import asyncio
import difflib
import json
import re
import uuid
from datetime import datetime
from typing import Optional

import httpx
from rich.console import Console

import config

console = Console()

PASTEBIN_LIST_URL = "https://scrape.pastebin.com/api_scraping.php?limit=100"
PASTEBIN_RAW_URL  = "https://scrape.pastebin.com/api_scrape_item.php?i={key}"
GITHUB_GISTS_URL  = "https://api.github.com/gists/public?per_page=100"
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_DOMAIN_URL   = "https://haveibeenpwned.com/api/v3/latestbreach/{domain}"

_RATE_LIMIT = 1.0  # seconds between Pastebin requests


async def _get_active_clients() -> list[dict]:
    """Return clients with search terms derived from their email domains and stack profile."""
    from db import database as db
    clients = await db.get_clients()
    result = []
    for c in clients:
        stack = c.get("stack_profile") or {}
        if isinstance(stack, str):
            try:
                stack = json.loads(stack)
            except Exception:
                stack = {}
        terms = []
        email = c.get("contact_email", "")
        if email and "@" in email:
            domain = email.split("@")[1].lower().strip()
            if domain and "." in domain:
                terms.append(domain)
                terms.append(f"@{domain}")
        for d in stack.get("domains", []):
            if d:
                terms.append(d.lower())
        for ip in stack.get("ip_ranges", []):
            if ip:
                terms.append(ip)
        result.append({
            "id": c["id"],
            "name": c["name"],
            "terms": list(set(t for t in terms if len(t) > 3)),
        })
    return result


def _search_content(content: str, terms: list[str]) -> Optional[str]:
    """Return the first matched term if content contains any client identifier."""
    content_lower = content.lower()
    for term in terms:
        if term.lower() in content_lower:
            return term
    return None


# ── Pastebin Monitor ──────────────────────────────────────────────────────────

async def run_pastebin_monitor() -> int:
    """Scan recent Pastebin pastes for client identifier leaks."""
    from db import database as db
    clients = await _get_active_clients()
    if not clients:
        return 0

    alerts_created = 0
    headers = {"User-Agent": "PhantomFeed/1.0"}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        try:
            resp = await client.get(PASTEBIN_LIST_URL)
            if resp.status_code == 403:
                # Pastebin scraping API requires Pro account
                return 0
            if resp.status_code != 200:
                return 0
            pastes = resp.json()
        except Exception:
            return 0

        for paste in pastes:
            key = paste.get("key", "")
            if not key:
                continue

            if await db.is_darkweb_seen("pastebin", key):
                continue

            await asyncio.sleep(_RATE_LIMIT)

            try:
                raw_resp = await client.get(PASTEBIN_RAW_URL.format(key=key))
                if raw_resp.status_code != 200:
                    await db.mark_darkweb_seen("pastebin", key)
                    continue
                content = raw_resp.text
            except Exception:
                await db.mark_darkweb_seen("pastebin", key)
                continue

            paste_url = f"https://pastebin.com/{key}"

            for c in clients:
                if not c["terms"]:
                    continue
                matched = _search_content(content, c["terms"])
                if matched:
                    preview = content[:300].replace("\n", " ")
                    await db.create_darkweb_alert(
                        client_id=c["id"],
                        alert_type="paste_leak",
                        source="Pastebin",
                        matched_term=matched,
                        content_preview=preview,
                        url=paste_url,
                    )
                    alerts_created += 1
                    # Also create a threat item
                    _create_darkweb_threat_item(
                        title=f"Client data detected on Pastebin: {paste_url}",
                        description=f"Identifier '{matched}' found in Pastebin paste. Preview: {preview[:200]}",
                        url=paste_url,
                        source="Pastebin",
                    )

            await db.mark_darkweb_seen("pastebin", key)

    if alerts_created:
        console.print(f"[magenta]Dark Web[/] Pastebin: {alerts_created} new alerts")
    return alerts_created


# ── GitHub Gist Monitor ───────────────────────────────────────────────────────

async def run_gist_monitor() -> int:
    """Scan recent public GitHub Gists for client identifier leaks."""
    from db import database as db
    clients = await _get_active_clients()
    if not clients:
        return 0

    alerts_created = 0
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "PhantomFeed/1.0"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        try:
            resp = await client.get(GITHUB_GISTS_URL)
            if resp.status_code != 200:
                return 0
            gists = resp.json()
        except Exception:
            return 0

        for gist in gists:
            gist_id = gist.get("id", "")
            if not gist_id:
                continue
            if await db.is_darkweb_seen("github_gist", gist_id):
                continue

            # Fetch raw content for each file in the gist
            content_parts = []
            files = gist.get("files", {})
            for fname, finfo in list(files.items())[:5]:
                raw_url = finfo.get("raw_url", "")
                if not raw_url:
                    continue
                try:
                    rc = await client.get(raw_url)
                    if rc.status_code == 200:
                        content_parts.append(rc.text[:5000])
                except Exception:
                    pass

            full_content = " ".join(content_parts)
            gist_url = gist.get("html_url", f"https://gist.github.com/{gist_id}")

            for c in clients:
                if not c["terms"]:
                    continue
                matched = _search_content(full_content, c["terms"])
                if matched:
                    preview = full_content[:300].replace("\n", " ")
                    await db.create_darkweb_alert(
                        client_id=c["id"],
                        alert_type="gist_leak",
                        source="GitHub Gist",
                        matched_term=matched,
                        content_preview=preview,
                        url=gist_url,
                    )
                    alerts_created += 1

            await db.mark_darkweb_seen("github_gist", gist_id)

    if alerts_created:
        console.print(f"[magenta]Dark Web[/] GitHub Gist: {alerts_created} new alerts")
    return alerts_created


# ── Ransomware Leak Monitor ───────────────────────────────────────────────────

async def run_ransomware_monitor() -> int:
    """Poll ransomware leak site feeds and fuzzy-match against active client names."""
    from db import database as db
    clients = await _get_active_clients()
    if not clients:
        return 0

    alerts_created = 0

    async with httpx.AsyncClient(timeout=30) as client:
        for feed in config.RANSOMWARE_FEEDS:
            try:
                resp = await client.get(feed["url"], timeout=20)
                if resp.status_code != 200:
                    continue
                posts = resp.json()
            except Exception:
                continue

            for post in posts:
                victim = (post.get("post_title") or post.get("victim") or
                          post.get("name") or "").strip()
                if not victim:
                    continue

                post_id = post.get("id") or post.get("post_url") or victim
                source_key = f"{feed['name']}:{post_id}"
                if await db.is_darkweb_seen("ransomwatch", source_key):
                    continue

                for c in clients:
                    ratio = difflib.SequenceMatcher(
                        None, victim.lower(), c["name"].lower()
                    ).ratio()
                    if ratio >= 0.85:
                        post_url = post.get("post_url") or post.get("url") or feed["url"]
                        preview = f"Victim: {victim} | Group: {post.get('group_name', feed['name'])}"
                        await db.create_darkweb_alert(
                            client_id=c["id"],
                            alert_type="ransomware_listing",
                            source=f"Ransomware: {feed['name']}",
                            matched_term=victim,
                            content_preview=preview,
                            url=post_url,
                        )
                        alerts_created += 1
                        _create_darkweb_threat_item(
                            title=f"RANSOMWARE: {c['name']} listed on {feed['name']} leak site",
                            description=(f"Client '{c['name']}' matched ransomware victim '{victim}' "
                                         f"(similarity: {ratio:.0%}) on {feed['name']}."),
                            url=post_url,
                            source=feed["name"],
                            severity="CRITICAL",
                        )

                await db.mark_darkweb_seen("ransomwatch", source_key)

    if alerts_created:
        console.print(f"[magenta]Dark Web[/] Ransomware feeds: {alerts_created} new alerts")
    return alerts_created


# ── HIBP Monitor ──────────────────────────────────────────────────────────────

async def run_hibp_monitor() -> int:
    """Check HIBP for new breaches affecting client domains (daily)."""
    if not config.HIBP_API_KEY:
        return 0

    from db import database as db
    clients = await _get_active_clients()
    alerts_created = 0

    headers = {
        "hibp-api-key": config.HIBP_API_KEY,
        "User-Agent": "PhantomFeed/1.0",
    }

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        for c in clients:
            # Extract domain from contact_email
            domain = ""
            for term in c["terms"]:
                if "." in term and not term.startswith("@") and not term.startswith("10."):
                    domain = term
                    break
            if not domain:
                continue

            source_key = f"hibp:{domain}"
            if await db.is_darkweb_seen("hibp_domain", source_key):
                continue

            try:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                )
                await asyncio.sleep(1.5)  # HIBP rate limit
            except Exception:
                continue

            if resp.status_code == 200:
                breach_data = resp.json()
                total = sum(len(v) for v in breach_data.values()) if breach_data else 0
                if total > 0:
                    await db.create_darkweb_alert(
                        client_id=c["id"],
                        alert_type="hibp_breach",
                        source="HaveIBeenPwned",
                        matched_term=domain,
                        content_preview=f"{total} accounts from domain {domain} found in data breaches",
                        url=f"https://haveibeenpwned.com/DomainSearch/{domain}",
                    )
                    alerts_created += 1

            await db.mark_darkweb_seen("hibp_domain", source_key)

    if alerts_created:
        console.print(f"[magenta]Dark Web[/] HIBP: {alerts_created} new alerts")
    return alerts_created


# ── Shared helper ─────────────────────────────────────────────────────────────

def _create_darkweb_threat_item(title: str, description: str, url: str,
                                 source: str, severity: str = "HIGH"):
    """Fire-and-forget: schedule a threat item creation for a dark web finding."""
    async def _insert():
        from db import database as db
        from compliance.mappings import tag_item
        item = {
            "feed_id": f"darkweb_{source.lower().replace(' ', '_')}",
            "feed_label": f"Dark Web / {source}",
            "category": "darkweb",
            "severity": severity,
            "title": title[:250],
            "description": description[:2000],
            "vendor": "", "product": "", "url": url,
            "published_at": datetime.utcnow().strftime("%Y-%m-%d"),
            "cve_ids": [], "tags": ["Dark Web", source],
            "raw": {}, "compliance_tags": [],
        }
        item["compliance_tags"] = tag_item(item)
        try:
            await db.upsert_item(item)
        except Exception:
            pass
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_insert())
    except Exception:
        pass


# ── Entrypoint for scheduler ──────────────────────────────────────────────────

async def run_all_darkweb_monitors() -> int:
    """Run all dark web monitors and return total alert count."""
    total = 0
    for monitor in [
        run_ransomware_monitor,
        run_pastebin_monitor,
        run_gist_monitor,
        run_hibp_monitor,
    ]:
        try:
            n = await monitor()
            total += n
        except Exception as e:
            console.print(f"[red]Dark web monitor error ({monitor.__name__}): {e}[/]")
    return total


async def run_client_darkweb_scan(client_id: str) -> dict:
    """Trigger an immediate dark web scan for a specific client."""
    from db import database as db
    client = await db.get_client(client_id)
    if not client:
        return {"error": "Client not found"}

    before = await db.count_unacknowledged_alerts(client_id)
    await run_all_darkweb_monitors()
    after = await db.count_unacknowledged_alerts(client_id)

    return {
        "client_id": client_id,
        "new_alerts": max(0, after - before),
        "total_unacknowledged": after,
        "scanned_at": datetime.utcnow().isoformat(),
    }
