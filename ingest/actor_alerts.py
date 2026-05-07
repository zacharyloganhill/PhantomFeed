"""
PhantomFeed — Actor-Item Linking & Targeted Actor Alerts
Scans new threat items for actor name/alias mentions and links them.
Creates targeted alerts when actors target a client's industry.
"""
import re
from rich.console import Console

console = Console()

# Pre-compiled patterns are built lazily from the actor list
_ACTOR_PATTERNS: dict = {}


async def _build_patterns():
    """Build regex patterns for all actor names and aliases."""
    global _ACTOR_PATTERNS
    if _ACTOR_PATTERNS:
        return
    from db import database as db
    actors = await db.get_threat_actors()
    for actor in actors:
        terms = [actor["name"]] + (actor.get("aliases") or [])
        patterns = []
        for t in terms:
            if t and len(t) >= 4:
                try:
                    patterns.append(re.compile(re.escape(t), re.IGNORECASE))
                except re.error:
                    pass
        if patterns:
            _ACTOR_PATTERNS[actor["id"]] = {
                "patterns": patterns,
                "actor": actor,
            }


async def link_item_to_actors(item: dict) -> list[str]:
    """Scan an item's title/description for actor mentions and create links."""
    await _build_patterns()
    text = f"{item.get('title', '')} {item.get('description', '')} {' '.join(item.get('tags', []))}"
    item_id = item.get("id", "")
    if not item_id:
        return []

    linked = []
    from db import database as db
    for actor_id, data in _ACTOR_PATTERNS.items():
        for pat in data["patterns"]:
            if pat.search(text):
                try:
                    await db.link_actor_to_item(actor_id, item_id)
                    linked.append(actor_id)
                except Exception:
                    pass
                break  # one match per actor is enough

    return linked


async def check_actor_alerts_for_clients(item: dict, linked_actor_ids: list[str]):
    """When an actor linked to an item targets a client's industry, create an alert."""
    if not linked_actor_ids:
        return

    from db import database as db
    clients = await db.get_clients()
    actors_by_id = {a["id"]: a for a in await db.get_threat_actors()}

    for actor_id in linked_actor_ids:
        actor = actors_by_id.get(actor_id)
        if not actor:
            continue
        actor_industries = set(i.lower() for i in (actor.get("target_industries") or []))
        if not actor_industries:
            continue

        for client in clients:
            stack = client.get("stack_profile") or {}
            client_industry = (client.get("industry") or stack.get("industry") or "").lower()
            if not client_industry:
                continue

            # Check for industry overlap
            matched = any(
                ind in client_industry or client_industry in ind
                for ind in actor_industries
            )
            if matched and item.get("severity") in ("CRITICAL", "HIGH"):
                try:
                    await db.create_darkweb_alert(
                        client_id=client["id"],
                        alert_type="actor_targeting",
                        source=f"Threat Actor: {actor['name']}",
                        matched_term=actor["name"],
                        content_preview=(
                            f"{actor['name']} ({actor.get('origin', 'Unknown')}) is targeting "
                            f"{client_industry} organizations. New {item['severity']} threat: "
                            f"{item.get('title', '')[:150]}"
                        ),
                        url=item.get("url", ""),
                    )
                except Exception:
                    pass


async def run_actor_scan_on_new_items(limit: int = 100):
    """Link recent unscanned items to actors. Called on startup and after polls."""
    await _build_patterns()
    from db import database as db
    items = await db.get_items(limit=limit, sort="fetched")
    linked_total = 0
    for item in items:
        linked = await link_item_to_actors(item)
        if linked:
            await check_actor_alerts_for_clients(item, linked)
            linked_total += len(linked)
    return linked_total
