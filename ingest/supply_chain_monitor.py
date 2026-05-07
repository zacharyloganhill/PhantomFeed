"""
PhantomFeed — Supply Chain Risk Monitor

Monitors vendor software exposure: for each registered vendor-product pair,
checks for matching CVEs/advisories in the current threat feed and calculates
a vendor risk level. Triggers cascade alerts when critical findings emerge.
"""
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

RISK_LEVELS = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}


async def calculate_vendor_risk(client_id: str, vendor_id: str) -> dict:
    """
    Calculate risk level for a specific vendor based on current threat feed.
    Returns risk_level, item_count, cve_count, critical_count.
    """
    from db import database as db

    vendor = None
    # Get vendor details
    async with db.get_db().execute(
        "SELECT * FROM client_vendors WHERE id = ? AND client_id = ?",
        (vendor_id, client_id)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        return {}
    vendor = dict(row)

    vendor_name = vendor.get("vendor_name", "").lower()
    products = vendor.get("products") or []
    if isinstance(products, str):
        import json
        try:
            products = json.loads(products)
        except Exception:
            products = [products]

    # Find matching threat items
    items = await db.get_items(limit=300, sort="risk")
    matched = []
    for item in items:
        item_vendor = (item.get("vendor") or "").lower()
        item_product = (item.get("product") or "").lower()
        item_title = (item.get("title") or "").lower()

        if vendor_name and (vendor_name in item_vendor or vendor_name in item_title):
            matched.append(item)
        elif any(p.lower() in item_product or p.lower() in item_title for p in products if p):
            matched.append(item)

    critical_count = sum(1 for i in matched if i.get("severity") == "CRITICAL")
    high_count = sum(1 for i in matched if i.get("severity") == "HIGH")
    cve_count = sum(len(i.get("cve_ids") or []) for i in matched)

    if critical_count > 0:
        risk_level = "high"
    elif high_count > 2:
        risk_level = "high"
    elif high_count > 0 or len(matched) > 5:
        risk_level = "medium"
    elif matched:
        risk_level = "low"
    else:
        risk_level = "unknown"

    return {
        "vendor_id": vendor_id,
        "vendor_name": vendor.get("vendor_name"),
        "risk_level": risk_level,
        "item_count": len(matched),
        "cve_count": cve_count,
        "critical_count": critical_count,
        "matched_items": [i.get("id") for i in matched[:10]],
    }


async def run_supply_chain_monitor(client_id: str) -> int:
    """Run full supply chain risk assessment for a client. Returns update count."""
    from db import database as db

    vendors = await db.get_client_vendors(client_id)
    if not vendors:
        return 0

    updated = 0
    for vendor in vendors:
        risk_data = await calculate_vendor_risk(client_id, vendor["id"])
        if risk_data:
            await db.update_vendor_risk(client_id, vendor["id"], risk_data["risk_level"], risk_data)
            updated += 1

    return updated


async def build_supply_chain_graph(client_id: str) -> dict:
    """
    Build a D3.js-compatible force-directed graph of vendor relationships.
    Returns {nodes: [...], links: [...]} for the client's supply chain.
    """
    from db import database as db

    vendors = await db.get_client_vendors(client_id)
    client = await db.get_client(client_id)
    client_name = client.get("name", "Client") if client else "Client"

    # Root node (the client org)
    nodes = [{
        "id": f"client_{client_id}",
        "label": client_name,
        "type": "client",
        "risk": "none",
        "item_count": 0,
    }]
    links = []

    risk_colors = {
        "high": "#f0595a",
        "medium": "#e8a530",
        "low": "#3dd68c",
        "unknown": "#4e5d72",
    }

    for vendor in vendors:
        vid = vendor["id"]
        vendor_data = vendor.get("risk_data") or {}
        risk = vendor.get("threat_level", "unknown")

        nodes.append({
            "id": vid,
            "label": vendor.get("vendor_name", "Unknown"),
            "type": "vendor",
            "risk": risk,
            "color": risk_colors.get(risk, "#4e5d72"),
            "item_count": vendor_data.get("item_count", 0) if isinstance(vendor_data, dict) else 0,
            "cve_count": vendor_data.get("cve_count", 0) if isinstance(vendor_data, dict) else 0,
            "critical_count": vendor_data.get("critical_count", 0) if isinstance(vendor_data, dict) else 0,
            "products": vendor.get("products") or [],
            "category": vendor.get("category", ""),
        })

        links.append({
            "source": f"client_{client_id}",
            "target": vid,
            "risk": risk,
            "color": risk_colors.get(risk, "#2a2f3e"),
            "width": 3 if risk == "high" else 2 if risk == "medium" else 1,
        })

        # Sub-nodes for products
        products = vendor.get("products") or []
        if isinstance(products, str):
            import json
            try:
                products = json.loads(products)
            except Exception:
                products = []
        for prod in (products or [])[:5]:
            prod_id = f"prod_{vid}_{prod.replace(' ','_')}"
            nodes.append({
                "id": prod_id,
                "label": prod,
                "type": "product",
                "risk": risk,
                "color": risk_colors.get(risk, "#4e5d72"),
                "item_count": 0,
            })
            links.append({"source": vid, "target": prod_id, "risk": risk,
                          "color": "#2a2f3e", "width": 1})

    return {
        "nodes": nodes,
        "links": links,
        "stats": {
            "total_vendors": len(vendors),
            "high_risk": sum(1 for v in vendors if v.get("threat_level") == "high"),
            "medium_risk": sum(1 for v in vendors if v.get("threat_level") == "medium"),
            "low_risk": sum(1 for v in vendors if v.get("threat_level") == "low"),
        },
    }
