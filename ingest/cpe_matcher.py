"""
PhantomFeed — CPE Asset Matcher

Matches threat items to client assets using CPE strings, vendor/product tokens,
and keyword matching.

match_item_to_assets(item, assets) -> list of matches with confidence scores:
  1.0 — exact CPE string match
  0.8 — vendor + product match
  0.7 — vendor keyword appears in asset software field
  0.5 — vendor-only match
"""

import re
from typing import Optional


def _tok(s: str) -> set[str]:
    """Tokenise a string into lowercase words >= 3 chars."""
    if not s:
        return set()
    return {w.lower() for w in re.split(r"[\s\-_./\\]", s) if len(w) >= 3}


def _cpe_vendor_product(cpe: str) -> tuple[str, str]:
    """Extract vendor and product from a CPE 2.3 string."""
    parts = cpe.split(":")
    # cpe:2.3:a:vendor:product:...
    if len(parts) >= 5 and parts[0] in ("cpe", "cpe:2.3"):
        return parts[3], parts[4]
    # cpe:/a:vendor:product:...
    elif len(parts) >= 4:
        return parts[2], parts[3]
    return "", ""


def match_item_to_assets(item: dict, assets: list[dict]) -> list[dict]:
    """
    Returns list of dicts: {asset_id, client_id, match_type, confidence, asset}.
    """
    if not assets:
        return []

    raw = item.get("raw") or {}
    item_vendor  = (item.get("vendor") or "").lower().strip()
    item_product = (item.get("product") or "").lower().strip()

    # Gather CPE strings from item
    item_cpes: list[str] = []
    if raw.get("cpe"):
        item_cpes.append(str(raw["cpe"]).lower())
    for aff in (raw.get("affected") or []):
        if isinstance(aff, dict):
            for c in (aff.get("cpes") or []):
                item_cpes.append(str(c).lower())
        elif isinstance(aff, str) and aff.startswith("cpe:"):
            item_cpes.append(aff.lower())

    # Also extract from tags / cve_ids text
    tags_text = " ".join(str(t) for t in (item.get("tags") or []))

    matches = []
    seen_assets = set()

    for asset in assets:
        asset_id = asset.get("id", "")
        if asset_id in seen_assets:
            continue

        asset_software = (asset.get("software") or "").lower()
        asset_version  = (asset.get("version") or "").lower()
        asset_cpe      = (asset.get("cpe_string") or "").lower()
        asset_tokens   = _tok(asset_software) | _tok(asset.get("hostname") or "")

        confidence = 0.0
        match_type = ""

        # 1 — Exact CPE match
        if asset_cpe and item_cpes:
            for ic in item_cpes:
                if ic == asset_cpe:
                    confidence = 1.0
                    match_type = "cpe_exact"
                    break
                # CPE prefix match (ignore version)
                av, ap = _cpe_vendor_product(asset_cpe)
                iv, ip = _cpe_vendor_product(ic)
                if av and ap and av == iv and ap == ip:
                    confidence = max(confidence, 0.85)
                    match_type = "cpe_prefix"

        # 2 — Vendor + product token match
        if confidence < 0.8 and item_vendor and item_product:
            vtok = _tok(item_vendor)
            ptok = _tok(item_product)
            if vtok & asset_tokens and ptok & asset_tokens:
                confidence = max(confidence, 0.8)
                match_type = match_type or "vendor_product"

        # 3 — Vendor keyword in asset software
        if confidence < 0.7 and item_vendor:
            vtok = _tok(item_vendor)
            if vtok & asset_tokens:
                confidence = max(confidence, 0.7)
                match_type = match_type or "vendor_keyword"
            elif item_vendor in asset_software:
                confidence = max(confidence, 0.7)
                match_type = match_type or "vendor_keyword"

        # 4 — Vendor-only match via tokens in any field
        if confidence < 0.5 and item_vendor:
            all_asset_text = " ".join([
                asset.get("software") or "",
                asset.get("hostname") or "",
                asset.get("os") or "",
                asset.get("cpe_string") or "",
            ]).lower()
            vtok = _tok(item_vendor)
            for vt in vtok:
                if len(vt) >= 4 and vt in all_asset_text:
                    confidence = max(confidence, 0.5)
                    match_type = match_type or "vendor_only"
                    break

        if confidence >= 0.5:
            matches.append({
                "asset_id": asset_id,
                "client_id": asset.get("client_id", ""),
                "match_type": match_type,
                "confidence": round(confidence, 2),
                "asset": asset,
            })
            seen_assets.add(asset_id)

    # Sort by confidence descending
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches
