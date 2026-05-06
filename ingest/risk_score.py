"""
PhantomFeed — Risk Scoring Engine

Produces a 0–10 composite risk score per threat item using:
  CVSS component  40%  — item's stored CVSS / 10 * 4.0
  EPSS component  40%  — FIRST EPSS probability * 4.0
  KEV bonus       20%  — 2.0 if category == 'kev' or CVE appears in CISA KEV catalog

EPSSCache fetches from FIRST and caches results for 6 hours to avoid hammering the API.
"""

import asyncio
import time
from typing import Optional

import httpx

import config

_EPSS_CACHE: dict[str, tuple[float, float]] = {}  # cve -> (score, expires_at)
_EPSS_TTL = 6 * 3600  # 6 hours

_kev_cves: set[str] = set()
_kev_loaded_at: float = 0.0
_KEV_TTL = 12 * 3600  # 12 hours


async def _load_kev_catalog() -> set[str]:
    global _kev_cves, _kev_loaded_at
    now = time.time()
    if _kev_cves and (now - _kev_loaded_at) < _KEV_TTL:
        return _kev_cves
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(config.CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
        _kev_cves = {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
        _kev_loaded_at = now
    except Exception:
        pass
    return _kev_cves


async def _fetch_epss(cve_id: str) -> float:
    now = time.time()
    cached = _EPSS_CACHE.get(cve_id)
    if cached and now < cached[1]:
        return cached[0]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(config.FIRST_EPSS_API, params={"cve": cve_id})
            r.raise_for_status()
            data = r.json()
        entries = data.get("data", [])
        score = float(entries[0]["epss"]) if entries else 0.0
    except Exception:
        score = 0.0
    _EPSS_CACHE[cve_id] = (score, now + _EPSS_TTL)
    return score


class RiskScorer:
    """
    Composite risk scorer.  Call calculate() to get a 0–10 float.
    Uses async I/O — must be awaited.
    """

    async def calculate(self, item: dict) -> float:
        cvss: Optional[float] = item.get("cvss")
        category: str = item.get("category", "")
        cve_ids: list[str] = item.get("cve_ids") or []

        # CVSS component (40%)
        cvss_component = 0.0
        if cvss is not None and cvss > 0:
            cvss_component = min(cvss, 10.0) / 10.0 * 4.0

        # EPSS component (40%) — use highest EPSS across all CVEs
        epss_component = 0.0
        if cve_ids:
            scores = await asyncio.gather(*[_fetch_epss(c) for c in cve_ids[:5]])
            best_epss = max(scores) if scores else 0.0
            epss_component = best_epss * 4.0

        # KEV bonus (20%)
        kev_bonus = 0.0
        if category == "kev":
            kev_bonus = 2.0
        elif cve_ids:
            catalog = await _load_kev_catalog()
            if any(c in catalog for c in cve_ids):
                kev_bonus = 2.0

        score = cvss_component + epss_component + kev_bonus
        return round(min(score, 10.0), 2)


_scorer = RiskScorer()


async def score_item(item: dict) -> float:
    """Module-level helper — reuses singleton scorer."""
    return await _scorer.calculate(item)
