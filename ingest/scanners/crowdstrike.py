"""
CrowdStrike Falcon Spotlight scanner fetcher.
OAuth2 client_credentials flow, then two-phase vuln query.
"""

import logging

import httpx

from .base import BaseScannerFetcher

logger = logging.getLogger(__name__)

CROWDSTRIKE_BASE = "https://api.crowdstrike.com"


class CrowdStrikeFetcher(BaseScannerFetcher):
    scanner_type = "crowdstrike"

    async def fetch(self) -> list[dict]:
        base = self.host_url or CROWDSTRIKE_BASE
        client_id = self._api_key()      # CrowdStrike client_id stored as api_key
        client_secret = self._secret_key()
        async with httpx.AsyncClient(timeout=60) as client:
            token = await self._get_token(client, base, client_id, client_secret)
            headers = {"Authorization": f"Bearer {token}"}
            vuln_ids = await self._query_vulns(client, base, headers)
            if not vuln_ids:
                return []
            return await self._get_vuln_details(client, base, headers, vuln_ids)

    async def _get_token(self, client, base, client_id, client_secret) -> str:
        resp = await client.post(
            f"{base}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret,
                  "grant_type": "client_credentials"},
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def _query_vulns(self, client, base, headers) -> list[str]:
        """Phase 1: query for vuln IDs (Spotlight)."""
        ids = []
        after = None
        for _ in range(10):  # paginate up to 10 pages
            params = {
                "filter": "status:'open'+severity.name:['Critical','High','Medium']",
                "limit": 400,
            }
            if after:
                params["after"] = after
            resp = await client.get(
                f"{base}/spotlight/queries/vulnerabilities/v1",
                headers=headers,
                params=params,
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("resources", [])
            ids.extend(batch)
            pagination = data.get("meta", {}).get("pagination", {})
            after = pagination.get("after")
            if not after or len(batch) < 400:
                break
        return ids

    async def _get_vuln_details(self, client, base, headers, vuln_ids: list[str]) -> list[dict]:
        """Phase 2: fetch details in batches of 400."""
        findings = []
        for i in range(0, len(vuln_ids), 400):
            batch = vuln_ids[i:i + 400]
            resp = await client.get(
                f"{base}/spotlight/entities/vulnerabilities/v2",
                headers=headers,
                params=[("ids", vid) for vid in batch],
            )
            if resp.status_code != 200:
                logger.warning("CrowdStrike detail fetch: %d", resp.status_code)
                continue
            for v in resp.json().get("resources", []):
                f = self._normalize(v)
                if f:
                    findings.append(f)
        return findings

    def _normalize(self, v: dict) -> dict | None:
        try:
            cve = v.get("cve", {})
            cvss = None
            for key in ("base_score", "cvss_v3_base_score", "cvss_v2_base_score"):
                val = cve.get(key)
                if val is not None:
                    try:
                        cvss = float(val); break
                    except (TypeError, ValueError):
                        pass
            cve_id = cve.get("id", "")
            host = v.get("host_info", {})
            return {
                "plugin_id": v.get("id", ""),
                "title": cve.get("description", cve_id or "Unknown") or cve_id,
                "severity": self._sev(cvss),
                "cvss": cvss,
                "cve_id": cve_id,
                "hostname": host.get("hostname", ""),
                "ip_address": host.get("local_ip", ""),
                "description": (cve.get("description") or "")[:2000],
                "solution": "",
                "raw": {"cve_id": cve_id, "host_aid": host.get("aid")},
            }
        except Exception as exc:
            logger.debug("CrowdStrike normalize error: %s", exc)
            return None
