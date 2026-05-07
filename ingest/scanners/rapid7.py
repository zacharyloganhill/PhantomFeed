"""
Rapid7 InsightVM scanner fetcher.
Uses session-based REST API with paginated asset+vulnerability endpoints.
"""

import logging

import httpx

from .base import BaseScannerFetcher

logger = logging.getLogger(__name__)


class Rapid7Fetcher(BaseScannerFetcher):
    scanner_type = "rapid7"

    async def fetch(self) -> list[dict]:
        base = self.host_url  # e.g. https://your-console:3780
        username = self._username()
        password = self._password()
        findings = []
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            auth = (username, password)
            # Paginate assets
            page, page_size = 0, 100
            while True:
                resp = await client.get(
                    f"{base}/api/3/assets",
                    auth=auth,
                    params={"page": page, "size": page_size},
                )
                resp.raise_for_status()
                data = resp.json()
                assets = data.get("resources", [])
                for asset in assets:
                    asset_id = asset["id"]
                    asset_hostname = asset.get("hostName", "")
                    asset_ip = asset.get("ip", "")
                    vulns = await self._get_asset_vulns(client, base, auth, asset_id)
                    for v in vulns:
                        v["hostname"] = asset_hostname
                        v["ip_address"] = asset_ip
                        v["asset_id"] = str(asset_id)
                        findings.append(v)
                if page >= data.get("page", {}).get("totalPages", 1) - 1:
                    break
                page += 1
                if page > 20:  # safety cap
                    break
        return findings

    async def _get_asset_vulns(self, client, base, auth, asset_id) -> list[dict]:
        findings = []
        page, page_size = 0, 100
        while True:
            resp = await client.get(
                f"{base}/api/3/assets/{asset_id}/vulnerabilities",
                auth=auth,
                params={"page": page, "size": page_size},
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            for v in data.get("resources", []):
                f = await self._normalize_vuln(client, base, auth, v)
                if f:
                    findings.append(f)
            if page >= data.get("page", {}).get("totalPages", 1) - 1:
                break
            page += 1
            if page > 5:
                break
        return findings

    async def _normalize_vuln(self, client, base, auth, v: dict) -> dict | None:
        try:
            vuln_id = v.get("id", "")
            status = v.get("status", "")
            if status == "fixed":
                return None
            cvss = None
            for score_key in ("cvssV3Score", "cvssV2Score", "cvssScore"):
                s = v.get(score_key)
                if s:
                    try:
                        cvss = float(s); break
                    except (TypeError, ValueError):
                        pass
            # Fetch vuln details for title/description (cached by vuln_id in practice)
            detail = await self._get_vuln_detail(client, base, auth, vuln_id)
            title = detail.get("title", vuln_id)
            description = detail.get("description", {}).get("text", "")[:2000]
            solution = detail.get("solution", {}).get("text", "")
            cves = detail.get("cves", [])
            cve_id = cves[0] if cves else ""
            return {
                "plugin_id": str(vuln_id),
                "title": title,
                "severity": self._sev(cvss),
                "cvss": cvss,
                "cve_id": cve_id,
                "description": description,
                "solution": solution,
                "raw": {"vuln_id": vuln_id, "status": status},
            }
        except Exception as exc:
            logger.debug("Rapid7 normalize error: %s", exc)
            return None

    async def _get_vuln_detail(self, client, base, auth, vuln_id) -> dict:
        try:
            resp = await client.get(f"{base}/api/3/vulnerabilities/{vuln_id}", auth=auth)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}
