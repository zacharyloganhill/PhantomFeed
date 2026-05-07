"""
Tenable scanner fetcher.
Supports both Tenable.io (cloud) and Tenable.sc (on-prem).
"""

import logging

import httpx

from .base import BaseScannerFetcher

logger = logging.getLogger(__name__)

TENABLE_IO_BASE = "https://cloud.tenable.com"


class TenableFetcher(BaseScannerFetcher):
    scanner_type = "tenable"

    async def fetch(self) -> list[dict]:
        mode = self.extra.get("mode", "io")  # "io" or "sc"
        if mode == "sc":
            return await self._fetch_sc()
        return await self._fetch_io()

    # ── Tenable.io ────────────────────────────────────────────────────────────

    async def _fetch_io(self) -> list[dict]:
        api_key = self._api_key()
        secret = self._secret_key()
        base = self.host_url or TENABLE_IO_BASE
        headers = {
            "X-ApiKeys": f"accessKey={api_key};secretKey={secret}",
            "Accept": "application/json",
        }
        findings = []
        async with httpx.AsyncClient(timeout=60) as client:
            # List recent vulnerability export chunks
            resp = await client.post(
                f"{base}/vulns/export",
                headers=headers,
                json={
                    "filters": {"severity": ["critical", "high", "medium"]},
                    "num_assets": 500,
                },
            )
            if resp.status_code == 200:
                export_uuid = resp.json().get("export_uuid")
                findings = await self._poll_io_export(client, base, headers, export_uuid)
            else:
                # Fallback: workbench API
                resp2 = await client.get(
                    f"{base}/workbenches/vulnerabilities",
                    headers=headers,
                    params={"date_range": 30, "filter.0.filter": "severity",
                            "filter.0.quality": "gte", "filter.0.value": "medium"},
                )
                resp2.raise_for_status()
                findings = self._parse_io_workbench(resp2.json())
        return findings

    async def _poll_io_export(self, client, base, headers, export_uuid) -> list[dict]:
        import asyncio
        for _ in range(30):
            status = await client.get(
                f"{base}/vulns/export/{export_uuid}/status", headers=headers
            )
            if status.json().get("status") == "FINISHED":
                break
            await asyncio.sleep(5)
        chunks_resp = await client.get(
            f"{base}/vulns/export/{export_uuid}/chunks_available", headers=headers
        )
        chunks = chunks_resp.json().get("chunks_available", [])
        findings = []
        for chunk in chunks[:10]:  # cap at 10 chunks
            chunk_resp = await client.get(
                f"{base}/vulns/export/{export_uuid}/chunks/{chunk}", headers=headers
            )
            for vuln in chunk_resp.json():
                f = self._normalize_io_vuln(vuln)
                if f:
                    findings.append(f)
        return findings

    def _parse_io_workbench(self, data: dict) -> list[dict]:
        findings = []
        for vuln in data.get("vulnerabilities", []):
            cvss = vuln.get("cvss_base_score") or vuln.get("severity_base_score")
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                cvss = None
            findings.append({
                "plugin_id": str(vuln.get("plugin_id", "")),
                "title": vuln.get("plugin_name", "Unknown"),
                "severity": self._sev(cvss),
                "cvss": cvss,
                "cve_id": "",
                "hostname": "",
                "ip_address": "",
                "description": vuln.get("description", ""),
                "solution": vuln.get("solution", ""),
                "raw": vuln,
            })
        return findings

    def _normalize_io_vuln(self, vuln: dict) -> dict | None:
        try:
            plugin = vuln.get("plugin", {})
            asset = vuln.get("asset", {})
            cvss = None
            for key in ("cvss3_base_score", "cvss_base_score"):
                v = plugin.get(key)
                if v:
                    try:
                        cvss = float(v); break
                    except (TypeError, ValueError):
                        pass
            cves = plugin.get("cve", [])
            cve_id = cves[0] if cves else ""
            return {
                "plugin_id": str(plugin.get("id", "")),
                "title": plugin.get("name", "Unknown vulnerability"),
                "severity": self._sev(cvss),
                "cvss": cvss,
                "cve_id": cve_id,
                "hostname": asset.get("hostname", ""),
                "ip_address": asset.get("ipv4", ""),
                "description": plugin.get("description", "")[:2000],
                "solution": plugin.get("solution", ""),
                "raw": {"plugin_id": plugin.get("id"), "asset_id": asset.get("uuid")},
            }
        except Exception as exc:
            logger.debug("Tenable.io normalize error: %s", exc)
            return None

    # ── Tenable.sc ────────────────────────────────────────────────────────────

    async def _fetch_sc(self) -> list[dict]:
        base = self.host_url
        username = self._username()
        password = self._password()
        async with httpx.AsyncClient(timeout=60, verify=False) as client:
            # Authenticate
            auth_resp = await client.post(
                f"{base}/rest/token",
                json={"username": username, "password": password},
            )
            auth_resp.raise_for_status()
            token = auth_resp.json()["response"]["token"]
            headers = {"X-SecurityCenter": token}
            # Query vuln summary
            resp = await client.get(
                f"{base}/rest/analysis",
                headers=headers,
                params={
                    "type": "vuln",
                    "query": json_query(),
                    "sourceType": "cumulative",
                    "tool": "vulndetails",
                    "startOffset": 0,
                    "endOffset": 500,
                },
            )
            resp.raise_for_status()
            return self._parse_sc_vulns(resp.json())

    def _parse_sc_vulns(self, data: dict) -> list[dict]:
        findings = []
        for v in data.get("response", {}).get("results", []):
            try:
                cvss = float(v.get("baseScore") or 0) or None
                findings.append({
                    "plugin_id": str(v.get("pluginID", "")),
                    "title": v.get("pluginName", "Unknown"),
                    "severity": self._sev(cvss),
                    "cvss": cvss,
                    "cve_id": v.get("cve", ""),
                    "hostname": v.get("dnsName", ""),
                    "ip_address": v.get("ip", ""),
                    "description": v.get("description", "")[:2000],
                    "solution": v.get("solution", ""),
                    "raw": {"plugin_id": v.get("pluginID"), "ip": v.get("ip")},
                })
            except Exception as exc:
                logger.debug("Tenable.sc parse error: %s", exc)
        return findings


def json_query():
    return {
        "filters": [{"filterName": "severity", "operator": "=", "value": "3,4"}]
    }
