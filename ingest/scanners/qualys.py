"""
Qualys VMDR scanner fetcher.
Uses Basic auth + XML API; parses DETECTION elements.
"""

import logging
from xml.etree import ElementTree as ET

import httpx

from .base import BaseScannerFetcher

logger = logging.getLogger(__name__)

QUALYS_API_BASE = "https://qualysapi.qg2.apps.qualys.com"


class QualysFetcher(BaseScannerFetcher):
    scanner_type = "qualys"

    async def fetch(self) -> list[dict]:
        base = self.host_url or QUALYS_API_BASE
        username = self._username()
        password = self._password()
        headers = {
            "X-Requested-With": "PhantomFeed",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        params = {
            "action": "list",
            "show_results": "1",
            "status": "Active,New,Re-Opened",
            "severities": "3,4,5",
            "truncation_limit": "500",
        }
        async with httpx.AsyncClient(timeout=120, verify=True) as client:
            resp = await client.post(
                f"{base}/api/2.0/fo/asset/host/vm/detection/",
                auth=(username, password),
                headers=headers,
                data=params,
            )
            resp.raise_for_status()
            return self._parse_xml(resp.text)

    def _parse_xml(self, xml_text: str) -> list[dict]:
        findings = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.error("Qualys XML parse error: %s", exc)
            return findings
        for host in root.iter("HOST"):
            hostname = host.findtext("DNS", default="")
            ip_address = host.findtext("IP", default="")
            for detection in host.iter("DETECTION"):
                try:
                    qid = detection.findtext("QID", default="")
                    severity_num = int(detection.findtext("SEVERITY", default="0") or 0)
                    cvss_raw = detection.findtext("CVSS_BASE", default="")
                    cvss = None
                    try:
                        cvss = float(cvss_raw) if cvss_raw else None
                    except (TypeError, ValueError):
                        pass
                    # Map Qualys severity 1-5 to CVSS-like for our _sev()
                    if cvss is None:
                        cvss = {5: 9.5, 4: 7.5, 3: 5.0, 2: 2.5, 1: 0.5}.get(severity_num)
                    cve_ids_text = detection.findtext("CVE_IDS", default="") or ""
                    cve_id = cve_ids_text.split(",")[0].strip() if cve_ids_text else ""
                    title = detection.findtext("VULN_TITLE", default=f"QID-{qid}")
                    findings.append({
                        "plugin_id": qid,
                        "title": title,
                        "severity": self._sev(cvss),
                        "cvss": cvss,
                        "cve_id": cve_id,
                        "hostname": hostname,
                        "ip_address": ip_address,
                        "description": (detection.findtext("RESULTS", default="") or "")[:2000],
                        "solution": "",
                        "raw": {"qid": qid, "severity_num": severity_num},
                    })
                except Exception as exc:
                    logger.debug("Qualys detection parse error: %s", exc)
        return findings
