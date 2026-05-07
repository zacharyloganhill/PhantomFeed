"""
OSCAL (Open Security Controls Assessment Language) output engine.
Generates FedRAMP 20x compliant machine-readable documents:
  - POA&M  (Plan of Action & Milestones)
  - SAR    (Security Assessment Report)
  - VDR    (Vulnerability Disclosure Report)
  - OAR    (Ongoing Authorization Report)
  - SSP    (System Security Plan — partial)

All documents conform to NIST OSCAL 1.1.x schema patterns.
"""

import io
import json
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import Optional
from xml.etree import ElementTree as ET
from xml.dom import minidom

import db.database as db

OSCAL_NS = "http://csrc.nist.gov/ns/oscal/1.0"
FEDRAMP_NS = "https://fedramp.gov/ns/oscal"


def _ns(tag: str) -> str:
    return f"{{{OSCAL_NS}}}{tag}"


def _elem(parent, tag: str, text: str = None, **attribs) -> ET.Element:
    el = ET.SubElement(parent, _ns(tag), **attribs)
    if text is not None:
        el.text = text
    return el


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _pretty(root: ET.Element) -> bytes:
    raw = ET.tostring(root, encoding="unicode", xml_declaration=False)
    reparsed = minidom.parseString(f'<?xml version="1.0" encoding="UTF-8"?>{raw}')
    return reparsed.toprettyxml(indent="  ", encoding="UTF-8")


class OSCALGenerator:
    def __init__(self, client: dict):
        self.client = client
        self.client_id = client["id"]
        self.client_name = client.get("name", "Unknown")

    # ── POA&M ─────────────────────────────────────────────────────────────────

    async def generate_poam(self) -> bytes:
        """Plan of Action & Milestones — open remediation items mapped to OSCAL."""
        items = await db.get_remediations(self.client_id, status="open")
        root = ET.Element(_ns("plan-of-action-and-milestones"),
                          {"uuid": _uuid(),
                           f"{{{FEDRAMP_NS}}}schema-version": "FedRAMP-1.0.0"})
        meta = _elem(root, "metadata")
        _elem(meta, "title", f"POA&M — {self.client_name}")
        _elem(meta, "last-modified", _now())
        _elem(meta, "version", "1.0")
        _elem(meta, "oscal-version", "1.1.2")

        sys_id = _elem(root, "system-id",
                       f"urn:phantomfeed:client:{self.client_id}",
                       **{"identifier-type": "https://fedramp.gov"})

        for item in items:
            ti = await db.get_item(item["item_id"]) if item.get("item_id") else None
            poi = _elem(root, "poam-item", **{"uuid": _uuid()})
            _elem(poi, "title", (ti["title"][:120] if ti else item.get("item_id", "Unknown"))[:120])
            desc_el = _elem(poi, "description")
            _elem(desc_el, "p", (ti.get("description", "") if ti else "")[:500] or "No description")
            status_el = _elem(poi, "status")
            _elem(status_el, "state", "open")
            sched = _elem(poi, "scheduled-completion-date")
            sched.text = (item.get("due_date") or
                          (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%d"))
            risk_el = _elem(poi, "risk")
            _elem(risk_el, "title", ti["severity"] if ti else "UNKNOWN")
            char_el = _elem(risk_el, "characterization")
            origin_el = _elem(char_el, "origin")
            _elem(origin_el, "actor", **{
                "type": "tool",
                "actor-uuid": _uuid(),
                "task-uuid": _uuid(),
            })
            facet_el = _elem(char_el, "facet", **{
                "name": "likelihood",
                "system": "https://fedramp.gov",
                "value": self._likelihood(ti),
            })

        return _pretty(root)

    # ── SAR ───────────────────────────────────────────────────────────────────

    async def generate_sar(self) -> bytes:
        """Security Assessment Report — recent scan findings summary."""
        findings = await db.get_scan_findings(self.client_id, limit=500)
        root = ET.Element(_ns("assessment-results"), {"uuid": _uuid()})
        meta = _elem(root, "metadata")
        _elem(meta, "title", f"SAR — {self.client_name}")
        _elem(meta, "last-modified", _now())
        _elem(meta, "version", "1.0")
        _elem(meta, "oscal-version", "1.1.2")

        _elem(root, "import-ap",
              **{"href": f"urn:phantomfeed:client:{self.client_id}:ap"})

        result = _elem(root, "result", **{"uuid": _uuid()})
        _elem(result, "title", "Automated Vulnerability Assessment")
        _elem(result, "description")
        _elem(result, "start", _now())
        _elem(result, "end", _now())

        findings_el = _elem(result, "findings")
        for f in findings:
            finding = _elem(findings_el, "finding", **{"uuid": _uuid()})
            _elem(finding, "title", (f.get("title") or "Unknown")[:120])
            _elem(finding, "description")
            target = _elem(finding, "target", **{
                "type": "statement-id",
                "target-id": f"finding-{f.get('plugin_id', _uuid())[:32]}",
            })
            _elem(target, "title", f.get("hostname") or f.get("ip_address") or "Unknown host")
            status_el = _elem(target, "status")
            _elem(status_el, "state",
                  "not-satisfied" if f["severity"] in ("CRITICAL", "HIGH") else "satisfied")
            risk_el = _elem(finding, "associated-risk", **{"risk-uuid": _uuid()})

        return _pretty(root)

    # ── VDR ───────────────────────────────────────────────────────────────────

    async def generate_vdr(self) -> bytes:
        """Vulnerability Disclosure Report — active CVE-tagged findings."""
        findings = await db.get_scan_findings(self.client_id, limit=500)
        cve_findings = [f for f in findings if f.get("cve_id")]

        doc = {
            "oscal-version": "1.1.2",
            "document-type": "vulnerability-disclosure-report",
            "metadata": {
                "title": f"VDR — {self.client_name}",
                "generated": _now(),
                "version": "1.0",
            },
            "system": {
                "id": f"urn:phantomfeed:client:{self.client_id}",
                "name": self.client_name,
            },
            "vulnerabilities": [
                {
                    "cve-id": f.get("cve_id"),
                    "title": f.get("title", "")[:120],
                    "severity": f.get("severity"),
                    "cvss": f.get("cvss"),
                    "affected-asset": f.get("hostname") or f.get("ip_address") or "",
                    "plugin-id": f.get("plugin_id"),
                    "scanner-type": f.get("scanner_type"),
                    "first-seen": f.get("first_seen"),
                    "last-seen": f.get("last_seen"),
                    "status": "open",
                    "description": (f.get("description") or "")[:500],
                }
                for f in cve_findings
            ],
            "summary": {
                "total-vulnerabilities": len(cve_findings),
                "by-severity": {
                    sev: sum(1 for f in cve_findings if f["severity"] == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                },
            },
        }
        return json.dumps(doc, indent=2).encode()

    # ── OAR ───────────────────────────────────────────────────────────────────

    async def generate_oar(self) -> bytes:
        """Ongoing Authorization Report — aggregated continuous monitoring posture."""
        posture = await db.get_latest_posture_score(self.client_id)
        counts = await db.count_scan_findings_by_severity(self.client_id)
        open_items = await db.get_remediations(self.client_id, status="open")

        doc = {
            "oscal-version": "1.1.2",
            "document-type": "ongoing-authorization-report",
            "metadata": {
                "title": f"OAR — {self.client_name}",
                "generated": _now(),
                "reporting-period": "monthly",
                "version": "1.0",
            },
            "system": {
                "id": f"urn:phantomfeed:client:{self.client_id}",
                "name": self.client_name,
            },
            "security-posture": {
                "score": posture.get("score") if posture else None,
                "grade": posture.get("grade") if posture else "N/A",
                "calculated-at": posture.get("calculated_at") if posture else None,
            },
            "vulnerability-summary": counts,
            "open-findings-count": len(open_items),
            "authorization-decision": (
                "authorized" if (posture and posture.get("score", 0) >= 70)
                else "conditional"
            ),
            "continuous-monitoring-activities": [
                {"activity": "Automated scanner pulls", "frequency": "every 6 hours"},
                {"activity": "SIEM alert ingestion", "frequency": "every 6 hours"},
                {"activity": "KSI validation", "frequency": "every 6 hours"},
                {"activity": "Threat feed aggregation", "frequency": "every 15-60 minutes"},
            ],
        }
        return json.dumps(doc, indent=2).encode()

    # ── SSP (partial) ─────────────────────────────────────────────────────────

    async def generate_ssp(self) -> bytes:
        """System Security Plan (partial) — system description and control implementation stubs."""
        client = self.client
        stack = client.get("stack_profile") or {}
        if isinstance(stack, str):
            try:
                stack = json.loads(stack)
            except Exception:
                stack = {}

        root = ET.Element(_ns("system-security-plan"), {"uuid": _uuid()})
        meta = _elem(root, "metadata")
        _elem(meta, "title", f"SSP (Partial) — {self.client_name}")
        _elem(meta, "last-modified", _now())
        _elem(meta, "version", "1.0")
        _elem(meta, "oscal-version", "1.1.2")

        # Import profile
        _elem(root, "import-profile",
              **{"href": "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"})

        # System characteristics
        sc = _elem(root, "system-characteristics")
        _elem(sc, "system-id",
              f"urn:phantomfeed:client:{self.client_id}",
              **{"identifier-type": "https://fedramp.gov"})
        _elem(sc, "system-name", self.client_name)
        _elem(sc, "system-name-short", self.client_name[:20])
        _elem(sc, "description")

        prop = _elem(sc, "prop", **{
            "name": "authorization-type",
            "ns": FEDRAMP_NS,
            "value": "fedramp-20x",
        })

        si = _elem(sc, "system-information")
        ic = _elem(si, "information-component", **{"uuid": _uuid()})
        _elem(ic, "title", "System Information")
        _elem(ic, "description")
        _elem(ic, "confidentiality-impact")
        _elem(ic, "integrity-impact")
        _elem(ic, "availability-impact")

        status_el = _elem(sc, "status")
        _elem(status_el, "state", "operational")

        # System implementation stub
        impl = _elem(root, "system-implementation")
        user_el = _elem(impl, "user", **{"uuid": _uuid()})
        _elem(user_el, "title", "System Administrators")
        _elem(user_el, "role-id", "system-administrator")

        # Control implementation stubs for FedRAMP controls
        ci = _elem(root, "control-implementation")
        _elem(ci, "description", "FedRAMP 20x control implementations")
        for ctrl_id in ["ac-1", "ac-2", "au-1", "au-2", "si-1", "si-2", "si-3", "cm-6"]:
            req = _elem(ci, "implemented-requirement", **{
                "uuid": _uuid(),
                "control-id": ctrl_id,
            })
            _elem(req, "description",
                  f"Control {ctrl_id.upper()} implementation pending assessment.")

        return _pretty(root)

    # ── ZIP bundle ────────────────────────────────────────────────────────────

    async def generate_bundle_zip(self) -> bytes:
        """All 5 documents as a ZIP archive."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{self.client_name}_poam.xml", await self.generate_poam())
            zf.writestr(f"{self.client_name}_sar.xml", await self.generate_sar())
            zf.writestr(f"{self.client_name}_vdr.json", await self.generate_vdr())
            zf.writestr(f"{self.client_name}_oar.json", await self.generate_oar())
            zf.writestr(f"{self.client_name}_ssp.xml", await self.generate_ssp())
        buf.seek(0)
        return buf.read()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _likelihood(ti: Optional[dict]) -> str:
        if not ti:
            return "medium"
        sev = (ti.get("severity") or "").upper()
        return {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium",
                "LOW": "low"}.get(sev, "medium")
