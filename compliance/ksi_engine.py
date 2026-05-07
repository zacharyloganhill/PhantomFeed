"""
FedRAMP 20x KSI validation engine.
Runs all 7 KSI checks against live DB state and persists results.
Scheduled every 6 hours by APScheduler.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional

import db.database as db
from compliance.ksi_definitions import KSI_DEFINITIONS, KSI_LOOKUP

logger = logging.getLogger(__name__)


class KSIEngine:
    def __init__(self, client_id: str):
        self.client_id = client_id

    async def validate_all(self) -> list[dict]:
        """Run all KSI checks and store results. Returns list of result dicts."""
        results = []
        for ksi in KSI_DEFINITIONS:
            result = await self._validate_one(ksi)
            result["client_id"] = self.client_id
            await db.save_ksi_result(result)
            results.append(result)
        logger.info("KSI validation complete for client %s: %d checks",
                    self.client_id, len(results))
        return results

    async def _validate_one(self, ksi: dict) -> dict:
        ksi_id = ksi["id"]
        now = datetime.utcnow().isoformat()
        try:
            status, score, details = await self._run_check(ksi)
        except Exception as exc:
            logger.error("KSI %s check error: %s", ksi_id, exc)
            status, score, details = "error", 0.0, {"error": str(exc)}
        return {
            "id": str(uuid.uuid4()),
            "ksi_id": ksi_id,
            "ksi_name": ksi["name"],
            "status": status,      # "pass" | "conditional" | "fail" | "error"
            "score": score,        # 0.0 – 1.0
            "details": details,
            "validated_at": now,
        }

    async def _run_check(self, ksi: dict) -> tuple[str, float, dict]:
        cat = ksi["category"]
        if cat == "vulnerability":
            return await self._check_vulnerability()
        if cat == "patch":
            return await self._check_patch_currency()
        if cat == "monitoring":
            return await self._check_monitoring_coverage()
        if cat == "detection":
            return await self._check_siem_detection()
        if cat == "remediation":
            return await self._check_poam_timeliness()
        if cat == "supply_chain":
            return await self._check_supply_chain()
        if cat == "darkweb":
            return await self._check_darkweb()
        return "error", 0.0, {"error": f"Unknown category: {cat}"}

    # ── Individual checks ─────────────────────────────────────────────────────

    async def _check_vulnerability(self) -> tuple[str, float, dict]:
        """KSI-1: No CRITICAL/HIGH CVEs open longer than threshold."""
        thresholds = KSI_LOOKUP["KSI-1"]["thresholds"]
        findings = await db.get_scan_findings(self.client_id, limit=2000)
        now = datetime.utcnow()
        crit_over_15 = high_over_30 = 0
        crit_over_30 = high_over_60 = 0
        for f in findings:
            first_seen_str = f.get("first_seen") or f.get("last_seen") or ""
            if not first_seen_str:
                continue
            try:
                first_seen = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                continue
            age_days = (now - first_seen).days
            sev = f.get("severity", "INFO")
            if sev == "CRITICAL":
                if age_days > 15:
                    crit_over_15 += 1
                if age_days > 30:
                    crit_over_30 += 1
            elif sev == "HIGH":
                if age_days > 30:
                    high_over_30 += 1
                if age_days > 60:
                    high_over_60 += 1
        details = {
            "total_findings": len(findings),
            "critical_over_15d": crit_over_15,
            "critical_over_30d": crit_over_30,
            "high_over_30d": high_over_30,
            "high_over_60d": high_over_60,
        }
        if crit_over_15 == 0 and high_over_30 == 0:
            return "pass", 1.0, details
        if crit_over_30 == 0 and high_over_60 == 0:
            return "conditional", 0.6, details
        return "fail", 0.2, details

    async def _check_patch_currency(self) -> tuple[str, float, dict]:
        """KSI-2: Percentage of findings with solutions that are patched."""
        remediations = await db.get_remediations(self.client_id)
        if not remediations:
            return "pass", 1.0, {"message": "No open remediation items"}
        patched = sum(1 for r in remediations if r.get("status") == "patched")
        total = len(remediations)
        rate = patched / total if total else 1.0
        details = {"total": total, "patched": patched, "patch_rate": round(rate, 3)}
        thresholds = KSI_LOOKUP["KSI-2"]["thresholds"]
        if rate >= thresholds["pass"]["min_patch_rate"]:
            return "pass", rate, details
        if rate >= thresholds["conditional"]["min_patch_rate"]:
            return "conditional", rate * 0.8, details
        return "fail", rate * 0.5, details

    async def _check_monitoring_coverage(self) -> tuple[str, float, dict]:
        """KSI-3: All scanners polled within configured interval."""
        scanners = await db.get_scanner_configs(self.client_id)
        active = [s for s in scanners if s.get("is_active")]
        if not active:
            return "conditional", 0.5, {"message": "No scanners configured"}
        now = datetime.utcnow()
        lagging = []
        for s in active:
            last_polled = s.get("last_polled")
            if not last_polled:
                lagging.append({"id": s["id"], "label": s["label"], "reason": "never polled"})
                continue
            try:
                lp = datetime.fromisoformat(last_polled)
                lag_hours = (now - lp).total_seconds() / 3600
                interval = s.get("poll_interval_hours", 6)
                if lag_hours > interval + 2:  # 2h grace
                    lagging.append({"id": s["id"], "label": s["label"],
                                    "lag_hours": round(lag_hours, 1)})
            except ValueError:
                lagging.append({"id": s["id"], "label": s["label"], "reason": "invalid timestamp"})
        coverage = 1.0 - (len(lagging) / len(active))
        details = {"active_scanners": len(active), "lagging": lagging,
                   "coverage_rate": round(coverage, 3)}
        if not lagging:
            return "pass", 1.0, details
        if coverage >= 0.75:
            return "conditional", coverage * 0.8, details
        return "fail", coverage * 0.5, details

    async def _check_siem_detection(self) -> tuple[str, float, dict]:
        """KSI-4: At least one active SIEM receiving data."""
        siems = await db.get_siem_configs(self.client_id)
        active = [s for s in siems if s.get("is_active")]
        healthy = [s for s in active if (s.get("last_status") or "").startswith("ok")]
        details = {"total_siems": len(siems), "active": len(active), "healthy": len(healthy)}
        if healthy:
            return "pass", 1.0, details
        if active:
            return "conditional", 0.5, details
        return "fail", 0.0, details

    async def _check_poam_timeliness(self) -> tuple[str, float, dict]:
        """KSI-5: No overdue CRITICAL remediation items."""
        overdue = await db.get_overdue_remediations()
        client_overdue = [r for r in overdue
                          if r.get("client_id") == self.client_id or
                          not r.get("client_id")]
        # Cross-ref with scan findings severity
        crit_overdue = []
        for r in client_overdue:
            if r.get("priority", 0) >= 4:  # priority 4-5 = critical/high
                crit_overdue.append(r["id"])
        details = {"total_overdue": len(client_overdue), "critical_overdue": len(crit_overdue)}
        if len(crit_overdue) == 0:
            return "pass", 1.0, details
        if len(crit_overdue) <= 2:
            return "conditional", 0.6, details
        return "fail", 0.2, details

    async def _check_supply_chain(self) -> tuple[str, float, dict]:
        """KSI-6: Vendor risk assessments current."""
        vendors = await db.get_vendors(self.client_id)
        if not vendors:
            return "pass", 1.0, {"message": "No vendors configured"}
        cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
        assessed = [v for v in vendors
                    if (v.get("risk_data") or {}).get("assessed_at", "") >= cutoff]
        rate = len(assessed) / len(vendors)
        details = {"total_vendors": len(vendors), "recently_assessed": len(assessed),
                   "assessment_rate": round(rate, 3)}
        if rate >= 0.80:
            return "pass", rate, details
        if rate >= 0.50:
            return "conditional", rate * 0.8, details
        return "fail", rate * 0.5, details

    async def _check_darkweb(self) -> tuple[str, float, dict]:
        """KSI-7: No unacknowledged dark web alerts older than 48h."""
        alerts = await db.get_darkweb_alerts(self.client_id, unacknowledged_only=True)
        cutoff = (datetime.utcnow() - timedelta(hours=48)).isoformat()
        stale = [a for a in alerts if a.get("detected_at", "") < cutoff]
        details = {"unacknowledged_total": len(alerts), "stale_over_48h": len(stale)}
        if not stale:
            return "pass", 1.0, details
        cutoff_168 = (datetime.utcnow() - timedelta(hours=168)).isoformat()
        very_stale = [a for a in stale if a.get("detected_at", "") < cutoff_168]
        if not very_stale:
            return "conditional", 0.6, details
        return "fail", 0.2, details
