"""
PhantomFeed — Peer Benchmarking Engine
Calculates posture scores and industry percentile rankings.

Score formula (0–100):
  SLA compliance   30 pts  (% remediation items closed before SLA)
  MTTR             30 pts  (mean time to remediate vs industry median)
  Open criticals   20 pts  (inverted: 0 open crit = 20 pts)
  Patch velocity   20 pts  (items patched in last 30d vs total open)
"""
from datetime import datetime, timedelta
from typing import Optional


# Industry baseline statistics (synthetic, IBM/Ponemon-informed)
INDUSTRY_BASELINES = {
    "Technology": {
        "avg_mttr_days": 18, "med_open_crit": 4, "avg_sla_pct": 72,
        "avg_score": 68, "p25": 55, "p50": 68, "p75": 80, "p90": 89,
    },
    "Finance": {
        "avg_mttr_days": 12, "med_open_crit": 2, "avg_sla_pct": 81,
        "avg_score": 74, "p25": 62, "p50": 74, "p75": 84, "p90": 92,
    },
    "Healthcare": {
        "avg_mttr_days": 28, "med_open_crit": 7, "avg_sla_pct": 61,
        "avg_score": 59, "p25": 44, "p50": 59, "p75": 72, "p90": 83,
    },
    "Government": {
        "avg_mttr_days": 35, "med_open_crit": 9, "avg_sla_pct": 55,
        "avg_score": 54, "p25": 40, "p50": 54, "p75": 68, "p90": 79,
    },
    "Retail": {
        "avg_mttr_days": 22, "med_open_crit": 5, "avg_sla_pct": 66,
        "avg_score": 63, "p25": 50, "p50": 63, "p75": 76, "p90": 86,
    },
    "Energy": {
        "avg_mttr_days": 30, "med_open_crit": 6, "avg_sla_pct": 58,
        "avg_score": 56, "p25": 42, "p50": 56, "p75": 70, "p90": 81,
    },
    "Education": {
        "avg_mttr_days": 40, "med_open_crit": 11, "avg_sla_pct": 49,
        "avg_score": 48, "p25": 33, "p50": 48, "p75": 62, "p90": 75,
    },
    "Manufacturing": {
        "avg_mttr_days": 25, "med_open_crit": 6, "avg_sla_pct": 63,
        "avg_score": 61, "p25": 47, "p50": 61, "p75": 74, "p90": 84,
    },
    "Legal": {
        "avg_mttr_days": 21, "med_open_crit": 4, "avg_sla_pct": 69,
        "avg_score": 65, "p25": 52, "p50": 65, "p75": 77, "p90": 87,
    },
}

DEFAULT_BASELINE = INDUSTRY_BASELINES["Technology"]

SCORE_GRADE = [
    (90, "A+"), (85, "A"), (80, "A-"),
    (75, "B+"), (70, "B"), (65, "B-"),
    (60, "C+"), (55, "C"), (50, "C-"),
    (40, "D"), (0,  "F"),
]


def _grade(score: float) -> str:
    for threshold, letter in SCORE_GRADE:
        if score >= threshold:
            return letter
    return "F"


def _percentile(score: float, baseline: dict) -> int:
    """Return approximate percentile rank vs industry."""
    if score >= baseline["p90"]:
        return 95
    if score >= baseline["p75"]:
        return int(75 + (score - baseline["p75"]) / max(1, baseline["p90"] - baseline["p75"]) * 15)
    if score >= baseline["p50"]:
        return int(50 + (score - baseline["p50"]) / max(1, baseline["p75"] - baseline["p50"]) * 25)
    if score >= baseline["p25"]:
        return int(25 + (score - baseline["p25"]) / max(1, baseline["p50"] - baseline["p25"]) * 25)
    return max(5, int(score / max(1, baseline["p25"]) * 25))


class BenchmarkingEngine:

    async def calculate_posture(self, client_id: str) -> dict:
        """Calculate current posture score for a client."""
        from db import database as db

        client = await db.get_client(client_id)
        if not client:
            return {"error": "Client not found"}

        stack = client.get("stack_profile") or {}
        industry = client.get("industry") or stack.get("industry") or "Technology"
        baseline = INDUSTRY_BASELINES.get(industry, DEFAULT_BASELINE)

        remediations = await db.get_remediations(client_id)
        items = await db.get_items(limit=500, sort="risk", client_id=client_id)

        now = datetime.utcnow()
        thirty_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")

        # ── SLA compliance score (30 pts) ──────────────────────────────────
        closed = [r for r in remediations if r.get("status") in ("patched", "mitigated", "accepted")]
        on_time = [r for r in closed if not r.get("is_overdue")]
        sla_pct = (len(on_time) / len(closed) * 100) if closed else baseline["avg_sla_pct"]
        sla_score = (sla_pct / 100) * 30

        # ── MTTR score (30 pts) ──────────────────────────────────────────
        mttr_values = []
        for r in closed:
            opened = r.get("created_at") or r.get("opened_at")
            closed_at = r.get("closed_at") or r.get("updated_at")
            if opened and closed_at:
                try:
                    d1 = datetime.fromisoformat(opened[:19])
                    d2 = datetime.fromisoformat(closed_at[:19])
                    mttr_values.append((d2 - d1).days)
                except Exception:
                    pass
        avg_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else baseline["avg_mttr_days"]
        # Better than baseline = more pts; cap at 30
        mttr_score = min(30, max(0, 30 * (baseline["avg_mttr_days"] / max(1, avg_mttr))))

        # ── Open criticals score (20 pts) ────────────────────────────────
        open_rems = [r for r in remediations if r.get("status") not in ("patched", "mitigated", "accepted")]
        open_crit_items = [r for r in open_rems if r.get("severity") == "CRITICAL"]
        open_crit_count = len(open_crit_items)
        # 0 criticals = 20 pts; linear decay; baseline med as reference
        med = baseline["med_open_crit"]
        crit_score = max(0, 20 - (open_crit_count / max(1, med * 2)) * 20)

        # ── Patch velocity (20 pts) ──────────────────────────────────────
        patched_30d = len([r for r in closed if (r.get("closed_at") or r.get("updated_at") or "") >= thirty_ago])
        total_open = len(open_rems) + patched_30d
        velocity_pct = patched_30d / max(1, total_open) * 100
        velocity_score = min(20, (velocity_pct / 100) * 20 * 1.5)  # slight bonus for high velocity

        total_score = round(sla_score + mttr_score + crit_score + velocity_score, 1)
        total_score = min(100, max(0, total_score))
        percentile = _percentile(total_score, baseline)
        grade = _grade(total_score)

        result = {
            "client_id": client_id,
            "client_name": client.get("name"),
            "industry": industry,
            "score": total_score,
            "grade": grade,
            "percentile": percentile,
            "components": {
                "sla_compliance": round(sla_score, 1),
                "mttr": round(mttr_score, 1),
                "open_criticals": round(crit_score, 1),
                "patch_velocity": round(velocity_score, 1),
            },
            "metrics": {
                "sla_pct": round(sla_pct, 1),
                "avg_mttr_days": round(avg_mttr, 1),
                "open_critical_count": open_crit_count,
                "patched_30d": patched_30d,
                "total_remediations": len(remediations),
            },
            "industry_baseline": {
                "avg_score": baseline["avg_score"],
                "avg_mttr_days": baseline["avg_mttr_days"],
                "avg_sla_pct": baseline["avg_sla_pct"],
                "med_open_crit": baseline["med_open_crit"],
            },
            "calculated_at": now.isoformat(),
        }

        # Persist to DB
        try:
            await db.save_posture_score(
                client_id, total_score, grade, percentile,
                sla_component=round(sla_score, 1),
                mttr_component=round(mttr_score, 1),
                open_crit_component=round(crit_score, 1),
                velocity_component=round(velocity_score, 1),
            )
        except Exception:
            pass

        return result

    async def get_posture_history(self, client_id: str, limit: int = 30) -> list:
        from db import database as db
        return await db.get_posture_history(client_id, limit)

    async def get_industry_benchmark(self, industry: str) -> dict:
        """Return benchmark stats for an industry."""
        baseline = INDUSTRY_BASELINES.get(industry, DEFAULT_BASELINE)
        return {
            "industry": industry,
            "available_industries": list(INDUSTRY_BASELINES.keys()),
            "baseline": baseline,
            "description": {
                "avg_score": "Average posture score across similar organizations",
                "p25": "Bottom quartile threshold",
                "p50": "Median posture score",
                "p75": "Top quartile threshold",
                "p90": "Top decile threshold",
            },
        }

    async def get_all_clients_ranking(self) -> list:
        """Calculate and rank all clients by posture score."""
        from db import database as db
        clients = await db.get_clients()
        results = []
        for client in clients:
            try:
                posture = await self.calculate_posture(client["id"])
                results.append({
                    "client_id": client["id"],
                    "client_name": client["name"],
                    "industry": posture.get("industry"),
                    "score": posture.get("score"),
                    "grade": posture.get("grade"),
                    "percentile": posture.get("percentile"),
                })
            except Exception:
                pass
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        for i, r in enumerate(results):
            r["rank"] = i + 1
        return results
