"""
FedRAMP 20x Key Security Indicators (KSI) definitions.
Each KSI maps to one or more automated checks against live DB state.
"""

KSI_DEFINITIONS = [
    {
        "id": "KSI-1",
        "name": "Vulnerability Management",
        "description": "No CRITICAL/HIGH CVEs open for more than 30 days",
        "category": "vulnerability",
        "thresholds": {
            "pass": {"max_crit_open_days": 15, "max_high_open_days": 30},
            "conditional": {"max_crit_open_days": 30, "max_high_open_days": 60},
        },
    },
    {
        "id": "KSI-2",
        "name": "Patch Currency",
        "description": "Scanner findings with available fixes applied within SLA",
        "category": "patch",
        "thresholds": {
            "pass": {"min_patch_rate": 0.90},
            "conditional": {"min_patch_rate": 0.75},
        },
    },
    {
        "id": "KSI-3",
        "name": "Continuous Monitoring Coverage",
        "description": "All active scanners polled within configured interval",
        "category": "monitoring",
        "thresholds": {
            "pass": {"max_poll_lag_hours": 8},
            "conditional": {"max_poll_lag_hours": 24},
        },
    },
    {
        "id": "KSI-4",
        "name": "Incident Detection",
        "description": "SIEM integrations active and receiving data",
        "category": "detection",
        "thresholds": {
            "pass": {"min_active_siems": 1, "max_poll_lag_hours": 8},
            "conditional": {"min_active_siems": 0, "max_poll_lag_hours": 48},
        },
    },
    {
        "id": "KSI-5",
        "name": "POA&M Timeliness",
        "description": "Open remediation items within SLA (no overdue CRITICAL items)",
        "category": "remediation",
        "thresholds": {
            "pass": {"max_overdue_critical": 0},
            "conditional": {"max_overdue_critical": 2},
        },
    },
    {
        "id": "KSI-6",
        "name": "Supply Chain Risk Monitoring",
        "description": "Vendor risk scores current (assessed within 30 days)",
        "category": "supply_chain",
        "thresholds": {
            "pass": {"min_vendor_assessment_rate": 0.80},
            "conditional": {"min_vendor_assessment_rate": 0.50},
        },
    },
    {
        "id": "KSI-7",
        "name": "Dark Web Exposure",
        "description": "No unacknowledged critical dark web alerts older than 48 hours",
        "category": "darkweb",
        "thresholds": {
            "pass": {"max_unack_alert_age_hours": 48},
            "conditional": {"max_unack_alert_age_hours": 168},
        },
    },
]

KSI_LOOKUP = {k["id"]: k for k in KSI_DEFINITIONS}
