"""
ThreatPulse — Executive Report PDF Generator
Produces a per-client security posture brief using ReportLab.
"""

import io
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from auth.auth import decode_token, require_client_access
import db.database as db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Reports"])


async def _get_user_from_token_or_header(
    request: Request,
    token: str = Query(None),
) -> dict:
    """Accept JWT from ?token= query param or Authorization: Bearer header."""
    raw = token
    if not raw:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw = auth_header[7:]
    if not raw:
        raise HTTPException(401, "Not authenticated")
    payload = decode_token(raw)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token")
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(401, "User not found")
    return user


@router.get("/clients/{client_id}/report/pdf",
            summary="Generate executive security report PDF")
async def generate_pdf_report(
    client_id: str,
    user: dict = Depends(_get_user_from_token_or_header),
):
    require_client_access(user, client_id)
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    data = await _collect_data(client_id, client)
    pdf_bytes = _build_pdf(data)

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    safe_name = client["name"].replace(" ", "_").replace("/", "-")
    filename = f"ThreatPulse_Executive_Report_{safe_name}_{date_str}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Data collection ───────────────────────────────────────────────────────────

async def _collect_data(client_id: str, client: dict) -> dict:
    conn = db.get_db()

    # Threat feed stats (global)
    stats = await db.get_stats()

    # Top 10 CRITICAL threat items
    async with conn.execute(
        "SELECT title, category, feed_label, cvss, published_at "
        "FROM threat_items WHERE severity='CRITICAL' "
        "ORDER BY fetched_at DESC LIMIT 10"
    ) as cur:
        top_critical = [dict(r) for r in await cur.fetchall()]

    # Top 10 HIGH threat items
    async with conn.execute(
        "SELECT title, category, feed_label, cvss, published_at "
        "FROM threat_items WHERE severity='HIGH' "
        "ORDER BY fetched_at DESC LIMIT 10"
    ) as cur:
        top_high = [dict(r) for r in await cur.fetchall()]

    # KSI results
    ksi_results = await db.get_latest_ksi_results(client_id)

    # Scan findings by severity
    scan_counts = await db.count_scan_findings_by_severity(client_id)

    # Remediation metrics
    async with conn.execute(
        "SELECT COUNT(*) as cnt FROM remediation_items "
        "WHERE client_id=? AND status='open'", (client_id,)
    ) as cur:
        open_rem = (await cur.fetchone())["cnt"]
    async with conn.execute(
        "SELECT COUNT(*) as cnt FROM remediation_items "
        "WHERE client_id=? AND is_overdue=1", (client_id,)
    ) as cur:
        overdue_rem = (await cur.fetchone())["cnt"]

    # Dark web alerts
    dw_alerts = await db.get_darkweb_alerts(client_id, limit=500)
    dw_unack  = sum(1 for a in dw_alerts if not a.get("is_acknowledged"))
    dw_by_type = {}
    for a in dw_alerts:
        t = a.get("alert_type", "unknown")
        dw_by_type[t] = dw_by_type.get(t, 0) + 1

    return {
        "client": client,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "stats": stats,
        "top_critical": top_critical,
        "top_high": top_high,
        "ksi_results": ksi_results,
        "scan_counts": scan_counts,
        "open_remediation": open_rem,
        "overdue_remediation": overdue_rem,
        "dw_total": len(dw_alerts),
        "dw_unack": dw_unack,
        "dw_by_type": dw_by_type,
    }


# ── PDF Build ─────────────────────────────────────────────────────────────────

def _build_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    # ── Palette ──────────────────────────────────────────────────────────────
    C_NAVY   = colors.HexColor("#0c1420")
    C_TEAL   = colors.HexColor("#00d4aa")
    C_RED    = colors.HexColor("#f0595a")
    C_AMBER  = colors.HexColor("#e8a530")
    C_BLUE   = colors.HexColor("#4d9de0")
    C_PURPLE = colors.HexColor("#9b8ef5")
    C_GREEN  = colors.HexColor("#3dd68c")
    C_LGRAY  = colors.HexColor("#f0f3f7")
    C_MGRAY  = colors.HexColor("#8a9bb0")
    C_DGRAY  = colors.HexColor("#2d3748")
    C_WHITE  = colors.white
    C_BLACK  = colors.HexColor("#0d1117")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.6*inch, bottomMargin=0.6*inch,
    )

    # ── Styles ───────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def sty(name, **kw):
        base = styles["Normal"]
        return ParagraphStyle(name, parent=base, **kw)

    S_H1   = sty("H1",   fontName="Helvetica-Bold", fontSize=22, textColor=C_BLACK, spaceAfter=4)
    S_H2   = sty("H2",   fontName="Helvetica-Bold", fontSize=13, textColor=C_NAVY,  spaceAfter=6, spaceBefore=14)
    S_H3   = sty("H3",   fontName="Helvetica-Bold", fontSize=10, textColor=C_NAVY,  spaceAfter=4, spaceBefore=8)
    S_BODY = sty("BODY", fontName="Helvetica",      fontSize=9,  textColor=C_DGRAY, leading=14, spaceAfter=4)
    S_MUTED= sty("MUTED",fontName="Helvetica",      fontSize=8,  textColor=C_MGRAY, leading=12)
    S_MONO = sty("MONO", fontName="Courier",        fontSize=8,  textColor=C_DGRAY, leading=12)
    S_CTR  = sty("CTR",  fontName="Helvetica",      fontSize=9,  textColor=C_DGRAY, alignment=TA_CENTER)
    S_LABEL= sty("LABEL",fontName="Helvetica-Bold", fontSize=7,  textColor=C_MGRAY, leading=10)
    S_BIG  = sty("BIG",  fontName="Helvetica-Bold", fontSize=28, textColor=C_TEAL,  leading=32)
    S_COVER_TITLE = sty("COVER_TITLE", fontName="Helvetica-Bold", fontSize=32, textColor=C_WHITE, leading=38)
    S_COVER_SUB   = sty("COVER_SUB",   fontName="Helvetica",      fontSize=12, textColor=C_TEAL,  leading=16)
    S_COVER_META  = sty("COVER_META",  fontName="Helvetica",      fontSize=10, textColor=C_MGRAY, leading=14)

    client  = data["client"]
    stats   = data["stats"]
    sev     = stats.get("by_severity", {})
    ksi     = data["ksi_results"]
    dw_type = data["dw_by_type"]

    story = []
    W = doc.width

    # ─── COVER PAGE ──────────────────────────────────────────────────────────

    # Dark header band
    cover_tbl = Table(
        [[
            Paragraph("THREATPULSE", sty("CT", fontName="Helvetica-Bold", fontSize=11,
                       textColor=C_TEAL, letterSpacing=3)),
            Paragraph("INTELLIGENCE PLATFORM", sty("CR", fontName="Helvetica", fontSize=8,
                       textColor=C_MGRAY, alignment=TA_RIGHT)),
        ]],
        colWidths=[W/2, W/2],
    )
    cover_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_NAVY),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LEFTPADDING",  (0,0), (-1,-1), 16),
        ("RIGHTPADDING", (0,0), (-1,-1), 16),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(cover_tbl)
    story.append(Spacer(1, 0.5*inch))

    story.append(Paragraph("EXECUTIVE SECURITY REPORT", sty("CS",
        fontName="Helvetica-Bold", fontSize=9, textColor=C_TEAL, letterSpacing=2)))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(client["name"], sty("CN",
        fontName="Helvetica-Bold", fontSize=28, textColor=C_BLACK, leading=34)))
    story.append(Spacer(1, 0.15*inch))
    story.append(HRFlowable(width=W, thickness=2, color=C_TEAL, spaceAfter=12))

    story.append(Paragraph(f"Generated: {data['generated_at']}", S_MUTED))
    story.append(Paragraph("Classification: CONFIDENTIAL — For authorized personnel only", S_MUTED))
    story.append(Spacer(1, 0.4*inch))

    # Posture score chips
    ksi_pass = sum(1 for r in ksi if r["status"] == "pass")
    ksi_total = len(ksi)
    ksi_pct  = int(100 * ksi_pass / ksi_total) if ksi_total else 0
    auth_status = _auth_label(ksi_pass, ksi_total)

    chip_data = [
        ["CRITICAL",              "HIGH",                 "KSI PASS RATE",  "DARK WEB"],
        [str(sev.get("CRITICAL",0)), str(sev.get("HIGH",0)), f"{ksi_pct}%", str(data["dw_total"])],
    ]
    chip_tbl = Table(chip_data, colWidths=[W/4]*4, rowHeights=[0.22*inch, 0.58*inch])
    chip_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(0,-1), C_RED),
        ("BACKGROUND",   (1,0),(1,-1), C_AMBER),
        ("BACKGROUND",   (2,0),(2,-1), C_TEAL),
        ("BACKGROUND",   (3,0),(3,-1), C_PURPLE),
        ("TEXTCOLOR",    (0,0),(0,-1), C_WHITE),
        ("TEXTCOLOR",    (1,0),(1,-1), C_BLACK),
        ("TEXTCOLOR",    (2,0),(2,-1), C_BLACK),
        ("TEXTCOLOR",    (3,0),(3,-1), C_WHITE),
        ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,0), 7),
        ("FONTNAME",     (0,1),(-1,1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,1),(-1,1), 22),
        ("ALIGN",        (0,0),(-1,-1), "CENTER"),
        ("VALIGN",       (0,0),(-1,0), "BOTTOM"),
        ("VALIGN",       (0,1),(-1,1), "TOP"),
        ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ("RIGHTPADDING", (0,0),(-1,-1), 8),
        ("TOPPADDING",   (0,0),(-1,0), 8),
        ("BOTTOMPADDING",(0,0),(-1,0), 2),
        ("TOPPADDING",   (0,1),(-1,1), 4),
        ("BOTTOMPADDING",(0,1),(-1,1), 8),
    ]))
    story.append(chip_tbl)
    story.append(Spacer(1, 0.25*inch))

    story.append(Paragraph(
        f"Authorization Status: <b>{auth_status}</b>",
        sty("AUTH", fontName="Helvetica-Bold", fontSize=11,
            textColor=C_GREEN if "AUTHORIZED" in auth_status else C_AMBER)
    ))
    story.append(PageBreak())

    # ─── SECTION 1: EXECUTIVE SUMMARY ────────────────────────────────────────
    _section_header(story, "01", "Executive Summary", C_NAVY, C_TEAL, W)

    total = stats.get("total", 0)
    new   = stats.get("new_count", 0)
    story.append(Paragraph(
        f"This report summarizes the current security posture for <b>{client['name']}</b> "
        f"as of {data['generated_at']}. The ThreatPulse platform is actively monitoring "
        f"<b>{total:,}</b> threat intelligence items across 27 sources, with <b>{new:,}</b> "
        f"new items ingested in the current cycle.",
        S_BODY
    ))
    story.append(Spacer(1, 0.1*inch))

    sum_rows = [
        ["Metric", "Value", "Status"],
        ["Critical Severity Items",   str(sev.get("CRITICAL",0)),   _status_label(sev.get("CRITICAL",0), 0, 5, 20)],
        ["High Severity Items",       str(sev.get("HIGH",0)),       _status_label(sev.get("HIGH",0), 0, 20, 100)],
        ["KEV (Known Exploited)",     str(stats.get("by_category",{}).get("kev",0)), "MONITOR"],
        ["KSI Compliance",            f"{ksi_pass}/{ksi_total}",    auth_status],
        ["Open Remediations",         str(data["open_remediation"]),_status_label(data["open_remediation"], 0, 1, 10)],
        ["Overdue Remediations",      str(data["overdue_remediation"]),_status_label(data["overdue_remediation"], 0, 1, 5)],
        ["Dark Web Alerts (Unacked)", str(data["dw_unack"]),        _status_label(data["dw_unack"], 0, 1, 5)],
    ]
    story.append(_make_table(sum_rows, [W*0.45, W*0.2, W*0.35], header=True))
    story.append(Spacer(1, 0.2*inch))

    # ─── SECTION 2: THREAT INTELLIGENCE ─────────────────────────────────────
    _section_header(story, "02", "Threat Intelligence Feed", C_NAVY, C_TEAL, W)

    cat = stats.get("by_category", {})
    sev_rows = [
        ["Severity",  "Count", "% of Feed"],
        ["CRITICAL",  str(sev.get("CRITICAL",0)), _pct(sev.get("CRITICAL",0), total)],
        ["HIGH",      str(sev.get("HIGH",0)),      _pct(sev.get("HIGH",0), total)],
        ["MEDIUM",    str(sev.get("MEDIUM",0)),    _pct(sev.get("MEDIUM",0), total)],
        ["LOW",       str(sev.get("LOW",0)),        _pct(sev.get("LOW",0), total)],
        ["INFO",      str(sev.get("INFO",0)),       _pct(sev.get("INFO",0), total)],
        ["TOTAL",     str(total),                  "100%"],
    ]
    cat_rows = [
        ["Category",     "Count"],
        ["CVEs",         str(cat.get("cve",0))],
        ["CISA KEV",     str(cat.get("kev",0))],
        ["Vendor Advisories", str(cat.get("vendor",0))],
        ["Malware / C2", str(cat.get("malware",0))],
        ["Supply Chain", str(cat.get("supply",0))],
        ["ICS / OT",     str(cat.get("ics",0))],
        ["Gov Advisories",str(cat.get("advisory",0))],
    ]

    side_tbl = Table(
        [[_make_table(sev_rows, [W*0.2, W*0.12, W*0.12], header=True),
          _make_table(cat_rows, [W*0.32, W*0.14], header=True)]],
        colWidths=[W*0.46, W*0.54],
    )
    side_tbl.setStyle(TableStyle([
        ("VALIGN",       (0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",  (0,0),(-1,-1), 0),
        ("RIGHTPADDING", (0,0),(-1,-1), 0),
        ("TOPPADDING",   (0,0),(-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
    ]))
    story.append(side_tbl)

    # Top Critical
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph("Top Critical & High Severity Items", S_H3))
    item_rows = [["Title", "Category", "Source"]]
    for item in (data["top_critical"] + data["top_high"])[:12]:
        title = (item.get("title") or "")[:72]
        if len(item.get("title","")) > 72:
            title += "..."
        item_rows.append([
            Paragraph(title, S_MONO),
            str(item.get("category","")[:10]),
            str(item.get("feed_label","")[:18]),
        ])
    story.append(_make_table(item_rows, [W*0.58, W*0.14, W*0.28], header=True))
    story.append(PageBreak())

    # ─── SECTION 3: FEDRAMP KSI STATUS ───────────────────────────────────────
    _section_header(story, "03", "FedRAMP 20x KSI Compliance", C_NAVY, C_TEAL, W)

    if not ksi:
        story.append(Paragraph(
            "No KSI validation has been run for this client. Trigger a validation "
            "from the FedRAMP dashboard to populate compliance data.", S_BODY))
    else:
        ksi_rows = [["KSI ID", "Name", "Status", "Score", "Details"]]
        for r in ksi:
            status_hex = {"pass": "#3dd68c", "conditional": "#e8a530",
                          "fail": "#f0595a", "error": "#8a9bb0"}.get(r.get("status",""), "#8a9bb0")
            score = r.get("score")
            score_str = f"{score:.0%}" if score is not None else "—"
            details = str(r.get("details", {}) or {})[:60]
            ksi_rows.append([
                r.get("ksi_id",""),
                r.get("ksi_name","")[:28],
                Paragraph(f'<font color="{status_hex}">'
                          f'<b>{(r.get("status","") or "").upper()}</b></font>', S_CTR),
                score_str,
                Paragraph(details[:60], S_MONO),
            ])
        story.append(_make_table(ksi_rows, [W*0.1, W*0.28, W*0.14, W*0.1, W*0.38], header=True))

    story.append(Spacer(1, 0.2*inch))

    # ─── SECTION 4: SCAN FINDINGS ─────────────────────────────────────────────
    _section_header(story, "04", "Vulnerability Scan Findings", C_NAVY, C_TEAL, W)

    scan = data["scan_counts"]
    if not scan:
        story.append(Paragraph(
            "No scanner findings for this client. Configure a vulnerability scanner "
            "(Tenable, Rapid7, Qualys, or CrowdStrike) in the FedRAMP dashboard to "
            "begin automated scanning.", S_BODY))
    else:
        scan_rows = [["Severity", "Finding Count"]]
        for sev_name in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            cnt = scan.get(sev_name, 0)
            if cnt:
                scan_rows.append([sev_name, str(cnt)])
        story.append(_make_table(scan_rows, [W*0.4, W*0.6], header=True))

    story.append(Spacer(1, 0.2*inch))

    # ─── SECTION 5: REMEDIATION STATUS ───────────────────────────────────────
    _section_header(story, "05", "Remediation Status", C_NAVY, C_TEAL, W)

    rem_rows = [
        ["Metric", "Value"],
        ["Open Remediation Items",    str(data["open_remediation"])],
        ["Overdue Items (Past SLA)",   str(data["overdue_remediation"])],
    ]
    story.append(_make_table(rem_rows, [W*0.6, W*0.4], header=True))
    story.append(Spacer(1, 0.1*inch))
    if data["overdue_remediation"] > 0:
        story.append(Paragraph(
            f"WARNING: {data['overdue_remediation']} remediation item(s) are past their SLA deadline. "
            "Immediate action is recommended to maintain FedRAMP authorization status.", S_BODY))

    story.append(Spacer(1, 0.2*inch))

    # ─── SECTION 6: DARK WEB ─────────────────────────────────────────────────
    _section_header(story, "06", "Dark Web Exposure", C_NAVY, C_TEAL, W)

    if data["dw_total"] == 0:
        story.append(Paragraph(
            "No dark web alerts detected for this client. ThreatPulse continuously monitors "
            "Pastebin, GitHub Gists, and ransomware leak sites for credential exposure.", S_BODY))
    else:
        dw_rows = [["Alert Type", "Count"]]
        labels = {
            "ransomware_listing": "Ransomware Listing",
            "hibp_breach":        "HIBP Credential Breach",
            "paste_leak":         "Paste Site Leak",
            "gist_leak":          "GitHub Gist Leak",
        }
        for t, cnt in dw_type.items():
            dw_rows.append([labels.get(t, t), str(cnt)])
        dw_rows.append(["TOTAL", str(data["dw_total"])])
        dw_rows.append(["Unacknowledged", str(data["dw_unack"])])
        story.append(_make_table(dw_rows, [W*0.6, W*0.4], header=True))

    story.append(Spacer(1, 0.3*inch))

    # Footer note
    story.append(HRFlowable(width=W, thickness=0.5, color=C_MGRAY, spaceAfter=6))
    story.append(Paragraph(
        f"Generated by ThreatPulse Intelligence Platform · {data['generated_at']} · "
        "This report is confidential and intended for authorized personnel only.",
        sty("FTR", fontName="Helvetica", fontSize=7, textColor=C_MGRAY, alignment=TA_CENTER)
    ))

    doc.build(story, onFirstPage=_add_page_num, onLaterPages=_add_page_num)
    return buf.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _section_header(story, num, title, bg, accent, width):
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph
    from reportlab.lib import colors

    tbl = Table(
        [[Paragraph(f'<font color="#00d4aa">{num}</font>  {title}',
                    ParagraphStyle("SH", fontName="Helvetica-Bold",
                                   fontSize=12, textColor=colors.white, leading=16))]],
        colWidths=[width],
        rowHeights=[0.45*inch],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor("#0c1420")),
        ("LEFTPADDING",  (0,0),(-1,-1), 14),
        ("RIGHTPADDING", (0,0),(-1,-1), 14),
        ("TOPPADDING",   (0,0),(-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
    ]))
    story.append(tbl)
    story.append(Paragraph("", ParagraphStyle("SP", spaceAfter=6)))


def _make_table(rows, col_widths, header=False):
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle

    C_NAVY  = colors.HexColor("#0c1420")
    C_LGRAY = colors.HexColor("#f0f3f7")
    C_MGRAY = colors.HexColor("#8a9bb0")

    tbl = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("TEXTCOLOR",   (0,0), (-1,-1), colors.HexColor("#2d3748")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f9fb")]),
        ("GRID",        (0,0), (-1,-1), 0.4, colors.HexColor("#dde3ec")),
        ("TOPPADDING",  (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
    ]
    if header:
        style += [
            ("BACKGROUND",  (0,0), (-1,0), C_NAVY),
            ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,0), 8),
        ]
    tbl.setStyle(TableStyle(style))
    return tbl



def _pct(val, total):
    if not total:
        return "0%"
    return f"{100 * val / total:.1f}%"


def _status_label(val, good, warn_thresh, bad_thresh):
    if val <= good:
        return "GOOD"
    if val <= warn_thresh:
        return "MONITOR"
    if val <= bad_thresh:
        return "WARNING"
    return "CRITICAL"


def _auth_label(passing, total):
    if total == 0:
        return "UNKNOWN"
    if passing == total:
        return "AUTHORIZED"
    if passing >= total * 0.8:
        return "CONDITIONAL"
    return "NOT AUTHORIZED"


def _add_page_num(canvas, doc):
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#8a9bb0"))
    canvas.drawRightString(
        doc.pagesize[0] - 0.75*inch,
        0.4*inch,
        f"Page {canvas.getPageNumber()} | ThreatPulse Executive Report | CONFIDENTIAL"
    )
    canvas.restoreState()
