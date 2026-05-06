"""
PhantomFeed — PDF Report Generator

Generates client threat intelligence reports as HTML (always available)
and PDF via WeasyPrint (if installed) or ReportLab as a fallback.

Entry point:
    generate_client_report(client, items, days) -> bytes (PDF) | str (HTML fallback)
    generate_client_report_html(client, items, days) -> str
"""

import io
from datetime import datetime, timedelta
from typing import Optional


SEVERITY_COLORS = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#d69e2e",
    "LOW":      "#38a169",
    "INFO":     "#718096",
}

COMPLIANCE_COLORS = {
    "CMMC": "#6b46c1",
    "NIST": "#2b6cb0",
    "CIS":  "#276749",
}


def _compliance_pill_style(tag: str) -> str:
    color = "#718096"
    for prefix, c in COMPLIANCE_COLORS.items():
        if tag.startswith(prefix):
            color = c
            break
    return f"background:{color};color:#fff;padding:2px 7px;border-radius:10px;font-size:11px;margin:2px;display:inline-block"


def generate_client_report_html(client: dict, items: list[dict], days: int = 7) -> str:
    now = datetime.utcnow()
    cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    report_date = now.strftime("%B %d, %Y %H:%M UTC")

    # Filter to items within the window
    recent = [i for i in items if (i.get("published_at") or "") >= cutoff]
    critical = [i for i in recent if i.get("severity") == "CRITICAL"]
    high = [i for i in recent if i.get("severity") == "HIGH"]

    # Compliance coverage
    all_ctags: set[str] = set()
    for item in recent:
        for t in (item.get("compliance_tags") or []):
            all_ctags.add(t)

    stack = client.get("stack_profile") or {}
    stack_html = ""
    if stack:
        stack_html = "<ul>" + "".join(f"<li><b>{k}:</b> {v}</li>" for k, v in stack.items()) + "</ul>"
    else:
        stack_html = "<p><em>No stack profile configured.</em></p>"

    def item_row(item: dict) -> str:
        sev = item.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#718096")
        rs = item.get("risk_score")
        rs_str = f"{rs:.1f}" if rs is not None else "—"
        cves = ", ".join(item.get("cve_ids") or []) or "—"
        ctags = item.get("compliance_tags") or []
        pills = "".join(f'<span style="{_compliance_pill_style(t)}">{t}</span>' for t in ctags[:4])
        return f"""<tr>
          <td><span style="color:{color};font-weight:bold">{sev}</span></td>
          <td style="font-size:12px">{item.get('title','')[:90]}</td>
          <td style="font-size:11px">{item.get('published_at','')[:10]}</td>
          <td style="text-align:center;font-weight:bold">{rs_str}</td>
          <td style="font-size:10px">{cves}</td>
          <td>{pills}</td>
        </tr>"""

    rows_html = "\n".join(item_row(i) for i in recent[:100])

    # Remediation checklist — group by category
    categories_seen = {}
    for item in critical + high:
        cat = item.get("category", "advisory")
        categories_seen.setdefault(cat, []).append(item.get("title", "")[:70])
    checklist = ""
    for cat, titles in categories_seen.items():
        checklist += f"<li><b>{cat.upper()}</b>: Review and patch — {', '.join(titles[:2])}</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhantomFeed Intelligence Report — {client.get('name','Client')}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a202c; font-size: 13px; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #6b46c1; padding-bottom: 8px; }}
  h2 {{ color: #2d3748; margin-top: 28px; font-size: 16px; border-left: 4px solid #6b46c1; padding-left: 10px; }}
  .meta {{ color: #718096; font-size: 12px; margin-bottom: 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
  .stat-card {{ background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-card .num {{ font-size: 28px; font-weight: bold; }}
  .stat-card .label {{ font-size: 11px; color: #718096; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th {{ background: #2d3748; color: white; padding: 8px; text-align: left; font-size: 11px; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f7fafc; }}
  .checklist {{ background: #fffaf0; border: 1px solid #f6e05e; border-radius: 6px; padding: 16px; }}
  .checklist li {{ margin: 6px 0; }}
  .footer {{ margin-top: 40px; font-size: 11px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 12px; }}
  .compliance-coverage {{ margin: 12px 0; }}
</style>
</head>
<body>

<h1>PhantomFeed Intelligence Report</h1>
<div class="meta">
  <b>Client:</b> {client.get('name','Unknown')} &nbsp;|&nbsp;
  <b>Contact:</b> {client.get('contact_email','')} &nbsp;|&nbsp;
  <b>Period:</b> Last {days} days (since {cutoff}) &nbsp;|&nbsp;
  <b>Generated:</b> {report_date}
</div>

<h2>Technology Stack Profile</h2>
{stack_html}

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="stat-card">
    <div class="num" style="color:#e53e3e">{len(critical)}</div>
    <div class="label">CRITICAL Items</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#dd6b20">{len(high)}</div>
    <div class="label">HIGH Items</div>
  </div>
  <div class="stat-card">
    <div class="num">{len(recent)}</div>
    <div class="label">Total Items ({days}d)</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#6b46c1">{len(all_ctags)}</div>
    <div class="label">Compliance Domains</div>
  </div>
</div>

<h2>Compliance Coverage</h2>
<div class="compliance-coverage">
{"".join(f'<span style="{_compliance_pill_style(t)}">{t}</span>' for t in sorted(all_ctags)) or "<em>No compliance tags found.</em>"}
</div>

<h2>Threat Items ({len(recent)} total)</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Title</th><th>Date</th><th>Risk</th><th>CVEs</th><th>Compliance</th>
    </tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>

<h2>Remediation Checklist</h2>
<div class="checklist">
  <ul>
    {checklist or "<li>No critical or high-severity items in this period.</li>"}
    <li>Review all CRITICAL items immediately and apply vendor patches.</li>
    <li>Verify CISA KEV items are patched per CISA remediation deadlines.</li>
    <li>Update threat intel blocklists for any malware/IOC items.</li>
    <li>Validate supply chain dependencies against advisory items.</li>
  </ul>
</div>

<div class="footer">
  Generated by PhantomFeed Intelligence Platform &nbsp;·&nbsp;
  <a href="https://github.com/zacharyloganhill/PhantomFeed">github.com/zacharyloganhill/PhantomFeed</a> &nbsp;·&nbsp;
  Report covers items with published_at &ge; {cutoff}
</div>

</body>
</html>"""
    return html


def generate_client_report(client: dict, items: list[dict], days: int = 7) -> tuple[bytes, str]:
    """
    Returns (content_bytes, media_type).
    Tries WeasyPrint → ReportLab → HTML fallback.
    """
    html = generate_client_report_html(client, items, days)

    # Try WeasyPrint first
    try:
        from weasyprint import HTML as WeasyprintHTML
        pdf_bytes = WeasyprintHTML(string=html).write_pdf()
        return pdf_bytes, "application/pdf"
    except ImportError:
        pass
    except Exception:
        pass

    # Try ReportLab (basic, text-only summary)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        now = datetime.utcnow().strftime("%B %d, %Y")
        story = [
            Paragraph(f"PhantomFeed Intelligence Report — {client.get('name','Client')}", styles["Title"]),
            Paragraph(f"Generated: {now} | Period: Last {days} days", styles["Normal"]),
            Spacer(1, 12),
        ]

        recent = [i for i in items if (i.get("published_at") or "") >= (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")]
        critical = [i for i in recent if i.get("severity") == "CRITICAL"]
        story.append(Paragraph(f"Summary: {len(critical)} critical, {len(recent)} total items", styles["Heading2"]))

        for item in recent[:50]:
            sev = item.get("severity", "INFO")
            rs = item.get("risk_score")
            rs_str = f" [Risk:{rs:.1f}]" if rs is not None else ""
            story.append(Paragraph(f"[{sev}]{rs_str} {item.get('title','')[:100]}", styles["Normal"]))
            story.append(Spacer(1, 4))

        doc.build(story)
        return buf.getvalue(), "application/pdf"
    except ImportError:
        pass

    # Final fallback: return HTML
    return html.encode("utf-8"), "text/html"
