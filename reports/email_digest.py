"""
PhantomFeed — Email Digest

Sends a styled HTML email digest to the client's contact_email address.
Uses SMTP with TLS (STARTTLS). Falls back gracefully if SMTP is not configured.
"""

import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import config

SEVERITY_COLORS = {
    "CRITICAL": "#e53e3e",
    "HIGH":     "#dd6b20",
    "MEDIUM":   "#d69e2e",
    "LOW":      "#38a169",
    "INFO":     "#718096",
}


def _build_html(client: dict, items: list[dict], days: int) -> str:
    cutoff = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [i for i in items if (i.get("published_at") or "") >= cutoff]
    critical = [i for i in recent if i.get("severity") == "CRITICAL"]
    high = [i for i in recent if i.get("severity") == "HIGH"]
    report_date = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%B %d, %Y")

    def item_row(item: dict, idx: int) -> str:
        sev = item.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "#718096")
        rs = item.get("risk_score")
        rs_str = f"{rs:.1f}" if rs is not None else "—"
        url = item.get("url", "#")
        title = item.get("title", "")[:80]
        return f"""
        <tr style="background:{'#fff5f5' if idx % 2 == 0 else '#fff'}">
          <td style="padding:8px;color:{color};font-weight:bold;font-size:12px;white-space:nowrap">{sev}</td>
          <td style="padding:8px;font-size:13px"><a href="{url}" style="color:#2d3748;text-decoration:none">{title}</a></td>
          <td style="padding:8px;text-align:center;font-weight:bold;color:#6b46c1">{rs_str}</td>
          <td style="padding:8px;font-size:11px;color:#718096">{(item.get('published_at') or '')[:10]}</td>
        </tr>"""

    rows = "".join(item_row(i, idx) for idx, i in enumerate(recent[:30]))

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f7fafc;margin:0;padding:0">
<div style="max-width:680px;margin:0 auto;padding:20px">

  <div style="background:linear-gradient(135deg,#1a1a2e 0%,#6b46c1 100%);border-radius:12px;padding:24px;margin-bottom:20px">
    <h1 style="color:#fff;margin:0;font-size:22px">PhantomFeed Intelligence Digest</h1>
    <p style="color:rgba(255,255,255,0.7);margin:4px 0 0">{report_date} &nbsp;·&nbsp; {client.get('name','Client')}</p>
  </div>

  <div style="display:flex;gap:12px;margin-bottom:20px">
    <div style="flex:1;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:bold;color:#e53e3e">{len(critical)}</div>
      <div style="font-size:12px;color:#718096">CRITICAL</div>
    </div>
    <div style="flex:1;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:bold;color:#dd6b20">{len(high)}</div>
      <div style="font-size:12px;color:#718096">HIGH</div>
    </div>
    <div style="flex:1;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center">
      <div style="font-size:28px;font-weight:bold;color:#2d3748">{len(recent)}</div>
      <div style="font-size:12px;color:#718096">TOTAL ({days}d)</div>
    </div>
  </div>

  <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:20px">
    <h2 style="margin:0 0 12px;font-size:15px;color:#2d3748">Top Threat Items</h2>
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#f7fafc">
          <th style="padding:8px;text-align:left;font-size:11px;color:#718096">SEVERITY</th>
          <th style="padding:8px;text-align:left;font-size:11px;color:#718096">ITEM</th>
          <th style="padding:8px;text-align:center;font-size:11px;color:#718096">RISK</th>
          <th style="padding:8px;text-align:left;font-size:11px;color:#718096">DATE</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div style="font-size:11px;color:#a0aec0;text-align:center;padding-top:12px;border-top:1px solid #e2e8f0">
    PhantomFeed Intelligence Platform &nbsp;·&nbsp; This digest was automatically generated.
  </div>
</div>
</body>
</html>"""


async def send_client_digest(client: dict, items: list[dict], days: int = 7) -> dict:
    """
    Send an email digest to the client's contact_email.
    Returns {"status": "sent"} or {"status": "error", "detail": ...}.
    """
    if not all([config.SMTP_HOST, config.SMTP_USER, config.SMTP_PASSWORD]):
        return {
            "status": "skipped",
            "detail": "SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD in .env",
        }

    to_email = client.get("contact_email", "")
    if not to_email:
        return {"status": "error", "detail": "Client has no contact_email set"}

    html_body = _build_html(client, items, days)
    report_date = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%B %d, %Y")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"PhantomFeed Digest — {client.get('name','Client')} — {report_date}"
    msg["From"] = config.SMTP_FROM or config.SMTP_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_FROM or config.SMTP_USER, to_email, msg.as_string())
        return {"status": "sent", "to": to_email}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
