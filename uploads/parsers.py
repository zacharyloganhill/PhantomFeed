"""
PhantomFeed — Upload Parsers

Parsers for scan exports (Nessus, Qualys, OpenVAS, Rapid7), asset CSVs,
IOC lists, and STIX 2.1 bundles. Each parser returns a normalized dict
with 'assets' and 'findings' (or 'iocs' / 'items') keys.
"""

import csv
import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional


SEV_MAP_INT = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
}

SEV_MAP_QUALYS = {
    "1": "INFO",
    "2": "LOW",
    "3": "MEDIUM",
    "4": "HIGH",
    "5": "CRITICAL",
}


def _clean(s) -> str:
    if s is None:
        return ""
    return str(s).strip()


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


# ---------------------------------------------------------------------------
# NessusParser
# ---------------------------------------------------------------------------

class NessusParser:
    """Parse .nessus XML files (ZIP-wrapped or bare XML)."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        xml_data = self._unwrap(data, filename)
        root = ET.fromstring(xml_data)

        assets = []
        findings = []

        for report_host in root.iter("ReportHost"):
            hostname = _clean(report_host.get("name", ""))
            ip = ""
            os_name = ""

            for tag in report_host.iter("tag"):
                name_attr = tag.get("name", "")
                if name_attr == "host-ip":
                    ip = _clean(tag.text)
                elif name_attr == "operating-system":
                    os_name = _clean(tag.text)

            if hostname or ip:
                assets.append({
                    "hostname": hostname,
                    "ip_address": ip,
                    "os": os_name,
                    "software": os_name or "Unknown",
                    "version": "",
                })

            for item in report_host.iter("ReportItem"):
                plugin_name = _clean(item.get("pluginName", ""))
                sev_int = _clean(item.get("severity", "0"))
                severity = SEV_MAP_INT.get(sev_int, "INFO")

                cves = [_clean(c.text) for c in item.findall("cve") if c.text]
                desc = _clean(getattr(item.find("description"), "text", "") or "")
                solution = _clean(getattr(item.find("solution"), "text", "") or "")

                if plugin_name:
                    findings.append({
                        "title": plugin_name,
                        "severity": severity,
                        "cve_ids": cves,
                        "description": desc[:2000],
                        "solution": solution[:1000],
                        "hostname": hostname,
                        "ip_address": ip,
                    })

        return {
            "format": "nessus",
            "assets": assets,
            "findings": findings,
        }

    def _unwrap(self, data: bytes, filename: str) -> bytes:
        # Some .nessus files are ZIP archives
        if filename.endswith(".nessus") or data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for name in z.namelist():
                        if name.endswith(".xml") or name.endswith(".nessus"):
                            return z.read(name)
            except Exception:
                pass
        return data


# ---------------------------------------------------------------------------
# QualysParser
# ---------------------------------------------------------------------------

class QualysParser:
    """Parse Qualys CSV or XML exports. Auto-detects format."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        text = data.decode("utf-8", errors="replace")
        if filename.endswith(".xml") or text.lstrip().startswith("<"):
            return self._parse_xml(text)
        return self._parse_csv(text)

    def _parse_csv(self, text: str) -> dict:
        reader = csv.DictReader(io.StringIO(text))
        assets_map = {}
        findings = []

        for row in reader:
            ip = _clean(row.get("IP") or row.get("ip") or "")
            dns = _clean(row.get("DNS") or row.get("dns") or row.get("Hostname") or "")
            os_name = _clean(row.get("OS") or row.get("os") or "")
            qid = _clean(row.get("QID") or "")
            title = _clean(row.get("Title") or row.get("title") or "")
            sev = SEV_MAP_QUALYS.get(_clean(row.get("Severity") or "1"), "LOW")
            cve_raw = _clean(row.get("CVE ID") or row.get("CVE") or "")
            cves = [c.strip() for c in re.split(r"[,;]", cve_raw) if c.strip().startswith("CVE-")]
            solution = _clean(row.get("Solution") or row.get("Threat") or "")

            key = ip or dns
            if key and key not in assets_map:
                assets_map[key] = {
                    "hostname": dns,
                    "ip_address": ip,
                    "os": os_name,
                    "software": os_name or "Unknown",
                    "version": "",
                }

            if title:
                findings.append({
                    "title": title,
                    "severity": sev,
                    "cve_ids": cves,
                    "description": f"QID: {qid}",
                    "solution": solution[:1000],
                    "hostname": dns,
                    "ip_address": ip,
                })

        return {
            "format": "qualys_csv",
            "assets": list(assets_map.values()),
            "findings": findings,
        }

    def _parse_xml(self, text: str) -> dict:
        root = ET.fromstring(text)
        assets_map = {}
        findings = []

        for host in root.iter("HOST"):
            ip = _clean(getattr(host.find("IP"), "text", "") or host.get("ip", ""))
            dns = _clean(getattr(host.find("DNS"), "text", "") or "")
            os_name = _clean(getattr(host.find("OS"), "text", "") or "")

            key = ip or dns
            if key and key not in assets_map:
                assets_map[key] = {
                    "hostname": dns,
                    "ip_address": ip,
                    "os": os_name,
                    "software": os_name or "Unknown",
                    "version": "",
                }

            for vuln in host.iter("VULN"):
                title = _clean(getattr(vuln.find("TITLE"), "text", "") or "")
                sev_raw = _clean(getattr(vuln.find("SEVERITY"), "text", "") or "1")
                sev = SEV_MAP_QUALYS.get(sev_raw, "LOW")
                cve_el = vuln.find("CVE_ID_LIST")
                cves = []
                if cve_el is not None:
                    cves = [_clean(c.text) for c in cve_el.findall("CVE_ID") if c.text]
                solution = _clean(getattr(vuln.find("SOLUTION"), "text", "") or "")

                if title:
                    findings.append({
                        "title": title,
                        "severity": sev,
                        "cve_ids": cves,
                        "description": "",
                        "solution": solution[:1000],
                        "hostname": dns,
                        "ip_address": ip,
                    })

        return {
            "format": "qualys_xml",
            "assets": list(assets_map.values()),
            "findings": findings,
        }


# ---------------------------------------------------------------------------
# OpenVASParser
# ---------------------------------------------------------------------------

class OpenVASParser:
    """Parse OpenVAS/GVM XML reports. Root element is <report>."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        root = ET.fromstring(data.decode("utf-8", errors="replace"))
        # OpenVAS wraps in <report><report>...</report></report>
        inner = root.find("report") or root

        assets_map = {}
        findings = []

        for result in inner.iter("result"):
            host_el = result.find("host")
            ip = _clean(getattr(host_el, "text", "") or "")
            hostname = ""
            if host_el is not None:
                detail = host_el.find("detail")
                if detail is None:
                    # Try hostname in <asset>
                    asset_el = result.find("asset")
                    if asset_el is not None:
                        hostname = _clean(asset_el.get("name", ""))
                else:
                    hostname = _clean(getattr(detail.find("value"), "text", "") or "")

            key = ip or hostname
            if key and key not in assets_map:
                os_el = result.find(".//detail[name='best_os_txt']/value")
                os_name = _clean(getattr(os_el, "text", "") or "")
                assets_map[key] = {
                    "hostname": hostname,
                    "ip_address": ip,
                    "os": os_name,
                    "software": os_name or "Unknown",
                    "version": "",
                }

            nvt = result.find("nvt")
            if nvt is None:
                continue

            name = _clean(getattr(result.find("name"), "text", "") or nvt.get("oid", ""))
            sev_el = result.find("severity")
            try:
                sev_float = float(getattr(sev_el, "text", 0) or 0)
            except ValueError:
                sev_float = 0.0
            if sev_float >= 9.0:
                severity = "CRITICAL"
            elif sev_float >= 7.0:
                severity = "HIGH"
            elif sev_float >= 4.0:
                severity = "MEDIUM"
            elif sev_float > 0:
                severity = "LOW"
            else:
                severity = "INFO"

            cves = []
            for ref in nvt.findall("refs/ref"):
                if ref.get("type", "").upper() == "CVE":
                    cves.append(_clean(ref.get("id", "")))

            desc = _clean(getattr(result.find("description"), "text", "") or "")
            solution = _clean(getattr(nvt.find("solution"), "text", "") or "")

            if name:
                findings.append({
                    "title": name,
                    "severity": severity,
                    "cve_ids": cves,
                    "description": desc[:2000],
                    "solution": solution[:1000],
                    "hostname": hostname,
                    "ip_address": ip,
                })

        return {
            "format": "openvas",
            "assets": list(assets_map.values()),
            "findings": findings,
        }


# ---------------------------------------------------------------------------
# Rapid7Parser
# ---------------------------------------------------------------------------

class Rapid7Parser:
    """Parse Rapid7/InsightVM CSV exports."""

    # Column name variants
    COL_IP = ["asset ip address", "asset ip", "ip address", "ip"]
    COL_HOST = ["asset hostname", "hostname", "host", "dns"]
    COL_OS = ["asset os name", "asset os", "os name", "os"]
    COL_TITLE = ["vulnerability title", "title", "vuln title", "name"]
    COL_CVES = ["vulnerability cve ids", "cve ids", "cve id", "cve"]
    COL_SEV = ["vulnerability severity", "severity", "risk score"]
    COL_DESC = ["vulnerability description", "description"]
    COL_SOL = ["solution", "fix"]

    def parse(self, data: bytes, filename: str = "") -> dict:
        text = data.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        # Normalize header names
        if reader.fieldnames is None:
            return {"format": "rapid7", "assets": [], "findings": []}
        norm_map = {h.lower().strip(): h for h in reader.fieldnames}

        def col(options):
            for o in options:
                if o in norm_map:
                    return norm_map[o]
            return None

        ip_col = col(self.COL_IP)
        host_col = col(self.COL_HOST)
        os_col = col(self.COL_OS)
        title_col = col(self.COL_TITLE)
        cve_col = col(self.COL_CVES)
        sev_col = col(self.COL_SEV)
        desc_col = col(self.COL_DESC)
        sol_col = col(self.COL_SOL)

        assets_map = {}
        findings = []

        for row in reader:
            ip = _clean(row.get(ip_col) if ip_col else "")
            hostname = _clean(row.get(host_col) if host_col else "")
            os_name = _clean(row.get(os_col) if os_col else "")
            title = _clean(row.get(title_col) if title_col else "")
            cve_raw = _clean(row.get(cve_col) if cve_col else "")
            sev_raw = _clean(row.get(sev_col) if sev_col else "").upper()
            desc = _clean(row.get(desc_col) if desc_col else "")
            solution = _clean(row.get(sol_col) if sol_col else "")

            # Map severity
            if sev_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                severity = sev_raw
            else:
                try:
                    n = float(sev_raw)
                    severity = "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW"
                except ValueError:
                    severity = "MEDIUM"

            cves = [c.strip() for c in re.split(r"[,;]", cve_raw) if c.strip().startswith("CVE-")]
            key = ip or hostname
            if key and key not in assets_map:
                assets_map[key] = {
                    "hostname": hostname,
                    "ip_address": ip,
                    "os": os_name,
                    "software": os_name or "Unknown",
                    "version": "",
                }

            if title:
                findings.append({
                    "title": title,
                    "severity": severity,
                    "cve_ids": cves,
                    "description": desc[:2000],
                    "solution": solution[:1000],
                    "hostname": hostname,
                    "ip_address": ip,
                })

        return {
            "format": "rapid7",
            "assets": list(assets_map.values()),
            "findings": findings,
        }


# ---------------------------------------------------------------------------
# GenericCSVParser
# ---------------------------------------------------------------------------

FUZZY_HOSTNAME = ["hostname", "host", "device", "computer", "name", "machine", "server"]
FUZZY_IP = ["ip", "ip_address", "ipaddress", "address", "ip address"]
FUZZY_OS = ["os", "operating system", "operatingsystem", "platform", "os name"]
FUZZY_SOFTWARE = ["software", "application", "app", "product", "program"]
FUZZY_VERSION = ["version", "ver", "release", "build"]
FUZZY_SEVERITY = ["severity", "risk", "priority", "cvss", "score"]
FUZZY_CVE = ["cve", "cve_id", "cve ids", "vulnerability"]
FUZZY_TITLE = ["title", "name", "finding", "vuln", "vulnerability", "description"]
FUZZY_SOLUTION = ["solution", "fix", "remediation", "recommendation"]


def _best_match(header: str, candidates: list[str]) -> bool:
    h = header.lower().strip()
    return any(c in h or h in c for c in candidates)


class GenericCSVParser:
    """Flexible CSV parser with fuzzy column mapping."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        # Handle XLSX
        if filename.endswith(".xlsx"):
            return self._parse_xlsx(data)

        text = data.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return {"format": "generic_csv", "assets": [], "findings": [], "field_mapping": {}, "preview": []}

        mapping = self._detect_mapping(list(reader.fieldnames))
        rows = []
        for i, row in enumerate(reader):
            if i >= 100:
                break
            rows.append(dict(row))

        preview = rows[:5]
        assets, findings = self._extract(rows, mapping)

        return {
            "format": "generic_csv",
            "assets": assets,
            "findings": findings,
            "field_mapping": mapping,
            "preview": preview,
        }

    def _parse_xlsx(self, data: bytes) -> dict:
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        ws = wb.active
        rows_raw = list(ws.iter_rows(values_only=True))
        if not rows_raw:
            return {"format": "generic_xlsx", "assets": [], "findings": [], "field_mapping": {}, "preview": []}

        headers = [_clean(h) for h in rows_raw[0]]
        mapping = self._detect_mapping(headers)
        rows = []
        for row in rows_raw[1:101]:
            rows.append({headers[i]: _clean(v) for i, v in enumerate(row) if i < len(headers)})

        preview = rows[:5]
        assets, findings = self._extract(rows, mapping)
        return {
            "format": "generic_xlsx",
            "assets": assets,
            "findings": findings,
            "field_mapping": mapping,
            "preview": preview,
        }

    def _detect_mapping(self, headers: list[str]) -> dict:
        mapping = {}
        for h in headers:
            if _best_match(h, FUZZY_HOSTNAME):
                mapping.setdefault("hostname", h)
            if _best_match(h, FUZZY_IP):
                mapping.setdefault("ip_address", h)
            if _best_match(h, FUZZY_OS):
                mapping.setdefault("os", h)
            if _best_match(h, FUZZY_SOFTWARE):
                mapping.setdefault("software", h)
            if _best_match(h, FUZZY_VERSION):
                mapping.setdefault("version", h)
            if _best_match(h, FUZZY_SEVERITY):
                mapping.setdefault("severity", h)
            if _best_match(h, FUZZY_CVE):
                mapping.setdefault("cve_ids", h)
            if _best_match(h, FUZZY_TITLE):
                mapping.setdefault("title", h)
            if _best_match(h, FUZZY_SOLUTION):
                mapping.setdefault("solution", h)
        return mapping

    def _extract(self, rows: list[dict], mapping: dict) -> tuple[list, list]:
        assets_map = {}
        findings = []
        for row in rows:
            hostname = _clean(row.get(mapping.get("hostname", ""), ""))
            ip = _clean(row.get(mapping.get("ip_address", ""), ""))
            os_name = _clean(row.get(mapping.get("os", ""), ""))
            software = _clean(row.get(mapping.get("software", ""), "")) or os_name or "Unknown"
            version = _clean(row.get(mapping.get("version", ""), ""))
            title = _clean(row.get(mapping.get("title", ""), ""))
            sev_raw = _clean(row.get(mapping.get("severity", ""), "")).upper()
            cve_raw = _clean(row.get(mapping.get("cve_ids", ""), ""))
            solution = _clean(row.get(mapping.get("solution", ""), ""))

            if sev_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                severity = sev_raw
            else:
                severity = "MEDIUM"

            cves = [c.strip() for c in re.split(r"[,;]", cve_raw) if c.strip().startswith("CVE-")]
            key = ip or hostname
            if key and key not in assets_map:
                assets_map[key] = {
                    "hostname": hostname,
                    "ip_address": ip,
                    "os": os_name,
                    "software": software,
                    "version": version,
                }
            if title:
                findings.append({
                    "title": title,
                    "severity": severity,
                    "cve_ids": cves,
                    "description": "",
                    "solution": solution[:1000],
                    "hostname": hostname,
                    "ip_address": ip,
                })
        return list(assets_map.values()), findings


# ---------------------------------------------------------------------------
# IOCParser
# ---------------------------------------------------------------------------

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
    r"(?:com|net|org|io|gov|edu|mil|int|info|biz|co|uk|de|ru|cn|fr|jp|"
    r"xyz|app|dev|tech|online|site|store|shop|club|top|cc|tk|ml|ga|cf|gq)\b",
    re.IGNORECASE
)


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if RE_SHA256.fullmatch(v):
        return "sha256"
    if RE_SHA1.fullmatch(v):
        return "sha1"
    if RE_MD5.fullmatch(v):
        return "md5"
    if RE_IPV6.fullmatch(v):
        return "ipv6"
    if RE_IPV4.fullmatch(v):
        return "ip"
    if RE_URL.fullmatch(v):
        return "url"
    if RE_DOMAIN.fullmatch(v):
        return "domain"
    return "unknown"


def _extract_iocs_from_text(text: str) -> list[dict]:
    iocs = []
    seen = set()

    def _add(value, ioc_type):
        v = value.strip()
        if v and v not in seen and ioc_type != "unknown":
            seen.add(v)
            iocs.append({"type": ioc_type, "value": v})

    for m in RE_SHA256.finditer(text):
        _add(m.group(), "sha256")
    for m in RE_SHA1.finditer(text):
        if m.group() not in seen:
            _add(m.group(), "sha1")
    for m in RE_MD5.finditer(text):
        if m.group() not in seen:
            _add(m.group(), "md5")
    for m in RE_URL.finditer(text):
        _add(m.group(), "url")
    for m in RE_IPV4.finditer(text):
        _add(m.group(), "ip")
    for m in RE_DOMAIN.finditer(text):
        if m.group() not in seen:
            _add(m.group(), "domain")

    return iocs


class IOCParser:
    """Parse plain text IOC lists, CSV/JSON IOC files, and STIX 2.1 bundles."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        text = data.decode("utf-8", errors="replace").strip()

        # STIX JSON bundle
        if filename.endswith(".json") or (text.startswith("{") and '"type"' in text):
            try:
                obj = json.loads(text)
                if obj.get("type") == "bundle":
                    return self._parse_stix(obj)
            except json.JSONDecodeError:
                pass

        # JSON array of IOCs
        if text.startswith("["):
            try:
                arr = json.loads(text)
                iocs = []
                for item in arr:
                    if isinstance(item, dict):
                        val = _clean(item.get("value") or item.get("ioc") or item.get("indicator") or "")
                        if val:
                            ioc_type = item.get("type") or detect_ioc_type(val)
                            iocs.append({"type": ioc_type, "value": val})
                    elif isinstance(item, str):
                        t = detect_ioc_type(item.strip())
                        if t != "unknown":
                            iocs.append({"type": t, "value": item.strip()})
                return {"format": "json_ioc", "iocs": iocs}
            except json.JSONDecodeError:
                pass

        # CSV with a value column
        if "," in text[:500] and "\n" in text:
            try:
                reader = csv.DictReader(io.StringIO(text))
                if reader.fieldnames:
                    val_col = None
                    for h in reader.fieldnames:
                        if h.lower() in ("value", "ioc", "indicator", "ip", "hash", "domain", "url"):
                            val_col = h
                            break
                    if val_col:
                        iocs = []
                        type_col = next((h for h in (reader.fieldnames or []) if h.lower() in ("type", "ioc_type")), None)
                        for row in reader:
                            val = _clean(row.get(val_col, ""))
                            if val:
                                ioc_type = _clean(row.get(type_col, "")) if type_col else detect_ioc_type(val)
                                iocs.append({"type": ioc_type or detect_ioc_type(val), "value": val})
                        return {"format": "csv_ioc", "iocs": iocs}
            except Exception:
                pass

        # Plain text — one IOC per line, or mixed text
        iocs = []
        seen = set()
        for line in text.splitlines():
            line = line.strip().lstrip("#").strip()
            if not line or line.startswith("//"):
                continue
            t = detect_ioc_type(line)
            if t != "unknown" and line not in seen:
                seen.add(line)
                iocs.append({"type": t, "value": line})

        # Fallback: regex scan entire text
        if not iocs:
            iocs = _extract_iocs_from_text(text)

        return {"format": "txt_ioc", "iocs": iocs}

    def _parse_stix(self, bundle: dict) -> dict:
        iocs = []
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                # Extract values from STIX patterns like [ipv4-addr:value = '1.2.3.4']
                for m in re.finditer(r"'([^']+)'", pattern):
                    val = m.group(1)
                    t = detect_ioc_type(val)
                    if t != "unknown":
                        iocs.append({
                            "type": t,
                            "value": val,
                            "name": obj.get("name", ""),
                            "description": obj.get("description", ""),
                        })
        return {"format": "stix_ioc", "iocs": iocs}


# ---------------------------------------------------------------------------
# STIXBundleParser
# ---------------------------------------------------------------------------

SEV_TLP = {"white": "INFO", "green": "LOW", "amber": "MEDIUM", "red": "HIGH"}


class STIXBundleParser:
    """Parse STIX 2.1 JSON bundles into PhantomFeed threat_items format."""

    def parse(self, data: bytes, filename: str = "") -> dict:
        try:
            bundle = json.loads(data.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            return {"format": "stix_bundle", "items": [], "error": str(e)}

        items = []
        now = datetime.utcnow().strftime("%Y-%m-%d")

        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")
            if obj_type == "indicator":
                items.append(self._norm_indicator(obj, now))
            elif obj_type == "malware":
                items.append(self._norm_malware(obj, now))
            elif obj_type == "threat-actor":
                items.append(self._norm_threat_actor(obj, now))
            elif obj_type == "vulnerability":
                items.append(self._norm_vulnerability(obj, now))
            elif obj_type == "course-of-action":
                items.append(self._norm_coa(obj, now))

        items = [i for i in items if i]
        return {
            "format": "stix_bundle",
            "items": items,
            "counts": {
                "total": len(items),
            },
        }

    def _base(self, obj: dict, now: str) -> dict:
        name = obj.get("name", obj.get("id", "Unknown STIX Object"))
        desc = obj.get("description", "")
        created = (obj.get("created") or now)[:10]
        cves = []
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "cve":
                cves.append(ref.get("external_id", ""))
        tags = list(obj.get("labels", []))
        return {
            "feed_id": "stix_upload",
            "feed_label": "STIX Bundle (Upload)",
            "title": name[:250],
            "description": desc[:2000],
            "published_at": created,
            "fetched_at": now,
            "cve_ids": cves,
            "tags": tags,
            "raw": {},
            "compliance_tags": [],
        }

    def _norm_indicator(self, obj: dict, now: str) -> dict:
        item = self._base(obj, now)
        item.update({
            "category": "threat",
            "severity": "MEDIUM",
            "vendor": "",
            "product": "",
            "url": "",
        })
        pattern = obj.get("pattern", "")
        for ref in obj.get("external_references", []):
            if ref.get("url"):
                item["url"] = ref["url"]
                break
        return item

    def _norm_malware(self, obj: dict, now: str) -> dict:
        item = self._base(obj, now)
        item.update({
            "category": "malware",
            "severity": "HIGH",
            "vendor": "",
            "product": "",
            "url": "",
        })
        return item

    def _norm_threat_actor(self, obj: dict, now: str) -> dict:
        item = self._base(obj, now)
        item.update({
            "category": "threat",
            "severity": "HIGH",
            "vendor": "",
            "product": "",
            "url": "",
        })
        return item

    def _norm_vulnerability(self, obj: dict, now: str) -> dict:
        item = self._base(obj, now)
        item.update({
            "category": "cve",
            "severity": "MEDIUM",
            "vendor": "",
            "product": "",
            "url": "",
        })
        return item

    def _norm_coa(self, obj: dict, now: str) -> dict:
        item = self._base(obj, now)
        item.update({
            "category": "advisory",
            "severity": "INFO",
            "vendor": "",
            "product": "",
            "url": "",
        })
        return item


# ---------------------------------------------------------------------------
# Auto-detect parser from filename/content
# ---------------------------------------------------------------------------

def detect_parser(data: bytes, filename: str) -> tuple[str, object]:
    """Return (format_name, parser_instance) for the given upload."""
    fname = filename.lower()
    text_start = data[:500].decode("utf-8", errors="replace").lstrip()

    if fname.endswith(".nessus"):
        return "nessus", NessusParser()

    if fname.endswith(".xml"):
        # OpenVAS reports have <report> root; Qualys has <SCAN> or <HOST>
        if "<report" in text_start.lower():
            return "openvas", OpenVASParser()
        return "qualys_xml", QualysParser()

    if fname.endswith(".csv"):
        # Rapid7 has distinctive headers
        if "asset ip address" in text_start.lower() or "vulnerability title" in text_start.lower():
            return "rapid7", Rapid7Parser()
        if "qid" in text_start.lower() and "dns" in text_start.lower():
            return "qualys_csv", QualysParser()
        return "generic_csv", GenericCSVParser()

    if fname.endswith(".xlsx"):
        return "generic_xlsx", GenericCSVParser()

    if fname.endswith(".txt"):
        return "ioc_txt", IOCParser()

    if fname.endswith(".json"):
        if '"type"' in text_start and "bundle" in text_start:
            return "stix_bundle", STIXBundleParser()
        return "ioc_json", IOCParser()

    # Fallback: try XML, then IOC
    if text_start.startswith("<"):
        if "ReportHost" in text_start or "NessusClientData" in text_start:
            return "nessus", NessusParser()
        if "<report" in text_start.lower():
            return "openvas", OpenVASParser()
        return "qualys_xml", QualysParser()

    return "ioc_txt", IOCParser()
