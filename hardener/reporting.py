"""Report Generation Engine: exports findings to TXT, JSON, CSV, XML, HTML.

Includes executive summary, asset inventory, discovered hosts, open ports,
detected services, OS, findings, CVE references, risk ratings and remediation.
"""

import csv
import html
import json
import os
import re
import xml.etree.ElementTree as ET

from .utils import ensure_dir

SEVERITY_COLOR = {
    "informational": "#6c757d",
    "low": "#28a745",
    "medium": "#ffc107",
    "high": "#fd7e14",
    "critical": "#dc3545",
}

# XML 1.0 legal character ranges
_XML_VALID = re.compile(r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]")


def _xml_clean(text):
    """Strip control characters illegal in XML 1.0."""
    if not text:
        return ""
    return _XML_VALID.sub("", str(text))


def _port_rows(report):
    rows = []
    for host in report.hosts:
        for pr in host.ports:
            if pr.state != "open":
                continue
            rows.append({
                "ip": host.ip,
                "hostname": host.hostname or "",
                "port": pr.port,
                "protocol": pr.protocol,
                "service": pr.service,
                "version": pr.version,
            })
    return rows


def _finding_rows(report):
    rows = []
    for f in report.findings:
        rows.append({
            "asset": f.asset,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "title": f.title,
            "category": f.category,
            "cve": f.cve or "",
            "evidence": f.evidence,
            "remediation": "; ".join(f.remediation),
        })
    return rows


# ---------------------------------------------------------------------------
# TXT
# ---------------------------------------------------------------------------

def _render_txt(report):
    lines = []
    lines.append("=" * 78)
    lines.append(f" {report.tool_name} - Security Assessment Report")
    lines.append(f" Version: {report.tool_version}  Started: {report.started_at}  Duration: {report.duration}")
    lines.append("=" * 78)
    lines.append("\n[EXECUTIVE SUMMARY]")
    s = report.stats
    lines.append(f"  Targets assessed : {len(report.targets)}")
    lines.append(f"  Hosts discovered : {len(report.hosts)}")
    lines.append(f"  Open ports       : {sum(1 for r in _port_rows(report))}")
    lines.append(f"  Findings         : {s.get('total', 0)} "
                 f"(critical {s.get('critical', 0)}, high {s.get('high', 0)}, "
                 f"medium {s.get('medium', 0)}, low {s.get('low', 0)})")
    lines.append(f"  Max risk score   : {s.get('max_risk', 0)}/10")

    lines.append("\n[ASSET INVENTORY]")
    for host in report.hosts:
        os_name = host.os_fingerprint.get("os", "Unknown")
        lines.append(f"  {host.ip}  {host.hostname or ''}  OS={os_name} "
                     f"alive={host.alive_method}")
        for r in _port_rows(report):
            if r["ip"] == host.ip:
                lines.append(f"      {r['port']:>5}/{r['protocol']}  {r['service']:<14} {r['version']}")

    lines.append("\n[FINDINGS BY SEVERITY]")
    for f in sorted(report.findings, key=lambda x: x.risk_score, reverse=True):
        lines.append(f"  [{f.severity.upper():<12}] {f.risk_score:>4}/10  {f.title}  ({f.asset})")
        if f.cve:
            lines.append(f"      CVE: {f.cve}")
        if f.evidence:
            lines.append(f"      Evidence: {f.evidence[:120]}")
        if f.remediation:
            lines.append(f"      Remediation: {'; '.join(f.remediation)}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _report_dict(report):
    return {
        "tool": {"name": report.tool_name, "version": report.tool_version},
        "meta": {"started_at": report.started_at, "finished_at": report.finished_at,
                 "duration": report.duration},
        "summary": report.stats,
        "targets": [{"raw": t.raw, "kind": t.kind, "hostname": t.hostname,
                     "ip": t.ip, "network": t.network} for t in report.targets],
        "hosts": [
            {
                "ip": h.ip, "hostname": h.hostname, "alive": h.alive,
                "alive_method": h.alive_method, "rtt_ms": h.rtt_ms,
                "cdn": h.cdn, "waf": h.waf,
                "dns_records": [{"type": r.rtype, "value": r.value, "ttl": r.ttl}
                                for r in h.dns_records],
                "subdomains": h.subdomains,
                "os_fingerprint": h.os_fingerprint,
                "http": None if not h.http else {
                    "url": h.http.url, "status": h.http.status,
                    "server": h.http.server, "powered_by": h.http.powered_by,
                    "title": h.http.title, "framework": h.http.framework,
                    "security_headers": h.http.security_headers,
                    "methods": h.http.methods, "found_paths": h.http.found_paths,
                    "directory_listing": h.http.directory_listing,
                },
                "http_audits": {
                    str(port): {"url": a.url, "status": a.status, "server": a.server,
                                "powered_by": a.powered_by, "title": a.title,
                                "security_headers": a.security_headers,
                                "methods": a.methods, "found_paths": a.found_paths,
                                "directory_listing": a.directory_listing}
                    for port, a in h.http_audits.items()
                },
                "ports": [{"port": p.port, "protocol": p.protocol, "state": p.state,
                           "service": p.service, "version": p.version,
                           "banners": p.banners, "enumeration": p.enumeration,
                           "evidence": p.scan_evidence} for p in h.ports],
            }
            for h in report.hosts
        ],
        "findings": [
            {
                "asset": f.asset, "title": f.title, "description": f.description,
                "category": f.category, "severity": f.severity,
                "impact": f.impact, "likelihood": f.likelihood,
                "risk_score": f.risk_score, "cve": f.cve, "evidence": f.evidence,
                "remediation": f.remediation, "confidence": f.confidence,
            }
            for f in report.findings
        ],
    }


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------

def _render_xml(report):
    root = ET.Element("SecurityAssessmentReport")
    meta = ET.SubElement(root, "Meta")
    ET.SubElement(meta, "Tool").text = _xml_clean(report.tool_name)
    ET.SubElement(meta, "Version").text = _xml_clean(report.tool_version)
    ET.SubElement(meta, "StartedAt").text = _xml_clean(report.started_at)
    ET.SubElement(meta, "Duration").text = _xml_clean(report.duration)

    summary = ET.SubElement(root, "Summary")
    for k, v in report.stats.items():
        ET.SubElement(summary, k.capitalize()).text = _xml_clean(str(v))

    assets = ET.SubElement(root, "Assets")
    for host in report.hosts:
        h = ET.SubElement(assets, "Host", ip=_xml_clean(host.ip),
                          alive=str(host.alive).lower())
        ET.SubElement(h, "Hostname").text = _xml_clean(host.hostname or "")
        ET.SubElement(h, "OS").text = _xml_clean(host.os_fingerprint.get("os", "Unknown"))
        ET.SubElement(h, "OSConfidence").text = _xml_clean(
            host.os_fingerprint.get("confidence_pct", "0%"))
        ports = ET.SubElement(h, "Ports")
        for pr in host.ports:
            if pr.state != "open":
                continue
            p = ET.SubElement(ports, "Port", number=str(pr.port),
                              protocol=_xml_clean(pr.protocol),
                              state=_xml_clean(pr.state),
                              service=_xml_clean(pr.service))
            p.text = _xml_clean(pr.version)
    findings = ET.SubElement(root, "Findings")
    for f in sorted(report.findings, key=lambda x: x.risk_score, reverse=True):
        fn = ET.SubElement(findings, "Finding", severity=_xml_clean(f.severity),
                           risk_score=str(f.risk_score), asset=_xml_clean(f.asset))
        ET.SubElement(fn, "Title").text = _xml_clean(f.title)
        ET.SubElement(fn, "Cve").text = _xml_clean(f.cve or "")
        ET.SubElement(fn, "Evidence").text = _xml_clean(f.evidence)
        rem = ET.SubElement(fn, "Remediation")
        for r in f.remediation:
            ET.SubElement(rem, "Action").text = _xml_clean(r)
    return ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _render_html(report):
    s = report.stats
    rows = "".join(
        f"<tr><td>{html.escape(f.asset)}</td>"
        f"<td><span class='badge' style='background:{SEVERITY_COLOR[f.severity]}'>{f.severity}</span></td>"
        f"<td>{f.risk_score}</td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.cve or '')}</td>"
        f"<td>{html.escape(f.evidence[:100])}</td>"
        f"<td>{html.escape('; '.join(f.remediation)[:140])}</td></tr>"
        for f in sorted(report.findings, key=lambda x: x.risk_score, reverse=True)
    )
    port_rows = "".join(
        f"<tr><td>{html.escape(r['ip'])}</td><td>{html.escape(r['hostname'])}</td>"
        f"<td>{r['port']}/{r['protocol']}</td><td>{html.escape(r['service'])}</td>"
        f"<td>{html.escape(r['version'])}</td></tr>"
        for r in _port_rows(report)
    )
    host_rows = "".join(
        f"<tr><td>{html.escape(h.ip)}</td><td>{html.escape(h.hostname or '')}</td>"
        f"<td>{html.escape(h.os_fingerprint.get('os', 'Unknown'))}</td>"
        f"<td>{len([p for p in h.ports if p.state == 'open'])}</td></tr>"
        for h in report.hosts
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(report.tool_name)} - Report</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; color: #222; }}
 h1, h2 {{ color: #1a1a2e; }} table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
 th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 14px; }}
 th {{ background: #1a1a2e; color: #fff; }}
 tr:nth-child(even) {{ background: #f6f6f6; }}
 .badge {{ color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 12px; }}
 .summary {{ display: flex; gap: 2rem; margin-bottom: 2rem; }}
 .kpi {{ flex: 1; border: 1px solid #ddd; border-radius: 8px; padding: 1rem; text-align: center; }}
 .kpi .n {{ font-size: 2rem; font-weight: bold; }}
 .footer {{ margin-top: 3rem; color: #888; font-size: 12px; }}
</style></head><body>
<h1>{html.escape(report.tool_name)}</h1>
<p>Version {html.escape(report.tool_version)} &nbsp;|&nbsp; Started {html.escape(report.started_at)}
&nbsp;|&nbsp; Finished {html.escape(report.finished_at)} &nbsp;|&nbsp; Duration {html.escape(report.duration)}</p>
<div class="summary">
 <div class="kpi"><div class="n">{len(report.hosts)}</div>Hosts</div>
 <div class="kpi"><div class="n">{s.get('total', 0)}</div>Findings</div>
 <div class="kpi"><div class="n" style="color:#dc3545">{s.get('critical', 0)}</div>Critical</div>
 <div class="kpi"><div class="n" style="color:#fd7e14">{s.get('high', 0)}</div>High</div>
 <div class="kpi"><div class="n" style="color:#ffc107">{s.get('medium', 0)}</div>Medium</div>
 <div class="kpi"><div class="n">{s.get('max_risk', 0)}/10</div>Max Risk</div>
</div>
<h2>Hosts</h2>
<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open Ports</th></tr>{host_rows}</table>
<h2>Open Ports / Services</h2>
<table><tr><th>IP</th><th>Hostname</th><th>Port</th><th>Service</th><th>Version</th></tr>{port_rows}</table>
<h2>Findings &amp; Remediation</h2>
<table><tr><th>Asset</th><th>Severity</th><th>Risk</th><th>Finding</th><th>CVE</th><th>Evidence</th><th>Remediation</th></tr>{rows}</table>
<div class="footer">Generated by {html.escape(report.tool_name)} v{html.escape(report.tool_version)}. Remediation guidance is advisory; validate before applying.</div>
</body></html>"""


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def generate_reports(report, output_dir="reports"):
    """Write all report formats to output_dir; return dict of file paths."""
    out = ensure_dir(output_dir)
    paths = {}

    txt = _render_txt(report)
    paths["txt"] = _write(os.path.join(out, "report.txt"), txt)

    json_text = json.dumps(_report_dict(report), indent=2)
    paths["json"] = _write(os.path.join(out, "report.json"), json_text)

    xml_text = _render_xml(report)
    paths["xml"] = _write(os.path.join(out, "report.xml"), xml_text)

    csv_path = os.path.join(out, "report.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["asset", "severity", "risk_score",
                                                "title", "category", "cve",
                                                "evidence", "remediation"])
        writer.writeheader()
        for row in _finding_rows(report):
            writer.writerow(row)
    paths["csv"] = csv_path

    html_text = _render_html(report)
    paths["html"] = _write(os.path.join(out, "report.html"), html_text)

    return paths


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return str(path)
