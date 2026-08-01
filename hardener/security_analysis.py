"""Security Analysis: correlates scan/enumeration data into Findings.

Checks firewall exposure, insecure services, weak TLS, missing HTTP security
headers, exposed admin panels, directory listing, open databases, and CVE
correlation against discovered software versions.
"""

from .config import INSECURE_SERVICES, SECURITY_HEADERS
from .cve_db import display_name, match_cves, match_software_aliases
from .models import Finding


def _mk(host, title, category, severity, impact, likelihood, evidence,
        description="", cve=None, remediation=None, confidence="medium"):
    return Finding(
        title=title,
        description=description,
        category=category,
        severity=severity,
        impact=impact,
        likelihood=likelihood,
        evidence=evidence,
        asset=host.ip,
        cve=cve,
        remediation=remediation or [],
        confidence=confidence,
    )


def analyze_host(host, tls_results=None, enable_cve=True):
    """Produce Findings for one Host."""
    findings = []
    tls_results = tls_results or {}

    # --- insecure services / firewall exposure -----------------------------
    for pr in host.ports:
        if pr.state != "open":
            continue
        base = INSECURE_SERVICES.get(pr.service.lower())
        flags = pr.scan_evidence.get("flags", [])
        if "smbv1" in flags:
            findings.append(_mk(
                host, "SMBv1 protocol enabled",
                "insecure-protocol", "critical", 9, 8,
                f"Port {pr.port}/tcp accepted SMBv1 negotiation",
                "SMBv1 is legacy and vulnerable to MS17-010 (EternalBlue) class attacks.",
                cve="CVE-2017-0144",
                remediation=["Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false)",
                             "Apply MS17-010 security patches"]))
        if "anonymous_login" in flags:
            findings.append(_mk(
                host, "FTP anonymous login enabled", "weak-auth", "high", 8, 8,
                f"Port {pr.port}/tcp allowed anonymous login",
                "Anonymous FTP allows unauthenticated file access and staging of malware.",
                remediation=["Disable anonymous FTP access", "Enforce authenticated users only"]))
        if "unauthenticated" in flags:
            findings.append(_mk(
                host, f"{pr.service} exposed without authentication",
                "open-database", "critical", 10, 9,
                f"Port {pr.port}/tcp responded without credentials",
                f"{pr.service} answered protocol commands with no authentication; this allows full data exposure.",
                remediation=[f"Require authentication for {pr.service}",
                             "Restrict access to trusted networks / bind to loopback"]))
        if "ftps_supported" not in flags and pr.service.lower() in ("ftp",):
            findings.append(_mk(
                host, "Cleartext FTP service", "cleartext", "medium", 7, 6,
                f"Port {pr.port}/tcp FTP; no AUTH TLS advertised",
                "FTP transmits credentials and data in cleartext.",
                remediation=["Migrate to FTPS/SFTP", "Disable cleartext FTP"]))
        if pr.service.lower() == "telnet":
            findings.append(_mk(
                host, "Telnet exposed (cleartext)", "cleartext", "high", 8, 7,
                f"Port {pr.port}/tcp Telnet",
                "Telnet sends all session data including credentials unencrypted.",
                remediation=["Replace Telnet with SSH", "Block Telnet at the firewall"]))
        if pr.service.lower() == "snmp":
            findings.append(_mk(
                host, "SNMP service exposed", "insecure-protocol", "high", 8, 6,
                f"Port {pr.port}/udp SNMP",
                "SNMP (esp. v1/v2c) exposes device configuration and can use default community strings.",
                remediation=["Disable SNMP or restrict to management networks",
                             "Use SNMPv3 with strong auth/privacy"]))
        if pr.service.lower() in ("mongodb", "redis", "elasticsearch", "memcached") and pr.version:
            if "unauthenticated" not in flags:
                findings.append(_mk(
                    host, f"{pr.service} exposed publicly",
                    "open-database", "high", 9, 7,
                    f"Port {pr.port}/tcp {pr.version}",
                    "Data stores should not be reachable from the internet.",
                    remediation=["Bind to private/loopback interfaces",
                                 "Restrict via firewall / security group"]))
        if base:
            level = base
            impact_map = {"informational": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}
            findings.append(_mk(
                host, f"{pr.service} exposed on port {pr.port}",
                "attack-surface", level, impact_map[level],
                5, f"Open port {pr.port}/tcp ({pr.service})",
                f"Service {pr.service} increases the attack surface and should be validated/restricted.",
                remediation=["Close unused ports", "Restrict access via firewall/ACL",
                             "Enable strong authentication"]))

    # --- CVE correlation ----------------------------------------------------
    if enable_cve:
        for pr in host.ports:
            if pr.state != "open" or not pr.version:
                continue
            key = match_software_aliases(pr.service, pr.version)
            if not key:
                continue
            for entry in match_cves(key, pr.version):
                cve_likelihood = min(10, max(3, int(entry["cvss"])))
                findings.append(_mk(
                    host, f"{display_name(key)} affected by {entry['cve']}",
                    "cve", "high" if entry["cvss"] >= 9 else "medium",
                    9, cve_likelihood,
                    f"{pr.port}/tcp {pr.version}",
                    entry["description"],
                    cve=entry["cve"],
                    remediation=[f"Upgrade {display_name(key)} to version >= {entry['fixed']}"],
                    confidence="medium"))

    # --- HTTP findings ------------------------------------------------------
    http_audits = host.http_audits or ({0: host.http} if host.http else {})
    for _port, http in http_audits.items():
        findings.extend(_analyze_http(host, http))
    return findings


def _analyze_http(host, http):
    """Evaluate HTTP audit results for a single web endpoint."""
    findings = []
    present = set(http.security_headers.keys())
    for header in SECURITY_HEADERS:
        if header not in present:
            findings.append(_mk(
                host, f"Missing HTTP security header: {header}",
                "missing-header", "low", 3, 4,
                f"{http.url} returned {http.status} without {header}",
                f"Absence of {SECURITY_HEADERS[header]} weakens clickjacking/XSS protections.",
                remediation=[f"Set '{header}' on all responses"]))
    if http.server:
        findings.append(_mk(
            host, "Server header discloses software/version",
            "info-disclosure", "low", 2, 6,
            f"{http.url} -> Server: {http.server}",
            "Exposing server versions aids attackers in targeting known vulnerabilities.",
            remediation=["Strip or obfuscate Server header", "Disable verbose server tokens"]))
    if http.powered_by:
        findings.append(_mk(
            host, "X-Powered-By header discloses technology",
            "info-disclosure", "low", 2, 5,
            f"{http.url} -> {http.powered_by}",
            "Technology fingerprinting helps attackers select exploits.",
            remediation=["Disable X-Powered-By / X-AspNet-Version headers"]))
    if http.directory_listing:
        findings.append(_mk(
            host, "Directory listing enabled",
            "misconfiguration", "medium", 5, 5,
            http.url,
            "Directory browsing exposes file structure and potentially sensitive files.",
            remediation=["Disable autoindex / DirectoryIndex listing in the web server"]))
    for path in http.found_paths:
        findings.append(_mk(
            host, f"Sensitive path exposed: /{path}",
            "exposed-panel", "medium", 6, 5,
            f"{http.url}/{path} -> 200/301/302",
            "Administrative or sensitive endpoints are reachable; assess exposure.",
            remediation=["Restrict access to admin/panel endpoints",
                         "Move sensitive files out of the web root"]))
    if http.status and not http.security_headers and not host.cdn:
        findings.append(_mk(
            host, "No HTTP security headers configured",
            "missing-header", "medium", 4, 6,
            http.url,
            "A web application with no security headers provides weak client-side protection.",
            remediation=["Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options"]))
    if http.cookies and http.cookies[0] and "httponly" not in " ".join(http.cookies).lower():
        findings.append(_mk(
            host, "Cookies set without HttpOnly/Secure flags",
            "weak-cookie", "medium", 6, 5,
            f"{http.url} Set-Cookie: {http.cookies[0][:60]}",
            "Cookies lacking HttpOnly/Secure can be stolen via XSS or transit in cleartext.",
            remediation=["Add HttpOnly and Secure flags to all cookies"]))
    for method in http.methods:
        if method in ("PUT", "DELETE", "TRACE", "PATCH"):
            findings.append(_mk(
                host, f"Dangerous HTTP method enabled: {method}",
                "misconfiguration", "medium", 6, 5,
                f"{http.url} OPTIONS -> Allow: {', '.join(http.methods)}",
                "PUT/DELETE/TRACE methods can allow content modification or XST attacks.",
                remediation=["Disable unnecessary HTTP methods in server config"]))
    return findings


def summarize(findings):
    counts = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
