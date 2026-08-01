"""Remediation Guidance: actionable recommendations per finding category."""

REMEDIATION_MAP = {
    "insecure-protocol": [
        "Disable legacy protocols (SMBv1, Telnet, SNMPv1, FTP).",
        "Prefer authenticated and encrypted alternatives (SFTP, SSH, SMBv2+, SNMPv3).",
    ],
    "weak-tls": [
        "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or 1.3.",
        "Disable RC4, DES, NULL, EXPORT and CBC ciphers; use AEAD suites.",
        "Apply web-server TLS hardening templates (Mozilla Intermediate/Modern).",
    ],
    "missing-header": [
        "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options and Referrer-Policy.",
        "Review and tighten Content-Security-Policy after rollout.",
    ],
    "info-disclosure": [
        "Disable Server and X-Powered-By headers; set server_tokens off.",
        "Remove verbose error pages and stack traces from production.",
    ],
    "misconfiguration": [
        "Disable directory autoindexing.",
        "Disable unnecessary HTTP methods (PUT/DELETE/TRACE).",
        "Audit web server configuration against CIS benchmarks.",
    ],
    "exposed-panel": [
        "Restrict admin/management endpoints by IP or VPN.",
        "Move sensitive files out of the web root; enforce strong auth + MFA.",
    ],
    "weak-cookie": [
        "Set Secure and HttpOnly flags on all session cookies.",
        "Use SameSite=Strict/Lax and short session lifetimes.",
    ],
    "certificate": [
        "Renew and automate certificate lifecycle management (e.g., ACME).",
        "Replace self-signed certificates with CA-issued ones.",
    ],
    "open-database": [
        "Bind databases to loopback / private interfaces only.",
        "Enforce authentication and strong passwords; remove default credentials.",
        "Restrict access with firewall rules / security groups.",
    ],
    "weak-auth": [
        "Disable anonymous or guest access.",
        "Enforce strong passwords, MFA and account lockout policies.",
    ],
    "cleartext": [
        "Replace cleartext services with encrypted ones (SSH, FTPS, HTTPS).",
        "Block cleartext ports at the firewall.",
    ],
    "attack-surface": [
        "Close unnecessary ports; adopt allow-list firewall rules.",
        "Segment the network to limit reachability of sensitive services.",
        "Inventory all exposed services and owners.",
    ],
    "cve": [
        "Patch and upgrade software to fixed versions immediately.",
        "Add compensating controls while patching is pending (WAF rules, network ACLs).",
        "Subscribe to vendor security advisories.",
    ],
    "general": [
        "Review the finding in the context of the environment.",
        "Apply vendor hardening guidance and industry benchmarks.",
    ],
}


def get_remediation(category):
    return REMEDIATION_MAP.get(category, REMEDIATION_MAP["general"])


def attach_remediation(finding):
    if not finding.remediation:
        finding.remediation = list(get_remediation(finding.category))
    return finding


def attach_remediation_all(findings):
    for f in findings:
        attach_remediation(f)
    return findings
