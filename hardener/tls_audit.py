"""TLS/SSL Audit: protocol versions, weak ciphers and certificate checks.

Evaluates deprecated protocols (TLS 1.0/1.1), weak cipher support, and
certificate validity/expiry for HTTPS/WinRM/RDP/LDAPS style endpoints.
"""

import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .utils import low_pri, ok, warn, vuln

TLS_VERSIONS = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

WEAK_CIPHERS = [
    "RC4", "DES", "NULL", "EXPORT", "anon", "3DES", "CBC-SHA"
]

DEPRECATED = {"TLSv1": "deprecated", "TLSv1.1": "deprecated"}


def audit_tls(ip, port, timeout=2.0, hostname=None):
    """Return a dict of TLS findings for a TLS endpoint."""
    result = {
        "versions": {},            # version -> bool
        "certificate": {},         # parsed cert facts
        "weak_ciphers": [],
        "errors": [],
        "tls_enabled": False,
    }
    host = hostname or ip
    cert_bytes = None

    for label, ver in TLS_VERSIONS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            sock = socket.create_connection((ip, port), timeout=timeout)
            tls = ctx.wrap_socket(sock, server_hostname=host)
            tls.settimeout(timeout)
            cipher = tls.cipher()
            result["versions"][label] = True
            result["tls_enabled"] = True
            if cipher:
                cname = cipher[0]
                for w in WEAK_CIPHERS:
                    if w in cname:
                        result["weak_ciphers"].append(f"{label}:{cname}")
            try:
                der = tls.getpeercert(binary_form=True)
                if der:
                    cert_bytes = der
            except Exception:
                pass
            tls.close()
        except (OSError, ssl.SSLError, ssl.SSLCertVerificationError):
            result["versions"][label] = False

    if cert_bytes:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            result["certificate"] = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "expired": cert.not_valid_after_utc < datetime.now(timezone.utc),
                "self_signed": cert.subject.rfc4514_string() == cert.issuer.rfc4514_string(),
                "serial": str(cert.serial_number)[:16],
            }
        except Exception as exc:
            result["errors"].append(f"cert parse: {exc}")

    _print_tls(result, ip, port)
    return result


def _print_tls(result, ip, port):
    if not result["tls_enabled"]:
        warn(f"  TLS audit {ip}:{port}: TLS handshake failed (may be non-TLS or filtered).")
        return
    supported = [v for v, okv in result["versions"].items() if okv]
    ok(f"  TLS audit {ip}:{port}: supported {', '.join(supported) or 'none'}")
    for v in supported:
        if v in DEPRECATED:
            vuln(f"    [VULN] Deprecated protocol enabled: {v}")
    for c in result["weak_ciphers"]:
        vuln(f"    [VULN] Weak cipher offered: {c}")
    cert = result["certificate"]
    if cert:
        if cert.get("expired"):
            vuln(f"    [VULN] Certificate EXPIRED on {cert['not_after']}")
        if cert.get("self_signed"):
            warn(f"    [-] Certificate is self-signed: {cert['subject']}")
        low_pri(f"    Cert subject: {cert.get('subject')}")
