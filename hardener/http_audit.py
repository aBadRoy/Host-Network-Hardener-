"""HTTP Security Audit: headers, methods, directory listing, admin panels.

Produces an HttpInfo object with security-relevant facts used by the analysis
and risk layers.
"""

import re
import socket
import ssl
from urllib.parse import urljoin

from .config import SENSITIVE_PATHS, SECURITY_HEADERS
from .models import HttpInfo
from .utils import low_pri, ok, vuln, warn

USER_AGENT = "Mozilla/5.0 (compatible; HostNetworkHardener/1.0)"


def _raw_request(ip, port, path, method="GET", headers=None, use_ssl=False,
                 timeout=2.0):
    headers = headers or {}
    req_lines = [f"{method} {path} HTTP/1.1", f"Host: {ip}", f"User-Agent: {USER_AGENT}",
                 "Connection: close"]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    req = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        sock.connect((ip, port))
        sock.sendall(req)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", errors="ignore")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        status = 0
        if lines:
            m = re.match(r"HTTP/\d\.\d\s+(\d+)", lines[0])
            if m:
                status = int(m.group(1))
        headers_out = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers_out[k.strip().lower()] = v.strip()
        return status, headers_out, body
    except (OSError, ssl.SSLError):
        return 0, {}, ""


def audit_http(ip, port, use_ssl=False, timeout=2.0):
    """Full HTTP audit for a host:port. Returns HttpInfo."""
    scheme = "https" if use_ssl else "http"
    info = HttpInfo(url=f"{scheme}://{ip}:{port}", status=0)

    status, headers, body = _raw_request(ip, port, "/", use_ssl=use_ssl, timeout=timeout)
    info.status = status
    info.headers = headers
    if status == 0:
        return info
    info.server = headers.get("server", "")
    info.powered_by = headers.get("x-powered-by", "") or headers.get("x-aspnet-version", "")
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    info.title = m.group(1).strip() if m else ""
    info.cookies = headers.get("set-cookie", "").split(";")

    info.framework = _detect_framework(headers, body)

    for h, label in SECURITY_HEADERS.items():
        if h in headers:
            info.security_headers[h] = headers[h]

    if body and "<ul>" in body and re.search(r"<a href=\"[^\"]+\"", body):
        if "Index of" in body or "Parent Directory" in body:
            info.directory_listing = True

    # methods
    _status, _h, _b = _raw_request(ip, port, "/", method="OPTIONS", use_ssl=use_ssl, timeout=timeout)
    allow = _h.get("allow") or _h.get("public")
    if allow:
        info.methods = [m.strip().upper() for m in allow.split(",")]

    # sensitive paths
    for path in SENSITIVE_PATHS:
        _s, _hd, _bd = _raw_request(ip, port, "/" + path, use_ssl=use_ssl, timeout=timeout)
        if _s in (200, 301, 302) and path not in ("robots.txt",):
            info.found_paths.append(path)

    # WAF detection hook
    from .dns_discovery import detect_waf_from_headers
    info = _attach_waf(info, detect_waf_from_headers(headers))

    _print_audit(info, ip, port)
    return info


def _attach_waf(info, waf):
    info.headers["_waf"] = waf or "none"
    return info


def _detect_framework(headers, body):
    text = (str(headers) + " " + body[:2000]).lower()
    markers = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal", "x-generator: drupal"],
        "Joomla": ["joomla"],
        "PHP": ["x-powered-by: php", "php/" ],
        "ASP.NET": ["x-aspnet-version", "asp.net"],
        "Ruby on Rails": ["rails", "x-powered-by: phusion"],
        "Django": ["csrftoken", "x-frame-options: deny"],
        "Node.js/Express": ["x-powered-by: express"],
        "Nginx": ["server: nginx"],
        "Apache": ["server: apache"],
        "IIS": ["server: microsoft-iis", "server: microsoft-httpapi"],
        "Tomcat": ["server: apache-coyote"],
    }
    for name, sigs in markers.items():
        if any(s in text for s in sigs):
            return name
    return ""


def _print_audit(info, ip, port):
    low_pri(f"  HTTP audit {info.url}: status {info.status or 'no response'}"
            f"{' | ' + info.server if info.server else ''}"
            f"{' | ' + info.powered_by if info.powered_by else ''}"
            f"{' | title: ' + info.title[:60] if info.title else ''}")
    for h in SECURITY_HEADERS:
        if h in info.security_headers:
            ok(f"    [+] Security header present: {h.upper()}")
    if info.directory_listing:
        vuln(f"    [VULN] Directory listing enabled on {info.url}")
    if info.found_paths:
        for p in info.found_paths:
            warn(f"    [-] Sensitive path exposed: /{p}")
    waf = info.headers.get("_waf")
    if waf and waf != "none":
        ok(f"    [+] WAF detected: {waf}")
