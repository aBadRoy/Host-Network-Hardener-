"""Service Enumeration: protocol handshakes, banner analysis and version ID.

For every open port the matching probe is dispatched. Each probe returns
a dict with version information, captured banners and structured enumeration
telemetry consumed by the analysis/risk/report layers.
"""

import re
import socket
import ssl
import struct

from .utils import low_pri, sanitize_text


def _tcp_socket(timeout, ssl_wrap=False, hostname=None, port=None, ctx=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if ssl_wrap:
        context = ctx or ssl.create_default_context()
        if ctx is None:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=hostname)
        if port is not None:
            sock.connect((hostname, port))
    return sock


def _read_banner(sock, n=1024):
    try:
        data = sock.recv(n)
    except OSError:
        return ""
    return sanitize_text(data.decode("utf-8", errors="replace")).strip()


# ---------------------------------------------------------------------------
# Individual service probes
# ---------------------------------------------------------------------------

def probe_ftp(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}, "flags": []}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        banner = _read_banner(s)
        out["banners"].append(banner)
        out["version"] = banner
        out["enumeration"]["banner"] = banner
        if "ftp" in banner.lower():
            s.sendall(b"FEAT\r\n")
            feat = _read_banner(s, 2048)
            out["enumeration"]["features"] = feat
            if "AUTH TLS" in feat.upper() or "AUTH SSL" in feat.upper():
                out["flags"].append("ftps_supported")
        # anonymous login check
        s.sendall(b"USER anonymous\r\n")
        r1 = _read_banner(s)
        s.sendall(b"PASS anonymous@none.invalid\r\n")
        r2 = _read_banner(s)
        if r2.startswith("230") or "logged in" in r2.lower():
            out["flags"].append("anonymous_login")
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_ssh(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        banner = _read_banner(s)
        out["banners"].append(banner)
        out["version"] = banner
        out["enumeration"]["banner"] = banner
        m = re.search(r"SSH-2\.0-([^\s]+)", banner)
        if m:
            out["enumeration"]["software"] = m.group(1)
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_telnet(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    IAC = b"\xff"
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        data = s.recv(2048)
        printable = re.sub(rb"\xff[\xfb-\xfe].", b"", data)
        banner = printable.decode("utf-8", errors="ignore").strip()
        out["banners"].append(banner or "IAC-only response")
        out["version"] = banner or "Telnet (cleartext)"
        out["enumeration"]["negotiation"] = f"{len(data)} bytes IAC negotiation"
        out["enumeration"]["cleartext"] = "Telnet transmits credentials in cleartext"
        out["enumeration"]["banner"] = banner
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_smtp(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    use_tls = port in (465,)
    try:
        s = _tcp_socket(timeout, ssl_wrap=use_tls, hostname=ip, port=port)
        banner = _read_banner(s)
        out["banners"].append(banner)
        out["version"] = banner
        out["enumeration"]["banner"] = banner
        s.sendall(b"EHLO hardener.local\r\n")
        ehlo = _read_banner(s, 4096)
        caps = [ln[4:].strip() for ln in ehlo.splitlines()
                if ln.startswith("250-") or ln.startswith("250 ")]
        if caps:
            out["enumeration"]["capabilities"] = caps
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_pop3(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    use_tls = port == 995
    try:
        s = _tcp_socket(timeout, ssl_wrap=use_tls, hostname=ip, port=port)
        banner = _read_banner(s)
        out["banners"].append(banner)
        out["version"] = banner
        out["enumeration"]["banner"] = banner
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_imap(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    use_tls = port == 993
    try:
        s = _tcp_socket(timeout, ssl_wrap=use_tls, hostname=ip, port=port)
        banner = _read_banner(s)
        out["banners"].append(banner)
        out["version"] = banner
        out["enumeration"]["banner"] = banner
        if not use_tls:
            s.sendall(b"a001 CAPABILITY\r\n")
            out["enumeration"]["capability"] = _read_banner(s, 2048)
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_ldap(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    use_tls = port == 636
    try:
        s = _tcp_socket(timeout, ssl_wrap=use_tls, hostname=ip, port=port)
        bind_req = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.sendall(bind_req)
        resp = s.recv(1024)
        out["enumeration"]["bind_response"] = resp.hex()[:40]
        if resp and resp[0] == 0x30:
            out["version"] = "Active LDAP (BER bind response)"
            out["enumeration"]["anonymous_bind"] = "possible (check result code)"
        else:
            out["version"] = "LDAP service open"
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_smb(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}, "flags": []}
    smb_header = (b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00"
                  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    payload = smb_header + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    netbios = struct.pack("!xL", len(payload))
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(netbios + payload)
        resp = s.recv(1024)
        s.close()
        if b"\xffSMB" in resp:
            out["version"] = "SMBv1 dialect accepted"
            out["flags"].append("smbv1")
        elif b"\xfeSMB" in resp:
            out["version"] = "SMBv2/v3 dialect negotiated"
            out["flags"].append("smbv2")
        else:
            out["version"] = "SMB active"
        out["enumeration"]["negotiation"] = out["version"]
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_kerberos(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(b"\x6e\x81\x00\x00")  # empty TGS-REQ
        resp = s.recv(1024)
        s.close()
        if resp:
            out["version"] = "Kerberos KDC (v5) responding"
            out["enumeration"]["response_len"] = len(resp)
        else:
            out["version"] = "Kerberos port open"
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_oracle(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    tns = (b"\x00\x3a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00"
           b"\x7f\xff\x01\x00\x00\x00\x00\x20\x00\x3a\x00\x01\x20\x00\x00\x00"
           b"(CONNECT_DATA=(COMMAND=version))")
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(tns)
        data = s.recv(2048).decode("utf-8", errors="ignore")
        s.close()
        if "VSNNUM" in data:
            out["version"] = "Oracle TNS Listener (version data present)"
        else:
            out["version"] = "Oracle service open"
        out["enumeration"]["response"] = data[:80].strip()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_mysql(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        data = s.recv(1024)
        s.close()
        if len(data) >= 5 and data[4] == 10:
            null_idx = data.find(b"\x00", 5)
            ver = data[5:null_idx].decode("utf-8", errors="ignore")
            out["version"] = f"MySQL/MariaDB {ver}"
            out["enumeration"]["version"] = ver
        else:
            out["version"] = "MySQL protocol open"
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_postgres(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(struct.pack("!II", 8, 80877103))
        resp = s.recv(1)
        s.close()
        if resp == b"S":
            out["version"] = "PostgreSQL (SSL supported)"
            out["enumeration"]["ssl"] = "supported"
        elif resp == b"N":
            out["version"] = "PostgreSQL (SSL disabled)"
            out["enumeration"]["ssl"] = "disabled"
        else:
            out["version"] = "PostgreSQL service open"
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_redis(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}, "flags": []}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(b"INFO\r\n")
        data = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        m = re.search(r"redis_version:([^\r\n]+)", data)
        if m:
            out["version"] = f"Redis {m.group(1)}"
            out["enumeration"]["version"] = m.group(1)
            out["flags"].append("unauthenticated")  # INFO returned without AUTH
        elif "NOAUTH" in data or "WRONGPASS" in data:
            out["version"] = "Redis (auth required)"
        else:
            out["version"] = "Redis service open"
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_mongodb(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}, "flags": []}
    ismaster = (b"\x3d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00"
                b"\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00")
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(ismaster)
        resp = s.recv(1024)
        s.close()
        if resp and (b"ismaster" in resp or b"ok" in resp):
            out["version"] = "MongoDB (wire protocol responding)"
            out["flags"].append("unauthenticated")
        else:
            out["version"] = "MongoDB service open"
        out["enumeration"]["response_len"] = len(resp)
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_elasticsearch(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}, "flags": []}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % ip.encode())
        data = s.recv(2048).decode("utf-8", errors="ignore")
        s.close()
        m = re.search(r'"number"\s*:\s*"([^"]+)"', data)
        if m:
            out["version"] = f"Elasticsearch {m.group(1)}"
            out["enumeration"]["version"] = m.group(1)
        else:
            out["version"] = "Elasticsearch-like HTTP open"
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_memcached(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(b"stats\r\n")
        data = s.recv(2048).decode("utf-8", errors="ignore")
        s.close()
        if "STAT " in data:
            out["version"] = "Memcached"
            out["enumeration"]["stats"] = data[:200]
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_vnc(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        data = s.recv(12)
        s.close()
        if len(data) >= 12:
            out["version"] = f"VNC protocol {data[0]}"
            out["enumeration"]["handshake"] = data.hex()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_rdp(ip, port, timeout):
    """RDP negotiation request; detect protocol + OS hints from NLA."""
    out = {"version": "", "banners": [], "enumeration": {}}
    neg_req = struct.pack("<BBHI", 1, 0, 0x0008, 0x00000001)
    x224 = b"\xe0\x00\x00\x00\x00\x00" + neg_req
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(tpkt)
        resp = s.recv(2048)
        s.close()
        if resp:
            out["version"] = "RDP (TLS negotiation offered)"
            out["enumeration"]["negotiation_response"] = resp.hex()[:64]
            if len(resp) >= 19:
                proto = struct.unpack("<I", resp[15:19])[0]
                out["enumeration"]["selected_protocol"] = proto
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_mssql(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b"
                  b"\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01"
                  b"\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00"
                  b"\x00\x00\x00\x00")
        data = s.recv(1024)
        s.close()
        if data:
            out["version"] = "MSSQL (TDS prelogin response)"
            out["enumeration"]["response_len"] = len(data)
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def probe_dns_tcp(ip, port, timeout):
    out = {"version": "", "banners": [], "enumeration": {}}
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        s.sendall(struct.pack(">H", len(q)) + q)
        data = s.recv(1024)
        s.close()
        if data:
            out["version"] = "DNS (TCP) responding"
            out["enumeration"]["response_len"] = len(data)
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _probe(ip, port, timeout):
    probes = {
        21: probe_ftp,
        22: probe_ssh,
        23: probe_telnet,
        25: probe_smtp,
        465: probe_smtp,
        587: probe_smtp,
        110: probe_pop3,
        995: probe_pop3,
        143: probe_imap,
        993: probe_imap,
        389: probe_ldap,
        636: probe_ldap,
        445: probe_smb,
        88: probe_kerberos,
        1521: probe_oracle,
        3306: probe_mysql,
        5432: probe_postgres,
        6379: probe_redis,
        27017: probe_mongodb,
        9200: probe_elasticsearch,
        11211: probe_memcached,
        5900: probe_vnc,
        3389: probe_rdp,
        1433: probe_mssql,
    }
    if port in probes:
        return probes[port](ip, port, timeout)
    # generic banner grab
    out = {"version": "", "banners": [], "enumeration": {}}
    try:
        s = _tcp_socket(timeout)
        s.connect((ip, port))
        banner = _read_banner(s)
        if banner:
            out["banners"].append(banner)
            out["version"] = banner
            out["enumeration"]["banner"] = banner
        s.close()
    except OSError as exc:
        out["enumeration"]["error"] = str(exc)
    return out


def _refine_service(port_result):
    """When a port is not on the well-known map, infer service from its banner."""
    if port_result.service != "unknown":
        return
    text = f"{port_result.version} {' '.join(port_result.banners)}".lower()
    hints = [
        ("SSH", ["openssh", "ssh-2.0"]),
        ("FTP", ["ftp", "vsftpd", "proftpd", "220 "]),
        ("Telnet", ["telnet"]),
        ("HTTP", ["http/1.", "nginx", "apache", "iis", "server:"]),
        ("MySQL", ["mysql", "mariadb"]),
        ("PostgreSQL", ["postgresql", "postgres"]),
        ("Redis", ["redis"]),
        ("MongoDB", ["mongodb"]),
        ("SMTP", ["smtp", "esmtp", "220"]),
        ("SMB", ["smb"]),
        ("LDAP", ["ldap"]),
        ("RDP", ["rdp"]),
        ("VNC", ["vnc"]),
    ]
    for name, markers in hints:
        if any(m in text for m in markers):
            port_result.service = name
            return


def enumerate_port(ip, port_result, timeout=2.0):
    """Run the app-layer probe for an open port; populate PortResult."""
    data = _probe(ip, port_result.port, timeout)
    port_result.version = data.get("version") or port_result.version
    port_result.banners = data.get("banners") or port_result.banners
    port_result.enumeration = data.get("enumeration") or {}
    port_result.scan_evidence["flags"] = data.get("flags", [])
    _refine_service(port_result)
    if data.get("version"):
        low_pri(f"  -> {port_result.port}/tcp {port_result.service}: {port_result.version}")
    return port_result
