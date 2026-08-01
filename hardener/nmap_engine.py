"""Optional nmap backend for port scanning.

When the `nmap` binary is present (as it is on Kali and most audit distros)
the engine delegates port scanning to nmap and parses its XML output. This is
faster and more accurate than the socket fallback, and it natively handles
awkward services, retries, and timing. When nmap is unavailable the pipeline
silently falls back to the built-in socket scanner.
"""

import shutil
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import TIMING_TEMPLATES
from .models import PortResult
from .utils import low_pri, ok, v_info, warn

# nmap scan technique flag per --scan-type
_TECHNIQUE_FLAGS = {
    "connect": "sT",
    "syn": "sS",
    "ack": "sA",
    "null": "sN",
    "fin": "sF",
    "xmas": "sX",
}

# Normalise nmap service names to the tool's service labels.
_SERVICE_LABELS = {
    "ssh": "SSH", "http": "HTTP", "https": "HTTPS", "ftp": "FTP",
    "telnet": "Telnet", "smtp": "SMTP", "pop3": "POP3", "imap": "IMAP",
    "domain": "DNS", "mysql": "MySQL", "postgresql": "PostgreSQL",
    "redis": "Redis", "mongodb": "MongoDB", "memcached": "Memcached",
    "smb": "SMB", "microsoft-ds": "SMB", "netbios-ssn": "NetBIOS-SSN",
    "netbios-ns": "NetBIOS-NS", "msrpc": "MSRPC", "nfs": "NFS",
    "rpcbind": "RPC", "sunrpc": "RPC", "vnc": "VNC", "rdp": "RDP",
    "ms-wbt-server": "RDP", "http-proxy": "HTTP-Proxy", "socks": "SOCKS",
    "docker": "Docker", "kibana": "Kibana", "elasticsearch": "Elasticsearch",
    "oracle-tns": "Oracle-TNS", "ldap": "LDAP", "ldaps": "LDAPS",
    "smtps": "SMTPS", "imaps": "IMAPS", "pop3s": "POP3S",
    "kerberos-sec": "Kerberos", "webmin": "Webmin", "ajp": "Apache-JServ",
    "java-rmi": "Java-RMI", "ingreslock": "IngresLock",
    "shell": "rsh", "login": "rlogin", "exec": "rexec",
    "irc": "IRC", "nntp": "NNTP", "ntp": "NTP", "snmp": "SNMP",
    "isakmp": "ISAKMP/VPN", "unknown": "unknown",
}

_NMAP_BIN = shutil.which("nmap")


def nmap_available():
    """True if the nmap binary is on PATH."""
    return _NMAP_BIN is not None


def _service_label(name):
    if not name:
        return "unknown"
    return _SERVICE_LABELS.get(name.lower(), name.replace("_", "-").title())


def _banner_from_service(service):
    """Compose a version/banner string from nmap's service element."""
    if service is None:
        return None
    parts = [service.get("product", ""), service.get("version", ""),
             service.get("extrainfo", "")]
    banner = " ".join(p for p in parts if p).strip()
    return banner or None


def parse_nmap_xml(xml_text):
    """Parse nmap -oX XML into (host_up, list[PortResult]).

    Returns (up: bool, ports: list[PortResult]). Handles both per-host and
    per-port state elements. Unknown or malformed sections are ignored.
    """
    root = ET.fromstring(xml_text)
    host = root.find(".//host")
    if host is None:
        return False, []
    status = host.find("status")
    up = status is not None and status.get("state") == "up"

    ports = []
    for port in host.findall(".//ports/port"):
        try:
            portid = int(port.get("portid"))
        except (TypeError, ValueError):
            continue
        protocol = port.get("protocol", "tcp")
        state_el = port.find("state")
        state = state_el.get("state", "filtered") if state_el is not None else "filtered"
        reason = state_el.get("reason") if state_el is not None else ""
        service = port.find("service")
        svc_label = _service_label(service.get("name") if service is not None else None)
        banner = _banner_from_service(service)
        ports.append(PortResult(
            port=portid,
            protocol=protocol,
            state=state,
            service=svc_label,
            version=banner or "",
            scan_evidence={"method": "nmap", "note": reason or "nmap"},
            banners=[banner] if banner else [],
        ))
    return up, ports


def _estimate_timeout(port_count, timing, host_timeout):
    """Budget a subprocess timeout so nmap can never hang the run."""
    if host_timeout and host_timeout > 0:
        return host_timeout + 60
    threads = TIMING_TEMPLATES.get(timing, (50, 2.0, 0.0))[0]
    probe = TIMING_TEMPLATES.get(timing, (50, 2.0, 0.0))[1]
    est = (port_count / max(threads, 1)) * probe + 30
    return max(60, min(est, 1800))


def _build_cmd(ip, ports, scan_type="connect", timing=3, timeout=2.0,
               retries=0, version_detect=False, host_timeout=0.0, udp=False,
               bin_path=None):
    technique = _TECHNIQUE_FLAGS.get(scan_type, "sT")
    nmap = bin_path or _NMAP_BIN or "nmap"
    cmd = [nmap, "-Pn", f"-{technique}"]
    if udp:
        cmd = [nmap, "-Pn", "-sU"]
        if scan_type == "connect":
            cmd.append("-sT")
    cmd += ["-T%d" % max(0, min(timing, 5))]
    cmd.append("-p")
    if ports:
        cmd.append(",".join(str(p) for p in ports))
    else:
        cmd.append("1-65535")
    cmd += ["--max-retries", str(max(0, retries))]
    if host_timeout and host_timeout > 0:
        cmd += ["--host-timeout", f"{host_timeout}s"]
    else:
        cmd += ["--host-timeout", f"{max(timeout, 2.0) * 2}s"]
    if version_detect:
        cmd.append("-sV")
    cmd += ["-oX", "-", ip]
    return cmd


def _run_nmap(cmd, port_count, timing, host_timeout):
    """Run nmap, capturing XML; retries with -sT if -sS needs root."""
    budget = _estimate_timeout(port_count, timing, host_timeout)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=budget)
    except subprocess.TimeoutExpired:
        warn("nmap timed out (host timeout exceeded); marking host filtered.")
        return "", ""
    if proc.returncode != 0 and "-sS" in cmd:
        low_pri("nmap -sS needs root; falling back to -sT connect scan.")
        cmd = [c if c != "-sS" else "-sT" for c in cmd]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=budget)
        except subprocess.TimeoutExpired:
            warn("nmap timed out (host timeout exceeded); marking host filtered.")
            return "", ""
    return proc.stdout, proc.stderr


def nmap_tcp_scan(ip, ports, timeout=2.0, timing=3, scan_type="connect",
                  retries=0, version_detect=False, host_timeout=0.0,
                  limiter=None):
    """Scan TCP ports with nmap; returns list of PortResult (empty if down)."""
    cmd = _build_cmd(ip, ports, scan_type=scan_type, timing=timing,
                     timeout=timeout, retries=retries,
                     version_detect=version_detect, host_timeout=host_timeout)
    stdout, _stderr = _run_nmap(cmd, len(ports), timing, host_timeout)
    if not stdout:
        warn(f"nmap produced no output for {ip}.")
        return []
    try:
        up, results = parse_nmap_xml(stdout)
    except ET.ParseError as exc:
        warn(f"Could not parse nmap output for {ip}: {exc}")
        return []
    if not up:
        warn(f"nmap reports {ip} is down.")
        return []
    open_ports = sorted(r.port for r in results if r.state == "open")
    if open_ports:
        ok(f"{ip}: {len(open_ports)} open TCP port(s): {open_ports}")
    else:
        warn(f"{ip}: no open TCP ports in scanned set.")
    return results


def nmap_udp_scan(ip, ports, timeout=2.0, timing=3, retries=0,
                  host_timeout=0.0):
    """Scan UDP ports with nmap; returns list of PortResult."""
    cmd = _build_cmd(ip, ports, scan_type="connect", timing=timing,
                     timeout=timeout, retries=retries, host_timeout=host_timeout,
                     udp=True)
    stdout, _stderr = _run_nmap(cmd, len(ports), timing, host_timeout)
    if not stdout:
        warn(f"nmap produced no output for {ip} (UDP).")
        return []
    try:
        _up, results = parse_nmap_xml(stdout)
    except ET.ParseError as exc:
        warn(f"Could not parse nmap UDP output for {ip}: {exc}")
        return []
    open_ports = sorted(r.port for r in results if r.state == "open")
    if open_ports:
        ok(f"{ip}: {len(open_ports)} open UDP port(s): {open_ports}")
    return results


def nmap_scan_hosts(ip, ports, **kwargs):
    """Convenience wrapper matching the socket scanner's call shape."""
    return nmap_tcp_scan(ip, ports, **kwargs)


def nmap_scan_hosts_parallel(ip_ports, threads=10, **kwargs):
    """Run nmap against several (ip, ports) pairs concurrently."""
    v_info(2, f"nmap backend scanning {len(ip_ports)} host(s).")
    out = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(nmap_tcp_scan, ip, ports, **kwargs): ip
                   for ip, ports in ip_ports}
        for fut in as_completed(futures):
            try:
                out[futures[fut]] = fut.result()
            except Exception:
                continue
    return out
