"""Port Scanner: TCP connect, TCP SYN (scapy) and UDP scans with threading.

A high-trust CONNECT scan plus optional SYN stealth and UDP probes determine
open/closed/filtered states for the configured port set.
"""

import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import PORT_SERVICES
from .models import PortResult
from .utils import low_pri, ok, warn

try:
    from scapy.all import IP, TCP, sr1, send  # noqa: F401
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


# ===========================================================================
# TCP connect scan
# ===========================================================================

def tcp_connect_scan(ip, port, timeout=2.0):
    """Return (state, evidence) using a plain TCP three-way handshake."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        result = sock.connect_ex((ip, port))
        latency = time.time() - start
        if result == 0:
            sock.settimeout(1.0)
            try:
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            except OSError:
                banner = ""
            return "open", {"method": "connect", "rtt": round(latency * 1000, 1),
                            "banner": banner}
        return "closed", {"method": "connect", "errno": result}
    except socket.timeout:
        return "filtered", {"method": "connect", "note": "timeout"}
    except OSError as exc:
        return "filtered", {"method": "connect", "note": str(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ===========================================================================
# TCP SYN scan (requires scapy + raw socket privileges)
# ===========================================================================

def scapy_available():
    return _SCAPY_OK


def tcp_syn_scan(ip, port, timeout=2.0):
    """Stealth SYN probe; SYN-ACK => open, RST => closed, else filtered."""
    if not _SCAPY_OK:
        return "filtered", {"method": "syn", "note": "scapy not installed"}
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(packet, timeout=timeout, verbose=0)
        if resp is None:
            return "filtered", {"method": "syn", "note": "no response"}
        if resp.haslayer(TCP):
            if resp[TCP].flags & 0x12 == 0x12:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
                return "open", {"method": "syn"}
            if resp[TCP].flags & 0x14 == 0x14:
                return "closed", {"method": "syn"}
        return "filtered", {"method": "syn", "note": "no TCP layer"}
    except OSError as exc:
        return "filtered", {"method": "syn", "note": f"raw socket unavailable: {exc}"}


# ===========================================================================
# UDP scan (connected-socket technique, works without raw sockets)
# ===========================================================================

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03",           # DNS chaos version.bind
    67: b"\x01\x01\x06\x00" + b"\x00" * 236,                   # DHCP discover
    69: b"\x00\x01test\x00octet\x00",                          # TFTP RRQ
    123: b"\x1b" + b"\x00" * 47,                               # NTP v3
    137: b"\x80\x90\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         b"\x00\x00\x21\x00\x01",                              # NetBIOS name query
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
          b"\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b"
          b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",      # SNMP get-next
    500: b"\x00" * 28,                                          # ISAKMP
    5353: b"\x00\x00\x00\x00",                                  # mDNS
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n",
}


def udp_scan(ip, port, timeout=2.0):
    """UDP probe using a connected socket.

    - response/data received        -> open
    - ICMP port unreachable (ECONNREFUSED) -> closed
    - timeout                        -> open|filtered (filtered)
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        probe = UDP_PROBES.get(port, b"\x00" * 8)
        sock.send(probe)
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                return "open", {"method": "udp", "bytes": len(data)}
        except socket.timeout:
            return "filtered", {"method": "udp", "note": "open|filtered (no ICMP)"}
        except OSError as exc:
            if getattr(exc, "errno", None) in (10054, 111):  # ECONNRESET / refused
                return "closed", {"method": "udp", "note": "ICMP port unreachable"}
            return "filtered", {"method": "udp", "note": str(exc)}
        return "filtered", {"method": "udp", "note": "no reply"}
    except OSError as exc:
        if getattr(exc, "errno", None) in (10054, 111):
            return "closed", {"method": "udp", "note": "ICMP port unreachable"}
        return "filtered", {"method": "udp", "note": str(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ===========================================================================
# Orchestrated scanning
# ===========================================================================

def _scan_one_tcp(ip, port, timeout, use_syn):
    if use_syn and scapy_available():
        state, evidence = tcp_syn_scan(ip, port, timeout)
    else:
        state, evidence = tcp_connect_scan(ip, port, timeout)
    result = PortResult(port=port, protocol="tcp", state=state,
                        service=PORT_SERVICES.get((port, "tcp"), "unknown"),
                        scan_evidence=evidence)
    if state == "open" and evidence.get("banner"):
        result.banners.append(evidence["banner"])
    return result


def _scan_one_udp(ip, port, timeout):
    state, evidence = udp_scan(ip, port, timeout)
    return PortResult(port=port, protocol="udp", state=state,
                      service=PORT_SERVICES.get((port, "udp"), "unknown"),
                      scan_evidence=evidence)


def scan_tcp_ports(ip, ports, timeout=2.0, threads=50, use_syn=False,
                   progress_label=""):
    """Scan a list of TCP ports; returns list of PortResult."""
    results = []
    label = progress_label or ip
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one_tcp, ip, p, timeout, use_syn): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                continue
    open_ports = sorted(r.port for r in results if r.state == "open")
    if open_ports:
        ok(f"{label}: {len(open_ports)} open TCP port(s): {open_ports}")
    else:
        warn(f"{label}: no open TCP ports in scanned set.")
    for r in sorted(results, key=lambda x: x.port):
        if r.state == "open":
            low_pri(f"  {r.port:6d}/tcp  {r.service}")
    return results


def scan_udp_ports(ip, ports, timeout=2.0, threads=20, progress_label=""):
    """Scan a list of UDP ports; returns list of PortResult."""
    results = []
    label = progress_label or ip
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one_udp, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                continue
    open_ports = sorted(r.port for r in results if r.state == "open")
    if open_ports:
        ok(f"{label}: {len(open_ports)} open UDP port(s): {open_ports}")
    for r in sorted(results, key=lambda x: x.port):
        if r.state == "open":
            low_pri(f"  {r.port:6d}/udp  {r.service}")
    return results
