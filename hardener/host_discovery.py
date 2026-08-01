"""Host Discovery: determine which systems are alive before scanning.

Uses ICMP Echo (ping subprocess fallback on Windows), TCP SYN/connect ping and
HTTP/HTTPS probing. Reduces wasted traffic against offline systems.
"""

import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import TCP_PING_PORTS
from .models import Host
from .utils import fmt_time, info, low_pri, ok, warn

# ICMP socket payload (arbitrary echo data)
_PING_DATA = b"NetworkHardenerProbe0123456789"


def icmp_ping(ip, timeout=2.0, count=1):
    """Best-effort ICMP echo.

    Attempts a raw ICMP socket (works on Linux as root / Windows admin);
    falls back to the platform `ping` binary so discovery works without
    privileges. Returns RTT in seconds, or None.
    """
    # --- raw socket attempt -------------------------------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        ident = time.time_ns() & 0xFFFF
        seq = 1
        checksum = _icmp_checksum(struct_pack := _icmp_packet(ident, seq))
        packet = struct_pack[:2] + checksum + struct_pack[4:]
        start = time.time()
        sock.sendto(packet, (ip, 0))
        while True:
            try:
                data, _addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            if _parse_icmp_reply(data, ident, seq):
                return time.time() - start
        sock.close()
    except OSError:
        pass
    # --- ping binary fallback -----------------------------------------------
    exe = "ping"
    params = ["-n", str(count), "-w", str(int(timeout * 1000))]
    if not shutil.which(exe):
        exe = "/bin/ping"
        params = ["-c", str(count), "-W", str(int(timeout))]
    try:
        proc = subprocess.run([exe, *params, ip], capture_output=True,
                              text=True, timeout=timeout + 3, creationflags=0)
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", proc.stdout, re.IGNORECASE)
        if m:
            return float(m.group(1)) / 1000.0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _icmp_packet(ident, seq):
    import struct
    header = struct.pack(">BBHHH", 8, 0, 0, ident, seq)
    return header + _PING_DATA


def _icmp_checksum(packet):
    if len(packet) % 2:
        packet += b"\x00"
    total = 0
    for i in range(0, len(packet), 2):
        total += (packet[i] << 8) + packet[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total & 0xFFFF).to_bytes(2, "big")


def _parse_icmp_reply(data, ident, seq):
    if len(data) < 28:
        return False
    # IP header len is data[0]&0x0F words
    ihl = (data[0] & 0x0F) * 4
    icmp = data[ihl:]
    if len(icmp) < 8:
        return False
    icmp_type, _code, _cs, p_ident, p_seq = icmp[0], icmp[1], icmp[2:4], \
        int.from_bytes(icmp[4:6], "big"), int.from_bytes(icmp[6:8], "big")
    return icmp_type == 0 and p_ident == ident and p_seq == seq


def tcp_ping(ip, ports=None, timeout=1.5):
    """Return (bool, port) if any common TCP port accepts a connection."""
    ports = ports or TCP_PING_PORTS
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True, port
        except OSError:
            continue
    return False, None


def http_probe(ip, timeout=2.0):
    """Return True if an HTTP or HTTPS GET returns any response."""
    for port, ssl_ in ((80, False), (443, True)):
        try:
            import ssl as _ssl
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if ssl_:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock)
            sock.connect((ip, port))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % ip.encode())
            data = sock.recv(64)
            sock.close()
            if data:
                return True
        except OSError:
            continue
    return False


def discover_host(ip, hostname=None, timeout=2.0):
    """Alive-check a single IP. Returns a Host object."""
    host = Host(ip=ip, hostname=hostname)
    info(f"Host discovery: {ip}{(' (' + hostname + ')') if hostname else ''}")

    rtt = icmp_ping(ip, timeout=timeout)
    if rtt is not None:
        host.alive = True
        host.alive_method = "ICMP"
        host.rtt_ms = rtt * 1000
        ok(f"{ip} is up via ICMP (RTT {fmt_time(rtt)})")
        return host

    tcp_alive, tcp_port = tcp_ping(ip, timeout=timeout)
    if tcp_alive:
        host.alive = True
        host.alive_method = f"TCP ping (port {tcp_port})"
        ok(f"{ip} is up via TCP connect ping on port {tcp_port}")
        return host

    if http_probe(ip, timeout=timeout):
        host.alive = True
        host.alive_method = "HTTP probe"
        ok(f"{ip} is up via HTTP probe")
        return host

    host.alive = False
    host.alive_method = "No response"
    warn(f"{ip} did not respond to ICMP/TCP/HTTP probes; skipping further scans.")
    return host


def discover_hosts(ips, hostnames=None, timeout=2.0, threads=30):
    """Parallel alive-check for a list of IPs."""
    hostnames = hostnames or {}
    hosts = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(discover_host, ip, hostnames.get(ip), timeout): ip for ip in ips}
        for fut in as_completed(futures):
            try:
                hosts.append(fut.result())
            except Exception:
                continue
    return [h for h in hosts if h.alive]
