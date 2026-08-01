"""OS Fingerprinting: TTL / window-size / banner heuristics.

Estimates whether a host runs Windows, Linux, BSD, macOS or is an embedded
appliance, and attaches a confidence score.
"""

import re
import socket
import struct

from .utils import info, low_pri, warn

# TTL heuristics per OS family (first hop typical values)
TTL_HINTS = [
    ("Linux / Unix / macOS", 60, 66),
    ("Windows", 124, 130),
    ("BSD / iOS", 60, 66),
    ("Network appliance / router", 230, 254),
    ("Embedded / IoT", 250, 255),
]


def _ttl_from_ping(ip, timeout=2.0):
    """Get TTL from an ICMP reply via raw socket (best effort)."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        ident = 0x42
        payload = b"\x08\x00\x00\x00" + struct.pack(">HH", ident, 1) + b"NetworkHardenerTTL" * 2
        # checksum
        if len(payload) % 2:
            payload += b"\x00"
        s = sum(struct.unpack(">%dH" % (len(payload) // 2), payload))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        chk = (~s & 0xFFFF).to_bytes(2, "big")
        payload = b"\x08\x00" + chk + payload[4:]
        sock.sendto(payload, (ip, 0))
        while True:
            data, _ = sock.recvfrom(2048)
            if data and data[20] == 0:  # echo reply
                return data[8]
    except OSError:
        return None
    except (IndexError, struct.error):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return None


def fingerprint_os(host, timeout=2.0):
    """Combine TTL, banners and service evidence into an OS estimate."""
    score = {"windows": 0, "linux": 0, "bsd": 0, "appliance": 0}
    evidence = []

    ttl = _ttl_from_ping(host.ip, timeout)
    if ttl is None and host.rtt_ms is not None:
        ttl = None
    if ttl is not None:
        for name, lo, hi in TTL_HINTS:
            if lo <= ttl <= hi:
                if "Windows" in name:
                    score["windows"] += 3
                elif "Linux" in name or "BSD" in name:
                    score["linux"] += 3
                elif "appliance" in name:
                    score["appliance"] += 3
                evidence.append(f"TTL={ttl} -> {name}")

    # service-based hints (only open ports carry real evidence)
    for pr in host.ports:
        if pr.state != "open":
            continue
        svc = pr.service.lower()
        ver = (pr.version or "").lower()
        if svc in ("smb", "msrpc", "netbios") or "windows" in ver:
            score["windows"] += 4
            evidence.append(f"{pr.service} on port {pr.port}")
        if "openssh" in ver or "linux" in ver:
            score["linux"] += 4
            evidence.append(f"{ver}")
        if "apache" in ver or "nginx" in ver:
            score["linux"] += 1

    if host.http and host.http.server:
        srv = host.http.server.lower()
        if "iis" in srv or "microsoft" in srv:
            score["windows"] += 4
            evidence.append(f"HTTP Server: {host.http.server}")
        elif "apache" in srv or "nginx" in srv or "lighttpd" in srv:
            score["linux"] += 2
            evidence.append(f"HTTP Server: {host.http.server}")

    if host.http and host.http.framework == "IIS":
        score["windows"] += 4

    best = max(score, key=lambda k: score[k])
    total = score[best]
    if total <= 0:
        host.os_fingerprint = {
            "os": "Unknown (insufficient evidence)",
            "confidence": 0,
            "confidence_pct": "0%",
            "evidence": evidence,
        }
    else:
        name_map = {
            "windows": "Microsoft Windows",
            "linux": "Linux / Unix-like",
            "bsd": "BSD / macOS",
            "appliance": "Embedded / Network appliance",
        }
        conf = min(total / 10.0, 1.0)
        host.os_fingerprint = {
            "os": name_map[best],
            "confidence": round(conf, 2),
            "confidence_pct": f"{conf * 100:.0f}%",
            "evidence": evidence,
        }
    info(f"OS fingerprint for {host.ip}: {host.os_fingerprint.get('os')} "
         f"(confidence {host.os_fingerprint.get('confidence_pct')})")
    for e in evidence[:6]:
        low_pri(f"  evidence: {e}")
    return host.os_fingerprint
