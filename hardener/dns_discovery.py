"""DNS & Infrastructure Discovery.

Queries A, AAAA, MX, NS, TXT, CNAME, SOA and PTR records (stdlib-only DNS
client), extracts SPF/DKIM mail infrastructure, enumerates subdomains from a
wordlist, and detects CDN / WAF fronting.
"""

import ipaddress
import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import CDN_IP_RANGES, DEFAULT_DNS_SERVERS, WAF_SIGNATURES
from .models import DNSRecord
from .utils import info, low_pri, ok, warn

# DNS record type codes we care about
QTYPE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28,
}
RTYPE_NAMES = {v: k for k, v in QTYPE.items()}

# Common subdomain wordlist (top of the popularity range)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "imap", "pop", "ns1", "ns2", "ns3", "dns",
    "admin", "webmail", "owa", "vpn", "remote", "portal", "intranet", "extranet",
    "api", "dev", "staging", "test", "qa", "beta", "demo", "prod", "backup",
    "git", "github", "gitlab", "jenkins", "ci", "cd", "build", "deploy",
    "blog", "news", "shop", "store", "pay", "billing", "secure", "auth",
    "login", "sso", "idp", "ldap", "adfs", "exchange", "autodiscover", "owa2",
    "status", "stats", "monitor", "grafana", "kibana", "logs", "metrics",
    "db", "mysql", "postgres", "redis", "mongo", "database", "sql",
    "files", "download", "uploads", "cdn", "static", "assets", "media",
    "support", "help", "docs", "wiki", "confluence", "jira", "ticket",
    "cloud", "app", "mobile", "m", "w", "office", "owa", "web", "www2",
    "cpanel", "webmail2", "host", "server", "proxy", "edge", "gateway",
    "firewall", "router", "switch", "storage", "nas", "backup2", "archive",
]


# ===========================================================================
# Minimal stdlib DNS client
# ===========================================================================

def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", errors="ignore")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data, offset):
    labels = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
        offset += length
    return ".".join(labels), end


def _build_query(name, qtype):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)
    return header + question


def _parse_response(data):
    """Parse a DNS response into (answers: list[(type, value)], authoritative=False)."""
    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = _decode_name(data, offset)
        offset += 4

    answers = []
    for _ in range(an + ns + ar):
        if offset + 10 > len(data):
            break
        rname, offset = _decode_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if rtype == 1 and rdlen == 4:                       # A
            value = socket.inet_ntop(socket.AF_INET, data[offset:offset + 4])
        elif rtype == 28 and rdlen == 16:                   # AAAA
            value = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        elif rtype in (2, 5, 12):                           # NS / CNAME / PTR
            value, _ = _decode_name(data, offset)
        elif rtype == 15 and rdlen >= 3:                    # MX
            pref = struct.unpack(">H", data[offset:offset + 2])[0]
            exch, _ = _decode_name(data, offset + 2)
            value = f"{pref} {exch}"
        elif rtype == 16:                                   # TXT
            parts = []
            pos = offset
            while pos < rdata_start + rdlen:
                ln = data[pos]
                parts.append(data[pos + 1:pos + 1 + ln].decode("utf-8", errors="ignore"))
                pos += 1 + ln
            value = "".join(parts)
        elif rtype == 6:                                    # SOA
            mname, pos = _decode_name(data, offset)
            rname2, pos = _decode_name(data, pos)
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[pos:pos + 20])
            value = f"{mname} {rname2} serial={serial}"
        else:
            value = f"<{rtype} ({rdlen}B)>"
        answers.append((rtype, value, ttl, rname))
        offset = rdata_start + rdlen
    return answers


def dns_query(name, qtype, servers=None, timeout=3.0):
    """Query name/qtype against a list of resolvers. Returns list of answers."""
    servers = servers or DEFAULT_DNS_SERVERS
    qcode = QTYPE.get(qtype.upper())
    if qcode is None:
        return []
    packet = _build_query(name, qcode)
    for server in servers:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
            answers = _parse_response(data)
            if answers:
                return answers
        except OSError:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return []


# ===========================================================================
# Discovery layer
# ===========================================================================

def resolve_host_records(hostname, servers=None):
    """Collect all DNS records for a hostname."""
    records = []
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in types:
        for (code, value, ttl, _rname) in dns_query(hostname, rtype, servers=servers):
            records.append(DNSRecord(rtype=rtype, value=value, ttl=ttl))
    return records


def extract_mail_infrastructure(records):
    """Identify mail servers, SPF and DKIM records from TXT/MX data."""
    mx = [r.value for r in records if r.rtype == "MX"]
    spf = [r.value for r in records if r.rtype == "TXT" and "v=spf1" in r.value]
    dkim = [r.value for r in records if r.rtype == "TXT" and "v=DKIM1" in r.value]
    return {"mx": mx, "spf": spf, "dkim": dkim}


def resolve_domain_ips(hostname, servers=None):
    """Return set of A records for a hostname."""
    ips = set()
    for (code, value, ttl, _rname) in dns_query(hostname, "A", servers=servers):
        if code == QTYPE["A"]:
            ips.add(value)
    return ips


def reverse_lookup(ip, servers=None):
    """PTR reverse lookup; returns list of hostnames."""
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
    except ValueError:
        return []
    out = []
    for (code, value, ttl, _rname) in dns_query(rev, "PTR", servers=servers):
        if code == QTYPE["PTR"]:
            out.append(value)
    return out


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain, servers=None, wordlist=None, threads=30):
    """Brute force common subdomains via DNS resolution."""
    wordlist = wordlist or SUBDOMAIN_WORDLIST
    found = []
    base_ips = resolve_domain_ips(domain, servers=servers)

    def check(word):
        candidate = f"{word}.{domain}"
        ips = resolve_domain_ips(candidate, servers=servers)
        if ips and ips != base_ips or (ips and candidate not in base_ips):
            return candidate, sorted(ips)
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, w): w for w in wordlist}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    found.append(res)
            except Exception:
                continue
    return found


# ---------------------------------------------------------------------------
# CDN / WAF detection
# ---------------------------------------------------------------------------

def detect_cdn(ip):
    """Return CDN name if the IP falls inside a known CDN range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cdn, ranges in CDN_IP_RANGES.items():
        for cidr in ranges:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return cdn
            except ValueError:
                continue
    return None


def detect_waf_from_headers(headers):
    """Classify a WAF/proxy from HTTP response headers."""
    if not headers:
        return None
    joined = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
    for waf, sigs in WAF_SIGNATURES.items():
        if all(s in joined for s in sigs):
            return waf.upper()
    return None


# ---------------------------------------------------------------------------
# Orchestrated discovery for a host
# ---------------------------------------------------------------------------

def discover_host_infrastructure(host, servers=None):
    """Fill DNS records, subdomains, CDN/WAF for a Host object."""
    hostname = host.hostname
    if hostname:
        records = resolve_host_records(hostname, servers=servers)
        host.dns_records = records
        mail = extract_mail_infrastructure(records)
        if mail["mx"]:
            low_pri(f"  Mail servers (MX): {', '.join(mail['mx'])}")
        if mail["spf"]:
            low_pri(f"  SPF record: {' '.join(mail['spf'])[:120]}")
        if mail["dkim"]:
            low_pri(f"  DKIM record present: {' '.join(mail['dkim'])[:120]}")
        info(f"DNS discovery for {hostname}: {len(records)} record(s) collected.")
        for r in records:
            low_pri(f"  {r.rtype:5s} {r.value}")
        subs = enumerate_subdomains(hostname, servers=servers)
        host.subdomains = [s[0] for s in subs]
        if subs:
            ok(f"Discovered {len(subs)} additional subdomain(s): {', '.join(s[0] for s in subs[:10])}")
    if host.ip:
        host.cdn = detect_cdn(host.ip)
        if host.cdn:
            warn(f"Host {host.ip} is fronted by CDN: {host.cdn}")
