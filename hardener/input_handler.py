"""Input Handler: parses user-supplied targets into validated Target objects.

Supports single IPs, CIDR ranges, hostnames, and URLs. Multiple targets may be
given as comma/whitespace separated values or via a target file (one per line).
"""

import ipaddress
from urllib.parse import urlparse

from .models import Target
from .utils import host_to_ip, is_valid_cidr, is_valid_hostname, is_valid_ip

MAX_TARGETS = 500


class TargetParseError(Exception):
    pass


def _parse_single(raw):
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("//"):
        raw = raw[2:]
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname
        port = parsed.port
        if not host:
            return None
        t = Target(raw=raw, hostname=host, kind="url", default_port=port)
        if is_valid_ip(host):
            t.ip = host
            t.kind = "single_ip"
        else:
            resolved = host_to_ip(host)
            if resolved:
                t.ip = resolved
        return t
    if is_valid_ip(raw):
        return Target(raw=raw, ip=raw, kind="single_ip", ip_list=[raw])
    if is_valid_cidr(raw):
        net = ipaddress.ip_network(raw, strict=False)
        ips = [str(h) for h in net.hosts()]
        if net.prefixlen == 32:
            ips = [str(net.network_address)]
        if len(ips) > MAX_TARGETS:
            raise TargetParseError(
                f"CIDR {raw} expands to {len(ips)} hosts; refusing > {MAX_TARGETS}."
            )
        return Target(raw=raw, network=str(net), kind="cidr", ip_list=ips)
    if is_valid_hostname(raw):
        t = Target(raw=raw, hostname=raw, kind="hostname")
        resolved = host_to_ip(raw)
        if resolved:
            t.ip = resolved
            t.ip_list = [resolved]
        return t
    # fallback: treat as bare hostname with dash/underscore tolerance
    if all(c.isalnum() or c in ".-_" for c in raw) and "." in raw:
        t = Target(raw=raw, hostname=raw, kind="hostname")
        resolved = host_to_ip(raw)
        if resolved:
            t.ip = resolved
            t.ip_list = [resolved]
        return t
    raise TargetParseError(f"'{raw}' is not a valid IP, CIDR, hostname or URL")


def parse_targets(values, target_file=None):
    """Parse a list of strings + optional file into Target objects."""
    raw_list = []
    if values:
        for v in values:
            raw_list.extend(x for x in v.replace(",", " ").split() if x)
    if target_file:
        try:
            with open(target_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        raw_list.append(line)
        except OSError as exc:
            raise TargetParseError(f"Could not read target file '{target_file}': {exc}")

    if not raw_list:
        raise TargetParseError("No targets provided. Use --targets or --target-file.")

    targets = []
    seen = set()
    for raw in raw_list:
        t = _parse_single(raw)
        if t is None:
            continue
        key = (t.kind, t.hostname or t.ip or t.network or t.raw)
        if key in seen:
            continue
        seen.add(key)
        targets.append(t)
    return targets


def expand_targets(targets):
    """Flatten CIDR targets into individual IP host targets."""
    expanded = []
    for t in targets:
        if t.kind == "cidr":
            for ip in t.ip_list:
                expanded.append(Target(raw=ip, ip=ip, kind="single_ip", ip_list=[ip], network=t.network))
        else:
            expanded.append(t)
    return expanded
