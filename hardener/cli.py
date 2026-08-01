"""Command-line interface for the Host & Network Hardener."""

import argparse
import sys

from . import config
from .hardener import Hardener
from .input_handler import parse_targets
from .models import ScanConfig
from .utils import set_color

PORT_RANGE = (0, 65535)  # every TCP/UDP port in existence


def parse_port_list(value):
    """Parse '1-1000,8080,8443' (or single numbers) into a port list."""
    if isinstance(value, (list, tuple)):
        return list(value)
    ports, seen = [], set()
    for chunk in str(value).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                raise argparse.ArgumentTypeError(f"invalid port range: {chunk!r}")
            if lo < PORT_RANGE[0] or hi > PORT_RANGE[1] or lo > hi:
                raise argparse.ArgumentTypeError(
                    f"port range must be within {PORT_RANGE[0]}-{PORT_RANGE[1]}: {chunk!r}")
            for p in range(lo, hi + 1):
                if p not in seen:
                    ports.append(p)
                    seen.add(p)
        else:
            try:
                p = int(chunk)
            except ValueError:
                raise argparse.ArgumentTypeError(f"invalid port: {chunk!r}")
            if not PORT_RANGE[0] <= p <= PORT_RANGE[1]:
                raise argparse.ArgumentTypeError(
                    f"port must be within {PORT_RANGE[0]}-{PORT_RANGE[1]}: {p}")
            if p not in seen:
                ports.append(p)
                seen.add(p)
    return ports


def build_parser():
    p = argparse.ArgumentParser(
        prog="hardener",
        description="Host & Network Hardener - security assessment, hardening "
                    "and remediation engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -t 10.0.0.5\n"
            "  python main.py -t example.com --all-ports --authorized\n"
            "  python main.py -t 10.0.0.0/24 --udp --threads 100\n"
            "  python main.py --target-file targets.txt --syn\n"
        ),
    )
    p.add_argument("-t", "--targets", nargs="*", default=[],
                   help="Targets: IP, CIDR, hostname or URL (space/comma separated)")
    p.add_argument("-f", "--target-file", default=None,
                   help="File with one target per line")
    p.add_argument("-p", "--ports", type=parse_port_list, default=None,
                   help="TCP ports to scan: comma list and/or ranges, e.g. 22,80-90,443")
    p.add_argument("-U", "--udp-ports", type=parse_port_list, default=None,
                   help="UDP ports to scan: comma list and/or ranges, e.g. 53,161")
    p.add_argument("--all-ports", action="store_true",
                   help="Scan every TCP port 0-65535 (use with --authorized)")
    p.add_argument("--syn", action="store_true",
                   help="Use SYN stealth scan where scapy/raw sockets are available")
    p.add_argument("--udp", action="store_true", help="Also run UDP port scan")
    p.add_argument("--threads", type=int, default=config.DEFAULT_THREADS,
                   help=f"Scan threads (default {config.DEFAULT_THREADS})")
    p.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT,
                   help=f"Socket timeout in seconds (default {config.DEFAULT_TIMEOUT})")
    p.add_argument("--authorized", action="store_true",
                   help="Pre-confirm explicit authorisation to scan")
    p.add_argument("--scope-file", default=None,
                   help="JSON scope config {allowed, excluded, rate_limit, window}")
    p.add_argument("--output-dir", default="reports",
                   help="Directory for generated reports (default 'reports')")
    p.add_argument("--no-enum", action="store_true",
                   help="Skip application-layer service enumeration")
    p.add_argument("--no-os", action="store_true", help="Skip OS fingerprinting")
    p.add_argument("--no-cve", action="store_true", help="Skip CVE correlation")
    p.add_argument("--dns-server", default=None, action="append",
                   help="Custom DNS resolver (repeatable)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour output")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    return p


def load_scope(path):
    import json
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not load scope file '{path}': {exc}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    set_color(not args.no_color)

    if args.version:
        print(f"{config.TOOL_NAME} v{config.VERSION}")
        return 0

    try:
        targets = parse_targets(args.targets, args.target_file)
    except Exception as exc:
        print(f"Input error: {exc}")
        return 2

    scope = load_scope(args.scope_file) if args.scope_file else {}

    if args.all_ports and not args.authorized and not scope:
        print("--all-ports requires --authorized (or a --scope-file).")
        return 2

    ports = args.ports or list(range(PORT_RANGE[0], PORT_RANGE[1] + 1)) \
        if args.all_ports else args.ports

    cfg = ScanConfig(
        targets=targets,
        ports=ports,
        udp_ports=args.udp_ports,
        all_ports=args.all_ports,
        syn_scan=args.syn,
        udp_scan=args.udp,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output_dir,
        authorized=args.authorized,
        scope=scope,
        enumerate_services=not args.no_enum,
        os_detection=not args.no_os,
        cve_check=not args.no_cve,
        dns_servers=args.dns_server or [],
    )

    engine = Hardener(cfg, scope=scope)
    try:
        engine.run(targets=targets)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
