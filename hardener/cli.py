"""Command-line interface for the Host & Network Hardener."""

import argparse
import sys

from . import config
from .hardener import Hardener
from .input_handler import parse_targets
from .models import ScanConfig
from .utils import set_color, set_debug, set_verbosity

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


def _timing(value):
    """Parse -T0..-T5 (or a bare 0..5) into an int template index."""
    text = value.strip().lower()
    if text.startswith("t"):
        text = text[1:]
    if text.isdigit() and 0 <= int(text) <= 5:
        return int(text)
    raise argparse.ArgumentTypeError(f"timing template must be -T0..-T5: {value!r}")


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
            "  python main.py --target-file targets.txt --syn -T4 -v\n"
            "  python main.py -t 10.0.0.5 -F -A --reason\n"
            "  python main.py -t 10.0.0.5 -sn --open -oG scan.gnmap\n"
        ),
    )
    # --- targets ----------------------------------------------------------
    p.add_argument("-t", "--targets", nargs="*", default=[],
                   help="Targets: IP, CIDR, hostname or URL (space/comma separated)")
    p.add_argument("-f", "--target-file", default=None,
                   help="File with one target per line")
    p.add_argument("-iL", dest="target_file2", default=None,
                   help="Alias of --target-file (nmap-style)")
    # --- port selection ---------------------------------------------------
    p.add_argument("-p", "--ports", type=parse_port_list, default=None,
                   help="TCP ports to scan: comma list and/or ranges, e.g. 22,80-90,443")
    p.add_argument("-p-", dest="all_ports", action="store_true",
                   help="Scan every TCP port 0-65535 (nmap alias of --all-ports)")
    p.add_argument("-U", "--udp-ports", type=parse_port_list, default=None,
                   help="UDP ports to scan: comma list and/or ranges, e.g. 53,161")
    p.add_argument("--all-ports", action="store_true",
                   help="Scan every TCP port 0-65535 (use with --authorized)")
    p.add_argument("-F", "--fast", action="store_true",
                   help="Fast mode: scan the 100 most common TCP ports only")
    p.add_argument("--top-ports", type=int, default=0, metavar="N",
                   help="Scan the N most common TCP ports (masscan-style)")
    p.add_argument("--exclude-ports", type=parse_port_list, default=None,
                   help="Ports to skip: comma list and/or ranges")
    # --- scan techniques --------------------------------------------------
    p.add_argument("--syn", action="store_true",
                   help="Use SYN stealth scan where scapy/raw sockets are available")
    p.add_argument("--scan-type", choices=["connect", "syn", "ack", "null",
                                           "fin", "xmas"], default="connect",
                   help="TCP scan technique (default connect; ack/null/fin/xmas "
                        "need scapy + raw sockets)")
    p.add_argument("--udp", action="store_true", help="Also run UDP port scan")
    p.add_argument("-sV", "--version-detect", action="store_true",
                   help="Enable service/version detection pass")
    p.add_argument("--version-intensity", type=int, default=7, metavar="0-9",
                   help="Version detection intensity 0-9 (default 7)")
    p.add_argument("-A", "--aggressive", action="store_true",
                   help="Aggressive mode: version + OS detection + full enumeration")
    # --- host discovery ---------------------------------------------------
    p.add_argument("-sn", "--ping-sweep", action="store_true",
                   help="Ping sweep only: discover live hosts, no port scan")
    p.add_argument("-PE", "--icmp-ping", action="store_true",
                   help="Enable ICMP echo discovery probe")
    p.add_argument("-PS", "--tcp-ping", action="store_true",
                   help="Enable TCP SYN ping discovery probe")
    p.add_argument("-PA", "--ack-ping", action="store_true",
                   help="Enable TCP ACK ping discovery probe")
    p.add_argument("-PU", "--udp-ping", action="store_true",
                   help="Enable UDP ping discovery probe")
    p.add_argument("--randomize", action="store_true",
                   help="Randomize host and port scan order")
    # --- timing / performance ---------------------------------------------
    p.add_argument("-T", "--timing", type=_timing, default=3, metavar="0-5",
                   help="Timing template -T0 (paranoid) to -T5 (insane); "
                        "controls threads/timeout/scan delay")
    p.add_argument("--threads", type=int, default=config.DEFAULT_THREADS,
                   help=f"Scan threads (default {config.DEFAULT_THREADS})")
    p.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT,
                   help=f"Socket timeout in seconds (default {config.DEFAULT_TIMEOUT})")
    p.add_argument("--max-rate", type=float, default=0.0, metavar="PPS",
                   help="Maximum packets/second (masscan-style --rate)")
    p.add_argument("--min-rate", type=float, default=0.0, metavar="PPS",
                   help="Informational lower bound; does not throttle faster scans")
    p.add_argument("--max-retries", type=int, default=config.DEFAULT_RETRIES,
                   help=f"Re-probe attempts for uncertain ports (default {config.DEFAULT_RETRIES})")
    p.add_argument("--host-timeout", type=float, default=0.0, metavar="SEC",
                   help="Give up on a host after this many seconds")
    p.add_argument("--stats-every", type=int, default=0, metavar="SEC",
                   help="Print periodic scan progress every N seconds")
    # --- authorization / scope --------------------------------------------
    p.add_argument("--authorized", action="store_true",
                   help="Pre-confirm explicit authorisation to scan")
    p.add_argument("--scope-file", default=None,
                   help="JSON/YAML scope config {allowed, excluded, rate_limit, window}")
    p.add_argument("--exclude", action="append", default=[], metavar="IP|CIDR",
                   help="Exclude a target/IP/CIDR from scanning (repeatable)")
    # --- output ------------------------------------------------------------
    p.add_argument("--output-dir", default="reports",
                   help="Directory for generated reports (default 'reports')")
    p.add_argument("-oG", dest="grepable", metavar="FILE",
                   help="Write grepable output to FILE (nmap -oG)")
    p.add_argument("--open", action="store_true",
                   help="Only report open (not filtered/closed) ports")
    p.add_argument("--reason", action="store_true",
                   help="Show the reason a port was classified open/closed")
    p.add_argument("--banners", action="store_true",
                   help="Grab service banners on open ports (masscan-style)")
    p.add_argument("--no-enum", action="store_true",
                   help="Skip application-layer service enumeration")
    p.add_argument("--no-os", action="store_true", help="Skip OS fingerprinting")
    p.add_argument("--no-cve", action="store_true", help="Skip CVE correlation")
    p.add_argument("--dns-server", default=None, action="append",
                   help="Custom DNS resolver (repeatable)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour output")
    # --- verbosity / debug -------------------------------------------------
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase verbosity (-v, -vv, -vvv)")
    p.add_argument("-d", "--debug", action="count", default=0,
                   help="Increase debug level (-d, -dd, -ddd)")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    return p


def load_scope(path):
    """Load a JSON or YAML scope file; returns a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    # YAML files commonly start with a key followed by a colon on the first line.
    stripped = content.lstrip()
    looks_yaml = stripped.startswith(("allowed:", "blocked:", "max_rate", "scan_"))
    if looks_yaml:
        try:
            import yaml  # optional dependency
            return yaml.safe_load(content) or {}
        except ImportError:
            pass
    import json
    try:
        return json.loads(content)
    except ValueError as exc:
        raise SystemExit(f"Could not parse scope file '{path}': {exc}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    set_color(not args.no_color)
    set_verbosity(args.verbose)
    set_debug(args.debug)

    if args.version:
        print(f"{config.TOOL_NAME} v{config.VERSION}")
        return 0

    target_file = args.target_file or args.target_file2
    try:
        targets = parse_targets(args.targets, target_file)
    except Exception as exc:
        print(f"Input error: {exc}")
        return 2

    scope = load_scope(args.scope_file) if args.scope_file else {}

    if (args.all_ports or args.top_ports) and not args.authorized and not scope:
        print("--all-ports/--top-ports requires --authorized (or a --scope-file).")
        return 2

    # Port selection priority: -p > -p- > -F/--top-ports > --all-ports > default.
    # An empty list means "use the built-in default port set".
    ports = []
    if args.ports:
        ports = list(args.ports)
    elif args.all_ports:
        ports = list(range(PORT_RANGE[0], PORT_RANGE[1] + 1))
    elif args.top_ports:
        ports = sorted(set(config.TOP_PORTS_RANKED[:args.top_ports]))
    elif args.fast:
        ports = list(config.FAST_PORTS)
    if args.exclude_ports:
        excluded = set(args.exclude_ports)
        ports = [p for p in (ports or config.DEFAULT_PORTS) if p not in excluded]

    # Timing template adjusts threads/timeout unless explicitly overridden.
    threads, timeout, scan_delay = config.TIMING_TEMPLATES[args.timing]
    if args.threads != config.DEFAULT_THREADS:
        threads = args.threads
    if args.timeout != config.DEFAULT_TIMEOUT:
        timeout = args.timeout

    if args.aggressive:
        args.version_detect = True
        args.syn = True  # prefer SYN in aggressive mode when raw sockets exist

    probes = {
        "icmp": args.icmp_ping,
        "tcp": args.tcp_ping,
        "ack": args.ack_ping,
        "udp": args.udp_ping,
        "http": True,
    }
    if not any([args.icmp_ping, args.tcp_ping, args.ack_ping, args.udp_ping]):
        probes = {"icmp": True, "tcp": True, "ack": False, "udp": False,
                  "http": True}

    cfg = ScanConfig(
        targets=targets,
        ports=ports,
        udp_ports=args.udp_ports,
        all_ports=args.all_ports,
        syn_scan=args.syn or args.scan_type == "syn",
        scan_type=args.scan_type,
        udp_scan=args.udp,
        threads=threads,
        timeout=timeout,
        output_dir=args.output_dir,
        authorized=args.authorized,
        scope=scope,
        enumerate_services=not args.no_enum,
        os_detection=not args.no_os,
        cve_check=not args.no_cve,
        dns_servers=args.dns_server or [],
        verbose=args.verbose,
        debug=args.debug,
        timing=args.timing,
        fast=args.fast,
        top_ports=args.top_ports,
        exclude_ports=args.exclude_ports or [],
        show_open_only=args.open,
        show_reason=args.reason,
        max_rate=args.max_rate,
        min_rate=args.min_rate,
        max_retries=args.max_retries,
        host_timeout=args.host_timeout,
        stats_every=args.stats_every,
        banners=args.banners,
        ping_sweep=args.ping_sweep,
        icmp_ping=probes["icmp"],
        tcp_ping=probes["tcp"],
        ack_ping=probes["ack"],
        udp_ping=probes["udp"],
        randomize=args.randomize,
        aggressive=args.aggressive,
        version_intensity=args.version_intensity,
        grepable_path=args.grepable,
        exclude_list=args.exclude,
        scan_delay=scan_delay,
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
