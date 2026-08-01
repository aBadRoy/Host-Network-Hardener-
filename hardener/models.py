"""Data models shared across the engine."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Target:
    raw: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    network: Optional[str] = None      # CIDR string for range targets
    ip_list: List[str] = field(default_factory=list)
    kind: str = "unknown"              # single_ip | cidr | hostname | url
    default_port: Optional[int] = None


@dataclass
class DNSRecord:
    rtype: str
    value: str
    ttl: int = 0


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"              # open | closed | filtered
    service: str = "unknown"
    version: str = ""
    banners: List[str] = field(default_factory=list)
    scan_evidence: dict = field(default_factory=dict)
    enumeration: dict = field(default_factory=dict)


@dataclass
class HttpInfo:
    url: str = ""
    status: int = 0
    server: str = ""
    powered_by: str = ""
    title: str = ""
    headers: dict = field(default_factory=dict)
    methods: List[str] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    found_paths: List[str] = field(default_factory=list)
    directory_listing: bool = False
    framework: str = ""
    cookies: List[str] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    description: str = ""
    category: str = "general"
    severity: str = "medium"           # informational|low|medium|high|critical
    impact: int = 5                    # 0-10
    likelihood: int = 5                # 0-10
    risk_score: float = 0.0            # impact*likelihood/10
    evidence: str = ""
    asset: str = ""
    cve: Optional[str] = None
    remediation: List[str] = field(default_factory=list)
    confidence: str = "medium"         # high|medium|low

    def __post_init__(self):
        if not self.remediation:
            self.remediation = []


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    alive: bool = False
    alive_method: str = ""
    rtt_ms: Optional[float] = None
    dns_records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    waf: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    os_fingerprint: dict = field(default_factory=dict)
    http: Optional[HttpInfo] = None
    http_audits: dict = field(default_factory=dict)   # port -> HttpInfo
    findings: List[Finding] = field(default_factory=list)
    services_scanned: bool = False


@dataclass
class ScanConfig:
    targets: List[Target] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    udp_ports: List[int] = field(default_factory=list)
    all_ports: bool = False
    syn_scan: bool = False
    scan_type: str = "connect"       # connect|syn|ack|null|fin|xmas
    udp_scan: bool = False
    threads: int = 50
    timeout: float = 2.0
    output_dir: str = "reports"
    authorized: bool = False
    scope: Optional[dict] = None        # {allowed, excluded, rate_limit, window}
    enumerate_services: bool = True
    os_detection: bool = True
    cve_check: bool = True
    dns_servers: List[str] = field(default_factory=list)
    verbose: int = 0
    debug: int = 0
    timing: int = 3                     # -T0..-T5 template
    fast: bool = False                  # -F fast mode
    top_ports: int = 0                  # --top-ports N
    exclude_ports: List[int] = field(default_factory=list)
    show_open_only: bool = False        # --open
    show_reason: bool = False           # --reason
    max_rate: float = 0.0               # --max-rate pkts/sec
    min_rate: float = 0.0               # --min-rate pkts/sec
    max_retries: int = 0                # --max-retries
    host_timeout: float = 0.0           # --host-timeout seconds
    stats_every: int = 0                # --stats-every N (seconds)
    banners: bool = False               # --banners
    ping_sweep: bool = False            # -sn: discover only
    icmp_ping: bool = True              # -PE
    tcp_ping: bool = True               # -PS
    ack_ping: bool = False              # -PA
    udp_ping: bool = False              # -PU
    randomize: bool = False             # --randomize scan order
    aggressive: bool = False            # -A
    version_intensity: int = 7          # -sV / --version-intensity 0-9
    run_id: str = ""
    grepable_path: str = ""             # -oG output file
    exclude_list: List[str] = field(default_factory=list)
    scan_delay: float = 0.0             # per-port delay from -T template
    use_nmap: bool = True               # prefer nmap backend when on PATH


@dataclass
class ScanReport:
    tool_name: str = ""
    tool_version: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration: str = ""
    targets: List[Target] = field(default_factory=list)
    hosts: List[Host] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
