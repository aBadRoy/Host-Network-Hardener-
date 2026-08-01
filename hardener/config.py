"""Static configuration, defaults, banners and lookup tables."""

TOOL_NAME = "Host & Network Hardener"
TOOL_TAGLINE = "Discovery | Enumeration | Analysis | Risk Scoring | Remediation"
VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 50
DEFAULT_SCAN_WINDOW = "00:00-23:59"
DEFAULT_RATE_LIMIT = 1000          # packets / second ceiling (informational)
DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
DEFAULT_RETRIES = 1                # extra probes per port
DEFAULT_MAX_RATE = 0               # 0 == no explicit cap (threads govern pace)

# nmap-style timing templates: T0 paranoid ... T5 insane.
# dict: template -> (max_threads, socket_timeout, scan_delay_seconds)
TIMING_TEMPLATES = {
    0: (1, 5.0, 5.0),      # paranoid
    1: (2, 3.0, 1.5),      # sneaky
    2: (10, 2.0, 0.1),     # polite
    3: (50, 2.0, 0.0),     # normal (default)
    4: (100, 1.5, 0.0),    # aggressive
    5: (256, 1.0, 0.0),    # insane
}

# Most common TCP ports ranked by frequency (used by -F / --top-ports)
TOP_PORTS_RANKED = [
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 23, 3389, 5900, 8080,
    8443, 8000, 8888, 3306, 5432, 1433, 1521, 6379, 11211, 27017, 9200,
    5601, 161, 445, 139, 135, 445, 53, 464, 636, 88, 389, 636, 3268,
    3269, 137, 139, 445, 593, 1025, 1026, 1080, 123, 587, 465, 2525,
    990, 989, 5060, 5061, 1723, 500, 4500, 1701, 1194, 2222, 3000, 4000,
    5000, 7001, 7002, 10000, 10001, 2000, 2001, 49152, 49153, 49154,
    49155, 49156, 49157, 515, 631, 9100, 3283, 3389, 5984, 5985, 5986,
    47001, 445, 5353, 1900, 5355, 5357, 3702, 593, 5722, 49152, 49154,
    49155, 49156, 49157, 50000, 50030, 50070, 8020, 8030, 8032, 8042,
    8085, 8086, 8090, 8181, 8880, 8888, 9080, 9090, 9999, 10000,
]
FAST_PORTS = sorted(set(TOP_PORTS_RANKED))

BANNER = r"""
  _  _     _    ____          ____                            _           
 | || |___| |_ / ___|  __ _  / /\ \__ _ _ __ _ __ _   _ _ __ | |_ ___ _ __
 | __ / -_)  _| |  _  / _` |/ /_/ / _` | '_ \ '_ \| | | | '_ \|  _/ _ \ '__|
 |_||_\___|\__|_| (_) \ (_| / __  / (_| | | | | | | |_| | | | | ||  __/ |   
                        \__,_\/ /_/ \__,_|_| |_| |_|\__,_|_| |_|\__\___|_|   
"""

# ---------------------------------------------------------------------------
# Port -> service map used for scoring/prioritisation.
# key: (port, protocol) value: service label
# ---------------------------------------------------------------------------
PORT_SERVICES = {
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (53, "tcp"): "DNS",
    (53, "udp"): "DNS",
    (67, "udp"): "DHCP-Server",
    (68, "udp"): "DHCP-Client",
    (69, "udp"): "TFTP",
    (80, "tcp"): "HTTP",
    (88, "tcp"): "Kerberos",
    (110, "tcp"): "POP3",
    (123, "udp"): "NTP",
    (135, "tcp"): "MSRPC",
    (137, "udp"): "NetBIOS-NS",
    (139, "tcp"): "NetBIOS-SSN",
    (143, "tcp"): "IMAP",
    (161, "udp"): "SNMP",
    (389, "tcp"): "LDAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "SMB",
    (465, "tcp"): "SMTPS",
    (500, "udp"): "ISAKMP/VPN",
    (587, "tcp"): "SMTP-Submission",
    (636, "tcp"): "LDAPS",
    (873, "tcp"): "Rsync",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    (1080, "tcp"): "SOCKS",
    (1433, "tcp"): "MSSQL",
    (1521, "tcp"): "Oracle-TNS",
    (2049, "tcp"): "NFS",
    (2375, "tcp"): "Docker",
    (3000, "tcp"): "Grafana/Web",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5432, "tcp"): "PostgreSQL",
    (5601, "tcp"): "Kibana",
    (5900, "tcp"): "VNC",
    (5985, "tcp"): "WinRM-HTTP",
    (5986, "tcp"): "WinRM-HTTPS",
    (6379, "tcp"): "Redis",
    (8080, "tcp"): "HTTP-Alt",
    (8443, "tcp"): "HTTPS-Alt",
    (8888, "tcp"): "Web",
    (9092, "tcp"): "Kafka",
    (9200, "tcp"): "Elasticsearch",
    (9443, "tcp"): "HTTPS-Alt",
    (10000, "tcp"): "Webmin",
    (11211, "tcp"): "Memcached",
    (27017, "tcp"): "MongoDB",
    (50000, "tcp"): "SAP/DB",
}

# Ports checked during host-discovery "TCP ping"
TCP_PING_PORTS = [22, 80, 443, 445, 3389, 8080]

# Default TCP port set for a standard scan
DEFAULT_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000, 3306,
    3389, 5432, 5601, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 9443,
    10000, 11211, 27017,
})

DEFAULT_UDP_PORTS = sorted({53, 67, 68, 69, 123, 137, 161, 500, 5353, 1900})

# ---------------------------------------------------------------------------
# Service version -> severity of exposure (informational baseline)
# ---------------------------------------------------------------------------
INSECURE_SERVICES = {
    "ftp": "medium",
    "telnet": "high",
    "snmp": "high",
    "tftp": "high",
    "smbv1": "critical",
    "smtp": "low",
    "http": "informational",
    "mongodb": "high",
    "redis": "high",
    "elasticsearch": "high",
    "memcached": "high",
    "mysql": "medium",
    "postgresql": "medium",
    "msrpc": "low",
    "netbios": "medium",
    "nfs": "medium",
    "vnc": "high",
    "docker": "high",
    "samba": "medium",
}

# HTTP security headers that should be present
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Strict-Transport-Security)",
    "content-security-policy": "Content-Security-Policy (CSP)",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Common admin / sensitive paths probed on web servers
SENSITIVE_PATHS = [
    "admin/", "admin/login", "login", "phpmyadmin/", "wp-login.php",
    "wp-admin/", ".git/config", ".env", "server-status", "console/",
    "jenkins/", "actuator/", "swagger-ui.html", "api/", "backup.zip",
    "web.config", "robots.txt", "crossdomain.xml", "manager/html",
]

# CDN ranges (curated subset, keyed by CDN name)
CDN_IP_RANGES = {
    "Cloudflare": ["104.16.0.0/13", "103.21.244.0/22", "103.22.200.0/22",
                   "103.31.4.0/22", "172.64.0.0/13", "190.93.240.0/20",
                   "197.234.240.0/22", "198.41.128.0/17"],
    "Akamai": ["23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "CloudFront": ["13.32.0.0/15", "52.84.0.0/15", "54.230.0.0/16",
                   "54.239.128.0/18", "204.246.164.0/22"],
    "Imperva": ["199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
                "103.28.248.0/22"],
    "StackPath": ["199.232.0.0/16"],
    "Microsoft Azure CDN": ["13.64.0.0/11", "20.0.0.0/8"],
}

# WAF / proxy header signatures
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "server: cloudflare"],
    "akamai": ["x-akamai-transformed", "server: akamaighost"],
    "fastly": ["x-fastly-request-id", "server: fastly"],
    "imperva": ["x-cdn", "server: imperva"],
    "aws waf": ["x-amz-cf-id", "via: 1.1 amazon"],
    "f5": ["server: bigip", "x-cnection"],
    "sucuri": ["x-sucuri-id", "server: sucuri"],
}

# ---------------------------------------------------------------------------
# Severity labels & colors
# ---------------------------------------------------------------------------
SEVERITIES = ["informational", "low", "medium", "high", "critical"]

SEVERITY_LEVEL = {
    "informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 9,
}
