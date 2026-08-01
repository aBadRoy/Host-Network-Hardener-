"""Static configuration, defaults, banners and lookup tables."""

TOOL_NAME = "Host & Network Hardener"
TOOL_TAGLINE = "Discovery | Enumeration | Analysis | Risk Scoring | Remediation"
VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 50
DEFAULT_SCAN_WINDOW = "00:00-23:59"
DEFAULT_RATE_LIMIT = 1000          # packets / second ceiling (informational)
DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

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
