# Host & Network Hardener

A command-line security assessment, hardening and remediation engine for hosts and networks.
It walks a target through a complete 10-phase workflow — from scope validation and discovery
through to CVE correlation, risk scoring and remediation guidance — and exports reports in
multiple formats.

> ⚠️ **Authorized use only.** This tool performs active network scanning. Only scan systems you
> own or have explicit written permission to test.

---

## Features

- **10-phase assessment workflow**
  1. Input intake & scope validation (authorization gate)
  2. DNS & infrastructure discovery (A/AAAA/MX/NS/TXT/SOA/CNAME, subdomains, CDN/WAF detection)
  3. Host discovery (ICMP, TCP ping, HTTP probe)
  4. Port scanning — TCP connect, TCP SYN (scapy) and UDP; **full 0–65535 range supported**
  5. Service enumeration — per-protocol probes (SSH, FTP, Telnet, SMTP, POP3, IMAP, LDAP,
     SMB, Kerberos, Oracle, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached,
     VNC, RDP, MSSQL, DNS) + generic banner grabbing
  6. Banner grabbing & HTTP/TLS fingerprinting (security headers, methods, sensitive paths,
     weak TLS, certificate issues)
  7. OS fingerprinting (TTL + banner + service evidence)
  8. Security analysis & CVE correlation (local curated CVE database)
  9. Risk scoring & prioritization
  10. Report generation & remediation guidance

- **Reports**: TXT, JSON, XML, CSV and HTML (executive + technical)
- **Scope enforcement**: allowed/excluded networks, scan windows, rate limits
- **Threaded scanning** for speed; colorized console output

---

## Requirements

- Python **3.9+**
- Windows / Linux / macOS
- Optional: [scapy](https://scapy.net) (for SYN stealth scan), `cryptography`

## Installation

```bash
git clone https://github.com/aBadRoy/Host-Network-Hardener-.git
cd Host-Network-Hardener-
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py -t <target> [options]
```

`<target>` can be an IP, CIDR, hostname or URL.

### Examples

```bash
# Single host
python main.py -t 127.0.0.1 --authorized

# Hostname
python main.py -t scanme.nmap.org --authorized

# CIDR range
python main.py -t 10.0.0.0/24 --authorized

# Specific ports
python main.py -t 127.0.0.1 -p 22,80,443 --authorized

# Port ranges
python main.py -t 127.0.0.1 -p 1-1000 --authorized

# Every port (0-65535)
python main.py -t 127.0.0.1 --all-ports --authorized

# UDP scan
python main.py -t 127.0.0.1 -U 53,161 --udp --authorized

# SYN stealth scan (needs scapy + raw socket privileges)
python main.py -t 127.0.0.1 --syn --authorized

# Enforce a scope configuration file
python main.py -t 127.0.0.1 --scope-file scope.json

# Custom report directory
python main.py -t 127.0.0.1 --output-dir my_reports
```

### Options

| Option | Description |
| --- | --- |
| `-t, --targets` | Target(s): IP, CIDR, hostname or URL (space/comma separated) |
| `-f, --target-file` | File with one target per line |
| `-p, --ports` | TCP ports to scan: comma list and/or ranges, e.g. `22,80-90,443` |
| `-U, --udp-ports` | UDP ports to scan, e.g. `53,161` |
| `--all-ports` | Scan every TCP port 0–65535 (requires `--authorized`) |
| `--syn` | Use SYN stealth scan where scapy/raw sockets are available |
| `--udp` | Also run UDP port scan |
| `--threads` | Scan threads (default 50) |
| `--timeout` | Socket timeout in seconds (default 2.0) |
| `--authorized` | Pre-confirm explicit authorization to scan |
| `--scope-file` | JSON scope config: `{allowed, excluded, rate_limit, window}` |
| `--output-dir` | Report directory (default `reports`) |
| `--no-enum` | Skip service enumeration |
| `--no-os` | Skip OS fingerprinting |
| `--no-cve` | Skip CVE correlation |
| `--dns-server` | Custom DNS resolver (repeatable) |
| `--no-color` | Disable ANSI color output |

> Without `--authorized` (or a `--scope-file`), the tool prompts for confirmation
> before scanning. That gate is on purpose.

---

## Local testing with the mock lab

A mock target lab is included so you can exercise the full pipeline without touching
any external systems. It serves an Apache/PHP site, OpenSSH, vsftpd, Telnet, Redis,
MySQL, PostgreSQL and a TLS server on `127.0.0.1`.

```bash
# Terminal 1 — start the lab
python lab_mock.py

# Terminal 2 — scan it
python main.py -t 127.0.0.1 -p 8080,2222,2121,2323,6379,13306,15432,8443 --authorized
```

---

## Reports

Reports are written to the output directory (default `reports/`):

| File | Content |
| --- | --- |
| `report.txt` | Human-readable full report |
| `report.json` | Structured machine-readable data |
| `report.xml` | XML export |
| `report.csv` | Findings spreadsheet |
| `report.html` | Styled executive/technical report |

---

## Project layout

```
network_hardener/
├── main.py                    # CLI entry point
├── lab_mock.py                # local mock target lab (testing)
├── scope.json                 # example scope configuration
├── requirements.txt
└── hardener/
    ├── cli.py                 # argument parsing
    ├── hardener.py            # workflow orchestrator
    ├── config.py              # defaults, port/service maps, signatures
    ├── input_handler.py       # target parsing & CIDR expansion
    ├── scope_validator.py     # authorization gate & scope rules
    ├── dns_discovery.py       # DNS records, subdomains, CDN/WAF
    ├── host_discovery.py      # alive checks
    ├── port_scanner.py        # TCP/SYN/UDP scanning
    ├── service_enum.py        # per-protocol probes
    ├── http_audit.py          # HTTP security checks
    ├── tls_audit.py           # TLS/certificate checks
    ├── os_fingerprint.py      # OS estimation
    ├── cve_db.py              # local CVE database & matching
    ├── security_analysis.py   # finding generation
    ├── risk_engine.py         # scoring & prioritization
    ├── remediation.py         # fix guidance
    ├── reporting.py           # TXT/JSON/XML/CSV/HTML export
    ├── models.py              # dataclasses
    └── utils.py               # shared helpers
```

---

## License

See the repository for license details.
