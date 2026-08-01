# Host & Network Hardener

[![CI](https://github.com/aBadRoy/Host-Network-Hardener-/actions/workflows/ci.yml/badge.svg)](https://github.com/aBadRoy/Host-Network-Hardener-/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

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

# Run without installing
pip install -r requirements.txt
python main.py --help

# Or install as a package (adds the `hardener` console command)
pip install .
hardener --help
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

# Fast mode: top 100 ports, aggressive timing, verbose
python main.py -t scanme.nmap.org -F -T4 -v --authorized

# Full aggressive: version + OS + enumeration
python main.py -t 10.0.0.5 -A --reason --authorized

# Ping sweep only (discovery, no port scan)
python main.py -t 10.0.0.0/24 -sn -PA --authorized

# Rate-limited, random order, grepable output
python main.py -t 10.0.0.5 -F --max-rate 500 --randomize -oG scan.gnmap --authorized

# Debug-level tracing of every probe
python main.py -t 127.0.0.1 -F -d -d --authorized

# Enforce a scope configuration file
python main.py -t 127.0.0.1 --scope-file scope.json

# Custom report directory
python main.py -t 127.0.0.1 --output-dir my_reports
```

### Options

#### Target & port selection

| Option | Description |
| --- | --- |
| `-t, --targets` | Target(s): IP, CIDR, hostname or URL (space/comma separated) |
| `-f, --target-file` / `-iL` | File with one target per line |
| `-p, --ports` | TCP ports: comma list and/or ranges, e.g. `22,80-90,443` |
| `-p-` / `--all-ports` | Scan every TCP port 0–65535 (requires `--authorized`) |
| `-U, --udp-ports` | UDP ports to scan, e.g. `53,161` |
| `-F, --fast` | Fast mode: scan only the 100 most common TCP ports |
| `--top-ports N` | Scan the N most common TCP ports (masscan-style) |
| `--exclude-ports` | Skip these ports (comma list and/or ranges) |
| `--exclude` | Exclude a target/IP/CIDR from scanning (repeatable) |

#### Scan techniques

| Option | Description |
| --- | --- |
| `--scan-type` | `connect` (default) · `syn` · `ack` · `null` · `fin` · `xmas` |
| `--syn` | SYN stealth scan (needs scapy + raw socket privileges) |
| `--udp` | Also run UDP port scan |
| `-sV, --version-detect` | Enable service/version detection pass |
| `--version-intensity 0-9` | Version detection intensity (default 7) |
| `-A, --aggressive` | Aggressive mode: version + OS + full enumeration + SYN |

#### Host discovery

| Option | Description |
| --- | --- |
| `-sn, --ping-sweep` | Discover live hosts only; no port scan |
| `-PE, --icmp-ping` | ICMP echo discovery probe |
| `-PS, --tcp-ping` | TCP SYN ping discovery probe |
| `-PA, --ack-ping` | TCP ACK ping discovery probe |
| `-PU, --udp-ping` | UDP ping discovery probe |
| `--randomize` | Randomize host and port scan order |

#### Timing / performance

| Option | Description |
| --- | --- |
| `-T 0-5, --timing` | Timing template: `-T0` paranoid … `-T5` insane (nmap-style) |
| `--threads` | Scan threads (default 50) |
| `--timeout` | Socket timeout in seconds (default 2.0) |
| `--max-rate PPS` | Hard packets/second cap (masscan-style `--rate`) |
| `--min-rate PPS` | Informational lower rate bound |
| `--max-retries` | Re-probe attempts for uncertain ports (default 1) |
| `--host-timeout SEC` | Give up on a host after this many seconds |
| `--stats-every SEC` | Print periodic scan progress every N seconds |

#### Authorization / scope

| Option | Description |
| --- | --- |
| `--authorized` | Pre-confirm explicit authorization to scan |
| `--scope-file` | JSON or YAML scope config: `{allowed, excluded, rate_limit, window}` |

#### Output

| Option | Description |
| --- | --- |
| `--output-dir` | Report directory (default `reports`) |
| `-oG FILE` | Write nmap-style grepable output to FILE |
| `--open` | Only report open ports |
| `--reason` | Show the reason each port was classified open/closed |
| `--banners` | Grab service banners on open ports (masscan-style) |
| `--no-enum` | Skip service enumeration |
| `--no-os` | Skip OS fingerprinting |
| `--no-cve` | Skip CVE correlation |
| `--dns-server` | Custom DNS resolver (repeatable) |
| `--no-color` | Disable ANSI color output |

#### Verbosity / debug

| Option | Description |
| --- | --- |
| `-v, -vv, -vvv` | Increase verbosity (per-phase detail) |
| `-d, -dd, -ddd` | Increase debug level (per-probe tracing) |

> Without `--authorized` (or a `--scope-file`), the tool prompts for confirmation
> before scanning. That gate is on purpose.

### Reports

Every run writes an **audit trail** (`audit.log`) alongside the standard
TXT/JSON/XML/CSV/HTML reports. See the reports section below for details.

---

## Development & testing

```bash
# Install with dev dependencies (pytest, pyflakes)
python -m pip install -e ".[dev]"

# Run the test suite
python -m pytest

# Lint check
python -m pyflakes hardener main.py lab_mock.py conftest.py tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

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
| `audit.log` | Append-only audit trail of every action per run |

With `-oG <file>`, nmap-style grepable output is written in addition
(e.g. `Host: 45.33.32.156 (scanme.nmap.org)\tPorts: 22/open/tcp//ssh//`).

---

## Project layout

```
network_hardener/
├── main.py                    # CLI entry point
├── lab_mock.py                # local mock target lab (testing)
├── scope.json                 # example scope configuration
├── requirements.txt
├── pyproject.toml             # packaging & tool config
├── LICENSE                    # MIT license
├── conftest.py                # pytest bootstrap
├── .github/workflows/ci.yml   # CI (lint + tests)
├── tests/                     # pytest test suite
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

Released under the [MIT License](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.
