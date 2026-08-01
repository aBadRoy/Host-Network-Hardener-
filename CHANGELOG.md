# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08

### Added

- MIT license.
- Packaging via `pyproject.toml` (installable with `pip install .`, console
  script `hardener`).
- GitHub Actions CI (lint + tests on Python 3.9–3.12).
- Pytest test suite covering CLI, reporting, CVE DB, input handling, models,
  risk engine, scope validation and utilities.
- Contribution, security and changelog documentation.
- Verbose and debug levels: `-v/-vv/-vvv` and `-d/-dd/-ddd` (nmap-style)
  with thread-safe, leveled console output.
- Append-only audit trail: `audit.log` per run, one line per action
  (stage, action, target, result).
- Global rate limiter: `--max-rate PPS` (masscan-style) plus `--min-rate`.
- Timing templates `-T0..-T5` (paranoid → insane) controlling threads,
  timeout and per-port scan delay.
- Stateless scan types via `--scan-type`: `ack`, `null`, `fin`, `xmas`
  (scapy + raw sockets) alongside existing connect and SYN scans.
- Port-selection options: `-F/--fast`, `--top-ports N`, `--exclude-ports`,
  `-p-` alias, `--open`, `--reason`.
- Performance controls: `--max-retries`, `--host-timeout`, `--stats-every`.
- Host-discovery probes: `-sn` ping sweep, `-PE`, `-PS`, `-PA`, `-PU`.
- Output: nmap-style grepable export (`-oG FILE`), `--banners`.
- Aggressive mode `-A` and service version detection `-sV` /
  `--version-intensity 0-9`.
- `--randomize` host/port scan order (rustscan/masscan-style).
- `--exclude` repeatable target/IP/CIDR exclusion and YAML scope-file support.

### Changed

- `is_valid_cidr` now requires an explicit prefix (e.g. `10.0.0.0/8`); bare IPs
  are rejected.

## [1.0.0] - 2026-07

### Added

- 10-phase assessment workflow: input/scope validation, DNS discovery, host
  discovery, port scanning, service enumeration, banner grabbing, HTTP/TLS
  audit, OS fingerprinting, CVE correlation, risk scoring, report generation.
- Full TCP port range support (`--all-ports`, 0–65535) plus `-p`/`-U` with
  ranges (`22,80-90,443`).
- TCP connect, TCP SYN (scapy) and UDP scanning modes.
- Per-protocol service enumeration probes and generic banner grabbing.
- HTTP security header checks, method/URI probes and TLS/certificate auditing.
- OS fingerprinting from TTL, banners and service evidence.
- Local curated CVE database with signature matching.
- Risk scoring with severity × impact × likelihood prioritization.
- Reports in TXT, JSON, XML, CSV and HTML formats.
- Scope enforcement (allowed/excluded networks, rate limits, scan windows)
  with an authorization gate.
- Local mock target lab (`lab_mock.py`) for offline testing.
