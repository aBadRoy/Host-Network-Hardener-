# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT license.
- Packaging via `pyproject.toml` (installable with `pip install .`, console
  script `hardener`).
- GitHub Actions CI (lint + tests on Python 3.9–3.12).
- Pytest test suite covering CLI, reporting, CVE DB, input handling, models,
  risk engine, scope validation and utilities.
- Contribution, security and changelog documentation.

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
