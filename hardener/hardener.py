"""Hardener engine: orchestrates the full assessment workflow.

1. Input intake          6. Service enumeration
2. Scope validation      7. Banner/fingerprint + HTTP/TLS audit
3. DNS discovery         8. OS fingerprinting
4. Host discovery        9. Security analysis + CVE correlation
5. Port scanning        10. Risk scoring + reporting + remediation
"""

import time

from . import config
from .dns_discovery import discover_host_infrastructure
from .host_discovery import discover_hosts
from .http_audit import audit_http
from .input_handler import expand_targets
from .models import Host, ScanConfig, ScanReport
from .os_fingerprint import fingerprint_os
from .port_scanner import scan_tcp_ports, scan_udp_ports
from .remediation import attach_remediation_all
from .reporting import generate_reports
from .risk_engine import deduplicate, prioritize, score_all, summary_stats
from .scope_validator import ScopeValidator
from .security_analysis import analyze_host
from .service_enum import enumerate_port
from .tls_audit import audit_tls
from .utils import (Color, elapsed, fmt_time, info, low_pri, ok, out, paint,
                    timestamp, vuln, warn)

TLS_PORTS = {443, 8443, 9443, 5986, 636, 993, 995, 465}
HTTP_PORTS = {80, 443, 8080, 8443, 9443}


class Hardener:
    def __init__(self, config_: ScanConfig, scope=None):
        self.cfg = config_
        self.scope = scope or {}
        self.report = ScanReport(
            tool_name=config.TOOL_NAME,
            tool_version=config.VERSION,
        )
        self._tls_results = {}
        self.validator = ScopeValidator(
            scope=self.scope,
            authorized=self.cfg.authorized,
            scan_window=self.scope.get("window"),
            rate_limit=self.scope.get("rate_limit"),
        )
        if not self.cfg.dns_servers:
            self.cfg.dns_servers = config.DEFAULT_DNS_SERVERS

    # ------------------------------------------------------------------
    def run(self, targets=None):
        self.report.started_at = timestamp()
        start = time.time()
        out(paint(config.BANNER, Color.CYAN, bold=True))
        out(paint(config.TOOL_NAME, Color.CYAN, bold=True) +
            f"  --  {config.TOOL_TAGLINE}")
        info(f"Workflow started at {self.report.started_at}")

        # 1. Input intake
        self.cfg.targets = targets or self.cfg.targets
        if not self.cfg.targets:
            raise ValueError("No targets supplied to the engine.")
        info(f"Parsed {len(self.cfg.targets)} target(s) from input.")
        self.report.targets = self.cfg.targets

        # 2. Scope validation + authorization
        info("Step 1/10 - Scope validation & authorisation")
        if not self.validator.confirm_authorization():
            return self._finish(start, aborted=True)
        approved = []
        for t in expand_targets(self.cfg.targets):
            ok_flag, reason = self.validator.validate(t)
            if not ok_flag:
                warn(f"Out of scope: {t.raw} ({reason})")
                continue
            approved.append(t)
        if not approved:
            warn("No in-scope targets remain; aborting.")
            return self._finish(start, aborted=True)
        info(f"Authorised target list ({len(approved)}): "
             + ", ".join(sorted({t.ip or t.hostname or t.raw for t in approved})))

        # 3. DNS / infrastructure discovery
        info("Step 2/10 - DNS & infrastructure discovery")
        dns_targets = [t for t in approved if t.hostname and not t.kind.startswith("single")]
        for t in dns_targets:
            h = Host(ip=t.ip or "", hostname=t.hostname, alive=True,
                     alive_method="DNS target")
            try:
                discover_host_infrastructure(h, servers=self.cfg.dns_servers)
            except Exception as exc:
                warn(f"DNS discovery error for {t.hostname}: {exc}")
            t.__dict__.setdefault("_dns_host", h)

        # 4. Host discovery
        info("Step 3/10 - Host discovery")
        ip_hosts = {}
        for t in approved:
            if t.ip and not t.ip_list:
                t.ip_list = [t.ip]
            for ip in t.ip_list or ([t.ip] if t.ip else []):
                ip_hosts.setdefault(ip, t)
        alive_hosts = discover_hosts(
            list(ip_hosts.keys()),
            hostnames={ip: t.hostname for ip, t in ip_hosts.items()},
            timeout=self.cfg.timeout,
        )
        info(f"{len(alive_hosts)} live host(s) identified; "
             f"{len(ip_hosts) - len(alive_hosts)} unreachable.")
        for h in alive_hosts:
            t = ip_hosts.get(h.ip)
            if t and t.hostname:
                h.hostname = t.hostname
                try:
                    discover_host_infrastructure(h, servers=self.cfg.dns_servers)
                except Exception:
                    pass
        self.report.hosts = alive_hosts
        if not alive_hosts:
            warn("No live hosts; nothing further to assess.")
            return self._finish(start)

        # 5. Port scanning
        info("Step 4/10 - Port scanning")
        ports = self.cfg.ports or config.DEFAULT_PORTS
        for h in alive_hosts:
            h.ports = scan_tcp_ports(h.ip, ports, timeout=self.cfg.timeout,
                                     threads=self.cfg.threads,
                                     use_syn=self.cfg.syn_scan,
                                     progress_label=h.ip)
            if self.cfg.udp_scan:
                h.ports += scan_udp_ports(h.ip, self.cfg.udp_ports or config.DEFAULT_UDP_PORTS,
                                          timeout=self.cfg.timeout,
                                          progress_label=h.ip)

        # 6. Service enumeration
        info("Step 5/10 - Service enumeration")
        if self.cfg.enumerate_services:
            for h in alive_hosts:
                for pr in h.ports:
                    if pr.state == "open":
                        enumerate_port(h.ip, pr, timeout=self.cfg.timeout)

        # 7. HTTP + TLS audit
        info("Step 6/10 - Banner grabbing & HTTP/TLS fingerprinting")
        for h in alive_hosts:
            self._audit_http_tls(h)

        # 8. OS fingerprinting
        info("Step 7/10 - Operating system fingerprinting")
        if self.cfg.os_detection:
            for h in alive_hosts:
                try:
                    fingerprint_os(h, timeout=self.cfg.timeout)
                except Exception as exc:
                    warn(f"OS fingerprint error for {h.ip}: {exc}")

        # 9. Security analysis + CVE correlation
        info("Step 8/10 - Comprehensive security analysis & CVE correlation")
        for h in alive_hosts:
            tls = {p: r for p, r in self._tls_results.items()
                   if r.get("_ip") == h.ip}
            h.findings = analyze_host(h, tls_results=tls,
                                      enable_cve=self.cfg.cve_check)

        # 10. Risk scoring, remediation, reporting
        info("Step 9/10 - Risk scoring & prioritisation")
        all_findings = [f for h in alive_hosts for f in h.findings]
        all_findings = score_all(all_findings)
        all_findings = deduplicate(all_findings)
        all_findings = attach_remediation_all(all_findings)
        all_findings = prioritize(all_findings)
        self.report.findings = all_findings
        self.report.stats = summary_stats(all_findings)

        info("Step 10/10 - Report generation & remediation guidance")
        self._print_summary()
        return self._finish(start)

    # ------------------------------------------------------------------
    def _audit_http_tls(self, host):
        for pr in host.ports:
            if pr.state != "open":
                continue
            if pr.protocol != "tcp":
                continue
            port = pr.port
            if port in HTTP_PORTS:
                use_ssl = port in TLS_PORTS
                try:
                    http = audit_http(host.ip, port, use_ssl=use_ssl,
                                      timeout=self.cfg.timeout)
                    if http.status:
                        host.http_audits[port] = http
                        if host.http is None:
                            host.http = http
                except Exception as exc:
                    low_pri(f"  HTTP audit error {host.ip}:{port}: {exc}")
            if port in TLS_PORTS:
                try:
                    tls = audit_tls(host.ip, port, timeout=self.cfg.timeout,
                                    hostname=host.hostname)
                    tls["_ip"] = host.ip
                    self._tls_results[f"{host.ip}:{port}"] = tls
                except Exception as exc:
                    low_pri(f"  TLS audit error {host.ip}:{port}: {exc}")

    # ------------------------------------------------------------------
    def _print_summary(self):
        s = self.report.stats
        out("")
        out(paint("=" * 70, Color.CYAN))
        out(paint(" SECURITY POSTURE SUMMARY", Color.CYAN, bold=True))
        out(paint("=" * 70, Color.CYAN))
        out(f"  Hosts assessed    : {len(self.report.hosts)}")
        open_ports = sum(1 for h in self.report.hosts for p in h.ports if p.state == "open")
        out(f"  Open ports found  : {open_ports}")
        out(f"  Total findings    : {s.get('total', 0)}")
        for sev in ("critical", "high", "medium", "low", "informational"):
            color = {"critical": Color.RED, "high": Color.YELLOW,
                     "medium": Color.YELLOW, "low": Color.BLUE,
                     "informational": Color.DIM}.get(sev, Color.RESET)
            out(f"    {sev:<13}: {s.get(sev, 0)}", color=color)
        out(f"  Maximum risk score: {s.get('max_risk', 0)} / 10")
        out(paint("=" * 70, Color.CYAN))
        out("")
        out(paint("TOP FINDINGS (highest risk first)", Color.CYAN, bold=True))
        for f in self.report.findings[:10]:
            vuln(f"  [{f.severity.upper():<12}] {f.risk_score:>4}/10  {f.title}  ({f.asset})"
                 + (f"  [{f.cve}]" if f.cve else ""))
            for r in f.remediation[:2]:
                low_pri(f"      fix: {r}")

    # ------------------------------------------------------------------
    def _finish(self, start, aborted=False):
        self.report.finished_at = timestamp()
        self.report.duration = fmt_time(elapsed(start))
        if not aborted:
            paths = generate_reports(self.report, output_dir=self.cfg.output_dir)
            ok("Reports generated:")
            for fmt_, path in paths.items():
                low_pri(f"  {fmt_.upper():4s}: {path}")
        else:
            warn("Scan aborted; no reports generated.")
        info(f"Workflow finished at {self.report.finished_at} "
             f"(duration {self.report.duration})")
        return self.report
