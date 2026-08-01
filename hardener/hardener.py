"""Hardener engine: orchestrates the full assessment workflow.

1. Input intake          6. Service enumeration
2. Scope validation      7. Banner/fingerprint + HTTP/TLS audit
3. DNS discovery         8. OS fingerprinting
4. Host discovery        9. Security analysis + CVE correlation
5. Port scanning        10. Risk scoring + reporting + remediation

Every stage writes to the shared audit log so a run is fully traceable.
"""

import time
from typing import Optional

from . import config
from .audit import AuditLog
from .dns_discovery import discover_host_infrastructure
from .host_discovery import discover_hosts
from .http_audit import audit_http
from .input_handler import expand_targets
from .models import Host, ScanConfig, ScanReport
from .nmap_engine import nmap_available, nmap_tcp_scan, nmap_udp_scan
from .os_fingerprint import fingerprint_os
from .port_scanner import scan_tcp_ports, scan_udp_ports
from .ratelimit import RateLimiter
from .remediation import attach_remediation_all
from .reporting import generate_reports, write_grepable
from .risk_engine import deduplicate, prioritize, score_all, summary_stats
from .scope_validator import ScopeValidator
from .security_analysis import analyze_host
from .service_enum import enumerate_port
from .tls_audit import audit_tls
from .utils import (Color, elapsed, fmt_time, info, low_pri, ok, out, paint,
                    timestamp, v_info, vuln, warn)

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
            rate_limit=self.scope.get("rate_limit") or self.cfg.max_rate,
        )
        if not self.cfg.dns_servers:
            self.cfg.dns_servers = config.DEFAULT_DNS_SERVERS
        self.limiter = RateLimiter(self.cfg.max_rate)
        self.audit: Optional[AuditLog] = None

    # ------------------------------------------------------------------
    def run(self, targets=None):
        self.report.started_at = timestamp()
        start = time.time()
        out(paint(config.BANNER, Color.CYAN, bold=True))
        out(paint(config.TOOL_NAME, Color.CYAN, bold=True) +
            f"  --  {config.TOOL_TAGLINE}")
        info(f"Workflow started at {self.report.started_at}")
        v_info(2, f"verbosity={self.cfg.verbose} debug={self.cfg.debug} "
                  f"timing=-T{self.cfg.timing} scan_type={self.cfg.scan_type}")

        self._setup_audit()

        # 1. Input intake
        self.cfg.targets = targets or self.cfg.targets
        if not self.cfg.targets:
            raise ValueError("No targets supplied to the engine.")
        info(f"Parsed {len(self.cfg.targets)} target(s) from input.")
        self.report.targets = self.cfg.targets
        self._log("STAGE1", "input_parsed", result=f"{len(self.cfg.targets)} targets")

        # 2. Scope validation + authorization
        info("Step 1/10 - Scope validation & authorisation")
        if not self.validator.confirm_authorization():
            return self._finish(start, aborted=True)
        approved = []
        for t in expand_targets(self.cfg.targets):
            ok_flag, reason = self.validator.validate(t)
            self._log("STAGE2", "scope_check", target=t.raw,
                           result="ALLOWED" if ok_flag else "DENIED",
                           reason=reason)
            if not ok_flag:
                warn(f"Out of scope: {t.raw} ({reason})")
                continue
            approved.append(t)
        if self.cfg.exclude_list:
            approved = [t for t in approved
                        if t.raw not in self.cfg.exclude_list
                        and t.ip not in self.cfg.exclude_list]
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
        probes = {
            "icmp": self.cfg.icmp_ping,
            "tcp": self.cfg.tcp_ping,
            "ack": self.cfg.ack_ping,
            "udp": self.cfg.udp_ping,
            "http": True,
        }
        v_info(2, f"discovery probes: {[k for k, v in probes.items() if v]}")
        alive_hosts = discover_hosts(
            list(ip_hosts.keys()),
            hostnames={ip: t.hostname for ip, t in ip_hosts.items()},
            timeout=self.cfg.timeout,
            probes=probes,
        )
        for h in alive_hosts:
            self._log("STAGE4", "host_discovery", target=h.ip,
                           result="ALIVE", method=h.alive_method)
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

        if self.cfg.ping_sweep:
            info("Ping-sweep mode (-sn): skipping port scanning.")
            return self._finish(start)

        # 5. Port scanning
        info("Step 4/10 - Port scanning")
        ports = self.cfg.ports or config.DEFAULT_PORTS
        use_nmap = self.cfg.use_nmap and nmap_available()
        if use_nmap:
            v_info(1, "nmap backend detected on PATH; using nmap for port "
                       "scanning (fall back with --no-nmap).")
        for h in alive_hosts:
            deadline = (time.time() + self.cfg.host_timeout
                        if self.cfg.host_timeout > 0 else 0)
            if use_nmap:
                h.ports = nmap_tcp_scan(
                    h.ip, ports, timeout=self.cfg.timeout,
                    timing=self.cfg.timing, scan_type=self.cfg.scan_type,
                    retries=self.cfg.max_retries,
                    version_detect=self.cfg.version_intensity > 0,
                    host_timeout=self.cfg.host_timeout,
                )
            else:
                h.ports = scan_tcp_ports(
                    h.ip, ports, timeout=self.cfg.timeout, threads=self.cfg.threads,
                    use_syn=self.cfg.syn_scan, progress_label=h.ip,
                    scan_type=self.cfg.scan_type, retries=self.cfg.max_retries,
                    limiter=self.limiter, scan_delay=self.cfg.scan_delay,
                    randomize=self.cfg.randomize, stats_every=self.cfg.stats_every,
                    show_open_only=self.cfg.show_open_only,
                    show_reason=self.cfg.show_reason, deadline=deadline,
                )
            open_tcp = [r.port for r in h.ports if r.state == "open"]
            self._log("STAGE5", "port_scan", target=h.ip,
                           result=f"{len(open_tcp)} open ports", ports=",".join(map(str, open_tcp)))
            if self.cfg.udp_scan:
                if use_nmap:
                    h.ports += nmap_udp_scan(
                        h.ip, self.cfg.udp_ports or config.DEFAULT_UDP_PORTS,
                        timeout=self.cfg.timeout, timing=self.cfg.timing,
                        retries=self.cfg.max_retries,
                        host_timeout=self.cfg.host_timeout,
                    )
                else:
                    h.ports += scan_udp_ports(
                        h.ip, self.cfg.udp_ports or config.DEFAULT_UDP_PORTS,
                        timeout=self.cfg.timeout, progress_label=h.ip,
                        retries=self.cfg.max_retries, limiter=self.limiter,
                        randomize=self.cfg.randomize, show_reason=self.cfg.show_reason,
                    )

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
            self._log("STAGE9", "analysis", target=h.ip,
                           result=f"{len(h.findings)} findings")

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
    def _log(self, stage, action, target="", result="", **extra):
        if self.audit is not None:
            self.audit.log(stage, action, target=target, result=result, **extra)

    # ------------------------------------------------------------------
    def _setup_audit(self):
        out_dir = self.cfg.output_dir
        from .utils import ensure_dir
        ensure_dir(out_dir)
        self.audit = AuditLog(self.cfg.output_dir + "/audit.log")

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
            if self.cfg.grepable_path:
                write_grepable(self.report, self.cfg.grepable_path)
            ok("Reports generated:")
            for fmt_, path in paths.items():
                low_pri(f"  {fmt_.upper():4s}: {path}")
            if self.audit:
                self._log("STAGE10", "reports", result="generated",
                               dir=self.cfg.output_dir)
                self.audit.close()
        else:
            warn("Scan aborted; no reports generated.")
        info(f"Workflow finished at {self.report.finished_at} "
             f"(duration {self.report.duration})")
        return self.report
