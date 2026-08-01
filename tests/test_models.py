"""Tests for the dataclass models."""

from hardener.models import Finding, Host, PortResult, ScanConfig, Target


def test_target_defaults():
    t = Target(raw="127.0.0.1", ip="127.0.0.1")
    assert t.kind == "unknown"
    assert t.ip_list == []
    assert t.default_port is None


def test_port_result_defaults():
    p = PortResult(port=80)
    assert p.protocol == "tcp"
    assert p.state == "closed"
    assert p.service == "unknown"
    assert p.banners == []


def test_host_defaults():
    h = Host(ip="10.0.0.1")
    assert h.alive is False
    assert h.ports == []
    assert h.http_audits == {}
    assert h.os_fingerprint == {}


def test_finding_remediation_default():
    f = Finding(title="x")
    assert f.remediation == []


def test_scan_config_defaults():
    c = ScanConfig()
    assert c.threads == 50
    assert c.timeout == 2.0
    assert c.authorized is False
    assert c.enumerate_services is True
