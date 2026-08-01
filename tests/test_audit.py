"""Tests for the append-only audit trail."""

from hardener.audit import AuditLog


def test_audit_log_writes_entries(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(str(path))
    log.log("STAGE5", "port_scan", target="10.0.0.5", result="3 open ports",
            ports="22,80,443")
    log.log("STAGE2", "scope_check", target="10.0.0.5", result="DENIED",
            reason="out of scope")
    log.close()
    text = path.read_text(encoding="utf-8")
    assert "STAGE5" in text
    assert "port_scan" in text
    assert "target=10.0.0.5" in text
    assert "result=3 open ports" in text
    assert "ports=22,80,443" in text
    assert "scope_check" in text


def test_audit_log_appends_not_overwrites(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(str(path))
    log.log("STAGE1", "input_parsed", result="1 targets")
    log.close()
    log2 = AuditLog(str(path))
    log2.log("STAGE1", "input_parsed", result="2 targets")
    log2.close()
    text = path.read_text(encoding="utf-8")
    assert text.count("input_parsed") == 2


def test_audit_log_sanitizes_pipes(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(str(path))
    log.log("STAGE5", "port_scan", target="10.0.0.5", result="a | b")
    log.close()
    assert "a | b" not in path.read_text(encoding="utf-8")
