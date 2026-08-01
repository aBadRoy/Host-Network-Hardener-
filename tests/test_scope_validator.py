"""Tests for scope validation and the authorization gate."""

from hardener.models import Target
from hardener.scope_validator import ScopeValidator


def _target(ip=None, hostname=None):
    return Target(raw=ip or hostname, ip=ip, hostname=hostname, kind="single_ip")


def test_authorized_in_scope():
    v = ScopeValidator(authorized=True)
    ok_flag, reason = v.validate(_target("10.0.0.5"))
    assert ok_flag is True
    assert "scope" in reason


def test_not_authorized_denied():
    v = ScopeValidator(authorized=False)
    ok_flag, reason = v.validate(_target("10.0.0.5"))
    assert ok_flag is False
    assert "--authorized" in reason


def test_out_of_scope_denied():
    v = ScopeValidator(scope={"allowed": ["10.0.0.0/8"]}, authorized=True)
    ok_flag, _ = v.validate(_target("192.168.1.1"))
    assert ok_flag is False


def test_excluded_denied():
    v = ScopeValidator(
        scope={"allowed": ["0.0.0.0/0"], "excluded": ["10.0.0.5"]},
        authorized=True,
    )
    ok_flag, _ = v.validate(_target("10.0.0.5"))
    assert ok_flag is False


def test_blocked_asset_denied():
    v = ScopeValidator(
        scope={"allowed": ["0.0.0.0/0"], "blocked_assets": ["internal.corp"]},
        authorized=True,
    )
    ok_flag, _ = v.validate(_target(hostname="internal.corp"))
    assert ok_flag is False


def test_scan_window_always_open():
    v = ScopeValidator(scope={"window": "00:00-23:59"}, authorized=True)
    assert v._scan_window_allowed() is True


def test_confirm_authorization_flag():
    v = ScopeValidator(authorized=True)
    assert v.confirm_authorization() is True


def test_confirm_authorization_declined(monkeypatch):
    v = ScopeValidator(authorized=False)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert v.confirm_authorization() is False
