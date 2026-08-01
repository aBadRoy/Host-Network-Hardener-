"""Tests for shared utility helpers."""

import sys

from hardener.utils import (fmt_time, is_valid_cidr, is_valid_hostname,
                            is_valid_ip, normalize_url_target, sanitize_text)


def test_sanitize_text_strips_control_chars():
    out = sanitize_text("a\x00\x1bb\x7fc")
    assert "\x00" not in out and "\x1b" not in out


class _FakeStdout:
    def __init__(self, encoding):
        self.encoding = encoding


def test_sanitize_text_non_encodable(monkeypatch):
    # Simulate the Windows cp1252 console where U+036E cannot be encoded.
    monkeypatch.setattr(sys, "stdout", _FakeStdout("cp1252"))
    out = sanitize_text("bad\u036echar")
    assert isinstance(out, str)
    assert "\u036e" not in out
    assert out.startswith("bad")


def test_sanitize_text_keeps_utf8(monkeypatch):
    monkeypatch.setattr(sys, "stdout", _FakeStdout("utf-8"))
    assert sanitize_text("café") == "café"


def test_sanitize_text_non_string():
    assert sanitize_text(None) == ""
    assert sanitize_text(123) == "123"


def test_is_valid_ip():
    assert is_valid_ip("10.0.0.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("not-an-ip")


def test_is_valid_cidr():
    assert is_valid_cidr("10.0.0.0/8")
    assert is_valid_cidr("192.168.0.0/24")
    assert not is_valid_cidr("10.0.0.0")


def test_is_valid_hostname():
    assert is_valid_hostname("scanme.nmap.org")
    assert not is_valid_hostname("not a hostname")


def test_normalize_url_target():
    host, port = normalize_url_target("http://example.com:8080")
    assert (host, port) == ("example.com", 8080)
    host, port = normalize_url_target("https://example.com")
    assert host == "example.com"
    assert port is None


def test_fmt_time():
    assert fmt_time(0.5) == "500 ms"
    assert fmt_time(2.0) == "2.00 s"
