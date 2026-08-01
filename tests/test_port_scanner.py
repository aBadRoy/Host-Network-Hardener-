"""Tests for the threaded port scanner."""

import time

from hardener.port_scanner import _probe_tcp, scan_tcp_ports, udp_scan


def test_scan_tcp_ports_skips_all_when_deadline_passed():
    out = scan_tcp_ports("127.0.0.1", [22, 80], deadline=time.time() - 1)
    assert out == []


def test_scan_tcp_ports_respects_explicit_deadline(monkeypatch):
    called = []

    def fake_probe(ip, port, timeout, scan_type, retries):
        called.append(port)
        return "closed", {"method": "connect"}

    monkeypatch.setattr("hardener.port_scanner._probe_tcp", fake_probe)
    out = scan_tcp_ports("127.0.0.1", [22, 80, 443],
                         deadline=time.time() + 0.5)
    assert len(out) == 3


def test_probe_tcp_retries_filtered(monkeypatch):
    responses = iter(["filtered", "open"])

    def fake_probe(ip, port, timeout):
        state = next(responses)
        return state, {"method": "connect", "note": "probe"}

    monkeypatch.setattr("hardener.port_scanner.tcp_connect_scan", fake_probe)
    state, evidence = _probe_tcp("10.0.0.1", 22, 1.0, "connect", retries=1)
    assert state == "open"


def test_udp_scan_closed_via_icmp_unreachable(monkeypatch):
    import socket as _socket

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def send(self, data):
            pass

        def recvfrom(self, size):
            raise OSError(111, "Connection refused")

        def close(self):
            pass

    monkeypatch.setattr(_socket, "socket", FakeSock)
    state, evidence = udp_scan("10.0.0.1", 53, timeout=1.0)
    assert state == "closed"
    assert "unreachable" in evidence["note"]
