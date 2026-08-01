"""Tests for host discovery helpers."""

import hardener.host_discovery as hd


def test_ping_command_windows(monkeypatch):
    monkeypatch.setattr(hd.os, "name", "nt")
    cmd = hd._ping_command(2, 1.5)
    assert cmd[0] == "ping"
    assert "-n" in cmd and "2" in cmd
    assert "-w" in cmd and "1500" in cmd


def test_ping_command_posix(monkeypatch):
    monkeypatch.setattr(hd.os, "name", "posix")
    monkeypatch.setattr(hd.shutil, "which", lambda name: "/usr/bin/ping")
    cmd = hd._ping_command(2, 1.5)
    assert cmd[0] == "ping"
    assert "-c" in cmd and "2" in cmd
    assert "-W" in cmd and "1" in cmd


def test_ping_command_posix_no_ping_on_path(monkeypatch):
    monkeypatch.setattr(hd.os, "name", "posix")
    monkeypatch.setattr(hd.shutil, "which", lambda name: None)
    cmd = hd._ping_command(2, 1.5)
    assert cmd[0] == "/bin/ping"
    assert "-c" in cmd and "-W" in cmd
