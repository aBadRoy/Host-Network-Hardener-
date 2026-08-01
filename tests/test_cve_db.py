"""Tests for CVE correlation, version extraction and software matching."""

from hardener.cve_db import (extract_version, match_cves,
                             match_software_aliases, version_tuple)


def test_version_tuple():
    assert version_tuple("7.9p1") == (7, 9, 1)
    assert version_tuple("2.4.54") == (2, 4, 54)
    assert version_tuple("") == ()


def test_extract_version_openssh():
    assert extract_version("openssh", "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu0.1") == "7.9p1"


def test_extract_version_apache():
    assert extract_version("apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)") == "2.4.54"


def test_match_cves_openssh_vulnerable():
    cves = {e["cve"] for e in match_cves("openssh", "SSH-2.0-OpenSSH_6.6.1p1")}
    assert "CVE-2023-38408" in cves
    assert "CVE-2018-15473" in cves


def test_match_cves_openssh_patched():
    cves = match_cves("openssh", "SSH-2.0-OpenSSH_9.3p2")
    assert cves == []


def test_match_cves_redis():
    cves = {e["cve"] for e in match_cves("redis", "redis_version:5.0.7")}
    assert "CVE-2022-0543" in cves


def test_match_cves_apache_patched():
    assert match_cves("apache", "Apache/2.4.54 (Ubuntu)") == []


def test_match_software_aliases_vmware_banner_not_vnc():
    banner = ("220 VMware Authentication Daemon Version 1.0, "
              "ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC")
    assert match_software_aliases("FTP", banner) is None


def test_match_software_aliases_vsftpd():
    assert match_software_aliases("FTP", "220 Mock FTP (vsftpd 2.3.4) ready.") == "vsftpd"


def test_match_software_aliases_service_name():
    assert match_software_aliases("SSH", "SSH-2.0-OpenSSH_7.9p1") == "openssh"
    assert match_software_aliases("Redis", "Redis 5.0.7") == "redis"


def test_match_software_aliases_rfb_vnc():
    assert match_software_aliases("unknown", "RFB 003.008") == "vnc"


def test_match_software_aliases_unknown_returns_none():
    assert match_software_aliases("unknown", "220 strange daemon") is None
