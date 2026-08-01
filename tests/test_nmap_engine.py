"""Tests for the optional nmap backend."""

import hardener.nmap_engine as ne

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.04">
<scaninfo type="connect" protocol="tcp" numservices="4" services="22,80,443,25"/>
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="user-set" reason_ttl="0"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13"
         extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="Apache httpd" version="2.4.7" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset" reason_ttl="0"/></port>
<port protocol="tcp" portid="25"><state state="filtered" reason="no-response"/></port>
</ports>
</host>
<runstats><finished time="1700000001" elapsed="1.12" exit="success"/>
<hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def test_parse_nmap_xml_states_and_labels():
    up, ports = ne.parse_nmap_xml(SAMPLE_XML)
    assert up is True
    by_port = {p.port: p for p in ports}
    assert set(by_port) == {22, 25, 80, 443}
    assert by_port[22].state == "open"
    assert by_port[22].service == "SSH"
    assert by_port[22].version == "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 " \
        "Ubuntu Linux; protocol 2.0"
    assert by_port[22].banners == [by_port[22].version]
    assert by_port[80].service == "HTTP"
    assert by_port[443].state == "closed"
    assert by_port[25].state == "filtered"
    assert by_port[22].scan_evidence["method"] == "nmap"


def test_parse_nmap_xml_host_down():
    up, ports = ne.parse_nmap_xml(
        '<nmaprun><host><status state="down"/></host></nmaprun>')
    assert up is False
    assert ports == []


def test_parse_nmap_xml_no_host():
    up, ports = ne.parse_nmap_xml("<nmaprun></nmaprun>")
    assert up is False
    assert ports == []


def test_service_label_normalisation():
    assert ne._service_label("microsoft-ds") == "SMB"
    assert ne._service_label("ms-wbt-server") == "RDP"
    assert ne._service_label("java-rmi") == "Java-RMI"
    assert ne._service_label("foo_bar") == "Foo-Bar"
    assert ne._service_label(None) == "unknown"
    assert ne._service_label("") == "unknown"


def test_build_cmd_connect():
    cmd = ne._build_cmd("10.0.0.5", [22, 80], scan_type="connect",
                        host_timeout=30.0, bin_path="nmap")
    assert cmd[0] == "nmap"
    assert "-sT" in cmd
    assert "-Pn" in cmd
    assert "-n" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80"
    assert "--host-timeout" in cmd
    assert cmd[cmd.index("--host-timeout") + 1] == "30.0s"
    assert cmd[-3:] == ["-oX", "-", "10.0.0.5"]


def test_build_cmd_no_dns_and_no_default_host_timeout():
    cmd = ne._build_cmd("10.0.0.5", [22], bin_path="nmap")
    assert "-n" in cmd
    assert "--host-timeout" not in cmd
    assert "-sV" not in cmd


def test_build_cmd_version_intensity():
    cmd = ne._build_cmd("10.0.0.5", [22], version_detect=True,
                        version_intensity=3, bin_path="nmap")
    assert "-sV" in cmd
    assert cmd[cmd.index("--version-intensity") + 1] == "3"


def test_build_cmd_syn_and_version_detect():
    cmd = ne._build_cmd("10.0.0.5", [22], scan_type="syn",
                        version_detect=True, bin_path="nmap")
    assert "-sS" in cmd
    assert "-sV" in cmd


def test_build_cmd_udp():
    cmd = ne._build_cmd("10.0.0.5", [53, 161], udp=True, bin_path="nmap")
    assert "-sU" in cmd
    assert cmd[cmd.index("-p") + 1] == "53,161"


def test_build_cmd_no_ports_means_all():
    cmd = ne._build_cmd("10.0.0.5", [], bin_path="nmap")
    assert cmd[cmd.index("-p") + 1] == "1-65535"


def test_port_spec_collapses_ranges():
    assert ne._port_spec([22, 80, 443]) == "22,80,443"
    assert ne._port_spec([20, 21, 22, 80]) == "20-22,80"
    assert ne._port_spec(list(range(1, 65536))) == "1-65535"
    assert ne._port_spec([]) == "1-65535"


def test_estimate_timeout_honours_host_timeout():
    assert ne._estimate_timeout(100, 3, 30.0) == 90.0
    assert ne._estimate_timeout(2, 3, 0.0) >= 60


def test_run_nmap_falls_back_from_syn_to_connect(monkeypatch):
    calls = []

    class FakeProc:
        def __init__(self, rc, out=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if "-sS" in cmd:
            return FakeProc(1)
        return FakeProc(0, "<nmaprun/>")

    monkeypatch.setattr(ne.subprocess, "run", fake_run)
    cmd = ["nmap", "-Pn", "-sS", "-p", "22,80", "-oX", "-", "10.0.0.5"]
    out, _err = ne._run_nmap(cmd, 2, 3, 0.0)
    assert out == "<nmaprun/>"
    assert len(calls) == 2
    assert "-sT" in calls[1]
