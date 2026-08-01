"""Tests for the report generation engine (TXT/JSON/XML/CSV/HTML)."""

import csv
import json
import xml.etree.ElementTree as ET

from hardener.models import (Finding, Host, PortResult, ScanReport)
from hardener.risk_engine import score_all, summary_stats
from hardener.reporting import generate_reports


def _sample_report():
    host = Host(ip="10.0.0.5", hostname="target.corp", alive=True,
                alive_method="ICMP")
    host.ports.append(PortResult(port=22, protocol="tcp", state="open",
                                 service="SSH",
                                 version="SSH-2.0-OpenSSH_7.9p1"))
    host.ports.append(PortResult(port=443, protocol="tcp", state="open",
                                 service="HTTPS"))
    host.ports.append(PortResult(port=80, protocol="tcp", state="closed"))
    findings = score_all([
        Finding(title="Weak SSH version", description="Old OpenSSH",
                severity="high", impact=8, likelihood=7,
                asset="10.0.0.5", cve="CVE-2023-38408"),
        Finding(title="Missing security header", category="http",
                severity="low", impact=3, likelihood=3,
                asset="10.0.0.5", evidence="strict-transport-security"),
    ])
    report = ScanReport(tool_name="test", tool_version="0.0.1",
                        targets=[], hosts=[host], findings=findings)
    report.stats = summary_stats(findings)
    return report


def test_generate_all_formats(tmp_path):
    paths = generate_reports(_sample_report(), output_dir=str(tmp_path))
    assert set(paths) == {"txt", "json", "xml", "csv", "html"}
    for fmt_, path in paths.items():
        assert tmp_path.joinpath(path).exists(), fmt_


def test_json_report_well_formed(tmp_path):
    paths = generate_reports(_sample_report(), output_dir=str(tmp_path))
    with open(tmp_path / paths["json"], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["summary"]["total"] == 2
    assert data["hosts"][0]["ip"] == "10.0.0.5"


def test_xml_report_parses(tmp_path):
    paths = generate_reports(_sample_report(), output_dir=str(tmp_path))
    tree = ET.parse(tmp_path / paths["xml"])
    assert tree.getroot().tag == "SecurityAssessmentReport"
    # All findings present in XML.
    nodes = tree.findall(".//Finding")
    assert len(nodes) == 2


def test_csv_report_has_header_and_rows(tmp_path):
    paths = generate_reports(_sample_report(), output_dir=str(tmp_path))
    with open(tmp_path / paths["csv"], "r", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert all("title" in row for row in rows)


def test_txt_report_mentions_finding(tmp_path):
    paths = generate_reports(_sample_report(), output_dir=str(tmp_path))
    text = (tmp_path / paths["txt"]).read_text(encoding="utf-8")
    assert "Weak SSH version" in text
