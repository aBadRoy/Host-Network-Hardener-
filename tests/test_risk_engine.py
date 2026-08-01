"""Tests for the correlation & risk scoring engine."""

import pytest

from hardener.models import Finding
from hardener.risk_engine import (deduplicate, prioritize, score_all,
                                  score_finding, severity_from_score,
                                  summary_stats)


def _finding(title, impact=5, likelihood=5, asset="10.0.0.1", cve=None):
    return Finding(title=title, impact=impact, likelihood=likelihood,
                   asset=asset, cve=cve)


def test_severity_bands():
    assert severity_from_score(0.0) == "informational"
    assert severity_from_score(2.0) == "low"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(9.0) == "critical"


def test_score_finding_formula():
    f = score_finding(_finding("test", impact=8, likelihood=7))
    assert f.risk_score == pytest.approx(5.6)
    assert f.severity == "medium"


def test_score_all():
    findings = score_all([_finding("a", 10, 10), _finding("b", 1, 1)])
    assert findings[0].risk_score == 10.0
    assert findings[1].risk_score == 0.1


def test_deduplicate_keeps_highest():
    low = score_finding(_finding("dup", impact=3, likelihood=3, cve="CVE-2020-0001"))
    high = score_finding(_finding("dup", impact=9, likelihood=9, cve="CVE-2020-0001"))
    result = deduplicate([low, high])
    assert len(result) == 1
    assert result[0].risk_score == 8.1


def test_prioritize_high_first():
    scored = score_all([_finding("low", 2, 2), _finding("high", 9, 9)])
    ordered = prioritize(scored)
    assert ordered[0].title == "high"


def test_summary_stats_counts():
    findings = score_all([
        _finding("crit", 10, 10),
        _finding("high", 8, 9),   # 8*9/10 = 7.2 -> high
        _finding("low", 4, 4),    # 4*4/10 = 1.6 -> low
    ])
    stats = summary_stats(findings)
    assert stats["total"] == 3
    assert stats["critical"] == 1
    assert stats["high"] == 1
    assert stats["low"] == 1
    assert stats["max_risk"] == 10.0


def test_summary_stats_empty():
    stats = summary_stats([])
    assert stats["total"] == 0
    assert stats["max_risk"] == 0.0
