"""Correlation & Risk Scoring Engine.

Risk Score = Impact x Likelihood (normalised to 0-10). Severity is derived from
the score using standard banding. Findings are correlated and deduplicated
before scoring to reduce false positives.
"""

from .models import Finding

SEVERITY_BANDS = [
    (0.0, 1.0, "informational"),
    (1.0, 4.0, "low"),
    (4.0, 6.5, "medium"),
    (6.5, 8.5, "high"),
    (8.5, 10.0, "critical"),
]


def severity_from_score(score):
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= score < hi:
            return label
    return "critical"


def score_finding(finding):
    """Compute and assign risk score + severity for a Finding."""
    impact = max(0, min(10, finding.impact))
    likelihood = max(0, min(10, finding.likelihood))
    score = round((impact * likelihood) / 10.0, 2)
    finding.risk_score = score
    finding.severity = severity_from_score(score)
    return finding


def score_all(findings):
    for f in findings:
        score_finding(f)
    return findings


def deduplicate(findings):
    """Correlation + false-positive reduction.

    Dedupes findings that share (title, asset, cve) and keeps the highest-severity
    representative.
    """
    seen = {}
    for f in findings:
        key = (f.title.lower(), f.asset, f.cve or "")
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            if f.risk_score > existing.risk_score:
                seen[key] = f
    return list(seen.values())


def prioritize(findings):
    """Return findings sorted by risk (critical first)."""
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def summary_stats(findings):
    counts: dict[str, int] = {"informational": 0, "low": 0, "medium": 0,
                              "high": 0, "critical": 0}
    avg = 0.0
    if findings:
        avg = round(sum(f.risk_score for f in findings) / len(findings), 2)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    max_risk = round(max((f.risk_score for f in findings), default=0.0), 2)
    return {**counts, "total": len(findings), "avg_risk": avg, "max_risk": max_risk}
