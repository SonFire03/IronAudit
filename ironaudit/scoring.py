from __future__ import annotations

from ironaudit.models import Finding


def compute_score(findings: list[Finding]) -> int:
    deductions = sum(
        finding.points for finding in findings if finding.status in {"fail", "warn"} and finding.points > 0
    )
    score = 100 - deductions
    return max(0, min(100, score))


def score_rating(score: int) -> str:
    if score >= 90:
        return "Hardened"
    if score >= 70:
        return "Acceptable"
    if score >= 50:
        return "Weak"
    return "Critical"
