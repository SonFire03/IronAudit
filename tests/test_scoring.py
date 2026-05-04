from ironaudit.models import Finding
from ironaudit.scoring import compute_score, compute_score_breakdown, score_rating


def _f(severity: str, points: int, status: str = "fail") -> Finding:
    return Finding(
        check_id="x",
        title="t",
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        category="c",
        evidence="e",
        remediation="r",
        points=points,
    )


def test_no_findings() -> None:
    b = compute_score_breakdown([])
    assert b.final_score == 100
    assert b.total_deduction == 0


def test_info_only_findings() -> None:
    findings = [_f("info", 40), _f("info", 10, "warn")]
    b = compute_score_breakdown(findings)
    assert b.capped_deductions_by_severity["info"] == 0
    assert b.final_score == 100


def test_low_findings_capped_small() -> None:
    findings = [_f("low", 7), _f("low", 9)]
    b = compute_score_breakdown(findings)
    assert b.deductions_by_severity["low"] == 16
    assert b.capped_deductions_by_severity["low"] == 8
    assert b.final_score == 92


def test_medium_findings_capped_moderate() -> None:
    findings = [_f("medium", 20), _f("medium", 20)]
    b = compute_score_breakdown(findings)
    assert b.capped_deductions_by_severity["medium"] == 18
    assert b.final_score == 82


def test_one_high_finding() -> None:
    score = compute_score([_f("high", 18)])
    assert score == 82


def test_multiple_high_findings_capped() -> None:
    b = compute_score_breakdown([_f("high", 20), _f("high", 20), _f("high", 20)])
    assert b.deductions_by_severity["high"] == 60
    assert b.capped_deductions_by_severity["high"] == 30
    assert b.final_score == 70


def test_critical_findings_strong_impact() -> None:
    b = compute_score_breakdown([_f("critical", 40), _f("critical", 40)])
    assert b.capped_deductions_by_severity["critical"] == 80
    assert b.final_score == 20


def test_non_critical_findings_do_not_drop_to_zero() -> None:
    b = compute_score_breakdown(
        [
            _f("high", 100),
            _f("high", 100),
            _f("medium", 100),
            _f("medium", 100),
            _f("low", 100),
            _f("low", 100),
        ]
    )
    assert b.total_deduction == 56
    assert b.final_score == 44


def test_zero_score_requires_critical_and_dangerous_mix() -> None:
    b = compute_score_breakdown(
        [_f("critical", 100), _f("critical", 100), _f("high", 100), _f("medium", 100), _f("low", 100)]
    )
    assert b.total_deduction == 136
    assert b.final_score == 0


def test_mixed_findings() -> None:
    findings = [
        _f("critical", 35),
        _f("high", 20),
        _f("medium", 10),
        _f("low", 5),
        _f("info", 50),
    ]
    b = compute_score_breakdown(findings)
    assert b.total_deduction == 70
    assert b.final_score == 30


def test_score_rating_labels() -> None:
    assert score_rating(95) == "Excellent"
    assert score_rating(80) == "Good"
    assert score_rating(65) == "Fair"
    assert score_rating(50) == "Weak"
    assert score_rating(25) == "Poor"
    assert score_rating(10) == "Critical"
