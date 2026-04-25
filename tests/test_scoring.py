from ironaudit.models import Finding
from ironaudit.scoring import compute_score, score_rating


def _f(points: int, status: str = "fail") -> Finding:
    return Finding(
        check_id="x",
        title="t",
        severity="low",
        status=status,  # type: ignore[arg-type]
        category="c",
        evidence="e",
        remediation="r",
        points=points,
    )


def test_compute_score_deducts_fail_warn_only() -> None:
    findings = [_f(20, "fail"), _f(5, "warn"), _f(50, "info"), _f(99, "pass")]
    assert compute_score(findings) == 75


def test_compute_score_bounded() -> None:
    findings = [_f(80), _f(80)]
    assert compute_score(findings) == 0


def test_score_rating() -> None:
    assert score_rating(95) == "Hardened"
    assert score_rating(80) == "Acceptable"
    assert score_rating(60) == "Weak"
    assert score_rating(40) == "Critical"
