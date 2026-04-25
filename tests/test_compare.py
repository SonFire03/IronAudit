from ironaudit.compare import compare_reports
from ironaudit.models import Finding, ScanMetadata, ScanReport


def _report(score: int, findings: list[Finding]) -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(hostname="host", distro="Ubuntu"),
        selected_checks=["ssh", "firewall"],
        findings=findings,
        score=score,
        rating="Acceptable",
    )


def test_compare_reports_new_and_resolved_risks() -> None:
    old = _report(
        70,
        [
            Finding(
                check_id="ssh",
                title="SSH password authentication enabled",
                severity="high",
                status="fail",
                category="ssh",
                evidence="x",
                remediation="y",
                points=15,
            )
        ],
    )
    new = _report(
        82,
        [
            Finding(
                check_id="firewall",
                title="No active firewall detected",
                severity="high",
                status="fail",
                category="firewall",
                evidence="x",
                remediation="y",
                points=20,
            )
        ],
    )

    result = compare_reports(old, new)

    assert result.score_delta == 12
    assert len(result.new_risks) == 1
    assert result.new_risks[0].check_id == "firewall"
    assert len(result.resolved_risks) == 1
    assert result.resolved_risks[0].check_id == "ssh"
