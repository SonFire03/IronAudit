from ironaudit.models import Finding, ScanMetadata, ScanReport
from ironaudit.webapp import parse_csv, render_home


def _report() -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(hostname="lab", distro="Ubuntu 24.04"),
        selected_checks=["ssh", "firewall"],
        findings=[
            Finding(
                check_id="ssh",
                title="SSH password authentication enabled",
                severity="high",
                status="fail",
                category="ssh",
                evidence="PasswordAuthentication yes",
                remediation="Disable password auth",
                points=15,
            )
        ],
        score=85,
        rating="Acceptable",
    )


def test_parse_csv() -> None:
    assert parse_csv(None) is None
    assert parse_csv("") is None
    assert parse_csv("ssh, firewall ,users") == ["ssh", "firewall", "users"]


def test_render_home_no_report() -> None:
    html = render_home(None)
    assert "No scan executed yet." in html
    assert "IronAudit Security Console" in html
    assert "HTML Report" in html


def test_render_home_with_report() -> None:
    html = render_home(_report(), include="ssh", exclude="updates")
    assert "Score: 85/100 (Acceptable)" in html
    assert "SSH password authentication enabled" in html
    assert "value='ssh'" in html
    assert "value='updates'" in html
