from ironaudit.exporters.html_exporter import to_html
from ironaudit.exporters.json_exporter import to_json
from ironaudit.exporters.markdown_exporter import to_markdown
from ironaudit.exporters.sarif_exporter import to_sarif
from ironaudit.models import Finding, ScanMetadata, ScanReport


def _sample_report() -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(hostname="host", distro="Ubuntu"),
        selected_checks=["ssh"],
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


def test_json_export_contains_score() -> None:
    payload = to_json(_sample_report())
    assert '"score": 85' in payload
    assert '"rating": "Acceptable"' in payload


def test_markdown_export_contains_sections() -> None:
    payload = to_markdown(_sample_report())
    assert "# IronAudit Report" in payload
    assert "## Findings" in payload
    assert "SSH password authentication enabled" in payload


def test_html_export_contains_key_content() -> None:
    payload = to_html(_sample_report())
    assert "<!doctype html>" in payload.lower()
    assert "IronAudit Report" in payload
    assert "SSH password authentication enabled" in payload


def test_sarif_export_contains_structure() -> None:
    payload = to_sarif(_sample_report())
    assert '"version": "2.1.0"' in payload
    assert '"runs"' in payload
    assert '"ruleId"' in payload
