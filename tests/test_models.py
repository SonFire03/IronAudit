from ironaudit.models import Finding, ScanMetadata, ScanReport


def test_finding_to_dict() -> None:
    finding = Finding(
        check_id="ssh",
        title="SSH root login is enabled",
        severity="high",
        status="fail",
        category="ssh",
        evidence="PermitRootLogin yes",
        remediation="Set PermitRootLogin no",
        points=20,
    )
    data = finding.to_dict()

    assert data["check_id"] == "ssh"
    assert data["points"] == 20


def test_report_to_dict_contains_findings() -> None:
    report = ScanReport(
        metadata=ScanMetadata(hostname="host1", distro="Ubuntu"),
        selected_checks=["ssh"],
        findings=[
            Finding(
                check_id="ssh",
                title="ok",
                severity="info",
                status="pass",
                category="ssh",
                evidence="x",
                remediation="y",
                points=0,
            )
        ],
        score=100,
        rating="Hardened",
    )

    data = report.to_dict()
    assert data["score"] == 100
    assert isinstance(data["findings"], list)
    assert data["findings"][0]["status"] == "pass"


def test_report_from_dict_roundtrip() -> None:
    raw = {
        "metadata": {
            "hostname": "host1",
            "distro": "Ubuntu",
            "duration_seconds": 1.234,
            "scan_profile": "server",
            "scanned_at": "2026-01-01T00:00:00+00:00",
        },
        "selected_checks": ["ssh"],
        "findings": [
            {
                "check_id": "ssh",
                "title": "SSH root login disabled",
                "severity": "info",
                "status": "pass",
                "category": "ssh",
                "evidence": "PermitRootLogin no",
                "remediation": "Keep disabled",
                "points": 0,
            }
        ],
        "score": 100,
        "rating": "Hardened",
    }

    report = ScanReport.from_dict(raw)
    assert report.metadata.duration_seconds == 1.234
    assert report.metadata.scan_profile == "server"
    assert report.findings[0].check_id == "ssh"
    assert report.score == 100
