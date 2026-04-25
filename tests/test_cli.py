import json

import pytest

pytest.importorskip("typer")

from typer.testing import CliRunner

from ironaudit.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_info_command() -> None:
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "IronAudit" in result.stdout
    assert "Checks" in result.stdout


def test_scan_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from ironaudit import cli
    from ironaudit.models import Finding, ScanMetadata, ScanReport

    def fake_run_scan(include=None, exclude=None) -> ScanReport:  # type: ignore[no-untyped-def]
        _ = include, exclude
        return ScanReport(
            metadata=ScanMetadata(hostname="test-host", distro="Ubuntu"),
            selected_checks=["ssh"],
            findings=[
                Finding(
                    check_id="ssh",
                    title="SSH root login disabled",
                    severity="info",
                    status="pass",
                    category="ssh",
                    evidence="PermitRootLogin no",
                    remediation="Keep disabled",
                    points=0,
                )
            ],
            score=100,
            rating="Hardened",
        )

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)

    result = runner.invoke(app, ["scan", "--json"])
    assert result.exit_code == 0
    assert '"score": 100' in result.stdout
    assert '"rating": "Hardened"' in result.stdout


def test_scan_html_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from ironaudit import cli
    from ironaudit.models import Finding, ScanMetadata, ScanReport

    def fake_run_scan(include=None, exclude=None) -> ScanReport:  # type: ignore[no-untyped-def]
        _ = include, exclude
        return ScanReport(
            metadata=ScanMetadata(hostname="test-host", distro="Ubuntu"),
            selected_checks=["ssh"],
            findings=[
                Finding(
                    check_id="ssh",
                    title="SSH root login disabled",
                    severity="info",
                    status="pass",
                    category="ssh",
                    evidence="PermitRootLogin no",
                    remediation="Keep disabled",
                    points=0,
                )
            ],
            score=100,
            rating="Hardened",
        )

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    result = runner.invoke(app, ["scan", "--html"])
    assert result.exit_code == 0
    assert "<!doctype html>" in result.stdout.lower()


def test_compare_json_output(tmp_path) -> None:  # type: ignore[no-untyped-def]
    before = {
        "metadata": {"hostname": "h1", "distro": "Ubuntu"},
        "selected_checks": ["ssh"],
        "findings": [
            {
                "check_id": "ssh",
                "title": "SSH password authentication enabled",
                "severity": "high",
                "status": "fail",
                "category": "ssh",
                "evidence": "x",
                "remediation": "y",
                "points": 15,
            }
        ],
        "score": 70,
        "rating": "Weak",
    }
    after = {
        "metadata": {"hostname": "h1", "distro": "Ubuntu"},
        "selected_checks": ["firewall"],
        "findings": [
            {
                "check_id": "firewall",
                "title": "No active firewall detected",
                "severity": "high",
                "status": "fail",
                "category": "firewall",
                "evidence": "x",
                "remediation": "y",
                "points": 20,
            }
        ],
        "score": 65,
        "rating": "Weak",
    }

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    result = runner.invoke(app, ["compare", str(before_path), str(after_path), "--json"])
    assert result.exit_code == 0
    assert '"score_delta": -5' in result.stdout
    assert '"new_risks_count": 1' in result.stdout


def test_history_list_empty(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IRONAUDIT_HISTORY_DIR", str(tmp_path))
    result = runner.invoke(app, ["history", "list"])
    assert result.exit_code == 0
    assert "No snapshots found" in result.stdout
