from __future__ import annotations

from ironaudit.history import latest_two_reports, list_snapshots, load_snapshot_by_id, save_snapshot
from ironaudit.models import Finding, ScanMetadata, ScanReport


def _report(score: int) -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(hostname="lab", distro="Ubuntu"),
        selected_checks=["ssh"],
        findings=[
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
        score=score,
        rating="Weak",
    )


def test_save_and_list_snapshots(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IRONAUDIT_HISTORY_DIR", str(tmp_path))

    path = save_snapshot(_report(70), label="baseline")
    assert path.exists()

    snapshots = list_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0].score == 70


def test_load_snapshot_by_id(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IRONAUDIT_HISTORY_DIR", str(tmp_path))
    path = save_snapshot(_report(74), label="first")

    loaded = load_snapshot_by_id(path.stem)
    assert loaded.score == 74
    assert loaded.metadata.hostname == "lab"


def test_latest_two_reports(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("IRONAUDIT_HISTORY_DIR", str(tmp_path))
    save_snapshot(_report(60), label="older")
    save_snapshot(_report(80), label="newer")

    pair = latest_two_reports()
    assert pair is not None
    before, after = pair
    assert before.score == 60
    assert after.score == 80
