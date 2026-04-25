from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ironaudit.models import ScanReport

DEFAULT_HISTORY_DIR = ".ironaudit-history"


@dataclass(slots=True)
class Snapshot:
    path: Path
    snapshot_id: str
    created_at: str
    score: int
    rating: str
    hostname: str


def history_dir() -> Path:
    raw = os.getenv("IRONAUDIT_HISTORY_DIR", DEFAULT_HISTORY_DIR)
    return Path(raw)


def ensure_history_dir() -> Path:
    target = history_dir()
    target.mkdir(parents=True, exist_ok=True)
    return target


def save_snapshot(report: ScanReport, label: str | None = None) -> Path:
    target = ensure_history_dir()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    safe_host = _safe_fragment(report.metadata.hostname)
    safe_label = _safe_fragment(label) if label else "scan"
    snapshot_id = f"{stamp}_{safe_host}_{safe_label}"
    path = target / f"{snapshot_id}.json"
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def list_snapshots(limit: int | None = None) -> list[Snapshot]:
    target = ensure_history_dir()
    files = sorted(target.glob("*.json"), reverse=True)
    if limit is not None:
        files = files[:limit]

    snapshots: list[Snapshot] = []
    for path in files:
        report = _load_report(path)
        if report is None:
            continue
        snapshots.append(
            Snapshot(
                path=path,
                snapshot_id=path.stem,
                created_at=report.metadata.scanned_at,
                score=report.score,
                rating=report.rating,
                hostname=report.metadata.hostname,
            )
        )
    return snapshots


def load_snapshot_by_id(snapshot_id: str) -> ScanReport:
    path = ensure_history_dir() / f"{snapshot_id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid snapshot format: {path}")
    return ScanReport.from_dict(data)


def latest_two_reports() -> tuple[ScanReport, ScanReport] | None:
    snapshots = list_snapshots(limit=2)
    if len(snapshots) < 2:
        return None

    newest = _load_report(snapshots[0].path)
    previous = _load_report(snapshots[1].path)
    if newest is None or previous is None:
        return None
    return previous, newest


def _safe_fragment(value: str | None) -> str:
    text = (value or "unknown").strip().lower()
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in text)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "unknown"


def _load_report(path: Path) -> ScanReport | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return ScanReport.from_dict(data)
