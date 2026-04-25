from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["pass", "fail", "warn", "info", "unsupported"]


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    category: str
    evidence: str
    remediation: str
    points: int = 0
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        refs_raw = data.get("references", [])
        references = [str(item) for item in refs_raw] if isinstance(refs_raw, list) else []
        points_raw = data.get("points", 0)
        points = points_raw if isinstance(points_raw, int) else 0
        return cls(
            check_id=str(data.get("check_id", "unknown")),
            title=str(data.get("title", "Untitled finding")),
            severity=str(data.get("severity", "info")),  # type: ignore[arg-type]
            status=str(data.get("status", "info")),  # type: ignore[arg-type]
            category=str(data.get("category", "general")),
            evidence=str(data.get("evidence", "")),
            remediation=str(data.get("remediation", "")),
            points=points,
            references=references,
        )


@dataclass(slots=True)
class ScanMetadata:
    hostname: str
    distro: str
    duration_seconds: float | None = None
    scan_profile: str | None = None
    scanned_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanMetadata:
        duration = data.get("duration_seconds")
        duration_value = float(duration) if isinstance(duration, (int, float)) else None
        return cls(
            hostname=str(data.get("hostname", "unknown")),
            distro=str(data.get("distro", "Linux")),
            duration_seconds=duration_value,
            scan_profile=str(data["scan_profile"]) if "scan_profile" in data and data["scan_profile"] is not None else None,
            scanned_at=str(data.get("scanned_at", datetime.now(UTC).isoformat(timespec="seconds"))),
        )


@dataclass(slots=True)
class ScanReport:
    metadata: ScanMetadata
    selected_checks: list[str]
    findings: list[Finding]
    score: int
    rating: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanReport:
        metadata_raw = data.get("metadata", {})
        metadata = ScanMetadata.from_dict(metadata_raw if isinstance(metadata_raw, dict) else {})

        findings_raw = data.get("findings", [])
        findings = [
            Finding.from_dict(item) for item in findings_raw if isinstance(item, dict)
        ]

        selected_raw = data.get("selected_checks", [])
        selected_checks = [str(item) for item in selected_raw] if isinstance(selected_raw, list) else []

        score_raw = data.get("score", 0)
        score = score_raw if isinstance(score_raw, int) else 0

        return cls(
            metadata=metadata,
            selected_checks=selected_checks,
            findings=findings,
            score=score,
            rating=str(data.get("rating", "Critical")),
        )
