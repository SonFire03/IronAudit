from __future__ import annotations

from typing import Literal

from ironaudit.models import Finding
from ironaudit.utils import distro_id_like, run_command

CHECK_ID = "updates"


def run() -> list[Finding]:
    distro = distro_id_like()
    if not ({"debian", "ubuntu"} & distro):
        return [
            Finding(
                check_id=CHECK_ID,
                title="Package update check unsupported on this distribution",
                severity="info",
                status="unsupported",
                category="patching",
                evidence=f"Detected distro identifiers: {', '.join(sorted(distro)) or 'unknown'}",
                remediation="Use native package manager tooling for update status checks.",
                points=0,
            )
        ]

    result = run_command(["apt", "list", "--upgradable"])
    if result.returncode != 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to enumerate upgradable packages",
                severity="low",
                status="info",
                category="patching",
                evidence=result.stderr or "apt command failed",
                remediation="Ensure apt is available and package indexes are readable.",
                points=0,
            )
        ]

    lines = [line for line in result.stdout.splitlines() if line and not line.startswith("Listing")]
    pending = len(lines)
    if pending == 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="No pending package updates",
                severity="info",
                status="pass",
                category="patching",
                evidence="apt reports no upgradable packages",
                remediation="Maintain regular patching cadence.",
                points=0,
            )
        ]

    points = 10 if pending >= 50 else 8 if pending >= 20 else 5
    severity: Literal["medium", "low"] = "medium" if pending >= 20 else "low"
    sample = ", ".join(lines[:5])
    return [
        Finding(
            check_id=CHECK_ID,
            title="Pending package updates detected",
            severity=severity,
            status="warn",
            category="patching",
            evidence=f"{pending} package(s) upgradable. Sample: {sample}",
            remediation="Run apt update && apt upgrade on a validated maintenance window.",
            points=points,
        )
    ]
