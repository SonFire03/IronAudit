from __future__ import annotations

import platform

from ironaudit.models import Finding
from ironaudit.utils import detect_distro, hostname, run_command

CHECK_ID = "system"


def run() -> list[Finding]:
    findings: list[Finding] = []
    host = hostname()
    distro = detect_distro()
    kernel = platform.release()
    arch = platform.machine() or "unknown"

    findings.append(
        Finding(
            check_id=CHECK_ID,
            title="System information collected",
            severity="info",
            status="info",
            category="system",
            evidence=f"host={host}, distro={distro}, kernel={kernel}, arch={arch}",
            remediation="Use this inventory as baseline metadata for audit evidence.",
            points=0,
        )
    )

    kernel_major = _major_from_kernel(kernel)
    if kernel_major is not None and kernel_major < 5:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Legacy Linux kernel branch detected",
                severity="medium",
                status="warn",
                category="system",
                evidence=f"Running kernel: {kernel}",
                remediation="Plan upgrade to a currently supported kernel from your distribution.",
                points=8,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Linux kernel branch appears modern",
                severity="info",
                status="pass",
                category="system",
                evidence=f"Running kernel: {kernel}",
                remediation="Maintain regular kernel and security update cadence.",
                points=0,
            )
        )

    uptime = run_command(["uptime", "-p"])
    if uptime.returncode == 0 and uptime.stdout:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="System uptime captured",
                severity="info",
                status="info",
                category="system",
                evidence=uptime.stdout,
                remediation="Correlate long uptimes with patching and reboot strategy.",
                points=0,
            )
        )

    return findings


def _major_from_kernel(kernel: str) -> int | None:
    first = kernel.split(".", 1)[0]
    if first.isdigit():
        return int(first)
    return None
