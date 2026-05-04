from __future__ import annotations

from ironaudit.models import Finding
from ironaudit.utils import run_command

CHECK_ID = "enabled_services"
RISKY_SERVICE_NAMES = {
    "telnet",
    "vsftpd",
    "proftpd",
    "rsh",
    "rlogin",
    "rexec",
    "xinetd",
}


def run() -> list[Finding]:
    result = run_command(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"])
    if result.returncode != 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to enumerate enabled services",
                severity="low",
                status="info",
                category="services",
                evidence=result.stderr or "systemctl command unavailable",
                remediation="Run on a systemd host or collect enabled services manually.",
                points=0,
            )
        ]

    services = _extract_services(result.stdout)
    risky = [svc for svc in services if any(flag in svc for flag in RISKY_SERVICE_NAMES)]

    findings = [
        Finding(
            check_id=CHECK_ID,
            title="Enabled services inventory",
            severity="info",
            status="info",
            category="services",
            evidence=f"{len(services)} enabled services detected. Sample: {', '.join(services[:8])}",
            remediation="Keep startup services minimal and aligned with system role.",
            points=0,
        )
    ]

    if len(services) >= 80:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Large enabled service footprint",
                severity="medium",
                status="warn",
                category="services",
                evidence=f"{len(services)} services enabled at boot",
                remediation="Disable unnecessary services to reduce attack surface.",
                points=8,
            )
        )

    if risky:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Potentially risky legacy services enabled",
                severity="high",
                status="fail",
                category="services",
                evidence=f"Enabled legacy services: {', '.join(risky[:8])}",
                remediation="Disable or replace legacy remote services with hardened alternatives.",
                points=15,
            )
        )

    return findings


def _extract_services(output: str) -> list[str]:
    names: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        name = line.split()[0]
        if name.endswith(".service"):
            names.append(name)
    return names
