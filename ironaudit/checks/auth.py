from __future__ import annotations

from ironaudit.models import Finding
from ironaudit.utils import run_command, safe_read_text

CHECK_ID = "auth"


def run() -> list[Finding]:
    findings: list[Finding] = []

    fail2ban_result = _check_fail2ban()
    findings.append(fail2ban_result)

    findings.extend(_check_pam_basics())
    return findings


def _check_fail2ban() -> Finding:
    systemctl = run_command(["systemctl", "is-enabled", "fail2ban"])
    if systemctl.returncode == 0 and "enabled" in systemctl.stdout:
        return Finding(
            check_id=CHECK_ID,
            title="fail2ban is enabled",
            severity="info",
            status="pass",
            category="authentication",
            evidence="systemctl reports fail2ban enabled",
            remediation="Keep fail2ban jail policies reviewed.",
            points=0,
        )

    client = run_command(["fail2ban-client", "status"])
    if client.returncode == 0:
        return Finding(
            check_id=CHECK_ID,
            title="fail2ban present",
            severity="info",
            status="pass",
            category="authentication",
            evidence="fail2ban-client status succeeded",
            remediation="Ensure service is enabled at boot.",
            points=0,
        )

    return Finding(
        check_id=CHECK_ID,
        title="fail2ban not detected",
        severity="low",
        status="warn",
        category="authentication",
        evidence=systemctl.stderr or client.stderr or "No fail2ban signal found",
        remediation="Install and configure fail2ban for brute-force mitigation.",
        points=5,
    )


def _check_pam_basics() -> list[Finding]:
    findings: list[Finding] = []

    common_auth = safe_read_text("/etc/pam.d/common-auth")
    common_password = safe_read_text("/etc/pam.d/common-password")
    if common_auth is None and common_password is None:
        return [
            Finding(
                check_id=CHECK_ID,
                title="PAM baseline checks unsupported",
                severity="info",
                status="unsupported",
                category="authentication",
                evidence="Debian-like PAM files not present",
                remediation="Validate equivalent PAM policies for your distribution.",
                points=0,
            )
        ]

    auth_text = common_auth or ""
    pass_text = common_password or ""

    has_faillock = "pam_faillock.so" in auth_text
    has_pwquality = "pam_pwquality.so" in pass_text

    if has_faillock:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="PAM faillock policy present",
                severity="info",
                status="pass",
                category="authentication",
                evidence="pam_faillock.so found in /etc/pam.d/common-auth",
                remediation="Keep lockout thresholds tuned for your risk model.",
                points=0,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="PAM faillock policy not detected",
                severity="medium",
                status="warn",
                category="authentication",
                evidence="pam_faillock.so missing from /etc/pam.d/common-auth",
                remediation="Enable PAM account lockout controls with pam_faillock.",
                points=8,
            )
        )

    if has_pwquality:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="PAM password quality policy present",
                severity="info",
                status="pass",
                category="authentication",
                evidence="pam_pwquality.so found in /etc/pam.d/common-password",
                remediation="Maintain password complexity and policy review.",
                points=0,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="PAM password quality policy not detected",
                severity="medium",
                status="warn",
                category="authentication",
                evidence="pam_pwquality.so missing from /etc/pam.d/common-password",
                remediation="Add pam_pwquality policy to strengthen password controls.",
                points=8,
            )
        )

    return findings
