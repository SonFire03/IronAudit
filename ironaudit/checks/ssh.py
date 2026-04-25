from __future__ import annotations

from pathlib import Path

from ironaudit.models import Finding
from ironaudit.utils import parse_ssh_directives, run_command, safe_read_text

CHECK_ID = "ssh"


def run() -> list[Finding]:
    findings: list[Finding] = []
    config_path = Path("/etc/ssh/sshd_config")
    if not config_path.exists():
        return [
            Finding(
                check_id=CHECK_ID,
                title="SSH configuration file missing",
                severity="medium",
                status="warn",
                category="ssh",
                evidence="/etc/ssh/sshd_config not found",
                remediation="Install and configure OpenSSH server only if needed.",
                points=8,
            )
        ]

    text = safe_read_text(config_path) or ""
    directives = parse_ssh_directives(text)

    permit_root_login = directives.get("permitrootlogin", "prohibit-password").lower()
    if permit_root_login in {"yes", "without-password"}:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="SSH root login is enabled",
                severity="high",
                status="fail",
                category="ssh",
                evidence=f"PermitRootLogin {permit_root_login}",
                remediation="Set `PermitRootLogin no` and reload sshd.",
                points=20,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="SSH root login disabled",
                severity="info",
                status="pass",
                category="ssh",
                evidence=f"PermitRootLogin {permit_root_login}",
                remediation="Keep root login disabled for SSH.",
                points=0,
            )
        )

    password_auth = directives.get("passwordauthentication", "yes").lower()
    if password_auth == "yes":
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="SSH password authentication enabled",
                severity="high",
                status="fail",
                category="ssh",
                evidence=f"PasswordAuthentication {password_auth}",
                remediation="Set `PasswordAuthentication no` and use SSH keys.",
                points=15,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="SSH password authentication disabled",
                severity="info",
                status="pass",
                category="ssh",
                evidence=f"PasswordAuthentication {password_auth}",
                remediation="Keep password auth disabled for remote SSH.",
                points=0,
            )
        )

    socket_findings = _ssh_socket_finding(directives)
    findings.extend(socket_findings)
    return findings


def _ssh_socket_finding(directives: dict[str, str]) -> list[Finding]:
    result = run_command(["ss", "-ltn"])
    if result.returncode != 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to determine SSH listening state",
                severity="low",
                status="info",
                category="ssh",
                evidence=result.stderr or "ss command unavailable",
                remediation="Install iproute2 (`ss`) or manually verify sshd socket exposure.",
                points=0,
            )
        ]

    configured_port = directives.get("port", "22")
    open_ports = _extract_listen_ports(result.stdout)
    target_port = int(configured_port) if configured_port.isdigit() else 22
    is_listening = target_port in open_ports

    if is_listening:
        return [
            Finding(
                check_id=CHECK_ID,
                title="SSH service is listening",
                severity="low",
                status="warn",
                category="ssh",
                evidence=f"TCP port {target_port} is listening",
                remediation="Ensure firewall rules restrict SSH access to trusted sources.",
                points=2,
            )
        ]
    return [
        Finding(
            check_id=CHECK_ID,
            title="SSH service is not listening",
            severity="info",
            status="pass",
            category="ssh",
            evidence=f"No listener on configured SSH port {target_port}",
            remediation="No action required if SSH access is not needed.",
            points=0,
        )
    ]


def _extract_listen_ports(output: str) -> set[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr = parts[3]
        if ":" not in local_addr:
            continue
        maybe_port = local_addr.rsplit(":", 1)[-1]
        if maybe_port.isdigit():
            ports.add(int(maybe_port))
    return ports
