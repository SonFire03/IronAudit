from __future__ import annotations

from pathlib import Path
from typing import TypedDict

from ironaudit.models import Finding
from ironaudit.utils import safe_read_text

CHECK_ID = "users"


NON_INTERACTIVE_SHELL_HINTS = {"nologin", "false", "sync", "halt", "shutdown"}


class PasswdRecord(TypedDict):
    user: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


def run() -> list[Finding]:
    passwd_text = safe_read_text("/etc/passwd")
    if passwd_text is None:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to read /etc/passwd",
                severity="medium",
                status="unsupported",
                category="identity",
                evidence="/etc/passwd unavailable",
                remediation="Verify local filesystem permissions and Linux environment.",
                points=0,
            )
        ]

    records = _parse_passwd(passwd_text)
    interactive = [r["user"] for r in records if _is_interactive(r["shell"])]
    uid0_accounts = [r["user"] for r in records if int(r["uid"]) == 0]
    unexpected_uid0 = [u for u in uid0_accounts if u != "root"]

    findings: list[Finding] = [
        Finding(
            check_id=CHECK_ID,
            title="Interactive account inventory",
            severity="info",
            status="info",
            category="identity",
            evidence=f"Interactive users: {', '.join(interactive) if interactive else 'none'}",
            remediation="Review interactive accounts and disable stale identities.",
            points=0,
        )
    ]

    if unexpected_uid0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Unexpected UID 0 account detected",
                severity="critical",
                status="fail",
                category="identity",
                evidence=f"UID 0 accounts: {', '.join(unexpected_uid0)}",
                remediation="Remove UID 0 from non-root accounts and review escalation paths.",
                points=25,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="No unexpected UID 0 accounts",
                severity="info",
                status="pass",
                category="identity",
                evidence="Only root has UID 0",
                remediation="Keep UID 0 restricted to root.",
                points=0,
            )
        )

    sudo_members = _sudo_or_wheel_members()
    findings.append(
        Finding(
            check_id=CHECK_ID,
            title="Privileged group membership",
            severity="info",
            status="info",
            category="identity",
            evidence=(
                f"sudo/wheel members: {', '.join(sudo_members)}"
                if sudo_members
                else "No direct sudo/wheel members found in /etc/group"
            ),
            remediation="Limit privileged groups to required administrators.",
            points=0,
        )
    )

    return findings


def _parse_passwd(text: str) -> list[PasswdRecord]:
    records: list[PasswdRecord] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, gecos, home, shell = parts[:7]
        if not uid.isdigit() or not gid.isdigit():
            continue
        records.append(
            {
                "user": user,
                "uid": int(uid),
                "gid": int(gid),
                "gecos": gecos,
                "home": home,
                "shell": shell,
            }
        )
    return records


def _is_interactive(shell: str) -> bool:
    shell_name = Path(shell).name.lower()
    return shell_name not in NON_INTERACTIVE_SHELL_HINTS


def _sudo_or_wheel_members() -> list[str]:
    group_text = safe_read_text("/etc/group")
    if not group_text:
        return []

    members: set[str] = set()
    for line in group_text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        group_name = parts[0]
        if group_name not in {"sudo", "wheel"}:
            continue
        listed = [item.strip() for item in parts[3].split(",") if item.strip()]
        members.update(listed)
    return sorted(members)
