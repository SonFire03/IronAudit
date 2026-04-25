from __future__ import annotations

from ironaudit.models import Finding
from ironaudit.utils import run_command

CHECK_ID = "firewall"


def run() -> list[Finding]:
    ufw = _check_ufw()
    if ufw is not None:
        return [ufw]

    nft = _check_nftables()
    if nft is not None:
        return [nft]

    iptables = _check_iptables()
    if iptables is not None:
        return [iptables]

    return [
        Finding(
            check_id=CHECK_ID,
            title="No active firewall detected",
            severity="high",
            status="fail",
            category="firewall",
            evidence="ufw/nftables/iptables not active or unavailable",
            remediation="Enable a host firewall (ufw, nftables, or iptables policy).",
            points=20,
        )
    ]


def _check_ufw() -> Finding | None:
    result = run_command(["ufw", "status"])
    if result.returncode == 127:
        return None
    if "Status: active" in result.stdout:
        return Finding(
            check_id=CHECK_ID,
            title="UFW firewall is active",
            severity="info",
            status="pass",
            category="firewall",
            evidence="ufw status reports active",
            remediation="Maintain least-privilege inbound rules.",
            points=0,
        )
    return Finding(
        check_id=CHECK_ID,
        title="UFW installed but inactive",
        severity="high",
        status="fail",
        category="firewall",
        evidence=result.stdout or result.stderr or "ufw inactive",
        remediation="Enable UFW with a deny-by-default inbound policy.",
        points=20,
    )


def _check_nftables() -> Finding | None:
    result = run_command(["nft", "list", "ruleset"])
    if result.returncode == 127:
        return None
    if result.returncode == 0 and result.stdout.strip() and "table" in result.stdout:
        return Finding(
            check_id=CHECK_ID,
            title="nftables ruleset present",
            severity="info",
            status="pass",
            category="firewall",
            evidence="nft list ruleset returned at least one table",
            remediation="Review nftables policy regularly.",
            points=0,
        )
    return Finding(
        check_id=CHECK_ID,
        title="nftables available but no active ruleset",
        severity="high",
        status="fail",
        category="firewall",
        evidence=result.stderr or "Empty or inaccessible nftables ruleset",
        remediation="Define and load nftables rules before exposing services.",
        points=20,
    )


def _check_iptables() -> Finding | None:
    result = run_command(["iptables", "-L"])
    if result.returncode == 127:
        return None
    if result.returncode == 0 and "Chain" in result.stdout:
        return Finding(
            check_id=CHECK_ID,
            title="iptables rules detected",
            severity="info",
            status="pass",
            category="firewall",
            evidence="iptables -L returned chain definitions",
            remediation="Ensure rules are persisted and least-privilege.",
            points=0,
        )
    return Finding(
        check_id=CHECK_ID,
        title="iptables unavailable or inaccessible",
        severity="medium",
        status="warn",
        category="firewall",
        evidence=result.stderr or "iptables command failed",
        remediation="Validate firewall backend and permissions.",
        points=10,
    )
