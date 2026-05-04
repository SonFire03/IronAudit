from __future__ import annotations

from typing import TypedDict

from ironaudit.models import Finding
from ironaudit.utils import run_command

CHECK_ID = "ports"


class Listener(TypedDict):
    addr: str
    port: int


def run() -> list[Finding]:
    result = run_command(["ss", "-lnt"])
    if result.returncode != 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to enumerate listening TCP ports",
                severity="low",
                status="info",
                category="network",
                evidence=result.stderr or "ss command unavailable",
                remediation="Install iproute2 and re-run the audit.",
                points=0,
            )
        ]

    listeners = _parse_listeners(result.stdout)
    exposed = [item for item in listeners if item["addr"] not in {"127.0.0.1", "::1", "localhost"}]

    findings = [
        Finding(
            check_id=CHECK_ID,
            title="Open listening TCP ports inventory",
            severity="info",
            status="info",
            category="network",
            evidence=f"Detected {len(listeners)} listeners, {len(exposed)} externally reachable",
            remediation="Keep externally reachable ports to a strict minimum.",
            points=0,
        )
    ]

    if len(exposed) >= 10:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="High number of externally reachable TCP listeners",
                severity="high",
                status="warn",
                category="network",
                evidence=f"{len(exposed)} external listeners detected",
                remediation="Reduce attack surface and block unnecessary ports using host firewall policy.",
                points=15,
            )
        )
    elif len(exposed) >= 5:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Multiple externally reachable TCP listeners",
                severity="medium",
                status="warn",
                category="network",
                evidence=f"{len(exposed)} external listeners detected",
                remediation="Review each open service for business need and network restriction.",
                points=8,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Limited externally reachable TCP listeners",
                severity="info",
                status="pass",
                category="network",
                evidence=f"{len(exposed)} external listeners detected",
                remediation="Maintain least-exposure posture for network services.",
                points=0,
            )
        )

    return findings


def _parse_listeners(output: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in output.splitlines():
        if not line or line.startswith("State") or line.startswith("Recv-Q"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue

        local = parts[3]
        if ":" not in local:
            continue
        addr, port_raw = local.rsplit(":", 1)
        addr = addr.strip("[]")
        if not port_raw.isdigit():
            continue
        listeners.append({"addr": addr, "port": int(port_raw)})
    return listeners
