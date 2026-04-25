from __future__ import annotations

from typing import TypedDict

from ironaudit.models import Finding
from ironaudit.utils import run_command

CHECK_ID = "services"
SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    111: "RPCBind",
    139: "NetBIOS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


class Listener(TypedDict):
    addr: str
    port: int


def run() -> list[Finding]:
    result = run_command(["ss", "-lntup"])
    if result.returncode != 0:
        return [
            Finding(
                check_id=CHECK_ID,
                title="Unable to enumerate listening services",
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

    findings: list[Finding] = [
        Finding(
            check_id=CHECK_ID,
            title="Listening services inventory",
            severity="info",
            status="info",
            category="network",
            evidence=f"Detected {len(listeners)} listeners, {len(exposed)} exposed",
            remediation="Keep service inventory minimal and reviewed.",
            points=0,
        )
    ]

    if len(exposed) >= 5:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Multiple network services exposed",
                severity="medium",
                status="warn",
                category="network",
                evidence=f"{len(exposed)} non-loopback listeners detected",
                remediation="Disable unnecessary services and restrict inbound access.",
                points=10,
            )
        )
    elif len(exposed) == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="No externally exposed listening services",
                severity="info",
                status="pass",
                category="network",
                evidence="All listeners are loopback-bound or none detected",
                remediation="Maintain this principle-of-least-exposure posture.",
                points=0,
            )
        )

    sensitive_hits = [item for item in exposed if item["port"] in SENSITIVE_PORTS]
    if sensitive_hits:
        labels = ", ".join(
            f"{entry['port']}({SENSITIVE_PORTS[entry['port']]})" for entry in sensitive_hits[:8]
        )
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Sensitive network ports exposed",
                severity="high",
                status="warn",
                category="network",
                evidence=f"Sensitive exposed ports: {labels}",
                remediation="Bind services to trusted interfaces and enforce strict firewall ACLs.",
                points=12,
            )
        )

    return findings


def _parse_listeners(output: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in output.splitlines():
        if not line or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue

        local = parts[4]
        if ":" not in local:
            continue
        addr, port_raw = local.rsplit(":", 1)
        addr = addr.strip("[]")
        if not port_raw.isdigit():
            continue
        listeners.append({"addr": addr, "port": int(port_raw)})
    return listeners
