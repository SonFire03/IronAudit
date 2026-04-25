from __future__ import annotations

import os
from pathlib import Path

from ironaudit.models import Finding

CHECK_ID = "permissions"
WORLD_WRITABLE_PATHS = ["/etc", "/usr/local/bin", "/opt", "/var/www"]
SUID_SCAN_PATHS = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/opt", "/tmp", "/var/tmp"]
MAX_WORLD_WRITABLE_HITS = 40
MAX_SUID_HITS = 60


def run() -> list[Finding]:
    world_writable = _find_world_writable()
    suid_sgid = _find_suid_sgid()

    findings: list[Finding] = []

    if world_writable:
        sample = ", ".join(world_writable[:5])
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="Sensitive world-writable paths found",
                severity="high",
                status="fail",
                category="filesystem",
                evidence=f"Found {len(world_writable)} world-writable entries. Sample: {sample}",
                remediation="Remove world-writable bits from sensitive paths (chmod o-w).",
                points=15,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="No world-writable entries in sensitive paths",
                severity="info",
                status="pass",
                category="filesystem",
                evidence=f"Scanned: {', '.join(WORLD_WRITABLE_PATHS)}",
                remediation="Continue monitoring write permissions in critical paths.",
                points=0,
            )
        )

    if suid_sgid:
        suspicious = [p for p in suid_sgid if p.startswith("/tmp") or p.startswith("/var/tmp") or p.startswith("/opt")]
        if suspicious:
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    title="Potentially risky SUID/SGID binaries in unusual paths",
                    severity="high",
                    status="warn",
                    category="filesystem",
                    evidence=f"Suspicious SUID/SGID entries: {', '.join(suspicious[:8])}",
                    remediation="Review ownership and necessity of SUID/SGID binaries in custom paths.",
                    points=12,
                )
            )

        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="SUID/SGID inventory",
                severity="info",
                status="info",
                category="filesystem",
                evidence=f"Detected {len(suid_sgid)} SUID/SGID entries. Sample: {', '.join(suid_sgid[:6])}",
                remediation="Audit SUID/SGID binaries periodically and remove unnecessary bits.",
                points=0,
            )
        )
    else:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                title="No SUID/SGID entries discovered in scanned paths",
                severity="info",
                status="info",
                category="filesystem",
                evidence=f"Scanned: {', '.join(SUID_SCAN_PATHS)}",
                remediation="If this is unexpected, run a full privileged filesystem inventory.",
                points=0,
            )
        )

    return findings


def _find_world_writable() -> list[str]:
    hits: list[str] = []
    for base in WORLD_WRITABLE_PATHS:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for root, dirs, files in os.walk(base, topdown=True):
            entries = dirs + files
            for name in entries:
                full_path = Path(root) / name
                try:
                    mode = full_path.stat(follow_symlinks=False).st_mode
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                if mode & 0o002:
                    hits.append(str(full_path))
                    if len(hits) >= MAX_WORLD_WRITABLE_HITS:
                        return hits
    return hits


def _find_suid_sgid() -> list[str]:
    hits: list[str] = []
    for base in SUID_SCAN_PATHS:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for root, _, files in os.walk(base, topdown=True):
            for name in files:
                full_path = Path(root) / name
                try:
                    mode = full_path.stat(follow_symlinks=False).st_mode
                except (PermissionError, FileNotFoundError, OSError):
                    continue
                if mode & 0o6000:
                    hits.append(str(full_path))
                    if len(hits) >= MAX_SUID_HITS:
                        return hits
    return hits
