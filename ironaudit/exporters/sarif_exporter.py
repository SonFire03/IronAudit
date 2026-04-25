from __future__ import annotations

import json
import re
from collections import OrderedDict

from ironaudit import __version__
from ironaudit.models import Finding, ScanReport


def to_sarif(report: ScanReport, pretty: bool = True) -> str:
    rules: OrderedDict[str, dict[str, object]] = OrderedDict()
    results: list[dict[str, object]] = []

    for finding in report.findings:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {
                    "text": f"{finding.title}. Category: {finding.category}. Status: {finding.status}."
                },
                "defaultConfiguration": {"level": _sarif_level(finding)},
                "properties": {
                    "check_id": finding.check_id,
                    "category": finding.category,
                    "severity": finding.severity,
                },
            }

        message = (
            f"{finding.title}. "
            f"Evidence: {finding.evidence}. "
            f"Remediation: {finding.remediation}"
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding),
                "message": {"text": message},
                "properties": {
                    "status": finding.status,
                    "severity": finding.severity,
                    "category": finding.category,
                    "points": finding.points,
                    "check_id": finding.check_id,
                },
            }
        )

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "IronAudit",
                        "version": __version__,
                        "informationUri": "https://github.com/SonFire03/IronAudit",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {
                    "id": f"ironaudit/{report.metadata.hostname}/{report.metadata.scanned_at}"
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "score": report.score,
                            "rating": report.rating,
                            "hostname": report.metadata.hostname,
                            "distro": report.metadata.distro,
                            "scan_profile": report.metadata.scan_profile,
                            "duration_seconds": report.metadata.duration_seconds,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }

    if pretty:
        return json.dumps(payload, indent=2)
    return json.dumps(payload)


def _rule_id(finding: Finding) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    if not slug:
        slug = "finding"
    return f"{finding.check_id}.{slug}"


def _sarif_level(finding: Finding) -> str:
    if finding.status == "fail":
        if finding.severity in {"critical", "high"}:
            return "error"
        if finding.severity == "medium":
            return "warning"
        return "note"
    if finding.status == "warn":
        return "warning"
    return "note"
