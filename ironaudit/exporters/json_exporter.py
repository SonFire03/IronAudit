from __future__ import annotations

import json

from ironaudit.models import ScanReport


def to_json(report: ScanReport, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    return json.dumps(report.to_dict())
