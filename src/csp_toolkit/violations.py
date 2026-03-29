"""Parse and summarize CSP violation reports (e.g. ``report-uri`` JSON)."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any


def parse_violations_json(text: str) -> list[dict[str, Any]]:
    """Parse JSON containing one or more CSP reports.

    Accepts a single object, an array, or objects wrapped in ``csp-report`` (reporting API shape).
    """
    data = json.loads(text)
    items: list[Any]
    if isinstance(data, list):
        items = data
    else:
        items = [data]
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and "csp-report" in item:
            inner = item["csp-report"]
            if isinstance(inner, dict):
                out.append(inner)
        elif isinstance(item, dict):
            out.append(item)
    return out


def group_violations(
    violations: list[dict[str, Any]],
) -> list[tuple[tuple[str, str, str], int]]:
    """Group by (blocked-uri, effective-directive, violated-directive) with counts."""
    keys: list[tuple[str, str, str]] = []
    for v in violations:
        bu = str(v.get("blocked-uri") or v.get("blocked_uri") or "")
        ed = str(v.get("effective-directive") or v.get("effective_directive") or "")
        vd = str(v.get("violated-directive") or v.get("violated_directive") or "")
        keys.append((bu, ed, vd))
    return Counter(keys).most_common()


def violations_summary_json(violations: list[dict[str, Any]]) -> dict[str, Any]:
    """Structured summary for JSON output."""
    grouped = group_violations(violations)
    return {
        "count": len(violations),
        "groups": [
            {"blocked_uri": bu, "effective_directive": ed, "violated_directive": vd, "count": c}
            for (bu, ed, vd), c in grouped
        ],
    }
