"""Stable JSON and SARIF exports for findings (analyze / bypass)."""

from __future__ import annotations

import json
import uuid

from .models import Finding, Severity
from ._version import __version__


def _severity_to_sarif_level(sev: Severity) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def format_findings_stable_json(findings: list[Finding], *, tool: str = "csp_analyze") -> str:
    """Stable json-v1 document for tooling."""
    doc = {
        "schema_version": "1.0",
        "tool": tool,
        "findings": [
            {
                "id": str(uuid.uuid4()),
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "directive": f.directive,
                "bypass_type": f.bypass_type,
                "references": f.references,
            }
            for f in findings
        ],
    }
    return json.dumps(doc, indent=2)


def format_findings_sarif_json(findings: list[Finding]) -> str:
    """SARIF 2.1.0 log with one run and one result per finding."""
    results = []
    for f in findings:
        rule_id = (f.title or "finding").replace("\n", " ")[:128]
        results.append(
            {
                "ruleId": rule_id,
                "message": {"text": f.description},
                "level": _severity_to_sarif_level(f.severity),
            }
        )
    run = {
        "tool": {"driver": {"name": "csp-toolkit", "semanticVersion": __version__}},
        "results": results,
    }
    log = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    }
    return json.dumps(log, indent=2)
