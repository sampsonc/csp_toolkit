"""Stable JSON and SARIF exports for findings (analyze / bypass)."""

from __future__ import annotations

import json

from .models import Finding, Severity, _slug
from ._version import __version__


def _severity_to_sarif_level(sev: Severity) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def _security_severity(sev: Severity) -> str:
    """Numeric severity GitHub code scanning uses to rank alerts."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]


def format_findings_stable_json(findings: list[Finding], *, tool: str = "csp_analyze") -> str:
    """Stable json-v1 document for tooling."""
    doc = {
        "schema_version": "1.1",
        "tool": tool,
        "findings": [
            {
                # Stable across runs, unlike the random uuid emitted before 1.1 —
                # baselines and alert dedupe need an id that survives a re-run.
                "id": f.fingerprint,
                "check_id": f.check_id,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "directive": f.directive,
                "subject": f.subject,
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
    rules: dict[str, dict] = {}
    for f in findings:
        # A prose title as ruleId makes GitHub treat a reworded message as a new
        # alert, so the stable check id is the rule and the title is its name.
        rule_id = f.check_id or _slug(f.title)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": (f.title or "finding").replace("\n", " ")[:256]},
                "defaultConfiguration": {"level": _severity_to_sarif_level(f.severity)},
                "properties": {"security-severity": _security_severity(f.severity)},
            },
        )
        result = {
            "ruleId": rule_id,
            "message": {"text": f.description},
            "level": _severity_to_sarif_level(f.severity),
            "partialFingerprints": {"cspToolkitFindingV1": f.fingerprint},
        }
        if f.directive or f.subject:
            result["properties"] = {
                k: v for k, v in (("directive", f.directive), ("subject", f.subject)) if v
            }
        results.append(result)
    run = {
        "tool": {
            "driver": {
                "name": "csp-toolkit",
                "semanticVersion": __version__,
                "informationUri": "https://github.com/sampsonc/csp_toolkit",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    log = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    }
    return json.dumps(log, indent=2)
