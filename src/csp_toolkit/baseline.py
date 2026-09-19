"""Baseline ratcheting — gate on getting *worse*, not on an absolute threshold.

An absolute gate (``--fail-on high``) only works once a policy is already good.
A policy that grades D fails on day one and keeps failing, so the check gets
removed. A baseline records the findings a policy has today; later runs fail only
on findings that are not in it. That makes the gate adoptable at any starting
quality, and lets remediation proceed on its own schedule.

The stored key is :attr:`csp_toolkit.models.Finding.fingerprint`, which is derived
from the check id rather than the message text, so rewording a finding does not
silently invalidate a committed baseline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import analyze, score_policy
from .models import Finding, Policy, Severity

SCHEMA = "csp-toolkit-baseline-v1"

#: Key used for a baseline entry that came from a policy string or file rather
#: than a URL, so `analyze` and `fetch` can share one baseline file.
POLICY_KEY = "policy"

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class BaselineError(Exception):
    """Raised when a baseline file is missing, unreadable, or the wrong shape."""


@dataclass
class BaselineEntry:
    """The recorded state of one target (a URL, or the policy key)."""

    grade: str
    score: int
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"grade": self.grade, "score": self.score, "findings": self.findings}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BaselineEntry:
        return cls(
            grade=str(d.get("grade", "")),
            score=int(d.get("score", 0)),
            findings=dict(d.get("findings", {})),
        )


@dataclass
class Baseline:
    created: str = ""
    updated: str = ""
    targets: dict[str, BaselineEntry] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "created": self.created,
            "updated": self.updated,
            "targets": {k: v.to_dict() for k, v in self.targets.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Baseline:
        schema = d.get("schema")
        if schema != SCHEMA:
            raise BaselineError(
                f"unrecognized baseline schema {schema!r} (expected {SCHEMA!r}); "
                "regenerate it with --update-baseline"
            )
        targets = d.get("targets")
        if not isinstance(targets, dict):
            raise BaselineError("baseline file has no 'targets' object")
        return cls(
            created=str(d.get("created", "")),
            updated=str(d.get("updated", "")),
            targets={k: BaselineEntry.from_dict(v) for k, v in targets.items()},
        )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def finding_record(finding: Finding) -> dict[str, Any]:
    """The human-readable context stored alongside a fingerprint.

    Only the fingerprint is used for comparison; these fields exist so a
    committed baseline is reviewable in a pull request rather than a wall of
    opaque hashes.
    """
    return {
        "check_id": finding.check_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "directive": finding.directive,
        "subject": finding.subject,
    }


def entry_for_policy(policy: Policy) -> BaselineEntry:
    """Snapshot a policy's current findings and grade."""
    grade, score = score_policy(policy)
    return BaselineEntry(
        grade=grade,
        score=score,
        findings={f.fingerprint: finding_record(f) for f in analyze(policy)},
    )


def load(path: str | Path) -> Baseline:
    p = Path(path)
    if not p.exists():
        raise BaselineError(f"baseline file not found: {p} — create it with --update-baseline")
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"baseline file {p} must contain a JSON object")
    return Baseline.from_dict(data)


def save(baseline: Baseline, path: str | Path) -> None:
    p = Path(path)
    now = _now()
    if not baseline.created:
        baseline.created = now
    baseline.updated = now
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(baseline.to_dict(), indent=2) + "\n")


def update(path: str | Path, key: str, policy: Policy) -> Baseline:
    """Record (or re-record) one target in a baseline file, preserving the others."""
    p = Path(path)
    baseline = load(p) if p.exists() else Baseline()
    baseline.targets[key] = entry_for_policy(policy)
    save(baseline, p)
    return baseline


@dataclass
class Comparison:
    """The result of checking a policy against its recorded baseline."""

    key: str
    new_findings: list[Finding] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    grade_before: str = ""
    grade_after: str = ""
    score_before: int = 0
    score_after: int = 0
    #: True when the target has no entry in the baseline at all.
    untracked: bool = False

    @property
    def score_delta(self) -> int:
        return self.score_after - self.score_before

    def regressions(self, threshold: Severity | None) -> list[Finding]:
        """New findings at or above `threshold` (all of them when None)."""
        if threshold is None:
            return list(self.new_findings)
        limit = _SEVERITY_ORDER[threshold]
        return [f for f in self.new_findings if _SEVERITY_ORDER[f.severity] <= limit]


def compare(policy: Policy, baseline: Baseline, key: str) -> Comparison:
    """Compare a policy's findings against the baseline entry for `key`."""
    findings = analyze(policy)
    grade, score = score_policy(policy)
    entry = baseline.targets.get(key)

    if entry is None:
        # Nothing recorded for this target. Report it rather than inventing an
        # empty baseline, which would make every existing finding a regression.
        return Comparison(
            key=key,
            new_findings=[],
            unchanged=list(findings),
            grade_after=grade,
            score_after=score,
            untracked=True,
        )

    known = set(entry.findings)
    seen = {f.fingerprint for f in findings}
    return Comparison(
        key=key,
        new_findings=[f for f in findings if f.fingerprint not in known],
        resolved=[rec for fp, rec in entry.findings.items() if fp not in seen],
        unchanged=[f for f in findings if f.fingerprint in known],
        grade_before=entry.grade,
        grade_after=grade,
        score_before=entry.score,
        score_after=score,
    )
