"""Batch URL scanner — fetch and rank CSP weaknesses across multiple targets."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass

from .analyzer import analyze, score_policy
from .bypass import find_bypasses
from .fetcher import FetchResult, fetch_csp
from .models import Policy, Severity


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    has_csp: bool
    grade: str
    score: int
    num_findings: int
    num_bypasses: int
    num_critical: int
    num_high: int
    num_medium: int
    policy_mode: str  # "enforced", "report-only", "none"
    csp_raw: str
    error: str | None = None


def scan_url(url: str, *, timeout: float = 10.0, verify_ssl: bool = True) -> ScanResult:
    """Scan a single URL and return a summary result."""
    try:
        result = fetch_csp(url, timeout=timeout, verify_ssl=verify_ssl)
    except Exception as e:
        return ScanResult(
            url=url, final_url=url, status_code=0, has_csp=False,
            grade="?", score=0, num_findings=0, num_bypasses=0,
            num_critical=0, num_high=0, num_medium=0,
            policy_mode="error", csp_raw="", error=str(e),
        )

    if not result.policies:
        return ScanResult(
            url=url, final_url=result.final_url, status_code=result.status_code,
            has_csp=False, grade="-", score=0, num_findings=0, num_bypasses=0,
            num_critical=0, num_high=0, num_medium=0,
            policy_mode="none", csp_raw="",
        )

    # Use the first enforced policy, or first report-only if no enforced
    enforced = [p for p in result.policies if not p.report_only]
    policy = enforced[0] if enforced else result.policies[0]
    mode = "enforced" if not policy.report_only else "report-only"

    findings = analyze(policy)
    bypasses = find_bypasses(policy)
    grade, score = score_policy(policy)

    return ScanResult(
        url=url,
        final_url=result.final_url,
        status_code=result.status_code,
        has_csp=True,
        grade=grade,
        score=score,
        num_findings=len(findings),
        num_bypasses=len(bypasses),
        num_critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        num_high=sum(1 for f in findings if f.severity == Severity.HIGH),
        num_medium=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        policy_mode=mode,
        csp_raw=str(policy),
    )


def scan_urls(
    urls: list[str],
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> list[ScanResult]:
    """Scan multiple URLs and return results sorted by weakness (worst first)."""
    results = []
    for url in urls:
        results.append(scan_url(url, timeout=timeout, verify_ssl=verify_ssl))

    # Sort: errors last, then no-CSP, then by score ascending (weakest first)
    def sort_key(r: ScanResult) -> tuple:
        if r.error:
            return (2, 0, r.url)
        if not r.has_csp:
            return (1, 0, r.url)
        return (0, r.score, r.url)

    results.sort(key=sort_key)
    return results


def results_to_csv(results: list[ScanResult]) -> str:
    """Export scan results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "url", "grade", "score", "findings", "bypasses",
        "critical", "high", "medium", "mode", "error",
    ])
    for r in results:
        writer.writerow([
            r.url, r.grade, r.score, r.num_findings, r.num_bypasses,
            r.num_critical, r.num_high, r.num_medium, r.policy_mode,
            r.error or "",
        ])
    return output.getvalue()


def results_to_json(results: list[ScanResult]) -> str:
    """Export scan results as JSON."""
    return json.dumps(
        [
            {
                "url": r.url,
                "final_url": r.final_url,
                "status_code": r.status_code,
                "has_csp": r.has_csp,
                "grade": r.grade,
                "score": r.score,
                "findings": r.num_findings,
                "bypasses": r.num_bypasses,
                "critical": r.num_critical,
                "high": r.num_high,
                "medium": r.num_medium,
                "mode": r.policy_mode,
                "csp": r.csp_raw,
                "error": r.error,
            }
            for r in results
        ],
        indent=2,
    )
