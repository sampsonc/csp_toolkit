"""Active probes — nonce reuse detection, header injection, report-uri analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .models import Finding, Policy, Severity
from .parser import parse


@dataclass
class NonceReuseResult:
    url: str
    nonces_found: list[str]
    is_static: bool  # True = same nonce every time = vulnerable
    num_requests: int
    directive: str  # Which directive the nonces came from


def detect_nonce_reuse(
    url: str,
    *,
    num_requests: int = 5,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> NonceReuseResult | None:
    """Fetch a URL multiple times and check if the CSP nonce changes.

    A static nonce completely defeats nonce-based CSP protection.
    Returns None if no nonces are found in the CSP.
    """
    nonces: list[str] = []
    directive_name = ""

    with httpx.Client(follow_redirects=True, timeout=timeout, verify=verify_ssl) as client:
        for _ in range(num_requests):
            try:
                resp = client.get(url)
            except (httpx.HTTPError, httpx.TimeoutException):
                continue

            csp_header = resp.headers.get("content-security-policy", "")
            if not csp_header:
                csp_header = resp.headers.get("content-security-policy-report-only", "")
            if not csp_header:
                continue

            policy = parse(csp_header)
            for dname in ("script-src", "default-src", "style-src"):
                directive = policy.get_directive(dname)
                if directive is None:
                    continue
                for source in directive.sources:
                    if source.raw.lower().startswith("'nonce-") and source.raw.endswith("'"):
                        nonce_val = source.raw[7:-1]  # Strip 'nonce-' and trailing '
                        nonces.append(nonce_val)
                        directive_name = dname
                        break
                if nonces and nonces[-1] != "":
                    break

    if not nonces:
        return None

    unique_nonces = set(nonces)
    return NonceReuseResult(
        url=url,
        nonces_found=nonces,
        is_static=len(unique_nonces) == 1 and len(nonces) >= 2,
        num_requests=num_requests,
        directive=directive_name,
    )


@dataclass
class HeaderInjectionResult:
    url: str
    vulnerable: bool
    technique: str  # Which injection technique worked, if any
    details: str


def check_header_injection(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> HeaderInjectionResult:
    """Check if a URL is vulnerable to CSP header injection via CRLF or parameter pollution.

    Tests common injection vectors in URL parameters that might end up in response headers.
    """
    # CRLF injection payloads to test
    payloads = [
        ("%0d%0aContent-Security-Policy:%20script-src%20*", "crlf_url_encoded"),
        ("%0aContent-Security-Policy:%20script-src%20*", "lf_only"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "crlf_body_injection"),
        ("\r\nContent-Security-Policy: script-src *", "crlf_raw"),
    ]

    separator = "&" if "?" in url else "?"

    with httpx.Client(follow_redirects=False, timeout=timeout, verify=verify_ssl) as client:
        for payload, technique in payloads:
            test_url = f"{url}{separator}csp_test={payload}"
            try:
                resp = client.get(test_url)
                # Check if our injected header appears
                # Look for script-src * which we injected
                all_csp = resp.headers.get_list("content-security-policy")
                for csp_val in all_csp:
                    if "script-src *" in csp_val or "script-src%20*" in csp_val:
                        return HeaderInjectionResult(
                            url=url, vulnerable=True, technique=technique,
                            details=f"Injected CSP header detected via {technique}: {csp_val}",
                        )

                # Also check if payload appears in any response header value
                for header_name, header_val in resp.headers.items():
                    if "script-src" in header_val and header_name.lower() != "content-security-policy":
                        return HeaderInjectionResult(
                            url=url, vulnerable=True, technique=f"{technique}_in_{header_name}",
                            details=f"Payload reflected in {header_name} header: {header_val[:200]}",
                        )
            except (httpx.HTTPError, httpx.TimeoutException, httpx.InvalidURL, ValueError):
                continue

    return HeaderInjectionResult(
        url=url, vulnerable=False, technique="none",
        details="No header injection vectors detected",
    )


@dataclass
class ReportUriResult:
    url: str
    report_uri: str | None
    report_to: str | None
    uri_reachable: bool | None  # None if no report-uri found
    uri_status_code: int | None
    accepts_post: bool | None
    details: str


def analyze_report_uri(
    policy: Policy,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> ReportUriResult:
    """Analyze the report-uri/report-to directives in a CSP policy.

    Checks if the reporting endpoint exists, is reachable, and accepts POST.
    """
    report_uri_directive = policy.get_directive("report-uri")
    report_to_directive = policy.get_directive("report-to")

    report_uri = None
    report_to = None

    if report_uri_directive and report_uri_directive.sources:
        report_uri = report_uri_directive.sources[0].raw

    if report_to_directive and report_to_directive.sources:
        report_to = report_to_directive.sources[0].raw

    if not report_uri and not report_to:
        return ReportUriResult(
            url="", report_uri=None, report_to=report_to,
            uri_reachable=None, uri_status_code=None, accepts_post=None,
            details="No report-uri or report-to directive found",
        )

    # Test report-uri reachability
    uri_reachable = None
    uri_status_code = None
    accepts_post = None

    if report_uri and report_uri.startswith("http"):
        try:
            # Send a minimal CSP violation report
            test_report = {
                "csp-report": {
                    "document-uri": "https://example.com/test",
                    "violated-directive": "script-src 'self'",
                    "effective-directive": "script-src",
                    "original-policy": "script-src 'self'",
                    "blocked-uri": "https://evil.com/script.js",
                    "status-code": 200,
                }
            }

            with httpx.Client(timeout=timeout, verify=verify_ssl) as client:
                # Try GET first to see if it's reachable
                try:
                    resp = client.get(report_uri)
                    uri_reachable = True
                    uri_status_code = resp.status_code
                except (httpx.HTTPError, httpx.TimeoutException):
                    uri_reachable = False

                # Try POST with a CSP report
                if uri_reachable:
                    try:
                        resp = client.post(
                            report_uri,
                            json=test_report,
                            headers={"Content-Type": "application/csp-report"},
                        )
                        accepts_post = resp.status_code < 500
                    except (httpx.HTTPError, httpx.TimeoutException):
                        accepts_post = False

        except Exception:
            uri_reachable = False

    details_parts = []
    if report_uri:
        details_parts.append(f"report-uri: {report_uri}")
        if uri_reachable is True:
            details_parts.append(f"  Reachable (status {uri_status_code})")
            if accepts_post:
                details_parts.append("  Accepts POST with CSP report")
            else:
                details_parts.append("  Does NOT accept POST")
        elif uri_reachable is False:
            details_parts.append("  NOT reachable")
    if report_to:
        details_parts.append(f"report-to: {report_to} (group name, not directly testable)")

    return ReportUriResult(
        url=report_uri or "",
        report_uri=report_uri,
        report_to=report_to,
        uri_reachable=uri_reachable,
        uri_status_code=uri_status_code,
        accepts_post=accepts_post,
        details="\n".join(details_parts),
    )
