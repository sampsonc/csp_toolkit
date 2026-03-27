"""HTTP fetcher for live CSP headers — fetches and parses CSP from URLs."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from .models import Policy
from .parser import parse, parse_meta


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    csp_headers: list[str] = field(default_factory=list)
    csp_report_only_headers: list[str] = field(default_factory=list)
    csp_meta_tags: list[str] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)

    @property
    def csp_header(self) -> str | None:
        """First ``Content-Security-Policy`` header value (backwards compatibility)."""
        return self.csp_headers[0] if self.csp_headers else None

    @property
    def csp_report_only_header(self) -> str | None:
        """First ``Content-Security-Policy-Report-Only`` header value (backwards compatibility)."""
        return self.csp_report_only_headers[0] if self.csp_report_only_headers else None


_SECURITY_HEADER_NAMES = {
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
}


def fetch_csp(
    url: str,
    *,
    follow_redirects: bool = True,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> FetchResult:
    """Fetch CSP headers and meta tags from a URL.

    Multiple ``Content-Security-Policy`` (or Report-Only) header fields are each
    parsed as a separate policy, per the CSP specification.

    Args:
        url: The URL to fetch.
        follow_redirects: Whether to follow HTTP redirects.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        FetchResult with parsed CSP policies and related security headers.
    """
    with httpx.Client(
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify_ssl,
    ) as client:
        response = client.get(url)

    result = FetchResult(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
    )

    for raw in response.headers.get_list("content-security-policy"):
        raw = raw.strip()
        if not raw:
            continue
        result.csp_headers.append(raw)
        result.policies.append(parse(raw, report_only=False))

    for raw in response.headers.get_list("content-security-policy-report-only"):
        raw = raw.strip()
        if not raw:
            continue
        result.csp_report_only_headers.append(raw)
        result.policies.append(parse(raw, report_only=True))

    # Extract CSP from <meta> tags
    content_type = response.headers.get("content-type", "")
    if "html" in content_type.lower():
        soup = BeautifulSoup(response.text, "html.parser")
        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if meta["http-equiv"].lower() == "content-security-policy":
                content = meta.get("content", "")
                if content:
                    result.csp_meta_tags.append(content)
                    result.policies.append(parse_meta(content))

    # Capture related security headers
    for header_name in _SECURITY_HEADER_NAMES:
        value = response.headers.get(header_name)
        if value:
            result.security_headers[header_name] = value

    return result
