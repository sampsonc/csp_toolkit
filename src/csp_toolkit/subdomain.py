"""Subdomain CSP variance detection — find weak subdomains on the same target."""

from __future__ import annotations

from dataclasses import dataclass

from .analyzer import score_policy
from .fetcher import fetch_csp
from .models import Policy
from .scanner import ScanResult, scan_url


# Common subdomains to check when enumerating
DEFAULT_PREFIXES = [
    "www",
    "app",
    "api",
    "admin",
    "staging",
    "stage",
    "dev",
    "beta",
    "test",
    "qa",
    "m",
    "mobile",
    "portal",
    "dashboard",
    "console",
    "accounts",
    "auth",
    "login",
    "sso",
    "mail",
    "docs",
    "help",
    "support",
    "status",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "blog",
    "shop",
    "store",
    "pay",
    "checkout",
    "internal",
]


@dataclass
class SubdomainResult:
    subdomain: str
    url: str
    scan: ScanResult


def check_subdomains(
    base_domain: str,
    *,
    prefixes: list[str] | None = None,
    timeout: float = 8.0,
    verify_ssl: bool = True,
) -> list[SubdomainResult]:
    """Check CSP across subdomains of a base domain.

    Args:
        base_domain: The base domain (e.g. "example.com")
        prefixes: Subdomain prefixes to check. Defaults to common ones.
        timeout: HTTP timeout per request.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        List of SubdomainResults, sorted by CSP score (weakest first).
        Only includes subdomains that responded successfully.
    """
    if prefixes is None:
        prefixes = DEFAULT_PREFIXES

    # Clean up base domain
    base_domain = base_domain.strip().lower()
    for prefix in ("https://", "http://"):
        if base_domain.startswith(prefix):
            base_domain = base_domain[len(prefix):]
    base_domain = base_domain.rstrip("/")

    # Also check the bare domain
    urls_to_check = [f"https://{base_domain}"]
    for prefix in prefixes:
        urls_to_check.append(f"https://{prefix}.{base_domain}")

    results: list[SubdomainResult] = []
    for url in urls_to_check:
        scan = scan_url(url, timeout=timeout, verify_ssl=verify_ssl)
        if scan.error:
            continue  # Skip unreachable subdomains
        subdomain = url.replace("https://", "")
        results.append(SubdomainResult(
            subdomain=subdomain,
            url=url,
            scan=scan,
        ))

    # Sort by score ascending (weakest first), then has_csp=False before has_csp=True
    def sort_key(r: SubdomainResult) -> tuple:
        if not r.scan.has_csp:
            return (0, 0, r.subdomain)  # No CSP = most interesting
        return (1, r.scan.score, r.subdomain)

    results.sort(key=sort_key)
    return results
