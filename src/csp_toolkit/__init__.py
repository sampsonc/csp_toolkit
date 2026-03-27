"""CSP Toolkit — Parse, analyze, generate, and find bypasses in Content Security Policy headers."""

from ._version import __version__
from .analyzer import analyze, analyze_header, score_policy
from .bypass import check_domain_gadgets, check_domain_jsonp, find_bypasses, probe_jsonp_endpoint
from .diff import PolicyDiff, diff_headers, diff_policies
from .discover import DiscoveredResources, discover_resources, generate_csp
from .fetcher import FetchResult, fetch_csp
from .generator import CSPBuilder
from .models import Directive, Finding, Policy, Severity, Source, SourceType
from .parser import parse, parse_meta
from .probes import (
    HeaderInjectionResult,
    NonceReuseResult,
    NonceReuseStatus,
    ReportUriResult,
    analyze_report_uri,
    check_header_injection,
    detect_nonce_reuse,
)
from .scanner import ScanResult, scan_url, scan_urls
from .subdomain import SubdomainResult, check_subdomains
from .tracker import EvolutionAlert, Snapshot, check_evolution, take_snapshot

__all__ = [
    "__version__",
    "analyze",
    "analyze_header",
    "analyze_report_uri",
    "check_domain_gadgets",
    "check_domain_jsonp",
    "check_evolution",
    "check_header_injection",
    "check_subdomains",
    "CSPBuilder",
    "detect_nonce_reuse",
    "diff_headers",
    "diff_policies",
    "Directive",
    "DiscoveredResources",
    "discover_resources",
    "EvolutionAlert",
    "fetch_csp",
    "FetchResult",
    "find_bypasses",
    "Finding",
    "generate_csp",
    "HeaderInjectionResult",
    "NonceReuseResult",
    "NonceReuseStatus",
    "parse",
    "parse_meta",
    "probe_jsonp_endpoint",
    "Policy",
    "PolicyDiff",
    "ReportUriResult",
    "scan_url",
    "scan_urls",
    "ScanResult",
    "score_policy",
    "Severity",
    "Snapshot",
    "Source",
    "SourceType",
    "SubdomainResult",
    "take_snapshot",
]
