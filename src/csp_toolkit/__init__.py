"""CSP Toolkit — Parse, analyze, generate, and find bypasses in Content Security Policy headers."""

from ._version import __version__
from .analyzer import CHECKS, analyze, analyze_header, score_policy
from .baseline import Baseline, BaselineError, Comparison
from .baseline import compare as compare_to_baseline
from .baseline import entry_for_policy
from .bypass import check_domain_gadgets, check_domain_jsonp, find_bypasses, probe_jsonp_endpoint
from .diff import PolicyDiff, diff_headers, diff_policies
from .discover import DiscoveredResources, discover_resources, generate_csp
from .effective import combine_enforced_header_policies, combine_policies
from .explain import Resolution, explain_json, explain_policy
from .export_ops import format_findings_sarif_json, format_findings_stable_json
from .fetcher import FetchResult, fetch_csp
from .generator import CSPBuilder
from .harden import Change, HardenResult, harden_json, harden_policy
from .models import (
    FALLBACK_CHAINS,
    Directive,
    Finding,
    Policy,
    Severity,
    Source,
    SourceType,
)
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
from .violations import (
    build_patched_csp,
    group_violations,
    parse_violations_json,
    suggest_violation_fixes,
    violations_summary_json,
)

__all__ = [
    "__version__",
    "analyze",
    "analyze_header",
    "analyze_report_uri",
    "Baseline",
    "BaselineError",
    "build_patched_csp",
    "Change",
    "check_domain_gadgets",
    "check_domain_jsonp",
    "check_evolution",
    "check_header_injection",
    "check_subdomains",
    "CHECKS",
    "combine_enforced_header_policies",
    "combine_policies",
    "compare_to_baseline",
    "Comparison",
    "CSPBuilder",
    "detect_nonce_reuse",
    "diff_headers",
    "diff_policies",
    "Directive",
    "discover_resources",
    "DiscoveredResources",
    "entry_for_policy",
    "EvolutionAlert",
    "explain_json",
    "explain_policy",
    "FALLBACK_CHAINS",
    "fetch_csp",
    "FetchResult",
    "find_bypasses",
    "Finding",
    "format_findings_sarif_json",
    "format_findings_stable_json",
    "generate_csp",
    "group_violations",
    "harden_json",
    "harden_policy",
    "HardenResult",
    "HeaderInjectionResult",
    "NonceReuseResult",
    "NonceReuseStatus",
    "parse",
    "parse_meta",
    "parse_violations_json",
    "Policy",
    "PolicyDiff",
    "probe_jsonp_endpoint",
    "ReportUriResult",
    "Resolution",
    "scan_url",
    "scan_urls",
    "ScanResult",
    "score_policy",
    "Severity",
    "Snapshot",
    "Source",
    "SourceType",
    "SubdomainResult",
    "suggest_violation_fixes",
    "take_snapshot",
    "violations_summary_json",
]
