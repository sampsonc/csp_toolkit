"""CSP weakness detection engine — checks a Policy for misconfigurations and vulnerabilities."""

from __future__ import annotations

from .models import Finding, Policy, Severity, SourceType
from .parser import parse


def analyze(policy: Policy) -> list[Finding]:
    """Run all weakness checks against a policy and return findings sorted by severity."""
    if not policy.directives:
        return []

    findings: list[Finding] = []
    for check_id, check in CHECKS:
        for finding in check(policy):
            if finding.check_id is None:
                finding.check_id = check_id
            findings.append(finding)

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings.sort(key=lambda f: severity_order[f.severity])
    return findings


def analyze_header(header: str, report_only: bool = False) -> list[Finding]:
    """Convenience: parse a raw CSP header string and analyze it."""
    return analyze(parse(header, report_only=report_only))


_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def score_policy(policy: Policy) -> tuple[str, int]:
    """Score a policy and return a letter grade (A+ to F) and numeric score (0-100).

    100 = perfect (no findings), deducted by severity-weighted findings.
    """
    findings = analyze(policy)
    penalty = sum(_SEVERITY_WEIGHTS[f.severity] for f in findings)
    numeric = max(0, 100 - penalty)

    if numeric >= 95:
        grade = "A+"
    elif numeric >= 90:
        grade = "A"
    elif numeric >= 80:
        grade = "B"
    elif numeric >= 70:
        grade = "C"
    elif numeric >= 50:
        grade = "D"
    else:
        grade = "F"

    return grade, numeric


# --- Individual checks ---


def _check_missing_script_src_and_default_src(policy: Policy) -> list[Finding]:
    """No script-src and no default-src means scripts are unrestricted."""
    if not policy.has_directive("script-src") and not policy.has_directive("default-src"):
        if policy.directives:  # Only flag if the policy has *some* directives
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    title="No script-src or default-src — scripts are unrestricted",
                    description=(
                        "Without script-src or default-src, there are no restrictions on "
                        "script loading. Any origin can serve JavaScript to this page."
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src"
                    ],
                )
            ]
    return []


def _check_unsafe_inline_script(policy: Policy) -> list[Finding]:
    """'unsafe-inline' in script-src defeats CSP's XSS protection."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "'unsafe-inline'" for s in sources):
        # If nonce or hash is also present with strict-dynamic, unsafe-inline is ignored
        # in CSP3 browsers. But CSP2 browsers still honor it, so still flag it.
        has_nonce_or_hash = any(
            s.source_type in (SourceType.NONCE, SourceType.HASH) for s in sources
        )
        if has_nonce_or_hash:
            return [
                Finding(
                    severity=Severity.MEDIUM,
                    title="'unsafe-inline' with nonce/hash — bypassed in CSP2 browsers",
                    description=(
                        "When nonce or hash is present, CSP3 browsers ignore 'unsafe-inline'. "
                        "However, CSP2 browsers (older) still honor 'unsafe-inline', allowing "
                        "arbitrary inline script execution."
                    ),
                    directive="script-src",
                )
            ]
        return [
            Finding(
                severity=Severity.CRITICAL,
                title="'unsafe-inline' allows arbitrary inline scripts",
                description=(
                    "The 'unsafe-inline' source in script-src allows execution of inline "
                    "<script> tags, onclick handlers, and javascript: URIs. This completely "
                    "undermines CSP's XSS protection."
                ),
                directive="script-src",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src#unsafe_inline_script"
                ],
            )
        ]
    return []


def _check_data_uri_script(policy: Policy) -> list[Finding]:
    """data: in script-src allows script injection via data URIs."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "data:" for s in sources):
        return [
            Finding(
                severity=Severity.CRITICAL,
                title="data: URI in script-src allows script injection",
                description=(
                    "The data: scheme in script-src allows loading scripts from data URIs, "
                    "e.g. <script src='data:text/javascript,alert(1)'></script>. This is "
                    "trivially exploitable for XSS."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_unsafe_eval_script(policy: Policy) -> list[Finding]:
    """'unsafe-eval' allows eval() and similar dynamic code execution."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "'unsafe-eval'" for s in sources):
        return [
            Finding(
                severity=Severity.HIGH,
                title="'unsafe-eval' allows eval() and dynamic code execution",
                description=(
                    "The 'unsafe-eval' source allows eval(), Function(), setTimeout(string), "
                    "and setInterval(string). If an attacker can control a string passed to "
                    "any of these, they achieve arbitrary code execution."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_wildcard_source(policy: Policy) -> list[Finding]:
    """Wildcard * in fetch directives allows loading from any origin."""
    findings = []
    for name, directive in policy.directives.items():
        if any(s.source_type == SourceType.WILDCARD for s in directive.sources):
            sev = Severity.HIGH if name in ("script-src", "default-src") else Severity.MEDIUM
            findings.append(
                Finding(
                    severity=sev,
                    title="Wildcard '*' allows loading from any origin",
                    description=(
                        f"The wildcard source in {name} allows loading resources from any "
                        f"origin. For script-src this is equivalent to no CSP protection."
                    ),
                    directive=name,
                )
            )
    return findings


def _check_blob_uri_script(policy: Policy) -> list[Finding]:
    """blob: in script-src allows script creation from blobs."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "blob:" for s in sources):
        return [
            Finding(
                severity=Severity.HIGH,
                title="blob: URI in script-src allows blob-based script injection",
                description=(
                    "The blob: scheme in script-src allows creating scripts from Blob URLs. "
                    "If an attacker has any JS execution, they can create and load arbitrary "
                    "scripts via blob: URLs."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_missing_object_src(policy: Policy) -> list[Finding]:
    """Missing object-src allows plugin-based XSS (Flash, Java applets)."""
    effective = policy.effective_directive("object-src")
    if effective is None:
        return [
            Finding(
                severity=Severity.HIGH,
                title="Missing object-src — plugin-based code execution possible",
                description=(
                    "Without object-src (and no default-src fallback), <object>, <embed>, "
                    "and <applet> elements can load content from any origin. Flash-based "
                    "XSS and other plugin attacks are possible."
                ),
            )
        ]
    # Also flag if object-src is not 'none'
    if not effective.has_source("'none'"):
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="object-src is not 'none' — plugins may be loadable",
                description=(
                    "object-src should be set to 'none' unless plugins are explicitly needed. "
                    "Permissive object-src can allow Flash-based XSS."
                ),
                directive="object-src",
            )
        ]
    return []


def _check_missing_base_uri(policy: Policy) -> list[Finding]:
    """Missing base-uri allows <base> tag injection."""
    if not policy.has_directive("base-uri"):
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing base-uri — <base> tag injection possible",
                description=(
                    "Without base-uri, an attacker who can inject HTML can use a <base> tag "
                    "to change the base URL for all relative URLs on the page, redirecting "
                    "script loads and form submissions to an attacker-controlled server."
                ),
                references=[
                    "https://html.spec.whatwg.org/multipage/semantics.html#the-base-element"
                ],
            )
        ]
    return []


def _check_missing_form_action(policy: Policy) -> list[Finding]:
    """Missing form-action allows form data exfiltration."""
    if not policy.has_directive("form-action"):
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing form-action — form data exfiltration possible",
                description=(
                    "Without form-action, forms on the page can submit data to any URL. "
                    "An attacker who can inject HTML can create or modify forms to send "
                    "sensitive data (CSRF tokens, credentials) to an attacker-controlled server."
                ),
            )
        ]
    return []


def _check_missing_frame_ancestors(policy: Policy) -> list[Finding]:
    """Missing frame-ancestors allows clickjacking."""
    if not policy.has_directive("frame-ancestors"):
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing frame-ancestors — clickjacking possible",
                description=(
                    "Without frame-ancestors, this page can be embedded in frames/iframes "
                    "on any origin, enabling clickjacking attacks. Note: X-Frame-Options "
                    "header may provide equivalent protection if present."
                ),
            )
        ]
    return []


# Domains known to host JSONP or other bypassable endpoints
_BROAD_DOMAINS = frozenset(
    {
        "*.googleapis.com",
        "*.gstatic.com",
        "*.google.com",
        "*.cloudflare.com",
        "*.amazonaws.com",
        "*.azurewebsites.net",
        "*.herokuapp.com",
        "*.firebaseapp.com",
        "*.cloudfront.net",
        "*.akamaihd.net",
    }
)


def _check_overly_broad_hosts(policy: Policy) -> list[Finding]:
    """Flag broad wildcard domains known to host bypassable endpoints."""
    findings = []
    for name in ("script-src", "default-src"):
        directive = policy.get_directive(name)
        if directive is None:
            continue
        for source in directive.host_sources():
            raw_lower = source.raw.lower()
            if raw_lower in _BROAD_DOMAINS:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"Broad wildcard domain '{source.raw}' may host bypassable endpoints",
                        description=(
                            f"The domain {source.raw} in {name} is a large shared-hosting or CDN "
                            f"domain that likely hosts JSONP endpoints, script gadgets, or "
                            f"attacker-controllable content. Use the bypass finder for specifics."
                        ),
                        directive=name,
                        subject=source.raw,
                        bypass_type="broad_domain",
                    )
                )
    return findings


def _check_unsafe_hashes(policy: Policy) -> list[Finding]:
    """'unsafe-hashes' allows specific inline event handlers."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "'unsafe-hashes'" for s in sources):
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="'unsafe-hashes' allows specific inline event handlers",
                description=(
                    "'unsafe-hashes' allows execution of specific inline event handlers "
                    "whose content matches a hash in the policy. While more restrictive than "
                    "'unsafe-inline', it still permits inline JS execution."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_unsafe_inline_style(policy: Policy) -> list[Finding]:
    """'unsafe-inline' in style-src — lower severity but enables CSS-based attacks."""
    sources = policy.effective_sources("style-src")
    if any(s.raw.lower() == "'unsafe-inline'" for s in sources):
        return [
            Finding(
                severity=Severity.LOW,
                title="'unsafe-inline' in style-src allows CSS injection",
                description=(
                    "'unsafe-inline' in style-src allows arbitrary inline styles. While less "
                    "dangerous than script injection, CSS can be used for data exfiltration "
                    "via attribute selectors and @font-face unicode-range tricks."
                ),
                directive="style-src",
            )
        ]
    return []


def _check_strict_dynamic_without_nonce_hash(policy: Policy) -> list[Finding]:
    """'strict-dynamic' without nonce or hash is a misconfiguration."""
    sources = policy.effective_sources("script-src")
    has_strict_dynamic = any(s.raw.lower() == "'strict-dynamic'" for s in sources)
    has_nonce_or_hash = any(s.source_type in (SourceType.NONCE, SourceType.HASH) for s in sources)
    if has_strict_dynamic and not has_nonce_or_hash:
        return [
            Finding(
                severity=Severity.HIGH,
                title="'strict-dynamic' without nonce or hash — no scripts can load",
                description=(
                    "'strict-dynamic' tells the browser to trust scripts loaded by already-trusted "
                    "scripts, but without a nonce or hash to bootstrap trust, no scripts will "
                    "execute at all. This is likely a misconfiguration."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_report_only(policy: Policy) -> list[Finding]:
    """Report-Only policies are not enforced."""
    if policy.report_only:
        return [
            Finding(
                severity=Severity.INFO,
                title="Policy is Content-Security-Policy-Report-Only (not enforced)",
                description=(
                    "This policy uses the Report-Only header, meaning violations are logged "
                    "but not blocked. This is useful for testing but provides no protection."
                ),
            )
        ]
    return []


def _check_http_sources(policy: Policy) -> list[Finding]:
    """HTTP scheme sources on HTTPS pages allow MitM injection."""
    findings = []
    for name, directive in policy.directives.items():
        if any(s.raw.lower() == "http:" for s in directive.sources):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title=f"http: scheme in {name} allows mixed content",
                    description=(
                        f"The http: scheme source in {name} allows loading resources over "
                        f"unencrypted HTTP. On an HTTPS page, this enables man-in-the-middle "
                        f"injection of malicious content."
                    ),
                    directive=name,
                )
            )
    return findings


def _check_ip_address_sources(policy: Policy) -> list[Finding]:
    """IP address sources are unusual and may indicate internal services."""
    import re

    ip_re = re.compile(r"^(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    findings = []
    for name, directive in policy.directives.items():
        for source in directive.host_sources():
            if ip_re.match(source.raw):
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title=f"IP address source '{source.raw}' in {name}",
                        description=(
                            "IP address sources are unusual in production CSP policies and "
                            "may indicate internal/development services that could be accessible "
                            "or exploitable."
                        ),
                        directive=name,
                        subject=source.raw,
                    )
                )
    return findings


def _check_data_uri_in_non_script(policy: Policy) -> list[Finding]:
    """data: URI in non-script directives — lower severity but notable."""
    findings = []
    for name in ("object-src", "frame-src", "child-src"):
        sources = policy.effective_sources(name)
        if any(s.raw.lower() == "data:" for s in sources):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"data: URI in {name} may allow content injection",
                    description=(
                        f"The data: scheme in {name} allows embedding arbitrary content via "
                        f"data URIs. For object-src this may enable plugin-based attacks; for "
                        f"frame-src it may enable phishing via embedded frames."
                    ),
                    directive=name,
                )
            )
    return findings


def _check_https_scheme_script(policy: Policy) -> list[Finding]:
    """https: scheme in script-src allows loading scripts from any HTTPS origin."""
    sources = policy.effective_sources("script-src")
    if any(s.raw.lower() == "https:" for s in sources):
        return [
            Finding(
                severity=Severity.HIGH,
                title="https: scheme in script-src allows scripts from any HTTPS origin",
                description=(
                    "The https: scheme source in script-src allows loading JavaScript from "
                    "any HTTPS origin. This is nearly as permissive as a wildcard — any "
                    "attacker-controlled HTTPS domain can serve malicious scripts."
                ),
                directive="script-src",
            )
        ]
    return []


def _check_missing_trusted_types(policy: Policy) -> list[Finding]:
    """Missing require-trusted-types-for — no DOM XSS sink protection."""
    if not policy.has_directive("require-trusted-types-for"):
        return [
            Finding(
                severity=Severity.INFO,
                title="Missing require-trusted-types-for — no Trusted Types enforcement",
                description=(
                    "Trusted Types prevent DOM XSS by requiring typed objects for dangerous "
                    "DOM sinks (innerHTML, eval, etc.). Adding "
                    "\"require-trusted-types-for 'script'\" enforces this protection. "
                    "Supported in Chromium-based browsers."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for"
                ],
            )
        ]
    return []


def _check_missing_navigate_to(policy: Policy) -> list[Finding]:
    """Missing navigate-to — no navigation restrictions."""
    if not policy.has_directive("navigate-to"):
        return [
            Finding(
                severity=Severity.INFO,
                title="Missing navigate-to — page navigation is unrestricted",
                description=(
                    "Without navigate-to, the page can navigate to any URL via links, "
                    "form submissions, window.location, or meta refresh. The navigate-to "
                    "directive restricts allowed navigation targets. Note: limited browser "
                    "support as of 2025."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/navigate-to"
                ],
            )
        ]
    return []


def _check_worker_src_fallback(policy: Policy) -> list[Finding]:
    """Missing worker-src inherits a broader source list than script-src allows.

    Workers fall back worker-src -> child-src -> script-src -> default-src (see
    models.FALLBACK_CHAINS). When child-src is present and looser than script-src,
    worker code can be loaded from origins the script-src was written to exclude.
    """
    if policy.has_directive("worker-src"):
        return []

    _, inherited_from = policy.resolve("worker-src")
    # Only child-src widens things; inheriting script-src or default-src directly
    # cannot be looser than script-src, and having nothing at all is already
    # reported by the missing-script-src check.
    if inherited_from != "child-src":
        return []

    child_src = policy.get_directive("child-src")
    script_src = policy.effective_directive("script-src")
    if child_src is None or script_src is None:
        return []

    script_allowed = {s.raw.lower() for s in script_src.sources}
    # Nonces and hashes cannot be satisfied by a worker script URL, so a
    # nonce-based script-src is strictly narrower than any host/scheme list.
    extra = [
        s
        for s in child_src.sources
        if s.source_type in (SourceType.HOST, SourceType.SCHEME, SourceType.WILDCARD)
        and s.raw.lower() not in script_allowed
    ]
    if not extra:
        return []

    sources = ", ".join(f"'{s.raw}'" if not s.raw.startswith("'") else s.raw for s in extra)
    return [
        Finding(
            severity=Severity.MEDIUM,
            title="Missing worker-src — workers inherit broader child-src sources",
            description=(
                "worker-src is absent, so Workers, SharedWorkers, and ServiceWorkers "
                f"fall back to child-src, which allows {sources} that script-src does "
                "not. An attacker who can inject a worker URL executes script from "
                "those origins, bypassing the tighter script-src. Set worker-src "
                "explicitly (e.g. \"worker-src 'self'\")."
            ),
            directive="worker-src",
            references=["https://www.w3.org/TR/CSP3/#directive-worker-src"],
        )
    ]


def _check_meta_ignored_directives(policy: Policy) -> list[Finding]:
    """Directives specified in a <meta> policy that the browser ignores outright."""
    if not policy.ignored_directives:
        return []

    names = ", ".join(policy.ignored_directives)
    return [
        Finding(
            severity=Severity.MEDIUM,
            title=f"Meta-delivered policy specifies ignored directive(s): {names}",
            description=(
                f"This policy was delivered via <meta http-equiv>, where {names} "
                "is ignored by the browser. The protection it appears to provide is "
                "not in effect and has been excluded from this analysis. Move the "
                "policy to a Content-Security-Policy response header to enforce it."
            ),
            references=[
                "https://www.w3.org/TR/CSP3/#meta-element",
            ],
        )
    ]


#: The analyzer's checks, paired with the stable ids that appear in json-v1
#: output, SARIF rule ids, and stored baselines. Ids are part of the output
#: contract: rename a check function freely, but changing an id here breaks
#: every baseline in the wild.
CHECKS: tuple[tuple[str, object], ...] = (
    ("no-script-src", _check_missing_script_src_and_default_src),
    ("unsafe-inline-script", _check_unsafe_inline_script),
    ("data-uri-script", _check_data_uri_script),
    ("unsafe-eval", _check_unsafe_eval_script),
    ("wildcard-source", _check_wildcard_source),
    ("blob-uri-script", _check_blob_uri_script),
    ("object-src", _check_missing_object_src),
    ("missing-base-uri", _check_missing_base_uri),
    ("missing-form-action", _check_missing_form_action),
    ("missing-frame-ancestors", _check_missing_frame_ancestors),
    ("broad-host", _check_overly_broad_hosts),
    ("unsafe-hashes", _check_unsafe_hashes),
    ("unsafe-inline-style", _check_unsafe_inline_style),
    ("strict-dynamic-without-nonce", _check_strict_dynamic_without_nonce_hash),
    ("https-scheme-script", _check_https_scheme_script),
    ("report-only", _check_report_only),
    ("http-scheme-source", _check_http_sources),
    ("ip-address-source", _check_ip_address_sources),
    ("data-uri-non-script", _check_data_uri_in_non_script),
    ("missing-trusted-types", _check_missing_trusted_types),
    ("missing-navigate-to", _check_missing_navigate_to),
    ("missing-worker-src", _check_worker_src_fallback),
    ("meta-ignored-directives", _check_meta_ignored_directives),
)
