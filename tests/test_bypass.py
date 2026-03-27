"""Tests for CSP bypass finder."""

from csp_toolkit.bypass import (
    _verify_live_endpoints,
    check_domain_gadgets,
    check_domain_jsonp,
    find_bypasses,
    find_bypasses_header,
    probe_jsonp_endpoint,
    _domain_matches,
)
from csp_toolkit.models import Finding, Severity
from csp_toolkit.parser import parse


class TestDomainMatches:
    def test_exact_match(self):
        assert _domain_matches("accounts.google.com", "accounts.google.com")

    def test_case_insensitive(self):
        assert _domain_matches("Accounts.Google.Com", "accounts.google.com")

    def test_wildcard_source(self):
        assert _domain_matches("*.googleapis.com", "maps.googleapis.com")
        assert _domain_matches("*.googleapis.com", "ajax.googleapis.com")

    def test_wildcard_matches_base(self):
        assert _domain_matches("*.googleapis.com", "googleapis.com")

    def test_no_match(self):
        assert not _domain_matches("example.com", "other.com")

    def test_strips_scheme(self):
        assert _domain_matches("https://accounts.google.com", "accounts.google.com")

    def test_strips_port(self):
        assert _domain_matches("accounts.google.com:443", "accounts.google.com")

    def test_partial_no_match(self):
        assert not _domain_matches("notgoogle.com", "google.com")
        assert not _domain_matches("*.google.com", "notgoogle.com")


class TestCheckDomainJsonp:
    def test_known_domain(self):
        results = check_domain_jsonp("accounts.google.com")
        assert len(results) >= 1
        assert any("callback" in ep["path"].lower() for ep in results)

    def test_unknown_domain(self):
        results = check_domain_jsonp("totally-unknown-domain.com")
        assert results == []


class TestCheckDomainGadgets:
    def test_known_cdn(self):
        results = check_domain_gadgets("cdnjs.cloudflare.com")
        assert len(results) >= 1
        assert any(g["library"] == "angularjs" for g in results)

    def test_unknown_domain(self):
        results = check_domain_gadgets("totally-unknown-cdn.com")
        assert results == []


class TestJsonpBypasses:
    def test_googleapis_wildcard(self):
        findings = find_bypasses_header("script-src 'self' *.googleapis.com")
        jsonp = [f for f in findings if f.bypass_type == "jsonp"]
        assert len(jsonp) >= 1

    def test_exact_google_domain(self):
        findings = find_bypasses_header("script-src 'self' accounts.google.com")
        jsonp = [f for f in findings if f.bypass_type == "jsonp"]
        assert len(jsonp) >= 1

    def test_no_jsonp_for_safe_domain(self):
        findings = find_bypasses_header("script-src 'self' cdn.example.com")
        jsonp = [f for f in findings if f.bypass_type == "jsonp"]
        assert jsonp == []


class TestCdnGadgets:
    def test_cdnjs_cloudflare(self):
        findings = find_bypasses_header("script-src 'self' cdnjs.cloudflare.com")
        gadgets = [f for f in findings if f.bypass_type == "cdn_gadget"]
        assert len(gadgets) >= 1
        assert any("angularjs" in f.title.lower() for f in gadgets)

    def test_jsdelivr(self):
        findings = find_bypasses_header("script-src 'self' cdn.jsdelivr.net")
        gadgets = [f for f in findings if f.bypass_type == "cdn_gadget"]
        assert len(gadgets) >= 1

    def test_unpkg(self):
        findings = find_bypasses_header("script-src 'self' unpkg.com")
        gadgets = [f for f in findings if f.bypass_type == "cdn_gadget"]
        assert len(gadgets) >= 1


class TestDataUriBypasses:
    def test_triggers(self):
        findings = find_bypasses_header("script-src 'self' data:")
        data = [f for f in findings if f.bypass_type == "data_uri"]
        assert len(data) == 1
        assert data[0].severity == Severity.CRITICAL

    def test_not_triggered(self):
        findings = find_bypasses_header("script-src 'self'")
        data = [f for f in findings if f.bypass_type == "data_uri"]
        assert data == []


class TestBlobUriBypasses:
    def test_triggers(self):
        findings = find_bypasses_header("script-src 'self' blob:")
        blob = [f for f in findings if f.bypass_type == "blob_uri"]
        assert len(blob) == 1
        assert blob[0].severity == Severity.HIGH

    def test_not_triggered(self):
        findings = find_bypasses_header("script-src 'self'")
        blob = [f for f in findings if f.bypass_type == "blob_uri"]
        assert blob == []


class TestBaseUriBypasses:
    def test_missing_base_uri(self):
        findings = find_bypasses_header("script-src 'self'")
        base = [f for f in findings if f.bypass_type == "base_uri"]
        assert len(base) == 1

    def test_base_uri_present(self):
        findings = find_bypasses_header("script-src 'self'; base-uri 'self'")
        base = [f for f in findings if f.bypass_type == "base_uri"]
        assert base == []


class TestFormActionBypasses:
    def test_missing_form_action(self):
        findings = find_bypasses_header("script-src 'self'")
        form = [f for f in findings if f.bypass_type == "form_action"]
        assert len(form) == 1

    def test_form_action_present(self):
        findings = find_bypasses_header("script-src 'self'; form-action 'self'")
        form = [f for f in findings if f.bypass_type == "form_action"]
        assert form == []


class TestCsp2DowngradeBypasses:
    def test_unsafe_inline_with_nonce(self):
        findings = find_bypasses_header("script-src 'nonce-abc' 'unsafe-inline'")
        csp2 = [f for f in findings if f.bypass_type == "csp2_downgrade"]
        assert len(csp2) == 1

    def test_unsafe_inline_without_nonce(self):
        findings = find_bypasses_header("script-src 'self' 'unsafe-inline'")
        csp2 = [f for f in findings if f.bypass_type == "csp2_downgrade"]
        assert csp2 == []

    def test_nonce_without_unsafe_inline(self):
        findings = find_bypasses_header("script-src 'nonce-abc'")
        csp2 = [f for f in findings if f.bypass_type == "csp2_downgrade"]
        assert csp2 == []


class TestArbitraryHostingBypasses:
    def test_raw_github(self):
        findings = find_bypasses_header("script-src 'self' raw.githubusercontent.com")
        arb = [f for f in findings if f.bypass_type == "arbitrary_hosting"]
        assert len(arb) >= 1
        assert arb[0].severity == Severity.CRITICAL

    def test_wildcard_covers_hosting(self):
        findings = find_bypasses_header("script-src 'self' *.netlify.app")
        arb = [f for f in findings if f.bypass_type == "arbitrary_hosting"]
        assert len(arb) >= 1

    def test_safe_domain_not_flagged(self):
        findings = find_bypasses_header("script-src 'self' cdn.example.com")
        arb = [f for f in findings if f.bypass_type == "arbitrary_hosting"]
        assert arb == []


class TestEmptyPolicy:
    def test_no_bypasses_for_empty(self):
        p = parse("")
        findings = find_bypasses(p)
        assert findings == []


class TestCombinedPolicy:
    def test_multiple_bypasses_found(self):
        # A terrible CSP with many bypass vectors
        findings = find_bypasses_header(
            "script-src 'self' data: blob: cdnjs.cloudflare.com *.googleapis.com"
        )
        bypass_types = {f.bypass_type for f in findings}
        assert "data_uri" in bypass_types
        assert "blob_uri" in bypass_types
        assert "cdn_gadget" in bypass_types
        assert "jsonp" in bypass_types


class TestVerifyLiveEndpoints:
    def test_non_jsonp_findings_passed_through(self):
        findings = [
            Finding(severity=Severity.CRITICAL, title="data: bypass", description="...", bypass_type="data_uri"),
            Finding(severity=Severity.MEDIUM, title="base tag", description="...", bypass_type="base_uri"),
        ]
        result = _verify_live_endpoints(findings)
        assert len(result) == 2
        # Non-JSONP findings should be unchanged
        assert result[0].title == "data: bypass"
        assert result[1].title == "base tag"

    def test_jsonp_findings_get_annotated(self):
        findings = [
            Finding(
                severity=Severity.HIGH,
                title="JSONP bypass via example.com",
                description="payload: https://example.com/jsonp?callback=alert(document.domain)//",
                bypass_type="jsonp",
                directive="script-src",
            ),
        ]
        # With a very short timeout, the endpoint won't be reachable
        result = _verify_live_endpoints(findings, timeout=0.1)
        assert len(result) == 1
        assert "[UNVERIFIED]" in result[0].title or "[LIVE]" in result[0].title
