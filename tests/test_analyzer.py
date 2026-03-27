"""Tests for CSP analyzer — one test per check, plus clean-policy negatives."""

from csp_toolkit.analyzer import analyze, analyze_header
from csp_toolkit.models import Severity
from csp_toolkit.parser import parse


class TestAnalyzeCleanPolicy:
    """A strict policy should produce minimal findings."""

    def test_strict_policy_no_critical_or_high(self):
        p = parse(
            "default-src 'none'; "
            "script-src 'nonce-abc123' 'strict-dynamic'; "
            "style-src 'nonce-abc123'; "
            "img-src 'self'; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        )
        findings = analyze(p)
        severe = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert severe == [], f"Unexpected severe findings: {severe}"

    def test_empty_policy_no_findings(self):
        p = parse("")
        findings = analyze(p)
        assert findings == []


class TestMissingScriptSrcAndDefaultSrc:
    def test_triggers(self):
        p = parse("style-src 'self'; img-src 'self'")
        findings = analyze(p)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        titles = [f.title for f in critical]
        assert any("No script-src or default-src" in t for t in titles)

    def test_not_triggered_with_default_src(self):
        p = parse("default-src 'self'")
        findings = analyze(p)
        titles = [f.title for f in findings]
        assert not any("No script-src or default-src" in t for t in titles)


class TestUnsafeInlineScript:
    def test_triggers_critical(self):
        findings = analyze_header("script-src 'self' 'unsafe-inline'")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert any("unsafe-inline" in f.title.lower() for f in critical)

    def test_with_nonce_downgrades_to_medium(self):
        findings = analyze_header("script-src 'nonce-abc' 'unsafe-inline'")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert any("unsafe-inline" in f.title.lower() for f in medium)

    def test_not_triggered_without(self):
        findings = analyze_header("script-src 'self' 'nonce-abc'")
        assert not any("unsafe-inline" in f.title.lower() for f in findings)


class TestDataUriScript:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' data:")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert any("data:" in f.title.lower() for f in critical)

    def test_not_triggered_in_img_src(self):
        findings = analyze_header("script-src 'self'; img-src data:")
        # data: in img-src should NOT trigger the script-specific check
        script_data = [f for f in findings if "data:" in f.title.lower() and f.directive == "script-src"]
        assert script_data == []


class TestUnsafeEval:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' 'unsafe-eval'")
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert any("unsafe-eval" in f.title.lower() for f in high)

    def test_not_triggered_without(self):
        findings = analyze_header("script-src 'self'")
        assert not any("unsafe-eval" in f.title.lower() for f in findings)


class TestWildcardSource:
    def test_script_src_wildcard_is_high(self):
        findings = analyze_header("script-src *")
        wildcards = [f for f in findings if "wildcard" in f.title.lower()]
        assert any(f.severity == Severity.HIGH for f in wildcards)

    def test_img_src_wildcard_is_medium(self):
        findings = analyze_header("script-src 'self'; img-src *")
        img_wildcards = [f for f in findings if "wildcard" in f.title.lower() and f.directive == "img-src"]
        assert all(f.severity == Severity.MEDIUM for f in img_wildcards)


class TestBlobUriScript:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' blob:")
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert any("blob:" in f.title.lower() for f in high)


class TestMissingObjectSrc:
    def test_missing_triggers(self):
        findings = analyze_header("script-src 'self'")
        titles = [f.title for f in findings]
        assert any("object-src" in t.lower() for t in titles)

    def test_none_is_clean(self):
        findings = analyze_header("script-src 'self'; object-src 'none'")
        object_findings = [f for f in findings if f.directive == "object-src"]
        assert object_findings == []

    def test_permissive_object_src(self):
        findings = analyze_header("script-src 'self'; object-src 'self'")
        object_findings = [f for f in findings if f.directive == "object-src"]
        assert len(object_findings) == 1
        assert object_findings[0].severity == Severity.MEDIUM


class TestMissingBaseUri:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'; object-src 'none'")
        assert any("base-uri" in f.title.lower() for f in findings)

    def test_not_triggered_when_present(self):
        findings = analyze_header("script-src 'self'; base-uri 'self'")
        assert not any("base-uri" in f.title.lower() for f in findings)


class TestMissingFormAction:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'")
        assert any("form-action" in f.title.lower() for f in findings)

    def test_not_triggered_when_present(self):
        findings = analyze_header("script-src 'self'; form-action 'self'")
        assert not any("form-action" in f.title.lower() for f in findings)


class TestMissingFrameAncestors:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'")
        assert any("frame-ancestors" in f.title.lower() for f in findings)

    def test_not_triggered_when_present(self):
        findings = analyze_header("script-src 'self'; frame-ancestors 'none'")
        assert not any("frame-ancestors" in f.title.lower() for f in findings)


class TestOverlyBroadHosts:
    def test_googleapis_flagged(self):
        findings = analyze_header("script-src 'self' *.googleapis.com")
        broad = [f for f in findings if f.bypass_type == "broad_domain"]
        assert len(broad) >= 1

    def test_specific_host_not_flagged(self):
        findings = analyze_header("script-src 'self' cdn.example.com")
        broad = [f for f in findings if f.bypass_type == "broad_domain"]
        assert broad == []


class TestUnsafeHashes:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' 'unsafe-hashes' 'sha256-abc'")
        assert any("unsafe-hashes" in f.title.lower() for f in findings)


class TestUnsafeInlineStyle:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'; style-src 'self' 'unsafe-inline'")
        style_findings = [f for f in findings if f.directive == "style-src"]
        assert any("unsafe-inline" in f.title.lower() for f in style_findings)


class TestStrictDynamicWithoutNonce:
    def test_triggers(self):
        findings = analyze_header("script-src 'strict-dynamic'")
        assert any("strict-dynamic" in f.title.lower() for f in findings)

    def test_not_triggered_with_nonce(self):
        findings = analyze_header("script-src 'nonce-abc' 'strict-dynamic'")
        sd_findings = [f for f in findings if "strict-dynamic" in f.title.lower() and "without" in f.title.lower()]
        assert sd_findings == []


class TestReportOnly:
    def test_triggers(self):
        p = parse("default-src 'self'", report_only=True)
        findings = analyze(p)
        assert any("report-only" in f.title.lower() for f in findings)

    def test_not_triggered_enforced(self):
        p = parse("default-src 'self'", report_only=False)
        findings = analyze(p)
        assert not any("report-only" in f.title.lower() for f in findings)


class TestHttpSources:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' http:")
        http_findings = [f for f in findings if "http:" in f.title.lower()]
        assert len(http_findings) >= 1

    def test_https_not_flagged(self):
        findings = analyze_header("script-src 'self' https:")
        http_findings = [f for f in findings if "http:" in f.title.lower() and "https" not in f.title.lower()]
        assert http_findings == []


class TestIpAddressSources:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' 192.168.1.1")
        ip_findings = [f for f in findings if "ip address" in f.title.lower()]
        assert len(ip_findings) >= 1

    def test_domain_not_flagged(self):
        findings = analyze_header("script-src 'self' cdn.example.com")
        ip_findings = [f for f in findings if "ip address" in f.title.lower()]
        assert ip_findings == []


class TestDataUriNonScript:
    def test_object_src_data(self):
        findings = analyze_header("script-src 'self'; object-src data:")
        data_findings = [f for f in findings if "data:" in f.title.lower() and f.directive == "object-src"]
        assert len(data_findings) >= 1

    def test_frame_src_data(self):
        findings = analyze_header("script-src 'self'; frame-src data:")
        data_findings = [f for f in findings if "data:" in f.title.lower() and f.directive == "frame-src"]
        assert len(data_findings) >= 1


class TestSortOrder:
    def test_findings_sorted_by_severity(self):
        # A policy with multiple issues
        findings = analyze_header("script-src 'self' 'unsafe-inline' 'unsafe-eval' *")
        severities = [f.severity for f in findings]
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        values = [severity_order[s] for s in severities]
        assert values == sorted(values)
