"""Tests for CSP analyzer — one test per check, plus clean-policy negatives."""

from csp_toolkit.analyzer import analyze, analyze_header, score_policy
from csp_toolkit.models import Severity
from csp_toolkit.parser import parse, parse_meta


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
        script_data = [
            f for f in findings if "data:" in f.title.lower() and f.directive == "script-src"
        ]
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
        img_wildcards = [
            f for f in findings if "wildcard" in f.title.lower() and f.directive == "img-src"
        ]
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
        sd_findings = [
            f
            for f in findings
            if "strict-dynamic" in f.title.lower() and "without" in f.title.lower()
        ]
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
        http_findings = [
            f for f in findings if "http:" in f.title.lower() and "https" not in f.title.lower()
        ]
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
        data_findings = [
            f for f in findings if "data:" in f.title.lower() and f.directive == "object-src"
        ]
        assert len(data_findings) >= 1

    def test_frame_src_data(self):
        findings = analyze_header("script-src 'self'; frame-src data:")
        data_findings = [
            f for f in findings if "data:" in f.title.lower() and f.directive == "frame-src"
        ]
        assert len(data_findings) >= 1


class TestHttpsSchemeScript:
    def test_triggers(self):
        findings = analyze_header("script-src 'self' https:")
        https_findings = [
            f
            for f in findings
            if "https:" in f.title.lower() and "any https" in f.description.lower()
        ]
        assert len(https_findings) >= 1
        assert https_findings[0].severity == Severity.HIGH

    def test_not_triggered_without(self):
        findings = analyze_header("script-src 'self'")
        https_findings = [f for f in findings if "https: scheme in script-src" in f.title.lower()]
        assert https_findings == []


class TestMissingTrustedTypes:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'")
        tt = [f for f in findings if "trusted types" in f.title.lower()]
        assert len(tt) == 1
        assert tt[0].severity == Severity.INFO

    def test_not_triggered_when_present(self):
        findings = analyze_header("script-src 'self'; require-trusted-types-for 'script'")
        tt = [f for f in findings if "trusted types" in f.title.lower()]
        assert tt == []


class TestMissingNavigateTo:
    def test_triggers(self):
        findings = analyze_header("script-src 'self'")
        nav = [f for f in findings if "navigate-to" in f.title.lower()]
        assert len(nav) == 1
        assert nav[0].severity == Severity.INFO

    def test_not_triggered_when_present(self):
        findings = analyze_header("script-src 'self'; navigate-to 'self'")
        nav = [f for f in findings if "navigate-to" in f.title.lower()]
        assert nav == []


class TestScorePolicy:
    def test_strict_policy_high_score(self):
        p = parse(
            "default-src 'none'; "
            "script-src 'nonce-abc123' 'strict-dynamic'; "
            "style-src 'nonce-abc123'; "
            "img-src 'self'; font-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'; "
            "require-trusted-types-for 'script'; navigate-to 'self'"
        )
        grade, score = score_policy(p)
        assert grade in ("A+", "A")
        assert score >= 90

    def test_weak_policy_low_score(self):
        p = parse("script-src 'self' 'unsafe-inline' 'unsafe-eval' *")
        grade, score = score_policy(p)
        assert grade in ("D", "F")
        assert score < 50

    def test_empty_policy_perfect(self):
        p = parse("")
        grade, score = score_policy(p)
        assert grade == "A+"
        assert score == 100

    def test_moderate_policy_mid_score(self):
        p = parse(
            "default-src 'self'; script-src 'self'; "
            "object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'self'"
        )
        grade, score = score_policy(p)
        assert grade in ("A+", "A", "B", "C")  # Decent policy, mostly INFO findings
        assert score >= 70


class TestSortOrder:
    def test_findings_sorted_by_severity(self):
        # A policy with multiple issues
        findings = analyze_header("script-src 'self' 'unsafe-inline' 'unsafe-eval' *")
        severities = [f.severity for f in findings]
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        values = [severity_order[s] for s in severities]
        assert values == sorted(values)


class TestWorkerSrcFallback:
    """worker-src falls back worker-src -> child-src -> script-src -> default-src."""

    def test_flags_child_src_looser_than_script_src(self):
        p = parse("script-src 'nonce-abc' 'strict-dynamic'; child-src https://cdn.evil.example")
        findings = [f for f in analyze(p) if f.directive == "worker-src"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "cdn.evil.example" in findings[0].description

    def test_flags_wildcard_child_src(self):
        p = parse("script-src 'self'; child-src *")
        assert [f for f in analyze(p) if f.directive == "worker-src"]

    def test_explicit_worker_src_suppresses_finding(self):
        p = parse("script-src 'nonce-abc'; child-src https://cdn.example; worker-src 'self'")
        assert [f for f in analyze(p) if f.directive == "worker-src"] == []

    def test_no_child_src_falls_through_without_finding(self):
        # With no child-src, workers inherit script-src itself — nothing widened.
        p = parse("script-src 'self'")
        assert [f for f in analyze(p) if f.directive == "worker-src"] == []

    def test_child_src_narrower_than_script_src_not_flagged(self):
        p = parse("script-src 'self' https://cdn.example; child-src 'self'")
        assert [f for f in analyze(p) if f.directive == "worker-src"] == []

    def test_child_src_without_any_script_src_not_flagged(self):
        # Nothing to compare against; the missing-script-src check covers this policy.
        p = parse("child-src https://cdn.example")
        assert [f for f in analyze(p) if f.directive == "worker-src"] == []

    def test_child_src_matching_script_src_not_flagged(self):
        p = parse("script-src 'self' https://cdn.example; child-src https://cdn.example")
        assert [f for f in analyze(p) if f.directive == "worker-src"] == []


class TestMetaIgnoredDirectives:
    def test_flags_frame_ancestors_in_meta_policy(self):
        p = parse_meta("default-src 'self'; frame-ancestors 'none'")
        titles = [f.title for f in analyze(p)]
        assert any("Meta-delivered policy specifies ignored directive" in t for t in titles)

    def test_meta_policy_no_longer_credited_for_frame_ancestors(self):
        """Regression: frame-ancestors in a meta tag must not suppress the clickjacking check."""
        p = parse_meta("default-src 'self'; frame-ancestors 'none'")
        titles = [f.title for f in analyze(p)]
        assert any("Missing frame-ancestors" in t for t in titles)

    def test_header_policy_not_flagged(self):
        p = parse("default-src 'self'; frame-ancestors 'none'")
        titles = [f.title for f in analyze(p)]
        assert not any("Meta-delivered" in t for t in titles)
        assert not any("Missing frame-ancestors" in t for t in titles)


class TestCheckRegistry:
    """The check ids are part of the output contract — baselines and SARIF key on them."""

    def test_ids_are_unique(self):
        from csp_toolkit.analyzer import CHECKS

        ids = [cid for cid, _ in CHECKS]
        assert len(set(ids)) == len(ids)

    def test_ids_are_slug_shaped(self):
        import re

        from csp_toolkit.analyzer import CHECKS

        for cid, _ in CHECKS:
            assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", cid), cid

    def test_every_finding_carries_a_check_id(self):
        messy = (
            "default-src *; script-src 'unsafe-inline' 'unsafe-eval' data: blob: http: "
            "https: *.googleapis.com 10.0.0.1 'unsafe-hashes'; style-src 'unsafe-inline'; "
            "child-src data: *; object-src data:"
        )
        findings = analyze(parse(messy))
        assert findings
        assert all(f.check_id for f in findings)

    def test_fingerprints_are_unique_within_one_report(self):
        """A collision would make two findings indistinguishable to a baseline."""
        messy = (
            "script-src 'self' *.googleapis.com *.cloudfront.net 10.0.0.1 192.168.1.1 http:; "
            "img-src http: 172.16.0.1; child-src data:; object-src data:"
        )
        findings = analyze(parse(messy))
        fingerprints = [f.fingerprint for f in findings]
        assert len(set(fingerprints)) == len(fingerprints)
