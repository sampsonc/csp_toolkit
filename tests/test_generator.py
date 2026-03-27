"""Tests for CSP generator — builder and presets."""

from csp_toolkit.generator import CSPBuilder
from csp_toolkit.parser import parse
from csp_toolkit.analyzer import analyze
from csp_toolkit.models import Severity


class TestCSPBuilder:
    def test_add_directive(self):
        csp = CSPBuilder().add_directive("script-src", "'self'").build()
        assert csp == "script-src 'self'"

    def test_multiple_directives(self):
        csp = (
            CSPBuilder()
            .add_directive("script-src", "'self'")
            .add_directive("style-src", "'none'")
            .build()
        )
        assert "script-src 'self'" in csp
        assert "style-src 'none'" in csp

    def test_add_source(self):
        csp = (
            CSPBuilder()
            .add_directive("script-src", "'self'")
            .add_source("script-src", "cdn.example.com")
            .build()
        )
        assert "script-src 'self' cdn.example.com" in csp

    def test_add_source_no_duplicate(self):
        csp = (
            CSPBuilder()
            .add_directive("script-src", "'self'")
            .add_source("script-src", "'self'")
            .build()
        )
        assert csp.count("'self'") == 1

    def test_add_source_creates_directive(self):
        csp = CSPBuilder().add_source("script-src", "'self'").build()
        assert "script-src 'self'" in csp

    def test_remove_directive(self):
        csp = (
            CSPBuilder()
            .add_directive("script-src", "'self'")
            .add_directive("style-src", "'none'")
            .remove_directive("style-src")
            .build()
        )
        assert "style-src" not in csp
        assert "script-src" in csp

    def test_remove_source(self):
        csp = (
            CSPBuilder()
            .add_directive("script-src", "'self'", "'unsafe-inline'")
            .remove_source("script-src", "'unsafe-inline'")
            .build()
        )
        assert "'unsafe-inline'" not in csp
        assert "'self'" in csp

    def test_set_report_uri(self):
        csp = (
            CSPBuilder()
            .add_directive("default-src", "'self'")
            .set_report_uri("/csp-report")
            .build()
        )
        assert "report-uri /csp-report" in csp

    def test_set_report_to(self):
        csp = (
            CSPBuilder()
            .add_directive("default-src", "'self'")
            .set_report_to("csp-endpoint")
            .build()
        )
        assert "report-to csp-endpoint" in csp

    def test_directive_without_sources(self):
        csp = CSPBuilder().add_directive("upgrade-insecure-requests").build()
        assert csp == "upgrade-insecure-requests"

    def test_build_meta(self):
        meta = CSPBuilder().add_directive("default-src", "'self'").build_meta()
        assert '<meta http-equiv="Content-Security-Policy"' in meta
        assert "default-src 'self'" in meta

    def test_build_nginx(self):
        nginx = CSPBuilder().add_directive("default-src", "'self'").build_nginx()
        assert "add_header Content-Security-Policy" in nginx
        assert "always;" in nginx

    def test_build_apache(self):
        apache = CSPBuilder().add_directive("default-src", "'self'").build_apache()
        assert "Header always set Content-Security-Policy" in apache

    def test_copy(self):
        original = CSPBuilder().add_directive("script-src", "'self'")
        copied = original.copy().add_source("script-src", "cdn.example.com")
        assert "cdn.example.com" not in original.build()
        assert "cdn.example.com" in copied.build()


class TestPresets:
    def test_strict_roundtrip(self):
        csp_str = CSPBuilder.strict(nonce="testnonce").build()
        policy = parse(csp_str)
        assert policy.has_directive("script-src")
        assert policy.has_directive("default-src")
        assert policy.has_directive("base-uri")
        assert policy.has_directive("form-action")
        assert policy.has_directive("frame-ancestors")
        assert policy.has_directive("object-src")
        # Should have nonce
        script_src = policy.get_directive("script-src")
        assert script_src.has_source("'nonce-testnonce'")
        assert script_src.has_source("'strict-dynamic'")

    def test_strict_no_critical_findings(self):
        csp_str = CSPBuilder.strict(nonce="testnonce").build()
        policy = parse(csp_str)
        findings = analyze(policy)
        critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical == [], f"Strict preset has critical/high findings: {critical}"

    def test_strict_generates_random_nonce(self):
        csp1 = CSPBuilder.strict().build()
        csp2 = CSPBuilder.strict().build()
        assert csp1 != csp2  # Different nonces

    def test_moderate_roundtrip(self):
        csp_str = CSPBuilder.moderate().build()
        policy = parse(csp_str)
        assert policy.has_directive("script-src")
        assert policy.has_directive("object-src")
        assert policy.get_directive("object-src").has_source("'none'")

    def test_moderate_no_critical_findings(self):
        csp_str = CSPBuilder.moderate().build()
        policy = parse(csp_str)
        findings = analyze(policy)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical == []

    def test_permissive_roundtrip(self):
        csp_str = CSPBuilder.permissive().build()
        policy = parse(csp_str)
        assert policy.has_directive("script-src")
        script_src = policy.get_directive("script-src")
        assert script_src.has_source("'unsafe-inline'")
        assert script_src.has_source("'unsafe-eval'")

    def test_permissive_has_object_src_none(self):
        csp_str = CSPBuilder.permissive().build()
        policy = parse(csp_str)
        assert policy.get_directive("object-src").has_source("'none'")
