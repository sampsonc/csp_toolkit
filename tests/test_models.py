"""Tests for CSP models — Source, Directive, Policy, Finding."""

from csp_toolkit.models import (
    Directive,
    Finding,
    Policy,
    Severity,
    Source,
    SourceType,
    classify_source,
)


class TestClassifySource:
    def test_wildcard(self):
        assert classify_source("*") == SourceType.WILDCARD

    def test_keywords(self):
        assert classify_source("'self'") == SourceType.KEYWORD
        assert classify_source("'none'") == SourceType.KEYWORD
        assert classify_source("'unsafe-inline'") == SourceType.KEYWORD
        assert classify_source("'unsafe-eval'") == SourceType.KEYWORD
        assert classify_source("'strict-dynamic'") == SourceType.KEYWORD
        assert classify_source("'unsafe-hashes'") == SourceType.KEYWORD
        assert classify_source("'wasm-unsafe-eval'") == SourceType.KEYWORD

    def test_schemes(self):
        assert classify_source("https:") == SourceType.SCHEME
        assert classify_source("http:") == SourceType.SCHEME
        assert classify_source("data:") == SourceType.SCHEME
        assert classify_source("blob:") == SourceType.SCHEME

    def test_nonce(self):
        assert classify_source("'nonce-abc123'") == SourceType.NONCE
        assert classify_source("'nonce-r4nd0m+/='") == SourceType.NONCE
        assert classify_source("'nonce-YWJj_MTIz-'") == SourceType.NONCE

    def test_hash(self):
        assert classify_source("'sha256-abc123def456'") == SourceType.HASH
        assert classify_source("'sha384-abc123def456'") == SourceType.HASH
        assert classify_source("'sha512-abc123def456'") == SourceType.HASH

    def test_host(self):
        assert classify_source("example.com") == SourceType.HOST
        assert classify_source("*.example.com") == SourceType.HOST
        assert classify_source("https://cdn.example.com") == SourceType.HOST
        assert classify_source("https://cdn.example.com:443") == SourceType.HOST

    def test_case_insensitive_keywords(self):
        assert classify_source("'SELF'") == SourceType.KEYWORD
        assert classify_source("'Unsafe-Inline'") == SourceType.KEYWORD


class TestSource:
    def test_from_string(self):
        s = Source.from_string("'self'")
        assert s.raw == "'self'"
        assert s.source_type == SourceType.KEYWORD
        assert s.is_keyword is True
        assert s.is_host is False

    def test_host_source(self):
        s = Source.from_string("cdn.example.com")
        assert s.is_host is True
        assert s.is_keyword is False

    def test_str(self):
        s = Source.from_string("'unsafe-inline'")
        assert str(s) == "'unsafe-inline'"


class TestDirective:
    def test_from_tokens(self):
        d = Directive.from_tokens("script-src", ["'self'", "cdn.example.com"])
        assert d.name == "script-src"
        assert len(d.sources) == 2
        assert d.sources[0].raw == "'self'"
        assert d.sources[1].raw == "cdn.example.com"

    def test_has_source(self):
        d = Directive.from_tokens("script-src", ["'self'", "'unsafe-inline'"])
        assert d.has_source("'self'") is True
        assert d.has_source("'SELF'") is True
        assert d.has_source("'none'") is False

    def test_host_sources(self):
        d = Directive.from_tokens("script-src", ["'self'", "cdn.example.com", "*.foo.com"])
        hosts = d.host_sources()
        assert len(hosts) == 2
        assert hosts[0].raw == "cdn.example.com"
        assert hosts[1].raw == "*.foo.com"

    def test_str(self):
        d = Directive.from_tokens("script-src", ["'self'", "'unsafe-inline'"])
        assert str(d) == "script-src 'self' 'unsafe-inline'"

    def test_str_no_sources(self):
        d = Directive.from_tokens("upgrade-insecure-requests", [])
        assert str(d) == "upgrade-insecure-requests"

    def test_name_normalized_lowercase(self):
        d = Directive.from_tokens("Script-Src", ["'self'"])
        assert d.name == "script-src"


class TestPolicy:
    def test_get_directive(self):
        d = Directive.from_tokens("script-src", ["'self'"])
        p = Policy(raw="script-src 'self'", directives={"script-src": d})
        assert p.get_directive("script-src") is d
        assert p.get_directive("style-src") is None

    def test_has_directive(self):
        d = Directive.from_tokens("script-src", ["'self'"])
        p = Policy(raw="script-src 'self'", directives={"script-src": d})
        assert p.has_directive("script-src") is True
        assert p.has_directive("style-src") is False

    def test_effective_directive_direct(self):
        d = Directive.from_tokens("script-src", ["'self'"])
        p = Policy(raw="script-src 'self'", directives={"script-src": d})
        assert p.effective_directive("script-src") is d

    def test_effective_directive_fallback_to_default_src(self):
        default = Directive.from_tokens("default-src", ["'self'"])
        p = Policy(raw="default-src 'self'", directives={"default-src": default})
        # Fetch directives fall back to default-src
        assert p.effective_directive("script-src") is default
        assert p.effective_directive("img-src") is default
        assert p.effective_directive("style-src") is default

    def test_effective_directive_no_fallback_for_non_fetch(self):
        default = Directive.from_tokens("default-src", ["'self'"])
        p = Policy(raw="default-src 'self'", directives={"default-src": default})
        # Non-fetch directives do NOT fall back
        assert p.effective_directive("frame-ancestors") is None
        assert p.effective_directive("form-action") is None
        assert p.effective_directive("base-uri") is None

    def test_effective_sources(self):
        default = Directive.from_tokens("default-src", ["'self'", "cdn.example.com"])
        p = Policy(raw="default-src 'self' cdn.example.com", directives={"default-src": default})
        sources = p.effective_sources("script-src")
        assert len(sources) == 2
        assert sources[0].raw == "'self'"

    def test_effective_sources_empty_when_missing(self):
        p = Policy(raw="", directives={})
        assert p.effective_sources("script-src") == []
        assert p.effective_sources("form-action") == []

    def test_str(self):
        d1 = Directive.from_tokens("script-src", ["'self'"])
        d2 = Directive.from_tokens("style-src", ["'none'"])
        p = Policy(raw="", directives={"script-src": d1, "style-src": d2})
        assert str(p) == "script-src 'self'; style-src 'none'"


class TestFinding:
    def test_str_with_directive(self):
        f = Finding(
            severity=Severity.CRITICAL,
            title="unsafe-inline allows arbitrary inline scripts",
            description="...",
            directive="script-src",
        )
        assert "[CRITICAL]" in str(f)
        assert "script-src" in str(f)

    def test_str_without_directive(self):
        f = Finding(
            severity=Severity.INFO,
            title="Policy is report-only",
            description="...",
        )
        assert "[INFO]" in str(f)
        assert "report-only" in str(f)
