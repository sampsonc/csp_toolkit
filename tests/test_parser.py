"""Tests for CSP parser."""

from csp_toolkit.models import SourceType
from csp_toolkit.parser import parse, parse_meta


class TestParse:
    def test_empty_string(self):
        p = parse("")
        assert p.directives == {}
        assert p.report_only is False

    def test_single_directive(self):
        p = parse("script-src 'self'")
        assert "script-src" in p.directives
        d = p.directives["script-src"]
        assert len(d.sources) == 1
        assert d.sources[0].raw == "'self'"

    def test_multiple_directives(self):
        p = parse("script-src 'self'; style-src 'none'; img-src *")
        assert len(p.directives) == 3
        assert "script-src" in p.directives
        assert "style-src" in p.directives
        assert "img-src" in p.directives

    def test_multiple_sources(self):
        p = parse("script-src 'self' cdn.example.com https://other.com 'unsafe-inline'")
        d = p.directives["script-src"]
        assert len(d.sources) == 4
        assert d.sources[0].source_type == SourceType.KEYWORD
        assert d.sources[1].source_type == SourceType.HOST
        assert d.sources[2].source_type == SourceType.HOST
        assert d.sources[3].source_type == SourceType.KEYWORD

    def test_directive_no_sources(self):
        p = parse("upgrade-insecure-requests")
        assert "upgrade-insecure-requests" in p.directives
        assert len(p.directives["upgrade-insecure-requests"].sources) == 0

    def test_duplicate_directives_first_wins(self):
        p = parse("script-src 'self'; script-src 'none'")
        d = p.directives["script-src"]
        assert d.has_source("'self'")
        assert not d.has_source("'none'")

    def test_trailing_semicolons(self):
        p = parse("script-src 'self'; ; ; style-src 'none';")
        assert len(p.directives) == 2

    def test_extra_whitespace(self):
        p = parse("  script-src   'self'   cdn.example.com  ;  style-src   'none'  ")
        assert len(p.directives) == 2
        d = p.directives["script-src"]
        assert len(d.sources) == 2

    def test_report_only_flag(self):
        p = parse("default-src 'self'", report_only=True)
        assert p.report_only is True

    def test_nonce_source(self):
        p = parse("script-src 'nonce-abc123'")
        d = p.directives["script-src"]
        assert d.sources[0].source_type == SourceType.NONCE

    def test_hash_source(self):
        p = parse("script-src 'sha256-abcdef123456'")
        d = p.directives["script-src"]
        assert d.sources[0].source_type == SourceType.HASH

    def test_scheme_sources(self):
        p = parse("img-src https: data:")
        d = p.directives["img-src"]
        assert d.sources[0].source_type == SourceType.SCHEME
        assert d.sources[1].source_type == SourceType.SCHEME

    def test_wildcard(self):
        p = parse("img-src *")
        d = p.directives["img-src"]
        assert d.sources[0].source_type == SourceType.WILDCARD

    def test_preserves_raw(self):
        raw = "script-src 'self'; style-src 'none'"
        p = parse(raw)
        assert p.raw == raw

    def test_directive_name_case_insensitive(self):
        p = parse("Script-Src 'self'")
        assert "script-src" in p.directives

    def test_complex_real_world_policy(self):
        csp = (
            "default-src 'none'; "
            "script-src 'self' 'nonce-r4nd0m' 'strict-dynamic' https://cdn.example.com; "
            "style-src 'self' 'sha256-abc123'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' https://api.example.com wss://ws.example.com; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "report-uri /csp-violation; "
            "report-to csp-endpoint"
        )
        p = parse(csp)
        assert len(p.directives) == 12
        assert p.directives["script-src"].has_source("'strict-dynamic'")
        assert p.directives["object-src"].has_source("'none'")
        assert p.directives["frame-ancestors"].has_source("'none'")


class TestParseMeta:
    def test_basic(self):
        p = parse_meta("default-src 'self'; script-src 'nonce-abc'")
        assert p.report_only is False
        assert len(p.directives) == 2
