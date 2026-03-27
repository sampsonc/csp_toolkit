"""Tests for CSP diff module."""

from csp_toolkit.diff import diff_headers, diff_policies
from csp_toolkit.parser import parse


class TestDiffPolicies:
    def test_identical_policies(self):
        result = diff_headers("script-src 'self'", "script-src 'self'")
        assert not result.has_changes
        assert result.unchanged_directives == ["script-src"]

    def test_added_directive(self):
        result = diff_headers(
            "script-src 'self'",
            "script-src 'self'; base-uri 'none'",
        )
        assert result.has_changes
        assert len(result.added_directives) == 1
        assert result.added_directives[0].directive == "base-uri"
        assert "'none'" in result.added_directives[0].new_sources

    def test_removed_directive(self):
        result = diff_headers(
            "script-src 'self'; base-uri 'none'",
            "script-src 'self'",
        )
        assert result.has_changes
        assert len(result.removed_directives) == 1
        assert result.removed_directives[0].directive == "base-uri"

    def test_modified_directive_added_source(self):
        result = diff_headers(
            "script-src 'self'",
            "script-src 'self' cdn.example.com",
        )
        assert result.has_changes
        assert len(result.modified_directives) == 1
        mod = result.modified_directives[0]
        assert mod.directive == "script-src"
        assert "cdn.example.com" in mod.added_sources
        assert mod.removed_sources == []

    def test_modified_directive_removed_source(self):
        result = diff_headers(
            "script-src 'self' 'unsafe-inline'",
            "script-src 'self'",
        )
        assert result.has_changes
        mod = result.modified_directives[0]
        assert "'unsafe-inline'" in mod.removed_sources

    def test_weakened_detection(self):
        result = diff_headers(
            "script-src 'self'",
            "script-src 'self' 'unsafe-inline'",
        )
        assert len(result.weakened) >= 1

    def test_strengthened_detection(self):
        result = diff_headers(
            "script-src 'self' 'unsafe-inline'",
            "script-src 'self'",
        )
        assert len(result.strengthened) >= 1

    def test_removed_directive_is_weakening(self):
        result = diff_headers(
            "script-src 'self'; base-uri 'none'; object-src 'none'",
            "script-src 'self'",
        )
        weakened = result.weakened
        directives = [c.directive for c in weakened]
        assert "base-uri" in directives
        assert "object-src" in directives

    def test_added_directive_is_strengthening(self):
        result = diff_headers(
            "script-src 'self'",
            "script-src 'self'; base-uri 'none'; object-src 'none'",
        )
        strengthened = result.strengthened
        directives = [c.directive for c in strengthened]
        assert "base-uri" in directives
        assert "object-src" in directives

    def test_complex_diff(self):
        old = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self'; object-src 'none'"
        )
        new = (
            "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; "
            "style-src 'self' 'unsafe-inline'; base-uri 'none'; object-src 'none'"
        )
        result = diff_headers(old, new)
        assert result.has_changes
        assert len(result.added_directives) == 1  # base-uri
        assert len(result.modified_directives) == 2  # script-src, style-src
        assert len(result.unchanged_directives) == 2  # default-src, object-src

    def test_wildcard_weakening(self):
        result = diff_headers(
            "script-src 'self'",
            "script-src 'self' *.example.com",
        )
        assert len(result.weakened) >= 1

    def test_empty_to_policy(self):
        result = diff_headers("", "script-src 'self'")
        assert result.has_changes
        assert len(result.added_directives) == 1

    def test_policy_to_empty(self):
        result = diff_headers("script-src 'self'", "")
        assert result.has_changes
        assert len(result.removed_directives) == 1
