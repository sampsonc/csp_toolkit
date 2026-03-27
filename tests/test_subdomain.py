"""Tests for subdomain CSP variance detection."""

from csp_toolkit.subdomain import DEFAULT_PREFIXES, check_subdomains


class TestDefaults:
    def test_has_common_prefixes(self):
        assert "www" in DEFAULT_PREFIXES
        assert "api" in DEFAULT_PREFIXES
        assert "app" in DEFAULT_PREFIXES
        assert "staging" in DEFAULT_PREFIXES
        assert "admin" in DEFAULT_PREFIXES

    def test_reasonable_prefix_count(self):
        # Should have enough to be useful but not too many
        assert 20 <= len(DEFAULT_PREFIXES) <= 60


class TestCheckSubdomains:
    def test_unreachable_domain_returns_empty(self):
        results = check_subdomains(
            "this-domain-does-not-exist-12345.com",
            prefixes=["www"],
            timeout=2.0,
        )
        assert len(results) == 0

    def test_strips_scheme(self):
        # Should handle "https://example.com" input
        results = check_subdomains(
            "https://this-domain-does-not-exist-12345.com",
            prefixes=["www"],
            timeout=2.0,
        )
        assert len(results) == 0  # Just verify no crash

    def test_custom_prefixes(self):
        results = check_subdomains(
            "this-domain-does-not-exist-12345.com",
            prefixes=["www", "api"],
            timeout=2.0,
        )
        # All unreachable, so empty
        assert len(results) == 0
