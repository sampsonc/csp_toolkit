"""Tests for active probes — nonce reuse, header injection, report-uri analysis."""

from csp_toolkit.probes import (
    NonceReuseStatus,
    analyze_report_uri,
    check_header_injection,
    detect_nonce_reuse,
)
from csp_toolkit.parser import parse


class TestNonceReuse:
    def test_unreachable_is_fetch_failed(self):
        result = detect_nonce_reuse(
            "https://this-does-not-exist-99999.com",
            num_requests=2,
            timeout=2.0,
        )
        assert result.status == NonceReuseStatus.FETCH_FAILED
        assert result.http_responses == 0
        assert result.last_error is not None
        assert not result

    def test_csp_without_nonce(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"content-security-policy": "default-src 'self'"},
        )
        result = detect_nonce_reuse("https://example.com", num_requests=1)
        assert result.status == NonceReuseStatus.NO_NONCE
        assert result.http_responses == 1
        assert not result

    def test_nonce_bool_like_legacy(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"content-security-policy": "script-src 'nonce-abc'"},
        )
        result = detect_nonce_reuse("https://example.com", num_requests=1)
        assert result.status == NonceReuseStatus.ANALYZED
        assert bool(result)


class TestHeaderInjection:
    def test_unreachable_returns_not_vulnerable(self):
        result = check_header_injection(
            "https://this-does-not-exist-99999.com",
            timeout=2.0,
        )
        assert result.vulnerable is False


class TestReportUriAnalysis:
    def test_no_report_uri(self):
        policy = parse("script-src 'self'")
        result = analyze_report_uri(policy)
        assert result.report_uri is None
        assert result.report_to is None

    def test_with_report_uri(self):
        policy = parse("script-src 'self'; report-uri /csp-report")
        result = analyze_report_uri(policy)
        assert result.report_uri == "/csp-report"
        # /csp-report is relative, not an absolute URL, so reachability isn't tested
        assert result.uri_reachable is None

    def test_with_report_to(self):
        policy = parse("script-src 'self'; report-to csp-endpoint")
        result = analyze_report_uri(policy)
        assert result.report_to == "csp-endpoint"

    def test_with_absolute_report_uri_unreachable(self):
        policy = parse("script-src 'self'; report-uri https://this-does-not-exist-99999.com/csp")
        result = analyze_report_uri(policy, timeout=2.0)
        assert result.report_uri == "https://this-does-not-exist-99999.com/csp"
        assert result.uri_reachable is False
