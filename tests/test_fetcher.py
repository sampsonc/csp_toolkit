"""Tests for CSP fetcher — mocked HTTP responses."""

from csp_toolkit.fetcher import fetch_csp


CSP_HEADER = "default-src 'self'; script-src 'self' 'nonce-abc'"
CSP_RO_HEADER = "default-src 'none'"
HTML_WITH_META = """
<html>
<head>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src *">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
</head>
<body>Hello</body>
</html>
"""
HTML_NO_META = "<html><head></head><body>Hello</body></html>"


class TestFetchCsp:
    def test_csp_header(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"content-security-policy": CSP_HEADER},
        )
        result = fetch_csp("https://example.com")
        assert result.csp_header == CSP_HEADER
        assert len(result.policies) == 1
        assert result.policies[0].has_directive("script-src")
        assert result.policies[0].report_only is False

    def test_report_only_header(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={"content-security-policy-report-only": CSP_RO_HEADER},
        )
        result = fetch_csp("https://example.com")
        assert result.csp_report_only_header == CSP_RO_HEADER
        assert len(result.policies) == 1
        assert result.policies[0].report_only is True

    def test_both_headers(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "content-security-policy": CSP_HEADER,
                "content-security-policy-report-only": CSP_RO_HEADER,
            },
        )
        result = fetch_csp("https://example.com")
        assert len(result.policies) == 2

    def test_multiple_csp_headers(self, httpx_mock):
        """Each Content-Security-Policy header field is a separate policy."""
        a = "default-src 'none'"
        b = "script-src 'self'"
        httpx_mock.add_response(
            url="https://example.com",
            headers=[
                ("content-security-policy", a),
                ("content-security-policy", b),
            ],
        )
        result = fetch_csp("https://example.com")
        assert result.csp_headers == [a, b]
        assert result.csp_header == a
        assert len(result.policies) == 2
        assert result.policies[0].has_directive("default-src")
        assert result.policies[1].has_directive("script-src")

    def test_meta_tag_extraction(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            html=HTML_WITH_META,
            headers={"content-type": "text/html; charset=utf-8"},
        )
        result = fetch_csp("https://example.com")
        assert len(result.csp_meta_tags) == 1
        assert "default-src 'self'" in result.csp_meta_tags[0]
        assert len(result.policies) == 1

    def test_no_csp(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            html=HTML_NO_META,
            headers={"content-type": "text/html"},
        )
        result = fetch_csp("https://example.com")
        assert result.csp_header is None
        assert result.csp_report_only_header is None
        assert result.csp_meta_tags == []
        assert result.policies == []

    def test_security_headers_captured(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            headers={
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            },
        )
        result = fetch_csp("https://example.com")
        assert result.security_headers["x-frame-options"] == "DENY"
        assert "strict-transport-security" in result.security_headers

    def test_status_code_and_urls(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            status_code=200,
        )
        result = fetch_csp("https://example.com")
        assert result.status_code == 200
        assert result.url == "https://example.com"

    def test_header_and_meta_combined(self, httpx_mock):
        httpx_mock.add_response(
            url="https://example.com",
            html=HTML_WITH_META,
            headers={
                "content-security-policy": CSP_HEADER,
                "content-type": "text/html",
            },
        )
        result = fetch_csp("https://example.com")
        assert len(result.policies) == 2  # One from header, one from meta
