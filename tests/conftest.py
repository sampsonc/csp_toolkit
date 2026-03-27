"""Shared test fixtures — sample CSP headers."""

import pytest

from csp_toolkit.parser import parse


SAMPLE_POLICIES = {
    "strict": (
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
    ),
    "weak": "script-src 'self' 'unsafe-inline' 'unsafe-eval' *",
    "google_bypass": "script-src 'self' accounts.google.com *.googleapis.com",
    "cdn_gadget": "script-src 'self' cdnjs.cloudflare.com",
    "missing_directives": "default-src 'self'",
    "data_uri": "script-src 'self' data:",
    "blob_uri": "script-src 'self' blob:",
    "empty": "",
    "report_only": "default-src 'self'; report-uri /csp-report",
    "nonce_and_hash": (
        "script-src 'nonce-r4nd0m' 'sha256-abc123def456' 'strict-dynamic'"
    ),
    "multiple_directives": (
        "default-src 'none'; "
        "script-src 'self' https://cdn.example.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.googleapis.com; "
        "connect-src 'self' https://api.example.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}


@pytest.fixture(params=SAMPLE_POLICIES.keys())
def sample_policy_name(request):
    return request.param


@pytest.fixture
def sample_policy(sample_policy_name):
    return parse(SAMPLE_POLICIES[sample_policy_name])


@pytest.fixture
def strict_policy():
    return parse(SAMPLE_POLICIES["strict"])


@pytest.fixture
def weak_policy():
    return parse(SAMPLE_POLICIES["weak"])
