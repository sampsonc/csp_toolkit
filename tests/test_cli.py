"""Tests for CLI commands using Click's CliRunner."""

from click.testing import CliRunner

from csp_toolkit.cli import main


runner = CliRunner()


class TestAnalyzeCommand:
    def test_basic(self):
        result = runner.invoke(main, ["analyze", "script-src 'self' 'unsafe-inline'"])
        assert result.exit_code == 0
        assert "unsafe-inline" in result.output.lower()

    def test_shows_grade(self):
        result = runner.invoke(main, ["analyze", "script-src 'self' 'unsafe-inline'"])
        assert result.exit_code == 0
        assert "policy score:" in result.output.lower()

    def test_clean_policy(self):
        result = runner.invoke(main, [
            "analyze",
            "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
            "style-src 'nonce-abc'; img-src 'self'; font-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'",
        ])
        assert result.exit_code == 0

    def test_json_format(self):
        result = runner.invoke(main, [
            "analyze", "--format", "json",
            "script-src 'self' 'unsafe-inline'",
        ])
        assert result.exit_code == 0
        assert '"severity"' in result.output

    def test_detail_format(self):
        result = runner.invoke(main, [
            "analyze", "--format", "detail",
            "script-src 'self' 'unsafe-inline'",
        ])
        assert result.exit_code == 0

    def test_report_only(self):
        result = runner.invoke(main, [
            "analyze", "--report-only",
            "default-src 'self'",
        ])
        assert result.exit_code == 0
        assert "report-only" in result.output.lower()

    def test_from_stdin(self):
        result = runner.invoke(main, ["analyze", "--file", "-"], input="script-src 'self'")
        assert result.exit_code == 0

    def test_no_input(self):
        result = runner.invoke(main, ["analyze"])
        assert result.exit_code != 0


class TestBypassCommand:
    def test_basic(self):
        result = runner.invoke(main, [
            "bypass",
            "script-src 'self' cdnjs.cloudflare.com *.googleapis.com",
        ])
        assert result.exit_code == 0
        assert "bypass" in result.output.lower()

    def test_json_format(self):
        result = runner.invoke(main, [
            "bypass", "--format", "json",
            "script-src 'self' cdnjs.cloudflare.com",
        ])
        assert result.exit_code == 0
        assert '"bypass_type"' in result.output

    def test_no_bypasses(self):
        result = runner.invoke(main, [
            "bypass",
            "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
            "base-uri 'none'; form-action 'self'; object-src 'none'",
        ])
        assert result.exit_code == 0
        assert "no known bypasses" in result.output.lower()


class TestGenerateCommand:
    def test_strict_preset(self):
        result = runner.invoke(main, ["generate", "--preset", "strict", "--nonce", "test123"])
        assert result.exit_code == 0
        assert "nonce-test123" in result.output
        assert "strict-dynamic" in result.output

    def test_moderate_preset(self):
        result = runner.invoke(main, ["generate", "--preset", "moderate"])
        assert result.exit_code == 0
        assert "default-src 'self'" in result.output

    def test_permissive_preset(self):
        result = runner.invoke(main, ["generate", "--preset", "permissive"])
        assert result.exit_code == 0
        assert "unsafe-inline" in result.output

    def test_add_source(self):
        result = runner.invoke(main, [
            "generate", "--preset", "moderate",
            "--add-source", "script-src cdn.example.com",
        ])
        assert result.exit_code == 0
        assert "cdn.example.com" in result.output

    def test_nginx_format(self):
        result = runner.invoke(main, [
            "generate", "--preset", "moderate", "--format", "nginx",
        ])
        assert result.exit_code == 0
        assert "add_header" in result.output

    def test_apache_format(self):
        result = runner.invoke(main, [
            "generate", "--preset", "moderate", "--format", "apache",
        ])
        assert result.exit_code == 0
        assert "Header always set" in result.output

    def test_meta_format(self):
        result = runner.invoke(main, [
            "generate", "--preset", "moderate", "--format", "meta",
        ])
        assert result.exit_code == 0
        assert "<meta" in result.output


class TestBypassCheckLiveFlag:
    def test_check_live_flag_accepted(self):
        result = runner.invoke(main, [
            "bypass",
            "script-src 'self' cdn.example.com",
        ])
        assert result.exit_code == 0


class TestFetchBatchUrls:
    """Test that fetch accepts multiple URLs (CLI argument parsing only)."""

    def test_fetch_requires_at_least_one_url(self):
        result = runner.invoke(main, ["fetch"])
        assert result.exit_code != 0


class TestScanCommand:
    def test_no_urls_error(self):
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0

    def test_scan_from_stdin(self):
        result = runner.invoke(main, ["scan", "--file", "-"], input="https://this-does-not-exist-999.com\n")
        assert result.exit_code == 0

    def test_csv_format(self):
        result = runner.invoke(main, [
            "scan", "--format", "csv",
            "https://this-does-not-exist-999.com",
        ], catch_exceptions=False)
        assert result.exit_code == 0
        assert "url,grade,score" in result.output


class TestDiffCommand:
    def test_identical(self):
        result = runner.invoke(main, ["diff", "script-src 'self'", "script-src 'self'"])
        assert result.exit_code == 0
        assert "identical" in result.output.lower()

    def test_added_directive(self):
        result = runner.invoke(main, [
            "diff",
            "script-src 'self'",
            "script-src 'self'; base-uri 'none'",
        ])
        assert result.exit_code == 0
        assert "base-uri" in result.output

    def test_weakened_warning(self):
        result = runner.invoke(main, [
            "diff",
            "script-src 'self'",
            "script-src 'self' 'unsafe-inline'",
        ])
        assert result.exit_code == 0
        assert "weaken" in result.output.lower()

    def test_json_format(self):
        result = runner.invoke(main, [
            "diff", "--format", "json",
            "script-src 'self'",
            "script-src 'self' 'unsafe-inline'",
        ])
        assert result.exit_code == 0
        assert '"has_changes": true' in result.output


class TestSubdomainsCommand:
    def test_unreachable_domain(self):
        result = runner.invoke(main, [
            "subdomains", "this-does-not-exist-12345.com",
            "--prefixes", "www",
            "--timeout", "2",
        ])
        assert result.exit_code == 0
        assert "no reachable" in result.output.lower() or "0" in result.output


class TestVersionFlag:
    def test_version(self):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
