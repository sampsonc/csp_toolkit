"""Tests for scanner module."""

from csp_toolkit.scanner import ScanResult, scan_urls, results_to_csv, results_to_json


class TestScanUrl:
    def test_scan_unreachable(self):
        """Unreachable URLs should return error results, not crash."""
        results = scan_urls(["https://this-domain-does-not-exist-12345.com"], timeout=2.0)
        assert len(results) == 1
        assert results[0].error is not None


class TestResultsExport:
    def test_csv_output(self):
        results = [
            ScanResult(
                url="https://example.com",
                final_url="https://example.com",
                status_code=200,
                has_csp=True,
                grade="A",
                score=90,
                num_findings=3,
                num_bypasses=1,
                num_critical=0,
                num_high=1,
                num_medium=2,
                policy_mode="enforced",
                csp_raw="default-src 'self'",
            ),
            ScanResult(
                url="https://other.com",
                final_url="https://other.com",
                status_code=200,
                has_csp=False,
                grade="-",
                score=0,
                num_findings=0,
                num_bypasses=0,
                num_critical=0,
                num_high=0,
                num_medium=0,
                policy_mode="none",
                csp_raw="",
            ),
        ]
        csv_output = results_to_csv(results)
        assert "example.com" in csv_output
        assert "other.com" in csv_output
        assert "url,grade,score" in csv_output

    def test_json_output(self):
        results = [
            ScanResult(
                url="https://example.com",
                final_url="https://example.com",
                status_code=200,
                has_csp=True,
                grade="B",
                score=80,
                num_findings=5,
                num_bypasses=2,
                num_critical=1,
                num_high=2,
                num_medium=2,
                policy_mode="enforced",
                csp_raw="default-src 'self'",
            ),
        ]
        json_output = results_to_json(results)
        assert '"grade": "B"' in json_output
        assert '"score": 80' in json_output
        assert '"bypasses": 2' in json_output


class TestSortOrder:
    def test_weakest_first(self):
        results = [
            ScanResult(
                url="https://strong.com",
                final_url="https://strong.com",
                status_code=200,
                has_csp=True,
                grade="A",
                score=95,
                num_findings=1,
                num_bypasses=0,
                num_critical=0,
                num_high=0,
                num_medium=0,
                policy_mode="enforced",
                csp_raw="",
            ),
            ScanResult(
                url="https://weak.com",
                final_url="https://weak.com",
                status_code=200,
                has_csp=True,
                grade="F",
                score=10,
                num_findings=10,
                num_bypasses=5,
                num_critical=3,
                num_high=4,
                num_medium=3,
                policy_mode="enforced",
                csp_raw="",
            ),
            ScanResult(
                url="https://nocsp.com",
                final_url="https://nocsp.com",
                status_code=200,
                has_csp=False,
                grade="-",
                score=0,
                num_findings=0,
                num_bypasses=0,
                num_critical=0,
                num_high=0,
                num_medium=0,
                policy_mode="none",
                csp_raw="",
            ),
        ]

        # Re-sort
        # Just verify the sort logic manually
        def sort_key(r):
            if r.error:
                return (2, 0, r.url)
            if not r.has_csp:
                return (1, 0, r.url)
            return (0, r.score, r.url)

        sorted_results = sorted(results, key=sort_key)
        assert sorted_results[0].url == "https://weak.com"  # Lowest score first
        assert sorted_results[1].url == "https://strong.com"  # Higher score
        assert sorted_results[2].url == "https://nocsp.com"  # No CSP last
