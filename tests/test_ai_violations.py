"""Test AI-enhanced violation analysis."""

import json
from unittest.mock import Mock, patch

from csp_toolkit.violations import (
    ai_enhance_violations,
    _has_anthropic,
    _build_violation_analysis_prompt,
)
from csp_toolkit.parser import parse


class TestAIViolationEnhancement:
    """Test AI enhancement of violation analysis."""

    def test_has_anthropic_detection(self):
        """Test detection of anthropic package availability."""
        # This will test the actual availability in the test environment
        result = _has_anthropic()
        assert isinstance(result, bool)

    @patch("csp_toolkit.violations._has_anthropic")
    def test_ai_enhance_no_anthropic(self, mock_has_anthropic):
        """Test graceful handling when anthropic package is not available."""
        mock_has_anthropic.return_value = False

        violations = [
            {
                "blocked-uri": "https://example.com/script.js",
                "effective-directive": "script-src",
                "violated-directive": "script-src",
            }
        ]

        result = ai_enhance_violations(violations)

        assert result["enhanced"] is False
        assert "anthropic package not available" in result["error"]
        assert "fallback_summary" in result

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("csp_toolkit.violations._has_anthropic")
    @patch("anthropic.Anthropic")
    def test_ai_enhance_success(self, mock_anthropic_class, mock_has_anthropic):
        """Test successful AI enhancement."""
        mock_has_anthropic.return_value = True

        # Mock the anthropic client and response
        mock_client = Mock()
        mock_anthropic_class.return_value = mock_client

        mock_response = Mock()
        mock_response.content = json.dumps(
            {
                "explanation": "These violations occur because external scripts are blocked",
                "security_impact": "Medium risk - legitimate scripts are being blocked",
                "implementation_notes": [
                    "Add script sources to script-src directive",
                    "Test thoroughly before deploying",
                ],
                "risk_assessment": "medium",
            }
        )
        mock_client.messages.create.return_value = mock_response

        violations = [
            {
                "blocked-uri": "https://cdn.example.com/script.js",
                "effective-directive": "script-src",
                "violated-directive": "script-src",
            }
        ]
        policy = parse("script-src 'self'")

        result = ai_enhance_violations(violations, policy, "e-commerce")

        assert result["enhanced"] is True
        assert "explanation" in result
        assert "security_impact" in result
        assert "implementation_notes" in result
        assert "risk_assessment" in result
        assert (
            result["ai_analysis"]["explanation"]
            == "These violations occur because external scripts are blocked"
        )

    def test_build_violation_analysis_prompt(self):
        """Test prompt building for AI analysis."""
        summary = {
            "count": 5,
            "groups": [
                {
                    "blocked_uri": "https://cdn.example.com/script.js",
                    "effective_directive": "script-src",
                    "violated_directive": "script-src",
                    "count": 3,
                },
                {
                    "blocked_uri": "https://fonts.googleapis.com/css",
                    "effective_directive": "style-src",
                    "violated_directive": "style-src",
                    "count": 2,
                },
            ],
        }

        policy = parse("default-src 'self'")
        suggestions = [
            {
                "directive": "script-src",
                "suggested_source": "https://cdn.example.com",
                "action": "consider_adding_source",
            }
        ]

        prompt = _build_violation_analysis_prompt(summary, policy, suggestions, "e-commerce")

        assert "Total violations: 5" in prompt
        assert "Business Context: e-commerce" in prompt
        assert "Current CSP Policy:" in prompt
        assert "https://cdn.example.com/script.js" in prompt
        assert "implementation_notes" in prompt.lower()
        assert "security_impact" in prompt.lower()

    def test_build_prompt_no_policy(self):
        """Test prompt building without a current policy."""
        summary = {"count": 1, "groups": []}

        prompt = _build_violation_analysis_prompt(summary, None, [], None)

        assert "Total violations: 1" in prompt
        assert "Business Context: Not specified" in prompt
        assert "Current CSP Policy:" not in prompt or "Current CSP Policy: " in prompt

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("csp_toolkit.violations._has_anthropic")
    @patch("anthropic.Anthropic")
    def test_ai_enhance_api_error(self, mock_anthropic_class, mock_has_anthropic):
        """Test handling of API errors."""
        mock_has_anthropic.return_value = True

        mock_client = Mock()
        mock_anthropic_class.return_value = mock_client
        mock_client.messages.create.side_effect = Exception("API Error")

        violations = [
            {
                "blocked-uri": "test.com",
                "effective-directive": "script-src",
                "violated-directive": "script-src",
            }
        ]

        result = ai_enhance_violations(violations)

        assert result["enhanced"] is False
        assert "API Error" in result["error"]
        assert "fallback_summary" in result

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("csp_toolkit.violations._has_anthropic")
    @patch("anthropic.Anthropic")
    def test_ai_enhance_malformed_json(self, mock_anthropic_class, mock_has_anthropic):
        """Test handling of malformed JSON response."""
        mock_has_anthropic.return_value = True

        mock_client = Mock()
        mock_anthropic_class.return_value = mock_client

        mock_response = Mock()
        mock_response.content = (
            "This is not valid JSON but has useful explanation about CSP violations"
        )
        mock_client.messages.create.return_value = mock_response

        violations = [
            {
                "blocked-uri": "test.com",
                "effective-directive": "script-src",
                "violated-directive": "script-src",
            }
        ]

        result = ai_enhance_violations(violations)

        assert result["enhanced"] is True
        assert "explanation" in result["ai_analysis"]
        # Should fallback to text parsing when JSON parsing fails
        assert (
            result["ai_analysis"]["explanation"]
            == "This is not valid JSON but has useful explanation about CSP violations"
        )
