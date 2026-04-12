"""Parse, summarize, and suggest fixes for CSP violation reports."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from .models import Policy


def parse_violations_json(text: str) -> list[dict[str, Any]]:
    """Parse JSON containing one or more CSP reports.

    Accepts a single object, an array, or objects wrapped in ``csp-report`` (reporting API shape).
    """
    data = json.loads(text)
    items: list[Any]
    if isinstance(data, list):
        items = data
    else:
        items = [data]
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and "csp-report" in item:
            inner = item["csp-report"]
            if isinstance(inner, dict):
                out.append(inner)
        elif isinstance(item, dict):
            out.append(item)
    return out


def group_violations(
    violations: list[dict[str, Any]],
) -> list[tuple[tuple[str, str, str], int]]:
    """Group by (blocked-uri, effective-directive, violated-directive) with counts."""
    keys: list[tuple[str, str, str]] = []
    for v in violations:
        bu = str(v.get("blocked-uri") or v.get("blocked_uri") or "")
        ed = str(v.get("effective-directive") or v.get("effective_directive") or "")
        vd = str(v.get("violated-directive") or v.get("violated_directive") or "")
        keys.append((bu, ed, vd))
    return Counter(keys).most_common()


def violations_summary_json(violations: list[dict[str, Any]]) -> dict[str, Any]:
    """Structured summary for JSON output."""
    grouped = group_violations(violations)
    return {
        "count": len(violations),
        "groups": [
            {"blocked_uri": bu, "effective_directive": ed, "violated_directive": vd, "count": c}
            for (bu, ed, vd), c in grouped
        ],
    }


def suggest_violation_fixes(
    violations: list[dict[str, Any]], policy: Policy
) -> list[dict[str, str | bool | int]]:
    """Suggest minimal policy updates based on grouped violations and current policy."""
    grouped = group_violations(violations)
    suggestions: list[dict[str, str | bool | int]] = []
    for (blocked_uri, effective_directive, violated_directive), count in grouped:
        directive_name = (effective_directive or violated_directive or "").split()[0]
        if not directive_name:
            continue
        source = _blocked_uri_to_source(blocked_uri, directive_name)
        if source is None:
            suggestions.append(
                {
                    "directive": directive_name,
                    "blocked_uri": blocked_uri or "",
                    "count": count,
                    "suggested_source": "",
                    "already_allowed": False,
                    "action": "manual_review",
                    "reason": "Cannot infer safe source expression from blocked-uri.",
                }
            )
            continue

        existing = policy.effective_directive(directive_name)
        already_allowed = existing is not None and existing.has_source(source)
        action = "none" if already_allowed else "consider_adding_source"
        reason = (
            "Source already present in effective directive."
            if already_allowed
            else "Violation indicates this source is currently blocked."
        )
        suggestions.append(
            {
                "directive": directive_name,
                "blocked_uri": blocked_uri or "",
                "count": count,
                "suggested_source": source,
                "already_allowed": already_allowed,
                "action": action,
                "reason": reason,
            }
        )
    return suggestions


def build_patched_csp(policy: Policy, suggestions: list[dict[str, str | bool | int]]) -> str:
    """Build a patched CSP draft by applying additive suggestions."""
    directives: dict[str, list[str]] = {
        name: [s.raw for s in directive.sources] for name, directive in policy.directives.items()
    }

    for s in suggestions:
        action = str(s.get("action") or "")
        if action != "consider_adding_source":
            continue
        directive = str(s.get("directive") or "").strip().lower()
        source = str(s.get("suggested_source") or "").strip()
        if not directive or not source:
            continue

        # If directive only exists via default-src fallback, materialize explicit directive first.
        if directive not in directives:
            fallback = policy.effective_directive(directive)
            directives[directive] = [src.raw for src in fallback.sources] if fallback else []

        if source not in directives[directive]:
            directives[directive].append(source)

    parts: list[str] = []
    for name in sorted(directives.keys()):
        sources = directives[name]
        if sources:
            parts.append(f"{name} {' '.join(sources)}")
        else:
            parts.append(name)
    return "; ".join(parts)


def _blocked_uri_to_source(blocked_uri: str, directive_name: str) -> str | None:
    raw = (blocked_uri or "").strip()
    lower = raw.lower()
    if not lower:
        return None
    if lower == "self":
        return "'self'"
    if lower in {"inline", "inline-script", "inline-style"}:
        # Better options are nonce/hash, but this points to the direct unblock token.
        return "'unsafe-inline'"
    if lower == "eval":
        return "'unsafe-eval'"
    if lower.endswith(":"):
        return lower
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    if directive_name in {"img-src", "media-src", "font-src"} and lower in {"data", "blob"}:
        return f"{lower}:"
    if "://" not in raw and "." in raw:
        return raw
    return None


def ai_enhance_violations(
    violations: list[dict[str, Any]], policy: Policy | None = None, context: str | None = None
) -> dict[str, Any]:
    """Enhance violation analysis with AI explanations and recommendations."""
    if not _has_anthropic():
        return {
            "enhanced": False,
            "error": "anthropic package not available - install with: pip install anthropic",
            "fallback_summary": violations_summary_json(violations),
        }

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        # Use existing analysis as foundation
        summary = violations_summary_json(violations)
        suggestions = suggest_violation_fixes(violations, policy) if policy else []

        # Build enhanced prompt
        prompt = _build_violation_analysis_prompt(summary, policy, suggestions, context)

        # Get AI analysis
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse response into structured format
        ai_analysis = _parse_ai_response(response.content)

        return {
            "enhanced": True,
            "summary": summary,
            "suggestions": suggestions,
            "ai_analysis": ai_analysis,
            "explanation": ai_analysis.get("explanation", ""),
            "security_impact": ai_analysis.get("security_impact", ""),
            "implementation_notes": ai_analysis.get("implementation_notes", []),
            "risk_assessment": ai_analysis.get("risk_assessment", "medium"),
        }

    except Exception as e:
        return {
            "enhanced": False,
            "error": f"AI enhancement failed: {str(e)}",
            "fallback_summary": summary,
            "fallback_suggestions": suggestions if policy else [],
        }


def _has_anthropic() -> bool:
    """Check if anthropic package is available."""
    try:
        import anthropic  # noqa: F401

        return True
    except ImportError:
        return False


def _build_violation_analysis_prompt(
    summary: dict[str, Any],
    policy: Policy | None,
    suggestions: list[dict[str, Any]],
    context: str | None,
) -> str:
    """Build structured prompt for AI violation analysis."""

    current_policy = ""
    if policy:
        current_policy = f"Current CSP Policy: {policy.raw}"

    business_context = (
        f"Business Context: {context}" if context else "Business Context: Not specified"
    )

    violation_details = ""
    for group in summary.get("groups", []):
        violation_details += (
            f"- {group['count']}x {group['effective_directive']}: {group['blocked_uri']}\n"
        )

    suggested_fixes = ""
    for suggestion in suggestions:
        action = suggestion.get("action", "")
        if action == "consider_adding_source":
            suggested_fixes += (
                f"- Add '{suggestion['suggested_source']}' to {suggestion['directive']}\n"
            )
        elif action == "manual_review":
            suggested_fixes += (
                f"- Manual review needed for {suggestion['directive']}: {suggestion['reason']}\n"
            )

    return f"""You are a Content Security Policy (CSP) security expert. Analyze these CSP violation reports and provide actionable recommendations.

VIOLATION SUMMARY:
Total violations: {summary.get("count", 0)}

{business_context}

{current_policy}

VIOLATION BREAKDOWN:
{violation_details}

SUGGESTED TECHNICAL FIXES:
{suggested_fixes}

Please provide:

1. EXPLANATION: Clear explanation of what's happening and why these violations occur
2. SECURITY_IMPACT: Risk assessment of current violations (low/medium/high/critical) with reasoning
3. IMPLEMENTATION_NOTES: Practical implementation advice as a JSON array of strings
4. RISK_ASSESSMENT: Overall risk level (low/medium/high/critical)

Format your response as JSON with these exact keys: explanation, security_impact, implementation_notes, risk_assessment

Focus on practical security advice for developers implementing these fixes."""


def _parse_ai_response(content: str) -> dict[str, Any]:
    """Parse AI response into structured format."""
    try:
        # Try to extract JSON from response
        import re

        json_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback to text parsing
    return {
        "explanation": content,
        "security_impact": "Analysis available in explanation text",
        "implementation_notes": ["Review AI explanation for implementation guidance"],
        "risk_assessment": "medium",
    }
