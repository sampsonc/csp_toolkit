"""CSP header parser — converts raw header strings into Policy objects."""

from __future__ import annotations

from .models import Directive, Policy


def parse(header: str, report_only: bool = False) -> Policy:
    """Parse a CSP header string into a Policy object.

    Args:
        header: Raw CSP header value (e.g. "script-src 'self'; style-src 'none'")
        report_only: Whether this is a Content-Security-Policy-Report-Only header

    Returns:
        A Policy object with parsed directives.
    """
    header = header.strip()
    if not header:
        return Policy(raw=header, directives={}, report_only=report_only)

    directives: dict[str, Directive] = {}

    for raw_directive in header.split(";"):
        raw_directive = raw_directive.strip()
        if not raw_directive:
            continue

        tokens = raw_directive.split()
        if not tokens:
            continue

        name = tokens[0].lower()
        sources = tokens[1:]

        # Per spec, duplicate directives are ignored (first one wins)
        if name not in directives:
            directives[name] = Directive.from_tokens(name, sources)

    return Policy(raw=header, directives=directives, report_only=report_only)


def parse_meta(content: str) -> Policy:
    """Parse CSP from a <meta http-equiv="Content-Security-Policy"> content attribute.

    Meta-element CSP has restrictions: report-uri, frame-ancestors, and sandbox
    directives are ignored when delivered via meta element.
    """
    return parse(content, report_only=False)
