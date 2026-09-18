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


#: Directives the UA ignores when a policy is delivered via <meta http-equiv>.
META_IGNORED_DIRECTIVES = frozenset({"report-uri", "frame-ancestors", "sandbox"})


def parse_meta(content: str) -> Policy:
    """Parse CSP from a <meta http-equiv="Content-Security-Policy"> content attribute.

    Meta-element CSP has restrictions: report-uri, frame-ancestors, and sandbox
    are ignored when delivered via meta element, so they are dropped from the
    returned policy rather than credited. The names that were present but
    discarded are recorded on ``Policy.ignored_directives`` so callers can
    report the gap instead of silently losing it.
    """
    policy = parse(content, report_only=False)

    ignored = sorted(n for n in policy.directives if n in META_IGNORED_DIRECTIVES)
    if not ignored:
        return Policy(
            raw=policy.raw,
            directives=policy.directives,
            report_only=False,
            delivery="meta",
        )

    kept = {n: d for n, d in policy.directives.items() if n not in META_IGNORED_DIRECTIVES}
    return Policy(
        raw=policy.raw,
        directives=kept,
        report_only=False,
        delivery="meta",
        ignored_directives=tuple(ignored),
    )
