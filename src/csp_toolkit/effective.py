"""Combine multiple CSP policies (stacked headers) using an intersection heuristic."""

from __future__ import annotations

from .models import Directive, Policy, Source
from .parser import parse


def combine_policies(policies: list[Policy]) -> tuple[Policy, list[str]]:
    """Return a single policy whose fetch directives are the per-directive intersection of sources.

    When multiple ``Content-Security-Policy`` values are sent, browsers enforce their
    intersection. This is a heuristic: it intersects *literal* directive source lists
    (with ``default-src`` fallback via :meth:`Policy.effective_directive`).
    """
    warnings: list[str] = []
    if not policies:
        return Policy(raw=""), warnings
    if len(policies) == 1:
        p = policies[0]
        return Policy(raw=p.raw, directives=dict(p.directives), report_only=p.report_only), warnings

    names: set[str] = set()
    for p in policies:
        names.update(p.directives.keys())

    out: dict[str, Directive] = {}
    for name in sorted(names):
        acc: set[str] | None = None
        any_restricted = False
        for p in policies:
            ed = p.effective_directive(name)
            if ed is None:
                continue
            any_restricted = True
            sset = {s.raw for s in ed.sources}
            acc = sset if acc is None else acc & sset
        if not any_restricted:
            continue
        if acc is None or not acc:
            if acc is not None and not acc:
                warnings.append(
                    f"Directive '{name}': intersection is empty — using 'none' for combined policy."
                )
            srcs = (Source.from_string("'none'"),)
        else:
            srcs = tuple(Source.from_string(s) for s in sorted(acc))
        out[name] = Directive(name=name, sources=srcs)

    raw = "; ".join(str(out[k]) for k in sorted(out.keys()))
    combined = Policy(raw=raw, directives=out, report_only=False)
    return combined, warnings


def combine_enforced_header_policies(csp_strings: list[str]) -> tuple[Policy, list[str]]:
    """Parse each non-empty string as a CSP and :func:`combine_policies`."""
    policies = [parse(s.strip()) for s in csp_strings if s.strip()]
    return combine_policies(policies)
