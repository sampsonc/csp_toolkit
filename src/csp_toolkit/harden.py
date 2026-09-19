"""Turn a policy's findings into a tightened policy.

`analyze` names what is wrong and every Finding carries remediation prose. This
executes that prose: it returns a hardened header plus a record of what changed
and what each change risks, because a hardening tool that silently drops
capability is a tool that breaks production.

Changes are classified by risk and gated by level, so the default output is one a
maintainer can apply without auditing every inline script:

* ``none`` — a no-op for modern browsers (e.g. dropping ``'unsafe-inline'`` that a
  nonce already causes CSP2+ browsers to ignore).
* ``low``  — rarely breaks a site, and the breakage is obvious if it does.
* ``high`` — removes capability the page may rely on; needs ``allow_breaking``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Directive, Policy, SourceType

#: Level -> the risks it is willing to apply.
LEVELS: dict[str, frozenset[str]] = {
    "safe": frozenset({"none", "low"}),
    "strict": frozenset({"none", "low", "high"}),
}

_SCRIPT_DIRECTIVES = ("script-src", "script-src-elem", "script-src-attr")


@dataclass(frozen=True)
class Change:
    """One edit to a policy, with why it is safe (or not)."""

    action: str  # "add" | "remove" | "replace"
    directive: str
    detail: str
    risk: str
    rationale: str

    def __str__(self) -> str:
        symbol = {"add": "+", "remove": "-", "replace": "~"}.get(self.action, "?")
        return f"{symbol} {self.directive}: {self.detail}"


@dataclass
class HardenResult:
    original: str
    hardened: str
    changes: list[Change]
    #: Changes that were identified but held back by the level or allow_breaking.
    skipped: list[Change]

    @property
    def changed(self) -> bool:
        return self.original != self.hardened


def _has_nonce_or_hash(directive: Directive | None) -> bool:
    if directive is None:
        return False
    return any(s.source_type in (SourceType.NONCE, SourceType.HASH) for s in directive.sources)


def _render(directives: dict[str, list[str]]) -> str:
    parts = []
    for name, sources in directives.items():
        parts.append(f"{name} {' '.join(sources)}".strip() if sources else name)
    return "; ".join(parts)


def harden_policy(
    policy: Policy,
    *,
    level: str = "safe",
    allow_breaking: bool = False,
) -> HardenResult:
    """Produce a tightened version of *policy*.

    Returns the new header plus the applied and withheld changes. Never mutates
    the input policy.
    """
    if level not in LEVELS:
        raise ValueError(f"unknown level {level!r}; choose from {sorted(LEVELS)}")
    allowed = LEVELS[level]

    working: dict[str, list[str]] = {
        name: [s.raw for s in d.sources] for name, d in policy.directives.items()
    }
    applied: list[Change] = []
    skipped: list[Change] = []

    def consider(change: Change, apply) -> None:
        breaking_blocked = change.risk == "high" and not allow_breaking
        if change.risk in allowed and not breaking_blocked:
            apply()
            applied.append(change)
        else:
            skipped.append(change)

    # --- Remove keywords that are already inert, or that defeat the policy ---
    for name in _SCRIPT_DIRECTIVES:
        sources = working.get(name)
        if not sources:
            continue
        directive = policy.get_directive(name)
        lowered = [s.lower() for s in sources]

        if "'unsafe-inline'" in lowered:
            if _has_nonce_or_hash(directive):
                consider(
                    Change(
                        "remove",
                        name,
                        "'unsafe-inline'",
                        "none",
                        "a nonce or hash is present, so CSP2+ browsers already ignore "
                        "'unsafe-inline'; removing it only closes the CSP1 fallback",
                    ),
                    lambda n=name: _drop(working, n, "'unsafe-inline'"),
                )
            else:
                consider(
                    Change(
                        "remove",
                        name,
                        "'unsafe-inline'",
                        "high",
                        "no nonce or hash present, so every inline script will break; "
                        "add nonces or hashes first (see the discover command)",
                    ),
                    lambda n=name: _drop(working, n, "'unsafe-inline'"),
                )

        if "'unsafe-eval'" in lowered:
            consider(
                Change(
                    "remove",
                    name,
                    "'unsafe-eval'",
                    "high",
                    "removes eval()/new Function(); breaks code that compiles strings "
                    "at runtime, including some template libraries",
                ),
                lambda n=name: _drop(working, n, "'unsafe-eval'"),
            )

        for scheme in ("data:", "blob:"):
            if scheme in lowered:
                consider(
                    Change(
                        "remove",
                        name,
                        scheme,
                        "high",
                        f"{scheme} in a script directive lets an injection point load "
                        "attacker-authored script; removing it breaks legitimate "
                        f"{scheme} script loads if the page uses them",
                    ),
                    lambda n=name, sc=scheme: _drop(working, n, sc),
                )

        if "*" in lowered:
            consider(
                Change(
                    "remove",
                    name,
                    "*",
                    "high",
                    "a wildcard makes the directive equivalent to no protection; "
                    "replace it with the specific origins the page needs",
                ),
                lambda n=name: _drop(working, n, "*"),
            )

    # --- Add the directives that do not fall back to default-src ---
    for name, value, risk, why in (
        (
            "object-src",
            "'none'",
            "low",
            "object-src does not inherit usefully in older browsers and plugins are a "
            "code-execution path; 'none' is right for virtually every modern site",
        ),
        (
            "base-uri",
            "'none'",
            "low",
            "base-uri has no default-src fallback, so without it an injected <base> tag "
            "can re-point every relative URL on the page",
        ),
        (
            "form-action",
            "'self'",
            "low",
            "form-action has no default-src fallback; without it an injected form can "
            "post credentials to an attacker",
        ),
    ):
        if not policy.has_directive(name):
            consider(
                Change("add", name, value, risk, why),
                lambda n=name, v=value: working.setdefault(n, [v]),
            )

    if not policy.has_directive("frame-ancestors"):
        consider(
            Change(
                "add",
                "frame-ancestors",
                "'none'",
                "high",
                "blocks all framing of this page; breaks any legitimate embedding, so "
                "set it to the allowed parents instead if the page is meant to be framed",
            ),
            lambda: working.setdefault("frame-ancestors", ["'none'"]),
        )

    # --- Pin worker-src when it would inherit something looser than script-src ---
    if not policy.has_directive("worker-src"):
        _, inherited_from = policy.resolve("worker-src")
        if inherited_from == "child-src":
            script_directive = policy.effective_directive("script-src")
            pin = "'self'"
            consider(
                Change(
                    "add",
                    "worker-src",
                    pin,
                    "low",
                    "workers currently inherit child-src, which is looser than "
                    f"script-src ({script_directive}); pinning worker-src stops worker "
                    "code loading from those origins",
                ),
                lambda v=pin: working.setdefault("worker-src", [v]),
            )

    # --- Strict-only tightening ---
    style_sources = working.get("style-src") or working.get("default-src") or []
    if "'unsafe-inline'" in [s.lower() for s in style_sources] and "style-src" in working:
        consider(
            Change(
                "remove",
                "style-src",
                "'unsafe-inline'",
                "high",
                "breaks inline style attributes and <style> blocks, which many "
                "component libraries emit; needs hashes or nonces first",
            ),
            lambda: _drop(working, "style-src", "'unsafe-inline'"),
        )

    if not policy.has_directive("require-trusted-types-for"):
        consider(
            Change(
                "add",
                "require-trusted-types-for",
                "'script'",
                "high",
                "enforces Trusted Types on DOM sinks; requires application changes "
                "before it can be enabled without breaking the page",
            ),
            lambda: working.setdefault("require-trusted-types-for", ["'script'"]),
        )

    # --- http: -> https: anywhere it appears ---
    for name, sources in list(working.items()):
        if "http:" in [s.lower() for s in sources]:
            consider(
                Change(
                    "replace",
                    name,
                    "http: -> https:",
                    "low",
                    "http: sources permit man-in-the-middle content injection on an "
                    "HTTPS page; https: is the same allowance without the downgrade",
                ),
                lambda n=name: _swap(working, n, "http:", "https:"),
            )

    return HardenResult(
        original=str(policy),
        hardened=_render(working),
        changes=applied,
        skipped=skipped,
    )


def _drop(working: dict[str, list[str]], directive: str, value: str) -> None:
    sources = working.get(directive)
    if sources is None:
        return
    working[directive] = [s for s in sources if s.lower() != value.lower()]
    # A directive emptied of sources would allow everything, so make it explicit.
    if not working[directive]:
        working[directive] = ["'none'"]


def _swap(working: dict[str, list[str]], directive: str, old: str, new: str) -> None:
    sources = working.get(directive)
    if sources is None:
        return
    out: list[str] = []
    for s in sources:
        replacement = new if s.lower() == old.lower() else s
        if replacement not in out:
            out.append(replacement)
    working[directive] = out


def harden_json(result: HardenResult) -> dict:
    """Machine-readable form of a harden run."""

    def encode(changes: list[Change]) -> list[dict]:
        return [
            {
                "action": c.action,
                "directive": c.directive,
                "detail": c.detail,
                "risk": c.risk,
                "rationale": c.rationale,
            }
            for c in changes
        ]

    return {
        "original": result.original,
        "hardened": result.hardened,
        "changed": result.changed,
        "applied": encode(result.changes),
        "skipped": encode(result.skipped),
    }


__all__ = [
    "Change",
    "HardenResult",
    "LEVELS",
    "harden_json",
    "harden_policy",
]
