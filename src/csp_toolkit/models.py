"""Core data structures for CSP parsing and analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceType(Enum):
    KEYWORD = "keyword"  # 'self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic', etc.
    HOST = "host"  # example.com, *.example.com, https://example.com
    SCHEME = "scheme"  # https:, data:, blob:, mediastream:, filesystem:
    NONCE = "nonce"  # 'nonce-abc123'
    HASH = "hash"  # 'sha256-...', 'sha384-...', 'sha512-...'
    WILDCARD = "wildcard"  # *


KEYWORDS = frozenset(
    {
        "'self'",
        "'none'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'strict-dynamic'",
        "'unsafe-hashes'",
        "'unsafe-allow-redirects'",
        "'report-sample'",
        "'wasm-unsafe-eval'",
        "'inline-speculation-rules'",
    }
)

SCHEMES = frozenset(
    {
        "https:",
        "http:",
        "data:",
        "blob:",
        "mediastream:",
        "filesystem:",
    }
)

VALID_DIRECTIVES = frozenset(
    {
        "default-src",
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "style-src",
        "style-src-elem",
        "style-src-attr",
        "img-src",
        "font-src",
        "connect-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "child-src",
        "frame-src",
        "worker-src",
        "frame-ancestors",
        "form-action",
        "base-uri",
        "navigate-to",
        "manifest-src",
        "plugin-types",
        "sandbox",
        "report-uri",
        "report-to",
        "require-trusted-types-for",
        "trusted-types",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
    }
)

#: Fallback chains per CSP Level 3, each listed most specific first. A directive
#: absent from this map does not fall back at all (frame-ancestors, form-action,
#: base-uri, navigate-to, sandbox, and the reporting directives).
FALLBACK_CHAINS: dict[str, tuple[str, ...]] = {
    "default-src": ("default-src",),
    "script-src": ("script-src", "default-src"),
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "style-src": ("style-src", "default-src"),
    "style-src-elem": ("style-src-elem", "style-src", "default-src"),
    "style-src-attr": ("style-src-attr", "style-src", "default-src"),
    "img-src": ("img-src", "default-src"),
    "font-src": ("font-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    "manifest-src": ("manifest-src", "default-src"),
    "prefetch-src": ("prefetch-src", "default-src"),
    "child-src": ("child-src", "default-src"),
    # frame-src and worker-src route through child-src, and worker-src through
    # script-src after that — the chain a "worker-src is missing" bug hides in.
    "frame-src": ("frame-src", "child-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
}


_NONCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/=_-]+'$")
_HASH_RE = re.compile(r"^'sha(256|384|512)-[A-Za-z0-9+/=]+'$")


def classify_source(raw: str) -> SourceType:
    """Classify a CSP source value into its type."""
    lower = raw.lower()

    if lower == "*":
        return SourceType.WILDCARD
    if lower in KEYWORDS:
        return SourceType.KEYWORD
    if lower in SCHEMES:
        return SourceType.SCHEME
    if _NONCE_RE.match(raw):
        return SourceType.NONCE
    if _HASH_RE.match(raw):
        return SourceType.HASH
    return SourceType.HOST


@dataclass(frozen=True)
class Source:
    raw: str
    source_type: SourceType

    @classmethod
    def from_string(cls, raw: str) -> Source:
        return cls(raw=raw, source_type=classify_source(raw))

    @property
    def is_keyword(self) -> bool:
        return self.source_type == SourceType.KEYWORD

    @property
    def is_host(self) -> bool:
        return self.source_type == SourceType.HOST

    def __str__(self) -> str:
        return self.raw


@dataclass(frozen=True)
class Directive:
    name: str
    sources: tuple[Source, ...]

    @classmethod
    def from_tokens(cls, name: str, source_tokens: list[str]) -> Directive:
        return cls(
            name=name.lower().strip(),
            sources=tuple(Source.from_string(t) for t in source_tokens),
        )

    def has_source(self, value: str) -> bool:
        """Check if this directive contains a source matching the given value (case-insensitive)."""
        lower = value.lower()
        return any(s.raw.lower() == lower for s in self.sources)

    def sources_of_type(self, source_type: SourceType) -> list[Source]:
        return [s for s in self.sources if s.source_type == source_type]

    def host_sources(self) -> list[Source]:
        return self.sources_of_type(SourceType.HOST)

    def __str__(self) -> str:
        if self.sources:
            return f"{self.name} {' '.join(s.raw for s in self.sources)}"
        return self.name


@dataclass(frozen=True)
class Policy:
    raw: str
    directives: dict[str, Directive] = field(default_factory=dict)
    report_only: bool = False
    #: How the policy reached the page: "header" or "meta".
    delivery: str = "header"
    #: Directive names present in the raw policy but discarded as unenforceable
    #: for this delivery method (see parser.META_IGNORED_DIRECTIVES).
    ignored_directives: tuple[str, ...] = ()

    def get_directive(self, name: str) -> Directive | None:
        return self.directives.get(name.lower())

    def fallback_chain(self, name: str) -> tuple[str, ...]:
        """The directives a UA consults for *name*, most specific first.

        Several directives fall back through an intermediate rather than straight
        to default-src — worker-src goes through child-src and script-src, and
        frame-src through child-src — which is why a tight script-src plus a loose
        child-src still lets worker code load from the looser list.
        """
        return FALLBACK_CHAINS.get(name.lower(), ())

    def resolve(self, name: str) -> tuple[Directive | None, str | None]:
        """Resolve *name* through its fallback chain.

        Returns the governing directive and the name it actually came from, so
        callers can tell an explicit value from an inherited one. Returns
        ``(None, None)`` when nothing in the chain is present.
        """
        for candidate in self.fallback_chain(name):
            directive = self.get_directive(candidate)
            if directive is not None:
                return directive, candidate
        return None, None

    def effective_directive(self, name: str) -> Directive | None:
        """Get the directive that governs *name*, following the real fallback chain.

        Non-fetch directives (frame-ancestors, form-action, base-uri, etc.) do not
        fall back at all, so they resolve to themselves or to nothing.
        """
        directive, _ = self.resolve(name)
        return directive

    def effective_sources(self, directive_name: str) -> list[Source]:
        """Get the effective source list for a directive, with default-src fallback."""
        directive = self.effective_directive(directive_name)
        if directive is None:
            return []
        return list(directive.sources)

    def has_directive(self, name: str) -> bool:
        return name.lower() in self.directives

    def __str__(self) -> str:
        return "; ".join(str(d) for d in self.directives.values())


def _slug(text: str) -> str:
    """Fallback identity for a Finding constructed without a check_id."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    directive: str | None = None
    bypass_type: str | None = None
    references: list[str] = field(default_factory=list)
    #: Stable slug for the check that produced this finding. Set by the analyzer
    #: from its check registry; treat it as part of the public output contract,
    #: since baselines and SARIF rule IDs are keyed on it.
    check_id: str | None = None
    #: The specific source or value that triggered this finding, for checks that
    #: emit more than one finding per directive (e.g. two broad domains in
    #: script-src). Part of the fingerprint so those stay distinguishable.
    subject: str | None = None

    @property
    def fingerprint(self) -> str:
        """Stable identity for this finding, for baseline comparison and SARIF dedupe.

        Deliberately derived from check_id / directive / subject and *not* from the
        title or description, so rewording a message does not invalidate a stored
        baseline or churn a code-scanning alert.
        """
        parts = [self.check_id or _slug(self.title), self.directive or "", self.subject or ""]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    def __str__(self) -> str:
        prefix = f"[{self.severity.value.upper()}]"
        if self.directive:
            return f"{prefix} {self.title} (in {self.directive})"
        return f"{prefix} {self.title}"
