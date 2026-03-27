"""Core data structures for CSP parsing and analysis."""

from __future__ import annotations

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
    KEYWORD = "keyword"      # 'self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic', etc.
    HOST = "host"            # example.com, *.example.com, https://example.com
    SCHEME = "scheme"        # https:, data:, blob:, mediastream:, filesystem:
    NONCE = "nonce"          # 'nonce-abc123'
    HASH = "hash"            # 'sha256-...', 'sha384-...', 'sha512-...'
    WILDCARD = "wildcard"    # *


KEYWORDS = frozenset({
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
})

SCHEMES = frozenset({
    "https:",
    "http:",
    "data:",
    "blob:",
    "mediastream:",
    "filesystem:",
})

VALID_DIRECTIVES = frozenset({
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
})

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

    def get_directive(self, name: str) -> Directive | None:
        return self.directives.get(name.lower())

    def effective_directive(self, name: str) -> Directive | None:
        """Get directive with default-src fallback.

        Per the CSP spec, if a fetch directive is not present, the UA falls back
        to default-src. Non-fetch directives (frame-ancestors, form-action,
        base-uri, etc.) do NOT fall back to default-src.
        """
        directive = self.get_directive(name)
        if directive is not None:
            return directive

        # Only fetch directives fall back to default-src
        fetch_directives = {
            "script-src", "script-src-elem", "script-src-attr",
            "style-src", "style-src-elem", "style-src-attr",
            "img-src", "font-src", "connect-src", "media-src",
            "object-src", "prefetch-src", "child-src", "frame-src",
            "worker-src", "manifest-src",
        }
        if name.lower() in fetch_directives:
            return self.get_directive("default-src")

        return None

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


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    directive: str | None = None
    bypass_type: str | None = None
    references: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        prefix = f"[{self.severity.value.upper()}]"
        if self.directive:
            return f"{prefix} {self.title} (in {self.directive})"
        return f"{prefix} {self.title}"
