"""CSP policy generator — programmatic builder with presets."""

from __future__ import annotations

import secrets
from copy import deepcopy


class CSPBuilder:
    """Fluent builder for Content Security Policy headers."""

    def __init__(self) -> None:
        self._directives: dict[str, list[str]] = {}

    def add_directive(self, name: str, *sources: str) -> CSPBuilder:
        """Add a directive with the given sources. Replaces if directive already exists."""
        self._directives[name.lower()] = list(sources)
        return self

    def remove_directive(self, name: str) -> CSPBuilder:
        """Remove a directive."""
        self._directives.pop(name.lower(), None)
        return self

    def add_source(self, directive: str, source: str) -> CSPBuilder:
        """Add a source to an existing directive, or create the directive with that source."""
        key = directive.lower()
        if key not in self._directives:
            self._directives[key] = []
        if source not in self._directives[key]:
            self._directives[key].append(source)
        return self

    def remove_source(self, directive: str, source: str) -> CSPBuilder:
        """Remove a source from a directive."""
        key = directive.lower()
        if key in self._directives:
            self._directives[key] = [s for s in self._directives[key] if s != source]
        return self

    def set_report_uri(self, uri: str) -> CSPBuilder:
        """Set the report-uri directive."""
        self._directives["report-uri"] = [uri]
        return self

    def set_report_to(self, group: str) -> CSPBuilder:
        """Set the report-to directive."""
        self._directives["report-to"] = [group]
        return self

    def build(self) -> str:
        """Build the CSP header string."""
        parts = []
        for name, sources in self._directives.items():
            if sources:
                parts.append(f"{name} {' '.join(sources)}")
            else:
                parts.append(name)
        return "; ".join(parts)

    def build_meta(self) -> str:
        """Build a <meta> tag with the CSP."""
        return f'<meta http-equiv="Content-Security-Policy" content="{self.build()}">'

    def build_nginx(self) -> str:
        """Build an nginx add_header directive."""
        return f'add_header Content-Security-Policy "{self.build()}" always;'

    def build_apache(self) -> str:
        """Build an Apache Header directive."""
        return f'Header always set Content-Security-Policy "{self.build()}"'

    def copy(self) -> CSPBuilder:
        """Create a copy of this builder."""
        new = CSPBuilder()
        new._directives = deepcopy(self._directives)
        return new

    @classmethod
    def strict(cls, nonce: str | None = None) -> CSPBuilder:
        """Create a strict CSP with nonce-based script loading.

        This is the recommended CSP for modern applications.
        Uses 'strict-dynamic' so only nonced scripts and their children execute.
        """
        if nonce is None:
            nonce = secrets.token_urlsafe(16)

        return (
            cls()
            .add_directive("default-src", "'none'")
            .add_directive("script-src", f"'nonce-{nonce}'", "'strict-dynamic'")
            .add_directive("style-src", f"'nonce-{nonce}'")
            .add_directive("img-src", "'self'")
            .add_directive("font-src", "'self'")
            .add_directive("connect-src", "'self'")
            .add_directive("base-uri", "'none'")
            .add_directive("form-action", "'self'")
            .add_directive("frame-ancestors", "'none'")
            .add_directive("object-src", "'none'")
        )

    @classmethod
    def moderate(cls) -> CSPBuilder:
        """Create a moderate CSP suitable for apps that need some flexibility.

        Uses 'self' for most directives. No unsafe-inline or unsafe-eval.
        """
        return (
            cls()
            .add_directive("default-src", "'self'")
            .add_directive("script-src", "'self'")
            .add_directive("style-src", "'self'", "'unsafe-inline'")
            .add_directive("img-src", "'self'", "data:")
            .add_directive("font-src", "'self'")
            .add_directive("connect-src", "'self'")
            .add_directive("base-uri", "'self'")
            .add_directive("form-action", "'self'")
            .add_directive("frame-ancestors", "'self'")
            .add_directive("object-src", "'none'")
        )

    @classmethod
    def permissive(cls) -> CSPBuilder:
        """Create a permissive CSP — better than nothing but not strong.

        Suitable as a starting point for legacy applications.
        """
        return (
            cls()
            .add_directive("default-src", "'self'")
            .add_directive("script-src", "'self'", "'unsafe-inline'", "'unsafe-eval'")
            .add_directive("style-src", "'self'", "'unsafe-inline'")
            .add_directive("img-src", "*")
            .add_directive("font-src", "*")
            .add_directive("connect-src", "'self'")
            .add_directive("object-src", "'none'")
        )
