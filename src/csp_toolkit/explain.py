"""Resolve what a policy actually governs, per resource type.

`analyze` answers "what is wrong with this policy". This answers the prior
question people get wrong: *which directive is actually in force for scripts,
workers, frames, images?* A policy can look tight because `script-src` is tight,
while workers quietly inherit a far looser `child-src`. Reading a header does not
show that; resolving the fallback chain does.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Policy, Source

#: Resource types worth explaining, in the order a reader most cares about, each
#: paired with the directive that governs it and a plain-language description of
#: what it covers.
RESOURCE_TYPES: tuple[tuple[str, str, str], ...] = (
    ("scripts", "script-src", "<script src>, inline scripts, eval"),
    ("script elements", "script-src-elem", "<script> elements specifically"),
    ("script attributes", "script-src-attr", "inline event handlers (onclick=...)"),
    ("styles", "style-src", "stylesheets and inline CSS"),
    ("workers", "worker-src", "Worker, SharedWorker, ServiceWorker"),
    ("frames", "frame-src", "<iframe>, <frame>"),
    ("images", "img-src", "<img>, favicons, CSS images"),
    ("fonts", "font-src", "@font-face"),
    ("connections", "connect-src", "fetch, XHR, WebSocket, EventSource, beacon"),
    ("media", "media-src", "<audio>, <video>, <track>"),
    ("objects", "object-src", "<object>, <embed>, plugins"),
    ("manifests", "manifest-src", "web app manifest"),
    ("form targets", "form-action", "<form action> destinations"),
    ("framing parents", "frame-ancestors", "who may frame this page"),
    ("base URL", "base-uri", "<base href> values"),
)


@dataclass(frozen=True)
class Resolution:
    """How one resource type resolves against a policy."""

    resource: str
    directive: str
    description: str
    #: The directive the value actually came from — None when nothing governs it.
    governed_by: str | None
    sources: tuple[Source, ...]

    @property
    def is_explicit(self) -> bool:
        return self.governed_by == self.directive

    @property
    def is_inherited(self) -> bool:
        return self.governed_by is not None and self.governed_by != self.directive

    @property
    def is_unrestricted(self) -> bool:
        """True when nothing in the chain governs this resource type at all."""
        return self.governed_by is None

    @property
    def status(self) -> str:
        if self.is_unrestricted:
            return "unrestricted"
        return "explicit" if self.is_explicit else "inherited"

    @property
    def rendered_sources(self) -> str:
        if self.is_unrestricted:
            return "(anything)"
        if not self.sources:
            return "(empty)"
        return " ".join(s.raw for s in self.sources)


def explain_policy(policy: Policy) -> list[Resolution]:
    """Resolve every interesting resource type against *policy*."""
    resolutions = []
    for resource, directive, description in RESOURCE_TYPES:
        governing, governed_by = policy.resolve(directive)
        # A directive with no fallback chain (frame-ancestors, form-action,
        # base-uri) is still worth reporting: absent means unrestricted.
        if governed_by is None and policy.has_directive(directive):
            governing, governed_by = policy.get_directive(directive), directive
        resolutions.append(
            Resolution(
                resource=resource,
                directive=directive,
                description=description,
                governed_by=governed_by,
                sources=tuple(governing.sources) if governing else (),
            )
        )
    return resolutions


def explain_json(policy: Policy) -> dict:
    """Machine-readable form of the explanation."""
    return {
        "delivery": policy.delivery,
        "report_only": policy.report_only,
        "ignored_directives": list(policy.ignored_directives),
        "resources": [
            {
                "resource": r.resource,
                "directive": r.directive,
                "covers": r.description,
                "governed_by": r.governed_by,
                "status": r.status,
                "fallback_chain": list(policy.fallback_chain(r.directive)),
                "sources": [s.raw for s in r.sources],
            }
            for r in explain_policy(policy)
        ],
    }
