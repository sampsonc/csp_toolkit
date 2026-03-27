"""CSP diff — compare two policies and surface changes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Directive, Policy, Source


@dataclass
class DirectiveChange:
    directive: str
    change_type: str  # "added", "removed", "modified"
    old_sources: list[str] = field(default_factory=list)
    new_sources: list[str] = field(default_factory=list)
    added_sources: list[str] = field(default_factory=list)
    removed_sources: list[str] = field(default_factory=list)


@dataclass
class PolicyDiff:
    added_directives: list[DirectiveChange] = field(default_factory=list)
    removed_directives: list[DirectiveChange] = field(default_factory=list)
    modified_directives: list[DirectiveChange] = field(default_factory=list)
    unchanged_directives: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added_directives or self.removed_directives or self.modified_directives)

    @property
    def weakened(self) -> list[DirectiveChange]:
        """Changes that likely weaken the policy."""
        weak = []
        # Removed directives = weaker
        weak.extend(self.removed_directives)
        # Modified directives with added permissive sources
        _DANGEROUS_SOURCES = {"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:", "https:", "http:"}
        for change in self.modified_directives:
            for src in change.added_sources:
                if src.lower() in _DANGEROUS_SOURCES or src.startswith("*."):
                    weak.append(change)
                    break
        return weak

    @property
    def strengthened(self) -> list[DirectiveChange]:
        """Changes that likely strengthen the policy."""
        strong = []
        # Added directives = stronger
        strong.extend(self.added_directives)
        # Modified directives with removed permissive sources
        _DANGEROUS_SOURCES = {"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "blob:", "https:", "http:"}
        for change in self.modified_directives:
            for src in change.removed_sources:
                if src.lower() in _DANGEROUS_SOURCES or src.startswith("*."):
                    strong.append(change)
                    break
        return strong


def diff_policies(old: Policy, new: Policy) -> PolicyDiff:
    """Compare two CSP policies and return the differences."""
    result = PolicyDiff()

    old_names = set(old.directives.keys())
    new_names = set(new.directives.keys())

    # Added directives
    for name in sorted(new_names - old_names):
        d = new.directives[name]
        result.added_directives.append(DirectiveChange(
            directive=name,
            change_type="added",
            new_sources=[s.raw for s in d.sources],
        ))

    # Removed directives
    for name in sorted(old_names - new_names):
        d = old.directives[name]
        result.removed_directives.append(DirectiveChange(
            directive=name,
            change_type="removed",
            old_sources=[s.raw for s in d.sources],
        ))

    # Shared directives — check for modifications
    for name in sorted(old_names & new_names):
        old_d = old.directives[name]
        new_d = new.directives[name]

        old_sources = {s.raw for s in old_d.sources}
        new_sources = {s.raw for s in new_d.sources}

        if old_sources == new_sources:
            result.unchanged_directives.append(name)
        else:
            added = sorted(new_sources - old_sources)
            removed = sorted(old_sources - new_sources)
            result.modified_directives.append(DirectiveChange(
                directive=name,
                change_type="modified",
                old_sources=[s.raw for s in old_d.sources],
                new_sources=[s.raw for s in new_d.sources],
                added_sources=added,
                removed_sources=removed,
            ))

    return result


def diff_headers(old_header: str, new_header: str) -> PolicyDiff:
    """Convenience: diff two raw CSP header strings."""
    from .parser import parse
    return diff_policies(parse(old_header), parse(new_header))
