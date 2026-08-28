#!/usr/bin/env python3
"""Build the mkdocs site from README.md.

README.md is the single source of truth for user-facing documentation. This
script slices it by heading and writes the `docs/` tree, so the site can never
drift from the README. Run it after editing README.md:

    python tools/build_docs.py

`--check` verifies the committed docs match what the README would produce and
exits non-zero otherwise; CI uses this to catch a README edit that forgot to
regenerate the site.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCS = ROOT / "docs"

# Page layout: output path -> (H1 + intro, [README section headings, in order]).
# Section names are matched against the README's `### ` / `## ` headings.
PAGES: dict[str, tuple[str, list[str]]] = {
    "cli/analysis.md": (
        "# Analysis\n\nCommands that inspect a policy you already have.",
        ["`analyze`", "`bypass`", "`effective`"],
    ),
    "cli/live-targets.md": (
        "# Live targets\n\nCommands that reach out over the network.\n\n"
        "!!! warning\n    Only run these against systems you are authorized to test.",
        ["`fetch`", "`scan`", "`subdomains`", "`monitor`"],
    ),
    "cli/generation.md": (
        "# Generation and repair\n\nCommands that produce or fix a policy.",
        ["`auto`", "`generate`", "`violations`", "`diff`"],
    ),
    "cli/probes.md": (
        "# Active probes\n\nTargeted security tests against a live host.\n\n"
        "!!! warning\n    Only run these against systems you are authorized to test.",
        ["`nonce-check`", "`header-inject`", "`report-uri`"],
    ),
    "library.md": ("", ["Library Usage"]),
    "checks.md": ("", ["Analyzer Checks"]),
    "bypass-database.md": ("", ["Bypass Database"]),
    "ci/github-action.md": ("", ["GitHub Action"]),
    "integrations.md": ("# Integrations", ["Browser Extension", "Nuclei Templates"]),
    "development.md": ("", ["Development"]),
}

INDEX = """# csp-toolkit

Parse, analyze, generate, and find bypasses in Content Security Policy headers.

A Python library and CLI tool for security researchers and bug bounty hunters.
Auto-generate CSPs by crawling a website, analyze policies with 21 weakness
checks, find bypasses against a database of 79 domains (66 JSONP + 13 CDNs),
score policies A+ to F, diff policies, detect nonce reuse, and more.

[![PyPI](https://img.shields.io/pypi/v/csp-toolkit)](https://pypi.org/project/csp-toolkit/)
[![License](https://img.shields.io/pypi/l/csp-toolkit)](https://github.com/sampsonc/csp_toolkit/blob/main/LICENSE)

{install}

## Quickstart

```bash
# Grade a policy you already have
csp-toolkit analyze "script-src 'self' 'unsafe-inline'"

# Pull the policy off a live site and analyze it
csp-toolkit fetch https://example.com --analyze

# Fail a CI build when a policy regresses
csp-toolkit analyze --fail-on high --min-grade B -f policy.txt
```

## Where to go next

| If you want to… | Start here |
|---|---|
| Check a policy for weaknesses | [Analysis commands](cli/analysis.md) |
| Work against live targets | [Live targets](cli/live-targets.md) |
| Build or repair a policy | [Generation](cli/generation.md) |
| Probe for nonce reuse or header injection | [Active probes](cli/probes.md) |
| Gate CI on CSP quality | [GitHub Action](ci/github-action.md) |
| Use it from Python | [Library usage](library.md) |
| Know what it checks for | [Analyzer checks](checks.md) |
| See the bypass data | [Bypass database](bypass-database.md) |

!!! warning "Authorization"
    Use active probes (`fetch`, `scan`, `header-inject`, `nonce-check`,
    `bypass --check-live`, and similar) only against systems you are
    **authorized** to test.
"""


def parse_sections(text: str) -> dict[str, str]:
    """Map each `##`/`###` heading to its body, keyed by the heading text."""
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    for line in text.split("\n"):
        if re.match(r"^#{2,3} ", line):
            if current is not None:
                sections[current] = "\n".join(buf).rstrip()
            current = line.lstrip("#").strip()
            buf = [line]
        elif current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).rstrip()
    return sections


def find(sections: dict[str, str], needle: str) -> str:
    """Return the one section whose heading starts with *needle*."""
    matches = [v for k, v in sections.items() if k.startswith(needle)]
    if len(matches) != 1:
        raise SystemExit(
            f"README section {needle!r} matched {len(matches)} headings; "
            "update PAGES in tools/build_docs.py"
        )
    return matches[0]


REPO_BLOB = "https://github.com/sampsonc/csp_toolkit/blob/main/"


def absolutize(text: str) -> str:
    """Point repo-relative links at GitHub.

    The README lives at the repo root, so links like `CHANGELOG.md` resolve there
    but not on the docs site. Rewrite anything that is not an external URL or an
    on-page anchor to an absolute blob URL.
    """

    def repl(m: re.Match) -> str:
        target = m.group(2)
        if target.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        return f"[{m.group(1)}]({REPO_BLOB}{target})"

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl, text)


def render(readme: str) -> dict[str, str]:
    sections = parse_sections(readme)
    out = {"index.md": INDEX.format(install=find(sections, "Install"))}
    for path, (front, names) in PAGES.items():
        chunks = [find(sections, n) for n in names]
        if front:
            body = "\n\n".join([front] + [re.sub(r"^### ", "## ", c, flags=re.M) for c in chunks])
        else:
            # Single top-level section: promote it to the page H1.
            body = "\n\n".join(re.sub(r"^## ", "# ", c, count=1) for c in chunks)
        out[path] = absolutize(body).rstrip() + "\n"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify docs/ is in sync; do not write")
    args = ap.parse_args()

    pages = render(README.read_text())

    if args.check:
        stale = []
        for rel, body in pages.items():
            target = DOCS / rel
            if not target.exists() or target.read_text() != body:
                stale.append(rel)
        if stale:
            print("docs/ is out of sync with README.md:", file=sys.stderr)
            for rel in stale:
                print(f"  - docs/{rel}", file=sys.stderr)
            print("\nRun: python tools/build_docs.py", file=sys.stderr)
            return 1
        print(f"docs/ is in sync with README.md ({len(pages)} pages)")
        return 0

    for rel, body in pages.items():
        target = DOCS / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        print(f"wrote docs/{rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
