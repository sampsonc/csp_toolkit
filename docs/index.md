# csp-toolkit

Parse, analyze, generate, and find bypasses in Content Security Policy headers.

A Python library and CLI tool for security researchers and bug bounty hunters.
Auto-generate CSPs by crawling a website, analyze policies with 21 weakness
checks, find bypasses against a database of 79 domains (66 JSONP + 13 CDNs),
score policies A+ to F, diff policies, detect nonce reuse, and more.

[![PyPI](https://img.shields.io/pypi/v/csp-toolkit)](https://pypi.org/project/csp-toolkit/)
[![License](https://img.shields.io/pypi/l/csp-toolkit)](https://github.com/sampsonc/csp_toolkit/blob/main/LICENSE)

## Install

```bash
pip install csp-toolkit
# or with uv
uv pip install csp-toolkit
```

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
