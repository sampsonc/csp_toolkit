# csp-toolkit

Parse, analyze, generate, and find bypasses in Content Security Policy headers.

A Python library and CLI tool for security researchers and developers. Includes a JSONP endpoint database (~30 domains), CDN script gadget detection, and 18 weakness checks.

## Install

```bash
pip install -e .
# or with uv
uv pip install -e .
```

## CLI Usage

### Analyze a CSP for weaknesses

```bash
# From a string
csp-toolkit analyze "script-src 'self' 'unsafe-inline' *.googleapis.com"

# From a file
csp-toolkit analyze -f policy.txt

# From stdin
curl -sI https://example.com | grep -i content-security-policy | cut -d: -f2- | csp-toolkit analyze -f -

# Output formats: table (default), detail, json
csp-toolkit analyze -o json "script-src 'self' 'unsafe-inline'"
csp-toolkit analyze -o detail "script-src 'self' 'unsafe-inline'"

# Analyze a Report-Only header
csp-toolkit analyze --report-only "default-src 'self'"
```

### Find CSP bypasses

```bash
csp-toolkit bypass "script-src 'self' *.googleapis.com cdnjs.cloudflare.com"
csp-toolkit bypass -f policy.txt
csp-toolkit bypass -o json "script-src 'self' data: cdnjs.cloudflare.com"
```

Checks whitelisted domains against known:
- JSONP endpoints (Google, Facebook, Twitter, Yahoo, Microsoft, GitHub, etc.)
- CDN script gadgets (AngularJS < 1.6, Knockout.js, Mithril, Dojo, etc.)
- Arbitrary hosting platforms (raw.githubusercontent.com, unpkg.com, codepen.io, etc.)
- Scheme abuse (data:, blob: payloads)
- Missing directive exploitation (base-uri, form-action)

### Fetch and analyze a live URL

```bash
# Fetch CSP headers and meta tags
csp-toolkit fetch https://example.com

# Fetch + analyze + find bypasses
csp-toolkit fetch https://example.com --all

# Individual flags
csp-toolkit fetch https://example.com --analyze
csp-toolkit fetch https://example.com --bypass

# Skip SSL verification
csp-toolkit fetch https://example.com --all --no-verify-ssl
```

### Generate a CSP

```bash
# Strict (nonce-based, recommended)
csp-toolkit generate --preset strict
csp-toolkit generate --preset strict --nonce my-random-nonce

# Moderate (self-based, some flexibility)
csp-toolkit generate --preset moderate

# Permissive (legacy fallback)
csp-toolkit generate --preset permissive

# Add custom sources
csp-toolkit generate --preset moderate --add-source "script-src cdn.example.com"

# Output formats: header (default), meta, nginx, apache
csp-toolkit generate --preset strict -o nginx
csp-toolkit generate --preset strict -o apache
csp-toolkit generate --preset strict -o meta
```

## Library Usage

```python
import csp_toolkit

# Parse
policy = csp_toolkit.parse("script-src 'self' 'unsafe-inline' *.googleapis.com")

# Analyze
findings = csp_toolkit.analyze(policy)
for f in findings:
    print(f)  # [CRITICAL] 'unsafe-inline' allows arbitrary inline scripts (in script-src)

# Find bypasses
bypasses = csp_toolkit.find_bypasses(policy)
for b in bypasses:
    print(b)  # [HIGH] JSONP bypass via maps.googleapis.com (in script-src)

# Look up specific domains
csp_toolkit.check_domain_jsonp("accounts.google.com")
csp_toolkit.check_domain_gadgets("cdnjs.cloudflare.com")

# Generate
from csp_toolkit import CSPBuilder

csp = (
    CSPBuilder.strict(nonce="abc123")
    .add_source("connect-src", "https://api.example.com")
    .build()
)

# Fetch live
result = csp_toolkit.fetch_csp("https://example.com")
for policy in result.policies:
    print(csp_toolkit.analyze(policy))
```

## Analyzer Checks

| Severity | Check |
|----------|-------|
| CRITICAL | `unsafe-inline` in script-src |
| CRITICAL | `data:` URI in script-src |
| CRITICAL | No script-src and no default-src |
| HIGH | `unsafe-eval` in script-src |
| HIGH | Wildcard `*` in script-src/default-src |
| HIGH | `blob:` URI in script-src |
| HIGH | Missing object-src |
| HIGH | `strict-dynamic` without nonce/hash |
| MEDIUM | Missing base-uri |
| MEDIUM | Missing form-action |
| MEDIUM | Missing frame-ancestors |
| MEDIUM | Overly broad wildcard domains (*.googleapis.com, etc.) |
| MEDIUM | `unsafe-hashes` in script-src |
| MEDIUM | `unsafe-inline` + nonce/hash (CSP2 downgrade) |
| MEDIUM | `data:` in object-src/frame-src/child-src |
| LOW | `unsafe-inline` in style-src |
| LOW | `http:` scheme sources |
| LOW | IP address sources |
| INFO | Report-Only mode |

## Bypass Database

The bypass finder includes curated databases of:

- **JSONP endpoints** across ~30 domains (Google, Facebook, Twitter, Yahoo, LinkedIn, Microsoft, GitHub, Wikipedia, etc.) with concrete callback URLs
- **CDN script gadgets** for cdnjs, jsDelivr, unpkg, googleapis, jQuery CDN, and others — including AngularJS template injection, Knockout.js data-bind, and more
- **Arbitrary hosting domains** where anyone can serve JS (raw.githubusercontent.com, surge.sh, netlify.app, vercel.app, codepen.io, etc.)

## Development

```bash
# Install dev dependencies
uv sync --all-extras

# Run tests
uv run pytest -v

# Lint
uv run ruff check src/
```
