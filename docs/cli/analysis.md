# Analysis

Commands that inspect a policy you already have.

## `analyze` — Check a CSP for weaknesses

```bash
# From a string
csp-toolkit analyze "script-src 'self' 'unsafe-inline' *.googleapis.com"

# From a file or stdin
csp-toolkit analyze -f policy.txt
curl -sI https://example.com | grep -i content-security-policy | cut -d: -f2- | csp-toolkit analyze -f -

# Output formats: table (default), detail, json
csp-toolkit analyze -o json "script-src 'self' 'unsafe-inline'"

# Analyze a Report-Only header
csp-toolkit analyze --report-only "default-src 'self'"

# CI gating: exit 3 if any finding is CRITICAL or HIGH
csp-toolkit analyze --fail-on high "script-src 'self' 'unsafe-inline'"

# CI gating: exit 3 if the policy grades below B
csp-toolkit analyze --min-grade B "script-src 'self'"

# Write SARIF to a file for upload to a code-scanning dashboard
csp-toolkit analyze -o sarif --output csp.sarif -f policy.txt
```

Outputs a severity-sorted findings table and an A+ to F grade with numeric score (0-100).

**Exit codes:** `0` success, `1` runtime error, `2` usage error, `3` a `--fail-on` or `--min-grade`
gate was violated. The distinct gate code lets CI tell a policy regression apart from a broken
invocation. Without a gate flag the command always exits `0`.

## `bypass` — Find CSP bypass vectors

```bash
csp-toolkit bypass "script-src 'self' *.googleapis.com cdnjs.cloudflare.com"
csp-toolkit bypass -f policy.txt
csp-toolkit bypass -o json "script-src 'self' data: cdnjs.cloudflare.com"

# Probe JSONP endpoints to verify they're live
csp-toolkit bypass --check-live "script-src 'self' *.googleapis.com"
```

Checks whitelisted domains against known:
- **JSONP endpoints** — 66 domains with concrete callback URLs
- **CDN script gadgets** — AngularJS, Vue.js, Knockout, Lodash, Handlebars, Dojo, Mithril, jQuery, Ember, and more
- **Arbitrary hosting platforms** — raw.githubusercontent.com, unpkg.com, codepen.io, vercel.app, netlify.app, etc.
- **Scheme abuse** — data: and blob: payloads
- **Missing directive exploitation** — base-uri injection, form-action hijacking

## `effective` — Combine stacked enforced CSP headers

When a response sends multiple `Content-Security-Policy` headers, browsers enforce their **intersection**. This command approximates that by intersecting literal source lists per directive (with `default-src` fallback where applicable).

```bash
# File: one CSP value per line (at least two non-empty lines)
csp-toolkit effective -f stacked-csp.txt
csp-toolkit effective -f stacked-csp.txt -o json
```
