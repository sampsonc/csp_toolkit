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

#### Baseline ratcheting

`--fail-on` and `--min-grade` are absolute: a policy that already grades D fails on day one and
keeps failing, so the check gets removed. A baseline records what the policy looks like *today* and
gates only on findings that are not in it — so the gate is adoptable at any starting quality while
remediation proceeds on its own schedule.

```bash
# Record the current state once, then commit the file
csp-toolkit analyze -f policy.txt --baseline .csp-baseline.json --update-baseline

# Later runs: exit 3 only on findings the baseline does not already contain
csp-toolkit analyze -f policy.txt --baseline .csp-baseline.json

# Narrow the ratchet: only NEW critical/high findings fail the build
csp-toolkit analyze -f policy.txt --baseline .csp-baseline.json --fail-on high
```

With a baseline, `--fail-on` filters *which new findings count* rather than gating on the policy's
total state — a pre-existing HIGH does not fail the build, a newly introduced one does.
`--min-grade` stays absolute, because a grade floor is meant as a hard limit. Report-Only policies
are still never gated.

A baseline stores each finding's stable fingerprint plus its check id, severity and title, so the
committed file is reviewable in a pull request. Fingerprints are derived from the check id,
directive and subject — never the message text — so rewording a finding does not invalidate a
baseline. When a finding is fixed, the run reports it as resolved and suggests re-recording to lock
the improvement in.

`fetch --baseline` works the same way and keys entries by URL, so one file can cover several
deployed targets.

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
