# Generation and repair

Commands that explain, produce, or fix a policy.

## `explain` — Show which directive actually governs each resource type

```bash
csp-toolkit explain "script-src 'nonce-a' 'strict-dynamic'; child-src https://cdn.example"

# Only the resource types that inherit from a fallback — where the surprises are
csp-toolkit explain -f policy.txt --inherited-only

# One resource type, by directive or friendly name
csp-toolkit explain -f policy.txt --resource worker-src
csp-toolkit explain -f policy.txt --resource workers

csp-toolkit explain -f policy.txt -o json
```

Resolves every resource type through its real CSP Level 3 fallback chain and labels each one
`explicit`, `inherited`, or `unrestricted`. This is how you catch a policy that looks strict
because `script-src` is strict while workers inherit a much looser `child-src`:

```
Resource   Governed by             Status      Effective sources
workers    worker-src → child-src  inherited   https://cdn.example
frames     frame-src → child-src   inherited   https://cdn.example
scripts    script-src              explicit    'nonce-a' 'strict-dynamic'
```

Most fetch directives fall back to `default-src`, but not all of them do it directly —
`worker-src` goes through `child-src` then `script-src`, and `frame-src` through `child-src`.
Non-fetch directives (`frame-ancestors`, `form-action`, `base-uri`) do not fall back at all, so
their absence means unrestricted.

## `harden` — Emit a tightened version of a policy

```bash
# Safe by default: skips anything that can break a page
csp-toolkit harden -f policy.txt

# Just the policy, for piping into a config file
csp-toolkit harden -f policy.txt -o header > policy.hardened.txt

# Attempt the breaking changes too
csp-toolkit harden -f policy.txt --level strict --allow-breaking

csp-toolkit harden -f policy.txt -o json
```

Every change is labelled with its risk, and nothing is applied silently:

| Risk | Meaning |
|------|---------|
| `none` | A no-op for modern browsers — e.g. dropping `'unsafe-inline'` that a nonce already causes CSP2+ browsers to ignore |
| `low` | Rarely breaks a page, and the breakage is obvious if it does — adding `object-src 'none'`, upgrading `http:` to `https:` |
| `high` | Removes capability the page may rely on; requires `--allow-breaking` |

`--level safe` (the default) applies `none` and `low` changes: it removes inert keywords, adds the
directives that have no `default-src` fallback (`object-src`, `base-uri`, `form-action`), and pins
`worker-src` when workers would otherwise inherit a looser `child-src`. `--level strict` also
attempts the `high`-risk changes — removing `'unsafe-eval'`, script wildcards and `data:`/`blob:`
script sources, adding `frame-ancestors 'none'` and `require-trusted-types-for 'script'` — and
still needs `--allow-breaking` to apply them.

Hardening is idempotent and never lowers a policy's score. Two deliberate limits: it will not strip
`'unsafe-inline'` from `script-src` unless a nonce or hash is already present (use `auto` to
generate hashes for a real page first), and it leaves wildcards in non-script directives alone,
because it cannot know which origins your framing or images legitimately need. Those keep showing
up in `analyze` output.

## `auto` — Auto-generate a CSP from a live website

```bash
# Crawl a page and generate a CSP based on its resources
csp-toolkit auto https://example.com

# Output as nginx or apache directive
csp-toolkit auto https://example.com -o nginx
csp-toolkit auto https://example.com -o apache

# Crawl deeper (follow same-origin links)
csp-toolkit auto https://example.com --depth 1

# Auto-generate nonces for inline scripts/styles (shows which tags need nonce="...")
csp-toolkit auto https://example.com --auto-nonce

# Use SHA-256 hashes for inline content (most secure, no HTML changes needed)
csp-toolkit auto https://example.com --hash

# Use a specific nonce value
csp-toolkit auto https://example.com --nonce my-server-nonce

# Analyze the generated CSP for weaknesses
csp-toolkit auto https://example.com --analyze

# JSON output with all discovered resources, hashes, and nonces
csp-toolkit auto https://example.com -o json
```

Discovers all external resources (scripts, styles, images, fonts, frames, forms, media) and generates a tailored CSP that whitelists exactly the origins the site needs.

Three modes for handling inline scripts/styles:

| Flag | Security | How it works |
|------|----------|--------------|
| `--hash` | Highest | Computes SHA-256 of each inline block — browser verifies content matches |
| `--auto-nonce` | High | Generates a nonce, tells you which tags need `nonce="..."` added |
| `--nonce VALUE` | High | Same as auto-nonce but you provide the value |
| (default) | Low | Uses `unsafe-inline` with a warning |

## `generate` — Generate a CSP from a preset

```bash
# Strict (nonce-based, recommended)
csp-toolkit generate --preset strict
csp-toolkit generate --preset strict --nonce my-random-nonce

# Moderate or permissive
csp-toolkit generate --preset moderate
csp-toolkit generate --preset permissive

# Add custom sources
csp-toolkit generate --preset moderate --add-source "script-src cdn.example.com"

# Output formats: header (default), meta, nginx, apache
csp-toolkit generate --preset strict -o nginx
csp-toolkit generate --preset strict -o apache
csp-toolkit generate --preset strict -o meta
```

## `violations` — Summarize violation reports and suggest policy fixes

Reads JSON from a file (one object, an array, or `csp-report`-wrapped reports). Without a CSP, it only groups and counts violations. With `--csp` or `--csp-file`, it suggests which directive likely needs which source, checks whether that source is already allowed (including `default-src` fallback), and can emit a **patched CSP draft**.

```bash
# Grouped summary only
csp-toolkit violations reports.json

# Compare reports to your current policy (string or file)
csp-toolkit violations reports.json --csp "default-src 'self'; script-src 'self'"
csp-toolkit violations reports.json --csp-file policy.txt

# AI-enhanced analysis with explanations and recommendations
csp-toolkit violations reports.json --csp-file policy.txt --ai-enhance --context "e-commerce"

# Emit a draft policy with additive fixes (review before deploy)
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch

# Write the draft to disk
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch --write-patch patched.csp

# JSON: summary, suggestions, patched_csp (patch mode), ai_analysis (with --ai-enhance)
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch --format json --ai-enhance
```

**AI Enhancement** (requires `pip install anthropic` and `ANTHROPIC_API_KEY`):
- **Contextual Explanations**: Understands why violations occur in business context
- **Security Impact Assessment**: Risk scoring with detailed reasoning  
- **Implementation Guidance**: Step-by-step deployment recommendations
- **Smart Recommendations**: Business-aware policy suggestions beyond basic fixes

**Workflow with a live site:** fetch or copy the CSP first (`csp-toolkit fetch https://example.com`), save violation JSON from your browser or `report-uri` collector, then run `violations` with `--csp-file`. Inline/script violations may suggest `'unsafe-inline'`; prefer nonces or hashes where possible.

## `diff` — Compare two CSP policies

```bash
# Compare two CSP strings
csp-toolkit diff "script-src 'self' 'unsafe-inline'" "script-src 'self' 'nonce-abc' 'strict-dynamic'"

# Compare two live URLs
csp-toolkit diff https://example.com https://staging.example.com

# JSON output
csp-toolkit diff -o json "old csp" "new csp"
```

Shows score delta, added/removed/modified directives, and warns when changes weaken the policy.
