# Generation and repair

Commands that produce or fix a policy.

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
