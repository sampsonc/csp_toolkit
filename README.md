# csp-toolkit

Parse, analyze, generate, and find bypasses in Content Security Policy headers.

A Python library and CLI tool for security researchers and bug bounty hunters. Auto-generate CSPs by crawling a website, analyze policies with 21 weakness checks, find bypasses against a database of 79 domains (66 JSONP + 13 CDNs), score policies A+ to F, diff policies, detect nonce reuse, and more.

## Install

```bash
pip install -e .
# or with uv
uv pip install -e .
```

## CLI Commands

### `analyze` — Check a CSP for weaknesses

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
```

Outputs a severity-sorted findings table and an A+ to F grade with numeric score (0-100).

### `bypass` — Find CSP bypass vectors

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

### `fetch` — Fetch and analyze live URLs

```bash
# Fetch CSP headers and meta tags
csp-toolkit fetch https://example.com

# Fetch + analyze + find bypasses
csp-toolkit fetch https://example.com --all

# Multiple URLs
csp-toolkit fetch https://example.com https://github.com --all

# Probe JSONP endpoints live
csp-toolkit fetch https://example.com --all --check-live

# Skip SSL verification
csp-toolkit fetch https://example.com --all --no-verify-ssl
```

### `scan` — Batch scan and rank targets

```bash
# Scan multiple URLs, ranked weakest-first
csp-toolkit scan https://google.com https://github.com https://facebook.com

# From a file of URLs
csp-toolkit scan -f targets.txt

# Export as CSV or JSON
csp-toolkit scan -f targets.txt -o csv > results.csv
csp-toolkit scan -f targets.txt -o json
```

### `diff` — Compare two CSP policies

```bash
# Compare two CSP strings
csp-toolkit diff "script-src 'self' 'unsafe-inline'" "script-src 'self' 'nonce-abc' 'strict-dynamic'"

# Compare two live URLs
csp-toolkit diff https://example.com https://staging.example.com

# JSON output
csp-toolkit diff -o json "old csp" "new csp"
```

Shows score delta, added/removed/modified directives, and warns when changes weaken the policy.

### `subdomains` — Find weak subdomains

```bash
# Check ~35 common subdomains
csp-toolkit subdomains example.com

# Custom prefixes
csp-toolkit subdomains example.com -p "www,api,staging,admin,internal"

# Export
csp-toolkit subdomains example.com -o json
```

### `monitor` — Track CSP evolution over time

```bash
# Take snapshots and alert on changes
csp-toolkit monitor https://facebook.com https://github.com

# From a file of URLs (run via cron)
csp-toolkit monitor -f targets.txt

# View snapshot history
csp-toolkit history https://facebook.com
```

Stores snapshots in `~/.csp-toolkit/snapshots/`. Alerts when policies are weakened, strengthened, or removed.

### `nonce-check` — Detect static nonce reuse

```bash
csp-toolkit nonce-check https://target.com
csp-toolkit nonce-check https://target.com -n 10  # 10 requests
```

Fetches the URL multiple times and checks if the CSP nonce changes. A static nonce completely defeats nonce-based CSP protection.

The CLI distinguishes **unreachable host** (no HTTP responses) from **CSP present but no nonce**. In code, use `NonceReuseStatus` (`ANALYZED`, `NO_NONCE`, `FETCH_FAILED`) on the result of `detect_nonce_reuse`.

### `header-inject` — Test for CSP header injection

```bash
csp-toolkit header-inject https://target.com
```

Tests CRLF injection vectors that could allow an attacker to inject or override CSP headers.

### `report-uri` — Analyze reporting endpoints

```bash
csp-toolkit report-uri --url https://target.com
csp-toolkit report-uri "script-src 'self'; report-uri https://example.com/csp"
```

Checks if the `report-uri` / `report-to` endpoint is reachable and accepts CSP violation reports.

### `effective` — Combine stacked enforced CSP headers

When a response sends multiple `Content-Security-Policy` headers, browsers enforce their **intersection**. This command approximates that by intersecting literal source lists per directive (with `default-src` fallback where applicable).

```bash
# File: one CSP value per line (at least two non-empty lines)
csp-toolkit effective -f stacked-csp.txt
csp-toolkit effective -f stacked-csp.txt -o json
```

### `violations` — Summarize violation reports and suggest policy fixes

Reads JSON from a file (one object, an array, or `csp-report`-wrapped reports). Without a CSP, it only groups and counts violations. With `--csp` or `--csp-file`, it suggests which directive likely needs which source, checks whether that source is already allowed (including `default-src` fallback), and can emit a **patched CSP draft**.

```bash
# Grouped summary only
csp-toolkit violations reports.json

# Compare reports to your current policy (string or file)
csp-toolkit violations reports.json --csp "default-src 'self'; script-src 'self'"
csp-toolkit violations reports.json --csp-file policy.txt

# Emit a draft policy with additive fixes (review before deploy)
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch

# Write the draft to disk
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch --write-patch patched.csp

# JSON: summary, suggestions, patched_csp (patch mode), patched_csp_written_to (with --write-patch)
csp-toolkit violations reports.json --csp-file policy.txt --fix-mode patch --format json
```

**Workflow with a live site:** fetch or copy the CSP first (`csp-toolkit fetch https://example.com`), save violation JSON from your browser or `report-uri` collector, then run `violations` with `--csp-file`. Inline/script violations may suggest `'unsafe-inline'`; prefer nonces or hashes where possible.

### `auto` — Auto-generate a CSP from a live website

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

### `generate` — Generate a CSP from a preset

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

## Library Usage

```python
import csp_toolkit

# Parse
policy = csp_toolkit.parse("script-src 'self' 'unsafe-inline' *.googleapis.com")

# Analyze + score
findings = csp_toolkit.analyze(policy)
grade, score = csp_toolkit.score_policy(policy)
print(f"{grade} ({score}/100), {len(findings)} findings")

# Find bypasses
bypasses = csp_toolkit.find_bypasses(policy)
for b in bypasses:
    print(b)  # [HIGH] JSONP bypass via maps.googleapis.com (in script-src)

# Diff two policies
diff = csp_toolkit.diff_headers(old_csp, new_csp)
print(diff.weakened)       # Directives that got weaker
print(diff.strengthened)   # Directives that got stronger

# Scan multiple URLs
results = csp_toolkit.scan_urls(["https://example.com", "https://github.com"])
for r in results:
    print(f"{r.url}: {r.grade} ({r.score})")

# Check subdomains
results = csp_toolkit.check_subdomains("example.com")

# Track evolution
snapshot, alert = csp_toolkit.take_snapshot("https://example.com")
if alert and alert.alert_type == "weakened":
    print(f"CSP weakened! {alert.score_delta}")

# Detect nonce reuse (check result.status: ANALYZED, NO_NONCE, or FETCH_FAILED)
result = csp_toolkit.detect_nonce_reuse("https://example.com")
if result.status == csp_toolkit.NonceReuseStatus.ANALYZED and result.is_static:
    print(f"Static nonce: {result.nonces_found[0]}")

# Check header injection
result = csp_toolkit.check_header_injection("https://example.com")

# Analyze report-uri
result = csp_toolkit.analyze_report_uri(policy)

# Violation reports: parse JSON, suggest fixes vs a policy, build patched draft
reports = csp_toolkit.parse_violations_json(open("reports.json").read())
suggestions = csp_toolkit.suggest_violation_fixes(reports, policy)
patched = csp_toolkit.build_patched_csp(policy, suggestions)

# Stacked policies (intersection heuristic)
combined, warnings = csp_toolkit.combine_enforced_header_policies(
    ["default-src 'self'", "script-src https://cdn.example.com"]
)

# Look up specific domains
csp_toolkit.check_domain_jsonp("accounts.google.com")
csp_toolkit.check_domain_gadgets("cdnjs.cloudflare.com")

# Generate
csp = csp_toolkit.CSPBuilder.strict(nonce="abc123").build()

# Fetch live
result = csp_toolkit.fetch_csp("https://example.com")
```

## Analyzer Checks (21)

| Severity | Check |
|----------|-------|
| CRITICAL | `unsafe-inline` in script-src |
| CRITICAL | `data:` URI in script-src |
| CRITICAL | No script-src and no default-src |
| HIGH | `unsafe-eval` in script-src |
| HIGH | `https:` scheme in script-src (allows any HTTPS origin) |
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
| INFO | Missing `require-trusted-types-for` |
| INFO | Missing `navigate-to` |

## Bypass Database

- **66 JSONP domains** (69 endpoints) — Google (10+), Facebook, Twitter, Yahoo, LinkedIn, Microsoft, GitHub, Wikipedia, Pinterest, Tumblr, Spotify, Vimeo, SoundCloud, Dailymotion, Reddit, WordPress, Bing, Stripe, reCAPTCHA, Cloudflare Turnstile, Mixpanel, Segment, Hotjar, Twitch, and more
- **13 CDN domains** (31 gadgets) — cdnjs, jsDelivr, unpkg, googleapis, jQuery CDN, BootstrapCDN, BootCSS, Sina, StaticFile, Statically, gitcdn, RawGit, raw.githubusercontent.com
- **Gadget libraries** — AngularJS template injection, Vue.js template injection, Knockout.js data-bind, Lodash/Underscore template RCE, Handlebars prototype pollution, Dojo/Ember template injection, jQuery selector XSS, jQuery UI dialog XSS
- **18+ arbitrary hosting domains** — raw.githubusercontent.com, codepen.io, jsfiddle.net, surge.sh, netlify.app, vercel.app, pages.dev, workers.dev, and more

## Browser Extension

A Chrome extension that shows a CSP grade badge on every page you visit.

1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `browser-extension/` directory

The badge shows the CSP grade (A+ to F) with color coding. Click it to see the full findings list, score, and raw CSP header. All analysis runs locally — no network requests.

## Nuclei Templates

10 templates for scanning CSP misconfigurations at scale with [Nuclei](https://github.com/projectdiscovery/nuclei):

```bash
# Scan a single target
nuclei -t nuclei-templates/ -u https://example.com

# Scan a list with httpx pipeline
cat subdomains.txt | httpx -silent | nuclei -t nuclei-templates/ -severity critical,high

# Broad scan, then deep analysis with csp-toolkit
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high -o flagged.txt
cat flagged.txt | awk '{print $NF}' | sort -u | csp-toolkit scan -f - -o csv
```

| Template | Severity | Detects |
|----------|----------|---------|
| `csp-missing` | Medium | No CSP header |
| `csp-unsafe-inline` | High | `'unsafe-inline'` in script-src |
| `csp-unsafe-eval` | Medium | `'unsafe-eval'` in script-src |
| `csp-wildcard-script` | High | Wildcard `*` in script-src |
| `csp-data-uri-script` | Critical | `data:` in script-src |
| `csp-https-scheme-script` | High | `https:` scheme in script-src |
| `csp-report-only` | Info | Report-Only without enforced CSP |
| `csp-missing-object-src` | Medium | Missing object-src |
| `csp-missing-base-uri` | Medium | Missing base-uri |
| `csp-broad-cdn-whitelist` | Medium | Broad CDN wildcards in script-src |

## Development

Use active probes (`fetch`, `scan`, `header-inject`, `nonce-check`, `bypass --check-live`, etc.) only against systems you are **authorized** to test.

Release history: [CHANGELOG.md](CHANGELOG.md). Security reporting and dependency notes: [SECURITY.md](SECURITY.md).

Pushing a tag `v*` runs [`.github/workflows/publish.yml`](.github/workflows/publish.yml) (tests, then PyPI upload via [trusted publishing](https://docs.pypi.org/trusted-publishers/)). Configure the publisher once under [PyPI → csp-toolkit → Publishing](https://pypi.org/manage/project/csp-toolkit/settings/publishing/).

```bash
# Install dev dependencies
uv sync --all-extras

# Run tests (269 tests)
uv run pytest -v

# Same coverage gate as CI (optional locally)
uv run pytest --cov=csp_toolkit --cov-fail-under=75 -q

# Lint and format check
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```
