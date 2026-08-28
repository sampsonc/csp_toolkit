# Live targets

Commands that reach out over the network.

!!! warning
    Only run these against systems you are authorized to test.

## `fetch` — Fetch and analyze live URLs

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

# CI gating against a live target (exit 3 on a violated gate)
csp-toolkit fetch https://staging.example.com --fail-on high --min-grade B

# Fail when a target serves no CSP at all
csp-toolkit fetch https://example.com --fail-on-missing-csp

# Pool findings from every URL into one SARIF report
csp-toolkit fetch https://a.example.com https://b.example.com \
  --analyze -o sarif --output csp.sarif
```

`--fail-on` and `--min-grade` imply `--analyze`, and use the same exit codes as
`analyze` (`3` = gate violated). Report-Only policies are reported but never
gated — they are advisory by definition.

## `scan` — Batch scan and rank targets

```bash
# Scan multiple URLs, ranked weakest-first
csp-toolkit scan https://google.com https://github.com https://facebook.com

# From a file of URLs
csp-toolkit scan -f targets.txt

# Export as CSV or JSON
csp-toolkit scan -f targets.txt -o csv > results.csv
csp-toolkit scan -f targets.txt -o json
```

## `subdomains` — Find weak subdomains

```bash
# Check ~35 common subdomains
csp-toolkit subdomains example.com

# Custom prefixes
csp-toolkit subdomains example.com -p "www,api,staging,admin,internal"

# Export
csp-toolkit subdomains example.com -o json
```

## `monitor` — Track CSP evolution over time

```bash
# Take snapshots and alert on changes
csp-toolkit monitor https://facebook.com https://github.com

# From a file of URLs (run via cron)
csp-toolkit monitor -f targets.txt

# View snapshot history
csp-toolkit history https://facebook.com
```

Stores snapshots in `~/.csp-toolkit/snapshots/`. Alerts when policies are weakened, strengthened, or removed.
