# GitHub Action

Gate pull requests on CSP quality and publish findings to GitHub code scanning.

```yaml
name: CSP Check
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  csp:
    runs-on: ubuntu-latest
    steps:
      - uses: sampsonc/csp_toolkit@v1
        with:
          url: https://staging.example.com
          fail-on: high
          min-grade: B
```

Analyze a policy string or file instead of a live URL:

```yaml
      - uses: sampsonc/csp_toolkit@v1
        with:
          policy-file: config/csp.txt
          fail-on: critical
          upload-sarif: false
```

| Input | Default | Description |
|-------|---------|-------------|
| `url` | — | URL to fetch and analyze |
| `policy` | — | CSP header string to analyze |
| `policy-file` | — | File containing a CSP header string |
| `fail-on` | `high` | Fail if any finding is at or above this severity (`critical`…`info`, or `none`) |
| `min-grade` | — | Fail if the grade is below this letter (`A+`…`F`) |
| `fail-on-missing-csp` | `false` | With `url`, fail when no CSP header is served |
| `bypass` | `false` | Also run the JSONP/CDN bypass finder |
| `report-only` | `false` | Treat `policy`/`policy-file` as a Report-Only header |
| `upload-sarif` | `true` | Upload SARIF to code scanning (needs `security-events: write`) |
| `sarif-file` | `csp-toolkit.sarif` | Where to write the SARIF report |
| `version` | `latest` | csp-toolkit version from PyPI, or `local` to install from the checkout |
| `python-version` | `3.12` | Python used to run the tool |

Outputs: `passed` (`true`/`false`) and `sarif-file`. Exactly one of `url`, `policy`, or
`policy-file` must be set. Report-Only policies are never gated — they are advisory by
definition — but their findings still appear in the SARIF report. Requires csp-toolkit >= 0.8.0.
