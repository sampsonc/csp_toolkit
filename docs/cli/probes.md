# Active probes

Targeted security tests against a live host.

!!! warning
    Only run these against systems you are authorized to test.

## `nonce-check` — Detect static nonce reuse

```bash
csp-toolkit nonce-check https://target.com
csp-toolkit nonce-check https://target.com -n 10  # 10 requests
```

Fetches the URL multiple times and checks if the CSP nonce changes. A static nonce completely defeats nonce-based CSP protection.

The CLI distinguishes **unreachable host** (no HTTP responses) from **CSP present but no nonce**. In code, use `NonceReuseStatus` (`ANALYZED`, `NO_NONCE`, `FETCH_FAILED`) on the result of `detect_nonce_reuse`.

## `header-inject` — Test for CSP header injection

```bash
csp-toolkit header-inject https://target.com
```

Tests CRLF injection vectors that could allow an attacker to inject or override CSP headers.

## `report-uri` — Analyze reporting endpoints

```bash
csp-toolkit report-uri --url https://target.com
csp-toolkit report-uri "script-src 'self'; report-uri https://example.com/csp"
```

Checks if the `report-uri` / `report-to` endpoint is reachable and accepts CSP violation reports.
