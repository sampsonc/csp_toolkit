# Analyzer Checks (21)

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
