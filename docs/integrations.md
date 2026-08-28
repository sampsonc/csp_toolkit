# Integrations

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
