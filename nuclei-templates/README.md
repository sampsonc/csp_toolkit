# CSP Toolkit Nuclei Templates

[Nuclei](https://github.com/projectdiscovery/nuclei) templates for detecting CSP misconfigurations at scale.

## Templates

| Template | Severity | What it detects |
|----------|----------|-----------------|
| `csp-missing.yaml` | Medium | No CSP header at all |
| `csp-unsafe-inline.yaml` | High | `'unsafe-inline'` in script-src |
| `csp-unsafe-eval.yaml` | Medium | `'unsafe-eval'` in script-src |
| `csp-wildcard-script.yaml` | High | Wildcard `*` in script-src |
| `csp-data-uri-script.yaml` | Critical | `data:` URI in script-src |
| `csp-https-scheme-script.yaml` | High | `https:` scheme in script-src |
| `csp-report-only.yaml` | Info | CSP-Report-Only without enforced CSP |
| `csp-missing-object-src.yaml` | Medium | Missing object-src directive |
| `csp-missing-base-uri.yaml` | Medium | Missing base-uri directive |
| `csp-broad-cdn-whitelist.yaml` | Medium | Broad CDN wildcards (*.googleapis.com, etc.) |

## Usage

```bash
# Scan a single target
nuclei -t nuclei-templates/ -u https://example.com

# Scan a list of targets
nuclei -t nuclei-templates/ -l targets.txt

# Scan with httpx pipeline
cat subdomains.txt | httpx -silent | nuclei -t nuclei-templates/

# Only critical/high findings
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high
```

## Integration with httpx

```bash
# Discover live hosts and pipe to nuclei
echo "example.com" | subfinder -silent | httpx -silent | nuclei -t nuclei-templates/

# Export results as JSON
nuclei -t nuclei-templates/ -l targets.txt -json -o csp-findings.json
```

## Combining with csp-toolkit CLI

Use nuclei for broad scanning, then csp-toolkit for deep analysis on flagged targets:

```bash
# Step 1: Broad scan with nuclei
nuclei -t nuclei-templates/ -l targets.txt -severity critical,high -o flagged.txt

# Step 2: Deep analysis with csp-toolkit
cat flagged.txt | awk '{print $NF}' | sort -u > urls.txt
csp-toolkit scan -f urls.txt -o csv > detailed-results.csv
```
