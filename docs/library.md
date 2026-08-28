# Library Usage

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
