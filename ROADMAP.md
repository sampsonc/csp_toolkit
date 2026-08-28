# Roadmap

Security-research and bug-bounty oriented work for **csp-toolkit**. Priorities are automation-friendly output, realistic multi-header behavior, and triage helpers.

## Shipped — 0.6.0

| Priority | Theme | Delivered |
|----------|--------|-----------|
| **P1** | Stacked / effective CSP | `combine_policies`, `combine_enforced_header_policies` (intersection heuristic + warnings); `fetch --combine-enforced`; `effective` CLI. |
| **P2** | Violation JSON workflow | `parse_violations_json`, grouping, hints, `violations_summary_json`; `violations` CLI (stdin/file). |
| **P3** | Stable machine output | **json-v1** and **SARIF 2.1.0** for `analyze` / `bypass` (`-o json-v1`, `-o sarif`). |

Details: [CHANGELOG.md](CHANGELOG.md) (0.6.0).

## Shipped — 0.7.x / 0.8.x

| Version | Theme | Delivered |
|---------|-------|-----------|
| **0.7.0** | AI-Enhanced Violations | `violations --ai-enhance` for contextual explanations, impact assessment, and fix guidance via Claude; `--context <business-type>`; AI output in JSON; optional `csp-toolkit[ai]` extra. |
| **0.7.1** | Live-probe pacing & observability | `--probe-delay` for `fetch` / `bypass` (sleeps between JSONP liveness probes); `DEBUG` logging for failed probes and redirect chains. |
| **0.7.2** | CI hardening | Version test reads `__version__` from package metadata so patch releases no longer break CI. |
| **0.8.0** | GitHub Actions / CI integration | `--fail-on` / `--min-grade` exit-code gating (exit 3) and `--output` for `analyze` / `fetch`; `fetch --fail-on-missing-csp`; composite `action.yml` with SARIF upload to code scanning. |

Details: [CHANGELOG.md](CHANGELOG.md) (0.7.0–0.8.0).

## Planned — Future Releases

### High Priority
| Priority | Theme | Description |
|----------|-------|-------------|
| **P1** | Burp Suite Integration | Browser extension for real-time CSP analysis in Burp Suite. |

### Medium Priority  
| Priority | Theme | Description |
|----------|-------|-------------|
| **P2** | AI Policy Recommendations | Full LLM-powered CSP policy generation with business context. |
| **P3** | Real-time Bypass Intelligence | Auto-updating bypass database from threat intelligence. |
| **P4** | Advanced Reporting | Executive dashboards and trend analysis. |

### Integration & Automation
| Priority | Theme | Description |
|----------|-------|-------------|
| **P5** | Security Tool Integration | ZAP, Nessus, OpenVAS plugin formats. |
| **P6** | Cloud Security Integration | AWS CloudFront, Azure Front Door, Cloudflare analysis. |
| **P7** | Supply Chain Security | Third-party script analysis and SBOM integration. |
| **P8** | Performance Analysis | CSP impact on page load with Lighthouse integration. |

### Research & Innovation
| Priority | Theme | Description |
|----------|-------|-------------|
| **P9** | ML Bypass Detection | Machine learning models for bypass pattern prediction. |
| **P10** | Anomaly Detection | Unusual policy combination analysis. |

## Legacy Future Items
- **Combine semantics:** Document edge cases; optional stricter modes or union paths where research needs differ from “effective minimum.”
- **Violations:** Richer parsers (e.g. browser export variants), optional correlation with `fetch` / policy text.
- **SARIF / JSON:** More rule metadata, fingerprints, or integration notes for CI (CodeQL-style consumers).
- **Extension / nuclei:** Align versions and workflows with CLI/library feature set where it helps hunters.

Update this file when priorities change.
