# Roadmap

Security-research and bug-bounty oriented work for **csp-toolkit**. Priorities are automation-friendly output, realistic multi-header behavior, and triage helpers.

## Shipped — 0.6.0

| Priority | Theme | Delivered |
|----------|--------|-----------|
| **P1** | Stacked / effective CSP | `combine_policies`, `combine_enforced_header_policies` (intersection heuristic + warnings); `fetch --combine-enforced`; `effective` CLI. |
| **P2** | Violation JSON workflow | `parse_violations_json`, grouping, hints, `violations_summary_json`; `violations` CLI (stdin/file). |
| **P3** | Stable machine output | **json-v1** and **SARIF 2.1.0** for `analyze` / `bypass` (`-o json-v1`, `-o sarif`). |

Details: [CHANGELOG.md](CHANGELOG.md) (0.6.0).

## In Progress — 0.7.0

| Priority | Theme | Status |
|----------|-------|---------|
| **P1** | AI-Enhanced Violations | 🚧 LLM integration for violation explanations and smart policy fixes |

## Planned — Future Releases

### High Priority
| Priority | Theme | Description |
|----------|-------|-------------|
| **P2** | Burp Suite Integration | Browser extension for real-time CSP analysis in Burp Suite |
| **P3** | GitHub Actions/CI Integration | Policy enforcement in CI/CD pipelines |

### Medium Priority  
| Priority | Theme | Description |
|----------|-------|-------------|
| **P4** | AI Policy Recommendations | Full LLM-powered CSP policy generation with business context |
| **P5** | Real-time Bypass Intelligence | Auto-updating bypass database from threat intelligence |
| **P6** | Advanced Reporting | Executive dashboards and trend analysis |

### Integration & Automation
| Priority | Theme | Description |
|----------|-------|-------------|
| **P7** | Security Tool Integration | ZAP, Nessus, OpenVAS plugin formats |
| **P8** | Cloud Security Integration | AWS CloudFront, Azure Front Door, Cloudflare analysis |
| **P9** | Supply Chain Security | Third-party script analysis and SBOM integration |
| **P10** | Performance Analysis | CSP impact on page load with Lighthouse integration |

### Research & Innovation
| Priority | Theme | Description |
|----------|-------|-------------|
| **P11** | ML Bypass Detection | Machine learning models for bypass pattern prediction |
| **P12** | Anomaly Detection | Unusual policy combination analysis |

## Legacy Future Items
- **Combine semantics:** Document edge cases; optional stricter modes or union paths where research needs differ from “effective minimum.”
- **Violations:** Richer parsers (e.g. browser export variants), optional correlation with `fetch` / policy text.
- **SARIF / JSON:** More rule metadata, fingerprints, or integration notes for CI (CodeQL-style consumers).
- **Extension / nuclei:** Align versions and workflows with CLI/library feature set where it helps hunters.

Update this file when priorities change.
