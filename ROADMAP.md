# Roadmap

Security-research and bug-bounty oriented work for **csp-toolkit**. Priorities are automation-friendly output, realistic multi-header behavior, and triage helpers.

## Shipped — 0.6.0

| Priority | Theme | Delivered |
|----------|--------|-----------|
| **P1** | Stacked / effective CSP | `combine_policies`, `combine_enforced_header_policies` (intersection heuristic + warnings); `fetch --combine-enforced`; `effective` CLI. |
| **P2** | Violation JSON workflow | `parse_violations_json`, grouping, hints, `violations_summary_json`; `violations` CLI (stdin/file). |
| **P3** | Stable machine output | **json-v1** and **SARIF 2.1.0** for `analyze` / `bypass` (`-o json-v1`, `-o sarif`). |

Details: [CHANGELOG.md](CHANGELOG.md) (0.6.0).

## Future (not scheduled)

Ideas for later releases; no ordering commitment.

- **Combine semantics:** Document edge cases; optional stricter modes or union paths where research needs differ from “effective minimum.”
- **Violations:** Richer parsers (e.g. browser export variants), optional correlation with `fetch` / policy text.
- **SARIF / JSON:** More rule metadata, fingerprints, or integration notes for CI (CodeQL-style consumers).
- **Extension / nuclei:** Align versions and workflows with CLI/library feature set where it helps hunters.

Update this file when priorities change.
