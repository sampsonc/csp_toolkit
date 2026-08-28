# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-08-28

### Fixed

- **Report-Only policies are no longer gated by `analyze`.** `fetch` already skipped gating for Report-Only policies, but `analyze --report-only --fail-on <severity>` still exited 3, contradicting the documented behavior. A Report-Only header blocks nothing, so a weakness in one is not exploitable and must never fail a build. Both commands now route through one `_gate_policy` helper, so they cannot drift apart again. Findings are still reported either way.

## [0.8.0] - 2026-08-28

### Added

- **CI policy gating:** `analyze` and `fetch` accept `--fail-on <severity>` (fail when any finding is at or above `critical`/`high`/`medium`/`low`/`info`, or `none` to disable) and `--min-grade <grade>` (fail when the policy grades below `A+`…`F`). A violated gate exits **3** — deliberately distinct from `1` (runtime error) and `2` (Click usage error) so CI can tell a policy regression apart from a broken invocation. Without a gate flag both commands still always exit `0`.
- **`fetch --fail-on-missing-csp`:** fail when a URL serves no CSP header at all.
- **`--output <file>`:** `analyze` and `fetch` can write `json`/`json-v1`/`sarif` output to a file instead of stdout, so machine output stays clean while gate messages go to stderr. On `fetch`, findings from every URL and policy are pooled into a single report.
- **GitHub Action:** a composite `action.yml` wrapping the above — analyze a `url`, `policy`, or `policy-file`, gate the build on `fail-on`/`min-grade`, and upload SARIF to GitHub code scanning. Exposes `passed` and `sarif-file` outputs. Report-Only policies are reported but never gated.
- **Action self-test workflow:** `.github/workflows/action-test.yml` exercises the action end to end (passing policy, failing policy, policy file, ambiguous input) against the local checkout via `version: local`.
- **Tests:** 25 new CLI tests covering severity threshold ordering, grade comparison, exit-code separation, file output, and gating over mocked live responses.

## [0.7.2] - 2026-05-07

### Fixed

- **CI:** `TestVersionFlag.test_version` now reads `__version__` from package metadata instead of hardcoding the version string, so future patch releases don't break CI. This release contains the same functionality as the unpublished 0.7.1 tag plus this test fix.

## [0.7.1] - 2026-05-07

### Added

- **Live-probe pacing:** `find_bypasses` / `find_bypasses_header` accept a new `probe_delay` parameter (seconds) that sleeps between JSONP liveness probes when `check_live=True`. Exposed on the CLI as `--probe-delay <seconds>` for `csp-toolkit fetch` and `csp-toolkit bypass`.
- **Probe observability:** `probe_jsonp_endpoint` now emits `DEBUG`-level log records for failed probes (recording the exception type and message) and for redirect chains followed during a probe. No behavior change at the default log level.
- **Tests:** New tests verifying `probe_delay` sleeps `n - 1` times for `n` probes and never sleeps when `probe_delay=0`.

### Changed

- **README:** Install instructions updated to use `pip install csp-toolkit` / `uv pip install csp-toolkit` instead of the editable local install.

## [0.7.0] - 2026-04-11

### Added

- **AI-Enhanced Violations Analysis:** New `--ai-enhance` flag for `violations` command provides contextual explanations, security impact assessment, and implementation guidance using Claude AI.
- **Business Context Support:** `--context` option allows specifying business type (e-commerce, saas, etc.) for more relevant AI recommendations.
- **Enhanced JSON Output:** AI analysis included in JSON output when `--ai-enhance` is used.
- **Optional AI Dependencies:** `anthropic` package available as optional dependency (`pip install csp-toolkit[ai]`).
- **Comprehensive Testing:** 7 new tests covering AI enhancement features with proper error handling.

### Changed

- **Documentation:** Updated README.md with AI enhancement examples and installation instructions.
- **Roadmap:** Added detailed feature roadmap with priorities for Burp Suite integration, GitHub Actions, and advanced AI features.

## [0.6.3] - 2026-04-03

### Added

- **`[project.urls]`** in `pyproject.toml` — Homepage, Repository, Documentation, and Author links (shown on the [PyPI project page](https://pypi.org/project/csp-toolkit/)).

### Changed

- **`.gitignore`:** ignore `.letta/` (local session/tooling artifacts).

## [0.6.2] - 2026-04-01

### Added

- **`violations` CLI:** Compare violation report JSON to a supplied CSP (`--csp` / `--csp-file`), show suggested directive/source fixes, optional patched CSP draft (`--fix-mode patch`), and write the draft to a file (`--write-patch`).
- **Library:** `suggest_violation_fixes` and `build_patched_csp` in `csp_toolkit.violations`, re-exported from `csp_toolkit`.

## [0.6.1] - 2026-03-29

### Fixed

- Ship `effective`, `violations`, and `export_ops` in the package so the `effective` and `violations` CLI commands and `json-v1` / SARIF outputs match the 0.6.0 changelog.

## [0.6.0] - 2026-03-27

### Added (bug bounty)

- **Effective / stacked CSP:** `combine_policies` and `combine_enforced_header_policies` — intersection heuristic for multiple enforced policies; `fetch --combine-enforced`; `effective` CLI command.
- **Violation reports:** `parse_violations_json`, grouping, remediation hints; `violations` CLI.
- **Automation exports:** stable `json-v1` document and **SARIF 2.1.0** for `analyze` / `bypass` (`-o json-v1`, `-o sarif`).

## [0.5.1] - 2026-03-27

### Changed

- Patch release; version alignment across package, CLI, and browser extension.

## [0.5.0] - 2026-03-27

### Changed

- Version alignment across package metadata, CLI `--version`, and browser extension manifest.

## [0.4.0] - 2026-03-27

### Added

- `NonceReuseStatus` (`ANALYZED`, `NO_NONCE`, `FETCH_FAILED`) for `detect_nonce_reuse`; results always return `NonceReuseResult` with `http_responses` and `last_error` where relevant.
- `FetchResult.csp_headers` / `csp_report_only_headers` with multiple `Content-Security-Policy` header fields parsed as separate policies; `csp_header` / `csp_report_only_header` remain as first-value properties.
- `py.typed` for type checkers; `__version__` from package metadata (`_version.py`).
- CI: `ruff format --check`, pytest coverage with `--cov-fail-under=75`.
- GitHub Actions workflow to publish tagged releases to PyPI via trusted publishing.

### Changed

- CLI `fetch` and `nonce-check` messaging for multi-header policies and unreachable vs no-nonce cases.
- `report-uri` (fetch mode) prefers a policy that declares `report-uri` / `report-to`.
- Browser extension `manifest.json` version aligned to **0.4.0**.

### Development

- README: authorized-use note for active probes; optional local coverage command.

## [0.3.0] - 2026-03-27

### Added

- `auto` command: `--hash`, `--auto-nonce`, and `--nonce` for inline scripts and styles; `InlineContent` with SHA-256 and nonce assignment; JSON output for inline hashes and nonces.

## [0.2.0] - 2026-03-27

### Added

- `auto` command to crawl pages and generate CSP from discovered resources; crawl depth and page limits.

## [0.1.0] - 2026-03-27

### Added

- Initial release: CSP parse/analyze/bypass/scan/diff/subdomains/monitor, CLI, browser extension, Nuclei templates.

[0.7.2]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.7.2
[0.7.1]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.7.1
[0.7.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.7.0
[0.6.3]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.6.3
[0.6.2]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.6.2
[0.6.1]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.6.1
[0.6.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.6.0
[0.5.1]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.5.1
[0.5.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.5.0
[0.4.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.4.0
[0.3.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.3.0
[0.2.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.1.0
