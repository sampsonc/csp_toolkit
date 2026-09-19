# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-09-19

### Added

- **Baseline ratcheting for CI gates.** `analyze` and `fetch` accept `--baseline <file>` and `--update-baseline`. An absolute gate (`--fail-on high`) only works on a policy that is already good; a policy grading D fails on day one and keeps failing until someone removes the check. A baseline records the findings a policy has today, and later runs fail only on findings that are not in it — so the gate is adoptable at any starting quality while remediation proceeds separately. With a baseline, `--fail-on` narrows *which new findings* count as a regression rather than gating on the policy's total state; `--min-grade` stays absolute. Report-Only policies are still never gated. `fetch` keys entries by URL, so one file covers several deployed targets. New `baseline` input on the GitHub Action.
- **`explain` command.** Resolves every resource type through its real CSP Level 3 fallback chain and labels each `explicit`, `inherited`, or `unrestricted`. Catches the policy that looks strict because `script-src` is strict while workers inherit a much looser `child-src`. `--resource` narrows to one type, `--inherited-only` shows just the inherited ones, and `-o json` emits the chains.
- **`harden` command.** Emits a tightened policy from an existing one — the executable form of the remediation prose already carried on every finding. Each change is labelled by risk: `none` (a no-op for modern browsers, like dropping `'unsafe-inline'` that a nonce already neutralises), `low` (rarely breaks a page), `high` (removes capability the page may rely on, and needs `--allow-breaking`). `--level safe` is the default and never applies a `high` change; `-o header` prints just the policy for piping into config. Hardening is idempotent and never lowers a policy's score.
- **Stable finding identity.** Every `Finding` now carries a `check_id` from the analyzer's check registry, a `subject` for checks that emit several findings per directive, and a `fingerprint` derived from those rather than from the message text — so rewording a finding does not invalidate a committed baseline or churn a code-scanning alert.
- **Public API:** `explain_policy`, `explain_json`, `Resolution`, `harden_policy`, `harden_json`, `HardenResult`, `Change`, `Baseline`, `compare_to_baseline`, `entry_for_policy`, `Comparison`, `BaselineError`, `CHECKS`, `FALLBACK_CHAINS`.
- **Tests:** 105 new tests (422 total), including invariants that hardening is idempotent and never lowers a score, that finding fingerprints never collide within a report, and that a reworded title cannot look like a baseline regression.

### Fixed

- **`Policy.effective_directive` now follows the real CSP Level 3 fallback chains.** It previously fell back from any fetch directive straight to `default-src`, skipping the intermediate hops: `worker-src` actually resolves through `child-src` then `script-src`, `frame-src` through `child-src`, and the `-elem`/`-attr` variants through their parent directive. Callers asking what governs a worker or a frame got `default-src` when a `child-src` was present and in force. The chains are now declared in `models.FALLBACK_CHAINS` and exposed through `Policy.fallback_chain()` and `Policy.resolve()`, which also reports *which* directive a value came from.

### Changed

- **json-v1 is now `schema_version` 1.1.** The `id` field was a fresh `uuid4` on every run, so nothing could key on it; it is now the finding's stable fingerprint. Added `check_id` and `subject` fields. Any consumer that depended on the previous `id` was already unable to match a finding across two runs, so this cannot break a working integration.
- **SARIF `ruleId` is now the stable check id** (e.g. `unsafe-inline-script`) rather than the finding's prose title, which means rewording a message no longer creates a new GitHub code-scanning alert. Results now also carry `partialFingerprints`, and the run declares `rules` metadata with `security-severity` so alerts sort correctly in the Security tab.

## [0.8.2] - 2026-09-18

### Fixed

- **`<meta>`-delivered policies no longer get credit for directives browsers ignore.** `parse_meta` documented that `report-uri`, `frame-ancestors`, and `sandbox` are ignored in a `<meta http-equiv>` policy, but parsed them anyway. A site serving `<meta ... content="frame-ancestors 'none'">` therefore suppressed the "Missing frame-ancestors" finding and scored as protected against clickjacking that the browser never enforced. Those directives are now dropped from the parsed policy, and the names are recorded on `Policy.ignored_directives`. Because this removes a false negative, affected meta-delivered policies will score lower than on 0.8.1 — the new grade is the accurate one.

### Added

- **Check: missing `worker-src` inheriting a broader `child-src`** (MEDIUM). Workers fall back `worker-src` → `child-src` → `script-src` → `default-src`. When `child-src` is present and allows hosts or schemes that `script-src` does not, worker code loads from origins the `script-src` was written to exclude — e.g. `script-src 'nonce-x' 'strict-dynamic'; child-src https://cdn.example`. Brings the analyzer to **23 checks**.
- **Check: meta-delivered policy specifies ignored directives** (MEDIUM). Names the directives that were discarded so the gap is reported rather than silently dropped.
- **`Policy.delivery`** (`"header"` or `"meta"`) and **`Policy.ignored_directives`**, so callers can distinguish a header policy from a meta one. Both default to header-equivalent values, so existing constructions are unaffected.
- **Tests:** 14 new tests covering the meta-restriction fix, the clickjacking-regression case, and the `worker-src` fallback chain (including negatives where the finding must not fire). 317 tests total.

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
