# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
