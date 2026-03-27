# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.4.0
[0.3.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.3.0
[0.2.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/sampsonc/csp_toolkit/releases/tag/v0.1.0
