# Development

Use active probes (`fetch`, `scan`, `header-inject`, `nonce-check`, `bypass --check-live`, etc.) only against systems you are **authorized** to test.

Release history: [CHANGELOG.md](https://github.com/sampsonc/csp_toolkit/blob/main/CHANGELOG.md). Security reporting and dependency notes: [SECURITY.md](https://github.com/sampsonc/csp_toolkit/blob/main/SECURITY.md).

Pushing a tag `v*` runs [`.github/workflows/publish.yml`](https://github.com/sampsonc/csp_toolkit/blob/main/.github/workflows/publish.yml) (tests, then PyPI upload via [trusted publishing](https://docs.pypi.org/trusted-publishers/)). Configure the publisher once under [PyPI → csp-toolkit → Publishing](https://pypi.org/manage/project/csp-toolkit/settings/publishing/).

```bash
# Install dev dependencies
uv sync --all-extras

# Run tests (298 tests)
uv run pytest -v

# Same coverage gate as CI (optional locally)
uv run pytest --cov=csp_toolkit --cov-fail-under=75 -q

# Lint and format check
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```
