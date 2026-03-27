# Security

## Reporting

Please report security issues privately via [GitHub Security Advisories](https://github.com/sampsonc/csp_toolkit/security/advisories/new) for this repository, or contact the maintainer through the email on [PyPI](https://pypi.org/project/csp-toolkit/).

## Dependency monitoring

- [Dependabot](https://github.com/sampsonc/csp_toolkit/security/dependabot) is enabled for **pip** (`uv.lock`) and **GitHub Actions**.
- CI runs on Python 3.11–3.13 with lint, format, and tests including a coverage floor.

## Known advisories (transitive / no fix yet)

| ID | Package | Severity | Notes |
|----|---------|----------|--------|
| [GHSA-5239-wwwm-4pmq](https://github.com/advisories/GHSA-5239-wwwm-4pmq) | Pygments | Low | ReDoS in a lexer path (local attack vector). Brought in transitively by dev tooling (e.g. via pytest/rich stack). **PyPI’s latest `pygments` is still 2.19.2** with no patched release listed on the advisory; Dependabot will propose an upgrade when available. |

If GitHub shows this alert on `uv.lock`, it is expected until upstream ships a fixed Pygments version.
