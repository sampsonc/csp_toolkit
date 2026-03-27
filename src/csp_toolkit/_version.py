"""Package version — resolved from installed metadata when available."""

from __future__ import annotations


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("csp-toolkit")
    except Exception:
        return "0.5.0"


__version__ = get_version()
