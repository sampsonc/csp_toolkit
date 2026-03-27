"""Output formatting — rich terminal, JSON, and plain text."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .models import Finding, Policy, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_LABELS = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def format_findings_rich(findings: list[Finding], console: Console | None = None) -> None:
    """Print findings as a rich table to the terminal."""
    if console is None:
        console = Console()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title="CSP Analysis Findings", show_lines=True)
    table.add_column("Severity", width=6, justify="center")
    table.add_column("Directive", width=14)
    table.add_column("Finding", ratio=1)

    for f in findings:
        sev_style = _SEVERITY_COLORS[f.severity]
        sev_text = Text(_SEVERITY_LABELS[f.severity], style=sev_style)
        directive = f.directive or "-"
        table.add_row(sev_text, directive, f.title)

    console.print(table)


def format_findings_detail(findings: list[Finding], console: Console | None = None) -> None:
    """Print findings with full descriptions."""
    if console is None:
        console = Console()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    for i, f in enumerate(findings):
        sev_style = _SEVERITY_COLORS[f.severity]
        console.print(f"\n[{sev_style}][{f.severity.value.upper()}][/{sev_style}] {f.title}")
        if f.directive:
            console.print(f"  Directive: {f.directive}")
        if f.bypass_type:
            console.print(f"  Bypass type: {f.bypass_type}")
        console.print(f"  {f.description}")
        if f.references:
            console.print("  References:")
            for ref in f.references:
                console.print(f"    - {ref}")
        if i < len(findings) - 1:
            console.print("  " + "-" * 60)


def format_findings_json(findings: list[Finding]) -> str:
    """Return findings as a JSON string."""
    return json.dumps(
        [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "directive": f.directive,
                "bypass_type": f.bypass_type,
                "references": f.references,
            }
            for f in findings
        ],
        indent=2,
    )


def format_policy_summary(policy: Policy, console: Console | None = None) -> None:
    """Print a summary of a parsed policy."""
    if console is None:
        console = Console()

    if not policy.directives:
        console.print("[yellow]Empty policy — no directives found.[/yellow]")
        return

    if policy.report_only:
        console.print("[yellow]Policy mode: Report-Only (not enforced)[/yellow]")
    else:
        console.print("[green]Policy mode: Enforced[/green]")

    table = Table(title="CSP Directives")
    table.add_column("Directive", style="bold")
    table.add_column("Sources")

    for name, directive in policy.directives.items():
        sources_str = " ".join(s.raw for s in directive.sources)
        if not sources_str:
            sources_str = "(no sources)"
        table.add_row(name, sources_str)

    console.print(table)


def format_security_headers(headers: dict[str, str], console: Console | None = None) -> None:
    """Print related security headers."""
    if console is None:
        console = Console()

    if not headers:
        console.print("[dim]No additional security headers found.[/dim]")
        return

    table = Table(title="Security Headers")
    table.add_column("Header", style="bold")
    table.add_column("Value")

    for name, value in sorted(headers.items()):
        table.add_row(name, value)

    console.print(table)
