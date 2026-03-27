"""Click-based CLI for csp-toolkit."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from .analyzer import analyze, score_policy
from .bypass import find_bypasses
from .fetcher import fetch_csp
from .generator import CSPBuilder
from .output import (
    format_findings_detail,
    format_findings_json,
    format_findings_rich,
    format_grade,
    format_policy_summary,
    format_security_headers,
)
from .parser import parse


console = Console()


def _read_csp_input(csp: str | None, file: str | None) -> str:
    """Read CSP from argument or file."""
    if file:
        if file == "-":
            return sys.stdin.read().strip()
        with open(file) as f:
            return f.read().strip()
    if csp:
        return csp
    click.echo("Error: provide a CSP string or --file", err=True)
    sys.exit(1)


def _output_findings(findings: list, fmt: str) -> None:
    """Output findings in the requested format."""
    if fmt == "json":
        click.echo(format_findings_json(findings))
    elif fmt == "detail":
        format_findings_detail(findings, console)
    else:
        format_findings_rich(findings, console)


@click.group()
@click.version_option(version="0.1.0", prog_name="csp-toolkit")
def main():
    """CSP Toolkit — Parse, analyze, generate, and find bypasses in Content Security Policy headers."""


@main.command()
@click.argument("csp", required=False)
@click.option("--file", "-f", "file_path", help="Read CSP from file (use - for stdin)")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "detail", "json"]), default="table")
@click.option("--report-only", is_flag=True, help="Treat as Report-Only header")
def analyze_cmd(csp: str | None, file_path: str | None, fmt: str, report_only: bool):
    """Analyze a CSP header for weaknesses."""
    raw = _read_csp_input(csp, file_path)
    policy = parse(raw, report_only=report_only)

    console.print()
    format_policy_summary(policy, console)
    console.print()

    findings = analyze(policy)
    _output_findings(findings, fmt)

    # Grade and summary
    if fmt != "json":
        grade, score = score_policy(policy)
        format_grade(grade, score, console)

        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        if counts:
            parts = [f"{v} {k}" for k, v in counts.items()]
            console.print(f"[bold]Total: {len(findings)} findings[/bold] ({', '.join(parts)})")


@main.command()
@click.argument("urls", nargs=-1, required=True)
@click.option("--analyze/--no-analyze", "do_analyze", default=False, help="Run analyzer on fetched policy")
@click.option("--bypass/--no-bypass", "do_bypass", default=False, help="Run bypass finder on fetched policy")
@click.option("--all", "do_all", is_flag=True, help="Run both analyzer and bypass finder")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "detail", "json"]), default="table")
@click.option("--no-verify-ssl", is_flag=True, help="Skip SSL certificate verification")
@click.option("--check-live", is_flag=True, help="Probe JSONP endpoints to verify they are live")
def fetch(urls: tuple[str, ...], do_analyze: bool, do_bypass: bool, do_all: bool, fmt: str, no_verify_ssl: bool, check_live: bool):
    """Fetch and display CSP headers from one or more URLs."""
    for url_idx, url in enumerate(urls):
        if url_idx > 0:
            console.print("\n" + "=" * 70 + "\n")

        try:
            result = fetch_csp(url, verify_ssl=not no_verify_ssl)
        except Exception as e:
            console.print(f"[red]Error fetching {url}: {e}[/red]")
            continue

        console.print(f"\n[bold]URL:[/bold] {result.url}")
        if result.final_url != result.url:
            console.print(f"[bold]Redirected to:[/bold] {result.final_url}")
        console.print(f"[bold]Status:[/bold] {result.status_code}")

        if not result.policies:
            console.print("\n[yellow]No CSP found on this page.[/yellow]")
            format_security_headers(result.security_headers, console)
            continue

        for i, policy in enumerate(result.policies):
            label = "Report-Only" if policy.report_only else "Enforced"
            source = "header" if i == 0 and result.csp_header else "meta tag"
            console.print(f"\n[bold]Policy #{i + 1} ({label}, from {source}):[/bold]")
            format_policy_summary(policy, console)

            if do_all or do_analyze:
                console.print(f"\n[bold]Analysis:[/bold]")
                findings = analyze(policy)
                _output_findings(findings, fmt)

                if fmt != "json":
                    grade, score = score_policy(policy)
                    format_grade(grade, score, console)

            if do_all or do_bypass:
                console.print(f"\n[bold]Bypass Findings:[/bold]")
                bypasses = find_bypasses(policy, check_live=check_live)
                _output_findings(bypasses, fmt)

        if result.security_headers:
            console.print()
            format_security_headers(result.security_headers, console)


@main.command("bypass")
@click.argument("csp", required=False)
@click.option("--file", "-f", "file_path", help="Read CSP from file (use - for stdin)")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "detail", "json"]), default="detail")
@click.option("--check-live", is_flag=True, help="Probe JSONP endpoints to verify they are live")
def bypass_cmd(csp: str | None, file_path: str | None, fmt: str, check_live: bool):
    """Find potential CSP bypasses."""
    raw = _read_csp_input(csp, file_path)
    policy = parse(raw)

    findings = find_bypasses(policy, check_live=check_live)
    _output_findings(findings, fmt)

    if fmt != "json":
        if findings:
            console.print(f"\n[bold]Total: {len(findings)} potential bypasses found[/bold]")
        else:
            console.print("\n[green]No known bypasses found for this policy.[/green]")


@main.command()
@click.option("--preset", type=click.Choice(["strict", "moderate", "permissive"]), default="strict")
@click.option("--add-source", multiple=True, help="Add source: 'directive source' (e.g. 'script-src cdn.example.com')")
@click.option("--format", "-o", "fmt", type=click.Choice(["header", "meta", "nginx", "apache"]), default="header")
@click.option("--nonce", help="Nonce value for strict preset (auto-generated if not provided)")
def generate(preset: str, add_source: tuple[str, ...], fmt: str, nonce: str | None):
    """Generate a CSP header from a preset."""
    builders = {
        "strict": lambda: CSPBuilder.strict(nonce=nonce),
        "moderate": CSPBuilder.moderate,
        "permissive": CSPBuilder.permissive,
    }
    builder = builders[preset]()

    for src_spec in add_source:
        parts = src_spec.split(None, 1)
        if len(parts) != 2:
            console.print(f"[red]Invalid --add-source format: '{src_spec}'. Use 'directive source'.[/red]")
            sys.exit(1)
        builder.add_source(parts[0], parts[1])

    formatters = {
        "header": builder.build,
        "meta": builder.build_meta,
        "nginx": builder.build_nginx,
        "apache": builder.build_apache,
    }
    click.echo(formatters[fmt]())
