"""Click-based CLI for csp-toolkit."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .analyzer import analyze, score_policy
from .bypass import find_bypasses
from .diff import diff_headers
from .fetcher import fetch_csp
from .generator import CSPBuilder
from .probes import analyze_report_uri, check_header_injection, detect_nonce_reuse
from .tracker import check_evolution, load_history
from .output import (
    format_findings_detail,
    format_findings_json,
    format_findings_rich,
    format_grade,
    format_policy_summary,
    format_security_headers,
)
from .parser import parse
from .scanner import results_to_csv, results_to_json, scan_urls
from .subdomain import check_subdomains


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


_GRADE_COLORS = {
    "A+": "bold green", "A": "green", "B": "yellow",
    "C": "yellow", "D": "red", "F": "bold red",
    "-": "dim", "?": "dim",
}


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
                console.print("\n[bold]Analysis:[/bold]")
                findings = analyze(policy)
                _output_findings(findings, fmt)

                if fmt != "json":
                    grade, score = score_policy(policy)
                    format_grade(grade, score, console)

            if do_all or do_bypass:
                console.print("\n[bold]Bypass Findings:[/bold]")
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


@main.command()
@click.argument("urls", nargs=-1)
@click.option("--file", "-f", "file_path", help="Read URLs from file (one per line)")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "csv", "json"]), default="table")
@click.option("--no-verify-ssl", is_flag=True, help="Skip SSL certificate verification")
@click.option("--timeout", type=float, default=10.0, help="HTTP timeout per request (seconds)")
def scan(urls: tuple[str, ...], file_path: str | None, fmt: str, no_verify_ssl: bool, timeout: float):
    """Scan multiple URLs and rank by CSP weakness.

    Accepts URLs as arguments or from a file (one URL per line).
    Results are sorted weakest-first for easy target prioritization.
    """
    url_list = list(urls)
    if file_path:
        if file_path == "-":
            url_list.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            with open(file_path) as f:
                url_list.extend(line.strip() for line in f if line.strip())

    if not url_list:
        click.echo("Error: provide URLs as arguments or via --file", err=True)
        sys.exit(1)

    console.print(f"[bold]Scanning {len(url_list)} URLs...[/bold]\n")

    results = scan_urls(url_list, timeout=timeout, verify_ssl=not no_verify_ssl)

    if fmt == "csv":
        click.echo(results_to_csv(results))
    elif fmt == "json":
        click.echo(results_to_json(results))
    else:
        table = Table(title=f"CSP Scan Results ({len(results)} URLs)", show_lines=True)
        table.add_column("Grade", width=5, justify="center")
        table.add_column("Score", width=5, justify="right")
        table.add_column("URL", ratio=1)
        table.add_column("Mode", width=12)
        table.add_column("Findings", width=8, justify="right")
        table.add_column("Bypasses", width=8, justify="right")
        table.add_column("Crit/High", width=9, justify="right")

        for r in results:
            if r.error:
                table.add_row("?", "-", r.url, "[red]error[/red]", "-", "-", "-")
                continue

            color = _GRADE_COLORS.get(r.grade, "white")
            grade_text = Text(r.grade, style=color)
            score_text = str(r.score) if r.has_csp else "-"
            mode = r.policy_mode
            if mode == "none":
                mode = "[yellow]no CSP[/yellow]"
            elif mode == "report-only":
                mode = "[dim]report-only[/dim]"

            crit_high = f"{r.num_critical}/{r.num_high}" if r.has_csp else "-"
            findings = str(r.num_findings) if r.has_csp else "-"
            bypasses = str(r.num_bypasses) if r.has_csp else "-"

            table.add_row(grade_text, score_text, r.url, mode, findings, bypasses, crit_high)

        console.print(table)

        # Summary
        with_csp = sum(1 for r in results if r.has_csp)
        no_csp = sum(1 for r in results if not r.has_csp and not r.error)
        errors = sum(1 for r in results if r.error)
        console.print(f"\n[bold]{with_csp}[/bold] with CSP, [bold]{no_csp}[/bold] without CSP, [bold]{errors}[/bold] errors")


@main.command("diff")
@click.argument("old_csp")
@click.argument("new_csp")
@click.option("--old-file", help="Read old CSP from file instead of argument")
@click.option("--new-file", help="Read new CSP from file instead of argument")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "json"]), default="table")
def diff_cmd(old_csp: str, new_csp: str, old_file: str | None, new_file: str | None, fmt: str):
    """Compare two CSP policies and show differences.

    Pass two CSP strings as arguments, or use --old-file / --new-file.
    Use URLs as arguments to fetch and compare live policies.
    """
    # Resolve inputs — support URLs, files, or raw strings
    old_raw = _resolve_diff_input(old_csp, old_file)
    new_raw = _resolve_diff_input(new_csp, new_file)

    result = diff_headers(old_raw, new_raw)

    if fmt == "json":
        import json
        data = {
            "has_changes": result.has_changes,
            "added": [{"directive": c.directive, "sources": c.new_sources} for c in result.added_directives],
            "removed": [{"directive": c.directive, "sources": c.old_sources} for c in result.removed_directives],
            "modified": [
                {
                    "directive": c.directive,
                    "added_sources": c.added_sources,
                    "removed_sources": c.removed_sources,
                }
                for c in result.modified_directives
            ],
            "unchanged": result.unchanged_directives,
            "weakened": [c.directive for c in result.weakened],
            "strengthened": [c.directive for c in result.strengthened],
        }
        click.echo(json.dumps(data, indent=2))
        return

    if not result.has_changes:
        console.print("[green]Policies are identical.[/green]")
        return

    # Score both
    old_policy = parse(old_raw)
    new_policy = parse(new_raw)
    old_grade, old_score = score_policy(old_policy)
    new_grade, new_score = score_policy(new_policy)

    delta = new_score - old_score
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    delta_color = "green" if delta > 0 else ("red" if delta < 0 else "dim")
    console.print(f"\n[bold]Score:[/bold] {old_grade} ({old_score}) → {new_grade} ({new_score}) [{delta_color}]({delta_str})[/{delta_color}]")

    if result.added_directives:
        console.print(f"\n[green][bold]Added directives ({len(result.added_directives)}):[/bold][/green]")
        for c in result.added_directives:
            console.print(f"  [green]+ {c.directive}[/green]: {' '.join(c.new_sources)}")

    if result.removed_directives:
        console.print(f"\n[red][bold]Removed directives ({len(result.removed_directives)}):[/bold][/red]")
        for c in result.removed_directives:
            console.print(f"  [red]- {c.directive}[/red]: {' '.join(c.old_sources)}")

    if result.modified_directives:
        console.print(f"\n[yellow][bold]Modified directives ({len(result.modified_directives)}):[/bold][/yellow]")
        for c in result.modified_directives:
            console.print(f"  [bold]{c.directive}[/bold]:")
            for src in c.added_sources:
                console.print(f"    [green]+ {src}[/green]")
            for src in c.removed_sources:
                console.print(f"    [red]- {src}[/red]")

    if result.unchanged_directives:
        console.print(f"\n[dim]Unchanged: {', '.join(result.unchanged_directives)}[/dim]")

    # Warnings
    weakened = result.weakened
    if weakened:
        console.print(f"\n[bold red]Warning: Policy WEAKENED in {len(weakened)} directive(s):[/bold red]")
        for c in weakened:
            console.print(f"  [red]{c.directive}[/red] ({c.change_type})")

    strengthened = result.strengthened
    if strengthened:
        console.print(f"\n[bold green]Policy strengthened in {len(strengthened)} directive(s):[/bold green]")
        for c in strengthened:
            console.print(f"  [green]{c.directive}[/green] ({c.change_type})")


def _resolve_diff_input(value: str, file_path: str | None) -> str:
    """Resolve a diff input — could be a file path, URL, or raw CSP string."""
    if file_path:
        with open(file_path) as f:
            return f.read().strip()

    # Check if it looks like a URL
    if value.startswith("https://") or value.startswith("http://"):
        result = fetch_csp(value)
        if result.policies:
            # Use first enforced, or first available
            enforced = [p for p in result.policies if not p.report_only]
            policy = enforced[0] if enforced else result.policies[0]
            return str(policy)
        console.print(f"[yellow]No CSP found at {value}[/yellow]")
        return ""

    return value


@main.command()
@click.argument("domain")
@click.option("--prefixes", "-p", help="Comma-separated subdomain prefixes (overrides defaults)")
@click.option("--format", "-o", "fmt", type=click.Choice(["table", "csv", "json"]), default="table")
@click.option("--no-verify-ssl", is_flag=True, help="Skip SSL certificate verification")
@click.option("--timeout", type=float, default=8.0, help="HTTP timeout per request (seconds)")
def subdomains(domain: str, prefixes: str | None, fmt: str, no_verify_ssl: bool, timeout: float):
    """Check CSP across subdomains to find weak ones.

    Checks common subdomains (www, api, app, staging, admin, etc.)
    and ranks them by CSP weakness.
    """
    prefix_list = prefixes.split(",") if prefixes else None

    console.print(f"[bold]Checking subdomains of {domain}...[/bold]\n")

    results = check_subdomains(
        domain,
        prefixes=prefix_list,
        timeout=timeout,
        verify_ssl=not no_verify_ssl,
    )

    if not results:
        console.print("[yellow]No reachable subdomains found.[/yellow]")
        return

    if fmt == "json":
        import json
        data = [
            {
                "subdomain": r.subdomain,
                "url": r.url,
                "has_csp": r.scan.has_csp,
                "grade": r.scan.grade,
                "score": r.scan.score,
                "findings": r.scan.num_findings,
                "bypasses": r.scan.num_bypasses,
                "mode": r.scan.policy_mode,
            }
            for r in results
        ]
        click.echo(json.dumps(data, indent=2))
    elif fmt == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["subdomain", "grade", "score", "findings", "bypasses", "mode"])
        for r in results:
            writer.writerow([
                r.subdomain, r.scan.grade, r.scan.score,
                r.scan.num_findings, r.scan.num_bypasses, r.scan.policy_mode,
            ])
        click.echo(output.getvalue())
    else:
        table = Table(title=f"Subdomain CSP Analysis — {domain}", show_lines=True)
        table.add_column("Grade", width=5, justify="center")
        table.add_column("Score", width=5, justify="right")
        table.add_column("Subdomain", ratio=1)
        table.add_column("Mode", width=12)
        table.add_column("Findings", width=8, justify="right")
        table.add_column("Bypasses", width=8, justify="right")

        for r in results:
            s = r.scan
            color = _GRADE_COLORS.get(s.grade, "white")
            grade_text = Text(s.grade, style=color)
            score_text = str(s.score) if s.has_csp else "-"
            mode = s.policy_mode
            if mode == "none":
                mode = "[yellow]no CSP[/yellow]"
            elif mode == "report-only":
                mode = "[dim]report-only[/dim]"

            table.add_row(
                grade_text, score_text, r.subdomain, mode,
                str(s.num_findings) if s.has_csp else "-",
                str(s.num_bypasses) if s.has_csp else "-",
            )

        console.print(table)

        with_csp = sum(1 for r in results if r.scan.has_csp)
        no_csp = sum(1 for r in results if not r.scan.has_csp)
        console.print(f"\n[bold]{len(results)}[/bold] reachable, [bold]{with_csp}[/bold] with CSP, [bold]{no_csp}[/bold] without CSP")


@main.command()
@click.argument("urls", nargs=-1)
@click.option("--file", "-f", "file_path", help="Read URLs from file (one per line)")
@click.option("--timeout", type=float, default=10.0)
def monitor(urls: tuple[str, ...], file_path: str | None, timeout: float):
    """Track CSP changes over time. Run periodically to detect policy evolution.

    Stores snapshots in ~/.csp-toolkit/snapshots/ and alerts on changes.
    """
    url_list = list(urls)
    if file_path:
        if file_path == "-":
            url_list.extend(line.strip() for line in sys.stdin if line.strip())
        else:
            with open(file_path) as f:
                url_list.extend(line.strip() for line in f if line.strip())

    if not url_list:
        click.echo("Error: provide URLs as arguments or via --file", err=True)
        sys.exit(1)

    results = check_evolution(url_list, timeout=timeout)

    for snap, alert in results:
        if alert is None:
            console.print(f"[red]Error checking {snap.url}[/red]")
            continue

        grade_color = _GRADE_COLORS.get(snap.grade, "white")

        if alert.alert_type == "new" and alert.old_snapshot is alert.new_snapshot:
            console.print(f"[bold]{snap.url}[/bold]: [{grade_color}]{snap.grade} ({snap.score})[/{grade_color}] [dim](first snapshot)[/dim]")
        elif alert.alert_type == "weakened":
            old = alert.old_snapshot
            console.print(f"[bold red]WEAKENED[/bold red] {snap.url}: {old.grade}({old.score}) → [{grade_color}]{snap.grade}({snap.score})[/{grade_color}]")
            for c in alert.diff.weakened:
                console.print(f"  [red]  {c.directive} ({c.change_type})[/red]")
        elif alert.alert_type == "strengthened":
            old = alert.old_snapshot
            console.print(f"[bold green]STRENGTHENED[/bold green] {snap.url}: {old.grade}({old.score}) → [{grade_color}]{snap.grade}({snap.score})[/{grade_color}]")
        elif alert.alert_type == "csp_removed":
            console.print(f"[bold red]CSP REMOVED[/bold red] {snap.url}: CSP header no longer present!")
        elif alert.alert_type == "changed":
            old = alert.old_snapshot
            console.print(f"[yellow]CHANGED[/yellow] {snap.url}: {old.grade}({old.score}) → [{grade_color}]{snap.grade}({snap.score})[/{grade_color}]")
        else:
            console.print(f"[dim]No change[/dim] {snap.url}: [{grade_color}]{snap.grade} ({snap.score})[/{grade_color}]")


@main.command("history")
@click.argument("url")
def history_cmd(url: str):
    """Show CSP snapshot history for a URL."""
    snapshots = load_history(url)
    if not snapshots:
        console.print(f"[yellow]No snapshots found for {url}[/yellow]")
        console.print("[dim]Run 'csp-toolkit monitor' first to take snapshots.[/dim]")
        return

    table = Table(title=f"CSP History — {url}")
    table.add_column("Timestamp", width=20)
    table.add_column("Grade", width=5, justify="center")
    table.add_column("Score", width=5, justify="right")
    table.add_column("Mode", width=12)
    table.add_column("CSP (truncated)", ratio=1)

    for snap in snapshots:
        ts = snap.timestamp[:19].replace("T", " ")
        color = _GRADE_COLORS.get(snap.grade, "white")
        grade_text = Text(snap.grade, style=color)
        mode = "report-only" if snap.report_only else "enforced"
        csp_trunc = snap.csp_raw[:80] + "..." if len(snap.csp_raw) > 80 else (snap.csp_raw or "(no CSP)")
        table.add_row(ts, grade_text, str(snap.score), mode, csp_trunc)

    console.print(table)


@main.command("nonce-check")
@click.argument("url")
@click.option("--requests", "-n", type=int, default=5, help="Number of requests to make")
@click.option("--no-verify-ssl", is_flag=True)
def nonce_check(url: str, requests: int, no_verify_ssl: bool):
    """Check if a URL reuses CSP nonces (static nonce = CSP bypass)."""
    console.print(f"[bold]Checking nonce reuse on {url} ({requests} requests)...[/bold]\n")

    result = detect_nonce_reuse(url, num_requests=requests, verify_ssl=not no_verify_ssl)

    if result is None:
        console.print("[dim]No nonces found in CSP headers.[/dim]")
        return

    if result.is_static:
        console.print("[bold red]VULNERABLE: Static nonce detected![/bold red]")
        console.print(f"  Directive: {result.directive}")
        console.print(f"  Nonce value: '{result.nonces_found[0]}' (same across {result.num_requests} requests)")
        console.print("  Impact: Attacker can reuse this nonce to bypass CSP nonce-based protection.")
    else:
        unique = len(set(result.nonces_found))
        console.print("[green]Nonces are rotating correctly.[/green]")
        console.print(f"  Directive: {result.directive}")
        console.print(f"  {unique} unique nonces across {len(result.nonces_found)} requests")


@main.command("header-inject")
@click.argument("url")
@click.option("--no-verify-ssl", is_flag=True)
def header_inject(url: str, no_verify_ssl: bool):
    """Test for CSP header injection via CRLF injection vectors."""
    console.print(f"[bold]Testing header injection on {url}...[/bold]\n")

    result = check_header_injection(url, verify_ssl=not no_verify_ssl)

    if result.vulnerable:
        console.print("[bold red]VULNERABLE: Header injection detected![/bold red]")
        console.print(f"  Technique: {result.technique}")
        console.print(f"  {result.details}")
    else:
        console.print("[green]No header injection vectors detected.[/green]")


@main.command("report-uri")
@click.argument("csp", required=False)
@click.option("--file", "-f", "file_path", help="Read CSP from file")
@click.option("--url", "fetch_url", help="Fetch CSP from URL first")
@click.option("--no-verify-ssl", is_flag=True)
def report_uri_cmd(csp: str | None, file_path: str | None, fetch_url: str | None, no_verify_ssl: bool):
    """Analyze the report-uri/report-to endpoint in a CSP policy."""
    if fetch_url:
        result = fetch_csp(fetch_url, verify_ssl=not no_verify_ssl)
        if not result.policies:
            console.print(f"[yellow]No CSP found at {fetch_url}[/yellow]")
            return
        policy = result.policies[0]
    else:
        raw = _read_csp_input(csp, file_path)
        policy = parse(raw)

    console.print("[bold]Analyzing report-uri/report-to...[/bold]\n")

    result = analyze_report_uri(policy, verify_ssl=not no_verify_ssl)

    if not result.report_uri and not result.report_to:
        console.print("[yellow]No report-uri or report-to directive found in this policy.[/yellow]")
        return

    if result.report_uri:
        console.print(f"[bold]report-uri:[/bold] {result.report_uri}")
        if result.uri_reachable is True:
            console.print(f"  [green]Reachable[/green] (HTTP {result.uri_status_code})")
            if result.accepts_post:
                console.print("  [green]Accepts POST[/green] with CSP violation reports")
            else:
                console.print("  [yellow]Does NOT accept POST[/yellow] — reports may not be collected")
        elif result.uri_reachable is False:
            console.print("  [red]NOT reachable[/red] — violation reports are being lost")

    if result.report_to:
        console.print(f"[bold]report-to:[/bold] {result.report_to} [dim](group name — endpoint configured via Report-To header)[/dim]")
