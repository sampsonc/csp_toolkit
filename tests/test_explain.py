"""Tests for fallback-chain resolution and the explain command."""

import json

from click.testing import CliRunner

from csp_toolkit.cli import main
from csp_toolkit.explain import explain_json, explain_policy
from csp_toolkit.models import FALLBACK_CHAINS
from csp_toolkit.parser import parse

runner = CliRunner()


class TestFallbackChains:
    def test_worker_src_routes_through_child_src_then_script_src(self):
        assert FALLBACK_CHAINS["worker-src"] == (
            "worker-src",
            "child-src",
            "script-src",
            "default-src",
        )

    def test_frame_src_routes_through_child_src(self):
        assert FALLBACK_CHAINS["frame-src"] == ("frame-src", "child-src", "default-src")

    def test_non_fetch_directives_have_no_chain(self):
        p = parse("default-src 'self'")
        for name in ("frame-ancestors", "form-action", "base-uri", "sandbox", "report-uri"):
            assert p.fallback_chain(name) == ()
            assert p.effective_directive(name) is None

    def test_resolve_prefers_child_src_over_default_src_for_workers(self):
        """The bug this fixes: worker-src used to fall straight through to default-src."""
        p = parse("default-src 'self'; child-src https://cdn.example")
        directive, source = p.resolve("worker-src")
        assert source == "child-src"
        assert [s.raw for s in directive.sources] == ["https://cdn.example"]

    def test_resolve_falls_through_to_script_src_for_workers(self):
        p = parse("script-src 'self'")
        _, source = p.resolve("worker-src")
        assert source == "script-src"

    def test_resolve_returns_nothing_when_chain_is_empty(self):
        p = parse("img-src 'self'")
        assert p.resolve("worker-src") == (None, None)

    def test_explicit_directive_wins(self):
        p = parse("worker-src 'none'; child-src https://cdn.example")
        _, source = p.resolve("worker-src")
        assert source == "worker-src"

    def test_style_src_elem_routes_through_style_src(self):
        p = parse("style-src 'self'; default-src 'none'")
        _, source = p.resolve("style-src-elem")
        assert source == "style-src"


class TestExplainPolicy:
    def test_marks_explicit_inherited_and_unrestricted(self):
        p = parse("script-src 'self'")
        by_resource = {r.resource: r for r in explain_policy(p)}
        assert by_resource["scripts"].status == "explicit"
        assert by_resource["script elements"].status == "inherited"
        assert by_resource["images"].status == "unrestricted"

    def test_surfaces_the_worker_inheritance_surprise(self):
        p = parse("script-src 'nonce-a' 'strict-dynamic'; child-src https://cdn.example")
        workers = next(r for r in explain_policy(p) if r.resource == "workers")
        assert workers.governed_by == "child-src"
        assert workers.is_inherited
        assert workers.rendered_sources == "https://cdn.example"

    def test_non_fetch_directive_present_is_reported_explicit(self):
        p = parse("frame-ancestors 'none'")
        fa = next(r for r in explain_policy(p) if r.directive == "frame-ancestors")
        assert fa.status == "explicit"
        assert fa.rendered_sources == "'none'"

    def test_unrestricted_renders_as_anything(self):
        p = parse("script-src 'self'")
        imgs = next(r for r in explain_policy(p) if r.resource == "images")
        assert imgs.rendered_sources == "(anything)"

    def test_empty_source_list_is_distinguished_from_unrestricted(self):
        p = parse("default-src 'self'; upgrade-insecure-requests")
        uir = [r for r in explain_policy(p) if r.directive == "upgrade-insecure-requests"]
        assert uir == []  # not a resource type we explain

    def test_json_includes_chain_and_delivery(self):
        doc = explain_json(parse("script-src 'self'"))
        assert doc["delivery"] == "header"
        workers = next(r for r in doc["resources"] if r["resource"] == "workers")
        assert workers["fallback_chain"] == [
            "worker-src",
            "child-src",
            "script-src",
            "default-src",
        ]


class TestExplainCli:
    def test_table_output(self):
        result = runner.invoke(main, ["explain", "script-src 'self'; child-src *"])
        assert result.exit_code == 0
        assert "workers" in result.output

    def test_json_output(self):
        result = runner.invoke(main, ["explain", "script-src 'self'", "-o", "json"])
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert doc["resources"]

    def test_resource_filter_by_directive(self):
        result = runner.invoke(main, ["explain", "script-src 'self'", "--resource", "worker-src"])
        assert result.exit_code == 0
        assert "workers" in result.output
        assert "images" not in result.output

    def test_resource_filter_by_friendly_name(self):
        result = runner.invoke(main, ["explain", "script-src 'self'", "--resource", "workers"])
        assert result.exit_code == 0
        assert "workers" in result.output

    def test_unknown_resource_is_an_error(self):
        result = runner.invoke(main, ["explain", "script-src 'self'", "--resource", "nonsense"])
        assert result.exit_code == 1
        assert "unknown resource" in result.output

    def test_inherited_only_filter(self):
        result = runner.invoke(
            main, ["explain", "script-src 'self'; child-src *", "--inherited-only"]
        )
        assert result.exit_code == 0
        assert "explicit" not in result.output

    def test_report_only_is_labelled(self):
        result = runner.invoke(main, ["explain", "script-src 'self'", "--report-only"])
        assert result.exit_code == 0
        assert "Report-Only" in result.output

    def test_reads_from_stdin(self):
        result = runner.invoke(main, ["explain", "-f", "-"], input="script-src 'self'")
        assert result.exit_code == 0
        assert "scripts" in result.output
