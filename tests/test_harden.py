"""Tests for the harden command — emitting a tightened policy, with honest risk labels."""

import json

import pytest
from click.testing import CliRunner

from csp_toolkit.analyzer import score_policy
from csp_toolkit.cli import main
from csp_toolkit.harden import harden_json, harden_policy
from csp_toolkit.parser import parse

runner = CliRunner()

NONCE_WITH_REDUNDANT_INLINE = "script-src 'nonce-abc' 'unsafe-inline'"
WIDE_OPEN = "default-src *; script-src 'unsafe-inline' 'unsafe-eval' data: http:"
ALREADY_TIGHT = (
    "default-src 'none'; script-src 'nonce-a'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'"
)


class TestSafeLevel:
    def test_removes_unsafe_inline_that_a_nonce_already_neutralises(self):
        r = harden_policy(parse(NONCE_WITH_REDUNDANT_INLINE))
        assert "'unsafe-inline'" not in r.hardened
        removal = next(c for c in r.changes if c.detail == "'unsafe-inline'")
        assert removal.risk == "none"

    def test_keeps_unsafe_inline_without_a_nonce_at_safe_level(self):
        """Removing it would break every inline script, so safe must not do it."""
        r = harden_policy(parse("script-src 'self' 'unsafe-inline'"))
        assert "'unsafe-inline'" in r.hardened
        held = next(c for c in r.skipped if c.detail == "'unsafe-inline'")
        assert held.risk == "high"

    def test_adds_directives_that_do_not_fall_back(self):
        r = harden_policy(parse("script-src 'self'"))
        for directive in ("object-src", "base-uri", "form-action"):
            assert directive in r.hardened

    def test_does_not_add_frame_ancestors_at_safe_level(self):
        r = harden_policy(parse("script-src 'self'"))
        assert "frame-ancestors" not in r.hardened
        assert any(c.directive == "frame-ancestors" for c in r.skipped)

    def test_pins_worker_src_when_child_src_is_looser(self):
        r = harden_policy(parse("script-src 'nonce-a'; child-src https://cdn.example"))
        assert "worker-src 'self'" in r.hardened

    def test_does_not_pin_worker_src_when_nothing_widens(self):
        r = harden_policy(parse("script-src 'self'"))
        assert "worker-src" not in r.hardened

    def test_upgrades_http_scheme(self):
        r = harden_policy(parse("img-src 'self' http:"))
        assert "https:" in r.hardened
        assert "http:" not in r.hardened.replace("https:", "")

    def test_leaves_an_already_tight_policy_alone(self):
        r = harden_policy(parse(ALREADY_TIGHT))
        assert r.changes == []
        assert not r.changed


class TestStrictLevel:
    def test_strict_needs_allow_breaking_to_apply_high_risk_changes(self):
        held = harden_policy(parse("script-src 'self' 'unsafe-eval'"), level="strict")
        assert "'unsafe-eval'" in held.hardened
        applied = harden_policy(
            parse("script-src 'self' 'unsafe-eval'"), level="strict", allow_breaking=True
        )
        assert "'unsafe-eval'" not in applied.hardened

    def test_strict_removes_script_wildcards_and_schemes(self):
        r = harden_policy(parse(WIDE_OPEN), level="strict", allow_breaking=True)
        script = [p for p in r.hardened.split("; ") if p.startswith("script-src")][0]
        for bad in ("'unsafe-inline'", "'unsafe-eval'", "data:", "*"):
            assert bad not in script

    def test_emptied_directive_becomes_none_rather_than_allowing_everything(self):
        """Dropping the only source must not leave a directive that permits anything."""
        r = harden_policy(parse("script-src 'unsafe-inline'"), level="strict", allow_breaking=True)
        assert "script-src 'none'" in r.hardened

    def test_adds_trusted_types_at_strict(self):
        r = harden_policy(parse("script-src 'self'"), level="strict", allow_breaking=True)
        assert "require-trusted-types-for 'script'" in r.hardened


class TestInvariants:
    @pytest.mark.parametrize(
        "csp",
        [
            NONCE_WITH_REDUNDANT_INLINE,
            WIDE_OPEN,
            "script-src 'self'",
            "img-src 'self' http:",
            ALREADY_TIGHT,
            "default-src 'self'; child-src https://cdn.example",
        ],
    )
    @pytest.mark.parametrize("level,breaking", [("safe", False), ("strict", True)])
    def test_never_lowers_the_score(self, csp, level, breaking):
        r = harden_policy(parse(csp), level=level, allow_breaking=breaking)
        _, before = score_policy(parse(r.original))
        _, after = score_policy(parse(r.hardened))
        assert after >= before

    @pytest.mark.parametrize(
        "csp", [NONCE_WITH_REDUNDANT_INLINE, WIDE_OPEN, "script-src 'self'", "img-src 'self'"]
    )
    @pytest.mark.parametrize("level,breaking", [("safe", False), ("strict", True)])
    def test_is_idempotent(self, csp, level, breaking):
        once = harden_policy(parse(csp), level=level, allow_breaking=breaking).hardened
        twice = harden_policy(parse(once), level=level, allow_breaking=breaking).hardened
        assert once == twice

    def test_output_is_parseable(self):
        r = harden_policy(parse(WIDE_OPEN), level="strict", allow_breaking=True)
        assert parse(r.hardened).directives

    def test_does_not_mutate_the_input_policy(self):
        policy = parse(NONCE_WITH_REDUNDANT_INLINE)
        harden_policy(policy, level="strict", allow_breaking=True)
        assert str(policy) == NONCE_WITH_REDUNDANT_INLINE

    def test_unknown_level_is_rejected(self):
        with pytest.raises(ValueError, match="unknown level"):
            harden_policy(parse("script-src 'self'"), level="nuclear")

    def test_every_change_carries_a_rationale(self):
        r = harden_policy(parse(WIDE_OPEN), level="strict", allow_breaking=True)
        for c in r.changes + r.skipped:
            assert c.rationale and c.risk in ("none", "low", "high")


class TestHardenJson:
    def test_shape(self):
        doc = harden_json(harden_policy(parse("script-src 'self'")))
        assert doc["original"] and doc["hardened"]
        assert doc["changed"] is True
        assert doc["applied"] and isinstance(doc["skipped"], list)
        assert set(doc["applied"][0]) == {"action", "directive", "detail", "risk", "rationale"}


class TestHardenCli:
    def test_table_output(self):
        result = runner.invoke(main, ["harden", "script-src 'self'"])
        assert result.exit_code == 0
        assert "Hardened policy" in result.output

    def test_header_output_is_just_the_policy(self):
        result = runner.invoke(main, ["harden", "script-src 'self'", "-o", "header"])
        assert result.exit_code == 0
        assert result.output.strip().startswith("script-src 'self'")
        assert "Applied" not in result.output

    def test_header_output_round_trips_through_the_parser(self):
        result = runner.invoke(main, ["harden", "script-src 'self'", "-o", "header"])
        assert parse(result.output.strip()).directives

    def test_json_output(self):
        result = runner.invoke(main, ["harden", "script-src 'self'", "-o", "json"])
        assert result.exit_code == 0
        assert json.loads(result.output)["hardened"]

    def test_strict_with_allow_breaking(self):
        result = runner.invoke(
            main,
            ["harden", "script-src 'self' 'unsafe-eval'", "--level", "strict", "--allow-breaking"],
        )
        assert result.exit_code == 0
        assert "'unsafe-eval'" not in result.output.split("Applied")[0]

    def test_held_back_changes_are_explained(self):
        result = runner.invoke(main, ["harden", "script-src 'self'"])
        assert "Held back" in result.output
        assert "--allow-breaking" in result.output

    def test_nothing_to_harden_is_reported(self):
        result = runner.invoke(main, ["harden", ALREADY_TIGHT])
        assert result.exit_code == 0
        assert "Nothing to harden" in result.output

    def test_reads_from_stdin(self):
        result = runner.invoke(main, ["harden", "-f", "-"], input="script-src 'self'")
        assert result.exit_code == 0
