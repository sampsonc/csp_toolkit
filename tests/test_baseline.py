"""Tests for baseline ratcheting — the gate that fails on regression, not on absolute state."""

import json

import pytest

from csp_toolkit import baseline as bl
from csp_toolkit.models import Severity
from csp_toolkit.parser import parse

MEDIOCRE = "script-src 'self' 'unsafe-inline'"
WORSE = "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
BETTER = "script-src 'self'"


class TestRoundTrip:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "b.json"
        bl.update(path, bl.POLICY_KEY, parse(MEDIOCRE))
        loaded = bl.load(path)
        assert bl.POLICY_KEY in loaded.targets
        assert loaded.targets[bl.POLICY_KEY].grade
        assert loaded.created and loaded.updated

    def test_records_reviewable_context_not_just_hashes(self, tmp_path):
        path = tmp_path / "b.json"
        bl.update(path, bl.POLICY_KEY, parse(MEDIOCRE))
        data = json.loads(path.read_text())
        record = next(iter(data["targets"][bl.POLICY_KEY]["findings"].values()))
        assert record["check_id"] and record["severity"] and record["title"]

    def test_update_preserves_other_targets(self, tmp_path):
        path = tmp_path / "b.json"
        bl.update(path, "https://a.example", parse(MEDIOCRE))
        bl.update(path, "https://b.example", parse(BETTER))
        loaded = bl.load(path)
        assert set(loaded.targets) == {"https://a.example", "https://b.example"}

    def test_creates_parent_directory(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "b.json"
        bl.update(path, bl.POLICY_KEY, parse(MEDIOCRE))
        assert path.exists()


class TestErrors:
    def test_missing_file(self, tmp_path):
        with pytest.raises(bl.BaselineError, match="not found"):
            bl.load(tmp_path / "nope.json")

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text("{not json")
        with pytest.raises(bl.BaselineError, match="not valid JSON"):
            bl.load(path)

    def test_wrong_schema_is_named_not_silently_accepted(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"schema": "something-else", "targets": {}}))
        with pytest.raises(bl.BaselineError, match="unrecognized baseline schema"):
            bl.load(path)

    def test_missing_targets(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"schema": bl.SCHEMA}))
        with pytest.raises(bl.BaselineError, match="no 'targets'"):
            bl.load(path)

    def test_non_object_json(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text("[]")
        with pytest.raises(bl.BaselineError, match="must contain a JSON object"):
            bl.load(path)


class TestCompare:
    def _baseline(self, tmp_path, csp=MEDIOCRE):
        path = tmp_path / "b.json"
        bl.update(path, bl.POLICY_KEY, parse(csp))
        return bl.load(path)

    def test_unchanged_policy_has_no_regressions(self, tmp_path):
        c = bl.compare(parse(MEDIOCRE), self._baseline(tmp_path), bl.POLICY_KEY)
        assert c.new_findings == []
        assert c.resolved == []
        assert c.unchanged
        assert c.regressions(None) == []

    def test_preexisting_critical_is_not_a_regression(self, tmp_path):
        """The whole point: a bad-but-known policy must not fail the gate."""
        c = bl.compare(parse(MEDIOCRE), self._baseline(tmp_path), bl.POLICY_KEY)
        assert any(f.severity == Severity.CRITICAL for f in c.unchanged)
        assert c.regressions(None) == []

    def test_new_finding_is_a_regression(self, tmp_path):
        c = bl.compare(parse(WORSE), self._baseline(tmp_path), bl.POLICY_KEY)
        assert [f.check_id for f in c.new_findings] == ["unsafe-eval"]
        assert c.regressions(None)

    def test_threshold_filters_regressions(self, tmp_path):
        c = bl.compare(parse(MEDIOCRE + " http:"), self._baseline(tmp_path), bl.POLICY_KEY)
        assert [f.severity for f in c.new_findings] == [Severity.LOW]
        assert c.regressions(Severity.HIGH) == []
        assert c.regressions(Severity.LOW)

    def test_improvement_is_reported_as_resolved(self, tmp_path):
        c = bl.compare(parse(BETTER), self._baseline(tmp_path), bl.POLICY_KEY)
        assert c.resolved
        assert c.regressions(None) == []
        assert c.score_delta > 0

    def test_untracked_target_does_not_manufacture_regressions(self, tmp_path):
        """An unknown key must not treat every existing finding as new."""
        c = bl.compare(parse(WORSE), self._baseline(tmp_path), "https://unknown.example")
        assert c.untracked is True
        assert c.new_findings == []
        assert c.regressions(None) == []

    def test_grade_and_score_carried_both_ways(self, tmp_path):
        c = bl.compare(parse(BETTER), self._baseline(tmp_path), bl.POLICY_KEY)
        assert c.grade_before and c.grade_after
        assert c.score_after > c.score_before


class TestFingerprintStability:
    def test_reworded_title_does_not_invalidate_a_baseline(self, tmp_path):
        """Baselines key on check_id/directive/subject, never on message text."""
        path = tmp_path / "b.json"
        bl.update(path, bl.POLICY_KEY, parse(MEDIOCRE))
        loaded = bl.load(path)

        entry = loaded.targets[bl.POLICY_KEY]
        for record in entry.findings.values():
            record["title"] = "completely different wording"

        c = bl.compare(parse(MEDIOCRE), loaded, bl.POLICY_KEY)
        assert c.new_findings == [], "rewording a title must not look like a regression"

    def test_multiple_subjects_in_one_directive_stay_distinct(self, tmp_path):
        path = tmp_path / "b.json"
        two = "script-src 'self' *.googleapis.com"
        bl.update(path, bl.POLICY_KEY, parse(two))
        three = "script-src 'self' *.googleapis.com *.cloudfront.net"
        c = bl.compare(parse(three), bl.load(path), bl.POLICY_KEY)
        assert len(c.new_findings) == 1
        assert c.new_findings[0].subject == "*.cloudfront.net"
