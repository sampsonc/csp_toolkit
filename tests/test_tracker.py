"""Tests for policy evolution tracker."""

import tempfile
from pathlib import Path

from csp_toolkit.tracker import Snapshot, load_history, save_snapshot, check_evolution


class TestSnapshot:
    def test_roundtrip(self):
        snap = Snapshot(
            url="https://example.com",
            timestamp="2025-01-01T00:00:00+00:00",
            csp_raw="script-src 'self'",
            grade="A",
            score=90,
            report_only=False,
        )
        d = snap.to_dict()
        restored = Snapshot.from_dict(d)
        assert restored.url == snap.url
        assert restored.grade == snap.grade


class TestSaveAndLoad:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = Path(tmpdir)
            snap = Snapshot(
                url="https://example.com",
                timestamp="2025-01-01T00:00:00+00:00",
                csp_raw="script-src 'self'",
                grade="A",
                score=90,
                report_only=False,
            )
            save_snapshot(snap, store_dir=store)

            history = load_history("https://example.com", store_dir=store)
            assert len(history) == 1
            assert history[0].grade == "A"

    def test_multiple_snapshots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = Path(tmpdir)
            for i in range(3):
                snap = Snapshot(
                    url="https://example.com",
                    timestamp=f"2025-01-0{i + 1}T00:00:00+00:00",
                    csp_raw="script-src 'self'",
                    grade="A",
                    score=90 + i,
                    report_only=False,
                )
                save_snapshot(snap, store_dir=store)

            history = load_history("https://example.com", store_dir=store)
            assert len(history) == 3

    def test_load_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            history = load_history("https://nonexistent.com", store_dir=Path(tmpdir))
            assert history == []


class TestCheckEvolution:
    def test_unreachable_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = check_evolution(
                ["https://this-does-not-exist-12345.com"],
                store_dir=Path(tmpdir),
                timeout=2.0,
            )
            assert len(results) == 1
