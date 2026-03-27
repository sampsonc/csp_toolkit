"""Policy evolution tracker — store CSP snapshots and detect changes over time."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import score_policy
from .diff import PolicyDiff, diff_policies
from .fetcher import fetch_csp
from .parser import parse


DEFAULT_STORE_DIR = Path.home() / ".csp-toolkit" / "snapshots"


@dataclass
class Snapshot:
    url: str
    timestamp: str
    csp_raw: str
    grade: str
    score: int
    report_only: bool

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "csp_raw": self.csp_raw,
            "grade": self.grade,
            "score": self.score,
            "report_only": self.report_only,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        return cls(**d)


@dataclass
class EvolutionAlert:
    url: str
    old_snapshot: Snapshot
    new_snapshot: Snapshot
    diff: PolicyDiff
    score_delta: int
    alert_type: str  # "weakened", "strengthened", "changed", "new", "csp_removed"


def _store_path(store_dir: Path, url: str) -> Path:
    """Get the JSON file path for a URL's snapshot history."""
    # Sanitize URL to filename
    safe = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    return store_dir / f"{safe}.json"


def load_history(url: str, *, store_dir: Path | None = None) -> list[Snapshot]:
    """Load snapshot history for a URL."""
    if store_dir is None:
        store_dir = DEFAULT_STORE_DIR
    path = _store_path(store_dir, url)
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return [Snapshot.from_dict(d) for d in data]


def save_snapshot(snapshot: Snapshot, *, store_dir: Path | None = None) -> None:
    """Append a snapshot to the history for a URL."""
    if store_dir is None:
        store_dir = DEFAULT_STORE_DIR
    store_dir.mkdir(parents=True, exist_ok=True)
    path = _store_path(store_dir, snapshot.url)

    history = []
    if path.exists():
        with open(path) as f:
            history = json.load(f)

    history.append(snapshot.to_dict())

    with open(path, "w") as f:
        json.dump(history, f, indent=2)


def take_snapshot(
    url: str, *, store_dir: Path | None = None, timeout: float = 10.0
) -> tuple[Snapshot, EvolutionAlert | None]:
    """Fetch current CSP, store it, and compare against the previous snapshot.

    Returns the new snapshot and an alert if the policy changed.
    """
    result = fetch_csp(url, timeout=timeout)

    if result.policies:
        enforced = [p for p in result.policies if not p.report_only]
        policy = enforced[0] if enforced else result.policies[0]
        grade, score = score_policy(policy)
        csp_raw = str(policy)
        report_only = policy.report_only
    else:
        policy = None
        grade = "-"
        score = 0
        csp_raw = ""
        report_only = False

    now = datetime.now(timezone.utc).isoformat()
    new_snap = Snapshot(
        url=url,
        timestamp=now,
        csp_raw=csp_raw,
        grade=grade,
        score=score,
        report_only=report_only,
    )

    # Compare against previous
    history = load_history(url, store_dir=store_dir)
    alert = None

    if history:
        prev = history[-1]
        if prev.csp_raw != csp_raw:
            old_policy = parse(prev.csp_raw) if prev.csp_raw else parse("")
            new_policy = parse(csp_raw) if csp_raw else parse("")
            diff = diff_policies(old_policy, new_policy)
            score_delta = score - prev.score

            if not prev.csp_raw and csp_raw:
                alert_type = "new"
            elif prev.csp_raw and not csp_raw:
                alert_type = "csp_removed"
            elif diff.weakened:
                alert_type = "weakened"
            elif diff.strengthened:
                alert_type = "strengthened"
            else:
                alert_type = "changed"

            alert = EvolutionAlert(
                url=url,
                old_snapshot=prev,
                new_snapshot=new_snap,
                diff=diff,
                score_delta=score_delta,
                alert_type=alert_type,
            )
    else:
        # First snapshot
        alert = EvolutionAlert(
            url=url,
            old_snapshot=new_snap,
            new_snapshot=new_snap,
            diff=PolicyDiff(),
            score_delta=0,
            alert_type="new",
        )

    save_snapshot(new_snap, store_dir=store_dir)
    return new_snap, alert


def check_evolution(
    urls: list[str],
    *,
    store_dir: Path | None = None,
    timeout: float = 10.0,
) -> list[tuple[Snapshot, EvolutionAlert | None]]:
    """Check multiple URLs for CSP changes."""
    results = []
    for url in urls:
        try:
            snap, alert = take_snapshot(url, store_dir=store_dir, timeout=timeout)
            results.append((snap, alert))
        except Exception:
            now = datetime.now(timezone.utc).isoformat()
            error_snap = Snapshot(
                url=url, timestamp=now, csp_raw="", grade="?", score=0, report_only=False
            )
            results.append((error_snap, None))
    return results
