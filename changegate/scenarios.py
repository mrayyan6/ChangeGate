"""Load, order and validate scenario YAML files."""

from __future__ import annotations

import fnmatch
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from changegate.contracts import Scenario

EXPECTED_PAIRS = {
    "security": 6,
    "blast_radius": 4,
    "change_window": 3,
    "sod_approval": 3,
    "split_change": 2,
    "injection": 2,
}


def load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def load_scenarios(directory: str | Path) -> list[Scenario]:
    directory = Path(directory)
    scenarios = [load_scenario(p) for p in sorted(directory.glob("*.yaml"))]
    return order_scenarios(scenarios)


def order_scenarios(scenarios: list[Scenario]) -> list[Scenario]:
    """Group requests by session (first appearance order) and sort each session by sequence, then id."""
    first_seen: dict[str, int] = {}
    for index, sc in enumerate(scenarios):
        first_seen.setdefault(sc.session_id, index)
    return sorted(scenarios, key=lambda s: (first_seen[s.session_id], s.sequence, s.id))


def group_sessions(scenarios: list[Scenario]) -> list[tuple[str, list[Scenario]]]:
    groups: dict[str, list[Scenario]] = defaultdict(list)
    order: list[str] = []
    for sc in order_scenarios(scenarios):
        if sc.session_id not in groups:
            order.append(sc.session_id)
        groups[sc.session_id].append(sc)
    return [(sid, groups[sid]) for sid in order]


def select(
    scenarios: list[Scenario],
    patterns: list[str] | None = None,
    label: str | None = None,
    category: str | None = None,
    limit: int | None = None,
) -> list[Scenario]:
    """Filter scenarios, then add every earlier request of the selected sessions so sessions stay intact."""
    chosen = [
        s
        for s in scenarios
        if (not patterns or any(fnmatch.fnmatch(s.id, p) for p in patterns))
        and (label is None or s.label == label)
        and (category is None or s.category == category)
    ]
    if limit is not None:
        chosen = chosen[:limit]
    keep: set[str] = set()
    by_session = dict(group_sessions(scenarios))
    for sc in chosen:
        for member in by_session[sc.session_id]:
            if (member.sequence, member.id) <= (sc.sequence, sc.id):
                keep.add(member.id)
    return [s for s in order_scenarios(scenarios) if s.id in keep]


def validate(scenarios: list[Scenario], expect_full_set: bool = True) -> list[str]:
    """Return a list of problems (empty when the set is consistent)."""
    problems: list[str] = []
    ids = Counter(s.id for s in scenarios)
    problems += [f"duplicate id {i}" for i, n in ids.items() if n > 1]

    twins: dict[str, list[Scenario]] = defaultdict(list)
    for sc in scenarios:
        twins[sc.twin_id].append(sc)
        if sc.label == "unsafe" and not sc.violated_controls:
            problems.append(f"{sc.id}: unsafe scenario without violated_controls")
        if sc.label == "safe" and sc.violated_controls:
            problems.append(f"{sc.id}: safe scenario lists violated_controls")
        if sc.label == "safe" and sc.compliant_assertions:
            problems.append(f"{sc.id}: compliant_assertions are only for unsafe scenarios")
        if not sc.assertions:
            problems.append(f"{sc.id}: no assertions")
        if sc.timestamp.tzinfo is None:
            problems.append(f"{sc.id}: timestamp must carry a timezone (use Z)")
    for twin_id, members in twins.items():
        labels = sorted(m.label for m in members)
        if labels != ["safe", "unsafe"]:
            problems.append(f"twin {twin_id}: expected one safe and one unsafe request, got {labels}")
        if len({m.category for m in members}) != 1:
            problems.append(f"twin {twin_id}: members have different categories")

    for session_id, members in group_sessions(scenarios):
        patches = {tuple((p.path, p.old, p.new) for p in m.workspace_patches) for m in members}
        if len(patches) > 1:
            problems.append(f"session {session_id}: members disagree on workspace_patches")
        if len({m.sequence for m in members}) != len(members):
            problems.append(f"session {session_id}: members need distinct sequence numbers")

    if expect_full_set:
        if len(scenarios) != 40:
            problems.append(f"expected 40 scenarios, found {len(scenarios)}")
        pairs = Counter(members[0].category for members in twins.values() if members)
        for category, expected in EXPECTED_PAIRS.items():
            if pairs.get(category, 0) != expected:
                problems.append(f"category {category}: expected {expected} twin pairs, found {pairs.get(category, 0)}")
    return problems
