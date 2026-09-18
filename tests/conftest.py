"""Shared pytest fixtures.

`executor/` is not a package and is deliberately not importable from
`sentinel/` — see executor/README.md. Adding it to sys.path here is the one
exception, so its hostile-input tests can reach it.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "executor"))


@pytest.fixture
def good_plan() -> dict[str, Any]:
    """A complete, valid patch plan. Tests mutate a copy to break one thing."""
    return json.loads((FIXTURES / "good_plan.json").read_text(encoding="utf-8"))


@pytest.fixture
def debian_plan() -> dict[str, Any]:
    """The Debian counterpart of `good_plan`: a complete, valid plan for an
    `apt-get` host, version-pinned on both directions.

    Shared with `tests/unit/test_patch_planner_platform.py::_full_debian_plan`
    on purpose — a second, private copy of the same plan is a copy nothing
    cross-checks, and that is how the refused `--only-upgrade` form survived
    three rounds in a test fixture.
    """
    return json.loads((FIXTURES / "debian_plan.json").read_text(encoding="utf-8"))


@pytest.fixture
def broken_plan(good_plan: dict[str, Any]):
    """Return a helper that breaks exactly one thing in an otherwise valid plan.

    Testing a broken field against an otherwise-valid plan is the only way to
    know a rule fires for the reason you think. A plan missing ten things
    produces ten errors and proves nothing about any of them.
    """

    def _break(path: str, value: Any) -> dict[str, Any]:
        plan = copy.deepcopy(good_plan)
        node: Any = plan
        parts = path.split(".")
        for part in parts[:-1]:
            node = node[int(part)] if part.isdigit() else node[part]
        last = parts[-1]
        if value is ...:
            del node[int(last) if last.isdigit() else last]
        else:
            node[int(last) if last.isdigit() else last] = value
        return plan

    return _break
