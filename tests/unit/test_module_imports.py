"""Every module under `sentinel/` (and, separately, `executor/`) must import
cleanly.

Prevents: commit 41b7723, which added `from sentinel.respond.executor_client
import TIMEOUT_MARGIN_S, ExecutorClient` to `sentinel/patch/backup.py`,
`checks.py` and `runner.py` without ever committing `TIMEOUT_MARGIN_S` itself.
Nothing in 5255 tests imported those three modules, so nothing noticed —
`sentinel-maintenance.service` crash-looped hourly on both production hosts,
backups stopped, and the only trace was an ERROR line naming a symbol nobody
was watching for. A suite can contain a correctness test for every function
in a module and still miss this, because a correctness test necessarily
imports the module first — this test is the one thing standing between a
broken import and "nothing runs this file, so nothing knows".

This does not replace targeted tests. `TIMEOUT_MARGIN_S` existing is not the
same as it having the right value, applied at the right call sites — that is
`tests/unit/test_executor_client_timeout.py` and
`tests/unit/test_patch_runner.py`. This test answers one narrower question:
does the module load at all.

Discovery walks the filesystem directly rather than `pkgutil.walk_packages`:
that function silently swallows `ImportError` raised while it recurses into a
package to list further submodules (unless given `onerror`, and even then it
reports one name and stops) — precisely the failure this test exists to
surface. A plain glob plus an explicit `importlib.import_module` per name has
no such hole: every name is attempted, every outcome is recorded.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SENTINEL_ROOT = REPO_ROOT / "sentinel"
EXECUTOR_ROOT = REPO_ROOT / "executor"

# Modules that cannot be imported from THIS machine for a specific, checked
# reason -- named individually so a new failure anywhere else is never read
# as "oh, that's just another platform module". Measured empty on this
# Windows sandbox as of 2026-09-15 (pytest run below): psutil, used by
# sentinel/health/capacity.py, is a cross-platform wheel and imports fine
# here even though the AF_PACKET socket it opens at RUNTIME is Linux-only
# (see sentinel-health memory note) -- that is a call-time restriction, not
# an import-time one, so it does not belong in this dict. If a module is
# ever added here, name the platform fact that makes it unavoidable, not
# just "fails on Windows".
KNOWN_UNIMPORTABLE: dict[str, str] = {}


def _sentinel_module_names() -> list[str]:
    names = []
    for path in sorted(SENTINEL_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(REPO_ROOT)
        parts = list(rel.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names.append(".".join(parts))
    return names


def _executor_module_names() -> list[str]:
    # executor/ has no __init__.py and is never imported as a package: the
    # executor is run as a bare script (deploy/systemd/sentinel-executor.service:
    # ExecStart=.../sentinel_executor.py), and sentinel_executor.py itself
    # does `sys.path.insert(0, str(Path(__file__).parent))` before `import
    # policy` / `import commands` (executor/sentinel_executor.py). Importing
    # these as top-level names with executor/ on sys.path reproduces exactly
    # that, rather than a package layout the code was never written for.
    names = []
    for path in sorted(EXECUTOR_ROOT.glob("*.py")):
        names.append(path.stem)
    return names


def test_every_sentinel_module_imports_without_error():
    names = _sentinel_module_names()
    assert names, "discovery found nothing under sentinel/ -- the test itself is broken"

    failures: dict[str, str] = {}
    for name in names:
        if name in KNOWN_UNIMPORTABLE:
            continue
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - report every kind, not just ImportError
            failures[name] = f"{type(exc).__name__}: {exc}"

    assert not failures, (
        "these modules raise on import -- anything that imports them, "
        "directly or transitively, dies before doing any work:\n"
        + "\n".join(f"  {name}: {detail}" for name, detail in sorted(failures.items()))
    )


def test_every_executor_module_imports_without_error():
    names = _executor_module_names()
    assert names, "discovery found nothing under executor/ -- the test itself is broken"

    sys.path.insert(0, str(EXECUTOR_ROOT))
    try:
        failures: dict[str, str] = {}
        for name in names:
            if name in KNOWN_UNIMPORTABLE:
                continue
            try:
                importlib.import_module(name)
            except Exception as exc:  # noqa: BLE001
                failures[name] = f"{type(exc).__name__}: {exc}"
    finally:
        sys.path.remove(str(EXECUTOR_ROOT))

    assert not failures, (
        "these executor modules raise on import:\n"
        + "\n".join(f"  {name}: {detail}" for name, detail in sorted(failures.items()))
    )
