"""`op_restore_drill_verify` — real execution, not just source inspection.

Everything here runs the actual function against a real temporary directory
tree, the way the executor would see it on a live host, with `BACKUP_ROOT`
and `DRILL_ROOT` monkeypatched onto a pytest `tmp_path`. `hashlib`, `json` and
plain filesystem operations do not need root, so these are genuine
falsifications, not source-text assertions dressed up as tests.

What could NOT be exercised for real HERE, in this file: `tar --zstd`'s own
compression, since this sandbox has no standalone `zstd` binary. The
`restorable_verified` and `structure_mismatch` verdicts — the actual happy
path this function exists for — ARE proven by real execution, real tar
create-then-extract, real `--one-top-level`, in
`tests/security/test_backup_create_path_structure.py`, which substitutes
`--zstd` for no compression and (only where `--one-top-level` is needed)
routes through a real GNU tar found on the machine's own PATH — see that
file's module docstring for exactly what is substituted and why. The
STATIC assertions at the bottom of this file remain as a second, cheap
check on the exact source shape (matching the convention used for the rest
of the root executor in `tests/security/test_patch_safety.py`), not as the
only proof of the verdicts.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

import commands
import policy

REPO = Path(__file__).resolve().parents[2]
EXECUTOR = (REPO / "executor" / "commands.py").read_text(encoding="utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _seed_point(tmp_path: Path, monkeypatch, *, items: list[dict], point_id="20260901-x"):
    """Builds `<BACKUP_ROOT>/<point_id>/` with the given artifacts and a
    manifest.json describing them, and points the module constants at it."""
    root = tmp_path / "backups"
    drill_root = root / ".restore-drill"
    monkeypatch.setattr(commands, "BACKUP_ROOT", root)
    monkeypatch.setattr(commands, "DRILL_ROOT", drill_root)

    point_dir = root / point_id
    point_dir.mkdir(parents=True)
    manifest_items = []
    for item in items:
        artifact_path = point_dir / item["artifact"]
        artifact_path.write_bytes(item["content"])
        manifest_items.append({
            "artifact": item["artifact"],
            "sha256": item.get("sha256_override", _sha256(item["content"])),
            "size_bytes": len(item["content"]),
            "is_archive": item["is_archive"],
        })
    (point_dir / "manifest.json").write_text(
        json.dumps({"restore_point_id": point_id, "items": manifest_items}),
        encoding="utf-8")
    return point_id, drill_root


# ---------------------------------------------------------------------------
# States that must be reported, not silently swallowed
# ---------------------------------------------------------------------------
def test_a_restore_point_missing_from_disk_is_reported_not_raised(tmp_path, monkeypatch):
    """DB says the point is live, disk disagrees — exactly the class of bug
    this whole project is vigilant about. Must come back as `ok: False`, never
    an unhandled exception that takes the monthly job down with it."""
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")
    monkeypatch.setattr(commands, "DRILL_ROOT", tmp_path / "backups" / ".restore-drill")
    result = commands.op_restore_drill_verify(
        {"restore_point_id": "does-not-exist", "sources": []})
    assert result["ok"] is False
    assert "does not exist" in result["error"]


def test_a_missing_manifest_is_reported(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    monkeypatch.setattr(commands, "BACKUP_ROOT", root)
    monkeypatch.setattr(commands, "DRILL_ROOT", root / ".restore-drill")
    (root / "point-1").mkdir(parents=True)
    result = commands.op_restore_drill_verify(
        {"restore_point_id": "point-1", "sources": []})
    assert result["ok"] is False
    assert "manifest.json" in result["error"]


def test_a_manifest_with_no_items_is_reported(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    monkeypatch.setattr(commands, "BACKUP_ROOT", root)
    monkeypatch.setattr(commands, "DRILL_ROOT", root / ".restore-drill")
    point_dir = root / "point-1"
    point_dir.mkdir(parents=True)
    (point_dir / "manifest.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    result = commands.op_restore_drill_verify(
        {"restore_point_id": "point-1", "sources": []})
    assert result["ok"] is False
    assert "no items" in result["error"]


# ---------------------------------------------------------------------------
# The corruption test the brief asks for by name: an artifact whose bytes
# have changed since sealing must be caught by execution, not assumed.
# ---------------------------------------------------------------------------
def test_a_corrupted_artifact_is_flagged_not_missed(tmp_path, monkeypatch):
    """Falsified: change the check to compare against `sha256_override` instead
    of a freshly-computed digest, and this goes from failing to passing —
    proving the test actually exercises the recomputation, not just the shape
    of the response."""
    point_id, _ = _seed_point(tmp_path, monkeypatch, items=[
        {"artifact": "rpm-nginx.txt", "content": b"nginx-1.20.1-14.el9.x86_64\n",
         "is_archive": False, "sha256_override": "0" * 64},  # wrong on purpose
    ])
    result = commands.op_restore_drill_verify(
        {"restore_point_id": point_id, "sources": []})
    assert result["ok"] is True
    (item,) = result["items"]
    assert item["verdict"] == "corrupt", (
        f"a tampered checksum came back as {item['verdict']!r}")
    assert item["sha256_ok"] is False


def test_an_intact_informational_artifact_is_never_reported_restorable(tmp_path, monkeypatch):
    """The exact property the brief calls out: `restore.sh` itself only prints
    "informativ, vezi manifest.json" for an rpm_state/git_ref artifact — it
    never restores anything. A checksum that matches must not upgrade that
    to "restorable_verified"."""
    content = b"nginx-1.20.1-14.el9.x86_64\n"
    point_id, _ = _seed_point(tmp_path, monkeypatch, items=[
        {"artifact": "rpm-nginx.txt", "content": content, "is_archive": False},
    ])
    result = commands.op_restore_drill_verify(
        {"restore_point_id": point_id, "sources": ["/anything"]})
    (item,) = result["items"]
    assert item["sha256_ok"] is True
    assert item["verdict"] == "informational_only"
    assert item["verdict"] != "restorable_verified"


def test_an_artifact_the_manifest_names_but_disk_does_not_have_is_corrupt(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    monkeypatch.setattr(commands, "BACKUP_ROOT", root)
    monkeypatch.setattr(commands, "DRILL_ROOT", root / ".restore-drill")
    point_dir = root / "point-1"
    point_dir.mkdir(parents=True)
    (point_dir / "manifest.json").write_text(json.dumps({"items": [
        {"artifact": "ghost.tar.zst", "sha256": "a" * 64, "size_bytes": 10,
         "is_archive": True},
    ]}), encoding="utf-8")
    result = commands.op_restore_drill_verify(
        {"restore_point_id": "point-1", "sources": []})
    (item,) = result["items"]
    assert item["verdict"] == "corrupt"
    assert "nu (mai) există" in item["detail"]


# ---------------------------------------------------------------------------
# The most important test in this file: nothing lands outside the isolated
# drill directory, proven by looking at the filesystem after the call, not by
# reading the source and trusting it.
# ---------------------------------------------------------------------------
def test_the_drill_touches_nothing_outside_its_own_isolated_directory(tmp_path, monkeypatch):
    """Falsified: point `DRILL_ROOT` outside `BACKUP_ROOT` (comment out the
    `_reset_drill_root` calls, or write the payload straight into
    `target_dir`) and this test starts finding files where it should not.

    Snapshots the ENTIRE tmp_path tree before and after — not just the one
    directory the code is expected to use — so a bug that writes to an
    unexpected sibling path would still be caught.
    """
    point_id, drill_root = _seed_point(tmp_path, monkeypatch, items=[
        {"artifact": "rpm-nginx.txt", "content": b"nginx-1.20.1-14.el9\n",
         "is_archive": False},
    ])
    before = tmp_path / "backups" / point_id

    def _snapshot() -> set[str]:
        # DRILL_ROOT itself is allowed to exist (empty) after a call — the
        # function recreates it so the next call always has somewhere ready to
        # write. What must NOT exist is anything INSIDE it, or anything
        # anywhere else that was not there before.
        return {str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                if p != drill_root}

    before_files = _snapshot()
    result = commands.op_restore_drill_verify(
        {"restore_point_id": point_id, "sources": []})
    after_files = _snapshot()

    assert result["ok"] is True
    # Nothing new survives anywhere in the tree: the drill root is wiped again
    # on the way out, and this artifact was informational (no extraction), so
    # the only legitimate diff is none at all.
    assert after_files == before_files, (
        f"files appeared or vanished outside expectations: "
        f"new={after_files - before_files} gone={before_files - after_files}")
    assert not drill_root.exists() or not any(drill_root.iterdir()), (
        "the drill root was left non-empty after the call")
    assert before.exists(), "the real restore point directory was touched or removed"


def test_a_failed_extraction_still_leaves_the_drill_root_clean(tmp_path, monkeypatch):
    """An archive item whose bytes are not valid zstd data — the corrupted-
    archive case, exercised for real without needing a `zstd` binary on this
    machine: `tar --zstd` still shells out and still fails, which is exactly
    the `corrupt` branch this proves. What matters here is that a FAILED
    extraction does not leave debris in the drill root."""
    point_id, drill_root = _seed_point(tmp_path, monkeypatch, items=[
        {"artifact": "etc_nginx.tar.zst", "content": b"not a real archive at all",
         "is_archive": True},
    ])
    result = commands.op_restore_drill_verify(
        {"restore_point_id": point_id, "sources": ["/etc/nginx"]})
    assert result["ok"] is True
    (item,) = result["items"]
    assert item["verdict"] == "corrupt"
    assert not drill_root.exists() or not any(drill_root.iterdir())


# ---------------------------------------------------------------------------
# Sources: validated through policy, not trusted blind
# ---------------------------------------------------------------------------
def test_a_malformed_source_is_dropped_not_fatal(tmp_path, monkeypatch):
    """One bad string in `sources` must not abort the whole monthly drill —
    it is excluded from matching and the rest proceeds."""
    point_id, _ = _seed_point(tmp_path, monkeypatch, items=[
        {"artifact": "rpm-nginx.txt", "content": b"x", "is_archive": False},
    ])
    result = commands.op_restore_drill_verify(
        {"restore_point_id": point_id, "sources": ["not-absolute", "../etc/passwd", 42]})
    assert result["ok"] is True


def test_sources_are_checked_through_policy_check_path():
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert "policy.check_path(str(s)" in body


def _func(source: str, name: str) -> str:
    m = re.search(
        rf"^(?:async )?def {re.escape(name)}\(.*?(?=^(?:async )?def |\Z)",
        source, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


# ---------------------------------------------------------------------------
# Static: the happy path this sandbox cannot run for real (see module docstring)
# ---------------------------------------------------------------------------
def test_extraction_never_targets_a_real_path():
    """`restore.sh` extracts to `/` because that IS a real restore. This
    function must never pass `-C /` — every extraction target is built from
    DRILL_ROOT, a path this module owns."""
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert '"-C", "/"' not in body
    assert '-C", str(item_dir)' in body


def test_extraction_uses_one_top_level_for_structural_containment():
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert "--one-top-level=payload" in body


def test_checksum_is_recomputed_not_trusted_from_the_manifest_alone():
    """Same principle as `op_backup_finalize`: a stored digest is not proof
    that today's bytes still match it."""
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert "hashlib.sha256()" in body
    assert "digest.hexdigest() == expected_sha" in body


def test_the_drill_root_is_reset_before_and_after_every_call():
    body = _func(EXECUTOR, "op_restore_drill_verify")
    reset_calls = [m.start() for m in re.finditer(r"_reset_drill_root\(\)", body)]
    assert len(reset_calls) >= 2, (
        "the drill root must be wiped both before use (in case a previous run "
        "was killed) and after (so nothing lingers) — found only "
        f"{len(reset_calls)} call(s)")


def test_low_disk_space_refuses_to_extract_rather_than_risk_filling_the_disk():
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert "DRILL_SPACE_MULTIPLIER" in body
    assert "skipped_low_disk" in body


def test_an_archive_with_no_matching_source_is_structure_mismatch_not_success():
    """The finding this whole feature exists to be able to make: an archive
    that extracts cleanly and checksums correctly, but does not reconstruct
    any declared source at its real path."""
    body = _func(EXECUTOR, "op_restore_drill_verify")
    assert '"structure_mismatch"' in body
    idx_match = body.index("if matched:")
    idx_mismatch = body.index('"structure_mismatch"')
    assert idx_match < idx_mismatch, "the no-match branch is not the else of the match branch"
