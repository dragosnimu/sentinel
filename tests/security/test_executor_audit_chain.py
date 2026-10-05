"""Audit chain resume and rotation (E6).

Prevents two related failures in `sentinel_executor`'s hash-chained audit log:

1. `_load_audit_chain` used to read a FIXED 8192-byte tail window to find the
   most recent complete line and resume the chain from its hash. Nothing
   bounded how large a single entry could be (`param_keys` had no cap), so an
   operation with many or long argument names could produce a line bigger
   than that window — landing the read in the MIDDLE of it, failing to
   parse, and silently starting a new chain link. A gap in a tamper-evident
   log is supposed to look like tampering; this made it look like nothing
   happened.
2. Nothing rotated the file, so the fixed-window problem above only ever got
   more likely to hit as the file grew, never less.

Pure file logic — no socket, no root, no chown — so these run on any
platform the way `_load_audit_chain`/`_rotate_audit_if_needed` themselves do
(they use only `open`/`Path.stat`/`Path.rename`, not the POSIX-only
`os.chown`/`os.O_NOFOLLOW` the write path in `audit()` needs).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))

import sentinel_executor as se  # noqa: E402

pytestmark = pytest.mark.security


def _write_chain(path: Path, hashes: list[str], *, pad_last_to: int = 0) -> None:
    """Write a minimal but structurally valid audit chain to `path`.

    `pad_last_to` inflates the LAST entry's `detail` field so its line can be
    made deliberately larger than the old fixed 8192-byte tail window,
    reproducing the exact shape of the bug.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for i, h in enumerate(hashes):
        detail = "x" * pad_last_to if (i == len(hashes) - 1 and pad_last_to) else None
        lines.append(json.dumps({"seq": i, "entry_hash": h, "detail": detail}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_resumes_from_the_last_hash_in_a_small_ordinary_chain(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    _write_chain(audit_path, ["hash-a", "hash-b", "hash-c"])
    monkeypatch.setattr(se, "AUDIT_PATH", audit_path)

    assert se._load_audit_chain() == "hash-c"


def test_missing_file_starts_a_fresh_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(se, "AUDIT_PATH", tmp_path / "does-not-exist.jsonl")
    assert se._load_audit_chain() == "0" * 64


def test_resume_survives_a_final_entry_larger_than_the_starting_tail_window(tmp_path, monkeypatch):
    """The exact bug: a final line bigger than the (old, fixed) 8192-byte
    window used to land the read mid-line, fail to parse, and silently reset
    the chain to zero instead of resuming it. The fix must keep widening the
    read until it finds a complete final line, up to its own ceiling."""
    audit_path = tmp_path / "audit.jsonl"
    _write_chain(audit_path, ["hash-a", "hash-b", "hash-final"], pad_last_to=20_000)
    monkeypatch.setattr(se, "AUDIT_PATH", audit_path)

    assert se._load_audit_chain() == "hash-final"


def test_resume_gives_up_past_the_ceiling_rather_than_hanging_or_guessing(tmp_path, monkeypatch):
    """If even the ceiling cannot find a complete line (a genuinely corrupt or
    absurdly larger-than-expected file), the function must return the
    zero-hash sentinel rather than raising or blocking indefinitely — a
    resume mechanism that cannot resume must fail safely, not fail loudly
    into a crash loop."""
    audit_path = tmp_path / "audit.jsonl"
    # A single line with no trailing newline, larger than the ceiling: no
    # window this function tries will ever contain a parseable full line
    # (there isn't one — this simulates a torn/corrupt tail).
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_bytes(b"{" + b"x" * (se._AUDIT_TAIL_MAX_BYTES + 1000))
    monkeypatch.setattr(se, "AUDIT_PATH", audit_path)

    assert se._load_audit_chain() == "0" * 64


def test_rotates_once_the_file_passes_the_size_ceiling(tmp_path, monkeypatch):
    audit_dir = tmp_path
    audit_path = audit_dir / "audit.jsonl"
    audit_path.write_bytes(b"x" * (10))
    monkeypatch.setattr(se, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(se, "AUDIT_PATH", audit_path)
    monkeypatch.setattr(se, "AUDIT_ROTATE_BYTES", 5)  # tiny, so the file above already exceeds it

    se._rotate_audit_if_needed()

    assert not audit_path.exists(), "the oversized file must have been moved aside"
    rotated = list(audit_dir.glob("audit-*.jsonl"))
    assert len(rotated) == 1
    assert rotated[0].read_bytes() == b"x" * 10


def test_does_not_rotate_a_file_under_the_ceiling(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_bytes(b"x" * 10)
    monkeypatch.setattr(se, "AUDIT_DIR", tmp_path)
    monkeypatch.setattr(se, "AUDIT_PATH", audit_path)
    monkeypatch.setattr(se, "AUDIT_ROTATE_BYTES", 1_000_000)

    se._rotate_audit_if_needed()

    assert audit_path.exists()
    assert audit_path.read_bytes() == b"x" * 10


def test_param_keys_are_capped_in_count_and_length(monkeypatch, tmp_path):
    """Directly targets the root cause the tail-window bug exploited: nothing
    used to bound how many argument names, or how long each one, an audit
    entry could carry.

    Exercises the real `audit()` write path with `os.open`/`os.fdopen`
    mocked out — not because the logic under test needs mocking, but because
    `os.O_NOFOLLOW` does not exist on this sandbox's non-POSIX platform (see
    the module note in test_executor_client_timeout.py for the same
    constraint on AF_UNIX). The mocks stand in for the filesystem only; the
    capping logic that builds `entry` runs unmodified.
    """
    many_long_keys = {f"argument_name_number_{i:03d}_padded_out_long" * 2: "x" for i in range(200)}
    written: dict[str, bytes] = {}

    class _FakeHandle:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def write(self, data):
            written["line"] = data

        def flush(self):
            pass

        def fileno(self):
            return 0

    monkeypatch.setattr(se.os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(se.os, "open", lambda *a, **k: 0)
    monkeypatch.setattr(se.os, "fdopen", lambda *a, **k: _FakeHandle())
    monkeypatch.setattr(se.os, "fsync", lambda *a, **k: None)
    monkeypatch.setattr(se.os, "chmod", lambda *a, **k: None)
    monkeypatch.setattr(se, "AUDIT_PATH", tmp_path / "audit.jsonl")

    se.audit("op", None, many_long_keys, "ok", None, {"uid": 0, "pid": 1})

    entry = json.loads(written["line"])
    assert len(entry["param_keys"]) <= se._AUDIT_PARAM_KEYS_MAX
    assert all(len(k) <= se._AUDIT_PARAM_KEY_LEN_MAX for k in entry["param_keys"])
    # The truncation must be honest about how much it hid, not silent about it.
    assert entry["param_key_count"] == len(many_long_keys)
