"""Real filesystem/DAC behaviour of the audit directory move (E3).

Prevents: the audit directory living under `/var/lib/sentinel` again, which
is 0750 sentinel:sentinel - the `sentinel` user owns that parent and can
rename or replace anything directly inside it, and the executor's own
capability set omits CAP_DAC_OVERRIDE, so `mkdir` under a hostile or merely
misconfigured parent fails while every operation since would keep executing
and logging "AUDIT WRITE FAILED". The mechanism is reproduced here, in a
directory under `tmp_path`, with `setpriv --bounding-set=-all` standing in for a
capability-stripped systemd unit. It is NOT an outage that was seen on either
live host (5 October 2026: the old chain exists root-owned on both, and the
current boot logged no "AUDIT WRITE FAILED"): the directory move closes a
property of the permissions, and these tests prove the property, not an incident.

NOTHING HERE TOUCHES A REAL PATH. An earlier version of this file removed
`/var/lib/sentinel` and `/var/lib/sentinel-executor` with `shutil.rmtree` around
every test, so running the suite as root on a host with Sentinel installed
destroyed the audit chain - the one record of what ran as root. Every directory is
now under `tmp_path`, injected into the module's constants, and the tests that used
to need root to `chown` to uid 0 run as an ordinary user by letting the owner be
injected too (`AUDIT_OWNER`). What each test still checks is the same POSIX fact:
the mode, the owner, the symlink refusal and the one-time migration. The two tests
that reproduce the capability-stripped `mkdir` need real root and `setpriv`, and are
skipped without them - but even there they create only inside `tmp_path`.

Needs a POSIX filesystem (os.chown, symlinks): skipped on Windows.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))

import sentinel_executor as se  # noqa: E402

pytestmark = pytest.mark.security

posix_only = pytest.mark.skipif(
    not hasattr(os, "chown") or not hasattr(os, "getuid"),
    reason="needs a real POSIX filesystem (os.chown, ownership, modes)",
)
requires_root_and_setpriv = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="reproduces a root process without CAP_DAC_OVERRIDE; needs real root and setpriv "
           "(run in a throwaway container, never on a host that has Sentinel installed)",
)


@pytest.fixture
def audit_tree(tmp_path, monkeypatch):
    """The module's audit locations, relocated under `tmp_path`, with the owner the
    test process itself can chown to. Nothing outside `tmp_path` is read or written."""
    root = tmp_path / "var" / "lib"
    root.mkdir(parents=True)
    audit_dir = root / "sentinel-executor"
    monkeypatch.setattr(se, "AUDIT_DIR", audit_dir)
    monkeypatch.setattr(se, "AUDIT_PATH", audit_dir / "audit.jsonl")
    monkeypatch.setattr(se, "LEGACY_AUDIT_PATH", root / "sentinel" / "executor" / "audit.jsonl")
    if hasattr(os, "getuid"):
        monkeypatch.setattr(se, "AUDIT_OWNER", (os.getuid(), os.getgid()))
    return root


def test_the_shipped_audit_owner_is_root_and_the_paths_are_the_real_ones():
    """The injection above must not be how production runs: unmodified, the owner is
    uid 0 / gid 0 and the directory is the root-only sibling of /var/lib/sentinel."""
    assert se.AUDIT_OWNER == (0, 0)
    assert se.AUDIT_DIR == Path("/var/lib/sentinel-executor")
    assert se.AUDIT_PATH == se.AUDIT_DIR / "audit.jsonl"
    assert se.LEGACY_AUDIT_PATH == Path("/var/lib/sentinel/executor/audit.jsonl")


@posix_only
def test_creates_a_0700_directory_owned_by_the_configured_owner(audit_tree):
    """Uses se.AUDIT_DIR itself, not a hardcoded stand-in: a future change
    that points the constant back at the old, sentinel-writable location
    must fail this test, not sail past it because the test brought its own
    path."""
    se._prepare_audit_dir()

    st = os.stat(se.AUDIT_DIR)
    assert (st.st_uid, st.st_gid) == se.AUDIT_OWNER
    assert (st.st_mode & 0o777) == 0o700


@posix_only
def test_a_directory_whose_mode_has_drifted_is_put_back_to_0700(audit_tree):
    """The same self-healing systemd-tmpfiles' own `d` type does on every boot: a mode
    loosened by hand is corrected, not trusted."""
    se.AUDIT_DIR.mkdir()
    se.AUDIT_DIR.chmod(0o755)
    se._prepare_audit_dir()
    assert (os.stat(se.AUDIT_DIR).st_mode & 0o777) == 0o700


@posix_only
def test_refuses_to_start_when_it_cannot_give_the_directory_to_its_owner(audit_tree, monkeypatch):
    """No trustworthy place for audit rows means no start: `chown` failing is refused,
    not tolerated. Provoked by naming an owner an unprivileged process cannot chown to."""
    if os.geteuid() == 0:
        pytest.skip("root can chown to anyone; the refusal this tests cannot be provoked this way")
    other = os.getuid() + 1
    monkeypatch.setattr(se, "AUDIT_OWNER", (other, other))
    with pytest.raises(SystemExit):
        se._prepare_audit_dir()


@posix_only
def test_a_chown_that_reported_success_is_not_believed(audit_tree, monkeypatch):
    """A call succeeding without producing the state it promised is what this file
    exists to not have: the read-back refuses a directory that did not end up owned by
    the owner, even when `chown` itself said nothing. The kernel is simulated lying
    (chown does nothing) because a real one cannot be made to."""
    other = os.getuid() + 1
    monkeypatch.setattr(se, "AUDIT_OWNER", (other, other))
    monkeypatch.setattr(se.os, "chown", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        se._prepare_audit_dir()


@posix_only
def test_migrates_the_legacy_chain_once_and_resumes_from_it(audit_tree):
    legacy = se.LEGACY_AUDIT_PATH
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"seq": 1, "entry_hash": "aaa"}\n{"seq": 2, "entry_hash": "bbb"}\n')

    se._prepare_audit_dir()

    assert se.AUDIT_PATH.read_text() == legacy.read_text()
    assert se._load_audit_chain() == "bbb"

    # Idempotent: a second call must not re-migrate over a newer legacy write.
    legacy.write_text(legacy.read_text() + '{"seq": 3, "entry_hash": "ccc"}\n')
    se._prepare_audit_dir()
    assert se._load_audit_chain() == "bbb"


@posix_only
def test_audit_write_refuses_a_symlink_planted_at_the_audit_path(audit_tree, tmp_path):
    se._prepare_audit_dir()

    target = tmp_path / "evil-target"
    target.write_text("")
    os.symlink(str(target), str(se.AUDIT_PATH))

    se.audit("block_ip", "203.0.113.6", {}, "ok", None, {"uid": 0, "pid": 1})

    assert target.read_text() == "", "O_NOFOLLOW must refuse to write through the symlink"


@posix_only
def test_an_audit_row_really_reaches_the_relocated_file(audit_tree):
    """The positive control for the symlink test above: with no symlink the same call
    writes a hash-chained row. Without this, 'the target stayed empty' would also be
    what a broken fixture produces."""
    se._prepare_audit_dir()
    se.audit("block_ip", "203.0.113.6", {}, "ok", None, {"uid": 0, "pid": 1})
    rows = [json.loads(line) for line in se.AUDIT_PATH.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["operation"] == "block_ip"
    assert oct(os.stat(se.AUDIT_PATH).st_mode & 0o777) == oct(0o600)


@posix_only
@requires_root_and_setpriv
def test_the_old_writable_parent_blocks_mkdir_without_cap_dac_override(tmp_path):
    """The root-cause reproduction: this is what actually broke on production
    before the fix - a root process WITHOUT CAP_DAC_OVERRIDE (the executor's
    real capability set) could not create a directory under the
    sentinel-writable /var/lib/sentinel, because ownership of a leaf
    directory does not matter if an ancestor denies traversal/write to a
    uid-0 process lacking that capability.

    The 'sentinel-writable parent' is a directory under `tmp_path` owned by an
    unprivileged uid; the real /var/lib/sentinel is never created or touched."""
    parent = tmp_path / "var" / "lib" / "sentinel"
    parent.mkdir(parents=True, mode=0o750)
    os.chown(parent, 1000, 1000)  # simulates sentinel:sentinel

    proc = subprocess.run(
        ["setpriv", "--bounding-set=-all", "--inh-caps=-all", sys.executable, "-c",
         f"import os\nos.mkdir({str(parent / 'executor')!r})"],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0, (
        "expected mkdir under the OLD sentinel-writable parent to fail without "
        f"CAP_DAC_OVERRIDE; got rc={proc.returncode}, stderr={proc.stderr!r}"
    )


@posix_only
@requires_root_and_setpriv
def test_the_new_sibling_parent_allows_mkdir_without_cap_dac_override(tmp_path):
    """The fix, under the same constraint the bug above needs to reproduce:
    /var/lib is root-owned and world-traversable, so creating a SIBLING of
    /var/lib/sentinel there does not depend on CAP_DAC_OVERRIDE at all. The stand-in
    for /var/lib is a root-owned 0755 directory under `tmp_path`."""
    lib = tmp_path / "var" / "lib"
    lib.mkdir(parents=True)
    os.chmod(lib, 0o755)
    target = lib / "sentinel-executor"

    proc = subprocess.run(
        ["setpriv", "--bounding-set=-all", "--inh-caps=-all", sys.executable, "-c",
         f"import os\np = {str(target)!r}\nos.mkdir(p)\nos.chown(p, 0, 0)\nos.chmod(p, 0o700)"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        f"expected mkdir under a root-owned parent to succeed without "
        f"CAP_DAC_OVERRIDE; got rc={proc.returncode}, stderr={proc.stderr!r}"
    )
    assert (os.stat(target).st_mode & 0o777) == 0o700
