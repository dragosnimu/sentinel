"""Per-uid connection admission on the executor's unix socket (E7).

Prevents: the unprivileged `sentinel` uid opening enough idle connections to
fill every one of the executor's fixed connection slots. Before this, a flat
semaphore treated every caller alike, so `sentinel` — a bug, or an attacker
who has gained that uid — filling all `MAX_CONCURRENT` slots for up to the
idle timeout meant `uid 0` (the watchdog, `ping`ing this same socket to
notice sentinel-side daemons have stopped) got `busy` too, on the one root
process whose entire job is noticing that kind of failure.

Pure in-memory logic: no socket, no thread, no filesystem. `sentinel_executor`
imports cleanly without touching the filesystem or requiring root, so these
run on any platform.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))

import sentinel_executor as se  # noqa: E402

pytestmark = pytest.mark.security

SENTINEL_UID = 999
ROOT_UID = 0


@pytest.fixture(autouse=True)
def _reset_admission_state():
    """Each test starts from zero connections, regardless of execution order."""
    se._active_total = 0
    se._active_by_uid.clear()
    yield
    se._active_total = 0
    se._active_by_uid.clear()


def test_sentinel_uid_is_capped_below_the_flat_total():
    """`sentinel` must never be able to claim every slot — MAX_CONCURRENT_SENTINEL
    is strictly less than MAX_CONCURRENT so headroom always remains."""
    assert se.MAX_CONCURRENT_SENTINEL < se.MAX_CONCURRENT


def test_sentinel_uid_is_refused_past_its_own_cap_while_slots_remain_globally():
    """The bug this replaces: a flat semaphore would admit `sentinel`
    connections until MAX_CONCURRENT regardless of who else might need a
    slot. Here, `sentinel` must be refused once it reaches its own cap even
    though the global total has room to spare."""
    for _ in range(se.MAX_CONCURRENT_SENTINEL):
        assert se._try_admit(SENTINEL_UID, SENTINEL_UID) is True

    assert se._active_total == se.MAX_CONCURRENT_SENTINEL
    assert se._active_total < se.MAX_CONCURRENT, (
        "test setup assumption broken: MAX_CONCURRENT_SENTINEL must leave "
        "global headroom for this test to mean anything"
    )
    assert se._try_admit(SENTINEL_UID, SENTINEL_UID) is False


def test_root_is_admitted_even_when_sentinel_is_at_its_own_cap():
    """The actual guarantee: root (the watchdog) must still get a slot while
    `sentinel` is maxed out — this is what 'reserve a slot for uid 0' means
    in practice, not just a comment."""
    for _ in range(se.MAX_CONCURRENT_SENTINEL):
        assert se._try_admit(SENTINEL_UID, SENTINEL_UID) is True

    assert se._try_admit(ROOT_UID, SENTINEL_UID) is True


def test_root_is_refused_only_once_the_flat_total_is_actually_exhausted():
    """Root has no special exemption from the GLOBAL cap — only from
    sentinel's narrower one. Filling every slot with a mix of uids must
    still eventually refuse root, or MAX_CONCURRENT is decorative."""
    admitted = 0
    for uid in range(se.MAX_CONCURRENT):
        # Alternate uids so no single uid's own cap is what stops admission.
        ok = se._try_admit(1000 + uid, SENTINEL_UID)
        assert ok is True
        admitted += 1
    assert admitted == se.MAX_CONCURRENT
    assert se._try_admit(ROOT_UID, SENTINEL_UID) is False


def test_release_frees_the_slot_for_the_same_uid():
    for _ in range(se.MAX_CONCURRENT_SENTINEL):
        se._try_admit(SENTINEL_UID, SENTINEL_UID)
    assert se._try_admit(SENTINEL_UID, SENTINEL_UID) is False

    se._release(SENTINEL_UID)
    assert se._try_admit(SENTINEL_UID, SENTINEL_UID) is True


def test_release_never_goes_negative_on_an_unbalanced_call():
    """Defensive: a double-release (a bug elsewhere calling _release twice for
    one connection) must not corrupt the counters into letting MORE than
    MAX_CONCURRENT connections in later."""
    se._try_admit(SENTINEL_UID, SENTINEL_UID)
    se._release(SENTINEL_UID)
    se._release(SENTINEL_UID)  # unbalanced
    assert se._active_total == 0
    assert se._active_by_uid.get(SENTINEL_UID, 0) == 0
