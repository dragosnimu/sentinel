"""S9/S4: two systemd unit files that used to leave a real gap unaddressed.

`sentinel-selfcheck.service`'s `TimeoutStartSec=60` was too tight for a
oneshot that opens a fresh connection pool and runs several dozen queries
sequentially — the DB connect alone took 14s once on production, and a check
scanning a 4.7 GB table (fixed separately, S9's other half, in
test_selfcheck.py) made the margin worse. `sentinel-restore-drill.timer`'s
`OnCalendar=*-*-01 04:20:00` + `Persistent=true` does not catch up on a FIRST
activation — Persistent relies on a stamp file systemd only writes once the
unit has fired at least once, so a fresh install would wait up to a month for
its first drill.

These are static config files; the only honest way to test a systemd
directive is to read the file and check the directive itself.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_selfcheck_start_timeout_has_real_margin():
    unit = _read("deploy/systemd/sentinel-selfcheck.service")
    line = next(l for l in unit.splitlines() if l.startswith("TimeoutStartSec="))
    seconds = int(line.split("=", 1)[1])
    assert seconds >= 120, (
        f"TimeoutStartSec is {seconds}s — production measured a 14s DB "
        f"connect alone; a one-minute ceiling leaves too little margin for "
        f"ordinary jitter (a checkpoint, a vacuum) to be told apart from a "
        f"real hang")


def test_restore_drill_timer_runs_shortly_after_first_enablement():
    """Without OnActiveSec (or OnBootSec), a fresh install's first drill
    waits for the 1st of the month — Persistent=true does not help here,
    because it only catches up a run MISSED after the timer has already
    fired at least once."""
    unit = _read("deploy/systemd/sentinel-restore-drill.timer")
    assert "OnActiveSec=" in unit or "OnBootSec=" in unit, (
        "no catch-up trigger for a timer's first-ever activation — a fresh "
        "install gets zero proof a backup can be restored for up to a month")
    assert "OnCalendar=" in unit, "the monthly cadence itself must still exist"
    assert "Persistent=true" in unit, (
        "Persistent=true must stay — it is what catches a run missed because "
        "the host was off, which OnActiveSec does not cover")
