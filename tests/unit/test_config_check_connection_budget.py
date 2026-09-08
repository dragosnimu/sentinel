"""S8: `config-check` must say when the pool arithmetic does not fit the
server, not just that each field is individually a valid number.

`pool_max: 10` reads as sane on its own. Multiplied across every daemon that
holds a pool open continuously (`_PERSISTENT_POOL_SERVICES`), it is the real
ceiling on the server's `max_connections` — measured at 40 on both production
hosts. Each test drives `_connection_budget_line` with a fake
`_read_max_connections`, so nothing here needs a real Postgres.

Round 2: the multiplier used to be `len(SERVICES)` (14 entries) — counting
`restoredrill`/`patchwindow` (periodic jobs, not resident daemons) and
`scan`/`health`/`maintenance`/`selfcheck`/`reconcile` (systemd-timer
oneshots) right alongside the seven processes that actually sit there
holding a pool 24/7. `_PERSISTENT_POOL_SERVICES` (7 entries) is the number
an operator can actually check by eye against `systemctl list-units`.
"""
from __future__ import annotations

from types import SimpleNamespace

from sentinel import __main__ as cli


def _cfg(pool_max: int) -> SimpleNamespace:
    return SimpleNamespace(database=SimpleNamespace(pool_max=pool_max))


def test_the_persistent_multiplier_is_seven_not_every_service(monkeypatch):
    """Sanity on the fixture itself: `_PERSISTENT_POOL_SERVICES` must be the
    seven resident daemons, not the full `SERVICES` tuple (14 entries,
    including timer oneshots and periodic jobs) it used to be."""
    assert len(cli._PERSISTENT_POOL_SERVICES) == 7
    assert len(cli._PERSISTENT_POOL_SERVICES) < len(cli.SERVICES)
    for oneshot in ("restoredrill", "patchwindow", "health", "selfcheck",
                    "scan", "maintenance", "reconcile"):
        assert oneshot not in cli._PERSISTENT_POOL_SERVICES, (
            f"{oneshot!r} is a periodic job / timer oneshot, not a resident "
            f"daemon holding a pool open — it must not inflate the multiplier")


def test_budget_under_the_servers_limit_is_not_a_warning(monkeypatch):
    async def _fake(cfg):
        return 100

    monkeypatch.setattr(cli, "_read_max_connections", _fake)
    line = cli._connection_budget_line(_cfg(pool_max=1))
    assert "ATENȚIE" not in line
    assert str(len(cli._PERSISTENT_POOL_SERVICES) * 1) in line


def test_budget_over_the_servers_limit_warns_loudly(monkeypatch):
    """Confirmed on both production hosts: max_connections is 40. The
    shipped defaults (pool_max=10) must still warn: 7 × 10 = 70 > 40 — a
    config that does not fit the server's own default limit without the
    operator changing one of the two numbers."""
    async def _fake(cfg):
        return 40

    monkeypatch.setattr(cli, "_read_max_connections", _fake)
    line = cli._connection_budget_line(_cfg(pool_max=10))
    assert len(cli._PERSISTENT_POOL_SERVICES) * 10 > 40   # sanity on the fixture itself
    assert "ATENȚIE" in line
    assert "40" in line


def test_the_timer_oneshots_are_named_not_silently_dropped(monkeypatch):
    """Excluding health/selfcheck/etc. from the multiplier must not make
    them invisible — the line still says they exist and connect briefly."""
    async def _fake(cfg):
        return 100

    monkeypatch.setattr(cli, "_read_max_connections", _fake)
    line = cli._connection_budget_line(_cfg(pool_max=1))
    assert "health" in line.lower()
    assert "selfcheck" in line.lower()


def test_unreachable_server_says_so_instead_of_pretending_the_budget_is_fine(monkeypatch):
    """'Could not tell' and 'fine' must not look the same here either — the
    same rule CLAUDE.md states for every other check in this codebase."""
    async def _fake(cfg):
        return None

    monkeypatch.setattr(cli, "_read_max_connections", _fake)
    line = cli._connection_budget_line(_cfg(pool_max=10))
    assert "nu a putut fi citit" in line
    assert "ATENȚIE" not in line   # unknown is not the same claim as "over budget"


def test_a_crashing_probe_does_not_crash_config_check(monkeypatch):
    async def _boom(cfg):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "_read_max_connections", _boom)
    line = cli._connection_budget_line(_cfg(pool_max=10))
    assert "nu a putut fi citit" in line
