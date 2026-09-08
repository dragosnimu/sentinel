"""S5: a socket-activated service must not be reported down between connections.

`sentinel-detect` on Ubuntu ran `systemctl is-active sshd` — a Debian host
actually calls the unit `ssh`, and either name reports `inactive` whenever the
socket has not been asked to spawn the service since boot. `/services`
therefore showed ssh down for days on a host where `ssh -p 22` worked the
whole time. Each test here reproduces one branch of the fix by controlling
exactly what `systemctl is-active` (and a raw TCP connect) would answer,
through a fake `shellsafe.run_async` — nothing here needs a real systemd.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from sentinel.db.repo import assets as assets_repo
from sentinel.health import prober


def run(c):
    return asyncio.run(c)


def _asset(**over: Any) -> assets_repo.Asset:
    now = datetime.now(timezone.utc)
    base = dict(
        id=1, name="ssh", kind="service", bind_addr="127.0.0.1", port=22,
        is_internet_exposed=True, criticality=5, systemd_unit="sshd",
        container_id=None, container_image=None, vhost_file=None, webroot=None,
        stack=None, databases=[], protected=False, confirmed_by_operator=True,
        tags=[], notes=None, first_seen=now, last_seen=now,
    )
    base.update(over)
    return assets_repo.Asset(**base)


@dataclass
class _FakeResult:
    stdout: str
    exit_code: int = 0
    timed_out: bool = False
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def _fake_run_async(answers: dict[tuple, str]):
    """`answers` maps a tuple(argv) to the stdout `systemctl is-active` would
    print for it. Anything not listed raises, so a test cannot pass by
    accident on an unexamined call."""
    async def _run(argv: list[str], timeout_s: int = 10):
        key = tuple(argv)
        if key not in answers:
            raise AssertionError(f"unexpected shellsafe call: {argv}")
        return _FakeResult(stdout=answers[key])
    return _run


def test_active_unit_is_up(monkeypatch):
    monkeypatch.setattr(prober.shellsafe, "run_async",
                        _fake_run_async({("systemctl", "is-active", "sshd"): "active"}))
    result = run(prober._probe_systemd(_asset(), 5, "rhel"))
    assert result.status == "up"


def test_socket_activated_service_reads_up_via_the_socket_unit(monkeypatch):
    """The exact bug: the service unit is idle (inactive) but the socket is
    listening — before this fix that was reported down."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd"): "inactive",
        ("systemctl", "is-active", "sshd.socket"): "active",
    }))
    result = run(prober._probe_systemd(_asset(), 5, "rhel"))
    assert result.status == "up"


def test_debian_family_maps_sshd_to_ssh(monkeypatch):
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "ssh"): "inactive",
        ("systemctl", "is-active", "ssh.socket"): "active",
    }))
    result = run(prober._probe_systemd(_asset(systemd_unit="sshd"), 5, "debian"))
    assert result.status == "up"


def test_dot_service_suffix_maps_to_the_right_socket_name(monkeypatch):
    """`foo.service` must probe `foo.socket`, not `foo.service.socket`."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd.service"): "inactive",
        ("systemctl", "is-active", "sshd.socket"): "active",
    }))
    result = run(prober._probe_systemd(_asset(systemd_unit="sshd.service"), 5, "rhel"))
    assert result.status == "up"


def test_unit_and_socket_both_down_falls_back_to_a_real_tcp_probe(monkeypatch):
    """Belt and braces: even if neither systemd unit looks active, a port
    that actually answers must not be called down."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd"): "inactive",
        ("systemctl", "is-active", "sshd.socket"): "inactive",
    }))

    async def _fake_tcp(asset, timeout_s):
        return prober.ProbeResult(status="up", probe="tcp", latency_ms=3)

    monkeypatch.setattr(prober, "_probe_tcp", _fake_tcp)
    result = run(prober._probe_systemd(_asset(port=22), 5, "rhel"))
    assert result.status == "up"


def test_genuinely_down_service_stays_down(monkeypatch):
    """The fix must not turn every dead service into 'up' — a socket that is
    ALSO inactive and a port that does not answer is really down."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd"): "inactive",
        ("systemctl", "is-active", "sshd.socket"): "inactive",
    }))

    async def _fake_tcp(asset, timeout_s):
        return prober.ProbeResult(status="down", probe="tcp", error="refused")

    monkeypatch.setattr(prober, "_probe_tcp", _fake_tcp)
    result = run(prober._probe_systemd(_asset(port=22), 5, "rhel"))
    assert result.status == "down"


def test_no_port_declared_skips_the_tcp_fallback_cleanly(monkeypatch):
    """An asset with no port to probe must not crash trying the TCP fallback,
    and must still report down when both systemd checks fail."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "myapp"): "inactive",
        ("systemctl", "is-active", "myapp.socket"): "inactive",
    }))
    result = run(prober._probe_systemd(_asset(systemd_unit="myapp", port=None), 5, "rhel"))
    assert result.status == "down"


# ---------------------------------------------------------------------------
# S5 (round 2): `failed` + an `active` socket + a refused TCP connect used to
# read as `up` — the socket alone vouched for a unit that had already tried
# to start and not managed it.
# ---------------------------------------------------------------------------
def test_failed_unit_with_an_active_socket_and_a_refused_port_stays_down(monkeypatch):
    """The exact bug: `failed` means systemd already tried to spawn the
    service (on a connection, or on its own) and it did not work — the
    socket still listening for the NEXT attempt is not evidence anything
    will answer it. Before this fix, `socket_res.stdout.strip() == "active"`
    returned `up` unconditionally, without ever looking at `state`."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd"): "failed",
        ("systemctl", "is-active", "sshd.socket"): "active",
    }))

    async def _fake_tcp(asset, timeout_s):
        return prober.ProbeResult(status="down", probe="tcp", error="connection refused")

    monkeypatch.setattr(prober, "_probe_tcp", _fake_tcp)
    result = run(prober._probe_systemd(_asset(port=22), 5, "rhel"))
    assert result.status == "down", (
        f"failed unit + active socket + refused TCP read as {result.status!r}, "
        f"not down — the socket alone vouched for a unit that already failed to start")
    assert "failed" in result.error


def test_failed_unit_with_an_active_socket_but_a_working_port_is_up(monkeypatch):
    """The flip side: if the port genuinely answers (systemd DID respawn the
    service successfully after the last failure was recorded), that is real
    evidence and must still read up — this is not "failed always means
    down", it is "the socket alone is not enough when the unit is failed"."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "sshd"): "failed",
        ("systemctl", "is-active", "sshd.socket"): "active",
    }))

    async def _fake_tcp(asset, timeout_s):
        return prober.ProbeResult(status="up", probe="tcp", latency_ms=4)

    monkeypatch.setattr(prober, "_probe_tcp", _fake_tcp)
    result = run(prober._probe_systemd(_asset(port=22), 5, "rhel"))
    assert result.status == "up"


def test_failed_unit_with_no_port_declared_stays_down_not_a_crash(monkeypatch):
    """A `failed` unit with an active socket and nothing to TCP-probe must
    not silently read as up just because there was no way to check further."""
    monkeypatch.setattr(prober.shellsafe, "run_async", _fake_run_async({
        ("systemctl", "is-active", "myapp"): "failed",
        ("systemctl", "is-active", "myapp.socket"): "active",
    }))
    result = run(prober._probe_systemd(_asset(systemd_unit="myapp", port=None), 5, "rhel"))
    assert result.status == "down"
