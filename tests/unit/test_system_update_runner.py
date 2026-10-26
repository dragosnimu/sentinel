"""Un plan de update, rulat prin runnerul REAL contra unui executor fals.

Ce dovedește fișierul: planul construit în cod nu doar trece validatorul, ci își parcurge
fazele în runner — preflight, backup, apply, health, post-verificare — și se comportă cum a
promis docstring-ul lui `system_update` când ceva cade: un singur pas de apply, un singur pas
de rollback cu toate pinurile, «exit 0 și nimic instalat» prins de post-verificare.

Ce NU dovedește: nimic despre `dnf` sau `rpm` adevărate (executorul de aici e o dublură care
răspunde cu versiunile din plan), despre legarea la aprobarea semnată (dublura nu o impune; vezi
`test_executor_plan_binding`), sau despre faptul că `dnf downgrade` către o versiune deja
instalată iese cu cod 1 — asta e presupunerea din spatele rândului «nimic de restaurat» din
mesajul de rezultat, citită din codul dnf, NEverificată pe o gazdă.
"""
from __future__ import annotations

import asyncio
from typing import Any

from sentinel.patch import backup as backup_mod
from sentinel.patch import checks as checks_mod
from sentinel.patch import runner
from sentinel.patch import system_update as su
from tests.unit import _system_update_support as sup
from tests.unit.test_patch_runner import _FakeDB, _FakeExec


def run(c):
    return asyncio.run(c)


class _HostExec(_FakeExec):
    """Executor fals cu stare: `rpm -q` răspunde cu versiunea de dinainte până ce un `dnf update`
    real a rulat, apoi cu cea țintă — ca o gazdă."""

    def __init__(self, plan: dict[str, Any], *, update_installs: bool = True, update_exit: int = 0,
                 downgrade_exit: int = 0) -> None:
        super().__init__()
        self.meta = {p["name"]: p for p in plan["update"]["packages"]}
        self.installed = {n: p["before"] for n, p in self.meta.items()}
        self.update_installs, self.update_exit, self.downgrade_exit = update_installs, update_exit, downgrade_exit

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        argv = args.get("argv") or []
        if op == "patch_step_exec" and not args.get("dry_run"):
            if argv[:3] == ["dnf", "-y", "update"]:
                self.calls.append({"op": op, **args})
                if self.update_exit == 0 and self.update_installs:
                    for name in argv[3:]:
                        self.installed[name] = self.meta[name]["target"]
                return {"exit_code": self.update_exit, "stdout": "", "stderr": "boom" if self.update_exit else "",
                        "timed_out": False}
            if argv[:3] == ["dnf", "-y", "downgrade"]:
                self.calls.append({"op": op, **args})
                if self.downgrade_exit == 0:
                    for pin in argv[3:]:
                        for name, p in self.meta.items():
                            if pin == f"{name}-{p['before']}":
                                self.installed[name] = p["before"]
                return {"exit_code": self.downgrade_exit, "stdout": "", "stderr": "", "timed_out": False}
            if argv[:3] == ["rpm", "-q", "--qf"] and argv[-1] in self.installed:
                self.calls.append({"op": op, **args})
                evr = self.installed[argv[-1]]
                epoch, rest = (evr.split(":", 1) if ":" in evr else ("0", evr))
                return {"exit_code": 0, "stdout": f"{epoch}:{rest}\n", "stderr": "", "timed_out": False}
        return super().call(op, **args)


def _lot(monkeypatch) -> dict[str, Any]:
    sup.install(monkeypatch, sup.FakeHost())
    return run(su.select(sup.FakeDB(), sup.cfg())).lots[0].plan


def _wire(monkeypatch, fake: _FakeExec) -> None:
    for module in (runner, backup_mod, checks_mod):
        monkeypatch.setattr(module, "_client", fake)


def _real_calls(fake: _HostExec, prefix: list[str]) -> list[dict[str, Any]]:
    return [c for c in fake.calls if c["op"] == "patch_step_exec" and not c.get("dry_run")
            and (c.get("argv") or [])[:len(prefix)] == prefix]


def test_a_dry_run_of_a_lot_succeeds_without_running_anything(monkeypatch):
    plan = _lot(monkeypatch)
    fake = _HostExec(plan)
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan, status="validated"), None, 1, mode="dry_run"))
    assert res.status == "succeeded", res.error
    assert not _real_calls(fake, ["dnf"]), "un dry-run a rulat dnf"


def test_an_apply_runs_one_update_and_every_check_confirms_it(monkeypatch):
    """Calea fericită, cap-coadă prin runnerul real: un singur `dnf update` cu toate pachetele, o
    copie de siguranță `rpm_state` pe pachet, iar post-verificarea (`rpm -q`) vede versiunile
    țintă — nu codul de ieșire."""
    plan = _lot(monkeypatch)
    fake = _HostExec(plan)
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))

    assert res.status == "succeeded", res.error
    updates = _real_calls(fake, ["dnf", "-y", "update"])
    assert len(updates) == 1 and updates[0]["argv"] == plan["apply"][0]["argv"]
    assert not _real_calls(fake, ["dnf", "-y", "downgrade"])
    kinds = [c["kind"] for c in fake.calls if c["op"] == "backup_create"]
    assert kinds and set(kinds) == {"rpm_state"} and len(kinds) == len(plan["update"]["packages"])


def test_a_failed_update_rolls_back_with_one_step_carrying_every_pin(monkeypatch):
    """Dacă tranzacția cade, rulează UN pas de rollback cu toate pinurile lotului — nu câte unul pe
    pachet. Starea după revenire e cea de dinainte, citită prin aceleași `rpm -q`."""
    plan = _lot(monkeypatch)
    fake = _HostExec(plan, update_exit=1)
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))

    assert res.status == "rolled_back", (res.status, res.error)
    downgrades = _real_calls(fake, ["dnf", "-y", "downgrade"])
    assert len(downgrades) == 1 and downgrades[0]["argv"] == plan["rollback"][0]["argv"]
    assert len(downgrades[0]["argv"]) == 3 + len(plan["update"]["packages"])
    assert fake.installed == {n: p["before"] for n, p in fake.meta.items()}


def test_exit_zero_with_nothing_installed_is_caught_by_the_post_verification(monkeypatch):
    """«Exit 0, nimic instalat» — dnf spune succes, un depozit îngheţat n-a oferit nimic nou. Nu
    codul decide: `pkg_version at_least` din post-verificare citește `rpm`, pică, și planul își
    face rollback-ul în loc să raporteze o reparație care nu s-a întâmplat."""
    plan = _lot(monkeypatch)
    fake = _HostExec(plan, update_installs=False)
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))

    assert res.status == "rolled_back", (res.status, res.error)
    assert "post_verification" in (res.rollback_reason or res.error or "")
    assert len(_real_calls(fake, ["dnf", "-y", "downgrade"])) == 1


def test_a_failed_rollback_is_the_loudest_state(monkeypatch):
    plan = _lot(monkeypatch)
    fake = _HostExec(plan, update_exit=1, downgrade_exit=1)
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))
    assert res.status == "rollback_failed"


def test_the_preflight_stops_a_lot_whose_installed_versions_moved(monkeypatch):
    """`pkg_version equals` fixează versiunea pe care se sprijină revenirea. Dacă gazda a mers
    mai departe între propunere și aplicare (alt update, manual), planul se oprește ÎNAINTE de
    orice schimbare: rollback-ul fixat pe versiunea veche ar duce pachetul pe una pe care gazda
    n-a avut-o în momentul acesta."""
    plan = _lot(monkeypatch)
    fake = _HostExec(plan)
    first = sorted(fake.meta)[0]
    fake.installed[first] = "9.9-9.el9"
    _wire(monkeypatch, fake)
    res = run(runner.run_plan(_FakeDB(plan), None, 1, mode="apply"))

    assert res.status == "aborted", (res.status, res.error)
    assert not _real_calls(fake, ["dnf"])
    assert not [c for c in fake.calls if c["op"] == "backup_create"], "backup făcut după un preflight picat"
