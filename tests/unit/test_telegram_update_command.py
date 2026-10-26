"""`/update` — comanda, și ce face `patch_flow` cu planurile ei.

Eșecul pe care fișierul ăsta îl previne, măsurat pe producție pe 26 octombrie 2026: 347 de
constatări `dnf` deschise, TOATE cu reparație, 33 de pachete — și nicio comandă care să le
transforme în ceva ce operatorul poate aproba. Calea de aplicare există deja întreagă
(`patch_flow`); ce lipsea era un mod de a-i da planuri fără să se construiască un al doilea drum.

Ce NU se poate verifica de aici:

  * că Telegram acceptă comanda în meniu — nu există token în suită (vezi `test_telegram_menu`);
  * că o tranzacție reală `dnf` se încheie bine, sau că semnătura de pe stația operatorului
    acceptă cererea unui lot: `approval.challenge` vorbește cu executorul, care aici lipsește.
    Ce se verifică e lungimea cererii, față de plafonul pe care îl aplică (vezi
    `test_system_update_plan`).
"""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("telegram")

from sentinel.config import Config  # noqa: E402
from sentinel.db.repo import approvals  # noqa: E402
from sentinel.db.repo import patches as patch_repo  # noqa: E402
from sentinel.patch import runner  # noqa: E402
from sentinel.patch import system_update as su  # noqa: E402
from sentinel.telegram import bot, patch_flow, update_view, views  # noqa: E402
from tests.unit import _system_update_support as sup  # noqa: E402

CHAT_ID = 1234567890   # substituent — vezi nota din tests/unit/test_telegram_errors.py
OTHER_CHAT = 1987654321


def run(c):
    return asyncio.run(c)


class _Msg:
    def __init__(self, events: list) -> None:
        self.events = events
        self.sent: list[str] = []

    async def reply_text(self, text, **kw):
        self.sent.append(text)
        self.events.append(("reply", text))


def _cfg(*, viewer: bool = False) -> Config:
    cfg = Config()
    cfg.telegram.allowed_chat_ids = [CHAT_ID]
    if viewer:
        cfg.telegram.owner_chat_id = OTHER_CHAT
    return cfg


class World:
    """Tot ce atinge comanda în afara ei: baza, gazda, repo-ul de planuri, fluxul de aprobare."""

    def __init__(self, monkeypatch, *, db: sup.FakeDB | None = None, host: sup.FakeHost | None = None,
                 drill: Any = None, viewer: bool = False) -> None:
        self.events: list[tuple[str, Any]] = []
        self.stored: list[dict[str, Any]] = []
        self.offered: list[dict[str, Any]] = []
        self.db = db or sup.FakeDB(scanners=[
            {"scanner": "dnf", "n": 347, "with_fix": 347},
            {"scanner": "trivy_image", "n": 2536, "with_fix": 1679},
            {"scanner": "trivy_fs", "n": 140, "with_fix": 140}])
        sup.install(monkeypatch, host or sup.FakeHost())

        async def store_plan(db, **kw):
            self.stored.append(kw)
            self.events.append(("store", kw["generated_by"]))
            return 100 + len(self.stored)

        async def mark(db, plan_id):
            self.events.append(("mark", plan_id))

        async def get_plan(db, plan_id):
            kw = self.stored[plan_id - 101]
            plan = kw["plan"]
            return patch_repo.PlanRow(
                id=plan_id, plan_id=uuid.uuid4(), plan_hash=kw["plan_hash"], plan=plan,
                status="validated", risk_level=plan["risk"]["level"],
                requires_reboot=plan["risk"]["requires_reboot"], reversible=plan["risk"]["reversible"],
                estimated_downtime_s=0, asset_id=None,
                created_at=datetime(2026, 10, 26, tzinfo=timezone.utc), approved_by=None,
                approved_at=None, validation_errors=None)

        async def drill_summary(db):
            return drill

        async def send(bot_, db, chat_id, row, *, gate_note=None, allow_apply=True):
            self.offered.append({"chat": chat_id, "plan": row.id, "gate_note": gate_note,
                                 "allow_apply": allow_apply})
            self.events.append(("offer", row.id))

        async def never(*a, **k):
            raise AssertionError("un token de aprobare a fost emis de comanda /update")

        monkeypatch.setattr(su.repo, "store_plan", store_plan)
        monkeypatch.setattr(su.repo, "mark_plan_notified", mark)
        monkeypatch.setattr(patch_repo, "get_plan", get_plan)
        monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", drill_summary)
        monkeypatch.setattr(patch_flow, "send_plan_for_approval", send)
        monkeypatch.setattr(approvals, "issue", never)
        self.msg = _Msg(self.events)
        self.update = SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                                      effective_message=self.msg, message=self.msg)
        self.cfg = _cfg(viewer=viewer)

    def command(self, *args: str) -> list[str]:
        ctx = SimpleNamespace(bot_data={"db": self.db, "cfg": self.cfg}, args=list(args), bot=object())
        run(bot.cmd_update(self.update, ctx))
        return self.msg.sent

    @property
    def writes(self) -> list[str]:
        return [sql for sql, _ in self.db.calls if re.search(r"\b(INSERT|UPDATE|DELETE)\b", sql)]


# ---------------------------------------------------------------------------
# Suprafața
# ---------------------------------------------------------------------------
def test_update_is_an_acting_command_with_ascii_names_and_the_help_names_it():
    """Un diacritic într-un alias a oprit botul o zi (1113 reporniri). Numele canonic trebuie să
    fie cel pe care îl tipărește /ajutor, iar comanda — în tabela care cere rolul."""
    cmd = next(c for c in bot.COMMANDS if "update" in c.names)
    assert cmd in bot.ACTING and cmd not in bot.READ_ONLY
    assert cmd.canonical == "update"
    assert all(re.fullmatch(r"[a-z0-9_]{1,32}", n) for n in cmd.names), cmd.names
    assert any(ln.startswith("/update ") for ln in views.HELP.splitlines())


# ---------------------------------------------------------------------------
# Fără argument: citește și atât
# ---------------------------------------------------------------------------
def test_the_overview_shows_the_numbers_and_changes_nothing(monkeypatch):
    """«Ce e actualizabil» nu are voie să pornească nimic: nici un plan scris, nici un buton, nici
    un token de aprobare, nici o scriere în bază. Cifrele vin din bază, pe categorii."""
    w = World(monkeypatch)
    sent = w.command()

    assert len(sent) == 1
    text = sent[0]
    assert "347" in text and "1679" in text and "140" in text
    assert "Sistem de operare" in text and "Container" in text and "Aplica" in text
    assert w.stored == [] and w.offered == [] and w.writes == []
    assert not [e for e in w.events if e[0] in ("store", "mark", "offer")]
    # Ce se reține apare cu motiv, nu doar ca un număr.
    assert "install-only" in text


def test_the_overview_says_so_when_it_cannot_tell_what_is_updatable(monkeypatch):
    """Dacă `rpm` nu răspunde, cifrele din bază se arată, iar «ce se poate actualiza» spune că nu
    se știe — nu «0 pachete»."""
    w = World(monkeypatch, host=sup.FakeHost("garbage\n"))
    text = w.command()[0]
    assert "347" in text and "Nu pot spune ce se poate actualiza" in text
    assert "de actualizat: <b>0</b>" not in text


def test_a_viewer_reads_the_overview_but_cannot_start_an_update(monkeypatch):
    w = World(monkeypatch, viewer=True)
    assert "347" in w.command()[0]
    sent = w.command("sistem")
    assert "rol de operator" in sent[-1]
    assert w.stored == [] and w.offered == []


# ---------------------------------------------------------------------------
# /update sistem: un lot, prin fluxul care există
# ---------------------------------------------------------------------------
def test_update_system_stores_one_lot_and_offers_it_through_patch_flow(monkeypatch):
    """Un singur lot odată, dat lui `patch_flow.send_plan_for_approval` — același flux, aceeași poartă,
    aceleași butoane ca pentru orice plan. Nu doua loturi deodată: unul care cade nu trebuie să
    găsească altul deja oferit, cu butoane vii."""
    w = World(monkeypatch)
    sent = w.command("sistem")

    assert len(w.stored) == 1
    kw = w.stored[0]
    assert kw["generated_by"] == "update" and kw["model"] is None and kw["status"] == "validated"
    assert len(w.offered) == 1 and w.offered[0]["plan"] == 101 and w.offered[0]["chat"] == CHAT_ID
    assert "lotul 1 din 2" in sent[0]
    assert "kernel" in sent[0], "nucleul e reținut, iar operatorul trebuie să vadă că și de ce"
    # Ordinea contează: marcat notificat ÎNAINTE de trimitere (altfel bucla de push îl oferă a doua oară).
    kinds = [e[0] for e in w.events]
    assert kinds.index("store") < kinds.index("mark") < kinds.index("offer")


def test_the_return_path_verdict_reaches_the_buttons(monkeypatch):
    """Verdictul porții de întoarcere (`_verdict_de_intoarcere`, același ca la /planifica) hotărăște
    dacă butonul «Aplică» apare. Pe rhel fiecare lot e azi UNPROVEN (nicio arhivă `path` în plan,
    niciun exercițiu): butonul rămâne, cu avertismentul scris lângă el — ca la orice plan."""
    w = World(monkeypatch)
    w.command("sistem")
    assert w.offered[0]["allow_apply"] is True
    assert "NEDOVEDITĂ" in w.offered[0]["gate_note"]


def test_a_withdrawn_apply_button_stays_withdrawn(monkeypatch):
    """Dacă poarta spune «fără cale de întoarcere», comanda nu are voie să dea butonul oricum."""
    async def refuse(db, row):
        return ("⛔ Fără cale de întoarcere", False)

    monkeypatch.setattr(bot, "_verdict_de_intoarcere", refuse)
    w = World(monkeypatch)
    w.command("sistem")
    assert w.offered[0]["allow_apply"] is False
    assert "Fără cale de întoarcere" in w.offered[0]["gate_note"]


def test_no_second_lot_while_one_is_open(monkeypatch):
    """Loturile sunt tranzacții separate, care se aplică pe rând. Cât unul e deschis, un al doilea
    ar avea butoane vii peste o gazdă pe care nimeni n-a recitit-o după primul."""
    w = World(monkeypatch, db=sup.FakeDB(open_plans=[{"id": 12, "status": "validated"}]))
    sent = w.command("sistem")
    assert "#12" in sent[0] and "/patch 12" in sent[0]
    assert w.stored == [] and w.offered == []


def test_update_all_names_what_cannot_be_updated_from_here(monkeypatch):
    """`/update tot` care ar propune doar pachetele de sistem ar părea că a acoperit tot. Containerele
    și aplicațiile apar cu cifrele lor și cu motivul."""
    w = World(monkeypatch)
    text = w.command("tot")[0]
    assert "Nu se actualizează de aici" in text and "1679" in text and "140" in text
    assert len(w.stored) == 1, "«tot» nu înseamnă toate loturile deodată"


def test_a_package_argument_narrows_the_selection(monkeypatch):
    w = World(monkeypatch)
    w.command("expat")
    assert len(w.stored) == 1
    assert w.stored[0]["plan"]["update"]["scope"] == "package"
    assert [p["name"] for p in w.stored[0]["plan"]["update"]["packages"]] == ["expat"]


def test_nothing_to_propose_says_why_instead_of_staying_silent(monkeypatch):
    """Un răspuns gol ar fi citit ca «nu e nimic de făcut». Aici nu e nimic de PROPUS, iar motivul
    (nucleul e install-only) trebuie să fie în mesaj."""
    rows = [r for r in sup.finding_rows() if r["package"].startswith("kernel")]
    w = World(monkeypatch, db=sup.FakeDB(rows, scanners=[{"scanner": "dnf", "n": 10, "with_fix": 10}]))
    sent = w.command("sistem")
    assert "Nicio actualizare" in sent[0] and "install-only" in sent[0]
    assert w.stored == [] and w.offered == []


# ---------------------------------------------------------------------------
# Argumente care nu sunt ce par
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("args", [["a", "b"], ["-a"], ["--all"], ["../etc/passwd"], ["x;reboot"]])
def test_a_bad_argument_is_refused_before_anything_is_read_or_written(monkeypatch, args):
    """Argumentul ajunge, ca nume de pachet, într-o interogare `rpm`. Ce nu arată a nume de pachet
    se refuză de la început — nu se dă lui `rpm`, care l-ar citi drept flag."""
    w = World(monkeypatch)
    host_calls = []
    monkeypatch.setattr(su, "_run", lambda *a, **k: host_calls.append(a))
    sent = w.command(*args)
    assert len(sent) == 1 and ("Un singur argument" in sent[0] or "Nu am înțeles" in sent[0])
    assert w.stored == [] and w.offered == [] and host_calls == []


def test_a_selection_that_raises_is_reported_with_its_reason(monkeypatch):
    """O excepție în alegere nu se înghite: operatorul primește motivul, nu «eroare» generic."""
    async def boom(*a, **k):
        raise RuntimeError("conexiune pierdută")

    w = World(monkeypatch)
    monkeypatch.setattr(su, "select", boom)
    sent = w.command("sistem")
    assert "RuntimeError" in sent[0] and "conexiune pierdută" in sent[0]
    assert w.stored == [] and w.offered == []


def test_a_selection_error_is_said_and_proposes_nothing(monkeypatch):
    w = World(monkeypatch, host=sup.FakeHost("garbage\n"))
    sent = w.command("sistem")
    assert sent[0].startswith("⛔") and "nu propun nimic" in sent[0]
    assert w.stored == [] and w.offered == []


# ---------------------------------------------------------------------------
# patch_flow: ce vede operatorul, și poarta care rămâne
# ---------------------------------------------------------------------------
def _lot_plan(monkeypatch, *, reboot: bool = False) -> dict[str, Any]:
    if reboot:
        rows = [dict(id=1, package="glibc", cve=None, severity="high", kev=False, priority=1,
                     fixed_version="2.34-2.el9", ecosystem="rpm", asset_id=None, asset_name=None,
                     asset_protected=False, fix_pending_reboot=False)]
        host = sup.FakeHost(sup.rpm_line("glibc", "2.34-1.el9") + "\n")
        sup.install(monkeypatch, host)
        return run(su.select(sup.FakeDB(rows), sup.cfg())).lots[0].plan
    sup.install(monkeypatch, sup.FakeHost())
    return run(su.select(sup.FakeDB(), sup.cfg())).lots[0].plan


def _row(plan: dict[str, Any]) -> patch_repo.PlanRow:
    return patch_repo.PlanRow(
        id=7, plan_id=uuid.uuid4(), plan_hash="h" * 64, plan=plan, status="validated",
        risk_level=plan["risk"]["level"], requires_reboot=plan["risk"]["requires_reboot"],
        reversible=plan["risk"]["reversible"], estimated_downtime_s=0, asset_id=None,
        created_at=datetime(2026, 10, 26, tzinfo=timezone.utc), approved_by=None, approved_at=None,
        validation_errors=None)


def _stage1(monkeypatch, plan, *, drill=None):
    token_row = SimpleNamespace(stage=1, plan_id=7, plan_hash="h" * 64)
    row = _row(plan)

    async def consume(*a, **k):
        return token_row

    async def get_plan(*a, **k):
        return row

    async def summary(db):
        return drill

    async def issue(db, **kw):
        return "stage2-tok"

    monkeypatch.setattr(approvals, "consume", consume)
    monkeypatch.setattr(patch_repo, "get_plan", get_plan)
    monkeypatch.setattr(patch_repo, "latest_archive_drill_summary", summary)
    monkeypatch.setattr(approvals, "issue", issue)
    edits: list[str] = []

    async def edit(text, **kw):
        edits.append(text)

    update = SimpleNamespace(callback_query=SimpleNamespace(edit_message_text=edit),
                             effective_chat=SimpleNamespace(id=CHAT_ID))
    ctx = SimpleNamespace(bot_data={"db": object(), "cfg": sup.cfg()})
    run(patch_flow.on_stage1(update, ctx, "tok"))
    return edits


def test_the_second_screen_of_an_update_does_not_promise_a_restart(monkeypatch):
    """«Necesită REBOOT — serverul va reporni» ar fi FALS pentru un update: Sentinel nu repornește
    nimic. Operatorul care crede că serverul se repornește singur nu-l mai repornește, iar nucleul
    sau biblioteca veche rulează mai departe. Nici «Downtime estimat: 0 secunde» nu e un fapt."""
    edits = _stage1(monkeypatch, _lot_plan(monkeypatch, reboot=True))
    text = edits[-1]
    assert "va reporni" not in text
    assert "NU repornește" in text
    assert "0 secunde" not in text and "necunoscut" in text


def test_an_update_plan_that_declares_itself_irreversible_is_still_refused_at_the_first_tap(monkeypatch):
    """Fereastra de patch-uri se aplică și planurilor de update: poarta stă în `on_stage1`, pe
    drumul comun al oricărui token. Un plan cu `reversible: false` nu primește token stage-2."""
    plan = _lot_plan(monkeypatch)
    plan["risk"]["reversible"] = False
    edits = _stage1(monkeypatch, plan)
    assert any("Fără cale de întoarcere" in e for e in edits), edits


def test_the_plan_message_lists_the_packages_and_what_is_not_checked(monkeypatch):
    """Mesajul pe care se decide: ce pachete, de la ce versiune la care, și ce NU se verifică
    (serviciile). «Downtime estimat: 0s» ar spune că se știe."""
    text = patch_flow.format_plan(_row(_lot_plan(monkeypatch)))
    assert "o singură tranzacție" in text and "→" in text
    assert "Ce NU se verifică" in text and "serviciile" in text
    assert "unit_change" in text, "alertele pe care update-ul și le declanșează singur nu sunt anunțate"
    assert "Downtime estimat: <b>necunoscut</b>" in text and "<b>0s</b>" not in text
    # «Reversibil: da» ar fi mai mult decât știe planul: rollback-ul cere ca versiunile vechi să
    # mai fie în oglindă, și asta nu se vede de pe gazdă.
    assert "nedovedit" in text and "Reversibil: da" not in text


# ---------------------------------------------------------------------------
# După rulare
# ---------------------------------------------------------------------------
def _result(status: str, *, execution_id: int = 9) -> runner.RunResult:
    return runner.RunResult(status, execution_id, [], error=None if status == "succeeded" else "boom")


def _result_text(monkeypatch, plan, status, *, states=None, read_error=None, detections=None,
                 detections_error=None):
    row = _row(plan)

    async def get_plan(db, plan_id):
        return row

    async def reconcile(plan_, family):
        if isinstance(states, Exception):
            raise states
        return (states if states is not None else []), read_error

    async def detections_during(db, execution_id):
        if detections_error:
            raise RuntimeError(detections_error)
        return detections or []

    monkeypatch.setattr(patch_repo, "get_plan", get_plan)
    monkeypatch.setattr(su, "reconcile", reconcile)
    monkeypatch.setattr(su, "detections_during", detections_during)
    return run(patch_flow._result_text(object(), sup.cfg(), 7, _result(status)))


def _states(plan, state: str, *, now: str | None = None, reboot_names: tuple[str, ...] = ()):
    out = []
    for p in plan["update"]["packages"]:
        have = now or (p["target"] if state == su.STATE_TARGET else p["before"])
        out.append(su.PkgState(p["name"], p["before"], p["target"], have, state,
                               p["name"] in reboot_names))
    return out


def test_a_success_says_installed_and_never_updated(monkeypatch):
    """`rpm` dovedește că versiunea e pe disc; nu dovedește că procesele o rulează. «Actualizat» ar
    afirma exact ce nu s-a verificat. Pentru un pachet care cere repornire: «așteaptă repornire»."""
    plan = _lot_plan(monkeypatch, reboot=True)
    name = plan["update"]["packages"][0]["name"]
    text = _result_text(monkeypatch, plan, "succeeded",
                        states=_states(plan, su.STATE_TARGET, reboot_names=(name,)))
    assert "instalat" in text and "așteaptă repornire" in text.lower()
    assert "NU au fost verificate" in text, "serviciile: o propoziție, nu o tăcere"
    assert "actualizat" not in text.lower()
    assert "✅" not in text.splitlines()[0], "titlul nu are voie să promită mai mult decât spune rpm"


def test_a_success_that_rpm_does_not_confirm_is_called_out(monkeypatch):
    """«Exit 0, nimic instalat» e forma pe care depozitul ăsta a mai văzut-o. Dacă executorul și
    runnerul spun succes, iar `rpm` arată versiunea veche, operatorul trebuie să afle."""
    plan = _lot_plan(monkeypatch)
    text = _result_text(monkeypatch, plan, "succeeded", states=_states(plan, su.STATE_UNCHANGED))
    assert "rpm NU confirmă" in text and "Nu te baza pe mesajul de sus" in text


@pytest.mark.parametrize("status", ["rollback_failed", "failed", "aborted", "rolled_back"])
def test_after_a_failure_the_host_decides_what_there_is_to_restore(monkeypatch, status):
    """Cel mai frecvent eșec (oglindă picată, conflict) se întâmplă ÎNAINTE de orice schimbare, iar
    `dnf downgrade` către versiunea deja instalată iese cu cod 1 (după codul dnf, cu «No packages marked for downgrade»; citit din sursă, NEverificat pe o gazdă) — adică un «ROLLBACK-UL A EȘUAT»
    roșu pentru o mașină neatinsă. Starea citită de pe gazdă spune ce e adevărat."""
    plan = _lot_plan(monkeypatch)
    text = _result_text(monkeypatch, plan, status, states=_states(plan, su.STATE_UNCHANGED))
    assert "nu e nimic de restaurat" in text and "versiunea de dinainte" in text


def test_a_mixed_state_after_a_failure_is_not_called_clean(monkeypatch):
    plan = _lot_plan(monkeypatch)
    states = _states(plan, su.STATE_UNCHANGED)
    states[0] = su.PkgState(states[0].name, states[0].before, states[0].target, states[0].target,
                            su.STATE_TARGET, False)
    text = _result_text(monkeypatch, plan, "rollback_failed", states=states)
    assert "Stare mixtă" in text and "nu e nimic de restaurat" not in text


def test_an_unreadable_host_is_admitted_and_the_base_message_still_goes(monkeypatch):
    """Dacă starea nu se poate citi, mesajul de bază pleacă oricum, iar lipsa se spune."""
    plan = _lot_plan(monkeypatch)
    text = _result_text(monkeypatch, plan, "succeeded", states=RuntimeError("rpm: timeout"))
    assert "Nu am putut citi starea pachetelor" in text and "RuntimeError" in text
    assert "execuție #9" in text
    text2 = _result_text(monkeypatch, plan, "succeeded", states=_states(plan, su.STATE_TARGET),
                         detections_error="baza nu răspunde")
    assert "Nu am putut citi detecțiile" in text2


def test_detections_that_the_update_triggered_are_attributed_not_suppressed(monkeypatch):
    plan = _lot_plan(monkeypatch)
    text = _result_text(
        monkeypatch, plan, "succeeded", states=_states(plan, su.STATE_TARGET),
        detections=[{"rule_id": "intrusion.persistence.unit_change", "severity": "critical",
                     "processes": ["/usr/bin/python3.9"], "count": 3}])
    assert "persistence.unit_change ×3" in text and "python3.9" in text
    assert "nu le-a suprimat" in text


def test_the_result_always_fits_in_one_telegram_message(monkeypatch):
    """Un mesaj peste 4096 de caractere nu se livrează deloc, iar rezultatul unei aplicări e
    singurul lucru pe care operatorul îl așteaptă. Lista pe pachete se scurtează; concluziile nu."""
    plan = _lot_plan(monkeypatch)
    long_name = "x" * 90
    states = [su.PkgState(f"{long_name}{i}", "1.0-1", "2.0-1", "2.0-1", su.STATE_TARGET, False)
              for i in range(60)]
    text = _result_text(monkeypatch, plan, "succeeded", states=states)
    assert len(text) <= 4096
    assert "rpm confirmă" in text and "NU au fost verificate" in text


def test_an_ordinary_plan_gets_exactly_the_usual_result(monkeypatch):
    """Doar planurile de update primesc starea citită de pe gazdă; restul rămân exact cum erau."""
    plain = {"target": {"asset_name": "host"},
             "risk": {"level": "low", "requires_reboot": False, "reversible": True}}
    row = _row(plain)

    async def get_plan(db, plan_id):
        return row

    monkeypatch.setattr(patch_repo, "get_plan", get_plan)
    result = _result("succeeded")
    assert run(patch_flow._result_text(object(), sup.cfg(), 7, result)) == patch_flow.format_apply_result(result)


def test_a_plan_that_cannot_be_reread_is_admitted(monkeypatch):
    async def get_plan(db, plan_id):
        raise RuntimeError("conexiune pierdută")

    monkeypatch.setattr(patch_repo, "get_plan", get_plan)
    text = run(patch_flow._result_text(object(), sup.cfg(), 7, _result("succeeded")))
    assert "Nu am putut reciti planul" in text and "execuție #9" in text


def test_the_overview_text_never_calls_the_selection_a_guarantee():
    """Cifrele din antet sunt ce poate PROPUNE planificatorul, nu o promisiune că dnf va reuși."""
    sel = su.Selection(lots=[], held=[], error=None)
    text = update_view.overview_text(
        categories=[su.CategoryCount("os", "sistem de operare", 10, 10)], sel=sel, scanner="dnf",
        open_plans=[])
    assert "garant" not in text.lower() and "actualizat" not in text.lower().replace("de actualizat", "")


def test_a_package_with_no_finding_gets_an_explanation_not_a_blank(monkeypatch):
    """Un răspuns gol la `/update ceva` s-ar citi ca «nu e nimic de făcut». Fără o constatare nu
    există o versiune țintă de verificat, și asta se spune."""
    w = World(monkeypatch)
    sent = w.command("nu-exista-pachetul")
    assert "nu are nicio constatare deschisă" in sent[0]
    assert w.stored == [] and w.offered == []


def test_a_failed_previous_lot_is_flagged_before_anything_else(monkeypatch):
    """O comandă care propune un lot nou imediat după unul căzut arată ca o continuare firească a
    unei gazde pe care nimeni n-a recitit-o. Fereastra săptămânală se oprește definitiv la primul
    eșec; aici comanda doar avertizează (decizia opririi e a operatorului) — dar avertizează."""
    w = World(monkeypatch, db=sup.FakeDB(last_finished=[{"id": 9, "status": "rolled_back"}],
                                         scanners=[{"scanner": "dnf", "n": 1, "with_fix": 1}]))
    sent = w.command("sistem")
    assert sent[0].startswith("⚠️") and "#9" in sent[0] and "rolled_back" in sent[0]
    assert len(w.stored) == 1, "avertismentul nu oprește comanda"


def test_an_applied_previous_lot_is_not_a_warning(monkeypatch):
    w = World(monkeypatch, db=sup.FakeDB(last_finished=[{"id": 9, "status": "applied"}]))
    assert "Ultimul lot" not in w.command("sistem")[0]


def test_the_selection_text_drops_whole_lines_never_half_a_tag():
    """Un mesaj peste 4096 de caractere nu se livrează, iar o tăietură prin mijlocul unui
    `<code>` îl face ilizibil pentru Telegram. Se scot linii întregi, cu un rând care spune că
    au fost scoase."""
    held = [su.Held([f"pachet-{i:03d}-" + "x" * 40 for i in range(8)], "validator", "motiv " * 80)
            for _ in range(10)]
    text = update_view.selection_text(su.Selection(held=held), only=None)
    assert len(text) <= 4096
    assert text.count("<code>") == text.count("</code>") and text.count("<i>") == text.count("</i>")


def test_a_very_long_package_name_cannot_push_the_plan_message_over_the_limit():
    plan = {"update": {"version": 1, "scope": "system", "lot": 1, "lots": 1, "packages": [
        {"name": "n" * 300, "before": "1" * 200, "target": "2" * 200, "reboot": False, "findings": 1}
        for _ in range(12)]}}
    text = "".join(update_view.plan_lines(plan))
    assert len(text) < 3000 and "…" in text
