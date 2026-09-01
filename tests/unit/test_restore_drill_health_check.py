"""Un exercițiu de restaurare care n-a rulat niciodată trebuie să AJUNGĂ la operator.

Eșecul pe care îl previne: măsurat pe gazdă pe 1 septembrie 2026, „restaurari
incercate vreodata: ZERO" — trei puncte de restaurare, nicio dovadă vreodată
că vreunul se poate întoarce. `verified_at` de pe fiecare confirmă doar
fișierul tocmai scris, în aceeași secundă; nu spune nimic despre luna
următoare.

Verificarea de aici (`check_restore_drill`) e drumul pe care starea „netestat"
sau „a picat" ajunge la operator — canalul deja existent (`/selfcheck`), nu
unul nou.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from sentinel.selfcheck import checks

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class _DB:
    """Întoarce exact rândurile date lui `fetch`, indiferent de SQL.

    `live_restore_points_with_last_drill` face o singură interogare; ciotul nu
    o parsează, doar o memorează pentru asertare separată.
    """

    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.fetch_sql: str | None = None

    async def fetch(self, sql, *args):
        self.fetch_sql = sql
        return self.rows


def _point(id_=1, asset_name="blog", *, drill=True, age_days=5.0,
           succeeded=True, notes="1 artefact(e) dovedite restaurabile",
           result=None):
    row = {
        "id": id_, "asset_id": 10, "created_at": NOW - timedelta(days=90),
        "asset_name": asset_name,
        "drill_id": (100 + id_) if drill else None,
        "performed_at": (NOW - timedelta(days=age_days)) if drill else None,
        "succeeded": succeeded if drill else None,
        "notes": notes if drill else None,
        "result": json.dumps(result or {"restorable_verified": 1}) if drill else None,
        "drill_age_min": (age_days * 24 * 60) if drill else None,
    }
    return row


def _by_key(results):
    return {r.key: r for r in results}


# ---------------------------------------------------------------------------
def test_no_restore_points_at_all_is_ok_not_unknown() -> None:
    """O gazdă proaspătă, fără niciun backup încă, nu e o stare de alarmă.

    La fel ca `scan:last` cu `scan.enabled: false`: absența unui SUBIECT de
    verificat e o stare validă, nu o măsurătoare lipsă.
    """
    (r,) = run(checks.check_restore_drill(_DB([])))
    assert r.status == "ok"
    assert r.key == "restore_drill:any"
    assert "nimic de testat" in r.detail


def test_a_point_never_drilled_is_unknown_not_ok() -> None:
    """«N-a rulat niciodată» nu e «e bine».

    Cazul măsurat pe gazdă, exact: un punct de restaurare există, dar
    exercițiul automat nu a rulat niciodată pentru el.
    """
    r = run(checks.check_restore_drill(_DB([_point(drill=False)])))[0]
    assert r.status == "unknown", (
        f"un punct niciodată testat a ieșit ca {r.status}, nu «unknown»")
    assert r.action, "operatorul nu află cum să pornească exercițiul"
    assert "netestat" in r.title.lower() or "niciodată" in r.detail


def test_a_recent_successful_drill_is_ok() -> None:
    r = run(checks.check_restore_drill(_DB([_point(age_days=5.0, succeeded=True)])))[0]
    assert r.status == "ok"
    assert "restorable_verified" in str(r.facts.get("result"))


def test_a_failed_drill_is_degraded_and_names_the_reason() -> None:
    """Verdictul trebuie să spună CE anume a picat, nu doar «a picat»."""
    r = run(checks.check_restore_drill(_DB([_point(
        age_days=2.0, succeeded=False,
        notes="arhiva s-a extras curat, dar nicio sursă declarată nu apare")])))[0]
    assert r.status == "degraded"
    assert "nicio sursă declarată" in r.detail


def test_an_informational_only_point_is_never_reported_as_a_success() -> None:
    """Chiar constrângerea centrală a Funcționalității 07: un punct doar
    informativ nu iese `ok` numai fiindcă nimic n-a picat.

    `restore_drill.py` scrie `succeeded=False` pentru punctele numai
    informative — verificarea de aici trebuie doar să respecte acel boolean,
    nu să-l reinterpreteze. Falsificat mai jos prin inversarea lui `succeeded`.
    """
    r = run(checks.check_restore_drill(_DB([_point(
        age_days=1.0, succeeded=False,
        notes="punct numai informativ (rpm_state / git_ref) — nimic din el "
              "a fost extras, deci nimic din el a fost dovedit restaurabil",
        result={"informational_only": 1})])))[0]
    assert r.status != "ok", (
        "un punct numai informativ a fost raportat ca restaurare reușită")
    assert "informativ" in r.detail


def test_a_stale_successful_drill_is_degraded() -> None:
    """Timer-ul oprit de-a binelea nu are voie să pară «totul e bine» la
    nesfârșit, doar fiindcă ultima rulare REUȘITĂ a fost, cândva, reușită."""
    r = run(checks.check_restore_drill(_DB([_point(
        age_days=checks.RESTORE_DRILL_STALE_DAYS + 10, succeeded=True)])))[0]
    assert r.status == "degraded"
    assert "vechi" in r.detail.lower()


def test_the_staleness_threshold_has_slack_for_a_late_run() -> None:
    """Chiar sub prag e încă `ok` — un răgaz pentru `RandomizedDelaySec` și o
    recuperare la boot, nu o alarmă la fiecare mică întârziere."""
    r = run(checks.check_restore_drill(_DB([_point(
        age_days=checks.RESTORE_DRILL_STALE_DAYS - 1, succeeded=True)])))[0]
    assert r.status == "ok"
    assert checks.RESTORE_DRILL_STALE_DAYS > 30, (
        "pragul e sub o lună, deci un exercițiu lunar perfect normal ar fi "
        "mereu raportat «învechit»")


def test_each_restore_point_gets_its_own_key() -> None:
    """Un punct stricat nu are voie să-l ascundă pe cel bun de lângă el."""
    results = run(checks.check_restore_drill(_DB([
        _point(id_=1, asset_name="blog", succeeded=True),
        _point(id_=2, asset_name="crm", succeeded=False,
              notes="checksum greșit"),
    ])))
    keys = _by_key(results)
    assert "restore_drill:1" in keys and "restore_drill:2" in keys, sorted(keys)
    assert keys["restore_drill:1"].status == "ok"
    assert keys["restore_drill:2"].status == "degraded"


def test_no_verdict_from_this_check_is_ever_down() -> None:
    """`down` face runda `critical`, deci trece peste orele de liniște. Un
    backup netestat sau un exercițiu picat e o problemă serioasă, dar nu de
    genul care se repară la 3 dimineața."""
    scenarii = {
        "gol": _DB([]),
        "netestat": _DB([_point(drill=False)]),
        "picat": _DB([_point(succeeded=False, notes="coruptă")]),
        "învechit": _DB([_point(age_days=checks.RESTORE_DRILL_STALE_DAYS + 20,
                                succeeded=True)]),
        "reușit": _DB([_point(succeeded=True)]),
    }
    for nume, db in scenarii.items():
        for r in run(checks.check_restore_drill(db)):
            assert r.status != "down", (
                f"{nume}: {r.key} a ieșit `down`, deci runda devine `critical`")


def test_the_query_reads_only_live_restore_points_with_their_last_automated_drill() -> None:
    """Interogarea trebuie să aducă punctele VII, ultimul lor drill AUTOMAT, și
    vârsta lui calculată în bază — nu în Python, cu ceasul gazdei care rulează
    verificarea."""
    db = _DB([_point()])
    run(checks.check_restore_drill(db))
    assert db.fetch_sql is not None, "verificarea nu a interogat deloc baza"
    sql = " ".join(db.fetch_sql.split())
    assert "restore_points" in sql
    assert "deleted_at IS NULL" in sql
    assert "d.automated" in sql
    assert "now() - ld.performed_at" in sql
