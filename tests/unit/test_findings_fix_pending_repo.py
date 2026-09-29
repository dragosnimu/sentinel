"""Predicatul „reparația e instalată, dar nu rulează” și interogările lui.

Nu există un Postgres în suită, deci ce se verifică aici e forma SQL-ului, cablajul
lui și legătura cu ce SCRIE scanarea — nu execuția. Execuția a fost verificată
separat, cu un `SELECT` de citire pe gazda de producție, pe valori jsonb literale
(vezi raportul predării); testele de aici păzesc ca predicatul să nu dispară sau să
nu se rupă de formatul verdictului.

Constatarea rămâne `status = 'open'`: verdictul stă în `raw.fix_state`, iar
predicatul îl citește pentru cei care ACȚIONEAZĂ pe constatare (planificator, bot).
"""
from __future__ import annotations

import asyncio
import json
import re

from sentinel.db.repo import findings as fx
from sentinel.scan import fix_state


def run(coro):
    return asyncio.run(coro)


def _flat(sql: str) -> str:
    return " ".join(sql.split())


class _Db:
    def __init__(self, rows=()):
        self.calls: list[tuple[str, tuple]] = []
        self.rows = list(rows)

    async def fetch(self, sql, *args):
        self.calls.append((_flat(sql), args))
        return self.rows

    async def fetchrow(self, sql, *args):
        self.calls.append((_flat(sql), args))
        return None


def _walk(raw: dict, path: list[str]):
    cur = raw
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _eval_pending(expr: str, status: str, raw: dict) -> bool:
    """Evaluează predicatul în Python, DIN TEXTUL lui SQL: scoate calea jsonb și
    valoarea comparată, le aplică pe `raw`. E o mică evaluare, nu un motor SQL — dar
    e legată de textul real, deci dacă predicatul citește altă cale decât scrie
    scanarea, rezultatul iese fals."""
    m = re.search(r"raw #>> '\{([^}]*)\}' = '([^']*)'", expr)
    assert m, f"predicatul nu mai are forma `raw #>> '{{cale}}' = 'valoare'`: {expr}"
    path, want = m.group(1).split(","), m.group(2)
    return status == "open" and _walk(raw, path) == want


# --- predicatul ----------------------------------------------------------------------
def test_the_predicate_reads_the_path_the_scan_writes():
    """Predicatul citește exact cheia pe care o scrie `Verdict.as_raw` sub
    `raw.fix_state`.

    Ce se strică dacă cele două se despart (o cheie redenumită de o parte): SQL-ul
    întoarce mereu `false`, iar planificatorul redactează din nou cele cinci planuri
    `dnf update` — nicio eroare, nicio alarmă, doar comportamentul vechi înapoi.
    """
    sql = fx.pending_reboot_sql("f.")
    pending = {"advisory_line": "l",
               "fix_state": fix_state.Verdict(fix_state.PENDING, "x").as_raw()}
    other = {"fix_state": fix_state.Verdict(fix_state.NOT_PENDING, "x").as_raw()}
    unknown = {"fix_state": fix_state.Verdict(fix_state.UNKNOWN, "x").as_raw()}

    assert _eval_pending(sql, "open", pending) is True
    assert _eval_pending(sql, "open", other) is False
    assert _eval_pending(sql, "open", unknown) is False
    assert _eval_pending(sql, "open", {"advisory_line": "l"}) is False, (
        "un rând fără verdict trebuie să iasă `false`, nu NULL")


def test_the_predicate_requires_the_finding_to_be_open():
    """`raw` al unui rând rezolvat nu se rescrie: păstrează verdictul de dinaintea
    repornirii. Fără `status = 'open'` în predicat, `/planifica` pe un rând închis ar
    spune „așteaptă o repornire” — fals: dnf nu-l mai listează."""
    sql = fx.pending_reboot_sql("f.")

    assert "f.status = 'open'" in sql
    assert f"'{fx.FIX_PENDING_REBOOT}'" in sql


def test_the_predicate_never_yields_null():
    """Un rând fără `raw.fix_state` (orice constatare non-`dnf`) dă NULL la `#>>`,
    iar `AND NOT NULL` e NULL: selecția din `generate_for_kev` ar arunca tăcut
    rândul. `COALESCE(..., false)` face din „lipsă” un `false` curat."""
    sql = fx.pending_reboot_sql("f.")

    assert sql.startswith("COALESCE(") and sql.endswith(", false)")


def test_the_alias_is_applied_to_both_columns():
    """Fără alias, `status`/`raw` din interogările cu JOIN pe `assets` ar fi ambigue
    (`assets` are și el o coloană `status`)."""
    with_alias, without = fx.pending_reboot_sql("f."), fx.pending_reboot_sql()

    assert "f.status" in with_alias and "f.raw" in with_alias
    assert " f." not in without and "(status" in without


def test_the_verdict_constant_is_the_one_the_classifier_writes():
    """O singură valoare pentru „în așteptare”, în clasificator și în SQL."""
    assert fix_state.PENDING == fx.FIX_PENDING_REBOOT == "pending_reboot"


# --- cine folosește predicatul ---------------------------------------------------------
def test_get_finding_and_list_open_expose_the_flag_and_the_evidence():
    """`/planifica`, `/vuln` și `/vulnerabilitati` decid pe `fix_pending_reboot`. Un
    `SELECT` care nu-l aduce lasă botul să răspundă „nu mai e deschisă” sau „cere un
    plan” pentru un rând care așteaptă o repornire."""
    db = _Db()
    run(fx.get_finding(db, 7))
    run(fx.list_open(db, limit=5))

    (get_sql, _), (list_sql, _) = db.calls
    expr = _flat(fx.pending_reboot_sql("f."))
    assert f"{expr} AS fix_pending_reboot" in get_sql
    assert f"{expr} AS fix_pending_reboot" in list_sql
    for col in ("fix_installed", "fix_running", "fix_since"):
        assert f"AS {col}" in get_sql


def test_get_finding_no_longer_reads_resolution_as_the_marker():
    """`resolution` nu mai poartă starea: era marca lui `deferred` la varianta care
    muta constatarea. `status` rămâne neatins."""
    db = _Db()
    run(fx.get_finding(db, 7))

    (sql, _), = db.calls
    assert "f.resolution" not in sql


def test_no_query_moves_a_finding_by_status_because_of_the_verdict():
    """Constatarea rămâne `open` și numărată — decizia operatorului din 29
    septembrie 2026. Nu există funcție care să-i schimbe `status` din cauza
    verdictului; dacă cineva o adaugă, cifra „KEV deschise” scade din nou, iar
    panoul spune „2 KEV” peste un nucleu vulnerabil."""
    assert not hasattr(fx, "mark_fix_pending_reboot")
    assert not hasattr(fx, "reopen_fix_not_pending")
    assert not hasattr(fx, "PENDING_REBOOT_RESOLUTION")


# --- verdictul de ieri ------------------------------------------------------------------
def test_previous_states_are_read_by_the_scanners_own_keys():
    """Ce se strică dacă interogarea nu e mărginită la scaner și la chei: verdictul
    unui alt scaner sau al altei gazde ar fi dus înainte peste `unknown`."""
    db = _Db([{"finding_key": "k1", "status": "open",
               "fix_state": json.dumps({"state": "pending_reboot", "since": "2026-09-26"})},
              {"finding_key": "k2", "status": "resolved", "fix_state": None},
              {"finding_key": "k3", "status": "open", "fix_state": "nu e json"}])

    got = run(fx.previous_fix_states(db, "dnf", None, ["k1", "k2", "k3"]))

    (sql, args), = db.calls
    assert "scanner = $1 AND asset_id IS NOT DISTINCT FROM $2" in sql
    assert "finding_key = ANY($3::text[])" in sql
    assert args == ("dnf", None, ["k1", "k2", "k3"])
    assert got["k1"] == {"status": "open",
                         "fix_state": {"state": "pending_reboot", "since": "2026-09-26"}}
    assert got["k2"] == {"status": "resolved", "fix_state": {}}
    assert got["k3"]["fix_state"] == {}, "un jsonb ilizibil nu are voie să ridice"


def test_previous_states_accept_an_already_decoded_object():
    """Cu un codec jsonb pe conexiune, `asyncpg` întoarce dict, nu text."""
    db = _Db([{"finding_key": "k1", "status": "open",
               "fix_state": {"state": "pending_reboot"}}])

    got = run(fx.previous_fix_states(db, "dnf", None, ["k1"]))

    assert got["k1"]["fix_state"] == {"state": "pending_reboot"}


def test_no_keys_cost_no_query():
    db = _Db()

    assert run(fx.previous_fix_states(db, "dnf", None, [])) == {}
    assert db.calls == []


# --- ce așteaptă acum --------------------------------------------------------------------
def test_the_waiting_list_comes_from_the_database_through_the_predicate():
    """Mesajul și reamintirea descriu ce e în bază DUPĂ upsert, prin același predicat
    ca planificatorul — nu ce a calculat trecerea. Ce se strică altfel: un verdict
    păstrat peste un `unknown` n-ar mai apărea în reamintire, deși planificatorul îl
    ține deoparte."""
    db = _Db([{"id": 1, "finding_key": "k", "kev": True}])

    rows = run(fx.list_pending_reboot(db, "dnf", None))

    (sql, args), = db.calls
    assert _flat(fx.pending_reboot_sql("f.")) in sql
    assert "f.scanner = $1 AND f.asset_id IS NOT DISTINCT FROM $2" in sql
    assert args == ("dnf", None)
    assert rows == [{"id": 1, "finding_key": "k", "kev": True}]
