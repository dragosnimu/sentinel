"""Planificatorul nu redactează un plan pentru o reparație deja instalată.

Eșecul prevenit, în termeni de operator: constatarea rămâne `open` (și numărată ca
KEV — decizia din 29 septembrie 2026), deci `generate_for_kev`, care alege pe
`status = 'open'`, ar redacta iar cele cinci planuri `dnf -y update kernel*` la care
`dnf` răspunde „Nothing to do.". Fiecare plan pică poarta de reversibilitate, iar
autoverificarea îl raportează din patru în patru ore — exact ce a ținut operatorul
patru zile.

Interogarea din `generate_for_kev` e EXECUTATĂ aici pe SQLite, cu textul ei real (calea
jsonb tradusă mecanic), pe rânduri concrete: nu doar „conține cuvântul”, ci „rândul în
așteptare nu iese, cel neinstalat iese, iar cel fără verdict iese”.
"""
from __future__ import annotations

import asyncio
import json
import re
import sqlite3

from sentinel.config import Config
from sentinel.db.repo import findings as fx
from sentinel.patch import planner
from sentinel.scan import fix_state

ECOSISTEM = planner.OS_PACKAGE_ECOSYSTEM["rhel"]


def run(c):
    return asyncio.run(c)


def _cfg():
    cfg = Config()
    cfg.platform.family = "rhel"
    return cfg


class _CaptureDB:
    def __init__(self, rows=()):
        self.sql: str | None = None
        self.rows = list(rows)

    async def fetch(self, sql, *a):
        self.sql = sql
        return self.rows


def _to_sqlite(sql: str) -> str:
    """Aceeași traducere mecanică ca în `test_patch_planner_kev._translate`."""
    needle = "f.id = ANY(p.finding_ids)"
    assert needle in sql
    sql = re.sub(r"(\w+\.raw) #>> '\{([^}]*)\}'",
                 lambda m: f"json_extract({m.group(1)}, '$.{m.group(2).replace(',', '.')}')",
                 sql)
    return (sql.replace(needle, "f.id = p.finding_id")
               .replace("$1", "?").replace("$2", "?"))


def _verdict(state: str) -> str:
    return json.dumps({"advisory_line": "l",
                       "fix_state": fix_state.Verdict(state, "x").as_raw()})


def _selected(rows, *, limit=3) -> list[int]:
    """Ce alege `generate_for_kev` dintre `rows` = (id, status, priority, raw)."""
    db = _CaptureDB()
    run(planner.generate_for_kev(db, cfg=_cfg(), api_key="sk-test", limit=limit))
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE findings (id INTEGER, status TEXT, kev INTEGER, "
                 "fixed_version TEXT, priority INTEGER, ecosystem TEXT, raw TEXT)")
    conn.execute("CREATE TABLE patch_plans (finding_id INTEGER, status TEXT)")
    conn.executemany("INSERT INTO findings VALUES (?, ?, 1, '1.2.3', ?, ?, ?)",
                     [(i, st, pr, ECOSISTEM, raw) for i, st, pr, raw in rows])
    return [r[0] for r in conn.execute(_to_sqlite(db.sql), (ECOSISTEM, limit))]


def test_a_pending_kev_is_not_drafted_and_one_that_is_not_pending_is():
    """Rândurile în așteptare nu ies din selecție, cele neinstalate da — cu control
    pozitiv: fără al doilea, „nu iese nimic” ar putea veni dintr-o interogare stricată."""
    got = _selected([(1, "open", 90, _verdict(fix_state.PENDING)),
                     (2, "open", 80, _verdict(fix_state.NOT_PENDING))])

    assert got == [2]


def test_the_pending_rows_do_not_eat_the_slots_of_the_pass():
    """Rândurile în așteptare sunt KEV, deci primele după prioritate. Dacă ar fi
    filtrate DUPĂ `LIMIT`, cele trei sloturi ale trecerii s-ar consuma pe ele, iar
    bucla n-ar mai redacta niciodată un plan pentru un KEV cu reparația neinstalată —
    aceeași capcană pe care o descrie docstring-ul pentru ecosisteme."""
    pending = [(i, "open", 100 - i, _verdict(fix_state.PENDING)) for i in range(1, 6)]
    real = (9, "open", 10, _verdict(fix_state.NOT_PENDING))

    got = _selected(pending + [real], limit=3)

    assert got == [9]


def test_a_row_without_a_verdict_is_still_drafted():
    """Un rând fără `raw.fix_state` (orice constatare non-`dnf`, sau `raw` NULL, sau
    scrisă înaintea mecanismului) trebuie să rămână planificabil: „nu se știe că
    așteaptă” nu e „așteaptă”. Fără `COALESCE` în predicat, `NOT NULL` ar arunca tăcut
    rândul, iar bucla n-ar mai redacta nimic pentru nicio constatare fără verdict."""
    got = _selected([(1, "open", 90, None),
                     (2, "open", 80, json.dumps({"advisory_line": "l"})),
                     (3, "open", 70, _verdict(fix_state.UNKNOWN))])

    assert got == [1, 2, 3]


def test_a_finding_that_is_not_open_is_never_selected_whatever_its_verdict():
    """Rezolvat sau decis de om: `status = 'open'` rămâne poarta întâi."""
    got = _selected([(1, "resolved", 90, _verdict(fix_state.NOT_PENDING)),
                     (2, "accepted_risk", 80, None)])

    assert got == []


# --- generate(): refuzul pentru oricine ajunge la el ------------------------------------------
class _CtxDB:
    """`_context` citește un singur rând; restul nu trebuie atins înainte de refuz."""

    def __init__(self, row):
        self.row = row
        self.sql: list[str] = []

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        return self.row

    async def fetch(self, sql, *a):
        raise AssertionError("generate() a interogat baza după ce trebuia să refuze")

    async def fetchval(self, sql, *a):
        raise AssertionError("generate() a interogat baza după ce trebuia să refuze")


def _ctx_row(**over):
    row = {"id": 7, "cve": "CVE-2025-39964", "title": "t", "severity": "high",
           "cvss": None, "epss": None, "kev": True, "priority": 90,
           "package": "kernel-core", "installed_version": None,
           "fixed_version": "5.14.0-687.51.1.el9_8", "ecosystem": "rpm",
           "scanner": "dnf", "location": None, "fix_pending_reboot": False,
           "asset_id": None, "asset_name": None, "asset_kind": None,
           "systemd_unit": None, "container_id": None, "stack": None,
           "criticality": 3, "is_internet_exposed": False, "protected": False,
           "vhost_file": None, "webroot": None}
    row.update(over)
    return row


def test_generate_refuses_a_pending_finding_before_any_model_or_budget_call(monkeypatch):
    """`/planifica` (dacă botul a ratat ramura lui, sau scanarea a schimbat verdictul între
    verificare și apel) și bucla KEV ajung amândouă aici. Refuzul spune motivul adevărat și
    nu costă niciun apel: nici `budget.allowed`, nici modelul.

    Ce se strică dacă garda dispare: un apel Opus plătit pentru un plan `dnf update` fără
    nimic de instalat, respins de poarta de reversibilitate.
    """
    async def boom(*a, **k):
        raise AssertionError("s-a plătit ceva pentru o constatare fără nimic de aplicat")

    monkeypatch.setattr(planner.budget, "allowed", boom)
    monkeypatch.setattr(planner, "call_structured", boom)
    db = _CtxDB(_ctx_row(fix_pending_reboot=True))

    plan_id, reason = run(planner.generate(db, _cfg(), "sk-test", 7))

    assert plan_id is None
    assert reason == fix_state.PENDING_EXPLANATION_RO
    assert "repornire" in reason and "nu mai e deschisă" not in reason


def test_generate_does_not_refuse_a_finding_that_is_not_pending(monkeypatch):
    """Reversul, fără de care garda ar putea refuza tot și testele ar rămâne verzi: un
    rând care NU așteaptă trece de ea și ajunge la verificările următoare."""
    db = _CtxDB(_ctx_row(fix_pending_reboot=False, fixed_version=None))

    plan_id, reason = run(planner.generate(db, _cfg(), "sk-test", 7))

    assert plan_id is None
    assert reason == "nu se cunoaște o versiune care repară — nu există ce aplica"


def test_the_context_query_reads_the_pending_flag_through_the_shared_predicate():
    """Un `_context` care nu aduce indicatorul lasă garda de mai sus fără date: ar citi
    mereu `None` și nu ar refuza niciodată — fără nicio eroare."""
    db = _CtxDB(None)

    run(planner._context(db, 7))

    (sql,) = db.sql
    assert " ".join(fx.pending_reboot_sql("f.").split()) in " ".join(sql.split())
    assert "AS fix_pending_reboot" in sql
