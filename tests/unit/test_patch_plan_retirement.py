"""Retragerea planurilor de patch a căror constatare s-a rezolvat.

Eșecul pe care îl previne fișierul ăsta, spus pe scaunul operatorului: a scos
pachetul de pe server pe 25 septembrie, Sentinel a văzut (constatarea a devenit
`resolved`), dar planul #10 a rămas `validated`. Patru zile la rând fereastra de
reparare l-a oferit, autoverificarea l-a raportat din patru în patru ore ca
`patch_window:plan:10`, iar la apăsarea butonului operatorul primea un mesaj
despre ireversibilitate — adevărat, dar nu motivul pentru care planul nu trebuia
să mai existe.

Cauza: ciclul de viață al planului era decuplat de al constatării. Repararea
(`patches.retire_moot_plans`, pasul orar `maintenance_service.retire_plans`)
retrage un plan doar când TOATE constatările lui sunt rezolvate — și doar atât.
Partea cu adevărat periculoasă e cealaltă direcție: un predicat care retrage prea
mult ar scoate din ofertă planurile #12 și #13 (kernel-core, kernel-devel), care
sunt reale și instalate.

De aceea majoritatea testelor de mai jos rulează SQL-ul REAL al funcției, peste
SQLite, pe rânduri concrete — nu caută subșiruri în text. Un test pe text trece
și peste un predicat care a devenit o tautologie (vezi antetul lui
`test_patch_window_repo.py`, runda 2).

Ce NU are simularea SQLite față de PostgreSQL, și de ce e sigur:

  * tablourile: `finding_ids` e `bigint[]` în PostgreSQL, JSON text aici;
    `unnest`/`cardinality` sunt traduse în `json_each`/`json_array_length`.
    Traducerea refuză (`_ca_sqlite`) dacă în text rămâne vreo sintaxă
    PostgreSQL netradusă, deci nu poate deveni tăcut oarbă;
  * `IS DISTINCT FROM` devine `IS NOT` — aceeași semantică pe NULL, care e
    exact cazul care contează aici (findingul lipsă);
  * declanșatorul `updated_at` și tranzacțiile reale nu există. Sintaxa
    UPDATE ... RETURNING cu subinterogare corelată peste `unnest` a fost în
    schimb verificată pe PostgreSQL-ul de producție cu `EXPLAIN` (fără
    execuție), iar `SELECT`-ul cu același predicat a întors exact planul #10.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.db.repo import patches as repo
from sentinel.services import maintenance_service as ms

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = REPO_ROOT / "sentinel" / "db" / "migrations"


def run(c):
    return asyncio.run(c)


def _valorile_check(migratie: str, tabela: str) -> tuple[str, ...]:
    """Valorile pe care baza le acceptă pentru `status`, citite din CHECK-ul
    migrației — nu scrise aici, ca un status nou să intre în parametrizare fără
    ca cineva să-și amintească s-o completeze."""
    sql = (MIGRATIONS / migratie).read_text(encoding="utf-8")
    start = sql.index(f"CREATE TABLE {tabela}")
    m = re.search(r"CHECK \(status IN \((.*?)\)\)", sql[start:], re.S)
    assert m, f"n-am găsit CHECK-ul de status al lui {tabela} în {migratie}"
    return tuple(re.findall(r"'([a-z_]+)'", m.group(1)))


STATUSURI_PLAN = _valorile_check("0004_patch.sql", "patch_plans")
STATUSURI_FINDING = _valorile_check("0003_vuln.sql", "findings")

# Un parametrizat golit tăcut ar trece verde fără să verifice nimic — exact
# defectul pe care CLAUDE.md îl numește. Numărul e fixat, deci o schimbare a
# schemei strică testul și cere o clasificare conștientă.
assert "validated" in STATUSURI_PLAN and len(STATUSURI_PLAN) == 11, STATUSURI_PLAN
assert "resolved" in STATUSURI_FINDING and len(STATUSURI_FINDING) == 7, STATUSURI_FINDING

PLANURI_ALTELE_DECAT_VALIDATED = tuple(s for s in STATUSURI_PLAN if s != "validated")
FINDINGURI_NEREZOLVATE = tuple(s for s in STATUSURI_FINDING if s != "resolved")


# ---------------------------------------------------------------------------
# SQLite în locul PostgreSQL — vezi antetul modulului
# ---------------------------------------------------------------------------
class _SqliteDB:
    """`fetch` peste SQLite, cu SQL-ul REAL al funcției testate."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, status TEXT, cve TEXT, "
            "package TEXT, resolved_at TEXT)")
        self.conn.execute(
            "CREATE TABLE patch_plans (id INTEGER PRIMARY KEY, status TEXT, "
            "finding_ids TEXT, rejected_by TEXT, rejected_reason TEXT, "
            "generated_by TEXT, proposed_by_window INTEGER, created_at TEXT)")
        self.sql: list[str] = []

    def finding(self, fid, status, cve="CVE-2026-0001", package="pkg",
                resolved_at="2026-09-25T09:03:00+00:00"):
        self.conn.execute("INSERT INTO findings VALUES (?,?,?,?,?)",
                          (fid, status, cve, package, resolved_at))

    def plan(self, pid, status, finding_ids, *, generated_by="ai",
             created_at="2026-09-25T10:00:00+00:00"):
        self.conn.execute(
            "INSERT INTO patch_plans (id, status, finding_ids, generated_by, "
            "proposed_by_window, created_at) VALUES (?,?,?,?,0,?)",
            (pid, status, json.dumps(finding_ids), generated_by, created_at))

    def status_of(self, pid):
        return self.conn.execute(
            "SELECT status FROM patch_plans WHERE id = ?", (pid,)).fetchone()[0]

    def statusuri(self):
        return {r[0]: r[1] for r in self.conn.execute("SELECT id, status FROM patch_plans")}

    @staticmethod
    def _ca_sqlite(sql: str) -> str:
        out = (sql
               .replace("cardinality(finding_ids)", "json_array_length(finding_ids)")
               .replace("unnest(patch_plans.finding_ids) AS fid",
                        "json_each(patch_plans.finding_ids) AS fid")
               .replace("ON f.id = fid", "ON f.id = fid.value")
               .replace("IS DISTINCT FROM", "IS NOT")
               .replace("= ANY($1::bigint[])", "IN (SELECT value FROM json_each($1))"))
        out = re.sub(r"\$\d+", "?", out)
        # Refuz zgomotos, nu potrivire pe nimic: dacă interogarea reală capătă
        # o sintaxă PostgreSQL nouă, testul trebuie să spună că traducerea e
        # depășită, nu să treacă pe un text pe care nu-l mai rulează nimeni.
        for ramas in ("unnest(", "cardinality(", "DISTINCT FROM", "ANY(", "::"):
            if ramas in out:
                raise AssertionError(
                    f"sintaxă PostgreSQL netradusă ({ramas!r}) — actualizează "
                    f"`_SqliteDB._ca_sqlite`: {out!r}")
        return out

    async def fetch(self, sql, *args):
        self.sql.append(sql)
        params = [json.dumps(a) if isinstance(a, list) else a for a in args]
        rows = self.conn.execute(self._ca_sqlite(sql), params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("finding_ids"), str):
                d["finding_ids"] = json.loads(d["finding_ids"])
            if isinstance(d.get("resolved_at"), str):
                d["resolved_at"] = datetime.fromisoformat(d["resolved_at"])
            out.append(d)
        return out


def _ids(retrase):
    return sorted(p["id"] for p in retrase)


# ===========================================================================
# Ce se retrage
# ===========================================================================
def test_plan_whose_only_finding_is_resolved_is_retired_and_says_why():
    """Cazul planului #10. Fără el: planul rămâne oferit și raportat până la
    plafonul de 30 de zile de vârstă (25 octombrie), adică încă vreo patru
    săptămâni de alarme pentru ceva terminat. Verifică și MOTIVUL de pe rând —
    „expirat după 72 de ore" și „expirat fiindcă nu mai era nimic de reparat"
    trebuie să se deosebească în panoul extern, care afișează
    `rejected_reason` lângă status."""
    db = _SqliteDB()
    db.finding(38989, "resolved", cve="CVE-2026-3909", package="webkit2gtk3-jsc")
    db.plan(10, "validated", [38989])

    retrase = run(repo.retire_moot_plans(db))

    assert _ids(retrase) == [10]
    assert db.status_of(10) == "expired"
    row = db.conn.execute(
        "SELECT rejected_by, rejected_reason FROM patch_plans WHERE id = 10").fetchone()
    assert row["rejected_by"] == repo.RETIRED_BY, dict(row)
    assert "rezolvate" in row["rejected_reason"], dict(row)
    # Ce primește apelantul ca să poată spune operatorului CE a retras.
    f = retrase[0]["findings"]
    assert [(x["cve"], x["package"]) for x in f] == [("CVE-2026-3909", "webkit2gtk3-jsc")]
    assert f[0]["resolved_at"].year == 2026


def test_plans_whose_finding_is_still_open_are_untouched():
    """Planurile #12 și #13 de pe gazdă (kernel-core, kernel-devel): findingul e
    `open`, pachetele sunt instalate, planurile sunt reale. Un predicat prea
    larg le-ar scoate din ofertă exact când operatorul le are de făcut — și ar
    face din retragere o pagubă, nu o curățenie. Planul #10, rezolvat, e pus
    alături ca testul să nu treacă printr-o retragere care nu face nimic."""
    db = _SqliteDB()
    db.finding(38989, "resolved", package="webkit2gtk3-jsc")
    db.finding(41761, "open", cve="CVE-2025-39964", package="kernel-core")
    db.finding(41867, "open", cve="CVE-2025-39964", package="kernel-devel")
    db.plan(10, "validated", [38989])
    db.plan(12, "validated", [41761])
    db.plan(13, "validated", [41867])

    retrase = run(repo.retire_moot_plans(db))

    assert _ids(retrase) == [10]
    assert db.statusuri() == {10: "expired", 12: "validated", 13: "validated"}


def test_a_plan_with_one_resolved_and_one_open_finding_stays():
    """Planul cu mai multe CVE-uri se retrage doar când TOATE sunt rezolvate.
    Cu „măcar unul rezolvat", un plan care încă repară o vulnerabilitate
    deschisă ar dispărea de sub ochii operatorului din cauza alteia."""
    db = _SqliteDB()
    db.finding(1, "resolved")
    db.finding(2, "open")
    db.plan(20, "validated", [1, 2])

    assert run(repo.retire_moot_plans(db)) == []
    assert db.status_of(20) == "validated"


def test_a_plan_with_all_of_several_findings_resolved_is_retired():
    """Reversul testului de mai sus, fără de care predicatul ar putea refuza
    orice plan cu mai mult de un finding și testul parțial ar rămâne verde."""
    db = _SqliteDB()
    db.finding(1, "resolved", package="a")
    db.finding(2, "resolved", package="b")
    db.plan(21, "validated", [1, 2])

    retrase = run(repo.retire_moot_plans(db))

    assert _ids(retrase) == [21]
    assert db.status_of(21) == "expired"
    assert sorted(x["package"] for x in retrase[0]["findings"]) == ["a", "b"]


def test_a_plan_pointing_at_a_finding_that_no_longer_exists_stays():
    """Măsurat pe gazdă: planurile #2 și #3 au ids (16108, 16110) care nu mai
    sunt în `findings`. „Nu găsesc findingul" nu e „findingul e rezolvat" — un
    `JOIN` obișnuit în locul lui `LEFT JOIN` ar face ca rândul lipsă să nu
    conteze deloc, iar planul ar fi retras fără nicio dovadă. Aici planul are
    și un finding rezolvat, ca să se vadă că lipsa singură ajunge să-l țină."""
    db = _SqliteDB()
    db.finding(1, "resolved")
    db.plan(30, "validated", [1, 999999])
    db.plan(31, "validated", [999999])

    assert run(repo.retire_moot_plans(db)) == []
    assert db.statusuri() == {30: "validated", 31: "validated"}


def test_a_plan_with_no_findings_at_all_stays():
    """`NOT EXISTS` peste zero rânduri e adevărat, deci un plan scris fără
    findinguri ar părea „cu toate constatările rezolvate" și ar fi retras. Nu
    are nicio dovadă că ceva s-a rezolvat; rămâne cum era."""
    db = _SqliteDB()
    db.plan(40, "validated", [])

    assert run(repo.retire_moot_plans(db)) == []
    assert db.status_of(40) == "validated"


@pytest.mark.parametrize("status", PLANURI_ALTELE_DECAT_VALIDATED)
def test_only_validated_plans_are_ever_retired(status):
    """Un plan aprobat, programat, în aplicare, aplicat, eșuat sau respins are
    un om sau o execuție în spate; a-i schimba statusul de sub ele ar fi o
    decizie luată fără cei care o așteaptă. Rulat pentru FIECARE status pe care
    schema îl admite (citite din CHECK), cu findingul rezolvat, ca singurul
    motiv pentru care rămâne neatins să fie statusul."""
    db = _SqliteDB()
    db.finding(1, "resolved")
    db.plan(50, status, [1])

    assert run(repo.retire_moot_plans(db)) == []
    assert db.status_of(50) == status


@pytest.mark.parametrize("status", FINDINGURI_NEREZOLVATE)
def test_only_the_resolved_finding_status_counts(status):
    """Un finding amânat, acceptat ca risc, fals-pozitiv, în curs de patch sau
    doar planificat e o DECIZIE a cuiva sau o stare în mișcare, nu o rezolvare
    observată de scaner. Doar `resolved` retrage un plan; restul îl lasă.
    Parametrizat pe fiecare status de finding din schemă."""
    db = _SqliteDB()
    db.finding(1, status)
    db.plan(60, "validated", [1])

    assert run(repo.retire_moot_plans(db)) == []
    assert db.status_of(60) == "validated"


def test_retiring_twice_changes_nothing_the_second_time():
    """Pasul rulează orar. Al doilea apel nu are voie să retragă din nou (și să
    anunțe din nou) un plan deja retras — altfel operatorul ar primi același
    mesaj în fiecare oră."""
    db = _SqliteDB()
    db.finding(1, "resolved")
    db.plan(70, "validated", [1])

    assert _ids(run(repo.retire_moot_plans(db))) == [70]
    assert run(repo.retire_moot_plans(db)) == []


def test_a_reopened_finding_does_not_bring_the_retired_plan_back():
    """Un pachet reinstalat redeschide findingul. Planul vechi a fost scris
    pentru versiunile, calea de rollback și backup-ul de atunci; învierea lui ar
    oferi butoane de aprobare pe fapte vechi. Rămâne `expired`, iar starea lui
    e MOARTĂ pentru `live_plan_for_finding` / `generate_for_kev`, deci findingul
    poate primi un plan proaspăt. Ultima jumătate e ce se strică dacă cineva
    schimbă `RETIRED_STATUS` într-un status viu: findingul redeschis ar rămâne
    fără plan pentru totdeauna."""
    db = _SqliteDB()
    db.finding(1, "resolved")
    db.plan(80, "validated", [1])
    run(repo.retire_moot_plans(db))

    db.conn.execute("UPDATE findings SET status = 'open' WHERE id = 1")

    assert run(repo.retire_moot_plans(db)) == []
    assert db.status_of(80) == "expired"
    assert repo.RETIRED_STATUS not in repo.LIVE_PLAN_STATUSES, repo.LIVE_PLAN_STATUSES


def test_the_retired_status_is_one_the_schema_accepts():
    """`UPDATE ... SET status = 'expired'` cade cu o încălcare de CHECK dacă
    valoarea nu e în `0004_patch.sql` — și pasul orar ar eșua în fiecare oră pe
    producție, cu SQLite-ul din testele de mai sus perfect mulțumit (nu are
    CHECK-ul). Citit din migrație, nu presupus."""
    assert repo.RETIRED_STATUS in STATUSURI_PLAN, (repo.RETIRED_STATUS, STATUSURI_PLAN)
    assert repo.RETIRED_STATUS != "validated"


def test_a_retired_plan_leaves_the_windows_candidate_pool():
    """Efectul pe care îl vede operatorul: planul #10 nu mai e candidat al
    ferestrei, deci `patch_window:plan:10` dispare din autoverificare (iar
    rândul ei `degraded` iese ca «nu se mai raportează»), în timp ce #12 rămâne.
    Rulat pe clauza REALĂ a `window_candidate_plans`, nu doar pe statusul scris
    în bază — un plan poate fi `expired` și tot să fie oferit dacă un alt loc îl
    citește altfel."""
    db = _SqliteDB()
    db.finding(38989, "resolved")
    db.finding(41761, "open")
    db.plan(10, "validated", [38989])
    db.plan(12, "validated", [41761])
    run(repo.retire_moot_plans(db))

    class _Cap:
        sql = ""

        async def fetch(self, sql, *a):
            self.sql = sql
            return []

    cap = _Cap()
    run(repo.window_candidate_plans(cap))
    where = cap.sql.split("WHERE", 1)[1]
    where = (where.replace("now() - make_interval(days => $1)", "?")
                  .replace("$2", "?"))
    rows = db.conn.execute(
        "SELECT id FROM patch_plans WHERE " + where,
        ("2026-01-01T00:00:00+00:00", 10)).fetchall()
    assert [r[0] for r in rows] == [12], [r[0] for r in rows]


# ===========================================================================
# Serviciul: retragerea și anunțul, într-o singură tranzacție
# ===========================================================================
class _Conn:
    def __init__(self, *, retrase=None, gasite=None, cade_inserarea=False):
        self.sql: list[str] = []
        self.args: list[tuple] = []
        self.retrase = retrase if retrase is not None else []
        self.gasite = gasite if gasite is not None else []
        self.cade_inserarea = cade_inserarea

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        self.args.append(a)
        if "UPDATE patch_plans" in sql:
            return self.retrase
        if "FROM findings" in sql:
            return self.gasite
        return []

    async def execute(self, sql, *a):
        self.sql.append(sql)
        self.args.append(a)
        if self.cade_inserarea and "INSERT INTO notifications" in sql:
            raise RuntimeError("baza a refuzat inserarea")
        return "INSERT 0 1"


class _TxDB:
    """Orice instrucțiune trimisă pe `db` în loc de pe conexiunea tranzacției
    e o eroare: exact asta ar însemna retragere și anunț în tranzacții
    diferite, adică un plan care dispare fără nicio urmă dacă al doilea pas
    cade."""

    def __init__(self, conn: _Conn):
        self.conn = conn
        self.tranzactii = 0
        self.iesire_cu_eroare: BaseException | None = None

    @contextlib.asynccontextmanager
    async def transaction(self):
        self.tranzactii += 1
        try:
            yield self.conn
        except BaseException as exc:
            self.iesire_cu_eroare = exc
            raise

    async def fetch(self, sql, *a):
        raise AssertionError(f"instrucțiune în afara tranzacției: {sql!r}")

    fetchrow = fetchval = execute = fetch


def _un_plan_retras(pid=10, fid=38989):
    return ([{"id": pid, "finding_ids": [fid]}],
            [{"id": fid, "cve": "CVE-2026-3909", "package": "webkit2gtk3-jsc",
              "resolved_at": datetime(2026, 9, 25, 9, 3, tzinfo=timezone.utc)}])


def test_retirement_and_notice_share_one_transaction_and_retire_comes_first():
    """Un plan retras fără anunț dispare din `/patches` fără nicio urmă pentru
    un om care îl avea pe ecran; un anunț scris ÎNAINTEA retragerii promite
    ceva ce încă nu s-a făcut. Ambele instrucțiuni trebuie să meargă pe
    conexiunea aceleiași tranzacții, în ordinea asta."""
    retrase, gasite = _un_plan_retras()
    conn = _Conn(retrase=retrase, gasite=gasite)
    db = _TxDB(conn)

    detail, facts = run(ms.retire_plans(db))

    assert db.tranzactii == 1
    i_update = next(i for i, s in enumerate(conn.sql) if "UPDATE patch_plans" in s)
    i_insert = next(i for i, s in enumerate(conn.sql) if "INSERT INTO notifications" in s)
    assert i_update < i_insert, conn.sql
    assert facts == {"retired": 1, "plan_ids": [10]}
    assert "#10" in detail


def test_a_failed_notice_fails_the_step_instead_of_reporting_success():
    """Dacă inserarea anunțului cade, pasul trebuie să EȘUEZE (excepția iese din
    tranzacție, deci retragerea se anulează cu ea) — nu să raporteze «1 plan
    retras» peste un plan pe care operatorul n-a fost anunțat. Excepția care
    trece prin `_step` devine un pas eșuat în raportul orei, iar unitatea iese
    nenul."""
    retrase, gasite = _un_plan_retras()
    db = _TxDB(_Conn(retrase=retrase, gasite=gasite, cade_inserarea=True))

    with pytest.raises(RuntimeError, match="refuzat"):
        run(ms.retire_plans(db))
    assert isinstance(db.iesire_cu_eroare, RuntimeError), (
        "excepția n-a ieșit prin tranzacție — rollback-ul n-ar avea loc")

    rep = ms.Report()
    run(ms._step(rep, "retire_plans", ms.retire_plans(
        _TxDB(_Conn(retrase=retrase, gasite=gasite, cade_inserarea=True)))))
    assert [s.name for s in rep.failed] == ["retire_plans"]


def test_nothing_to_retire_writes_no_notice():
    """O trecere care n-a retras nimic nu trimite nimic: altfel operatorul ar
    primi un mesaj „0 planuri retrase" în fiecare oră."""
    conn = _Conn()
    db = _TxDB(conn)

    detail, facts = run(ms.retire_plans(db))

    assert facts == {"retired": 0, "plan_ids": []}
    assert not any("INSERT INTO notifications" in s for s in conn.sql), conn.sql
    assert "niciun plan" in detail


def test_the_notice_says_what_was_retired_why_and_that_the_server_is_untouched():
    """Fără CE și DE CE, mesajul e o alarmă fără conținut; fără «pe server nu
    s-a schimbat nimic», «plan retras» se poate citi ca «plan aplicat». Textul
    NU pretinde cum s-a rezolvat constatarea (scanerul știe doar că nu o mai
    vede), și e trimis ca `low`, ținut de fereastra de liniște, cu un fel
    propriu — nu implicitul `selfcheck`."""
    retrase, gasite = _un_plan_retras()
    conn = _Conn(retrase=retrase, gasite=gasite)
    run(ms.retire_plans(_TxDB(conn)))

    i = next(i for i, s in enumerate(conn.sql) if "INSERT INTO notifications" in s)
    kind, dedup, title, body = conn.args[i]
    assert kind == ms.RETIRED_NOTICE_KIND
    assert "'low'" in conn.sql[i]
    assert dedup == "patches:retired:10"
    assert title == "Planuri de patch retrase"
    for needed in ("#10", "webkit2gtk3-jsc", "CVE-2026-3909", "2026-09-25",
                   "Pe server nu s-a schimbat nimic", "nu o a doua problemă"):
        assert needed in body, (needed, body)
    for claimed in ("dezinstalat", "scos de pe server", "actualizat la"):
        assert claimed not in body, f"mesajul pretinde o cauză necunoscută: {claimed}"


def test_the_notice_escapes_what_the_scanner_wrote():
    """Numele pachetului și CVE-ul vin de la un scaner, iar mesajul e trimis ca
    HTML: un `<` neescapat face Telegram să refuze mesajul întreg, adică plan
    retras, operator neanunțat, și trei încercări eșuate de trimitere."""
    title, body = ms._retirement_notice([{
        "id": 5, "finding_ids": [1],
        "findings": [{"id": 1, "cve": "CVE-1<b>", "package": "a<script>&b",
                      "resolved_at": None}]}])
    assert "<script>" not in body and "a&lt;script&gt;&amp;b" in body, body
    assert "CVE-1&lt;b&gt;" in body, body


def test_a_large_backlog_is_one_message_that_counts_the_rest():
    """Prima trecere de după livrare poate găsi o restanță. Un mesaj per plan ar
    fi zgomotul din care operatorul a învățat să nu mai citească; un mesaj care
    listează toate ar depăși ce se poate citi. Se enumeră un număr fix, iar
    restul se NUMĂRĂ — nu se ascunde."""
    n = ms.RETIRED_NOTICE_MAX_LISTED + 2
    retrase = [{"id": 100 + i, "finding_ids": [i],
                "findings": [{"id": i, "cve": f"CVE-{i}", "package": f"p{i}",
                              "resolved_at": None}]} for i in range(n)]
    _, body = ms._retirement_notice(retrase)
    assert body.count("• #") == ms.RETIRED_NOTICE_MAX_LISTED, body
    assert "și încă 2" in body, body
    assert f"#{100 + n - 1}" not in body


def test_the_step_actually_runs_in_the_hourly_pass(monkeypatch):
    """Eșecul prevenit: funcția există, e testată, și nu o chemă nimeni — starea
    în care a stat `expire_stale_plans` până pe 15 septembrie 2026. Verificat pe
    RULAREA reală (`ms.run`), nu pe prezența unui nume în sursă."""
    from sentinel.db.repo import patches as patch_repo

    chemari: list = []

    async def _retrage(db):
        chemari.append(db)
        return [{"id": 10, "finding_ids": [1],
                 "findings": [{"id": 1, "cve": "C", "package": "p",
                               "resolved_at": None}]}]

    async def _fara_retea(db):
        return "sărit în test", {}

    monkeypatch.setattr(patch_repo, "retire_moot_plans", _retrage)
    monkeypatch.setattr(ms, "refresh_intel", _fara_retea)

    conn = _Conn()
    rep = run(ms.run(_TxDB(conn), _cfg()))

    assert chemari, "nimeni n-a chemat retragerea planurilor în trecerea orară"
    pasi = [s for s in rep.steps if s.name == "retire_plans"]
    assert len(pasi) == 1, [s.name for s in rep.steps]
    assert pasi[0].ok and pasi[0].facts["plan_ids"] == [10], pasi[0]


def _cfg():
    from types import SimpleNamespace
    r = SimpleNamespace(raw_events_days=30, rollup_1m_days=90, rollup_1h_days=400,
                        health_samples_days=30, disk_guard_free_pct=15)
    return SimpleNamespace(retention=r,
                           patch=SimpleNamespace(retention_count=10, retention_days=30))
