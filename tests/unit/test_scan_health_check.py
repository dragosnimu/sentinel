"""O scanare care eșuează trebuie să AJUNGĂ la operator.

Eșecul pe care îl previne, trăit pe 21 august 2026: operatorul s-a uitat în panou,
a văzut 31 de vulnerabilități neaplicate, a rulat `dnf update` pe server și n-a
găsit nimic de actualizat. Numărul fusese măsurat la 03:23, pachetele fuseseră
reparate la 09:14, iar scanarea de la 10:33 — cea care le-ar fi închis — eșuase cu
`timeout`.

Eșecul acela n-a ajuns nicăieri: nici pe Telegram, nici în `/selfcheck`, nici în
panou. Rândul din `scans` îl spunea, dar nimeni nu se uita acolo. Operatorul a
văzut două surse care nu erau de acord și n-a avut de unde ști care minte.

Verificarea de aici e drumul pe care eșecul ajunge la el: intră în
`selfcheck_state`, deci și în `/selfcheck` pe Telegram, și în pagina Servicii a
panoului — canalul care există tocmai fiindcă expeditorul n-are unul propriu.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.selfcheck import checks

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class _DB:
    """Întoarce rândurile cerute, sau cade — după cum cere testul.

    Ciotul nu aserteaă nimic despre SQL: `check_last_scan` prinde `Exception` în
    jurul ambelor apeluri, deci o aserțiune de aici ar fi înghițită și s-ar
    întoarce ca un `unknown` cuminte — un test care trece fără să verifice nimic.
    Interogațiile se țin minte și se aserteaă în corpul testului.
    """

    def __init__(self, rows=None, boom: str | None = None,
                 age_boom: str | None = None) -> None:
        self.rows = list(rows or [])
        self.boom = boom
        self.age_boom = age_boom
        self.fetch_sql: str | None = None
        self.fetchval_sql: list[str] = []
        self.fetchval_args: list = []

    async def fetch(self, sql, *args):
        self.fetch_sql = sql
        if self.boom:
            raise RuntimeError(self.boom)
        return self.rows

    async def fetchval(self, sql, *args):
        self.fetchval_sql.append(sql)
        self.fetchval_args.append(args)
        if self.age_boom:
            raise RuntimeError(self.age_boom)
        # `EXTRACT(EPOCH FROM (now() - $1))`, calculat față de un NOW fix.
        return (NOW - args[0]).total_seconds()


def _cfg(enabled: bool = True):
    return SimpleNamespace(scan=SimpleNamespace(enabled=enabled))


def _row(status: str, ore_in_urma: float, scanner: str = "dnf",
         error: str | None = None, findings: int = 0):
    return {"scanner": scanner, "status": status,
            "started_at": NOW - timedelta(hours=ore_in_urma),
            "finished_at": NOW - timedelta(hours=ore_in_urma),
            "error": error, "findings_count": findings}


def _row_lung(status: str, pornit_acum_ore: float, incheiat_acum_ore: float,
              scanner: str = "dnf", findings: int = 0):
    """O rulare care a ținut ore — pornită demult, încheiată recent."""
    return {"scanner": scanner, "status": status,
            "started_at": NOW - timedelta(hours=pornit_acum_ore),
            "finished_at": NOW - timedelta(hours=incheiat_acum_ore),
            "error": None, "findings_count": findings}


def _by_key(results):
    return {r.key: r for r in results}


def test_a_failed_scan_is_reported_not_swallowed() -> None:
    """Cazul din 21 august, în forma lui exactă.

    `degraded`, nu `down`: nimic de pe gazdă nu s-a oprit — colectarea și
    blocarea merg mai departe. Ce e stricat e prospețimea unei liste. „🔴 SENTINEL
    NU FUNCȚIONEAZĂ COMPLET" trebuie să însemne în continuare *nimeni nu se uită
    la serverul ăsta*.
    """
    results = run(checks.check_last_scan(
        _DB([_row("failed", 1.5, error="timeout")]), _cfg()))
    assert results, "verificarea nu a emis nicio cheie"
    r = results[0]
    assert r.status == "degraded", f"eșecul a ieșit ca {r.status}"
    assert "timeout" in r.detail, "motivul eșecului nu ajunge la operator"
    assert r.action, "operatorul nu află ce să facă"
    # Textul trebuie să spună CE se strică pentru el, nu doar că a picat ceva.
    assert "reparat" in r.detail or "deschis" in r.detail, (
        "detaliul nu spune consecința: că ce a reparat între timp apare în "
        "continuare ca deschis")


def test_a_scan_that_timed_out_counts_as_failed() -> None:
    """`timeout` e statusul cu care a căzut cea reală. Tratat ca necunoscut sau
    ca ok, chiar cazul care a produs pana ar fi trecut."""
    r = run(checks.check_last_scan(_DB([_row("timeout", 1.0)]), _cfg()))[0]
    assert r.status == "degraded"


def test_a_recent_successful_scan_is_ok() -> None:
    """Cazul obișnuit. Fără el, o reparație care face totul galben ar trece."""
    r = run(checks.check_last_scan(_DB([_row("completed", 2.0, findings=31)]),
                                   _cfg()))[0]
    assert r.status == "ok"
    assert "31" in r.detail, "numărul de constatări nu apare"


def test_a_scan_that_stopped_running_is_reported_even_without_a_failure() -> None:
    """Nicio eroare, dar nici măsurători.

    O gazdă care a scanat ultima oară acum trei zile arată, din statusuri, exact
    ca una sănătoasă: ultima rulare e `completed`. Diferența e vârsta, iar fără
    linia asta panoul ar arăta o cifră veche de zile ca și cum ar fi de azi.
    """
    r = run(checks.check_last_scan(
        _DB([_row("completed", checks.STALE_SCAN_HOURS + 5)]), _cfg()))[0]
    assert r.status == "degraded"
    assert "urm" in r.title.lower() or "urm" in r.detail.lower()


def test_the_staleness_threshold_has_slack_for_a_late_run() -> None:
    """Chiar sub prag e încă `ok`.

    Fără răgaz, o rulare întârziată de o gazdă încărcată ar aprinde alarma
    degeaba — iar o alarmă care se aprinde degeaba e una pe care operatorul
    învață s-o ignore, și atunci n-o mai vede nici pe cea adevărată.
    """
    r = run(checks.check_last_scan(
        _DB([_row("completed", checks.STALE_SCAN_HOURS - 1)]), _cfg()))[0]
    assert r.status == "ok"
    assert checks.STALE_SCAN_HOURS > 24, (
        "pragul e sub o zi, deci o scanare zilnică perfect normală ar fi mereu "
        "în întârziere")


def test_a_scan_running_right_now_is_not_a_fault_but_is_not_a_measurement() -> None:
    """`running` e purtarea normală în fereastra de scanare — și atât.

    Starea `ok` singură nu e de ajuns ca aserțiune: o rulare în curs tratată ca
    măsurătoare reușită iese TOT `ok`, dar pretinde un rezultat care nu există
    încă — „0 constatări" la o scanare care abia a pornit. Verificat prin
    falsificare: fără rândurile de mai jos, ștergerea ramurii trecea neobservată.
    """
    r = run(checks.check_last_scan(_DB([_row("running", 0.1)]), _cfg()))[0]
    assert r.status == "ok"
    assert "rulea" in r.title.lower(), (
        f"o scanare în curs e prezentată ca altceva: {r.title!r}")
    assert "constat" not in r.detail, (
        "o rulare neîncheiată raportează un număr de constatări, adică un "
        "rezultat pe care nu-l are")


def test_no_scan_at_all_is_unknown_not_ok() -> None:
    """«N-a rulat niciodată» nu e «e bine».

    Contopite, o gazdă pe care scanarea n-a pornit niciodată ar arăta verde, iar
    pagina de vulnerabilități ar fi goală și liniștitoare.
    """
    r = run(checks.check_last_scan(_DB([]), _cfg()))[0]
    assert r.status == "unknown"
    assert r.action, "nu se spune cum se pornește o scanare"


def test_a_database_that_cannot_be_read_says_so() -> None:
    """Aceeași regulă ca la restul pachetului: «nu știu» se EMITE, nu se tace.

    Runner-ul reconciliază starea după cheile emise, deci o tăcere aici ar șterge
    o constatare reală și i-ar arăta operatorului o revenire care nu s-a
    întâmplat.
    """
    results = run(checks.check_last_scan(_DB(boom="relația scans nu există"),
                                          _cfg()))
    assert results, "verificarea a tăcut când n-a putut citi"
    r = results[0]
    assert r.status == "unknown"
    assert r.key.endswith(":unreadable"), (
        "starea «nu pot spune» împarte cheia cu verdictul, deci o citire "
        "eșuată ar arăta ca o revenire")


def test_scanning_switched_off_is_not_a_fault_and_is_said_out_loud() -> None:
    """Oprită din configurație e `ok`, dar SPUS — nu prin lipsa cheii.

    Omisă, operatorul ar trebui să deducă din spațiul gol că scanarea e oprită.
    """
    r = run(checks.check_last_scan(_DB([]), _cfg(enabled=False)))[0]
    assert r.status == "ok"
    assert "oprit" in r.detail


@pytest.mark.parametrize("scanner", ["dnf", "trivy_fs"])
def test_each_scanner_gets_its_own_key(scanner: str) -> None:
    """Un `dnf` care cade contează altfel decât un `trivy` care cade.

    Sub o singură cheie, cel care se repară l-ar ascunde pe celălalt — iar
    `_reconcile_state` ar șterge constatarea celui rămas rupt.
    """
    results = run(checks.check_last_scan(
        _DB([_row("failed", 1.0, scanner="dnf", error="timeout"),
             _row("completed", 1.0, scanner="trivy_fs")]), _cfg()))
    keys = _by_key(results)
    assert f"scan:last:{scanner}" in keys, sorted(keys)
    assert keys["scan:last:dnf"].status == "degraded"
    assert keys["scan:last:trivy_fs"].status == "ok"


def test_the_newest_run_per_scanner_is_the_one_read() -> None:
    """`DISTINCT ON` alege PRIMUL rând al fiecărui scaner în ordinea dată.

    Eșecul pe care îl previne: cu `ASC`, rândul ales ar fi cea mai VECHE rulare a
    scanerului. O gazdă care a scanat acum zece minute ar apărea permanent
    „rămasă în urmă", iar un eșec de azi ar fi ascuns de o reușită de acum o
    lună — exact eșecul din 21 august, pe dos.

    Asertat în corpul testului, nu în ciot: `check_last_scan` înghite orice
    excepție din `db.fetch` și o transformă într-un `unknown` care ar trece.
    """
    db = _DB([_row("completed", 2.0)])
    run(checks.check_last_scan(db, _cfg()))
    assert db.fetch_sql is not None, "verificarea nu a interogat deloc `scans`"
    sql = " ".join(db.fetch_sql.split())
    assert "FROM scans" in sql, sql
    assert "DISTINCT ON (scanner)" in sql, sql
    assert "ORDER BY scanner, started_at DESC" in sql, (
        f"ordinea nu selectează ultima rulare a fiecărui scaner: {sql}")


def test_the_age_is_computed_in_the_database_against_a_bound_timestamptz() -> None:
    """Vârsta se măsoară cu ceasul BAZEI, iar parametrul își spune tipul.

    Două eșecuri într-unul:

    * calculată în Python, diferența dintre ceasul gazdei și cel al bazei ar
      apărea aici ca o vechime inventată — în orice sens;
    * fără `::timestamptz`, `now() - $1` are două citiri în Postgres (minus
      interval și minus timestamptz) și tipul parametrului nu se poate deduce.
      Interogația cade la pregătire, iar `except`-ul din verificare transformă
      căderea aia într-un `unknown` PERMANENT: o verificare care nu mai spune
      niciodată nimic despre prospețimea listei, fără să pară stricată.
    """
    db = _DB([_row("completed", 2.0)])
    run(checks.check_last_scan(db, _cfg()))
    assert db.fetchval_sql, "vârsta nu s-a calculat în baza de date"
    sql = " ".join(db.fetchval_sql[0].split())
    assert "now()" in sql, sql
    assert "EXTRACT(EPOCH FROM" in sql, sql
    assert "$1::timestamptz" in sql, (
        f"parametrul nu-și declară tipul, deci `now() - $1` e ambiguu: {sql}")


def test_an_age_that_cannot_be_computed_is_unknown_not_ok() -> None:
    """«Nu știu cât de veche e» nu e «e proaspătă».

    Eșecul pe care îl previne: rândul există și are un status cuminte
    (`completed`), dar calculul vârstei a căzut. Raportat `ok`, panoul ar arăta o
    cifră fără vârstă cunoscută ca și cum ar fi de azi — chiar forma pățită pe 21
    august, unde numărul era vechi și nimic nu spunea că e vechi.

    Sub cheia scanerului, nu sub alta: `unknown` și verdictul trebuie să se
    înlocuiască unul pe altul, altfel ieșirea `unknown` ar arăta pentru runner ca
    o retragere a constatării `degraded`, adică o revenire care nu s-a întâmplat.
    """
    results = run(checks.check_last_scan(
        _DB([_row("completed", 2.0)], age_boom="conexiunea a căzut"), _cfg()))
    assert results, "verificarea a tăcut când nu a putut afla vârsta"
    (r,) = results
    assert r.status == "unknown", f"o vârstă necunoscută a ieșit ca {r.status}"
    assert r.key == "scan:last:dnf", r.key


def test_no_verdict_from_this_check_is_ever_down() -> None:
    """`down` face runda `critical`, iar `critical` sare peste orele de liniște.

    Eșecul pe care îl previne: `runner._announce` pune `critical` pe orice rundă
    cu măcar un `down`, iar `telegram/quiet.passes_anyway` livrează `critical`
    prin orice fereastră de liniște. O listă de vulnerabilități învechită ar
    trezi operatorul la 3 dimineața pentru ceva ce nu se repară la 3 dimineața —
    iar o alarmă care sună degeaba e una pe care învață s-o ignore, și atunci n-o
    mai vede nici pe cea adevărată. „SENTINEL NU FUNCȚIONEAZĂ COMPLET" trebuie
    să însemne în continuare *nimeni nu se uită la serverul ăsta*.
    """
    scenarii = {
        "eșec": _DB([_row("failed", 1.0, error="timeout")]),
        "în curs": _DB([_row("running", 0.1)]),
        "proaspătă": _DB([_row("completed", 2.0)]),
        "învechită": _DB([_row("completed", checks.STALE_SCAN_HOURS + 5)]),
        "sărită": _DB([_row("skipped", 1.0)]),
        "niciuna": _DB([]),
        "baza căzută": _DB(boom="relația scans nu există"),
        "vârstă necunoscută": _DB([_row("completed", 2.0)], age_boom="căzut"),
    }
    assert len(scenarii) == 8, "lista de scenarii s-a golit; testul n-ar verifica nimic"
    for nume, db in scenarii.items():
        results = run(checks.check_last_scan(db, _cfg()))
        assert results, f"{nume}: verificarea nu a emis nicio cheie"
        for r in results:
            assert r.status != "down", (
                f"{nume}: {r.key} a ieșit `down`, deci runda devine `critical` "
                f"și trece peste orele de liniște")


def test_the_age_is_measured_from_when_the_scan_finished() -> None:
    """Cifra din panou se scrie când scanarea SE ÎNCHEIE, nu când pornește.

    Abatere declarată față de versiunea de pe gazdă din 25 august 2026, care
    măsura de la `started_at`.

    Eșecul pe care îl previne: `sentinel-scan.service` e `Type=oneshot` cu
    `TimeoutStartSec=14400`, deci o rulare poate ține ore. Măsurată de la
    pornire, o listă scrisă acum o oră de o scanare care a durat mult apare ca
    depășită — iar operatorul primește „a rămas în urmă" despre măsurătoarea cea
    mai proaspătă pe care o are. Un galben care nu corespunde la nimic e cum se
    pierde încrederea într-un panou.

    Rezerva pe `started_at` rămâne pentru rândurile fără `finished_at`; fără
    niciunul din două se cade în `unknown`, verificat mai jos.
    """
    r = run(checks.check_last_scan(
        _DB([_row_lung("completed", pornit_acum_ore=checks.STALE_SCAN_HOURS + 10,
                       incheiat_acum_ore=1.0, findings=7)]), _cfg()))[0]
    assert r.status == "ok", (
        f"o listă scrisă acum o oră e raportată ca {r.status}")
    assert "7" in r.detail


def test_a_finished_row_without_any_timestamp_is_unknown_not_fresh() -> None:
    """Fără niciun moment, vârsta nu se poate afla — și asta se SPUNE.

    Eșecul pe care îl previne: tratat ca vârstă zero, un rând fără marcaje de
    timp ar raporta o listă „proaspătă" pe care nimeni n-a datat-o niciodată.
    """
    rand = _row("completed", 2.0)
    rand["started_at"] = None
    rand["finished_at"] = None
    (r,) = run(checks.check_last_scan(_DB([rand]), _cfg()))
    assert r.status == "unknown", f"un rând fără ceas a ieșit ca {r.status}"
