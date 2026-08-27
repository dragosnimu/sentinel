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
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
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

    `age_boom_after` spune CÂTE citiri de vârstă reușesc înainte de cădere. E
    nevoie de el fiindcă o rundă poate citi vârsta de două ori — o dată pentru
    rândul blocat, o dată pentru ultimul rezultat real pe care îl ascunde — iar
    un ciot care le doboară pe amândouă iese mai devreme, pe `unknown`, și lasă
    a doua ramură netestată. Zero păstrează purtarea dinainte: cade de la prima.
    """

    def __init__(self, rows=None, boom: str | None = None,
                 age_boom: str | None = None, age_boom_after: int = 0) -> None:
        self.rows = list(rows or [])
        self.boom = boom
        self.age_boom = age_boom
        self.age_boom_after = age_boom_after
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
        if self.age_boom and len(self.fetchval_sql) > self.age_boom_after:
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


def _rand_running(pornit_acum_ore: float, scanner: str = "dnf",
                  scan_id: int = 41, *, ultima_incheiata_acum_ore: float | None = None,
                  ultima_constatari: int = 0):
    """Un rând `running`, cu sau fără o rulare încheiată în urma lui.

    `finished_at` e NULL prin construcție — un rând deschis de `start_scan` nu-l
    are, iar un test care i-ar pune unul n-ar semăna cu nimic din bază.

    Coloanele `ok_*` sunt cele pe care `_LAST_SCAN_SQL` le aduce din `LEFT JOIN
    LATERAL`: ultimul rând `completed` al aceluiași scaner. `None` peste tot
    înseamnă că scanerul n-a încheiat niciodată o rulare.
    """
    ok_ts = (None if ultima_incheiata_acum_ore is None
             else NOW - timedelta(hours=ultima_incheiata_acum_ore))
    return {"id": scan_id, "scanner": scanner, "status": "running",
            "started_at": NOW - timedelta(hours=pornit_acum_ore),
            "finished_at": None, "error": None, "findings_count": 0,
            "ok_started_at": ok_ts, "ok_finished_at": ok_ts,
            "ok_findings_count": None if ok_ts is None else ultima_constatari}


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
        "în curs": _DB([_rand_running(0.1)]),
        "blocată": _DB([_rand_running(checks.STUCK_SCAN_HOURS + 100,
                                      ultima_incheiata_acum_ore=26.0,
                                      ultima_constatari=31)]),
        "blocată, fără nicio încheiere": _DB([
            _rand_running(checks.STUCK_SCAN_HOURS + 100)]),
        "în curs, vârstă necunoscută": _DB([_rand_running(0.1)], age_boom="căzut"),
        "proaspătă": _DB([_row("completed", 2.0)]),
        "învechită": _DB([_row("completed", checks.STALE_SCAN_HOURS + 5)]),
        "niciuna": _DB([]),
        "baza căzută": _DB(boom="relația scans nu există"),
        "vârstă necunoscută": _DB([_row("completed", 2.0)], age_boom="căzut"),
    }
    assert len(scenarii) == 10, "lista de scenarii s-a golit; testul n-ar verifica nimic"
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


# ---------------------------------------------------------------------------
# Un rând rămas `running` — raportat `ok` la nesfârșit până pe 26 august 2026
# ---------------------------------------------------------------------------
def test_a_run_still_inside_the_systemd_timeout_is_not_called_stuck() -> None:
    """O scanare care chiar rulează nu are voie să fie numită „blocată".

    Eșecul pe care îl previne: `sentinel-scan.service` are
    `TimeoutStartSec=14400`, deci o rulare de ore e purtare NORMALĂ. Un prag prea
    strâns ar aprinde galbenul pe fiecare noapte în care scanarea ține mult — iar
    o alarmă care sună degeaba e una pe care operatorul învață s-o ignore, și
    atunci n-o mai vede nici pe cea adevărată.
    """
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(checks.STUCK_SCAN_HOURS - 0.5)]), _cfg()))
    assert r.status == "ok", f"o scanare încă în viață e raportată ca {r.status}"
    assert "rulea" in r.title.lower(), r.title
    assert "constat" not in r.detail, (
        "o rulare neîncheiată raportează un număr de constatări, adică un "
        "rezultat pe care nu-l are")


def test_a_run_stuck_in_running_stops_being_reported_ok() -> None:
    """Un rând `running` care nu se va încheia NICIODATĂ.

    Eșecul pe care îl previne, citit din cod pe 26 august 2026: ramura `running`
    întorcea `ok` fără să se uite vreodată la vârstă, deci un rând rămas acolo ar
    fi ieșit «ok | Scanarea „dnf” rulează acum» oricât de vechi. `finish_scan` rulează
    doar în proces, deci un SIGKILL de la systemd după `TimeoutStartSec`, un OOM
    sub `MemoryMax=1G` sau o repornire la mijloc lasă rândul acolo pentru
    totdeauna și nimic nu-l curăță. Verde pe vecie peste o scanare care nu mai
    rulează de trei luni: operatorul crede că lista de vulnerabilități se
    împrospătează în fiecare noapte.

    Cifra de 2160 de ore de mai jos e scenariul testului, nu o observație de pe
    gazdă: acolo, pe 26 august 2026, erau 0 rânduri `running`. Ce se dovedește
    aici e purtarea codului la o vechime aleasă, nu că vechimea aia a existat.

    A doua tăcere pe care o previne: sfatul trebuie să poarte `id`-ul rândului.
    Un `UPDATE ... WHERE id=<id>` pe care operatorul trebuie să-l completeze
    singur, dintr-un mesaj de Telegram, e un sfat pe care ori îl sare, ori îl
    completează cu rândul greșit — și rândul greșit se închide ca „întrerupt".
    """
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(2160.0, scan_id=8123)]), _cfg()))
    assert r.status == "degraded", f"un rând mort de 90 de zile a ieșit ca {r.status}"
    assert "rulează acum" not in r.detail, (
        "verificarea încă spune despre un proces mort că rulează acum")
    assert r.action, "operatorul nu află ce să facă"
    assert "WHERE id=8123;" in r.action, (
        f"sfatul nu numește rândul concret, deci operatorul ar trebui să-l caute "
        f"el printre rândurile din `scans`, la ora la care primește alerta: "
        f"{r.action!r}")
    assert r.facts.get("scan_id") == 8123, r.facts


def test_a_stuck_run_whose_last_result_has_an_unreadable_age_does_not_claim_it_is_fresh() -> None:
    """A treia stare din `_last_completed_phrase`: există, dar nu-i știu vârsta.

    Eșecul pe care îl previne: rândul blocat ascunde ultima rulare încheiată, iar
    dacă a doua citire a vârstei cade, singurul răspuns onest e „nu știu din când
    e cifra din panou". Umplută cu «e de acum atât» — sau cu o vârstă de zero —
    constatarea l-ar liniști pe operator exact despre lucrul pentru care există:
    că se uită la o cifră veche. „Nu știu" și „e proaspătă" sunt stări diferite.

    Ramura asta n-a fost atinsă de niciun test până acum: ciotul dobora AMÂNDOUĂ
    citirile de vârstă, deci verificarea ieșea mai devreme, pe `unknown`, și
    ramura de aici putea fi înlocuită cu orice minciună fără ca suita s-o simtă.
    De-aia `age_boom_after=1`: prima citire (vârsta rândului blocat) reușește, a
    doua (vârsta ultimului rezultat real) cade.
    """
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(2160.0, ultima_incheiata_acum_ore=26.0,
                           ultima_constatari=31)],
            age_boom="conexiunea a căzut", age_boom_after=1), _cfg()))
    assert r.status == "degraded", (
        f"a ieșit ca {r.status}; dacă e `unknown`, ciotul a doborât și prima "
        f"citire a vârstei, deci ramura vizată nici n-a fost atinsă")
    assert "nu i-am putut citi vârsta" in r.detail, (
        f"nu se spune că vârsta ultimului rezultat real e necunoscută: {r.detail!r}")
    assert "last_completed_age_h" not in r.facts, (
        f"se raportează o vârstă pentru un rezultat a cărui vârstă tocmai n-a "
        f"putut fi citită: {r.facts}")
    assert r.facts.get("last_completed_findings") == 31, (
        f"numărul de constatări se știe din rând și nu are de ce să se piardă "
        f"odată cu vârsta: {r.facts}")
    assert "0 constatări" not in r.detail, (
        f"se inventează «0 constatări» peste o rulare care a găsit 31: {r.detail!r}")


def test_a_stuck_run_names_both_the_stall_and_the_result_it_is_hiding() -> None:
    """Două tăceri, nu una — și amândouă trebuie rupte.

    Eșecul pe care îl previne: `_LAST_SCAN_SQL` alege rândul cel mai nou per
    scaner, deci rândul blocat UMBREȘTE ultima rulare încheiată. Operatorul se
    uită la un panou unde numărul de vulnerabilități e vechi de o zi și jumătate
    și nimic nu i-o spune. O constatare care spune doar «scanarea e blocată»
    repară tăcerea despre scanare și o lasă întreagă pe cea despre cifră: el ar
    citi în continuare 31 ca și cum ar fi de azi.
    """
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(2160.0, ultima_incheiata_acum_ore=26.0,
                           ultima_constatari=31)]), _cfg()))
    assert r.status == "degraded"
    # Faptul 1: de când stă rândul acolo. 2160 h = 90 de zile.
    assert "90z" in r.detail, f"nu se spune de când e blocată: {r.detail!r}"
    # Faptul 2: din când e cifra pe care o vede în panou, și care e ea.
    assert "1z 2h" in r.detail, (
        f"nu se spune din când e ultimul rezultat real: {r.detail!r}")
    assert "31" in r.detail, (
        f"nu se spune câte constatări are ultimul rezultat real: {r.detail!r}")
    assert r.facts.get("last_completed_findings") == 31, r.facts


def test_a_stuck_run_with_no_completed_run_ever_says_so_instead_of_inventing_one() -> None:
    """„Nu există niciun rezultat" și „rezultatul e vechi" sunt lucruri diferite.

    Eșecul pe care îl previne: pe o gazdă unde scanerul n-a dus niciodată o rulare
    până la capăt, un mesaj care ar tăcea despre asta — sau, mai rău, ar spune „0
    constatări" — l-ar liniști pe operator cu o măsurătoare care nu s-a făcut
    niciodată. Exact perechea de stări pe care le confundă un instrument de
    monitorizare când colapsează «nu știu» în «e bine».
    """
    (r,) = run(checks.check_last_scan(_DB([_rand_running(2160.0)]), _cfg()))
    assert r.status == "degraded"
    assert "nu există nicio rulare încheiată" in r.detail, (
        f"lipsa oricărui rezultat real nu e spusă: {r.detail!r}")
    assert "0 constatări" not in r.detail, (
        "se raportează «0 constatări» pentru un scaner care n-a încheiat "
        "niciodată o rulare")
    assert r.facts.get("last_completed", "lipsă") is None, r.facts


def test_a_running_row_whose_age_cannot_be_read_is_unknown_not_ok() -> None:
    """Fără vârstă nu pot deosebi „rulează acum" de „a murit acum trei luni".

    Eșecul pe care îl previne: căderea calculului vârstei readuce exact vechea
    purtare — `ok`, pentru totdeauna, pe un rând mort. „Nu știu" se EMITE, sub
    cheia scanerului, ca să înlocuiască verdictul; sub altă cheie, runner-ul ar
    citi ieșirea ca pe o retragere a constatării, adică o revenire care nu s-a
    întâmplat.
    """
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(0.1)], age_boom="conexiunea a căzut"), _cfg()))
    assert r.status == "unknown", f"o vârstă necunoscută a ieșit ca {r.status}"
    assert r.key == "scan:last:dnf", r.key


def _timeout_start_sec() -> int:
    """`TimeoutStartSec` al unității de scanare, în secunde.

    Citit din fișierul unității, nu dintr-o copie a numărului: o copie ar putea
    diverge exact ca numărul pe care îl păzește.
    """
    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-scan.service").read_text(encoding="utf-8")
    valori = re.findall(r"^TimeoutStartSec=(\S+)\s*$", unit, re.MULTILINE)
    assert len(valori) == 1, (
        f"{len(valori)} linii `TimeoutStartSec=` în sentinel-scan.service; "
        f"testul nu poate ști care e cea care contează")
    brut = valori[0]
    assert brut.isdigit(), (
        f"`TimeoutStartSec={brut}` nu mai e în secunde simple; învață testul "
        f"formatul systemd (`4h`, `90s`, ...) înainte să treacă mai departe")
    return int(brut)


#: Cât peste `TimeoutStartSec` are voie să stea pragul de „blocată".
#:
#: E o DECIZIE, nu un calcul, și e luată aici la două ore. Constanta din
#: `checks` e construită ca `TimeoutStartSec` plus o oră — marja de oprire
#: (SIGTERM, apoi `TimeoutStopSec`, apoi SIGKILL) și diferența dintre ceasul
#: gazdei și cel al bazei. Plafonul lasă marja aia să fie dublată fără să se
#: atingă testul, fiindcă e o mărime pe care o poți estima greșit cu o oră; și
#: refuză orice e de alt ordin de mărime, fiindcă peste două ore lucrul acela nu
#: mai e o marjă de oprire, ci altă decizie — și una care se ia pe față, nu se
#: strecoară într-o constantă.
#:
#: Alternativa evidentă, `== TimeoutStartSec + 3600`, ar fi o copie a derivării
#: din `checks` mutată în test: ar pica la orice reglaj legitim de un sfert de
#: oră și n-ar spune nimic în plus.
_MARJA_MAXIMA_S = 2 * 3600


def test_the_stuck_threshold_stays_between_the_systemd_timeout_and_a_bounded_margin() -> None:
    """Pragul e derivat din unitate; dacă unitatea se mută, pragul se mută cu ea.

    Eșecul de jos: cineva urcă `TimeoutStartSec` fiindcă scanările au început să
    dureze mai mult, `STUCK_SCAN_HOURS` rămâne pe loc, și verificarea începe să
    strige „blocată" peste scanări care chiar rulează. Galbenul acela nu
    corespunde la nimic, iar operatorul învață să treacă peste el.

    Eșecul de sus, care trecea până acum: legătura era doar în jos. Cu
    `STUCK_SCAN_HOURS = 50` — o cifră pe care o scrie oricine gândește „mai
    lasă-i loc" — pragul devine două zile, toată suita rămâne verde, iar un rând
    mort de o zi și jumătate iese `ok` cu textul «rulează acum». Adică fix
    defectul pe care fișierul ăsta îl repară, doar mai lent: panoul arată o cifră
    de alaltăieri ca proaspătă, iar autodiagnosticul spune că totul e bine.

    Marja admisă e o decizie, argumentată la `_MARJA_MAXIMA_S`.
    """
    brut = _timeout_start_sec()
    prag_s = checks.STUCK_SCAN_HOURS * 3600

    assert prag_s > brut, (
        f"STUCK_SCAN_HOURS={checks.STUCK_SCAN_HOURS} ({prag_s}s) nu mai e peste "
        f"TimeoutStartSec={brut}s, deci verificarea numește «blocată» o scanare "
        f"pe care systemd încă o lasă să ruleze")
    assert prag_s <= brut + _MARJA_MAXIMA_S, (
        f"STUCK_SCAN_HOURS={checks.STUCK_SCAN_HOURS} ({prag_s}s) e cu "
        f"{prag_s - brut}s peste TimeoutStartSec={brut}s, adică peste marja de "
        f"oprire admisă ({_MARJA_MAXIMA_S}s). Systemd a omorât deja procesul, "
        f"deci în tot intervalul ăla un rând care nu se va încheia NICIODATĂ e "
        f"raportat «rulează acum», iar cifra din panou pare proaspătă")


def test_a_row_older_than_any_permitted_threshold_is_stuck_whatever_the_constant_says() -> None:
    """Pragul se aplică în ore — verificat pe purtare, nu pe valoarea constantei.

    Eșecul pe care îl previne: `age_s <= STUCK_SCAN_HOURS * 3600 * 24`, o eroare
    de unități pe o singură linie și cu atât mai ușor de scris cu cât `* 3600` e
    deja acolo. `STUCK_SCAN_HOURS` rămâne 5, deci invariantul de deasupra trece
    liniștit, iar pragul REAL devine cinci zile: un rând `running` de 105 ore iese
    `ok`, cu «rulează acum». Operatorul citește un panou vechi de patru zile ca
    pe unul de azi, iar `/selfcheck` îi confirmă că e verde.

    Vârsta de aici e derivată din UNITATE plus marja maximă admisă, nu din
    `STUCK_SCAN_HOURS`: un scenariu scris relativ la constantă se mută odată cu
    ea, și de-aia n-a prins nici constanta umflată, nici greșeala de unități.
    """
    prea_vechi_ore = (_timeout_start_sec() + _MARJA_MAXIMA_S) / 3600 + 0.5
    (r,) = run(checks.check_last_scan(
        _DB([_rand_running(prea_vechi_ore)]), _cfg()))
    assert r.status == "degraded", (
        f"un rând `running` de {prea_vechi_ore} ore — peste orice prag pe care "
        f"invariantul îl admite — a ieșit ca {r.status}")
    assert "rulează acum" not in r.detail, (
        f"se spune despre un rând pe care systemd l-a omorât demult că rulează "
        f"acum: {r.detail!r}")


def test_the_query_also_reads_the_last_completed_run_per_scanner() -> None:
    """Fără al doilea rând, constatarea n-ar avea ce spune despre cifra din panou.

    Eșecul pe care îl previne: `DISTINCT ON` singur întoarce rândul blocat și
    atât. Mesajul ar putea spune că scanarea e blocată, dar nu din când e ultimul
    rezultat real — iar aia e chiar informația care lipsea operatorului.

    `LEFT JOIN`, nu `JOIN`: un scaner fără nicio rulare încheiată trebuie să
    rămână în rezultat, cu `ok_*` NULL. Scos din listă, cheia lui n-ar mai fi
    emisă, iar `_reconcile_state` ar citi tăcerea ca pe o revenire.

    Asertat în corpul testului, nu în ciot: `check_last_scan` înghite orice
    excepție din `db.fetch` și ar întoarce un `unknown` cuminte.
    """
    db = _DB([_row("completed", 2.0)])
    run(checks.check_last_scan(db, _cfg()))
    assert db.fetch_sql is not None, "verificarea nu a interogat deloc `scans`"
    sql = " ".join(db.fetch_sql.split())
    assert "LEFT JOIN LATERAL" in sql, (
        f"nu se citește a doua oară tabela, deci ultimul rezultat real e "
        f"necunoscut: {sql}")
    assert "c.status = 'completed'" in sql, (
        f"al doilea rând nu e filtrat pe rulări încheiate, deci «ultimul rezultat "
        f"real» ar putea fi tot rândul blocat: {sql}")
    assert "ok_findings_count" in sql and "ok_finished_at" in sql, sql
