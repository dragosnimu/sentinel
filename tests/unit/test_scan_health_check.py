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
    """Întoarce rândurile cerute, sau cade — după cum cere testul."""

    def __init__(self, rows=None, boom: str | None = None) -> None:
        self.rows = list(rows or [])
        self.boom = boom

    async def fetch(self, sql, *args):
        if self.boom:
            raise RuntimeError(self.boom)
        assert "FROM scans" in sql, sql
        return self.rows

    async def fetchval(self, sql, *args):
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
