"""Autodiagnostic: nucleul își aruncă înregistrările de audit?

Eșecul pe care îl previne, și de ce e o categorie proprie de minciună:

De la 24 august 2026 istoricul de comenzi atârnă de auditd — fiecare `execve`
dintr-o sesiune cu login. Măsurat pe gazdă, **~630 de înregistrări pentru o
singură logare interactivă** și **~405 000 pentru un deploy**, într-o rafală de
două minute.

Când tamponul nucleului se umple, înregistrările se ARUNCĂ. O înregistrare
aruncată nu produce nicio eroare și niciun rând lipsă vizibil — produce un
istoric mai scurt decât realitatea, exact în minutul aglomerat în care cineva
lucrează repede. Adică minutul care contează.

E chiar tiparul din `CLAUDE.md`, în forma lui cea mai curată: **absența unui
semnal citită ca absența unui eveniment.**
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel.selfcheck import checks


def run(coro):
    return asyncio.run(coro)


def _cu_status(monkeypatch, status: dict[str, int] | None) -> None:
    monkeypatch.setattr(checks, "_auditctl_status", lambda: status)


SANATOS = {"enabled": 1, "lost": 0, "backlog": 0, "backlog_limit": 8192}


def test_no_loss_reads_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _cu_status(monkeypatch, SANATOS)
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "ok"
    assert r.facts["lost"] == 0


def test_a_single_lost_record_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pragul e ZERO, dinadins.

    `lost` e cumulativ de la pornirea lui auditd, iar orice creștere înseamnă
    istoric pierdut definitiv. Un prag mai mare ar spune «puțin istoric lipsă e
    în regulă» — dar un istoric cu goluri arată exact ca unul complet, deci n-ai
    cum să afli cât lipsește.
    """
    _cu_status(monkeypatch, {**SANATOS, "lost": 1})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "degraded"
    assert "1" in r.detail
    assert r.facts["lost"] == 1


def test_a_half_full_buffer_warns_before_anything_is_lost(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Avertismentul dinaintea faptului.

    `backlog` mare fără pierderi înseamnă că următoarea rafală le va produce. Un
    deploy e ~405 000 de înregistrări în două minute; avertizat la jumătate, mai e
    timp să se lărgească tamponul.
    """
    _cu_status(monkeypatch, {**SANATOS, "backlog": 4096})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "degraded"
    assert "4096" in r.detail


def test_a_quarter_full_buffer_is_still_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garda celuilalt sens: un tampon care lucrează nu e un tampon care cade.

    Fără ea, testul de mai sus ar trece și pentru o versiune care raportează
    `degraded` la orice ocupare — iar o verificare permanent roșie e una pe care
    operatorul o învață să o ignore.
    """
    _cu_status(monkeypatch, {**SANATOS, "backlog": 1024})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "ok"


def test_an_unreadable_status_is_unknown_not_ok(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """«Nu știu dacă s-a pierdut ceva» nu e «nu s-a pierdut nimic».

    Runner-ul reconciliază starea după cheile emise, deci o tăcere aici ar ȘTERGE
    o constatare reală și ar arăta o revenire care nu s-a întâmplat. Aceeași
    lecție ca la `check_last_scan`.
    """
    _cu_status(monkeypatch, None)
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "unknown"
    assert "nu" in r.detail.lower()


def test_a_missing_backlog_limit_does_not_divide_by_zero(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """O ieșire de `auditctl` fără `backlog_limit` există: versiuni mai vechi.

    Împărțit la zero, autodiagnosticul ar cădea — iar o verificare care cade nu
    raportează `unknown`, ci dispare din listă, ceea ce runner-ul citește ca
    „nu mai există problema".
    """
    _cu_status(monkeypatch, {"lost": 0, "backlog": 0})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "ok"


def test_the_check_is_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    """O verificare scrisă și neînregistrată nu rulează niciodată.

    Trece toate testele de mai sus și nu se uită nimeni la ea — cea mai liniștită
    formă de acoperire care nu există.
    """
    assert any(name == "audit" for name, _ in checks.CHECKS)


class _ExecutorCiot:
    """Un executor care răspunde exact ca gazda reală, la nivelul lui `call`.

    `ExecutorClient.call` întoarce dicționarul OPERAȚIEI, luat din
    `response["result"]`. Transportul și operația au fiecare `ok`-ul lor, iar
    `executor/sentinel_executor.py` pune `ok: True` pe TRANSPORT chiar și când
    `op_audit_status` a întors `{"ok": False, "error": ...}` — o comandă rulată
    care a răspuns „nu pot" e o cerere onorată, nu una refuzată. Deci răspunsul
    ajunge aici fără nicio excepție, cu `ok` fals înăuntru.
    """

    def __init__(self, raspuns: dict) -> None:
        self.raspuns = raspuns

    def __call__(self, *a, **k):  # ExecutorClient() — instanțierea
        return self

    def audit_status(self) -> dict:
        return self.raspuns


def _cu_executor(monkeypatch, raspuns: dict) -> None:
    from sentinel.respond import executor_client

    monkeypatch.setattr(executor_client, "ExecutorClient", _ExecutorCiot(raspuns))


def test_an_auditctl_that_refused_is_unknown_not_zero_losses(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """`auditctl: Operation not permitted` nu înseamnă «nicio pierdere».

    Eșecul pe care îl previne: operația răspunde `{"ok": False, "error": ...}`,
    dar transportul răspunde `ok: True`, deci nu se ridică nicio excepție și
    dicționarul ajunge întreg la apelant. Fără garda pe `ok`-ul operației,
    `.get("lost", 0)` îl citește ca zero, iar operatorul vede „Înregistrările de
    audit — nicio înregistrare pierdută" pe o gazdă unde nimeni nu poate citi
    contorul. Istoricul de comenzi atârnă de contorul ăsta, deci ar avea goluri
    fără ca nimic să spună — chiar acoperirea care nu există.

    Măsurat pe cod înainte de test: ștergerea gărzii trecea toate cele 11 teste
    de aici.
    """
    _cu_executor(monkeypatch, {"ok": False, "error": "Operation not permitted"})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "unknown", (
        f"un `auditctl` care a refuzat a ieșit ca {r.status}: {r.detail!r}")
    assert r.facts.get("lost") is None, (
        "se raportează un număr de pierderi care n-a fost citit de nicăieri")


def test_a_reply_the_operation_disowned_is_never_read_as_a_measurement(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Când operația spune `ok: false`, câmpurile ei NU sunt o măsurătoare.

    Eșecul pe care îl previne: `op_audit_status` și-a dezis răspunsul, dar
    transportul l-a livrat cu `ok: True` al lui, deci nu se ridică nicio
    excepție. Citite oricum, cifrele dintr-un răspuns dezis ies ca
    „Înregistrările de audit — nicio înregistrare pierdută": verde, pe o gazdă
    unde nimeni n-a putut citi contorul.

    De ce e nevoie de testul ăsta pe lângă cele două de mai sus: forma de eroare
    pe care `op_audit_status` o produce AZI n-are niciun număr în ea, deci `or
    None` de la finalul lui `_auditctl_status` o prinde din întâmplare. Asta e o
    coincidență a formei de azi, nu o regulă — măsurat: cu `or None` pe loc,
    ștergerea gărzii pe `ok` NU pică niciun test. Răspunsul de mai jos e ales
    tocmai ca să despartă cele două gărzi: dezis și totuși plin de cifre.
    """
    _cu_executor(monkeypatch, {"ok": False,
                               "error": "auditctl: Operation not permitted",
                               "lost": 0, "backlog": 0, "backlog_limit": 8192})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "unknown", (
        f"cifrele dintr-un răspuns dezis au fost citite ca măsurătoare, "
        f"ieșind {r.status}: {r.detail!r}")
    assert r.facts.get("lost") is None, (
        "se raportează `lost` dintr-un răspuns pe care operația l-a dezis")


def test_a_reply_without_any_counter_is_unknown_not_ok(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Un răspuns cu `ok` și fără niciun contor e un răspuns neînțeles.

    Redus la un dicționar gol, apelantul îl citește prin `.get("lost", 0)` drept
    „zero pierderi" și raportează verde — același schimb ca mai sus, pe alt
    drum. `None` îl duce în `unknown`, care e ce s-a întâmplat de fapt.
    """
    _cu_executor(monkeypatch, {"ok": True})
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "unknown", (
        f"un răspuns fără niciun contor a ieșit ca {r.status}: {r.detail!r}")


class _ExecutorCareCade(_ExecutorCiot):
    """Un executor al cărui socket dispare între instanțiere și răspuns."""

    def audit_status(self) -> dict:
        raise OSError("socket-ul executorului a dispărut")


def test_a_socket_error_while_reading_is_unknown_not_a_crash(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Un `OSError` din citire se raportează, nu propagă.

    Eșecul pe care îl previne: propagată, excepția scoate tot GRUPUL din rulare.
    Runner-ul tratează o rulare incompletă corect — nu reconciliază nimic —, dar
    rezultatul e că verificarea nu mai spune NIMIC despre auditd cât ține
    defecțiunea, iar operatorul vede o listă din care lipsește o linie, nu un
    `unknown` care să-i atragă atenția. „Nu am putut citi" e o stare care se
    EMITE.

    `ExecutorClient.call` împăchetează azi erorile de socket în
    `ExecutorUnavailable`, deci calea asta e o plasă, nu drumul obișnuit — dar o
    plasă pe care n-o vezi ținând nu e o plasă.
    """
    from sentinel.respond import executor_client

    monkeypatch.setattr(executor_client, "ExecutorClient", _ExecutorCareCade({}))
    (r,) = run(checks.check_audit_records(None, None))
    assert r.status == "unknown"
    assert r.key == "audit:records"


def test_the_key_is_the_one_production_already_carries(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheia e `audit:records`, în toate cele patru ieșiri.

    Eșecul pe care îl previne: `selfcheck_state` ține istoricul pe CHEIE, iar
    panoul extern la fel. O redenumire nu se vede ca o eroare — se vede ca o
    constatare nouă fără trecut, lângă una veche pe care runner-ul o retrage
    fiindcă rularea n-a mai emis-o. Continuitatea verificării se pierde tăcut,
    iar „de când" și „de câte ori" devin de azi.

    Toate patru sub o singură cheie, dinadins: două chei ar face ca ieșirea
    `unknown` să arate ca o revenire a celei `degraded`.
    """
    chei = set()
    for stare in (SANATOS, {**SANATOS, "lost": 1}, {**SANATOS, "backlog": 4096}):
        _cu_status(monkeypatch, stare)
        (r,) = run(checks.check_audit_records(None, None))
        chei.add(r.key)
    _cu_status(monkeypatch, None)
    (r,) = run(checks.check_audit_records(None, None))
    chei.add(r.key)
    assert chei == {"audit:records"}, sorted(chei)


def test_the_blocking_read_does_not_run_on_the_event_loop(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Socketul executorului are 30 de secunde de așteptare, pe firul buclei.

    Eșecul pe care îl previne: când executorul nu răspunde — adică exact când
    autodiagnosticul are ceva de spus — apelul sincron ar ține bucla în loc o
    jumătate de minut, iar toate celelalte verificări ale rundei ar aștepta după
    el. Restul apelurilor blocante din `checks.py` sunt împăchetate; ăsta a fost
    scos la o re-derivare.

    Se probează FAPTUL (pe ce fir a rulat cititorul), nu prezența unui nume în
    sursa funcției.
    """
    import threading

    firul_buclei = None
    firul_cititorului = {}

    def _cititor():
        firul_cititorului["id"] = threading.get_ident()
        return SANATOS

    monkeypatch.setattr(checks, "_auditctl_status", _cititor)

    async def _scenariu():
        nonlocal firul_buclei
        firul_buclei = threading.get_ident()
        return await checks.check_audit_records(None, None)

    (r,) = run(_scenariu())
    assert r.status == "ok"
    assert firul_cititorului.get("id") is not None, "cititorul nu a fost chemat"
    assert firul_cititorului["id"] != firul_buclei, (
        "citirea stării de audit rulează pe firul buclei de evenimente; un "
        "executor care nu răspunde blochează toată runda 30 de secunde")


def test_the_status_is_read_through_the_EXECUTOR_not_directly() -> None:
    """`auditctl` cere root, iar autodiagnosticul rulează ca `sentinel`.

    Prima versiune îl chema direct. Măsurat pe gazdă pe 25 august 2026:
    verificarea raporta `unknown` la FIECARE trecere, pentru totdeauna — cinstit
    ca propoziție, inutil ca pază. Nimeni nu s-ar fi uitat niciodată la contorul
    de înregistrări pierdute, iar istoricul de comenzi atârnă de el.

    Se cere ca cititorul să treacă prin executor, nu să pornească un proces: e
    singurul drum către root din proiect, iar o regulă `sudoers` pentru
    `sentinel` ar fi un al doilea.
    """
    import inspect

    sursa = inspect.getsource(checks._auditctl_status)
    assert "executor_client" in sursa, (
        "starea auditului nu se mai citește prin executor")
    assert "subprocess" not in sursa, (
        "autodiagnosticul pornește iar un proces — care va eșua ca `sentinel` "
        "și va raporta `unknown` la fiecare trecere")


def test_the_executor_parses_real_auditctl_output() -> None:
    """Forma reală a ieșirii, copiată de pe gazdă.

    Se probează PARSAREA acolo unde se face acum — în executor —, separat de
    decizie: un dicționar fabricat în test ar trece și pentru un cititor care nu
    înțelege formatul lui `auditctl`.
    """
    import sys
    from pathlib import Path
    from unittest.mock import patch

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))
    import commands as executor_commands

    iesire = ("enabled 1\nfailure 1\npid 599\nrate_limit 0\n"
              "backlog_limit 8192\nlost 3\nbacklog 12\nbacklog_wait_time 60000\n")
    with patch.object(executor_commands, "_run",
                      return_value={"exit_code": 0, "stdout": iesire, "stderr": ""}):
        status = executor_commands.op_audit_status({})

    assert status["ok"] is True
    assert status["lost"] == 3
    assert status["backlog"] == 12
    assert status["backlog_limit"] == 8192


def test_an_output_without_lost_is_refused_not_read_as_zero() -> None:
    """Un răspuns fără `lost` NU e o stare de audit.

    Întors ca dicționar gol, apelantul l-ar citi ca „zero pierderi" — adică ar
    transforma «n-am înțeles răspunsul» în «totul e bine», care e chiar clasa de
    defect pe care o păzește verificarea asta.
    """
    import sys
    from pathlib import Path
    from unittest.mock import patch

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))
    import commands as executor_commands

    with patch.object(executor_commands, "_run",
                      return_value={"exit_code": 0, "stdout": "enabled 1\n",
                                    "stderr": ""}):
        status = executor_commands.op_audit_status({})
    assert status["ok"] is False

    with patch.object(executor_commands, "_run",
                      return_value={"exit_code": 1, "stdout": "",
                                    "stderr": "Operation not permitted"}):
        status = executor_commands.op_audit_status({})
    assert status["ok"] is False
    assert "permitted" in status["error"]


def test_the_operation_takes_no_arguments() -> None:
    """N-are ce valida, deci n-are cum să fie folosită pentru altceva.

    O operație privilegiată care acceptă argumente e o suprafață; una care nu
    acceptă niciunul nu poate fi îndreptată nicăieri.
    """
    import inspect
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "executor"))
    import commands as executor_commands

    sursa = inspect.getsource(executor_commands.op_audit_status)
    assert "args.get" not in sursa, "operația citește un argument"
    assert "audit_status" in executor_commands.OPERATIONS
