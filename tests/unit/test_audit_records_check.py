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
