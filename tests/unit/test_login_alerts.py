"""Ce se anunță la o logare, ce se tace, și ce nu se tace niciodată.

Cerința operatorului, din 24 august 2026, în două jumătăți care se contrazic
dacă nu ești atent: **„nu se tace niciodată"** și **„atenție să nu generezi fals
pozitiv"**. A doua e ce face prima suportabilă — o alertă care nu poate fi tăcută
trebuie să fie rară și adevărată, altfel scutirea de la orele de liniște devine
chiar mecanismul prin care canalul e abandonat.

Măsurat pe gazda de producție, pe șapte zile: **557 de sesiuni fără terminal**
(fiecare rulare a scriptului de livrare deschide vreo zece) și **29 cu terminal**.
Un mesaj pe fiecare ar fi însemnat ~80 pe zi, dintre care 75 despre propriile
automatizări. Testele de aici păzesc chiar raportul ăla.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.detect import logins as detect_logins
from sentinel.telegram.quiet import NEVER_MUTED_KINDS, passes_anyway

NOW = datetime(2026, 8, 24, 14, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


class _DB:
    """Dublu cât să poarte anunțarea și rezumatul."""

    def __init__(self, sessions: list[dict], baseline: set[tuple[str, str]] | None = None,
                 commands: list[dict] | None = None) -> None:
        self.sessions = sessions
        self.baseline = dict.fromkeys(baseline or set(), 1)
        self.commands = commands or []
        self.queued: list[dict] = []
        self.sql: list[str] = []

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        if "FROM login_sessions" in sql:
            if "alerted_at IS NULL" in sql:
                # Se filtrează CUM SPUNE instrucțiunea. Un dublu care ar întoarce
                # tot ar face testul despre sesiunile neinteractive să treacă
                # degeaba — și exact aia e proprietatea care ține canalul viu.
                assert "interactive = true" in sql, sql
                return [s for s in self.sessions
                        if s.get("alerted_at") is None and s.get("interactive")]
            assert "closed_at IS NOT NULL" in sql, sql
            assert "alerted_at IS NOT NULL" in sql, sql
            return [s for s in self.sessions
                    if s.get("closed_at") is not None
                    and s.get("alerted_at") is not None
                    and s.get("summarised_at") is None]
        if "FROM session_commands" in sql:
            priv = set(a[1])
            return [c for c in self.commands
                    if c["session_id"] == a[0]
                    and (c.get("exe") or "").rsplit("/", 1)[-1] in priv]
        raise AssertionError(f"fetch nerecunoscut: {sql}")

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        if "min(first_seen)" in sql:
            return None
        raise AssertionError(f"fetchval nerecunoscut: {sql}")

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        if "INSERT INTO login_baseline" in sql:
            cheie = (a[0], a[1])
            nou = cheie not in self.baseline
            self.baseline[cheie] = self.baseline.get(cheie, 0) + 1
            # `xmax = 0` e felul lui PostgreSQL de a spune „inserat acum".
            return {"seen_count": self.baseline[cheie], "inserted": nou}
        raise AssertionError(f"fetchrow nerecunoscut: {sql}")

    async def execute(self, sql, *a):
        self.sql.append(sql)
        if "INSERT INTO notifications" in sql:
            assert "kind" in sql.split("VALUES")[0], (
                "notificarea nu poartă felul, deci fereastra de liniște n-ar "
                "putea ști că e o logare")
            self.queued.append({"severity": a[0], "kind": a[1], "dedup": a[2],
                                "title": a[3], "body": a[4], "buttons": a[5]})
            return "INSERT 0 1"
        if "UPDATE login_sessions SET alerted_at" in sql:
            for s in self.sessions:
                if s["id"] == a[0]:
                    s["alerted_at"] = NOW
                    s["unexpected"] = a[1]
            return "UPDATE 1"
        if "UPDATE login_sessions SET summarised_at" in sql:
            for s in self.sessions:
                if s["id"] == a[0]:
                    s["summarised_at"] = NOW
            return "UPDATE 1"
        raise AssertionError(f"execute nerecunoscut: {sql}")


def _sesiune(**over) -> dict:
    baza = {"id": 1, "session_key": "432", "username": "operator",
            "src_ip": "198.51.100.7", "terminal": "/dev/pts/0",
            "interactive": True, "opened_at": NOW, "closed_at": None,
            "command_count": 0, "sudo_count": 0, "commands_purged": 0,
            "alerted_at": None, "summarised_at": None}
    baza.update(over)
    return baza


# ---------------------------------------------------------------------------
# Cine primește mesaj
# ---------------------------------------------------------------------------
def test_an_interactive_session_is_announced() -> None:
    db = _DB([_sesiune()])
    assert run(detect_logins.announce_new_sessions(db)) == 1
    assert len(db.queued) == 1
    corp = db.queued[0]["body"]
    assert "operator" in corp
    assert "198.51.100.7" in corp


def test_a_session_without_a_terminal_is_NOT_announced() -> None:
    """557 pe săptămână pe gazda reală, față de 29 interactive.

    Anunțate, canalul ar produce ~80 de mesaje pe zi, dintre care 75 despre
    propriile automatizări — iar un canal cu optzeci de mesaje pe zi se oprește
    într-o săptămână. Un canal oprit e mai rău decât niciunul: arată ca
    acoperire și nu e.
    """
    db = _DB([_sesiune(interactive=False, terminal="ssh")])
    assert run(detect_logins.announce_new_sessions(db)) == 0
    assert db.queued == []


def test_a_session_is_announced_exactly_once() -> None:
    """Starea trăiește în COLOANĂ, nu în memoria procesului.

    Un bot repornit între citire și trimitere ar anunța a doua oară; unul
    repornit invers n-ar anunța deloc.
    """
    db = _DB([_sesiune()])
    run(detect_logins.announce_new_sessions(db))
    run(detect_logins.announce_new_sessions(db))
    assert len(db.queued) == 1


# ---------------------------------------------------------------------------
# Ce e neașteptat
# ---------------------------------------------------------------------------
def test_a_known_account_from_a_known_address_is_not_a_surprise() -> None:
    db = _DB([_sesiune()], baseline={("account", "operator"),
                                     ("src_ip", "198.51.100.7")})
    # A doua vedere: prima intrare le-a înregistrat, a doua le găsește.
    run(detect_logins.classify(db, _sesiune()))
    surprize = run(detect_logins.classify(db, _sesiune()))
    assert surprize == []


def test_a_new_account_is_a_surprise() -> None:
    db = _DB([])
    surprize = run(detect_logins.classify(db, _sesiune(username="intrus")))
    assert any("cont" in s for s in surprize)


def test_a_new_address_is_a_surprise() -> None:
    db = _DB([])
    surprize = run(detect_logins.classify(db, _sesiune(src_ip="203.0.113.9")))
    assert any("adres" in s for s in surprize)


@pytest.mark.parametrize("ora,surprinde", [(3, True), (4, True), (14, False),
                                           (22, False), (6, False)])
def test_an_odd_hour_is_a_surprise_even_when_it_repeats(ora: int, surprinde: bool) -> None:
    """Ora e o MARGINE, nu un obicei.

    Cine se loghează la 4 dimineața de trei ori nu face ora aia obișnuită — spre
    deosebire de cont și de adresă, care se învață. Trecută prin linia de
    referință, a doua logare de noapte ar fi tăcută, adică exact cazul pe care îl
    caută cineva.
    """
    db = _DB([])
    moment = NOW.replace(hour=ora)
    run(detect_logins.classify(db, _sesiune(opened_at=moment)))
    surprize = run(detect_logins.classify(db, _sesiune(opened_at=moment)))
    assert any("oră" in s for s in surprize) is surprinde


def test_a_surprise_raises_the_severity() -> None:
    """O logare obișnuită e o informație; una de pe o adresă nemaivăzută nu."""
    db = _DB([_sesiune()])
    run(detect_logins.announce_new_sessions(db))
    assert db.queued[0]["severity"] == "high"

    db2 = _DB([_sesiune()], baseline={("account", "operator"),
                                      ("src_ip", "198.51.100.7")})
    run(detect_logins.classify(db2, _sesiune()))
    run(detect_logins.announce_new_sessions(db2))
    assert db2.queued[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Fereastra de liniște
# ---------------------------------------------------------------------------
def test_a_login_alert_is_never_muted() -> None:
    """Cerut explicit. Fără felul pe rând, mesajul ar fi ținut până dimineața —
    iar cineva care intră la 3 noaptea e chiar motivul pentru care există."""
    assert detect_logins.KIND in NEVER_MUTED_KINDS
    assert passes_anyway("info", kind=detect_logins.KIND) is True


def test_an_ordinary_alert_is_still_mutable() -> None:
    """Garda celuilalt sens: fără ea, testul de mai sus ar trece și pentru o
    versiune în care NIMIC nu se mai poate tăcea, iar orele de liniște ar
    dispărea fără ca nimeni să observe."""
    assert passes_anyway("info", kind="selfcheck") is False


# ---------------------------------------------------------------------------
# Butoanele
# ---------------------------------------------------------------------------
def test_the_alert_carries_the_two_buttons() -> None:
    db = _DB([_sesiune()])
    run(detect_logins.announce_new_sessions(db))
    butoane = json.loads(db.queued[0]["buttons"])
    date = [b["data"] for b in butoane]
    assert "cancel" in date
    assert any(d.startswith("nteu:") for d in date)


def test_the_button_carries_the_SESSION_not_the_address() -> None:
    """Un buton care ar purta adresa poate fi apăsat peste trei ore, când de pe
    ea e conectat altcineva. Sesiunea e ce trebuie închis."""
    db = _DB([_sesiune(id=77)])
    run(detect_logins.announce_new_sessions(db))
    butoane = json.loads(db.queued[0]["buttons"])
    nteu = [b for b in butoane if b["data"].startswith("nteu:")][0]
    assert nteu["data"] == "nteu:77"
    assert "198.51.100.7" not in nteu["data"]


def test_a_session_without_an_address_gets_no_kill_button() -> None:
    """O logare pe consola locală n-are ce bloca, iar un buton care nu poate
    face ce promite e mai rău decât lipsa lui."""
    db = _DB([_sesiune(src_ip=None, terminal="tty1")])
    run(detect_logins.announce_new_sessions(db))
    butoane = json.loads(db.queued[0]["buttons"])
    assert not any(b["data"].startswith("nteu:") for b in butoane)


# ---------------------------------------------------------------------------
# Rezumatul
# ---------------------------------------------------------------------------
def test_a_closed_session_gets_a_summary() -> None:
    db = _DB(
        [_sesiune(closed_at=NOW + timedelta(minutes=95), alerted_at=NOW,
                  command_count=412, sudo_count=3)],
        commands=[{"session_id": 1, "exe": "/usr/bin/sudo",
                   "argv": "sudo systemctl restart nginx"}])
    assert run(detect_logins.summarise_closed_sessions(db)) == 1
    corp = db.queued[0]["body"]
    assert "1h 35m" in corp
    assert "412" in corp
    assert "systemctl restart nginx" in corp, (
        "«412 comenzi» nu spune nimic; comenzile privilegiate sunt jumătatea "
        "utilă a rezumatului")


def test_a_purged_session_does_not_report_zero_commands() -> None:
    """Un «0 comenzi» singur ar spune «n-a rulat nimic» despre un deploy.

    `command_count` numără rândurile care SUNT în tabelă, iar curatărea le poate
    fi luat pe toate. Rezumatul de închidere e citit pe Telegram, unde nu se
    poate cere lămurirea: dacă spune «0 comenzi» despre o sesiune care a rulat
    558 079, informația care contează — că automatizarea a rulat o jumătate de
    milion de comenzi — nu mai există nicăieri.
    """
    db = _DB([_sesiune(closed_at=NOW + timedelta(minutes=2), alerted_at=NOW,
                       command_count=0, sudo_count=0, commands_purged=558_079)])
    assert run(detect_logins.summarise_closed_sessions(db)) == 1
    corp = db.queued[0]["body"]
    assert "0 comenzi" in corp
    assert "558079" in corp, (
        "rezumatul nu spune că sesiunea a rulat o jumătate de milion de comenzi "
        "și că au fost șterse din istoric")


def test_a_session_that_was_never_purged_says_nothing_about_purging() -> None:
    """Linia se scrie doar când chiar s-a șters ceva.

    Un «și încă 0 șterse» la fiecare rezumat e zgomot care se învață să fie
    sărit cu ochiul — iar atunci nici cel care contează nu se mai citește.
    """
    db = _DB([_sesiune(closed_at=NOW + timedelta(minutes=2), alerted_at=NOW,
                       command_count=7, commands_purged=0)])
    run(detect_logins.summarise_closed_sessions(db))
    assert "șterse din istoric" not in db.queued[0]["body"]


def test_a_session_that_was_never_announced_gets_no_summary() -> None:
    """Altfel fiecare dintre cele 557 de sesiuni de deploy ar produce un mesaj
    la final — jumătate din zgomotul evitat, întors pe ușa din dos."""
    db = _DB([_sesiune(interactive=False, closed_at=NOW + timedelta(minutes=1),
                       alerted_at=None)])
    assert run(detect_logins.summarise_closed_sessions(db)) == 0
    assert db.queued == []


def test_the_summary_is_sent_exactly_once() -> None:
    db = _DB([_sesiune(closed_at=NOW + timedelta(minutes=5), alerted_at=NOW)])
    run(detect_logins.summarise_closed_sessions(db))
    run(detect_logins.summarise_closed_sessions(db))
    assert len(db.queued) == 1


def test_a_command_line_cannot_break_the_message() -> None:
    """Linia de comandă e text ales de cine rulează comanda.

    Un `<b>` în ea ar rupe mesajul HTML; unul construit cu grijă l-ar putea face
    să spună altceva decât s-a întâmplat.
    """
    db = _DB(
        [_sesiune(closed_at=NOW + timedelta(minutes=5), alerted_at=NOW,
                  sudo_count=1)],
        commands=[{"session_id": 1, "exe": "/usr/bin/sudo",
                   "argv": "sudo sh -c '<b>totul e bine</b>'"}])
    run(detect_logins.summarise_closed_sessions(db))
    corp = db.queued[0]["body"]
    assert "&lt;b&gt;" in corp
    assert "<b>totul e bine</b>" not in corp


# ---------------------------------------------------------------------------
# Fereastra de învățare
# ---------------------------------------------------------------------------
def test_the_learning_window_is_derived_from_the_data() -> None:
    """O dată de pornire ținută separat s-ar putea desincroniza de conținut, iar
    atunci fereastra ar spune «am învățat» despre o tabelă goală."""
    db = _DB([])
    assert run(detect_logins.learning_until(db)) is None
    assert detect_logins.LEARNING_DAYS == 14


# ---------------------------------------------------------------------------
# Tastatura, construită din rândul de notificare
# ---------------------------------------------------------------------------
def test_the_keyboard_is_actually_buildable_from_a_queued_row() -> None:
    """Eșecul: `name 'json' is not defined`, în producție, pe 24 august 2026.

    Constructorul de tastatură folosea `json.loads`, iar `bot.py` nu importa
    `json`. Consecința nu era o alertă de logare lipsă — era **coada de
    notificări întreagă oprită**: bucla de livrare cădea pe fiecare rând, pentru
    orice fel de veste, iar singurul semn era o linie de eroare în jurnal.

    Testul construiește tastatura DINTR-UN RÂND, nu doar importă modulul: un
    import trece și pentru un modul în care funcția n-a fost niciodată chemată.
    """
    from sentinel.telegram.bot import _kb_from_row

    kb = _kb_from_row({"buttons": json.dumps(
        [{"text": "✔️ Am văzut", "data": "cancel"},
         {"text": "🚨 Nu sunt eu", "data": "nteu:77"}])})
    assert kb is not None
    date = [b.callback_data for rand in kb.inline_keyboard for b in rand]
    assert date == ["cancel", "nteu:77"]


def test_a_row_without_buttons_gets_no_keyboard() -> None:
    """Majoritatea notificărilor n-au butoane. O tastatură goală trimisă la
    Telegram e o eroare de API, adică tot coada oprită."""
    from sentinel.telegram.bot import _kb_from_row

    assert _kb_from_row({"buttons": "[]"}) is None
    assert _kb_from_row({"buttons": None}) is None


def test_a_malformed_buttons_column_does_not_stop_the_queue() -> None:
    """Un rând stricat nu are voie să oprească livrarea celorlalte.

    E aceeași judecată ca la `_push_notifications`: o veste care nu se poate
    trimite se sare, nu doboară canalul.
    """
    from sentinel.telegram.bot import _kb_from_row

    assert _kb_from_row({"buttons": "{nu e json"}) is None
    assert _kb_from_row({"buttons": '[{"text": "fara date"}]'}) is None
