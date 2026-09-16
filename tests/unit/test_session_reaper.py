"""Sfârșitul unei sesiuni: observat pe gazdă, nu așteptat într-un jurnal.

Eșecul pe care îl previne fișierul ăsta, în cuvintele operatorului: *„pe
instanța n8n am rulat comenzi dar nu am primit alerta… sesiunea a fost închisă
dar tot nu am primit.”*

Ce s-a măsurat în baza acelei gazde pe 15 septembrie 2026: **toate cele 17
sesiuni închise poartă `closed_inferred = true`** — nicio ieșire văzută
vreodată, fiindcă `USER_LOGOUT` aproape nu se scrie —, iar rezumatul fiecăreia
a plecat la exact douăsprezece ore după ultima activitate (`summarised_at -
closed_at`: 12:00:04, 12:00:09, 12:00:08, 12:00:02, 12:00:01, 12:00:06). La ora
aia, pentru omul care a închis terminalul dimineața, „a venit peste
douăsprezece ore” și „nu a venit” sunt același lucru.

Ce păzește fiecare test de aici:

  * **sesiunea moartă se închide** — altfel rezumatul rămâne la douăsprezece
    ore, adică la niciodată;
  * **sesiunea VIE nu se închide** — operatorul care citește „Sesiune
    încheiată” despre cineva care încă tastează e mai rău păgubit decât cel
    care așteaptă. De-asta dovada vine din `/proc`, care ține o sesiune „vie”
    și când logind n-o mai listează;
  * **o citire oarbă nu e o listă goală** — sub `ProtectProc=invisible` scanul
    vede zece procese, toate ale lui, și zero sesiuni. Luat de bun, ar închide
    toate sesiunile gazdei deodată și ar trimite un rezumat pentru fiecare;
  * **momentul pus e ultima activitate, nu `now()`** — nimeni n-a văzut
    ieșirea, deci ora la care am observat noi absența nu e ora la care a plecat
    omul, iar mesajul spune „cel puțin”;
  * **restanța veche rămâne a măturătoarei** — fereastra reaper-ului se
    termină unde începe a ei, deci prima rulare pe o gazdă cu rânduri vechi nu
    poate produce un val de rezumate;
  * **coada de audit trebuie citită dincolo de clipa scanului** — o sesiune
    închisă cât timp comenzile ei încă așteaptă în fișier produce un rezumat
    care numără mai puțin decât s-a rulat;
  * **dar nu până la ultimul octet** — poarta dinainte cerea fișierul citit
    complet, iar măsurată pe bucla adevărată se deschidea de 4 ori din 27 la
    100 de înregistrări pe secundă și de 0 din 24 la 500: se închidea exact pe
    gazda ocupată, adică fix atunci când se loghează cineva;
  * **filigranul nu se ține minte peste o trecere picată** — `poll_once`
    citește liniile înainte să mute cursorul, deci o trecere picată între cele
    două (25 august 2026: la fiecare lot care deschidea o sesiune) ar lăsa în
    urmă un „am citit până acolo” despre înregistrări aruncate;
  * **un refuz lasă urmă** — „reaper-ul e înfometat” și „n-a murit nicio
    sesiune” sunt aceeași liniște pentru oricine se uită de-afară, inclusiv
    pentru cine încearcă să le măsoare;
  * **un refuz nu e un proces mort** — `ENOENT` și `EACCES` sunt răspunsuri
    diferite ale nucleului, iar băgate în același „n-am putut citi” fac dintr-o
    sesiune vie, dar ascunsă, una încheiată.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.collectors import nginx_tail
from sentinel.collectors.audit_sessions import LiveAuditSessions, read_live_sessions
from sentinel.db.repo import logins
from sentinel.model.event import Event

NOW = datetime(2026, 9, 15, 11, 30, tzinfo=timezone.utc)

#: Vechimea observației, pentru testele cărora nu ea le stă în cale: „m-am
#: uitat la gazdă chiar acum". Scrisă o dată, ca înțelesul parametrului să nu
#: fie rescris în treizeci de apeluri.
PROASPAT = 0.0


def run(coro):
    return asyncio.run(coro)


def _viu(*chei: str) -> LiveAuditSessions:
    """Un scan reușit care a văzut sesiunile date."""
    return LiveAuditSessions(frozenset(chei), True, "", scanned=187)


ORB = LiveAuditSessions(
    frozenset(), False,
    "/proc/1/sessionid is unreadable: this process cannot see processes it "
    "does not own", 0)


# ---------------------------------------------------------------------------
# Dublul de bază
# ---------------------------------------------------------------------------
class _DB:
    """Dublu care MODELEAZĂ ce spune instrucțiunea, nu ce voiam să spună.

    Fiecare clauză a reaper-ului se caută în textul SQL și se aplică numai dacă
    e acolo. Un dublu care ar aplica regulile din capul lui ar da exact același
    verde și după ce clauza a fost ștearsă din cod — felul de test care a trecut
    de mai multe ori în repository-ul ăsta verificând nimic.
    """

    def __init__(self, sessions: list[dict], commands: list[dict] | None = None,
                 now: datetime = NOW) -> None:
        self.sessions = sessions
        self.commands = commands or []
        self.now = now
        self.sql: list[str] = []
        #: Ce s-a scris sub `reaper:sessions` — starea durabilă pe care o
        #: citește `check_session_reaper`. Ținută deoparte de `sql`, fiindcă
        #: „instrucțiunea reaper-ului a rulat" și „s-a raportat o stare" sunt
        #: două fapte diferite, și fiecare are testul lui.
        self.stari: list[tuple] = []
        #: Cursoarele de colector scrise de `poll_once` (auditd, nginx, …).
        self.cursoare: list[tuple] = []

    @property
    def reaps(self) -> list[str]:
        """Doar instrucțiunile reaper-ului.

        `sql` adună de acum și cursoarele scrise de `poll_once`, iar „nimic
        n-a ajuns la bază" trebuie să însemne tot „niciun rând de sesiune
        n-a fost atins", nu „daemonul n-a făcut nimic".
        """
        return [q for q in self.sql if "closed_inferred = true" in q]

    def _ultima(self, s: dict) -> datetime:
        ale_ei = [c["ts"] for c in self.commands if c["session_id"] == s["id"]]
        return max(ale_ei) if ale_ei else s["opened_at"]

    async def execute(self, sql, *a):
        self.sql.append(sql)
        if "closed_inferred = true" in sql and "candidat" in sql:
            return self._reap(sql, *a)
        if "INSERT INTO collector_cursors" in sql:
            if a and a[0] == logins.REAPER_MARKER:
                self.stari.append(tuple(a))
            else:
                self.cursoare.append(tuple(a))
            return "INSERT 0 1"
        raise AssertionError(f"execute nerecunoscut: {sql}")

    async def executemany(self, sql, rows):
        self.sql.append(sql)
        return None

    async def fetch(self, sql, *a):
        # Lista de reputație pe care `poll_once` o reîncarcă; goală, ca
        # ingestia din teste să nu depindă de conținutul ei.
        return []

    async def fetchval(self, sql, *a):
        return None

    async def fetchrow(self, sql, *a):
        if "collector_cursors" in sql and a and a[0] == logins.REAPER_MARKER:
            if not self.stari:
                return None
            _nume, stare, filigran = self.stari[-1]
            return {"cursor": stare, "cursor_at": filigran,
                    "updated_at": datetime.now(timezone.utc)}
        return None

    def _reap(self, sql, *a) -> str:
        vii = set(a[0])
        ragaz = timedelta(seconds=a[1])
        varsta = timedelta(hours=a[2])
        # Clipa în care s-a citit `/proc`, refăcută din vechimea primită.
        # Instrucțiunea măsoară AMBELE margini de acolo, nu din `now()`: între
        # scan și `UPDATE` se poate loga cineva, iar sesiunea lui lipsește
        # dintr-un instantaneu luat înainte să existe.
        observat = self.now - timedelta(seconds=max(0.0, a[3]))

        # Ce filtre SUNT în instrucțiune. Scoase din text, ca ștergerea
        # oricăruia dintre ele să schimbe ce face dublul, nu doar ce scrie.
        # Spațiile se strâng întâi: clauzele sunt scrise pe două rânduri, iar
        # un dublu care ar depinde de indentare ar potrivi formatarea.
        compact = " ".join(sql.split())
        filtreaza_vii = "NOT (s.session_key = ANY($1::text[]))" in sql
        doar_deschise = "s.closed_at IS NULL" in sql
        are_ragaz = ("candidat.ultima < now() - make_interval(secs => $4) "
                     "- make_interval(secs => $2)" in compact)
        are_varsta = ("candidat.ultima > now() - make_interval(secs => $4) "
                      "- make_interval(hours => $3)" in compact)

        # Ce se scrie în `closed_at` se citește tot din instrucțiune: „ultima
        # activitate” și „acum” sunt afirmații diferite despre aceeași sesiune,
        # iar diferența dintre ele ajunge în mesaj ca o durată.
        if "SET closed_at = candidat.ultima" in sql:
            def moment(ultima: datetime) -> datetime:
                return ultima
        elif re.search(r"SET\s+closed_at\s*=\s*now\(\)", sql):
            def moment(ultima: datetime) -> datetime:
                return self.now
        else:
            raise AssertionError(f"nu recunosc ce se scrie în closed_at: {sql}")

        n = 0
        for s in self.sessions:
            if doar_deschise and s.get("closed_at") is not None:
                continue
            if filtreaza_vii and s["session_key"] in vii:
                continue
            ultima = self._ultima(s)
            if are_ragaz and not ultima < observat - ragaz:
                continue
            if are_varsta and not ultima > observat - varsta:
                continue
            s["closed_at"] = moment(ultima)
            s["closed_inferred"] = True
            n += 1
        return f"UPDATE {n}"


def _sesiune(**over) -> dict:
    baza = {"id": 19, "session_key": "2604", "username": "operator",
            "opened_at": NOW - timedelta(hours=1), "closed_at": None,
            "closed_inferred": False, "interactive": True}
    baza.update(over)
    return baza


def _comanda(session_id: int = 19, *, minute: int = 10) -> dict:
    """O comandă rulată cu `minute` minute în urmă."""
    return {"session_id": session_id, "ts": NOW - timedelta(minutes=minute)}


# ---------------------------------------------------------------------------
# Ce se închide și ce nu
# ---------------------------------------------------------------------------
def test_a_dead_session_is_closed_so_the_summary_can_finally_leave() -> None:
    """Fără asta, rândul stă deschis până la măturătoarea de douăsprezece ore,
    iar «🔓 Sesiune încheiată» ajunge la operator noaptea, despre dimineață."""
    s = _sesiune()
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, _viu("2472", "2624"), PROASPAT)) == 1
    assert s["closed_at"] is not None, (
        "sesiunea a cărei sesiune de audit nu mai există pe gazdă a rămas "
        "deschisă — rezumatul ei nu poate pleca niciodată")


def test_a_live_session_is_never_closed() -> None:
    """Cel mai rău rezultat posibil: „Sesiune încheiată” despre cineva care
    încă tastează. De-asta cheia vie e citită din procesele gazdei."""
    s = _sesiune()
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, _viu("2604"), PROASPAT)) == 0
    assert s["closed_at"] is None, (
        "o sesiune cu procese vii pe gazdă a fost declarată încheiată")


def test_a_blind_scan_closes_nothing_at_all() -> None:
    """Sub `ProtectProc=invisible` scanul vede zero sesiuni. Dacă zero ar
    însemna „nu mai e nimeni”, prima trecere ar închide TOATE sesiunile gazdei
    și ar trimite un rezumat pentru fiecare."""
    s = _sesiune()
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, ORB, PROASPAT)) == 0
    assert s["closed_at"] is None
    assert db.sql == [], (
        "o citire în care nu se poate avea încredere a ajuns totuși la bază")


def test_a_trusted_scan_with_nobody_logged_in_still_closes() -> None:
    """Cealaltă direcție a aceleiași deosebiri: o gazdă pe care chiar nu e
    nimeni logat are o listă goală de sesiuni vii, iar rândurile rămase trebuie
    să se închidă. Altfel garda de mai sus ar fi cumpărat liniștea cu inerția."""
    s = _sesiune()
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, _viu(), PROASPAT)) == 1
    assert s["closed_at"] is not None


def test_an_already_closed_session_is_not_closed_a_second_time() -> None:
    """O sesiune închisă corect de `USER_LOGOUT` nu are voie să-și piardă
    momentul adevărat și să capete `closed_inferred` de la reaper."""
    inchisa = NOW - timedelta(hours=3)
    s = _sesiune(closed_at=inchisa)
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, _viu(), PROASPAT)) == 0
    assert s["closed_at"] == inchisa
    assert s["closed_inferred"] is False


# ---------------------------------------------------------------------------
# Ce moment primește rândul
# ---------------------------------------------------------------------------
def test_the_close_is_stamped_at_the_last_command_not_at_the_observation() -> None:
    """`now()` ar fi o minciună de mărime necunoscută: între ultima comandă și
    clipa în care observăm absența pot trece ore. Durata din mesaj se calculează
    din momentul ăsta, deci aici se hotărăște dacă «Durată: 3h 12m» e adevărată."""
    s = _sesiune()
    ultima = _comanda(minute=40)
    db = _DB([s], [ultima])
    run(logins.reap_dead_sessions(db, _viu(), PROASPAT))
    assert s["closed_at"] == ultima["ts"], (
        "momentul închiderii nu mai e ultima activitate; durata din rezumat "
        "spune altceva decât s-a întâmplat")


def test_a_session_that_ran_nothing_is_stamped_at_its_login() -> None:
    """Fără nicio comandă, singurul moment cunoscut e deschiderea. O sesiune
    fără `closed_at` n-ar putea fi rezumată deloc."""
    s = _sesiune(opened_at=NOW - timedelta(hours=2))
    db = _DB([s], [])
    run(logins.reap_dead_sessions(db, _viu(), PROASPAT))
    assert s["closed_at"] == NOW - timedelta(hours=2)


def test_the_close_is_marked_as_inferred() -> None:
    """`closed_inferred` e ce face mesajul să spună «cel puțin». Fără el,
    operatorul citește ca măsurată o durată care e doar o margine de jos."""
    s = _sesiune()
    db = _DB([s], [_comanda()])
    run(logins.reap_dead_sessions(db, _viu(), PROASPAT))
    assert s["closed_inferred"] is True


# ---------------------------------------------------------------------------
# Marginile: răgazul și restanța
# ---------------------------------------------------------------------------
def test_a_session_that_only_just_went_quiet_is_left_alone() -> None:
    """Instantaneul din `/proc` se ia înaintea instrucțiunii. O sesiune născută
    între cele două lipsește din el fără să fi murit, iar fără răgaz ar fi
    închisă la o secundă după logare."""
    s = _sesiune(opened_at=NOW - timedelta(seconds=5))
    db = _DB([s], [_comanda(minute=0)])
    assert run(logins.reap_dead_sessions(db, _viu(), PROASPAT)) == 0
    assert s["closed_at"] is None


def test_the_grace_is_short_enough_to_be_a_repair() -> None:
    """Un răgaz de ore ar face reaper-ul o a doua măturătoare. Cifra e cea care
    hotărăște dacă operatorul primește rezumatul cât mai e la birou."""
    assert logins.REAP_GRACE_S <= 300, (
        "răgazul a crescut atât încât rezumatul nu mai vine la câteva minute "
        "după ce omul a închis terminalul")


def test_an_old_row_is_left_to_the_sweeper_not_reaped_in_a_burst() -> None:
    """Prima rulare pe o gazdă cu restanță nu are voie să închidă dintr-o dată
    sesiuni moarte de zile — fiecare ar deveni un mesaj pe telefon, toate în
    aceeași secundă, despre lucruri de săptămâna trecută. Peste
    `STALE_SESSION_H` ore rândul e treaba măturătoarei, ca înainte."""
    vechi = _sesiune(id=3, session_key="163",
                     opened_at=NOW - timedelta(days=4))
    db = _DB([vechi], [_comanda(session_id=3, minute=60 * 24 * 3)])
    assert run(logins.reap_dead_sessions(db, _viu(), PROASPAT)) == 0
    assert vechi["closed_at"] is None


def test_the_two_windows_touch_without_a_gap() -> None:
    """Sub plafon reaper-ul, peste plafon măturătoarea: dacă între ele ar rămâne
    o fereastră, rândurile din ea n-ar fi închise de nimeni."""
    la_limita = _sesiune(id=4, opened_at=NOW - timedelta(hours=11, minutes=59))
    db = _DB([la_limita], [])
    assert run(logins.reap_dead_sessions(db, _viu(), PROASPAT)) == 1

# ---------------------------------------------------------------------------
# Vechimea observației
# ---------------------------------------------------------------------------
def test_a_session_born_after_the_scan_is_out_of_its_reach() -> None:
    """Un instantaneu nu poate ști despre cine s-a logat după el.

    Reaper-ul ține scanul din `/proc` până citește coada de audit dincolo de
    clipa lui — o fracțiune de secundă pe o gazdă liniștită, minute pe una
    unde ingestia recuperează un vârf. În tot timpul ăsta se poate loga cineva,
    iar sesiunea lui lipsește dintr-un instantaneu luat înainte să existe.

    Măsurate din clipa OBSERVAȚIEI, marginile nu pot atinge rândul lui.
    Măsurate din `now()`, îl închid la două minute după logare și îi trimit
    operatorului «Sesiune încheiată» despre cineva care tocmai s-a conectat.
    """
    # Scanul s-a luat acum zece minute; sesiunea s-a deschis acum nouă.
    s = _sesiune(opened_at=NOW - timedelta(minutes=9))
    db = _DB([s], [])
    assert run(logins.reap_dead_sessions(db, _viu(), 600.0)) == 0
    assert s["closed_at"] is None, (
        "un instantaneu luat ÎNAINTE de logare a închis sesiunea; răgazul nu "
        "mai e măsurat din clipa în care s-a citit gazda")


def test_an_old_scan_still_closes_what_was_already_dead() -> None:
    """Cealaltă direcție a aceleiași reguli: vechimea observației întârzie
    închiderea, nu o anulează. Dacă un scan vechi n-ar mai închide nimic,
    reaper-ul s-ar opri exact când ingestia are de recuperat — adică fix în
    cazul pentru care a fost rescrisă poarta."""
    s = _sesiune()
    db = _DB([s], [_comanda(minute=30)])
    assert run(logins.reap_dead_sessions(db, _viu(), 600.0)) == 1
    assert s["closed_at"] is not None


def test_a_negative_observation_age_cannot_move_the_window_forward() -> None:
    """Un ceas sărit înapoi poate produce o vechime negativă. Dusă în
    instrucțiune, ar muta ambele margini în VIITOR: o sesiune tăcută de câteva
    secunde ar deveni «tăcută de două minute» și s-ar închide sub omul care
    tastează. Se taie la zero, iar tăierea e în funcția care scrie, nu în
    apelant."""
    s = _sesiune(opened_at=NOW - timedelta(seconds=5))
    db = _DB([s], [_comanda(minute=0)])
    assert run(logins.reap_dead_sessions(db, _viu(), -3600.0)) == 0
    assert s["closed_at"] is None


# ---------------------------------------------------------------------------
# Cititorul din /proc
# ---------------------------------------------------------------------------
def _proc(tmp_path, procese: dict[str, str | None], *, cu_pid1: bool = True):
    """Un /proc de mână. `None` = directorul există fără `sessionid`."""
    root = tmp_path / "proc"
    root.mkdir()
    if cu_pid1:
        (root / "1").mkdir()
        (root / "1" / "sessionid").write_text("4294967295", encoding="ascii")
    for pid, ses in procese.items():
        d = root / pid
        d.mkdir(exist_ok=True)
        if ses is not None:
            (d / "sessionid").write_text(ses, encoding="ascii")
    return root


def test_the_scan_reports_the_sessions_that_still_have_a_process(tmp_path) -> None:
    """Asta e tot mecanismul: o sesiune cu procese e vie, una fără e încheiată."""
    root = _proc(tmp_path, {"1538917": "2472", "1538993": "2472",
                            "1538921": "2473", "424242": "2624"})
    live = read_live_sessions(root)
    assert live.trusted
    assert live.keys == {"2472", "2473", "2624"}


def test_the_no_session_marker_is_not_a_session(tmp_path) -> None:
    """`4294967295` înseamnă „niciun login”. Numărată ca sesiune vie, ar ține
    deschis la nesfârșit orice rând care ar nimeri cheia asta."""
    root = _proc(tmp_path, {"900": "4294967295", "901": "2604"})
    assert read_live_sessions(root).keys == {"2604"}


def test_a_proc_that_hides_other_users_is_not_trusted(tmp_path) -> None:
    """Chiar cazul măsurat sub `ProtectProc=invisible`: PID 1 nu se vede, deci
    nici sesiunile altora. Un scan care ar raporta „nicio sesiune vie” de acolo
    ar închide toată gazda."""
    root = _proc(tmp_path, {"777": "4294967295"}, cu_pid1=False)
    live = read_live_sessions(root)
    assert live.trusted is False
    assert live.keys == frozenset()
    assert "hidepid" in live.detail or "audit" in live.detail, live.detail


def test_a_process_that_vanishes_mid_scan_does_not_break_the_scan(tmp_path) -> None:
    """Procesele mor în timp ce citim. O excepție aici ar opri reaper-ul
    complet, iar rezumatele s-ar întoarce tăcut la douăsprezece ore."""
    root = _proc(tmp_path, {"800": None, "801": "2604"})
    live = read_live_sessions(root)
    assert live.trusted
    assert live.keys == {"2604"}


def test_what_could_not_be_read_is_counted_not_swallowed(tmp_path) -> None:
    """Procesele care au murit în timpul scanului se numără, ca „n-am închis
    nimic” să poată fi citit alături de cât din gazdă chiar s-a putut citi.

    Ele NU fac scanul nedemn de încredere — un proces dispărut nu e o dovadă
    ascunsă, e o dovadă care nu mai există. Refuzul (`EACCES`) e altceva și are
    testul lui mai jos."""
    root = _proc(tmp_path, {"800": None, "802": None, "801": "2604"})
    live = read_live_sessions(root)
    assert live.unreadable == 2
    assert live.denied == 0
    assert live.trusted is True
    assert live.scanned == 2, "PID 1 și 801 s-au citit; restul sunt necitite"


def _refuza(monkeypatch, *pids: str) -> None:
    """Fă ca `sessionid` al proceselor date să dea EACCES, nu ENOENT.

    Prin monkeypatch fiindcă deosebirea e între două clase de excepție, iar un
    director fără drepturi se comportă altfel pe Windows decât pe Linux — ce se
    verifică aici e ce face codul cu `PermissionError`, nu cum îl produce
    sistemul de fișiere.
    """
    citeste = Path.read_text

    def refuz(self, *a, **k):
        if self.name == "sessionid" and self.parent.name in pids:
            raise PermissionError(13, "Permission denied")
        return citeste(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", refuz)


def test_a_denied_read_is_partial_blindness_not_a_dead_process(
        tmp_path, monkeypatch) -> None:
    """Un proces care a ieșit n-are director (`ENOENT`); unuia căruia i se
    refuză citirea directorul îi e acolo (`EACCES`). Nucleul le deosebește.

    Băgate în același răspuns, sesiunea procesului refuzat lipsește din lista
    vie, scanul se declară de încredere, iar `UPDATE`-ul pleacă: «Sesiune
    încheiată» despre cineva care tastează în clipa aia.
    """
    root = _proc(tmp_path, {"800": "2472", "801": "2604"})
    _refuza(monkeypatch, "801")
    live = read_live_sessions(root)
    assert live.denied == 1
    assert live.trusted is False, (
        "un scan căruia i s-a refuzat o citire s-a declarat complet")
    assert "refused" in live.detail, live.detail

    s = _sesiune(session_key="2604")
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, live, PROASPAT)) == 0
    assert s["closed_at"] is None, (
        "sesiunea al cărei proces era VIU dar necitibil a fost declarată "
        "încheiată")
    assert db.sql == []


def test_a_denied_pid1_is_unknown_and_never_raises(tmp_path, monkeypatch) -> None:
    """Controlul pozitiv poate fi refuzat, nu doar ascuns — iar funcția asta
    promite că nu aruncă niciodată. O excepție de aici ar ieși prin
    `maybe_reap_sessions` în `run()`, unde singurul semn ar fi o linie de
    eroare, la fiecare rotație, fără ca nimeni să știe de ce tac rezumatele."""
    root = _proc(tmp_path, {"801": "2604"})
    _refuza(monkeypatch, "1")
    live = read_live_sessions(root)
    assert live.trusted is False
    assert live.keys == frozenset()
    assert "refused" in live.detail, live.detail


def test_a_directory_named_in_unicode_digits_is_not_a_pid(tmp_path) -> None:
    r"""`\d` potrivește în Python și cifrele non-ASCII; `[0-9]` nu.

    `/proc` nu are azi așa ceva, dar regula e scrisă o dată și ține de ce
    înseamnă o cheie de sesiune: `session_key` în bază e ce-a scris auditd,
    ASCII simplu. Un nume care doar SEAMĂNĂ cu un număr, luat drept PID și
    citit, ar băga în lista de sesiuni vii o cheie care nu vine de la nucleu —
    iar o cheie vie inventată ține un rând deschis la nesfârșit.
    """
    from sentinel.collectors import audit_sessions

    # 2604 cu cifre arabo-indice și cu cifre fullwidth, scrise ca escape-uri ca
    # să nu depindă de cum trece fișierul ăsta prin unelte.
    arabo = "٢٦٠٤"
    fullwidth = "２６０４"
    assert audit_sessions._DECIMAL.match(arabo) is None
    assert audit_sessions._DECIMAL.match(fullwidth) is None

    root = _proc(tmp_path, {"801": "2472"})
    fals = root / arabo
    fals.mkdir()
    (fals / "sessionid").write_text("2604", encoding="ascii")
    live = read_live_sessions(root)
    assert live.keys == {"2472"}, (
        "un director care nu e un PID a fost citit ca proces")
    assert live.scanned == 2, "PID 1 și 801, atât"


def test_a_session_id_with_a_leading_zero_is_the_same_session(tmp_path) -> None:
    """Cheia din bază vine din `ses=2604` al lui auditd, asta din `/proc`.
    Comparația care hotărăște dacă cineva e viu e pe ȘIRURI, deci `02604` și
    `2604` s-ar rata una pe alta, iar rândul unei sesiuni vii s-ar închide cu
    tot cu rezumat."""
    root = _proc(tmp_path, {"801": "02604"})
    live = read_live_sessions(root)
    assert live.trusted
    assert live.keys == {"2604"}, (
        "id-ul de sesiune nu e adus la forma în care e stocat")

    s = _sesiune(session_key="2604")
    db = _DB([s], [_comanda()])
    assert run(logins.reap_dead_sessions(db, live, PROASPAT)) == 0
    assert s["closed_at"] is None


def test_an_entry_that_is_not_a_pid_is_ignored(tmp_path) -> None:
    """`/proc/self`, `/proc/net` — nu sunt procese, iar `self` ar număra de două
    ori chiar procesul care citește."""
    root = _proc(tmp_path, {"802": "2604"})
    (root / "self").mkdir()
    (root / "self" / "sessionid").write_text("999999", encoding="ascii")
    assert read_live_sessions(root).keys == {"2604"}


def test_a_missing_proc_is_unknown_not_empty(tmp_path) -> None:
    """Nici măcar directorul nu există: tot „nu știu”, niciodată „nu e nimeni”."""
    live = read_live_sessions(tmp_path / "nu-exista")
    assert live.trusted is False
    assert live.keys == frozenset()


def test_a_pathological_sessionid_does_not_break_the_scan(tmp_path) -> None:
    """`int()` refuză un șir decimal mai lung decât limita interpretorului
    (4300 de cifre implicit, CPython ≥ 3.10.7), iar conversia stătea în afara
    lui `try`.

    Nucleul scrie un u32, deci un `/proc` adevărat nu poate ajunge acolo. Dar
    docstring-ul funcției promite că NU aruncă niciodată, iar promisiunea aia e
    tot ce-i dă voie apelantului să trateze „n-am putut citi" ca stare, nu ca
    pană. O excepție de aici iese prin `maybe_reap_sessions` în `run()`, unde
    singurul semn e o linie de eroare la fiecare trecere — colectarea merge mai
    departe, sesiunile nu se mai închid niciodată, și nimic nu leagă cele două.
    """
    assert hasattr(sys, "get_int_max_str_digits"), (
        "interpretorul n-are limita de cifre, deci testul ăsta nu poate "
        "măsura nimic — nu se sare tăcut peste el")
    assert sys.get_int_max_str_digits() < 5000

    root = _proc(tmp_path, {"801": "1" * 5000, "802": "2604"})
    live = read_live_sessions(root)
    assert live.trusted is True, (
        "o valoare imposibilă a oprit scanul întreg")
    assert live.keys == {"2604"}, (
        "valoarea pe care nu s-a putut da un id de sesiune a intrat totuși "
        "în lista de sesiuni vii")


# ---------------------------------------------------------------------------
# Garda pe coada de audit
# ---------------------------------------------------------------------------
def test_the_tail_is_at_the_end_only_when_it_really_is(tmp_path) -> None:
    """„Am citit tot” e faptul care lipsește dacă mai sunt comenzi nescrise în
    bază: rezumatul ar număra mai puține comenzi decât s-au rulat."""
    jurnal = tmp_path / "audit.log"
    jurnal.write_text("o linie\n", encoding="utf-8")
    _, cursor = nginx_tail.read_new_lines(str(jurnal), "0:0")
    assert nginx_tail.at_end(str(jurnal), cursor) is True

    with jurnal.open("a", encoding="utf-8") as fh:
        fh.write("încă una\n")
    assert nginx_tail.at_end(str(jurnal), cursor) is False, (
        "coada raportează „la zi” deși în fișier mai sunt linii necitite")


def test_a_rotated_file_is_not_at_the_end(tmp_path) -> None:
    """Cursorul poartă inode-ul. După rotație, aceeași dimensiune pe alt fișier
    ar arăta ca „am citit tot” fără să fi citit nimic din el."""
    jurnal = tmp_path / "audit.log"
    jurnal.write_text("o linie\n", encoding="utf-8")
    _, cursor = nginx_tail.read_new_lines(str(jurnal), "0:0")
    jurnal.unlink()
    jurnal.write_text("o linie\n", encoding="utf-8")
    assert nginx_tail.at_end(str(jurnal), cursor) is False


def test_a_cursor_past_the_end_of_the_file_is_not_at_the_end(tmp_path) -> None:
    """Fișier trunchiat: cursorul e DINCOLO de capăt, nu la capăt.

    `at_end` cere egalitate, nu „cel puțin cât fișierul”. Cu `>=`, un
    `audit.log` golit pe loc (`> audit.log`, rotație prin trunchiere, un disc
    plin recuperat) ar fi raportat drept citit până la capăt, deși din ce e
    acum în el n-a fost citit nimic — iar reaper-ul ar închide sesiuni exact
    peste conținutul pe care abia trebuie să-l citească.
    """
    jurnal = tmp_path / "audit.log"
    jurnal.write_text("o linie destul de lungă ca să conteze\n", encoding="utf-8")
    _, cursor = nginx_tail.read_new_lines(str(jurnal), "0:0")
    assert nginx_tail.at_end(str(jurnal), cursor) is True

    with jurnal.open("r+", encoding="utf-8") as fh:
        fh.truncate(3)
    assert nginx_tail.at_end(str(jurnal), cursor) is False, (
        "un cursor rămas dincolo de capătul unui fișier trunchiat raportează "
        "„am citit tot” despre linii pe care nu le-a văzut nimeni")


def test_an_unreadable_file_is_not_at_the_end(tmp_path) -> None:
    assert nginx_tail.at_end(str(tmp_path / "nu-exista"), "1:0") is False
    assert nginx_tail.at_end(str(tmp_path), None) is False


# ---------------------------------------------------------------------------
# Bucla care îl cheamă
# ---------------------------------------------------------------------------
def _ingest(tmp_path, db):
    """Un `Ingest` cu coada de audit pe un fișier REAL și fără alți colectori.

    Fișierul chiar se scrie și chiar se citește, prin `poll_once`-ul adevărat:
    filigranul pe care se sprijină poarta se naște acolo, iar un test care l-ar
    pune de mână ar verifica exact ce nu trebuie — ce ține minte cineva în loc
    de ce s-a măsurat.
    """
    from sentinel.services import ingest_service

    jurnal = tmp_path / "audit.log"
    jurnal.write_text("", encoding="utf-8")
    cfg = SimpleNamespace(
        ingest=SimpleNamespace(exclude_sources=(), flush_interval_ms=200),
        history=SimpleNamespace(skip_command_accounts=()))
    ingest = ingest_service.Ingest(cfg, db)
    ingest._audit_path = str(jurnal)
    # Un cursor care NU e None: fișierul e deja cunoscut. Cu `None`, prima
    # citire sare la capăt și nu întoarce nicio linie, dinadins.
    ingest._audit_cursor = "0:0"
    return ingest, jurnal


def _scrie(jurnal: Path, ts: datetime, *, serial: int = 4242,
           tip: str = "CRYPTO_KEY_USER", intreg: bool = True) -> None:
    """O înregistrare auditd adevărată, cu ștampila cerută.

    `CRYPTO_KEY_USER` e tipul pe care sshd îl scrie cu sutele și pe care
    `parse_auditd_lines` NU-l păstrează: lotul rămâne gol, deci testele de mai
    jos măsoară poarta, nu proiecția. Ștampila e ce contează, iar ea se citește
    din linia brută, înaintea oricărei filtrări — ceea ce e chiar motivul
    pentru care filigranul nu se ia din evenimente.

    `intreg=False` lasă linia fără caracterul de linie nouă: exact ce vede
    tailerul când auditd e la jumătatea unei scrieri. Coada rămâne atunci în
    urmă, adică NU la capăt, care e starea în care poarta veche refuza.
    """
    linie = (f"type={tip} msg=audit({int(ts.timestamp())}."
             f"{ts.microsecond // 1000:03d}:{serial}): pid=1 uid=0 "
             f"auid=1000 ses=2604 res=success")
    # Dacă în fișier a rămas o linie neterminată, se termină întâi: altfel
    # înregistrarea nouă s-ar lipi de cea veche, iar ștampila citită ar fi a
    # celei vechi — un test care s-ar fi mințit singur.
    brut = jurnal.read_bytes()
    prefix = "" if (not brut or brut.endswith(b"\n")) else "\n"
    with jurnal.open("a", encoding="utf-8") as fh:
        fh.write(prefix + linie + ("\n" if intreg else ""))


def _coada_in_urma(jurnal: Path, ts: datetime, *, serial: int = 4242) -> None:
    """O înregistrare citibilă, urmată de una neterminată.

    Adică starea obișnuită a unui `audit.log` pe care se scrie: ce s-a citit
    are o ștampilă, iar coada NU e la capăt.
    """
    _scrie(jurnal, ts, serial=serial)
    _scrie(jurnal, ts, serial=serial + 1, intreg=False)


def test_the_ingest_loop_closes_a_dead_session(tmp_path, monkeypatch) -> None:
    """Reaper-ul scris și nechemat ar fi exact pana de azi: cod corect, rânduri
    deschise la nesfârșit, rezumat la douăsprezece ore."""
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu("2472"))

    stop = asyncio.Event()
    treceri = [0]
    adevarata = ingest.poll_once

    async def doua_treceri():
        # Trecerea ADEVĂRATă, de două ori: dovada vine cu cea de DUPĂ scan —
        # prima citește coada și ia instantaneul, a doua duce filigranul
        # dincolo de el. E cadența reală a daemonului, nu o concesie a
        # testului; iar un dublu de `poll_once` ar fi șters exact pasul care
        # face poarta să se deschidă.
        treceri[0] += 1
        n = await adevarata()
        if treceri[0] >= 2:
            stop.set()
        return n

    monkeypatch.setattr(ingest, "poll_once", doua_treceri)
    run(ingest.run(stop))
    assert s["closed_at"] is not None, (
        "bucla de ingestie nu închide sesiunile moarte")


def test_the_reaper_runs_while_the_audit_tail_is_still_being_written(
        tmp_path, monkeypatch) -> None:
    """Poarta dinainte cerea fișierul citit până la ULTIMUL octet.

    Între citirea aia și hotărâre stau `insert_batch` și `logins.project`, adică
    un drum la bază pentru fiecare comandă din lot — 636 pentru o singură
    logare, ~405 000 pentru un deploy. Măsurată pe bucla adevărată, poarta se
    deschidea de 19 ori din 28 la 20 de înregistrări pe secundă, de 4 din 27 la
    100, și de 0 din 24 la 500: se închidea exact pe gazda ocupată, adică fix
    când se loghează cineva, iar rezumatele se întorceau la douăsprezece ore.

    Aici coada e în urmă la fiecare pas, ca pe gazda ocupată — și tot ce e
    necitit e mai NOU decât clipa în care s-a citit `/proc`, deci nu poate fi
    al unei sesiuni care era deja moartă atunci.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    acum = datetime.now(timezone.utc)
    _coada_in_urma(jurnal, acum - timedelta(minutes=1))
    run(ingest.poll_once())
    assert run(ingest.maybe_reap_sessions()) == 0, (
        "reaper-ul a închis un rând deși coada nu fusese citită dincolo de "
        "clipa în care s-a uitat la gazdă")

    # Înregistrări mai noi decât instantaneul ținut în mână — adică timpul care
    # trece pe o gazdă pe care chiar se scrie. Testul nu doarme cinci secunde,
    # scrie înregistrarea pe care nucleul ar fi scris-o atunci.
    _scrie(jurnal, acum + timedelta(seconds=5), serial=4244)
    run(ingest.poll_once())
    # …și încă una, ajunsă în fișier cât timp lotul se scria în bază: exact
    # fereastra în care poarta veche se închidea.
    _scrie(jurnal, acum + timedelta(seconds=6), serial=4245)

    assert nginx_tail.at_end(str(jurnal), ingest._audit_cursor) is False, (
        "testul nu mai măsoară ce trebuie: coada a ajuns la capăt, deci și "
        "poarta veche ar fi lăsat reaper-ul să treacă")
    assert run(ingest.maybe_reap_sessions()) == 1, (
        "reaper-ul a refuzat fiindcă mai era ceva necitit în coadă, deși tot "
        "ce e necitit e mai nou decât clipa scanului — poarta cere din nou "
        "decalaj zero, adică se închide pe orice gazdă ocupată")
    assert s["closed_at"] is not None


def test_a_session_is_not_closed_while_its_own_commands_are_still_unread(
        tmp_path, monkeypatch) -> None:
    """Închisă peste comenzile ei încă necitite, sesiunea primește un rezumat
    care numără mai puțin decât s-a rulat — «71 de comenzi» despre o sesiune cu
    447. Nimic nu-l mai corectează după aceea: `summarise_closed_sessions` nu
    așteaptă nimic, iar `summarised_at` îl oprește să mai plece o dată.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    acum = datetime.now(timezone.utc)
    _coada_in_urma(jurnal, acum - timedelta(minutes=10))
    run(ingest.poll_once())
    assert run(ingest.maybe_reap_sessions()) == 0

    # Coada avansează, dar numai cu înregistrări mai VECHI decât scanul: ce a
    # rămas necitit poate fi încă al sesiunii ăsteia.
    _coada_in_urma(jurnal, acum - timedelta(minutes=9), serial=4244)
    run(ingest.poll_once())

    assert run(ingest.maybe_reap_sessions()) == 0, (
        "reaper-ul a închis o sesiune deși coada de audit n-a fost citită "
        "nici măcar până la clipa în care s-a uitat la gazdă")
    assert s["closed_at"] is None
    assert db.reaps == [], (
        "instrucțiunea a ajuns la bază peste comenzi încă necitite")


def test_a_poll_that_crashed_before_committing_does_not_move_the_watermark(
        tmp_path, monkeypatch) -> None:
    """Chiar pana din 25 august 2026, jucată până la capăt.

    Atunci `poll_once` arunca pe FIECARE lot care deschidea o sesiune, iar
    `run()` prinde excepția și cheamă reaper-ul oricum, în aceeași rotație.
    Dacă filigranul s-ar muta la citire, defectul ăla n-ar mai opri doar
    colectarea: ar pune reaper-ul să închidă sesiuni sprijinindu-se pe
    înregistrări care tocmai s-au pierdut — adică despre fix sesiunile ale
    căror comenzi lipsesc din bază.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    acum = datetime.now(timezone.utc)
    _coada_in_urma(jurnal, acum - timedelta(minutes=10))
    run(ingest.poll_once())
    assert run(ingest.maybe_reap_sessions()) == 0
    inainte = ingest._audit_seen_through

    # Linii care ar duce filigranul dincolo de scan — dar lotul lor moare la
    # scriere, deci nu ajunge în bază nimic din ele.
    _scrie(jurnal, acum + timedelta(seconds=5), tip="USER_CMD", serial=4244)

    def _crapa(*a, **k):
        raise RuntimeError("Logger._log() got an unexpected keyword argument")

    monkeypatch.setattr(ingest_service.events_repo, "insert_batch", _crapa)
    with pytest.raises(RuntimeError):
        run(ingest.poll_once())

    assert ingest._audit_seen_through == inainte, (
        "filigranul a avansat peste un lot care n-a ajuns niciodată în bază")
    assert run(ingest.maybe_reap_sessions()) == 0, (
        "reaper-ul a închis o sesiune sprijinindu-se pe înregistrări pierdute")
    assert s["closed_at"] is None
    assert db.reaps == []


def test_a_quiet_host_still_reaps(tmp_path, monkeypatch) -> None:
    """Pe o gazdă pe care nu se scrie nimic în `audit.log` nu există nicio
    ștampilă din care să vină filigranul.

    Dacă el n-ar veni atunci din citirea însăși — coada golită, la clipa
    citirii —, reaper-ul n-ar porni NICIODATĂ exact pe gazda cea mai liniștită,
    unde de fapt are cel mai puțin de așteptat. Ar fi aceeași înfometare tăcută,
    mutată la celălalt capăt al traficului.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())
    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())

    assert s["closed_at"] is not None, (
        "pe o gazdă fără nicio înregistrare de audit nouă, reaper-ul nu mai "
        "închide nimic; rezumatele se întorc la măturătoarea de 12 ore")


def test_an_undatable_tail_freezes_the_watermark_instead_of_inventing_one(
        tmp_path, monkeypatch) -> None:
    """Coada e în urmă și nicio linie citită nu poartă ștampilă.

    „Nu știu până când am citit" nu are voie să devină „am citit până acum":
    filigranul rămâne nepus, iar reaper-ul refuză. Un implicit aici ar fi exact
    minciuna pe care o păzește tot fișierul ăsta, doar că scrisă cu ceasul
    nostru în loc de al nucleului.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    jurnal.write_text("o linie fără ștampilă\nși una neterminată",
                      encoding="utf-8")
    run(ingest.poll_once())

    assert ingest._audit_seen_through is None, (
        "s-a pus un filigran deși nicio înregistrare citită n-avea ștampilă")
    assert run(ingest.maybe_reap_sessions()) == 0
    assert db.reaps == []


def test_the_host_is_not_scanned_on_every_poll(tmp_path, monkeypatch) -> None:
    """Un scan pe trecere ar însemna 187 de fișiere deschise la fiecare câteva
    secunde, pe gazda pe care Sentinel e doar musafir.

    Și încă ceva: scanul care ÎNCĂ AȘTEAPTĂ nu se reia. Absența unei sesiuni
    rămâne adevărată oricât — procesele nu învie —, deci un instantaneu vechi
    doar întârzie închiderea. Reluat la fiecare trecere, ar muta linia de
    sosire în același ritm în care aleargă filigranul, și n-ar fi atinsă
    niciodată.
    """
    from sentinel.services import ingest_service

    scanuri = []
    db = _DB([_sesiune()], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    _coada_in_urma(jurnal, datetime.now(timezone.utc) - timedelta(minutes=10))
    run(ingest.poll_once())

    def numara(*a, **k):
        scanuri.append(1)
        return _viu()

    monkeypatch.setattr(ingest_service, "read_live_sessions", numara)
    run(ingest.maybe_reap_sessions())
    primul = ingest._pending_scan
    run(ingest.maybe_reap_sessions())
    assert len(scanuri) == 1
    assert ingest._pending_scan is primul, (
        "instantaneul care aștepta a fost aruncat și luat din nou")


def test_a_blind_daemon_says_so_in_the_journal(tmp_path, monkeypatch, caplog) -> None:
    """Un reaper care nu poate citi `/proc` arată exact ca unul pe o gazdă unde
    nu e nimeni logat: zero rânduri atinse, niciun mesaj. Deosebirea trebuie să
    ajungă undeva unde se poate citi."""
    from sentinel.services import ingest_service

    db = _DB([_sesiune()], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions", lambda *a, **k: ORB)
    with caplog.at_level(logging.WARNING):
        assert run(ingest.maybe_reap_sessions()) == 0
    assert any("alive" in r.message for r in caplog.records), (
        "daemonul orb n-a spus nimic în jurnal")


def test_a_readable_scan_is_announced_the_first_time(
        tmp_path, monkeypatch, caplog) -> None:
    """`_reap_state` pornește din `None`, nu din `""`.

    Cu `""`, prima stare bună e egală cu cea de pornire: linia nu se tipărește
    nici la prima pornire, nici la a suta, iar singura dovadă pozitivă că
    daemonul chiar vede procesele gazdei nu apare niciodată. Un reaper orb și
    unul care merge devin din nou aceeași tăcere — fix deosebirea pentru care
    există starea asta.
    """
    from sentinel.services import ingest_service

    db = _DB([_sesiune()], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu("2472"))
    with caplog.at_level(logging.INFO):
        run(ingest.maybe_reap_sessions())

    linii = [r for r in caplog.records
             if "live login sessions readable" in r.message]
    assert linii, (
        "scanul reușit n-a spus nimic în jurnal, deci nimic nu deosebește un "
        "reaper care vede gazda de unul orb")
    assert getattr(linii[0], "processes", None) == 187, (
        "linia nu poartă câte procese s-au citit, adică nu spune cât de "
        "completă a fost citirea pe care se ia hotărârea")


def test_closing_a_session_is_announced_in_the_journal(
        tmp_path, monkeypatch, caplog) -> None:
    """Singura dovadă pozitivă că reaper-ul chiar lucrează.

    Fără linia asta, «n-a murit nicio sesiune» și «reaper-ul n-a atins nimic
    de o săptămână» sunt aceeași tăcere în jurnal, iar numărul din ea e ce
    leagă mesajul de pe telefon de rândurile din bază.
    """
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    acum = datetime.now(timezone.utc)
    _coada_in_urma(jurnal, acum - timedelta(minutes=1))
    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())
    _scrie(jurnal, acum + timedelta(seconds=5), serial=4244)
    run(ingest.poll_once())

    with caplog.at_level(logging.INFO):
        assert run(ingest.maybe_reap_sessions()) == 1

    linii = [r for r in caplog.records
             if "dead login sessions closed" in r.message]
    assert linii, (
        "reaper-ul a închis o sesiune și n-a spus-o nicăieri")
    assert getattr(linii[0], "count", None) == 1, (
        "linia nu spune CÂTE rânduri s-au închis; fără număr nu se poate lega "
        "de mesajele plecate")


def test_a_deferred_reap_is_written_where_a_reboot_cannot_erase_it(
        tmp_path, monkeypatch) -> None:
    """Un refuz care nu lasă urmă e indistinguibil de o gazdă pe care n-a murit
    nimeni — inclusiv pentru cine încearcă să-l măsoare.

    Și o linie de jurnal nu e de ajuns aici: pe gazda de producție nu există
    `/var/log/journal`, deci jurnalul stă în RAM (2,79 zile măsurate) și se
    pierde la fiecare reboot. Starea pleacă de aceea în `collector_cursors`,
    de unde o citește `/selfcheck`.
    """
    from sentinel.services import ingest_service

    db = _DB([_sesiune()], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())
    # Ceasul monoton al daemonului, ca amânarea să poată trece de răgaz fără
    # ca testul să aștepte două minute. Se înlocuiește numai referința din
    # modul, nu modulul `time` al procesului.
    ceas = [1000.0]
    monkeypatch.setattr(ingest_service, "time",
                        SimpleNamespace(monotonic=lambda: ceas[0]))

    _coada_in_urma(jurnal, datetime.now(timezone.utc) - timedelta(minutes=10))
    run(ingest.poll_once())
    assert run(ingest.maybe_reap_sessions()) == 0
    ceas[0] += logins.REAP_GRACE_S + 1
    assert run(ingest.maybe_reap_sessions()) == 0

    assert db.stari, (
        "reaper-ul a refuzat să închidă ceva mai mult decât răgazul lui și "
        "n-a lăsat nicio urmă durabilă; «înfometat» și «n-a murit nimeni» "
        "rămân aceeași liniște")
    nume, stare, filigran = db.stari[-1]
    assert nume == logins.REAPER_MARKER
    assert stare == logins.REAPER_WAITING
    assert filigran == ingest._audit_seen_through, (
        "urma nu poartă filigranul, deci nu se poate spune CÂT de în urmă e "
        "ingestia — doar că e")


def test_a_working_reaper_says_so_in_the_database(tmp_path, monkeypatch) -> None:
    """Cealaltă direcție: dacă numai refuzurile ar lăsa urmă, un reaper sănătos
    ar arăta la fel ca unul care n-a pornit niciodată, iar verificarea n-ar
    avea ce citi."""
    from sentinel.services import ingest_service

    s = _sesiune()
    db = _DB([s], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions",
                        lambda *a, **k: _viu())

    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())
    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())

    assert db.stari, "un reaper care a rulat n-a scris nicio stare"
    assert db.stari[-1][1] == logins.REAPER_WORKING


def test_a_blind_scan_is_recorded_as_blind_not_as_working(
        tmp_path, monkeypatch) -> None:
    """Scanul orb trece prin aceeași cale ca unul bun — `reap_dead_sessions`
    refuză singur, ca garda să stea într-un loc. Dacă urma ar spune «working»,
    verificarea ar raporta sănătate despre un daemon care nu poate vedea nimic.
    """
    from sentinel.services import ingest_service

    db = _DB([_sesiune()], [_comanda()])
    ingest, jurnal = _ingest(tmp_path, db)
    monkeypatch.setattr(ingest_service, "read_live_sessions", lambda *a, **k: ORB)

    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())
    run(ingest.poll_once())
    run(ingest.maybe_reap_sessions())

    assert db.stari, "un scan orb n-a lăsat nicio urmă durabilă"
    assert db.stari[-1][1] == logins.REAPER_BLIND


def test_the_ingest_unit_can_still_see_the_hosts_processes() -> None:
    """Unitatea care rulează reaper-ul NU are voie să capete
    `ProtectProc=invisible`.

    Măsurat pe 15 septembrie 2026, înăuntrul sandbox-ului lui
    `sentinel-detect.service`, care îl are: utilizatorul `sentinel` vede zece
    procese, toate ale lui, iar `/proc/1/sessionid` nu există. Pus pe ingestie,
    același rând ar face reaper-ul complet orb — nu greșit, orb: controlul
    pozitiv îl oprește, dar rezumatele se întorc tăcut la douăsprezece ore, iar
    singurul semn e o linie de WARNING în jurnal.

    E o constrângere scrisă aici tocmai fiindcă trage în sens opus țintei de
    întărire din faza P10. Cine o schimbă trebuie să vadă testul ăsta picând și
    să decidă cu ochii deschiși, nu să afle peste o lună din faptul că sesiunile
    se închid iar cu douăsprezece ore întârziere.
    """
    from pathlib import Path

    radacina = Path(__file__).resolve().parents[2]
    unitate = (radacina / "deploy" / "systemd" / "sentinel-ingest.service"
               ).read_text(encoding="utf-8")
    linii = [ln.strip() for ln in unitate.splitlines()
             if ln.strip().startswith("ProtectProc=")]
    assert not any(ln.endswith(("invisible", "ptraceable", "noaccess"))
                   for ln in linii), (
        f"sentinel-ingest.service ascunde procesele altor utilizatori "
        f"({linii}); reaper-ul de sesiuni nu mai poate vedea nicio sesiune de "
        f"login, iar rezumatele se întorc la măturătoarea de 12 ore")


@pytest.mark.parametrize("cheie", ["2604", "2572"])
def test_the_two_stuck_rows_from_the_host_would_now_close(cheie: str) -> None:
    """Chiar cele două rânduri măsurate pe gazdă pe 15 septembrie 2026: `ses`
    2572 și 2604, amândouă deschise în tabelă, niciuna prezentă în
    `/proc/[0-9]*/sessionid` (unde erau 2472, 2473, 2475, 2484, 2512, 2624)."""
    s = _sesiune(session_key=cheie)
    db = _DB([s], [_comanda()])
    vii = _viu("2472", "2473", "2475", "2484", "2512", "2624")
    assert run(logins.reap_dead_sessions(db, vii, PROASPAT)) == 1


# ---------------------------------------------------------------------------
# Ce ajunge la operator: verificarea de sine
# ---------------------------------------------------------------------------
class _DBUrma:
    """Doar urma reaper-ului, așa cum o citește verificarea."""

    def __init__(self, rand: dict | None) -> None:
        self.rand = rand
        self.cereri: list[str] = []

    async def fetchrow(self, sql, *a):
        self.cereri.append(sql)
        assert "collector_cursors" in sql
        assert a and a[0] == logins.REAPER_MARKER
        return self.rand


def _urma(stare: str, *, filigran_s: float = 5.0,
          scrisa_s: float = 10.0) -> dict:
    acum = datetime.now(timezone.utc)
    return {"cursor": stare,
            "cursor_at": acum - timedelta(seconds=filigran_s),
            "updated_at": acum - timedelta(seconds=scrisa_s)}


_CFG_AUDITD = SimpleNamespace(ingest=SimpleNamespace(auditd=True))


def _verifica(rand: dict | None, cfg=_CFG_AUDITD):
    from sentinel.selfcheck import checks

    rezultate = run(checks.check_session_reaper(_DBUrma(rand), cfg))
    assert len(rezultate) == 1, (
        "verificarea emite mai mult sau mai puțin de o cheie; runner-ul "
        "reconciliază pe chei emise, deci a doua ar șterge un finding")
    return rezultate[0]


def test_the_selfcheck_reports_a_working_reaper_as_ok() -> None:
    """Dacă starea bună n-ar fi `ok`, verificarea ar suna la fiecare rulare și
    ar fi oprită de operator în două zile — iar atunci n-ar mai raporta nici
    ziua în care chiar se strică ceva."""
    r = _verifica(_urma(logins.REAPER_WORKING))
    assert r.status == "ok"
    assert r.key == "sessions:reaper"


def test_the_selfcheck_reports_a_blind_reaper() -> None:
    """Sub `ProtectProc=invisible` reaper-ul refuză să atingă vreun rând — ceea
    ce e corect — iar sesiunile se închid iar la douăsprezece ore. Fără
    verificarea asta, singurul semn e un WARNING în jurnalul care pe gazda de
    producție stă în RAM și dispare la reboot."""
    r = _verifica(_urma(logins.REAPER_BLIND))
    assert r.status == "degraded"
    assert r.bad


def test_the_selfcheck_reports_a_reaper_starved_by_the_audit_tail() -> None:
    """Chiar defectul din runda a doua: poarta închisă sub sarcină, fără ca
    nimic să spună asta nimănui. Un filigran vechi de ore înseamnă rezumate
    întârziate cu ore."""
    r = _verifica(_urma(logins.REAPER_WAITING, filigran_s=4 * 3600))
    assert r.status == "degraded"
    assert r.facts["watermark_lag_s"] >= 4 * 3600 - 5


def test_a_short_wait_is_not_an_alarm() -> None:
    """Amânarea de câteva secunde e forma NORMALĂ a porții: scanul se ia acum,
    dovada vine cu trecerea următoare. Raportată ca degradare, ar suna la
    fiecare vârf de trafic — iar o verificare care sună des nu mai e citită."""
    r = _verifica(_urma(logins.REAPER_WAITING, filigran_s=3.0))
    assert r.status == "ok"


def test_a_frozen_trace_is_not_read_as_the_state_it_froze_in() -> None:
    """Ingestia rescrie rândul la fiecare `REAPER_REFRESH_S` chiar când nu se
    schimbă nimic. Dacă starea scrisă ar fi citită fără vârsta ei, un daemon
    mort în „working" ar raporta «merge» pentru totdeauna — exact «serviciu
    activ o dată» din CLAUDE.md, mutat în bază."""
    from sentinel.selfcheck import checks

    r = _verifica(_urma(logins.REAPER_WORKING,
                        scrisa_s=checks.REAPER_STALE_S + 60))
    assert r.status == "degraded"
    assert "systemctl" in r.action


def test_a_missing_trace_is_unknown_not_ok() -> None:
    """„N-a scris nimeni niciodată" înseamnă ori cod vechi pe gazdă, ori
    `auditd` cerut în configurație cu fișierul de jurnal lipsă — caz în care
    reaper-ul iese înainte să se uite la gazdă. Raportat `ok`, ar fi tăcere în
    formă de sănătate."""
    r = _verifica(None)
    assert r.status == "unknown"
    assert r.facts["writer_ran"] is False


def test_an_unknown_state_word_is_not_read_as_health() -> None:
    """Vocabularul e un contract între `db/repo/logins.py` și verificare. Dacă
    s-ar despărți, o stare necunoscută citită ca `ok` ar stinge verificarea
    tăcut, pentru totdeauna."""
    r = _verifica(_urma("altceva"))
    assert r.status == "unknown"


def test_the_check_runs_at_all() -> None:
    """O verificare care nu e în `CHECKS` nu rulează niciodată, iar absența ei
    nu se vede nicăieri: panoul arată o listă întreagă de verzi."""
    from sentinel.selfcheck import checks

    assert ("sessions", checks.check_session_reaper) in checks.CHECKS
