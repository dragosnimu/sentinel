"""Proiecția: evenimente de audit -> sesiuni și istoric de comenzi.

Eșecurile pe care le previne, fiecare cu forma pe care ar avea-o pe ecran:

  * **9200 de sesiuni deschise.** `USER_LOGIN` se scrie și pentru încercările
    EȘUATE — pe gazda reală sunt 9200 la două zile, brute-force din internet.
    Deschise ca sesiuni, panoul ar arăta zece mii de oameni conectați, niciunul
    n-ar închide vreodată, iar alerta ar pleca la fiecare.
  * **Comenzile unui daemon puse în seama cuiva.** `ses=4294967295` înseamnă
    „niciun login". Tratat ca o cheie, ar aduna sub el fiecare proces de sistem
    într-o singură „sesiune" cu milioane de comenzi.
  * **Comenzi pierdute fiindcă au sosit prea devreme.** Ordinea înregistrărilor
    nu e garantată. O comandă aruncată fiindcă nu i s-a găsit sesiunea e o
    comandă pierdută definitiv.
  * **Un deploy alertat ca o intruziune.** `terminal=ssh` e o comandă rulată prin
    ssh fără terminal; `/dev/pts/N` e un om. 557 față de 29 pe șapte zile.
  * **Un rezumat care nu se potrivește cu lista de sub el.** Contoarele se
    recalculează din rânduri, nu se incrementează în cod.
  * **Contul de automatizare devenit cale de intrare tăcută.** Comenzile lui fără
    terminal nu se mai scriu — 405 777 pentru un singur deploy —, dar filtrul e
    pe TERMINALUL COMENZII: o logare interactivă pe același cont își păstrează
    comenzile, deci sesiunea se promovează și alerta pleacă. Un filtru pe cont ar
    fi tăiat chiar drumul alertei.
  * **Un filtru care taie în tăcere.** Rândurile aruncate se numără și ajung în
    jurnal; altfel „n-a rulat nimeni nimic" și „am aruncat 405 777 de rânduri" ar
    arăta identic.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.db.repo import logins
from sentinel.model.event import Event

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


def _login(key: str = "432", *, res: str = "success", terminal: str = "ssh",
           user: str | None = "operator", ts: datetime = NOW,
           ip: str | None = "198.51.100.7") -> Event:
    return Event(ts=ts, source="auditd", action="login", username=user, src_ip=ip,
                 raw={"record_type": "USER_LOGIN", "ses": key, "res": res,
                      "terminal": terminal, "auid": "1000"})


def _logout(key: str = "432", *, ts: datetime = NOW + timedelta(hours=1),
            terminal: str = "ssh") -> Event:
    return Event(ts=ts, source="auditd", action="logout", username="operator",
                 raw={"record_type": "USER_END", "ses": key, "terminal": terminal})


def _command(key: str = "432", argv: str = "/usr/bin/ls -la", *,
             exe: str = "/usr/bin/ls", ts: datetime = NOW,
             ppid: str = "100", tty: str = "(none)",
             user: str = "operator") -> Event:
    """O comandă. `tty` implicit `(none)`: cazul obișnuit e o automatizare.

    557 de sesiuni fără terminal față de 29 cu, măsurat pe gazdă — deci
    implicitul care nu surprinde e cel fără.
    """
    return Event(ts=ts, source="auditd", action="command", username=user,
                 raw={"record_type": "SYSCALL", "ses": key, "argv": argv,
                      "exe": exe, "ppid": ppid, "success": "yes", "tty": tty})


def _interval(sql: str, dupa: str) -> timedelta:
    """Marja scrisa in instructiune, dupa o anumita conditie.

    Citita din SQL, nu fixata aici: o fereastra largita in cod fara ca testul sa
    afle ar face ca proba despre repornire sa treaca degeaba. Dublul modeleaza
    ce SPUNE instructiunea.
    """
    rest = sql.split(dupa, 1)[1]
    m = re.search(r"interval '(\d+) (minute|hour|day)'", rest)
    assert m, f"nu gasesc intervalul dupa {dupa!r} in: {rest[:120]}"
    unitate = {"minute": "minutes", "hour": "hours", "day": "days"}[m.group(2)]
    return timedelta(**{unitate: int(m.group(1))})


class _DB:
    """Dublu de bază, cât să poarte proiecția.

    Ține sesiunile și comenzile ca liste de dicționare și răspunde la
    instrucțiunile pe care le scrie modulul. NU reimplementează semantica: acolo
    unde contează CE spune SQL-ul — filtrul de sesiune deschisă, recalcularea
    contoarelor — se cere textul, fiindcă un dublu care își face singur regulile
    probează dublul, nu codul.
    """

    def __init__(self) -> None:
        self.sessions: list[dict] = []
        self.commands: list[dict] = []
        self.sql: list[str] = []
        self._next_id = 1

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id - 1

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        if "INSERT INTO login_sessions" in sql and "ON CONFLICT" in sql:
            key, user, auid, ip, terminal, interactive, opened = a[:7]
            for s in self.sessions:
                if s["session_key"] == key and s["opened_at"] == opened:
                    s["username"] = s["username"] or user
                    s["src_ip"] = s["src_ip"] or ip
                    return {"id": s["id"]}
            # Se citeste din INSTRUCTIUNE care coloane sunt numite, nu din
            # numarul de argumente: instructiunea de inchidere refoloseste `$7`
            # pentru patru coloane, deci `len(a)` e acelasi in ambele cazuri.
            # Un dublu care ghiceste dupa lungime ar da acelasi raspuns si dupa
            # ce `alerted_at` ar fi scos din instructiune.
            inchisa = "closed_at" in sql.split("VALUES")[0]
            row = {"id": self._id(), "session_key": key, "username": user,
                   "auid": auid, "src_ip": ip, "terminal": terminal,
                   "interactive": interactive, "opened_at": opened,
                   "closed_at": opened if inchisa else None,
                   "command_count": 0, "sudo_count": 0,
                   "alerted_at": opened if "alerted_at" in sql.split("VALUES")[0]
                   else None}
            self.sessions.append(row)
            return {"id": row["id"]}
        if sql.strip().startswith("UPDATE login_sessions SET closed_at"):
            key, ts = a
            # Se filtrează CUM SPUNE instrucțiunea: numai sesiunile DESCHISE, cea
            # mai recentă. Un dublu care ar închide oricare ar face testul despre
            # două sesiuni ale aceluiași cont să treacă degeaba.
            assert "closed_at IS NULL" in sql, sql
            assert "ORDER BY opened_at DESC" in sql, sql
            candidati = [s for s in self.sessions
                         if s["session_key"] == key and s["closed_at"] is None]
            if not candidati:
                return None
            s = max(candidati, key=lambda x: x["opened_at"])
            s["closed_at"] = ts
            return {"id": s["id"]}
        raise AssertionError(f"fetchrow nerecunoscut: {sql}")

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        if "SELECT id FROM login_sessions" in sql:
            key = a[0]
            moment = a[1]
            if "closed_at >=" in sql and "opened_at <=" not in sql:
                # Cautarea unei sesiuni DEJA INCHISE, inainte de a fabrica una
                # noua la o a doua inchidere. Se cere fereastra ca text: fara
                # ea, o cheie refolosita dupa repornire ar inghiti inchiderea
                # unei sesiuni de acum trei luni.
                assert "interval" in sql, sql
                marja = _interval(sql, "closed_at >=")
                candidati = [s for s in self.sessions
                             if s["session_key"] == key
                             and s["closed_at"] is not None
                             and s["closed_at"] >= moment - marja]
                if not candidati:
                    return None
                return max(candidati, key=lambda x: x["opened_at"])["id"]

            # Cautarea sesiunii careia ii apartine o comanda: deschisa SAU deja
            # inchisa, dar numai daca momentul comenzii cade IN ea. Ambele
            # margini se cer ca text, fiindca ele sunt chiar proprietatea.
            assert "opened_at <=" in sql, sql
            assert "closed_at IS NULL OR closed_at >=" in sql, sql
            sus = _interval(sql, "opened_at <=")
            jos = _interval(sql, "closed_at >=")
            candidati = [
                s for s in self.sessions
                if s["session_key"] == key
                and s["opened_at"] <= moment + sus
                and (s["closed_at"] is None or s["closed_at"] >= moment - jos)]
            if not candidati:
                return None
            return max(candidati, key=lambda x: x["opened_at"])["id"]
        if "min(first_seen)" in sql:
            return None
        raise AssertionError(f"fetchval nerecunoscut: {sql}")

    async def execute(self, sql, *a):
        self.sql.append(sql)
        if "INSERT INTO session_commands" in sql:
            self.commands.append({
                "session_id": a[0], "session_key": a[1], "ts": a[2],
                "username": a[3], "exe": a[4], "argv": a[5], "cwd": a[6],
                "tty": a[7], "pid": a[8], "ppid": a[9], "success": a[10]})
            return "INSERT 0 1"
        if "UPDATE session_commands c SET session_id" in sql:
            assert "c.session_id IS NULL" in sql, sql
            # Aceeasi fereastra ca la cautare, si din acelasi motiv: o orfana de
            # azi lipita de sesiunea cu aceeasi cheie de acum trei luni ar pune
            # fapta cuiva in cronologia altcuiva.
            assert "c.ts >= s.opened_at" in sql, sql
            assert "s.closed_at IS NULL OR c.ts <= s.closed_at" in sql, sql
            sus = _interval(sql, "c.ts >= s.opened_at -")
            jos = _interval(sql, "c.ts <= s.closed_at +")
            sesiune = next((s for s in self.sessions if s["id"] == a[1]), None)
            n = 0
            for c in self.commands:
                if (c["session_key"] == a[0] and c["session_id"] is None
                        and sesiune is not None
                        and c["ts"] >= sesiune["opened_at"] - sus
                        and (sesiune["closed_at"] is None
                             or c["ts"] <= sesiune["closed_at"] + jos)):
                    c["session_id"] = a[1]
                    n += 1
            return f"UPDATE {n}"
        if "SET interactive = true" in sql:
            # Se cere ca promovarea sa citeasca din COMENZI, nu din logare:
            # `USER_LOGIN` nu poarta terminalul, iar o versiune care l-ar citi
            # de acolo ar marca fiecare sesiune drept neinteractiva.
            assert "FROM session_commands" in sql, sql
            assert "tty ~" in sql, sql
            import re as _re
            # Ordinea se citește DIN INSTRUCȚIUNE, nu se presupune: `DISTINCT ON`
            # alege primul rând al fiecărei grupe, iar care e primul depinde de
            # `ORDER BY`. Un dublu care ar lua mereu prima comandă ar trece și
            # dacă instrucțiunea ar cere ultima.
            ordine = _re.search(r"ORDER BY session_id, id( DESC)?", sql)
            assert ordine, sql
            invers = bool(ordine.group(1))
            tipar = _re.compile(a[1])
            n = 0
            for s in self.sessions:
                if s["id"] not in a[0] or s.get("interactive"):
                    continue
                cu_tty = [c for c in self.commands
                          if c["session_id"] == s["id"]
                          and c.get("tty") and tipar.match(c["tty"])]
                if cu_tty:
                    s["interactive"] = True
                    s["terminal"] = (cu_tty[-1] if invers else cu_tty[0])["tty"]
                    n += 1
            return f"UPDATE {n}"
        if "UPDATE login_sessions s" in sql:
            # Contoarele se recalculează DIN RÂNDURI. Se cere textul care o
            # spune: o versiune care ar incrementa în cod ar trece altfel.
            assert "count(*)" in sql, sql
            assert "FROM session_commands" in sql, sql
            priv = set(a[1])
            for s in self.sessions:
                ale_ei = [c for c in self.commands if c["session_id"] == s["id"]]
                s["command_count"] = len(ale_ei)
                s["sudo_count"] = sum(
                    1 for c in ale_ei
                    if (c["exe"] or "").rsplit("/", 1)[-1] in priv)
            return "UPDATE 1"
        raise AssertionError(f"execute nerecunoscut: {sql}")

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        return []


# ---------------------------------------------------------------------------
# Ce NU are voie să devină o sesiune
# ---------------------------------------------------------------------------
def test_a_failed_login_does_not_open_a_session() -> None:
    """9200 la două zile pe gazda reală. Deschise, panoul ar arăta zece mii de
    oameni conectați, iar alerta ar pleca la fiecare."""
    db = _DB()
    run(logins.project(db, [_login(res="failed")]))
    assert db.sessions == [], "o încercare eșuată a deschis o sesiune"


def test_a_process_without_a_login_session_is_skipped() -> None:
    """`ses=4294967295` e „niciun login".

    Tratat ca o cheie, ar aduna fiecare daemon și fiecare proces din containere
    într-o singură „sesiune" care nu se închide niciodată.
    """
    db = _DB()
    run(logins.project(db, [_command(key="4294967295"), _login(key="unset")]))
    assert db.sessions == []
    assert db.commands == []


def test_events_from_other_sources_are_ignored() -> None:
    """Numai auditd poartă `ses`. Un eveniment sshd cu aceleași câmpuri ar
    produce o a doua sesiune pentru aceeași logare."""
    db = _DB()
    ev = _login()
    ev.source = "sshd"
    run(logins.project(db, [ev]))
    assert db.sessions == []


# ---------------------------------------------------------------------------
# Deschiderea, închiderea
# ---------------------------------------------------------------------------
def test_a_successful_login_opens_a_session_with_who_and_from_where() -> None:
    db = _DB()
    run(logins.project(db, [_login()]))
    assert len(db.sessions) == 1
    s = db.sessions[0]
    assert s["username"] == "operator"
    assert s["src_ip"] == "198.51.100.7"
    assert s["opened_at"] == NOW
    assert s["closed_at"] is None


def test_the_same_login_seen_twice_does_not_open_two_sessions() -> None:
    """Cursorul se reia la repornire, deci aceleași linii se citesc din nou.

    Două sesiuni pentru o singură logare înseamnă două alerte și un rezumat care
    numără comenzile de două ori.
    """
    db = _DB()
    run(logins.project(db, [_login()]))
    run(logins.project(db, [_login()]))
    assert len(db.sessions) == 1


def test_a_logout_closes_the_most_recent_open_session() -> None:
    db = _DB()
    run(logins.project(db, [_login(), _logout()]))
    assert db.sessions[0]["closed_at"] == NOW + timedelta(hours=1)


def test_two_sessions_of_the_same_account_do_not_close_each_other() -> None:
    """Un om și un deploy, în același timp, sub același cont.

    Cheile sunt diferite fiindcă nucleul le dă diferite. Închise una pe alta,
    rezumatul unei sesiuni ar conține comenzile celeilalte.
    """
    db = _DB()
    run(logins.project(db, [_login("432"), _login("433", ts=NOW + timedelta(minutes=1))]))
    run(logins.project(db, [_logout("433", ts=NOW + timedelta(minutes=2))]))

    dupa_cheie = {s["session_key"]: s for s in db.sessions}
    assert dupa_cheie["433"]["closed_at"] is not None
    assert dupa_cheie["432"]["closed_at"] is None, (
        "s-a închis sesiunea greșită")


def test_a_logout_without_a_login_still_records_that_the_session_existed() -> None:
    """Colectorul poate porni la mijlocul unei sesiuni.

    Aruncată, ar dispărea și dovada că sesiunea a existat. Creată, nu are ce
    alerta — mesajul ar sosi după ce omul a plecat.
    """
    db = _DB()
    run(logins.project(db, [_logout("999")]))
    assert len(db.sessions) == 1
    s = db.sessions[0]
    assert s["closed_at"] is not None
    assert s["alerted_at"] is not None, (
        "o sesiune deja încheiată ar produce o alertă «cineva s-a logat»")


# ---------------------------------------------------------------------------
# Interactiv sau nu
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tty,asteptat", [
    ("pts0", True), ("pts12", True), ("tty1", True),
    ("(none)", False), ("", False), ("ssh", False), ("cron", False),
])
def test_a_tty_tells_a_human_from_a_script(tty: str, asteptat: bool) -> None:
    """Temelia întregii politici de alertare — și NU e câmpul care pare.

    `USER_LOGIN` scrie `terminal=ssh` pentru orice conexiune prin ssh, cu pty sau
    fără. Verificat pe gazdă: o sesiune deschisă cu `ssh -tt` primește tot
    `terminal=ssh`. Câmpul ăla e numele SERVICIULUI.

    Ce deosebește cu adevărat un om de un script e `tty` de pe `SYSCALL`: `pts0`
    pentru o sesiune cu terminal, `(none)` pentru una fără. Prima versiune a citit
    câmpul greșit și a marcat FIECARE sesiune drept neinteractivă — adică alerta
    de logare n-ar fi plecat niciodată, iar tăcerea aia arată exact ca «nu s-a
    logat nimeni».
    """
    assert logins.is_interactive(tty) is asteptat


def test_an_unknown_terminal_counts_as_a_script() -> None:
    """Greșeala în direcția asta produce o alertă ÎNTÂRZIATĂ, nu una falsă.

    Pe un canal care nu se poate tăcea, a doua e cea care distruge canalul.
    """
    assert logins.is_interactive(None) is False


def test_a_session_becomes_interactive_at_its_first_terminal_command() -> None:
    """Promovarea: logarea nu poartă terminalul, prima comandă îl poartă.

    Consecința, scrisă ca să fie citită: alerta pleacă la PRIMA COMANDĂ, nu la
    logare. Cine se conectează și nu tastează nimic nu produce niciun mesaj — dar
    nici nu face nimic.
    """
    db = _DB()
    run(logins.project(db, [_login()]))
    assert db.sessions[0]["interactive"] is False, (
        "sesiunea a fost declarată interactivă din logare, unde informația nu "
        "există")

    run(logins.project(db, [_command(tty="pts3")]))
    assert db.sessions[0]["interactive"] is True
    assert db.sessions[0]["terminal"] == "pts3", (
        "panoul ar arăta «ssh» pentru o sesiune care s-a folosit de pts3")


def test_a_script_session_stays_non_interactive() -> None:
    """Garda celuilalt sens: cele 557 de sesiuni de deploy pe săptămână.

    Promovate, canalul ar produce ~80 de mesaje pe zi și s-ar opri într-o
    săptămână.
    """
    db = _DB()
    run(logins.project(db, [_login(), _command(), _command()]))
    assert db.sessions[0]["interactive"] is False


def test_a_command_is_attached_to_its_session() -> None:
    db = _DB()
    run(logins.project(db, [_login(), _command()]))
    assert len(db.commands) == 1
    assert db.commands[0]["session_id"] == db.sessions[0]["id"]


def test_a_command_that_arrives_before_its_login_is_not_lost() -> None:
    """Ordinea înregistrărilor nu e garantată.

    Aruncată, ar fi o comandă pierdută definitiv — exact în minutul în care
    cineva tocmai a intrat.
    """
    db = _DB()
    run(logins.project(db, [_command()]))
    assert len(db.commands) == 1, "comanda sosită prea devreme a fost aruncată"
    assert db.commands[0]["session_id"] is None
    assert db.commands[0]["session_key"] == "432"

    run(logins.project(db, [_login()]))
    assert db.commands[0]["session_id"] == db.sessions[0]["id"], (
        "comanda orfană nu a fost legată de sesiune când aceasta a apărut")


def test_the_command_keeps_what_makes_it_readable() -> None:
    db = _DB()
    run(logins.project(db, [_login(),
                            _command(argv="/usr/bin/systemctl restart nginx",
                                     exe="/usr/bin/systemctl")]))
    c = db.commands[0]
    assert c["argv"] == "/usr/bin/systemctl restart nginx"
    assert c["exe"] == "/usr/bin/systemctl"
    assert c["ppid"] == 100, "fără părinte, un deploy și un om arată la fel"
    assert c["success"] is True


def test_a_command_without_arguments_is_still_recorded() -> None:
    """`argv` e NOT NULL în schemă, iar `EXECVE` poate lipsi cu totul.

    Cheia se ȘTERGE din `raw`, nu se pune goală: un binar pornit fără argumente
    nu produce nicio înregistrare `EXECVE`, deci colectorul nu pune cheia deloc.
    Cu ea prezentă și goală, un `raw["argv"]` fără valoare implicită ar trece
    testul și ar cădea în producție cu `KeyError` — adică lotul întreg al rundei
    s-ar pierde, nu doar comanda.
    """
    db = _DB()
    ev = _command()
    del ev.raw["argv"]
    run(logins.project(db, [_login(), ev]))
    assert len(db.commands) == 1, "o comandă fără argumente a fost sărită"
    assert db.commands[0]["argv"] == ""
    assert db.commands[0]["exe"] == "/usr/bin/ls", (
        "binarul s-a pierdut odată cu argumentele")


# ---------------------------------------------------------------------------
# Contoarele
# ---------------------------------------------------------------------------
def test_the_counters_are_recomputed_from_the_rows() -> None:
    """Un `+= n` ținut în cod se desincronizează la prima repornire la mijlocul
    unui lot, iar rezumatul ar raporta un număr care nu se potrivește cu lista
    de sub el."""
    db = _DB()
    run(logins.project(db, [
        _login(),
        _command(argv="/usr/bin/ls", exe="/usr/bin/ls"),
        _command(argv="/usr/bin/sudo systemctl restart x", exe="/usr/bin/sudo"),
        _command(argv="/usr/bin/cat /etc/hosts", exe="/usr/bin/cat"),
    ]))
    s = db.sessions[0]
    assert s["command_count"] == 3
    assert s["sudo_count"] == 1, (
        "«412 comenzi» nu spune nimic; «412 comenzi, 3 cu sudo» spune ce s-a "
        "întâmplat")


def test_the_projection_reports_what_it_did() -> None:
    """Apelantul trebuie să poată loga fapte, nu intenții."""
    db = _DB()
    counts = run(logins.project(db, [_login(), _command(), _command(),
                                     _logout()]))
    assert counts["sessions_opened"] == 1
    assert counts["sessions_closed"] == 1
    assert counts["commands"] == 2


def test_an_empty_batch_touches_nothing() -> None:
    db = _DB()
    counts = run(logins.project(db, []))
    assert counts["commands"] == 0
    assert db.sql == [], "un lot gol a interogat baza"


# ---------------------------------------------------------------------------
# Ce s-a măsurat pe gazdă, la prima livrare — 24 august 2026
# ---------------------------------------------------------------------------
def test_repeated_logouts_do_not_create_phantom_sessions() -> None:
    """Măsurat: **175 de `USER_END` pentru 55 de logări reușite**.

    PAM emite o închidere pentru FIECARE strat de sesiune — cea a lui sshd, plus
    cele deschise de `sudo` sau `su` înăuntru. Prima o închide pe cea adevărată;
    a doua nu mai găsește niciuna deschisă și, cu prima versiune a codului,
    fabrica o sesiune nouă, deja închisă, fără cont și fără adresă.

    Rezultatul pe ecran era o listă în care fiecare logare apărea de două-trei
    ori, cea reală amestecată cu fantomele ei — iar fantoma avea `username` gol,
    deci arăta exact ca o logare pe care Sentinel n-a putut s-o atribuie nimănui.
    """
    db = _DB()
    run(logins.project(db, [_login("432")]))
    run(logins.project(db, [_logout("432"),
                            _logout("432", ts=NOW + timedelta(hours=1, seconds=1)),
                            _logout("432", ts=NOW + timedelta(hours=1, seconds=2))]))

    assert len(db.sessions) == 1, (
        f"{len(db.sessions)} rânduri pentru o singură sesiune: închiderile "
        f"repetate au fabricat sesiuni-fantomă")
    assert db.sessions[0]["username"] == "operator"


def test_a_command_arriving_after_the_session_closed_is_still_attached() -> None:
    """Măsurat: **299 de comenzi orfane din 2070** — 14%.

    O sesiune de deploy trăiește o secundă. Comenzile ei sosesc în același lot cu
    închiderea, sau în următorul, iar prima versiune căuta doar sesiuni DESCHISE:
    o comandă sosită după închidere rămânea fără părinte pentru totdeauna.

    Consecința nu era o comandă pierdută — rândul se scria oricum —, ci una care
    nu apare în niciun rezumat și în nicio cronologie de sesiune. Adică prezentă
    în tabelă și invizibilă acolo unde cineva ar căuta-o.
    """
    db = _DB()
    run(logins.project(db, [_login("432"), _logout("432")]))
    run(logins.project(db, [_command("432", ts=NOW + timedelta(minutes=30))]))

    assert len(db.commands) == 1
    assert db.commands[0]["session_id"] == db.sessions[0]["id"], (
        "comanda a rămas orfană fiindcă sesiunea era deja închisă")


def test_a_command_is_not_attached_to_a_session_from_another_boot() -> None:
    """Garda celuilalt sens, și motivul pentru care nu se ia pur și simplu
    ultima sesiune cu cheia asta.

    `ses` se renumerotează de la zero după repornire. O comandă de azi lipită de
    sesiunea cu aceeași cheie de acum trei luni ar pune fapta cuiva în cronologia
    altcuiva — iar asta e mai rău decât o comandă orfană, fiindcă arată corect.
    """
    db = _DB()
    veche = NOW - timedelta(days=90)
    run(logins.project(db, [_login("432", ts=veche),
                            _logout("432", ts=veche + timedelta(minutes=5))]))
    run(logins.project(db, [_command("432", ts=NOW)]))

    assert db.commands[0]["session_id"] is None, (
        "comanda de azi a fost lipită de o sesiune de acum trei luni")


# ---------------------------------------------------------------------------
# Contul de automatizare — 25 august 2026
#
# Un singur deploy a produs 405 777 de comenzi în 140 de secunde: `systemctl` de
# 320 591 de ori și `sleep` de 173 376, adică buclele de așteptare ale
# instalatorului. Replica de pe agregator a crescut de la 83 MB la 909 MB în
# câteva ore.
# ---------------------------------------------------------------------------
DEPLOY = "sentinel-deploy"


def test_an_automation_command_without_a_terminal_is_not_written() -> None:
    """Cele 405 777 de rânduri ale unui deploy, și numărul care spune că au căzut.

    Fără filtru, tabela crește cu ~400 000 de rânduri la fiecare livrare, iar pe
    agregator — găzduire partajată, cu cotă — o bază plină nu înseamnă „tabela e
    mare", înseamnă ingestia refuzată pentru TOATE fluxurile.

    Fără contor, jurnalul n-ar putea deosebi „n-a rulat nimeni nimic" de „am
    aruncat 405 777 de rânduri conform politicii" — iar un filtru care într-o zi
    începe să prindă și altceva n-ar fi observat de nimeni.
    """
    db = _DB()
    counts = run(logins.project(
        db,
        [_login(user=DEPLOY),
         _command(argv="/usr/bin/systemctl is-active nginx",
                  exe="/usr/bin/systemctl", user=DEPLOY),
         _command(argv="/usr/bin/sleep 1", exe="/usr/bin/sleep", user=DEPLOY)],
        skip_accounts=[DEPLOY]))

    assert db.commands == [], "comenzile contului de automatizare au ajuns în tabelă"
    assert counts["commands_skipped"] == 2
    assert counts["commands"] == 0, (
        "rândurile aruncate au fost numărate și ca scrise: jurnalul ar raporta "
        "o muncă pe care baza n-a văzut-o")
    assert len(db.sessions) == 1, (
        "rândul de sesiune a dispărut odată cu comenzile — «s-a deschis o "
        "sesiune de deploy» e faptul cu valoare de securitate")


def test_an_interactive_login_on_the_automation_account_is_still_recorded() -> None:
    """Gaura de securitate pe care o păzește filtrul pe TTY, nu pe cont.

    Sesiunea devine `interactive` abia la prima comandă cu terminal real
    (`_promote_interactive`), iar `announce_new_sessions()` cere `interactive =
    true`. Un filtru de forma „tot ce rulează contul de deploy" ar arunca și
    comanda aia: sesiunea n-ar fi promovată niciodată, alerta n-ar pleca
    niciodată, iar contul de automatizare — care are `sudo NOPASSWD: ALL` — ar
    deveni singura cale de intrare pe care Sentinel tace.

    Deci: `ssh sentinel-deploy@gazdă` cu shell adevărat capătă `pts0`, comenzile
    lui se păstrează, sesiunea se promovează.
    """
    db = _DB()
    counts = run(logins.project(
        db,
        [_login(user=DEPLOY), _command(user=DEPLOY, tty="pts0")],
        skip_accounts=[DEPLOY]))

    assert len(db.commands) == 1, (
        "comanda tastată de un om pe contul de automatizare a fost aruncată")
    assert counts["commands_skipped"] == 0
    assert db.sessions[0]["interactive"] is True, (
        "sesiunea nu s-a promovat, deci alerta de logare nu ar pleca niciodată")
    assert db.sessions[0]["terminal"] == "pts0"


def test_an_empty_account_list_drops_nothing() -> None:
    """Implicitul livrat, și ce înseamnă o configurație pe care nimeni n-a scris-o.

    `history.skip_command_accounts` e gol în lipsa lui, iar gol trebuie să
    însemne exact comportamentul de dinaintea filtrului. Altfel o instalare care
    nu cunoaște cheia ar începe tăcut să piardă istoric.
    """
    db = _DB()
    counts = run(logins.project(
        db, [_login(user=DEPLOY), _command(user=DEPLOY), _command(user=DEPLOY)],
        skip_accounts=[]))

    assert len(db.commands) == 2, "lista goală a aruncat comenzi"
    assert counts["commands_skipped"] == 0
    assert counts["commands"] == 2

    # Și fără al treilea argument deloc: un apelant care nu spune nimic
    # păstrează tot.
    db2 = _DB()
    run(logins.project(db2, [_login(user=DEPLOY), _command(user=DEPLOY)]))
    assert len(db2.commands) == 1


def test_a_human_command_without_a_terminal_is_kept() -> None:
    """`ssh operator@gazdă 'uptime'` — fără terminal, dar al unui om.

    Filtrul e legat de CONT, nu de absența terminalului: pe gazdă sunt 557 de
    sesiuni fără terminal pe săptămână, iar cele ale operatorului sunt chiar
    istoricul pentru care există tabela. O regulă „fără tty = se aruncă" ar
    șterge diagnosticele rulate de la distanță de om.
    """
    db = _DB()
    counts = run(logins.project(
        db,
        [_login(user="operator"),
         _command(argv="/usr/bin/uptime", exe="/usr/bin/uptime", user="operator")],
        skip_accounts=[DEPLOY]))

    assert len(db.commands) == 1, (
        "comanda unui om fără terminal a fost aruncată: filtrul s-a legat de "
        "absența tty-ului, nu de cont")
    assert counts["commands_skipped"] == 0


def test_the_counter_of_a_session_counts_only_the_rows_that_exist() -> None:
    """Contorul și lista de sub el trebuie să spună același lucru.

    O sesiune cu o comandă tastată și două aruncate are UNA. Un rezumat care
    spune «3 comenzi» și arată una singură e chiar starea pe care recalcularea
    din rânduri există s-o împiedice — iar filtrul nou e exact locul unde cele
    două puteau să se despartă.
    """
    db = _DB()
    counts = run(logins.project(
        db,
        [_login(user=DEPLOY),
         _command(user=DEPLOY, tty="pts0", argv="/usr/bin/id", exe="/usr/bin/id"),
         _command(user=DEPLOY, argv="/usr/bin/sleep 1", exe="/usr/bin/sleep"),
         _command(user=DEPLOY, argv="/usr/bin/sleep 1", exe="/usr/bin/sleep")],
        skip_accounts=[DEPLOY]))

    s = db.sessions[0]
    assert len(db.commands) == 1
    assert s["command_count"] == 1, (
        f"contorul spune {s['command_count']}, tabela are {len(db.commands)}")
    assert counts["commands"] == 1 and counts["commands_skipped"] == 2


def test_a_session_whose_commands_were_all_dropped_keeps_a_truthful_counter() -> None:
    """Cazul de margine al recalculării: nu s-a scris niciun rând.

    `_refresh_counters` primește sesiunile atinse din `known`, iar o sesiune ale
    cărei comenzi au căzut toate nu are ce recalcula. Contorul ei trebuie să
    rămână zero — nu numărul comenzilor aruncate, și nici contorul altei
    sesiuni.
    """
    db = _DB()
    run(logins.project(db, [_login(user=DEPLOY)], skip_accounts=[DEPLOY]))
    counts = run(logins.project(
        db,
        [_command(user=DEPLOY, argv="/usr/bin/sleep 1", exe="/usr/bin/sleep"),
         _command(user=DEPLOY, argv="/usr/bin/sudo systemctl restart x",
                  exe="/usr/bin/sudo")],
        skip_accounts=[DEPLOY]))

    s = db.sessions[0]
    assert s["command_count"] == 0 and s["sudo_count"] == 0, (
        "contorul a numărat rânduri care nu există")
    assert s["interactive"] is False
    assert counts["commands_skipped"] == 2


def test_dropping_commands_does_not_break_orphan_linking() -> None:
    """Legarea orfanilor pleacă de la LOGARE, nu de la comenzi.

    O comandă sosită înaintea logării ei se scrie cu `session_id` NULL și se
    leagă mai târziu. Dacă filtrul ar scoate din evidență și sesiunile pe care
    nu le mai atinge nicio comandă, o orfană a unui OM sosită în același lot cu
    zgomotul deploy-ului ar rămâne nelegată pentru totdeauna — prezentă în
    tabelă, invizibilă în orice cronologie.
    """
    db = _DB()
    run(logins.project(
        db,
        [_command(key="500", user="operator", argv="/usr/bin/uptime",
                  exe="/usr/bin/uptime"),
         _command(key="432", user=DEPLOY, argv="/usr/bin/sleep 1",
                  exe="/usr/bin/sleep")],
        skip_accounts=[DEPLOY]))
    assert len(db.commands) == 1 and db.commands[0]["session_id"] is None

    counts = run(logins.project(db, [_login(key="500", user="operator")],
                                skip_accounts=[DEPLOY]))
    assert counts["orphans_attached"] == 1
    assert db.commands[0]["session_id"] == db.sessions[0]["id"]


# ---------------------------------------------------------------------------
# De la daemon până în jurnal
#
# Proiecția poate fi corectă și complet inertă: dacă lista de conturi nu ajunge
# de la configurație la `project()`, filtrul e o cheie de configurare care nu
# face nimic — și arată identic cu una care funcționează.
# ---------------------------------------------------------------------------
def _linii_comanda(argv: list[str], *, ses: str = "432", user: str = DEPLOY,
                   tty: str = "(none)", serial: str = "178100") -> list[str]:
    """Liniile pe care le scrie chiar nucleul pentru un `execve` supravegheat.

    Prin parserul adevărat, nu prin `Event` construit de mână: filtrul citește
    `ev.username` și `raw["tty"]`, iar dacă vreunul dintre ele ar fi numit altfel
    de colector, un eveniment fabricat aici n-ar afla-o niciodată.
    """
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return [
        f'type=SYSCALL msg=audit(1787575800.000:{serial}): arch=c000003e syscall=59 '
        f'success=yes exit=0 ppid=1814690 pid=1814800 auid=1001 uid=1001 '
        f'ses={ses} tty={tty} comm="{argv[0].rsplit("/", 1)[-1]}" '
        f'exe="{argv[0]}" key="sentinel_cmd"AUID="{user}" UID="{user}"',
        f'type=EXECVE msg=audit(1787575800.000:{serial}): argc={len(argv)} {args}',
    ]


def _ingest_peste(tmp_path, monkeypatch, conturi, linii):
    """Un `Ingest` care citește liniile date și scrie într-un dublu de bază."""
    from types import SimpleNamespace

    from sentinel.collectors import nginx_tail
    from sentinel.services import ingest_service

    jurnal = tmp_path / "audit.log"
    jurnal.write_text("", encoding="utf-8")
    _, cursor0 = nginx_tail.read_new_lines(str(jurnal), None)

    cfg = SimpleNamespace(ingest=SimpleNamespace(exclude_sources=()),
                          history=SimpleNamespace(skip_command_accounts=conturi))
    db = _DB()
    ingest = ingest_service.Ingest(cfg, db)
    ingest._audit_path = str(jurnal)
    ingest._audit_cursor = cursor0

    async def fake_insert(_db, events):
        return len(events)

    async def fake_set_cursor(_db, name, cursor, *, events_seen=0):
        return None

    monkeypatch.setattr(ingest_service.events_repo, "insert_batch", fake_insert)
    monkeypatch.setattr(ingest_service.events_repo, "set_cursor", fake_set_cursor)

    with jurnal.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(linii) + "\n")
    run(ingest.poll_once())
    return db


def test_the_configured_accounts_reach_the_projection(tmp_path, monkeypatch) -> None:
    """Cheia de configurare care nu e legată de nimic.

    `project()` poate fi perfect corect și complet inert: dacă daemonul nu îi dă
    `history.skip_command_accounts`, operatorul scrie contul în `sentinel.yaml`,
    repornește, iar tabela crește mai departe cu 405 777 de rânduri la fiecare
    deploy. O configurație care nu are efect arată exact ca una care are.

    Se citește faptul de la capătul lanțului — ce a ajuns în tabelă —, nu
    argumentul cu care a fost chemată funcția.
    """
    linii = _linii_comanda(["/usr/bin/sleep", "1"])

    cu_filtru = _ingest_peste(tmp_path, monkeypatch, (DEPLOY,), linii)
    assert cu_filtru.commands == [], (
        "lista din configurație nu ajunge la proiecție: filtrul e o cheie moartă")

    fara_filtru = _ingest_peste(tmp_path, monkeypatch, (), linii)
    assert len(fara_filtru.commands) == 1, (
        "cu lista goală comanda trebuie să se scrie — altfel testul de mai sus "
        "ar trece și dacă nimic nu s-ar mai înregistra vreodată")


def test_the_dropped_rows_reach_the_journal(tmp_path, monkeypatch, caplog) -> None:
    """Un filtru tăcut nu se poate deosebi de o gazdă liniștită.

    Un deploy produce sute de loturi cu comenzi și NICIO logare. Dacă linia de
    jurnal se scrie doar când s-a deschis sau s-a închis o sesiune, cele 405 777
    de rânduri aruncate nu lasă nicio urmă — iar în ziua în care filtrul începe
    să prindă și altceva decât contul de automatizare, nimic nu o spune.
    """
    # Seriale diferite: două grupuri cu același serial sunt CORELATE de colector
    # într-un singur eveniment, iar testul ar cere doi și ar primi unul.
    linii = (_linii_comanda(["/usr/bin/sleep", "1"], serial="178100")
             + _linii_comanda(["/usr/bin/systemctl", "is-active", "nginx"],
                              serial="178101"))

    with caplog.at_level("INFO", logger="sentinel.services.ingest_service"):
        db = _ingest_peste(tmp_path, monkeypatch, (DEPLOY,), linii)

    assert db.commands == []
    aruncate = [r for r in caplog.records
                if getattr(r, "commands_skipped", 0) > 0]
    assert aruncate, (
        "niciun rând de jurnal despre comenzile aruncate: «n-a rulat nimeni "
        "nimic» și «am aruncat 405 777 de rânduri» arată identic")
    assert getattr(aruncate[0], "commands_skipped") == 2
    assert getattr(aruncate[0], "commands") == 0


# ---------------------------------------------------------------------------
# Configurația livrată, contul creat de instalator, și un deploy adevărat
# ---------------------------------------------------------------------------
def _cont_din_instalator() -> str:
    """`DEPLOY_ACCOUNT` implicit din `deploy/install.sh` — contul care CHIAR se
    creează pe gazdă, cu `NOPASSWD: ALL`."""
    import re as _re

    instalator = (Path(__file__).resolve().parents[2]
                  / "deploy" / "install.sh").read_text(encoding="utf-8")
    m = _re.search(r'DEPLOY_ACCOUNT="\$\{DEPLOY_ACCOUNT:-([A-Za-z0-9_-]+)\}"',
                   instalator)
    assert m, "install.sh nu mai definește DEPLOY_ACCOUNT în forma citită aici"
    return m.group(1)


def _conturi_din_sablon() -> list[str]:
    """`history.skip_command_accounts` din chiar `sentinel.yaml.tmpl` livrat,
    trecut prin `load_config` — nu citit cu un grep."""
    from sentinel.config import load_config

    import tempfile

    sablon = (Path(__file__).resolve().parents[2]
              / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    for tinta, valoare in {
        "@@HOSTNAME@@": "host.example.test",
        "@@DOMAIN@@": "panel.example.test",
        "@@NGINX_MODE@@": "dedicated",
        "@@PUBLIC_PORT@@": "8443",
        "@@IFACE@@": "eth0",
        "@@BPF_FILTER@@": "",
        "@@SURICATA_ENABLED@@": "true",
        "@@AUDITD_ENABLED@@": "true",
        "@@TELEGRAM_CHAT_ID@@": "1",
        "@@EXTRA_ALLOWLIST@@": '"192.0.2.10"',
    }.items():
        sablon = sablon.replace(tinta, valoare)
    assert "@@" not in sablon, "un @@placeholder@@ nou, pe care testul nu-l umple"

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "sentinel.yaml"
        p.write_text(sablon, encoding="utf-8")
        return list(load_config(p).history.skip_command_accounts)


def _deploy_events(user: str, key: str = "2521") -> list[Event]:
    """Semnătura reală a unui deploy, măsurată pe gazdă.

    `systemctl` de 320 591 de ori și `sleep` de 173 376 — buclele de așteptare
    ale instalatorului —, plus `grep`-urile lui, toate fără terminal. Aici sunt
    câte una din fiecare, plus un rând cu `tty` LIPSĂ cu totul: nucleul nu scrie
    întotdeauna câmpul, iar «nu știu ce terminal a avut» nu e «a avut unul».
    """
    return [
        _login(key=key, user=user, ip="203.0.113.10"),
        _command(key=key, user=user, argv="/usr/bin/systemctl is-active nginx",
                 exe="/usr/bin/systemctl"),
        _command(key=key, user=user, argv="/usr/bin/sleep 1",
                 exe="/usr/bin/sleep"),
        _command(key=key, user=user, argv="/usr/bin/grep -q ok /tmp/x",
                 exe="/usr/bin/grep", tty=None),
    ]


def test_the_shipped_configuration_actually_drops_a_real_deploy_burst() -> None:
    """Șablonul livrat + contul creat de instalator + un flux de deploy adevărat.

    ## De ce testul ăsta îl înlocuiește pe cel dinainte

    `test_the_template_skips_the_account_the_installer_actually_creates` compara
    NUMELE din `install.sh` cu NUMELE din `sentinel.yaml.tmpl` — două fișiere din
    depozit, care pot fi perfect de acord între ele și în dezacord cu gazda. Și
    exact asta s-a întâmplat: deploy-ul se rula sub contul de logare al
    operatorului, iar `auid` e uid-ul de LOGARE și supraviețuiește lui `sudo`,
    deci cele 405 777 de comenzi se scriau sub numele lui. Filtrul nu potrivea nimic, tabela creștea
    la fiecare rulare, iar testul era verde.

    O aserțiune pe prezența unui nume nu spune nimic despre decizia luată din el.
    Aici se cere DECIZIA: dându-se fluxul, proiecția aruncă rândurile și le
    numără.
    """
    cont = _cont_din_instalator()
    conturi = _conturi_din_sablon()

    db = _DB()
    counts = run(logins.project(db, _deploy_events(cont), skip_accounts=conturi))

    assert counts["commands_skipped"] == 3, (
        f"configurația livrată ({conturi}) nu aruncă comenzile contului pe care "
        f"instalatorul îl creează ({cont}): filtrul e inert")
    assert db.commands == [], "un rând al deploy-ului a ajuns totuși în tabelă"
    assert counts["commands"] == 0
    assert len(db.sessions) == 1, (
        "rândul de sesiune a dispărut: «s-a deschis o sesiune de deploy» e "
        "faptul cu valoare de securitate")
    assert db.sessions[0]["command_count"] == 0


def test_both_deploy_scripts_default_to_the_account_the_filter_knows() -> None:
    """Cele trei implicituri care trebuie să fie același nume.

    Testul de deasupra probează că filtrul chiar aruncă comenzile contului pe
    care instalatorul îl creează. Ce nu poate proba e sub ce cont RULEAZĂ
    deploy-ul — și exact acolo a fost defectul: `--user` era obligatoriu, fiecare
    rulare numea contul de logare al operatorului, `auid` supraviețuiește lui
    `sudo`, iar cele 405 777 de comenzi se scriau sub un nume pe care filtrul nu-l
    cunoștea. Măsurat pe gazdă: filtrul ar fi șters 1 143 din 2 978 485 de rânduri.

    E o aserțiune pe NUME, și asta se spune aici, nu se ascunde: nu poate ști ce
    tastează operatorul, nici cu ce `DEPLOY_ACCOUNT` a instalat. Ce poate ști e că
    cele trei implicituri livrate nu s-au despărțit unul de altul — iar
    despărțirea lor e ce a făcut filtrul inert.
    """
    import re as _re

    radacina = Path(__file__).resolve().parents[2]
    instalator = _cont_din_instalator()

    sh = (radacina / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    m = _re.search(r'^DEPLOY_USER_DEFAULT="([A-Za-z0-9._-]+)"$', sh, _re.MULTILINE)
    assert m, "deploy.sh nu mai definește un cont implicit în forma citită aici"
    assert m.group(1) == instalator, (
        f"deploy.sh livrează ca {m.group(1)!r}, instalatorul creează "
        f"{instalator!r}")
    assert '[[ -n "$USER" ]] || die' in sh, (
        "`--user \"\"` ar trece, iar ssh ar folosi numele local — chiar contul "
        "de care fugim")

    ps1 = (radacina / "scripts" / "deploy.ps1").read_text(encoding="utf-8-sig")
    m = _re.search(r"\[string\]\$User = '([A-Za-z0-9._-]+)'", ps1)
    assert m, "deploy.ps1 nu mai are un implicit pentru -User în forma citită aici"
    assert m.group(1) == instalator, (
        f"deploy.ps1 livrează ca {m.group(1)!r}, instalatorul creează "
        f"{instalator!r} — cele două căi de livrare scriu istoric sub conturi "
        f"diferite, iar filtrul îl cunoaște pe unul singur")
    assert "Mandatory = $true)][string]$User" not in ps1, (
        "-User a redevenit obligatoriu, deci fiecare rulare numește iar contul "
        "celui care livrează")

    # Și capătul celălalt: contul ăla chiar e cel pe care configurația livrată îl
    # aruncă. Fără legătura asta, cele trei ar putea fi de acord între ele și
    # străine de filtru.
    assert instalator in _conturi_din_sablon()


def test_the_same_account_written_as_a_bare_uid_is_dropped_too() -> None:
    """87 935 de rânduri scrise ca `username = '1000'`.

    `collectors/auditd.py` scrie `auid`-ul numeric brut când nici câmpul
    îmbogățit al lui auditd, nici `pwd.getpwuid` nu dau un nume. E ACELAȘI cont,
    iar `is_dropped_command` compară pe egalitate exactă — deci o listă care are
    doar numele lasă ortografia numerică să treacă întreagă, în tăcere, cu un
    jurnal care raportează zero rânduri aruncate.
    """
    from sentinel.config import resolve_skip_command_accounts

    cont = _cont_din_instalator()
    rezolvate = resolve_skip_command_accounts(_conturi_din_sablon(),
                                              uid_of=lambda n: 998)
    assert "998" in rezolvate.matches, (
        "rezolvarea nu produce ortografia numerică, deci filtrul n-o poate prinde")

    db = _DB()
    counts = run(logins.project(
        db,
        _deploy_events(cont, key="2521") + _deploy_events("998", key="2522"),
        skip_accounts=rezolvate.matches))

    assert counts["commands_skipped"] == 6, (
        "comenzile scrise cu auid-ul numeric al aceluiași cont au fost păstrate")
    assert db.commands == []


def test_an_account_that_cannot_be_resolved_is_reported_not_swallowed() -> None:
    """Un cont configurat care nu există pe gazdă nu potrivește niciodată nimic.

    Compararea e pe egalitate exactă. Un nume greșit tastat, sau contul unei alte
    gazde copiat din documentație, dă o secțiune care ARATĂ configurată și nu
    aruncă niciun rând — la fel ca lipsa ei. Cele două trebuie să se deosebească,
    iar singurul loc unde se poate afla diferența e rezolvarea.
    """
    from sentinel.config import resolve_skip_command_accounts

    rezolvate = resolve_skip_command_accounts(["nu-exista"], uid_of=lambda n: None)
    assert rezolvate.unresolved == ("nu-exista",)
    assert rezolvate.lookup_ok is True, (
        "«contul nu există» a fost confundat cu «nu pot citi conturile»")

    # Și celălalt sens: baza de conturi ilizibilă e „nu știu", nu „nu există".
    def refuza(_nume):
        raise OSError("nu se poate citi /etc/passwd")

    oarba = resolve_skip_command_accounts(["sentinel-deploy"], uid_of=refuza)
    assert oarba.lookup_ok is False
    assert oarba.unresolved == (), (
        "un cont care poate exista a fost raportat drept inexistent")
    assert "sentinel-deploy" in oarba.matches, (
        "filtrul a rămas fără nume, deci n-ar mai arunca nimic")


# ---------------------------------------------------------------------------
# Mutațiile pe care suita nu le prindea
# ---------------------------------------------------------------------------
def test_a_command_with_no_tty_field_at_all_is_dropped() -> None:
    """Ramura `tty=None` a filtrului, chemată direct.

    Niciun test nu chema `is_dropped_command`, iar fiecare ajutor `_command()`
    punea `tty="(none)"` — deci ramura în care nucleul n-a scris deloc câmpul nu
    era exercitată nicăieri. Geamănul ei din SQL (`tty IS NULL`) avea test;
    partea din Python, nu.

    „Nu știu ce terminal a avut" nu e „a avut unul": tratată invers, fiecare
    înregistrare căreia îi lipsește câmpul ar fi păstrată, iar filtrul ar prinde
    o fracțiune din ce spune că prinde.
    """
    conturi = {DEPLOY}
    assert logins.is_dropped_command(DEPLOY, None, conturi) is True
    assert logins.is_dropped_command(DEPLOY, "(none)", conturi) is True
    assert logins.is_dropped_command(DEPLOY, "pts0", conturi) is False
    # Și amândouă condițiile, nu una: contul singur nu ajunge, lipsa
    # terminalului singură nu ajunge.
    assert logins.is_dropped_command("operator", None, conturi) is False
    assert logins.is_dropped_command(None, None, conturi) is False
    assert logins.is_dropped_command(DEPLOY, None, set()) is False


def test_a_deploy_row_without_a_tty_field_never_reaches_the_table() -> None:
    """Aceeași ramură, dar prin proiecție: rândul chiar nu se scrie."""
    db = _DB()
    counts = run(logins.project(
        db,
        [_login(user=DEPLOY),
         _command(user=DEPLOY, tty=None, argv="/usr/bin/sleep 1",
                  exe="/usr/bin/sleep")],
        skip_accounts=[DEPLOY]))

    assert db.commands == [], (
        "o comandă fără câmpul `tty` a fost scrisă: «nu știu» a fost citit ca "
        "«a avut terminal»")
    assert counts["commands_skipped"] == 1


@pytest.mark.parametrize("tty", [" pts0", "pts0 ", "\tpts0", "pts0\n"])
def test_whitespace_around_a_terminal_does_not_change_the_answer(tty: str) -> None:
    """`' pts0'` era PĂSTRAT de filtrul viu și ȘTERS de curățarea de pe PostgreSQL.

    `is_interactive` făcea `.strip()`, iar niciun predicat SQL nu-l făcea. Adică
    exact rândul unui om tastând pe contul de automatizare cădea într-o bază și
    rămânea în cealaltă. Marginile sunt acum în chiar tiparul pe care îl folosesc
    toate cele trei motoare, deci răspunsul e unul singur.
    """
    assert logins.is_interactive(tty) is True
    assert logins.is_dropped_command(DEPLOY, tty, {DEPLOY}) is False


def test_a_session_takes_the_terminal_it_started_on_not_the_last_one() -> None:
    """`ORDER BY session_id, id` — primul terminal al sesiunii, nu ultimul.

    Un `sudo su - altcineva` deschide un `pts` nou în aceeași sesiune. Cu
    ultimul, panoul ar arăta terminalul pe care omul a AJUNS, nu pe cel de pe
    care a intrat, iar cronologia s-ar citi de la coadă. Prima comandă cu
    terminal e chiar cea care a promovat sesiunea, deci ea o și descrie.
    """
    db = _DB()
    run(logins.project(db, [
        _login(),
        _command(tty="pts0", argv="/usr/bin/id", exe="/usr/bin/id"),
        _command(tty="pts7", argv="/usr/bin/w", exe="/usr/bin/w"),
    ]))

    assert db.sessions[0]["interactive"] is True
    assert db.sessions[0]["terminal"] == "pts0", (
        f"sesiunea poartă {db.sessions[0]['terminal']!r}: promovarea a luat "
        f"ULTIMUL terminal, nu primul")


def test_a_batch_that_only_attaches_orphans_still_refreshes_the_counters() -> None:
    """Lotul în care nu se scrie nicio comandă, dar se leagă orfane.

    Ordinea înregistrărilor nu e garantată: o comandă poate sosi înaintea logării
    ei și se scrie cu `session_id` NULL. Lotul următor aduce logarea, o leagă — și
    atât. `counts["commands"]` e zero pentru lotul ăla.

    Dacă poarta de reîmprospătare ar cere doar comenzi noi, sesiunea ar rămâne cu
    `command_count = 0` peste o comandă legată de ea, și — mai rău —
    neinteractivă peste o comandă cu `pts0`: alerta de logare n-ar pleca
    niciodată pentru o sesiune de om ale cărei comenzi au sosit primele.
    """
    db = _DB()
    run(logins.project(db, [
        _command(key="500", user="operator", tty="pts0",
                 argv="/usr/bin/id", exe="/usr/bin/id"),
    ]))
    assert db.commands[0]["session_id"] is None, "orfana s-a legat prea devreme"

    counts = run(logins.project(db, [_login(key="500", user="operator")]))

    assert counts["commands"] == 0 and counts["orphans_attached"] == 1
    s = db.sessions[0]
    assert s["command_count"] == 1, (
        f"contorul spune {s['command_count']} peste o comandă legată de sesiune")
    assert s["interactive"] is True, (
        "sesiunea nu s-a promovat, deci alerta de logare nu ar pleca niciodată "
        "pentru o sesiune ale cărei comenzi au sosit înaintea logării")
    assert counts["promoted"] == 1
