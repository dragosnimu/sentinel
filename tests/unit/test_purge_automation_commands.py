"""Curățarea istoricului deja strâns, pe gazdă: `scripts/purge-automation-commands.py`.

Eșecurile pe care le previne, fiecare cu forma pe care ar avea-o pentru operator:

  * **Un „dry-run" care șterge.** Modul uscat e singura cale prin care cineva se
    uită la ce ar cădea înainte de a hotărî. Dacă el scrie, greșeala nu se poate
    descoperi decât după — pe un istoric care nu se mai poate reface, fiindcă
    `raw_events` are 30 de zile de retenție iar tabela asta e arhiva.
  * **Altă regulă decât a filtrului.** Dacă ștergerea și filtrul nu potrivesc
    exact aceleași rânduri, datele vechi și cele noi înseamnă lucruri diferite:
    ori rămâne un morman pe care filtrul nou nu-l mai poate curăța, ori se taie
    comenzi ale unui om pe care filtrul le-ar fi păstrat.
  * **Un `DELETE` fără `LIMIT`.** Câteva milioane de rânduri într-o singură
    instrucțiune țin un lock lung, iar ingestia expiră în timpul lui.
  * **Un raport care confirmă intenția.** «Am șters 2,9 milioane de rânduri»,
    urmat de o bază exact la fel de mare, fiindcă `DELETE` nu întoarce spațiul
    sistemului de fișiere.
  * **O listă goală citită ca «nimic de făcut».** Pe o gazdă unde nimeni n-a
    scris încă secțiunea `history:`, «0 rânduri» arată identic cu o bază curată.
  * **«558 079 comenzi» deasupra unui tabel gol.** `command_count` e un contor
    memorat al rândurilor șterse, iar panoul și rezumatul de pe Telegram îl
    citesc. Lăsat neatins după `--apply`, e chiar eșecul pentru care există
    `_refresh_counters`.
  * **Ștergerea sesiunii unui om.** Modul pe sesiune taie tot ce a rulat sesiunea
    aleasă. Un identificator greșit tastat, sau unul al unei sesiuni interactive,
    ar lua istoricul care contează cel mai mult.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import re
from pathlib import Path

import pytest

from sentinel.db.repo.logins import REAL_TTY_SQL, is_dropped_command, is_interactive

REPO = Path(__file__).resolve().parents[2]
CALE = REPO / "scripts" / "purge-automation-commands.py"


def _modul():
    spec = importlib.util.spec_from_file_location("purge_automation_commands", CALE)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


purge = _modul()


def run(coro):
    return asyncio.run(coro)


def _cmd(session_id, username="sentinel-deploy", tty=None, exe="/usr/bin/systemctl"):
    return {"session_id": session_id, "username": username, "tty": tty, "exe": exe}


class _Conn:
    """Dublu de conexiune care ȚINE RÂNDURI, nu doar un contor.

    Regulile NU sunt reimplementate din memorie: fiecare predicat se citește din
    CHIAR TEXTUL instrucțiunii pe care i-l dă scriptul. Un dublu care își face
    singur regulile probează dublul, nu codul — iar aici tocmai despre ce anume
    potrivește regula e vorba.
    """

    def __init__(self, commands, sessions=(), *, bytes_=953_000_000):
        self.commands = [dict(c) for c in commands]
        self.sessions = [dict(s) for s in sessions]
        self.inchisa = False
        self.executate: list[tuple[str, tuple]] = []
        self.interogate: list[tuple[str, tuple]] = []

    # -- predicatele, citite din SQL -------------------------------------
    def _pred(self, sql, args):
        if "username = ANY($1::text[])" in sql:
            conturi, tipar = args[0], args[1]
            assert "tty IS NULL OR tty !~" in sql, sql
            return lambda r: (r["username"] in conturi
                              and (r["tty"] is None
                                   or not re.match(tipar, r["tty"])))
        if "session_id = ANY($1::bigint[])" in sql:
            ids = args[0]
            return lambda r: r["session_id"] in ids
        raise AssertionError(f"predicat nerecunoscut: {sql}")

    async def fetchval(self, sql, *a):
        self.interogate.append((sql, a))
        if "FROM login_sessions" in sql:
            assert "interactive = false" in sql, sql
            return sum(1 for s in self.sessions if not s.get("interactive"))
        if "WHERE" in sql:
            p = self._pred(sql, a)
            return sum(1 for r in self.commands if p(r))
        return len(self.commands)

    async def fetchrow(self, sql, *a):
        self.interogate.append((sql, a))
        assert "pg_total_relation_size" in sql, sql
        return {"bytes": 953_000_000, "pretty": "909 MB"}

    async def fetch(self, sql, *a):
        self.interogate.append((sql, a))
        if "unnest($1::bigint[])" in sql:
            cunoscute = {s["id"] for s in self.sessions}
            return [{"id": i} for i in a[0] if i not in cunoscute]
        if "interactive = true" in sql:
            return [dict(s) for s in self.sessions
                    if s["id"] in a[0] and s.get("interactive")]
        if "CROSS JOIN LATERAL" in sql:
            # Numărătoarea mărginită, jucată ca pe server: se citesc cel mult
            # `cap` rânduri ale sesiunii, iar `capped` spune că s-a oprit acolo.
            # Dublul NU numără tot și taie după: atunci testul n-ar mai putea
            # deosebi «s-a oprit la plafon» de «atâtea erau».
            assert "interactive = false" in sql, sql
            # Plafonul se citește din TEXTUL instrucțiunii, ca predicatele de mai
            # sus: o laterală fără `LIMIT` numără tot, exact ca serverul, iar
            # testul vede diferența în loc s-o presupună.
            limita = a[0]
            cap = a[1] if "LIMIT $2" in sql else None
            randuri = []
            for s in self.sessions:
                if s.get("interactive"):
                    continue
                n = 0
                for c in self.commands:
                    if c["session_id"] == s["id"]:
                        n += 1
                        if cap is not None and n >= cap:
                            break
                randuri.append({**s, "rows_now": n,
                                "capped": cap is not None and n >= cap,
                                "commands_purged": s.get("commands_purged", 0)})
            randuri.sort(key=lambda r: (-r["rows_now"],
                                        -int(r.get("command_count") or 0)))
            return randuri[:limita]
        if "ORDER BY s.command_count DESC" in sql:
            assert "interactive = false" in sql, sql
            assert "session_commands" not in sql, (
                "listarea nemăsurată tot atinge tabela de comenzi")
            randuri = [dict(s) for s in self.sessions if not s.get("interactive")]
            randuri.sort(key=lambda r: -int(r.get("command_count") or 0))
            return randuri[:a[0]]
        if "FILTER" in sql and "session_id = ANY($1::bigint[])" in sql:
            priv = set(a[1])
            out = []
            for sid in a[0]:
                ale_ei = [c for c in self.commands if c["session_id"] == sid]
                if not ale_ei:
                    continue
                out.append({"session_id": sid, "n": len(ale_ei),
                            "priv": sum(1 for c in ale_ei
                                        if (c["exe"] or "").rsplit("/", 1)[-1] in priv)})
            return out
        if "GROUP BY session_id" in sql:
            assert "session_id IS NOT NULL" in sql, sql
            p = self._pred(sql, a)
            pe_sesiune: dict[int, int] = {}
            for r in self.commands:
                if r["session_id"] is not None and p(r):
                    pe_sesiune[r["session_id"]] = pe_sesiune.get(r["session_id"], 0) + 1
            return [{"session_id": k, "n": v} for k, v in sorted(pe_sesiune.items())]
        raise AssertionError(f"fetch nerecunoscut: {sql}")

    async def close(self):
        self.inchisa = True

    async def execute(self, sql, *a):
        self.executate.append((sql, a))
        if sql.lstrip().startswith("VACUUM"):
            return "VACUUM"
        if sql.lstrip().startswith("UPDATE login_sessions"):
            assert "command_count = $2" in sql, sql
            assert "commands_purged = commands_purged + $4" in sql, sql
            sid, n, priv, cazute = a
            for s in self.sessions:
                if s["id"] == sid:
                    s["command_count"] = n
                    s["sudo_count"] = priv
                    s["commands_purged"] = s.get("commands_purged", 0) + cazute
            return "UPDATE 1"
        assert sql.lstrip().startswith("DELETE"), sql
        limita = a[-1]
        p = self._pred(sql, a)
        de_sters = [r for r in self.commands if p(r)][:limita]
        for r in de_sters:
            self.commands.remove(r)
        return f"DELETE {len(de_sters)}"


def _sesiune(id_, **kw):
    baza = {"id": id_, "session_key": str(id_), "username": "sentinel-deploy",
            "terminal": "ssh", "interactive": False, "opened_at": "2026-08-25 10:00:00",
            "command_count": 0, "sudo_count": 0, "commands_purged": 0}
    baza.update(kw)
    return baza


def _ruleaza(conn, *, apply, batch=5000, conturi=("sentinel-deploy",),
             sesiuni=None, spellings=None):
    out = io.StringIO()
    rezultat = run(purge.purge(conn, None if sesiuni else list(conturi),
                               apply=apply, batch=batch, out=out,
                               session_ids=sesiuni, spellings=spellings))
    return rezultat, out.getvalue()


def _multe(n, session_id=1, **kw):
    return [_cmd(session_id, **kw) for _ in range(n)]


def _coloana(text, sesiune, indice=1):
    """Ce scrie pe RÂNDUL sesiunii, la coloana cerută.

    Se citește chiar celula, nu doar prezența unui semn undeva prin ieșire: `?`
    apare și în explicația de sub tabel, deci o căutare pe tot textul ar trece și
    peste o coloană care arată «0».
    """
    for linie in text.splitlines():
        campuri = linie.split()
        if campuri and campuri[0] == str(sesiune):
            return campuri[indice]
    raise AssertionError(f"sesiunea {sesiune} nu apare în listă:\n{text}")


# ---------------------------------------------------------------------------
# Modul uscat
# ---------------------------------------------------------------------------
def test_the_dry_run_writes_nothing() -> None:
    """Implicitul e „uită-te", nu „șterge".

    E singura cale prin care cineva vede ce ar cădea înainte să hotărască. Un
    mod uscat care scrie face greșeala descoperibilă doar după ea, pe o arhivă
    care nu se mai poate reface din `raw_events` — acolo retenția e 30 de zile.
    """
    conn = _Conn(_multe(120) + _multe(30, 2, username="operator"),
                 [_sesiune(1), _sesiune(2)])
    rezultat, text = _ruleaza(conn, apply=False)

    assert conn.executate == [], (
        f"modul uscat a executat instrucțiuni: {[s for s, _ in conn.executate]}")
    assert rezultat["deleted"] == 0
    assert len(conn.commands) == 150, "dublul spune că rândurile chiar au căzut"
    assert conn.sessions[0]["command_count"] == 0, "a atins contorul în modul uscat"
    assert "120" in text, "modul uscat nu spune câte rânduri ar cădea"
    assert "--apply" in text


def test_the_command_line_without_arguments_deletes_nothing(monkeypatch, capsys) -> None:
    """Rulat fără niciun argument — cum îl rulează cineva prima oară.

    Un implicit distructiv face dintr-o comandă tastată din curiozitate o arhivă
    pierdută. Se cere `--apply`, iar aici se probează chiar drumul din linia de
    comandă, nu doar funcția de sub el.
    """
    from types import SimpleNamespace

    conn = _Conn(_multe(120), [_sesiune(1)])
    monkeypatch.setattr(purge, "get_config", lambda: SimpleNamespace(
        history=SimpleNamespace(skip_command_accounts=["sentinel-deploy"])))
    monkeypatch.setattr(purge, "database_dsn", lambda cfg: "postgresql://x/y")
    rezolva = purge.resolve_skip_command_accounts
    monkeypatch.setattr(purge, "resolve_skip_command_accounts",
                        lambda nume: rezolva(nume, uid_of=lambda n: 998))

    async def fake_connect(*a, **k):
        return conn

    monkeypatch.setattr(purge.asyncpg, "connect", fake_connect)

    cod = purge.main([])
    assert cod == 0
    assert conn.executate == [], "rularea fără argumente a scris în bază"
    assert conn.inchisa, "conexiunea a rămas deschisă"
    assert "[uscat]" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Aceeași regulă ca filtrul
# ---------------------------------------------------------------------------
def test_the_deletion_uses_the_same_rule_as_the_new_filter() -> None:
    """Datele vechi și cele noi trebuie să însemne același lucru.

    Tiparul de terminal nu se rescrie aici, se ia din
    `sentinel/db/repo/logins.py`. O copie hardcodată care ar rămâne în urmă ar
    lăsa un morman pe care filtrul nou nu-l mai curăță, sau — în cealaltă
    direcție — ar șterge comenzi pe care filtrul le păstrează.
    """
    conn = _Conn(_multe(10), [_sesiune(1)])
    _ruleaza(conn, apply=True, conturi=("sentinel-deploy",))

    perechi = conn.interogate + conn.executate
    cu_regula = [(s, a) for s, a in perechi if "username = ANY" in s]
    assert len(cu_regula) >= 2, (
        f"numărătoarea și ștergerea trebuie să poarte amândouă regula: {cu_regula}")
    for sql, args in cu_regula:
        assert "username = ANY($1::text[])" in sql, sql
        assert args[0] == ["sentinel-deploy"], (
            f"contul nu pleacă legat ca parametru: {args!r}")
        assert args[1] == REAL_TTY_SQL, (
            f"tiparul de terminal e o copie, nu cel din logins.py: {args[1]!r}")
        assert "tty IS NULL OR tty !~" in sql, (
            "un `tty` NULL trebuie tratat ca «fără terminal», exact ca "
            "`is_interactive(None)`")


def test_a_command_with_a_real_terminal_is_outside_the_rule() -> None:
    """Garda celuilalt sens, pe chiar tiparul trimis bazei.

    Dacă tiparul s-ar strica — `pts` fără cifre, o ancoră lipsă —, `!~` ar
    potrivi și rândurile cu `pts0`, adică ștergerea ar înghiți exact comenzile
    tastate de un om pe contul de automatizare. Sunt cele care contează.
    """
    tipar = re.compile(REAL_TTY_SQL)
    for real in ("pts0", "pts12", "tty1"):
        assert tipar.match(real), f"{real} n-ar mai fi terminal real"
    for fals in ("(none)", "", "ssh", "cron"):
        assert not tipar.match(fals)


def test_the_row_a_human_typed_on_the_automation_account_survives() -> None:
    """Ce se pierde dacă regula ar fi «tot ce rulează contul».

    O logare interactivă pe contul de automatizare — `ssh sentinel-deploy@gazdă`
    cu shell adevărat — capătă `pts0`. Comenzile ei sunt chiar cele care
    promovează sesiunea la `interactive` și trimit alerta. Ștergerea NU are voie
    să le atingă, altfel contul cu `NOPASSWD: ALL` devine calea de intrare pe
    care nu se anunță nimic.
    """
    conn = _Conn(_multe(5) + [_cmd(1, tty="pts0", exe="/usr/bin/vim")],
                 [_sesiune(1)])
    rezultat, _ = _ruleaza(conn, apply=True)

    assert rezultat["deleted"] == 5
    ramase = [c for c in conn.commands]
    assert len(ramase) == 1 and ramase[0]["tty"] == "pts0", (
        "s-a șters comanda tastată de un om pe contul de automatizare")


# ---------------------------------------------------------------------------
# Tranșele
# ---------------------------------------------------------------------------
def test_the_deletion_runs_in_bounded_batches() -> None:
    """Un `DELETE` de milioane de rânduri ține un lock lung, iar ingestia expiră
    în timpul lui — pe gazdă, asta oprește colectarea pentru toate sursele."""
    conn = _Conn(_multe(12_003), [_sesiune(1)])
    rezultat, _ = _ruleaza(conn, apply=True, batch=5000)

    stergeri = [(s, a) for s, a in conn.executate if s.startswith("DELETE")]
    assert len(stergeri) == 3, f"{len(stergeri)} tranșe pentru 12 003 rânduri"
    for sql, args in stergeri:
        assert "LIMIT $3" in sql, "instrucțiunea n-are limită: lock lung"
        assert args[-1] == 5000, "limita nu pleacă legată ca parametru"
    assert rezultat["deleted"] == 12_003


def test_the_report_states_what_is_left_and_what_it_costs() -> None:
    """Efectul, nu intenția — pe amândouă axele.

    Codul de retur al lui `DELETE` spune ce a raportat serverul. Ce a rămas se
    renumără. Iar mărimea pe disc NU scade după `DELETE`, deci raportul trebuie
    să spună asta și să numească pasul care lipsește — altfel operatorul citește
    «2,9 milioane șterse», se uită la o bază la fel de mare, și nu știe care
    dintre cele două minte.
    """
    conn = _Conn(_multe(2_003), [_sesiune(1)])
    rezultat, text = _ruleaza(conn, apply=True)

    assert rezultat["deleted"] == 2_003
    assert rezultat["remaining"] == 0
    assert any(s.strip().startswith("VACUUM") for s, _ in conn.executate), (
        "nu s-a rulat niciun VACUUM: spațiul nu devine nici măcar reutilizabil")
    assert "909 MB" in text, "raportul nu spune cât măsura tabela"
    assert "VACUUM FULL" in text, (
        "raportul nu numește singurul pas care întoarce spațiul sistemului de "
        "fișiere — «am șters 2,9 milioane» și o bază la fel de mare")
    assert "ACCESS EXCLUSIVE" in text, (
        "VACUUM FULL e recomandat fără să i se spună costul: blochează ingestia "
        "cât durează")


def test_the_counters_run_before_the_vacuum() -> None:
    """O întrerupere în timpul lui `VACUUM` nu are voie să lase panoul mințind.

    `VACUUM (ANALYZE)` pe o tabelă de sute de MB durează. Dacă în intervalul ăla
    cade procesul, ce trebuie să fie deja adevărat e contorul: statistici vechi
    fac planificatorul mai lent, un `command_count` vechi face panoul să arate
    «558 079 comenzi» deasupra unui tabel gol.
    """
    conn = _Conn(_multe(10), [_sesiune(1)])
    _ruleaza(conn, apply=True)

    ordine = [s.lstrip()[:6] for s, _ in conn.executate]
    assert "UPDATE" in ordine and "VACUUM" in ordine
    assert ordine.index("UPDATE") < ordine.index("VACUUM"), (
        f"contoarele se scriu după VACUUM: {ordine}")


# ---------------------------------------------------------------------------
# Contoarele sesiunii
# ---------------------------------------------------------------------------
def test_the_session_counter_stops_claiming_rows_that_are_gone() -> None:
    """«558 079 comenzi» deasupra unui tabel gol.

    `command_count` e un contor MEMORAT al rândurilor din `session_commands`, iar
    panoul (`aggregator/lib/panel-page.ts`) și rezumatul de închidere de pe
    Telegram (`sentinel/detect/logins.py`) îl citesc pe el, nu tabela. Curățarea
    care nu-l atinge produce exact eșecul pentru care există `_refresh_counters`.
    """
    conn = _Conn(_multe(500), [_sesiune(1, command_count=500, sudo_count=0)])
    rezultat, text = _ruleaza(conn, apply=True)

    assert rezultat["deleted"] == 500
    s = conn.sessions[0]
    assert s["command_count"] == 0, (
        f"contorul spune {s['command_count']} despre un tabel gol")
    assert s["commands_purged"] == 500, (
        "nu s-a păstrat nicăieri că sesiunea a rulat 500 de comenzi")
    assert "contoare" in text, "raportul nu spune că a atins contoarele"


def test_the_counter_counts_what_actually_fell_not_what_was_planned() -> None:
    """Ingestia rulează în paralel cu ștergerea.

    Dacă `commands_purged` ar fi «câte am vrut să șterg», un rând sosit între
    numărătoare și ștergere ar face contorul să pretindă mai mult decât s-a
    întâmplat. Se scade CE E ACUM din CE ERA — două măsurători, nu un plan.
    """
    conn = _Conn(_multe(10) + [_cmd(1, tty="pts0")],
                 [_sesiune(1, command_count=11)])
    _ruleaza(conn, apply=True)

    s = conn.sessions[0]
    assert s["command_count"] == 1, "rândul cu terminal a dispărut din contor"
    assert s["commands_purged"] == 10, (
        f"a numărat {s['commands_purged']} șterse din 11 rânduri din care a "
        f"căzut 10")


def test_a_privileged_command_left_behind_is_still_counted() -> None:
    """`sudo_count` se renumără odată cu celălalt, din aceleași rânduri.

    «412 comenzi, 3 cu sudo» e chiar propoziția care spune ce s-a întâmplat. Dacă
    doar unul dintre contoare s-ar reface, rezumatul ar spune «0 comenzi, 3 cu
    sudo» — o afirmație care nu poate fi adevărată.
    """
    conn = _Conn(_multe(4) + [_cmd(1, tty="pts0", exe="/usr/bin/sudo")],
                 [_sesiune(1, command_count=5, sudo_count=1)])
    _ruleaza(conn, apply=True)

    s = conn.sessions[0]
    assert (s["command_count"], s["sudo_count"]) == (1, 1)


# ---------------------------------------------------------------------------
# Modul pe sesiune
# ---------------------------------------------------------------------------
def test_the_session_mode_deletes_everything_that_session_ran() -> None:
    """Istoricul de dinaintea filtrului nu e pe contul de automatizare.

    Deploy-ul se rula sub contul de logare al operatorului — `auid` e uid-ul de
    LOGARE și supraviețuiește lui `sudo` —, iar pe același cont stau și
    diagnosticele lui, care se păstrează. Nicio regulă pe cont nu le poate
    deosebi. Ce le deosebește e sesiunea.
    """
    conn = _Conn(_multe(300, 1, username="operator")
                 + _multe(7, 2, username="operator", exe="/usr/bin/psql"),
                 [_sesiune(1, username="operator"),
                  _sesiune(2, username="operator")])
    rezultat, text = _ruleaza(conn, apply=True, sesiuni=[1])

    assert rezultat["deleted"] == 300
    assert [c["session_id"] for c in conn.commands] == [2] * 7, (
        "s-au șters și comenzile sesiunii de diagnostic")
    assert conn.sessions[1]["commands_purged"] == 0, (
        "contorul altei sesiuni a fost atins")
    assert "indiferent de cont" in text, (
        "raportul nu spune că modul pe sesiune ignoră contul și terminalul")


def test_the_session_mode_refuses_an_interactive_session() -> None:
    """Sesiunea unui om la tastatură e chiar istoricul care contează.

    Modul pe sesiune taie TOT ce a rulat sesiunea. Singurul lucru pe care baza îl
    știe sigur despre «a fost cineva acolo» e fanionul `interactive`, pus la prima
    comandă cu `tty` real. O cifră greșită tastată nu are voie să ia sesiunea
    unui om.
    """
    conn = _Conn(_multe(50, 3, tty="pts0"),
                 [_sesiune(3, interactive=True, username="operator")])
    rezultat, text = _ruleaza(conn, apply=True, sesiuni=[3])

    assert rezultat["deleted"] == 0
    assert len(conn.commands) == 50, "s-a șters o sesiune interactivă"
    assert conn.executate == [], "a scris în bază după ce a refuzat"
    assert "INTERACTIVĂ" in text
    assert rezultat["refused"] == 1


def test_the_session_mode_refuses_an_id_that_does_not_exist() -> None:
    """O cifră greșită nu are voie să treacă drept «sesiune fără nimic de șters».

    Un raport «0 rânduri» pentru sesiunea 2251 în loc de 2521 arată exact ca o
    sesiune deja curățată, iar operatorul pleacă crezând că a terminat.
    """
    conn = _Conn(_multe(9, 1), [_sesiune(1)])
    rezultat, text = _ruleaza(conn, apply=True, sesiuni=[999])

    assert rezultat["deleted"] == 0
    assert len(conn.commands) == 9
    assert "999" in text and "Nu există sesiunile" in text


def test_the_listing_orders_by_size_so_the_boundary_is_visible() -> None:
    """Granița se citește, nu se codifică.

    Un deploy are 250 000–560 000 de comenzi, o sesiune de diagnostic a unui om
    are sute. Un prag scris în cod ar fi o presupunere despre gazda altcuiva;
    lista ordonată descrescător face diferența de trei ordine de mărime vizibilă
    dintr-o privire, iar alegerea rămâne a operatorului.
    """
    conn = _Conn(_multe(300, 1) + _multe(4, 2) + _multe(50, 3),
                 [_sesiune(1), _sesiune(2), _sesiune(3),
                  _sesiune(4, interactive=True)])
    out = io.StringIO()
    randuri = run(purge.list_sessions(conn, limit=10, out=out))

    assert [r["id"] for r in randuri] == [1, 3, 2], (
        "lista nu e ordonată după câte comenzi are sesiunea")
    assert all(not r["interactive"] for r in randuri), (
        "o sesiune interactivă a ajuns în lista de curățat")
    assert conn.executate == [], "listarea a scris în bază"
    assert "--sessions" in out.getvalue()


def test_the_listing_stops_counting_at_the_cap_instead_of_scanning_the_table() -> None:
    """18,4 secunde și trei procese de fundal, plătite ca să se afle ce se vede
    și dintr-o singură privire.

    Măsurat pe gazdă pe 25 august 2026, cu listarea care număra exact:
    `Execution Time: 18395.833 ms`, `Heap Fetches: 243723`, agregare peste 2,85
    milioane de rânduri — și nimic n-o oprea, fiindcă `_connect` pune
    `statement_timeout = 0` pentru `VACUUM`. Prețul se plătea exact înainte de
    curățare, când tabela e cea mai mare, pe o gazdă care în aceeași zi a dat 504
    pe panou: unealta de curățat putea lua jos chiar gazda pe care o curăță.

    Deci numărătoarea se oprește la plafon pentru fiecare sesiune. Ce trebuie să
    rămână adevărat: cifra vine din TABELĂ (nu din contorul memorat), sesiunea
    grasă se vede ca fiind grasă, iar plafonul se SPUNE — „2000+" și „2000" nu au
    voie să arate la fel.
    """
    conn = _Conn(_multe(30, 1) + _multe(6, 2),
                 [_sesiune(1, command_count=30), _sesiune(2, command_count=6)])
    out = io.StringIO()
    randuri = run(purge.list_sessions(conn, limit=10, out=out, cap=10))
    text = out.getvalue()

    assert [r["id"] for r in randuri] == [1, 2]
    assert randuri[0]["capped"] is True, "plafonul n-a fost atins pe sesiunea grasă"
    assert randuri[1]["capped"] is False
    assert _coloana(text, 1) == "10+", (
        "plafonul nu se vede în listă, deci 10 pare exact")
    assert _coloana(text, 2) == "6"
    assert "sau mai multe" in text, (
        "nimic nu-i spune operatorului ce înseamnă semnul plus")

    # Și mărginirea în sine: dublul numără rând cu rând, deci o citire care ar
    # trece prin toate cele 30 s-ar vedea aici. Ce se cere de la SQL e `LIMIT`-ul
    # dinăuntrul lateralei.
    lateral = [s for s, _ in conn.interogate if "CROSS JOIN LATERAL" in s]
    assert lateral, "listarea nu mai numără mărginit"
    assert "LIMIT $2" in lateral[0], (
        "sub-interogarea numără fără plafon: costul redevine cel de 18 s")


def test_a_host_with_too_many_sessions_says_it_did_not_measure() -> None:
    """„N-am numărat" și „am numărat zero" nu au voie să arate la fel.

    Numărătoarea mărginită costă `sesiuni × plafon`. Pe o gazdă cu zeci de mii de
    sesiuni fără terminal nici ea nu mai încape, iar atunci singura ordonare
    posibilă e după `command_count` — un contor MEMORAT, adică exact felul de
    afirmație pe care restul fișierului refuză s-o creadă. Se poate face, dar
    trebuie spus: altfel operatorul citește o cifră numărată acolo unde nu e una.
    """
    conn = _Conn(_multe(30, 1),
                 [_sesiune(1, command_count=30), _sesiune(2, command_count=999)])
    out = io.StringIO()
    randuri = run(purge.list_sessions(conn, limit=10, out=out, cap=10, budget=5))
    text = out.getvalue()

    assert [r["id"] for r in randuri] == [2, 1], (
        "fără măsurătoare, ordonarea trebuie să cadă pe contorul memorat")
    assert _coloana(text, 1) == "?", "coloana nemăsurată arată ca o cifră"
    assert _coloana(text, 2) == "?"
    assert "NU s-a măsurat" in text
    assert "contor MEMORAT" in text, (
        "nu se spune că ordonarea se sprijină pe o afirmație, nu pe o măsurătoare")
    assert not any("session_commands" in s for s, _ in conn.interogate), (
        "listarea nemăsurată tot a citit tabela de comenzi")


def test_the_listing_shows_the_stored_counter_next_to_the_measured_one() -> None:
    """Contorul care minte trebuie să se vadă mințind.

    `command_count` e memorat pe rândul sesiunii și e ce citesc panoul și
    rezumatul de pe Telegram. Dacă rândurile au fost șterse din altă parte —
    replica își curăță tabela, gazda nu — contorul rămâne mare deasupra unui
    tabel gol. Arătat singur, ar fi crezut; arătat lângă numărătoarea din tabelă,
    dezacordul e vizibil fără să fie nevoie de vreo decizie în cod.
    """
    conn = _Conn([], [_sesiune(1, command_count=558_079)])
    out = io.StringIO()
    run(purge.list_sessions(conn, limit=10, out=out))
    text = out.getvalue()

    assert "558 079" in text, "contorul memorat nu se mai vede deloc"
    assert "contor" in text
    assert "a rămas în urmă" in text, (
        "nimic nu-i spune operatorului ce înseamnă două cifre care nu seamănă")


def test_an_empty_listing_reads_as_empty_not_as_a_failure() -> None:
    """Zero sesiuni și o interogare care n-a mers arată identic într-o listă goală.

    Pe o gazdă fără nicio sesiune neinteractivă, o ieșire complet mută l-ar lăsa
    pe operator să se întrebe dacă unealta e stricată.
    """
    conn = _Conn([], [])
    out = io.StringIO()
    assert run(purge.list_sessions(conn, limit=10, out=out)) == []
    assert "niciuna" in out.getvalue()


def test_a_mistyped_session_list_is_refused_not_silently_shortened() -> None:
    """`2521,25 30` — cine a tastat asta crede că a dat două sesiuni.

    O listă tăcut mai scurtă ar lăsa în urmă exact rândurile pe care credea că
    le-a șters, iar raportul ar arăta ca un succes.
    """
    assert purge.parse_session_ids("2521, 2530") == [2521, 2530]
    with pytest.raises(ValueError):
        purge.parse_session_ids("2521,25 30")
    with pytest.raises(ValueError):
        purge.parse_session_ids("toate")


def test_the_two_modes_cannot_be_combined() -> None:
    """Două reguli deodată dau un raport din care nu se mai citește ce a căzut
    și de ce — iar raportul e tot ce are operatorul."""
    with pytest.raises(SystemExit):
        purge.main(["--accounts", "x", "--sessions", "1"])
    with pytest.raises(SystemExit):
        purge.main(["--list-sessions", "--apply"])


def test_rows_written_while_deleting_are_reported_not_hidden(monkeypatch) -> None:
    """Ingestia rulează în paralel, deci pot apărea rânduri noi în timpul rulării.

    «Am terminat» pe o tabelă în care regula mai potrivește șapte rânduri e o
    afirmație falsă. Se renumără după ștergere, iar restul se SPUNE.
    """
    conn = _Conn(_multe(100), [_sesiune(1)])
    original = conn.execute
    stare = {"gata": False}

    async def execute(sql, *a):
        rezultat = await original(sql, *a)
        if sql.lstrip().startswith("VACUUM") and not stare["gata"]:
            stare["gata"] = True
            conn.commands.extend(_multe(7))
        return rezultat

    conn.execute = execute
    rezultat, text = _ruleaza(conn, apply=True)

    assert rezultat["remaining"] == 7
    assert "mai potrivesc regula: 7" in text
    assert "din nou" in text, "nu se spune ce are de făcut operatorul"


# ---------------------------------------------------------------------------
# „Nu știu" nu e „nimic de făcut"
# ---------------------------------------------------------------------------
def test_an_empty_account_list_refuses_instead_of_reporting_zero(
        monkeypatch, capsys) -> None:
    """Pe o gazdă unde nimeni n-a scris secțiunea `history:`, «0 rânduri de
    șters» arată exact ca o bază deja curată.

    Scriptul se oprește, o spune, și — important — nici măcar nu deschide
    conexiunea: nu are ce întreba.
    """
    from types import SimpleNamespace

    monkeypatch.setattr(purge, "get_config", lambda: SimpleNamespace(
        history=SimpleNamespace(skip_command_accounts=[])))

    async def refuza(*a, **k):
        raise AssertionError("s-a conectat la bază fără să știe ce conturi caută")

    monkeypatch.setattr(purge.asyncpg, "connect", refuza)

    cod = purge.main([])
    assert cod == 2
    err = capsys.readouterr().err
    assert "nu se aruncă nimic" in err
    assert "--list-sessions" in err, (
        "nu i se spune unde e istoricul vechi, care nu e pe contul ăsta")


def test_the_accounts_come_from_the_configuration_not_from_the_source() -> None:
    """Contul se ia din `sentinel.yaml`, la fel ca filtrul.

    Codificat în sursă, o gazdă cu alt `DEPLOY_ACCOUNT` ar curăța contul
    altcuiva — sau, mai probabil, nimic, în tăcere.
    """
    from types import SimpleNamespace

    cfg = SimpleNamespace(history=SimpleNamespace(
        skip_command_accounts=["sentinel-deploy", "ci-runner"]))
    assert purge.accounts_of(cfg, None) == ["sentinel-deploy", "ci-runner"]
    assert purge.accounts_of(cfg, "altul") == ["altul"]


def test_the_numeric_spelling_is_purged_too() -> None:
    """87 935 de rânduri scrise ca `username = '1000'`.

    `collectors/auditd.py` scrie `auid`-ul numeric brut când nici câmpurile
    îmbogățite ale lui auditd, nici `pwd` nu dau un nume. E ACELAȘI cont, iar o
    curățare care compară literal cu numele îl lasă întreg în urmă, cu un raport
    care arată ca o bază curată.
    """
    conturi = purge.resolve_skip_command_accounts(["sentinel-deploy"],
                                                  uid_of=lambda n: 998)
    conn = _Conn(_multe(10, 1, username="sentinel-deploy")
                 + _multe(6, 1, username="998")
                 + _multe(3, 2, username="operator"),
                 [_sesiune(1), _sesiune(2)])
    rezultat, text = _ruleaza(conn, apply=True, conturi=sorted(conturi.matches),
                              spellings=conturi)

    assert rezultat["deleted"] == 16, (
        "ortografia numerică a contului a scăpat curățării")
    assert [c["username"] for c in conn.commands] == ["operator"] * 3
    assert "998" in text, "raportul nu spune ce ortografii caută"


def test_an_account_that_does_not_resolve_is_said_out_loud() -> None:
    """Un cont configurat care nu există pe gazdă nu potrivește nimic.

    Raportat, e o linie pe care operatorul o vede. Înghițit, e o curățare care
    caută uid-ul unui cont inexistent, nu-l găsește, și raportează zero — adică
    exact ce ar raporta o bază curată.
    """
    conturi = purge.resolve_skip_command_accounts(["nu-exista"],
                                                  uid_of=lambda n: None)
    conn = _Conn(_multe(4, 1), [_sesiune(1)])
    _, text = _ruleaza(conn, apply=False, conturi=sorted(conturi.matches),
                       spellings=conturi)
    assert "nu există pe gazda asta" in text


def test_the_session_rows_are_never_deleted() -> None:
    """Sesiunile rămân, oricâte comenzi cad.

    „S-a deschis o sesiune de deploy" e faptul cu valoare de securitate; sunt
    câteva sute de rânduri și nu ocupă nimic. O ștergere care le-ar lua odată cu
    comenzile ar șterge chiar dovada că automatizarea a intrat pe server.

    Contoarele LOR se ating, și trebuie: testul de dinainte cerea ca
    `login_sessions` să nu apară deloc în instrucțiuni, ceea ce fixa exact
    bug-ul de la punctul D — «558 079 comenzi» deasupra unui tabel gol.
    """
    conn = _Conn(_multe(10), [_sesiune(1)])
    _ruleaza(conn, apply=True)
    atinse = [s for s, _ in conn.executate + conn.interogate]
    assert not any("DELETE" in s and "login_sessions" in s for s in atinse), (
        "scriptul șterge din tabela de sesiuni, care nu e a lui")
    assert len(conn.sessions) == 1, "a dispărut un rând de sesiune"


@pytest.mark.parametrize("sql", [purge.count_sql(), purge.delete_sql(),
                                 purge.count_sql(purge.SESSION_PREDICATE),
                                 purge.delete_sql(purge.SESSION_PREDICATE)])
def test_every_statement_targets_only_the_command_history(sql: str) -> None:
    """O singură tabelă, numită dintr-o constantă."""
    assert "session_commands" in sql
    assert "DROP" not in sql.upper() and "TRUNCATE" not in sql.upper()


# ---------------------------------------------------------------------------
# Egalitatea între motoare
# ---------------------------------------------------------------------------
def _tipar_replicii() -> str:
    """Tiparul CHIAR AȘA CUM ÎL VEDE MariaDB, nu cum arată sursa TypeScript.

    Literalul din `.ts` se decodează ca șir JavaScript — `json.loads` acoperă
    exact submulțimea de evadări pe care o poate conține un literal cu ghilimele
    duble. Citit brut, `\\t` din sursă ar fi comparat ca backslash-t în loc de
    tab, iar testul ar compara două scrieri, nu două reguli.
    """
    ts = (REPO / "aggregator" / "lib" / "purge-automation.ts").read_text(encoding="utf-8")
    m = re.search(r'export const REAL_TTY =\s*\n?\s*"((?:[^"\\]|\\.)*)"', ts)
    assert m, ("nu găsesc `REAL_TTY` în aggregator/lib/purge-automation.ts — "
               "testul ar trece degeaba dacă l-aș sări")
    return json.loads('"' + m.group(1) + '"')


def test_the_two_databases_use_literally_the_same_terminal_rule() -> None:
    """Gazda și replica trebuie să șteargă EXACT aceleași rânduri.

    Sunt două implementări, în două limbi, peste două motoare de bază de date.
    Dacă s-ar despărți, o comandă ar fi „a unui om" pe o bază și „a unei
    automatizări" pe cealaltă — iar cronologia care contează pentru securitate ar
    fi diferită după care panou o citești.

    Nu «se comportă la fel pe o listă de cazuri», ci ACELAȘI ȘIR: o listă de
    cazuri probează cazurile de pe listă, iar divergența care a existat până pe
    25 august 2026 — marginile de spațiu — nu era pe listă.
    """
    assert _tipar_replicii() == REAL_TTY_SQL, (
        f"replica trimite {_tipar_replicii()!r}, gazda {REAL_TTY_SQL!r}")


@pytest.mark.parametrize("tty", [" pts0", "pts0 ", "\tpts0", "pts0\n", "\npts0"])
def test_padding_around_a_terminal_is_the_same_answer_everywhere(tty: str) -> None:
    """`' pts0'` era PĂSTRAT de filtrul viu și ȘTERS de curățare.

    `is_interactive` făcea `.strip()`, iar niciun predicat SQL nu-l făcea. Adică
    exact rândul unui om tastând pe contul de automatizare cădea pe replica de
    arhivă și rămânea pe gazdă — o cronologie diferită după care panou o citești,
    fix pentru comenzile care contează.

    Marginile sunt acum în chiar tipar, deci le vede fiecare motor.
    """
    tipar_replica = re.compile(_tipar_replicii())
    assert is_interactive(tty), "filtrul viu nu mai vede un terminal real"
    assert re.match(REAL_TTY_SQL, tty), "predicatul de pe gazdă l-ar șterge"
    assert tipar_replica.match(tty), "predicatul replicii l-ar șterge"
    assert not is_dropped_command("sentinel-deploy", tty, {"sentinel-deploy"})


@pytest.mark.parametrize("tty", ["PTS0", "TTY1", "Pts0"])
def test_an_uppercase_terminal_is_dropped_by_every_engine(tty: str) -> None:
    """`'PTS0'` era aruncat de filtrul viu, șters pe PostgreSQL și PĂSTRAT pe
    replică.

    Colația `utf8mb4_unicode_ci` a coloanei face `REGEXP` insensibil la
    majuscule, deci `PTS0` trecea acolo drept terminal real. Diferența e mică pe
    datele de azi — nucleul scrie `pts0` — și e o divergență reală între două
    baze despre care se spune că șterg aceleași rânduri.

    Ce se probează AICI e doar partea pe care o poate proba o mașină fără
    MariaDB: tiparul singur, insensibil la nimic, dă același răspuns în Python și
    în PostgreSQL. Partea de pe replică — că serverul chiar aplică
    `COLLATE utf8mb4_bin` — nu se poate deduce dintr-un șir, deci NU se afirmă
    aici: se probează pe server, la rulare, prin `assertRuleMatchesTheHost`, iar
    ștergerea nu pornește dacă răspunsul nu e cel al gazdei.
    """
    tipar_replica = re.compile(_tipar_replicii())
    assert not is_interactive(tty)
    assert not re.match(REAL_TTY_SQL, tty)
    assert not tipar_replica.match(tty), (
        "tiparul însuși a devenit insensibil la majuscule")
    assert is_dropped_command("sentinel-deploy", tty, {"sentinel-deploy"})


def test_the_replica_refuses_to_delete_until_the_server_proves_the_collation() -> None:
    """Divergența pe care un test din Python NU o poate închide.

    `COLLATE utf8mb4_bin` scris în predicat nu e dovadă că serverul îl aplică —
    e chiar tiparul din `CLAUDE.md`. De aceea replica întreabă serverul înainte
    de orice ștergere, cu chiar construcția din predicat, și se oprește dacă
    răspunsul nu e cel al gazdei.

    Testul ăsta verifică doar că mecanismul EXISTĂ în fișierul livrat și că e
    legat înaintea ștergerii; comportamentul lui pe MariaDB se probează în
    `aggregator/tests/purge-automation.test.ts`.
    """
    ts = (REPO / "aggregator" / "lib" / "purge-automation.ts").read_text(encoding="utf-8")
    assert "assertRuleMatchesTheHost" in ts
    inainte = ts.index("assertRuleMatchesTheHost(db)")
    sterge = ts.index("const dsql = `DELETE FROM")
    assert inainte < sterge, (
        "proba de colație se face după ștergere, deci nu oprește nimic")
