"""Sesiunile de login și comenzile lor: proiecția evenimentelor în entități.

`raw_events` primește tot ce vede colectorul, ca fapte plate cu retenție de 30
de zile. Aici se face pasul următor: o logare devine o SESIUNE care se deschide,
adună comenzi și se închide, iar comenzile ei devin un istoric cu retenție
nelimitată.

## De ce o proiecție, și nu o interogare peste `raw_events`

Fiindcă „ultima logare a sesiunii 432, dacă n-a fost închisă între timp, cu
numărul de comenzi rulate de atunci" e o interogare pe care nimeni n-o scrie
corect din prima, se scrie diferit în fiecare loc care are nevoie de ea, iar
după 30 de zile nu mai are pe ce rula.

## Ordinea în care sosesc înregistrările

Nu e garantată. O comandă poate ajunge înaintea logării care a produs-o — două
citiri diferite din același jurnal, sau nucleul care a scris `EXECVE` înainte ca
sesiunea PAM să se fi încheiat de deschis. Deci:

  * o comandă fără sesiune cunoscută se scrie ORICUM, cu `session_key` pe rând și
    `session_id` NULL. Se leagă mai târziu, la prima proiecție care găsește
    sesiunea. O comandă aruncată fiindcă nu i-am găsit părintele e o comandă
    pierdută definitiv;
  * o sesiune care se închide fără să se fi deschis se creează închisă. „Am văzut
    ieșirea, n-am văzut intrarea" e o stare reală — colectorul poate porni la
    mijlocul unei sesiuni — și e o informație, nu o eroare de aruncat.

## Singura comandă care NU se scrie

Cea a unui cont de automatizare (`history.skip_command_accounts`) rulată FĂRĂ
terminal real. Măsurat pe gazdă: un singur deploy a produs 405 777 de comenzi în
140 de secunde — `systemctl` de 320 591 de ori și `sleep` de 173 376, adică
buclele de așteptare ale instalatorului —, iar replica de pe agregator a crescut
de la 83 MB la 909 MB în câteva ore.

Se taie DOAR proiecția asta. Regulile auditd rămân neatinse și jurnalul de pe
disc rămâne sursa completă: un `-F auid!=<uid>` ar opri emisia din nucleu și ar
face contul complet neînregistrat — o gaură fix acolo unde ar căuta cineva.

Rândul de sesiune rămâne și el. „S-a deschis o sesiune de deploy" e faptul cu
valoare de securitate; ~161 de sesiuni nu ocupă nimic.

Iar filtrul e pe TERMINALUL COMENZII, nu pe contul sesiunii — vezi
`is_dropped_command`, unde e scris de ce diferența asta e chiar reparația.

## `session_commands.event_id`

Coloana există din 0026 dar a rămas nescrisă până acum: `record_command` n-o
punea în lista de coloane. Măsurat pe gazdă la descoperire: 0 din 420 494 de
rânduri o aveau populată — o investigație nu putea lega o comandă din istoric
înapoi de rândul brut din care a fost construită.

Se completează din `ev.id`, pus de `events_repo.insert_batch` PE ACELEAȘI
obiecte `Event` înainte ca lotul să ajungă la `project()` — nu se citește
nimic înapoi din bază. Când preallocarea id-urilor eșuează pentru un lot,
`ev.id` rămâne `None` și `event_id` se scrie NULL: o comandă scrisă fără
legătură e corectă; una legată de rândul altcuiva ar fi otrăvit exact
investigația pentru care există coloana.

Rândurile scrise ÎNAINTE de reparația asta rămân NULL pentru totdeauna — vezi
`sentinel/db/migrations/0040_session_commands_event_id_comment.sql` pentru
decizia de a nu face backfill și de ce.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger
from sentinel.model.event import Event

log = get_logger(__name__)

if TYPE_CHECKING:
    # Numai pentru tip: `collectors/audit_sessions.py` importă `NO_SESSION` de
    # aici, deci un import obișnuit în sens invers ar fi un ciclu. Funcția care
    # o primește nu are nevoie de clasă la rulare, doar de câmpurile ei.
    from sentinel.collectors.audit_sessions import LiveAuditSessions

#: Ce valoare a lui `ses` înseamnă „nicio sesiune de login".
#:
#: auditd scrie `4294967295` (adică `(uint32)-1`) pentru procesele care n-au
#: sesiune. Un rând cu cheia asta ar aduna sub el fiecare daemon de pe gazdă,
#: într-o „sesiune" care nu se închide niciodată și are milioane de comenzi.
NO_SESSION = frozenset({"4294967295", "unset", "-1", "", "?"})


#: După câte ore fără nicio activitate se consideră încheiată o sesiune care
#: n-a produs nicio ieșire.
#:
#: `USER_LOGOUT` sosește mai rar decât `USER_LOGIN` — 11 față de 31, măsurat pe
#: gazdă — fiindcă o sesiune tăiată de rețea, una oprită de un `reboot` sau una
#: încă deschisă când s-a rotit jurnalul nu produce niciuna. Fără măturătoare,
#: panoul ar arăta oameni conectați de săptămâni, iar rezumatul lor n-ar pleca
#: niciodată.
#:
#: Douăsprezece ore: o sesiune de lucru reală poate sta deschisă peste noapte
#: fără să se atingă nimeni de ea, iar o închidere prea grăbită ar trimite
#: rezumatul în timp ce omul e încă acolo — și l-ar trimite din nou la fiecare
#: comandă următoare.
#:
#: De pe 15 septembrie 2026 măturătoarea nu mai e calea obișnuită, ci plasa:
#: `reap_dead_sessions` închide sesiunea când sesiunea ei de audit chiar a
#: dispărut de pe gazdă, în minute în loc de ore. Aici rămân cazurile pe care
#: nimeni nu le poate observa — o gazdă pe care `/proc` nu se poate citi, un
#: proces rămas în urmă care ține id-ul de sesiune viu, ingestia oprită.
STALE_SESSION_H = 12

#: Cât trebuie să stea nemișcat un rând înainte ca absența sesiunii lui de pe
#: gazdă să însemne că s-a terminat.
#:
#: Nu apără împotriva unei sesiuni VII — aia e apărată de faptul că o sesiune
#: vie are procese, deci apare în `/proc`. Apără împotriva cursei dintre cele
#: două citiri: instantaneul din `/proc` se ia înaintea instrucțiunii, iar o
#: sesiune născută între ele ar lipsi din el fără să fi murit vreodată.
#:
#: Două minute, adică de o mie de ori mai mult decât decalajul măsurat între
#: cele două citiri (o trecere de ingestie; întârzierea auditd pe gazda Ubuntu
#: la 15 septembrie 2026 era de 0,34 s) și de 360 de ori mai puțin decât cele
#: douăsprezece ore pe care le înlocuiește. Direcția în care greșim dacă e prea
#: mic e singura care contează: un rezumat trimis despre cineva care încă
#: tastează. De-asta nu e mai mic.
REAP_GRACE_S = 120

#: Binarele care înseamnă „a rulat ceva cu privilegii". Numărate separat, fiindcă
#: «412 comenzi» nu spune nimic iar «412 comenzi, 3 cu sudo» spune ce s-a
#: întâmplat.
PRIVILEGED = frozenset({"sudo", "su", "doas", "pkexec", "runuser"})


#: Un terminal adevărat, așa cum îl scrie nucleul în `SYSCALL.tty`.
#:
#: `pts0`, `pts12`, `tty1`. Orice altceva — `(none)`, gol — înseamnă că nu e
#: nimeni la tastatură.
#:
#: Un singur ȘIR pentru toate cele trei motoare: `re` aici, `~` în PostgreSQL
#: (`scripts/purge-automation-commands.py`, `_promote_interactive`) și `REGEXP`
#: în MariaDB (`aggregator/lib/purge-automation.ts`). Două decizii îl fac să
#: însemne același lucru în toate trei:
#:
#:   * **`[0-9]`, nu `\d`.** În Python `\d` potrivește și cifrele Unicode
#:     (`pts٣`), în PostgreSQL depinde de colație, în PCRE nu. Trei răspunsuri
#:     diferite la aceeași întrebare, pe un tipar care decide dacă un rând se
#:     păstrează sau se aruncă;
#:   * **marginile de spațiu sunt ÎN tipar.** Până pe 25 august 2026,
#:     `is_interactive` făcea `.strip()` iar niciun predicat SQL nu-l făcea:
#:     `' pts0'` era PĂSTRAT de filtrul viu și ȘTERS de curățare, adică exact
#:     rândul unui om tastând pe contul de automatizare. Clasa e scrisă cu
#:     caracterele ei și nu ca `\s`, fiindcă `\s` e Unicode în Python și ASCII
#:     în PCRE — aceeași despărțire, mutată cu un pas mai încolo.
#:
#: Marginile se acceptă, nu se resping: dacă vreodată sosește un `tty` cu spații
#: în jur, „e un terminal real" păstrează rândul și promovează sesiunea, adică
#: greșeala cade în direcția care nu pierde istoric și nu tace o alertă.
REAL_TTY_SQL = r"^[ \t\n\r\f\v]*(pts[0-9]+|tty[0-9]+)[ \t\n\r\f\v]*$"

#: Același tipar, compilat. Derivat din constantă, nu scris a doua oară: două
#: copii care se despart ar face ca datele vechi și cele noi să însemne lucruri
#: diferite, iar diferența s-ar vedea abia peste luni, într-o cronologie din
#: care lipsește ceva.
_REAL_TTY = re.compile(REAL_TTY_SQL)


def is_interactive(terminal: str | None) -> bool:
    """Un om la tastatură, sau un script.

    ## De ce se citește din `tty`, și nu din `terminal`

    `USER_LOGIN` scrie `terminal=ssh` pentru ORICE conexiune prin ssh, cu pty sau
    fără. Verificat pe gazdă: o sesiune deschisă cu `ssh -tt`, adică cu terminal
    forțat, primește tot `terminal=ssh`. Câmpul ăla e numele SERVICIULUI, nu al
    terminalului — iar prima versiune a acestui modul l-a citit ca terminal și a
    marcat fiecare sesiune drept neinteractivă.

    Ce deosebește cu adevărat cele două e `tty` de pe înregistrările `SYSCALL`:
    `pts0` pentru o sesiune cu terminal, `(none)` pentru una fără. E pe fiecare
    comandă, deci sesiunea se poate promova când sosește prima.

    Necunoscut înseamnă NEinteractiv: greșeala în direcția asta produce o alertă
    întârziată, nu una falsă. Pe un canal care nu se poate tăcea, a doua e cea
    care distruge canalul.

    ## De ce nu se mai face `.strip()` aici

    Se făcea, până pe 25 august 2026, iar predicatele SQL n-o făceau: `' pts0'`
    era interactiv pentru filtrul viu și neinteractiv pentru curățare, deci
    ștergerea înghițea rânduri pe care filtrul le păstra. Marginile de spațiu
    sunt acum în CHIAR tiparul pe care îl folosesc toate cele trei motoare —
    vezi `REAL_TTY_SQL`. Un `.strip()` în plus aici ar reface despărțirea în
    tăcere, fiindcă el taie și spațiul Unicode, iar tiparul nu.
    """
    if terminal is None:
        return False
    return bool(_REAL_TTY.match(terminal))


def is_dropped_command(username: str | None, tty: str | None,
                       accounts: Collection[str]) -> bool:
    """Comanda unui cont de automatizare, rulată fără terminal real.

    Amândouă condițiile, nu una: contul SINGUR nu ajunge.

    ## De ce filtrul e pe terminalul COMENZII

    Interactivitatea unei sesiuni nu se știe la logare — `USER_LOGIN` nu poartă
    terminalul — și se stabilește abia din prima comandă cu `tty` real, în
    `_promote_interactive`. Iar `announce_new_sessions()` cere `interactive =
    true` ca să trimită alerta.

    Deci o regulă de forma „tot ce rulează contul X" ar închide chiar drumul pe
    care pleacă alerta: nicio comandă scrisă, deci nicio promovare, deci nicio
    logare anunțată. Contul de automatizare ar deveni o cale de intrare tăcută —
    exact locul unde s-ar uita cineva care știe că există.

    Cu regula pe `tty`, `ssh sentinel-deploy@gazdă` cu shell adevărat capătă
    `pts0`, comenzile se păstrează, sesiunea se promovează, alerta pleacă.

    ## Ce trebuie să conțină `accounts`

    Comparația e pe egalitate exactă, iar ACELAȘI cont ajunge în `username` sub
    două ortografii: numele, când auditd sau `pwd` l-au rezolvat, și `auid`-ul
    NUMERIC ca șir, când niciunul n-a putut (`collectors/auditd.py`, ultima cale
    din `nume`). Măsurat pe gazdă pe 25 august 2026: 87 935 de rânduri scrise ca
    `username = '1000'` pentru contul care are și 2,8 milioane sub numele lui.

    Deci `accounts` NU e lista din configurație, e ea rezolvată — vezi
    `sentinel.config.resolve_skip_command_accounts`, care întoarce amândouă
    ortografiile și spune pe care nu le-a putut rezolva.

    O listă goală înseamnă „nu se aruncă nimic" — comportamentul de dinaintea
    filtrului, și implicitul.
    """
    if username is None or username not in accounts:
        return False
    return not is_interactive(tty)


def session_key_of(ev: Event) -> str | None:
    """Cheia de sesiune a unui eveniment, sau `None` dacă n-are una utilizabilă."""
    key = (ev.raw or {}).get("ses")
    if key is None:
        return None
    key = str(key).strip()
    return None if key in NO_SESSION else key


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Deschiderea și închiderea
# ---------------------------------------------------------------------------
async def open_session(db: Database, ev: Event, key: str) -> int | None:
    """Deschide o sesiune, sau o găsește pe cea deschisă deja.

    `ON CONFLICT DO NOTHING` plus o recitire: două rulări peste aceleași linii —
    o repornire care reia cursorul — nu au voie să producă două sesiuni. Cheia
    naturală e `(session_key, opened_at)`, deci reluarea aceleiași linii nimerește
    exact același rând.
    """
    raw = ev.raw or {}
    terminal = raw.get("terminal")
    # `interactive` pleacă FALS și se promovează la prima comandă cu terminal —
    # vezi `is_interactive`. `USER_LOGIN` nu poartă terminalul, deci la
    # deschidere pur și simplu nu se știe, iar a ghici aici ar însemna ori o
    # alertă la fiecare rulare de deploy, ori niciuna.
    row = await db.fetchrow(
        """
        INSERT INTO login_sessions
            (session_key, username, auid, src_ip, terminal, interactive, opened_at)
        VALUES ($1, $2, $3, $4::inet, $5, $6, $7)
        ON CONFLICT (session_key, opened_at) DO UPDATE
            SET username = COALESCE(login_sessions.username, EXCLUDED.username),
                src_ip   = COALESCE(login_sessions.src_ip, EXCLUDED.src_ip)
        RETURNING id
        """,
        key, ev.username, raw.get("auid"), ev.src_ip, terminal, False, ev.ts)
    return row["id"] if row else None


async def close_session(db: Database, ev: Event, key: str) -> int | None:
    """Închide cea mai recentă sesiune deschisă cu cheia asta.

    Dacă nu există niciuna, se creează una ÎNCHISĂ, cu `opened_at = closed_at`.
    „Am văzut ieșirea, n-am văzut intrarea" e o stare reală: colectorul poate
    porni la mijlocul unei sesiuni, sau nucleul poate fi pierdut înregistrarea de
    deschidere. Aruncată, ar dispărea și dovada că sesiunea a existat.
    """
    row = await db.fetchrow(
        """
        UPDATE login_sessions SET closed_at = $2
         WHERE id = (SELECT id FROM login_sessions
                      WHERE session_key = $1 AND closed_at IS NULL
                      ORDER BY opened_at DESC LIMIT 1)
        RETURNING id
        """,
        key, ev.ts)
    if row is not None:
        return row["id"]

    # Nicio sesiune DESCHISĂ cu cheia asta. Înainte de a fabrica una, se caută
    # dacă există deja una ÎNCHISĂ: PAM emite o închidere pentru fiecare strat de
    # sesiune — cea a lui sshd, plus cele deschise de `sudo` sau `su` înăuntru.
    #
    # Măsurat pe gazdă la prima livrare: 175 de `USER_END` pentru 55 de logări
    # reușite. Fără verificarea asta, fiecare logare apărea în panou de două-trei
    # ori, iar fantomele aveau contul gol — adică arătau exact ca o logare pe care
    # Sentinel n-a putut s-o atribuie nimănui.
    deja = await db.fetchval(
        """
        SELECT id FROM login_sessions
         WHERE session_key = $1 AND closed_at >= $2::timestamptz - interval '1 day'
         ORDER BY opened_at DESC LIMIT 1
        """,
        key, ev.ts)
    if deja is not None:
        return deja

    raw = ev.raw or {}
    terminal = raw.get("terminal")
    created = await db.fetchrow(
        """
        INSERT INTO login_sessions
            (session_key, username, auid, src_ip, terminal, interactive,
             opened_at, closed_at, alerted_at, summarised_at)
        VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $7, $7, $7)
        ON CONFLICT (session_key, opened_at) DO NOTHING
        RETURNING id
        """,
        key, ev.username, raw.get("auid"), ev.src_ip, terminal,
        is_interactive(terminal), ev.ts)
    # `alerted_at` și `summarised_at` sunt puse la creare, dinadins: o sesiune a
    # cărei deschidere n-am văzut-o nu are ce alerta — mesajul ar sosi după ce
    # omul a plecat, spunând „cineva s-a logat" despre o sesiune deja încheiată.
    return created["id"] if created else None


# ---------------------------------------------------------------------------
# Comenzile
# ---------------------------------------------------------------------------
_INSERT_COMMAND = """
INSERT INTO session_commands
    (session_id, session_key, ts, username, exe, argv, cwd, tty, pid, ppid, success, event_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
"""


async def record_command(db: Database, ev: Event, key: str,
                         session_id: int | None) -> None:
    """Scrie o comandă. `session_id` poate fi `None` — vezi capul modulului.

    `event_id` vine din `ev.id`, pus de `events_repo.insert_batch` ÎNAINTE ca
    lotul ăsta să ajungă aici — `project()` rulează pe ACELEAȘI obiecte
    `Event`, nu pe copii citite din bază. Rămâne `None` dacă preallocarea
    id-urilor a eșuat pentru lot: un `event_id` greșit ar lega comanda de
    evenimentul altcuiva, ceea ce e mai rău decât o coloană goală — deci NULL
    e răspunsul corect ori de câte ori legătura nu e sigură, nu doar aici.
    """
    raw = ev.raw or {}
    await db.execute(
        _INSERT_COMMAND,
        session_id, key, ev.ts, ev.username,
        raw.get("exe") or ev.process,
        # `argv` e deja redactat de colector. NOT NULL în schemă, deci se scrie
        # șirul gol când `EXECVE` n-a adus argumente — se întâmplă la binare
        # pornite fără argv, iar un rând lipsă ar fi o comandă pierdută.
        raw.get("argv") or "",
        raw.get("cwd"), raw.get("tty"),
        _int(raw.get("pid")) or ev.pid, _int(raw.get("ppid")),
        raw.get("success") == "yes" if raw.get("success") is not None else None,
        ev.id)


async def _find_session(db: Database, key: str, ts: Any) -> int | None:
    """Sesiunea căreia îi aparține o comandă, deschisă SAU deja închisă.

    Prima versiune căuta doar sesiuni deschise, iar pe gazdă asta a lăsat **299
    de comenzi orfane din 2070** în primele minute: o sesiune de deploy trăiește
    o secundă, iar comenzile ei sosesc în același lot cu închiderea sau în
    următorul. Rândurile se scriau, dar nu apăreau în niciun rezumat și în nicio
    cronologie — prezente în tabelă și invizibile acolo unde le-ar căuta cineva.

    Fereastra e ce împiedică reparația să strice altceva: `ses` se renumerotează
    după repornire, iar o comandă de azi lipită de sesiunea cu aceeași cheie de
    acum trei luni ar pune fapta cuiva în cronologia altcuiva. Deci se cere ca
    momentul comenzii să cadă ÎN sesiune, cu o margine pentru ceasul care poate
    să nu fie perfect aliniat între înregistrări.
    """
    return await db.fetchval(
        """
        SELECT id FROM login_sessions
         WHERE session_key = $1
           AND opened_at <= $2::timestamptz + interval '1 minute'
           AND (closed_at IS NULL OR closed_at >= $2::timestamptz - interval '1 minute')
         ORDER BY opened_at DESC LIMIT 1
        """,
        key, ts)


async def _attach_orphans(db: Database, key: str, session_id: int) -> int:
    """Leagă de sesiune comenzile care sosiseră înaintea ei.

    Numai cele NELEGATE și numai pe cheia asta, într-o fereastră de un minut
    în jurul deschiderii — aceeași margine de ceas dezaliniat pe care o
    folosește `_find_session` mai sus.

    `close_session` fabrică rândul cu `opened_at = closed_at` când n-a văzut
    deschiderea — vezi docstring-ul ei. Pentru o sesiune fabricată, fereastra
    de o secundă în care ea „există" cade EXACT la închidere, iar comenzile ei
    reale, dacă au rulat mai devreme de un minut, rămân neatașate — corect,
    fiindcă nu există un fapt din care să se dovedească cui aparțin.

    S-a încercat o lărgire a marginii de jos până la închiderea celei mai
    recente sesiuni ANTERIOARE cu aceeași cheie (sau, în lipsa ei, ora de
    pornire a gazdei). Măsurat pe producție, 16 septembrie 2026: fiindcă
    `session_key` se reciclează NUMAI la reboot, orice sesiune anterioară găsită
    era, prin construcție, dincolo de o repornire — granița „lărgită" nu apăra
    nimic, doar întindea fereastra peste boot. 1616 comenzi orfane s-ar fi
    legat greșit, 1607 dintre ele peste graniță de reboot, cu utilizator diferit
    de al sesiunii care le-ar fi înghițit (320 de comenzi ale uid 1000 din
    24 august atașate unei sesiuni `sentinel-deploy` din 7 septembrie; 143 de
    comenzi root din 4 septembrie atașate unei sesiuni din 14 septembrie).
    Exact ce interzice capul acestei funcții: fapta unei persoane în cronologia
    alteia. Lărgirea a fost retrasă; o identitate de boot adevărată (un
    `boot_id` ștampilat pe rând, nu o comparație de ore) rămâne lucru separat.
    """
    result = await db.execute(
        """
        UPDATE session_commands c SET session_id = $2
          FROM login_sessions s
         WHERE c.session_key = $1 AND c.session_id IS NULL
           AND s.id = $2
           AND c.ts >= s.opened_at - interval '1 minute'
           AND (s.closed_at IS NULL OR c.ts <= s.closed_at + interval '1 minute')
        """,
        key, session_id)
    return int(str(result).rsplit(" ", 1)[-1]) if result else 0


# ---------------------------------------------------------------------------
# Proiecția
# ---------------------------------------------------------------------------
async def project(db: Database, events: list[Event],
                  skip_accounts: Collection[str] = ()) -> dict[str, int]:
    """Trece lotul prin sesiuni și comenzi, în ordinea în care a sosit.

    Se rulează DUPĂ `insert_batch`, ca `raw_events` să rămână sursa completă chiar
    dacă proiecția are un defect. Ordinea contează: o logare din același lot
    trebuie să deschidă sesiunea înainte ca prima comandă s-o caute.

    `skip_accounts` vine din configurație (`history.skip_command_accounts`) și e
    gol dacă apelantul nu spune nimic — un apelant care uită să-l dea păstrează
    tot, adică greșește în direcția care nu pierde istoric.

    Întoarce ce s-a făcut, ca apelantul să poată loga fapte, nu intenții.
    `commands_skipped` e acolo tocmai fiindcă altfel „n-a rulat nimeni nimic" și
    „am aruncat 405 777 de rânduri conform politicii" ar arăta identic în jurnal.
    """
    counts = {"sessions_opened": 0, "sessions_closed": 0,
              "commands": 0, "commands_skipped": 0,
              "orphans_attached": 0, "promoted": 0}
    skip = frozenset(skip_accounts)
    # Sesiunile deschise în lotul ăsta, ca o comandă care urmează imediat unei
    # logări să nu mai caute în bază. Nu e o memorie între loturi: o cheie
    # necunoscută se caută oricum în bază, deci un proces repornit nu pierde
    # nimic.
    known: dict[str, int] = {}
    # Sesiunile ÎNCHISE în lotul ăsta. Scoase din `known` imediat după închidere
    # (mai jos), ca o comandă cu aceeași cheie mai departe în lot să nu se lege
    # orbește de o sesiune care s-ar putea să fi fost deja retrasă — dar tot
    # trebuie recalculate: `_attach_orphans` de la închidere poate atașa comenzi
    # care schimbă `command_count`, iar sesiunea aia nu mai e în `known` la
    # finalul buclei ca să intre în recalculare pe calea veche.
    closed: set[int] = set()

    for ev in events:
        if ev.source != "auditd":
            continue
        key = session_key_of(ev)
        if key is None:
            continue

        if ev.action == "login":
            # Numai autentificările REUȘITE deschid o sesiune. Pe gazda reală
            # sunt 9200 de `USER_LOGIN` eșuate la două zile — brute-force din
            # internet. Fiecare ar deveni o sesiune deschisă care nu se închide
            # niciodată, iar panoul ar arăta zece mii de oameni conectați.
            if (ev.raw or {}).get("res") not in ("success", "1"):
                continue
            session_id = await open_session(db, ev, key)
            if session_id is not None:
                known[key] = session_id
                counts["sessions_opened"] += 1
                counts["orphans_attached"] += await _attach_orphans(db, key, session_id)

        elif ev.action == "logout":
            session_id = await close_session(db, ev, key)
            if session_id is not None:
                counts["sessions_closed"] += 1
                # Pe Ubuntu `USER_LOGIN` se scrie DOAR pentru sesiunile cu pty
                # — majoritatea sesiunilor sshd n-au niciuna. `open_session`
                # nu rulează niciodată pentru ele, deci comenzile lor sosesc
                # deja orfane și rămân așa pentru totdeauna dacă nimeni nu mai
                # caută înapoi. `close_session` întoarce un rând de fiecare
                # dată — deschis și tocmai închis, deja închis (dedup), sau
                # fabricat — și oricare din cele trei e un rând de care se pot
                # lega orfanele. `_attach_orphans` atinge numai
                # `session_id IS NULL`, deci a treia rulare pe aceeași
                # sesiune (PAM + sshd trimit până la trei semnale de închidere
                # pentru o singură ieșire) nu mai are ce lega — idempotentă
                # prin construcție, nu prin verificare separată aici.
                counts["orphans_attached"] += await _attach_orphans(db, key, session_id)
                closed.add(session_id)
            known.pop(key, None)

        elif ev.action == "command":
            if is_dropped_command(ev.username, (ev.raw or {}).get("tty"), skip):
                # Înainte de căutarea sesiunii, dinadins: un rând care nu se
                # scrie n-are de ce să atingă baza. Sesiunea NU intră astfel în
                # `known`, deci nu ajunge nici în `atinse` — și e corect, fiindcă
                # nimic nu s-a schimbat pentru ea: `_refresh_counters` numără din
                # tabelă, iar acolo n-a apărut niciun rând nou.
                #
                # Orfanele nu se pierd: legarea lor pleacă de la sesiunea pusă în
                # `known` de o LOGARE, nu de la comenzi.
                counts["commands_skipped"] += 1
                continue
            session_id = known.get(key)
            if session_id is None:
                session_id = await _find_session(db, key, ev.ts)
                if session_id is not None:
                    known[key] = session_id
            await record_command(db, ev, key, session_id)
            counts["commands"] += 1

    if counts["commands"] or counts["orphans_attached"]:
        # `known` contine si sesiunile gasite in baza pentru comenzi, nu doar pe
        # cele deschise in lot; `closed` le adauga pe cele inchise in lotul asta,
        # scoase din `known` mai sus. Se recalculeaza si dupa legarea orfanelor:
        # altfel contorul unei sesiuni ar ramane in urma exact cu comenzile care
        # i s-au atasat cu intarziere -- la deschidere sau la inchidere -- iar
        # rezumatul n-ar mai fi de acord cu lista.
        atinse = sorted(set(known.values()) | closed)
        await _refresh_counters(db, atinse)
        counts["promoted"] = await _promote_interactive(db, atinse)
    return counts


async def close_stale_sessions(db: Database) -> int:
    """Închide PRESUPUS sesiunile fără ieșire și fără activitate recentă.

    Momentul pus e ultima activitate cunoscută — ultima comandă, sau deschiderea
    dacă n-a rulat nimic —, nu `now()`. O sesiune tăiată de rețea la 14:32 s-a
    terminat la 14:32, nu peste douăsprezece ore când am observat noi.

    `closed_inferred` marchează diferența. „S-a deconectat la 14:32" și „n-am mai
    auzit nimic de ea după 14:32" sunt afirmații diferite, iar un panou care le
    arată identic minte liniștit.
    """
    result = await db.execute(
        """
        UPDATE login_sessions s
           SET closed_at = COALESCE(
                   (SELECT max(ts) FROM session_commands c WHERE c.session_id = s.id),
                   s.opened_at),
               closed_inferred = true
         WHERE s.closed_at IS NULL
           AND COALESCE(
                   (SELECT max(ts) FROM session_commands c WHERE c.session_id = s.id),
                   s.opened_at) < now() - make_interval(hours => $1)
        """,
        STALE_SESSION_H)
    return int(str(result).rsplit(" ", 1)[-1]) if result else 0


async def reap_dead_sessions(db: Database, live: LiveAuditSessions,
                             observed_s_ago: float) -> int:
    """Închide rândurile a căror sesiune de audit nu mai există pe gazdă.

    Calea rapidă rămâne `USER_LOGOUT` — când sosește, e precisă și imediată.
    Asta e calea pentru restul, care pe gazda Ubuntu înseamnă TOT: 17 din 17
    sesiuni închise de acolo poartă `closed_inferred = true`, adică niciuna
    n-a fost închisă vreodată de o ieșire văzută, iar rezumatul lor a plecat
    fix la douăsprezece ore după ultima comandă.

    ## De ce primește dovada, nu o listă de chei

    Fiindcă „nu e nimeni logat” și „n-am putut citi” arată identic ca listă
    goală, iar diferența dintre ele e diferența dintre a nu închide nimic și a
    închide TOT. Nu e o grijă teoretică: sub `ProtectProc=invisible` — cum
    rulează `sentinel-detect.service` chiar acum — un scan al lui `/proc` vede
    zece procese, toate ale lui, și zero sesiuni. Cu `trusted = False` funcția
    asta nu atinge niciun rând, iar garda stă într-un singur loc: apelantul nu
    repetă decizia, ca să nu poată nimeri unul dintre ei altfel.

    ## Ce moment primește rândul

    Ultima activitate cunoscută — ultima comandă, sau deschiderea dacă n-a
    rulat nimic —, împreună cu `closed_inferred = true`. NU `now()`: nimeni
    n-a văzut ieșirea, deci ora la care am observat noi absența n-are nicio
    legătură cu ora la care a plecat omul, iar diferența dintre ele poate fi
    de ore. Exact regula măturătoarei, dinadins: două căi care scriu același
    rând după reguli diferite ar face ca „Durată” să însemne altceva după cum
    l-a atins una sau alta. Ce iese în mesaj e o margine de jos, și
    `summary_text` o spune ca atare.

    ## De ce nu poate inunda telefonul

    Fereastra ei se termină exact unde începe a măturătoarei: un rând fără
    activitate de peste `STALE_SESSION_H` ore e treaba lui
    `close_stale_sessions`, și era și înaintea acestei funcții. Deci prima
    rulare pe o gazdă cu restanță nu poate închide niciun rând pe care
    măturătoarea nu l-ar fi închis oricum în următoarele douăsprezece ore — nu
    există niciun val pe care să-l producă ea și nu l-ar fi produs cealaltă.

    Ce rămâne nerezolvat, și nu de aici: o gazdă pe care detecția a stat oprită
    săptămâni adună rânduri deschise, iar la repornire măturătoarea le rezumă
    pe toate deodată. E comportamentul de azi, neschimbat.

    ## De ce primește și VECHIMEA observației

    Fiindcă `live` descrie gazda la momentul scanului, iar instrucțiunea rulează
    mai târziu — uneori mult mai târziu, fiindcă apelantul așteaptă dinadins să
    fi citit coada de audit dincolo de clipa scanului (vezi
    `services/ingest_service.py`). Între cele două momente se poate LOGA cineva,
    iar sesiunea lui lipsește dintr-un scan luat înainte să existe, fără să fi
    murit vreodată.

    Până pe 15 septembrie 2026 apărarea era implicită: răgazul se măsura de la
    `now()`, deci ținea numai cât timp scanul era mai proaspăt de
    `REAP_GRACE_S`. Nimic nu impunea asta și nimic n-ar fi spus când încetează
    să fie adevărat. Acum ambele margini se măsoară din clipa observației —
    „rândul ăsta tăcea deja de două minute CÂND m-am uitat la gazdă" —, deci un
    scan vechi întârzie închiderea în loc s-o facă greșită, iar apelantul poate
    ține unul în mână oricât are nevoie.

    Vine ca DURATĂ, nu ca moment: momentul ar fi de pe ceasul procesului, iar
    comparația se face pe ceasul bazei. Două ceasuri care nu sunt de acord fac
    dintr-un răgaz de două minute un răgaz de altceva; o durată înseamnă
    același lucru pe amândouă.

    ## Rularea în paralel cu măturătoarea

    Se pot atinge: reaper-ul rulează în ingestie, măturătoarea în detecție.
    Dacă nimeresc același rând, scriu aceeași valoare (aceeași expresie pentru
    `closed_at`), iar rezumatul pleacă o singură dată fiindcă `summarised_at` e
    ce-l oprește, nu numărul de închideri.
    """
    if not live.trusted:
        return 0
    result = await db.execute(
        """
        WITH candidat AS (
            SELECT s.id,
                   COALESCE((SELECT max(ts) FROM session_commands c
                              WHERE c.session_id = s.id),
                            s.opened_at) AS ultima
              FROM login_sessions s
             WHERE s.closed_at IS NULL
               AND NOT (s.session_key = ANY($1::text[]))
        )
        UPDATE login_sessions s
           SET closed_at = candidat.ultima,
               closed_inferred = true
          FROM candidat
         WHERE s.id = candidat.id
           AND candidat.ultima < now() - make_interval(secs => $4)
                                       - make_interval(secs => $2)
           AND candidat.ultima > now() - make_interval(secs => $4)
                                       - make_interval(hours => $3)
        """,
        # `max(ts)` calculat o singură dată pe sesiune deschisă, în CTE, și
        # numai pentru cele care NU mai sunt vii: instrucțiunea măturătoarei
        # scrie același subselect de două ori, iar 0031 a măsurat ce costă.
        #
        # `$4` e vechimea scanului: `now() - $4` e clipa în care s-a citit
        # `/proc`, iar ambele margini pleacă de acolo. Negativ n-are înțeles —
        # ar muta marginile în VIITOR, adică ar închide rânduri active —, deci
        # se taie la zero aici, nu în apelant, unde s-ar putea uita.
        sorted(live.keys), float(REAP_GRACE_S), STALE_SESSION_H,
        max(0.0, float(observed_s_ago)))
    return int(str(result).rsplit(" ", 1)[-1]) if result else 0


# ---------------------------------------------------------------------------
# Starea reaper-ului, scrisă unde supraviețuiește unei reporniri
# ---------------------------------------------------------------------------
#: Numele urmei în `collector_cursors`. Prefixul `reaper:` îl ține departe de
#: numele de colectoare, care sunt surse de evenimente.
REAPER_MARKER = "reaper:sessions"

#: Vocabularul stărilor. Îl citește `selfcheck/checks.py:check_session_reaper`,
#: deci e un contract între două fișiere și e fixat de test — un șir schimbat
#: aici și necitit acolo ar face verificarea să raporteze o stare inexistentă
#: drept „nu știu", la nesfârșit.
REAPER_WORKING = "working"   # scan de încredere, instrucțiunea a rulat
REAPER_BLIND = "blind"       # `/proc` necitibil: `trusted = False`, nimic atins
REAPER_WAITING = "waiting"   # coada de audit nu e citită până dincolo de scan

#: Cât de des se rescrie urma când starea NU se schimbă.
#:
#: Urma are două întrebuințări, iar a doua o cere: „ce stare" se scrie la
#: schimbare, dar „mai rulează cineva" se citește din `updated_at`, și o valoare
#: care nu se mai atinge devine indistinguibilă de un daemon oprit. Cinci minute
#: înseamnă un rând scris de 288 de ori pe zi — nimic — și o fereastră în care
#: `check_session_reaper` poate spune „urma a înghețat" fără să acuze o gazdă
#: liniștită.
REAPER_REFRESH_S = 300


async def record_reaper_state(db: Database, state: str,
                              seen_through: datetime | None) -> None:
    """Scrie ce face reaper-ul acolo unde se poate citi după o repornire.

    Jurnalul nu e de ajuns, și nu din principiu: pe gazda de producție nu există
    `/var/log/journal`, deci jurnalul stă în RAM (2,79 zile măsurate) și se
    pierde la fiecare reboot. Un WARNING scris o dată, la schimbarea stării, e
    exact felul de dovadă care dispare fix când e nevoie de ea — iar «reaper-ul
    e înfometat» și «n-a murit nicio sesiune» arată identic pentru oricine se
    uită de-afară.

    `cursor_at` ia filigranul cozii de audit, nu ora scrierii: diferența dintre
    el și `now()` E mărimea întârzierii, adică singurul număr din care se poate
    spune dacă starea `waiting` e o clipă sau o zi. `NULL` când nu s-a măsurat
    încă niciun filigran — „nu știu" e o a treia valoare și n-are voie să fie
    scrisă ca zero.

    Eșecul se loghează și se înghite, ca la `db/identity_mirror.py:_record`:
    dacă nici urma nu se poate scrie, baza e căzută, iar asta se aude mai tare
    decât o sesiune închisă târziu. Ce NU are voie să facă e să oprească
    închiderea sesiunilor — scrierea e o raportare, nu o condiție.
    """
    try:
        await db.execute(
            """
            INSERT INTO collector_cursors (name, cursor, cursor_at, updated_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (name) DO UPDATE
                SET cursor = EXCLUDED.cursor,
                    cursor_at = EXCLUDED.cursor_at,
                    updated_at = now()
            """,
            REAPER_MARKER, state, seen_through)
    except Exception as exc:  # noqa: BLE001
        log.error("cannot record the session reaper state",
                  extra={"state": state, "detail": str(exc)[:220]})


async def read_reaper_state(db: Database) -> dict[str, Any] | None:
    """Urma reaper-ului, sau `None` dacă n-a fost scrisă niciodată."""
    row = await db.fetchrow(
        "SELECT cursor, cursor_at, updated_at FROM collector_cursors "
        "WHERE name = $1",
        REAPER_MARKER)
    return dict(row) if row is not None else None


async def _promote_interactive(db: Database, session_ids: list[int]) -> int:
    """Marchează drept interactivă orice sesiune care a rulat ceva de la un terminal.

    Se citește din comenzile ei, fiindcă logarea nu poartă informația asta — vezi
    nota lungă din `is_interactive`. Consecința, spusă pe față: alerta pleacă la
    PRIMA COMANDĂ, nu la logare. Cine se conectează și nu tastează nimic nu
    produce niciun mesaj — dar nici nu face nimic.

    `terminal` se aduce la zi odată cu fanionul, ca mesajul să poată spune `pts0`
    în loc de `ssh`: un panou care arată altceva decât ce s-a folosit e un panou
    în care nu ai încredere a doua oară.

    `ORDER BY session_id, id` — adică PRIMUL terminal al sesiunii, nu ultimul.
    Nu e o preferință de scriere: un `sudo su - altcineva` deschide un `pts` nou
    în aceeași sesiune, iar cu ultimul, panoul ar arăta terminalul pe care omul
    a ajuns, nu pe cel de pe care a intrat. Prima comandă cu terminal e chiar
    cea care a promovat sesiunea, deci ea e și cea care o descrie.
    """
    if not session_ids:
        return 0
    result = await db.execute(
        """
        UPDATE login_sessions s
           SET interactive = true, terminal = c.tty
          FROM (SELECT DISTINCT ON (session_id) session_id, tty
                  FROM session_commands
                 WHERE session_id = ANY($1::bigint[]) AND tty ~ $2
                 ORDER BY session_id, id) c
         WHERE s.id = c.session_id AND s.interactive = false
        """,
        session_ids, REAL_TTY_SQL)
    return int(str(result).rsplit(" ", 1)[-1]) if result else 0


async def _refresh_counters(db: Database, session_ids: list[int]) -> None:
    """Recalculează contoarele din rândurile REALE, nu prin incrementare.

    Un `+= n` ținut în cod se desincronizează la prima repornire în mijlocul unui
    lot, iar rezumatul de la închiderea sesiunii ar raporta un număr de comenzi
    care nu se potrivește cu lista de sub el. Numărate din tabelă, cele două nu
    pot să nu fie de acord.
    """
    if not session_ids:
        return
    await db.execute(
        """
        UPDATE login_sessions s
           SET command_count = c.n, sudo_count = c.priv
          FROM (SELECT session_id,
                       count(*) AS n,
                       count(*) FILTER (
                           WHERE split_part(coalesce(exe, ''), '/', -1) = ANY($2::text[])
                       ) AS priv
                  FROM session_commands
                 WHERE session_id = ANY($1::bigint[])
                 GROUP BY session_id) c
         WHERE s.id = c.session_id
           AND (s.command_count, s.sudo_count) IS DISTINCT FROM (c.n, c.priv)
        """,
        session_ids, sorted(PRIVILEGED))


# ---------------------------------------------------------------------------
# Citiri
# ---------------------------------------------------------------------------
async def open_sessions(db: Database) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT id, session_key, username, host(src_ip) AS src_ip, terminal,
               interactive, opened_at, command_count, sudo_count
          FROM login_sessions WHERE closed_at IS NULL
         ORDER BY opened_at DESC
        """)
    return [dict(r) for r in rows]


async def session_commands(db: Database, session_id: int,
                           limit: int = 500) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT ts, username, exe, argv, ppid, success
          FROM session_commands WHERE session_id = $1
         ORDER BY id LIMIT $2
        """,
        session_id, limit)
    return [dict(r) for r in rows]


async def learning_started_at(db: Database) -> datetime | None:
    """Începutul ferestrei de învățare: cel mai vechi fapt cunoscut.

    Derivat din conținut, nu dintr-o dată scrisă separat. O dată ținută aparte
    s-ar putea desincroniza de tabelă, iar atunci fereastra ar spune „am învățat"
    despre o linie de referință goală.
    """
    return await db.fetchval("SELECT min(first_seen) FROM login_baseline")
