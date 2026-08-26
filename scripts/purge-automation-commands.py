#!/usr/bin/env python3
"""Șterge din `session_commands` istoricul deja strâns al automatizărilor.

Perechea, pe replica externă, e `aggregator/bin/purge-automation-commands.ts`.
Sunt două scripturi și nu unul cu două moduri fiindcă cele două baze n-au nimic
în comun în afară de regulă: PostgreSQL de aici se atinge cu `asyncpg` și cu
parola din `/etc/sentinel/secrets.env`, MariaDB de acolo cu `mysql2` și cu
variabilele de mediu ale găzduirii, care nu există nicăieri pe gazda asta. Un
script care ar cuprinde amândouă ar trebui să care un client MySQL în venv-ul
agentului și să primească parola replicii în linia de comandă — adică exact ce
`docs/SECURITATE.md` interzice.

## Două moduri, fiindcă sunt două probleme diferite

**Pe cont** (`--accounts`, implicit din configurație) — aceeași regulă ca filtrul
care oprește scrierea rândurilor noi (`sentinel/db/repo/logins.py`,
`is_dropped_command`):

    contul e în `history.skip_command_accounts`  ȘI  comanda n-a avut terminal

Ambele bucăți vin de acolo, nu sunt rescrise aici: conturile din configurație —
REZOLVATE, vezi mai jos —, tiparul de terminal din `logins.REAL_TTY_SQL`.

**Pe sesiune** (`--sessions`, cu `--list-sessions` ca să le vezi) — pentru
istoricul de dinaintea filtrului. Măsurat pe gazdă pe 25 august 2026: cele
2 978 485 de rânduri vechi NU sunt pe contul de automatizare, sunt pe contul de
logare al operatorului: `scripts/deploy.sh` cerea `--user`, iar `auid` e uid-ul
de LOGARE și supraviețuiește lui `sudo`. Filtrul pe cont ar șterge din ele 1 143.

Pe același cont stau însă și diagnosticele rulate de la distanță de operator —
`psql` de 69 977 de ori, `find` de 90 659, `cat` de 100 938, `ps` de 38 051 —,
care trebuie PĂSTRATE. Nicio regulă pe cont nu le poate deosebi, fiindcă e chiar
același cont. Ce le deosebește e sesiunea: un deploy are 250 000–560 000 de
comenzi, o sesiune de diagnostic a unui om are sute. Granița se vede la citire,
deci se citește — `--list-sessions` o arată — și alege operatorul. Un prag scris
în cod ar fi o presupunere despre gazda altcuiva.

## Conturile se REZOLVĂ, nu se compară literal

Același cont ajunge în tabelă sub două ortografii: numele, și `auid`-ul numeric
ca șir atunci când nici auditd nici `pwd` n-au putut rezolva unul. Măsurat:
87 935 de rânduri scrise ca `username = '1000'`. Un `--accounts sentinel-deploy`
comparat literal le-ar lăsa pe toate în urmă, în tăcere, cu un raport care arată
ca o bază curată. De-aceea lista se trece prin
`sentinel.config.resolve_skip_command_accounts`, iar raportul TIPĂREȘTE
ortografiile pe care le va căuta — inclusiv ca să poată fi copiate în comanda
replicii, care n-are `/etc/passwd`-ul ăsta.

## Contoarele sesiunii se aduc la zi

`login_sessions` nu se șterge, dar `command_count` de pe rând e un contor
MEMORAT al rândurilor șterse. Lăsat neatins, sesiunea 2521 ar arăta «558 079
comenzi» deasupra unui tabel gol — fix eșecul pentru care există
`_refresh_counters`. Deci după ștergere: `command_count` și `sudo_count` se
renumără din tabelă, iar cât s-a șters intră în `commands_purged`
(`0028_commands_purged.sql`), ca informația «sesiunea asta chiar a rulat o
jumătate de milion de comenzi» să nu dispară odată cu rândurile.

## ÎNTÂI migrația, apoi scriptul

`0028_commands_purged.sql` adaugă coloana `commands_purged`, iar scriptul o
citește chiar în listare. Rulat pe o bază nemigrată, `--list-sessions` moare cu

    column s.commands_purged does not exist

— verificat pe gazdă. Deci ordinea de livrare e:

    sudo sentinel migrate                                      # întâi
    sudo -u sentinel /opt/sentinel/venv/bin/python \\
         scripts/purge-automation-commands.py --list-sessions  # abia apoi

Pe replică e la fel, cu `0016_commands_purged.sql`: `npm run migrate` înaintea
primului `npm run purge-automation`.

## Cum se rulează

    sudo -u sentinel /opt/sentinel/venv/bin/python \\
         scripts/purge-automation-commands.py                  # uscat, implicit
    sudo -u sentinel /opt/sentinel/venv/bin/python \\
         scripts/purge-automation-commands.py --list-sessions  # ce sesiuni sunt
    sudo -u sentinel /opt/sentinel/venv/bin/python \\
         scripts/purge-automation-commands.py --sessions 2521,2530
    sudo -u sentinel /opt/sentinel/venv/bin/python \\
         scripts/purge-automation-commands.py --sessions 2521,2530 --apply

Modul uscat nu scrie nimic: numără și raportează. Ștergerea se face în tranșe cu
`LIMIT`, fiecare într-o tranzacție proprie, ca lock-urile să dureze milisecunde
și ca o întrerupere cu Ctrl-C să lase baza într-o stare bună — ce s-a șters
rămâne șters, restul se ia de la capăt la rularea următoare.

## Spațiul NU se întoarce singur

`DELETE` raportează rândurile șterse și lasă fișierul exact la fel de mare:
spațiul devine reutilizabil de tabelă, nu liber pentru sistemul de fișiere.
`VACUUM (ANALYZE)` — pe care scriptul îl rulează după ștergere — marchează
spațiul ca reutilizabil și aduce statisticile la zi, dar tot nu micșorează
fișierul.

Singurul lucru care îl micșorează e `VACUUM FULL`, iar ăla NU se rulează de
aici: rescrie tabela sub `ACCESS EXCLUSIVE`, adică ingestia și panoul așteaptă
tot timpul cât durează, și are nevoie de încă o dată dimensiunea tabelei liberă
pe disc. E o decizie cu un cost real, deci o ia operatorul, nu scriptul — care
însă tipărește comanda exactă, fiindcă un raport «am șters 2,9 milioane de
rânduri» urmat de o bază la fel de mare e chiar tiparul confirmării intenției
pe care îl păzește `CLAUDE.md`.

De aceea raportul spune AMÂNDOUĂ: câte rânduri au căzut (efectul cerut) și cât
măsoară tabela înainte și după (efectul pe disc, care se schimbă abia după
`VACUUM FULL`).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

# Scriptul stă în `scripts/`, adică lângă pachet, nu în el. Rulat cu python-ul
# din venv-ul agentului, `sentinel` e deja instalat și importul merge; rulat din
# arborele desfăcut de `deploy.sh`, nu e — de aceea rădăcina depozitului intră
# explicit în cale.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncpg  # noqa: E402

from sentinel.config import (  # noqa: E402
    Config, SkipAccounts, database_dsn, get_config, resolve_skip_command_accounts,
)
from sentinel.db.repo.logins import PRIVILEGED, REAL_TTY_SQL  # noqa: E402

TABLE = "session_commands"

#: Regula pe cont, în SQL. Gemenele ei în Python e `logins.is_dropped_command`.
#:
#: `tty IS NULL` cade tot aici, dinadins: `is_interactive(None)` e fals, deci un
#: rând fără terminal cunoscut e tratat la fel în amândouă părțile. „Nu știu ce
#: terminal a avut" nu e „a avut unul".
#:
#: Marginile de spațiu NU se taie aici cu `btrim`: sunt în chiar tiparul din
#: `REAL_TTY_SQL`, ca toate cele trei motoare să răspundă la fel despre `' pts0'`.
#: Până pe 25 august 2026 nu erau nicăieri în SQL, iar `is_interactive` făcea
#: `.strip()` — deci filtrul păstra rândul și curățarea îl ștergea.
PREDICATE = "username = ANY($1::text[]) AND (tty IS NULL OR tty !~ $2)"

#: Regula pe sesiune. Nu se uită nici la cont, nici la terminal: sesiunile le
#: alege operatorul, dintr-o listă pe care o citește.
SESSION_PREDICATE = "session_id = ANY($1::bigint[])"

#: Câte rânduri într-o singură instrucțiune. Aceeași valoare ca retenția
#: replicii (`aggregator/lib/retention.ts`): destul cât o restanță de milioane
#: să se golească în timp rezonabil, puțin cât lock-ul să dureze milisecunde.
BATCH = 5000

#: Câte sesiuni arată `--list-sessions` implicit. Pe gazdă sunt 197 fără terminal
#: (25 august 2026); plafonul e ca o gazdă cu istoric de un an să nu verse mii de
#: rânduri într-un terminal.
LIST_LIMIT = 40


def count_sql(predicate: str = PREDICATE) -> str:
    return f"SELECT count(*) FROM {TABLE} WHERE {predicate}"


def delete_sql(predicate: str = PREDICATE, *, limit_param: str = "$3") -> str:
    """O tranșă. `ctid` fiindcă `DELETE ... LIMIT` nu există în PostgreSQL.

    Limita pleacă tot ca PARAMETRU, deși azi vine dintr-o constantă de aici:
    regula „valorile nu se interpolează niciodată în SQL" nu are excepții care
    merită ținute minte.
    """
    return (f"DELETE FROM {TABLE} WHERE ctid = ANY(ARRAY("
            f"SELECT ctid FROM {TABLE} WHERE {predicate} LIMIT {limit_param}))")


def size_sql() -> str:
    return ("SELECT pg_total_relation_size($1::regclass) AS bytes, "
            "pg_size_pretty(pg_total_relation_size($1::regclass)) AS pretty")


#: Câte rânduri are FIECARE sesiune atinsă, acum. Se cere înainte și după
#: ștergere: diferența e ce s-a șters cu adevărat din fiecare, nu ce ne-am
#: propus să ștergem.
PER_SESSION_SQL = (
    f"SELECT session_id, count(*) AS n, "
    f"       count(*) FILTER (WHERE split_part(coalesce(exe, ''), '/', -1) "
    f"                        = ANY($2::text[])) AS priv "
    f"  FROM {TABLE} WHERE session_id = ANY($1::bigint[]) GROUP BY session_id")

#: Sesiunile care AR fi atinse de o ștergere, cu câte rânduri fiecare. Rulează și
#: în modul uscat: e chiar ce trebuie să vadă operatorul înainte să hotărască.
TOUCHED_SQL = (
    f"SELECT session_id, count(*) AS n FROM {TABLE} "
    f"WHERE session_id IS NOT NULL AND {{predicate}} GROUP BY session_id")

#: Câte rânduri se numără CEL MULT pentru o singură sesiune, în listare.
#:
#: Măsurat pe gazdă, pe 25 august 2026, cu vechea listare care număra exact:
#:
#:     Parallel Index Only Scan on session_commands  rows=951772 loops=3
#:     Heap Fetches: 243723   Execution Time: 18395.833 ms
#:
#: 18,4 secunde și trei procese de fundal, plătite exact când operatorul cere
#: lista — adică ÎNAINTE de curățare, când tabela e cea mai mare, și pe o gazdă
#: care în aceeași zi a dat 504 pe panou. Nici `statement_timeout` nu-l oprea:
#: `_connect` îl pune pe `0` fiindcă `VACUUM` are nevoie de asta.
#:
#: Numărătoarea exactă nu se putea ieftini: ordonarea după ea cere numărarea
#: TUTUROR sesiunilor, iar cele mai grase — chiar cele care se listează — sunt
#: cele care costă. Deci se numără MĂRGINIT: pentru fiecare sesiune se citesc cel
#: mult atâtea rânduri, iar coloana arată «2000+» când s-a atins plafonul.
#: Alegerea operatorului e între sute și sute de mii — trei ordine de mărime —,
#: și pentru ea „peste 2000" spune tot atât cât 558 079. Cifra exactă apare
#: oricum înainte de orice ștergere: `--sessions` în modul uscat o numără din
#: tabelă, pentru sesiunile alese.
LIST_PROBE_CAP = 2000

#: Câte rânduri are voie să citească listarea, cu totul.
#:
#: Costul e `sesiuni_neinteractive × LIST_PROBE_CAP`, și e mărginit prin
#: construcție, nu prin noroc. Pe gazdă sunt 197 de sesiuni fără terminal, deci
#: 394 000 de intrări de index în loc de 2,85 milioane de rânduri cu 243 723 de
#: citiri din heap. Dacă o gazdă are atâtea sesiuni încât nici asta nu mai
#: încape, listarea NU numără deloc și o spune — vezi `list_sessions`.
LIST_PROBE_BUDGET = 500_000

#: Câte sesiuni fără terminal are gazda. Se cere înaintea listării, ca să se știe
#: dacă numărătoarea mărginită încape în buget. Rulează pe `login_sessions`, care
#: are sute de rânduri, nu milioane.
NONINTERACTIVE_COUNT_SQL = ("SELECT count(*) AS n FROM login_sessions "
                            "WHERE interactive = false")

#: Sesiunile fără terminal, cele mai grase întâi, cu numărătoarea MĂRGINITĂ.
#:
#: `interactive` e proprietatea SESIUNII (`_promote_interactive` o pune la prima
#: comandă cu `tty` real), deci o sesiune de om cu shell nu apare aici deloc.
#: Numărul arătat e cel numărat din tabelă, nu `command_count` — pe o gazdă pe
#: care s-a mai curățat o dată, cele două diferă, iar cel care contează pentru
#: „ce mai am de șters" e primul. `command_count` se arată alături, tocmai ca
#: dezacordul dintre ele să se vadă în loc să fie ales tăcut de cod.
#:
#: `LATERAL` cu `LIMIT` înăuntru, nu `count(*)` peste toată tabela: subinterogarea
#: se oprește la plafon pentru fiecare sesiune, deci munca e
#: `sesiuni × LIST_PROBE_CAP` și nu „câte rânduri o fi având gazda".
LIST_SESSIONS_SQL = f"""
SELECT s.id, s.session_key, s.username, s.terminal, s.opened_at,
       s.command_count, s.commands_purged,
       p.n AS rows_now, (p.n >= $2) AS capped
  FROM login_sessions s
  CROSS JOIN LATERAL (
       SELECT count(*) AS n FROM (
            SELECT 1 FROM {TABLE} c WHERE c.session_id = s.id LIMIT $2) t) p
 WHERE s.interactive = false
 ORDER BY p.n DESC, s.command_count DESC, s.opened_at DESC
 LIMIT $1
"""

#: Aceeași listă, pe o gazdă cu prea multe sesiuni ca să fie măsurate.
#:
#: Ordonarea cade atunci pe `command_count`, care e un contor MEMORAT — adică
#: exact felul de afirmație de care se ferește tot fișierul ăsta. De-aia coloana
#: numărată din tabelă se tipărește ca `?`, nu ca o cifră: „n-am măsurat" și
#: „am măsurat zero" nu au voie să arate la fel.
LIST_SESSIONS_UNMEASURED_SQL = """
SELECT s.id, s.session_key, s.username, s.terminal, s.opened_at,
       s.command_count, s.commands_purged
  FROM login_sessions s
 WHERE s.interactive = false
 ORDER BY s.command_count DESC, s.opened_at DESC
 LIMIT $1
"""

#: Sesiunile cerute care sunt INTERACTIVE, adică ale unui om la tastatură.
#: Ștergerea le refuză: modul pe sesiune e o unealtă cu bătaie mare, iar singurul
#: lucru pe care baza îl știe sigur despre „a fost cineva acolo" e fanionul ăsta.
INTERACTIVE_SQL = ("SELECT id, username, opened_at FROM login_sessions "
                   "WHERE id = ANY($1::bigint[]) AND interactive = true "
                   "ORDER BY id")

#: Sesiunile cerute care nu există deloc. Un identificator greșit tastat nu are
#: voie să treacă drept „sesiune fără nimic de șters".
MISSING_SQL = ("SELECT u.id FROM unnest($1::bigint[]) AS u(id) "
               "LEFT JOIN login_sessions s ON s.id = u.id "
               "WHERE s.id IS NULL ORDER BY u.id")

#: Contoarele, aduse la zi după ștergere. `command_count` și `sudo_count` se
#: RENUMĂRĂ din tabelă (invariantul lui `_refresh_counters`); `commands_purged`
#: primește câte au căzut, cumulat.
REFRESH_SQL = """
UPDATE login_sessions SET command_count = $2, sudo_count = $3,
       commands_purged = commands_purged + $4
 WHERE id = $1
"""


def accounts_of(cfg: Config, override: str | None) -> list[str]:
    """Conturile de curățat, din configurație sau din linia de comandă.

    Gol NU e „nimic de făcut", e „nu știu": scriptul se oprește și o spune. Un
    raport «0 rânduri de șters» pe o gazdă unde nimeni n-a scris încă secțiunea
    `history:` ar arăta exact ca o bază deja curată.
    """
    if override:
        return [name.strip() for name in override.split(",") if name.strip()]
    return list(cfg.history.skip_command_accounts)


def parse_session_ids(text: str) -> list[int]:
    """`--sessions 2521, 2530` → `[2521, 2530]`.

    Orice bucată care nu e un număr e o EROARE, nu o bucată sărită: cine a
    tastat `2521,25 30` crede că a dat două sesiuni, iar o listă tăcut mai scurtă
    ar lăsa în urmă exact rândurile pe care credea că le-a șters.
    """
    ids: list[int] = []
    for bucata in text.split(","):
        bucata = bucata.strip()
        if not bucata:
            continue
        if not bucata.isdigit():
            raise ValueError(f"„{bucata}” nu e un identificator de sesiune")
        ids.append(int(bucata))
    return ids


def _n(value: int) -> str:
    return f"{value:,}".replace(",", " ")


async def _table_size(conn: Any) -> tuple[int, str]:
    row = await conn.fetchrow(size_sql(), TABLE)
    return int(row["bytes"]), str(row["pretty"])


async def _per_session(conn: Any, ids: list[int]) -> dict[int, tuple[int, int]]:
    if not ids:
        return {}
    rows = await conn.fetch(PER_SESSION_SQL, ids, sorted(PRIVILEGED))
    return {int(r["session_id"]): (int(r["n"]), int(r["priv"])) for r in rows}


async def list_sessions(conn: Any, *, limit: int = LIST_LIMIT,
                        out: Any = None, cap: int = LIST_PROBE_CAP,
                        budget: int = LIST_PROBE_BUDGET) -> list[dict[str, Any]]:
    """Sesiunile fără terminal, ordonate după câte comenzi mai au în tabelă.

    Nu decide nimic și nu șterge nimic: arată granița, ca s-o vadă operatorul.
    Un deploy are sute de mii de comenzi, o sesiune de diagnostic a unui om are
    sute — diferența e de trei ordine de mărime și nu are nevoie de un prag
    codificat ca să fie evidentă.

    Numărătoarea e MĂRGINITĂ (`LIST_PROBE_CAP`) fiindcă varianta exactă costa
    18,4 secunde și trei procese de fundal pe gazdă, chiar în clipa în care
    operatorul se uită la listă — vezi comentariul constantei. Ce se pierde e
    cifra exactă a sesiunilor grase, care nu intră în nicio decizie de aici;
    ce nu se pierde e faptul că numărul vine din TABELĂ, nu dintr-un contor.

    Când nici numărătoarea mărginită nu încape în buget, nu se măsoară nimic și
    se spune: coloana devine `?`, iar ordonarea trece pe contorul memorat. Un
    număr inventat ar fi mai rău decât lipsa lui.
    """
    out = out if out is not None else sys.stdout
    nesesiuni = int(await conn.fetchval(NONINTERACTIVE_COUNT_SQL) or 0)
    masurat = nesesiuni * cap <= budget
    if masurat:
        rows = [dict(r) for r in await conn.fetch(LIST_SESSIONS_SQL, limit, cap)]
    else:
        rows = [dict(r) for r in
                await conn.fetch(LIST_SESSIONS_UNMEASURED_SQL, limit)]

    print(f"Sesiuni FĂRĂ terminal, cele mai grase întâi (cel mult {limit} din "
          f"{_n(nesesiuni)}):", file=out)
    print("", file=out)
    print(f"{'id':>7}  {'în tabelă':>10}  {'contor':>10}  {'șterse':>9}  "
          f"{'cont':<20} {'deschisă':<20} cheie", file=out)
    for r in rows:
        deschisa = str(r["opened_at"])[:19]
        if not masurat:
            # „N-am numărat" — nu zero, nu o estimare.
            acum = "?"
        elif r.get("capped"):
            acum = f"{_n(cap)}+"
        else:
            acum = _n(int(r["rows_now"]))
        print(f"{r['id']:>7}  {acum:>10}  {_n(int(r['command_count'] or 0)):>10}  "
              f"{_n(int(r['commands_purged'])):>9}  "
              f"{str(r['username'] or '—'):<20} {deschisa:<20} "
              f"{r['session_key']}", file=out)
    if not rows:
        # Lista goală e o stare validă și trebuie să se citească ca atare, nu ca
        # o interogare care n-a mers.
        print("  (niciuna — nicio sesiune neinteractivă în bază)", file=out)
    print("", file=out)
    print("Alege-le pe cele de șters și dă-le explicit:", file=out)
    print("    --sessions <id,id,…>            uscat, arată ce ar cădea",
          file=out)
    print("    --sessions <id,id,…> --apply    șterge", file=out)
    print("Coloana «șterse» e cât s-a mai curățat din sesiune până acum.",
          file=out)
    if masurat:
        print(f"«în tabelă» e numărat acum, dar se oprește la {_n(cap)}: "
              f"«{_n(cap)}+» înseamnă atâtea sau mai multe. Numărătoarea "
              f"întreagă costa 18 s pe gazdă.", file=out)
        print("«contor» e `command_count` de pe rândul sesiunii. Dacă cele două "
              "nu seamănă, contorul a rămas în urmă.", file=out)
        print("Cifra exactă a sesiunilor alese o dă `--sessions <id,…>` fără "
              "`--apply`.", file=out)
    else:
        print(f"«în tabelă» e `?`: sunt {_n(nesesiuni)} sesiuni fără terminal, "
              f"iar numărarea lor ar citi peste {_n(budget)} de rânduri. NU s-a "
              f"măsurat nimic.", file=out)
        print("Ordonarea e după `command_count`, un contor MEMORAT — poate "
              "descrie rânduri care nu mai există. Verifică sesiunea aleasă cu "
              "`--sessions <id>` fără `--apply`.", file=out)
    return rows


async def _guard_sessions(conn: Any, ids: list[int], *, out: Any) -> bool:
    """Refuză identificatorii care nu descriu ce crede operatorul că descriu.

    Două stări separate, fiindcă cer lucruri diferite de la om: o sesiune care nu
    există (probabil o cifră greșită) și una interactivă (există, dar e a unui om
    la tastatură — exact istoricul pe care nimic de aici n-are voie să-l ia).
    """
    lipsa = [int(r["id"]) for r in await conn.fetch(MISSING_SQL, ids)]
    umane = [dict(r) for r in await conn.fetch(INTERACTIVE_SQL, ids)]
    if lipsa:
        print(f"Nu există sesiunile: {', '.join(str(i) for i in lipsa)}",
              file=out)
    for r in umane:
        print(f"Sesiunea {r['id']} e INTERACTIVĂ (cont "
              f"{r['username'] or 'necunoscut'}, deschisă {str(r['opened_at'])[:19]}) "
              f"— e a unui om la tastatură, nu o șterg.", file=out)
    if lipsa or umane:
        print("Nu s-a șters nimic. Verifică lista cu --list-sessions.", file=out)
        return False
    return True


async def purge(conn: Any, accounts: list[str] | None = None, *, apply: bool,
                batch: int = BATCH, out: Any = None,
                session_ids: list[int] | None = None,
                spellings: SkipAccounts | None = None) -> dict[str, int]:
    """Numără, șterge dacă i se cere, și raportează FAPTE pe fiecare pas.

    Exact unul dintre `accounts` și `session_ids`: sunt două reguli diferite, iar
    una care le-ar combina ar fi imposibil de citit din raport.

    `out` se ia la APEL, nu ca valoare implicită legată la definirea funcției:
    altfel raportul ar pleca spre `sys.stdout`-ul de la import, iar orice
    redirectare de după — inclusiv `tee` într-un fișier — l-ar pierde.
    """
    out = out if out is not None else sys.stdout
    if (accounts is None) == (session_ids is None):
        raise ValueError("exact unul dintre `accounts` și `session_ids`")

    pe_sesiuni = session_ids is not None
    if pe_sesiuni:
        predicate, params = SESSION_PREDICATE, (session_ids,)
    else:
        predicate, params = PREDICATE, (accounts, REAL_TTY_SQL)
    limit_param = f"${len(params) + 1}"

    bytes_before, pretty_before = await _table_size(conn)
    total_rows = await conn.fetchval(f"SELECT count(*) FROM {TABLE}")
    matching = await conn.fetchval(count_sql(predicate), *params)

    if pe_sesiuni and not await _guard_sessions(conn, session_ids, out=out):
        return {"matching": 0, "deleted": 0, "remaining": 0, "refused": 1,
                "bytes_before": bytes_before, "bytes_after": bytes_before}

    print(f"tabela   : {TABLE}", file=out)
    if pe_sesiuni:
        print(f"sesiuni  : {', '.join(str(i) for i in session_ids)}", file=out)
        print("regula   : TOATE comenzile sesiunilor astea, indiferent de cont "
              "și de terminal", file=out)
    else:
        if spellings is not None:
            print(f"conturi  : {', '.join(spellings.configured_names)}", file=out)
            print(f"caut ca  : {', '.join(sorted(accounts or []))}", file=out)
            if not spellings.lookup_ok:
                print("  ATENȚIE: nu s-a putut citi baza de conturi a gazdei, "
                      "deci uid-urile lipsesc din listă.", file=out)
                print("  Rândurile scrise cu auid numeric NU vor fi găsite.",
                      file=out)
            for nume in spellings.unresolved:
                print(f"  ATENȚIE: contul „{nume}” nu există pe gazda asta; "
                      f"caut doar după nume.", file=out)
        else:
            print(f"conturi  : {', '.join(accounts or [])}", file=out)
        print(f"regula   : cont din listă ȘI tty care nu potrivește "
              f"{REAL_TTY_SQL!r}", file=out)
    print(f"înainte  : {_n(total_rows)} rânduri, {pretty_before}", file=out)
    procent = f" ({100 * matching / total_rows:.1f}%)" if total_rows else ""
    print(f"potrivesc: {_n(matching)} rânduri{procent}", file=out)

    # Ce sesiuni ating rândurile astea, și câte rânduri au ELE acum. Se citește
    # ÎNAINTE de ștergere și în amândouă modurile: în cel uscat e chiar ce vrea
    # operatorul să vadă, iar în cel umed e baza pentru contoare.
    atinse = {int(r["session_id"]): int(r["n"]) for r in
              await conn.fetch(TOUCHED_SQL.format(predicate=predicate), *params)}
    if atinse:
        print(f"sesiuni atinse: {len(atinse)}", file=out)
        for sid, n in sorted(atinse.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  · {sid}: {_n(n)} rânduri", file=out)
        if len(atinse) > 10:
            print(f"  … și încă {len(atinse) - 10}", file=out)
    orfane = matching - sum(atinse.values())
    if orfane:
        # `session_id IS NULL` = comenzi a căror logare nu s-a văzut niciodată.
        # N-au contor de reparat, dar se șterg, deci se spun.
        print(f"din care fără sesiune legată: {_n(orfane)}", file=out)

    if not apply:
        print("\n[uscat] nu s-a șters nimic și nu s-a scris nimic.", file=out)
        print("        Rulează din nou cu --apply ca să șteargă.", file=out)
        return {"matching": matching, "deleted": 0, "remaining": matching,
                "sessions_touched": len(atinse), "counters_fixed": 0,
                "bytes_before": bytes_before, "bytes_after": bytes_before}

    inainte = await _per_session(conn, sorted(atinse))

    deleted = 0
    while True:
        tag = await conn.execute(delete_sql(predicate, limit_param=limit_param),
                                 *params, batch)
        n = int(str(tag).rsplit(" ", 1)[-1])
        deleted += n
        if n:
            print(f"  … {_n(deleted)} / {_n(matching)}", file=out, flush=True)
        if n < batch:
            break

    # Contoarele, ÎNAINTE de VACUUM: dacă rularea e întreruptă, mai bine cu
    # statistici vechi și contoare corecte decât invers. Un panou care minte e
    # exact ce reparăm; un planificator cu statistici vechi e doar mai lent.
    #
    # Se scade CE E ACUM din CE ERA, per sesiune: diferența e ce a căzut cu
    # adevărat din fiecare, nu ce ne-am propus. Ingestia rulează în paralel, iar
    # un rând nou apărut între cele două numărători ar face un `commands_purged`
    # prea mare dacă am crede planul în loc de măsurătoare.
    dupa = await _per_session(conn, sorted(atinse))
    counters_fixed = 0
    for sid in sorted(atinse):
        era, _ = inainte.get(sid, (0, 0))
        acum, priv = dupa.get(sid, (0, 0))
        cazute = max(era - acum, 0)
        await conn.execute(REFRESH_SQL, sid, acum, priv, cazute)
        counters_fixed += 1
    if counters_fixed:
        print(f"contoare : {counters_fixed} sesiuni renumărate "
              f"(command_count din tabelă, ce a căzut în commands_purged)",
              file=out)

    # VACUUM nu poate rula într-o tranzacție, deci pe conexiunea asta, în
    # autocommit. ANALYZE odată cu el: după ce dispare 95% dintr-o tabelă,
    # planificatorul lucrează cu statistici despre o tabelă care nu mai există.
    print("VACUUM (ANALYZE) …", file=out, flush=True)
    await conn.execute(f"VACUUM (ANALYZE) {TABLE}")

    # Faptul, nu intenția: se renumără CE MAI POTRIVEȘTE regula, după ștergere.
    # Codul de retur al lui DELETE spune ce a raportat serverul; numărătoarea
    # asta spune ce a rămas.
    remaining = await conn.fetchval(count_sql(predicate), *params)
    rows_after = await conn.fetchval(f"SELECT count(*) FROM {TABLE}")
    bytes_after, pretty_after = await _table_size(conn)

    print(f"\nșterse   : {_n(deleted)} rânduri", file=out)
    print(f"rămase   : {_n(rows_after)} rânduri, {pretty_after}", file=out)
    print(f"mai potrivesc regula: {_n(remaining)}"
          + ("" if remaining == 0 else "  ← NU e zero; vezi mai jos"), file=out)
    if remaining:
        print("  Rândurile astea au fost scrise DUPĂ ce a început ștergerea "
              "(ingestia rulează în paralel) sau ștergerea a fost întreruptă. "
              "Rulează scriptul din nou.", file=out)

    if bytes_after >= bytes_before:
        print(f"\nMărimea pe disc: {pretty_before} → {pretty_after}. "
              f"NU s-a micșorat, și e normal:", file=out)
    else:
        print(f"\nMărimea pe disc: {pretty_before} → {pretty_after}.", file=out)
    print("`DELETE` + `VACUUM` fac spațiul reutilizabil de tabelă; nu-l dau "
          "înapoi sistemului de fișiere.", file=out)
    print("Singurul lucru care micșorează fișierul e, iar el NU se rulează de "
          "aici:", file=out)
    print(f"    sudo -u postgres psql -d sentinel -c 'VACUUM FULL {TABLE}'",
          file=out)
    print("Rescrie tabela sub ACCESS EXCLUSIVE — ingestia și panoul așteaptă "
          "tot timpul cât durează —", file=out)
    print(f"și are nevoie de încă {pretty_after} liberi pe disc. E decizia ta, "
          f"nu a scriptului.", file=out)

    return {"matching": matching, "deleted": deleted, "remaining": remaining,
            "sessions_touched": len(atinse), "counters_fixed": counters_fixed,
            "bytes_before": bytes_before, "bytes_after": bytes_after}


async def _connect(cfg: Config) -> Any:
    # Conexiune proprie, nu pool-ul din `sentinel.db.engine`: acela pune
    # `statement_timeout = 30 s`, iar `VACUUM` pe o tabelă de sute de MB îl
    # depășește și ar fi omorât la mijloc — cu un mesaj despre timeout, nu
    # despre ce n-a apucat să facă.
    return await asyncpg.connect(
        database_dsn(cfg),
        server_settings={"application_name": "sentinel-purge",
                         "statement_timeout": "0"})


async def _main(args: argparse.Namespace) -> int:
    cfg = get_config()

    if args.list_sessions:
        conn = await _connect(cfg)
        try:
            await list_sessions(conn, limit=args.limit)
        finally:
            await conn.close()
        return 0

    session_ids: list[int] | None = None
    accounts: list[str] | None = None
    spellings: SkipAccounts | None = None

    if args.sessions is not None:
        try:
            session_ids = parse_session_ids(args.sessions)
        except ValueError as exc:
            print(f"--sessions: {exc}", file=sys.stderr)
            return 2
        if not session_ids:
            print("--sessions n-a primit niciun identificator.", file=sys.stderr)
            return 2
    else:
        nume = accounts_of(cfg, args.accounts)
        if not nume:
            print("Nu știu ce conturi să curăț: `history.skip_command_accounts` "
                  "e gol în /etc/sentinel/sentinel.yaml și nu s-a dat "
                  "--accounts.", file=sys.stderr)
            print("Gol înseamnă «nu se aruncă nimic», iar un raport «0 rânduri» "
                  "ar arăta ca o bază deja curată. Nu șterg nimic.",
                  file=sys.stderr)
            print("Dacă vrei să cureți istoricul de dinaintea filtrului, el nu "
                  "e pe contul de automatizare: vezi --list-sessions.",
                  file=sys.stderr)
            return 2
        spellings = resolve_skip_command_accounts(nume)
        accounts = sorted(spellings.matches)

    conn = await _connect(cfg)
    try:
        rezultat = await purge(conn, accounts, apply=args.apply,
                               batch=args.batch, session_ids=session_ids,
                               spellings=spellings)
    finally:
        await conn.close()
    if rezultat.get("refused"):
        return 2
    return 0 if rezultat["remaining"] == 0 or not args.apply else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="purge-automation-commands.py",
        description="Șterge din session_commands comenzile fără terminal ale "
                    "conturilor de automatizare, sau toate comenzile unor "
                    "sesiuni alese explicit.")
    p.add_argument("--apply", action="store_true",
                   help="chiar șterge. Fără el, scriptul doar numără.")
    p.add_argument("--accounts", default=None,
                   help="listă separată prin virgulă, în locul celei din "
                        "sentinel.yaml")
    p.add_argument("--sessions", default=None,
                   help="identificatori de sesiune, separați prin virgulă. "
                        "Șterge TOATE comenzile lor. Pentru istoricul de "
                        "dinaintea filtrului, care nu e pe contul de "
                        "automatizare.")
    p.add_argument("--list-sessions", action="store_true",
                   help="arată sesiunile fără terminal, cele mai grase întâi, "
                        "și nu șterge nimic")
    p.add_argument("--limit", type=int, default=LIST_LIMIT,
                   help=f"câte sesiuni arată --list-sessions (implicit "
                        f"{LIST_LIMIT})")
    p.add_argument("--batch", type=int, default=BATCH,
                   help=f"rânduri pe tranșă (implicit {BATCH})")
    args = p.parse_args(argv)
    if args.batch < 1:
        p.error("--batch trebuie să fie cel puțin 1")
    if args.limit < 1:
        p.error("--limit trebuie să fie cel puțin 1")
    if args.sessions is not None and args.accounts is not None:
        # Două reguli diferite. Combinate, raportul n-ar mai spune care rânduri
        # au căzut pentru care motiv, iar asta e tot ce are operatorul.
        p.error("--sessions și --accounts sunt două moduri diferite; alege unul")
    if args.list_sessions and args.apply:
        p.error("--list-sessions nu șterge nimic; scoate --apply")
    return asyncio.run(_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
