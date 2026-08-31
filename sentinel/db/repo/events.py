"""The raw_events pipeline: insert normalised events, query them, track cursors.

Collectors produce `model.event.Event`; this module writes them and reads them
back for the Events page. The attacker-controlled fields are stored verbatim
(the Event has already bounded their length) — truncating evidence to tidy it up
destroys what an investigation needs.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from sentinel.db.engine import Database
from sentinel.errors import StorageError
from sentinel.logging_setup import get_logger
from sentinel.model.event import Event

log = get_logger(__name__)

# Column order for the batch insert. Must match the placeholders below exactly.
_COLS = [
    "ts", "source", "action", "asset_id", "src_ip", "src_port", "dst_ip",
    "dst_port", "proto", "username", "http_method", "http_path", "http_query",
    "http_status", "http_ua", "http_host", "http_referer", "bytes_in",
    "bytes_out", "latency_ms", "process", "pid", "file_path", "tls_sni",
    "tls_ja4", "geo_country", "geo_asn", "geo_as_org", "reputation", "raw",
]

# `id` merge ÎNAINTEA celorlalte, folosit doar când `_preallocate_ids` a reușit
# — vezi `insert_batch`. Ținut separat de `_COLS` ca varianta obișnuită (fără
# id, cu implicitul din `bigserial`) să rămână calea care nu poate pica din
# cauza unei secvențe indisponibile.
_COLS_WITH_ID = ["id", *_COLS]

# src_ip/dst_ip sunt inet și raw e jsonb; restul se leagă ca atare. reputation
# e text[], pe care asyncpg îl mapează nativ dintr-o listă Python.
#
# Tipul se leagă de NUMELE coloanei, nu de poziția ei: o valoare hardcodată de
# tipul `"$5::inet"` ar rămâne corectă doar cât timp nimeni nu adaugă sau mută
# o coloană înaintea lui `src_ip` — exact ce se întâmplă mai jos cu `id`.
_TYPED_COLS = {"src_ip": "inet", "dst_ip": "inet", "raw": "jsonb"}


def _placeholders(cols: list[str]) -> str:
    return ", ".join(
        f"${i}::{_TYPED_COLS[c]}" if c in _TYPED_COLS else f"${i}"
        for i, c in enumerate(cols, start=1)
    )


_INSERT = f"INSERT INTO raw_events ({', '.join(_COLS)}) VALUES ({_placeholders(_COLS)})"
_INSERT_WITH_ID = (
    f"INSERT INTO raw_events ({', '.join(_COLS_WITH_ID)}) "
    f"VALUES ({_placeholders(_COLS_WITH_ID)})"
)


#: Ce se pune în locul unui octet NUL care a ajuns până aici.
#:
#: Un spațiu, fiindcă în practic toate cazurile în care apare — `argv` de la
#: auditd, un câmp binar dintr-un jurnal — NUL e un SEPARATOR. Șters, două
#: cuvinte s-ar lipi într-unul.
_NUL_REPLACEMENT = " "


def _scrub(value: Any) -> Any:
    """Scoate octeții NUL dintr-un text.

    PostgreSQL refuză `\u0000` în `text` și în `jsonb`. Un singur rând cu un NUL
    face să eșueze `executemany` pentru LOTUL ÎNTREG — deci un octet dintr-o
    linie de jurnal oprește colectarea pentru toate sursele, iar simptomul e
    tăcere, nu o eroare pe rândul vinovat.

    S-a întâmplat pe 25 august 2026: decodorul de argumente hexa al colectorului
    de auditd a început să producă NUL-uri (`argv` e NUL-separat în nucleu), iar
    ingestia a căzut în întregime.

    Reparația adevărată e la sursă, și e făcută acolo. Asta e plasa: `raw_events`
    primește text din cinci colectoare, iar al șaselea care va produce un octet
    nepotrivit nu are voie să oprească din nou totul.
    """
    if isinstance(value, str):
        return value.replace("\x00", _NUL_REPLACEMENT)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _row_tuple(ev: Event, cols: list[str] = _COLS) -> tuple[Any, ...]:
    row = ev.to_row()
    values: list[Any] = []
    for c in cols:
        if c == "raw":
            values.append(json.dumps(_scrub(row.get("raw") or {})))
        elif c == "reputation":
            values.append(list(row.get("reputation") or []))
        else:
            values.append(_scrub(row.get(c)))
    return tuple(values)


async def _preallocate_ids(db: Database, n: int) -> list[int] | None:
    """Rezervă `n` valori din `raw_events_id_seq`, ÎNAINTE de a scrie lotul.

    De ce înainte, și nu `INSERT ... RETURNING id` după: PostgreSQL nu
    garantează că ordinea rândurilor din `RETURNING` corespunde ordinii de
    intrare a unui `executemany`/`unnest` — „în practică se potrivesc" nu e o
    dovadă, e o observație, și e exact genul de raționament care a produs
    bug-urile din `CLAUDE.md`.

    Aici problema aia nu există: fiecare `Event` primește id-ul lui ÎNAINTE de
    orice INSERT, iar rândul se scrie cu id-ul pe care obiectul îl poartă deja.
    Nu există moment în care corespondența dintre un rând scris și comanda
    care i-a atribuit id-ul să depindă de ordinea vreunui rezultat — o
    atribuim noi, în Python, nu o citim înapoi.

    Eșuează închis: dacă secvența nu poate fi citită (bază picată, pool
    închis, timeout), se întoarce `None`, iar `insert_batch` scrie lotul cu
    id-ul implicit din `bigserial`, ca înainte de reparația asta. Colectarea
    e calea vitală — n-are voie să cadă ca să câștige o coloană de urmărire
    (`session_commands.event_id`, care rămâne NULL în cazul ăsta; vezi
    `sentinel/db/repo/logins.py:record_command`).
    """
    try:
        rows = await db.fetch(
            "SELECT nextval('raw_events_id_seq') AS id FROM generate_series(1, $1)", n)
    except (asyncpg.PostgresError, OSError, StorageError) as exc:
        log.warning(
            "could not preallocate raw_events ids; event_id will be NULL for this batch",
            extra={"detail": str(exc), "batch_size": n},
        )
        return None
    if len(rows) != n:
        # N-ar trebui să se poată întâmpla — `generate_series(1, n)` dă exact
        # `n` rânduri — dar o presupunere nevalidată aici ar însemna id-uri
        # atribuite la nimereală unor evenimente greșite, ceea ce regula 1 a
        # temei interzice explicit. Mai bine NULL peste tot lotul.
        log.warning(
            "raw_events id preallocation returned an unexpected row count",
            extra={"expected": n, "got": len(rows)},
        )
        return None
    return [int(r["id"]) for r in rows]


async def insert_batch(db: Database, events: list[Event]) -> int:
    if not events:
        return 0
    ids = await _preallocate_ids(db, len(events))
    if ids is not None:
        for ev, new_id in zip(events, ids, strict=True):
            ev.id = new_id
        await db.executemany(_INSERT_WITH_ID, [_row_tuple(e, _COLS_WITH_ID) for e in events])
    else:
        await db.executemany(_INSERT, [_row_tuple(e) for e in events])
    return len(events)


# --- cursors ---------------------------------------------------------------
async def get_cursor(db: Database, name: str) -> str | None:
    return await db.fetchval("SELECT cursor FROM collector_cursors WHERE name = $1", name)


async def set_cursor(db: Database, name: str, cursor: str, *, events_seen: int = 0) -> None:
    await db.execute(
        """
        INSERT INTO collector_cursors (name, cursor, events_seen, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (name) DO UPDATE SET
            cursor      = EXCLUDED.cursor,
            events_seen = collector_cursors.events_seen + EXCLUDED.events_seen,
            updated_at  = now()
        """,
        name,
        cursor,
        events_seen,
    )


# --- reads for the Events page --------------------------------------------
async def recent(
    db: Database,
    *,
    limit: int = 200,
    source: str | None = None,
    action: str | None = None,
    src_ip: str | None = None,
    since_minutes: int | None = None,
) -> list[dict]:
    where = ["true"]
    args: list[Any] = []
    if source:
        args.append(source); where.append(f"source = ${len(args)}")
    if action:
        args.append(action); where.append(f"action = ${len(args)}")
    if src_ip:
        args.append(src_ip); where.append(f"src_ip = ${len(args)}::inet")
    if since_minutes:
        args.append(since_minutes); where.append(f"ts > now() - make_interval(mins => ${len(args)})")
    args.append(limit)
    rows = await db.fetch(
        f"""
        SELECT ts, source, action, host(src_ip) AS src_ip, src_port, username,
               http_method, http_path, http_status, http_host, http_ua,
               geo_country, geo_asn, geo_as_org, process, proto, dst_port
        FROM raw_events
        WHERE {' AND '.join(where)}
        ORDER BY ts DESC
        LIMIT ${len(args)}
        """,
        *args,
    )
    return [dict(r) for r in rows]


async def summary(db: Database, since_minutes: int = 60) -> dict[str, Any]:
    """Counts for the page header — total, per source, per action, top talkers."""
    total = await db.fetchval(
        "SELECT count(*) FROM raw_events WHERE ts > now() - make_interval(mins => $1)",
        since_minutes,
    )
    by_source = await db.fetch(
        """
        SELECT source, count(*) AS n
        FROM raw_events WHERE ts > now() - make_interval(mins => $1)
        GROUP BY source ORDER BY n DESC
        """,
        since_minutes,
    )
    top_ips = await db.fetch(
        """
        SELECT host(src_ip) AS ip, count(*) AS n,
               count(*) FILTER (WHERE action = 'auth_fail') AS auth_fails
        FROM raw_events
        WHERE ts > now() - make_interval(mins => $1) AND src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY n DESC LIMIT 8
        """,
        since_minutes,
    )
    return {
        "total": int(total or 0),
        "by_source": [dict(r) for r in by_source],
        "top_ips": [dict(r) for r in top_ips],
    }
