"""The raw_events pipeline: insert normalised events, query them, track cursors.

Collectors produce `model.event.Event`; this module writes them and reads them
back for the Events page. The attacker-controlled fields are stored verbatim
(the Event has already bounded their length) — truncating evidence to tidy it up
destroys what an investigation needs.
"""

from __future__ import annotations

import json
from typing import Any

from sentinel.db.engine import Database
from sentinel.model.event import Event

# Column order for the batch insert. Must match the placeholders below exactly.
_COLS = [
    "ts", "source", "action", "asset_id", "src_ip", "src_port", "dst_ip",
    "dst_port", "proto", "username", "http_method", "http_path", "http_query",
    "http_status", "http_ua", "http_host", "http_referer", "bytes_in",
    "bytes_out", "latency_ms", "process", "pid", "file_path", "tls_sni",
    "tls_ja4", "geo_country", "geo_asn", "geo_as_org", "reputation", "raw",
]

# src_ip/dst_ip are inet and raw is jsonb; the rest bind as-is. reputation is a
# text[] which asyncpg maps from a Python list natively.
_PLACEHOLDERS = ", ".join(
    {"src_ip": "$5::inet", "dst_ip": "$7::inet", "raw": "$30::jsonb"}.get(c, f"${i}")
    for i, c in enumerate(_COLS, start=1)
)
_INSERT = f"INSERT INTO raw_events ({', '.join(_COLS)}) VALUES ({_PLACEHOLDERS})"


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


def _row_tuple(ev: Event) -> tuple[Any, ...]:
    row = ev.to_row()
    values: list[Any] = []
    for c in _COLS:
        if c == "raw":
            values.append(json.dumps(_scrub(row.get("raw") or {})))
        elif c == "reputation":
            values.append(list(row.get("reputation") or []))
        else:
            values.append(_scrub(row.get(c)))
    return tuple(values)


async def insert_batch(db: Database, events: list[Event]) -> int:
    if not events:
        return 0
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
