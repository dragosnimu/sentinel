"""The numbers behind the dashboard.

One module, one round of queries, so the page renders from a single snapshot
rather than a dozen scattered calls that can disagree with each other by a few
seconds. Everything here is a plain aggregate; the interpretation lives in
insights.py.

## Două tipare care se repetă mai jos, și de ce

**Se numără perechile distincte, nu `count(DISTINCT)`.** PostgreSQL nu poate
face `count(DISTINCT x)` prin hash: agregatul sortează rândurile fiecărui grup.
Pe fereastra de 7 zile asta însemna, măsurat pe o replică a formei de pe gazdă,
o sortare externă de 387 000 de rânduri care se vărsa pe disc (`external merge
Disk: 12736kB`) — și care ajunsese să coste mai mult decât citirea datelor.
Scrise ca un `GROUP BY dimensiune, ip` interior plus un `count(ip)` exterior,
aceleași cifre ies dintr-un `HashAggregate` în memorie. Contează că e
`count(ip)`, nu `count(*)`: rândurile fără `src_ip` formează un grup propriu,
iar `count(*)` l-ar număra ca pe încă o adresă — exact rezultatul pe care
`count(DISTINCT)` nu-l dădea, fiindcă sare peste NULL.

**Întrebările „pe sursă" nu citesc toate rândurile.** `sources` — și
`_gap_insights` din insights.py — întreabă *când s-a văzut ultima dată fiecare
colector*. Scris ca `GROUP BY source` peste fereastră, răspunsul costă cât
întreaga fereastră, deși are ~20 de rânduri.

Pentru „ultima activitate" nici atât nu e nevoie: răspunsul stă deja în
`event_rollup_1m`, care e mărginit de (minute × perechi), nu de volumul de
evenimente. Vezi `last_activity_sql` — și acolo scrie și ce se pierde.

Numărătoarea pe 24 h a rămas o căutare punctuală pe fiecare pereche (sursă,
acțiune): costă cât numărul de perechi, iar fereastra ei e ziua curentă. Vezi
comentariul de la `_INVENTAR_SQL` pentru de unde vine lista de perechi și ce se
întâmplă când ea lipsește.
"""

from __future__ import annotations

from typing import Any

from sentinel.db.engine import Database

#: Perechile (sursă, acțiune) care se știe că există.
#:
#: Vine în primul rând din `event_rollup_1m`, fiindcă acolo perechile sunt deja
#: chei: tabela e mărginită de (minute × perechi), nu de volumul de evenimente,
#: deci întrebarea rămâne ieftină oricât ar crește `raw_events`. Pe gazdă erau
#: 24 de perechi și 138 000 de rânduri de rollup, față de milioane de rânduri
#: brute.
#:
#: Reuniunea cu ultima oră din `raw_events` NU e o plasă de siguranță
#: decorativă: jobul de întreținere rulează din oră în oră, deci un colector
#: pornit acum n-a intrat încă în rollup, iar fără reuniune ar lipsi din panou
#: exact în ora în care cineva se uită dacă a pornit. Ora e mărginită de volumul
#: unei ore, nu de fereastră — măsurat pe replică: 28 ms într-o oră obișnuită,
#: 315 ms într-o oră din ziua de vârf (233 000 de rânduri). E cel mai prost caz
#: și e plătit de două ori pe pagină; un `LIMIT` l-ar face constant, cu prețul
#: de a putea rata o sursă nouă și rară exact în timpul unei rafale, ceea ce e
#: mai rău decât trei sutimi de secundă.
#:
#: Ce NU acoperă reuniunea: dacă rollup-ul e gol sau vechi, lista conține doar
#: sursele care AU scris în ultima oră — adică fix cele care nu sunt tăcute.
#: Cine judecă tăcerea (`_gap_insights`) trebuie să verifice separat vârsta
#: rollup-ului și să spună că nu poate ști, în loc să raporteze „nimic tăcut"
#: dintr-o listă din care tăcuții au dispărut.
#:
#: Nu mai e folosit în modulul ăsta — `sources` ia și inventarul, și ultima
#: activitate, dintr-o singură trecere prin `last_activity_sql`. Rămâne fiindcă
#: `_gap_insights` din insights.py îl importă de aici.
_INVENTAR_SQL = """
    SELECT DISTINCT source, action FROM event_rollup_1m
     WHERE bucket > now() - interval '30 days'
    UNION
    SELECT DISTINCT source, action FROM raw_events
     WHERE ts > now() - interval '1 hour'
"""

#: Cât de veche are voie să fie frontiera rollup-ului înainte ca „ultima
#: activitate" să nu mai poată fi citită întreagă, în ore.
#:
#: Coada citită din `raw_events` pornește de la frontiera rollup-ului, deci în
#: mod normal cele două jumătăți se ating și nu există gaură. Plafonul ăsta e
#: singurul lucru care poate deschide una: dacă frontiera e mai veche de atât,
#: evenimentele dintre ea și plafon nu se văd nicăieri.
#:
#: E ales să fie ≥ întârzierea la care `_gap_insights` refuză deja să judece
#: tăcerea (`_TACERE_MINIMA_H`, 6 ore, în insights.py). Așa, gaura nu poate
#: apărea decât după ce singurul consumator care trage o concluzie din valoarea
#: asta a spus deja „nu pot ști" — altfel un `ultim` prea vechi ar fi produs
#: exact alarma falsă „sursa a amuțit" pe care regula aia o dă. Constanta nu se
#: importă de acolo fiindcă insights.py importă modulul ăsta, nu invers; dacă
#: pragul de acolo se mișcă, se mișcă și ăsta.
_PLAFON_COADA_ORE = 6


def last_activity_sql() -> str:
    """SQL fragment: one row per known (source, action) pair, with the last
    moment that pair was seen — columns `source`, `action`, `ultim`.

    Se pune în `WITH`-ul apelantului. `sources` de mai jos și `_gap_insights`
    din insights.py pun aceeași întrebare; scrisă de două ori, era plătită de
    două ori la fiecare încărcare a paginii — măsurat pe gazdă, ~9 s dintr-o
    pagină de 18,4 s, pe același răspuns.

    ## De unde vine răspunsul

    Din `event_rollup_1m`, nu din `raw_events`. Rollup-ul e mărginit de
    (minute × perechi) — 147 764 de rânduri și 24 de perechi pe gazdă — pe când
    `raw_events` are milioane, cu o partiție de 2967 MB. Măsurat pe gazdă, în
    același moment și pe aceleași date: 4445 ms peste `raw_events` pe 30 de
    zile, 104 ms așa, aceleași surse și aceleași valori.

    ## Coada neagregată, și de ce nu e o oră fixă

    Rollup-ul rămâne în urmă între rulări, deci ultima bucată de timp există
    doar în `raw_events`. Fereastra aia nu e o constantă: începe exact de la
    `max(bucket)`, frontiera rollup-ului, deci cele două jumătăți se ating
    oricât ar întârzia rularea.

    O oră fixă — ce face `_INVENTAR_SQL` — ar fi lăsat o gaură în funcționare
    normală: `sentinel-maintenance.timer` e `OnCalendar=hourly` cu
    `RandomizedDelaySec=300` și `AccuracySec=60`, deci între două rulări pot
    trece peste 66 de minute fără ca nimic să fie stricat. O sursă care a scris
    exact în minutele alea ar fi ieșit cu ultima activitate mai veche decât e,
    fix când cineva se uită dacă mai scrie.

    Legată de frontieră, fereastra e și mai ieftină decât ora fixă: în
    funcționare normală citește cât e de veche frontiera, adică minute.

    ## Ce se pierde: un minut, într-o singură direcție

    `bucket` e trunchiat la minut, deci pentru ce e deja agregat `ultim` poate
    fi cu până la 59 de secunde mai vechi decât adevărul — `max(bucket)` nu
    poate depăși `max(ts)`, deci niciodată invers. Pragurile care citesc
    valoarea sunt în ORE (6 și 72, în `_gap_insights`), iar eroarea e într-o
    singură direcție: poate face o sursă să pară puțin mai tăcută, niciodată
    mai proaspătă. O valoare de monitorizare care greșește spre vechi nu spune
    niciodată „e bine" când nu e.

    ## Ce se strică dacă rollup-ul se oprește

    Frontiera îngheață. Sub plafon, coada din `raw_events` acoperă în
    continuare tot ce e după ea, deci răspunsul rămâne întreg. Peste plafon
    (`_PLAFON_COADA_ORE`) se deschide o gaură, iar sursele care tăcuseră deja
    rămân cu `ultim` fix pe ultima frontieră — „tăcute de când s-a oprit
    rollup-ul", ceea ce e adevărat.

    Dacă rollup-ul e GOL, perechile rămân doar cele care au scris în ultimele
    `_PLAFON_COADA_ORE` ore — adică exact cele care nu tac. E aceeași gaură pe
    care o descrie `_INVENTAR_SQL`: cine trage o concluzie din tăcere verifică
    separat vârsta rollup-ului.

    ## Un singur rând pe pereche

    `UNION ALL` plus un `GROUP BY` exterior, nu `UNION ALL` gol. O pereche
    văzută în ambele ramuri ar ieși de două ori, iar un apelant care leagă
    rândurile de altceva — `sources` numără evenimentele pe 24 h pe fiecare
    pereche — ar număra și acolo de două ori.
    """
    return f"""
        SELECT source, action, max(ultim) AS ultim
          FROM (
            SELECT source, action, max(bucket) AS ultim
              FROM event_rollup_1m
             WHERE bucket > now() - interval '30 days'
             GROUP BY 1, 2
            UNION ALL
            SELECT source, action, max(ts) AS ultim
              FROM raw_events
             WHERE ts > now() - interval '{_PLAFON_COADA_ORE} hours'
               AND ts >= COALESCE((SELECT max(bucket) FROM event_rollup_1m),
                                  now() - interval '{_PLAFON_COADA_ORE} hours')
             GROUP BY 1, 2
          ) t
         GROUP BY 1, 2
    """  # noqa: S608 - interpolarea e o constantă de modul, nu date de la cineva


async def kpis(db: Database) -> dict[str, Any]:
    """The headline counters, all over the same 24-hour window."""
    ev = await db.fetchrow(
        """
        SELECT count(*) AS total,
               count(*) FILTER (WHERE action IN ('auth_fail','alert')) AS ostile,
               count(DISTINCT host(src_ip)) FILTER (WHERE src_ip IS NOT NULL) AS ips
        FROM raw_events WHERE ts > now() - interval '24 hours'
        """
    )
    inc = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status IN ('open','acknowledged')) AS deschise,
               count(*) FILTER (WHERE status IN ('open','acknowledged')
                                  AND severity IN ('high','critical')) AS grave
        FROM incidents
        """
    )
    fnd = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status = 'open') AS deschise,
               count(*) FILTER (WHERE status = 'open' AND kev) AS kev
        FROM findings
        """
    )
    blocked = int(await db.fetchval("SELECT count(*) FROM blocklist WHERE active") or 0)
    return {
        "evenimente_24h": int(ev["total"] or 0),
        "ostile_24h": int(ev["ostile"] or 0),
        "atacatori_24h": int(ev["ips"] or 0),
        "incidente_deschise": int(inc["deschise"] or 0),
        "incidente_grave": int(inc["grave"] or 0),
        "vuln_deschise": int(fnd["deschise"] or 0),
        "vuln_kev": int(fnd["kev"] or 0),
        "blocate": blocked,
    }


async def sources(db: Database) -> list[dict[str, Any]]:
    """Which collectors are actually producing. A zero row here is the fastest
    way to spot a silent collector.

    Inventarul și „ultima activitate" vin amândouă din `last_activity_sql`,
    adică din `event_rollup_1m`, nu din `raw_events`. Măsurată pe gazdă,
    funcția asta era 4373 ms din cele 18,4 s ale paginii, aproape tot în
    `max(ts)` per pereche peste 30 de zile de evenimente brute.

    Numărătoarea pe 24 h a rămas ce era: o coborâre în `raw_events_source_idx`
    pentru fiecare pereche, mărginită de ziua curentă. Din rollup s-ar putea
    lua și ea — `n` e chiar `count(*)` pe minut — dar numai cu o tăietură fix
    pe frontieră, fiindcă bucketul de la frontieră e încă parțial și
    suprapunerea ar aduna de două ori aceleași evenimente. Și, mai important,
    ar deveni greșită tăcut ori de câte ori rollup-ul rămâne în urmă: cifra
    asta e singura din tabel din care șablonul trage o concluzie (punctul
    „activă/tăcută"), deci un colector viu ar fi desenat tăcut. Un `ultim` cu
    un minut mai vechi nu minte pe nimeni; un zero, da. Cât din pagină costă
    numărătoarea nu s-a măsurat separat, deci nu s-a atins.

    O sursă fără niciun eveniment în ultimele 24 h apare, cu zero — asta e
    chiar întrebarea panoului.

    Nu are propriul refuz „nu pot ști" când rollup-ul e vechi, deși atunci
    inventarul lui se subțiază la fel ca al lui `_gap_insights`. Motivul e că
    tabelul ăsta nu dă niciun verdict — numără și afișează — iar pagina pe care
    ajunge poartă deja, deasupra lui, cardul lui `_gap_insights` pentru exact
    condiția asta. Un al doilea mecanism care întreabă aceeași vârstă ar putea
    să nu fie de acord cu primul, și atunci panoul s-ar contrazice singur. Dacă
    `sources` ajunge vreodată să fie desenat singur — Telegram, un API —
    moștenește o gaură neanunțată și îi trebuie și lui verificarea.
    """
    rows = await db.fetch(
        f"""
        WITH activitate AS ({last_activity_sql()})
        SELECT a.source,
               COALESCE(sum(c.n), 0)::bigint AS ev_24h,
               max(a.ultim) AS ultim
          FROM activitate a
          LEFT JOIN LATERAL (
              SELECT count(*) AS n FROM raw_events e
               WHERE e.source = a.source AND e.action = a.action
                 AND e.ts > now() - interval '24 hours') c ON true
         GROUP BY 1 ORDER BY ev_24h DESC
        """  # noqa: S608 - SQL din constante de modul, nu din date de la cineva
    )
    return [dict(r) for r in rows]


async def top_attackers(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Ranked by how many independent collectors saw them, then by volume —
    breadth is a better signal of intent than a single loud source."""
    rows = await db.fetch(
        """
        SELECT host(src_ip) AS ip,
               count(*) AS ev,
               count(DISTINCT source) AS surse,
               string_agg(DISTINCT source, '+' ORDER BY source) AS care,
               max(geo_country) AS tara,
               max(ts) AS ultim,
               EXISTS (SELECT 1 FROM blocklist b
                       WHERE b.ip = raw_events.src_ip AND b.active) AS blocat
        FROM raw_events
        WHERE ts > now() - interval '48 hours' AND src_ip IS NOT NULL
          AND action IN ('auth_fail','alert')
        GROUP BY src_ip
        ORDER BY count(DISTINCT source) DESC, count(*) DESC
        LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def targeted_accounts(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT username, sum(n)::bigint AS n, count(ip) AS ips
        FROM (SELECT username, host(src_ip) AS ip, count(*) AS n
                FROM raw_events
               WHERE source = 'sshd' AND action = 'auth_fail'
                 AND username IS NOT NULL
                 AND ts > now() - interval '7 days'
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def probed_paths(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT http_path, sum(n)::bigint AS n, count(ip) AS ips
        FROM (SELECT http_path, host(src_ip) AS ip, count(*) AS n
                FROM raw_events
               WHERE source = 'nginx' AND http_status = 404
                 AND http_path IS NOT NULL
                 AND ts > now() - interval '7 days' AND http_path <> '/'
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def ids_signatures(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    """Real threat signatures only — engine diagnostics are dropped at the
    collector, but older rows predate that filter.

    Citește coloana `signature`, nu `raw->>'signature'`. PostgreSQL 16 nu poate
    întoarce valoarea unei expresii dintr-un index — `check_index_only` o
    ignoră — deci cu expresia în WHERE fiecare rând de suricata din fereastră
    cerea o pagină de heap, intercalate printre milioane de rânduri de auditd:
    233 187 de buffere pentru 233 595 de rânduri, măsurat pe replică. Coloana
    reală, umplută de declanșatorul de pe `raw_events` (migrația 0034), face
    `Index Only Scan` posibil: 3 536 de buffere pe aceleași date, `Heap
    Fetches: 0`. Verificat cu `EXCEPT`: zero rânduri diferite față de forma
    veche, pe toată fereastra.
    """
    rows = await db.fetch(
        """
        SELECT sig, sum(n)::bigint AS n, count(ip) AS ips
        FROM (SELECT signature AS sig, host(src_ip) AS ip, count(*) AS n
                FROM raw_events
               WHERE source = 'suricata' AND ts > now() - interval '7 days'
                 AND signature NOT LIKE 'SURICATA %'
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def hourly_activity(db: Database) -> list[dict[str, Any]]:
    """24 hourly buckets for the sparkline. Gaps are filled with zero so the
    shape is honest: a quiet hour must look quiet, not be skipped."""
    rows = await db.fetch(
        """
        SELECT date_trunc('hour', ts) AS ora, count(*) AS n
        FROM raw_events
        WHERE ts > now() - interval '24 hours' AND action IN ('auth_fail','alert')
        GROUP BY 1 ORDER BY 1
        """
    )
    by_hour = {r["ora"]: int(r["n"]) for r in rows}
    if not by_hour:
        return []
    peak = max(by_hour.values()) or 1
    return [{"ora": k, "n": v, "pct": round(v * 100 / peak)} for k, v in sorted(by_hour.items())]


async def by_country(db: Database, limit: int = 7) -> list[dict[str, Any]]:
    """Where the hostile traffic comes from. `pct` is relative to the top row so
    the bars are comparable at a glance rather than against an invisible total."""
    rows = await db.fetch(
        """
        SELECT tara, sum(ev)::bigint AS ev, count(ip) AS ips
        FROM (SELECT geo_country AS tara, host(src_ip) AS ip, count(*) AS ev
                FROM raw_events
               WHERE ts > now() - interval '7 days' AND geo_country IS NOT NULL
                 AND action IN ('auth_fail','alert')
               GROUP BY 1, 2) pereche
        GROUP BY 1 ORDER BY ev DESC LIMIT $1
        """,
        limit,
    )
    out = [dict(r) for r in rows]
    peak = max((r["ev"] for r in out), default=1) or 1
    for r in out:
        r["pct"] = round(r["ev"] * 100 / peak)
    return out


async def by_asn(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    """Hostile traffic by network operator. A large event count from very few
    addresses is the signature of concentrated attacker infrastructure — far
    more actionable than the country, which is usually just where a VPS sits."""
    rows = await db.fetch(
        """
        SELECT operator, asn, sum(ev)::bigint AS ev, count(ip) AS ips
        FROM (SELECT geo_as_org AS operator, geo_asn AS asn,
                     host(src_ip) AS ip, count(*) AS ev
                FROM raw_events
               WHERE ts > now() - interval '7 days' AND geo_as_org IS NOT NULL
                 AND action IN ('auth_fail','alert')
               GROUP BY 1, 2, 3) pereche
        GROUP BY 1, 2 ORDER BY ev DESC LIMIT $1
        """,
        limit,
    )
    out = [dict(r) for r in rows]
    peak = max((r["ev"] for r in out), default=1) or 1
    for r in out:
        r["pct"] = round(r["ev"] * 100 / peak)
    return out


async def deltas(db: Database) -> dict[str, dict[str, Any]]:
    """Today against the same window yesterday, for the KPI chips. `dir` is
    spelled out so the arrow, not only the colour, carries the direction."""
    row = await db.fetchrow(
        """
        SELECT
          count(*) FILTER (WHERE ts > now() - interval '24 hours'
                             AND action IN ('auth_fail','alert')) AS ostile_azi,
          count(*) FILTER (WHERE ts <= now() - interval '24 hours'
                             AND action IN ('auth_fail','alert')) AS ostile_ieri,
          count(DISTINCT host(src_ip)) FILTER (WHERE ts > now() - interval '24 hours') AS ips_azi,
          count(DISTINCT host(src_ip)) FILTER (WHERE ts <= now() - interval '24 hours') AS ips_ieri
        FROM raw_events WHERE ts > now() - interval '48 hours' AND src_ip IS NOT NULL
        """
    )

    def chip(now_v: int, prev_v: int) -> dict[str, Any]:
        if not prev_v:
            return {"dir": "flat", "pct": None, "text": "fără referință"}
        change = (now_v - prev_v) * 100 / prev_v
        if abs(change) < 5:
            return {"dir": "flat", "pct": 0, "text": "≈ la fel"}
        direction = "up" if change > 0 else "down"
        arrow = "↑" if change > 0 else "↓"
        # A percentage in the thousands is arithmetically correct and completely
        # useless: it means the comparison window was nearly empty (a collector
        # was down, or old rows were pruned), not that attacks grew 37-fold.
        # Say that instead of rendering a number that reads as a bug.
        if abs(change) >= 900:
            return {"dir": direction, "pct": None, "text": f"{arrow} de la o bază foarte mică"}
        return {"dir": direction, "pct": abs(round(change)), "text": f"{arrow} {abs(round(change))}%"}

    return {
        "ostile": chip(int(row["ostile_azi"] or 0), int(row["ostile_ieri"] or 0)),
        "atacatori": chip(int(row["ips_azi"] or 0), int(row["ips_ieri"] or 0)),
    }


async def activity_feed(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Latest meaningful events across incidents, blocks and scans — the "what
    just happened" column. Deliberately mixed rather than one table per kind:
    the useful question is chronological, not categorical."""
    rows = await db.fetch(
        """
        (SELECT 'incident' AS kind, i.id, i.severity AS lvl, i.title AS txt,
                COALESCE(i.actor_key, '') AS meta, i.last_detection_at AS at
         FROM incidents i
         WHERE i.status IN ('open','acknowledged')
         ORDER BY i.last_detection_at DESC LIMIT $1)
        UNION ALL
        (SELECT 'block', b.id, CASE WHEN b.active THEN 'high' ELSE 'info' END,
                CASE WHEN b.active THEN 'IP blocat: ' ELSE 'IP deblocat: ' END || host(b.ip),
                COALESCE(b.created_by, ''), b.blocked_at
         FROM blocklist b ORDER BY b.blocked_at DESC LIMIT 4)
        UNION ALL
        (SELECT 'scan', s.id,
                CASE WHEN s.status = 'failed' THEN 'high' ELSE 'info' END,
                'Scanare ' || s.scanner || ': ' || s.findings_count || ' rezultate',
                s.status, COALESCE(s.finished_at, s.started_at)
         FROM scans s ORDER BY s.started_at DESC LIMIT 3)
        ORDER BY at DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def service_health(db: Database) -> dict[str, int]:
    """How many services are up, down, degraded or unmeasured, right now.

    Cifra pe care o citește operatorul: linia `Servicii: 🟢 10 · 🔴 4` din
    rezumatul de pe Telegram (`telegram/views.py`) și cardul „Servicii
    monitorizate" de pe prima pagină vin amândouă de aici.

    ## De ce `retired_at IS NULL`

    Fiindcă starea citită mai jos e ULTIMUL eșantion al activului, fără nicio
    margine de timp. Pentru un activ care încă se sondează, „ultimul" înseamnă
    „acum câteva minute". Pentru unul care nu se mai sondează, înseamnă pe
    vecie ultima măsurătoare făcută vreodată — iar dacă ea era `down`, activul
    rămâne roșu în numărătoare pentru totdeauna.

    Exact asta s-a întâmplat: pe 29 august 2026 panoul arăta patru servicii
    roșii de optsprezece zile — `n8n`, `n8n-traefik`, `qdrant`, `webmin` — deși
    niciunul nu era picat. Fuseseră dezinstalate de pe gazdă (niciun pachet,
    nicio unitate, niciun container, niciun port ascultat pe 88, 6333 sau
    5678), ultima sondă reușită pe 11, respectiv 7 august.

    `sentinel/scan/inventory.py:sync` le poate acum retrage, iar
    `assets_repo.list_all` le ascunde implicit — de-asta sonda, pagina Servicii
    și `/services` de pe Telegram s-au conformat fără nicio schimbare. Dar
    interogarea ASTA nu trece prin `list_all`; citește direct din tabelă. Fără
    rândul de mai jos, retragerea unui activ nu ar schimba cu nimic chiar cifra
    pentru care a fost făcută.

    Numără activele, nu eșantioanele: un activ retras iese cu totul din
    numărătoare — nici la verde, nici la roșu, nici la „necunoscut". Rândurile
    lui din `health_samples` rămân pe disc și rămân interogabile; doar că nu mai
    răspund la întrebarea „ce se întâmplă acum".
    """
    rows = await db.fetch(
        """
        SELECT COALESCE(s.status, 'necunoscut') AS stare, count(*) AS n
        FROM assets a
        LEFT JOIN LATERAL (
            SELECT status FROM health_samples h
            WHERE h.asset_id = a.id ORDER BY ts DESC LIMIT 1
        ) s ON true
        WHERE a.retired_at IS NULL
        GROUP BY 1
        """
    )
    return {r["stare"]: int(r["n"]) for r in rows}
