"""Ce citește din baza de date o încărcare a paginii principale.

Lista de mai jos e singura. Routerul o folosește ca să deseneze pagina, iar
`selfcheck.checks.check_dashboard_latency` o folosește ca să măsoare cât
durează. Două liste ar diverge, iar divergența e tăcută: un panou adăugat în
router și uitat în sondă înseamnă că sonda rămâne verde peste exact interogarea
care a rupt pagina. Asta e forma bug-ului pe care depozitul ăsta îl vânează —
verificarea nu poate vedea defectul, prin construcție — și e chiar motivul
pentru care fișierul ăsta există.

Ce NU e aici, deliberat: `_self_status` și notița de fază din router. Amândouă
citesc configurația și starea gazdei, nu analytics, iar partea lor de bază de
date e `db.healthy()`, `pg_database_size()` și un `max(version)` — trei
interogări pe chei primare. Dacă vreuna dintre ele ajunge vreodată să conteze,
locul ei e aici, nu într-o a doua listă.

Interogările rămân **secvențiale**. `asyncio.gather` peste ele ar transforma
suma în maxim, dar pool-ul are `database.pool_max` conexiuni (10 pe gazdă),
împărțite cu fluxul SSE și cu restul paginilor; a suprapune douăzeci de
interogări peste el mută costul, nu îl scade, iar când pool-ul se golește
cererile se așteaptă una pe alta oricum. Câștigul măsurat vine din a citi mai
puțin (vezi migrația 0030 și rescrierile din `aggregate`), nu din a citi în
paralel. Dacă suprapunerea se adaugă vreodată, se adaugă cu o măsurătoare pe
gazdă în mână, nu pe intuiție.
"""

from __future__ import annotations

from typing import Any

from sentinel.analytics import aggregate
from sentinel.analytics import insights as insights_mod
from sentinel.db.engine import Database


async def load(db: Database) -> dict[str, Any]:
    """Toate valorile pe care le pune pagina principală în șablon.

    Ordinea e cea din șablon: verdict, contoare, interpretare, apoi tabelele din
    care a ieșit interpretarea.
    """
    found = await insights_mod.collect(db)
    return {
        "posture": await insights_mod.posture(db, found),
        "insights": found,
        "kpi": await aggregate.kpis(db),
        "deltas": await aggregate.deltas(db),
        "countries": await aggregate.by_country(db),
        "asns": await aggregate.by_asn(db),
        "feed": await aggregate.activity_feed(db),
        "sources": await aggregate.sources(db),
        "attackers": await aggregate.top_attackers(db, limit=8),
        "accounts": await aggregate.targeted_accounts(db),
        "paths": await aggregate.probed_paths(db),
        "signatures": await aggregate.ids_signatures(db),
        "hourly": await aggregate.hourly_activity(db),
        "health": await aggregate.service_health(db),
        # Al 15-lea `await`, adăugat cu măsurătoare, nu din inerție — vezi
        # avertismentul din docstring-ul modulului. `aggregate.campaigns` nu
        # citește `incidents` și nu agregă nimic la citire: contoarele sunt
        # deja recalculate la scriere, în `attach_incident`. Tabela
        # `incident_campaigns` are o singură campanie ACTIVĂ per familie
        # (indexul unic parțial din 0039), adică 14 rânduri pe gazda pentru
        # care a fost dimensionată asta. Măsurat local cu EXPLAIN (ANALYZE,
        # BUFFERS) pe aceeași formă (968 incidente, 14 campanii): Seq Scan,
        # 55 de buffere, 0,127 ms — vezi docstring-ul `aggregate.campaigns`.
        "campaigns": await aggregate.campaigns(db),
    }
