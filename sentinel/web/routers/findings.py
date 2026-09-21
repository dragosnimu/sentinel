"""The Findings page: what the scanners found, ranked by priority.

Read-only. Titles/descriptions come from scanner output and vendor advisories;
Jinja autoescaping renders all of it as text. Applying a fix is the patch
pipeline (P9), never a click here.

## Why the page has a filter and pages, measured rather than assumed

The table carries 200 rows. On the production host at 21 September 2026 those
200 were 183 `trivy_image` and 17 `trivy_fs`; the first `dnf` row was 373rd in
the page's own ordering, because every one of the 477 open OS findings scores
below the cut (dnf tops out at priority 83, the 200th row sits at 83 while
container and filesystem findings run to 100). So the column that says what a
finding sits on could show "Sistem de operare" exactly never, on a host with
470 open HIGH findings on its own packages — and a page that cannot show them
must not be the only way to ask for them.

Hence two things that are one mechanism: category totals counted over ALL open
rows (so "0 container" is a measurement and not a side effect of the cut), and
`?asociat=` + `?pagina=` so every counted row has a route to the screen.
Server-rendered links, because `sentinel/web/static/` contains no JavaScript at
all and this page is not where that changes.

A query parameter that cannot be honoured is reported, never silently dropped:
showing all 1055 rows under a heading the operator asked to filter is the same
lie as showing none.
"""

from __future__ import annotations

from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request, Response

from sentinel.db.engine import Database
from sentinel.db.repo import findings as fx
from sentinel.db.repo import users as users_repo
from sentinel.logging_setup import get_logger
from sentinel.scan.subject import KIND_UNKNOWN, Category, categories, describe
from sentinel.util.ids import parse_id
from sentinel.web.deps import current_user, get_db

log = get_logger(__name__)
router = APIRouter()

_SEV_DOT = {"info": "off", "low": "off", "medium": "warn", "high": "bad", "critical": "bad"}

# How many rows the table carries. Named, because the number is rendered next to
# the total and drives the paging arithmetic: the page showed 200 of 1055 open
# findings with nothing saying so, and the moment an operator groups the rows by
# what they sit on, they count — and the counts do not add up to the header.
PAGE_LIMIT = 200

#: Câte cifre poate avea un număr de pagină înainte să fie refuzat ca neînțeles.
#:
#: CPython refuză conversia unui întreg scris cu peste 4300 de cifre
#: (`sys.set_int_max_str_digits`, implicit 4300; măsurat 3.12.3 și 3.12.14 în
#: venv-urile celor două gazde, iar `PYTHONINTMAXSTRDIGITS` nu e setat nicăieri
#: în depozit). `int("9"*4301)` aruncă `ValueError`, adică 500 pe pagina de
#: vulnerabilități, dintr-un parametru de URL — iar nginx acceptă linia de
#: cerere până la 8 kB pe ambele gazde, deci cererea chiar ajunge la aplicație.
#:
#: Verificarea pe LUNGIME stă înaintea conversiei, fiindcă asta e singura
#: ordine în care conversia nu mai poate fi atinsă. Nouă cifre sunt mai multe
#: pagini decât poate avea tabela asta în orice viitor plauzibil.
MAX_PAGE_DIGITS = 9

#: Cât din valoarea neînțeleasă se dă înapoi operatorului în mesaj. Fără plafon,
#: o cerere de 4,3 kB s-ar întoarce întreagă în pagină — escapată, deci
#: inofensivă, dar tot un parametru de atacator reflectat în panou la lungimea
#: lui.
MAX_ECHO = 40


def _echo(value: str) -> str:
    """Valoarea, scurtată, pentru un mesaj care o citează înapoi."""
    return value if len(value) <= MAX_ECHO else value[:MAX_ECHO] + "…"


def page_url(kind: str | None, page: int) -> str:
    """Legătura către pagina asta, cu filtrul și numărul de pagină în ea.

    Construită într-o funcție pură, nu prin lipirea de șiruri în șablon: o
    legătură greșită e un drum care nu duce nicăieri, iar drumul e chiar ce
    lipsea.
    """
    query: dict[str, str] = {}
    if kind:
        query["asociat"] = kind
    if page > 1:
        query["pagina"] = str(page)
    return "/findings" + (f"?{urlencode(query)}" if query else "")


def resolve_page(raw: str | None, pages: int) -> tuple[int, str | None]:
    """Numărul de pagină cerut, mărginit la ce există — plus ce n-a mers.

    Al doilea element e mesajul pentru operator, `None` când cererea a fost
    onorată întocmai. O pagină cerută dincolo de sfârșit ar întoarce altfel un
    tabel gol care arată exact ca „nu mai e nimic deschis".

    Ce înseamnă „un număr" e decis de `sentinel.util.ids.parse_id`, o singură
    dată pentru tot depozitul: doar cifre ASCII (`int()` acceptă și cifrele
    arabo-indice sau pe cele fullwidth, iar un „２" într-un URL nu e ce a vrut
    cineva să scrie), și lungimea verificată înaintea conversiei (un șir de
    4301 de cifre trece de `isdigit()` și pică în `int()`, deci verificarea
    pusă să curețe parametrul l-ar fi transformat ea însăși într-o pagină de
    eroare).

    Marginea de aici e `MAX_PAGE_DIGITS`, nu `bigint`: un număr de pagină nu
    ajunge în nicio coloană, deci lumea lui e cât poate avea tabela asta, nu
    cât duce Postgres.
    """
    if raw is None:
        return 1, None
    wanted = parse_id(raw, maximum=10**MAX_PAGE_DIGITS - 1)
    if wanted is None:
        return 1, f"Număr de pagină neînțeles: „{_echo(raw)}”. Se arată prima pagină."
    if wanted > pages:
        return pages, f"Pagina {wanted} nu există; ultima e {pages}."
    return wanted, None


@router.get("/findings")
async def findings_page(
    request: Request,
    user: Annotated[users_repo.User, Depends(current_user)],
    db: Annotated[Database, Depends(get_db)],
    asociat: Annotated[str | None, Query()] = None,
    pagina: Annotated[str | None, Query()] = None,
) -> Response:
    warnings: list[str] = []

    # Peste TOATE rândurile deschise, nu peste cele afișate — vezi
    # `subject.categories`.
    cats = categories(await fx.open_counts_by_scanner(db))

    selected: Category | None = None
    if asociat is not None:
        selected = next((c for c in cats if c.kind == asociat), None)
        if selected is None:
            warnings.append(
                f"Categorie necunoscută: „{_echo(asociat)}”. Se arată toate categoriile.")

    # `None` = fără filtru; lista (chiar goală) = numai scanerele categoriei.
    scanners = list(selected.scanners) if selected is not None else None

    counts = await fx.open_counts(db, scanners=scanners)
    total = int(counts.get("total", 0))
    pages = max(1, -(-total // PAGE_LIMIT))
    page, page_warning = resolve_page(pagina, pages)
    if page_warning:
        warnings.append(page_warning)

    offset = (page - 1) * PAGE_LIMIT
    rows = await fx.list_open(db, limit=PAGE_LIMIT, offset=offset, scanners=scanners)
    for r in rows:
        r["sev_dot"] = _SEV_DOT.get(r["severity"], "off")
        # What the row is associated with — OS, container, application. Derived
        # here and not in the template: a branch inside Jinja cannot be
        # falsified on its own, and this one has four outcomes including "I
        # cannot tell", which is the one that must never be silently dropped.
        r["subject"] = describe(r.get("scanner"), r.get("location"))

    # Categoria goală „necunoscut" nu se arată — azi e zero pe ambele gazde și
    # o pastilă permanentă pe zero e zgomot. Pe orice alt număr apare, fiindcă
    # atunci chiar e ceva ce nimeni n-a clasificat.
    chips: list[dict[str, Any]] = [
        {"kind": c.kind, "label": c.label, "count": c.count,
         "url": page_url(c.kind, 1),
         "active": selected is not None and selected.kind == c.kind}
        for c in cats if c.kind != KIND_UNKNOWN or c.count]

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "user": user, "active": "findings", "rows": rows, "counts": counts,
            # `counts["total"]` counts every open finding in the CURRENT view
            # (filtered or not); `rows` stops at PAGE_LIMIT. The template says
            # which slice is on screen whenever the two differ.
            #
            # The two numbers come from two round-trips, so a scan finishing
            # between them can leave `shown` one or two above `total` for a
            # single render. Not locked: a transaction around a read-only page
            # costs more than the worst case, which is a row range reading
            # "1–200 din 199" for one refresh.
            "shown": len(rows),
            "primul": offset + 1, "ultimul": offset + len(rows),
            "pagina": page, "pagini": pages,
            "prev_url": page_url(selected.kind if selected else None, page - 1) if page > 1 else None,
            "next_url": page_url(selected.kind if selected else None, page + 1) if page < pages else None,
            "categorii": chips,
            "selectat": selected.label if selected is not None else None,
            "url_toate": page_url(None, 1),
            "avertismente": warnings,
        },
    )
