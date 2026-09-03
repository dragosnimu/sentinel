"""`sentinel maintenance` — retenție, agregate, intelligence, backup-uri.

One-shot, pornit din oră în oră de `sentinel-maintenance.timer`.

Serviciul acesta a lipsit din build. Unitatea systemd exista, timerul rula,
comanda era listată în CLI — și modulul nu. Rezultatul: eșec din oră în oră cu
`No module named`, iar retenția partițiilor nu a rulat niciodată. Nimic nu se
strica zgomotos; discul creștea tăcut. A fost găsit de verificarea post-deploy
a produsului, nu de un client, pe 5 august 2026.

## Ordinea pașilor este parte din corectitudine

    1. partiții înainte    — un insert fără partiție cade în DEFAULT
    2. agregate            — pe datele care încă există
    3. retenție            — abia apoi se aruncă detaliul
    4. garda de disc       — ce a mai rămas de făcut dacă tot e plin

Dacă retenția ar rula înaintea agregatelor, ar șterge exact rândurile pe care
agregatele trebuiau să le rezume, iar pierderea ar fi tăcută și definitivă:
partiția e deja aruncată când cineva se uită la grafic și vede o gaură.

## Recuperarea după o pauză

Fereastra de agregare nu e „ultima oră", ci „de la ce s-a agregat ultima dată".
Un serviciu care nu a rulat trei zile — sau, ca aici, niciodată — trebuie să
recupereze singur, nu să lase o gaură permanentă exact în perioada în care ceva
era stricat.

Recuperarea e plafonată (`MAX_CATCHUP_HOURS`) fiindcă unitatea are
`TimeoutStartSec=900` și `MemoryMax=384M`: o rulare care încearcă să agrege o
lună dintr-o dată e omorâtă la mijloc și nu termină niciodată. Se recuperează
cât încape, se scrie în jurnal cât a rămas, iar rularea următoare continuă.

## Filigranul merge doar înainte — și acolo e o gaură diferită

„De la ce s-a agregat ultima dată" recuperează o PAUZĂ (mentenanța n-a rulat).
Nu recuperează un rând care sosește cu `ts` într-o oră pe care filigranul a
lăsat-o deja în urmă: filigranul e derivat din `max(bucket)`, deci odată trecut
de o oră nu se mai întoarce la ea de la sine, oricâte rânduri noi ar ajunge cu
`ts` acolo. Măsurat pe 24 august 2026: ingestia a rămas zile în urmă în timpul
unui potop UDP, iar `event_rollup_1h` a rămas cu 3,96 milioane de rânduri lipsă
pentru acea zi — tăcut, fiindcă interogarea rămâne validă și întoarce doar mai
puțin. `repair_rollup_gaps` e reparația: compară `event_rollup_1h` cu
`raw_events` pe orele deja stabilite (nu pe cele încă în recuperarea de mai
sus) și reface, plafonat, cele mai vechi mai întâi — vezi docstring-ul ei
pentru de ce nu ajunge să reagrege doar ora. Rezultatul se scrie o dată pe
trecere în `rollup_reconcile_runs` (migrația 0044); detecția — separat, în
`sentinel/selfcheck/checks.py::check_rollup_reconcile` — CITEȘTE acel rând,
nu recalculează, ca autoverificarea să nu reproducă asupra ei însăși boala pe
care o consemnează memoria proiectului: un panou încet fiindcă propria lui
verificare la 5 minute reface agregări scumpe.

## Unitatea de reparat nu e ora — un test măsurat pe gazdă a demonstrat de ce

Runda 2 repara câte o oră întreagă dintr-o singură instrucțiune SQL
(`sentinel_rollup_events_1m(ora_început, ora_sfârșit)`). Măsurat pe gazdă, pe
ora cea mai grea a incidentului (24.08 14:00, 4 329 065 rânduri):
**67-70 de secunde** — peste `statement_timeout_ms` al conexiunii (30 000 ms,
`sentinel/db/engine.py`), care omoară INSTRUCȚIUNEA, nu doar rularea.
Consecința: prima trecere pică exact pe ora aia, iar fiindcă `hourly_gaps`
alege mereu cea mai veche gaură RĂMASĂ, fiecare trecere următoare reia de la
ACEEAȘI oră și moare la fel — reparație care raportează că repară fără să
repare niciodată, pentru totdeauna. Un plafon mai mic de ore pe rulare n-ar
fi ajutat: o SINGURĂ oră depășea deja limita.

Costul nu crește liniar cu numărul de rânduri — 895 013 rânduri (13:00) au
durat 2,2 s cald, de 4,8x mai puține decât 14:00 dar de 32x mai rapid, semn că
`work_mem` (8 MB) e depășit undeva între cele două praguri, iar sortarea
(`percentile_cont`) trece pe disc. Felierea pe MINUT, granulația proprie a lui
`event_rollup_1m`, ține fiecare instrucțiune sub acel prag — vezi
`GAP_REPAIR_SLICE`. Testul obligatoriu pentru asta e
`test_no_single_sql_statement_gets_a_whole_hour_interval`, în
`tests/unit/test_maintenance_rollup_repair.py`.

## Un pas care cade nu îi oprește pe ceilalți

Reîmprospătarea fluxurilor de intelligence are nevoie de rețea. Retenția, nu.
Dacă ar fi în aceeași încercare, o cădere de DNS ar opri curățarea discului —
adică o problemă de rețea ar deveni, câteva săptămâni mai târziu, o problemă de
disc plin. Fiecare pas e izolat și raportează separat.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import asyncpg

from sentinel.config import Config, get_config
from sentinel.db.engine import Database
from sentinel.db.repo import incidents as inc_repo
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.services import parse_service_args

log = get_logger(__name__)

# Cât se creează în avans. Trei zile înseamnă că o pană de mentenanță de până la
# trei zile nu poate face un insert să eșueze.
PARTITIONS_AHEAD = 3

# Plafonul de recuperare, în ore de date agregate într-o singură rulare.
# 48 la un timer orar: recuperează o pană de weekend din prima încercare, dar
# rămâne mult sub TimeoutStartSec.
MAX_CATCHUP_HOURS = 48

# Câte ore ÎNGHEȚATE de filigran (deja lăsate în urmă, nu în recuperarea de mai
# sus) se repară pe rulare. NU e comparat cu TimeoutStartSec (900 s, al
# unității) — comparația care conta era cu `statement_timeout_ms` (30 000 ms,
# per CONEXIUNE, `sentinel/db/engine.py`), iar o oră de incident poate depăși
# aia singură (vezi docstring-ul modulului). De-aia plafonul de aici nu mai e
# ce ține reparația sub timeout — `GAP_REPAIR_SLICE` e — ci doar cât progres
# se face pe rulare: opt ore pe trecere golesc restanța de 15 ore a
# incidentului măsurat în două-trei treceri, cele mai vechi primele, fiindcă o
# oră nereparată concurează cu retenția brutului (`raw_events_days`): odată
# ieșită din fereastră, rămâne greșită definitiv, indiferent ce se întâmplă
# aici după aceea.
MAX_GAP_REPAIR_HOURS = 8

# Unitatea ATOMICĂ a unei instrucțiuni SQL de reagregare — podeaua sub care nu
# se mai coboară, indiferent cât de grea e ora. `sentinel_rollup_events_1m`
# grupează pe `date_trunc('minute', ts)` și SUPRASCRIE la ON CONFLICT
# (`SET n = EXCLUDED.n`, nu adunare — 0017_partition_fixes.sql): două
# instrucțiuni care taie ACELAȘI minut în jumătate ar scrie amândouă pe
# ACELAȘI bucket, iar a doua ar înlocui tăcut rândul primei, nu l-ar aduna la
# el — o felie mai mică de un minut ar pierde jumătate din rânduri, nu le-ar
# repara. Minutul e deci podeaua dată de granulația tabelei, nu o alegere de
# performanță — `repair_rollup_gaps` nu coboară niciodată sub ea.
#
# Nu e nici plafonul de sus care garantează că o felie încape sub
# `statement_timeout_ms`. Măsurat pe gazdă, cu încărcare reală și cache RECE
# (nu cald, din rulări repetate pe aceeași felie — asta a raportat anterior
# 1 821-2 058 ms și s-a dovedit greșit): o felie de un minut cu 13 767 rânduri
# a durat 3 027 ms; aceeași unitate, dar cu 549 401 rânduri (minutul 14:45 al
# incidentului din 24 august), a durat 17 513-30 015+ ms — uneori PESTE cei
# 30 000 ms ai `statement_timeout_ms`, nu comod sub el. Un singur minut poate
# deci depăși plafonul chiar la granulația cea mai fină posibilă, iar de
# acolo nu mai există o felie mai mică de încercat — vezi `repair_rollup_gaps`
# pentru ce se întâmplă atunci (ora rămâne nereparată în trecerea asta,
# NUMITĂ, fără să blocheze restul).
GAP_REPAIR_SLICE = timedelta(minutes=1)

# Pragul de rânduri BRUTE per instrucțiune sub care mai multe minute merg
# batute într-o SINGURĂ chemare, în loc de una pe minut — vezi
# `repair_rollup_gaps`. Prins între cele două fapte măsurate mai sus, cu
# marjă generoasă pe fiecare parte: de aproape 4x peste felia sigură (13 767
# rânduri, 3 027 ms) și de aproape 11x sub felia care a depășit plafonul
# (549 401 rânduri). O oră obișnuită (~14 000 rânduri, vezi antetul
# modulului) intră astfel într-o singură instrucțiune pe toată ora, nu 60 —
# fără să se apropie vreodată de felia care a picat pe gazdă. Numărul de
# rânduri al orei (`raw_n`) vine gratis din `hourly_gaps` — deja calculat de
# interogarea care a găsit gaura, nu e nevoie de o numărare separată.
GAP_REPAIR_ROW_TARGET = 50_000

# Zile golite din DEFAULT pe rulare. Mutarea unei zile e o singură
# tranzacție care nu se poate întrerupe; la un timer orar, șase rulări
# scurte bat una care lovește TimeoutStartSec și lasă treaba pe jumătate.
MAX_DRAIN_DAYS = 3

# Ștergerile din tabelele neparticionate se fac în tranșe. Un DELETE care atinge
# milioane de rânduri ține un lock lung pe o bază care deservește în paralel
# detecția — iar detecția care așteaptă un lock e detecție oprită.
DELETE_BATCH = 20_000

# Tabelele partiționate și cheia de configurație care le dă retenția.
PARTITIONED = (
    ("raw_events", "raw_events_days"),
    ("health_samples", "health_samples_days"),
    ("capacity_samples", "health_samples_days"),
)


@dataclass
class StepResult:
    name: str
    ok: bool = True
    detail: str = ""
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    steps: list[StepResult] = field(default_factory=list)

    def add(self, s: StepResult) -> StepResult:
        self.steps.append(s)
        return s

    @property
    def failed(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok]

    def as_dict(self) -> dict[str, Any]:
        return {s.name: ({"ok": s.ok, "detail": s.detail} | s.facts) for s in self.steps}


async def _step(report: Report, name: str, coro) -> StepResult:
    """Rulează un pas izolat.

    O excepție aici e raportată și mersul continuă. Singurul lucru care nu are
    voie să se întâmple e ca o cădere într-un pas să lase discul necurățat.
    """
    try:
        detail, facts = await coro
        return report.add(StepResult(name, True, detail, facts))
    except Exception as exc:  # noqa: BLE001 - izolarea e chiar scopul
        log.error("maintenance step failed", extra={"step": name, "detail": str(exc)})
        return report.add(StepResult(name, False, str(exc)))


# ---------------------------------------------------------------------------
# 1. Partiții
# ---------------------------------------------------------------------------
async def ensure_partitions(db: Database) -> tuple[str, dict[str, Any]]:
    created = await db.fetchval("SELECT sentinel_ensure_partitions($1)", PARTITIONS_AHEAD)
    n = int(created or 0)
    return (f"{n} partiții create în avans" if n else "partițiile existau deja",
            {"created": n, "ahead_days": PARTITIONS_AHEAD})


async def drain_default(db: Database) -> tuple[str, dict[str, Any]]:
    """Mută în partiții proprii rândurile rămase blocate în DEFAULT.

    Rândurile ajung acolo când partiția zilei lipsea — adică exact perioada în
    care mentenanța nu rula. Sunt invizibile pentru retenție: DEFAULT nu se
    elimină niciodată, fiindcă a-l arunca ar șterge fix datele sosite cât ceva
    era stricat.

    Plafonat la câteva zile pe rulare. Mutarea unei zile e o singură tranzacție
    care nu se poate întrerupe, iar timerul e orar: mai bine șase rulări scurte
    decât una care lovește TimeoutStartSec și lasă treaba pe jumătate.
    """
    moved: dict[str, dict[str, int]] = {}
    remaining_total = 0
    for parent, _ in PARTITIONED:
        rows = await db.fetch("SELECT * FROM sentinel_default_partition_days($1)", parent)
        if not rows:
            continue
        done: dict[str, int] = {}
        for r in rows[:MAX_DRAIN_DAYS]:
            day, count = r["day"], int(r["rows_in_default"] or 0)
            await db.fetchval("SELECT sentinel_create_partition($1, $2)", parent, day)
            done[day.isoformat()] = count
            log.info("default partition drained",
                     extra={"parent": parent, "day": day.isoformat(), "rows": count})
        left = len(rows) - len(done)
        remaining_total += left
        if done:
            moved[parent] = done
        if left:
            # Spus, nu presupus. O golire plafonată care tace arată identic cu
            # una completă, iar diferența e că restul rândurilor rămân în afara
            # retenției până la o rulare care nu vine niciodată dacă nimeni nu
            # știe că mai e ceva de făcut.
            log.warning("default partition drain capped",
                        extra={"parent": parent, "days_left": left})
    n = sum(len(v) for v in moved.values())
    if not n:
        return "nimic blocat în DEFAULT", {"moved": {}, "days_remaining": 0}
    return (f"{n} zile mutate din DEFAULT" +
            (f", {remaining_total} rămase" if remaining_total else ""),
            {"moved": moved, "days_remaining": remaining_total})


# ---------------------------------------------------------------------------
# 2. Agregate
# ---------------------------------------------------------------------------
async def _watermark(db: Database, table: str, floor_hours: int) -> datetime:
    """De unde reia agregarea.

    Din `max(bucket)` al tabelei de agregate, nu dintr-un cursor separat: starea
    e derivată din date, deci nu poate ieși din sincron cu ele. Un cursor pierdut
    sau resetat ar produce o gaură pe care nimeni nu o observă.
    """
    last = await db.fetchval(f"SELECT max(bucket) FROM {table}")  # noqa: S608 - nume din constantă
    now = datetime.now(timezone.utc)
    if last is None:
        return now - timedelta(hours=floor_hours)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return last


async def rollup_events(db: Database) -> tuple[str, dict[str, Any]]:
    """Recuperarea normală: de la filigran până la acum, plafonat la
    `MAX_CATCHUP_HOURS`.

    Feliată la aceeași granulație pe care `repair_rollup_gaps` a măsurat-o
    (vezi antetul modulului): înainte de asta, fereastra întreagă — până la
    48h — pleca într-o SINGURĂ instrucțiune `sentinel_rollup_events_1m`. Pe
    volum normal (87 443 rânduri pe 48h) asta a durat 664 ms, nicio problemă —
    dar fereastra de recuperare nu e mereu volum normal: dacă mentenanța ar fi
    fost oprită o oră chiar în timpul potopului din 24 august, o SINGURĂ oră
    de incident (4 329 065 rânduri, 67-70s) ar fi fost de ajuns s-o depășească
    pe `statement_timeout_ms` (30 000 ms). Iar acolo eșecul nu e curat: nimic
    nu s-ar fi scris, filigranul (`max(bucket)`, `_watermark`) n-ar fi
    înaintat deloc, iar rularea următoare ar relua EXACT aceeași fereastră și
    ar muri identic — `event_rollup_1m`/`_1h` blocate până când partițiile
    brute ies din retenție.
    `event_rollup_1m` se feliază la `GAP_REPAIR_SLICE` (un minut) — pragul
    măsurat: 1 821 ms cea mai grea felie, sub cei 30 000 ms. `event_rollup_1h`
    se feliază la o oră, nu mai mult: e ieftin per oră (mărginit de perechi
    asset/sursă/acțiune, nu de volumul brut — 0017_partition_fixes.sql), dar
    fereastra de recuperare normală e de obicei deja o oră (timerul rulează
    orar), deci felierea la o oră nu adaugă niciun dus-întors în cazul comun —
    doar în recuperarea unei pauze mai lungi. O felie la un minut și pentru
    `_1h` n-ar fi greșită, dar ar transforma fiecare rulare orară normală în
    60 de apeluri în loc de unul — cost plătit fără măsurătoare care s-o
    ceară.

    Fiecare felie e propria ei instrucțiune SQL, deci propriul ei commit: un
    eșec la mijloc (ex. o felie care tot depășește timeout-ul) lasă scrise
    feliile de dinainte, iar filigranul de la rularea următoare — derivat din
    `max(bucket)`, nu dintr-un cursor separat (vezi `_watermark`) — pornește
    de acolo, nu de la începutul ferestrei picate. Progresul parțial e deci
    real, nu doar sperat.
    """
    now = datetime.now(timezone.utc)
    facts: dict[str, Any] = {}
    parts: list[str] = []

    for table, fn, slice_size in (
        ("event_rollup_1m", "sentinel_rollup_events_1m", GAP_REPAIR_SLICE),
        ("event_rollup_1h", "sentinel_rollup_events_1h", timedelta(hours=1)),
    ):
        start = await _watermark(db, table, floor_hours=MAX_CATCHUP_HOURS)
        # Bucketul de la watermark se reface: ultima rulare l-a putut prinde
        # incomplet. Funcțiile SQL sunt idempotente prin ON CONFLICT DO UPDATE,
        # deci suprascrierea e corectă, nu o dublare.
        end = min(now, start + timedelta(hours=MAX_CATCHUP_HOURS))
        if end <= start:
            parts.append(f"{table}: la zi")
            facts[table] = {"rows": 0, "hours": 0}
            continue
        # Feliat — vezi docstring-ul funcției pentru de ce nicio instrucțiune
        # nu are voie să acopere fereastra întreagă dintr-o dată.
        rows = 0
        cursor = start
        while cursor < end:
            nxt = min(cursor + slice_size, end)
            rows += int(await db.fetchval(f"SELECT {fn}($1, $2)", cursor, nxt) or 0)  # noqa: S608
            cursor = nxt
        hours = round((end - start).total_seconds() / 3600, 1)
        remaining = round((now - end).total_seconds() / 3600, 1)
        parts.append(f"{table}: {rows} rânduri pe {hours}h")
        facts[table] = {"rows": rows, "hours": hours, "remaining_hours": remaining}
        if remaining > 1:
            # Spus explicit. O recuperare plafonată care tace arată identic cu
            # una completă, iar diferența contează.
            log.warning("rollup catch-up capped",
                        extra={"table": table, "covered_hours": hours,
                               "remaining_hours": remaining})
    return "; ".join(parts), facts


async def _persist_reconcile(
    db: Database, *, status: str, raw_exists: bool,
    window_lower: datetime | None = None, window_upper: datetime | None = None,
    gap_hours: int = 0, rows_missing: int = 0,
    worst_bucket: datetime | None = None, worst_missing: int = 0,
    hours_repaired: int = 0,
) -> None:
    """Scrie rândul pe care `check_rollup_reconcile` îl citește — vezi
    `0044_rollup_reconcile_runs.sql`. Se scrie pe FIECARE trecere, chiar și
    când n-are ce compara, ca autoverificarea să poată deosebi „a fost
    verificat și e bine" de „n-a fost verificat niciodată" fără să interogheze
    ea însăși `raw_events`/`event_rollup_1h`."""
    await db.execute(
        """
        INSERT INTO rollup_reconcile_runs
            (status, raw_exists, window_lower, window_upper,
             gap_hours, rows_missing, worst_bucket, worst_missing, hours_repaired)
        VALUES ($1::text, $2::boolean, $3::timestamptz, $4::timestamptz,
                $5::int, $6::bigint, $7::timestamptz, $8::bigint, $9::int)
        """,
        status, raw_exists, window_lower, window_upper,
        gap_hours, rows_missing, worst_bucket, worst_missing, hours_repaired)


def _gap_repair_slices(raw_n: int) -> int:
    """Câte unități `GAP_REPAIR_SLICE` merg batute într-o SINGURĂ instrucțiune
    `sentinel_rollup_events_1m`, date fiind rândurile brute ale OREI (`raw_n`
    — deja cunoscut din `hourly_gaps`, fără interogare în plus).

    Presupune densitate uniformă pe oră — o aproximare, nu o garanție: o oră
    cu media joasă dar un minut ascuns mult mai greu decât restul tot ajunge,
    prin `_repair_minutes`, să înjumătățească până la o singură unitate și,
    dacă nici acolo nu încape, să eșueze izolat pe ora aia (vezi
    `repair_rollup_gaps`). Rezultatul de aici e doar PUNCTUL DE PORNIRE al
    feliei, nu promisiunea că ea va reuși.

    Rotunjire în jos și clampare la [1, ore-întregi], ca o oră foarte rară să
    nu ceară o felie mai mare decât ea însăși, iar una foarte deasă să nu
    ceară o felie sub o unitate (vezi `GAP_REPAIR_SLICE` pentru de ce aia ar
    fi incorectă, nu doar riscantă).
    """
    slices_per_hour = timedelta(hours=1) // GAP_REPAIR_SLICE  # de obicei 60
    per_slice_rows = max(raw_n, 1) / slices_per_hour
    return max(1, min(slices_per_hour, int(GAP_REPAIR_ROW_TARGET / per_slice_rows)))


async def _repair_minutes(db: Database, start: datetime, end: datetime, n_slices: int) -> None:
    """Reagregă `[start, end)` — `n_slices` unități `GAP_REPAIR_SLICE`
    ALINIATE, niciodată o tăietură arbitrară — cu o SINGURĂ instrucțiune.

    Dacă instrucțiunea depășește `statement_timeout_ms` (semnătura:
    `asyncio.TimeoutError` de la `command_timeout`-ul conexiunii, sau
    `QueryCanceledError` dacă nucleul apucă să răspundă primul — vezi antetul
    modulului pentru cazul real, prins cu `detail` gol în jurnalul de
    mentenanță), felia se înjumătățește ca NUMĂR DE UNITĂȚI — nu ca durată
    brută, ca să rămână aliniată la minut — și se reia doar pe cele două
    bucăți, recursiv. NICIODATĂ sub o singură unitate: vezi `GAP_REPAIR_SLICE`
    pentru de ce o felie mai mică ar suprascrie, nu ar aduna, jumătate din
    rânduri. Sub o unitate, eșecul se propagă neschimbat — apelantul
    (`_repair_hour`, apoi `repair_rollup_gaps`) decide ce înseamnă o oră
    nereparată, nu funcția asta.
    """
    try:
        await db.fetchval("SELECT sentinel_rollup_events_1m($1, $2)", start, end)
    except (asyncio.TimeoutError, asyncpg.exceptions.QueryCanceledError):
        if n_slices <= 1:
            raise
        half = max(1, n_slices // 2)
        mid = start + GAP_REPAIR_SLICE * half
        await _repair_minutes(db, start, mid, half)
        await _repair_minutes(db, mid, end, n_slices - half)


async def _repair_hour(db: Database, gap: Any) -> None:
    """Reagregă o oră întreagă: toate minutele ei, apoi ora — în ordinea asta,
    fiindcă `_1h` citește din `_1m`, nu din `raw_events` (vezi docstring-ul
    lui `repair_rollup_gaps`). Felia de pornire per instrucțiune vine din
    densitatea orei (`gap.raw_n`) — vezi `_gap_repair_slices`. Orice eșec
    rămas după înjumătățirea din `_repair_minutes` se propagă neschimbat:
    `_1h` nu se cheamă decât după ce TOATE minutele au fost scrise cu succes,
    ca ora să nu fie marcată reparată pe baza unui `event_rollup_1m` parțial.
    """
    start = gap.bucket
    end = start + timedelta(hours=1)
    span = GAP_REPAIR_SLICE * _gap_repair_slices(gap.raw_n)
    cursor = start
    while cursor < end:
        nxt = min(cursor + span, end)
        n_slices = max(1, (nxt - cursor) // GAP_REPAIR_SLICE)
        await _repair_minutes(db, cursor, nxt, n_slices)
        cursor = nxt
    await db.fetchval("SELECT sentinel_rollup_events_1h($1, $2)", start, end)


async def repair_rollup_gaps(db: Database) -> tuple[str, dict[str, Any]]:
    """Reagregă orele deja lăsate în urmă de filigran în care au ajuns rânduri
    brute mai târziu.

    `rollup_events` de mai sus avansează filigranul strict înainte (vezi
    `_watermark` și antetul modulului): odată ce o oră trece de el, nu se mai
    recalculează niciodată de la sine, oricâte rânduri noi ar sosi cu `ts` în
    ea. Pe 24 august 2026 asta a lăsat `event_rollup_1h` cu 3,96 milioane de
    rânduri lipsă pentru o singură zi, tăcut. Pasul ăsta e reparația: găsește
    orele deja STABILITE (sub filigranul curent, nu în recuperarea de mai sus,
    care e încă în desfășurare) unde `event_rollup_1h` numără mai puțin decât
    `raw_events`, și le reface — vezi antetul modulului pentru unitatea de
    lucru aleasă (feliere pe minut, nu pe oră) și de ce.

    `event_rollup_1h` nu citește niciodată din `raw_events` — citește din
    `event_rollup_1m` (`sentinel_rollup_events_1h`, 0017_partition_fixes.sql).
    Filigranul lui `event_rollup_1m` are exact același defect, pe aceeași cale
    (aceeași buclă din `rollup_events`, aceeași `_watermark`), deci o oră
    ratată la nivel de minut rămâne ratată la nivel de oră chiar dacă doar ora
    e reagregată — cererea ar citi din nou din minutul deja incomplet. De-aia
    fiecare oră reparată aici reface întâi TOATE minutele ei, apoi ora — vezi
    `_repair_hour`. `sentinel_rollup_events_1m`/`_1h` sunt idempotente prin
    `ON CONFLICT ... DO UPDATE SET col = EXCLUDED.col` (nu se adună la ce era
    acolo, se suprascrie), deci refacerea minutului chiar și pe orele unde NU
    era nimic greșit e ieftină și corectă, nu o dublare.

    O oră care eșuează — chiar și după înjumătățirea din `_repair_minutes`,
    până la limita ei (`GAP_REPAIR_SLICE`) — NU oprește restul eșantionului.
    Bug-ul activ pe 3 septembrie 2026: ora 14:00 a 24 august pica de fiecare
    trecere, iar excepția ei ieșea din funcția asta înainte de orice
    `_persist_reconcile`, deci trecerea arăta ca „nu s-a întâmplat" în
    `rollup_reconcile_runs` chiar și după ce reparase deja 745 000 de rânduri
    din orele de dinaintea ei — și cele 14 ore mai noi din coadă nu erau
    încercate NICIODATĂ, fiindcă `hourly_gaps` alege mereu cea mai veche gaură
    rămasă. Fiecare oră din eșantion e izolată mai jos: un eșec e prins,
    NUMIT (bucket + motiv) în `facts["hours_failed"]` și în jurnal, nu doar
    scăzut tăcut din numărătoare, iar bucla trece la ora următoare.

    Rândul persistat (`_persist_reconcile`) poartă starea de DUPĂ reparație
    doar când niciun gol n-a rămas netrimis („left == 0" mai jos): în cazul
    ăla, fiindcă TOATE golurile din fereastră — nu doar eșantionul plafonat —
    au fost procesate cu succes chiar în trecerea asta, „ok" e o concluzie
    dovedită, nu o presupunere. Când mai rămân goluri (plafonul a tăiat lista,
    SAU cel puțin o oră din eșantion a eșuat), rândul poartă totalurile
    DINAINTE de reparație — subestimate cu ce s-a reparat chiar acum,
    niciodată supraestimate — fiindcă a recalcula exact starea rămasă ar cere
    o a doua interogare pe toată fereastra, exact rescanarea pe care
    persistarea asta există s-o evite. Rândul se scrie ORICUM, indiferent câte
    ore au eșuat — asta e chiar reparația bug-ului de mai sus.
    """
    from sentinel.analytics import reports as report_repo
    from sentinel.db.repo import rollups as rollup_repo

    cov = await report_repo.rollup_coverage(db)
    if cov["never_ran"]:
        raw_exists = (await report_repo.raw_coverage(db)) is not None
        await _persist_reconcile(db, status="never_ran", raw_exists=raw_exists)
        return "rollup-ul n-a rulat niciodată; nimic de reparat", {"hours_repaired": 0}

    upper = cov["latest"].replace(minute=0, second=0, microsecond=0)
    lower = await report_repo.raw_coverage(db)
    if lower is None or lower >= upper:
        await _persist_reconcile(
            db, status="empty_window", raw_exists=lower is not None,
            window_lower=lower, window_upper=upper)
        return "nicio oră stabilită încă de reparat", {"hours_repaired": 0}

    report = await rollup_repo.hourly_gaps(
        db, lower=lower, upper=upper, limit=MAX_GAP_REPAIR_HOURS)
    if not report.hours:
        await _persist_reconcile(
            db, status="ok", raw_exists=True, window_lower=lower, window_upper=upper)
        return "niciun gol între agregat și brut", {"hours_repaired": 0, "hours_left": 0}

    repaired: list[str] = []
    failed: list[dict[str, str]] = []
    for gap in report.hours:
        start = gap.bucket
        try:
            await _repair_hour(db, gap)
        except Exception as exc:  # noqa: BLE001 - izolarea PER ORĂ e chiar scopul
            detail = str(exc) or repr(exc)  # `asyncio.TimeoutError` are str() gol
            failed.append({"bucket": start.isoformat(), "detail": detail})
            log.warning(
                "rollup gap repair failed for one hour; the rest of the sample continues",
                extra={"bucket": start.isoformat(), "detail": detail,
                       "rows_missing": gap.missing})
            continue
        repaired.append(start.isoformat())
        log.info("rollup gap repaired",
                 extra={"bucket": start.isoformat(), "rows_missing_before": gap.missing})

    left = report.total_hours - len(repaired)
    if left:
        # Spus, nu presupus — la fel ca la golirea din DEFAULT. O reparație
        # plafonată sau parțial eșuată care tace arată identic cu una
        # completă, iar orele rămase concurează cu retenția brutului.
        log.warning("rollup gap repair capped or partially failed; more remain",
                    extra={"hours_repaired": len(repaired), "hours_left": left,
                           "hours_failed": len(failed),
                           "rows_missing_total": report.total_missing})
        await _persist_reconcile(
            db, status="gaps", raw_exists=True, window_lower=lower, window_upper=upper,
            gap_hours=report.total_hours, rows_missing=report.total_missing,
            worst_bucket=report.worst_bucket, worst_missing=report.worst_missing,
            hours_repaired=len(repaired))
    else:
        # Fereastra întreagă a fost procesată cu succes chiar acum — dovedit,
        # nu ghicit.
        await _persist_reconcile(
            db, status="ok", raw_exists=True, window_lower=lower, window_upper=upper,
            hours_repaired=len(repaired))

    parts = [f"{len(repaired)} ore reagregate"]
    if failed:
        parts.append(f"{len(failed)} eșuate ({', '.join(f['bucket'] for f in failed)})")
    sample_missed = report.total_hours - len(report.hours)
    if sample_missed:
        parts.append(f"{sample_missed} rămase în afara eșantionului")
    return ("; ".join(parts),
            {"hours_repaired": len(repaired), "hours_left": left, "hours_failed": failed,
             "rows_missing_total": report.total_missing, "hours": repaired})


async def rollup_availability(db: Database) -> tuple[str, dict[str, Any]]:
    """Ieri și azi.

    Ieri fiindcă abia acum e o zi completă; azi fiindcă panoul trebuie să arate
    ziua în curs, chiar dacă valoarea se va rescrie la următoarea rulare.
    """
    today = datetime.now(timezone.utc).date()
    done = {}
    for day in (today - timedelta(days=1), today):
        done[day.isoformat()] = int(
            await db.fetchval("SELECT sentinel_rollup_availability($1)", day) or 0)
    total = sum(done.values())
    return f"{total} rânduri de disponibilitate", {"days": done}


# ---------------------------------------------------------------------------
# 3. Retenție
# ---------------------------------------------------------------------------
async def drop_partitions(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    dropped: dict[str, list[str]] = {}
    rows_freed = 0
    for parent, key in PARTITIONED:
        days = int(getattr(cfg.retention, key))
        recs = await db.fetch("SELECT * FROM sentinel_drop_old_partitions($1, $2)",
                              parent, days)
        names = [r["dropped"] for r in recs]
        rows_freed += sum(int(r["rows_estimate"] or 0) for r in recs)
        if names:
            dropped[parent] = names
            log.info("partitions dropped",
                     extra={"parent": parent, "keep_days": days, "dropped": names})
    n = sum(len(v) for v in dropped.values())
    return (f"{n} partiții eliminate (~{rows_freed:,} rânduri)" if n
            else "nimic de eliminat", {"dropped": dropped, "rows_estimate": rows_freed})


async def trim_rollups(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    """Agregatele nu sunt partiționate, deci se șterg pe bucăți.

    O ștergere în tranșe poate lăsa treaba neterminată dacă se atinge plafonul.
    Asta e în regulă: rularea următoare continuă, iar alternativa — un DELETE
    nelimitat — blochează detecția până termină.
    """
    out: dict[str, int] = {}
    for table, key in (("event_rollup_1m", "rollup_1m_days"),
                       ("event_rollup_1h", "rollup_1h_days")):
        days = int(getattr(cfg.retention, key))
        removed = 0
        batches = 0
        while True:
            # `count(*)` peste CTE-ul de ștergere, nu `RETURNING 1` citit cu
            # fetchval: acela ar întoarce 1 pentru orice ștergere nevidă, iar
            # raportul ar conține un număr inventat. O cifră aproximativă
            # într-un jurnal de mentenanță e mai rea decât niciuna.
            n = int(await db.fetchval(
                f"""WITH doomed AS (
                        SELECT ctid FROM {table}
                        WHERE bucket < now() - ($1::int * interval '1 day')
                        LIMIT {DELETE_BATCH}
                    ), del AS (
                        DELETE FROM {table} t USING doomed d
                        WHERE t.ctid = d.ctid RETURNING 1
                    )
                    SELECT count(*) FROM del""",  # noqa: S608 - nume din constantă
                days) or 0)
            if n == 0:
                break
            removed += n
            batches += 1
            if batches >= 20:
                log.warning("rollup trim hit its batch ceiling; continuing next run",
                            extra={"table": table})
                break
        out[table] = removed
    total = sum(out.values())
    return (f"~{total:,} rânduri de agregate șterse" if total else "agregatele sunt în limită",
            {"trimmed": out})


# ---------------------------------------------------------------------------
# 4. Garda de disc
# ---------------------------------------------------------------------------
async def _data_directory(db: Database) -> str:
    try:
        return str(await db.fetchval("SHOW data_directory") or "/var/lib/sentinel")
    except Exception:  # noqa: BLE001 - fără drepturi de superuser, întrebarea e refuzată
        return "/var/lib/sentinel"


async def disk_guard(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    """Sub pragul de spațiu liber, retenția se scurtează și se alertează.

    Un disc plin oprește ingestia, oprește PostgreSQL și, pe o gazdă partajată,
    ia cu el tot ce mai rulează acolo. Merită să pierzi istoric vechi ca să nu
    ajungi acolo — dar niciodată tăcut, fiindcă operatorul trebuie să știe că
    are mai puține date decât crede.
    """
    path = await _data_directory(db)
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        path = "/var/lib/sentinel"
        usage = shutil.disk_usage(path)
    free_pct = round(100.0 * usage.free / usage.total, 1)
    facts = {"path": path, "free_pct": free_pct,
             "free_gb": round(usage.free / 2**30, 1),
             "threshold_pct": cfg.retention.disk_guard_free_pct}

    if free_pct >= cfg.retention.disk_guard_free_pct:
        return f"{free_pct}% liber pe {path}", facts

    target = max(7, int(cfg.retention.raw_events_days) // 4)
    dropped = int(await db.fetchval("SELECT sentinel_emergency_retention($1)", target) or 0)
    facts |= {"emergency": True, "target_days": target, "dropped": dropped}
    log.error("disk guard triggered",
              extra={"free_pct": free_pct, "target_days": target, "dropped": dropped})

    await _alert(
        db,
        severity="critical",
        dedup_key=f"maintenance:disk:{int(free_pct)}",
        title="Spațiu pe disc sub prag",
        body=(f"<b>Spațiu liber: {free_pct}%</b> pe <code>{path}</code> "
              f"(prag {cfg.retention.disk_guard_free_pct}%).\n\n"
              f"Retenția a fost scurtată de urgență la {target} zile și "
              f"{dropped} partiții au fost eliminate.\n\n"
              f"<b>Ai mai puțin istoric decât înainte.</b> Verifică ce ocupă "
              f"discul înainte ca următoarea rulare să scurteze din nou."))
    return f"URGENȚĂ: {free_pct}% liber, {dropped} partiții eliminate", facts


async def _alert(db: Database, *, severity: str, dedup_key: str,
                 title: str, body: str) -> None:
    """Pe același drum ca restul: un rând în `notifications`, pe care botul îl ia.

    Alertele de disc nu sunt supuse orelor de liniște — un disc care se umple la
    03:00 nu așteaptă până la 06:00.
    """
    await db.execute(
        """
        INSERT INTO notifications (channel, severity, dedup_key, title, body)
        VALUES ('telegram', $1::text, $2::text, $3::text, $4::text)
        """,
        severity, dedup_key[:180], title, body)


# ---------------------------------------------------------------------------
# 5. Intelligence și backup-uri
# ---------------------------------------------------------------------------
async def refresh_intel(db: Database) -> tuple[str, dict[str, Any]]:
    from sentinel.intel import kev, reputation

    n = await kev.refresh(db)
    # Ships with `intel_feeds` empty/disabled (see that module's docstring),
    # deci `rep` e de obicei `{}` — un WHERE peste zero rânduri activate, nu o
    # cerere de rețea. Fiecare feed e izolat de `_refresh_one`: unul căzut nu-l
    # oprește pe următorul, la fel ca separarea dintre pașii de aici.
    rep = await reputation.refresh_all(db)
    ok_feeds = {k: v for k, v in rep.items() if v >= 0}
    failed_feeds = [k for k, v in rep.items() if v < 0]
    parts = [f"{n} intrări KEV actualizate" if n else "KEV era la zi"]
    if rep:
        parts.append(
            f"{sum(ok_feeds.values())} intrări de reputație pe {len(ok_feeds)} feed-uri"
            + (f", {len(failed_feeds)} eșuate ({', '.join(failed_feeds)})" if failed_feeds else ""))
    return "; ".join(parts), {"kev": n, "reputation": rep}


async def prune_backups(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    from sentinel.patch import backup
    n = await backup.prune(db, cfg)
    return (f"{n} puncte de restaurare eliminate" if n else "nimic de eliminat",
            {"removed": n})


# ---------------------------------------------------------------------------
# 9. Incidente tăcute
# ---------------------------------------------------------------------------
# Cine a închis. Nu un nume de om, fiindcă nu a fost un om — iar cronologia
# trebuie să poată fi citită peste șase luni de cineva care întreabă „cine a
# decis asta".
CLOSED_BY = "sentinel-maintenance"


async def close_stale_incidents(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    """Închide incidentele fără activitate nouă, pe praguri de severitate.

    Motivul nu e spațiul pe disc — un incident ocupă câțiva octeți. Motivul e
    că o coadă de 851 de incidente deschise nu e citită de nimeni, iar cel care
    conta se ascunde perfect printre cele 850 care nu contau. Pragurile de aici
    sunt o politică de citire, nu una de retenție.

    Ce NU face:

    * nu șterge nimic. Rândul rămâne cu toate probele, iar cronologia câștigă o
      intrare care spune cine a închis, când și de ce;
    * nu învie nimic. Indexul unic pe amprentă acoperă doar `open` și
      `acknowledged`, deci activitate nouă deschide un incident NOU. Asta e și
      corect: un atacator care revine după trei săptămâni e un eveniment, nu o
      continuare;
    * nu atinge `critical`. Un critic la care nu s-a uitat nimeni de două
      săptămâni e o constatare despre operator, nu despre incident, iar
      ascunderea lui ar fi singurul lucru mai rău decât o coadă lungă.
    """
    closed: dict[str, int] = {}
    for severity, days in sorted(cfg.retention.incident_stale_days.items()):
        if severity == "critical":
            # Configurabil, deci cineva îl poate adăuga. Refuzăm în cod, unde
            # refuzul nu poate fi anulat dintr-un fișier de configurare editat
            # în graba de a face coada să arate mai bine.
            log.warning("refusing to auto-close critical incidents; ignoring the setting")
            continue
        rows = await db.fetch(
            """
            UPDATE incidents SET status = 'resolved', resolved_at = now(),
                resolution_note = $3
            WHERE status IN ('open', 'acknowledged')
              AND severity = $1
              AND last_detection_at < now() - ($2::int * interval '1 day')
            RETURNING id
            """,
            severity, int(days),
            f"închis automat: fără activitate nouă de {days} zile")
        for r in rows:
            await inc_repo.add_timeline(
                db, r["id"], "status", CLOSED_BY,
                {"status": "resolved", "auto": True,
                 "reason": "stale", "stale_days": int(days)})
        if rows:
            closed[severity] = len(rows)

    total = sum(closed.values())
    detail = (", ".join(f"{k}: {v}" for k, v in closed.items())
              if closed else "nimic de închis")
    return (f"{total} incidente închise ({detail})" if total else detail,
            {"closed": closed})


# ---------------------------------------------------------------------------
# 10. Campanii tăcute
# ---------------------------------------------------------------------------
async def quiet_campaigns(db: Database) -> tuple[str, dict[str, Any]]:
    """Trece în `quiet` campaniile active fără activitate nouă de
    `CAMPAIGN_QUIET_HOURS`.

    La fel ca `close_stale_incidents`: nu șterge, nu închide — doar marchează
    frontul ca stins, ca panoul să nu-l mai numere printre cele active. O
    campanie `quiet` nu se reactivează niciodată; vezi
    `sentinel/db/repo/incident_campaigns.py` pentru motiv.
    """
    from sentinel.db.repo import incident_campaigns as camp_repo
    n = await camp_repo.quiet_stale(db, camp_repo.CAMPAIGN_QUIET_HOURS)
    return (f"{n} campanii trecute în quiet" if n else "nicio campanie de liniștit",
            {"quieted": n})


# ---------------------------------------------------------------------------
# Rularea
# ---------------------------------------------------------------------------
async def run(db: Database, cfg: Config) -> Report:
    rep = Report()

    # Ordinea contează — vezi antetul modulului.
    await _step(rep, "partitions", ensure_partitions(db))
    await _step(rep, "drain_default", drain_default(db))
    await _step(rep, "rollup_events", rollup_events(db))
    await _step(rep, "repair_rollup_gaps", repair_rollup_gaps(db))
    await _step(rep, "rollup_availability", rollup_availability(db))
    await _step(rep, "retention_partitions", drop_partitions(db, cfg))
    await _step(rep, "retention_rollups", trim_rollups(db, cfg))
    await _step(rep, "disk_guard", disk_guard(db, cfg))
    await _step(rep, "intel", refresh_intel(db))
    await _step(rep, "backups", prune_backups(db, cfg))
    await _step(rep, "stale_incidents", close_stale_incidents(db, cfg))
    await _step(rep, "quiet_campaigns", quiet_campaigns(db))
    return rep


async def _main() -> int:
    cfg = get_config()
    db = Database(cfg)
    await db.connect()
    started = datetime.now(timezone.utc)
    try:
        log.info("maintenance pass started")
        rep = await run(db, cfg)
    finally:
        await db.close()

    ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    if rep.failed:
        # Ieșire nenulă: systemd marchează unitatea `failed`, ceea ce e vizibil.
        # Pașii reușiți rămân reușiți — nu se anulează nimic.
        log.error("maintenance finished with failures",
                  extra={"duration_ms": ms, "failed": [s.name for s in rep.failed],
                         "report": rep.as_dict()})
        return 1
    log.info("maintenance done", extra={"duration_ms": ms, "report": rep.as_dict()})
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel maintenance", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args = parse_service_args(parser, argv)
    setup_logging("sentinel-maintenance", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("maintenance failed to start", extra={"detail": str(exc)})
        return 1
