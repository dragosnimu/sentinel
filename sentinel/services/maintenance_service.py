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
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sentinel.config import Config, get_config
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger, setup_logging

log = get_logger(__name__)

# Cât se creează în avans. Trei zile înseamnă că o pană de mentenanță de până la
# trei zile nu poate face un insert să eșueze.
PARTITIONS_AHEAD = 3

# Plafonul de recuperare, în ore de date agregate într-o singură rulare.
# 48 la un timer orar: recuperează o pană de weekend din prima încercare, dar
# rămâne mult sub TimeoutStartSec.
MAX_CATCHUP_HOURS = 48

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
    now = datetime.now(timezone.utc)
    facts: dict[str, Any] = {}
    parts: list[str] = []

    for table, fn, step in (("event_rollup_1m", "sentinel_rollup_events_1m", timedelta(minutes=1)),
                            ("event_rollup_1h", "sentinel_rollup_events_1h", timedelta(hours=1))):
        start = await _watermark(db, table, floor_hours=MAX_CATCHUP_HOURS)
        # Bucketul de la watermark se reface: ultima rulare l-a putut prinde
        # incomplet. Funcțiile SQL sunt idempotente prin ON CONFLICT DO UPDATE,
        # deci suprascrierea e corectă, nu o dublare.
        end = min(now, start + timedelta(hours=MAX_CATCHUP_HOURS))
        if end <= start:
            parts.append(f"{table}: la zi")
            facts[table] = {"rows": 0, "hours": 0}
            continue
        rows = await db.fetchval(f"SELECT {fn}($1, $2)", start, end)  # noqa: S608
        hours = round((end - start).total_seconds() / 3600, 1)
        remaining = round((now - end).total_seconds() / 3600, 1)
        parts.append(f"{table}: {rows or 0} rânduri pe {hours}h")
        facts[table] = {"rows": int(rows or 0), "hours": hours, "remaining_hours": remaining}
        if remaining > 1:
            # Spus explicit. O recuperare plafonată care tace arată identic cu
            # una completă, iar diferența contează.
            log.warning("rollup catch-up capped",
                        extra={"table": table, "covered_hours": hours,
                               "remaining_hours": remaining})
    return "; ".join(parts), facts


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
    from sentinel.intel import kev
    n = await kev.refresh(db)
    return (f"{n} intrări KEV actualizate" if n else "KEV era la zi", {"kev": n})


async def prune_backups(db: Database, cfg: Config) -> tuple[str, dict[str, Any]]:
    from sentinel.patch import backup
    n = await backup.prune(db, cfg)
    return (f"{n} puncte de restaurare eliminate" if n else "nimic de eliminat",
            {"removed": n})


# ---------------------------------------------------------------------------
# Rularea
# ---------------------------------------------------------------------------
async def run(db: Database, cfg: Config) -> Report:
    rep = Report()

    # Ordinea contează — vezi antetul modulului.
    await _step(rep, "partitions", ensure_partitions(db))
    await _step(rep, "drain_default", drain_default(db))
    await _step(rep, "rollup_events", rollup_events(db))
    await _step(rep, "rollup_availability", rollup_availability(db))
    await _step(rep, "retention_partitions", drop_partitions(db, cfg))
    await _step(rep, "retention_rollups", trim_rollups(db, cfg))
    await _step(rep, "disk_guard", disk_guard(db, cfg))
    await _step(rep, "intel", refresh_intel(db))
    await _step(rep, "backups", prune_backups(db, cfg))
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


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinel maintenance", add_help=False)
    parser.add_argument("--log-level", default="INFO")
    args, _ = parser.parse_known_args()
    setup_logging("sentinel-maintenance", args.log_level)
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("maintenance failed to start", extra={"detail": str(exc)})
        return 1
