"""Funcționalitatea 07: exercițiul de restaurare, programat lunar.

„Un backup pe care nu l-ai restaurat niciodată nu e un backup — e o ipoteză."
Modulul ăsta produce faptul durabil de care Funcționalitatea 08 (fereastra de
reparare automată) va depinde: proprietatea ei de siguranță e că aplică doar
reparații cu întoarcere DOVEDITĂ prin exercițiu, nu doar prezentă pe disc.

## Constrângerea care nu se negociază

Exercițiul nu atinge NICIODATĂ fișierele reale. `restore.sh` restaurează în
LOC — `tar -xf ... -C /` — și de aceea nu e rulat aici, nici măcar citit ca
sursă de instrucțiuni: partea lui care se refolosește e strict comanda tar de
extragere a UNEI arhive, cu `-C /` înlocuit de un director izolat pe care
executorul îl construiește, îl folosește și îl șterge în aceeași chemare —
`executor/commands.py:op_restore_drill_verify`.

Extragerea rulează în executor, nu aici, dintr-un motiv structural, nu de
stil: `/var/backups/sentinel/<id>/` e `0700 root:root`. Un serviciu
neprivilegiat ca ăsta nu poate nici măcar CITI arhiva, darămite s-o extragă.

## Ce compară

Pentru fiecare artefact: checksum-ul recalculat față de manifest (nu cel
ținut minte de la creare), plus — doar pentru arhive — dacă arborele extras
chiar conține sursele declarate în manifestul din bază (`sources[]`), la
calea absolută unde ar trebui să existe. Verdictul „structure_mismatch" —
arhivă validă ca checksum, extrasă cu succes, dar care nu reproduce nicio
sursă declarată la calea ei — e exact faptul pe care exercițiul trebuie să-l
poată spune, nu să-l mascheze.

## Ce înregistrează

Un rând în `restore_drills` (`automated = true`) plus câte un rând în
`restore_drill_items` pentru fiecare artefact — vezi migrația 0042 pentru
motivul separării. Un punct numai cu artefacte informative (`rpm_state`,
`git_ref`) nu poate ieși niciodată `succeeded = true`: nimic din el a fost
extras, deci nimic din el a fost dovedit.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.respond.executor_client import ExecutorClient

log = get_logger(__name__)

# The default client socket timeout (30s, `ExecutorClient.DEFAULT_TIMEOUT_S`)
# is shorter than a single archive's own extraction ceiling inside the
# executor (300s — see `op_restore_drill_verify`'s per-item tar timeout), and
# a restore point can carry more than one archive. A generous, explicit
# timeout here avoids reporting "executor unreachable" for a drill that was
# simply still working; this is a slow, monthly, non-urgent job, so there is
# no cost to waiting. A restore point with enough archives to exceed even
# this is rare, and the failure mode if it happens is a retry next month, not
# a wrong answer this one.
_client = ExecutorClient(timeout_s=600)

PERFORMED_BY = "sentinel-restore-drill"

# Verdictele care fac punctul, în ansamblu, "succeeded". Deliberat NU include
# "informational_only": un punct care conține doar artefacte informative n-a
# dovedit nimic prin extragere, iar "structure_mismatch" e chiar defectul pe
# care exercițiul există să-l prindă.
_OK_VERDICTS = frozenset({"restorable_verified", "informational_only"})


@dataclass
class DrillOutcome:
    ran: bool                       # a existat un punct de testat
    drill_id: int | None = None
    restore_point_db_id: int | None = None
    succeeded: bool | None = None
    detail: str = ""
    counts: dict[str, int] = field(default_factory=dict)


def _restore_point_id_from_path(path: str) -> str:
    # Aceeași derivare ca `backup.prune`: id-ul e ultima componentă a căii, nu
    # calea însăși — executorul își reconstruiește singur ținta sub propriul
    # BACKUP_ROOT, deci nimic compus aici nu poate indica altundeva.
    return str(path).rstrip("/").rsplit("/", 1)[-1]


async def run(db: Database, cfg: Config) -> DrillOutcome:
    """Rulează exercițiul lunar: alege un punct, cere executorului să-l
    verifice izolat, înregistrează rezultatul. Nu ridică — un exercițiu care
    nu poate rula trebuie să spună asta prin rândul pe care îl scrie sau, dacă
    nici nu poate scrie, prin log, nu să oprească restul mentenanței."""
    point = await repo.pick_restore_point_for_drill(db)
    if point is None:
        has_any = await repo.any_live_restore_point(db)
        # Distincția contează: `has_any=False` e o gazdă fără backup-uri încă
        # (stare normală, la instalare); `pick_restore_point_for_drill`
        # întorcând None cu puncte vii ar fi o eroare de interogare, nu o
        # gazdă goală — de aceea se spune diferit în jurnal.
        detail = ("niciun punct de restaurare pe gazdă — nimic de testat încă"
                  if not has_any else
                  "interogarea de selecție n-a întors niciun punct, deși există "
                  "puncte vii — verifică pick_restore_point_for_drill")
        log.info("restore drill: nothing to drill", extra={"detail": detail})
        return DrillOutcome(ran=False, detail=detail)

    rp_id = _restore_point_id_from_path(point["path"])
    manifest = point.get("manifest") or {}
    sources = [s for s in (manifest.get("sources") or []) if isinstance(s, str)]

    started = time.monotonic()
    try:
        result = await asyncio.to_thread(
            _client.call, "restore_drill_verify",
            restore_point_id=rp_id, sources=sources)
    except Exception as exc:  # noqa: BLE001 - executorul poate fi jos, nu e motiv să pice tot
        duration_ms = int((time.monotonic() - started) * 1000)
        notes = f"executorul nu a răspuns: {exc}"
        log.error("restore drill: executor unreachable",
                 extra={"restore_point": rp_id, "detail": str(exc)})
        drill_id = await repo.record_drill(
            db, restore_point_id=point["id"], automated=True,
            performed_by=PERFORMED_BY, succeeded=False, duration_ms=duration_ms,
            notes=notes, result={"error": "executor_unreachable"}, items=[])
        return DrillOutcome(ran=True, drill_id=drill_id,
                           restore_point_db_id=point["id"], succeeded=False,
                           detail=notes)

    duration_ms = int((time.monotonic() - started) * 1000)

    if not result.get("ok"):
        notes = f"executorul a refuzat verificarea: {result.get('error')}"
        log.error("restore drill: executor refused",
                 extra={"restore_point": rp_id, "detail": result.get("error")})
        drill_id = await repo.record_drill(
            db, restore_point_id=point["id"], automated=True,
            performed_by=PERFORMED_BY, succeeded=False, duration_ms=duration_ms,
            notes=notes, result={"error": str(result.get("error"))}, items=[])
        return DrillOutcome(ran=True, drill_id=drill_id,
                           restore_point_db_id=point["id"], succeeded=False,
                           detail=notes)

    items = result.get("items") or []
    counts: dict[str, int] = {}
    for item in items:
        v = str(item.get("verdict"))
        counts[v] = counts.get(v, 0) + 1

    # "succeeded" pentru TOT punctul: fiecare artefact trebuie să fie fie
    # dovedit restaurabil, fie declarat informativ pe față — un singur artefact
    # corupt sau nereconstituit ("structure_mismatch") coboară verdictul
    # întregului punct, ca să nu ascundă o problemă reală în spatele altor
    # artefacte care au ieșit bine. Un punct exclusiv informativ (fără nicio
    # arhivă) nu a dovedit nimic prin extragere, deci nu poate fi "succeeded"
    # — vezi _OK_VERDICTS.
    all_ok = bool(items) and all(str(i.get("verdict")) in _OK_VERDICTS for i in items)
    any_restored = any(str(i.get("verdict")) == "restorable_verified" for i in items)
    succeeded = all_ok and any_restored

    if not items:
        notes = "manifestul nu avea niciun artefact — nimic de verificat"
    elif not any_restored:
        notes = ("punct numai informativ (rpm_state / git_ref) — nimic din el "
                 "a fost extras, deci nimic din el a fost dovedit restaurabil")
    elif not all_ok:
        rele = ", ".join(f"{i.get('artifact')}: {i.get('verdict')}"
                         for i in items if str(i.get("verdict")) not in _OK_VERDICTS)
        notes = f"cel puțin un artefact nu a trecut verificarea: {rele}"
    else:
        notes = f"{counts.get('restorable_verified', 0)} artefact(e) dovedite restaurabile"

    drill_id = await repo.record_drill(
        db, restore_point_id=point["id"], automated=True,
        performed_by=PERFORMED_BY, succeeded=succeeded, duration_ms=duration_ms,
        notes=notes, result=counts, items=items)

    log.warning("restore drill finished",
               extra={"restore_point": rp_id, "succeeded": succeeded,
                      "counts": counts, "duration_ms": duration_ms})
    return DrillOutcome(ran=True, drill_id=drill_id, restore_point_db_id=point["id"],
                        succeeded=succeeded, detail=notes, counts=counts)
