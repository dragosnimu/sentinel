"""Semnalul periodic către un martor din afara gazdei.

Un agent de securitate găzduit nu poate garanta că raportează propria
dispariție: cine îl oprește controlează și canalul prin care ar fi anunțat.
Toate alertele Sentinel pleacă de pe serverul monitorizat, deci `systemctl stop`
pe serviciile potrivite produce tăcere completă și nicio urmă în afara gazdei.

Modulul ăsta e jumătatea de pe server a reparației. Trimite periodic un semnal
unui martor extern; **absența semnalului devine alarma**, iar decizia de a suna
stă pe o mașină pe care atacatorul nu o controlează.

## De ce nu un simplu „sunt viu"

Un ping fără conținut e falsificabil de orice linie de cron, inclusiv a
atacatorului, și e minciuna cea mai comodă: procesul răspunde, deci pare că
merge. Semnalul poartă **cifre care trebuie să crească** — ultimul eveniment
ingerat, cât a consumat detecția, verdictul autodiagnosticului. Un martor care
primește semnale cu contoare înțepenite știe că procesul trăiește și conducta e
moartă, ceea ce e un mod real de a cădea și e complet invizibil altfel.

## Ce nu poate face

Cheia de semnare stă pe mașina monitorizată. Un atacator cu root o citește și
poate fabrica semnale cu cifre care cresc. `audit_head` ridică bariera — capul
lanțului de hash-uri din jurnalul de audit trebuie menținut consistent, nu doar
incrementat — dar nu o face absolută.

Prinde sigur: serviciu oprit, proces căzut, OOM, disc plin, gazdă repornită,
rețea tăiată, ingestie blocată cu procesul viu, atacator care oprește Sentinel
fără să se gândească la consecințe. Nu prinde sigur un atacator informat și
răbdător. Nimic găzduit nu poate.

## Serviciu propriu, nu inclus în altul

Ca să raporteze DESPRE celelalte servicii în loc să moară ÎMPREUNĂ cu ele.
Ambele moduri de eșec ajung astfel la martor: dacă expeditorul cade, semnalul
dispare; dacă altceva cade, semnalul sosește cu contoare care nu mai avansează.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from sentinel.config import Config, get_secrets
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

SECRET_NAME = "SENTINEL_BEACON_SECRET"
SIGNATURE_HEADER = "X-Sentinel-Signature"
SEQUENCE_KEY = "beacon:seq"


def canonical(payload: dict[str, Any]) -> bytes:
    """Forma exactă peste care se calculează semnătura.

    Chei sortate, fără spații: cele două capete trebuie să serializeze identic,
    altfel semnătura nu se verifică niciodată și eșecul arată ca o cheie greșită.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign(payload: dict[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical(payload),
                    hashlib.sha256).hexdigest()


async def _next_sequence(db: Database) -> int:
    """Număr strict crescător, persistat.

    Martorul refuză un `seq` care scade sau se repetă, ceea ce face inutilă
    reluarea unui semnal valid capturat. Ținut în aceeași tabelă ca restul
    cursoarelor, nu într-un fișier: supraviețuiește repornirii și nu adaugă o
    stare nouă de întreținut.
    """
    return int(await db.fetchval(
        """
        INSERT INTO collector_cursors (name, cursor, updated_at)
        VALUES ($1, '1', now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = ((collector_cursors.cursor)::bigint + 1)::text,
                updated_at = now()
        RETURNING cursor::bigint
        """,
        SEQUENCE_KEY) or 1)


async def collect(db: Database, cfg: Config) -> dict[str, Any]:
    """Contoarele care trebuie să avanseze, plus verdictul propriu.

    Fiecare interogare e tolerantă la lipsă: pe o instalare parțială sau în
    timpul unei migrări, un tabel absent nu are voie să oprească semnalul. Un
    heartbeat care tace fiindcă o interogare secundară a eșuat produce exact
    alarma falsă pe care sistemul ăsta trebuie să nu o dea.
    """
    async def val(sql: str, default: Any = None) -> Any:
        try:
            return await db.fetchval(sql)
        except Exception as exc:  # noqa: BLE001
            log.warning("beacon probe failed", extra={"sql": sql[:60], "detail": str(exc)})
            return default

    last_event = await val("SELECT max(id) FROM raw_events", 0)
    detect_cursor = await val(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = 'detect:events'", 0)
    incidents_open = await val(
        "SELECT count(*) FROM incidents WHERE status = 'open'", 0)
    blocklist = await val(
        "SELECT count(*) FROM blocklist WHERE unblocked_at IS NULL", 0)
    audit_head = await val(
        "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1", "")

    sc = None
    try:
        sc = await db.fetchrow(
            "SELECT worst_status, checks_run, checks_bad, started_at "
            "FROM selfcheck_runs ORDER BY started_at DESC LIMIT 1")
    except Exception:  # noqa: BLE001
        pass

    return {
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "max_age_s": cfg.beacon.max_age_s,
        "interval_s": cfg.beacon.interval_s,
        "last_event_id": int(last_event or 0),
        "detect_cursor": int(detect_cursor or 0),
        "incidents_open": int(incidents_open or 0),
        "blocklist_size": int(blocklist or 0),
        "audit_head": (audit_head or "")[:64],
        "selfcheck": {
            "worst": sc["worst_status"] if sc else "unknown",
            "checks": int(sc["checks_run"]) if sc else 0,
            "bad": int(sc["checks_bad"]) if sc else 0,
            "ran_at": sc["started_at"].isoformat() if sc else None,
        },
    }


async def send_once(db: Database, cfg: Config, secret: str) -> bool:
    """Un semnal. `True` dacă martorul l-a acceptat.

    Eșecul e raportat în jurnal și nimic mai mult: un martor indisponibil nu are
    voie să devină o problemă a serverului monitorizat. Dacă găzduirea martorului
    cade, Sentinel continuă să apere serverul exact ca înainte.
    """
    import httpx

    payload = await collect(db, cfg)
    payload["seq"] = await _next_sequence(db)
    body = canonical(payload)
    headers = {
        SIGNATURE_HEADER: sign(payload, secret),
        "Content-Type": "application/json",
        # Prin CDN, un semnal pus în cache ar face martorul să vadă la nesfârșit
        # ultimul răspuns bun — adică fix minciuna pe care o prevenim.
        "Cache-Control": "no-store",
    }
    try:
        async with httpx.AsyncClient(timeout=cfg.beacon.timeout_s) as client:
            r = await client.post(cfg.beacon.url, content=body, headers=headers)
        if r.status_code // 100 == 2:
            return True
        log.warning("beacon rejected",
                    extra={"status": r.status_code, "body": r.text[:200],
                           "seq": payload["seq"]})
    except Exception as exc:  # noqa: BLE001 - orice problemă de rețea, aceeași reacție
        log.warning("beacon unreachable",
                    extra={"detail": str(exc)[:200], "seq": payload["seq"]})
    return False


async def run_forever(db: Database, cfg: Config) -> None:
    secret = get_secrets().get(SECRET_NAME) or ""
    if not cfg.beacon.enabled or not cfg.beacon.url or not secret:
        # O dată, limpede, apoi liniște. Un expeditor care încearcă la nesfârșit
        # o adresă goală umple jurnalul și ascunde problemele reale.
        log.info("beacon disabled",
                 extra={"enabled": cfg.beacon.enabled,
                        "has_url": bool(cfg.beacon.url),
                        "has_secret": bool(secret)})
        return

    log.info("beacon started", extra={"interval_s": cfg.beacon.interval_s})
    consecutive_failures = 0
    while True:
        ok = await send_once(db, cfg, secret)
        if ok:
            if consecutive_failures:
                log.info("beacon reachable again",
                         extra={"after_failures": consecutive_failures})
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            # Doar în jurnal. Alerta pentru „martorul nu răspunde" e a
            # autodiagnosticului; dacă ar fi aici, ar pleca prin exact canalul
            # care s-ar putea să fie stricat.
            if consecutive_failures in (3, 30, 300):
                log.error("beacon has been failing",
                          extra={"consecutive": consecutive_failures})
        await asyncio.sleep(cfg.beacon.interval_s)
