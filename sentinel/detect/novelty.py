"""Detecția pe baza profilului învățat: ce nu s-a mai văzut, și ce s-a schimbat brusc.

Două reguli, care răspund la două întrebări diferite.

**Noutatea** e punctuală: cheia asta nu apare în profil, iar dimensiunea a văzut
destul cât să aibă dreptul să se mire. Un utilizator care se autentifică pentru
prima dată în trei săptămâni de observație, un ASN nou pentru o autentificare
reușită, un binar care nu s-a executat niciodată aici.

**Schimbarea de compoziție** e agregată: nu contează care cheie e nouă, contează
că într-o oră au apărut cinci, când media dimensiunii e sub una pe zi. Asta e
detecția pe care a cerut-o operatorul — „dacă se schimbă brusc comportamentul" —
și e distinctă de noutate fiindcă fiecare cheie în parte poate avea o explicație
nevinovată, în timp ce rafala nu are.

## Ordinea contează

Regulile astea rulează DUPĂ ce `behaviour.observe()` a actualizat profilul, în
aceeași trecere. Asta pare greșit — profilul a învățat deja cheia, deci nu mai
e „nouă" — și e corect: `observe()` întoarce exact cheile pe care le-a inserat
prima dată, iar regulile evaluează lista aia, nu baza de date. Alternativa,
evaluarea înainte de învățare, ar rata cheia dacă serviciul cade între cei doi
pași și ar re-alerta la nesfârșit dacă nu cade.
"""

from __future__ import annotations

from typing import Any

from sentinel.db.engine import Database
from sentinel.detect.spec import DetectionSpec
from sentinel.logging_setup import get_logger
from sentinel.predict import behaviour as bh

log = get_logger(__name__)

# Câte ore de istoric se folosesc ca referință pentru rata de chei noi.
RATE_LOOKBACK_HOURS = 24 * 14

# De câte ori peste propria medie trebuie să sară rata ca să conteze, și
# minimul absolut sub care nu se alertează niciodată. Fără minim, o dimensiune
# cu media 0,02 chei noi pe oră ar alerta la a doua cheie dintr-o lună.
RATE_MULTIPLE = 4.0
RATE_MIN_NEW = 3


async def _fresh_keys(db: Database, dimension: str, limit: int = 20) -> list[Any]:
    """Cheile inserate în ultima trecere, cu contextul lor.

    `first_seen` în ultimele câteva minute e definiția operațională a lui „nou":
    profilul tocmai le-a creat.
    """
    return await db.fetch(
        """
        SELECT key, first_seen, observations
        FROM behaviour_profiles
        WHERE dimension = $1
          AND acknowledged = false
          AND first_seen > now() - interval '10 minutes'
        ORDER BY first_seen DESC
        LIMIT $2
        """,
        dimension, limit)


# ---------------------------------------------------------------------------
# 1. Noutate punctuală
# ---------------------------------------------------------------------------
async def unseen_before(db: Database, cursor: int) -> list[DetectionSpec]:
    """O cheie care nu apare în profilul unei dimensiuni calde.

    Tace complet cât timp dimensiunea învață. Asta e proprietatea care face
    diferența între o unealtă folosibilă și una care se ignoră: în prima zi,
    fără poartă, ar produce o alertă pentru fiecare utilizator, fiecare rețea și
    fiecare binar de pe server.
    """
    out: list[DetectionSpec] = []
    for dim in bh.DIMENSIONS:
        if not await bh.is_warm(db, dim.name):
            continue
        for row in await _fresh_keys(db, dim.name):
            key = row["key"]
            out.append(DetectionSpec(
                rule_id=f"novelty.{dim.name}",
                rule_family="novelty",
                severity=dim.severity,
                src_ip=None,
                actor_key="host",
                # Amprenta include cheia: două valori noi diferite sunt două
                # incidente, nu unul actualizat.
                fingerprint=f"novelty.{dim.name}:{key}",
                title=f"{dim.novel_title}: {key}",
                summary=(f"`{key}` nu a mai apărut niciodată ca {dim.label} pe "
                         f"serverul ăsta. Profilul e activ de "
                         f"{await _profile_age_days(db, dim.name):.0f} zile. "
                         f"Dacă e o schimbare făcută de tine, confirm-o ca să nu "
                         f"mai alerteze; dacă nu, verifică cine a făcut-o."),
                evidence={
                    "dimension": dim.name, "key": key,
                    "first_seen": row["first_seen"].isoformat(),
                    "observations": row["observations"],
                    "known_keys": await _known_count(db, dim.name),
                },
                event_ids=[],
            ))
    return out


async def _profile_age_days(db: Database, dimension: str) -> float:
    v = await db.fetchval(
        "SELECT EXTRACT(EPOCH FROM (now() - started_at))/86400 "
        "FROM behaviour_learning WHERE dimension = $1", dimension)
    return float(v or 0)


async def _known_count(db: Database, dimension: str) -> int:
    return int(await db.fetchval(
        "SELECT count(*) FROM behaviour_profiles WHERE dimension = $1", dimension) or 0)


# ---------------------------------------------------------------------------
# 2. Schimbare bruscă de compoziție
# ---------------------------------------------------------------------------
async def composition_shift(db: Database, cursor: int) -> list[DetectionSpec]:
    """O rafală de chei noi într-o oră, față de propriul istoric.

    Un server matur nu descoperă utilizatori noi în fiecare oră. Când o face,
    ceva s-a schimbat — un deploy, o migrare, sau altcineva care se plimbă prin
    sistem. Regula nu spune care dintre ele; spune că nu e ora obișnuită.
    """
    out: list[DetectionSpec] = []
    for dim in bh.DIMENSIONS:
        if not await bh.is_warm(db, dim.name):
            continue
        row = await db.fetchrow(
            """
            WITH cur AS (
                SELECT new_keys FROM behaviour_novelty_rate
                WHERE dimension = $1 AND bucket = date_trunc('hour', now())
            ), hist AS (
                SELECT avg(new_keys)::float AS mean, count(*) AS buckets
                FROM behaviour_novelty_rate
                WHERE dimension = $1
                  AND bucket < date_trunc('hour', now())
                  AND bucket > now() - make_interval(hours => $2)
            )
            SELECT COALESCE((SELECT new_keys FROM cur), 0) AS now_new,
                   COALESCE((SELECT mean FROM hist), 0)    AS mean,
                   COALESCE((SELECT buckets FROM hist), 0) AS buckets
            """,
            dim.name, RATE_LOOKBACK_HOURS)
        if row is None:
            continue
        now_new, mean, buckets = row["now_new"], row["mean"], row["buckets"]
        # Fără istoric nu există „față de ce". Douăzeci și patru de ore e
        # minimul sub care media nu spune nimic.
        if buckets < 24 or now_new < RATE_MIN_NEW:
            continue
        if now_new < max(RATE_MIN_NEW, mean * RATE_MULTIPLE):
            continue

        keys = [r["key"] for r in await _fresh_keys(db, dim.name, limit=10)]
        out.append(DetectionSpec(
            rule_id=f"novelty.shift.{dim.name}",
            rule_family="novelty",
            severity="high",
            src_ip=None,
            actor_key="host",
            fingerprint=f"novelty.shift.{dim.name}",
            title=f"Schimbare bruscă de comportament: {dim.label}",
            summary=(f"{now_new} valori noi în ora asta, față de o medie de "
                     f"{mean:.2f} pe oră în ultimele {buckets} ore observate. "
                     + (f"Noi: {', '.join(keys[:6])}." if keys else "")),
            evidence={"dimension": dim.name, "new_this_hour": now_new,
                      "mean_per_hour": round(mean, 3), "history_buckets": buckets,
                      "multiple": round(now_new / mean, 1) if mean else None,
                      "keys": keys},
            event_ids=[],
        ))
    return out


# `observe` nu e o regulă de detecție, dar trebuie să ruleze în aceeași buclă și
# ÎNAINTEA celor două de mai sus. Motorul iterează secvențial peste tuplu, deci
# ordinea de aici e ordinea de execuție.
async def _learn(db: Database, cursor: int) -> list[DetectionSpec]:
    try:
        await bh.observe(db, cursor)
    except Exception as exc:  # noqa: BLE001 - învățarea nu are voie să oprească detecția
        log.error("behaviour learning failed", extra={"detail": str(exc)})
    return []


NOVELTY_RULES = (_learn, unseen_before, composition_shift)
