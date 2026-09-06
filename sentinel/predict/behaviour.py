"""Profilul de comportament normal al gazdei, învățat din propriul flux.

Regulile de detecție prind ce am știut să descriu dinainte. Asta prinde ce nu
am știut: „lucrul ăsta nu s-a mai întâmplat niciodată aici".

## Dimensiunile

Fiecare dimensiune e o întrebare la care un server sănătos dă mereu cam același
răspuns, iar o compromitere îl schimbă:

    login_user         cine se autentifică cu succes
    login_asn          din ce rețea vine o autentificare reușită
    login_country      din ce țară
    sudo_user          cine folosește privilegii
    exec_binary        ce se execută sub supraveghere
    webroot_writer     ce proces scrie în conținutul servit
    outbound_dst       ce destinație de ieșire contactează gazda (F04)

Nu sunt alese ca să acopere tot, ci ca să fie STABILE. O dimensiune care se
schimbă legitim în fiecare zi nu poate produce niciodată o alertă utilă: fie
tace mereu, fie țipă mereu. `login_user` pe un server administrat de doi oameni
are două valori un an întreg — de asta a treia contează.

## De ce nu e o medie

`predict/baseline.py` face deja mediană și MAD sezonier pe volum, cu 14 zile de
încălzire, și răspunde la „e mai mult trafic decât de obicei?". E oarbă exact la
cazul care contează aici: un atacator care se autentifică O DATĂ, cu credențiale
furate, dintr-o rețea în care nu ai fost niciodată, nu mișcă niciun volum.

Compoziția se schimbă înaintea volumului. De asta profilul e o mulțime de chei
văzute, nu o serie de numere — și de asta devine utilă după câteva zile, nu după
paisprezece: îți trebuie destule observații ca să știi ce e normal, nu destule
ca să estimezi o distribuție.

## Poarta de încălzire

Două praguri, ȘI, nu SAU: destule zile și destule observații.

Numai zilele nu ajung — un server care a stat oprit trei zile ar deveni „cald"
fără să fi văzut nimic, apoi ar alerta pentru primul lucru normal care se
întâmplă. Numai observațiile nu ajung — o mie de autentificări într-o oră spun
ce se întâmplă într-o oră, nu ce e normal marți dimineața.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class Dimension:
    name: str
    # Din ce evenimente se învață.
    source: str
    action: str
    # Cum se extrage cheia dintr-un rând de eveniment.
    key_of: Callable[[Any], str | None]
    # Ce înseamnă o cheie nouă, în română, pentru alerta operatorului.
    label: str
    novel_title: str
    severity: str
    # Poarta de încălzire.
    warmup_days: int = 3
    min_observations: int = 40
    # Câte chei distincte trebuie văzute înainte ca „una nouă" să fie
    # informativă. O dimensiune care a văzut o singură valoare nu a învățat
    # nimic — a doua nu e o anomalie, e a doua.
    min_distinct: int = 2


def _s(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s[:200] or None


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        "login_user", "sshd", "auth_ok", lambda r: _s(r["username"]),
        label="utilizator care se autentifică",
        novel_title="Autentificare reușită a unui utilizator nou",
        severity="high"),
    Dimension(
        "login_asn", "sshd", "auth_ok", lambda r: _s(r["geo_asn"]),
        label="rețea sursă pentru autentificări",
        novel_title="Autentificare reușită dintr-o rețea nouă",
        severity="high"),
    Dimension(
        "login_country", "sshd", "auth_ok", lambda r: _s(r["geo_country"]),
        label="țară sursă pentru autentificări",
        novel_title="Autentificare reușită dintr-o țară nouă",
        severity="high"),
    Dimension(
        "sudo_user", "sudo", "privilege_use", lambda r: _s(r["username"]),
        label="utilizator care folosește sudo",
        novel_title="Utilizator nou care folosește privilegii",
        severity="high"),
    Dimension(
        "exec_binary", "auditd", "suspicious_exec", lambda r: _s(r["process"]),
        label="binar executat sub supraveghere",
        novel_title="Binar nou executat sub supraveghere",
        severity="high",
        # Executabilele supravegheate sunt rare; pragul de observații trebuie
        # să fie pe măsură, altfel dimensiunea nu se încălzește niciodată.
        min_observations=10),
    Dimension(
        "webroot_writer", "auditd", "webroot_change", lambda r: _s(r["process"]),
        label="proces care scrie în conținutul servit",
        novel_title="Proces nou care scrie în conținutul servit",
        severity="high",
        min_observations=10),
    # F04: o destinație de ieșire pe care gazda n-a mai contactat-o niciodată.
    # Semnalul principal al colectorului conntrack — vezi
    # `collectors/conntrack.py` pentru ce prinde (C2 persistent, exfiltrare
    # lentă) și ce ratează (o conexiune scurtă între două eșantioane).
    #
    # Volum mult sub cel al logărilor SSH — eșantionare o dată pe minut, cu
    # deduplicare pe oră, nu jurnal complet — deci pragul de OBSERVAȚII e cel
    # folosit și pentru `exec_binary`/`webroot_writer`, dimensiuni la fel de
    # rare, nu cel implicit de 40 gândit pentru autentificări.
    #
    # `severity` și `warmup_days` NU sunt implicitele — au fost coborâte/
    # urcate pe 6 septembrie 2026, pe măsurătoare, nu pe presupunere: pe
    # gazda de producție, în primele șase zile de profil, „chei noi pe zi"
    # pentru dimensiunea asta a fost 671, 355, 59, 19, 7, 4 — încă nenul în a
    # șasea zi, ultima măsurată, zi în care profilul era deja „cald" de două
    # zile (implicitul de 3) și ridicase deja 16 incidente HIGH, fiecare cu un
    # IP gol în text („dacă e o schimbare, confirm-o; dacă nu, verifică cine")
    # pe care nimeni nu-l putea tria — vezi `collectors/conntrack.py`, secțiunea
    # „Severity" din docstring, pentru șirul complet și sursa cifrelor.
    # `login_user`/`login_asn` au câteva valori STABILE; `outbound_dst` are
    # peste o mie și încă adaugă — nu e aceeași formă de dimensiune, deci nu
    # merită aceeași poartă. 14 zile nu e ales să arate bine pe grafic: e
    # ACELAȘI 14 pe care `RATE_LOOKBACK_HOURS` din `detect/novelty.py` îl
    # tratează deja drept „destul istoric ca să însemne ceva" pentru familia
    # asta de reguli — și nici el nu e dovedit corect după ziua șase, fiindcă
    # atât s-a măsurat până acum.
    #
    # ATENȚIE, ca să nu se creadă din diff că amândouă schimbările au avut
    # efect: `warmup_days=14` e FĂRĂ EFECT pe gazda de producție chiar acum.
    # `outbound_dst.warm_at` era deja setat acolo, la două zile după
    # `started_at`, sub vechiul `warmup_days=3` — iar `_promote_warm` mai jos
    # sare peste orice rând cu `warm_at IS NOT NULL`, pe propriul ei invariant
    # documentat: o dimensiune devenită caldă n-are voie să redevină rece.
    # Pragul nou nu atinge un rând deja cald; doar `severity` (citit live din
    # DIMENSIONS la fiecare alertă, niciodată cache-uit) se aplică imediat, și
    # doar pentru alertele de-acum-încolo — cele 16 incidente HIGH deja
    # deschise nu devin MEDIUM retroactiv. Resetarea lui `warm_at` pentru
    # `outbound_dst` pe gazda asta ar face `warmup_days=14` să conteze și
    # acolo, dar asta contrazice invariantul scris mai sus în cod — e decizia
    # operatorului, nu una luată tăcut din acest modul.
    Dimension(
        "outbound_dst", "conntrack", "connect", lambda r: _s(r["dst_ip"]),
        label="destinație de ieșire contactată de gazdă",
        novel_title="Conexiune de ieșire către o destinație nouă",
        severity="medium",
        warmup_days=14,
        min_observations=15),
)

BY_NAME = {d.name: d for d in DIMENSIONS}


# ---------------------------------------------------------------------------
# Învățarea
# ---------------------------------------------------------------------------
async def observe(db: Database, cursor: int) -> dict[str, dict[str, int]]:
    """Consumă evenimentele noi și actualizează profilul.

    Întoarce, per dimensiune, câte observații și câte chei NOI au fost — cheile
    noi fiind exact ce evaluează regulile de noutate imediat după.

    Rulează în aceeași buclă cu detecția și pe același cursor: dacă ar avea
    cursor propriu, cele două s-ar putea desincroniza și un eveniment ar putea
    fi evaluat ca „nou" după ce profilul l-a învățat deja, sau invers.
    """
    out: dict[str, dict[str, int]] = {}
    for dim in DIMENSIONS:
        rows = await db.fetch(
            """
            SELECT id, username, process, geo_asn, geo_country, dst_ip, ts
            FROM raw_events
            WHERE id > $1 AND source = $2 AND action = $3
            ORDER BY id
            LIMIT 5000
            """,
            cursor, dim.source, dim.action)
        if not rows:
            continue

        keys: dict[str, int] = {}
        for r in rows:
            k = dim.key_of(r)
            if k:
                keys[k] = keys.get(k, 0) + 1
        if not keys:
            continue

        # Un singur UPSERT pe cheie. `xmax = 0` e cum întreabă Postgres „a fost
        # inserat, nu actualizat" — fără el ar trebui un SELECT în prealabil,
        # iar între SELECT și INSERT altcineva poate insera aceeași cheie.
        new_keys = 0
        for k, n in keys.items():
            inserted = await db.fetchval(
                """
                INSERT INTO behaviour_profiles (dimension, key, observations)
                VALUES ($1, $2, $3)
                ON CONFLICT (dimension, key) DO UPDATE
                    SET observations = behaviour_profiles.observations + EXCLUDED.observations,
                        last_seen = now()
                RETURNING (xmax = 0)
                """,
                dim.name, k, n)
            if inserted:
                new_keys += 1

        total = sum(keys.values())
        await db.execute(
            """
            INSERT INTO behaviour_learning (dimension, observations, distinct_keys)
            VALUES ($1, $2, $3)
            ON CONFLICT (dimension) DO UPDATE
                SET observations  = behaviour_learning.observations + EXCLUDED.observations,
                    distinct_keys = (SELECT count(*) FROM behaviour_profiles
                                      WHERE dimension = $1)
            """,
            dim.name, total, len(keys))

        await db.execute(
            """
            INSERT INTO behaviour_novelty_rate (dimension, bucket, new_keys, total_obs)
            VALUES ($1, date_trunc('hour', now()), $2, $3)
            ON CONFLICT (dimension, bucket) DO UPDATE
                SET new_keys  = behaviour_novelty_rate.new_keys + EXCLUDED.new_keys,
                    total_obs = behaviour_novelty_rate.total_obs + EXCLUDED.total_obs
            """,
            dim.name, new_keys, total)

        out[dim.name] = {"observations": total, "new_keys": new_keys,
                         "distinct": len(keys)}
    await _promote_warm(db)
    return out


async def _promote_warm(db: Database) -> list[str]:
    """Marchează dimensiunile care au văzut destul.

    Persistat, nu recalculat la fiecare interogare: retenția taie observațiile
    vechi, iar o dimensiune care a devenit caldă nu are voie să redevină rece
    fiindcă i s-a șters istoricul. Ar însemna o a doua perioadă oarbă, exact
    când profilul e cel mai valoros.
    """
    promoted: list[str] = []
    for dim in DIMENSIONS:
        row = await db.fetchrow(
            "SELECT started_at, observations, distinct_keys, warm_at "
            "FROM behaviour_learning WHERE dimension = $1", dim.name)
        if row is None or row["warm_at"] is not None:
            continue
        age_days = (datetime.now(timezone.utc) - row["started_at"]).total_seconds() / 86400
        if (age_days >= dim.warmup_days
                and row["observations"] >= dim.min_observations
                and row["distinct_keys"] >= dim.min_distinct):
            await db.execute(
                "UPDATE behaviour_learning SET warm_at = now() WHERE dimension = $1",
                dim.name)
            promoted.append(dim.name)
            log.info("behaviour dimension is warm",
                     extra={"dimension": dim.name, "days": round(age_days, 1),
                            "observations": row["observations"],
                            "distinct_keys": row["distinct_keys"]})
    return promoted


async def status(db: Database) -> list[dict[str, Any]]:
    """Ce a învățat și cât mai are — pentru panou și pentru Telegram."""
    rows = await db.fetch(
        "SELECT dimension, started_at, observations, distinct_keys, warm_at "
        "FROM behaviour_learning")
    have = {r["dimension"]: r for r in rows}
    out = []
    for dim in DIMENSIONS:
        r = have.get(dim.name)
        if r is None:
            out.append({"dimension": dim.name, "label": dim.label, "warm": False,
                        "observations": 0, "distinct_keys": 0, "days": 0.0,
                        "needs": f"{dim.warmup_days} zile și {dim.min_observations} observații"})
            continue
        days = (datetime.now(timezone.utc) - r["started_at"]).total_seconds() / 86400
        warm = r["warm_at"] is not None
        out.append({
            "dimension": dim.name, "label": dim.label, "warm": warm,
            "observations": r["observations"], "distinct_keys": r["distinct_keys"],
            "days": round(days, 1),
            "needs": None if warm else (
                f"încă {max(0, dim.warmup_days - days):.1f} zile, "
                f"{max(0, dim.min_observations - r['observations'])} observații"),
        })
    return out


async def is_warm(db: Database, dimension: str) -> bool:
    return bool(await db.fetchval(
        "SELECT warm_at IS NOT NULL FROM behaviour_learning WHERE dimension = $1",
        dimension))
