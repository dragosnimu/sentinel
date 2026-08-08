"""Deterministic detection rules.

Each rule is a small async function that queries raw_events and returns zero or
more DetectionSpec. Rules only ever consider IPs that produced a NEW event since
the engine's cursor — so an ongoing brute-force is re-evaluated when fresh
failures arrive, not on a fixed clock, and a quiet attacker does not generate a
detection every cycle forever.

These are honest thresholds, not "AI anomaly detection": a count in a window, a
ratio of 404s. They cost nothing, run 24/7, and are explainable — an operator can
read the rule and know exactly why an incident fired.
"""

from __future__ import annotations

from typing import Any

from sentinel.db.engine import Database
# DetectionSpec trăiește în `spec`, ca modulele de reguli să se poată importa
# între ele fără ciclu. Re-exportat de aici: e importat din `rules` peste tot.
from sentinel.detect.spec import DetectionSpec  # noqa: F401

# SSH brute-force: failed logins from one source in a window.
SSH_WINDOW_MIN = 10
SSH_THRESHOLDS = ((100, "critical"), (25, "high"), (8, "medium"))

# Web enumeration: a source hammering many distinct paths that 404 — a scanner
# walking the site looking for something to exploit.
WEB_WINDOW_MIN = 5
WEB_404_THRESHOLD = 30



def _severity_for(count: int, thresholds: tuple[tuple[int, str], ...]) -> str | None:
    for threshold, sev in thresholds:
        if count >= threshold:
            return sev
    return None


async def ssh_bruteforce(db: Database, cursor: int) -> list[DetectionSpec]:
    rows = await db.fetch(
        """
        WITH fresh AS (
            SELECT DISTINCT src_ip FROM raw_events
            WHERE id > $1 AND source = 'sshd' AND action = 'auth_fail' AND src_ip IS NOT NULL
        )
        SELECT host(e.src_ip) AS ip,
               count(*) AS fails,
               array_agg(DISTINCT e.username) FILTER (WHERE e.username IS NOT NULL) AS users,
               array_agg(e.id ORDER BY e.id DESC) AS event_ids,
               min(e.ts) AS first_ts, max(e.ts) AS last_ts,
               max(e.geo_country) AS country, max(e.geo_asn) AS asn
        FROM raw_events e
        JOIN fresh f ON f.src_ip = e.src_ip
        WHERE e.source = 'sshd' AND e.action = 'auth_fail'
          AND e.ts > now() - make_interval(mins => $2)
        GROUP BY e.src_ip
        """,
        cursor, SSH_WINDOW_MIN,
    )
    specs: list[DetectionSpec] = []
    for r in rows:
        sev = _severity_for(r["fails"], SSH_THRESHOLDS)
        if sev is None:
            continue
        users = (r["users"] or [])[:12]
        specs.append(DetectionSpec(
            rule_id="auth.ssh_bruteforce",
            rule_family="auth",
            severity=sev,
            src_ip=r["ip"],
            dst_port=22,
            fingerprint=f"auth.ssh_bruteforce:{r['ip']}",
            title=f"Brute-force SSH de la {r['ip']}",
            summary=(f"{r['fails']} autentificări eșuate în {SSH_WINDOW_MIN} min, "
                     f"utilizatori încercați: {', '.join(users) or '—'}"),
            evidence={
                "fails": r["fails"], "window_min": SSH_WINDOW_MIN, "usernames": users,
                "first_seen": r["first_ts"].isoformat(), "last_seen": r["last_ts"].isoformat(),
                "country": r["country"], "asn": r["asn"],
            },
            event_ids=list(r["event_ids"])[:200],
        ))
    return specs


async def web_enumeration(db: Database, cursor: int) -> list[DetectionSpec]:
    rows = await db.fetch(
        """
        WITH fresh AS (
            SELECT DISTINCT src_ip FROM raw_events
            WHERE id > $1 AND source = 'nginx' AND http_status = 404 AND src_ip IS NOT NULL
        )
        SELECT host(e.src_ip) AS ip,
               count(*) FILTER (WHERE e.http_status = 404) AS notfound,
               count(DISTINCT e.http_path) AS distinct_paths,
               array_agg(DISTINCT e.http_path) FILTER (WHERE e.http_status = 404) AS paths,
               array_agg(e.id ORDER BY e.id DESC) AS event_ids,
               max(e.http_ua) AS ua
        FROM raw_events e
        JOIN fresh f ON f.src_ip = e.src_ip
        WHERE e.source = 'nginx' AND e.ts > now() - make_interval(mins => $2)
        GROUP BY e.src_ip
        HAVING count(*) FILTER (WHERE e.http_status = 404) >= $3
        """,
        cursor, WEB_WINDOW_MIN, WEB_404_THRESHOLD,
    )
    specs: list[DetectionSpec] = []
    for r in rows:
        sev = "high" if r["notfound"] >= 200 else "medium"
        paths = (r["paths"] or [])[:15]
        specs.append(DetectionSpec(
            rule_id="web.enumeration",
            rule_family="web",
            severity=sev,
            src_ip=r["ip"],
            dst_port=443,
            fingerprint=f"web.enumeration:{r['ip']}",
            title=f"Enumerare web de la {r['ip']}",
            summary=(f"{r['notfound']} răspunsuri 404 pe {r['distinct_paths']} căi distincte "
                     f"în {WEB_WINDOW_MIN} min"),
            evidence={
                "notfound": r["notfound"], "distinct_paths": r["distinct_paths"],
                "window_min": WEB_WINDOW_MIN, "sample_paths": paths, "user_agent": r["ua"],
            },
            event_ids=list(r["event_ids"])[:200],
        ))
    return specs


# --- Suricata IDS alerts (P6.3) ---------------------------------------------
SURICATA_WINDOW_MIN = 10
# Suricata severity 1 = most severe, 3 = informational noise we do not raise on.
_SURICATA_SEV = {1: "high", 2: "medium"}
# A severity-2 signature is often reputational ("this source is on a block
# list") rather than evidence of an attack on you, and the internet supplies a
# steady drip of those. One hit is not an incident: it produced 485 open
# incidents here, drowning everything else. A severity-1 signature is a real
# exploit attempt and still raises on the first hit.
SURICATA_MIN_HITS = {1: 1, 2: 4}


async def suricata_alert(db: Database, cursor: int) -> list[DetectionSpec]:
    """Group fresh Suricata alerts by source IP into one incident per attacker.
    Severity is the worst (lowest-numbered) signature seen. Informational
    (severity 3) alerts are recorded as events but never raise an incident."""
    rows = await db.fetch(
        """
        WITH fresh AS (
            SELECT DISTINCT src_ip FROM raw_events
            WHERE id > $1 AND source = 'suricata' AND action = 'alert' AND src_ip IS NOT NULL
        )
        SELECT host(e.src_ip) AS ip,
               count(*) AS hits,
               min((e.raw->>'severity')::int) AS min_sev,
               array_agg(DISTINCT e.raw->>'signature')
                   FILTER (WHERE e.raw->>'signature' IS NOT NULL) AS sigs,
               array_agg(e.id ORDER BY e.id DESC) AS event_ids,
               max(e.dst_port) AS dport
        FROM raw_events e
        JOIN fresh f ON f.src_ip = e.src_ip
        WHERE e.source = 'suricata' AND e.action = 'alert'
          AND e.ts > now() - make_interval(mins => $2)
        GROUP BY e.src_ip
        """,
        cursor, SURICATA_WINDOW_MIN,
    )
    specs: list[DetectionSpec] = []
    for r in rows:
        if r["min_sev"] is None:
            continue
        worst = int(r["min_sev"])
        sev = _SURICATA_SEV.get(worst)
        if sev is None or int(r["hits"]) < SURICATA_MIN_HITS.get(worst, 1):
            continue
        sigs = (r["sigs"] or [])[:6]
        specs.append(DetectionSpec(
            rule_id="ids.suricata", rule_family="ids", severity=sev,
            src_ip=r["ip"], dst_port=r["dport"],
            fingerprint=f"ids.suricata:{r['ip']}",
            title=f"Alertă IDS de la {r['ip']}",
            summary=(f"{r['hits']} alerte Suricata (severitate max {r['min_sev']}): "
                     f"{', '.join(s for s in sigs if s) or '—'}"),
            evidence={"hits": r["hits"], "min_severity": r["min_sev"], "signatures": sigs},
            event_ids=list(r["event_ids"])[:200],
        ))
    return specs


# --- seasonal volume anomaly (P6.2) ----------------------------------------
# Robust z bands. 3.5 ≈ a genuine outlier for MAD-scaled normal data; 8 is a
# flood. A minute quieter than usual is not an incident, so only the upper tail
# fires (z > 0).
ANOMALY_Z = ((8.0, "critical"), (5.0, "high"), (3.5, "medium"))
# Below this raw count a spike is not worth an incident: going from 1 to 6
# requests is a huge z but means nothing operationally.
ANOMALY_MIN_COUNT = 20


def _severity_for_z(z: float) -> str | None:
    for threshold, sev in ANOMALY_Z:
        if z >= threshold:
            return sev
    return None


async def volume_anomaly(db: Database, cursor: int) -> list[DetectionSpec]:
    """Compare the last completed minute against its seasonal baseline. Silent
    until a baseline is warm (14 days) — records nothing while learning, so it
    cannot flood the operator on day one. Its subject is an asset, not an IP, so
    the decider never auto-blocks on it."""
    from sentinel.db.repo import events as ev_repo
    from sentinel.predict import baseline as bl

    target = await db.fetchval("SELECT date_trunc('minute', now()) - interval '1 minute'")
    if target is None:
        return []
    if await ev_repo.get_cursor(db, "predict:anomaly") == target.isoformat():
        return []  # already evaluated this minute

    how = bl.hour_of_week(target)
    specs: list[DetectionSpec] = []
    for metric in bl.METRICS:
        asset_id = await db.fetchval("SELECT id FROM assets WHERE name = $1", metric.asset_name)
        if asset_id is None:
            continue
        b = await db.fetchrow(
            "SELECT median, mad, warm FROM baselines "
            "WHERE asset_id = $1 AND metric = $2 AND hour_of_week = $3",
            asset_id, metric.name, how)
        if not b or not b["warm"]:
            continue
        n = int(await db.fetchval(
            "SELECT count(*) FROM raw_events "
            "WHERE source = $1 AND ($2::text IS NULL OR action = $2) "
            "AND ts >= $3 AND ts < $3 + interval '1 minute'",
            metric.source, metric.action, target) or 0)
        if n < ANOMALY_MIN_COUNT:
            continue
        z = bl.robust_z(float(n), float(b["median"]), float(b["mad"]))
        sev = _severity_for_z(z)
        if sev is None:
            continue
        specs.append(DetectionSpec(
            rule_id="anomaly.volume", rule_family="anomaly", severity=sev,
            src_ip=None, actor_key=f"host:{metric.asset_name}",
            fingerprint=f"anomaly.volume:{metric.name}:{asset_id}",
            title=f"Anomalie de volum: {metric.name} pe {metric.asset_name}",
            summary=(f"{n} pe minut la ora-săptămânii {how} "
                     f"(normal ≈ {float(b['median']):.0f}, z={z:.1f})"),
            evidence={"metric": metric.name, "observed": n, "median": float(b["median"]),
                      "mad": float(b["mad"]), "z": round(z, 2), "hour_of_week": how},
            event_ids=[], asset_id=asset_id,
        ))

    await ev_repo.set_cursor(db, "predict:anomaly", target.isoformat())
    return specs


_ATTEMPT_RULES = (ssh_bruteforce, web_enumeration, suricata_alert, volume_anomaly)


def _all_rules() -> tuple:
    """Tentativele plus post-compromiterea.

    Separarea în două module e intenționată. Regulile de mai sus răspund la
    „cine încearcă?"; cele din `intrusion` la „a reușit cineva?". Sunt întrebări
    diferite, cu praguri diferite — tentativele contează în rafală, o
    compromitere contează de la prima apariție — și le ține împreună doar faptul
    că motorul le rulează pe amândouă.
    """
    from sentinel.detect.accounts import ACCOUNT_RULES
    from sentinel.detect.exposed import EXPOSURE_RULES
    from sentinel.detect.intrusion import INTRUSION_RULES
    from sentinel.detect.novelty import NOVELTY_RULES
    return (_ATTEMPT_RULES + INTRUSION_RULES + ACCOUNT_RULES + NOVELTY_RULES
            + EXPOSURE_RULES)


RULES = _all_rules()
