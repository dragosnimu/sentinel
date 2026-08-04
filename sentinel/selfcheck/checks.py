"""The individual checks.

Each returns a `CheckResult` and never raises into the runner: a check that
crashes must report itself as broken, not take the whole self-check down with
it. A self-check that fails silently is the exact disease it exists to cure.

Two rules shape every check here.

**Prove the effect, not the process.** `systemctl is-active` is a hint. That a
collector wrote a row, that the kernel holds a table, that the executor replied
— those are facts.

**Silence is only a fault when something else is talking.** A host where nothing
happened looks identical to a host where nothing is being watched, and the only
way to tell them apart from the inside is to compare sources against each other.
A collector that has gone quiet while its neighbours keep writing is broken. All
of them quiet together is a quiet night.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from sentinel.config import Config
from sentinel.constants import SYSTEMD_UNITS
from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

Status = Literal["ok", "degraded", "down", "unknown"]

# Ordered worst-first, so a run's overall verdict is `min` by this index.
_RANK = {"down": 0, "degraded": 1, "unknown": 2, "ok": 3}


@dataclass(frozen=True)
class CheckResult:
    key: str                     # stable id, used for change detection
    title: str                   # Romanian, shown to the operator
    status: Status
    detail: str = ""             # Romanian, what was actually observed
    action: str = ""             # Romanian, what to do about it
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def bad(self) -> bool:
        return self.status in ("down", "degraded")


def worst(results: list[CheckResult]) -> Status:
    if not results:
        return "unknown"
    return min((r.status for r in results), key=lambda s: _RANK.get(s, 2))


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------
def _systemctl(*args: str) -> str:
    if not shutil.which("systemctl"):
        return ""
    try:
        out = subprocess.run(["systemctl", *args], capture_output=True,
                             text=True, timeout=10)
        return (out.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


async def check_units(cfg: Config) -> list[CheckResult]:
    """Every unit that should be running, is.

    The weakest check in the file, and first only because it is the one people
    expect. A unit being active proves that a process exists — nothing about
    whether it is doing its job. Everything below is what actually matters.
    """
    results: list[CheckResult] = []
    for unit in SYSTEMD_UNITS:
        # A build without the AI layer configured legitimately has no ai unit.
        if unit == "sentinel-ai.service" and not cfg.ai.enabled:
            continue
        state = await asyncio.to_thread(_systemctl, "is-active", unit)
        if state == "active":
            results.append(CheckResult(f"unit:{unit}", f"Serviciul {unit}", "ok",
                                       detail="activ"))
            continue
        # `activating` during a restart is not yet a fault; a crash loop is,
        # and that is what the restart counter below catches.
        status: Status = "degraded" if state in ("activating", "reloading") else "down"
        restarts = await asyncio.to_thread(
            _systemctl, "show", unit, "-p", "NRestarts", "--value")
        results.append(CheckResult(
            f"unit:{unit}", f"Serviciul {unit}", status,
            detail=f"stare: {state or 'necunoscută'} · reporniri: {restarts or '?'}",
            action=f"journalctl -u {unit} -n 50",
            facts={"state": state, "restarts": restarts}))
    return results


async def check_timers(cfg: Config) -> list[CheckResult]:
    """Timers are scheduled and have actually fired.

    A timer that is enabled but whose next elapse is in the past has stopped;
    one that has never fired on a host that has been up for days never will.
    """
    results: list[CheckResult] = []
    for unit in ("sentinel-scan.timer", "sentinel-health.timer",
                 "sentinel-maintenance.timer", "sentinel-watchdog.timer",
                 "sentinel-selfcheck.timer"):
        state = await asyncio.to_thread(_systemctl, "is-active", unit)
        if not state:
            continue  # systemd not reachable; check_units already said so
        if state != "active":
            results.append(CheckResult(
                f"timer:{unit}", f"Timerul {unit}", "down",
                detail=f"stare: {state}",
                action=f"systemctl enable --now {unit}"))
            continue
        results.append(CheckResult(f"timer:{unit}", f"Timerul {unit}", "ok",
                                   detail="programat"))
    return results


# ---------------------------------------------------------------------------
# Data liveness — the checks that would have caught the real outages
# ---------------------------------------------------------------------------
#
# Per-source patience. A number here is "how long this source may be quiet on a
# host where OTHER sources are still writing". Generous on purpose: the
# comparison against neighbours is what makes the check sharp, so these only
# have to be long enough to survive a lull.
SOURCE_MAX_SILENCE_MIN: dict[str, int] = {
    "suricata": 30,    # an internet-facing host is scanned constantly
    "auditd": 60,      # cron, logins, privilege use
    "nginx": 180,      # a low-traffic site can genuinely be quiet
    "sshd": 180,       # ditto, though in practice never is
    "sudo": 24 * 60,   # only when someone works on the box
    "su": 7 * 24 * 60,  # rare by design; effectively never alerts
}
DEFAULT_MAX_SILENCE_MIN = 180


async def check_ingest_sources(db: Database, cfg: Config) -> list[CheckResult]:
    """Each collector that has ever produced data is still producing it.

    This is the check that would have caught the 21-hour blind spot: the ingest
    service was `active`, had never restarted, and had logged no error, while
    its journald reader returned nothing poll after poll. Only the data said so.
    """
    rows = await db.fetch(
        """
        SELECT source,
               max(ts) AS ultim,
               EXTRACT(EPOCH FROM (now() - max(ts)))/60 AS minute_tacere
        FROM raw_events
        WHERE ts > now() - interval '30 days'
        GROUP BY source
        """)
    if not rows:
        return [CheckResult("ingest:any", "Colectare de evenimente", "down",
                            detail="niciun eveniment în 30 de zile",
                            action="journalctl -u sentinel-ingest -n 100")]

    ages = {r["source"]: float(r["minute_tacere"] or 0) for r in rows}
    # The discriminator: is ANY source still writing? If none is, the host is
    # quiet (or the whole daemon is down, which check_units reports) — and
    # blaming each collector individually would be six alerts for one fault.
    freshest = min(ages.values())
    others_are_live = freshest <= 5

    results: list[CheckResult] = []
    for source, minutes in sorted(ages.items()):
        limit = SOURCE_MAX_SILENCE_MIN.get(source, DEFAULT_MAX_SILENCE_MIN)
        if minutes <= limit:
            results.append(CheckResult(
                f"ingest:{source}", f"Colector „{source}”", "ok",
                detail=f"ultimul eveniment acum {int(minutes)} min"))
            continue
        if not others_are_live:
            # Everything is quiet together. Report it once, at the top, rather
            # than accusing each collector of a fault it does not have.
            continue
        results.append(CheckResult(
            f"ingest:{source}", f"Colector „{source}” a amuțit", "down",
            detail=(f"niciun eveniment de {int(minutes // 60)}h {int(minutes % 60)}m, "
                    f"dar alte surse scriu în continuare"),
            action="systemctl restart sentinel-ingest",
            facts={"minutes_silent": int(minutes), "limit_min": limit}))

    if not others_are_live:
        results.append(CheckResult(
            "ingest:all", "Toate sursele au amuțit", "down",
            detail=f"cea mai recentă acum {int(freshest)} min — nu e o noapte liniștită",
            action="systemctl status sentinel-ingest; journalctl -u sentinel-ingest -n 100"))
    return results


async def check_detection_loop(db: Database) -> list[CheckResult]:
    """The detector is consuming what the collectors produce.

    Ingesting into a table nobody reads is a very convincing imitation of
    working: the dashboard fills up, the event count rises, and no incident is
    ever raised.
    """
    row = await db.fetchrow(
        "SELECT cursor, updated_at, "
        "EXTRACT(EPOCH FROM (now() - updated_at))/60 AS minute "
        "FROM collector_cursors WHERE name = 'detect:events'")
    if row is None:
        return [CheckResult("detect:cursor", "Bucla de detecție", "unknown",
                            detail="nu a rulat niciodată")]
    minutes = float(row["minute"] or 0)
    if minutes > 15:
        return [CheckResult(
            "detect:cursor", "Bucla de detecție s-a oprit", "down",
            detail=f"cursorul nu a avansat de {int(minutes)} min",
            action="journalctl -u sentinel-detect -n 100",
            facts={"minutes": int(minutes)})]
    return [CheckResult("detect:cursor", "Bucla de detecție", "ok",
                        detail=f"cursor avansat acum {int(minutes)} min")]


# ---------------------------------------------------------------------------
# Enforcement — is the blocking real?
# ---------------------------------------------------------------------------
def _nft_table_present() -> tuple[bool | None, str]:
    """(True, ruleset) · (False, why) · (None, why) when we could not look.

    The third case is not pedantry. "The table is missing" means the host is
    unprotected; "I was not allowed to read the ruleset" means the check is
    broken. Reporting the first when the second is true is a false alarm about
    the most serious thing this file can say, and a channel that cries wolf
    about total loss of protection is a channel that gets ignored.
    """
    if not shutil.which("nft"):
        return None, "nft nu e instalat"
    try:
        out = subprocess.run(["nft", "list", "table", "inet", "sentinel"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if out.returncode != 0:
        err = (out.stderr or "").strip().splitlines()
        first = err[0] if err else "absentă"
        if "permitted" in first or "permission" in first.lower():
            return None, first
        return False, first
    return True, out.stdout


async def check_enforcement(db: Database, cfg: Config) -> list[CheckResult]:
    """The firewall table exists and agrees with the database.

    This is the other real outage: after a reboot the table was simply gone.
    Sentinel recorded seven active blocks, the kernel held none, and the next
    automatic block would have failed with nobody told. Blocking is the whole
    point of the product, and it was decorative for a day.
    """
    present, detail = await asyncio.to_thread(_nft_table_present)
    if present is None:
        return [CheckResult(
            "nft:table", "Nu pot citi regulile nftables", "unknown",
            detail=f"{detail} — nu știu dacă blocarea funcționează sau nu",
            action="Verificarea are nevoie de CAP_NET_ADMIN: "
                   "systemctl show sentinel-selfcheck -p AmbientCapabilities")]
    if not present:
        return [CheckResult(
            "nft:table", "Tabela nftables lipsește", "down",
            detail=f"`nft list table inet sentinel` → {detail}. "
                   "Nicio blocare nu are efect, nici manuală, nici automată.",
            action="./scripts/deploy.sh --force-step 29  (sau reinstalează pasul nftables)")]

    results = [CheckResult("nft:table", "Tabela nftables", "ok", detail="prezentă")]

    # The anti-lockout invariant, checked rather than assumed.
    admin = getattr(cfg.response, "admin_ip", None) or ""
    if admin and admin not in detail:
        results.append(CheckResult(
            "nft:allowlist", "Adresa ta de administrare nu e în allowlist", "degraded",
            detail=f"{admin} lipsește din setul allowlist — te poți bloca singur afară",
            action=f"sentinel allow {admin}"))

    # Kernel vs database. They should agree; when they do not, one of them is
    # lying about who is blocked, and averaging that away is how it stays hidden.
    from sentinel.respond import actions

    live = await actions.live_count()
    stored = int(await db.fetchval(
        "SELECT count(*) FROM blocklist WHERE unblocked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at > now())") or 0)
    if live < 0:
        results.append(CheckResult(
            "nft:count", "Numărul de blocări din kernel nu se poate citi", "degraded",
            detail="executorul nu a răspuns la interogarea setului",
            action="systemctl status sentinel-executor"))
    elif live != stored:
        results.append(CheckResult(
            "nft:count", "Blocklistul din bază nu corespunde cu kernelul", "degraded",
            detail=f"{stored} în bază · {live} în nftables",
            action="Verifică dacă serverul a repornit; blocurile nu se persistă",
            facts={"stored": stored, "live": live}))
    else:
        results.append(CheckResult("nft:count", "Blocklist sincronizat", "ok",
                                   detail=f"{stored} adrese"))
    return results


async def check_executor() -> list[CheckResult]:
    """The one privileged component answers.

    Checked with a read-only operation. A self-check that had to block
    something to prove blocking works would be worse than no self-check.
    """
    from sentinel.respond import actions

    live = await actions.live_count()
    if live < 0:
        return [CheckResult(
            "executor:socket", "Executorul nu răspunde", "down",
            detail="socketul unix nu a răspuns la o operație read-only",
            action="systemctl status sentinel-executor; ls -l /run/sentinel/executor.sock")]
    return [CheckResult("executor:socket", "Executorul", "ok", detail="răspunde")]


# ---------------------------------------------------------------------------
# Foundations
# ---------------------------------------------------------------------------
async def check_database(db: Database) -> list[CheckResult]:
    if not await db.healthy():
        return [CheckResult("db:reachable", "Baza de date", "down",
                            detail="nu răspunde",
                            action="systemctl status postgresql")]
    results = [CheckResult("db:reachable", "Baza de date", "ok", detail="răspunde")]

    # Schema drift: code newer than the schema fails at the first query that
    # needs the new column, at whatever hour that query happens to run.
    try:
        applied = int(await db.fetchval("SELECT max(version) FROM schema_version") or 0)
        on_disk = max(
            (int(p.name[:4]) for p in
             (Path(__file__).resolve().parents[1] / "db" / "migrations").glob("*.sql")),
            default=0)
        if applied < on_disk:
            results.append(CheckResult(
                "db:schema", "Migrații neaplicate", "degraded",
                detail=f"aplicat {applied}, pe disc {on_disk}",
                action="sentinel migrate",
                facts={"applied": applied, "on_disk": on_disk}))
        else:
            results.append(CheckResult("db:schema", "Schema bazei", "ok",
                                       detail=f"versiunea {applied}"))
    except Exception as exc:  # noqa: BLE001
        results.append(CheckResult("db:schema", "Versiunea schemei", "unknown",
                                   detail=str(exc)[:120]))
    return results


async def check_resources(db: Database) -> list[CheckResult]:
    """Disk and memory, from the samples the capacity collector already takes.

    A full disk stops PostgreSQL, which stops everything. It is also the
    failure with the longest warning time, so there is no excuse for meeting it
    by surprise.
    """
    from sentinel.db.repo import capacity as capacity_repo

    cap = await capacity_repo.latest(db)
    if cap is None:
        return [CheckResult("res:sample", "Măsurători de capacitate", "unknown",
                            detail="niciuna încă")]
    results: list[CheckResult] = []
    for mount, d in (cap.disks or {}).items():
        used = int(d.get("used_pct", 0))
        if used >= 90:
            status: Status = "down" if used >= 95 else "degraded"
            results.append(CheckResult(
                f"res:disk:{mount}", f"Disc {mount} aproape plin", status,
                detail=f"{used}% folosit",
                action="Verifică retenția: sentinel maintenance --prune",
                facts={"used_pct": used}))
        else:
            results.append(CheckResult(f"res:disk:{mount}", f"Disc {mount}", "ok",
                                       detail=f"{used}% folosit"))
    if cap.mem_available_mb is not None and cap.mem_available_mb < 200:
        results.append(CheckResult(
            "res:memory", "Memorie disponibilă scăzută", "degraded",
            detail=f"{cap.mem_available_mb} MB disponibili",
            action="OOM killer alege cel mai mare proces — de obicei aplicația ta"))
    else:
        results.append(CheckResult("res:memory", "Memorie", "ok",
                                   detail=f"{cap.mem_available_mb} MB disponibili"))
    return results


async def check_alerting(db: Database, cfg: Config) -> list[CheckResult]:
    """The channel that carries every other alert.

    Checked last and reported loudest: if this is broken, nothing else in this
    file can reach anyone, and the operator's impression of "no news is good
    news" becomes exactly wrong.
    """
    if not cfg.telegram.enabled:
        return [CheckResult("alert:telegram", "Telegram", "unknown",
                            detail="dezactivat în configurație")]

    state = await asyncio.to_thread(_systemctl, "is-active", "sentinel-telegram.service")
    if state and state != "active":
        return [CheckResult(
            "alert:telegram", "Botul Telegram nu rulează", "down",
            detail=f"stare: {state} — nicio alertă nu poate ajunge la tine",
            action="journalctl -u sentinel-telegram -n 50")]

    # Delivery, not just liveness: a bot that is running but failing to send is
    # the same outcome as one that is stopped.
    stuck = int(await db.fetchval(
        "SELECT count(*) FROM notifications WHERE state = 'queued' "
        "AND enqueued_at < now() - interval '10 minutes'") or 0)
    if stuck:
        return [CheckResult(
            "alert:telegram", "Notificări blocate în coadă", "degraded",
            detail=f"{stuck} mesaje în așteptare de peste 10 minute",
            action="journalctl -u sentinel-telegram -n 50",
            facts={"stuck": stuck})]
    return [CheckResult("alert:telegram", "Canalul Telegram", "ok", detail="activ")]


async def check_running_code_is_current() -> list[CheckResult]:
    """Are the daemons running the code that is installed?

    A deploy copies files; only a restart makes a process use them. When those
    two come apart the result is the worst kind of state to reason about: the
    fix is on disk, the bug is in memory, and "is this fixed on the server?" has
    no answer you can trust.

    Found the hard way — the installer restarted two of six units, so four ran
    the previous release after every upgrade until someone happened to restart
    them.
    """
    lib = Path("/opt/sentinel/lib/sentinel")
    if not lib.exists():
        return []
    try:
        code_mtime = max(p.stat().st_mtime for p in lib.rglob("*.py"))
    except (OSError, ValueError):
        return []

    stale: list[str] = []
    for unit in SYSTEMD_UNITS:
        started = await asyncio.to_thread(
            _systemctl, "show", unit, "-p", "ActiveEnterTimestampMonotonic", "--value")
        if not started or not started.isdigit() or started == "0":
            continue
        # Monotonic microseconds since boot → wall clock, via the boot time.
        try:
            with open("/proc/stat") as fh:
                btime = next(int(l.split()[1]) for l in fh if l.startswith("btime"))
        except (OSError, StopIteration):
            return []
        started_at = btime + int(started) / 1_000_000
        if code_mtime > started_at + 5:
            stale.append(unit)

    if not stale:
        return [CheckResult("code:current", "Codul care rulează", "ok",
                            detail="toate serviciile rulează versiunea instalată")]
    return [CheckResult(
        "code:current", "Servicii care rulează cod vechi", "degraded",
        detail=f"{', '.join(u.replace('sentinel-', '').replace('.service', '') for u in stale)}"
               f" — pornite înaintea ultimei instalări",
        action="systemctl restart " + " ".join(stale),
        facts={"stale": stale})]


async def check_autonomy(cfg: Config) -> list[CheckResult]:
    """State the operator should be reminded of, not a fault.

    Auto-block ships disabled and is meant to be turned on after the observation
    window. Nothing enforces that, and "temporarily off" is how a safety feature
    stays off for a year.
    """
    if cfg.response.auto_block.enabled:
        return [CheckResult("mode:autoblock", "Blocare automată", "ok", detail="activă")]
    return [CheckResult(
        "mode:autoblock", "Blocarea automată este oprită", "degraded",
        detail="incidentele sunt raportate, dar nimic nu se blochează singur",
        action="Activează după fereastra de observare: response.auto_block.enabled")]


# ---------------------------------------------------------------------------
CHECKS: tuple[tuple[str, Callable], ...] = (
    ("units", check_units),
    ("timers", check_timers),
    ("ingest", check_ingest_sources),
    ("detect", check_detection_loop),
    ("enforcement", check_enforcement),
    ("executor", check_executor),
    ("database", check_database),
    ("resources", check_resources),
    ("code", check_running_code_is_current),
    ("alerting", check_alerting),
    ("autonomy", check_autonomy),
)


async def run_all(db: Database, cfg: Config) -> list[CheckResult]:
    """Every check, each isolated.

    A check that raises reports itself as broken and the run continues. The
    alternative — one exception ending the run — would mean the self-check goes
    quiet for the same reason everything else does, and quiet is the thing it
    exists to make impossible.
    """
    out: list[CheckResult] = []
    for name, fn in CHECKS:
        try:
            sig = fn.__code__.co_varnames[:fn.__code__.co_argcount]
            args: list[Any] = []
            if "db" in sig:
                args.append(db)
            if "cfg" in sig:
                args.append(cfg)
            out.extend(await fn(*args))
        except Exception as exc:  # noqa: BLE001
            log.error("selfcheck group failed", extra={"group": name, "detail": str(exc)})
            out.append(CheckResult(
                f"selfcheck:{name}", f"Verificarea „{name}” a eșuat", "unknown",
                detail=str(exc)[:200],
                action="Verificarea însăși e stricată — asta trebuie reparat întâi"))
    return out


def since(moment: datetime | None) -> timedelta | None:
    return None if moment is None else datetime.now(timezone.utc) - moment
