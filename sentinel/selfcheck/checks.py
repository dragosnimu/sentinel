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

## Emitting nothing is a statement, and it is not "fine"

Many keys here are conditional: `ingest:all` exists only while every source is
silent, `ingest:any` only while nothing has been collected at all, `unit:…ai`
only while the AI layer is configured, `res:disk:/x` only while that mount
exists. The runner reconciles `selfcheck_state` against the keys a run emits, so
a key absent from a run is treated as a finding the check withdrew.

That makes "I did not emit this key" a load-bearing claim, and it must only ever
mean *the check looked and had nothing to report* — never *the check could not
look*. A check that returns nothing because a probe failed would have its own
previous finding deleted, and the operator would be shown a recovery that never
happened. When a check cannot read what it needs, it emits `unknown`; it does
not fall silent. (`ingest:{source}` has one honest gap left: a source that goes
quiet for more than the 30-day window drops out of the query altogether. Worth
knowing about before extending that window's use.)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Literal

import yaml

from sentinel.config import CONFIG_PATH, Config, resolve_skip_command_accounts
from sentinel.constants import SYSTEMD_UNITS
from sentinel.db.engine import Database
from sentinel.db.repo.logins import REAL_TTY_SQL
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


async def _service_started_at(unit: str) -> datetime | None:
    """Când a intrat ULTIMA OARĂ în `active` unitatea — ceas de perete, sau `None`.

    E cel mai devreme moment în care codul livrat (deci și filtrul de istoric
    încărcat odată cu el) putea avea efect. Aceeași conversie ca în
    `check_code_current`: microsecunde monotone de la boot, aduse la ceasul de
    perete prin `btime` din `/proc/stat`.

    `None` înseamnă „nu pot afla", nu „acum": pe o gazdă fără systemd, cu
    unitatea niciodată pornită, sau când `/proc/stat` nu se poate citi. Apelantul
    NU are voie să confunde «n-am putut citi pornirea» cu «filtrul a putut
    acționa» — altfel ar acuza filtrul pe o gazdă unde n-a măsurat nimic.
    """
    mono = await asyncio.to_thread(
        _systemctl, "show", unit, "-p", "ActiveEnterTimestampMonotonic", "--value")
    if not mono or not mono.isdigit() or mono == "0":
        return None
    try:
        with open("/proc/stat") as fh:
            btime = next(int(l.split()[1]) for l in fh if l.startswith("btime"))
    except (OSError, StopIteration, ValueError):
        return None
    return datetime.fromtimestamp(btime + int(mono) / 1_000_000, tz=timezone.utc)


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
        # Idem beaconul: fără un martor extern configurat, unitatea nu are ce
        # face și e oprită intenționat. A o raporta „down" ar fi exact alarma
        # falsă pe care sursele conduse de om au produs-o deja o dată. Citit
        # direct din `cfg.beacon.enabled`, nu printr-un `getattr` cu valoare de
        # rezervă: `beacon` e o secțiune reală pe `Config`, iar o rezervă ar fi
        # exact garda moartă pe care `test_no_check_reads_a_config_field_that_
        # does_not_exist` există s-o interzică.
        if unit == "sentinel-beacon.service" and not cfg.beacon.enabled:
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
            # An empty answer means `systemctl` is missing, errored, or timed
            # out — not that the timer is fine. This used to `continue`, on the
            # grounds that check_units reports the same outage anyway. Dropping
            # the key is no longer free: the runner reconciles state against the
            # keys a run emits, so a timer that was `down` and then vanished for
            # one flaky probe would be deleted and reported as no longer a
            # finding. One slow `systemctl` must not produce a recovery.
            results.append(CheckResult(
                f"timer:{unit}", f"Timerul {unit}", "unknown",
                detail="nu am putut citi starea — systemctl nu a răspuns",
                action=f"systemctl list-timers {unit}"))
            continue
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
}
DEFAULT_MAX_SILENCE_MIN = 180

# Sources whose events exist only when a HUMAN acts. Silence here is not
# evidence of anything: a server nobody logged into for a day produces zero
# sudo events, and that is the healthy state.
#
# These used to carry thresholds (sudo 24h, su 7d) and the 24h one fired on the
# first quiet day, announcing "SENTINEL NU FUNCȚIONEAZĂ COMPLET" and advising a
# restart of a service that was working correctly. That is worse than no check:
# an alert that cries wolf on a normal weekend trains the operator to dismiss
# the channel that carries the real ones.
#
# The `others_are_live` discriminator below cannot rescue them. It answers "is
# the host quiet, or is this collector broken?" by comparing against neighbours
# — which works for traffic-driven sources, because an exposed host is scanned
# continuously and a silent suricata beside a busy nginx is a genuine fault. It
# says nothing about whether a person happened to type `sudo`.
#
# They are not left unmonitored. sshd, sudo and su come from the SAME journald
# reader — one `_COMM` match set, one loop, classified into sources after the
# fact (see JOURNALD_COMMS in services/ingest_service.py). A broken reader takes
# all three down together, and sshd on an internet-facing host is never quiet.
# So the sshd row above IS the liveness proof for sudo and su.
#
# What this does not catch, stated rather than papered over: a parse-level
# regression affecting only sudo — a distro changing the sudo log format so the
# regex in collectors/system.py stops matching — would leave sudo permanently
# empty while sshd kept flowing. Catching that needs the reader to report what
# it saw and discarded, which it does not currently track.
HUMAN_DRIVEN = frozenset({"sudo", "su"})


def _ago(minutes: float) -> str:
    m = int(minutes)
    if m < 60:
        return f"{m} min"
    if m < 24 * 60:
        return f"{m // 60}h {m % 60}m"
    return f"{m // (24 * 60)}z {(m % (24 * 60)) // 60}h"


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
        if source in HUMAN_DRIVEN:
            # Reported, never alerted on. The operator still sees the source and
            # when it last spoke; what changes is that quiet is not a fault.
            results.append(CheckResult(
                f"ingest:{source}", f"Colector „{source}”", "ok",
                detail=(f"fără activitate de {_ago(minutes)} — normal, "
                        f"evenimentele apar doar când cineva lucrează pe server"),
                facts={"minutes_silent": int(minutes), "human_driven": True}))
            continue
        limit = SOURCE_MAX_SILENCE_MIN.get(source, DEFAULT_MAX_SILENCE_MIN)
        if minutes <= limit:
            results.append(CheckResult(
                f"ingest:{source}", f"Colector „{source}”", "ok",
                detail=f"ultimul eveniment acum {_ago(minutes)}"))
            continue
        if not others_are_live:
            # Everything is quiet together. Report it once, at the top, rather
            # than accusing each collector of a fault it does not have.
            continue
        results.append(CheckResult(
            f"ingest:{source}", f"Colector „{source}” a amuțit", "down",
            detail=(f"niciun eveniment de {_ago(minutes)}, "
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
        # systemd sets INVOCATION_ID for every unit it starts. Its absence means
        # this is a hand-run — `sudo -u sentinel sentinel selfcheck --print` —
        # and the unit's ambient CAP_NET_ADMIN was never granted, because
        # capabilities come from the unit, not from the user.
        #
        # Worth distinguishing, because a hand-run is exactly how an operator
        # debugs, and pointing them at the unit file when the unit file is
        # already correct wastes the trip. An operator who is sent chasing a
        # non-problem twice stops reading the output.
        under_systemd = bool(os.environ.get("INVOCATION_ID"))
        return [
            CheckResult(
                "nft:table", "Nu pot citi regulile nftables", "unknown",
                detail=(f"{detail} — nu știu dacă blocarea funcționează sau nu"
                        + ("" if under_systemd else
                           ". Rulat manual, deci fără capabilitatea pe care i-o dă "
                           "unitatea — nu e neapărat o problemă de configurare")),
                action=("Verificarea are nevoie de CAP_NET_ADMIN: "
                        "systemctl show sentinel-selfcheck -p AmbientCapabilities"
                        if under_systemd else
                        "Rulează verificarea prin systemd, care acordă capabilitatea: "
                        "systemctl start sentinel-selfcheck && journalctl -u sentinel-selfcheck -n 40")),
            # Emis, nu omis. Fără el, o rulare care n-a putut citi regulile ar
            # raporta o rulare COMPLETĂ fără cheia asta, iar runner-ul ar șterge
            # o constatare „blocklistul nu corespunde cu kernelul" adevărată și
            # nereparată, spunându-i operatorului că nu se mai raportează.
            CheckResult(
                "nft:count", "Nu pot compara blocklistul cu kernelul", "unknown",
                detail="fără regulile nftables nu știu câte adrese ține de fapt kernelul",
                action="systemctl show sentinel-selfcheck -p AmbientCapabilities"),
        ]
    if not present:
        return [CheckResult(
            "nft:table", "Tabela nftables lipsește", "down",
            detail=f"`nft list table inet sentinel` → {detail}. "
                   "Nicio blocare nu are efect, nici manuală, nici automată.",
            action="./scripts/deploy.sh --force-step 29  (sau reinstalează pasul nftables)")]

    results = [CheckResult("nft:table", "Tabela nftables", "ok", detail="prezentă")]

    # AICI A STAT `nft:allowlist`, „invariantul anti-lockout, verificat nu
    # presupus". Nu a rulat niciodată. Citea `cfg.response.admin_ip` printr-un
    # `getattr(..., None)`, iar `ResponseConfig` n-are câmpul — deci garda era
    # întotdeauna falsă, cheia nu s-a emis niciodată, și acțiunea propusă,
    # `sentinel allow <ip>`, e o comandă care nu există în CLI. Trei straturi de
    # ficțiune, dintre care testul verifica doar unul: își construia un
    # `SimpleNamespace(admin_ip=...)` pe care `Config`-ul real nu-l poate
    # produce, deci trecea verde peste cod mort.
    #
    # Scos, nu reparat, și scos deliberat într-o schimbare care NU e despre el.
    # Adresa de administrare chiar ajunge în configurație — `install.sh:631-635`
    # o pune ca prima intrare în `response.extra_allowlist` — deci o verificare
    # reală există și merită scrisă: compară `cfg.response.extra_allowlist` cu
    # setul din kernel. Ce o face muncă de sine stătătoare e potrivirea: setul
    # are `flags interval`, deci nftables normalizează și îmbină elementele, iar
    # un `x in text` naiv trece pentru `192.168.1.1` când în set e
    # `192.168.1.10`. Fals-OK pe exact invariantul care ține operatorul afară
    # din propriul server e mai rău decât nicio verificare — și e ce era aici.
    #
    # Până atunci, invariantul se verifică cu ochii, prin docs/TESTARE.md §11.2.

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
        # The ONLY silent exit left in this function, and the only one that is
        # safe: on a host with no installed tree this check has never emitted
        # `code:current`, so there is no finding for the runner to withdraw. The
        # two below are different — there the key exists and the probe failed.
        return []
    try:
        code_mtime = max(p.stat().st_mtime for p in lib.rglob("*.py"))
    except (OSError, ValueError):
        # `step_package` in install.sh does `rm -rf` then `cp -r`, so during a
        # deploy this glob can come back empty (ValueError) or race a file that
        # disappears mid-stat (OSError) — and the timer keeps firing every five
        # minutes throughout. Returning [] here reported a COMPLETE run that had
        # simply not looked, so the runner deleted the `code:current` row and
        # told the operator the finding was no longer reported. Those are the
        # exact minutes around a deploy, which are exactly the minutes when
        # "services are running old code" is true.
        return [CheckResult(
            "code:current", "Nu pot citi codul instalat", "unknown",
            detail="fișierele din /opt/sentinel/lib se schimbau în timpul citirii "
                   "— nu știu dacă serviciile rulează versiunea instalată",
            action="Reia verificarea după instalare: systemctl start sentinel-selfcheck")]

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
            return [CheckResult(
                "code:current", "Nu pot citi momentul pornirii sistemului", "unknown",
                detail="/proc/stat nu a putut fi citit — fără el nu pot spune dacă "
                       "serviciile au pornit înainte sau după ultima instalare",
                action="cat /proc/stat | grep btime")]
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


# ---------------------------------------------------------------------------
# Expedierea către agregator, și semnalul către martorul extern
# ---------------------------------------------------------------------------
#
# How old the oldest unshipped row may get before `ship:lag` calls it a finding.
#
# Generous, and for the same reason as the numbers above: the shipper drains on
# a cadence, so a backlog measured seconds after rows were written is the normal
# state, not a fault. Fifteen minutes matches `detect:cursor`, which answers the
# same shape of question about the loop next door.
SHIP_LAG_GRACE_MIN = 15

# Excepții de prag de vârstă, pe flux. Un flux enumerat aici primește pragul lui;
# oricare altul rămâne la `SHIP_LAG_GRACE_MIN`. Harta ridică pragul DOAR pentru
# fluxul numit — nu e un prag global mărit, fiindcă restul fluxurilor trebuie să
# rămână sensibile la 15 minute. Goală, se comportă ca azi pentru toate.
#
# `session_commands` e fluxul cu cel mai mare volum din toate (~630 de rânduri
# pentru o singură logare, ~405 000 pentru un deploy — vezi
# `SESSION_COMMAND_STREAM` în `report/shipper.py`). Se scurge legitim în
# minute-ore, nu în secunde, deci la 15 minute ar produce o constatare pe
# funcționarea normală, iar o alarmă care se aprinde pe normal e una peste care
# operatorul învață să treacă. Șase ore e restanța pe care o tolerăm ÎNAINTE de a
# o numi „rămasă în urmă". Oprirea propriu-zisă — cursorul care nu mai înaintează
# deloc — e prinsă separat, în câteva minute, de detectorul de înțepenire de mai
# jos; cele două sunt diagnostice diferite și nu au voie să se aștepte una pe alta.
SHIP_LAG_GRACE_MIN_BY_STREAM: dict[str, int] = {
    "session_commands": 360,  # 6 ore
}

# Câte rulări consecutive ale autodiagnosticului văd VALOAREA cursorului
# neschimbată — deși există rânduri în așteptare — înainte ca fluxul să fie numit
# înțepenit. Trei, adică se raportează „la a treia privire", exact aceeași
# convenție ca `BEACON_REFUSALS_BEFORE_FINDING`: temporizatorul e la 5 minute
# (`OnUnitActiveSec=5min`), deci ~15 minute, prins pe scala minutelor, nu a orelor
# pragului de vârstă de mai sus. O restanță reală care se recuperează nu s-a
# oprit — cursorul ei înaintează la fiecare rundă, deci resetează contorul; numai
# un cursor înghețat trece pragul.
#
# Semnalul e VALOAREA cursorului comparată între rulări, NU ora vreunei scrieri,
# și asta e miezul reparației. Măsurat în `report/shipper.py`: `_advance` (fluxul
# pe `id`) și `_advance_mutable` (fluxul pe `(updated_at, cheie)`) scriu amândouă
# `updated_at = now()` NECONDIȚIONAT la fiecare upsert, în timp ce `cursor` și
# `cursor_at` se mișcă doar când chiar avansează (`GREATEST`, respectiv
# `CASE WHEN moved`). Un detector clădit pe `updated_at` n-ar vedea deci niciodată
# o înțepenire — ar arăta identic cu munca normală. Comparăm `item.cursor`:
# `cursor` (int) pentru fluxul pe `id`, `cursor_at` (isoformat) pentru cel mutabil
# — ambele se schimbă numai când expedierea înaintează cu adevărat.
STALL_RUNS_BEFORE_FINDING = 3

# How long the last ACCEPTED beat may sit before `beacon:delivery` calls it a
# finding, and how many refused rounds in a row make a never-accepted beacon one.
#
# Fifteen minutes is three runs of the self-check timer (`OnUnitActiveSec=5min`),
# so a host reports the finding on the third look rather than on a single
# unlucky one. It is also deliberately LONGER than the witness's own silence
# alarm: the witness is the authority on "this host went quiet", and it says so
# from a machine an attacker does not control. What this end adds is the case
# the witness structurally cannot see — an instance that has never beaten, whose
# every beat is being refused.
#
# Three refusals is the same scale as the beacon's own log escalation
# (`_PROBE_ALARM_AT`), so the log line and the panel start meaning the same
# thing at the same moment.
BEACON_DELIVERY_GRACE_MIN = 15
BEACON_REFUSALS_BEFORE_FINDING = 3

# The aggregator's request-body ceiling, in bytes — `MAX_BODY_BYTES` in
# `aggregator/lib/ingest.ts`, which is `MAX_ROWS_PER_BATCH * MAX_ROW_BYTES`.
#
# It is repeated here, and kept in agreement by a test, because of WHERE the two
# copies are read. The aggregator's copy lives in a TypeScript docstring on a
# different host, published on a different cycle; the operator of THIS machine
# will never open it. But this machine is where the symptom shows: `audit_log`
# stops moving and `ship:lag` grows without bound.
#
# The cause the number explains: `params` and `detail` are unbounded in the
# source table, so ONE audit row larger than this ceiling can never be shipped.
# The batch containing it is refused with 413, the cursor never gets past it, and
# nothing on this host can fix it — deliberately. Bounding row size at the sender
# would give code on the monitored machine a say in which parts of its own
# history are allowed to leave, which is the property the whole design refuses.
# The unblocking is done on the aggregator, by raising its ceiling.
AGGREGATOR_MAX_BODY_BYTES = 8_192_000


async def check_ship_lag(db: Database, cfg: Config) -> list[CheckResult]:
    """Is what leaves this host for the aggregator keeping up with what it writes?

    The shipper has no alerting path of its own, on purpose: a component that
    reports its own failure through the channel it might have broken is the
    pattern this package exists to remove. So the escalation is here, and it
    reaches the operator through `/dashboard` on Telegram like everything else.

    Four states, and collapsing any pair of them is how a monitoring tool lies:

    * **not configured** — `ship.enabled` is false. Nothing is wrong; the
      aggregator does not exist yet. `ok`, and said out loud rather than by
      omitting the key, so `/selfcheck` shows shipping is off instead of leaving
      the operator to infer it from a blank space.
    * **configured and current** — the cursor is at the head of the stream.
    * **configured and behind** — rows are waiting. `degraded` at worst, never
      `down`: nothing on this host has stopped. Collection, detection and
      blocking carry on; what is broken is the copy held somewhere else. "🔴
      SENTINEL NU FUNCȚIONEAZĂ COMPLET" has to keep meaning *nobody is watching
      this server*.
    * **cannot tell** — the cursor table or the stream could not be read. That
      is `unknown`, and it is emitted rather than skipped: the runner reconciles
      state against the keys a run emits, so falling silent here would delete a
      real, unfixed backlog finding and show the operator a recovery that never
      happened. It is emitted **per stream**, which is the repair of 16 August
      2026: one unreadable stream used to raise out of `shipper.lag` and collapse
      the whole check to a single `ship:lag` key, so the append-only stream —
      which needs neither the trigger nor `cursor_at` — vanished from the panel
      because the mutable one could not be read. Measured on the production host
      (schema_version=22, migration 0023 not applied): the only key emitted was
      `ship:lag`, and `ship:lag:audit_log` was reconciled away. A guard hiding
      another guard.

    A fifth case sits inside "behind" and is the one that catches a shipper
    nobody started: configured, but no cursor has ever been written. That is not
    "current" — it is "the queue has never been read".

    A sixth belongs only to streams whose cursor is `(updated_at, id)`, and it is
    the one that would otherwise be read as health: **the server clock went
    backwards past the stream's watermark.** Rows touched from then on get an
    `updated_at` below it and are never selected again, so `pending` counts zero
    and the stream looks current — permanently, while everything that changes on
    the host is lost. It is judged BEFORE `pending` for exactly that reason. Its
    action is `timedatectl`, not `journalctl`: nothing about the aggregator is
    wrong. See the head of `sentinel/report/shipper.py` for why the watermark is
    not rewound automatically.

    Every branch returns exactly one key per stream and never an empty list. An
    empty list is not a state; it is the absence of one, and on a complete run
    the reconciler deletes what was not emitted — so the check would vanish from
    the panel rather than say anything. See the `if not lags` branch below.
    """
    from sentinel.report import shipper

    if not cfg.ship.enabled:
        return [CheckResult(
            "ship:lag", "Expedierea către agregator", "ok",
            detail="oprită în configurație (ship.enabled: false)",
            facts={"configured": False})]

    # Enabled but unusable is its own state, and it is invisible from outside:
    # the service logs one line and exits 0, so the unit is `inactive` and looks
    # like a component that was never turned on.
    if not cfg.ship.url:
        return [CheckResult(
            "ship:lag", "Expedierea e pornită dar nu are destinație", "degraded",
            detail="ship.enabled este true, iar ship.url e gol — nu pleacă nimic",
            action="Completează ship.url în /etc/sentinel/sentinel.yaml, apoi "
                   "systemctl restart sentinel-shipper")]
    try:
        from sentinel.config import get_secrets

        has_secret = get_secrets().has(shipper.SECRET_NAME)
    except Exception as exc:  # noqa: BLE001
        return [CheckResult(
            "ship:lag", "Nu pot citi cheia de expediere", "unknown",
            detail=f"{shipper.SECRET_NAME} nu s-a putut citi: {str(exc)[:140]}",
            action="ls -l /etc/sentinel/secrets.env")]
    if not has_secret:
        return [CheckResult(
            "ship:lag", "Expedierea e pornită dar nu are cheie", "degraded",
            detail=f"ship.enabled este true, iar {shipper.SECRET_NAME} lipsește "
                   f"din secrets.env — expeditorul iese curat și nu trimite nimic",
            action=f"Adaugă {shipper.SECRET_NAME} în /etc/sentinel/secrets.env "
                   f"(aceeași valoare la agregator), apoi "
                   f"systemctl restart sentinel-shipper")]

    try:
        lags = await shipper.lag(db)
    except Exception as exc:  # noqa: BLE001
        return [CheckResult(
            "ship:lag", "Nu pot spune cât a rămas în urmă expedierea", "unknown",
            detail=f"cursoarele ship:* nu s-au putut citi: {str(exc)[:140]}",
            action="sentinel migrate ; journalctl -u sentinel-shipper -n 50")]

    # An empty list is not "nothing is wrong" — it is "this check produced no
    # keys", and on a complete run `_reconcile_state` deletes every row it did
    # not emit. Shipping enabled with no streams to ship would therefore make
    # the whole check DISAPPEAR from `/selfcheck` rather than go red. It cannot
    # happen while `STREAMS` is a non-empty module constant; it becomes
    # reachable the moment E3 gates streams on configuration, and the failure it
    # would produce then is silent by construction.
    if not lags:
        return [CheckResult(
            "ship:lag", "Expedierea e pornită dar nu are niciun flux", "unknown",
            detail="ship.enabled este true, iar shipper.STREAMS e gol — nu există "
                   "cursor de citit, deci nu se poate spune nici „la zi”, nici "
                   "„în urmă”",
            action="journalctl -u sentinel-shipper -n 50")]

    results: list[CheckResult] = []
    for item in lags:
        title = f"Expedierea fluxului „{item.stream}”"
        # The floor is permanent and belongs in every message about this stream:
        # it is the one fact that says some rows will never arrive, and a fact
        # that lives only in a log line written months ago is a fact nobody has.
        floor_note = ""
        if item.floor:
            floor_note = (f" · intrările până la id {item.floor} sunt dinaintea "
                          f"pornirii expedierii și nu vor pleca niciodată")
        elif item.floor_at:
            floor_note = (f" · rândurile neatinse de dinainte de "
                          f"{item.floor_at:%Y-%m-%d %H:%M} sunt dinaintea pornirii "
                          f"expedierii și nu vor pleca niciodată")
        if item.lost_below_cursor:
            # Aceeași alegere ca la prag, și din același motiv: e o pierdere
            # definitivă și DEJA întâmplată. Ca stare roșie permanentă ar fi o
            # cheie care nu se mai stinge niciodată, adică una peste care se
            # învață să se treacă; ca notă, rămâne citibilă luni mai târziu.
            # Alarma propriu-zisă e linia de ERROR din clipa constatării.
            floor_note += (f" · {item.lost_below_cursor} rânduri au apărut sub "
                           f"filigran după ce a trecut peste ele (tranzacție de "
                           f"scriere mai lungă decât fereastra de siguranță) și "
                           f"nu vor pleca niciodată")

        # ÎNAINTEA tuturor, fiindcă e singura care spune „nu m-am putut uita".
        # Un flux ilizibil e o stare a FLUXULUI, nu a verificării: cât timp
        # `shipper.lag` ridica, un `incidents` necitibil — pe gazda de producție,
        # cu 0023 neaplicată, chiar asta se întâmplă — ducea tot `check_ship_lag`
        # în ramura de mai sus, care întoarce O SINGURĂ cheie. Runner-ul șterge
        # ce o rulare completă n-a emis, deci `ship:lag:audit_log` dispărea din
        # panou: fluxul append-only devenea invizibil fiindcă vecinul mutabil nu
        # s-a putut citi. Aici fiecare flux răspunde numai pentru el.
        if item.error:
            # ALTĂ cheie decât `ship:lag:<flux>`, și nu din gust. `bad` e fals
            # pentru `unknown`, iar runner-ul numește „revenit" orice cheie care
            # era `degraded` și nu mai e `bad`. Sub aceeași cheie, o restanță
            # reală care devine necitibilă ar fi anunțată operatorului ca 🟢
            # revenire, iar restanța ar rămâne acolo, nevăzută, cât timp baza nu
            # se repară. Cu cheia asta separată, cea veche nu mai e emisă, deci
            # dispariția ei se anunță ca RETRAGERE — „Nu se mai raportează" —,
            # care e adevărul.
            results.append(CheckResult(
                f"ship:lag:{item.stream}:unreadable",
                f"{title} nu se poate măsura", "unknown",
                detail=f"restanța fluxului „{item.stream}” nu s-a putut citi: "
                       f"{item.error}. Nu înseamnă „la zi” și nu înseamnă „în "
                       f"urmă” — înseamnă că întrebarea n-a primit răspuns",
                action="sentinel migrate  (o coloană sau o tabelă lipsă din "
                       "mesaj vine dintr-o migrație neaplicată) ; apoi "
                       "journalctl -u sentinel-shipper -n 50",
                facts={"stream": item.stream}))
            continue

        # Prima constatare de STARE, înaintea cursorului și a ceasului. Fără
        # triggerul care mișcă `updated_at`, un
        # flux mutabil e mort și arată perfect sănătos: cursorul e scris, ceasul
        # e bun, restanța e zero, fiindcă niciun rând nu-și mai schimbă momentul.
        # Un fișier de migrație pe disc nu e dovadă că nucleul l-a acceptat —
        # întrebarea se pune lui `pg_trigger`, la fiecare rulare.
        if item.updated_at_trigger is False:
            results.append(CheckResult(
                f"ship:lag:{item.stream}",
                f"{title} nu are filigran întreținut", "degraded",
                detail=f"coloana care ține filigranul fluxului „{item.stream}” nu "
                       f"e actualizată de niciun trigger activ, deci un rând "
                       f"schimbat își păstrează momentul vechi și nu mai e "
                       f"expediat niciodată. Fluxul e oprit — altfel ar fi părut "
                       f"la zi la fiecare rulare",
                action="sentinel migrate ; apoi verifică efectul, nu fișierul: "
                       "sudo -u postgres psql sentinel -c \"SELECT tgname, "
                       "tgenabled FROM pg_trigger WHERE NOT tgisinternal AND "
                       "tgfoid = to_regproc('set_updated_at')\"",
                # Fără `cursor`, dinadins: de când măsurătoarea se oprește pe
                # trigger, cursorul nu mai e citit, iar un `None` publicat aici
                # ar fi citit ca „expeditorul n-a scris niciodată nimic" — un
                # „neîntrebat" travestit în stare.
                facts={"updated_at_trigger": False}))
            continue

        if item.cursor is None:
            results.append(CheckResult(
                f"ship:lag:{item.stream}", f"{title} nu a început", "degraded",
                detail="configurată, dar expeditorul nu a scris niciodată un "
                       "cursor — nimic nu a plecat de pe gazda asta",
                action="systemctl status sentinel-shipper ; "
                       "journalctl -u sentinel-shipper -n 50",
                facts={"configured": True, "cursor": None}))
            continue

        # ÎNAINTE de `pending`, și asta e tot rostul ramurii. Un flux al cărui
        # filigran a rămas în viitorul ceasului nu numără nimic ca restanță —
        # rândurile atinse de atunci încoace au un `updated_at` mai mic decât el
        # și nu intră în interogare. Judecat pe `pending`, fluxul apare „la zi",
        # verde, la nesfârșit, în timp ce tot ce se schimbă pe gazdă se pierde.
        # Cele două nu au voie să arate la fel; vezi capul lui
        # sentinel/report/shipper.py.
        if item.clock_ahead_s is not None and item.clock_ahead_s > 0:
            results.append(CheckResult(
                f"ship:lag:{item.stream}",
                f"{title} e oprită de ceasul serverului", "degraded",
                detail=f"filigranul e cu {int(item.clock_ahead_s)} s înaintea "
                       f"ceasului bazei — ceasul a mers înapoi. Până când timpul "
                       f"real ajunge din urmă filigranul nu pleacă nimic din "
                       f"fluxul ăsta, iar ce se schimbă între timp nu va fi "
                       f"expediat niciodată{floor_note}",
                action="timedatectl status ; chronyc tracking — repară sursa de "
                       "timp. Filigranul NU se retrage singur: pe un ceas care "
                       "oscilează ar retrimite aceeași fereastră la fiecare "
                       "rundă, la nesfârșit. Retragerea lui e o decizie de "
                       "operator: docs/OPERARE.md, „Expedierea s-a oprit din "
                       "cauza ceasului”",
                facts={"cursor": item.cursor,
                       "clock_ahead_s": int(item.clock_ahead_s),
                       "lost_below_cursor": item.lost_below_cursor}))
            continue

        # --- Detector de înțepenire, separat de vârstă -----------------------
        # „A rămas în urmă" (vârsta, mai jos) și „nu mai înaintează" (aici) sunt
        # diagnostice diferite, duc la acțiuni diferite, deci au chei diferite.
        # Pana reală din care s-a cerut asta nu era o restanță care se recuperează
        # — cursorul NU avansa deloc. Pentru genul ăsta, a aștepta pragul de vârstă
        # (6h pentru `session_commands`) ar fi greșit: înțepenirea se prinde în
        # câteva minute.
        #
        # Semnalul e VALOAREA cursorului între rulări (vezi
        # `STALL_RUNS_BEFORE_FINDING`), nu ora vreunei scrieri: `updated_at` e pus
        # necondiționat la fiecare upsert al expeditorului, deci un detector pe el
        # n-ar deosebi o înțepenire de munca normală. Starea între rulări stă în
        # `collector_cursors`, sub cheia `ship:<flux>:stall`, cu aceeași disciplină
        # ca celelalte cursoare: `cursor` ține ultima valoare văzută, `events_seen`
        # numărul de priviri anterioare consecutive la aceeași valoare. Ambele
        # coloane există din 0010, deci detectorul merge și pe schema veche (0023
        # neaplicată), acolo unde un flux mutabil oricum iese pe ramura `error` de
        # mai sus și nu ajunge aici.
        stall_key = f"ship:{item.stream}:stall"
        prev_stall = await db.fetchrow(
            "SELECT cursor, events_seen FROM collector_cursors WHERE name = $1",
            stall_key)
        cursor_repr = str(item.cursor)
        if (prev_stall is None or str(prev_stall["cursor"]) != cursor_repr
                or not item.pending):
            # Cursorul a înaintat (valoare nouă sau prima privire), ori nu mai e
            # nimic în așteptare — în ambele cazuri fluxul NU e înțepenit, deci
            # contorul revine la zero. Un flux fără rânduri în așteptare e la zi,
            # nu blocat: cursorul e la cap, n-are ce înainta.
            prior_frozen_looks = 0
        else:
            # Aceeași valoare, cu rânduri în așteptare: încă o privire consecutivă
            # în care nu s-a mișcat.
            prior_frozen_looks = int(prev_stall["events_seen"] or 0) + 1
        await db.execute(
            """
            INSERT INTO collector_cursors (name, cursor, events_seen, updated_at)
            VALUES ($1, $2::text, $3::bigint, now())
            ON CONFLICT (name) DO UPDATE
                SET cursor = $2::text,
                    events_seen = $3::bigint,
                    updated_at = now()
            """,
            stall_key, cursor_repr, prior_frozen_looks)

        # Privirea curentă e a `prior_frozen_looks + 1`-a la aceeași valoare. La a
        # treia (prag), fluxul e înțepenit. `degraded`, NU `down`, dinadins și în
        # ciuda faptului că e mai grav decât o restanță: `runner._announce` ridică
        # la `critical` — care trece de mute — exact când un rezultat e `down`, iar
        # regula întregii verificări (vezi docstring) e că „🔴 SENTINEL NU
        # FUNCȚIONEAZĂ COMPLET" înseamnă „nimeni nu se uită la gazdă". O expediere
        # înțepenită nu e asta: pe gazdă totul funcționează, doar copia din afară
        # nu mai crește. Gravitatea suplimentară o poartă cheia și titlul distinct
        # („s-a înțepenit" vs „a rămas în urmă") și prinderea în minute, nu status-ul.
        if item.pending and prior_frozen_looks + 1 >= STALL_RUNS_BEFORE_FINDING:
            results.append(CheckResult(
                f"ship:lag:{item.stream}:stall",
                f"{title} s-a înțepenit", "degraded",
                detail=f"cursorul fluxului „{item.stream}” a rămas la valoarea "
                       f"{item.cursor} în {prior_frozen_looks + 1} rulări la rând, "
                       f"deși {item.pending} rânduri așteaptă — nu rămâne în urmă, "
                       f"nu mai înaintează deloc. Copia din afara gazdei e oprită "
                       f"pe loc, iar restanța nu se va recupera singură{floor_note}",
                action="journalctl -u sentinel-shipper -n 50  (un cursor blocat "
                       "înseamnă că fiecare lot e refuzat sau că un singur rând nu "
                       "poate pleca: caută „HTTP 413” — lot peste plafonul "
                       f"agregatorului de {AGGREGATOR_MAX_BODY_BYTES} octeți, „200 "
                       "fără ecou” — cerere care nu ajunge la agregator, ori „cannot "
                       "encode a row” — un rând pe care expeditorul nu-l poate "
                       "codifica îi blochează fluxul pe loc)",
                facts={"cursor": item.cursor, "pending": item.pending,
                       "stall_runs": prior_frozen_looks + 1,
                       "lost_below_cursor": item.lost_below_cursor}))
            continue

        # Pragul de vârstă, pe flux: fluxul enumerat în hartă își primește pragul
        # lui, restul rămân la `SHIP_LAG_GRACE_MIN`. Podeaua de trei runde ține în
        # picioare pentru un operator care setează un `interval_s` lung — un prag
        # care se aprinde între două trimiteri normale e unul peste care se învață
        # să se treacă.
        grace_min = max(SHIP_LAG_GRACE_MIN_BY_STREAM.get(item.stream,
                                                         SHIP_LAG_GRACE_MIN),
                        3 * cfg.ship.interval_s / 60)

        if not item.pending:
            results.append(CheckResult(
                f"ship:lag:{item.stream}", title, "ok",
                detail=f"la zi, până la id {item.cursor}{floor_note}",
                facts={"cursor": item.cursor, "pending": 0, "floor": item.floor,
                       "lost_below_cursor": item.lost_below_cursor}))
            continue

        minutes = item.oldest_pending_min or 0.0
        if minutes <= grace_min:
            # A backlog younger than the grace window is the normal state
            # between two rounds, not a fault. Calling it one would fire on
            # every busy minute and train the operator to ignore the key.
            results.append(CheckResult(
                f"ship:lag:{item.stream}", title, "ok",
                detail=f"{item.pending} rânduri în curs de expediere, cel mai "
                       f"vechi de {_ago(minutes)}{floor_note}",
                facts={"cursor": item.cursor, "pending": item.pending,
                       "lost_below_cursor": item.lost_below_cursor}))
            continue

        results.append(CheckResult(
            f"ship:lag:{item.stream}", f"{title} a rămas în urmă", "degraded",
            detail=f"{item.pending} rânduri neexpediate, cel mai vechi de "
                   f"{_ago(minutes)} — pe gazdă nu s-a oprit nimic, dar copia "
                   f"din afara ei nu mai e completă{floor_note}",
            # `batch_streams` e numit AICI fiindcă întrebarea operatorului e „al
            # cui rând a produs asta", iar cheia roșie e a fluxului rămas în urmă
            # — adică a efectului. Fluxurile scadente pleacă într-un lot comun,
            # deci un refuz al lotului oprește și fluxuri care n-au nicio vină, și
            # un remediu care numește doar `params`/`detail` din audit ar trimite
            # operatorul să caute în tabela greșită. Ce NU se mai întâmplă de la
            # backoff-ul pe flux încoace: un flux oprit (ceas, trigger, rând
            # necodificabil) nu mai contribuie cu rânduri la lot și nu mai
            # încetinește pe nimeni — de-aia lista de cauze de mai jos e scurtă.
            action="journalctl -u sentinel-shipper -n 50  (caută „200 fără ecou” "
                   "— un cursor care nu avansează la un răspuns 200 înseamnă că "
                   "cererea nu ajunge la agregator; caută și „HTTP 413”, care "
                   f"înseamnă lot peste plafonul agregatorului de "
                   f"{AGGREGATOR_MAX_BODY_BYTES} octeți. Lotul e COMUN mai multor "
                   f"fluxuri, iar câmpul `batch_streams` din aceeași linie spune "
                   f"care erau în el și cu câte rânduri — cauza poate fi rândurile "
                   f"altui flux decât „{item.stream}”. Un SINGUR rând mai mare de "
                   "atât — un `params`, un `detail` sau un `summary` uriaș — nu "
                   "poate pleca niciodată, cursorul rămâne blocat în fața lui, "
                   "iar restanța crește la nesfârșit. Nu se repară de pe gazda "
                   "asta, dinadins: plafonul se ridică pe agregator. Caută în "
                   "sfârșit „cannot encode a row”: un rând pe care expeditorul "
                   "nu-l poate codifica îi blochează fluxul pe loc, iar `detail` "
                   "numește coloana — asta nu ține de agregator deloc)",
            facts={"cursor": item.cursor, "pending": item.pending,
                   "oldest_min": int(minutes),
                   "lost_below_cursor": item.lost_below_cursor}))
    return results


async def check_beacon_delivery(db: Database, cfg: Config) -> list[CheckResult]:
    """Is the witness outside this host actually ACCEPTING what we send it?

    Its own check rather than a branch of `ship:lag`, and the reason is not
    tidiness. `ship:lag` answers "how far behind is the copy of my rows", from a
    cursor that only ever moves on a receipt the aggregator echoes back. The
    beacon has no cursor of that kind and no backlog: every round is complete or
    lost, and the question is binary — did the far end take it. Folded into one
    key the two would share a title, a grace window and a status, and the
    operator would read "expedierea a rămas în urmă" for a heartbeat that is
    being refused. They also fail independently: shipping and beaconing are
    separate units with separate keys, and the whole point of the beacon being
    its own service is that a bug in the shipper is not a heartbeat outage.

    The property this exists to cover: **"I send, and I am refused every single
    time" may not look like "everything is fine".**

    Until 15 August 2026 it did. `send_once` reports a rejection only in the log
    — deliberately, because an alert about the witness must not travel through
    the channel that might be broken — and delegated the alerting here, where
    nothing about the beacon was checked beyond `check_units` seeing the unit
    `active`. It stays `active` while every beat is refused. At the other end,
    an instance that has NEVER been accepted sits in `no-beat`, which is never
    counted and never alerted, on purpose, so that a key left behind in the
    configuration cannot hold the panel red forever. Measured with
    `beacon.max_age_s: 100000` on a fresh install: beat → 400, `/status` → 200
    "ok", and not one surface said otherwise.

    So the states, and none of them collapsed into another:

    * **not configured** — `beacon.enabled` false. `ok`, said out loud rather
      than by omitting the key, because the runner deletes what a complete run
      did not emit and a missing key reads as a withdrawn finding.
    * **configured but unusable** — no url, or no `SENTINEL_BEACON_SECRET`.
      `run_forever` logs one line and returns, so the unit exits and looks like
      one nobody started. `degraded`.
    * **nothing recorded yet** — no round has written an outcome. That is
      `unknown`, not `ok` and not `degraded`: right after a deploy it is true of
      every healthy host, and it clears within one `interval_s`. A beacon that
      was never started lands here too, and `check_units` is the check that
      calls that one — enabled unit, not active.
    * **never accepted** — rounds have run and not one was taken. `degraded`
      once the refusals pass the threshold below, and `degraded` as well once
      the trace itself goes stale, however few the refusals. Below both, this is
      `unknown` — a startup in progress — and **never `ok`**. Nothing has ever
      been accepted, so there is no fact that supports "fine", and an `ok` here
      is an absorbing state rather than a transient one: it does not clear the
      way the branch above does. That version shipped and is what F1 was.
    * **accepted, but not lately** — this covers both "it stopped being
      accepted" and "the sender died", which the refusal counter alone cannot
      see: a process that is gone stops refusing too.
    * **cannot tell** — the cursors could not be read. `unknown`, emitted, never
      skipped.

    Only one branch says `ok` about a configured beacon, and it is the one that
    has a recent, real acceptance behind it.

    `degraded`, never `down`, for the same reason as `ship:lag`: nothing on this
    host has stopped. "🔴 SENTINEL NU FUNCȚIONEAZĂ COMPLET" has to keep meaning
    *nobody is watching this server*.
    """
    from sentinel.report import beacon

    if not cfg.beacon.enabled:
        return [CheckResult(
            "beacon:delivery", "Semnalul către martorul extern", "ok",
            detail="oprit în configurație (beacon.enabled: false)",
            facts={"configured": False})]

    if not cfg.beacon.url:
        return [CheckResult(
            "beacon:delivery", "Semnalul e pornit dar nu are destinație", "degraded",
            detail="beacon.enabled este true, iar beacon.url e gol — nu pleacă nimic",
            action="Completează beacon.url în /etc/sentinel/sentinel.yaml, apoi "
                   "systemctl restart sentinel-beacon")]

    try:
        from sentinel.config import get_secrets

        has_secret = get_secrets().has(beacon.SECRET_NAME)
    except Exception as exc:  # noqa: BLE001
        return [CheckResult(
            "beacon:delivery", "Nu pot citi cheia semnalului", "unknown",
            detail=f"{beacon.SECRET_NAME} nu s-a putut citi: {str(exc)[:140]}",
            action="ls -l /etc/sentinel/secrets.env")]
    if not has_secret:
        return [CheckResult(
            "beacon:delivery", "Semnalul e pornit dar nu are cheie", "degraded",
            detail=f"beacon.enabled este true, iar {beacon.SECRET_NAME} lipsește "
                   f"din secrets.env — expeditorul iese curat și nu trimite nimic",
            action=f"Adaugă {beacon.SECRET_NAME} în /etc/sentinel/secrets.env "
                   f"(aceeași valoare la martor), apoi "
                   f"systemctl restart sentinel-beacon")]

    # Vârsta se calculează în baza de date, ca la `check_ingest_sources`: ceasul
    # gazdei și cel al bazei pot diferi, iar diferența ar apărea aici ca o
    # vechime inventată.
    async def marker(name: str) -> Any:
        return await db.fetchrow(
            "SELECT cursor, EXTRACT(EPOCH FROM (now() - updated_at))/60 AS minute "
            "FROM collector_cursors WHERE name = $1", name)

    try:
        delivered = await marker(beacon.DELIVERED_KEY)
        refused = await marker(beacon.REFUSED_KEY)
    except Exception as exc:  # noqa: BLE001
        return [CheckResult(
            "beacon:delivery", "Nu pot spune dacă martorul primește semnalul", "unknown",
            detail=f"urmele beacon:* nu s-au putut citi: {str(exc)[:140]}",
            action="sentinel migrate ; journalctl -u sentinel-beacon -n 50")]

    refusals = int(refused["cursor"] or 0) if refused else 0
    # Cel puțin trei runde, ca la `ship:lag`: un prag care se aprinde în
    # funcționare normală e unul peste care operatorul învață să treacă.
    grace_min = max(BEACON_DELIVERY_GRACE_MIN, 3 * cfg.beacon.interval_s / 60)

    if delivered is None and refused is None:
        # Nicio rundă n-a lăsat urmă. Adevărat despre orice gazdă sănătoasă în
        # primul minut de după un deploy, deci `unknown` — care se vede în titlul
        # lui /selfcheck și nu sună. Cazul „unitatea nu a fost pornită deloc" e
        # al lui `check_units`, care are faptul potrivit pentru el.
        return [CheckResult(
            "beacon:delivery", "Nu știu încă dacă martorul primește semnalul", "unknown",
            detail="expeditorul nu a raportat încă rezultatul niciunei runde — "
                   "normal în primul interval de după o instalare sau un deploy",
            action="systemctl status sentinel-beacon ; "
                   "journalctl -u sentinel-beacon -n 50",
            facts={"delivered": False, "refusals": refusals})]

    if delivered is None:
        # **`ok` nu e o valoare posibilă pe ramura asta.** Nimic nu a fost
        # acceptat vreodată, deci nu există niciun fapt care să susțină „totul e
        # în regulă" — iar prima variantă a verificării ăsteia îl întorcea
        # oricum, cât timp contorul de refuzuri stătea sub prag. Măsurat de
        # verificator pe 15 august 2026, condus prin codul livrat: „niciodată
        # acceptat, 2 refuzuri, ultima urmă acum UN AN" → `ok`. Adică exact bucla
        # pe care verificarea a fost scrisă s-o rupă: unitatea rămâne `active`
        # deci `check_units` tace, martorul ține instanța în `no-beat` care prin
        # proiectare nu alarmează, iar aici era verde. Toate suprafețele spuneau
        # că e bine.
        #
        # Cauza nu era pragul, ci că ramura arunca vechimea pe care interogarea o
        # aducea oricum: fără ea, `ok` sub prag e o stare ABSORBANTĂ, nu una
        # trecătoare. Ramura „încă nicio urmă" de mai sus se limpezește într-un
        # `interval_s`; asta nu se limpezea niciodată.
        minutes = float(refused["minute"] or 0.0)
        if refusals >= BEACON_REFUSALS_BEFORE_FINDING:
            # Cazul pentru care există verificarea: gazda trimite, martorul
            # refuză de fiecare dată, și pe partea LUI instanța e `no-beat` —
            # care nu se numără și nu alarmează niciodată.
            return [CheckResult(
                "beacon:delivery", "Martorul nu a acceptat NICIO bătaie", "degraded",
                detail=f"{refusals} runde la rând refuzate și niciuna acceptată "
                       f"vreodată — la martor instanța asta apare „no-beat”, stare "
                       f"care nu se numără și nu alertează, deci tăcerea de aici nu "
                       f"e văzută de nimeni",
                action="journalctl -u sentinel-beacon -n 50  (linia „beacon rejected” "
                       "poartă codul și primii 200 de octeți ai corpului, iar corpul "
                       "numește câmpul greșit; un 401 înseamnă cheie sau identitate, "
                       "un 400 înseamnă payload)",
                facts={"delivered": False, "refusals": refusals})]
        if minutes > grace_min:
            # Sub prag, dar urma a înghețat: expeditorul a făcut o rundă-două și
            # a încetat să mai completeze vreuna — proces blocat, sau scrierea
            # urmei care eșuează la nesfârșit (`_record_delivery` înghite orice
            # excepție, prin proiectare). Numărul mic de refuzuri nu e o dovadă
            # de sănătate, e chiar simptomul.
            return [CheckResult(
                "beacon:delivery", "Expeditorul nu mai raportează, și nu a fost "
                                   "acceptat niciodată", "degraded",
                detail=f"nicio bătaie acceptată vreodată, iar ultima rundă care a "
                       f"raportat ceva a fost acum {_ago(minutes)} ({refusals} "
                       f"refuzate) — unitatea poate fi în continuare `active`, dar "
                       f"nu mai iese nimic pe fir",
                action="systemctl status sentinel-beacon ; "
                       "journalctl -u sentinel-beacon -n 50",
                facts={"delivered": False, "refusals": refusals,
                       "minutes": int(minutes)})]
        return [CheckResult(
            "beacon:delivery", "Nu știu încă dacă martorul primește semnalul", "unknown",
            detail=f"încă nicio bătaie acceptată, {refusals} rundă/runde refuzate "
                   f"acum {_ago(minutes)} — sub pragul de "
                   f"{BEACON_REFUSALS_BEFORE_FINDING} și proaspăt, deci o pornire "
                   f"în curs; nu e o afirmație că merge",
            action="journalctl -u sentinel-beacon -n 50",
            facts={"delivered": False, "refusals": refusals,
                   "minutes": int(minutes)})]

    minutes = float(delivered["minute"] or 0.0)
    last_seq = str(delivered["cursor"] or "?")

    if minutes <= grace_min:
        return [CheckResult(
            "beacon:delivery", "Semnalul către martorul extern", "ok",
            detail=f"ultima bătaie acceptată acum {_ago(minutes)} (seq {last_seq})",
            facts={"delivered": True, "refusals": refusals, "seq": last_seq})]

    if refusals:
        detail = (f"ultima bătaie acceptată acum {_ago(minutes)} (seq {last_seq}), "
                  f"iar de atunci {refusals} runde la rând au fost refuzate")
    else:
        # Nici acceptat, nici refuzat: expeditorul nu mai raportează nimic, deci
        # nu mai rulează. `check_units` vede unitatea; asta vede efectul.
        detail = (f"ultima bătaie acceptată acum {_ago(minutes)} (seq {last_seq}), "
                  f"iar de atunci nicio rundă nu a mai raportat vreun rezultat — "
                  f"expeditorul nu mai rulează")
    return [CheckResult(
        "beacon:delivery", "Martorul nu mai acceptă semnalul", "degraded",
        detail=detail,
        action="journalctl -u sentinel-beacon -n 50 ; "
               "systemctl status sentinel-beacon",
        facts={"delivered": True, "refusals": refusals, "seq": last_seq,
               "minutes": int(minutes)})]


# ---------------------------------------------------------------------------
# Filtrul de istoric de sesiune: „configurat" și „în vigoare" sunt afirmații
# diferite, iar verdictul pleacă de la DATE, nu de la configurație
# ---------------------------------------------------------------------------
#: Peste câte ore înapoi se uită autodiagnosticul filtrului de istoric.
#:
#: Un deploy nu rulează zilnic, deci fereastra e destul de largă cât să prindă
#: unul, și destul de scurtă cât interogarea să meargă pe indexul
#: `session_commands_user_idx (username, ts DESC)` în loc să scaneze o tabelă de
#: milioane de rânduri la fiecare trecere.
HISTORY_WINDOW_H = 48

#: Peste ce ritm pe oră o serie de comenzi fără terminal e automatizare, nu om.
#:
#: Ales ca media geometrică între cea mai săracă oră de deploy măsurată pe gazdă
#: (174 839) și cea mai bogată oră de muncă omenească măsurată (2 438), tocmai ca
#: granița să cadă între ele: sub prag rămâne diagnosticul de la distanță al
#: operatorului, peste prag rafala unei automatizări.
HISTORY_STORM_PER_H = 20_000

#: Câte comenzi trage felia înainte de a le grupa pe oră. Mult mai mare decât
#: pragul, fiindcă ORA se numără din chiar felia asta: o furtună tăiată de granița
#: dintre două ore ar sta sub prag în amândouă gălețile, adică cea mai violentă ar
#: fi cea mai ușor de ratat. Mărginită dinadins — interogarea rulează la 5 minute
#: pe o tabelă de milioane de rânduri.
HISTORY_SAMPLE = 60_000

#: Unitatea care încarcă filtrul de istoric. Pornirea ei e cel mai devreme moment
#: în care el putea avea efect: un rând interzis mai vechi decât atât a fost scris
#: de procesul dinainte, nu de filtrul de acum.
INGEST_UNIT = "sentinel-ingest.service"


def _mii(value: float) -> str:
    """Cifră cu spații între mii. Raportul e citit de un om, nu de un script."""
    return f"{value:,.0f}".replace(",", " ")


def _ceas(ts: datetime | None) -> str:
    """Un moment, citit de un om. `None` când nu se cunoaște."""
    if ts is None:
        return "necunoscut"
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class _HistoryTop:
    """Contul cel mai activ fără terminal din felia citită, și ora lui de vârf."""

    username: str
    #: Câte comenzi fără terminal are contul în toată felia.
    fara_terminal: int
    #: Câte are în ORA lui cea mai încărcată. Asta se compară cu pragul.
    per_hour: int
    sampled: int
    span_s: float
    #: Adevărat când felia s-a umplut, adică fereastra e mai lungă decât ce s-a
    #: văzut. Fără el, „n-am văzut nicio furtună" ar suna la fel pe o gazdă
    #: liniștită de 48 de ore și pe una din care s-au citit ultimele 40 de secunde.
    capped: bool

    @property
    def storm(self) -> bool:
        return self.per_hour >= HISTORY_STORM_PER_H


def _history_top(rows: list[Any]) -> _HistoryTop | None:
    """Felia, citită. `None` înseamnă «niciun rând în fereastră», nu «e bine»."""
    randuri = [dict(r) for r in rows]
    if not randuri:
        return None
    sampled = sum(int(r["total"]) for r in randuri)
    momente = [r[c] for r in randuri for c in ("oldest", "newest") if r.get(c)]
    span = (max(momente) - min(momente)).total_seconds() if momente else 0.0

    pe_cont: dict[str, list[int]] = {}
    for r in randuri:
        pe_cont.setdefault(str(r["username"] or ""), []).append(int(r["fara_terminal"]))
    nume, ore = max(pe_cont.items(), key=lambda kv: (max(kv[1]), sum(kv[1])))
    if max(ore) == 0:
        # Toată felia are terminal real: nu există „contul care scrie fără
        # terminal", și asta e chiar starea sănătoasă. Se întoarce oricum, cu
        # zero, ca raportul să poată spune CE a văzut.
        return _HistoryTop("", 0, 0, sampled, span, sampled >= HISTORY_SAMPLE)
    return _HistoryTop(nume, sum(ore), max(ore), sampled, span,
                       sampled >= HISTORY_SAMPLE)


def _history_seen(top: _HistoryTop | None) -> str:
    """Ce s-a văzut, în cuvinte — inclusiv când nu s-a văzut nimic."""
    if top is None:
        return (f"nicio comandă în ultimele {HISTORY_WINDOW_H} de ore, deci n-am "
                f"pe ce mă uita")
    # Când felia s-a umplut, intervalul ACOPERIT e ce s-a văzut cu adevărat, și
    # el se spune: altfel „n-am văzut nicio furtună în 48 de ore" ar fi o
    # afirmație mai tare decât măsurătoarea din spatele ei.
    felie = (f"cele mai recente {_mii(top.sampled)} comenzi, adică ultimele "
             f"{top.span_s / 3600.0:.1f} ore" if top.capped
             else f"toate cele {_mii(top.sampled)} comenzi din ultimele "
                  f"{HISTORY_WINDOW_H} de ore")
    if top.fara_terminal == 0:
        return f"în {felie}, niciuna fără terminal"
    # Formatarea se face pe FIECARE număr, nu pe fraza întreagă: un
    # `.replace(",", " ")` peste tot textul mânca virgulele propoziției.
    return (f"în {felie}, cel mai activ fără terminal e "
            f"„{top.username or '(fără nume)'}” cu {_mii(top.fara_terminal)}, "
            f"din care {_mii(top.per_hour)} în ora lui de vârf")


@dataclass(frozen=True)
class _UnmergedHistory:
    """Ce spune `sentinel.yaml.new` despre filtru, față de ce s-a încărcat.

    Trei stări, fiindcă cer lucruri diferite: nu există `.new` (normal),
    există și nu se poate citi („nu știu"), există și numește alte conturi.
    """

    exists: bool = False
    readable: bool = True
    accounts: tuple[str, ...] = ()
    error: str = ""
    path: str = ""


def _unmerged_history() -> _UnmergedHistory:
    """`sentinel.yaml.new`, citit direct de pe disc.

    `install_config` refuză să suprascrie un `sentinel.yaml` existent: scrie
    `.new` și avertizează. Citit pe gazdă pe 25 august 2026: `sentinel.yaml` din
    20 august și `sentinel.yaml.new` din 25, plus `inventory.yaml.new` — toate
    neîmbinate, deci avertismentul e demonstrat că nu se citește. Fișierul ăsta e
    singurul lucru care deosebește «operatorul a ales să nu arunce nimic» de
    «instalatorul a scris configurația și n-a îmbinat-o nimeni», iar cele două nu
    au voie să arate amândouă a `ok`.

    Ce NU acoperă, spus aici fiindcă e starea gazdei de azi: dacă nici `.new` nu
    are secțiunea — cazul unei gazde pe care codul cu filtrul n-a ajuns încă —,
    cele două fișiere sunt de acord și nu e nimic de raportat. Atunci singurul
    lucru care mai poate spune ceva sunt DATELE, și de aceea ele se întreabă
    primele și necondiționat.
    """
    cale = Path(str(CONFIG_PATH) + ".new")
    if not cale.exists():
        return _UnmergedHistory(path=str(cale))
    try:
        incarcat = yaml.safe_load(cale.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        # Nu „nu e nimic acolo": fișierul EXISTĂ și nu l-am putut citi.
        return _UnmergedHistory(exists=True, readable=False, error=str(exc)[:120],
                                path=str(cale))
    sectiune = (incarcat or {}).get("history") if isinstance(incarcat, dict) else None
    conturi = (sectiune or {}).get("skip_command_accounts") if isinstance(sectiune, dict) else None
    if not isinstance(conturi, list):
        conturi = []
    return _UnmergedHistory(exists=True, readable=True,
                            accounts=tuple(str(c) for c in conturi), path=str(cale))


_HISTORY_TOP_SQL = """
WITH recent AS (
    SELECT username, ts, tty
      FROM session_commands
     WHERE ts > now() - make_interval(hours => $2)
     ORDER BY ts DESC
     LIMIT $1
)
SELECT coalesce(username, '') AS username,
       date_trunc('hour', ts) AS ora,
       count(*) AS total,
       count(*) FILTER (WHERE tty IS NULL OR tty !~ $3) AS fara_terminal,
       min(ts) AS oldest,
       max(ts) AS newest
  FROM recent
 GROUP BY 1, 2
"""


#: Rândurile care, dacă filtrul e în vigoare, NU pot exista.
#:
#: Aceeași regulă ca `is_dropped_command`, scrisă în SQL o singură dată. Nu se
#: întreabă „e filtrul configurat" — asta se citește din configurație și nu
#: dovedește nimic — ci „a scris totuși cineva un rând pe care regula îl
#: interzice". Un rând din ăsta e dovada că între configurație și efect e o
#: prăpastie: secțiunea `history:` nemutată din `sentinel.yaml.new`, sau
#: procesul care încă rulează codul dinaintea livrării.
#:
#: `newest` e `max(ts)` peste RÂNDURILE INTERZISE, nu peste toate: momentul celei
#: mai recente comenzi pe care regula o oprește. E singurul care contează pentru
#: „a fost scris după ce filtrul putea acționa?" — un `max(ts)` peste tot ar
#: aluneca pe o comandă tastată legitim și ar acuza filtrul pentru un rând vechi.
_HISTORY_EFFECT_SQL = """
SELECT count(*) AS total,
       count(*) FILTER (WHERE tty IS NULL OR tty !~ $2) AS interzise,
       max(ts) FILTER (WHERE tty IS NULL OR tty !~ $2) AS newest
  FROM session_commands
 WHERE username = ANY($1::text[])
   AND ts > now() - make_interval(hours => $3)
"""


async def check_command_history_filter(db: Database, cfg: Config) -> list[CheckResult]:
    """Filtrul de istoric: configurat, și chiar în vigoare?

    ## Eșecul pe care îl previne

    `history.skip_command_accounts` oprește scrierea comenzilor fără terminal ale
    conturilor de automatizare — 405 777 de rânduri pentru un singur deploy. Până
    pe 25 august 2026 nimic nu citea cheia înapoi. Verificarea propusă în
    `docs/ISTORIC-SESIUNI.md` era

        journalctl -u sentinel-ingest | grep commands_skipped

    și nu funcționa: `commands_skipped` e mereu în `extra`, iar `JSONFormatter`
    scrie și zerourile, deci grep-ul potrivea ÎNTOTDEAUNA. Nu deosebea «am aruncat
    405 777 de rânduri» de «secțiunea n-a fost îmbinată niciodată» — exact tiparul
    din `CLAUDE.md`: un grep după un tipar care potrivește orice.

    Iar prăpastia e reală, nu ipotetică: `install_config` refuză să suprascrie un
    `sentinel.yaml` existent, scrie `.new` și avertizează. Pe gazdă existau pe 25
    august ȘI `sentinel.yaml.new` ȘI `inventory.yaml.new`, din 20 august,
    neîmbinate — deci avertismentul e demonstrat că nu se citește.

    ## De ce verdictul NU mai pleacă de la configurație

    Prima scriere a verificării ăsteia citea `history.skip_command_accounts` și,
    pe lista goală, ieșea `ok` înainte de orice SQL. Citit prin ssh pe 25 august
    2026: `/etc/sentinel/sentinel.yaml` e din 20 august și NU are secțiunea
    `history:`, iar `sentinel.yaml.new` — din 25 august, scris de instalator și
    neîmbinat — n-o are NICI EL. Filtrul n-a ajuns niciodată pe gazda asta, iar
    contul de deploy scrisese totuși 1 266 de comenzi fără terminal în 48 de ore.
    Verificarea scrisă tocmai ca să deosebească intenția de efect raporta `ok`,
    fiindcă și ea pleca de la intenție — de la o cheie de configurație.

    Acum întâi se întreabă DATELE — *cine scrie comenzi fără terminal, și cu ce
    ritm* —, și abia apoi configurația spune dacă ăla e un cont pe care cineva a
    cerut să-l arunce. Întrebarea aia nu știe nimic despre `deploy.sh`, despre
    `--user` sau despre secțiuni de YAML, deci prinde la fel de bine o invocație
    cu contul vechi, un cont nou apărut și o configurație neîmbinată.

    ## Stările, ținute separate

    * **baza de conturi nu se poate citi** — `unknown`. Fără ea nu se pot afla
      uid-urile, iar rândurile scrise cu `auid` numeric (87 935, măsurat) scapă
      filtrului. „Nu știu" nu e „e în regulă";
    * **un cont configurat care nu există pe gazdă** — `degraded`. Filtrul îl
      compară pe egalitate exactă, deci un nume greșit nu potrivește niciodată
      și nu se plânge niciodată;
    * **rânduri care n-ar fi trebuit scrise** — `degraded`. Faptul, nu intenția;
    * **o furtună de comenzi fără terminal pe un cont din afara filtrului** —
      `degraded`, chiar dacă nu e configurat NIMIC. Ăsta e cazul pe care lista
      goală îl ascundea;
    * **`sentinel.yaml.new` cere un cont pe care configurația ÎNCĂRCATĂ nu-l
      are** — `degraded`. `install_config` nu suprascrie: scrie `.new` și
      avertizează, iar avertismentul e demonstrat că nu se citește. E singurul
      lucru care deosebește «am ales să nu arunc nimic» de «nimeni n-a îmbinat».
      Numai sensul ăsta: încărcată care aruncă MAI MULT decât cere `.new` e o
      alegere a operatorului peste un `.new` rămas în urmă, nu un filtru inert;
    * **`.new` există și nu se poate citi** — `unknown`, din același motiv;
    * **listă goală, nimic în `.new`, nicio furtună** — `ok`, spus explicit ca
      atare: se păstrează fiecare comandă, fiindcă asta s-a cerut.

    Ce NU se poate afirma de aici, și de aceea nu se afirmă: că filtrul a aruncat
    ceva. Zero rânduri interzise într-o fereastră fără niciun deploy arată exact
    ca zero rânduri interzise pe o gazdă care aruncă cum trebuie. Detaliul spune
    care dintre cele două s-a văzut — și cât de departe înapoi s-a putut uita —,
    nu concluzia care sună mai bine.
    """
    nume = list(cfg.history.skip_command_accounts)
    skip = resolve_skip_command_accounts(nume)
    nou = _unmerged_history()
    # Conturile pe care `.new` le cere și configurația ÎNCĂRCATĂ nu le are.
    #
    # Diferența e ORIENTATĂ, nu o egalitate: filtrul inert e un cont cerut de
    # instalator pe care serviciul nu-l aruncă. Celălalt sens — încărcată aruncă
    # mai mult decât cere `.new` — e o alegere a operatorului peste un `.new`
    # rămas în urmă, și e chiar starea de așteptat aici: `sentinel.yaml.new` de pe
    # gazdă e din 25 august 2026 și n-are secțiunea `history:` deloc. Comparate pe
    # egalitate, în clipa în care cineva adaugă contul de mână în `sentinel.yaml`
    # — reacția firească la constatarea de mai jos — verificarea ar rămâne roșie
    # pentru totdeauna, spunând exact pe dos: că filtrul nu e îmbinat, tocmai când
    # el e cel care rulează. O constatare care nu se stinge niciodată e cum ajunge
    # operatorul să nu mai citească niciuna.
    nemutate = sorted(set(nou.accounts) - set(nume)) if nou.exists else []

    # Întrebarea pusă datelor. Prima, și fără nicio condiție: e singura care nu
    # depinde de ce a scris cineva într-un fișier.
    top = _history_top(await db.fetch(_HISTORY_TOP_SQL, HISTORY_SAMPLE,
                                      HISTORY_WINDOW_H, REAL_TTY_SQL))
    vazut = _history_seen(top)

    facts: dict[str, Any] = {
        "configured": nume,
        "matches": sorted(skip.matches),
        "resolved": {n: u for n, u in skip.resolved},
        "unresolved": list(skip.unresolved),
        "window_h": HISTORY_WINDOW_H,
        "sample": HISTORY_SAMPLE,
        "storm_per_h": HISTORY_STORM_PER_H,
        "top_account": top.username if top else "",
        "top_no_tty": top.fara_terminal if top else 0,
        "top_peak_hour": top.per_hour if top else 0,
        "sampled": top.sampled if top else 0,
        "sample_capped": bool(top and top.capped),
        "unmerged_new": nou.exists,
        "unmerged_accounts": list(nou.accounts),
        "unmerged_missing": nemutate,
    }

    if nume and not skip.lookup_ok:
        return [CheckResult(
            "history:filter", "Conturile filtrului nu se pot rezolva", "unknown",
            f"configurate: {', '.join(nume)}. Baza de conturi a gazdei nu se "
            f"poate citi, deci nu știu uid-urile lor. Rândurile scrise cu `auid` "
            f"numeric — 87 935 pe gazdă, măsurat — nu sunt prinse de filtru, iar "
            f"eu nu pot spune câte sunt. Din date: {vazut}",
            facts=facts, action="getent passwd " + " ".join(nume))]

    if skip.unresolved:
        return [CheckResult(
            "history:filter", "Filtrul numește conturi care nu există", "degraded",
            f"„{', '.join(skip.unresolved)}” nu e pe gazda asta. Filtrul compară "
            f"pe egalitate exactă, deci un nume care nu există nu potrivește "
            f"niciodată niciun rând și nu se plânge niciodată — secțiunea arată "
            f"configurată și nu aruncă nimic. Din date: {vazut}",
            facts=facts, action="getent passwd " + " ".join(skip.unresolved))]

    total = interzise = 0
    newest: datetime | None = None
    if nume:
        row = await db.fetchrow(_HISTORY_EFFECT_SQL, sorted(skip.matches),
                                REAL_TTY_SQL, HISTORY_WINDOW_H)
        total = int((row or {}).get("total") or 0)
        interzise = int((row or {}).get("interzise") or 0)
        newest = (row or {}).get("newest")
        facts.update({"rows_seen": total, "rows_forbidden": interzise,
                      "newest_forbidden": newest.isoformat() if newest else None})

    ortografii = ", ".join(sorted(skip.matches))
    if interzise:
        # Un rând interzis dovedește că filtrul e inert DOAR dacă a fost scris după
        # ce filtrul putea acționa. Cel mai devreme moment în care putea acționa e
        # ultima pornire a serviciului de ingestie: ce e mai vechi de atât l-a
        # scris procesul dinainte. Reprodus pe gazdă (2026-08-26): 1 871 de rânduri
        # `sentinel-deploy` fără terminal, TOATE scrise înainte ca filtrul să
        # existe. După ce operatorul adaugă contul și repornește, ele rămân în
        # fereastra de 48h; acuzat pentru ele, panoul devine roșu cu un mesaj care
        # numește două cauze false și o acțiune care nu arată nimic, și îngroapă
        # sub aceeași cheie furtunile adevărate până expiră ultimul rând vechi.
        started = await _service_started_at(INGEST_UNIT)
        facts["ingest_started"] = started.isoformat() if started else None
        if started is None or newest is None:
            # „Nu știu" nu e „e spart": fără momentul pornirii, sau fără o dată a
            # celui mai recent rând, nu pot spune dacă rândurile sunt de dinainte
            # sau de după filtru. Dau faptul pe care operatorul îl poate lega el
            # de momentul îmbinării, și mă opresc din a acuza.
            return [CheckResult(
                "history:filter",
                "Rânduri interzise pe care nu le pot data față de filtru",
                "unknown",
                f"{interzise} comenzi fără terminal ale conturilor {ortografii} "
                f"sunt în ultimele {HISTORY_WINDOW_H} de ore, cea mai recentă la "
                f"{_ceas(newest)}. Nu pot citi când a pornit ultima oară "
                f"`{INGEST_UNIT}` ({_ceas(started)}), deci nu pot spune dacă au "
                f"fost scrise înainte sau după ce filtrul putea acționa. Din "
                f"date: {vazut}",
                facts=facts,
                action=f"systemctl show {INGEST_UNIT} -p ActiveEnterTimestamp")]
        # 5 secunde răgaz: un rând scris chiar în secunda pornirii nu e o dovadă
        # de defect. Același prag ca `check_code_current`, din același motiv.
        if newest > started + timedelta(seconds=5):
            return [CheckResult(
                "history:filter",
                "Filtrul de istoric e configurat, dar nu e în vigoare", "degraded",
                f"{interzise} comenzi fără terminal ale conturilor {ortografii} au "
                f"fost SCRISE în ultimele {HISTORY_WINDOW_H} de ore, cea mai "
                f"recentă la {_ceas(newest)} — DUPĂ ultima pornire a serviciului "
                f"de ingestie ({_ceas(started)}), deci filtrul rula deja când au "
                f"fost scrise. Ori secțiunea `history:` din `sentinel.yaml` nu e "
                f"cea pe care o citește serviciul, ori procesul rulează încă codul "
                f"dinaintea livrării. Din date: {vazut}",
                facts=facts,
                action="systemctl restart sentinel-ingest && journalctl -u "
                       "sentinel-ingest -n 20")]
        # Toate rândurile interzise sunt mai vechi decât ultima pornire a
        # filtrului: le-a scris procesul dinainte. Nu e o acuzație — e data pe care
        # operatorul o leagă de momentul îmbinării. Niciun rând interzis de când
        # rulează filtrul.
        #
        # Dar `ok`-ul ăsta e despre ce-a scris procesul DINAINTE, nu despre ce se
        # scrie ACUM. Dacă în aceeași fereastră un cont din AFARA filtrului scrie în
        # ritm de automatizare, furtuna aia e activă și e dovada mai tare — un
        # deploy care rulează chiar acum pe contul de logare al operatorului e mai
        # urgent decât niște rânduri vechi excusate. N-are voie să stea sub verdele
        # dat pentru rânduri vechi: lăsăm cazul să cadă prin la ramura de furtună de
        # mai jos, care îl descrie corect. Contul CONFIGURAT nu cade prin
        # (`top.username in skip.matches` îl exclude), deci o furtună VECHE pe chiar
        # contul filtrului rămâne `ok` — roșul fals pe care B1 tocmai l-a stins nu
        # reînvie.
        furtuna_din_afara = (top is not None and top.storm
                             and top.username not in skip.matches)
        if not furtuna_din_afara:
            return [CheckResult(
                "history:filter", "Filtrul de istoric", "ok",
                f"conturi {ortografii}; {interzise} comenzi fără terminal ale lor "
                f"sunt încă în fereastra de {HISTORY_WINDOW_H} de ore, dar cea mai "
                f"recentă e la {_ceas(newest)}, ÎNAINTE de ultima pornire a "
                f"serviciului de ingestie ({_ceas(started)}) — le-a scris procesul "
                f"dinaintea filtrului, nu filtrul de acum, și niciun rând interzis "
                f"n-a mai fost scris de când rulează. Din date: {vazut}",
                facts=facts)]

    # Furtuna pe un cont pe care filtrul NU-l cunoaște. Contul din filtru nu poate
    # ajunge aici: rândurile lui ar fi fost numărate de ramura de deasupra, care
    # întreabă chiar despre ele.
    if top is not None and top.storm:
        cunoscut = top.username in skip.matches
        return [CheckResult(
            "history:filter",
            "Comenzi de automatizare scrise pe un cont din afara filtrului"
            if not cunoscut else "Filtrul de istoric nu e în vigoare",
            "degraded",
            f"{vazut}. Peste {_mii(HISTORY_STORM_PER_H)}/h e ritm de automatizare, nu "
            f"de om — pe gazdă, un deploy a scris 405 777 de rânduri în 140 de "
            f"secunde, iar cea mai încărcată oră de muncă omenească măsurată a "
            f"avut 2 438. Contul „{top.username or '(fără nume)'}” "
            + ("e în filtru, deci rândurile astea n-ar fi trebuit scrise"
               if cunoscut else
               f"NU e în `history.skip_command_accounts` "
               f"({', '.join(nume) if nume else 'gol'}), deci nimic nu le oprește"),
            facts=facts,
            action="grep -A3 '^history:' /etc/sentinel/sentinel.yaml*")]

    # Configurația de pe disc, față de cea încărcată. Ultima poartă înainte de
    # `ok`: fără ea, «n-am ales să arunc nimic» și «nimeni n-a îmbinat fișierul»
    # ies amândouă verzi.
    if nou.exists and not nou.readable:
        return [CheckResult(
            "history:filter", "Nu pot citi configurația neîmbinată", "unknown",
            f"`{nou.path}` există și nu se poate citi ({nou.error}), deci nu pot "
            f"spune dacă filtrul încărcat e cel scris de instalator. Din date: "
            f"{vazut}",
            facts=facts, action=f"sudo cat {nou.path}")]

    if nemutate:
        return [CheckResult(
            "history:filter", "Configurația filtrului n-a fost îmbinată", "degraded",
            f"`{nou.path}` cere {', '.join(nou.accounts)}, dar "
            f"{', '.join(nemutate)} nu e în configurația ÎNCĂRCATĂ "
            f"({', '.join(nume) if nume else 'lista goală'}). Instalatorul nu "
            f"suprascrie `sentinel.yaml`: scrie `.new` și avertizează, iar "
            f"avertismentul se pierde între o sută de linii. Din date: {vazut}",
            facts=facts,
            action=f"diff {CONFIG_PATH} {nou.path}")]

    if not nume:
        return [CheckResult(
            "history:filter", "Filtrul de istoric nu aruncă nimic", "ok",
            f"`history.skip_command_accounts` e gol în configurația ÎNCĂRCATĂ, "
            f"deci se păstrează fiecare comandă. E implicitul și e o stare "
            f"validă, iar datele n-o contrazic: {vazut}",
            facts=facts,
            action="grep -A3 '^history:' /etc/sentinel/sentinel.yaml*")]

    if total:
        return [CheckResult(
            "history:filter", "Filtrul de istoric", "ok",
            f"conturi {ortografii}; {total} comenzi ale lor în ultimele "
            f"{HISTORY_WINDOW_H} de ore, TOATE cu terminal real — adică exact "
            f"cele pe care regula le păstrează. Din date: {vazut}",
            facts=facts)]

    return [CheckResult(
        "history:filter", "Filtrul de istoric", "ok",
        f"conturi {ortografii}, rezolvate. Niciun rând al lor în ultimele "
        f"{HISTORY_WINDOW_H} de ore, deci n-am ce observa: asta NU e o dovadă că "
        f"filtrul aruncă, e doar lipsa unei dovezi că nu aruncă",
        facts=facts)]


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
# Scanarea de vulnerabilități: un eșec trebuie să AJUNGĂ la operator
# ---------------------------------------------------------------------------
#: Peste câte ore fără o scanare încheiată recent lista de vulnerabilități e
#: considerată veche. Peste o zi dinadins: scanarea rulează zilnic, deci un prag
#: sub 24 de ore ar aprinde alarma pe fiecare rulare perfect normală întârziată
#: de o gazdă încărcată — iar o alarmă care sună mereu e una peste care operatorul
#: învață să treacă, și atunci n-o mai vede nici pe cea adevărată.
STALE_SCAN_HOURS = 30

#: Statusurile cu care o scanare se încheie FĂRĂ un rezultat de încredere.
#: `timeout` e chiar statusul cu care a căzut pana din 21 august 2026; tratat ca
#: „necunoscut" sau ca reușită, exact cazul care a produs-o ar fi trecut.
_FAILED_SCAN_STATUSES = frozenset({"failed", "timeout"})

#: Peste câte ore un rând rămas `running` NU MAI POATE fi o scanare vie.
#:
#: Cifra e derivată din unitate, nu dintr-o părere despre cât durează o scanare:
#: `deploy/systemd/sentinel-scan.service` are `TimeoutStartSec=14400`, deci
#: systemd omoară unitatea la 4 ore. Peste atât nu mai există niciun proces care
#: ar putea încheia rândul. Ora în plus e marja de oprire (SIGTERM, apoi SIGKILL)
#: și diferența dintre ceasuri.
#:
#: Contează fiindcă `finish_scan` rulează DOAR în proces: un SIGKILL după
#: timeout, un OOM sub `MemoryMax=1G` sau o repornire la mijlocul scanării lasă
#: rândul `running` pentru totdeauna, și nimic nu-l curăță.
#:
#: Defectul a fost găsit CITIND CODUL, nu observat pe gazdă — și se spune așa, ca
#: să nu treacă drept măsurătoare: ramura `running` întorcea `ok` fără să se uite
#: vreodată la vârstă, deci un rând rămas acolo ar fi ieșit «rulează acum» oricât
#: de vechi ar fi fost. Pe gazdă, pe 26 august 2026, nu exista niciun astfel de
#: rând: 34 de rânduri în `scans`, 0 cu `running`, cel mai vechi `started_at` din
#: 31 iulie, secvența la 34 (deci nimic n-a fost șters), iar `selfcheck_state`
#: avea `scan:last:dnf | ok | ultima reușită acum 11 ore, 13 constatări`. Cifra
#: de 2160 de ore din teste e scenariul lor sintetic, nu ceva ce s-a văzut acolo.
#:
#: Legat de unitate printr-un test care citește `TimeoutStartSec` din fișierul
#: unității — dacă cineva urcă timeout-ul, constanta trebuie să urce cu el.
STUCK_SCAN_HOURS = 5

#: Ultima rulare a fiecărui scaner ȘI ultimul lui rezultat REAL.
#:
#: A doua jumătate nu e un lux. `DISTINCT ON (scanner) ... ORDER BY started_at
#: DESC` alege ultimul rând, iar un rând rămas `running` de la un SIGKILL e
#: pentru totdeauna ultimul rând: el UMBREȘTE ultima rulare încheiată, adică
#: exact cifra pe care o arată pagina de vulnerabilități. Fără coloanele `ok_*`,
#: constatarea despre rândul blocat ar putea spune că scanarea e blocată și n-ar
#: putea spune din când e cifra din panou — ar repara o tăcere și ar lăsa alta.
#:
#: `LATERAL` peste mulțimea DEJA deduplicată, nu peste tabela întreagă: se
#: execută o dată per scaner (2-3 azi), nu o dată per rând. Fiecare execuție e un
#: `LIMIT 1` pe `scans_scanner_idx (scanner, started_at DESC)`, indexul din 0003.
#:
#: `LEFT JOIN`, nu `JOIN`: un scaner care n-a încheiat NICIODATĂ o rulare trebuie
#: să iasă din interogare cu `ok_*` NULL, ca verificarea să poată spune „nu
#: există niciun rezultat real" — nu să dispară din listă, fiindcă atunci nu s-ar
#: mai spune nimic despre el, iar runner-ul ar citi tăcerea ca pe o revenire.
_LAST_SCAN_SQL = """
SELECT last.id, last.scanner, last.status, last.started_at, last.finished_at,
       last.error, last.findings_count,
       ok.started_at     AS ok_started_at,
       ok.finished_at    AS ok_finished_at,
       ok.findings_count AS ok_findings_count
  FROM (SELECT DISTINCT ON (scanner)
               id, scanner, status, started_at, finished_at, error, findings_count
          FROM scans
         ORDER BY scanner, started_at DESC) last
  LEFT JOIN LATERAL (
        SELECT started_at, finished_at, findings_count
          FROM scans c
         WHERE c.scanner = last.scanner AND c.status = 'completed'
         ORDER BY c.started_at DESC
         LIMIT 1
       ) ok ON true
 ORDER BY last.scanner
"""


async def _scan_age_s(db: Database, ts: Any) -> float | None:
    """Vârsta unui moment din `scans`, în secunde, măsurată cu ceasul BAZEI.

    `None` înseamnă „nu pot afla", niciodată „proaspăt": fie n-a fost niciun
    moment de măsurat, fie interogarea a căzut. Apelanții îl duc în `unknown`.

    Calculată în bază, ca la `check_ingest_sources`: ceasul gazdei și cel al
    bazei pot diferi, iar diferența ar apărea aici ca o vechime inventată. Iar
    `$1::timestamptz` e obligatoriu — fără el `now() - $1` are două citiri în
    Postgres, tipul parametrului nu se poate deduce, și interogarea cade la
    pregătire.
    """
    if ts is None:
        return None
    try:
        return float(await db.fetchval(
            "SELECT EXTRACT(EPOCH FROM (now() - $1::timestamptz))", ts) or 0.0)
    except Exception:  # noqa: BLE001
        return None


async def _last_completed_phrase(db: Database, r: dict) -> tuple[str, dict[str, Any]]:
    """Din când e ultimul rezultat REAL al scanerului, ca propoziție și ca fapte.

    Trei răspunsuri, și niciunul nu are voie să fie tăcerea sau o cifră
    inventată:

      * există o rulare încheiată — se spune din când și cu câte constatări,
        fiindcă aia e cifra pe care o arată panoul;
      * n-a existat NICIODATĂ una — se spune asta pe față; „0 constatări" ar fi
        chiar minciuna pe care o reparăm;
      * există, dar nu i-am putut citi vârsta — nu e nici „nu există", nici
        „proaspătă"; se spune că nu știu.
    """
    ts = r.get("ok_finished_at") or r.get("ok_started_at")
    if ts is None:
        return ("nu există nicio rulare încheiată a acestui scaner, deci panoul "
                "n-are de la el nicio cifră — nici măcar una veche",
                {"last_completed": None})

    findings = int(r.get("ok_findings_count") or 0)
    age_s = await _scan_age_s(db, ts)
    if age_s is None:
        return (f"există o rulare încheiată mai devreme, cu {findings} constatări, "
                f"dar nu i-am putut citi vârsta",
                {"last_completed_findings": findings})
    return (f"ultimul rezultat real e de acum {_ago(age_s / 60)}, cu {findings} "
            f"constatări — aia e cifra din panou",
            {"last_completed_age_h": int(age_s / 3600),
             "last_completed_findings": findings})


async def check_last_scan(db: Database, cfg: Config) -> list[CheckResult]:
    """Ultima scanare de vulnerabilități s-a încheiat, și s-a încheiat recent.

    Eșecul pe care îl previne, trăit pe 21 august 2026: numărul din panou fusese
    măsurat la 03:23, pachetele fuseseră reparate la 09:14, iar scanarea de la
    10:33 — cea care le-ar fi închis — eșuase cu `timeout`. Eșecul acela n-a ajuns
    nicăieri: operatorul a văzut două surse care nu erau de acord și n-a avut de
    unde ști care minte. Verificarea de aici e drumul pe care eșecul intră în
    `selfcheck_state`, deci și în `/selfcheck` pe Telegram.

    Al doilea eșec, găsit pe 26 august 2026 citind codul, nu văzut pe gazdă:
    ramura `running` întorcea `ok` fără să se uite la vârstă, deci un rând rămas
    acolo ar fi fost raportat «rulează acum» oricât de vechi. Pe gazdă erau atunci
    0 rânduri `running`, deci nu s-a observat nimic — ceea ce nu-l face mai puțin
    real: `finish_scan` rulează doar în proces, deci un SIGKILL după
    `TimeoutStartSec`, un OOM sau o repornire la mijloc lasă rândul acolo și nimic
    nu-l curăță. Peste
    `STUCK_SCAN_HOURS` se raportează, cu AMÂNDOUĂ faptele: că rularea n-a mai
    ajuns niciodată la capăt, ȘI din când e ultimul rezultat real — fiindcă
    `_LAST_SCAN_SQL` alege rândul cel mai nou, deci cel blocat umbrește tocmai
    cifra pe care operatorul o vede în panou.

    `degraded`, nu `down`: nimic de pe gazdă nu s-a oprit — colectarea și blocarea
    merg mai departe. Ce e stricat e prospețimea unei liste. Fiecare scanner își
    primește cheia lui: un `dnf` care cade contează altfel decât un `trivy`, iar
    sub o cheie comună cel care se repară l-ar ascunde pe celălalt.
    """
    if not cfg.scan.enabled:
        return [CheckResult(
            "scan:last", "Scanarea de vulnerabilități", "ok",
            detail="oprită în configurație (scan.enabled: false)",
            facts={"enabled": False})]

    try:
        rows = await db.fetch(_LAST_SCAN_SQL)
    except Exception as exc:  # noqa: BLE001
        # „Nu pot citi" se EMITE, nu se tace: runner-ul reconciliază starea după
        # cheile emise, deci o tăcere aici ar șterge o constatare reală. Cheie
        # separată de verdict — o citire eșuată nu are voie să arate ca o revenire.
        return [CheckResult(
            "scan:last:unreadable", "Nu pot citi starea scanărilor", "unknown",
            detail=f"tabela `scans` nu s-a putut citi: {str(exc)[:140]} — nu pot "
                   f"spune dacă ultima scanare a reușit sau a eșuat",
            action="sentinel migrate ; journalctl -u sentinel-scan -n 50")]

    if not rows:
        return [CheckResult(
            "scan:last", "Nicio scanare încă", "unknown",
            detail="nu există nicio rulare în tabela `scans` — «n-a rulat "
                   "niciodată» nu e «e bine», iar pagina de vulnerabilități ar "
                   "fi goală și liniștitoare",
            action="systemctl start sentinel-scan ; journalctl -u sentinel-scan -n 50")]

    results: list[CheckResult] = []
    for row in rows:
        r = dict(row)
        scanner = str(r.get("scanner") or "?")
        status = str(r.get("status") or "")
        key = f"scan:last:{scanner}"

        # O rulare în curs e purtarea normală în fereastra de scanare — dar numai
        # cât timp POATE fi în curs. Vezi `STUCK_SCAN_HOURS`: peste pragul ăla
        # procesul nu mai există, deci rândul e o rămășiță, nu o scanare.
        if status == "running":
            age_s = await _scan_age_s(db, r.get("started_at"))
            if age_s is None:
                # Fără vârstă nu pot deosebi „rulează acum" de „a murit acum trei
                # luni". „Nu știu" nu e „e bine", deci se emite `unknown` — sub
                # cheia scanerului, ca să înlocuiască verdictul, nu să-l retragă.
                results.append(CheckResult(
                    key, f"Scanarea „{scanner}” — nu-i pot afla vârsta", "unknown",
                    detail="rândul e „running”, dar nu am putut citi de când, deci "
                           "nu știu dacă e o scanare în curs sau una moartă demult",
                    action="journalctl -u sentinel-scan -n 50",
                    facts={"scanner": scanner, "status": status}))
                continue

            if age_s <= STUCK_SCAN_HOURS * 3600:
                # Tratată ca măsurătoare reușită ar pretinde un rezultat care nu
                # există încă („0 constatări" la o scanare abia pornită), deci nu
                # se spune nimic despre constatări aici.
                results.append(CheckResult(
                    key, f"Scanarea „{scanner}” rulează acum", "ok",
                    detail=f"o scanare e în curs de {_ago(age_s / 60)} — starea "
                           f"normală în fereastra de scanare; rezultatul se vede "
                           f"când se încheie",
                    facts={"scanner": scanner, "status": status,
                           "age_h": int(age_s / 3600)}))
                continue

            # Peste prag. DOUĂ fapte, și amândouă trebuie spuse: rândul nu se va
            # încheia niciodată, ȘI cât timp stă acolo el umbrește ultimul
            # rezultat real (`DISTINCT ON` îl alege pe el), deci operatorul se
            # uită la o cifră veche fără ca ceva să i-o spună.
            ultima, fapte = await _last_completed_phrase(db, r)
            scan_id = r.get("id")
            results.append(CheckResult(
                key, f"Scanarea „{scanner}” a rămas blocată în „running”", "degraded",
                detail=f"a pornit acum {_ago(age_s / 60)} și nu s-a încheiat "
                       f"niciodată — mai demult de {STUCK_SCAN_HOURS} ore, iar "
                       f"systemd a omorât deja unitatea la `TimeoutStartSec`, deci "
                       f"nu mai e nimic viu care s-o închidă (SIGKILL după timeout, "
                       f"OOM, sau o repornire la mijloc). Cât rândul stă așa, el "
                       f"ASCUNDE ultima rulare încheiată în panou: {ultima}",
                action="journalctl -u sentinel-scan -n 100 ; rândul rămas se închide "
                       f"cu: UPDATE scans SET status='failed', error='întrerupt' "
                       f"WHERE id={scan_id};",
                facts={"scanner": scanner, "status": status,
                       "scan_id": scan_id, "age_h": int(age_s / 3600), **fapte}))
            continue

        if status in _FAILED_SCAN_STATUSES:
            eroare = str(r.get("error") or status)
            results.append(CheckResult(
                key, f"Scanarea „{scanner}” a eșuat", "degraded",
                detail=f"ultima rulare s-a încheiat cu „{status}”: {eroare}. Ce a "
                       f"reparat operatorul între timp apare în continuare ca "
                       f"deschis, fiindcă lista nu s-a mai împrospătat",
                action="journalctl -u sentinel-scan -n 50 ; sentinel scan --now",
                facts={"scanner": scanner, "status": status, "error": eroare}))
            continue

        # Încheiată: proaspătă sau veche? (`skipped` a ieșit din constrângere în
        # migrația 0029 — vezi acolo de ce nu se tratează, ci se face
        # nereprezentabil.) Vârsta se calculează în baza de date, ca la
        # `check_ingest_sources`: ceasul gazdei și cel al bazei pot diferi, iar
        # diferența ar apărea aici ca o vechime inventată.
        #
        # `finished_at` întâi, `started_at` doar ca rezervă. Întrebarea de aici e
        # „cât de veche e cifra din panou", iar cifra se scrie când scanarea SE
        # ÎNCHEIE. `sentinel-scan.service` are `TimeoutStartSec=14400`, deci o
        # rulare poate ține ore: măsurată de la pornire, o listă scrisă acum zece
        # minute ar putea fi raportată ca depășită. Rezerva pe `started_at`
        # rămâne fiindcă un rând încheiat fără `finished_at` există — iar fără
        # niciunul din două se cade în `unknown` mai jos, nu în `ok`.
        age_s = await _scan_age_s(db, r.get("finished_at") or r.get("started_at"))

        if age_s is None:
            # Fără vârstă nu pot spune dacă lista e proaspătă. „Nu știu" nu e „e
            # bine": se emite `unknown`, sub aceeași cheie a scannerului.
            results.append(CheckResult(
                key, f"Scanarea „{scanner}” — nu-i pot afla vârsta", "unknown",
                detail=f"ultima rulare e „{status}”, dar nu am putut citi când s-a "
                       f"încheiat, deci nu știu dacă lista e proaspătă",
                action="journalctl -u sentinel-scan -n 50",
                facts={"scanner": scanner, "status": status}))
            continue

        if age_s > STALE_SCAN_HOURS * 3600:
            # Nicio eroare, dar nici măsurători: o gazdă care a scanat ultima oară
            # acum trei zile arată, din statusuri, exact ca una sănătoasă. Diferența
            # e vârsta, iar fără ea panoul ar arăta o cifră veche de zile ca și cum
            # ar fi de azi.
            results.append(CheckResult(
                key, f"Scanarea „{scanner}” a rămas în urmă", "degraded",
                detail=f"ultima rulare încheiată a fost acum {_ago(age_s / 60)} — "
                       f"mai veche de {STALE_SCAN_HOURS} de ore, deci cifra din "
                       f"panou e veche și nu mai spune ce e deschis acum",
                action="systemctl start sentinel-scan ; journalctl -u sentinel-scan -n 50",
                facts={"scanner": scanner, "status": status,
                       "age_h": int(age_s / 3600)}))
            continue

        findings = int(r.get("findings_count") or 0)
        results.append(CheckResult(
            key, f"Scanarea „{scanner}”", "ok",
            detail=f"ultima rulare încheiată acum {_ago(age_s / 60)}, "
                   f"{findings} constatări",
            facts={"scanner": scanner, "status": status, "findings": findings}))
    return results


# ---------------------------------------------------------------------------
# Auditd: nucleul își aruncă înregistrările?
# ---------------------------------------------------------------------------
#: Pragul de înregistrări pierdute e ZERO, dinadins. `lost` e cumulativ de la
#: pornirea lui auditd, iar orice creștere înseamnă istoric pierdut definitiv. Un
#: prag mai mare ar spune „puțin istoric lipsă e în regulă" — dar un istoric cu
#: goluri arată exact ca unul complet, deci n-ai cum să afli cât lipsește.
AUDIT_LOST_MAX = 0

#: Peste ce procent din tampon se avertizează ÎNAINTE de a se pierde ceva. Un
#: `backlog` mare fără pierderi înseamnă că următoarea rafală le va produce — un
#: deploy e ~405 000 de înregistrări în două minute; avertizat la jumătate, mai e
#: timp să se lărgească tamponul.
AUDIT_BACKLOG_WARN_PCT = 50


def _auditctl_status() -> dict[str, int] | None:
    """Starea nucleului de audit (`auditctl -s`), citită PRIN executor.

    `auditctl` cere root, iar autodiagnosticul rulează ca `sentinel`. Chemat
    direct, apelul eșuează mereu — măsurat pe gazdă pe 25 august 2026, verificarea
    raporta `unknown` la FIECARE trecere, cinstit ca propoziție și inutil ca pază.
    Singurul drum către root din proiect e executorul (o regulă `sudoers` pentru
    `sentinel` ar fi un al doilea), deci pe acolo se cere — fără să pornim vreun
    proces aici.

    `None` înseamnă „nu am putut citi", niciodată „zero pierderi": apelantul îl
    transformă în `unknown`.
    """
    from sentinel.errors import ExecutorRejected, ExecutorUnavailable
    from sentinel.respond.executor_client import ExecutorClient

    try:
        result = ExecutorClient().audit_status()
    except (ExecutorUnavailable, ExecutorRejected, OSError):
        return None
    if not result.get("ok"):
        return None
    # Doar câmpurile întregi ale ieșirii lui `auditctl`, fără `ok`. `bool` e
    # subclasă de `int` în Python, dar `ok` a fost deja exclus, iar restul
    # câmpurilor sunt numere adevărate.
    #
    # `or None` la final NU e cosmetic: un răspuns care a trecut de garda `ok`
    # dar din care n-a ieșit niciun câmp întreg e un răspuns pe care nu l-am
    # înțeles. Returnat ca dicționar gol, apelantul l-ar citi prin `.get("lost",
    # 0)` drept „zero pierderi" și ar raporta `ok` — adică exact schimbul pe care
    # verificarea asta există ca să-l prevină. `None` îl duce în `unknown`.
    return {k: int(v) for k, v in result.items()
            if k != "ok" and isinstance(v, int)} or None


async def check_audit_records(db: Database, cfg: Config) -> list[CheckResult]:
    """Nucleul își aruncă înregistrările de audit?

    De la 24 august 2026 istoricul de comenzi atârnă de auditd — fiecare `execve`
    dintr-o sesiune cu login. Când tamponul nucleului se umple, înregistrările se
    ARUNCĂ fără nicio eroare și fără vreun rând lipsă vizibil: produc un istoric
    mai scurt decât realitatea, exact în minutul aglomerat în care cineva lucrează
    repede. E tiparul din `CLAUDE.md` în forma lui cea mai curată — absența unui
    semnal citită ca absența unui eveniment.

    `degraded`, nu `down`: pe gazdă nu s-a oprit nimic. Se raportează EFECTUL —
    numărul real de înregistrări pierdute citit din nucleu —, nu un cod de ieșire.
    """
    # Apel BLOCANT (socket unix, `DEFAULT_TIMEOUT_S = 30`) — pe bucla de
    # evenimente ar ține în loc toate celelalte verificări ale rundei exact
    # când executorul nu răspunde, adică exact când sunt de citit. Ca toate
    # celelalte apeluri blocante din fișierul ăsta, se împăchetează.
    status = await asyncio.to_thread(_auditctl_status)
    if status is None:
        # „Nu știu dacă s-a pierdut ceva" nu e „nu s-a pierdut nimic". Se emite,
        # nu se tace: o tăcere ar șterge o constatare reală prin reconciliere.
        return [CheckResult(
            "audit:records", "Nu pot citi starea auditului", "unknown",
            detail="`auditctl -s` nu a răspuns prin executor — nu știu dacă "
                   "nucleul a aruncat înregistrări de audit",
            action="systemctl status sentinel-executor")]

    lost = int(status.get("lost", 0))
    backlog = int(status.get("backlog", 0))
    limit = int(status.get("backlog_limit", 0))
    facts = {"lost": lost, "backlog": backlog, "backlog_limit": limit}

    if lost > AUDIT_LOST_MAX:
        return [CheckResult(
            "audit:records", "Nucleul a aruncat înregistrări de audit", "degraded",
            detail=f"{lost} înregistrări pierdute de la pornirea auditd — istoric "
                   f"de comenzi pierdut definitiv, chiar în minutele aglomerate. "
                   f"Un istoric cu goluri arată exact ca unul complet",
            action="Lărgește tamponul: auditctl -b <valoare mai mare>, apoi "
                   "persistă în /etc/audit/rules.d/. Vezi backlog_wait_time.",
            facts=facts)]

    # Împărțire evitată — `limit` poate lipsi din ieșirea unor versiuni mai vechi
    # de `auditctl`; comparat prin înmulțire, un `limit` zero nu declanșează.
    if limit > 0 and backlog * 100 >= limit * AUDIT_BACKLOG_WARN_PCT:
        return [CheckResult(
            "audit:records", "Tamponul de audit se apropie de plin", "degraded",
            detail=f"{backlog} din {limit} în tampon — peste "
                   f"{AUDIT_BACKLOG_WARN_PCT}%, deci următoarea rafală (un deploy e "
                   f"~405 000 de înregistrări în două minute) le poate pierde",
            action="Lărgește tamponul: auditctl -b <valoare mai mare>, apoi "
                   "persistă în /etc/audit/rules.d/.",
            facts=facts)]

    return [CheckResult(
        "audit:records", "Înregistrările de audit", "ok",
        detail=f"nicio înregistrare pierdută; {backlog} în tampon",
        facts=facts)]


# ---------------------------------------------------------------------------
# Identitatea instalării: fișierul e autoritatea, rândul din bază e oglinda
# ---------------------------------------------------------------------------
async def check_instance_identity(db: Database) -> list[CheckResult]:
    """Fișierul de identitate și oglinda din bază spun același lucru?

    Un panou extern care adună mai multe instalări le deosebește după o singură
    valoare. `/etc/sentinel/instance_id` e autoritatea; rândul din
    `instance_identity` e oglinda. Nepotrivirea dintre ele e simptomul unui backup
    luat pe o gazdă și restaurat pe o clonă a alteia — două servere își amestecă
    istoriile într-un panou comun și nimic nu raportează o defecțiune, cifrele doar
    încetează să însemne ce spun.

    `degraded`, nu `down`: pe gazda asta nu s-a oprit nimic. Fiecare cale emite
    exact o cheie — „n-am emis cheia" înseamnă „am privit și n-am avut ce raporta",
    niciodată „n-am putut privi".
    """
    from sentinel.db import identity_mirror
    from sentinel.identity import IdentityError, read_instance_id

    key = "identity:instance"

    try:
        file_id = read_instance_id()
    except IdentityError as exc:
        # „Nu se știe" și „e bine" sunt stări diferite: fără fișier nu există
        # comparație, deci verificarea nu s-a uitat. Acțiunea numește AMBELE
        # tratamente, fiindcă cele două cauze cer lucruri diferite: fișierul lipsă
        # îl creează orice deploy, iar unul care există dar nu e o identitate nu se
        # rescrie de nimeni, dinadins.
        return [CheckResult(
            key, "Nu pot citi identitatea instalării", "unknown",
            detail=str(exc)[:200],
            action="Un fișier lipsă îl creează un deploy obișnuit: "
                   "./scripts/deploy.sh --host <host> --user <user>. Un fișier "
                   "care există dar nu e o identitate NU se rescrie automat — "
                   "uită-te la conținutul lui: od -c /etc/sentinel/instance_id")]

    try:
        row = await db.fetchrow(
            "SELECT instance_id, first_seen FROM instance_identity WHERE only_row = true")
    except Exception as exc:  # noqa: BLE001
        # Cod nou, migrații neaplicate: tabela nu există încă. Lăsată să iasă,
        # excepția marchează grupul eșuat și rularea devine incompletă — nimic nu
        # s-ar mai reconcilia în runda aia. Prinsă aici, e doar `unknown`.
        return [CheckResult(
            key, "Nu pot citi oglinda identității", "unknown",
            detail=f"tabela `instance_identity` nu s-a putut citi: {str(exc)[:140]}",
            action="sentinel migrate")]

    if row is not None:
        db_id = str(dict(row).get("instance_id") or "")
        if db_id == file_id:
            return [CheckResult(
                key, "Identitatea instalării", "ok",
                detail="fișierul și oglinda din bază spun aceeași identitate",
                facts={"mirrored": True})]
        return [CheckResult(
            key, "Identitatea din bază nu e cea a gazdei", "degraded",
            detail=f"fișierul spune {file_id[:8]}…, iar rândul din "
                   f"`instance_identity` spune {db_id[:8]}… — semn de bază "
                   f"restaurată pe o mașină clonată; istoriile a două servere se "
                   f"amestecă într-un panou comun",
            action="docs/OPERARE.md, „Identitatea instalării” (§12)",
            facts={"file": file_id, "db": db_id})]

    # Rândul lipsește. „Scriitorul n-a rulat încă" (normal pe o instalare nouă) și
    # „a rulat și n-a reușit" (defect) arată la fel de aici; le deosebește urma
    # scriitorului, citită sub numele pe care chiar el îl scrie.
    try:
        marker = await db.fetchrow(
            "SELECT cursor, updated_at FROM collector_cursors WHERE name = $1",
            identity_mirror.MIRROR_MARKER)
    except Exception as exc:  # noqa: BLE001
        # Fără urmă, cele două înțelesuri nu se pot despărți. A ghici ar însemna să
        # alegem între o alarmă falsă permanentă și o tăcere falsă permanentă.
        return [CheckResult(
            key, "Nu pot citi urma scriitorului de oglindă", "unknown",
            detail=f"urma `{identity_mirror.MIRROR_MARKER}` nu s-a putut citi: "
                   f"{str(exc)[:140]}",
            action="sentinel migrate")]

    if marker is None:
        # Nici oglindă, nici urmă: scriitorul nu a fost încă încercat. E starea
        # normală a fiecărei instalări în primele secunde, între copierea codului
        # și `sentinel migrate`. `degraded` aici ar suna la fiecare instalare nouă.
        return [CheckResult(
            key, "Identitatea instalării", "ok",
            detail="oglinda din bază nu e scrisă încă — starea normală a unei "
                   "instalări noi, până rulează `sentinel migrate`",
            facts={"mirrored": False, "writer_ran": False})]

    # Scriitorul a rulat (există urmă) și rândul tot lipsește: oglinda nu se scrie,
    # iar nepotrivirea pe care ea o păzește n-ar mai putea fi observată de nimeni.
    # Rezultatul înregistrat ajunge în text, ca operatorul să nu ghicească dacă e
    # vina fișierului, a tabelei sau a drepturilor.
    outcome = str(dict(marker).get("cursor") or "")
    return [CheckResult(
        key, "Scriitorul oglinzii a rulat și nu a scris rândul", "degraded",
        detail=f"urma scriitorului spune „{outcome}”, dar rândul din "
               f"`instance_identity` lipsește — oglinda nu se scrie, deci o bază "
               f"restaurată pe o clonă n-ar mai fi prinsă",
        action="sentinel migrate ; journalctl -u sentinel-migrate -n 50",
        facts={"mirrored": False, "writer_ran": True, "outcome": outcome})]


# ---------------------------------------------------------------------------
CHECKS: tuple[tuple[str, Callable], ...] = (
    ("units", check_units),
    ("timers", check_timers),
    ("ingest", check_ingest_sources),
    ("detect", check_detection_loop),
    ("enforcement", check_enforcement),
    ("executor", check_executor),
    ("database", check_database),
    ("identity", check_instance_identity),
    ("resources", check_resources),
    ("code", check_running_code_is_current),
    ("ship", check_ship_lag),
    ("scan", check_last_scan),
    ("audit", check_audit_records),
    ("history", check_command_history_filter),
    ("beacon", check_beacon_delivery),
    ("alerting", check_alerting),
    ("autonomy", check_autonomy),
)


@dataclass(frozen=True)
class RunOutcome:
    """What a pass produced — and whether it produced all of it.

    The second field is the one that matters. The runner reconciles
    `selfcheck_state` against the keys a run emitted, and that is only sound if
    "this key is missing" means the check withdrew it. A group that raised
    emitted none of its keys for a reason that has nothing to do with the host,
    so an incomplete run must reconcile nothing: deleting a finding because the
    code that produces it crashed would turn a broken check into a clean bill of
    health — the exact swap this whole package exists to prevent.
    """

    results: list[CheckResult]
    failed_groups: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.failed_groups


async def run_groups(db: Database, cfg: Config) -> RunOutcome:
    """Every check, each isolated.

    A check that raises reports itself as broken and the run continues. The
    alternative — one exception ending the run — would mean the self-check goes
    quiet for the same reason everything else does, and quiet is the thing it
    exists to make impossible.

    The group is also named in `failed_groups`, because "the run continued" and
    "the run saw everything" are different facts and only the caller can act on
    the difference.
    """
    out: list[CheckResult] = []
    failed: list[str] = []
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
            failed.append(name)
            log.error("selfcheck group failed", extra={"group": name, "detail": str(exc)})
            out.append(CheckResult(
                f"selfcheck:{name}", f"Verificarea „{name}” a eșuat", "unknown",
                detail=str(exc)[:200],
                action="Verificarea însăși e stricată — asta trebuie reparat întâi"))
    return RunOutcome(out, tuple(failed))


async def run_all(db: Database, cfg: Config) -> list[CheckResult]:
    """The results alone, for callers that only print them (`--print`)."""
    return (await run_groups(db, cfg)).results


def since(moment: datetime | None) -> timedelta | None:
    return None if moment is None else datetime.now(timezone.utc) - moment
