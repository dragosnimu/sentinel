"""`sentinel ingest` — the collection daemon.

Long-running (systemd Type=exec, Restart=always). Every flush interval it reads
what is new since the last cursor from each source, normalises it into canonical
events, enriches with geo/ASN, writes a batch, and only then advances the cursors
— so a crash re-reads a few events rather than losing them.

Sources in this build:
  * journald — sshd/sshd-session (authentication) and sudo/su (privilege use);
  * nginx access logs (tailed, inode-aware);
  * Suricata eve.json (alerts only, engine diagnostics dropped);
  * auditd audit.log (security record types only);
  * conntrack — periodic outbound-traffic sampling, not a log tail. See
    `sentinel/collectors/conntrack.py`'s module docstring for what it catches
    (persistent C2, slow exfiltration) and what it cannot (a connection that
    opens and closes between two one-minute samples).

Not yet collected, and deliberately marked false in config rather than claimed:
docker container logs and standalone file-integrity monitoring.

One thing here is not collection: every `REAP_INTERVAL_S` the daemon asks the
host which audit login sessions still have a process, and closes the rows whose
session is gone (`maybe_reap_sessions`). It runs here because this is where the
rows are opened and closed already — and because this is the only one of the
two candidate daemons whose sandbox lets it see other users' processes at all.

Every source is filtered at the collector, not after: auditd and Suricata can
each produce tens of thousands of irrelevant records a day, and storing them
buries the signal and fills partitions. A source listed in
`ingest.exclude_sources` is dropped as well — the escape hatch for a chatty feed
with no security value.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sentinel.collectors import nginx_tail
from sentinel.collectors.audit_sessions import LiveAuditSessions, read_live_sessions
from sentinel.collectors.auditd import last_record_time, parse_auditd_lines
from sentinel.collectors.conntrack import ConntrackSampler
from sentinel.collectors.nginx import parse_nginx
from sentinel.collectors.sshd import parse_sshd
from sentinel.collectors.suricata_eve import parse_suricata
from sentinel.collectors.system import parse_system
from sentinel.config import Config, get_config, resolve_skip_command_accounts
from sentinel.db.engine import Database
from sentinel.db.repo import events as events_repo
from sentinel.db.repo import logins
from sentinel.enrich.geoip import GeoEnricher
from sentinel.enrich.reputation import ReputationEnricher
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.model.event import Event
from sentinel.services import parse_service_args

log = get_logger(__name__)

# The journal processes worth reading. "sshd-session" is where OpenSSH 9.8+ logs
# authentication; "sshd" covers older releases and the listener itself. sudo/su
# are the privilege-escalation path — the step after an account is compromised.
JOURNALD_COMMS = ("sshd-session", "sshd", "sudo", "su", "su-l")

# How often the daemon asks the host which login sessions are still alive.
#
# Not every poll: the scan opens one file per process (187 on the Ubuntu host,
# 201 on the AlmaLinux one) and the flush interval is measured in seconds. Half
# a minute is invisible next to the grace period the reaper applies anyway
# (`logins.REAP_GRACE_S`, two minutes), and ludicrously fast next to the twelve
# hours it replaces.
#
# It bounds how often a scan is TAKEN. A scan already taken and not yet used
# is kept, never retaken: a scan whose session is absent stays absent — dead is
# permanent — so an old scan can only be late, never wrong, and retaking it
# while waiting would move the finish line at the same speed as the runner.
REAP_INTERVAL_S = 30


@dataclass(frozen=True)
class _PendingScan:
    """One reading of the host, and the two clocks that say when it was taken.

    Two clocks because the two comparisons it feeds cannot share one:

      * `taken_at` is wall clock, and is compared with the audit watermark,
        which comes from the kernel's own record stamps — the same clock;
      * `taken_monotonic` measures how old the scan is when the statement
        finally runs, and that number is handed to PostgreSQL as a DURATION.
        A wall-clock difference would be wrong by exactly as much as the clock
        stepped (ntp, a VM resumed), and it would be wrong in the direction
        that closes live sessions.
    """

    live: LiveAuditSessions
    taken_at: datetime
    taken_monotonic: float


def _audit_watermark(lines: list[str], citit_la: datetime,
                     la_capat: bool) -> datetime | None:
    """Până CÂND a fost urmărită coada de audit după citirea asta, sau `None`.

    Două dovezi, de puteri diferite, și se folosește cea potrivită stării cozii:

      * **coada are octeți necitiți** → ștampila ultimei înregistrări citite.
        auditd scrie în ordinea în care nucleul îi dă înregistrările, deci nimic
        necitit nu e mai vechi decât ea. E dovada TARE, și e cea care ține sub
        sarcină: cu cât se scrie mai mult, cu atât filigranul urcă mai repede;
      * **coada e golită** → clipa citirii. Atunci fișierul n-avea nimic
        necitit, deci tot ce apucase să fie SCRIS era citit. E dovada slabă:
        între fapta unei comenzi și înregistrarea ei în fișier trece coada lui
        auditd (0,34 s măsurat pe gazda Ubuntu la 15 septembrie 2026), iar
        marginea aia nu se vede din nicio poziție în fișier. E exact marginea pe
        care o avea și poarta dinainte, nici mai mare, nici mai mică.

    `None` când coada e în urmă și nicio linie din lot n-are ștampilă citibilă.
    Atunci filigranul NU se mișcă — nu se pune clipa citirii în locul lui,
    fiindcă acolo e chiar minciuna: „am citit tot" despre un fișier din care
    tocmai n-am putut citi ora nici unei înregistrări.
    """
    filigran = last_record_time(lines)
    if la_capat and (filigran is None or filigran < citit_la):
        return citit_la
    return filigran


async def _connect(cfg: Config) -> Database:
    db = Database(cfg)
    await db.connect()
    return db


class Ingest:
    def __init__(self, cfg: Config, db: Database):
        self.cfg = cfg
        self.db = db
        self.exclude = set(cfg.ingest.exclude_sources)
        # Read once, at construction, like `exclude` above: a missing or
        # malformed section then fails when the daemon starts, not silently on
        # the first batch that happens to carry a command.
        #
        # Resolved, not taken literally: the same account reaches the table
        # under its name AND under its numeric auid, and the filter compares on
        # exact equality. See `SkipAccounts` for the measurement and the edge.
        self.skip_accounts = resolve_skip_command_accounts(
            cfg.history.skip_command_accounts)
        self.skip_command_accounts = self.skip_accounts.matches
        # A configured account that does not exist on this host is a filter that
        # can never match. Said once, at start, because the alternative is a
        # section that looks configured and drops nothing — which is exactly how
        # the first version of this filter spent a week doing nothing.
        if not self.skip_accounts.lookup_ok:
            log.warning(
                "cannot read the account database; skip_command_accounts "
                "resolved by name only",
                extra={"configured": list(cfg.history.skip_command_accounts)})
        elif self.skip_accounts.unresolved:
            log.warning(
                "skip_command_accounts names accounts absent from this host",
                extra={"unresolved": list(self.skip_accounts.unresolved)})
        self.geo = GeoEnricher()
        # Reloaded periodically from `intel_feed_entries`, never queried per
        # event — see `sentinel/enrich/reputation.py`'s docstring for the
        # measurement behind that split.
        self.reputation = ReputationEnricher()
        self._journald = None
        self._nginx_cursors: dict[str, str | None] = {}
        self._eve_path: str | None = None
        self._eve_cursor: str | None = None
        self._audit_path: str | None = None
        self._audit_cursor: str | None = None
        self._conntrack: ConntrackSampler | None = None
        # The time half of the audit cursor: how far the tail has been followed
        # IN TIME, not in bytes. Written only where the byte cursor is written —
        # after the batch it covers is committed — for the reason in
        # `maybe_reap_sessions`: a watermark that survives a poll which threw
        # away its records describes a database that does not exist.
        #
        # `None` is "never measured", and it is not "now". A daemon that has not
        # yet read a single audit record knows nothing about what is unread, and
        # the reaper below refuses on it rather than assuming the file is quiet.
        self._audit_seen_through: datetime | None = None
        self._next_reap = 0.0
        # The scan taken and not yet used, if any. See `maybe_reap_sessions`.
        self._pending_scan: _PendingScan | None = None
        # How many passes in a row have refused to reap while holding it. The
        # journal is RAM-only on the production host, so this number is also
        # written to the database — "the reaper is starved" and "nobody died"
        # are otherwise the same silence.
        self._reap_deferred = 0
        # None, not "": the first scan always says something, so a daemon that
        # cannot see the host's processes says so at startup instead of looking
        # exactly like one on a host where nobody is logged in.
        self._reap_state: str | None = None
        # (state, monotonic) of the last durable write, so an unchanged state is
        # refreshed on a timer instead of on every poll.
        self._reap_recorded: tuple[str, float] | None = None

    async def setup(self) -> None:
        if self.cfg.ingest.journald:
            try:
                from sentinel.collectors.journald_reader import JournaldReader

                # OpenSSH 9.8+ splits the per-connection worker into a separate
                # binary, so authentication now logs under _COMM=sshd-session.
                # Matching only "sshd" here made SSH brute-force detection blind
                # on any host with a current OpenSSH — both names are matched.
                self._journald = JournaldReader([
                    {"_COMM": c} for c in JOURNALD_COMMS])
                self._journald.seek(await events_repo.get_cursor(self.db, "sshd"))
                log.info("journald reader ready", extra={"comms": list(JOURNALD_COMMS)})
            except Exception as exc:  # noqa: BLE001 - no journald is degraded, not fatal
                log.warning("journald unavailable; sshd collection disabled", extra={"detail": str(exc)})
                self._journald = None

        for path in nginx_tail.expand_paths(self.cfg.ingest.nginx_log_paths) if self.cfg.ingest.nginx else []:
            self._nginx_cursors[path] = await events_repo.get_cursor(self.db, f"nginx:{path}")
        if self._nginx_cursors:
            log.info("nginx tailers ready", extra={"files": list(self._nginx_cursors)})

        if self.cfg.ingest.suricata and self.cfg.suricata.enabled:
            self._eve_path = self.cfg.suricata.eve_path
            self._eve_cursor = await events_repo.get_cursor(self.db, "suricata")
            log.info("suricata eve.json tailer ready", extra={"path": self._eve_path})

        if self.cfg.ingest.auditd:
            path = self.cfg.ingest.auditd_log_path
            if Path(path).exists():
                self._audit_path = path
                self._audit_cursor = await events_repo.get_cursor(self.db, "auditd")
                log.info("auditd tailer ready", extra={"path": path})
            else:
                log.warning("auditd enabled but log absent", extra={"path": path})

        if self.cfg.ingest.conntrack:
            # No cursor: each sample is a self-contained snapshot of the
            # kernel's current connection table, not a position in a log —
            # there is nothing to resume from after a restart, and none is
            # needed. `ConntrackSampler` owns its own cadence internally.
            self._conntrack = ConntrackSampler(self.cfg.ingest.conntrack_path)
            log.info("conntrack sampler ready", extra={"path": self.cfg.ingest.conntrack_path})

        if self.geo.available:
            log.info("geoip enrichment active")

    async def poll_once(self) -> int:
        batch: list[Event] = []
        sshd_cursor: str | None = None
        sshd_n = 0

        if self._journald is not None:
            for message, ts, cursor, comm in self._journald.read_new():
                sshd_cursor = cursor
                # sshd first (the high-volume case), then sudo/su. A message
                # that matches neither is simply not security-relevant.
                ev = parse_sshd(message, ts) if comm.startswith("sshd") else None
                if ev is None:
                    ev = parse_system(message, ts, comm)
                if ev is not None:
                    batch.append(ev)
                    sshd_n += 1

        nginx_new: dict[str, str | None] = {}
        for path, cursor in self._nginx_cursors.items():
            lines, new_cursor = nginx_tail.read_new_lines(path, cursor)
            if new_cursor != cursor:
                nginx_new[path] = new_cursor
            for line in lines:
                ev = parse_nginx(line)
                if ev is not None:
                    batch.append(ev)

        eve_new: str | None = None
        if self._eve_path is not None:
            lines, new_cursor = nginx_tail.read_new_lines(self._eve_path, self._eve_cursor)
            if new_cursor != self._eve_cursor:
                eve_new = new_cursor
            for line in lines:
                ev = parse_suricata(line)
                if ev is not None:
                    batch.append(ev)

        audit_new: str | None = None
        audit_seen: datetime | None = None
        if self._audit_path is not None:
            # Ceasul ÎNAINTE de citire, „mai e ceva necitit?" imediat DUPĂ ea.
            # Amândouă lipite de citire, nu la capătul trecerii: între citire și
            # sfârșitul lui `poll_once` stau `insert_batch` și `logins.project`,
            # adică un drum la bază PE FIECARE comandă din lot — 636 pentru o
            # singură logare, ~405 000 pentru un deploy. O măsurătoare luată
            # acolo descrie un fișier care între timp a mai fost scris de zeci
            # de ori, și exact asta ținea poarta închisă sub sarcină.
            citit_la = datetime.now(timezone.utc)
            lines, new_cursor = nginx_tail.read_new_lines(self._audit_path, self._audit_cursor)
            la_capat = nginx_tail.at_end(self._audit_path, new_cursor)
            if new_cursor != self._audit_cursor:
                audit_new = new_cursor
            audit_seen = _audit_watermark(lines, citit_la, la_capat)
            # Pe lot, nu pe linie: o acțiune supravegheată produce mai multe
            # linii care împart un serial, iar cine, ce binar și pe ce fișier
            # sunt împrăștiate între ele.
            batch.extend(parse_auditd_lines(lines))

        if self._conntrack is not None:
            # A no-op call, no file I/O, unless its own (much slower) sample
            # interval has elapsed — see the docstring on `maybe_sample`.
            batch.extend(self._conntrack.maybe_sample())

        batch = [e for e in batch if e.source not in self.exclude]
        # Reload check first: a no-op unless the interval elapsed, so this
        # never adds a query to the common case of "nothing due yet".
        await self.reputation.maybe_refresh(self.db)
        for ev in batch:
            self.geo.enrich(ev)
            self.reputation.enrich(ev)

        if batch:
            await events_repo.insert_batch(self.db, batch)
            # DUPA scrierea brutului, nu in locul lui. `raw_events` ramane sursa
            # completa chiar daca proiectia are un defect, iar o sesiune care nu
            # s-a construit corect se poate reface din evenimentele ei.
            proiectat = await logins.project(
                self.db, batch, self.skip_command_accounts)
            # `commands_skipped` intra in conditie, nu doar in dictionar: un
            # deploy produce sute de loturi cu comenzi si NICIO logare, deci un
            # filtru care taie 405 777 de randuri n-ar lasa nicio urma in jurnal.
            # Un filtru tacut care intr-o zi prinde si altceva decat trebuie nu
            # s-ar vedea niciodata.
            if (proiectat["sessions_opened"] or proiectat["sessions_closed"]
                    or proiectat["commands_skipped"]):
                # `extra=`, nu argumente cu nume. `Logger._log()` nu le accepta,
                # iar exceptia cade IN bucla de ingestie: pe 25 august 2026 asta
                # a oprit colectarea pentru toate sursele, si numai atunci cand
                # chiar se deschidea o sesiune — deci a aratat intermitent.
                log.info("login sessions projected", extra=proiectat)

        # Advance cursors only after the batch they cover is committed.
        if sshd_cursor is not None:
            await events_repo.set_cursor(self.db, "sshd", sshd_cursor, events_seen=sshd_n)
        for path, new_cursor in nginx_new.items():
            self._nginx_cursors[path] = new_cursor
            if new_cursor:
                await events_repo.set_cursor(self.db, f"nginx:{path}", new_cursor)
        if eve_new is not None:
            self._eve_cursor = eve_new
            await events_repo.set_cursor(self.db, "suricata", eve_new)
        if audit_new is not None:
            self._audit_cursor = audit_new
            await events_repo.set_cursor(self.db, "auditd", audit_new)
            # Aici, lângă cursor, nu la măsurare: filigranul spune „tot ce e mai
            # vechi de atât e ÎN BAZĂ", iar asta devine adevărat abia după
            # `insert_batch`. O trecere care aruncă între citire și scriere (25
            # august 2026: fiecare lot care deschidea o sesiune) trebuie să lase
            # filigranul unde era, altfel reaper-ul închide sesiuni peste exact
            # comenzile care tocmai s-au pierdut.
            if audit_seen is not None:
                self._audit_seen_through = audit_seen
        elif audit_seen is not None:
            # Cursorul n-a mișcat, deci nu s-a citit nicio linie și nu e nimic
            # de comis: singura cale prin care se ajunge aici e coada golită,
            # unde filigranul e chiar clipa citirii. Fără ramura asta, o gazdă
            # liniștită n-ar avansa niciodată filigranul și reaper-ul ar refuza
            # pe veci — tăcut, ca înainte.
            self._audit_seen_through = audit_seen

        return len(batch)

    async def maybe_reap_sessions(self) -> int:
        """Close the login sessions whose audit session is gone from the host.

        Here rather than in the detection daemon for one measured reason:
        `sentinel-detect.service` runs with `ProtectProc=invisible`, and inside
        that sandbox the `sentinel` user sees ten processes, all its own, and
        no login session at all — see `collectors/audit_sessions.py`. This
        daemon sets no `ProtectProc` and sees all 187. It is also the process
        that opens these rows in the first place, so the fast path
        (`USER_LOGOUT` through `logins.project`) and this one write the same
        table from the same place; the summariser in the detection loop picks
        up either within one of its own passes, exactly as it does today.

        ## Ce trebuie dovedit înainte de a închide un rând

        Că nicio comandă a sesiunii ăleia nu mai stă necitită în `audit.log`.
        Altfel rezumatul pleacă numărând mai puțin decât s-a rulat, iar
        operatorul citește «71 de comenzi» despre o sesiune cu 447.

        Până pe 15 septembrie 2026 dovada era cerută pe fișierul ÎNTREG: coada
        trebuia să fie fix la capăt. Măsurat pe bucla adevărată, cu o bază fără
        nicio latență, poarta aia se deschidea de 19 ori din 28 la 20 de
        înregistrări pe secundă, de 4 din 27 la 100, și de 0 din 24 la 500 cu
        1 ms pe drum — adică se închidea exact când gazda e ocupată, care e
        exact când se loghează cineva. Și se închidea TĂCUT: nimeni nu număra
        refuzurile, deci „reaper-ul e înfometat" și „n-a murit nicio sesiune"
        erau aceeași liniște.

        Cauza nu era pragul, era întrebarea. „Fișierul e citit până la capăt?"
        e o proprietate a întregului fișier, cerută în octeți și la toleranță
        zero, pentru o hotărâre care se ia pe UN rând: o singură sesiune
        vorbăreață ținea închise toate celelalte.

        ## Întrebarea de acum

        *A fost citită coada dincolo de clipa în care m-am uitat la gazdă?*

        Scanul din `/proc` e luat la un moment anume. O sesiune care lipsea din
        el era moartă ATUNCI — procesele nu învie, iar un id de sesiune nu se
        refolosește —, deci ultima ei comandă e mai veche decât scanul. Dacă
        filigranul cozii (`_audit_seen_through`, vezi `_audit_watermark`) a
        trecut de clipa scanului, comanda aia e citită și scrisă: ordinea de
        scriere a lui auditd spune că nimic necitit nu e mai vechi decât
        filigranul.

        Ce câștigă asta față de poarta veche, spus în termeni de sarcină: sub
        trafic filigranul URCĂ ODATĂ CU ÎNREGISTRĂRILE, deci cu cât se scrie
        mai mult, cu atât dovada vine mai repede. Poarta veche cerea invers —
        o clipă în care nimeni nu scrie.

        Iar scanul care așteaptă nu se aruncă și nu se reia: absența unei
        sesiuni rămâne adevărată oricât, deci un scan vechi întârzie
        închiderea, nu o strică. Amândouă marginile ferestrei (răgazul și
        restanța) se măsoară din clipa LUI, nu din `now()` — de-asta primește
        `reap_dead_sessions` vechimea observației.

        ## Ce rămâne neacoperit, scris pe față

        Decalajul lui auditd între faptă și scrierea ei (0,34 s măsurat) când
        coada e golită și filigranul e clipa citirii. O sesiune care tace două
        minute, rulează o ultimă comandă și moare în aceeași fracțiune de
        secundă poate fi rezumată fără ea. Poarta veche avea exact aceeași
        margine, din același motiv, iar sub sarcină noua e mai strânsă: acolo
        filigranul vine din ștampilele nucleului, nu din ceasul nostru.

        Și încă una: ce s-a pierdut la o rotație nu se mai citește niciodată de
        nimeni. Nicio poartă nu poate aștepta înregistrări care nu mai există —
        vezi `nginx_tail.at_end`, unde scria greșit că „tot ce s-a scris a fost
        citit".

        ## De ce refuzul se numără și se scrie în bază

        Fiindcă un refuz care nu lasă urmă e indistinguibil de o gazdă pe care
        n-a murit nimeni, inclusiv pentru cine încearcă să-l măsoare. Starea
        pleacă în `collector_cursors` (`logins.record_reaper_state`), unde
        supraviețuiește repornirii — pe gazda de producție jurnalul e în RAM —
        și de unde o citește `check_session_reaper`.
        """
        if self._audit_path is None:
            return 0
        acum = time.monotonic()

        if self._pending_scan is None:
            if acum < self._next_reap:
                return 0
            self._next_reap = acum + REAP_INTERVAL_S
            live = read_live_sessions()
            self._pending_scan = _PendingScan(
                live, datetime.now(timezone.utc), acum)
            self._spune_starea_scanului(live)

        scan = self._pending_scan
        vazut = self._audit_seen_through
        if vazut is None or vazut < scan.taken_at:
            self._reap_deferred += 1
            intarziere = acum - scan.taken_monotonic
            # Sub răgaz, amânarea e forma NORMALĂ a porții: scanul se ia acum,
            # iar dovada vine cu trecerea următoare. Peste el, ingestia e în
            # urmă cu mai mult decât întârzie reaper-ul oricum, și asta se
            # spune — o dată, la schimbarea stării, nu la fiecare trecere.
            if intarziere >= logins.REAP_GRACE_S:
                await self._record_reap_state(logins.REAPER_WAITING, vazut)
            return 0

        self._pending_scan = None
        amanari, self._reap_deferred = self._reap_deferred, 0
        n = await logins.reap_dead_sessions(
            self.db, scan.live, acum - scan.taken_monotonic)
        await self._record_reap_state(
            logins.REAPER_WORKING if scan.live.trusted else logins.REAPER_BLIND,
            vazut)
        if n:
            log.info("dead login sessions closed",
                     extra={"count": n, "live": len(scan.live.keys),
                            # Cât de completă a fost citirea pe care s-a luat
                            # decizia. Un scan parțial orb închide o sesiune
                            # vie, iar cifra asta e singurul loc unde s-ar
                            # vedea.
                            "unreadable": scan.live.unreadable,
                            # Câte treceri a așteptat dovada. Zero e normal; un
                            # număr mare spune că ingestia abia ține pasul, și e
                            # singurul loc din jurnal unde se vede.
                            "deferred": amanari})
        return n

    def _spune_starea_scanului(self, live: LiveAuditSessions) -> None:
        """Ce a putut citi scanul, spus în jurnal o dată, la schimbare."""
        stare = "" if live.trusted else live.detail
        if stare == self._reap_state:
            return
        self._reap_state = stare
        if stare:
            # Not silent, and not fatal: sessions still close, twelve hours
            # later, through `close_stale_sessions`. What must not happen is
            # this looking the same as a host where the reaper is working.
            log.warning(
                "cannot tell which login sessions are alive; session "
                "summaries will wait for the 12h sweeper",
                # `denied` here and not in the reason: the reason is what
                # decides whether this line is printed at all, so a count
                # inside it would print one every thirty seconds. See
                # `read_live_sessions`.
                extra={"detail": live.detail, "denied": live.denied,
                       "unreadable": live.unreadable})
        else:
            log.info("live login sessions readable",
                     extra={"processes": live.scanned, "sessions": len(live.keys),
                            "unreadable": live.unreadable})

    async def _record_reap_state(self, stare: str,
                                 vazut: datetime | None) -> None:
        """Urma durabilă a reaper-ului, plus o linie de jurnal la schimbare.

        Scrisă la schimbare SAU la fiecare `REAPER_REFRESH_S`, nu la fiecare
        trecere: trecerile vin la câteva sute de milisecunde, iar un rând scris
        de cinci ori pe secundă ar fi o interogare în plus în bucla de ingestie.
        Reîmprospătarea nu e cosmetică — `updated_at` e felul în care
        `check_session_reaper` deosebește „starea asta e de acum" de „daemonul
        a murit în starea asta".
        """
        ultima = self._reap_recorded
        acum = time.monotonic()
        if (ultima is not None and ultima[0] == stare
                and acum - ultima[1] < logins.REAPER_REFRESH_S):
            return
        if ultima is None or ultima[0] != stare:
            intarziere = None if vazut is None else (
                datetime.now(timezone.utc) - vazut).total_seconds()
            if stare == logins.REAPER_WAITING:
                log.warning(
                    "session reaping deferred: the audit tail has not been "
                    "read past the moment the host was scanned",
                    extra={"deferred_passes": self._reap_deferred,
                           "watermark_lag_s": intarziere})
            elif ultima is not None:
                log.info("session reaping resumed",
                         extra={"state": stare, "watermark_lag_s": intarziere})
        self._reap_recorded = (stare, acum)
        await logins.record_reaper_state(self.db, stare, vazut)

    async def run(self, stop: asyncio.Event) -> None:
        interval = max(0.2, self.cfg.ingest.flush_interval_ms / 1000)
        total = 0
        while not stop.is_set():
            try:
                n = await self.poll_once()
                total += n
                if n:
                    log.info("ingested", extra={"batch": n, "total": total})
            except Exception as exc:  # noqa: BLE001 - one bad poll must not kill the daemon
                log.error("ingest poll failed", extra={"detail": str(exc)})
            try:
                await self.maybe_reap_sessions()
            except Exception as exc:  # noqa: BLE001 - idem: a bad scan must not stop collection
                log.error("session reaping failed", extra={"detail": str(exc)})
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)

    def close(self) -> None:
        if self._journald is not None:
            self._journald.close()
        self.geo.close()


async def _main() -> int:
    cfg = get_config()
    db = await _connect(cfg)
    ingest = Ingest(cfg, db)
    await ingest.setup()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    log.info("ingest daemon started")
    try:
        await ingest.run(stop)
    finally:
        ingest.close()
        await db.close()
    log.info("ingest daemon stopped")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parse_service_args(
        argparse.ArgumentParser(prog="sentinel ingest", add_help=False), argv)
    setup_logging("sentinel-ingest")
    try:
        return asyncio.run(_main())
    except Exception as exc:  # noqa: BLE001
        log.error("ingest failed to start", extra={"detail": str(exc)})
        return 1
