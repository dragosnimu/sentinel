"""`sentinel ingest` — the collection daemon.

Long-running (systemd Type=exec, Restart=always). Every flush interval it reads
what is new since the last cursor from each source, normalises it into canonical
events, enriches with geo/ASN, writes a batch, and only then advances the cursors
— so a crash re-reads a few events rather than losing them.

Sources in this build:
  * journald — sshd/sshd-session (authentication) and sudo/su (privilege use);
  * nginx access logs (tailed, inode-aware);
  * Suricata eve.json (alerts only, engine diagnostics dropped);
  * auditd audit.log (security record types only).

Not yet collected, and deliberately marked false in config rather than claimed:
docker container logs and standalone file-integrity monitoring.

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
from collections.abc import Sequence
from pathlib import Path

from sentinel.collectors import nginx_tail
from sentinel.collectors.auditd import parse_auditd_lines
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
        if self._audit_path is not None:
            lines, new_cursor = nginx_tail.read_new_lines(self._audit_path, self._audit_cursor)
            if new_cursor != self._audit_cursor:
                audit_new = new_cursor
            # Pe lot, nu pe linie: o acțiune supravegheată produce mai multe
            # linii care împart un serial, iar cine, ce binar și pe ce fișier
            # sunt împrăștiate între ele.
            batch.extend(parse_auditd_lines(lines))

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

        return len(batch)

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
