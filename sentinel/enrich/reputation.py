"""Reputation enrichment from an in-memory snapshot of `intel_feed_entries`.

Fills `raw_events.reputation` at ingestion, the same slot `GeoEnricher` fills
for country/ASN, and for the same reason: cheap enough to sit on the busiest
path in the process, ~55 000 events/day through `sentinel-ingest`.

## Why in-memory, and measured, not guessed

A per-event query against the database was the first design considered and is
explicitly what CLAUDE.md's failure table warns about turning into: correct in
isolation, unacceptable at 55 000 calls/day layered onto a database that also
serves detect, the dashboard, and partition maintenance.

Measured with a synthetic micro-benchmark (3 000 `/24` CIDR entries — a
Spamhaus-DROP-shaped worst case, since a feed of individual hosts skips the
scan entirely, see below — against 55 000 lookups, one per average day's
event volume): a plain linear scan costs 540 µs/event — 30 s/day in
aggregate, tolerable amortized, but a burst of 5 000 events in one
`poll_once` (a real brute-force minute) would block the single-threaded
ingest loop for ~2.7 s while every OTHER collector in that same call waits.
Bucketing IPv4 CIDR entries by their first octet before scanning — every
public feed proposed in `sentinel/intel/reputation.py` publishes /8 or
narrower, so a network's first octet is fixed — cut that to 2.5 µs/event
(215×): the same burst costs ~12 ms, not 2.7 s. Individual-host entries (most
blocklists — blocklist.de is one IP per line) skip the scan machinery
entirely: a dict lookup, ~0.7 µs/event, independent of how many hosts are
loaded.

## Refreshed periodically, not on every poll

`maybe_refresh` reloads the snapshot from the database at most once per
`_RELOAD_INTERVAL_S`. `sentinel-maintenance` fetches feeds hourly (see
`sentinel/intel/reputation.py`); reloading in-memory every 5 minutes keeps this
process's view within about an hour of that without adding a query to every
`poll_once` — at a 1 s flush interval that is one query per ~300 polls, not one
per event. A reload failure (the database is briefly unreachable) keeps the
previous snapshot and tries again next interval; it never blanks the cache,
since "the feed lookup failed" and "this address has no reputation" are
different facts and only one of them should silently do nothing.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger
from sentinel.model.event import Event

log = get_logger(__name__)

_RELOAD_INTERVAL_S = 300

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ReputationEnricher:
    def __init__(self) -> None:
        # Single-address entries (the common case: most public blocklists are
        # one IP per line) — O(1), independent of how many are loaded.
        self._hosts: dict[str, list[str]] = {}
        # Genuine ranges, IPv4 only, bucketed by first octet — see module
        # docstring for the measurement behind this.
        self._buckets: dict[int, list[tuple[_IPNetwork, str]]] = {}
        # Anything that does not fit either bucket above: IPv6 ranges, or an
        # IPv4 network narrower than /8 (no feed measured here produces one,
        # but a bug or a future feed might, and silently dropping it would be
        # worse than the linear scan this list costs on the rare entry).
        self._wide: list[tuple[_IPNetwork, str]] = []
        self._loaded_monotonic: float | None = None
        self._entry_count = 0

    @property
    def available(self) -> bool:
        return bool(self._hosts or self._buckets or self._wide)

    async def maybe_refresh(self, db: Database) -> None:
        now = time.monotonic()
        if self._loaded_monotonic is not None and (now - self._loaded_monotonic) < _RELOAD_INTERVAL_S:
            return
        try:
            from sentinel.intel import reputation as intel_reputation

            rows = await intel_reputation.snapshot(db)
        except Exception as exc:  # noqa: BLE001 - a slow/unreachable db must not stop ingest
            log.warning("reputation snapshot reload failed; keeping previous data",
                        extra={"detail": str(exc)})
            # Still stamp the attempt time, or a persistently unreachable db
            # would retry every single poll instead of every interval.
            self._loaded_monotonic = now
            return
        self._load(rows)
        self._loaded_monotonic = now

    def _load(self, rows: list[tuple[str, str, int]]) -> None:
        hosts: dict[str, list[str]] = {}
        buckets: dict[int, list[tuple[_IPNetwork, str]]] = defaultdict(list)
        wide: list[tuple[_IPNetwork, str]] = []
        for net_str, category, _confidence in rows:
            try:
                net = ipaddress.ip_network(net_str)
            except ValueError:
                continue
            if (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128):
                hosts.setdefault(net.network_address.compressed, []).append(category)
            elif net.version == 4 and net.prefixlen >= 8:
                octet = int(net.network_address) >> 24
                buckets[octet].append((net, category))
            else:
                wide.append((net, category))
        self._hosts = hosts
        self._buckets = dict(buckets)
        self._wide = wide
        self._entry_count = len(rows)
        log.info("reputation snapshot loaded",
                  extra={"entries": len(rows), "hosts": len(hosts),
                         "ranges": sum(len(v) for v in buckets.values()) + len(wide)})

    def _categories(self, ip_str: str) -> list[str]:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return []
        cats = list(self._hosts.get(addr.compressed, ()))
        if addr.version == 4:
            octet = int(addr) >> 24
            for net, cat in self._buckets.get(octet, ()):
                if addr in net:
                    cats.append(cat)
        for net, cat in self._wide:
            if addr in net:
                cats.append(cat)
        return sorted(set(cats))

    def enrich(self, event: Event) -> None:
        ip = event.src_ip
        if not ip or not self.available:
            return
        cats = self._categories(ip)
        if cats:
            event.reputation = cats
