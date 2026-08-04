"""Read new journal entries for a set of units, resuming from a saved cursor.

Wraps systemd.journal.Reader. Imported lazily so the rest of the package (and its
tests) load on a machine without the `systemd` module — only the ingest daemon,
which runs on the Linux host, ever constructs this.

The journald cursor is opaque and authoritative: seeking to it and stepping once
resumes exactly after the last entry we processed, with no replay and no gap.

## Why this rebuilds itself

A long-lived Reader can stop yielding entries and never recover. Observed in
production: the daemon read normally for an hour after start, then returned zero
entries on every poll for 21 hours while the journal kept filling. The service
stayed `active`, restarted zero times, logged no error, and the other three
collectors in the same poll loop stayed current — so the only symptom was that
SSH authentication had silently stopped being watched.

The cursor was fine. A *fresh* Reader seeking to that same cursor returned
entries immediately, and restarting the daemon caught the whole backlog up. The
fault is in the reader object, not in the position — which is why the fix is to
notice the silence and build a new one.

`process()` alone does not cover it. It is documented as the way to pick up
rotation, it is called on every read below, and it did not help.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Consecutive empty reads before the reader is assumed stuck and rebuilt.
#
# At the default poll interval this is well under a minute, which bounds how
# long authentication can go unwatched. It cannot be 1: a quiet journal
# legitimately returns nothing, and rebuilding on every idle poll would seek
# constantly for no reason. It cannot be large either — nobody notices this
# failure from the outside, so the recovery has to be automatic and quick.
REBUILD_AFTER_EMPTY_POLLS = 60


class JournaldReader:
    def __init__(self, matches: list[dict[str, str]]):
        self._matches = matches
        self._cursor: str | None = None
        self._empty_polls = 0
        self._rebuilds = 0
        self._reader = self._build()
        self._positioned = False

    def _build(self) -> Any:
        from systemd import journal  # noqa: PLC0415 - server-only, imported on use

        reader = journal.Reader()
        # Each match dict is OR-ed against the others (add_disjunction between
        # groups), the keys within a dict are AND-ed.
        first = True
        for group in self._matches:
            if not first:
                reader.add_disjunction()
            for key, value in group.items():
                reader.add_match(**{key: value})
            first = False
        return reader

    def seek(self, cursor: str | None) -> None:
        if cursor:
            try:
                self._reader.seek_cursor(cursor)
                self._reader.get_next()  # step past the entry AT the cursor
                self._cursor = cursor
                self._positioned = True
                return
            except Exception:  # noqa: BLE001 - a stale cursor after log rotation
                pass
        # No cursor (or an unusable one): start at the tail so a first run does
        # not ingest the entire history of the journal in one gulp.
        self._reader.seek_tail()
        self._reader.get_previous()
        self._positioned = True

    def _rebuild(self) -> None:
        """Replace the underlying reader and resume from the last cursor.

        Deliberately keeps the cursor: the point is to discard the reader
        object, not the position. Falling back to the tail here would silently
        drop every entry written while the reader was stuck, turning a
        recoverable fault into a permanent hole in the record.
        """
        self._rebuilds += 1
        log.error("journald reader produced nothing for %d polls; rebuilding",
                  self._empty_polls,
                  extra={"rebuilds": self._rebuilds,
                         "resuming_from_cursor": bool(self._cursor)})
        try:
            self._reader.close()
        except Exception:  # noqa: BLE001
            pass
        self._reader = self._build()
        self.seek(self._cursor)
        self._empty_polls = 0

    def read_new(self, limit: int = 2000) -> list[tuple[str, datetime, str, str]]:
        """Return up to `limit` new (message, ts, cursor, comm) tuples.

        `comm` (_COMM) is carried through because one reader now serves several
        services: a bare pam_unix line is ambiguous between sudo, su and sshd,
        and only the originating process disambiguates it.
        """
        if self._cursor and self._empty_polls >= REBUILD_AFTER_EMPTY_POLLS:
            self._rebuild()

        # process() before iterating: a long-running reader that polls (rather
        # than wait()s) will NOT notice journald rotating its files on its own —
        # it stays pinned to the rotated-away file and silently reads nothing new.
        # sd_journal_process (this call) is what repositions it onto the current
        # file. Necessary, and by itself not sufficient — see the module
        # docstring for the failure it does not cover.
        try:
            self._reader.process()
        except Exception:  # noqa: BLE001
            pass

        out: list[tuple[str, datetime, str, str]] = []
        for entry in self._reader:
            message = _as_text(entry.get("MESSAGE"))
            ts = entry.get("__REALTIME_TIMESTAMP") or datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            cursor = entry.get("__CURSOR", "")
            comm = _as_text(entry.get("_COMM"))
            if cursor:
                # Tracked even for entries that are not returned. This cursor is
                # what a rebuild resumes from, so it has to record what has been
                # LOOKED at; tying it to what was stored would re-read the same
                # uninteresting entries after every rebuild.
                self._cursor = cursor
            if message and cursor:
                out.append((message, ts, cursor, comm))
            if len(out) >= limit:
                break

        self._empty_polls = 0 if out else self._empty_polls + 1
        return out

    @property
    def empty_polls(self) -> int:
        """Consecutive polls that returned nothing. Exposed for health checks."""
        return self._empty_polls

    @property
    def rebuilds(self) -> int:
        """How often this reader had to be replaced. Non-zero is worth seeing:
        it means the failure above is happening on this host."""
        return self._rebuilds

    def close(self) -> None:
        try:
            self._reader.close()
        except Exception:  # noqa: BLE001
            pass


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""
