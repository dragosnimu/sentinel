"""Read new journal entries for a set of units, resuming from a saved cursor.

Wraps systemd.journal.Reader. Imported lazily so the rest of the package (and its
tests) load on a machine without the `systemd` module — only the ingest daemon,
which runs on the Linux host, ever constructs this.

The journald cursor is opaque and authoritative: seeking to it and stepping once
resumes exactly after the last entry we processed, with no replay and no gap.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class JournaldReader:
    def __init__(self, matches: list[dict[str, str]]):
        from systemd import journal  # noqa: PLC0415 - server-only, imported on use

        self._reader = journal.Reader()
        # Each match dict is OR-ed against the others (add_disjunction between
        # groups), the keys within a dict are AND-ed.
        first = True
        for group in matches:
            if not first:
                self._reader.add_disjunction()
            for key, value in group.items():
                self._reader.add_match(**{key: value})
            first = False
        self._positioned = False

    def seek(self, cursor: str | None) -> None:
        if cursor:
            try:
                self._reader.seek_cursor(cursor)
                self._reader.get_next()  # step past the entry AT the cursor
                self._positioned = True
                return
            except Exception:  # noqa: BLE001 - a stale cursor after log rotation
                pass
        # No cursor (or an unusable one): start at the tail so a first run does
        # not ingest the entire history of the journal in one gulp.
        self._reader.seek_tail()
        self._reader.get_previous()
        self._positioned = True

    def read_new(self, limit: int = 2000) -> list[tuple[str, datetime, str, str]]:
        """Return up to `limit` new (message, ts, cursor, comm) tuples.

        `comm` (_COMM) is carried through because one reader now serves several
        services: a bare pam_unix line is ambiguous between sudo, su and sshd,
        and only the originating process disambiguates it.
        """
        # process() before iterating: a long-running reader that polls (rather
        # than wait()s) will NOT notice journald rotating its files on its own —
        # it stays pinned to the rotated-away file and silently reads nothing new.
        # sd_journal_process (this call) is what repositions it onto the current
        # file. Without it the daemon stops seeing sshd after the first rotation,
        # exactly the failure this line prevents.
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
            if message and cursor:
                out.append((message, ts, cursor, comm))
            if len(out) >= limit:
                break
        return out

    def close(self) -> None:
        try:
            self._reader.close()
        except Exception:  # noqa: BLE001
            pass


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""
