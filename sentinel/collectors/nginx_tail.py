"""Tail nginx access logs, inode-aware, resuming from a saved offset.

The cursor is "<inode>:<offset>". Tracking the inode is what makes log rotation
safe: when logrotate moves access.log to access.log.1 and creates a fresh one,
the inode changes, so we read the new file from the start instead of seeking to
an offset that belongs to a different file. A truncated file (offset past EOF)
is treated the same way.

Pure enough to test: it reads real files, but nothing else, and returns lines
plus the new cursor rather than doing any parsing or database work.
"""

from __future__ import annotations

import glob
import os


def _inode(path: str) -> int | None:
    try:
        return os.stat(path).st_ino
    except OSError:
        return None


def read_new_lines(path: str, cursor: str | None, *, max_bytes: int = 4_000_000) -> tuple[list[str], str | None]:
    """Return (new complete lines, new cursor) for one log file.

    A partial last line (no trailing newline) is left unread — the offset stops
    at the last newline, so the next poll picks the line up whole rather than
    ingesting half a request.
    """
    inode = _inode(path)
    if inode is None:
        return [], cursor  # file gone (mid-rotation); try again next poll

    try:
        size = os.path.getsize(path)
    except OSError:
        return [], cursor

    if cursor is None:
        # First time we have ever seen this file: start at the END, like the
        # journald reader tails rather than replaying history. Backfilling a
        # multi-gigabyte access.log on first start would flood the pipeline and
        # bury today's events under weeks of old ones.
        return [], f"{inode}:{size}"

    start = 0
    try:
        c_inode_s, c_offset_s = cursor.split(":", 1)
        if int(c_inode_s) == inode:
            start = int(c_offset_s)
    except ValueError:
        start = 0
    if start > size:
        start = 0  # truncated or replaced under the same inode — reread

    if start == size:
        return [], f"{inode}:{size}"

    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            data = fh.read(min(size - start, max_bytes))
    except OSError:
        return [], cursor

    last_nl = data.rfind(b"\n")
    if last_nl == -1:
        return [], f"{inode}:{start}"  # no complete line yet
    consumed = data[: last_nl + 1]
    new_offset = start + len(consumed)
    lines = consumed.decode("utf-8", "replace").splitlines()
    return lines, f"{inode}:{new_offset}"


def at_end(path: str, cursor: str | None) -> bool:
    """True only when `cursor` names this file and stops at its current end.

    The claim is narrow on purpose, and it is worth reading twice: **at the
    instant of this call, this file holds no bytes this cursor has not read.**
    That is all. Three things it deliberately does NOT say:

      * not "everything the kernel has written has been read". A record
        generated a moment ago may still be inside auditd's queue and not yet
        in the file at all; no byte position can see it;
      * not "no record has been missed". Across a rotation this answers False
        for exactly as long as the new file is unread, and True again
        afterwards — while the records that went to the rotated file, or into
        the gap while auditd reopened it, were never read by anyone and never
        will be. A hole that has scrolled past is invisible to a size
        comparison, so "at the end" spans it without noticing;
      * not "and it is still true now". The answer describes the moment it was
        taken. A caller that measures it, then does work, then acts on the
        answer is acting on a fact about the past — see the note in
        `services/ingest_service.py` about the window that opened between a
        `getsize` at the top of a poll and one after the batch was written.

    The one caller is the audit-session watermark in
    `sentinel/services/ingest_service.py`, which uses it for what it does say:
    with no unread bytes, the moment of the read is a lower bound on how far
    the tail has been followed IN TIME. When bytes remain unread, that bound
    comes from the last record's own timestamp instead, which is the stronger
    of the two and the one that holds under load.

    Every uncertainty answers False: no cursor yet, a cursor for a different
    inode (the file rotated and the new one has not been read from the start),
    a malformed cursor, a file that cannot be stat'ed, or a trailing partial
    line the tailer deliberately left behind.
    """
    if cursor is None:
        return False
    inode = _inode(path)
    if inode is None:
        return False
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    try:
        c_inode_s, c_offset_s = cursor.split(":", 1)
        return int(c_inode_s) == inode and int(c_offset_s) == size
    except ValueError:
        return False


def expand_paths(patterns: list[str]) -> list[str]:
    """Resolve the configured globs to actual files, newest first.

    Rotated files (access.log.1) are excluded — they are history, already read
    while they were the live file.
    """
    files: list[str] = []
    for pattern in patterns:
        for p in glob.glob(pattern):
            base = os.path.basename(p)
            if base.endswith((".gz",)) or base[-1:].isdigit():
                continue
            files.append(p)
    return sorted(set(files))
