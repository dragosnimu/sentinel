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
