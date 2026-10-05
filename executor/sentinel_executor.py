#!/usr/bin/env python3
"""The privileged action broker. The only Sentinel process that runs as root.

Listens on a unix socket, accepts newline-delimited JSON requests from the
unprivileged `sentinel` user, validates each one against a hard-coded policy,
performs it, and writes the audit record itself.

READ executor/README.md BEFORE CHANGING ANYTHING IN THIS DIRECTORY.

Four properties, in order of how much they matter:

1. **It writes its own audit rows.** The caller never does. A compromised
   daemon can therefore neither forge an entry nor omit one for something it
   actually did.

2. **It imports nothing from the `sentinel` package.** Stdlib plus the two
   sibling modules. A compromise of the main codebase — a bad dependency, a bug
   in a collector — must not reach the process that can change the firewall.

3. **Policy is code.** Not YAML, not a database table. A database compromise
   gets an attacker the security history; it does not get them the ability to
   remove themselves from the never-block list.

4. **It stays small.** Roughly 400 lines across three files. If it grows past
   ~600, something has been added that belongs on the other side of the
   boundary.

Protocol, one JSON object per line, request and response:

    → {"id":"<uuid>","op":"block_ip","args":{"ip":"203.0.113.44","ttl":86400}}
    ← {"id":"<uuid>","ok":true,"result":{...},"audit_id":9182}
    ← {"id":"<uuid>","ok":false,"error":"refused","detail":"..."}
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import commands  # noqa: E402
import policy  # noqa: E402
import transient_unit  # noqa: E402
from policy import PolicyRefusal  # noqa: E402

SOCKET_PATH = os.environ.get("SENTINEL_EXECUTOR_SOCKET", "/run/sentinel/executor.sock")

# A sibling of /var/lib/sentinel, not a child of it — the same reason
# /var/lib/sentinel-watchdog exists next to it rather than inside it (see
# deploy/tmpfiles/sentinel.conf). /var/lib/sentinel is 0750 sentinel:sentinel:
# the sentinel user owns the PARENT directory, so it can rename or replace
# anything directly inside it, including a directory this process then cannot
# write to or recreate, because its capability set omits CAP_DAC_OVERRIDE. That
# is an argument from the permissions, reproduced in a container with a
# capability-stripped `mkdir` (tests/security/test_executor_audit_dir_posix.py);
# it is NOT an outage that was observed - on 5 October 2026 both live hosts had
# the old chain, root-owned (55.6 MB on production, 25.4 MB on n8n), and the
# current boot logged no "AUDIT WRITE FAILED". The new directory is root:root
# 0700, a permission `sentinel` cannot traverse at all, so it can neither
# redirect it with a symlink nor delete it to force a silent recreate.
AUDIT_DIR = Path("/var/lib/sentinel-executor")
AUDIT_PATH = AUDIT_DIR / "audit.jsonl"
#: Who must own the audit directory. Root, always, in production. A constant and not a
#: literal in `_prepare_audit_dir` so that the test of that function can run it
#: against a directory under `tmp_path` as an unprivileged user (chown to oneself is
#: allowed) instead of needing root and the REAL `/var/lib/sentinel-executor` - a test
#: that has to be root to run is one somebody eventually runs as root on a host that
#: has an audit chain. Nothing reads it from the environment or a request.
AUDIT_OWNER = (0, 0)
#: Where the audit chain used to live. Read once at startup, never written
#: again: if it holds a chain, its last hash becomes this process's starting
#: `prev_hash`, so migrating away from the sentinel-writable directory does
#: not look like tampering to anyone verifying the chain across the move.
LEGACY_AUDIT_PATH = Path("/var/lib/sentinel/executor/audit.jsonl")
#: Rotate before a single tail-read (see `_load_audit_chain`) would ever need
#: to scan more than a few megabytes to find the last complete line.
AUDIT_ROTATE_BYTES = 16 * 1024 * 1024
SECRETS_PATH = Path("/etc/sentinel/secrets.env")
PANIC_FILE = Path("/etc/sentinel/PANIC")

MAX_REQUEST_BYTES = 256 * 1024
#: How long a connection may sit with nothing to read before this process
#: gives up on it. This is purely an IDLE timeout — the server does not touch
#: the socket while a request is being processed (subprocess.run happens
#: entirely off the socket), so lowering it does not cut short a long patch
#: step. It only decides how fast a slot comes back after a client that opened
#: a connection and never sent anything, or never asked again.
IDLE_TIMEOUT_S = 30
MAX_CONCURRENT = 8
#: Of the total, how many the unprivileged `sentinel` uid may hold at once.
#: Leaves headroom for uid 0 (the watchdog, `ping`ing over this same socket)
#: so that a `sentinel`-side bug or an attacker who has that uid opening
#: connections and going idle cannot fill every slot and starve the process
#: whose entire job is noticing sentinel-side daemons have stopped working.
MAX_CONCURRENT_SENTINEL = 6

_shutdown = threading.Event()
_audit_lock = threading.Lock()
_audit_prev_hash = "0" * 64
#: Audit rows that did not reach disk. `audit()` never raises into the request
#: path: it logs and carries on, which is right for a firewall block and wrong for
#: a command about to run as unconfined root. The transaction path reads this
#: before and after its own row to learn whether THAT row landed.
_audit_write_failures = 0
_conn_lock = threading.Lock()
_active_total = 0
_active_by_uid: dict[int, int] = {}
_active_threads: list[threading.Thread] = []


# ---------------------------------------------------------------------------
# Logging — journald via stderr, structured, never carrying a secret
# ---------------------------------------------------------------------------
def log(level: str, message: str, **fields: Any) -> None:
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "level": level, "service": "sentinel-executor", "msg": message, **fields}
    print(json.dumps(record, default=str), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Audit — append-only, hash-chained, written here and nowhere else
# ---------------------------------------------------------------------------
#: Ceilings applied to `param_keys` before it is ever written. Nothing bounded
#: the list or the length of each name before this: an operation whose `args`
#: carried many, or long, keys could push a single audit LINE past the fixed
#: 8 KiB tail window `_load_audit_chain` used to read, so the one line that
#: mattered most — the most recent one, the one the chain resumes from — could
#: be the one line the tail read only ever saw a fragment of. Bounded here
#: instead of only widening the read window: a resume mechanism that depends
#: on "no entry is ever this large" should say so, not discover it once.
_AUDIT_PARAM_KEYS_MAX = 32
_AUDIT_PARAM_KEY_LEN_MAX = 64
#: Tail-read window for chain resume. Doubled up to this ceiling if the first
#: read does not contain a complete final line — belt and suspenders on top of
#: the cap above, not instead of it: a cap can be raised by a future change
#: without anyone remembering why 8192 was the number that made this safe.
_AUDIT_TAIL_MAX_BYTES = 1024 * 1024


def _prepare_audit_dir() -> None:
    """Create the root-only audit directory, correct its ownership/mode if
    they have drifted, and migrate the old chain the first time this runs.

    Called once, before the socket exists and before anything can be
    audited. The `chown`+`chmod` are unconditional, the same way
    systemd-tmpfiles' own `d` type re-asserts a path's owner and mode on
    every boot rather than only creating it once (see the comment on this
    directory's line in deploy/tmpfiles/sentinel.conf): self-healing a
    permission drift found on an existing directory is preferable to
    refusing to start Sentinel's whole response capability over a mistake a
    `chmod` can fix. Root running this process already has CAP_CHOWN and
    CAP_FOWNER (see the unit's CapabilityBoundingSet) specifically so this
    can happen unconditionally rather than only on first creation.

    What DOES refuse to start: `chown`/`chmod` themselves failing (`OSError`
    — e.g. those capabilities are missing), and the read-back check right
    after them, which exists as a second, independent confirmation that the
    directory that resulted from the calls above is actually what this
    process is about to trust with the one thing it guarantees — that a
    privileged operation always leaves a row behind. A call succeeding
    without producing the state it promised is exactly the kind of gap this
    file exists to not have.
    """
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        os.chown(AUDIT_DIR, *AUDIT_OWNER)
        os.chmod(AUDIT_DIR, 0o700)
    except OSError as exc:
        log("error", "cannot prepare the audit directory; refusing to start without "
            "a trustworthy place to write audit rows", path=str(AUDIT_DIR), detail=str(exc))
        raise SystemExit(1) from exc

    stat = AUDIT_DIR.stat()
    if stat.st_uid != AUDIT_OWNER[0] or (stat.st_mode & 0o777) != 0o700:
        log("error", "audit directory is not root-owned 0700 even after chown/chmod "
            "reported success; refusing to start rather than trust a directory that "
            "did not end up in the state just asked for",
            path=str(AUDIT_DIR), uid=stat.st_uid, mode=oct(stat.st_mode & 0o777))
        raise SystemExit(1)

    if not AUDIT_PATH.exists() and LEGACY_AUDIT_PATH.exists():
        # One-time migration, so chain continuity survives the move away from
        # the sentinel-writable directory. Best-effort: a failure here starts
        # a fresh chain rather than blocking startup, because the alternative
        # — refusing to run at all because an old log could not be copied —
        # is a worse outage than losing history the migration was meant to
        # preserve in the first place.
        try:
            AUDIT_PATH.write_bytes(LEGACY_AUDIT_PATH.read_bytes())
            os.chmod(AUDIT_PATH, 0o600)
            log("warning", "migrated the audit chain from the old, "
                "sentinel-writable directory", legacy=str(LEGACY_AUDIT_PATH))
        except OSError as exc:
            log("error", "could not migrate the legacy audit chain; starting a new "
                "chain instead of one that silently drops history",
                legacy=str(LEGACY_AUDIT_PATH), detail=str(exc))


def _load_audit_chain() -> str:
    """Resume the hash chain across restarts. A gap would look like tampering."""
    if not AUDIT_PATH.exists():
        return "0" * 64
    window = 8192
    try:
        size = AUDIT_PATH.stat().st_size
        while window <= _AUDIT_TAIL_MAX_BYTES:
            with open(AUDIT_PATH, "rb") as handle:
                handle.seek(max(0, size - window))
                tail = handle.read().decode("utf-8", "replace")
            lines = [line for line in tail.splitlines() if line.strip()]
            if lines:
                try:
                    return json.loads(lines[-1]).get("entry_hash", "0" * 64)
                except json.JSONDecodeError:
                    # The window very likely landed inside the last line rather
                    # than before it. Try again with more of the file, up to
                    # the ceiling, instead of accepting a truncated fragment as
                    # "no chain" — which is indistinguishable from tampering.
                    if window >= size:
                        break
                    window *= 2
                    continue
            break
    except OSError as exc:
        log("warning", "could not resume the audit chain", detail=str(exc))
        return "0" * 64
    log("warning", "could not find a complete final audit line within "
        f"{_AUDIT_TAIL_MAX_BYTES} bytes of the tail; starting a new chain link "
        "rather than guessing one")
    return "0" * 64


def _rotate_audit_if_needed() -> None:
    """Move the current file aside once it passes the size ceiling.

    Called with `_audit_lock` held, so the size check and the rename cannot
    race a concurrent append. The chain itself does not restart: the next
    entry's `prev_hash` still points at the last hash written to the old
    file, carried in the in-memory `_audit_prev_hash` regardless of which
    physical file holds it — the rotation is invisible to the chain, only to
    the filesystem.
    """
    try:
        if AUDIT_PATH.exists() and AUDIT_PATH.stat().st_size >= AUDIT_ROTATE_BYTES:
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            rotated = AUDIT_DIR / f"audit-{stamp}.jsonl"
            AUDIT_PATH.rename(rotated)
            log("info", "rotated the audit log", rotated_to=str(rotated))
    except OSError as exc:
        log("warning", "audit rotation failed; continuing to append to the same file",
            detail=str(exc))


def audit(operation: str, target: str | None, params: dict[str, Any],
          result: str, detail: str | None, peer: dict[str, Any]) -> int:
    """Append one hash-chained audit record. Never raises into the request path."""
    global _audit_prev_hash, _audit_write_failures

    with _audit_lock:
        all_keys = sorted(params.keys())
        entry = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seq": int(time.time() * 1000),
            "actor": f"uid:{peer.get('uid')}/pid:{peer.get('pid')}",
            "source": "executor",
            "operation": operation,
            "target": target,
            # Only argument NAMES, never values. An argument could be a path
            # containing a token, or a reason string containing anything.
            # Capped in count and per-key length: nothing about a request's
            # `args` is trusted, including how many keys it has.
            "param_keys": [str(k)[:_AUDIT_PARAM_KEY_LEN_MAX]
                           for k in all_keys[:_AUDIT_PARAM_KEYS_MAX]],
            "param_key_count": len(all_keys),
            "result": result,
            "detail": (detail or "")[:1000] or None,
            "prev_hash": _audit_prev_hash,
        }
        material = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry["entry_hash"] = hashlib.sha256(material.encode()).hexdigest()
        _audit_prev_hash = entry["entry_hash"]

        try:
            _rotate_audit_if_needed()
            # O_NOFOLLOW: refuse to write through a symlink planted at this
            # path. The parent directory being root:root 0700 already makes
            # planting one there impossible for anything but this process, but
            # a permission regression on the directory should not silently
            # become a permission bypass on the file too.
            fd = os.open(AUDIT_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                # fsync so a power loss cannot lose the record of something
                # that already happened to the system.
                os.fsync(handle.fileno())
            os.chmod(AUDIT_PATH, 0o600)
        except OSError as exc:
            # A failed audit write must not swallow the operation's result, but
            # it must be loud: an unaudited privileged action is exactly what
            # this file exists to prevent.
            log("error", "AUDIT WRITE FAILED", operation=operation, detail=str(exc))
            _audit_write_failures += 1

        return entry["seq"]


def _audit_transaction(event: str, result: str, detail: dict[str, Any]) -> bool:
    """The audit sink for `transient_unit`: True only if the row reached disk.

    Written by this process about itself (`uid:0`), so the row says what was
    spawned and how it ended; who asked is in the request's own row, which
    follows it. The counter is compared before and after rather than trusting
    `audit()`'s return value, which is a sequence number whether or not the write
    worked. A failure by ANOTHER thread in that window makes this answer False
    too - refusing a spawn on a false alarm, never allowing one on a false all-clear.
    """
    before = _audit_write_failures
    audit(f"transaction_{event}", transient_unit.UNIT_FULL, {}, result,
          json.dumps(detail, sort_keys=True, separators=(",", ":")),
          {"uid": 0, "pid": os.getpid()})
    return _audit_write_failures == before


def _wire_transaction_audit() -> None:
    transient_unit.configure(AUDIT_PATH, _audit_transaction, _shutdown, log)


# ---------------------------------------------------------------------------
# Peer credentials
# ---------------------------------------------------------------------------
def peer_credentials(conn: socket.socket) -> dict[str, int]:
    """SO_PEERCRED: the kernel's word on who is on the other end.

    Filesystem permissions on the socket are the first gate. This is the second,
    and it is the one that cannot be widened by a chmod.
    """
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return {"pid": pid, "uid": uid, "gid": gid}


def expected_uid() -> int:
    import pwd

    try:
        return pwd.getpwnam("sentinel").pw_uid
    except KeyError:
        log("error", "user 'sentinel' does not exist")
        raise SystemExit(78) from None


# ---------------------------------------------------------------------------
# Connection admission — per-uid, not just a flat cap
# ---------------------------------------------------------------------------
def _try_admit(uid: int, allowed_uid: int) -> bool:
    """Reserve one slot for `uid`, or refuse.

    A flat `MAX_CONCURRENT` semaphore treats every caller alike: the
    unprivileged `sentinel` uid opening up to `MAX_CONCURRENT` idle
    connections can fill every slot for up to `IDLE_TIMEOUT_S`, and during
    that window uid 0 — the watchdog `ping`ing this same socket — gets
    `busy` too. Capping `sentinel` below the total keeps at least
    `MAX_CONCURRENT - MAX_CONCURRENT_SENTINEL` slots free for everyone else,
    root included, regardless of what `sentinel` is doing.
    """
    global _active_total
    with _conn_lock:
        if _active_total >= MAX_CONCURRENT:
            return False
        if uid == allowed_uid and _active_by_uid.get(uid, 0) >= MAX_CONCURRENT_SENTINEL:
            return False
        _active_total += 1
        _active_by_uid[uid] = _active_by_uid.get(uid, 0) + 1
        return True


def _release(uid: int) -> None:
    global _active_total
    with _conn_lock:
        _active_total = max(0, _active_total - 1)
        _active_by_uid[uid] = max(0, _active_by_uid.get(uid, 0) - 1)


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------
def handle_request(payload: dict[str, Any], peer: dict[str, int]) -> dict[str, Any]:
    request_id = str(payload.get("id", ""))[:64]
    op = payload.get("op")
    args = payload.get("args", {})

    if not isinstance(op, str) or op not in commands.OPERATIONS:
        audit(str(op)[:64], None, {}, "refused", "unknown operation", peer)
        return {"id": request_id, "ok": False, "error": "unknown_operation",
                "detail": f"{op!r} is not one of {sorted(commands.OPERATIONS)}"}

    if not isinstance(args, dict):
        audit(op, None, {}, "refused", "args must be an object", peer)
        return {"id": request_id, "ok": False, "error": "bad_request",
                "detail": "args must be a JSON object"}

    target = str(args.get("ip") or args.get("unit") or args.get("path")
                 or args.get("source") or args.get("plan_hash") or "")[:200] or None

    try:
        result = commands.OPERATIONS[op](args)
        # An operation may hand back what its audit row should SAY (`audit_detail`),
        # which is for the row and not for the caller. `register_plan` uses it so
        # the chain records the digest of the commands an approval covered - the
        # argument NAMES `audit()` writes would otherwise be all it said.
        detail = result.pop("audit_detail", None) if isinstance(result, dict) else None
        audit_id = audit(op, target, args, "ok", detail if isinstance(detail, str) else None, peer)
        return {"id": request_id, "ok": True, "result": result, "audit_id": audit_id}

    except PolicyRefusal as exc:
        # Refusals are the normal, healthy outcome of the boundary working.
        # Logged at warning, audited, never retried.
        audit_id = audit(op, target, args, "refused", str(exc), peer)
        log("warning", "refused by policy", operation=op, target=target, reason=str(exc))
        return {"id": request_id, "ok": False, "error": "refused",
                "detail": str(exc), "audit_id": audit_id}

    except Exception as exc:  # noqa: BLE001 - a crash here would take root down
        audit_id = audit(op, target, args, "error", f"{type(exc).__name__}: {exc}", peer)
        log("error", "operation failed", operation=op, target=target,
            detail=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc()[:2000])
        # The exception type only. The message could contain a path, an
        # argument, or something else the unprivileged caller should not learn.
        return {"id": request_id, "ok": False, "error": "internal_error",
                "detail": type(exc).__name__, "audit_id": audit_id}


def serve_client(conn: socket.socket, allowed_uid: int, peer: dict[str, int]) -> None:
    try:
        conn.settimeout(IDLE_TIMEOUT_S)

        if peer["uid"] not in (allowed_uid, 0):
            log("warning", "rejected connection from an unexpected uid", **peer)
            audit("connect", None, {}, "refused", f"uid {peer['uid']} not permitted", peer)
            conn.sendall(b'{"ok":false,"error":"forbidden"}\n')
            return

        buffer = b""
        while not _shutdown.is_set():
            try:
                chunk = conn.recv(8192)
            except TimeoutError:
                break
            if not chunk:
                break

            buffer += chunk
            if len(buffer) > MAX_REQUEST_BYTES:
                conn.sendall(b'{"ok":false,"error":"request_too_large"}\n')
                return

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    conn.sendall(json.dumps(
                        {"ok": False, "error": "bad_json", "detail": str(exc)}
                    ).encode() + b"\n")
                    continue
                if not isinstance(payload, dict):
                    conn.sendall(b'{"ok":false,"error":"bad_request"}\n')
                    continue

                response = handle_request(payload, peer)
                conn.sendall(json.dumps(response, default=str).encode() + b"\n")

    except (OSError, BrokenPipeError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Panic watcher
# ---------------------------------------------------------------------------
def panic_watcher() -> None:
    """Flush the blocklist while /etc/sentinel/PANIC exists.

    The systemd watchdog timer is the primary mechanism; this is a second,
    independent one inside the process that actually owns the nftables sets. If
    the timer is somehow disabled, the escape hatch still works.
    """
    was_present = False
    while not _shutdown.wait(10):
        present = PANIC_FILE.exists()
        if present:
            # Flush on EVERY cycle it exists, not just the appearing edge: a
            # detector that keeps adding blocks while PANIC is up must keep
            # finding them gone. Log only on the transition to avoid spam.
            if not was_present:
                log("warning", "PANIC file detected — flushing the blocklist "
                    "every cycle until it is removed")
            try:
                result = commands.op_flush_blocklist({"reason": "PANIC file"})
                audit("flush_blocklist", None, {"reason": "panic"}, "ok",
                      json.dumps(result)[:500], {"uid": 0, "pid": os.getpid()})
            except Exception as exc:  # noqa: BLE001 - must never stop the watcher
                log("error", "panic flush failed", detail=str(exc))
        elif was_present:
            log("info", "PANIC file removed — blocking may resume")
        was_present = present


def _log_allowlist_refresh(entries: list[str]) -> None:
    """Warn when a never-block hostname resolved to nothing.

    `refresh_runtime_allowlist` treats a resolution failure as non-fatal and
    says so in its own docstring — reasonable, since refusing to start over a
    transient DNS hiccup would be worse. But silence on both ends meant that
    on a host where the resolvers are unreachable (see the executor's
    IPAddressDeny=any: nothing here would actually be able to look anything
    up), `api.telegram.org` / `api.anthropic.com` could sit permanently
    unresolved and nobody would ever be told the hard-coded protection for
    Sentinel's own alerting channel was not actually in effect.
    """
    resolved_hosts = {e.split("=", 1)[0] for e in entries if "=" in e}
    missing = [h for h in policy.NEVER_BLOCK_HOSTNAMES if h not in resolved_hosts]
    if missing:
        log("warning", "never-block hostname did not resolve to any address; "
            "it is not protected by the runtime allowlist until it does",
            hostnames=missing)


def allowlist_refresher() -> None:
    """Re-resolve the never-block hostnames. Their addresses change."""
    while not _shutdown.wait(3600):
        try:
            entries = policy.refresh_runtime_allowlist(_operator_allowlist())
            _log_allowlist_refresh(entries)
            log("info", "runtime allowlist refreshed", entries=len(entries))
        except Exception as exc:  # noqa: BLE001
            log("warning", "allowlist refresh failed", detail=str(exc))


def _yaml_unwrap_item(item: str) -> str:
    """One `extra_allowlist` value, unwrapped the way install.sh unwraps it.

    The quotes are resolved FIRST and a comment only afterwards, on what is left
    outside them. The other order turns `"203.0.113.5 # not a comment"` into the
    unbalanced `"203.0.113.5`. An unterminated quote is handed back whole rather
    than repaired into something that reads like an address, because the caller
    can name a value it does not recognise and cannot un-mangle one.
    """
    text = item.strip()
    if text[:1] in ('"', "'"):
        quote = text[0]
        end = text.find(quote, 1)
        if end != -1:
            return text[1:end]
        return text
    return text.split("#", 1)[0].strip()


def _yaml_flow_close(text: str) -> int:
    """Index of the first `]` that is not inside quotes, or -1.

    Not `endswith("]")`: `extra_allowlist: ["203.0.113.5"]  # nota` ends in a
    comment, and the reader that required the line to end in a bracket returned
    NOTHING for it while install.sh returned the entry — so the executor and the
    firewall disagreed about who was allowlisted.
    """
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in ('"', "'"):
            quote = char
        elif char == "]":
            return index
    return -1


def _yaml_flow_items(text: str) -> list[str]:
    """Split on commas that are not inside quotes."""
    items: list[str] = []
    current = ""
    quote = ""
    for char in text:
        if quote:
            current += char
            if char == quote:
                quote = ""
        elif char in ('"', "'"):
            current += char
            quote = char
        elif char == ",":
            items.append(current)
            current = ""
        else:
            current += char
    items.append(current)
    return items


def _operator_allowlist(config_path: str = "/etc/sentinel/sentinel.yaml") -> list[str]:
    """Read response.extra_allowlist without a YAML parser.

    Deliberately crude: pulling in PyYAML would mean a third-party dependency
    inside the root process, for one list of strings. (config_path is a parameter
    only so the parser can be unit-tested against both YAML styles.)

    Crude, but not DIFFERENT from the installer. deploy/install.sh reads the same
    key out of the same file in awk, and the two used to disagree: a trailing
    `# nota` after a flow list made this one return an empty list while the
    installer returned the entries, so the executor treated as blockable an
    address the firewall had allowlisted. tests/unit/test_allowlist_v6.py runs
    both readers over one fixture table and asserts they agree; the helpers above
    are this side of that contract.

    Anchored under a top-level `response:` for the same reason as the installer:
    sentinel.yaml already carries an unrelated `ip_allowlist` under `web:`, and
    an `extra_allowlist:` added there some day must not silently become firewall
    policy.
    """
    config = Path(config_path)
    if not config.exists():
        return []
    entries: list[str] = []
    in_response = False
    in_section = False
    try:
        for raw in config.read_text(encoding="utf-8").splitlines():
            if raw[:1] not in ("", " ", "\t", "#"):
                # A line beginning in column 0 closes whatever top-level block
                # was open and opens another. `raw.split()[0]` is awk's `$1`, so
                # `response:` and `response:  # x` are the block and
                # `responses:` is not.
                fields = raw.split()
                in_response = bool(fields) and fields[0] == "response:"
                in_section = False
                continue
            stripped = raw.strip()
            if in_response and stripped.startswith("extra_allowlist:"):
                rest = stripped[len("extra_allowlist:"):].strip()
                if rest.startswith("["):
                    close = _yaml_flow_close(rest[1:])
                    if close >= 0:
                        for item in _yaml_flow_items(rest[1:1 + close]):
                            value = _yaml_unwrap_item(item)
                            if value:
                                entries.append(value)
                    # No unquoted "]" on this line: the flow sequence continues
                    # where neither reader follows. Nothing is taken from it,
                    # which is what install.sh does too — it also warns, and it
                    # can, because it has an operator watching it run.
                    in_section = False
                    continue
                in_section = True
                continue
            if in_section:
                if stripped.startswith("#"):
                    # A commented-out entry stays out, and does not end the
                    # block either: that is how an operator parks one.
                    continue
                if stripped.startswith("-") and stripped[1:2] in (" ", "\t"):
                    value = _yaml_unwrap_item(stripped[1:])
                    if value:
                        entries.append(value)
                elif stripped:
                    in_section = False
    except OSError:
        pass
    return entries


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def notify_systemd(state: str) -> None:
    """sd_notify without the systemd python bindings."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(state.encode())
    except OSError:
        pass


def preflight() -> None:
    if os.geteuid() != 0:
        log("error", "the executor must run as root")
        raise SystemExit(1)

    # If this file is writable by the sentinel user, the privilege split is a
    # fiction: whoever can write it can execute arbitrary code as root.
    for path in (Path(__file__), Path(__file__).parent / "policy.py",
                 Path(__file__).parent / "commands.py",
                 Path(__file__).parent / "transient_unit.py"):
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_uid != 0:
            log("error", "executor file is not owned by root", path=str(path), uid=stat.st_uid)
            raise SystemExit(1)
        if stat.st_mode & 0o022:
            log("error", "executor file is group- or world-writable", path=str(path),
                mode=oct(stat.st_mode & 0o777))
            raise SystemExit(1)

    if SECRETS_PATH.exists() and SECRETS_PATH.stat().st_mode & 0o007:
        log("warning", "secrets.env is world-readable", mode=oct(SECRETS_PATH.stat().st_mode & 0o777))


def main() -> int:
    preflight()
    _prepare_audit_dir()

    global _audit_prev_hash
    _audit_prev_hash = _load_audit_chain()
    # Before the socket exists: the first request of a fresh process must find the
    # transaction path wired, not refused for a reason nobody would look for.
    _wire_transaction_audit()
    # A package transaction lives in a unit PID 1 owns, so it can outlive the
    # process that started it. Settle what the previous executor left - record a
    # finished one, follow a running one - before a new request can start another.
    log("info", "package transaction state at startup", status=transient_unit.recover())

    # Before anything can be blocked, there has to be somewhere to put it.
    # A host that reboots comes back with no `inet sentinel` table, and every
    # block against a missing table fails — which is how this deployment spent a
    # day believing it had seven addresses blocked while the kernel had none.
    table = commands.ensure_table()
    if table.get("created"):
        log("warning", "recreated the nftables table at startup", **table)

    allowed_uid = expected_uid()
    entries = policy.refresh_runtime_allowlist(_operator_allowlist())
    _log_allowlist_refresh(entries)
    log("info", "starting", socket=SOCKET_PATH, allowed_uid=allowed_uid,
        allowlist_entries=len(entries), operations=len(commands.OPERATIONS))

    import grp

    socket_path = Path(SOCKET_PATH)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    # The runtime directory must be TRAVERSABLE by the sentinel group. The
    # socket's own 660 root:sentinel is necessary but not sufficient — reaching a
    # socket requires +x on every directory in its path, and a default mkdir
    # leaves /run/sentinel as 750 root:root, which a sentinel-user client cannot
    # enter. Without this the web and telegram services get "permission denied"
    # before they even touch the socket.
    try:
        _sentinel_gid = grp.getgrnam("sentinel").gr_gid
        os.chown(str(socket_path.parent), 0, _sentinel_gid)
        os.chmod(str(socket_path.parent), 0o750)
    except (KeyError, OSError) as exc:
        log("warning", "could not set runtime dir group ownership", detail=str(exc))

    if socket_path.exists():
        socket_path.unlink()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Bind under a restrictive umask so there is no window in which the socket
    # is world-writable between bind() and chmod().
    old_umask = os.umask(0o007)
    try:
        server.bind(str(socket_path))
    finally:
        os.umask(old_umask)

    try:
        os.chown(str(socket_path), 0, grp.getgrnam("sentinel").gr_gid)
    except (KeyError, OSError) as exc:
        log("warning", "could not set socket group ownership", detail=str(exc))
    os.chmod(str(socket_path), 0o660)
    server.listen(16)

    def shutdown(signum: int, _frame: object) -> None:
        log("info", "shutting down", signal=signum)
        _shutdown.set()
        try:
            server.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    threading.Thread(target=panic_watcher, daemon=True, name="panic").start()
    threading.Thread(target=allowlist_refresher, daemon=True, name="allowlist").start()

    notify_systemd("READY=1")
    log("info", "ready")

    while not _shutdown.is_set():
        try:
            conn, _ = server.accept()
        except OSError:
            if _shutdown.is_set():
                break
            continue

        try:
            peer = peer_credentials(conn)
        except OSError as exc:
            log("warning", "could not read peer credentials, rejecting", detail=str(exc))
            try:
                conn.close()
            except OSError:
                pass
            continue

        if not _try_admit(peer["uid"], allowed_uid):
            # Backpressure rather than unbounded threads: a caller that opens
            # hundreds of connections must not be able to exhaust the root
            # process. Per-uid, not just a flat cap — see _try_admit.
            log("warning", "connection limit reached, rejecting", uid=peer["uid"])
            try:
                conn.sendall(b'{"ok":false,"error":"busy"}\n')
                conn.close()
            except OSError:
                pass
            continue

        def worker(connection: socket.socket = conn, connection_peer: dict[str, int] = peer) -> None:
            try:
                serve_client(connection, allowed_uid, connection_peer)
            finally:
                _release(connection_peer["uid"])
                # Self-removal, not periodic cleanup: this process is meant to
                # run for months, and a list that only ever grows would be a
                # slow leak that only shows up long after the change that
                # caused it.
                with _conn_lock:
                    current = threading.current_thread()
                    if current in _active_threads:
                        _active_threads.remove(current)

        thread = threading.Thread(target=worker, daemon=True)
        with _conn_lock:
            _active_threads.append(thread)
        thread.start()

    # Stop accepting, but do not exit out from under work already in flight:
    # every one of these threads is daemon=True, so falling through to
    # process exit here would kill a mid-step subprocess without ever letting
    # `handle_request` write its audit row — the exact "SIGTERM mid-step not
    # audited" gap. Joining them means a normal `systemctl stop` waits for
    # in-flight operations to actually finish (bounded by the unit's own
    # TimeoutStopSec, after which systemd sends SIGKILL regardless — nothing
    # in this process can extend past that).
    log("info", "no longer accepting connections; draining requests in flight")
    with _conn_lock:
        threads_to_join = list(_active_threads)
    for thread in threads_to_join:
        thread.join()
    if threads_to_join:
        log("info", "drained requests in flight", count=len(threads_to_join))

    notify_systemd("STOPPING=1")
    try:
        socket_path.unlink()
    except OSError:
        pass
    log("info", "stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
