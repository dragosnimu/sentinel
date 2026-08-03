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
from policy import PolicyRefusal  # noqa: E402

SOCKET_PATH = os.environ.get("SENTINEL_EXECUTOR_SOCKET", "/run/sentinel/executor.sock")
AUDIT_PATH = Path("/var/lib/sentinel/executor/audit.jsonl")
SECRETS_PATH = Path("/etc/sentinel/secrets.env")
PANIC_FILE = Path("/etc/sentinel/PANIC")

MAX_REQUEST_BYTES = 256 * 1024
CLIENT_TIMEOUT_S = 120
MAX_CONCURRENT = 8

_shutdown = threading.Event()
_audit_lock = threading.Lock()
_audit_prev_hash = "0" * 64
_slots = threading.Semaphore(MAX_CONCURRENT)


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
def _load_audit_chain() -> str:
    """Resume the hash chain across restarts. A gap would look like tampering."""
    if not AUDIT_PATH.exists():
        return "0" * 64
    try:
        with open(AUDIT_PATH, "rb") as handle:
            # Read only the tail: this file grows without bound by design.
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 8192))
            last = handle.read().decode("utf-8", "replace").strip().splitlines()
        if last:
            return json.loads(last[-1]).get("entry_hash", "0" * 64)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        log("warning", "could not resume the audit chain", detail=str(exc))
    return "0" * 64


def audit(operation: str, target: str | None, params: dict[str, Any],
          result: str, detail: str | None, peer: dict[str, Any]) -> int:
    """Append one hash-chained audit record. Never raises into the request path."""
    global _audit_prev_hash

    with _audit_lock:
        entry = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seq": int(time.time() * 1000),
            "actor": f"uid:{peer.get('uid')}/pid:{peer.get('pid')}",
            "source": "executor",
            "operation": operation,
            "target": target,
            # Only argument NAMES, never values. An argument could be a path
            # containing a token, or a reason string containing anything.
            "param_keys": sorted(params.keys()),
            "result": result,
            "detail": (detail or "")[:1000] or None,
            "prev_hash": _audit_prev_hash,
        }
        material = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry["entry_hash"] = hashlib.sha256(material.encode()).hexdigest()
        _audit_prev_hash = entry["entry_hash"]

        try:
            AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(AUDIT_PATH, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
                handle.flush()
                # fsync so a power loss cannot lose the record of something
                # that already happened to the system.
                os.fsync(handle.fileno())
            os.chmod(AUDIT_PATH, 0o640)
        except OSError as exc:
            # A failed audit write must not swallow the operation's result, but
            # it must be loud: an unaudited privileged action is exactly what
            # this file exists to prevent.
            log("error", "AUDIT WRITE FAILED", operation=operation, detail=str(exc))

        return entry["seq"]


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
                 or args.get("source") or "")[:200] or None

    try:
        result = commands.OPERATIONS[op](args)
        audit_id = audit(op, target, args, "ok", None, peer)
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


def serve_client(conn: socket.socket, allowed_uid: int) -> None:
    try:
        conn.settimeout(CLIENT_TIMEOUT_S)
        peer = peer_credentials(conn)

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


def allowlist_refresher() -> None:
    """Re-resolve the never-block hostnames. Their addresses change."""
    while not _shutdown.wait(3600):
        try:
            entries = policy.refresh_runtime_allowlist(_operator_allowlist())
            log("info", "runtime allowlist refreshed", entries=len(entries))
        except Exception as exc:  # noqa: BLE001
            log("warning", "allowlist refresh failed", detail=str(exc))


def _operator_allowlist(config_path: str = "/etc/sentinel/sentinel.yaml") -> list[str]:
    """Read response.extra_allowlist without a YAML parser.

    Deliberately crude: pulling in PyYAML would mean a third-party dependency
    inside the root process, for one list of strings. (config_path is a parameter
    only so the parser can be unit-tested against both YAML styles.)
    """
    config = Path(config_path)
    if not config.exists():
        return []
    entries: list[str] = []
    in_section = False
    try:
        for raw in config.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if stripped.startswith("extra_allowlist:"):
                # Two YAML styles must both work. The installer writes the inline
                # flow list `extra_allowlist: ["203.0.113.4"]`; an operator editing by
                # hand may use the block style with `- ` items below. Parsing only
                # the block style silently dropped the admin address the installer
                # seeds inline — and a dropped allowlist entry is a lockout risk.
                rest = stripped[len("extra_allowlist:"):].strip()
                if rest.startswith("[") and rest.endswith("]"):
                    for item in rest[1:-1].split(","):
                        cleaned = item.strip().strip("\"'")
                        if cleaned:
                            entries.append(cleaned)
                    continue          # inline list is complete on this line
                in_section = True
                continue
            if in_section:
                if stripped.startswith("- "):
                    entries.append(stripped[2:].strip().strip("\"'"))
                elif stripped and not stripped.startswith("#"):
                    break
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
                 Path(__file__).parent / "commands.py"):
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

    global _audit_prev_hash
    _audit_prev_hash = _load_audit_chain()

    allowed_uid = expected_uid()
    entries = policy.refresh_runtime_allowlist(_operator_allowlist())
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

        if not _slots.acquire(blocking=False):
            # Backpressure rather than unbounded threads: a caller that opens
            # hundreds of connections must not be able to exhaust the root
            # process.
            log("warning", "connection limit reached, rejecting")
            try:
                conn.sendall(b'{"ok":false,"error":"busy"}\n')
                conn.close()
            except OSError:
                pass
            continue

        def worker(connection: socket.socket = conn) -> None:
            try:
                serve_client(connection, allowed_uid)
            finally:
                _slots.release()

        threading.Thread(target=worker, daemon=True).start()

    notify_systemd("STOPPING=1")
    try:
        socket_path.unlink()
    except OSError:
        pass
    log("info", "stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
