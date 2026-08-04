"""The complete set of privileged operations.

Eight operations, and the list is deliberately short. Every one validates its
arguments through `policy` before touching anything, and every one returns a
plain dict that the executor serialises.

Nothing here trusts its caller. The caller is `sentinel`, an unprivileged user,
but "unprivileged" is not "uncompromised": if a collector has a bug and an
attacker gets execution as `sentinel`, this file is the boundary that stops it
becoming root.

Stdlib only. No imports from the `sentinel` package — see README.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 - running commands is the job
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import policy
from policy import PolicyRefusal


def log(level: str, message: str, **fields: Any) -> None:
    """Same shape as the executor's own logger, defined here rather than
    imported: `sentinel_executor` imports this module, and importing back would
    make the one root component in the system depend on an import cycle."""
    import sys

    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "level": level, "service": "sentinel-executor", "msg": message, **fields}
    print(json.dumps(record, default=str), file=sys.stderr, flush=True)

NFT = "/usr/sbin/nft"

# The table skeleton and the persisted allowlist, both root-owned, installed
# next to this file.
#
# They exist because the table does NOT survive a reboot and nothing recreated
# it. Observed: a host came back from a reboot with no `inet sentinel` table at
# all, so seven recorded blocks were fiction and every subsequent block — manual
# or automatic — would have failed with nobody told.
#
# The allowlist is persisted; the blocklist deliberately is not. Rebooting stays
# an escape from a self-inflicted block, which is a stated guarantee of this
# design, while the addresses that must NEVER be dropped come back with the
# table rather than after it.
NFT_TABLE_FILE = "/opt/sentinel/libexec/sentinel-table.nft"
NFT_ALLOWLIST_FILE = "/opt/sentinel/libexec/sentinel-allowlist.nft"
SYSTEMCTL = "/usr/bin/systemctl"
TABLE = "inet sentinel"

BACKUP_ROOT = Path("/var/backups/sentinel")
MAX_OUTPUT_BYTES = 64 * 1024

# Redacted from captured output before it is returned, logged or stored. Better
# to over-redact a log line than to let a token reach the database and from
# there a Telegram message.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"), "sk-ant-***REDACTED***"),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b"), "***TELEGRAM_TOKEN_REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
     r"\1=***REDACTED***"),
    (re.compile(r"(?i)://[^:/@\s]+:[^@/\s]+@"), "://***:***@"),
)

# Block-rate accounting. A sliding window of timestamps rather than a counter,
# so the cap is genuinely "per minute" and not "per arbitrary reset boundary".
_block_times: list[float] = []


def _redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _run(argv: list[str], timeout: int = 30, cwd: str | None = None) -> dict[str, Any]:
    """Run a validated command. Never uses a shell. Never raises on non-zero."""
    started = time.monotonic()
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
        "TERM": "dumb",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    try:
        proc = subprocess.run(  # noqa: S603 - argv validated by policy.check_argv
            argv, capture_output=True, timeout=timeout, cwd=cwd, env=env,
            shell=False, check=False,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": _redact(proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")),
            "stderr": _redact(proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 124, "stdout": "", "stderr": f"timeout after {timeout}s",
            "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": True,
        }
    except OSError as exc:
        return {
            "exit_code": 127, "stdout": "", "stderr": _redact(str(exc)),
            "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": False,
        }


def _set_for(network: Any) -> str:
    return "blocklist_v4" if network.version == 4 else "blocklist_v6"


def _count_elements(set_name: str) -> int:
    result = _run([NFT, "list", "set", "inet", "sentinel", set_name], timeout=10)
    if result["exit_code"] != 0:
        return 0
    match = re.search(r"elements\s*=\s*\{(.*?)\}", result["stdout"], re.DOTALL)
    if not match:
        return 0
    return len([p for p in match.group(1).split(",") if p.strip()])


def _check_rate_cap(set_name: str) -> None:
    """Refuse if either cap is exceeded. A runaway detector stops here."""
    now = time.monotonic()
    _block_times[:] = [t for t in _block_times if now - t < 60]
    if len(_block_times) >= policy.MAX_BLOCKS_PER_MINUTE:
        raise PolicyRefusal(
            f"rate cap reached: {policy.MAX_BLOCKS_PER_MINUTE} blocks per minute. "
            "Refusing further blocks. A detector producing this many blocks is "
            "malfunctioning, and letting it continue would black-hole the internet "
            "one address at a time."
        )
    if _count_elements(set_name) >= policy.MAX_BLOCKLIST_ELEMENTS:
        raise PolicyRefusal(
            f"blocklist has reached the hard cap of {policy.MAX_BLOCKLIST_ELEMENTS} "
            "elements. Refusing further blocks until an operator intervenes."
        )


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------
def op_block_ip(args: dict[str, Any]) -> dict[str, Any]:
    network = policy.check_blockable(str(args.get("ip", "")))
    ttl = policy.check_ttl(args.get("ttl"))
    reason = str(args.get("reason", ""))[:200]

    set_name = _set_for(network)
    _check_rate_cap(set_name)

    element = str(network.network_address) if network.num_addresses == 1 else str(network)
    spec = f"{{ {element}" + (f" timeout {ttl}s" if ttl else "") + " }"

    result = _run([NFT, "add", "element", "inet", "sentinel", set_name, spec], timeout=10)
    if result["exit_code"] != 0:
        # The table can disappear underneath a running system — a reboot, an
        # `nft flush ruleset` from another tool, someone tidying up. Recreating
        # it at startup covers the reboot and nothing else, and the moment that
        # matters most is this one: a block being placed against a table that is
        # not there. Heal and retry once.
        healed = ensure_table()
        if healed.get("created"):
            result = _run([NFT, "add", "element", "inet", "sentinel", set_name, spec],
                          timeout=10)
            log("warning", "table was missing when placing a block; recreated and retried",
                target=element, applied=result["exit_code"] == 0)
        if result["exit_code"] != 0:
            return {"applied": False, "error": result["stderr"]}

    _block_times.append(time.monotonic())
    return {
        "applied": True,
        "target": element,
        "set": set_name,
        "ttl_seconds": ttl,
        "permanent": ttl is None,
        "reason": reason,
        "expires_at": (time.time() + ttl) if ttl else None,
    }


def op_unblock_ip(args: dict[str, Any]) -> dict[str, Any]:
    # Deliberately does NOT go through check_blockable: unblocking something
    # that policy would refuse to block is always safe, and refusing it would
    # leave an operator unable to clean up an entry added by hand.
    try:
        import ipaddress

        network = ipaddress.ip_network(str(args.get("ip", "")), strict=False)
    except ValueError as exc:
        raise PolicyRefusal(f"not a valid address: {exc}") from None

    set_name = _set_for(network)
    element = str(network.network_address) if network.num_addresses == 1 else str(network)
    result = _run([NFT, "delete", "element", "inet", "sentinel", set_name, f"{{ {element} }}"],
                  timeout=10)
    # A missing element is success: the caller wanted it gone, and it is.
    removed = result["exit_code"] == 0 or "No such file" in result["stderr"]
    return {"removed": removed, "target": element, "detail": result["stderr"] if not removed else None}


def op_allow_ip(args: dict[str, Any]) -> dict[str, Any]:
    import ipaddress

    try:
        network = ipaddress.ip_network(str(args.get("ip", "")), strict=False)
    except ValueError as exc:
        raise PolicyRefusal(f"not a valid address: {exc}") from None

    set_name = "allowlist_v4" if network.version == 4 else "allowlist_v6"
    result = _run([NFT, "add", "element", "inet", "sentinel", set_name, f"{{ {network} }}"],
                  timeout=10)
    applied = result["exit_code"] == 0
    if applied:
        # Persisted immediately. An allowlist entry that only exists in the
        # kernel is one the next reboot silently removes — and the entry an
        # operator adds by hand is usually the one that matters most.
        _persist_allowlist_entry(set_name, str(network))
    return {"applied": applied, "target": str(network),
            "error": result["stderr"] or None}


def _persist_allowlist_entry(set_name: str, element: str) -> None:
    line = f"add element inet sentinel {set_name} {{ {element} }}" + "\n"
    try:
        path = Path(NFT_ALLOWLIST_FILE)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if line in existing:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        os.chmod(path, 0o644)
    except OSError as exc:
        # Not fatal: the entry IS in the kernel and works until the next reboot.
        log("warning", "could not persist allowlist entry", element=element, error=str(exc))


def ensure_table() -> dict[str, Any]:
    """Make sure `inet sentinel` exists, loading it if it does not.

    Called at startup, before the socket accepts anything. Loads the skeleton
    and then the persisted allowlist, in that order — allowlist entries have to
    be present before anything can be dropped, which is the same ordering the
    installer uses and for the same reason.

    Blocks are NOT restored here. That is the anti-lockout guarantee: a reboot
    clears the blocklist and is therefore always a way out.
    """
    check = _run([NFT, "list", "table", "inet", "sentinel"], timeout=10)
    if check["exit_code"] == 0:
        return {"created": False}

    if not Path(NFT_TABLE_FILE).exists():
        log("error", "nftables table missing and no ruleset to load from",
            path=NFT_TABLE_FILE)
        return {"created": False, "error": "ruleset file absent"}

    loaded = _run([NFT, "-f", NFT_TABLE_FILE], timeout=30)
    if loaded["exit_code"] != 0:
        log("error", "failed to load the nftables table", error=loaded["stderr"])
        return {"created": False, "error": loaded["stderr"]}

    allow_count = 0
    if Path(NFT_ALLOWLIST_FILE).exists():
        allow = _run([NFT, "-f", NFT_ALLOWLIST_FILE], timeout=30)
        if allow["exit_code"] != 0:
            # A table with drops and no allowlist is the dangerous state, so say
            # so loudly. The blocklist is empty at this point, so nothing is
            # actually being dropped yet — but the next block would be unsafe.
            log("error", "table loaded but the allowlist did NOT",
                error=allow["stderr"])
        else:
            allow_count = sum(
                1 for line in Path(NFT_ALLOWLIST_FILE).read_text(
                    encoding="utf-8").splitlines() if line.strip())

    log("warning", "nftables table was missing and has been recreated",
        allowlist_entries=allow_count)
    return {"created": True, "allowlist_entries": allow_count}


def op_flush_blocklist(args: dict[str, Any]) -> dict[str, Any]:
    """The panic path. Must work when everything else is broken."""
    flushed = {}
    for set_name in ("blocklist_v4", "blocklist_v6"):
        before = _count_elements(set_name)
        result = _run([NFT, "flush", "set", "inet", "sentinel", set_name], timeout=10)
        flushed[set_name] = {"before": before, "ok": result["exit_code"] == 0}
    _block_times.clear()
    return {"flushed": flushed, "reason": str(args.get("reason", "manual"))[:200]}


def op_list_sets(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for set_name in ("blocklist_v4", "blocklist_v6", "allowlist_v4", "allowlist_v6",
                     "watchlist_v4", "watchlist_v6"):
        result = _run([NFT, "-j", "list", "set", "inet", "sentinel", set_name], timeout=10)
        if result["exit_code"] != 0:
            out[set_name] = {"error": result["stderr"]}
            continue
        try:
            out[set_name] = json.loads(result["stdout"])
        except json.JSONDecodeError:
            out[set_name] = {"raw": result["stdout"][:8000]}
    return out


def op_service_action(args: dict[str, Any]) -> dict[str, Any]:
    unit, action = policy.check_unit(args.get("unit"), args.get("action"))
    result = _run([SYSTEMCTL, action, unit], timeout=90)
    return {"unit": unit, "action": action, **result}


def op_read_privileged_file(args: dict[str, Any]) -> dict[str, Any]:
    path = policy.check_readable_path(args.get("path"))
    max_bytes = min(int(args.get("max_bytes", 65536)), 1_048_576)
    offset = max(0, int(args.get("offset", 0)))

    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(max_bytes)
            size = os.fstat(handle.fileno()).st_size
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "path": path,
        "offset": offset,
        "bytes_read": len(data),
        "file_size": size,
        "content": _redact(data.decode("utf-8", "replace")),
    }


def op_patch_step_exec(args: dict[str, Any]) -> dict[str, Any]:
    """Execute one step of an already-validated, already-approved patch plan.

    The plan passed `sentinel/patch/validator.py` before an operator ever saw
    it. This re-validates anyway: that validator runs on the untrusted side of
    the boundary, and a step arriving here is a request, not a fact.
    """
    argv = policy.check_argv(args.get("argv"))
    timeout = int(args.get("timeout_s", 60))
    if not 1 <= timeout <= 3600:
        raise PolicyRefusal(f"timeout_s {timeout} outside 1..3600")

    cwd = args.get("cwd")
    if cwd is not None:
        cwd = policy.check_path(cwd, purpose="run a command in")

    if args.get("dry_run"):
        return {"dry_run": True, "would_run": argv, "cwd": cwd, "timeout_s": timeout}

    result = _run(argv, timeout=timeout, cwd=cwd)
    return {"argv": argv, "cwd": cwd, **result}


def op_backup_create(args: dict[str, Any]) -> dict[str, Any]:
    """Create one backup artifact and record its checksum.

    The checksum is verified by the caller before any apply step runs — a
    corrupt backup discovered after the patch is not a backup.
    """
    import hashlib

    kind = str(args.get("kind", ""))
    source = str(args.get("source", ""))
    restore_point = re.sub(r"[^A-Za-z0-9_-]", "", str(args.get("restore_point_id", "")))[:64]
    if not restore_point:
        raise PolicyRefusal("restore_point_id is required")
    if kind not in ("path", "rpm_state", "git_ref"):
        # mysql/postgres/docker_volume need credentials and container control,
        # which the runner supplies through patch_step_exec with a validated
        # argv rather than by teaching this function about them. Keeping the
        # executor small matters more than keeping it convenient.
        raise PolicyRefusal(
            f"backup kind {kind!r} is not handled directly by the executor; the runner "
            "performs it through patch_step_exec with a validated command"
        )

    target_dir = BACKUP_ROOT / restore_point
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)

    if kind == "path":
        path = policy.check_path(source, purpose="back up")
        if not Path(path).exists():
            return {"ok": False, "error": f"{path} does not exist"}
        artifact = target_dir / (re.sub(r"[^A-Za-z0-9_-]", "_", path.strip("/")) + ".tar.zst")
        parent, name = str(Path(path).parent), Path(path).name
        result = _run(["tar", "--zstd", "-cf", str(artifact), "-C", parent, name], timeout=1800)
    elif kind == "rpm_state":
        artifact = target_dir / f"rpm-{re.sub(r'[^A-Za-z0-9_.-]', '_', source)}.txt"
        result = _run(["rpm", "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n", source],
                      timeout=30)
        artifact.write_text(result["stdout"], encoding="utf-8")
    else:  # git_ref
        repo = policy.check_path(source, purpose="back up")
        artifact = target_dir / "git-ref.txt"
        head = _run(["git", "-C", repo, "rev-parse", "HEAD"], timeout=30)
        status = _run(["git", "-C", repo, "status", "--porcelain"], timeout=30)
        artifact.write_text(f"HEAD={head['stdout'].strip()}\n\n{status['stdout']}", encoding="utf-8")
        result = head

    # Every kind, not just `path`. Checking only tar meant that `rpm -q` on a
    # package that is not installed, or `git rev-parse` in a non-repository,
    # wrote an EMPTY artifact and returned ok=True with a perfectly valid
    # checksum of nothing. A backup that captured nothing is the most dangerous
    # kind of failure: it looks like a way back right up until you need it.
    if result["exit_code"] != 0:
        return {"ok": False, "error": (result["stderr"] or
                                       f"{kind} backup of {source!r} exited "
                                       f"{result['exit_code']}")[:500]}
    if not artifact.exists() or artifact.stat().st_size == 0:
        return {"ok": False,
                "error": f"{kind} backup of {source!r} produced an empty artifact"}

    digest = hashlib.sha256()
    with open(artifact, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    os.chmod(artifact, 0o600)

    return {
        "ok": True,
        "kind": kind,
        "source": source,
        "artifact": str(artifact),
        "size_bytes": artifact.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def op_backup_finalize(args: dict[str, Any]) -> dict[str, Any]:
    """Seal a restore point: re-checksum every artifact, write manifest.json,
    and generate a standalone restore.sh.

    The script is generated HERE, from what this process can see on disk — the
    caller supplies only a restore-point id. That is deliberate: writing
    caller-supplied text into a root-owned executable file is precisely how a
    privilege boundary becomes a rootkit. Nothing crossing the socket ever
    becomes a line of this script.

    Re-checksumming rather than trusting the values the caller remembers is the
    same principle: a backup is verified by reading it back, not by believing a
    number from the other side of the boundary.
    """
    import hashlib

    restore_point = re.sub(r"[^A-Za-z0-9_-]", "", str(args.get("restore_point_id", "")))[:64]
    if not restore_point:
        raise PolicyRefusal("restore_point_id is required")
    target_dir = BACKUP_ROOT / restore_point
    if not target_dir.is_dir():
        return {"ok": False, "error": f"restore point {restore_point} does not exist"}

    items: list[dict[str, Any]] = []
    for artifact in sorted(target_dir.iterdir()):
        if not artifact.is_file() or artifact.name in ("manifest.json", "restore.sh"):
            continue
        digest = hashlib.sha256()
        with open(artifact, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        items.append({
            "artifact": artifact.name,
            "sha256": digest.hexdigest(),
            "size_bytes": artifact.stat().st_size,
            "is_archive": artifact.name.endswith(".tar.zst"),
        })

    if not items:
        return {"ok": False, "error": "restore point is empty"}

    manifest = {
        "restore_point_id": restore_point,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "items": items,
    }
    (target_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    os.chmod(target_dir / "manifest.json", 0o600)

    # Dependency-free on purpose: when this is needed, the assumption that
    # Sentinel works is the assumption that has already failed.
    lines = [
        "#!/usr/bin/env bash",
        "# Restaurare autonoma. NU are nevoie de Sentinel, Python sau PostgreSQL.",
        "#   sudo bash restore.sh",
        f"# Punct de restaurare: {restore_point}",
        "set -euo pipefail",
        'cd "$(dirname "$0")"',
        "",
        "echo '== verific integritatea inainte de a atinge ceva =='",
    ]
    for item in items:
        lines.append(
            f"echo '{item['sha256']}  {item['artifact']}' | sha256sum -c - "
            f"|| {{ echo 'ARHIVA {item['artifact']} ESTE CORUPTA - opresc'; exit 1; }}")
    lines += ["", "echo '== restaurez =='"]
    for item in items:
        if item["is_archive"]:
            lines.append(f"echo '  {item['artifact']}'")
            # Archives store paths relative to the filesystem root.
            lines.append(f"tar --use-compress-program=unzstd -xf '{item['artifact']}' -C /")
        else:
            lines.append(f"echo '  {item['artifact']}: informativ, vezi manifest.json'")
    lines += ["", "echo '== gata. Verifica: systemctl status <serviciu> =='", ""]

    script = target_dir / "restore.sh"
    script.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(script, 0o700)

    return {"ok": True, "restore_point_id": restore_point, "items": items,
            "manifest_path": str(target_dir / "manifest.json"),
            "restore_script": str(script),
            "total_bytes": sum(i["size_bytes"] for i in items)}


def op_backup_prune(args: dict[str, Any]) -> dict[str, Any]:
    """Delete ONE restore point directory.

    A dedicated operation rather than `rm -rf` through patch_step_exec, because
    `rm` is deliberately absent from the patch binary allowlist. Deletion is the
    one thing you cannot undo, so it gets the narrowest possible door:

      * the id is stripped to [A-Za-z0-9_-], so no separator survives and no
        traversal is expressible;
      * the resolved path must be a DIRECT child of BACKUP_ROOT, re-checked
        after resolution so a symlink planted in the backup root cannot redirect
        the delete somewhere else;
      * only regular files and directories below it are removed — never a
        symlink target outside the tree.
    """
    restore_point = re.sub(r"[^A-Za-z0-9_-]", "", str(args.get("restore_point_id", "")))[:64]
    if not restore_point:
        raise PolicyRefusal("restore_point_id is required")

    target = (BACKUP_ROOT / restore_point).resolve()
    root = BACKUP_ROOT.resolve()
    if target.parent != root or target == root:
        raise PolicyRefusal(
            f"refusing to delete {target}: not a direct child of {root}")
    if not target.is_dir():
        return {"ok": False, "error": f"restore point {restore_point} does not exist"}
    if target.is_symlink():
        raise PolicyRefusal("refusing to delete a symlinked restore point")

    freed = 0
    for path in target.rglob("*"):
        if path.is_file() and not path.is_symlink():
            freed += path.stat().st_size
    shutil.rmtree(target)
    return {"ok": True, "restore_point_id": restore_point, "freed_bytes": freed}


def op_backup_restore(args: dict[str, Any]) -> dict[str, Any]:
    """Replay one restore command, after verifying the artifact's checksum."""
    import hashlib

    artifact = policy.check_path(args.get("artifact"), purpose="restore from")
    expected = str(args.get("sha256", ""))
    argv = policy.check_argv(args.get("restore_argv"))

    if not Path(artifact).exists():
        return {"ok": False, "error": f"{artifact} does not exist"}

    if expected:
        digest = hashlib.sha256()
        with open(artifact, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            # Restoring from a corrupt artifact is worse than not restoring:
            # it replaces a known-broken state with an unknown one.
            raise PolicyRefusal(
                f"checksum mismatch for {artifact}: expected {expected}, "
                f"got {digest.hexdigest()}. Refusing to restore."
            )

    argv = [artifact if part == "{artifact}" else part for part in argv]
    result = _run(argv, timeout=1800)
    return {"ok": result["exit_code"] == 0, "artifact": artifact, **result}


def op_disk_free(args: dict[str, Any]) -> dict[str, Any]:
    path = policy.check_path(args.get("path", "/var/backups/sentinel"), purpose="stat")
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "path": path, "total": usage.total, "free": usage.free,
            "used_pct": round(100 * usage.used / usage.total, 2)}


def op_ping(args: dict[str, Any]) -> dict[str, Any]:
    """Liveness probe for the watchdog and the health page."""
    return {"pong": True, "pid": os.getpid(), "uptime_s": int(time.monotonic())}


OPERATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "block_ip": op_block_ip,
    "unblock_ip": op_unblock_ip,
    "allow_ip": op_allow_ip,
    "flush_blocklist": op_flush_blocklist,
    "list_sets": op_list_sets,
    "service_action": op_service_action,
    "read_privileged_file": op_read_privileged_file,
    "patch_step_exec": op_patch_step_exec,
    "backup_create": op_backup_create,
    "backup_finalize": op_backup_finalize,
    "backup_prune": op_backup_prune,
    "backup_restore": op_backup_restore,
    "disk_free": op_disk_free,
    "ping": op_ping,
}
