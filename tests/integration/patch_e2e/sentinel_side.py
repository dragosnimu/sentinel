"""Partea neprivilegiată a probei de capăt-la-capăt: tot ce poate face procesul
`sentinel` — botul care cere aprobarea, runner-ul care aplică, și un atacator.

Rulează ca utilizatorul `sentinel`, în containerul de probă (vezi run.sh și
tests/integration/test_patch_apply_end_to_end.py). Vorbește cu executorul REAL prin
socketul lui, ca în producție; baza de date e dublura din testele runner-ului, fiindcă
baza nu e subiectul probei. Scrie JSON pe stdout, ca testul (root) să poată afirma
fapte pe el, și log pe stderr.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, "/opt/e2e/repo")
sys.path.insert(0, "/opt/e2e/repo/executor")

from sentinel.patch import approval, runner  # noqa: E402
from sentinel.patch.validator import plan_hash  # noqa: E402
from sentinel.respond.executor_client import ExecutorClient  # noqa: E402
from tests.unit.test_patch_runner import _FakeDB  # noqa: E402

#: The family the runner is configured for; the debian harness (setup_debian.sh) sets it.
FAMILY = os.environ.get("E2E_FAMILY", "rhel")
CFG = SimpleNamespace(platform=SimpleNamespace(family=FAMILY))


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def outcome(result, db) -> dict:
    return {
        "status": result.status,
        "error": result.error,
        "unknown_outcome": result.unknown_outcome,
        "apply_verdicts": result.apply_verdicts,
        "restore_point": result.restore_point,
        "restore_path": result.restore_path,
        "plan_statuses": db.plan_statuses,
        "steps": [{"phase": s.phase, "step_id": s.step_id, "ok": s.ok, "exit_code": s.exit_code,
                   "stdout": s.stdout[-400:], "stderr": s.stderr[-600:]} for s in result.steps],
    }


def cmd_ping(_args) -> dict:
    return {"pong": ExecutorClient().ping()}


def cmd_challenge(args) -> dict:
    plan = load(args[0])
    request = asyncio.run(approval.challenge(plan, plan_hash(plan), FAMILY))
    return {"plan_hash": plan_hash(plan), "request": request}


def cmd_dryrun(args) -> dict:
    plan = load(args[0])
    db = _FakeDB(plan, status="validated")
    try:
        result = asyncio.run(runner.run_plan(db, CFG, 1, mode="dry_run"))
    except runner.PatchRefused as exc:
        return {"refused": str(exc)}
    return outcome(result, db)


def cmd_apply(args) -> dict:
    """Register the operator's token, then apply - the order the bot does it in."""
    plan, token = load(args[0]), args[1]
    try:
        registered = asyncio.run(approval.register(plan, plan_hash(plan), FAMILY, token))
    except approval.ApprovalError as exc:
        return {"registration_refused": str(exc)}
    db = _FakeDB(plan, status="approved")
    try:
        result = asyncio.run(runner.run_plan(db, CFG, 1, mode="apply", triggered_by="e2e"))
    except runner.PatchRefused as exc:
        return {"registered": registered, "refused": str(exc)}
    return {"registered": registered, **outcome(result, db)}


def cmd_apply_unregistered(args) -> dict:
    """Apply WITHOUT registering anything: what a compromised runner could try."""
    plan = load(args[0])
    db = _FakeDB(plan, status="approved")
    try:
        result = asyncio.run(runner.run_plan(db, CFG, 1, mode="apply", triggered_by="e2e-attack"))
    except runner.PatchRefused as exc:
        return {"refused": str(exc)}
    return outcome(result, db)


def cmd_attack(args) -> dict:
    """Everything an attacker who owns the `sentinel` uid can try against the approval,
    short of the docker socket (which this container does not have, and which the report
    measures separately)."""
    import hashlib
    import hmac

    client = ExecutorClient()
    found: dict = {}

    # 1. The key. Direct read, and what the executor's own gate would say.
    for path in ("/var/lib/sentinel-executor/approval.key", "/var/lib/sentinel-executor"):
        try:
            with open(path, "rb") as handle:
                found[f"read:{path}"] = "READ OK: " + handle.read(80).decode("ascii", "replace")
        except OSError as exc:
            found[f"read:{path}"] = f"denied: {exc.strerror}"

    # 2. The old key: readable, and worth nothing now.
    old_key = ""
    try:
        with open("/etc/sentinel/secrets.env", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("SENTINEL_EXECUTOR_APPROVAL_KEY="):
                    old_key = line.split("=", 1)[1].strip()
    except OSError as exc:
        found["old_key_read"] = f"denied: {exc.strerror}"
    found["old_key_readable_by_sentinel"] = bool(old_key)

    steps = [["dnf", "-y", "install", "nano"]]
    plan_hash_ = hashlib.sha256(b"attacker plan").hexdigest()
    try:
        challenge = client.call("plan_challenge", plan_hash=plan_hash_, steps=steps)
    except Exception as exc:  # noqa: BLE001
        found["challenge"] = f"refused: {exc}"
        challenge = None

    def attempt(label: str, token: str) -> None:
        try:
            client.call("register_plan", plan_hash=plan_hash_, steps=steps, ttl_s=600, approval_token=token)
            found[label] = "REGISTERED"
        except Exception as exc:  # noqa: BLE001
            found[label] = f"refused: {str(exc)[:160]}"

    if challenge is not None:
        digest = challenge["digest"]
        message = b"\n".join((b"sentinel-plan-approval-v1", plan_hash_.encode(), digest.encode(),
                              challenge["nonce"].encode()))
        # signed with the key `sentinel` CAN read (the old secrets.env one)
        attempt("forged_with_old_key", hmac.new(bytes.fromhex(old_key) if old_key else b"x", message,
                                                hashlib.sha256).hexdigest())
        # the old scheme: an HMAC of the bare plan hash
        attempt("forged_old_scheme", hmac.new(old_key.encode(), plan_hash_.encode(), hashlib.sha256).hexdigest())
        attempt("random_token", "ab" * 32)

    # 3. A real, unregistered command straight at the socket.
    for label, plan_hash_arg in (("unregistered_no_hash", None), ("unregistered_guessed_hash", plan_hash_)):
        kwargs = {"argv": ["dnf", "-y", "install", "nano"], "timeout_s": 60}
        if plan_hash_arg:
            kwargs.update(plan_hash=plan_hash_arg, step_index=0)
        try:
            client.call("patch_step_exec", **kwargs)
            found[label] = "RAN"
        except Exception as exc:  # noqa: BLE001
            found[label] = f"refused: {str(exc)[:160]}"

    # 4. Writing where the approval lives.
    for path in ("/var/lib/sentinel-executor/approval.key", "/var/lib/sentinel-executor/planted"):
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write("x")
            found[f"write:{path}"] = "WROTE"
        except OSError as exc:
            found[f"write:{path}"] = f"denied: {exc.strerror}"

    found["socket_exists"] = os.path.exists("/run/sentinel/executor.sock")
    found["uid"] = os.getuid()
    return found


def cmd_raw_challenge(args) -> dict:
    """Ask for a challenge for ARBITRARY steps (not a plan): what the executor says, in its own
    words, when it is asked to describe steps that cannot run."""
    plan_hash_, steps = args[0], json.loads(args[1])
    try:
        answer = ExecutorClient().call("plan_challenge", plan_hash=plan_hash_, steps=steps)
    except Exception as exc:  # noqa: BLE001
        return {"refused": str(exc)}
    return {"request": approval.build_request(plan_hash_, answer["digest"], answer["nonce"], steps)}


def cmd_raw_register(args) -> dict:
    plan_hash_, steps, token = args[0], json.loads(args[1]), args[2]
    try:
        out = ExecutorClient().call("register_plan", plan_hash=plan_hash_, steps=steps, ttl_s=3600,
                                    approval_token=token)
    except Exception as exc:  # noqa: BLE001
        return {"refused": str(exc)}
    return {"registered": out.get("registered")}


def cmd_exec(args) -> dict:
    """One `patch_step_exec`, exactly as given: `exec ARGV_JSON PLAN_HASH|- STEP_INDEX [dry]`."""
    argv, hash_, index = json.loads(args[0]), args[1], int(args[2])
    extra = {} if hash_ == "-" else {"plan_hash": hash_, "step_index": index}
    try:
        out = ExecutorClient().call("patch_step_exec", argv=argv, timeout_s=120, dry_run=len(args) > 3 and args[3] == "dry",
                                    socket_timeout_s=400, **extra)
    except Exception as exc:  # noqa: BLE001
        return {"refused": str(exc)}
    return {"result": out}


def cmd_register(args) -> dict:
    """Register the operator's token for a plan, and nothing else (the bot's half of an approval)."""
    plan, token = load(args[0]), args[1]
    try:
        return {"registered": asyncio.run(approval.register(plan, plan_hash(plan), FAMILY, token))}
    except approval.ApprovalError as exc:
        return {"registration_refused": str(exc)}


def cmd_spend(args) -> dict:
    """Run ONE registered step of a plan by hand - what an approval used up before the runner
    gets to it. `spend PLAN_FILE PHASE POSITION`."""
    plan, phase, position = load(args[0]), args[1], int(args[2])
    binding = approval.bind(plan, plan_hash(plan), FAMILY)
    ref = binding.for_item(phase, position)
    step = plan[phase][position]
    try:
        out = ExecutorClient().call("patch_step_exec", argv=step["argv"], timeout_s=step.get("timeout_s", 60),
                                    plan_hash=ref[0], step_index=ref[1], socket_timeout_s=400)
    except Exception as exc:  # noqa: BLE001
        return {"refused": str(exc)}
    return {"exit_code": out.get("exit_code")}


def cmd_apply_registered(args) -> dict:
    """Apply a plan whose approval was ALREADY registered (by `register`), without registering."""
    plan = load(args[0])
    db = _FakeDB(plan, status="approved")
    try:
        result = asyncio.run(runner.run_plan(db, CFG, 1, mode="apply", triggered_by="e2e"))
    except runner.PatchRefused as exc:
        return {"refused": str(exc)}
    return outcome(result, db)


def cmd_attack_restore(args) -> dict:
    """What `sentinel` can do with `backup_restore`, the one root operation that took a
    caller-chosen archive and a caller-chosen `tar`. Three shapes, each of which WROTE or LEAKED
    the approval key before the operation was refused (5 October 2026, measured in this container
    with the executor's real unit):

    * `-C /var/lib/sentinel-executor` with `approval.key` in the archive;
    * `-C /` with the protected path as an archive MEMBER (no argument names it);
    * the read: `backup_create` of `<dir sentinel owns>/link/approval.key` (`link` -> the
      executor's state), `backup_restore` into a directory sentinel made, `chmod` to open it.

    Records, per attempt, what the executor SAID; whether the key changed and whether a copy of it
    is readable is for the root-side test to check - it is the only side that can."""
    import io
    import tarfile

    client = ExecutorClient()
    found: dict = {}

    def build(path: str, members: dict) -> None:
        with tarfile.open(path, "w:gz") as handle:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))

    def call(label: str, op: str, **kwargs):
        try:
            out = client.call(op, **kwargs)
            found[label] = "ok" if out.get("ok", True) and out.get("exit_code", 0) == 0 else f"failed: {str(out)[:160]}"
            return out
        except Exception as exc:  # noqa: BLE001
            found[label] = f"refused: {str(exc)[:160]}"
            return None

    build("/dev/shm/r3-key.tgz", {"approval.key": b"ATTACKER-KEY\n"})
    call("replace_key", "backup_restore", artifact="/dev/shm/r3-key.tgz",
         restore_argv=["tar", "-xzf", "{artifact}", "-C", "/var/lib/sentinel-executor"])
    build("/dev/shm/r3-root.tgz", {"var/lib/sentinel-executor/approval.key": b"ATTACKER-KEY\n",
                                   "etc/sentinel/planted-by-restore": b"x\n",
                                   "run/sentinel/planted-by-restore": b"x\n",
                                   "var/backups/sentinel/planted-by-restore": b"x\n"})
    call("member_path", "backup_restore", artifact="/dev/shm/r3-root.tgz",
         restore_argv=["tar", "-xzf", "{artifact}", "-C", "/"])

    # The read. `d` is not sticky, so the kernel lets root follow a symlink in it; in /dev/shm itself
    # `fs.protected_symlinks` would stop root, which is a property of the kernel and not of Sentinel.
    os.makedirs("/dev/shm/r3-d", exist_ok=True)
    os.makedirs("/dev/shm/r3-out", exist_ok=True)
    os.chmod("/dev/shm/r3-out", 0o777)
    try:
        os.symlink("/var/lib/sentinel-executor", "/dev/shm/r3-d/x")
    except FileExistsError:
        pass
    made = call("exfil_archive", "backup_create", kind="path", source="/dev/shm/r3-d/x/approval.key",
                restore_point_id="e2e-attack")
    artifact = (made or {}).get("artifact") or "/var/backups/sentinel/e2e-attack/dev_shm_r3-d_x_approval_key.tar.zst"
    call("exfil_extract", "backup_restore", artifact=artifact,
         restore_argv=["tar", "--zstd", "-xf", "{artifact}", "-C", "/dev/shm/r3-out"])
    call("exfil_chmod", "backup_restore", artifact=artifact,
         restore_argv=["chmod", "-R", "755", "/dev/shm/r3-out"])

    # What `sentinel` can now read, looked for the way an attacker would.
    leaked = []
    for root, _dirs, files in os.walk("/dev/shm/r3-out"):
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as handle:
                    leaked.append((path, handle.read(80).decode("ascii", "replace")))
            except OSError:
                pass
    found["leaked_files"] = leaked
    found["uid"] = os.getuid()
    return found


COMMANDS = {"ping": cmd_ping, "challenge": cmd_challenge, "dryrun": cmd_dryrun, "apply": cmd_apply,
            "apply-unregistered": cmd_apply_unregistered, "attack": cmd_attack,
            "attack-restore": cmd_attack_restore,
            "raw-challenge": cmd_raw_challenge, "raw-register": cmd_raw_register, "exec": cmd_exec,
            "register": cmd_register, "spend": cmd_spend, "apply-registered": cmd_apply_registered}

if __name__ == "__main__":
    if os.getuid() == 0:
        sys.exit("must run as the unprivileged sentinel user")
    name, rest = sys.argv[1], sys.argv[2:]
    print(json.dumps(COMMANDS[name](rest), default=str))
