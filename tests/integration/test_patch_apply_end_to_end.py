"""Fluxul de patch, de la cerere la pachet schimbat, pe un sistem REAL.

Nu rulează în suita obișnuită: cere un container cu systemd ca PID 1 și root, și se
lansează cu `tests/integration/patch_e2e/run.sh`, care ridică un container nou, copiază
depozitul, instalează executorul sub propria lui unitate systemd (cea din
`deploy/systemd/`, nemodificată) și rulează fișierul ăsta ÎN container. Pe orice altceva
— o gazdă, un laptop, CI fără container — se sare, cu motivul. NU se rulează pe o gazdă
cu Sentinel instalat: fixture-ul refuză dacă nu e într-un container.

Ce dovedește, și de ce nu se putea dovedi altfel. Fiecare verdict al căii de pachete a
fost odată corect într-un test cu un `subprocess` înlocuit și greșit pe un sistem real:
`systemd-run --pipe` a întors 0 cu pachetul neinstalat, iar `--collect` a șters verdictul
unității. Un plan care ajunge `applied` într-un asemenea test nu spune nimic despre pachet.
Aici dovada nu e codul de ieșire al nimănui: **`rpm -q`, rulat de test, în afara
executorului**, înainte și după, cu un martor pozitiv (`rpm -q bash` trebuie să răspundă „da”
în același moment, altfel „nu e instalat” ar însemna doar că `rpm` e stricat).

Ce NU e real: `nft` e un stub (nu e pe calea probată), baza de date a runner-ului e dublura
din testele lui, și containerul n-are grupul `docker` — deci ce poate face un atacator prin
socketul docker nu se măsoară aici (e subiectul raportului despre grupul `docker`).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "executor"))
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.skipif(
    os.environ.get("SENTINEL_E2E_CONTAINER") != "1",
    reason="proba de capăt-la-capăt cere containerul cu systemd: tests/integration/patch_e2e/run.sh",
)

UNIT = "sentinel-executor"
AUDIT = Path("/var/lib/sentinel-executor/audit.jsonl")
KEY_ON_HOST = Path("/var/lib/sentinel-executor/approval.key")
SIDE = "/opt/e2e/repo/tests/integration/patch_e2e/sentinel_side.py"
PY = "/opt/e2e/venv/bin/python"
RUNUSER = "/usr/sbin/runuser"
OPERATOR_KEY = Path("/root/operator-workstation/approval.key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sh(command: str, *, check: bool = False, timeout: int = 300, input: str | None = None):
    proc = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=timeout, input=input)
    if check and proc.returncode != 0:
        raise AssertionError(f"{command!r} -> {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    return proc


def rpm_has(package: str) -> bool:
    """Whether the package is installed - asked of `rpm`, never of the executor. Positive
    control inside: `rpm -q bash` must say yes in the same breath, or "not installed"
    would only mean `rpm` is broken."""
    control = sh("rpm -q bash")
    assert control.returncode == 0, f"rpm cannot see bash, so its answer about {package} means nothing"
    return sh(f"rpm -q {package}").returncode == 0


def sentinel_side(*args: str, timeout: int = 900) -> dict:
    proc = subprocess.run([RUNUSER, "-u", "sentinel", "--", PY, "-B", SIDE, *args],
                          capture_output=True, text=True, timeout=timeout,
                          env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/home/sentinel",
                               "E2E_FAMILY": os.environ.get("E2E_FAMILY", "rhel")})
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert proc.returncode == 0 and lines, f"sentinel side failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    return json.loads(lines[-1])


def audit_rows() -> list[dict]:
    if not AUDIT.exists():
        return []
    return [json.loads(line) for line in AUDIT.read_text(encoding="utf-8").splitlines() if line.strip()]


def unit_state(name: str = "sentinel-txn.service") -> dict[str, str]:
    out = sh(f"systemctl show {name} --property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus").stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def wait_for(predicate, *, timeout: float, what: str, interval: float = 0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def make_plan(package: str, *, binary: str | None = None, post_package: str | None = None) -> dict:
    """A plan that passes the REAL validator and installs one small package, with the
    rollback that removes it. `post_package` names a package that is not installed, to
    make the post-verification fail after the install really happened."""
    from sentinel.patch.validator import validate_plan
    from tests.unit.test_patch_runner import _check, _plan, _step

    binary = binary or f"/usr/bin/{package}"
    plan = copy.deepcopy(_plan())
    plan["target"]["asset_name"] = package
    plan["vulnerabilities"][0]["package"] = package
    plan["preflight"] = [
        _check("pf_disk", {"kind": "disk_free", "path": "/var", "min_bytes": 524288000}),
        _check("pf_absent", {"kind": "file_absent", "path": binary}),
        _check("pf_notinst", {"kind": "command", "argv": ["rpm", "-q", package], "expect_exit": [1]}),
    ]
    plan["backup"][0]["source"] = "/etc/yum.repos.d"
    plan["apply"] = [_step("ap1", ["dnf", "-y", "install", package], timeout_s=600, idempotent=True)]
    plan["health_check"] = [_check("hc_file", {"kind": "file_exists", "path": binary})]
    plan["post_verification"] = [
        _check("pv_rpm", {"kind": "command", "argv": ["rpm", "-q", post_package or package], "expect_exit": [0]})]
    plan["rollback"] = [_step("rb1", ["dnf", "-y", "remove", package], on_failure="abort", timeout_s=600)]
    verdict = validate_plan(plan, platform_family="rhel")
    assert verdict.valid, [e.message for e in verdict.errors]
    return plan


def make_service_plan() -> dict:
    """A plan that changes no package: it starts `crond` (apply) and stops it (rollback). Every
    command of it runs in the executor's own sandbox - the path the replay and the refusals
    below are about - and it passes the REAL validator."""
    from sentinel.patch.validator import validate_plan
    from tests.unit.test_patch_runner import _check, _step

    plan = make_plan("tree")
    plan["target"]["asset_name"] = "crond"
    plan["vulnerabilities"][0]["package"] = "cronie"
    plan["preflight"] = [
        _check("pf_disk", {"kind": "disk_free", "path": "/var", "min_bytes": 524288000}),
        _check("pf_idle", {"kind": "systemd", "unit": "crond.service", "expect_state": "inactive"})]
    plan["apply"] = [_step("ap1", ["systemctl", "start", "crond.service"], timeout_s=60, idempotent=True)]
    plan["health_check"] = [_check("hc_up", {"kind": "systemd", "unit": "crond.service", "expect_state": "active"})]
    plan["post_verification"] = [_check("pv_up", {"kind": "systemd", "unit": "crond.service", "expect_state": "active"})]
    plan["rollback"] = [_step("rb1", ["systemctl", "stop", "crond.service"], on_failure="abort", timeout_s=60)]
    verdict = validate_plan(plan, platform_family="rhel")
    assert verdict.valid, [e.message for e in verdict.errors]
    return plan


def is_active(unit: str) -> str:
    return sh(f"systemctl is-active {unit}").stdout.strip()


def write_plan(_tmp_path: Path, plan: dict, name: str) -> str:
    """Where the unprivileged side can read it: pytest's own temporary directories are
    0700 root, which `sentinel` cannot traverse."""
    directory = Path("/opt/e2e/plans")
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    path.chmod(0o644)
    return str(path)


def operator_signs(request: str) -> str:
    """The operator's side, on the real tool: parse the request, recompute the digest,
    sign with the key that lives on the operator's workstation (a different file from the
    one on the host)."""
    from _approval_support import tool

    key = bytes.fromhex(OPERATOR_KEY.read_text(encoding="ascii").strip())
    import policy

    token, _digest = tool.make_token(policy, key, tool.parse_request(request))
    return token


def docs_enrolment_command() -> str:
    """The enrolment command EXACTLY as docs/PATCHING.md tells the operator to type it
    (minus `sudo`, because the test is root). A documented command that does not work is
    how a host ends up with no key and no idea why."""
    for line in (REPO / "docs" / "PATCHING.md").read_text(encoding="utf-8").splitlines():
        if "read -r K" in line and line.startswith("sudo "):
            return line[len("sudo "):]
    raise AssertionError("docs/PATCHING.md has no enrolment command")


# ---------------------------------------------------------------------------
# The world
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module", autouse=True)
def world():
    """Refuses to run anywhere but the throwaway container, then brings the executor up
    under its own unit with an enrolled key."""
    if not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        pytest.exit("REFUZ: nu e un container; proba asta nu rulează pe o gazdă", returncode=3)
    assert sh("ps -p 1 -o comm=").stdout.strip() == "systemd", "PID 1 nu e systemd"
    assert os.geteuid() == 0

    # The operator's workstation: a key of its own, made by the tool's own `init`.
    from _approval_support import tool

    OPERATOR_KEY.parent.mkdir(parents=True, exist_ok=True)
    OPERATOR_KEY.unlink(missing_ok=True)
    os.environ["SENTINEL_APPROVAL_KEY_FILE"] = str(OPERATOR_KEY)
    assert tool.main(["init"]) == 0
    key_hex = OPERATOR_KEY.read_text(encoding="ascii").strip()

    # Enrolment on the host: the documented command, fed the key on stdin.
    KEY_ON_HOST.unlink(missing_ok=True)
    sh(docs_enrolment_command(), check=True, input=key_hex + "\n")

    sh(f"systemctl reset-failed {UNIT}; systemctl start {UNIT}", check=True)
    wait_for(lambda: sentinel_side("ping").get("pong") is True, timeout=60, what="the executor to answer a ping")
    yield
    sh(f"systemctl stop {UNIT}")
    sh("systemctl stop crond.service")
    for package in ("tree", "bc", "nano", "telnet", "tmux"):
        sh(f"dnf -y -q remove {package}")


# ---------------------------------------------------------------------------
# Controls first
# ---------------------------------------------------------------------------
def test_the_environment_can_tell_installed_from_not_installed():
    """The controls every later claim leans on: `rpm` answers yes for something that is
    there and no for something that is not, and the repositories actually offer the
    packages the plans install. Without the last one a plan that 'installed nothing'
    could be a mirror that was never reachable."""
    assert sh("rpm -q bash").returncode == 0
    assert sh("rpm -q tree").returncode == 1, "tree is already installed; the container is not clean"
    offered = sh("dnf -q repoquery tree bc nano", timeout=300).stdout
    for package in ("tree", "bc", "nano"):
        assert package in offered, f"the repositories do not offer {package}: {offered!r}"
    assert sh("systemctl is-system-running").stdout.strip() in {"running", "degraded"}


def test_the_documented_enrolment_produced_a_root_only_key_the_executor_accepts():
    """Enrolled by the exact command in the docs. Root-owned, 0600, in a directory
    `sentinel` cannot traverse - read with the kernel, not with the executor's opinion."""
    info = KEY_ON_HOST.stat()
    assert (info.st_uid, info.st_mode & 0o777) == (0, 0o600)
    assert (Path(KEY_ON_HOST.parent).stat().st_mode & 0o777) == 0o700
    assert sh(f"{RUNUSER} -u sentinel -- test -r /var/lib/sentinel-executor/approval.key").returncode == 1
    control = sh(f"{RUNUSER} -u sentinel -- test -r /usr/bin/test")
    assert control.returncode == 0, "the probe cannot say yes, so its 'no' above means nothing"


# ---------------------------------------------------------------------------
# Gate 1 and 2, against the real executor
# ---------------------------------------------------------------------------
def test_an_attacker_who_owns_the_sentinel_uid_cannot_approve_or_run_anything(tmp_path):
    """Everything the `sentinel` account can try against the approval, on the real socket:
    read the key, sign with the key it CAN read (the old one in secrets.env), replay the old
    scheme, send an unregistered `dnf install` straight to the socket, write into the
    directory the key lives in. Nothing registers and nothing is installed - and the
    independent `rpm -q` agrees."""
    assert not rpm_has("nano")
    found = sentinel_side("attack")
    assert found["uid"] != 0
    assert found["old_key_readable_by_sentinel"] is True, (
        "control: the old key IS readable by sentinel; the attack below is real, not vacuous")
    assert found["read:/var/lib/sentinel-executor/approval.key"].startswith("denied")
    assert found["read:/var/lib/sentinel-executor"].startswith("denied")
    for attempt in ("forged_with_old_key", "forged_old_scheme", "random_token"):
        assert found[attempt].startswith("refused"), (attempt, found[attempt])
    for label in ("unregistered_no_hash", "unregistered_guessed_hash"):
        assert found[label].startswith("refused"), (label, found[label])
    for target in ("write:/var/lib/sentinel-executor/approval.key", "write:/var/lib/sentinel-executor/planted"):
        assert found[target].startswith("denied"), (target, found[target])
    assert not rpm_has("nano"), "an unapproved `dnf install nano` changed the machine"


def backup_restore_attack_leaves_the_key_alone() -> dict:
    """Run `sentinel`'s three attempts with `backup_restore` (see `sentinel_side.cmd_attack_restore`)
    and assert on the machine, read by root: the key is byte-for-byte what it was, nothing was
    planted under the root-owned directories the executor can write, and no readable copy of the
    key exists anywhere `sentinel` can look. Shared with the apt probe: same executor, same unit."""
    planted = [Path("/etc/sentinel/planted-by-restore"), Path("/run/sentinel/planted-by-restore"),
               Path("/var/backups/sentinel/planted-by-restore")]
    key = KEY_ON_HOST.read_bytes()
    # Control: the places looked at below can be seen and written by this test, so "absent"
    # afterwards means the attack did not write them and not that the check cannot see.
    for path in planted:
        path.write_text("control", encoding="ascii")
        assert path.exists(), f"cannot even see {path}, so its absence below would prove nothing"
        path.unlink()
    try:
        found = sentinel_side("attack-restore")
        assert found["uid"] != 0
        for label in ("replace_key", "member_path", "exfil_extract", "exfil_chmod"):
            assert found[label].startswith("refused"), (label, found[label])
        assert KEY_ON_HOST.read_bytes() == key, "backup_restore replaced the approval key"
        assert not [p for p in planted if p.exists()], "backup_restore wrote under a root-owned directory"
        assert found["leaked_files"] == [], f"sentinel can read what the executor extracted: {found['leaked_files']}"
        assert key.strip().decode("ascii") not in json.dumps(found), "the key reached the sentinel side"
        return found
    finally:
        sh("rm -rf /dev/shm/r3-key.tgz /dev/shm/r3-root.tgz /dev/shm/r3-d /dev/shm/r3-out /var/backups/sentinel/e2e-attack")


def test_backup_restore_cannot_replace_or_leak_the_approval_key():
    """Reproduced 5 October 2026 in this container, before the operation was refused: as `sentinel`,
    `backup_restore` with a tar from /dev/shm replaced `approval.key` (and, with `-C /`, wrote
    /etc/sentinel, /run/sentinel and a restore point's `restore.sh` as root), and a `backup_create`
    through a symlink plus an extraction plus a `chmod` handed the key itself to `sentinel`. Each
    was one call to an operation that needed neither approval nor a checksum. Gate 1 is the key; the
    operator's signature means nothing if the account it restrains can write or read it."""
    backup_restore_attack_leaves_the_key_alone()


def test_an_apply_with_no_signature_stops_at_the_first_command_and_changes_nothing(tmp_path):
    plan_file = write_plan(tmp_path, make_plan("tree"), "tree-unsigned")
    outcome = sentinel_side("apply-unregistered", plan_file)
    assert outcome.get("refused") or outcome["status"] == "aborted", outcome
    assert not rpm_has("tree")


def test_the_dry_run_is_green_only_when_the_gate_is_really_open(tmp_path):
    """A dry run reports what the real run would be refused for. Open gate: it passes.
    Then the key's mode is loosened the way a careless `chmod` would, and the very same
    dry run turns red with the executor's own reason - not green because nothing ran."""
    plan_file = write_plan(tmp_path, make_plan("tree"), "tree-dry")
    opened = sentinel_side("dryrun", plan_file)
    assert opened.get("status") == "succeeded", opened

    sh(f"chgrp sentinel {KEY_ON_HOST} && chmod 0640 {KEY_ON_HOST}", check=True)
    try:
        closed = sentinel_side("dryrun", plan_file)
    finally:
        sh(f"chown root:root {KEY_ON_HOST} && chmod 0600 {KEY_ON_HOST}", check=True)
    assert closed.get("status") == "aborted", closed
    reasons = " ".join(step["stderr"] for step in closed["steps"] if not step["ok"])
    assert "readable by the requester" in reasons or "not trusted" in reasons, reasons
    assert sentinel_side("dryrun", plan_file).get("status") == "succeeded", "the gate did not reopen"


# ---------------------------------------------------------------------------
# The six steps, for real
# ---------------------------------------------------------------------------
def test_a_signed_plan_installs_the_package_for_real_and_pid_1_says_so(tmp_path):
    """Redactare -> Validare -> Backup -> Aplicare -> Verificare, with the verdict from
    PID 1: the plan reaches `applied`, and `rpm` - asked by the test, not by the executor -
    says the package is there now and was not before."""
    plan = make_plan("tree")
    plan_file = write_plan(tmp_path, plan, "tree-apply")
    assert not rpm_has("tree"), "precondition: tree is absent"

    asked = sentinel_side("challenge", plan_file)
    token = operator_signs(asked["request"])
    first = len(audit_rows())

    outcome = sentinel_side("apply", plan_file, token)
    assert outcome.get("registered"), outcome
    assert outcome["status"] == "succeeded", json.dumps(outcome, indent=1)[:4000]
    assert "applied" in outcome["plan_statuses"]
    phases = [s["phase"] for s in outcome["steps"] if s["ok"]]
    assert phases[0] == "preflight" and "backup" in phases and "apply" in phases
    assert "health_check" in phases and phases[-1] == "post_verification"
    assert all(s["ok"] for s in outcome["steps"]), [s for s in outcome["steps"] if not s["ok"]]

    # The package really changed: asked of rpm and of the filesystem, not of the executor.
    assert rpm_has("tree"), "the plan reached 'applied' and the package is NOT installed"
    assert Path("/usr/bin/tree").exists()

    # PID 1's verdict, as the executor read it: all four facts together.
    apply_step = next(s for s in outcome["steps"] if s["phase"] == "apply")
    assert "result=success" in apply_step["stderr"] and "exec_code=1" in apply_step["stderr"]
    assert "exec_status=0" in apply_step["stderr"] and "state=active/exited" in apply_step["stderr"]
    assert "verified=True" in apply_step["stderr"]

    # The audit chain: what was approved (digest), and the transaction, start to end.
    rows = audit_rows()[first:]
    ops = [row["operation"] for row in rows]
    assert "register_plan" in ops
    register = next(row for row in rows if row["operation"] == "register_plan")
    assert json.loads(register["detail"])["steps_digest"]
    start = next(row for row in rows if row["operation"] == "transaction_start")
    end = next(row for row in rows if row["operation"] == "transaction_end")
    assert start["result"] == "ok" and end["result"] == "ok"
    detail = json.loads(end["detail"])
    assert detail["verified"] is True and detail["exit_code"] == 0 and detail["result"] == "success"
    assert ops.index("transaction_start") < ops.index("transaction_end")

    # And the unit was released: the name is free for the next transaction.
    assert unit_state()["LoadState"] == "not-found"
    # The unit's own output is in the journal, by invocation id.
    journal = sh(f"journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID={detail['invocation_id']}").stdout
    assert "tree" in journal and ("Installed" in journal or "Complete" in journal), journal[-800:]


def test_the_token_that_approved_that_plan_approves_nothing_a_second_time(tmp_path):
    """A copy of the token - a chat history, a log - must not let the same steps be
    registered again (which would reset the used-marks of an approved rollback)."""
    plan = make_plan("bc")
    plan_file = write_plan(tmp_path, plan, "bc-replay")
    asked = sentinel_side("challenge", plan_file)
    token = operator_signs(asked["request"])
    first = sentinel_side("apply", plan_file, token)
    assert first["status"] == "succeeded", json.dumps(first, indent=1)[:3000]
    assert rpm_has("bc")
    sh("dnf -y -q remove bc", check=True)
    assert not rpm_has("bc")

    again = sentinel_side("apply", plan_file, token)
    assert "registration_refused" in again, again
    assert not rpm_has("bc"), "a replayed token installed the package again"


def test_a_token_for_one_plan_does_not_let_another_plan_run(tmp_path):
    """The binding, on the real executor: the operator signs for `tree`; the same token is
    presented for a plan that installs `telnet`. Refused, and `telnet` stays absent."""
    signed_plan = make_plan("bc")
    other_plan = make_plan("telnet")
    signed_file = write_plan(tmp_path, signed_plan, "bc-signed")
    other_file = write_plan(tmp_path, other_plan, "telnet-other")
    asked = sentinel_side("challenge", signed_file)
    token = operator_signs(asked["request"])
    refused = sentinel_side("apply", other_file, token)
    assert "registration_refused" in refused, refused
    assert not rpm_has("telnet")
    assert not rpm_has("bc")


def test_a_failed_verification_rolls_the_change_back_for_real(tmp_path):
    """Revenire. The install really happens; the post-verification then fails; the runner
    rolls back with the plan's own `dnf remove`, which is a second approved transaction
    step - and `rpm` says the package is gone again."""
    plan = make_plan("bc", post_package="package-that-is-not-installed")
    plan_file = write_plan(tmp_path, plan, "bc-rollback")
    assert not rpm_has("bc")
    asked = sentinel_side("challenge", plan_file)
    token = operator_signs(asked["request"])
    first = len(audit_rows())

    outcome = sentinel_side("apply", plan_file, token)
    assert outcome["status"] == "rolled_back", json.dumps(outcome, indent=1)[:4000]
    assert "rolled_back" in outcome["plan_statuses"]
    phases = [s["phase"] for s in outcome["steps"]]
    assert "apply" in phases and "rollback" in phases
    assert not rpm_has("bc"), "the rollback reported success and the package is still installed"

    ends = [row for row in audit_rows()[first:] if row["operation"] == "transaction_end"]
    assert len(ends) == 2, "an install and a removal: two transactions, two end rows"
    assert all(json.loads(row["detail"])["verified"] for row in ends)


def test_killing_the_executor_mid_transaction_neither_loses_nor_invents_the_outcome(tmp_path):
    """The `--pipe` lesson, on the real thing. With `--pipe`, killing the client made `dnf`
    exit 0 having installed NOTHING. Here the unit has no client: the executor is SIGKILLed
    while the transaction runs, PID 1 finishes it, the package is installed, and the next
    executor finds the finished unit, writes its end row (`recovered: true`) with the verdict
    PID 1 kept, and releases the unit."""
    plan = make_plan("telnet")
    plan_file = write_plan(tmp_path, plan, "telnet-kill")
    assert not rpm_has("telnet")
    asked = sentinel_side("challenge", plan_file)
    token = operator_signs(asked["request"])
    first = len(audit_rows())

    runner = subprocess.Popen([RUNUSER, "-u", "sentinel", "--", PY, "-B", SIDE, "apply", plan_file, token],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/home/sentinel"})
    try:
        wait_for(lambda: unit_state()["LoadState"] == "loaded" and unit_state()["ActiveState"] in
                 {"active", "activating"}, timeout=240, what="the transaction unit to be running", interval=0.05)
        # SIGKILL the executor while PID 1 owns the transaction.
        sh(f"systemctl kill --signal=SIGKILL {UNIT}", check=True)
    finally:
        runner.communicate(timeout=900)

    # PID 1 finishes it without anyone watching.
    wait_for(lambda: rpm_has("telnet") or unit_state()["ActiveState"] == "failed", timeout=300,
             what="the transaction to finish under PID 1")
    assert rpm_has("telnet"), "killing the executor stopped the transaction; the unit must not depend on it"

    # The restarted executor settles the record.
    wait_for(lambda: sh(f"systemctl is-active {UNIT}").stdout.strip() == "active", timeout=60,
             what="the executor to come back")
    ends = wait_for(lambda: [row for row in audit_rows()[first:] if row["operation"] == "transaction_end"],
                    timeout=120, what="the end row")
    detail = json.loads(ends[0]["detail"])
    assert detail["recovered"] is True, detail
    assert detail["verified"] is True and detail["exit_code"] == 0 and detail["result"] == "success", detail
    wait_for(lambda: unit_state()["LoadState"] == "not-found", timeout=60, what="the unit to be released")


# ---------------------------------------------------------------------------
# Steps that have nowhere to run, and an approval that is used up
# ---------------------------------------------------------------------------
def test_a_step_with_nowhere_to_run_is_refused_at_every_stage_and_nothing_changes():
    """Reproduced against this executor on 5 October 2026 before the rule existed: a plan whose
    apply step was `mkdir /var/lib/e2e-probe-dir` passed its dry run ("would run") and failed
    with "Read-only file system" at the apply, after which the runner rolled back a machine
    nothing had touched and reported `rollback_failed`. Now the executor says no where each of
    the three can still be read - the challenge (before the operator signs), the dry run (what
    the runner shows) and the real call - and the directory is never made."""
    probe = Path("/var/lib/e2e-probe-dir")
    assert not probe.exists()
    step = ["mkdir", str(probe)]
    plan_hash = hashlib.sha256(b"e2e: mkdir").hexdigest()

    asked = sentinel_side("raw-challenge", plan_hash, json.dumps([step]))
    assert "cannot run on this host" in asked["refused"] and "Read-only file system" in asked["refused"], asked

    dry = sentinel_side("exec", json.dumps(step), "-", "0", "dry")
    assert dry["result"]["refused_because"], dry

    real = sentinel_side("exec", json.dumps(step), plan_hash, "0")
    assert "cannot run on this host" in real["refused"], real
    assert not probe.exists(), "the refused step ran"

    # The control: a step that CAN run is challenged normally, so the refusals above are about
    # the step and not about a broken harness.
    ok = sentinel_side("raw-challenge", hashlib.sha256(b"e2e: ok").hexdigest(),
                       json.dumps([["systemctl", "is-active", "crond.service"]]))
    assert ok["request"].startswith("SENTINEL-APPROVAL-V1:"), ok


def test_an_approved_step_that_runs_in_the_sandbox_runs_exactly_once():
    """Reproduced on 5 October 2026: `systemctl restart systemd-logind.service`, registered once
    with a one-hour TTL, ran on attempts 0, 1 and 2. The sandbox path only looked the step up.
    The proof is the service, asked by the test: started by the first call, stopped by the test,
    and NOT started again by the second."""
    steps = [["systemctl", "start", "crond.service"]]
    plan_hash = hashlib.sha256(b"e2e: replay").hexdigest()
    token = operator_signs(sentinel_side("raw-challenge", plan_hash, json.dumps(steps))["request"])
    assert sentinel_side("raw-register", plan_hash, json.dumps(steps), token)["registered"]

    sh("systemctl stop crond.service")
    assert is_active("crond.service") == "inactive", "precondition"
    first = sentinel_side("exec", json.dumps(steps[0]), plan_hash, "0")
    assert first["result"]["exit_code"] == 0 and is_active("crond.service") == "active", first

    sh("systemctl stop crond.service")
    for attempt in (1, 2):
        again = sentinel_side("exec", json.dumps(steps[0]), plan_hash, "0")
        assert "already been executed" in again["refused"], (attempt, again)
        assert is_active("crond.service") == "inactive", f"attempt {attempt} ran: an approval was replayed"


def test_a_first_apply_step_the_executor_refuses_ends_aborted_with_no_rollback(tmp_path):
    """The ghost, end to end: the operator's approval for the apply step was already used up (the
    executor refuses it as spent), so it never runs. The runner must say nothing changed and must
    not send the rollback - before, it rolled back a machine nobody touched and reported
    `rollback_failed`, which tells the operator to restore by hand."""
    plan = make_service_plan()
    plan_file = write_plan(tmp_path, plan, "service-spent")
    sh("systemctl stop crond.service")
    token = operator_signs(sentinel_side("challenge", plan_file)["request"])
    assert sentinel_side("register", plan_file, token)["registered"]
    spent = sentinel_side("spend", plan_file, "apply", "0")
    assert spent["exit_code"] == 0, spent
    sh("systemctl stop crond.service")

    outcome = sentinel_side("apply-registered", plan_file)
    assert outcome["status"] == "aborted", json.dumps(outcome, indent=1)[:3000]
    assert "REFUZAT" in outcome["error"] and "nu s-a făcut rollback" in outcome["error"]
    assert not [s for s in outcome["steps"] if s["phase"] == "rollback"], "a rollback was sent for a step that never ran"
    assert outcome["plan_statuses"][-1] == "failed"
    assert is_active("crond.service") == "inactive"


def test_restarting_the_executor_under_an_install_is_reported_unknown_then_finished_and_nothing_is_rolled_back(tmp_path):
    """Reproduced on 5 October 2026: `systemctl restart sentinel-executor` while the transaction
    ran. The runner read the executor's "not over, do not treat as failure" (exit 125) as a
    failure, rolled back - refused, approvals do not survive a restart - and ended
    `rollback_failed`, with the operator told to restore by hand a machine whose package `rpm`
    showed installed and whose transaction the NEW executor had recorded as finished. Now: no
    rollback, the executor is asked how it ended, and the answer - its own end row - is what the
    operator reads."""
    assert sh("dnf -q repoquery tmux", timeout=300).stdout.strip(), "the repositories do not offer tmux"
    plan = make_plan("tmux")
    plan_file = write_plan(tmp_path, plan, "tmux-restart")
    assert not rpm_has("tmux"), "precondition: tmux is absent"
    token = operator_signs(sentinel_side("challenge", plan_file)["request"])
    first = len(audit_rows())

    runner = subprocess.Popen([RUNUSER, "-u", "sentinel", "--", PY, "-B", SIDE, "apply", plan_file, token],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/home/sentinel"})
    try:
        wait_for(lambda: unit_state()["LoadState"] == "loaded" and unit_state()["ActiveState"] in
                 {"active", "activating"}, timeout=240, what="the transaction unit to be running", interval=0.05)
        sh(f"systemctl restart {UNIT}", check=True)      # SIGTERM: the executor stops waiting, the unit does not
    finally:
        stdout, stderr = runner.communicate(timeout=900)
    lines = [line for line in stdout.splitlines() if line.strip()]
    assert lines, f"the runner printed nothing:\n{stderr}"
    outcome = json.loads(lines[-1])

    wait_for(lambda: rpm_has("tmux"), timeout=300, what="the transaction to finish under PID 1")
    assert outcome["status"] == "failed", json.dumps(outcome, indent=1)[:4000]
    assert not [s for s in outcome["steps"] if s["phase"] == "rollback"], "a rollback was attempted"
    assert outcome["plan_statuses"][-1] == "failed" and "rollback_failed" not in outcome["plan_statuses"]
    verdict = outcome["unknown_outcome"]
    assert verdict["state"] == "recorded", outcome
    assert (verdict["end"]["outcome"], verdict["end"]["exit_code"], verdict["end"]["verified"]) == ("finished", 0, True)
    assert verdict["end"]["recovered"] is True, "it was the NEW executor that closed the record"
    assert "CU SUCCES" in outcome["error"] and "NECUNOSCUT" in outcome["error"]
    assert outcome["restore_point"] and outcome["restore_path"].endswith(outcome["restore_point"])

    # The executor's own chain agrees with what the operator was told.
    ends = [row for row in audit_rows()[first:] if row["operation"] == "transaction_end"]
    assert len(ends) == 1 and json.loads(ends[0]["detail"])["recovered"] is True
    wait_for(lambda: unit_state()["LoadState"] == "not-found", timeout=60, what="the unit to be released")
