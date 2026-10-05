"""Fluxul de patch pe familia `debian` (apt), pe un sistem REAL: Ubuntu cu systemd ca PID 1.

Geamănul probei din `test_patch_apply_end_to_end.py`, pentru gazda care n-are `dnf`: pe n8n
`apt-get` e singurul manager de pachete, deci o cale de pachete care nu merge pe apt înseamnă o
gazdă pe care NU se poate aplica nimic. Executorul a rulat până acum doar `dnf` printr-o unitate
tranzitorie; `apt-get install` ajungea în sandbox-ul de numai-citire și pica cu cod 100 la
/var/cache/apt/archives/partial (`is_transaction(['apt-get', ...])` era `False`).

Se lansează cu `E2E_DISTRO=debian tests/integration/patch_e2e/run.sh`, care ridică un container
nou (imaginea din `patch_e2e/Dockerfile.debian`), copiază depozitul, instalează executorul sub
propria lui unitate și rulează fișierul ăsta ÎN container. Pe orice altceva se sare.

Dovada nu e codul de ieșire al nimănui: `dpkg-query`, rulat de test în afara executorului, înainte
și după, cu un martor pozitiv (`dpkg-query -W bash` trebuie să spună „da” în același moment).

Ce NU e real: `nft` e un stub, imaginea e Ubuntu 24.04 (gazda are 26.04), și nu e încercat un
pachet cu întrebări debconf.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "executor"))
sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.skipif(
    os.environ.get("SENTINEL_E2E_CONTAINER") != "1" or shutil.which("dpkg-query") is None,
    reason="proba apt cere containerul Ubuntu cu systemd: E2E_DISTRO=debian tests/integration/patch_e2e/run.sh",
)

if os.environ.get("SENTINEL_E2E_CONTAINER") == "1":
    os.environ.setdefault("E2E_FAMILY", "debian")

from tests.integration.test_patch_apply_end_to_end import (  # noqa: E402
    KEY_ON_HOST,
    OPERATOR_KEY,
    UNIT,
    audit_rows,
    backup_restore_attack_leaves_the_key_alone,
    docs_enrolment_command,
    operator_signs,
    sentinel_side,
    sh,
    unit_state,
    wait_for,
    write_plan,
)

PACKAGE = "tree"
BINARY = "/usr/bin/tree"


def dpkg_has(package: str) -> bool:
    """Whether the package is installed - asked of `dpkg-query`, never of the executor. Positive
    control inside: `dpkg-query -W bash` must say yes in the same breath, or "not installed" would
    only mean `dpkg-query` is broken."""
    assert sh("dpkg-query -W -f='${Status}' bash").stdout.strip() == "install ok installed", (
        "dpkg-query cannot see bash, so its answer about " + package + " means nothing")
    return sh(f"dpkg-query -W -f='${{Status}}' {package}").stdout.strip() == "install ok installed"


def candidate(package: str) -> str:
    """The version `apt-get install` would take, from the package index - the pin a real Debian plan
    carries (`pkg=version`)."""
    out = sh(f"apt-cache policy {package}").stdout
    for line in out.splitlines():
        if line.strip().startswith("Candidate:"):
            version = line.split(":", 1)[1].strip()
            assert version and version != "(none)", out
            return version
    raise AssertionError(out)


def make_apt_plan(package: str = PACKAGE, *, post_package: str | None = None) -> dict:
    """A plan that passes the REAL validator, for the debian family, and installs one small package,
    with the rollback that removes it."""
    from sentinel.patch.validator import validate_plan
    from tests.integration.test_patch_apply_end_to_end import make_plan
    from tests.unit.test_patch_runner import _check, _step

    plan = make_plan(package)
    version = candidate(package)
    plan["preflight"] = [
        _check("pf_disk", {"kind": "disk_free", "path": "/var", "min_bytes": 524288000}),
        _check("pf_absent", {"kind": "file_absent", "path": BINARY}),
        _check("pf_notinst", {"kind": "command", "argv": ["dpkg-query", "-W", package], "expect_exit": [1]}),
    ]
    plan["backup"][0]["source"] = "/etc/apt"
    plan["apply"] = [_step("ap1", ["apt-get", "-y", "install", f"{package}={version}"], timeout_s=600,
                           idempotent=True)]
    plan["health_check"] = [_check("hc_file", {"kind": "file_exists", "path": BINARY})]
    plan["post_verification"] = [
        _check("pv_dpkg", {"kind": "command", "argv": ["dpkg-query", "-W", post_package or package],
                           "expect_exit": [0]})]
    plan["rollback"] = [_step("rb1", ["apt-get", "-y", "remove", package], on_failure="abort", timeout_s=600)]
    verdict = validate_plan(plan, platform_family="debian")
    assert verdict.valid, [e.message for e in verdict.errors]
    return plan


@pytest.fixture(scope="module", autouse=True)
def world():
    """Refuses to run anywhere but the throwaway container, then brings the executor up under its own
    unit with an enrolled key."""
    if not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        pytest.exit("REFUZ: nu e un container; proba asta nu rulează pe o gazdă", returncode=3)
    assert sh("ps -p 1 -o comm=").stdout.strip() == "systemd", "PID 1 nu e systemd"
    assert os.geteuid() == 0

    from _approval_support import tool

    OPERATOR_KEY.parent.mkdir(parents=True, exist_ok=True)
    OPERATOR_KEY.unlink(missing_ok=True)
    os.environ["SENTINEL_APPROVAL_KEY_FILE"] = str(OPERATOR_KEY)
    assert tool.main(["init"]) == 0
    key_hex = OPERATOR_KEY.read_text(encoding="ascii").strip()
    KEY_ON_HOST.unlink(missing_ok=True)
    sh(docs_enrolment_command(), check=True, input=key_hex + "\n")

    # The package index: apt-get install pins a version, and the index is what knows it.
    sh("apt-get update -qq", check=True, timeout=600)
    sh(f"systemctl reset-failed {UNIT}; systemctl start {UNIT}", check=True)
    wait_for(lambda: sentinel_side("ping").get("pong") is True, timeout=60, what="the executor to answer a ping")
    yield
    sh(f"systemctl stop {UNIT}")
    sh(f"apt-get -y -qq remove {PACKAGE}")


# ---------------------------------------------------------------------------
# Controls first
# ---------------------------------------------------------------------------
def test_the_environment_can_tell_installed_from_not_installed():
    """The controls every later claim leans on: `dpkg-query` says yes for something that is there and
    no for something that is not, and the index offers the package the plans install."""
    assert dpkg_has("bash") is True
    assert dpkg_has(PACKAGE) is False, "tree is already installed; the container is not clean"
    assert candidate(PACKAGE)
    assert sh("systemctl is-system-running").stdout.strip() in {"running", "degraded"}


def test_apt_get_is_routed_to_the_unit_by_the_real_executor_and_the_gate_is_open():
    """The dry run of an `apt-get install` says it goes to the transient unit and that nothing
    refuses it: before, it was a step for the read-only sandbox."""
    step = ["apt-get", "-y", "install", f"{PACKAGE}={candidate(PACKAGE)}"]
    dry = sentinel_side("exec", json.dumps(step), "-", "0", "dry")["result"]
    assert dry["transaction"]["transient_unit"] is True and dry["transaction"]["refused_because"] == [], dry


# ---------------------------------------------------------------------------
# The six steps, for real, on apt
# ---------------------------------------------------------------------------
def test_a_signed_apt_plan_installs_the_package_for_real_and_pid_1_says_so(tmp_path):
    """Redactare -> Validare -> Backup -> Aplicare -> Verificare, on a host whose only package manager
    is apt: the plan reaches `applied`, and `dpkg-query` - asked by the test, not by the executor - says
    the package is there now and was not before. The apply step's output carries PID 1's verdict."""
    plan = make_apt_plan()
    plan_file = write_plan(tmp_path, plan, "apt-tree")
    assert not dpkg_has(PACKAGE), "precondition: tree is absent"

    asked = sentinel_side("challenge", plan_file)
    token = operator_signs(asked["request"])
    first = len(audit_rows())

    outcome = sentinel_side("apply", plan_file, token)
    assert outcome.get("registered"), outcome
    assert outcome["status"] == "succeeded", json.dumps(outcome, indent=1)[:4000]
    assert "applied" in outcome["plan_statuses"]
    assert all(s["ok"] for s in outcome["steps"]), [s for s in outcome["steps"] if not s["ok"]]

    assert dpkg_has(PACKAGE), "the plan reached 'applied' and the package is NOT installed"
    assert Path(BINARY).exists()

    apply_step = next(s for s in outcome["steps"] if s["phase"] == "apply")
    for fact in ("result=success", "exec_code=1", "exec_status=0", "state=active/exited", "verified=True"):
        assert fact in apply_step["stderr"], (fact, apply_step["stderr"])

    rows = audit_rows()[first:]
    start = next(row for row in rows if row["operation"] == "transaction_start")
    end = next(row for row in rows if row["operation"] == "transaction_end")
    assert start["result"] == "ok" and end["result"] == "ok"
    assert json.loads(start["detail"])["argv"][0] == "apt-get"
    detail = json.loads(end["detail"])
    assert detail["verified"] is True and detail["exit_code"] == 0 and detail["result"] == "success"
    assert unit_state()["LoadState"] == "not-found", "the unit was not released"


def test_a_failed_verification_rolls_the_apt_change_back_for_real(tmp_path):
    """Revenire on apt: the install really happens; the post-verification then fails; the rollback is
    the plan's own `apt-get remove`, a second approved transaction - and `dpkg-query` says the
    package is gone again."""
    sh(f"apt-get -y -qq remove {PACKAGE}")
    plan = make_apt_plan(post_package="package-that-is-not-installed")
    plan_file = write_plan(tmp_path, plan, "apt-tree-rollback")
    assert not dpkg_has(PACKAGE)
    token = operator_signs(sentinel_side("challenge", plan_file)["request"])
    first = len(audit_rows())

    outcome = sentinel_side("apply", plan_file, token)
    assert outcome["status"] == "rolled_back", json.dumps(outcome, indent=1)[:4000]
    assert "apply" in [s["phase"] for s in outcome["steps"]] and "rollback" in [s["phase"] for s in outcome["steps"]]
    assert not dpkg_has(PACKAGE), "the rollback reported success and the package is still installed"
    ends = [row for row in audit_rows()[first:] if row["operation"] == "transaction_end"]
    assert len(ends) == 2 and all(json.loads(row["detail"])["verified"] for row in ends)


def test_the_option_and_a_tilde_version_reach_apt_unchanged_through_the_unit():
    """Two things the closed alphabet and the router once got wrong, on the real thing. `-o
    Dpkg::Options::=--force-confold` (the one option the grammar allows) was read as the subcommand,
    so the install was not routed. And `~` - in every Debian security version (`1:2.3-1~deb12u1`) -
    was refused by the token alphabet. Here apt itself reports the version it was asked for: the
    package does not exist at that version, which is the point - the string in apt's error message
    is the string that was sent."""
    bogus = f"{PACKAGE}=2.1.1~e2e-no-such-version"
    step = ["apt-get", "-o", "Dpkg::Options::=--force-confold", "-y", "install", "--allow-downgrades", bogus]
    plan_hash = hashlib.sha256(b"e2e: apt tilde").hexdigest()
    token = operator_signs(sentinel_side("raw-challenge", plan_hash, json.dumps([step]))["request"])
    assert sentinel_side("raw-register", plan_hash, json.dumps([step]), token)["registered"]
    out = sentinel_side("exec", json.dumps(step), plan_hash, "0")["result"]
    assert out["transaction"]["unit_ran"] is True and out["transaction"]["verified"] is True
    assert out["exit_code"] == 100, out
    assert "2.1.1~e2e-no-such-version" in out["stdout"], out["stdout"]
    assert not dpkg_has(PACKAGE), "a bogus version installed something"


def test_a_step_that_writes_and_is_not_a_transaction_is_refused_on_this_host_too(tmp_path):
    """n8n plan 1 had `tar -czf /var/backups/polkit-1.tar.gz -C / etc/polkit-1` as an apply step: the
    dry run passed and the apply failed with "Read-only file system". The refusal is the same on this
    family - at the challenge, naming the step."""
    step = ["tar", "-czf", "/var/backups/polkit-1.tar.gz", "-C", "/", "etc/polkit-1"]
    asked = sentinel_side("raw-challenge", hashlib.sha256(b"e2e: tar").hexdigest(), json.dumps([step]))
    assert "cannot run on this host" in asked["refused"] and "Read-only file system" in asked["refused"], asked
    assert not Path("/var/backups/polkit-1.tar.gz").exists()


# ---------------------------------------------------------------------------
# needrestart must not restart the executor under its own transaction
# ---------------------------------------------------------------------------
def test_an_apt_transaction_does_not_get_the_executor_restarted_by_needrestart(tmp_path):
    """Measured on 5 October 2026: Ubuntu's apt hook runs `needrestart -m u`, which restarts the
    services using a replaced library BY ITSELF - sentinel-executor among them. Run outside the
    unit it does; inside the unit it does nothing today, because the unit drops CAP_SYS_PTRACE and
    cannot read other processes' maps. An executor restarted in the middle of the transaction it
    waits on would report a SUCCESSFUL install as one it could not follow, on every library update.

    Falsified (the three runs are in the handback): with CAP_SYS_PTRACE given back and
    NEEDRESTART_MODE=l present this test passes; with the capability given back and the variable
    removed it FAILS - the executor is restarted inside the transaction; with only the variable
    removed it passes, because the capability is still dropped. So it tests the combination, and
    shows that the variable is the guard that matters if the capability ever returns.

    A library is replaced the way an upgrade does (a new file renamed over the old one: the old inode
    stays mapped as deleted). The control comes first: `needrestart -b`, run from outside, lists the
    executor as needing a restart, so "it was not restarted" is not vacuous. Then the plan is applied
    and the executor's own start time is compared. Last in the file: the container's libc is left replaced."""
    sh(f"apt-get -y -qq remove {PACKAGE}")
    libc = Path(sh("readlink -f /usr/lib/x86_64-linux-gnu/libc.so.6", check=True).stdout.strip())
    sh(f"cp -p {libc} {libc}.new && mv {libc}.new {libc}", check=True)
    listed = sh("/usr/sbin/needrestart -b").stdout
    assert f"NEEDRESTART-SVC: {UNIT}.service" in listed, (
        "control: needrestart must list the executor as needing a restart, or this test proves nothing\n" + listed)

    def started() -> str:
        return sh(f"systemctl show {UNIT} -p ActiveEnterTimestampMonotonic --value", check=True).stdout.strip()

    before = started()
    plan = make_apt_plan()
    plan_file = write_plan(tmp_path, plan, "apt-needrestart")
    token = operator_signs(sentinel_side("challenge", plan_file)["request"])
    outcome = sentinel_side("apply", plan_file, token)
    assert outcome["status"] == "succeeded", json.dumps(outcome, indent=1)[:4000]
    assert dpkg_has(PACKAGE)
    assert started() == before, "the executor was restarted during its own apt transaction"
    assert subprocess.run(["systemctl", "is-active", UNIT], capture_output=True, text=True).stdout.strip() == "active"


def test_backup_restore_cannot_replace_or_leak_the_approval_key():
    """The same three attempts as the rhel probe, on the Ubuntu unit: `backup_restore` is one
    executor and one sandbox on both families, and the key is the one thing the operator's
    signature rests on."""
    backup_restore_attack_leaves_the_key_alone()
