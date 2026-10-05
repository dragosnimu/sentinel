"""`backup_restore` is refused, and the executor's own state is a protected path.

Prevents: `sentinel` - an unprivileged account, the one the approval key exists to
restrain - replacing that key (and the audit chain) through the one root operation that
took a caller-chosen archive and a caller-chosen `tar`. Reproduced on 5 October 2026 in a
container with the real unit and the real sandbox: a tar in /dev/shm holding
`approval.key`, `backup_restore ... tar -xzf {artifact} -C /var/lib/sentinel-executor`,
and the next signature the executor accepted was the attacker's. Two things made that
possible and neither is an argument-list property:

* `/var/lib/sentinel-executor` was in the executor's ReadWritePaths but not in
  `PROTECTED_PATHS` (and "/var/lib/sentinel" does not cover it - the prefix match is on
  "/var/lib/sentinel/");
* naming it is not even required: `-C /` with a member `var/lib/sentinel-executor/
  approval.key` inside the archive writes the same file, and `check_argv` reads the argv,
  not the archive. So the operation is refused outright, and the tests below check the
  EFFECT - nothing is extracted - rather than the presence of a name in a list.

Nothing here runs as root or touches a real path: every directory is under `tmp_path`.
"""

from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

import pytest

import commands
import policy
from policy import PolicyRefusal

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]
KEY_PATH = "/var/lib/sentinel-executor/approval.key"


def _archive(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as handle:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
    return path


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def spy(monkeypatch):
    """Records every command the operation would run AS ROOT, and still runs it, so a
    regression extracts for real into `tmp_path` instead of merely 'calling'."""
    calls: list[list[str]] = []
    real = commands._run

    def recording(argv, **kwargs):
        calls.append(list(argv))
        return real(argv, **kwargs)

    monkeypatch.setattr(commands, "_run", recording)
    return calls


# ---------------------------------------------------------------------------
# The operation itself
# ---------------------------------------------------------------------------
def test_backup_restore_does_not_replace_the_approval_key(tmp_path, spy):
    """The reproduced attack, relocated under `tmp_path` (the destination stands for
    /var/lib/sentinel-executor, which no test may touch): an archive holding `approval.key`,
    extracted with `-C <the executor's state>`. For the operator this is the whole of Gate 1
    - whoever writes that file approves anything - so the assertion is on the file."""
    state = tmp_path / "sentinel-executor"
    state.mkdir()
    (state / "approval.key").write_text("THE-OPERATORS-KEY", encoding="ascii")
    artifact = _archive(tmp_path / "evil.tgz", {"approval.key": b"ATTACKER"})

    # `match`: on a host whose temp paths are not POSIX-absolute (Windows) `check_path` would
    # refuse the artifact for THAT reason, and this test would pass with the bug back in.
    with pytest.raises(PolicyRefusal, match="disabled"):
        commands.op_backup_restore({"artifact": str(artifact),
                                    "restore_argv": ["tar", "-xzf", "{artifact}", "-C", str(state)]})

    assert (state / "approval.key").read_text(encoding="ascii") == "THE-OPERATORS-KEY"
    assert spy == [], "a command was run as root for a refused operation"


def test_backup_restore_refuses_the_archive_that_carries_the_protected_path(tmp_path, spy):
    """The form a path list cannot see: `-C /` (here: a stand-in root) and the protected
    path INSIDE the archive. The argument names nothing protected; the effect is the same
    write. Refusing the operation is what stops it, so nothing may be extracted whatever
    the members are called - the tree is compared before and after."""
    fake_root = tmp_path / "root"
    fake_root.mkdir()
    artifact = _archive(tmp_path / "evil.tgz", {
        "var/lib/sentinel-executor/approval.key": b"ATTACKER",
        "etc/sentinel/sentinel.yaml": b"ATTACKER",
    })
    before = _tree(fake_root)

    with pytest.raises(PolicyRefusal, match="disabled"):
        commands.op_backup_restore({"artifact": str(artifact),
                                    "restore_argv": ["tar", "-xzf", "{artifact}", "-C", str(fake_root)]})

    assert _tree(fake_root) == before == []
    assert spy == []


@pytest.mark.parametrize("args", [
    {},                                                        # no arguments at all
    {"artifact": "/var/backups/sentinel/rp1/x.tar.zst", "restore_argv": ["dnf", "-y", "downgrade", "nginx"]},
    {"artifact": "/dev/shm/x.tgz", "sha256": "0" * 64, "restore_argv": ["chmod", "-R", "755", "/dev/shm/out"]},
])
def test_backup_restore_refuses_whatever_it_is_asked_including_a_valid_looking_restore(args, spy):
    """Not 'refuses the attack shapes': refuses. A restore point of the executor's own
    (artifact under its backup root, sha256 supplied) is refused too, because the read
    half of the attack used exactly such an artifact - made by `backup_create` from a
    symlink - and the `chmod` that made the extracted key readable is in this list."""
    with pytest.raises(PolicyRefusal, match="disabled"):
        commands.op_backup_restore(args)
    assert spy == []


def test_the_refusal_reaches_the_caller_and_the_audit_chain_as_a_refusal(monkeypatch):
    """Through the request handler, the way the socket reaches it: the answer is
    `refused` (not 'unknown operation', not a crash) and an audit row says so - an
    attacker's probe of this operation leaves a line in the chain."""
    import sentinel_executor as se

    rows: list[tuple] = []
    monkeypatch.setattr(se, "audit", lambda op, target, params, result, detail, peer: rows.append(
        (op, result)) or 7)
    response = se.handle_request(
        {"id": "x", "op": "backup_restore",
         "args": {"artifact": "/dev/shm/evil.tgz", "restore_argv": ["tar", "-xzf", "{artifact}", "-C", "/"]}},
        {"uid": 1001, "pid": 7, "gid": 1001})
    assert response["ok"] is False and response["error"] == "refused", response
    assert rows == [("backup_restore", "refused")]


def test_nothing_in_sentinel_sends_backup_restore():
    """The refusal costs nothing only while nobody asks. The restore is `restore.sh`, run by
    the operator; the runner never executes `restore_argv`. If a caller is added to
    `sentinel/`, this goes red - so the author learns the operation answers `refused`
    here instead of finding out on the night a restore is needed."""
    pattern = re.compile(r"""["']backup_restore["']""")
    hits = [f"{path.relative_to(REPO)}:{number}"
            for path in (REPO / "sentinel").rglob("*.py")
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if pattern.search(line)]
    assert hits == [], f"something sends backup_restore, which is refused: {hits}"


# ---------------------------------------------------------------------------
# The path list - still needed for plan steps and for `check_path` callers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "/var/lib/sentinel-executor", KEY_PATH, "/var/lib/sentinel-executor/audit.jsonl",
    "/var/lib/sentinel-executor/planted",
])
def test_the_executors_own_state_is_a_protected_path(path):
    """`/var/lib/sentinel` did not cover it. A plan step, a `cwd` or a backup source that
    names the executor's state is refused like every other protected path."""
    with pytest.raises(PolicyRefusal, match="protected"):
        policy.check_path(path)


@pytest.mark.parametrize("argv", [
    ["tar", "-xzf", "/dev/shm/evil.tgz", "-C", "/var/lib/sentinel-executor"],
    ["tar", "--directory=/var/lib/sentinel-executor", "-xf", "/dev/shm/evil.tar"],
    # Forms that name the directory without a token that starts with "/", which is the
    # only thing `check_argv`'s generic loop looks at. Each was ACCEPTED before.
    ["tar", "-xf", "/dev/shm/evil.tar", "-C", "var/lib/sentinel-executor"],
    ["tar", "-xf", "/dev/shm/evil.tar", "--directory", "var/lib/sentinel-executor"],
    ["tar", "-xf", "/dev/shm/evil.tar", "--one-top-level=/var/lib/sentinel-executor"],
    ["tar", "-xCf", "var/lib/sentinel-executor", "/dev/shm/evil.tar"],     # -C bundled in a cluster
    ["tar", "-Cx", "var/lib/sentinel-executor", "-f", "/dev/shm/evil.tar"],
    ["cp", "-f", "/dev/shm/k", KEY_PATH],
    ["install", "-m", "600", "/dev/shm/k", KEY_PATH],
    ["mv", "-f", "/dev/shm/k", KEY_PATH],
    ["chmod", "644", KEY_PATH],
    ["chown", "root:root", KEY_PATH],
    ["cp", "-r", KEY_PATH, "/dev/shm/stolen"],
])
def test_a_plan_step_naming_the_executors_state_is_refused(argv):
    """Every write binary in the grammar, and a copy OUT of the state: the generic
    per-token path check is what catches these, so each is exercised through `check_argv`."""
    with pytest.raises(PolicyRefusal):
        policy.check_argv(argv)


@pytest.mark.parametrize("argv", [
    ["tar", "--zstd", "-xf", "/var/backups/sentinel/rp1/a.tar.zst", "-C", "/"],
    ["tar", "-xf", "/dev/shm/a.tar", "--directory=/etc/nginx/conf.d"],
    ["tar", "-xf", "/dev/shm/a.tar", "--one-top-level=extracted", "-C", "/dev/shm"],
])
def test_the_tar_forms_a_real_step_uses_are_still_accepted(argv):
    """Control for the three refusals above: the same flags with an ordinary destination
    pass, so those refusals are about the destination and not about the flag."""
    assert policy.check_argv(argv) == argv


def test_a_sibling_directory_that_merely_shares_the_prefix_is_not_swept_in():
    """Control: the entry matches the directory and what is under it, not every path that
    starts with the same letters - or the new entry would be refusing real work."""
    assert policy.check_path("/var/lib/sentinel-executor-notes/x") == "/var/lib/sentinel-executor-notes/x"


def test_the_untrusted_side_protects_the_same_path():
    """`sentinel/constants.py` is what the validator and the planner prompt use; a plan
    naming the executor's state is refused THERE too, before it is ever shown to the
    operator. Through `validate_plan`, so the decision is checked and not the list."""
    from sentinel import constants
    from sentinel.patch.validator import validate_plan
    from tests.unit.test_patch_runner import _plan, _step

    assert "/var/lib/sentinel-executor" in constants.PROTECTED_PATHS
    plan = _plan()
    plan["apply"] = [_step("ap1", ["cp", "-f", "/etc/yum.repos.d/a.repo", KEY_PATH], timeout_s=60)]
    result = validate_plan(plan, platform_family="rhel")
    assert not result.valid
    assert "protected_path" in {e.code for e in result.errors}, [e.as_dict() for e in result.errors]
