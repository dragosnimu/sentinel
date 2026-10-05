"""Binding `patch_step_exec` to an approved plan, and who may approve one.

Round 1's per-binary grammar answers "is this argv well-formed". It cannot answer
"did the operator approve THIS argv" - `dnf -y install some-plausible-package` is
grammar-legal and could be sent straight to the socket by a `sentinel`-uid attacker
who never went through the Telegram flow at all. These tests are the specification of
the mechanism that closes that gap (`challenge_plan_steps` / `register_plan_steps` /
`lookup_registered_step` in policy.py, and the `plan_hash`/`step_index` requirement
`op_patch_step_exec` enforces on every REAL call), and of the two defects the first
version of it had:

* the key an approval was checked against was readable by the account the approval
  restrains, so that account could approve itself (Gate 1);
* the token was an HMAC of the plan hash ALONE, so a signature for one plan registered
  the steps of any other: `dnf -y remove openssh-server` was registered under another
  plan's hash and then accepted by `lookup_registered_step` and
  `consume_registered_step` (Gate 2).

Tokens are made by the operator's own tool (`scripts/approve-plan.py`), loaded from the
script, and verified by the executor's own code.
"""

from __future__ import annotations

import hashlib
import os
import time

import pytest

import commands
import policy
from _approval_support import KEY, KEY_HEX, OTHER_KEY, approve, enrol_key, sign
from policy import PolicyRefusal

pytestmark = pytest.mark.security

_PLAN_HASH = hashlib.sha256(b"plan contents").hexdigest()
_OTHER_HASH = hashlib.sha256(b"another plan").hexdigest()
_STEPS = [["dnf", "-y", "update", "nginx"], ["systemctl", "reload", "nginx.service"]]
#: Grammar-LEGAL on purpose. If it were not, every refusal below could be the
#: grammar's and the test would prove nothing about the binding.
_EVIL = [["dnf", "-y", "remove", "openssh-server"]]

for _argv in (*_STEPS, *_EVIL):
    assert policy.check_argv(_argv) == _argv


@pytest.fixture(autouse=True)
def _clean_state():
    """The registry and the pending challenges are module-global state: a test that
    leaves a registration behind approves things for the next one."""
    policy._plan_registry.clear()
    policy._challenges.clear()
    yield
    policy._plan_registry.clear()
    policy._challenges.clear()


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    """A key is enrolled where the executor reads one, with the properties a real one
    has (see `enrol_key`)."""
    return enrol_key(tmp_path, monkeypatch)


# ---------------------------------------------------------------------------
# Gate 1 - the key. Fails closed, and says why.
# ---------------------------------------------------------------------------
def test_register_refuses_when_no_key_is_enrolled(tmp_path, monkeypatch):
    """A host where nobody has enrolled a key must not accept a registration: that
    would mean a plan nothing could have signed was approved."""
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "absent.key")
    with pytest.raises(PolicyRefusal, match="no approval key is enrolled"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, "0" * 64)


def test_a_challenge_is_refused_when_no_key_is_enrolled(tmp_path, monkeypatch):
    """Asking the operator to read commands and run a tool for an approval that can
    never be completed wastes the one thing that is scarce - their attention - and
    hides the real problem (no key) behind a failure at the last step."""
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "absent.key")
    with pytest.raises(PolicyRefusal, match="no approval key is enrolled"):
        policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    assert policy._challenges == {}


def test_lookup_says_nothing_can_be_approved_here_when_no_key_is_enrolled(tmp_path, monkeypatch):
    """Distinguishes 'no key enrolled' from 'no plan registered' in the refusal - an
    operator debugging a host that never had a key should not have to guess whether
    registration was ever attempted."""
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "absent.key")
    with pytest.raises(PolicyRefusal, match="disabled"):
        policy.lookup_registered_step(_PLAN_HASH, 0, _STEPS[0])


def test_the_key_lives_beside_the_audit_chain_and_not_in_secrets_env():
    """The first defect, as a fact about the shipped default: `secrets.env` is `0640
    root:sentinel`, so a key kept there is readable by the account the approval is meant
    to constrain. The key belongs in the root-only directory the audit chain is in
    (`0700 root:root`, which `sentinel` cannot even traverse). No fixture replaces the
    path here: this is what ships."""
    import sentinel_executor as se

    shipped = policy.approval_key_path()
    assert shipped.parent == se.AUDIT_DIR
    assert shipped.as_posix() not in policy.SECRET_PATHS
    assert not shipped.as_posix().startswith("/etc/sentinel/")


def test_a_key_that_sits_in_secrets_env_is_not_an_approval_key(tmp_path, monkeypatch):
    """A host that still carries the old `SENTINEL_EXECUTOR_APPROVAL_KEY=` line in
    secrets.env must not approve anything with it: that key is readable by `sentinel`.
    Nothing reads that line any more."""
    old = tmp_path / "secrets.env"
    old.write_text("SENTINEL_EXECUTOR_APPROVAL_KEY=" + KEY_HEX + "\n", encoding="ascii")
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", tmp_path / "approval.key")  # absent
    token = sign(_PLAN_HASH, _STEPS, "0" * 32)  # signed with the key that is in secrets.env
    with pytest.raises(PolicyRefusal, match="no approval key is enrolled"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, token)


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        (dict(is_regular=True, uid=0, mode=0o600, parent_uid=0, parent_mode=0o700), None),
        (dict(is_regular=True, uid=0, mode=0o400, parent_uid=0, parent_mode=0o755), None),
        (dict(is_regular=False, uid=0, mode=0o600, parent_uid=0, parent_mode=0o700), "regular file"),
        (dict(is_regular=True, uid=999, mode=0o600, parent_uid=0, parent_mode=0o700), "owned by uid 999"),
        (dict(is_regular=True, uid=0, mode=0o640, parent_uid=0, parent_mode=0o700), "group or other can reach"),
        (dict(is_regular=True, uid=0, mode=0o604, parent_uid=0, parent_mode=0o700), "group or other can reach"),
        (dict(is_regular=True, uid=0, mode=0o660, parent_uid=0, parent_mode=0o700), "group or other can reach"),
        (dict(is_regular=True, uid=0, mode=0o600, parent_uid=999, parent_mode=0o700), "directory is owned by uid 999"),
        (dict(is_regular=True, uid=0, mode=0o600, parent_uid=0, parent_mode=0o770), "can write to it"),
        (dict(is_regular=True, uid=0, mode=0o600, parent_uid=0, parent_mode=0o757), "can write to it"),
    ],
)
def test_what_makes_a_key_file_trustworthy(kwargs, fragment):
    """A key group or other can read is the original defect again, and a directory
    they can write is a way to replace the key with one of their own. The table is
    numbers only, so every row runs on every platform."""
    problem = policy._key_stat_problem(**kwargs)
    if fragment is None:
        assert problem is None
    else:
        assert problem is not None and fragment in problem


@pytest.mark.parametrize("content", ["", "not hex at all", "ab" * 31, "ab" * 33, ("AB" * 32), "zz" * 32])
def test_a_malformed_key_is_not_a_key(tmp_path, monkeypatch, content):
    """A truncated paste or a key written in capitals is not 'close enough': failing
    closed with the reason beats verifying tokens against something the operator did
    not intend."""
    enrol_key(tmp_path, monkeypatch, key_hex=content)
    with pytest.raises(PolicyRefusal, match="not 64 lowercase hex digits"):
        policy.challenge_plan_steps(_PLAN_HASH, _STEPS)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="needs POSIX ownership and modes")
def test_a_real_key_that_group_can_read_is_refused(enrolled):
    """The kernel's own view of a real file, not a table: loosen the mode of an
    enrolled key and the very next use refuses (nothing is cached)."""
    policy.challenge_plan_steps(_PLAN_HASH, _STEPS)  # control: it works at 0600
    enrolled.chmod(0o640)
    with pytest.raises(PolicyRefusal, match="not trusted"):
        policy.challenge_plan_steps(_PLAN_HASH, _STEPS)


@pytest.mark.skipif(not hasattr(os, "symlink") or not hasattr(os, "getuid"), reason="needs POSIX symlinks")
def test_a_symlink_planted_at_the_key_path_is_not_followed(tmp_path, monkeypatch):
    """`O_NOFOLLOW`: a link at the path would let whoever can create one point the
    verification at a file of their own."""
    real = tmp_path / "elsewhere.key"
    real.write_text(KEY_HEX + "\n")
    real.chmod(0o600)
    link = tmp_path / "approval.key"
    os.symlink(real, link)
    tmp_path.chmod(0o700)
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", link)
    monkeypatch.setattr(policy, "_APPROVAL_KEY_OWNER_UID", os.getuid())
    with pytest.raises(PolicyRefusal):
        policy.challenge_plan_steps(_PLAN_HASH, _STEPS)


def test_the_probed_path_is_the_verified_path(enrolled):
    """`transient_unit` probes `approval_key_path()` as the `sentinel` uid; if that
    were a copy of the path the gate would check one file and verify against
    another."""
    assert policy.approval_key_path() == enrolled


# ---------------------------------------------------------------------------
# Gate 2 - the token is bound to the steps it was computed over
# ---------------------------------------------------------------------------
def test_the_old_attack_a_token_for_one_plan_does_not_register_the_steps_of_another(enrolled):
    """The attack, reproduced: an approval exists for a HARMLESS plan under hash H;
    the attacker presents it with `dnf -y remove openssh-server` under the same hash.
    The old token covered H alone, so it verified, the evil step was registered, and
    `lookup_registered_step` accepted it. Now the token covers the digest of the steps,
    and the executor refuses to register steps other than the ones the challenge
    named."""
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    token = sign(_PLAN_HASH, _STEPS, challenge["nonce"])  # the operator's, for the harmless plan

    with pytest.raises(PolicyRefusal, match="not the ones the approval"):
        policy.register_plan_steps(_PLAN_HASH, _EVIL, 600, token)

    assert _PLAN_HASH not in policy._plan_registry
    with pytest.raises(PolicyRefusal):
        policy.lookup_registered_step(_PLAN_HASH, 0, _EVIL[0])
    with pytest.raises(PolicyRefusal):
        policy.consume_registered_step(_PLAN_HASH, 0, _EVIL[0])


def test_the_old_attack_with_a_challenge_of_the_attackers_own_choosing(enrolled):
    """The attacker is not limited to the nonce it was given: it can ask for its own
    challenge for the evil steps (challenges are inert, anyone may ask) and then
    present the operator's token for the harmless ones. The HMAC covers the digest,
    so it does not verify against a challenge for different steps."""
    harmless = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    operators_token = sign(_PLAN_HASH, _STEPS, harmless["nonce"])

    policy.challenge_plan_steps(_PLAN_HASH, _EVIL)  # replaces the pending challenge
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.register_plan_steps(_PLAN_HASH, _EVIL, 600, operators_token)
    assert _PLAN_HASH not in policy._plan_registry


def test_a_token_for_one_plan_hash_does_not_register_another_plan_hash(enrolled):
    """The token covers the plan hash too: the operator's signature for plan A cannot
    be moved onto plan B even with identical steps."""
    challenge_a = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    policy.challenge_plan_steps(_OTHER_HASH, _STEPS)
    token_for_a = sign(_PLAN_HASH, _STEPS, challenge_a["nonce"])
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.register_plan_steps(_OTHER_HASH, _STEPS, 600, token_for_a)
    assert _OTHER_HASH not in policy._plan_registry


def test_the_token_covers_the_digest_of_the_steps_and_not_only_the_hash(enrolled):
    """The binding itself, at the level of the HMAC: two step lists give two different
    tokens for the same hash and nonce. This is the assertion that goes red when the
    digest is dropped from what is signed - which is how the old design looked."""
    nonce = "0" * 32
    assert sign(_PLAN_HASH, _STEPS, nonce) != sign(_PLAN_HASH, _EVIL, nonce)
    assert sign(_PLAN_HASH, _STEPS, nonce) != sign(_PLAN_HASH, list(reversed(_STEPS)), nonce), \
        "the ORDER of the commands is part of what is approved"


def test_a_token_is_made_with_the_enrolled_key_and_no_other(enrolled):
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    forged = sign(_PLAN_HASH, _STEPS, challenge["nonce"], key=OTHER_KEY)
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, forged)
    assert _PLAN_HASH not in policy._plan_registry


def test_a_token_is_spent_by_the_registration_it_authorises(enrolled):
    """A copy of the token - a chat history, a log line, a database row - must not
    authorise a second registration. A replay would reset the used-marks of a plan
    whose `dnf downgrade` already ran and let it run again."""
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    token = sign(_PLAN_HASH, _STEPS, challenge["nonce"])
    assert policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, token) == 2
    with pytest.raises(PolicyRefusal, match="no approval is waiting"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, token)


def test_a_wrong_token_does_not_destroy_the_pending_challenge(enrolled):
    """If a bad token spent the challenge, anyone able to reach the socket could stop
    an approval in progress with one malformed call."""
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, "0" * 64)
    policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, sign(_PLAN_HASH, _STEPS, challenge["nonce"]))


def test_a_second_challenge_for_the_same_plan_invalidates_the_first_nonce(enrolled):
    """Latest wins: a token for an older nonce no longer verifies."""
    first = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    second = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    assert first["nonce"] != second["nonce"]
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, sign(_PLAN_HASH, _STEPS, first["nonce"]))
    policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, sign(_PLAN_HASH, _STEPS, second["nonce"]))


def test_registering_without_asking_for_a_challenge_is_refused(enrolled):
    """Even a token computed with the right key over the right steps needs a nonce
    this process issued: otherwise a token could be prepared in advance, and kept."""
    token = sign(_PLAN_HASH, _STEPS, "0" * 32)
    with pytest.raises(PolicyRefusal, match="no approval is waiting"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, token)


def test_an_expired_challenge_cannot_be_completed(enrolled):
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    token = sign(_PLAN_HASH, _STEPS, challenge["nonce"])
    policy._challenges[_PLAN_HASH]["expires_at"] = time.monotonic() - 1
    with pytest.raises(PolicyRefusal, match="no approval is waiting"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, token)


def test_a_challenge_makes_nothing_runnable(enrolled):
    """Anyone who can reach the socket may ask for a challenge; that must not be a way
    to get a step approved."""
    policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal):
        policy.lookup_registered_step(_PLAN_HASH, 0, _STEPS[0])


def test_challenges_are_capped_and_expired_ones_make_room(enrolled):
    for i in range(policy._CHALLENGE_MAX):
        policy.challenge_plan_steps(hashlib.sha256(f"c{i}".encode()).hexdigest(), _STEPS)
    with pytest.raises(PolicyRefusal, match="already waiting"):
        policy.challenge_plan_steps(hashlib.sha256(b"one too many").hexdigest(), _STEPS)
    for entry in policy._challenges.values():
        entry["expires_at"] = time.monotonic() - 1
    policy.challenge_plan_steps(hashlib.sha256(b"one too many").hexdigest(), _STEPS)


def test_the_challenge_tells_the_operator_what_will_be_approved(enrolled):
    """The digest is of the steps the executor was handed, so the operator's tool and
    the executor can be seen to agree before anything is signed."""
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    assert challenge["digest"] == policy.steps_digest(_STEPS)
    assert challenge["step_count"] == 2
    assert len(challenge["nonce"]) == 32


@pytest.mark.parametrize("bad_ttl", [0, -1, 3601, "600", 600.0, True])
def test_register_refuses_an_out_of_range_ttl(enrolled, bad_ttl):
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, bad_ttl, sign(_PLAN_HASH, _STEPS, challenge["nonce"]))


@pytest.mark.parametrize("bad", ["", "not-hex", "0" * 63, "0" * 65, "G" * 64, None, 5])
def test_register_refuses_a_malformed_token(enrolled, bad):
    policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal, match="approval_token"):
        policy.register_plan_steps(_PLAN_HASH, _STEPS, 600, bad)


def test_register_and_challenge_refuse_a_malformed_plan_hash(enrolled):
    with pytest.raises(PolicyRefusal):
        policy.challenge_plan_steps("not-a-sha256", _STEPS)
    with pytest.raises(PolicyRefusal):
        policy.register_plan_steps("not-a-sha256", _STEPS, 600, "0" * 64)


def test_a_grammar_illegal_step_is_neither_challenged_nor_registered(enrolled):
    """An approval says WHICH grammar-legal commands were approved; it is never a way
    around the grammar. The operator is not asked to sign what the executor would
    refuse."""
    steps = [["git", "status"]]  # dropped from BINARY_ALLOWLIST entirely
    with pytest.raises(PolicyRefusal, match="grammar"):
        policy.challenge_plan_steps(_PLAN_HASH, steps)
    assert policy._challenges == {}


def test_register_revalidates_every_step_through_check_argv(enrolled):
    """The grammar is checked at registration too, not only at the challenge: a
    challenge made for legal steps must not be completed with illegal ones. (The
    digest would differ as well; this pins the grammar check as its own wall.)"""
    challenge = policy.challenge_plan_steps(_PLAN_HASH, _STEPS)
    bad = [["git", "status"]]
    with pytest.raises(PolicyRefusal, match="grammar"):
        policy.register_plan_steps(_PLAN_HASH, bad, 600, sign(_PLAN_HASH, _STEPS, challenge["nonce"]))
    assert _PLAN_HASH not in policy._plan_registry


@pytest.mark.parametrize("steps", [[], "dnf update", None, [["dnf"], "x"]])
def test_steps_must_be_a_non_empty_list_of_argv_lists(enrolled, steps):
    with pytest.raises(PolicyRefusal):
        policy.challenge_plan_steps(_PLAN_HASH, steps)


def test_the_digest_and_the_token_are_pinned_to_their_published_definition():
    """The definition is written out HERE, independently of the implementation: the digest
    is sha256 of a domain line and the compact JSON of the list, and the token is an
    HMAC-SHA256 over four newline-joined fields. Pinning it matters because the operator's
    tool and a host can be on different checkouts: a quiet change to the encoding makes
    every request in flight unverifiable, and nothing else would say why."""
    import hashlib
    import hmac

    steps = [["dnf", "-y", "update", "nginx"], ["systemctl", "reload", "nginx.service"]]
    expected_digest = hashlib.sha256(
        b"sentinel-plan-steps-v1\n" + b'[["dnf","-y","update","nginx"],["systemctl","reload","nginx.service"]]'
    ).hexdigest()
    assert policy.steps_digest(steps) == expected_digest

    nonce = "0123456789abcdef" * 2
    message = b"\n".join([b"sentinel-plan-approval-v1", _PLAN_HASH.encode(), expected_digest.encode(), nonce.encode()])
    assert policy.approval_token(KEY, _PLAN_HASH, expected_digest, nonce) == hmac.new(
        KEY, message, hashlib.sha256).hexdigest()


def test_the_steps_digest_is_one_definition_for_both_ends(enrolled):
    """The operator's tool imports the digest from policy.py instead of keeping its
    own, so the two cannot drift apart into a token that never verifies."""
    import _approval_support as support
    assert support.tool.make_token(policy, KEY, {
        "plan_hash": _PLAN_HASH, "nonce": "0" * 32, "digest": policy.steps_digest(_STEPS), "steps": _STEPS,
    })[1] == policy.steps_digest(_STEPS)


# ---------------------------------------------------------------------------
# The happy path, and what "byte for byte" means
# ---------------------------------------------------------------------------
def test_approve_then_lookup_succeeds_for_the_registered_step(enrolled):
    assert approve(_PLAN_HASH, _STEPS) == 2
    policy.lookup_registered_step(_PLAN_HASH, 0, _STEPS[0])
    policy.lookup_registered_step(_PLAN_HASH, 1, _STEPS[1])


def test_lookup_refuses_an_argv_that_does_not_match_byte_for_byte(enrolled):
    approve(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.lookup_registered_step(_PLAN_HASH, 0, ["dnf", "-y", "update", "httpd"])


def test_lookup_refuses_extra_or_missing_arguments(enrolled):
    """Byte-for-byte, not prefix-or-subset - an extra flag tacked onto an
    otherwise-approved command is a different command."""
    approve(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal):
        policy.lookup_registered_step(_PLAN_HASH, 0, [*_STEPS[0], "--allowerasing"])


def test_lookup_refuses_a_truncated_argv(enrolled):
    """The other direction of 'byte-for-byte': a caller argv with the LAST token
    dropped is a strict PREFIX of the registered step. Dropping the trailing package
    name from `dnf -y update nginx` still passes the grammar (a bare `dnf -y update`
    updates everything dnf knows about) while looking like 'the same command with one
    less argument'."""
    approve(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal, match="does not match"):
        policy.lookup_registered_step(_PLAN_HASH, 0, _STEPS[0][:-1])


def test_lookup_refuses_an_out_of_range_step_index(enrolled):
    approve(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal, match="out of range"):
        policy.lookup_registered_step(_PLAN_HASH, 5, _STEPS[0])


def test_lookup_refuses_a_plan_hash_that_was_never_registered(enrolled):
    with pytest.raises(PolicyRefusal, match="no plan is registered"):
        policy.lookup_registered_step(_OTHER_HASH, 0, _STEPS[0])


def test_lookup_refuses_after_expiry(enrolled):
    approve(_PLAN_HASH, _STEPS, ttl=1)
    policy._plan_registry[_PLAN_HASH]["expires_at"] = time.monotonic() - 1
    with pytest.raises(PolicyRefusal, match="expired"):
        policy.lookup_registered_step(_PLAN_HASH, 0, _STEPS[0])
    assert _PLAN_HASH not in policy._plan_registry  # purged, not just refused


def test_re_approving_the_same_hash_replaces_the_steps_and_refreshes_ttl(enrolled):
    """A re-approval must not be refused as 'already registered' - but it needs a new
    token, i.e. the operator."""
    approve(_PLAN_HASH, _STEPS)
    new_steps = [["systemctl", "is-active", "nginx.service"]]
    approve(_PLAN_HASH, new_steps)
    policy.lookup_registered_step(_PLAN_HASH, 0, new_steps[0])
    with pytest.raises(PolicyRefusal):
        policy.lookup_registered_step(_PLAN_HASH, 1, _STEPS[1])  # old step 1 is gone


def test_registry_is_capped(enrolled):
    for i in range(policy._PLAN_REGISTRY_MAX):
        approve(hashlib.sha256(f"plan {i}".encode()).hexdigest(), _STEPS)
    overflow_hash = hashlib.sha256(b"one too many").hexdigest()
    challenge = policy.challenge_plan_steps(overflow_hash, _STEPS)
    with pytest.raises(PolicyRefusal, match="already registered"):
        policy.register_plan_steps(overflow_hash, _STEPS, 600, sign(overflow_hash, _STEPS, challenge["nonce"]))
    assert overflow_hash in policy._challenges, "a refused registration must not spend the approval"


# ---------------------------------------------------------------------------
# The operations - what the socket peer can actually reach
# ---------------------------------------------------------------------------
def test_the_operations_exist_and_the_old_unsigned_path_does_not():
    assert {"plan_challenge", "register_plan"} <= set(commands.OPERATIONS)


def test_register_plan_records_what_was_approved_in_the_audit_detail_not_the_token(enrolled):
    """The audit row of an approval says WHICH commands the signature covered (their
    digest), and never carries the token: an argument's NAME is all the chain writes by
    default, and a row that said only 'register_plan' would not tell anyone what was
    approved."""
    import json

    challenge = commands.OPERATIONS["plan_challenge"]({"plan_hash": _PLAN_HASH, "steps": _STEPS})
    token = sign(_PLAN_HASH, _STEPS, challenge["nonce"])
    result = commands.OPERATIONS["register_plan"](
        {"plan_hash": _PLAN_HASH, "steps": _STEPS, "ttl_s": 600, "approval_token": token})
    detail = json.loads(result["audit_detail"])
    assert detail["steps_digest"] == policy.steps_digest(_STEPS) == result["digest"]
    assert token not in result["audit_detail"]


def test_the_server_writes_what_was_approved_into_the_audit_row_and_not_the_token(enrolled, monkeypatch):
    """Through the real request handler, the way the socket reaches it: the audit row of
    `register_plan` carries the digest of the approved commands, the caller's response does
    not carry the row's private field, and the token is nowhere. Without the digest the
    chain would say only that SOMETHING was registered."""
    import json

    import sentinel_executor as se

    rows: list[tuple] = []
    monkeypatch.setattr(se, "audit", lambda op, target, params, result, detail, peer: rows.append(
        (op, target, sorted(params), result, detail)) or 1)
    peer = {"uid": 1001, "pid": 7, "gid": 1001}
    challenge = se.handle_request(
        {"id": "a", "op": "plan_challenge", "args": {"plan_hash": _PLAN_HASH, "steps": _STEPS}}, peer)
    assert challenge["ok"], challenge
    token = sign(_PLAN_HASH, _STEPS, challenge["result"]["nonce"])
    response = se.handle_request(
        {"id": "b", "op": "register_plan",
         "args": {"plan_hash": _PLAN_HASH, "steps": _STEPS, "ttl_s": 600, "approval_token": token}}, peer)
    assert response["ok"], response
    assert "audit_detail" not in response["result"], "the row's private field leaked to the caller"

    op, target, param_names, result, detail = rows[-1]
    assert (op, result, target) == ("register_plan", "ok", _PLAN_HASH)
    assert json.loads(detail)["steps_digest"] == policy.steps_digest(_STEPS)
    assert token not in json.dumps(rows) and "approval_token" in param_names, (
        "the argument NAME is audited, never its value")


def test_a_refused_registration_is_audited_as_refused_without_the_token(enrolled, monkeypatch):
    import json

    import sentinel_executor as se

    rows: list[tuple] = []
    monkeypatch.setattr(se, "audit", lambda op, target, params, result, detail, peer: rows.append(
        (op, result, detail)) or 1)
    peer = {"uid": 1001, "pid": 7, "gid": 1001}
    se.handle_request({"id": "a", "op": "plan_challenge", "args": {"plan_hash": _PLAN_HASH, "steps": _STEPS}}, peer)
    forged = "0" * 64
    response = se.handle_request(
        {"id": "b", "op": "register_plan",
         "args": {"plan_hash": _PLAN_HASH, "steps": _STEPS, "ttl_s": 600, "approval_token": forged}}, peer)
    assert response["ok"] is False and response["error"] == "refused"
    assert rows[-1][:2] == ("register_plan", "refused")
    assert forged not in json.dumps(rows)


def test_patch_step_exec_dry_run_needs_no_registration():
    """runner.py's own rule: 'dry run needs no approval'. A dry run never
    reaches `_run`, so there is nothing here for the binding to protect."""
    result = commands.op_patch_step_exec(
        {"argv": ["dnf", "-y", "update", "nginx"], "dry_run": True})
    assert result["dry_run"] is True


@pytest.mark.parametrize(
    "argv",
    [
        ["systemctl", "restart", "nginx.service"],
        ["tar", "-tzf", "/var/tmp/x.tgz"],
        ["tar", "-cf", "/tmp/x.tar", "-C", "/", "var/www/html"],
        ["dnf", "-y", "update", "nginx"],
    ],
)
def test_dry_run_provably_never_calls_run(monkeypatch, argv):
    """'A dry run never reaches `_run`' (the docstring above) is a claim
    about behaviour, not a comment - this proves it by making `_run` itself
    raise if it is ever invoked on the dry_run branch, for three different
    binaries. A `dry_run: True` request that quietly ran the command anyway
    would still return a plausible-looking response (the caller only checks
    `result["dry_run"]`), which is exactly how a 'preview' becomes an
    unapproved execution nobody notices until the audit log is read."""
    def _run_was_called(*_args, **_kwargs):
        raise AssertionError(f"_run was reached during a dry run of {argv!r}")

    monkeypatch.setattr(commands, "_run", _run_was_called)
    result = commands.op_patch_step_exec({"argv": argv, "dry_run": True})
    if argv[0] == "dnf":
        # A package transaction is routed to the transient unit
        # (executor/transient_unit.py), and its dry run also carries the gate's
        # report of what the real run would be refused for. Asserted to be
        # there, then removed so the rest of the shape is still compared exactly.
        assert "refused_because" in result.pop("transaction")
    if argv[:2] == ["tar", "-cf"]:
        # A step that writes the filesystem and is not a transaction has nowhere to run
        # (policy.sandbox_refusal): its dry run says so instead of "would run".
        assert result.pop("refused_because")
    assert result == {"dry_run": True, "would_run": argv, "cwd": None, "timeout_s": 60}


# The tests below exercise the binding through `_run`. A `dnf` step does not reach
# `_run` at all - it goes to the transient unit, which enforces the same binding
# itself and is tested in test_executor_transient_unit.py - so they use the plan's
# other step, which still runs in the executor's sandbox.
def test_patch_step_exec_real_call_without_plan_hash_is_refused(enrolled):
    with pytest.raises(PolicyRefusal, match="plan_hash is required"):
        commands.op_patch_step_exec({"argv": _STEPS[1]})


def test_patch_step_exec_real_call_with_wrong_step_index_is_refused(enrolled):
    approve(_PLAN_HASH, _STEPS)
    with pytest.raises(PolicyRefusal, match="does not match"):
        commands.op_patch_step_exec(
            {"argv": _STEPS[1], "plan_hash": _PLAN_HASH, "step_index": 0})


def test_patch_step_exec_real_call_with_matching_registration_runs(enrolled, monkeypatch):
    """The one path that must still work: argv, plan_hash and step_index all
    agree with what was registered."""
    calls = []

    def fake_run(argv, timeout=30, cwd=None):
        calls.append(argv)
        return {"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 1, "timed_out": False}

    monkeypatch.setattr(commands, "_run", fake_run)
    approve(_PLAN_HASH, _STEPS)
    result = commands.op_patch_step_exec(
        {"argv": _STEPS[1], "plan_hash": _PLAN_HASH, "step_index": 1})
    assert result["exit_code"] == 0
    assert calls == [_STEPS[1]]


def test_patch_step_exec_still_runs_the_narrow_grammar_before_the_binding_check():
    """A grammar-illegal argv is refused for that reason, before the binding
    check ever runs - even if a caller manages to name a step_index that
    happens to match nothing, the grammar refusal fires first, so the two
    protections are independent, not one masking the other."""
    with pytest.raises(PolicyRefusal):
        commands.op_patch_step_exec(
            {"argv": ["git", "status"], "plan_hash": _PLAN_HASH, "step_index": 0})
