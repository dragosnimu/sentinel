"""Support for the tests of the executor's approval path. Not a test module.

An approval has two ends - the executor that verifies a token (executor/policy.py)
and the operator's tool that signs one (scripts/approve-plan.py) - and a test that
signs with a second implementation of the signing would pass while the two disagreed
in production. So the tests sign with the tool itself, loaded from the script, and
verify with the executor's own code.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "executor"))

import policy  # noqa: E402

#: Derived, not written out: a 64-digit hex literal in a tracked file is what
#: tests/security/test_repo_is_sanitised.py reads as a leaked secret.
KEY_HEX = hashlib.sha256(b"unit-test approval key - not a secret").hexdigest()
KEY = bytes.fromhex(KEY_HEX)
OTHER_KEY = bytes.fromhex(hashlib.sha256(b"a different key").hexdigest())


def _load_tool():
    spec = importlib.util.spec_from_file_location("approve_plan_tool", REPO / "scripts" / "approve-plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: The operator's signing tool, as shipped.
tool = _load_tool()


def enrol_key(tmp_path, monkeypatch, key_hex: str = KEY_HEX) -> Path:
    """Put a key where the executor reads one, with the properties a real one has.

    Where the platform has uids the REAL ownership and mode check runs against a
    real file (the test's own uid stands in for root, which a test cannot be). Where
    it does not (Windows) that check is replaced by one that passes: `_key_stat_problem`
    has its own platform-independent table of tests, and `_read_approval_key`'s use of
    real stat results is covered wherever a POSIX filesystem exists.
    """
    path = tmp_path / "approval.key"
    path.write_text(key_hex + "\n", encoding="ascii")
    monkeypatch.setattr(policy, "_APPROVAL_KEY_PATH", path)
    if hasattr(os, "getuid"):
        path.chmod(0o600)
        tmp_path.chmod(0o700)
        monkeypatch.setattr(policy, "_APPROVAL_KEY_OWNER_UID", os.getuid())
    else:
        monkeypatch.setattr(policy, "_key_stat_problem", lambda **_kw: None)
    return path


def sign(plan_hash: str, steps: list[list[str]], nonce: str, key: bytes = KEY) -> str:
    """What the operator's tool prints for this request."""
    request = {"plan_hash": plan_hash, "nonce": nonce, "digest": policy.steps_digest(steps), "steps": steps}
    token, _digest = tool.make_token(policy, key, request)
    return token


def approve(plan_hash: str, steps: list[list[str]], ttl: int = 600, key: bytes = KEY) -> int:
    """The whole approval, through the executor's real challenge and registration."""
    challenge = policy.challenge_plan_steps(plan_hash, steps)
    return policy.register_plan_steps(plan_hash, steps, ttl, sign(plan_hash, steps, challenge["nonce"], key))
