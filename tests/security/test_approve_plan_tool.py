"""The operator's signing tool (`scripts/approve-plan.py`).

This is the one place a human decides, so each test names what goes wrong for the
operator if it stops holding: a signature given for commands nobody read, a token that
the executor then refuses without saying why, or a key left where something else can
read it. The tool signs with the executor's own `policy.approval_token`, so the tests
also check that the two ends agree about what a valid key and token are.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys

import pytest

import policy
from _approval_support import KEY, KEY_HEX, enrol_key, tool
from sentinel.patch import approval

pytestmark = pytest.mark.security

PLAN_HASH = "ab" * 32
NONCE = "cd" * 16
STEPS = [["dnf", "-y", "update", "nginx"], ["systemctl", "reload", "nginx.service"]]


def request_for(steps=STEPS, *, digest=None, plan_hash=PLAN_HASH, nonce=NONCE) -> str:
    return approval.build_request(plan_hash, digest or policy.steps_digest(steps), nonce, steps)


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture
def keyed(tmp_path, monkeypatch):
    path = tmp_path / "operator" / "approval.key"
    path.parent.mkdir()
    path.write_text(KEY_HEX + "\n", encoding="ascii")
    monkeypatch.setenv("SENTINEL_APPROVAL_KEY_FILE", str(path))
    return path


def _sign(monkeypatch, capsys, request: str, answer: str, *, file=None, tmp_path=None):
    """Drive `sign` the way a person does: a terminal, the request pasted or given as a
    file, and an answer typed at the question."""
    typed = ([] if file else [request]) + [answer]
    monkeypatch.setattr(sys, "stdin", _Tty("\n".join(typed) + "\n"))
    argv = ["sign"] + ([str(file)] if file else [])
    code = tool.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# ---------------------------------------------------------------------------
# What is signed is what is shown
# ---------------------------------------------------------------------------
def test_the_token_is_printed_only_after_the_operator_types_the_digest(keyed, monkeypatch, capsys):
    """A yes/no question is answered by reflex. Typing the first eight digits of the
    digest is a deliberate act - and the digest is the thing the executor will check,
    so the operator has at least looked at the number that identifies what they sign."""
    digest = policy.steps_digest(STEPS)
    code, out, err = _sign(monkeypatch, capsys, request_for(), digest[:8])
    assert code == 0
    assert out.strip() == policy.approval_token(KEY, PLAN_HASH, digest, NONCE)


@pytest.mark.parametrize("answer", ["", "y", "da", "semnez", "0" * 8, "ABCDEF12"])
def test_anything_but_the_digest_signs_nothing(keyed, monkeypatch, capsys, answer):
    code, out, err = _sign(monkeypatch, capsys, request_for(), answer)
    assert code == 1
    assert out == "", "a token was printed although the operator did not confirm"


def test_the_commands_are_shown_in_order_before_the_question(keyed, monkeypatch, capsys):
    """The display that matters is the tool's, not the bot's: the operator reads the
    commands here, recomputed from the request, in the order they will run."""
    digest = policy.steps_digest(STEPS)
    code, out, err = _sign(monkeypatch, capsys, request_for(), digest[:8])
    assert err.index("dnf -y update nginx") < err.index("systemctl reload nginx.service")
    assert err.index("systemctl reload nginx.service") < err.index("Ca s")
    assert PLAN_HASH in err and digest in err


def test_stdout_carries_only_the_token(keyed, monkeypatch, capsys):
    """`sign | clip` must put a token in the clipboard and nothing else: the prompts and
    the commands are for the human and go to stderr."""
    digest = policy.steps_digest(STEPS)
    code, out, err = _sign(monkeypatch, capsys, request_for(), digest[:8])
    assert out.strip().isalnum() and len(out.strip()) == 64
    assert "Lipește" in err and "tastează" in err


def test_a_request_whose_digest_is_not_the_digest_of_its_commands_is_refused(keyed, monkeypatch, capsys):
    """The bot is what might lie. The tool recomputes the digest from the commands it
    was handed; a request that declares another is not signed, whatever the operator
    types."""
    code, out, err = _sign(monkeypatch, capsys, request_for(digest="0" * 64), "00000000")
    assert code == 2 and out == "" and "NU corespunde" in err


@pytest.mark.parametrize(
    "text,fragment",
    [
        ("", "trebuie să înceapă"),
        ("hello", "trebuie să înceapă"),
        (tool.REQUEST_PREFIX + "!!!", "decoda"),
        (tool.REQUEST_PREFIX + base64.urlsafe_b64encode(b"[1,2]").decode(), "nu e un obiect"),
        (tool.REQUEST_PREFIX + base64.urlsafe_b64encode(json.dumps({"plan_hash": "x"}).encode()).decode(),
         "nu are câmpul"),
    ],
)
def test_a_request_that_is_not_a_request_is_refused_with_the_reason(keyed, monkeypatch, capsys, text, fragment):
    code, out, err = _sign(monkeypatch, capsys, text, "00000000")
    assert code == 2 and out == "" and fragment in err


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(steps=[]),
        lambda d: d.update(steps=[[]]),
        lambda d: d.update(steps=[["dnf", 5]]),
        lambda d: d.update(plan_hash="nothex"),
        lambda d: d.update(nonce="short"),
    ],
)
def test_malformed_fields_are_refused_before_anything_is_signed(keyed, mutate):
    payload = {"plan_hash": PLAN_HASH, "nonce": NONCE, "digest": policy.steps_digest(STEPS), "steps": STEPS}
    mutate(payload)
    with pytest.raises(ValueError):
        tool.make_token(policy, KEY, payload)


def test_a_command_the_executor_would_refuse_is_flagged_but_the_operator_decides(keyed, monkeypatch, capsys):
    """A plan that cannot run should not be signed blindly, and a tool that refused it
    outright would hide what the executor will say. It warns, in front of the command."""
    steps = [["git", "status"]]
    code, out, err = _sign(monkeypatch, capsys, request_for(steps), policy.steps_digest(steps)[:8])
    assert "ATENȚIE" in err and "refuză" in err
    assert code == 0


# ---------------------------------------------------------------------------
# The human must be there
# ---------------------------------------------------------------------------
def test_without_a_terminal_it_refuses_to_sign_at_all(keyed, monkeypatch, capsys):
    """The same hole moved to the operator's machine: a signature that any script, pipe
    or process started by someone else can request is not an approval by a person."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(request_for() + "\n" + policy.steps_digest(STEPS)[:8] + "\n"))
    code = tool.main(["sign"])
    out = capsys.readouterr()
    assert code == 3 and out.out == ""
    assert "un om la tastatură" in out.err


def test_a_console_that_cannot_print_romanian_does_not_crash_the_tool(keyed, monkeypatch):
    """A Windows console in cp1252 cannot encode the diacritics this tool prints - it
    crashed with UnicodeEncodeError exactly when the operator needed it. A character
    shown as `?` is ugly; a token that cannot be printed is an outage."""
    narrow = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stderr", narrow)
    monkeypatch.setattr(sys, "stdin", io.StringIO("x"))  # not a terminal: prints the Romanian refusal
    assert tool.main(["sign"]) == 3


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------
def test_init_makes_a_key_the_executor_accepts_and_never_overwrites_one(tmp_path, monkeypatch, capsys):
    """The key made here is the key the executor reads, byte for byte in format: if the
    two disagreed about the format the operator would enrol a key the executor then
    refuses as malformed. And an existing key is never replaced: a new one would
    silently invalidate the one already on the host."""
    path = tmp_path / "k" / "approval.key"
    monkeypatch.setenv("SENTINEL_APPROVAL_KEY_FILE", str(path))
    assert tool.main(["init"]) == 0
    made = path.read_text(encoding="ascii")
    assert len(made.strip()) == 64 and made.endswith("\n")
    enrol_key(tmp_path, monkeypatch, key_hex=made.strip())
    assert policy._read_approval_key() == bytes.fromhex(made.strip())
    assert tool.main(["init"]) == 1
    assert path.read_text(encoding="ascii") == made


@pytest.mark.skipif(not hasattr(os, "chmod") or os.name == "nt", reason="needs POSIX modes")
def test_init_creates_the_key_readable_by_its_owner_only(tmp_path, monkeypatch):
    path = tmp_path / "approval.key"
    monkeypatch.setenv("SENTINEL_APPROVAL_KEY_FILE", str(path))
    tool.main(["init"])
    assert path.stat().st_mode & 0o777 == 0o600


def test_show_key_prints_the_key_in_the_format_the_host_expects(keyed, capsys):
    assert tool.main(["show-key"]) == 0
    assert capsys.readouterr().out.strip() == KEY_HEX


def test_a_missing_or_malformed_key_stops_the_tool_with_the_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_APPROVAL_KEY_FILE", str(tmp_path / "absent.key"))
    with pytest.raises(SystemExit, match="init"):
        tool.read_key()
    bad = tmp_path / "bad.key"
    bad.write_text("not a key", encoding="ascii")
    monkeypatch.setenv("SENTINEL_APPROVAL_KEY_FILE", str(bad))
    with pytest.raises(SystemExit, match="nu e o cheie"):
        tool.read_key()


def test_the_digest_and_the_token_come_from_the_executors_own_policy(keyed):
    """One definition of 'these commands' and of 'a token for them', shared by the signer
    and the verifier. A tool with its own copy could drift into producing tokens that
    never verify."""
    payload = {"plan_hash": PLAN_HASH, "nonce": NONCE, "digest": policy.steps_digest(STEPS), "steps": STEPS}
    token, digest = tool.make_token(policy, KEY, payload)
    assert digest == policy.steps_digest(STEPS)
    assert token == policy.approval_token(KEY, PLAN_HASH, digest, NONCE)
