"""Every field the formatters render goes through redaction — except one, named below.

The first version of this docstring said "nothing reaches journald without
passing the redaction step". That was false when it was written: `payload["msg"]`
was not redacted, so a non-string `msg` or `%`-argument went out raw. A sentence
like that is worse than no sentence — the next person wondering whether `msg` is
safe reads it and stops looking. So this one is written to be checkable, and the
gap that remains is named rather than rounded off.

**Covered, and tested below:** `msg` after interpolation, `exc`, `stack`, string
extras, and extras the formatter has to stringify.

**Not covered:** strings nested inside a JSON-serialisable extra —
`extra={"peer": {"auth": "token=..."}}` is handed to `json.dumps` whole. Five
call sites pass container extras today — three of them build the dict at
runtime (`extra=vars(result)`, `extra=summary`), which is why an earlier census
that scanned literal `extra={...}` dicts reported four and named the wrong
three. None carries a credential, and nothing prevents one.
Note that `redact` is contextual, so recursing into containers
would clean a self-describing leaf but not a split `{"token": "<value>"}`.

`RedactingFilter` cleans `record.msg` and `record.args` only when they are
already `str`, plus the string extras. It cannot clean the exception: `exc_info`
and `exc_text` are in `_RESERVED`, deliberately, and a filter cannot rewrite a
traceback that has not been rendered yet. So every `exc_info=`/`log.exception()`
call used to put the exception text into `payload["exc"]` untouched.

That path is live today: a PostgreSQL constraint violation quotes the rejected
row verbatim, and on this deployment the rejected row is whatever the operator
typed into a Telegram chat. Only "the operator pasted a credential" is
speculative; "the exception message reproduces user text" is not.

These tests assert on the WHOLE rendered line, never on a chosen field. The bug
this file exists to prevent was found under a test that named the leak in its
docstring and then asserted on a different field, which was already safe.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from sentinel.logging_setup import HumanFormatter, JSONFormatter, RedactingFilter
from sentinel.util.shellsafe import redact

SECRET = "aBcDeF1234567890"          # matched by the `token=...` pattern
ANTHROPIC_KEY = "sk-ant-" + "A1b2C3d4E5f6G7h8i9"


def _emit(fn, *, service: str = "sentinel-test") -> str:
    """Run `fn(logger)` through a handler wired exactly like `setup_logging`."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter(service))
    handler.addFilter(RedactingFilter())

    logger = logging.getLogger("sentinel.tests.redaction")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    try:
        fn(logger)
    finally:
        logger.handlers = []
    return stream.getvalue()


def _raise(message: str) -> Exception:
    try:
        raise ValueError(message)
    except ValueError as exc:
        return exc


# --- the exception path -----------------------------------------------------
def test_a_credential_in_an_exception_message_never_reaches_the_log():
    """The hole this file was written for. `log.exception` and `exc_info=` are
    the only inputs the filter is structurally unable to clean, and an exception
    message is the single most likely place for user text to reappear."""
    exc = _raise(f"new row violates check constraint: token={SECRET}")
    line = _emit(lambda log: log.error("write failed", exc_info=exc))

    assert SECRET not in line, line
    payload = json.loads(line)
    assert "REDACTED" in payload["exc"]
    # Redacted, not deleted: the diagnosis has to survive.
    assert "ValueError" in payload["exc"] and "Traceback" in payload["exc"]


def test_log_exception_is_covered_too():
    """`log.exception()` sets `exc_info` without ever naming it, so a grep for
    `exc_info` misses these. Two callers already exist in `sentinel/web/`."""
    def emit(log):
        try:
            raise RuntimeError(f"upstream said {ANTHROPIC_KEY}")
        except RuntimeError:
            log.exception("call failed")

    line = _emit(emit)
    assert ANTHROPIC_KEY not in line, line
    assert "REDACTED" in json.loads(line)["exc"]


def test_a_credential_in_a_chained_cause_is_redacted_as_well():
    """`raise ... from ...` renders both tracebacks. Cleaning only the outermost
    exception would leave the interesting one — the database error — in place."""
    def emit(log):
        try:
            try:
                raise ValueError(f"token={SECRET}")
            except ValueError as inner:
                raise RuntimeError("wrapped") from inner
        except RuntimeError:
            log.exception("failed")

    line = _emit(emit)
    assert SECRET not in line, line


def test_stack_info_is_redacted():
    """`stack_info` is the second reserved attribute the filter cannot see.

    The value is planted directly rather than produced by `stack_info=True`,
    and that is the honest way to test this: a rendered stack contains SOURCE
    LINES, so it can never hold a runtime secret. The first version of this test
    passed `stack_info=True` with the secret in the message — it passed with the
    redaction removed, because the stack showed the literal text `token={SECRET}`
    and the message was cleaned by the filter. It asserted nothing.

    Nothing in `sentinel/` passes `stack_info=True` today. This covers the field
    because it is the same mechanism as `exc`, not because a leak is likely
    through it.
    """
    def emit(log):
        record = log.makeRecord("t", logging.ERROR, __file__, 1, "boom", (), None,
                                sinfo=f"Stack (most recent call last):\n  token={SECRET}")
        log.handle(record)

    line = _emit(emit)
    payload = json.loads(line)
    assert "stack" in payload, "campul nu a fost randat deloc; testul nu ar dovedi nimic"
    assert SECRET not in line, line
    assert "REDACTED" in payload["stack"]


# --- the rendered message ---------------------------------------------------
def test_a_non_string_percent_argument_is_redacted():
    """`log.debug("cannot read %s: %s", path, exc)`.

    The filter skips `exc` because it is not a `str`, and the interpolation that
    turns it into text happens in the formatter. Between the two, nothing looked
    at it. This is the shape real code already uses — two such calls exist in
    `sentinel/`, neither carrying a credential today.
    """
    exc = _raise(f"token={SECRET}")
    line = _emit(lambda log: log.debug("cannot read %s: %s", "/proc/net/tcp", exc))

    assert SECRET not in line, line
    payload = json.loads(line)
    assert "/proc/net/tcp" in payload["msg"] and "REDACTED" in payload["msg"]


def test_a_non_string_message_object_is_redacted():
    """`log.error(exc)` — the message itself is not a string, so the filter's
    `isinstance(record.msg, str)` guard skips it entirely."""
    line = _emit(lambda log: log.error(_raise(f"token={SECRET}")))

    assert SECRET not in line, line
    assert "REDACTED" in json.loads(line)["msg"]


def test_the_two_formatters_cover_the_same_fields():
    """`HumanFormatter` wraps the whole line, so `msg` was always safe there;
    `JSONFormatter` builds field by field and had missed it. The formatter that
    runs under systemd was the weaker of the two — the exact inverse of the risk
    order, since journald is the more public of the two destinations."""
    exc = _raise(f"token={SECRET}")
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "read %s failed",
                               (exc,), None)

    assert SECRET not in JSONFormatter("sentinel-test").format(record)
    assert SECRET not in HumanFormatter("sentinel-test").format(record)


# --- the paths the filter already covered, kept as regressions --------------
@pytest.mark.parametrize("emit,label", [
    (lambda log: log.error(f"raw token={SECRET}"), "msg"),
    (lambda log: log.error("with extra", extra={"detail": f"token={SECRET}"}), "extra str"),
    (lambda log: log.error("with arg %s", f"token={SECRET}"), "args"),
])
def test_the_paths_the_filter_already_covered_stay_covered(emit, label):
    line = _emit(emit)
    assert SECRET not in line, f"{label}: {line}"


def test_an_unserialisable_extra_is_redacted_when_it_is_stringified():
    """A non-JSON value is turned into text by the formatter, after the filter
    has run — so the filter never saw a string to clean."""
    class Opaque:
        def __str__(self) -> str:
            return f"Opaque(token={SECRET})"

    line = _emit(lambda log: log.error("odd extra", extra={"payload": Opaque()}))
    assert SECRET not in line, line
    assert "REDACTED" in json.loads(line)["payload"]


# --- why the redaction is applied to values, not to the serialised line -----
def test_redacting_the_serialised_json_would_corrupt_it():
    """Guards the shape of the fix, not just its effect.

    The credential pattern ends in `\\S+`, which is greedy and does not stop at
    a quote. Applied to already-serialised JSON it eats the closing quote and
    the comma, and journald gets a line no parser can read — a silent loss of
    every log entry that happens to mention a token. So the formatter redacts
    the VALUES. If someone later "simplifies" it to one call around
    `json.dumps`, this test says why not.
    """
    serialised = json.dumps({"detail": f"token={SECRET}", "chat_id": 42})
    with pytest.raises(json.JSONDecodeError):
        json.loads(redact(serialised))

    # The real formatter, on the same content, stays parseable.
    line = _emit(lambda log: log.error("x", extra={"detail": f"token={SECRET}",
                                                   "chat_id": 42}))
    assert json.loads(line)["chat_id"] == 42
    assert SECRET not in line


# --- the docstring has to stay true -----------------------------------------
def test_every_reachable_field_is_covered_and_the_gap_is_exactly_where_documented():
    """Pins the claim the module docstrings make, so it cannot rot again.

    The first version of those docstrings claimed total coverage while `msg`
    leaked. The fix is not to write a softer sentence — it is to make the
    sentence checkable. Every field a caller can put text into is asserted
    clean here, and the one known gap is asserted to be still exactly that one.

    If someone closes the nested-container gap, this test fails on the last
    assertion. That is the intended signal: close it, then delete the assertion
    and the "Not covered" paragraph from both docstrings. Do NOT satisfy this
    test by putting the leak back.
    """
    exc = _raise(f"in-exception token={SECRET}")

    def emit(log):
        # The secret reaches `msg` through the non-string argument, which is the
        # path the filter cannot see. The format string deliberately contains no
        # credential word: `RedactingFilter` rewrites `record.msg` itself, so a
        # literal `token=%s` there would be redacted into `token=***REDACTED***`,
        # eat the placeholder, and make `msg % args` raise — see the report.
        log.error("in-msg %s", exc, exc_info=exc,
                  extra={"detail": f"in-extra token={SECRET}",
                         # Self-describing leaf: `redact` CAN see this one, and
                         # a recursive filter would clean it. A split key/value
                         # like {"token": SECRET} is a harder case that value
                         # recursion does not solve — see the docstring.
                         "nested": {"auth": f"token={SECRET}"}})

    line = _emit(emit)
    payload = json.loads(line)

    for field in ("msg", "exc", "detail"):
        assert SECRET not in str(payload[field]), f"{field} leaks: {payload[field]!r}"

    # The documented gap, still exactly one field wide.
    leaking = [k for k, v in payload.items() if SECRET in str(v)]
    assert leaking == ["nested"], (
        "the set of leaking fields changed. If you closed the nested-container "
        f"gap, update both docstrings and this test. Leaking now: {leaking}")


# --- the terminal formatter ------------------------------------------------
def test_the_human_formatter_redacts_the_traceback_too():
    """Used when stderr is a tty. The base `logging.Formatter` appends
    `exc_text`, which the filter never touched either."""
    exc = _raise(f"token={SECRET}")
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", None,
                               (type(exc), exc, exc.__traceback__))
    rendered = HumanFormatter("sentinel-test").format(record)
    assert SECRET not in rendered, rendered
    assert "ValueError" in rendered
