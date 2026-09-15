"""The client's socket timeout must cover the executor's own declared duration.

Prevents: a patch step (or check) with a legitimate `timeout_s` of up to
3600s (executor/commands.py, op_patch_step_exec) being reported as
`ExecutorUnavailable` by a client that gave up after its own fixed, much
shorter default — while the step was still running as root on the other end.
That mismatch is what let a rollback start concurrently with the very apply
step it was rolling back: the runner saw "unavailable" and moved to recover
from a failure that had not actually happened yet.

Two layers of test:

* `_FakeSocket` tests replace the socket module entirely and assert on the
  exact value handed to `settimeout()` — this is the one thing the fix
  changes, and it does not need a real socket of any address family to
  observe.
* The `_fake_slow_executor` tests reproduce the bug end-to-end over a real
  unix-domain socket, sleeping to simulate genuine server-side work. They are
  skipped where `socket.AF_UNIX` does not exist — this sandbox's Python
  build lacks it entirely (`hasattr(socket, "AF_UNIX")` is False here even
  though the target host is Linux, where the executor actually runs) — so
  they could not be observed failing/passing from this machine. See the
  hand-off notes for what that means for verification.
"""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from sentinel.errors import ExecutorUnavailable
from sentinel.respond.executor_client import TIMEOUT_MARGIN_S, ExecutorClient


# ---------------------------------------------------------------------------
# Layer 1: exact value passed to settimeout(), no real socket needed
# ---------------------------------------------------------------------------
class _FakeSocket:
    """Stands in for `socket.socket(...)`. Records the timeout it was given
    and answers one well-formed response, regardless of what was sent."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.timeout: float | None = None
        self._answered = False
        self.sent: list[dict] = []

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, _path: str) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(json.loads(data.rstrip(b"\n")))

    def recv(self, _n: int) -> bytes:
        if self._answered:
            return b""
        self._answered = True
        return json.dumps({"ok": True, "result": {"exit_code": 0}}).encode() + b"\n"

    def close(self) -> None:
        pass

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _patch_socket_module(monkeypatch) -> list[_FakeSocket]:
    """Replace both `socket.socket` and `socket.AF_UNIX` for the client
    module under test.

    `AF_UNIX` itself is patched too, not just the socket constructor: this
    sandbox's Python build has no `socket.AF_UNIX` attribute at all (see the
    module docstring), so `executor_client.call()`'s own
    `socket.socket(socket.AF_UNIX, ...)` line fails on the attribute lookup
    before the fake constructor is ever reached. `raising=False` because the
    attribute may not exist here to begin with.
    """
    created: list[_FakeSocket] = []

    def fake_socket_factory(*args: object, **kwargs: object) -> _FakeSocket:
        sock = _FakeSocket(*args, **kwargs)
        created.append(sock)
        return sock

    monkeypatch.setattr("sentinel.respond.executor_client.socket.socket", fake_socket_factory)
    monkeypatch.setattr("sentinel.respond.executor_client.socket.AF_UNIX", 1, raising=False)
    return created


def test_default_call_uses_the_instances_own_timeout(monkeypatch):
    """No regression: a call without an override must behave exactly as
    before this change — this is an addition to the client, not a
    replacement of its per-instance timeout."""
    created = _patch_socket_module(monkeypatch)
    client = ExecutorClient("/run/sentinel/executor.sock", timeout_s=30)
    client.call("ping")

    assert len(created) == 1
    assert created[0].timeout == 30


def test_socket_timeout_s_override_reaches_settimeout(monkeypatch):
    """The fix: passing socket_timeout_s must be what `settimeout()` actually
    receives, not the client's own fixed default — this is the exact
    mechanism that let a client give up on a step still running as root."""
    created = _patch_socket_module(monkeypatch)
    client = ExecutorClient("/run/sentinel/executor.sock", timeout_s=30)
    step_timeout = 3600
    client.call("patch_step_exec", argv=["true"], timeout_s=step_timeout,
                socket_timeout_s=step_timeout + TIMEOUT_MARGIN_S)

    assert len(created) == 1
    assert created[0].timeout == step_timeout + TIMEOUT_MARGIN_S
    assert created[0].timeout > client.timeout_s, (
        "socket_timeout_s must be able to exceed the client's own fixed "
        "default; if it does not, the override is decorative"
    )


def test_socket_timeout_s_does_not_leak_into_the_executors_own_args(monkeypatch):
    """`socket_timeout_s` is consumed by `call()` itself and must never reach
    the executor's `args` dict.

    Before `socket_timeout_s` was a real, explicit keyword on `call(**args)`,
    it would have been swallowed into `**args` like any other caller-supplied
    field and sent over the wire as a command argument the executor's policy
    was never written to expect — a silent second bug hiding behind the
    ImportError this round actually fixes (see the module this test lives
    next to)."""
    created = _patch_socket_module(monkeypatch)
    client = ExecutorClient("/run/sentinel/executor.sock", timeout_s=30)
    client.call("patch_step_exec", argv=["true"], timeout_s=5, socket_timeout_s=999)

    assert len(created) == 1
    sent_args = created[0].sent[0]["args"]
    assert "socket_timeout_s" not in sent_args
    assert sent_args == {"argv": ["true"], "timeout_s": 5}


# ---------------------------------------------------------------------------
# Layer 2: end-to-end over a real unix-domain socket, skipped where the
# platform's Python build has none (this sandbox; not the Linux target host).
# ---------------------------------------------------------------------------
requires_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="this Python build has no socket.AF_UNIX; the executor's actual "
           "transport cannot be exercised end-to-end from here",
)


def _fake_slow_executor(sock_path: str, delay_s: float) -> None:
    """Accept one connection, read one request line, sleep, answer `ok`.

    Mirrors the real executor's shape closely enough for this test: it does
    not touch the socket at all while "processing" (the sleep), exactly like
    `sentinel_executor.handle_request` does not touch the socket while a
    subprocess runs — the client's timeout is therefore purely about how
    long it waits for bytes to arrive, never about server-side processing
    time.
    """
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(10)
    try:
        conn, _ = server.accept()
    except OSError:
        return
    try:
        conn.settimeout(10)
        buffer = b""
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buffer += chunk
        time.sleep(delay_s)
        response = json.dumps({"ok": True, "result": {"exit_code": 0, "stdout": "", "stderr": ""}})
        conn.sendall(response.encode() + b"\n")
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        server.close()


def _start_fake_executor(sock_path: str, delay_s: float) -> threading.Thread:
    thread = threading.Thread(target=_fake_slow_executor, args=(sock_path, delay_s), daemon=True)
    thread.start()
    time.sleep(0.2)
    return thread


@requires_af_unix
def test_short_default_client_timeout_reports_unavailable_for_a_slow_step(tmp_path):
    """Reproduces the mismatch directly: a step whose own timeout_s is 5s,
    sleeping 2s to simulate genuine work, reported as unreachable by a client
    whose default socket timeout (1s) has nothing to do with that 5s."""
    sock_path = str(tmp_path / "executor.sock")
    thread = _start_fake_executor(sock_path, delay_s=2)
    try:
        client = ExecutorClient(sock_path, timeout_s=1)
        with pytest.raises(ExecutorUnavailable):
            client.call("patch_step_exec", argv=["true"], timeout_s=5)
    finally:
        thread.join(timeout=5)


@requires_af_unix
def test_socket_timeout_s_override_lets_the_same_slow_step_succeed(tmp_path):
    """The fix, end-to-end: passing socket_timeout_s derived from the step's
    own timeout_s plus TIMEOUT_MARGIN_S must let the identical slow step
    complete instead of being reported unavailable."""
    sock_path = str(tmp_path / "executor.sock")
    thread = _start_fake_executor(sock_path, delay_s=2)
    try:
        client = ExecutorClient(sock_path, timeout_s=1)
        result = client.call(
            "patch_step_exec", argv=["true"], timeout_s=5,
            socket_timeout_s=5 + TIMEOUT_MARGIN_S,
        )
        assert result["exit_code"] == 0
    finally:
        thread.join(timeout=5)
