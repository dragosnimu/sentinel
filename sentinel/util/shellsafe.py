"""The only place in Sentinel that starts a subprocess.

Rules enforced here, and by tests:

* Commands are `list[str]`. Never a string.
* `shell=True` and `os.system` do not appear anywhere in this repository. A test
  greps for them.
* Every call has a timeout.
* Output is captured, size-bounded and redacted before it reaches a log, the
  database, a Telegram message or a model prompt.

Nothing in here decides *whether* a command is allowed to run — that is
`sentinel.patch.validator` for patch steps and `executor/policy.py` for
privileged operations. This module makes running a command safe once something
else has decided it may.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import signal
import subprocess  # noqa: S404 - the whole point of this module
import time
from dataclasses import dataclass
from pathlib import Path

from sentinel.constants import SHELL_METACHARACTERS
from sentinel.errors import UnsafeCommandError

MAX_CAPTURE_BYTES = 64 * 1024

# Environment variables never passed to a child process.
_ENV_DENY_PREFIXES = ("ANTHROPIC_", "TELEGRAM_", "SENTINEL_DB_", "PG")
_ENV_DENY_EXACT = frozenset({"SENTINEL_SECRETS", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"})

# Patterns redacted from captured output before it is stored or shown. Better to
# over-redact a log line than to leak a token into the database and then into a
# Telegram message.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"), "sk-ant-***REDACTED***"),
    (re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b"), "***TELEGRAM_TOKEN_REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
     r"\1=***REDACTED***"),
    (re.compile(r"(?i)://[^:/@\s]+:[^@/\s]+@"), "://***:***@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.DOTALL), "***PRIVATE_KEY_REDACTED***"),
)


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def redact(text: str) -> str:
    """Remove anything that looks like a credential."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _truncate(raw: bytes) -> str:
    text = raw[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    if len(raw) > MAX_CAPTURE_BYTES:
        text += f"\n[... truncated, {len(raw) - MAX_CAPTURE_BYTES} more bytes]"
    return redact(text)


def assert_safe_argv(argv: object) -> list[str]:
    """Validate the shape of a command. Raises rather than sanitising.

    Silently fixing a malformed command hides the bug that produced it.
    """
    if isinstance(argv, str):
        raise UnsafeCommandError(
            "command must be a list of strings, not a string — there is no shell"
        )
    if not isinstance(argv, list | tuple) or not argv:
        raise UnsafeCommandError("command must be a non-empty list of strings")

    out: list[str] = []
    for i, part in enumerate(argv):
        if not isinstance(part, str):
            raise UnsafeCommandError(f"argv[{i}] is {type(part).__name__}, expected str")
        for meta in SHELL_METACHARACTERS:
            if meta in part:
                raise UnsafeCommandError(
                    f"argv[{i}] contains {meta!r}; shell metacharacters are not "
                    "interpreted and their presence means the command was written "
                    "for a shell that does not exist here"
                )
        out.append(part)

    program = out[0]
    if program.startswith("/"):
        if not Path(program).is_file():
            raise UnsafeCommandError(f"{program} does not exist")
    elif "/" in program:
        raise UnsafeCommandError(
            f"argv[0]={program!r} is a relative path; use a bare name or an absolute path"
        )
    return out


def scrub_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A minimal environment with every secret-shaped variable removed."""
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108 - fallback only
        "TERM": "dumb",
        "DEBIAN_FRONTEND": "noninteractive",
    }
    for key, value in (extra or {}).items():
        if key in _ENV_DENY_EXACT or key.startswith(_ENV_DENY_PREFIXES):
            raise UnsafeCommandError(f"refusing to pass {key} to a child process")
        env[key] = value
    return env


def which(program: str) -> str | None:
    return shutil.which(program)


def run(
    argv: list[str],
    *,
    timeout_s: int = 60,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command synchronously. Never raises on a non-zero exit."""
    safe = assert_safe_argv(argv)
    started = _now_ms()
    try:
        proc = subprocess.run(  # noqa: S603 - argv validated above, shell=False
            safe,
            capture_output=True,
            timeout=timeout_s,
            cwd=cwd,
            env=scrub_env(env),
            input=input_text.encode() if input_text else None,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=safe,
            exit_code=124,
            stdout=_truncate(exc.stdout or b""),
            stderr=_truncate(exc.stderr or b"") + f"\n[timeout after {timeout_s}s]",
            duration_ms=_now_ms() - started,
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            argv=safe,
            exit_code=127,
            stdout="",
            stderr=redact(str(exc)),
            duration_ms=_now_ms() - started,
            timed_out=False,
        )

    return CommandResult(
        argv=safe,
        exit_code=proc.returncode,
        stdout=_truncate(proc.stdout),
        stderr=_truncate(proc.stderr),
        duration_ms=_now_ms() - started,
        timed_out=False,
    )


async def run_async(
    argv: list[str],
    *,
    timeout_s: int = 60,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Async variant. Kills the whole process group on timeout so a child that
    spawned children does not survive."""
    safe = assert_safe_argv(argv)
    started = _now_ms()

    proc = await asyncio.create_subprocess_exec(
        *safe,
        stdin=asyncio.subprocess.PIPE if input_text else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=scrub_env(env),
        start_new_session=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_text.encode() if input_text else None),
            timeout=timeout_s,
        )
    except TimeoutError:
        _kill_group(proc.pid)
        with contextlib.suppress(TimeoutError, ProcessLookupError):
            await asyncio.wait_for(proc.wait(), timeout=5)
        return CommandResult(
            argv=safe,
            exit_code=124,
            stdout="",
            stderr=f"[timeout after {timeout_s}s; process group killed]",
            duration_ms=_now_ms() - started,
            timed_out=True,
        )

    return CommandResult(
        argv=safe,
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=_truncate(stdout or b""),
        stderr=_truncate(stderr or b""),
        duration_ms=_now_ms() - started,
        timed_out=False,
    )


def _kill_group(pid: int) -> None:
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _now_ms() -> int:
    return int(time.monotonic() * 1000)
