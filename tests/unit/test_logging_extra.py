"""No reserved LogRecord attribute may appear as a key in a logging `extra=` dict.

Python's logging raises `KeyError: "Attempt to overwrite 'name' in LogRecord"` at
`makeRecord` time — before any filter runs — when `extra` carries a key that
collides with a built-in record attribute. It is not caught by import or by a
happy-path unit test; it only fires when that exact log line executes, which is
how a migration crashed mid-apply on the server. This static check keeps the
whole codebase clean of the class.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[2]

# Attributes LogRecord sets itself; `extra` may not overwrite any of them.
RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
}


def _py_files() -> list[Path]:
    out: list[Path] = []
    for d in ("sentinel", "executor", ".claude/skills/sentinel-soc/scripts"):
        out += [f for f in (REPO_ROOT / d).rglob("*.py") if "__pycache__" not in f.parts]
    return out


def test_no_reserved_keys_in_logging_extra():
    # Match an `extra={...}` up to the closing brace (non-greedy, single- or
    # multi-line), then pull the string-literal keys out of it.
    extra_block = re.compile(r"extra\s*=\s*\{(.*?)\}", re.DOTALL)
    key = re.compile(r"""["'](\w+)["']\s*:""")

    offenders: list[str] = []
    for f in _py_files():
        text = f.read_text(encoding="utf-8")
        for block in extra_block.finditer(text):
            line = text[: block.start()].count("\n") + 1
            for k in key.findall(block.group(1)):
                if k in RESERVED:
                    offenders.append(f"{f.relative_to(REPO_ROOT)}:{line}: '{k}'")
    assert not offenders, (
        "reserved LogRecord keys in extra= (rename them; logging crashes on these):\n  "
        + "\n  ".join(offenders)
    )
