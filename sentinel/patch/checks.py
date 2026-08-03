"""Evaluate the structured checks a patch plan declares.

Preflight, health_check and post_verification are not free-form commands: each
is a `{kind, ...}` object the plan author picked from a fixed vocabulary. That
matters for safety — "is nginx active?" expressed as `{"kind": "systemd", "unit":
"nginx.service", "expect_state": "active"}` cannot be turned into anything else,
whereas the same question expressed as a shell command can.

Only the `command` kind reaches the executor, and it does so through the same
validated-argv path as an apply step. Every other kind is answered by a targeted
query the executor already exposes.

A check that cannot be evaluated is a FAILED check, never a passing one. The
alternative — treating "I could not tell" as "fine" — is how a patch proceeds
against a machine nobody actually verified.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger
from sentinel.respond.executor_client import ExecutorClient

log = get_logger(__name__)

_client = ExecutorClient()


@dataclass
class CheckOutcome:
    ok: bool
    detail: str
    kind: str = ""


async def _exec(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    return await asyncio.to_thread(
        _client.call, "patch_step_exec", argv=argv, timeout_s=timeout)


async def evaluate(db: Database, check: dict[str, Any]) -> CheckOutcome:
    """Run one check. Never raises: an error is a failed check."""
    kind = str(check.get("kind", ""))
    try:
        return await _dispatch(db, kind, check)
    except Exception as exc:  # noqa: BLE001 - unevaluable is failed, not passed
        return CheckOutcome(False, f"verificarea nu a putut fi evaluată: {exc}", kind)


async def _dispatch(db: Database, kind: str, c: dict[str, Any]) -> CheckOutcome:
    if kind == "systemd":
        unit, expect = str(c["unit"]), str(c["expect_state"])
        res = await _exec(["systemctl", "is-active", unit])
        state = str(res.get("stdout", "")).strip()
        return CheckOutcome(state == expect, f"{unit} este {state!r}, așteptat {expect!r}", kind)

    if kind == "command":
        argv = [str(a) for a in c["argv"]]
        expect = [int(x) for x in c.get("expect_exit", [0])]
        res = await _exec(argv, timeout=int(c.get("timeout_s", 60)))
        code = res.get("exit_code")
        return CheckOutcome(code in expect, f"cod {code}, așteptat {expect}", kind)

    if kind == "file_exists":
        res = await _exec(["test", "-e", str(c["path"])])
        return CheckOutcome(res.get("exit_code") == 0, f"{c['path']} există", kind)

    if kind == "file_absent":
        res = await _exec(["test", "-e", str(c["path"])])
        return CheckOutcome(res.get("exit_code") != 0, f"{c['path']} lipsește", kind)

    if kind == "pkg_version":
        name = str(c["name"])
        res = await _exec(["rpm", "-q", name])
        installed = str(res.get("stdout", "")).strip()
        want = c.get("expect_version")
        if want:
            return CheckOutcome(str(want) in installed,
                                f"{installed or 'neinstalat'}, așteptat {want}", kind)
        return CheckOutcome(res.get("exit_code") == 0, installed or "neinstalat", kind)

    if kind == "disk_free":
        info = await asyncio.to_thread(_client.call, "disk_free", path=str(c["path"]))
        free = int(info.get("free", 0))
        need = int(c["min_bytes"])
        return CheckOutcome(free >= need,
                            f"{free // 1_048_576} MB liberi, necesari {need // 1_048_576} MB",
                            kind)

    if kind == "no_open_incident":
        # Patching a machine that is actively under attack turns two problems
        # into one confusing one.
        n = int(await db.fetchval(
            "SELECT count(*) FROM incidents WHERE status IN ('open','acknowledged') "
            "AND severity IN ('high','critical') "
            # Cast for the same reason as in repo/patches.py: a parameter whose
            # only other appearance is a bare IS NULL cannot always be inferred.
            "AND (asset_id = $1::bigint OR $1::bigint IS NULL)",
            c.get("asset_id")) or 0)
        return CheckOutcome(n == 0, f"{n} incidente grave deschise", kind)

    if kind == "file_sha256":
        res = await _exec(["sha256sum", str(c["path"])])
        actual = str(res.get("stdout", "")).split()[0] if res.get("stdout") else ""
        return CheckOutcome(actual == str(c["sha256"]),
                            f"sha256 {'corespunde' if actual == str(c['sha256']) else 'diferit'}",
                            kind)

    if kind in ("http", "tcp", "docker"):
        # These need a network probe or the docker socket. The health prober
        # already owns those; wiring them here would duplicate that logic with
        # slightly different timeouts, which is how two answers to one question
        # appear. Declared unsupported rather than silently passing.
        return CheckOutcome(False, f"verificarea {kind} nu este încă implementată "
                                   "în runner — folosește kind 'command'", kind)

    return CheckOutcome(False, f"tip de verificare necunoscut: {kind}", kind)
