"""Binding a patch plan to the executor's approval: which commands, in which order,
and how the operator is asked to sign for them.

The executor (root) runs a real patch step only if its argv is, byte for byte, step
N of a plan an operator signed for (executor/policy.py, "Plan binding, and who is
allowed to approve a plan"). This module is the untrusted side of that contract:

* `flatten` turns a plan into the list of argvs the executor will be shown, in a
  fixed order, and remembers which entry belongs to which plan item - the runner
  and the checks send that index with every call;
* `challenge` asks the executor to describe what would be approved and to issue the
  nonce the operator's token must cover, and turns the answer into the one-line
  request the operator pastes into `scripts/approve-plan.py`;
* `register` hands the executor the operator's token together with the steps.

It holds no key and decides nothing. The worst a bug here can do is make an approval
fail, or ask the operator to sign something that is not what runs: the first is loud,
and the second is why the tool on the operator's side recomputes the digest and prints
the commands instead of trusting this module.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Any

from sentinel.errors import ExecutorRejected, ExecutorUnavailable
from sentinel.respond.executor_client import ExecutorClient

#: First characters of the one-line request. `scripts/approve-plan.py` refuses
#: anything that does not start with them; the two must agree (a test holds them).
REQUEST_PREFIX = "SENTINEL-APPROVAL-V1:"

#: How long the executor keeps an approval alive (its own ceiling is the same
#: number, `policy._MAX_TTL_S`). Everything the plan will send must happen inside it.
APPROVAL_TTL_S = 3600
#: What a plan's declared timeouts may add up to. The window starts when the operator
#: signs and the backup runs inside it before the first command does, so the
#: commands do not get all of `APPROVAL_TTL_S`. A registration that expires halfway
#: leaves a half-applied machine whose rollback is refused - the worst place to learn
#: the window was too short, so the plan is refused up front. Enforced in two places
#: that use the same sum (`flatten`): the VALIDATOR (`run_budget_exceeded`, so the plan is
#: never stored as valid or offered, and the planner's retry is told the numbers) and
#: `challenge` below (the last line, for a plan that got past it).
RUN_BUDGET_S = 2400
#: One Telegram message holds 4096 characters, and the request is not worth
#: truncating: a truncated request would not verify, and the operator would have no
#: way to tell why.
MAX_REQUEST_CHARS = 3200

#: The order commands are registered in. Fixed, because registration and execution
#: both derive indexes from it and a plan that reorders itself must not shift them.
PHASE_ORDER = ("preflight", "apply", "health_check", "post_verification", "rollback")
#: Phases whose items carry a literal argv; the others carry a typed check.
STEP_PHASES = ("apply", "rollback")
#: What `checks.py` gives a check that declares no timeout of its own: `command` reads
#: `timeout_s` (default 60), every other kind that reaches the executor uses 30.
_CHECK_DEFAULT_TIMEOUT_S = 30
_COMMAND_CHECK_DEFAULT_TIMEOUT_S = 60

_client = ExecutorClient()


class ApprovalError(Exception):
    """An approval cannot be asked for or completed. The message is for the operator."""


@dataclass(frozen=True)
class Flattened:
    """The commands of a plan, in registration order."""

    steps: list[list[str]]
    #: (phase, position in `plan[phase]`) -> index into `steps`. A plan item that
    #: sends no argv to the executor (a database check, a disk check) has no entry.
    index: dict[tuple[str, int], int]
    #: Sum of the timeouts the plan declares for those commands, in seconds.
    budget_s: int

    def ref(self, phase: str, position: int) -> int | None:
        return self.index.get((phase, position))


@dataclass(frozen=True)
class Binding:
    """What the runner needs to tell the executor which approved step a call is."""

    plan_hash: str
    flat: Flattened

    def for_item(self, phase: str, position: int) -> tuple[str, int] | None:
        step_index = self.flat.ref(phase, position)
        return None if step_index is None else (self.plan_hash, step_index)


def flatten(plan: dict[str, Any], family: str) -> Flattened:
    """Every argv the runner will send through `patch_step_exec`, in a fixed order.

    The check argvs come from `checks.argv_for` - the function `checks.evaluate` uses
    to execute and the validator uses to judge - so what is registered is what is run,
    by construction. A check missing a field its kind needs raises `ApprovalError`:
    the validator has already refused such a plan, and guessing what its author meant
    is not this function's job.
    """
    # Lazy: `checks` pulls in the database engine and the executor client, and this
    # module is imported by the Telegram flow, which must stay importable without them.
    from sentinel.patch.checks import argv_for

    steps: list[list[str]] = []
    index: dict[tuple[str, int], int] = {}
    budget = 0
    for phase in PHASE_ORDER:
        for position, item in enumerate(plan.get(phase) or []):
            if phase in STEP_PHASES:
                argv: list[str] | None = [str(a) for a in item.get("argv", [])]
                timeout = int(item.get("timeout_s", 60))
            else:
                check = item.get("check") or {}
                try:
                    argv = argv_for(check, family)
                except (KeyError, TypeError) as exc:
                    raise ApprovalError(
                        f"verificarea {item.get('id', position)} din faza {phase} nu poate fi "
                        f"transformată în comandă ({type(exc).__name__}: {exc})") from None
                timeout = (int(check.get("timeout_s", _COMMAND_CHECK_DEFAULT_TIMEOUT_S))
                           if check.get("kind") == "command" else _CHECK_DEFAULT_TIMEOUT_S)
            if not argv:
                continue
            index[(phase, position)] = len(steps)
            steps.append(list(argv))
            budget += timeout
    return Flattened(steps, index, budget)


def bind(plan: dict[str, Any], plan_hash: str, family: str) -> Binding:
    return Binding(plan_hash, flatten(plan, family))


def _policy() -> Any:
    """The executor's own policy module - the copy the validator already imports -
    for the one definition of "these steps". Refuses, in words, when it is too old
    to have it: a host that was not redeployed must say so, not fail on an
    AttributeError."""
    try:
        from executor import policy
    except Exception as exc:  # noqa: BLE001 - every import failure means the same thing here
        raise ApprovalError(f"politica executorului nu se poate încărca ({type(exc).__name__}: {exc})") from None
    if not hasattr(policy, "steps_digest"):
        raise ApprovalError("copia politicii executorului e veche (nu cunoaște rezumatul comenzilor); "
                            "redeploy-ul o aduce la zi")
    return policy


def build_request(plan_hash: str, digest: str, nonce: str, steps: list[list[str]]) -> str:
    """The one line the operator pastes into the signing tool: the prefix and the
    compact JSON, base64 url-safe. ASCII-escaped, so a character a chat client would
    rewrite cannot change what is signed."""
    payload = {"plan_hash": plan_hash, "digest": digest, "nonce": nonce, "steps": steps}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True).encode("ascii")
    return REQUEST_PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _executor_error(exc: Exception) -> ApprovalError:
    if isinstance(exc, ExecutorRejected):
        return ApprovalError(str(exc))
    return ApprovalError(f"executorul nu răspunde ({exc})")


async def challenge(plan: dict[str, Any], plan_hash: str, family: str, *,
                    client: ExecutorClient | None = None) -> str:
    """Ask the executor what would be approved and return the request to sign.

    Raises `ApprovalError` with the reason when it cannot be asked for: no key is
    enrolled (the executor says so), the plan's timeouts do not fit the approval
    window, the executor describes different commands than the ones sent, or the
    request would not fit one message.
    """
    flat = flatten(plan, family)
    if not flat.steps:
        raise ApprovalError("planul nu are nicio comandă pe care executorul s-o ruleze")
    if flat.budget_s > RUN_BUDGET_S:
        raise ApprovalError(
            f"planul declară timeouturi însumate de {flat.budget_s} s pentru comenzile lui; fereastra de "
            f"aprobare e de {APPROVAL_TTL_S} s și punctul de restaurare consumă din ea, deci planul "
            f"trebuie să încapă în {RUN_BUDGET_S} s. O aprobare expirată la jumătate ar lăsa un sistem "
            "pe jumătate modificat, cu revenirea refuzată.")
    digest = _policy().steps_digest(flat.steps)
    try:
        answer = await asyncio.to_thread((client or _client).call, "plan_challenge",
                                         plan_hash=plan_hash, steps=flat.steps)
    except (ExecutorRejected, ExecutorUnavailable) as exc:
        raise _executor_error(exc) from None
    nonce = answer.get("nonce")
    if answer.get("digest") != digest or answer.get("plan_hash") != plan_hash or not isinstance(nonce, str):
        raise ApprovalError("executorul a descris alte comenzi decât cele trimise; nu cer semnătura")
    request = build_request(plan_hash, digest, nonce, flat.steps)
    if len(request) > MAX_REQUEST_CHARS:
        raise ApprovalError(f"cererea de aprobare are {len(request)} de caractere și nu încape într-un "
                            f"mesaj Telegram ({MAX_REQUEST_CHARS}); planul are prea multe comenzi")
    return request


async def register(plan: dict[str, Any], plan_hash: str, family: str, token: str, *,
                   client: ExecutorClient | None = None) -> int:
    """Hand the executor the operator's token with the steps it covers. Returns the
    number of steps registered; raises `ApprovalError` with the executor's reason."""
    flat = flatten(plan, family)
    try:
        answer = await asyncio.to_thread((client or _client).call, "register_plan", plan_hash=plan_hash,
                                         steps=flat.steps, ttl_s=APPROVAL_TTL_S, approval_token=token)
    except (ExecutorRejected, ExecutorUnavailable) as exc:
        raise _executor_error(exc) from None
    count = answer.get("step_count")
    if not answer.get("registered") or count != len(flat.steps):
        raise ApprovalError("executorul n-a confirmat înregistrarea tuturor comenzilor planului")
    return count
