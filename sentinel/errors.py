"""Exception hierarchy.

Distinguishing operational failures (the network is down, the API is rate
limited) from safety refusals (the policy says no) matters: the first is
retried, the second never is.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base for everything Sentinel raises deliberately."""


# ---------------------------------------------------------------------------
# Configuration and startup
# ---------------------------------------------------------------------------
class ConfigError(SentinelError):
    """Malformed, missing or contradictory configuration. Not retryable."""


class SecretMissingError(ConfigError):
    """A required secret is absent from secrets.env."""


# ---------------------------------------------------------------------------
# Safety refusals — never retried, always audited
# ---------------------------------------------------------------------------
class PolicyViolation(SentinelError):
    """An action was refused by policy. The caller does not get to retry."""


class NeverBlockViolation(PolicyViolation):
    """A block was requested for an address that may never be blocked."""


class RateCapExceeded(PolicyViolation):
    """A blocking rate cap was hit. Refusing further blocks is the safe result."""


class ProtectedTargetError(PolicyViolation):
    """An operation targeted a protected path, asset or unit."""


class UnsafeCommandError(PolicyViolation):
    """A command failed the argv safety rules (shell metacharacters, allowlist)."""


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------
class ExecutorError(SentinelError):
    """The privileged executor could not complete a request."""


class ExecutorUnavailable(ExecutorError):
    """The executor socket is not reachable. Retryable."""


class ExecutorRejected(ExecutorError):
    """The executor validated the request and refused it. Not retryable."""


# ---------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------
class PatchError(SentinelError):
    """Base for patch generation and execution failures."""


class PlanValidationError(PatchError):
    """A generated plan failed validation. Carries the structured error list."""

    def __init__(self, message: str, errors: list[dict[str, str]] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class PlanHashMismatch(PatchError):
    """An approval referenced a plan hash that is no longer current."""


class BackupFailedError(PatchError):
    """A backup step failed or its checksum did not verify. Nothing is applied."""


class RollbackFailedError(PatchError):
    """Rollback itself failed. This is the worst case and always alerts."""


# ---------------------------------------------------------------------------
# AI
# ---------------------------------------------------------------------------
class AIError(SentinelError):
    """Base for AI-layer failures."""


class AIUnavailable(AIError):
    """The model could not be reached. Degrade gracefully; do not block on it."""


class AIBudgetExceeded(AIError):
    """The configured spend cap was reached. Not retryable until it resets."""


class AIOutputInvalid(AIError):
    """The model returned something that does not match the expected schema."""


# ---------------------------------------------------------------------------
# Collection and storage
# ---------------------------------------------------------------------------
class CollectorError(SentinelError):
    """A collector failed. Isolated per collector so one bad source cannot stop
    ingestion of the others."""


class StorageError(SentinelError):
    """Database operation failed."""


# ---------------------------------------------------------------------------
# Telegram / web
# ---------------------------------------------------------------------------
class AuthorizationError(SentinelError):
    """The caller is not permitted to do this. Logged, never explained to them."""


class CallbackInvalid(SentinelError):
    """A callback token was expired, already used, tampered with, or bound to a
    different plan hash."""
