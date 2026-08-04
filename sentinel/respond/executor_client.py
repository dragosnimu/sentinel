"""Client for the privileged executor's unix socket.

Deliberately stdlib-only and free of imports from anywhere else in this package
except `errors`. The watchdog runs as root, must work when the database is down
and the rest of Sentinel has failed, and is invoked as a bare script — so
anything it depends on has to be equally simple.

The executor validates every request against its own hard-coded policy, so a
bug here cannot widen what is permitted. The worst a broken client can do is
fail to ask.
"""

from __future__ import annotations

import json
import socket
import uuid
from typing import Any

from sentinel.errors import ExecutorRejected, ExecutorUnavailable

DEFAULT_SOCKET = "/run/sentinel/executor.sock"
DEFAULT_TIMEOUT_S = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ExecutorClient:
    def __init__(
        self, socket_path: str = DEFAULT_SOCKET, timeout_s: int = DEFAULT_TIMEOUT_S
    ) -> None:
        self.socket_path = socket_path
        self.timeout_s = timeout_s

    def call(self, op: str, **args: Any) -> dict[str, Any]:
        """Send one request and return its result.

        Raises `ExecutorUnavailable` when the socket cannot be reached (retryable)
        and `ExecutorRejected` when the executor validated the request and said no
        (never retryable — a refusal is the boundary working).
        """
        request = {"id": uuid.uuid4().hex, "op": op, "args": args}
        payload = (json.dumps(request) + "\n").encode()

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_s)
                sock.connect(self.socket_path)
                sock.sendall(payload)

                buffer = b""
                while b"\n" not in buffer:
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise ExecutorUnavailable(
                            "executor closed the connection without responding"
                        )
                    buffer += chunk
                    if len(buffer) > MAX_RESPONSE_BYTES:
                        raise ExecutorUnavailable("executor response too large")
        except FileNotFoundError as exc:
            raise ExecutorUnavailable(
                f"{self.socket_path} does not exist — is sentinel-executor running?"
            ) from exc
        except PermissionError as exc:
            raise ExecutorUnavailable(
                f"permission denied on {self.socket_path}; the caller must be root "
                "or in the sentinel group"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise ExecutorUnavailable(f"executor socket error: {exc}") from exc

        line = buffer.split(b"\n", 1)[0]
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ExecutorUnavailable(f"executor returned malformed JSON: {exc}") from exc

        if not response.get("ok"):
            error = response.get("error", "unknown")
            detail = response.get("detail", "")
            if error in ("refused", "unknown_operation", "bad_request"):
                raise ExecutorRejected(f"{error}: {detail}")
            raise ExecutorUnavailable(f"{error}: {detail}")

        result = response.get("result")
        return result if isinstance(result, dict) else {"result": result}

    # -- convenience wrappers ---------------------------------------------
    def ping(self) -> bool:
        try:
            return bool(self.call("ping").get("pong"))
        except (ExecutorUnavailable, ExecutorRejected):
            return False

    def block_ip(
        self, ip: str, ttl: int | None, reason: str, incident_id: int | None = None
    ) -> dict[str, Any]:
        return self.call("block_ip", ip=ip, ttl=ttl, reason=reason, incident_id=incident_id)

    def unblock_ip(self, ip: str) -> dict[str, Any]:
        return self.call("unblock_ip", ip=ip)

    def allow_ip(self, ip: str) -> dict[str, Any]:
        return self.call("allow_ip", ip=ip)

    def flush_blocklist(self, reason: str) -> dict[str, Any]:
        return self.call("flush_blocklist", reason=reason)

    def list_sets(self) -> dict[str, Any]:
        return self.call("list_sets")

    def blocklist_size(self) -> int:
        """Element count across both blocklist sets, or -1 if unknown.

        Returns -1 rather than 0 on failure. Zero means "nothing is blocked",
        which would tell the watchdog everything is fine — the opposite of what
        an unreachable executor should communicate.
        """
        try:
            sets = self.list_sets()
        except (ExecutorUnavailable, ExecutorRejected):
            return -1

        total = 0
        for name in ("blocklist_v4", "blocklist_v6"):
            data = sets.get(name)
            if not isinstance(data, dict):
                continue
            total += _count_nft_elements(data)
        return total


def _count_nft_elements(data: dict[str, Any]) -> int:
    """Count elements in `nft -j list set` output.

    The JSON shape is `{"nftables": [{"metainfo": …}, {"set": {"elem": [...]}}]}`.
    Walked defensively: nft's schema has changed across versions, and a parsing
    error here must not make the watchdog think the blocklist is empty.
    """
    try:
        for entry in data.get("nftables", []):
            if isinstance(entry, dict) and "set" in entry:
                elements = entry["set"].get("elem", [])
                if isinstance(elements, list):
                    return len(elements)
    except (AttributeError, TypeError, KeyError):
        pass
    return 0


def _nft_elements(data: dict[str, Any]) -> list[str]:
    """The element VALUES in `nft -j list set` output, as plain strings.

    Counting was enough for the watchdog's cap; reconciling needs to know WHICH
    addresses are present, because "the kernel has fewer than the database" and
    "the kernel is missing these three" call for different repairs.

    Each element is either a bare string, or an object once it carries a
    timeout: `{"elem": {"val": "203.0.113.4", "timeout": 3600}}`. Both shapes are
    handled, and anything unrecognised is skipped rather than guessed at — a
    misparsed element would mean unblocking someone who is still blocked.
    """
    out: list[str] = []
    try:
        for entry in data.get("nftables", []):
            if not (isinstance(entry, dict) and "set" in entry):
                continue
            for element in entry["set"].get("elem", []) or []:
                if isinstance(element, str):
                    out.append(element)
                elif isinstance(element, dict):
                    inner = element.get("elem", element)
                    value = inner.get("val") if isinstance(inner, dict) else None
                    if isinstance(value, str):
                        out.append(value)
                    elif isinstance(value, dict) and "prefix" in value:
                        prefix = value["prefix"]
                        out.append(f"{prefix.get('addr')}/{prefix.get('len')}")
    except (AttributeError, TypeError, KeyError):
        pass
    return out
