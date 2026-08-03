#!/usr/bin/env python3
"""The anti-lockout deadman.

Runs as root, every 60 seconds, from `sentinel-watchdog.timer`. It is the single
most important component in the deployment, and the one most likely to be
running when everything else has failed.

It flushes the entire blocklist when any of these hold:

  1. `/etc/sentinel/PANIC` exists          — the operator's manual escape hatch
  2. the web health endpoint has been down > 5 min — Sentinel is broken
  3. `sentinel-detect` is failed or restart-looping — the detector is untrustworthy
  4. the blocklist exceeds the hard cap    — something has run away

The reasoning behind (2) and (3): a detector that cannot run must not leave
stale drops in the kernel. If Sentinel is broken, the blocks it placed are no
longer being reasoned about — nobody is deciding they should still be there,
and nobody is going to remove them when they should expire. Failing open is the
correct behaviour for a deny-lister on a remote server.

DESIGN CONSTRAINTS — these are not stylistic:

* **No database dependency.** PostgreSQL being down is one of the conditions
  this is supposed to survive.
* **Imports only stdlib plus `executor_client` and `errors`.** Anything heavier
  is something else that can fail.
* **Never raises.** An exception here means no flush, which is exactly the
  outcome it exists to prevent. Every failure path is caught and logged.
* **Fails toward flushing.** When state cannot be determined, the safe answer is
  to remove blocks, not to keep them.

Runnable as a bare script: the systemd unit invokes it directly with
`PYTHONPATH=/opt/sentinel/lib`, so it does not need the CLI dispatcher, the
config loader, or anything else to be working.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 - reads systemd state; argv-only, never a shell
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# The package is on PYTHONPATH when systemd runs this, but when someone runs it
# by hand from a checkout it may not be. Make the one import that matters work
# either way.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.respond.executor_client import ExecutorClient  # noqa: E402

PANIC_FILE = Path(os.environ.get("SENTINEL_PANIC_FILE", "/etc/sentinel/PANIC"))
STATE_FILE = Path(os.environ.get("SENTINEL_WATCHDOG_STATE", "/var/lib/sentinel/watchdog.json"))
EXECUTOR_SOCKET = os.environ.get("SENTINEL_EXECUTOR_SOCKET", "/run/sentinel/executor.sock")
HEALTH_URL = os.environ.get("SENTINEL_HEALTH_URL", "http://127.0.0.1:8787/healthz")

WEB_DOWN_FLUSH_S = 300          # web unhealthy this long → flush
DETECT_RESTART_LIMIT = 5        # restarts within the window → flush
DETECT_RESTART_WINDOW_S = 300
MAX_BLOCKLIST_ELEMENTS = 20_000
HEALTH_TIMEOUT_S = 5


def log(level: str, message: str, **fields: object) -> None:
    """Structured line to stderr, which systemd routes to the journal."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "service": "sentinel-watchdog",
        "msg": message,
        **fields,
    }
    print(json.dumps(record, default=str), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# State, persisted between runs
# ---------------------------------------------------------------------------
def load_state() -> dict[str, object]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # A missing or corrupt state file is not an error: it means this is the
        # first run, or the file was lost. Start clean rather than refusing.
        return {}


def save_state(state: dict[str, object]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Written via a temporary file and renamed: a power loss mid-write must
        # not leave a truncated file that the next run cannot parse.
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, default=str), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError as exc:
        log("warning", "could not persist watchdog state", detail=str(exc))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
def web_healthy() -> bool | None:
    """True healthy, False unhealthy, None if it could not be determined.

    None matters: "I could not tell" must not be counted as a failure, or a
    transient DNS or socket hiccup would start the flush countdown.
    """
    try:
        request = urllib.request.Request(HEALTH_URL, method="GET")  # noqa: S310 - fixed loopback URL
        with urllib.request.urlopen(request, timeout=HEALTH_TIMEOUT_S) as response:  # noqa: S310
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        # It answered, so the process is alive. 503 means degraded — usually the
        # database — which is a real unhealthy state.
        return 200 <= exc.code < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
    except Exception:  # noqa: BLE001 - must never propagate out of the watchdog
        return None


def _systemctl(*args: str) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            ["/usr/bin/systemctl", *args],
            capture_output=True,
            timeout=10,
            shell=False,
            check=False,
        )
        return result.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def detect_unhealthy() -> bool:
    """True when sentinel-detect cannot be trusted to be making decisions.

    Two cases: the unit has failed outright, or systemd's restart counter shows
    it flapping. A process that starts, crashes and starts again every few
    seconds may well be placing blocks from half-initialised state.
    """
    state = _systemctl("is-active", "sentinel-detect.service")
    if state == "failed":
        return True

    # Not installed yet (early phases) is not a fault.
    if state in ("", "inactive"):
        load_state_value = _systemctl("is-enabled", "sentinel-detect.service")
        return load_state_value == "enabled"   # enabled but not running → wrong

    n_restarts = _systemctl("show", "sentinel-detect.service", "-p", "NRestarts", "--value")
    try:
        return int(n_restarts) >= DETECT_RESTART_LIMIT
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------
def decide(
    *,
    panic: bool,
    web: bool | None,
    web_down_since: float | None,
    detect_bad: bool,
    blocklist_size: int,
    now: float,
) -> tuple[bool, str | None]:
    """Pure decision function: should the blocklist be flushed, and why.

    Separated from the I/O so it can be tested exhaustively without a server,
    an executor or a systemd. Every branch here is covered by a unit test.
    """
    if panic:
        return True, "PANIC file present"

    if detect_bad:
        return True, "sentinel-detect is failed or restart-looping"

    if blocklist_size > MAX_BLOCKLIST_ELEMENTS:
        return True, f"blocklist exceeded the hard cap ({blocklist_size})"

    if web is False and web_down_since is not None:
        down_for = now - web_down_since
        if down_for >= WEB_DOWN_FLUSH_S:
            return True, f"web health down for {int(down_for)}s"

    return False, None


# ---------------------------------------------------------------------------
def run_once() -> int:
    state = load_state()
    now = time.time()

    panic = PANIC_FILE.exists()
    web = web_healthy()

    # Track when the web service first went down, so the threshold is
    # "unhealthy continuously for 5 minutes" rather than "unhealthy on five
    # separate occasions".
    web_down_since = state.get("web_down_since")
    if web is False:
        if not isinstance(web_down_since, int | float):
            web_down_since = now
            log("warning", "web health check failing", url=HEALTH_URL)
    elif web is True:
        if web_down_since is not None:
            log("info", "web health recovered")
        web_down_since = None
    # web is None: leave the timer as it was. An indeterminate probe is not
    # evidence of failure.

    detect_bad = detect_unhealthy()
    client = ExecutorClient(EXECUTOR_SOCKET, timeout_s=10)
    blocklist_size = client.blocklist_size()

    should_flush, reason = decide(
        panic=panic,
        web=web,
        web_down_since=web_down_since if isinstance(web_down_since, int | float) else None,
        detect_bad=detect_bad,
        blocklist_size=blocklist_size,
        now=now,
    )

    if should_flush:
        if blocklist_size == 0:
            # Nothing to do, but keep saying why so the journal shows the
            # condition is still active rather than going silent.
            log("info", "flush condition active, blocklist already empty", reason=reason)
        elif blocklist_size < 0:
            log(
                "error",
                "flush condition active but the executor is unreachable",
                reason=reason,
                hint="check sentinel-executor; blocks may be stuck in the kernel",
            )
        else:
            try:
                result = client.flush_blocklist(f"watchdog: {reason}")
                log(
                    "warning",
                    "BLOCKLIST FLUSHED",
                    reason=reason,
                    previous_size=blocklist_size,
                    result=result,
                )
            except Exception as exc:  # noqa: BLE001 - never propagate
                log("error", "flush failed", reason=reason, detail=str(exc))

    # A record of every decision, not just the flushes. "The watchdog ran and
    # decided not to flush" is the thing you want to see in the journal when
    # asking why a block survived.
    state.update(
        {
            "last_run": now,
            "web_down_since": web_down_since,
            "last_web": web,
            "last_detect_bad": detect_bad,
            "last_blocklist_size": blocklist_size,
            "last_flush_reason": reason,
            "last_flush_at": now if should_flush else state.get("last_flush_at"),
        }
    )
    save_state(state)

    if not should_flush:
        log(
            "debug",
            "ok",
            blocklist=blocklist_size,
            web="up" if web else ("down" if web is False else "unknown"),
            panic=panic,
        )
    return 0


def main() -> int:
    if os.geteuid() != 0:
        # nftables changes need root. Refusing loudly beats appearing to run and
        # silently never being able to flush anything.
        log("error", "the watchdog must run as root")
        return 1
    try:
        return run_once()
    except Exception as exc:  # noqa: BLE001 - the last line of defence
        # An unhandled exception means no flush happened, which is precisely the
        # failure this component exists to prevent. Log it loudly and exit
        # non-zero so systemd records the failure.
        import traceback

        log(
            "error",
            "watchdog raised — no flush decision was made",
            detail=f"{type(exc).__name__}: {exc}",
            trace=traceback.format_exc()[:2000],
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
