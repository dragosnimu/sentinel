"""Hard-coded safety policy for the privileged executor.

READ THE THREAT MODEL IN README.md BEFORE CHANGING ANYTHING HERE.

Three properties make this file what it is:

1. **It is code, not configuration.** Nothing here can be widened by editing a
   YAML file or by writing to the database. Compromising the database gets an
   attacker the security history; it does not get them the ability to unblock
   themselves by removing an allowlist row, or to block the operator out.

2. **It imports nothing from the `sentinel` package.** The executor runs as
   root; the rest of Sentinel does not. If the main codebase is compromised —
   a malicious dependency, a bug in a collector — that compromise must not
   reach into the one process that can change the firewall and run commands as
   root. Stdlib only, no shared imports, no shared state.

3. **It refuses, it does not sanitise.** A request that violates policy is
   rejected and audited. Silently "fixing" a bad request hides the bug that
   produced it, and on this side of the trust boundary the bug might be an
   attacker.

Some values here duplicate `sentinel/constants.py`. That duplication is
deliberate, and a test asserts the two agree. Sharing the module would mean
importing from the untrusted side.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

# ---------------------------------------------------------------------------
# Never-block networks
# ---------------------------------------------------------------------------
# Blocking any of these is a self-inflicted outage.
#
# Only the universal ones live here — true on every host, and therefore safe to
# hard-code. Deployment-specific addresses (an uptime monitor, a CI runner, an
# office range, a high-volume telemetry source you must not cut off) go in
# `response.extra_allowlist` in the config, which is loaded at startup and
# refreshed hourly.
#
# The split matters: hard-coding a customer's address here would be wrong on
# every other deployment, and putting loopback in a config file would let a
# config compromise make it blockable.
NEVER_BLOCK_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fe80::/10",
        "fc00::/7",
        "224.0.0.0/4",
        "0.0.0.0/32",
        "255.255.255.255/32",
    )
)

# Resolved at startup and refreshed periodically. Blocking Sentinel's own
# alerting and analysis endpoints would be silent: no error, no alert, just a
# system that has quietly stopped telling anyone anything.
NEVER_BLOCK_HOSTNAMES: tuple[str, ...] = ("api.telegram.org", "api.anthropic.com")

# A /24 is already 256 addresses and enough to take out a NAT'd office.
MAX_BLOCK_PREFIX_V4 = 24
MAX_BLOCK_PREFIX_V6 = 64

# ---------------------------------------------------------------------------
# Rate caps
# ---------------------------------------------------------------------------
# A runaway detector must not be able to black-hole the internet one /32 at a
# time. Exceeding either raises an alert and refuses further blocks until an
# operator intervenes.
MAX_BLOCKS_PER_MINUTE = 60
MAX_BLOCKLIST_ELEMENTS = 20_000

MIN_BLOCK_TTL_S = 60
MAX_BLOCK_TTL_S = 30 * 86_400

# ---------------------------------------------------------------------------
# Protected paths
# ---------------------------------------------------------------------------
# No privileged operation may read, write, back up, restore or execute anything
# under these: Sentinel's own paths, and the ones that would lock the operator
# out or escalate privileges.
#
# Deployment-specific paths go in `patch.extra_protected_paths` in the config
# and are enforced by the patch validator on the untrusted side. This list is
# the floor that no configuration change can lower.
PROTECTED_PATHS: tuple[str, ...] = (
    "/opt/sentinel",
    "/etc/sentinel",
    "/root/.ssh",
    "/etc/ssh",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/boot",
    "/etc/systemd/system/sentinel-executor.service",
)

# Files whose contents must never be read into a log, a prompt or the database.
SECRET_PATHS: tuple[str, ...] = ("/etc/sentinel/secrets.env",)

# The only paths `read_privileged_file` will open. An allowlist, not a
# blocklist: a blocklist here is an information-disclosure bug waiting for
# someone to find the path it missed.
READABLE_PATHS: tuple[str, ...] = (
    "/var/log/audit/audit.log",
    "/var/log/secure",
    "/var/log/suricata/eve.json",
    "/var/log/nginx/",
    "/var/log/httpd/",
    "/proc/net/",
)

# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
# argv[0] must be one of these. `sh`, `bash`, `env`, `sudo`, `python` and
# `perl` are absent on purpose: any one of them turns an argv allowlist into no
# allowlist at all.
BINARY_ALLOWLIST: frozenset[str] = frozenset(
    {
        "dnf", "rpm", "systemctl",
        "nginx", "httpd", "apachectl",
        "docker",
        "git", "npm", "yarn", "composer", "pip", "pip3", "wp",
        "mysqldump", "mysql", "pg_dump", "psql",
        "tar", "zstd", "gzip",
        "cp", "mv", "ln", "mkdir", "install", "chown", "chmod", "sed", "test",
        # Read-only inspection: can answer a question, cannot change anything.
        # The plan schema's file_sha256 check needs this.
        "sha256sum",
        "certbot",
        "curl",
    }
)

# Rejected wherever they appear, in any argument, on any binary.
FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "mkfs", "dd if=", "dd of=", "/dev/sd", "/dev/nvme", "/dev/mapper",
    "nft", "iptables", "ip6tables", "firewall-cmd", "firewalld",
    "userdel", "usermod", "passwd", "chpasswd",
    "authorized_keys", "sshd_config",
    "--no-preserve-root",
)

# Characters that only make sense if you believe a shell is involved. There is
# no shell here, so their presence means the caller built the command wrong —
# or is trying something.
SHELL_METACHARACTERS: tuple[str, ...] = (
    "|", ";", "&", "$(", "`", ">", "<", "\n", "\r", "\x00",
)

# systemd units the executor will act on. Not "any unit": restarting sshd or
# postgresql on a whim is how a patch becomes an outage, and stopping the
# executor's own unit through the executor is an obvious foot-gun.
CONTROLLABLE_UNIT_RE = re.compile(r"^[a-zA-Z0-9@._-]{1,64}\.(service|socket|timer)$")
UNCONTROLLABLE_UNITS: frozenset[str] = frozenset(
    {
        "sshd.service",
        "sentinel-executor.service",
        "sentinel-watchdog.service",
        "sentinel-watchdog.timer",
        "firewalld.service",
        "systemd-journald.service",
        "dbus.service",
    }
)

ALLOWED_SERVICE_ACTIONS: frozenset[str] = frozenset({"start", "stop", "restart", "reload", "status"})


class PolicyRefusal(Exception):
    """The policy said no. Never retried, always audited."""


# ---------------------------------------------------------------------------
# Runtime allowlist
# ---------------------------------------------------------------------------
_runtime_allowlist: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []


def refresh_runtime_allowlist(extra_cidrs: list[str] | None = None) -> list[str]:
    """Resolve the never-block hostnames and add the host's own addresses.

    Called at startup and periodically. Resolution failures are ignored rather
    than fatal: an executor that refuses to start because DNS is momentarily
    down is worse than one running with a slightly smaller allowlist.
    """
    global _runtime_allowlist
    resolved: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    names: list[str] = []

    for hostname in NEVER_BLOCK_HOSTNAMES:
        try:
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                net = ipaddress.ip_network(f"{addr}/32" if ":" not in addr else f"{addr}/128")
                if net not in resolved:
                    resolved.append(net)
                    names.append(f"{hostname}={addr}")
        except (OSError, ValueError):
            continue

    for cidr in extra_cidrs or []:
        try:
            resolved.append(ipaddress.ip_network(cidr, strict=False))
            names.append(cidr)
        except ValueError:
            continue

    _runtime_allowlist = resolved
    return names


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def check_blockable(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate a block target. Raises PolicyRefusal with a specific reason."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        # Unparseable is refused, not permitted. Anything that reaches here and
        # is not an address is either a bug or an injection attempt.
        raise PolicyRefusal(f"{target!r} is not a valid IP address or network: {exc}") from None

    limit = MAX_BLOCK_PREFIX_V4 if network.version == 4 else MAX_BLOCK_PREFIX_V6
    if network.prefixlen < limit:
        raise PolicyRefusal(
            f"{network} is wider than /{limit}. Blocking a range this large takes out "
            f"{network.num_addresses} addresses, which on a NAT'd network means an entire "
            "organisation."
        )

    for protected in NEVER_BLOCK_NETWORKS:
        if network.version == protected.version and network.overlaps(protected):
            raise PolicyRefusal(
                f"{network} overlaps {protected}, which may never be blocked. "
                "This list is hard-coded in executor/policy.py precisely so that no "
                "configuration change, database write or AI output can remove an entry."
            )

    for protected in _runtime_allowlist:
        if network.version == protected.version and network.overlaps(protected):
            raise PolicyRefusal(
                f"{network} overlaps {protected}, resolved from the never-block "
                "hostnames or supplied as an operator allowlist entry. Blocking it "
                "would silently disable Sentinel's own alerting or analysis."
            )

    return network


def check_ttl(ttl: Any) -> int | None:
    """Validate a block TTL. None means permanent, which only an operator may set."""
    if ttl is None:
        return None
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        raise PolicyRefusal(f"ttl must be an integer number of seconds, got {type(ttl).__name__}")
    if not MIN_BLOCK_TTL_S <= ttl <= MAX_BLOCK_TTL_S:
        raise PolicyRefusal(
            f"ttl {ttl} is outside {MIN_BLOCK_TTL_S}..{MAX_BLOCK_TTL_S} seconds"
        )
    return ttl


def check_path(path: Any, *, purpose: str = "operate on") -> str:
    """Reject protected paths, relative paths and traversal."""
    if not isinstance(path, str) or not path:
        raise PolicyRefusal("path must be a non-empty string")
    if not path.startswith("/"):
        raise PolicyRefusal(f"path must be absolute, got {path!r}")
    if ".." in path.split("/"):
        raise PolicyRefusal(f"path {path!r} contains '..'; traversal is refused, not normalised")
    if "\x00" in path:
        raise PolicyRefusal("path contains a null byte")

    for protected in (*PROTECTED_PATHS, *SECRET_PATHS):
        if path == protected or path.startswith(protected.rstrip("/") + "/"):
            raise PolicyRefusal(
                f"refusing to {purpose} {path!r}: it is under {protected}, which is "
                "protected. Sentinel's own paths are managed by the installer, not by "
                "automated changes; the rest are things the operator has "
                "declared off limits."
            )
    return path


def check_readable_path(path: Any) -> str:
    """A read allowlist. Anything not explicitly listed is refused."""
    path = check_path(path, purpose="read")
    for allowed in READABLE_PATHS:
        if path == allowed or path.startswith(allowed):
            return path
    raise PolicyRefusal(
        f"{path!r} is not in the readable-path allowlist. This is an allowlist rather "
        "than a blocklist because a blocklist is an information-disclosure bug waiting "
        "for someone to find the path it missed."
    )


def check_argv(argv: Any) -> list[str]:
    """Validate a command. Raises with the specific reason it was refused."""
    if isinstance(argv, str):
        raise PolicyRefusal(
            "command must be a list of strings, not a string. There is no shell here, "
            "so a string command cannot be executed."
        )
    if not isinstance(argv, list) or not argv:
        raise PolicyRefusal("command must be a non-empty list of strings")
    if len(argv) > 64:
        raise PolicyRefusal(f"command has {len(argv)} arguments; the limit is 64")

    for i, part in enumerate(argv):
        if not isinstance(part, str):
            raise PolicyRefusal(f"argv[{i}] is {type(part).__name__}, expected str")
        if len(part) > 4096:
            raise PolicyRefusal(f"argv[{i}] is {len(part)} characters; the limit is 4096")

    program = argv[0]
    basename = program.rsplit("/", 1)[-1]
    allowed_absolute = program.startswith("/opt/sentinel/bin/")

    if not allowed_absolute and basename not in BINARY_ALLOWLIST:
        raise PolicyRefusal(
            f"{program!r} is not in the binary allowlist. Note that sh, bash, env, sudo "
            "and python are excluded deliberately: any one of them would turn this "
            "allowlist into no allowlist at all."
        )
    if program.startswith("/") and not allowed_absolute:
        raise PolicyRefusal(
            f"{program!r}: use the bare binary name, or an absolute path under "
            "/opt/sentinel/bin/"
        )

    for i, part in enumerate(argv):
        for meta in SHELL_METACHARACTERS:
            if meta in part:
                raise PolicyRefusal(
                    f"argv[{i}] contains {meta!r}. Commands run directly, not through a "
                    "shell, so its presence means the command was written for a shell "
                    "that does not exist."
                )
        lowered = part.lower()
        for forbidden in FORBIDDEN_SUBSTRINGS:
            if forbidden in lowered:
                raise PolicyRefusal(f"argv[{i}] contains {forbidden!r}, which is never permitted")

        if part.startswith("/"):
            check_path(part, purpose="run a command against")

    return list(argv)


#: Cea mai mare valoare pe care o poate lua o cheie de sesiune de la nucleu.
#:
#: `ses` e un `unsigned int` pe 32 de biti. `4294967295` e chiar valoarea
#: rezervata pentru «nicio sesiune», deci e refuzata separat mai jos: inchisa,
#: ar insemna «omoara tot ce nu are sesiune», adica fiecare daemon de pe gazda.
MAX_SESSION_KEY = 4294967294

#: Sesiunea marcata de nucleu drept «niciun login».
NO_SESSION_KEY = "4294967295"


def check_session_key(value: Any) -> str:
    """Cheia unei sesiuni de login, ca text, sau refuz.

    Valoarea ajunge in `loginctl terminate-session`, deci trebuie sa fie exact
    o insiruire de CIFRE. Nu se citeaza si nu se escapeaza — se refuza orice
    altceva: o validare care accepta si apoi curata e o validare pe care cineva
    o va ocoli, iar aici capatul e o comanda privilegiata.

    Zero e refuzat: `ses=0` e sesiunea nucleului insusi pe unele versiuni, si
    nu e nimic de inchis acolo.
    """
    text = str(value).strip()
    if not text.isdigit():
        raise PolicyRefusal("session key must be digits only")
    if text == NO_SESSION_KEY:
        raise PolicyRefusal(
            "refusing to terminate the 'no session' key: it would mean every "
            "process without a login behind it")
    number = int(text)
    if not 1 <= number <= MAX_SESSION_KEY:
        raise PolicyRefusal(f"session key out of range: {number}")
    return text


def check_unit(unit: Any, action: Any) -> tuple[str, str]:
    """Validate a systemd unit and the action requested on it."""
    if not isinstance(unit, str) or not CONTROLLABLE_UNIT_RE.match(unit):
        raise PolicyRefusal(f"{unit!r} is not a valid systemd unit name")
    if unit in UNCONTROLLABLE_UNITS:
        raise PolicyRefusal(
            f"{unit} may not be controlled through the executor. Stopping sshd would "
            "lose remote access; stopping the executor or the watchdog through the "
            "executor would remove the mechanisms that undo a mistake."
        )
    if action not in ALLOWED_SERVICE_ACTIONS:
        raise PolicyRefusal(f"action must be one of {sorted(ALLOWED_SERVICE_ACTIONS)}")
    return unit, action


def is_never_block(address: str) -> bool:
    """Convenience predicate. Unparseable input is treated as never-block."""
    try:
        check_blockable(address)
    except PolicyRefusal:
        return True
    return False
