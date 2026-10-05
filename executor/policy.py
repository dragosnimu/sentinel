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

import hashlib
import hmac
import ipaddress
import json
import os
import posixpath
import re
import secrets
import socket
import stat as stat_module
import threading
import time
from pathlib import Path
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
    # `sentinel` owns this directory (0750 sentinel:sentinel — see
    # sentinel_executor.py's AUDIT_DIR comment for why the audit chain moved
    # OUT of it). Missing here, present in constants.PROTECTED_PATHS, this let
    # a package-name argument with no leading '/' — "evil.rpm" sitting in
    # /var/lib/sentinel, `cwd` pointed at it — dodge every check_path call in
    # this file, since none of them ever saw an absolute path to refuse.
    # `check_argv`'s own PKG_NAME_RE additionally refuses a bare *.rpm/*.deb
    # positional argument outright (see `_check_dnf_argv`/`_check_apt_argv`),
    # but a plan step's `cwd` or a `tar`/`cp` path argument can still name
    # this directory directly, and now does the same refusal everything else
    # protected here gets. Kept out of the list on purpose:
    # /var/backups/sentinel (BACKUP_ROOT) — op_backup_restore used to pass a
    # caller-given artifact path under it through check_path, and protecting it
    # here would have refused every restore. That operation now refuses
    # outright, so nothing needs the exemption any more; it is left as it was
    # because changing it is a separate decision (constants.PROTECTED_PATHS
    # already lists it).
    "/var/lib/sentinel",
    # The executor's OWN state: `approval.key` (the operator's HMAC key, which
    # is Gate 1) and `audit.jsonl` (the hash chain). 0700 root:root, so
    # `sentinel` cannot touch it directly - but it is in the executor's
    # ReadWritePaths, which makes it a place a root-run `tar`/`cp`/`install`
    # lands without a single permission error. Missing from this list, a
    # `backup_restore` with `tar -xzf {artifact} -C /var/lib/sentinel-executor`
    # replaced the key with the caller's (reproduced 5 October 2026, in a
    # container). The entry above does not cover it: `check_path` matches
    # `protected + "/"` as a prefix, and "/var/lib/sentinel-executor" does not
    # start with "/var/lib/sentinel/".
    #
    # This closes the argument that NAMES the directory. It does not close an
    # archive that CARRIES it as a member (`-C /` plus `var/lib/sentinel-executor/
    # approval.key` inside the tar), which no argv check can see - that is why
    # `op_backup_restore` refuses outright instead of relying on this list.
    "/var/lib/sentinel-executor",
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
#
# Narrowed 8 September 2026, after the round-1 verifier ran the previous list
# (32 binaries, a denylist layered on the allowlist for the riskiest of them)
# against real binaries and got root through `patch_step_exec` six different
# ways: `git --exec-path=... evilcmd`, `sed -n '2e ...'`, `rpm -i evil.rpm`,
# `dnf install evil.rpm`, `npm install <url>`, `pip install --find-links=...`,
# and `docker` with a handful of host-equivalent flags. Every one of those was
# a binary whose OWN scripting/plugin/hook surface cannot be enumerated —
# git's `-c` machinery, sed's `e` command, npm/pip's lifecycle scripts,
# docker's whole point being to hand a container host access. The fix is not a
# better denylist for those binaries; it is not having them here at all.
#
# What is left is binaries this file can give a POSITIVE grammar to — allowed
# subcommands, allowed flags, positional arguments validated by shape — in
# `_BINARY_GRAMMAR` below, one function per binary, no exceptions. Dropped
# entirely, with no narrower grammar written for them because none would be
# honest: `docker`, `git`, `npm`, `yarn`, `composer`, `pip`, `pip3`, `wp`,
# `sed`, `curl` (an exfiltration path with no patch use once file:// was the
# only thing narrowed), `httpd`, `apachectl` (nginx is the deployed web
# server; these had no demonstrated caller), `mysqldump`, `mysql`, `pg_dump`,
# `psql` (interactive SQL clients carry their own shell-escape metacommands —
# psql's `\!` — and nothing in this codebase today builds a validated argv
# step that uses them; adding them back is a deliberate future change with
# its own grammar, not a default), `zstd`, `gzip` (compression here is always
# `tar --zstd`/`--use-compress-program`, never a bare invocation), `ln`,
# `certbot` (no plan template or fixture in the repository uses either).
# `rm` is deliberately NOT restored despite being on the round-1 verifier's
# suggested list: tests/security/test_patch_safety.py::
# test_rm_is_not_in_the_patch_binary_allowlist encodes an existing, reasoned
# decision — deletion goes through the one narrow, path-scoped
# `op_backup_prune` operation instead of general argv — and this change does
# not reopen a door another round deliberately closed. See the handback notes
# for this round for the full list of what was requested but not added.
BINARY_ALLOWLIST: frozenset[str] = frozenset(
    {
        "dnf", "apt-get", "apt",
        "rpm", "dpkg-query", "dpkg",
        "systemctl",
        "nginx",
        "tar",
        "cp", "mv", "mkdir", "install", "chown", "chmod",
        # Read-only inspection: can answer a question, cannot change anything.
        # `test -e` and `sha256sum` are built directly by
        # sentinel/patch/checks.py for the file_exists/file_absent/
        # file_sha256/systemd check kinds — not optional even though neither
        # is on the round-1 verifier's suggested list, because removing them
        # breaks every preflight and health check that uses those kinds.
        "test", "sha256sum",
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


def check_allowable(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate an allowlist target. `op_allow_ip` had no width cap at all —
    `0.0.0.0/0` parsed and was handed straight to `nft add element`, which
    would have allowlisted the entire internet and made every future block a
    no-op. The cap is the same one a block gets: an allowlist entry does not
    need to be wider than that to cover a real office, monitor or partner
    range, and wider than that is not an allowlist, it is switching detection
    off.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise PolicyRefusal(f"{target!r} is not a valid IP address or network: {exc}") from None

    limit = MAX_BLOCK_PREFIX_V4 if network.version == 4 else MAX_BLOCK_PREFIX_V6
    if network.prefixlen < limit:
        raise PolicyRefusal(
            f"{network} is wider than /{limit}. Allowlisting a range this wide does "
            f"not protect {network.num_addresses} addresses, it turns off blocking "
            "for all of them."
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
    """Reject protected paths, relative paths and traversal.

    `/etc//shadow` and `/etc/./sentinel/PANIC` used to pass this function
    untouched: the protected-path comparison below is a plain string prefix
    check, and neither of those strings is a prefix match for
    `/etc/shadow` or `/etc/sentinel` even though the kernel resolves them to
    exactly those paths. Refusing whenever `posixpath.normpath` would change the
    string closes the whole family at once, and it fits the file's own rule —
    refuse, don't sanitise: a path that needs cleaning to reveal what it
    actually points at is exactly the shape a bypass attempt takes.
    """
    if not isinstance(path, str) or not path:
        raise PolicyRefusal("path must be a non-empty string")
    if not path.startswith("/"):
        raise PolicyRefusal(f"path must be absolute, got {path!r}")
    if ".." in path.split("/"):
        raise PolicyRefusal(f"path {path!r} contains '..'; traversal is refused, not normalised")
    if "\x00" in path:
        raise PolicyRefusal("path contains a null byte")

    normalised = posixpath.normpath(path)
    if normalised != path:
        raise PolicyRefusal(
            f"path {path!r} is not in normalised form (the kernel would read it as "
            f"{normalised!r}); refused rather than cleaned up, for the same reason "
            "traversal is refused rather than stripped"
        )

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


# ---------------------------------------------------------------------------
# Per-binary grammar
# ---------------------------------------------------------------------------
# Being on BINARY_ALLOWLIST answers "which program". It does not answer "which
# invocation of it" — round 1 demonstrated that argv[0]-allowlisting alone let
# `patch_step_exec` reach root through binaries that WERE on the list:
#
#   docker run --privileged -v /:/host alpine chroot /host   -> root on the host
#   systemctl link /var/lib/sentinel/evil.service (+ start)  -> arbitrary unit, then run it
#   systemctl stop sshd.service / poweroff                   -> outage via a path check_unit never sees
#   tar --to-command=... / --checkpoint-action=exec=...      -> runs an external command mid-archive
#   sed -e 'e id' / s///e                                    -> GNU sed's own command-execution feature
#   rpm --eval '%(id)'                                       -> macro immediate-shell-expansion
#   git --exec-path=/var/lib/sentinel evilcmd                -> runs /var/lib/sentinel/git-evilcmd as root
#   npm install <url>                                        -> arbitrary lifecycle script execution
#   pip install evil --find-links=/var/lib/sentinel           -> runs a local build backend as root
#   dnf install /var/lib/sentinel/evil.rpm                    -> %post scriptlet as root
#
# The round-1 fix was a denylist layered on the allowlist: block the known-bad
# flag, keep everything else. That is provably weaker than a positive grammar
# ("only these subcommands, only these flags, positional arguments validated
# by shape") for any binary whose own scripting surface cannot be fully
# enumerated — git's `-c` machinery, sed's `e` command, npm/pip's lifecycle
# hooks, docker being a remote-control interface to the host by design. Round
# 2 removed every one of those from BINARY_ALLOWLIST rather than trying to
# write a grammar honest enough to keep them (see the comment there for the
# full list of what was dropped and why). What remains below is a POSITIVE
# grammar for every binary still on the allowlist — no denylist function left
# in this file. `_BINARY_GRAMMAR` is total over `BINARY_ALLOWLIST`: every
# allowlisted binary has an entry, so being on the allowlist always means
# "and its shape was checked", never "and nothing further was".
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]+(:[^/\s]+)?$")
_REPO_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
#: 3-digit octal, or 4-digit with a leading zero — never a leading 1/2/4/6/7,
#: which is the setuid/setgid/sticky digit. `^[0-7]{3,4}$` (pre round-3)
#: accepted `4755`, `2755`, `6755`, `7755` and `1755` exactly as readily as
#: `0755`: the character class `[0-7]` cannot tell a mode bit from a
#: permission bit, so `install -m 4755` and `chmod 6755` both passed this
#: file's grammar straight into root's own `install(1)`/`chmod(1)`. Ordinary
#: modes never need the fourth digit non-zero — a legitimate patch step
#: writes `755`, `644`, `0755`, never `4755` — so refusing it outright costs
#: nothing real.
_MODE_RE = re.compile(r"^(?:[0-7]{3}|0[0-7]{3})$")
#: A name, OR a bare numeric uid/gid (`chown 1000:1000 x` is ordinary,
#: valid coreutils syntax) — either shape, on either side of the optional
#: `:`. Accepting the numeric shape does not add capability on its own:
#: `_OWNER_RE` never restricted WHICH name was acceptable, so `chown root
#: file` was already grammar-legal before this round exactly as `chown 0
#: file` is now; what changes is that `_refuse_forbidden_owner`'s numeric
#: comparison below has a shape that can actually reach it, rather than
#: guarding an input `_OWNER_RE` made unreachable by requiring a leading
#: letter.
_OWNER_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+)(?::(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+))?$"
)

#: The unprivileged account the executor exists to contain. Handing it
#: ownership of a file is not an ordinary chown here: `sentinel` can already
#: write through its own filesystem permissions, so owning a file it could
#: not touch before means it can now replace that file's *contents*, and if
#: that file sits on PATH, root or any other user who later runs it executes
#: whatever `sentinel` — or whoever compromised it — put there. `chown
#: sentinel /usr/local/bin/x` and `chown -R sentinel:sentinel /usr/local`
#: both passed this file's grammar before this round for exactly that reason:
#: the owner-shape regex checked that the value LOOKED like a user[:group],
#: never which user.
_SERVICE_ACCOUNT = "sentinel"


def _service_account_uid_gid() -> tuple[str | None, str | None]:
    """Resolve `sentinel`'s numeric uid/gid right now, or (None, None).

    Read fresh on every call, the same reasoning as `_read_approval_key`
    below: a value cached at import time would still say "unknown" on a host
    where the installer created the account after the executor started.
    `pwd`/`grp` do not exist on the platform this file's own test suite runs
    on (Windows); that is a reason the NUMERIC half of the check cannot run
    there, not a reason to skip the check — `_check_chown_argv` still refuses
    by NAME regardless of whether either lookup below succeeds, which is the
    comparison every attack in the round-3 brief actually used.
    """
    uid = gid = None
    try:
        import pwd

        uid = str(pwd.getpwnam(_SERVICE_ACCOUNT).pw_uid)
    except (ImportError, KeyError):
        pass
    try:
        import grp

        gid = str(grp.getgrnam(_SERVICE_ACCOUNT).gr_gid)
    except (ImportError, KeyError):
        pass
    return uid, gid


def _refuse_forbidden_owner(binary: str, spec: str) -> None:
    """Refuse an owner/group spec that names `sentinel` by name or by its
    resolved numeric id.

    Shared by `chown`'s combined `user[:group]` and `install -o`/`install
    -g`'s separate values — install assigns ownership exactly as chown does,
    and checking one call site while leaving the other unchecked would be
    the same hole reopened through the sibling binary rather than closed.
    """
    uid, gid = _service_account_uid_gid()
    forbidden = {_SERVICE_ACCOUNT}
    if uid:
        forbidden.add(uid)
    if gid:
        forbidden.add(gid)
    if any(part in forbidden for part in spec.split(":")):
        raise PolicyRefusal(
            f"{binary} target {spec!r} names the executor's own unprivileged account "
            f"({_SERVICE_ACCOUNT!r}) as owner or group; giving it ownership of anything "
            "is a privilege-escalation primitive, not an ordinary ownership change"
        )


#: Directories a PATH lookup or the base system walks. Not the same list as
#: `PROTECTED_PATHS` above, and deliberately NOT merged into it: PROTECTED_PATHS
#: is enforced by `check_path`/`check_argv`'s own per-token loop against EVERY
#: absolute-path argument on EVERY binary, including reads (a `tar` backup
#: source, `disk_free`'s path) and ordinary deep writes a real patch performs
#: constantly — `install -m 644 x /etc/nginx/conf.d/x.conf` writes several
#: levels under `/etc`, and that must keep working. This list exists for one
#: narrower question — is a chmod/chown/cp/install/mv WRITE TARGET one of
#: these directories itself, or (only when the operation recurses) an
#: ancestor of one — and is checked only by the five write-binary grammar
#: functions below, never by the generic per-token path check.
_PATH_DIRECTORIES: tuple[str, ...] = (
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin", "/usr/local", "/usr",
    "/etc", "/",
)


def _touches_a_path_directory(path: str, *, recursive: bool) -> bool:
    """True if `path` names one of `_PATH_DIRECTORIES` outright — no
    legitimate patch step ever targets `/usr/bin` or `/etc` AS THE ARGUMENT,
    only paths several levels under them — or, when `recursive` is true,
    is a filesystem ANCESTOR of one of them, because a recursive operation
    rooted above a PATH directory reaches every file inside it too, and
    there is no single equality match at the root to catch that on its own.
    """
    normalised = path.rstrip("/") or "/"
    prefix = normalised + "/" if normalised != "/" else "/"
    for directory in _PATH_DIRECTORIES:
        if normalised == directory:
            return True
        if recursive and directory.startswith(prefix):
            return True
    return False


def _refuse_path_directory_targets(binary: str, argv: list[str], *, recursive: bool) -> None:
    """Refuse any absolute-path argument that is, or (recursively) reaches
    into, a system PATH directory. Mode/owner VALUES never start with '/',
    so scanning every token of argv[1:] rather than picking out positionals
    is exact, not an approximation.
    """
    for part in argv[1:]:
        if part.startswith("/") and _touches_a_path_directory(part, recursive=recursive):
            reach = "or, recursively, an ancestor of one" if recursive else "itself"
            raise PolicyRefusal(
                f"{binary} argument {part!r} is a system PATH directory {reach}; "
                "changing its ownership, permissions or contents reaches everything "
                "the rest of the system finds by searching PATH"
            )


_DNF_SUBCOMMANDS = frozenset(
    {"upgrade", "update", "install", "downgrade", "reinstall", "remove",
     "clean", "check-update", "makecache"}
)
_APT_SUBCOMMANDS = frozenset(
    {"install", "upgrade", "dist-upgrade", "update", "remove", "autoremove"}
)
#: The one `-o` value round 1's task allowed — a config-file confirmation
#: default, not an arbitrary override. Any other `-o` value is refused.
_APT_ALLOWED_DPKG_OPTION = "Dpkg::Options::=--force-confold"
#: A Debian version string, and nothing else.
#:
#: Deliberately NOT a reuse of the `[^/\s]+` that `_PKG_NAME_RE` gives the
#: `:arch` qualifier. That class is "anything without a slash or whitespace",
#: which would accept `pkg=--allow-unauthenticated`, `pkg==1.0` or any other
#: byte string apt might reinterpret; a version is a closed alphabet —
#: digits, letters, dot, plus, tilde, colon (epoch) and hyphen (revision) —
#: so it gets its own, and everything outside it is refused rather than
#: quoted, escaped or trimmed.
_DEB_VERSION_RE = re.compile(r"^[A-Za-z0-9.+~:-]+$")

_TAR_ALLOWED_LONG: frozenset[str] = frozenset(
    {"--zstd", "--one-top-level", "--no-same-owner", "--same-owner", "--directory"}
)
_TAR_ALLOWED_SHORT_CHARS = frozenset("cxtfzjJCp")


def _pkg_name_or_refuse(binary: str, pkg: str) -> None:
    """A package specifier, never a filesystem path.

    `evil.rpm` / `evil.deb` with no leading '/' still matches the character
    class `_PKG_NAME_RE` allows — dots and letters are exactly what a version
    string is made of — so a bare local filename would sail through the regex
    alone if `cwd` pointed at a directory `sentinel` can write to (see the
    PROTECTED_PATHS comment on /var/lib/sentinel for the other half of this).
    Refusing the suffix outright closes it regardless of `cwd`.
    """
    if pkg.lower().endswith((".rpm", ".deb")) or "/" in pkg:
        raise PolicyRefusal(
            f"{binary} package {pkg!r} names a local file, not a package spec; "
            "installing an on-disk file runs its scriptlets as root and is never "
            "permitted"
        )
    if not _PKG_NAME_RE.match(pkg):
        raise PolicyRefusal(f"{binary} package {pkg!r} is not a valid package name")


def _apt_pkg_spec_or_refuse(pkg: str) -> None:
    """An apt package specifier — `name[:arch][=version]` — never a path.

    The `=version` half is what makes a Debian plan reversible at all. `apt`
    has no `downgrade` subcommand: the only way back to the version that was
    installed before the patch is `install pkg=version`. Refusing the pin (as
    this file did until round 3) left every Debian plan with either
    `reversible: false` or a rollback that reinstalls the version the patch
    had just replaced — a rollback that provably restores nothing, which is
    worse than an honest refusal because it reads as safety.

    The local-file refusal is applied to the WHOLE spec, before it is split:
    `foo=1.0.deb` and `./foo=1.0` name a file on disk exactly as much as
    `evil.deb` does, and installing an on-disk file runs its maintainer
    scripts as root. Splitting first and checking the halves separately would
    have missed both.
    """
    if pkg.lower().endswith((".rpm", ".deb")) or "/" in pkg:
        raise PolicyRefusal(
            f"apt/apt-get package {pkg!r} names a local file, not a package spec; "
            "installing an on-disk file runs its maintainer scripts as root and is "
            "never permitted"
        )
    name, pinned, version = pkg.partition("=")
    if pinned and not _DEB_VERSION_RE.match(version):
        raise PolicyRefusal(
            f"apt/apt-get package {pkg!r} carries a version pin {version!r} that is "
            "not a Debian version string (letters, digits, '.', '+', '~', ':', '-'); "
            "refused rather than quoted or trimmed"
        )
    if not _PKG_NAME_RE.match(name):
        raise PolicyRefusal(f"apt/apt-get package {pkg!r} is not a valid package name")


def _refuse_unpinned_downgrade(subcommand: str, packages: list[str]) -> None:
    """`--allow-downgrades` is permitted for ONE purpose: returning a package
    to the exact version the plan's preflight proved was installed before it
    ran. That purpose always names a version.

    Without `=version` on every package the flag tells apt "any older
    candidate will do", and the older candidate is by definition the one the
    patch was applied to remove — a vulnerable version, reinstalled by the one
    process on this host that runs as root. That is the attack this executor
    exists to prevent, so the unpinned form is refused rather than merely
    discouraged.
    """
    if subcommand != "install":
        raise PolicyRefusal(
            f"apt/apt-get --allow-downgrades is only permitted with 'install', not "
            f"{subcommand!r}: on any other subcommand it authorises a downgrade that "
            "nothing in the argv names"
        )
    if not packages:
        raise PolicyRefusal(
            "apt/apt-get --allow-downgrades names no package, so it would authorise "
            "downgrading whatever apt happens to choose"
        )
    unpinned = [p for p in packages if "=" not in p]
    if unpinned:
        raise PolicyRefusal(
            "apt/apt-get --allow-downgrades requires an explicit '=version' pin on "
            f"every package; {unpinned!r} carries none. An unpinned downgrade lets "
            "apt pick any older version, including the vulnerable one the patch was "
            "applied to remove"
        )


def _check_dnf_argv(argv: list[str]) -> None:
    subcommand: str | None = None
    packages: list[str] = []
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-y", "--assumeyes"):
            i += 1
            continue
        if part == "--setopt=install_weak_deps=False":
            i += 1
            continue
        if part.startswith("--enablerepo=") or part.startswith("--disablerepo="):
            repo = part.split("=", 1)[1]
            if not _REPO_ID_RE.match(repo):
                raise PolicyRefusal(f"dnf repo id {repo!r} is not a plain name")
            i += 1
            continue
        if part.startswith("-"):
            raise PolicyRefusal(
                f"dnf flag {part!r} is not permitted; only -y, "
                "--setopt=install_weak_deps=False and --enablerepo=/--disablerepo=<name> "
                "are — in particular -c (alternate config), --installroot and "
                "'dnf shell' are never permitted"
            )
        if subcommand is None:
            if part not in _DNF_SUBCOMMANDS:
                raise PolicyRefusal(f"dnf subcommand {part!r} is not in {sorted(_DNF_SUBCOMMANDS)}")
            subcommand = part
        else:
            packages.append(part)
        i += 1
    if subcommand is None:
        raise PolicyRefusal("dnf requires a subcommand")
    for pkg in packages:
        _pkg_name_or_refuse("dnf", pkg)


def _check_apt_argv(argv: list[str]) -> None:
    """`--only-upgrade` is deliberately absent, and stays absent.

    Under the version-pinned design the planner now teaches (`apt-get -y
    install pkg=<fixed>` forward, `apt-get -y install --allow-downgrades
    pkg=<installed>` back) it buys nothing: the pin already says exactly which
    version may be installed, which is strictly more information than "only if
    it is already there". Every flag on an allowlist a root process reads is a
    permanent cost, so one that adds no capability is not added.
    """
    subcommand: str | None = None
    packages: list[str] = []
    allow_downgrades = False
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-y", "--yes", "--assume-yes"):
            i += 1
            continue
        if part == "-o":
            if i + 1 >= len(argv) or argv[i + 1] != _APT_ALLOWED_DPKG_OPTION:
                raise PolicyRefusal(
                    f"apt/apt-get -o may only be followed by "
                    f"{_APT_ALLOWED_DPKG_OPTION!r}"
                )
            i += 2
            continue
        if part == "--allow-downgrades":
            allow_downgrades = True
            i += 1
            continue
        if part.startswith("-"):
            raise PolicyRefusal(
                f"apt/apt-get flag {part!r} is not permitted; only -y, "
                f"'-o {_APT_ALLOWED_DPKG_OPTION}' and --allow-downgrades (with "
                "'install' and a '=version' pin on every package) are"
            )
        if subcommand is None:
            if part not in _APT_SUBCOMMANDS:
                raise PolicyRefusal(f"apt/apt-get subcommand {part!r} is not in {sorted(_APT_SUBCOMMANDS)}")
            subcommand = part
        else:
            packages.append(part)
        i += 1
    if subcommand is None:
        raise PolicyRefusal("apt/apt-get requires a subcommand")
    for pkg in packages:
        _apt_pkg_spec_or_refuse(pkg)
    if allow_downgrades:
        _refuse_unpinned_downgrade(subcommand, packages)


def _check_rpm_argv(argv: list[str]) -> None:
    """Query and verify only. Install/upgrade/erase go through `dnf`, which has
    a scriptlet-review workflow this direct path does not."""
    if len(argv) < 2:
        raise PolicyRefusal("rpm requires -q, -qa or -V")
    mode = argv[1]
    if mode not in ("-q", "-qa", "-V"):
        raise PolicyRefusal(
            f"rpm may only be run as -q, -qa or -V; {mode!r} is not permitted — "
            "-i/-U/-e install or remove a package outside dnf's scriptlet review, "
            "and --eval/--pipe/--dbpath/--root/--import are never permitted"
        )
    i = 2
    while i < len(argv):
        part = argv[i]
        if part in ("--qf", "--queryformat"):
            if i + 1 >= len(argv):
                raise PolicyRefusal(f"rpm {part} requires a format argument")
            fmt = argv[i + 1]
            lowered = fmt.lower()
            if "%(" in fmt or "lua:" in lowered:
                raise PolicyRefusal(
                    f"rpm format {fmt!r} contains a macro-expansion primitive "
                    "(%(...) or %{lua:...}), which evaluates as code"
                )
            i += 2
            continue
        if part.startswith("-"):
            raise PolicyRefusal(f"rpm flag {part!r} is not permitted in query/verify mode")
        if not _PKG_NAME_RE.match(part):
            raise PolicyRefusal(f"rpm argument {part!r} is not a valid package name")
        i += 1


def _check_dpkg_query_argv(argv: list[str]) -> None:
    saw_action = False
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-f", "--showformat"):
            if i + 1 >= len(argv):
                raise PolicyRefusal(f"dpkg-query {part} requires a format argument")
            i += 2
            continue
        if part.startswith("-f=") or part.startswith("--showformat="):
            i += 1
            continue
        if part in ("-W", "-l", "-s"):
            saw_action = True
            i += 1
            continue
        if part.startswith("-"):
            raise PolicyRefusal(f"dpkg-query flag {part!r} is not in -W, -l, -s, -f/--showformat")
        if not _PKG_NAME_RE.match(part):
            raise PolicyRefusal(f"dpkg-query argument {part!r} is not a valid package name")
        i += 1
    if not saw_action:
        raise PolicyRefusal("dpkg-query requires one of -W, -l, -s")


_DPKG_COMPARE_OPS = frozenset({"lt", "le", "eq", "ne", "ge", "gt", "<<", "<=", "=", ">=", ">>"})


def _check_dpkg_argv(argv: list[str]) -> None:
    """`--compare-versions` only — a read-only comparison, never an install."""
    if len(argv) != 5 or argv[1] != "--compare-versions" or argv[3] not in _DPKG_COMPARE_OPS:
        raise PolicyRefusal(
            "dpkg may only be run as 'dpkg --compare-versions VERSION OP VERSION' "
            f"with OP in {sorted(_DPKG_COMPARE_OPS)}; -i/-r/--configure and every "
            "other subcommand install, remove or run maintainer scripts as root "
            "and are never permitted"
        )


def _check_systemctl_argv(argv: list[str]) -> None:
    """`op_service_action` already routes every request through `check_unit`.
    `patch_step_exec` does not — it hands `systemctl` a raw argv — so a plan
    step could reach `systemctl link <attacker unit>` (registers a unit this
    policy never validated) or `systemctl stop sshd.service` / `poweroff`
    (actions `check_unit` would refuse). This closes both: only the same
    actions `check_unit` allows, plus `is-active` for the patch schema's own
    `systemd` check kind, and only in the exact `systemctl ACTION UNIT` shape.
    """
    allowed_actions = ALLOWED_SERVICE_ACTIONS | {"is-active"}
    if len(argv) != 3 or argv[1] not in allowed_actions:
        raise PolicyRefusal(
            f"systemctl may only be run as 'systemctl ACTION UNIT' with ACTION in "
            f"{sorted(allowed_actions)}; {argv[1:]!r} is not that shape. In particular, "
            "'link', 'enable', 'disable', 'mask', 'daemon-reload' and any subcommand "
            "that introduces or replaces a unit file are never permitted here."
        )
    unit = argv[2]
    if not CONTROLLABLE_UNIT_RE.match(unit):
        raise PolicyRefusal(f"{unit!r} is not a valid systemd unit name")
    if unit in UNCONTROLLABLE_UNITS:
        raise PolicyRefusal(
            f"{unit} may not be controlled through the executor, including via "
            "patch_step_exec — the same units check_unit refuses for service_action."
        )


def _check_tar_argv(argv: list[str]) -> None:
    """Positive flag list, not a denylist: everything not named here refuses,
    including `--use-compress-program`/`--to-command`/`-I`/`-T`/`-P` etc. that
    round 1 had to name explicitly to block. A future dangerous flag this list
    does not yet know about is refused by default instead of by omission.
    """
    base_dir: str | None = None
    saw_mode = False
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-C", "--directory"):
            if i + 1 >= len(argv):
                raise PolicyRefusal(f"tar {part} requires a directory argument")
            base_dir = argv[i + 1]
            # Absolute and path-checked, like the `--directory=` form below. A
            # RELATIVE value skips `check_argv`'s "starts with /" test and is
            # resolved against the executor's working directory (/ under
            # systemd): `-C var/lib/sentinel-executor` was accepted, and wrote
            # there.
            check_path(base_dir, purpose="extract into")
            i += 2
            continue
        if part.startswith("--directory="):
            base_dir = part.split("=", 1)[1]
            # `check_argv` path-checks only tokens that START with "/"; this one
            # starts with "--", so without this line the directory was never
            # compared with PROTECTED_PATHS at all. Measured 5 October 2026 against
            # the policy: `tar -xf x.tar --directory=/var/lib/sentinel-executor`
            # was accepted, while `-C /var/lib/sentinel-executor` was not.
            check_path(base_dir, purpose="extract into")
            i += 1
            continue
        if part.startswith("--one-top-level"):
            # bare, or `--one-top-level=NAME`. NAME is a directory NAME, and a
            # name has no "/": measured in a container on 5 October 2026, GNU tar
            # 1.34 extracts into `--one-top-level=/root/t/abs` as an ABSOLUTE
            # directory, ignoring `-C` - the same write as `-C /root/t/abs`, in a
            # form no path check sees.
            if "=" in part and "/" in part.split("=", 1)[1]:
                raise PolicyRefusal(
                    f"tar {part!r}: --one-top-level takes a directory name, not a path; "
                    "an absolute value extracts there regardless of -C"
                )
            i += 1
            continue
        if part in _TAR_ALLOWED_LONG:
            i += 1
            continue
        if part.startswith("--"):
            raise PolicyRefusal(f"tar flag {part!r} is not in the allowed set {sorted(_TAR_ALLOWED_LONG)}")
        if part.startswith("-") and len(part) > 1:
            chars = part[1:]
            if "C" in chars and len(chars) > 1:
                # `-xCf DIR FILE`: C inside a cluster takes the next argument as
                # the directory, but this loop only parses a standalone `-C`, so
                # DIR was never path-checked (measured 5 October 2026: `tar -xCf
                # var/lib/sentinel-executor x.tar` was accepted). One spelling.
                raise PolicyRefusal(
                    f"tar flag {part!r} bundles -C with other flags; write -C DIR "
                    "as its own argument so the directory can be checked"
                )
            for ch in chars:
                if ch not in _TAR_ALLOWED_SHORT_CHARS:
                    raise PolicyRefusal(
                        f"tar flag {part!r} contains {ch!r}, which is not in the "
                        f"allowed set {sorted(_TAR_ALLOWED_SHORT_CHARS)}"
                    )
            if "c" in chars or "x" in chars or "t" in chars:
                saw_mode = True
            i += 1
            continue
        i += 1

    if not saw_mode:
        raise PolicyRefusal("tar requires exactly one of -c (create), -x (extract) or -t (list)")

    if base_dir is None:
        return
    # `tar -C / etc/shadow` names a RELATIVE member that only becomes
    # `/etc/shadow` once joined with `-C`'s directory — check_path never sees
    # that join, since the member argument itself does not start with `/`.
    i = 1
    while i < len(argv):
        part = argv[i]
        if part.startswith("-"):
            if part in ("-C", "--directory") and not part.startswith("--directory="):
                i += 2
                continue
            i += 1
            continue
        if part == base_dir:
            i += 1
            continue
        candidate = part if part.startswith("/") else f"{base_dir.rstrip('/')}/{part}"
        candidate = posixpath.normpath(candidate)
        for protected in (*PROTECTED_PATHS, *SECRET_PATHS):
            if candidate == protected or candidate.startswith(protected.rstrip("/") + "/"):
                raise PolicyRefusal(
                    f"tar member {part!r} resolves to {candidate!r} under "
                    f"-C {base_dir!r}, which is protected"
                )
        i += 1


def _check_flag_allowlist(binary: str, argv: list[str], allowed: frozenset[str]) -> None:
    """Every flag-shaped token (starts with '-') must be in `allowed`. Any
    non-flag token is a positional argument and is left to the caller — most
    of these binaries' positionals are paths, already checked generically by
    `check_argv`'s own `if part.startswith('/'): check_path(...)` for every
    binary, not just these.
    """
    for part in argv[1:]:
        if part.startswith("-") and part not in allowed:
            raise PolicyRefusal(f"{binary} flag {part!r} is not in the allowed set {sorted(allowed)}")


_CP_ALLOWED_FLAGS = frozenset(
    {"-r", "-R", "--recursive", "-p", "--preserve", "-a", "--archive",
     "-f", "--force", "-n", "--no-clobber", "-v", "--verbose",
     "-T", "--no-target-directory", "--parents"}
)
_MV_ALLOWED_FLAGS = frozenset(
    {"-f", "--force", "-n", "--no-clobber", "-v", "--verbose",
     "-T", "--no-target-directory"}
)
_MKDIR_ALLOWED_FLAGS = frozenset({"-p", "--parents", "-v", "--verbose"})
_CHMOD_ALLOWED_FLAGS = frozenset({"-R", "--recursive", "-v", "--verbose", "-c", "--changes"})
_CHOWN_ALLOWED_FLAGS = frozenset({"-R", "--recursive", "-v", "--verbose"})
#: `--strip-program=COMMAND` is deliberately absent: it runs COMMAND, caller
#: chosen, as root to strip the installed binary — the coreutils `install`
#: equivalent of tar's `--to-command`. `-s`/`--strip` alone is fine; it uses
#: the fixed system `strip`, not an attacker-supplied one.
_INSTALL_ALLOWED_FLAGS = frozenset(
    {"-m", "--mode", "-o", "--owner", "-g", "--group", "-d", "--directory",
     "-D", "-v", "--verbose", "-p", "--preserve-timestamps", "-s", "--strip",
     "-b", "--backup", "-C", "--compare"}
)


def _check_install_argv(argv: list[str]) -> None:
    _check_flag_allowlist("install", argv, _INSTALL_ALLOWED_FLAGS)
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-m", "--mode") and i + 1 < len(argv):
            mode = argv[i + 1]
            if not _MODE_RE.match(mode):
                raise PolicyRefusal(
                    f"install mode {mode!r} must be a 3-digit octal mode, or 4 digits "
                    "with a leading zero — never a leading setuid/setgid/sticky digit"
                )
            i += 2
            continue
        if part in ("-o", "--owner", "-g", "--group") and i + 1 < len(argv):
            owner = argv[i + 1]
            if not _OWNER_RE.match(owner):
                raise PolicyRefusal(f"install {part} value {owner!r} is not a valid name")
            _refuse_forbidden_owner("install", owner)
            i += 2
            continue
        i += 1
    # `install` has no recursive flag — it names its own destination(s)
    # directly, so equality alone (no ancestor case) is the whole check.
    _refuse_path_directory_targets("install", argv, recursive=False)


def _check_chmod_argv(argv: list[str]) -> None:
    _check_flag_allowlist("chmod", argv, _CHMOD_ALLOWED_FLAGS)
    recursive = any(p in ("-R", "--recursive") for p in argv[1:])
    positionals = [p for p in argv[1:] if not p.startswith("-")]
    if not positionals:
        raise PolicyRefusal("chmod requires a mode")
    mode = positionals[0]
    # `s`/`t` deliberately excluded from the symbolic permission class: those
    # are setuid/setgid/sticky, not a permission bit, and `u+s`/`g+s`/`a+s`/
    # `+t`/`u=rws` all matched the pre-round-3 class (`[rwxXst]`) the same way
    # `chmod u+x` legitimately does. `X` stays — "execute if already
    # executable for someone" carries no privilege of its own.
    symbolic = re.compile(r"^[ugoa]*[-+=][rwxX]+(,[ugoa]*[-+=][rwxX]+)*$")
    if not (_MODE_RE.match(mode) or symbolic.match(mode)):
        raise PolicyRefusal(f"chmod mode {mode!r} is neither octal nor a recognised symbolic mode")
    _refuse_path_directory_targets("chmod", argv, recursive=recursive)


def _check_chown_argv(argv: list[str]) -> None:
    _check_flag_allowlist("chown", argv, _CHOWN_ALLOWED_FLAGS)
    recursive = any(p in ("-R", "--recursive") for p in argv[1:])
    positionals = [p for p in argv[1:] if not p.startswith("-")]
    if not positionals:
        raise PolicyRefusal("chown requires an owner")
    owner_spec = positionals[0]
    if not _OWNER_RE.match(owner_spec):
        raise PolicyRefusal(f"chown owner {owner_spec!r} is not a valid user[:group]")
    _refuse_forbidden_owner("chown", owner_spec)
    _refuse_path_directory_targets("chown", argv, recursive=recursive)


def _check_cp_argv(argv: list[str]) -> None:
    _check_flag_allowlist("cp", argv, _CP_ALLOWED_FLAGS)
    # `-a`/`--archive` implies `-r` (POSIX: archive mode preserves structure
    # AND recurses); treated as recursive here for the same reason.
    recursive = any(p in ("-r", "-R", "--recursive", "-a", "--archive") for p in argv[1:])
    _refuse_path_directory_targets("cp", argv, recursive=recursive)


def _check_mv_argv(argv: list[str]) -> None:
    _check_flag_allowlist("mv", argv, _MV_ALLOWED_FLAGS)
    # `mv` has no recursive flag — moving a directory always takes the whole
    # tree with it — so, like `install`, only the equality case applies.
    _refuse_path_directory_targets("mv", argv, recursive=False)


def _check_nginx_argv(argv: list[str]) -> None:
    if argv[1:] != ["-t"]:
        raise PolicyRefusal(
            "nginx may only be run as 'nginx -t' (config test) through the executor; "
            "reload/restart go through systemctl"
        )


def _check_test_argv(argv: list[str]) -> None:
    """`sentinel/patch/checks.py` builds exactly `["test", "-e", path]` for
    file_exists/file_absent — this is the whole real usage, so the grammar is
    the whole real usage."""
    if len(argv) != 3 or argv[1] != "-e":
        raise PolicyRefusal("test may only be run as 'test -e PATH'")


def _check_sha256sum_argv(argv: list[str]) -> None:
    """`sentinel/patch/checks.py` builds exactly `["sha256sum", path]` for
    file_sha256 — same reasoning as `test` above."""
    if len(argv) != 2:
        raise PolicyRefusal("sha256sum may only be run as 'sha256sum PATH'")


_BINARY_GRAMMAR: dict[str, Any] = {
    "dnf": _check_dnf_argv,
    "apt-get": _check_apt_argv,
    "apt": _check_apt_argv,
    "rpm": _check_rpm_argv,
    "dpkg-query": _check_dpkg_query_argv,
    "dpkg": _check_dpkg_argv,
    "systemctl": _check_systemctl_argv,
    "tar": _check_tar_argv,
    "cp": _check_cp_argv,
    "mv": _check_mv_argv,
    "mkdir": lambda argv: _check_flag_allowlist("mkdir", argv, _MKDIR_ALLOWED_FLAGS),
    "install": _check_install_argv,
    "chmod": _check_chmod_argv,
    "chown": _check_chown_argv,
    "nginx": _check_nginx_argv,
    "test": _check_test_argv,
    "sha256sum": _check_sha256sum_argv,
}
assert set(_BINARY_GRAMMAR) == BINARY_ALLOWLIST, (
    "every binary on BINARY_ALLOWLIST must have a grammar entry, or being "
    "allowlisted would once again mean nothing past argv[0] was checked"
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

    grammar = _BINARY_GRAMMAR.get(basename)
    if grammar is not None:
        grammar(argv)

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


# ---------------------------------------------------------------------------
# Where a plan step can run - and the steps that can run nowhere
# ---------------------------------------------------------------------------
# A step of an approved plan runs in one of two places, and which one is decided
# from its argv alone:
#
#   * a package TRANSACTION (`dnf`, `apt-get` or `apt` with a subcommand that
#     changes the package database) is handed to a transient systemd unit whose
#     root is writable (`transient_unit.py`);
#   * everything else runs inside the executor's own sandbox, which is
#     `ProtectSystem=strict`: `/`, `/usr`, `/etc`, `/var` and `/run` are read-only
#     there, and the few paths that are writable (the backup root, Sentinel's own
#     directories, a PRIVATE /tmp) are either protected from a plan or invisible
#     to everybody else.
#
# So a step that writes the filesystem and is not a package transaction has no
# place to run. Measured on 5 October 2026 in a container (AlmaLinux 9.8, the real
# executor under its own unit, as `sentinel`, an approved plan):
#
#     mkdir /var/lib/NEW                        exit 1  Read-only file system
#     tar -czf /var/backups/X.tgz -C / etc/Y    exit 2  Cannot open: Read-only file system
#     chmod / chown / mv / cp  (under /etc)     exit 1  Read-only file system
#     nginx -t                                  exit 1  open() "/var/log/nginx/error.log"
#                                                       failed (30: Read-only file system)
#     dnf check-update | clean all | makecache  exit 1  Config error: [Errno 30]
#                                                       Read-only file system: '/var/log/dnf.log'
#     apt-get update   (Ubuntu 24.04, a systemd-run unit with the same ProtectSystem=strict and
#                       read-write list, not the executor itself)
#                                               exit 0 (!)  W: Problem unlinking
#                                                       /var/lib/apt/lists/... (30: Read-only
#                                                       file system) - and nothing was refreshed
#     apt-get -y install X  (same unit)          exit 100  E: Failed to fetch ... Could not open file
#                                                       /var/cache/apt/archives/partial/...:
#                                                       Read-only file system
#     mkdir -p /tmp/NEW                         exit 0  - and /tmp/NEW exists nowhere
#                                                       but inside the executor
#     rpm -q, sha256sum, test -e, systemctl is-active/restart   work (they read, or
#                                                       they ask PID 1)
#
# The first five (and `apt-get install`) are the failure this section exists for: the dry run said "would
# run", the real run failed, and the runner - which cannot tell "the command
# failed" from "the machine was changed and then failed" - rolled back a machine
# nothing had touched, and then reported the rollback itself as failed. The sixth
# is the same defect pointed the other way: a step that reports success for a
# change that happened in a directory nobody can see.
#
# There are two honest answers. One is to route more binaries to a unit with a
# writable root - a widening of what unconfined root may be asked to do (`cp`,
# `mv`, `chmod` on any path a plan names), which is the operator's decision and not
# a side effect of a bug fix. The other, taken here, is to refuse such a step where
# the refusal can still be read: validation, the challenge, the dry run and the
# real call all ask the ONE function below, so they cannot disagree.
#
# `systemctl`, `rpm`, `dpkg`, `dpkg-query`, `test`, `sha256sum` and `tar -t` are
# not refused: they read, or they ask PID 1. A package manager given by absolute
# path never gets this far - `check_argv` refuses an absolute program.
#: Subcommands that change the package database, per manager. `transient_unit`
#: routes exactly these to its unit. Together with `CACHE_SUBCOMMANDS` they are
#: exactly the subcommands each grammar above accepts (asserted below), so a
#: subcommand added to a grammar later is classified by a person, not by default.
TRANSACTION_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "dnf": frozenset({"upgrade", "update", "install", "downgrade", "reinstall", "remove"}),
    "apt-get": frozenset({"install", "upgrade", "dist-upgrade", "remove", "autoremove"}),
    "apt": frozenset({"install", "upgrade", "dist-upgrade", "remove", "autoremove"}),
}
#: Accepted by the grammar, change no package, and write the manager's cache or log -
#: read-only in the executor, and not given a unit (a separate decision, recorded in
#: `transient_unit`). Refused by `sandbox_refusal`.
CACHE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "dnf": frozenset({"clean", "check-update", "makecache"}),
    "apt-get": frozenset({"update"}),
    "apt": frozenset({"update"}),
}
#: Flags that take the NEXT token as their value, so that value is not mistaken
#: for the subcommand. dnf has none (its values are joined: `--enablerepo=x`).
_PACKAGE_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "dnf": frozenset(),
    "apt-get": frozenset({"-o"}),
    "apt": frozenset({"-o"}),
}
assert set(TRANSACTION_SUBCOMMANDS) == set(CACHE_SUBCOMMANDS) == set(_PACKAGE_VALUE_FLAGS)
for _manager, _grammar_subcommands in (("dnf", _DNF_SUBCOMMANDS), ("apt-get", _APT_SUBCOMMANDS),
                                       ("apt", _APT_SUBCOMMANDS)):
    assert (TRANSACTION_SUBCOMMANDS[_manager] | CACHE_SUBCOMMANDS[_manager] == _grammar_subcommands
            and not TRANSACTION_SUBCOMMANDS[_manager] & CACHE_SUBCOMMANDS[_manager]), (
        f"{_manager}: every subcommand its grammar accepts must be classified as a transaction "
        "or as a cache operation, exactly once")


def package_subcommand(argv: Any) -> str | None:
    """The subcommand of a `dnf`/`apt-get`/`apt` argv: the first token that is not a
    flag and not a flag's value - which is how `_check_dnf_argv` and `_check_apt_argv`
    find it. None for anything else.

    `-o VALUE` is the reason this is not "the first token without a dash": the value
    of `-o Dpkg::Options::=--force-confold` has no dash, and read as the subcommand it
    makes a real `apt-get -o ... install` look like something that is not a
    transaction - which sends it to the read-only sandbox.
    """
    if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
        return None
    takes_value = _PACKAGE_VALUE_FLAGS.get(argv[0])
    if takes_value is None:
        return None
    i = 1
    while i < len(argv):
        part = argv[i]
        if not isinstance(part, str):
            return None
        if part in takes_value:
            i += 2
            continue
        if part.startswith("-"):
            i += 1
            continue
        return part
    return None


def is_package_transaction(argv: Any) -> bool:
    """True if this (grammar-validated) argv changes the package database and so is
    run in `transient_unit`'s unit. Keyed on `argv[0]` exactly, like the unit's own
    program table: a program given any other way is not routed there."""
    subcommand = package_subcommand(argv)
    return subcommand is not None and subcommand in TRANSACTION_SUBCOMMANDS[argv[0]]


_SANDBOX_WRITERS = frozenset({"cp", "mv", "mkdir", "install", "chmod", "chown"})


def _tar_writes(argv: list[str]) -> bool:
    """Whether a (grammar-validated) `tar` argv creates or extracts - `-t` only
    lists. Scans the way `_check_tar_argv` does, so the value of `-C` is not read as
    a cluster of mode letters."""
    i = 1
    while i < len(argv):
        part = argv[i]
        if part in ("-C", "--directory"):
            i += 2
            continue
        if part.startswith("--"):
            i += 1
            continue
        if part.startswith("-") and len(part) > 1 and ("c" in part[1:] or "x" in part[1:]):
            return True
        i += 1
    return False


def sandbox_refusal(argv: Any) -> str | None:
    """Why this (grammar-validated) step cannot run anywhere a plan can put it, or
    None if it can.

    ONE function for four callers: the plan validator (a plan that cannot run is
    never stored as valid), the challenge and the registration (the operator is never
    asked to sign for it), the dry run (it is not reported as "would run") and the
    real call (it is never run to fail with EROFS, or to "succeed" in a private
    /tmp). The reason names the command and what happens to it; the caller adds
    WHICH step.
    """
    if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
        return None
    program = argv[0].rsplit("/", 1)[-1]
    if program in TRANSACTION_SUBCOMMANDS:
        if is_package_transaction(argv):
            return None
        return (f"`{program} {package_subcommand(argv) or '?'}` writes the package manager's cache and log, "
                "which are read-only in the executor's sandbox, and it changes no package, so it is "
                "not run in the unit that package transactions get. Measured: `dnf` exits 1 with "
                "'Read-only file system'; `apt-get update` exits 0 after warning 'Problem unlinking "
                "... Read-only file system', having refreshed nothing. A plan needs only the "
                "transaction itself")
    if program in _SANDBOX_WRITERS or (program == "tar" and _tar_writes(argv)):
        return (f"`{program}` writes the filesystem, and a plan step that is not a package "
                "transaction runs inside the executor's sandbox, where every path a plan may name is "
                "read-only: it fails with 'Read-only file system' (or, under /tmp, appears to succeed "
                "in a private directory nobody else can see). Files are saved by the plan's `backup` "
                "section and changed by the package manager; only a package transaction has a unit "
                "that can write")
    if program == "nginx":
        return ("`nginx -t` opens nginx's log files and creates its temporary directories, which are "
                "read-only in the executor's sandbox: it exits 1 with 'Read-only file system' on a "
                "configuration that is fine. Check the service instead (`systemctl is-active`), and "
                "reload through `systemctl`")
    return None


# ---------------------------------------------------------------------------
# Plan binding, and who is allowed to approve a plan.
#
# Two separate questions, both answered here, because a registry that records
# WHICH commands were approved is worth nothing if anyone can write to it.
#
# 1. WHICH commands run. The grammar above says a command is well-formed, not
#    that the operator approved THIS one: `dnf -y install some-plausible-package`
#    is grammar-legal. So `patch_step_exec` refuses any real call whose argv is
#    not, byte for byte, step N of a plan that was registered here.
#
# 2. WHO may register one. This is the part that used to be wrong. The previous
#    design signed `plan_hash` with a key in /etc/sentinel/secrets.env, a file
#    `0640 root:sentinel` - readable by the `sentinel` account, which runs the
#    Telegram bot, the web UI and the detection pipeline. Anything that
#    compromised any of those could read the key and sign an approval of its own
#    choosing: the gate protected nothing against the attacker it exists for.
#    The token was also an HMAC of the hash ALONE, so a signature obtained for
#    one plan was accepted for the steps of any other (reproduced twice: `dnf -y
#    remove openssh-server` registered under another plan's hash, then accepted
#    by `lookup_registered_step` and `consume_registered_step`).
#
# THE CHOICE, and what was not chosen.
#
#   Not a separate approver account that owns the key. The operator's tap
#   arrives in the bot, which is `sentinel`. For the approver to sign anything
#   the bot must ask it to; a compromised bot asks too, so the approver is a
#   signing oracle with an extra uid in front of it. An approver that does NOT
#   sign on request has to reach the human by a channel of its own - a second
#   Telegram bot with a token `sentinel` cannot read: a new daemon, a new
#   credential, a new unit. That is a mechanism for the operator to approve, not
#   one to slip in underneath a bug fix.
#
#   Not plain TOTP either. A six-digit code proves the human was present at some
#   moment and says nothing about WHAT they approved, and it would be typed into
#   the chat of the very process the gate distrusts: a compromised bot reads the
#   code and spends it, inside its validity window, on steps of its own. No
#   signature would cover the steps, so the binding below could not exist.
#
#   Chosen: an operator-held key and a transaction-bound token. The key exists in
#   two places - the operator's workstation and a root-only file here - and is
#   readable by nothing that runs as `sentinel`. The token is
#   HMAC-SHA256(key, plan_hash | digest of the exact steps | a nonce this process
#   issued). The operator's tool (scripts/approve-plan.py) recomputes the digest
#   from the steps and prints the commands before it signs, so the display that
#   matters is not the bot's: a bot that lies about what it will register can
#   register nothing but what the operator read on his own screen.
#
#   What that buys, one property per sentence. The token cannot be made without
#   the key. It is valid for exactly the steps it was computed over - a token for
#   one plan registers no other. It is valid once: the nonce is consumed by the
#   registration, so a copy of the token (a chat history, a log, a database row)
#   authorises nothing a second time.
#
#   What it costs: approving needs the operator's workstation, not only the
#   phone. That is the price of a display the bot does not control, and it is the
#   operator's to waive (a phone-side TOTP is the cheaper, weaker alternative).
#
# WHAT AN ATTACKER WHO OWNS THE `sentinel` UID CAN STILL DO, said plainly:
#
#   * Ask for a challenge and register nothing: challenges are inert. It can
#     replace a pending challenge for a plan hash (latest wins), so it can make
#     the operator's token stop matching, and it can fill the table of pending
#     challenges (`_CHALLENGE_MAX`) so that a legitimate one is refused until
#     they expire - a denial of approvals either way. That was already possible
#     by stopping the bot.
#   * Ask the operator to sign something. The operator reads the commands on his
#     own screen; this is the one place a human still has to look.
#   * USE THE DOCKER SOCKET. `sentinel` is in the `docker` group, which is root on
#     this host through /run/docker.sock: `docker run -v /:/host` reads the key
#     file, or simply runs the command. That is not closed here and is not made
#     worse; it is the measured subject of the gate-3 report, and no refusal was
#     added for it. Until that membership changes, everything this section does
#     holds against an attacker who stays inside the `sentinel` account and not
#     against one who uses the socket.
#   * Everything that is not `patch_step_exec`: blocking an address, a restore
#     drill, a service action. Those are other operations with their own policy.
#
# What was NOT done: persisting registrations. The registry is in memory, so a
# restart of this process asks for a new approval. That is deliberate (a restart
# is a reason to look again) and README.md says so.
# ---------------------------------------------------------------------------
_PLAN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
#: Beside the audit chain, in a directory `sentinel` cannot even traverse
#: (0700 root:root). NOT in /etc/sentinel/secrets.env, which is readable by the
#: account this key exists to restrain.
_APPROVAL_KEY_PATH = Path("/var/lib/sentinel-executor/approval.key")
_APPROVAL_KEY_OWNER_UID = 0
#: 32 random bytes, written as 64 lowercase hex digits and a newline.
_APPROVAL_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

#: Domain separators: a token or a digest made for one purpose cannot be
#: presented as the other, and neither collides with a value made by the old
#: scheme (which signed the bare plan hash).
_APPROVAL_DOMAIN = b"sentinel-plan-approval-v1"
_STEPS_DOMAIN = b"sentinel-plan-steps-v1"

#: A challenge lives this long. The operator has to read the commands, run the
#: tool and paste the answer; much longer is a window for nothing.
_CHALLENGE_TTL_S = 900
_CHALLENGE_MAX = 16

#: Registered plans are capped in count so that a caller that can reach
#: `register_plan` at all (a valid token AND grammar-legal steps still required)
#: cannot grow this dict without bound between restarts.
_PLAN_REGISTRY_MAX = 200
_MAX_STEPS_PER_PLAN = 256
_MAX_TTL_S = 3600

_plan_registry_lock = threading.Lock()
#: plan_hash -> {"steps": list[list[str]], "expires_at": float (monotonic)}
_plan_registry: dict[str, dict[str, Any]] = {}
#: plan_hash -> {"digest": str, "nonce": str, "expires_at": float (monotonic)}.
#: Guarded by the same lock as the registry: a challenge is consumed by the
#: registration it authorises, and the two must change together.
_challenges: dict[str, dict[str, Any]] = {}


def steps_digest(steps: Any) -> str:
    """sha256 over the exact commands of a plan, in order. The one definition of
    "these steps": the executor computes it from what it is handed, the
    operator's tool computes it from what it shows, and a token only verifies if
    both got the same answer.

    ASCII-escaped JSON with no whitespace, so that two programs in two languages
    encode the same list to the same bytes. A non-string element is not
    "converted": the grammar refuses it long before this runs.
    """
    canonical = json.dumps(steps, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(_STEPS_DOMAIN + b"\n" + canonical.encode("ascii")).hexdigest()


def approval_token(key: bytes, plan_hash: str, digest: str, nonce: str) -> str:
    """What the operator's tool computes and this process verifies.

    Covers the plan hash AND the digest of the steps AND this process's nonce:
    drop any one and an old attack comes back (the hash alone: any plan's token
    registers any plan's steps; no nonce: a token can be registered again).
    """
    message = b"\n".join((_APPROVAL_DOMAIN, plan_hash.encode("ascii"),
                          digest.encode("ascii"), nonce.encode("ascii")))
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def approval_key_path() -> Path:
    """Where the approval key is read from.

    A function and not the constant, so a caller that asks "which file would an
    approval be verified with" gets the answer for the path actually in force -
    `transient_unit` probes this file as the `sentinel` uid, and a probe of a
    copy of the path would be a check of the wrong file that reports it clean.
    """
    return _APPROVAL_KEY_PATH


def _key_stat_problem(*, is_regular: bool, uid: int, mode: int, parent_uid: int,
                      parent_mode: int, owner_uid: int = 0) -> str | None:
    """Why a key file with these properties cannot be trusted, or None.

    A pure function of numbers, so every branch is exercised on any platform: the
    properties of the REAL file are read by `_read_approval_key`, and this is the
    judgement about them. A key that group or other can read is the original
    defect again; a parent directory they can write is a way to replace the file
    with one of their own.
    """
    if not is_regular:
        return "it is not a regular file"
    if uid != owner_uid:
        return f"it is owned by uid {uid}, not by uid {owner_uid}"
    if mode & 0o077:
        return (f"its mode is {mode & 0o777:04o}; group or other can reach it, and the point "
                "of the key is that nothing but root can")
    if parent_uid != owner_uid:
        return f"its directory is owned by uid {parent_uid}, not by uid {owner_uid}, who could replace the file"
    if parent_mode & 0o022:
        return (f"its directory has mode {parent_mode & 0o777:04o}; group or other can write to it "
                "and replace the file")
    return None


def _read_approval_key() -> bytes:
    """The approval key, or a refusal that says why there is none.

    Read fresh on every call, never cached: whoever enrols a key does not also
    have to restart the executor, and a key that was replaced or loosened is
    noticed on the next use rather than at the next boot. `O_NOFOLLOW`: a
    symlink planted at the path is refused, not followed.
    """
    where = str(_APPROVAL_KEY_PATH)
    try:
        fd = os.open(where, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        raise PolicyRefusal(
            f"no approval key is enrolled at {where}; patch_step_exec is disabled on this host "
            "until the operator enrols one (see docs/PATCHING.md, 'Aprobarea unui plan') - failing "
            "closed rather than accepting a plan nothing actually approved") from None
    except OSError as exc:
        raise PolicyRefusal(f"the approval key at {where} cannot be opened ({exc.strerror or exc}); "
                            "failing closed") from None
    try:
        info = os.fstat(fd)
        try:
            parent = os.stat(os.path.dirname(where))
        except OSError as exc:
            raise PolicyRefusal(f"the directory of the approval key cannot be examined "
                                f"({exc.strerror or exc}); failing closed") from None
        problem = _key_stat_problem(
            is_regular=stat_module.S_ISREG(info.st_mode), uid=info.st_uid, mode=info.st_mode,
            parent_uid=parent.st_uid, parent_mode=parent.st_mode, owner_uid=_APPROVAL_KEY_OWNER_UID)
        if problem:
            raise PolicyRefusal(f"the approval key at {where} is not trusted: {problem}")
        data = os.read(fd, 4096)
    except OSError as exc:
        raise PolicyRefusal(f"the approval key at {where} cannot be read ({exc.strerror or exc}); "
                            "failing closed") from None
    finally:
        os.close(fd)
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if not _APPROVAL_KEY_RE.match(text):
        raise PolicyRefusal(f"the approval key at {where} is not 64 lowercase hex digits; failing closed")
    return bytes.fromhex(text)


def approval_key_problem() -> str | None:
    """Why no approval can be verified on this host right now, or None if one can.

    For `transient_unit`'s gate, which must say "the key is not there" rather than
    leave the operator to infer it from a refusal later. Reads the key the same
    way verification does - the two cannot disagree about what a usable key is.
    """
    try:
        _read_approval_key()
    except PolicyRefusal as exc:
        return str(exc)
    return None


def _plan_steps_or_refuse(steps: Any) -> list[list[str]]:
    if not isinstance(steps, list) or not steps:
        raise PolicyRefusal("steps must be a non-empty list of argv lists")
    if len(steps) > _MAX_STEPS_PER_PLAN:
        raise PolicyRefusal(f"{len(steps)} steps exceeds the limit of {_MAX_STEPS_PER_PLAN}")
    validated: list[list[str]] = []
    for i, step in enumerate(steps):
        try:
            validated.append(check_argv(step))
        except PolicyRefusal as exc:
            raise PolicyRefusal(f"steps[{i}] does not pass the binary/argv grammar: {exc}") from None
        # After the grammar, before anybody is asked to sign: a step that can only fail
        # here is refused at the challenge, where the operator has spent nothing yet.
        why = sandbox_refusal(validated[-1])
        if why:
            raise PolicyRefusal(f"steps[{i}] {validated[-1]!r} cannot run on this host: {why}")
    return validated


def _plan_hash_or_refuse(plan_hash: Any) -> str:
    if not isinstance(plan_hash, str) or not _PLAN_HASH_RE.match(plan_hash):
        raise PolicyRefusal("plan_hash must be a 64-character lowercase sha256 hex digest")
    return plan_hash


def challenge_plan_steps(plan_hash: Any, steps: Any) -> dict[str, Any]:
    """Start an approval: say what exactly would be approved, and issue the nonce
    the operator's token must cover.

    Inert. Nothing becomes runnable, and the caller needs no authority to ask: the
    answer is a digest of what it sent and a random value. It does need an
    enrolled key - asking for an approval that can never be completed would only
    waste the operator's time reading commands.

    A second challenge for the same `plan_hash` replaces the first, so the older
    nonce stops working. The steps are grammar-checked here too, so the operator is
    never asked to sign something the executor would refuse.
    """
    _plan_hash_or_refuse(plan_hash)
    _read_approval_key()  # refuses, with the reason, when no usable key is enrolled
    validated = _plan_steps_or_refuse(steps)
    digest = steps_digest(validated)
    nonce = secrets.token_hex(16)
    now = time.monotonic()
    with _plan_registry_lock:
        for stale in [h for h, entry in _challenges.items() if entry["expires_at"] <= now]:
            del _challenges[stale]
        if plan_hash not in _challenges and len(_challenges) >= _CHALLENGE_MAX:
            raise PolicyRefusal(f"{_CHALLENGE_MAX} approvals are already waiting for an answer; "
                                "refusing to open another rather than growing without bound")
        _challenges[plan_hash] = {"digest": digest, "nonce": nonce, "expires_at": now + _CHALLENGE_TTL_S}
    return {"plan_hash": plan_hash, "digest": digest, "nonce": nonce,
            "step_count": len(validated), "expires_in_s": _CHALLENGE_TTL_S}


def register_plan_steps(plan_hash: Any, steps: Any, ttl_s: Any, token: Any) -> int:
    """Approve one plan's exact commands for `patch_step_exec` to run.

    Succeeds only if `token` is the operator's HMAC over THIS `plan_hash`, THESE
    steps and the nonce of a challenge this process issued for exactly these
    steps and has not yet spent. Every step is re-validated through `check_argv`
    too: registering a plan is never a way around the grammar, only a way to say
    which of the grammar-legal commands were approved. Returns the number of steps.

    The challenge is consumed only by a SUCCESSFUL registration. A wrong token
    must not be a way to destroy the operator's pending approval.
    """
    _plan_hash_or_refuse(plan_hash)
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        raise PolicyRefusal("approval_token is required: 64 lowercase hex digits")
    if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or not 1 <= ttl_s <= _MAX_TTL_S:
        raise PolicyRefusal(f"ttl_s must be an integer in 1..{_MAX_TTL_S}, got {ttl_s!r}")
    key = _read_approval_key()
    validated = _plan_steps_or_refuse(steps)
    digest = steps_digest(validated)

    now = time.monotonic()
    with _plan_registry_lock:
        challenge = _challenges.get(plan_hash)
        if challenge is None or challenge["expires_at"] <= now:
            _challenges.pop(plan_hash, None)
            raise PolicyRefusal(
                f"no approval is waiting for {plan_hash}: it was never asked for, was already used, "
                "or expired; ask for a new challenge")
        if challenge["digest"] != digest:
            raise PolicyRefusal(
                f"these steps are not the ones the approval of {plan_hash} was asked for; a token "
                "authorises exactly the steps it was computed over and nothing else")
        expected = approval_token(key, plan_hash, digest, challenge["nonce"])
        if not hmac.compare_digest(expected, token):
            raise PolicyRefusal("approval_token does not match this plan, these steps and this challenge "
                                "under the enrolled key")
        # Purge expired entries before the size check, so a host that has been
        # up for a while does not refuse a fresh, legitimate registration
        # because of old plans nobody will ever run again.
        for expired_hash in [h for h, entry in _plan_registry.items() if entry["expires_at"] <= now]:
            del _plan_registry[expired_hash]
        if plan_hash not in _plan_registry and len(_plan_registry) >= _PLAN_REGISTRY_MAX:
            raise PolicyRefusal(
                f"{_PLAN_REGISTRY_MAX} plans are already registered and unexpired; "
                "refusing to register another rather than growing without bound"
            )
        del _challenges[plan_hash]
        _plan_registry[plan_hash] = {"steps": validated, "expires_at": now + ttl_s}
    return len(validated)


def lookup_registered_step(plan_hash: Any, step_index: Any, argv: list[str]) -> None:
    """Refuse unless `argv` is byte-for-byte the step registered at
    `step_index` for `plan_hash`, and the registration has not expired.

    This is the enforcement half of the module comment above. A dry run never
    calls this — see `op_patch_step_exec` — because a dry run does not execute
    anything and `runner.py`'s own rule is that a dry run needs no approval;
    only a REAL, non-dry-run step is bound to a registered plan.
    """
    if not isinstance(plan_hash, str) or not _PLAN_HASH_RE.match(plan_hash):
        raise PolicyRefusal(
            "plan_hash is required and must be a 64-character lowercase sha256 hex "
            "digest; patch_step_exec only runs a step that was registered via "
            "register_plan after the operator signed it"
        )
    if not isinstance(step_index, int) or isinstance(step_index, bool) or step_index < 0:
        raise PolicyRefusal("step_index must be a non-negative integer")

    now = time.monotonic()
    with _plan_registry_lock:
        entry = _plan_registry.get(plan_hash)
        if entry is not None:
            if entry["expires_at"] <= now:
                del _plan_registry[plan_hash]
                raise PolicyRefusal(f"the registration for {plan_hash} has expired; re-approve to run it")
            steps = entry["steps"]
            if step_index >= len(steps):
                raise PolicyRefusal(
                    f"step_index {step_index} is out of range for {plan_hash} ({len(steps)} "
                    "registered steps)"
                )
            if steps[step_index] != list(argv):
                raise PolicyRefusal(
                    f"argv for step {step_index} does not match what was approved for "
                    f"{plan_hash}; refusing rather than running something different from "
                    "what the operator saw"
                )
            return
    # Nothing registered. Said outside the lock - reading the key is file I/O - and
    # said differently when no key is enrolled: "nothing can ever be approved on
    # this host" is not "this plan was not approved".
    problem = approval_key_problem()
    if problem is not None:
        raise PolicyRefusal(f"patch_step_exec is disabled: no plan can be registered on this "
                            f"host ({problem})")
    raise PolicyRefusal(
        f"no plan is registered for {plan_hash}; patch_step_exec only runs a "
        "step that was registered via register_plan after the operator signed it"
    )


def consume_registered_step(plan_hash: Any, step_index: Any, argv: list[str]) -> None:
    """`lookup_registered_step`, and the approval is spent: the same step of the
    same registration is refused the second time.

    Only the transient-unit path calls this. A registration lets a step be
    replayed until it expires, which is harmless for a command that runs inside
    the executor's read-only sandbox and is not for one that runs as unconfined
    root: the rollback step of an approved plan is a `dnf downgrade`, and
    "approved once" must not mean "runnable at will for the next hour".

    What it does NOT close: nothing here knows which phase a plan is in, so an
    approved rollback step can still be run first, once, without the apply step
    having failed. Only a registration that carries ordering could close that.
    Re-registering the same `plan_hash` replaces the entry and so resets the
    used marks - which needs a valid approval token, i.e. the approver.
    """
    lookup_registered_step(plan_hash, step_index, argv)
    with _plan_registry_lock:
        entry = _plan_registry.get(plan_hash)
        if entry is None or entry["expires_at"] <= time.monotonic():
            raise PolicyRefusal(f"the registration for {plan_hash} expired while the step was being consumed")
        # Checked again under the lock that marks it: between `lookup_...` above
        # and here the registration can have been replaced by another whose
        # step at this index is a different command.
        if entry["steps"][step_index] != list(argv):
            raise PolicyRefusal(
                f"argv for step {step_index} does not match what was approved for "
                f"{plan_hash}; the registration was replaced while it was being consumed")
        used = entry.setdefault("used", set())
        if step_index in used:
            raise PolicyRefusal(
                f"step {step_index} of {plan_hash} has already been executed; an approval "
                "runs one step once - approve the plan again to run it again")
        used.add(step_index)
