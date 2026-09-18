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
import posixpath
import re
import socket
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
    # /var/backups/sentinel (BACKUP_ROOT) — op_backup_restore legitimately
    # passes a caller-given artifact path under it through check_path, and
    # protecting it here would refuse every restore.
    "/var/lib/sentinel",
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

    Read fresh on every call, the same reasoning as `_load_approval_key`
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
            i += 2
            continue
        if part.startswith("--directory="):
            base_dir = part.split("=", 1)[1]
            i += 1
            continue
        if part.startswith("--one-top-level"):
            # bare, or `--one-top-level=NAME`
            i += 1
            continue
        if part in _TAR_ALLOWED_LONG:
            i += 1
            continue
        if part.startswith("--"):
            raise PolicyRefusal(f"tar flag {part!r} is not in the allowed set {sorted(_TAR_ALLOWED_LONG)}")
        if part.startswith("-") and len(part) > 1:
            chars = part[1:]
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
# Plan binding — round 1 narrowed WHAT any single `patch_step_exec` call can
# do (the grammar above). It did not narrow WHICH calls get to happen at all:
# a `sentinel`-uid attacker who can reach the socket can still construct an
# argv that is grammar-legal — `dnf -y install some-plausible-package` passes
# every check above — without that argv ever having been the operator's
# Telegram approval. The grammar cannot tell "legal shape" from "approved
# command"; only a record of what was actually approved can.
#
# `register_plan` is that record: the trusted caller (sentinel-telegram, after
# BOTH taps of the two-stage approval — see docs/PATCHING.md) presents a
# plan_hash, the exact argv list the plan will run, and an HMAC of the hash
# under a key only root and that caller can read. `patch_step_exec` then
# refuses to run anything that is not byte-for-byte one of those registered
# steps. A compromised `sentinel` uid that can read the same key (it can —
# secrets.env is 0640 root:sentinel, stated honestly rather than pretended
# away) can forge a token for a plan_hash of its own choosing, but it cannot
# forge one for a HASH IT DID NOT ALSO CHOOSE THE CONTENT OF — the token binds
# to the hash, and the hash is `sentinel.patch.validator.plan_hash(plan)`, a
# function of the plan's own content computed independently on the untrusted
# side. What this closes is not "a compromised sentinel-uid can never run a
# command" (nothing here can promise that with one shared uid); it is "a
# grammar-legal `patch_step_exec` call with no corresponding registration is
# refused, not silently run" — see README.md "Binding to an approved plan".
# ---------------------------------------------------------------------------
_PLAN_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_APPROVAL_KEY_NAME = "SENTINEL_EXECUTOR_APPROVAL_KEY"
#: Same file as SECRET_PATHS[0] — not imported from there so this section
#: reads standalone; a test asserts the two stay equal.
_APPROVAL_KEY_PATH = Path("/etc/sentinel/secrets.env")

#: Registered plans are capped in count so that a caller that can reach
#: `register_plan` at all (grammar-legal steps still required — see below)
#: cannot grow this dict without bound between restarts.
_PLAN_REGISTRY_MAX = 200
_MAX_STEPS_PER_PLAN = 256
_MAX_TTL_S = 3600

_plan_registry_lock = threading.Lock()
#: plan_hash -> {"steps": list[list[str]], "expires_at": float (monotonic)}
_plan_registry: dict[str, dict[str, Any]] = {}


def _load_approval_key() -> str | None:
    """Read SENTINEL_EXECUTOR_APPROVAL_KEY from secrets.env, or None.

    Read fresh on every call rather than cached at startup: the installer can
    add the key to a running host, and the alternative — a key that only
    starts working after a restart nobody was told to do — is a worse failure
    mode than the cost of re-reading one short file on the rare path that
    calls this. Parsing matches sentinel/config.py's own `load_secrets`
    (KEY=VALUE, optional matching quotes, '#' comments) — duplicated rather
    than imported for the same reason every other constant in this file is:
    this process must not import from the untrusted side.
    """
    try:
        if not _APPROVAL_KEY_PATH.exists():
            return None
        for raw in _APPROVAL_KEY_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() != _APPROVAL_KEY_NAME:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value or None
    except OSError:
        return None
    return None


def _check_approval_token(plan_hash: Any, token: Any) -> None:
    if not isinstance(plan_hash, str) or not _PLAN_HASH_RE.match(plan_hash):
        raise PolicyRefusal("plan_hash must be a 64-character lowercase sha256 hex digest")
    if not isinstance(token, str) or not token:
        raise PolicyRefusal("approval_token is required")
    key = _load_approval_key()
    if not key:
        raise PolicyRefusal(
            f"{_APPROVAL_KEY_NAME} is not set in {_APPROVAL_KEY_PATH}; patch_step_exec "
            "is disabled on this host until the installer generates one (see "
            "docs/PATCHING.md, 'Binding to an approved plan') — failing closed rather "
            "than accepting a plan nothing actually approved"
        )
    expected = hmac.new(key.encode("utf-8"), plan_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, token):
        raise PolicyRefusal("approval_token does not match plan_hash under the configured key")


def register_plan_steps(plan_hash: Any, steps: Any, ttl_s: Any, token: Any) -> int:
    """Approve one plan's exact commands for `patch_step_exec` to run.

    Every step is re-validated through `check_argv` here too: registering a
    plan is not a way to bypass the grammar above, only a way to say WHICH of
    the grammar-legal commands were actually approved. Returns the number of
    steps registered.
    """
    _check_approval_token(plan_hash, token)

    if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or not 1 <= ttl_s <= _MAX_TTL_S:
        raise PolicyRefusal(f"ttl_s must be an integer in 1..{_MAX_TTL_S}, got {ttl_s!r}")
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

    now = time.monotonic()
    with _plan_registry_lock:
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
            "register_plan after the Telegram two-tap approval"
        )
    if not isinstance(step_index, int) or isinstance(step_index, bool) or step_index < 0:
        raise PolicyRefusal("step_index must be a non-negative integer")

    now = time.monotonic()
    with _plan_registry_lock:
        entry = _plan_registry.get(plan_hash)
        if entry is None:
            if _load_approval_key() is None:
                raise PolicyRefusal(
                    f"patch_step_exec is disabled: {_APPROVAL_KEY_NAME} is not "
                    "configured, so no plan can ever be registered on this host"
                )
            raise PolicyRefusal(
                f"no plan is registered for {plan_hash}; patch_step_exec only runs a "
                "step that was registered via register_plan after the Telegram "
                "two-tap approval"
            )
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
