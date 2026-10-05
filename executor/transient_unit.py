"""A package transaction, run in a transient systemd unit instead of in the executor.

READ executor/README.md BEFORE CHANGING ANYTHING HERE. This file is the one place
where the executor hands an approved command to something that is NOT sandboxed
like the executor, so it is the most dangerous file in the directory.

Why it exists. The executor runs with `ProtectSystem=strict`, and its mount table
(measured from /proc/<MainPID>/mountinfo on production) has `/`, `/boot`, `/usr`,
`/var/lib/rpm`, `/var/cache`, `/var/log` and `/etc` read-only. A package
transaction writes to every one of them, so it cannot happen inside the executor
by construction: `patch_executions` id 9 failed with `[Errno 30] Read-only file
system: '/var/log/dnf.log'` - dnf's FIRST write, not its only one. Widening the
executor's own sandbox path by path was rejected (it is root and listens on a
socket); dropping OS patching was rejected. What is left is this: for one approved
plan step, ask systemd (PID 1) to run the command in a transient unit whose
properties are fixed HERE, in code.

What the unit is allowed to be. Root, with `ProtectSystem=strict` and an explicit
read-write list, no `/home`, a private `/tmp`, the Sentinel trust anchors masked
out (`/etc/sentinel`, the audit chain, the backups, `/opt/sentinel`, the socket
directory), a capability bounding set that drops the ones a package manager has
no use for, only the four address families dnf needs, and hard resource limits
so a runaway transaction cannot starve the websites this host also serves.

What it is never allowed to be. Anything derived from the request. Every unit
property, the unit name, the working directory and the environment are module
constants below. The only request-derived bytes that reach systemd are the
tokens of `argv[1:]`, placed AFTER a `--` so systemd-run cannot read one as an
option, handed over as separate exec arguments (no shell, no `sh -c`, no
re-joining, no re-parsing) and each one restricted to a closed alphabet so that
systemd's own `$VAR`/`%specifier` substitution has nothing to substitute.
`timeout_s` from the request bounds how long the EXECUTOR waits; the unit's own
runtime ceiling is the constant `RUNTIME_MAX_S`.

THE OUTCOME BELONGS TO PID 1, NOT TO THIS PROCESS. The first version of this file
ran `systemd-run --wait --collect --pipe` and read the result off the client's
pipes. Measured in a lab (AlmaLinux 9.8, systemd 252), that tied the transaction's
fate to the executor's life: with `--pipe` the unit's stdout IS the client's pipe,
so when the client died - executor OOM-stop (`MemoryMax=192M`, `OOMPolicy=stop`),
crash, SIGKILL - the unit's next write hit a closed pipe. A Python child printing
for 10 s exited 120 three seconds after the client was killed; real `dnf -y install
tree` killed at 0.3 s came out `Deactivated successfully`, exit 0, and `rpm -q tree`
said NOT INSTALLED (dnf swallows the broken pipe and reports success). And
`--collect` had already garbage-collected the unit, so `systemctl show` answered
`success/0/inactive` for a transaction that had failed: the API reported success
that the journal contradicted. Both are "exit 0, nothing installed" - the failure
this repository exists to stop.

So the unit no longer has a client at all:

  * no `--pipe`, no `--wait`: the unit writes to the JOURNAL (`StandardOutput=
    journal`, named in the properties so a changed default cannot change it), and
    `systemd-run` returns as soon as the start job has finished. Type=exec makes
    that "the program was exec'd", not "the request was queued". Nothing this
    process does afterwards - or fails to do - can close a pipe the unit writes to;
  * `RemainAfterExit=yes` and NO `--collect`: when the main process ends the unit
    stays loaded (`active/exited`, or `failed`) with `Result`, `ExecMainCode`,
    `ExecMainStatus` and `InvocationID` intact, until somebody releases it. The
    verdict is therefore a property of a unit that still exists, not of one that
    has just been garbage-collected. `LoadState=not-found` reads `Result=success`
    too, so an absent unit is its own state (`absent`) and is never an outcome;
  * this process WAITS BY POLLING `systemctl show` and reads that verdict. It does
    not wait on a child. Killing it changes nothing about the transaction;
  * the record is closed in a fixed order - end row, marker, release - and the
    unit is released only after the row that describes it is on disk. Until then
    the outcome stays readable in PID 1.

What happens when the executor comes back (`recover()`, called by main() before
the socket exists, and `_reconcile()`, called by every `run()` before it spawns):
`transaction.pending` beside the audit chain says a transaction was started and
not closed; the unit says what became of it.

  unit finished (`active/exited`, `failed`)  ->  an end row with `recovered: true`
                                                 and the verdict PID 1 kept, then
                                                 the unit is released;
  unit still running                         ->  adopted: the lock is held by a
                                                 thread that polls it to the end
                                                 and records it. No new transaction
                                                 starts meanwhile;
  unit gone, marker present                  ->  an end row `outcome: lost`, result
                                                 unknown (reboot, or somebody stopped
                                                 the unit by hand). Nothing says
                                                 whether the packages changed, and
                                                 the row does not pretend to;
  unit unreadable / a foreign unit file      ->  every transaction refused, with the
                                                 reason, until an operator looks.

What is NOT recovered, and is not pretended to be: the approval. The registry of
approved plans is in memory (policy.register_plan_steps), so after a restart the
rollback step of an interrupted plan must be approved again; persisting approvals
would be a new mechanism and is left to the operator. What the runner does about
that: it does not roll back from a transaction that is "not over" (it could not be
approved, and it would race the transaction); it asks `transaction_outcome` what
this process recorded for the step and tells the operator. A duplicate end row for one
invocation is possible only if the process died between writing it and releasing
the unit; it carries `recovered: true` and the true verdict. The unit's OUTPUT is
kept by the journal (volatile on production: gone at reboot) and returned to the
requester when there is one; a recovered transaction has no requester, so its
output is only in the journal and its verdict is in the audit row.

Properties kept and dropped, and why. Each drop below is either measured or a
documented systemd semantic; a protection is dropped only when a real run showed
it necessary, never because it could not be tried.

  KEPT    ProtectSystem=strict + ReadWritePaths   the root stays read-only except
                                                  where packages actually go
          ProtectHome, PrivateTmp                 no scriptlet has business in
                                                  /home or in the shared /tmp
          InaccessiblePaths (Sentinel anchors)    secrets, audit chain, backups,
                                                  executor code and socket are
                                                  invisible to the transaction
          CapabilityBoundingSet=~CAP_...          no module loading, raw I/O,
                                                  reboot, clock, ptrace, BPF,
                                                  network administration (so the
                                                  Sentinel nftables table cannot
                                                  be edited by a scriptlet), no
                                                  switching the audit subsystem off
          RestrictAddressFamilies                 UNIX, INET, INET6, NETLINK only
          RestrictNamespaces, RestrictRealtime,   nothing a scriptlet needs
          LockPersonality
          ProtectControlGroups                    cgroups are PID 1's business
          NoNewPrivileges, MemoryDenyWriteExecute ON. Measured with both on (lab,
                                                  systemd 252): install, remove,
                                                  `reinstall util-linux-core` (mount
                                                  and su are setuid) and a sixteen-
                                                  package `upgrade` (systemd, pam,
                                                  openssl, coreutils, ...) all
                                                  succeeded. NNP costs nothing for a
                                                  uid-0 process with a near-full
                                                  bounding set, and there is no
                                                  SELinux transition to lose
                                                  (production: `getenforce`
                                                  Disabled). Not tried: a kernel or
                                                  bootloader update, Java or Node
                                                  scriptlets - if one of those is
                                                  shown to need either, drop that
                                                  one line and say what broke
          MemoryMax, TasksMax, CPUWeight,         the sites on this host keep
          IOWeight, Nice, RuntimeMaxSec           running while it patches

  DROPPED RestrictSUIDSGID    rpm installs setuid binaries (sudo, su, mount, ping);
                              with this on, `dnf -y reinstall util-linux-core` fails
                              with `Error unpacking rpm package` (reproduced twice,
                              by two people). The executor's own unit sets it, which
                              is one of the reasons patching could never work there.
          ProtectKernelModules  it makes /usr/lib/modules inaccessible (systemd's
                              documented semantic): no kernel update could be
                              installed. CAP_SYS_MODULE is dropped instead, which is
                              what actually stops loading one.
          PrivateDevices      puts /dev behind a device policy; dracut, grub and lvm
                              scriptlets need real nodes
          ProtectClock, ProtectKernelTunables, SystemCallArchitectures  are simply
                              not set. The reasons that were once given for them
                              (udev triggers writing under /sys, 32-bit scriptlet
                              helpers) are reasons, not measurements: they were not
                              tried in the lab, and they are the first candidates
                              to test before anyone calls them necessary.

  THE HONEST LIMIT. None of the above is a boundary against code that runs INSIDE
  the unit, and nothing that could be added to it would be. Measured in a lab
  (AlmaLinux 9.8, systemd 252): with CAP_SYS_ADMIN, root in the unit `umount`s a
  masked path and reads what was masked; with CAP_SYS_ADMIN taken away as well,
  it asks PID 1 for a NEW transient unit - through /run/systemd/private or D-Bus,
  which `%systemd_post` scriptlets need and so cannot be cut off - and that unit
  is unconfined and reads it. So the restrictions hold against mistakes and
  against unprivileged code, not against a hostile package. What makes a
  transaction safe to run is that only an approved step ever reaches it.

Network. The executor has `IPAddressDeny=any`; a transient unit does not inherit
that, because it is PID 1's child and not the executor's. This unit gets outbound
network with no address filter, because dnf reaches mirrors and CDNs whose
addresses cannot be listed. That is a real widening - a scriptlet can exfiltrate -
and it is accepted only for the duration of one approved step. (The nftables table
has no output hook, so nothing on the host bounds it either.) `apt-get` and `apt`
reach their mirrors the same way, and run in the same unit.

THE GATE. This path is not switchable by a flag, an environment variable or a
config file: `refusal_reasons()` computes, at every call, facts about the host,
and every one of them must hold. They are the prerequisites for handing a
socket peer unconfined root. What each one is an observation OF, and what it is
not, is written out because two of them were once claimed to be measured by the
kernel and could not be:

  1. an audit sink is wired and the audit path is known.
  2. CONTROL, read: `test -r /usr/bin/test` as the requester uid answers yes.
  3. CONTROL, write: `test -w /dev/null` as the requester uid answers yes. A
     character device is exempt from the read-only-mount check, so this answers
     "can the probe say yes to -w at all" even from inside a read-only namespace.
     Without it a broken `-w` (wrong uid, no exec) reads as "cannot write" for
     every path below, and the gate would open on a probe that never worked.
  4. the requester uid cannot read the approval key, AND a usable key exists. The
     key is what an approval token is checked against; whoever can read it can sign
     a plan of their own choosing. It lives in the root-only directory beside the
     audit chain (policy.approval_key_path()), not in secrets.env, which the
     `sentinel` account reads. Two observations, kept apart because each is blind
     where the other sees: "cannot read" is ANSWERED BY THE KERNEL (`test -r` as that
     uid; reading is not refused by a read-only mount, so this process's namespace
     does not distort it) but is also what a MISSING key looks like from the
     requester's side; so the executor reads the key itself, as root, the way it will
     to verify a token (`policy.approval_key_problem()`: exists, regular file, owned
     by root, no group/other bits, directory not writable by others, 64 hex digits).
  5. the requester cannot write the audit file, its directory, or any ancestor
     (an ancestor it owns lets it rename the directory away and recreate one) - and
     the same for the approval key and every directory above it.
     This is NOT one kind of answer, and it must not be described as one:

       * a path on a mount that is WRITABLE in this process's mount namespace is
         asked of the kernel (`test -w` as the requester uid).
       * a path on a mount that is READ-ONLY here cannot be asked. The executor
         runs with `ProtectSystem=strict`: `/`, `/var` and `/var/lib` are `ro`
         in its namespace, so `access(W_OK)` returns EROFS for them whatever the
         host's permissions say, and `test -w` answers "no" - a guard that
         cannot fail (reproduced: a directory owned by the requester, host
         `test -w` -> 0, probed from inside a strict unit -> False). Detected by
         `statvfs` (`ST_RDONLY`), which IS visible from here. For those paths the
         answer is read from `stat`: owned by the requester (an owner can chmod
         at will), other-writable, or group-writable with a group the requester
         is in, means yes. This is an opinion about mode bits, not the kernel's
         answer - it does not consult ACLs. What it does instead is refuse
         whenever the path HAS an extended ACL (`system.posix_acl_access`), so an
         ACL it cannot evaluate is never counted as "fine".
       * anything that cannot be determined (statvfs, stat or the probe fails)
         is refused as unknown, never as fine.

  6. the audit hook writes the "start" row and the pending marker BEFORE the unit
     is spawned; if either cannot be written, nothing is spawned.
  7. the argv is byte-for-byte a step of a plan that was registered through
     `policy.register_plan_steps` and has not been executed yet.
  8. no other transaction is running, and no unit of that name is left over:
     PID 1 refuses a second unit with the same name, and `_reconcile()` reads
     what is there before every spawn.

History, because it is why this gate exists. The approval key used to be read from
/etc/sentinel/secrets.env, which is 0640 root:sentinel because the sentinel services
read that file for their own reasons (measured on production, 30 September 2026), so
this fact was false on every host and the gate stayed closed. The key is now an
operator-held secret that lives in a root-only file, and the fact holds once an
operator has enrolled one (docs/PATCHING.md, "Aprobarea unui plan"). WHAT THE GATE
DOES NOT OBSERVE: whether the requester can reach root some other way. `sentinel` is
in the `docker` group, which is root through the socket, and no fact above looks at
that - on purpose, and reported separately: a refusal added here would close the path
for a reason nobody has decided on yet.

Stdlib only, imports nothing from `sentinel/` - see README.md.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat as stat_module
import subprocess  # noqa: S404 - handing a validated argv to systemd is the job
import threading
import time
from collections.abc import Callable
from pathlib import PurePath, PurePosixPath
from typing import Any

import policy
from policy import PolicyRefusal

# ---------------------------------------------------------------------------
# Constants. Nothing below this line up to `build_command` may be assigned from
# a request, and a test asserts `run`'s signature has no parameter that could.
# ---------------------------------------------------------------------------
#: Absolute paths, never looked up through PATH: this is a root process handing
#: work to another root process.
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
JOURNALCTL = "/usr/bin/journalctl"
TEST = "/usr/bin/test"
#: World-writable on every Linux, and a character device, which the kernel
#: exempts from the read-only-mount check: the one path that answers "can `test
#: -w` say yes" from inside any mount namespace.
WRITE_CONTROL = "/dev/null"

#: The bare name the grammar validated -> the binary that is actually run. Every
#: package manager the grammar knows has an entry (a test holds the two tables
#: together): a manager the grammar accepts and this table lacks would be a
#: transaction with nowhere to go. `apt` and `apt-get` are two names for the same
#: Debian family of binaries; each is run as itself, never one as the other.
PROGRAMS: dict[str, str] = {
    "dnf": "/usr/bin/dnf",
    "apt-get": "/usr/bin/apt-get",
    "apt": "/usr/bin/apt",
}

#: Subcommands that write to the package database - `policy.TRANSACTION_SUBCOMMANDS`,
#: the one definition, which the plan validator and the challenge read too (they run
#: on the other side of the trust boundary and cannot import this module). Together
#: with `NOT_ROUTED_SUBCOMMANDS` it is exactly each grammar's subcommand set, so a
#: subcommand added to a grammar later is classified by a human, not by default.
MUTATING_SUBCOMMANDS: dict[str, frozenset[str]] = policy.TRANSACTION_SUBCOMMANDS
#: Not given a unit. They write the manager's cache and log, which are read-only in
#: the executor's sandbox - see the README - but they change no package, and giving
#: them an unconfined unit is a separate decision. A step like that is REFUSED up
#: front (`policy.sandbox_refusal`), not run to fail.
NOT_ROUTED_SUBCOMMANDS: dict[str, frozenset[str]] = policy.CACHE_SUBCOMMANDS

#: One fixed name. systemd refuses a second unit with the same name, which makes
#: "one transaction at a time" a fact PID 1 enforces across executor restarts and
#: not a promise this process keeps. `systemd-run` appends `.service`.
UNIT = "sentinel-txn"
UNIT_FULL = UNIT + ".service"
DESCRIPTION = "Sentinel package transaction (one approved plan step)"
WORKING_DIRECTORY = "/"

#: The unit's own ceiling, enforced by systemd even if this process is gone. The
#: same number as the plan validator's `MAX_TIMEOUT_S`.
RUNTIME_MAX_S = 3600
#: How long systemd waits between SIGTERM and SIGKILL. Generous on purpose: a
#: SIGKILL in the middle of an rpm transaction is the worst thing that can
#: happen to the package database.
STOP_TIMEOUT_S = 300

#: Every entry starts with `-` ("ignore if absent"), on purpose: a path that does
#: not exist makes systemd fail the unit before dnf starts (status 226/NAMESPACE,
#: `Failed to set up mount namespacing: /run/systemd/unit-root/boot: No such file
#: or directory` - seen in the lab on a host with no /boot). On a host that has
#: all of them the `-` changes nothing; on one that lacks one it is the difference
#: between a transaction and a failure that looks like dnf's.
READ_WRITE_PATHS = ("-/usr", "-/boot", "-/boot/efi", "-/efi", "-/etc", "-/var", "-/opt", "-/srv", "-/run")
#: Sentinel's own trust anchors. `-` = ignore if absent.
MASKED_PATHS = (
    "-/etc/sentinel", "-/var/lib/sentinel", "-/var/lib/sentinel-executor",
    "-/var/backups/sentinel", "-/run/sentinel", "-/opt/sentinel",
)
DENIED_CAPABILITIES = (
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_BOOT", "CAP_SYS_TIME",
    "CAP_SYS_PTRACE", "CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_AUDIT_CONTROL", "CAP_SYSLOG", "CAP_WAKE_ALARM",
)

UNIT_PROPERTIES: tuple[str, ...] = (
    "ProtectSystem=strict",
    "ReadWritePaths=" + " ".join(READ_WRITE_PATHS),
    "InaccessiblePaths=" + " ".join(MASKED_PATHS),
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "ProtectControlGroups=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    "CapabilityBoundingSet=~" + " ".join(DENIED_CAPABILITIES),
    # On, because a real run showed them compatible (see the module docstring);
    # named, not left to a default, so a change of default cannot turn them off.
    "NoNewPrivileges=yes",
    "MemoryDenyWriteExecute=yes",
    # Named as OFF, not left to a default, so a later "hardening" that turns one
    # of them on has to delete a line that says why it is off.
    "RestrictSUIDSGID=no",
    "ProtectKernelModules=no",
    "PrivateDevices=no",
    "UMask=0022",
    # The outcome contract - see "THE OUTCOME BELONGS TO PID 1". The unit's output
    # goes to the journal (no pipe to a client that can die) and the unit outlives
    # its main process, so its verdict stays readable until it is released.
    "RemainAfterExit=yes",
    "StandardOutput=journal",
    "StandardError=journal",
    f"RuntimeMaxSec={RUNTIME_MAX_S}",
    f"TimeoutStopSec={STOP_TIMEOUT_S}",
    "MemoryMax=3G",
    "TasksMax=2048",
    "CPUWeight=20",
    "IOWeight=20",
    "Nice=10",
)
UNIT_ENVIRONMENT: tuple[str, ...] = (
    "PATH=/usr/sbin:/usr/bin",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "HOME=/root",
    "TERM=dumb",
    # No terminal, no one to answer. Measured (Ubuntu 24.04, `postfix`, which asks a
    # debconf question): WITHOUT this, debconf tries the Dialog frontend, then Readline,
    # each failing with a warning, falls back to Teletype and takes the defaults - the
    # install completes; with it, it goes straight there. So it is the conventional
    # setting that keeps the outcome from depending on a fallback chain, and it is NOT
    # shown to be necessary. Not read by dnf.
    "DEBIAN_FRONTEND=noninteractive",
    # Ubuntu's apt hook runs `needrestart -m u` after every dpkg run, and in that mode
    # it RESTARTS affected services by itself. Measured on 5 October 2026 (Ubuntu 24.04
    # container, needrestart 3.6, libc replaced the way an upgrade does): run as the
    # hook runs it, OUTSIDE this unit, it executed `systemctl restart
    # sentinel-executor.service systemd-journald.service` and the executor's start time
    # changed - the "restarted under an install" case (`recover`, runner rule 9).
    # INSIDE this unit it does nothing today, with or without this line: it prints "No
    # services need to be restarted", because the unit drops CAP_SYS_PTRACE
    # (DENIED_CAPABILITIES) and so cannot read other processes' memory maps. This line
    # is the second guard, and it is proved only for the case where the first one goes:
    # with CAP_SYS_PTRACE given back and this line absent the end-to-end test
    # (test_patch_apply_end_to_end_apt.py) fails - the executor IS restarted inside the
    # apt transaction - and with the line present it passes. `l` lists and restarts
    # nothing; the plan's own `systemctl restart` is then the only restart, as after a
    # `dnf` transaction on the rpm hosts. Not read by dnf.
    "NEEDRESTART_MODE=l",
)
#: The environment of the CLIENTS this process starts (`systemd-run`, `systemctl`,
#: `journalctl`, the probe), not of the unit.
_CLIENT_ENV = {"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

#: The closed alphabet a transaction token may use. Wider than a package name
#: needs nowhere; narrower than `policy._PKG_NAME_RE`, which lets everything but
#: `/` and whitespace follow a `:` - including `$` and `%`, which systemd
#: substitutes in an exec line. `~` is in it because a Debian version is: every
#: Debian security update carries one (`1:2.3-1~deb12u1`), and without it the
#: rollback pin of a Debian plan could never be sent. Measured that systemd hands
#: it to the program unchanged (`systemd-run -- /usr/bin/echo 'pkg=2:1.2~rc1-1~deb12u1'`
#: prints the argument as given); it has no meaning in an exec line, unlike `$` and `%`.
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._+:=~-]+")
_MAX_TOKEN_CHARS = 200
#: The whole argv, JSON-encoded, goes into ONE audit row whose detail field is
#: cut at 1000 characters. Longer is refused, never truncated: a row that shows a
#: prefix of what was run is worse than no row.
MAX_AUDITED_ARGV_CHARS = 500

OUTPUT_LIMIT_BYTES = 64 * 1024
#: Exit code reported when the transaction's outcome cannot be vouched for: the
#: manager did not say "success", the unit vanished, this process stopped waiting.
#: 125 is what `env`/`nohup` use for "the wrapper failed", not the command.
EXIT_UNVERIFIED = 125
EXIT_TIMEOUT = 124
EXIT_NOT_STARTED = 127
#: How long `systemd-run` gets to return. It returns when the START JOB is done, so
#: this is not the transaction's length.
_SPAWN_TIMEOUT_S = 120
#: Between two reads of the unit's state. A transaction lasts minutes, and a
#: process that is asked to stop notices within this long.
POLL_INTERVAL_S = 2.0
#: Consecutive unreadable states before this process stops waiting. It does NOT
#: stop the unit: not being able to look is not a reason to kill an rpm transaction.
_UNREADABLE_LIMIT = 5
#: The most an adopted transaction (see `recover`) is followed for: the unit's own
#: ceiling, its stop grace, and a margin. PID 1 ends it by then whatever we do.
_ADOPT_CEILING_S = RUNTIME_MAX_S + STOP_TIMEOUT_S + 120

#: Written beside the audit chain when a transaction starts and removed when its
#: end row is on disk. It is a HINT for the case the unit cannot answer (gone);
#: the unit, when there is one, is the authority.
MARKER_NAME = "transaction.pending"

_INVOCATION_ID = re.compile(r"[0-9a-f]{32}")
_PLAN_HASH = re.compile(r"[0-9a-f]{64}")
_PLAIN_VALUE = re.compile(r"[A-Za-z0-9._:-]{0,64}")

# ---------------------------------------------------------------------------
# Wiring, set once by sentinel_executor.main(). Not reachable from a request:
# `configure` is not in commands.OPERATIONS.
# ---------------------------------------------------------------------------
AuditWrite = Callable[[str, str, dict[str, Any]], bool]
_audit_write: AuditWrite | None = None
_audit_path: PurePosixPath | None = None
#: Set when the executor is shutting down: waiting stops, the unit does not.
_stop: threading.Event | None = None
_log: Callable[..., None] = lambda level, message, **fields: None  # noqa: E731

_transaction_lock = threading.Lock()
#: Invocation ids whose end row this process has already written, so a unit that
#: could not be released is not re-recorded on every later call.
_closed_invocations: set[str] = set()

#: The end rows THIS process wrote, by (plan_hash, step_index): the answer to "what
#: became of the transaction for this approved step?" that `transaction_outcome`
#: gives the runner. A mirror of rows that are already on disk - never a second
#: source of truth: it is filled only after `audit_write` said the row landed,
#: bounded, and gone at a restart (the audit chain is what survives one).
_RECORDED_MAX = 64
_recorded: dict[tuple[str, int], dict[str, Any]] = {}
_recorded_lock = threading.Lock()


def configure(audit_path: Any, audit_write: AuditWrite, stop: threading.Event | None = None,
              log: Callable[..., None] | None = None) -> None:
    """Tell this module where the audit chain lives and how to write to it.

    `audit_write(event, result, detail)` must return True only if the row is on
    disk. It is a parameter and not an import because the executor imports this
    module, and importing back would be a cycle in the one root component.
    `stop` is the executor's shutdown event; `log` is its logger.
    """
    global _audit_write, _audit_path, _stop, _log
    text = audit_path.as_posix() if isinstance(audit_path, PurePath) else str(audit_path)
    _audit_path = PurePosixPath(text)
    _audit_write = audit_write
    _stop = stop
    _log = log if log is not None else (lambda level, message, **fields: None)


# ---------------------------------------------------------------------------
# Classification and shape
# ---------------------------------------------------------------------------
def is_transaction(argv: Any) -> bool:
    """True if this (already grammar-validated) argv writes to the package
    database and therefore belongs in a transient unit.

    Decided by `policy.is_package_transaction`, which finds the subcommand the way the
    grammar does - the first token that is neither a flag nor a flag's value (`apt-get
    -o Dpkg::Options::=--force-confold install x` is an install) - and the grammar
    refuses every abbreviation (`in`, `up`, `rm`) the managers themselves would accept,
    so the two cannot disagree about which word is the subcommand.

    A False answer does NOT mean "run it in the sandbox and see": `op_patch_step_exec`
    then asks `policy.sandbox_refusal`, and a step that can only fail there is refused
    before it is run.
    """
    return policy.is_package_transaction(argv)


def check_shape(argv: list[str]) -> None:
    """The second, narrower lock on the bytes that will reach systemd.

    The grammar already ran. This exists because systemd is a second parser of
    an exec line - `$VAR`, `${VAR}` and `%specifier` are substituted - and
    `policy._PKG_NAME_RE` lets `$` and `%` through after a `:`. A token that
    systemd would rewrite is a token that is no longer byte-identical to what was
    validated, so it is refused, not escaped.
    """
    for index, part in enumerate(argv):
        if len(part) > _MAX_TOKEN_CHARS or not _SAFE_TOKEN.fullmatch(part):
            raise PolicyRefusal(
                f"argv[{index}] is not made only of letters, digits and . _ + : = ~ -; "
                "a package transaction is handed to systemd, which substitutes $ and % "
                "in an exec line, so anything outside that alphabet is refused rather "
                "than escaped"
            )
    encoded = json.dumps(argv, separators=(",", ":"))
    if len(encoded) > MAX_AUDITED_ARGV_CHARS:
        raise PolicyRefusal(
            f"the command is {len(encoded)} characters as JSON; a transaction must fit "
            f"in one audit row ({MAX_AUDITED_ARGV_CHARS}), and a truncated record of a "
            "root command is refused rather than written"
        )


def build_command(argv: list[str]) -> list[str]:
    """The complete argv of the `systemd-run` client. A pure function of `argv`.

    Everything before the `--` is a module constant. After it come the absolute
    path of the program and `argv[1:]` exactly as validated.

    No `--wait`, `--pipe` or `--collect`: see "THE OUTCOME BELONGS TO PID 1". The
    client's exit status means "the start job finished", nothing more, and nothing
    about the transaction hangs on the client staying alive.
    """
    return [
        SYSTEMD_RUN,
        "--no-ask-password",
        f"--unit={UNIT}",
        f"--description={DESCRIPTION}",
        "--service-type=exec",   # the start job finishes when the program has been exec'd
        f"--working-directory={WORKING_DIRECTORY}",
        *(f"--property={item}" for item in UNIT_PROPERTIES),
        *(f"--setenv={item}" for item in UNIT_ENVIRONMENT),
        "--",
        PROGRAMS[argv[0]],
        *argv[1:],
    ]


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
def _requester() -> tuple[int, int, list[int]] | None:
    """The `sentinel` account's uid, gid and supplementary groups, as the kernel
    will apply them to a process running as it, or None if they cannot be read."""
    account = policy._SERVICE_ACCOUNT  # noqa: SLF001
    try:
        import pwd

        entry = pwd.getpwnam(account)
        return entry.pw_uid, entry.pw_gid, os.getgrouplist(entry.pw_name, entry.pw_gid)
    except (ImportError, KeyError, OSError, AttributeError):
        return None


def _probe(flag: str, path: str) -> bool | None:
    """Ask the kernel whether the requester uid passes `test FLAG PATH`.

    True / False are answers. None is "I could not find out" and is never
    treated as either: 0 and 1 are the only exit codes `test` gives an answer
    with, and a process that could not be started as that uid says nothing.

    A False for `-w` is only an answer about permissions when the mount holding
    PATH is writable in this process's namespace; see `_requester_can_write`.
    """
    who = _requester()
    if who is None:
        return None
    uid, gid, groups = who
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [TEST, flag, path], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=10, shell=False, check=False, cwd="/", env=dict(_CLIENT_ENV),
            user=uid, group=gid, extra_groups=groups,
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None


def _mount_read_only(path: str) -> bool | None:
    """Whether the mount holding `path` is read-only in THIS process's mount
    namespace, or None if that cannot be read.

    This is the fact that decides whether `test -w` can be asked at all: on a
    read-only mount `access(W_OK)` fails with EROFS before permissions are looked
    at. A path that does not exist yet (the audit file before its first row) is on
    the mount of its nearest existing ancestor.
    """
    probe = path
    try:
        while True:
            try:
                flags = os.statvfs(probe).f_flag
                break
            except FileNotFoundError:
                parent = os.path.dirname(probe)
                if parent == probe:
                    return None
                probe = parent
    except (OSError, AttributeError):
        return None
    return bool(flags & os.ST_RDONLY)


def _has_extended_acl(path: str) -> bool | None:
    """Whether `path` carries an access ACL beyond its mode bits; None if that
    cannot be read. A filesystem without xattrs cannot have one."""
    try:
        names = os.listxattr(path)
    except OSError as exc:
        if exc.errno in {getattr(errno, "ENOTSUP", -1), getattr(errno, "EOPNOTSUPP", -1)}:
            return False
        return None
    except AttributeError:
        return None
    return "system.posix_acl_access" in names


def _stat_says_requester_can_write(path: str) -> tuple[bool | None, str]:
    """The requester's write access to `path`, read from owner and mode bits. For
    the paths `_probe` cannot answer about. An opinion, and it says so: it is
    conservative (a directory it cannot traverse still counts as writable if the
    bits say so) and it refuses what it cannot evaluate - an extended ACL - rather
    than pass it."""
    who = _requester()
    if who is None:
        return None, "the requester account could not be read"
    uid, _gid, groups = who
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return False, "it does not exist yet"
    except OSError as exc:
        return None, f"stat failed: {exc}"
    if info.st_uid == uid:
        return True, "it is owned by the requester, who can chmod it whatever the mode says"
    if info.st_mode & stat_module.S_IWOTH:
        return True, "it is writable by everyone"
    if info.st_mode & stat_module.S_IWGRP and info.st_gid in groups:
        return True, "it is group-writable by a group the requester is in"
    acl = _has_extended_acl(path)
    if acl is None:
        return None, "whether it carries an ACL could not be read"
    if acl:
        return None, "it carries an extended ACL, which this check does not evaluate"
    return False, "owner and mode bits give the requester no write access"


def _requester_can_write(path: str) -> tuple[bool | None, str]:
    """(answer, how it was obtained). The kernel is asked where it can answer; see
    the module docstring, THE GATE item 5, for why that is not everywhere."""
    read_only = _mount_read_only(path)
    if read_only is None:
        return None, "the mount holding it could not be inspected"
    if read_only:
        answer, why = _stat_says_requester_can_write(path)
        return answer, f"read from owner/mode bits, because its mount is read-only in the executor's namespace: {why}"
    return _probe("-w", path), "asked of the kernel"


def _audit_chain_paths(audit_path: PurePosixPath) -> list[str]:
    return [str(audit_path), *(str(parent) for parent in audit_path.parents)]


def _protected_paths(audit_path: PurePosixPath | None, key_path: str) -> list[str]:
    """Everything the requester must not be able to write: the audit chain, and the
    approval key with every directory above it. A writable directory above the key
    lets its owner replace the file with a key of their own, which is the same as
    reading it."""
    paths = list(_audit_chain_paths(audit_path)) if audit_path is not None else []
    key = PurePosixPath(PurePath(key_path).as_posix())
    paths += [str(key), *(str(parent) for parent in key.parents)]
    return list(dict.fromkeys(paths))


def refusal_reasons() -> list[str]:
    """Every reason a package transaction may not run on this host right now.
    An empty list means every fact below holds; there is no other way in.

    Evaluated on every call and never cached: these are properties of files and
    accounts that an operator can change under a running executor.
    """
    reasons: list[str] = []
    account = policy._SERVICE_ACCOUNT  # noqa: SLF001
    audit_write, audit_path = _audit_write, _audit_path
    if audit_write is None or audit_path is None:
        reasons.append("the executor has not wired an audit sink into the transaction path")

    control = _probe("-r", TEST)
    if control is not True:
        reasons.append(
            f"cannot check what the requester may do: `test -r {TEST}` as the "
            f"{account!r} account returned {control!r} instead of True, so a "
            "'not readable' answer would not mean anything"
        )
        return reasons
    write_control = _probe("-w", WRITE_CONTROL)
    if write_control is not True:
        reasons.append(
            f"cannot check what the requester may write: `test -w {WRITE_CONTROL}` as the "
            f"{account!r} account returned {write_control!r} instead of True, so a "
            "'not writable' answer would not mean anything"
        )
        return reasons

    key_path = str(policy.approval_key_path())
    readable = _probe("-r", key_path)
    if readable is None:
        reasons.append(f"could not determine whether the requester can read the approval key {key_path}")
    elif readable:
        reasons.append(
            f"the approval key {key_path} is readable by the requester ({account!r}), so "
            "it can sign an approval for a plan of its own choosing: the approval binds "
            "nothing against the account it is meant to constrain"
        )
    # The other half of fact 4. "The requester cannot read it" is also what a key
    # that does not exist looks like from the requester's side, and a gate that
    # opened on a missing key would open on a host where no approval can ever be
    # checked. The executor reads the key itself, as root, the way it will to
    # verify a token, and says what is wrong with it.
    problem = policy.approval_key_problem()
    if problem is not None:
        reasons.append(f"no approval can be verified on this host: {problem}")

    for path in _protected_paths(audit_path, key_path):
        writable, how = _requester_can_write(path)
        if writable is None:
            reasons.append(f"could not determine whether the requester can write {path}, "
                           f"which the audit chain or the approval key depends on ({how})")
        elif writable:
            reasons.append(
                f"the requester can write {path}, which the audit chain or the approval key "
                f"depends on: it could rewrite, or rename away and replace, the record of what "
                f"runs as root, or the key an approval is checked against ({how})"
            )
    return reasons


def dry_run_report() -> dict[str, Any]:
    """What a dry run says about a transaction step. A dry run never spawns
    anything, so on its own it would report a step the real run will refuse as
    though it were fine - the same "unknown reads as fine" collapse as a health
    check that cannot see what it checks."""
    return {"transient_unit": True, "refused_because": refusal_reasons()}


# ---------------------------------------------------------------------------
# What PID 1 says about the unit
# ---------------------------------------------------------------------------
_STATE_KEYS = (
    "LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus",
    "InvocationID", "Transient", "FragmentPath",
    "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic",
)


def _plain(value: Any) -> str:
    """A value from PID 1 made safe to print into a row or a message: anything
    outside a small alphabet is replaced, not passed through."""
    text = "" if value is None else str(value)
    return text if _PLAIN_VALUE.fullmatch(text) else "?"


def _unit_state() -> dict[str, str] | None:
    """The unit's properties as PID 1 reports them, or None if they could not be
    read. None is not "the unit is gone": that is `LoadState=not-found`, which
    systemd answers with rc 0."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [SYSTEMCTL, "show", UNIT_FULL, "--property=" + ",".join(_STATE_KEYS)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=15, shell=False,
            check=False, cwd="/", env=dict(_CLIENT_ENV),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    state: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in _STATE_KEYS:
            state[key] = value
    if not {"LoadState", "ActiveState", "SubState"} <= state.keys():
        return None
    return state


def _classify(state: dict[str, str] | None) -> str:
    """What the unit's state means, in words that are not systemd's.

      unknown   the state could not be read, or is one this code has no meaning for
      absent    no such unit (`LoadState=not-found`). NEVER an outcome: systemd
                reports `Result=success` for a unit that does not exist
      foreign   a unit of this name that is not transient - a unit FILE somebody
                put there. `systemd-run` cannot replace it
      running   the main process is running, starting or being stopped
      finished  the main process is over and PID 1 kept the verdict
                (`active/exited` because of RemainAfterExit, or `failed`)
      stopped   loaded and inactive: stopped by hand; no verdict was kept
    """
    if state is None:
        return "unknown"
    loaded = state.get("LoadState")
    if loaded == "not-found":
        return "absent"
    if loaded != "loaded":
        return "unknown"
    if state.get("Transient") != "yes":
        return "foreign"
    active, sub = state.get("ActiveState"), state.get("SubState")
    if active == "failed" or (active == "active" and sub == "exited"):
        return "finished"
    if active in ("active", "activating", "deactivating", "reloading", "refreshing"):
        return "running"
    if active == "inactive":
        return "stopped"
    return "unknown"


def _verdict(state: dict[str, str]) -> dict[str, Any]:
    """The exit code and whether it can be vouched for, from a FINISHED unit.

    Success needs all of it at once: the manager's `Result=success`, a main process
    that exited (code 1 = CLD_EXITED) with status 0, and a unit that is
    `active/exited`. Anything short of that is a failure or unverified, never a
    success - a missing field is not a zero.
    """
    result = _plain(state.get("Result"))
    code = state.get("ExecMainCode")
    try:
        status = int(state.get("ExecMainStatus", ""))
    except ValueError:
        status = None
    if status is None or code not in ("1", "2", "3"):
        return {"exit_code": EXIT_UNVERIFIED, "verified": False, "result": result}
    if code == "1":
        if status == 0:
            ok = (result == "success" and state.get("ActiveState") == "active"
                  and state.get("SubState") == "exited")
            # Exited 0 but the manager does not say success: not proof of anything.
            return {"exit_code": 0 if ok else EXIT_UNVERIFIED, "verified": ok, "result": result}
        return {"exit_code": status, "verified": True, "result": result}
    # Killed (2) or dumped (3): the status is the signal number.
    return {"exit_code": 128 + status, "verified": True, "result": result}


def _duration_ms(state: dict[str, str] | None) -> int | None:
    """How long the main process ran, by PID 1's own monotonic timestamps."""
    if state is None:
        return None
    try:
        begin = int(state.get("ExecMainStartTimestampMonotonic", ""))
        end = int(state.get("ExecMainExitTimestampMonotonic", ""))
    except ValueError:
        return None
    return (end - begin) // 1000 if 0 < begin <= end else None


def _summary(state: dict[str, str] | None, verdict: dict[str, Any] | None) -> str:
    """One line for the caller, built from values PID 1 gave and this code checked
    - never from text a package could have printed."""
    if state is None:
        return f"[sentinel-txn] unit={UNIT_FULL} state=unreadable"
    line = (f"[sentinel-txn] unit={UNIT_FULL} invocation={_plain(state.get('InvocationID'))} "
            f"state={_plain(state.get('ActiveState'))}/{_plain(state.get('SubState'))} "
            f"result={_plain(state.get('Result'))} exec_code={_plain(state.get('ExecMainCode'))} "
            f"exec_status={_plain(state.get('ExecMainStatus'))}")
    if verdict is not None:
        line += f" verified={verdict['verified']}"
    return line


def _systemctl(*args: str, timeout: int) -> None:
    """Run `systemctl ARGS` and ignore what it says. The exit status is the
    intention; what happened is read back from `_unit_state` by the caller."""
    try:
        subprocess.run(  # noqa: S603 - fixed argv
            [SYSTEMCTL, *args], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=timeout, shell=False, check=False, cwd="/", env=dict(_CLIENT_ENV),
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _settled() -> bool | None:
    """Whether nothing of the transaction is running, as systemd says it now.

    True if the unit reads absent, stopped or finished; False if it runs; None if
    the state could not be read or is not the kind of unit this code started."""
    kind = _classify(_unit_state())
    if kind in ("absent", "stopped", "finished"):
        return True
    if kind == "running":
        return False
    return None


def _stop_unit() -> bool | None:
    """Stop the unit and report what systemd says afterwards (`_settled`). The exit
    status of `systemctl stop` is not consulted: it is the intention and the state
    is the effect."""
    _systemctl("stop", UNIT_FULL, timeout=STOP_TIMEOUT_S + 30)
    return _settled()


def _release_unit(expected_id: str | None) -> bool | None:
    """Make the unit's name free again, and confirm it: True only when the unit
    reads absent afterwards. A unit that is running, foreign, or has a different
    invocation id than the one being closed is NOT touched - releasing must never
    stop a transaction it did not record."""
    before = _unit_state()
    kind = _classify(before)
    if kind == "absent":
        return True
    if kind not in ("finished", "stopped"):
        return None if kind == "unknown" else False
    seen = (before or {}).get("InvocationID") or None
    if expected_id is not None and seen not in (None, expected_id):
        return False
    _systemctl("stop", UNIT_FULL, timeout=STOP_TIMEOUT_S + 30)
    _systemctl("reset-failed", UNIT_FULL, timeout=30)
    after = _classify(_unit_state())
    if after == "absent":
        return True
    return None if after == "unknown" else False


# ---------------------------------------------------------------------------
# Running it
# ---------------------------------------------------------------------------
class _Tail:
    """The last `limit` bytes of a stream, counting what was dropped.

    Reading everything and cutting afterwards is what would let a scriptlet that
    prints without end take the executor's 192 MiB down with it. The END is kept
    because that is where the failure is."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.buffer = bytearray()
        self.dropped = 0

    def feed(self, chunk: bytes) -> None:
        self.buffer += chunk
        over = len(self.buffer) - self.limit
        if over > 0:
            del self.buffer[:over]
            self.dropped += over

    def text(self) -> str:
        head = f"[... {self.dropped} earlier bytes dropped ...]\n" if self.dropped else ""
        return head + self.buffer.decode("utf-8", "replace")


def _drain(stream: Any, tail: _Tail) -> None:
    try:
        while True:
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                return
            tail.feed(chunk)
    except (OSError, ValueError):
        return


def _run_bounded(argv: list[str], timeout_s: int) -> dict[str, Any]:
    """Run a helper with bounded output and a deadline. `returncode` is None when
    it could not be started or was killed for running too long; `error` says which."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is a constant plus validated tokens
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, cwd="/", env=dict(_CLIENT_ENV), close_fds=True,
        )
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": "", "timed_out": False,
                "error": f"could not start {argv[0]}: {exc}"}
    out, err = _Tail(OUTPUT_LIMIT_BYTES), _Tail(OUTPUT_LIMIT_BYTES)
    readers = [threading.Thread(target=_drain, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err), daemon=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        returncode: int | None = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
        returncode = None
    for reader in readers:
        reader.join(timeout=5)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except OSError:
            pass
    return {"returncode": returncode, "stdout": out.text(), "stderr": err.text(), "timed_out": timed_out,
            "error": f"{argv[0]} did not finish within {timeout_s} s and was killed" if timed_out else None}


def _spawn(command: list[str]) -> dict[str, Any]:
    """Start the unit. `systemd-run` returns when the start job is done; the unit
    is PID 1's from then on, and this process holds nothing it depends on."""
    return _run_bounded(command, _SPAWN_TIMEOUT_S)


def _read_output(invocation_id: str | None) -> tuple[str, str]:
    """The unit's output, read back from the journal by invocation id, and a note
    (empty when nothing is wrong). The id is checked before it is put in an argv:
    it comes from PID 1, and a value that is not 32 hex digits is not used.

    Best effort, and the verdict does not depend on it: the journal is volatile on
    production and rate-limits a service that prints without end, so the text can
    be incomplete. The exit status comes from the unit's own properties."""
    if not invocation_id or not _INVOCATION_ID.fullmatch(invocation_id):
        return "", "\n[sentinel-txn] no valid invocation id: the unit's output was not read"
    got = _run_bounded(
        [JOURNALCTL, "--no-pager", "--quiet", "--output=cat", f"_SYSTEMD_INVOCATION_ID={invocation_id}"], 60)
    if got["returncode"] != 0:
        detail = (got["error"] or got["stderr"] or "").strip()[:300]
        return got["stdout"], (f"\n[sentinel-txn] the unit's output could not be read from the journal "
                               f"(journalctl exit {got['returncode']}): {detail}")
    return got["stdout"], ""


def _outcome(**fields: Any) -> dict[str, Any]:
    """The shape every path out of `_execute` returns. The defaults are the
    pessimistic ones: unverified, not run, not timed out, closed."""
    base: dict[str, Any] = {
        "exit_code": EXIT_UNVERIFIED, "stdout": "", "stderr": "", "timed_out": False,
        "duration_ms": 0, "result": None, "unit_ran": None, "verified": False,
        "stopped_after_timeout": None, "invocation_id": None, "outcome": "unverified",
        #: True = the transaction is not over as far as this process knows (still
        #: running, or unreadable). It is then NOT recorded, marked or released:
        #: the unit and the pending marker are what the next reconcile reads.
        "open": False,
    }
    base.update(fields)
    return base


def _observe(deadline: float, expected_id: str | None,
             stop: threading.Event | None) -> tuple[dict[str, str] | None, str, str | None]:
    """Poll the unit until it has a verdict. Returns (last state, why, invocation id).

    why: finished | vanished (the unit disappeared or was stopped without a verdict)
         | replaced (a different invocation now holds the name) | timeout
         | detached (this process was asked to stop) | unreadable.
    """
    unreadable = 0
    while True:
        state = _unit_state()
        kind = _classify(state)
        if kind == "unknown":
            unreadable += 1
            if unreadable >= _UNREADABLE_LIMIT:
                return state, "unreadable", expected_id
        else:
            unreadable = 0
            seen = (state or {}).get("InvocationID") or None
            if kind in ("running", "finished") and seen:
                if expected_id is None:
                    expected_id = seen
                elif seen != expected_id:
                    return state, "replaced", expected_id
            if kind == "finished":
                return state, "finished", expected_id
            if kind in ("absent", "stopped", "foreign"):
                return state, "vanished", expected_id
        if stop is not None and stop.is_set():
            return state, "detached", expected_id
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return state, "timeout", expected_id
        pause = min(POLL_INTERVAL_S, remaining)
        if stop is not None:
            stop.wait(pause)
        else:
            time.sleep(pause)


def _execute(command: list[str], timeout_s: int) -> dict[str, Any]:
    started = time.monotonic()

    def elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    spawn = _spawn(command)
    if spawn["returncode"] is None and not spawn["timed_out"]:
        return _outcome(exit_code=EXIT_NOT_STARTED, stderr=spawn["error"] or "could not start systemd-run",
                        unit_ran=False, outcome="not_started")
    if spawn["returncode"] != 0:
        # `systemd-run` said the unit did not start, or was killed before it could
        # say. Only the second case can have left a start job queued that would
        # begin a transaction nobody is watching, and only that one is stopped. For a
        # client that said "failed" the state is READ, not stopped: whatever holds
        # the name then is not something this call started, and stopping it would
        # kill a transaction it did not record. If it cannot be shown that nothing
        # runs, the transaction stays open for the next reconcile.
        settled = _stop_unit() if spawn["timed_out"] else _settled()
        state = _unit_state()
        note = f"\n[sentinel-txn] {spawn['error']}" if spawn["error"] else ""
        return _outcome(
            exit_code=spawn["returncode"] or EXIT_UNVERIFIED, stdout=spawn["stdout"],
            stderr=spawn["stderr"] + note, unit_ran=False, outcome="not_started",
            invocation_id=(state or {}).get("InvocationID") or None,
            open=settled is not True, duration_ms=elapsed())

    state, why, invocation_id = _observe(started + timeout_s, None, _stop)
    if why == "timeout":
        # One more read before giving up: a unit that finished in the last poll
        # interval has a verdict, and stopping it would throw that away.
        again = _unit_state()
        if _classify(again) == "finished":
            state, why = again, "finished"
    client_text = spawn["stderr"]

    if why == "finished":
        assert state is not None
        verdict = _verdict(state)
        text, note = _read_output(invocation_id)
        return _outcome(
            exit_code=verdict["exit_code"], stdout=text,
            stderr=client_text + _summary(state, verdict) + note, unit_ran=True,
            verified=verdict["verified"], result=verdict["result"], invocation_id=invocation_id,
            outcome="finished", duration_ms=_duration_ms(state) or elapsed())

    if why == "timeout":
        stopped = _stop_unit()
        text, note = _read_output(invocation_id)
        return _outcome(
            exit_code=EXIT_TIMEOUT, stdout=text, timed_out=True, stopped_after_timeout=stopped,
            stderr=client_text + _summary(_unit_state(), None) + note, unit_ran=True,
            invocation_id=invocation_id, outcome="timed_out", open=stopped is not True,
            duration_ms=elapsed())

    if why in ("detached", "unreadable"):
        reason = ("the executor is shutting down" if why == "detached"
                  else "the unit's state could not be read")
        return _outcome(
            exit_code=EXIT_UNVERIFIED, unit_ran=True, invocation_id=invocation_id, outcome=why, open=True,
            stderr=(f"{client_text}[sentinel-txn] {reason}; the transaction was NOT stopped and is still "
                    f"owned by systemd as {UNIT_FULL}. Its outcome will be recorded in the audit chain by "
                    "the executor that finds it. Do not treat this as a failure or as a success."),
            duration_ms=elapsed())

    # vanished / replaced: the unit that was watched no longer has a verdict.
    text, note = _read_output(invocation_id)
    return _outcome(
        exit_code=EXIT_UNVERIFIED, stdout=text, unit_ran=True, invocation_id=invocation_id, outcome=why,
        stderr=(f"{client_text}[sentinel-txn] the unit {why} without leaving a verdict; nothing says whether "
                f"the transaction completed. {_summary(state, None)}{note}"),
        duration_ms=elapsed())


# ---------------------------------------------------------------------------
# The record: pending marker, end row, release - in that order
# ---------------------------------------------------------------------------
def _marker_path() -> str | None:
    if _audit_path is None:
        return None
    return str(_audit_path.parent / MARKER_NAME)


def _write_marker(record: dict[str, Any]) -> bool:
    """Atomically write the pending marker; True only if it is on disk (file and
    directory entry both flushed). It goes beside the audit chain, in the
    directory the gate has already required the requester cannot write."""
    path = _marker_path()
    if path is None:
        return False
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except OSError:
        return False
    return True


def _read_marker() -> dict[str, Any] | None:
    """None = there is no marker. A marker that exists but cannot be read is
    still a marker: `{"unreadable": True}`."""
    path = _marker_path()
    if path is None:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(4096)
    except FileNotFoundError:
        return None
    except OSError:
        return {"unreadable": True}
    try:
        value = json.loads(raw)
    except ValueError:
        return {"unreadable": True}
    return value if isinstance(value, dict) else {"unreadable": True}


def _clear_marker() -> bool:
    """True if there is no marker afterwards."""
    path = _marker_path()
    if path is None:
        return False
    try:
        os.unlink(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _end_detail(outcome: dict[str, Any], marker: dict[str, Any] | None, recovered: bool) -> dict[str, Any]:
    """The end row. Every field is a number, a bool, or a value PID 1 gave that
    passed `_plain`; nothing a package printed. Well under the 1000 characters an
    audit detail is cut at (a test holds it there)."""
    detail: dict[str, Any] = {
        "unit": UNIT_FULL, "invocation_id": outcome.get("invocation_id"),
        "outcome": outcome["outcome"], "exit_code": outcome["exit_code"],
        "result": outcome["result"], "verified": outcome["verified"], "unit_ran": outcome["unit_ran"],
        "timed_out": outcome["timed_out"], "stopped_after_timeout": outcome["stopped_after_timeout"],
        "duration_ms": outcome["duration_ms"], "recovered": recovered,
    }
    if marker:
        plan_hash = marker.get("plan_hash")
        if isinstance(plan_hash, str) and _PLAN_HASH.fullmatch(plan_hash):
            detail["plan_hash"] = plan_hash
        step_index = marker.get("step_index")
        if isinstance(step_index, int) and not isinstance(step_index, bool):
            detail["step_index"] = step_index
    return detail


def _remember(detail: dict[str, Any]) -> None:
    """Keep what an end row said, for `transaction_outcome`. Called only once the row
    is on disk. A row with no plan hash or step index (a transaction nobody can tie
    to a step) is not kept: there is nobody who could ask."""
    plan_hash, step_index = detail.get("plan_hash"), detail.get("step_index")
    if not isinstance(plan_hash, str) or not isinstance(step_index, int):
        return
    with _recorded_lock:
        _recorded.pop((plan_hash, step_index), None)
        _recorded[(plan_hash, step_index)] = detail
        while len(_recorded) > _RECORDED_MAX:
            del _recorded[next(iter(_recorded))]


def transaction_outcome(plan_hash: Any, step_index: Any) -> dict[str, Any]:
    """What became of the package transaction started for one approved step, as this
    executor knows it. Read-only: it settles nothing (`recover` and `_reconcile` do).

    For the runner, which cannot see the audit chain and needs to know - when a step
    came back `still_running_or_unknown` because the executor was restarted under it -
    whether to tell the operator "it finished" or "it is still going" before anyone
    suggests restoring anything.

      recorded   an end row for this step was written by this process; `end` carries
                 what it says (outcome, exit_code, verified, result, recovered)
      running    a transaction is running under systemd now (`this_step` says whether
                 it is the one asked about)
      unknown    nothing is recorded by this process and nothing runs: a transaction
                 settled by an earlier executor process is in the audit chain only
    """
    if not isinstance(plan_hash, str) or not _PLAN_HASH.fullmatch(plan_hash):
        raise PolicyRefusal("plan_hash must be a 64-character lowercase sha256 hex digest")
    if not isinstance(step_index, int) or isinstance(step_index, bool) or step_index < 0:
        raise PolicyRefusal("step_index must be a non-negative integer")
    with _recorded_lock:
        kept = _recorded.get((plan_hash, step_index))
    if kept is not None:
        return {"state": "recorded", "end": {
            key: kept.get(key) for key in
            ("outcome", "exit_code", "verified", "result", "recovered", "duration_ms")}}
    if _classify(_unit_state()) == "running":
        marker = _read_marker() or {}
        return {"state": "running", "unit": UNIT_FULL,
                "this_step": marker.get("plan_hash") == plan_hash and marker.get("step_index") == step_index}
    return {"state": "unknown"}


def _finalize(outcome: dict[str, Any], marker: dict[str, Any] | None, *, recovered: bool) -> dict[str, Any]:
    """Close a transaction's record, in the only order that never loses an outcome:

      1. the end row, on disk (skipped if this process already wrote it);
      2. the pending marker, removed;
      3. the unit, released and confirmed absent.

    Each step happens only if the one before it did. What is left undone is
    exactly what the next `_reconcile` finds and finishes, and until step 3 the
    verdict is still readable in PID 1."""
    invocation_id = outcome.get("invocation_id")
    audit_write = _audit_write
    recorded = invocation_id is not None and invocation_id in _closed_invocations
    if not recorded:
        if audit_write is None:
            return {"end_recorded": False, "marker_cleared": None, "released": None}
        end_detail = _end_detail(outcome, marker, recovered)
        recorded = bool(audit_write("end", "ok" if outcome["exit_code"] == 0 else "error", end_detail))
        if recorded:
            _remember(end_detail)
            if invocation_id is not None:
                _closed_invocations.add(invocation_id)
    if not recorded:
        return {"end_recorded": False, "marker_cleared": None, "released": None}
    if not _clear_marker():
        return {"end_recorded": True, "marker_cleared": False, "released": None}
    return {"end_recorded": True, "marker_cleared": True, "released": _release_unit(invocation_id)}


def _reconcile() -> tuple[str, str]:
    """Read what is there and close what was left open. Called with the lock held.

    Returns (status, why): `clean` (nothing left over), `closed` (a leftover was
    recorded and its unit released), `running` (a transaction is live), or
    `blocked` (something is left over that this process could not settle; new
    transactions are refused until it is).
    """
    if _audit_write is None or _audit_path is None:
        return "blocked", "the audit sink is not wired, so a leftover transaction cannot be recorded"
    state = _unit_state()
    kind = _classify(state)
    marker = _read_marker()
    if kind == "unknown":
        return "blocked", (f"the state of {UNIT_FULL} could not be read (LoadState="
                           f"{_plain((state or {}).get('LoadState'))}), so it cannot be known whether a "
                           "transaction is already running")
    if kind == "foreign":
        return "blocked", (f"{UNIT_FULL} exists as a unit file ({_plain((state or {}).get('FragmentPath'))}), "
                           "not as a transient unit; systemd-run cannot replace it and nothing here will "
                           "touch it - an operator has to remove that file")
    if kind == "running":
        return "running", f"{UNIT_FULL} is running"
    if kind == "absent":
        if marker is None:
            return "clean", ""
        lost = _outcome(outcome="lost", stderr="")
        done = _finalize(lost, marker, recovered=True)
        if done["end_recorded"] and done["marker_cleared"]:
            _log("warning", "a transaction was started and its unit is gone; recorded as lost",
                 detail="outcome unknown")
            return "closed", "a transaction whose unit was gone was recorded as lost"
        return "blocked", "a transaction was started and never closed, and its end row could not be written"
    # finished or stopped: PID 1 still holds the unit
    if kind == "finished":
        assert state is not None
        verdict = _verdict(state)
        left = _outcome(outcome="finished", exit_code=verdict["exit_code"], verified=verdict["verified"],
                        result=verdict["result"], invocation_id=(state.get("InvocationID") or None),
                        duration_ms=_duration_ms(state))
    else:
        left = _outcome(outcome="stopped", invocation_id=((state or {}).get("InvocationID") or None))
    done = _finalize(left, marker, recovered=True)
    if done["end_recorded"] and done["marker_cleared"] and done["released"] is True:
        _log("warning", "recorded and released a transaction that nobody had closed",
             outcome=left["outcome"], exit_code=left["exit_code"])
        return "closed", "a leftover transaction was recorded and its unit released"
    return "blocked", (f"{UNIT_FULL} holds the verdict of an earlier transaction and it could not be "
                       f"recorded and released (end row: {done['end_recorded']}, marker cleared: "
                       f"{done['marker_cleared']}, released: {done['released']})")


def recover() -> str:
    """Called once by main(), after the audit sink is wired and before the socket
    exists: settle whatever a previous executor left, or take over a transaction
    that is still running. Returns the status (`clean`, `closed`, `running`,
    `blocked`, `busy`); never raises. A `blocked` result is logged, not fatal -
    refusing to start would take the alerting channel down with it - and every
    `run()` re-reads the state and refuses with the reason."""
    if not _transaction_lock.acquire(blocking=False):
        return "busy"
    keep_lock = False
    try:
        status, why = _reconcile()
        if status == "running":
            keep_lock = True
            threading.Thread(target=_adopt, name="transaction-adopt", daemon=True).start()
            _log("warning", "a package transaction is running under systemd; following it to the end",
                 unit=UNIT_FULL)
        elif status == "blocked":
            _log("error", "a leftover package transaction could not be settled; transactions are "
                 "refused until it is", detail=why)
        return status
    except Exception as exc:  # noqa: BLE001 - never take the executor down from here
        _log("error", "recovering the package transaction state failed", detail=repr(exc))
        return "blocked"
    finally:
        if not keep_lock:
            _transaction_lock.release()


def _adopt() -> None:
    """Follow a transaction that a previous executor started, holding the lock so
    nothing else starts, and record it when it ends. Releases the lock that
    `recover` handed over."""
    try:
        _state, why, _invocation = _observe(time.monotonic() + _ADOPT_CEILING_S, None, _stop)
        if why in ("finished", "vanished", "replaced"):
            status, detail = _reconcile()
            _log("warning", "the adopted package transaction ended", status=status, detail=detail)
        else:
            _log("warning", "stopped following an adopted package transaction; the next executor "
                 "or the next request will settle it", why=why)
    except Exception as exc:  # noqa: BLE001
        _log("error", "following an adopted package transaction failed", detail=repr(exc))
    finally:
        _transaction_lock.release()


def run(argv: list[str], *, timeout_s: int, plan_hash: Any, step_index: Any,
        redact: Callable[[str], str] = lambda text: text) -> dict[str, Any]:
    """Run one approved package-transaction step in the transient unit.

    The parameters are the whole of what a request can influence, and none of
    them reaches a unit property: `argv` becomes the tokens after `--`,
    `timeout_s` bounds this process's wait, `plan_hash`/`step_index` select the
    registered step to consume and are written to the audit row.
    """
    if not is_transaction(argv):
        raise PolicyRefusal("not a package transaction")
    check_shape(argv)
    if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or not 1 <= timeout_s <= RUNTIME_MAX_S:
        raise PolicyRefusal(f"timeout_s must be an integer in 1..{RUNTIME_MAX_S}")

    reasons = refusal_reasons()
    if reasons:
        raise PolicyRefusal(
            "package transactions are refused on this host: " + "; ".join(reasons))

    if not _transaction_lock.acquire(blocking=False):
        raise PolicyRefusal("another package transaction is already running")
    try:
        # Before the approval is spent: a leftover unit is not the operator's doing.
        status, why = _reconcile()
        if status == "running":
            raise PolicyRefusal(f"another package transaction is already running ({UNIT_FULL})")
        if status == "blocked":
            raise PolicyRefusal(f"a package transaction left something unsettled: {why}")

        # After the gate and the reconcile, so a refusal for a reason outside the
        # operator's approval does not use the approval up.
        policy.consume_registered_step(plan_hash, step_index, argv)

        command = build_command(argv)
        audit_write = _audit_write
        marker = {"version": 1, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "plan_hash": plan_hash, "step_index": step_index}
        if not _write_marker(marker):
            raise PolicyRefusal(
                "the pending-transaction marker could not be written, so nothing was started; the "
                "approval for this step is spent - approve it again once the audit directory is writable")
        started_ok = audit_write("start", "ok", {
            "unit": UNIT_FULL, "argv": argv, "plan_hash": plan_hash, "step_index": step_index,
            "timeout_s": timeout_s,
            "command_sha256": hashlib.sha256(json.dumps(command).encode()).hexdigest(),
        })
        if not started_ok:
            _clear_marker()
            raise PolicyRefusal(
                "the audit row for this transaction could not be written, so nothing was "
                "started; the approval for this step is spent - approve it again once "
                "the audit chain is writable")

        outcome = _execute(command, timeout_s)

        if outcome["open"]:
            # Still running, or unreadable: no end row, the marker stays, the unit
            # is not released. The next reconcile (a request, or a restart) closes it.
            done = {"end_recorded": False, "marker_cleared": False, "released": False}
        else:
            done = _finalize(outcome, marker, recovered=False)
        return {
            "argv": argv, "cwd": None,
            "exit_code": outcome["exit_code"],
            "stdout": redact(outcome["stdout"]), "stderr": redact(outcome["stderr"]),
            "duration_ms": outcome["duration_ms"], "timed_out": outcome["timed_out"],
            "transaction": {
                "unit": UNIT_FULL, "unit_ran": outcome["unit_ran"], "result": outcome["result"],
                "verified": outcome["verified"], "outcome": outcome["outcome"],
                "invocation_id": outcome["invocation_id"],
                "still_running_or_unknown": outcome["open"],
                "stopped_after_timeout": outcome["stopped_after_timeout"],
                "audit_end_recorded": done["end_recorded"], "unit_released": done["released"],
            },
        }
    finally:
        _transaction_lock.release()
