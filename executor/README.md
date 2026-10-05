# The executor — threat model

**Read this before changing anything in this directory.**

This is the only Sentinel component that runs as root. Everything else runs as
the unprivileged `sentinel` user. A bug here is full root compromise of a
machine that is also running whatever it was installed to protect.

---

## What it is

A unix-socket server that accepts newline-delimited JSON from the `sentinel`
user, validates each request against a hard-coded policy, performs it, and
writes the audit record itself.

Four files, **4964 lines as of 5 October 2026** (measured with `wc -l`, not the
aspirational figure below — see "It stays small"):

| File | Role |
|---|---|
| `policy.py` | The decisions. Never-block networks, protected paths, binary allowlist, per-binary argv grammar, rate caps |
| `commands.py` | The operations. Twenty of them, each validating through `policy` first |
| `transient_unit.py` | A package transaction handed to PID 1 as a transient unit; the gate that decides whether it may run, and the record of how it ended |
| `sentinel_executor.py` | The socket server, peer-credential check, per-uid admission control, audit chain (root-only directory, rotation, drain-on-shutdown), panic watcher |

---

## Why a daemon and not sudoers

A sudoers rule broad enough to be useful — `nft`, `tar`, `systemctl`, `dnf` —
is broad enough to be a privilege escalation for anyone who gets execution as
`sentinel`. `nft` alone lets you flush the ruleset. `tar` lets you write any
file. `systemctl` lets you install a unit.

A daemon can validate *what* is being asked, not just *which binary*. `nft add
element ... blocklist_v4 { 203.0.113.7 }` is fine; `nft flush ruleset` is not. A
sudoers rule cannot tell them apart.

There is a fallback sudoers file in `deploy/sudoers/sentinel` for environments
where the daemon cannot run. It is deliberately narrower and correspondingly
less capable.

---

## The four invariants

### 1. It writes its own audit rows

The caller never does. A compromised daemon can therefore neither forge an
audit entry nor omit one for something it actually caused.

The chain is `prev_hash → entry_hash`, resumed across restarts by reading the
tail of `/var/lib/sentinel-executor/audit.jsonl` — a **sibling** of
`/var/lib/sentinel`, not a child of it, and `0700 root:root`. It used to live
under `/var/lib/sentinel/executor/`, which is `0750 sentinel:sentinel`:
`sentinel` owns that parent and can rename or replace anything directly
inside it, and the executor's capability set omits `CAP_DAC_OVERRIDE`, so a
directory it made there could be replaced by one the executor cannot write —
every operation since would keep executing while logging `AUDIT WRITE FAILED`,
which is the one outcome this file exists to prevent. That is an argument from
the permissions (a capability-stripped `mkdir` was reproduced in a container),
not an outage that was observed: on 5 October 2026 both live hosts had the old
chain, root-owned, and no `AUDIT WRITE FAILED` in the current boot. The new
directory is unreachable to `sentinel`
entirely (not just unwritable — untraversable), so it can be neither
symlink-redirected nor deleted out from under the process. The old file is
read once, at startup, to carry its last hash forward so the move itself
does not look like a gap in the chain; writes go through `os.open(...,
O_NOFOLLOW)` as a second guard against a symlink planted at the path. The
file rotates at 16 MiB (`AUDIT_ROTATE_BYTES`) so a single tail-read never has
to scan more than that to find the last complete line — `param_keys` is also
capped in count and per-key length for the same reason: an oversized final
line used to be exactly what made a resume silently start a NEW chain link
instead of continuing the old one. Records are `fsync`'d: a power loss must
not lose the record of something that already happened to the system.

**Only argument names are logged, never values.** A path might contain a token;
a "reason" string might contain anything.

### 2. It imports nothing from `sentinel/`

Stdlib plus its own two sibling modules. Nothing else.

If the main codebase is compromised — a malicious dependency, a bug in a
collector, a supply-chain problem in one of a dozen PyPI packages — that
compromise must not reach the process that can change the firewall and run
commands as root.

This means some constants are duplicated between `policy.py` and
`sentinel/constants.py`. That duplication is intentional. A test asserts the
two agree; sharing the module would mean importing from the untrusted side.

### 3. Policy is code, not configuration

Nothing in `policy.py` can be widened by editing YAML or by writing to the
database.

Compromising the database gets an attacker the security history. It does not
get them the ability to remove themselves from the never-block list, or to add
`/etc/shadow` to the readable paths, or to put `bash` in the binary allowlist.

Changing any of it is a code review.

### 4. It stays small — and this line is honest about having lost that fight

The original target was ~600 lines total. Measured at ~2900 as of the round-2
narrowing (8 September 2026), and that growth is not padding: it is a
per-binary argv grammar (`dnf`, `apt`/`apt-get`, `rpm`, `dpkg-query`, `dpkg`,
`systemctl`, `tar`, `cp`, `mv`, `mkdir`, `install`, `chmod`, `chown`, `nginx`,
`test`, `sha256sum` — every binary on `BINARY_ALLOWLIST`, no exceptions, see
`_BINARY_GRAMMAR`'s `assert set(_BINARY_GRAMMAR) == BINARY_ALLOWLIST`), the
plan-binding registry (`register_plan`/`lookup_registered_step`, see "Binding
to an approved plan" below), a root-only audit directory with migration and
rotation, and per-uid connection admission. Every one of those was added
because a narrower version of this file was shown, concretely, to let a
request that argv[0]-allowlisting alone had already approved do something no
request should be able to do. The alternative to the length was not a shorter
file — it was the same bugs still open.

Round 1's grammar (September 2026) was a denylist layered on a wider
allowlist — `docker`, `git`, `npm`/`yarn`, `pip`/`pip3`, `sed`, `wp`,
`composer`, `curl`, `mysql`/`psql` and others were on `BINARY_ALLOWLIST` with
specific dangerous flags blocked. The round-1 verifier ran it against real
binaries and got root six different ways: `git --exec-path=/var/lib/sentinel
evilcmd`, `sed -n '2e touch /tmp/pwned'`, `rpm -i evil.rpm`,
`dnf install evil.rpm`, `npm install <url>`, `pip install evil
--find-links=/var/lib/sentinel`, and several `docker` flag combinations. Round
2 removed every binary whose own scripting/plugin/hook surface cannot be
fully enumerated — see the comment above `_BINARY_GRAMMAR` in `policy.py` for
the complete list of what was dropped and why. `BINARY_ALLOWLIST` is now 17
binaries, every one with a positive grammar (allowed subcommands, allowed
flags, positional arguments validated by shape), not a denylist.

Round 2's grammar still validated a mode or an owner's *shape*, not what
either one could DO: `^[0-7]{3,4}$` accepted `4755` exactly as readily as
`0755`, and the owner regex accepted `sentinel` exactly as readily as
`www-data`. The round-2 verifier turned that into root through
`patch_step_exec` without ever leaving the grammar: `install -m 4755 /bin/sh
/tmp/rootsh`, `chmod u+s /usr/bin/bash`, `chown sentinel
/usr/local/bin/x`, `chown -R sentinel:sentinel /usr/local`. Round 3 (8
September 2026) closes the class, not the four examples: **an octal mode may
only be 3 digits, or 4 with a leading zero** (`_MODE_RE`) — a leading
4/2/6/7/1 sets setuid/setgid/sticky and is refused outright, on both `chmod`
and `install -m`/`--mode`; **a symbolic mode may not name `s` or `t`** as a
permission character (`u+s`, `g+s`, `a+s`, `+t`, `u=rws`, and comma-lists
containing any of them all refused) — only `r`, `w`, `x`, `X` remain, none of
which grant a privilege the invoking user did not already have; **`chown`
and `install -o`/`-g` refuse the executor's own unprivileged account**
(`sentinel`, by name or by its numeric uid/gid resolved via `pwd`/`grp` at
call time) as a target owner or group, on both binaries — checking one while
leaving the other open would be the same hole reopened through the sibling
call site; and **`chmod`/`chown`/`cp`/`install`/`mv` refuse a write target
that IS a system PATH directory outright, and — for the three that support
recursion (`chmod -R`, `chown -R`, `cp -r`/`-R`/`-a`) — refuse one that is an
ANCESTOR of one**, because `chmod -R 755 /usr/local` sets no setuid bit and
`chown -R www-data /usr` names no forbidden owner, yet both make a whole tree
of system binaries writable or owned by someone other than root. That last
check is deliberately its own list (`_PATH_DIRECTORIES` in `policy.py`), not
folded into `PROTECTED_PATHS`: `PROTECTED_PATHS` gates every absolute-path
argument on every binary, including ordinary deep writes a real patch
performs constantly (`install -m 644 x /etc/nginx/conf.d/x.conf`), and
`/etc` — one of the PATH-adjacent directories — has to stay writable several
levels down for exactly that reason.

What the number still means: **new code here is still a decision, not a
default.** The line count is a prompt to ask "does this belong on the other
side of the boundary" every time, not a budget that, once spent, licenses
skipping the question. If a future change pushes this well past 2500 without
a comparably concrete reason, that is the moment to ask it again — not to
raise the number quietly and move on.

Backup kinds needing credentials or container control (`mysql`, `postgres`,
`docker_volume`) are deliberately **not** implemented here. The runner performs
them through `patch_step_exec` with a validated argv. Keeping the executor
small matters more than keeping it convenient.

---

## Binding to an approved plan, and who may approve one

A grammar tells you a command is well-formed. It does not tell you the
operator approved THIS one: `dnf -y install some-plausible-package` passes
every check in `_BINARY_GRAMMAR`. The registry in `policy.py` records which
commands were approved, and `patch_step_exec` runs a REAL step only if its argv
is, byte for byte, step N of a registered plan, and SPENDS it
(`consume_registered_step`, for transactions and for everything that runs in this
sandbox alike: the same step of the same registration is refused the second time -
measured before, a `systemctl restart` registered once ran on attempts 0, 1 and 2).
A dry run is exempt - it never reaches `_run`, and `runner.py`'s own rule is
that a dry run needs no approval.

**Who may register a plan was the defect, and it is closed only against an attacker who stays inside the `sentinel` account** (the `docker` group is not closed: see below). The first
version signed `plan_hash` with a key in `/etc/sentinel/secrets.env`
(`0640 root:sentinel`): readable by the account that runs the bot, the web UI
and the detection pipeline, so anything that compromised one of them could
approve a plan of its own. The token also covered the hash alone, so a
signature for one plan registered the steps of another (reproduced twice:
`dnf -y remove openssh-server` registered under a different plan's hash, then
accepted by both lookup functions). The shapes that were weighed, and why this
one - in `policy.py`, "Plan binding, and who is allowed to approve a plan":

- **A separate approver account** does not help: the operator's tap arrives in
  the bot, so the approver would have to sign on the bot's request, and a
  compromised bot makes the same request. An approver with its own channel to
  the human is a new daemon with a new credential - a mechanism for the operator
  to approve, not one to slip in under a bug fix.
- **Plain TOTP** proves the human was present and binds nothing to what they
  approved, and the code would be typed into the chat of the very process the
  gate distrusts.
- **Chosen: an operator-held key and a transaction-bound token.** The key
  lives on the operator's workstation and in `/var/lib/sentinel-executor/
  approval.key` (`0600 root:root`, in the directory the audit chain is in and
  `sentinel` cannot traverse). The operator signs with `scripts/approve-plan.py`,
  which recomputes the digest of the commands from the request, prints them, and
  asks for the first eight digits of the digest before it prints a token. The
  token is `HMAC-SHA256(key, plan_hash | steps_digest | nonce)`.

The two operations the caller sees:

1. `plan_challenge(plan_hash, steps)` - inert. Grammar-checks the steps, needs an
   enrolled key, stores `{digest, nonce}` for `plan_hash` (a second challenge
   replaces the first, so the older nonce stops working) and returns them.
2. `register_plan(plan_hash, steps, ttl_s, approval_token)` - re-validates every
   step through `check_argv`, requires a live challenge for exactly THESE steps,
   verifies the token with the key read from disk **fresh on every call**, and
   only then registers and spends the challenge. A wrong token does not spend it.

What that gives, one property per line: a token cannot be made without the key;
it registers exactly the steps it was computed over and no others; it works once.
The audit row of `register_plan` carries the digest of what was approved (never
the token), so the chain says which commands a signature covered.

**Fails closed.** No key, a key that is not 64 lowercase hex digits, a key that
group or other can reach, a directory they can write, or a symlink at the path:
every one refuses, with the reason, and `patch_step_exec` is disabled on that host
until it is fixed. `SENTINEL_EXECUTOR_APPROVAL_KEY` in `secrets.env` is not read
by anything any more.

**What an attacker who owns the `sentinel` uid can still do**, stated and not
resolved: ask for challenges, replace a pending one, or fill the table of pending ones (a
denial of approvals, which stopping the bot already was); ask the operator to sign something (the
operator reads the commands on their own screen); do everything that is not
`patch_step_exec`; and **use the docker socket** - `sentinel` is in the `docker`
group, which is root through `/run/docker.sock`, and that can read the key file
or run the command outright. That membership is the subject of a separate
report and is deliberately neither changed nor refused here. The registry is in
memory: a restart of the executor asks for a new approval.

The runner (`sentinel/patch/runner.py`) and the checks (`checks.py`) send
`plan_hash` + `step_index` on every real call, derived from the same flattened
list the operator signed (`sentinel/patch/approval.py:flatten`), including the
preflight/health/verification checks and the rollback steps. `docs/PATCHING.md`,
"Aprobarea unui plan", is the operator's side: enrolling the key and signing.

---

## Package transactions: the transient unit

`dnf install|update|upgrade|downgrade|reinstall|remove` and `apt-get`/`apt`
`install|upgrade|dist-upgrade|remove|autoremove` cannot run inside this
process: its `ProtectSystem=strict` sandbox is read-only exactly where a package
manager writes (`patch_executions` id 9 died on `/var/log/dnf.log`; on a Debian host
`apt-get install` fails with exit 100 at `/var/cache/apt/archives/partial`, "Read-only
file system", and there is no other package manager there). Such a step is handed to PID 1 as a transient unit,
`sentinel-txn.service`, whose properties are constants in `transient_unit.py`. **Read that file's docstring before
touching it** - it is the one place this daemon hands root work to something
that is not sandboxed like it.

Three rules that were each learned from a measured failure:

- **The outcome belongs to PID 1, not to this process.** No `--pipe`, `--wait`
  or `--collect`. The unit writes to the journal and stays loaded after its main
  process ends (`RemainAfterExit=yes`), so its verdict (`Result`, `ExecMainCode`,
  `ExecMainStatus`, `InvocationID`) is readable after the fact. With `--pipe` an
  executor OOM-stop or SIGKILL made dnf exit 0 having installed nothing; with
  `--collect` a failed unit read as `success/0` because it no longer existed. An
  ABSENT unit is never an outcome.
- **The record closes in a fixed order** - end row, pending marker
  (`transaction.pending`, beside the audit chain), release of the unit - and each
  step only if the previous one happened. On startup `transient_unit.recover()`
  settles what a previous executor left: a finished unit gets an end row with
  `recovered: true`, a running one is followed to its end, a vanished one with a
  marker is recorded as `lost` (outcome unknown), an unreadable or foreign unit
  refuses every transaction with the reason.
- **The gate checks facts, and says what kind of fact.** `refusal_reasons()`
  asks the kernel (`test -r` / `test -w` as the `sentinel` uid) where the kernel
  can answer, and reads owner/mode bits where it cannot: `/`, `/var`, `/var/lib`
  are read-only in this process's namespace, so `access(W_OK)` says EROFS for
  them whatever the host permits. Both `-r` and `-w` have a positive control. An
  extended ACL it cannot evaluate is refused, not passed.

**Everything else that writes has nowhere to run, and says so up front.** A step that is not a
transaction runs in THIS sandbox, where `/`, `/etc`, `/var` and `/usr` are read-only. `mkdir`,
`tar -c/-x`, `cp`, `mv`, `install`, `chmod`, `chown`, `nginx -t`, `dnf clean|check-update|makecache`
and `apt-get update` were measured (5 October 2026, AlmaLinux 9.8 and Ubuntu 24.04) failing with
"Read-only file system" - or "succeeding": under `/tmp` in a private directory nobody else sees, and
`apt-get update` exiting 0 after warnings, having refreshed nothing. `policy.sandbox_refusal` is the one function that says so,
and the plan validator, `plan_challenge`/`register_plan`, the dry run (`refused_because`) and the
real call all ask it, so a step that can only fail is refused before anyone is asked to sign - not
run, rolled back, and reported as a failed rollback. Routing those binaries to a unit with a
writable root would widen what unconfined root may be asked to do; it is the operator's decision
and is not made here.

`transaction_outcome(plan_hash, step_index)` is the read-only question the runner asks when a step
came back "not over / cannot tell how it ended" (the executor was restarted under it): what this
process recorded in the end row for that step. It answers `recorded`, `running` or `unknown` -
never "finished" without an end row.

The gate opens on a host where an operator has enrolled an approval key (see
"Binding to an approved plan, and who may approve one") and the audit chain is
at `/var/lib/sentinel-executor`. It was closed on every host until then: the
approval key was readable by `sentinel`. What it does NOT look at is whether the
requester can reach root some other way - `sentinel` is in the `docker` group,
and no fact above asks about that, on purpose (see the gate-3 report).

**`backup_restore` is refused, always** (5 October 2026). It took a caller-chosen archive and a
caller-chosen `tar`, with no approval and an optional checksum, and ran them as root inside this
process, whose `ReadWritePaths` are Sentinel's own state. Measured in a container as `sentinel`,
with the real unit: it replaced `approval.key` (and, with `-C /` and the path as an archive
MEMBER - no argument names it, so no argv check can see it - wrote `/etc/sentinel`,
`/run/sentinel` and a restore point's `restore.sh`); and `backup_create` through a symlink in a
directory `sentinel` owns, then an extraction into a directory `sentinel` made, then `chmod`,
handed the key itself to `sentinel`. Naming `/var/lib/sentinel-executor` in `PROTECTED_PATHS`
(done, and needed for plan steps) stops only the first form. Nothing in `sentinel/` sends this
operation and a restore is `restore.sh`, run by the operator, so refusing costs nothing today;
bringing it back would have to be a step of an approved plan. Still true after this: `backup_create`
validates its source lexically, so a symlink makes it archive a protected file into a root-only
restore point - harmless while nothing can extract that, and a reason to resolve the path first
if anything ever can.

---

## Trust boundary

```
sentinel daemons   →  trusted to REQUEST. Not trusted to AUTHORISE.
executor policy    →  the authority. Refuses a trusted caller.
```

Every request is validated even when the caller has already validated it.
`sentinel/patch/validator.py` runs on the untrusted side; a patch step arriving
here is a *request*, not a *fact*.

The socket is `0660 root:sentinel`, and `SO_PEERCRED` confirms the peer uid
independently. Filesystem permissions are the first gate; the kernel's word on
who is connected is the one that cannot be widened by a `chmod`.

At startup the executor refuses to run if any of its own files are not
root-owned or are group/world-writable. If the `sentinel` user can write
`policy.py`, the privilege split is a fiction.

---

## Refusals are the healthy path

A `PolicyRefusal` means the boundary worked. It is logged at warning, audited
with `result=refused`, and **never retried** — retrying a refusal is how a
policy check becomes a policy suggestion.

Internal errors return only the exception *type* to the caller. The message
could contain a path, an argument, or something else an unprivileged process
should not learn.

---

## Connections and shutdown

`MAX_CONCURRENT` connections total, but `sentinel` may hold at most
`MAX_CONCURRENT_SENTINEL` of them (currently 8 and 6) — a flat semaphore
would let `sentinel` fill every slot, and the process most likely to need one
free is `uid 0`, the watchdog, `ping`ing this same socket to notice
`sentinel`-side daemons have stopped working. The idle timeout
(`IDLE_TIMEOUT_S`) governs only how long a connection may sit with nothing to
read; it does not bound how long a single operation may run, since the
server never touches the socket while `subprocess.run` is executing.

On `SIGTERM`, the process stops **accepting** new connections immediately but
joins every thread already handling one before it actually exits. Without
this, a patch step running for up to 3600s (see `op_patch_step_exec`) could
be killed mid-operation by a routine `systemctl stop` — as root, with no
audit row ever written for it, which is the "SIGTERM mid-step not audited"
failure this closes. The unit's `TimeoutStopSec` is set generously enough to
let that drain finish before systemd's own `SIGKILL` arrives; nothing in this
process can extend past that deadline, nor should it.

## Anti-lockout, in this process

Beyond the systemd watchdog timer, the executor runs its own panic watcher: a
thread that checks `/etc/sentinel/PANIC` every 10 seconds and flushes the
blocklist while it exists.

Two independent mechanisms for the same escape hatch, because the situation in
which you need it is the situation in which things are already broken.

---

## Adding an operation

Ask first whether it belongs here at all. Most things do not.

If it genuinely needs root:

1. Add the validation to `policy.py`. Refuse; do not sanitise.
2. Add the function to `commands.py`. It must call the policy check *first*.
3. Register it in `OPERATIONS`.
4. Add a hostile-input test in `tests/security/`. Not a happy-path test — a
   test that tries to break it.
5. Update the operations table in
   `.claude/skills/sentinel-soc/references/architecture.md`.
6. Re-read invariant 4.

---

## What to check when reviewing a change here

- Does it still import nothing from `sentinel/`?
- Is every new argument validated before use, and does validation *refuse*
  rather than clean up?
- Can any new path escape `check_path`? Traversal, symlinks, relative paths?
- Does any new command build a string that reaches a shell? (There must be no
  shell. `shell=False`, always.)
- Is the operation audited on every path, including failure?
- Could the return value leak a filesystem layout, a credential, or an internal
  path to the unprivileged caller?
- Does argv[0] being on `BINARY_ALLOWLIST` actually mean the rest of argv is
  safe? Since round 2, every allowlisted binary MUST have an entry in
  `_BINARY_GRAMMAR` — `assert set(_BINARY_GRAMMAR) == BINARY_ALLOWLIST` fails
  the moment one is added without the other. Adding a binary to the allowlist
  without a genuinely positive grammar (not a denylist — see "It stays small")
  is exactly the round-1 mistake.
- Does a new privileged operation that runs caller-influenced argv need
  binding to an approved plan the way `patch_step_exec` is, or is its input
  narrow enough (a fixed shape, like `service_action`) that a grammar alone
  is enough? See "Binding to an approved plan".
- Does a new or changed `-m`/`--mode` value accept a 4-digit octal mode with a
  non-zero leading digit, or a symbolic mode containing `s`/`t`? Either one is
  setuid/setgid/sticky, not a permission — round 3's mistake, see "It stays
  small" — and belongs nowhere in this file's accepted shapes.
- Does a new or changed owner/group value get checked against the executor's
  own unprivileged account (`_refuse_forbidden_owner` — name AND numeric
  uid/gid), on EVERY call site that can assign ownership, not just `chown`?
  `install -o`/`-g` do the same thing chown does and were the round-3
  verifier's second finding on the first pass.
- Does a new write destination for `chmod`/`chown`/`cp`/`install`/`mv` get
  checked against `_PATH_DIRECTORIES`, and — if the binary supports
  recursion — against being an ANCESTOR of one? A mode/owner check alone does
  not stop `chmod -R 755 /usr/local`, which sets no setuid bit and names no
  forbidden owner.
- Is every path this file writes to still owned and reachable only by root —
  would a regression on a parent directory's permissions reproduce the
  `/var/lib/sentinel/executor` bug this file's audit-directory comment
  describes?
