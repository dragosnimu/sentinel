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

Three files, roughly 400 lines of substance:

| File | Role |
|---|---|
| `policy.py` | The decisions. Never-block networks, protected paths, binary allowlist, rate caps |
| `commands.py` | The operations. Twelve of them, each validating through `policy` first |
| `sentinel_executor.py` | The socket server, peer-credential check, audit chain, panic watcher |

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
tail of `/var/lib/sentinel/executor/audit.jsonl`. That directory is owned by
root, not the `sentinel` user: the executor's capability set omits
`CAP_DAC_OVERRIDE`, so it can only write where it owns the path. Records are
`fsync`'d: a power loss must not
lose the record of something that already happened to the system.

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

### 4. It stays small

If these three files exceed ~600 lines total, something has been added that
belongs on the other side of the boundary.

Backup kinds needing credentials or container control (`mysql`, `postgres`,
`docker_volume`) are deliberately **not** implemented here. The runner performs
them through `patch_step_exec` with a validated argv. Keeping the executor
small matters more than keeping it convenient.

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
- Is the total still under ~600 lines?
