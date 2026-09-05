#!/usr/bin/env bash
#
# Deploy Sentinel to the server over SSH. Run from Git Bash or WSL.
#
#   ./scripts/deploy.sh --host 203.0.113.10 --domain sentinel.exemplu.ro
#
#   --key K        private key. Defaults to ~/.ssh/sentinel_deploy, which is the
#                  key authorized on the sentinel-deploy account --user also
#                  defaults to. The two belong together: a key that opens the
#                  operator's own login and a --user of sentinel-deploy is
#                  "Permission denied (publickey)", and the older key some
#                  documentation named is authorized on the human account only —
#                  which is the account whose 405 777 terminal-less commands per
#                  run this default exists to stop writing.
#
#   --user U       SSH account to deploy as. Defaults to sentinel-deploy, the
#                  account deploy/install.sh creates with NOPASSWD sudo. It is
#                  also the account named in history.skip_command_accounts, so
#                  deploying as anything else puts a quarter of a million
#                  terminal-less commands per run into session_commands under a
#                  name the filter does not know. Override only if you have
#                  installed with a different DEPLOY_ACCOUNT — and change the
#                  config to match.
#
#   --nginx-mode M dedicated (own listener on --web-port) or shared (a vhost on
#                  the nginx already serving 80/443). See docs/DEPLOYMENT.md §2.
#   --web-port N   dashboard HTTPS port in dedicated mode (default 8443)
#   --cert-mode M  auto|webroot|dns|selfsigned|none — see docs/DEPLOYMENT.md §2.1
#   --db-port N    pin PostgreSQL's own port instead of letting step 22 read
#                  whatever the cluster actually ended up on. See
#                  deploy/install.sh's own --db-port for why 5432 is never
#                  assumed. Forwarded to install.sh as-is; unset means no
#                  override, same as running install.sh without the flag.
#   --dry-run      run preflight only; change nothing
#   --rollback     undo a previous deployment
#   --from-step N  resume an interrupted install. It skips the steps BELOW N;
#                  at or above N a completion marker still wins, so it does NOT
#                  re-run anything already done
#   --force-step L re-run the listed steps even though they are marked done.
#                  One number, or a comma-separated list: --force-step 22,27
#                  re-runs both in the SAME pass, which is what rotating a
#                  secret requires — see docs/OPERARE.md §11
#   --secrets P    path to the secrets file. Omitted, this is exactly today's
#                  behaviour: secrets/.env.local, including the fall-through
#                  to scripts/secrets-init.sh when that default is missing.
#                  Given and missing, it is a hard stop instead — no fresh
#                  secrets are generated under a name the operator chose on
#                  purpose. See secrets/.gitkeep for the incident this exists
#                  to close: a mixed file installed one host's bot token next
#                  to another's database password, and a stale fallback would
#                  have rotated SENTINEL_BEACON_SECRET, silencing the one
#                  component whose job is to notice Sentinel going quiet.
#   --allow-rotation
#                  explicit consent for the secret rotation compare_secrets_
#                  with_host below is about to warn about. Applies to every
#                  key that would change. --yes does NOT imply this — see the
#                  note on --yes.
#   --allow-rotation-keys L
#                  same consent as --allow-rotation, but only for the
#                  comma-separated key names in L. A bare --allow-rotation
#                  cannot take a list value of its own — it cannot tell "no
#                  value" from "the next flag" apart — so a per-key rotation
#                  uses this separate flag instead.
#   --purge        with --rollback, also drop the database
#
# This script is deliberately thin. All the real logic lives in
# deploy/install.sh on the server, so there is one implementation to test and
# deploy.ps1 can be its exact behavioural twin.
#
# Secrets go over the SSH channel on stdin. Never argv (where `ps` on the
# server would show them), never a file in the tarball, never an environment
# variable that lingers in a shell.
#
# Before any of that, the local file is compared against /etc/sentinel/
# secrets.env already on the host — by key name and a SHA-256 prefix of the
# value, never the value itself. This runs on a --dry-run too, report-only:
# a rehearsal is exactly where "these six keys would change value" belongs,
# and it tolerates a missing local file so a first install can still
# rehearse. A key that would change is not automatically wrong (rotation is a
# real, documented operation — docs/OPERARE.md §11), so on a real run it is a
# warning and a confirmation — interactive by default, or --allow-rotation
# for a scripted one. --yes answers the OTHER prompts this script already
# asked before this change existed; it does not, by itself, wave a rotation
# through — see compare_secrets_with_host below for why.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_FILE="${REPO_ROOT}/secrets/.env.local"

HOST=""; KEY=""; DOMAIN=""; EMAIL=""; ADMIN_IP=""; DB_PORT=""; SECRETS_ARG=""
# Rotation consent, separate from ASSUME_YES on purpose — see the --yes note
# in the header comment and compare_secrets_with_host below.
ALLOW_ROTATION_ALL=0
ALLOW_ROTATION_KEYS=""
# The account this deploys AS, and the reason it has a default at all.
#
# Until 25 August 2026 this was empty and --user was required, so every
# run named the operator's own login. auid survives sudo — it is the
# LOGIN uid, not the effective one — so all 405 777 terminal-less commands
# of a deploy landed in session_commands under the human account, which is
# not in history.skip_command_accounts and must not be: the operator's
# remote diagnostics run under the same name and are worth keeping.
#
# Hardcoded rather than read from the environment: $USER is set in every
# shell, so a default of "${USER:-sentinel-deploy}" would silently be the
# old behaviour on the exact machine it is meant to fix.
DEPLOY_USER_DEFAULT="sentinel-deploy"
USER="$DEPLOY_USER_DEFAULT"
# The key that opens THAT account, because the two are one decision.
#
# The account default above shipped on its own, and on its own it is a way to
# fail: sentinel-deploy authorizes ~/.ssh/sentinel_deploy and nothing else, so a
# run that keeps the new --user and the old key gets "Permission denied
# (publickey)" before the first step. The operator's remaining move would be to
# put --user back, and then the filter is inert again — which is how the account
# default came to be worth nothing.
#
# Only a DEFAULT. An explicit --key is used as given and must exist; a missing
# default is a warning and ssh chooses an identity as it did before, because an
# agent, an IdentityFile in ~/.ssh/config or a differently named key are all
# legitimate here and this script cannot tell which. "I do not know" is not "you
# are wrong".
DEPLOY_KEY_DEFAULT="${HOME}/.ssh/sentinel_deploy"
DRY_RUN=0; ROLLBACK=0; PURGE=0; FROM_STEP=""; FORCE_STEP=""; ASSUME_YES=0
SSH_PORT=22
# The dashboard's public HTTPS port. Not 443 — this host serves something else
# there. Must also be open in the provider's firewall.
WEB_PORT=8443
CERT_MODE=auto
# dedicated = own listener on WEB_PORT; shared = a vhost on the existing nginx.
NGINX_MODE=dedicated

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

# The whole header comment, however long it grows. A hardcoded line range was
# here and it silently truncated --help the moment a flag was documented above
# the end of it — the reader then believes the missing flags do not exist.
usage() { sed -n '2,${/^#/!q;p;}' "$0"; exit 0; }

# --force-step is passed through to install.sh, which stays the authority on
# what the numbers mean. Two things still have to happen here:
#
#   * the value lands in an UNQUOTED expansion of INSTALL_ARGS inside the remote
#     command string, so "22, 27" would arrive at the installer as two separate
#     arguments and it would die on the second. The spaces are removed.
#   * "22 27" — a comma-less list — must be REFUSED, not squeezed into 2227.
#     That is why the shape is checked before any whitespace is stripped: a
#     silently mangled step number is exactly the class of bug this flag exists
#     to stop.
normalize_step_list() {
    local raw="$1" flag="$2"
    if [[ ! "$raw" =~ ^[[:space:]]*[0-9]+([[:space:]]*,[[:space:]]*[0-9]+)*[[:space:]]*$ ]]; then
        die "${flag}: '${raw}' is not a step number or a comma-separated list of them (e.g. 22 or 22,27)"
    fi
    printf '%s' "${raw//[[:space:]]/}"
}

# Same shape check as normalize_step_list, for --allow-rotation-keys: refuse a
# malformed list rather than silently matching nothing (which would look
# identical to "no key allowed" and refuse a rotation the operator thought
# they had just authorised).
normalize_key_list() {
    local raw="$1" flag="$2"
    if [[ ! "$raw" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*([[:space:]]*,[[:space:]]*[A-Za-z_][A-Za-z0-9_]*)*[[:space:]]*$ ]]; then
        die "${flag}: '${raw}' is not a KEY_NAME or a comma-separated list of them (e.g. SENTINEL_DB_PASSWORD or SENTINEL_DB_PASSWORD,TELEGRAM_BOT_TOKEN)"
    fi
    printf '%s' "${raw//[[:space:]]/}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)      HOST="${2:-}"; shift 2 ;;
        --user)      USER="${2:-}"; shift 2 ;;
        --key)       KEY="${2:-}"; shift 2 ;;
        --port)      SSH_PORT="${2:-}"; shift 2 ;;
        --domain)    DOMAIN="${2:-}"; shift 2 ;;
        --email)     EMAIL="${2:-}"; shift 2 ;;
        --web-port)   WEB_PORT="${2:-}"; shift 2 ;;
        --nginx-mode) NGINX_MODE="${2:-}"; shift 2 ;;
        --admin-ip)  ADMIN_IP="${2:-}"; shift 2 ;;
        --cert-mode) CERT_MODE="${2:-}"; shift 2 ;;
        --db-port)   DB_PORT="${2:-}"; shift 2 ;;
        --secrets)   SECRETS_ARG="${2:-}"; shift 2 ;;
        --allow-rotation) ALLOW_ROTATION_ALL=1; shift ;;
        --allow-rotation-keys) ALLOW_ROTATION_KEYS="${2:-}"; shift 2 ;;
        --from-step) FROM_STEP="${2:-}"; shift 2 ;;
        # install.sh has always had this; deploy.sh could not pass it
        # through, so the only way to re-run one step was to ssh in and run
        # the installed copy — which fails, because the source tree it needs
        # only exists inside the transferred tarball.
        #
        # It takes a list now: some steps are one operation and forcing half of
        # one leaves the host inconsistent. See normalize_step_list above.
        --force-step) FORCE_STEP="${2:-}"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        --rollback)  ROLLBACK=1; shift ;;
        --purge)     PURGE=1; shift ;;
        --yes|-y)    ASSUME_YES=1; shift ;;
        --help|-h)   usage ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$HOST" ]] || die "--host is required"
# --user may be given, but it may not be given EMPTY: `--user ""` would
# otherwise deploy as whatever the ssh client falls back to, which is the
# local username — the failure this default exists to remove.
[[ -n "$USER" ]] || die "--user was given an empty value"

# An explicit --secrets replaces the default path outright. Left as a check on
# $SECRETS_ARG rather than folded into a second SECRETS_FILE assignment,
# because what matters further down is not just WHICH path is in use but
# whether the operator NAMED it — that is what decides whether a missing file
# dies here or falls through to secrets-init.sh.
[[ -n "$SECRETS_ARG" ]] && SECRETS_FILE="$SECRETS_ARG"

# Refused here, before a tarball is built or an SSH session opened. The
# installer checks it again on the server — it is the authority — but a typo
# should cost a second, not a round trip.
if [[ -n "$FORCE_STEP" ]]; then
    FORCE_STEP="$(normalize_step_list "$FORCE_STEP" --force-step)" || exit 1
fi
if [[ -n "$ALLOW_ROTATION_KEYS" ]]; then
    ALLOW_ROTATION_KEYS="$(normalize_key_list "$ALLOW_ROTATION_KEYS" --allow-rotation-keys)" || exit 1
fi

# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------
SSH_OPTS=(-o BatchMode=no -o StrictHostKeyChecking=accept-new
          -o ConnectTimeout=15 -o ServerAliveInterval=30)
# scp spells the port flag -P, not -p. Kept as separate arrays rather than
# substituting into one, which silently mangles any option containing "-p".
SCP_OPTS=("${SSH_OPTS[@]}")
SSH_OPTS+=(-p "$SSH_PORT")
SCP_OPTS+=(-P "$SSH_PORT")

# No --key: fall back to the key that belongs to the account default, but only
# if it is really there. Substituting a path that does not exist would turn
# "ssh, pick an identity" into a hard error on machines that were working.
if [[ -z "$KEY" && -f "$DEPLOY_KEY_DEFAULT" ]]; then
    KEY="$DEPLOY_KEY_DEFAULT"
    info "using default key ${KEY} (pairs with --user ${DEPLOY_USER_DEFAULT})"
elif [[ -z "$KEY" ]]; then
    warn "no --key and ${DEPLOY_KEY_DEFAULT} does not exist; ssh will choose an identity."
    warn "If it picks the one for your own login, ${USER}@${HOST} refuses it with"
    warn "'Permission denied (publickey)' — that account authorizes sentinel_deploy."
fi

if [[ -n "$KEY" ]]; then
    KEY="${KEY/#\~/$HOME}"
    [[ -f "$KEY" ]] || die "SSH key not found: ${KEY}"
    # Git Bash on Windows reports permissions that OpenSSH may reject. Warn
    # rather than fail: on a native filesystem this is a real problem, under
    # Git Bash it is usually an artifact.
    perms="$(stat -c '%a' "$KEY" 2>/dev/null || echo '')"
    if [[ -n "$perms" && "$perms" != "600" && "$perms" != "400" ]]; then
        warn "key ${KEY} has mode ${perms}; OpenSSH may refuse it. chmod 600 if it does."
    fi
    SSH_OPTS+=(-i "$KEY")
    SCP_OPTS+=(-i "$KEY")
fi

# One authentication, many commands. Also keeps the operator from being
# prompted for a passphrase at each step.
#
# It is an optimisation, not a requirement, so it is PROBED rather than assumed.
# Multiplexing needs a unix socket, and it does not work under Git Bash on
# Windows (the mux handshake dies with "read from master failed") or where the
# socket directory is mounted noexec. Assuming it works turns a cosmetic
# limitation into "cannot reach the host", which is both wrong and the hardest
# possible message to debug — it points at the network, and the network is fine.
CTRL_PATH="${TMPDIR:-/tmp}/sentinel-deploy-%r@%h:%p"
CTRL_OPTS=(-o "ControlMaster=auto" -o "ControlPath=${CTRL_PATH}" -o "ControlPersist=10m")
MUX="no"

# A socket left behind by an interrupted run is not reusable, and ssh does not
# say so plainly: it prints "ControlSocket already exists, disabling
# multiplexing" on EVERY later connection and carries on unmultiplexed. The
# probe below then sees a command that worked and concludes multiplexing is
# fine. Clear the concrete path first so the probe measures this run.
rm -f "${TMPDIR:-/tmp}/sentinel-deploy-${USER}@${HOST}:${SSH_PORT}" 2>/dev/null || true

# The probe runs a real command through the master and reads what ssh SAYS about
# it, not just the exit code. Two ways this goes wrong otherwise:
#
#   * `ssh -O check` reports the master alive on Git Bash, and then every
#     session over it dies with "read from master failed" — "is it alive" is a
#     different question from "can I use it";
#   * when multiplexing is refused, ssh warns and silently falls back to a
#     direct connection, so the command SUCCEEDS. Exit code alone says yes.
if ssh -M -N -f -o ConnectTimeout=15 "${SSH_OPTS[@]}" "${CTRL_OPTS[@]}" \
       "${USER}@${HOST}" 2>/dev/null &&
   PROBE_OUT="$(ssh "${SSH_OPTS[@]}" "${CTRL_OPTS[@]}" "${USER}@${HOST}" true 2>&1)" &&
   [[ "$PROBE_OUT" != *"disabling multiplexing"* ]] &&
   [[ "$PROBE_OUT" != *"read from master failed"* ]]
then
    MUX="yes"
    SSH_OPTS+=("${CTRL_OPTS[@]}")
    SCP_OPTS+=("${CTRL_OPTS[@]}")
else
    # Tear the master down AND unlink the socket. `-O exit` fails against a
    # master that is already half-dead, which is exactly the case that got us
    # here, and the leftover file poisons every subsequent run.
    ssh -O exit "${SSH_OPTS[@]}" "${CTRL_OPTS[@]}" "${USER}@${HOST}" >/dev/null 2>&1 || true
    rm -f "${TMPDIR:-/tmp}/sentinel-deploy-${USER}@${HOST}:${SSH_PORT}" 2>/dev/null || true
    warn "SSH multiplexing unavailable here (normal on Windows/Git Bash)."
    warn "Continuing without it — you may be asked for the key more than once."
fi

ssh_run()  { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"; }
# NOTE: this elevates ONE command. `ssh_sudo "a && b"` runs only `a` as root.
# Call it once per command, or wrap the chain in `sh -c` yourself.
ssh_sudo() { ssh -t "${SSH_OPTS[@]}" "${USER}@${HOST}" "sudo -p 'sudo password: ' $*"; }

# Shared by the secrets comparison below and by the install step further down:
# both need sudo to answer without a prompt, because both feed one end of the
# SSH connection with something that is not a human typing a password —
# structured output here, the secrets file on stdin there. Idempotent: once
# credentials are cached, this is a single `sudo -n true` and nothing more, so
# calling it twice in one run costs one cheap round trip, not a second prompt.
prime_sudo() {
    if ! ssh_run "sudo -n true" 2>/dev/null; then
        info "caching sudo credentials (you will be asked once)"
        ssh -t "${SSH_OPTS[@]}" "${USER}@${HOST}" "sudo -v" \
            || die "sudo is not usable non-interactively. Either add a NOPASSWD rule for \
${USER}, or run sudo -v in your second SSH session and retry within the timeout."
    fi
}

# Runs ON THE HOST, under `sudo -n bash` fed by a pipe — never interpolated
# into a quoted command string, and never given a value to echo. It reads
# /etc/sentinel/secrets.env itself, hashes each value with sha256sum ON THAT
# MACHINE, and prints only KEY and a hash. The value that produced the hash
# never leaves the process that read it.
#
# Written with single quotes nowhere in it on purpose: it travels to the host
# base64-encoded, so nothing about its own quoting has to survive being
# embedded inside ssh's command string, and there is no escaping to get wrong.
REMOTE_SECRETS_SCRIPT="$(cat <<'REMOTE_SCRIPT'
F=/etc/sentinel/secrets.env
if [ ! -e "$F" ]; then
    printf 'ABSENT'
    exit 0
fi
CR=$(printf '\r')
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$CR}"
    stripped="${line#"${line%%[![:space:]]*}"}"
    case "$stripped" in
        ''|'#'*) continue ;;
    esac
    case "$stripped" in
        [A-Za-z_]*=*) ;;
        *) continue ;;
    esac
    key="${stripped%%=*}"
    value="${stripped#*=}"
    # Same single trailing-then-leading double-quote strip as the LOCAL side
    # of this comparison (compare_secrets_with_host / Compare-SecretsWithHost)
    # and install.sh's stdin reader (read_stdin_secrets). Skipped, a value
    # install.sh once wrote with quotes and now carries forward VERBATIM
    # (existing_secret, deploy/install.sh, never strips) would hash
    # differently here than the same value typed unquoted into
    # secrets/.env.local — a secret that never actually changed would report
    # as "changed" forever.
    value="${value%\"}"; value="${value#\"}"
    hash="$(printf '%s' "$value" | sha256sum | cut -c1-16)"
    printf '%s %s\n' "$key" "$hash"
done < "$F"
REMOTE_SCRIPT
)"
REMOTE_SECRETS_SCRIPT_B64="$(printf '%s' "$REMOTE_SECRETS_SCRIPT" | base64 | tr -d '\n')"

# The half that matters: refuse to rotate a secret without saying so. Compares
# by KEY NAME plus the hash computed above — never a value, on either side —
# and reports three groups: what would CHANGE (a real rotation risk), what
# exists only locally (about to be added), what exists only on the host
# (untouched by this run; step 27 on the server carries forward any key not
# supplied on stdin).
#
# A host with no secrets.env yet is a first install: nothing to compare, and
# nothing here says otherwise.
#
# Consent to actually SEND a rotation is decided by ALLOW_ROTATION_ALL /
# ALLOW_ROTATION_KEYS, not by ASSUME_YES — see the --yes note in the header
# comment. On a --dry-run this function only reports; it never gates,
# because a dry run sends nothing to gate.
rotation_allowed() {
    local k="$1" list_k
    (( ALLOW_ROTATION_ALL )) && return 0
    [[ -n "$ALLOW_ROTATION_KEYS" ]] || return 1
    local IFS=,
    for list_k in $ALLOW_ROTATION_KEYS; do
        [[ "$list_k" == "$k" ]] && return 0
    done
    return 1
}

compare_secrets_with_host() {
    local -A local_hash=() remote_hash=()
    local -a changed=() local_only=() host_only=()
    local raw_line stripped k v remote_out remote_rc line key hash answer
    local ssh_err_file remote_err

    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        raw_line="${raw_line%$'\r'}"
        stripped="${raw_line#"${raw_line%%[![:space:]]*}"}"
        [[ -z "$stripped" || "$stripped" == \#* ]] && continue
        [[ "$stripped" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
        # The same single trailing-then-leading quote strip install.sh's own
        # stdin reader applies (deploy/install.sh, read_stdin_secrets). Skipped,
        # a hand-quoted value in secrets/.env.local would hash differently here
        # than the unquoted value the installer actually writes to the host —
        # and a perfectly ordinary rotation would report as "changed" forever.
        v="${v%\"}"; v="${v#\"}"
        local_hash["$k"]="$(printf '%s' "$v" | sha256sum | cut -c1-16)"
    done < "$SECRETS_FILE"

    # ssh's OWN stderr (this OpenSSH build prints a three-line PQ-key-exchange
    # warning on every connection to this host) goes to a FILE, never merged
    # with 2>&1 into $remote_out — merged, it lands inside the text this
    # function parses as KEY HASH lines and produces a bogus key, silently
    # losing ABSENT detection.
    #
    # The assignment is the CONDITION of this if, not a bare statement: under
    # this script's `set -euo pipefail`, a bare `remote_out="$(...)"` that
    # fails exits the shell right there, before `remote_rc=$?` is ever
    # reached — sudo -n failing on the host would abort with no message at
    # all. As the test of an if it is exempt from -e, so remote_rc below is
    # real and reachable.
    ssh_err_file="$(mktemp)"
    if remote_out="$(ssh_run "printf '%s' '${REMOTE_SECRETS_SCRIPT_B64}' | base64 -d | sudo -n bash" 2>"$ssh_err_file")"; then
        remote_rc=0
    else
        remote_rc=$?
    fi
    remote_err="$(cat "$ssh_err_file" 2>/dev/null)"
    rm -f "$ssh_err_file"
    if (( remote_rc != 0 )); then
        die "could not read /etc/sentinel/secrets.env on ${HOST} to compare secrets \
(sudo -n failed: ${remote_err}). This refuses rather than deploying unchecked — cache \
sudo credentials (sudo -v in your second SSH session) and retry."
    fi

    if [[ "$remote_out" == "ABSENT" ]]; then
        info "${HOST} has no /etc/sentinel/secrets.env yet — first install, nothing to compare."
        return 0
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        key="${line%% *}"; hash="${line#* }"
        remote_hash["$key"]="$hash"
    done <<< "$remote_out"

    for k in "${!local_hash[@]}"; do
        if [[ -v "remote_hash[$k]" ]]; then
            [[ "${local_hash[$k]}" != "${remote_hash[$k]}" ]] && changed+=("$k")
        else
            local_only+=("$k")
        fi
    done
    for k in "${!remote_hash[@]}"; do
        [[ -v "local_hash[$k]" ]] || host_only+=("$k")
    done
    (( ${#changed[@]} ))     && mapfile -t changed     < <(printf '%s\n' "${changed[@]}"     | sort)
    (( ${#local_only[@]} ))  && mapfile -t local_only  < <(printf '%s\n' "${local_only[@]}"  | sort)
    (( ${#host_only[@]} ))   && mapfile -t host_only   < <(printf '%s\n' "${host_only[@]}"   | sort)

    (( ${#local_only[@]} )) && info "only in the local file (will be added): ${local_only[*]}"
    (( ${#host_only[@]} )) && info "only on the host (not sent, left untouched): ${host_only[*]}"

    if (( ${#changed[@]} == 0 )); then
        ok "secrets: no existing key would change value"
        return 0
    fi

    warn "these EXISTING keys on the host would get a NEW value: ${changed[*]}"
    for k in "${changed[@]}"; do
        if [[ "$k" == "SENTINEL_BEACON_SECRET" ]]; then
            warn "SENTINEL_BEACON_SECRET is the key shared with the external watcher — a \
new value here alone means the watcher rejects every signal as a bad signature, which \
looks exactly like a host that has gone silent. Only rotate it together with the \
watcher's copy (docs/OPERARE.md §11)."
        fi
    done

    # A dry run reports and stops here — it sends nothing, so there is
    # nothing left to gate. This is the rehearsal the incident this check
    # closes never got: --dry-run used to skip this whole comparison.
    if (( DRY_RUN )); then
        warn "dry run: reporting only. A real run either asks interactively or needs \
--allow-rotation for these keys — see docs/OPERARE.md §11."
        return 0
    fi

    warn "if this is a rotation you meant to run (docs/OPERARE.md §11), continue. If you \
did not expect any of these to change, stop — the local file may be the wrong one."

    local -a unallowed=()
    for k in "${changed[@]}"; do
        rotation_allowed "$k" || unallowed+=("$k")
    done

    if (( ${#unallowed[@]} == 0 )); then
        ok "secrets: rotation of ${changed[*]} explicitly allowed by --allow-rotation"
        return 0
    fi

    # --yes does NOT reach here as consent. It answers the OTHER prompts this
    # script asks (the "did you open a second session" one, the missing-keys
    # one); a secret rotation needs its own explicit flag, because "answer
    # every prompt so the run doesn't stop" was exactly how a stale fallback
    # file would have rotated SENTINEL_BEACON_SECRET without anyone reading a
    # word of this warning.
    if (( ASSUME_YES )); then
        die "--yes does not authorise a secret rotation by itself: ${unallowed[*]} would \
change and --allow-rotation was not given for them. Re-run with --allow-rotation (or \
--allow-rotation-keys ${unallowed[*]// /,}) once you have confirmed this is the rotation \
you meant, or without --yes to be asked interactively."
    fi

    read -r -p "Continui rotirea? [da/NU] " answer
    [[ "$answer" == "da" ]] || die "aborted — nothing was sent to the host"
}

cleanup() {
    [[ "$MUX" == "yes" ]] &&
        ssh -O exit "${SSH_OPTS[@]}" "${USER}@${HOST}" 2>/dev/null || true
    [[ -n "${TARBALL:-}" && -f "${TARBALL:-}" ]] && rm -f "$TARBALL"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
info "connecting to ${USER}@${HOST}:${SSH_PORT}"
ssh_run "echo connected" >/dev/null || die "cannot reach ${HOST}. Check the address, \
the key, and whether your address is allowed by the provider firewall."
ok "SSH working"

# The address we connect FROM, as the server sees it. This is what must be in
# the nftables allowlist before any drop rule exists — lose it and the first
# auto-block could shut you out. It has to be read here, over plain SSH, because
# preflight and install run under sudo, which scrubs SSH_CLIENT from the
# environment. --admin-ip overrides for the case where you administer from a
# different address than you deploy from.
if [[ -z "${ADMIN_IP:-}" ]]; then
    ADMIN_IP="$(ssh_run 'echo $SSH_CONNECTION' 2>/dev/null | awk '{print $1}')"
fi
if [[ -n "$ADMIN_IP" ]]; then
    ok "admin address (for the allowlist): ${ADMIN_IP}"
else
    warn "could not determine your address; the allowlist may end up empty. \
Pass --admin-ip <your-ip> explicitly."
fi

# ---------------------------------------------------------------------------
# Rollback path — no packaging, no secrets
# ---------------------------------------------------------------------------
if (( ROLLBACK )); then
    warn "This will stop Sentinel, delete its nftables table (removing every block) \
and restore the pre-deploy configuration."
    (( PURGE )) && warn "--purge: the database WILL be dropped — incidents, blocklist \
history, vulnerability findings and the patch audit trail are all in it."
    if (( ! ASSUME_YES )); then
        read -r -p "Continui? [da/NU] " answer
        [[ "$answer" == "da" ]] || die "aborted"
    fi
    ssh_sudo "/opt/sentinel/deploy/rollback.sh $( ((PURGE)) && echo --purge ) --yes" \
        || die "rollback reported errors — read the output above before retrying"
    ok "rollback complete"
    exit 0
fi

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
# The --secrets existence check runs whether or not this is a dry run: a
# misspelled path must fail preflight, not "pass" it and only die on the real
# run that follows — the exact gap a --dry-run rehearsal exists to close.
if [[ -n "$SECRETS_ARG" && ! -f "$SECRETS_FILE" ]]; then
    # Named explicitly: the operator meant THIS file. Generating a fresh one
    # under its name is exactly the failure mode this flag exists to close —
    # see the --secrets doc at the top of this file.
    die "--secrets ${SECRETS_FILE}: file not found. Not running \
secrets-init.sh for it — a name you chose does not get a freshly generated \
replacement, that would silently rotate whatever it invented."
fi

if [[ ! -f "$SECRETS_FILE" ]]; then
    if (( DRY_RUN )); then
        # No name was given (checked above) — the ordinary default-missing
        # case. Tolerated here so a first install can still rehearse: there
        # is nothing to compare yet, and secrets-init.sh has not run to
        # invent something a dry run must not act as though it had.
        warn "no ${SECRETS_FILE} — dry run continues without a secrets comparison; a real \
run will need it (scripts/secrets-init.sh) or the path you pass with --secrets."
    else
        warn "no ${SECRETS_FILE}"
        info "running scripts/secrets-init.sh"
        "${REPO_ROOT}/scripts/secrets-init.sh" || die "secret initialisation failed"
    fi
fi

if [[ -f "$SECRETS_FILE" ]]; then
    missing=()
    for key in SENTINEL_DB_PASSWORD ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID; do
        grep -qE "^${key}=.+" "$SECRETS_FILE" || missing+=("$key")
    done
    if (( ${#missing[@]} > 0 )); then
        warn "missing or empty in ${SECRETS_FILE}: ${missing[*]}"
        warn "Sentinel will install but the corresponding feature will be inert."
        if (( ! DRY_RUN )) && (( ! ASSUME_YES )); then
            read -r -p "Continui oricum? [da/NU] " answer
            [[ "$answer" == "da" ]] || die "aborted; run scripts/secrets-init.sh"
        fi
    fi

    # Runs on a dry run too — report-only, see compare_secrets_with_host.
    prime_sudo
    compare_secrets_with_host
fi

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------
STAMP="$(date -u +%Y%m%d-%H%M%S)"
REMOTE_DIR="/tmp/sentinel-deploy-${STAMP}"
TARBALL="${TMPDIR:-/tmp}/sentinel-${STAMP}.tar.gz"

# Source, vendored dashboard assets and the GeoIP-less deploy tree compress to
# roughly 1 MB. Twenty is not a budget, it is a tripwire: nothing legitimate
# grows twentyfold between releases.
PACKAGE_MAX_KB=20480

info "packaging the repository"

# secrets/ is excluded from the tarball. Secrets travel on stdin only — a
# tarball lands in /tmp on the server and lingers there.
#
# watcher/ is excluded on purpose, not to save bytes. It is the external
# witness, and its whole value is running somewhere the monitored host cannot
# reach. Shipping a copy here would put the thing that reports Sentinel's death
# on the machine whose death it reports.
#
# aggregator/ is excluded for the same reason and one more. It runs on the same
# external hosting as the witness, and it is the archive of what left this
# machine — "what left cannot be deleted from here" stops being true the moment
# a copy of the archive's schema and credentials-handling code sits on the host
# that is being archived. Nothing under deploy/ or sentinel/ reads it.
#
# scratchpad/ is where verification harnesses keep their working copies —
# `.bak` snapshots of install.sh, config.py, signing.py, beacon.py. Three
# reasons it must not ship, and the size ceiling below sees none of them: it is
# source that nothing on the host runs, it is a second copy of files whose
# single-copy-ness is the point, and a stale harness left there can be executed
# against a newer tree. That last one is not hypothetical — it clobbered this
# working tree twice during E2.2.
#
# .claude/worktrees/ is excluded; the REST of .claude/ must ship, and that
# distinction is load-bearing. `deploy/install.sh` step 25 does
# `cp -r "${SRC_ROOT}/.claude/skills"` and the same for `.claude/agents`, where
# SRC_ROOT is this archive unpacked on the host. An exclude on all of .claude/
# deletes the source of that cp; with `set -euo pipefail` the installer dies at
# step 25. Making the cp tolerant instead would be worse: the headless CLI on
# the server would lose the skill and the six agent definitions without a word,
# so patch-plan generation, /ask and incident dossiers stop existing and
# nothing reports a fault.
#
# worktrees/ is the part that actually grows — 228 KB of skills and 52 KB of
# agents against 6.6 MB of worktrees, under a 20 MB ceiling. It is a second
# checkout this repository leaves behind between agent sessions; nothing on the
# host reads it, and it is the only thing under .claude/ that would push the
# archive past PACKAGE_MAX_KB.
#
# The list is an intention. `tests/security/test_package_contents.py` builds a
# real archive with a file planted under scratchpad/ and asserts `tar -tzf`
# does not list it, because the archive is the effect.
tar --exclude='./secrets' \
    --exclude='./.git' \
    --exclude='./.claude/worktrees' \
    --exclude='./tests' \
    --exclude='./docs' \
    --exclude='./watcher' \
    --exclude='./aggregator' \
    --exclude='./scratchpad' \
    --exclude='./dist' \
    --exclude='node_modules' \
    --exclude='.next' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='.pytest_cache' \
    --exclude='.mypy_cache' \
    --exclude='.ruff_cache' \
    -czf "$TARBALL" -C "$REPO_ROOT" .

size_kb=$(( $(stat -c%s "$TARBALL" 2>/dev/null || stat -f%z "$TARBALL") / 1024 ))
ok "package built (${size_kb} KB)"

# The exclude list above was written before watcher/ existed, and for a while
# every deploy quietly compressed 400 MB of node_modules. It did not fail; it
# just appeared to hang. A ceiling turns the next such omission into one clear
# line instead of a wait long enough to reach for Ctrl+C.
if (( size_kb > PACKAGE_MAX_KB )); then
    die "package is ${size_kb} KB, over the ${PACKAGE_MAX_KB} KB ceiling.
    Something large is being shipped that should not be. Inspect with:
    tar -tzf ${TARBALL} | head -50
    then add it to the exclude list above."
fi

# A CRLF in a .sh or .service file fails on Linux as `bad interpreter:
# /bin/bash^M`, which is a confusing twenty minutes if you have not seen it.
# A CRLF in deploy/audit/sentinel.rules is worse, because it is quiet: the key
# becomes `sentinel_ssh^M`, auditd accepts the rule, and the collector matches
# nothing for as long as nobody notices.
#
# The check is on the PACKAGE, run after tar and before the transfer, so it
# reads the exact bytes that are about to leave this machine rather than a
# second guess at what tar included. .gitattributes normalises on commit; this
# is what catches a file a tool rewrote between commit and deploy. The criterion
# and the exemptions are argued in the script itself.
#
# Any non-zero exit stops the deploy, including exit 2 — "I could not inspect
# the package" is not permission to send it.
#
# Invoked through `bash` rather than as an executable: the exec bit does not
# survive every route this repository takes onto a Windows disk.
bash "${REPO_ROOT}/scripts/lib/check-line-endings.sh" "$TARBALL" "$REPO_ROOT" \
    || die "refusing to deploy this package — see above."

info "transferring to ${HOST}:${REMOTE_DIR}"
ssh_run "mkdir -p '${REMOTE_DIR}'"
scp "${SCP_OPTS[@]}" -q "$TARBALL" "${USER}@${HOST}:${REMOTE_DIR}/sentinel.tar.gz" \
    || die "transfer failed"
ssh_run "cd '${REMOTE_DIR}' && tar -xzf sentinel.tar.gz && rm -f sentinel.tar.gz && \
         chmod +x deploy/*.sh deploy/lib/*.sh 2>/dev/null || true"
ok "package extracted"

# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------
if (( DRY_RUN )); then
    printf '\n'
    info "preflight only — nothing on the server will be changed"
    ssh_sudo "'${REMOTE_DIR}/deploy/preflight.sh' ${DOMAIN:+--domain '${DOMAIN}'} --web-port '${WEB_PORT}' --nginx-mode '${NGINX_MODE}' ${ADMIN_IP:+--admin-ip '${ADMIN_IP}'}"
    rc=$?
    ssh_run "rm -rf '${REMOTE_DIR}'"
    exit $rc
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
cat <<'EOF'

  ┌────────────────────────────────────────────────────────────────────┐
  │  ÎNAINTE DE A CONTINUA                                             │
  │                                                                    │
  │  1. Deschide o A DOUA sesiune SSH acum și las-o deschisă.          │
  │  2. Verifică accesul la consola VPS-ului de la provider —          │
  │     testează-l, nu presupune că funcționează.                      │
  │  3. Ieșiri de urgență, dacă ceva merge prost:                      │
  │       touch /etc/sentinel/PANIC   -> blocklist golit în ≤60s       │
  │       reboot                      -> blocurile nu se persistă      │
  └────────────────────────────────────────────────────────────────────┘

EOF
if (( ! ASSUME_YES )); then
    read -r -p "Ai făcut cele de mai sus? [da/NU] " answer
    [[ "$answer" == "da" ]] || die "aborted — do the above first"
fi

info "installing (secrets go over stdin, never argv)"

# stdin carries the secrets, so it cannot also be a TTY — which means sudo must
# not prompt. Credentials were already primed once for the secrets comparison
# above; the ControlMaster keeps that warm, so this is normally a single
# `sudo -n true` and nothing more. Called again anyway: packaging and the
# line-ending check run in between, and a slow one of those is exactly the
# gap a cached credential can expire in.
prime_sudo

# install.sh is executed as a file that already exists on the server, not piped
# in as a script — `bash -s` would consume stdin and the secrets would never
# arrive. The file is the script; stdin is the data.
#
# The secrets file is piped straight into the remote command. It never touches
# the server's filesystem except as /etc/sentinel/secrets.env, which is created
# with umask 077 before any content is written to it.
INSTALL_ARGS=(--nginx-mode "$NGINX_MODE" --web-port "$WEB_PORT" --cert-mode "$CERT_MODE")
[[ -n "$ADMIN_IP"  ]] && INSTALL_ARGS+=(--admin-ip "$ADMIN_IP")
[[ -n "$DOMAIN"    ]] && INSTALL_ARGS+=(--domain "$DOMAIN")
[[ -n "$EMAIL"     ]] && INSTALL_ARGS+=(--email "$EMAIL")
[[ -n "$DB_PORT"   ]] && INSTALL_ARGS+=(--db-port "$DB_PORT")
[[ -n "$FROM_STEP" ]] && INSTALL_ARGS+=(--from-step "$FROM_STEP")
[[ -n "$FORCE_STEP" ]] && INSTALL_ARGS+=(--force-step "$FORCE_STEP")
(( ASSUME_YES )) && INSTALL_ARGS+=(--yes)

if ! ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" \
        "sudo -n '${REMOTE_DIR}/deploy/install.sh' ${INSTALL_ARGS[*]}" \
        < "$SECRETS_FILE"; then
    printf '\n'
    warn "installation failed"
    warn "The installer is step-numbered and idempotent. Fix the cause, then resume:"
    warn "    ./scripts/deploy.sh --host ${HOST} --user ${USER} ${KEY:+--key ${KEY}} \\"
    warn "        ${DOMAIN:+--domain ${DOMAIN}} --from-step <N>"
    warn "Or undo everything:"
    warn "    ./scripts/deploy.sh --host ${HOST} --user ${USER} ${KEY:+--key ${KEY}} --rollback"
    exit 1
fi

ok "installation finished"

# Keep the extracted tree: rollback.sh lives in it, and the operator will want
# it if something needs resuming.
#
# Replaced wholesale, not copied over. `cp -r src dest` nests when dest exists,
# so the second deploy to a host produced /opt/sentinel/deploy/deploy and left
# the FIRST deploy's rollback.sh in place — the one script whose being stale
# matters most. Removed first, then copied.
# One sudo per command, deliberately. `sudo cmd1 && cmd2` elevates cmd1 ONLY —
# the rest of the chain runs as the login user. Written as a chain, this removed
# the old tree as root and then failed to write the new one, leaving the host
# with no rollback.sh at all.
ssh_sudo "install -d -m 0755 /opt/sentinel" \
    && ssh_sudo "rm -rf /opt/sentinel/deploy" \
    && ssh_sudo "cp -r '${REMOTE_DIR}/deploy' /opt/sentinel/deploy" \
    || warn "could not refresh /opt/sentinel/deploy — rollback.sh there may be from an older release"
ssh_run "rm -rf '${REMOTE_DIR}'"

# ---------------------------------------------------------------------------
printf '\n'
ok "Sentinel deployed to ${HOST}"
cat <<EOF

  Dashboard : $( [[ "$NGINX_MODE" == "shared" ]]                   && printf 'https://%s' "${DOMAIN:-${HOST}}"                   || printf 'https://%s:%s
              (portul %s trebuie deschis în firewall-ul providerului)'                             "${DOMAIN:-${HOST}}" "$WEB_PORT" "$WEB_PORT" )
  Mod nginx : ${NGINX_MODE}
  Loguri    : ./scripts/tail-logs.sh --host ${HOST} --user ${USER} ${KEY:+--key ${KEY}}
  Rollback  : ./scripts/deploy.sh --host ${HOST} --user ${USER} ${KEY:+--key ${KEY}} --rollback

  Următorii pași:
    1. Verifică Telegram — ar trebui să fi primit un mesaj de confirmare.
       Primirea lui dovedește tot lanțul: config, secrete, rețea, token, chat id.
    2. Revizuiește /etc/sentinel/inventory.yaml.
    3. Lasă auto-block DEZACTIVAT 72h. Vei primi pe Telegram ce AR FI blocat.
    4. După 72h fără fals-pozitive, activează-l.

EOF
