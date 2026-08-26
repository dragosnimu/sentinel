#!/usr/bin/env bash
# Shared helpers for the server-side deploy scripts.
# Sourced, never executed directly.

set -euo pipefail

SENTINEL_PREFIX="${SENTINEL_PREFIX:-/opt/sentinel}"
SENTINEL_CONFIG_DIR="${SENTINEL_CONFIG_DIR:-/etc/sentinel}"
SENTINEL_STATE_DIR="${SENTINEL_STATE_DIR:-/var/lib/sentinel}"
SENTINEL_BACKUP_DIR="${SENTINEL_BACKUP_DIR:-/var/backups/sentinel}"
SENTINEL_USER="${SENTINEL_USER:-sentinel}"
STATE_MARKERS="${SENTINEL_STATE_DIR}/.install-state"

# Ports Sentinel needs for itself.
#
# NOT 80 or 443: the host is usually already serving something there, and a
# monitoring agent that displaces the service it monitors has inverted its
# purpose. The public port is configurable (--web-port) and defaults to 8443.
#
# 8787 and 5432 are loopback-only. Everything else on the host is discovered
# rather than assumed: preflight snapshots what is listening and refuses to take
# a port already in use.
SENTINEL_PUBLIC_PORT="${SENTINEL_PUBLIC_PORT:-8443}"
SENTINEL_PORTS=("$SENTINEL_PUBLIC_PORT" 8787 5432)

_C_RESET=''; _C_RED=''; _C_GREEN=''; _C_YELLOW=''; _C_BLUE=''; _C_BOLD=''
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
    _C_RESET=$'\033[0m'; _C_RED=$'\033[31m'; _C_GREEN=$'\033[32m'
    _C_YELLOW=$'\033[33m'; _C_BLUE=$'\033[34m'; _C_BOLD=$'\033[1m'
fi

STEP_CURRENT=""
FAIL_COUNT=0
WARN_COUNT=0

log()   { printf '%s\n' "$*"; }
info()  { printf '%s[.]%s %s\n' "$_C_BLUE"  "$_C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$_C_GREEN" "$_C_RESET" "$*"; }
warn()  { WARN_COUNT=$((WARN_COUNT + 1)); printf '%s[!]%s %s\n' "$_C_YELLOW" "$_C_RESET" "$*" >&2; }
fail()  { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '%s[x]%s %s\n' "$_C_RED" "$_C_RESET" "$*" >&2; }

die() {
    printf '%s[FATAL]%s %s\n' "$_C_RED$_C_BOLD" "$_C_RESET" "$*" >&2
    [[ -n "$STEP_CURRENT" ]] && printf '        (during step %s)\n' "$STEP_CURRENT" >&2
    exit 1
}

section() {
    printf '\n%s== %s ==%s\n' "$_C_BOLD" "$*" "$_C_RESET"
}

# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------
# Every install step is guarded by a marker file. Re-running the installer is
# safe and fast; --from-step N re-runs from a point; --force-step N[,N…] re-runs
# the listed steps.
step_done() { [[ -f "${STATE_MARKERS}/$1" ]]; }

mark_done() {
    mkdir -p "$STATE_MARKERS"
    date -u +%Y-%m-%dT%H:%M:%SZ > "${STATE_MARKERS}/$1"
}

clear_step() { rm -f "${STATE_MARKERS}/$1"; }

# --------------------------------------------------------------------------
# --force-step: a LIST, not one number
# --------------------------------------------------------------------------
# One number was enough while every step stood on its own. Rotating
# SENTINEL_DB_PASSWORD is not: step 22 runs `ALTER ROLE sentinel PASSWORD` and
# step 27 rewrites /etc/sentinel/secrets.env — one value, two places, no
# synchronisation between them.
#
# Force one without the other, in either order, and the run does not survive its
# own next step: `migrate` (28) is in ALWAYS_STEPS and connects to the database
# with whatever secrets.env holds, so it dies on the mismatch. Had it not, the
# ALWAYS `start_services` (32) would have restarted every daemon into the same
# mismatch at the end of that pass. Both halves belong to one operation, so they
# have to be forceable in one pass.
#
# Parsed once, up front, into decimal integers. A value that is not a list of
# numbers is refused before any step runs — half a rotation is worse than none.
FORCE_STEPS=()
FORCE_STEPS_RAN=()
STEPS_SKIPPED_MARKED=()
FORCE_STEPS_PARSED=0

parse_force_steps() {
    local raw="${1:-}" item
    FORCE_STEPS=()
    FORCE_STEPS_PARSED=1
    [[ -z "$raw" ]] && return 0

    # Whitespace is tolerated only AROUND the commas. Stripping it everywhere
    # first would turn "22 27" — a plausible way to type a list — into the
    # single number 2227, which matches no step and would be obeyed silently.
    # So the shape is checked on the raw value, before anything is removed.
    if [[ ! "$raw" =~ ^[[:space:]]*[0-9]+([[:space:]]*,[[:space:]]*[0-9]+)*[[:space:]]*$ ]]; then
        die "--force-step: '${raw}' is not a step number or a comma-separated list of them (e.g. 22 or 22,27)"
    fi

    local -a parts=()
    IFS=',' read -r -a parts <<< "${raw//[[:space:]]/}"
    for item in "${parts[@]}"; do
        # 10# so a value typed as 022 means step 22 rather than an invalid
        # octal literal that would abort the arithmetic.
        FORCE_STEPS+=("$((10#$item))")
    done
}

force_step_requested() {
    local want="$1" n
    for n in ${FORCE_STEPS[@]+"${FORCE_STEPS[@]}"}; do
        (( n == 10#$want )) && return 0
    done
    return 1
}

# Refuse a number that is not a step of THIS installer.
#
# `--force-step 22,72` would clear one marker, run one step, and finish green
# having done half of what was asked — which for a password rotation means the
# database changed and the services did not. The step numbers are read from the
# installer's own `run_step` lines, so this cannot drift away from them.
assert_force_steps_exist() {
    local script="$1" want n hit
    (( ${#FORCE_STEPS[@]} )) || return 0

    local -a known=() unknown=()
    while read -r n; do known+=("$n"); done < <(
        grep -oE '^[[:space:]]*run_step[[:space:]]+[0-9]+' "$script" | awk '{print $2}')

    # An empty list would accept every number instead of none. If the extraction
    # ever stops matching, that has to be a refusal, not a free pass.
    if (( ${#known[@]} == 0 )); then
        die "internal: no run_step lines found in ${script}; cannot check --force-step"
    fi

    for want in "${FORCE_STEPS[@]}"; do
        hit=0
        for n in "${known[@]}"; do
            (( 10#$n == want )) && { hit=1; break; }
        done
        (( hit )) || unknown+=("$want")
    done

    if (( ${#unknown[@]} )); then
        die "--force-step: no such step: ${unknown[*]}. This installer has steps: $(
            printf '%s ' "${known[@]}")"
    fi
}

# The proof that --force-step did anything is that the step's BODY ran.
#
# Clearing a marker is intent; running the body is effect. A step that
# --from-step had already skipped past, or one whose branch was not taken, would
# otherwise leave the run ending with "installation finished" and the operator's
# request quietly unperformed — which is how the rotation that prompted all this
# went unnoticed in the first place.
assert_forced_steps_ran() {
    local want ran missed=()
    (( ${#FORCE_STEPS[@]} )) || return 0

    for want in "${FORCE_STEPS[@]}"; do
        local hit=0
        for ran in ${FORCE_STEPS_RAN[@]+"${FORCE_STEPS_RAN[@]}"}; do
            (( ran == want )) && { hit=1; break; }
        done
        (( hit )) || missed+=("$want")
    done

    if (( ${#missed[@]} )); then
        die "--force-step a cerut pașii [${missed[*]}], dar corpul lor nu a rulat.
        Nimic din ce depinde de ei nu s-a întâmplat. Verifică dacă nu cumva
        --from-step a sărit peste ei în aceeași rulare."
    fi
    ok "--force-step: re-rulați efectiv pașii ${FORCE_STEPS_RAN[*]}"
}

# Steps that are NOT offered in a generated --force-step suggestion.
#
# Not "steps you may never force" — the flag still takes them, and there are
# good reasons to. This is the narrower claim: re-running them has a side effect
# beyond the step itself, so the installer will not put them in a line the
# operator is invited to paste. The reason is printed next to the step, because
# a refusal without one gets pasted anyway.
#
# Only what this repository can point at is listed. 29 is here because
# ALWAYS_STEPS excludes it for the same reason, in the comment right below.
force_step_is_flagged() {
    case "$((10#$1))" in
        29) return 0 ;;
        *)  return 1 ;;
    esac
}

force_step_flag_reason() {
    case "$((10#$1))" in
        29) printf '%s' "re-rularea reîncarcă tabela nftables. ALWAYS_STEPS o ține \
deoparte fiindcă asta poate goli seturile, adică deblochează tăcut tot ce e blocat \
acum. Dacă chiar vrei, adaugă-l tu, uitându-te întâi la 'nft list table inet sentinel'" ;;
        *)  printf '%s' "re-rularea are efecte în afara pasului" ;;
    esac
}

# What --from-step did NOT do, said once, at the end, where it is still on screen.
#
# The operator ran `--from-step 22` to rotate a password. Steps 22 and 27 printed
# "(already done)" in green, in the middle of a hundred lines, and the run
# finished with "installation finished". Nothing had been rotated.
#
# --from-step only skips the steps BELOW N; at or above N a marker still wins.
# That is right for resuming an interrupted install and wrong for re-running a
# step, and the difference is invisible unless it is spelled out.
report_marked_skips() {
    [[ -n "${FROM_STEP:-}" ]] || return 0
    (( ${#STEPS_SKIPPED_MARKED[@]} )) || return 0

    warn "--from-step ${FROM_STEP}: ${#STEPS_SKIPPED_MARKED[@]} pas(i) de la ${FROM_STEP} în sus \
erau deja marcați și NU au rulat:"
    warn "    ${STEPS_SKIPPED_MARKED[*]}"
    warn "--from-step sare doar pașii de SUB N; unul marcat rămâne marcat. Ca să reiei"
    warn "pași marcați, dă-le numerele lui --force-step, toate în aceeași rulare."

    # The suggested command is generated, so it reads as advice. It must not
    # advise something this same file calls dangerous a few lines below: step 29
    # is kept out of ALWAYS_STEPS precisely because re-running it touches the
    # live nftables table. A paste-ready line containing 29 would have been an
    # instruction to do that, printed by the installer itself.
    local key num
    local -a safe=() flagged=()
    for key in "${STEPS_SKIPPED_MARKED[@]}"; do
        num="${key%%_*}"
        if force_step_is_flagged "$num"; then flagged+=("$key"); else safe+=("$num"); fi
    done

    if (( ${#safe[@]} )); then
        warn "    --force-step $(IFS=,; printf '%s' "${safe[*]}")"
        warn "Comanda re-rulează exact pașii ăia, nimic altceva: scoate-i pe cei pe care"
        warn "nu-i vrei, în loc s-o dai așa cum e."
    else
        warn "Niciunul dintre ei nu e sugerat automat — vezi mai jos."
    fi

    for key in ${flagged[@]+"${flagged[@]}"}; do
        num="${key%%_*}"
        warn "    ${key} NU e în comanda de mai sus: $(force_step_flag_reason "$num")"
    done
}

# Steps that must run on EVERY invocation, marker or not.
#
# A marker means "this was done once", which is the right question for creating
# a user or initialising a database cluster, and the wrong question for
# installing the code. The documented upgrade path is `git pull` and re-run —
# and with everything marker-gated that re-run skipped the package copy AND the
# migrations, reported success, and changed nothing. An upgrade that silently
# does nothing is worse than one that fails.
#
# Everything listed here is idempotent by construction: the package copy wipes
# and rewrites, migrations are forward-only and skip what is applied, unit files
# are overwritten, the nginx step validates before and after and removes its own
# files if it broke anything, certificate acquisition short-circuits when a
# certificate already exists, and the service start is a restart behind a health
# gate.
#
# The rule for this list: does the step carry CONTENT FROM THE REPO that changes
# between releases? An nginx rate-limit fix that never reaches the server is as
# useless as a code fix that never reaches it — that happened, and the operator
# kept getting 429s from the config the installer had declined to update.
#
# `nftables` is deliberately absent. Re-creating the table would empty the
# named sets, which means silently unblocking every attacker currently blocked.
# Refreshing config is worth a re-run; dropping a live blocklist is not.
# `snapshot` is here for a SECOND reason, not the one above: it carries no repo
# content at all. It is here because a pre-deploy snapshot whose contents predate
# the deploy is not a rollback point — it is a rollback point's costume. Marked
# done once and skipped forever, step 18 left every later deploy advertising the
# first snapshot ever taken; on 21 August 2026 a deploy printed one whose files
# were dated 31 July. Cheap to redo (a few `nft list`, `rpm -qa` and a tar), and
# worthless if stale, so it re-runs every time.
ALWAYS_STEPS="package claude_workspace configs migrate systemd start_services \
nginx nginx_shared auxiliary snapshot"

step_is_always() {
    case " ${ALWAYS_STEPS} " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# step NN name -- runs the body unless already marked or below --from-step.
run_step() {
    local num="$1" name="$2"; shift 2
    local key
    key="$(printf '%02d_%s' "$num" "$name")"
    STEP_CURRENT="$key"

    # A raw --force-step that reached run_step unparsed would be ignored in
    # silence, which is the failure this whole mechanism exists to remove.
    if [[ -n "${FORCE_STEP:-}" ]] && (( ! FORCE_STEPS_PARSED )); then
        die "internal: --force-step was set but parse_force_steps was never called"
    fi

    if [[ -n "${FROM_STEP:-}" ]] && (( num < FROM_STEP )); then
        printf '%s[-]%s step %-28s (skipped: below --from-step)\n' "$_C_BLUE" "$_C_RESET" "$key"
        return 0
    fi
    if force_step_requested "$num"; then
        clear_step "$key"
    fi
    if step_done "$key" && ! step_is_always "$name"; then
        # Yellow, and said differently, when --from-step is in play: that is the
        # run in which the operator asked for something and this line is the
        # answer "no". In a plain re-run it is just idempotency, and green.
        if [[ -n "${FROM_STEP:-}" ]]; then
            STEPS_SKIPPED_MARKED+=("$key")
            printf '%s[=]%s step %-28s (already done — --from-step does not re-run it)\n' \
                "$_C_YELLOW" "$_C_RESET" "$key"
        else
            printf '%s[=]%s step %-28s (already done)\n' "$_C_GREEN" "$_C_RESET" "$key"
        fi
        return 0
    fi

    printf '\n%s[>] step %s%s\n' "$_C_BOLD" "$key" "$_C_RESET"
    "$@"
    mark_done "$key"
    if force_step_requested "$num"; then
        FORCE_STEPS_RAN+=("$((10#$num))")
    fi
    STEP_CURRENT=""
}

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# Exact membership: in_list NEEDLE ITEM...
#
# Whole-element comparison, and that is the entire point. The callers pass
# secret key names, where anything looser is a deletion: with a prefix match, a
# key on disk called SENTINEL_SESSION would be judged already-known because
# SENTINEL_SESSION_SECRET is in the list, and would then be dropped from the
# rewritten file — the failure this whole path exists to prevent.
#
# (step_is_always uses `case " $list " in *" $1 "*` on a space-padded string,
# which is a whole-WORD match and is correct for what it does. An earlier
# version of this comment called it a substring match. It is not.)
in_list() {
    local needle="$1"; shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

need_root() {
    [[ "$(id -u)" -eq 0 ]] || die "this must run as root (the deploy script uses sudo)"
}

# Write a file only if absent. If it exists and differs, leave it alone and
# write .new alongside — an operator's tuned config is never silently replaced.
install_config() {
    local src="$1" dst="$2" mode="${3:-0640}" owner="${4:-root:${SENTINEL_USER}}"

    if [[ ! -f "$dst" ]]; then
        install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dst"
        ok "created $dst"
        return 0
    fi
    if cmp -s "$src" "$dst"; then
        ok "$dst unchanged"
        return 0
    fi
    install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "${dst}.new"
    warn "$dst exists and differs — wrote ${dst}.new instead. Review with:"
    warn "    diff -u ${dst} ${dst}.new"
}

port_free() {
    ! ss -tlnH "sport = :$1" 2>/dev/null | grep -q . \
        && ! ss -ulnH "sport = :$1" 2>/dev/null | grep -q .
}

port_owner() {
    ss -tlnpH "sport = :$1" 2>/dev/null | head -1 | sed 's/.*users:((//; s/).*//' || true
}

# The systemd unit named in a /proc/PID/cgroup, read from stdin. Empty when the
# process belongs to no unit — a container, a login session, a bare fork.
#
# Its own function so it can be tested without a live process. The extraction
# is one regex over kernel-supplied text, which is exactly the shape of thing
# that breaks quietly and stays broken.
#
# Matched anywhere in the path rather than only at the end: a service that forks
# into sub-cgroups appends further components after the unit name.
cgroup_unit() {
    sed -n 's#.*/\([A-Za-z0-9@_.-]*\.service\).*#\1#p' | head -1
}

# Which systemd unit owns the process listening on a port, if any.
#
# The process name cannot answer "is this ours". Sentinel's dashboard reports
# itself as `python`, and so does every other Python service on the host. The
# cgroup path can: the kernel writes it, and any process could call itself
# python but cannot place itself in another unit's cgroup.
port_owner_unit() {
    local pid
    pid="$(ss -tlnpH "sport = :$1" 2>/dev/null | head -1 |
           sed -n 's/.*pid=\([0-9]\+\).*/\1/p')"
    [[ -n "$pid" ]] || return 0
    cgroup_unit < "/proc/${pid}/cgroup" 2>/dev/null
}

mem_available_mb() {
    awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo
}

disk_free_gb() {
    df -BG --output=avail "$1" 2>/dev/null | tail -1 | tr -dc '0-9'
}

# --------------------------------------------------------------------------
# Do-no-harm: what was running before, and is it still running after
# --------------------------------------------------------------------------
# Sentinel is being installed onto a server that presumably already does
# something. Whatever that is, installing a security agent must not break it.
#
# Rather than knowing about any particular product, this records what was
# running and listening before the deploy and compares afterwards. That works
# on any host, catches port conflicts and accidental restarts, and does not go
# stale the moment the machine changes.

BASELINE_SERVICES=""
BASELINE_PORTS=""

capture_baseline() {
    local dir="${1:-$STATE_MARKERS}"
    mkdir -p "$dir"

    # LC_ALL=C throughout so the on-disk baseline is in byte order — the same
    # order assert_nothing_broken re-sorts into before comparing. Consistency here
    # is not strictly required (the comparison re-sorts) but avoids a misleading
    # file and keeps the two functions honest about collation.
    systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
        | awk '{print $1}' | LC_ALL=C sort > "${dir}/baseline-services.txt" || true
    ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | LC_ALL=C sort -u \
        > "${dir}/baseline-ports.txt" || true

    if have docker; then
        docker ps --format '{{.Names}}' 2>/dev/null | LC_ALL=C sort > "${dir}/baseline-containers.txt" || true
    fi

    BASELINE_SERVICES="${dir}/baseline-services.txt"
    BASELINE_PORTS="${dir}/baseline-ports.txt"

    ok "baseline captured: $(wc -l < "${dir}/baseline-services.txt" 2>/dev/null || echo 0) services, \
$(wc -l < "${dir}/baseline-ports.txt" 2>/dev/null || echo 0) listening ports"
}

# Compare against the baseline. A service that was running and now is not, or a
# port that was listening and now is not, means Sentinel disturbed something it
# had no business touching.
assert_nothing_broken() {
    local when="$1" dir="${2:-$STATE_MARKERS}" broken=0

    if [[ -f "${dir}/baseline-services.txt" ]]; then
        local now_services
        now_services="$(mktemp)"
        systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
            | awk '{print $1}' | sort > "$now_services"

        # Both inputs are re-sorted with LC_ALL=C right here, immediately before
        # comm. comm checks sortedness with the current locale's collation, and a
        # plain `sort` uses locale collation too — but service names carry `@`,
        # `-` and `.`, which locale and byte order disagree on. A baseline sorted
        # in one run and compared in another (different locale, or sort vs comm
        # disagreeing) makes comm emit "file N is not in sorted order" and garbage
        # output, which reads as "a service stopped" and triggers a false
        # rollback of a perfectly good install. C collation makes it deterministic.
        local lost
        lost="$(comm -23 <(LC_ALL=C sort "${dir}/baseline-services.txt") <(LC_ALL=C sort "$now_services") \
            | grep -v '^sentinel-' || true)"
        rm -f "$now_services"

        if [[ -n "$lost" ]]; then
            broken=1
            fail "services that were running before the deploy are no longer running (${when}):"
            printf '        %s\n' $lost >&2
        fi
    fi

    if [[ -f "${dir}/baseline-ports.txt" ]]; then
        local now_ports lost_ports
        now_ports="$(mktemp)"
        ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' > "$now_ports"
        # LC_ALL=C lexical sort on both sides: the baseline was written with a
        # NUMERIC sort, but comm compares lexically, so "80" vs "443" vs "8787"
        # would otherwise look out of order. Sort both the same way, here.
        lost_ports="$(comm -23 <(LC_ALL=C sort -u "${dir}/baseline-ports.txt") <(LC_ALL=C sort -u "$now_ports") || true)"
        rm -f "$now_ports"

        if [[ -n "$lost_ports" ]]; then
            broken=1
            fail "ports that were listening before the deploy are now closed (${when}): \
$(tr '\n' ' ' <<< "$lost_ports")"
        fi
    fi

    if have docker && [[ -f "${dir}/baseline-containers.txt" ]]; then
        local now_containers lost_containers
        now_containers="$(mktemp)"
        docker ps --format '{{.Names}}' 2>/dev/null > "$now_containers"
        lost_containers="$(comm -23 <(LC_ALL=C sort "${dir}/baseline-containers.txt") <(LC_ALL=C sort "$now_containers") || true)"
        rm -f "$now_containers"

        if [[ -n "$lost_containers" ]]; then
            broken=1
            fail "containers that were running before the deploy have stopped (${when}): \
$(tr '\n' ' ' <<< "$lost_containers")"
        fi
    fi

    if (( broken )); then
        return 1
    fi
    ok "nothing that was running before the deploy has stopped (${when})"
    return 0
}

# --------------------------------------------------------------------------
# Anti-lockout
# --------------------------------------------------------------------------
# The address the operator is connected from. It goes into the nftables
# allowlist BEFORE any drop rule exists, and it is never blockable.
ssh_peer_ip() {
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        awk '{print $1}' <<< "$SSH_CLIENT"
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        awk '{print $1}' <<< "$SSH_CONNECTION"
    else
        echo ""
    fi
}

public_ips() {
    ip -o addr show scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | sort -u
}

lockout_warning() {
    cat <<'EOF'

  ┌────────────────────────────────────────────────────────────────────┐
  │  ÎNAINTE DE A CONTINUA                                             │
  │                                                                    │
  │  1. Deschide o A DOUA sesiune SSH acum și las-o deschisă.          │
  │  2. Verifică accesul la consola VPS-ului de la provider —          │
  │     testează-l, nu presupune că funcționează.                      │
  │  3. Reține ieșirile de urgență:                                    │
  │       touch /etc/sentinel/PANIC   → blocklist golit în ≤60s        │
  │       reboot                      → blocurile nu se persistă       │
  │                                                                    │
  │  Sentinel folosește `policy accept`. Nu te poate bloca prin        │
  │  eșec — doar blocându-te explicit.                                 │
  └────────────────────────────────────────────────────────────────────┘

EOF
}

confirm() {
    local prompt="${1:-Continui?}"
    if [[ "${SENTINEL_ASSUME_YES:-0}" == "1" ]]; then
        info "$prompt  [auto-yes]"
        return 0
    fi
    read -r -p "$prompt [da/NU] " answer
    [[ "$answer" == "da" || "$answer" == "yes" || "$answer" == "y" ]]
}

# --------------------------------------------------------------------------
# Snapshots — the rollback target
# --------------------------------------------------------------------------
snapshot_create() {
    local dir="$1"
    mkdir -p "$dir"

    nft list ruleset            > "${dir}/nftables.rules"     2>/dev/null || true
    ss -tlnp                    > "${dir}/listening.txt"      2>/dev/null || true
    systemctl list-units --type=service --state=running --no-legend \
                                > "${dir}/services.txt"       2>/dev/null || true
    rpm -qa | sort              > "${dir}/rpm.txt"            2>/dev/null || true
    [[ -d /etc/nginx ]] && tar -cf "${dir}/nginx.tar" -C / etc/nginx 2>/dev/null || true
    [[ -d "$SENTINEL_CONFIG_DIR" ]] && \
        tar -cf "${dir}/sentinel-config.tar" -C / "etc/sentinel" 2>/dev/null || true
    systemctl is-active firewalld > "${dir}/firewalld.txt" 2>&1 || true
    have docker && docker ps --format '{{.Names}}\t{{.Image}}' > "${dir}/containers.txt" 2>/dev/null || true

    date -u +%Y-%m-%dT%H:%M:%SZ > "${dir}/created_at"
    ok "pre-deploy snapshot written to ${dir}"
}
