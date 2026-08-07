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
# safe and fast; --from-step N re-runs from a point; --force-step N re-runs one.
step_done() { [[ -f "${STATE_MARKERS}/$1" ]]; }

mark_done() {
    mkdir -p "$STATE_MARKERS"
    date -u +%Y-%m-%dT%H:%M:%SZ > "${STATE_MARKERS}/$1"
}

clear_step() { rm -f "${STATE_MARKERS}/$1"; }

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
ALWAYS_STEPS="package claude_workspace configs migrate systemd start_services \
nginx nginx_shared auxiliary"

step_is_always() {
    case " ${ALWAYS_STEPS} " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# step NN name -- runs the body unless already marked or below --from-step.
run_step() {
    local num="$1" name="$2"; shift 2
    local key
    key="$(printf '%02d_%s' "$num" "$name")"
    STEP_CURRENT="$key"

    if [[ -n "${FROM_STEP:-}" ]] && (( num < FROM_STEP )); then
        printf '%s[-]%s step %-28s (skipped: below --from-step)\n' "$_C_BLUE" "$_C_RESET" "$key"
        return 0
    fi
    if [[ "${FORCE_STEP:-}" == "$num" ]]; then
        clear_step "$key"
    fi
    if step_done "$key" && ! step_is_always "$name"; then
        printf '%s[=]%s step %-28s (already done)\n' "$_C_GREEN" "$_C_RESET" "$key"
        return 0
    fi

    printf '\n%s[>] step %s%s\n' "$_C_BOLD" "$key" "$_C_RESET"
    "$@"
    mark_done "$key"
    STEP_CURRENT=""
}

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

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
