#!/usr/bin/env bash
#
# Create /etc/sentinel/vps-watchdog.conf on the host, from the hand-copied
# watchdog script that is running there today.
#
#   ./scripts/vps-watchdog-conf-init.sh --host H [--user U] [--key K] [--port P] \
#       [--ssh-config FILE] [--ssh-bin PATH] [--dry-run]
#
#   --dry-run      read and validate what would be written; change nothing
#   --ssh-config   passed to ssh as -F. H may be a Host alias from that file, in
#                  which case --user/--key/--port are normally not needed
#   --ssh-bin      the ssh to use. On Git Bash the bundled ssh cannot see the
#                  Windows ssh-agent, so a key that works from PowerShell looks
#                  refused; C:/Windows/System32/OpenSSH/ssh.exe can
#
# WHY THIS EXISTS. deploy/install.sh adopts a host's watchdog only where this
# file exists (it is the opt-in), and where it does not, the deploy only warns
# and the old copy keeps running. On the production host the old copy has the
# 400 MB RAM floor that stayed silent through a kernel OOM kill on 21 Oct 2026.
# Creating the file is therefore the step that lets the reviewed watchdog in,
# and `ssh host 'cat > ...'` typed by hand is exactly what CLAUDE.md says a
# change to the host must not be. This is that step, as reviewed code.
#
# WHAT IT WRITES. HEALTH_DOMAINS — the client sites whose /api/health the
# watchdog probes — and EXCLUDE_AUTOFIX if the old script sets one (the list of
# containers auto-fix may never restart; install.sh's own warning says to carry
# both over). Nothing else: thresholds are NOT carried, because the old floors
# (RAM 400 MB, swap %) are the ones being replaced on purpose.
#
# THE DOMAINS ARE NOT IN THIS REPOSITORY, and must not be: they are clients' and
# the repository is public. They are read from the host at run time, parsed as
# DATA out of the old script (never sourced, never evaluated), validated token
# by token, and written to the host. They are never printed on success — the
# summary carries a count and a short digest, which is enough to see that what
# was read is what was written.
#
# WHAT IT REFUSES. (1) To overwrite: if the conf exists, nothing is touched,
# including when it is wrong — a second run says "already exists" and reports
# what it found. (2) To write a conf with no domains. An empty HEALTH_DOMAINS
# does not fail anything: it turns off the one check that watches the client
# sites, and the watchdog still reports healthy. So zero assignments, several
# assignments (which one wins is a guess), an empty value, or a token that does
# not look like a host name are all hard stops with nothing written.
#
# WHAT IT PROVES. Not an exit code. After writing, a SEPARATE ssh session reads
# the file back and this script judges the facts itself: a regular file (not a
# link), owner root:root, mode 0600, one name (the temporary is gone), the keys
# it expected, and every domain valid with the same count and digest it
# derived from the old script. Any miss is a non-zero exit that says not to
# deploy yet. That second session is also what runs on a host that already has
# the file, so the answer to "is it right" does not depend on who wrote it.
#
# HOW THE FILE IS PUBLISHED. Created 0600 root:root from the start (a temporary
# in the same directory, umask 077), checked, then hard-linked into place. `ln`
# fails if the name exists, so two runs racing cannot overwrite each other, and
# a reader never sees a half-written conf; `mv -n` would not do — it exits 0
# when it declines to move.
#
# NOT DONE HERE. It does not run the deploy, restart anything, or touch the old
# script. It changes one file, once.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Paths and owner are overridable through the environment for the tests, not for
# operation — the same convention as WATCHDOG_* in deploy/vps-watchdog/watchdog.sh.
# The watchdog reads /etc/sentinel/vps-watchdog.conf and nothing else, so a conf
# written anywhere else is a conf that does nothing.
CONF_PATH="${VPSW_CONF:-/etc/sentinel/vps-watchdog.conf}"
SOURCE_PATH="${VPSW_SOURCE:-/opt/vps-watchdog/watchdog.sh}"
WANT_OWNER="${VPSW_OWNER:-root:root}"
WANT_MODE=600

HOST=""; USER_ARG=""; KEY=""; PORT=""; SSH_CONFIG=""; SSH_BIN="ssh"; DRY_RUN=0

_G=$'\033[32m'; _R=$'\033[31m'; _B=$'\033[34m'; _0=$'\033[0m'
[[ -n "${NO_COLOR:-}" ]] && { _G=""; _R=""; _B=""; _0=""; }
die()  { printf '%serror:%s %s\n' "$_R" "$_0" "$*" >&2; exit 1; }
ok()   { printf '%s[+]%s %s\n' "$_G" "$_0" "$*"; }
info() { printf '%s[.]%s %s\n' "$_B" "$_0" "$*"; }

# The whole header comment, however long it grows (same reason as deploy.sh).
usage() { sed -n '2,${/^#/!q;p;}' "$0"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       HOST="${2:-}"; shift 2 ;;
        --user)       USER_ARG="${2:-}"; shift 2 ;;
        --key)        KEY="${2:-}"; shift 2 ;;
        --port)       PORT="${2:-}"; shift 2 ;;
        --ssh-config) SSH_CONFIG="${2:-}"; shift 2 ;;
        --ssh-bin)    SSH_BIN="${2:-}"; shift 2 ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --help|-h)    usage ;;
        *) die "argument necunoscut: $1" ;;
    esac
done

[[ -n "$HOST" ]] || die "--host este obligatoriu"
[[ -n "$SSH_BIN" ]] || die "--ssh-bin a primit o valoare goala"
# These end up inside the script that runs as root on the host. They are plain
# paths and a plain owner; anything else is refused here instead of quoted well.
[[ "$CONF_PATH" =~ ^/[A-Za-z0-9._/@+-]+$ ]]   || die "VPSW_CONF nu e o cale simpla: ${CONF_PATH}"
[[ "$SOURCE_PATH" =~ ^/[A-Za-z0-9._/@+-]+$ ]] || die "VPSW_SOURCE nu e o cale simpla: ${SOURCE_PATH}"
[[ "$WANT_OWNER" =~ ^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$ ]] || die "VPSW_OWNER nu e utilizator:grup: ${WANT_OWNER}"
# First character alphanumeric: a value starting with `-` would be read by ssh as an option.
[[ "$HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._@:-]*$ ]] || die "--host nu arata a nume de gazda sau alias: ${HOST}"
[[ -z "$USER_ARG" || "$USER_ARG" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || die "--user nu arata a nume de utilizator: ${USER_ARG}"
[[ "$PORT" =~ ^[0-9]*$ ]] || die "--port nu e un numar: ${PORT}"

# Same options as deploy.sh minus multiplexing: this makes two or three
# connections, not a hundred. Port is passed only when given — 22 by default
# would override a Port set in the ssh config for an alias.
SSH_CMD=("$SSH_BIN" -n -o BatchMode=no -o StrictHostKeyChecking=accept-new
         -o ConnectTimeout=15 -o ServerAliveInterval=30)
[[ -n "$SSH_CONFIG" ]] && SSH_CMD+=(-F "$SSH_CONFIG")
[[ -n "$PORT" ]] && SSH_CMD+=(-p "$PORT")
if [[ -n "$KEY" ]]; then
    KEY="${KEY/#\~/$HOME}"
    [[ -f "$KEY" ]] || die "cheia SSH nu exista: ${KEY}"
    SSH_CMD+=(-i "$KEY")
fi
SSH_CMD+=("${USER_ARG:+${USER_ARG}@}${HOST}")

# The part that runs ON THE HOST is scripts/lib/vps-watchdog-conf-init-remote.sh; read it
# here, once, as text. A missing or empty file is a stop: shipped empty it would run
# nothing, say nothing, and look like a host with nothing to report.
REMOTE_SCRIPT_FILE="${REPO_ROOT}/scripts/lib/vps-watchdog-conf-init-remote.sh"
[[ -r "$REMOTE_SCRIPT_FILE" ]] || die "nu gasesc ${REMOTE_SCRIPT_FILE}"
REMOTE_SCRIPT="$(cat "$REMOTE_SCRIPT_FILE")"
[[ -n "$REMOTE_SCRIPT" ]] || die "${REMOTE_SCRIPT_FILE} e gol"

REMOTE_OUT=""; REMOTE_RC=0; REMOTE_ERR=""

# run_remote MODE — one ssh session. Sets REMOTE_OUT / REMOTE_RC / REMOTE_ERR.
# ssh's own stderr goes to a file and is never merged into the output this
# script parses: this OpenSSH build prints a key-exchange warning on every
# connection, and merged it would land among the facts.
run_remote() {
    local mode="$1" payload b64 errf
    payload="$(printf 'MODE=%q\nCONF=%q\nSRC=%q\nWANT_OWNER=%q\nWANT_MODE=%q\n' \
                      "$mode" "$CONF_PATH" "$SOURCE_PATH" "$WANT_OWNER" "$WANT_MODE")"
    payload+=$'\n'"$REMOTE_SCRIPT"
    b64="$(printf '%s' "$payload" | base64 | tr -d '\n')"
    errf="$(mktemp)"
    set +e
    REMOTE_OUT="$("${SSH_CMD[@]}" "printf '%s' '${b64}' | base64 -d | sudo -n bash" 2>"$errf")"
    REMOTE_RC=$?
    set -e
    REMOTE_ERR="$(cat "$errf")"
    rm -f "$errf"
}

# fact NAME -> the value of the LAST `VPSW:NAME value` line, or nothing.
fact() { printf '%s\n' "$REMOTE_OUT" | sed -n "s/^VPSW:$1 //p" | tail -n 1; }

# After run_remote: stop on anything but a verdict from the remote script.
# An empty output is NOT "nothing to report" — a sudo that asked for a password,
# an ssh that was refused and a remote script that died all look like that, and
# each has to be a failure, not a pass.
require_verdict() {
    local what="$1" errs
    errs="$(printf '%s\n' "$REMOTE_OUT" | sed -n 's/^VPSW:ERR //p')"
    if [[ -n "$errs" ]]; then
        die "${what}: ${errs}"
    fi
    if (( REMOTE_RC != 0 )) || [[ -z "$(fact RESULT)" ]]; then
        die "${what}: gazda nu a dat un verdict (cod ${REMOTE_RC}). Ce a spus ssh/sudo: ${REMOTE_ERR:-nimic}. \
Daca e vorba de sudo, 'sudo -n true' trebuie sa mearga fara parola pe contul folosit."
    fi
}

info "gazda: ${SSH_CMD[-1]}  conf: ${CONF_PATH}  sursa: ${SOURCE_PATH}"

# ---------------------------------------------------------------------------
# 1. Write (or plan). The remote script reads the domains, validates them and
#    publishes — or says exists, or stops.
# ---------------------------------------------------------------------------
if (( DRY_RUN )); then
    run_remote plan
    require_verdict "nu pot citi starea gazdei"
    case "$(fact RESULT)" in
        exists) ok "--dry-run: ${CONF_PATH} exista deja pe gazda; ar fi lasat neatins." ;;
        plan)
            ok "--dry-run: ar scrie ${CONF_PATH} (${WANT_OWNER}, ${WANT_MODE}) cu $(fact DOMAINS_COUNT) domenii \
(amprenta $(fact DOMAINS_DIGEST)); EXCLUDE_AUTOFIX: $(fact EXCLUDE)." ;;
        *) die "--dry-run: raspuns neasteptat de la gazda: $(fact RESULT)" ;;
    esac
    info "nimic nu a fost scris pe gazda."
    exit 0
fi

run_remote create
require_verdict "nu am scris ${CONF_PATH}"
RESULT="$(fact RESULT)"
case "$RESULT" in
    created) CREATED=1
        WROTE_COUNT="$(fact DOMAINS_COUNT)"; WROTE_DIGEST="$(fact DOMAINS_DIGEST)"; WROTE_EXCLUDE="$(fact EXCLUDE)"
        info "scris: ${WROTE_COUNT} domenii (amprenta ${WROTE_DIGEST}), EXCLUDE_AUTOFIX ${WROTE_EXCLUDE}" ;;
    exists) CREATED=0
        info "${CONF_PATH} exista deja pe gazda: nu l-am atins. Citesc ce contine ca sa spun daca e bun." ;;
    *) die "raspuns neasteptat de la gazda: '${RESULT}'" ;;
esac

# ---------------------------------------------------------------------------
# 2. Read it back in a SEPARATE session and judge the facts.
# ---------------------------------------------------------------------------
run_remote verify
require_verdict "nu pot verifica ${CONF_PATH}"
[[ "$(fact RESULT)" == "present" ]] || die "${CONF_PATH} NU exista pe gazda dupa scriere (rezultat: $(fact RESULT)). Nu face deploy."

problems=()
[[ "$(fact TYPE)"  == "regular" ]]         || problems+=("nu e un fisier obisnuit ($(fact TYPE))")
[[ "$(fact OWNER)" == "$WANT_OWNER" ]]     || problems+=("proprietar $(fact OWNER), nu ${WANT_OWNER}")
[[ "$(fact MODE)"  == "$WANT_MODE" ]]      || problems+=("modul $(fact MODE), nu ${WANT_MODE}")
[[ "$(fact LINKS)" == "1" ]]               || problems+=("$(fact LINKS) nume pe disc, nu 1 (a ramas un temporar?)")
KEYS=" $(fact KEYS) "
[[ "$KEYS" == *" HEALTH_DOMAINS "* ]]      || problems+=("cheia HEALTH_DOMAINS lipseste")
N_NOW="$(fact DOMAINS_COUNT)"
[[ "$N_NOW" =~ ^[0-9]+$ ]] && (( N_NOW >= 1 )) || problems+=("HEALTH_DOMAINS e gol sau ilizibil: lista goala opreste verificarea site-urilor clientilor")
[[ "$(fact DOMAINS_INVALID)" == "0" ]]     || problems+=("$(fact DOMAINS_INVALID) elemente din HEALTH_DOMAINS nu arata a nume de gazda")
if (( CREATED )); then
    # Numarul si amprenta merg impreuna: aceeasi lista, nu doar una la fel de lunga.
    [[ "$N_NOW" == "$WROTE_COUNT" && "$(fact DOMAINS_DIGEST)" == "$WROTE_DIGEST" ]] \
        || problems+=("domeniile citite inapoi (${N_NOW}, amprenta $(fact DOMAINS_DIGEST)) nu coincid cu cele scrise (${WROTE_COUNT}, amprenta ${WROTE_DIGEST})")
    if [[ "$WROTE_EXCLUDE" == "carried" ]]; then
        [[ "$KEYS" == *" EXCLUDE_AUTOFIX "* ]] || problems+=("EXCLUDE_AUTOFIX trebuia preluat si lipseste")
    fi
fi

if (( ${#problems[@]} )); then
    printf '%serror:%s %s are probleme:\n' "$_R" "$_0" "$CONF_PATH" >&2
    for p in "${problems[@]}"; do printf '  - %s\n' "$p" >&2; done
    if (( CREATED )); then
        printf '  Fisierul a fost scris de aceasta rulare si NU l-am sters. NU face deploy pana nu e corect:\n' >&2
        printf '  citeste-l (sudo cat %s), apoi sterge-l de mana (sudo rm %s) si ruleaza din nou.\n' "$CONF_PATH" "$CONF_PATH" >&2
    else
        printf '  Fisierul exista de dinainte si nu l-am modificat. Repara-l de mana.\n' >&2
    fi
    exit 1
fi

if (( CREATED )); then
    ok "${CONF_PATH} scris si verificat intr-o sesiune separata: fisier obisnuit, ${WANT_OWNER}, ${WANT_MODE}, un singur nume, ${N_NOW} domenii cu aceeasi amprenta (${WROTE_DIGEST})."
    info "Urmatorul pas e deploy-ul (install.sh adopta acum watchdog-ul). Copia veche se pastreaza ca *.pre-adoption."
else
    ok "${CONF_PATH} exista deja si arata bine (${WANT_OWNER}, ${WANT_MODE}, ${N_NOW} domenii). Nu am scris nimic: rularea repetata e inofensiva."
fi
