#!/usr/bin/env bash
#
# Deploy Sentinel to the server over SSH. Run from Git Bash or WSL.
#
#   ./scripts/deploy.sh --host 203.0.113.10 --user deploy \
#       --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro
#
#   --nginx-mode M dedicated (own listener on --web-port) or shared (a vhost on
#                  the nginx already serving 80/443). See docs/DEPLOYMENT.md §2.
#   --web-port N   dashboard HTTPS port in dedicated mode (default 8443)
#   --cert-mode M  auto|webroot|dns|selfsigned|none — see docs/DEPLOYMENT.md §2.1
#   --dry-run      run preflight only; change nothing
#   --rollback     undo a previous deployment
#   --from-step N  resume an interrupted install
#   --force-step N re-run one step even though it is marked done
#   --purge        with --rollback, also drop the database
#
# This script is deliberately thin. All the real logic lives in
# deploy/install.sh on the server, so there is one implementation to test and
# deploy.ps1 can be its exact behavioural twin.
#
# Secrets go over the SSH channel on stdin. Never argv (where `ps` on the
# server would show them), never a file in the tarball, never an environment
# variable that lingers in a shell.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_FILE="${REPO_ROOT}/secrets/.env.local"

HOST=""; USER=""; KEY=""; DOMAIN=""; EMAIL=""; ADMIN_IP=""
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

usage() { sed -n '2,20p' "$0"; exit 0; }

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
        --from-step) FROM_STEP="${2:-}"; shift 2 ;;
        # install.sh has always had this; deploy.sh could not pass it
        # through, so the only way to re-run one step was to ssh in and run
        # the installed copy — which fails, because the source tree it needs
        # only exists inside the transferred tarball.
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
[[ -n "$USER" ]] || die "--user is required"

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
if (( ! DRY_RUN )); then
    if [[ ! -f "$SECRETS_FILE" ]]; then
        warn "no ${SECRETS_FILE}"
        info "running scripts/secrets-init.sh"
        "${REPO_ROOT}/scripts/secrets-init.sh" || die "secret initialisation failed"
    fi

    missing=()
    for key in SENTINEL_DB_PASSWORD ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID; do
        grep -qE "^${key}=.+" "$SECRETS_FILE" || missing+=("$key")
    done
    if (( ${#missing[@]} > 0 )); then
        warn "missing or empty in ${SECRETS_FILE}: ${missing[*]}"
        warn "Sentinel will install but the corresponding feature will be inert."
        if (( ! ASSUME_YES )); then
            read -r -p "Continui oricum? [da/NU] " answer
            [[ "$answer" == "da" ]] || die "aborted; run scripts/secrets-init.sh"
        fi
    fi
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
tar --exclude='./secrets' \
    --exclude='./.git' \
    --exclude='./tests' \
    --exclude='./docs' \
    --exclude='./watcher' \
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
# .gitattributes covers a git checkout; this catches everything else.
if command -v file >/dev/null && \
   grep -rlU $'\r' "${REPO_ROOT}/deploy" --include='*.sh' --include='*.service' 2>/dev/null | grep -q .; then
    die "CRLF line endings found under deploy/. Fix with:
    find deploy -type f \\( -name '*.sh' -o -name '*.service' -o -name '*.timer' \\) -exec sed -i 's/\\r\$//' {} +"
fi

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
# not prompt. Prime the credential cache over a separate interactive connection
# first; the ControlMaster keeps it warm for the real run.
if ! ssh_run "sudo -n true" 2>/dev/null; then
    info "caching sudo credentials (you will be asked once)"
    ssh -t "${SSH_OPTS[@]}" "${USER}@${HOST}" "sudo -v" \
        || die "sudo is not usable non-interactively. Either add a NOPASSWD rule for \
${USER}, or run sudo -v in your second SSH session and retry within the timeout."
fi

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
