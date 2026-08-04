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
#                [--admin-ip 1.2.3.4] [--from-step N] [--force-step N]
#                [--skip-preflight]
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

# Set in step_packages: whether nginx was on this host before we touched it.
# Decides whether editing nginx.conf is ours to do.
NGINX_WAS_PREEXISTING=0
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
        --yes|-y)         export SENTINEL_ASSUME_YES=1; shift ;;
        --help|-h)        sed -n '2,25p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

need_root

# Secrets from stdin, before anything else can consume it.
#
# When stdin is a pipe it belongs entirely to the secrets, which means there is
# no terminal left to prompt on. That is the normal path: deploy.sh has already
# shown the lockout warning and taken the operator's confirmation locally, so
# prompting again here would only deadlock on EOF.
declare -A SECRETS=()
if [[ ! -t 0 ]]; then
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        value="${value%\"}"; value="${value#\"}"
        SECRETS["$key"]="$value"
    done
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
    NGINX_WAS_PREEXISTING="${NGINX_WAS_PREEXISTING:-0}"

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

    # Stabilise the snapshot directory across resumes. SNAPSHOT_DIR is seeded from
    # a per-run timestamp, so a resumed process would point at a directory step 18
    # never created — breaking the nginx-config backup (step 33) and the automatic
    # rollback (step 38), both of which write to and read from it. If a prior run
    # already made the snapshot, its `predeploy-latest` symlink is the truth.
    local latest="${SENTINEL_BACKUP_DIR}/predeploy-latest"
    if [[ -L "$latest" ]]; then
        local resolved; resolved="$(readlink -f "$latest" 2>/dev/null || true)"
        [[ -n "$resolved" && -d "$resolved" ]] && SNAPSHOT_DIR="$resolved"
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
    if getent group docker >/dev/null; then
        info "adding ${SENTINEL_USER} to the docker group for container inventory."
        warn "docker group membership is effectively root. It is required for \
container scanning; remove it and set scan.containers=false if you would rather not."
        usermod -aG docker "$SENTINEL_USER"
    fi
}

# --- 20 -------------------------------------------------------------------
step_packages() {
    # Recorded BEFORE the install, because it decides whether nginx.conf is ours
    # to edit later. If nginx was already serving the operator's sites, its
    # config belongs to them.
    if pkg_installed nginx || systemctl is-active --quiet nginx 2>/dev/null; then
        NGINX_WAS_PREEXISTING=1
        printf 'NGINX_WAS_PREEXISTING=1
' >> "${STATE_MARKERS}/preflight.env"
        info "nginx is already installed here — its configuration will not be modified"
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

    # Shared roles, per-family names. `systemd-devel` / `libsystemd-dev` matter
    # most: systemd-python is a C extension built at pip time, and without the
    # headers the venv step dies with "Package 'libsystemd' ... not found".
    local pkgs=()
    while read -r p; do pkgs+=("$p"); done < <(pkg_names_core)
    pkg_install "${pkgs[@]}" || die "package installation failed"

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
step_external_tools() {
    # Never `curl | bash`. Every external binary is downloaded, checksummed
    # against a pinned value, and only then installed — a security tool that
    # pipes the internet into a shell has no business auditing anything.
    local manifest="${SCRIPT_DIR}/tools/manifest.txt"
    if [[ ! -f "$manifest" ]]; then
        warn "no tools manifest at ${manifest}; skipping Trivy/nuclei. \
Vulnerability scanning (P7) will not be available until they are installed."
        return 0
    fi

    local name url sha
    while read -r name url sha; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        if have "$name"; then ok "${name} already installed"; continue; fi

        local tmp="/tmp/sentinel-${name}.tar.gz"
        info "downloading ${name}"
        curl -fsSL --max-time 120 -o "$tmp" "$url" || { warn "download failed: ${name}"; continue; }
        if ! echo "${sha}  ${tmp}" | sha256sum -c --status; then
            rm -f "$tmp"
            fail "checksum mismatch for ${name}. Refusing to install. This is either a \
corrupted download or a compromised mirror — do not work around it."
            continue
        fi
        tar -xzf "$tmp" -C /usr/local/bin "$name" 2>/dev/null \
            || tar -xzf "$tmp" -C /usr/local/bin
        chmod 0755 "/usr/local/bin/${name}" 2>/dev/null || true
        rm -f "$tmp"
        ok "${name} installed"
    done < "$manifest"
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
step_configs() {
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

    sed -e "s|@@DOMAIN@@|${DOMAIN}|g" \
        -e "s|@@HOSTNAME@@|${hostname_fqdn}|g" \
        -e "s|@@NGINX_MODE@@|${NGINX_MODE}|g" \
        -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
        -e "s|@@IFACE@@|${iface}|g" \
        -e "s|@@BPF_FILTER@@|${bpf}|g" \
        -e "s|@@SURICATA_ENABLED@@|$( (( SURICATA_OK )) && echo true || echo false )|g" \
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

    install -D -m 0644 "${SCRIPT_DIR}/logrotate/sentinel" /etc/logrotate.d/sentinel

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

# Read a key out of the secrets file already on disk, if there is one.
existing_secret() {
    local target="${SENTINEL_CONFIG_DIR}/secrets.env" key="$1"
    [[ -r "$target" ]] || return 1
    local line
    line="$(grep -m1 "^${key}=" "$target" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

step_secrets() {
    local target="${SENTINEL_CONFIG_DIR}/secrets.env"

    # Create with the right mode BEFORE any content exists. Writing first and
    # chmod'ing after leaves a window in which the file is world-readable.
    ( umask 077; : > "${target}.tmp" )
    chown "root:${SENTINEL_USER}" "${target}.tmp"
    chmod 0640 "${target}.tmp"

    local key value kept=0 made=0
    {
        echo "# Generated by install.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Mode 0640 root:sentinel. Never commit, never copy, never echo."

        # Operator-supplied values. Precedence: what was just handed to us wins,
        # then whatever is already on disk. An upgrade run that supplies no
        # secrets must not erase the ones that are working.
        for key in ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID \
                   SENTINEL_DB_PASSWORD TELEGRAM_APPLY_PIN; do
            value="${SECRETS[$key]:-}"
            [[ -z "$value" ]] && value="$(existing_secret "$key" || true)"
            [[ -n "$value" ]] && printf '%s=%s\n' "$key" "$value"
        done

        # Host-generated keys. Kept if they exist, in any form, from anywhere.
        for key in "${GENERATED_SECRET_KEYS[@]}"; do
            value="${SECRETS[$key]:-}"
            [[ -z "$value" ]] && value="$(existing_secret "$key" || true)"
            if [[ -n "$value" ]]; then
                kept=$((kept + 1))
            else
                value="$(openssl rand -hex 32)"
                made=$((made + 1))
            fi
            printf '%s=%s\n' "$key" "$value"
        done
    } >> "${target}.tmp"

    mv "${target}.tmp" "$target"
    ok "secrets written to ${target} (0640 root:${SENTINEL_USER})"
    (( kept )) && ok "kept ${kept} existing key(s) — TOTP enrolments stay valid"
    if (( made )); then
        warn "generated ${made} new key(s). If this host had TOTP enrolments"
        warn "from an older secret, they must be re-enrolled:"
        warn "    sudo sentinel web --enroll-totp --username <user>"
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

        if systemctl is-active --quiet "$unit"; then
            ok "${unit} active"
        else
            journalctl -u "$unit" -n 30 --no-pager >&2
            die "${unit} did not stay running. Nothing further will be started."
        fi
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
}

# --- 33 -------------------------------------------------------------------
step_nginx() {
    # The vhost `include`s both of these. Installing the vhost without them
    # makes `nginx -t` fail with a confusing "open() failed" before certbot ever
    # gets a chance to run.
    install -D -m 0644 "${SCRIPT_DIR}/nginx/sentinel-security-headers.conf" \
        /etc/nginx/conf.d/sentinel-security-headers.conf
    install -D -m 0644 "${SCRIPT_DIR}/nginx/sentinel-proxy-params.conf" \
        /etc/nginx/conf.d/sentinel-proxy-params.conf

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
    if ! port_free 80 && [[ "${NGINX_WAS_PREEXISTING:-0}" != "1" ]]; then
        local owner80; owner80="$(port_owner 80)"
        info "port 80 is held by ${owner80:-another service}; neutralising nginx.conf's :80 listener"

        cp -a /etc/nginx/nginx.conf "${SNAPSHOT_DIR}/nginx.conf.orig" 2>/dev/null || true

        # Idempotent: the marker means a re-run does not double-comment.
        if ! grep -q 'SENTINEL-DISABLED' /etc/nginx/nginx.conf; then
            sed -i -E 's|^([[:space:]]*)(listen[[:space:]]+(\[::\]:)?80;)|\1# SENTINEL-DISABLED \2|' \
                /etc/nginx/nginx.conf
            ok "nginx.conf :80 listener commented out (original in the snapshot)"
        fi
    elif ! port_free 80; then
        warn "port 80 is in use and nginx was already installed here. Not touching \
nginx.conf — it is yours. If nginx fails to start, a server block in it is \
competing for :80."
    fi

    local conf=/etc/nginx/conf.d/sentinel.conf
    sed -e "s|@@DOMAIN@@|${DOMAIN:-_}|g" \
        -e "s|@@PORT@@|8787|g" \
        -e "s|@@PUBLIC_PORT@@|${PUBLIC_PORT}|g" \
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
    systemctl reload nginx

    obtain_certificate
}

# ---------------------------------------------------------------------------
# Shared mode: Sentinel as a vhost on the operator's existing nginx
# ---------------------------------------------------------------------------
SENTINEL_NGINX_FILES=(
    /etc/nginx/conf.d/sentinel-shared.conf
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

    install -D -m 0644 "${SCRIPT_DIR}/nginx/sentinel-security-headers.conf" \
        /etc/nginx/conf.d/sentinel-security-headers.conf
    install -D -m 0644 "${SCRIPT_DIR}/nginx/sentinel-proxy-params.conf" \
        /etc/nginx/conf.d/sentinel-proxy-params.conf

    ensure_placeholder_certificate

    sed -e "s|@@DOMAIN@@|${DOMAIN}|g" \
        -e "s|@@PORT@@|8787|g" \
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

    systemctl reload nginx || die "nginx reload failed"
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
    local cert=/etc/pki/tls/certs/sentinel-selfsigned.crt
    local key=/etc/pki/tls/private/sentinel-selfsigned.key
    [[ -f "$cert" ]] && return 0

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
    systemctl reload nginx
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
step_suricata() {
    if (( ! SURICATA_OK )); then
        info "Suricata skipped (RAM gate). Sentinel runs log-only."
        return 0
    fi
    pkg_install "$(suricata_pkg)" || { warn "suricata install failed; continuing log-only"; return 0; }

    # We do NOT replace the distro suricata.yaml — it is complete and passes -T.
    # Everything site-specific is layered on top via OPTIONS, a BPF file, a
    # drop-in and an ACL, so an upgrade of the package never clobbers our config.
    local iface bpf pubip options
    iface="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
    iface="${iface:-eth0}"
    pubip="$(public_ips 2>/dev/null | head -1)"

    # Inspecting a high-volume, low-value flow is the fastest way to fill the
    # disk. Preflight flags the dominant one; exclude it in the kernel BPF so
    # Suricata never even sees those packets.
    bpf=""
    [[ -n "${BPF_HINT:-}" ]] && bpf="not host ${BPF_HINT}"
    options="--af-packet=${iface}"
    if [[ -n "${bpf}" ]]; then
        printf '%s\n' "${bpf}" > /etc/suricata/capture-filter.bpf
        options+=" -F /etc/suricata/capture-filter.bpf"
        info "Suricata BPF excludes: ${bpf}"
    fi
    # HOME_NET must include this host's public address or inbound-attack rules
    # (EXTERNAL_NET -> HOME_NET) never match. The distro default is RFC1918 only.
    [[ -n "${pubip}" ]] && options+=" --set vars.address-groups.HOME_NET=[${pubip}]"

    printf 'OPTIONS="%s"\n' "${options}" > "$(suricata_defaults_file)"

    # A NIDS on a small VPS must have a ceiling, or a rule explosion OOM-kills
    # whatever it was meant to protect.
    install -d -m 0755 /etc/systemd/system/suricata.service.d
    printf '[Service]\nMemoryMax=1G\nRestart=on-failure\nRestartSec=5\n' \
        > /etc/systemd/system/suricata.service.d/sentinel.conf
    systemctl daemon-reload

    # The unprivileged ingest daemon reads eve.json. A per-user ACL grants
    # exactly read, and a default ACL keeps it working across logrotate.
    install -d -m 0750 /var/log/suricata
    if have setfacl; then
        setfacl -R -m u:"${SENTINEL_USER}":rX /var/log/suricata 2>/dev/null || true
        setfacl -R -d -m u:"${SENTINEL_USER}":rX /var/log/suricata 2>/dev/null || true
    fi

    suricata-update >/dev/null 2>&1 || warn "suricata-update failed; using shipped rules"
    # shellcheck disable=SC2086
    suricata -T -c /etc/suricata/suricata.yaml ${options} || die "suricata config test failed"

    systemctl enable --now suricata
    ok "Suricata running (IDS on ${iface}, MemoryMax=1G)"
}

# --- 36 -------------------------------------------------------------------
step_auxiliary() {
    if [[ -f "${SCRIPT_DIR}/audit/sentinel.rules" ]]; then
        install -D -m 0640 "${SCRIPT_DIR}/audit/sentinel.rules" /etc/audit/rules.d/sentinel.rules
        augenrules --load 2>/dev/null || warn "could not reload audit rules"
        ok "auditd rules installed"
    fi
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
step_smoke_test() {
    "${SENTINEL_PREFIX}/bin/sentinel" config-check -v || warn "config-check reported problems"

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
step_notify() {
    # Receiving this message IS the end-to-end proof: config loaded, secrets
    # readable, network egress works, the bot token is valid, the chat id is
    # right. A green install log proves much less.
    "${SENTINEL_PREFIX}/bin/sentinel" telegram --send-test \
        --message "Sentinel $(cat "${SENTINEL_PREFIX}/VERSION") instalat pe $(hostname -f). Dashboard: https://${DOMAIN:-<fara domeniu>}" \
        2>/dev/null && ok "Telegram test message sent" \
        || info "Telegram test not available in this build (arrives in P4)"
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
    run_step 20 packages          step_packages
    run_step 21 external_tools    step_external_tools
    run_step 22 postgres          step_postgres
    run_step 23 venv              step_venv
    run_step 24 package           step_package
    run_step 25 claude_workspace  step_claude_workspace
    run_step 26 configs           step_configs
    run_step 27 secrets           step_secrets
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
    run_step 36 auxiliary         step_auxiliary
    run_step 37 smoke_test        step_smoke_test
    run_step 38 verify_intact     step_verify_nothing_broken
    run_step 39 notify            step_notify

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
