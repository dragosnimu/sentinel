#!/usr/bin/env bash
#
# Go/no-go checks. Runs on the server. Changes nothing.
#
# Invoked automatically by install.sh, and standalone by
# `scripts/deploy.sh --dry-run`.
#
#   ./preflight.sh [--domain sentinel.exemplu.ro] [--web-port 8443]
#                  [--nginx-mode dedicated|shared]
#
# Exit codes:
#   0  clear to deploy
#   1  blocking failure — do not deploy
#   2  could not run the checks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DOMAIN=""
NGINX_MODE="dedicated"
ADMIN_IP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)   DOMAIN="${2:-}"; shift 2 ;;
        --web-port) SENTINEL_PUBLIC_PORT="${2:-}"; SENTINEL_PORTS=("$SENTINEL_PUBLIC_PORT" 8787 5432); shift 2 ;;
        --nginx-mode) NGINX_MODE="${2:-}"; shift 2 ;;
        # The client's address, captured before sudo — sudo scrubs SSH_CLIENT, so
        # by the time this script runs the variable is gone and the peer looks
        # local. The deploy wrapper reads it over a plain SSH call and passes it in.
        --admin-ip) ADMIN_IP="${2:-}"; shift 2 ;;
        --help|-h)  sed -n '2,15p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$NGINX_MODE" in
    dedicated) ;;
    shared)
        # In shared mode Sentinel binds no public port — nginx already owns 443
        # and forwards to 127.0.0.1:8787. Insisting that 8443 be free would fail
        # the preflight over a port the deployment is never going to touch.
        SENTINEL_PORTS=(8787 5432)
        ;;
    *) die "unknown --nginx-mode: ${NGINX_MODE} (expected 'dedicated' or 'shared')" ;;
esac

SURICATA_OK=0

section "Sistem"

# ---------------------------------------------------------------------------
# The same detection the installer uses, so preflight cannot pass on a host the
# installer would then refuse.
_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/distro.sh"
if [[ -r "$_lib" ]]; then
    # shellcheck disable=SC1090
    . "$_lib"
    if distro_detect && distro_supported; then
        ok "OS: ${DISTRO_PRETTY} (${DISTRO_FAMILY}-family)"
    else
        fail "OS is ${DISTRO_PRETTY:-unknown}. Sentinel installs on RHEL-family (AlmaLinux, Rocky, RHEL, CentOS Stream, Fedora) and Debian-family (Debian, Ubuntu) hosts."
    fi

    # systemd is not negotiable: the journald collector is how SSH brute-force
    # is seen at all, and every service ships as a unit.
    if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
        fail "systemd is required (journald is the primary log source)"
    fi

    if _py="$(python_find 2>/dev/null)"; then
        ok "Python: ${_py} ($("$_py" -V 2>&1))"
    else
        warn "no Python >= 3.${PYTHON_MIN_MINOR} yet — the installer will add one"
    fi
else
    fail "cannot read lib/distro.sh next to this script"
fi

if [[ "$(id -u)" -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        ok "sudo available without a password prompt"
    else
        warn "sudo will prompt for a password. The deploy uses a controlled TTY, \
so this works, but a passwordless sudo rule makes reruns smoother."
    fi
fi

# ---------------------------------------------------------------------------
section "Memorie — constrângerea principală pe acest server"

MEM_AVAIL="$(mem_available_mb)"
MEM_TOTAL="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
SWAP_TOTAL="$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)"

log "    MemTotal ${MEM_TOTAL} MB · MemAvailable ${MEM_AVAIL} MB · Swap ${SWAP_TOTAL} MB"

if (( MEM_AVAIL < 1500 )); then
    fail "MemAvailable is ${MEM_AVAIL} MB. Below 1500 MB this deployment will run out \
of memory, and the OOM killer picks whatever is largest — which on most servers is \
the application you are trying to protect. Add swap, free memory, or use a bigger host."
elif (( MEM_AVAIL < 2500 )); then
    warn "MemAvailable is ${MEM_AVAIL} MB. Suricata will be SKIPPED (it needs ~700 MB \
of headroom of its own). Sentinel runs in log-only mode, which is still genuinely \
useful — it just has no packet-level visibility."
else
    ok "memory headroom sufficient; Suricata will be installed"
    SURICATA_OK=1
fi

if (( SWAP_TOTAL == 0 )) && (( MEM_TOTAL < 8192 )); then
    warn "no swap configured on a ${MEM_TOTAL} MB host. A scanner spike has nowhere \
to go but the OOM killer. Consider a 2 GB swapfile."
fi

# ---------------------------------------------------------------------------
section "Spațiu pe disc"

for mount in / /var; do
    free_gb="$(disk_free_gb "$mount")"
    [[ -z "$free_gb" ]] && { warn "cannot read free space on ${mount}"; continue; }
    min=8; [[ "$mount" == "/" ]] && min=10
    if (( free_gb < min )); then
        fail "${mount}: ${free_gb} GB free, need ≥${min} GB (packages, PostgreSQL, \
event partitions, backups)"
    else
        ok "${mount}: ${free_gb} GB free"
    fi
done

# ---------------------------------------------------------------------------
section "Porturi"

for port in "${SENTINEL_PORTS[@]}"; do
    if port_free "$port"; then
        ok "port ${port} free"
    else
        owner="$(port_owner "$port")"
        unit="$(port_owner_unit "$port")"
        if [[ "$port" == "5432" ]]; then
            warn "port 5432 is in use by ${owner:-unknown} — an existing PostgreSQL. \
The installer will reuse it and create a separate 'sentinel' database and role."
        elif [[ "$unit" == sentinel-* ]]; then
            # Preflight has to run identically on a first install and on an
            # upgrade. On an upgrade the port is held by the previous version of
            # the very service being deployed, which is not a conflict — it is
            # the expected state. Reporting it as blocking told the operator to
            # stop Sentinel in order to deploy Sentinel.
            ok "port ${port} held by ${unit} — the running Sentinel; the installer restarts it"
        else
            fail "port ${port} is in use by ${owner:-unknown}. Sentinel needs it. \
Pick another with --web-port, or stop that service."
        fi
    fi
done

# ---------------------------------------------------------------------------
# 80 and 443 are NOT required, and Sentinel will not take them. But what owns
# them decides how a certificate can be obtained, so report it.
section "Porturile 80 și 443 — ale altcuiva"

for port in 80 443; do
    if port_free "$port"; then
        info "port ${port} liber (Sentinel nu îl folosește oricum)"
    else
        owner="$(port_owner "$port")"
        ok "port ${port} folosit de ${owner:-alt serviciu} — neatins"
    fi
done

owner80="$(port_owner 80)"
if [[ -z "$owner80" ]] && port_free 80; then
    warn "nimic nu ascultă pe :80. Provocarea HTTP-01 a lui certbot are nevoie de el, \
iar Sentinel nu îl deține — deci certificatul va avea nevoie de DNS-01, sau vei primi \
unul self-signed. Vezi docs/DEPLOYMENT.md §2.1."
elif grep -qi nginx <<< "$owner80"; then
    ok "nginx deține :80 — modul 'shared' este disponibil și e probabil alegerea mai bună"
    printf '\n'
    info "    --nginx-mode shared"
    info "      Sentinel devine un vhost pe nginx-ul existent, selectat prin server_name."
    info "      URL curat (fără port), redirect HTTP→HTTPS funcțional, și certificatul se"
    info "      emite normal fiindcă Sentinel servește singur provocarea ACME."
    info "      În schimb scrie în /etc/nginx/conf.d/, director partajat cu site-urile tale."
    info "      Instalarea rulează nginx -t înainte și după, și își șterge fișierele dacă"
    info "      le-a rupt — un config care nu validează nu are voie să rămână."
    printf '\n'
    info "    --nginx-mode dedicated  (implicit)"
    info "      Listener propriu pe :${SENTINEL_PUBLIC_PORT}. Nu atinge nimic din ce"
    info "      există, dar URL-ul conține portul, nu există redirect de la HTTP, portul"
    info "      trebuie deschis în firewall-ul providerului, iar certificatul are nevoie"
    info "      de webroot sau DNS-01."
    printf '\n'

    # nginx.conf validity matters much more in shared mode: a broken config there
    # affects every site on the host, not just Sentinel's.
    if nginx -t >/dev/null 2>&1; then
        ok "nginx -t trece acum — condiție necesară pentru modul shared"
    else
        fail "nginx -t EȘUEAZĂ deja, înainte ca Sentinel să atingă ceva. Modul shared va refuza să continue: nu adaugă un vhost la un nginx rupt. Repară configurația existentă."
    fi
else
    info "${owner80} deține :80. Pentru un certificat real, fie îl lași să servească"
    info "/.well-known/acme-challenge/ din /var/lib/letsencrypt (--cert-mode webroot),"
    info "fie folosești o provocare DNS-01. install.sh testează accesibilitatea"
    info "înainte să încerce, ca să nu consume din rate-limit-ul Let's Encrypt."
fi

# ---------------------------------------------------------------------------
section "Ce rulează deja pe acest server"

# Sentinel is being installed onto a server that presumably already does
# something. Whatever that is, installing a security agent must not break it.
# This records the baseline; install.sh compares against it afterwards and
# rolls back if anything that was running has stopped.
capture_baseline

running_count="$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | wc -l)"
listening_count="$(ss -tlnH 2>/dev/null | wc -l)"
log "    ${running_count} servicii active, ${listening_count} porturi în ascultare"

# Anything bound to a public address is an attack surface Sentinel will be
# expected to defend, so the operator should recognise every line here.
printf '\n    Servicii expuse public (0.0.0.0 sau ::):\n'
exposed="$(ss -tlnpH 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\[::\]|\*):/ {print $4, $6}' || true)"
if [[ -n "$exposed" ]]; then
    printf '      %s\n' "$exposed" | sed 's/users:((//; s/)).*//'
    warn "verifică lista de mai sus. Fiecare linie este o suprafață de atac pe care \
Sentinel o va monitoriza — dacă nu recunoști ceva, investighează înainte de deploy."
else
    info "niciun serviciu legat pe o adresă publică (în afară de ce vezi mai sus)"
fi

if have docker; then
    container_count="$(docker ps -q 2>/dev/null | wc -l)"
    if (( container_count > 0 )); then
        info "${container_count} containere Docker rulează; vor fi incluse în inventar și scanate"
    fi
fi

# ---------------------------------------------------------------------------
section "Firewall"

fw_state="$(systemctl is-active firewalld 2>/dev/null || true)"
if [[ "$fw_state" == "active" ]]; then
    if [[ "${ALLOW_FIREWALLD:-0}" == "1" ]]; then
        warn "firewalld is ACTIVE and --allow-firewalld was passed. Sentinel's nftables \
table coexists (priority -5, policy accept) and does not modify firewalld, but verify \
afterwards that port ${SENTINEL_PUBLIC_PORT} and every other service on this host are still reachable."
    else
        fail "firewalld is ACTIVE. Sentinel does not manage firewalld and will not enable, \
disable or modify it — its own table coexists alongside. Review your firewalld rules to \
confirm port ${SENTINEL_PUBLIC_PORT} is open, then re-run with --allow-firewalld."
    fi
else
    ok "firewalld inactive (as expected)"
fi

if have nft; then
    ok "nftables available"
    if nft list table inet sentinel >/dev/null 2>&1; then
        info "table inet sentinel already exists — the installer will reconcile it"
    fi
else
    fail "nft is not installed. dnf install nftables"
fi

# ---------------------------------------------------------------------------
section "Rețea și acces"

# Prefer the address the wrapper captured before sudo; fall back to the env,
# then to SSH_CLIENT (only present when this runs without sudo stripping it).
PEER="${ADMIN_IP:-$(ssh_peer_ip)}"
[[ -z "$PEER" ]] && PEER="${SENTINEL_ADMIN_IP:-}"
if [[ -n "$PEER" ]]; then
    ok "admin address for the allowlist: ${PEER} — it goes in before any drop rule"
else
    warn "cannot determine your admin address. sudo strips SSH_CLIENT, so if you \
ran this over plain SSH the wrapper should have passed --admin-ip. Set \
SENTINEL_ADMIN_IP before installing, or you will have no allowlisted address."
fi

for ip in $(public_ips); do
    info "local address: ${ip}"
done

for host in api.telegram.org api.anthropic.com; do
    if curl -s --max-time 8 -o /dev/null "https://${host}/" 2>/dev/null; then
        ok "${host} reachable"
    else
        warn "${host} not reachable. $( [[ $host == api.telegram.org ]] \
&& echo 'No alerts and no commands.' || echo 'AI analysis degrades to deterministic only.' )"
    fi
done

# ---------------------------------------------------------------------------
section "Volum de trafic (pentru filtrul Suricata)"

# Rather than guessing which flows to exclude, measure. A single high-volume
# flow with no security value — bulk telemetry, a syslog feed, backup
# replication — can fill the disk within hours if Suricata inspects it, and
# every host has different ones.
BPF_HINT=""
if (( SURICATA_OK )) && have tcpdump; then
    iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    iface="${iface:-eth0}"
    info "sampling ${iface} for 10 seconds to find the top talkers…"

    sample="$(mktemp)"
    timeout 12 tcpdump -ni "$iface" -c 4000 -q -t 2>/dev/null > "$sample" || true
    total="$(wc -l < "$sample")"

    if (( total > 0 )); then
        printf '    top surse în eșantion (%s pachete în ~10s):\n' "$total"
        top="$(awk '{print $2}' "$sample" | sed 's/\.[0-9]*$//' | sort | uniq -c | sort -rn | head -5)"
        printf '      %s\n' "$top"

        # If one source dominates, it is a strong candidate for exclusion.
        top_count="$(awk 'NR==1{print $1}' <<< "$top")"
        top_host="$(awk 'NR==1{print $2}' <<< "$top")"
        if [[ -n "$top_count" ]] && (( total > 500 )) && (( top_count * 100 / total > 60 )); then
            rate=$(( total * 6 ))
            warn "un singur flux domină traficul: ${top_host} (~$(( top_count * 100 / total ))% \
din ~${rate} pachete/minut)."
            warn "Dacă are volum mare și valoare de securitate mică (telemetrie, syslog, \
replicare backup), exclude-l — altfel Suricata umple discul:"
            warn "    suricata.bpf_filter: \"not host ${top_host}\""
            BPF_HINT="$top_host"
        else
            ok "niciun flux dominant; suricata.bpf_filter poate rămâne gol"
        fi
    else
        info "no traffic captured in the sample window"
    fi
    rm -f "$sample"
elif (( SURICATA_OK )); then
    info "tcpdump absent; skipping the traffic sample. Review suricata.bpf_filter by hand."
else
    info "Suricata is not being installed; the BPF filter is irrelevant"
fi

# ---------------------------------------------------------------------------
section "DNS și certificat"

if [[ -n "$DOMAIN" ]]; then
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
    if [[ -z "$resolved" ]]; then
        fail "${DOMAIN} does not resolve. certbot will fail. Create the A record and \
wait for propagation."
    elif public_ips | grep -qx "$resolved"; then
        ok "${DOMAIN} → ${resolved} (this host)"
    else
        fail "${DOMAIN} resolves to ${resolved}, which is not an address on this host. \
certbot's HTTP-01 challenge will fail."
    fi
else
    warn "no --domain given. The dashboard will use a self-signed certificate and every \
browser visit shows a warning."
fi

# ---------------------------------------------------------------------------
section "Dependențe"

if have python3.12; then
    ok "python3.12 present"
elif have python3 && [[ "$(python3 -c 'import sys; print(sys.version_info[:2] >= (3,12))')" == "True" ]]; then
    ok "python3 is $(python3 -V | cut -d' ' -f2)"
else
    info "python3.12 absent — the installer will dnf install it"
fi

for tool in curl tar systemctl ss awk; do
    have "$tool" || fail "${tool} is missing"
done

have docker && ok "docker present" || info "docker absent — container scanning will be skipped"

# ---------------------------------------------------------------------------
section "Integritatea pachetului de deploy"

# A CRLF in a .sh or .service file fails as `bad interpreter: /bin/bash^M`,
# which is a confusing 20 minutes if you have not seen it before. This is a real
# failure mode when the repo is authored on Windows.
crlf_files="$(grep -rlU $'\r' "${SCRIPT_DIR}" --include='*.sh' --include='*.service' \
    --include='*.timer' --include='*.nft' --include='*.conf' 2>/dev/null || true)"
if [[ -n "$crlf_files" ]]; then
    fail "CRLF line endings found — these files will not execute on Linux:"
    printf '        %s\n' $crlf_files >&2
    fail "Fix with: sed -i 's/\\r$//' <files>  (or re-clone with .gitattributes applied)"
else
    ok "line endings clean (LF)"
fi

# ---------------------------------------------------------------------------
section "Rezultat"

printf '\n'
if (( FAIL_COUNT > 0 )); then
    printf '%s%d verificare(i) blocante au eșuat, %d avertisment(e).%s\n' \
        "$_C_RED$_C_BOLD" "$FAIL_COUNT" "$WARN_COUNT" "$_C_RESET"
    printf 'NU se poate face deploy. Rezolvă cele de mai sus și rulează din nou.\n'
    exit 1
fi

printf '%sPreflight trecut.%s %d avertisment(e).\n' "$_C_GREEN$_C_BOLD" "$_C_RESET" "$WARN_COUNT"
printf 'Suricata:  %s\n' "$( (( SURICATA_OK )) && echo 'va fi instalată' || echo 'SĂRITĂ (RAM insuficient) — mod log-only' )"
if [[ "$NGINX_MODE" == "shared" ]]; then
    printf 'Dashboard: https://%s  (vhost pe nginx existent, fără port de deschis)\n' "${DOMAIN:-<host>}"
else
    printf 'Dashboard: https://%s:%s\n' "${DOMAIN:-<host>}" "${SENTINEL_PUBLIC_PORT}"
    printf '           portul %s trebuie deschis și în firewall-ul providerului\n' "${SENTINEL_PUBLIC_PORT}"
fi

# Consumed by install.sh so the RAM gate decision and the traffic sample are
# taken once rather than repeated per step.
mkdir -p "$STATE_MARKERS"
printf 'SURICATA_OK=%d\nMEM_AVAIL=%d\nADMIN_IP=%s\nDOMAIN=%s\nBPF_HINT=%s\nPUBLIC_PORT=%s\n' \
    "$SURICATA_OK" "$MEM_AVAIL" "${PEER}" "${DOMAIN}" "${BPF_HINT:-}" "${SENTINEL_PUBLIC_PORT}" \
    > "${STATE_MARKERS}/preflight.env"

exit 0
