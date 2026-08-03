#!/usr/bin/env bash
#
# Undo a Sentinel deployment.
#
#   ./rollback.sh [snapshot-dir] [--purge] [--yes]
#
# Without a snapshot directory it uses /var/backups/sentinel/predeploy-latest.
#
# What it does:
#   * stops and disables every sentinel-* unit
#   * deletes `table inet sentinel` — every block disappears immediately
#   * removes its nginx files; in dedicated mode also restores /etc/nginx from
#     the snapshot, in shared mode deliberately does NOT (that would revert your
#     own site changes made since the deploy)
#   * verifies nothing that was running before the install is still stopped
#   * reports what it deliberately left behind
#
# What it does NOT do, on purpose:
#   * revert package installs. Downgrading nginx or PostgreSQL to undo a
#     Sentinel deploy is far more dangerous than leaving them installed. The
#     packages are listed for you to act on if you want.
#   * drop the database, unless --purge. That database is the security history:
#     incidents, blocks, findings, patch audit trail. Deleting it to undo an
#     install is almost never what you want.
#
# This is also invoked automatically by install.sh when a health gate fails, or
# when a service that was running before the deploy has stopped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SNAPSHOT="${SENTINEL_BACKUP_DIR}/predeploy-latest"
PURGE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE=1; shift ;;
        --yes|-y) export SENTINEL_ASSUME_YES=1; shift ;;
        --help|-h) sed -n '2,30p' "$0"; exit 0 ;;
        -*) die "unknown argument: $1" ;;
        *) SNAPSHOT="$1"; shift ;;
    esac
done

need_root

section "Sentinel rollback"
log "  snapshot: ${SNAPSHOT}"
[[ -d "$SNAPSHOT" ]] || warn "snapshot directory not found — config restore will be skipped"
(( PURGE )) && warn "--purge given: the sentinel database WILL be dropped, including the \
full incident, blocklist, vulnerability and patch-audit history"

confirm "Continui cu rollback-ul?" || die "aborted"

# ---------------------------------------------------------------------------
section "1. Oprire servicii"

mapfile -t units < <(systemctl list-unit-files --no-legend 'sentinel-*' 2>/dev/null | awk '{print $1}')
if (( ${#units[@]} == 0 )); then
    info "no sentinel units installed"
else
    for unit in "${units[@]}"; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        ok "stopped and disabled ${unit}"
    done
    rm -f /etc/systemd/system/sentinel-*.service /etc/systemd/system/sentinel-*.timer
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
section "2. Firewall"

# Deleting the table removes every block at once. This is the fastest possible
# unblock and cannot fail partway: either the table exists or it does not.
if nft list table inet sentinel >/dev/null 2>&1; then
    blocked="$(nft list set inet sentinel blocklist_v4 2>/dev/null | grep -c 'elements' || echo 0)"
    nft delete table inet sentinel
    ok "table inet sentinel deleted — all blocks removed"
    [[ "$blocked" != "0" ]] && info "the blocklist was non-empty; those addresses are now unblocked"
else
    info "no sentinel nftables table present"
fi

# ---------------------------------------------------------------------------
section "3. nginx"

# Sentinel's own files, in either mode. Removing exactly these is always safe.
SENTINEL_NGINX_FILES=(
    /etc/nginx/conf.d/sentinel.conf
    /etc/nginx/conf.d/sentinel-shared.conf
    /etc/nginx/conf.d/sentinel-default-deny.conf
    /etc/nginx/conf.d/sentinel-security-headers.conf
    /etc/nginx/conf.d/sentinel-proxy-params.conf
)

# Which mode was installed decides how far the rollback may reach.
INSTALLED_MODE="dedicated"
if [[ -f /etc/nginx/conf.d/sentinel-shared.conf ]]; then
    INSTALLED_MODE="shared"
elif [[ -f "${SENTINEL_CONFIG_DIR}/sentinel.yaml" ]] \
     && grep -qE '^\s*nginx_mode:\s*shared' "${SENTINEL_CONFIG_DIR}/sentinel.yaml" 2>/dev/null; then
    INSTALLED_MODE="shared"
fi
info "nginx mode at install time: ${INSTALLED_MODE}"

rm -f "${SENTINEL_NGINX_FILES[@]}"
ok "Sentinel's nginx files removed"

if [[ "$INSTALLED_MODE" == "shared" ]]; then
    # DELIBERATELY does NOT restore the /etc/nginx snapshot.
    #
    # In shared mode Sentinel only ever added its own files to a directory it
    # shares with the operator's vhosts. Unpacking the pre-install tarball would
    # also revert any change they made to THEIR sites after the deploy — a
    # rollback of Sentinel silently rolling back their work. Removing our files
    # is the complete and correct undo here.
    info "shared mode: leaving the rest of /etc/nginx exactly as it is"
    info "  (restoring the pre-install snapshot would also revert changes you made"
    info "   to your own sites since the deploy — not ours to undo)"

    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        ok "nginx -t passes and nginx reloaded — your sites are unaffected"
    else
        nginx -t || true
        fail "nginx -t FAILS after removing Sentinel's files. That means something \
else in your configuration is broken — it is not Sentinel's vhost, which is gone. \
Do NOT restart nginx until nginx -t passes. The pre-install snapshot is at \
${SNAPSHOT}/nginx.tar if you need to compare."
    fi

elif [[ -f "${SNAPSHOT}/nginx.tar" ]]; then
    # Dedicated mode: Sentinel may have commented out nginx.conf's :80 listener,
    # so the full restore is the correct undo.
    tar -xf "${SNAPSHOT}/nginx.tar" -C /
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        ok "nginx configuration restored from the snapshot and reloaded"
    else
        # Leaving nginx broken would be worse than leaving Sentinel's vhost in
        # place, so say so loudly rather than reloading a config that fails.
        fail "the restored nginx config does not pass nginx -t. NOT reloading. \
Inspect /etc/nginx manually before touching anything else."
    fi
else
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
    warn "no nginx snapshot; removed Sentinel's vhost files only"
fi

# The certificate is deliberately left in place: it is valid, it cost a rate
# limit against Let's Encrypt to obtain, and removing it achieves nothing.
if [[ -n "${DOMAIN:-}" ]]; then
    info "Let's Encrypt certificate left intact. Remove with: certbot delete --cert-name <domain>"
fi

# ---------------------------------------------------------------------------
section "4. Configurație"

if [[ -f "${SNAPSHOT}/sentinel-config.tar" ]]; then
    rm -rf "$SENTINEL_CONFIG_DIR"
    tar -xf "${SNAPSHOT}/sentinel-config.tar" -C /
    ok "${SENTINEL_CONFIG_DIR} restored from the snapshot"
elif [[ -d "$SENTINEL_CONFIG_DIR" ]]; then
    # secrets.env is preserved. Deleting it means re-issuing an Anthropic key
    # and a bot token to redeploy, for no security benefit — the file is 0640
    # and the directory is going nowhere.
    if [[ -f "${SENTINEL_CONFIG_DIR}/secrets.env" ]]; then
        install -D -m 0600 -o root -g root "${SENTINEL_CONFIG_DIR}/secrets.env" \
            "${SENTINEL_BACKUP_DIR}/secrets.env.preserved"
        ok "secrets.env preserved at ${SENTINEL_BACKUP_DIR}/secrets.env.preserved (0600)"
    fi
    rm -rf "$SENTINEL_CONFIG_DIR"
    ok "${SENTINEL_CONFIG_DIR} removed"
fi

# ---------------------------------------------------------------------------
section "5. Fișiere"

rm -rf "${SENTINEL_PREFIX}/lib" "${SENTINEL_PREFIX}/libexec" "${SENTINEL_PREFIX}/venv" \
       "${SENTINEL_PREFIX}/claude-workspace" "${SENTINEL_PREFIX}/bin"
rm -f /usr/local/bin/sentinel
rm -f /usr/lib/tmpfiles.d/sentinel.conf
rm -rf /run/sentinel
ok "${SENTINEL_PREFIX} cleaned"

# State and backups survive: /var/lib/sentinel holds collector cursors, and
# /var/backups/sentinel holds restore points that may be the only way back from
# a patch applied before the rollback. (The install-step markers inside the state
# dir are cleared at the very end — after the baseline check below still needs
# them.)
info "kept ${SENTINEL_STATE_DIR} and ${SENTINEL_BACKUP_DIR} — restore points may still be needed"

# ---------------------------------------------------------------------------
section "6. Bază de date"

if (( PURGE )); then
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='sentinel'" 2>/dev/null | grep -q 1; then
        sudo -u postgres dropdb sentinel
        sudo -u postgres psql -c "DROP ROLE IF EXISTS sentinel" >/dev/null
        ok "database and role dropped"
    fi
else
    info "database left intact (use --purge to drop it). It holds the incident, \
blocklist, vulnerability and patch-audit history."
fi

# ---------------------------------------------------------------------------
section "7. Suricata"

if systemctl is-enabled suricata >/dev/null 2>&1; then
    warn "Suricata is still installed and enabled. Sentinel configured it; it will \
keep writing eve.json with nothing reading it. Disable with: \
systemctl disable --now suricata"
fi

# ---------------------------------------------------------------------------
section "8. Utilizator"

if getent passwd "$SENTINEL_USER" >/dev/null; then
    info "user ${SENTINEL_USER} left in place. Remove with: userdel ${SENTINEL_USER}"
fi

# ---------------------------------------------------------------------------
section "9. Servicii preexistente"

# The rollback itself must not break anything either. Compare against the same
# baseline the install used.
if [[ -f "${STATE_MARKERS}/baseline-services.txt" ]]; then
    assert_nothing_broken "after rollback" || \
        fail "Something that was running before Sentinel was installed is still not \
running after the rollback. Investigate now — compare with \
${STATE_MARKERS}/baseline-services.txt"
else
    info "no pre-install baseline recorded; cannot verify automatically"
    info "check by hand: systemctl --failed && ss -tlnp"
fi

# Done here, at the very end, because the baseline check above still needs the
# files in this directory. The install-step completion markers record what the
# rolled-back install did; leaving them would make a reinstall skip steps whose
# files this rollback just removed — a half-installed system that reports itself
# complete. Clearing them is what makes rollback + reinstall a reliable path.
if [[ -d "${STATE_MARKERS}" ]]; then
    rm -rf "${STATE_MARKERS}"
    ok "install-step markers cleared — a reinstall starts from a clean slate"
fi

# ---------------------------------------------------------------------------
section "Rollback complet"

cat <<EOF

  Rămase în urmă, deliberat:
    - pachete instalate (nginx, postgresql, nftables, certbot, python3.12)
      Lista dinainte de deploy: ${SNAPSHOT}/rpm.txt
    - ${SENTINEL_STATE_DIR} și ${SENTINEL_BACKUP_DIR}
    - certificatul Let's Encrypt
$( (( PURGE )) || echo "    - baza de date 'sentinel' (folosește --purge pentru a o șterge)" )

  Verifică:
    systemctl list-units 'sentinel-*'     # gol
    systemctl --failed                    # nimic picat
    nft list tables                       # fără 'inet sentinel'
    ss -tlnp | grep -E ':(8787|443|80)'

EOF

(( FAIL_COUNT > 0 )) && exit 1
exit 0
