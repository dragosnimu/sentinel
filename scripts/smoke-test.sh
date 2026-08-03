#!/usr/bin/env bash
#
# Post-deploy verification. Read-only: it checks, it does not fix.
#
#   ./scripts/smoke-test.sh --host 203.0.113.10 --user deploy \
#       --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro \
#       [--nginx-mode shared | --web-port 8443]
#
# The most important check here is the last one. Sentinel is a guest on this
# server; a deployment that installs Sentinel perfectly and stops something the
# host was already doing is a failed deployment.

set -euo pipefail

HOST=""; USER=""; KEY=""; PORT=22; DOMAIN=""
# The dashboard's public HTTPS port. Not 443 — this host serves something else there.
WEB_PORT=8443
# dedicated = own listener on WEB_PORT; shared = a vhost on the existing nginx,
# in which case the URL has no port suffix.
NGINX_MODE=dedicated
PASS=0; FAIL=0; WARN=0

_G=$'\033[32m'; _R=$'\033[31m'; _Y=$'\033[33m'; _B=$'\033[34m'; _0=$'\033[0m'

pass() { PASS=$((PASS+1)); printf '%s[+]%s %s\n' "$_G" "$_0" "$*"; }
fail() { FAIL=$((FAIL+1)); printf '%s[x]%s %s\n' "$_R" "$_0" "$*"; }
warn() { WARN=$((WARN+1)); printf '%s[!]%s %s\n' "$_Y" "$_0" "$*"; }
sect() { printf '\n%s== %s ==%s\n' "$_B" "$*" "$_0"; }
die()  { printf '%serror:%s %s\n' "$_R" "$_0" "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)   HOST="${2:-}"; shift 2 ;;
        --user)   USER="${2:-}"; shift 2 ;;
        --key)    KEY="${2:-}"; shift 2 ;;
        --port)   PORT="${2:-}"; shift 2 ;;
        --domain)   DOMAIN="${2:-}"; shift 2 ;;
        --web-port)   WEB_PORT="${2:-}"; shift 2 ;;
        --nginx-mode) NGINX_MODE="${2:-}"; shift 2 ;;
        --help|-h) sed -n '2,12p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$HOST" && -n "$USER" ]] || die "--host and --user are required"

# In shared mode the dashboard is on 443 and the URL carries no port. Building
# the base URL once means every check below is automatically mode-correct.
if [[ "$NGINX_MODE" == "shared" ]]; then
    WEB_PORT=443
    URL_SUFFIX=""
else
    URL_SUFFIX=":${WEB_PORT}"
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p "$PORT")
[[ -n "$KEY" ]] && SSH_OPTS+=(-i "${KEY/#\~/$HOME}")
r() { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@" 2>/dev/null; }

printf '%sSentinel smoke test — %s%s\n' "$_B" "$HOST" "$_0"

# ---------------------------------------------------------------------------
sect "Servicii"

for unit in sentinel-executor sentinel-web; do
    state="$(r "systemctl is-active ${unit}" || true)"
    case "$state" in
        active)   pass "${unit} active" ;;
        inactive) fail "${unit} inactive — journalctl -u ${unit} -n 50" ;;
        failed)   fail "${unit} FAILED — journalctl -u ${unit} -n 50" ;;
        *)        warn "${unit} not installed in this build" ;;
    esac
done

for timer in sentinel-watchdog.timer sentinel-health.timer sentinel-maintenance.timer; do
    if [[ "$(r "systemctl is-active ${timer}" || true)" == "active" ]]; then
        pass "${timer} active"
    else
        # The watchdog is the anti-lockout deadman. Without it, a self-inflicted
        # block has no automatic way out.
        [[ "$timer" == sentinel-watchdog.timer ]] \
            && fail "${timer} NOT ACTIVE — the anti-lockout watchdog is not running" \
            || warn "${timer} not active"
    fi
done

# ---------------------------------------------------------------------------
sect "Bază de date"

if [[ "$(r "sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname='sentinel'\"" || true)" == "1" ]]; then
    pass "database 'sentinel' exists"
    tables="$(r "sudo -u postgres psql -tAc \"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'\" sentinel" || echo 0)"
    (( tables > 20 )) && pass "schema present (${tables} tables)" \
                      || fail "only ${tables} tables — migrations may not have run"
    version="$(r "sudo -u postgres psql -tAc 'SELECT max(version) FROM schema_version' sentinel" || echo '?')"
    pass "schema version ${version}"
else
    fail "database 'sentinel' not found"
fi

# ---------------------------------------------------------------------------
sect "Firewall"

if r "sudo nft list table inet sentinel" | grep -q 'table inet sentinel'; then
    pass "table inet sentinel loaded"

    # policy accept is the property that stops Sentinel locking anyone out by
    # failing. If this is ever `drop`, stop and investigate before anything else.
    if r "sudo nft list chain inet sentinel input" | grep -q 'policy accept'; then
        pass "base chain policy is accept (deny-lister, not a firewall)"
    else
        fail "base chain policy is NOT accept. Sentinel is a deny-lister; a drop \
policy here means a bug or a manual edit, and it CAN lock you out."
    fi

    allow_n="$(r "sudo nft list set inet sentinel allowlist_v4" | grep -oP 'elements = \{\K[^}]*' | tr ',' '\n' | grep -c . || echo 0)"
    (( allow_n > 0 )) && pass "allowlist has ${allow_n} entries" \
                      || fail "allowlist is EMPTY — nothing protects you from a bad block"

    block_n="$(r "sudo nft list set inet sentinel blocklist_v4" | grep -oP 'elements = \{\K[^}]*' | tr ',' '\n' | grep -c . || echo 0)"
    printf '    blocklist: %s entries\n' "$block_n"

    # Blocking Sentinel's own alerting or analysis endpoints would be silent:
    # no error, no alert, just a system that has stopped telling anyone anything.
    for endpoint in api.telegram.org api.anthropic.com; do
        ip="$(r "getent ahostsv4 ${endpoint} | awk 'NR==1{print \$1}'" || true)"
        [[ -z "$ip" ]] && continue
        r "sudo nft list set inet sentinel allowlist_v4" | grep -q "$ip" \
            && pass "${endpoint} (${ip}) allowlisted" \
            || warn "${endpoint} (${ip}) not in the allowlist — a block there would silence alerting"
    done
else
    fail "nftables table not loaded"
fi

# ---------------------------------------------------------------------------
sect "Dashboard"

code="$(r "curl -sk -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8787/healthz" || echo 000)"
[[ "$code" =~ ^(200|401|302|503)$ ]] && pass "app answers on 127.0.0.1:8787 (HTTP ${code})" \
                                     || fail "app did not answer on 8787 (got ${code})"

# nginx in front of it, still over loopback. Separating this from the external
# check below means a failure names the layer that is wrong, rather than just
# saying "unreachable".
code="$(r "curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1:${WEB_PORT}/healthz" || echo 000)"
[[ "$code" =~ ^(200|401|302|503)$ ]] && pass "nginx serving on :${WEB_PORT} (HTTP ${code})" \
                                     || fail "nginx did not answer on :${WEB_PORT} (got ${code})"

if r "nginx -t"; then pass "nginx config valid"; else fail "nginx -t failed"; fi

if [[ -n "$DOMAIN" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://${DOMAIN}${URL_SUFFIX}/healthz" || echo 000)"
    if [[ "$code" =~ ^(200|401|302)$ ]]; then
        pass "reachable from outside at https://${DOMAIN}${URL_SUFFIX} (HTTP ${code})"
    elif [[ "$code" == "000" ]]; then
        fail "https://${DOMAIN}${URL_SUFFIX}/healthz did not connect. If the loopback \
check above passed, port ${WEB_PORT} is blocked by the provider firewall or DNS is \
not pointing here yet — Sentinel itself is fine."
    else
        fail "https://${DOMAIN}${URL_SUFFIX}/healthz returned ${code}"
    fi

    if curl -s --max-time 15 -o /dev/null "https://${DOMAIN}${URL_SUFFIX}/" 2>/dev/null; then
        pass "TLS certificate valid (no --insecure needed)"
        days="$(echo | openssl s_client -servername "$DOMAIN" -connect "${DOMAIN}:${WEB_PORT}" 2>/dev/null \
                | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
        [[ -n "$days" ]] && printf '    expires: %s\n' "$days"
    else
        warn "TLS certificate is not trusted — self-signed, or certbot has not run"
    fi

    hdrs="$(curl -sk -I --max-time 10 "https://${DOMAIN}${URL_SUFFIX}/" 2>/dev/null || true)"
    for h in Content-Security-Policy Strict-Transport-Security X-Frame-Options; do
        grep -qi "^${h}:" <<< "$hdrs" && pass "${h} present" || warn "${h} missing"
    done

    # Only the named vhost may reach the dashboard. What "correct" looks like
    # depends on the mode, and conflating the two would produce a false failure.
    #
    #   dedicated — Sentinel's port serves nothing but Sentinel's vhost, so a
    #               bare-IP or unknown-Host request must get no response at all.
    #   shared    — port 443 is shared with the operator's sites, so a bare-IP
    #               request SHOULD reach whichever of their vhosts is the default.
    #               That is correct and expected. What must not happen is it
    #               reaching Sentinel.
    body="$(curl -sk --max-time 10 -H 'Host: not-sentinel.invalid' \
        "https://${HOST}${URL_SUFFIX}/login" 2>/dev/null | head -c 4000 || true)"
    bare="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
        -H 'Host: not-sentinel.invalid' "https://${HOST}${URL_SUFFIX}/" 2>/dev/null || echo 000)"

    if grep -qi 'sentinel' <<< "$body"; then
        fail "a request with an UNKNOWN Host header returns Sentinel's dashboard \
(HTTP ${bare}). A bare-IP scan would find the login page, advertising that a security \
dashboard lives here and where to aim a credential attack."
        if [[ "$NGINX_MODE" == "shared" ]]; then
            fail "  Fix it in YOUR vhost: add default_server to its listen directives."
        else
            fail "  The catch-all deny is missing, or another vhost claims default_server \
on :${WEB_PORT}."
        fi
    elif [[ "$NGINX_MODE" == "shared" ]]; then
        # Reaching their site here is the right answer, not a problem.
        pass "an unknown Host does not reach Sentinel (HTTP ${bare} — your own vhost answered)"
    elif [[ "$bare" == "000" || "$bare" == "444" ]]; then
        pass "unknown Host refused with no response"
    else
        warn "unknown Host returned ${bare} on Sentinel's dedicated port; expected no \
response. It is not Sentinel's dashboard, but check what is answering."
    fi
fi

# ---------------------------------------------------------------------------
sect "Configurație și secrete"

r "sudo /opt/sentinel/bin/sentinel config-check" >/dev/null 2>&1 \
    && pass "config-check passed" \
    || warn "config-check reported problems — run it on the server for detail"

perms="$(r "stat -c '%a %U:%G' /etc/sentinel/secrets.env" || echo '')"
if [[ "$perms" == "640 root:sentinel" ]]; then
    pass "secrets.env is 640 root:sentinel"
else
    fail "secrets.env has permissions '${perms}', expected '640 root:sentinel'"
fi

# Observe mode is the intended state for the first 72 hours.
if r "grep -A2 'auto_block:' /etc/sentinel/sentinel.yaml" | grep -q 'enabled: false'; then
    pass "auto_block disabled (observe mode — the intended first-72h state)"
else
    warn "auto_block is ENABLED. Confirm you have finished tuning; an untuned \
auto-block takes out uptime monitors, ACME validators and your own mobile address."
fi

# ---------------------------------------------------------------------------
sect "Resurse"

mem="$(r "awk '/MemAvailable/ {print int(\$2/1024)}' /proc/meminfo" || echo 0)"
if   (( mem < 500 ));  then fail "MemAvailable ${mem} MB — critical. The OOM killer will pick the largest process, usually the application rather than Sentinel."
elif (( mem < 1024 )); then warn "MemAvailable ${mem} MB — tight"
else                        pass "MemAvailable ${mem} MB"
fi

disk="$(r "df --output=pcent / | tail -1 | tr -dc '0-9'" || echo 0)"
(( disk > 85 )) && fail "root filesystem ${disk}% full" || pass "root filesystem ${disk}% used"

# ---------------------------------------------------------------------------
sect "Regresie — ce rula înainte de instalare"

# The check that matters most. Sentinel installing correctly while stopping
# something the server was already doing is a failed deployment, not a partial
# success — and the operator would find out from their users, not from here.
baseline_dir=/var/lib/sentinel/.install-state

if r "test -f ${baseline_dir}/baseline-services.txt"; then
    lost="$(r "comm -23 ${baseline_dir}/baseline-services.txt \
<(systemctl list-units --type=service --state=running --no-legend --plain | awk '{print \$1}' | sort) \
| grep -v '^sentinel-'" || true)"
    if [[ -z "$lost" ]]; then
        pass "every service that was running before the install is still running"
    else
        fail "services stopped since the install: $(tr '\n' ' ' <<< "$lost")"
    fi

    lost_ports="$(r "comm -23 ${baseline_dir}/baseline-ports.txt \
<(ss -tlnH | awk '{print \$4}' | sed 's/.*://' | sort -un)" || true)"
    if [[ -z "$lost_ports" ]]; then
        pass "every port that was listening before the install still is"
    else
        fail "ports closed since the install: $(tr '\n' ' ' <<< "$lost_ports")"
    fi
else
    warn "no pre-install baseline at ${baseline_dir} — cannot verify automatically. \
Check by hand: systemctl --failed"
fi

failed_units="$(r "systemctl --failed --no-legend --plain | awk '{print \$1}'" || true)"
if [[ -z "$failed_units" ]]; then
    pass "no failed systemd units"
else
    fail "failed units: $(tr '\n' ' ' <<< "$failed_units")"
fi

if r "command -v docker >/dev/null"; then
    unhealthy="$(r "docker ps --filter health=unhealthy --format '{{.Names}}'" || true)"
    [[ -z "$unhealthy" ]] && pass "no unhealthy containers" \
                          || fail "unhealthy containers: $(tr '\n' ' ' <<< "$unhealthy")"
fi

# ---------------------------------------------------------------------------
printf '\n%s== Rezultat ==%s\n' "$_B" "$_0"
printf '  %s%d trecute%s · %s%d avertismente%s · %s%d eșuate%s\n\n' \
    "$_G" "$PASS" "$_0" "$_Y" "$WARN" "$_0" "$_R" "$FAIL" "$_0"

if (( FAIL > 0 )); then
    printf '%sVerificări eșuate. Nu considera deployment-ul reușit.%s\n' "$_R" "$_0"
    exit 1
fi
printf '%sSentinel funcționează, nimic altceva nu a fost afectat.%s\n' "$_G" "$_0"
