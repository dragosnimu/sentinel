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
# Distinge „operatorul a cerut dedicated" de „nimeni nu a spus nimic".
MODE_GIVEN=0
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
        --nginx-mode) NGINX_MODE="${2:-}"; MODE_GIVEN=1; shift 2 ;;
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

# Numără elementele unui set nftables fără `grep -P`.
#
# `grep -P` este o extensie GNU, și acest grep rulează LOCAL — pe Git Bash cu un
# locale non-UTF-8 refuză să pornească. Rezultatul a fost „allowlist is EMPTY"
# raportat pe un allowlist populat, adică fix alarma falsă care te învață să nu
# mai citești raportul.
#
# Întoarce "?" când nft nu a răspuns deloc, ca apelantul să poată deosebi „setul
# e gol" de „nu am putut citi". Confuzia dintre cele două a produs eșecul fals.
count_set_elements() {
    local raw; raw="$(r "sudo nft list set inet sentinel $1" || true)"
    [[ -z "$raw" ]] && { printf '?'; return; }
    printf '%s' "$raw" | tr -d '\n' | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' \
        | tr ',' '\n' | sed 's/[[:space:]]//g' | grep -c . || printf '0'
}

printf '%sSentinel smoke test — %s%s\n' "$_B" "$HOST" "$_0"

# ---------------------------------------------------------------------------
# What the server actually has, before checking anything against it.
#
# The flags above are what the OPERATOR believes is deployed. sentinel.yaml is
# what IS deployed. When they disagree, every check below is aimed at the wrong
# port and reports failures that say nothing about the system — "nginx did not
# answer on :8443" on a host running shared mode, where nothing was ever meant
# to listen there.
#
# Reading the deployed values also makes this script answer the question you
# need before a re-deploy: install.sh does not persist nginx_mode, so a re-run
# without --nginx-mode silently reverts to `dedicated` and the nginx step
# rewrites the vhost of a working dashboard.
sect "Configurația instalată"

deployed_mode="$(r "sudo grep -E '^[[:space:]]*nginx_mode:' /etc/sentinel/sentinel.yaml | head -1 | awk '{print \$2}' | tr -d \\\"\\'" || true)"
deployed_domain="$(r "sudo grep -E '^[[:space:]]*domain:' /etc/sentinel/sentinel.yaml | head -1 | awk '{print \$2}' | tr -d \\\"\\'" || true)"
# Doar `public_port`. Un `port:` generic prinde întâi portul PostgreSQL, care e
# tot în fișier — raporta port=5432 pentru dashboard.
deployed_port="$(r "sudo grep -E '^[[:space:]]*public_port:' /etc/sentinel/sentinel.yaml | head -1 | awk '{print \$2}'" || true)"

if [[ -n "$deployed_mode" ]]; then
    pass "nginx_mode=${deployed_mode} domain=${deployed_domain:-<none>} port=${deployed_port:-?}"
    # Doar când operatorul a afirmat EXPLICIT altceva. Comparând cu valoarea
    # implicită, avertismentul apărea la fiecare rulare fără flag — zgomot care
    # ar face un dezacord real să treacă neobservat.
    if (( MODE_GIVEN )) && [[ "$NGINX_MODE" != "$deployed_mode" ]]; then
        warn "ai dat --nginx-mode ${NGINX_MODE}, dar serverul are ${deployed_mode} — folosesc ce e pe server"
    fi
    NGINX_MODE="$deployed_mode"
    [[ -z "$DOMAIN" && -n "$deployed_domain" ]] && DOMAIN="$deployed_domain"
    if [[ "$NGINX_MODE" == "shared" ]]; then
        WEB_PORT=443; URL_SUFFIX=""
    else
        [[ -n "$deployed_port" ]] && WEB_PORT="$deployed_port"
        URL_SUFFIX=":${WEB_PORT}"
    fi
    printf '    verific dashboard-ul la https://%s%s\n' "${DOMAIN:-<host>}" "$URL_SUFFIX"
else
    warn "nu am putut citi /etc/sentinel/sentinel.yaml — verific cu valorile date pe linia de comandă"
fi

# ---------------------------------------------------------------------------
sect "Servicii"

# Ce e INSTALAT pe gazdă, nu o listă scrisă aici.
#
# Lista era codată fix — `sentinel-executor` și `sentinel-web` — de pe vremea
# când doar alea existau. De atunci s-au adăugat ingest, detect, ai, telegram și
# beacon, iar smoke-testul a continuat să raporteze „toate serviciile active"
# fără să se fi uitat vreodată la conducta de detecție. Un raport de verificare
# care numără doar ce știa autorul la scriere e mai rău decât unul care lipsește:
# spune un număr, iar numărul e crezut.
units="$(r "ls /etc/systemd/system/sentinel-*.service 2>/dev/null | xargs -r -n1 basename" || true)"
[[ -n "$units" ]] || units="sentinel-executor.service sentinel-web.service"

# Componente opt-in: oprite prin configurare, nu stricate.
#
# `beacon` poate fi dezactivat în sentinel.yaml. Serviciul iese atunci cu
# 0 și rămâne `inactive`, iar el nu are timer, deci nu se poate deosebi de
# un daemon căzut fără să te uiți în configurare.
#
# Autoverificarea agentului avea deja excepția asta (`selfcheck/checks.py`);
# smoke-testul nu, iar prima versiune a enumerării dinamice raporta „deployment
# eșuat" pe o instalare perfect corectă cu beaconul oprit — exact alarma falsă
# pe care restul codului o numește „cea care te învață să nu mai citești
# raportul".
# Întrebăm ÎNCĂRCĂTORUL de configurare, nu fișierul.
#
# O primă versiune făcea grep după `enabled:` sub numele secțiunii. Cădea pe
# CRLF, pe un comentariu la capătul liniei, pe `False`, pe `no`, pe un comentariu
# între secțiune și cheie — și, cel mai rău, pe absența completă a secțiunii:
# `BeaconConfig.enabled` e implicit `false`, deci o instalare fără `beacon:` are
# beaconul legitim oprit, iar grep-ul nu întorcea nimic și raporta eșec.
#
# Codul produsului știe toate astea deja. Îl întrebăm pe el.
opt_in_off=""
opt_in_raw="$(r "sudo -u sentinel PYTHONPATH=/opt/sentinel/lib /opt/sentinel/venv/bin/python -c \
    'from sentinel.config import get_config as g; c=g(); print(\"beacon\", c.beacon.enabled); print(\"ai\", c.ai.enabled)'" || true)"
if [[ -z "$opt_in_raw" ]]; then
    warn "nu am putut citi configurarea încărcată — tratez beacon/ai ca pornite"
else
    while read -r comp enabled; do
        # Doar beaconul. `run_forever` iese imediat cand e dezactivat, si unitatea
        # are `Restart=on-failure`, deci ramane `inactive` — indistinct de un
        # daemon cazut fara sa te uiti in configurare.
        #
        # `ai` NU: workerul bucleaza la nesfarsit indiferent de `ai.enabled`, iar
        # unitatea are `Restart=always`. O unitate `Restart=always` nu poate fi
        # legitim `inactive`, deci scutirea ar fi mascat o cadere reala. Am scris
        # initial ca „ambele ies cu 0" — fals pentru ai, si contrazicea chiar
        # poarta din install.sh, care moare daca sentinel-ai nu ramane activ.
        [[ "$comp" == "beacon" && "$enabled" == "False" ]]             && opt_in_off="${opt_in_off} sentinel-${comp}.service"
    done <<< "$opt_in_raw"
fi

for unit in $units; do
    # Unitățile oneshot pornite de timer sunt `inactive` între rulări — starea
    # lor normală. A le raporta ca oprite ar fi o alarmă falsă la fiecare rulare.
    triggered="$(r "systemctl show ${unit} -p TriggeredBy --value" || true)"
    state="$(r "systemctl is-active ${unit}" || true)"
    case "$state" in
        active)   pass "${unit} active" ;;
        inactive) if [[ -n "$triggered" ]]; then
                      pass "${unit} inactive (pornit de ${triggered// /, })"
                  elif [[ " ${opt_in_off} " == *" ${unit} "* ]]; then
                      pass "${unit} inactive (dezactivat în sentinel.yaml)"
                  else
                      fail "${unit} inactive — journalctl -u ${unit} -n 50"
                  fi ;;
        failed)   fail "${unit} FAILED — journalctl -u ${unit} -n 50" ;;
        # `activating` înseamnă două lucruri complet diferite, iar `TriggeredBy`
        # le desparte.
        #
        # O unitate oneshot pornită de timer e `activating` CÂT TIMP RULEAZĂ —
        # `sentinel-health` la fiecare 30 de secunde, `sentinel-scan` timp de 74
        # de secunde pe zi. O primă versiune a acestei ramuri le trata ca eșec, și
        # 3 din 20 de rulări raportau „deployment eșuat" pe o gazdă sănătoasă.
        #
        # Un daemon fără timer, în schimb, e `activating` doar între moartea
        # procesului și repornirea lui: acolo e bucla.
        activating) if [[ -n "$triggered" ]]; then
                        pass "${unit} rulează acum (pornit de ${triggered// /, })"
                    else
                        fail "${unit} ACTIVATING fără timer — se reporneşte în buclă? journalctl -u ${unit} -n 50"
                    fi ;;
        *)        warn "${unit} stare necunoscută: ${state:-?}" ;;
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

    allow_n="$(count_set_elements allowlist_v4)"
    if [[ "$allow_n" == "?" ]]; then
        warn "nu am putut citi allowlist_v4 — stare necunoscută, nu o raportez ca goală"
    elif (( allow_n > 0 )); then
        pass "allowlist has ${allow_n} entries"
    else
        fail "allowlist is EMPTY — nothing protects you from a bad block"
    fi

    printf '    blocklist: %s entries\n' "$(count_set_elements blocklist_v4)"

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
[[ "$code" =~ ^(200|301|302|303|307|308|401|503)$ ]] && pass "app answers on 127.0.0.1:8787 (HTTP ${code})" \
                                     || fail "app did not answer on 8787 (got ${code})"

# nginx in front of it, still over loopback. Separating this from the external
# check below means a failure names the layer that is wrong, rather than just
# saying "unreachable".
code="$(r "curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1:${WEB_PORT}/healthz" || echo 000)"
[[ "$code" =~ ^(200|301|302|303|307|308|401|503)$ ]] && pass "nginx serving on :${WEB_PORT} (HTTP ${code})" \
                                     || fail "nginx did not answer on :${WEB_PORT} (got ${code})"

if r "sudo nginx -t"; then pass "nginx config valid"; else fail "nginx -t failed"; fi

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

# Ce spune Sentinel despre sine.
#
# Are 33 de verificări proprii, mult mai amănunțite decât orice poate întreba un
# script de la distanță — cursorul de detecție, tăcerea fiecărui colector,
# concordanța dintre nucleu și baza de date. Nu erau citite de aici, deci un
# deployment putea trece „27 din 27" în timp ce agentul raporta el însuși
# probleme, iar singurul loc unde se vedea era un mesaj pe telefon.
#
# Rulat prin systemd, nu direct: verificarea de nftables are nevoie de
# CAP_NET_ADMIN, iar capabilitatea vine de la unitate, nu de la utilizator.
# Citit din ieşirea `--print`, nu ghicit din formatul JSON al jurnalului.
#
# Prima versiune căuta în journald un tipar inventat de mine. Nu s-a potrivit
# niciodată, deci raporta „autoverificarea nu raportează nimic" în timp ce
# agentul spunea `down · 31/33`. Un rezultat verde care nu s-a uitat la nimic e
# mai rău decât o verificare absentă: absenţa se vede în listă.
selfcheck="$(r "sudo -u sentinel /opt/sentinel/bin/sentinel selfcheck --print 2>/dev/null" || true)"
if [[ -z "$selfcheck" ]]; then
    warn "nu am putut rula autoverificarea — încearcă /autoverificare pe Telegram"
else
    # `[??]` e „nu ştiu", nu „e rău": rulată de mână, verificarea de nftables nu
    # primeşte CAP_NET_ADMIN, fiindcă acela vine de la unitate.
    bad="$(grep -vE '^\[  ok\]|^\[  \?\?\]|^ ' <<< "$selfcheck" | grep -E '^\[' || true)"
    if [[ -z "$bad" ]]; then
        pass "autoverificarea nu raportează nimic ($(grep -c '^\[  ok\]' <<< "$selfcheck") verificări ok)"
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] && fail "autoverificare: ${line}"
        done <<< "$bad"
    fi
fi

perms="$(r "sudo stat -c '%a %U:%G' /etc/sentinel/secrets.env" || echo '')"
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
