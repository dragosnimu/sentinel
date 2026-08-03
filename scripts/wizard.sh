#!/usr/bin/env bash
#
# Sentinel — interactive installer.
#
# Asks what it needs, checks what it can, then installs. Works two ways and
# figures out which on its own:
#
#   * run it on your own machine  → it asks for a target and installs over SSH
#   * run it on the target itself → it skips the SSH half and installs locally
#
# Three rules it follows throughout:
#
#   1. **Nothing is guessed silently.** Where a sensible default exists it is
#      offered and shown; where one does not, it asks.
#   2. **Secrets never reach the process table.** Tokens and keys are read with
#      the terminal echo off and handed over on stdin, never as arguments —
#      `ps` on a shared host would otherwise show them to everyone.
#   3. **Nothing is changed before the summary is confirmed.** Everything up to
#      that point is questions and read-only checks.
#
# Re-runnable: answers can be saved to a file and replayed unattended, which is
# what you want for a second server or a rebuild.
#
#   ./scripts/wizard.sh                      interactive
#   ./scripts/wizard.sh --save my.conf       interactive, remembers the answers
#   ./scripts/wizard.sh --config my.conf     unattended, no questions
#
set -uo pipefail

# ${#var} counts characters only in a UTF-8 locale; a C-locale login would
# otherwise misalign every label containing a diacritic.
export LC_ALL="${LC_ALL:-C.UTF-8}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------- appearance
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
    OK=$'\033[32m'; WARN=$'\033[33m'; ERR=$'\033[31m'; ACC=$'\033[36m'
else
    B=""; DIM=""; R=""; OK=""; WARN=""; ERR=""; ACC=""
fi

say()   { printf '%s\n' "$*"; }
info()  { printf '  %s\n' "$*"; }
good()  { printf '  %s✓%s %s\n' "$OK" "$R" "$*"; }
warn()  { printf '  %s!%s %s\n' "$WARN" "$R" "$*"; }
bad()   { printf '  %s✗%s %s\n' "$ERR" "$R" "$*"; }
die()   { printf '\n%sOprit:%s %s\n' "$ERR" "$R" "$*" >&2; exit 1; }
title() { printf '\n%s%s%s\n%s\n' "$B" "$*" "$R" "$(printf '─%.0s' $(seq 1 ${#1}))"; }

# printf pads by BYTES, and a Romanian label is full of two-byte characters —
# "Analiză AI:" is 11 characters but 13 bytes, so %-22s under-pads it and the
# whole column walks. Pad by character count instead.
row() {
    local label="$1" value="$2" pad
    pad=$(( 23 - ${#label} ))
    (( pad < 1 )) && pad=1
    printf '  %s%*s%s
' "$label" "$pad" "" "$value"
}

# ---------------------------------------------------------------- prompting
# ask VAR "Question" ["default"]
ask() {
    local var="$1" q="$2" def="${3:-}" ans
    if [[ -n "${!var:-}" ]]; then return 0; fi        # already set by --config
    if [[ -n "$def" ]]; then
        read -r -p "  ${q} ${DIM}[${def}]${R}: " ans
        ans="${ans:-$def}"
    else
        while [[ -z "${ans:-}" ]]; do
            read -r -p "  ${q}: " ans
            [[ -z "$ans" ]] && warn "obligatoriu"
        done
    fi
    printf -v "$var" '%s' "$ans"
}

# ask_secret VAR "Question" — echo off, never shown, never in argv.
ask_secret() {
    local var="$1" q="$2" ans
    if [[ -n "${!var:-}" ]]; then return 0; fi
    read -r -s -p "  ${q}: " ans; printf '\n'
    printf -v "$var" '%s' "$ans"
}

# ask_yn VAR "Question" default(y|n)
ask_yn() {
    local var="$1" q="$2" def="${3:-y}" ans hint
    if [[ -n "${!var:-}" ]]; then return 0; fi
    [[ "$def" == "y" ]] && hint="Y/n" || hint="y/N"
    read -r -p "  ${q} ${DIM}[${hint}]${R}: " ans
    ans="${ans:-$def}"
    case "${ans,,}" in y|yes|d|da) printf -v "$var" 'yes' ;; *) printf -v "$var" 'no' ;; esac
}

# ask_choice VAR "Question" "opt1:description" "opt2:description" ...
ask_choice() {
    local var="$1" q="$2"; shift 2
    if [[ -n "${!var:-}" ]]; then return 0; fi
    local -a keys=() descs=()
    local o
    for o in "$@"; do keys+=("${o%%:*}"); descs+=("${o#*:}"); done
    printf '  %s\n' "$q"
    local i
    for i in "${!keys[@]}"; do
        printf '    %s%d%s) %s%-10s%s %s%s%s\n' "$ACC" "$((i+1))" "$R" \
               "$B" "${keys[$i]}" "$R" "$DIM" "${descs[$i]}" "$R"
    done
    local pick
    while :; do
        read -r -p "  alege [1-${#keys[@]}]: " pick
        [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= ${#keys[@]} )) && break
        warn "alege un număr între 1 și ${#keys[@]}"
    done
    printf -v "$var" '%s' "${keys[$((pick-1))]}"
}

# ---------------------------------------------------------------- arguments
CONFIG_FILE=""; SAVE_FILE=""; ASSUME_YES="no"; DRY_RUN="no"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG_FILE="${2:-}"; shift 2 ;;
        --save)   SAVE_FILE="${2:-}"; shift 2 ;;
        --yes|-y) ASSUME_YES="yes"; shift ;;
        --dry-run) DRY_RUN="yes"; shift ;;
        -h|--help)
            sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "argument necunoscut: $1 (încearcă --help)" ;;
    esac
done

if [[ -n "$CONFIG_FILE" ]]; then
    [[ -r "$CONFIG_FILE" ]] || die "nu pot citi ${CONFIG_FILE}"
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
    good "răspunsuri încărcate din ${CONFIG_FILE}"
fi

# ---------------------------------------------------------------- banner
printf '\n%s  ███ SENTINEL%s  %sinstalare ghidată%s\n' "$ACC" "$R" "$DIM" "$R"
printf '  %sAgent de securitate pentru un server Linux.%s\n' "$DIM" "$R"

# ---------------------------------------------------------------- 1. target
title "1. Unde instalăm"

# A machine that has the repo AND is the target is the "local" case. Detecting
# rather than asking avoids the most common wrong answer.
LOCAL_HINT="no"
if [[ -r /etc/os-release ]] && command -v systemctl >/dev/null 2>&1; then
    LOCAL_HINT="yes"
fi

if [[ -z "${TARGET_MODE:-}" ]]; then
    if [[ "$LOCAL_HINT" == "yes" ]]; then
        info "Acest sistem pare a fi un server Linux cu systemd."
        ask_choice TARGET_MODE "Instalăm aici sau pe alt server?" \
            "local:pe acest sistem, direct" \
            "ssh:pe un server la distanță, prin SSH"
    else
        info "Acest sistem nu e un server Linux cu systemd — instalez la distanță."
        TARGET_MODE="ssh"
    fi
fi

if [[ "$TARGET_MODE" == "ssh" ]]; then
    ask SSH_HOST   "Adresa serverului (IP sau nume DNS)"
    ask SSH_USER   "Utilizator SSH (cu drept de sudo)" "root"
    ask SSH_PORT   "Port SSH" "22"
    ask SSH_KEY    "Cheia SSH privată" "${HOME}/.ssh/id_ed25519"
    SSH_KEY="${SSH_KEY/#\~/$HOME}"
    [[ -r "$SSH_KEY" ]] || die "nu pot citi cheia ${SSH_KEY}"
else
    [[ "$(id -u)" -eq 0 ]] || command -v sudo >/dev/null 2>&1 || \
        die "instalarea locală cere root sau sudo"
fi

# ---------------------------------------------------------------- 2. probe
title "2. Verific serverul"

# One helper for both modes, so every later check is written once.
remote() {
    if [[ "$TARGET_MODE" == "local" ]]; then
        bash -c "$1"
    else
        ssh -i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=10 \
            -o StrictHostKeyChecking=accept-new "${SSH_USER}@${SSH_HOST}" "$1"
    fi
}

if [[ "$TARGET_MODE" == "ssh" ]]; then
    remote true 2>/dev/null || die "nu mă pot conecta la ${SSH_USER}@${SSH_HOST}:${SSH_PORT}. \
Verifică adresa, cheia și că utilizatorul există."
    good "conexiune SSH reușită"
fi

PROBE="$(remote '
    . /etc/os-release 2>/dev/null
    echo "ID=${ID:-?}"
    echo "LIKE=${ID_LIKE:-}"
    echo "PRETTY=${PRETTY_NAME:-?}"
    echo "VER=${VERSION_ID:-?}"
    echo "SYSTEMD=$(command -v systemctl >/dev/null 2>&1 && echo yes || echo no)"
    echo "MEM=$(awk "/MemAvailable/{print int(\$2/1024)}" /proc/meminfo 2>/dev/null || echo 0)"
    echo "DISK=$(df -Pm / 2>/dev/null | awk "NR==2{print \$4}")"
    echo "NGINX=$(command -v nginx >/dev/null 2>&1 && echo yes || echo no)"
    echo "P80=$(ss -tln 2>/dev/null | grep -qE ":80 " && echo busy || echo free)"
    echo "P443=$(ss -tln 2>/dev/null | grep -qE ":443 " && echo busy || echo free)"
    echo "IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP "src \K\S+" | head -1)"
    echo "PEER=${SSH_CLIENT%% *}"
' 2>/dev/null)" || die "verificarea serverului a eșuat"

get() { printf '%s\n' "$PROBE" | grep -m1 "^$1=" | cut -d= -f2- ; }
OS_ID="$(get ID)"; OS_LIKE="$(get LIKE)"; OS_PRETTY="$(get PRETTY)"
HAS_SYSTEMD="$(get SYSTEMD)"; MEM_MB="$(get MEM)"; DISK_MB="$(get DISK)"
HAS_NGINX="$(get NGINX)"; PORT80="$(get P80)"; PORT443="$(get P443)"
SERVER_IP="$(get IP)"; PEER_IP="$(get PEER)"

case " ${OS_ID} ${OS_LIKE} " in
    *" rhel "*|*" fedora "*|*" centos "*|*almalinux*|*rocky*) OS_FAMILY="rhel" ;;
    *" debian "*|*" ubuntu "*|*debian*|*ubuntu*)              OS_FAMILY="debian" ;;
    *) OS_FAMILY="" ;;
esac

[[ -n "$OS_FAMILY" ]] || die "distribuție nesuportată: ${OS_PRETTY}.
Sentinel se instalează pe familia RHEL (AlmaLinux, Rocky, RHEL, Fedora)
și pe familia Debian (Debian, Ubuntu)."
[[ "$HAS_SYSTEMD" == "yes" ]] || die "systemd lipsește. Colectorul journald e sursa \
principală de detecție SSH, deci systemd nu e opțional."

good "sistem: ${OS_PRETTY} (familia ${OS_FAMILY})"
(( MEM_MB >= 1500 )) && good "memorie disponibilă: ${MEM_MB} MB" \
                     || warn "doar ${MEM_MB} MB memorie disponibilă — sub 1500 MB e riscant"
(( DISK_MB >= 5000 )) && good "spațiu liber pe /: $((DISK_MB/1024)) GB" \
                      || warn "doar $((DISK_MB/1024)) GB liberi pe / — recomandat 5+ GB"
[[ "$HAS_NGINX" == "yes" ]] && info "nginx e deja instalat aici"

# Suricata needs headroom; saying so now avoids a surprise later.
SURICATA_POSSIBLE="yes"
(( MEM_MB < 2500 )) && SURICATA_POSSIBLE="no"

# ---------------------------------------------------------------- 3. web
title "3. Interfața web"

ask DOMAIN "Domeniul pentru panou (trebuie să indice deja spre acest server)" \
    "sentinel.exemplu.ro"

if [[ "$PORT443" == "busy" ]]; then
    info "portul 443 e deja ocupat — probabil de nginx-ul tău."
    ask_choice NGINX_MODE "Cum expunem panoul?" \
        "shared:vhost lângă site-urile existente, pe 443 (URL curat)" \
        "dedicated:port propriu, nu atinge nginx-ul existent"
else
    ask_choice NGINX_MODE "Cum expunem panoul?" \
        "dedicated:port propriu, izolat (implicit sigur)" \
        "shared:vhost pe 80/443, URL curat, are nevoie de nginx"
fi

if [[ "$NGINX_MODE" == "dedicated" ]]; then
    ask PUBLIC_PORT "Portul public al panoului" "8443"
    info "deschide ${PUBLIC_PORT}/tcp și în firewall-ul furnizorului"
else
    PUBLIC_PORT="443"
fi

if [[ "$PORT80" == "free" && "$NGINX_MODE" == "dedicated" ]]; then
    warn "portul 80 e liber, dar în modul dedicat certbot nu-l poate folosi"
fi

# ---------------------------------------------------------------- 4. safety
title "4. Siguranță — ca să nu te blochezi singur afară"

info "Adresa ta intră permanent în allowlist: executorul refuză s-o blocheze,"
info "iar regula nftables o acceptă înaintea oricărei reguli de blocare."
DEFAULT_ADMIN="${PEER_IP:-}"
[[ -z "$DEFAULT_ADMIN" && "$TARGET_MODE" == "local" ]] && DEFAULT_ADMIN="$(get IP)"
ask ADMIN_IP "Adresa ta publică (de unde administrezi)" "${DEFAULT_ADMIN:-}"

if [[ ! "$ADMIN_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    warn "„${ADMIN_IP}” nu arată ca o adresă IPv4 — verifică-o"
fi

# ---------------------------------------------------------------- 5. telegram
title "5. Telegram — canalul de urgență"

info "Funcționează prin long-polling: niciun port deschis în plus, și merge"
info "chiar dacă nginx sau certificatul sunt stricate."
ask_yn USE_TELEGRAM "Configurezi Telegram acum?" "y"

if [[ "$USE_TELEGRAM" == "yes" ]]; then
    if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
        info "${DIM}Creează un bot: scrie /newbot la @BotFather și copiază tokenul.${R}"
        info "${DIM}Află chat id: scrie /start la @userinfobot.${R}"
    fi
    ask_secret TELEGRAM_BOT_TOKEN "Token bot Telegram"
    ask TELEGRAM_CHAT_ID "Chat id (al tău)"
    [[ "$TELEGRAM_CHAT_ID" =~ ^-?[0-9]+$ ]] || warn "chat id ar trebui să fie numeric"
fi

# ---------------------------------------------------------------- 6. ai
title "6. Analiză AI (opțional)"

info "Folosită pentru triajul incidentelor grave și generarea planurilor de patch."
info "Fără cheie, totul funcționează — pierzi doar comentariul în română."
ask_yn USE_AI "Adaugi o cheie API Anthropic?" "n"
[[ "$USE_AI" == "yes" ]] && ask_secret ANTHROPIC_API_KEY "Cheie API Anthropic (sk-ant-...)"

# ---------------------------------------------------------------- 7. options
title "7. Opțiuni"

if [[ "$SURICATA_POSSIBLE" == "yes" ]]; then
    ask_yn WITH_SURICATA "Instalezi Suricata (detecție în trafic)?" "y"
else
    warn "sub 2500 MB memorie disponibilă — sar peste Suricata"
    WITH_SURICATA="no"
fi

info "Auto-block se livrează OPRIT indiferent de răspuns: primele zile sunt de"
info "observare, ca fals-pozitivele să apară înainte să tai pe cineva la 3 noaptea."

# ---------------------------------------------------------------- summary
title "Rezumat"

row "Țintă:" "$([[ "$TARGET_MODE" == "local" ]] && echo "acest sistem" || echo "${SSH_USER}@${SSH_HOST}:${SSH_PORT}")"
row "Sistem:" "${OS_PRETTY} (${OS_FAMILY})"
row "Domeniu:" "${DOMAIN}"
row "Mod nginx:" "${NGINX_MODE} (port ${PUBLIC_PORT})"
row "IP admin:" "${ADMIN_IP}"
row "Telegram:" "$([[ "$USE_TELEGRAM" == "yes" ]] && echo "da (chat ${TELEGRAM_CHAT_ID})" || echo "nu")"
row "Analiză AI:" "$([[ "${USE_AI:-no}" == "yes" ]] && echo "da" || echo "nu")"
row "Suricata:" "$([[ "$WITH_SURICATA" == "yes" ]] && echo "da" || echo "nu")"
row "Auto-block:" "oprit (mod observă)"

if [[ -n "$SAVE_FILE" ]]; then
    umask 077
    {
        echo "# Răspunsuri Sentinel — reluare cu: wizard.sh --config $(basename "$SAVE_FILE")"
        echo "# ATENȚIE: conține secrete. Păstrează-l 0600 și în afara git."
        for v in TARGET_MODE SSH_HOST SSH_USER SSH_PORT SSH_KEY DOMAIN NGINX_MODE \
                 PUBLIC_PORT ADMIN_IP USE_TELEGRAM TELEGRAM_CHAT_ID USE_AI \
                 WITH_SURICATA TELEGRAM_BOT_TOKEN ANTHROPIC_API_KEY; do
            [[ -n "${!v:-}" ]] && printf '%s=%q\n' "$v" "${!v}"
        done
    } > "$SAVE_FILE"
    chmod 0600 "$SAVE_FILE"
    good "răspunsuri salvate în ${SAVE_FILE} (0600)"
fi

if [[ "$DRY_RUN" == "yes" ]]; then
    printf '\n  %s--dry-run: nu s-a modificat nimic.%s\n\n' "$DIM" "$R"
    exit 0
fi

printf '\n'
if [[ "$ASSUME_YES" != "yes" ]]; then
    warn "Din acest punct înainte se modifică serverul."
    if [[ "$TARGET_MODE" == "ssh" ]]; then
        warn "Deschide ACUM o a doua sesiune SSH și las-o deschisă, ca plasă de siguranță."
    fi
    ask_yn CONFIRM "Continuăm?" "n"
    [[ "$CONFIRM" == "yes" ]] || die "anulat de utilizator — nimic nu a fost modificat"
fi

# ---------------------------------------------------------------- install
title "Instalare"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

info "împachetez proiectul…"
tar --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='secrets/*' --exclude='.venv' --exclude='node_modules' \
    -czf "${STAGE}/sentinel.tar.gz" -C "$REPO_DIR" . 2>/dev/null \
    || die "împachetarea a eșuat"
good "arhivă: $(du -h "${STAGE}/sentinel.tar.gz" | cut -f1)"

# Secrets go on stdin, never in argv: `ps` on a shared host shows arguments to
# every user, and a bot token in a chat history is bad enough already.
build_secrets() {
    [[ "$USE_TELEGRAM" == "yes" ]] && printf 'TELEGRAM_BOT_TOKEN=%s\n' "$TELEGRAM_BOT_TOKEN"
    [[ "${USE_AI:-no}" == "yes" ]] && printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY"
    return 0
}

INSTALL_ENV=$(cat <<EOF
export SENTINEL_DOMAIN=$(printf '%q' "$DOMAIN")
export SENTINEL_NGINX_MODE=$(printf '%q' "$NGINX_MODE")
export SENTINEL_PUBLIC_PORT=$(printf '%q' "$PUBLIC_PORT")
export ADMIN_IP=$(printf '%q' "$ADMIN_IP")
export TELEGRAM_CHAT_ID=$(printf '%q' "${TELEGRAM_CHAT_ID:-}")
export SENTINEL_WITH_SURICATA=$(printf '%q' "$WITH_SURICATA")
EOF
)

run_install() {
    local sudo_prefix=""
    [[ "$(id -u)" -ne 0 ]] && sudo_prefix="sudo -E"
    $sudo_prefix bash -c '
        set -e
        rm -rf /tmp/sentinel-install && mkdir -p /tmp/sentinel-install
        tar -xzf /tmp/sentinel-src.tar.gz -C /tmp/sentinel-install
        cd /tmp/sentinel-install
        [[ -s /tmp/sentinel-secrets ]] && cp /tmp/sentinel-secrets /tmp/si.env || true
        bash deploy/preflight.sh || true
        bash deploy/install.sh
        rm -f /tmp/sentinel-secrets /tmp/si.env
    '
}

if [[ "$TARGET_MODE" == "local" ]]; then
    cp "${STAGE}/sentinel.tar.gz" /tmp/sentinel-src.tar.gz
    build_secrets > /tmp/sentinel-secrets; chmod 600 /tmp/sentinel-secrets
    eval "$INSTALL_ENV"
    run_install || die "instalarea a eșuat — vezi mesajele de mai sus"
else
    info "transfer arhiva…"
    scp -q -i "$SSH_KEY" -P "$SSH_PORT" -o StrictHostKeyChecking=accept-new \
        "${STAGE}/sentinel.tar.gz" "${SSH_USER}@${SSH_HOST}:/tmp/sentinel-src.tar.gz" \
        || die "transferul a eșuat"
    good "arhivă transferată"

    info "transfer secretele (prin stdin, nu prin argumente)…"
    build_secrets | ssh -i "$SSH_KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${SSH_HOST}" 'umask 077; cat > /tmp/sentinel-secrets' \
        || die "transferul secretelor a eșuat"

    info "rulez instalarea (durează câteva minute)…"
    ssh -tt -i "$SSH_KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${SSH_HOST}" "${INSTALL_ENV}; $(declare -f run_install); run_install" \
        || die "instalarea a eșuat — vezi mesajele de mai sus"
fi

# ---------------------------------------------------------------- done
title "Gata"

URL="https://${DOMAIN}"
[[ "$PUBLIC_PORT" != "443" ]] && URL="${URL}:${PUBLIC_PORT}"

good "Sentinel instalat."
printf '\n  Panou:  %s%s%s\n' "$ACC" "$URL" "$R"
say ""
info "Pașii următori:"
info "  1. Creează contul de administrator (comanda e afișată mai sus de installer)"
info "  2. Scanează codul QR pentru TOTP — se arată o singură dată"
[[ "$USE_TELEGRAM" == "yes" ]] && \
info "  3. Scrie /status botului, ca să confirmi canalul de urgență"
say ""
warn "Auto-block e OPRIT. Lasă-l așa câteva zile: vei primi pe Telegram ce AR FI"
warn "fost blocat, cu buton. Pornește-l după ce nu mai apar fals-pozitive."
say ""
