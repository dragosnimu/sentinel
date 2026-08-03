#!/usr/bin/env bash
#
# Collect the secrets Sentinel needs into secrets/.env.local.
#
# That file is gitignored, excluded from the deploy tarball, and transferred to
# the server over the SSH channel on stdin — never as a command-line argument,
# where `ps` on the server would show it, and never as a file left in /tmp.
#
#   ./scripts/secrets-init.sh          # prompt for anything missing
#   ./scripts/secrets-init.sh --force  # re-prompt for everything

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${REPO_ROOT}/secrets"
SECRETS_FILE="${SECRETS_DIR}/.env.local"
FORCE=0

[[ "${1:-}" == "--force" ]] && FORCE=1

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

mkdir -p "$SECRETS_DIR"

declare -A VALUES=()
if [[ -f "$SECRETS_FILE" ]] && (( ! FORCE )); then
    while IFS='=' read -r k v; do
        [[ -z "$k" || "$k" == \#* ]] && continue
        VALUES["$k"]="$v"
    done < "$SECRETS_FILE"
    info "reading existing values from ${SECRETS_FILE}"
fi

# Masked input. The value never appears on screen and never enters shell history.
ask_secret() {
    local key="$1" prompt="$2" optional="${3:-0}"
    if [[ -n "${VALUES[$key]:-}" ]]; then
        ok "${key} already set (use --force to change it)"
        return
    fi
    printf '\n%s\n' "$prompt"
    local value
    read -rs -p "  ${key}: " value
    printf '\n'
    if [[ -z "$value" ]]; then
        if (( optional )); then
            info "${key} left empty"
            return
        fi
        die "${key} is required"
    fi
    VALUES["$key"]="$value"
}

ask_plain() {
    local key="$1" prompt="$2"
    if [[ -n "${VALUES[$key]:-}" ]]; then
        ok "${key} = ${VALUES[$key]}"
        return
    fi
    printf '\n%s\n' "$prompt"
    local value
    read -r -p "  ${key}: " value
    [[ -n "$value" ]] || die "${key} is required"
    VALUES["$key"]="$value"
}

cat <<'EOF'

  Sentinel — configurare secrete

  Valorile sunt citite mascat, nu apar pe ecran și nu intră în istoricul
  shell-ului. Se scriu în secrets/.env.local, care este gitignored și exclus
  din arhiva de deploy. Ajung pe server doar prin stdin-ul conexiunii SSH.

EOF

# --------------------------------------------------------------------------
# Generated locally: no reason for a human to invent or ever see these.
# --------------------------------------------------------------------------
if [[ -z "${VALUES[SENTINEL_DB_PASSWORD]:-}" ]]; then
    if command -v openssl >/dev/null; then
        VALUES[SENTINEL_DB_PASSWORD]="$(openssl rand -base64 33 | tr -d '/+=' | head -c 40)"
        ok "SENTINEL_DB_PASSWORD generated (40 chars)"
    else
        die "openssl not found and SENTINEL_DB_PASSWORD is unset. Install openssl \
or set it by hand in ${SECRETS_FILE}."
    fi
fi

# --------------------------------------------------------------------------
ask_secret ANTHROPIC_API_KEY "$(cat <<'EOF'
  Cheia API Anthropic (sk-ant-...).
  Folosită pentru triaj, corelare, predicții, rapoarte și generarea planurilor
  de patch. Fără ea, Sentinel rulează determinist: detecția, blocarea,
  alertarea și scanarea funcționează în continuare.

  Pune o limită de cheltuială pe cheie în consola Anthropic. Plafonul din
  sentinel.yaml este prima linie de apărare, nu singura.
EOF
)" 1

ask_secret TELEGRAM_BOT_TOKEN "$(cat <<'EOF'
  Tokenul botului Telegram, de la @BotFather.

  Creează un bot NOU, dedicat lui Sentinel. Nu refolosi unul care duce deja
  alte notificări — amestecarea alertelor de rutină cu cele de securitate este
  exact modul în care alertele de securitate ajung să nu mai fie citite.

  Acest token este planul de control. Cine îl are poate cere deblocări, poate
  opri alertele și poate aproba patch-uri (limitat de allowlist-ul de chat_id
  și de dubla confirmare). Tratează-l ca pe o parolă de root.
EOF
)" 1

ask_plain TELEGRAM_CHAT_ID "$(cat <<'EOF'
  ID-ul tău numeric de chat, de la @userinfobot. Nu username-ul.
  Doar acest chat va putea da comenzi botului.
EOF
)"

ask_secret TELEGRAM_APPLY_PIN "$(cat <<'EOF'
  PIN opțional (4-8 cifre) pentru aplicarea patch-urilor și modificarea
  allowlist-ului. Apărare în adâncime dacă telefonul este furat: e ceva ce
  hoțul nu are. Enter pentru a sări peste.
EOF
)" 1


# --------------------------------------------------------------------------
# Written with the right mode BEFORE any content exists. Writing first and
# chmod'ing after leaves a window in which the file is world-readable.
# --------------------------------------------------------------------------
umask 077
: > "${SECRETS_FILE}.tmp"

{
    echo "# Sentinel secrets. NEVER commit this file."
    echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by scripts/secrets-init.sh"
    echo "#"
    echo "# TELEGRAM_CALLBACK_HMAC_KEY and SENTINEL_SESSION_SECRET are generated"
    echo "# on the server by install.sh — there is no reason for them to exist here."
    echo
    for key in SENTINEL_DB_PASSWORD ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN \
               TELEGRAM_CHAT_ID TELEGRAM_APPLY_PIN; do
        [[ -n "${VALUES[$key]:-}" ]] && printf '%s=%s\n' "$key" "${VALUES[$key]}"
    done
} >> "${SECRETS_FILE}.tmp"

mv "${SECRETS_FILE}.tmp" "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"

printf '\n'
ok "written to ${SECRETS_FILE} (mode 600)"

# A .gitignore covering this is easy to lose in a merge, and the cost of
# noticing late is a leaked API key in a public repository.
if git -C "$REPO_ROOT" check-ignore -q "$SECRETS_FILE" 2>/dev/null; then
    ok "gitignored, as expected"
else
    warn "THIS FILE IS NOT GITIGNORED. Add 'secrets/*' to .gitignore before committing \
anything, and if it has already been committed, rotate every value in it."
fi

cat <<EOF

  Următorul pas — verificare fără modificări:

    ./scripts/deploy.sh --host <ip> --user <user> --key <cheie> \\
        --domain <domeniu> --dry-run

EOF
