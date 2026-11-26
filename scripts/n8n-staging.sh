#!/usr/bin/env bash
#
# O copie de aruncat a instanței n8n de producție, pe o versiune nouă, IZOLATĂ de rețea, ca upgrade-ul (2.x -> 3.0.x) să se
# încerce înainte să atingă producția. De pe stația operatorului (Git Bash sau WSL), ca system-update.sh.
#
#   ./scripts/n8n-staging.sh --host H --user U --key K up --version 3.0.1
#   ./scripts/n8n-staging.sh --host H --user U --key K status
#   ./scripts/n8n-staging.sh --host H --user U --key K logs [--tail 200]
#   ./scripts/n8n-staging.sh --host H --user U --key K down
#
#   --host H   gazda            --user U   implicit sentinel-deploy
#   --key K    cheia privată    --port P   portul ssh (22)
#   Doar pentru `up` (toate se validează aici ȘI pe gazdă; `sudo` curăță mediul, deci altfel n-ar ajunge acolo):
#   --health-timeout S  cât așteaptă /healthz 200, în secunde, 60-7200 (implicit 1200 = 20 min; migrarea unei baze de ~10 GB poate dura)
#   --cpus C            limita de procesor a containerului și a probei, 0.25-2 (implicit 1; gazda are 2 procesoare)
#   --memory M          limita de memorie, 512m-6g (implicit 3g; gazda are 7,9 GB și producția rulează pe ea)
#   Contul are nevoie doar de `sudo -n`. Exemplu:
#   ./scripts/n8n-staging.sh --host n8n.srv1051579.hstgr.cloud --user dragos --key ~/.ssh/id_ed25519 up --version 3.0.1
#
# De ce există: workflow-urile de producție sună debitori prin Twilio, trimit WhatsApp și e-mail, iar multe sunt active. O copie
# care ar ajunge pe internet ar face apeluri REALE. `up` creează copia pe o rețea docker `--internal`, fără porturi publicate, și
# DOVEDEȘTE izolarea prin efect (din interiorul containerului, TCP spre 1.1.1.1:443 și DNS cad); dacă vede ieșire, șterge
# containerul și iese cu 5. Producția rămâne pornită și neatinsă: amprenta lui root-n8n-1 se compară la ieșire (cod 4 dacă diferă).
# Detaliile (copia online SQLite, /files doar-citire, mediul fără valori tipărite) sunt în antetul scripts/lib/n8n-staging-host.sh.
#
# Codul de ieșire: 0 = totul dovedit; 1 = refuzat sau eșuat (la refuz de preflight nu s-a creat nimic); 2 = argumente greșite;
# 3 = ceva n-a putut fi măsurat (NU e «bine»); 4 = PRODUCȚIA s-a schimbat; 5 = s-a văzut ieșire din container (șters);
# 255 = ssh a căzut (pe gazdă rămân obiectele deja create, cu eticheta de staging; citește `status`, apoi `down`).
#
# Ce face acest script, și doar atât: validează argumentele AICI, înainte de orice rețea, și trimite scripts/lib/n8n-staging-host.sh
# pe stdin într-un `sudo -n bash -s`. Nu lasă nimic pe gazdă (deci nu are ce sumă să verifice) și nu rulează nimic în afară de
# ssh. Tunelul îl pornește operatorul, cu comanda tipărită la final.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_LIB="${REPO_ROOT}/scripts/lib/n8n-staging-host.sh"

DEPLOY_USER_DEFAULT="sentinel-deploy"
HOST=""; USER="$DEPLOY_USER_DEFAULT"; KEY=""; SSH_PORT=22; SUB=""; VERSION=""; TAIL=""; HEALTH_TIMEOUT=""; CPUS=""; MEMORY=""
LOCAL_TUNNEL_PORT=5679

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 2; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

# O opțiune cu valoare, dată ca ultim argument, făcea `shift 2` să cadă sub `set -e`: ieșire 1, fără niciun mesaj. Acum: 2, cu mesaj.
need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 cere o valoare nevidă"; }
set_sub() { [[ -z "$SUB" ]] || die "o singură subcomandă (am deja '$SUB', nu și '$1')"; SUB="$1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    need_value "$@"; HOST="$2"; shift 2 ;;
        --user)    need_value "$@"; USER="$2"; shift 2 ;;
        --key)     need_value "$@"; KEY="$2"; shift 2 ;;
        --port)    need_value "$@"; SSH_PORT="$2"; shift 2 ;;
        --help|-h) usage ;;
        up)        set_sub up; shift
                   while [[ $# -gt 0 ]]; do
                       case "$1" in
                           --version)        need_value "$@"; VERSION="$2" ;;
                           --health-timeout) need_value "$@"; HEALTH_TIMEOUT="$2" ;;
                           --cpus)           need_value "$@"; CPUS="$2" ;;
                           --memory)         need_value "$@"; MEMORY="$2" ;;
                           *) break ;;
                       esac
                       shift 2
                   done
                   [[ -n "$VERSION" ]] || die "up cere: --version X.Y.Z" ;;
        status|down) set_sub "$1"; shift ;;
        logs)      set_sub logs; shift
                   if [[ "${1:-}" == --tail ]]; then need_value "$@"; TAIL="$2"; shift 2; fi ;;
        *)         die "argument necunoscut: '$1' (subcomenzi: up --version X.Y.Z [--health-timeout S] [--cpus C] [--memory M] | status | logs [--tail N] | down)" ;;
    esac
done

# Fiecare valoare care trece în comanda ssh sau în scriptul de pe gazdă se validează AICI, strict. O versiune nu ajunge nici
# măcar la ssh dacă nu e MAJOR.MINOR.PATCH în cifre: nici `latest`, nici un șir cu `;` sau `$(...)`.
[[ -n "$SUB" ]] || die "lipsește subcomanda (up --version X.Y.Z | status | logs | down)"
[[ -n "$HOST" ]] || die "--host este obligatoriu"
[[ "$HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || die "--host refuzat (caractere nepermise; un nume care începe cu - ar deveni o opțiune ssh): '${HOST}'"
[[ "$USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "--user refuzat: '${USER}'"
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || die "--port cere un număr"
(( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || die "--port în afara 1-65535"
if [[ "$SUB" == up ]]; then
    [[ ${#VERSION} -le 32 && "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "versiune refuzată: cer exact MAJOR.MINOR.PATCH (ex. 3.0.1), nu '${VERSION}' (nici 'latest')"
    # `sudo` curăță mediul, deci pragurile ajung pe gazdă DOAR ca argumente; gazda le validează încă o dată, la fel.
    if [[ -n "$HEALTH_TIMEOUT" ]]; then
        [[ "$HEALTH_TIMEOUT" =~ ^[0-9]{1,5}$ ]] && (( 10#$HEALTH_TIMEOUT >= 60 && 10#$HEALTH_TIMEOUT <= 7200 )) \
            || die "--health-timeout cere secunde, doar cifre, între 60 și 7200 (implicit 1200), nu '${HEALTH_TIMEOUT}'"
    fi
    if [[ -n "$CPUS" ]]; then
        [[ "$CPUS" =~ ^[0-9](\.[0-9]{1,2})?$ ]] || die "--cpus cere un număr între 0.25 și 2, nu '${CPUS}'"
        cpus_hundredths="$(awk -v v="$CPUS" 'BEGIN { printf "%d", v * 100 + 0.5 }')"
        (( cpus_hundredths >= 25 && cpus_hundredths <= 200 )) || die "--cpus cere un număr între 0.25 și 2, nu '${CPUS}'"
    fi
    if [[ -n "$MEMORY" ]]; then
        [[ "$MEMORY" =~ ^([0-9]{1,4})([mg])$ ]] || die "--memory cere o valoare ca 3g sau 2048m, nu '${MEMORY}'"
        memory_mb=$((10#${BASH_REMATCH[1]}))
        if [[ "${BASH_REMATCH[2]}" == g ]]; then memory_mb=$((memory_mb * 1024)); fi
        (( memory_mb >= 512 && memory_mb <= 6144 )) || die "--memory trebuie să fie între 512m și 6g (gazda are 7,9 GB și producția rulează pe ea), nu '${MEMORY}'"
    fi
fi
if [[ "$SUB" == logs && -n "$TAIL" ]]; then
    [[ "$TAIL" =~ ^[0-9]{1,5}$ ]] || die "--tail cere un număr (cel mult 5 cifre), nu '${TAIL}'"
fi

if [[ -z "$KEY" && -f "${HOME}/.ssh/sentinel_deploy" && "$USER" == "$DEPLOY_USER_DEFAULT" ]]; then
    KEY="${HOME}/.ssh/sentinel_deploy"
    info "folosesc cheia implicită ${KEY}"
elif [[ -z "$KEY" ]]; then
    warn "nu s-a dat --key; ssh va alege o identitate."
fi
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=40 -p "$SSH_PORT")
if [[ -n "$KEY" ]]; then
    KEY="${KEY/#\~/$HOME}"
    [[ -f "$KEY" ]] || die "cheia ssh nu există: ${KEY}"
    SSH_OPTS+=(-o IdentitiesOnly=yes -i "$KEY")
fi

# `-n`-ul din probe: stdin-ul nu trebuie consumat de ele. Doar rularea propriu-zisă primește scriptul pe stdin.
ssh_probe() { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@" < /dev/null; }

# Un CR într-un .sh devine `bad interpreter: bash^M` pe gazdă. Verificat pe octeți, nu cu grep.
[[ -f "$HOST_LIB" ]] || die "lipsește ${HOST_LIB}"
if ! tr -d '\r' < "$HOST_LIB" | cmp -s - "$HOST_LIB"; then
    die "$(basename "$HOST_LIB") conține CR (sfârșituri de linie Windows); refuz să-l trimit. Vezi .gitattributes"
fi
bash -n "$HOST_LIB" || die "$(basename "$HOST_LIB") nu trece de bash -n"

info "mă conectez la ${USER}@${HOST}:${SSH_PORT}"
ssh_probe "echo conectat" > /dev/null || { warn "nu pot ajunge la ${HOST}. Verifică adresa, cheia și firewall-ul providerului."; exit 1; }
ssh_probe "sudo -n true" || { warn "sudo nu răspunde fără parolă pentru ${USER}; scriptul nu poate rula neinteractiv"; exit 1; }
ok "ssh și sudo -n funcționează"

# Argumentele pe gazdă, prin printf %q (ssh le lipește într-un singur șir de comandă). Toate sunt deja doar cifre, puncte și
# cuvinte fixe, dar citarea nu se bazează pe validarea de mai sus.
remote_cmd="sudo -n bash -s -- ${SUB}"
if [[ "$SUB" == up ]]; then
    remote_cmd+=" --version $(printf '%q' "$VERSION")"
    [[ -z "$HEALTH_TIMEOUT" ]] || remote_cmd+=" --health-timeout $(printf '%q' "$HEALTH_TIMEOUT")"
    [[ -z "$CPUS" ]] || remote_cmd+=" --cpus $(printf '%q' "$CPUS")"
    [[ -z "$MEMORY" ]] || remote_cmd+=" --memory $(printf '%q' "$MEMORY")"
fi
[[ "$SUB" == logs && -n "$TAIL" ]] && remote_cmd+=" --tail $(printf '%q' "$TAIL")"

out_file="$(mktemp)"
trap 'rm -f -- "$out_file"' EXIT
info "trimit scripts/lib/n8n-staging-host.sh și pornesc: ${SUB}"
rc=0
set +e
ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$remote_cmd" < "$HOST_LIB" 2>&1 | tee "$out_file"
rc="${PIPESTATUS[0]}"
set -e
printf '\n'

# Comanda de tunel completă (cu cheia, portul și contul acestei stații), din adresa containerului raportată de gazdă.
tunnel_ip="$(sed -n 's/^N8N_STAGING_IP=\([0-9][0-9.]*\)$/\1/p' "$out_file" | tail -n 1)"
if [[ "$rc" -eq 0 && "$SUB" != down && "$SUB" != logs && -n "$tunnel_ip" ]]; then
    tunnel="ssh -N -L ${LOCAL_TUNNEL_PORT}:${tunnel_ip}:5678 -p ${SSH_PORT}"
    [[ -n "$KEY" ]] && tunnel+=" -i '${KEY}'"
    tunnel+=" ${USER}@${HOST}"
    ok "tunel (lasă-l deschis într-un terminal):"
    printf '    %s\n' "$tunnel"
    ok "apoi deschide http://localhost:${LOCAL_TUNNEL_PORT}/"
elif [[ "$rc" -eq 0 && "$SUB" == up ]]; then
    warn "ieșire 0, dar gazda n-a raportat adresa containerului: nu pot construi comanda de tunel; rulează \`status\`"
fi

case "$rc" in
    0)   ok "${SUB}: cod 0" ;;
    1)   warn "${SUB}: REFUZAT sau EȘUAT (cod 1) — citește ce e marcat [x] mai sus" ;;
    2)   warn "${SUB}: argumente greșite pe gazdă (cod 2)" ;;
    3)   warn "${SUB}: NECUNOSCUT (cod 3) — ceva n-a putut fi măsurat; asta NU e «bine»" ;;
    4)   warn "${SUB}: PRODUCȚIA S-A SCHIMBAT (cod 4) — citește mesajul de mai sus înainte de orice altceva" ;;
    5)   warn "${SUB}: S-A VĂZUT IEȘIRE DIN CONTAINER (cod 5) — containerul a fost șters; NU folosi această gazdă pentru staging" ;;
    255) warn "ssh a căzut (cod 255). Pe gazdă pot fi obiecte create, cu eticheta de staging:"
         warn "    ./scripts/n8n-staging.sh --host ${HOST} --user ${USER} status" ;;
    *)   warn "${SUB}: cod de ieșire neașteptat ${rc}" ;;
esac
exit "$rc"
