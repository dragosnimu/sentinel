#!/usr/bin/env bash
#
# Actualizarea completă a gazdei de producție (sistem + containere), pe faze, de pe
# stația operatorului. Rulează din Git Bash sau WSL, ca deploy.sh.
#
#   ./scripts/system-update.sh --host H --phase preflight
#   ./scripts/system-update.sh --host H --phase backup
#   ./scripts/system-update.sh --host H --phase os
#   ./scripts/system-update.sh --host H --phase containers --dry-run
#   ./scripts/system-update.sh --host H --phase containers --rebuild clinica,oferte
#   (după --rebuild/--accept-drift/--only/--retry-failed urmează o LISTĂ de proiecte, niciodată o altă opțiune: `--rebuild
#   --dry-run` e refuzat aici și pe gazdă, ca să nu devină o rulare în serios; numele trebuie să existe în baseline.
#   La fel --acknowledge, dar cu chei PROIECT/SERVICIU)
#   ./scripts/system-update.sh --host H --phase containers --acknowledge PROIECT/SERVICIU[,PROIECT/SERVICIU]
#   ./scripts/system-update.sh --host H --phase reboot
#   ./scripts/system-update.sh --host H --phase verify
#   ./scripts/system-update.sh --host H --phase status
#
#   --host H   gazda            --user U   implicit sentinel-deploy (ca deploy.sh)
#   --key K    cheia privată    --port P   portul ssh (22)
#   Cu un alt cont (și o gazdă Debian/Ubuntu), cheia și contul se dau împreună; contul are nevoie doar de `sudo -n`:
#   ./scripts/system-update.sh --host n8n.srv1051579.hstgr.cloud --user dragos --key ~/.ssh/id_ed25519 --phase preflight
#
#   Gestionarul de pachete (dnf pe AlmaLinux/RHEL/Rocky/Fedora, apt pe Debian/Ubuntu) se stabilește PE GAZDĂ, o singură dată, din
#   /etc/os-release (ID/ID_LIKE) ȘI din binarele care trebuie să existe; preflight îl scrie în baseline (pkgmgr.kv), iar os/reboot/verify
#   refuză un baseline luat cu altul. O gazdă care nu e nici una, nici alta: ieșire 1, nimic atins. Pe apt: `apt-get dist-upgrade --no-remove`
#   (nucleul nou e un pachet NOU, pe care `upgrade` nu-l instalează; nimic nu se șterge, nimic de pe hold nu se atinge), așteptând blocarea dpkg
#   (unattended-upgrades pornește zilnic, la ore aleatorii; așteptarea se face pe blocări, nu pe nume de procese); `--phase backup` cere `--allow-stale-srv-backup` pe o gazdă fără backup-ul zilnic /var/lib/srv-backup.
#   --phase F  una dintre: preflight backup os containers reboot verify status
#   --yes      răspunde «da» la confirmarea fazelor care schimbă gazda (os, containers,
#              reboot). NU face nimic altceva: ce schimbă faza o spun ele.
#
# Orice alt argument se trimite fazei de pe gazdă (--rebuild, --accept-drift, --only,
# --dry-run, --keep-going, --gap, --wait, --new-baseline, --force, ...). Lista lor completă
# și sensul fiecăreia sunt în antetul scripts/lib/system-update-host.sh; o fază care
# primește un argument pe care nu-l cunoaște iese cu 2, fără să atingă nimic.
#
# Faza containers, după un eșec: rezultatul fiecărui serviciu e o STARE. Un eșec (`failed`, `pull-failed`, `build-failed`,
# `tag-failed`, `unread`, `stale-baseline`) rămâne roșu — ieșire 1, fără containers.ok, roșu și în verify — oricâte rulări urmează (cu sau
# fără --only, cu --dry-run), până când îl rezolvă succesul lui specific, verificat; nimic altceva nu-l șterge:
#   failed        (recreat și picat, ori readus manual la eticheta de rollback): o rulare simplă NU îl trage și NU îl
#                 recreează. Singurul drum spre verde:
#   ./scripts/system-update.sh --host H --phase containers --retry-failed PROIECT[,PROIECT]
#                 (după ce ai citit de ce a picat; doar proiectele numite; reușește doar dacă recrearea e dovedită și stabilă;
#                 la o aplicație construită local, fără --rebuild, doar re-verifică containerul de acum)
#   pull-failed   se rezolvă printr-un pull reușit, apoi verificat (la hold-config-drift: --accept-drift PROIECT)
#   build-failed  se rezolvă printr-un build reușit (`--rebuild PROIECT`), apoi verificat
#   tag-failed    eticheta de rollback n-a putut fi dovedită; se rezolvă când o rulare următoare o dovedește (recreare sau
#                 re-verificare) și containerul e sănătos
#   stale-baseline  un serviciu rulează o imagine pe care nici baseline-ul, nici mentenanța asta n-au pus-o (un redeploy de după
#                 baseline). Proiectul e ținut înainte de orice pull/build/tag/up, pentru orice fel de serviciu, iar faza iese 1 și
#                 nu scrie containers.ok (nici la --dry-run nu iese «dovedit»). Ieșiri: `--phase preflight --new-baseline` (preia
#                 în baseline-ul nou eșecurile nerezolvate; după `os`, un reboot în așteptare nu-l mai blochează), apoi
#                 `--phase backup` dacă are peste 12 h, apoi `--phase containers`; sau readu containerul pe imaginea din baseline
# Un serviciu care a DISPĂRUT din baseline-ul nou (nu mai are niciun container, în nicio stare: a fost scos din compose) își închide singur episodul la
# `--phase preflight --new-baseline` (linie `episode-closed` în jurnal; nici stările lipicioase, nici recunoașterea lui nu se preiau). Un container care există dar nu rulează (oprit, repornit în buclă, în pauză, creat, mort)
# NU a dispărut: eșecul rămâne roșu, iar ieșirea e să-l pornești și să iei un baseline nou, ori `--acknowledge`. O listă de containere măsurată dar GOALĂ nu închide nimic.
# Ieșirea pentru ORICE stare lipicioasă (în afară de stale-baseline) a unui serviciu care nu mai poate fi adus la starea cerută: `--phase containers --acknowledge PROIECT/SERVICIU` (o numește fiecare mesaj). E o decizie a
# operatorului, nu se face niciodată singură: scrie `acked` în jurnal (vizibil în verify) și tipărește un avertisment. Un baseline nou preia eșecurile
# nerezolvate ÎMPREUNĂ cu faptele față de care au fost judecate: un `failed` se verifică față de sănătatea de DINAINTE de eșec (nu de a baseline-ului
# nou, luat poate cât containerul era deja stricat), iar un `pull-failed` unde eticheta a fost mutată chiar de pull-ul mentenanței se poate reîncerca.
# Calea `os` -> containers (refuzat) -> `preflight --new-baseline` poate fi repetată înainte de reboot (explicația se preia, legată de boot);
# după reboot ieșirea e `--phase reboot`, apoi un baseline curat.
# `containers.ok` se scrie doar la o rulare care a procesat TOATE proiectele; un `--only X` care a atins un singur proiect nu îl scrie
# (și nu șterge unul dovedit de o rulare completă: verify cere doar ca rularea parțială să fi ajuns la capăt).
#   unread        proiectul n-a putut fi citit; se rezolvă când i se citește configurația
# `--dry-run` nu schimbă nimic, dar iese 1 (nu «totul dovedit») cât timp există un eșec nerezolvat.
# Eticheta de rollback rollback/maint-<baseline>/<proiect>-<serviciu>:prev se scrie O SINGURĂ
# dată, pe imaginea pe care containerul o rula chiar înainte de prima schimbare (citită din container, înregistrată înainte de
# tag și up), și nu se mai suprascrie la rulările repetate.
#
# Ce face acest script, și doar atât: (1) trimite pe gazdă fișierele din scripts/lib/
# system-update-*.sh într-un director root-only și îi verifică suma SHA-256 CITITĂ DE PE
# GAZDĂ — octeții care rulează sunt cei revizuiți, nu cei pe care i-a «copiat» scp;
# (2) cere confirmarea operatorului, aici, pe terminalul lui; (3) pornește faza prin
# `sudo -n` și îi întoarce codul de ieșire. Toată logica e pe gazdă, într-un singur loc.
#
# Codul de ieșire: 0 = nimic eșuat — citește linia REZULTAT: «TOTUL DOVEDIT», sau «DOVEDIT, cu N servicii recunoscute de operator» când un
# --acknowledge stă în picioare (acele servicii rămân NERESOLVATE în fapt; codul 0 nu le acoperă); 1 = ceva a eșuat sau e mai rău decât la baseline;
# 3 = ceva n-a putut fi măsurat (NU e «bine»); 255 = ssh a căzut (faza `os` și `containers`
# continuă pe gazdă într-o unitate systemd; vezi --phase status).
#
# De ce nu există un twin PowerShell, ca la deploy.ps1: deploy.ps1 reimplementează deploy.sh
# (~1000 de linii) fiindcă acolo ambele ating și stația operatorului (împachetare, chei,
# secrete). Aici stația nu face nimic în afară de ssh + tar + sha256sum, iar documentația
# deploy.sh spune deja «Git Bash sau WSL». Un al doilea script ar fi o a doua copie a
# confirmărilor și a validării argumentelor, care s-ar desincroniza prima.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="${REPO_ROOT}/scripts/lib"
# SU_REMOTE_BIN: doar pentru teste (o gazdă momeală nu are /var/lib); pe gazda reală rămâne implicitul.
REMOTE_BIN="${SU_REMOTE_BIN:-/var/lib/sentinel-maint/bin}"
LIB_FILES=(system-update-host.sh system-update-lib.sh system-update-measure.sh
           system-update-containers.sh system-update-verify.sh)
PHASES="preflight backup os containers reboot verify status"

# Aceleași valori implicite ca deploy.sh: contul și cheia merg împreună.
DEPLOY_USER_DEFAULT="sentinel-deploy"
DEPLOY_KEY_DEFAULT="${HOME}/.ssh/sentinel_deploy"
HOST=""; USER="$DEPLOY_USER_DEFAULT"; KEY=""; SSH_PORT=22; PHASE=""; ASSUME_YES=0
FORWARD=()

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  HOST="${2:-}"; shift 2 ;;
        --user)  USER="${2:-}"; shift 2 ;;
        --key)   KEY="${2:-}"; shift 2 ;;
        --port)  SSH_PORT="${2:-}"; shift 2 ;;
        --phase) PHASE="${2:-}"; shift 2 ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --help|-h) usage ;;
        *)       FORWARD+=("$1"); shift ;;
    esac
done

[[ -n "$HOST" ]] || die "--host este obligatoriu"
[[ -n "$USER" ]] || die "--user a primit o valoare goală"
# exact UN token: o verificare pe subșir lăsa să treacă «backup os» (două nume într-un argument)
case "$PHASE" in
    preflight|backup|os|containers|reboot|verify|status) ;;
    *) die "--phase trebuie să fie exact una dintre: ${PHASES} (nu '${PHASE}')" ;;
esac
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--port cere un număr"

# Fiecare argument trimis gazdei ajunge într-un șir de comandă ssh. Un spațiu, un `;` sau un
# apostrof într-unul ar fi comenzi, nu argumente — refuzate aici, înainte de orice rețea.
# (Pe lângă asta, fiecare e trecut prin printf %q mai jos.)
for a in ${FORWARD[@]+"${FORWARD[@]}"}; do
    [[ "$a" =~ ^[A-Za-z0-9_.,:/=@+-]+$ ]] || die "argument refuzat (caractere nepermise pentru o comandă la distanță): '${a}'"
done

if [[ -z "$KEY" && -f "$DEPLOY_KEY_DEFAULT" ]]; then
    KEY="$DEPLOY_KEY_DEFAULT"
    info "folosesc cheia implicită ${KEY} (merge cu --user ${DEPLOY_USER_DEFAULT})"
elif [[ -z "$KEY" ]]; then
    warn "nu s-a dat --key și ${DEPLOY_KEY_DEFAULT} nu există; ssh va alege o identitate."
fi
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=20 -p "$SSH_PORT")
if [[ -n "$KEY" ]]; then
    KEY="${KEY/#\~/$HOME}"
    [[ -f "$KEY" ]] || die "cheia ssh nu există: ${KEY}"
    SSH_OPTS+=(-i "$KEY")
fi

ssh_run() { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"; }

# --- fișierele locale ------------------------------------------------------
# Un CR într-un .sh devine `bad interpreter: bash^M` pe gazdă. Verificat pe octeți
# (`tr -d` + `cmp`), nu cu `grep $'\r'`, care pe unele Git Bash numără toate liniile.
for f in "${LIB_FILES[@]}"; do
    [[ -f "${LIB_DIR}/${f}" ]] || die "lipsește ${LIB_DIR}/${f}"
    if ! tr -d '\r' < "${LIB_DIR}/${f}" | cmp -s - "${LIB_DIR}/${f}"; then
        die "${f} conține CR (sfârșituri de linie Windows); refuz să-l trimit. Vezi .gitattributes și scripts/lib/check-line-endings.sh"
    fi
    bash -n "${LIB_DIR}/${f}" || die "${f} nu trece de bash -n"
done

# --- confirmarea, aici, pe terminalul operatorului ----------------------------
# «E simulare?» se decide cum o decide gazda (parse_args din system-update-host.sh), nu după un tipar `--dry-run`
# oriunde în argumente: o opțiune cu valoare CONSUMĂ tokenul următor. Altfel `--rebuild --dry-run` părea simulare aici
# (fără confirmare), iar gazda citea `--dry-run` ca valoare a lui --rebuild și pornea rularea în serios. O listă de
# proiecte care lipsește sau începe cu `-` se refuză aici, înainte de orice rețea (gazda o refuză la fel, cu 2).
LIST_OPTS=" --rebuild --accept-drift --only --retry-failed --acknowledge "
VALUE_OPTS="${LIST_OPTS}--gap --wait --health-timeout --stable "
is_dry_run=0; skip_value=0; prev=""
for a in ${FORWARD[@]+"${FORWARD[@]}"}; do
    if (( skip_value )); then
        if [[ "$LIST_OPTS" == *" ${prev} "* && "$a" == -* ]]; then
            die "${prev} cere o listă de proiecte, nu o altă opțiune (primit '${a}'); nu s-a pornit nimic"
        fi
        skip_value=0; continue
    fi
    if [[ "$a" == --dry-run ]]; then is_dry_run=1
    elif [[ "$VALUE_OPTS" == *" ${a} "* ]]; then skip_value=1; prev="$a"
    fi
done
(( skip_value )) && { [[ "$LIST_OPTS" == *" ${prev} "* ]] && die "${prev} cere o listă de proiecte (lipsește valoarea); nu s-a pornit nimic"; }
needs_confirm=0
case "$PHASE" in
    os|reboot) needs_confirm=1 ;;
    containers) (( is_dry_run )) || needs_confirm=1 ;;
esac
if (( needs_confirm && ! ASSUME_YES )); then
    case "$PHASE" in
        os) cat <<'EOF'

  ┌────────────────────────────────────────────────────────────────────┐
  │  Actualizare completă a sistemului, cu gestionarul gazdei:         │
  │  `dnf upgrade --refresh -y` (AlmaLinux/RHEL) sau                   │
  │  `apt-get dist-upgrade` (Debian/Ubuntu) — îl alege gazda, din      │
  │  /etc/os-release; pe orice altceva faza REFUZĂ.                    │
  │                                                                    │
  │  1. Ai rulat preflight ȘI backup, iar backup-ul a ieșit cu 0?      │
  │  2. Ai o A DOUA sesiune ssh deschisă și acces TESTAT la consola    │
  │     VPS-ului de la provider (nucleul se schimbă)?                  │
  │  3. Faza rulează într-o unitate systemd: dacă sesiunea cade, ea    │
  │     continuă. Starea o vezi cu --phase status.                     │
  │  4. nginx, mariadb, php-fpm, systemd, openssl, sudo, docker (pe    │
  │     apt și containerd) se actualizează; unele se repornesc singure │
  │     — site-urile și containerele pot clipi.                        │
  └────────────────────────────────────────────────────────────────────┘

EOF
            ;;
        containers) cat <<'EOF'

  Recrearea containerelor produce o scurtă indisponibilitate per serviciu.
  Ai rulat `--phase containers --dry-run` și ai citit ce se sare și de ce?
  Reconstruirea aplicațiilor proprii livrează CODUL DE PE DISC — numai cu --rebuild.

EOF
            ;;
        reboot) cat <<'EOF'

  ┌────────────────────────────────────────────────────────────────────┐
  │  REPORNIREA gazdei de producție, programată peste ~1 minut.        │
  │                                                                    │
  │  • toate containerele și site-urile cad ~3-5 minute;               │
  │  • blocurile Sentinel nu se persistă — blocklist-ul se golește;    │
  │  • vor veni mesaje Telegram (vps-watchdog) cât timp gazda e jos;   │
  │  • dacă nucleul nou nu pornește, singura cale e consola providerului.│
  │  Anulare după ce ai confirmat: ssh la gazdă, apoi  shutdown -c     │
  └────────────────────────────────────────────────────────────────────┘

EOF
            ;;
    esac
    read -r -p "Continui? [da/NU] " answer
    [[ "$answer" == "da" ]] || die "anulat — nimic nu s-a schimbat pe gazdă"
fi

# --- ssh + sudo -------------------------------------------------------------
info "mă conectez la ${USER}@${HOST}:${SSH_PORT}"
ssh_run "echo conectat" > /dev/null || die "nu pot ajunge la ${HOST}. Verifică adresa, cheia și firewall-ul providerului."
ssh_run "sudo -n true" || die "sudo nu răspunde fără parolă pentru ${USER}; faza nu poate rula neinteractiv"
ok "ssh și sudo -n funcționează"

# --- trimitere + verificare -------------------------------------------------
# tar peste ssh, un singur apel. Verificarea e suma citită de pe gazdă, după: `tar` ieșit
# cu 0 nu dovedește că fișierul de acolo are aceiași octeți.
info "trimit ${#LIB_FILES[@]} fișiere în ${REMOTE_BIN} (root-only)"
ssh_run "sudo -n install -d -m 0700 '${REMOTE_BIN}'" || die "nu pot crea ${REMOTE_BIN} pe gazdă"
tar -C "$LIB_DIR" -cf - "${LIB_FILES[@]}" \
    | ssh_run "sudo -n tar -C '${REMOTE_BIN}' -xf - --no-same-owner --no-same-permissions" \
    || die "transferul a eșuat"
ssh_run "sudo -n chmod 0700 $(printf "'${REMOTE_BIN}/%s' " "${LIB_FILES[@]}")" || die "chmod pe gazdă a eșuat"

# sha256sum din Git Bash pe Windows scrie `hash *nume` (mod binar), cel de pe Linux `hash  nume`:
# comparate brut, sumele ar fi "diferite" la fiecare rulare reală. Se normalizează ambele părți.
norm_sums() { awk '{ n = $2; sub(/^[*]/, "", n); sub(/.*[/]/, "", n); print $1 "  " n }'; }
want="$(cd "$LIB_DIR" && sha256sum "${LIB_FILES[@]}" | norm_sums)"
# Căi absolute, fără `cd`: directorul e root 0700, iar un `cd` ar rula ca sentinel-deploy
# (Permission denied) — doar `sha256sum` are sudo.
got="$(ssh_run "sudo -n sha256sum $(printf "'${REMOTE_BIN}/%s' " "${LIB_FILES[@]}")" | norm_sums)" \
    || die "nu pot citi sumele de pe gazdă — nu pot dovedi ce rulează"
if [[ "$want" != "$got" ]]; then
    printf 'local:\n%s\nlocalizat pe gazdă:\n%s\n' "$want" "$got" >&2
    die "sumele SHA-256 nu se potrivesc — fișierele de pe gazdă NU sunt cele din depozit; nu rulez nimic"
fi
ok "sumele SHA-256 coincid (citite de pe gazdă)"

# --- rularea ----------------------------------------------------------------
remote_args=()
[[ "$PHASE" == reboot ]] && remote_args+=(--yes)
for a in ${FORWARD[@]+"${FORWARD[@]}"}; do remote_args+=("$a"); done
remote_cmd="sudo -n /usr/bin/bash '${REMOTE_BIN}/system-update-host.sh' ${PHASE}"
for a in ${remote_args[@]+"${remote_args[@]}"}; do remote_cmd+=" $(printf '%q' "$a")"; done

info "pornesc faza ${PHASE}"
rc=0
ssh_run "$remote_cmd" || rc=$?
printf '\n'
case "$rc" in
    0)   ok "faza ${PHASE}: cod 0 — citește linia REZULTAT de mai sus: «TOTUL DOVEDIT», sau «DOVEDIT, cu N servicii recunoscute de operator» (acelea rămân NERESOLVATE în fapt)" ;;
    1)   warn "faza ${PHASE}: EȘEC sau ceva mai rău decât la baseline (cod 1) — citește ce e marcat [x] mai sus" ;;
    3)   warn "faza ${PHASE}: NECUNOSCUT (cod 3) — ceva n-a putut fi măsurat; asta NU e «bine»" ;;
    255) warn "ssh a căzut (cod 255). Fazele os și containers continuă pe gazdă, într-o unitate systemd; citește starea:"
         warn "    ./scripts/system-update.sh --host ${HOST} --user ${USER} --phase status" ;;
    *)   warn "faza ${PHASE}: cod de ieșire neașteptat ${rc}" ;;
esac
exit "$rc"
