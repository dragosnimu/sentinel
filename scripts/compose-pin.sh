#!/usr/bin/env bash
#
# Fixează imaginile unui fișier docker-compose de pe gazdă pe o versiune sau un digest, fără să schimbe ce rulează, și curăță drift-ul pe care
# îl creează. De pe stația operatorului (Git Bash sau WSL), ca system-update.sh.
#
#   ./scripts/compose-pin.sh --host H --user U --key K show --file /root/docker-compose.yml
#   ./scripts/compose-pin.sh --host H --user U --key K pin --file /root/docker-compose.yml \
#         --pin traefik=traefik:v3.8.0 --pin n8n=docker.n8n.io/n8nio/n8n:2.49.5 [--allow-version-change] [--allow-floating-tag] [--yes]
#   ./scripts/compose-pin.sh --host H --user U --key K recreate --file /root/docker-compose.yml --service traefik,n8n [--yes]
#   ./scripts/compose-pin.sh --host H --user U --key K restore --file /root/docker-compose.yml [--backup B] [--force] [--yes]
#
#   --host H   gazda            --user U   implicit sentinel-deploy
#   --key K    cheia privată    --port P   portul ssh (22)
#   show       doar citire: pentru fiecare serviciu, imaginea scrisă, dacă are build: (construit local, nu se fixează), containerul care rulează
#              (id imagine, RepoDigests), dacă referința e fixată și dacă există drift de config-hash (eticheta containerului ≠ fișierul).
#   pin        --pin SERVICIU=REF (de câte ori e nevoie); REF = nume:versiune sau nume@sha256:.... Se refuză aici, înainte de orice rețea: `latest`,
#              eticheta goală, lipsa etichetei și etichetele FLOTANTE (`stable`, `v3`, `v3.8`, `16-alpine`, `next`: orice nu e MAJOR.MINOR.PATCH
#              sau digest), afară de --allow-floating-tag. Implicit pin PUR: REF se trage pe gazdă și se refuză dacă nu e EXACT imaginea pe care
#              containerul serviciului o rulează acum. --allow-version-change acceptă altă versiune (vezi «după un pin» mai jos).
#   recreate   --service S[,S]: repornește pe ACEEAȘI imagine serviciile fixate în fișier al căror config-hash a rămas în urmă (drift), cu
#              `docker compose up -d --no-deps --no-build --force-recreate`, și DOVEDEȘTE: container nou, imaginea fixată, hash la zi, healthy,
#              stabil. Refuză serviciile cu build:, fără drift, care nu rulează, nefixate sau care ar schimba versiunea. Indisponibilitate de
#              câteva secunde per serviciu. Nu face rollback singur: pe eșec tipărește comenzile exacte.
#   restore    pune la loc copia de rezervă scrisă de `pin` (implicit cea mai nouă), doar dacă fișierul e încă exact cel scris de unealtă.
#   --project P  numele proiectului compose (implicit: cel al containerelor create din fișier)
#   --yes        sare peste confirmare (vezi mai jos)
#   Contul are nevoie doar de `sudo -n`. Exemplu:
#   ./scripts/compose-pin.sh --host n8n.srv1051579.hstgr.cloud --user dragos --key ~/.ssh/id_ed25519 show --file /root/docker-compose.yml
#
# De ce există: `image: traefik` și `image: docker.n8n.io/n8nio/n8n` înseamnă `:latest`, iar `system-update.sh --phase containers` trage ce
# numește fișierul compose: în ziua în care n8n marchează 3.x «stable», o mentenanță de rutină ar face un upgrade major neplanificat.
#
# După un pin (citit din scripts/lib/system-update-containers.sh, dovedit de teste care rulează faza reală): schimbarea șirului `image:` schimbă
# config-hash-ul serviciului, iar faza containers ține orice serviciu cu hash diferit ca `hold-config-drift`, în afară de `--accept-drift <proiect>`.
#   * PIN PUR: cu --accept-drift pull-ul dă aceeași imagine (`up-to-date`), nu recreează nimic, iar eticheta de hash rămâne veche (drift permanent).
#     De aceea `pin` tipărește comanda `recreate` de rulat; până atunci faza containers raportează hold-config-drift pentru serviciu.
#   * VERSIUNE NOUĂ (--allow-version-change): faza containers o REȚINE, nu o aplică. Se aplică cu `system-update.sh --phase containers
#     --accept-drift <proiect>` (comanda exactă o tipărește `pin`); `recreate` o refuză (ar pune imaginea în afara evidenței system-update).
#   * Sfatul din `pin` se judecă cu ACELAȘI predicat ca poarta lui `recreate` (recreate_eligibility, pe starea reală de după scriere): `recreate` apare doar dacă
#     ar fi acceptat acum; altfel `pin` explică de ce nu există o comandă de rulat. Un pin FLOTANT (--allow-floating-tag) nu e eligibil (poarta cere un serviciu
#     fixat): alternativele sunt re-fixarea pe o versiune întreagă sau `restore`. `--accept-drift` e sfătuit doar dacă faza ar recreea serviciul (accept_drift_eligibility).
#   * Rollback: un `recreate` care n-a ajuns la `docker compose up` (refuz, «nu are drift», măsurare eșuată înainte) NU tipărește niciun rollback; gazda
#     marchează COMPOSE_PIN_UP_RAN=1 chiar înainte de up, iar rollback-ul se tipărește doar cu marcajul și cu verificarea eșuată (cod 1).
# Ce face `pin` pe gazdă (detaliile și dovezile sunt în antetul scripts/lib/compose-pin-host.sh): editează DOAR valoarea liniei `image:`, cu copie de
# rezervă 0600 scrisă înainte și scriere atomică, apoi DOVEDEȘTE prin `docker compose config --format json` că imaginile sunt cele cerute și că restul
# configurației e neschimbat; dacă proba pică, pune copia la loc și dovedește restaurarea. Tipărește diferența (doar liniile image:), calea copiei și
# comanda exactă de rollback.
#
# Confirmarea (pin, recreate, restore; fără --yes): se rulează întâi un PLAN pe gazdă (aceleași verificări, nimic schimbat), se arată ce se va întâmpla
# (pentru recreate: ce container se oprește), se cere «da», iar acțiunea pornește cu suma fișierului din plan: dacă fișierul s-a schimbat între
# timp, gazda refuză.
#
# Codul de ieșire: 0 = totul dovedit (sau nimic de făcut); 1 = refuzat sau eșuat; 2 = argumente greșite; 3 = ceva n-a putut fi măsurat
# (NU e «bine»); 4 = un container al proiectului s-a schimbat în timpul rulării; 255 = ssh a căzut (verifică cu `show`).
#
# Ce face acest script, și doar atât: validează argumentele AICI, înainte de orice rețea, și trimite scripts/lib/compose-pin-host.sh pe stdin
# într-un `sudo -n bash -s`. Nu lasă nimic pe gazdă (deci nu are ce sumă să verifice) și nu rulează nimic în afară de ssh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_LIB="${REPO_ROOT}/scripts/lib/compose-pin-host.sh"

DEPLOY_USER_DEFAULT="sentinel-deploy"
HOST=""; USER="$DEPLOY_USER_DEFAULT"; KEY=""; SSH_PORT=22; SUB=""; FILE=""; PROJECT=""; ALLOW=0; ALLOW_FLOAT=0; ASSUME_YES=0; SERVICES=""; BACKUP=""; FORCE=0
PINS=()
FULL_VERSION_RE='^v?[0-9]+\.[0-9]+\.[0-9]+([-+_.][A-Za-z0-9._+-]+)?$'

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 2; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 cere o valoare nevidă"; }
set_sub() { [[ -z "$SUB" ]] || die "o singură subcomandă (am deja '$SUB', nu și '$1')"; SUB="$1"; }

# Aceeași regulă ca split_ref din scripts/lib/compose-pin-host.sh (gazda o verifică încă o dată): `latest`, eticheta goală și lipsa ei sunt
# refuzate, fiindcă un pin care nu fixează nimic nu e un pin; REF_FLOATING=1 pentru o etichetă care nu e MAJOR.MINOR.PATCH și nu are digest.
split_ref() {
    local ref="$1" rest last tag="" name digest=""
    REF_WHY=""; REF_FLOATING=0
    if [[ ${#ref} -gt 255 || ! "$ref" =~ ^[a-z0-9][A-Za-z0-9._:/@-]*$ ]]; then REF_WHY="caractere nepermise (sau prea lung)"; return 1; fi
    rest="$ref"
    if [[ "$rest" == *@* ]]; then
        digest="${rest#*@}"; rest="${rest%%@*}"
        [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { REF_WHY="digestul trebuie să fie sha256:<64 cifre hex>"; return 1; }
    fi
    last="${rest##*/}"
    if [[ "$last" == *:* ]]; then
        tag="${last##*:}"; name="${rest%:*}"
        [[ -n "$tag" ]] || { REF_WHY="eticheta e goală (după ':' nu urmează nimic)"; return 1; }
        [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { REF_WHY="etichetă invalidă"; return 1; }
        [[ "${tag,,}" != latest ]] || { REF_WHY="\`latest\` nu fixează nimic"; return 1; }
    else
        name="$rest"
    fi
    [[ -n "$name" && ! "$name" =~ (//|\.\.|:$|:/) && "$name" =~ ^[a-z0-9][a-z0-9._/:-]*[a-z0-9]$|^[a-z0-9]$ ]] || { REF_WHY="numele imaginii e invalid"; return 1; }
    [[ -n "$tag" || -n "$digest" ]] || { REF_WHY="nu are nici etichetă, nici digest (fără etichetă înseamnă latest)"; return 1; }
    if [[ -z "$digest" && ! "$tag" =~ $FULL_VERSION_RE ]]; then REF_FLOATING=1; fi
    return 0
}

# Fiecare argument care ajunge în comanda ssh trece prin printf %q: citarea NU se bazează pe validarea de mai jos (un `;` sau un `$(...)` scăpat
# de ea ar rămâne text, nu comandă). Funcții separate, ca un test să le poată chema cu valori pe care validarea le-ar refuza.
remote_arg() { printf '%q' "$1"; }
build_remote_cmd() {
    local out="sudo -n bash -s -- $1" a
    shift
    for a in "$@"; do out+=" $(remote_arg "$a")"; done
    printf '%s' "$out"
}

# Încărcat cu `source` de teste: doar funcțiile de mai sus, fără parcurgerea argumentelor.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    need_value "$@"; HOST="$2"; shift 2 ;;
        --user)    need_value "$@"; USER="$2"; shift 2 ;;
        --key)     need_value "$@"; KEY="$2"; shift 2 ;;
        --port)    need_value "$@"; SSH_PORT="$2"; shift 2 ;;
        --file)    need_value "$@"; FILE="$2"; shift 2 ;;
        --project) need_value "$@"; PROJECT="$2"; shift 2 ;;
        --pin)     need_value "$@"; PINS+=("$2"); shift 2 ;;
        --service) need_value "$@"; SERVICES="$2"; shift 2 ;;
        --backup)  need_value "$@"; BACKUP="$2"; shift 2 ;;
        --allow-version-change) ALLOW=1; shift ;;
        --allow-floating-tag)   ALLOW_FLOAT=1; shift ;;
        --force)   FORCE=1; shift ;;
        --yes|-y)  ASSUME_YES=1; shift ;;
        --help|-h) usage ;;
        show|pin|recreate|restore) set_sub "$1"; shift ;;
        *)         die "argument necunoscut: '$1' (subcomenzi: show --file F | pin --file F --pin SERVICIU=REF ... | recreate --file F --service S[,S] | restore --file F [--backup B] [--force])" ;;
    esac
done

[[ -n "$SUB" ]] || die "lipsește subcomanda (show | pin | recreate | restore)"
[[ -n "$HOST" ]] || die "--host este obligatoriu"
[[ "$HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || die "--host refuzat (caractere nepermise; un nume care începe cu - ar deveni o opțiune ssh): '${HOST}'"
[[ "$USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "--user refuzat: '${USER}'"
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || die "--port cere un număr"
(( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || die "--port în afara 1-65535"
[[ -n "$FILE" ]] || die "--file este obligatoriu (calea absolută a fișierului compose de pe gazdă)"
[[ ${#FILE} -le 200 && "$FILE" =~ ^/[A-Za-z0-9._/@+-]+$ && ! "$FILE" =~ (^|/)\.\.(/|$) && "$FILE" != */ ]] \
    || die "--file refuzat (cer o cale absolută, fără .., fără spații sau caractere speciale): '${FILE}'"
if [[ -n "$PROJECT" ]]; then
    [[ ${#PROJECT} -le 64 && "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "--project refuzat: '${PROJECT}'"
fi
# Opțiunile care aparțin unei singure subcomenzi nu se ignoră în tăcere pe alta: o opțiune ignorată e o decizie pe care operatorul crede că a luat-o.
[[ ${#PINS[@]} -eq 0 && $ALLOW -eq 0 && $ALLOW_FLOAT -eq 0 || "$SUB" == pin ]] || die "--pin, --allow-version-change și --allow-floating-tag sunt doar pentru pin"
[[ -z "$SERVICES" || "$SUB" == recreate ]] || die "--service e doar pentru recreate"
[[ -z "$BACKUP" && $FORCE -eq 0 || "$SUB" == restore ]] || die "--backup și --force sunt doar pentru restore"
[[ "$SUB" != show || $ASSUME_YES -eq 0 ]] || die "show nu primește --yes"
case "$SUB" in
    pin)
        [[ ${#PINS[@]} -gt 0 ]] || die "pin cere cel puțin un --pin SERVICIU=REF"
        seen=" "
        for p in "${PINS[@]}"; do
            [[ "$p" == *=* ]] || die "--pin cere SERVICIU=REF, nu '${p}'"
            svc="${p%%=*}"; ref="${p#*=}"
            [[ ${#svc} -le 64 && "$svc" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "nume de serviciu invalid în --pin: '${svc}'"
            split_ref "$ref" || die "REF refuzat pentru ${svc} ('${ref}'): ${REF_WHY}"
            if [[ $REF_FLOATING -eq 1 && $ALLOW_FLOAT -eq 0 ]]; then
                die "eticheta lui ${svc} ('${ref}') e FLOTANTĂ: registrul o poate muta, deci nu fixează o versiune. Cer o versiune întreagă (MAJOR.MINOR.PATCH, ex. 2.49.5) sau un digest @sha256:...; dacă vrei oricum, --allow-floating-tag"
            fi
            [[ "$seen" != *" ${svc} "* ]] || die "serviciul ${svc} apare în două --pin"
            seen+="${svc} "
        done ;;
    recreate)
        [[ -n "$SERVICES" ]] || die "recreate cere --service S[,S]"
        seen=","
        IFS=, read -r -a svc_list <<< "$SERVICES"
        for svc in "${svc_list[@]}"; do
            [[ ${#svc} -le 64 && "$svc" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "nume de serviciu invalid în --service: '${svc}'"
            [[ "$seen" != *",${svc},"* ]] || die "serviciul ${svc} apare de două ori în --service"
            seen+="${svc},"
        done ;;
    restore)
        if [[ -n "$BACKUP" ]]; then
            [[ "$BACKUP" == "${FILE}.pin-bak-"* && "$BACKUP" =~ ^/[A-Za-z0-9._/@+-]+$ && ! "$BACKUP" =~ \.sums$ ]] \
                || die "--backup refuzat: trebuie să fie ${FILE}.pin-bak-<UTC> (copia scrisă de pin)"
        fi ;;
esac

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

# Argumentele pe gazdă (fiecare prin remote_arg).
remote_args=(--file "$FILE")
[[ -z "$PROJECT" ]] || remote_args+=(--project "$PROJECT")
case "$SUB" in
    pin)
        for p in "${PINS[@]}"; do remote_args+=(--pin "$p"); done
        [[ $ALLOW -eq 0 ]] || remote_args+=(--allow-version-change)
        [[ $ALLOW_FLOAT -eq 0 ]] || remote_args+=(--allow-floating-tag) ;;
    recreate) remote_args+=(--service "$SERVICES") ;;
    restore)
        [[ -z "$BACKUP" ]] || remote_args+=(--backup "$BACKUP")
        [[ $FORCE -eq 0 ]] || remote_args+=(--force) ;;
esac

# UN SINGUR loc în care se construiește orice comandă pe care o tipărim ca «rulează asta»: din TOT ce selectează ținta în rularea aceasta (gazdă, cont, cheie,
# port, fișier, proiect), citat de remote_arg. De trei ori o comandă tipărită a căzut când rulată întocmai fiindcă îi lipsea un argument al țintei (ultima oară
# --project: cu un proiect pornit din alte fișiere, autodetectarea alege altul). O comandă nouă se adaugă prin advise, nu prin concatenare.
CONN_ARGS=(--host "$HOST" --user "$USER")
[[ -z "$KEY" ]] || CONN_ARGS+=(--key "$KEY")
[[ "$SSH_PORT" == 22 ]] || CONN_ARGS+=(--port "$SSH_PORT")
TARGET_ARGS=(--file "$FILE")
[[ -z "$PROJECT" ]] || TARGET_ARGS+=(--project "$PROJECT")
# advise SUBCOMANDĂ [argumente suplimentare...] -> comanda acestui script, pentru aceeași țintă
advise() {
    local sub="$1" a out="./scripts/compose-pin.sh"
    shift
    for a in "${CONN_ARGS[@]}"; do out+=" $(remote_arg "$a")"; done
    out+=" $(remote_arg "$sub")"
    for a in "${TARGET_ARGS[@]}" "$@"; do out+=" $(remote_arg "$a")"; done
    printf '%s' "$out"
}
# la fel pentru system-update.sh: ia doar conexiunea (țintește gazda, nu un fișier compose)
advise_update() {
    local a out="./scripts/system-update.sh"
    for a in "${CONN_ARGS[@]}"; do out+=" $(remote_arg "$a")"; done
    for a in "$@"; do out+=" $(remote_arg "$a")"; done
    printf '%s' "$out"
}

out_file="$(mktemp)"
trap 'rm -f -- "$out_file"' EXIT

# Trimite biblioteca și rulează comanda $1; codul gazdei în $rc, ieșirea ei și în $out_file.
run_remote() {
    info "trimit scripts/lib/compose-pin-host.sh și pornesc: ${SUB}"
    rc=0
    set +e
    ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$1" < "$HOST_LIB" 2>&1 | tee "$out_file"
    rc="${PIPESTATUS[0]}"
    set -e
    printf '\n'
}

report_rc() {
    case "$rc" in
        0)   ok "${SUB}: cod 0" ;;
        1)   warn "${SUB}: REFUZAT sau EȘUAT (cod 1) — citește ce e marcat [x] mai sus" ;;
        2)   warn "${SUB}: argumente greșite pe gazdă (cod 2)" ;;
        3)   warn "${SUB}: NECUNOSCUT (cod 3) — ceva n-a putut fi măsurat; asta NU e «bine»" ;;
        4)   warn "${SUB}: UN CONTAINER AL PROIECTULUI S-A SCHIMBAT (cod 4) — citește mesajul de mai sus înainte de orice altceva" ;;
        255) warn "ssh a căzut (cod 255). Fișierul sau containerele pot fi schimbate sau nu; citește starea:"
             warn "    $(advise show)" ;;
        *)   warn "${SUB}: cod de ieșire neașteptat ${rc}" ;;
    esac
}

# Pașii următori ADEVĂRAȚI după un pin, din liniile COMPOSE_PIN_NEXT= ale gazdei (măsurate pe gazdă din hash-uri, nu presupuse aici).
print_next_steps() {
    local line recreate_list="" accept_project="" explain_list="" kind a b
    while IFS= read -r line; do
        read -r kind a b <<< "${line#COMPOSE_PIN_NEXT=}"
        case "$kind" in
            recreate) recreate_list+="${recreate_list:+,}${a}" ;;
            accept-drift) accept_project="$a" ;;
            explain) explain_list+="${explain_list:+, }${a}:${b}" ;;
        esac
    done < <(grep '^COMPOSE_PIN_NEXT=' "$out_file" || true)
    if [[ -n "$recreate_list" ]]; then
        warn "PASUL URMĂTOR (pin pur): până îl rulezi, faza containers raportează hold-config-drift pentru: ${recreate_list}."
        warn "    $(advise recreate --service "${recreate_list}")"
        warn "    (repornește containerele pe aceeași imagine, cu scurtă indisponibilitate; --accept-drift NU ajută la un pin pur)"
    fi
    if [[ -n "$accept_project" ]]; then
        warn "PASUL URMĂTOR (versiune nouă): faza containers o REȚINE (hold-config-drift), nu o aplică. Aplicarea:"
        warn "    $(advise_update --phase containers --accept-drift "${accept_project}" --dry-run)   (întâi, ca să vezi ce face)"
        warn "    $(advise_update --phase containers --accept-drift "${accept_project}")"
        warn "    (--accept-drift acceptă driftul tuturor serviciilor proiectului ${accept_project}; \`recreate\` refuză o schimbare de versiune)"
    fi
    if [[ -n "$explain_list" ]]; then
        warn "NU EXISTĂ O COMANDĂ DE RULAT pentru: ${explain_list} (serviciu:motiv). Gazda a explicat mai sus de ce și ce alternative sunt; nimic de aici nu se rezolvă de la sine."
        explain_alternatives
    fi
}

# Alternativele ca COMENZI exacte (cu ținta întreagă): re-fixarea (singurul lucru pe care operatorul trebuie să-l completeze e versiunea; numele imaginii e
# cel dat la pin) și readucerea fișierului din copia scrisă de această rulare.
explain_alternatives() {
    local line kind svc cls p name ref last backup
    backup="$(sed -n 's/^COMPOSE_PIN_BACKUP=\(.*\)$/\1/p' "$out_file" | tail -n 1)"
    while IFS= read -r line; do
        read -r kind svc cls <<< "${line#COMPOSE_PIN_NEXT=}"
        [[ "$kind" == explain && "$cls" == floating ]] || continue
        for p in "${PINS[@]}"; do
            [[ "${p%%=*}" == "$svc" ]] || continue
            ref="${p#*=}"; last="${ref##*/}"; name="$ref"
            [[ "$last" != *:* ]] || name="${ref%:*}"
            warn "  (1) re-fixează pe o versiune întreagă (înlocuiește <MAJOR.MINOR.PATCH>):"
            warn "      $(advise pin --pin "${svc}=${name}:<MAJOR.MINOR.PATCH>")"
        done
    done < <(grep '^COMPOSE_PIN_NEXT=' "$out_file" || true)
    if [[ -n "$backup" ]]; then
        warn "  (2) readu fișierul de dinainte de acest pin:"
        warn "      $(advise restore --backup "$backup")"
    fi
}

# Ce se spune după un `recreate` care n-a ieșit cu 0, DOAR din ce a raportat gazda: marcajul COMPOSE_PIN_UP_RAN=1 există numai dacă `docker compose up` a
# fost pornit. Fără el nu s-a repornit nimic și fișierul nu s-a schimbat (un refuz, un «nu are drift», o măsurare eșuată înainte de up): niciun rollback,
# doar motivul (marcat [x] mai sus). Cu el: rollback (restore) doar dacă verificarea a eșuat (cod 1); la 3/4/255 starea nu e dovedită și nu se recomandă
# nimic care schimbă fișierul pe încredere.
recreate_followup() {
    local up_ran=0
    grep -q '^COMPOSE_PIN_UP_RAN=1$' "$out_file" && up_ran=1
    if [[ $up_ran -eq 0 ]]; then
        if [[ $rc -eq 255 ]]; then
            warn "ssh a căzut și n-am văzut dacă \`docker compose up\` a pornit: nu recomand niciun rollback; citește starea (comanda de mai sus)."
        else
            warn "NU s-a repornit nimic: gazda n-a ajuns la \`docker compose up\` (refuz sau măsurare nereușită dinainte); fișierul nu s-a schimbat, deci nu e nimic de readus. Motivul e marcat [x] mai sus."
        fi
    elif [[ $rc -eq 1 ]]; then
        warn "ROLLBACK (nu se face singur; \`up\` A RULAT și verificarea a eșuat): readu fișierul cu"
        warn "    $(advise restore)"
        warn "  apoi, dacă un container trebuie repornit pe imaginea veche, comanda exactă e tipărită mai sus de gazdă."
    else
        warn "\`docker compose up\` A RULAT, dar rezultatul nu e dovedit (cod ${rc}): citește starea ($(advise show)) înainte de orice; nu rula restore pe încredere, el readuce doar fișierul."
    fi
}

rc=0
if [[ "$SUB" != show && $ASSUME_YES -eq 0 ]]; then
    run_remote "$(build_remote_cmd "$SUB" "${remote_args[@]}" --plan)"
    if [[ $rc -ne 0 ]]; then
        report_rc
        if [[ "$SUB" == recreate ]]; then recreate_followup; fi
        exit "$rc"
    fi
    if grep -q '^COMPOSE_PIN_NOOP=1$' "$out_file"; then ok "nimic de făcut"; exit 0; fi
    plan_sha="$(sed -n 's/^COMPOSE_PIN_FILE_SHA256=\([0-9a-f]\{64\}\)$/\1/p' "$out_file" | tail -n 1)"
    [[ -n "$plan_sha" ]] || { warn "planul s-a încheiat cu 0, dar gazda n-a raportat suma fișierului: nu pot lega acțiunea de ce ai văzut"; exit 3; }
    case "$SUB" in
        pin) cat <<'EOF'

  Se editează DOAR liniile image: de mai sus, cu copie de rezervă 0600 scrisă înainte; apoi se dovedește că restul configurației e
  neschimbat (altfel copia se pune la loc singură). Planul de mai sus a RULAT `docker pull` pe referințele numite (nu atinge containerele
  care rulează; imaginea rămâne pe disc dacă renunți). NU se recreează niciun container acum. Config-hash-ul serviciilor se schimbă: faza
  containers le va ține ca hold-config-drift până faci pasul următor, pe care îl tipărește scriptul după.

EOF
            ;;
        recreate) cat <<'EOF'

  Containerele de mai sus se OPRESC și se recreează pe aceeași imagine (indisponibilitate de câteva secunde per serviciu), apoi se
  dovedește: container nou, imaginea fixată, config-hash la zi, healthy, stabil. Nu se face rollback singur.

EOF
            ;;
        restore) cat <<'EOF'

  Se pune la loc DOAR fișierul compose (nu se atinge niciun container), doar dacă are încă exact conținutul scris de unealtă.

EOF
            ;;
    esac
    answer=""
    read -r -p "Continui? [da/NU] " answer || answer=""
    # un răspuns gol sau un stdin închis e «nu»; anularea nu e o eroare de argumente (2), ci un refuz (1)
    if [[ "$answer" != "da" ]]; then
        # planul unui `pin` a rulat `docker pull` (singurul mod de a dovedi că REF e imaginea care rulează): fișierul și containerele sunt neatinse,
        # dar imaginea poate fi acum pe disc; textul nu are voie să spună «nimic nu s-a schimbat» peste asta
        if [[ "$SUB" == pin ]]; then
            warn "anulat — fișierul compose și containerele NU s-au atins; planul a rulat însă \`docker pull\` pe referințele numite, deci imaginile pot fi acum pe disc (docker image rm <ref> dacă nu le vrei)"
        else
            warn "anulat — nimic nu s-a schimbat pe gazdă"
        fi
        exit 1
    fi
    run_remote "$(build_remote_cmd "$SUB" "${remote_args[@]}" --expect-sha256 "$plan_sha")"
else
    run_remote "$(build_remote_cmd "$SUB" "${remote_args[@]}")"
fi
report_rc
if [[ $rc -eq 0 && "$SUB" == pin ]]; then print_next_steps; fi
if [[ $rc -ne 0 && "$SUB" == recreate ]]; then recreate_followup; fi
exit "$rc"
