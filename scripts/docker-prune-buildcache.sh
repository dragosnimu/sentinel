#!/usr/bin/env bash
#
# Eliberează DOAR cache-ul de build al lui docker de pe gazdă, și dovedește efectul. De pe stația operatorului (Git Bash sau WSL),
# ca system-update.sh.
#
#   ./scripts/docker-prune-buildcache.sh --host H --user U --key K --dry-run     # doar raportează, nu șterge nimic
#   ./scripts/docker-prune-buildcache.sh --host H --user U --key K               # arată planul, cere «da», apoi șterge
#   ./scripts/docker-prune-buildcache.sh --host H --user U --key K --yes         # fără întrebare (rulare neinteractivă)
#
#   --host H   gazda            --user U   implicit sentinel-deploy
#   --key K    cheia privată    --port P   portul ssh (22)
#   --dry-run  doar citire: cache-ul de build (intrări, în uz, eliberabil), discul, builderii; nu rulează prune
#   --yes      sare peste confirmare; fără el, un stdin care nu e terminal înseamnă «nu»
#   Contul are nevoie doar de `sudo -n`. Exemplu:
#   ./scripts/docker-prune-buildcache.sh --host 31.220.93.242 --key ~/.ssh/sentinel_deploy --dry-run
#
# De ce există: cache-ul de build al lui docker crește fără limită (intrări vechi ale unor construcții de mult terminate) și ocupă discul
# pe care rulează și site-urile operatorului. Nicio altă cale versionată de pe gazdă nu-l curăță.
#
# Ce rulează pe gazdă: `docker builder prune -a -f`, atât. NU atinge imagini (nici cele dangling; imaginile rollback/*:prev rămân), containere,
# volume sau rețele; nu există `docker system prune` nicăieri aici. Nu șterge nici builderi. Un builder buildx cu alt driver (docker-container)
# își ține cache-ul în volumul LUI, pe care `docker builder prune` pe builderul implicit nu-l atinge: dacă există, scriptul îl NUMEȘTE și
# spune cum se curăță (`docker buildx prune --builder NUME -a -f`), dar nu o face. Dacă builderul CURENT al lui root nu e `default`
# (driver docker), scriptul REFUZĂ (cod 1): prune ar curăța cache-ul altuia decât cel pe care îl măsurăm.
#
# Efectul se MĂSOARĂ, nu se presupune. Înainte și după, gazda dă lista intrărilor de cache (identificator, în uz, octeți) din API-ul
# daemonului, spațiul `df` al DockerRootDir, imaginile (ID complet + depozit:etichetă) și volumele. Apoi:
#   * «eliberat» = octeții intrărilor eliberabile de dinainte care NU mai există după. «Eliberabil» = nici în uz, nici Shared=true (partajat cu
#     o imagine): exact coloana RECLAIMABLE a lui `docker system df`. Dacă înainte era ceva eliberabil și nu a dispărut
#     nicio intrare: eșec (cod 1), oricât de zero ar fi ieșit prune. Ce a rămas (în uz sau nu) se tipărește;
#   * dacă o imagine (ID sau depozit:etichetă) sau un volum de dinainte lipsește după: cod 4, cu lista. Asta e garda că prune n-a ieșit
#     din domeniul lui. Ce a APĂRUT între timp (un build sau un deploy în paralel) se raportează, nu se pedepsește;
#   * `df` se raportează ca context, nu hotărăște: alte procese scriu pe același disc și între cele două măsurători.
#
# Codul de ieșire: 0 = făcut și dovedit, sau nimic de făcut (cache gol / totul în uz) / --dry-run; 1 = refuzat sau eșuat (sudo refuzat, docker
# oprit, builder curent greșit, prune a ieșit cu cod nenul, cache-ul nu s-a micșorat, răspuns negativ la confirmare); 2 = argumente greșite;
# 3 = ceva n-a putut fi măsurat (NU e «bine»; de ex. n-am putut măsura după prune); 4 = o imagine sau un volum a DISPĂRUT; 255 = ssh a căzut
# (dacă a căzut în timpul prune, rezultatul e necunoscut: rulează `--dry-run`; prune e idempotent).
#
# Ce face acest script, și doar atât: validează argumentele AICI, înainte de orice rețea, și trimite scripts/lib/docker-prune-buildcache-host.sh
# pe stdin într-un `sudo -n bash -s`. Nu lasă nimic pe gazdă; fișierele de lucru sunt într-un director temporar LOCAL, șters la ieșire.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_LIB="${REPO_ROOT}/scripts/lib/docker-prune-buildcache-host.sh"

DEPLOY_USER_DEFAULT="sentinel-deploy"
HOST=""; USER="$DEPLOY_USER_DEFAULT"; KEY=""; SSH_PORT=22; DRY_RUN=0; ASSUME_YES=0

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 2; }
info() { printf '\033[34m[.]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 cere o valoare nevidă"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    need_value "$@"; HOST="$2"; shift 2 ;;
        --user)    need_value "$@"; USER="$2"; shift 2 ;;
        --key)     need_value "$@"; KEY="$2"; shift 2 ;;
        --port)    need_value "$@"; SSH_PORT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes|-y)  ASSUME_YES=1; shift ;;
        --help|-h) usage ;;
        *)         die "argument necunoscut: '$1' (opțiuni: --host H --user U --key K --port P --dry-run --yes)" ;;
    esac
done

[[ -n "$HOST" ]] || die "--host este obligatoriu"
[[ "$HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || die "--host refuzat (caractere nepermise; un nume care începe cu - ar deveni o opțiune ssh): '${HOST}'"
[[ "$USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "--user refuzat: '${USER}'"
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || die "--port cere un număr"
(( 10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535 )) || die "--port în afara 1-65535"
(( DRY_RUN == 0 || ASSUME_YES == 0 )) || die "--dry-run și --yes se exclud: --dry-run nu șterge nimic, deci nu are ce confirma"

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

# Un CR într-un .sh devine `bad interpreter: bash^M` pe gazdă. Verificat pe octeți, nu cu grep.
[[ -f "$HOST_LIB" ]] || die "lipsește ${HOST_LIB}"
if ! tr -d '\r' < "$HOST_LIB" | cmp -s - "$HOST_LIB"; then
    die "$(basename "$HOST_LIB") conține CR (sfârșituri de linie Windows); refuz să-l trimit. Vezi .gitattributes"
fi
bash -n "$HOST_LIB" || die "$(basename "$HOST_LIB") nu trece de bash -n"

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
BEFORE="${WORK}/before"; AFTER="${WORK}/after"; ERR="${WORK}/err"; PRUNE_OUT="${WORK}/prune"

# `-n`-ul: stdin-ul nu trebuie consumat de sonde. Doar rularea propriu-zisă primește scriptul pe stdin.
# stderr-ul trece prin show_stderr: avertismentul ssh despre schimbul de chei s-ar tipări altfel la fiecare sondă.
ssh_probe() { local rc=0; ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@" < /dev/null 2> "$ERR" || rc=$?; show_stderr "$ERR"; return "$rc"; }

# Zgomotul pe care ssh îl scrie pe stderr la orice conexiune; restul stderr-ului e al comenzii și ajunge la operator.
show_stderr() { grep -v -E '^Warning: Permanently added|^\*\* (WARNING: connection is not using|This session may be vulnerable|The server may need to be upgraded)' "$1" >&2 || true; }

# Un număr de octeți, ca la `docker system df` (unități zecimale), cu octeții exacți alături.
human() { awk -v b="$1" 'BEGIN { split("B KB MB GB TB", u, " "); i = 1; x = b; while (x >= 1000 && i < 5) { x /= 1000; i++ } f = (i == 1 ? "%.0f %s" : "%.2f %s"); printf f, x, u[i] }'; }
fmt_bytes() { printf '%s (%.0f B)' "$(human "$1")" "$1"; }
# Diferență cu semn, în octeți (awk: octeții trec de 2^31 și mawk ar trunchia un %d).
signed_human() { awk -v d="$1" 'BEGIN { printf "%s%.0f", (d < 0 ? "-" : "+"), (d < 0 ? -d : d) }'; }

# Codul de ieșire final: cel mai grav dintre cele văzute (4 imagine/volum dispărut > 3 nemăsurat > 1 eșec > 0).
FINAL_RC=0
rank() { case "$1" in 4) echo 3 ;; 3) echo 2 ;; 1) echo 1 ;; *) echo 0 ;; esac; }
raise_rc() { if (( $(rank "$1") > $(rank "$FINAL_RC") )); then FINAL_RC="$1"; fi; }

# O operație pe gazdă: stdout -> $2, stderr -> $ERR. Întoarce codul comenzii (255 = ssh însuși).
run_host_op_quiet() {
    local rc=0
    ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "sudo -n bash -s -- $1" < "$HOST_LIB" > "$2" 2> "$ERR" || rc=$?
    tr -d '\r' < "$2" > "${2}.lf" && mv -f -- "${2}.lf" "$2"
    return "$rc"
}

# Ce înseamnă un cod nenul al bibliotecii (sau al ssh/sudo), în cuvinte pentru operator. Setează PHASE_EXIT.
explain_rc() {
    local rc="$1" what="$2"
    show_stderr "$ERR"
    case "$rc" in
        255) warn "ssh a căzut (cod 255) în timpul: ${what}."
             PHASE_EXIT=255 ;;
        11)  fail "daemonul docker nu răspunde pe gazdă (${what}): nu s-a șters nimic. Verifică \`systemctl status docker\`."
             PHASE_EXIT=1 ;;
        12)  fail "docker nu e instalat pe gazdă (${what}): nu s-a șters nimic."
             PHASE_EXIT=1 ;;
        13)  warn "n-am putut MĂSURA starea (${what}); asta NU e «bine». Mesajul gazdei e mai sus."
             PHASE_EXIT=3 ;;
        14)  fail "REFUZ (${what}): builderul curent nu e cel implicit; nu s-a șters nimic. Mesajul gazdei e mai sus."
             PHASE_EXIT=1 ;;
        15)  fail "\`docker builder prune\` a ieșit cu cod nenul (${what}); citește ce a tipărit mai sus."
             PHASE_EXIT=1 ;;
        *)   if grep -q -E '^sudo: ' "$ERR"; then
                 fail "sudo a refuzat comanda pe gazdă (${what}); contul ${USER} are nevoie de \`sudo -n\` fără parolă."
                 PHASE_EXIT=1
             else
                 warn "cod de ieșire neașteptat ${rc} în timpul: ${what}."
                 PHASE_EXIT=3
             fi ;;
    esac
}

snap_val() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

# O fotografie e bună doar dacă e ÎNTREAGĂ: încheiată cu SNAPSHOT_END, cu atâtea intrări de cache câte a numărat gazda, cu df și server.
snapshot_complete() {
    local f="$1" declared actual
    [[ "$(tail -n 1 "$f")" == SNAPSHOT_END ]] || return 1
    declared="$(snap_val "$f" BC_COUNT)"
    [[ "$declared" =~ ^[0-9]+$ ]] || return 1
    actual="$(grep -c '^BCENTRY ' "$f" || true)"
    [[ "$declared" == "$actual" ]] || return 1
    grep -q -E '^DF [0-9]+ [0-9]+ [0-9]+$' "$f" || return 1
    # fiecare intrare: BCENTRY <id> <0|1 în uz> <octeți> <0|1 partajat>; un câmp lipsă ar face o intrare «eliberabilă» din greșeală
    awk '$1 == "BCENTRY" && !(NF == 5 && $3 ~ /^[01]$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[01]$/) { bad++ } END { exit (bad > 0) }' "$f" || return 1
    [[ -n "$(snap_val "$f" DOCKER_SERVER)" ]]
}

# Ia o fotografie în $1; la orice eșec explică și iese (în faza dinainte de prune) sau întoarce 1 (după).
take_snapshot() {
    local out="$1" rc=0
    run_host_op_quiet snapshot "$out" || rc=$?
    if (( rc != 0 )); then explain_rc "$rc" "măsurarea"; return 1; fi
    show_stderr "$ERR"
    if ! snapshot_complete "$out"; then
        warn "răspunsul gazdei la măsurare e trunchiat sau nu are forma așteptată (lipsește SNAPSHOT_END, numărul de intrări nu se potrivește, sau df/server lipsesc); asta NU e «bine»."
        PHASE_EXIT=3
        return 1
    fi
}

# bc_stats FIȘIER -> "n octeți în_uz octeți_în_uz partajate octeți_partajate eliberabile octeți_eliberabili". Ordinea claselor: în uz, apoi
# partajat cu o imagine (Shared), apoi eliberabil = restul; același criteriu ca RECLAIMABLE din `docker system df`.
bc_stats() { awk '$1 == "BCENTRY" { n++; b += $4; if ($3 == 1) { u++; ub += $4 } else if ($5 == 1) { sh++; shb += $4 } else { r++; rb += $4 } }
    END { printf "%.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f", n, b, u, ub, sh, shb, r, rb }' "$1"; }
df_avail() { awk '$1 == "DF" { printf "%.0f", $4 }' "$1"; }
df_line() { awk '$1 == "DF" { printf "total %s, folosit %s, liber %s", $2, $3, $4 }' "$1"; }

# set_of FIȘIER TIP -> liniile sortate ale tipului (IMAGE sau VOLUME), fără prefix
set_of() { grep "^$2 " "$1" | sed "s/^$2 //" | LC_ALL=C sort -u || true; }

report_state() {
    local f="$1" label="$2" n b u ub sh shb r rb
    read -r n b u ub sh shb r rb <<< "$(bc_stats "$f")"
    info "cache de build ${label}: ${n} intrări, ${b} B total; în uz: ${u} (${ub} B); partajate cu imagini: ${sh} (${shb} B); eliberabile: ${r}, $(fmt_bytes "$rb")"
    info "disc ${label} ($(snap_val "$f" DOCKER_ROOT)): $(df_line "$f")"
}

report_builders() {
    local f="$1" others
    if [[ "$(grep -c '^BUILDX=' "$f" || true)" == 0 ]]; then return 0; fi
    if grep -q '^BUILDX=absent$' "$f"; then
        info "pluginul buildx lipsește pe gazdă: nu există alți builderi, \`docker builder prune\` vorbește direct cu daemonul"
        return 0
    fi
    info "builderi buildx: $(awk '$1 == "BUILDER" { printf "%s(%s%s) ", $2, $3, ($4 == 1 ? ", curent" : "") }' "$f")"
    others="$(awk '$1 == "BUILDER" && !($2 == "default" && $3 == "docker") { printf "%s ", $2 }' "$f")"
    if [[ -n "$others" ]]; then
        warn "builderi în afara celui implicit: ${others}— cache-ul lor NU e atins de acest script (nu șterg builderi și nu le curăț cache-ul). Pentru fiecare: docker buildx prune --builder NUME -a -f, de mână, dacă vrei."
    fi
}

# ---------------------------------------------------------------------------------------------------------------------------------

info "mă conectez la ${USER}@${HOST}:${SSH_PORT}"
ssh_probe "echo conectat" > /dev/null || { warn "nu pot ajunge la ${HOST}. Verifică adresa, cheia și firewall-ul providerului."; exit 1; }
ssh_probe "sudo -n true" || { fail "sudo nu răspunde fără parolă pentru ${USER}; scriptul nu poate rula neinteractiv. Nu s-a schimbat nimic."; exit 1; }
ok "ssh și sudo -n funcționează"

PHASE_EXIT=3
take_snapshot "$BEFORE" || exit "$PHASE_EXIT"

report_state "$BEFORE" "înainte"
report_builders "$BEFORE"
read -r B_N B_BYTES B_U B_UB B_S B_SB B_R B_RB <<< "$(bc_stats "$BEFORE")"

# Nimic de eliberat: intrările în uz și cele partajate cu imagini (Shared) nu le șterge `docker builder prune`, iar `docker system df` nu le
# numără ca RECLAIMABLE. «Eliberabil» de aici = nici în uz, nici partajat, adică exact ce numără și docker.
nothing_to_free() {
    if (( B_N == 0 )); then
        ok "cache-ul de build e deja gol (0 intrări); nimic de făcut"
    else
        ok "nimic de eliberat acum: din cele ${B_N} intrări ($(fmt_bytes "$B_BYTES")), ${B_U} sunt în uz (un build rulează) și ${B_S} sunt partajate cu imagini ($(fmt_bytes "$B_SB")); docker nu le șterge pe niciuna. Dacă un build rulează, încearcă după ce se termină."
    fi
    exit 0
}
if (( B_R == 0 )); then nothing_to_free; fi

if (( DRY_RUN == 1 )); then
    ok "--dry-run: s-ar rula pe gazdă \`docker builder prune -a -f\` și s-ar elibera cel mult $(fmt_bytes "$B_RB") (${B_R} intrări); ${B_U} intrări în uz și ${B_S} partajate cu imagini rămân. Nu s-a șters nimic."
    exit 0
fi

if (( ASSUME_YES == 0 )); then
    cat <<EOT

  Se rulează pe ${HOST}, ca root:  docker builder prune -a -f
  Se șterg ${B_R} intrări de cache de build, cel mult $(fmt_bytes "$B_RB"). Cele ${B_U} intrări în uz și cele ${B_S} partajate cu imagini rămân.
  NU se ating imagini (nici dangling), containere, volume, rețele. După aceea scriptul verifică asta pe gazdă și iese cu cod 4 dacă
  vreun ID de imagine, vreo etichetă de imagine sau vreun volum de acum lipsește.

EOT
    answer=""
    read -r -p "Continui? [da/NU] " answer || answer=""
    if [[ "$answer" != "da" ]]; then
        warn "anulat — nimic nu s-a schimbat pe gazdă"
        exit 1
    fi
    # Cât a așteptat operatorul răspunsul, gazda a mers mai departe (un build a terminat, o imagine s-a reconstruit). Măsurătoarea «înainte» se
    # reia ACUM, ca ce s-a schimbat între timp să nu fie pus în seama lui prune.
    take_snapshot "$BEFORE" || exit "$PHASE_EXIT"
    read -r B_N B_BYTES B_U B_UB B_S B_SB B_R B_RB <<< "$(bc_stats "$BEFORE")"
    info "măsurătoare reluată după confirmare: ${B_N} intrări, ${B_R} eliberabile ($(fmt_bytes "$B_RB"))"
    if (( B_R == 0 )); then nothing_to_free; fi
fi

info "rulez \`docker builder prune -a -f\` pe gazdă (poate dura minute)"
prune_rc=0
set +e
ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "sudo -n bash -s -- prune" < "$HOST_LIB" 2>&1 | tee "$PRUNE_OUT"
prune_rc="${PIPESTATUS[0]}"
set -e
printf '\n'

if (( prune_rc == 255 )); then
    warn "ssh a căzut (cod 255) în timpul prune: rezultatul e NECUNOSCUT (daemonul poate fi terminat sau nu). Rulează din nou cu --dry-run ca să vezi starea."
    exit 255
fi
if (( prune_rc != 0 )); then
    # Refuzurile din biblioteca de pe gazdă (14 = builder curent greșit, 11/12 = docker) ajung aici înainte de orice ștergere; explicăm,
    # dar măsurăm oricum după, ca să nu afirmăm «nimic nu s-a schimbat» pe încredere.
    grep '^sudo: ' "$PRUNE_OUT" > "$ERR" || true
    PHASE_EXIT=1
    explain_rc "$prune_rc" "prune"
    # PRUNE_START e tipărit chiar înainte de `docker builder prune`: fără el, gazda a refuzat înainte să șteargă ceva.
    if ! grep -q '^PRUNE_START$' "$PRUNE_OUT"; then
        fail "prune nu a pornit; nu s-a șters nimic."
        exit "$PHASE_EXIT"
    fi
    raise_rc "$PHASE_EXIT"
fi

PHASE_EXIT=3
if ! take_snapshot "$AFTER"; then
    warn "NU pot dovedi efectul: măsurarea de după prune a eșuat (prune: cod ${prune_rc}). Rulează --dry-run ca să vezi starea."
    if [[ "$PHASE_EXIT" == 255 ]]; then exit 255; fi
    raise_rc 3
    exit "$FINAL_RC"
fi

# --- efectul pe cache ---
read -r A_N A_BYTES A_U A_UB A_S A_SB A_R A_RB <<< "$(bc_stats "$AFTER")"
report_state "$AFTER" "după"
# Intrările eliberabile de dinainte (nici în uz, nici partajate): dispărute = eliberate; rămase = fie explicate (între timp au ajuns în uz sau
# partajate cu o imagine nouă, deci docker are voie să le țină), fie NEEXPLICATE (tot eliberabile, deși prune -a ar fi trebuit să le șteargă).
read -r FREED_N FREED_B EXPL_N EXPL_B UNEX_N UNEX_B HELD_N HELD_B <<< "$(awk 'NR == FNR { if ($1 == "BCENTRY") st[$2] = ($3 == 1 ? "u" : ($5 == 1 ? "s" : "r")); next }
    $1 == "BCENTRY" && $3 == 0 && $5 == 0 {
        if (!($2 in st)) { f++; fb += $4 } else if (st[$2] == "r") { un++; unb += $4 } else { ex++; exb += $4 } }
    $1 == "BCENTRY" && ($3 == 1 || $5 == 1) && !($2 in st) { hg++; hgb += $4 }
    END { printf "%.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f", f, fb, ex, exb, un, unb, hg, hgb }' "$AFTER" "$BEFORE")"
NEW_N="$(awk 'NR == FNR { if ($1 == "BCENTRY") before[$2] = 1; next } $1 == "BCENTRY" && !($2 in before) { n++ } END { printf "%.0f", n }' "$BEFORE" "$AFTER")"

if (( FREED_N == 0 )); then
    fail "cache-ul de build NU s-a micșorat: înainte erau ${B_R} intrări eliberabile ($(fmt_bytes "$B_RB")), iar după prune nu a dispărut niciuna (prune: cod ${prune_rc}). Nu raportez succes."
    raise_rc 1
else
    ok "eliberat: ${FREED_N} intrări, $(fmt_bytes "$FREED_B") (din ${B_R} intrări eliberabile, $(fmt_bytes "$B_RB"))"
    if (( UNEX_N > 0 )); then
        fail "PARȚIAL: au rămas ${UNEX_N} intrări eliberabile ($(fmt_bytes "$UNEX_B")), nici în uz, nici partajate cu imagini, deși \`prune -a\` trebuia să le șteargă. Cache-ul NU e curățat. Rulează --dry-run, apoi din nou."
        raise_rc 1
    fi
fi
if (( EXPL_N > 0 )); then
    info "${EXPL_N} intrări eliberabile de dinainte ($(fmt_bytes "$EXPL_B")) au ajuns între timp în uz sau partajate cu o imagine; docker are voie să le țină"
fi
if (( HELD_N > 0 )); then
    info "${HELD_N} intrări care erau în uz sau partajate cu imagini ($(fmt_bytes "$HELD_B")) au dispărut între măsurători; NU le număr la «eliberat» (docker nu le socotește eliberabile)"
fi
if (( A_U > 0 )); then
    info "au rămas ${A_U} intrări în uz ($(fmt_bytes "$A_UB")): docker nu șterge intrări folosite de un build în curs"
fi
if (( A_S > 0 )); then
    info "au rămas ${A_S} intrări partajate cu imagini ($(fmt_bytes "$A_SB")): prune nu le șterge intenționat (țin straturile imaginilor) și docker nu le numără ca eliberabile"
fi
if (( NEW_N > 0 )); then
    info "${NEW_N} intrări de cache au APĂRUT între cele două măsurători (un build în paralel); nu sunt greșeli"
fi
info "cache de build: ${B_N} -> ${A_N} intrări, $(fmt_bytes "$B_BYTES") -> $(fmt_bytes "$A_BYTES")"
DF_DELTA="$(awk -v a="$(df_avail "$AFTER")" -v b="$(df_avail "$BEFORE")" 'BEGIN { printf "%.0f", a - b }')"
info "spațiu liber pe disc: $(signed_human "$DF_DELTA") B (doar context: alte procese scriu pe același disc și între măsurători)"

# --- garda de domeniu: imagini și volume ---
# Imaginile se compară separat ca ID-uri și ca etichete (depozit:etichetă, fără <none>). O reconstruire în paralel mută eticheta `app:latest`
# pe un ID nou, iar ID-ul vechi rămâne ca <none>:<none>: asta nu e o pierdere. Alarma e doar când un ID nu mai există, sau când o etichetă
# nu mai duce la nicio imagine.
for stage in BEFORE AFTER; do
    f="${!stage}"; lc="$(tr 'A-Z' 'a-z' <<< "$stage")"
    awk '$1 == "IMAGE" { print $2 }' "$f" | LC_ALL=C sort -u > "${WORK}/ids.${lc}"
    awk '$1 == "IMAGE" && $3 !~ /<none>/ { print $3 }' "$f" | LC_ALL=C sort -u > "${WORK}/refs.${lc}"
    awk '$1 == "VOLUME" { print $2 }' "$f" | LC_ALL=C sort -u > "${WORK}/vols.${lc}"
done
check_lost() {
    local set="$1" label="$2" what="$3" gone appeared n_before n_after
    gone="$(LC_ALL=C comm -23 "${WORK}/${set}.before" "${WORK}/${set}.after")"
    appeared="$(LC_ALL=C comm -13 "${WORK}/${set}.before" "${WORK}/${set}.after" | grep -c . || true)"
    n_before="$(grep -c . "${WORK}/${set}.before" || true)"
    n_after="$(grep -c . "${WORK}/${set}.after" || true)"
    if [[ -n "$gone" ]]; then
        fail "${label} DISPĂRUTE după prune ($(grep -c . <<< "$gone") din ${n_before}) — prune a ieșit din domeniul lui, sau altceva a șters în paralel:"
        head -n 20 <<< "$gone" | sed 's/^/      /' >&2
        raise_rc 4
    else
        ok "${label}: toate cele ${n_before} de dinainte există și după (acum ${n_after})"
    fi
    if (( appeared > 0 )); then info "${what} noi apărute între măsurători: ${appeared} (un build sau un deploy în paralel)"; fi
}
check_lost ids "ID-uri de imagine (și dangling)" "ID-uri de imagine"
check_lost refs "etichete de imagine (care trebuie să ducă la o imagine)" "etichete"
check_lost vols "volume" "volume"
RB_BEFORE="$(grep -c '^rollback/' "${WORK}/refs.before" || true)"
RB_AFTER="$(grep -c '^rollback/' "${WORK}/refs.after" || true)"
info "imagini rollback/*: ${RB_BEFORE} înainte, ${RB_AFTER} după"

case "$FINAL_RC" in
    0) ok "gata: efectul e dovedit (cache micșorat, nicio imagine sau volum pierdut)" ;;
    1) warn "EȘUAT sau PARȚIAL (cod 1) — citește ce e marcat [x] mai sus" ;;
    3) warn "NECUNOSCUT (cod 3) — ceva n-a putut fi măsurat; asta NU e «bine»" ;;
    4) warn "O IMAGINE, O ETICHETĂ SAU UN VOLUM A DISPĂRUT (cod 4) — citește lista de mai sus înainte de orice altceva" ;;
esac
exit "$FINAL_RC"
