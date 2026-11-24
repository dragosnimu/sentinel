#!/usr/bin/env bash
#
# Faza `containers` a lui scripts/lib/system-update-host.sh. Încărcat cu `source`;
# folosește funcțiile `say_*`, variabilele OPT_* și BASE ale fișierului principal.
#
# Ce face, per proiect compose (descoperit din etichetele containerelor care RULAU la
# baseline — nu dintr-o listă scrisă de mână):
#
#   * serviciu cu `build:`  -> opt-in pe proiect (`--rebuild`): `build --pull`, doar dacă
#     codul de pe disc e cel care rulează (vezi su_drift_verdict) ori operatorul a acceptat
#     explicit diferența (`--accept-drift`);
#   * serviciu fără `build:` -> `pull` pe ACEEAȘI etichetă; recreat doar dacă imaginea s-a
#     schimbat. Nicio etichetă nu se schimbă, nicio versiune majoră nu se ia singură.
#
# Recrearea e `up -d --no-deps --no-build <serviciile schimbate>`, NICIODATĂ `up -d` pe
# tot proiectul: acela ar recrea orice serviciu al cărui container rulează alt ID decât
# are acum eticheta (snipeit-app-1: rulează imaginea din august, eticheta arată una din
# octombrie), adică ar sări peste versiuni cu migrări la pornire.
#
# La o REÎNCERCARE a unui eșec preluat (sau recreare peste imaginea unui eșec recunoscut), ținta rollback-ului urmează ce a rulat ÎNAINTE de schimbarea de acum, citit din
# container: dacă imaginea care rulează e una dintre cele pe care eșecul le-a pus (`landed`, în episod), ținta e `prev` din episod; altfel cineva a schimbat-o între timp
# și ținta e imaginea de acum (vezi ensure_rollback_tag).
#
# Ce se dovedește după fiecare recreare (check_container), nu ce se presupune:
#   containerul rulează ID-ul de imagine AȘTEPTAT, a fost creat DUPĂ începutul rulării,
#   ajunge la o sănătate nu mai rea decât baseline-ul într-un timp mărginit, și rămâne
#   așa două eșantioane la STABLE_S distanță (aceleași reporniri, același moment de pornire).
#
# Nu face rollback automat. Înainte de orice schimbare, imaginea veche primește eticheta
# `rollback/maint-<baseline>/<proiect>-<serviciu>:prev`, iar la un eșantion rău se tipărește
# comanda exactă. Un rollback automat ar fi un al doilea drum de cod, mai puțin probat decât
# cel pe care îl repară.
#
# Ținta etichetei de rollback = imaginea pe care containerul O RULA în clipa în care scriptul era pe cale
# să-l schimbe, citită din container și scrisă ca fapt explicit (`prev`, în containers.owned) ÎNAINTE de
# `tag` și `up`; apoi nu se mai rescrie (prima scriere câștigă: o reîncercare după un eșec nu are voie să pună
# imaginea picată sub eticheta de rollback). NU e «imaginea din baseline» decât prin faptul că cele două
# coincid: un serviciu care rulează altceva decât baseline-ul ȘI decât ce a pus scriptul însuși (un redeploy
# de după baseline: oferte api/worker, dms app, 20 nov 2026) e ținut la clasificare — înainte de pull, tag sau
# up — ca `stale-baseline`: o etichetă pe imaginea din baseline ar anula acel deploy, iar una pe imaginea
# străină ar fi un rollback spre ceva ce nimeni nu a verificat. Proprietatea NU se deduce din liniile
# `pulled`/`built` (un pull care n-a găsit nimic scria ID-ul străin și îl făcea «al nostru»): `su_image_is_ours`
# citește doar faptele `landed` (imagini văzute RULÂND după un `up` făcut de noi), vezi system-update-lib.sh.

# Jurnalul fazei. Stările lui lipicioase și succesele care le rezolvă (failed/retried, pull-failed/pulled,
# build-failed/built, tag-failed/tagged, unread/read-ok) sunt definite într-un singur loc, SU_STICKY_SPEC din
# system-update-lib.sh, iar `su_report_final` e SINGURA funcție care reduce jurnalul la o stare. Aici nu se
# decide nimic: se scrie ce s-a întâmplat. Un dry-run nu scrie nimic.
# load_carried_episodes PROIECT — stările lipicioase NEREZOLVATE ale proiectului care sunt eșecuri preluate, în CARRIED_EP (cheie `proiect/serviciu|stare`), înainte de
# orice scriere din proiect: și un `unread` care pică din nou, înainte de clasificare, își păstrează episodul.
load_carried_episodes() {
    local key st det ep
    while IFS='|' read -r key st det; do
        [[ "${key%%/*}" == "$1" ]] || continue
        ep="$(su_episode_of "$det")"
        if [[ -n "$ep" ]]; then CARRIED_EP["${key}|${st}"]="$ep"; fi
    done < <(su_report_final "${BASE}/containers.report" all)
}

# Un eșec NOU al aceleiași stări lipicioase care e deja un eșec PRELUAT (o reîncercare care pică din nou) rămâne în episodul preluat: linia lui poartă același
# prefix `[episod=ID] ` (CARRIED_EP, completat de classify_services), altfel s-ar rescrie ca un eșec de «acum» și următorul baseline ar judeca serviciul după
# sănătatea măsurată cât era deja stricat — exact ce episodul există ca să împiedice.
declare -A CARRIED_EP=()
report_line() {
    (( OPT_DRY_RUN )) && return 0
    local det="$4" ep=""
    if [[ "$3" != stale-baseline ]] && su_is_sticky "$3"; then ep="${CARRIED_EP["$1/$2|$3"]:-}"; fi
    [[ -z "$ep" ]] || det="[episod=${ep}] ${det}"
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$det" >> "${BASE}/containers.report"
}

# owned_record PROIECT SERVICIU TIP ID — un fapt de proprietate (prev|landed), într-un fișier separat de jurnal. Un dry-run nu scrie nimic.
owned_record() {
    (( OPT_DRY_RUN )) && return 0
    printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "${BASE}/containers.owned"
}

# Serviciile care rulau la baseline în PROIECT (din containers.tsv, nu din compose: compose-ul poate fi chiar ce nu se citește).
project_services() { awk -F'|' -v p="$1" '$2 == p && $7 == "running" { print $3 }' "${BASE}/containers.tsv" | LC_ALL=C sort -u; }

# fail_project PROIECT STARE DETALIU — un eșec care oprește proiectul ÎNAINTE de clasificare: fiecare serviciu al lui
# rămâne roșu în jurnal, ca o rulare ulterioară (--only alt proiect, ori fără --only) să nu iasă verde peste el.
fail_project() {
    local svc
    while IFS= read -r svc; do
        [[ -n "$svc" ]] && report_line "$1" "$svc" "$2" "$3"
    done < <(project_services "$1")
    return 0
}

# fail_services PROIECT STARE DETALIU SERVICIU... — același lucru, pentru serviciile unui proiect citit, iar `unresolved`
# (scop dinamic, din execute_project) opărește re-verificarea lor în rularea asta.
fail_services() {
    local project="$1" state="$2" detail="$3" svc
    shift 3
    for svc in "$@"; do unresolved[$svc]="$state"; report_line "$project" "$svc" "$state" "$detail"; done
}

# Numele imaginii pentru comanda de rollback: cea din configurație (pull), cea cu care compose a creat containerul,
# apoi numele implicit compose <proiect>-<serviciu>. Niciodată gol: un serviciu cu `build:` și fără `image:` n-are
# `image:` în config, iar comanda tipărită ar fi `docker tag <eticheta> ` fără țintă.
service_image_ref() { printf '%s' "${cfg_image[$2]:-${svc_image[$2]:-${1}-${2}}}"; }

# JSON-ul lui `docker compose config` -> serviciu<US>imagine<US>context-build (US = 0x1f).
# NU TAB: tab e spațiu alb pentru IFS, deci `read` prăbușește câmpul gol dintre două taburi — la un
# serviciu cu `build:` și fără `image:` (8 pe gazdă) contextul ajungea în câmpul imaginii, iar
# `--rebuild` nu făcea nimic și ieșea cu «totul dovedit».
compose_services_tsv() {
    "${SU_PYTHON:-python3}" -c '
import json, sys
for name, s in json.load(sys.stdin).get("services", {}).items():
    b = s.get("build")
    ctx = ""
    if b:
        ctx = b if isinstance(b, str) else (b.get("context") or ".")
    print(chr(31).join([name, s.get("image") or "", ctx]))
' | tr -d '\r'   # un python nativ Windows scrie CRLF; un CR ramas in ultimul camp ar face dintr-un serviciu fara build unul cu context
}

# Fapte despre contextul de build, față de imaginea care RULEAZĂ: câte fișiere sunt mai
# noi decât ea, câte intrări are `git status`, dacă ultimul commit e mai nou. «N|D|H».
# Se măsoară față de ID-ul imaginii care rulează, nu față de etichetă: eticheta poate
# arăta deja o imagine construită ulterior, iar atunci data ei n-ar mai însemna nimic.
ctx_drift_facts() {
    local ctx="$1" image_id="$2" created epoch newer dirty head gitout ct rc
    created="$(docker image inspect -f '{{.Created}}' "$image_id" || true)"
    if epoch="$(su_epoch "$created")"; then
        rc=0
        newer="$(find "$ctx" \( -name .git -o -name node_modules -o -name __pycache__ -o -name .venv -o -name .next \) -prune -o -type f -newermt "@${epoch}" -print | wc -l)" || rc=$?
        (( rc == 0 )) || newer="?"
        newer="${newer//[[:space:]]/}"
    else
        epoch=""; newer="?"
    fi
    if gitout="$(git -c safe.directory='*' -C "$ctx" rev-parse --is-inside-work-tree 2>&1)"; then
        dirty="$(git --no-optional-locks -c safe.directory='*' -C "$ctx" status --porcelain -- . | wc -l)" || dirty="?"
        dirty="${dirty//[[:space:]]/}"
        ct="$(git -c safe.directory='*' -C "$ctx" log -1 --format=%ct -- . || true)"
        if [[ -z "$ct" ]]; then head="no"
        elif [[ -z "$epoch" ]]; then head="?"
        elif (( ct > epoch )); then head="yes"
        else head="no"
        fi
    elif [[ "$gitout" == *"not a git repository"* ]]; then
        dirty="norepo"; head="norepo"
    else
        dirty="?"; head="?"
    fi
    printf '%s|%s|%s\n' "$newer" "$dirty" "$head"
}

ctx_changed_files() {
    local ctx="$1" image_id="$2" created epoch
    created="$(docker image inspect -f '{{.Created}}' "$image_id" || true)"
    epoch="$(su_epoch "$created")" || return 0
    find "$ctx" \( -name .git -o -name node_modules -o -name __pycache__ -o -name .venv -o -name .next \) -prune -o -type f -newermt "@${epoch}" -print | head -n 5 || true
}

# ctr_sample NUME -> stare|sănătate|reporniri|pornit-la|id-imagine|creat
ctr_sample() {
    local out
    if out="$(docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.Image}}|{{.Created}}' "$1")"; then
        printf '%s' "$out"
    else
        printf 'missing|none|0|-|-|-'
    fi
}

# wait_settled NUME TIMEOUT — așteaptă (mărginit) ieșirea din `starting`/oprit.
# 0 = a ieșit din tranziție (verdictul îl dă ctr_sample), 1 = timeout.
wait_settled() {
    local name="$1" timeout="$2" deadline s cls h
    deadline=$(( $(now_epoch) + timeout ))
    while :; do
        s="$(ctr_sample "$name")"
        h="$(cut -d'|' -f2 <<< "$s")"
        cls="$(su_health_class "${s%%|*}" "$h")"
        case "$cls" in starting|down) ;; *) return 0 ;; esac
        (( $(now_epoch) < deadline )) || return 1
        sleep "$POLL_S"
    done
}

# check_container NUME ID_AȘTEPTAT SĂNĂTATE_BASELINE ÎNCEPUT [VERIFICĂ_CREAREA=1] [SĂNĂTĂȚI_DIN_EPISOD] [SĂNĂTĂȚI_DIN_RECUNOAȘTERI] [CHEIE] — 0 = dovedit bun, 1 = rău.
# SĂNĂTĂȚI_DIN_EPISOD (șir cu spații; gol = serviciul n-are un eșec preluat): sănătățile din baseline-urile în care s-au produs eșecurile preluate. Un
# eșec preluat e rezolvat doar dacă ȘI su_container_verdict(sănătatea din episod, starea de acum) e `ok` sau `same-bad` (su_episode_resolves: același standard
# ca baseline-ul original — un serviciu care era unhealthy ÎNAINTE de eșec și e la fel acum e în starea dinainte; `worse` NU rezolvă) — aceeași funcție, nu un
# al doilea clasament; `-` (episod fără sănătate înregistrată) nu se poate judeca și nu rezolvă nimic.
# SĂNĂTĂȚI_DIN_RECUNOAȘTERI: la fel, pentru episoadele unei recunoașteri a operatorului (--acknowledge). NU pot pica verificarea (operatorul a acceptat starea),
# ci doar setează ACK_RESOLVED=1 când ambele verdicte (față de episod și față de baseline) rezolvă după ACEEAȘI regulă ca un eșec preluat: `ok` sau `same-bad`
# (su_ack_clears), ca apelantul să scrie `ack-cleared`; ACK_SAME_BAD=1 dacă unul dintre ele a fost `same-bad` (serviciul e încă unhealthy, la fel ca înainte de eșec: apelantul o spune, nu spune «sănătos»).
# STARE_RECUNOSCUTĂ: sănătatea pe care o avea containerul când operatorul a dat `--acknowledge` în ACEST baseline (fapt `ackstate`, ack_state_for; gol = necunoscută). Un
# serviciu recunoscut în baseline-ul în care a picat e încă «mai rău decât baseline-ul» la următoarea rulare, dar nu mai rău decât ce s-a recunoscut: verificarea nu redeschide
# eșecul (`failed`) cât timp verdictul față de starea recunoscută e `ok`/`same-bad`; mai rău decât ea (de pildă oprit) e roșu din nou. Recunoașterea rămâne (nu e `ok` față de baseline).
# CHEIE = proiect/serviciu, pentru ieșirea numită în mesaje.
# VERIFICĂ_CREAREA=0 la o RE-verificare a unei stări deja existente (un serviciu atins de o rulare
# anterioară): sănătatea și stabilitatea se cer la fel, dar «creat după începutul acestei rulări» nu are
# sens pentru un container pe care această rulare nu l-a recreat.
ACK_RESOLVED=0
ACK_SAME_BAD=0      # 1 = cel puțin unul dintre verdictele care au șters recunoașterea a fost `same-bad` (serviciul e încă unhealthy, la fel ca înainte de eșec), nu `ok`
check_container() {
    local name="$1" want_id="$2" base_health="$3" start_epoch="$4" check_created="${5:-1}" ep_healths="${6:-}" ack_healths="${7:-}" key="${8:-PROIECT/SERVICIU}" ack_state="${9:-}"
    local s1 s2 state health restarts started image created verdict flap created_epoch eh ev ah av acked_state_ok=0
    ACK_RESOLVED=0; ACK_SAME_BAD=0
    if ! wait_settled "$name" "$HEALTH_TIMEOUT_S"; then
        say_bad "${name}: încă 'starting' sau oprit după ${HEALTH_TIMEOUT_S}s"; return 1
    fi
    s1="$(ctr_sample "$name")"
    IFS='|' read -r state health restarts started image created <<< "$s1"
    if [[ "$image" != "$want_id" ]]; then
        say_bad "${name}: rulează imaginea ${image:7:12}, nu cea așteptată ${want_id:7:12} — recrearea NU a avut loc"; return 1
    fi
    created_epoch="$(su_epoch "$created")" || created_epoch=""
    if [[ "$check_created" == 1 ]] && { [[ -z "$created_epoch" ]] || (( created_epoch < start_epoch - 5 )); }; then
        say_bad "${name}: containerul e mai vechi decât această rulare (creat ${created}) — nu a fost recreat acum"; return 1
    fi
    verdict="$(su_container_verdict running "$base_health" "$state" "$health")"
    case "$verdict" in
        ok|same-bad) ;;
        *)
            if [[ -n "$ack_state" ]] && su_episode_resolves "$(su_container_verdict running "$ack_state" "$state" "$health")"; then
                acked_state_ok=1
                say_warn "${name}: ${state}/${health} e mai rău decât baseline-ul (${base_health}), dar nu mai rău decât starea pe care a recunoscut-o operatorul (${ack_state}) — nu redeschid eșecul recunoscut"
            else
                say_bad "${name}: după recreare e ${state}/${health} (baseline ${base_health}) — verdict ${verdict}"; return 1
            fi ;;
    esac
    for eh in $ep_healths; do
        if [[ "$eh" == "-" ]]; then
            say_bad "${name}: eșec preluat fără sănătatea de dinainte de eșec înregistrată (containers.episode) — nu pot dovedi că e rezolvat; dacă serviciul nu mai are ce verifica: --phase containers --acknowledge ${key}"; return 1
        fi
        ev="$(su_container_verdict running "$eh" "$state" "$health")"
        if ! su_episode_resolves "$ev"; then
            say_bad "${name}: eșec preluat — acum ${state}/${health}, față de sănătatea de dinainte de eșec (${eh}) verdictul e ${ev}, nici ok, nici same-bad; rămâne nerezolvat. Ieșirea dacă nu se mai poate rezolva: --phase containers --acknowledge ${key}"; return 1
        fi
        if [[ "$ev" == same-bad ]]; then
            say_info "${name}: eșec preluat — față de sănătatea de dinainte de eșec (${eh}) verdictul e same-bad: era la fel de rău ÎNAINTE de orice mentenanță, deci e înapoi în starea dinainte (același standard ca baseline-ul original)"
        fi
    done
    sleep "$STABLE_S"
    s2="$(ctr_sample "$name")"
    flap="$(su_flap_verdict "${s1%%|*}|$(cut -d'|' -f3,4 <<< "$s1")" "${s2%%|*}|$(cut -d'|' -f3,4 <<< "$s2")" running)"
    if [[ "$flap" != stable ]]; then
        say_bad "${name}: ${flap} — reporniri sau moment de pornire schimbate în ${STABLE_S}s (${s1} -> ${s2})"; return 1
    fi
    if (( acked_state_ok )); then
        say_warn "${name}: stabil, în starea recunoscută de operator (${state}/${health})"
    elif [[ "$verdict" == same-bad ]]; then
        say_warn "${name}: stabil, dar unhealthy — ca la baseline"
    else
        say_ok "${name}: imaginea ${image:7:12}, ${health}, stabil ${STABLE_S}s"
    fi
    # Recunoașterea operatorului se judecă ACUM, cu starea stabilă, după regula rezolvării (su_ack_clears: ambele verdicte `ok` sau `same-bad`; ack_clear_if_resolved), orice altceva o lasă în picioare.
    if [[ -n "$ack_healths" ]]; then
        ACK_RESOLVED=1
        for ah in $ack_healths; do
            if [[ "$ah" == "-" ]]; then ACK_RESOLVED=0; continue; fi
            av="$(su_container_verdict running "$ah" "$state" "$health")"
            su_ack_clears "$av" "$verdict" || ACK_RESOLVED=0
            if [[ "$av" == same-bad || "$verdict" == same-bad ]]; then ACK_SAME_BAD=1; fi
        done
        if (( ACK_RESOLVED )); then say_info "${name}: recunoașterea operatorului: verdict ok sau same-bad față de episod și față de baseline (regula rezolvării) — se șterge"
        else say_warn "${name}: recunoașterea operatorului RĂMÂNE: se șterge doar cu verdict ok sau same-bad față de sănătatea din episod ȘI față de baseline (acum ${state}/${health}; baseline ${base_health}; episod ${ack_healths})"; fi
    fi
}

# ack_state_for PROIECT SERVICIU NUME — sănătatea containerului în clipa `--acknowledge` din baseline-ul ăsta (ULTIMUL fapt `ackstate` din containers.owned), doar dacă
# serviciul are o recunoaștere în picioare (ack_eps, scop dinamic). Gol = necunoscută: verificarea se poartă ca înainte (față de baseline), nu ghicește. Ultimul fapt
# câștigă, iar `-` (starea din clipa recunoașterii nu se putea reprezenta: oprit, în pornire, necitit) îl ACOPERĂ pe unul mai vechi: fără el, o recunoaștere dată cu
# containerul oprit ar fi judecat serviciul după starea unei recunoașteri ANTERIOARE, deja ștearsă.
ack_state_for() {
    [[ -n "${ack_eps[$2]:-}" && -s "${BASE}/containers.owned" ]] || return 0
    awk -F'|' -v p="$1" -v s="$2" -v n="$3" '$1 == p && $2 == s && $3 == "ackstate" && $4 == n { v = $5 } END { if (v != "" && v != "-") print v }' "${BASE}/containers.owned"
}

# ack_state_record PROIECT SERVICIU NUME — la `--acknowledge` (ack_service: în clipa în care cheia e acceptată, nu la clasificarea proiectului), scrie sănătatea containerului de
# ACUM: `running` cu healthy|unhealthy|none ca atare; orice altceva — oprit, starting, necunoscut — se scrie ca `-` (nu se poate reprezenta ca o stare «recunoscută», iar
# `-` lasă verificarea să judece față de baseline și acoperă o stare recunoscută mai veche; vezi ack_state_for).
ack_state_record() {
    local sample state health cls
    sample="$(ctr_sample "$3")"
    IFS='|' read -r state health _ <<< "$sample"
    cls="$(su_health_class "$state" "$health")"
    case "$cls" in healthy|unhealthy|none) owned_record "$1" "$2" ackstate "${3}|${cls}" ;; *) owned_record "$1" "$2" ackstate "${3}|-" ;; esac
}

# Eticheta de rollback a ACESTEI baseline-uri. Actualizarea săptămânală (container-update.sh) folosește
# `rollback/<proiect>-<serviciu>:prev`; aici spațiul e separat, ca niciuna s-o suprascrie pe cealaltă.
rollback_tag() {
    local b="${BASE##*/}"
    printf 'rollback/maint-%s/%s-%s:prev' "${b,,}" "${1,,}" "${2,,}"
}

rollback_hint() {
    local tag id
    tag="$(rollback_tag "$1" "$2")"
    # Comanda se tipărește doar dacă eticheta EXISTĂ acum (citită din docker): un indiciu spre o etichetă care n-a fost pusă ar lăsa operatorul cu o
    # comandă care dă peste nimic, sau — mai rău — peste o altă imagine decât cea de dinainte de schimbare.
    if id="$(docker image inspect -f '{{.Id}}' "$tag" 2> /dev/null)" && [[ -n "$id" ]]; then
        say_info "  rollback: docker tag ${tag} ${3} && docker compose -p ${1} <fișierele proiectului> up -d --no-deps --no-build --force-recreate ${2}   (eticheta arată ${id:7:12})"
    else
        say_info "  rollback: NU există eticheta ${tag} — nicio țintă de rollback dovedită pentru ${1}/${2}; nu tipăresc o comandă care ar da peste nimic și nu aleg o țintă"
    fi
}

print_skips() {
    local item
    (( ${#SKIP_LIST[@]} )) || return 0
    say_sect "Sărite — nu s-a atins nimic din ele"
    for item in "${SKIP_LIST[@]}"; do printf '  - %s\n' "$item"; done
}

# ack_states CHEIE — stările lipicioase nerezolvate ale serviciului (`proiect/serviciu`), una pe linie, ca `stare|detaliu` (toate, nu doar prima afișată).
ack_states() {
    su_report_final "${BASE}/containers.report" all | awk -F'|' -v k="$1" '$1 == k { d = $3; for (i = 4; i <= NF; i++) d = d "|" $i; print $2 "|" d }'
}

# unresolved_ack_hint PROIECT — ieșirea `--acknowledge` cu cheile REALE ale serviciilor proiectului care au o stare lipicioasă nerezolvată în jurnal (nu un substituent).
unresolved_ack_hint() {
    local key st det keys=""
    while IFS='|' read -r key st det; do
        [[ "${key%%/*}" == "$1" && "$st" != stale-baseline ]] && su_is_sticky "$st" && keys+="${keys:+,}${key}"
    done < <(su_report_final "${BASE}/containers.report" all)
    if [[ -n "$keys" ]]; then printf -- '--phase containers --acknowledge %s' "$keys"; else printf 'proiectul n-are nicio stare lipicioasă nerezolvată în jurnal (nimic de recunoscut)'; fi
}

# ack_service CHEIE — recunoașterea EXPLICITĂ a operatorului (`--acknowledge`): scrie `acked` (șterge stările lipicioase ale serviciului, în afară de `stale-baseline`,
# vezi su_report_final) și pune un STEAG durabil legat de episod: câte o linie `acked` cu prefixul `[episod=ID] ` pentru fiecare episod al stărilor recunoscute (cel preluat,
# ori baseline-ul de acum pentru un eșec produs în el). Steagul rămâne până la un verdict ok sau same-bad (ack_clear_if_resolved) — nu-l șterge niciun skip/hold/recreated/unread/eșec nou.
# Nu e niciodată apelată fără ca operatorul să fi numit cheia; un dry-run o descrie și nu scrie nimic.
ack_service() {
    local key="$1" line st rawdet det list="" stale="" ep eps=" " cur="${BASE##*/}" q
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        st="${line%%|*}"; rawdet="${line#*|}"; det="$(su_episode_strip "$rawdet")"
        if [[ "$st" == stale-baseline ]]; then stale=" ${st} (${det}) RĂMÂNE: se rezolvă printr-un baseline nou sau readucerea containerului, nu printr-o recunoaștere."; continue; fi
        list+="${list:+; }${st} (${det})"
        ep="$(su_episode_of "$rawdet")"; [[ -n "$ep" ]] || ep="$cur"
        [[ "$eps" == *" ${ep} "* ]] || eps+="${ep} "
    done < <(ack_states "$key")
    if (( OPT_DRY_RUN )); then
        say_warn "(dry-run: nu scriu nimic) ${key}: ar fi recunoscut de operator, cu stările nerezolvate: ${list}.${stale}"
        return 0
    fi
    for ep in $eps; do
        report_line "${key%%/*}" "${key#*/}" acked "[episod=${ep}] recunoscut explicit de operator (--acknowledge ${key}); erau nerezolvate: ${list}"
    done
    # Starea recunoscută se scrie AICI, în clipa recunoașterii, pentru fiecare container al serviciului care rula la baseline (singurele pe care le verifică check_container; un
    # container care nu rula atunci nu se verifică, deci nu are ce recunoaște): nu depinde de ordinea proiectelor, de
    # `--only` și nici de un proiect anterior care oprește rularea înainte să ajungă la acesta (altfel o rulare simplă de mai târziu ar redeschide `failed` peste
    # starea chiar recunoscută).
    while IFS= read -r q; do
        [[ -n "$q" ]] && ack_state_record "${key%%/*}" "${key#*/}" "$q"
    done < <(awk -F'|' -v p="${key%%/*}" -v s="${key#*/}" '$2 == p && $3 == s && $7 == "running" { print $1 }' "${BASE}/containers.tsv")
    say_warn "${key}: RECUNOSCUT de operator (--acknowledge) fără să fie rezolvat — erau: ${list}.${stale} Decizia rămâne scrisă în containers.report (acked, pe episodul ${eps# }), apare la fiecare rulare, în verify și în status, iar rezultatul final spune «DOVEDIT, cu servicii recunoscute», nu «TOTUL DOVEDIT»; se șterge doar când serviciul e verificat cu verdict ok sau same-bad (nu mai rău decât înainte de eșec) față de sănătatea de dinainte de eșec ȘI față de baseline (o rulare care îl re-verifică), nu de un skip, un hold, o recreare sau un eșec trecător"
}

phase_containers() {
    need_root; require_baseline
    say_sect "Containere$( ((OPT_DRY_RUN)) && printf ' (dry-run: nu se schimbă nimic)')"
    if [[ "$(base_state "${BASE}/containers.tsv")" != measured ]]; then
        die "baseline-ul nu are lista containerelor (containers.tsv.unknown) — nu știu ce rulează; rulează din nou preflight"
    fi
    local -a projects=()
    mapfile -t projects < <(awk -F'|' '$2 != "" && $7 == "running" { print $2 }' "${BASE}/containers.tsv" | LC_ALL=C sort -u)

    # `--only` care nu potrivește NICIUN proiect nu e «nimic de făcut»: e o greșeală de scriere. Un
    # nume necunoscut oprește totul, înainte de blocări, de backup și de orice atingere a gazdei.
    # La fel pentru `--rebuild` și `--accept-drift`: un nume scris greșit ar fi fost ignorat (nimic nu s-ar fi reconstruit,
    # sau codul diferit n-ar fi fost acceptat) iar faza ar fi ieșit verde peste o cerere a operatorului neîndeplinită.
    # `--rebuild all` e cuvântul-cheie, nu un nume de proiect.
    local o q found flagname flaglist
    for flagname in --only --retry-failed --rebuild --accept-drift; do
        case "$flagname" in
            --only) flaglist="$OPT_ONLY" ;;
            --retry-failed) flaglist="$OPT_RETRY_FAILED" ;;
            --rebuild) flaglist="$OPT_REBUILD" ;;
            --accept-drift) flaglist="$OPT_ACCEPT_DRIFT" ;;
        esac
        [[ -n "$flaglist" ]] || continue
        [[ "$flagname" == --rebuild && "$flaglist" == all ]] && continue
        while IFS= read -r o; do
            [[ -n "$o" ]] || continue
            found=0
            for q in ${projects[@]+"${projects[@]}"}; do [[ "$q" == "$o" ]] && found=1; done
            if (( ! found )); then
                say_bad "${flagname} ${o}: niciun proiect compose cu numele ăsta în baseline (proiecte: ${projects[*]:-niciunul})$([[ "$flagname" == --retry-failed ]] && printf '. Dacă proiectul nu mai are niciun container la baseline-ul acesta (scos din compose), un baseline nou (--phase preflight --new-baseline) îi închide episoadele nerezolvate; dacă serviciile lui doar s-au oprit, un baseline nou NU le închide (pornește-le și ia baseline nou, sau recunoaște-le); în jurnalul de acum: %s' "$(unresolved_ack_hint "$o")")"
            fi
        done < <(tr ',' '\n' <<< "$flaglist")
        (( FAIL_N == 0 )) || finish
    done

    # `--acknowledge P/S`: fiecare cheie trebuie să aibă ceva nerezolvat în jurnal (în afară de `stale-baseline`, care se rezolvă prin baseline nou
    # și ar reapărea la clasificarea din aceeași rulare): o cheie scrisă greșit nu are voie să treacă drept «recunoscut» în tăcere.
    local -a ack_keys=()
    if [[ -n "$OPT_ACKNOWLEDGE" ]]; then
        local ak line st real
        while IFS= read -r ak; do
            [[ -n "$ak" ]] || continue
            real=0
            while IFS= read -r line; do
                st="${line%%|*}"
                if [[ -n "$st" && "$st" != stale-baseline ]] && su_is_sticky "$st"; then real=1; fi
            done < <(ack_states "$ak")
            if (( real )); then ack_keys+=("$ak")
            else say_bad "--acknowledge ${ak}: serviciul n-are nicio stare lipicioasă nerezolvată în jurnal (stale-baseline nu se recunoaște: se rezolvă printr-un baseline nou) — cheie scrisă greșit? nu s-a scris nimic"
            fi
        done < <(tr ',' '\n' <<< "$OPT_ACKNOWLEDGE")
        (( FAIL_N == 0 )) || finish
    fi

    local lock_cu lock_bk p selected=0 partial=0
    for p in ${projects[@]+"${projects[@]}"}; do
        if [[ -z "$OPT_ONLY" ]] || su_list_has "$OPT_ONLY" "$p" 0; then selected=$((selected + 1)); fi
    done
    (( selected < ${#projects[@]} )) && partial=1
    if (( ! OPT_DRY_RUN )); then
        require_backup_gate
        take_lock lock_cu "${SU_RUN_DIR}/container-update.lock" "actualizarea săptămânală a containerelor"
        take_lock lock_bk "${SU_RUN_DIR}/srv-backup.lock" "backup-ul zilnic"
        # O rulare PARȚIALĂ (--only peste o parte din proiecte) nu are voie să distrugă un containers.ok dovedit de o rulare care le-a
        # acoperit pe toate: ea își ține propria pereche de markere (containers.only.started / .ok), iar verify cere ca ultima să fie
        # încheiată. Una completă începe de la zero: `.started` șterge `.ok`, iar markerele parțiale dispar (le acoperă pe toate).
        if (( partial )); then
            mark_phase containers.only.started
        else
            rm -f "${BASE}/phases/containers.only.started" "${BASE}/phases/containers.only.ok"
            mark_phase containers.started
        fi
        touch "${BASE}/containers.report"   # cumulativ: o rulare repetată nu șterge ce au făcut cele dinainte
    fi
    for ak in ${ack_keys[@]+"${ack_keys[@]}"}; do ack_service "$ak"; done
    (( ${#projects[@]} )) || say_unk "baseline-ul n-are niciun container compose care rulează — nu e nimic de actualizat (sau n-a fost măsurat bine)"
    local processed=0
    for p in ${projects[@]+"${projects[@]}"}; do
        if [[ -n "$OPT_ONLY" ]] && ! su_list_has "$OPT_ONLY" "$p" 0; then continue; fi
        processed=$((processed + 1))
        if ! process_project "$p"; then
            (( OPT_KEEP_GOING )) || { say_warn "mă opresc după primul proiect eșuat (${p}); proiectele următoare rămân neatinse. --keep-going ca să continui"; break; }
        fi
    done
    print_skips
    # Rezultatul fazei e o VERDICT despre starea de acum a fiecărui serviciu atins sub acest baseline, nu jurnalul
    # acțiunilor: un eșec lipicios (su_is_sticky) rămas dintr-o rulare anterioară — inclusiv într-un proiect neatins
    # de rularea asta — blochează `containers.ok` până când succesul lui specific, verificat, îl rezolvă. Și un
    # dry-run îl spune: «TOTUL DOVEDIT» peste un eșec nerezolvat ar fi o afirmație pe care nimeni n-a verificat-o.
    local key st det
    # Recunoașterile operatorului se arată MEREU (și când un alt serviciu e roșu, și când proiectul a fost procesat în rularea asta): `acked` e
    # rezultatul final al serviciului până la o reușită verificată sau un eșec nou (su_report_final), iar ce e recunoscut nu e rezolvat.
    while IFS='|' read -r key st det; do
        say_warn "${key}: recunoscut de operator, NERESOLVAT în fapt — ${det}"; ACK_N=$((ACK_N + 1))
    done < <(su_report_final "${BASE}/containers.report" acked)
    if (( FAIL_N == 0 )); then
        while IFS='|' read -r key st det; do
            su_is_sticky "$st" || continue
            say_bad "rezultat NEREZOLVAT$( ((OPT_DRY_RUN)) && printf ' (dry-run: nu s-a schimbat nimic, dar nici nu pot declara dovedit)') dintr-o rulare anterioară: ${key} (${st}) — $(su_episode_strip "$det"). $(su_sticky_hint "$st" "${key%%/*}" "${key#*/}")"
        done < <(su_report_final "${BASE}/containers.report")
    fi
    # containers.ok = «toate proiectele au fost procesate acum și nimic nu e nerezolvat». O rulare cu `--only X` care a
    # procesat un singur proiect din mai multe nu spune nimic despre celelalte: nu scrie markerul (care ar ajunge «dovedit»
    # în verify). Rularea care îl scrie e una fără --only (sau cu --only peste toate proiectele).
    if (( ! OPT_DRY_RUN && processed > 0 && processed == ${#projects[@]} && FAIL_N == 0 && UNK_N == 0 )); then
        mark_phase containers.ok
    elif (( ! OPT_DRY_RUN && FAIL_N == 0 && UNK_N == 0 && processed < ${#projects[@]} )); then
        mark_phase containers.only.ok
        say_info "containers.ok NU s-a scris: rularea a procesat ${processed} din ${#projects[@]} proiecte (--only ${OPT_ONLY}); o rulare fără --only le acoperă pe toate. Un containers.ok dintr-o rulare completă anterioară rămâne neatins"
    fi
    finish
}

# Etichetele compose ale unui proiect, din containerul LUI: «director|fișier1,fișier2»,
# ca în container-update.sh (nu din nume ghicite).
project_compose_labels() {
    local ref
    ref="$(awk -F'|' -v p="$1" '$2 == p && $7 == "running" { print $1; exit }' "${BASE}/containers.tsv")"
    docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$ref"
}

# Variabile locale ale lui process_project, văzute de funcțiile de mai jos (scop dinamic):
#   DC (comanda compose), svc_image, svc_ctx, svc_names, old_id, want_id, base_health,
#   cfg_image, act, build_svcs, pull_svcs, base_id (imaginea din baseline = cea de dinainte de mentenanță),
#   prior_st (rezultatul final al serviciului la începutul rulării), refuse (1 = un serviciu cu baseline vechi: proiectul nu se atinge),
#   ep_health (sănătățile din episoadele eșecurilor preluate, `-` = neînregistrată), ep_prev (`prev` din episodul unui `failed` preluat),
#   ep_failed (1 = serviciul are un `failed` preluat), ep_ids (ID-urile episoadelor preluate, separate prin spațiu), ep_landed (imaginile `landed` din episoadele
#   unui `failed` preluat sau ale unei recunoașteri), ack_eps / ack_health (episoadele recunoașterii în picioare a serviciului și sănătățile lor; gol = nicio recunoaștere)
process_project() {
    local project="$1" labels workdir files f cfg_json tsv errf svc image ctx refuse=0
    local -a DC=() cfgs=() build_svcs=() pull_svcs=() check_svcs=()
    local -A svc_image=() svc_ctx=() svc_names=() old_id=() want_id=() base_health=() cfg_image=() act=() base_id=() prior_st=()
    local -A ep_health=() ep_prev=() ep_failed=() ep_ids=() ep_landed=() ack_eps=() ack_health=()    # episodul eșecurilor PRELUATE ale serviciului și al recunoașterilor lui (vezi classify_services)
    say_sect "Proiect ${project}"
    load_carried_episodes "$project"
    # Orice întoarcere cu 1 de aici înainte lasă fiecare serviciu al proiectului `unread` în jurnal: proiectul nu s-a
    # clasificat, deci nimic din el nu s-a verificat, iar o rulare următoare (alt --only) nu are voie să iasă verde.
    labels="$(project_compose_labels "$project")" || { say_bad "${project}: nu pot citi etichetele compose"; fail_project "$project" unread "etichetele compose ilizibile"; return 1; }
    workdir="${labels%%|*}"; files="${labels#*|}"
    if [[ -z "$workdir" || -z "$files" ]]; then
        SKIP_LIST+=("${project}: fără etichete compose pe containere (pornit altfel decât cu compose)")
        say_warn "${project}: sărit — fără etichete compose"; return 0
    fi
    IFS=',' read -r -a cfgs <<< "$files"
    DC=(docker compose -p "$project" --project-directory "$workdir")
    for f in "${cfgs[@]}"; do
        if [[ ! -r "$f" ]]; then
            SKIP_LIST+=("${project}: fișierul compose ${f} lipsește sau nu se poate citi")
            say_warn "${project}: sărit — ${f} nu există"; return 0
        fi
        DC+=(-f "$f")
    done
    errf="$(mktemp)"
    if ! cfg_json="$("${DC[@]}" config --format json 2> "$errf")"; then
        say_bad "${project}: docker compose config a eșuat: $(head -c 200 "$errf" | tr '\n' ' ')"; rm -f "$errf"
        fail_project "$project" unread "docker compose config a eșuat"; return 1
    fi
    rm -f "$errf"
    tsv="$(printf '%s' "$cfg_json" | compose_services_tsv)" || { say_bad "${project}: nu pot citi serviciile din config"; fail_project "$project" unread "serviciile din config ilizibile"; return 1; }
    while IFS=$'\x1f' read -r svc image ctx; do
        [[ -n "$svc" ]] || continue
        svc_image[$svc]="$image"; svc_ctx[$svc]="$ctx"
    done <<< "$tsv"
    # citirea a reușit: doar asta rezolvă `unread` (nu s-a schimbat nimic în proiect, deci nu e nimic de verificat)
    while IFS= read -r svc; do [[ -n "$svc" ]] && report_line "$project" "$svc" read-ok "configurația citită"; done < <(project_services "$project")

    classify_services "$project"
    if (( refuse )); then say_bad "${project}: refuzat — nu s-a schimbat nimic în proiect"; return 1; fi
    (( OPT_DRY_RUN )) && return 0
    execute_project "$project"
}

# skip_service PROJECT SERVICE CODE MOTIV — nimic nu se sare în tăcere: motivul ajunge pe
# ecran, în raportul de sfârșit și în containers.report (citit de verify).
# Al cincilea argument = 1: nu se scrie în jurnal (o reîncercare `--retry-failed` a unei aplicații construite local, fără
# --rebuild, nu are de ce să dezarmeze reîncercarea cu un `skip`: ea doar re-verifică containerul de acum).
skip_service() {
    SKIP_LIST+=("${1}/${2}: ${4}")
    say_warn "${1}/${2}: sărit (${3}) — ${4}"
    (( OPT_DRY_RUN || ${5:-0} )) || report_line "$1" "$2" "$3" "$4"
    act[$2]="$3"
}

# Baseline-ul e vechi pentru un serviciu: rulează o imagine pe care nici baseline-ul, nici mentenanța de față n-au pus-o.
stale_baseline_msg() {
    printf '%s/%s: baseline-ul e vechi pentru serviciul ăsta: containerul rulează acum imaginea %s, nu cea din baseline (%s), iar mentenanța de față nu a pus-o acolo (un redeploy de după baseline). O etichetă de rollback pe imaginea din baseline ar anula acel deploy. Ia un baseline nou: --phase preflight --new-baseline (apoi --phase backup dacă backup-ul are peste 12 h, apoi --phase containers), sau readu containerul pe imaginea din baseline' \
        "$1" "$2" "${3:7:12}" "${4:7:12}"
}

# flag_stale_baseline PROIECT SERVICIU ID_CARE_RULEAZĂ — baseline vechi pentru serviciu: tipărește, scrie `stale-baseline`, ține TOT proiectul
# (refuse=1, variabila lui process_project). Folosit și pentru un serviciu `failed` reținut: reținerea lui nu are voie să ascundă un redeploy
# de după baseline (un frate al lui, cu un pull de făcut, ar fi fost tras/etichetat/recreat în același proiect fără niciun cuvânt despre baseline).
flag_stale_baseline() {
    local project="$1" svc="$2" cur="$3" reason
    reason="$(stale_baseline_msg "$project" "$svc" "$cur" "${base_id[$svc]}")"
    say_bad "${reason}; nu atinge nimic în proiect"
    SKIP_LIST+=("${project}/${svc}: stale-baseline — ${cur:7:12} nu e imaginea din baseline (${base_id[$svc]:7:12}) și nici una pusă de mentenanță")
    report_line "$project" "$svc" stale-baseline "baseline vechi: rulează ${cur:7:12}, baseline ${base_id[$svc]:7:12}"
    act[$svc]=hold-stale-baseline; refuse=1
}

# hold_ownership_check PROIECT SERVICIU NUME — pentru un serviciu REȚINUT (failed neîncercat, ori recunoscut în rularea asta) care nu se atinge, dar al cărui container
# se poate citi: dacă rulează o imagine pe care nici baseline-ul, nici mentenanța n-au pus-o => stale-baseline (ține proiectul); dacă e a noastră => `owned-ok`,
# care rezolvă un stale-baseline rămas (faptul nu mai e adevărat), fără să atingă nicio altă stare.
hold_ownership_check() {
    local project="$1" svc="$2" name="$3" cur
    if cur="$(docker inspect -f '{{.Image}}' "$name")" && [[ -n "$cur" ]]; then
        if su_image_is_ours "$cur" "${base_id[$svc]}" "${BASE}/containers.owned" "$project" "$svc"; then
            report_line "$project" "$svc" owned-ok "rulează ${cur:7:12} (baseline sau pusă de mentenanță)"
        else
            flag_stale_baseline "$project" "$svc" "$cur"
        fi
    fi
}

# Hash-ul de configurație al serviciului, cel cu care a fost creat containerul față de cel
# pe care l-ar crea `up` acum. Diferă când fișierul compose s-a schimbat după creare: `up`
# ar livra și schimbarea aceea. Măsurat pe gazdă (19 nov 2026): se potrivește pentru toate
# cele 11 containere probate, deci o diferență e reală, nu zgomot de versiune.
# yes | no | unknown
cfg_hash_changed() {
    local project="$1" svc="$2" name="$3" label now
    label="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.config-hash"}}' "$name" || true)"
    now="$("${DC[@]}" config --hash "$svc" | awk 'NR == 1 { print $2 }')" || now=""
    if [[ -z "$label" || -z "$now" ]]; then echo unknown
    elif [[ "$label" == "$now" ]]; then echo no
    else echo yes
    fi
}

classify_services() {
    local project="$1" svc line image ctx name run_id tag_id health base_img facts newer dirty headn verdict decision
    local exists digests cfgchg reason cur_run hold_run hold_tag touched prior prior_all retrying fkey cur_tag eh ep est ptag prun exempt q
    local -a row
    local -A facts_cache=()
    local svc_list
    svc_list="$(printf '%s\n' "${!svc_image[@]}" | LC_ALL=C sort)"
    while IFS= read -r svc; do
        [[ -n "$svc" ]] || continue
        line="$(awk -F'|' -v p="$project" -v s="$svc" '$2 == p && $3 == s && $7 == "running" { print; exit }' "${BASE}/containers.tsv")"
        if [[ -z "$line" ]]; then
            skip_service "$project" "$svc" skip-not-running "nu rula la baseline; nu pornesc ce n-a rulat"; continue
        fi
        IFS='|' read -r -a row <<< "$line"
        name="${row[0]}"; base_img="${row[3]}"; run_id="${row[4]}"; tag_id="${row[5]}"; health="${row[7]}"
        svc_names[$svc]="$(awk -F'|' -v p="$project" -v s="$svc" '$2 == p && $3 == s && $7 == "running" { printf "%s ", $1 }' "${BASE}/containers.tsv")"
        cfg_image[$svc]="$base_img"   # implicit numele cu care compose a creat containerul (pull/build îl înlocuiesc mai jos)
        prior="$(su_report_final "${BASE}/containers.report" | awk -F'|' -v k="${project}/${svc}" '$1 == k { print $2; exit }')"
        prior_st[$svc]="$prior"
        # TOATE stările lipicioase nerezolvate ale serviciului (`prior` e doar prima, în ordinea de afișare): un `stale-baseline` afișat peste un
        # `failed` nu are voie să facă reținerea lui `failed` să dispară când containerul revine pe imaginea din baseline.
        prior_all="$(su_report_final "${BASE}/containers.report" all | awk -F'|' -v k="${project}/${svc}" '$1 == k { print $2 }')"
        base_id[$svc]="$run_id"      # încă ID-ul din baseline (run_id se suprascrie mai jos): imaginea de dinainte de mentenanță
        # Un serviciu recunoscut de operator ÎN RULAREA ASTA nu se atinge: `acked` e rezultatul lui final și niciun eveniment din aceeași rulare (skip-*, hold-*,
        # o recreare) nu are voie să-l înlocuiască — verify l-ar fi arătat verde, fără niciun cuvânt despre recunoaștere. Nu scrie nimic în jurnal.
        # Proprietatea se verifică totuși (citire): `--acknowledge` nu șterge `stale-baseline`, iar un redeploy de după baseline ține TOT proiectul, ca la orice serviciu.
        if in_array "${project}/${svc}" ${ack_keys[@]+"${ack_keys[@]}"}; then
            SKIP_LIST+=("${project}/${svc}: recunoscut de operator în rularea asta (--acknowledge) — neatins")
            say_warn "${project}/${svc}: recunoscut de operator în rularea asta — nu-l ating și nu-i schimb rezultatul final (acked)"
            hold_ownership_check "$project" "$svc" "$name"
            act[$svc]=hold-acked; continue
        fi
        # Un serviciu `failed` sub această baseline (recreat și picat, ori readus manual la eticheta de rollback)
        # NU se mai trage și NU se mai recreează la o rulare simplă: ar pune la loc exact imaginea care a picat,
        # peste rollback-ul operatorului. Rămâne roșu până când operatorul cere explicit `--retry-failed`.
        # Reținerea se judecă ÎNAINTEA oricărei citiri a containerului: un serviciu `failed` al cărui container nu mai
        # există (ramura «niciun container după up») ar fi ieșit `skip-unreadable`, iar acela înlocuia eșecul.
        retrying=0
        if [[ $'\n'"${prior_all}"$'\n' == *$'\nfailed\n'* ]]; then
            if su_list_has "$OPT_RETRY_FAILED" "$project" 0; then retrying=1
            else
                SKIP_LIST+=("${project}/${svc}: failed sub această baseline — neatins la rularea asta")
                say_bad "${project}/${svc}: rezultatul final sub această baseline e failed (recreat și picat, sau readus manual la imaginea veche) — NU îl trag și NU îl recreez; rămâne roșu. După ce ai citit de ce a picat: --retry-failed ${project} (și la o aplicație construită local: re-verifică containerul de acum, fără --rebuild). $(su_ack_hint "$project" "$svc")"
                act[$svc]=hold-failed
                # Reținerea nu scutește serviciul de verificarea proprietății (făcută doar când containerul se poate citi: un `failed` fără
                # container rămâne `failed`, nu devine alt rezultat): un redeploy de după baseline ține proiectul, ca și pentru orice alt serviciu.
                hold_ownership_check "$project" "$svc" "$name"
                continue
            fi
        fi
        # Imaginea care rulează ACUM, nu cea din baseline. La o a doua rulare (după un eșec într-un alt
        # proiect, de pildă) serviciile deja actualizate rulează alt ID decât în baseline: decizia de
        # «recreez» luată din baseline ar cere o recreare care n-are ce să schimbe, iar verificarea
        # «creat după începutul rulării» ar declara eșec pe un container sănătos.
        if ! cur_run="$(docker inspect -f '{{.Image}}' "$name")" || [[ -z "$cur_run" ]]; then
            skip_service "$project" "$svc" skip-unreadable "nu pot citi imaginea care rulează acum pentru ${name}"; continue
        fi
        old_id[$svc]="$cur_run"; base_health[$svc]="$health"
        # Un eșec PRELUAT dintr-un baseline anterior se judecă după episodul lui (containers.episode), legat de linia lui din jurnal prin ID: sănătatea din
        # baseline-ul eșecului și `prev`. Baseline-ul nou (`health`) rămâne baza verdictului obișnuit; episodul adaugă o a doua judecată, cu ACEEAȘI funcție
        # (su_container_verdict, în check_container), care trebuie să dea `ok`. Lipsa sănătății din episod nu e «sănătos»: `-` = neînregistrată, nu se poate rezolva.
        base_health[$svc]="$health"; ep_health[$svc]=""; ep_ids[$svc]=""; ep_failed[$svc]=0; ep_prev[$svc]=""; ep_landed[$svc]=""; ack_eps[$svc]=""; ack_health[$svc]=""
        while IFS='|' read -r est ep; do
            [[ -n "$est" && -n "$ep" ]] || continue
            eh="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" base_health | awk 'NR == 1')"
            [[ -n "$eh" ]] || eh="-"
            ep_health[$svc]+="${ep_health[$svc]:+ }${eh}"; ep_ids[$svc]+="${ep_ids[$svc]:+ }${ep}"
            CARRIED_EP["${project}/${svc}|${est}"]="$ep"
            if [[ "$est" == failed ]]; then
                ep_failed[$svc]=1
                [[ -n "${ep_prev[$svc]}" ]] || ep_prev[$svc]="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" prev | awk 'NR == 1')"
                ep_landed[$svc]+="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" landed | tr '\n' ' ')"
            fi
            say_info "${svc}: eșec preluat (${est}, episodul ${ep}) — îl judec și față de sănătatea de dinainte de eșec (${eh}), pe lângă baseline-ul nou (${health})"
        done < <(su_state_episodes "${BASE}/containers.report" "$project" "$svc")
        # O recunoaștere a operatorului în picioare (steagul `acked`, durabil) are episoadele ei: aceeași sănătate de dinainte de eșec, judecată de aceeași funcție, dar
        # ea NU poate pica verificarea (operatorul a acceptat starea): doar decide dacă steagul se șterge (verdict ok sau same-bad față de episod ȘI baseline). `prev`/`landed` din
        # episod hotărăsc și ținta rollback-ului când serviciul se recreează peste imaginea picată (ensure_rollback_tag), ca la un `failed` preluat.
        while IFS= read -r ep; do
            [[ -n "$ep" ]] || continue
            eh="-"
            if [[ "$ep" == "-" || "$ep" == "${BASE##*/}" ]]; then
                # recunoaștere a unui eșec produs ÎN baseline-ul de acum: episodul lui e chiar baseline-ul (`health` din containers.tsv), `prev`/`landed` sunt în containers.owned
                ep="${BASE##*/}"; eh="${health:--}"
            elif [[ "$ep" != "-" ]]; then
                eh="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" base_health | awk 'NR == 1')"; [[ -n "$eh" ]] || eh="-"
                [[ -n "${ep_prev[$svc]}" ]] || ep_prev[$svc]="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" prev | awk 'NR == 1')"
                ep_landed[$svc]+="$(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" landed | tr '\n' ' ')"
            fi
            ack_eps[$svc]+="${ack_eps[$svc]:+ }${ep}"; ack_health[$svc]+="${ack_health[$svc]:+ }${eh}"
            say_info "${svc}: recunoscut de operator (episodul ${ep}) — NERESOLVAT în fapt; îl re-verific și se șterge doar cu verdict ok sau same-bad față de sănătatea de dinainte de eșec (${eh}) ȘI față de baseline-ul nou (${health})"
        done < <(su_ack_episodes "${BASE}/containers.report" "$project" "$svc")
        # Baseline vechi: imaginea care rulează nu e nici cea din baseline, nici una pe care am văzut-o noi rulând după un `up` al nostru.
        # Se ține AICI, înainte de pull, build, tag și up, pentru orice fel de serviciu (și pentru unul pe care rularea de acum
        # nu l-ar fi schimbat): «nimic nou de tras» nu schimbă proprietatea, iar un verde peste un container pe care nimeni nu
        # l-a verificat sub acest baseline ar fi tocmai afirmația pe care nu o putem face. Rămâne roșu (lipicios) până când
        # faptul încetează să fie adevărat (containerul revine pe imaginea din baseline) sau se ia un baseline nou.
        if ! su_image_is_ours "$cur_run" "${base_id[$svc]}" "${BASE}/containers.owned" "$project" "$svc"; then
            flag_stale_baseline "$project" "$svc" "$cur_run"; continue
        fi
        report_line "$project" "$svc" owned-ok "rulează ${cur_run:7:12} (baseline sau pusă de mentenanță)"
        # `--retry-failed` e cerut ȘI containerul poate fi citit: abia acum e o reîncercare reală. Doar `retried` urmat de o
        # recreare/verificare dovedită șterge `failed` (su_report_final); un pull eșuat sau un skip între ele îl dezarmează.
        if (( retrying )); then report_line "$project" "$svc" retried "--retry-failed ${project}"; fi
        # Un serviciu e ATINS sub această baseline dacă rulează alt ID de imagine decât la baseline sau dacă
        # rezultatul lui final (su_report_final) e un eșec. Se RE-VERIFICĂ starea lui de acum (sănătate +
        # stabilitate) indiferent ce spune `pull`: «imaginea trasă e cea care rulează» nu e «containerul e
        # sănătos» — fără asta, a doua rulare declara «la zi» un container care se repornea în buclă.
        touched=0
        if [[ "$cur_run" != "${row[4]}" ]]; then touched=1; fi
        if su_is_sticky "$prior"; then touched=1; fi
        if [[ -n "${ack_eps[$svc]}" ]]; then touched=1; fi      # o recunoaștere în picioare se re-verifică la fiecare rulare: altfel n-ar avea cum să se rezolve niciodată
        if (( touched )); then
            check_svcs+=("$svc")
            say_info "${svc}: atins sub această baseline (imagine schimbată sau eșec anterior) — îi re-verific starea de acum"
        fi
        # `hold-moved-tag` se judecă din faptele din baseline, dar DOAR cât containerul n-a fost atins
        # de la baseline; dacă rulează alt ID, baseline-ul nu mai spune nimic despre el.
        hold_run="$run_id"; hold_tag="$tag_id"
        if [[ "$cur_run" != "$run_id" ]]; then hold_run="$cur_run"; hold_tag="$cur_run"; fi
        # Eticheta mutată de pull-ul mentenanței însăși nu e «mutată de altcineva»: recrearea pe ea e exact ce ar fi făcut rularea care a căzut. Scutirea e legată
        # de EPISOD (un eșec preluat, încă nerezolvat) și cere AMBELE fapte ale pull-ului: eticheta de acum e TAG-ul pe care l-am tras, iar containerul rulează
        # ÎNCĂ imaginea pe care o rula la acel pull. Un redeploy străin de după (alt ID rulează) urmat de un baseline nou lasă eticheta pe TAG, dar ce rulează
        # nu mai e ce rula atunci: rămâne hold-moved-tag, ca orice altă mutare.
        if [[ "$hold_tag" != "$hold_run" ]]; then
            exempt=0
            for ep in ${ep_ids[$svc]:-}; do
                while IFS='|' read -r ptag prun; do
                    if [[ -n "$ptag" && -n "$prun" && "$ptag" == "$hold_tag" && "$prun" == "$cur_run" ]]; then exempt=1; fi
                done < <(su_episode_vals "${BASE}/containers.episode" "$project" "$svc" "$ep" pulled)
            done
            if (( exempt )); then
                say_info "${svc}: eticheta arată ${hold_tag:7:12}, imaginea pe care a tras-o chiar mentenanța asta (episod preluat), iar containerul rulează încă ${cur_run:7:12}, ca la pull: nu e o mutare a altcuiva, deci nu o țin ca hold-moved-tag"
                hold_tag="$hold_run"
            fi
        fi
        run_id="$cur_run"
        ctx="${svc_ctx[$svc]}"; image="${svc_image[$svc]}"
        cfgchg="$(cfg_hash_changed "$project" "$svc" "$name")"

        if [[ -n "$ctx" ]]; then
            if [[ ! -d "$ctx" ]]; then
                skip_service "$project" "$svc" skip-no-context "contextul de build ${ctx} nu există pe disc — nu pot reconstrui"; continue
            fi
            # Faptele se măsoară față de imaginea care rulează sub FIECARE serviciu: două servicii cu același context (nis2
            # api/worker) pot avea imagini de vârste diferite, iar cel cu imaginea mai veche nu moștenește «curat» de la celălalt.
            fkey="${ctx}|${run_id}"
            if [[ -z "${facts_cache[$fkey]:-}" ]]; then facts_cache[$fkey]="$(ctx_drift_facts "$ctx" "$run_id")"; fi
            IFS='|' read -r newer dirty headn <<< "${facts_cache[$fkey]}"
            verdict="$(su_drift_verdict "$newer" "$dirty" "$headn")"
            if [[ "$cfgchg" == yes ]]; then verdict="drift"
            elif [[ "$cfgchg" == unknown && "$verdict" == clean ]]; then verdict="unknown"; fi
            decision="$(su_build_decision "$project" "$OPT_REBUILD" "$OPT_ACCEPT_DRIFT" "$verdict")"
            say_info "${svc}: build din ${ctx} — fișiere mai noi decât imaginea=${newer}, git murdar=${dirty}, commit mai nou=${headn}, config compose schimbat=${cfgchg} => cod ${verdict}, decizie ${decision}"
            # Eticheta de ACUM față de ce rulează acum (nu eticheta din baseline față de ce rula la baseline: un `docker build`/redeploy
            # de după baseline mută eticheta fără să atingă baseline-ul, iar mesajul vechi tăcea sau minția despre starea de azi).
            cur_tag="$(docker image inspect -f '{{.Id}}' "$base_img" || true)"
            if [[ -n "$cur_tag" && "$cur_tag" != "$run_id" ]]; then
                say_info "  NB: eticheta ${base_img} arată acum imaginea ${cur_tag:7:12}, iar containerul rulează ${run_id:7:12} — eticheta a fost mutată (build) după crearea containerului"
            fi
            case "$decision" in
                build|build-accepted-drift)
                    [[ "$decision" == build-accepted-drift ]] && say_warn "${svc}: construiesc cu cod diferit de cel care rulează, acceptat de operator (--accept-drift ${project})"
                    cfg_image[$svc]="$base_img"; build_svcs+=("$svc"); act[$svc]=build ;;
                skip-not-requested)
                    reason="aplicație construită local; reconstruirea e opt-in (--rebuild ${project})"
                    skip_service "$project" "$svc" skip-not-requested "$reason" "$retrying" ;;
                *)
                    reason="codul de pe disc diferă de cel care rulează (${newer} fișiere mai noi decât imaginea, git murdar=${dirty}, commit mai nou=${headn}, config compose schimbat=${cfgchg})"
                    [[ "$decision" == skip-unknown ]] && reason="nu pot stabili dacă codul de pe disc e cel care rulează (${newer}/${dirty}/${headn})"
                    skip_service "$project" "$svc" "$decision" "${reason}. Primele fișiere noi: $(ctx_changed_files "$ctx" "$run_id" | tr '\n' ' '). Revizuiește codul din ${ctx}, apoi --accept-drift ${project}" ;;
            esac
            continue
        fi

        exists=no; digests="?"
        if docker image inspect "$image" > /dev/null 2>&1; then
            exists=yes
            digests="$(docker image inspect -f '{{len .RepoDigests}}' "$image")" || digests="?"
        fi
        decision="$(su_pull_decision "$base_img" "$exists" "$digests" "$hold_run" "$hold_tag")"
        # «nu pot compara» (unknown) nu e «nu s-a schimbat»: ține serviciul, ca și un hash diferit
        if [[ "$decision" == pull && "$cfgchg" != no ]] && ! su_list_has "$OPT_ACCEPT_DRIFT" "$project" 0; then
            decision="hold-config-drift"
        fi
        case "$decision" in
            pull)
                say_info "${svc}: pull ${image} (rulează ${run_id:7:12}, eticheta arată aceeași imagine)"
                cfg_image[$svc]="$image"; pull_svcs+=("$svc"); act[$svc]=pull ;;
            skip-bare-id)  skip_service "$project" "$svc" "$decision" "containerul rulează de pe un ID de imagine gol (${base_img}) — nu există o etichetă de tras" ;;
            skip-no-image) skip_service "$project" "$svc" "$decision" "imaginea ${image} nu există local" ;;
            skip-unknown)  skip_service "$project" "$svc" "$decision" "nu pot citi RepoDigests pentru ${image}" ;;
            skip-local)    skip_service "$project" "$svc" "$decision" "imaginea ${image} n-a venit niciodată dintr-un registru (RepoDigests gol): un pull ar căuta acel nume pe Docker Hub; se reface din sursa ei, nu de aici" ;;
            hold-moved-tag) skip_service "$project" "$svc" "$decision" "eticheta ${image} arată ${tag_id:7:12}, dar containerul rulează ${run_id:7:12}: s-a tras o imagine nouă fără recreare. Recrearea ar sări peste toate versiunile dintre ele (migrări la pornire) — decizie manuală" ;;
            hold-config-drift) skip_service "$project" "$svc" "$decision" "configurația compose a serviciului s-a schimbat de la crearea containerului; recrearea ar livra și schimbarea aceea. Revizuiește fișierele compose, apoi --accept-drift ${project}" ;;
        esac
    done <<< "$svc_list"
}

# După un build eșuat: dovada că NIMIC din proiect nu s-a mișcat. Se compară cu starea de DINAINTEA
# acestei rulări (pre_img, luată de execute_project), nu cu baseline-ul: la o rulare repetată, containerele
# deja actualizate rulează legitim alt ID decât în baseline, iar comparația cu baseline-ul ar striga
# «imaginea s-a schimbat» pe ce n-a atins această rulare.
assert_project_untouched() {
    local project="$1" name want now bad=0
    for name in "${!pre_img[@]}"; do
        want="${pre_img[$name]}"
        now="$(docker inspect -f '{{.Image}}' "$name")" || now="?"
        if [[ "$now" != "$want" ]]; then say_bad "${name}: imaginea s-a schimbat (${now:7:12}) deși build-ul a eșuat"; bad=1; fi
    done
    (( bad )) || say_ok "${project}: build-ul a eșuat, dar containerele rulează neschimbate (ID-uri de imagine identice cu cele de dinaintea acestei rulări)"
}

in_array() {
    local needle="$1" x; shift
    for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
    return 1
}

# execute_project PROJECT — scop dinamic: DC, pull_svcs, build_svcs, check_svcs, old_id, cfg_image, unresolved
# (serviciu -> pull-failed|build-failed în rularea asta; recheck_services nu-l are voie să-l înlocuiască cu `verified`), ...
# Două etape: schimbările (build/pull/recreare, cu dovada lor) și RE-VERIFICAREA serviciilor atinse.
execute_project() {
    local project="$1" rc1=0 rc2=0 start_epoch name
    local -a recreate=()
    local -A pre_img=() unresolved=()
    start_epoch="$(now_epoch)"
    if (( ${#pull_svcs[@]} + ${#build_svcs[@]} + ${#check_svcs[@]} == 0 )); then say_info "${project}: nimic de făcut"; return 0; fi
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        pre_img[$name]="$(docker inspect -f '{{.Image}}' "$name")" || pre_img[$name]="?"
    done < <(awk -F'|' -v p="$project" '$2 == p && $7 == "running" { print $1 }' "${BASE}/containers.tsv")
    execute_changes "$project" || rc1=$?
    recheck_services "$project" || rc2=$?
    (( rc1 == 0 && rc2 == 0 ))
}

# ack_clear_if_resolved PROIECT SERVICIU 1|0 [1|0] — coboară steagul `acked` (`ack-cleared`) doar dacă serviciul are o recunoaștere în picioare ȘI verificarea (toate containerele lui)
# a dat verdict ok sau same-bad față de episod și față de baseline (ACK_RESOLVED, setat de check_container). Al patrulea argument = 1 dacă vreun verdict a fost `same-bad`:
# textul spune verdictul real, nu «sănătos» peste un serviciu încă unhealthy. Altfel nu scrie nimic: steagul rămâne.
ack_clear_if_resolved() {
    local verdict=ok
    [[ -n "${ack_eps[$2]:-}" && "$3" == 1 ]] || return 0
    if [[ "${4:-0}" == 1 ]]; then verdict=same-bad; fi
    if [[ "$verdict" == ok ]]; then
        report_line "$1" "$2" ack-cleared "verdict ok față de sănătatea din episod (${ack_health[$2]}) și față de baseline: recunoașterea operatorului se șterge"
        say_ok "${1}/${2}: recunoașterea operatorului a fost ștearsă — verdict ok față de episod și față de baseline: serviciul e sănătos"
    else
        report_line "$1" "$2" ack-cleared "verdict same-bad față de sănătatea din episod (${ack_health[$2]}) și/sau baseline: serviciul e încă unhealthy, dar nu mai rău decât înainte de eșec; recunoașterea operatorului se șterge"
        say_ok "${1}/${2}: recunoașterea operatorului a fost ștearsă — verdict same-bad: serviciul e încă unhealthy, dar nu mai rău decât era înainte de eșec (același standard ca la un eșec rezolvat); NU e «sănătos»"
    fi
}

# RE-verificarea serviciilor atinse care NU au fost recreate de rularea asta: starea de acum, nu o
# acțiune. Reușita se înregistrează ca `verified` (singurul care înlocuiește un `failed` în rezumat).
recheck_services() {
    local project="$1" svc name failed=0 tag_bad="" ack_all ack_sb
    local -a names=()
    for svc in ${check_svcs[@]+"${check_svcs[@]}"}; do
        in_array "$svc" ${recreate[@]+"${recreate[@]}"} && continue
        # un pull/build eșuat în rularea asta NU se șterge cu o verificare de sănătate a containerului vechi:
        # «rulează sănătos» nu spune nimic despre ce n-a putut fi tras ori construit
        if [[ -n "${unresolved[$svc]:-}" ]]; then
            say_info "${project}/${svc}: ${unresolved[$svc]} în rularea asta — nu-l marchez verificat. $(su_sticky_hint "${unresolved[$svc]}" "$project" "$svc")"; continue
        fi
        # Un serviciu `tag-failed` care nu se recreează acum (imaginea trasă e cea care rulează) nu și-ar putea rezolva
        # starea niciodată: `tagged` se scria doar la recreare. Eticheta se verifică/scrie din nou ÎNAINTE de re-verificare.
        # La fel pentru un `failed` PRELUAT reîncercat fără recreare: indiciul de rollback de la un eșec nou trebuie să arate o etichetă pusă pe `prev` din episod.
        if [[ "${prior_st[$svc]:-}" == tag-failed || "${ep_failed[$svc]:-0}" == 1 ]] && ! ensure_rollback_tag "$project" "$svc"; then
            say_bad "$tag_bad"; failed=1
            report_line "$project" "$svc" tag-failed "rollback neprobat: ${tag_bad#*: }"; continue
        fi
        read -r -a names <<< "${svc_names[$svc]}"
        ack_all=1; ack_sb=0
        for name in "${names[@]}"; do
            if check_container "$name" "${old_id[$svc]}" "${base_health[$svc]}" "$start_epoch" 0 "${ep_health[$svc]:-}" "${ack_health[$svc]:-}" "${project}/${svc}" "$(ack_state_for "$project" "$svc" "$name")"; then
                report_line "$project" "$svc" verified "${name} ${old_id[$svc]:7:12}"
                (( ACK_RESOLVED )) || ack_all=0
                (( ACK_SAME_BAD )) && ack_sb=1
            else
                failed=1; ack_all=0; report_line "$project" "$svc" failed "$name"
                rollback_hint "$project" "$svc" "$(service_image_ref "$project" "$svc")"
            fi
        done
        ack_clear_if_resolved "$project" "$svc" "$ack_all" "$ack_sb"
    done
    (( failed == 0 ))
}

# ensure_rollback_tag PROIECT SERVICIU — 0 = eticheta de rollback arată imaginea pe care containerul o rula înainte de prima noastră
# schimbare (dovedit după ID) și s-a scris `tagged`; 1 = nu, iar motivul e în `tag_bad` (variabilă a apelantului, scop dinamic).
# Faptele se citesc LA MOMENTUL schimbării, nu din clasificarea făcută mai devreme (între ele au trecut pull-uri și build-uri):
#   * containerul rulează acum ID-ul clasificat — altfel a fost schimbat de altcineva între timp și nu etichetăm nimic;
#   * ID-ul e al baseline-ului sau unul pe care l-am văzut noi rulând (altfel baseline vechi: nicio etichetă);
#   * `prev` (primul fapt scris înainte de tag/up) e ținta etichetei. Prima scriere câștigă: la o rulare repetată `old_id` poate fi
#     deja imaginea picată; retagarea ar lăsa originalul fără etichetă, iar `docker image prune --filter until=720h` din timerul
#     săptămânal l-ar șterge. Fără `prev` încă, prima atingere cere ca imaginea să fie chiar cea din baseline.
ensure_rollback_tag() {
    local project="$1" svc="$2" tag id live prev first landed_hit landed_n l
    local owned="${BASE}/containers.owned"
    read -r first _ <<< "${svc_names[$svc]}"
    live="$(docker inspect -f '{{.Image}}' "$first")" || live=""
    if [[ -z "$live" || "$live" != "${old_id[$svc]}" ]]; then
        tag_bad="${project}/${svc}: containerul ${first} rulează acum ${live:7:12}${live:+, }nu ${old_id[$svc]:7:12} cât a fost clasificat — l-a schimbat altcineva între timp; nu pun nicio etichetă și nu recreez nimic în proiect"; return 1
    fi
    if ! su_image_is_ours "$live" "${base_id[$svc]}" "$owned" "$project" "$svc"; then
        tag_bad="$(stale_baseline_msg "$project" "$svc" "$live" "${base_id[$svc]}")"; return 1
    fi
    prev="$(su_owned_ids "$owned" "$project" "$svc" prev | awk 'NR == 1')"
    if [[ -z "$prev" ]] && { [[ "${ep_failed[$svc]:-0}" == 1 ]] || [[ -n "${ep_prev[$svc]:-}" ]]; }; then
        # Reîncercarea unui `failed` PRELUAT (ori recreare peste o imagine care a picat, sub o recunoaștere): ținta depinde de ce a rulat ÎNAINTE de schimbarea noastră,
        # citit din container ACUM, nu din baseline-ul nou (care poate fi luat după ce altcineva a schimbat imaginea):
        #   * imaginea de acum e una dintre cele pe care schimbarea noastră eșuată le-a pus (`landed` din episod): imaginea picată încă rulează, deci ținta e `prev` din episod;
        #   * altfel cineva a schimbat-o între timp (un deploy de după eșec), iar ce rulează acum e ce era ÎNAINTE de schimbarea de acum: ținta e imaginea de acum
        #     (proprietatea ei a fost deja dovedită mai sus, su_image_is_ours — baseline-ul nou o are ca imagine din baseline);
        #   * episodul n-are niciun `landed` (nu știu dacă ce rulează e imaginea picată): ca înainte, doar `prev` din episod, ori nimic.
        # ID-urile din episod pot fi trunchiate (su_image_id_same: prefix de cel puțin 12 cifre hex). Un câmp care nu e un ID (prea scurt, ne-hex) nu spune nimic: nu numără
        # nici ca «imaginea picată» nici ca «schimbată de altcineva» — fără niciun ID citibil se aplică regula veche (`prev` din episod).
        landed_hit=0; landed_n=0
        for l in ${ep_landed[$svc]:-}; do
            [[ "${l#sha256:}" =~ ^[0-9a-f]{12,64}$ ]] || continue
            landed_n=$((landed_n + 1))
            if su_image_id_same "$l" "$live"; then landed_hit=1; fi
        done
        if (( landed_n )) && (( ! landed_hit )); then
            prev="$live"
        else
            prev="${ep_prev[$svc]:-}"
            if [[ -z "$prev" ]]; then
                tag_bad="${project}/${svc}: eșecul preluat nu are înregistrată imaginea de dinainte de schimbare (prev, în containers.episode) — nu pot alege o țintă de rollback și nu ghicesc una (ar putea fi chiar imaginea picată); nu recreez nimic în proiect. Ieșirea dacă nu se mai poate rezolva: --phase containers --acknowledge ${project}/${svc}"; return 1
            fi
        fi
        owned_record "$project" "$svc" prev "$prev"      # prima scriere câștigă, ca la orice prev: înainte de tag și de up
    elif [[ -z "$prev" ]]; then
        if [[ "$live" != "${base_id[$svc]}" ]]; then
            tag_bad="${project}/${svc}: nu există o imagine «de dinainte de mentenanță» înregistrată, iar containerul rulează ${live:7:12}, nu imaginea din baseline ${base_id[$svc]:7:12} — nu pot alege o țintă de rollback; nu recreez nimic în proiect"; return 1
        fi
        prev="$live"
        owned_record "$project" "$svc" prev "$prev"      # faptul se scrie ÎNAINTE de tag și de up
    fi
    tag="$(rollback_tag "$project" "$svc")"
    if id="$(docker image inspect -f '{{.Id}}' "$tag" 2> /dev/null)" && [[ -n "$id" ]]; then
        if [[ "$id" != "$prev" ]]; then
            tag_bad="${project}/${svc}: eticheta ${tag} există și arată ${id:7:12}, nu imaginea de dinainte de mentenanță ${prev:7:12} — n-o suprascriu; nu recreez nimic în proiect"; return 1
        fi
        say_info "${project}/${svc}: eticheta de rollback există deja și arată imaginea originală (${id:7:12}) — o las neatinsă"
    else
        if ! docker tag "$prev" "$tag"; then
            tag_bad="${project}/${svc}: nu pot pune eticheta de rollback pe imaginea originală ${prev:7:12} — nu recreez nimic în proiect"; return 1
        fi
        id="$(docker image inspect -f '{{.Id}}' "$tag")" || id=""
        if [[ "$id" != "$prev" ]]; then
            tag_bad="${project}/${svc}: eticheta ${tag} nu arată imaginea originală (${id:-nimic}) — nu recreez nimic în proiect"; return 1
        fi
    fi
    report_line "$project" "$svc" tagged "$tag"
}

execute_changes() {
    local project="$1" svc rc new res tag free_kb image id cname now_img pull_failed=0
    local -A pulled_rc=()

    # 1. build înainte de pull: un build eșuat se oprește înainte să fi mutat vreo etichetă
    if (( ${#build_svcs[@]} )); then
        free_kb="$(df -Pk / | awk 'NR == 2 { print $4 }')" || free_kb=""
        if [[ ! "$free_kb" =~ ^[0-9]+$ ]] || (( free_kb / 1048576 < MIN_FREE_GB )); then
            say_bad "${project}: spațiu liber insuficient sau necitibil pentru un build (minim ${MIN_FREE_GB} GB)"
            fail_services "$project" build-failed "spațiu liber insuficient sau necitibil (minim ${MIN_FREE_GB} GB): build refuzat" "${build_svcs[@]}"
            return 1
        fi
        say_info "${project}: docker compose build --pull ${build_svcs[*]}"
        rc=0; nolock "${DC[@]}" build --pull "${build_svcs[@]}" || rc=$?
        if (( rc != 0 )); then
            say_bad "${project}: build a eșuat (cod ${rc}); nu recreez nimic din proiect"
            fail_services "$project" build-failed "build --pull cod ${rc}" "${build_svcs[@]}"
            assert_project_untouched "$project"; return 1
        fi
        for svc in "${build_svcs[@]}"; do
            new="$(docker image inspect -f '{{.Id}}' "${cfg_image[$svc]}")" || new=""
            if [[ -z "$new" ]]; then
                say_bad "${project}/${svc}: nu pot citi imaginea ${cfg_image[$svc]} după build"
                # build-ul s-a încheiat dar rezultatul nu se poate dovedi, iar întoarcerea de aici lasă TOT proiectul nerecreat
                fail_services "$project" build-failed "imaginea ${cfg_image[$svc]} nu se poate citi după build; proiectul oprit" "${build_svcs[@]}"
                return 1
            fi
            report_line "$project" "$svc" built "${cfg_image[$svc]} ${new:7:12}"
            if [[ "$new" == "${old_id[$svc]}" ]]; then
                if in_array "$svc" ${check_svcs[@]+"${check_svcs[@]}"}; then
                    say_info "${project}/${svc}: build terminat, imaginea e identică — starea de acum se re-verifică mai jos"
                else
                    say_ok "${project}/${svc}: build terminat, imaginea e identică (straturi la zi) — nimic de recreat"
                    report_line "$project" "$svc" up-to-date "build fără schimbări"
                fi
            else
                want_id[$svc]="$new"; recreate+=("$svc")
            fi
        done
    fi

    # 2. pull: «a eșuat» nu e «nu e nimic nou»
    for svc in ${pull_svcs[@]+"${pull_svcs[@]}"}; do
        image="${cfg_image[$svc]}"
        if [[ -z "${pulled_rc[$image]:-}" ]]; then
            rc=0; nolock docker pull -q "$image" > /dev/null || rc=$?
            pulled_rc[$image]="$rc"
        fi
        new="$(docker image inspect -f '{{.Id}}' "$image" || true)"
        res="$(su_pull_result "${pulled_rc[$image]}" "${old_id[$svc]}" "$new")"
        case "$res" in
            pull-failed)
                say_bad "${project}/${svc}: docker pull ${image} a eșuat (cod ${pulled_rc[$image]}) — nu știu dacă există o versiune nouă; NU declar «la zi»"
                pull_failed=1; unresolved[$svc]=pull-failed
                report_line "$project" "$svc" pull-failed "$image" ;;
            up-to-date)
                report_line "$project" "$svc" pulled "$image ${new:7:12}"
                if in_array "$svc" ${check_svcs[@]+"${check_svcs[@]}"}; then
                    say_info "${project}/${svc}: ${image} — imaginea trasă e cea care rulează; starea de acum se re-verifică mai jos"
                else
                    say_ok "${project}/${svc}: ${image} e la zi (imaginea trasă e cea care rulează)"
                    report_line "$project" "$svc" up-to-date "$image"
                fi ;;
            recreate)
                report_line "$project" "$svc" pulled "$image ${new:7:12}"
                # fapt: eticheta a fost mutată de pull-ul NOSTRU pe imaginea asta, cât containerul rula ID-ul citit ACUM din el (carry_forward_sticky îl preia în
                # episod; scutirea de hold-moved-tag cere ambele). Un container ilizibil nu scrie nimic: fără RUN, nicio scutire.
                read -r cname _ <<< "${svc_names[$svc]}"
                now_img="$(docker inspect -f '{{.Image}}' "$cname")" || now_img=""
                if [[ -n "$now_img" ]]; then owned_record "$project" "$svc" pulled "${new}|${now_img}"; fi
                want_id[$svc]="$new"; recreate+=("$svc") ;;
        esac
    done
    # un pull eșuat oprește TOT proiectul: jumătate de proiect pe imagini noi, jumătate pe vechi, nu e o stare pe care s-o fi cerut cineva.
    # Serviciile care erau gata de recreat (eticheta lor a și mutat, containerul nu) rămân nerezolvate în jurnal, cu starea
    # TRASEULUI lor (pull sau build), ca un `--only` ulterior pe alt proiect să nu iasă verde peste ele.
    if (( pull_failed )); then
        local st
        for svc in ${recreate[@]+"${recreate[@]}"}; do
            st=pull-failed; [[ "${act[$svc]:-}" == build ]] && st=build-failed
            fail_services "$project" "$st" "proiect oprit de un pull eșuat la alt serviciu; ${svc} nu a fost recreat" "$svc"
        done
        return 1
    fi
    if (( ${#recreate[@]} == 0 )); then say_info "${project}: nimic de recreat"; return 0; fi

    # 3. imaginea veche capătă eticheta de rollback ÎNAINTE de `up`, doar pentru serviciile care chiar se
    # recreează (la o rulare repetată nu se recreează nimic, deci eticheta originală NU se suprascrie cu
    # imaginea deja nouă), iar eticheta se citește înapoi (ensure_rollback_tag).
    # O eticheta care nu se poate dovedi oprește TOT proiectul, iar pull-ul/build-ul a mutat deja etichetele imaginii,
    # în timp ce containerele rulează încă pe cea veche: fiecare serviciu care trebuia recreat rămâne `tag-failed`.
    local tag_bad=""
    for svc in "${recreate[@]}"; do
        ensure_rollback_tag "$project" "$svc" || break
    done
    if [[ -n "$tag_bad" ]]; then
        say_bad "$tag_bad"
        fail_services "$project" tag-failed "rollback neprobat, proiect oprit: ${tag_bad#*: }" "${recreate[@]}"
        return 1
    fi

    # 4. recreare țintită + dovada
    say_info "${project}: recreez ${recreate[*]}"
    rc=0; nolock "${DC[@]}" up -d --no-deps --no-build "${recreate[@]}" || rc=$?
    (( rc == 0 )) || say_bad "${project}: docker compose up a ieșit cu ${rc} — verific totuși ce rulează"
    local failed=0 ack_all ack_sb
    for svc in "${recreate[@]}"; do
        local -a ids=()
        mapfile -t ids < <("${DC[@]}" ps -q "$svc")
        if (( ${#ids[@]} == 0 )); then
            say_bad "${project}/${svc}: niciun container după up"; failed=1; report_line "$project" "$svc" failed "niciun container"
            rollback_hint "$project" "$svc" "$(service_image_ref "$project" "$svc")"; continue
        fi
        ack_all=1; ack_sb=0
        for id in "${ids[@]}"; do
            cname="$(docker inspect -f '{{.Name}}' "$id")" || cname="$id"; cname="${cname#/}"
            # Efectul `up`, observat: ce imagine RULEAZĂ containerul acum. Doar dacă e cea voită o recunoaștem ca a noastră (`landed`),
            # înainte de verificarea de sănătate: o reîncercare după un eșec rulează tocmai imaginea picată, iar ea nu e «străină».
            now_img="$(docker inspect -f '{{.Image}}' "$cname")" || now_img=""
            if [[ -n "$now_img" && "$now_img" == "${want_id[$svc]}" ]]; then owned_record "$project" "$svc" landed "$now_img"; fi
            if check_container "$cname" "${want_id[$svc]}" "${base_health[$svc]}" "$start_epoch" 1 "${ep_health[$svc]:-}" "${ack_health[$svc]:-}" "${project}/${svc}" "$(ack_state_for "$project" "$svc" "$cname")"; then
                report_line "$project" "$svc" recreated "${old_id[$svc]:7:12} -> ${want_id[$svc]:7:12}"
                CHANGED_LIST+=("${cname}: ${old_id[$svc]:7:12} -> ${want_id[$svc]:7:12}")
                (( ACK_RESOLVED )) || ack_all=0
                (( ACK_SAME_BAD )) && ack_sb=1
            else
                failed=1; ack_all=0; report_line "$project" "$svc" failed "${cname}"
                rollback_hint "$project" "$svc" "$(service_image_ref "$project" "$svc")"
            fi
        done
        ack_clear_if_resolved "$project" "$svc" "$ack_all" "$ack_sb"
    done
    (( failed == 0 ))
}
