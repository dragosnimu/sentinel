#!/usr/bin/env bash
# VPS watchdog - monitorizare disponibilitate/capacitate + auto-remediere marginita.
#
# Rulat de vps-watchdog.timer, o data pe minut. Nu depinde de Sentinel (nici baza
# de date, nici venv-ul): foloseste doar bash, awk, curl si docker. Trimite pe
# Telegram cu tokenul din secrets.env, deci mesajele ajung sub numele botului
# Sentinel - de aceea scriptul traieste in depozit, revizuit, nu pe gazda.
#
# CONFIGURAREA GAZDEI NU E AICI. Domeniile verificate sunt ale unor clienti, iar
# depozitul e public: stau in /etc/sentinel/vps-watchdog.conf (vezi
# deploy/config/vps-watchdog.conf.example) si se citesc la fiecare rulare. Fisierul
# NU e executat (`source`): se citesc doar cheile de mai jos, ca date.
#
# ---------------------------------------------------------------------------
# 1. Identitatea unei probleme e CHEIA (campul dinaintea primului `|`), nu linia.
#
# Versiunea de dinainte compara linii intregi, iar linia continea masuratoarea
# ("Swap la 99%"). Fiecare punct procentual de miscare producea o "problema noua"
# si una "rezolvata" - operatorul a primit "Swap la 99%" ca nou si "Swap la 100%"
# ca rezolvat, desi nimic nu se rezolvase. Acum noua/rezolvata se calculeaza
# doar din chei; o problema care persista cu alta valoare nu emite nimic.
#
# Fisierul de stare pastreaza TOT randul (cheie|text), pentru ca mesajul
# "rezolvat" trebuie sa citeze textul unei probleme care nu mai exista in rularea
# curenta. Formatul e cel vechi, deci o stare scrisa de versiunea dinainte se
# citeste fara migrare.
#
# ---------------------------------------------------------------------------
# 2. Swap-ul plin NU e o defectiune; paginarea activa ESTE.
#
# Pragul pe procentul de swap masura consecinta: nucleul scosese ~2 GB pe disc
# cand RAM-ul fusese strans, iar swap-ul ramanea la 99-100% ore intregi dupa ce
# presiunea trecuse (vmstat: si=0 so=0). Alerta suna pe starea statica, nu pe
# eveniment. Acum se masoara RITMUL: pswpin+pswpout din /proc/vmstat sunt
# contoare cumulative, deci se pastreaza un istoric scurt (vmstat.ring) si se
# calculeaza media pagini/s pe ~5 minute.
#
#   PAGING_PAGES_S_MAX=100  (implicit)
#     Masurat pe capacity_samples (2026-10-09..21, 33k esantioane la ~31 s),
#     cu suma |variatiei swap| pe 300 s ca margine inferioara a ritmului brut:
#     sub 100 pagini/s raman doar salturi izolate de 8-15 MB (<= ~13 pagini/s
#     pe 5 min, zilnic); peste, 12 episoade in 12 zile, fiecare cu >= ~117 MB
#     miscati in 5 min, inclusiv cele trei din ultimele 24 h (doua dintre cele 12
#     sunt scaderi bruste de 720-800 MB intr-un singur esantion - swapoff sau
#     repornire, nu paginare - deci numarul e un plafon). Intre 50 si 250
#     numarul de episoade se schimba doar 14 -> 10: pragul nu e sensibil.
#     Paginarea de pe gazda vine in rafale de 30-65 s (ex.: 560 MB intr-un
#     minut), nu in platouri: de aceea e o MEDIE pe fereastra, nu "N rulari la
#     rand peste prag", care ar fi ratat toate cele trei evenimente.
#     Contoarele din /proc/vmstat de pe gazda dau in medie 3,3 pagini/s
#     (brut, pe 2,7 zile, rafalele incluse), deci in afara rafalelor ritmul real e ~0.
#
# Prima rulare dupa instalare (sau dupa repornire, sau dupa o pauza lunga) NU are
# un esantion anterior: nu alerteaza si nu raporteaza niciun ritm. Cat timp nu
# exista istoric de cel putin PAGING_MIN_SPAN_S, verificarea e "fara verdict" -
# NU "sanatoasa": o problema deja semnalata ramane semnalata, nu se declara
# rezolvata din lipsa de date. Cu timerul de 60 s, verdictul apare la a treia
# rulare (tests/security/test_vps_watchdog.py tine legatura asta).
#
# Contoarele care scad (repornire) sau ceasul dat inapoi arunca istoricul.
#
# ---------------------------------------------------------------------------
# 3. RAM disponibil: pragul 1200 MB (MEM_AVAIL_MIN_MB), nu 400.
#
# Gazda are 7680 MB. Pragul de 400 MB nu s-a atins NICIODATA: minimul din
# 2026-10-20 a fost 809 MB, la care swap-ul era la 36%. Pe 12-19 octombrie
# minimul a fost 1642 MB; 1200 e de 1,48 ori peste 809 si cu 27% sub 1642, deci
# vede un eveniment ca cel real fara sa sune pe zilele normale. Intre pragurile
# 900/1000/1200/1500 are cele mai putine episoade pe date (4, fata de 59/29/13):
# adica cele mai putine perechi nou/rezolvat. Se schimba in conf pe o gazda cu
# alta memorie.
#
# ---------------------------------------------------------------------------
# 4. "Nu pot citi" nu e "e bine".
#
# O masuratoare ilizibila (df, /proc/meminfo, /proc/loadavg, /proc/vmstat) da o
# problema `unk:*` si pastreaza starea anterioara a verificarii. Versiunea
# veche inlocuia valoarea lipsa cu una sanatoasa (disc 0%, RAM 99999 MB).
# Valorile invalide din conf se raporteaza (`sys:config:*`), nu se ignora tacut.
#
# Auto-remedierea containerelor (sectiunea docker) e neschimbata fata de
# versiunea de dinainte: aceleasi reguli, aceleasi plafoane.
set -uo pipefail

# Caile se pot muta doar prin mediu - pentru teste, nu pentru operare. Unitatea
# systemd nu seteaza nimic din ele.
SECRETS="${WATCHDOG_SECRETS:-/etc/sentinel/secrets.env}"
CONF="${WATCHDOG_CONF:-/etc/sentinel/vps-watchdog.conf}"
STATE_DIR="${WATCHDOG_STATE_DIR:-/opt/vps-watchdog/state}"
PROC="${WATCHDOG_PROC:-/proc}"

STATE="$STATE_DIR/problems.state"; SEEDED="$STATE_DIR/.seeded"; FIXDIR="$STATE_DIR/fix"
RING="$STATE_DIR/vmstat.ring"
mkdir -p "$STATE_DIR" "$FIXDIR"

# Valori implicite. Se pot suprascrie din conf (doar cele din lista de mai jos).
AUTO_FIX=1; MAX_FIX=3; UNHEALTHY_STREAK=2; EXCLUDE_AUTOFIX="root-app-1"
DISK_PCT_MAX=88; MEM_AVAIL_MIN_MB=1200; PAGING_PAGES_S_MAX=100; LOAD_PER_CORE_MAX=2.0
HEALTH_DOMAINS=""; CURL_TIMEOUT=10
# Constante de proiectare, nu de operare: fereastra tinta, istoricul minim fara
# de care nu dam verdict, si cat de vechi poate fi un esantion ca sa mai conteze.
PAGING_MIN_SPAN_S=120; PAGING_KEEP_S=330; PAGING_RING_MAX=8
# Chei care nu se mai emit. Se scot din starea anterioara, ca dispari lor sa nu
# apara ca "rezolvat" (swap-ul nu s-a rezolvat: pur si simplu nu mai e verificat).
RETIRED_KEYS="cap:swap"

problems=""; add(){ problems+="$1"$'\n'; }

# conf_get FISIER CHEIE -> valoarea, fara ghilimele; iese cu 1 daca fisierul nu
# se poate citi sau cheia lipseste. Nu executa nimic din fisier. Ultima aparitie
# castiga (ca la `source`); CR de la sfarsit de rand se ignora.
conf_get(){
  [ -r "$1" ] || return 1
  awk -v k="$2" -v q="'" '
    { sub(/\r$/, ""); line = $0; sub(/^[ \t]*export[ \t]+/, "", line) }
    index(line, k "=") == 1 { v = substr(line, length(k) + 2); found = 1 }
    END {
      if (!found) exit 1
      c = substr(v, 1, 1)
      if (c == "\"" || c == q) { v = substr(v, 2); i = index(v, c); if (i) v = substr(v, 1, i - 1) }
      else { sub(/[ \t]*#.*$/, "", v); sub(/[ \t]+$/, "", v) }
      print v
    }' "$1"
}

# setting NUME TIP - valoarea din conf peste cea implicita. O valoare invalida
# NU se ignora in tacere: ramane cea implicita, iar problema se vede.
setting(){
  local name="$1" kind="$2" val
  local re_int='^[0-9]+$' re_num='^[0-9]+(\.[0-9]+)?$' re_list='^[A-Za-z0-9._ -]*$'
  val=$(conf_get "$CONF" "$name") || return 0
  case "$kind" in
    int)  [[ "$val" =~ $re_int ]] ;;
    num)  [[ "$val" =~ $re_num ]] ;;
    list) [[ "$val" =~ $re_list ]] ;;
    *)    false ;;
  esac && { printf -v "$name" '%s' "$val"; return 0; }
  add "sys:config:${name}|⚙️ ${name} din ${CONF} e invalid ('${val}') - folosesc valoarea implicita"
}

if [ -e "$CONF" ] && [ ! -r "$CONF" ]; then
  add "sys:config|⚙️ Nu pot citi ${CONF} - folosesc valorile implicite, fara domenii de verificat"
fi
for s in AUTO_FIX:int MAX_FIX:int UNHEALTHY_STREAK:int DISK_PCT_MAX:int MEM_AVAIL_MIN_MB:int \
         PAGING_PAGES_S_MAX:int CURL_TIMEOUT:int LOAD_PER_CORE_MAX:num \
         HEALTH_DOMAINS:list EXCLUDE_AUTOFIX:list; do
  setting "${s%%:*}" "${s##*:}"
done

TG_TOKEN=$(conf_get "$SECRETS" TELEGRAM_BOT_TOKEN) || TG_TOKEN=""
TG_CHAT=$(conf_get "$SECRETS" TELEGRAM_CHAT_ID) || TG_CHAT=""
# Tokenul NU intra in argv (`ps` il arata oricui are cont pe gazda, iar aici se
# vorbeste cu planul de control al botului): URL-ul merge pe stdin, spre `curl -K -`.
send(){
  [ -n "$TG_TOKEN" ] && [ -n "$TG_CHAT" ] || return 0
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TG_TOKEN" \
    | curl -fsS -m 15 -K - --data-urlencode "chat_id=${TG_CHAT}" --data-urlencode "text=$1" >/dev/null 2>&1 || true
}
HOST=$(hostname -s)
in_list(){ case " $2 " in *" $1 "*) return 0;; *) return 1;; esac; }
SEED=0; [ ! -f "$SEEDED" ] && SEED=1
baseline_extra=""

# Starea anterioara, fara cheile retrase. Citita inainte de orice verificare:
# `carry` are nevoie de ea.
prev=""
[ -f "$STATE" ] && prev=$(awk -v r="$RETIRED_KEYS" '
  BEGIN { n = split(r, a, " "); for (i = 1; i <= n; i++) dead[a[i]] = 1 }
  { i = index($0, "|"); k = (i ? substr($0, 1, i - 1) : $0); if (!(k in dead)) print }' "$STATE")

# carry CHEIE - pastreaza problema din rularea trecuta, daca era una. Pentru o
# verificare care NU poate spune nimic acum: "necunoscut" nu e "rezolvat".
carry(){
  local line
  line=$(printf '%s\n' "$prev" | awk -F'|' -v k="$1" '$1 == k { print; exit }')
  [ -n "$line" ] && problems+="$line"$'\n'
  return 0
}
# unknown CHEIE-cap:* CE - nu am putut citi masuratoarea.
unknown(){
  add "unk:${1#cap:}|❔ Nu pot citi ${2} - starea (${1#cap:}) e NECUNOSCUTA, nu sanatoasa"
  carry "$1"
}

if timeout 20 docker info >/dev/null 2>&1; then
  while read -r name; do
    [ -z "$name" ] && continue
    pol=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$name" 2>/dev/null || echo "")
    case "$pol" in unless-stopped|always) ;; *) continue ;; esac
    status=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo "?")
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$name" 2>/dev/null || echo "")
    fa="$FIXDIR/$name.attempts"; fd="$FIXDIR/$name.disabled"; fu="$FIXDIR/$name.ustreak"

    # OK = running + healthy (sau fara healthcheck)
    if [ "$status" = "running" ] && { [ "$health" = "healthy" ] || [ -z "$health" ]; }; then
      if [ -f "$fd" ] || [ -f "$fa" ]; then rm -f "$fa" "$fd" "$fu"; send "✅ VPS ${HOST}: \"$name\" functional din nou (auto-fix resetat)."; else rm -f "$fu"; fi
      continue
    fi
    # PENDING = health "starting" (grace dupa pornire/restart): asteapta, nu reseta, nu reporni
    if [ "$status" = "running" ] && [ "$health" = "starting" ]; then continue; fi
    # crash-loop
    if [ "$status" = "restarting" ]; then add "ctr:$name:loop|🔁 \"$name\" in crash-loop - auto-fix NU reporneste crash-loop, necesita investigatie"; continue; fi
    # broken
    if [ "$status" = "running" ]; then brk="unhealthy"; else brk="down ($status)"; fi
    if in_list "$name" "$EXCLUDE_AUTOFIX"; then add "ctr:$name:excl|⛔ \"$name\" $brk (auto-fix exclus - manual)"; continue; fi
    if [ -f "$fd" ]; then add "ctr:$name:disabled|⛔ \"$name\" $brk (auto-fix dezactivat dupa esecuri - manual)"; continue; fi
    if [ "$SEED" = 1 ]; then baseline_extra+="• \"$name\" $brk (se va remedia automat)"$'\n'; continue; fi
    if [ "$AUTO_FIX" != 1 ]; then add "ctr:$name:brk|⚠️ \"$name\" $brk"; continue; fi
    # unhealthy: cere streak consecutiv
    if [ "$status" = "running" ]; then
      us=$(cat "$fu" 2>/dev/null || echo 0); us=$((us+1)); echo "$us" > "$fu"
      if [ "$us" -lt "$UNHEALTHY_STREAK" ]; then send "⚠️ VPS ${HOST}: \"$name\" unhealthy - urmaresc; repornesc daca persista."; continue; fi
    fi
    at=$(cat "$fa" 2>/dev/null || echo 0); at=$((at+1)); echo "$at" > "$fa"
    if [ "$at" -gt "$MAX_FIX" ]; then touch "$fd"; send "⛔ VPS ${HOST}: \"$name\" inca $brk dupa ${MAX_FIX} reporniri - auto-fix DEZACTIVAT, necesita interventie manuala."; continue; fi
    if docker restart "$name" >/dev/null 2>&1; then r=ok; else r=ESEC; fi
    rm -f "$fu"   # reset streak dupa restart (urmatorul restart cere iar 2 unhealthy)
    sleep 3
    ns=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo "?")
    send "🔧 VPS ${HOST} auto-remediere: \"$name\" era $brk → restart ($at/${MAX_FIX}, $r). Status acum: $ns."
  done < <(docker ps -a --format '{{.Names}}')
else
  add "sys:docker|🔴 Docker daemon nu raspunde"
fi

# --- paginare ---------------------------------------------------------------
# Vezi antetul, sectiunea 2. Scrie istoricul in $RING (atomic) si adauga
# cap:paging doar la un verdict HIGH.
check_paging(){
  local pin pout now res verdict rate span
  pin=$(awk '$1 == "pswpin" { print $2; exit }' "$PROC/vmstat" 2>/dev/null)
  pout=$(awk '$1 == "pswpout" { print $2; exit }' "$PROC/vmstat" 2>/dev/null)
  now=$(date +%s)
  if ! [[ "$pin" =~ ^[0-9]+$ && "$pout" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]]; then
    unknown cap:paging "pswpin/pswpout din $PROC/vmstat"; return 0
  fi
  local src="$RING"; [ -f "$src" ] || src=/dev/null
  res=$(awk -v now="$now" -v cin="$pin" -v cout="$pout" -v keep="$PAGING_KEEP_S" \
            -v minspan="$PAGING_MIN_SPAN_S" -v maxn="$PAGING_RING_MAX" -v thr="$PAGING_PAGES_S_MAX" '
    BEGIN { n = 0 }
    NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { t[n] = $1 + 0; pi[n] = $2 + 0; po[n] = $3 + 0; n++ }
    END {
      # Contoare mai mari decat cele de acum, esantion din viitor sau istoric
      # necrescator: repornire sau ceas dat inapoi. Istoricul nu mai spune nimic.
      reset = 0
      for (i = 0; i < n; i++) {
        if (t[i] > now || pi[i] > cin || po[i] > cout) reset = 1
        if (i > 0 && (t[i] < t[i-1] || pi[i] < pi[i-1] || po[i] < po[i-1])) reset = 1
      }
      m = 0
      if (!reset) for (i = 0; i < n; i++) if (now - t[i] <= keep) { kt[m] = t[i]; ki[m] = pi[i]; ko[m] = po[i]; m++ }
      kt[m] = now; ki[m] = cin; ko[m] = cout; m++
      first = (m > maxn) ? m - maxn : 0
      span = now - kt[first]; rate = 0; verdict = "NONE"
      if (span >= minspan) { rate = ((cin - ki[first]) + (cout - ko[first])) / span; verdict = (rate >= thr) ? "HIGH" : "OK" }
      printf "%s %.0f %.0f\n", verdict, rate, span
      for (i = first; i < m; i++) printf "%.0f %.0f %.0f\n", kt[i], ki[i], ko[i]
    }' "$src") || res=""
  if [ -z "$res" ]; then unknown cap:paging "istoricul de paginare (awk a esuat)"; return 0; fi
  if ! printf '%s\n' "$res" | tail -n +2 > "$RING.tmp" || ! mv -f "$RING.tmp" "$RING"; then
    unknown cap:paging "istoricul de paginare (nu pot scrie $RING)"; return 0
  fi
  read -r verdict rate span <<< "$(printf '%s\n' "$res" | head -n 1)"
  case "$verdict" in
    HIGH) add "cap:paging|📄 Paginare swap ~${rate} pagini/s (media pe ${span}s, prag ${PAGING_PAGES_S_MAX}/s)" ;;
    OK)   ;;
    *)    carry cap:paging ;;   # fara istoric suficient: nu stim, deci nu declaram rezolvat
  esac
}

# --- capacitate -------------------------------------------------------------
disk=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -z "$disk" ]; then unknown cap:disk "ocuparea discului /"
elif [ "$disk" -ge "$DISK_PCT_MAX" ]; then add "cap:disk|💽 Disk / la ${disk}% (prag ${DISK_PCT_MAX}%)"; fi

mem=$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024; exit }' "$PROC/meminfo" 2>/dev/null)
if ! [[ "$mem" =~ ^[0-9]+$ ]]; then unknown cap:mem "MemAvailable din $PROC/meminfo"
elif [ "$mem" -lt "$MEM_AVAIL_MIN_MB" ]; then add "cap:mem|🧠 RAM disponibil ${mem}MB (prag ${MEM_AVAIL_MIN_MB}MB)"; fi

check_paging

cores=$(nproc); load1=$(awk '{ print $1; exit }' "$PROC/loadavg" 2>/dev/null)
if ! [[ "$load1" =~ ^[0-9]+(\.[0-9]+)?$ && "$cores" =~ ^[0-9]+$ ]]; then unknown cap:load "load-ul din $PROC/loadavg"
elif awk -v l="$load1" -v c="$cores" -v m="$LOAD_PER_CORE_MAX" 'BEGIN{exit !(l > c*m)}'; then
  add "cap:load|📈 Load1 ${load1} (>${LOAD_PER_CORE_MAX}x${cores} core)"
fi

# `curl -w` scrie singur 000 cand conexiunea cade; un `|| echo 000` dupa el dubla
# valoarea in "000000" si verificarea nu mai putea suna niciodata.
for d in $HEALTH_DOMAINS; do
  code=$(curl -s -o /dev/null -m "$CURL_TIMEOUT" -w '%{http_code}' "https://$d/api/health" 2>/dev/null || true)
  [ -n "$code" ] || code=000
  [ "$code" = "000" ] && add "net:$d|🌐 $d nu raspunde"
done

# --- diferenta pe identitate ------------------------------------------------
# Un singur rand per cheie (primul castiga), fara randuri goale.
cur=$(printf '%s' "$problems" | awk 'NF { i = index($0, "|"); k = (i ? substr($0, 1, i - 1) : $0); if (!(k in s)) { s[k] = 1; print } }')
printf '%s\n' "$cur" | sed '/^$/d' > "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"
if [ "$SEED" = 1 ]; then
  touch "$SEEDED"; n=$(printf '%s\n' "$cur" | sed '/^$/d' | grep -c . || true)
  msg="🛡️ VPS watchdog FAZA 2 activ pe ${HOST} (verificare 1 min). Probleme (alerta): ${n}"
  [ "$n" -gt 0 ] && msg+=$'\n'"$(printf '%s\n' "$cur" | sed '/^$/d' | cut -d'|' -f2-)"
  [ -n "$baseline_extra" ] && msg+=$'\n'"Remediabile automat:"$'\n'"${baseline_extra}"
  send "$msg"; exit 0
fi
# lines_missing_from A B - randurile din A a caror CHEIE nu apare in B.
lines_missing_from(){
  awk 'function key(l,  i) { i = index(l, "|"); return i ? substr(l, 1, i - 1) : l }
       NR == FNR { if ($0 != "") seen[key($0)] = 1; next }
       $0 != "" && !(key($0) in seen)' "$2" "$1"
}
newp=$(lines_missing_from <(printf '%s\n' "$cur") <(printf '%s\n' "$prev"))
resp=$(lines_missing_from <(printf '%s\n' "$prev") <(printf '%s\n' "$cur"))
[ -n "$newp" ] && send "🚨 VPS ${HOST} - problema noua:"$'\n'"$(printf '%s\n' "$newp" | sed '/^$/d' | cut -d'|' -f2-)"
[ -n "$resp" ] && send "✅ VPS ${HOST} - rezolvat:"$'\n'"$(printf '%s\n' "$resp" | sed '/^$/d' | cut -d'|' -f2-)"
exit 0
