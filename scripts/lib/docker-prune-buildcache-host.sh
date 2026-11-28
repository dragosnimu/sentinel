#!/usr/bin/env bash
#
# Partea de pe gazdă a scripts/docker-prune-buildcache.sh. Nu se rulează de mână: lansatorul o trimite pe stdin într-un
# `sudo -n bash -s -- OPERAȚIE` și nu lasă nimic pe disc.
#
#   snapshot   doar citire. Tipărește starea ca linii `CHEIE=valoare` / `TIP câmpuri`, încheiate cu `SNAPSHOT_END`:
#                DOCKER_SERVER=, DOCKER_ROOT=, DF <octeți-total> <folosiți> <liberi>   (sistemul de fișiere al DockerRootDir)
#                BUILDX=absent | BUILDX=present, BUILDER <nume> <driver> <1 dacă e cel curent>
#                BC_COUNT=N, BCENTRY <id> <1 dacă e în uz> <octeți> <1 dacă e partajat cu o imagine>   (câte una pe intrare)
#                IMAGE <id-complet> <depozit:etichetă>, VOLUME <nume>
#   prune      reface verificările, REFUZĂ dacă builderul curent nu e cel implicit (driver `docker`), apoi rulează EXACT
#              `docker builder prune -a -f` și tipărește codul lui. Nimic altceva: nu atinge imagini, containere, volume, rețele.
#
# De ce intrările de cache vin din API-ul daemonului (`GET /system/df`) și nu din `docker system df`: acela rotunjește la 10 MB și nu
# dă identificatori. Cu identificatori, lansatorul dovedește EFECTUL (intrările care existau înainte și nu mai există după), nu o
# diferență de două numere rotunjite, pe care o construcție care rulează în paralel ar putea s-o ascundă. Verificat pe gazdă (doar citire,
# 28 nov 2026, de verificator): suma TUTUROR intrărilor (Size) = 95923809987 B se potrivește cu coloana SIZE a lui `docker system df`
# («95.92GB»), iar suma intrărilor cu InUse=false ȘI Shared=false = 87010959009 B este EXACT coloana RECLAIMABLE. Cele 763 de intrări
# Shared=true (8912850978 B) țin straturi ale imaginilor: docker nu le numără ca eliberabile, deci nici lansatorul.
#
# Codurile de ieșire (lansatorul le traduce): 0 = ok; 2 = operație necunoscută; 11 = daemonul docker nu răspunde; 12 = docker nu e
# instalat; 13 = n-am putut MĂSURA (lipsește curl/python3, API-ul n-a răspuns, răspunsul nu are forma așteptată) — nu e «bine»;
# 14 = REFUZ: builderul curent nu e cel implicit, iar `docker builder prune` ar curăța altceva decât ce măsurăm; 15 = docker
# builder prune a ieșit cu cod nenul.
#
# Nu folosim `set -e`: fiecare cod de ieșire de mai sus e decis explicit. Fiecare comandă care poate eșua are stderr-ul LĂSAT să
# curgă (ajunge la operator); singurul `>/dev/null` e pe `command -v`, care nu scrie nimic pe stderr.

set -uo pipefail

DOCKER_SOCK=/var/run/docker.sock

say() { printf '%s\n' "$*"; }
bad() { printf '[x] %s\n' "$*" >&2; }
have() { command -v "$1" > /dev/null; }

# Programele Python sunt în variabile, nu pe stdin: stdin-ul e chiar scriptul acesta, citit de `bash -s`, și orice proces care îl
# citește i-ar mânca restul. Doar Python 3.6+ (gazda are 3.9).
PY_BUILDCACHE='
import json, re, sys
d = json.load(sys.stdin)
if not isinstance(d, dict) or "BuildCache" not in d:
    sys.exit("raspunsul /system/df nu are cheia BuildCache (forma API-ului s-a schimbat?)")
rows = d["BuildCache"] or []
print("BC_COUNT=%d" % len(rows))
for r in rows:
    i = r["ID"]
    if not re.match(r"^[A-Za-z0-9._-]+$", i):
        sys.exit("identificator de cache neasteptat: %r" % (i,))
    if not isinstance(r["InUse"], bool):
        sys.exit("InUse nu e boolean pentru %s" % i)
    if not isinstance(r["Shared"], bool):
        sys.exit("Shared nu e boolean pentru %s" % i)
    print("BCENTRY %s %d %d %d" % (i, 1 if r["InUse"] else 0, int(r["Size"]), 1 if r["Shared"] else 0))
'
PY_BUILDERS='
import json, re, sys
objs = []
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if line:
        o = json.loads(line)
        objs.extend(o if isinstance(o, list) else [o])
if not objs:
    sys.exit("buildx ls nu a raportat niciun builder")
for o in objs:
    n, drv = o["Name"], o["Driver"]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", n) or not re.match(r"^[A-Za-z0-9._-]+$", drv):
        sys.exit("nume sau driver de builder neasteptat: %r %r" % (n, drv))
    print("BUILDER %s %s %d" % (n, drv, 1 if o.get("Current") else 0))
'

# Setează DOCKER_SERVER. 11/12/13 după felul în care lipsește ceva.
preflight() {
    have docker || { bad "docker nu e instalat (sau nu e în PATH-ul lui sudo)"; return 12; }
    have curl && have python3 || { bad "pe gazdă lipsește curl sau python3: nu pot măsura exact cache-ul de build"; return 13; }
    DOCKER_SERVER="$(docker version --format '{{.Server.Version}}' < /dev/null)" \
        || { bad "daemonul docker nu răspunde (docker version a eșuat; mesajul lui e mai sus)"; return 11; }
    [[ -n "$DOCKER_SERVER" ]] || { bad "docker version n-a dat versiunea serverului"; return 11; }
    return 0
}

# Tipărește liniile BUILDX=/BUILDER în BUILDERS_OUT. Fără plugin buildx nu pot exista alți builderi, iar `docker builder prune` vorbește
# direct cu daemonul; cu plugin, cere `buildx ls` să răspundă și să existe exact un builder curent.
collect_builders() {
    local bx_ver bx_json cur
    BUILDERS_OUT=""
    if ! bx_ver="$(docker buildx version 2>&1 < /dev/null)"; then
        BUILDERS_OUT="BUILDX=absent"
        return 0
    fi
    bx_json="$(docker buildx ls --format json < /dev/null)" || { bad "docker buildx ls a eșuat (mesajul lui e mai sus)"; return 13; }
    BUILDERS_OUT="$(printf '%s\n' "$bx_json" | python3 -I -c "$PY_BUILDERS")" || { bad "n-am putut citi lista de buildere"; return 13; }
    cur="$(printf '%s\n' "$BUILDERS_OUT" | awk '$1 == "BUILDER" && $4 == 1 { n++ } END { print n + 0 }')"
    [[ "$cur" == 1 ]] || { bad "buildx ls nu arată exact un builder curent (arată ${cur})"; return 13; }
    BUILDERS_OUT="BUILDX=present"$'\n'"${BUILDERS_OUT}"
    return 0
}

# Reface verificarea chiar înainte de prune, în ACELAȘI apel ssh (fără fereastră între o măsurătoare și cealaltă).
builder_guard() {
    local line name drv cur
    collect_builders || return $?
    [[ "$BUILDERS_OUT" == "BUILDX=absent" ]] && return 0
    line="$(printf '%s\n' "$BUILDERS_OUT" | awk '$1 == "BUILDER" && $4 == 1')"
    read -r _ name drv cur <<< "$line"
    if [[ "$name" != default || "$drv" != docker ]]; then
        bad "REFUZ: builderul curent al lui root e «${name}» (driver ${drv}), nu «default» (driver docker). \`docker builder prune\` ar curăța cache-ul LUI, nu pe cel al daemonului pe care îl măsurăm, iar efectul n-ar fi dovedit."
        return 14
    fi
    return 0
}

take_snapshot() {
    local df_json bc root df_line df_size df_used df_avail images volumes out
    preflight || return $?
    df_json="$(curl -sS --fail --max-time 300 --unix-socket "$DOCKER_SOCK" http://localhost/system/df < /dev/null)" \
        || { bad "GET /system/df pe ${DOCKER_SOCK} a eșuat (mesajul curl e mai sus)"; return 13; }
    bc="$(printf '%s' "$df_json" | python3 -I -c "$PY_BUILDCACHE")" || { bad "n-am putut citi cache-ul de build din răspunsul /system/df"; return 13; }
    collect_builders || return $?
    root="$(docker info --format '{{.DockerRootDir}}' < /dev/null)" || { bad "docker info a eșuat"; return 13; }
    [[ "$root" == /* ]] || { bad "DockerRootDir neașteptat: '${root}'"; return 13; }
    df_line="$(df -B1 --output=size,used,avail -- "$root" < /dev/null | tail -n 1)" || { bad "df pe ${root} a eșuat"; return 13; }
    [[ "$df_line" =~ ^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]*$ ]] || { bad "df a dat o linie neașteptată: '${df_line}'"; return 13; }
    images="$(docker image ls -a --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' < /dev/null)" || { bad "docker image ls a eșuat"; return 13; }
    volumes="$(docker volume ls -q < /dev/null)" || { bad "docker volume ls a eșuat"; return 13; }

    read -r df_size df_used df_avail <<< "$df_line"
    out="DOCKER_SERVER=${DOCKER_SERVER}"$'\n'"DOCKER_ROOT=${root}"$'\n'"DF ${df_size} ${df_used} ${df_avail}"$'\n'"${BUILDERS_OUT}"$'\n'"${bc}"$'\n'
    [[ -z "$images" ]] || out+="$(printf '%s\n' "$images" | LC_ALL=C sort -u | sed 's/^/IMAGE /')"$'\n'
    [[ -z "$volumes" ]] || out+="$(printf '%s\n' "$volumes" | LC_ALL=C sort -u | sed 's/^/VOLUME /')"$'\n'
    printf '%s' "$out"
    say "SNAPSHOT_END"
}

do_prune() {
    local rc
    preflight || return $?
    builder_guard || return $?
    say "PRUNE_START"
    docker builder prune -a -f < /dev/null 2>&1
    rc=$?
    say "PRUNE_DOCKER_RC=${rc}"
    (( rc == 0 )) || return 15
    return 0
}

main() {
    if [[ $# -ne 1 ]]; then bad "o singură operație: snapshot | prune"; return 2; fi
    case "$1" in
        snapshot) take_snapshot ;;
        prune)    do_prune ;;
        *)        bad "operație necunoscută: '$1' (snapshot | prune)"; return 2 ;;
    esac
}

main "$@"
exit $?
