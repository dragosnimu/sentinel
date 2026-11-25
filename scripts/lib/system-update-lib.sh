#!/usr/bin/env bash
#
# Deciziile pure ale lui scripts/lib/system-update-host.sh — fără nicio atingere
# a gazdei. Încărcat cu `source`; nu rulează nimic și nu setează opțiuni de shell.
#
# De ce sunt într-un fișier separat: tot ce poate minți într-o actualizare de
# sistem e o DECIZIE luată dintr-o măsurătoare («e sănătos?», «dump-ul e complet?»,
# «codul de pe disc e cel care rulează?»), nu comanda în sine. Decizia, scoasă din
# fișierul care rulează dnf și docker, se poate proba fără gazdă — vezi
# tests/unit/test_system_update_lib.py. Fiecare funcție primește măsurătorile ca
# argumente și răspunde cu UN cuvânt (sau un cod de ieșire), niciodată cu „bine"
# prin tăcere.
#
# Trei stări, peste tot: măsurat și bine / măsurat și rău / **n-am putut măsura**.
# A treia nu e niciuna din primele două. De aceea fiecare funcție de mai jos are un
# cuvânt `unknown` (sau cod 2), iar apelantul nu are voie să-l citească ca «ok».
#
# Formele de ieșire de care depind verificările de dump au fost MĂSURATE pe gazdă
# pe 19 noiembrie 2026 (doar citire — dump către stdout, fără scriere pe disc):
#
#   pg_dumpall (PostgreSQL 16, imaginea postgres:16-alpine) se termină cu
#       \unrestrict <cheie>
#       (linie goală)
#       --
#       -- PostgreSQL database cluster dump complete
#       --
#       (linie goală)
#     adică marcajul NU e ultima linie, iar `\unrestrict` (adăugat de versiunile
#     din august 2025 încoace) vine ÎNAINTEA lui. Un `tail -n 1 | grep complete`
#     ar fi declarat «dump incomplet» pe fiecare dump sănătos.
#   mariadb-dump 11.4 se termină cu `-- Dump completed on AAAA-LL-ZZ HH:MM:SS`,
#     prima linie e `/*M!999999\- enable the sandbox mode */`, iar `-- MariaDB dump`
#     vine pe a doua.

# ---------------------------------------------------------------------------
# Nucleu și repornire
# ---------------------------------------------------------------------------

# su_kernel_matches_default RUNNING DEFAULT
#   0  nucleul care RULEAZĂ e cel pe care gazda îl va porni implicit
#   1  diferă
#   2  una dintre ele nu s-a putut citi (nu e «la fel»)
# DEFAULT e ieșirea lui `grubby --default-kernel`: o cale /boot/vmlinuz-<versiune>.
su_kernel_matches_default() {
    local running="${1:-}" def="${2:-}"
    [[ -n "$running" && -n "$def" ]] || return 2
    def="${def##*/}"
    def="${def#vmlinuz-}"
    [[ "$running" == "$def" ]]
}

# `needs-restarting -r`: 1 = repornire necesară, 0 = nu. Orice altceva (comandă
# lipsă, 127; eroare de rpm) NU e «nu e nevoie» — e necunoscut.
su_reboot_needed_from_rc() {
    case "${1:-}" in
        0) echo no ;;
        1) echo yes ;;
        *) echo unknown ;;
    esac
}

# `dnf check-update`: 0 = nimic de actualizat, 100 = există actualizări, restul = eroare
# (1: depozit inaccesibil, cache lipsă). O eroare nu e «nu a rămas nimic».
su_check_update_state() {
    case "${1:-}" in
        0)   echo none ;;
        100) echo pending ;;
        *)   echo error ;;
    esac
}

# ---------------------------------------------------------------------------
# Gestionarul de pachete (dnf pe familia RHEL, apt pe Debian/Ubuntu)
# ---------------------------------------------------------------------------
# Formele de ieșire de mai jos (apt-get -s, grub.cfg, history.log, dpkg-query) sunt MĂSURATE pe n8n.srv1051579.hstgr.cloud
# (Ubuntu 24.04, apt 2.8.4) pe 24 noiembrie 2026, doar citire. Fiecare funcție e o decizie pură: măsurătoarea vine ca argument sau pe stdin.

# su_pkgmgr_family ID ID_LIKE — familia după /etc/os-release: apt | dnf | unknown.
# O gazdă care se declară în ambele familii, ori în niciuna cunoscută (SUSE, Alpine, Arch), e `unknown`: nu se ghicește.
su_pkgmgr_family() {
    local id="${1:-}" like="${2:-}" w apt=0 dnf=0
    id="${id,,}"; like="${like,,}"
    for w in $id $like; do
        case "$w" in
            debian|ubuntu|raspbian|linuxmint|pop) apt=1 ;;
            rhel|centos|fedora|almalinux|rocky|ol|amzn) dnf=1 ;;
        esac
    done
    if (( apt && ! dnf )); then echo apt
    elif (( dnf && ! apt )); then echo dnf
    else echo unknown
    fi
}

# su_pkgmgr_decide FAMILIE ARE_DNF ARE_APT — apt | dnf | unknown | no-binary.
# Familia din os-release SPUNE ce gestionar are gazda; binarul trebuie să existe și el. O familie apt pe care lipsește apt-get (sau una dnf fără dnf)
# e `no-binary`, nu «folosesc celălalt»: două surse care nu se potrivesc nu se rezolvă prin alegerea uneia.
su_pkgmgr_decide() {
    case "${1:-}" in
        apt) [[ "${3:-0}" == 1 ]] && echo apt || echo no-binary ;;
        dnf) [[ "${2:-0}" == 1 ]] && echo dnf || echo no-binary ;;
        *)   echo unknown ;;
    esac
}

# su_apt_sim_names KIND < ieșirea lui `apt-get -s` — numele pachetelor de pe liniile `Inst` / `Remv`.
su_apt_sim_names() {
    awk -v k="${1:-Inst}" '$1 == k { print $2 }' | LC_ALL=C sort -u
}

# su_apt_kept_back < ieșirea lui `apt-get -s` — pachetele din secțiunea «kept back» (pe hold, în fază sau blocate de dependențe).
su_apt_kept_back() {
    awk '/^The following packages? (have been|was) kept back:/ { on = 1; next }
         on && /^[[:space:]]/ { for (i = 1; i <= NF; i++) print $i; next }
         { on = 0 }' | LC_ALL=C sort -u
}

# su_apt_kernel_pending < ieșirea lui `apt-get -s` — 0 dacă simularea INSTALEAZĂ un pachet linux-image-<versiune>.
su_apt_kernel_pending() {
    awk '$1 == "Inst" && $2 ~ /^linux-image-[0-9]/ { f = 1 } END { exit !f }'
}

# su_apt_pkglist < `dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}=${Version}\n'` — doar pachetele INSTALATE (ii, hi), sortate.
# Un pachet scos dar cu fișiere de configurare rămase (`rc`) nu e instalat și nu intră în comparația dinainte/după.
su_apt_pkglist() {
    awk -F'|' '$1 ~ /^[hi]i/ && $2 != "" { print $2 }' | LC_ALL=C sort
}

# su_apt_unclean < `dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}\n'` — pachetele a căror stare NU e una stabilă:
# ii (instalat), hi (instalat, pe hold), un/pn (necunoscut/purjat), rc (scos, configurația a rămas). Orice altceva (iU despachetat, iF configurat pe
# jumătate, iH instalat pe jumătate, iW/it în așteptarea declanșatoarelor, ri…) înseamnă că dpkg a lăsat ceva neterminat.
su_apt_unclean() {
    awk -F'|' '$1 !~ /^(ii|hi|un|pn|rc) ?$/ && $1 != "" { print $1 "|" $2 }'
}

# su_apt_kernel_versions FLAVOR < `dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\n' 'linux-image-[0-9]*'`
# — versiunile INSTALATE (nu `deinstall … config-files`: gazda de test are 25 de linii de felul ăsta) ale variantei de nucleu care rulează (`-generic`).
su_apt_kernel_versions() {
    awk -F'|' -v fl="${1:-}" '$1 ~ /^[hi]i/ && $2 ~ /^linux-image-[0-9]/ { v = $2; sub(/^linux-image-/, "", v); if (fl == "" || v ~ ("-" fl "$")) print v }'
}

# su_grub_default_is_first VALOARE — GRUB_DEFAULT arată prima intrare (gol sau 0)? 0 da, 1 nu (saved, un id, un număr).
# Doar atunci prima intrare din grub.cfg e nucleul care pornește; altfel NU știm care e, și spunem asta.
su_grub_default_is_first() {
    local v="${1:-}"
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    [[ -z "$v" || "$v" == 0 ]]
}

# su_apt_grub_default_kernel < grub.cfg — /boot/vmlinuz-<versiune> din PRIMA intrare de nivel superior (nu din submeniul «Advanced options»).
# 1 dacă nu se găsește o linie `linux` cu un fișier vmlinuz-* înainte de a doua intrare ori de submeniu.
su_apt_grub_default_kernel() {
    awk '/^menuentry[[:space:]]/ { if (seen) exit; seen = 1; next }
         /^submenu[[:space:]]/ { exit }
         seen && ($1 == "linux" || $1 == "linuxefi") { n = $2; sub(/.*\//, "", n); if (n ~ /^vmlinuz-/) { print "/boot/" n; found = 1 } exit }
         END { exit !found }'
}

# su_apt_reboot_state FIȘIER_EXISTĂ CÂRLIG_EXISTĂ — yes | no | unknown.
# /var/run/reboot-required îl scrie cârligul pachetului update-notifier-common la fiecare instalare care cere reboot. Fișierul PREZENT = reboot
# necesar. Fișierul ABSENT dovedește «nu» doar dacă cârligul care l-ar fi scris există: fără el, absența nu înseamnă nimic (Debian de bază nu-l are).
su_apt_reboot_state() {
    if [[ "${1:-0}" == 1 ]]; then echo yes
    elif [[ "${2:-0}" == 1 ]]; then echo no
    else echo unknown
    fi
}

# su_apt_history_verdict ÎNAINTE DUPĂ ULTIMUL — ce spune /var/log/apt/history.log despre rularea de acum.
#   ÎNAINTE/DUPĂ = numărul de blocuri `Start-Date:`; ULTIMUL = ok | unfinished | error | ? (starea ultimului bloc).
#   none | new-ok | new-unfinished | new-error | unknown
su_apt_history_verdict() {
    local b="${1:-}" a="${2:-}" last="${3:-?}"
    [[ "$b" =~ ^[0-9]+$ && "$a" =~ ^[0-9]+$ ]] || { echo unknown; return 0; }
    (( a >= b )) || { echo unknown; return 0; }    # jurnalul s-a rotit între cele două citiri
    (( a > b )) || { echo none; return 0; }
    case "$last" in
        ok)         echo new-ok ;;
        unfinished) echo new-unfinished ;;
        error)      echo new-error ;;
        *)          echo unknown ;;
    esac
}

# ---------------------------------------------------------------------------
# Containere
# ---------------------------------------------------------------------------

# su_health_class STATE HEALTH — starea unui container, într-un cuvânt:
#   healthy | unhealthy | starting | none (rulează, fără healthcheck) | down | unknown
# `down` = orice STATE în afară de `running` (exited, restarting, created, paused,
# dead, lipsă). `restarting` e `down` dinadins: un container în buclă trece prin
# `running` la fiecare ciclu, iar o verificare făcută o dată l-ar prinde exact acolo.
su_health_class() {
    local state="${1:-}" health="${2:-}"
    [[ "$state" == running ]] || { echo down; return 0; }
    case "$health" in
        healthy)   echo healthy ;;
        unhealthy) echo unhealthy ;;
        starting)  echo starting ;;
        ""|none)   echo none ;;
        *)         echo unknown ;;
    esac
}

# su_container_verdict BASE_STATE BASE_HEALTH NOW_STATE NOW_HEALTH
#   skip      nu rula la baseline — nu e treaba noastră să-l pornim
#   ok        la fel de bine sau mai bine
#   same-bad  e rău, dar era rău și la baseline (bet-calculator: unhealthy înainte de orice)
#   worse     mai rău decât la baseline
#   pending   încă `starting`: nu e verdict, e „mai așteaptă"
#   unknown   n-am cum să compar (healthcheck-ul a dispărut, valoare necunoscută)
# «Nu mai rău decât baseline», nu «totul sănătos»: o cerere de «tot healthy» ar fi
# roșie azi pe un container care era deja unhealthy, adică fix alarma care învață
# operatorul să nu mai citească raportul.
su_container_verdict() {
    local b n
    b="$(su_health_class "${1:-}" "${2:-}")"
    n="$(su_health_class "${3:-}" "${4:-}")"
    [[ "$b" == down ]] && { echo skip; return 0; }
    case "$n" in
        down)      echo worse ;;
        starting)  echo pending ;;
        unknown)   echo unknown ;;
        unhealthy) if [[ "$b" == unhealthy ]]; then echo same-bad; else echo worse; fi ;;
        healthy)   echo ok ;;
        none)
            # Fără healthcheck acum: dacă înainte avea unul, nu mai putem spune nimic
            # despre sănătate — nu e «ok».
            case "$b" in
                healthy|unhealthy) echo unknown ;;
                *)                 echo ok ;;
            esac ;;
    esac
}

# su_flap_verdict SAMPLE1 SAMPLE2 UPSTATE — două eșantioane `stare|numărătoare|marcaj`
# luate la distanță. stable | flapping | down.
# Un serviciu sau un container activ O DATĂ nu e dovadă că rămâne pornit: o buclă
# de repornire trece prin `active` la fiecare ciclu. Același număr de reporniri și
# același marcaj de intrare în starea activă, la ambele eșantioane, e ce se cere.
su_flap_verdict() {
    local s1="${1:-}" s2="${2:-}" up="${3:-active}"
    [[ "${s1%%|*}" == "$up" && "${s2%%|*}" == "$up" ]] || { echo down; return 0; }
    if [[ "$s1" == "$s2" ]]; then echo stable; else echo flapping; fi
}

# su_classify_db IMAGE ARGV... — ce fel de container e, după CE RULEAZĂ, nu după nume.
#   postgres | mariadb | sidecar | unclear | other
# Pe gazdă, `nis2-backup` și `oferte-backup` au imaginea postgres:16-alpine, ca bazele
# lor, dar rulează `sh -c 'pg_dump ... | gzip'`: nu sunt servere. Un dump făcut pe
# ele ar eșua, iar o regulă «imagine de postgres = bază» ar cere dump-uri unor
# containere fără bază.
#   * ARGV = Entrypoint urmat de Cmd, despărțite pe spații; contează primele două cuvinte;
#   * un server se recunoaște după binarul pornit (direct sau prin docker-entrypoint.sh),
#     indiferent de numele imaginii — o imagine proprie care rulează `postgres` e tot bază;
#   * o imagine de bază de date a cărei comandă nu e nici server, nici shell e `unclear`:
#     «nu pot decide» nu e «nu e bază», iar apelantul îl tratează ca eșec.
su_classify_db() {
    local image="${1:-}"; shift || true
    local b0 b1 first base
    b0="${1:-}"; b0="${b0##*/}"
    b1="${2:-}"; b1="${b1##*/}"
    first="$b0"
    case "$b0" in docker-entrypoint.sh|entrypoint.sh) first="$b1" ;; esac
    case "$first" in
        postgres)                              echo postgres; return 0 ;;
        mariadbd|mysqld|mariadbd-safe|mysqld_safe) echo mariadb; return 0 ;;
    esac
    base="${image%%@*}"; base="${base##*/}"; base="${base%%:*}"
    case "$base" in
        postgres|postgresql|pgvector|pgvecto-rs|postgis|timescaledb|mariadb|mysql|percona-server)
            case "$b0" in
                sh|bash|dash|ash) echo sidecar ;;
                *)                echo unclear ;;
            esac ;;
        *) echo other ;;
    esac
}

# ---------------------------------------------------------------------------
# Dump-uri
# ---------------------------------------------------------------------------

# su_dump_header_ok KIND < primele linii
su_dump_header_ok() {
    case "${1:-}" in
        postgres) grep -qE '^-- PostgreSQL database cluster dump' ;;
        mariadb)  grep -qE '^-- (MariaDB|MySQL) dump' ;;
        *)        return 2 ;;
    esac
}

# su_dump_tail_ok KIND < ultimele linii
# Ultima linie care CONTEAZĂ trebuie să fie marcajul de încheiere. Liniile goale,
# `--` singur și `\unrestrict …` de la coadă nu contează (vezi antetul fișierului:
# așa se termină un pg_dumpall real). Marcajul din mijlocul textului, urmat de alt
# conținut, nu e un dump încheiat — e ceva adăugat după el.
su_dump_tail_ok() {
    local kind="${1:-}" last re
    case "$kind" in
        postgres) re='^-- PostgreSQL database cluster dump complete$' ;;
        mariadb)  re='^-- Dump completed on ' ;;
        *)        return 2 ;;
    esac
    last="$(grep -vE '^[[:space:]]*$|^--[[:space:]]*$|^\\unrestrict ' | tail -n 1 || true)"
    [[ "$last" =~ $re ]]
}

# su_backup_gate MANIFEST NOW MAX_AGE DB... — poate începe o schimbare care riscă datele?
# MANIFEST: `epoch=<n>`, `dir=<director cu dump-uri>`, apoi pe linie
#   `ok|<nume>|<fel>|<octeți decomprimați>|<sha256 al .sql.gz>|<octeți pe disc>`,
#   `failed|<nume>|…` sau `skip|<nume>|…`.
# Tipărește motivele, câte unul pe linie; cod 0 doar dacă nu e niciunul.
#   no-manifest | stale | no-dir | missing:<nume> | failed:<nume> | file-missing:<nume> | file-changed:<nume>
# «Există un backup» nu ajunge: trebuie să fie recent, să acopere fiecare bază care există ACUM
# și — fiindcă manifestul e doar o declarație — fișierul dump să existe LA MOMENTUL POARTEI, cu
# mărimea și suma din manifest. Numele se potrivește pe CÂMPUL al doilea, exact: un `grep -F
# "|nume|"` potrivea și coloana «fel», deci un container numit `postgres` sau `mariadb` trecea
# poarta cu dump-ul lipsă sau eșuat.
su_backup_gate() {
    local manifest="$1" now="$2" max="$3"; shift 3
    local epoch dir name line status sum csize f got reasons=0
    local -a fields
    if [[ ! -s "$manifest" ]]; then echo no-manifest; return 1; fi
    epoch="$(awk -F= '$1 == "epoch" { print $2; exit }' "$manifest")"
    dir="$(awk '/^dir=/ { sub(/^dir=/, ""); print; exit }' "$manifest")"
    if [[ ! "$epoch" =~ ^[0-9]+$ ]] || (( now - epoch > max || epoch > now + 300 )); then
        echo stale; reasons=1
    fi
    for name in "$@"; do
        line="$(awk -F'|' -v n="$name" '$2 == n && ($1 == "ok" || $1 == "failed" || $1 == "skip") { print; exit }' "$manifest")"
        if [[ -z "$line" ]]; then echo "missing:${name}"; reasons=1; continue; fi
        status="${line%%|*}"
        if [[ "$status" != ok ]]; then echo "failed:${name}"; reasons=1; continue; fi
        IFS='|' read -r -a fields <<< "$line"
        sum="${fields[4]:-}"; csize="${fields[5]:-}"
        if [[ -z "$dir" ]]; then echo "no-dir"; reasons=1; continue; fi
        f="${dir}/${name}.sql.gz"
        if [[ ! -s "$f" ]]; then echo "file-missing:${name}"; reasons=1; continue; fi
        got="$(sha256sum "$f")" || got=""
        got="${got%% *}"
        if [[ -z "$sum" || "$got" != "$sum" || "$(stat -c %s "$f")" != "$csize" ]]; then
            echo "file-changed:${name}"; reasons=1
        fi
    done
    (( reasons == 0 ))
}

# Stările LIPICIOASE (sticky) ale unui serviciu din faza `containers`, fiecare cu SINGURUL eveniment care îl
# poate rezolva (`stare:eveniment`, în ordinea priorității la afișare). O stare lipicioasă nu o șterge niciun
# `skip*`, `hold*`, `up-to-date`, `dry-run` sau altă verificare: doar succesul numit, urmat de o verificare
# (`verified`/`recreated`). Lista e aici, într-un singur loc; awk-ul de mai jos și `su_is_sticky` o citesc de aici.
#   failed        <- retried   (cererea explicită --retry-failed pentru proiect, apoi recrearea dovedită)
#   build-failed  <- built     (un build reușit: rulare cu --rebuild pentru proiect)
#   pull-failed   <- pulled    (un pull reușit)
#   tag-failed    <- tagged    (eticheta de rollback verificată pe imaginea de dinainte de mentenanță)
#   unread        <- read-ok   (configurația proiectului citită; se șterge direct, fără verificare: nu s-a schimbat nimic)
#   stale-baseline <- owned-ok (serviciul rulează o imagine pe care nici baseline-ul, nici mentenanța asta n-au pus-o: un redeploy
#                  de după baseline. Se judecă din fapte (su_image_is_ours), nu din jurnal; se șterge direct când faptul nu mai e
#                  adevărat — containerul a revenit pe imaginea din baseline ori pe una pusă de mentenanță. Un baseline NOU îl
#                  rezolvă prin definiție: nu se preia într-un baseline nou)
#                  Se afișează PRIMUL (ordinea din SU_STICKY_SPEC): cât timp e adevărat, nicio altă stare a serviciului nu se poate
#                  rezolva, iar mesajul lui e cel acționabil.
# Ieșirea comună a tuturor (în afară de stale-baseline), pentru un serviciu care nu mai există sau nu mai poate fi adus la starea cerută: evenimentul
# `acked` (--acknowledge, ales de operator; vezi su_report_final) — nu e în listă fiindcă nu e un succes specific, ci o decizie.
SU_STICKY_SPEC="stale-baseline:owned-ok:direct failed:retried build-failed:built pull-failed:pulled tag-failed:tagged unread:read-ok:direct"

# su_is_sticky STARE — 0 dacă e o stare lipicioasă (un eșec nerezolvat), 1 altfel.
su_is_sticky() {
    local e s
    for e in $SU_STICKY_SPEC; do s="${e%%:*}"; [[ "$s" == "${1:-}" ]] && return 0; done
    return 1
}

# su_ack_hint PROIECT SERVICIU — ieșirea pentru un serviciu care nu mai există sau nu poate fi adus la starea pe care o cere rezolvarea
# (nu mai are niciun container în baseline-ul nou: scos din compose; sau containerul lui e oprit ori în buclă și nu-l pornești; sau imaginea lui nu se mai poate potrivi). Recunoașterea e o decizie a
# operatorului, scrisă ca eveniment `acked` și tipărită la fiecare apariție; nicio rulare nu o face singură.
su_ack_hint() {
    echo "Dacă serviciul nu mai poate fi adus la starea cerută (un serviciu fără NICIUN container în baseline-ul nou, scos din compose, își încheie episodul singur; unul oprit sau în buclă nu): --phase containers --acknowledge ${1:-PROIECT}/${2:-SERVICIU} (recunoaștere EXPLICITĂ a operatorului: eșecul rămâne scris în jurnal ca «acked» și apare în verify; nu se face niciodată singură)"
}

# su_sticky_hint STARE PROIECT [SERVICIU] — ce îi cere operatorului rezolvarea unei stări lipicioase (aceleași reguli ca mai sus).
# Textele sunt între ghilimele duble: un cuvânt-regulă se scrie între «», NICIODATĂ între ghilimele-oblice (backtick) — bash l-ar EXECUTA ca pe o comandă (B1, runda 11: `ok`, `worse`
# dispăreau din mesaj, iar un executabil cu numele lor din PATH rula). Testele (test_system_update_lib.py) rulează hint-urile cu momeli pe PATH și scanează toate scripturile.
# Fiecare stare lipicioasă în afară de `stale-baseline` (care se rezolvă prin baseline nou, nu prin recunoaștere) numește și ieșirea
# `--acknowledge PROIECT/SERVICIU`: un eșec preluat într-un baseline nou poate să nu mai aibă un container de re-verificat.
su_sticky_hint() {
    local p="${2:-PROIECT}" s="${3:-SERVICIU}" ack
    ack="$(su_ack_hint "$p" "$s")"
    case "${1:-}" in
        failed)       echo "Se rezolvă doar prin --retry-failed ${p} (și pentru o aplicație construită local, fără --rebuild: atunci re-verifică containerul de acum), după ce ai citit de ce a picat, iar recrearea/verificarea e dovedită și stabilă; nicio altă rulare nu îl atinge sau îl șterge. Într-un baseline nou, «dovedită» înseamnă că verdictul față de sănătatea din episodul eșecului (cea de ÎNAINTE de el, preluată) e «ok» sau «same-bad» (era la fel de rău înainte de orice mentenanță: același standard ca baseline-ul original), nu doar «la fel ca la baseline-ul nou»; «worse» nu rezolvă. ${ack}" ;;
        build-failed) echo "Se rezolvă doar printr-un build reușit (--rebuild ${p}), apoi verificat; o rulare fără --rebuild nu îl șterge. ${ack}" ;;
        pull-failed)  echo "Se rezolvă doar printr-un pull reușit, apoi verificat (rulează din nou proiectul: --phase containers --only ${p}; dacă rularea spune «hold-config-drift», după ce ai citit schimbarea din fișierele compose: --accept-drift ${p}); o rulare care nu trage nimic nu îl șterge. ${ack}" ;;
        tag-failed)   echo "Eticheta de rollback n-a putut fi dovedită pe imaginea de dinainte de mentenanță; repar-o, apoi rulează din nou proiectul ${p} (--only ${p}): eticheta se verifică din nou, iar starea se rezolvă când e dovedită și containerul e sănătos, cu sau fără recreare. ${ack}" ;;
        unread)       echo "Proiectul ${p} n-a putut fi citit; se rezolvă la prima rulare care îi citește configurația (--only ${p}). ${ack}" ;;
        stale-baseline) echo "Baseline-ul e vechi pentru serviciu: rulează o imagine pe care nici baseline-ul, nici mentenanța asta n-au pus-o (un redeploy de după baseline), iar o etichetă de rollback pe imaginea din baseline ar anula acel deploy. Nimic nu s-a atins. Ia un baseline nou: --phase preflight --new-baseline (apoi --phase backup dacă are peste 12 h, apoi --phase containers); sau readu containerul pe imaginea din baseline"  ;;
        *)            echo "stare lipicioasă necunoscută" ;;
    esac
}

# su_report_final REPORT [all] — rezultatul FINAL al fiecărui serviciu din raportul cumulativ al fazei
# `containers`, ca «proiect/serviciu|acțiune|detaliu», în ordinea primei apariții.
# Cu al doilea argument `all`, un serviciu cu mai multe stări lipicioase nerezolvate le arată pe toate (în ordinea din SU_STICKY_SPEC), nu doar prima:
# `stale-baseline` afișat primul ascunde altfel un `tag-failed`/`pull-failed` încă nerezolvat, iar un baseline nou nu are voie să-l piardă.
# Raportul e un jurnal de acțiuni; ce contează e starea de ACUM. Reguli:
#   * un eșec (`failed`, `build-failed`, `pull-failed`, `tag-failed`, `unread`, `stale-baseline`) e LIPICIOS: rămâne rezultatul
#     serviciului până când se rezolvă prin succesul lui specific (vezi SU_STICKY_SPEC). Succesul specific doar
#     ÎNARMEAZĂ eliberarea; o `verified`/`recreated` care vine imediat după îl șterge. Orice alt eveniment
#     între ele (`skip*`, `hold*`, un alt eșec) dezarmează: «a mers pull-ul» nu spune nimic dacă serviciul n-a
#     fost apoi verificat, iar un `verified` fără succesul specific nu spune nimic despre ce a eșuat. Tot dezarmează
#     succesul altei stări (`pull-failed pulled built verified` rămâne pull-failed: un serviciu nu e și trasat, și
#     construit), cu două excepții care fac parte din același drum: `tagged` (eticheta de rollback precede orice
#     recreare) și, pentru `failed`, `pulled`/`built` (reîncercarea trage sau construiește, apoi recreează);
#   * fără eșecuri lipicioase: `recreated`, `verified`, `skip*`, `hold*` înlocuiesc (ultimul câștigă);
#   * `acked` (scris DOAR de `--acknowledge P/S`, ales de operator) șterge stările lipicioase ale serviciului DIN EPISODUL pe care îl numește (prefixul `[episod=ID] `;
#     fără prefix = baseline-ul fișierului), ÎN AFARĂ DE `stale-baseline` (se
#     rezolvă prin baseline nou sau prin readucerea containerului, nu printr-o decizie), și pune un STEAG durabil pe serviciu, SEPARAT de ultimul
#     rezultat: niciun alt eveniment nu-l șterge — nici `skip*`/`hold*`/`up-to-date`, nici `unread`/`read-ok`, nici `recreated`/`verified`, nici un eșec nou
#     (un `unread` trecător după recunoaștere, apoi `read-ok`, lăsa serviciul «dovedit»: N15). Cât steagul stă, rezultatul final al serviciului (când nu
#     e o stare lipicioasă activă) e `acked`, nu ultimul rezultat. Îl șterge DOAR `ack-cleared` (scris de faza containers după un verdict `ok` sau `same-bad` față de
#     sănătatea din episodul recunoscut ȘI față de baseline-ul curent, vezi su_ack_clears) sau absența lui din baseline-ul următor (carry_forward_sticky
#     preia doar steagurile vii). Recunoașterea e legată de EPISOD: linia poartă prefixul `[episod=ID] `, iar `ackeps` listează episoadele vii.
#     Al doilea argument `acked` listează DOAR recunoașterile (și cele de sub un `stale-baseline` care rămâne), ca verify/status/faza să le arate mereu;
#   * `episode-closed` (scris DOAR de carry_forward_sticky pentru un serviciu care a dispărut din baseline-ul nou) e doar jurnal: nu e stare, nu e rezultat;
#   * `up-to-date` NU înlocuiește nimic: «imaginea trasă e cea care rulează» nu spune nimic despre
#     sănătatea containerului. Nici evenimentele de succes (`retried`, `built`, `pulled`, `tagged`, `read-ok`, `owned-ok`)
#     nu sunt rezultate: nu apar niciodată ca stare finală.
su_report_final() {
    [[ -s "${1:-}" ]] || return 0
    local cur
    cur="$(basename "$(dirname "$1")")"      # baseline-ul fișierului: episodul implicit al unei linii fără prefix `[episod=ID] `
    awk -F'|' -v spec="$SU_STICKY_SPEC" -v all="${2:-}" -v cur="$cur" '
        BEGIN { ns = split(spec, sp, " ")
                for (i = 1; i <= ns; i++) { split(sp[i], kv, ":"); fl[i] = kv[1]; isflag[kv[1]] = 1; res[kv[2]] = kv[1]; direct[kv[1]] = (kv[3] == "direct") } }
        function ep_of(x) { return match(x, /^\[episod=[A-Za-z0-9._-]+\] /) ? substr(x, 9, RLENGTH - 10) : "-" }
        function norm(e) { return e == "-" ? cur : e }            # o linie fără prefix e a baseline-ului în care stă fișierul
        function strip(x) { return match(x, /^\[episod=[A-Za-z0-9._-]+\] /) ? substr(x, RLENGTH + 1) : x }
        { k = $1 "/" $2; a = $3; d = $4; for (i = 5; i <= NF; i++) d = d "|" $i
          if (!(k in seen)) { seen[k] = 1; n++; keys[n] = k }
          if (a == "episode-closed") next                      # doar jurnal (carry_forward_sticky: serviciul a dispărut, episodul s-a închis): nu e rezultat și nu atinge nicio stare
          if (a == "acked") {                                  # recunoașterea EXPLICITĂ a operatorului (--acknowledge): acoperă DOAR episodul pe care îl numește
              e = norm(ep_of(d))                               # stările lipicioase ale ALTUI episod (un eșec nou, ori preluat din alt baseline) rămân roșii, în orice ordine ar sta liniile
              for (i = 1; i <= ns; i++) if (fl[i] != "stale-baseline" && on[k, fl[i]] && fep[k, fl[i]] == e) { on[k, fl[i]] = 0; armed[k, fl[i]] = 0 }
              ackon[k] = 1; ackdet[k] = strip(d); e = ep_of(d)
              if (index(" " ackep[k] " ", " " e " ") == 0) ackep[k] = ackep[k] (ackep[k] == "" ? "" : " ") e
              next }
          if (a == "ack-cleared") { ackon[k] = 0; ackep[k] = ""; next }   # singurul care coboară steagul (verdict ok sau same-bad față de episod ȘI baseline, scris de faza containers)
          if (a in isflag) {                                   # un eșec: dezarmează tot, apoi se pune
              for (i = 1; i <= ns; i++) armed[k, fl[i]] = 0
              on[k, a] = 1; fdet[k, a] = d; fep[k, a] = norm(ep_of(d))
              next }
          if (a in res) {                                      # succesul specific al unei stări lipicioase
              f = res[a]
              for (i = 1; i <= ns; i++) {                      # orice succes care nu aparține drumului unei stări înarmate o dezarmează
                  g = fl[i]
                  if (g == f || !armed[k, g]) continue
                  if (a == "tagged" || (g == "failed" && (a == "pulled" || a == "built"))) continue
                  armed[k, g] = 0 }
              if (on[k, f]) { if (direct[f]) on[k, f] = 0; else armed[k, f] = 1 }
              next }
          if (a == "up-to-date") { if (k in act) next; act[k] = a; det[k] = d; next }
          if (a == "verified" || a == "recreated") {           # verificarea care încheie o eliberare înarmată
              for (i = 1; i <= ns; i++) if (armed[k, fl[i]]) { on[k, fl[i]] = 0; armed[k, fl[i]] = 0 }
              act[k] = a; det[k] = d; next }
          for (i = 1; i <= ns; i++) armed[k, fl[i]] = 0        # skip*, hold*, orice altceva: dezarmează
          act[k] = a; det[k] = d }
        END { for (j = 1; j <= n; j++) { k = keys[j]; shown = 0
                if (all == "acked") { if (ackon[k]) print k "|acked|" ackdet[k]; continue }   # modul `acked`: DOAR recunoașterile, chiar și sub o stare lipicioasă (stale-baseline)
                if (all == "ackeps") { if (ackon[k]) { m = split(ackep[k], ee, " "); for (q = 1; q <= m; q++) print k "|" ee[q] }; continue }   # episoadele recunoașterilor vii: `cheie|EPISOD` (`-` = linie fără prefix)
                for (i = 1; i <= ns; i++) if (on[k, fl[i]]) { print k "|" fl[i] "|" fdet[k, fl[i]]; shown = 1; if (all != "all") break }
                if (!shown && ackon[k]) { print k "|acked|" ackdet[k]; shown = 1 }          # steagul durabil ține locul rezultatului final cât nu e o stare lipicioasă activă
                if (!shown && (k in act)) print k "|" act[k] "|" det[k] } }' "$1"
}

# Proprietatea asupra imaginii unui serviciu NU se deduce din jurnalul de acțiuni (`pulled`/`built` descriu ce a făcut un pull
# oricare, inclusiv unul care n-a găsit nimic și a scris ID-ul unei imagini străine: un redeploy de după baseline devenea «al
# nostru» printr-o rulare fără nicio schimbare). Ea stă într-un fișier separat, `containers.owned`, scris DOAR de faptele pe care
# mentenanța asta le-a observat, la momentul lor:
#   proiect|serviciu|prev|ID-complet    imaginea pe care containerul o rula chiar înainte de PRIMA schimbare făcută de noi
#                                       (ținta etichetei de rollback; scrisă înainte de `tag` și `up`, citită din container)
#   proiect|serviciu|landed|ID-complet  imaginea pe care am văzut-o RULÂND în container după `up` (efect observat, nu intenție;
#                                       indiferent dacă verificarea de sănătate a trecut: o reîncercare trebuie să recunoască imaginea picată)
# su_owned_ids FIȘIER PROIECT SERVICIU TIP — ID-urile complete de acel tip pentru serviciu (comparație exactă, nu pe prefix).
su_owned_ids() {
    [[ -s "${1:-}" ]] || return 0
    awk -F'|' -v p="${2:-}" -v s="${3:-}" -v k="${4:-}" '$1 == p && $2 == s && $3 == k { print $4 }' "$1"
}

# su_image_is_ours RULEAZĂ BASELINE OWNED PROIECT SERVICIU — imaginea care rulează acum e cea din baseline sau una pe care am
# văzut-o noi rulând sub serviciu (`landed`)? Altfel baseline-ul e VECHI pentru serviciu: cineva a făcut redeploy după el (oferte
# api/worker, dms app, 20 nov 2026), iar o etichetă de rollback pe imaginea din baseline ar anula acel deploy.
# O imagine «trasă» ori «construită» NU e dovadă: doar una văzută rulând după un `up` făcut de noi.
su_image_is_ours() {
    local run="${1:-}" base="${2:-}" id
    [[ -n "$run" ]] || return 1
    [[ "$run" == "$base" ]] && return 0
    while IFS= read -r id; do
        [[ -n "$id" && "$run" == "$id" ]] && return 0
    done < <(su_owned_ids "${3:-}" "${4:-}" "${5:-}" landed)
    return 1
}

# su_owned_has FIȘIER PROIECT SERVICIU TIP ID — există faptul exact `proiect|serviciu|TIP|ID`? (comparație pe ID complet)
su_owned_has() {
    local id
    while IFS= read -r id; do
        [[ -n "$id" && "$id" == "${5:-}" ]] && return 0
    done < <(su_owned_ids "${1:-}" "${2:-}" "${3:-}" "${4:-}")
    return 1
}

# Episodul unui eșec preluat. Un baseline nou preia un eșec nerezolvat împreună cu INTRĂRILE față de care a fost judecat, nu cu o stare derivată
# (un șir de sănătate «cel mai exigent», un ID de imagine tras): `containers.episode`, `proiect|serviciu|EPISOD|câmp|valoare...`, cu
#   base_health   sănătatea serviciului în baseline-ul în care s-a produs eșecul (ce se cere pentru ca eșecul să fie rezolvat)
#   base_id       imaginea care rula în acel baseline (doar informativ)
#   prev          imaginea pe care containerul o rula înainte de schimbarea noastră (ținta etichetei de rollback la o reîncercare)
#   landed        imaginea pe care schimbarea noastră a pus-o și am văzut-o RULÂND (una sau mai multe): la o reîncercare, dacă imaginea care rulează ACUM e
#                 una dintre ele, imaginea picată încă rulează și ținta rollback-ului e `prev`; altfel cineva a schimbat-o între timp, iar ținta e ce rulează acum
#   pulled|TAG|RUN  pull-ul NOSTRU a mutat eticheta pe TAG cât containerul rula RUN (scutirea de hold-moved-tag cere ambele)
# EPISODUL = numele baseline-ului în care s-a produs eșecul; linia carry din containers.report îl poartă ca prefix `[episod=ID] ` (jurnalul e
# singura sursă a ce e încă nerezolvat, deci și a EPISODULUI nerezolvat: un episod rezolvat și un eșec nou al aceluiași serviciu au ID-uri
# diferite, iar înregistrările celui rezolvat nu se mai preiau niciodată). Sănătatea nu se compară aici: o judecă un singur loc, su_container_verdict.
SU_EPISODE_PREFIX_RE='^\[episod=([A-Za-z0-9._-]+)\] (.*)$'

# su_episode_of DETALIU — ID-ul episodului din prefixul `[episod=ID] `, gol dacă detaliul nu e al unui eșec preluat.
su_episode_of() {
    [[ "${1:-}" =~ $SU_EPISODE_PREFIX_RE ]] && printf '%s' "${BASH_REMATCH[1]}"
    return 0
}

# su_episode_strip DETALIU — detaliul fără prefixul de episod.
su_episode_strip() {
    if [[ "${1:-}" =~ $SU_EPISODE_PREFIX_RE ]]; then printf '%s' "${BASH_REMATCH[2]}"; else printf '%s' "${1:-}"; fi
}

# su_episode_vals FIȘIER PROIECT SERVICIU EPISOD CÂMP — valorile câmpului (tot ce urmează după nume, cu `|`), câte una pe linie.
su_episode_vals() {
    [[ -s "${1:-}" ]] || return 0
    awk -F'|' -v p="${2:-}" -v s="${3:-}" -v e="${4:-}" -v f="${5:-}" '$1 == p && $2 == s && $3 == e && $4 == f { v = $5; for (i = 6; i <= NF; i++) v = v "|" $i; print v }' "$1"
}

# su_state_episodes RAPORT PROIECT SERVICIU — `stare|EPISOD` pentru fiecare stare lipicioasă NEREZOLVATĂ a serviciului care e un eșec preluat.
# Se citește din jurnal (su_report_final all), nu din containers.episode: o înregistrare rămasă de la un episod rezolvat nu are nicio linie vie.
su_state_episodes() {
    local want="${2:-}/${3:-}" key st det ep
    while IFS='|' read -r key st det; do
        [[ "$key" == "$want" ]] || continue
        ep="$(su_episode_of "$det")"
        if [[ -n "$ep" ]]; then printf '%s|%s\n' "$st" "$ep"; fi
    done < <(su_report_final "${1:-}" all)
    return 0
}

# su_ack_episodes RAPORT PROIECT SERVICIU — episoadele (ID-uri, `-` = linie fără prefix) ale recunoașterilor VII ale serviciului, câte unul pe linie.
su_ack_episodes() {
    local want="${2:-}/${3:-}" key ep
    while IFS='|' read -r key ep; do
        [[ "$key" == "$want" ]] && printf '%s
' "$ep"
    done < <(su_report_final "${1:-}" ackeps)
    return 0
}

# Cele două judecăți ale unui episod, într-un singur loc (aceeași su_container_verdict peste sănătatea din episod și peste cea din baseline-ul de acum).
# su_episode_resolves VERDICT — un eșec PRESELUAT se rezolvă când verdictul față de episod e `ok` sau `same-bad`: același standard ca baseline-ul
#   original (un serviciu care era unhealthy ÎNAINTE de orice mentenanță și e la fel de unhealthy acum e în starea de dinainte de eșec; cerința `ok`
#   l-ar fi lăsat blocat pe «--acknowledge» pentru un pull care a pierdut un singur apel de rețea). `worse`, `pending`, `unknown`, `skip` NU rezolvă.
su_episode_resolves() { [[ "${1:-}" == ok || "${1:-}" == same-bad ]]; }
# su_ack_clears VERDICT_EPISOD VERDICT_BASELINE — o recunoaștere a operatorului se șterge după ACEEAȘI regulă ca rezolvarea unui eșec (su_episode_resolves),
#   pe AMBELE judecăți: `ok` sau `same-bad`. Un serviciu care era unhealthy ÎNAINTE de orice mentenanță și e la fel acum e în starea dinainte (N1): recunoașterea lui
#   nu are voie să rămână pe veci, altfel același serviciu iese «TOTUL DOVEDIT» nerecunoscut și «DOVEDIT, cu 1 recunoscut» recunoscut, adică recunoașterea ar pedepsi.
su_ack_clears() { su_episode_resolves "${1:-}" && su_episode_resolves "${2:-}"; }

# su_image_id_same A B — două ID-uri de imagine, posibil trunchiate, sunt aceeași imagine? Un `landed` din episod poate fi scurtat (editare de mână, un câmp
#   tăiat): `docker inspect` dă ID-ul întreg, iar o comparație exactă ar lua imaginea picată drept «schimbată de altcineva» și ar pune-o sub eticheta de rollback.
#   Se compară fără prefixul `sha256:`; egale, sau unul prefix al celuilalt DAR ambele de cel puțin 12 cifre hex (lungimea ID-ului scurt din docker: sub ea un
#   prefix potrivește prea ușor). Gol sau ne-hex nu se potrivește cu nimic.
su_image_id_same() {
    local a="${1:-}" b="${2:-}"
    a="${a#sha256:}"; b="${b#sha256:}"
    [[ -n "$a" && -n "$b" ]] || return 1
    [[ "$a" == "$b" ]] && return 0
    [[ "$a" =~ ^[0-9a-f]{12,64}$ && "$b" =~ ^[0-9a-f]{12,64}$ ]] || return 1
    [[ "$a" == "$b"* || "$b" == "$a"* ]]
}

# su_age_state MTIME NOW MAX — `fresh` | `stale` | `missing` (mtime gol sau ne-numeric).
su_age_state() {
    local mtime="${1:-}" now="$2" max="$3"
    [[ "$mtime" =~ ^[0-9]+$ ]] || { echo missing; return 0; }
    if (( now - mtime > max )); then echo stale; else echo fresh; fi
}

# ---------------------------------------------------------------------------
# Imagini: ce are voie să facă `containers` cu un serviciu
# ---------------------------------------------------------------------------

# su_pull_decision CONFIG_IMAGE TAG_EXISTS DIGESTS BASE_RUNNING_ID BASE_TAG_ID
#   pull | skip-bare-id | skip-no-image | skip-local | skip-unknown | hold-moved-tag
# BASE_* sunt faptele din snapshot, nu cele de acum: un `docker pull` mută eticheta,
# iar o decizie luată din starea de după propriul pull ar vedea orice serviciu
# «cu eticheta mutată» la a doua rulare.
#   * ID gol (`6cd5a2fc29fe`): nu există etichetă de tras;
#   * DIGESTS = numărul de RepoDigests ai imaginii locale. 0 = n-a venit niciodată
#     dintr-un registru (cryptoitdata-hub:latest) — un `pull` ar încerca s-o ia de pe
#     Docker Hub sub un nume pe care îl poate deține altcineva;
#   * `hold-moved-tag`: containerul rulează alt ID decât cel pe care îl are acum
#     eticheta (snipeit-app-1: rulează imaginea din august, eticheta arată una din
#     octombrie). `up` ar sări peste toate versiunile dintre ele, cu migrări la pornire.
su_pull_decision() {
    local img="${1:-}" exists="${2:-}" digests="${3:-}" run="${4:-}" tag="${5:-}"
    if [[ "$img" =~ ^(sha256:)?[0-9a-f]{12,64}$ ]]; then echo skip-bare-id; return 0; fi
    [[ "$exists" == yes ]] || { echo skip-no-image; return 0; }
    [[ "$digests" =~ ^[0-9]+$ ]] || { echo skip-unknown; return 0; }
    (( digests > 0 )) || { echo skip-local; return 0; }
    [[ -n "$run" && "$run" == "$tag" ]] || { echo hold-moved-tag; return 0; }
    echo pull
}

# su_pull_result PULL_RC RUNNING_ID NEW_TAG_ID — ce a dovedit pull-ul:
#   up-to-date | recreate | pull-failed
# Un pull eșuat NU înseamnă «nimic nou»: n-am aflat dacă există ceva. Codul 0 fără un
# ID de imagine citit după el nu dovedește nimic.
su_pull_result() {
    local rc="${1:-}" running="${2:-}" new="${3:-}"
    [[ "$rc" == 0 && -n "$new" ]] || { echo pull-failed; return 0; }
    if [[ "$running" == "$new" ]]; then echo up-to-date; else echo recreate; fi
}

# su_drift_verdict NEWER DIRTY HEADNEWER — codul de pe disc e cel care rulează?
#   clean | drift | unknown
#   NEWER      câte fișiere din contextul de build sunt mai noi decât imaginea (număr sau `?`)
#   DIRTY      câte intrări are `git status --porcelain` (număr, `norepo` sau `?`)
#   HEADNEWER  ultimul commit al contextului e mai nou decât imaginea (yes|no|norepo|?)
# `docker compose build` livrează ce e pe disc în clipa asta. Orice pozitiv e `drift`;
# un «nu știu» fără niciun pozitiv e `unknown`, nu `clean`.
su_drift_verdict() {
    local newer="${1:-?}" dirty="${2:-?}" head="${3:-?}" drift=0 unk=0
    if [[ "$newer" =~ ^[0-9]+$ ]]; then (( newer > 0 )) && drift=1; else unk=1; fi
    case "$dirty" in
        norepo) ;;
        *) if [[ "$dirty" =~ ^[0-9]+$ ]]; then (( dirty > 0 )) && drift=1; else unk=1; fi ;;
    esac
    case "$head" in
        no|norepo) ;;
        yes)       drift=1 ;;
        *)         unk=1 ;;
    esac
    if (( drift )); then echo drift; elif (( unk )); then echo unknown; else echo clean; fi
}

# su_list_has LIST ITEM [ALLOW_ALL] — ITEM e în lista cu virgule? `all` acoperă orice
# doar când ALLOW_ALL=1 (implicit 1). Pentru `--accept-drift` se dă 0: «accept tot codul
# necitit de nimeni» nu e o decizie care să încapă într-un cuvânt.
su_list_has() {
    local list="${1:-}" item="${2:-}" allow_all="${3:-1}" x
    [[ -n "$list" ]] || return 1
    if [[ "$list" == all ]]; then [[ "$allow_all" == 1 ]]; return; fi
    local IFS=,
    for x in $list; do [[ "$x" == "$item" ]] && return 0; done
    return 1
}

# su_build_decision PROJECT REBUILD_LIST ACCEPT_LIST DRIFT_VERDICT
#   build | build-accepted-drift | skip-not-requested | skip-drift | skip-unknown
# Reconstruirea e opt-in pe proiect: fără --rebuild nu se construiește nimic.
su_build_decision() {
    local project="$1" rebuild="$2" accept="$3" verdict="$4"
    su_list_has "$rebuild" "$project" 1 || { echo skip-not-requested; return 0; }
    case "$verdict" in
        clean) echo build ;;
        drift)
            if su_list_has "$accept" "$project" 0; then echo build-accepted-drift; else echo skip-drift; fi ;;
        *)
            if su_list_has "$accept" "$project" 0; then echo build-accepted-drift; else echo skip-unknown; fi ;;
    esac
}

# ---------------------------------------------------------------------------
# Comparații cu baseline-ul
# ---------------------------------------------------------------------------

# su_http_verdict BASE NOW — ok | worse | same-bad | unknown
# Orice cod sub 500 înseamnă că vhostul a răspuns. 000 (curl n-a primit nimic) și 5xx
# sunt rele; sunt «mai rău» doar dacă la baseline nu erau deja. Un răspuns care lipsește
# (curl nu s-a putut rula) e `unknown`, nu 000.
su_http_verdict() {
    local base="${1:-}" now="${2:-}"
    [[ "$now" =~ ^[0-9]{3}$ ]] || { echo unknown; return 0; }
    [[ "$base" =~ ^[0-9]{3}$ ]] || { echo unknown; return 0; }
    if [[ "$now" == 000 || "$now" =~ ^5 ]]; then
        if [[ "$base" == 000 || "$base" =~ ^5 ]]; then echo same-bad; else echo worse; fi
        return 0
    fi
    echo ok
}

# su_probe_verdict BASE NOW — pentru sonde de tip număr (reguli auditd încărcate) sau
# da/nu (tabela nft, baza de pe gazdă răspunde). ok | worse | unknown | na.
# `na` la baseline = sonda nu se aplica (serviciul nu rula): nu se compară.
su_probe_verdict() {
    local base="${1:-}" now="${2:-}"
    [[ "$base" == na ]] && { echo na; return 0; }
    [[ -n "$now" && "$now" != unknown ]] || { echo unknown; return 0; }
    [[ -n "$base" && "$base" != unknown ]] || { echo unknown; return 0; }
    if [[ "$base" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]]; then
        if (( now < base )); then echo worse; else echo ok; fi
        return 0
    fi
    case "${base}/${now}" in
        yes/yes|no/no|no/yes) echo ok ;;
        yes/no)               echo worse ;;
        *)                    echo unknown ;;
    esac
}

# su_new_lines BASE NOW — liniile din NOW care nu sunt în BASE (comparație pe seturi).
# su_missing_lines BASE NOW — cele din BASE care nu mai sunt în NOW.
# `comm` ordonează după LOCALE, `sort` cu LC_ALL=C după octeți: fără LC_ALL=C și pe comm, cele
# două nu se înțeleg ("file 1 is not in sorted order", măsurat pe gazdă pe 19 nov 2026) iar
# intersecția iese trunchiată — lista de servicii care trebuie să fie sus ar fi lipsit tocmai
# docker și mariadb, deci verify nu le-ar fi cerut.
su_new_lines()     { LC_ALL=C comm -13 <(LC_ALL=C sort -u "$1") <(LC_ALL=C sort -u "$2"); }
su_missing_lines() { LC_ALL=C comm -23 <(LC_ALL=C sort -u "$1") <(LC_ALL=C sort -u "$2"); }

# su_vhost_names < `nginx -T` — numele de server literale (cu cel puțin un punct).
# `_`, regexurile (`~^…`) și wildcard-urile nu sunt nume care se pot proba cu --resolve.
su_vhost_names() {
    { sed -n 's/^[[:space:]]*server_name[[:space:]]\{1,\}\([^;]*\);.*/\1/p' \
        | tr ' \t' '\n\n' \
        | grep -E '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' \
        | LC_ALL=C sort -u; } || true
}

# su_epoch ISO — secunde de la epocă, sau nimic dacă data nu se poate citi.
su_epoch() {
    local e
    e="$(date -d "${1:-}" +%s 2>/dev/null)" || return 1
    [[ "$e" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$e"
}
