#!/usr/bin/env bash
#
# Măsurătorile lui scripts/lib/system-update-host.sh: ce întreabă gazda și cum își
# notează răspunsul. Încărcat cu `source` DUPĂ system-update-lib.sh; nu rulează nimic.
#
# Fiecare `m_*` tipărește pe stdout și NU scrie fișiere: tot ce scrie `snap_measure`
# (și doar el), ca „n-am putut întreba" să aibă un singur loc în care devine
# `<fișier>.unknown`. Regula e cea a lui `baseline_measure` din deploy/lib/common.sh,
# pentru aceleași motive: un fișier GOL care există trebuie să însemne «nu rula
# nimic», nu «n-am putut întreba», iar o comandă căzută lăsa tocmai un fișier gol —
# apoi comparația de după vedea fiecare serviciu «dispărut» sau, mai rău, niciunul.
#
# Toate se pot rula de mână pe gazdă, doar pentru citire (systemctl, docker ps/inspect,
# rpm -qa, curl pe loopback). Nicio funcție de aici nu modifică nimic.

# Numele de unități dintr-o listare `systemctl`, indiferent dacă prima coloană e `●`
# (marcajul de eșec) sau numele însuși.
unit_names() {
    awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.(service|socket|timer|mount|target|path|scope|slice|automount|swap|device)$/) { print $i; break } }'
}

# snap_measure DIR NUME MIN_LINII cmd... — pune ieșirea lui cmd în DIR/NUME, ori
# DIR/NUME.unknown cu motivul. 0 = măsurat; 1 = nemăsurat.
# MIN_LINII e controlul pozitiv: o comandă care iese cu 0 dar tipărește mai puțin
# decât poate tipări vreodată o gazdă sănătoasă (rpm -qa cu zero pachete) nu e o
# măsurătoare.
snap_measure() {
    local dir="$1" name="$2" min="$3"; shift 3
    local out="${dir}/${name}" errf rc=0 lines
    rm -f "$out" "${out}.unknown" "${out}.tmp"
    errf="$(mktemp)" || { printf 'mktemp a eșuat\n' > "${out}.unknown"; return 1; }
    "$@" > "${out}.tmp" 2> "$errf" || rc=$?
    if (( rc != 0 )); then
        printf 'cod=%s %s\n' "$rc" "$(head -c 300 "$errf" | tr '\n' ' ')" > "${out}.unknown"
        rm -f "${out}.tmp" "$errf"
        return 1
    fi
    lines="$(wc -l < "${out}.tmp")"
    if (( lines < min )); then
        printf 'comanda a ieșit cu 0 dar a tipărit %s linii (minim %s) — nu e o măsurătoare\n' "$lines" "$min" > "${out}.unknown"
        rm -f "${out}.tmp" "$errf"
        return 1
    fi
    mv -f "${out}.tmp" "$out"
    rm -f "$errf"
}

# base_state FILE — ce valorează un fișier din baseline: measured | unmeasured | missing.
# Apelantul tratează TOT ce nu e `measured` ca necunoscut.
base_state() {
    if [[ -f "$1.unknown" ]]; then echo unmeasured
    elif [[ -f "$1" ]]; then echo measured
    else echo missing
    fi
}

m_rpm_qa() { rpm -qa --qf '%{NEVRA}\n' | LC_ALL=C sort; }

# ---------------------------------------------------------------------------
# Gestionarul de pachete: detectat O DATĂ (pkg_detect, din init_state), apoi fiecare măsurătoare care depinde de el trece printr-un dispatcher.
# Un PKG_MGR necunoscut NU cade pe «dnf»: măsurătoarea iese cu 1 și devine `.unknown` — «nu știu» nu e «la fel ca pe gazda de producție».
# ---------------------------------------------------------------------------

# pkg_detect — din FAPTE: ID/ID_LIKE din os-release (familia) ȘI binarele care trebuie să existe (dnf; apt-get + dpkg + dpkg-query).
# Seteaza PKG_MGR (dnf|apt|unknown) și etichetele din mesaje; nu iese și nu refuză (refuzul e pkg_require). SU_OS_RELEASE: doar pentru teste.
pkg_detect() {
    local osr="${SU_OS_RELEASE:-/etc/os-release}" fam have_dnf=0 have_apt=0 verdict
    PKG_MGR=unknown; PKG_WHY=""; PKG_OS_ID=""; PKG_OS_LIKE=""
    if [[ ! -r "$osr" ]]; then PKG_WHY="nu pot citi ${osr}"; return 0; fi
    PKG_OS_ID="$(awk -F= '$1 == "ID" { v = $2; gsub(/^["\047]|["\047]$/, "", v); print v; exit }' "$osr")"
    PKG_OS_LIKE="$(awk -F= '$1 == "ID_LIKE" { v = $2; gsub(/^["\047]|["\047]$/, "", v); print v; exit }' "$osr")"
    fam="$(su_pkgmgr_family "$PKG_OS_ID" "$PKG_OS_LIKE")"
    have dnf && have_dnf=1
    if have apt-get && have dpkg && have dpkg-query; then have_apt=1; fi
    verdict="$(su_pkgmgr_decide "$fam" "$have_dnf" "$have_apt")"
    case "$verdict" in
        dnf|apt) PKG_MGR="$verdict" ;;
        no-binary) PKG_WHY="${osr} spune ID=${PKG_OS_ID} ID_LIKE=${PKG_OS_LIKE} (familia ${fam}), dar binarul gestionarului lipsește de pe gazdă" ;;
        *) PKG_WHY="ID=${PKG_OS_ID:-?} ID_LIKE=${PKG_OS_LIKE:-?} din ${osr} nu e nici familia RHEL (dnf), nici Debian (apt)" ;;
    esac
    case "$PKG_MGR" in
        dnf) PKG_DB=rpm;   PKG_LIST_FILE=rpm-qa.txt;     PKG_LIST_CMD="rpm -qa";
             KLIST_CMD="rpm -q kernel-core"; KDEF_NAME=grubby; KDEF_CMD="grubby --default-kernel"; REBOOT_PROBE_NAME="needs-restarting -r" ;;
        apt) PKG_DB=dpkg;  PKG_LIST_FILE=dpkg-list.txt;  PKG_LIST_CMD="dpkg-query -W";
             KLIST_CMD="dpkg-query linux-image-*"; KDEF_NAME=grub; KDEF_CMD="grub.cfg, GRUB_DEFAULT=0"; REBOOT_PROBE_NAME="/var/run/reboot-required" ;;
    esac
    return 0
}

m_dpkg_list() { dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}=${Version}\n' | su_apt_pkglist; }

m_pkg_list() {
    case "${PKG_MGR:-}" in
        dnf) m_rpm_qa ;;
        apt) m_dpkg_list ;;
        *)   echo "gestionarul de pachete nu e detectat (${PKG_WHY:-init_state n-a rulat})" >&2; return 1 ;;
    esac
}

# apt-get -s dist-upgrade: ce ar face upgrade-ul ACUM, din listele de pe disc (nu atinge rețeaua și nu ia blocări). Aceeași comandă ca upgrade-ul real,
# doar cu -s: o decizie luată din `upgrade` (care nu instalează pachete NOI) ar rata nucleul nou, linux-image-<versiune> fiind un pachet nou.
apt_simulate() { apt-get -s dist-upgrade; }

# apt_default_kernel — /boot/vmlinuz-<versiune> pe care îl va porni GRUB. Doar când GRUB_DEFAULT arată prima intrare; altfel iese cu 1 («nu știu»).
apt_grub_default_setting() {
    local f v="" files="${SU_GRUB_DEFAULT_FILES:-/etc/default/grub /etc/default/grub.d/*.cfg}"
    for f in $files; do
        [[ -f "$f" ]] || continue
        v="$(awk -F= -v cur="$v" '/^[[:space:]]*GRUB_DEFAULT=/ { cur = $2 } END { print cur }' "$f")" || return 1
    done
    printf '%s' "$v"
}
apt_default_kernel() {
    local cfg="${SU_GRUB_CFG:-/boot/grub/grub.cfg}" setting
    setting="$(apt_grub_default_setting)" || { echo "nu pot citi GRUB_DEFAULT" >&2; return 1; }
    su_grub_default_is_first "$setting" || { echo "GRUB_DEFAULT=${setting}: nu arată prima intrare, deci nu știu ce nucleu pornește" >&2; return 1; }
    [[ -r "$cfg" ]] || { echo "nu pot citi ${cfg}" >&2; return 1; }
    su_apt_grub_default_kernel < "$cfg" || { echo "nu găsesc un nucleu vmlinuz-* în prima intrare din ${cfg}" >&2; return 1; }
}

default_kernel() {
    case "${PKG_MGR:-}" in
        dnf) grubby --default-kernel ;;
        apt) apt_default_kernel ;;
        *)   echo "gestionarul de pachete nu e detectat" >&2; return 1 ;;
    esac
}

# Numele fișierului initrd al unei versiuni: dracut (RHEL) vs initramfs-tools (Debian).
boot_initrd_file() {
    case "${PKG_MGR:-}" in
        apt) printf 'initrd.img-%s' "$1" ;;
        *)   printf 'initramfs-%s.img' "$1" ;;
    esac
}

# reboot_probe — aceleași coduri ca `needs-restarting -r` (0 = nu, 1 = da, altceva = necunoscut), ca su_reboot_needed_from_rc să rămână singura decizie.
apt_reboot_probe() {
    local f="${SU_REBOOT_REQUIRED:-/var/run/reboot-required}" hooks="${SU_REBOOT_HOOKS:-/usr/share/update-notifier/notify-reboot-required /etc/kernel/postinst.d/unattended-upgrades}" ex=0 hk=0 pk="" hook
    [[ -e "$f" ]] && ex=1
    # Doi scriitori ai fișierului: update-notifier-common (Ubuntu) și pachetul unattended-upgrades (Debian de bază); oricare dovedește că absența înseamnă «nu».
    for hook in $hooks; do [[ -x "$hook" ]] && hk=1; done
    case "$(su_apt_reboot_state "$ex" "$hk")" in
        yes) [[ -r "${f}.pkgs" ]] && pk="$(tr '\n' ' ' < "${f}.pkgs")"
             printf '%s există (pachete: %s)\n' "$f" "${pk:-necitite}"; return 1 ;;
        no)  printf '%s nu există\n' "$f"; return 0 ;;
        *)   printf '%s lipsește, dar niciunul dintre cârligele care l-ar scrie (%s: update-notifier-common sau unattended-upgrades) nu e instalat: absența fișierului nu dovedește că nu e nevoie de reboot\n' "$f" "$hooks"; return 2 ;;
    esac
}
reboot_probe() {
    case "${PKG_MGR:-}" in
        dnf) needs-restarting -r ;;
        apt) apt_reboot_probe ;;
        *)   echo "gestionarul de pachete nu e detectat" >&2; return 127 ;;
    esac
}

# Unitățile eșuate. Controlul pozitiv e în funcție: dacă `systemctl list-units --all`
# nu listează NIMIC, systemctl nu răspunde, iar `--failed` gol ar fi o minciună.
m_failed_units() {
    local all
    all="$(systemctl list-units --all --no-legend --plain)" || return 1
    [[ -n "$all" ]] || { echo "systemctl list-units nu a listat nimic" >&2; return 1; }
    systemctl --failed --no-legend --plain | unit_names | LC_ALL=C sort -u
}

# Serviciile care trebuie să fie sus și după: cele care RULAU și sunt activate pe
# gazdă (intersecția), plus orice sentinel-* care rula. Un serviciu pornit de mână și
# neactivat nu e o promisiune a gazdei; nu-l cerem înapoi după reboot.
m_services() {
    local run en
    run="$(systemctl list-units --type=service --state=running --no-legend --plain | unit_names | LC_ALL=C sort -u)" || return 1
    en="$(systemctl list-unit-files --type=service --state=enabled --no-legend --plain | unit_names | LC_ALL=C sort -u)" || return 1
    {
        LC_ALL=C comm -12 <(printf '%s\n' "$run") <(printf '%s\n' "$en")
        printf '%s\n' "$run" | grep '^sentinel-' || true
    } | awk 'NF' | LC_ALL=C sort -u
}

# Servicii care RULEAZĂ dar sunt `disabled`: pornite de mână, nu revin după reboot (măsurat pe
# gazdă 19 nov 2026: php82-php-fpm.service; containerd.service revine ca dependență a lui docker).
# Se raportează, nu se schimbă: activarea unui serviciu nu e treaba acestui script.
m_running_disabled() {
    local run dis
    run="$(systemctl list-units --type=service --state=running --no-legend --plain | unit_names | LC_ALL=C sort -u)" || return 1
    dis="$(systemctl list-unit-files --type=service --state=disabled --no-legend --plain | unit_names | LC_ALL=C sort -u)" || return 1
    LC_ALL=C comm -12 <(printf '%s\n' "$run") <(printf '%s\n' "$dis") | awk 'NF'
}

m_timers() {
    systemctl list-units --type=timer --state=active --no-legend --plain | unit_names | LC_ALL=C sort -u
}

# O linie pe container, TOATE (și cele oprite — nu ne privesc, dar sunt în înregistrare):
#   nume|proiect|serviciu|imagine-config|id-imagine|id-etichetă|stare|sănătate|politică|reporniri|pornit-la
# id-etichetă = ID-ul pe care îl are ACUM eticheta din imagine-config (`-` dacă nu există
# local, ca la un ID gol). Diferența dintre id-imagine și id-etichetă e faptul pe care
# se bazează `hold-moved-tag`: containerul n-a fost recreat de când eticheta s-a mutat.
# `docker image inspect` eșuează AICI în mod normal (ID gol, imagine ștearsă) și
# rezultatul e `-`; un daemon căzut ar fi căzut deja la `docker inspect` de dinainte.
m_containers() {
    local rows id name proj svc rec img imgid state health pol rcount started tag
    docker info --format '{{.ServerVersion}}' > /dev/null || return 1
    rows="$(docker ps -a --no-trunc --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}')" || return 1
    while IFS='|' read -r id name proj svc; do
        [[ -n "$id" ]] || continue
        rec="$(docker inspect -f '{{.Config.Image}}|{{.Image}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.HostConfig.RestartPolicy.Name}}|{{.RestartCount}}|{{.State.StartedAt}}' "$id")" || return 1
        IFS='|' read -r img imgid state health pol rcount started <<< "$rec"
        tag="$(docker image inspect -f '{{.Id}}' "$img" 2> /dev/null)" || tag="-"
        printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$name" "$proj" "$svc" "$img" "$imgid" "$tag" \
            "$state" "$health" "${pol:-none}" "$rcount" "$started"
    done <<< "$rows"
}

# Un cod HTTP pe vhost, prin loopback, cu `--resolve` (URL-ul poartă numele, deci nginx
# alege vhostul după el). Fără `|| echo 000`: curl tipărește el însuși 000 când eșuează,
# iar `|| echo` ar fi tipărit a doua oară.
http_code() {
    local name="$1" port="${2:-443}" code
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "${name}:${port}:127.0.0.1" "https://${name}:${port}/")" || true
    printf '%s' "$code"
}

# nume|cod, pentru fiecare vhost literal din nginx, plus sonda de sănătate a lui
# Sentinel pe loopback (fără nginx).
m_http() {
    local conf name code
    conf="$(nginx -T)" || return 1
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        printf '%s|%s\n' "$name" "$(http_code "$name")"
    done < <(printf '%s\n' "$conf" | su_vhost_names)
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${SU_WEB_PORT:-8787}/healthz")" || true
    printf 'sentinel-web-%s|%s\n' "${SU_WEB_PORT:-8787}" "$code"
}

# probe_audit_rules / probe_nft / probe_pg / probe_mariadb: un cuvânt, niciodată gol.
probe_audit_rules() {
    local n
    n="$(auditctl -l)" || { echo unknown; return 0; }
    printf '%s\n' "$n" | grep -c 'sentinel' || true
}
probe_nft() {
    local t
    t="$(nft list tables)" || { echo unknown; return 0; }
    if printf '%s\n' "$t" | grep -q '^table inet sentinel$'; then echo yes; else echo no; fi
}
probe_pg() {
    systemctl is-active --quiet postgresql.service || { echo na; return 0; }
    if (cd / && runuser -u postgres -- pg_isready -q); then echo yes; else echo no; fi
}
probe_mariadb() {
    systemctl is-active --quiet mariadb.service || { echo na; return 0; }
    if mysqladmin ping > /dev/null; then echo yes; else echo no; fi
}
m_probes() {
    printf 'audit_sentinel_rules=%s\n' "$(probe_audit_rules)"
    printf 'nft_sentinel_table=%s\n' "$(probe_nft)"
    printf 'pg_host_ready=%s\n' "$(probe_pg)"
    printf 'mariadb_host_ping=%s\n' "$(probe_mariadb)"
}

# Actualizările în așteptare, din cache (-C: nu atinge rețeaua). Gol = nimic de făcut,
# doar dacă dnf a răspuns; un cache lipsit iese cu 1 și devine `.unknown`.
m_pending() {
    local out rc=0
    if [[ "${PKG_MGR:-}" == apt ]]; then
        out="$(apt_simulate)" || return 1
        printf '%s\n' "$out" | su_apt_sim_names Inst
        return 0
    fi
    out="$(dnf -C -q check-update)" || rc=$?
    case "$(su_check_update_state "$rc")" in
        none)    ;;
        pending) printf '%s\n' "$out" | awk 'NF >= 3 && $1 ~ /\./ { print $1 }' | LC_ALL=C sort -u ;;
        *)       return 1 ;;
    esac
}

# nucleul: ce rulează, ce pornește implicit, cel mai nou instalat, boot_id.
# boot_id e dovada că o repornire chiar s-a întâmplat între baseline și verificare:
# „uptime mic" nu e dovadă, un `reboot` cerut dar neexecutat nu schimbă boot_id.
newest_installed_kernel() {
    local out running
    case "${PKG_MGR:-}" in
        apt)
            running="$(uname -r)"
            out="$(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\n' 'linux-image-[0-9]*')" || return 1
            printf '%s\n' "$out" | su_apt_kernel_versions "${running##*-}" | LC_ALL=C sort -V | tail -n 1 ;;
        dnf) rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' | LC_ALL=C sort -V | tail -n 1 ;;
        *)   return 1 ;;
    esac
}
m_kernel() {
    local def newest
    def="$(default_kernel)" || return 1
    newest="$(newest_installed_kernel)" || return 1
    [[ -n "$def" && -n "$newest" ]] || return 1
    printf 'running=%s\n' "$(uname -r)"
    printf 'default=%s\n' "$def"
    printf 'newest=%s\n' "$newest"
    printf 'boot_id=%s\n' "$(cat "${SU_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}")"
    printf 'hostname=%s\n' "$(hostname)"
}

# kv_get FILE KEY — valoarea; gol dacă lipsește.
kv_get() { awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1"; }

# take_snapshot DIR — scrie baseline-ul în DIR (un director nou, gol). Întoarce numărul
# de măsurători care n-au reușit; fiecare are un `.unknown` cu motivul.
take_snapshot() {
    local dir="$1" unknown=0
    snap_measure "$dir" "${PKG_LIST_FILE:-rpm-qa.txt}" 50 m_pkg_list || unknown=$((unknown + 1))
    snap_measure "$dir" failed-units.txt 0     m_failed_units  || unknown=$((unknown + 1))
    snap_measure "$dir" services.txt 1         m_services      || unknown=$((unknown + 1))
    snap_measure "$dir" timers.txt 1           m_timers        || unknown=$((unknown + 1))
    snap_measure "$dir" disabled-running.txt 0 m_running_disabled || unknown=$((unknown + 1))
    snap_measure "$dir" containers.tsv 0       m_containers    || unknown=$((unknown + 1))
    snap_measure "$dir" http.tsv 1             m_http          || unknown=$((unknown + 1))
    snap_measure "$dir" probes.kv 4            m_probes        || unknown=$((unknown + 1))
    snap_measure "$dir" pending.txt 0          m_pending       || unknown=$((unknown + 1))
    snap_measure "$dir" kernel.kv 5            m_kernel        || unknown=$((unknown + 1))
    printf '%s\n' "$unknown"
}
