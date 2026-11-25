#!/usr/bin/env bash
#
# Actualizarea completă a gazdei (sistem de operare + containere), în faze pe care
# operatorul le rulează pe rând. Rulează PE GAZDĂ, ca root, și nu e chemat direct:
# scripts/system-update.sh îl trimite, îi verifică suma și îl pornește. Vezi
# antetul lui scripts/system-update.sh pentru ordinea recomandată a fazelor.
#
#   system-update-host.sh preflight  [--new-baseline]
#     --new-baseline preia în baseline-ul nou rezultatele lipicioase NEREZOLVATE din containers.report-ul celui vechi (le tipărește;
#     `stale-baseline` nu se preia — îl rezolvă baseline-ul nou), iar un reboot/nucleu implicit explicat de un `os.ok` din baseline-ul
#     înlocuit nu mai refuză preflight (os -> containers -> --new-baseline -> backup -> containers -> reboot). Explicația e legată de
#     boot-ul pe care a rulat `os` (boot_id din os.ok) și se preia în baseline-ul nou (os-carried.kv): un al doilea --new-baseline înainte
#     de reboot trece la fel; după un reboot nu mai e nimic de explicat (ieșirea e `--phase reboot`, apoi un baseline curat).
#     Odată cu un eșec preluat se preia EPISODUL lui (containers.episode: sănătatea din baseline-ul eșecului, `prev`, pull-urile mentenanței, legate
#     de ID-ul episodului din containers.report): vezi carry_forward_sticky.
#   system-update-host.sh backup     [--allow-stale-srv-backup]
#   system-update-host.sh os
#   system-update-host.sh containers [--dry-run] [--rebuild L|all] [--accept-drift L]
#                                    [--only L] [--retry-failed L] [--acknowledge P/S[,P/S]] [--keep-going] [--health-timeout S] [--stable S]
#     --acknowledge P/S  recunoaștere EXPLICITĂ a unui serviciu cu o stare lipicioasă pe care n-o mai poate rezolva nicio rulare (nu mai are niciun
#                        container în baseline-ul nou — scos din compose —, ori imaginea lui nu mai poate fi adusă la starea cerută, ori containerul lui e oprit și nu-l pornești). Scrie evenimentul
#                        `acked` în jurnal (șterge stările lipicioase ale serviciului DIN EPISODUL pe care îl numește, ÎN AFARĂ DE `stale-baseline`, care se rezolvă
#                        printr-un baseline nou; un eșec NOU sau dintr-un alt episod rămâne roșu) și pune un steag durabil, legat de episodul eșecului: «recunoscut de operator, NERESOLVAT în fapt» se tipărește la FIECARE
#                        rulare (faza, verify, status), iar rezultatul spune «DOVEDIT, cu N servicii recunoscute de operator», nu «TOTUL DOVEDIT» (cod 0:
#                        un avertisment nu schimbă codul). Steagul îl șterge doar ACEEAȘI regulă care rezolvă un eșec: verdict `ok` sau `same-bad` (nu mai rău decât înainte) față de sănătatea din
#                        episod ȘI față de baseline-ul curent, la o rulare care re-verifică serviciul (un serviciu recunoscut care era deja unhealthy înainte de orice
#                        mentenanță se închide deci ca varianta nerecunoscută), ori un baseline nou în care serviciul NU mai are NICIUN container, în nicio stare («dispărut» = absent: scos din compose ori
#                        proiect dispărut; un container oprit, repornit în buclă, în pauză, creat ori mort NU a dispărut și rămâne roșu; o listă măsurată dar goală e suspectă și nu închide nimic) — atunci episodul se închide cu o linie `episode-closed` în jurnal și nimic din el nu se preia. O recunoaștere dată în
#                        baseline-ul în care a picat ține cât serviciul nu e mai rău decât starea recunoscută (nu redeschide `failed`); mai rău decât ea e roșu din nou. Starea recunoscută (`ackstate`) se măsoară și se scrie ÎN CLIPA `--acknowledge`, pentru orice cheie acceptată, indiferent dacă rularea ajunge la proiect.
#                        Niciun skip/hold/recreated/unread nu o atinge.
#                        Nu se face niciodată singură; refuzată dacă serviciul n-are nimic nerezolvat (cheie scrisă greșit). Valorile sunt
#                        chei `proiect/serviciu` (nu pot începe cu `-`), la fel ca listele de proiecte.
#     L = proiecte compose separate prin virgulă; o valoare care începe cu `-` (ex. `--rebuild --dry-run`) e refuzată cu 2,
#     iar numele trebuie să existe în baseline (la fel pentru --only, --retry-failed, --rebuild, --accept-drift; `all` doar
#     la --rebuild) — altfel faza se oprește înainte de orice atingere. `containers.ok` se scrie doar la o rulare care a
#     procesat TOATE proiectele (fără --only) și n-a lăsat nimic nerezolvat.
#     Un serviciu al cărui container rulează o imagine pe care nici baseline-ul, nici mentenanța asta n-au pus-o (redeploy
#     după baseline) are baseline VECHI (`stale-baseline`): proiectul e ținut la clasificare, înainte de pull/build/tag/up, roșu și
#     fără containers.ok, pentru ORICE fel de serviciu — până la un baseline nou (`--phase preflight --new-baseline`, apoi
#     `--phase backup` dacă are peste 12 h, apoi `--phase containers`) sau până când containerul revine pe imaginea din baseline.
#     «Pusă de mentenanță» = văzută RULÂND după un `up` al scriptului (containers.owned, `landed`), nu dedusă din `pulled`/`built`.
#     Eticheta de rollback arată imaginea pe care containerul o rula chiar înainte de prima schimbare (`prev`, scrisă înainte de tag/up).
#     `--only` peste o parte din proiecte nu scrie containers.ok și nici nu șterge unul dovedit de o rulare completă (are markerele
#     lui, containers.only.started/.ok; verify cere ca ultima rulare parțială să fi ajuns la capăt).
#   system-update-host.sh reboot     --yes [--force] [--ignore-os-state]
#   system-update-host.sh verify     [--gap S] [--wait S]
#   system-update-host.sh status
#
# Rezultatul fiecărui serviciu din faza `containers` e o stare, nu un jurnal. Un eșec rămâne în rezultat (roșu, ieșire 1,
# fără containers.ok, și în verify) până când îl rezolvă SUCCESUL LUI SPECIFIC, urmat de o verificare; nicio altă linie
# (skip, hold, dry-run, un container vechi sănătos) nu îl șterge sau îl maschează:
#   failed        recreat și picat, ori readus manual la imaginea veche: nu se mai trage și nu se mai recreează la o rulare
#                 simplă. Doar `--retry-failed L` (L = proiectele pentru care operatorul cere o nouă încercare; alt proiect
#                 rămâne neatins) urmat de o recreare dovedită și verificată îl rezolvă; la o aplicație construită local,
#                 fără --rebuild, reîncercarea doar re-verifică containerul de acum (sănătos și stabil => rezolvat). Un pull eșuat în timpul reîncercării
#                 NU îl eliberează: rămâne failed și reținut.
#   pull-failed   doar un pull reușit, apoi verificat (la `hold-config-drift`: --accept-drift L, după ce ai citit schimbarea)
#   build-failed  (și build refuzat din lipsă de spațiu, sau imagine nelizibilă după build): doar un build reușit — rulare cu
#                 `--rebuild` pentru proiect — apoi verificat; o rulare fără --rebuild nu-l șterge
#   tag-failed    eticheta de rollback n-a putut fi dovedită: se rezolvă când o rulare următoare o dovedește pe imaginea de
#                 dinainte de mentenanță — la recreare ori la re-verificarea serviciului (cu sau fără recreare) — iar
#                 containerul e sănătos
#   stale-baseline  baseline vechi pentru serviciu (redeploy de după baseline): se rezolvă când containerul rulează din nou imaginea
#                 din baseline sau una pusă de mentenanță, ori printr-un baseline nou (nu se preia în el)
#   unread        proiectul n-a putut fi citit (etichete/config compose): doar o rulare care îi citește configurația
# Ieșirea pentru orice stare lipicioasă (în afară de stale-baseline) a unui serviciu care nu mai există sau nu mai poate fi adus la starea
# cerută: `--phase containers --acknowledge PROIECT/SERVICIU` (mesajul fiecărei stări o numește). Un `failed` preluat într-un baseline nou se
# judecă față de sănătatea din episodul lui (su_container_verdict peste ea trebuie să dea `ok`, în plus față de verdictul cu baseline-ul nou); un pull-failed
# preluat nu rămâne blocat de «eticheta mutată» doar când eticheta a fost mutată chiar de pull-ul mentenanței ȘI containerul rulează încă imaginea pe care
# o rula atunci (episodul); orice altceva e hold-moved-tag. Rollback-ul unei reîncercări a unui `failed` preluat pleacă de la `prev` din episod.
# `--dry-run` nu scrie nimic, dar un eșec nerezolvat îl face să iasă 1, nu «TOTUL DOVEDIT».
# Reducerea (singura) e `su_report_final` din system-update-lib.sh; lista stărilor, SU_STICKY_SPEC.
#
# `os` și `containers`, prin `follow_run`: o unitate se socotește încheiată doar dacă `systemctl show -p ActiveState` zice
# inactive/failed de DOUĂ ori la rând și nu există rezultat; o stare necitibilă (daemon-reexec în tranzacția dnf) se așteaptă,
# cel mult SU_FOLLOW_UNREADABLE_S secunde (120), apoi e «necunoscut» (3).
#
# Gestionarul de pachete: dnf (AlmaLinux/RHEL/Rocky/Fedora) sau apt (Debian/Ubuntu), stabilit O DATĂ în init_state (pkg_detect, system-update-measure.sh)
# din /etc/os-release ȘI din binarele care trebuie să existe; preflight îl scrie în baseline (pkgmgr.kv), iar os/reboot/verify refuză un baseline luat cu
# altul. Pe orice altă gazdă fazele pe pachete ies cu 1 înainte de orice atingere. Echivalențele (fiecare cu dovada ei, nu cu codul de ieșire):
#   dnf makecache --refresh        apt-get update (ieșirea citită: `Err:`/`E:` cu cod 0 = depozit căzut)
#   dnf check-update               apt-get -s dist-upgrade (liniile Inst/Remv; «kept back»)
#   dnf upgrade --refresh -y       apt-get dist-upgrade --no-remove, DEBIAN_FRONTEND=noninteractive, --force-confdef --force-confold, DPkg::Lock::Timeout
#   dnf history (Return-Code)      /var/log/apt/history.log (bloc nou, End-Date, fără Error:)
#   rpm -qa / dnf check            dpkg-query (ii/hi) / dpkg --audit + starea fiecărui pachet + apt-get check
#   grubby --default-kernel        prima intrare din grub.cfg, doar dacă GRUB_DEFAULT=0 (altfel «nu știu»)
#   needs-restarting -r            /var/run/reboot-required (absența dovedește «nu» doar cu cârligul update-notifier-common)
#   initramfs-<v>.img              initrd.img-<v>
# Pachetele pe hold (apt-mark showhold) nu se ating și se dovedește că au rămas la fel.
#
# Regula de la care pleacă tot ce e mai jos (CLAUDE.md): fiecare pas care raportează
# succes îl raportează pe baza unui FAPT observabil, nu a intenției. Un cod de ieșire
# nu e dovadă de efect (dnf ieșit cu 0 nu dovedește un nucleu nou, `docker compose up`
# cu 0 nu dovedește că serviciul rulează imaginea nouă, `shutdown -r` cu 0 nu dovedește
# că o repornire e programată). Ce se verifică pentru fiecare pas e scris la pasul lui.
#
# Trei rezultate, nu două: 0 = nimic eșuat (linia REZULTAT spune «TOTUL DOVEDIT», sau «DOVEDIT, cu N servicii recunoscute de operator» când un
# --acknowledge stă încă în picioare: acelea rămân NERESOLVATE în fapt, iar codul 0 nu le acoperă); 1 = ceva e mai rău decât la baseline sau
# a eșuat; 3 = n-am putut măsura ceva (NU e «bine»). Un script care citește doar
# codul de ieșire nu are voie să confunde 3 cu 0.
#
# Fazele `os` și `containers` rulează într-o unitate systemd tranzitorie, nu în sesiunea
# ssh: o sesiune căzută în mijlocul unei tranzacții rpm lasă baza de pachete la
# jumătate. Ieșirea merge într-un fișier din runs/ (nu într-o conductă care se poate
# rupe), iar rezultatul — un fișier `.result` scris la ieșire — e ce citește firul din
# sesiune; lipsa lui e «necunoscut», nu «reușit».
#
# Despre vps-watchdog: NU se oprește. Un temporizator oprit și uitat e un canal de
# alertare mut, exact eșecul pe care îl evită toată infrastructura de aici; zgomotul
# (mesaje Telegram la recrearea containerelor și la repornire) e doar neplăcut, iar
# watchdog-ul tratează deja recrearea prin `docker compose up` (vezi comentariile din
# deploy/vps-watchdog/watchdog.sh). Verify cere ca temporizatorul să fie activ după.

set -euo pipefail

SU_SELF="${BASH_SOURCE[0]}"
SU_HERE="$(cd "$(dirname "$SU_SELF")" && pwd)"
SU_SELF="${SU_HERE}/$(basename "$SU_SELF")"
# shellcheck source=system-update-lib.sh
source "${SU_HERE}/system-update-lib.sh"
# shellcheck source=system-update-measure.sh
source "${SU_HERE}/system-update-measure.sh"
# shellcheck source=system-update-containers.sh
source "${SU_HERE}/system-update-containers.sh"
# shellcheck source=system-update-verify.sh
source "${SU_HERE}/system-update-verify.sh"

SU_STATE="${SU_STATE:-/var/lib/sentinel-maint}"
SU_RUN_DIR="${SU_RUN_DIR:-/run}"
MIN_FREE_GB="${SU_MIN_FREE_GB:-15}"
MIN_BOOT_FREE_MB="${SU_MIN_BOOT_FREE_MB:-300}"
MIN_DUMP_BYTES="${SU_MIN_DUMP_BYTES:-500}"
BACKUP_MAX_AGE_S="${SU_BACKUP_MAX_AGE_S:-43200}"            # 12 h
SRV_BACKUP_STATE="${SU_SRV_BACKUP_STATE:-/var/lib/srv-backup/last-success}"
SRV_BACKUP_MAX_AGE_S="${SU_SRV_BACKUP_MAX_AGE_S:-93600}"    # 26 h, ca în container-update.sh
HEALTH_TIMEOUT_S="${SU_HEALTH_TIMEOUT_S:-300}"
STABLE_S="${SU_STABLE_S:-30}"
GAP_S="${SU_GAP_S:-45}"
WAIT_S="${SU_WAIT_S:-300}"
POLL_S="${SU_POLL_S:-5}"
FOLLOW_S="${SU_FOLLOW_S:-2}"
FOLLOW_CONFIRM_S="${SU_FOLLOW_CONFIRM_S:-1}"        # distanța dintre cele două citiri «inactive» care încheie o unitate
FOLLOW_UNREADABLE_S="${SU_FOLLOW_UNREADABLE_S:-120}"  # cât se așteaptă o stare necitibilă (daemon-reexec durează secunde)

PHASE=""
RUN_ID="${SU_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RESULT_FILE=""; RESULT_WRITTEN=0; LOG_FILE=""
BASE=""
ORIG_ARGS=()
OPT_IGNORE_OS_STATE=0; OPT_NEW_BASELINE=0; OPT_STALE_OK=0; OPT_DRY_RUN=0; OPT_YES=0; OPT_FORCE=0; OPT_KEEP_GOING=0
OPT_REBUILD=""; OPT_ACCEPT_DRIFT=""; OPT_ONLY=""; OPT_RETRY_FAILED=""; OPT_ACKNOWLEDGE=""

# Gestionarul de pachete (dnf | apt | unknown): detectat o dată, în init_state, din /etc/os-release + binare (pkg_detect, system-update-measure.sh).
PKG_MGR=""; PKG_WHY=""; PKG_OS_ID=""; PKG_OS_LIKE=""; PKG_DB=rpm; PKG_LIST_FILE=rpm-qa.txt; PKG_LIST_CMD="rpm -qa"
KLIST_CMD="rpm -q kernel-core"; KDEF_NAME=grubby; KDEF_CMD="grubby --default-kernel"; REBOOT_PROBE_NAME="needs-restarting -r"
APT_LOCK_TIMEOUT_S="${SU_APT_LOCK_TIMEOUT_S:-900}"     # cât așteaptă apt-get blocarea dpkg și cât se reîncearcă `update` (unattended-upgrades pornește zilnic, la ore aleatorii)
# Ce arată că o tranzacție apt rulează ACUM: blocările pe care le iau apt/dpkg (NU numele proceselor: `unattended-upgrade-shutdown` stă pornit luni întregi,
# iar packagekitd rămâne ~5 min după fiecare `apt-get update`, fără nicio blocare) și unitățile care pornesc `apt-get update`/`unattended-upgrade`.
APT_LOCK_FILES="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"
APT_TXN_UNITS="apt-daily.service apt-daily-upgrade.service"

WARN_N=0; FAIL_N=0; UNK_N=0
ACK_N=0    # servicii recunoscute de operator (--acknowledge) și încă nerezolvate în fapt: rezultatul spune asta, nu «TOTUL DOVEDIT»
BAD_LIST=(); UNK_LIST=(); SAME_LIST=(); CHANGED_LIST=(); SKIP_LIST=()

# ---------------------------------------------------------------------------
# Ieșire
# ---------------------------------------------------------------------------
say_info() { printf '[.] %s\n' "$*"; }
say_ok()   { printf '[+] %s\n' "$*"; }
say_warn() { WARN_N=$((WARN_N + 1)); printf '[!] %s\n' "$*"; }
say_bad()  { FAIL_N=$((FAIL_N + 1)); BAD_LIST+=("$*"); printf '[x] %s\n' "$*"; }
say_unk()  { UNK_N=$((UNK_N + 1)); UNK_LIST+=("$*"); printf '[?] %s\n' "$*"; }
say_sect() { printf '\n== %s ==\n' "$*"; }

write_result() {
    local status="$1" rc="$2" item
    [[ -n "$RESULT_FILE" ]] || return 0
    {
        # `dry_run=1`: o simulare nu schimbă nimic, deci rezultatul ei nu intră în verdictul lui `status` (care citește ultimul rezultat REAL al fazei).
        printf 'phase=%s\nrun=%s\nstatus=%s\nrc=%s\nfinished=%s\nfail=%s\nunknown=%s\nwarn=%s\ndry_run=%s\n' \
            "$PHASE" "$RUN_ID" "$status" "$rc" "$(date +%s)" "$FAIL_N" "$UNK_N" "$WARN_N" "$OPT_DRY_RUN"
        for item in ${BAD_LIST[@]+"${BAD_LIST[@]}"}; do printf 'bad=%s\n' "${item//$'\n'/ }"; done
        for item in ${UNK_LIST[@]+"${UNK_LIST[@]}"}; do printf 'unknown_item=%s\n' "${item//$'\n'/ }"; done
    } > "${RESULT_FILE}.tmp" && mv -f "${RESULT_FILE}.tmp" "$RESULT_FILE"
    RESULT_WRITTEN=1
}

# Un exit pe care nu l-a ales faza (set -e, kill) tot scrie un rezultat — `aborted`,
# cod nenul — ca firul din sesiune să nu citească tăcerea drept «reușit».
on_exit() {
    local rc=$?
    if (( ! RESULT_WRITTEN )) && [[ -n "$RESULT_FILE" ]]; then
        (( rc == 0 )) && rc=1
        write_result aborted "$rc" || true
    fi
}
trap on_exit EXIT

finish() {
    local rc=0 status=ok label="TOTUL DOVEDIT"
    if (( FAIL_N > 0 )); then rc=1; status=fail; label="EȘEC"
    elif (( UNK_N > 0 )); then rc=3; status=unknown; label="NECUNOSCUT (ceva n-a putut fi măsurat; asta NU e «bine»)"
    fi
    # Cod 0 cu recunoașteri în picioare: un avertisment nu schimbă codul (ca orice alt avertisment), dar «TOTUL DOVEDIT» ar fi fals peste un serviciu
    # pe care operatorul l-a recunoscut ca nerezolvat.
    if (( rc == 0 && ACK_N > 0 )); then label="DOVEDIT, cu ${ACK_N} servicii recunoscute de operator (NERESOLVATE în fapt)"; fi
    printf '\nREZULTAT %s: %s — %s probleme, %s necunoscute, %s avertismente\n' \
        "$PHASE" "$label" "$FAIL_N" "$UNK_N" "$WARN_N"
    write_result "$status" "$rc"
    exit "$rc"
}

die() { say_bad "$*"; finish; }

have() { command -v "$1" > /dev/null 2>&1; }
now_epoch() { date +%s; }
mib() { awk -v b="${1:-0}" 'BEGIN { printf "%.1f MiB", b / 1048576 }'; }

need_root() { [[ "$(id -u)" == 0 ]] || die "trebuie rulat ca root (îl pornește system-update.sh cu sudo)"; }

# take_lock VAR PATH ETICHETĂ — fd deschis, flock neblocant. Reținut până la ieșire.
# Descriptorii de blocare deschiși de acest proces. Un copil care îi moștenește (dnf pornește servicii
# prin scriptletele rpm, iar un daemon rămas în viață ține blocarea PENTRU TOTDEAUNA) ar face ca
# rulările următoare să spună «în curs» la nesfârșit — de aceea comenzile lungi trec prin `nolock`.
LOCK_FDS=()
nolock() {
    local fd redirs=""
    for fd in ${LOCK_FDS[@]+"${LOCK_FDS[@]}"}; do redirs+=" ${fd}>&-"; done
    eval '"$@"'"$redirs"
}

take_lock() {
    local var="$1" path="$2" label="$3"
    have flock || die "flock lipsește de pe gazdă — nu pot exclude rulările concurente"
    mkdir -p "$(dirname "$path")"
    exec {fd}>> "$path" || die "nu pot deschide ${path}"
    printf -v "$var" '%s' "$fd"
    LOCK_FDS+=("$fd")
    flock -n "$fd" || die "${label} e în curs (blocare ${path}); nu rulez peste el"
}

# ---------------------------------------------------------------------------
# Stare pe disc
# ---------------------------------------------------------------------------
init_state() {
    umask 077
    mkdir -p "${SU_STATE}/runs" "${SU_STATE}/snapshots" "${SU_STATE}/dumps"
    chmod 0700 "$SU_STATE"
    RESULT_FILE="${SU_STATE}/runs/${PHASE}-${RUN_ID}.result"
    LOG_FILE="${SU_STATE}/runs/${PHASE}-${RUN_ID}.log"
    [[ -L "${SU_STATE}/current" ]] && BASE="$(readlink -f "${SU_STATE}/current")" || BASE=""
    pkg_detect
}

# Fazele care ating pachetele (preflight, os, reboot, verify) cer un gestionar DETECTAT din fapte. Pe o gazdă care nu e nici dnf, nici apt, refuză cu
# ieșire 1 înainte de orice atingere: a alege unul «cel mai apropiat» ar rula comenzile greșite peste o gazdă de producție.
pkg_require() {
    case "$PKG_MGR" in
        dnf|apt) return 0 ;;
    esac
    die "nu pot stabili gestionarul de pachete al gazdei: ${PKG_WHY:-necunoscut}. Sunt acceptate doar dnf (AlmaLinux/RHEL/Rocky/Fedora) și apt (Debian/Ubuntu); refuz, nu ghicesc"
}

# Baseline-ul își notează gestionarul (pkgmgr.kv, scris la preflight): un baseline luat sub apt nu se judecă cu dnf sau invers. Un baseline FĂRĂ
# pkgmgr.kv e unul din vremea în care exista doar dnf — se acceptă doar pe o gazdă dnf.
pkg_check_baseline() {
    local rec=""
    [[ -f "${BASE}/pkgmgr.kv" ]] && rec="$(kv_get "${BASE}/pkgmgr.kv" manager)"
    if [[ -z "$rec" ]]; then
        [[ "$PKG_MGR" == dnf ]] || die "baseline-ul ${BASE##*/} n-are pkgmgr.kv (luat înainte de suportul apt), iar gazda e ${PKG_MGR} — rulează întâi: preflight --new-baseline"
        return 0
    fi
    [[ "$rec" == "$PKG_MGR" ]] || die "baseline-ul ${BASE##*/} a fost luat cu ${rec}, dar gazda e acum ${PKG_MGR} — nu le judec unul cu celălalt; rulează: preflight --new-baseline"
}

require_pkg_baseline() { require_baseline; pkg_require; pkg_check_baseline; }

# Faza cere un baseline COMPLET: fără el, «nu mai rău decât înainte» n-are față de ce.
require_baseline() {
    [[ -n "$BASE" && -f "${BASE}/COMPLETE" ]] \
        || die "nu există un baseline complet în ${SU_STATE}/current — rulează întâi: preflight"
}

# Un `.started` nou șterge `.ok`-ul rulării de dinainte: o a doua rulare căzută n-are voie să
# moștenească reușita primei.
mark_phase() { mkdir -p "${BASE}/phases"; [[ "$1" != *.started ]] || rm -f "${BASE}/phases/${1%.started}.ok"; printf 'run=%s\nepoch=%s\n' "$RUN_ID" "$(now_epoch)" > "${BASE}/phases/${1}"; }

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
pf_check_dnf_idle() {
    local rc=0 found
    found="$(pgrep -x -a 'dnf|dnf-3|yum|rpm|packagekitd|dnf-automatic')" || rc=$?
    case "$rc" in
        1) say_ok "dnf/rpm nu rulează acum" ;;
        0) say_bad "dnf/rpm rulează deja (${found//$'\n'/; }) — aștept să se termine; nu pornesc o a doua tranzacție" ;;
        *) say_bad "nu pot afla dacă dnf rulează (pgrep a întors ${rc}) — refuz, nu ghicesc" ;;
    esac
    if [[ -e /var/run/dnf.pid ]]; then
        say_bad "/var/run/dnf.pid există — o tranzacție dnf e în curs sau a rămas agățată"
    fi
}

# apt_busy_now — rulează ACUM o tranzacție apt? Iese cu 0 (ocupat; motivele pe stdout), 1 (liber) sau 2 (nu pot afla).
# Întrebarea e «ține cineva blocarea dpkg/apt?», nu «există un proces cu numele apt?»: măsurat pe n8n.srv1051579.hstgr.cloud (24 nov 2026), procesul
# `unattended-upgrade-shutdown --wait-for-signal` (pid 829) rulează de 37 de zile fără nicio blocare, iar packagekitd rămâne ~5 min după fiecare `apt-get
# update` tot fără blocări; o potrivire pe nume ar fi făcut preflight/os/reboot să aștepte 300 s și să iasă 1 de fiecare dată. `lslocks` (util-linux)
# citește blocările din nucleu (și POSIX, cum ia dpkg, și flock) fără să le ia; e în util-linux, deci pe orice Debian/Ubuntu. Fără el: «nu pot afla» (2).
apt_busy_now() {
    local out why="" u st
    if have lslocks; then
        out="$(lslocks -n -o COMMAND,PID,PATH)" || return 2
        why="$(awk -v files=" ${APT_LOCK_FILES} " 'NF >= 3 { p = $NF; if (index(files, " " p " ")) print $1 " (pid " $(NF - 1) ") ține " p }' <<< "$out")"
    else
        printf 'lslocks (util-linux) lipsește de pe gazdă'; return 2     # fără el nu citim blocările: «nu pot afla», nu «liber»
    fi
    for u in $APT_TXN_UNITS; do
        st="$(systemctl show -p ActiveState --value "$u")" || return 2
        case "$st" in active|activating|deactivating|reloading) why+="unitatea ${u} e ${st}"$'\n' ;; esac
    done
    printf '%s' "$why"
    [[ -z "$why" ]] || return 0
    return 1
}

# apt: așteptare MĂRGINITĂ, nu refuz pe loc. `unattended-upgrades` pornește zilnic (apt-daily-upgrade.timer, ore aleatorii: 06:11 azi, 06:46 mâine) și ține blocarea
# dpkg; o actualizare pornită în fereastra lui trebuie să aștepte, nu să cadă și nici să se bată cu el. După SU_APT_IDLE_WAIT_S secunde fără liniște, e roșu.
# `apt-get dist-upgrade` primește și `-o DPkg::Lock::Timeout` pentru cursa dintre verificare și pornire.
pf_check_apt_idle() {
    local rc found waited=0 limit="${SU_APT_IDLE_WAIT_S:-300}" step="${SU_APT_IDLE_STEP_S:-5}"
    while :; do
        rc=0; found="$(apt_busy_now)" || rc=$?
        case "$rc" in
            1) if (( waited > 0 )); then say_ok "apt/dpkg s-au liniștit după ${waited}s (nicio blocare apt/dpkg)"; else say_ok "nicio tranzacție apt/dpkg nu rulează (nicio blocare ținută)"; fi
               return 0 ;;
            0) ;;
            *) say_bad "nu pot afla dacă o tranzacție apt/dpkg rulează (${found:-lslocks/systemctl au eșuat}) — refuz, nu ghicesc"; return 0 ;;
        esac
        if (( waited >= limit )); then
            say_bad "o tranzacție apt/dpkg rulează încă după ${waited}s (${found//$'\n'/; }) — nu pornesc o a doua tranzacție; reia după ce se termină (unattended-upgrades?)"
            return 0
        fi
        (( waited > 0 )) || say_info "o tranzacție apt/dpkg rulează (${found//$'\n'/; }) — aștept până la ${limit}s să se termine"
        sleep "$step"; waited=$((waited + step))
        (( step > 0 )) || waited=$((waited + 1))
    done
}

pf_check_pkg_idle() {
    case "$PKG_MGR" in
        apt) pf_check_apt_idle ;;
        *)   pf_check_dnf_idle ;;
    esac
}

# Un baseline NOU luat cu --new-baseline după ce faza `os` a reușit (calea documentată când `containers` refuză un serviciu cu baseline
# vechi: os -> containers -> --new-baseline -> backup -> containers -> reboot) vede un reboot în așteptare și un nucleu implicit diferit
# de cel care rulează — fiindcă tocmai `os` le-a produs. Fără excepția asta calea ar fi închisă: preflight ar refuza «un reboot e DEJA
# necesar» pe urma propriei actualizări. Explicația cere TOATE: --new-baseline dat de operator, `os.ok` (succes dovedit) în baseline-ul
# înlocuit, și niciun `reboot.requested` (după un reboot cerut, o stare de «reboot necesar» nu mai e explicată de `os`).
# Explicația e legată de ACEST boot: `os.ok` poartă boot_id-ul pe care a rulat faza (phase_os îl scrie), iar o explicație valabilă îl are egal cu
# cel de acum. Un reboot ulterior (boot_id diferit) a consumat reboot-ul pe care `os` îl lăsase: o nevoie de reboot apărută după el e o
# problemă separată, nu «urma lui os». Un `os.ok` fără boot_id (scris altfel) sau un boot_id necitibil NU explică nimic: necunoscut nu e «explicat».
# Ce NU distinge: o altă actualizare (de pildă timerul săptămânal) care cere reboot în ACELAȘI boot, după `os`.
current_boot_id() { cat "${SU_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}" || true; }

# pf_os_boot_of DIRECTOR_BASELINE — boot_id-ul pe care `os` a fost dovedit în baseline-ul acesta (direct, `phases/os.ok`, ori preluat într-un
# baseline nou, `os-carried.kv`); nimic dacă n-a existat `os` dovedit sau dacă s-a cerut deja un reboot (el consumă explicația).
pf_os_boot_of() {
    local d="${1:-}"
    [[ -n "$d" && -d "$d" && ! -f "${d}/phases/reboot.requested" ]] || return 0
    if [[ -f "${d}/phases/os.ok" ]]; then kv_get "${d}/phases/os.ok" boot_id
    elif [[ -f "${d}/os-carried.kv" ]]; then kv_get "${d}/os-carried.kv" boot_id
    fi
}

pf_reboot_explained_by_os() {
    local rec live
    (( OPT_NEW_BASELINE )) || return 1
    rec="$(pf_os_boot_of "$BASE")"; live="$(current_boot_id)"
    [[ -n "$rec" && -n "$live" && "$rec" == "$live" ]]
}

# carry_forward_os_explanation BASELINE_VECHI BASELINE_NOU — baseline-ul nou nu are `phases/` (nu a rulat nicio fază), deci un al doilea
# `--new-baseline` înainte de reboot (de pildă un al doilea `stale-baseline`) n-ar mai avea ce să explice reboot-ul pe care `os` l-a lăsat și
# ar fi refuzat. Explicația se preia ca fapt separat (`os-carried.kv`, NU un `os.ok`: verify n-are voie să citească în baseline-ul nou o fază `os`
# care n-a rulat sub el), doar cât ESTE valabilă acum (același boot, niciun reboot cerut). Un reboot o stinge; ieșirea e atunci `--phase reboot`.
carry_forward_os_explanation() {
    local old="${1:-}" new="${2:-}" rec live
    [[ -n "$old" && -n "$new" && "$old" != "$new" ]] || return 0
    rec="$(pf_os_boot_of "$old")"; live="$(current_boot_id)"
    [[ -n "$rec" && -n "$live" && "$rec" == "$live" ]] || return 0
    printf 'from=%s\nboot_id=%s\n' "${old##*/}" "$rec" > "${new}/os-carried.kv"
    say_info "explicația «reboot-ul îl cere faza os» s-a preluat în baseline-ul nou (același boot); valabilă până la reboot. Reboot-ul rămâne de făcut: --phase reboot"
}

pf_check_pending_reboot() {
    local out rc=0 state def running first_line
    out="$(reboot_probe 2>&1)" || rc=$?
    first_line="$(awk 'NR == 1' <<< "$out")"   # prima linie, fără conductă care se poate închide
    state="$(su_reboot_needed_from_rc "$rc")"
    case "$state" in
        no)  say_ok "niciun reboot în așteptare (${REBOOT_PROBE_NAME})" ;;
        yes) if pf_reboot_explained_by_os; then
                 say_warn "un reboot e necesar (${first_line}), dar baseline-ul înlocuit are faza os încheiată cu succes dovedit (os.ok) și niciun reboot cerut: îl explică actualizarea de sistem de acum, nu o problemă separată. Reboot-ul rămâne de făcut (--phase reboot) după ce containerele sunt la zi"
             else
                 say_bad "un reboot e DEJA necesar, înainte de orice schimbare de-a noastră: ${first_line}. Nu ghicesc dacă are legătură cu actualizarea — decide separat (repornește sau investighează), apoi rulează din nou preflight"
             fi ;;
        *)   say_bad "nu pot afla dacă un reboot e în așteptare (${REBOOT_PROBE_NAME} a ieșit cu ${rc}: ${first_line}) — refuz, nu ghicesc" ;;
    esac
    running="$(uname -r)"
    def="$(default_kernel)" || def=""
    su_kernel_matches_default "$running" "$def" && rc=0 || rc=$?
    case "$rc" in
        0) say_ok "nucleul care rulează (${running}) e cel implicit la pornire" ;;
        1) if pf_reboot_explained_by_os; then
               say_warn "nucleul care rulează (${running}) NU e cel implicit la pornire (${def}): îl explică faza os încheiată cu succes dovedit (os.ok) în baseline-ul înlocuit; nucleul nou devine activ la --phase reboot"
           else
               say_bad "nucleul care rulează (${running}) NU e cel implicit la pornire (${def}) — o repornire nefinalizată; lămurește-o înainte"
           fi ;;
        *) say_bad "nu pot citi nucleul implicit (${KDEF_CMD}) — refuz, nu ghicesc" ;;
    esac
}

pf_check_disk() {
    local root_kb boot_kb
    root_kb="$(df -Pk / | awk 'NR == 2 { print $4 }')" || root_kb=""
    boot_kb="$(df -Pk /boot | awk 'NR == 2 { print $4 }')" || boot_kb=""
    if [[ ! "$root_kb" =~ ^[0-9]+$ ]]; then
        say_bad "nu pot citi spațiul liber pe / (df)"
    elif (( root_kb / 1048576 < MIN_FREE_GB )); then
        say_bad "pe / sunt liberi $((root_kb / 1048576)) GB, minim ${MIN_FREE_GB} GB (pachete + imagini + dump-uri)"
    else
        say_ok "pe / sunt liberi $((root_kb / 1048576)) GB (minim ${MIN_FREE_GB})"
    fi
    if [[ ! "$boot_kb" =~ ^[0-9]+$ ]]; then
        say_bad "nu pot citi spațiul liber pe /boot (df)"
    elif (( boot_kb / 1024 < MIN_BOOT_FREE_MB )); then
        say_bad "pe /boot sunt liberi $((boot_kb / 1024)) MB, minim ${MIN_BOOT_FREE_MB} MB — un nucleu nou nu încape"
    else
        say_ok "pe /boot sunt liberi $((boot_kb / 1024)) MB (minim ${MIN_BOOT_FREE_MB})"
    fi
}

# `skip_if_unavailable=False` e setarea globală a gazdei (măsurat 19 nov 2026): un
# depozit care nu răspunde (remi-modular a dat timeout în acea zi) face ca
# `dnf upgrade --refresh` să cadă întreg. Aflat aici, nu la jumătatea ferestrei.
# NU se adaugă `--setopt=skip_if_unavailable=True`: ar actualiza pe metadate parțiale.
pf_check_repos() {
    case "$PKG_MGR" in
        apt) pf_check_repos_apt ;;
        *)   pf_check_repos_dnf ;;
    esac
}

# apt-get update: scrie doar în /var/lib/apt/lists. Codul 0 NU dovedește că toate listele s-au adus (un depozit căzut dă adesea doar «W: Failed to fetch»
# și 0), deci ieșirea se citește: orice `Err:`, `E:` sau «Failed to fetch» e roșu — nu rulăm upgrade-ul pe liste parțiale (aceeași regulă ca la dnf).
# `apt-get update` NU primește `-o DPkg::Lock::Timeout`: opțiunea e a blocării dpkg, iar apt 2.8.4 ia blocarea listelor (/var/lib/apt/lists/lock) fără timeout și iese
# imediat cu «Could not get lock». De aceea așteptarea e aici: o reîncercare mărginită (APT_LOCK_TIMEOUT_S) DOAR pe eroarea de blocare a listelor; orice altă
# eroare (depozit căzut, rețea) nu se reîncearcă.
apt_refresh() {
    local rc waited=0 step="${SU_APT_IDLE_STEP_S:-5}"
    while :; do
        rc=0
        APT_REFRESH_OUT="$(timeout 1200 apt-get update -o APT::Update::Error-Mode=any 2>&1)" || rc=$?
        APT_REFRESH_RC="$rc"
        if (( rc != 0 && waited < APT_LOCK_TIMEOUT_S )) && grep -qE 'Could not get lock /var/lib/apt/lists/lock|Unable to lock directory /var/lib/apt/lists' <<< "$APT_REFRESH_OUT"; then
            sleep "$step"; waited=$((waited + step))
            (( step > 0 )) || waited=$((waited + 1))
            continue
        fi
        break
    done
    (( rc == 0 )) || return 1
    if grep -qE '^(Err:|E: |W: (Failed to fetch|Some index files failed))' <<< "$APT_REFRESH_OUT"; then return 1; fi
    return 0
}

pf_check_repos_apt() {
    say_info "reîmprospătez listele apt (scrie doar în /var/lib/apt/lists)"
    if apt_refresh; then
        say_ok "toate depozitele au răspuns (apt-get update, fără Err:/E:)"
    else
        say_bad "apt-get update a eșuat sau a raportat depozite căzute (cod ${APT_REFRESH_RC}): $(grep -E '^(Err:|E: |W: )' <<< "$APT_REFRESH_OUT" | tail -n 3 | tr '\n' ' ') — nu rulez actualizarea pe liste parțiale"
    fi
}

pf_check_repos_dnf() {
    local out rc=0
    say_info "reîmprospătez metadatele dnf (scrie doar în /var/cache/dnf)"
    out="$(timeout 1200 dnf -q makecache --refresh 2>&1)" || rc=$?
    if (( rc == 0 )); then
        say_ok "toate depozitele au răspuns (dnf makecache --refresh)"
    else
        say_bad "dnf makecache --refresh a eșuat (cod ${rc}): $(printf '%s' "$out" | tail -n 3 | tr '\n' ' ') — nu rulez actualizarea pe depozite parțiale"
    fi
}

pf_check_docker() {
    local v
    if v="$(docker info --format '{{.ServerVersion}}')" && [[ -n "$v" ]]; then
        say_ok "docker răspunde (${v})"
    else
        say_bad "docker nu răspunde — nu pot înregistra containerele"
    fi
    docker compose version --short > /dev/null || say_bad "plugin-ul docker compose lipsește sau nu rulează"
}

pf_check_idle_locks() {
    local fd rc
    for lock in "srv-backup.lock:backup-ul zilnic" "container-update.lock:actualizarea săptămânală a containerelor"; do
        exec {fd}>> "${SU_RUN_DIR}/${lock%%:*}" || { say_bad "nu pot deschide ${SU_RUN_DIR}/${lock%%:*}"; continue; }
        rc=0; flock -n "$fd" || rc=$?
        exec {fd}>&-
        if (( rc == 0 )); then say_ok "${lock#*:} nu rulează"; else say_bad "${lock#*:} rulează acum (${SU_RUN_DIR}/${lock%%:*} e blocat)"; fi
    done
}

# Reperele timpului, ca să nu fie nicio surpriză: zgomotul de Telegram din fereastră.
pf_note_watchdog() {
    local st
    st="$(systemctl is-active vps-watchdog.timer || true)"
    say_info "vps-watchdog.timer: ${st}. Rămâne PORNIT (decizie: un watchdog oprit și uitat e alertare mută)."
    say_info "Așteaptă mesaje Telegram în fereastră: la recrearea containerelor și la repornire (~3-5 min)."
}

# Actualizarea săptămânală a containerelor (container-update-*.timer) împarte cu această fază
# blocarea /run/container-update.lock. Eticheta de rollback a acesteia e `rollback/<proiect>-<serviciu>:prev`;
# aici se folosește `rollback/maint-<baseline>/…`, ca niciuna să n-o suprascrie pe cealaltă.
# Se raportează, nu se schimbă (temporizatoarele gazdei nu sunt ale acestui script).
pf_note_container_update() {
    local out n first
    if ! out="$(systemctl list-timers 'container-update-*' --all --no-legend --plain)"; then
        say_unk "nu pot citi temporizatoarele container-update-* — nu știu dacă una pornește în fereastră"; return 0
    fi
    n="$(awk 'NF' <<< "$out" | wc -l)"
    if (( n == 0 )); then say_info "niciun temporizator container-update-*"; return 0; fi
    first="$(awk 'NF { print; exit }' <<< "$out")"
    say_warn "${n} temporizatoare container-update-* (actualizarea săptămânală a containerelor), prima: ${first}. Ține aceeași blocare (/run/container-update.lock) — dacă pornește cât rulează faza, ea așteaptă ori faza refuză; etichetele de rollback sunt separate (rollback/maint-<baseline>/…)"
}

# Markerele de schimbare din baseline-ul curent (unul pe linie; nimic = baseline-ul e curat).
# `.started`, nu `.ok`: o fază eșuată la jumătate a schimbat deja ceva.
baseline_overwrite_markers() {
    local p
    [[ -n "$BASE" && -d "${BASE}/phases" ]] || return 0
    for p in os.started containers.started containers.only.started reboot.requested; do
        [[ -f "${BASE}/phases/${p}" ]] && printf '%s
' "$p"
    done
    return 0
}

phase_preflight() {
    need_root; pkg_require
    say_sect "Preflight"
    pf_check_pkg_idle
    pf_check_pending_reboot
    pf_check_disk
    pf_check_docker
    pf_check_idle_locks
    pf_check_repos
    pf_note_watchdog
    pf_note_container_update

    # Un nou baseline peste unul de dinainte de schimbări ar șterge exact martorul
    # față de care se judecă schimbările.
    if (( ! OPT_NEW_BASELINE )); then
        local p
        while IFS= read -r p; do
            [[ -n "$p" ]] && say_bad "baseline-ul existent are deja schimbări peste el (${p%%.*}); un nou preflight l-ar înlocui cu starea de DUPĂ. Dacă vrei asta dinadins: --new-baseline"
        done < <(baseline_overwrite_markers)
    fi

    if (( FAIL_N > 0 )); then
        say_info "nu înregistrez baseline-ul cât timp există motive de refuz"
        finish
    fi
    snapshot_and_publish "$BASE"
    finish
}

# carry_forward_sticky BASELINE_VECHI BASELINE_NOU — un baseline nou nu are voie să ierte în tăcere un eșec nerezolvat al celui vechi.
# Rezultatul FINAL (su_report_final) al fiecărui serviciu din containers.report-ul vechi, dacă e o stare lipicioasă, se scrie în jurnalul
# celui nou cu aceeași stare (se rezolvă la fel: prin succesul lui specific, urmat de verificare) și se tipărește. Excepție:
# `stale-baseline` — spune ceva despre baseline-ul VECHI, iar cel nou, luat din starea de acum, îl rezolvă prin definiție.
# Se preia, nu se refuză: calea spre un baseline nou e chiar ieșirea pe care o prescrie `stale-baseline`; un refuz ar bloca-o, iar
# un steag de confirmare ar fi încă un drum de cod. Preflight rămâne verde (baseline-ul s-a publicat), dar avertizează tare.
#
# Un eșec preluat se judecă după INTRĂRILE față de care a fost judecat în baseline-ul care l-a produs (episodul lui), nu după starea de ACUM a
# serviciului și nu după o valoare derivată din ele. Intrările stau în `containers.episode` (vezi su_episode_of în system-update-lib.sh): sănătatea
# serviciului în baseline-ul eșecului, imaginea lui, `prev` (imaginea de dinainte de schimbarea noastră) și pull-urile noastre (TAG mutat, RUN la acel
# moment). Reguli:
#   * se preiau DOAR episoadele stărilor încă nerezolvate: linia din jurnal poartă ID-ul episodului (`[episod=ID] `), iar o înregistrare a unui episod
#     rezolvat (sau a unuia din care a rămas alt eșec, cu alt ID) nu are nicio linie vie, deci nu se mai copiază;
#   * un eșec deja preluat își păstrează episodul ORIGINAL printr-un lanț de baseline-uri noi (înregistrările se copiază ca atare, cu același ID);
#   * un eșec produs în baseline-ul vechi are episodul lui, numit după el, scris acum din faptele lui nemodificabile (containers.tsv, containers.owned):
#     lipsa unui rând în containers.tsv înseamnă «sănătate necunoscută» (neînregistrată), nu «sănătos» — classify_services nu îl poate rezolva.
carry_forward_sticky() {
    local old="${1:-}" new="${2:-}" key st det n=0 dropped=0 proj svc ep inner oldname seen=" " closed=" "
    [[ -n "$old" && -n "$new" && "$old" != "$new" && -s "${old}/containers.report" ]] || return 0
    oldname="${old##*/}"
    # Recunoașterile VII (steagul `acked`, încă neșters de un verdict) se preiau PRIMELE, pe episod: o recunoaștere nu dispare pentru că s-a luat un baseline nou (eșecul pe
    # care îl acoperă e tot nerezolvat). Ordinea contează doar într-un caz: o stare lipicioasă vie a ACELUIAȘI episod care a venit DUPĂ recunoaștere (serviciul s-a înrăutățit
    # peste ce s-a recunoscut) trebuie să rămână roșie; scrisă după `acked`, nu o mai șterge nimic. Episoadele DIFERITE nu depind de ordine (su_report_final).
    # Un steag coborât (`ack-cleared`) nu are linie vie, deci nu se mai preia.
    while IFS='|' read -r key ep; do
        proj="${key%%/*}"; svc="${key#*/}"
        if [[ "$ep" == "-" ]]; then ep="$oldname"; fi
        if carry_close_if_gone "$key" "$ep"; then continue; fi
        if [[ "$seen" != *" ${key}|${ep} "* ]]; then
            if [[ "$ep" == "$oldname" ]]; then write_episode_records "$old" "$new" "$proj" "$svc" "$ep"; else carry_episode_records "$old" "$new" "$proj" "$svc" "$ep"; fi
            seen+="${key}|${ep} "
        fi
        printf '%s|%s|acked|[episod=%s] preluat din baseline-ul %s: recunoscut de operator, încă nerezolvat\n' "$proj" "$svc" "$ep" "$oldname" >> "${new}/containers.report"
        say_warn "recunoaștere a operatorului preluată în baseline-ul nou: ${key} (episodul ${ep}) — NERESOLVAT în fapt până la un verdict ok sau same-bad față de episod și baseline"
    done < <(su_report_final "${old}/containers.report" ackeps)
    while IFS='|' read -r key st det; do
        su_is_sticky "$st" || continue
        if [[ "$st" == stale-baseline ]]; then dropped=$((dropped + 1)); continue; fi
        proj="${key%%/*}"; svc="${key#*/}"
        ep="$(su_episode_of "$det")"
        if [[ -n "$ep" ]]; then
            inner="$(su_episode_strip "$det")"
        else
            ep="$oldname"; inner="$det"
        fi
        if carry_close_if_gone "$key" "$ep"; then continue; fi
        if [[ "$seen" != *" ${key}|${ep} "* ]]; then
            if [[ "$ep" == "$oldname" ]]; then write_episode_records "$old" "$new" "$proj" "$svc" "$ep"; else carry_episode_records "$old" "$new" "$proj" "$svc" "$ep"; fi
        fi
        seen+="${key}|${ep} "
        printf '%s|%s|%s|%s\n' "$proj" "$svc" "$st" "[episod=${ep}] preluat din baseline-ul ${oldname}: ${inner}" >> "${new}/containers.report"
        say_warn "rezultat NEREZOLVAT preluat în baseline-ul nou: ${key} (${st}) — ${inner}. $(su_sticky_hint "$st" "$proj" "$svc")"
        n=$((n + 1))
    done < <(su_report_final "${old}/containers.report" all)      # `all`: și stările ascunse sub `stale-baseline` (se afișează primul)
    if (( dropped )); then say_info "${dropped} servicii cu baseline vechi (stale-baseline) nu se preiau: baseline-ul nou le rezolvă"; fi
    if (( n )); then say_warn "${n} rezultate NEREZOLVATE din baseline-ul ${old##*/} au fost preluate în ${new##*/}: faza containers și verify rămân roșii pentru ele până se rezolvă"; fi
    return 0
}

# carry_service_state NOU PROIECT SERVICIU — ce spune containers.tsv al baseline-ului nou despre serviciu:
#   present  există cel puțin UN rând al lui, în ORICE stare (running, restarting, exited, paused, created, dead): un container oprit sau în buclă NU a dispărut — e chiar
#            ce trebuie să rămână roșu;
#   gone     lista e măsurată, are rânduri, și niciunul nu e al serviciului: singurul caz în care «a dispărut» e adevărat;
#   empty    lista e măsurată dar n-are niciun rând: docker a răspuns «niciun container». Pe o gazdă cu containere asta e suspect (un daemon repornit, un listing parțial), nu «totul
#            a dispărut»: se tratează ca necunoscut, iar apelantul o spune;
#   unknown  lista nu e măsurată (containers.tsv.unknown) sau lipsește: «n-am putut măsura» nu e «a dispărut».
# Tot ce nu e `gone` se preia ca înainte. Rândurile se numără ca rânduri întregi (cel puțin 7 câmpuri): un fișier cu o linie goală nu e o listă.
carry_service_state() {
    local tsv="${1}/containers.tsv" st
    [[ "$(base_state "$tsv")" == measured ]] || { echo unknown; return 0; }
    st="$(awk -F'|' -v p="$2" -v s="$3" 'NF >= 7 { n++; if ($2 == p && $3 == s) f = 1 } END { if (n == 0) print "empty"; else if (f) print "present"; else print "gone" }' "$tsv")"
    echo "${st:-unknown}"
}

# carry_close_if_gone CHEIE EPISOD — (scop dinamic: new, closed) un serviciu care nu mai are NICIUN container în baseline-ul nou (scos din compose, ori proiectul întreg a dispărut;
# vezi carry_service_state: un container oprit, repornit în buclă sau mort NU conta ca dispărut) nu mai are ce să-și rezolve: episodul se ÎNCHIDE. Nu se preiau nici starea
# lipicioasă, nici recunoașterea, nici înregistrările episodului (containers.episode); în jurnalul nou rămâne o linie `episode-closed` cu prefixul episodului și cu MOTIVUL,
# ca decizia să se vadă și să nu fie o ștergere tăcută. O listă măsurată dar GOALĂ nu închide nimic și o spune.
# 0 = închis (apelantul sare peste preluare), 1 = serviciul are un container sau nu se poate ști (se preia ca înainte).
carry_close_if_gone() {
    local key="$1" ep="$2" state why
    state="$(carry_service_state "$new" "${key%%/*}" "${key#*/}")"
    if [[ "$state" == empty ]]; then
        if [[ "$closed" != *" empty:${key}|${ep} "* ]]; then
            closed+="empty:${key}|${ep} "
            say_warn "${key}: lista containerelor din baseline-ul nou e măsurată, dar GOALĂ (docker n-a întors niciun container) — o gazdă docker cu lista goală e suspectă, nu «serviciul a dispărut»: nu închid episodul ${ep}, eșecul rămâne preluat (roșu)"
        fi
        return 1
    fi
    [[ "$state" == gone ]] || return 1
    if [[ "$closed" != *" ${key}|${ep} "* ]]; then
        closed+="${key}|${ep} "
        why="niciun container al lui în baseline-ul nou, în nicio stare"
        printf '%s|%s|episode-closed|[episod=%s] serviciul a dispărut din baseline-ul %s (%s): episodul %s s-a închis, iar recunoașterea operatorului (dacă exista) s-a șters
'             "${key%%/*}" "${key#*/}" "$ep" "${new##*/}" "$why" "$ep" >> "${new}/containers.report"
        say_warn "${key}: serviciul a dispărut din baseline-ul nou (${why}) — episodul ${ep} s-a închis, recunoașterea operatorului (dacă exista) s-a șters; nu se preia nimic din el"
    fi
    return 0
}

# carry_episode_records VECHI NOU PROIECT SERVICIU EPISOD — preia înregistrările unui episod deja preluat (același ID) din vechiul containers.episode ȘI împătureste în el
# faptele mentenanței din baseline-ul care se înlocuiește (containers.owned): episodul nu e o copie înghețată a baseline-ului care l-a produs.
#   base_health, base_id  ca atare (sănătatea de DINAINTE de eșec nu se schimbă niciodată);
#   landed                REUNIUNE: imaginile pe care eșecul le-a pus, plus cele pe care o reîncercare din baseline-ul vechi le-a pus și le-a văzut rulând (altfel următoarea
#                         reîncercare ar lua imaginea picată de reîncercarea precedentă drept «pusă de altcineva» și ar eticheta-o drept rollback, R2);
#   prev                  dacă episodul are deja un `prev`, cel mai nou `prev` scris de baseline-ul vechi îl înlocuiește (e ce a rulat chiar înainte de ultima schimbare: un deploy
#                         de om între rulări devine ținta, N11); un episod fără `prev` nu primește unul ghicit;
#   pulled                REUNIUNE (TAG|RUN): scutirea de hold-moved-tag e pentru orice pull al mentenanței.
carry_episode_records() {
    local f="${1}/containers.episode" own="${1}/containers.owned" out="${2}/containers.episode" proj="$3" svc="$4" ep="$5" prev id tag run
    [[ -s "$f" ]] || return 0
    [[ "$(awk -F'|' -v p="$proj" -v s="$svc" -v e="$ep" '$1 == p && $2 == s && $3 == e { n++ } END { print n + 0 }' "$f")" != 0 ]] || return 0
    awk -F'|' -v p="$proj" -v s="$svc" -v e="$ep" '$1 == p && $2 == s && $3 == e && ($4 == "base_health" || $4 == "base_id") { print }' "$f" >> "$out"
    prev="$(su_episode_vals "$f" "$proj" "$svc" "$ep" prev | awk 'NR == 1')"
    if [[ -n "$prev" ]]; then
        id="$(su_owned_ids "$own" "$proj" "$svc" prev | awk 'NR == 1')"
        printf '%s|%s|%s|prev|%s\n' "$proj" "$svc" "$ep" "${id:-$prev}" >> "$out"
    fi
    while IFS= read -r id; do
        [[ -n "$id" ]] && printf '%s|%s|%s|landed|%s\n' "$proj" "$svc" "$ep" "$id" >> "$out"
    done < <({ su_episode_vals "$f" "$proj" "$svc" "$ep" landed; su_owned_ids "$own" "$proj" "$svc" landed; } | awk '!s[$0]++')
    while IFS='|' read -r tag run; do
        if [[ -n "$tag" && -n "$run" ]]; then printf '%s|%s|%s|pulled|%s|%s\n' "$proj" "$svc" "$ep" "$tag" "$run" >> "$out"; fi
    done < <({ su_episode_vals "$f" "$proj" "$svc" "$ep" pulled
               if [[ -s "$own" ]]; then awk -F'|' -v p="$proj" -v s="$svc" '$1 == p && $2 == s && $3 == "pulled" && NF >= 5 { print $4 "|" $5 }' "$own"; fi
             } | awk '!s[$0]++')
}

# write_episode_records VECHI NOU PROIECT SERVICIU EPISOD — episodul unui eșec produs în baseline-ul VECHI, din faptele acestuia: sănătatea și imaginea din
# containers.tsv, `prev` și pull-urile din containers.owned. Un câmp pe care faptele nu-l au NU se scrie (gol nu e «sănătos»).
write_episode_records() {
    local old="$1" proj="$3" svc="$4" ep="$5" row h id prev tag run out="${2}/containers.episode"
    if [[ -s "${old}/containers.tsv" ]]; then
        row="$(awk -F'|' -v p="$proj" -v s="$svc" '$2 == p && $3 == s && $7 == "running" { print $8 "|" $5; exit }' "${old}/containers.tsv")" || row=""
        if [[ -n "$row" ]]; then
            h="${row%%|*}"; id="${row#*|}"
            printf '%s|%s|%s|base_health|%s\n' "$proj" "$svc" "$ep" "${h:-none}" >> "$out"
            printf '%s|%s|%s|base_id|%s\n' "$proj" "$svc" "$ep" "$id" >> "$out"
        fi
    fi
    prev="$(su_owned_ids "${old}/containers.owned" "$proj" "$svc" prev | awk 'NR == 1')"
    if [[ -n "$prev" ]]; then printf '%s|%s|%s|prev|%s\n' "$proj" "$svc" "$ep" "$prev" >> "$out"; fi
    # `landed`: imaginile pe care schimbările noastre le-au pus și le-am văzut rulând; o reîncercare compară imaginea de acum cu ele (ensure_rollback_tag)
    while IFS= read -r id; do
        [[ -n "$id" ]] && printf '%s|%s|%s|landed|%s\n' "$proj" "$svc" "$ep" "$id" >> "$out"
    done < <(su_owned_ids "${old}/containers.owned" "$proj" "$svc" landed | awk '!s[$0]++')
    if [[ -s "${old}/containers.owned" ]]; then
        while IFS='|' read -r tag run; do
            if [[ -n "$tag" && -n "$run" ]]; then printf '%s|%s|%s|pulled|%s|%s\n' "$proj" "$svc" "$ep" "$tag" "$run" >> "$out"; fi
        done < <(awk -F'|' -v p="$proj" -v s="$svc" '$1 == p && $2 == s && $3 == "pulled" && NF >= 5 { print $4 "|" $5 }' "${old}/containers.owned")
    fi
    return 0
}

# Gestionarul cu care s-a luat baseline-ul, scris înainte de orice măsurătoare (take_snapshot își alege fișierele după el).
record_pkgmgr() {
    printf 'manager=%s\nos_id=%s\nos_id_like=%s\n' "$PKG_MGR" "$PKG_OS_ID" "$PKG_OS_LIKE" > "${1}/pkgmgr.kv"
}

snapshot_and_publish() {
    local prev_base="${1:-}" stamp dir unknown live recorded name
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dir="${SU_STATE}/snapshots/${stamp}"
    mkdir -p "${dir}.tmp"
    say_sect "Baseline (${stamp})"
    record_pkgmgr "${dir}.tmp"
    unknown="$(take_snapshot "${dir}.tmp")"
    for name in "${dir}.tmp"/*.unknown; do
        [[ -e "$name" ]] || continue
        say_unk "baseline: nu am putut măsura $(basename "${name%.unknown}"): $(head -n 1 "$name")"
    done
    printf 'stamp=%s\nrun=%s\nunknown_measures=%s\n' "$stamp" "$RUN_ID" "$unknown" > "${dir}.tmp/meta.kv"
    case "$PKG_MGR" in
        apt) dpkg-query -W -f='${Package}-${Version}\n' docker-ce 2> /dev/null > "${dir}.tmp/docker-version.txt" || true ;;
        *)   rpm -q --qf '%{NAME}-%{VERSION}\n' docker-ce 2> /dev/null > "${dir}.tmp/docker-version.txt" || true ;;
    esac
    docker compose ls -a > "${dir}.tmp/compose-ls.txt" || say_warn "docker compose ls a eșuat — lista proiectelor nu e în înregistrare"
    : > "${dir}.tmp/COMPLETE"
    mv "${dir}.tmp" "$dir"
    ln -sfn "snapshots/${stamp}" "${SU_STATE}/current.new"
    mv -T "${SU_STATE}/current.new" "${SU_STATE}/current"

    # Dovada că s-a publicat: calea citită, nu comanda rulată.
    BASE="$(readlink -f "${SU_STATE}/current")"
    if [[ "$BASE" == "$(readlink -f "$dir")" && -f "${BASE}/COMPLETE" ]]; then
        say_ok "baseline publicat: ${BASE}"
    else
        die "baseline-ul nu e unde ar trebui (current -> ${BASE})"
    fi
    carry_forward_sticky "$prev_base" "$BASE"
    carry_forward_os_explanation "$prev_base" "$BASE"
    if [[ "$(base_state "${BASE}/containers.tsv")" == measured ]]; then
        recorded="$(wc -l < "${BASE}/containers.tsv")"
        live="$(docker ps -a -q | wc -l)"
        if [[ "$recorded" == "$live" ]]; then
            say_ok "containere înregistrate: ${recorded} (cât arată docker acum)"
        else
            say_warn "înregistrate ${recorded} containere, dar docker arată ${live} acum — ceva s-a schimbat în timpul măsurării"
        fi
        awk -F'|' '$7 == "running" && ($9 == "no" || $9 == "none" || $9 == "") { print "  " $1 }' "${BASE}/containers.tsv" > "${BASE}/no-restart-policy.txt"
        if [[ -s "${BASE}/no-restart-policy.txt" ]]; then
            say_warn "containere care rulează FĂRĂ politică de repornire — NU revin după reboot:"
            cat "${BASE}/no-restart-policy.txt"
        fi
    fi
    if [[ "$(base_state "${BASE}/disabled-running.txt")" == measured && -s "${BASE}/disabled-running.txt" ]]; then
        say_warn "servicii care RULEAZĂ dar sunt 'disabled' — nu revin după reboot (nu le schimb eu): $(tr '\n' ' ' < "${BASE}/disabled-running.txt")"
    fi
    if [[ "$(base_state "${BASE}/failed-units.txt")" == measured ]]; then
        say_info "unități eșuate la baseline: $(wc -l < "${BASE}/failed-units.txt") ($(head -n 5 "${BASE}/failed-units.txt" | tr '\n' ' '))"
    fi
    if [[ "$(base_state "${BASE}/pending.txt")" == measured ]]; then
        say_info "pachete de actualizat (din cache): $(wc -l < "${BASE}/pending.txt")"
    fi
}

# ---------------------------------------------------------------------------
# DB-uri: descoperire + backup
# ---------------------------------------------------------------------------
host_db_state() {
    if systemctl is-active --quiet "${1}.service"; then echo active
    elif systemctl list-unit-files "${1}.service" --no-legend | grep -q .; then echo down
    else echo absent
    fi
}

# nume|fel|stare — fiecare container care ARATĂ ca o bază de date (după ce rulează,
# nu după nume) și bazele de pe gazdă. Folosit de backup (ce se descarcă) și de poarta
# fazelor (ce trebuie să aibă dump).
discover_dbs() {
    local names name rec image state argv_text kind
    local -a argv
    names="$(docker ps -a --format '{{.Names}}')" || return 1
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        # Cmd-ul poate conține `|` (sidecar-ul de backup: `pg_dump … | gzip`), deci e ultimul câmp.
        rec="$(docker inspect -f '{{.Config.Image}}|{{.State.Status}}|{{range .Config.Entrypoint}}{{.}} {{end}}{{range .Config.Cmd}}{{.}} {{end}}' "$name")" || return 1
        IFS='|' read -r image state argv_text <<< "$rec"
        read -r -a argv <<< "$argv_text" || true
        kind="$(su_classify_db "$image" ${argv[@]+"${argv[@]}"})"
        case "$kind" in other) continue ;; esac
        printf '%s|%s|%s\n' "$name" "$kind" "$state"
    done <<< "$names"
    printf 'host-postgres|postgres|%s\n' "$(host_db_state postgresql)"
    printf 'host-mariadb|mariadb|%s\n' "$(host_db_state mariadb)"
}

# Numele care trebuie să aibă dump ACUM (pentru poartă).
required_dump_names() {
    local dbs name kind state
    dbs="$(discover_dbs)" || return 1
    while IFS='|' read -r name kind state; do
        case "$kind" in
            postgres|mariadb) [[ "$state" == absent ]] || printf '%s\n' "$name" ;;
            unclear)          printf '%s\n' "$name" ;;
        esac
    done <<< "$dbs"
}

# verify_dump FIȘIER FEL — setează VERIFY_WHY și VERIFY_BYTES. 0 = dump dovedit complet.
# Trei dovezi independente: arhiva se decomprimă întreagă (gzip -t), are antetul unui
# dump de acest fel LA ÎNCEPUT și marcajul de încheiere LA SFÂRȘIT. Codul de ieșire al
# comenzii de dump nu e una dintre ele: un docker exec căzut la jumătate iese uneori cu 0.
verify_dump() {
    local f="$1" kind="$2" gz_err head_txt tail_txt
    VERIFY_WHY=""; VERIFY_BYTES=0
    [[ -s "$f" ]] || { VERIFY_WHY="fișier gol"; return 1; }
    if ! gz_err="$(gzip -t "$f" 2>&1)"; then VERIFY_WHY="arhivă coruptă: ${gz_err}"; return 1; fi
    VERIFY_BYTES="$(gzip -dc "$f" | wc -c)"
    if (( VERIFY_BYTES < MIN_DUMP_BYTES )); then
        VERIFY_WHY="doar ${VERIFY_BYTES} octeți decomprimați (minim ${MIN_DUMP_BYTES})"; return 1
    fi
    head_txt="$({ gzip -dc "$f" | head -n 30; } || true)"
    if ! printf '%s\n' "$head_txt" | su_dump_header_ok "$kind"; then
        VERIFY_WHY="lipsește antetul unui dump ${kind}"; return 1
    fi
    tail_txt="$(gzip -dc "$f" | tail -n 30)"
    if ! printf '%s\n' "$tail_txt" | su_dump_tail_ok "$kind"; then
        VERIFY_WHY="lipsește marcajul de încheiere — dump trunchiat"; return 1
    fi
}

# dump_one NUME FEL DIR MANIFEST cmd... — ieșirea lui cmd, comprimată, verificată.
# Un dump neverificat nu rămâne sub numele lui final: devine `.INCOMPLETE`, ca nimeni
# să nu-l restaureze crezând că e bun.
dump_one() {
    local name="$1" kind="$2" dir="$3" manifest="$4"; shift 4
    local part="${dir}/${name}.sql.gz.part" final="${dir}/${name}.sql.gz" errf why sum
    local -a rcs
    errf="$(mktemp)"
    set +e
    "$@" 2> "$errf" | gzip -c > "$part"
    rcs=("${PIPESTATUS[@]}")
    set -e
    why=""
    if (( rcs[0] != 0 || rcs[1] != 0 )); then
        why="comanda de dump a ieșit cu ${rcs[0]} (gzip ${rcs[1]}): $(head -c 200 "$errf" | tr '\n|' '  ')"
    elif ! verify_dump "$part" "$kind"; then
        why="$VERIFY_WHY"
    fi
    rm -f "$errf"
    if [[ -n "$why" ]]; then
        mv -f "$part" "${final}.INCOMPLETE"
        printf 'failed|%s|%s|0|%s\n' "$name" "$kind" "${why//|/ }" >> "$manifest"
        say_bad "dump ${name}: ${why}"
        return 0
    fi
    mv -f "$part" "$final"
    sum="$(sha256sum "$final" | cut -d' ' -f1)"
    printf 'ok|%s|%s|%s|%s|%s\n' "$name" "$kind" "$VERIFY_BYTES" "$sum" "$(stat -c %s "$final")" >> "$manifest"
    say_ok "dump ${name} (${kind}): $(mib "$VERIFY_BYTES") decomprimat, $(mib "$(stat -c %s "$final")") pe disc — complet (antet, integritate, marcaj de încheiere)"
}

backup_one() {
    local name="$1" kind="$2" state="$3" dir="$4" manifest="$5"
    case "${name}:${kind}:${state}" in
        host-postgres:*:active)
            dump_one "$name" postgres "$dir" "$manifest" bash -c 'cd / && exec runuser -u postgres -- pg_dumpall --clean --if-exists' ;;
        host-mariadb:*:active)
            dump_one "$name" mariadb "$dir" "$manifest" mysqldump --all-databases --single-transaction --routines --events --triggers ;;
        host-*:*:absent)
            say_info "${name}: nu există pe gazdă — nimic de descărcat"; printf 'skip|%s|%s|0|absent\n' "$name" "$kind" >> "$manifest" ;;
        host-*:*:down)
            say_bad "${name}: serviciul e instalat dar NU rulează — nu pot face dump"
            printf 'failed|%s|%s|0|not-running\n' "$name" "$kind" >> "$manifest" ;;
        *:sidecar:*)
            say_info "${name}: imagine de bază de date, dar rulează un proces auxiliar (nu server) — fără dump"
            printf 'skip|%s|sidecar|0|-\n' "$name" >> "$manifest" ;;
        *:unclear:*)
            say_bad "${name}: imagine de bază de date a cărei comandă nu e nici server, nici shell — nu pot decide dacă are date; o decizi tu"
            printf 'failed|%s|unclear|0|unclear\n' "$name" >> "$manifest" ;;
        *:postgres:running)
            # utilizatorul vine din mediul containerului însuși, citit ÎN container
            dump_one "$name" postgres "$dir" "$manifest" \
                docker exec "$name" sh -c 'exec pg_dumpall -U "${POSTGRES_USER:-postgres}" --clean --if-exists' ;;
        *:mariadb:running)
            # parola root rămâne în container: e citită acolo din mediu, nu trece pe argv-ul gazdei
            dump_one "$name" mariadb "$dir" "$manifest" \
                docker exec "$name" sh -c 'MYSQL_PWD="${MARIADB_ROOT_PASSWORD:-$MYSQL_ROOT_PASSWORD}" exec "$(command -v mariadb-dump || command -v mysqldump)" -uroot --all-databases --single-transaction --routines --events --triggers' ;;
        *)
            say_bad "${name}: ${kind} în starea '${state}' — nu rulează, deci nu pot face dump"
            printf 'failed|%s|%s|0|%s\n' "$name" "$kind" "$state" >> "$manifest" ;;
    esac
}

phase_backup() {
    need_root
    say_sect "Backup"
    local mtime age dir manifest dbs name kind state count=0
    # backup-ul zilnic acoperă fișierele (vaultwarden e SQLite, nu e în dump-urile de mai jos)
    mtime="$(stat -c %Y "$SRV_BACKUP_STATE" || true)"
    age="$(su_age_state "$mtime" "$(now_epoch)" "$SRV_BACKUP_MAX_AGE_S")"
    case "$age" in
        fresh) say_ok "backup-ul zilnic (fișiere, volume) e proaspăt: $(( ($(now_epoch) - mtime) / 3600 )) h" ;;
        *) if (( OPT_STALE_OK )); then
               say_warn "backup-ul zilnic (${SRV_BACKUP_STATE}) e ${age} — continui doar fiindcă ai dat --allow-stale-srv-backup"
           else
               say_bad "backup-ul zilnic (${SRV_BACKUP_STATE}) e ${age} (limita $((SRV_BACKUP_MAX_AGE_S / 3600)) h). Dump-urile de aici acoperă DOAR bazele de date; fișierele (vaultwarden e SQLite) ține de backup-ul zilnic. Repară-l sau: --allow-stale-srv-backup"
           fi ;;
    esac
    dir="${SU_STATE}/dumps/$(date -u +%Y%m%dT%H%M%SZ)"
    manifest="${dir}/MANIFEST"
    mkdir -p "$dir"
    printf 'epoch=%s\nrun=%s\ndir=%s\n' "$(now_epoch)" "$RUN_ID" "$dir" > "$manifest"
    dbs="$(discover_dbs)" || die "nu pot lista containerele (docker) — nu știu ce baze există"
    while IFS='|' read -r name kind state; do
        [[ -n "$name" ]] || continue
        count=$((count + 1))
        backup_one "$name" "$kind" "$state" "$dir" "$manifest"
    done <<< "$dbs"
    cp -f "$manifest" "${SU_STATE}/backup.manifest"
    say_info "dump-uri în ${dir} (0700, necriptate: șterge-le după ce ai verificat că totul e bine)"
    say_info "fișierul de dovadă: ${SU_STATE}/backup.manifest ($(grep -c '^ok|' "$manifest" || true) ok din ${count} înregistrări)"
    finish
}

# Poarta fazelor care pot strica date: ultimul backup trebuie să fie recent și să
# acopere fiecare bază care există ACUM.
require_backup_gate() {
    local names reasons reason
    local -a want=()
    names="$(required_dump_names)" || die "nu pot lista bazele de date (docker) — refuz să schimb ceva fără să știu ce are nevoie de dump"
    while IFS= read -r reason; do [[ -n "$reason" ]] && want+=("$reason"); done <<< "$names"
    if reasons="$(su_backup_gate "${SU_STATE}/backup.manifest" "$(now_epoch)" "$BACKUP_MAX_AGE_S" ${want[@]+"${want[@]}"})"; then
        say_ok "backup-ul bazelor de date e proaspăt și complet (${#want[@]} baze)"
        return 0
    fi
    while IFS= read -r reason; do
        [[ -n "$reason" ]] && say_bad "poartă backup: ${reason} (rulează faza backup și repară ce a eșuat)"
    done <<< "$reasons"
    die "nicio schimbare fără un backup verificat al bazelor de date"
}

# ---------------------------------------------------------------------------
# os
# ---------------------------------------------------------------------------
# Ieșirea se captează ÎNTÂI: `dnf history list | awk '… exit'` închide conducta cât dnf mai scrie,
# iar sub pipefail dnf iese cu 141 (SIGPIPE) — măsurat pe gazdă, 5 din 6 rulări.
dnf_last_txn_id() {
    local out
    out="$(dnf history list)" || return 1
    awk 'NR > 2 && $1 ~ /^[0-9]+$/ { print $1; exit }' <<< "$out"
}

phase_os() {
    need_root; require_pkg_baseline
    say_sect "Actualizare sistem (os)"
    require_backup_gate
    local lock_cu lock_bk
    take_lock lock_cu "${SU_RUN_DIR}/container-update.lock" "actualizarea săptămânală a containerelor"
    take_lock lock_bk "${SU_RUN_DIR}/srv-backup.lock" "backup-ul zilnic"
    pf_check_pkg_idle
    pf_check_disk
    (( FAIL_N == 0 )) || finish

    case "$PKG_MGR" in
        apt) os_run_apt ;;
        *)   os_run_dnf ;;
    esac
    # os.ok = succes DOVEDIT (ieșire 0). O fază încheiată «necunoscut» (3) nu l-a dovedit: fără acest fișier, poarta
    # de reboot nu mai spune «succes dovedit» peste ceva ce n-a putut fi măsurat.
    # os.ok poartă boot_id-ul de acum: explicația «reboot-ul îl cere os» (pf_reboot_explained_by_os) e valabilă doar cât gazda n-a repornit.
    if (( FAIL_N == 0 && UNK_N == 0 )); then mark_phase os.ok; printf 'boot_id=%s\n' "$(current_boot_id)" >> "${BASE}/phases/os.ok"; fi
    finish
}

os_run_dnf() {
    local pending_n=0 kernel_expected=no hist_before rc=0 excl live_out live_rc=0
    # Ce e în așteptare ACUM, nu ce era la baseline: la o a doua rulare, după ce prima a reușit,
    # lista din baseline e veche, iar «dnf n-a schimbat nimic» ar părea o minciună a lui dnf.
    live_out="$(dnf -q check-update)" || live_rc=$?
    case "$(su_check_update_state "$live_rc")" in
        none)    pending_n=0 ;;
        pending)
            pending_n="$(awk 'NF >= 3 && $1 ~ /[.]/' <<< "$live_out" | wc -l)"
            if grep -qE '^kernel(-core)?[.]' <<< "$live_out"; then kernel_expected=yes; fi ;;
        *)
            say_unk "dnf -q check-update a ieșit cu ${live_rc} — nu știu ce e în așteptare acum; folosesc lista din baseline"
            if [[ "$(base_state "${BASE}/pending.txt")" == measured ]]; then
                pending_n="$(wc -l < "${BASE}/pending.txt")"
                if grep -qE '^kernel(-core)?[.]' "${BASE}/pending.txt"; then kernel_expected=yes; fi
            fi ;;
    esac
    hist_before="$(dnf_last_txn_id)" || hist_before=""
    excl="$(grep -hE '^(exclude|excludepkgs)=' /etc/dnf/dnf.conf || true)"
    [[ -z "$excl" ]] || say_info "excluderi din dnf.conf (rămân neatinse, nu le ocolesc): ${excl//$'\n'/; }"
    mark_phase os.started

    say_info "dnf upgrade --refresh -y — ${pending_n} pachete în așteptare la baseline; poate dura zeci de minute"
    nolock dnf upgrade --refresh -y || rc=$?
    say_info "dnf a ieșit cu ${rc} — codul nu e dovadă; efectul se verifică mai jos"
    (( rc == 0 )) || say_bad "dnf upgrade a ieșit cu ${rc}"

    os_check_transaction "$hist_before" "$pending_n" "$rc"
    os_check_packages "$pending_n"
    os_check_residual "$rc"
    os_check_kernel "$kernel_expected"
    os_check_services
}

# ---------------------------------------------------------------------------
# os pe apt (Debian/Ubuntu)
# ---------------------------------------------------------------------------
# De ce `dist-upgrade` și nu `upgrade`: un nucleu nou e un pachet NOU (linux-image-<versiune>), iar `apt-get upgrade` nu instalează niciodată pachete noi — ar
# lăsa meta-pachetul linux-image-virtual «kept back» și ar raporta «actualizat» cu nucleul vechi (măsurat: simularea de pe gazdă instalează 6 pachete noi,
# printre ele linux-image-6.8.0-151-generic). Prețul lui `dist-upgrade` e că poate ȘTERGE pachete ca să rezolve conflicte: de aceea (1) simularea se citește
# înainte și orice linie `Remv` oprește faza, iar (2) upgrade-ul real primește `--no-remove`, deci apt-get însuși refuză, nu doar scriptul.
# Nimic nu se «deține» (`apt-mark unhold`, `--allow-change-held-packages`, `--allow-downgrades`): un pachet pe hold rămâne pe hold, iar faza dovedește asta.
# Fișierele de configurare ale operatorului rămân (`--force-confdef --force-confold`); fără ele dpkg așteaptă la un prompt pe care nimeni nu-l vede (unitate detașată).
# needrestart (instalat implicit pe Ubuntu) ar reporni în mod automat serviciile cu biblioteci vechi: NEEDRESTART_MODE=l îl lasă doar să LISTEZE — ca la dnf,
# serviciile cu cod vechi se curăță la reboot, nu printr-o repornire pe care n-a cerut-o nimeni.
apt_upgrade_cmd() {
    nolock env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l APT_LISTCHANGES_FRONTEND=none \
        apt-get -y --no-remove -o "DPkg::Lock::Timeout=${APT_LOCK_TIMEOUT_S}" \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade
}

APT_HISTORY="${SU_APT_HISTORY:-/var/log/apt/history.log}"
# Numărul de blocuri `Start-Date:` din history.log (gol = necitibil). Un `grep -c` fără potriviri iese cu 1 și tipărește 0: nu e eroare.
apt_history_count() {
    local n
    [[ -r "$APT_HISTORY" ]] || return 0
    n="$(grep -c '^Start-Date:' "$APT_HISTORY" || true)"
    printf '%s' "$n"
}
# Starea ULTIMULUI bloc: ok (are End-Date, fără Error:) | unfinished (apt a murit înainte de End-Date) | error (blocul are o linie Error:) | ?
apt_history_last_state() {
    [[ -r "$APT_HISTORY" ]] || { echo '?'; return 0; }
    awk '/^Start-Date:/ { have = 1; ended = 0; err = 0 } /^End-Date:/ { ended = 1 } /^Error:/ { err = 1 }
         END { if (!have) print "?"; else if (err) print "error"; else if (ended) print "ok"; else print "unfinished" }' "$APT_HISTORY"
}

# Pachetele pe hold, cu versiunea lor: `nume=versiune`, sortat. Iese cu 1 dacă hold-urile nu se pot citi (necunoscut, nu «niciunul»).
apt_held_state() {
    local holds p v acc=""
    holds="$(apt-mark showhold)" || return 1
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        v="$(dpkg-query -W -f='${Package}=${Version}\n' "$p")" || return 1     # fără conductă: un `return` dintr-o conductă n-ar ieși din funcție
        acc+="${v}"$'\n'
    done <<< "$holds"
    printf '%s' "$acc" | LC_ALL=C sort
}

os_run_apt() {
    local pending_n=0 kernel_expected=no hist_before rc=0 sim sim_rc=0 removals held_before held_known=1
    say_info "apt-get update — listele se reîmprospătează ÎNAINTE de simulare (scrie doar în /var/lib/apt/lists)"
    if ! apt_refresh; then
        say_bad "apt-get update a eșuat sau a raportat depozite căzute (cod ${APT_REFRESH_RC}): $(grep -E '^(Err:|E: |W: )' <<< "$APT_REFRESH_OUT" | tail -n 3 | tr '\n' ' ') — nu rulez upgrade-ul pe liste parțiale"
        finish
    fi
    sim="$(apt_simulate)" || sim_rc=$?
    if (( sim_rc != 0 )); then
        say_bad "apt-get -s dist-upgrade a ieșit cu ${sim_rc} — nu știu ce ar face upgrade-ul (poate șterge pachete?); refuz să-l rulez"
        finish
    fi
    removals="$(su_apt_sim_names Remv <<< "$sim")"
    if [[ -n "$removals" ]]; then
        say_bad "dist-upgrade ar ȘTERGE pachete: $(tr '\n' ' ' <<< "$removals")— nu o fac singură; citește simularea (apt-get -s dist-upgrade) și decide tu"
        finish
    fi
    pending_n="$(su_apt_sim_names Inst <<< "$sim" | wc -l)"
    if su_apt_kernel_pending <<< "$sim"; then kernel_expected=yes; fi
    held_before="$(apt_held_state)" || { held_known=0; say_unk "nu pot citi pachetele pe hold (apt-mark showhold) — nu pot dovedi că rămân neatinse"; }
    if (( held_known )); then
        if [[ -n "$held_before" ]]; then say_info "pachete pe hold (rămân neatinse, nu le deblochez): $(tr '\n' ' ' <<< "$held_before")"; else say_info "niciun pachet pe hold"; fi
    fi
    hist_before="$(apt_history_count)"
    mark_phase os.started

    say_info "apt-get dist-upgrade — ${pending_n} pachete în simulare; blocarea dpkg se așteaptă până la ${APT_LOCK_TIMEOUT_S}s; poate dura zeci de minute"
    apt_upgrade_cmd || rc=$?
    say_info "apt-get a ieșit cu ${rc} — codul nu e dovadă; efectul se verifică mai jos"
    (( rc == 0 )) || say_bad "apt-get dist-upgrade a ieșit cu ${rc}"

    os_check_transaction_apt "$hist_before" "$pending_n" "$rc"
    os_check_packages "$pending_n"
    os_check_residual_apt
    os_check_kernel "$kernel_expected"
    if (( held_known )); then os_check_held "$held_before"; fi
    os_check_services
}

# Fapt 1 (apt): history.log a primit un bloc NOU, încheiat (End-Date) și fără linie `Error:`.
os_check_transaction_apt() {
    local before="$1" pending="$2" rc="$3" after last
    after="$(apt_history_count)"; last="$(apt_history_last_state)"
    case "$(su_apt_history_verdict "$before" "$after" "$last")" in
        unknown)         say_unk "nu pot citi ${APT_HISTORY} (înainte: '${before}', după: '${after}', ultimul bloc: ${last}) — nu pot dovedi că a existat o tranzacție" ;;
        none)
            if (( pending == 0 && rc == 0 )); then
                say_ok "nimic de actualizat și niciun bloc nou în history.log (${after} blocuri) — rulare repetată, no-op dovedit"
            elif (( pending > 0 && rc == 0 )); then
                say_bad "apt-get a ieșit cu 0 dar history.log n-are niciun bloc nou (${after} blocuri) — ${pending} pachete erau în simulare"
            else
                say_info "niciun bloc nou în history.log (${after} blocuri)"
            fi ;;
        new-ok)          say_ok "history.log: tranzacție nouă, încheiată (End-Date) și fără Error:" ;;
        new-unfinished)  say_bad "history.log: ultimul bloc n-are End-Date — apt a murit la jumătate; rulează: dpkg --audit; dpkg --configure -a" ;;
        new-error)       say_bad "history.log: ultimul bloc conține o linie Error: — baza dpkg poate fi la jumătate; rulează: dpkg --audit; tail ${APT_HISTORY}" ;;
    esac
}

# Fapt 3 (apt): ce a rămas, și dacă dpkg a lăsat ceva neterminat. Trei observatori care nu depind unul de altul: simularea (ce e încă de instalat), `dpkg --audit`
# (pachete despachetate dar neconfigurate) și starea fiecărui pachet din baza dpkg (db:Status-Abbrev). Codul de ieșire 0 al lui apt-get nu intră în niciunul.
os_check_residual_apt() {
    local sim sim_rc=0 n kept held unheld out arc=0 states bad
    sim="$(apt_simulate)" || sim_rc=$?
    if (( sim_rc != 0 )); then
        say_unk "apt-get -s dist-upgrade a ieșit cu ${sim_rc} — nu pot spune ce a rămas"
    else
        n="$(su_apt_sim_names Inst <<< "$sim" | wc -l)"
        if (( n == 0 )); then
            say_ok "apt-get -s dist-upgrade: nu a rămas nimic de instalat"
        else
            say_warn "au rămas ${n} pachete de actualizat (primele 15):"
            su_apt_sim_names Inst <<< "$sim" | awk '{ print "    " $1; if (++c >= 15) exit }'
            CHANGED_LIST+=("au rămas ${n} pachete neactualizate (vezi mai sus)")
        fi
        kept="$(su_apt_kept_back <<< "$sim")"
        if [[ -n "$kept" ]]; then
            held="$(apt-mark showhold || true)"
            unheld="$(LC_ALL=C comm -23 <(printf '%s\n' "$kept") <(printf '%s\n' "$held" | LC_ALL=C sort -u) | awk 'NF')"
            say_info "ținute înapoi de apt (kept back): $(tr '\n' ' ' <<< "$kept")"
            [[ -z "$unheld" ]] || say_warn "kept back FĂRĂ să fie pe hold (actualizare în fază, dependențe blocate): $(tr '\n' ' ' <<< "$unheld")— nu le forțez"
        fi
    fi
    out="$(dpkg --audit)" || arc=$?
    if [[ -n "$out" ]]; then
        say_bad "dpkg --audit raportează pachete neterminate: $(head -c 400 <<< "$out" | tr '\n' ' ') — rulează: dpkg --configure -a"
    elif (( arc != 0 )); then
        say_unk "dpkg --audit a ieșit cu ${arc} fără ieșire — nu pot spune că baza dpkg e curată"
    else
        say_ok "dpkg --audit: niciun pachet despachetat sau configurat pe jumătate"
    fi
    if states="$(dpkg-query -W -f='${db:Status-Abbrev}|${binary:Package}\n')"; then
        bad="$(su_apt_unclean <<< "$states")"
        if [[ -n "$bad" ]]; then say_bad "pachete într-o stare nestabilă în baza dpkg (stare|pachet): $(head -n 8 <<< "$bad" | tr '\n' ' ')"
        else say_ok "baza dpkg: toate pachetele sunt într-o stare stabilă (ii/hi/rc/un/pn)"; fi
    else
        say_unk "nu pot citi starea pachetelor din dpkg-query — nu pot dovedi că nimic n-a rămas neconfigurat"
    fi
    if out="$(apt-get check 2>&1)"; then say_ok "apt-get check: nicio dependență ruptă"; else say_bad "apt-get check raportează dependențe rupte: $(tail -n 2 <<< "$out" | tr '\n' ' ')"; fi
}

# Pachetele pe hold n-au fost atinse: aceeași listă, aceleași versiuni (cloud-init e ținut pe gazda de test din motive ale operatorului).
os_check_held() {
    local before="$1" after
    after="$(apt_held_state)" || { say_unk "nu pot citi pachetele pe hold după upgrade — nu pot dovedi că au rămas neatinse"; return 0; }
    if [[ "$before" == "$after" ]]; then
        if [[ -n "$after" ]]; then say_ok "pachetele pe hold au rămas neatinse (aceeași listă, aceleași versiuni): $(tr '\n' ' ' <<< "$after")"
        else say_ok "niciun pachet pe hold, înainte și după"; fi
    else
        say_bad "pachetele pe hold s-au schimbat. Înainte: $(tr '\n' ' ' <<< "$before")| după: $(tr '\n' ' ' <<< "$after")"
    fi
}

# Fapt 1: istoricul dnf a primit o tranzacție NOUĂ, încheiată cu Success.
os_check_transaction() {
    local before="$1" pending="$2" rc="$3" after info
    after="$(dnf_last_txn_id)" || after=""
    if [[ -z "$after" ]]; then say_unk "nu pot citi istoricul dnf — nu pot dovedi că a existat o tranzacție"; return 0; fi
    if [[ "$after" == "$before" ]]; then
        if (( pending == 0 && rc == 0 )); then
            say_ok "nimic de actualizat și nicio tranzacție nouă (ultima rămâne #${after}) — rulare repetată, no-op dovedit"
        elif (( pending > 0 && rc == 0 )); then
            say_bad "dnf a ieșit cu 0 dar istoricul n-are nicio tranzacție nouă (ultima rămâne #${after}) — ${pending} pachete erau în așteptare"
        else
            say_info "nicio tranzacție nouă în istoricul dnf (#${after})"
        fi
        return 0
    fi
    info="$(dnf history info "$after" | sed -n 's/^Return-Code[[:space:]]*:[[:space:]]*//p')"
    info="${info%%$'
'*}"
    if [[ "$info" == Success* ]]; then
        say_ok "tranzacția dnf #${after} încheiată cu Success"
    else
        say_bad "tranzacția dnf #${after} are Return-Code '${info:-necitit}' — baza de pachete poate fi la jumătate; rulează: dnf check; dnf history info ${after}"
    fi
}

# Fapt 2: pachetele chiar s-au schimbat în baza rpm (nu doar dnf a zis că le-a schimbat).
os_check_packages() {
    local pending="$1" now changed
    now="$(mktemp)"
    if ! m_pkg_list > "$now"; then rm -f "$now"; say_unk "nu pot citi ${PKG_LIST_CMD} după actualizare"; return 0; fi
    if [[ "$(base_state "${BASE}/${PKG_LIST_FILE}")" != measured ]]; then
        rm -f "$now"; say_unk "${PKG_LIST_CMD} din baseline lipsește — nu pot număra schimbările"; return 0
    fi
    changed="$(su_new_lines "${BASE}/${PKG_LIST_FILE}" "$now" | wc -l)"
    rm -f "$now"
    CHANGED_LIST+=("${changed} pachete instalate sau actualizate (${PKG_LIST_CMD} față de baseline)")
    if (( pending > 0 && changed == 0 )); then
        say_bad "baza ${PKG_DB} n-are niciun pachet schimbat față de baseline, deși ${pending} erau în așteptare"
    else
        say_ok "${changed} pachete diferă față de baseline în baza ${PKG_DB}"
    fi
}

# Fapt 3: ce a rămas. `dnf check-update` (cu rețea, nu din cache) și `dnf check`
# (dependențe rupte).
os_check_residual() {
    local rc="$1" out crc=0 n
    out="$(dnf -q check-update)" || crc=$?
    case "$(su_check_update_state "$crc")" in
        none) say_ok "dnf check-update: nu a rămas nimic de actualizat" ;;
        pending)
            n="$(printf '%s\n' "$out" | awk 'NF >= 3 && $1 ~ /\./' | wc -l)"
            say_warn "au rămas ${n} pachete de actualizat (primele 15):"
            # awk iese singur după 15: `| head -n 15` ar închide conducta, iar sub pipefail
            # rezultatul s-ar pierde cu 141 tocmai când dnf a căzut întreg (342 de linii)
            awk 'NF >= 3 && $1 ~ /[.]/ { print "    " $1; if (++c >= 15) exit }' <<< "$out"
            if [[ -n "$LOG_FILE" && -s "$LOG_FILE" ]]; then
                say_info "de ce (din jurnalul dnf): $(awk '/Skipping packages|Problem:|conflicts with|Error:/ { print; if (++c >= 6) exit }' "$LOG_FILE" | tr '\n' ' ')"
            fi
            CHANGED_LIST+=("au rămas ${n} pachete neactualizate (vezi mai sus)") ;;
        *) say_unk "dnf check-update a ieșit cu ${crc} — nu pot spune ce a rămas" ;;
    esac
    if dnf check > /dev/null; then say_ok "dnf check: nicio dependență ruptă"; else say_bad "dnf check raportează probleme de dependențe/baza rpm — rulează-l de mână"; fi
}

# Fapt 4: nucleul nou e INSTALAT (rpm), e cel IMPLICIT la pornire (grubby) și are
# fișierele pe disc. Un nucleu «instalat» al cărui initramfs lipsește nu pornește.
os_check_kernel() {
    local expected="$1" newest def running why_files
    running="$(uname -r)"
    newest="$(newest_installed_kernel)" || { say_unk "nu pot citi nucleele instalate (${KLIST_CMD})"; return 0; }
    def="$(default_kernel)" || { say_unk "nu pot citi nucleul implicit (${KDEF_CMD})"; return 0; }
    if [[ "$newest" == "$running" ]]; then
        if [[ "$expected" == yes ]]; then
            say_bad "baseline-ul avea un nucleu în așteptare dar cel mai nou instalat e tot cel care rulează (${running}) — nucleul nou NU s-a instalat"
        else
            say_info "niciun nucleu nou de instalat"
        fi
        return 0
    fi
    say_ok "nucleu nou instalat: ${running} -> ${newest}"
    CHANGED_LIST+=("nucleu: ${running} -> ${newest} (devine activ după reboot)")
    if su_kernel_matches_default "$newest" "$def"; then
        say_ok "nucleul nou e cel implicit la pornire (${KDEF_NAME})"
    else
        say_bad "nucleul nou (${newest}) NU e cel implicit la pornire (${KDEF_NAME} spune ${def}) — o repornire ar porni alt nucleu"
    fi
    if why_files="$(boot_files_ok "$newest")"; then
        say_ok "fișierele de pornire ale nucleului nou există (vmlinuz și $(boot_initrd_file "$newest"), de mărime credibilă)"
    else
        say_bad "nucleul nou (${newest}) NU poate porni: ${why_files%; } — o repornire n-ar porni nucleul nou"
    fi
}

# Fapt 5: nginx — configurația nouă se citește (nginx -t), iar PROCESUL care servește
# nu e un binar șters de pe disc. `systemctl reload` cu 0 e doar semnalul trimis.
os_check_services() {
    local out pid exe state restart_list
    if have nginx; then
        if out="$(nginx -t 2>&1)"; then say_ok "nginx -t: configurația e validă"; else say_bad "nginx -t a eșuat: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"; fi
        pid="$(systemctl show -p MainPID --value nginx.service || true)"
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
            exe="$(readlink "/proc/${pid}/exe" || true)"
            if [[ "$exe" == *"(deleted)"* ]]; then
                say_warn "nginx (pid ${pid}) rulează încă BINARUL VECHI (șters de pe disc) — se rezolvă la reboot sau cu: systemctl restart nginx"
            else
                say_ok "nginx rulează binarul de pe disc"
            fi
        fi
    fi
    state="$(su_reboot_needed_from_rc "$(reboot_probe > /dev/null; echo $?)")"
    say_info "reboot necesar după actualizare (${REBOOT_PROBE_NAME}): ${state}"
    if [[ "$PKG_MGR" == apt ]]; then
        [[ "$state" != yes ]] || say_info "$(reboot_probe || true)"
        return 0
    fi
    restart_list="$(needs-restarting -s | awk 'NF' | head -n 12 | tr '\n' ' ' || true)"
    [[ -z "$restart_list" ]] || say_info "servicii cu cod vechi în memorie (se curăță la reboot): ${restart_list}"
}


# ---------------------------------------------------------------------------
# Rulare detașată (os, containers) și firul din sesiune
# ---------------------------------------------------------------------------
# De ce nu `systemd-run --wait --pipe`: cu --pipe, ieșirea unității trece printr-o conductă
# către clientul systemd-run. Când sesiunea ssh cade, clientul moare, conducta se rupe, iar
# următoarea scriere a unității (sau a lui dnf) primește SIGPIPE — adică exact
# întreruperea la mijlocul tranzacției pe care detașarea trebuia s-o evite. Aici unitatea
# scrie într-un FIȘIER; sesiunea doar îl citește.
#
# Executabilul unității e /usr/bin/bash (un binar al sistemului), nu scriptul: nu depinde de
# bitul de execuție sau de eticheta SELinux a directorului de stare.
# Când se încheie unitatea? Nu când o singură citire a stării nu zice «activ». Măsurat pe gazdă (20 nov 2026): în
# tranzacția dnf, scriptletul pachetului systemd rulează `systemctl daemon-reexec` («systemd[1]: Reexecuting.»), iar
# `systemctl show -p ActiveState` a întors o clipă gol/eroare cât unitatea era încă activă și dnf încă rula — bucla
# o socotea încheiată, tipărea «FĂRĂ să scrie un rezultat» și ieșea 3 peste o actualizare care a terminat apoi cu 0.
# Acum:
#   * `active`, `activating`, `deactivating`, `reloading`, `refreshing` = unitatea încă există și rulează (la
#     `deactivating` procesul tocmai iese și EXIT trap-ul lui scrie `.result`: se așteaptă, mărginit de timeout-ul
#     de oprire al systemd);
#   * `inactive`/`failed` = încheiată DOAR dacă se citește la fel de două ori la rând, la FOLLOW_CONFIRM_S distanță
#     (și fișierul de rezultat tot nu a apărut între ele);
#   * gol, eroare de citire sau orice altă valoare = NECITIT, nu «încheiat»: se așteaptă mai departe, dar cel mult
#     FOLLOW_UNREADABLE_S secunde, apoi starea e necunoscută (3), ca o unitate dispărută să nu țină sesiunea la nesfârșit.
#     Fereastra se măsoară de la prima citire care nu e «activă» și se închide doar la una «activă»: citirile alternante
#     inactive/necitit (care își resetau reciproc contoarele) sunt mărginite la fel.
follow_run() {
    local unit="$1" log="$2" result="$3" pos=1 chunk n state ended=0 unread_since=0
    # Un fișier-chunk, nu `tail | head -c`: mărimea citită apoi (`stat`) putea diferi de cea copiată
    # (jurnalul crește între ele), iar `head` închidea conducta sub pipefail. Aici se tipărește exact
    # ce s-a copiat și poziția avansează cu atât.
    chunk="$(mktemp)"
    drain() {
        tail -c +"$pos" "$log" > "$chunk" || return 0
        n="$(wc -c < "$chunk")"
        if (( n > 0 )); then cat "$chunk"; pos=$(( pos + n )); fi
    }
    while :; do
        drain
        [[ -f "$result" ]] && break
        state="$(systemctl show -p ActiveState --value "$unit" || true)"
        case "$state" in
            active|activating|deactivating|reloading|refreshing) ended=0; unread_since=0 ;;
            inactive|failed)
                # Fereastra e UNA pentru ambele contoare: `inactive`, necitit, `inactive`, necitit... nu are voie să țină sesiunea
                # la nesfârșit (fiecare contor se reseta pe celălalt). Doar o citire «activă» o închide.
                (( unread_since )) || unread_since="$(now_epoch)"
                if (( ++ended >= 2 )); then
                    drain
                    [[ -f "$result" ]] && break
                    printf '\n[?] unitatea %s s-a încheiat FĂRĂ să scrie un rezultat (%s la două citiri la rând) — starea e NECUNOSCUTĂ (nu «reușit»). Vezi: journalctl -u %s ; %s status\n' "$unit" "$state" "$unit" "$SU_SELF"
                    rm -f "$chunk"; return 3
                fi
                if (( $(now_epoch) - unread_since >= FOLLOW_UNREADABLE_S )); then
                    drain
                    [[ -f "$result" ]] && break
                    printf '\n[?] unitatea %s nu a revenit la «active» de %ss (citiri alternante «%s»/necitibil) și nu există un rezultat — starea e NECUNOSCUTĂ (nu «reușit», nici «încheiat»). Vezi: journalctl -u %s ; %s status\n' "$unit" "$FOLLOW_UNREADABLE_S" "$state" "$unit" "$SU_SELF"
                    rm -f "$chunk"; return 3
                fi
                sleep "$FOLLOW_CONFIRM_S"; continue ;;
            *)
                ended=0
                (( unread_since )) || unread_since="$(now_epoch)"
                if (( $(now_epoch) - unread_since >= FOLLOW_UNREADABLE_S )); then
                    drain
                    [[ -f "$result" ]] && break
                    printf '\n[?] nu pot citi starea unității %s de %ss (systemctl a întors «%s») și nu există un rezultat — starea e NECUNOSCUTĂ (nu «reușit», nici «încheiat»). Vezi: journalctl -u %s ; %s status\n' "$unit" "$FOLLOW_UNREADABLE_S" "$state" "$unit" "$SU_SELF"
                    rm -f "$chunk"; return 3
                fi ;;
        esac
        sleep "$FOLLOW_S"
    done
    drain
    local rc
    rc="$(awk -F= '$1 == "rc" { print $2; exit }' "$result")"
    rm -f "$chunk"
    [[ "$rc" =~ ^[0-9]+$ ]] || { printf '\n[?] fișierul de rezultat %s nu are un cod citibil\n' "$result"; return 3; }
    return "$rc"
}

run_detached() {
    local unit="system-update-${PHASE}-${RUN_ID//[^A-Za-z0-9]/-}"
    : > "$LOG_FILE"
    have systemd-run || { printf '[x] systemd-run lipsește — refuz să rulez %s în sesiunea ssh (o sesiune căzută ar întrerupe tranzacția)\n' "$PHASE"; return 1; }
    printf '[.] pornesc unitatea %s (rezistă la căderea sesiunii ssh); jurnal: %s\n' "$unit" "$LOG_FILE"
    systemd-run --unit "$unit" --collect --quiet --working-directory=/ \
        --setenv=SU_DETACHED=1 --setenv=SU_RUN_ID="$RUN_ID" --setenv=SU_STATE="$SU_STATE" \
        -p "StandardOutput=append:${LOG_FILE}" -p "StandardError=append:${LOG_FILE}" \
        /usr/bin/bash "$SU_SELF" "$PHASE" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"} \
        || { printf '[x] systemd-run nu a pornit unitatea\n'; return 1; }
    follow_run "$unit" "$LOG_FILE" "$RESULT_FILE"
}

# ---------------------------------------------------------------------------
# Argumente
# ---------------------------------------------------------------------------
usage() { sed -n '2,/^set -euo/p' "$SU_SELF" | sed '$d' | sed 's/^# \{0,1\}//'; }

need_arg() { [[ $# -ge 2 && -n "$2" ]] || { printf 'error: %s cere o valoare\n' "$1" >&2; exit 2; }; }
need_num() { [[ "$2" =~ ^[0-9]+$ ]] || { printf 'error: %s cere un număr întreg, nu '"'"'%s'"'"'\n' "$1" "$2" >&2; exit 2; }; }
# O listă nu poate începe cu `-`: `--rebuild --dry-run` ar citi `--dry-run` drept valoare, iar rularea ar porni ÎN SERIOS
# (OPT_DRY_RUN rămâne 0) peste o cerere pe care operatorul o credea simulare. Un nume de proiect compose nu începe cu `-`.
need_list() {
    if [[ "$2" == -* ]]; then
        printf 'error: %s cere o listă de proiecte, nu o altă opțiune (primit '"'"'%s'"'"'); nu s-a pornit nimic\n' "$1" "$2" >&2; exit 2
    fi
    [[ "$2" =~ ^[A-Za-z0-9_.][A-Za-z0-9_.,-]*$ ]] || { printf 'error: %s cere nume separate prin virgulă, nu '"'"'%s'"'"'\n' "$1" "$2" >&2; exit 2; }
}

# `--acknowledge` primește chei `proiect/serviciu` separate prin virgulă (nu nume de proiect): fiecare cheie are exact un `/`, iar nicio valoare nu
# începe cu `-` (aceleași reguli B1 ca la need_list: `--acknowledge --dry-run` ar citi `--dry-run` drept valoare și ar porni în serios).
need_keys() {
    local k
    if [[ "$2" == -* ]]; then
        printf 'error: %s cere chei proiect/serviciu, nu o altă opțiune (primit '"'"'%s'"'"'); nu s-a pornit nimic\n' "$1" "$2" >&2; exit 2
    fi
    while IFS= read -r k; do
        [[ "$k" =~ ^[A-Za-z0-9_.][A-Za-z0-9_.-]*/[A-Za-z0-9_.][A-Za-z0-9_.-]*$ ]] \
            || { printf 'error: %s cere chei proiect/serviciu separate prin virgulă, nu '"'"'%s'"'"'\n' "$1" "$k" >&2; exit 2; }
    done < <(tr ',' '\n' <<< "$2")
}

flag_allowed() {
    case "${PHASE}:${1}" in
        preflight:--new-baseline|backup:--allow-stale-srv-backup|reboot:--yes|reboot:--force|reboot:--ignore-os-state|verify:--gap|verify:--wait) return 0 ;;
        containers:--dry-run|containers:--rebuild|containers:--accept-drift|containers:--only|containers:--retry-failed|containers:--acknowledge|containers:--keep-going|containers:--health-timeout|containers:--stable) return 0 ;;
    esac
    return 1
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        flag_allowed "$1" || { printf 'error: %s nu se aplică fazei %s (sau nu există)\n' "$1" "$PHASE" >&2; exit 2; }
        case "$1" in
            --new-baseline) OPT_NEW_BASELINE=1; shift ;;
            --allow-stale-srv-backup) OPT_STALE_OK=1; shift ;;
            --dry-run) OPT_DRY_RUN=1; shift ;;
            --yes) OPT_YES=1; shift ;;
            --force) OPT_FORCE=1; shift ;;
            --ignore-os-state) OPT_IGNORE_OS_STATE=1; shift ;;
            --keep-going) OPT_KEEP_GOING=1; shift ;;
            --rebuild) need_arg "$@"; need_list "$@"; OPT_REBUILD="$2"; shift 2 ;;
            --accept-drift)
                need_arg "$@"; need_list "$@"
                # «accept tot codul necitit de nimeni» nu încape într-un cuvânt
                [[ "$2" != all && ",$2," != *,all,* ]] || { printf 'error: --accept-drift nu primește `all`: numește proiectele al căror cod l-ai citit\n' >&2; exit 2; }
                OPT_ACCEPT_DRIFT="$2"; shift 2 ;;
            --only) need_arg "$@"; need_list "$@"; OPT_ONLY="$2"; shift 2 ;;
            --retry-failed) need_arg "$@"; need_list "$@"; OPT_RETRY_FAILED="$2"; shift 2 ;;
            --acknowledge) need_arg "$@"; need_keys "$@"; OPT_ACKNOWLEDGE="$2"; shift 2 ;;
            --gap) need_arg "$@"; need_num "$@"; GAP_S="$2"; shift 2 ;;
            --wait) need_arg "$@"; need_num "$@"; WAIT_S="$2"; shift 2 ;;
            --health-timeout) need_arg "$@"; need_num "$@"; HEALTH_TIMEOUT_S="$2"; shift 2 ;;
            --stable) need_arg "$@"; need_num "$@"; STABLE_S="$2"; shift 2 ;;
        esac
    done
}

main() {
    local phase="${1:-}"
    case "$phase" in
        ""|-h|--help|help) usage; exit 0 ;;
        preflight|backup|os|containers|reboot|verify|status) ;;
        *) printf 'error: fază necunoscută: %s (preflight|backup|os|containers|reboot|verify|status)\n' "$phase" >&2; exit 2 ;;
    esac
    shift
    PHASE="$phase"
    ORIG_ARGS=("$@")
    parse_args "$@"
    [[ "$(id -u)" == 0 ]] || { printf 'error: trebuie rulat ca root\n' >&2; exit 1; }
    init_state
    if [[ "$PHASE" == status ]]; then RESULT_FILE=""; local st_rc=0; phase_status || st_rc=$?; exit "$st_rc"; fi

    if [[ "$PHASE" == os || ( "$PHASE" == containers && OPT_DRY_RUN -eq 0 ) ]] && [[ -z "${SU_DETACHED:-}" && -z "${SU_NO_DETACH:-}" ]]; then
        # părinte: nu ține blocări, nu scrie rezultat — doar pornește unitatea și o urmărește
        RESULT_FILE="${SU_STATE}/runs/${PHASE}-${RUN_ID}.result"
        RESULT_WRITTEN=1
        run_detached
        exit $?
    fi
    # serializează fazele între ele: două rulări simultane ar strica baseline-ul sau tranzacția
    local lock_fd
    take_lock lock_fd "${SU_STATE}/lock" "o altă fază system-update"
    "phase_${PHASE}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
