#!/usr/bin/env bash
#
# Fazele `verify`, `reboot` și `status` ale lui scripts/lib/system-update-host.sh.
# Încărcat cu `source`; folosește `say_*`, OPT_*, BASE și măsurătorile din
# system-update-measure.sh.
#
# `verify` judecă totul FAȚĂ DE BASELINE, nu față de «totul trebuie să fie verde»:
# bet-calculator era deja unhealthy înainte de orice schimbare, dnf-makecache.service
# deja eșuat. Un verify care cere verde ar fi roșu azi, iar un verify mereu roșu e
# unul pe care operatorul învață să-l ignore — exact când ar conta. Patru rezultate
# pe fiecare element: ok / mai rău decât baseline / rău și la baseline (nu e vina
# schimbării) / necunoscut (n-am putut măsura — NU e «ok»).
#
# «Activ» o dată nu e dovadă că rămâne pornit (un serviciu în buclă trece prin `active`
# la fiecare ciclu), deci serviciile și containerele se eșantionează de DOUĂ ori, la
# GAP_S distanță, și se compară numărul de reporniri și momentul intrării în starea activă.

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
verify_boot() {
    local req_boot now_boot base_boot running def newest base_running rc state
    say_sect "Pornire și nucleu"
    now_boot="$(cat "${SU_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}")" || now_boot=""
    base_boot=""; [[ "$(base_state "${BASE}/kernel.kv")" == measured ]] && base_boot="$(kv_get "${BASE}/kernel.kv" boot_id)"
    if [[ -f "${BASE}/phases/reboot.requested" ]]; then
        req_boot="$(kv_get "${BASE}/phases/reboot.requested" boot_id)"
        if [[ -z "$now_boot" || -z "$req_boot" ]]; then
            say_unk "nu pot compara boot_id (cerere: '${req_boot}', acum: '${now_boot}') — nu pot spune dacă gazda s-a repornit"
        elif [[ "$now_boot" == "$req_boot" ]]; then
            say_bad "s-a cerut un reboot, dar boot_id e același — gazda NU s-a repornit (reboot anulat, programat și neexecutat, sau încă nu a venit ora)"
        else
            say_ok "gazda s-a repornit (boot_id diferit de cel de la cererea de reboot)"
            CHANGED_LIST+=("reboot efectuat")
        fi
    elif [[ -n "$base_boot" && -n "$now_boot" ]]; then
        if [[ "$base_boot" != "$now_boot" ]]; then say_info "gazda s-a repornit de la baseline (fără cerere prin faza reboot)"; CHANGED_LIST+=("reboot efectuat"); else say_info "gazda nu s-a repornit de la baseline"; fi
    fi

    running="$(uname -r)"
    def="$(default_kernel)" || def=""
    rc=0; su_kernel_matches_default "$running" "$def" || rc=$?
    case "$rc" in
        0) say_ok "nucleul care rulează (${running}) e cel implicit la pornire" ;;
        1) say_bad "rulează ${running}, dar implicit la pornire e ${def##*/vmlinuz-} — actualizarea nu e activă (reboot neefectuat) sau a pornit alt nucleu" ;;
        *) say_unk "nu pot citi nucleul implicit (${KDEF_CMD})" ;;
    esac
    newest="$(newest_installed_kernel)" || newest=""
    if [[ -n "$newest" && -n "$def" ]] && ! su_kernel_matches_default "$newest" "$def"; then
        say_warn "nucleul implicit (${def##*/vmlinuz-}) nu e cel mai nou instalat (${newest})"
    fi
    base_running=""; [[ -n "$base_boot" ]] && base_running="$(kv_get "${BASE}/kernel.kv" running)"
    if [[ -n "$base_running" && "$base_running" != "$running" ]]; then
        CHANGED_LIST+=("nucleu: ${base_running} -> ${running}")
    fi
    local nr_out=""
    rc=0; nr_out="$(reboot_probe 2>&1)" || rc=$?
    state="$(su_reboot_needed_from_rc "$rc")"
    # După actualizare și repornire nu mai trebuie să existe un reboot în așteptare: «încă necesar» e o
    # problemă (actualizarea nu e activă), iar «n-am putut afla» (127: comandă lipsă) e necunoscut, nu verde.
    case "$state" in
        yes)     say_bad "${REBOOT_PROBE_NAME} cere încă un reboot (pachete actualizate după ultima pornire) — actualizarea nu e încă activă" ;;
        unknown) say_unk "${REBOOT_PROBE_NAME} a ieșit cu ${rc} ($(awk 'NR == 1' <<< "$nr_out")) — nu pot spune dacă mai e nevoie de un reboot" ;;
    esac
    return 0
}

verify_failed_units() {
    local now new still cleared u
    say_sect "Unități eșuate"
    if [[ "$(base_state "${BASE}/failed-units.txt")" != measured ]]; then
        say_unk "lista unităților eșuate nu s-a măsurat la baseline — nu pot judeca ce e nou"; return 0
    fi
    now="$(mktemp)"
    if ! m_failed_units > "$now"; then rm -f "$now"; say_unk "nu pot citi unitățile eșuate acum"; return 0; fi
    new="$(su_new_lines "${BASE}/failed-units.txt" "$now")"
    still="$(LC_ALL=C comm -12 <(LC_ALL=C sort -u "${BASE}/failed-units.txt") <(LC_ALL=C sort -u "$now"))"
    cleared="$(su_missing_lines "${BASE}/failed-units.txt" "$now")"
    rm -f "$now"
    while IFS= read -r u; do [[ -n "$u" ]] && say_bad "unitate eșuată NOUĂ față de baseline: ${u}"; done <<< "$new"
    while IFS= read -r u; do [[ -n "$u" ]] && { SAME_LIST+=("unitate eșuată și la baseline: ${u}"); say_info "eșuată și la baseline (nu e din vina schimbării): ${u}"; }; done <<< "$still"
    while IFS= read -r u; do [[ -n "$u" ]] && say_info "eșuată la baseline, acum nu mai e: ${u}"; done <<< "$cleared"
    [[ -n "$new" ]] || say_ok "nicio unitate eșuată nouă față de baseline"
}

svc_sample() {
    local out
    out="$(systemctl show "$1" -p ActiveState -p NRestarts -p ActiveEnterTimestampMonotonic)" || { printf 'unknown|0|0'; return 0; }
    printf '%s|%s|%s' "$(sed -n 's/^ActiveState=//p' <<< "$out")" "$(sed -n 's/^NRestarts=//p' <<< "$out")" \
        "$(sed -n 's/^ActiveEnterTimestampMonotonic=//p' <<< "$out")"
}

# Serviciile și containerele: așteptare mărginită până se așază, primul eșantion, pauza
# GAP_S, al doilea eșantion, verdict. Ele așteaptă împreună, ca pauza să se plătească o dată.
verify_running_things() {
    local deadline u pending line name base_state_c base_health_c base_img_id s now_state now_health now_img v f1 f2
    local -a svcs=() ctrs=()
    local -A svc1=() ctr1=() ctr_base_health=() ctr_base_state=() ctr_base_img=()
    say_sect "Servicii, timere și containere"
    if [[ "$(base_state "${BASE}/services.txt")" == measured ]]; then mapfile -t svcs < "${BASE}/services.txt"
    else say_unk "lista serviciilor nu s-a măsurat la baseline — nu pot cere să fie toate sus"; fi
    if [[ "$(base_state "${BASE}/containers.tsv")" == measured ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS='|' read -r name _ _ _ base_img_id _ base_state_c base_health_c _ _ _ <<< "$line"
            [[ "$base_state_c" == running ]] || continue
            ctrs+=("$name"); ctr_base_health[$name]="$base_health_c"; ctr_base_state[$name]="$base_state_c"; ctr_base_img[$name]="$base_img_id"
        done < "${BASE}/containers.tsv"
    else
        say_unk "lista containerelor nu s-a măsurat la baseline — nu pot judeca ce ar fi trebuit să ruleze"
    fi

    # așteptare mărginită: după un reboot, serviciile și containerele pornesc pe rând
    deadline=$(( $(now_epoch) + WAIT_S ))
    while :; do
        pending=0
        for u in ${svcs[@]+"${svcs[@]}"}; do
            [[ "$(systemctl is-active "$u" || true)" == active ]] || pending=1
        done
        for name in ${ctrs[@]+"${ctrs[@]}"}; do
            s="$(ctr_sample "$name")"
            case "$(su_health_class "${s%%|*}" "$(cut -d'|' -f2 <<< "$s")")" in starting|down) pending=1 ;; esac
        done
        (( pending == 0 )) && break
        (( $(now_epoch) < deadline )) || break
        sleep "$POLL_S"
    done

    for u in ${svcs[@]+"${svcs[@]}"}; do svc1[$u]="$(svc_sample "$u")"; done
    for name in ${ctrs[@]+"${ctrs[@]}"}; do ctr1[$name]="$(ctr_sample "$name")"; done
    say_info "pauză ${GAP_S}s între cele două eșantioane (activ o singură dată nu dovedește că rămâne pornit)"
    sleep "$GAP_S"

    for u in ${svcs[@]+"${svcs[@]}"}; do
        s="$(svc_sample "$u")"
        v="$(su_flap_verdict "${svc1[$u]}" "$s" active)"
        case "$v" in
            stable)   ;;
            flapping) say_bad "${u}: se repornește (${svc1[$u]} -> ${s}: stare|reporniri|moment-intrare-activ)" ;;
            *)        say_bad "${u}: nu e activ (${svc1[$u]} apoi ${s}) — era activ la baseline" ;;
        esac
    done
    (( ${#svcs[@]} == 0 )) || say_info "servicii verificate (baseline: pornite și activate): ${#svcs[@]}"

    if [[ "$(base_state "${BASE}/timers.txt")" == measured ]]; then
        while IFS= read -r u; do
            [[ -n "$u" ]] || continue
            [[ "$(systemctl is-active "$u" || true)" == active ]] || say_bad "temporizatorul ${u} nu mai e activ (era la baseline)"
        done < "${BASE}/timers.txt"
    else
        say_unk "lista temporizatoarelor nu s-a măsurat la baseline"
    fi

    for name in ${ctrs[@]+"${ctrs[@]}"}; do
        s="$(ctr_sample "$name")"
        IFS='|' read -r now_state now_health _ _ now_img _ <<< "$s"
        v="$(su_container_verdict "${ctr_base_state[$name]}" "${ctr_base_health[$name]}" "$now_state" "$now_health")"
        case "$v" in
            ok)
                f1="$(cut -d'|' -f1,3,4 <<< "${ctr1[$name]}")"; f2="$(cut -d'|' -f1,3,4 <<< "$s")"
                if [[ "$(su_flap_verdict "$f1" "$f2" running)" != stable ]]; then
                    say_bad "${name}: se repornește (${f1} -> ${f2}: stare|reporniri|pornit-la)"
                fi ;;
            same-bad) SAME_LIST+=("container ${name}: ${now_state}/${now_health} și la baseline"); say_info "${name}: ${now_state}/${now_health} — era la fel și la baseline" ;;
            worse)    say_bad "${name}: ${now_state}/${now_health}, baseline ${ctr_base_state[$name]}/${ctr_base_health[$name]}" ;;
            pending)  say_bad "${name}: încă 'starting' după ${WAIT_S}s de așteptare" ;;
            *)        say_unk "${name}: nu pot compara sănătatea (baseline ${ctr_base_health[$name]}, acum ${now_health})" ;;
        esac
        if [[ -n "${ctr_base_img[$name]}" && "$now_img" != "${ctr_base_img[$name]}" && "$now_img" != "-" ]]; then
            CHANGED_LIST+=("${name}: imagine ${ctr_base_img[$name]:7:12} -> ${now_img:7:12}")
        fi
    done
    (( ${#ctrs[@]} == 0 )) || say_info "containere care rulau la baseline: ${#ctrs[@]}"
}

verify_http() {
    local now name code base v ok_n=0 conf
    say_sect "nginx și vhosturi"
    if have nginx; then
        if conf="$(nginx -t 2>&1)"; then say_ok "nginx -t: configurația e validă"; else say_bad "nginx -t a eșuat: $(tail -n 2 <<< "$conf" | tr '\n' ' ')"; fi
    fi
    if [[ "$(base_state "${BASE}/http.tsv")" != measured ]]; then say_unk "codurile HTTP nu s-au măsurat la baseline — nu pot compara"; return 0; fi
    now="$(mktemp)"
    if ! m_http > "$now"; then rm -f "$now"; say_unk "nu pot proba vhosturile acum (nginx -T a eșuat)"; return 0; fi
    while IFS='|' read -r name base; do
        [[ -n "$name" ]] || continue
        code="$(awk -F'|' -v n="$name" '$1 == n { print $2; exit }' "$now")"
        v="$(su_http_verdict "$base" "$code")"
        case "$v" in
            ok)       ok_n=$((ok_n + 1)) ;;
            worse)    say_bad "${name}: HTTP ${code}, la baseline ${base}" ;;
            same-bad) SAME_LIST+=("vhost ${name}: HTTP ${code} și la baseline"); say_info "${name}: HTTP ${code} — la fel și la baseline" ;;
            *)        say_unk "${name}: nu pot compara (baseline '${base}', acum '${code}')" ;;
        esac
    done < "${BASE}/http.tsv"
    rm -f "$now"
    say_info "vhosturi care răspund cel puțin la fel de bine ca la baseline: ${ok_n}"
}

verify_probes() {
    local now key base cur v
    say_sect "Sonde (auditd, nftables, baze de pe gazdă)"
    if [[ "$(base_state "${BASE}/probes.kv")" != measured ]]; then say_unk "sondele nu s-au măsurat la baseline"; return 0; fi
    now="$(mktemp)"; m_probes > "$now"
    while IFS='=' read -r key base; do
        [[ -n "$key" ]] || continue
        cur="$(kv_get "$now" "$key")"
        v="$(su_probe_verdict "$base" "$cur")"
        case "$v" in
            ok)      say_ok "${key}: ${base} -> ${cur}" ;;
            worse)   say_bad "${key}: ${base} -> ${cur} (mai rău decât la baseline)" ;;
            na)      ;;
            *)       say_unk "${key}: baseline '${base}', acum '${cur}' — nu pot compara" ;;
        esac
    done < "${BASE}/probes.kv"
    rm -f "$now"
}

verify_summary() {
    local item now n
    say_sect "Rezumat"
    if [[ "$(base_state "${BASE}/${PKG_LIST_FILE}")" == measured ]]; then
        now="$(mktemp)"
        if m_pkg_list > "$now"; then
            n="$(su_new_lines "${BASE}/${PKG_LIST_FILE}" "$now" | wc -l)"
            CHANGED_LIST+=("${n} pachete instalate sau actualizate față de baseline")
        fi
        rm -f "$now"
    fi
    if [[ -s "${BASE}/containers.report" ]]; then
        # Raportul e un jurnal cumulativ; ce se arată e rezultatul FINAL al fiecărui serviciu (su_report_final):
        # un `up-to-date` de la o rulare repetată nu șterge un `failed` ori un `recreated` de dinainte, iar un
        # eșec rămas neînlocuit de o verificare nouă e o PROBLEMĂ a verificării, nu o notă de subsol.
        local key action detail
        while IFS='|' read -r key action detail; do
            if su_is_sticky "$action"; then       # aceeași listă și aceeași reducere ca în faza containers (su_report_final)
                SKIP_LIST+=("${key}: ${action} — ${detail}")
                say_bad "${key}: rezultat final din faza containers = ${action} ($(su_episode_strip "$detail")); niciun succes specific, verificat, nu l-a rezolvat. $(su_sticky_hint "$action" "${key%%/*}" "${key#*/}")"
                continue
            fi
            case "$action" in
                acked)      ;;        # se arată mai jos, din modul `acked` al reducerii: și când un `stale-baseline` rămas îl acoperă în rezultatul final
                recreated)  CHANGED_LIST+=("${key}: recreat ${detail}") ;;
                skip*|hold*) SKIP_LIST+=("${key}: ${action} — ${detail}") ;;
            esac
        done < <(su_report_final "${BASE}/containers.report")
        # Recunoașterile operatorului (--acknowledge) apar MEREU, cu cheia serviciului, ca avertisment: ce e recunoscut nu e rezolvat, iar un verify verde
        # care nu le-ar pomeni ar face din decizia unui om o reușită.
        while IFS='|' read -r key action detail; do
            SKIP_LIST+=("${key}: acked — ${detail}"); ACK_N=$((ACK_N + 1))
            say_warn "${key}: recunoscut de operator (--acknowledge), NERESOLVAT în fapt — ${detail}"
        done < <(su_report_final "${BASE}/containers.report" acked)
    fi
    printf '\nCe s-a schimbat:\n'
    if (( ${#CHANGED_LIST[@]} )); then for item in "${CHANGED_LIST[@]}"; do printf '  + %s\n' "$item"; done; else printf '  (nimic înregistrat)\n'; fi
    printf '\nMai rău decât la baseline:\n'
    if (( ${#BAD_LIST[@]} )); then for item in "${BAD_LIST[@]}"; do printf '  x %s\n' "$item"; done; else printf '  (nimic)\n'; fi
    printf '\nRău și la baseline (nu vine din această schimbare):\n'
    if (( ${#SAME_LIST[@]} )); then for item in "${SAME_LIST[@]}"; do printf '  = %s\n' "$item"; done; else printf '  (nimic)\n'; fi
    printf '\nNecunoscut — n-am putut măsura (NU e «bine»):\n'
    if (( ${#UNK_LIST[@]} )); then for item in "${UNK_LIST[@]}"; do printf '  ? %s\n' "$item"; done; else printf '  (nimic)\n'; fi
    printf '\nSărit sau eșuat la faza containers:\n'
    if (( ${#SKIP_LIST[@]} )); then for item in "${SKIP_LIST[@]}"; do printf '  - %s\n' "$item"; done; else printf '  (nimic)\n'; fi
    printf '\nPas următor recomandat: ./scripts/smoke-test.sh (verifică și nftables, autoverificarea Sentinel, vhostul Sentinel din exterior).\n'
}

# O verificare «verde» nu are voie să însemne «nu s-a întâmplat nimic». Fazele care schimbă gazda
# lasă `.started` (înainte de prima schimbare) și `.ok` (doar la reușită dovedită): `.started` fără
# `.ok` = a murit sau a eșuat la jumătate. Lipsa lui `os.started` când baseline-ul avea pachete
# de actualizat înseamnă că actualizarea n-a rulat deloc.
verify_phases_done() {
    local ph
    say_sect "Fazele care schimbă gazda"
    for ph in os containers; do
        if [[ -f "${BASE}/phases/${ph}.ok" ]]; then
            say_ok "faza ${ph}: încheiată cu succes dovedit (${ph}.ok)"
            # o rulare PARȚIALĂ (--only) care a pornit după rularea completă și n-a ajuns la capăt a schimbat poate ceva: containers.ok
            # vechi nu o acoperă
            if [[ "$ph" == containers && -f "${BASE}/phases/containers.only.started" && ! -f "${BASE}/phases/containers.only.ok" ]]; then
                say_bad "o rulare parțială a fazei containers (--only) a PORNIT după containers.ok și n-a ajuns la capăt — a eșuat sau unitatea a murit; containers.ok de dinainte nu o acoperă"
            fi
        elif [[ "$ph" == containers && -f "${BASE}/phases/containers.only.started" && ! -f "${BASE}/phases/containers.started" ]]; then
            say_bad "faza containers: au rulat doar rulări parțiale (--only), niciuna care să acopere toate proiectele — nu există containers.ok; ce arată restul verificării NU e o actualizare dovedită a tuturor containerelor"
        elif [[ -f "${BASE}/phases/${ph}.started" ]]; then
            say_bad "faza ${ph} a PORNIT dar n-a ajuns la ${ph}.ok — a eșuat sau unitatea a murit; ce arată restul verificării NU e o actualizare reușită"
        elif [[ "$ph" == os ]]; then
            if [[ "$(base_state "${BASE}/pending.txt")" == measured && -s "${BASE}/pending.txt" ]]; then
                say_bad "faza os n-a rulat deloc, iar baseline-ul avea $(wc -l < "${BASE}/pending.txt") pachete de actualizat — nimic de verificat din actualizare"
            else
                say_info "faza os n-a rulat (baseline-ul n-avea actualizări în așteptare sau n-a fost măsurat)"
            fi
        else
            say_info "faza containers n-a rulat"
        fi
    done
}

# Serviciile care rulau dar erau `disabled` la baseline nu revin după reboot decât dacă le
# readuce altceva (containerd vine odată cu docker; php82-php-fpm nu).
verify_disabled_running() {
    local u
    [[ "$(base_state "${BASE}/disabled-running.txt")" == measured ]] || { say_unk "lista serviciilor pornite dar disabled nu s-a măsurat la baseline"; return 0; }
    while IFS= read -r u; do
        [[ -n "$u" ]] || continue
        if [[ "$(systemctl is-active "$u" || true)" == active ]]; then
            say_ok "${u}: rulează (era pornit dar 'disabled' la baseline)"
        else
            say_bad "${u}: NU rulează, deși rula la baseline; e 'disabled' deci nu revine după reboot — pornește-l de mână sau activează-l (nu schimb eu asta)"
        fi
    done < "${BASE}/disabled-running.txt"
}

phase_verify() {
    need_root; require_pkg_baseline
    say_sect "Verificare față de baseline ${BASE##*/}"
    verify_phases_done
    verify_boot
    verify_failed_units
    verify_running_things
    verify_disabled_running
    verify_http
    verify_probes
    verify_summary
    finish
}

# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------
# boot_files_ok VERSIUNE — nucleul NUMIT există pe disc cu fișiere de mărime credibilă. Se întreabă
# nucleul care va PORNI (cel din `grubby --default-kernel`), nu cel mai nou instalat: pot diferi.
# Tipărește motivul când nu e bine.
boot_files_ok() {
    local ver="$1" dir="${SU_BOOT_DIR:-/boot}" min="${SU_MIN_BOOT_FILE_BYTES:-1000000}" f sz bad=0
    for f in "vmlinuz-${ver}" "$(boot_initrd_file "$ver")"; do
        if [[ ! -f "${dir}/${f}" ]]; then printf '%s lipsește; ' "$f"; bad=1; continue; fi
        sz="$(stat -c %s "${dir}/${f}")" || sz=0
        if (( sz < min )); then printf '%s are doar %s octeți (minim %s); ' "$f" "$sz" "$min"; bad=1; fi
    done
    (( bad == 0 ))
}

# Reboot-ul schimbă gazda: nu se programează peste o actualizare care n-a ajuns la capăt. `os.ok` sau
# un `os` care n-a avut nimic de făcut (nicio actualizare în baseline) sunt starea cerută; `os.started`
# fără `os.ok` înseamnă o tranzacție căzută la jumătate, iar o repornire peste ea e cea mai proastă
# clipă posibilă. Ieșirea deliberată: --ignore-os-state, tastat de operator.
reboot_os_state_gate() {
    if [[ -f "${BASE}/phases/os.ok" ]]; then say_ok "faza os încheiată cu succes dovedit (os.ok)"; return 0; fi
    local why carried_boot live_boot
    carried_boot="$(pf_os_boot_of "$BASE")"; live_boot="$(current_boot_id)"
    if [[ -f "${BASE}/os-carried.kv" && -n "$carried_boot" && "$carried_boot" == "$live_boot" ]]; then
        say_ok "faza os încheiată cu succes dovedit în baseline-ul anterior (preluat în os-carried.kv), pe acest boot"; return 0
    fi
    if [[ -f "${BASE}/phases/os.started" ]]; then
        why="faza os a PORNIT dar n-a ajuns la os.ok (a eșuat sau unitatea a murit) — o repornire peste o tranzacție ${PKG_MGR} neterminată e riscul cel mai mare"
    elif [[ "$(base_state "${BASE}/pending.txt")" == measured && ! -s "${BASE}/pending.txt" ]]; then
        say_ok "faza os n-a rulat, dar baseline-ul n-avea nicio actualizare în așteptare"; return 0
    else
        why="faza os n-a rulat, iar baseline-ul avea actualizări în așteptare (sau n-a fost măsurat)"
    fi
    if (( OPT_IGNORE_OS_STATE )); then
        say_warn "${why} — continui doar fiindcă ai dat --ignore-os-state"; return 0
    fi
    say_bad "${why}. Refuz să programez reboot-ul; --ignore-os-state dacă știi ce faci"
}

phase_reboot() {
    need_root; require_pkg_baseline
    say_sect "Reboot"
    (( OPT_YES )) || die "reboot-ul cere --yes (confirmarea o ia system-update.sh de la operator, nu scriptul de pe gazdă)"
    local rc=0 out state running def def_ver newest boot_id why_files scheduled="${SU_SHUTDOWN_SCHEDULED:-/run/systemd/shutdown/scheduled}" need=no why=""
    pf_check_pkg_idle
    (( FAIL_N == 0 )) || finish
    reboot_os_state_gate
    (( FAIL_N == 0 )) || finish

    out="$(reboot_probe 2>&1)" || rc=$?
    state="$(su_reboot_needed_from_rc "$rc")"
    running="$(uname -r)"
    def="$(default_kernel)" || def=""
    rc=0; su_kernel_matches_default "$running" "$def" || rc=$?
    case "$state" in yes) need=yes; why="${REBOOT_PROBE_NAME} cere reboot" ;; esac
    [[ "$rc" == 1 ]] && { need=yes; why="${why:+${why}; }rulează ${running}, implicit e ${def##*/vmlinuz-}"; }
    if [[ "$state" == unknown || "$rc" == 2 ]]; then
        if (( OPT_FORCE )); then say_warn "nu pot afla dacă e nevoie de reboot; continui doar fiindcă ai dat --force"; need=yes; why="--force"
        else die "nu pot afla dacă e nevoie de reboot (${REBOOT_PROBE_NAME}: ${state}, ${KDEF_NAME}: cod ${rc}) — refuz să ghicesc; --force ca să-l faci oricum"
        fi
    fi
    if [[ "$need" == no ]]; then
        if (( OPT_FORCE )); then need=yes; why="--force"
        else say_ok "nu e nevoie de reboot (${REBOOT_PROBE_NAME}: nu; nucleul care rulează e cel implicit)"; finish
        fi
    fi
    say_info "reboot necesar: ${why}"

    # Nucleul care PORNEȘTE e cel implicit în grubby. Fișierele lui trebuie să existe (un nucleu
    # implicit fără initramfs nu pornește; pe un VPS asta înseamnă consola providerului), iar el
    # trebuie să fie cel mai nou instalat — aceeași condiție pe care o semnalează faza os.
    def_ver="${def##*/vmlinuz-}"
    newest="$(newest_installed_kernel)" || newest=""
    if [[ -z "$def_ver" ]]; then
        say_bad "nu pot citi nucleul implicit (${KDEF_CMD}) — nu știu ce ar porni"
    elif why_files="$(boot_files_ok "$def_ver")"; then
        say_ok "fișierele nucleului implicit (${def_ver}) există: vmlinuz și initramfs"
    else
        say_bad "nucleul implicit (${def_ver}) NU poate porni: ${why_files%; }"
    fi
    if [[ -n "$def_ver" && -n "$newest" && "$def_ver" != "$newest" ]]; then
        say_bad "nucleul implicit la pornire (${def_ver}) nu e cel mai nou instalat (${newest}) — reboot-ul ar porni alt nucleu decât cel actualizat"
    fi
    if [[ -s "${BASE}/no-restart-policy.txt" ]]; then
        say_warn "aceste containere NU au politică de repornire și vor rămâne oprite după reboot:"; cat "${BASE}/no-restart-policy.txt"
    fi
    (( FAIL_N == 0 )) || finish

    boot_id="$(cat "${SU_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}")"
    mkdir -p "${BASE}/phases"
    printf 'run=%s\nepoch=%s\nboot_id=%s\n' "$RUN_ID" "$(now_epoch)" "$boot_id" > "${BASE}/phases/reboot.requested"
    sync
    rm -f "$scheduled" || true
    rc=0; shutdown -r +1 "Actualizare de sistem: repornire programată de system-update.sh (anulare: shutdown -c)" || rc=$?
    # Codul lui shutdown spune că s-a trimis cererea; fișierul scris de systemd spune că e programat.
    if (( rc == 0 )) && [[ -f "$scheduled" ]] && grep -q '^MODE=reboot' "$scheduled"; then
        say_ok "repornirea e PROGRAMATĂ (${scheduled}: MODE=reboot) — peste ~1 minut. Anulare: shutdown -c"
        say_info "după ~3-5 minute: ./scripts/system-update.sh ... --phase verify"
    else
        rm -f "${BASE}/phases/reboot.requested"
        say_bad "shutdown -r a ieșit cu ${rc}, dar nu există o repornire programată (${scheduled} lipsește sau nu are MODE=reboot) — NU s-a programat nimic"
    fi
    finish
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

# Codul de ieșire al lui `status` e verdictul, nu «am afișat»: 0 doar dacă fiecare fază pornită
# (os, containers) are un rezultat reușit și ultimul rezultat al fiecărei faze rulate e 0.
#   1  o fază a eșuat, a murit fără rezultat, sau a pornit și n-a ajuns la `.ok`
#   3  ceva încă rulează (nu e verdict) sau ultimul rezultat e «necunoscut»
# Un `status` care ieșea mereu cu 0 făcea ca lansatorul să tipărească «totul dovedit» peste un os eșuat.
phase_status() {
    need_root
    local ph f latest dry_latest st rc verdict=0 units
    say_sect "Stare"
    if [[ -n "$BASE" ]]; then
        say_info "baseline curent: ${BASE} ($(wc -l < "${BASE}/containers.tsv" || echo '?') containere)"
    else
        say_info "nu există baseline (rulează preflight)"
    fi
    for ph in preflight backup os containers reboot verify; do
        # Ultimul rezultat REAL al fazei. O simulare (`dry_run=1`, scrisă de write_result) nu schimbă nimic, iar un `--dry-run` roșu nu are voie să
        # întoarcă verdictul în EȘEC peste o fază care a ieșit verde în serios; apare doar ca o linie etichetată, dacă e mai nouă decât rezultatul real.
        latest=""; dry_latest=""
        while IFS= read -r f; do
            if [[ "$(kv_get "$f" dry_run)" == 1 ]]; then [[ -n "$dry_latest" ]] || dry_latest="$f"; continue; fi
            latest="$f"; break
        done < <(find "${SU_STATE}/runs" -maxdepth 1 -name "${ph}-*.result" | LC_ALL=C sort -r)
        if [[ -n "$dry_latest" ]]; then
            printf '  %-10s simulare (--dry-run, NU intră în verdict): %s rc=%s la %s (jurnal: %s)\n' "$ph" "$(kv_get "$dry_latest" status)" "$(kv_get "$dry_latest" rc)" \
                "$(date -d "@$(kv_get "$dry_latest" finished)" '+%F %T' || echo '?')" "${dry_latest%.result}.log"
        fi
        if [[ -z "$latest" ]]; then printf '  %-10s (niciodată rulată în serios)\n' "$ph"; continue; fi
        st="$(kv_get "$latest" status)"; rc="$(kv_get "$latest" rc)"
        printf '  %-10s %s rc=%s la %s (jurnal: %s)\n' "$ph" "$st" "$rc" \
            "$(date -d "@$(kv_get "$latest" finished)" '+%F %T' || echo '?')" "${latest%.result}.log"
        awk '/^bad=/ { sub(/^bad=/, "      x "); print; if (++c >= 8) exit }' "$latest"
        awk '/^unknown_item=/ { sub(/^unknown_item=/, "      ? "); print; if (++c >= 8) exit }' "$latest"
        if [[ "$rc" == 1 || "$st" == fail || "$st" == aborted ]]; then
            verdict=1
        elif [[ "$rc" == 3 || "$st" == unknown ]]; then
            (( verdict == 1 )) || verdict=3
        fi
    done
    # Fazele cu urmări pe gazdă: `.started` fără `.ok` înseamnă că au schimbat ceva și n-au dovedit
    # că au terminat (cod 1, nu «necunoscut»: unitatea a murit sau a eșuat).
    for f in os containers; do
        if [[ -n "$BASE" && -f "${BASE}/phases/${f}.started" && ! -f "${BASE}/phases/${f}.ok" ]]; then
            say_bad "faza ${f} a PORNIT (a schimbat ceva) dar nu are marcajul de reușită ${f}.ok"
            verdict=1
        fi
    done
    # O rulare PARȚIALĂ (`containers --only`) are markerele ei: `.only.started` fără `.only.ok` = a pornit și n-a ajuns la capăt (verify o vede;
    # status ignora perechea și citea doar `containers.started`/`.ok`).
    if [[ -n "$BASE" && -f "${BASE}/phases/containers.only.started" && ! -f "${BASE}/phases/containers.only.ok" ]]; then
        say_bad "o rulare parțială a fazei containers (--only) a PORNIT dar nu are marcajul de reușită containers.only.ok"
        verdict=1
    fi
    # Recunoașterile operatorului din faza containers (--acknowledge): un avertisment cu cheia serviciului, MEREU. Nu schimbă verdictul (ce e recunoscut
    # e o decizie, nu un eșec nou), dar un `status` care le-ar tăcea ar lăsa un serviciu nerezolvat să arate «nimic eșuat».
    if [[ -n "$BASE" && -s "${BASE}/containers.report" ]]; then
        local ak_key ak_act ak_det
        while IFS='|' read -r ak_key ak_act ak_det; do
            say_warn "${ak_key}: recunoscut de operator (--acknowledge), NERESOLVAT în fapt — ${ak_det}"; ACK_N=$((ACK_N + 1))
        done < <(su_report_final "${BASE}/containers.report" acked)
    fi
    units="$(systemctl list-units 'system-update-*' --all --no-legend --plain | awk 'NF { print $1 " " $3 }')" || units=""
    if [[ -n "$units" ]]; then
        say_info "unități system-update-*:"; printf '%s\n' "$units"
        if grep -qE ' (active|activating)$' <<< "$units"; then
            say_warn "o fază încă rulează — nu e un verdict"
            (( verdict == 1 )) || verdict=3
        fi
    fi
    if [[ -f "${SU_STATE}/backup.manifest" ]]; then
        say_info "ultimul backup: $(date -d "@$(kv_get "${SU_STATE}/backup.manifest" epoch)" '+%F %T' || echo '?'); $(grep -c '^ok|' "${SU_STATE}/backup.manifest" || true) ok, $(grep -c '^failed|' "${SU_STATE}/backup.manifest" || true) eșuate"
    fi
    [[ -z "$BASE" || ! -f "${BASE}/phases/reboot.requested" ]] || say_info "marcaj în baseline: reboot.requested"
    printf '\nVERDICT status: %s\n' "$( case "$verdict" in 0) if (( ACK_N > 0 )); then echo "nimic eșuat sau neterminat, cu ${ACK_N} servicii recunoscute de operator (NERESOLVATE în fapt)"; else echo 'nimic eșuat sau neterminat'; fi;; 1) echo 'EȘEC sau fază neterminată';; *) echo 'NECUNOSCUT / în curs';; esac )"
    return "$verdict"
}
