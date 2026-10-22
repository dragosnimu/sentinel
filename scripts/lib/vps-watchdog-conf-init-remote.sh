#!/usr/bin/env bash
#
# The half of scripts/vps-watchdog-conf-init.sh that runs ON THE HOST, as root.
#
# Not run directly. The local script prepends five assignments (MODE, CONF, SRC,
# WANT_OWNER, WANT_MODE), ships the result base64 inside the ssh command string and
# feeds it to `sudo -n bash` through a pipe, so nothing about its quoting has to
# survive ssh (the technique of REMOTE_SECRETS_SCRIPT in scripts/deploy.sh). Run by
# hand without them, `set -u` stops it on the first line.
#
# It is a file of its own rather than a heredoc inside the local script because it is
# real shell with real functions: as a file it is read by `bash -n` and by the
# function-resolution gate (tests/unit/test_shell_function_calls_resolve.py), which
# treats a quoted heredoc as data and would never look at it.
#
# It reports FACTS as `VPSW:<NAME> <value>` lines and never judges them — except to
# stop. Judgement lives in the local script, in one place, where the tests can see it.
#
# It must not read its own stdin: bash is reading the script from it. No command
# below takes input from stdin.
#
# conf_get is the awk of conf_get in deploy/vps-watchdog/watchdog.sh, byte for byte
# (a test holds them equal): "the file says X" and "the watchdog reads X" must be the
# same sentence, or the read-back proves nothing about the consumer.
set -u
umask 077
emit() { printf 'VPSW:%s\n' "$*"; }
stop() { emit "ERR $*"; exit 1; }

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

conf_exists() { [ -e "$CONF" ] || [ -L "$CONF" ]; }

# Every quoted assignment of KEY in FILE outside comment lines, one per line,
# prefixed `V:` so that "no assignment" and "one empty assignment" differ. The old
# script puts several assignments on one line (`A=1; B="x"; C=...`), so this is
# not anchored to the start of the line; it is anchored to the start or a `;` or a
# space, which keeps OLD_HEALTH_DOMAINS and `for d in $HEALTH_DOMAINS` out.
assignments() {
    grep -v '^[[:space:]]*#' "$2" \
      | grep -o -E "(^|[;[:space:]])$1=(\"[^\"]*\"|'[^']*')" \
      | sed -E "s/^[;[:space:]]*$1=//; s/^[\"']//; s/[\"']\$//; s/^/V:/"
}

# Sets DOMAINS (single-space separated), N_DOMAINS, DIGEST, EXCLUDE_SET, EXCLUDE.
read_source() {
    [ -r "$SRC" ] || stop "nu pot citi ${SRC}: fara scriptul vechi nu am de unde lua domeniile"
    local vals n tok
    vals="$(assignments HEALTH_DOMAINS "$SRC")"
    n="$(printf '%s\n' "$vals" | grep -c '^V:')"
    [ "$n" -ge 1 ] || stop "nicio atribuire HEALTH_DOMAINS=\"...\" in ${SRC}: nu stiu ce domenii sa scriu"
    [ "$n" -eq 1 ] || stop "${n} atribuiri HEALTH_DOMAINS in ${SRC}: nu ghicesc care e cea buna"
    vals="${vals#V:}"
    set -f
    DOMAINS=""; N_DOMAINS=0
    for tok in $vals; do
        [[ "$tok" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] \
            || stop "un element din HEALTH_DOMAINS nu arata a nume de gazda: '${tok}'"
        DOMAINS="${DOMAINS:+${DOMAINS} }${tok}"; N_DOMAINS=$((N_DOMAINS + 1))
    done
    set +f
    [ "$N_DOMAINS" -ge 1 ] || stop "HEALTH_DOMAINS din ${SRC} e gol: o lista goala opreste in tacere singura verificare care priveste site-urile clientilor"
    DIGEST="$(printf '%s' "$DOMAINS" | sha256sum | cut -c1-12)"

    EXCLUDE_SET=0; EXCLUDE=""
    vals="$(assignments EXCLUDE_AUTOFIX "$SRC")"
    n="$(printf '%s\n' "$vals" | grep -c '^V:')"
    [ "$n" -le 1 ] || stop "${n} atribuiri EXCLUDE_AUTOFIX in ${SRC}: nu ghicesc care e cea buna"
    if [ "$n" -eq 1 ]; then
        EXCLUDE="${vals#V:}"
        [[ "$EXCLUDE" =~ ^[A-Za-z0-9._\ -]*$ ]] || stop "EXCLUDE_AUTOFIX din ${SRC} contine caractere neasteptate"
        EXCLUDE_SET=1
    fi
}

emit_source() {
    emit "DOMAINS_COUNT ${N_DOMAINS}"
    emit "DOMAINS_DIGEST ${DIGEST}"
    if [ "$EXCLUDE_SET" = 1 ]; then emit "EXCLUDE carried"; else emit "EXCLUDE absent"; fi
}

# What a file looks like NOW, read fresh. Used before publishing (on the
# temporary) and by the separate verify session (on the real name).
emit_file_facts() {
    local f="$1" t=other
    if [ -L "$f" ]; then t=symlink; elif [ -f "$f" ]; then t=regular; fi
    emit "TYPE ${t}"
    emit "OWNER $(stat -c '%U:%G' "$f")"
    emit "MODE $(stat -c '%a' "$f")"
    emit "LINKS $(stat -c '%h' "$f")"
}

case "$MODE" in
plan)
    if conf_exists; then emit "RESULT exists"; exit 0; fi
    read_source; emit_source; emit "RESULT plan"
    ;;
create)
    dir="$(dirname "$CONF")"
    [ -d "$dir" ] || stop "nu exista directorul ${dir}"
    if conf_exists; then emit "RESULT exists"; exit 0; fi
    read_source
    tmp="$(mktemp "${CONF}.XXXXXX")" || stop "nu pot crea un fisier temporar langa ${CONF}"
    trap 'rm -f "$tmp"' EXIT
    chown "$WANT_OWNER" "$tmp" || stop "chown ${WANT_OWNER} a esuat pe fisierul temporar"
    chmod "$WANT_MODE" "$tmp" || stop "chmod ${WANT_MODE} a esuat pe fisierul temporar"
    {
        printf '# %s - configuratia gazdei pentru vps-watchdog.\n' "$CONF"
        printf '# Creat de scripts/vps-watchdog-conf-init.sh la %s, din %s.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SRC"
        printf '# Prezenta lui este activarea: install.sh adopta watchdog-ul doar unde exista.\n'
        printf '# Sablon cu toate cheile: deploy/config/vps-watchdog.conf.example\n'
        printf 'HEALTH_DOMAINS="%s"\n' "$DOMAINS"
        if [ "$EXCLUDE_SET" = 1 ]; then printf 'EXCLUDE_AUTOFIX="%s"\n' "$EXCLUDE"; fi
    } > "$tmp" || stop "nu pot scrie ${tmp}"
    # The temporary is checked BEFORE it gets the real name: a conf in place is the
    # opt-in, and a wrong one adopts a host with the wrong settings.
    want_t="${WANT_OWNER} ${WANT_MODE}"
    got_t="$(stat -c '%U:%G %a' "$tmp")"
    [ "$got_t" = "$want_t" ] || stop "fisierul temporar are '${got_t}', nu '${want_t}': nu-l public"
    lnerr="$(ln "$tmp" "$CONF" 2>&1)" || {
        if conf_exists; then emit "RESULT exists"; exit 0; fi
        stop "ln nu a putut da numele ${CONF}: ${lnerr}"
    }
    rm -f "$tmp"
    emit_source
    emit "RESULT created"
    ;;
verify)
    conf_exists || { emit "RESULT absent"; exit 0; }
    emit "RESULT present"
    emit_file_facts "$CONF"
    keys="$(grep -v '^[[:space:]]*#' "$CONF" | sed -n -E 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' | sort -u | tr '\n' ' ')"
    emit "KEYS ${keys}"
    raw="$(conf_get "$CONF" HEALTH_DOMAINS)" || raw=""
    set -f
    n=0; bad=0; list=""
    for tok in $raw; do
        n=$((n + 1))
        [[ "$tok" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || bad=$((bad + 1))
        list="${list:+${list} }${tok}"
    done
    set +f
    emit "DOMAINS_COUNT ${n}"
    emit "DOMAINS_INVALID ${bad}"
    emit "DOMAINS_DIGEST $(printf '%s' "$list" | sha256sum | cut -c1-12)"
    ;;
*) stop "mod necunoscut: ${MODE}" ;;
esac
