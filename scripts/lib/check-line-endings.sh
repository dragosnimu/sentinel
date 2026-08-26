#!/usr/bin/env bash
#
# Refuse a deploy package that carries CR bytes inside a text file.
#
#   check-line-endings.sh <package.tar.gz> [source-root]
#
# Exit codes, and there are three on purpose:
#
#   0  every text file in the package is LF-only
#   1  at least one text file carries CR — every offender is named
#   2  the package could not be inspected. "Unknown" is not "clean", and the
#      caller must be able to tell the two apart.
#
# ---------------------------------------------------------------------------
# Why the check has this shape
#
# The guard this replaces looked for CR under deploy/ in *.sh and *.service,
# and its comment claimed it caught "everything else". Two things were wrong.
#
# The file set. deploy/audit/sentinel.rules is neither extension, and a
# trailing CR there turns the audit key `sentinel_ssh` into `sentinel_ssh^M`.
# auditd loads the rule, the kernel accepts it, the collector then matches
# nothing at all — and no component anywhere reports a fault. Blind, and quiet
# about being blind.
#
# The tree. The package is `tar -C "$REPO_ROOT" .` minus an exclude list, so
# sentinel/, scripts/, executor/ and .claude/ ship too. A CR does not break a
# .py module, but it does break a shebang, and executor/ runs as root.
#
# So the criterion is not a list of extensions — that is the thing that failed.
# It is: *does this byte sequence reach the server, and is it text?* Everything
# the host parses breaks on CR in its own quiet way: sh, systemd, auditd,
# nginx, SQL, YAML, a shebang line. The files where CR is genuinely harmless
# cannot be enumerated honestly, so they are not exempted.
#
# The subject is the PACKAGE, not the working tree, because the tarball is the
# artefact that leaves this machine. Inspecting it needs no second copy of the
# exclude list, so this guard cannot drift out of step with what tar actually
# put in there — which is how the old guard came to cover two extensions in one
# directory while the package carried five hundred files.
#
# Two exemptions, both deliberate:
#
#   * binary files, decided by CONTENT (a NUL byte) and not by name, so a new
#     binary format does not need a new exception here and cannot raise a false
#     alarm either;
#   * *.ps1, which ships only because scripts/ ships, is executed on Windows
#     alone, and is CRLF on purpose — see .gitattributes.
#
# It refuses; it does not repair. A silent repair would put correct bytes on
# the server and leave the working tree corrupt, so `git diff` would go on
# showing nothing and whatever rewrote those files would go on rewriting them.
# A refusal at three in the morning is annoying exactly once; a silent repair
# is invisible forever. The refusal therefore names every file and prints the
# command that fixes them.

set -euo pipefail

PKG="${1:-}"
SRC_ROOT="${2:-}"

_c_red=''; _c_reset=''
if [[ -t 2 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
    _c_red=$'\033[31m'; _c_reset=$'\033[0m'
fi

# The pattern, bound once here and NEVER written literally inside a $( ).
#
# Under Git Bash — the shell this script is normally run from — the MSYS layer
# strips CR out of the text of a command substitution, so
#
#     hits="$(grep -rlIU $'\r' "$dir")"
#
# hands grep an EMPTY pattern, which matches every line of every text file.
# Measured on bash 5.2.37 / MSYS2, 2026-08-10: the same grep outside a $( )
# returns one file, inside a $( ) it returns all of them. A variable expanded
# at run time is unaffected. This was found by the self-probe below on its
# first execution, which is the entire argument for having a self-probe.
CR=$'\r'

# Exit 2, never 0. Every path that ends in "I could not look" comes through
# here, so there is no way for this script to report a package clean on the
# strength of not having read it.
cannot_check() {
    printf '%serror:%s line-ending check could not run: %s\n' "$_c_red" "$_c_reset" "$*" >&2
    exit 2
}

[[ -n "$PKG" ]] || cannot_check "usage: check-line-endings.sh <package.tar.gz> [source-root]"
[[ -f "$PKG" ]] || cannot_check "no such package: ${PKG}"
command -v tar  >/dev/null 2>&1 || cannot_check "tar is not on PATH"
command -v grep >/dev/null 2>&1 || cannot_check "grep is not on PATH"

WORK="$(mktemp -d 2>/dev/null)" || cannot_check "could not create a temporary directory"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Prove the detector detects, before trusting its silence.
#
# `grep -lIU` does all the work below, and both flags matter: -U so a grep
# built for Windows does not strip the CR before it can match it, -I so a
# GeoIP database is not reported as a text file with strange line endings. A
# grep missing either would find nothing in any package, forever, and the guard
# would "pass" by never having looked — which is precisely the class of bug it
# exists to catch. Three files with known answers cost microseconds.
probe="${WORK}/probe"
mkdir -p "$probe"
printf 'a\r\n'      > "${probe}/crlf"
printf 'a\n'        > "${probe}/lf"
printf 'a\0b\r\n'   > "${probe}/binary"
probe_hits="$(grep -rlIU "$CR" "$probe" 2>/dev/null || true)"
case "$probe_hits" in
    *"${probe}/crlf"*) ;;
    *) cannot_check "grep did not flag a file known to contain CR; its silence proves nothing" ;;
esac
case "$probe_hits" in
    *"${probe}/lf"*) cannot_check "grep flagged a file known to be LF-only; its output cannot be used" ;;
esac
case "$probe_hits" in
    *"${probe}/binary"*) cannot_check "grep flagged a file known to be binary; -I is not honoured here" ;;
esac
rm -rf "$probe"

# ---------------------------------------------------------------------------
tree="${WORK}/pkg"
mkdir -p "$tree"
tar -xzf "$PKG" -C "$tree" >/dev/null 2>&1 || cannot_check "could not extract ${PKG}"

total="$(find "$tree" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
# An empty extraction would satisfy "no CR found" perfectly. It is not a clean
# package, it is the absence of one.
[[ "${total:-0}" -gt 0 ]] || cannot_check "${PKG} extracted to no files at all"

hits="${WORK}/hits"
grep -rlIU "$CR" "$tree" > "$hits" 2>/dev/null || true
sed -e "s|^${tree}/||" -e 's|^\./||' "$hits" | grep -v '\.ps1$' | sort > "${hits}.reported" || true

count="$(wc -l < "${hits}.reported" | tr -d '[:space:]')"
if [[ "${count:-0}" -gt 0 ]]; then
    printf '%serror:%s CR line endings in %s file(s) inside the deploy package:\n' \
        "$_c_red" "$_c_reset" "$count" >&2
    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        printf '    %s\n' "${SRC_ROOT:+${SRC_ROOT}/}${rel}" >&2
    done < "${hits}.reported"
    cat >&2 <<'EOF'

These would reach the server exactly as they are. A CR breaks a shebang
("bad interpreter: /bin/bash^M"), a systemd directive and an nginx value
loudly — and an auditd key silently: the rule loads and then matches nothing.

Fix them in the working tree, then deploy again:

    sed -i 's/\r//g' <the files listed above>

If git reports those files unmodified afterwards, something rewrote them
between commit and deploy: .gitattributes normalises on commit, not on disk.
EOF
    exit 1
fi

printf '%s file(s) in the package; no CR in any text file (binaries and *.ps1 exempt)\n' "$total"
exit 0
