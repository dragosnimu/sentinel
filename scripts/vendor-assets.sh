#!/usr/bin/env bash
#
# Download the front-end libraries the dashboard needs, verify their checksums,
# and place them under sentinel/web/static/vendor/.
#
#   ./scripts/vendor-assets.sh          # download anything missing
#   ./scripts/vendor-assets.sh --verify # check what is already there, download nothing
#   ./scripts/vendor-assets.sh --force  # re-download everything
#
# WHY THIS EXISTS
#
# The dashboard loads no third-party JavaScript from a CDN. On a security
# dashboard a CDN would mean a third party able to inject code into the interface
# you use to investigate incidents, plus a leak of the dashboard's existence to
# that third party on every page view. Vendoring locally is what allows the CSP
# to be `script-src 'self'` with no `unsafe-inline` — and that policy is why an
# XSS here would have nowhere to load a payload from.
#
# The files are NOT committed to the repository: binary-ish minified blobs in git
# are unreviewable, and a pinned checksum plus a download is both auditable and
# smaller. `install.sh` runs this, and the checksums below are the trust anchor.
#
# P1 needs none of this — the login page and the status dashboard are plain HTML
# and CSS. Charts arrive in P2.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${REPO_ROOT}/sentinel/web/static/vendor"

MODE="download"
[[ "${1:-}" == "--verify" ]] && MODE="verify"
[[ "${1:-}" == "--force"  ]] && MODE="force"

_R=$'\033[31m'; _G=$'\033[32m'; _Y=$'\033[33m'; _B=$'\033[34m'; _0=$'\033[0m'
ok()   { printf '%s[+]%s %s\n' "$_G" "$_0" "$*"; }
info() { printf '%s[.]%s %s\n' "$_B" "$_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$_Y" "$_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$_R" "$_0" "$*" >&2; exit 1; }

# name|version|url|sha256
#
# Update procedure, and it is not optional:
#   1. Download the new file by hand.
#   2. Read the release notes and diff against the version you are replacing.
#   3. Compute the checksum with `sha256sum` and put it here.
#   4. Commit the manifest change on its own, so the version bump is reviewable.
#
# Never paste a checksum taken from the same page you downloaded the file from
# without a second source: if the mirror is compromised, so is the checksum
# printed next to the link.
ASSETS=(
  # htmx 2.x — partial page updates without a build step or a framework.
  "htmx.min.js|2.0.4|https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js|"
  # uPlot — time-series charts. ~45 KB against Chart.js's ~200 KB, and far
  # faster with tens of thousands of points, which every analytics page has.
  "uPlot.iife.min.js|1.6.31|https://unpkg.com/uplot@1.6.31/dist/uPlot.iife.min.js|"
  "uPlot.min.css|1.6.31|https://unpkg.com/uplot@1.6.31/dist/uPlot.min.css|"
)

mkdir -p "$VENDOR_DIR"

missing_checksums=0
downloaded=0
verified=0

for entry in "${ASSETS[@]}"; do
    IFS='|' read -r name version url expected <<< "$entry"
    target="${VENDOR_DIR}/${name}"

    if [[ -z "$expected" ]]; then
        # Deliberately empty in the shipped manifest: pinning a checksum that
        # nobody in this project has verified would be security theatre. The
        # operator pins it once, reviewably, on first use.
        missing_checksums=$((missing_checksums + 1))
        warn "${name}: no pinned checksum in the manifest."
        warn "    Download it, review it, then pin the digest:"
        warn "      curl -fsSL -o '${target}' '${url}'"
        warn "      sha256sum '${target}'"
        warn "    Put that digest in ASSETS in this script and re-run."
        continue
    fi

    if [[ -f "$target" && "$MODE" != "force" ]]; then
        actual="$(sha256sum "$target" | cut -d' ' -f1)"
        if [[ "$actual" == "$expected" ]]; then
            ok "${name} ${version} present, checksum matches"
            verified=$((verified + 1))
            continue
        fi
        die "${name}: checksum MISMATCH.
    expected ${expected}
    actual   ${actual}
  This is either a corrupted file or a tampered one. Do not work around it —
  delete the file and re-run, and if it happens again investigate before
  deploying anything."
    fi

    [[ "$MODE" == "verify" ]] && { warn "${name}: absent"; continue; }

    info "downloading ${name} ${version}"
    tmp="$(mktemp)"
    curl -fsSL --max-time 60 -o "$tmp" "$url" || { rm -f "$tmp"; die "download failed: ${name}"; }

    actual="$(sha256sum "$tmp" | cut -d' ' -f1)"
    if [[ "$actual" != "$expected" ]]; then
        rm -f "$tmp"
        die "${name}: checksum mismatch on a fresh download.
    expected ${expected}
    actual   ${actual}
  Either the manifest is stale or the mirror is serving something else.
  Refusing to install it."
    fi

    mv "$tmp" "$target"
    chmod 0644 "$target"
    ok "${name} ${version} installed"
    downloaded=$((downloaded + 1))
done

printf '\n'
if (( missing_checksums > 0 )); then
    warn "${missing_checksums} asset(s) have no pinned checksum and were skipped."
    warn "The dashboard works without them until charts arrive in P2."
fi
ok "vendor: ${verified} verified, ${downloaded} downloaded, in ${VENDOR_DIR}"

cat <<'EOF'

  Reminder: these files are gitignored on purpose. A minified blob in git is
  unreviewable; a pinned checksum plus a download is auditable. install.sh runs
  this script, so a fresh deploy fetches them the same way.

EOF
