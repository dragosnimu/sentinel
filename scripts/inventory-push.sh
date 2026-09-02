#!/usr/bin/env bash
#
# Push a reviewed inventory.yaml to the server. Read-only diagnostics stay
# read-only; the one write this script makes is deliberate and confirmed.
#
#   ./scripts/inventory-push.sh --host H --user U [--key K] [--port P] \
#       --file path/to/inventory.yaml [--yes] [--dry-run]
#
# CLAUDE.md is explicit: ssh direct is for diagnostics, not for changes —
# anything that modifies the host goes through a reviewed script. Until this
# one existed, inventory.yaml had no such path at all: the only way to change
# it was `ssh ... vim /etc/sentinel/inventory.yaml`, unversioned, unreviewed,
# and indistinguishable in the shell history from a diagnostic command.
#
# What it does, in order, and nothing else:
#
#   1. validates the LOCAL file with the same loader the runtime uses
#      (sentinel.scan.inventory.load) — before any network I/O, so a typo
#      never costs an SSH round trip. A file that validates but declares ZERO
#      assets is refused here too — see "Why an empty local file is refused"
#      below, not skipped as a false "nothing to retire";
#   2. reads what the HOST currently has (read-only: `sudo cat`, never a
#      write) and prints the diff — what gets added, what stays, and what
#      gets RETIRED. Retirement is destructive: a retired asset drops out of
#      health checks and the dashboard (sentinel/scan/inventory.py:sync). This
#      is the one chance to see that coming before it happens;
#   3. on confirmation — required whenever anything would be retired, skipped
#      only with --yes — writes the file to the host with install.sh's own
#      ownership and mode (root:sentinel, 0640).
#
# It does not start, stop, reload or restart anything. sentinel-health picks
# up inventory.yaml on its own probe cycle (see
# sentinel/services/health_service.py, `_sync_inventory`) — a push here takes
# effect there, not here, and there is no unit whose restart would make that
# happen sooner.
#
# ## Why an empty local file is refused
#
# `sentinel/scan/inventory.py:sync` cannot tell a genuinely empty inventory
# apart from a file truncated by a failed edit or a full disk — `load()`
# returns `[]` for all three — so it treats an empty list as "nothing to
# retire", not "retire everything" (see `sync`'s own docstring). If this
# script diffed an empty local file against a host with real assets on it, it
# would print "SE RETRAG: <everything>" and, on confirmation, write an empty
# file to the host — a retirement `sync` would then silently refuse to apply.
# The operator would believe the fleet just got smaller; the host would
# believe nothing changed. Refusing here, before the diff is even computed,
# closes the gap instead of describing it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_PATH="/etc/sentinel/inventory.yaml"

HOST=""; USER=""; KEY=""; PORT=22; FILE=""
ASSUME_YES=0; DRY_RUN=0; ALLOW_TRACKED=0

_G=$'\033[32m'; _R=$'\033[31m'; _Y=$'\033[33m'; _B=$'\033[34m'; _0=$'\033[0m'
ok()   { printf '%s[+]%s %s\n' "$_G" "$_0" "$*"; }
die()  { printf '%serror:%s %s\n' "$_R" "$_0" "$*" >&2; exit 1; }
warn() { printf '%s[!]%s %s\n' "$_Y" "$_0" "$*" >&2; }
info() { printf '%s[.]%s %s\n' "$_B" "$_0" "$*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  HOST="${2:-}"; shift 2 ;;
        --user)  USER="${2:-}"; shift 2 ;;
        --key)   KEY="${2:-}"; shift 2 ;;
        --port)  PORT="${2:-}"; shift 2 ;;
        --file)  FILE="${2:-}"; shift 2 ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --allow-tracked) ALLOW_TRACKED=1; shift ;;
        --help|-h) sed -n '2,40p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$HOST" && -n "$USER" && -n "$FILE" ]] \
    || die "--host, --user and --file are required"
[[ -f "$FILE" ]] || die "no such file: $FILE"

# Windows' `python3` routinely resolves to the Microsoft Store's stub
# launcher: a real, executable file that `command -v` happily finds, but
# running it prints "Python was not found; run without arguments to install
# from the Microsoft Store..." to stderr and exits nonzero. A bare presence
# check passes on that stub, and the FIRST real invocation below then fails —
# which this script would otherwise report as "does not pass
# sentinel.scan.inventory.load", telling the operator a VALID file is broken.
# Resolve to an interpreter that actually runs: `python3` first (the correct,
# and only, answer on the Linux/WSL hosts this script targets), `python` as
# the fallback for a Windows PATH where only that name works.
resolve_python() {
    local candidate out
    for candidate in python3 python; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        out="$("$candidate" --version 2>&1)" || continue
        [[ "$out" == *"was not found"* ]] && continue
        printf '%s' "$candidate"
        return 0
    done
    return 1
}
PYTHON_BIN="$(resolve_python)" || die "no working python3 (or python) interpreter on PATH. On \
Windows, \`python3\` resolving to the Microsoft Store stub is the usual cause — install Python, or \
put a real interpreter ahead of it on PATH."

# Resolved through `cd`+`pwd` in THIS shell, same as REPO_ROOT above — not
# just string-pasted. This normalises the DISPLAY and upload path; it is NOT
# what the leak-prevention check below relies on, because on Windows `cd`+`pwd`
# does not itself canonicalise a lowercase drive letter or an 8.3 short name
# to the same spelling `pwd` produced for REPO_ROOT — see the git-root
# comparison just below, which does not have that problem.
FILE="$(cd "$(dirname "$FILE")" && pwd)/$(basename "$FILE")"

# The one kind of file this exact repository has already leaked once — see
# deploy/config/inventory-filled.yaml.example's own header. A real inventory
# is a map of services, ports and exposures on someone's server: free
# reconnaissance, the moment it lands in a public repo. Refuse by default if
# the given path is inside THIS repo's working tree and git would track it.
#
# Compared through git's own root discovery, not a string prefix against
# REPO_ROOT: on Windows a lowercase drive letter, a mixed-case directory name,
# or an 8.3 short name (`AGENTC~1`) all name the same file but are different
# STRINGS, and a plain prefix match silently lets every one of them through —
# measured. `git rev-parse --show-toplevel`, run from the file's own
# directory, resolves through the filesystem the same way `check-ignore`
# right below does, so the two agree by construction instead of by spelling.
if command -v git >/dev/null 2>&1; then
    FILE_GIT_ROOT="$(cd "$(dirname "$FILE")" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null || true)"
    REPO_GIT_ROOT="$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -n "$FILE_GIT_ROOT" && -n "$REPO_GIT_ROOT" && "$FILE_GIT_ROOT" == "$REPO_GIT_ROOT" ]] \
       && ! git -C "$REPO_ROOT" check-ignore -q -- "$FILE" 2>/dev/null; then
        if (( ALLOW_TRACKED )); then
            warn "${FILE} is inside the repo and not gitignored — --allow-tracked given, continuing"
        else
            die "${FILE} is inside the repo and NOT gitignored. A real inventory has leaked from \
this exact repository before (deploy/config/inventory-filled.yaml.example). Move it outside the \
repo, gitignore it, or pass --allow-tracked if you are certain this one is meant to be tracked."
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 1. Validate LOCAL, before touching the network.
# ---------------------------------------------------------------------------
info "validating ${FILE}"
LOCAL_COUNT="$(PYTHONPATH="$REPO_ROOT" PYTHONIOENCODING=utf-8 "$PYTHON_BIN" - "$FILE" <<'PY'
import sys
from pathlib import Path
from sentinel.scan.inventory import load

try:
    specs = load(Path(sys.argv[1]))
except Exception as exc:  # noqa: BLE001 - the message IS the diagnostic
    print(f"invalid: {exc}", file=sys.stderr)
    sys.exit(1)
print(len(specs))
PY
)" || die "${FILE} does not pass sentinel.scan.inventory.load — fix it locally before pushing"
ok "local file is valid (${LOCAL_COUNT} asset(s))"

# See "Why an empty local file is refused" at the top of this file. Checked
# here — before any SSH connection — because the whole point is to refuse
# before a diff can be computed and shown as if it meant something.
[[ "$LOCAL_COUNT" -gt 0 ]] || die "\n${FILE} lists NO assets. \`sentinel.scan.inventory.sync\` on the host treats an \nempty list as \"nothing to retire\", never as \"retire everything\" — a diff against it would show \
retirements that will NOT happen on the host, and every asset already tracked there would stay exactly \
as it is. Refusing before any network I/O."

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p "$PORT")
SCP_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -P "$PORT")
if [[ -n "$KEY" ]]; then
    KEY="${KEY/#\~/$HOME}"
    [[ -f "$KEY" ]] || die "SSH key not found: ${KEY}"
    SSH_OPTS+=(-i "$KEY"); SCP_OPTS+=(-i "$KEY")
fi
ssh_run() { ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$@"; }

info "connecting to ${USER}@${HOST}:${PORT}"
ssh_run "echo connected" >/dev/null || die "cannot reach ${HOST}. Check the address, the key, \
and whether your address is allowed by the provider firewall."
ok "SSH working"

# ---------------------------------------------------------------------------
# 2. Read the CURRENT inventory on the host — read-only — and diff.
# ---------------------------------------------------------------------------
REMOTE_COPY="$(mktemp)"
cleanup() { rm -f "$REMOTE_COPY"; }
trap cleanup EXIT

set +e
REMOTE_RAW="$(ssh_run "sudo -n cat '${REMOTE_PATH}' 2>&1")"
REMOTE_STATUS=$?
set -e

if (( REMOTE_STATUS != 0 )); then
    # Anchored to the exact path, not a loose substring: GNU coreutils' `cat`
    # says "cat: ${REMOTE_PATH}: No such file or directory" when the FILE is
    # missing. A generic `*No such file or directory*` also matches
    # "sudo: /usr/bin/cat: No such file or directory" (sudo itself, or the
    # cat binary, missing) — measured — which is a broken host, not a fresh
    # one, and must not be read as "first install".
    if [[ "$REMOTE_RAW" == *"cat: ${REMOTE_PATH}: No such file or directory"* ]]; then
        info "no ${REMOTE_PATH} on the host yet — treating the current inventory as empty (first install)"
        REMOTE_RAW=""
    else
        # Anything else — permission denied, sudo not configured, the
        # connection dropping mid-command — is NOT "empty". Collapsing it into
        # empty would make every asset already on the host look newly added,
        # and worse, would make a REAL current inventory this script simply
        # could not read look like nothing to protect.
        die "could not read ${REMOTE_PATH} on the host: ${REMOTE_RAW}"
    fi
fi
printf '%s' "$REMOTE_RAW" > "$REMOTE_COPY"

set +e
REPORT="$(PYTHONPATH="$REPO_ROOT" PYTHONIOENCODING=utf-8 "$PYTHON_BIN" - "$FILE" "$REMOTE_COPY" <<'PY'
import sys
from pathlib import Path
from sentinel.scan.inventory import diff, load

local_path, remote_path = sys.argv[1], sys.argv[2]
proposed = load(Path(local_path))  # already validated (and non-empty) once;
                                    # loaded again here against the SAME copy
                                    # that gets pushed.
try:
    current = load(Path(remote_path))
except Exception as exc:  # noqa: BLE001 - the message IS the diagnostic
    print(f"the host's current inventory does not parse: {exc}", file=sys.stderr)
    print("Nu se poate arăta un diff sigur peste o schemă necunoscută.", file=sys.stderr)
    sys.exit(1)

result = diff(current, proposed)
print(f"pe gazdă acum: {len(current)} activ(e)")
print(f"în fișierul local: {len(proposed)} activ(e)")
if result["added"]:
    print(f"ADĂUGATE ({len(result['added'])}): {', '.join(result['added'])}")
if result["kept"]:
    print(f"neschimbate ({len(result['kept'])}): {', '.join(result['kept'])}")
if result["retired"]:
    print(f"SE RETRAG ({len(result['retired'])}): {', '.join(result['retired'])}")
    print("Retragerea scoate activul din verificările de sănătate și din panou "
          "la următoarea rundă de sondare a lui sentinel-health.")
if not result["added"] and not result["retired"]:
    print("Niciun activ adăugat sau retras — inventarul de pe gazdă rămâne la fel.")

sys.exit(2 if result["retired"] else 0)
PY
)"
DIFF_STATUS=$?
set -e

printf '\n%s\n\n' "$REPORT"

if (( DIFF_STATUS != 0 && DIFF_STATUS != 2 )); then
    die "diff failed — see the message above"
fi

if (( DRY_RUN )); then
    ok "--dry-run: nothing written"
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. Confirm anything destructive, then write.
# ---------------------------------------------------------------------------
if (( DIFF_STATUS == 2 )) && (( ! ASSUME_YES )); then
    warn "retragerea de mai sus nu se poate lua înapoi din scriptul ăsta — activele scoase "
    warn "din fișier rămân retrase până sunt adăugate la loc, cu alt id, ca active noi."
    read -r -p "Continui? [da/NU] " answer
    [[ "$answer" == "da" ]] || die "aborted"
fi

REMOTE_TMP="/tmp/.sentinel-inventory-push.$$"
scp "${SCP_OPTS[@]}" -q "$FILE" "${USER}@${HOST}:${REMOTE_TMP}"
# chmod BEFORE anything else touches it: the upload just put a real inventory
# — the exact kind of file this script exists to stop leaking — into /tmp,
# even briefly. Narrowed to the uploading account before the install step
# that gives it its final home and ownership.
ssh_run "chmod 600 '${REMOTE_TMP}'"
ssh_run "sudo -n install -m 0640 -o root -g sentinel '${REMOTE_TMP}' '${REMOTE_PATH}' && rm -f '${REMOTE_TMP}'" \
    || die "could not install the file on the host as root:sentinel 0640 — check sudo access for ${USER}, \
and remove ${REMOTE_TMP} by hand if it was left behind"

ok "wrote ${REMOTE_PATH} on ${HOST}"
info "sentinel-health re-reads inventory.yaml on its own probe cycle — nothing here was restarted."
