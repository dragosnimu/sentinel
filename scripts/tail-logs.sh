#!/usr/bin/env bash
#
# Follow Sentinel's logs over SSH.
#
#   ./scripts/tail-logs.sh --host 203.0.113.10 --user deploy --key ~/.ssh/sentinel_deploy
#   ./scripts/tail-logs.sh --host ... --unit sentinel-detect
#   ./scripts/tail-logs.sh --host ... --since '1 hour ago' --no-follow
#   ./scripts/tail-logs.sh --host ... --errors
#
# Sentinel logs structured JSON to journald. Piped through jq when it is
# available locally, so the output is readable instead of a wall of braces.

set -euo pipefail

HOST=""; USER=""; KEY=""; PORT=22
UNIT="sentinel-*"; SINCE=""; FOLLOW=1; LINES=100; ERRORS_ONLY=0; RAW=0

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)      HOST="${2:-}"; shift 2 ;;
        --user)      USER="${2:-}"; shift 2 ;;
        --key)       KEY="${2:-}"; shift 2 ;;
        --port)      PORT="${2:-}"; shift 2 ;;
        --unit)      UNIT="${2:-}"; shift 2 ;;
        --since)     SINCE="${2:-}"; shift 2 ;;
        --lines|-n)  LINES="${2:-}"; shift 2 ;;
        --no-follow) FOLLOW=0; shift ;;
        --errors)    ERRORS_ONLY=1; shift ;;
        --raw)       RAW=1; shift ;;
        --help|-h)   sed -n '2,14p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$HOST" ]] || die "--host is required"
[[ -n "$USER" ]] || die "--user is required"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15
          -o ServerAliveInterval=30 -p "$PORT")
[[ -n "$KEY" ]] && SSH_OPTS+=(-i "${KEY/#\~/$HOME}")

# sudo, altfel journald răspunde „No journal files were opened due to
# insufficient permissions" și scriptul pare să funcționeze în timp ce nu arată
# nimic. Un tailer de loguri care tace când nu are drepturi e mai rău decât
# unul care lipsește: pare că nu s-a întâmplat nimic.
remote="sudo journalctl -u '${UNIT}' -n ${LINES} -o cat --no-pager"
(( FOLLOW ))      && remote+=" -f"
(( ERRORS_ONLY )) && remote+=" -p err"
[[ -n "$SINCE" ]] && remote+=" --since '${SINCE}'"

printf '\033[34m[.]\033[0m %s%s on %s\n' "$UNIT" "$( ((FOLLOW)) && echo ' (following)' )" "$HOST"
printf '    Ctrl-C to stop\n\n'

# -o cat gives the raw MESSAGE, which for Sentinel is one JSON object per line.
# jq turns it into something a human can scan during an incident; without jq,
# or with --raw, the JSON goes through untouched.
if (( RAW )) || ! command -v jq >/dev/null 2>&1; then
    exec ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$remote"
fi

ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" "$remote" | jq -R -r '
    . as $line
    | try (fromjson
        | "\(.ts[11:19])  \(.level[0:4] | ascii_upcase)  \(.service // "?" | sub("^sentinel-";""))  \(.msg)"
          + (
              # Everything beyond the standard fields, appended as k=v. This is
              # where the useful detail lives: rule ids, addresses, counts.
              [ to_entries[]
                | select(.key | IN("ts","level","service","logger","msg") | not)
                | "\(.key)=\(.value|tostring)"
              ] | if length > 0 then "  [90m(" + join(" ") + ")[0m" else "" end
            )
      ) catch $line
'
