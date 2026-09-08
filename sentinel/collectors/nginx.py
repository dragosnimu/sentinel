"""Parse nginx access-log lines (combined format) into canonical events.

The whole request line — method, path, query, user-agent, referer, host — is
chosen by the client, so every one of those fields is untrusted and stored
verbatim. The point of ingesting them is exactly to see the hostile ones:
`/wp-login.php`, `/../../etc/passwd`, an sqlmap user-agent.

Default combined format, plus an optional leading vhost that some setups prepend:
    [host] remote_addr - user [time] "METHOD path proto" status bytes "ref" "ua"

AlmaLinux/RHEL's stock `log_format main` appends one more quoted field after
the UA — `$http_x_forwarded_for` — and is what the tailed production access
log actually contains:
    remote_addr - user [time] "METHOD path proto" status bytes "ref" "ua" "xff"
`_LINE` allows any number of trailing quoted fields for exactly this reason
(see "Why the trailing-fields group is bounded" below). Whatever is in that
last field is NEVER read for `src_ip` — see "X-Forwarded-For is never trusted
for src_ip" below.

## X-Forwarded-For is never trusted for src_ip

`$http_x_forwarded_for` is a request header the CLIENT sends; unless this box
sits behind a reverse proxy that overwrites it (it does not — see
`deploy/nginx/*.tmpl`), an attacker can put any address they like in it.
`src_ip` always comes from `$remote_addr`/`addr` — the TCP peer address nginx
itself observed, which cannot be forged without completing a TCP handshake at
that address. The trailing-fields group captures XFF into the match (so a real
`main`-format line still fullmatches) but nothing downstream ever reads that
capture.

## Why the line regex is anchored, not searched

`$remote_user` is as attacker-influenced as everything else in the line — it is
the HTTP Basic-Auth username on any vhost that uses it, chosen by whoever is
connecting. Before this fix, `_LINE.search(line)` looked for the pattern
ANYWHERE in the line rather than requiring the line to actually BE one record,
so a `remote_user` crafted to contain its own fake
`[time] "request" status bytes "referer" "ua"` tail let an attacker's forged
fields win over the real ones nginx wrote after the genuine `remote_user` —
record injection, the same class of bug fixed in `collectors/sshd.py` for the
same reason (see that module's docstring). `fullmatch` makes `addr` (and every
other field) come from a single, complete parse of the WHOLE line under this
grammar; there is no second reading of it left for a crafted username to win.

`fullmatch` also removes the actual cause of the catastrophic-backtracking
finding: `.search()` retries the entire pattern at every one of a line's
`len(line)` starting offsets, and at each one a failing greedy run gives back
one character at a time before giving up — that per-offset backtrack cost
multiplied by "try every offset" is what turned a 100 KB non-matching line
into 65+ seconds of CPU (measured on this branch: 140 s on a 95 KB adversarial
line with the old `.search()`). `fullmatch` tries exactly one offset (the
start), so the same worst-case backtrack happens at most once — measured here
at under 1 ms for the same adversarial input, and under 0.25 ms to fullmatch a
genuine 1 MB line.

## Why the trailing-fields group is bounded, not a length cap

A PRE-match length cap used to sit here (`_MAX_LINE_LEN = 8192`, matching
`large_client_header_buffers 4 8k;`) and truncated any line past it before
either regex ran. That is not load-bearing for the timing above — removing it
changes nothing on the measurement — and it silently dropped every valid line
longer than the cap: truncation lands inside whatever quoted field happens to
be open at byte 8192, `fullmatch` then fails on the mangled tail, and the
request vanishes from the log as if it had never happened. Production already
logs lines of 7,966 bytes; worse, an attacker who wants a request invisible to
this collector need only pad the user-agent or referer past the cap —
detection evasion dressed up as a safety limit. `Event.__post_init__` already
bounds every untrusted field (`http_ua`, `http_path`, `http_referer`, ...) to
`MAX_FIELD_LEN` AFTER a successful parse, which is where truncation belongs:
on the field, once the line is known to be a genuine record, never on the raw
line before parsing decides that.

`_HARD_CAP` (1 MiB) is what remains: a resource-safety backstop, not a
functional bound — no real nginx line approaches it, `fullmatch` costs a
fraction of a millisecond even at that size, and a line beyond it is refused
outright rather than truncated-then-matched, so this cap can never reproduce
the silent-drop bug it replaced.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinel.model.event import Event

_LINE = re.compile(
    r'(?P<addr>[0-9a-fA-F:.]+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
    # Zero or more further quoted fields — e.g. AlmaLinux/RHEL's stock `main`
    # format's trailing `"$http_x_forwarded_for"`. Each element is its own
    # `"[^"]*"` (a quote can never appear unescaped inside it, so there is no
    # ambiguity in how the group repeats — same shape as every other quoted
    # field above, so it carries the same ReDoS-safety argument). An
    # INJECTED fake tail is not swallowed by this: the record-injection
    # payload's forged continuation starts with an UNQUOTED `[time]`, which
    # this group cannot consume, so `fullmatch` still fails on it — see "Why
    # the line regex is anchored, not searched" above.
    r'(?:\s+"[^"]*")*'
)
_HOST_PREFIX = re.compile(r'^(?P<host>[a-zA-Z0-9.\-:]+)\s+(?=[0-9a-fA-F:.]+\s+-\s)')

# Resource-safety backstop only — see "Why the trailing-fields group is
# bounded, not a length cap" in the module docstring.
_HARD_CAP = 1_048_576  # 1 MiB


def _parse_time(raw: str) -> datetime:
    # "31/Jul/2026:06:00:00 +0000"
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return datetime.now(timezone.utc)


def parse_nginx(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    if len(line) > _HARD_CAP:
        return None  # refused outright, never truncated-then-matched; see docstring

    host = None
    prefix = _HOST_PREFIX.match(line)
    if prefix:
        host = prefix["host"]
        line = line[prefix.end():]

    m = _LINE.fullmatch(line)
    if not m:
        return None

    request = m["request"]
    method = path = query = proto = None
    parts = request.split(" ")
    if len(parts) >= 2:
        method = parts[0][:16]
        target = parts[1]
        proto = parts[2] if len(parts) > 2 else None
        if "?" in target:
            path, query = target.split("?", 1)
        else:
            path = target

    raw = {"request": request[:512], "http_version": proto}

    return Event(
        ts=_parse_time(m["time"]),
        source="nginx",
        action="request",
        src_ip=m["addr"],
        http_method=method,
        http_path=path,
        http_query=query,
        http_status=int(m["status"]),
        http_ua=m["ua"] if m["ua"] != "-" else None,
        http_referer=m["referer"] if m["referer"] != "-" else None,
        http_host=host,
        bytes_out=int(m["bytes"]) if m["bytes"].isdigit() else None,
        proto="http",
        raw=raw,
    )
