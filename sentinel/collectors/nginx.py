"""Parse nginx access-log lines (combined format) into canonical events.

The whole request line — method, path, query, user-agent, referer, host — is
chosen by the client, so every one of those fields is untrusted and stored
verbatim. The point of ingesting them is exactly to see the hostile ones:
`/wp-login.php`, `/../../etc/passwd`, an sqlmap user-agent.

Default combined format, plus an optional leading vhost that some setups prepend:
    [host] remote_addr - user [time] "METHOD path proto" status bytes "ref" "ua"
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
)
_HOST_PREFIX = re.compile(r'^(?P<host>[a-zA-Z0-9.\-:]+)\s+(?=[0-9a-fA-F:.]+\s+-\s)')


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

    host = None
    prefix = _HOST_PREFIX.match(line)
    if prefix:
        host = prefix["host"]
        line = line[prefix.end():]

    m = _LINE.search(line)
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
        raw={"request": request[:512], "http_version": proto},
    )
