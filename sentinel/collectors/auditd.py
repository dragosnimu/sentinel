"""Parse auditd records into canonical events.

auditd is the kernel's own record of who did what: authentications, privilege
changes, and any syscall the loaded rules watch. It sees things journald cannot
— a file opened, a binary executed — and it is written by the kernel, so a
process that tampers with its own logging cannot erase it.

Only the security-relevant record types are kept. auditd is capable of enormous
volume (a SYSCALL rule on a busy path produces thousands of records a second),
so an unfiltered ingest would be the same disk-fill hazard as the Suricata
decoder firehose. Everything else is dropped before the database.

Fields after the record type are attacker-influenced once an account is
compromised (a chosen filename, a chosen command) — stored verbatim, never
trusted.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinel.model.event import Event

# Record types worth an event, mapped to a canonical action.
_KEEP = {
    "USER_AUTH": "auth_attempt",
    "USER_LOGIN": "login",
    "USER_ACCT": "auth_attempt",
    "ANOM_ABEND": "process_crash",       # a segfault can be an exploit landing
    "ANOM_PROMISCUOUS": "promiscuous",   # someone put an interface into promisc
    "AVC": "avc_denial",                 # SELinux denied something
    "USER_CMD": "privilege_use",
    "ADD_USER": "account_change",
    "DEL_USER": "account_change",
    "USER_MGMT": "account_change",
    "ADD_GROUP": "account_change",
    "ROLE_ASSIGN": "account_change",
    "CONFIG_CHANGE": "audit_config_change",  # someone edited the audit rules
}

# "type=USER_AUTH msg=audit(1754207100.123:456): pid=1 uid=0 ... res=failed"
_TYPE = re.compile(r"^type=(?P<type>[A-Z_]+)\s")
_STAMP = re.compile(r"msg=audit\((?P<epoch>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\)")
_FIELD = re.compile(r"\b(?P<key>[a-z_]+)=(?P<val>\"[^\"]*\"|[^\s]+)")

# Fields worth carrying. auditd emits dozens per record; these are the ones that
# answer "who, from where, what happened".
_INTERESTING = ("uid", "auid", "acct", "user", "exe", "hostname", "addr",
                "terminal", "res", "op", "cmd", "comm", "unit", "key")


def _unquote(v: str) -> str:
    # auditd nests fields inside msg='...', so the LAST field on a line arrives
    # with the wrapper's trailing apostrophe attached (res=failed'). Strip both
    # quote styles, or `res` never compares equal to "failed" and every failed
    # authentication is silently recorded as a success.
    v = v.strip().rstrip("'")
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v.strip('"')


def parse_auditd(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    m = _TYPE.match(line)
    if not m:
        return None
    rtype = m["type"]
    action = _KEEP.get(rtype)
    if action is None:
        return None

    stamp = _STAMP.search(line)
    if stamp:
        ts = datetime.fromtimestamp(int(stamp["epoch"]), tz=timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    fields = {}
    for f in _FIELD.finditer(line):
        key = f["key"]
        if key in _INTERESTING and key not in fields:
            fields[key] = _unquote(f["val"])[:200]

    # auditd writes the peer address as addr= (or hostname= on some records);
    # "?" is its placeholder for "not applicable", not an address.
    src_ip = fields.get("addr") or fields.get("hostname")
    if src_ip in ("?", "", "localhost"):
        src_ip = None

    # res=failed / res=success is how auditd reports the outcome; a failed
    # authentication is the one that matters for detection.
    result = fields.get("res")
    if action == "auth_attempt":
        action = "auth_fail" if result in ("failed", "0") else "auth_ok"

    return Event(
        ts=ts, source="auditd", action=action,
        src_ip=src_ip,
        username=fields.get("acct") or fields.get("user"),
        process=fields.get("comm") or fields.get("exe"),
        raw={"record_type": rtype, **fields},
    )
