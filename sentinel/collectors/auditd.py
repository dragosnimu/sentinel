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

# ---------------------------------------------------------------------------
# Înregistrările de supraveghere: SYSCALL + PATH + EXECVE
# ---------------------------------------------------------------------------
# Regulile din deploy/audit/sentinel.rules — cele 17 `-w` pe fișiere și cele 8
# pe execve — nu produc niciunul dintre tipurile de mai sus. Produc SYSCALL,
# PATH, EXECVE și PROCTITLE, care până acum erau aruncate la parsare.
#
# Efectul: o cheie SSH scrisă în /root/.ssh, o modificare de sudoers, un cron
# nou, o unitate systemd nouă sau un socat pornit erau înregistrate de kernel,
# scrise în audit.log — și nu ajungeau niciodată în baza de date. Regulile
# arătau ca o acoperire completă a post-compromiterii și nu era nimic în spate.
#
# Firehose-ul de care avertizează antetul modulului e real, așa că filtrul e
# strict: se păstrează DOAR grupurile al căror SYSCALL poartă o cheie
# `sentinel_*`, adică fix regulile noastre. Orice altă regulă de audit de pe
# gazdă — a distribuției, a altui produs — trece mai departe neatinsă.
_WATCH_KEYS = {
    "sentinel_identity": "identity_change",   # passwd, shadow, group
    "sentinel_priv":     "sudoers_change",    # sudoers și sudoers.d
    "sentinel_ssh":      "ssh_key_change",    # sshd_config, /root/.ssh, /home
    "sentinel_cron":     "cron_change",
    "sentinel_systemd":  "unit_change",
    "sentinel_webroot":  "webroot_change",
    "sentinel_exec":     "suspicious_exec",
}

_SERIAL = re.compile(r"msg=audit\(\d+\.\d+:(?P<serial>\d+)\)")

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


# ---------------------------------------------------------------------------
# Corelatorul multi-linie
# ---------------------------------------------------------------------------
# O singură acțiune supravegheată produce mai multe linii care împart același
# serial din `msg=audit(epoch.ms:SERIAL)`:
#
#     type=SYSCALL   ... auid=1000 uid=0 comm="tee" exe="/usr/bin/tee" key="sentinel_ssh"
#     type=CWD       cwd="/tmp"
#     type=PATH      item=1 name="/root/.ssh/authorized_keys" nametype=CREATE
#     type=PROCTITLE proctitle=...
#
# SYSCALL spune cine și cu ce; PATH spune pe ce. Separat, niciuna nu e o alertă
# utilizabilă: „cineva a rulat tee" și „cineva a atins un fișier" nu înseamnă
# nimic; „utilizatorul 1000 a scris în /root/.ssh/authorized_keys" înseamnă tot.
_FIELD_QUOTED = re.compile(r'\bname="(?P<name>[^"]*)"')
_EXEC_ARG = re.compile(r'\ba(?P<i>\d+)=(?P<v>"[^"]*"|[^\s]+)')


def _serial_of(line: str) -> str | None:
    m = _SERIAL.search(line)
    return m["serial"] if m else None


def _best_path(paths: list[dict[str, str]]) -> str | None:
    """Care PATH e subiectul.

    Un singur syscall raportează mai multe PATH-uri: directorul părinte, apoi
    fișierul. `nametype` le distinge — CREATE și DELETE sunt ținta acțiunii,
    PARENT e doar drumul până la ea. Fără preferința asta, jumătate din alerte
    ar arăta „/root/.ssh" în loc de fișierul chiar atins.
    """
    if not paths:
        return None
    for want in ("CREATE", "DELETE", "NORMAL"):
        for p in paths:
            if p.get("nametype") == want and p.get("name"):
                return p["name"]
    named = [p["name"] for p in paths if p.get("name")]
    # Fără nametype util, cel mai lung nume e cel mai specific.
    return max(named, key=len) if named else None


def parse_auditd_group(lines: list[str]) -> Event | None:
    """Un grup de linii cu același serial -> cel mult un eveniment de supraveghere.

    Întoarce None dacă grupul nu poartă o cheie `sentinel_*`, ceea ce e cazul
    pentru marea majoritate a traficului auditd de pe o gazdă obișnuită.
    """
    syscall: dict[str, str] | None = None
    paths: list[dict[str, str]] = []
    exec_argv: list[str] = []
    ts: datetime | None = None

    for line in lines:
        m = _TYPE.match(line.strip())
        if not m:
            continue
        rtype = m["type"]
        fields = {f["key"]: _unquote(f["val"]) for f in _FIELD.finditer(line)}

        if ts is None:
            stamp = _STAMP.search(line)
            if stamp:
                ts = datetime.fromtimestamp(int(stamp["epoch"]), tz=timezone.utc)

        if rtype == "SYSCALL":
            syscall = fields
        elif rtype == "PATH":
            # `name` poate conține spații; regexul general se oprește la primul.
            q = _FIELD_QUOTED.search(line)
            if q:
                fields["name"] = q["name"]
            paths.append(fields)
        elif rtype == "EXECVE":
            # Regex propriu: `_FIELD` cere chei numai din litere, iar
            # argumentele sunt a0, a1, a2. Fără asta, argv-ul iese gol și
            # alerta rămâne „cineva a rulat socat" — adevărat și inutil.
            args = {int(m["i"]): _unquote(m["v"]) for m in _EXEC_ARG.finditer(line)}
            exec_argv = [args[i] for i in sorted(args)]

    if syscall is None:
        return None
    key = syscall.get("key", "").strip('"')
    action = _WATCH_KEYS.get(key)
    if action is None:
        return None

    path = _best_path(paths)
    # auid e utilizatorul care s-a autentificat iniţial, nu cel curent: după un
    # `sudo su -`, uid e 0 dar auid rămâne cine a intrat. Pentru „cine a făcut
    # asta", auid e răspunsul corect, iar uid minte.
    auid = syscall.get("auid")
    if auid in ("unset", "4294967295", "-1"):
        auid = None

    return Event(
        ts=ts or datetime.now(timezone.utc),
        source="auditd",
        action=action,
        username=auid,
        process=syscall.get("exe") or syscall.get("comm"),
        pid=int(syscall["pid"]) if syscall.get("pid", "").isdigit() else None,
        file_path=path,
        raw={
            "record_type": "SYSCALL", "audit_key": key,
            "syscall": syscall.get("syscall"), "success": syscall.get("success"),
            "uid": syscall.get("uid"), "auid": syscall.get("auid"),
            "comm": syscall.get("comm"), "exe": syscall.get("exe"),
            **({"argv": " ".join(exec_argv)[:400]} if exec_argv else {}),
            **({"paths": [p.get("name", "") for p in paths][:6]} if len(paths) > 1 else {}),
        },
    )


def parse_auditd_lines(lines: list[str]) -> list[Event]:
    """Toate liniile dintr-un tur de citire -> evenimente.

    Liniile cu semantică de sine stătătoare (USER_AUTH, ADD_USER, …) trec prin
    parserul de o linie, neschimbat. Restul se grupează pe serial și trec prin
    corelator. Un grup rupt între două citiri produce, în cel mai rău caz, un
    eveniment fără cale — nu o excepţie şi nu o linie pierdută.
    """
    out: list[Event] = []
    groups: dict[str, list[str]] = {}
    order: list[str] = []

    for line in lines:
        m = _TYPE.match(line.strip())
        if not m:
            continue
        if m["type"] in _KEEP:
            ev = parse_auditd(line)
            if ev is not None:
                out.append(ev)
            continue
        if m["type"] not in ("SYSCALL", "PATH", "EXECVE", "CWD", "PROCTITLE"):
            continue
        serial = _serial_of(line)
        if serial is None:
            continue
        if serial not in groups:
            groups[serial] = []
            order.append(serial)
        groups[serial].append(line)

    for serial in order:
        ev = parse_auditd_group(groups[serial])
        if ev is not None:
            out.append(ev)
    return out
