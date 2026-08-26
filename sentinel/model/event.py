"""The canonical event.

Every collector produces this shape, whatever it read. Field names follow ECS
where a sensible equivalent exists, so that anyone who has used Elastic or
Elastic-style tooling can read a Sentinel event without a translation table.

Fields marked UNTRUSTED are written by whoever is talking to the server. They
are stored verbatim (truncating them would destroy evidence), never
interpolated into a command, and always wrapped in `<untrusted_data>` markers
before they enter a model prompt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# What a collector is reading.
SOURCES = (
    "sshd", "sudo", "su", "nginx", "apache", "auditd", "suricata",
    "docker", "journald", "fim", "conntrack", "internal",
)

# Acțiuni de post-compromitere, produse de regulile de supraveghere auditd.
#
# Separate de `file_write` generic dinadins: severitatea și textul alertei
# depind de CE s-a atins, iar decizia aia se ia o singură dată, la colectare,
# unde există cheia regulii de audit. O regulă de detecție care ar trebui să
# reconstruiască „e sudoers sau e un log oarecare" din calea fișierului ar
# refface o clasificare pe care kernelul a făcut-o deja corect.
#
# Lista asta e o jumătate dintr-un vocabular ținut în două locuri: cealaltă e
# `collectors/auditd._WATCH_KEYS`, care traduce cheile regulilor livrate în
# acțiunile de aici. Cele două au divergat — `suid_change` și `module_load`
# erau încărcate în nucleu și traduse de colector, dar lipseau de aici, deci
# `Event.__post_init__` ridica ValueError pe primul `chmod u+s` sau
# `init_module`, iar lotul întreg cădea. Legătura se verifică acum derivat, din
# `collectors/auditd.EMITTED_ACTIONS`, nu dintr-o listă scrisă de mână.
POST_COMPROMISE_ACTIONS = (
    "identity_change",    # passwd, shadow, group
    "sudoers_change",
    "ssh_key_change",     # sshd_config, /root/.ssh, /home/*/.ssh
    "cron_change",
    "unit_change",        # unitate systemd creată sau modificată
    "webroot_change",
    "suspicious_exec",    # nc, ncat, socat, wget, curl
    # Trei întrebări diferite, trei acțiuni diferite. `chmod u+s` și un modul de
    # kernel au împărțit cândva cheia cu uneltele de rețea de mai sus, iar o
    # singură regulă de detecție răspundea la toate cu aceeași propoziție: „unealtă
    # de atacator executată: chmod". Ce fișier a devenit setuid nu apărea nicăieri.
    "suid_change",        # bit setuid/setgid pus pe un fișier
    # init_module, finit_module ȘI delete_module: numele spune „load" fiindcă
    # regula de detecție care îl consumă se numește așa, dar acoperă și
    # descărcarea — de asta textul alertei din `detect/intrusion.py` spune
    # „încărcat sau descărcat".
    "module_load",
)

# Normalised outcome. Rules match on this rather than on source-specific text.
ACTIONS = POST_COMPROMISE_ACTIONS + (
    "accept", "deny", "auth_fail", "auth_ok", "request",
    "exec", "file_write", "file_read", "connect", "disconnect",
    "start", "stop", "error", "alert", "unknown",
    # Post-compromise activity: what happened after someone got in.
    "privilege_use", "login", "account_change", "audit_config_change",
    # Istoricul de sesiuni si de comenzi.
    #
    # `logout` e perechea lui `login`: fara ea o sesiune deschisa nu se mai
    # inchide niciodata in date, iar panoul ar arata oameni conectati de
    # saptamani. `command` e fiecare `execve` dintr-o sesiune cu login.
    "logout", "command",
    "process_crash", "promiscuous", "avc_denial",
)

MAX_FIELD_LEN = 2048


@dataclass
class Event:
    ts: datetime
    source: str
    action: str = "unknown"

    asset_id: int | None = None

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str | None = None

    username: str | None = None            # UNTRUSTED
    http_method: str | None = None
    http_path: str | None = None           # UNTRUSTED
    http_query: str | None = None          # UNTRUSTED
    http_status: int | None = None
    http_ua: str | None = None             # UNTRUSTED
    http_host: str | None = None           # UNTRUSTED
    http_referer: str | None = None        # UNTRUSTED
    bytes_in: int | None = None
    bytes_out: int | None = None
    latency_ms: int | None = None

    process: str | None = None
    pid: int | None = None
    file_path: str | None = None           # UNTRUSTED when it comes from a request
    tls_sni: str | None = None             # UNTRUSTED
    tls_ja4: str | None = None

    geo_country: str | None = None
    geo_asn: int | None = None
    geo_as_org: str | None = None
    reputation: list[str] = field(default_factory=list)

    raw: dict[str, Any] = field(default_factory=dict)

    # Set by ingest so a collector restart cannot silently re-read or skip.
    cursor: str | None = None

    UNTRUSTED_FIELDS = frozenset(
        {
            "username", "http_path", "http_query", "http_ua", "http_host",
            "http_referer", "file_path", "tls_sni",
        }
    )

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            self.ts = self.ts.replace(tzinfo=timezone.utc)
        if self.source not in SOURCES:
            raise ValueError(f"unknown source {self.source!r}; expected one of {SOURCES}")
        if self.action not in ACTIONS:
            raise ValueError(f"unknown action {self.action!r}; expected one of {ACTIONS}")

        # Bound the untrusted strings. A 4 MB User-Agent is itself an attack, and
        # storing it whole would bloat every partition.
        for name in self.UNTRUSTED_FIELDS:
            value = getattr(self, name)
            if isinstance(value, str) and len(value) > MAX_FIELD_LEN:
                setattr(self, name, value[:MAX_FIELD_LEN] + "…[truncated]")

    def to_row(self) -> dict[str, Any]:
        """Shape for insertion into `raw_events`."""
        row = asdict(self)
        row.pop("cursor", None)
        return row

    def untrusted(self) -> dict[str, str]:
        """The attacker-controlled fields, for wrapping before a model sees them."""
        return {
            name: value
            for name in self.UNTRUSTED_FIELDS
            if isinstance(value := getattr(self, name), str) and value
        }

    @property
    def is_web(self) -> bool:
        return self.http_path is not None

    @property
    def is_auth_failure(self) -> bool:
        return self.action == "auth_fail"
