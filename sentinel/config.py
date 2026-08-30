"""Layered configuration.

Precedence, lowest to highest:

    built-in defaults  ←  /etc/sentinel/sentinel.yaml  ←  secrets.env  ←  environment

Secrets never appear in `sentinel.yaml` and never appear in a `repr()` or a log
line. They live in `/etc/sentinel/secrets.env` (mode 0640, root:sentinel) and
are read into `Secrets`, which refuses to render itself.

Nothing here is a safety boundary. Values that must not be operator-editable
live in `sentinel.constants`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar, get_type_hints

import yaml

from sentinel.constants import CONFIG_DIR, DEFAULT_PUBLIC_PORT, SENTINEL_WEB_PORT
from sentinel.errors import ConfigError, SecretMissingError

CONFIG_PATH = Path(os.environ.get("SENTINEL_CONFIG", f"{CONFIG_DIR}/sentinel.yaml"))
SECRETS_PATH = Path(os.environ.get("SENTINEL_SECRETS", f"{CONFIG_DIR}/secrets.env"))

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
@dataclass
class PlatformConfig:
    """Which distribution family this host is, decided once at install time.

    `deploy/lib/distro.sh:distro_detect` decides it, install.sh renders it into
    sentinel.yaml, and everything in the runtime that has to differ per family
    reads it from here. Nothing in Python looks at /etc/os-release: a second
    detector is a second source of truth, and the two only ever disagree on the
    host where it matters.

    The default is `rhel`, and it is deliberate rather than incidental. Every
    installation that predates this key runs on AlmaLinux, and `install_config`
    refuses to overwrite a live sentinel.yaml — it writes sentinel.yaml.new and
    warns — so those hosts will never gain the key on their own. Defaulting to
    `rhel` is what keeps their behaviour byte-for-byte what it is today.

    A value outside PLATFORM_FAMILIES is refused at load. It must not be
    tolerated by falling back to the default: a Debian host whose family was
    mistyped would then run the dnf scanner, find no dnf, and report a failed
    scan for a reason nobody could see in the config.
    """
    family: str = "rhel"


@dataclass
class DatabaseConfig:
    host: str = "127.0.0.1"
    port: int = 5432
    name: str = "sentinel"
    user: str = "sentinel"
    pool_min: int = 2
    pool_max: int = 10
    statement_timeout_ms: int = 30_000


@dataclass
class RetentionConfig:
    raw_events_days: int = 30
    rollup_1m_days: int = 90
    rollup_1h_days: int = 400
    health_samples_days: int = 30
    # Below this free-space fraction the maintenance job drops the oldest
    # partitions early and alerts, rather than letting the disk fill.
    disk_guard_free_pct: int = 15

    # How long an incident may sit with no new detection before it is closed
    # automatically, per severity. Nothing is deleted: the row keeps its
    # evidence, its timeline gains an entry, and renewed activity opens a fresh
    # incident rather than reviving this one.
    #
    # The numbers are not a retention policy, they are a reading policy. A queue
    # of 851 open incidents is not read by anyone, and the one that mattered is
    # hidden by the 850 that did not — which is the failure this prevents.
    #
    # `critical` is deliberately absent and never auto-closes. A critical nobody
    # has looked at for two weeks is a finding about the operator, not about the
    # incident, and hiding it would be the one thing worse than a long queue.
    incident_stale_days: dict[str, int] = field(default_factory=lambda: {
        "info": 1, "low": 2, "medium": 7, "high": 21,
    })


@dataclass
class IngestConfig:
    # journald covers sshd (authentication) and sudo/su (privilege escalation).
    journald: bool = True
    nginx: bool = True
    apache: bool = False
    auditd: bool = True
    suricata: bool = True
    # NOT IMPLEMENTED YET — no collector exists for these, so leaving them true
    # would claim coverage Sentinel does not have. Container and file-integrity
    # collection is tracked as a known gap; auditd covers part of the FIM ground.
    docker: bool = False
    fim: bool = False
    nginx_log_paths: list[str] = field(
        default_factory=lambda: ["/var/log/nginx/*access*.log"]
    )
    auditd_log_path: str = "/var/log/audit/audit.log"
    # Sources that produce high volume with no security value on this host —
    # a chatty application log, a telemetry feed. Matched against the event
    # `source` field and dropped before they reach the database.
    exclude_sources: list[str] = field(default_factory=list)
    batch_size: int = 500
    flush_interval_ms: int = 1000


@dataclass
class HistoryConfig:
    """What the session-command history keeps, and what it refuses to keep.

    Automation accounts whose commands are NOT written to `session_commands`
    when they ran without a real terminal. Measured on the host: a single deploy
    produced 405 777 rows in 140 seconds — `systemctl` 320 591 and `sleep`
    173 376, the installer's wait loops — and the external replica went from
    83 MB to 909 MB in a few hours.

    The filter is on the COMMAND's tty, not on the session's account, and that
    distinction is the whole point. A session becomes `interactive` only when its
    FIRST command with a real tty arrives (`_promote_interactive`), and the login
    alert requires `interactive = true`. Dropping everything an account runs
    would mean an interactive login on that account never promotes its session
    and never alerts — an automation account that doubles as a silent way in.
    With the rule on tty, `ssh sentinel-deploy@host` with a real shell gets
    `pts0`, its commands are kept, the session promotes, the alert goes out.

    The auditd rules are deliberately NOT narrowed to match: the on-disk journal
    stays the complete record. Only this projection is trimmed.

    Empty means "drop nothing" — today's behaviour, and the default.

    The names here are what the OPERATOR wrote. They are not what the filter
    compares against: see `resolve_skip_command_accounts` below, and the second
    spelling it exists for.
    """

    skip_command_accounts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SkipAccounts:
    """A configured account list, resolved against the accounts on THIS host.

    `is_dropped_command` compares `username` for exact equality, and the same
    account reaches `session_commands` under two spellings. `collectors/auditd.py`
    writes the name when auditd's ENRICHED field carries one or when `pwd` can
    resolve the numeric `auid`; when neither works it writes the raw numeric
    auid as a string. Measured on the host on 25 August 2026: 87 935 rows spelled
    `username = '1000'` for an account that has 2.8 million rows under its name.

    A filter that knows only the name silently keeps every row of the second
    kind, which is exactly the shape of bug this file's comments keep warning
    about: configured, plausible, and matching a fraction of what it claims.

    Three fields because three states have to stay apart:

      * `matches` — every spelling the filter should catch. Names AND uids as
        strings;
      * `unresolved` — configured names that do not exist on this host. Not an
        error to raise (the daemon must still start) but not silence either: a
        filter naming an account that does not exist can never match anything;
      * `lookup_ok` — whether the account database could be consulted AT ALL.
        False means "I do not know", which is not "everything resolved". The
        self-check reports the two differently.

    ## The edge, written down so nobody has to find it

    A uid outlives the account that held it. Delete `sentinel-deploy` (uid 1002
    on this host, read from `/etc/passwd` on 25 August 2026 — the installer asks
    for the first free system uid, so it is NOT a constant across hosts and
    nothing here may compare against it), create a human account, and the kernel
    may hand the same number out again — after which a terminal-less command of
    that human's, recorded numerically, would be dropped by a filter still
    resolving the old name. The window is narrow (the
    mapping is rebuilt on every daemon start, and only terminal-less commands
    are affected at all) but it is real. Keeping the numeric spelling out of the
    filter would close it and reopen the much larger hole of 87 935 unfiltered
    rows per account, so this is the trade that was chosen, not one that was
    missed.
    """

    matches: frozenset[str] = frozenset()
    resolved: tuple[tuple[str, int], ...] = ()
    unresolved: tuple[str, ...] = ()
    lookup_ok: bool = True
    #: Exactly what the operator wrote, in order. Kept so a report can show the
    #: configured names next to the spellings they expanded into — the two being
    #: different is the whole point, and a report that only showed the expansion
    #: would look like the config said something it does not.
    configured_names: tuple[str, ...] = ()


def _passwd_uid(name: str) -> int | None:
    """The uid for an account name, `None` if this host has no such account.

    Raises `OSError` when the account database cannot be consulted at all —
    which is a different answer from "no such account" and must not be flattened
    into one. `pwd` does not exist off POSIX; the tests inject their own lookup.
    """
    try:
        import pwd
    except ImportError as exc:  # pragma: no cover - POSIX has pwd
        raise OSError("pwd unavailable on this platform") from exc
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def resolve_skip_command_accounts(
    names: list[str] | tuple[str, ...],
    uid_of: Any = None,
) -> SkipAccounts:
    """Expand configured account names into every spelling the rows carry.

    A name resolves to `{name, str(uid)}`. A name written as a number is taken
    as a uid already and kept as-is — an operator who wrote `- 1000` meant the
    account, not a user literally called "1000".

    An empty list gives an empty result with `lookup_ok = True`: "drop nothing"
    is a valid configuration, not a failure to read one.
    """
    lookup = uid_of if uid_of is not None else _passwd_uid
    matches: set[str] = set()
    resolved: list[tuple[str, int]] = []
    unresolved: list[str] = []
    configured: list[str] = []
    lookup_ok = True

    for raw in names:
        name = str(raw).strip()
        if not name:
            continue
        configured.append(name)
        matches.add(name)
        if name.isdigit():
            # Already a uid. Nothing to look up, and nothing to report missing:
            # the numeric spelling is the one the rows carry in the bad case.
            resolved.append((name, int(name)))
            continue
        try:
            uid = lookup(name)
        except OSError:
            # The account database itself could not be read. Every remaining
            # name is unknown, not absent, and saying "unresolved" here would
            # send the operator hunting for an account that may well exist.
            lookup_ok = False
            continue
        if uid is None:
            unresolved.append(name)
        else:
            matches.add(str(uid))
            resolved.append((name, uid))

    return SkipAccounts(frozenset(matches), tuple(resolved), tuple(unresolved),
                        lookup_ok, tuple(configured))


@dataclass
class DetectionConfig:
    enabled: bool = True
    rules_dir: str = f"{CONFIG_DIR}/rules.d"
    # Anomaly rules stay silent until a baseline is warm. See constants.
    baseline_warmup_days: int = 14
    # Suppress everything from these sources — uptime monitors, CI runners.
    suppress_sources: list[str] = field(default_factory=list)


@dataclass
class AutoBlockConfig:
    # Ships disabled. The first 72 hours are observe-only: the operator is told
    # what WOULD have been blocked, with a button. Turning this on before
    # tuning is how you block your own uptime monitor at 3 a.m.
    enabled: bool = False
    observe_mode_notify: bool = True
    # Below this the deterministic verdict still alerts, but never arms an
    # auto-block. High keeps enumeration noise from placing firewall rules.
    min_severity: str = "high"
    max_per_minute: int = 60
    max_elements: int = 20_000
    # Blocking a whole /24 takes out NAT'd offices. Off by default.
    allow_cidr_blocks: bool = False
    default_ttl_s: int = 86_400
    # A ceiling on active RANGE blocks specifically, separate from
    # max_elements: a single /24 quietly covers 254 addresses, so a handful of
    # them fills a meaningful share of max_elements without the *count* of
    # active blocks looking anywhere near its cap. sentinel/detect/cidr.py
    # measured ≈6 qualifying /24 candidates a day at its chosen threshold; 20
    # gives the operator more than three days of headroom to react to a
    # sustained wave before this stops arming new ranges. Moot while
    # allow_cidr_blocks stays False — this is the backstop for when it does not.
    max_active_cidrs: int = 20
    # Never auto-block something the reputation feeds identify as a research
    # scanner; it is internet background noise, not an attack on you.
    skip_known_scanners: bool = True


@dataclass
class ResponseConfig:
    auto_block: AutoBlockConfig = field(default_factory=AutoBlockConfig)
    executor_socket: str = "/run/sentinel/executor.sock"
    executor_timeout_s: int = 30
    # Operator-managed additions to the hard-coded never-block list in code.
    extra_allowlist: list[str] = field(default_factory=list)


@dataclass
class BeaconConfig:
    """Semnalul periodic către un martor din afara gazdei.

    Există fiindcă un agent găzduit nu poate garanta că raportează propria
    dispariție: cine îl oprește controlează și canalul. Singura ieșire e ca
    absența semnalului să fie ea însăși alarma, iar judecata să stea altundeva.

    Dezactivat implicit. Fără un martor configurat, serviciul pornește, spune o
    dată în jurnal că nu are unde trimite, și se oprește — un expeditor care
    încearcă la nesfârșit o adresă goală e doar zgomot.
    """
    enabled: bool = False
    url: str = ""
    interval_s: int = 60
    # Cât așteaptă un răspuns. Scurt dinadins: martorul indisponibil nu are voie
    # să devină o problemă a serverului monitorizat.
    timeout_s: int = 10
    # Un semnal mai vechi de atât e refuzat de martor ca reluare. Trimis în
    # payload ca să fie explicit de ambele părți, nu presupus.
    max_age_s: int = 120


@dataclass
class ShipConfig:
    """Expedierea rândurilor către agregatorul extern.

    Separat de `beacon`, și nu doar ca secțiune: e alt serviciu, altă unitate și
    altă cheie (`SENTINEL_SHIP_SECRET`). Motivul e în capul lui
    `sentinel/report/shipper.py` — purtarea beaconului e o proprietate de
    securitate, iar un bug în expeditor nu are voie să fie o pană de heartbeat.

    Dezactivat implicit, ca beaconul, și din același motiv plus unul în plus:
    agregatorul nu există încă. Fără el configurat, serviciul spune o dată în
    jurnal că nu are unde trimite și iese curat.
    """
    enabled: bool = False
    url: str = ""
    interval_s: int = 60
    # Mai lung decât cei 10 s ai beaconului: un lot de câteva mii de rânduri nu
    # e un heartbeat de o sută de octeți, iar un timeout mai scurt decât timpul
    # real de încărcare ar produce o restanță care nu se recuperează niciodată.
    timeout_s: int = 30
    # Prospețimea lotului, verificată la celălalt capăt. Mai mare decât cei 120 s
    # ai beaconului, tot fiindcă loturile pot fi mari.
    max_age_s: int = 300
    # Cea mai mare cerere pe care o poate produce o rundă. O pană lungă a
    # agregatorului se recuperează în multe cereri mici, nu într-una uriașă care
    # expiră și se reia la nesfârșit fără să progreseze.
    max_rows_per_batch: int = 2000
    # De unde începe un flux la PRIMA rundă, când nu există încă un cursor.
    # Rândurile mai vechi nu vor pleca niciodată, iar asta se scrie în jurnal
    # atunci și rămâne vizibilă în `ship:lag`. După ce cursorul există, limita
    # asta nu mai sare peste nimic — vezi capul lui shipper.py.
    max_backfill_days: int = 7
    # Sub-rânduri: coloanele-tablou care pleacă drept rânduri de legătură.
    #
    # Amândouă sunt PLAFOANE ALE RECEPTORULUI, repetate aici. Nu e o dublare
    # din neglijență: `ship_once` tratează la fel orice non-2xx și nu citește
    # niciodată corpul refuzului, iar nicăieri nu există logică de micșorare a
    # lotului. Deci un lot pe care agregatorul îl refuză nu se vede ca eroare
    # de configurație — se vede ca un agregator căzut, la nesfârșit, cu
    # backoff până la o oră.
    #
    # Egalitatea cu `MAX_CHILDREN_PER_ROW` și `MAX_CHILD_ROWS_PER_BATCH` din
    # `aggregator/lib/ingest.ts` e ținută de
    # `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`,
    # care citește numerele din sursa TypeScript.
    max_children_per_row: int = 1000
    max_child_rows_per_batch: int = 6000
    # Backoff exponențial cu jitter, plafonat. Prima pauză după un eșec.
    backoff_base_s: int = 30
    backoff_max_s: int = 3600


@dataclass
class TelegramConfig:
    enabled: bool = True
    allowed_chat_ids: list[int] = field(default_factory=list)
    owner_chat_id: int | None = None
    operator_chat_ids: list[int] = field(default_factory=list)
    viewer_chat_ids: list[int] = field(default_factory=list)
    # Deployment-wide default window, "22:00-06:00". A chat that sets its own
    # with /mute overrides this. Critical alerts, PANIC, the watchdog and patch
    # failures ignore it entirely — see telegram/quiet.py.
    quiet_hours: str | None = None
    # IANA zone the window is read in. None = the host's own zone, which is
    # what an operator typing "22:00" almost always means.
    timezone: str | None = None
    min_severity: str = "medium"
    digest_threshold: int = 10              # more than N alerts in 5 min → digest
    rate_limit_per_minute: int = 30
    callback_ttl_s: int = 600
    # Defence in depth if a phone is stolen: a static PIN for apply and allow.
    require_pin_for_apply: bool = False


@dataclass
class WebConfig:
    # The app itself, loopback only. nginx proxies to this.
    bind: str = "127.0.0.1"
    port: int = SENTINEL_WEB_PORT

    # How the dashboard is exposed.
    #
    #   dedicated — Sentinel runs its own nginx listener on `public_port`
    #               (8443 by default). Touches nothing that already exists, but
    #               the URL carries the port and certbot's HTTP-01 challenge is
    #               unavailable because Sentinel does not own :80.
    #
    #   shared    — Sentinel is one vhost among several on an nginx that is
    #               already serving 80 and 443, scoped by `server_name`. Clean
    #               URL, working HTTP→HTTPS redirect, and certificate issuance
    #               works normally because Sentinel serves the ACME challenge on
    #               its own :80 server block. Requires that nginx really is what
    #               owns those ports, and it writes into a configuration
    #               directory shared with the operator's own sites.
    #
    # Neither is strictly better. `dedicated` isolates; `shared` integrates.
    nginx_mode: str = "dedicated"

    # The port that appears in the dashboard URL.
    #
    # In `dedicated` mode nginx binds this. In `shared` mode nothing new is
    # bound — the existing nginx already listens on 443 — and this is only used
    # to build links, so 443 is legitimate there and refused everywhere else.
    public_port: int = DEFAULT_PUBLIC_PORT

    domain: str = ""
    session_ttl_s: int = 43_200
    require_totp: bool = True
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    # Empty means "any source that gets past nginx". Filling this in with your
    # own ranges is the cheapest hardening available for a public dashboard.
    ip_allowlist: list[str] = field(default_factory=list)


@dataclass
class AIConfig:
    enabled: bool = True
    model_fast: str = "claude-haiku-4-5-20251001"
    model_main: str = "claude-sonnet-5"
    model_patch: str = "claude-opus-5"
    max_tokens: int = 4096
    timeout_s: int = 120
    daily_budget_usd: float = 5.0
    monthly_budget_usd: float = 100.0
    # Only escalate to the model above this severity; everything else keeps the
    # deterministic verdict.
    triage_min_severity: str = "high"
    correlate_interval_minutes: int = 15
    daily_report_at: str = "08:00"
    ask_rate_limit_per_hour: int = 10
    cli_binary: str = "claude"
    cli_workspace: str = "/opt/sentinel/claude-workspace"
    cli_max_turns: int = 25


@dataclass
class ScanConfig:
    enabled: bool = True
    window: str = "03:00-05:00"
    os_packages: bool = True
    containers: bool = True
    filesystem: bool = True
    source_sca: bool = True
    secrets: bool = True
    # Slow and noisy across every repo. Opt in per repository.
    sast_repos: list[str] = field(default_factory=list)
    # DAST against your own live app. Requires confirmed_by_operator on the asset.
    web_dast: bool = False
    nuclei_rate_limit: int = 20
    nuclei_severities: list[str] = field(
        default_factory=lambda: ["medium", "high", "critical"]
    )
    lynis_weekly: bool = True
    discovery_paths: list[str] = field(
        default_factory=lambda: ["/var/www", "/opt", "/srv", "/home"]
    )
    max_concurrent: int = 1
    #: Anunta pe Telegram vulnerabilitatile NOI, imediat dupa scanare.
    #:
    #: Pornit implicit, la cererea operatorului. Doar constatarile noi ale rularii
    #: curente pleaca: o scanare care regaseste aceleasi doua sute de constatari
    #: nu trimite nimic, fiindca un canal care repeta aceeasi lista e unul pe care
    #: operatorul il opreste — si atunci se pierde si alarma care conta.
    announce_new: bool = True


@dataclass
class PatchConfig:
    # Generation is automatic; application never is.
    auto_generate_for_kev: bool = True
    # Paths this deployment will not let an automated patch touch, on top of
    # the hard-coded floor in sentinel.constants. Put another product's install
    # directory here, or anything you would rather patch by hand.
    extra_protected_paths: list[str] = field(default_factory=list)
    backup_dir: str = "/var/backups/sentinel"
    retention_count: int = 10
    retention_days: int = 30
    require_free_space_multiplier: int = 3
    dry_run_default: bool = True
    health_check_grace_s: int = 30
    restore_drill_days: int = 90


@dataclass
class HealthConfig:
    interval_s: int = 30
    http_timeout_s: int = 10
    down_after_failures: int = 3
    degraded_latency_multiplier: float = 3.0
    disk_warn_pct: int = 85
    mem_warn_mb: int = 1024
    mem_critical_mb: int = 500


@dataclass
class IntelConfig:
    enabled: bool = True
    refresh_hours: int = 6
    feeds_dir: str = f"{CONFIG_DIR}/feeds.d"
    geoip_db: str = "/var/lib/sentinel/geoip/dbip-asn-lite.mmdb"
    epss: bool = True
    kev: bool = True


@dataclass
class SuricataConfig:
    # Set to false by the installer when MemAvailable was under the gate at
    # install time. Sentinel then runs log-only, which is still genuinely good.
    enabled: bool = False
    eve_path: str = "/var/log/suricata/eve.json"
    interface: str = "eth0"
    # Traffic Suricata should not inspect at all, in BPF syntax.
    #
    # Empty is a valid and common answer. It matters when the host carries a
    # high-volume flow with no security value — bulk telemetry, a syslog feed,
    # a backup replication stream. Inspecting one of those can fill the disk in
    # hours and produces nothing worth reading.
    #
    # Preflight measures the top talkers on the interface and tells you whether
    # you need this, rather than guessing on your behalf.
    # Example: "not (host 203.0.113.10 and udp port 514)"
    bpf_filter: str = ""
    # Suricata's own memory ceiling. On a small VPS this is the difference
    # between a NIDS and an OOM kill.
    memcap_mb: int = 128


@dataclass
class Config:
    timezone: str = "Europe/Bucharest"
    hostname: str = ""
    # Operator-chosen display name for this installation — "prod-web-1". Purely
    # cosmetic, exactly like `hostname` above: it labels a row on the external
    # aggregator so a human can tell two servers apart at a glance.
    #
    # NEVER a key, never an identifier, never compared to decide whose data this
    # is. The identity is /etc/sentinel/instance_id (sentinel/identity.py) —
    # random, generated once, and not editable from configuration. Anything that
    # routed, authenticated or de-duplicated on this string would hand whoever
    # can edit sentinel.yaml the ability to rename a server into another one's
    # history, which is the failure the random id exists to prevent.
    #
    # Empty by default and empty is fine: the aggregator falls back to the id.
    instance_label: str = ""
    log_level: str = "INFO"
    platform: PlatformConfig = field(default_factory=PlatformConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    ingest: IngestConfig = field(default_factory=IngestConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    beacon: BeaconConfig = field(default_factory=BeaconConfig)
    ship: ShipConfig = field(default_factory=ShipConfig)
    web: WebConfig = field(default_factory=WebConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    patch: PatchConfig = field(default_factory=PatchConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    suricata: SuricataConfig = field(default_factory=SuricataConfig)


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
class Secrets:
    """Values from secrets.env. Refuses to render itself in any form."""

    __slots__ = ("_values",)

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key, default)

    def require(self, key: str) -> str:
        value = self._values.get(key)
        if not value:
            raise SecretMissingError(
                f"{key} is not set in {SECRETS_PATH}. Run scripts/secrets-init.sh "
                "and redeploy; never add it to sentinel.yaml."
            )
        return value

    def has(self, key: str) -> bool:
        return bool(self._values.get(key))

    def __repr__(self) -> str:
        return f"<Secrets: {len(self._values)} value(s), redacted>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)


def load_secrets(path: Path = SECRETS_PATH) -> Secrets:
    values: dict[str, str] = {}
    if path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            raise ConfigError(
                f"{path} is world-readable (mode {mode:o}). Expected 0640 root:sentinel."
            )
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value

    # Environment wins, so a systemd unit or a test can override without a file.
    for key in (
        "ANTHROPIC_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CALLBACK_HMAC_KEY",
        "SENTINEL_DB_PASSWORD",
        "SENTINEL_DB_DSN",
        "SENTINEL_SESSION_SECRET",
        "TELEGRAM_APPLY_PIN",
        "SENTINEL_BEACON_SECRET",
        "SENTINEL_SHIP_SECRET",
    ):
        if env_value := os.environ.get(key):
            values[key] = env_value

    return Secrets(values)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _coerce(target_type: Any, value: Any, path: str) -> Any:
    if is_dataclass(target_type) and isinstance(value, dict):
        # The dot belongs here, not in `_build`: `_build` joins `path + key`, so
        # without it a nested field came out as `beaconinterval_s` — a name that
        # appears nowhere in sentinel.yaml. It was cosmetic while nothing raised
        # on a nested scalar; the float rule below made it the message operators
        # actually meet, and beacon.py tells them the field will be named.
        return _build(target_type, value, f"{path}.")
    origin = getattr(target_type, "__origin__", None)
    if origin is list:
        if not isinstance(value, list):
            raise ConfigError(f"{path}: expected a list, got {type(value).__name__}")
        return value
    if target_type is bool and not isinstance(value, bool):
        raise ConfigError(f"{path}: expected true/false, got {value!r}")
    if _wants_int(target_type):
        if isinstance(value, bool):
            raise ConfigError(f"{path}: expected an integer, got a boolean")
        if isinstance(value, float):
            # YAML types the value, the annotation does not: `interval_s: 60.0`
            # is a float and used to stay one all the way into the beacon
            # payload, where the two signing implementations disagree — Python
            # writes `60.0`, JavaScript writes `60`, and the signature never
            # verifies. See the contract in sentinel/report/signing.py.
            #
            # Converting rather than refusing, for an integral value: an
            # operator who wrote `60.0` meant sixty, and a ConfigError here
            # refuses to start EVERY service over a decimal point. That is the
            # same trade already argued for `instance_label` in
            # sentinel/report/beacon.py — a value that changes no decision must
            # not be able to stop the process.
            #
            # `60.5` is a different case and is refused: there is no honest
            # conversion, and truncating to 60 would silently run at a cadence
            # nobody asked for. The refusal names the field, which a truncation
            # never would.
            if not value.is_integer():
                raise ConfigError(
                    f"{path}: expected an integer, got {value!r}. Round it "
                    f"yourself — this field has no fractional meaning and "
                    f"guessing which way to round it is not the config loader's "
                    f"call.")
            return int(value)
    return value


def _wants_int(target_type: Any) -> bool:
    """`int`, or `int | None`.

    Both read to an operator as "a number goes here", so both get the same
    treatment. Nothing else does: `list[int]` and `dict[str, int]` carry their
    integers inside a container this function never opens.
    """
    if target_type is int:
        return True
    args = getattr(target_type, "__args__", ())
    return bool(args) and set(args) == {int, type(None)}


def _build(cls: type[T], data: dict[str, Any], path: str = "") -> T:
    kwargs: dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}  # type: ignore[arg-type]
    # `field.type` is a STRING, not the class: `from __future__ import annotations`
    # (PEP 563) turns every annotation into its source text, so `known[key].type`
    # would be "WebConfig", not WebConfig — and `is_dataclass("WebConfig")` is
    # False, leaving nested sections as raw dicts. get_type_hints resolves the
    # strings back to real classes using the module's namespace.
    hints = get_type_hints(cls)
    for key, value in data.items():
        if key not in known:
            raise ConfigError(
                f"unknown configuration key {path}{key!r}. "
                f"Valid keys here: {', '.join(sorted(known))}"
            )
        if value is None:
            continue
        kwargs[key] = _coerce(hints[key], value, f"{path}{key}")
    return cls(**kwargs)  # type: ignore[call-arg]


def load_config(path: Path = CONFIG_PATH) -> Config:
    """Load and validate the configuration. Raises ConfigError with a usable message."""
    raw: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ConfigError(f"{path} must contain a mapping at the top level")
            raw = loaded

    config = _build(Config, raw)
    _validate(config)
    return config


def _validate(cfg: Config) -> None:
    from sentinel.constants import RESERVED_PORTS, SEVERITIES

    from sentinel.constants import NGINX_MODES, PLATFORM_FAMILIES

    if cfg.platform.family not in PLATFORM_FAMILIES:
        raise ConfigError(
            f"platform.family must be one of {list(PLATFORM_FAMILIES)}, got "
            f"{cfg.platform.family!r}. It is written by the installer from the "
            "family deploy/lib/distro.sh detected; do not hand-edit it to a "
            "distribution name. An unrecognised family selects no OS-package "
            "scanner, and a scanner that never runs looks exactly like a host "
            "with no vulnerabilities."
        )

    if cfg.web.nginx_mode not in NGINX_MODES:
        raise ConfigError(f"web.nginx_mode must be one of {NGINX_MODES}")

    shared = cfg.web.nginx_mode == "shared"

    for label, value in (
        ("web.port", cfg.web.port),
        ("web.public_port", cfg.web.public_port),
        ("database.port", cfg.database.port),
    ):
        # `public_port` in shared mode is a URL component, not something Sentinel
        # binds — the existing nginx is already listening there. Everything else,
        # including the loopback app port, really is bound and must not collide.
        exempt = shared and label == "web.public_port" and value in (80, 443)

        if value in RESERVED_PORTS and not exempt:
            raise ConfigError(
                f"{label} {value} is reserved ({sorted(RESERVED_PORTS)}). "
                "22 would end the operator's SSH session and their ability to undo "
                "it; binding 80 or 443 would displace whatever the host is "
                "actually for. "
                + (
                    "In shared nginx mode 443 is allowed for web.public_port, "
                    "because nothing new is bound there."
                    if label == "web.public_port"
                    else ""
                )
            )
        if not 1 <= value <= 65535:
            raise ConfigError(f"{label} {value} is not a valid port")

    if shared and cfg.web.public_port not in (80, 443):
        raise ConfigError(
            f"web.nginx_mode is 'shared' but public_port is {cfg.web.public_port}. "
            "Shared mode means Sentinel is a vhost on the existing nginx, which "
            "listens on 443 — set public_port to 443, or use dedicated mode."
        )

    ports = {
        "web.port": cfg.web.port,
        "web.public_port": cfg.web.public_port,
        "database.port": cfg.database.port,
    }
    if len(set(ports.values())) != len(ports):
        raise ConfigError(f"these must all differ: {ports}")
    if cfg.telegram.enabled and not cfg.telegram.allowed_chat_ids:
        raise ConfigError(
            "telegram.enabled is true but allowed_chat_ids is empty. An empty "
            "allowlist would accept commands from anyone who finds the bot."
        )
    if cfg.telegram.min_severity not in SEVERITIES:
        raise ConfigError(f"telegram.min_severity must be one of {SEVERITIES}")
    if cfg.ai.triage_min_severity not in SEVERITIES:
        raise ConfigError(f"ai.triage_min_severity must be one of {SEVERITIES}")
    if cfg.web.domain and cfg.web.bind not in ("127.0.0.1", "::1"):
        raise ConfigError(
            "web.bind must stay on loopback; nginx terminates TLS and proxies to it. "
            "Binding the app publicly would bypass TLS, rate limiting and the "
            "security headers."
        )
    if cfg.response.auto_block.max_elements > 20_000:
        raise ConfigError("response.auto_block.max_elements may not exceed the hard cap of 20000")
    if cfg.response.auto_block.min_severity not in SEVERITIES:
        raise ConfigError(
            f"response.auto_block.min_severity must be one of {sorted(SEVERITIES)}")
    if cfg.patch.retention_count < 1:
        raise ConfigError("patch.retention_count must be at least 1 — never zero ways back")

    # The beacon's freshness window, bounded here for the same reason as
    # `ship.max_age_s` below — and NOT for the reason that was written down for a
    # while, which was that a refused beat is loud enough on its own.
    #
    # It is loud on a host that has beaten before: the witness moves that
    # instance to `silent` and calls. It is completely silent on a NEW one, which
    # is the exact moment somebody types this value. Measured on 15 August 2026
    # with `beacon.max_age_s: 100000` (a milliseconds/seconds mix-up; the default
    # is 120): the watcher answers 400 naming the field, and `/status` stays 200
    # `ok` with the new instance sitting in `no-beat` — a state that is never
    # counted and never alerted, deliberately, so that a key left in the
    # configuration cannot hold the panel red forever. On this end
    # `beacon.run_forever` only writes `log.error`, so nothing calls either.
    #
    # So the rule the two receivers now share: every ceiling AT A RECEIVER gets a
    # bound at configuration load plus a test that reads both files. Whether the
    # refusal is noisy depends on whether the instance ever beat — something the
    # receiver neither controls nor can know at the moment the operator gets it
    # wrong.
    #
    # The number is the same one as `MAX_AGE_CEILING_S` in
    # `aggregator/app/api/sentinel/beat/route.ts`. Kept in agreement by
    # `tests/unit/test_beacon.py::test_the_two_ends_agree_on_the_beat_freshness_ceiling`,
    # which fails if either side moves.
    if not 1 <= cfg.beacon.max_age_s <= 86_400:
        raise ConfigError(
            f"beacon.max_age_s is {cfg.beacon.max_age_s}; it must be between 1 and 86400. "
            f"Zero would make every beat stale on arrival; a window wider than a "
            f"day is refused by the watcher, and on an installation that has not "
            f"beaten yet that refusal is silent on every surface — the watcher "
            f"reports the instance as `no-beat`, which never alerts.")

    # The shipper's bounds. Refused here rather than clamped in the loop: a
    # clamp runs at a cadence nobody wrote down, and the operator who set
    # `max_rows_per_batch: 0` would watch a cursor that never moves with nothing
    # anywhere saying why. These are also the only values in the section that
    # can turn the shipper into a hot loop or a request that never completes.
    if not 1 <= cfg.ship.max_rows_per_batch <= 2_000:
        raise ConfigError(
            f"ship.max_rows_per_batch is {cfg.ship.max_rows_per_batch}; it must be "
            f"between 1 and 2000. Zero would ship nothing forever while looking "
            f"configured; above 2000 the cost is not memory, it is ROUND TRIPS at "
            f"the receiver — ingestion writes and then COUNTS in chunks, so a "
            f"2000-row batch is already ~34 statements against MariaDB inside one "
            f"`ship.timeout_s`, and 20000 would be ~304 with a per-statement "
            f"latency nobody has measured. The batch size is not the lever for a "
            f"backlog anyway: the shipper drains full batches one second apart "
            f"(`DRAIN_PAUSE_S`), which is 2000 rows per second sustained. Same "
            f"number as `MAX_ROWS_PER_BATCH` in `aggregator/lib/ingest.ts`; kept "
            f"in agreement by tests/unit/test_shipper.py.")
    # Sub-rândurile au propriile plafoane, refuzate tot AICI și din același
    # motiv: un lot cu prea mulți copii primește 413 de la receptor, iar
    # `ship_once` nu-i citește niciodată corpul.
    #
    # Cazul care le atinge nu e exotic: 2000 de detecții cu câte cinci
    # evenimente fiecare înseamnă 10000 de sub-rânduri, peste plafonul de
    # 6000. De-aia expeditorul TAIE lotul scurt când bugetul de copii se
    # epuizează — trimite mai puțini părinți, nu un lot refuzat.
    if not 1 <= cfg.ship.max_children_per_row <= 1_000:
        raise ConfigError(
            f"ship.max_children_per_row is {cfg.ship.max_children_per_row}; it "
            f"must be between 1 and 1000. Same number as MAX_CHILDREN_PER_ROW in "
            f"aggregator/lib/ingest.ts. A single row above it can never ship: it "
            f"stalls the stream visibly rather than being skipped, because a "
            f"skipped row never comes back.")
    if not 1 <= cfg.ship.max_child_rows_per_batch <= 6_000:
        raise ConfigError(
            f"ship.max_child_rows_per_batch is "
            f"{cfg.ship.max_child_rows_per_batch}; it must be between 1 and 6000. "
            f"Same number as MAX_CHILD_ROWS_PER_BATCH in "
            f"aggregator/lib/ingest.ts, which is three times the row ceiling.")

    # `max_age_s` is enforced at the RECEIVER, and the receiver's ceiling is not
    # a number this end can discover at runtime: `ship_once` treats every non-2xx
    # the same and never reads the response body, and nothing anywhere shrinks a
    # value that was refused. So a window the aggregator will not accept looks
    # exactly like an aggregator that is down — forever, with backoff up to
    # `backoff_max_s`, while the audit chain stops leaving the host.
    #
    # The number below is the same one as `MAX_AGE_CEILING_S` in
    # `aggregator/app/api/sentinel/sync/route.ts`. Kept in agreement by
    # `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`,
    # which fails if either side moves.
    if not 1 <= cfg.ship.max_age_s <= 86_400:
        raise ConfigError(
            f"ship.max_age_s is {cfg.ship.max_age_s}; it must be between 1 and 86400. "
            f"Zero would make every batch stale on arrival; a window wider than a "
            f"day is refused by the aggregator, and a refused batch is "
            f"indistinguishable from an aggregator that is down.")
    if cfg.ship.max_backfill_days < 0:
        raise ConfigError(
            "ship.max_backfill_days may not be negative — a floor in the future "
            "would silently skip rows that have not been written yet")
    if cfg.ship.interval_s < 1:
        raise ConfigError("ship.interval_s must be at least 1 second")
    if cfg.ship.backoff_base_s < 1:
        raise ConfigError("ship.backoff_base_s must be at least 1 second")
    if cfg.ship.backoff_max_s < cfg.ship.backoff_base_s:
        raise ConfigError(
            f"ship.backoff_max_s ({cfg.ship.backoff_max_s}) is below "
            f"ship.backoff_base_s ({cfg.ship.backoff_base_s}), so the cap would "
            f"shorten the first retry instead of bounding the last")

    for path in cfg.patch.extra_protected_paths:
        if not path.startswith("/"):
            raise ConfigError(
                f"patch.extra_protected_paths entry {path!r} must be an absolute path"
            )
    for cidr in cfg.response.extra_allowlist:
        try:
            import ipaddress

            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"response.extra_allowlist entry {cidr!r} is not a valid network: {exc}"
            ) from None


_cached: Config | None = None
_cached_secrets: Secrets | None = None


def get_config(reload: bool = False) -> Config:
    global _cached
    if _cached is None or reload:
        _cached = load_config()
    return _cached


def get_secrets(reload: bool = False) -> Secrets:
    global _cached_secrets
    if _cached_secrets is None or reload:
        _cached_secrets = load_secrets()
    return _cached_secrets


def database_dsn(cfg: Config | None = None, secrets: Secrets | None = None) -> str:
    cfg = cfg or get_config()
    secrets = secrets or get_secrets()
    if dsn := secrets.get("SENTINEL_DB_DSN"):
        return dsn
    password = secrets.require("SENTINEL_DB_PASSWORD")
    db = cfg.database
    return f"postgresql://{db.user}:{password}@{db.host}:{db.port}/{db.name}"
