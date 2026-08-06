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
    log_level: str = "INFO"
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    ingest: IngestConfig = field(default_factory=IngestConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    beacon: BeaconConfig = field(default_factory=BeaconConfig)
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
    ):
        if env_value := os.environ.get(key):
            values[key] = env_value

    return Secrets(values)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _coerce(target_type: Any, value: Any, path: str) -> Any:
    if is_dataclass(target_type) and isinstance(value, dict):
        return _build(target_type, value, path)
    origin = getattr(target_type, "__origin__", None)
    if origin is list:
        if not isinstance(value, list):
            raise ConfigError(f"{path}: expected a list, got {type(value).__name__}")
        return value
    if target_type is bool and not isinstance(value, bool):
        raise ConfigError(f"{path}: expected true/false, got {value!r}")
    if target_type is int and isinstance(value, bool):
        raise ConfigError(f"{path}: expected an integer, got a boolean")
    return value


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

    from sentinel.constants import NGINX_MODES

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
