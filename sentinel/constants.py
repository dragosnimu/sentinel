"""Constants that must not be configurable.

Everything in this module is a safety boundary. Putting these in a config file
or in the database would mean a config-file compromise, a database compromise or
a bad AI output could widen them. They live in code, they are covered by tests,
and changing one is a code review.

`executor/policy.py` deliberately re-declares the subset it needs rather than
importing from here — the root executor imports nothing from this package. If
you change a value here that also appears there, change both. There is a test
that asserts they agree.
"""

from __future__ import annotations

import ipaddress
from typing import Final

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------
# Ports Sentinel itself owns.
SENTINEL_WEB_PORT: Final[int] = 8787          # loopback only; nginx proxies to it
POSTGRES_PORT: Final[int] = 5432               # loopback only

# The public HTTPS port for the dashboard.
#
# Not 443. Sentinel is a guest on a host that is usually already serving
# something, and taking 80/443 would mean either a port conflict or displacing
# whatever is there. A dedicated high port sidesteps both.
#
# The consequence is that certificate issuance cannot use certbot's HTTP-01
# challenge on :80 — see deploy/install.sh's cert modes.
DEFAULT_PUBLIC_PORT: Final[int] = 8443

# Ports Sentinel will not BIND, whatever the configuration says.
#
# 22 because losing SSH means losing the ability to fix anything. 80 and 443
# because binding them means displacing whatever the host is actually for, and a
# monitoring agent that takes down the service it monitors has inverted its
# purpose.
#
# The distinction is *binding*, not *appearing in a URL*. In `shared` nginx mode
# Sentinel is one vhost among several on an nginx that is already listening on
# 443 — it binds nothing, so 443 is a legitimate public port there. See
# WebConfig.nginx_mode.
RESERVED_BIND_PORTS: Final[frozenset[int]] = frozenset({22, 80, 443})

# Kept as an alias: several call sites and tests read this name.
RESERVED_PORTS: Final[frozenset[int]] = RESERVED_BIND_PORTS

NGINX_MODES: Final[tuple[str, ...]] = ("dedicated", "shared")

# Ports belonging to OTHER services on the host are not enumerated anywhere.
# They vary per machine, so the installer discovers them: preflight snapshots
# what is listening and refuses to take a port already in use. A hard-coded list
# would be wrong on every host but the one it was written for.

# ---------------------------------------------------------------------------
# Never-block networks
# ---------------------------------------------------------------------------
# Blocking any of these is a self-inflicted outage. The executor refuses a
# block request matching any of them regardless of who asks or why.
#
# These are the universal ones — true on every host. Anything specific to a
# deployment (an uptime monitor, a CI runner, an office range, a high-volume
# telemetry source) belongs in `response.extra_allowlist`, which the operator
# maintains and the executor loads at startup.
NEVER_BLOCK_NETWORKS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fe80::/10",
        "fc00::/7",
        "224.0.0.0/4",
    )
)

# Hostnames whose resolved addresses are allowlisted at startup and on every
# intel refresh. Blocking these would silently remove Sentinel's own alerting
# and analysis channels — a failure mode with no symptom.
NEVER_BLOCK_HOSTNAMES: Final[tuple[str, ...]] = (
    "api.telegram.org",
    "api.anthropic.com",
)

# A block request wider than this is always refused. A /24 is already 256
# addresses and enough to take out a NAT'd office.
MAX_BLOCK_PREFIX_V4: Final[int] = 24
MAX_BLOCK_PREFIX_V6: Final[int] = 64

# ---------------------------------------------------------------------------
# Blocking rate caps
# ---------------------------------------------------------------------------
# A runaway detector must not be able to black-hole the internet. Exceeding
# either cap raises an alert and refuses further blocks until an operator acts.
MAX_BLOCKS_PER_MINUTE: Final[int] = 60
MAX_BLOCKLIST_ELEMENTS: Final[int] = 20_000

DEFAULT_BLOCK_TTL_S: Final[dict[str, int]] = {
    "scan": 3_600,
    "web": 21_600,
    "auth": 86_400,
    "dos": 7_200,
    "host": 86_400,
    "anomaly": 3_600,
}
MIN_BLOCK_TTL_S: Final[int] = 60
MAX_BLOCK_TTL_S: Final[int] = 30 * 86_400

# ---------------------------------------------------------------------------
# Paths no automated change may touch
# ---------------------------------------------------------------------------
# Sentinel's own, and the ones that would lock the operator out or escalate
# privileges. The patch validator rejects any plan referencing these.
#
# Deployment-specific paths — another product's install directory, a database
# you would rather patch by hand — go in `patch.extra_protected_paths` in the
# config. This list is the floor, not the whole fence.
PROTECTED_PATHS: Final[tuple[str, ...]] = (
    "/opt/sentinel",
    "/etc/sentinel",
    "/var/lib/sentinel",
    "/var/backups/sentinel",
    "/root/.ssh",
    "/etc/ssh",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/systemd/system/sentinel-executor.service",
    "/boot",
)

# Files Sentinel must never read into a prompt, a log, or the database.
SECRET_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "/etc/sentinel/secrets.env",
    "**/.env",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/credentiale*",
)

# ---------------------------------------------------------------------------
# Patch execution safety
# ---------------------------------------------------------------------------
# argv[0] must be one of these. `sh`, `bash`, `env`, `sudo` and `python` are
# absent on purpose: they turn an argv allowlist into no allowlist at all.
PATCH_BINARY_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "dnf", "rpm", "systemctl",
        "nginx", "httpd", "apachectl",
        "docker",
        "git", "npm", "yarn", "composer", "pip", "pip3", "wp",
        "mysqldump", "mysql", "pg_dump", "psql",
        "tar", "zstd", "gzip",
        "cp", "mv", "ln", "mkdir", "install", "chown", "chmod", "sed", "test",
        # Read-only inspection: these can answer a question but cannot change
        # anything, which is why they are safe to allow and why the schema's
        # file_sha256 check needs them.
        "sha256sum",
        "certbot",
        "curl",
    }
)

# Rejected wherever they appear, in any argument, on any binary.
PATCH_FORBIDDEN_SUBSTRINGS: Final[tuple[str, ...]] = (
    "mkfs", "dd if=", "dd of=", "/dev/sd", "/dev/nvme", "/dev/mapper",
    "nft", "iptables", "ip6tables", "firewall-cmd", "firewalld",
    "userdel", "usermod", "passwd", "chpasswd",
    "authorized_keys", "sshd_config",
    "--no-preserve-root",
)

# Characters that only make sense if you believe a shell is involved. One of
# these in an argv is a sign the plan was written wrong.
SHELL_METACHARACTERS: Final[tuple[str, ...]] = (
    "|", ";", "&", "$(", "`", ">", "<", "\n", "\r", "\x00",
)

# Packages whose update requires a reboot, and therefore a separate approval.
REBOOT_REQUIRED_PACKAGES: Final[tuple[str, ...]] = (
    "kernel", "kernel-core", "kernel-modules",
    "glibc", "systemd", "openssl", "dbus", "linux-firmware", "microcode_ctl",
)

# ---------------------------------------------------------------------------
# Detection / correlation
# ---------------------------------------------------------------------------
SEVERITIES: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

KILLCHAIN_STAGES: Final[dict[int, str]] = {
    0: "observed",
    1: "recon",
    2: "enumeration",
    3: "credential_attack",
    4: "exploitation",
    5: "post_exploitation",
    6: "impact",
}

# Anomaly rules stay silent until a baseline has this much history. Skipping the
# warm-up is how you get several hundred false positives on day one.
BASELINE_WARMUP_DAYS: Final[int] = 14

# Incidents dedup on rule_family + actor + asset within this bucket.
INCIDENT_BUCKET_MINUTES: Final[int] = 15

# ---------------------------------------------------------------------------
# Filesystem layout on the server
# ---------------------------------------------------------------------------
INSTALL_PREFIX: Final[str] = "/opt/sentinel"
CONFIG_DIR: Final[str] = "/etc/sentinel"
STATE_DIR: Final[str] = "/var/lib/sentinel"
BACKUP_DIR: Final[str] = "/var/backups/sentinel"
RUNTIME_DIR: Final[str] = "/run/sentinel"
EXECUTOR_SOCKET: Final[str] = "/run/sentinel/executor.sock"
PANIC_FILE: Final[str] = "/etc/sentinel/PANIC"
CLAUDE_WORKSPACE: Final[str] = "/opt/sentinel/claude-workspace"

SERVICE_USER: Final[str] = "sentinel"

SYSTEMD_UNITS: Final[tuple[str, ...]] = (
    "sentinel-ingest.service",
    "sentinel-detect.service",
    "sentinel-ai.service",
    "sentinel-telegram.service",
    "sentinel-web.service",
    "sentinel-executor.service",
    "sentinel-beacon.service",
)

# ---------------------------------------------------------------------------
# Watchdog thresholds (the anti-lockout deadman)
# ---------------------------------------------------------------------------
WATCHDOG_WEB_DOWN_FLUSH_S: Final[int] = 300      # web health down this long → flush
WATCHDOG_RESTART_LOOP_COUNT: Final[int] = 5      # detect restarts in 5 min → flush
WATCHDOG_INTERVAL_S: Final[int] = 60


def is_never_block(ip: str) -> bool:
    """True if this address may never be blocked, whatever the caller claims."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable is refused, not permitted
    return any(addr in net for net in NEVER_BLOCK_NETWORKS)
