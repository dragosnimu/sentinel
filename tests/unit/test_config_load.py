"""Loading a real YAML file, not just constructing Config() with defaults.

The port-validation tests build `Config()` directly, so every nested section is
already a typed object and the YAML→object path is never exercised. That path had
a bug: under `from __future__ import annotations` the dataclass field types are
strings, so nested sections (`web:`, `database:`, `telegram:`) were left as raw
dicts and the first attribute access on them blew up at install time. These tests
load YAML the way the installer does.
"""

from __future__ import annotations

import pytest

from sentinel.config import load_config
from sentinel.errors import ConfigError


def _write(tmp_path, text: str):
    p = tmp_path / "sentinel.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_nested_sections_become_typed_objects(tmp_path):
    """The regression: web/database/telegram must be their dataclasses, not dicts."""
    from sentinel.config import DatabaseConfig, TelegramConfig, WebConfig

    cfg = load_config(_write(tmp_path, """
web:
  nginx_mode: shared
  public_port: 443
telegram:
  enabled: false
"""))
    assert isinstance(cfg.web, WebConfig)
    assert isinstance(cfg.database, DatabaseConfig)
    assert isinstance(cfg.telegram, TelegramConfig)
    # And the values round-tripped, not just the types.
    assert cfg.web.nginx_mode == "shared"
    assert cfg.web.public_port == 443


def test_nested_override_reaches_validation(tmp_path):
    """A shared-mode config with a bad public_port must be REJECTED, which only
    happens if the nested override actually took effect."""
    with pytest.raises(ConfigError, match="public_port"):
        load_config(_write(tmp_path, """
web:
  nginx_mode: shared
  public_port: 8443
telegram:
  enabled: false
"""))


def test_unknown_nested_key_is_reported_with_path(tmp_path):
    with pytest.raises(ConfigError, match="web.*noSuchKey|noSuchKey"):
        load_config(_write(tmp_path, """
web:
  noSuchKey: 1
telegram:
  enabled: false
"""))


def _render_shipped_template() -> str:
    """The installer's substitutions, with documentation-range values.

    `tests/security/test_repo_is_sanitised.py` greps this tree for real
    infrastructure, and a fixture that names a real host is as much of a problem
    as the real thing.
    """
    from pathlib import Path

    template = (Path(__file__).resolve().parents[2]
                / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    rendered = template
    for placeholder, value in {
        "@@HOSTNAME@@": "host.example.test",
        "@@DOMAIN@@": "panel.example.test",
        "@@PLATFORM_FAMILY@@": "rhel",
        "@@NGINX_MODE@@": "dedicated",
        "@@PUBLIC_PORT@@": "8443",
        "@@IFACE@@": "eth0",
        "@@BPF_FILTER@@": "",
        "@@SURICATA_ENABLED@@": "true",
        "@@AUDITD_ENABLED@@": "true",
        "@@SCAN_CONTAINERS@@": "true",
        "@@DB_PORT@@": "5432",
        "@@TELEGRAM_CHAT_ID@@": "1",
        "@@EXTRA_ALLOWLIST@@": '"192.0.2.10"',
    }.items():
        rendered = rendered.replace(placeholder, value)
    assert "@@" not in rendered, "a placeholder was added that this test does not render"
    return rendered


def test_the_shipped_template_still_loads(tmp_path):
    """The file every install actually gets, rendered and parsed.

    `_build` raises `ConfigError` on a key it does not know, and every daemon
    calls `load_config` at startup — so one key added to
    `deploy/config/sentinel.yaml.tmpl` without a matching field on `Config`
    stops the whole agent on the next deploy, with a message the operator only
    sees in `journalctl`. Nothing else in the suite parses the template.
    """
    cfg = load_config(_write(tmp_path, _render_shipped_template()))
    # And the field this test was written for: cosmetic, empty, and accepted.
    assert cfg.instance_label == ""
    # database.port is a placeholder now (@@DB_PORT@@), not a literal 5432 —
    # confirms the rendered value actually reaches Config, round-tripped.
    assert cfg.database.port == 5432


# This is where `test_the_template_skips_the_account_the_installer_actually_creates`
# used to be, removed on 25 August 2026. It compared the NAME in `install.sh`
# with the NAME in `sentinel.yaml.tmpl` — two files in this repository, which
# can agree perfectly with each other and disagree with the host. Which is
# exactly what happened: the deploy ran as a different account, `auid` survives
# `sudo`, the filter matched nothing, and the test was green.
#
# Its replacement is
# `tests/unit/test_login_projection.py::test_the_shipped_configuration_actually_drops_a_real_deploy_burst`,
# which asserts on the DECISION rather than on the presence of a name: given a
# real deploy's event stream, the projection drops the rows and counts them.


# --- platform family -------------------------------------------------------
def test_a_config_without_a_platform_section_is_still_rhel(tmp_path):
    """The production host runs AlmaLinux and will never gain this key.

    `install_config` refuses to overwrite a live sentinel.yaml — it writes
    sentinel.yaml.new and warns — so every installation that predates
    platform.family keeps a file without it. If the default were anything but
    `rhel`, the next scan pass on that host would run the wrong package manager,
    the scan would fail, and the vulnerability page would stop being refreshed.
    """
    from sentinel.config import PlatformConfig

    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert isinstance(cfg.platform, PlatformConfig)
    assert cfg.platform.family == "rhel"


def test_the_default_family_still_selects_the_scanner_production_reports_under(tmp_path):
    """The continuity this default exists for, checked as an effect.

    `check_last_scan` reports under `scan:last:{scanner}`, and `selfcheck_state`
    on the production host carries `scan:last:dnf` with history from 21 August
    2026. A default that loaded fine but selected any other scanner name would
    have that key reconciled away and a fresh one inserted with `since = now()`,
    throwing away the history the operator reads.
    """
    from sentinel.scan.os_packages import scanner_for

    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert scanner_for(cfg.platform.family) == "dnf"


def test_platform_family_from_the_file_is_what_reaches_the_runtime(tmp_path):
    """The installer writes the family into the file; if the load path dropped
    it, an Ubuntu host would silently keep the rhel default and run dnf."""
    cfg = load_config(_write(tmp_path, """
platform:
  family: debian
telegram:
  enabled: false
"""))
    assert cfg.platform.family == "debian"


def test_an_unrecognised_platform_family_is_refused(tmp_path):
    """`family: ubuntu` looks right and selects no scanner. Tolerating it — by
    falling back to the default — would run dnf on an Ubuntu host and produce a
    page of zero vulnerabilities that nobody could explain."""
    with pytest.raises(ConfigError, match="platform.family"):
        load_config(_write(tmp_path, """
platform:
  family: ubuntu
telegram:
  enabled: false
"""))


def test_an_unsubstituted_placeholder_is_refused(tmp_path):
    """If install.sh ever stops substituting @@PLATFORM_FAMILY@@, the literal
    token must stop the service at load rather than be quietly ignored."""
    with pytest.raises(ConfigError, match="platform.family"):
        load_config(_write(tmp_path, """
platform:
  family: "@@PLATFORM_FAMILY@@"
telegram:
  enabled: false
"""))


def test_a_config_without_a_history_section_drops_nothing(tmp_path):
    """Every host already running is exactly this file.

    `install_config` refuses to overwrite an existing `sentinel.yaml` — it writes
    `sentinel.yaml.new` and warns — so an upgraded host keeps a config with no
    `history:` section at all until somebody merges it by hand. The default must
    therefore mean "keep every command", the behaviour those hosts have today.
    An automation account baked in as the default would start dropping history on
    hosts whose operator never asked for it, and never named the account.
    """
    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert cfg.history.skip_command_accounts == [], (
        "a host that never configured the filter would silently lose commands")


def test_an_integer_field_written_as_a_yaml_float_becomes_an_int(tmp_path):
    """`beacon: {interval_s: 60.0}` used to put a float in the signed payload.

    YAML types the value, not the annotation, and `_coerce` passed it through.
    The float then reached `sentinel/report/signing.py`, where Python writes
    `60.0` and the TypeScript witness writes `60` — the signature never
    verifies, and the operator sees a 401 that looks exactly like a wrong key.

    The value, not just the type: `60.0` must become sixty, not the `600` that
    `deploy/install.sh`'s `tr -dc '0-9'` makes of the same text.
    """
    cfg = load_config(_write(tmp_path, """
beacon:
  interval_s: 60.0
  max_age_s: 120.0
telegram:
  enabled: false
"""))
    assert cfg.beacon.interval_s == 60
    assert type(cfg.beacon.interval_s) is int
    assert cfg.beacon.max_age_s == 120
    assert type(cfg.beacon.max_age_s) is int

    # And the whole point: what comes out is signable.
    from sentinel.report.signing import canonical
    assert canonical({"interval_s": cfg.beacon.interval_s}) == b'{"interval_s":60}'


def test_a_fractional_value_for_an_integer_field_is_refused(tmp_path):
    """`interval_s: 60.5` has no honest conversion.

    Truncating to 60 would run the beacon at a cadence nobody asked for and say
    nothing about it. The refusal names the field; a silent truncation never
    would. It costs a failed start, which is where a config error belongs.
    """
    with pytest.raises(ConfigError, match="interval_s"):
        load_config(_write(tmp_path, """
beacon:
  interval_s: 60.5
telegram:
  enabled: false
"""))


def test_the_error_names_a_field_that_exists_in_the_yaml(tmp_path):
    """`beaconinterval_s` appears nowhere in sentinel.yaml.

    `_build` joined the section and the key with no separator. It was invisible
    while nothing raised on a nested scalar; the float rule above made it the
    message an operator actually meets, and `sentinel/report/beacon.py` tells
    that operator the offending field will be named for them. A name they cannot
    grep for is worse than no name: it sends them looking for a key that does
    not exist.
    """
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, """
beacon:
  interval_s: 60.5
telegram:
  enabled: false
"""))
    assert "beacon.interval_s" in str(exc.value)
    assert "beaconinterval_s" not in str(exc.value)

    # Same joint, on the path an unknown key takes.
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, """
beacon:
  nuExista: 1
"""))
    assert "beacon.'nuExista'" in str(exc.value)


def test_an_optional_integer_field_gets_the_same_treatment(tmp_path):
    """`owner_chat_id: 12345.0` reads as an integer to whoever wrote it.

    `int | None` is still "a number goes here". Leaving it a float would put a
    float into every comparison against a chat id, and into any payload that
    later carries it.
    """
    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
  owner_chat_id: 12345.0
"""))
    assert cfg.telegram.owner_chat_id == 12345
    assert type(cfg.telegram.owner_chat_id) is int


def test_a_boolean_where_an_integer_belongs_is_still_refused(tmp_path):
    """The rule that was already there, kept while the float rule was added.

    `true` is `1` in Python, so without this the beacon would report an interval
    of one second and nothing would say why.
    """
    with pytest.raises(ConfigError, match="interval_s"):
        load_config(_write(tmp_path, """
beacon:
  interval_s: true
telegram:
  enabled: false
"""))


def test_web_defaults_survive_a_partial_file(tmp_path):
    """A file that only sets telegram must leave web at its typed defaults —
    proving _build fills unspecified sections rather than dropping them."""
    from sentinel.config import WebConfig

    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert isinstance(cfg.web, WebConfig)
    assert cfg.web.nginx_mode == "dedicated"   # the shipped default


# --- ship.*: the bounds that decide whether the shipper can make progress ---
def test_a_batch_size_of_zero_is_refused_rather_than_clamped(tmp_path):
    """`max_rows_per_batch: 0` selects no rows, so the cursor never moves and the
    aggregator never receives anything — while `sentinel config-check` prints a
    green line and the unit sits `active`. Clamping it in the loop would hide the
    typo behind a cadence nobody wrote down; refusing names the field."""
    with pytest.raises(ConfigError, match="max_rows_per_batch"):
        load_config(_write(tmp_path, """
ship:
  max_rows_per_batch: 0
telegram:
  enabled: false
"""))


def test_an_enormous_batch_size_is_refused(tmp_path):
    """One request that reads a million rows, encodes them, signs them and then
    times out — retried forever, never progressing. The backlog it is supposed
    to drain is exactly the situation that produces it."""
    with pytest.raises(ConfigError, match="max_rows_per_batch"):
        load_config(_write(tmp_path, """
ship:
  max_rows_per_batch: 500000
telegram:
  enabled: false
"""))


def test_a_backoff_cap_below_the_base_is_refused(tmp_path):
    """A cap under the base does not bound the last retry, it shortens the first
    — so an aggregator that is down gets hit harder than configured, by a file
    that reads as if it were being gentle."""
    with pytest.raises(ConfigError, match="backoff_max_s"):
        load_config(_write(tmp_path, """
ship:
  backoff_base_s: 300
  backoff_max_s: 60
telegram:
  enabled: false
"""))


def test_a_negative_backfill_window_is_refused(tmp_path):
    """A floor in the future skips rows that have not been written yet — the
    silent permanent loss the shipper exists to prevent, configured in."""
    with pytest.raises(ConfigError, match="max_backfill_days"):
        load_config(_write(tmp_path, """
ship:
  max_backfill_days: -1
telegram:
  enabled: false
"""))


def test_shipping_is_off_in_a_file_that_does_not_mention_it(tmp_path):
    """Every host in production today. The aggregator does not exist yet, so a
    default of `true` would mean every deploy starts a service that retries a
    blank URL forever."""
    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert cfg.ship.enabled is False
    assert cfg.ship.url == ""
    assert cfg.ship.max_rows_per_batch == 2000
    assert cfg.ship.max_backfill_days == 7


# --- S8: values that read as valid and kill a daemon at runtime ------------
def test_a_quoted_ai_budget_is_refused_instead_of_crashing_every_30s(tmp_path):
    """Confirmed on production: `ai.daily_budget_usd: '5'` reached the budget
    arithmetic unchanged and raised TypeError every single check, forever."""
    with pytest.raises(ConfigError, match="daily_budget_usd"):
        load_config(_write(tmp_path, """
ai:
  daily_budget_usd: '5'
telegram:
  enabled: false
"""))


def test_a_negative_ai_budget_is_refused_instead_of_silently_disabling_ai(tmp_path):
    """Confirmed on production: -1 turned the AI layer off with no error and
    no distinction from `ai.enabled: false` — a typo reads as a decision."""
    with pytest.raises(ConfigError, match="daily_budget_usd"):
        load_config(_write(tmp_path, """
ai:
  daily_budget_usd: -1
telegram:
  enabled: false
"""))


def test_a_nan_ai_budget_is_refused_not_a_cap_that_never_applies(tmp_path):
    """S8 (round 2): YAML's `.nan` parses straight into a real Python float,
    so `isinstance(value, (int, float))` was TRUE for it and it sailed
    through unchanged — `spent >= .nan` is always False in `budget.py`, so
    the cap silently never applied, no matter how much was spent."""
    with pytest.raises(ConfigError, match="daily_budget_usd"):
        load_config(_write(tmp_path, """
ai:
  daily_budget_usd: .nan
telegram:
  enabled: false
"""))


def test_an_infinite_ai_budget_is_refused(tmp_path):
    """The other direction of the same bug: `.inf` compares as "always under
    budget", which is the same "the cap never applies" outcome."""
    with pytest.raises(ConfigError, match="daily_budget_usd"):
        load_config(_write(tmp_path, """
ai:
  daily_budget_usd: .inf
telegram:
  enabled: false
"""))


def test_a_negative_monthly_ai_budget_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="monthly_budget_usd"):
        load_config(_write(tmp_path, """
ai:
  monthly_budget_usd: -50
telegram:
  enabled: false
"""))


def test_an_empty_model_name_is_refused(tmp_path):
    """An empty model name reaches the Messages API as a request naming no
    model — every call on that tier fails, not just the unusual ones."""
    with pytest.raises(ConfigError, match="model_fast"):
        load_config(_write(tmp_path, """
ai:
  model_fast: ''
telegram:
  enabled: false
"""))


def test_ai_checks_are_skipped_while_ai_is_disabled(tmp_path):
    """A disabled AI layer must not refuse to start over budget or model
    fields nobody is going to read."""
    cfg = load_config(_write(tmp_path, """
ai:
  enabled: false
  daily_budget_usd: -1
  model_fast: ''
telegram:
  enabled: false
"""))
    assert cfg.ai.enabled is False


def test_pool_max_below_pool_min_is_refused_not_left_for_asyncpg(tmp_path):
    """Confirmed on production: `pool_min: 20, pool_max: 2` reaches asyncpg's
    own pool constructor, which raises ValueError — every one of the daemons
    that opens a pool then exits 1 and restart-loops."""
    with pytest.raises(ConfigError, match="pool_max"):
        load_config(_write(tmp_path, """
database:
  pool_min: 20
  pool_max: 2
telegram:
  enabled: false
"""))


def test_zero_pool_min_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="pool_min"):
        load_config(_write(tmp_path, """
database:
  pool_min: 0
  pool_max: 5
telegram:
  enabled: false
"""))


def test_zero_statement_timeout_is_refused(tmp_path):
    """Zero disables Postgres's own statement_timeout — a single stuck query
    then holds a connection out of an already small pool forever."""
    with pytest.raises(ConfigError, match="statement_timeout_ms"):
        load_config(_write(tmp_path, """
database:
  statement_timeout_ms: 0
telegram:
  enabled: false
"""))


def test_an_unknown_timezone_is_refused(tmp_path):
    """`timezone: Mars/Olympus` reads as a plausible IANA name and is exactly
    the shape that must be caught at load, not three services later where
    util/tz.py degrades noisily per call instead of refusing to start."""
    with pytest.raises(ConfigError, match="timezone"):
        load_config(_write(tmp_path, """
timezone: Mars/Olympus
telegram:
  enabled: false
"""))


def test_an_unknown_telegram_timezone_is_also_refused(tmp_path):
    with pytest.raises(ConfigError, match="telegram.timezone"):
        load_config(_write(tmp_path, """
telegram:
  enabled: false
  timezone: Mars/Olympus
"""))


def test_a_whitespace_only_timezone_is_refused_not_a_crash(tmp_path):
    """S8 (round 2), confirmed with Python's own `zoneinfo` on this machine:
    `ZoneInfo("  ")` does not raise `ZoneInfoNotFoundError` or `ValueError`
    — it raises `PermissionError` trying to open a path built from the blank
    string, which the old `except (ZoneInfoNotFoundError, ValueError)` did
    not catch. `load_config` crashed with an unhandled exception instead of
    the clean `ConfigError` every other bad value here gets."""
    with pytest.raises(ConfigError, match="timezone"):
        load_config(_write(tmp_path, """
timezone: "  "
telegram:
  enabled: false
"""))


def test_a_timezone_padded_with_whitespace_still_loads(tmp_path):
    """The fix strips before validating — padding around a REAL zone name
    must not be refused, only whitespace-only collapsing to blank. The
    STORED value must be stripped too, not just the copy validation looked
    at: `util/tz.py:zone()` calls `ZoneInfo(cfg.timezone)` directly with
    whatever `load_config` left on the object, so a config-check that
    passes while the stored value still has padding would still fail at
    every actual window evaluation, silently degrading to the host zone."""
    cfg = load_config(_write(tmp_path, """
timezone: "  Europe/Bucharest  "
telegram:
  enabled: false
"""))
    assert cfg.timezone == "Europe/Bucharest", (
        f"cfg.timezone is {cfg.timezone!r} — the stored value still carries "
        f"whitespace, not just the string it was validated against")


def test_a_real_timezone_still_loads(tmp_path):
    cfg = load_config(_write(tmp_path, """
timezone: Europe/Bucharest
telegram:
  enabled: false
  timezone: America/New_York
"""))
    assert cfg.timezone == "Europe/Bucharest"
    assert cfg.telegram.timezone == "America/New_York"


def test_non_integer_chat_ids_are_refused(tmp_path):
    """Confirmed on production: `allowed_chat_ids: ['abc']` was accepted
    outright. A chat id compared against `update.effective_chat.id` (always
    an int) would then never match anything — the allowlist looks populated
    in config-check while rejecting every command."""
    with pytest.raises(ConfigError, match=r"allowed_chat_ids\[0\]"):
        load_config(_write(tmp_path, """
telegram:
  enabled: true
  allowed_chat_ids: ['abc']
"""))


def test_a_bool_disguised_as_a_chat_id_is_refused(tmp_path):
    """`bool` is a subclass of `int` in Python; YAML's `true`/`false` must
    not slip through a `list[int]` check that only asks `isinstance(x, int)`."""
    with pytest.raises(ConfigError, match=r"allowed_chat_ids\[0\]"):
        load_config(_write(tmp_path, """
telegram:
  enabled: true
  allowed_chat_ids: [true]
"""))


def test_a_non_string_entry_in_a_list_str_field_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=r"nginx_log_paths\[0\]"):
        load_config(_write(tmp_path, """
ingest:
  nginx_log_paths: [123]
telegram:
  enabled: false
"""))


# --- selfcheck.max_silence_min: per-installation ingest silence thresholds --
def test_selfcheck_silence_thresholds_load_as_a_typed_nested_section(tmp_path):
    """The section round-trips into `SelfcheckSilenceConfig`, not a plain dict
    — the shape `sentinel/selfcheck/checks.py` reads via `_silence_limit`."""
    from sentinel.config import SelfcheckSilenceConfig

    cfg = load_config(_write(tmp_path, """
selfcheck:
  max_silence_min:
    nginx: 1440
telegram:
  enabled: false
"""))
    assert isinstance(cfg.selfcheck.max_silence_min, SelfcheckSilenceConfig)
    assert cfg.selfcheck.max_silence_min.nginx == 1440
    # Untouched fields keep the shipped defaults — a partial override must not
    # silently zero out the sibling thresholds.
    assert cfg.selfcheck.max_silence_min.auditd == 60
    assert cfg.selfcheck.max_silence_min.default == 180


def test_selfcheck_section_absent_keeps_the_shipped_defaults(tmp_path):
    """Every host running today has no `selfcheck:` section at all — the
    default must be exactly what was previously hard-coded in checks.py."""
    cfg = load_config(_write(tmp_path, """
telegram:
  enabled: false
"""))
    assert cfg.selfcheck.max_silence_min.auditd == 60
    assert cfg.selfcheck.max_silence_min.nginx == 180
    assert cfg.selfcheck.max_silence_min.default == 180


def test_a_misspelled_key_under_selfcheck_is_refused_not_silently_ignored(tmp_path):
    """`ssh:` instead of a real field must stop the daemon at load — not sit
    in the file doing nothing, which is what a `dict[str, int]` shape would
    have allowed. This is the whole reason Change 2 uses a nested dataclass
    instead of a dict: `_build` raises on any key it does not know."""
    with pytest.raises(ConfigError, match="ssh"):
        load_config(_write(tmp_path, """
selfcheck:
  max_silence_min:
    ssh: 999
telegram:
  enabled: false
"""))


def test_a_quoted_pool_min_is_refused_not_silently_accepted(tmp_path):
    """The int-coercion gap was not specific to floats: a string int (`'5'`)
    passed through `_coerce` unchanged before this fix, for every int field,
    not only the ones this audit happened to measure."""
    with pytest.raises(ConfigError, match="pool_min"):
        load_config(_write(tmp_path, """
database:
  pool_min: '5'
telegram:
  enabled: false
"""))
