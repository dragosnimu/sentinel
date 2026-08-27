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
        "@@NGINX_MODE@@": "dedicated",
        "@@PUBLIC_PORT@@": "8443",
        "@@IFACE@@": "eth0",
        "@@BPF_FILTER@@": "",
        "@@SURICATA_ENABLED@@": "true",
        "@@AUDITD_ENABLED@@": "true",
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
