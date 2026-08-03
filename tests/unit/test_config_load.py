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
