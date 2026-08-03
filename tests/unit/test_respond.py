"""P5 unit tests: the never-block precheck and TTL parsing (pure logic).

The executor round-trip and nftables state are verified on the real host during
deploy; here we test the client-side guard rails.
"""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.1",
                                "172.16.5.5", "169.254.1.1", "224.0.0.1", "notanip"])
def test_validate_target_refuses_unsafe(ip):
    from sentinel.respond.actions import BlockRefused, _validate_target

    with pytest.raises(BlockRefused):
        _validate_target(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"])
def test_validate_target_accepts_public(ip):
    from sentinel.respond.actions import _validate_target

    _validate_target(ip)  # must not raise


def test_ttl_parsing():
    from sentinel.telegram.bot_ttl import parse_ttl  # thin shim; see below

    assert parse_ttl(None) == 86400          # default, never permanent by accident
    assert parse_ttl("1h") == 3600
    assert parse_ttl("30m") == 1800
    assert parse_ttl("3600") == 3600
    assert parse_ttl("perm") is None
    assert parse_ttl("garbage") == 86400     # unparseable falls back to the default


def test_operator_allowlist_parses_both_yaml_styles(tmp_path):
    """The executor's stdlib parser must read the admin IP whether the config
    uses the installer's inline list or a hand-edited block list. A missed entry
    here is a lockout risk: the executor would block an address meant to be safe.
    """
    from executor.sentinel_executor import _operator_allowlist

    inline = tmp_path / "inline.yaml"
    inline.write_text('response:\n  extra_allowlist: ["198.51.100.25", "203.0.113.0/24"]\n', encoding="utf-8")
    assert _operator_allowlist(str(inline)) == ["198.51.100.25", "203.0.113.0/24"]

    block = tmp_path / "block.yaml"
    block.write_text(
        'response:\n  extra_allowlist:\n    - "198.51.100.25"\n    - 10.9.8.0/24\n  next: 1\n',
        encoding="utf-8",
    )
    assert _operator_allowlist(str(block)) == ["198.51.100.25", "10.9.8.0/24"]

    empty = tmp_path / "empty.yaml"
    empty.write_text("response:\n  extra_allowlist: []\n", encoding="utf-8")
    assert _operator_allowlist(str(empty)) == []
