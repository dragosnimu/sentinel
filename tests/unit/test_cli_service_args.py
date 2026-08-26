"""A flag nobody parses must not be read as "run the default action".

`sentinel <service>` subcommands are registered with no arguments of their own,
deliberately, so argparse does not reject a service's flags before the service
sees them. The dispatcher then used `parse_known_args()` and assigned the
unknown half to `_extra` — which it discarded.

For a daemon that is the most destructive reading available. `sentinel telegram
--send-test --message "..."`, the last line of the installer, parsed as plain
`sentinel telegram` and started the long-polling bot: a second poller against
the token the live `sentinel-telegram.service` was already using, on a
production host, forever. The installer step printed neither of its two
branches because the command never returned.

The property fixed here and pinned by these tests:

  * whatever this dispatcher does not consume is HANDED to the service, not
    dropped;
  * a service refuses a flag it does not define, and starts nothing;
  * the flags services really do define (`web --create-admin`, `selfcheck
    --print`, `reconcile --reapply`, `health --rollup`) keep working — the
    mechanism exists for those and breaking them would take the dashboard's
    account management and the operator's hand-run checks with it.
"""

from __future__ import annotations

import importlib

import pytest

from sentinel import __main__ as cli

# Every service subcommand the dispatcher will route. Read from the shipped
# tuple, not copied: a service added without flag handling is exactly the gap
# this file exists to close.
SERVICES = cli.SERVICES


def test_the_service_list_is_not_empty():
    """A parametrised list that comes out empty is skipped in silence, and this
    repository has already shipped one of those. Nothing below is evidence
    unless this holds."""
    assert len(SERVICES) >= 10


# ---------------------------------------------------------------------------
# The dispatcher passes the leftovers on
# ---------------------------------------------------------------------------
def test_leftover_flags_reach_the_service(monkeypatch):
    """If they are dropped, `sentinel telegram --send-test` becomes `sentinel
    telegram`, which starts the bot. That is the production incident."""
    from sentinel.services import telegram_service

    seen: list[list[str]] = []
    monkeypatch.setattr(telegram_service, "main",
                        lambda argv: seen.append(list(argv)) or 0)
    monkeypatch.setattr("sys.argv",
                        ["sentinel", "telegram", "--send-test", "--message", "hi"])

    assert cli.main() == 0
    assert seen == [["--send-test", "--message", "hi"]]


def test_a_service_with_no_flags_is_still_started(monkeypatch):
    """systemd invokes every daemon with a bare subcommand. If passing the
    leftovers changed that, every unit on the host would fail to start."""
    from sentinel.services import detect_service

    seen: list[list[str]] = []
    monkeypatch.setattr(detect_service, "main",
                        lambda argv: seen.append(list(argv)) or 0)
    monkeypatch.setattr("sys.argv", ["sentinel", "detect"])

    assert cli.main() == 0
    assert seen == [[]]


# ---------------------------------------------------------------------------
# Every service refuses what it cannot act on
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", SERVICES)
def test_every_service_refuses_a_flag_it_does_not_define(name, monkeypatch, capsys):
    """One typo used to mean "start the daemon". On `telegram` that is a second
    poller on a live token; on `reconcile` it is a blocklist pass the operator
    did not ask for; on `web` it is a public dashboard instead of the account
    command they typed."""
    module = importlib.import_module(f"sentinel.services.{name}_service")

    with pytest.raises(SystemExit) as exc:
        module.main(["--nu-exista-steagul-asta"])

    assert exc.value.code == 64, f"{name} did not refuse an unknown flag"
    err = capsys.readouterr().err
    assert "--nu-exista-steagul-asta" in err, f"{name} did not name the flag"


# ---------------------------------------------------------------------------
# The flags that do exist still work
# ---------------------------------------------------------------------------
def _fake_web(monkeypatch):
    from sentinel.config import Config, Secrets
    from sentinel.services import web_service

    monkeypatch.setattr(web_service, "get_config", Config)
    monkeypatch.setattr(web_service, "get_secrets", lambda: Secrets({}))
    called: list[str] = []

    async def _list_users(cfg):
        called.append("list_users")
        return 0

    monkeypatch.setattr(web_service, "_list_users", _list_users)
    return called


def test_web_admin_flags_still_reach_the_service(monkeypatch):
    """`sentinel web --create-admin` and its siblings are the only way to
    manage accounts — the dashboard deliberately cannot. If the dispatcher
    stopped forwarding them, the documented recovery from a lost TOTP device
    would start the web server instead."""
    called = _fake_web(monkeypatch)
    monkeypatch.setattr("sys.argv", ["sentinel", "web", "--list-users"])

    assert cli.main() == 0
    assert called == ["list_users"]


def test_a_global_flag_before_the_subcommand_does_not_break_the_service(monkeypatch):
    """`sentinel --log-level DEBUG web --list-users` used to die with an
    argparse error: the service sliced sys.argv[2:] and got "DEBUG web".
    Debugging a service by raising its log level should not be the thing that
    stops it running."""
    called = _fake_web(monkeypatch)
    monkeypatch.setattr("sys.argv",
                        ["sentinel", "--log-level", "DEBUG", "web", "--list-users"])

    assert cli.main() == 0
    assert called == ["list_users"]


class _Parsed(Exception):
    """Carries the namespace the shipped parser produced, and stops main there."""

    def __init__(self, namespace):
        self.namespace = namespace


@pytest.mark.parametrize("name,argv,attr", [
    ("selfcheck", ["--print"], "print_all"),
    ("selfcheck", ["--quiet"], "quiet"),
    ("reconcile", ["--reapply"], "reapply"),
    ("health", ["--rollup"], "rollup"),
    ("health", ["--probe-only"], "probe_only"),
    ("telegram", ["--send-test"], "send_test"),
    ("web", ["--create-admin"], "create_admin"),
    ("web", ["--enroll-totp"], "enroll_totp"),
])
def test_documented_service_flags_are_really_parsed(name, argv, attr, monkeypatch):
    """docs/OPERARE.md, docs/DEPLOYMENT.md and docs/TESTARE.md tell the
    operator to run these. A documented flag that quietly does nothing is how
    `--send-test` became a comment in the CLI and a hang on the host.

    The real parser of the real service is exercised: the spy calls the shipped
    `parse_service_args`, keeps what it returned, and raises so the daemon or
    the account command underneath never starts. The assertion is on the value
    the service will branch on, not on the flag's name appearing somewhere.
    """
    module = importlib.import_module(f"sentinel.services.{name}_service")
    real = module.parse_service_args

    def spy(parser, passed):
        raise _Parsed(real(parser, passed))

    monkeypatch.setattr(module, "parse_service_args", spy)

    with pytest.raises(_Parsed) as exc:
        module.main(argv)

    assert getattr(exc.value.namespace, attr) is True, \
        f"{name} {argv[0]} parsed, but not into {attr}"


# ---------------------------------------------------------------------------
# The same rule for the commands the dispatcher handles itself
# ---------------------------------------------------------------------------
def test_a_mistyped_migrate_flag_does_not_apply_migrations(monkeypatch):
    """`--dry-runn` used to be dropped, and the operator watching for a preview
    got a real migration against production instead."""
    from sentinel.db import migrate as migrate_mod

    def explode(**kwargs):
        raise AssertionError("migrations ran on a mistyped flag")

    monkeypatch.setattr(migrate_mod, "run_migrations", explode)
    monkeypatch.setattr(cli, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr("sys.argv", ["sentinel", "migrate", "--dry-runn"])

    assert cli.main() == 64


def test_migrate_still_runs_when_the_flag_is_right(monkeypatch):
    """Proof that the test above is not passing because migrations became
    unreachable."""
    from sentinel.db import migrate as migrate_mod

    seen: list[bool] = []
    monkeypatch.setattr(migrate_mod, "run_migrations",
                        lambda dry_run: seen.append(dry_run) or 0)
    monkeypatch.setattr(cli, "setup_logging", lambda *a, **k: None)
    monkeypatch.setattr("sys.argv", ["sentinel", "migrate", "--dry-run"])

    assert cli.main() == 0
    assert seen == [True]
