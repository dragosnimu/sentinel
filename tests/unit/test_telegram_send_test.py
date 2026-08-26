"""`sentinel telegram --send-test` must send one message and come back.

This is the last step of every install, and the message arriving on the
operator's phone is the only end-to-end proof there is that alerting works:
config loaded, secrets readable, egress open, token valid, chat id right.

What it did before this file existed: nothing defined `--send-test`, the CLI
dispatcher silently dropped flags it did not recognise, and the invocation
therefore parsed as plain `sentinel telegram` — which starts the long-polling
bot. On the production host that meant a SECOND poller against the token
`sentinel-telegram.service` was already using (Telegram answers one of the two
with 409 Conflict), the installer step never returned, and the operator killed
the deploy by hand. Killing it skipped `scripts/deploy.sh`'s cleanup of
/tmp/sentinel-deploy-*, which is why three copies of a file containing the bot
token and the Anthropic key sat at mode 644 for nine days.

So the failures these tests prevent, in operator terms:

  * an installer step that never returns, and a competing bot poller on a host
    that is already running one;
  * "Telegram test message sent" printed over a message Telegram refused —
    which is the same green line an operator would see if alerting worked, on
    the day it does not.

## What the fake asserts

`httpx.MockTransport` stands in for api.telegram.org, and it asserts the parts
of Telegram's contract this code depends on:

  * the request goes to POST https://api.telegram.org/bot<token>/sendMessage
    with a JSON body carrying `chat_id` and `text`;
  * a successful reply is `200 {"ok": true, "result": {"message_id": <int>}}`;
  * a refusal is a 4xx with `{"ok": false, "description": "..."}` — this is
    what a wrong chat id, a wrong token or a bot never started by the chat
    actually produce;
  * a network failure raises `httpx.ReadTimeout` from the transport.

The real httpx client is used, so the URL, the JSON encoding and the timeout
handling under test are the shipped ones — only the socket is fake.
"""

from __future__ import annotations

import json

import httpx
import pytest

from sentinel.config import Config, Secrets, TelegramConfig
from sentinel.services import telegram_service

# Short and obviously fake, on purpose. `tests/security/test_repo_is_sanitised.py`
# greps every tracked file for token-shaped strings, and a fixture that trips
# that grep costs whoever triages the finding the same hour a real leak would —
# they cannot tell the difference from the match.
TOKEN = "0:fixture-not-a-real-token"


def _cfg(chat_ids=(111, 222), enabled=True) -> Config:
    return Config(telegram=TelegramConfig(enabled=enabled,
                                          allowed_chat_ids=list(chat_ids)))


def _secrets(token: str | None = TOKEN) -> Secrets:
    return Secrets({"TELEGRAM_BOT_TOKEN": token} if token else {})


@pytest.fixture
def telegram_api(monkeypatch):
    """Route every httpx.AsyncClient through a fake api.telegram.org.

    Returns a recorder the test configures per chat id and then reads back.
    """

    class Api:
        def __init__(self) -> None:
            self.requests: list[dict] = []
            self.replies: dict[int, object] = {}   # chat_id -> reply or exception
            self.default = httpx.Response(
                200, json={"ok": True, "result": {"message_id": 7}})

        def handler(self, request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode("utf-8"))
            self.requests.append({"url": str(request.url),
                                  "method": request.method, "body": body})
            reply = self.replies.get(int(body["chat_id"]), self.default)
            if isinstance(reply, Exception):
                raise reply
            return reply

    api = Api()
    transport = httpx.MockTransport(api.handler)
    real_client = httpx.AsyncClient

    def factory(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return api


@pytest.fixture
def poller(monkeypatch):
    """Make starting the bot observable — and loud.

    Every test here that says "this must not start a poller" is worthless
    unless something proves the poller CAN be started from this code path.
    `test_plain_sentinel_telegram_still_starts_the_poller` is that proof, and
    it uses this same fixture.
    """
    started: list[str] = []

    class FakeApp:
        def run_polling(self, **kwargs):
            started.append("run_polling")

    def build_application(cfg, sec):
        started.append("build_application")
        return FakeApp()

    bot = pytest.importorskip("sentinel.telegram.bot")
    monkeypatch.setattr(bot, "build_application", build_application)
    monkeypatch.setattr(telegram_service, "setup_logging", lambda *a, **k: None)
    return started


# ---------------------------------------------------------------------------
# The daemon must still be reachable — otherwise the tests below prove nothing
# ---------------------------------------------------------------------------
def test_plain_sentinel_telegram_still_starts_the_poller(monkeypatch, poller):
    """systemd runs `sentinel telegram` with no flags. If this stopped starting
    the bot, the operator would have no alerting channel at all."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)

    assert telegram_service.main([]) == 0
    assert poller == ["build_application", "run_polling"]


# ---------------------------------------------------------------------------
# --send-test: one message, a verdict, and no daemon
# ---------------------------------------------------------------------------
def test_send_test_sends_once_and_never_starts_a_poller(
        monkeypatch, telegram_api, poller, capsys):
    """The installer hung here for a day and ran a second bot against the live
    token. A test send that can reach the polling path is that bug again."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)

    rc = telegram_service.main(["--send-test", "--message", "instalat"])

    assert rc == 0
    assert poller == [], "the test send reached the long-polling path"
    assert [r["body"]["chat_id"] for r in telegram_api.requests] == [111, 222]
    for req in telegram_api.requests:
        assert req["method"] == "POST"
        assert req["url"] == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        assert req["body"]["text"] == "instalat"
    out = capsys.readouterr().out
    assert "chat 111: delivered (message_id=7)" in out


def test_the_installer_message_is_not_parsed_as_markup(
        monkeypatch, telegram_api, poller):
    """install.sh interpolates `${DOMAIN:-<fara domeniu>}`. Sent with
    parse_mode=HTML, Telegram rejects that as an unclosed tag and the operator
    is told the alert channel is broken when only the message was."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)

    text = "Sentinel 1.0 instalat. Dashboard: https://<fara domeniu>"
    assert telegram_service.main(["--send-test", "--message", text]) == 0
    for req in telegram_api.requests:
        assert "parse_mode" not in req["body"]
        assert req["body"]["text"] == text


def test_a_refusal_from_telegram_is_never_reported_as_delivered(
        monkeypatch, telegram_api, poller, capsys):
    """A wrong chat id answers 400 while the process exits cleanly. Reporting
    that as sent is the install log saying alerting works on the day it does
    not — and nobody looks again until an incident is missed."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)
    telegram_api.replies[222] = httpx.Response(
        400, json={"ok": False, "description": "Bad Request: chat not found"})

    rc = telegram_service.main(["--send-test", "--message", "x"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "chat 222: FAILED" in out
    assert "chat not found" in out
    assert "1 of 2 chat(s) did not receive it" in out


def test_ok_without_a_message_id_is_not_delivery(
        monkeypatch, telegram_api, poller, capsys):
    """A 200 whose body we did not understand is an unknown, and an unknown
    reported as success is how a monitoring tool starts lying."""
    monkeypatch.setattr(telegram_service, "get_config", lambda: _cfg([111]))
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)
    telegram_api.replies[111] = httpx.Response(200, json={"ok": True, "result": {}})

    assert telegram_service.main(["--send-test"]) == 1
    assert "no message_id" in capsys.readouterr().out


def test_a_network_failure_is_a_failure_not_a_silence(
        monkeypatch, telegram_api, poller, capsys):
    """Egress blocked by the provider firewall is the most likely real cause of
    this step failing. It has to name itself, not hang and not pass."""
    monkeypatch.setattr(telegram_service, "get_config", lambda: _cfg([111]))
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)
    telegram_api.replies[111] = httpx.ReadTimeout("timed out")

    assert telegram_service.main(["--send-test"]) == 1
    out = capsys.readouterr().out
    assert "ReadTimeout" in out
    assert poller == []


@pytest.mark.parametrize("cfg,secrets,why", [
    (lambda: _cfg(enabled=False), _secrets, "disabled in config"),
    (lambda: _cfg(), lambda: _secrets(None), "no token"),
    (lambda: _cfg(chat_ids=()), _secrets, "no allowed chat ids"),
])
def test_not_configured_has_its_own_exit_code(monkeypatch, telegram_api, poller,
                                              cfg, secrets, why, capsys):
    """"Nothing was sent because Telegram is off" and "the send failed" are
    different facts. install.sh prints an informational line for the first and
    a warning for the second; collapsing them either alarms an operator who
    turned Telegram off, or hides a broken channel from one who did not."""
    monkeypatch.setattr(telegram_service, "get_config", cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", secrets)

    assert telegram_service.main(["--send-test"]) == 78, why
    assert telegram_api.requests == []
    assert poller == []


def test_message_without_send_test_is_refused(monkeypatch, telegram_api, poller):
    """`--message` alone would otherwise change nothing and fall through to
    starting the daemon — the same shape as the bug this file is about."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)

    assert telegram_service.main(["--message", "hello"]) == 64
    assert poller == []
    assert telegram_api.requests == []


def test_a_mistyped_flag_refuses_instead_of_starting_the_bot(
        monkeypatch, telegram_api, poller, capsys):
    """The whole class of defect in one test: a flag nothing parses must not be
    read as "no flags", because "no flags" here means "start the daemon"."""
    monkeypatch.setattr(telegram_service, "get_config", _cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)

    with pytest.raises(SystemExit) as exc:
        telegram_service.main(["--send-tset"])

    assert exc.value.code == 64
    assert poller == []
    assert telegram_api.requests == []
    assert "--send-tset" in capsys.readouterr().err


@pytest.mark.parametrize("reply,label", [
    (httpx.Response(200, json={"ok": True, "result": {"message_id": 7}}), "delivered"),
    (httpx.Response(400, json={"ok": False, "description": "Bad Request: chat not found"}),
     "refused"),
    (httpx.ReadTimeout("timed out"), "network failure"),
])
def test_the_printed_verdict_survives_a_c_locale(monkeypatch, telegram_api, poller,
                                                 capsys, reply, label):
    """The installer runs this over ssh, where the locale is whatever the
    session brought with it. Under LC_ALL=C, printing a single non-ASCII
    character raises UnicodeEncodeError: the operator gets a traceback and an
    exit code instead of the reason the channel is broken.

    This repository lost a day to one diacritic in a command alias. The
    verdict lines stay ASCII.
    """
    monkeypatch.setattr(telegram_service, "get_config", lambda: _cfg([111]))
    monkeypatch.setattr(telegram_service, "get_secrets", _secrets)
    telegram_api.replies[111] = reply

    telegram_service.main(["--send-test", "--message", "instalat"])

    printed = capsys.readouterr().out
    assert printed.strip(), f"no verdict printed for a {label}"
    printed.encode("ascii")  # raises if a non-ASCII character crept in
