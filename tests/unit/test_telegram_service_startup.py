"""`sentinel telegram` (fără `--send-test`) trebuie să refuze curat, nu să
crape, când lipsește un secret de care are nevoie.

Fără verificarea adăugată pentru `TELEGRAM_CALLBACK_HMAC_KEY`,
`build_application` ar ridica `SecretMissingError` NEPRINS, direct prin
`main()` — un traceback în journald, în loc de aceeași linie de eroare
distinctă, cu cod de ieșire 78, pe care fișierul ăsta o folosește deja
pentru `TELEGRAM_BOT_TOKEN` lipsă sau `allowed_chat_ids` gol. Niciunul din
cele trei ziduri de gardă n-avea un test înainte de ăsta.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.services import telegram_service  # noqa: E402


def _cfg(enabled=True, chat_ids=None):
    return SimpleNamespace(telegram=SimpleNamespace(
        enabled=enabled, allowed_chat_ids=chat_ids if chat_ids is not None else [123]))


class _Secrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key, default=None):
        return self._values.get(key, default)


def _run_main(monkeypatch, cfg, secrets_values):
    monkeypatch.setattr(telegram_service, "get_config", lambda: cfg)
    monkeypatch.setattr(telegram_service, "get_secrets", lambda: _Secrets(secrets_values))
    monkeypatch.setattr(telegram_service, "setup_logging", lambda *a, **kw: None)

    def _boom(*_a, **_kw):
        raise AssertionError("build_application nu trebuia chemat")

    # Import-ul lui build_application se face LOCAL în main(), din
    # `sentinel.telegram.bot` — se monkeypatch-uiește la sursă.
    from sentinel.telegram import bot as bot_mod
    monkeypatch.setattr(bot_mod, "build_application", _boom)

    return telegram_service.main([])


def test_missing_hmac_key_refuses_before_building_the_application(monkeypatch):
    code = _run_main(monkeypatch, _cfg(), {"TELEGRAM_BOT_TOKEN": "0:test"})
    assert code == 78


def test_missing_bot_token_refuses_before_building_the_application(monkeypatch):
    code = _run_main(monkeypatch, _cfg(),
                     {"TELEGRAM_CALLBACK_HMAC_KEY": "deadbeef"})
    assert code == 78


def test_empty_allowed_chat_ids_refuses_before_building_the_application(monkeypatch):
    code = _run_main(monkeypatch, _cfg(chat_ids=[]),
                     {"TELEGRAM_BOT_TOKEN": "0:test",
                      "TELEGRAM_CALLBACK_HMAC_KEY": "deadbeef"})
    assert code == 78


def test_disabled_telegram_returns_ok_without_touching_secrets(monkeypatch):
    code = _run_main(monkeypatch, _cfg(enabled=False), {})
    assert code == 0
