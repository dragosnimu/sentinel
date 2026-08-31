"""`cmd_intreaba` din `sentinel/telegram/bot.py` — cablarea comenzii, nu
catalogul (acela e verificat în `test_ai_ask.py`).

Ce previn testele astea: o comandă care cheamă modelul de DOUĂ ori la fiecare
apăsare, fără verificare de plafon per chat; un răspuns care se preface că a
mers când cheia API lipsește; și un răspuns HTML care lasă neescapat ceva ce
vine din catalog sau din model.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("telegram")

from sentinel.ai import ask as ask_mod  # noqa: E402
from sentinel.config import Config  # noqa: E402
from sentinel.db.repo import ask_log as ask_log_repo  # noqa: E402
from sentinel.telegram import bot  # noqa: E402

CHAT_ID = 1234567890  # substituent — vezi nota din test_telegram_errors.py


def run(c):
    return asyncio.run(c)


class _Msg:
    def __init__(self):
        self.sent: list[tuple[str, dict]] = []

    async def reply_text(self, text, **kw):
        self.sent.append((text, kw))


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                           effective_message=msg, message=msg), msg


def _ctx(args=None, db=None, cfg=None):
    return SimpleNamespace(
        bot_data={"db": db or object(), "cfg": cfg or Config()},
        args=args or [])


def test_fara_intrebare_arata_folosirea_si_catalogul(monkeypatch):
    """Nimic nu trebuie să coste bani doar pentru că operatorul a scris
    `/intreaba` fără nimic după — nici bugetul, nici plafonul de rată."""
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: (_ for _ in ()).throw(AssertionError("nu trebuia citită cheia")))
    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=[])))

    assert len(msg.sent) == 1
    text, kw = msg.sent[0]
    assert "Folosire" in text
    assert "top_atacatori" in text  # o cheie reală din catalog, ca dovadă că lista chiar vine din el


def test_fara_cheie_api_spune_limpede_ca_lipseste(monkeypatch):
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: None))
    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=["ce", "servicii", "sunt", "picate?"])))

    assert len(msg.sent) == 1
    assert "cheie" in msg.sent[0][0].lower()


def test_ai_dezactivat_nu_ajunge_la_plafon_sau_la_model(monkeypatch):
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))

    async def _boom(*a, **kw):
        raise AssertionError("nu trebuia chemat modelul cu AI dezactivat")

    monkeypatch.setattr(ask_mod, "answer_question", _boom)

    cfg = Config()
    cfg.ai.enabled = False
    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=["stare"], cfg=cfg)))

    assert "dezactivat" in msg.sent[0][0].lower()


def test_plafonul_de_rata_opreste_comanda_inainte_de_orice_apel(monkeypatch):
    """Fără asta, o comandă apăsată în buclă ar multiplica costul de DOUĂ ori
    mai repede decât orice altă comandă din bot (două apeluri către model per
    întrebare)."""
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))

    async def _count_at_limit(db, chat_id):
        return cfg.ai.ask_rate_limit_per_hour  # exact la plafon

    async def _boom_record(db, chat_id):
        raise AssertionError("nu trebuia să scrie o încercare peste plafon")

    async def _boom_answer(*a, **kw):
        raise AssertionError("nu trebuia chemat modelul peste plafon")

    monkeypatch.setattr(ask_log_repo, "count_last_hour", _count_at_limit)
    monkeypatch.setattr(ask_log_repo, "record", _boom_record)
    monkeypatch.setattr(ask_mod, "answer_question", _boom_answer)

    cfg = Config()
    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=["stare"], cfg=cfg)))

    assert "limit" in msg.sent[0][0].lower()


def test_o_cerere_acceptata_scrie_in_jurnal_inainte_de_apel_si_arata_baza(monkeypatch):
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))

    order: list[str] = []

    async def _count_zero(db, chat_id):
        return 0

    async def _record(db, chat_id):
        order.append("record")
        assert chat_id == CHAT_ID

    async def _answer(db, cfg, api_key, question):
        order.append("answer")
        assert api_key == "sk-test"
        assert question == "cate servicii sunt picate?"
        return ask_mod.AskResult(ok=True, ai_formulated=True,
                                 based_on="servicii_picate()",
                                 text="Niciun serviciu picat acum.")

    monkeypatch.setattr(ask_log_repo, "count_last_hour", _count_zero)
    monkeypatch.setattr(ask_log_repo, "record", _record)
    monkeypatch.setattr(ask_mod, "answer_question", _answer)

    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=["cate", "servicii", "sunt", "picate?"])))

    assert order == ["record", "answer"], "plafonul trebuie scris ÎNAINTE de apelul către model"
    text = msg.sent[0][0]
    assert "Niciun serviciu picat acum." in text
    assert "servicii_picate()" in text  # "de unde știu asta"


def test_raspunsul_ai_e_escapat_pentru_html(monkeypatch):
    """Textul formulat de model ajunge cu parse_mode=HTML; dacă n-ar fi escapat,
    un `<script>` sau chiar `<` accidental ar rupe mesajul sau ar injecta markup."""
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda: SimpleNamespace(get=lambda k, d=None: "sk-test"))

    async def _count_zero(db, chat_id):
        return 0

    async def _record(db, chat_id):
        return None

    async def _answer(db, cfg, api_key, question):
        return ask_mod.AskResult(ok=True, ai_formulated=True, based_on="top_atacatori(limita=5)",
                                 text="<script>alert(1)</script>")

    monkeypatch.setattr(ask_log_repo, "count_last_hour", _count_zero)
    monkeypatch.setattr(ask_log_repo, "record", _record)
    monkeypatch.setattr(ask_mod, "answer_question", _answer)

    update, msg = _update()
    run(bot.cmd_intreaba(update, _ctx(args=["cine", "ataca?"])))

    text = msg.sent[0][0]
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
