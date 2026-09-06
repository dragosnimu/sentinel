"""Autorizarea Telegram verifica CHAT-ul, niciodata expeditorul.

Intr-un chat privat asta nu conteaza, fiindca `chat.id` e chiar id-ul
persoanei. Intr-un GRUP inseamna ca oricine e membru mosteneste rolul
grupului — masurat pe 5 septembrie 2026: doua instante Sentinel, aceeasi
gazduire de alerte, grup configurat drept `owner_chat_id` pe amandoua, iar pe
gazda de productie `auto_block` e activ. Adaugarea unei singure persoane in
grupul de alerte ii da drepturi de owner pe DOUA servere deodata, inclusiv
butonul care goleste blocklistul.

Testele astea verifica `telegram.allowed_user_ids`: o lista optionala de
utilizatori Telegram, aplicata IN PLUS fata de verificarea de chat, doar cand
chatul nu e privat. Goala (implicit), comportamentul e neschimbat — o
instalare existenta nu pierde nimic la actualizare.

Fiecare test isi numeste in docstring esecul pe care il previne. Falsificate
manual: revenire temporara la vechiul `_authorized` (doar `chat.id in
allowed_chat_ids`) si la vechiul `on_flush_callback` (doar `_can_act`, fara
`_authorized`) — vezi raportul agentului pentru numarul de teste picate la
fiecare revenire.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("telegram")

from sentinel.telegram import bot  # noqa: E402

# Valori inventate, nu ale unui chat sau utilizator real — depozitul e public.
# `-100...` e forma reala a unui id de supergrup Telegram, dar cifrele de aici
# nu corespund niciunui grup existent.
GROUP_CHAT_ID = -1009999999999
CHANNEL_CHAT_ID = -1008888888888
PRIVATE_CHAT_ID = 700000001
MEMBER_USER_ID = 700000002       # in allowed_user_ids
OUTSIDER_USER_ID = 700000003     # membru al grupului, NU in allowed_user_ids


class _Chat:
    def __init__(self, id_: int, type_: str) -> None:
        self.id = id_
        self.type = type_


class _User:
    def __init__(self, id_: int) -> None:
        self.id = id_


def _cfg(*, allowed_chat_ids, allowed_user_ids=None, owner_chat_id=None,
         operator_chat_ids=None):
    from types import SimpleNamespace
    kwargs = dict(allowed_chat_ids=allowed_chat_ids)
    if allowed_user_ids is not None:
        kwargs["allowed_user_ids"] = allowed_user_ids
    kwargs["owner_chat_id"] = owner_chat_id
    kwargs["operator_chat_ids"] = operator_chat_ids or []
    return SimpleNamespace(telegram=SimpleNamespace(**kwargs))


def _update(chat, user):
    from types import SimpleNamespace
    return SimpleNamespace(effective_chat=chat, effective_user=user)


# --- comportamentul de baza --------------------------------------------------
def test_group_member_outside_the_list_is_refused_though_the_group_is_allowed():
    """Previne exact incidentul din 5 septembrie 2026: un membru al grupului
    care NU e pe lista `allowed_user_ids` nu trebuie sa treaca doar fiindca
    grupul e in `allowed_chat_ids`."""
    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID])
    update = _update(_Chat(GROUP_CHAT_ID, "group"), _User(OUTSIDER_USER_ID))
    assert bot._authorized(cfg, update) is False


def test_group_member_on_the_list_is_authorized():
    """Contra-proba testului de mai sus: lista nu trebuie sa refuze pe toata
    lumea, doar pe cine nu e pe ea."""
    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID])
    update = _update(_Chat(GROUP_CHAT_ID, "group"), _User(MEMBER_USER_ID))
    assert bot._authorized(cfg, update) is True


def test_supergroup_is_covered_the_same_as_a_plain_group():
    """Telegram converteste grupurile in supergrupuri automat (membri multi,
    grup facut public); tipul `supergroup` nu are voie sa scape verificarii."""
    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID])
    update = _update(_Chat(GROUP_CHAT_ID, "supergroup"), _User(OUTSIDER_USER_ID))
    assert bot._authorized(cfg, update) is False


# --- nu strica o instalare existenta -----------------------------------------
def test_group_with_no_user_list_configured_keeps_the_old_behaviour():
    """O instalare care doar a actualizat codul, fara sa completeze
    `allowed_user_ids`, nu trebuie sa piarda acces: fara lista, verificarea de
    chat ramane singura, exact ca inainte de 5 septembrie 2026."""
    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[])
    update = _update(_Chat(GROUP_CHAT_ID, "group"), _User(OUTSIDER_USER_ID))
    assert bot._authorized(cfg, update) is True


def test_a_config_object_without_the_field_at_all_keeps_the_old_behaviour():
    """`allowed_user_ids` e un camp nou. Un obiect de configurare construit
    inainte de el (cazul testelor existente in acest depozit, care nu-l au)
    nu trebuie sa faca `_authorized` sa arunce, si nu trebuie sa refuze pe
    nimeni care trecea inainte doar de verificarea de chat."""
    from types import SimpleNamespace
    cfg = SimpleNamespace(telegram=SimpleNamespace(allowed_chat_ids=[GROUP_CHAT_ID]))
    update = _update(_Chat(GROUP_CHAT_ID, "group"), _User(OUTSIDER_USER_ID))
    assert bot._authorized(cfg, update) is True


def test_private_chat_ignores_the_user_list_even_if_one_is_configured():
    """Un chat privat leaga deja chat.id de persoana. Daca operatorul
    configureaza `allowed_user_ids` pentru grup si uita sa-si adauge propriul
    id privat acolo, comanda /mute din chatul lui personal nu are voie sa
    inceapa sa-l refuze — asta ar fi exact genul de auto-blocare pe care
    regula 'nu strica o instalare care functiona' o interzice."""
    cfg = _cfg(allowed_chat_ids=[PRIVATE_CHAT_ID],
               allowed_user_ids=[MEMBER_USER_ID])  # NU include PRIVATE_CHAT_ID
    update = _update(_Chat(PRIVATE_CHAT_ID, "private"), _User(PRIVATE_CHAT_ID))
    assert bot._authorized(cfg, update) is True


# --- expeditor nedefinit ------------------------------------------------------
def test_channel_post_with_no_sender_is_refused_when_the_list_is_configured():
    """`update.effective_user` e absent la o postare de canal — Telegram nu
    da niciodata autorul unei postari de canal catre bot, doar canalul ca
    `sender_chat`. Cand `allowed_user_ids` e configurat, o actiune fara nimeni
    de numit e refuzata, nu implicit acceptata."""
    cfg = _cfg(allowed_chat_ids=[CHANNEL_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID])
    update = _update(_Chat(CHANNEL_CHAT_ID, "channel"), None)
    assert bot._authorized(cfg, update) is False


def test_channel_post_with_no_sender_is_still_authorized_without_a_configured_list():
    """Contra-proba: fara `allowed_user_ids`, lipsa expeditorului nu conteaza
    — comportamentul vechi (doar chatul) ramane neschimbat pentru orice tip
    de chat, nu doar pentru grupuri."""
    cfg = _cfg(allowed_chat_ids=[CHANNEL_CHAT_ID], allowed_user_ids=[])
    update = _update(_Chat(CHANNEL_CHAT_ID, "channel"), None)
    assert bot._authorized(cfg, update) is True


# --- fiecare tip de update, la fel ------------------------------------------
# `_authorized` citeste doar `update.effective_chat` si `update.effective_user`
# — cele doua proprietati pe care python-telegram-bot le completeaza identic
# pentru ORICE tip de update. Testele de mai jos fixeaza exact asta: forma pe
# care o citeste verificarea e aceeasi indiferent daca update-ul real a fost
# un mesaj nou, unul editat, un callback de buton sau o schimbare de
# apartenenta — deci un handler nou, cablat pe oricare din ele, mosteneste
# aceeasi protectie fara sa scrie nimic in plus. Docs/TELEGRAM.md §2 numeste
# explicit `message`, `callback_query`, `edited_message`, `my_chat_member`.
@pytest.mark.parametrize("update_kind", [
    "message", "callback_query", "edited_message", "my_chat_member",
])
def test_the_sender_check_applies_the_same_regardless_of_update_kind(update_kind):
    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID])
    chat = _Chat(GROUP_CHAT_ID, "group")
    # Refuzat pentru un membru care nu e pe lista...
    assert bot._authorized(cfg, _update(chat, _User(OUTSIDER_USER_ID))) is False, update_kind
    # ...si permis pentru unul care e, indiferent de eticheta tipului de mai
    # sus (nefolosita in verificare, exact ca in productie).
    assert bot._authorized(cfg, _update(chat, _User(MEMBER_USER_ID))) is True, update_kind


# --- panic/flush: singurul buton care ocolea verificarea de chat ------------
class _StubQuery:
    def __init__(self, chat_id: int) -> None:
        self.message = None
        self._chat_id = chat_id
        self.edits: list[str] = []
        self.answered = False

    async def answer(self, *_a, **_kw):
        self.answered = True

    async def edit_message_text(self, text, **_kw):
        self.edits.append(text)


def _flush_context(cfg, *, db=None):
    from types import SimpleNamespace
    return SimpleNamespace(bot_data={"cfg": cfg, "db": db})


def test_flush_refuses_a_group_member_outside_the_list(monkeypatch):
    """`on_flush_callback` verifica DOAR `_can_act` inainte de aceasta
    reparatie — `_can_act` se uita numai la chat_id, nu la expeditor, deci
    PANIC/golirea blocklistului ramanea singurul buton pe care un membru
    neautorizat al grupului tot il putea apasa dupa ce restul fusesera
    inchise. Testul verifica efectul: `actions.flush` nu trebuie chemat."""
    from types import SimpleNamespace

    from sentinel.telegram import bot as bot_mod

    async def _boom(*_a, **_kw):
        raise AssertionError("actions.flush nu trebuia chemat pentru un expeditor refuzat")

    monkeypatch.setattr(bot_mod.actions, "flush", _boom)

    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID],
               owner_chat_id=GROUP_CHAT_ID)
    query = _StubQuery(GROUP_CHAT_ID)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=_Chat(GROUP_CHAT_ID, "group"),
                             effective_user=_User(OUTSIDER_USER_ID))
    context = _flush_context(cfg, db=SimpleNamespace())

    asyncio.run(bot_mod.on_flush_callback(update, context))

    assert query.edits == ["Neautorizat."]


def test_flush_still_works_for_a_listed_owner_in_the_group(monkeypatch):
    """Contra-proba: reparatia nu are voie sa strice PANIC-ul pentru cine
    chiar are dreptul — un owner listat, in grupul owner, tot goleste
    blocklistul."""
    from types import SimpleNamespace

    from sentinel.telegram import bot as bot_mod

    called = {}

    async def _flush(db, *, by, reason):
        called["by"] = by
        return {}

    monkeypatch.setattr(bot_mod.actions, "flush", _flush)

    cfg = _cfg(allowed_chat_ids=[GROUP_CHAT_ID], allowed_user_ids=[MEMBER_USER_ID],
               owner_chat_id=GROUP_CHAT_ID)
    query = _StubQuery(GROUP_CHAT_ID)
    update = SimpleNamespace(callback_query=query,
                             effective_chat=_Chat(GROUP_CHAT_ID, "group"),
                             effective_user=_User(MEMBER_USER_ID))
    context = _flush_context(cfg, db=SimpleNamespace())

    asyncio.run(bot_mod.on_flush_callback(update, context))

    assert query.edits == ["🚨 Blocklist golit."]
    assert called["by"] == f"telegram:{GROUP_CHAT_ID}"
