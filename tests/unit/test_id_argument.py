"""Un id tastat de om, oprit înainte să ajungă la Postgres.

Șase comenzi citesc un id dintr-un argument și îl caută în bază. Fiecare avea
propria idee despre ce e un număr, scrise în trei zile diferite:
`isascii()+isdigit()+plafon`, `.isdecimal()`, și `.isdigit()` simplu. Toate trei
opresc `'²'` sau nu-l opresc; **niciuna nu oprea `9223372036854775808`**, care e
19 cifre ASCII, trece de `int()`, și e refuzat abia de asyncpg pe fir:

    DataError: value out of int64 range

Adică o excepție care iese din handler, „A apărut o eroare la procesarea
comenzii" pentru operator, și un traceback în journal — dintr-un argument de 19
caractere pe care îl poate trimite oricine are voie în chat. Coloanele sunt
`bigserial` (`findings`, `incidents`, `patch_plans`).

Testele de aici cer două lucruri, pe fiecare comandă: valoarea NU ajunge la
bază, și operatorul primește un răspuns, nu o eroare.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("telegram")

from sentinel.config import Config
from sentinel.db.repo import findings as findings_repo
from sentinel.db.repo import incidents as inc_repo
from sentinel.telegram import bot, views
from sentinel.util.ids import BIGINT_MAX, parse_id

CHAT_ID = 4242

#: Cea mai mică valoare pe care Postgres o refuză. 19 cifre ASCII: trece de
#: `isdigit()`, trece de `isdecimal()`, trece de `int()`.
PESTE_BIGINT = str(2**63)


def run(c):
    return asyncio.run(c)


# --- funcția în sine --------------------------------------------------------
@pytest.mark.parametrize("raw", [
    None, "", "   ", "abc", "-1", "0", "1.0", "1e3", "7a", "a7",
    "²",            # isdigit() True, int() ridică ValueError
    "₂",            # idem, cifră-index
    "٢",            # arabo-indic: int() îl parsează, dar nu e ce a scris omul
    "２",           # noqa: RUF001 - fullwidth: chiar asta se testeaza
    PESTE_BIGINT,   # 19 cifre ASCII, refuzat de asyncpg pe fir
    "9" * 25,
    "9" * 4301,     # peste plafonul de cifre al lui int() însuși
])
def test_ce_nu_e_un_id_nu_devine_un_id(raw):
    """Fiecare dintre astea a fost, undeva, o excepție în handler.

    `None` înseamnă „nu e un id" — apelantul are un singur lucru de spus
    operatorului, și nu trebuie să aleagă între cinci mesaje.
    """
    assert parse_id(raw) is None


@pytest.mark.parametrize("raw,val", [
    ("1", 1), ("7", 7), (" 42 ", 42), ("0042", 42),
    ("31118", 31118),                 # id real de pe gazdă
    (str(BIGINT_MAX), BIGINT_MAX),    # exact la margine, încă valid
])
def test_un_id_adevarat_trece_neatins(raw, val):
    """Marginea se verifică pe ambele părți: un plafon pus cu unu mai jos ar
    face inaccesibil un rând real, și nimeni n-ar observa până la el."""
    assert parse_id(raw) == val


def test_lungimea_se_verifica_inaintea_conversiei():
    """`int("9"*4301)` ridică `ValueError` — CPython refuză conversia.

    Dacă verificarea de lungime ar sta după conversie, funcția pusă să
    oprească valoarea absurdă ar fi chiar cea care aruncă.
    """
    assert parse_id("9" * 4301) is None  # nu ridică


def test_marginea_vine_din_apelant():
    """Pagina are altă lume decât o coloană: numărul de pagină nu ajunge
    nicăieri în bază, deci plafonul lui e cât poate avea tabela."""
    assert parse_id("1000", maximum=999) is None
    assert parse_id("999", maximum=999) == 999


# --- /vuln ------------------------------------------------------------------
class _Msg:
    def __init__(self):
        self.sent: list[str] = []

    async def reply_text(self, text, **kw):
        self.sent.append(text)


def _update():
    msg = _Msg()
    return SimpleNamespace(effective_chat=SimpleNamespace(id=CHAT_ID),
                           effective_message=msg, message=msg), msg


def _cfg() -> Config:
    cfg = Config()
    cfg.telegram.allowed_chat_ids = [CHAT_ID]
    return cfg


def _ctx(args: list[str]) -> Any:
    return SimpleNamespace(
        bot_data={"db": object(), "cfg": _cfg()}, args=args,
        bot=SimpleNamespace())


def _nu_ajunge_la_baza(monkeypatch, module, name):
    """Înlocuiește un apel de repo cu unul care refuză ca Postgres.

    Nu doar înregistrează: RIDICĂ, exact ca asyncpg, ca testul să pice în
    aceeași formă în care pică producția. Un ciot care doar numără apelurile ar
    trece dacă cineva ar prinde excepția și ar înghiți-o.
    """
    apeluri: list[int] = []

    async def _fals(db, value, *a, **k):
        apeluri.append(value)
        if not -2**63 <= value < 2**63:
            raise ValueError("value out of int64 range")  # ce face asyncpg
        return None

    monkeypatch.setattr(module, name, _fals)
    return apeluri


def test_vuln_cu_id_peste_int64_raspunde_nu_pica(monkeypatch):
    """`/vuln 9223372036854775808` — 19 cifre, acceptate de `.isdigit()`.

    Comanda veche căuta id-ul printr-o listă în memorie, deci valoarea nu
    ajungea niciodată la bază și răspunsul era „inexistentă". De când caută
    după cheia primară, aceeași tastare ar fi ieșit din handler cu `DataError`
    și operatorul ar fi primit eroarea generică.
    """
    apeluri = _nu_ajunge_la_baza(monkeypatch, findings_repo, "get_finding")
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx([PESTE_BIGINT])))
    assert apeluri == [], "id-ul a plecat spre bază"
    assert "Folosire" in msg.sent[0]


@pytest.mark.parametrize("arg", ["²", "₂", "٢", "9" * 4301, "-5", "0"])
def test_vuln_cu_argument_care_nu_e_id(monkeypatch, arg):
    """Toate astea ajungeau la `int()` sau la bază. Niciunul nu e un id."""
    apeluri = _nu_ajunge_la_baza(monkeypatch, findings_repo, "get_finding")
    upd, msg = _update()
    run(views.cmd_vuln(upd, _ctx([arg])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0]


# --- /planifica, /incident, /resolve, /patch --------------------------------
def test_planifica_cu_id_peste_int64_raspunde_nu_pica(monkeypatch):
    """Același argument, comanda de alături — cea care cheltuie un apel la model.

    Aici garda fusese deja reparată o dată, pentru `'²'`, cu un comentariu de
    nouă rânduri. Jumătatea de sus a intervalului n-a fost văzută atunci.
    """
    apeluri = _nu_ajunge_la_baza(monkeypatch, findings_repo, "get_finding")
    upd, msg = _update()
    run(bot.cmd_planifica(upd, _ctx([PESTE_BIGINT])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0]


def test_incident_cu_id_peste_int64_raspunde_nu_pica(monkeypatch):
    """`incidents.id` e tot `bigserial`, iar `/incident` citea cu `.isdigit()`."""
    apeluri = _nu_ajunge_la_baza(monkeypatch, inc_repo, "get_incident")
    upd, msg = _update()
    run(bot.cmd_incident(upd, _ctx([PESTE_BIGINT])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0]


def test_resolve_cu_id_peste_int64_raspunde_nu_pica(monkeypatch):
    """`/resolve` închide un incident; argumentul lui mergea direct în bază."""
    apeluri = _nu_ajunge_la_baza(monkeypatch, inc_repo, "get_incident")
    upd, msg = _update()
    run(bot.cmd_resolve(upd, _ctx([PESTE_BIGINT])))
    assert apeluri == []
    assert "Folosire" in msg.sent[0]


@pytest.mark.parametrize("arg", [PESTE_BIGINT, "0", "٢", "abc"])
def test_patch_cu_un_id_neinteles_o_spune(monkeypatch, arg):
    """`/patch <ceva ce nu e id>` nu are voie să răspundă cu lista de planuri.

    Măsurat pe handlerul real după prima reparație: `/patch 0` și `/patch ٢`
    răspundeau înainte „Plan inexistent.", iar trecute prin `parse_id` fără
    linia asta cădeau pe „🩹 Planuri în așteptare" — un răspuns plauzibil la o
    comandă pe care nimeni n-a dat-o. Operatorul care tastează un id de plan și
    primește o listă generică n-are din ce afla că argumentul lui n-a fost
    înțeles; asta e aceeași tăcere pe care o repară tot restul schimbării.

    `9223372036854775808` e cazul în care vechiul cod chiar pica; celelalte
    sunt cele în care răspundea ceva.
    """
    from sentinel.db.repo import patches as patch_repo

    apeluri = _nu_ajunge_la_baza(monkeypatch, patch_repo, "get_plan")

    async def _list_plans(db, **k):
        raise AssertionError("s-a listat in loc sa se spuna ca id-ul nu e id")

    monkeypatch.setattr(patch_repo, "list_plans", _list_plans)
    upd, msg = _update()
    run(bot.cmd_patches(upd, _ctx([arg])))
    assert apeluri == [], "id-ul a plecat spre bază"
    assert "Nu am înțeles id-ul" in msg.sent[0], msg.sent


def test_patches_fara_argument_ramane_lista(monkeypatch):
    """Cealaltă jumătate: `/patches` fără argument e chiar comanda de listare.

    Fără testul ăsta, o gardă scrisă cu un `not context.args` greșit ar
    transforma comanda de listă într-un mesaj de folosire, iar cele patru
    planuri de pe gazdă n-ar mai putea fi văzute deloc.
    """
    from sentinel.db.repo import patches as patch_repo

    async def _list_plans(db, **k):
        return []

    monkeypatch.setattr(patch_repo, "list_plans", _list_plans)
    upd, msg = _update()
    run(bot.cmd_patches(upd, _ctx([])))
    assert "Niciun plan" in msg.sent[0]


# --- pagina -----------------------------------------------------------------
@pytest.mark.parametrize("raw", ["²", "２", "9" * 4301, "-1", "0", "abc"])  # noqa: RUF001
def test_pagina_refuza_acelasi_fel_de_valori(raw):
    """Aceeași definiție, în panou: un parametru de URL nu are voie să producă
    500 pe pagina de vulnerabilități."""
    from sentinel.web.routers.findings import resolve_page

    page, warning = resolve_page(raw, 6)
    assert page == 1
    assert warning and "neînțeles" in warning


def test_pagina_pastreaza_cele_doua_mesaje_diferite():
    """„N-am înțeles" și „pagina aia nu există" rămân două răspunsuri.

    Amândouă sunt onorate cu prima pagină, dar din motive diferite, iar un
    singur mesaj pentru amândouă i-ar spune operatorului că a scris greșit
    când de fapt a cerut o pagină de după sfârșit.
    """
    from sentinel.web.routers.findings import resolve_page

    assert resolve_page("99", 6) == (6, "Pagina 99 nu există; ultima e 6.")
    assert resolve_page("3", 6) == (3, None)
