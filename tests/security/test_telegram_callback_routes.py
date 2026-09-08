"""Fiecare buton emis trebuie să aibă un handler care îl rutează.

`bot.py` avea o ramură întreagă pentru `nteu:` — „Nu sunt eu", butonul de pe
FIECARE alertă de logare never-muted — dar `CallbackQueryHandler` era
înregistrat cu `pattern=r"^(blk:|unblk:|cancel$)"`, care nu-l include.
python-telegram-bot pur și simplu nu livra niciodată update-ul acelei ramuri:
tapul rămânea fără niciun efect, fără nicio eroare de nicăieri — cel mai greu
fel de bug de observat, fiindcă nu lasă nicio urmă.

Testul de aici NU e o listă scrisă de mână cu prefixele așteptate — o listă
de mână ar fi picat exact în fața bug-ului de mai sus, fiindcă cineva ar fi
trebuit să-și amintească să adauge `nteu:` și în listă, nu doar în cod.
`_emitted_prefixes()` citește din AST fiecare loc unde codul chiar
construiește un `callback_data`, iar `_registered_patterns()` construiește
APLICAȚIA REALĂ și citește tiparele cu care a înregistrat-o — exact ce ar
primi Telegram. Verificarea e că cele două mulțimi se acoperă, nu că
amândouă spun ce credea cineva că spun.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

pytest.importorskip("telegram")

REPO = Path(__file__).resolve().parents[2]
BOT_PY = REPO / "sentinel" / "telegram" / "bot.py"
PATCH_FLOW_PY = REPO / "sentinel" / "telegram" / "patch_flow.py"
LOGINS_PY = REPO / "sentinel" / "detect" / "logins.py"

#: Marcaj pentru un producător care nu se poate citi static — un al doilea
#: producător de genul ăsta ar trebui developat manual, nu presupus corect.
_DYNAMIC = "<construit dinamic>"


#: O valoare CITITĂ dintr-o structură de date (`b["data"]`, o variabilă) —
#: nu o construiește acest loc din cod, doar o transportă mai departe. Cine
#: a scris valoarea (alt `callback_data=`/`"data":` găsit tot de extractorul
#: ăsta) e producătorul real; a o număra și aici ar da un fals „prefix
#: nedescifrabil" pentru fiecare simplă transmitere, cum e
#: `_kb_from_row`, care doar redă în tastatură ce a scris deja `logins.py`.
_PASS_THROUGH = object()


def _literal_prefix(node: ast.AST):
    """Partea din față, până la primul ':', a unui `callback_data`.

    `"cancel"` rămâne `"cancel"` (nu conține ':'). `f"nteu:{session_id}"` sau
    `f"pdry:{row.id}"` dau `"nteu"`/`"pdry"` — segmentul literal de dinaintea
    primei interpolări. `callback_sign.sign_ip_action("blk", ...)` dă
    `"blk"` — primul argument pozițional, care e literalul cu care
    `on_callback` verifică prefixul.

    `callback_sign.sign_session_action(hmac_key, session_id)` n-are niciun
    argument literal de citit — prefixul „nteu" e scris în INTERIORUL
    funcției (vezi `callback_sign.py`), nu la locul apelului, spre deosebire
    de `sign_ip_action`. Recunoscut după NUME, nu citit dinamic: orice apel
    al funcției ăsteia produce `nteu:...`, prin construcție.

    Întoarce `_PASS_THROUGH` pentru un simplu citit din altă structură
    (`b["data"]`, o variabilă) — nu e un loc care INVENTEAZĂ un prefix nou.
    Întoarce `None` pentru orice altă formă pe care n-o recunoaște — aia
    chiar trebuie semnalată, nu tăcută.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.split(":", 1)[0]
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.split(":", 1)[0]
        return None  # interpolare chiar la început — nimic literal de citit
    if isinstance(node, ast.Call):
        func = node.func
        name = (func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute) else None)
        if name == "sign_ip_action" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return first_arg.value
        if name == "sign_session_action":
            return "nteu"
        return None
    if isinstance(node, (ast.Subscript, ast.Name, ast.Attribute)):
        return _PASS_THROUGH
    return None


def _emitted_prefixes(path: Path) -> set[str]:
    """Fiecare prefix de `callback_data` construit în `path`.

    Două forme de emitere, fiindcă ambele apar în depozit: argumentul numit
    `callback_data=` al unui `InlineKeyboardButton`, și cheia `"data"` dintr-un
    dicționar de buton scris pentru coloana `notifications.buttons`
    (`sentinel/detect/logins.py::_buttons`).
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        value = None
        if isinstance(node, ast.keyword) and node.arg == "callback_data":
            value = node.value
        elif isinstance(node, ast.Dict):
            # Forma unui buton, `{"text": ..., "data": ...}` — NU orice
            # dicționar cu o cheie `"data"`: `_guard_callback` loghează
            # `extra={"data": query.data, ...}`, care n-are nimic de-a face
            # cu construirea unui buton nou și ar da un fals „nedescifrabil".
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if {"text", "data"} <= keys:
                for key, val in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == "data":
                        value = val
        if value is None:
            continue
        prefix = _literal_prefix(value)
        if prefix is _PASS_THROUGH:
            continue
        found.add(prefix if prefix is not None else _DYNAMIC)
    return found


def _fake_secrets():
    """La fel ca în `test_telegram_command_names.py`: `build_application` nu
    se conectează la nimic la construire, doar înregistrează handlere."""
    from types import SimpleNamespace
    return SimpleNamespace(require=lambda k: "0:test",
                           has=lambda k: True, get=lambda k, d=None: None)


def _registered_callback_patterns():
    """Tiparele REALE cu care aplicația a fost construită — nu presupuse, ci
    citite de pe `CallbackQueryHandler`-ele chiar înregistrate."""
    from telegram.ext import CallbackQueryHandler

    from sentinel.config import Config
    from sentinel.telegram import bot

    app = bot.build_application(Config(), _fake_secrets())
    patterns = []
    for handlers in app.handlers.values():
        for h in handlers:
            if isinstance(h, CallbackQueryHandler) and h.pattern is not None:
                patterns.append(h.pattern)
    return patterns


def _sample_for(prefix: str) -> str:
    """Un `callback_data` PLAUZIBIL pentru un prefix, ca să se poată testa
    fiecare tipar exact cum ar primi-o Telegram — nu doar prefixul gol, care
    n-ar potrivi un tipar de forma `^blk:`."""
    return prefix if prefix in ("cancel", "flush") else f"{prefix}:x"


def test_at_least_the_known_producers_are_found():
    """Fără asta, o schimbare de formă în cele trei fișiere ar face
    extractorul să nu vadă nimic — și testul de mai jos ar trece gol, ceea ce
    nu verifică nimic."""
    all_prefixes = (_emitted_prefixes(BOT_PY) | _emitted_prefixes(PATCH_FLOW_PY)
                    | _emitted_prefixes(LOGINS_PY))
    assert _DYNAMIC not in all_prefixes, (
        "un `callback_data` nu s-a putut citi static — extinde "
        "`_literal_prefix` pentru noua formă înainte să continui")
    for expected in ("blk", "unblk", "nteu", "cancel", "flush",
                     "pap1", "pap2", "pdry", "prej"):
        assert expected in all_prefixes, f"producătorul lui {expected!r} nu a fost găsit"


def test_every_emitted_prefix_matches_a_registered_pattern():
    """Verificarea autoritară: fiecare buton pe care codul chiar îl trimite
    trebuie să ajungă la un handler REAL, în aplicația REAL construită —
    exact eșecul care a lăsat `nteu:` mort: ramura exista, tiparul nu o
    includea, și nimic din suita de dinainte nu compara cele două."""
    all_prefixes = (_emitted_prefixes(BOT_PY) | _emitted_prefixes(PATCH_FLOW_PY)
                    | _emitted_prefixes(LOGINS_PY))
    patterns = _registered_callback_patterns()
    assert patterns, "nu s-a găsit niciun CallbackQueryHandler cu tipar"

    orphaned = []
    for prefix in sorted(all_prefixes):
        sample = _sample_for(prefix)
        if not any(p.match(sample) for p in patterns):
            orphaned.append(prefix)
    assert not orphaned, (
        f"prefixele {orphaned} sunt emise de cod dar niciun "
        "CallbackQueryHandler înregistrat nu le rutează — butonul ajunge la "
        "Telegram, tap-ul se întoarce, și nimic nu-l procesează")


def _unwrapped_target(callback):
    """Funcția reală din spatele unui `wrapper` de închidere (`_guard`/
    `_guard_callback`): citește celula `handler` din `__closure__`, nu doar
    presupune un nume — un wrapper viitor cu alt nume de variabilă închisă ar
    face un test bazat pe nume să treacă orb."""
    if not getattr(callback, "__closure__", None):
        return callback
    names = callback.__code__.co_freevars
    for name, cell in zip(names, callback.__closure__):
        if name == "handler":
            return cell.cell_contents
    return callback


def test_the_nteu_button_specifically_routes_to_on_callback():
    """Falsificarea directă a bug-ului măsurat: `nteu:` trebuie să ajungă
    exact la `on_callback`, care are ramura „Nu sunt eu" — nu doar la ORICE
    handler, ca un tipar prea larg să nu ascundă o rutare greșită."""
    from telegram.ext import CallbackQueryHandler

    from sentinel.config import Config
    from sentinel.telegram import bot

    app = bot.build_application(Config(), _fake_secrets())
    matches = [
        h for handlers in app.handlers.values() for h in handlers
        if isinstance(h, CallbackQueryHandler) and h.pattern is not None
        and h.pattern.match("nteu:77")
    ]
    assert matches, "nteu: nu potrivește niciun handler înregistrat"
    target = _unwrapped_target(matches[0].callback)
    assert target is bot.on_callback, (
        f"nteu: e rutat la {target!r}, nu la bot.on_callback")
