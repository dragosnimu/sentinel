"""Semnarea payload-ului din `blk:`/`unblk:` callback_data.

## De ce

Telegram trimite `callback_data` înapoi exact așa cum a fost scris pe buton,
dar CLIENTUL e cel care-l trimite, iar protocolul care stă în spatele
`answerCallbackQuery` nu leagă rechemarea de textul real al butonului apăsat —
un client modificat (sau orice cont care poate vedea mesajul) poate cere
botului să proceseze orice șir de până la 64 de octeți pentru acel mesaj, nu
neapărat pe cel scris pe buton. Fără o semnătură, un membru al chatului
permis putea construi manual `blk:203.0.113.7:0` și bloca o adresă pe care
nimeni n-a raportat-o — vezi docs/TELEGRAM.md §5.

`TELEGRAM_CALLBACK_HMAC_KEY` semnează fiecare payload; `issued_at` +
`callback_ttl_s` mărginesc cât rămâne valid un buton emis. `ref` e
identificatorul incidentului care a generat butonul (0 pentru o confirmare
manuală din `/block`, care n-are incident) — legat în semnătură, deci un
buton nu poate fi reatribuit altui incident după ce a fost trimis.

## De ce IP-ul e codat, nu text

Un IPv6 necomprimat ("ffff:ffff:...") are 39 de caractere. Cu prefixul
acțiunii, TTL, ref, timpul emiterii și semnătura, formatul text singur ar
depăși limita Telegram de 64 de octeți pentru `callback_data` — motivul
pentru care `bot.py` avea, înainte de asta, `data.split(":", 2)` pe un șir
care putea conține oricâte două puncte suplimentare venite chiar din adresă.
`ip.packed` (bytes brute) + base64 duce un IPv6 la 22 caractere, un IPv4 la 6.

## Cât de tare e semnătura

Trunchiată la `TAG_BYTES` octeți — un compromis impus de buget, nu o alegere
de sine stătătoare: rolul (`_can_act`) și chatul (`_authorized`) tot trebuie
să treacă independent înainte ca oricare din funcțiile astea să fie chemate,
iar TTL-ul implicit (600s) mărginește fereastra în care o ghicire ar avea
vreo șansă practică. Mărită dincolo de-atât, formatul complet cu un IPv6 ar
depăși limita — vezi `test_the_worst_case_ipv6_payload_still_fits_in_64_bytes`
pentru limita exactă verificată, nu doar presupusă.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import time

#: Lungimea etichetei HMAC păstrate în payload, în octeți brut (înainte de
#: base64). Vezi docstring-ul modulului pentru compromisul de spațiu.
TAG_BYTES = 6

#: Limita reală a Telegram pentru `callback_data`. Depășită, `sendMessage`
#: refuză cererea — verificată aici la CONSTRUIRE, nu doar presupusă la
#: proiectare: `sign_ip_action` ridică dacă rezultatul o depășește, ca o
#: greșeală de calcul viitoare (un câmp lărgit fără să se refacă bugetul) să
#: pice la teste, nu la un buton mort în producție.
MAX_CALLBACK_BYTES = 64

_B36_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


class CallbackError(Exception):
    """Payload lipsă, trunchiat, semnat greșit sau expirat."""


class Malformed(CallbackError):
    """Nu s-a putut despacheta — formă necunoscută, nu neapărat falsificat."""


class BadSignature(CallbackError):
    """S-a despachetat, dar eticheta HMAC nu se potrivește."""


class Expired(CallbackError):
    """Semnătura e validă, dar `issued_at` a depășit `callback_ttl_s`."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _un_b64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001 - orice formă proastă e Malformed
        raise Malformed(f"base64 invalid: {exc}") from exc


def _b36(n: int) -> str:
    if n < 0:
        raise ValueError(f"nu se codează un întreg negativ: {n}")
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(_B36_DIGITS[r])
    return "".join(reversed(out))


def _un_b36(text: str) -> int:
    if not text or any(c not in _B36_DIGITS for c in text):
        raise Malformed(f"nu e un întreg base36: {text!r}")
    return int(text, 36)


def _encode_ip(ip: str) -> str:
    return _b64(ipaddress.ip_address(ip).packed)


def _decode_ip(token: str) -> str:
    raw = _un_b64(token)
    if len(raw) not in (4, 16):
        raise Malformed(f"lungime de adresă neașteptată: {len(raw)} octeți")
    return str(ipaddress.ip_address(raw))


def _mac(key: bytes, *fields: str) -> bytes:
    msg = ":".join(fields).encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).digest()[:TAG_BYTES]


def _verified(key: bytes, sig: str, *fields: str) -> bool:
    """MAC-ul câmpurilor date, comparat constant-time cu `sig`.

    `fields` și `sig` vin direct din `callback_data`, adică de la CLIENT — pot
    conține orice. `_mac` face `.encode("ascii")` pe câmpurile îmbinate, iar
    `hmac.compare_digest` pe două `str` cere ambele ASCII; un payload cu un
    singur caracter în afara ASCII (`blk:é:0:0:0:x`, sau chiar în `sig`:
    `blk:AQIDBA:0:0:0:é`) ridica `UnicodeEncodeError`/`TypeError` NECONTROLAT
    la nivelul ăsta — `_guard_callback` tot oprea căderea botului, dar
    operatorul vedea eroarea generică de-acolo, nu „buton nevalid", și
    defectul nu se distingea de un bug real în cod. Aici devine `Malformed`,
    ca orice altă formă proastă.
    """
    try:
        expected = _b64(_mac(key, *fields))
        return hmac.compare_digest(sig, expected)
    except (UnicodeEncodeError, TypeError) as exc:
        raise Malformed(f"payload nu e ASCII: {exc}") from exc


def sign_ip_action(action: str, key: bytes, ip: str, ttl_s: int, *,
                   ref: int = 0, issued_at: int | None = None) -> str:
    """Construiește `action:ip_b64:ttl_b36:ref_b36:issued_b36:sig`.

    `action` trebuie să fie exact `"blk"` sau `"unblk"` — literalul cu care
    `build_application` înregistrează `CallbackQueryHandler`-ul; orice altă
    valoare ar produce un buton pe care nimic nu-l rutează.

    `ttl_s` e 0 pentru un unblock (fără sens acolo) sau pentru un block
    permanent (`None` la apelant devine 0 aici — `on_callback` face invers la
    verificare: `0 -> None`). Apelantul e ținut să mărginească `ttl_s`
    ÎNAINTE de asta (`cmd_block` refuză sub 60s și peste 30 de zile) — funcția
    asta nu alege o valoare mai mică în locul apelantului, fiindcă atunci
    textul confirmării ("blochează pentru X") și fapta ar putea să nu mai fie
    aceleași afirmații.
    """
    issued = int(time.time()) if issued_at is None else issued_at
    fields = (action, _encode_ip(ip), _b36(ttl_s), _b36(ref), _b36(issued))
    sig = _b64(_mac(key, *fields))
    data = ":".join((*fields, sig))
    if len(data.encode("utf-8")) > MAX_CALLBACK_BYTES:
        # Vezi docstring-ul modulului: bugetul a fost calculat, nu ghicit — dar
        # un apelant care mărește `ref` sau `ttl_s` dincolo de ce s-a bugetat
        # trebuie să afle ACUM, la construire, nu dintr-un `sendMessage` care
        # refuză tăcut mai târziu într-un ciclu al buclei de push.
        raise ValueError(
            f"callback_data de {len(data.encode('utf-8'))} octeți depășește "
            f"limita Telegram de {MAX_CALLBACK_BYTES}: {data!r}")
    return data


def verify_ip_action(data: str, key: bytes | None, *,
                     ttl_s: int) -> tuple[str, int, int, int]:
    """Verifică și despachetează. Întoarce `(ip, ttl_s, ref, issued_at)`.

    Ridică `Malformed`, `BadSignature` sau `Expired` — apelantul alege ce
    spune operatorului pentru fiecare, dar decizia despre VALIDITATE se ia
    o singură dată, aici.

    `key=None` e tratat ca eșec de verificare, nu ca „fără verificare": un
    proces pornit fără `TELEGRAM_CALLBACK_HMAC_KEY` n-ar trebui să ajungă
    până aici (`build_application` cere secretul la construire), dar un
    apelant care totuși n-o are nu are voie să execute un blk/unblk nesemnat.
    """
    if not key:
        raise BadSignature("fără cheie de semnare")
    parts = data.split(":")
    if len(parts) != 6:
        raise Malformed(f"{len(parts)} câmpuri, așteptam 6: {data!r}")
    action, ip_b64, ttl_b36, ref_b36, issued_b36, sig = parts
    if not _verified(key, sig, action, ip_b64, ttl_b36, ref_b36, issued_b36):
        raise BadSignature(action)
    ip = _decode_ip(ip_b64)
    ttl = _un_b36(ttl_b36)
    ref = _un_b36(ref_b36)
    issued_at = _un_b36(issued_b36)
    if time.time() - issued_at > ttl_s:
        raise Expired(action)
    return ip, ttl, ref, issued_at


def sign_session_action(key: bytes, session_id: int, *,
                        issued_at: int | None = None) -> str:
    """Construiește `nteu:id_b36:issued_b36:sig`, pentru butonul „Nu sunt eu".

    Fără semnătură, orice membru `_can_act` al chatului putea trimite manual
    `nteu:<id secvențial>` — `on_callback` citea sesiunea din bază și chema
    `actions.block_and_terminate` pe orice id ghicit, inclusiv sesiunea unui
    IP din allowlist, unde efectul e să-ți închizi singur propriul SSH.

    Câmpurile lui `blk:` (IP, TTL, `ref`) nu au sens aici: nu există o adresă
    la momentul emiterii — se citește din `login_sessions` ABIA la apăsare
    (vezi `logins._buttons` și `on_callback`), ca butonul apăsat peste ore să
    lovească cine e conectat ATUNCI de pe sesiunea aia, nu adresa de la
    emitere. Payload-ul rămâne deci doar id-ul sesiunii și momentul emiterii.

    TTL-ul de verificare NU e purtat aici, spre deosebire de `blk:`/`unblk:`
    — e o constantă a apelantului (`bot.NTEU_TTL_S`), lungă în mod deliberat:
    butonul e gândit să fie apăsat ore mai târziu, nu în fereastra scurtă a
    unui `blk:` obișnuit.
    """
    issued = int(time.time()) if issued_at is None else issued_at
    fields = ("nteu", _b36(session_id), _b36(issued))
    sig = _b64(_mac(key, *fields))
    data = ":".join((*fields, sig))
    if len(data.encode("utf-8")) > MAX_CALLBACK_BYTES:
        raise ValueError(
            f"callback_data de {len(data.encode('utf-8'))} octeți depășește "
            f"limita Telegram de {MAX_CALLBACK_BYTES}: {data!r}")
    return data


def verify_session_action(data: str, key: bytes | None, *,
                          ttl_s: int) -> tuple[int, int]:
    """Verifică și despachetează un `nteu:...`. Întoarce `(session_id, issued_at)`.

    Aceeași decizie ca `verify_ip_action`: `key=None` e eșec de verificare,
    nu „fără verificare", și orice formă neașteptată (număr greșit de câmpuri,
    prefix greșit, câmpuri non-ASCII) e `Malformed`, nu o excepție scăpată
    până la `_guard_callback`.
    """
    if not key:
        raise BadSignature("fără cheie de semnare")
    parts = data.split(":")
    if len(parts) != 4:
        raise Malformed(f"{len(parts)} câmpuri, așteptam 4: {data!r}")
    action, id_b36, issued_b36, sig = parts
    if action != "nteu":
        raise Malformed(f"prefix neașteptat: {action!r}")
    if not _verified(key, sig, action, id_b36, issued_b36):
        raise BadSignature(action)
    session_id = _un_b36(id_b36)
    issued_at = _un_b36(issued_b36)
    if time.time() - issued_at > ttl_s:
        raise Expired(action)
    return session_id, issued_at
