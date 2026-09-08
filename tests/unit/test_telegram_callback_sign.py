"""Semnarea butoanelor `blk:`/`unblk:`.

Fără o semnătură verificată, orice membru al unui chat permis putea construi
manual `blk:203.0.113.7:0` și bloca o adresă pe care nimeni n-a raportat-o
niciodată — `callback_data` e trimis înapoi de CLIENT, nu de server, deci
poate fi orice șir de până la 64 de octeți, nu neapărat textul real al unui
buton emis de bot (docs/TELEGRAM.md §5, §6). Testele astea păzesc trei
lucruri separate: că o semnătură corectă chiar se verifică, că una greșită
(falsificată SAU expirată) chiar se refuză, și că formatul ales — IP-ul
codat binar, nu text — chiar încape în limita reală a Telegram pentru cel
mai mare payload posibil, nu doar pentru cazul obișnuit (IPv4).
"""
from __future__ import annotations

import time

import pytest

from sentinel.telegram import callback_sign as cs

KEY = b"testing-key-not-a-real-secret"
OTHER_KEY = b"a-different-key-entirely"


#: Un moment „acum" fix, ca testele să nu depindă de ceasul mașinii care le
#: rulează — dar suficient de aproape de real încât `Expired`/`ttl_s` să se
#: comporte ca în producție, nu ca la un moment arbitrar din trecut.
NOW = int(time.time())


def test_a_signed_block_round_trips():
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, ref=42,
                             issued_at=NOW)
    ip, ttl, ref, issued = cs.verify_ip_action(data, KEY, ttl_s=600)
    assert ip == "203.0.113.7"
    assert ttl == 3600
    assert ref == 42
    assert issued == NOW


def test_a_signed_unblock_round_trips_with_ipv6():
    data = cs.sign_ip_action("unblk", KEY, "2001:db8::1", 0, ref=7,
                             issued_at=NOW)
    ip, ttl, ref, issued = cs.verify_ip_action(data, KEY, ttl_s=600)
    assert ip == "2001:db8::1"
    assert ttl == 0
    assert ref == 7


def test_data_starts_with_the_literal_the_handler_pattern_matches():
    """`on_callback` e rutat de un `CallbackQueryHandler(pattern=r"^(blk:|unblk:|...)")`
    — dacă encodarea ar schimba prefixul, butonul n-ar mai ajunge nicăieri."""
    blk = cs.sign_ip_action("blk", KEY, "203.0.113.7", 60, issued_at=NOW)
    unblk = cs.sign_ip_action("unblk", KEY, "203.0.113.7", 0, issued_at=NOW)
    assert blk.startswith("blk:")
    assert unblk.startswith("unblk:")


# --- falsificare: o semnătură modificată nu trebuie să treacă niciodată -----
def test_a_tampered_ip_is_rejected():
    """Exact atacul pe care semnătura există să-l oprească: cineva schimbă
    IP-ul din payload, sperând că botul îl acceptă necontrolat."""
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=NOW)
    action, ip_b64, ttl_b36, ref_b36, issued_b36, sig = data.split(":")
    forged_ip_b64 = cs._encode_ip("198.51.100.99")
    forged = ":".join((action, forged_ip_b64, ttl_b36, ref_b36, issued_b36, sig))
    with pytest.raises(cs.BadSignature):
        cs.verify_ip_action(forged, KEY, ttl_s=600)


def test_a_tampered_ttl_is_rejected():
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 60, issued_at=NOW)
    action, ip_b64, ttl_b36, ref_b36, issued_b36, sig = data.split(":")
    forged = ":".join((action, ip_b64, cs._b36(999_999), ref_b36, issued_b36, sig))
    with pytest.raises(cs.BadSignature):
        cs.verify_ip_action(forged, KEY, ttl_s=600)


def test_signed_with_a_different_key_is_rejected():
    """Cheia trebuie să fie chiar cea din `secrets.env` — o cheie greșită (sau
    a altei instanțe, dacă ar fi comună) nu are voie să pară validă."""
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=NOW)
    with pytest.raises(cs.BadSignature):
        cs.verify_ip_action(data, OTHER_KEY, ttl_s=600)


def test_missing_key_is_rejected_not_treated_as_unsigned():
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=NOW)
    with pytest.raises(cs.BadSignature):
        cs.verify_ip_action(data, None, ttl_s=600)


def test_garbage_ip_field_with_an_otherwise_valid_signature_is_malformed():
    """O semnătură validă peste niște câmpuri stricate nu are voie să treacă
    de verificare doar fiindcă etichetele se potrivesc — codul trebuie să mai
    și DECODEZE ce a semnat, nu doar să confirme cine a semnat."""
    fields = ("blk", "not-valid-base64!!", cs._b36(0), cs._b36(0), cs._b36(NOW))
    sig = cs._b64(cs._mac(KEY, *fields))
    forged = ":".join((*fields, sig))
    with pytest.raises(cs.Malformed):
        cs.verify_ip_action(forged, KEY, ttl_s=600)


def test_wrong_field_count_is_malformed_not_a_crash():
    """Fostul `data.split(':', 2)` din `bot.py` arunca `ValueError`
    necontrolat pe orice `blk:` cu mai mult de două puncte în plus — exact ce
    produce un IPv6 în forma lui text. Aici verificarea trebuie să numească
    problema, nu doar să crape."""
    with pytest.raises(cs.Malformed):
        cs.verify_ip_action("blk:onlyonefield", KEY, ttl_s=600)


# --- expirare -----------------------------------------------------------
def test_an_expired_button_is_rejected():
    old = NOW - 1000
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=old)
    with pytest.raises(cs.Expired):
        cs.verify_ip_action(data, KEY, ttl_s=600)


def test_a_button_within_the_ttl_is_accepted():
    recent = NOW - 30
    data = cs.sign_ip_action("blk", KEY, "203.0.113.7", 3600, issued_at=recent)
    ip, *_ = cs.verify_ip_action(data, KEY, ttl_s=600)
    assert ip == "203.0.113.7"


# --- bugetul de 64 de octeți ----------------------------------------------
def test_the_worst_case_ipv6_payload_still_fits_in_64_bytes():
    """Cel mai lung IPv6 posibil ca text (39 de caractere, fără compresie),
    TTL-ul maxim documentat (30 de zile) și un `ref` realist de mare — cazul
    care ar fi depășit limita dacă IP-ul ar fi purtat ca text, nu ca octeți."""
    worst_ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    assert len(worst_ip) == 39
    data = cs.sign_ip_action("blk", KEY, worst_ip, 30 * 86400,
                             ref=999_999_999, issued_at=int(time.time()))
    assert len(data.encode("utf-8")) <= 64, (len(data), data)
    ip, ttl, ref, _ = cs.verify_ip_action(data, KEY, ttl_s=600)
    assert ip == worst_ip
    assert ttl == 30 * 86400
    assert ref == 999_999_999


def test_an_absurd_ref_is_refused_at_construction_not_sent_broken():
    """Dacă un apelant viitor ar mări `ref` mult dincolo de ce s-a bugetat,
    trebuie să afle la CONSTRUIRE — un test roșu, nu un buton pe care
    Telegram îl refuză tăcut în producție."""
    worst_ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    with pytest.raises(ValueError):
        cs.sign_ip_action("blk", KEY, worst_ip, 30 * 86400,
                          ref=36 ** 20, issued_at=int(time.time()))


def test_ipv4_round_trips_compactly():
    data = cs.sign_ip_action("unblk", KEY, "198.51.100.7", 0, issued_at=NOW)
    ip, *_ = cs.verify_ip_action(data, KEY, ttl_s=600)
    assert ip == "198.51.100.7"
    assert len(data) < 64


# --- payload non-ASCII: crapă necontrolat, sau se refuză curat? -----------
def test_non_ascii_ip_field_is_malformed_not_a_crash():
    """`_mac` face `.encode("ascii")` pe câmpurile îmbinate — un `ip_b64`
    (sau orice alt câmp) cu un singur caracter în afara ASCII ridica
    `UnicodeEncodeError` NECONTROLAT înaintea oricărei verificări de
    semnătură, în loc de un refuz curat."""
    with pytest.raises(cs.Malformed):
        cs.verify_ip_action("blk:é:0:0:0:x", KEY, ttl_s=600)


def test_non_ascii_signature_field_is_malformed_not_a_crash():
    """`hmac.compare_digest` pe două `str` cere ambele ASCII — un `sig` cu
    un caracter non-ASCII ridica `TypeError` NECONTROLAT, chiar dacă restul
    câmpurilor erau perfect valide."""
    with pytest.raises(cs.Malformed):
        cs.verify_ip_action("blk:AQIDBA:0:0:0:é", KEY, ttl_s=600)


def test_fewer_than_six_fields_is_malformed():
    """Un payload cu mai puține câmpuri decât formatul complet (aici 5, nu 6)
    trebuie numit, nu doar respins prin coincidența unei semnături greșite."""
    with pytest.raises(cs.Malformed):
        cs.verify_ip_action("blk:AQIDBA:0:0:0", KEY, ttl_s=600)


# --- `nteu:` — semnarea butonului „Nu sunt eu" -----------------------------
# Fără semnătură, orice membru `_can_act` al chatului putea trimite manual
# `nteu:<id secvențial>`, iar `on_callback` executa `block_and_terminate` pe
# orice sesiune ghicită — inclusiv una de pe o adresă din allowlist, unde
# efectul e să-ți închizi singur propriul SSH.
def test_a_signed_nteu_round_trips():
    data = cs.sign_session_action(KEY, 4711, issued_at=NOW)
    session_id, issued = cs.verify_session_action(data, KEY, ttl_s=600)
    assert session_id == 4711
    assert issued == NOW


def test_nteu_starts_with_the_literal_the_handler_pattern_matches():
    data = cs.sign_session_action(KEY, 1, issued_at=NOW)
    assert data.startswith("nteu:")


def test_nteu_fits_comfortably_in_the_64_byte_budget():
    data = cs.sign_session_action(KEY, 999_999_999_999, issued_at=NOW)
    assert len(data.encode("utf-8")) <= 64, (len(data), data)


def test_a_tampered_nteu_session_id_is_rejected():
    """Exact atacul pe care semnătura există să-l oprească: cineva schimbă
    id-ul sesiunii din payload, sperând să termine o sesiune arbitrară."""
    data = cs.sign_session_action(KEY, 100, issued_at=NOW)
    action, id_b36, issued_b36, sig = data.split(":")
    forged = ":".join((action, cs._b36(999), issued_b36, sig))
    with pytest.raises(cs.BadSignature):
        cs.verify_session_action(forged, KEY, ttl_s=600)


def test_nteu_signed_with_a_different_key_is_rejected():
    data = cs.sign_session_action(KEY, 100, issued_at=NOW)
    with pytest.raises(cs.BadSignature):
        cs.verify_session_action(data, OTHER_KEY, ttl_s=600)


def test_nteu_missing_key_is_rejected_not_treated_as_unsigned():
    data = cs.sign_session_action(KEY, 100, issued_at=NOW)
    with pytest.raises(cs.BadSignature):
        cs.verify_session_action(data, None, ttl_s=600)


def test_nteu_wrong_field_count_is_malformed_not_a_crash():
    with pytest.raises(cs.Malformed):
        cs.verify_session_action("nteu:onlyonefield", KEY, ttl_s=600)


def test_nteu_wrong_prefix_is_malformed():
    """Un `blk:`-shaped payload de patru câmpuri nu are voie să se
    verifice ca `nteu:` doar fiindcă numărul de câmpuri se potrivește."""
    fields = ("blk", cs._b36(1), cs._b36(NOW))
    sig = cs._b64(cs._mac(KEY, *fields))
    forged = ":".join((*fields, sig))
    with pytest.raises(cs.Malformed):
        cs.verify_session_action(forged, KEY, ttl_s=600)


def test_an_expired_nteu_button_is_rejected():
    old = NOW - 1000
    data = cs.sign_session_action(KEY, 100, issued_at=old)
    with pytest.raises(cs.Expired):
        cs.verify_session_action(data, KEY, ttl_s=600)


def test_an_nteu_button_within_a_seven_day_ttl_is_accepted():
    """Butonul e gândit să fie apăsat ore mai târziu — TTL-ul folosit la
    verificare (`bot.NTEU_TTL_S`) e mult mai lung decât cel implicit pentru
    `blk:`/`unblk:` (600s)."""
    hours_ago = NOW - 6 * 3600
    data = cs.sign_session_action(KEY, 100, issued_at=hours_ago)
    session_id, _ = cs.verify_session_action(data, KEY, ttl_s=7 * 86_400)
    assert session_id == 100


def test_non_ascii_nteu_signature_field_is_malformed_not_a_crash():
    with pytest.raises(cs.Malformed):
        cs.verify_session_action("nteu:2s:0:é", KEY, ttl_s=600)
