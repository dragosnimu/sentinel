"""Filigranul de timp al reaper-ului de sesiuni, `last_record_time`.

Reaper-ul de sesiuni (`sentinel/collectors/audit_sessions.py`) și
`ingest_service.py` folosesc `last_record_time(lines)` ca să știe PÂNĂ CÂND a
citit un tur de citire din `/var/log/audit/audit.log`, ca să nu închidă o
sesiune pentru care ar putea exista încă o comandă necitită. Fiecare test de
aici numește decizia din docstring-ul funcției pe care o apără și defectul
concret care ar strica reaper-ul dacă decizia ar dispărea.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel.collectors.auditd import last_record_time

# O ștampilă reală, așa cum o scrie nucleul: epoch, trei zecimale, serial.
_LINE_A = 'type=USER_LOGIN msg=audit(1787575786.880:178043): ses=432'
_LINE_B = 'type=USER_LOGOUT msg=audit(1787575900.123:178044): ses=432'


def test_stamp_is_the_kernel_epoch_not_our_read_time():
    """Ceasul întors trebuie să vină din `msg=audit(...)`, nu din `datetime.now()`.

    Dacă funcția ar întoarce ora noastră de citire în loc de ștampila
    nucleului, filigranul ar înainta chiar și când citirea e întârziată sau
    rulează pe un lot vechi (de exemplu la un redeploy care recitește jurnalul
    din urmă) — reaper-ul ar închide sesiuni pe baza cât de rapid a rulat
    scanul, nu pe baza a ce a citit efectiv.
    """
    result = last_record_time([_LINE_A])
    assert result == datetime.fromtimestamp(1787575786.880, tz=timezone.utc)
    # Nu doar egal cu un moment plauzibil — verificăm explicit că NU e "acum".
    assert abs((datetime.now(timezone.utc) - result).total_seconds()) > 60


def test_search_goes_tail_to_head_first_readable_stamp_wins():
    """Prima ștampilă găsită căutând de la coadă spre cap trebuie să fie cea mai NOUĂ.

    auditd adaugă înregistrări în ordinea nucleului, deci ultima linie a
    lotului e cea mai recentă. Liniile de mai jos NU sunt monotone (a doua e
    mai veche decât prima), tocmai ca o căutare cap-spre-coadă greșită să dea
    alt rezultat decât una coadă-spre-cap corectă — altfel testul ar trece și
    cu ordinea inversată, fără să dovedească nimic.
    """
    newer = 'type=USER_LOGIN msg=audit(1787575786.880:1): ses=1'
    older = 'type=USER_LOGIN msg=audit(1787500000.000:2): ses=2'
    lines = [older, newer]  # coada (ultimul element) e cea mai nouă
    result = last_record_time(lines)
    assert result == datetime.fromtimestamp(1787575786.880, tz=timezone.utc)


def test_stampless_line_is_skipped_not_fatal():
    """O linie fără ștampilă la coada lotului nu are voie să întoarcă `None`.

    O rotație de jurnal sau o scriere întreruptă poate lăsa un fragment de
    linie fără `msg=audit(...)` chiar la sfârșitul lotului citit. Dacă funcția
    ar întoarce `None` la prima linie nefolosibilă în loc s-o sară, filigranul
    ar îngheța la fiecare rotație — reaper-ul ar crede că n-a mai citit nimic
    nou de atunci și ar refuza să închidă sesiuni reale, la nesfârșit.
    """
    truncated_fragment = "type=USER_LOGOUT ses=432 stat sync"  # fără msg=audit(...)
    lines = [_LINE_A, truncated_fragment]
    result = last_record_time(lines)
    assert result == datetime.fromtimestamp(1787575786.880, tz=timezone.utc)


def test_fraction_is_decimal_string_not_integer_milliseconds():
    """Zecimalele se citesc ca `0.<ms>`, nu ca `int(ms)/1000`.

    auditd scrie azi trei cifre, dar formatul nu garantează exact trei. Cu
    `int(ms)/1000`, o ștampilă cu o singură cifră de zecimale (`.5`) ar deveni
    `5/1000 = 0.005s` în loc de `0.5s` — o eroare de sute de milisecunde care,
    înmulțită pe un lot întreg, poate muta filigranul cu secunde întregi față
    de ceasul real al ultimei comenzi.
    """
    line = 'type=USER_LOGIN msg=audit(1787575786.5:1): ses=1'
    result = last_record_time([line])
    assert result == datetime.fromtimestamp(1787575786.5, tz=timezone.utc)
    assert result.microsecond == 500000


def test_no_stamps_at_all_returns_none_never_now():
    """Lipsa oricărei ștampile trebuie să întoarcă `None`, niciodată ora curentă.

    Apelantul (`ingest_service.py`) tratează `None` ca „nu pot muta filigranul
    acum" și păstrează cursorul vechi. Dacă funcția ar întoarce `datetime.now()`
    când n-a găsit nimic, ar inventa un filigran care sare peste comenzi reale
    nepotrivite unei sesiuni — exact felul de „am citit tot" care o închide
    prematur.
    """
    assert last_record_time([]) is None

    no_stamp_lines = [
        "type=USER_LOGOUT ses=432 stat sync",
        "type=SYSCALL fragment fara stampila",
    ]
    assert last_record_time(no_stamp_lines) is None


def test_impossible_stamp_is_skipped_not_fatal_to_the_watermark():
    """O ștampilă imposibilă (epoch în afara intervalului) nu are voie să urce excepția.

    `_audit_watermark` din `ingest_service.py` cheamă `last_record_time` ÎNAINTE
    de `parse_auditd_lines`, `insert_batch` și avansul cursorului, fără niciun
    `try` în jur. Dacă `datetime.fromtimestamp` ar ridica pe un epoch imposibil
    (an sărit, linie coruptă de o rotație) în loc să întoarcă `None`, excepția
    ar urca necaptată din `poll_once`: cursorul n-ar mai avansa, turul următor
    ar reciti exact același lot corupt și ar pica identic — ingestia pentru
    TOATE sursele (nu doar auditd) ar îngheța până la rotația jurnalului.

    Corupția e cea deja folosită pentru sora acestei funcții,
    `parse_auditd_lines`, în `test_auditd_watch.py`: epoch înlocuit cu
    `99999999999999999`, care depășește ce acceptă `datetime.fromtimestamp`.
    """
    impossible = _LINE_A.replace("1787575786", "99999999999999999")

    # Ștampila imposibilă la COADĂ: căutarea coadă-spre-cap o lovește prima —
    # dacă n-ar fi sărită, ar întoarce None sau ar ridica, în loc să continue
    # spre ștampila bună de dinaintea ei.
    result = last_record_time([_LINE_A, impossible])
    assert result == datetime.fromtimestamp(1787575786.880, tz=timezone.utc)

    # Fără nicio ștampilă citibilă în tot lotul, rezultatul e None — niciodată
    # o excepție care ar urca necaptată din `_audit_watermark`.
    assert last_record_time([impossible]) is None
