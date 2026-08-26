"""Scanerul de pachete și unitatea lui trebuie să vorbească despre ACELAȘI cache.

Eșecul pe care îl previne, măsurat pe gazda reală pe 21 august 2026:
`dnf updateinfo list cves` rulează în 7 secunde ca root — care folosește cache-ul
sistemului din `/var/cache/dnf` — și în **82** ca utilizatorul `sentinel`, care
nu-l poate citi și reconstruiește toate metadatele la fiecare rulare. Plafonul
scanerului era 120 de secunde, iar rulările reale luau între 82 și 120: o monedă
aruncată în fiecare noapte. A picat de patru ori în două săptămâni, iar de
fiecare dată lista de vulnerabilități a rămas înghețată fără ca nimeni să afle.

Cu un cache propriu, scris o dată și refolosit: 2,4 secunde.

Ce leagă testul ăsta: calea din cod și cea creată de systemd. Despărțite, una
s-ar muta la o refactorizare și cealaltă ar scrie în continuare într-un director
pe care nu-l mai creează nimeni — iar simptomul ar fi fix cel de mai sus, întors,
fără nimic care să-l explice.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.scan import os_packages

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy" / "systemd" / "sentinel-scan.service"


def _unit() -> str:
    return UNIT.read_text(encoding="utf-8")


def test_the_unit_creates_the_directory_the_scanner_writes_to() -> None:
    """`CacheDirectory=X` face `/var/cache/X`. Trebuie să fie exact `CACHE_DIR`."""
    found = re.search(r"^CacheDirectory=(\S+)$", _unit(), re.M)
    assert found, (
        "unitatea nu declară `CacheDirectory=`, deci dnf ar scrie într-un "
        "director pe care nimeni nu-l creează — și fiecare scanare ar "
        "reconstrui metadatele, ca înainte de reparație")
    assert f"/var/cache/{found.group(1)}" == os_packages.CACHE_DIR, (
        f"unitatea creează /var/cache/{found.group(1)}, iar scanerul scrie în "
        f"{os_packages.CACHE_DIR}")


def test_the_scanner_actually_passes_the_cache_dir_to_dnf() -> None:
    """Constanta declarată și nefolosită e o reparație pe hârtie.

    Verificat pe SURSĂ, nu pe constantă: un `CACHE_DIR` corect pe care nu-l
    primește dnf lasă comportamentul neschimbat, iar testul de mai sus ar trece
    în continuare.
    """
    source = (ROOT / "sentinel" / "scan" / "os_packages.py").read_text(encoding="utf-8")
    assert "--setopt=cachedir=" in source, (
        "dnf nu primește niciun `cachedir`, deci folosește implicitul — cel pe "
        "care utilizatorul neprivilegiat nu-l poate scrie")
    assert "{CACHE_DIR}" in source, (
        "calea e scrisă de mână în argument, deci se poate despărți de constantă")


def test_the_directory_survives_between_runs() -> None:
    """`RuntimeDirectory=` l-ar șterge la oprire și ar readuce exact problema.

    Un cache care dispare după fiecare rulare nu e un cache — e o cheltuială.
    """
    text = _unit()
    assert not re.search(r"^RuntimeDirectory=.*dnf", text, re.M), (
        "cache-ul e declarat ca director de rulare, deci se șterge la oprirea "
        "serviciului și fiecare scanare o ia de la capăt")


def test_the_timeout_has_room_for_the_worst_case_that_remains() -> None:
    """Cache-ul rezolvă cazul obișnuit; plafonul trebuie să acopere primul.

    Prima rulare după ce cache-ul e șters a fost măsurată la 87 de secunde. Un
    plafon apropiat de ea readuce moneda aruncată, doar mai rar — iar mai rar e
    mai rău: o pană care apare o dată la două luni nu e diagnosticată, e uitată.
    """
    assert os_packages.TIMEOUT_S >= 180, (
        f"plafonul e {os_packages.TIMEOUT_S}s, iar prima rulare fără cache a fost "
        f"măsurată la 87s — marginea trebuie să fie peste dublu")


def test_the_default_timeout_of_run_is_the_declared_one() -> None:
    """Un implicit rămas în urmă e un plafon care nu se vede în constantă."""
    import inspect

    default = inspect.signature(os_packages._run).parameters["timeout"].default
    assert default == os_packages.TIMEOUT_S, (
        f"`_run` are implicitul {default}, iar constanta spune "
        f"{os_packages.TIMEOUT_S}: cine citește constanta află altceva decât "
        f"ce se întâmplă")


@pytest.mark.parametrize("cale", ["/var/cache/dnf", "/tmp", "/var/tmp"])
def test_the_cache_is_not_somewhere_shared_or_volatile(cale: str) -> None:
    """Nu cache-ul lui root, și nu un director temporar.

    `/var/cache/dnf` aparține lui root: scanerul n-are voie acolo, iar dacă ar
    avea, ar putea strica metadatele pe care se bazează `dnf update`. `/tmp` se
    golește, deci fiecare rulare ar fi prima.
    """
    assert os_packages.CACHE_DIR != cale
    assert not os_packages.CACHE_DIR.startswith(cale + "/")
