"""Smoke-testul nu are voie să treacă peste o verificare fără răspuns.

Eșecul pe care îl previne: instalarea se termină cu `[+] autoverificarea nu
raportează nimic`, iar în tot timpul ăsta agentul spune `unknown` despre ceva
real. Verde-ul e citit ca „am verificat și e bine", când de fapt înseamnă „am
aruncat linia care spunea că nu se știe".

Măsurat pe 21 august 2026: fluxul `selfcheck_state` nu pleca deloc, agentul îl
raporta corect ca `unknown` la fiecare rulare, iar linia care alegea problemele
excludea explicit marcajul `[  ??]`. Smoke-testul l-a văzut și a trecut peste el
de fiecare dată.

Marcajul fusese exclus dintr-un motiv real, nu din neglijență: rulată de mână,
verificarea de nftables nu primește `CAP_NET_ADMIN` — acela vine de la unitate —
deci chiar nu poate răspunde. Reparația păstrează motivul și schimbă răspunsul:
necunoscutele devin avertismente numite, nu tăcere.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts" / "smoke-test.sh"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")


def _report(text: str) -> tuple[str, int, int, int]:
    """Rulează `report_selfcheck` TĂIATĂ din scriptul livrat.

    Nu rescrisă: un test care retipărește logica probează copia lui, nu codul
    care ajunge la operator.
    """
    source = SMOKE.read_text(encoding="utf-8")
    match = re.search(r"^report_selfcheck\(\) \{.*?^\}", source, re.S | re.M)
    assert match, "report_selfcheck() nu a fost găsită în smoke-test.sh"

    script = (
        "PASS=0; FAIL=0; WARN=0\n"
        "pass() { PASS=$((PASS+1)); printf '[+] %s\\n' \"$*\"; }\n"
        "fail() { FAIL=$((FAIL+1)); printf '[x] %s\\n' \"$*\"; }\n"
        "warn() { WARN=$((WARN+1)); printf '[!] %s\\n' \"$*\"; }\n"
        + match.group(0) + "\n"
        'report_selfcheck "$(cat)"\n'
        'printf "CONTOARE %s %s %s\\n" "$PASS" "$WARN" "$FAIL"\n')
    # `encoding` explicit: pe Windows `text=True` foloseşte cp1252, iar
    # diacriticele din mesaje ies mutilate sau ridică `UnicodeEncodeError`. Un
    # test care pică pe codare nu spune nimic despre logica probată.
    out = subprocess.run([BASH, "-c", script], input=text,
                         capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    counts = re.search(r"CONTOARE (\d+) (\d+) (\d+)", out)
    assert counts, f"funcția nu a produs contoare; ieșire: {out!r}"
    return out, int(counts.group(1)), int(counts.group(2)), int(counts.group(3))


TOATE_OK = "[  ok] canalul Telegram\n[  ok] baza de date\n[  ok] bucla de detecție"

CU_NECUNOSCUT = (
    "[  ok] canalul Telegram\n"
    "[  ??] Expedierea fluxului „selfcheck_state” nu se poate măsura\n"
    "[  ok] baza de date")

CU_PROBLEMA = (
    "[  ok] canalul Telegram\n"
    "[down] bucla de detecție nu rulează\n"
    "[  ok] baza de date")


def test_an_unknown_check_is_surfaced_not_swallowed() -> None:
    """Cazul care a costat luni de zile de flux oprit.

    Necunoscuta trebuie SĂ APARĂ, numită, și numărul de ok nu are voie să fie
    prezentat ca „nu raportează nimic".
    """
    out, passes, warns, fails = _report(CU_NECUNOSCUT)
    assert warns == 1, f"necunoscuta nu a produs niciun avertisment: {out!r}"
    assert "selfcheck_state" in out, (
        "avertismentul nu numește verificarea, deci operatorul nu știe ce să caute")
    assert "nu raportează nimic" not in out, (
        "smoke-testul a spus că nu raportează nimic, deși o verificare nu se "
        "poate citi — exact formularea care a ascuns fluxul oprit")
    assert fails == 0, "o necunoscută nu e un eșec: nu se știe, nu e rău"
    assert passes == 1, "rezumatul trebuie să apară o dată, cu numerele lui"


def test_a_clean_run_still_says_nothing_is_wrong() -> None:
    """Cealaltă jumătate: fără necunoscute, formularea scurtă rămâne.

    Fără cazul ăsta, o reparație care ar transforma orice rulare în avertisment
    ar trece — iar un avertisment permanent e la fel de invizibil ca tăcerea.
    """
    out, passes, warns, fails = _report(TOATE_OK)
    assert (passes, warns, fails) == (1, 0, 0), out
    assert "nu raportează nimic" in out
    assert "3 verificări ok" in out


def test_a_real_problem_is_still_a_failure_not_a_warning() -> None:
    """`down` rămâne eșec. Necunoscuta e mai blândă; problema reală nu."""
    out, passes, warns, fails = _report(CU_PROBLEMA)
    assert fails == 1, out
    assert "bucla de detecție" in out
    assert passes == 0, (
        "un eșec nu are voie să fie urmat de un rezumat verde în aceeași rulare")


def test_a_problem_and_an_unknown_together_keep_both() -> None:
    """Amândouă deodată: eșecul nu ascunde necunoscuta, nici invers."""
    out, _passes, warns, fails = _report(CU_PROBLEMA + "\n" + CU_NECUNOSCUT)
    assert fails == 1, out
    assert warns == 1, out


def test_the_counted_unknowns_match_the_lines_reported() -> None:
    """Numărul din rezumat e cel al liniilor, nu unul plauzibil.

    Un rezumat care spune „1 fără răspuns" când sunt trei e chiar felul de raport
    după care e numit depozitul ăsta.
    """
    trei = "\n".join([
        "[  ok] canalul Telegram",
        "[  ??] prima nu se poate citi",
        "[  ??] a doua nu se poate citi",
        "[  ??] a treia nu se poate citi",
    ])
    out, _passes, warns, _fails = _report(trei)
    assert warns == 3, out
    assert "3 fără răspuns" in out, out
    assert "1 ok" in out, out
