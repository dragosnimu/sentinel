"""„N-am putut întreba `ss`” nu are voie să se scrie „portul e liber” în wizard.

`scripts/wizard.sh` sondează gazda țintă înainte să întrebe cum se expune panoul:

    echo "P80=$(ss -tln 2>/dev/null | grep -qE ":80 " && echo busy || echo free)"

Codul de ieșire al unei conducte e al ultimei comenzi, deci un `ss` lipsă (127) sau refuzat
ajungea la `grep -q` fără nicio linie de intrare, iar nicio linie e exact cum arată „liber”.
Wizard-ul îi spunea apoi operatorului „portul 80 e liber” și recomanda în consecință. Miza e
mică (sfat pentru un om, nu o decizie luată de instalator), dar e aceeași citire greșită.

Trei răspunsuri, nu două: `busy`, `free`, `unknown`. Consumatorul trebuie să le citească pe
toate: tot ce nu e exact `busy` sau `free` (inclusiv un câmp lipsă dintr-un răspuns trunchiat)
e `unknown` și nu se spune despre el nici „ocupat”, nici „liber”.

Fișierul rulează TEXTUL livrat: scriptul de sondare e extras din `wizard.sh` (argumentul lui
`remote '…'`) și rulat cu un `ss` momeală pe PATH, iar secțiunea 3 a wizard-ului e extrasă și
rulată cu `ask_choice`/`warn`/`info` înlocuite de funcții care înregistrează ce li s-a dat.

Ce NU are mediul ăsta: un `ss` real. Momeala tipărește capul de tabel pe care `ss -tln` îl
tipărește mereu (MĂSURAT pe cele două gazde de producție, 2 nov 2026, doar citire).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WIZARD = (REPO / "scripts" / "wizard.sh").read_text(encoding="utf-8")

BASH = shutil.which("bash")
_NO_BASH = ("bash lipsește din PATH, deci codul LIVRAT nu a fost rulat. "
            "Asta e „neverificat”, nu „în regulă”.")
pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason=_NO_BASH)]

HEADER = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port"
L22 = "LISTEN 0      128          0.0.0.0:22        0.0.0.0:*"
L80 = "LISTEN 0      511          0.0.0.0:80        0.0.0.0:*"
L443 = "LISTEN 0      511             [::]:443          [::]:*"
L8080 = "LISTEN 0      511          0.0.0.0:8080      0.0.0.0:*"


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _probe_script() -> str:
    """Scriptul de sondare din `PROBE="$(remote '…' 2>/dev/null)"`, exact cum îl primește
    `bash -c`. Extragerea e verificată: una ruptă ar face fiecare test să treacă pe nimic."""
    start_marker = 'PROBE="$(remote \''
    start = WIZARD.index(start_marker) + len(start_marker)
    end = WIZARD.index("\n' 2>/dev/null)\"", start)
    script = WIZARD[start:end]
    assert "P80" in script and "P443" in script and "os-release" in script, script[:200]
    return script


def _probe(tmp_path: Path, ss_body: str | None) -> dict[str, str]:
    """Rulează sonda cu un `ss` momeală (sau, cu None, FĂRĂ momeală: PATH-ul real) și întoarce
    câmpurile `KEY=value` pe care le tipărește."""
    binpath = tmp_path / "bin"
    binpath.mkdir()
    if ss_body is not None:
        _stub(binpath, "ss", ss_body)
    script = tmp_path / "probe.sh"
    script.write_text(_probe_script(), encoding="utf-8", newline="\n")
    environ = {**os.environ, "NO_COLOR": "1"}
    environ["PATH"] = binpath.as_posix() + os.pathsep + environ.get("PATH", "")
    proc = subprocess.run([BASH, script.as_posix()], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=environ)
    fields = dict(re.findall(r"^([A-Z0-9]+)=(.*)$", proc.stdout, re.M))
    assert "P80" in fields and "P443" in fields, \
        f"sonda nu a tipărit câmpurile:\n{proc.stdout}\n{proc.stderr}"
    return fields


def _table(*lines: str) -> str:
    text = "\n".join((HEADER, *lines))
    return f"cat <<'EOF'\n{text}\nEOF\nexit 0\n"


# ===========================================================================
# Sonda
# ===========================================================================
@pytest.mark.parametrize("ss_body,expected", [
    pytest.param(_table(L22, L80, L443), ("busy", "busy"), id="ambele-ocupate"),
    pytest.param(_table(L22, L80), ("busy", "free"), id="doar-80"),
    pytest.param(_table(L22), ("free", "free"), id="niciunul-dar-ss-a-raspuns"),
    pytest.param(_table(L22, L8080), ("free", "free"), id="8080-nu-e-80"),
])
def test_a_working_ss_still_gives_busy_and_free(tmp_path, ss_body, expected):
    """Contra-proba: cu un `ss` care ȘI răspunde, `busy`/`free` rămân ce erau — inclusiv
    nepotrivirea lui :8080 cu :80 (tiparul are spațiu la coadă). O sondă care ar răspunde
    `unknown` la tot ar trece testele de mai jos fără să mai deosebească nimic."""
    fields = _probe(tmp_path, ss_body)
    assert (fields["P80"], fields["P443"]) == expected, fields


@pytest.mark.parametrize("ss_body,why", [
    pytest.param("echo 'Error: netlink' >&2\nexit 1\n", "iese 1", id="ss-refuza"),
    pytest.param("echo 'ss: command not found' >&2\nexit 127\n", "lipseste", id="ss-lipseste"),
    pytest.param("exit 0\n", "iese 0 fara nimic", id="ss-tace"),
    pytest.param(f"cat <<'EOF'\n{HEADER}\n{L80}\nEOF\nexit 1\n",
                 "tipareste o tabela si iese 1", id="ss-tabela-si-esec"),
])
def test_an_ss_that_could_not_be_asked_is_unknown_not_free(tmp_path, ss_body, why):
    """Reproducerea. `ss | grep -qE` lăsa un `ss` căzut să ajungă la `grep` fără nicio linie —
    exact cum arată „liber” — iar wizard-ul spunea «portul 80 e liber» despre o gazdă pe care nu
    se măsurase nimic. Aici, `ss` ({why}) înseamnă `unknown` pe ambele porturi. Cazul «iese 0
    fără nimic» are control pozitiv în `ss -tln`: tipărește MEREU capul de tabel, deci un
    răspuns complet gol nu e o măsurătoare."""
    fields = _probe(tmp_path, ss_body)
    assert (fields["P80"], fields["P443"]) == ("unknown", "unknown"), (why, fields)


# ===========================================================================
# Consumatorul: secțiunea 3
# ===========================================================================
def _section3() -> str:
    start = WIZARD.index("# Trei raspunsuri de la sonda")
    end = WIZARD.index("# ---------------------------------------------------------------- 4. safety")
    block = WIZARD[start:end]
    assert "ask_choice NGINX_MODE" in block and "PORT80" in block, block[:200]
    return block


def _consume(tmp_path: Path, port80: str, port443: str, choice: str = "dedicated") -> str:
    """Rulează secțiunea 3 LIVRATĂ, sub `set -uo pipefail` ca wizard-ul, cu funcțiile de
    interfață înlocuite de unele care înregistrează."""
    script = tmp_path / "consume.sh"
    script.write_text(
        "set -uo pipefail\n"
        'warn() { echo "WARN: $*"; }\n'
        'info() { echo "INFO: $*"; }\n'
        'ask_choice() { local v="$1"; shift 2; echo "OPTIONS: $*"; printf -v "$v" "%s" "$CHOICE"; }\n'
        'ask() { printf -v "$1" "%s" 8443; }\n'
        f'PORT80="{port80}"\nPORT443="{port443}"\nNGINX_MODE=""\nCHOICE="{choice}"\n'
        + _section3() + '\necho "MODE=$NGINX_MODE"\n',
        encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, script.as_posix()], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"MODE={choice}" in proc.stdout, proc.stdout + proc.stderr
    return proc.stdout + proc.stderr


@pytest.mark.parametrize("value", ["unknown", "", "weird"])
def test_an_unknown_443_is_not_recommended_as_free(tmp_path, value):
    """Cu `[[ == busy ]] ... else`, orice altceva decât «busy» era tratat ca «free»: lista de
    opțiuni cu «(implicit sigur)» și niciun cuvânt despre faptul că nu s-a măsurat nimic. Un
    câmp lipsit (răspuns trunchiat: «») sau o valoare necunoscută se citesc la fel ca
    `unknown`: avertisment cu «NECUNOSCUT», iar «dedicated» (nu atinge nginx-ul existent)
    primul."""
    out = _consume(tmp_path, "unknown", value)
    assert "WARN:" in out and "NECUNOSCUT" in out and "portul 443" in out, out
    assert "(implicit sigur)" not in out and "deja ocupat" not in out, out
    options = next(ln for ln in out.splitlines() if ln.startswith("OPTIONS:"))
    assert options.index("dedicated:") < options.index("shared:"), options


def test_a_free_443_gets_the_options_it_always_got(tmp_path):
    """Contra-proba: `free` măsurat -> lista veche, cu «(implicit sigur)», fără avertisment
    despre 443."""
    out = _consume(tmp_path, "free", "free")
    assert "(implicit sigur)" in out and "NECUNOSCUT" not in out, out


def test_a_busy_443_gets_the_nginx_message_it_always_got(tmp_path):
    """Contra-proba pentru `busy`: mesajul despre nginx și `shared` primul, ca înainte."""
    out = _consume(tmp_path, "busy", "busy")
    assert "deja ocupat" in out and "NECUNOSCUT" not in out, out
    options = next(ln for ln in out.splitlines() if ln.startswith("OPTIONS:"))
    assert options.index("shared:") < options.index("dedicated:"), options


@pytest.mark.parametrize("port80,mode,says", [
    ("free", "dedicated", "portul 80 e liber, dar"),
    ("unknown", "dedicated", "NECUNOSCUT"),
    ("", "dedicated", "NECUNOSCUT"),
    ("busy", "dedicated", None),
    ("free", "shared", None),
    ("unknown", "shared", None),
])
def test_the_port_80_advice_follows_what_was_measured(tmp_path, port80, mode, says):
    """Sfatul despre :80 în modul dedicat (certbot nu-l poate folosi) se dă pe ce s-a măsurat:
    `free` -> «portul 80 e liber, dar…», `unknown` sau câmp lipsă -> avertisment «NECUNOSCUT» care NU
    afirmă «portul 80 e liber, dar…», `busy` și modul shared -> nimic despre 80. «Liber» spus pe `unknown` e
    exact citirea greșită pe care fișierul o închide."""
    out = _consume(tmp_path, port80, "free", choice=mode)
    lines80 = [ln for ln in out.splitlines() if "portul 80" in ln]
    if says is None:
        assert not lines80, out
        return
    assert lines80 and says in lines80[0], out
    if says == "NECUNOSCUT":
        assert "portul 80 e liber, dar" not in lines80[0], lines80[0]
