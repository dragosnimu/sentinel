"""Instalatorul și agentul trebuie să citească ACELAȘI număr din `interval_s`.

`beacon_interval_s()` din `deploy/install.sh` decide cât așteaptă
`smoke_beacon_is_beating` primul semnal după deploy: `limit = 2 * interval_s`.
Nimic nu compară valoarea aia cu ce citește agentul, deci un dezacord nu are
niciun simptom în afară de o probă de fum care se poartă ciudat — ori așteaptă
douăzeci de minute în tăcere, ori renunță prea devreme și tipărește un
avertisment despre un beacon sănătos, care e chiar felul în care operatorul
învață să treacă peste avertismentele instalatorului.

Vechea implementare era `awk ... | tr -dc '0-9'`, adică „șterge tot ce nu e
cifră". Măsurat:

    yaml 60     -> 60    (corect)
    yaml 60.0   -> 600   (fereastră de 20 de minute în loc de 2)
    yaml 0.5    -> 05    (adică 5)
    yaml 08     -> 08    -> `$(( 2 * 08 ))` omoară instalarea sub `set -e`, cu
                            „value too great for base", apoi „limit: unbound
                            variable"

Cât timp `_coerce` din `sentinel/config.py` lăsa un float din YAML neatins,
`interval_s: 60.0` era vizibil greșit peste tot — și în payload-ul semnat, unde
a fost și găsit. De când `_coerce` îl normalizează la `60`, funcția asta a rămas
SINGURUL cititor care mai înțelege altceva decât agentul.

**Testul central e `test_the_installer_reads_what_the_agent_reads`**: pentru
fiecare scalar, rulează funcția LIVRATĂ din `deploy/install.sh` și `load_config`
din agent pe ACELAȘI fișier, și cere fie același număr, fie un refuz explicit.
Restul fișierului sunt cazurile care au produs regula, ținute separat ca eșecul
să spună care anume s-a rupt.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sentinel.config import load_config
from sentinel.errors import ConfigError

REPO = Path(__file__).resolve().parents[2]
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")

_NO_BASH = (
    "bash lipsește din PATH, deci NU a rulat verificarea că instalatorul și "
    "agentul citesc același `interval_s`. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]

DEFAULT = "60"


def function_source() -> str:
    """Funcția așa cum se livrează, nu o copie."""
    match = re.search(r"^beacon_interval_s\(\)\s*\{.*?^\}", INSTALL, re.S | re.M)
    assert match, "beacon_interval_s nu mai există în install.sh"
    body = match.group(0)
    assert "tr -dc" not in body, (
        "`tr -dc '0-9'` s-a întors: șterge punctul în loc să-l înțeleagă, deci "
        "`60.0` devine `600`")
    return body


def run_installer(tmp_path: Path, yaml_text: str | None) -> tuple[str, str]:
    """(stdout, stderr) ale funcției livrate.

    Se face `source ./lib/common.sh` fiindcă funcția folosește `warn`, iar `warn`
    scrie pe STDERR. Dacă vreodată n-ar mai face-o, avertismentul ar ajunge în
    substituția de comandă din `smoke_beacon_is_beating` și `$(( 2 * ... ))` ar
    primi un text colorat în loc de un număr. De aia testele de mai jos se uită
    la cele două fluxuri separat.
    """
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    if yaml_text is not None:
        (cfg / "sentinel.yaml").write_text(yaml_text, encoding="utf-8", newline="\n")

    script = tmp_path / "harness.sh"
    script.write_text("source ./lib/common.sh\n" + function_source()
                      + "\nbeacon_interval_s\n",
                      encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        env={**os.environ, "NO_COLOR": "1",
             "SENTINEL_CONFIG_DIR": str(cfg).replace("\\", "/")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip(), proc.stderr


def read_interval(tmp_path: Path, yaml_text: str | None) -> str:
    return run_installer(tmp_path, yaml_text)[0]


def _yaml(value: str) -> str:
    return f"telegram:\n  enabled: false\nbeacon:\n  enabled: true\n  interval_s: {value}\n"


def agent_interval(tmp_path: Path, yaml_text: str):
    """Ce ajunge efectiv în `cfg.beacon.interval_s`, sau `None` dacă agentul
    refuză fișierul."""
    path = tmp_path / "agent.yaml"
    path.write_text(yaml_text, encoding="utf-8", newline="\n")
    try:
        return load_config(path).beacon.interval_s
    except ConfigError:
        return None


# ---------------------------------------------------------------------------
# Testul central: cele două capete, pe același fișier.
# ---------------------------------------------------------------------------
SCALARS = [
    "60", "90", "45",          # zecimale obișnuite
    "060", "0777",             # YAML 1.1 le citește OCTAL: 48 și 511
    "60.0", "60.00",           # float întreg, normalizat de `_coerce`
    "08",                      # nici zecimal, nici octal — PyYAML îl lasă ȘIR
    "00", "0",                 # zero
    '"90"', "'90'",            # ghilimele: `_coerce` lasă un ȘIR
    "0.5", "1.5",              # fracționar: `_coerce` ridică ConfigError
    "abc", "-30", "",          # non-număr, negativ, lipsă
]


@pytest.mark.parametrize("scalar", SCALARS, ids=lambda s: s or "(gol)")
def test_the_installer_reads_what_the_agent_reads(tmp_path, scalar):
    """Regula, aplicată pe fiecare formă: același număr, ori un refuz explicit.

    Eșecul pe care îl previne: instalatorul și agentul citesc numere diferite din
    ACELAȘI rând, iar singurul simptom e o probă de fum care se poartă ciudat.
    `060` e cazul care arată de ce nu se poate scrie „ia cifrele": YAML 1.1 îl
    citește octal, PyYAML întoarce 48, deci fereastra corectă e a lui 48. `08` e
    cazul care arată de ce nu se poate scrie „e un număr dacă are cifre".

    Un refuz e acceptabil doar dacă e SPUS: fereastra implicită plus un
    avertisment care numește câmpul. Un refuz tăcut ar fi tot un dezacord, doar
    invizibil.
    """
    text = _yaml(scalar)
    out, err = run_installer(tmp_path, text)
    agent = agent_interval(tmp_path, text)

    if isinstance(agent, int) and not isinstance(agent, bool) and agent > 0:
        assert out == str(agent), (
            f"instalatorul citește {out!r}, agentul {agent!r}, din același rând")
        assert "interval_s" not in err, (
            "avertisment pe o valoare pe care ambele capete o citesc la fel")
    else:
        # Agentul nu obține un număr de secunde utilizabil: șir, zero, negativ
        # sau ConfigError. Instalatorul nu are ce să potrivească, deci cade pe
        # valoarea implicită ȘI o spune.
        assert out == DEFAULT, f"agentul dă {agent!r}, instalatorul {out!r}"
        assert "beacon.interval_s" in err, err

    # Avertismentul nu are voie să ajungă în număr: `$(( 2 * ... ))` din
    # `smoke_beacon_is_beating` ar primi un text.
    assert re.fullmatch(r"[0-9]+", out), out


# ---------------------------------------------------------------------------
# Cazurile care au produs regula.
# ---------------------------------------------------------------------------
def test_a_plain_integer_is_read_as_itself(tmp_path):
    """Cazul de bază. Fără el, orice implementare care întoarce mereu valoarea
    implicită ar trece toate testele de mai jos."""
    assert read_interval(tmp_path, _yaml("90")) == "90"


def test_an_integral_float_is_read_as_the_integer_the_agent_will_use(tmp_path):
    """`interval_s: 60.0` — cazul care a produs tot E2.1.

    `_coerce` îl normalizează acum la `60`, deci beaconul bate la 60 de secunde.
    Vechiul `tr -dc '0-9'` scotea `600` de aici, iar proba de fum aștepta 1200 de
    secunde în loc de 120 — douăzeci de minute de tăcere pe consola unui deploy,
    fără nicio explicație pe ecran.
    """
    assert read_interval(tmp_path, _yaml("60.0")) == "60"
    assert read_interval(tmp_path, _yaml("60.00")) == "60"


def test_a_leading_zero_is_octal_because_that_is_what_pyyaml_does(tmp_path):
    """`interval_s: 060` înseamnă 48 de secunde, oricât de surprinzător e.

    Eșecul pe care îl previne: instalatorul „repară" zeroul din față cu `10#` sau
    tăindu-l, obține 60, iar agentul rămâne la 48. Ar fi o divergență NOUĂ,
    introdusă de o reparație — și exact clasa pe care funcția asta există s-o
    închidă. Premisa se verifică aici, nu se presupune.
    """
    assert agent_interval(tmp_path, _yaml("060")) == 48
    assert read_interval(tmp_path, _yaml("060")) == "48"
    assert agent_interval(tmp_path, _yaml("0777")) == 511
    assert read_interval(tmp_path, _yaml("0777")) == "511"


def test_a_value_that_is_not_a_number_names_the_field_instead_of_killing_bash(tmp_path):
    """`interval_s: 08` — nici zecimal, nici octal.

    Eșecul pe care îl previne, măsurat: `08` trecea de o verificare „numai
    cifre", ajungea în `$(( 2 * 08 ))`, iar sub `set -euo pipefail` instalarea
    murea cu „value too great for base (error token is \\"08\\")" și apoi cu
    „limit: unbound variable". Operatorul primea un mesaj despre interpretorul de
    shell în locul numelui câmpului — după o schimbare întreagă făcută tocmai ca
    să primească numele câmpului.
    """
    out, err = run_installer(tmp_path, _yaml("08"))
    assert out == DEFAULT
    assert "beacon.interval_s" in err
    assert "sentinel.yaml" in err
    assert "08" in err, "avertismentul nu spune ce a citit"
    # Și premisa: agentul nu obține nici el un număr din `08`.
    assert not isinstance(agent_interval(tmp_path, _yaml("08")), int)


def test_the_warning_never_lands_in_the_number(tmp_path):
    """`warn` scrie pe stderr, iar `$( )` capturează stdout.

    Eșecul pe care îl previne: avertismentul ajunge în substituția de comandă,
    `$(( 2 * "[!] beacon.interval_s ..." ))` cade, și instalarea moare exact în
    locul pe care avertismentul încerca să-l facă lizibil.
    """
    out, err = run_installer(tmp_path, _yaml("abc"))
    assert out == DEFAULT
    assert err.strip(), "refuzul e tăcut"
    assert "[!]" not in out and "beacon" not in out


def test_a_fractional_value_falls_back_instead_of_inventing_a_number(tmp_path):
    """`interval_s: 0.5` scotea `05` din cifrele rămase.

    `_coerce` respinge valoarea asta cu `ConfigError`, deci agentul nici nu
    pornește cu ea. Instalatorul nu are cum să ghicească ce s-a vrut, iar o cifră
    compusă din caracterele rămase e o invenție.
    """
    assert read_interval(tmp_path, _yaml("0.5")) == DEFAULT
    assert read_interval(tmp_path, _yaml("1.5")) == DEFAULT
    assert read_interval(tmp_path, _yaml("-30")) == DEFAULT


def test_a_quoted_scalar_is_refused_because_the_agent_refuses_it_too(tmp_path):
    """`interval_s: "90"` rămâne ȘIR și pentru agent.

    `_coerce` nu convertește un `str` la `int`, deci `asyncio.sleep('90')` ridică
    TypeError și beaconul moare la prima rundă. Instalatorul care ar citi 90 de
    acolo ar raporta o fereastră pentru un serviciu care nu pornește. Refuzul,
    cu numele câmpului în el, e singurul răspuns care descrie situația.
    """
    out, err = run_installer(tmp_path, _yaml('"90"'))
    assert out == DEFAULT
    assert "beacon.interval_s" in err
    assert not isinstance(agent_interval(tmp_path, _yaml('"90"')), int)


def test_a_trailing_comment_does_not_change_the_number(tmp_path):
    assert read_interval(tmp_path, _yaml("90  # o dată și jumătate")) == "90"


def test_an_unreadable_configuration_means_the_default_window(tmp_path):
    """„Nu știu" nu are voie să însemne „așteaptă oricât" — nici „nu aștepta"."""
    assert read_interval(tmp_path, None) == DEFAULT
    assert read_interval(tmp_path, "telegram:\n  enabled: false\n") == DEFAULT


def test_the_key_is_read_from_the_beacon_section_only(tmp_path):
    """Alt `interval_s`, din altă secțiune, nu are voie să câștige.

    Eșecul pe care îl previne: proba de fum ajustată după un interval care nu are
    nicio legătură cu beaconul, iar diagnosticul de după arată complet aiurea.
    """
    text = ("web:\n  interval_s: 999\n"
            "beacon:\n  enabled: true\n  interval_s: 45\n")
    assert read_interval(tmp_path, text) == "45"
