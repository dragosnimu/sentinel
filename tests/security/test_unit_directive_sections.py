"""Directivele systemd stau în secțiunea potrivită.

O directivă pusă în secțiunea greșită nu e o eroare: systemd scrie o linie în
jurnal — `Unknown key name '...' in section '...', ignoring` — pornește unitatea
și merge mai departe. Fișierul se citește ca și cum protecția ar exista, unitatea
rulează, nimic nu eșuează, iar protecția pur și simplu nu e acolo.

`StartLimitIntervalSec` și `StartLimitBurst` au stat în `[Service]` pe
sentinel-detect, cu un comentariu deasupra care explica exact ce trebuia să facă.
Nu făceau nimic. Găsit citind jurnalul după un deploy, nu de un test — de aceea
există fișierul ăsta.

Lista de mai jos nu e completă și nici nu încearcă să fie. Acoperă directivele
pe care le folosim și pe care e ușor să le pui greșit, fiindcă „limitarea
repornirilor" sună a comportament de serviciu și e, de fapt, o proprietate a
unității.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

UNITS_DIR = Path(__file__).resolve().parents[2] / "deploy" / "systemd"

# Directivă -> singura secțiune în care systemd o citește.
SECTION_OF = {
    # Limitarea ratei de pornire e a unității, nu a serviciului. Mutată în
    # [Unit] în systemd 229; în [Service] e acceptată tăcut și ignorată.
    "StartLimitIntervalSec": "Unit",
    "StartLimitBurst": "Unit",
    "StartLimitAction": "Unit",
    "OnFailure": "Unit",
    "Requires": "Unit",
    "Wants": "Unit",
    "After": "Unit",
    "Before": "Unit",
    "PartOf": "Unit",
    "Conflicts": "Unit",
    "Description": "Unit",
    "ConditionPathExists": "Unit",
    "RefuseManualStart": "Unit",
    # Iar astea sunt ale serviciului și nu au ce căuta în [Unit].
    "ExecStart": "Service",
    "ExecStop": "Service",
    "Restart": "Service",
    "RestartSec": "Service",
    "Type": "Service",
    "User": "Service",
    "Group": "Service",
    "TimeoutStartSec": "Service",
    "MemoryMax": "Service",
    "WorkingDirectory": "Service",
    "Environment": "Service",
    # Instalarea.
    "WantedBy": "Install",
    "RequiredBy": "Install",
}

_SECTION = re.compile(r"^\[(?P<name>[A-Za-z]+)\]\s*$")
_DIRECTIVE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9]*)=")


def _directives(path: Path) -> list[tuple[str, str, int]]:
    """(secțiune, directivă, linie) pentru fiecare directivă din fișier."""
    out: list[tuple[str, str, int]] = []
    section = ""
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        m = _SECTION.match(stripped)
        if m:
            section = m["name"]
            continue
        d = _DIRECTIVE.match(stripped)
        if d:
            out.append((section, d["key"], n))
    return out


UNIT_FILES = sorted(p for p in UNITS_DIR.iterdir()
                    if p.suffix in (".service", ".timer", ".target"))


def test_there_are_units_to_check():
    """O potrivire de fișiere care nu găsește nimic face ca toate testele
    parametrizate de mai jos să treacă fără să verifice ceva."""
    assert len(UNIT_FILES) >= 10, f"am găsit doar {len(UNIT_FILES)} unități"


@pytest.mark.parametrize("unit", UNIT_FILES, ids=lambda p: p.name)
def test_every_directive_is_in_the_section_systemd_reads(unit):
    wrong = []
    for section, key, line in _directives(unit):
        expected = SECTION_OF.get(key)
        if expected is None:
            continue          # nu e pe listă; nu ne pronunțăm
        # Timerele își au propria secțiune, cu directive omonime.
        if section == "Timer":
            continue
        if section != expected:
            wrong.append(f"linia {line}: {key} e în [{section}], "
                         f"systemd îl citește doar în [{expected}]")
    assert not wrong, f"{unit.name}:\n  " + "\n  ".join(wrong)


def test_the_detector_actually_gives_up_after_a_restart_loop():
    """Intenția scrisă în comentariul unității, verificată în locul potrivit.

    Fără asta, un detector care se rotește repornește la nesfârșit și continuă
    să ia decizii de blocare din stare pe jumătate inițializată — exact ce spune
    comentariul că nu trebuie să se întâmple.
    """
    unit = UNITS_DIR / "sentinel-detect.service"
    placed = {(s, k) for s, k, _ in _directives(unit)}
    assert ("Unit", "StartLimitIntervalSec") in placed
    assert ("Unit", "StartLimitBurst") in placed
    assert ("Service", "Restart") in placed, "restart-ul rămâne al serviciului"
