"""Vectori CVSS: ce poate citi Sentinel din ei, și cât de mult.

Un vector CVSS (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) spune CUM se
exploatează o vulnerabilitate și CE se pierde. Din el scoatem trei lucruri.

**Automatable și Technical Impact de aici sunt REZERVA.** CISA publică valorile ei
pentru fiecare CVE pe care l-a evaluat (`sentinel/intel/vulnrichment.py`), iar
`risk.py` le folosește întâi; euristicile de mai jos decid doar pentru CVE-urile
pe care CISA nu le-a evaluat. Pe gazda de producție (2 octombrie 2026) CISA a
publicat puncte pentru 196 din cele 406 CVE-uri distincte deschise = 48,3%, dar
acoperirea depinde de ecosistem, nu de gazdă: npm 78/78, composer 36/36, go 45/57,
alpine 13/16, **deb 13/185 (7%)**, rpm 6/32 (19%). Euristicile decid deci pentru
CVE-urile de nucleu și de pachete Debian, nu pentru o coadă rară. Măsurat pe cele
189 de CVE-uri cu vector și cu valoare CISA: Automatable din vector se potrivește
în 151 de cazuri (80%), Technical Impact cu `C:H` ȘI `I:H` în 179 (95%), cu `C:H`
SAU `I:H` în 149 (79%).

  * **scorul de bază** (doar v3.x) — pentru vectorii care vin FĂRĂ scor. OSV
    întoarce `{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}`, adică vectorul
    în locul numărului. Formula e cea din specificația FIRST v3.1, verificată în
    `tests/unit/test_cvss.py` contra tuturor perechilor (vector, scor) măsurate
    pe gazda de producție (571 de rânduri), nu doar contra două exemple.
  * **Automatable** (SSVC) — `yes` dacă atacul e din rețea, de complexitate
    mică, fără privilegii și fără interacțiunea unui utilizator
    (`AV:N/AC:L/PR:N/UI:N`; la v4 și `AT:N`). Asta e definiția dată de operator;
    ea acoperă pașii de recunoaștere, livrare și exploatare, nu și „armarea",
    pe care un vector n-o poate spune — o aproximare, numită ca atare. La v4,
    metrica suplimentară `AU` (Automatable) e însăși răspunsul SSVC și are
    prioritate când e prezentă și definită.
  * **Technical Impact** (SSVC) — `total` dacă se pierde complet ȘI confidențialitatea
    ȘI integritatea componentei vulnerabile (`C:H` **și** `I:H`; la v4 `VC:H`
    **și** `VI:H`), altfel `partial`. `A:H` singur rămâne `partial`: o cădere de
    serviciu nu dă control și nu dezvăluie nimic.

    **Dacă te gândești să schimbi „și" în „sau" fiindcă „definiția spune sau": asta
    s-a făcut o dată, și a fost greșit.** Definiția SSVC a lui `total` e „control
    total asupra comportamentului software-ului **sau** dezvăluirea totală a întregii
    informații **de pe sistem**" (CERT/CC, `technical_impact.py`) — două căi, și
    se pare că `C:H` ar fi a doua. Dar cele două scări nu măsoară același lucru:
    SSVC vorbește despre SISTEM, iar CVSS `C:H` e pierdere totală „în interiorul
    **componentei** afectate". Un `C:H` nu înseamnă că s-a dezvăluit tot ce e pe
    sistem, doar tot ce ține de componentă; citit ca `total`, `C:H` supra-citește
    CVSS-ul. Practica CISA e citirea apropiată de definiție, nu o abatere de la
    ea. Măsurat pe cele 189 de CVE-uri ale gazdei cu vector și valoare CISA:
    „și" se potrivește cu CISA în 179 de cazuri (95%), „sau" în 149 (79%), iar 19
    din 20 de CVE-uri cu `C:H` fără `I:H` sunt `partial` la CISA. O versiune
    anterioară a acestui fișier a folosit „sau"; a fost o instrucțiune greșită,
    corectată pe dovada asta.

    Pe gazda de producție, între „și" și „sau" nu se mută niciun rând (cele 812,
    la misiune medie și mare): cu Exploitation `none` Technical Impact nu decide
    culoarea (vezi tabelul din `ssvc.py`; schimbă doar Track ↔ Track*), iar
    singurele rânduri cu Exploitation `poc` sau `active` au valoarea publicată de
    CISA, deci nu trec pe aici. Alegerea contează numai pentru un CVE pe care CISA
    nu l-a evaluat și care e totuși în KEV.

Un vector pe care nu-l înțelegem — v2, un vector tăiat, o valoare în afara
specificației — dă `None`, adică „nu se știe". Niciodată un `partial` sau un
`no` ghicit: din `None` iese un gri, din ghicit iese o culoare falsă.

`parse` nu aruncă niciodată: vectorul vine din ieșirea unui scaner sau dintr-un
API terț, iar un rând ciudat nu are voie să oprească scanarea.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

_V3_VALUES: dict[str, str] = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "HLN", "I": "HLN", "A": "HLN",
}
_V4_VALUES: dict[str, str] = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
}


@dataclass(frozen=True)
class Vector:
    version: str                 # "3.0" | "3.1" | "4.0"
    metrics: dict[str, str]
    raw: str


def parse(value: Any) -> Vector | None:
    """Vectorul ca `Vector`, sau `None` dacă nu e un vector CVSS v3/v4 întreg."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    parts = text.split("/")
    if not parts or not parts[0].startswith("CVSS:"):
        return None
    version = parts[0][5:]
    if version in ("3.0", "3.1"):
        required = _V3_VALUES
    elif version == "4.0":
        required = _V4_VALUES
    else:
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep or not key or not val:
            return None
        # Prima apariție câștigă; o metrică dublată e un vector stricat.
        if key in metrics:
            return None
        metrics[key] = val
    for key, allowed in required.items():
        val = metrics.get(key)
        if val is None or len(val) != 1 or val not in allowed:
            return None
    return Vector(version=version, metrics=metrics, raw=text)


# --- scorul de bază v3.x -----------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup_31(x: float) -> float:
    # Specificația v3.1, apendicele A: întregi, ca să nu intre în joc zecimalele
    # binare (`ceil(4.000000000000001 * 10)` ar da 4.1).
    as_int = round(x * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def _roundup_30(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def base_score(vector: Vector | None) -> float | None:
    """Scorul de bază CVSS v3.0/v3.1, 0.0–10.0, sau `None`.

    Pentru v4.0 întoarce `None`: scorul v4 vine dintr-un tabel de 270 de intrări
    pe care n-are rost să-l copiem aici pentru trei vectori; apelantul cade pe
    scorul pe care sursa îl dă, iar dacă nici ăla nu există, importanța se
    estimează din severitate și spune că e o estimare.
    """
    if vector is None or vector.version not in ("3.0", "3.1"):
        return None
    m = vector.metrics
    changed = m["S"] == "C"
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    roundup = _roundup_31 if vector.version == "3.1" else _roundup_30
    raw = (impact + exploitability) * (1.08 if changed else 1.0)
    return roundup(min(raw, 10.0))


# --- punctele de decizie SSVC deduse din vector -------------------------------
def automatable(vector: Vector | None) -> str | None:
    """`"yes"` / `"no"` (SSVC Automatable), sau `None` dacă vectorul lipsește."""
    if vector is None:
        return None
    m = vector.metrics
    if vector.version == "4.0":
        # Metrica suplimentară AU e chiar punctul de decizie SSVC. `X` și lipsa
        # înseamnă „nedefinit": atunci rămâne euristica de mai jos.
        explicit = m.get("AU")
        if explicit == "Y":
            return "yes"
        if explicit == "N":
            return "no"
        wide_open = (m["AV"] == "N" and m["AC"] == "L" and m["AT"] == "N"
                     and m["PR"] == "N" and m["UI"] == "N")
    else:
        wide_open = (m["AV"] == "N" and m["AC"] == "L"
                     and m["PR"] == "N" and m["UI"] == "N")
    return "yes" if wide_open else "no"


def technical_impact(vector: Vector | None) -> str | None:
    """`"total"` / `"partial"` (SSVC Technical Impact), sau `None`."""
    if vector is None:
        return None
    m = vector.metrics
    # `și`, nu `sau`: vezi docstring-ul modulului (componentă contra sistem).
    if vector.version == "4.0":
        total = m["VC"] == "H" and m["VI"] == "H"
    else:
        total = m["C"] == "H" and m["I"] == "H"
    return "total" if total else "partial"
