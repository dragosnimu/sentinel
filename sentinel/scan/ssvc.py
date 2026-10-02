"""Arborele CISA SSVC (Track / Track* / Attend / Act), ca date, nu ca praguri.

Culoarea unei vulnerabilități nu iese dintr-o formulă inventată aici, ci din
tabelul de decizie publicat de CISA/SEI. Tabelul de mai jos e **copiat
cuvânt cu cuvânt** din `data/csv/cisa/cisa_coordinator_2_0_3.csv` din
https://github.com/CERTCC/SSVC (ultima modificare a fișierului: commit
`c5be80f18`, 27 august 2025), iar
`tests/unit/test_ssvc_table.py` compară cele 36 de rânduri cu o copie a
fișierului publicat. Un rând schimbat aici fără ca CISA să-l fi schimbat se
vede imediat.

## Cele patru puncte de decizie ale arborelui, și de unde vin la noi

  * **Exploitation** (`none` / `poc` / `active`) — starea ACUTĂ a exploatării.
    `active` = dovadă publică, observabilă, că se exploatează în sălbăticie;
    pentru noi: apartenența la lista CISA KEV sau valoarea publicată de CISA
    (vezi `risk.py`). EPSS NU intră: e o previziune, nu o observație.
    `poc` = există exploit public; singura sursă e valoarea publicată de CISA.
  * **Automatable** (`no` / `yes`) — poate un atacator să automatizeze, de
    încredere, primii patru pași ai lanțului (recunoaștere, armare, livrare,
    exploatare)? Se deduce din vectorul CVSS (`cvss.py`).
  * **Technical Impact** (`partial` / `total`) — controlul obținut asupra
    componentei vulnerabile. Se deduce din vectorul CVSS (`cvss.py`).
  * **Mission and Well-Being** (`low` / `medium` / `high`) — cât contează
    activul. Vine din `criticality` a activului (`risk.py`).

CISA îl folosește pentru vulnerabilități care privesc guvernul SUA și
infrastructura critică; pagina CISA spune explicit că organizațiile al căror
mandat nu se potrivește ar trebui să se uite la celelalte arbori SEI (cel de
„Deployer" are alte puncte de decizie: expunerea sistemului, impactul uman).
Că arborele ăsta e cel potrivit pentru o singură gazdă care servește siturile
operatorului e decizia operatorului, nu a codului — de aceea tabelul e izolat
aici, într-un singur loc, și poate fi înlocuit fără să se atingă restul.

## Necunoscutul nu e „bine"

`decide` cere toate cele patru valori. `decide_range` primește `None` pentru
ce nu se știe și răspunde cu CELE DOUĂ capete: cea mai joasă și cea mai înaltă
decizie pe care o poate da orice completare posibilă. `risk.py` le folosește
doar ca să DESCRIE un gri („poate fi între Track și Act"), niciodată ca să-l
transforme în culoare: chiar și când ambele capete coincid (nimic nu se
exploatează, misiune medie: Track oricare ar fi CVSS-ul), constatarea rămâne gri,
fiindcă „verde" ar spune „am evaluat", iar un CVE fără scor nu e unul sigur.
"""

from __future__ import annotations

from itertools import product

EXPLOITATION = ("none", "poc", "active")
AUTOMATABLE = ("no", "yes")
TECHNICAL_IMPACT = ("partial", "total")
MISSION = ("low", "medium", "high")

#: Deciziile, în ordinea gravității. Indexul e folosit ca ordine: `track` < `act`.
TRACK, TRACK_STAR, ATTEND, ACT = "track", "track_star", "attend", "act"
DECISIONS = (TRACK, TRACK_STAR, ATTEND, ACT)

#: `exploitation, automatable, technical_impact, mission -> decizia`, în
#: ordinea fișierului publicat (rândurile 0..35). `public poc` e scris `poc`.
_PUBLISHED = """
none,no,partial,low,track
none,no,partial,medium,track
none,no,partial,high,track
none,no,total,low,track
none,no,total,medium,track
none,no,total,high,track*
none,yes,partial,low,track
none,yes,partial,medium,track
none,yes,partial,high,attend
none,yes,total,low,track
none,yes,total,medium,track
none,yes,total,high,attend
poc,no,partial,low,track
poc,no,partial,medium,track
poc,no,partial,high,track*
poc,no,total,low,track
poc,no,total,medium,track*
poc,no,total,high,attend
poc,yes,partial,low,track
poc,yes,partial,medium,track
poc,yes,partial,high,attend
poc,yes,total,low,track
poc,yes,total,medium,track*
poc,yes,total,high,attend
active,no,partial,low,track
active,no,partial,medium,track
active,no,partial,high,attend
active,no,total,low,track
active,no,total,medium,attend
active,no,total,high,act
active,yes,partial,low,attend
active,yes,partial,medium,attend
active,yes,partial,high,act
active,yes,total,low,attend
active,yes,total,medium,act
active,yes,total,high,act
"""

_WORD = {"track": TRACK, "track*": TRACK_STAR, "attend": ATTEND, "act": ACT}


def _load() -> dict[tuple[str, str, str, str], str]:
    table: dict[tuple[str, str, str, str], str] = {}
    for line in _PUBLISHED.strip().splitlines():
        e, a, ti, m, word = line.split(",")
        key = (e, a, ti, m)
        if key in table or word not in _WORD:
            raise RuntimeError(f"tabelul SSVC e stricat la rândul {line!r}")
        table[key] = _WORD[word]
    # Complet, nu doar fără dubluri: un rând lipsă ar face `decide` să arunce
    # KeyError la prima vulnerabilitate care îl atinge, adică în mijlocul unei
    # scanări, nu la import.
    expected = set(product(EXPLOITATION, AUTOMATABLE, TECHNICAL_IMPACT, MISSION))
    if set(table) != expected:
        raise RuntimeError("tabelul SSVC nu acoperă toate combinațiile")
    return table


TABLE: dict[tuple[str, str, str, str], str] = _load()


def decide(exploitation: str, automatable: str, technical_impact: str,
           mission: str) -> str:
    """Decizia pentru o combinație COMPLETĂ de valori.

    O valoare din afara vocabularului e o eroare de programare, nu o dată
    lipsă: ridică `ValueError`, ca să nu devină tăcut un „track".
    """
    try:
        return TABLE[(exploitation, automatable, technical_impact, mission)]
    except KeyError:
        raise ValueError(
            "valori SSVC necunoscute: "
            f"{exploitation!r}, {automatable!r}, {technical_impact!r}, {mission!r}"
        ) from None


def decide_range(exploitation: str | None, automatable: str | None,
                 technical_impact: str | None,
                 mission: str | None) -> tuple[str, str]:
    """`(cea mai joasă, cea mai înaltă)` decizie peste toate completările lui
    `None`.

    Cu toate valorile cunoscute cele două capete sunt egale și întorc `decide`.
    Valorile CUNOSCUTE dar în afara vocabularului ridică, ca la `decide`: doar
    `None` înseamnă „nu se știe".
    """
    spaces = (
        (EXPLOITATION, exploitation), (AUTOMATABLE, automatable),
        (TECHNICAL_IMPACT, technical_impact), (MISSION, mission),
    )
    options: list[tuple[str, ...]] = []
    for vocabulary, value in spaces:
        if value is None:
            options.append(vocabulary)
        elif value in vocabulary:
            options.append((value,))
        else:
            raise ValueError(f"valoare SSVC necunoscută: {value!r}")
    results = [TABLE[combo] for combo in product(*options)]
    rank = DECISIONS.index
    return min(results, key=rank), max(results, key=rank)


def demote(decision: str) -> str:
    """O treaptă mai jos (`act` -> `attend` -> `track_star` -> `track`); `track`
    rămâne `track`. Folosit pentru „reparația e instalată, așteaptă repornirea"."""
    index = DECISIONS.index(decision)
    return DECISIONS[max(0, index - 1)]


#: Decizia -> culoarea semaforului. `track_star` e verde: CISA îi dă același
#: termen de remediere ca lui `track` („în ciclul obișnuit de actualizare"),
#: dar rămâne vizibil ca decizie, cu steluță, și se ordonează deasupra lui.
COLOR_OF = {ACT: "red", ATTEND: "amber", TRACK_STAR: "green", TRACK: "green"}
