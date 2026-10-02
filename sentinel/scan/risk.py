"""Evaluarea unei constatări: semafor SSVC, două axe, și numărul de ordonare.

Înlocuiește `prioritize.score`. Formula veche aduna puncte (bază + KEV + EPSS×20 +
expunere + criticitate) și le tăia la 100; pe producție asta dădea 80-90 pentru
212 din cele 218 constatări `dnf` deschise și 70-100 pentru toate cele 594 trivy:
un număr care nu mai deosebea nimic. Aici nu mai există puncte. Există:

  * **culoarea**, din arborele CISA SSVC (`ssvc.py`): roșu = Act, galben =
    Attend, verde = Track* / Track, **gri = nu se poate decide**;
  * **două axe**, afișate separat:
      - *importanța* = impactul dacă se exploatează (CVSS 0–10 al sursei
        aleasă, cu `Technical Impact` SSVC alături);
      - *urgența* = cât de repede trebuie făcut ceva = decizia SSVC (Act >
        Attend > Track* > Track), coborâtă o treaptă când reparația e deja
        instalată și lipsește doar o repornire;
  * **scorul de ordonare** `probabilitate × impact` (0–1): CVSS e impactul dacă
    se exploatează, EPSS e probabilitatea să se exploateze, iar o medie ar pune
    egal un CVSS 9,8 cu EPSS 0,001 și unul de 5,0 cu EPSS 0,6. Se folosește DOAR
    ca să se ordoneze în interiorul unei culori (documentația SSVC recomandă
    exact asta: EPSS brut drept cheie secundară), nu ca să se aleagă culoarea —
    nici măcar punctul Exploitation, care e o observație, nu o previziune.
    **O singură excepție, a Sentinel și numită ca atare:** suprapunerea EPSS
    peste o fotografie CISA veche (vezi „Ce e al Sentinel", mai jos).

## De unde vine fiecare punct de decizie

Fiecare punct își scrie în `risk.points.<punct>.basis` SURSA care l-a decis, iar un
punct luat de la CISA își scrie și data evaluării (`as_of`): o valoare publicată e o
fotografie, și trebuie să se vadă cât e de veche.

  * **Exploitation** — ce s-a OBSERVAT, nu ce se prezice:
      1. `active`, `basis = kev` — CVE-ul e în CISA KEV (oglindă la zi);
      2. valoarea publicată de CISA (`vulnrichment.py`: `none` / `poc` / `active`),
         `basis = vulnrichment`;
      3. altfel, dacă CISA n-a evaluat CVE-ul și nu e în KEV:
         `UNPUBLISHED_EXPLOITATION` (`none`), `basis = kev_absent` — o presupunere
         numită ca atare, vezi mai jos.
    **EPSS nu mai intră aici.** SSVC definește Exploitation ca stare observată;
    EPSS e o previziune, iar a deriva o observație dintr-o previziune e aceeași
    greșeală ca media dintre CVSS și EPSS, pe care am respins-o de la început.
    Măsurat pe CVE-urile gazdei: cele trei KEV au EPSS 0,006–0,014 (un prag EPSS le-ar
    fi pierdut pe toate trei), iar două CVE-uri cu EPSS 0,92 și 0,99 au la CISA
    `none` (fotografii din 2024 și 2025). Un prag greșește în ambele sensuri.
    EPSS rămâne probabilitatea din numărul de ordonare și se afișează întreg.
  * **Automatable**, **Technical Impact** — valoarea publicată de CISA
    (`basis = vulnrichment`); doar când CISA n-a evaluat CVE-ul, euristica din
    vectorul CVSS (`basis = cvss_vector`, `cvss.py`). Pe o gazdă neexpusă
    Automatable e `no` (`basis = asset_not_exposed`).
  * **Mission and Well-Being** — din `criticality` a activului: 1–2 = low,
    3 = medium, 4–5 = high. Constatările de azi primesc implicit 3 (legarea de un
    activ anume e muncă amânată: o potrivire greșită ar muta o vulnerabilitate
    pe alt sistem), deci aici toate sunt `medium`. Decizie a operatorului.

### Ce e al Sentinel și ce nu

Prima variantă avea două tăieturi EPSS (`EPSS_ACTIVE = 0,90` și `EPSS_POC = 0,50`)
care hotărau punctul Exploitation. Erau alegerile noastre (documentația SSVC pomenește
90% doar ca exemplu, iar banda „more likely than not" are acolo efectul PoC → Active,
nu none → PoC) și au fost scoase odată cu EPSS din decizie. **Acum sunt înapoi două cifre
ale Sentinel care folosesc EPSS, de data asta nu la punctul Exploitation, ci la
culoare, și sunt ale noastre — nu ale SSVC și nu ale FIRST.** Rămân, în total, trei
lucruri care sunt ALE NOASTRE și se numesc așa:

  * **suprapunerea EPSS peste o fotografie CISA veche** (`OVERLAY_MIN_AGE_DAYS = 180`,
    `OVERLAY_MIN_EPSS = 0,5`, `OVERLAY_FLOOR = attend`): dacă evaluarea CISA a
    exploatării (`none` sau `poc`) are mai mult de 180 de zile ȘI EPSS-ul de azi e cel
    puțin 0,5, culoarea nu coboară sub galben. Ce o face apărabilă nu e că EPSS e mare
    (asta singur e o previziune, exact ce am scos), ci că observația pe care EPSS-ul o
    contrazice **n-a mai fost reîmprospătată**: pentru CVE-2025-29927 `Exploitation:
    none` e o fotografie din 8 aprilie 2025, 542 de zile la 2 octombrie 2026; dintre
    cele 196 de evaluări CISA ale gazdei, 44 au peste un an (mediana: 141 de zile).
    Cele două cifre sunt alese, nu publicate: 180 de zile e aprobarea operatorului,
    iar 0,5 înseamnă „mai probabil decât nu" în cuvinte. Pe cele 403 CVE-uri cu EPSS ale
    gazdei, orice prag din (0,0456; 0,5918] prinde aceleași trei CVE-uri (golul e al
    gazdei, nu al lumii: în fișierul FIRST de 381.682 de CVE-uri, 4.317 au EPSS ≥ 0,5),
    deci cifra nu e „validată" de date, ci de înțelesul ei. Regula NU schimbă niciun
    punct de decizie (`points` rămâne ce a publicat CISA) și NU șterge decizia SSVC,
    scrisă în `risk.overlay.ssvc_decision`: ridică doar culoarea și o spune în
    `risk.overlay` (`basis = epss_overlay`). Se aplică după coborârea pentru repornire
    (podeaua e podea), nu se aplică unui gri (necunoscutul nu devine galben) și nici
    unui CVE a cărui exploatare e deja `active`/KEV (nu e o observație contrazisă);
    o evaluare CISA fără dată nu poate fi dovedită proaspătă, deci se tratează ca veche;
  * `UNPUBLISHED_EXPLOITATION` — ce punem când nici KEV, nici CISA nu spun nimic;
  * cât de des reluăm cererile către CISA (`vulnrichment.FOUND_DAYS` ș.a.), care
    mută doar CÂT DE REPEDE ajunge o evaluare nouă, nu ce decide arborele.

Ce nu e al nostru: tabelul de decizie (CISA Coordinator 2.0.3, `ssvc.py`) și
valorile punctelor, când vin de la CISA.

## Necunoscutul nu e verde

O decizie se ia doar cu toate cele patru puncte cunoscute. Lipsește unul — niciun
vector CVSS și niciun punct publicat, niciun CVE, oglinda KEV veche, un CVE pe care
nu l-am întrebat încă la CISA (sursa e căzută sau trecerea n-a ajuns la el), un aviz
fără CVE — și constatarea e **gri**, cu lista lipsurilor în `risk.missing` și cu
cele două capete posibile (`risk.possible`) ca să se vadă cât de rău poate fi. Gri se
ordonează deasupra lui verde: un CVE fără scor nu e unul sigur.

„CISA n-a evaluat CVE-ul" NU e „necunoscut": e un răspuns (rândul există, fără
puncte). Fără deosebirea asta, jumătate din rândurile gazdei de producție ar fi gri:
Exploitation vine din `kev_absent` la 395 din 812 rânduri (49%, 2 octombrie 2026).

EPSS lipsă sau vechi nu mai face un rând gri: nu mai e un punct de decizie. Numărul
de ordonare rămâne fără probabilitate (`risk_score` NULL), iar rândul stă la baza
benzii lui.

`assess` nu ridică. O intrare ciudată dă gri, nu o excepție în mijlocul scanării.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from sentinel.intel import epss as epss_mod
from sentinel.intel import osv as osv_mod
from sentinel.intel import redhat as redhat_mod
from sentinel.intel import vulnrichment as vr_mod
from sentinel.scan import cvss, ssvc

#: Versiunea formei lui `findings.risk`. Cine citește `risk` (panou, Telegram,
#: agregator) o verifică; o formă nouă ridică numărul.
SCHEMA_VERSION = 1

#: Ce valoare ia Exploitation pentru un CVE pe care CISA NU l-a evaluat și care nu e
#: în KEV (oglinda KEV la zi). **Alegerea Sentinel, nu o regulă publicată.** „Nu e în
#: KEV" înseamnă „nimeni nu l-a văzut exploatat activ"; despre un exploit public nu
#: spune nimic, deci `none` e o presupunere onestă, nu o observație — iar `basis`
#: spune `kev_absent`, nu `vulnrichment`. La misiune medie nu mută nicio culoare
#: (între `none` și `poc` arborele schimbă doar Track ↔ Track*, ambele verzi). `None`
#: ar face gri orice CVE neevaluat de CISA, adică pe gazda de producție **395 din 812
#: rânduri (49%)**, o pagină cu mai mult gri decât informație. CISA a publicat puncte
#: pentru 196 din cele 406 CVE-uri distincte deschise (48,3%), dar pe ecosistem: npm
#: 78/78, composer 36/36, go 45/57, alpine 13/16, **deb 13/185 (7%)**, rpm 6/32 (19%).
#: Deci presupunerea de aici nu e un colț rar: hotărăște despre jumătate din rânduri,
#: iar cele 185 de CVE-uri Debian de nucleu o poartă aproape toate.
UNPUBLISHED_EXPLOITATION: str | None = "none"

#: CISA KEV nu se mai consideră „da/nu" dacă oglinda n-a mai fost reîmprospătată
#: de atâtea zile: un „nu e în KEV" dintr-o oglindă de o lună e o presupunere.
KEV_MAX_AGE_DAYS = 7

#: ===== REGULA SENTINEL: EPSS peste o fotografie CISA veche ========================
#: **Alegerea Sentinel. Nu e regulă SSVC și nu e regulă FIRST**: nicio sursă nu spune
#: „un EPSS ≥ 0,5 lângă o evaluare de peste 180 de zile urcă la galben". Cele două cifre
#: sunt ale noastre (vezi „Ce e al Sentinel" în docstring-ul modulului): 180 de zile e
#: aprobarea operatorului, 0,5 înseamnă „mai probabil decât nu". Au mai fost aici, sub
#: alt chip, în runda 1 (0,90 / 0,50, la punctul Exploitation); au fost scoase în runda 2
#: și revin acum, la culoare, fiindcă justificarea e alta: observația pe care o
#: contrazice EPSS-ul n-a mai fost reîmprospătată.
#: Vârsta e a evaluării CISA (`ssvc_at`), nu a descărcării: o fotografie descărcată ieri
#: dintr-o evaluare din 2025 rămâne veche.
OVERLAY_MIN_AGE_DAYS = 180
OVERLAY_MIN_EPSS = 0.5
#: Podeaua: decizia nu coboară sub asta. `attend` = galben.
OVERLAY_FLOOR = ssvc.ATTEND
OVERLAY_BASIS = "epss_overlay"

GREY = "grey"

#: Benzile priorității 0..100: `(bază, lățime)`. Ordinea benzilor e ordinea în
#: care se citește lista: Act > Attend > gri > Track* > Track.
_BANDS: dict[str, tuple[int, int]] = {
    ssvc.ACT: (80, 21),
    ssvc.ATTEND: (60, 20),
    GREY: (40, 20),
    ssvc.TRACK_STAR: (20, 20),
    ssvc.TRACK: (0, 20),
}

#: Importanța estimată din severitatea categorică, FOLOSITĂ NUMAI când nu avem
#: niciun scor CVSS numeric (vector v4 fără scor, sursă care nu dă scor). Mijlocul
#: intervalelor calitative FIRST: Low 0,1–3,9 · Medium 4–6,9 · High 7–8,9 ·
#: Critical 9–10. Se marchează `estimated`.
_SEVERITY_IMPACT = {"critical": 0.95, "high": 0.80, "medium": 0.55,
                    "low": 0.20, "info": 0.05}

#: Etichetele pentru operator. O singură listă, ca panoul, Telegram-ul și
#: agregatorul să nu le scrie în trei feluri.
DECISION_LABEL_RO = {
    ssvc.ACT: "Act — acum",
    ssvc.ATTEND: "Attend — accelerat",
    ssvc.TRACK_STAR: "Track* — de urmărit",
    ssvc.TRACK: "Track — ciclul obișnuit",
    None: "fără date",
}
COLOR_LABEL_RO = {"red": "roșu", "amber": "galben", "green": "verde", "grey": "gri"}
COLOR_EMOJI = {"red": "🔴", "amber": "🟡", "green": "🟢", "grey": "⚪"}

#: Ordinea culorilor în liste: roșu, galben, gri, verde.
COLOR_ORDER = {"red": 0, "amber": 1, "grey": 2, "green": 3}


def mission_for(criticality: int) -> str:
    """`criticality` 1–5 al activului -> Mission and Well-Being SSVC."""
    return "low" if criticality <= 2 else ("medium" if criticality == 3 else "high")


def priority_of(decision: str | None, x: float | None) -> int:
    """`findings.priority` 0..100 din (decizie, număr 0..1).

    `decision` None = gri. `x` e scorul de ordonare (probabilitate × impact) sau,
    pentru gri, importanța; None se tratează ca 0. Priorități egale se desfac în
    SQL prin `risk_score` (vezi `list_open`): aici rezoluția e de 20 de trepte pe
    bandă, nu de 20 de poziții în listă.
    """
    base, width = _BANDS[decision if decision is not None else GREY]
    value = 0.0 if x is None or not math.isfinite(x) else min(1.0, max(0.0, x))
    return base + int(round(value * (width - 1)))


#: Prioritatea unui rând nou-venit, înainte de prima evaluare: gri, fără date.
UNASSESSED_PRIORITY = priority_of(None, None)


@dataclass
class Intel:
    """Tot ce se știe din afara constatării, încărcat o dată pe trecere."""
    epss: Mapping[str, epss_mod.Row] = field(default_factory=dict)
    redhat: Mapping[str, redhat_mod.Row] = field(default_factory=dict)
    osv: Mapping[str, osv_mod.Row] = field(default_factory=dict)
    #: Punctele SSVC publicate de CISA. Un CVE ABSENT de aici e „nu l-am întrebat
    #: încă" (necunoscut); unul prezent fără puncte e „CISA nu l-a evaluat".
    vulnrichment: Mapping[str, vr_mod.Row] = field(default_factory=dict)
    kev: Mapping[str, date | None] = field(default_factory=dict)
    #: Oglinda KEV există și nu e prea veche. Fără ea, „nu e în KEV" e necunoscut.
    kev_usable: bool = False
    today: date = field(default_factory=date.today)


@dataclass
class Assessment:
    color: str
    decision: str | None
    score: float | None
    importance: float | None
    priority: int
    kev: bool
    kev_due: date | None
    cvss_score: float | None
    cvss_vector: str | None
    #: Valorile de scris în coloanele `cvss` / `cvss_vector` DOAR dacă acolo nu e
    #: dovada scanerului (vezi `_scanner_candidate`); None = nu se atinge.
    write_cvss: bool
    epss: float | None
    epss_percentile: float | None
    risk: dict[str, Any]


def _prev_cvss(f: Mapping[str, Any]) -> dict[str, Any]:
    prev = f.get("risk")
    if isinstance(prev, dict):
        c = prev.get("cvss")
        if isinstance(c, dict):
            return c
    return {}


def _same_number(a: Any, b: Any) -> bool:
    """Aceeași valoare, cu „fără scor" egal cu „fără scor".

    `None` și `None` sunt ACEEAȘI valoare, nu „necunoscut vs. necunoscut": un vector
    CVSS v4 adus de OSV vine fără scor (nu îl calculăm), iar coloana `cvss` rămâne
    NULL lângă el. Dacă `None == None` ar fi fals, la trecerea următoare vectorul
    scris de noi ar fi luat drept dovadă a scanerului, sursa ar sări din „osv" în
    „trivy", iar evaluarea s-ar rescrie la fiecare trecere cu sursa greșită
    (prins la repetiția cu datele reale: 7 rânduri „schimbate" la a doua trecere).
    """
    if a is None or b is None:
        return a is None and b is None
    try:
        return abs(float(a) - float(b)) < 1e-9
    except (TypeError, ValueError):
        return False


def _scanner_candidate(f: Mapping[str, Any]) -> tuple[str, float | None, str | None] | None:
    """Evidența PROPRIE a scanerului (trivy dă scor + vector), sau None.

    Coloanele `cvss` / `cvss_vector` pot conține și ce am scris NOI la o trecere
    anterioară (vector de la Red Hat pentru un rând `dnf`, de exemplu), iar a le
    citi înapoi ca dovadă a scanerului ar atribui evaluarea Red Hat lui trivy.
    Dacă în `risk.cvss` stă o sursă de-a noastră și valorile coincid cu
    coloanele, coloanele sunt scrisul nostru, nu al scanerului.
    """
    score, vector = f.get("cvss"), f.get("cvss_vector")
    if score is None and not vector:
        return None
    prev = _prev_cvss(f)
    if (prev.get("source") in ("redhat", "osv")
            and _same_number(score, prev.get("score"))
            and (vector or None) == (prev.get("vector") or None)):
        return None
    label = "trivy" if str(f.get("scanner", "")).startswith("trivy") else str(f.get("scanner") or "scaner")
    return label, (None if score is None else float(score)), (vector or None)


def _pick_cvss(f: Mapping[str, Any], cve: str | None, intel: Intel) -> dict[str, Any] | None:
    """Alege O singură evaluare CVSS: scor și vector din ACEEAȘI sursă.

    Ordinea (cerută de operator: furnizorul înainte de rest, cu sursa numită):
      1. Red Hat, pentru pachete rpm;
      2. evidența scanerului însuși;
      3. OSV, după CVE și apoi după id-ul avizului.
    Prima care are un VECTOR citibil câștigă (din vector ies Automatable și
    Technical Impact); dacă nici una n-are, prima care are măcar un scor, ca
    importanța să fie măsurată, iar punctele de decizie rămân necunoscute.
    """
    cands: list[dict[str, Any]] = []
    if f.get("ecosystem") == "rpm" and cve:
        rh = intel.redhat.get(cve)
        if rh is not None and rh.status == "found" and (rh.vector or rh.score is not None):
            cands.append({"source": "redhat", "score": rh.score, "vector": rh.vector,
                          "vendor_severity": rh.severity})
    own = _scanner_candidate(f)
    if own is not None:
        cands.append({"source": own[0], "score": own[1], "vector": own[2]})
    for key in (cve, f.get("advisory_id")):
        row = intel.osv.get(key) if key else None
        if row is not None and row.status == "found" and (row.vector or row.score is not None):
            cands.append({"source": "osv", "score": row.score, "vector": row.vector,
                          "vendor_severity": row.severity})
            break

    parsed = [(c, cvss.parse(c.get("vector"))) for c in cands]
    for c, vec in parsed:
        if vec is not None:
            score = c["score"] if c["score"] is not None else cvss.base_score(vec)
            return {**c, "score": score, "vec": vec, "version": vec.version}
    for c, _ in parsed:
        if c["score"] is not None:
            return {**c, "vec": None, "vector": None, "version": None}
    return None


def _point(value: str | None, basis: str | None, as_of: str | None) -> dict[str, Any]:
    """Un punct de decizie în `risk.points`: valoare, SURSA care l-a decis și, pentru
    o valoare publicată de CISA, ziua evaluării."""
    out: dict[str, Any] = {"value": value, "basis": basis}
    if as_of is not None:
        out["as_of"] = as_of
    return out


def _alias_cve(f: Mapping[str, Any], intel: Intel) -> str | None:
    """CVE-ul unui aviz fără CVE (un GHSA), din aliasurile OSV, dacă există."""
    adv = f.get("advisory_id")
    row = intel.osv.get(adv) if adv else None
    if row is None or row.status != "found":
        return None
    return next((a for a in row.aliases if a.startswith("CVE-")), None)


def _epss_overlay(decision: str, basis: str | None, exploitation: str | None,
                  observed: date | None, epss_value: float | None,
                  today: date) -> dict[str, Any] | None:
    """Înregistrarea suprapunerii EPSS dacă se aplică lui `decision`, altfel `None`.

    Condițiile, toate: decizia e sub podea; Exploitation vine de la CISA
    (`basis = vulnrichment`) și nu e `active` (un `active` nu e contrazis de o
    probabilitate mare, iar KEV nu e o fotografie veche); EPSS-ul e PROASPĂT (un EPSS
    vechi nu se folosește, ca peste tot) și ≥ `OVERLAY_MIN_EPSS`; evaluarea are mai mult
    de `OVERLAY_MIN_AGE_DAYS` zile. O evaluare fără dată nu poate fi dovedită proaspătă:
    se tratează ca veche (`observation_age_days` e atunci `None`), nu ca „în regulă".
    """
    if decision not in ssvc.DECISIONS or basis != "vulnrichment" or exploitation == "active":
        return None
    if ssvc.DECISIONS.index(decision) >= ssvc.DECISIONS.index(OVERLAY_FLOOR):
        return None
    if epss_value is None or epss_value < OVERLAY_MIN_EPSS:
        return None
    age = None if observed is None else (today - observed).days
    if age is not None and age <= OVERLAY_MIN_AGE_DAYS:
        return None
    return {"basis": OVERLAY_BASIS, "floor": OVERLAY_FLOOR, "ssvc_decision": decision,
            "epss": round(epss_value, 5),
            "observation_as_of": None if observed is None else observed.isoformat(),
            "observation_age_days": age,
            "min_epss": OVERLAY_MIN_EPSS, "min_age_days": OVERLAY_MIN_AGE_DAYS}


def assess(f: Mapping[str, Any], intel: Intel, *, exposed: bool = True,
           criticality: int = 3) -> Assessment:
    """Evaluarea completă a unei constatări. Nu ridică (vezi docstring-ul
    modulului): ce nu poate fi evaluat iese gri."""
    try:
        return _assess(f, intel, exposed=exposed, criticality=criticality)
    except Exception as exc:  # noqa: BLE001 - o intrare ciudată nu are voie să oprească scanarea
        return _unassessable(f, f"{type(exc).__name__}: {exc}"[:120])


def _unassessable(f: Mapping[str, Any], reason: str) -> Assessment:
    return Assessment(
        color=GREY, decision=None, score=None, importance=None,
        priority=UNASSESSED_PRIORITY, kev=bool(f.get("kev")), kev_due=f.get("kev_due_date"),
        cvss_score=None, cvss_vector=None, write_cvss=False, epss=None,
        epss_percentile=None,
        risk={"v": SCHEMA_VERSION, "missing": ["assessment_error"], "error": reason})


def _assess(f: Mapping[str, Any], intel: Intel, *, exposed: bool,
            criticality: int) -> Assessment:
    missing: list[str] = []
    own_cve = f.get("cve") or None
    cve = own_cve or _alias_cve(f, intel)

    # ---- CVSS: scor + vector din aceeași sursă --------------------------------
    chosen = _pick_cvss(f, cve, intel)
    vec = chosen["vec"] if chosen else None

    # ---- Ce a publicat CISA ---------------------------------------------------
    vr_row = intel.vulnrichment.get(cve) if cve else None
    published = vr_row if vr_row is not None and vr_row.status == "found" else None
    as_of = (published.ssvc_at.date().isoformat()
             if published is not None and published.ssvc_at is not None else None)

    # ---- Automatable / Technical Impact: publicat întâi, vectorul doar ca rezervă
    automatable: str | None
    auto_basis: str | None
    if published is not None and published.automatable is not None:
        automatable, auto_basis = published.automatable, "vulnrichment"
    else:
        automatable = cvss.automatable(vec)
        auto_basis = "cvss_vector" if automatable is not None else None
    if not exposed:
        automatable, auto_basis = "no", "asset_not_exposed"
    technical: str | None
    tech_basis: str | None
    if published is not None and published.technical_impact is not None:
        technical, tech_basis = published.technical_impact, "vulnrichment"
    else:
        technical = cvss.technical_impact(vec)
        tech_basis = "cvss_vector" if technical is not None else None
    # CVSS-ul lipsește din `missing` doar când lipsa lui lasă un punct fără valoare:
    # cu ambele puncte publicate, decizia nu are nevoie de el (importanța cade pe
    # severitate, și o spune).
    if automatable is None or technical is None:
        if chosen is None:
            missing.append("cvss")
        elif vec is None:
            missing.append("cvss_vector")

    # ---- Exploitation: ce s-a OBSERVAT (KEV, apoi CISA), niciodată EPSS --------
    kev_listed = bool(cve and cve in intel.kev) or bool(f.get("kev"))
    kev_due = intel.kev.get(cve) if cve and cve in intel.kev else f.get("kev_due_date")
    epss_row = intel.epss.get(cve) if cve else None
    epss_ok = epss_mod.is_fresh(epss_row, intel.today)
    epss_value = epss_row.epss if epss_ok and epss_row else None
    exploitation: str | None
    expl_basis: str | None
    expl_as_of: str | None = None
    if kev_listed:
        exploitation, expl_basis = "active", "kev"
    elif published is not None and published.exploitation == "active":
        exploitation, expl_basis, expl_as_of = "active", "vulnrichment", as_of
    else:
        # Ce a lipsit, spus pe nume. „Nu e în KEV" și „CISA n-a evaluat" sunt
        # afirmații despre lume; fără CVE, fără oglindă KEV la zi sau fără să fi
        # întrebat CISA (rând absent) nu le putem face.
        problems: list[str] = []
        if not cve:
            problems.append("cve")
        if not intel.kev_usable:
            problems.append("kev_mirror")
        if cve and vr_row is None:
            problems.append("vulnrichment")
        if problems:
            exploitation, expl_basis = None, None
            missing += problems
        elif published is not None and published.exploitation is not None:
            exploitation, expl_basis, expl_as_of = (
                published.exploitation, "vulnrichment", as_of)
        elif UNPUBLISHED_EXPLOITATION is not None:
            exploitation, expl_basis = UNPUBLISHED_EXPLOITATION, "kev_absent"
        else:
            exploitation, expl_basis = None, None
            missing.append("exploitation_unpublished")

    mission = mission_for(criticality)

    # ---- Decizia --------------------------------------------------------------
    points = (exploitation, automatable, technical, mission)
    # Strict: un punct necunoscut face constatarea gri, chiar și când arborele ar
    # da același răspuns oricum (de pildă „nimic nu se exploatează, misiune
    # medie" e Track indiferent de CVSS). Un CVE fără scor nu e unul sigur —
    # cerința operatorului — iar „verde" ar spune „am evaluat". Capetele
    # intervalului rămân în `possible`, ca un gri să arate cât de rău poate fi
    # (și că un gri „oricum Track" se poate citi repede).
    low, high = ssvc.decide_range(*points)
    decision: str | None = ssvc.decide(*points) if None not in points else None
    before_reboot: str | None = None
    reboot = bool(f.get("fix_pending_reboot"))
    if decision is not None and reboot:
        before_reboot = decision
        decision = ssvc.demote(decision)
    # Regula Sentinel (NU SSVC): EPSS mare lângă o fotografie CISA veche. După
    # coborârea pentru repornire, ca podeaua să rămână podea; un gri n-are decizie,
    # deci rămâne gri.
    overlay = None
    if decision is not None:
        overlay = _epss_overlay(
            decision, expl_basis, exploitation,
            published.ssvc_at.date() if published is not None and published.ssvc_at else None,
            epss_value, intel.today)
        if overlay is not None:
            decision = OVERLAY_FLOOR
    color = ssvc.COLOR_OF[decision] if decision is not None else GREY

    # ---- Axele și scorul ------------------------------------------------------
    importance: float | None
    importance_basis: str
    estimated = False
    if chosen is not None and chosen["score"] is not None:
        importance, importance_basis = float(chosen["score"]) / 10.0, "cvss"
    else:
        sev = _SEVERITY_IMPACT.get(str(f.get("severity") or ""))
        importance, importance_basis, estimated = sev, "severity", sev is not None
    likelihood: float | None
    if kev_listed:
        likelihood, likelihood_basis = 1.0, "kev"
    elif exploitation == "active":
        # Exploatare activă observată de CISA: la fel de sigură ca una din KEV.
        likelihood, likelihood_basis = 1.0, "vulnrichment"
    elif epss_value is not None:
        likelihood, likelihood_basis = epss_value, "epss"
    else:
        likelihood, likelihood_basis = None, None
    score = (importance * likelihood
             if importance is not None and likelihood is not None else None)

    if decision is None:
        priority = priority_of(None, importance)
    else:
        priority = priority_of(decision, score)

    risk: dict[str, Any] = {
        "v": SCHEMA_VERSION,
        "cve": cve,
        "points": {
            "exploitation": _point(exploitation, expl_basis, expl_as_of),
            "automatable": _point(automatable, auto_basis,
                                  as_of if auto_basis == "vulnrichment" else None),
            "technical_impact": _point(technical, tech_basis,
                                       as_of if tech_basis == "vulnrichment" else None),
            "mission": {"value": mission, "basis": "asset_criticality"},
        },
        "decision": decision,
        "reboot_pending": reboot,
        "importance": None if importance is None else round(importance, 3),
        "importance_basis": importance_basis,
        "likelihood": None if likelihood is None else round(likelihood, 5),
        "likelihood_basis": likelihood_basis,
    }
    if own_cve is None and cve is not None:
        risk["cve_via"] = f.get("advisory_id")
    if before_reboot is not None:
        risk["decision_before_reboot"] = before_reboot
    if overlay is not None:
        risk["overlay"] = overlay
    if decision is None:
        risk["possible"] = [low, high]
    if missing:
        risk["missing"] = missing
    if chosen is not None:
        entry: dict[str, Any] = {"source": chosen["source"], "score": chosen["score"],
                                 "vector": chosen["vector"], "version": chosen["version"]}
        if chosen.get("vendor_severity"):
            entry["vendor_severity"] = chosen["vendor_severity"]
        if estimated:
            entry["estimated"] = True
        risk["cvss"] = entry
    elif estimated:
        risk["cvss"] = {"source": None, "estimated": True}
    if epss_row is not None and epss_row.epss is not None:
        risk["epss"] = {"p": epss_row.epss, "percentile": epss_row.percentile,
                        "date": None if epss_row.score_date is None
                        else epss_row.score_date.isoformat(),
                        "stale": not epss_ok}
    if kev_listed:
        risk["kev"] = {"due": None if kev_due is None else str(kev_due)}
    if not exposed:
        risk["exposed"] = False

    # Ce se scrie în coloanele existente. Niciodată peste dovada scanerului.
    own = _scanner_candidate(f)
    write_cvss = (chosen is not None and chosen["source"] in ("redhat", "osv")
                  and own is None)
    return Assessment(
        color=color, decision=decision,
        score=None if score is None else round(score, 5),
        importance=None if importance is None else round(importance, 3),
        priority=priority, kev=kev_listed, kev_due=kev_due if kev_listed else None,
        cvss_score=chosen["score"] if chosen else None,
        cvss_vector=chosen["vector"] if chosen else None,
        write_cvss=write_cvss,
        epss=epss_value, epss_percentile=epss_row.percentile if epss_ok and epss_row else None,
        risk=risk)
