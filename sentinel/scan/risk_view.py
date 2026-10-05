"""Cum se citește `findings.risk`: textele pentru operator, într-un singur loc.

Telegram, panoul fiecărui server și (prin TypeScript, vezi
`aggregator/lib/finding-risk.ts`) agregatorul arată aceeași culoare cu același
înțeles, dar nu aceeași cantitate. Ce e comun stă aici: etichetele, formatul
probabilității EPSS, motivul unui gri. O a doua scriere a lor într-un șablon sau
într-un handler e felul în care panoul ajunge să spună „roșu" și botul „galben"
despre același rând.

Funcțiile sunt PURE și primesc dicționarul `risk` așa cum e în bază (sau `None`,
pentru un rând niciodată evaluat). Niciuna nu ridică: un `risk` ciudat dă un text
care spune că nu se poate citi, nu o pagină de eroare.

Nimic de aici nu escapează HTML. Cine afișează (Jinja cu autoescape, `esc` din
Telegram) o face; textele astea sunt doar text. `risk` nu conține text liber —
numai cifre, cuvinte dintr-un vocabular, id-uri și vectori — dar o valoare din
rețea care ar fi ajuns acolo pe vreo cale trebuie să rămână inofensivă la
afișare, nu doar la scriere.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from sentinel.scan import risk as risk_mod
from sentinel.scan import ssvc

COLOR_ORDER = risk_mod.COLOR_ORDER
COLOR_EMOJI = risk_mod.COLOR_EMOJI
COLOR_LABEL_RO = risk_mod.COLOR_LABEL_RO
DECISION_LABEL_RO = risk_mod.DECISION_LABEL_RO
DECISION_SSVC_NAME = risk_mod.DECISION_SSVC_NAME

#: Clasa de punct din `sentinel.css` pentru fiecare culoare (`dot-ok` verde,
#: `dot-warn` galben, `dot-bad` roșu, `dot-off` gri). Nu există o clasă nouă:
#: o foaie de stil schimbată înseamnă și o adresă nouă cu rezumat în
#: `asset_url`, iar culorile existente sunt exact cele patru de aici.
DOT_CLASS = {"red": "bad", "amber": "warn", "green": "ok", "grey": "off"}

_SOURCE_RO = {"redhat": "Red Hat", "osv": "OSV", "trivy": "trivy"}

_POINT_RO = {
    "exploitation": {"none": "nimic exploatat cunoscut",
                     "poc": "exploit probabil public",
                     "active": "exploatat activ"},
    "automatable": {"yes": "automatizabil", "no": "neautomatizabil"},
    "technical_impact": {"total": "impact total", "partial": "impact parțial"},
    "mission": {"low": "misiune mică", "medium": "misiune medie", "high": "misiune mare"},
}

_BASIS_RO = {"kev": "CISA KEV", "epss": "EPSS", "cvss_vector": "vector CVSS",
             "vulnrichment": "CISA Vulnrichment (CISA-ADP, din înregistrarea CVE)",
             "kev_absent": "nu e în KEV, iar CISA nu l-a evaluat (presupunere)",
             "asset_criticality": "criticitatea activului",
             "asset_not_exposed": "activ neexpus"}

#: Ce lipsește, în cuvinte puține: textul de pe rândul unui gri (și motivul scurt din
#: Telegram). Explicația întreagă — `_MISSING_RO` — stă în detaliu, nu într-o celulă:
#: o frază de trei rânduri într-o coloană îngustă e o panglică, nu o etichetă.
_MISSING_SHORT_RO = {
    "cvss": "fără CVSS", "cvss_vector": "fără vector", "epss": "fără EPSS",
    "epss_stale": "EPSS vechi", "cve": "fără CVE", "kev_mirror": "KEV nelegibil",
    "vulnrichment": "fără date CISA", "exploitation_unpublished": "CISA n-a evaluat",
}

_MISSING_RO = {
    "cvss": "niciun scor CVSS",
    "cvss_vector": "vectorul CVSS",
    "epss": "EPSS (nu există încă pentru acest CVE)",
    "epss_stale": "EPSS (valoarea e prea veche)",
    "cve": "CVE (fără el nu există EPSS sau KEV)",
    "kev_mirror": "lista CISA KEV (oglinda lipsește sau e veche)",
    "vulnrichment": "punctele CISA (CVE-ul nu a fost încă întrebat)",
    "exploitation_unpublished": "exploatarea (CISA n-a evaluat CVE-ul)",
    "assessment_error": "evaluarea a eșuat",
}


#: Marcajul pus lângă o culoare urcată de regula Sentinel (`risk.py`, suprapunerea
#: EPSS). Același în Telegram, în panoul serverului și în agregator: un galben care
#: nu e al SSVC trebuie să spună pe orice ecran de la cine e. Marcajul e scurt de
#: voie — „nu SSVC" și cifrele stau în `OVERLAY_NOTE_RO` și în propoziția din detaliu,
#: iar legenda paginii spune ce înseamnă.
OVERLAY_TAG_RO = "regula Sentinel"
#: Aceeași idee, pentru text de detaliu unde e loc de „nu SSVC".
OVERLAY_NOTE_RO = "regula Sentinel, nu SSVC"
#: Sub ce EPSS un verde nu mai are nimic de spus despre EPSS pe rândul lui. Egal cu
#: pragul regulii Sentinel (`risk.OVERLAY_MIN_EPSS`), nu o cifră a paginii: de la el
#: în sus, un EPSS stând lângă un verde e o veste (CISA zice „nimic", FIRST zice
#: „aproape sigur"); dedesubt, cifra e deja în coloana EPSS și un al doilea rând
#: care o repetă e zgomot.
NOTEWORTHY_EPSS = risk_mod.OVERLAY_MIN_EPSS


def overlay_of(risk: Mapping[str, Any] | None, color: str | None = None) -> Mapping[str, Any] | None:
    """Înregistrarea `risk.overlay` dacă culoarea afișată E cea urcată de regulă.

    Cu `color` dat, înregistrarea se ia în seamă doar la galben: un `overlay` rămas
    într-un rând a cărui culoare nu mai e cea a podelei nu are voie să pună eticheta
    „regula Sentinel" pe un verde. Starea apare și fără un rând stricat: podeaua se aplică
    înaintea coborârii pentru repornire, deci un rând urcat a cărui reparație așteaptă o
    repornire e verde și își păstrează `overlay` în înregistrare.
    """
    if not isinstance(risk, Mapping):
        return None
    o = risk.get("overlay")
    if not isinstance(o, Mapping) or o.get("basis") != "epss_overlay":
        return None
    if color is not None and color != "amber":
        return None
    return o


def _num(value: Any) -> float | None:
    try:
        return None if value is None or isinstance(value, bool) else float(value)
    except (TypeError, ValueError):
        return None


def _dec(value: Any) -> Decimal | None:
    """`value` ca Decimal exact (din forma lui text), sau None dacă nu e un număr
    finit. Decimal, nu float: rotunjirea „la jumătate în sus" trebuie să dea
    același text aici și în TypeScript, iar `0,1225` ca float binar poate cădea
    pe oricare parte a unei jumătăți."""
    if value is None or isinstance(value, bool):
        return None
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return d if d.is_finite() else None


def _dec_ro(value: float, places: int) -> str:
    """Număr cu virgulă zecimală, ca în restul interfeței."""
    return f"{value:.{places}f}".replace(".", ",")


def _half_up(d: Decimal, places: int) -> str:
    q = d.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
    return f"{q:.{places}f}".replace(".", ",")


def fmt_epss(p: Any, percentile: Any = None) -> str:
    """„15,3% (percentila 92)" — probabilitatea ÎNTREAGĂ, cu percentilă.

    FIRST recomandă exact forma asta și refuză să le împartă în găleți. Sub 1%
    se arată două zecimale: `0,45%` și `0,05%` nu sunt același lucru, iar
    rotunjirea lor la `0%` ar spune că probabilitatea e nulă. Sub 0,01% se scrie
    `<0,01%`, nu `0,00%`. Rotunjirea e „la jumătate în sus" pe valoarea
    zecimală exactă, aceeași în TypeScript (`aggregator/lib/finding-risk.ts`).
    """
    prob = _dec(p)
    if prob is None:
        return "fără EPSS"
    pct = prob * 100
    if pct < Decimal("0.01"):
        text = "<0,01%"
    elif pct < 1:
        text = _half_up(pct, 2) + "%"
    else:
        text = _half_up(pct, 1) + "%"
    ptile = _dec(percentile)
    if ptile is not None:
        text += f" (percentila {_half_up(ptile * 100, 0)})"
    return text


def fmt_cvss(cvss: Mapping[str, Any] | None) -> str:
    """„CVSS 3,1 (Red Hat)", „CVSS ~9,5 (estimat din severitate)", sau „fără CVSS"."""
    if not isinstance(cvss, Mapping):
        return "fără CVSS"
    score = _num(cvss.get("score"))
    source = _SOURCE_RO.get(str(cvss.get("source")), None)
    if score is None:
        if cvss.get("estimated"):
            return "CVSS fără scor numeric (importanță estimată din severitate)"
        return "fără CVSS"
    text = f"CVSS {_dec_ro(score, 1)}"
    return text + (f" ({source})" if source else "")


def source_ro(risk: Mapping[str, Any] | None) -> str | None:
    """Cine a decis scorul CVSS, pe nume — sau `None` dacă nu există scor."""
    cvss = (risk or {}).get("cvss") if isinstance(risk, Mapping) else None
    if not isinstance(cvss, Mapping):
        return None
    return _SOURCE_RO.get(str(cvss.get("source")))


def headline(color: str, decision: str | None,
             risk: Mapping[str, Any] | None = None) -> str:
    """„🔴 Acum", „⚪ Nedecis". Dacă `risk` arată că galbenul e al regulii Sentinel,
    marcajul o spune: „🟡 Curând · regula Sentinel"."""
    text = (f"{COLOR_EMOJI.get(color, '⚪')} "
            f"{DECISION_LABEL_RO.get(decision, DECISION_LABEL_RO[None])}")
    if decision == "attend" and overlay_of(risk, color) is not None:
        text += f" · {OVERLAY_TAG_RO}"
    return text


def ssvc_name(decision: str | None) -> str | None:
    """Numele deciziei în vocabularul CISA SSVC („Attend"), sau `None` fără decizie."""
    return DECISION_SSVC_NAME.get(decision) if isinstance(decision, str) else None


#: Numele unei STĂRI, unul singur pe orice ecran: eticheta deciziei (`DECISION_LABEL_RO`),
#: nu numele culorii și nu o descriere a cauzei. „Roșu", „fără date" și „Nedecis" erau trei
#: nume ale aceleiași stări, la trei clicuri una de alta (cardul, pastila, rândul); aici
#: stă singurul. Cuvintele de culoare rămân doar ca ARGUMENT de filtru (`?culoare=gri`,
#: `/vulnerabilitati gri`) și în titlul unei pastile, niciodată ca nume de afișat.
#:
#: Verdele are două decizii (Track și Track*), deci grupa lui poartă ambele etichete: o
#: pastilă „Ciclul obișnuit" care ar aduce și rânduri „De urmărit*" ar fi o a patra
#: denumire.
COLOR_STATE_RO = {
    "red": DECISION_LABEL_RO[ssvc.ACT],
    "amber": DECISION_LABEL_RO[ssvc.ATTEND],
    "green": f"{DECISION_LABEL_RO[ssvc.TRACK]} / {DECISION_LABEL_RO[ssvc.TRACK_STAR]}",
    "grey": DECISION_LABEL_RO[None],
}

#: Ce se știe despre un gri, într-un cuvânt-cheie, pentru legende: „lipsesc date" explică
#: de ce nu e decis; nu e un al doilea nume al stării.
_GREY_WHY_RO = "lipsesc date"


def _ssvc_names_of(color: str) -> str | None:
    """Numele SSVC ale deciziilor unei culori („Track / Track*"), sau `None` la gri."""
    names = [DECISION_SSVC_NAME[d] for d in ssvc.DECISIONS if ssvc.COLOR_OF[d] == color]
    return " / ".join(names) if names else None


def state_with_ssvc(color: str) -> str:
    """„Acum (Act)", „Ciclul obișnuit / De urmărit* (Track / Track*)", „Nedecis": numele
    stării, apoi — unde există — cel din arborele CISA, ca eticheta să se poată urmări
    până la el."""
    name = COLOR_STATE_RO[color]
    ssvc_names = _ssvc_names_of(color)
    return f"{name} ({ssvc_names})" if ssvc_names else name


def pill_title(color: str) -> str:
    """Tooltip-ul unei pastile de culoare: cuvântul culorii (pentru cine nu o deosebește)
    și numele din arborele CISA, sau motivul unui gri."""
    ssvc_names = _ssvc_names_of(color)
    what = f"decizia CISA SSVC: {ssvc_names}" if ssvc_names else f"nu se poate decide: {_GREY_WHY_RO}"
    return f"{COLOR_LABEL_RO[color]} · {what}"


def legend_states() -> str:
    """Legenda stărilor, din aceleași etichete pe care le scrie `headline`: „🔴 Acum (Act) ·
    🟡 Curând (Attend) · 🟢 Ciclul obișnuit (Track) · 🟢 De urmărit* (Track*) · ⚪ Nedecis
    (lipsesc date)". Singura legendă a unui rând de listă din Telegram (rândul poartă doar
    punctul colorat), deci o legendă scrisă de mână care se abate de la etichete îi dă
    operatorului potrivirea greșită exact acolo."""
    parts = [f"{COLOR_EMOJI[ssvc.COLOR_OF[d]]} {DECISION_LABEL_RO[d]} ({DECISION_SSVC_NAME[d]})"
             for d in (ssvc.ACT, ssvc.ATTEND, ssvc.TRACK, ssvc.TRACK_STAR)]
    parts.append(f"{COLOR_EMOJI['grey']} {DECISION_LABEL_RO[None]} ({_GREY_WHY_RO})")
    return " · ".join(parts)


def counts_ro(red: int, amber: int, grey: int) -> str:
    """„Acum 1 · Curând 3 · Nedecis 27": câte constatări are fiecare stare, cu numele ei.
    Eticheta înaintea numărului, ca să nu fie nevoie de acord („27 nedecise" / „27 Nedecis").
    Nedecis apare mereu, chiar cu zero: „0 nedecise" e un fapt, iar tăcerea despre el ar
    arăta curat tocmai când nu se știe. Verdele nu se enumeră: e restul."""
    return (f"{COLOR_STATE_RO['red']} {red} · {COLOR_STATE_RO['amber']} {amber} · "
            f"{COLOR_STATE_RO['grey']} {grey}")


#: De ce celula KEV poate spune „nu se știe", în propoziția legendei. Aceeași pe server și în
#: agregator (paritatea o compară). Toate cauzele pe care le are celula: dacă o legendă
#: le-ar enumera doar pe unele, o a patra ar citi ca o defecțiune. Fără „a eșuat": testul
#: `aggregator/tests/scan-age.test.ts` caută cuvântul în toată pagina ca să prindă o scanare
#: în curs anunțată ca eșec, iar legenda lui l-ar fi aprins.
KEV_UNKNOWN_NOTE_RO = ("nu s-a căutat: lista KEV n-a putut fi citită, rândul n-are CVE, "
                       "evaluarea lui s-a oprit cu o eroare sau încă n-a fost făcută")


def _kev_unknown(risk: Mapping[str, Any] | None) -> bool:
    """Se poate spune „nu e în KEV"? Nu, dacă lista n-a putut fi citită, dacă rândul n-are
    CVE (nu există ce căuta), dacă n-a fost evaluat niciodată sau dacă evaluarea a căzut
    (`assessment_error`): în toate, `kev = false` e absența unui răspuns, nu răspunsul — la
    o evaluare căzută e chiar valoarea veche, păstrată de `risk._unassessable`, nu o
    căutare de azi."""
    if not isinstance(risk, Mapping) or not risk:
        return True
    missing = risk.get("missing")
    return isinstance(missing, list) and any(
        str(m) in ("cve", "kev_mirror", "assessment_error") for m in missing)


def fmt_kev(kev: Any, due: Any = None, risk: Mapping[str, Any] | None = None) -> str:
    """Celula KEV: „da — 2026-10-12", „nu", sau „nu se știe".

    „nu" se scrie numai când s-a căutat: un rând fără CVE, cu oglinda KEV lipsă ori veche
    sau a cărui evaluare a căzut nu poate fi „în afara" listei, iar un „nu" acolo ar liniști
    despre exact ce nu s-a verificat.
    """
    if kev:
        text = "da"
        if due is not None and str(due) != "":
            text += f" — {due}"
        return text
    return "nu se știe" if _kev_unknown(risk) else "nu"


def points_line(risk: Mapping[str, Any] | None) -> str:
    """Cele patru puncte de decizie într-o propoziție, cu `?` unde nu se știe.

    Un punct necunoscut apare ca „? exploatare" și nu e lăsat deoparte: o
    propoziție cu trei puncte din patru s-ar citi ca o evaluare completă.
    """
    pts = (risk or {}).get("points") if isinstance(risk, Mapping) else None
    if not isinstance(pts, Mapping):
        return "fără evaluare"
    names = {"exploitation": "exploatare", "automatable": "automatizare",
             "technical_impact": "impact", "mission": "misiune"}
    out = []
    for key in ("exploitation", "automatable", "technical_impact", "mission"):
        point = pts.get(key)
        value = point.get("value") if isinstance(point, Mapping) else None
        out.append(_POINT_RO[key].get(str(value), f"? {names[key]}"))
    return " · ".join(out)


def _overlay_sentence(overlay: Mapping[str, Any]) -> str:
    """Propoziția care spune, pe față, că galbenul e al Sentinel: de ce, cu ce cifre,
    și ce ar fi dat SSVC singur. Cifrele vin din înregistrare (ce s-a aplicat), nu
    din constantele de azi."""
    age = _num(overlay.get("observation_age_days"))
    as_of = overlay.get("observation_as_of")
    if age is not None and as_of:
        seen = f"e din {as_of} ({int(age)} de zile"
        min_age = _num(overlay.get("min_age_days"))
        seen += f"; prag: peste {int(min_age)})" if min_age is not None else ")"
    else:
        seen = "n-are dată (nu se poate dovedi proaspătă)"
    epss_p = _dec(overlay.get("epss"))
    epss_txt = "EPSS e " + (fmt_epss(overlay.get("epss")) if epss_p is not None else "necunoscut")
    min_epss = _num(overlay.get("min_epss"))
    if min_epss is not None:
        epss_txt += f" (prag: cel puțin {round(min_epss * 100)}%)"
    ssvc_said = ssvc_name(overlay.get("ssvc_decision")) or "altceva"
    return (f"⚠ Galbenul e al unei REGULI A SENTINEL — nu a SSVC, nu a FIRST: evaluarea "
            f"CISA a exploatării {seen}, iar {epss_txt}. "
            f"SSVC singur ar fi dat {ssvc_said}.")


def why_lines(risk: Mapping[str, Any] | None) -> list[str]:
    """Explicația completă, pe linii, pentru detaliul unei constatări."""
    if not isinstance(risk, Mapping) or not risk:
        return ["Încă neevaluată."]
    lines = []
    overlay = overlay_of(risk, "amber") if risk.get("decision") == "attend" else None
    name = ssvc_name(risk.get("decision"))
    # Numele din arborele CISA, ca eticheta din tabel să poată fi urmărită până la el.
    # Un galben urcat de regula Sentinel nu-l primește: „Attend" scris aici ar spune
    # că arborele a decis ce n-a decis; propoziția lui spune ce a dat SSVC singur.
    if name is not None and overlay is None:
        lines.append(f"Decizie CISA SSVC: {name} ({DECISION_LABEL_RO[risk['decision']]})")
    lines.append(points_line(risk))
    pts = risk.get("points") if isinstance(risk.get("points"), Mapping) else {}
    bases = []
    for key, label in (("exploitation", "exploatare"), ("automatable", "automatizare"),
                       ("technical_impact", "impact tehnic")):
        point = pts.get(key) if isinstance(pts, Mapping) else None
        basis = point.get("basis") if isinstance(point, Mapping) else None
        if basis:
            text = _BASIS_RO.get(str(basis), str(basis))
            # O valoare publicată de CISA e o fotografie: se spune de când.
            as_of = point.get("as_of") if isinstance(point, Mapping) else None
            if as_of:
                text += f", evaluat la {as_of}"
            bases.append(f"{label}: {text}")
    if bases:
        lines.append("Pe baza: " + " · ".join(bases))
    if overlay is not None:
        lines.append(_overlay_sentence(overlay))
    cvss_txt = fmt_cvss(risk.get("cvss"))
    epss = risk.get("epss")
    if isinstance(epss, Mapping) and epss.get("p") is not None:
        epss_txt = "EPSS " + fmt_epss(epss.get("p"), epss.get("percentile"))
        if epss.get("date"):
            epss_txt += f", din {epss['date']}"
        if epss.get("stale"):
            epss_txt += " — prea vechi, nefolosit"
    else:
        epss_txt = "fără EPSS"
    lines.append(f"{cvss_txt} · {epss_txt}")
    # Motivul unui gri, cu tot ce lipsește și cu capetele posibile: explicația lungă pe
    # care celula tabelului n-o mai poartă (acolo rămâne doar ce lipsește, în două-trei
    # cuvinte).
    detail = grey_detail(risk)
    if detail is not None:
        lines.append(f"{COLOR_STATE_RO['grey']}: {detail}")
    if risk.get("reboot_pending"):
        before = risk.get("decision_before_reboot")
        # Un rând urcat de regula Sentinel și apoi coborât de repornire: „de la Attend" ar fi
        # o decizie pe care SSVC singur nu a dat-o, deci se spune a cui era.
        via = (f", urcat de {OVERLAY_NOTE_RO}" if before == "attend"
               and overlay_of(risk) is not None else "")
        lines.append("🔁 Reparația e instalată, lipsește o repornire: urgența a "
                     "coborât o treaptă"
                     + (f" (de la {ssvc_name(before) or before}{via})" if before else "")
                     + "; importanța a rămas aceeași.")
    if risk.get("cve_via"):
        lines.append(f"CVE-ul vine din aliasul avizului {risk['cve_via']}.")
    return lines


#: Ce spune un gri al cărui `risk.missing` e gol: nu se știe de ce, și asta se scrie. Nu „fără
#: date" — numele acela a fost al STĂRII (acum „Nedecis"), iar un rând de listă care îl mai
#: spune ca motiv îl aduce înapoi pe un ecran.
_GREY_NO_CODE_RO = "decizia nu se poate lua"


def _missing_words(code: Any) -> str:
    """Un cod din `risk.missing`, în cuvintele pe care le citește operatorul: forma scurtă dacă
    există, altfel explicația din `_MISSING_RO`, altfel codul ca atare (un cod pe care
    vocabularul nu-l știe apare, nu dispare). UN SINGUR loc pentru celula tabelului
    (`grey_reason`) și pentru rândul de listă din Telegram (`one_liner`): două citiri ale
    aceluiași cod sunt felul în care o suprafață a spus „fără date" și cealaltă „decizia nu se
    poate lua" despre același rând."""
    return _MISSING_SHORT_RO.get(str(code)) or _MISSING_RO.get(str(code), str(code))


def grey_detail(risk: Mapping[str, Any] | None) -> str | None:
    """Tot ce se știe despre un gri, într-o propoziție: „lipsește EPSS (…); ar putea fi
    între Track și Attend". `None` când constatarea are o decizie.

    E explicația lungă, pentru detaliu (`why_lines`, tooltip): celula unui tabel poartă
    doar `grey_reason`. Capetele posibile sunt cu numele SSVC, ca în arbore."""
    if not isinstance(risk, Mapping) or not risk:
        return "încă neevaluată"
    if risk.get("decision") is not None:
        return None
    missing = risk.get("missing")
    parts = [_MISSING_RO.get(str(m), str(m)) for m in missing] if isinstance(missing, list) else []
    text = "lipsește " + ", ".join(parts) if parts else _GREY_NO_CODE_RO
    possible = risk.get("possible")
    if isinstance(possible, list) and len(possible) == 2:
        low, high = (ssvc_name(p) or str(p) for p in possible)
        text += (f"; oricum ar fi {low}" if low == high
                 else f"; ar putea fi între {low} și {high}")
    return text


def grey_reason(risk: Mapping[str, Any] | None) -> str | None:
    """Ce lipsește, pe scurt — „fără CVE" — sau `None` când constatarea are o decizie.

    Doar datumul care lipsește: „ar putea fi între X și Y" și fraza lungă sunt în
    `grey_detail`. Un cod pe care vocabularul nu-l știe apare ca atare, nu dispare."""
    if not isinstance(risk, Mapping) or not risk:
        return "încă neevaluată"
    if risk.get("decision") is not None:
        return None
    missing = risk.get("missing")
    parts: list[str] = []
    for m in (missing if isinstance(missing, list) else []):
        text = _missing_words(m)
        if text not in parts:
            parts.append(text)
    return ", ".join(parts) if parts else _GREY_NO_CODE_RO


def _overlay_epss(overlay: Mapping[str, Any]) -> str:
    """„EPSS 99,2%" — cifra înregistrării (ce s-a aplicat), nu a coloanei de azi."""
    return ("EPSS " + fmt_epss(overlay.get("epss"))
            if _dec(overlay.get("epss")) is not None else "EPSS mare")


def overlay_reason(overlay: Mapping[str, Any]) -> str:
    """Faptul din spatele unui galben al regulii Sentinel, în câteva cuvinte: „EPSS 99,2%,
    CISA veche". Pentru un loc care are deja marcajul „regula Sentinel" lângă etichetă
    (celula unui tabel); un rând de listă fără etichetă folosește `one_liner`. O evaluare
    fără dată nu e „veche", e „nedatată": nu se poate dovedi proaspătă, dar nici că are
    180 de zile."""
    epss_txt = _overlay_epss(overlay)
    as_of = overlay.get("observation_as_of")
    dated = (isinstance(as_of, str) and as_of != ""
             and _num(overlay.get("observation_age_days")) is not None)
    return f"{epss_txt}, CISA {'veche' if dated else 'nedatată'}"


def _exploitation_reason(risk: Mapping[str, Any]) -> str | None:
    """Motivul culorii când vine din exploatare: KEV sau CISA. `None` când nu e niciunul
    (rămâne EPSS-ul, dacă merită spus). Regula Sentinel o tratează fiecare apelant, fiindcă
    textul ei diferă după cum eticheta rândului e sau nu deasupra."""
    pts = risk.get("points") if isinstance(risk.get("points"), Mapping) else {}
    expl = pts.get("exploitation") if isinstance(pts, Mapping) else None
    basis = expl.get("basis") if isinstance(expl, Mapping) else None
    if basis == "kev":
        return "exploatat activ (KEV)"
    if basis == "vulnrichment" and isinstance(expl, Mapping) and expl.get("value") == "active":
        return "exploatat activ (CISA)"
    return None


def _epss_of(risk: Mapping[str, Any]) -> Any:
    epss = risk.get("epss")
    return epss.get("p") if isinstance(epss, Mapping) else None


def reason_line(color: str, risk: Mapping[str, Any] | None) -> str | None:
    """A doua linie a celulei „Risc" dintr-un tabel: DE CE e culoarea asta, într-o frază
    scurtă — sau `None` când n-ar spune nimic.

    Un verde al cărui singur motiv ar fi un EPSS mic nu primește linie: cifra e în
    coloana EPSS, iar o linie care o repetă pune o panglică acolo unde operatorul caută
    ce are de făcut. Un gri primește mereu linie (ce lipsește): griul fără motiv ar
    citi ca „în regulă". Fără semnul 🔁: tabelele îl pun separat, din `risk.reboot_pending`.
    """
    if color == "grey":
        return grey_reason(risk) or _GREY_NO_CODE_RO
    if not isinstance(risk, Mapping) or not risk:
        return "neevaluat"
    overlay = overlay_of(risk, color) if color == "amber" else None
    if overlay is not None:
        return overlay_reason(overlay)
    why = _exploitation_reason(risk)
    if why is not None:
        return why
    p = _dec(_epss_of(risk))
    if p is not None and (color != "green" or p >= Decimal(str(NOTEWORTHY_EPSS))):
        return "EPSS " + fmt_epss(_epss_of(risk))
    return None


def one_liner(color: str, risk: Mapping[str, Any] | None) -> str:
    """Motivul scurt de pe un rând de listă (Telegram): pentru ce e culoarea asta.

    „exploatat activ (KEV)", „EPSS 92,0%", „fără EPSS" — un singur motiv, cel mai
    puternic. Detaliul stă în `/vuln`. Spre deosebire de `reason_line`, aici nu lipsește
    niciodată: un rând de listă fără motiv ar lăsa un „ · · " gol în mijlocul lui.
    """
    if not isinstance(risk, Mapping) or not risk:
        return "neevaluat"
    if color == "grey":
        # Primul motiv, în aceleași cuvinte ca celula tabelului (`grey_reason`, care le
        # înșiră pe toate): un singur motiv încape pe rând, dar nu are voie să-l spună altfel.
        missing = risk.get("missing")
        if isinstance(missing, list) and missing:
            return _missing_words(missing[0])
        return _GREY_NO_CODE_RO
    reboot = " 🔁" if risk.get("reboot_pending") else ""
    overlay = overlay_of(risk, color) if color == "amber" else None
    if overlay is not None:
        # Un rând de listă n-are eticheta de deasupra, deci își poartă singur marcajul:
        # un galben al regulii Sentinel nu trebuie să arate ca oricare altul.
        return f"{OVERLAY_TAG_RO} · {_overlay_epss(overlay)}" + reboot
    why = _exploitation_reason(risk)
    if why is not None:
        return why + reboot
    if _dec(_epss_of(risk)) is not None:
        return "EPSS " + fmt_epss(_epss_of(risk)) + reboot
    return "—" + reboot


def counts_line(counts: Mapping[str, int]) -> str:
    """„🔴 1 · 🟡 3 · ⚪ 25 · 🟢 783", în ordinea listei: roșu, galben, gri, verde.

    Culorile cu zero lipsesc, dar gri nu: „⚪ 0" ar fi un fapt (nimic nu e fără
    date), iar tăcerea despre gri ar fi exact ce nu trebuie. Dacă nu există
    niciun rând, „—".
    """
    parts = []
    for color in ("red", "amber", "grey", "green"):
        n = int(counts.get(color, 0) or 0)
        if n or color == "grey":
            parts.append(f"{COLOR_EMOJI[color]} {n}")
    return " · ".join(parts) if any(int(counts.get(c, 0) or 0) for c in COLOR_ORDER) else "—"


def decision_rank(decision: str | None) -> int:
    return ssvc.DECISIONS.index(decision) if decision in ssvc.DECISIONS else -1
