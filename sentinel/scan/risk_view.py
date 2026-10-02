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


#: Eticheta pusă lângă o culoare urcată de regula Sentinel (`risk.py`, suprapunerea
#: EPSS). Aceeași în Telegram, în panoul serverului și în agregator: o culoare care
#: nu e a SSVC trebuie să spună pe orice ecran că nu e a SSVC.
OVERLAY_TAG_RO = "regula Sentinel, nu SSVC"
#: Motivul scurt de pe un rând de listă. Telegram taie motivul la 24 de caractere
#: (`telegram.views.MAX_REASON_LIST`), deci eticheta trebuie să încapă întreagă.
OVERLAY_REASON_RO = "regula Sentinel (EPSS)"


def overlay_of(risk: Mapping[str, Any] | None, color: str | None = None) -> Mapping[str, Any] | None:
    """Înregistrarea `risk.overlay` dacă culoarea afișată E cea urcată de regulă.

    Cu `color` dat, înregistrarea se ia în seamă doar la galben: un `overlay` rămas
    într-un rând a cărui culoare nu mai e cea a podelei (un rând stricat sau
    citit pe jumătate) nu are voie să pună eticheta „regula Sentinel" pe un verde.
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
    """„🔴 Act — acum", „⚪ fără date". Dacă `risk` arată că galbenul e al regulii
    Sentinel, eticheta o spune: „🟡 Attend — accelerat (regula Sentinel, nu SSVC)"."""
    text = (f"{COLOR_EMOJI.get(color, '⚪')} "
            f"{DECISION_LABEL_RO.get(decision, DECISION_LABEL_RO[None])}")
    if decision == "attend" and overlay_of(risk, color) is not None:
        text += f" ({OVERLAY_TAG_RO})"
    return text


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
    ssvc_said = DECISION_LABEL_RO.get(overlay.get("ssvc_decision"), "altceva")
    return (f"⚠ Galbenul e al unei REGULI A SENTINEL — nu a SSVC, nu a FIRST: evaluarea "
            f"CISA a exploatării {seen}, iar {epss_txt}. "
            f"SSVC singur ar fi dat {ssvc_said}.")


def why_lines(risk: Mapping[str, Any] | None) -> list[str]:
    """Explicația completă, pe linii, pentru detaliul unei constatări."""
    if not isinstance(risk, Mapping) or not risk:
        return ["Încă neevaluată."]
    lines = [points_line(risk)]
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
    overlay = overlay_of(risk, "amber") if risk.get("decision") == "attend" else None
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
    if risk.get("reboot_pending"):
        before = risk.get("decision_before_reboot")
        lines.append("🔁 Reparația e instalată, lipsește o repornire: urgența a "
                     "coborât o treaptă"
                     + (f" (de la {DECISION_LABEL_RO.get(before, before)})" if before else "")
                     + "; importanța a rămas aceeași.")
    if risk.get("cve_via"):
        lines.append(f"CVE-ul vine din aliasul avizului {risk['cve_via']}.")
    return lines


def grey_reason(risk: Mapping[str, Any] | None) -> str | None:
    """De ce e gri — „lipsește: …; ar putea fi între Track și Act" — sau `None`
    când constatarea are o decizie."""
    if not isinstance(risk, Mapping) or not risk:
        return "încă neevaluată"
    if risk.get("decision") is not None:
        return None
    missing = risk.get("missing")
    parts = [_MISSING_RO.get(str(m), str(m)) for m in missing] if isinstance(missing, list) else []
    text = "lipsește " + ", ".join(parts) if parts else "decizia nu se poate lua"
    possible = risk.get("possible")
    if isinstance(possible, list) and len(possible) == 2:
        low, high = (DECISION_LABEL_RO.get(p, str(p)).split(" ")[0] for p in possible)
        text += (f"; oricum ar fi {low}" if low == high
                 else f"; ar putea fi între {low} și {high}")
    return text


def one_liner(color: str, risk: Mapping[str, Any] | None) -> str:
    """Motivul scurt de pe un rând de listă (Telegram): pentru ce e culoarea asta.

    „KEV", „EPSS 92%", „fără EPSS", „fără CVSS" — un singur motiv, cel mai
    puternic. Detaliul stă în `/vuln`.
    """
    if not isinstance(risk, Mapping) or not risk:
        return "neevaluat"
    if color == "grey":
        missing = risk.get("missing")
        first = missing[0] if isinstance(missing, list) and missing else None
        return {"cvss": "fără CVSS", "cvss_vector": "fără vector", "epss": "fără EPSS",
                "epss_stale": "EPSS vechi", "cve": "fără CVE",
                "kev_mirror": "KEV nelegibil", "vulnrichment": "fără date CISA",
                "exploitation_unpublished": "CISA n-a evaluat"}.get(str(first), "fără date")
    pts = risk.get("points") if isinstance(risk.get("points"), Mapping) else {}
    expl = pts.get("exploitation") if isinstance(pts, Mapping) else None
    basis = expl.get("basis") if isinstance(expl, Mapping) else None
    reboot = " 🔁" if risk.get("reboot_pending") else ""
    if color == "amber" and overlay_of(risk, color) is not None:
        return OVERLAY_REASON_RO + reboot
    if basis == "kev":
        return "KEV" + reboot
    if basis == "vulnrichment" and isinstance(expl, Mapping) and expl.get("value") == "active":
        return "CISA: exploatat" + reboot
    epss = risk.get("epss")
    if isinstance(epss, Mapping) and epss.get("p") is not None:
        return "EPSS " + fmt_epss(epss.get("p")) + reboot
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
