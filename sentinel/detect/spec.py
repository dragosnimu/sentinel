"""Contractul dintre o regulă de detecție și motor.

Stă singur, fără să importe nimic din `detect`, ca modulele de reguli să se
poată importa între ele. Când `rules` deținea și `DetectionSpec`, și lista de
reguli, orice modul nou de reguli trebuia să importe din `rules`, iar `rules`
trebuia să importe modulul nou ca să îl adauge în listă — import circular, cu
un mesaj care arată ca o problemă de ordine și e de fapt una de structură.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.constants import SEVERITIES


@dataclass
class DetectionSpec:
    rule_id: str
    rule_family: str
    severity: str
    # An attacker address for the network rules; None for an anomaly whose
    # subject is an asset, not a host. actor_key then carries the subject.
    src_ip: str | None
    fingerprint: str
    title: str
    summary: str
    evidence: dict[str, Any]
    event_ids: list[int]
    dst_port: int | None = None
    asset_id: int | None = None
    actor_key: str = ""
    # Regula asta susține că un FIȘIER anume s-a schimbat. Vezi
    # `enforce_path_evidence` mai jos pentru ce se întâmplă când nu poate arăta
    # niciunul. Implicit fals: o regulă de brute-force sau o anomalie de volum
    # nu are ce cale să arate, iar o gardă pornită implicit ar retrograda-o.
    path_backed: bool = False

    def __post_init__(self) -> None:
        if not self.actor_key:
            self.actor_key = self.src_ip or ""


# ---------------------------------------------------------------------------
# Garda pe forma evidenței
# ---------------------------------------------------------------------------
# Incidentul 4268: „Mecanism de persistență modificat: chei SSH sau
# configurație", critic, 62 de detecții, cu `paths: ["=", "rotateCount"]`.
# Cauza era în colector și e reparată acolo. Garda de aici e a doua plasă: o
# detecție al cărei titlu spune „fișierul X s-a schimbat" și care nu poate arăta
# niciun X nu susține ce afirmă.
#
# NU o suprimă. Un critic fals repetat strică încrederea în toate celelalte, dar
# o alertă care dispare în tăcere e mai rău: ar ascunde exact colectorul stricat
# care a produs situația asta. Deci detecția se scrie, cu severitate coborâtă,
# cu motivul în evidență și cu un titlu care spune ce se știe de fapt.
#
# Amprentă separată, dinadins: dacă ar folosi-o pe cea a regulii, detecțiile
# degradate s-ar aduna în incidentul critic real (severitatea urcă, nu coboară)
# și i-ar umfla contorul — adică fix simptomul „62 de detecții pe nimic", doar
# cu alt text.
#
# `high`, nu `medium`, și asta e o decizie măsurată, nu o preferință. Botul e
# singurul consumator al alertelor, iar el citește `incidents.unnotified()` cu
# pragul din `telegram.min_severity`, care pe gazda asta e `high`. Coborâtă la
# `medium`, o detecție degradată nu ar fi trimisă niciodată — iar coada `medium`
# de acolo avea 433 de incidente deschise, dintre care 422 nenotificate: nu e o
# severitate mai mică, e o groapă. Degradarea ar fi devenit suprimare cu alt
# nume, exact ce refuză comentariul de mai sus.
#
# Costul e concret dacă alegerea e greșită: `parse_auditd_lines` spune singur că
# un grup rupt între două citiri produce un eveniment fără cale, deci un
# `chmod u+s` nimerit peste o graniță de citire ajunge aici. Trebuie să plece
# spre operator, nu într-o coadă pe care n-o citește nimeni.
#
# `high` rămâne sub `critical`, deci nu reintroduce falsul critic, și e cea mai
# de sus treaptă care nu e `critical` — vezi testul care leagă valoarea asta de
# scara canonică și de pragul livrat. Singurul mod de a o face invizibilă e
# ridicarea pragului la `critical`, ceea ce ar tăcea și cele 124 de incidente
# `high` deschise: o decizie a operatorului despre tot, nu un efect secundar al
# gărzii ăsteia.
#
# PLAFON, nu valoare fixă, iar asta e a doua decizie. Când garda a fost scrisă,
# fiecare regulă care susținea un fișier era `critical`, deci o atribuire era
# totuna cu o coborâre. `intrusion.bait_attribute_probe` e prima regulă `low`
# care susține un fișier: pentru ea atribuirea URCA severitatea cu două trepte
# și lipea deasupra propoziția „Severitate coborâtă din `low`" — alerta spunea
# exact pe dos ce tocmai făcuse, adică fix genul de afirmație pentru care
# există garda asta. Deci severitatea se atinge numai în jos, iar textul de mai
# jos spune care dintre cele două s-a întâmplat. Pentru regulile `critical`
# nimic nu se schimbă: erau coborâte la `high` și rămân coborâte la `high`.
UNSUPPORTED_SEVERITY = "high"

# Necunoscutul se plafonează, nu se crede. O severitate care nu e pe scara
# canonică e un defect în regula care a produs-o; lăsată neatinsă, ar putea
# trece peste `critical` la orice comparație care o citește.
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _above_the_guard(severity: str) -> bool:
    return _RANK.get(severity, len(SEVERITIES)) > _RANK[UNSUPPORTED_SEVERITY]


def _is_plausible_path(value: Any) -> bool:
    """O cale absolută POSIX. Fiecare urmărire din `deploy/audit/sentinel.rules`
    e pe o cale absolută, deci orice altceva înseamnă că nu știm ce s-a atins."""
    return isinstance(value, str) and value.startswith("/") and len(value) > 1


def enforce_path_evidence(spec: DetectionSpec) -> DetectionSpec:
    """Coboară o detecție pe fișier care nu poate arăta niciun fișier."""
    if not spec.path_backed:
        return spec
    paths = spec.evidence.get("paths") or []
    if any(_is_plausible_path(p) for p in paths):
        return spec

    ceruta = spec.severity
    coborata = _above_the_guard(ceruta)
    spec.evidence = {
        **spec.evidence,
        "evidence_guard": "no_plausible_path",
        "severity_claimed": ceruta,
    }
    if coborata:
        spec.severity = UNSUPPORTED_SEVERITY
    spec.fingerprint = f"{spec.fingerprint}:fara-cale"
    spec.title = f"{spec.title} — fără cale de fișier în evidență"
    spec.summary = (
        "Regula s-a declanșat, dar evidența nu conține nicio cale de fișier "
        "absolută, deci nu se poate spune CE s-a modificat. Cel mai probabil "
        "colectorul auditd nu a putut rezolva calea (înregistrare PATH fără "
        "CWD), nu o intruziune. "
        + (f"Severitate coborâtă din `{ceruta}` până când există o cale. "
           if coborata else
           f"Severitatea rămâne `{ceruta}`: garda nu urcă o alertă pe care "
           "evidența n-o susține. ")
        + f"Evidența brută: {spec.summary}")
    return spec
