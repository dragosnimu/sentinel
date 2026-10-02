"""CISA Vulnrichment — punctele SSVC PUBLICATE de CISA, oglindite local.

Arborele SSVC are trei puncte pe care un vector CVSS nu le poate spune cu
adevărat: *Exploitation* (ce s-a OBSERVAT: `none` / `poc` / `active`), *Automatable*
și *Technical Impact*. Până aici le deduceam — Automatable și Technical Impact din
vector (euristici), Exploitation dintr-un prag EPSS, adică o PREVIZIUNE luată drept
OBSERVAȚIE. CISA le publică ea însăși, pentru fiecare CVE pe care l-a evaluat, în
înregistrarea CVE (containerul ADP „CISA-ADP"), fără cheie:

    https://cveawg.mitre.org/api/cve/<CVE>

```
"containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP", ...},
  "metrics": [{"other": {"type": "ssvc", "content": {
      "timestamp": "2025-04-08T15:16:38.515188Z", "role": "CISA Coordinator",
      "version": "2.0.3", "options": [{"Exploitation": "none"},
      {"Automatable": "yes"}, {"Technical Impact": "total"}]}}}]}]}
```

## De ce serviciul CVE, per CVE, și nu o oglindă git

Aceeași înregistrare există în trei locuri: serviciul CVE (`cveawg.mitre.org`),
`CVEProject/cvelistV5` și `cisagov/vulnrichment`. Se alege UNUL, cel mai ieftin, și
nu se construiește și al doilea. Măsurat pe 2 octombrie 2026 (80 de CVE-uri ale
gazdei; un client de pe un laptop, deci cifrele de timp sunt ale rețelei de acolo):

| Cale | Cost |
|---|---|
| `cveawg.mitre.org/api/cve/<CVE>` | 19,0 s și 734 KiB pentru 80 de înregistrări (0,1 s pauză); limită declarată `25000;w=60`; zero disc |
| `raw.githubusercontent.com/.../cves/<an>/<N>xxx/<CVE>.json` | 25,7 s și 1,5 MiB pentru 80; înregistrarea întreagă (și CNA); limită nedeclarată |
| `cvelistV5`, clonă completă | 3,0 GB (mărimea raportată de GitHub); arhiva zilnică 618 MB; delta orară 0,3–0,4 MB |
| `cvelistV5`, clonă parțială (`--filter=blob:none --depth 1`) + `sparse-checkout` | gol: 9,6 MB, 5 s; cu 80 de fișiere: 50 MB, 2,4 s; apoi `fetch` + `checkout` la o zi distanță: +9,8 MB și ~17 s (un `fetch` fără nimic nou: 10–43 s); `.git` crește ~10 MB pe zi fără `gc` (~3,5 GB pe an) |

Oglinda git ar cere în plus binarul `git`, un director scriibil sub `ProtectSystem=strict`,
lista de căi menținută pe măsură ce se schimbă CVE-urile deschise, și curățenie
periodică; nu aduce nimic ce ne trebuie (CVSS vine de la Red Hat/OSV/scaner, intervalele
afectate nu se folosesc). Argumentul „oglinda merge și când rețeaua nu merge" e deja
îndeplinit: răspunsurile se scriu în tabela `vulnrichment` din Postgres, ca `kev_catalog`,
iar trecerea de evaluare citește DIN ea — un CVE deja întrebat rămâne cunoscut oricât
ar cădea rețeaua; doar un CVE nou așteaptă. Serviciul CVE întoarce EXACT același
container CISA-ADP (cu aceleași `timestamp` și `version`), deci proveniența se păstrează
întreagă: sursa e „CISA-ADP, prin înregistrarea CVE", cu momentul evaluării din
înregistrare (`ssvc_at`), nu cu ora descărcării.

## Ce înseamnă „nu avem valoare"

Trei stări, și nu sunt aceeași:

  * **niciun rând** — nu am întrebat încă (sau sursa e căzută). Necunoscut: punctul
    rămâne neluat, iar constatarea e gri;
  * **`found` fără puncte** — CVE-ul există, dar CISA nu l-a evaluat (încă). E un
    răspuns, nu o lipsă. Măsurat pe gazda de producție, 2 octombrie 2026, pe cele 406
    de CVE-uri distincte deschise: CISA a publicat puncte pentru 196 = **48,3%**, iar
    acoperirea depinde de ecosistem — npm 78/78, composer 36/36, go 45/57, alpine
    13/16, **deb 13/185 (7%)**, rpm 6/32 (19%). Pe rânduri, Exploitation vine din
    presupunerea `kev_absent` la 395 din 812 = **49%**. (Un eșantion anterior de 78 de
    CVE-uri, în mare parte npm/composer, dădea 80%: nu conținea niciunul din cele 185
    de CVE-uri Debian de nucleu. Pe un eșantion de 320 de CVE-uri Red Hat, 2019–2026,
    acoperirea e de 41%, cu 8–15% pe 2019–2021, 62–78% pe 2022–2024 și ~40% pe
    2025–2026: curba pe ani e adevărată, cifra pe gazdă nu era.);
  * **`not_found`** — 404.

## Un parser orb arată ca „CISA n-a evaluat nimic"

Dacă CISA își schimbă `orgId`, rolul sau forma `options`, fiecare răspuns devine
„found fără puncte", iar Exploitation cade tăcut pe `none`: presupunerea `kev_absent`
hotărăște deja 395 din 812 rânduri pe producție, deci un parser orb ar muta tăcut
jumătate din pagină. Alarma pentru asta a avut două defecte, ambele măsurate pe
2 octombrie 2026, înainte de forma de azi:

  * **Se ștergea singură în cel mult o oră.** Verdictul stătea în `intel_state.detail`
    al rândului `vulnrichment`, iar `mirror.run_lookups` rescrie `detail` ÎNTREG la
    sfârșitul oricărei treceri care a primit vreun răspuns. Reprodus: trecerea 1 (30 de
    CVE-uri, zero puncte) ridica `blind`; trecerea 2 (5 CVE-uri, zero puncte) îl ștergea
    și raporta `ok`. `enrich.run` rulează din oră în oră.
  * **Nu se evalua aproape niciodată.** Controlul se cerea doar când lotul avea cel puțin
    `CANARY_MIN` (20) CVE-uri `found` fără puncte. O trecere obișnuită de pe producție
    cere ~5–6 CVE-uri (196 evaluate reluate săptămânal ≈ 1,2/oră, ~210 neevaluate reluate
    la două zile ≈ 4,4/oră), deci într-o lume cu parserul orb pragul nu se atingea decât
    la o scanare cu 20+ CVE-uri NOI deodată, iar trecerea de după o ștergea.

Rezultat: „CISA Vulnrichment: ok” însemna „ultima trecere orară a primit răspunsuri”, nu
„parserul încă vede puncte”. Forma de acum are două părți, și fiecare repară câte un
defect:

**1. Controlul pozitiv se cere la FIECARE trecere, indiferent de lot.** Un CVE despre
care se știe că poartă puncte CISA trece live, prin același `fetch_one`, și dacă vine
fără puncte, parserul e orb. Costă o cerere pe oră (limita serviciului: 25.000/min) și
face ca verdictul să nu depindă de mărimea sau compoziția lotului: într-o lume orbă,
fiecare trecere îl calculează. Compoziția lotului nu mai poate nici ridica alarma pe
nedrept: 7% din CVE-urile Debian de nucleu au puncte, deci 20–30 de CVE-uri noi de
`linux-libc-dev` vin fără niciunul cu probabilitatea 0,93^20 ≈ 23%, fără ca parserul să
fi greșit ceva. Controlul trece LIVE, nu din fixture: o înregistrare reținută ar dovedi
doar că parserul încă înțelege formatul VECHI, adică exact ce nu e întrebarea.

**2. Verdictul stă pe rândul LUI din `intel_state`** (`CANARY_SOURCE`, migrația 0049), pe
care `run_lookups` nu-l atinge. Un succes al căutărilor nu mai poate șterge un verdict
de care nu e răspunzător; verdictul se schimbă doar când o NOUĂ încercare a controlului
dă alt răspuns. `last_ok_at` al rândului e momentul ultimei CONFIRMĂRI (controlul a dat
puncte), nu al ultimei treceri: autoverificarea citește vechimea confirmării, deci
„ok” înseamnă „parserul a văzut puncte acum X”, cu X afișat și mărginit.

Variantele respinse, ca să nu fie reinventate:

  * *o măsurătoare pe fereastră* (câte CVE-uri `found` față de câte cu puncte, pe ultimele
    24 de ore de `fetched_at`) — `store` păstrează punctele deja scrise
    (`COALESCE`), deci într-o lume orbă rândurile reluate își mută `fetched_at` și
    PĂSTREAZĂ punctele vechi: fereastra ar arăta sănătos tocmai când nu e;
  * *`blind` într-o cheie pe care un succes nu o poate suprascrie, în același rând* —
    merge, dar ar lăsa într-un singur rând două lucruri cu vârste diferite (ultima
    trecere a căutărilor, ultima confirmare a parserului), iar `last_ok_at` nu ar putea
    fi nici unul, nici celălalt fără o cheie în plus și un citit-apoi-scris.

### Măsurat (2 octombrie 2026), pe cele 400 de CVE-uri deschise ale producției

Răspunsurile reale ale serviciului reluate prin `vulnrichment.ensure` cu un ceas virtual de
o oră pe trecere, într-o lume în care parserul devine orb din prima oră (`orgId`-ul CISA
schimbat în toate răspunsurile). Două stări de plecare: *cohorte desincronizate* (starea
stabilă, ~5,3 CVE cerute pe trecere, 72 de treceri) și *cohortele pornirii la rece* (toate
cerute odată, cum e producția azi, 200 de treceri). Vechiul cod: verdictul calculat în
**0 din 72** de treceri (starea stabilă) și în **4–5 din 200** (cohorte: abia la trecerea 48,
când cele 207 CVE neevaluate ajung la termen); autoverificarea a spus „ok" **72 din 72**,
respectiv 47 de ore, într-o lume cu parserul orb. Codul de acum: verdictul calculat în **72 din
72** și **200 din 200**, `degraded` de la trecerea 1 și până la capăt. Simularea nu are CVE-uri noi
aduse de scanări și nu are căderi de rețea; are răspunsuri reale, codul real al trecerii și SQL-ul
real al `intel_state`.

### Ce poate și ce nu poate spune controlul

  * controlul DĂ puncte → parserul vede puncte pe o înregistrare vie (`control_ok`);
  * toate candidatele citite vin FĂRĂ puncte → parser orb (`control_blind`) — dar numai dacă
    nimic din aceeași trecere nu-l contrazice, vezi mai jos;
  * toate candidatele citite vin fără puncte, DAR parserul a citit puncte pe înregistrările
    gazdei (același parser, același minut, același drum) → nu parserul e orb, ci CANDIDATELE
    au rămas fără puncte (`control_exhausted`);
  * nicio candidată nu se poate citi (cerere picată, 404, răspuns ilizibil) →
    `control_unreadable`: NU se poate spune nimic, iar „nu se poate spune” nu e „în
    regulă”. Autoverificarea îl tratează ca pe un `unknown` cât confirmarea precedentă
    e recentă (`checks.CANARY_UNCONFIRMED_H`: o pană scurtă a serviciului CVE nu e o
    stricăciune a parserului), și ca pe `degraded` mai târziu — sau imediat, dacă lotul
    aceleiași treceri era suspect (`CANARY_MIN` CVE-uri `found` și niciun punct: forma
    alarmei de dinainte, păstrată întreagă).

**„Orb” și „cele trei candidate au amuțit” sunt două fapte, iar aceeași trecere le deosebește.**
Lotul gazdei trece prin același `fetch_one`: dacă a citit puncte (`with_points > 0`), parserul
nu e orb, oricâte candidate vin fără. Verdictul `control_exhausted` cere altă acțiune decât
`control_blind`: nu „parserul s-a stricat”, ci „înlocuiți `CANARY_CONTROL_CVES`”. Dovada vine
doar de la loturile cu puncte, iar majoritatea trecerilor orare au un lot fără niciunul (~5
CVE-uri, câteva evaluate): o regulă care ar judeca fiecare trecere separat ar spune
`control_exhausted` la trecerea cu puncte și `control_blind` la următoarea liniștită,
adică ar repeta minciuna jumătate din timp. De aceea dovada se PĂSTREAZĂ în rând
(`exhausted_proof_at`, preluată de la trecerea precedentă): o trecere liniștită cu toate
candidatele fără puncte rămâne `control_exhausted` cât timp dovada există, iar o trecere în
care controlul nu s-a putut citi n-o șterge. Dovada o șterge doar un `control_ok` (candidatele
au din nou puncte). Costul acceptat: într-o lume cu candidate epuizate, un parser care ar
orbi DUPĂ dovadă rămâne sub `control_exhausted`. Alarma suna oricum `degraded`, dar cu
diagnosticul greșit, **și înlocuirea candidatelor NU o repară**: dovada nu e legată de lista
de candidate, iar într-o lume oarbă `control_ok` nu mai vine niciodată, deci n-are ce s-o
șteargă. Măsurat pe 2 octombrie 2026, cu trei treceri după înlocuire: tot `control_exhausted`.
Singurul indiciu rămâne `batch_with_points: 0` în `facts.canary_detail`. Reparația e să se
păstreze lista de candidate lângă dovadă și să se arunce o dovadă înregistrată sub altă
listă — nefăcută aici, fir separat. Până atunci cazul cere două defecte suprapuse
(toate candidatele își pierd containerul ADP, și abia apoi se rupe parserul).

**Controlul nu atârnă de un singur CVE.** O singură candidată fixată ar fi făcut ca, în
ziua în care înregistrarea ei e retrasă, reevaluată sau își pierde containerul ADP,
fiecare trecere să raporteze „control indisponibil” la nesfârșit. De aceea sunt
`CANARY_CONTROL_CVES` candidate, întrebate pe rând până răspunde una cu puncte: una
retrasă nu dă alarmă (costă o cerere în plus pe trecere), iar parserul e declarat orb
doar dacă TOATE candidatele CITITE vin fără puncte. Candidatele au înregistrări reale
în `tests/fixtures/intel/` și un test verifică că fiecare parsează la puncte.

**Ce NU dovedește controlul**: că parserul citește corect fiecare înregistrare CVE. O
schimbare care atinge doar unele înregistrări (alt rol pentru CVE-uri noi, de exemplu)
lasă controlul verde. Dovedește că formatul pe care l-am citit până azi încă există.

Nu ridică niciodată spre apelant: o sursă căzută lasă punctele neluate, iar de acolo
iese gri, nu o scanare oprită.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.intel import mirror
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

SOURCE = "vulnrichment"
URL = "https://cveawg.mitre.org/api/cve/{cve}"

#: Containerul CISA din înregistrarea CVE: `orgId` e al CISA-ADP, stabil; numele
#: scurt ar putea fi redenumit.
CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
#: Rolul din `content.role`. Arborele nostru (`ssvc.py`) e „CISA Coordinator"; un
#: alt rol ar însemna alt arbore, cu alte puncte.
CISA_ROLE = "CISA Coordinator"

#: Vocabularul arborelui Coordinator. O valoare în afara lui nu se stochează.
_VOCAB: dict[str, tuple[str, frozenset[str]]] = {
    "Exploitation": ("exploitation", frozenset({"none", "poc", "active"})),
    "Automatable": ("automatable", frozenset({"yes", "no"})),
    "Technical Impact": ("technical_impact", frozenset({"partial", "total"})),
}

# --- Cât de des se reia o cerere --------------------------------------------------
# Cifrele astea sunt ALEGERI ale Sentinel (nu ale CISA): nicio sursă nu spune cât de
# des își reîmprospătează evaluările. Ele mută doar CÂT DE REPEDE ajunge la noi o
# evaluare nouă, nu ce decide arborele.
#: Un CVE evaluat: reluat săptămânal (fotografia se schimbă rar; KEV, care schimbă
#: Exploitation în `active`, vine pe alt canal, zilnic).
FOUND_DAYS = 7.0
#: Un CVE existent dar neevaluat: reluat la două zile — CISA recuperează în zile.
UNENRICHED_DAYS = 2.0
NOT_FOUND_DAYS = 7.0
#: Cereri pe trecere (hourly). Limita serviciului e de 25.000/min; pauza e
#: politețe, nu constrângere.
BUDGET = 400
PAUSE_S = 0.1
#: De la câte CVE-uri `found` într-o trecere, zero puncte SSVC fac LOTUL suspect. De la
#: aceeași valoare pornea, înainte, TOATĂ alarma; acum controlul se cere la fiecare
#: trecere, iar suspiciunea a rămas pentru un singur lucru: un control care nu se poate
#: citi, lângă un lot suspect, nu mai primește răgazul unui control care nu se poate
#: citi lângă un lot obișnuit (vezi „Ce poate și ce nu poate spune controlul").
CANARY_MIN = 20
#: Rândul din `intel_state` pe care stă verdictul controlului, SEPARAT de `vulnrichment`
#: ca succesul căutărilor (`run_lookups` rescrie `detail`-ul rândului lui) să nu-l poată
#: șterge. Valoarea trebuie să fie și în CHECK-ul `intel_state_source_check`
#: (migrația 0049); un test o verifică.
CANARY_SOURCE = "vulnrichment_canary"
#: Candidatele CONTROLULUI POZITIV, în ordinea în care se întreabă: înregistrări care
#: poartă un container CISA-ADP cu puncte SSVC, fiecare cu fixture real în
#: `tests/fixtures/intel/cveawg_<CVE>.json` (2 octombrie 2026):
#:   * CVE-2025-29927 — Exploitation `none`, Automatable `yes`, Technical Impact `total`,
#:     evaluat la 8 aprilie 2025;
#:   * CVE-2024-3094 — `none` / `yes` / `total`, 2 aprilie 2024;
#:   * CVE-2023-38545 — `poc` / `no` / `total`, 17 octombrie 2024, cu CISA-ADP între alte
#:     containere ADP (parserul trebuie să-l găsească și când nu e primul).
#: Alegerea e a Sentinel; orice CVE evaluat de CISA ar merge, iar unul vechi și stabil e mai
#: bun decât unul proaspăt, a cărui evaluare ar putea fi încă în curs. **Candidatele NU sunt
#: „CVE-uri care nu sunt ale gazdei": CVE-2025-29927 e o constatare deschisă pe producție.**
#: Controlul nu o stochează ca dată a gazdei (nu scrie nimic în `vulnrichment`); dacă CVE-ul
#: apare și printre cele ale gazdei, lotul îl cere separat, pe drumul lui obișnuit.
CANARY_CONTROL_CVES = ("CVE-2025-29927", "CVE-2024-3094", "CVE-2023-38545")


@dataclass(frozen=True)
class Row:
    status: str                       # "found" | "not_found"
    exploitation: str | None
    automatable: str | None
    technical_impact: str | None
    ssvc_at: datetime | None
    ssvc_version: str | None
    fetched_at: datetime | None

    @property
    def published(self) -> bool:
        """CISA a publicat măcar un punct pentru CVE-ul ăsta."""
        return (self.exploitation is not None or self.automatable is not None
                or self.technical_impact is not None)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    # `fromisoformat` din Python 3.10 cere exact 3 sau 6 zecimale la secunde, iar
    # un RFC 3339 valid are oricâte; fără normalizare, un `...:38.5Z` ar pierde
    # data evaluării, iar punctul ar apărea fără „evaluat la".
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"),
                  value.strip().replace("Z", "+00:00"), count=1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse(payload: Any) -> dict[str, Any] | None:
    """Punctele SSVC ale CISA dintr-o înregistrare CVE, sau `None` dacă răspunsul
    nu e o înregistrare CVE.

    Întoarce mereu un dict cu cele cinci chei când e o înregistrare; punctele sunt
    `None` unde CISA nu a publicat sau unde valoarea iese din vocabular. Dacă sunt
    mai multe evaluări CISA, o alege pe cea mai recentă.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
        return None
    containers = payload.get("containers")
    adp = containers.get("adp") if isinstance(containers, dict) else None
    # (moment, puncte, versiune) pentru fiecare evaluare CISA care are cel puțin
    # un punct valid.
    evaluations: list[tuple[datetime | None, dict[str, str], str | None]] = []
    for container in adp if isinstance(adp, list) else []:
        meta = container.get("providerMetadata") if isinstance(container, dict) else None
        if not isinstance(meta, dict) or meta.get("orgId") != CISA_ADP_ORG_ID:
            continue
        metrics = container.get("metrics")
        for metric in metrics if isinstance(metrics, list) else []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content")
            if not isinstance(content, dict) or content.get("role") != CISA_ROLE:
                continue
            options = content.get("options")
            points: dict[str, str] = {}
            for option in options if isinstance(options, list) else []:
                if not isinstance(option, dict):
                    continue
                for label, value in option.items():
                    spec = _VOCAB.get(label)
                    if spec is not None and isinstance(value, str) and value in spec[1]:
                        points[spec[0]] = value
            if points:
                version = content.get("version")
                evaluations.append((_parse_time(content.get("timestamp")), points,
                                    version[:20] if isinstance(version, str) else None))
    out: dict[str, Any] = {"exploitation": None, "automatable": None,
                           "technical_impact": None, "ssvc_at": None,
                           "ssvc_version": None}
    if evaluations:
        # Cea mai recentă; una fără moment pierde în fața uneia datate, iar la
        # egalitate rămâne prima din răspuns (`max` întoarce primul maxim).
        floor = datetime.min.replace(tzinfo=timezone.utc)
        moment, points, version = max(evaluations, key=lambda ev: ev[0] or floor)
        out.update(points)
        out["ssvc_at"], out["ssvc_version"] = moment, version
    return out


async def fetch_one(http: httpx.AsyncClient, cve: str) -> mirror.Outcome:
    try:
        resp = await http.get(URL.format(cve=cve))
    except httpx.HTTPError as exc:
        return mirror.Outcome("error", error=f"{type(exc).__name__}: {exc}"[:200])
    if resp.status_code == 404:
        return mirror.Outcome("not_found", {})
    if resp.status_code != 200:
        return mirror.Outcome("error", error=f"HTTP {resp.status_code}")
    try:
        record = parse(resp.json())
    except ValueError:
        record = None
    if record is None:
        return mirror.Outcome("error", error="răspuns ilizibil")
    return mirror.Outcome("found", record)


@dataclass(frozen=True)
class Control:
    """Ce a spus controlul pozitiv la o trecere."""
    verdict: str                 # "points" | "no_points" | "unreadable"
    cve: str | None              # candidata care a dat puncte (doar la "points")
    asked: tuple[str, ...]       # candidatele întrebate, în ordine
    why: str | None              # motivul, la "unreadable" / "no_points"


def _has_points(rec: dict[str, Any] | None) -> bool:
    return any((rec or {}).get(k) is not None
               for k in ("exploitation", "automatable", "technical_impact"))


async def _control_result(http: httpx.AsyncClient | None, *,
                          pause_s: float = PAUSE_S) -> Control:
    """Controlul pozitiv: cere LIVE candidatele din `CANARY_CONTROL_CVES`, pe rând, prin
    `fetch_one` — același drum ca pe orice CVE al gazdei — fără să scrie nimic în
    `vulnrichment`. Nu ridică.

    S-a oprit la prima care dă puncte: de regulă o singură cerere. Una citită dar FĂRĂ
    puncte (retrasă, reevaluată, fără container ADP) nu hotărăște nimic singură, se trece
    la următoarea; `no_points` înseamnă că toate cele CITITE vin fără (orb sau epuizate:
    `run_control` deosebește cele două, cu lotul gazdei). Dacă niciuna n-a putut fi citită,
    nu se poate spune nimic.

    Costul în cel mai rău caz (serviciul căzut): `len(CANARY_CONTROL_CVES)` cereri de câte
    `mirror.TIMEOUT_S`, adică 90 s, adăugate trecerii orare; unitatea de mentenanță are
    `TimeoutStartSec=900`, iar trecerea de risc e ultimul ei pas.
    """
    owns = http is None
    client = http or mirror.client()
    asked: list[str] = []
    without_points: list[str] = []
    unreadable: list[str] = []
    try:
        for index, cve in enumerate(CANARY_CONTROL_CVES):
            if index and pause_s:
                await asyncio.sleep(pause_s)
            asked.append(cve)
            try:
                outcome = await fetch_one(client, cve)
            except Exception as exc:  # noqa: BLE001 - controlul nu are voie să strice trecerea
                unreadable.append(f"{cve}: {type(exc).__name__}: {exc}"[:120])
                continue
            if outcome.kind == "found":
                if _has_points(outcome.record):
                    return Control("points", cve, tuple(asked), None)
                without_points.append(cve)
            else:
                unreadable.append(f"{cve}: {outcome.error or outcome.kind}"[:120])
    finally:
        if owns:
            await client.aclose()
    if without_points:
        why = ("fără puncte: " + ", ".join(without_points)
               + (f"; necitibile: {'; '.join(unreadable)}" if unreadable else ""))
        return Control("no_points", None, tuple(asked), why[:300])
    return Control("unreadable", None, tuple(asked), "; ".join(unreadable)[:300])


def _detail_dict(value: Any) -> dict[str, Any]:
    """`intel_state.detail` (jsonb) ca dict, oricum l-ar da driverul."""
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes)):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def _previous_proof(db: Database) -> str | None:
    """`exhausted_proof_at` din verdictul PRECEDENT al controlului, sau `None`.

    `None` și când rândul nu se poate citi: un control fără dovadă păstrată cade pe
    `control_blind`, adică pe varianta zgomotoasă, nu pe cea care liniștește. Nu ridică.
    """
    try:
        row = await mirror.state(db, CANARY_SOURCE)
    except Exception:  # noqa: BLE001 - controlul nu are voie să strice trecerea
        return None
    proof = _detail_dict((row or {}).get("detail")).get("exhausted_proof_at")
    return proof if isinstance(proof, str) and proof else None


async def run_control(db: Database, http: httpx.AsyncClient | None, *, found: int = 0,
                      with_points: int = 0, pause_s: float = PAUSE_S) -> dict[str, Any]:
    """Rulează controlul și scrie verdictul pe rândul `CANARY_SOURCE`. Nu ridică.

    `found` / `with_points` sunt ale LOTULUI acestei treceri. Lotul nu hotărăște singur
    verdictul (îl hotărăște controlul), dar are două roluri: un lot suspect (`CANARY_MIN`
    CVE-uri și niciun punct) împreună cu un control necitibil e citit de autoverificare ca
    „orb”, nu ca „necunoscut”; iar un lot CU puncte dovedește că parserul nu e orb, deci
    candidate care vin toate fără puncte sunt `control_exhausted`, nu `control_blind` (vezi
    „Orb” și „cele trei candidate au amuțit” în docstring-ul modulului, inclusiv de ce dovada
    se păstrează de la o trecere la alta).
    """
    suspect = found >= CANARY_MIN and with_points == 0
    try:
        ctl = await _control_result(http, pause_s=pause_s)
    except Exception as exc:  # noqa: BLE001 - nimic de aici nu are voie să strice trecerea
        ctl = Control("unreadable", None, (), f"{type(exc).__name__}: {exc}"[:200])
    verdict = {"points": "control_ok", "no_points": "control_blind",
               "unreadable": "control_unreadable"}[ctl.verdict]
    #: Când a citit parserul puncte pe o înregistrare a gazdei, cât timp candidatele nu mai
    #: au. Se scrie doar sub `control_exhausted` și se poartă prin `control_unreadable`.
    proof: str | None = None
    if ctl.verdict == "no_points" and with_points > 0:
        proof = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
        verdict = "control_exhausted"
    elif ctl.verdict != "points":
        proof = await _previous_proof(db)
        if ctl.verdict == "no_points" and proof:
            verdict = "control_exhausted"
        elif ctl.verdict == "no_points":
            proof = None
    detail: dict[str, Any] = {
        "canary": verdict, "control_cve": ctl.cve, "asked": list(ctl.asked),
        "suspect_batch": suspect, "batch_found": found, "batch_with_points": with_points}
    if proof:
        detail["exhausted_proof_at"] = proof
    out: dict[str, Any] = {"canary": verdict, "suspect_batch": suspect}
    if ctl.verdict == "points":
        if suspect:
            log.info("Vulnrichment: lot fără puncte, dar controlul pozitiv le are "
                     "(compoziția lotului, nu parser orb)",
                     extra={"detail": f"{found} CVE-uri", "control": ctl.cve})
        await mirror.record(db, CANARY_SOURCE, ok=True, error=None, detail=detail)
        return out
    batch = (f"; lotul acestei treceri: {found} CVE-uri primite și niciun punct"
             if suspect else "")
    if verdict == "control_exhausted":
        # Acțiunea întâi: `mirror.record` taie la 300 de caractere, iar coada e `why`.
        reason = ("candidatele controlului au rămas fără puncte SSVC: înlocuiți "
                  f"CANARY_CONTROL_CVES. Parserul a citit puncte pe CVE-urile gazdei la "
                  f"{proof}; {ctl.why}")
        log.warning("Vulnrichment: candidatele controlului nu mai au puncte (parserul "
                    "citește puncte pe CVE-urile gazdei)", extra={"detail": reason})
    elif verdict == "control_blind":
        reason = ("controlul pozitiv vine FĂRĂ puncte SSVC la toate candidatele citite "
                  f"({ctl.why}), deși au puncte, iar lotul acestei treceri n-a dovedit "
                  f"contrariul: parserul sau forma răspunsului s-a schimbat{batch}")
        log.error("Vulnrichment: parser orb", extra={"detail": reason})
    else:
        reason = ("controlul pozitiv nu a putut fi citit "
                  f"({ctl.why}): nu se poate spune dacă parserul vede punctele CISA{batch}")
        log.warning("Vulnrichment: controlul pozitiv nu se poate citi",
                    extra={"detail": reason})
    await mirror.record(db, CANARY_SOURCE, ok=False, error=reason, detail=detail)
    return out


async def store(db: Database, cve: str, outcome: mirror.Outcome) -> None:
    """Scrie un răspuns `found` / `not_found` în `vulnrichment`.

    Un răspuns `found` FĂRĂ puncte nu șterge punctele deja stocate: CISA nu retrage
    o evaluare, deci „acum nu le văd" e mai probabil un parser sau un răspuns
    trunchiat decât o retragere, iar suprascrisă cu NULL, o evaluare bună ar
    deveni „nepublicată" tăcut.
    """
    rec = outcome.record or {}
    await db.execute(
        """
        INSERT INTO vulnrichment (cve, status, exploitation, automatable,
                                  technical_impact, ssvc_at, ssvc_version, fetched_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now())
        ON CONFLICT (cve) DO UPDATE SET
            status = EXCLUDED.status,
            exploitation = COALESCE(EXCLUDED.exploitation, vulnrichment.exploitation),
            automatable = COALESCE(EXCLUDED.automatable, vulnrichment.automatable),
            technical_impact = COALESCE(EXCLUDED.technical_impact,
                                        vulnrichment.technical_impact),
            ssvc_at = COALESCE(EXCLUDED.ssvc_at, vulnrichment.ssvc_at),
            ssvc_version = COALESCE(EXCLUDED.ssvc_version, vulnrichment.ssvc_version),
            fetched_at = now()
        """,
        cve, outcome.kind, rec.get("exploitation"), rec.get("automatable"),
        rec.get("technical_impact"), rec.get("ssvc_at"), rec.get("ssvc_version"))


async def due(db: Database, cves: set[str], *, now: datetime | None = None) -> list[str]:
    """CVE-urile din `cves` care trebuie (re)cerute, în ordine stabilă. Lipsa
    rândului înseamnă „niciodată cerut"."""
    if not cves:
        return []
    rows = await db.fetch(
        """
        SELECT cve, status, exploitation, automatable, technical_impact, fetched_at
          FROM vulnrichment WHERE cve = ANY($1::text[])
        """, sorted(cves))
    have = {r["cve"]: r for r in rows}
    now = now or datetime.now(timezone.utc)
    out: list[str] = []
    for cve in sorted(cves):
        row = have.get(cve)
        if row is None:
            out.append(cve)
            continue
        age_days = (mirror.hours_since(row["fetched_at"], now=now) or 0.0) / 24
        if row["status"] == "not_found":
            limit = NOT_FOUND_DAYS
        elif (row["exploitation"] is None and row["automatable"] is None
              and row["technical_impact"] is None):
            limit = UNENRICHED_DAYS
        else:
            limit = FOUND_DAYS
        if age_days >= limit:
            out.append(cve)
    return out


async def ensure(db: Database, cves: set[str], *, http: httpx.AsyncClient | None = None,
                 now: datetime | None = None, budget: int = BUDGET,
                 pause_s: float = PAUSE_S) -> dict[str, Any]:
    """Aduce de la CISA ce lipsește sau a îmbătrânit pentru `cves`, apoi rulează controlul
    pozitiv (la fiecare trecere, vezi docstring-ul modulului). Nu ridică."""
    seen = {"found": 0, "with_points": 0}
    try:
        wanted = {c for c in cves if c and mirror.CVE_ID.match(c)}
        todo = await due(db, wanted, now=now)

        async def _store(d: Database, cve: str, outcome: mirror.Outcome) -> None:
            await store(d, cve, outcome)
            if outcome.kind == "found":
                seen["found"] += 1
                if _has_points(outcome.record):
                    seen["with_points"] += 1

        summary = await mirror.run_lookups(db, SOURCE, todo, fetch_one, http=http,
                                           budget=budget, pause_s=pause_s, store=_store)
        summary["wanted"] = len(wanted)
        summary["with_points"] = seen["with_points"]
    except Exception as exc:  # noqa: BLE001 - o sursă căzută nu strică scanarea
        reason = f"{type(exc).__name__}: {exc}"[:200]
        log.warning("Vulnrichment: trecere eșuată", extra={"detail": reason})
        await mirror.record(db, SOURCE, ok=False, error=reason)
        summary = {"status": "failed", "error": reason}
    # Controlul se rulează ORICARE ar fi fost lotul (inclusiv unul gol) și își scrie
    # verdictul pe rândul lui; ordinea față de `run_lookups` nu mai contează.
    summary.update(await run_control(db, http, found=seen["found"],
                                     with_points=seen["with_points"], pause_s=pause_s))
    return summary


async def load(db: Database, cves: set[str]) -> dict[str, Row]:
    if not cves:
        return {}
    rows = await db.fetch(
        """
        SELECT cve, status, exploitation, automatable, technical_impact, ssvc_at,
               ssvc_version, fetched_at
          FROM vulnrichment WHERE cve = ANY($1::text[])
        """, sorted(cves))
    return {r["cve"]: Row(r["status"], r["exploitation"], r["automatable"],
                          r["technical_impact"], r["ssvc_at"], r["ssvc_version"],
                          r["fetched_at"]) for r in rows}
