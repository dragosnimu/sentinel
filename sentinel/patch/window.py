"""Funcționalitatea 08: fereastra de reparare cu întoarcere dovedită.

Lanțul de patch era aproape complet înainte de asta: generarea (`planner.py`),
validarea (`validator.py`), aprobarea în două atingeri (`telegram/patch_flow.py`)
și execuția cu rollback (`runner.py`) existau deja. Ce lipsea era o cadență
programată pentru propunerea automată, o poartă care cere o dovadă reală de
întoarcere înainte de propunere, și o oprire care nu poate fi ocolită dacă un
plan din fereastră a eșuat deja la aplicare.

## Poarta: trei stări, nu două

„Doar reparațiile cu întoarcere DOVEDITĂ" e cerința. Dar dovada vine dintr-un
singur loc — exercițiul de restaurare lunar (Funcționalitatea 07) — și acela
poate dovedi ceva DOAR despre artefacte de tip `path` (arhive `tar.zst`
reale). Un backup `rpm_state` sau `git_ref` e, prin construcție, informativ:
`restore.sh` nu-l restaurează, doar îl citește cu voce tare — vezi
`ARHITECTURA.md` §3.19 și migrația 0042.

O poartă care cere „`restorable_verified` pentru TOATE elementele de backup"
ar respinge pentru totdeauna categoria cea mai frecventă de reparație: un
patch de pachet RPM salvează aproape întotdeauna și versiunea instalată
(`rpm_state`, ca să poată fi refăcută printr-un `dnf downgrade`) ALĂTURI de
o arhivă `path` a configurației — planul din `tests/fixtures/good_plan.json`
face exact asta. Sub o poartă „totul sau nimic", planul ăsta n-ar trece
NICIODATĂ, fereastra ar fi permanent inertă, și nimeni n-ar înțelege de ce.

Deci poarta cere ceva mai îngust și mai adevărat: **cel puțin un element de
backup `path` real**, plus o dovadă recentă (vezi `RESTORE_DRILL_STALE_DAYS`
din `sentinel/selfcheck/checks.py` — aceeași constantă, importată de aici, nu
duplicată) că mecanismul de arhivare-și-extragere CHIAR funcționează pe gazda
asta. Un `rpm_state` alăturat nu strică nimic: rolul lui e să alimenteze pasul
`rollback` din plan (executat automat de `runner.py` la eșec), nu să fie el
însuși extras de exercițiu.

Cele trei stări rezultate:

  * **REVERSIBLE** — planul are un backup `path`, iar cel mai recent exercițiu
    care a atins o arhivă a dovedit-o restaurabilă, de curând. Eligibil.
  * **NOT_REVERSIBLE** — fie planul se declară el însuși irevocabil
    (`risk.reversible: false`), fie cel mai recent exercițiu a găsit o arhivă
    care NU se reface (`corrupt` sau `structure_mismatch`). Blocat, zgomotos:
    e exact defectul pe care exercițiul există să-l prindă, nu o lipsă de
    informație.
  * **UNPROVEN** — orice altceva: niciun backup `path` în plan (doar
    `rpm_state`/`git_ref`, care nu pot produce niciodată o dovadă prin acest
    mecanism), niciun exercițiu care să fi atins vreodată o arhivă, sau o
    dovadă bună dar prea veche. Blocat, dar nu ca un defect — ca o stare încă
    nedovedită. Ce ar trebui construit ca să devină dovedibilă o reparație
    curat `rpm_state`: un exercițiu separat care chiar reinstalează versiunea
    înregistrată într-un mediu izolat (container, chroot) și verifică starea
    pachetului — nu doar citește un fișier text. Nu există azi; nu se
    construiește aici.

## Oprirea la primul eșec — de ce stă la aplicare, nu la propunere

Fereastra rulează o dată pe săptămână și poate elibera un plan; omul atinge
butoanele mai târziu, posibil peste zile. Dacă „oprire la eșec" ar fi impusă
doar la propunere (nu mai elibera NIMIC nou după un eșec), un plan deja
eliberat înainte de eșec ar rămâne cu butonul activ — a doua aplicare tot ar
trece.

De aceea poarta reală e `window_halt()`, recitită în
`telegram/patch_flow.on_stage2` chiar înainte de a rula planul: dacă VREUN
plan eliberat de fereastră a eșuat vreodată la aplicare (`failed`,
`rolled_back`, `rollback_failed`), niciun alt plan eliberat de fereastră nu
mai poate trece prin `on_stage2`, indiferent de ordinea în care omul a atins
butoanele sau de câte propuneri erau simultan în chat. Nu există cale de
ocolire prin Telegram — desfacerea e o decizie de operator, luată în afara
acestui flux (bază de date / procedură scrisă), nu un buton.

Latch-ul e PERMANENT, nu doar pentru rularea curentă a ferestrei: pe o gazdă
unde singurul rollback încercat vreodată a eșuat (măsurat 1 septembrie
2026), o oprire care se resetează singură săptămâna următoare ar fi exact
genul de „recuperare tăcută" pe care restul acestui depozit îl refuză (vezi
watchdog-ul, care golește blocklist-ul în loc să presupună că un detector în
buclă de restart e, totuși, de încredere).

Desfacerea nu e „fără cale", e fără cale PRIN TELEGRAM. `patch_window_overrides`
(migrația 0043) ține câte un rând per execuție iertată — cine, când, de ce —
niciodată un `UPDATE` pe `patch_executions`, care ar rescrie exact istoricul
pe care `sentinel/db/repo/patches.py` îl declară scris-înainte-de-fapt și de
nerescris. Scrierea rândului e azi manuală (psql / un script revizuit
separat): CINE poate ierta un eșec, prin ce ceremonie, e o decizie a
operatorului, nu ceva ce agentul a decis unilateral aici.

## Anunțul informativ — „generat" nu e „propus"

Runda 2 a arătat regresia: cu poarta de mai sus, un plan AI ținut în afara
canalului rapid de aprobare (`unnotified_plans`) putea rămâne INVIZIBIL o
lună întreagă — cât durează primul exercițiu de restaurare care l-ar putea
face eligibil. „Nu poate fi aplicat automat" și „nu trebuie să afli că
există" sunt fapte diferite, iar poarta de eligibilitate n-are voie să le
amestece.

`sentinel/telegram/bot.py:_push_window_gated_notices` trimite, o singură
dată, un mesaj FĂRĂ buton de aplicare pentru fiecare plan AI încă neeliberat
— `patches.unnotified_window_gated_plans` / `mark_window_notice_sent`,
independente de `notified_at` (care rămâne strict despre butonul de
aprobare). Modulul de față nu trimite nimic el însuși: `evaluate()` produce
doar motivul, iar `bot.py` îl pune în text — păstrează separarea „acest
modul nu vorbește cu Telegram" cerută de `test_telegram_names_its_instance.py`.

## Îmbătrânirea candidaților — zgomotoasă sau productivă, niciodată tăcută

Runda 3: `WINDOW_CANDIDATE_MAX_AGE_DAYS` (în `sentinel/db/repo/patches.py`)
taie exact în intervalul în care un plan chiar are nevoie să aștepte —
exercițiul rulează lunar, fereastra săptămânal, iar suma celor două poate
depăși plafonul de 30 de zile. Niciun plafon finit rezolvă asta prin
mărime: problema nu e numărul, e ce se întâmplă la depășire. Un plan care
dispare pur și simplu din `window_candidate_plans` fără nicio urmă ar fi
exact confuzia pe care restul funcționalității o desparte cu grijă — „nimic
nu s-a întâmplat" versus „n-am putut să mă uit" — și, mai rău, ar bloca
PENTRU TOTDEAUNA un plan proaspăt pentru același finding, fiindcă
`planner.generate_for_kev` refuză să redacteze cât timp unul `validated`
există deja.

Deci `run()` expiră explicit, la ÎNCEPUTUL fiecărei rulări —
`repo.expire_stale_window_candidates` — orice candidat mai vechi decât
plafonul: planul devine vizibil ca `expired` în `/patches`, iar
`generate_for_kev` e liber să redacteze unul nou, cu versiuni de pachet și
ceas proaspete, la scanarea următoare. Rulează ÎNAINTEA verificării de
oprire, fiindcă e o operație de întreținere independentă de zăvor — un plan
expirat n-a fost eliberat niciodată, deci n-are nicio legătură cu execuții
eșuate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.selfcheck.checks import RESTORE_DRILL_STALE_DAYS

log = get_logger(__name__)

# Câte planuri neconsiderate încă se citesc într-o rulare, în căutarea primului
# eligibil. Planurile automate sunt plafonate la câteva pe noapte
# (`MAX_PLANS_PER_PASS` în `scan/orchestrator.py`), deci lista nu poate deveni
# mare — plafonul e aici ca interogarea să rămână ieftină, nu ca să limiteze
# ceva care ar fi altfel nemărginit.
CANDIDATE_LIMIT = 10

REVERSIBLE = "reversible"
NOT_REVERSIBLE = "not_reversible"
UNPROVEN = "unproven"


@dataclass(frozen=True)
class GateResult:
    state: str
    reason: str


@dataclass
class WindowOutcome:
    proposed_plan_id: int | None = None
    halted: bool = False
    halt_detail: str | None = None
    candidates: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)
    expired: list[int] = field(default_factory=list)
    detail: str = ""


def _has_path_backup(plan: dict[str, Any]) -> bool:
    items = plan.get("backup") or []
    return any(str(i.get("kind")) == "path" for i in items)


def evaluate(plan: dict[str, Any],
            archive_evidence: dict[str, Any] | None) -> GateResult:
    """Poarta de eligibilitate pentru UN plan. Funcție pură — nu atinge baza,
    ca să poată fi probată fără DB și refolosită identic de fereastră și de
    verificarea de sănătate (o singură sursă de adevăr pentru decizie, chiar
    dacă e recalculată în două locuri)."""
    risk = plan.get("risk") or {}
    if risk.get("reversible") is False:
        return GateResult(
            NOT_REVERSIBLE,
            "planul se declară el însuși irevocabil (risk.reversible=false) — "
            "fereastra nu propune automat nimic fără cale de întoarcere")

    if not _has_path_backup(plan):
        return GateResult(
            UNPROVEN,
            "niciun element de backup de tip 'path' în plan — restul "
            "(rpm_state, git_ref) e doar informativ; exercițiul de restaurare "
            "n-are ce extrage din el, deci nu poate dovedi nimic (vezi "
            "ARHITECTURA.md §3.19)")

    if archive_evidence is None:
        return GateResult(
            UNPROVEN,
            "niciun exercițiu de restaurare n-a atins vreodată o arhivă pe "
            "gazda asta — «are un backup» și «se poate restaura» nu sunt "
            "același fapt")

    age_days = float(archive_evidence.get("age_days") or 0.0)
    if archive_evidence.get("any_bad"):
        return GateResult(
            NOT_REVERSIBLE,
            f"cel mai recent exercițiu care a atins o arhivă (acum "
            f"{age_days:.0f} zile) a găsit cel puțin una care NU se reface — "
            f"fereastra nu propune automat până la un exercițiu recent care "
            f"arată altfel")

    if not archive_evidence.get("all_good"):
        return GateResult(
            UNPROVEN,
            f"cel mai recent exercițiu care a atins o arhivă (acum "
            f"{age_days:.0f} zile) nu a dovedit restaurarea niciuneia "
            f"(verdict neconcludent, de exemplu spațiu insuficient la "
            f"verificare)")

    if age_days > RESTORE_DRILL_STALE_DAYS:
        return GateResult(
            UNPROVEN,
            f"ultima dovadă de restaurare reușită are {age_days:.0f} zile, "
            f"mai veche de {RESTORE_DRILL_STALE_DAYS} — exercițiul trebuie "
            f"repetat înainte ca dovada să mai conteze")

    return GateResult(
        REVERSIBLE,
        f"o arhivă a fost dovedită restaurabilă acum {age_days:.0f} zile, "
        f"prin extragere izolată plus verificare de checksum și structură")


async def run(db: Database, cfg: Config) -> WindowOutcome:
    """Rulează fereastra săptămânală: expiră candidații prea vechi, verifică
    oprirea, verifică dacă mai e un plan în așteptare, altfel caută primul
    candidat eligibil și îl eliberează.

    Scrie ÎNTOTDEAUNA un rând în `patch_window_runs`, indiferent de rezultat —
    „n-a rulat niciodată" trebuie să rămână distinct de „a rulat și n-a găsit
    nimic eligibil", exact tiparul cerut pentru Funcționalitatea 08 (vezi
    docstring-ul lui `check_restore_drill` din 07, pe care ăsta îl continuă).

    Expirarea candidaților prea vechi (`expire_stale_window_candidates`) e
    PRIMUL lucru făcut, înaintea oricărei verificări de oprire: e o operație
    de întreținere independentă de zăvor — un plan expirat n-a fost eliberat
    niciodată, deci n-are nicio legătură cu execuții eșuate — și trebuie să
    ruleze chiar și cât fereastra e oprită de un eșec anterior, altfel un
    plan ar putea îmbătrâni tăcut o săptămână în plus de fiecare dată când
    fereastra e oprită.
    """
    expired = await repo.expire_stale_window_candidates(db)
    if expired:
        log.warning("patch window expired stale candidates",
                   extra={"plans": expired})

    def _with_expired(text: str) -> str:
        if not expired:
            return text
        ids = ", ".join(f"#{p}" for p in expired)
        return (f"{text}; {len(expired)} plan(uri) expirate (prea vechi, "
               f"redactate din nou la scanarea următoare): {ids}")

    halt = await repo.window_halt(db)
    if halt is not None:
        detail = (f"fereastra e oprită: planul #{halt['plan_id']} "
                  f"(execuția #{halt['execution_id']}) a ieșit "
                  f"'{halt['status']}' — niciun plan nou din fereastră nu se "
                  f"propune până la o decizie a operatorului")
        detail = _with_expired(detail)
        log.error("patch window halted by a prior failure",
                 extra={"execution_id": halt["execution_id"],
                        "plan": halt["plan_id"]})
        await repo.record_window_run(db, candidates=0, proposed_plan_id=None,
                                     halted=True, detail=detail, skipped=[])
        return WindowOutcome(halted=True, halt_detail=detail, detail=detail,
                             expired=expired)

    outstanding = await repo.outstanding_window_plan(db)
    if outstanding is not None:
        detail = (f"planul #{outstanding['id']}, propus deja de fereastră, "
                  f"încă așteaptă o decizie — niciunul nou nu se propune "
                  f"peste el")
        detail = _with_expired(detail)
        await repo.record_window_run(db, candidates=0, proposed_plan_id=None,
                                     halted=False, detail=detail, skipped=[])
        return WindowOutcome(detail=detail, expired=expired)

    candidates = await repo.window_candidate_plans(db, limit=CANDIDATE_LIMIT)
    if not candidates:
        detail = _with_expired("niciun plan validat în așteptarea ferestrei")
        await repo.record_window_run(db, candidates=0, proposed_plan_id=None,
                                     halted=False, detail=detail, skipped=[])
        return WindowOutcome(detail=detail, expired=expired)

    evidence = await repo.latest_archive_drill_summary(db)
    skipped: list[dict[str, Any]] = []
    for row in candidates:
        gate = evaluate(row.plan, evidence)
        if gate.state == REVERSIBLE:
            await repo.mark_proposed_by_window(db, row.id)
            detail = _with_expired(f"planul #{row.id} eliberat: {gate.reason}")
            log.warning("patch window released a plan",
                       extra={"plan": row.id, "reason": gate.reason})
            await repo.record_window_run(
                db, candidates=len(candidates), proposed_plan_id=row.id,
                halted=False, detail=detail, skipped=skipped)
            return WindowOutcome(proposed_plan_id=row.id, candidates=len(candidates),
                                 skipped=skipped, detail=detail, expired=expired)
        skipped.append({"plan_id": row.id, "state": gate.state, "reason": gate.reason})

    detail = _with_expired(
        f"{len(candidates)} plan(uri) în așteptare, niciunul eligibil încă")
    await repo.record_window_run(db, candidates=len(candidates), proposed_plan_id=None,
                                 halted=False, detail=detail, skipped=skipped)
    return WindowOutcome(candidates=len(candidates), skipped=skipped, detail=detail,
                         expired=expired)
