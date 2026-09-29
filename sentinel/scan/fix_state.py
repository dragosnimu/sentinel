"""Reparația e instalată — dar rulează? Ce știe gazda, nu ce sperăm.

Măsurat pe gazda de producție la 29 septembrie 2026: 491 de constatări `dnf`
deschise, TOATE pachete `kernel*`, iar cea mai nouă reparație de care aveau
nevoie (5.14.0-687.51.1) era deja instalată de o zi. `rpm -q kernel-core` arăta
trei nuclee (687.46.1, 687.49.1, 687.51.1), `uname -r` arăta cel mai vechi dintre
ele, iar `dnf --assumeno update kernel-core` răspundea „Nothing to do". Singura
remediere rămasă e o repornire — și nimic din Sentinel nu știa să spună asta.
Planificatorul propunea în schimb `dnf -y update kernel*`, o operație nulă;
planurile erau declarate nereversibile, poarta de etapa 1 le refuza, iar
operatorul a încercat patru zile să le aplice.

## De ce `dnf` le listează totuși

Nu e o scăpare a scanerului. `dnf updateinfo list --security` (modul implicit,
„available") compară avizele cu pachetele CELE MAI NOI instalate, plus cele ale
nucleului care RULEAZĂ — `running_kernel_pkgs` din
`dnf/cli/commands/updateinfo.py`, citit de pe gazdă: toate pachetele instalate
cu același `SOURCERPM` ca nucleul curent. Cu nucleul vechi în execuție, avizele
mai noi decât el rămân în listă oricâte nuclee noi s-ar instala. Sursa nu e o
presupunere: cifrele de mai sus se explică doar așa.

## Ce dovedește o constatare „în așteptarea repornirii"

Trei fapte, toate citite de pe gazdă în aceeași trecere, niciunul dedus:

  1. o instanță instalată a pachetului are versiunea >= cea care repară
     (`rpm -qa`, cu epoch, comparată ca `rpm`);
  2. instanța pachetului din nucleul care rulează are versiunea < cea care repară
     — nucleul care rulează se află din `uname -r`, iar „pachetele lui" din
     `SOURCERPM`, exact regula lui dnf;
  3. `dnf` listează constatarea (altfel n-ar exista un rând de clasificat).

Dacă (1) nu e adevărat, reparația nu e instalată: constatarea rămâne deschisă și
planul de patch e răspunsul corect. Dacă (1) e adevărat dar (2) nu se poate
stabili, e o contradicție cu ce a listat dnf, iar contradicția rămâne deschisă —
o constatare ascunsă din greșeală e mai rea decât una zgomotoasă.

## Trei rezultate, nu două

    pending_reboot   dovedit: reparația e pe disc, nu rulează
    not_pending      dovezile s-au citit și NU susțin starea (reparația nu e
                     instalată, sau rulează deja și dnf o listează totuși)
    unknown          dovezile NU s-au putut citi (rpm lipsește, ieșire ilizibilă,
                     nucleul care rulează nu e în baza rpm: compilat local,
                     livepatch)

„Necunoscut" nu e „în regulă" și nu e „a dispărut reparația": nu ȘTERGE un
verdict `pending_reboot` dovedit data trecută. Fără regula asta, o cădere a lui
`rpm` la 03:00 ar rescrie verdictul celor 491 de constatări în „necunoscut",
planificatorul le-ar vedea din nou ca planificabile, iar cinci planuri `dnf
update` ar reveni.

## Ce face verdictul cu constatarea: nimic la `status`

Constatarea rămâne `open`. Reparația e pe disc, dar gazda rulează în continuare
codul vulnerabil: e exploatabilă, iar orice cifră „KEV deschise" trebuie să o
numere. Prima variantă o muta în `deferred`, ceea ce ar fi scos din numărătoare
cinci dintre cele șapte constatări KEV deschise — un panou cu „2 KEV" peste un
nucleu cu un CVE exploatat activ. Decizia operatorului, 29 septembrie 2026:
rămân numărate.

Verdictul îl citesc doar cei care ACȚIONEAZĂ pe constatare, prin predicatul unic
`findings.pending_reboot_sql`: planificatorul (nu redactează un plan pentru ea) și
botul (`/planifica` explică de ce nu; `/vuln` și `/vulnerabilitati` o marchează).
Nu există migrație, stare nouă sau grup nou în agregator.

Pentru că verdictul e în `raw`, iar upsertul rescrie `raw` întreg la fiecare
scanare, „unknown nu șterge" nu vine de la sine (cum ar veni de la o coloană pe
care upsertul n-o atinge): `reconcile` citește verdictul de ieri ÎNAINTE de
upsert și îl duce înainte peste un `unknown`.

## Ce NU face, dinadins

  * Nu generalizează la „o bibliotecă actualizată cât timp un proces o ține
    mapată". `dnf needs-restarting` există, dar lucrează pe procese, nu pe
    constatări, și n-are o legătură de la un proces la un CVE. Mai important:
    cazul acela e invers — dnf NU mai listează avizul (pachetul e actualizat),
    deci scanarea închide constatarea ca rezolvată, și aici problema nu e
    zgomotul, ci o închidere prematură. E o decizie de proiectare separată, nu o
    extensie a asta. Măsurat pe gazdă: `needs-restarting -r` cere repornire pentru
    `kernel`, `microcode_ctl` și `systemd`; niciun aviz de securitate deschis nu
    privește ultimele două, deci n-am ce lega.
  * Nu citește nucleul implicit la pornire. `/boot/grub2` e 0700 root, iar
    `grubby --default-kernel` rulat de un utilizator neprivilegiat tipărește
    `/boot` și iese cu 0 — un răspuns care arată a răspuns. Mesajul către
    operator spune că nu poate verifica și îi dă comanda.
  * Nu repornește nimic, și nu poate: `rpm -qa` e singura comandă rulată.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Final

from sentinel.db.repo.findings import FIX_PENDING_REBOOT
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

PENDING: Final = FIX_PENDING_REBOOT
NOT_PENDING: Final = "not_pending"
UNKNOWN: Final = "unknown"

#: Cât așteptăm după `rpm -qa`.
#:
#: Măsurat pe gazda reală, 29 septembrie 2026, sub restricțiile unității de
#: scanare (`systemd-run` cu aceleași proprietăți, `Nice=19`, I/O idle): 1118
#: pachete, 82 KB de ieșire, 0,69 secunde, cod 0. Plafonul de 60 nu derivă din
#: cifra asta — prinde un `rpm` atârnat pe o încuietoare a bazei, nu o rulare
#: normală, deci are marjă de aproape două ordine de mărime.
RPM_TIMEOUT_S: Final = 60

#: Cel mai rău caz al modulului, pentru bugetul unității de scanare. Vezi
#: `os_packages.WORST_CASE_TIMEOUT_S`: o singură comandă, deci plafonul ei.
WORST_CASE_TIMEOUT_S: Final = RPM_TIMEOUT_S

# `rpm -qa --qf`: patru câmpuri separate prin TAB. `%{EPOCH}` tipărește literal
# `(none)` fără epoch, iar `gpg-pubkey` are `(none)` și la ARCH și la SOURCERPM —
# ambele forme sunt tratate mai jos. `\t` și `\n` sunt secvențe pe care rpm le
# interpretează singur, nu shell-ul.
_QF: Final = "%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"


@dataclass(frozen=True)
class Pkg:
    """O instanță instalată, așa cum o tipărește `rpm -qa`."""
    name: str
    evr: str          # `(none):5.14.0-687.46.1.el9_8` — epoch inclus, cum îl dă rpm
    arch: str
    srpm: str         # `(none)` la pachetele fără sursă (gpg-pubkey)


@dataclass(frozen=True)
class HostState:
    """Ce se știe despre gazdă în trecerea asta.

    `error` setat înseamnă că starea NU se poate folosi: orice clasificare pe ea
    iese `unknown`. Un `HostState` fără eroare are `running_srpm` stabilit.
    """
    packages: dict[str, tuple[Pkg, ...]] = field(default_factory=dict)
    release: str | None = None       # `uname -r`, ex. 5.14.0-687.46.1.el9_8.x86_64
    running_srpm: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Verdict:
    state: str
    reason: str
    installed: str | None = None     # cea mai nouă instanță de pe disc, fără epoch 0
    running: str | None = None       # instanța din nucleul care rulează

    def as_raw(self) -> dict[str, Any]:
        """Ce se scrie în `findings.raw.fix_state` — dovada, nu doar verdictul.

        Rămâne pe rând ca operatorul să poată citi CE a văzut scanarea:
        `SELECT raw->'fix_state' FROM findings WHERE id = ...`.
        """
        out: dict[str, Any] = {"state": self.state, "reason": self.reason}
        if self.installed is not None:
            out["installed"] = self.installed
        if self.running is not None:
            out["running"] = self.running
        return out


# --- comparația de versiuni --------------------------------------------------
# Aceeași comparație ca la execuție (`sentinel.patch.checks`), verificată acolo
# contra `rpm.labelCompare`. Importată leneș, ca `planner._installed_nvr`: modulul
# de verificări trage după el motorul bazei de date și clientul executorului, iar
# un import de sus ar face din scanare un consumator al lor la încărcare.
def _rpm():
    from sentinel.patch.checks import _format_evr, _parse_rpm_evr, _rpm_evr_cmp
    return _rpm_evr_cmp, _parse_rpm_evr, _format_evr


def _fmt(evr: str) -> str:
    _, parse, fmt = _rpm()
    return fmt(*parse(evr))


def newest(evrs: list[str]) -> str | None:
    """Cea mai nouă dintre câteva versiuni, sau None dacă lista e goală."""
    cmp, _, _ = _rpm()
    best: str | None = None
    for e in evrs:
        if best is None or cmp(e, best) > 0:
            best = e
    return best


# --- citirea gazdei ----------------------------------------------------------
def parse_rpm_qa(text: str) -> tuple[dict[str, tuple[Pkg, ...]], str | None]:
    """`rpm -qa --qf` -> (pachete pe nume, eroare).

    O linie cu alt număr de câmpuri decât patru face TOT rezultatul inutilizabil:
    o linie sărită în tăcere ar fi o instanță lipsă, iar lipsa unei instanțe e
    exact ce ar transforma „reparația e instalată" în „nu e". La fel o ieșire
    goală: o gazdă rpm are sute de pachete, deci zero înseamnă că nu s-a citit.
    """
    by_name: dict[str, list[Pkg]] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) != 4 or not parts[0] or not parts[1]:
            return {}, f"linia {n} din `rpm -qa` nu are forma așteptată: {raw[:120]!r}"
        by_name.setdefault(parts[0], []).append(Pkg(*parts))
    if not by_name:
        return {}, "`rpm -qa` n-a întors niciun pachet"
    return {k: tuple(v) for k, v in by_name.items()}, None


def find_running_srpm(packages: dict[str, tuple[Pkg, ...]],
                      release: str) -> tuple[str | None, str | None]:
    """`SOURCERPM`-ul nucleului care rulează, după `uname -r` — sau motivul pentru
    care nu se poate afla. Regula lui dnf: pachetul instalat al cărui
    `versiune-release.arch` e chiar șirul din `uname -r`.

    Exact UN `SOURCERPM` distinct. Zero înseamnă un nucleu care nu vine dintr-un
    pachet instalat (compilat local, livepatch, șters de pe disc după pornire);
    mai multe, că șirul nu identifică un singur nucleu. În ambele cazuri
    răspunsul cinstit e „nu știu", nu o alegere.
    """
    _, parse, _ = _rpm()
    srpms: set[str] = set()
    for insts in packages.values():
        for p in insts:
            _, ver, rel = parse(p.evr)
            if f"{ver}-{rel}.{p.arch}" == release and p.srpm != "(none)":
                srpms.add(p.srpm)
    if len(srpms) == 1:
        return next(iter(srpms)), None
    if not srpms:
        return None, (f"niciun pachet instalat nu corespunde nucleului care "
                      f"rulează ({release}): compilat local, livepatch sau "
                      "pachet șters după pornire")
    return None, (f"{len(srpms)} pachete-sursă diferite se potrivesc nucleului "
                  f"{release}: nu se poate alege unul")


async def _run_rpm() -> tuple[int, str, str]:
    """`rpm -qa` cu plafon. (rc, stdout, stderr); 124 la timeout, 127 dacă
    `rpm` nu există — aceleași coduri ca shell-ul, ca eroarea să se citească."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "rpm", "-qa", "--qf", _QF,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except OSError as exc:
        return 127, "", f"rpm nu poate fi pornit: {exc}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=RPM_TIMEOUT_S)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", "timeout"
    return (proc.returncode or 0, out.decode(errors="replace"),
            err.decode(errors="replace"))


def _uname_release() -> str | None:
    """`uname -r`, din apelul de sistem — nu dintr-un subproces care ar putea lipsi."""
    uname = getattr(os, "uname", None)
    return uname().release if uname else None


async def read_host() -> HostState:
    """Citește gazda. Nu ridică: orice nu merge devine `HostState.error`."""
    release = _uname_release()
    if not release:
        return HostState(error="nu se poate citi versiunea nucleului care rulează")

    rc, out, err = await _run_rpm()
    if rc != 0:
        return HostState(release=release, error=(
            f"`rpm -qa` a eșuat (cod {rc}): {(err.strip() or out.strip())[:200]}"))

    packages, error = parse_rpm_qa(out)
    if error:
        return HostState(release=release, error=error)

    srpm, error = find_running_srpm(packages, release)
    if error:
        return HostState(packages=packages, release=release, error=error)
    return HostState(packages=packages, release=release, running_srpm=srpm)


# --- clasificarea ------------------------------------------------------------
def classify(package: str | None, fixed: str | None, host: HostState) -> Verdict:
    """Funcție PURĂ: aceleași intrări, același verdict, fără gazdă și fără rețea.

    Separată de citire ca fiecare ramură să se poată încerca cu o gazdă
    fabricată — un test care are nevoie de un `rpm` ca să verifice o comparație
    nu se scrie niciodată.
    """
    if host.error is not None:
        return Verdict(UNKNOWN, host.error)
    if not package or not fixed:
        return Verdict(NOT_PENDING, "constatarea nu numește pachetul sau versiunea "
                                    "care repară — nimic de comparat")

    cmp, _, _ = _rpm()
    insts = host.packages.get(package, ())
    if not insts:
        return Verdict(NOT_PENDING, f"{package} nu e instalat, deși dnf îl listează")

    best = insts[0]
    for p in insts[1:]:
        if cmp(p.evr, best.evr) > 0:
            best = p
    installed = _fmt(best.evr)

    if cmp(best.evr, fixed) < 0:
        return Verdict(NOT_PENDING, f"reparația ({fixed}) nu e instalată; cea mai "
                                    f"nouă versiune de pe disc e {installed}",
                       installed=installed)

    # Reparația E pe disc. Rămâne de dovedit că nu rulează.
    running = [p for p in insts if p.srpm == host.running_srpm]
    if not running:
        return Verdict(NOT_PENDING, (
            f"reparația e instalată ({installed}), dar {package} n-are nicio "
            "instanță din nucleul care rulează, așa că nu se poate spune că așteaptă "
            "o repornire — dnf o listează totuși, iar contradicția rămâne deschisă"),
            installed=installed)
    run = running[0]
    for p in running[1:]:
        if cmp(p.evr, run.evr) > 0:
            run = p
    if cmp(run.evr, fixed) >= 0:
        return Verdict(NOT_PENDING, (
            f"nucleul care rulează are deja reparația ({_fmt(run.evr)}), dar dnf o "
            "listează totuși — contradicție, rămâne deschisă"),
            installed=installed, running=_fmt(run.evr))
    return Verdict(PENDING, (
        f"reparația {fixed} e instalată ({installed}); rulează {_fmt(run.evr)}"),
        installed=installed, running=_fmt(run.evr))


def is_pending_row(row: dict[str, Any]) -> bool:
    """Rândul de constatare e „reparat, în așteptarea repornirii"?

    Citește booleanul `fix_pending_reboot`, calculat în SQL de
    `findings.pending_reboot_sql` (`get_finding`, `list_open`): o singură
    definiție, pentru bot, `/vuln`, `/vulnerabilitati` și planificator. Un rând
    fără cheia asta (un test, un apelant vechi) NU e în așteptare — „nu se știe"
    e planificabil ca înainte.
    """
    return bool(row.get("fix_pending_reboot"))


#: Explicația pentru operator, o propoziție, fără markup — apelantul o
#: escapează. Aceeași în `/planifica` și în `/vuln`, ca cele două să nu spună
#: lucruri diferite despre același rând. NU spune „nu mai e deschisă": e
#: deschisă, iar gazda e expusă până la repornire. „La ultima scanare": verdictul
#: e cel de la 03:15, iar o repornire de după el nu se vede până la scanarea
#: următoare — textul nu afirmă despre prezent ce știe doar despre trecut.
PENDING_EXPLANATION_RO: Final = (
    "reparația e deja instalată pe disc (dnf nu mai are nimic de instalat), dar "
    "la ultima scanare sistemul încă rula nucleul vechi — constatarea rămâne "
    "deschisă, iar gazda expusă, până la repornire. O repornire o aplică; un plan "
    "de patch n-ar schimba nimic. Sentinel nu repornește nimic — decizia e a ta"
)


@dataclass(frozen=True)
class Outcome:
    """Ce a hotărât `reconcile`, ca numere și ca chei — nu ca mesaje."""
    newly_pending: frozenset[str] = frozenset()  # au INTRAT acum în așteptare
    pending: int = 0                # verdictul final e pending_reboot (inclusiv păstrate)
    carried: int = 0                # `unknown` de azi, păstrat din verdictul de ieri
    unknown: int = 0                # `unknown` care a rămas unknown
    cleared: int = 0                # erau în așteptare, dovedit că nu mai sunt


def reconcile(findings: list[dict[str, Any]],
              previous: dict[str, dict[str, Any]], *, today: str) -> Outcome:
    """Pune verdictul de azi față în față cu cel de ieri, ÎNAINTE de upsert.

    Modifică `raw.fix_state` pe loc. Trei lucruri, fiecare cu un motiv:

      * `unknown` peste un `pending_reboot` dovedit și continuu `open` -> se
        păstrează verdictul de ieri (cu `unread` = de ce nu s-a putut citi azi).
        Altfel upsertul l-ar rescrie ca necunoscut, iar planificatorul ar vedea
        constatarea din nou ca planificabilă;
      * `pending_reboot` primește `since`: ziua în care a fost văzut întâi, dusă
        înainte cât timp rămâne în starea asta. Reamintirea către operator spune
        de câte zile așteaptă;
      * ce a INTRAT acum în așteptare (`newly_pending`) e singurul lucru anunțat
        integral — restul a fost anunțat data trecută.

    Un rând `resolved` la scanarea trecută se tratează ca inexistent: `raw` al lui
    nu se rescrie la închidere, deci verdictul lui e cel de dinaintea repornirii,
    nu o stare care a durat. Un rând cu status decis de om (`accepted_risk`,
    `false_positive`, …) nu are un „în așteptare" de păstrat: planificatorul nu-l
    atinge oricum.
    """
    newly: set[str] = set()
    pending = carried = unknown = cleared = 0
    for f in findings:
        raw = f.get("raw")
        cur = raw.get("fix_state") if isinstance(raw, dict) else None
        if not isinstance(cur, dict):
            continue                    # scaner fără verdicte (apt): nu se atinge
        key = f["finding_key"]
        prev = previous.get(key)
        was_resolved = prev is None or prev.get("status") == "resolved"
        prev_fs = {} if was_resolved else (prev.get("fix_state") or {})
        was_pending = prev_fs.get("state") == PENDING
        continuous = (prev is not None and prev.get("status") == "open"
                      and was_pending)

        state = cur.get("state")
        if state == UNKNOWN and continuous:
            raw["fix_state"] = {**prev_fs, "unread": cur.get("reason")}
            carried += 1
            pending += 1
        elif state == PENDING:
            cur["since"] = (prev_fs.get("since") if was_pending and prev_fs.get("since")
                            else today)
            pending += 1
            if not was_pending:
                newly.add(key)
        elif state == UNKNOWN:
            unknown += 1
        elif state == NOT_PENDING and was_pending:
            cleared += 1
    return Outcome(frozenset(newly), pending, carried, unknown, cleared)


async def annotate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Pune verdictul pe fiecare constatare (`raw.fix_state`) și întoarce faptele
    trecerii, pentru `facts` din rezultatul scanerului.

    Nu ridică niciodată: o eroare aici lasă TOATE constatările `unknown`, adică
    exact ce erau înainte să existe modulul. Scanarea e treaba; clasificarea e
    despre ea.
    """
    try:
        host = await read_host()
        verdicts = [classify(f.get("package"), f.get("fixed_version"), host)
                    for f in findings]
    except Exception as exc:  # noqa: BLE001 - nu are voie să pice scanarea
        log.error("clasificarea reparațiilor a eșuat", extra={"detail": str(exc)[:200]})
        host = HostState(error=f"clasificarea a ridicat o excepție: {str(exc)[:200]}")
        verdicts = [Verdict(UNKNOWN, host.error or "") for _ in findings]
    # Scris DUPĂ ce toate verdictele există: o excepție la a 300-a constatare nu
    # lasă 299 clasificate și restul fără, adică o gazdă „pe jumătate" în bază.
    for f, v in zip(findings, verdicts, strict=True):
        f.setdefault("raw", {})["fix_state"] = v.as_raw()
    if host.error:
        # WARNING, nu INFO: constatările rămân cum erau, dar operatorul trebuie să
        # știe că nu s-a putut face deosebirea, nu s-o deducă din cifre.
        log.warning("nu s-a putut deosebi „reparație instalată” de „neinstalată”",
                    extra={"detail": host.error})
    return {"running_kernel": host.release, "error": host.error}
