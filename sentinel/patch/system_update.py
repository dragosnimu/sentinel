"""Actualizările de sistem: planuri construite în cod, nu de un model.

`planner.py` întreabă un model fiindcă remedierea unui CVE e o judecată: ce pachet,
ce serviciu, ce se repornește. Un update nu e. Faptele sunt toate deterministe și sunt
deja în baza de date sau pe gazdă — pachetul, versiunea instalată, versiunea care
repară — iar forma comenzii e una singură pe familie. Un model aici ar costa un apel și
ar adăuga exact lucrul pe care validatorul există ca să-l prindă.

Ce NU e diferit: planul trece prin ACELAȘI `validator.validate_plan`, fără excepție,
fără parametru, fără ramură pentru planurile de aici. Dacă validatorul respinge o formă
corectă de update, rezultatul e o constatare (grupul e REȚINUT, cu mesajul validatorului,
și operatorul îl vede), nu un motiv de a-l modifica.

## Ce e o tranzacție

**Un plan = o tranzacție de pachete = un singur pas `dnf update <toate pachetele lotului>`**
(sau `apt-get install <pachet>=<versiune> ...`). Nu un pas per pachet. Motivul e în runner:
când ORICE pas de apply pică, rulează TOT `rollback`, inclusiv pentru pachetele la care
pasul nu ajunsese. Cu un pas per pachet, o cădere la al treilea ar fi rulat `downgrade` și
pe pachetele patru-zece, care nu fuseseră atinse, iar `dnf downgrade` către versiunea deja
instalată iese — după codul dnf, din memorie, NEverificat pe o gazdă — cu «No packages marked
for downgrade» și cod 1: adică un «ROLLBACK-UL A EȘUAT» roșu pentru o mașină sănătoasă.
Cu un singur pas, `dnf` hotărăște el: rezolvarea dependențelor, verificarea semnăturilor
și tranzacția de test se fac pentru TOT lotul înainte să se schimbe ceva, deci cele mai
multe căderi (oglindă picată, conflict, disc plin) se întâmplă înainte de orice schimbare.

Ce NU promite asta, spus pe față: `rpm` aplică elementele unei tranzacții pe rând, iar un
scriptlet care pică la mijloc lasă lotul pe jumătate aplicat. Nu există tranzacție atomică
la acest nivel. De aceea rollback-ul există, de aceea starea reală se recitește după
orice rulare (`reconcile`), și de aceea lotul e mic.

## Ce e un lot, și de ce nu 347

347 de constatări sunt 33 de pachete, iar 33 de pachete nu intră într-un plan:

  * cererea pe care operatorul o semnează pe stația lui (`approval.build_request`) are cel
    mult `MAX_REQUEST_CHARS` caractere — un mesaj Telegram — și ține TOATE comenzile
    planului, inclusiv cele două verificări `rpm -q` pe pachet. Un lot care n-ar încăpea ar
    fi refuzat abia la cerere, după trei atingeri și PIN;
  * timeouturile declarate au un buget (`RUN_BUDGET_S`) în care încap apply ȘI rollback.

Lotul se umple deci pe MĂSURĂTOARE, nu pe un număr scris aici: se adaugă o unitate cât
timp planul construit încape în amândouă plafoanele, exact cele pe care le aplică
`approval`. Un plan uriaș nu e răspunsul: «atomic» înseamnă că poți lua unul, iar la un
plan de 33 de pachete rollback-ul ar muta 33 de pachete pe o versiune pe care nimeni n-a
verificat-o împreună.

Unitatea indivizibilă e FAMILIA — pachetele care vin din același pachet-sursă (`httpd`,
`httpd-core`, `httpd-tools`...). Se țin împreună fiindcă `dnf` le trage oricum una după
alta prin dependențe (`httpd` cere `httpd-core` de aceeași versiune): a numi doar pe unul
ar însemna să actualizeze pe ascuns pe celelalte, fără verificare și fără rollback. O
familie care singură nu încape într-un lot e reținută, nu tăiată.

## Ce se REȚINE (și se spune)

Nimic nu dispare tăcut. Un grup reținut apare în răspuns cu motivul:

  * **install-only** (kernel): `dnf downgrade` e `install` al unei versiuni mai vechi, iar la
    un pachet install-only adaugă lângă cel nou, nu înlocuiește (vezi lungul comentariu din
    `validator.py`, «What this module can and cannot say about risk.reversible»). Rollback-ul
    nu restaurează nimic, deci planul ar trebui să se declare ireversibil, iar poarta de la
    primul atingere (`window.evaluate`) îl refuză — corect. Nu construiesc un plan pe care
    poarta îl va refuza oricum. Se citește de pe gazdă (`installonlypkg(...)` din
    furnizările rpm, regula lui dnf), nu dintr-o listă de nume: pe producție `kernel-headers`
    și `kernel-tools` NU sunt install-only, `kernel-core` e. Familia întreagă e reținută:
    `kernel-tools` fără `kernel` e un nucleu pe jumătate;
  * **doar manual** (`MANUAL_ONLY_PACKAGES`): `docs/PATCHING.md` §8 spune că `sshd` nu se
    patchează automat, și verificarea de sănătate nu poate vedea `sshd.service` (executorul
    îl refuză, e în `UNCONTROLLABLE_UNITS`);
  * **un membru deja într-un plan deschis, sau pe un asset protejat**: nu primește un al doilea
    plan, dar nici nu poate fi lăsat în afara lotului surorilor lui — tranzacția lor l-ar trage
    oricum, fără pin și fără verificare. Familia întreagă e reținută, cu planul numit. Regula
    după care se alege între «reține membrul» și «reține familia» e în docstring-ul lui
    `classify`;
  * **un membru rămas în urma țintei surorilor** (`behind_siblings`): constatarea LUI e reparată
    deja pe disc, dar surorile merg la o versiune mai mare, iar `dnf` îl trage după ele. Aceeași
    regulă ca mai sus, ajunsă pe altă ușă; vezi `classify`;
  * orice nu se poate dovedi: versiunea instalată necitită, mai multe versiuni instalate, un
    nume pe care executorul l-ar refuza.

## Un pachet instalat nu e o reparație care rulează

Ce dovedește planul: `rpm -q` (post_verification) spune că versiunea e INSTALATĂ. Ce nu
dovedește: că procesele care folosesc pachetul rulează codul nou. Un daemon pornit înainte
de instalare rulează în continuare biblioteca veche până la restart, iar `dnf
needs-restarting` — care spune care — nu e în gramatica executorului. De aceea nimic de aici
nu spune «actualizat»: spune «instalat», iar pentru pachetele din `REBOOT_REQUIRED_PACKAGES`
spune «instalat, așteaptă repornire».

## Ce nu se poate verifica de pe gazdă

  * că versiunea veche mai e în oglindă (`dnf downgrade` o cere). Se citește doar cu cache-ul
    `dnf`, care nu e scriibil din contul `sentinel`. Planul o spune în
    `restore_instructions_ro`; nu o garantează;
  * că `dnf update <pachet>` nu trage și alte pachete prin dependențe nenumite. Nu există
    simulare în gramatică (`--assumeno`, `--setopt` în afară de una nu sunt permise).
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from sentinel.constants import REBOOT_REQUIRED_PACKAGES
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.db.repo.findings import pending_reboot_sql
from sentinel.logging_setup import get_logger
from sentinel.patch.validator import plan_hash, validate_plan

log = get_logger(__name__)

#: Valoarea lui `patch_plans.generated_by` pentru planurile de aici. Nu `ai`: acela e
#: «ieșit nesupravegheat din planner», iar `window_candidate_plans` ia planurile `ai` și le
#: eliberează săptămânal. Un plan de update cerut de operator nu e al ferestrei.
GENERATED_BY: Final = "update"

#: Statusurile în care un plan de update ÎNCĂ blochează altul. `applied` lipsește dinadins:
#: `LIVE_PLAN_STATUSES` îl include, dar un plan `applied` a cărui constatare a rămas
#: deschisă e un plan care NU a avut efect, iar blocarea ar face constatarea
#: neplanificabilă pentru totdeauna (nimic nu expiră un plan `applied`).
OPEN_PLAN_STATUSES: Final = ("validated", "approved", "scheduled", "applying")

SCOPE_SYSTEM: Final = "system"
SCOPE_PACKAGE: Final = "package"
UPDATE_META_VERSION: Final = 1

#: Plafoanele pasului de pachete. Rămân sub `approval.RUN_BUDGET_S` împreună cu
#: verificările (30 s fiecare); dimensiunea lotului se măsoară, nu se presupune.
APPLY_TIMEOUT_S: Final = 900
ROLLBACK_TIMEOUT_S: Final = 600

#: Spațiul liber pe /var cerut înainte să înceapă. NU e o estimare a ce ocupă lotul (baza
#: nu știe mărimea pachetelor): e un prag sub care o descărcare cade la jumătate.
MIN_FREE_BYTES: Final = 1 << 30

#: Cât din plafonul cererii se lasă nefolosit. Cererea reală are exact aceleași câmpuri de
#: lungime fixă ca cea măsurată aici (hash 64, rezumat 64, nonce 32), deci marja nu
#: acoperă o diferență cunoscută, ci un câmp adăugat într-o zi la `build_request`.
REQUEST_MARGIN_CHARS: Final = 64

#: Cât așteaptă citirea gazdei (o interogare locală, fără rețea).
QUERY_TIMEOUT_S: Final = 20

#: Pachete pe care `docs/PATCHING.md` §8 le scoate din patch-ul automat. Familia lor
#: întreagă e reținută (vezi docstring-ul modulului).
MANUAL_ONLY_PACKAGES: Final = frozenset({"openssh-server"})

#: Ce deosebește numele din baza de date de un argument de linie de comandă. Numele vin de
#: la un scaner; unul care începe cu `-` ar fi citit de `rpm`/`dpkg-query` ca flag. Se folosește
#: DOAR cu `fullmatch`: `$` potrivește și înaintea unui rând nou de la coadă, deci `match` ar fi
#: lăsat să treacă «expat» urmat de un newline — un nume pe care `rpm` l-ar citi ca două argumente.
_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")

#: Familiile de distribuție pentru care știu să construiesc o comandă.
FAMILIES: Final = ("rhel", "debian")

#: Capabilitățile prin care dnf recunoaște un pachet install-only: valoarea implicită a lui
#: `installonlypkgs` din documentația dnf (NU citită din sursa de pe gazdă; pe gazdă s-a
#: verificat doar rezultatul — ce pachete furnizează aceste capabilități).
_INSTALLONLY_PROVIDES: Final = (
    "installonlypkg(kernel)", "installonlypkg(kernel-module)", "installonlypkg(vm)",
    "multiversion(kernel)")
#: Pe lângă furnizări, dnf ține și două NUME în aceeași listă implicită.
_INSTALLONLY_NAMES: Final = frozenset({"kernel", "kernel-PAE"})

_RPM_QF: Final = "%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n"
_DPKG_QF: Final = ("${Package}\\t${Version}\\t${Architecture}\\t${source:Package}"
                   "\\t${db:Status-Abbrev}\\n")

#: Linia pe care o tipărește `rpm -q` pentru un nume care nu e instalat.
_RPM_NOT_INSTALLED: Final = re.compile(r"^package (\S+) is not installed$")
#: Linia pentru o capabilitate fără furnizor la `rpm -q --whatprovides`.
_RPM_NO_PROVIDER: Final = re.compile(r"^no package provides ")
#: Pe stderr la `dpkg-query -W` pentru un nume necunoscut.
_DPKG_NOT_FOUND: Final = re.compile(r"^dpkg-query: no packages found matching (\S+)$")

_SEVERITY_RANK: Final = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Tipuri
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Inst:
    """O instanță instalată a unui pachet, așa cum a citit-o gazda."""
    name: str
    evr: str        # forma folosită și în `equals`, și în pinul de rollback
    arch: str
    source: str     # pachetul-sursă: ce se mișcă împreună (SRPM / `source:Package`)


@dataclass
class HostRead:
    """Ce știe gazda despre pachetele cerute. `error` setat = nu se poate folosi nimic."""
    installed: dict[str, tuple[Inst, ...]] = field(default_factory=dict)
    installonly: frozenset[str] = frozenset()
    error: str | None = None


@dataclass
class Candidate:
    """Un pachet cu cel puțin o constatare deschisă, nerezolvată, cu reparație."""
    package: str
    fixed: str
    finding_ids: list[int]
    kev: bool
    priority: int
    severity: str
    rep_id: int
    rep_cve: str | None
    asset_id: int | None
    asset_name: str | None
    protected: bool


@dataclass
class CandidateSet:
    candidates: list[Candidate] = field(default_factory=list)
    #: pachete ale căror constatări sunt TOATE «instalat, așteaptă repornire» (verdictul scanării)
    pending_reboot: list[str] = field(default_factory=list)
    #: constatări deschise fără nicio versiune care repară
    no_fix_findings: int = 0
    total_findings: int = 0
    #: (pachet, motiv) pentru rânduri pe care familia gazdei nu le poate atinge
    foreign: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class PlanPkg:
    name: str
    before: str
    target: str
    finding_ids: list[int]
    findings: int
    kev: bool
    cve: str | None
    rep_id: int
    severity: str
    reboot: bool


@dataclass
class Held:
    """Un grup lăsat pe dinafară, și motivul — niciodată o dispariție tăcută."""
    packages: list[str]
    code: str
    reason: str


@dataclass
class Lot:
    number: int
    packages: list[PlanPkg]
    plan: dict[str, Any]
    finding_ids: list[int]
    asset_id: int | None


@dataclass
class Selection:
    lots: list[Lot] = field(default_factory=list)
    held: list[Held] = field(default_factory=list)
    #: pachete care ar avea ce primi, dar sunt deja într-un plan deschis: (pachet, plan, stare)
    covered: list[tuple[str, int, str]] = field(default_factory=list)
    #: pachete deja instalate la versiunea care repară: (pachet, versiune instalată, cere repornire)
    already: list[tuple[str, str, bool]] = field(default_factory=list)
    pending_reboot: list[str] = field(default_factory=list)
    #: motivul pentru care nu s-a putut decide nimic. Nu e «nimic de făcut».
    error: str | None = None
    candidates: int = 0
    total_findings: int = 0
    no_fix_findings: int = 0


# ---------------------------------------------------------------------------
# Comparații de versiuni — aceleași ca la execuție
# ---------------------------------------------------------------------------
def _cmp_for(family: str):
    """`_rpm_evr_cmp` / `_deb_evr_cmp` din `checks`: AUTORITATEA, nu o a doua
    implementare. Importate leneș, ca `planner._installed_nvr` — `checks` trage după el
    motorul bazei de date și clientul executorului."""
    from sentinel.patch import checks
    return checks._rpm_evr_cmp if family == "rhel" else checks._deb_evr_cmp


def _epoch(family: str, evr: str) -> int:
    from sentinel.patch import checks
    parse = checks._parse_rpm_evr if family == "rhel" else checks._parse_deb_evr
    return parse(evr)[0]


def needs_reboot(name: str) -> bool:
    """Aceeași regulă ca `validator._validate_reboot_flag`: prefix de nume. Dacă cele două
    ar diverge, validatorul ar respinge planul (planul ar spune `false` pentru un pachet
    pe care el îl vede `true`) — iar un test ține cele două împreună."""
    lowered = name.lower()
    return any(lowered.startswith(p) for p in REBOOT_REQUIRED_PACKAGES)


# ---------------------------------------------------------------------------
# Citirea gazdei
# ---------------------------------------------------------------------------
#: Singurele programe pe care le pornește acest modul, și modul pe care trebuie să-l aibă ca
#: `argv[1]`. Cheia e numele GOL al programului (nu o cale): `/tmp/rpm` nu e `rpm`.
#:
#: `MappingProxyType`, nu `dict`: poarta (`_require_read_only`) își leagă valorile la DEFINIREA ei, ca
#: parametri cu implicită, iar un dicționar legat așa ar rămâne mutabil prin numele lui din modul
#: (`system_update.READ_ONLY_MODE["dnf"] = "-y"` — o linie, din orice fișier). Vederea nu se poate
#: scrie. Pe nume se poate încă REATRIBUI, dar poarta nu mai citește numele: citește ce a legat atunci.
READ_ONLY_MODE: Final = MappingProxyType({"rpm": "-q", "dpkg-query": "-W"})

#: Ce flag-uri (cuvinte care încep cu `-`) are voie să primească fiecare program. Nu o listă de
#: flag-uri INTERZISE: `rpm` are `--eval`/`-E`, `--define`/`-D`, `--macros`, `--rcfile`, `--pipe`
#: (rulează o comandă), `-i`/`-e` (schimbă gazda) și o listă care crește cu versiunea — o listă de
#: interzise ar fi mereu cu un cuvânt în urmă. Ce nu e aici pică. Pe RPM 4.16 doar `--eval` execută
#: `%(...)` din argument; lista albă nu se sprijină pe asta, fiindcă altă versiune poate schimba.
#:
#: O LĂRGIRE a acestei liste (sau a lui `READ_ONLY_MODE`) schimbă ce poate porni procesul `sentinel`
#: (grup `docker`, deci root prin soclu) și e o decizie, nu o corecție: o pază din
#: `tests/security/test_update_has_no_second_apply_path.py` citește valorile din acest fișier și
#: pică dacă nu sunt cele aprobate acolo.
READ_ONLY_FLAGS: Final = MappingProxyType(
    {"rpm": ("-q", "--qf", "--whatprovides"), "dpkg-query": ("-W", "-f")})

#: `%(...)` și `%{lua:...}` execută cod când `rpm` expandează o macro (`rpm --eval "%(id)"`).
_MACRO_EXEC: Final = re.compile(r"%\(|%\{\s*lua\s*:", re.IGNORECASE)


class RefusedCommand(Exception):
    """`_run` a primit un argv care nu e o interogare de citire, deci nu a pornit nimic.

    E o GREȘEALĂ DE PROGRAMARE (cineva a scris un apel nou), nu o stare a gazdei, și de aceea
    nu e un cod de ieșire: 127 înseamnă «programul lipsește», iar o refuzare confundată cu el
    ar arăta ca o gazdă fără `rpm`. Nu moștenește `OSError`, `ValueError`, `LookupError` sau
    `TimeoutError` — ce prind `except`-urile de pe cale ca să transforme o stare a gazdei într-un
    mesaj. Ce o prinde de fapt sunt cele trei `except Exception` care existau înainte (`/update`
    în `bot.py`, citirea de după rulare în `patch_flow`), și fiecare o PUNE ÎN MESAJ cu numele
    tipului și o înscrie în jurnal la nivel `error`: operatorul vede «RefusedCommand: ...», nu «nu
    pot citi starea pachetelor». Nu moștenește `BaseException` dinadins: un handler Telegram
    care moare cu o excepție pe care nu o prinde nimeni tace — iar canalul acela e singurul."""


def _require_read_only(argv: Any, *, modes: Mapping[str, str] = READ_ONLY_MODE,
                       flags: Mapping[str, tuple[str, ...]] = READ_ONLY_FLAGS,
                       macro_exec: re.Pattern[str] = _MACRO_EXEC) -> None:
    """Ridică `RefusedCommand` dacă `argv` nu e o interogare de citire (`rpm -q ...` sau
    `dpkg-query -W ...`). Se cheamă în `_run` ÎNAINTE de orice proces.

    Lista albă e legată aici, la DEFINIRE (cele trei implicite de mai sus), nu citită din globalele
    modulului la fiecare apel. Cu globale, parametrii limitei se puteau înlocui din orice fișier cu o
    atribuire (`system_update.READ_ONLY_FLAGS = {...}`), fără `getattr`, fără `globals()` — și poarta
    ar fi lăsat să treacă `rpm -q --flag-inventat bash`. Acum o atribuire pe numele din modul nu mai
    schimbă nimic din ce refuză poarta. `modes`/`flags`/`macro_exec` NU sunt o cale de lărgire pentru
    cei care cheamă: singurul apel e `_require_read_only(argv)` din `_run`, iar garda din
    `tests/security/` cere exact asta și interzice orice alt fișier să numească poarta. Testele care
    probează mașinăria de pornire o lărgesc pe durata testului împachetând funcția
    (`tests/unit/_system_update_support.py::allow_own_programs`), vizibil, nu prin cod de producție.

    Aici trăiește limita, nu în numele celor care cheamă `_run`: o gardă pe AST verifică
    ortografia apelanților dintr-un fișier, dar `_run` e o funcție importabilă, iar un alias
    (`_apply = _run`), un apel din alt modul sau un `sh -c` adăugat în interiorul ei nu trec
    prin nicio ortografie. Orice argv care ajunge la un proces trece pe aici, oricine l-ar fi dat."""
    # Tipul EXACT, nu `isinstance`: o subclasă de `str` cu un `startswith` care minte, sau una de `list`
    # cu un `__iter__` care dă altceva a doua oară, ar trece de poartă și ar rula altceva.
    if type(argv) is not list or not argv or any(type(a) is not str for a in argv):
        raise RefusedCommand(f"argv nu e o listă nevidă de șiruri (list/str exacte): {repr(argv)[:200]}")
    prog = argv[0]
    shown = repr(argv)[:200]
    if prog not in modes:
        raise RefusedCommand(f"{prog!r} nu e o interogare de citire: {shown}")
    # Un program cu mod și fără listă de flag-uri e o greșeală de programare în cele două tabele, nu un
    # argv rău: fără rândul ăsta ar ieși un `KeyError` (arată a defect, nu a refuz, și nu spune ce s-a
    # întâmplat). Tot fail-closed — nimic nu pornește — dar cu excepția care se citește.
    if prog not in flags:
        raise RefusedCommand(f"{prog!r} are mod, dar nu și listă de flag-uri: tabelele "
                             f"`READ_ONLY_MODE` și `READ_ONLY_FLAGS` nu se potrivesc: {shown}")
    if len(argv) < 2 or argv[1] != modes[prog]:
        raise RefusedCommand(f"argv[1] al lui {prog!r} trebuie să fie {modes[prog]!r}: {shown}")
    for word in argv[1:]:
        if word.startswith("-") and word not in flags[prog]:
            raise RefusedCommand(f"flag în afara listei pentru {prog!r}: {word!r}")
        if macro_exec.search(word):
            raise RefusedCommand(f"un cuvânt care expandează o macro (rulează cod): {word!r}")


async def _run(argv: list[str], limit_s: int = QUERY_TIMEOUT_S) -> tuple[int, str, str]:
    """`(cod, stdout, stderr)`. 127 = binarul lipsește, 124 = timeout — aceleași coduri ca
    shell-ul, ca eroarea să se citească. Un cod negativ e un semnal (sandbox), nu «lipsă».

    Ridică `RefusedCommand` dacă `argv` nu e o interogare de citire — ÎNAINTE de orice proces.
    Procesul primește exact `argv`, fără înveliș: ce a fost verificat e ce rulează."""
    _require_read_only(argv)
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    except OSError as exc:
        return 127, "", f"{argv[0]} nu poate fi pornit: {exc}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=limit_s)
    except asyncio.TimeoutError:  # noqa: UP041 - pe 3.10 nu e încă același cu TimeoutError
        proc.kill()
        await proc.wait()
        return 124, "", "timeout"
    code = proc.returncode if proc.returncode is not None else 0
    return code, out.decode(errors="replace"), err.decode(errors="replace")


def _srpm_source(srpm: str, fallback: str) -> str:
    """`kernel-5.14.0-687.53.1.el9_8.src.rpm` -> `kernel`. Fără sursă (gpg-pubkey,
    pachete făcute local) -> numele pachetului însuși: un pachet fără sursă cunoscută
    nu are cu cine să fie grupat."""
    value = srpm.strip()
    # Orice altă formă decât «nume-versiune-release.src.rpm» nu se interpretează: un pachet a
    # cărui sursă nu se recunoaște stă singur în grupul lui, nu într-unul ghicit.
    if not value.endswith(".src.rpm"):
        return fallback
    value = re.sub(r"\.src\.rpm$", "", value)
    parts = value.rsplit("-", 2)
    return parts[0] if len(parts) == 3 and parts[0] else fallback


def parse_rpm_query(text: str) -> tuple[dict[str, tuple[Inst, ...]], set[str], str | None]:
    """Ieșirea lui `rpm -q --qf _RPM_QF` -> (instanțe pe nume, nume neinstalate, eroare).

    O linie care nu e nici cele patru câmpuri, nici «package X is not installed» face TOT
    rezultatul inutilizabil: o linie sărită în tăcere ar fi o instanță lipsă, iar lipsa unei
    instanțe e exact ce ar transforma «e instalat» în «nu e» (același principiu ca
    `fix_state.parse_rpm_qa`).

    «Package X is not installed» vine pe STDOUT (măsurat pe producție), iar codul de ieșire
    al lui `rpm -q` e NUMĂRUL argumentelor care au eșuat — nu 0/1. Apelantul îl compară cu
    câte astfel de linii a numărat aici."""
    from sentinel.patch import checks

    by_name: dict[str, list[Inst]] = {}
    missing: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        gone = _RPM_NOT_INSTALLED.match(line)
        if gone:
            missing.add(gone.group(1))
            continue
        parts = raw.split("\t")
        if len(parts) != 4 or not parts[0] or not parts[1]:
            return {}, set(), f"linia {n} din `rpm -q` nu are forma așteptată: {raw[:120]!r}"
        name, evr, arch, srpm = parts
        by_name.setdefault(name, []).append(Inst(
            name, checks._format_evr(*checks._parse_rpm_evr(evr)), arch,
            _srpm_source(srpm, name)))
    return {k: tuple(v) for k, v in by_name.items()}, missing, None


def parse_dpkg_query(stdout: str, stderr: str) -> tuple[dict[str, tuple[Inst, ...]], set[str], str | None]:
    """Ieșirea lui `dpkg-query -W -f _DPKG_QF` -> (instanțe, nume negăsite, eroare).

    Doar `ii` (instalat) e o instanță: un pachet doar configurat sau în curs de dezinstalare
    nu e unul pe care să-l actualizezi. Numele negăsite vin pe STDERR
    («dpkg-query: no packages found matching X»), iar codul e 1."""
    by_name: dict[str, list[Inst]] = {}
    for n, raw in enumerate(stdout.splitlines(), 1):
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) != 5 or not parts[0] or not parts[1]:
            return {}, set(), f"linia {n} din `dpkg-query` nu are forma așteptată: {raw[:120]!r}"
        name, version, arch, source, status = parts
        if not status.strip().startswith("ii"):
            by_name.setdefault(name, [])        # răspuns primit: există, dar nu e instalat
            continue
        by_name.setdefault(name, []).append(Inst(name, version, arch, source.strip() or name))
    missing = {m.group(1) for m in (_DPKG_NOT_FOUND.match(ln.strip()) for ln in stderr.splitlines()) if m}
    return {k: tuple(v) for k, v in by_name.items() if v}, missing | {k for k, v in by_name.items() if not v}, None


def parse_installonly(text: str) -> tuple[frozenset[str], int, str | None]:
    """Numele de pachete care furnizează o capabilitate install-only, câte capabilități n-au
    furnizor, și eroarea.

    `rpm -q --whatprovides CAP ...` iese cu cod = numărul capabilităților fără furnizor, deci
    «cod 2» e normal aici, iar «cod 0 și nicio linie» e o pană tăcută care arată la fel ca
    «nimic nu e install-only». Ce le deosebește e un control pozitiv: capabilitatea `rpm` o
    furnizează pachetul `rpm`, pe orice gazdă rpm. Dacă linia asta lipsește, interogarea
    n-a răspuns, iar «nu există niciun install-only» ar fi o minciună."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    failures = sum(1 for ln in lines if _RPM_NO_PROVIDER.match(ln))
    names = {ln for ln in lines if " " not in ln}
    if "rpm" not in names:
        return frozenset(), failures, ("interogarea «ce e install-only» n-a răspuns (controlul "
                                       "pozitiv — pachetul `rpm` — lipsește din ieșire)")
    return frozenset(names - {"rpm"}), failures, None


#: Unde caută `installonlypkgs=`. Constantă, ca un test să poată arăta spre un fișier al lui.
_DNF_CONF_PATHS: Final = ("/etc/dnf/dnf.conf",)


def _dnf_conf_override() -> str | None:
    """`installonlypkgs=` în configurația dnf al gazdei: dnf are atunci o listă pe care nu o
    citesc, deci nu pot spune ce e install-only. Un fișier absent nu spune nimic; unul
    ilizibil NU e «nu spune nimic»."""
    for path in _DNF_CONF_PATHS:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    stripped = line.strip()
                    if not stripped.startswith(("#", ";")) and stripped.lower().startswith(
                            "installonlypkgs"):
                        return (f"{path} redefinește installonlypkgs, o listă pe care Sentinel "
                                "nu o citește")
        except FileNotFoundError:
            log.debug("dnf configuration file absent", extra={"path": path})
            continue
        except OSError as exc:
            return f"{path} nu se poate citi ({exc.strerror or exc}), deci nu pot ști ce e install-only"
    return None


def _short_err(out: str, err: str) -> str:
    return (err.strip() or out.strip())[:200]


async def read_host(family: str, names: list[str], *, with_install_only: bool = True) -> HostRead:
    """Citește ce e instalat din `names`, și ce e install-only. Nu ridică pentru o gazdă care
    răspunde prost (asta devine `HostRead.error`); ridică `RefusedCommand` dacă un argv de
    aici nu mai e o interogare de citire — o greșeală de programare, spusă ca atare.

    Doar nume care arată a nume de pachet ajung în argv (vezi `_NAME_RE`); restul sunt
    tratate de apelant ca «nume neacceptat», nu trecute lui `rpm` să le citească drept flag.

    Fiecare nume cerut trebuie să primească un răspuns — instalat sau «nu e instalat». Un
    nume fără niciunul e o ieșire trunchiată, iar o ieșire trunchiată nu e «nu e instalat».

    `with_install_only=False` sare peste «ce e install-only» (o a doua interogare și configurația dnf):
    recitirea de după rulare vrea doar versiunile, iar o pană la clasificare n-are de ce să
    ascundă starea pachetelor în clipa în care contează cel mai mult.
    """
    safe = sorted({n for n in names if _NAME_RE.fullmatch(n)})
    if not safe:
        return HostRead()

    if family == "rhel":
        code, out, err = await _run(["rpm", "-q", "--qf", _RPM_QF, *safe])
        installed, missing, error = parse_rpm_query(out)
        if error:
            return HostRead(error=error)
        if code != min(len(missing), 255):
            return HostRead(error=f"`rpm -q` a ieșit cu codul {code}, dar a raportat {len(missing)} "
                                  f"pachete neinstalate: {_short_err(out, err)}")
        unanswered = [n for n in safe if n not in installed and n not in missing]
        if unanswered:
            return HostRead(error="`rpm -q` n-a răspuns pentru: " + ", ".join(unanswered[:5]))

        if not with_install_only:
            return HostRead(installed)

        code, out, err = await _run(
            ["rpm", "-q", "--whatprovides", *_INSTALLONLY_PROVIDES, "rpm", "--qf", "%{NAME}\\n"])
        installonly, failures, error = parse_installonly(out)
        if error:
            return HostRead(error=error)
        if code != min(failures, 255):
            return HostRead(error=f"`rpm --whatprovides` a ieșit cu codul {code}, dar {failures} "
                                  f"capabilități n-au furnizor: {_short_err(out, err)}")
        override = _dnf_conf_override()
        if override:
            return HostRead(error=override)
        return HostRead(installed, installonly | _INSTALLONLY_NAMES)

    if family == "debian":
        code, out, err = await _run(["dpkg-query", "-W", "-f", _DPKG_QF, *safe])
        installed, missing, error = parse_dpkg_query(out, err)
        if error:
            return HostRead(error=error)
        if code not in (0, 1) or (code == 1 and not missing):
            return HostRead(error=f"`dpkg-query` a ieșit cu codul {code}: {_short_err(out, err)}")
        unanswered = [n for n in safe if n not in installed and n not in missing]
        if unanswered:
            return HostRead(error="`dpkg-query` n-a răspuns pentru: " + ", ".join(unanswered[:5]))
        # Debian n-are un marcaj install-only: nucleele se instalează în paralel prin
        # pachete `linux-*`. Prefixul e mai larg decât nucleul (`linux-firmware`) — direcția
        # sigură: un pachet reținut degeaba costă un apel manual, unul planificat degeaba
        # costă un rollback care nu restaurează.
        return HostRead(installed, frozenset(n for n in safe if n.startswith("linux-")))

    return HostRead(error=f"platform.family={family!r}: nu știu să citesc pachetele acestei familii")


# ---------------------------------------------------------------------------
# Candidații, din baza de date
# ---------------------------------------------------------------------------
async def load_candidates(db: Database, family: str) -> CandidateSet:
    """Constatările deschise ale scanerului de pachete al gazdei, grupate pe pachet.

    Doar scanerul gazdei (`dnf` pe rhel, `apt` pe debian): `trivy_image` și `trivy_fs` sunt
    conținut de container și lockfile-uri de aplicație, nu pachete ale gazdei.
    """
    from sentinel.patch import planner
    from sentinel.scan import os_packages

    scanner = os_packages.scanner_for(family)
    # Singura valoare interpolată e expresia constantă a lui `pending_reboot_sql`; scanerul, ca
    # orice altă valoare, merge prin parametru.
    rows = await db.fetch(
        f"""
        SELECT f.id, f.package, f.cve, f.severity, f.kev, f.priority, f.fixed_version,
               f.ecosystem, f.asset_id, a.name AS asset_name,
               COALESCE(a.protected, false) AS asset_protected,
               {pending_reboot_sql("f.")} AS fix_pending_reboot
        FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open' AND f.scanner = $1
        ORDER BY f.id
        """,  # noqa: S608
        scanner)

    cmp = _cmp_for(family)
    out = CandidateSet(total_findings=len(rows))
    by_pkg: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        row = dict(r)
        pkg = str(row.get("package") or "").strip()
        if not pkg:
            continue
        reason = planner.unplannable_reason(row.get("ecosystem"), family)
        if reason is not None:
            out.foreign.append((pkg, reason))
            continue
        by_pkg.setdefault(pkg, []).append(row)

    for pkg, group in sorted(by_pkg.items()):
        open_rows = [g for g in group if g.get("fixed_version") and not g.get("fix_pending_reboot")]
        out.no_fix_findings += sum(1 for g in group if not g.get("fixed_version"))
        if not open_rows:
            # Ori toate «instalat, așteaptă repornire», ori nicio reparație cunoscută.
            if any(g.get("fix_pending_reboot") for g in group):
                out.pending_reboot.append(pkg)
            continue
        fixed = str(open_rows[0]["fixed_version"])
        for g in open_rows[1:]:
            if cmp(str(g["fixed_version"]), fixed) > 0:
                fixed = str(g["fixed_version"])
        # Reprezentantul: KEV întâi, apoi prioritatea, apoi cel mai vechi id — o alegere
        # stabilă, ca același set de constatări să dea același plan (același hash).
        rep = sorted(open_rows, key=lambda g: (not g.get("kev"), -(g.get("priority") or 0), g["id"]))[0]
        sev = max((str(g.get("severity") or "info") for g in open_rows),
                  key=lambda s: _SEVERITY_RANK.get(s, 0))
        assets = {g.get("asset_id") for g in open_rows}
        one_asset = next(iter(assets)) if len(assets) == 1 else None
        out.candidates.append(Candidate(
            package=pkg, fixed=fixed, finding_ids=sorted(int(g["id"]) for g in open_rows),
            kev=any(g.get("kev") for g in open_rows),
            priority=max(int(g.get("priority") or 0) for g in open_rows),
            severity=sev, rep_id=int(rep["id"]), rep_cve=rep.get("cve"),
            asset_id=int(one_asset) if one_asset is not None else None,
            asset_name=rep.get("asset_name") if one_asset is not None else None,
            protected=any(bool(g.get("asset_protected")) for g in open_rows)))
    return out


@dataclass(frozen=True)
class CategoryCount:
    kind: str
    label: str
    open_total: int
    with_fix: int


async def category_counts(db: Database) -> list[CategoryCount]:
    """Constatările deschise pe categorie (sistem, container, aplicație), cu și fără reparație.

    Categoria o hotărăște `subject.describe` după SCANER — aceeași funcție ca pagina de
    vulnerabilități și ca `/vulnerabilitati`, nu o a doua hartă. «Necunoscut» apare doar dacă
    are rânduri: un scaner neclasificat trebuie numărat, dar un zero acolo n-ar spune nimic.
    """
    from sentinel.scan import subject

    rows = await db.fetch(
        "SELECT scanner, count(*) AS n, count(*) FILTER (WHERE fixed_version IS NOT NULL) AS with_fix "
        "FROM findings WHERE status = 'open' GROUP BY scanner")
    per: dict[str, list[int]] = {k: [0, 0] for k in subject.KINDS}
    for r in rows:
        kind = subject.describe(r["scanner"], None).kind
        per[kind][0] += int(r["n"])
        per[kind][1] += int(r["with_fix"])
    return [CategoryCount(k, subject.KIND_LABELS[k], per[k][0], per[k][1])
            for k in subject.KINDS if k != subject.KIND_UNKNOWN or per[k][0]]


async def open_update_plans(db: Database) -> list[tuple[int, str]]:
    """Planurile de update încă deschise (în așteptare sau în curs), cele mai vechi întâi."""
    rows = await db.fetch(
        "SELECT id, status FROM patch_plans WHERE generated_by = $1 "
        "AND status = ANY($2::text[]) ORDER BY id",
        GENERATED_BY, list(OPEN_PLAN_STATUSES))
    return [(int(r["id"]), str(r["status"])) for r in rows]


async def last_finished_update_plan(db: Database) -> tuple[int, str] | None:
    """Cel mai recent plan de update care s-a încheiat — aplicat, eșuat sau revenit — sau `None`.

    Comanda propune un lot nou la cerere, nu automat, deci omul e în buclă. Dar un lot nou oferit
    imediat după unul care a eșuat sau a revenit ar arăta ca o continuare firească, iar starea
    gazdei după eșec e exact lucrul pe care nu l-a recitit nimeni. Fereastra săptămânală se oprește
    definitiv la primul eșec; aici decizia (oprire, sau doar avertisment) e a operatorului, iar
    până atunci răspunsul avertizează."""
    rows = await db.fetch(
        "SELECT id, status FROM patch_plans WHERE generated_by = $1 "
        "AND status = ANY($2::text[]) ORDER BY id DESC LIMIT 1",
        GENERATED_BY, ["applied", "failed", "rolled_back"])
    return (int(rows[0]["id"]), str(rows[0]["status"])) if rows else None


async def _covering_plans(db: Database, finding_ids: list[int]) -> dict[int, tuple[int, str]]:
    """finding_id -> (plan, stare), pentru planurile deschise (ORICE origine) care îl acoperă."""
    if not finding_ids:
        return {}
    rows = await db.fetch(
        "SELECT id, status, finding_ids FROM patch_plans "
        "WHERE status = ANY($1::text[]) AND finding_ids && $2::bigint[] ORDER BY id",
        list(OPEN_PLAN_STATUSES), list(finding_ids))
    out: dict[int, tuple[int, str]] = {}
    for r in rows:
        for fid in r["finding_ids"] or []:
            out.setdefault(int(fid), (int(r["id"]), str(r["status"])))
    return out


# ---------------------------------------------------------------------------
# Construirea planului
# ---------------------------------------------------------------------------
def _check(cid: str, desc: str, check: dict[str, Any], *, blocking: bool = True) -> dict[str, Any]:
    return {"id": cid, "desc_ro": desc, "blocking": blocking, "check": check}


def _apply_argv(family: str, pkgs: list[PlanPkg]) -> list[str]:
    if family == "rhel":
        return ["dnf", "-y", "update", *[p.name for p in pkgs]]
    # `=versiune` pe fiecare pachet: forma dovedită pe Ubuntu 24.04 (docs/PATCHING.md §10) și
    # singura în care rollback-ul de mai jos are un contrapunct pe aceeași formă.
    return ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install",
            *[f"{p.name}={p.target}" for p in pkgs]]


def _rollback_argv(family: str, pkgs: list[PlanPkg]) -> list[str]:
    if family == "rhel":
        return ["dnf", "-y", "downgrade", *[f"{p.name}-{p.before}" for p in pkgs]]
    return ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install",
            "--allow-downgrades", *[f"{p.name}={p.before}" for p in pkgs]]


def build_plan(pkgs: list[PlanPkg], *, family: str, scope: str, number: int, total: int,
               asset_id: int | None, asset_name: str | None) -> dict[str, Any]:
    """Planul unui lot. Pură: aceleași intrări, același plan, același hash.

    Cele patru piese ale rețetei din `planner._update_recipe_doc`, scrise o dată pentru tot
    lotul: preflight care fixează ce era instalat, apply, rollback fixat pe EXACT ce a văzut
    preflight-ul, post_verification care citește ce s-a instalat.
    """
    pkgs = sorted(pkgs, key=lambda p: p.name)
    reboot = any(p.reboot for p in pkgs)
    eco = "rpm" if family == "rhel" else "deb"
    n = len(pkgs)
    names = ", ".join(p.name for p in pkgs)

    preflight: list[dict[str, Any]] = [
        _check("dsk01", f"Cel puțin {MIN_FREE_BYTES >> 30} GB liberi în /var pentru descărcarea pachetelor",
               {"kind": "disk_free", "path": "/var", "min_bytes": MIN_FREE_BYTES}),
    ]
    post: list[dict[str, Any]] = []
    backup: list[dict[str, Any]] = []
    for i, p in enumerate(pkgs, 1):
        preflight.append(_check(
            f"pre{i:02d}", f"{p.name} are versiunea {p.before} (cea pe care se fixează revenirea)",
            {"kind": "pkg_version", "name": p.name, "equals": p.before}))
        post.append(_check(
            f"post{i:02d}", f"{p.name} este instalat la cel puțin {p.target}",
            {"kind": "pkg_version", "name": p.name, "at_least": p.target}))

    rollback_argv = _rollback_argv(family, pkgs)
    if family == "rhel":
        for i, p in enumerate(pkgs, 1):
            backup.append({
                "id": f"bk{i:02d}", "kind": "rpm_state", "source": p.name,
                "desc_ro": f"Salvează versiunea instalată a lui {p.name}, pentru revenirea manuală",
                "restore_argv": ["dnf", "-y", "downgrade", f"{p.name}-{p.before}"],
                "estimated_size_mb": 1})
    else:
        # `rpm_state` nu există pe Debian (`validator.BACKUP_KIND_UNAVAILABLE_ON`). Registrul
        # de stare al dpkg e înregistrarea fidelă a ce era instalat; restaurarea lui peste
        # sistemul viu ar strica, deci calea de întoarcere scrisă aici e downgrade-ul fixat.
        backup.append({
            "id": "bk01", "kind": "path", "source": "/var/lib/dpkg/status",
            "desc_ro": "Salvează registrul dpkg: înregistrarea versiunilor de dinainte",
            "restore_argv": rollback_argv, "estimated_size_mb": 8})

    health = [_check(
        "hc01", "Baza de date de pachete răspunde după tranzacție (NU verifică serviciile)",
        {"kind": "pkg_version", "name": "rpm" if family == "rhel" else "dpkg", "at_least": "0"})]

    manual = " ".join(rollback_argv)
    return {
        "schema_version": 1,
        # Pagina web citește `plan.generated_by` și, fără el, scrie «ai» — pentru un plan la care
        # niciun model n-a pus mâna. Cheia e exclusă din `plan_hash`, deci nu schimbă ce se aprobă.
        "generated_by": GENERATED_BY,
        "target": {"asset_id": asset_id or 0, "asset_name": asset_name or "host",
                   "protected": False, "stack": "host", "unit": None},
        "vulnerabilities": [{
            "finding_id": p.rep_id, "cve": p.cve, "kev": p.kev, "package": p.name,
            "current": p.before, "fixed_in": p.target, "severity": p.severity,
            "ecosystem": eco, "findings": p.findings} for p in pkgs],
        "risk": {
            # Un singur fapt decide: pachetele din REBOOT_REQUIRED_PACKAGES. Restul («ce
            # serviciu se repornește») nu se știe de aici.
            "level": "high" if reboot else "medium",
            "blast_radius": "host-wide" if reboot else ("multi-service" if n > 1 else "single-service"),
            "reversible": True, "requires_reboot": reboot,
            # Necunoscut, nu «zero secunde»: repornirea serviciilor o hotărăsc scriptletele
            # pachetelor. Câmpul e obligatoriu, deci 0 + o linie care spune asta în mesaj.
            "estimated_downtime_s": 0,
            # Plan determinist, nu o presupunere a unui model. Nu spune nimic despre gazdă.
            "confidence": 1.0},
        "update": {
            "version": UPDATE_META_VERSION, "scope": scope, "lot": number, "lots": total,
            "packages": [{"name": p.name, "before": p.before, "target": p.target,
                          "reboot": p.reboot, "findings": p.findings} for p in pkgs]},
        "preflight": preflight,
        "backup": backup,
        "apply": [{
            "id": "upd01", "desc_ro": f"Actualizează într-o singură tranzacție: {names}",
            "argv": _apply_argv(family, pkgs), "timeout_s": APPLY_TIMEOUT_S,
            "on_failure": "rollback", "expect_exit": [0]}],
        "health_check": health,
        "rollback": [{
            "id": "rev01", "desc_ro": f"Readu pachetele la versiunile de dinainte: {names}",
            "argv": rollback_argv, "timeout_s": ROLLBACK_TIMEOUT_S,
            "on_failure": "abort", "expect_exit": [0]}],
        "post_verification": post,
        "restore_instructions_ro": (
            "Planul își face singur revenirea dacă tranzacția cade. Manual, ca root: "
            f"`{manual}`. Atenție: revenirea cere ca versiunea veche să mai fie în depozit — "
            "arhivele curăță versiunile vechi, iar asta nu se poate verifica de pe gazdă; dacă "
            "a dispărut, pachetele rămân pe versiunea nouă și decizia e a ta. Starea reală se "
            "citește cu `rpm -q <pachet>` (sau `dpkg-query -W <pachet>`), nu din acest mesaj."),
    }


def fits(plan: dict[str, Any], family: str) -> tuple[bool, str | None]:
    """Încape planul în plafoanele pe care le aplică `approval`? (True, None) sau (False, motiv).

    Cele două plafoane sunt EXACT cele ale lanțului de aprobare: bugetul de timeouturi
    (`flatten.budget_s` față de `RUN_BUDGET_S`, același număr pe care îl impune și validatorul)
    și lungimea cererii de semnat (`build_request`, față de `MAX_REQUEST_CHARS`). Cererea se
    construiește aici cu un rezumat și un nonce de lungimea celor reale — nu se estimează din
    numărul de pachete.
    """
    from sentinel.patch import approval

    try:
        flat = approval.flatten(plan, family)
    except approval.ApprovalError as exc:
        return False, str(exc)
    if flat.budget_s > approval.RUN_BUDGET_S:
        return False, (f"timeouturile însumează {flat.budget_s} s, peste plafonul de "
                       f"{approval.RUN_BUDGET_S} s")
    request = approval.build_request(plan_hash(plan), "0" * 64, "0" * 32, flat.steps)
    if len(request) > approval.MAX_REQUEST_CHARS - REQUEST_MARGIN_CHARS:
        return False, (f"cererea de semnat are {len(request)} de caractere; încape cel mult "
                       f"{approval.MAX_REQUEST_CHARS - REQUEST_MARGIN_CHARS}")
    return True, None


# ---------------------------------------------------------------------------
# Selecția: de la constatări la loturi
# ---------------------------------------------------------------------------
@dataclass
class _Member:
    cand: Candidate
    pkg: PlanPkg


@dataclass
class _Settled:
    """Un pachet aflat la sau peste versiunea care îi repară PROPRIA constatare. Încă nu e
    «deja instalat»: asta se hotărăște abia când se știe ce versiune vor avea surorile lui."""
    source: str
    name: str
    newest: str
    hit: tuple[int, str] | None     # planul deschis care îl acoperă, dacă e unul


def _short(reason: str, limit: int = 220) -> str:
    return reason if len(reason) <= limit else reason[: limit - 1] + "…"


def _plan_pkg(cand: Candidate, before: str) -> PlanPkg:
    cve = cand.rep_cve if (cand.rep_cve and re.match(r"^CVE-\d{4}-\d{4,}$", str(cand.rep_cve))) else None
    return PlanPkg(
        name=cand.package, before=before, target=cand.fixed, finding_ids=list(cand.finding_ids),
        findings=len(cand.finding_ids), kev=cand.kev, cve=cve, rep_id=cand.rep_id,
        severity=cand.severity, reboot=needs_reboot(cand.package))


def _unit_plan(members: list[_Member], family: str, scope: str, number: int, total: int) -> dict[str, Any]:
    assets = {m.cand.asset_id for m in members}
    one = next(iter(assets)) if len(assets) == 1 else None
    name = members[0].cand.asset_name if one is not None else None
    return build_plan([m.pkg for m in members], family=family, scope=scope, number=number,
                      total=total, asset_id=one, asset_name=name)


def classify(cands: CandidateSet, host: HostRead, family: str, sel: Selection,
             covering: dict[int, tuple[int, str]] | None = None) -> dict[str, list[_Member]]:
    """Din candidați + ce a citit gazda: grupurile care pot fi planificate (sursă -> membri).

    Tot ce nu poate fi planificat ajunge în `sel.held`, `sel.already`, `sel.covered` sau e
    raportat — cu motiv. Pură în raport cu rețeaua și baza: aceleași intrări, aceleași grupuri.
    `covering` = finding_id -> (plan, stare) pentru planurile deschise (`_covering_plans`), dat de
    apelant tocmai ca funcția asta să nu atingă baza.

    ## Ce reține un membru, și ce reține familia lui

    Întrebarea care hotărăște fiecare ramură: **ar muta `dnf`/`apt` pachetul ăsta oricum, ca
    dependență a surorilor planificate?**

      * Un pachet care ARE de actualizat și pe care refuzăm să-l numim (`covered` — e deja într-un
        plan deschis; `protected_asset`; `install_only`; `manual_only`; versiuni multiple; epoch)
        ar fi mutat nenumit: tranzacția surorilor îl trage prin dependențe (`httpd` cere
        `httpd-core` de aceeași versiune), fără pin de pregătire, fără pin de revenire și fără
        verificare. De aceea intră în `hard`: se reține FAMILIA ÎNTREAGĂ, cu el cu tot.
      * `not_installed` rămâne pe membru: un pachet care nu e instalat nu are ce fi mutat de nicio
        tranzacție. Dacă l-ai reține pe el, ai reține familia pentru un pachet pe care nimeni nu-l
        atinge.
      * «Reparația e deja pe disc» (`already`) e adevărată doar față de constatarea LUI, nu față de
        ținta surorilor: `httpd-core` instalat la 2.4.50-1 cu reparația proprie la 2.4.50-1 nu are
        nimic de instalat pentru ea, dar dacă `httpd` și celelalte merg la 2.4.50-2, `httpd` cere
        `httpd-core` de versiunea exactă a lui și `dnf` îl mută la 2.4.50-2, nenumit. De aceea
        decizia se amână până sunt cunoscute grupurile: un membru «gata» rămâne pe loc doar dacă
        versiunea lui e cel puțin cea mai mare țintă din familia planificată; altfel familia se
        reține (`behind_siblings`). Pe datele de azi nu se declanșează (măsurat de verificator, 27 oct
        2026, pe cei 32 de membri ai familiilor cu mai multe pachete: aceleași `fixed_version` în
        fiecare familie), dar regula nu se bazează pe asta.

    O excepție spusă pe față: `bad_name` rămâne pe membru, dar din alt motiv. Un nume pe care nu-l
    dau nici lui `rpm` nu are sursă citită, deci nu pot spune din ce familie face parte; nu pot
    reține o familie pe care n-o pot numi.
    """
    cmp = _cmp_for(family)
    covering = covering or {}
    groups: dict[str, list[_Member]] = {}
    hard: dict[str, list[tuple[str, str, str]]] = {}   # sursă -> (pachet, cod, motiv)
    settled: list[_Settled] = []                       # decise abia după ce grupurile sunt cunoscute

    for cand in cands.candidates:
        name = cand.package
        if not _NAME_RE.fullmatch(name):
            sel.held.append(Held([name], "bad_name",
                                 "numele pachetului nu e unul pe care să-l dau unei comenzi — nici "
                                 "sursa nu i-am citit, deci nu pot spune ce alte pachete ar trage "
                                 "după el"))
            continue
        hit = next((covering[i] for i in cand.finding_ids if i in covering), None)
        insts = host.installed.get(name, ())
        if not insts:
            # Nimic de mutat. Un pachet acoperit rămâne totuși vizibil ca acoperit.
            if hit is not None:
                sel.covered.append((name, hit[0], hit[1]))
            else:
                sel.held.append(Held([name], "not_installed",
                                     "scanerul îl listează, dar nu e instalat acum — constatarea e "
                                     "veche și se închide la scanarea următoare"))
            continue
        source = insts[0].source
        evrs = sorted({i.evr for i in insts})
        newest = evrs[0]
        for e in evrs[1:]:
            if cmp(e, newest) > 0:
                newest = e

        # Reparația e deja pe disc: nimic de instalat, indiferent de ce fel de pachet e. La un
        # install-only (nucleul) «cea mai nouă instanță» e cea care contează — celelalte două
        # sunt, prin construcție, cele vechi păstrate în paralel.
        if cmp(newest, cand.fixed) >= 0:
            settled.append(_Settled(source, name, newest, hit))
            continue
        if hit is not None:
            # Are de actualizat și e deja în planul #N: nu primește un al doilea, dar nici nu
            # poate fi lăsat în afara lotului surorilor lui, fiindcă dnf l-ar trage oricum.
            sel.covered.append((name, hit[0], hit[1]))
            hard.setdefault(source, []).append((
                name, "covered",
                f"e deja în planul #{hit[0]} ({hit[1]}) — vezi /patch {hit[0]}; tranzacția surorilor "
                "l-ar muta fără pin de revenire și fără verificare"))
            continue
        if cand.protected:
            hard.setdefault(source, []).append((name, "protected_asset",
                                                "asset-ul pachetului e marcat protejat: niciun plan "
                                                "automat"))
            continue
        if name in host.installonly:
            hard.setdefault(source, []).append((name, "install_only",
                                                "install-only: `downgrade` adaugă lângă cel nou, nu "
                                                "înlocuiește — planul n-ar avea cale de întoarcere"))
            continue
        if name in MANUAL_ONLY_PACKAGES:
            hard.setdefault(source, []).append((name, "manual_only",
                                                "docs/PATCHING.md §8: sshd nu se patchează automat, "
                                                "iar verificarea de sănătate nu-l poate vedea"))
            continue
        if len(evrs) > 1:
            hard.setdefault(source, []).append((name, "multiple_versions",
                                                f"mai multe versiuni instalate deodată ({', '.join(evrs)}): "
                                                "nu pot spune la care să fixez revenirea"))
            continue
        if _epoch(family, newest) != _epoch(family, cand.fixed):
            # Măsurat pe producție, 26 oct 2026: `zabbix-web` e instalat ca 6.4.21 (fără epoch),
            # iar reparația din baza de date e `1:6.0.48` (epoch 1). Un `dnf update` ar urca
            # epoch-ul — adică ar muta pachetul pe seria 6.0, o COBORÂRE de versiune majoră, iar
            # post_verification (`at_least 1:6.0.48`) ar spune «verificat». Un epoch diferit
            # înseamnă alt depozit sau altă serie, nu o actualizare obișnuită.
            hard.setdefault(source, []).append((name, "epoch_changed",
                                                f"epoch diferit: instalat {newest}, reparația {cand.fixed} — "
                                                "alt depozit sau altă serie, nu o actualizare obișnuită"))
            continue
        groups.setdefault(source, []).append(_Member(cand, _plan_pkg(cand, newest)))

    # Un grup cu un membru reținut din motive «tari» e reținut ÎNTREG: restul membrilor ar
    # trage prin dependențe membrul reținut, fără ca planul să-l numească.
    for source, reasons in hard.items():
        members = groups.pop(source, [])
        names = sorted({r[0] for r in reasons} | {m.cand.package for m in members})
        why = "; ".join(f"{n}: {r}" for n, _, r in sorted(reasons))
        sel.held.append(Held(names, sorted(reasons)[0][1],
                             f"grupul «{source}» se mișcă împreună și are un membru care nu se poate "
                             f"actualiza automat — {why}"))

    # Un membru «gata» rămâne pe loc doar dacă tranzacția surorilor nu l-ar mișca: versiunea lui
    # trebuie să atingă cea mai mare țintă din familia planificată (vezi docstring-ul).
    target: dict[str, str] = {}
    for source, members in groups.items():
        top = members[0].cand.fixed
        for m in members[1:]:
            if cmp(m.cand.fixed, top) > 0:
                top = m.cand.fixed
        target[source] = top
    behind: dict[str, list[_Settled]] = {}
    for st in settled:
        if st.source in target and cmp(st.newest, target[st.source]) < 0:
            behind.setdefault(st.source, []).append(st)
    for source, rows in behind.items():
        members = groups.pop(source)
        names = sorted({r.name for r in rows} | {m.cand.package for m in members})
        why = "; ".join(f"{r.name}: instalat {r.newest}" for r in sorted(rows, key=lambda r: r.name))
        sel.held.append(Held(names, "behind_siblings",
                             f"grupul «{source}» se mișcă împreună, iar țintele surorilor "
                             f"({target[source]}) sunt peste ce are deja un membru fără nimic de "
                             f"instalat pentru constatarea lui — {why}. `dnf` l-ar muta oricum, "
                             "fără pin de revenire și fără verificare"))
    behind_names = {r.name for rows in behind.values() for r in rows}
    for st in settled:
        if st.hit is not None:
            sel.covered.append((st.name, st.hit[0], st.hit[1]))
        # Un pachet acoperit de un plan DAR deja la versiunea care repară își păstrează și rândul
        # «instalat»: pentru unul care cere repornire, e singura linie care o spune.
        if st.name not in behind_names:
            sel.already.append((st.name, st.newest, needs_reboot(st.name)))
    return groups


def _order(groups: dict[str, list[_Member]]) -> list[tuple[str, list[_Member]]]:
    """KEV întâi, apoi prioritatea, apoi numele — o ordine care nu depinde de ordinea în care
    a răspuns baza de date, ca același set de constatări să dea aceleași loturi."""
    def key(item: tuple[str, list[_Member]]):
        source, members = item
        return (not any(m.cand.kev for m in members),
                -max(m.cand.priority for m in members), source)
    return sorted(groups.items(), key=key)


def assemble(groups: dict[str, list[_Member]], family: str, scope: str, sel: Selection) -> None:
    """Pune grupurile în loturi, pe măsurătoare. Completează `sel.lots` și `sel.held`.

    Fiecare grup e validat SINGUR întâi: cel respins de validator (sau care nu încape nici el
    singur) e reținut cu mesajul lui, iar celelalte merg mai departe — un grup cu un nume pe
    care executorul îl refuză nu golește tot răspunsul.
    """
    viable: list[list[_Member]] = []
    for _source, members in _order(groups):
        plan = _unit_plan(members, family, scope, 1, 1)
        verdict = validate_plan(plan, platform_family=family)
        if not verdict.valid:
            first = "; ".join(f"{e.path}: {e.message}" for e in verdict.errors[:2])
            sel.held.append(Held([m.cand.package for m in members], "validator",
                                 _short(f"validatorul respinge planul ({len(verdict.errors)} erori): {first}", 400)))
            continue
        ok, why = fits(plan, family)
        if not ok:
            sel.held.append(Held([m.cand.package for m in members], "too_big",
                                 f"grupul singur nu încape într-un plan: {why}"))
            continue
        viable.append(members)

    packed: list[list[_Member]] = []
    current: list[_Member] = []
    for members in viable:
        trial = current + members
        plan = _unit_plan(trial, family, scope, 1, 1)
        if validate_plan(plan, platform_family=family).valid and fits(plan, family)[0]:
            current = trial
            continue
        packed.append(current)
        current = list(members)
    if current:
        packed.append(current)

    total = len(packed)
    for number, members in enumerate(packed, 1):
        plan = _unit_plan(members, family, scope, number, total)
        verdict = validate_plan(plan, platform_family=family)
        if not verdict.valid:
            first = "; ".join(f"{e.path}: {e.message}" for e in verdict.errors[:2])
            sel.held.append(Held([m.cand.package for m in members], "validator",
                                 _short(f"lotul {number} nu trece validatorul: {first}", 400)))
            continue
        assets = {m.cand.asset_id for m in members}
        sel.lots.append(Lot(
            number=number, packages=[m.pkg for m in members], plan=plan,
            finding_ids=sorted({fid for m in members for fid in m.cand.finding_ids}),
            asset_id=next(iter(assets)) if len(assets) == 1 else None))


def _restrict_to(sel: Selection, names: set[str]) -> None:
    """Lasă în raport doar ce privește pachetele `names` — răspunsul despre un pachet nu
    listează tot ce e reținut pe gazdă."""
    sel.held = [h for h in sel.held if names & set(h.packages)]
    sel.covered = [c for c in sel.covered if c[0] in names]
    sel.already = [a for a in sel.already if a[0] in names]
    sel.pending_reboot = [p for p in sel.pending_reboot if p in names]


async def select(db: Database, cfg: Any, *, only: str | None = None) -> Selection:
    """Ce se poate actualiza acum, în loturi gata de oferit. NU scrie nimic și nu pornește nimic.

    `only` = un singur pachet (`/update <pachet>`): rămâne grupul lui, cu tot ce se mișcă
    împreună cu el (vezi docstring-ul modulului), și doar raportul care îl privește.
    """
    from sentinel.patch import planner

    family = str(getattr(cfg.platform, "family", "") or "").strip().lower()
    sel = Selection()
    if family not in FAMILIES:
        sel.error = (f"gazda e declarată platform.family={family!r}; nu știu ce pachete poate atinge "
                     "un plan pentru familia asta")
        return sel
    reason = planner.unplannable_reason(planner.OS_PACKAGE_ECOSYSTEM[family], family)
    if reason is not None:     # cod mort azi; «nu știu» nu devine «e bine» dacă tabelul se schimbă
        sel.error = reason
        return sel

    cands = await load_candidates(db, family)
    sel.pending_reboot = list(cands.pending_reboot)
    # Rânduri pe care familia gazdei nu le poate atinge (alt ecosistem): se spun, nu dispar.
    for pkg, why in dict(cands.foreign).items():
        sel.held.append(Held([pkg], "foreign", why))
    sel.candidates = len(cands.candidates)
    sel.total_findings = cands.total_findings
    sel.no_fix_findings = cands.no_fix_findings
    if not cands.candidates:
        if only is not None:
            _restrict_to(sel, {only})
        return sel

    host = await read_host(family, [c.package for c in cands.candidates])
    if host.error:
        sel.error = (f"nu pot citi starea pachetelor de pe gazdă ({host.error}) — nu pot spune "
                     "ce se poate actualiza, deci nu propun nimic")
        return sel

    # Un pachet deja într-un plan deschis nu primește un al doilea — iar familia lui nu se
    # planifică fără el (vezi `classify`). Interogarea se face aici, `classify` rămâne pură.
    covering = await _covering_plans(db, [i for c in cands.candidates for i in c.finding_ids])
    groups = classify(cands, host, family, sel, covering)

    scope = SCOPE_SYSTEM
    if only is not None:
        scope = SCOPE_PACKAGE
        source = next((src for src, ms in groups.items()
                       if any(m.cand.package == only for m in ms)), None)
        if source is None:
            keep = {only} | {n for h in sel.held if only in h.packages for n in h.packages}
            _restrict_to(sel, keep)
            return sel
        keep = {m.cand.package for m in groups[source]}
        groups = {source: groups[source]}
        _restrict_to(sel, keep)

    assemble(groups, family, scope, sel)
    return sel


# ---------------------------------------------------------------------------
# Stocarea
# ---------------------------------------------------------------------------
async def store_lot(db: Database, lot: Lot) -> int:
    """Scrie planul `validated` și îl marchează notificat ÎN ACELAȘI gest.

    `unnotified_plans` oferă orice plan `validated` cu `generated_by <> 'ai'` și
    `notified_at IS NULL`, la fiecare 15 secunde: un plan lăsat nemarcat până după trimitere
    ar fi oferit a doua oară, cu alt set de butoane, de bucla de push. Marcajul vine
    ÎNAINTE de trimitere (nu după, ca la `/planifica`, unde fereastra e de ordinul secundelor);
    dacă trimiterea pică, operatorul primește eroarea și planul rămâne în `/patches`.
    """
    plan_id = await repo.store_plan(
        db, plan=lot.plan, plan_hash=plan_hash(lot.plan), status="validated",
        asset_id=lot.asset_id, finding_ids=lot.finding_ids, generated_by=GENERATED_BY, model=None)
    await repo.mark_plan_notified(db, plan_id)
    log.warning("system update plan stored",
                extra={"plan": plan_id, "packages": len(lot.packages), "lot": lot.number})
    return plan_id


# ---------------------------------------------------------------------------
# După rulare: ce spune gazda, nu ce a raportat executorul
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PkgState:
    name: str
    before: str
    target: str
    now: str | None
    state: str      # target | unchanged | other | unread
    reboot: bool


STATE_TARGET: Final = "target"
STATE_UNCHANGED: Final = "unchanged"
STATE_OTHER: Final = "other"
STATE_UNREAD: Final = "unread"


def update_meta(plan: dict[str, Any]) -> dict[str, Any] | None:
    """Blocul `update` al unui plan făcut aici, sau `None` pentru orice alt plan."""
    meta = plan.get("update") if isinstance(plan, dict) else None
    if isinstance(meta, dict) and isinstance(meta.get("packages"), list):
        return meta
    return None


async def reconcile(plan: dict[str, Any], family: str) -> tuple[list[PkgState], str | None]:
    """Starea REALĂ a fiecărui pachet al planului, citită de pe gazdă după rulare.

    Executorul spune «cod 0» și post_verification spune «verificat»; asta spune ce are
    `rpm`. Cele trei trebuie să fie de acord, iar dacă nu sunt, operatorul trebuie să afle
    — în special «exit 0, nimic instalat», forma pe care acest depozit a mai văzut-o.
    """
    meta = update_meta(plan)
    if meta is None:
        return [], "planul nu e unul de update"
    pkgs = [p for p in meta["packages"] if isinstance(p, dict) and p.get("name")]
    host = await read_host(family, [str(p["name"]) for p in pkgs], with_install_only=False)
    if host.error:
        return [], host.error
    cmp = _cmp_for(family)
    out: list[PkgState] = []
    for p in pkgs:
        name, before, target = str(p["name"]), str(p["before"]), str(p["target"])
        insts = host.installed.get(name, ())
        reboot = bool(p.get("reboot"))
        if not insts:
            out.append(PkgState(name, before, target, None, STATE_UNREAD, reboot))
            continue
        best = insts[0].evr
        for i in insts[1:]:
            if cmp(i.evr, best) > 0:
                best = i.evr
        if cmp(best, target) >= 0:
            state = STATE_TARGET
        elif cmp(best, before) == 0:
            state = STATE_UNCHANGED
        else:
            state = STATE_OTHER
        out.append(PkgState(name, before, target, best, state, reboot))
    return out, None


class NoExecutionWindow(LookupError):
    """Execuția nu are o fereastră de timp în care să se caute: rând lipsă sau neînceput."""


async def detections_during(db: Database, execution_id: int) -> list[dict[str, Any]]:
    """Detecțiile `intrusion` grave apărute cât a rulat execuția (plus fereastra detectorului).

    `[]` înseamnă «am căutat în fereastra execuției și n-am găsit». Dacă nu există fereastră
    (execuția n-are rând, sau n-are ora de început), NU se întoarce `[]` — ar fi aceeași
    tăcere pentru «n-am putut căuta» —, ci se ridică `NoExecutionWindow`, iar apelantul spune
    asta operatorului.

    Un update își declanșează propriii detectori: `-w /usr/lib/systemd/system -p wa` nu are filtru
    de sesiune, iar `rpm` scrie fișiere de unitate. Aici NU se suprimă nimic — se atribuie, ca
    operatorul să vadă că alerta de acum o oră coincide cu tranzacția. Ce se întoarce: rânduri
    `{rule_id, severity, processes, count}`.

    ## De ce nu se suprimă

    Măsurat pe producție: o rulare manuală a lui dnf (12 și 16 oct 2026) a produs 40 de
    evenimente `unit_change` cu procesul `/usr/bin/python3.9` — interpretorul dnf; numele
    fișierelor aveau sufixul `;<hex>` al fișierelor temporare rpm. Livrările lui `deploy.sh`
    produc aceeași clasă de alerte, iar cauza lor nu s-a reparat suprimând după `auid` (contul de
    deploy e exact cel pe care l-ar folosi un atacator). Aici nu există un precedent de copiat:
    nimic din `sentinel/detect/` nu tratează tranzacțiile de pachete, iar `detections.suppressed`
    există în schemă și nu e scris de nimic.

    O suprimare ar fi un mecanism nou, cu un compromis real: «ignoră scrierile de unități făcute
    de rpm cât rulează o execuție aprobată» lasă o fereastră de minute în care un atacator cu
    root poate planta o unitate numindu-și procesul `rpm`. Cine acceptă fereastra aia e
    operatorul, nu acest modul. Până atunci: avertisment înainte (`update_view.plan_lines`) și
    atribuire după (această funcție).
    """
    row = await db.fetchrow(
        "SELECT started_at, finished_at FROM patch_executions WHERE id = $1", execution_id)
    if row is None:
        raise NoExecutionWindow(f"execuția #{execution_id} nu are niciun rând în patch_executions")
    if row["started_at"] is None:
        raise NoExecutionWindow(f"execuția #{execution_id} nu are ora de început înregistrată")
    rows = await db.fetch(
        """
        SELECT rule_id, severity, evidence FROM detections
        WHERE rule_family = 'intrusion' AND severity IN ('high', 'critical')
          AND ts >= $1::timestamptz
          AND ts <= COALESCE($2::timestamptz, now()) + interval '10 minutes'
        ORDER BY id
        LIMIT 200
        """,
        row["started_at"], row["finished_at"])
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (str(r["rule_id"]), str(r["severity"]))
        slot = grouped.setdefault(key, {"rule_id": key[0], "severity": key[1],
                                        "processes": set(), "count": 0})
        slot["count"] += 1
        evidence = r["evidence"]
        if isinstance(evidence, (str, bytes)):
            try:
                import json
                evidence = json.loads(evidence)
            except ValueError:
                evidence = {}
        procs = evidence.get("processes") if isinstance(evidence, dict) else None
        for proc in procs or []:
            slot["processes"].add(str(proc))
    return [{**v, "processes": sorted(v["processes"])[:4]} for v in grouped.values()]


def is_package_name(value: str) -> bool:
    """Arată `value` a nume de pachet (și nu a flag, cale sau comandă)?"""
    return bool(_NAME_RE.fullmatch(value))
