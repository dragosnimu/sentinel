"""`sentinel/scan/fix_state.py` — „reparația e instalată, dar nu rulează".

Eșecul de fond, măsurat pe gazda de producție la 29 septembrie 2026: 491 de
constatări `dnf` deschise, toate pachete `kernel*`, iar cea mai nouă reparație de
care aveau nevoie era deja instalată. Sentinel nu știa să deosebească „reparația
nu e instalată" de „e instalată, dar sistemul rulează nucleul vechi", așa că
planificatorul propunea un `dnf update` fără nimic de instalat, poarta de etapa 1
îl refuza, iar operatorul a încercat patru zile să aplice cinci planuri.

Ce e MĂSURAT în fixtura de mai jos și ce nu, spus pe față:

  * numele, versiunile, arhitectura și `SOURCERPM`-ul pachetelor de nucleu, cele
    trei nuclee instalate și `uname -r` sunt citite de pe gazda de producție pe 29
    septembrie 2026 (`rpm -qa --qf`, rulat sub restricțiile unității de scanare);
  * liniile `gpg-pubkey` (ARCH și SOURCERPM `(none)`) sunt tot de acolo;
  * `openssl-libs` cu epoch 1 și `kernel-srpm-macros` sunt PLAUZIBILE, nu
    măsurate în această formă — servesc ca pachete care NU sunt din nucleul care
    rulează.

Fiecare test își numește în docstring ce s-ar strica pentru operator dacă
regula ar dispărea, și a fost văzut picând (vezi raportul predării).
"""
from __future__ import annotations

import asyncio

import pytest

from sentinel.scan import fix_state
from sentinel.scan.fix_state import NOT_PENDING, PENDING, UNKNOWN

RUNNING = "5.14.0-687.46.1.el9_8.x86_64"
NEW = "5.14.0-687.51.1.el9_8"

_KERNEL_PKGS = ("kernel", "kernel-core", "kernel-modules", "kernel-modules-core",
                "kernel-devel")


def _rows() -> str:
    lines: list[str] = []
    for ver in ("5.14.0-687.46.1.el9_8", "5.14.0-687.49.1.el9_8", NEW):
        for name in _KERNEL_PKGS:
            lines.append(f"{name}\t(none):{ver}\tx86_64\tkernel-{ver}.src.rpm")
    # Instalate o singură dată, doar la cea mai nouă versiune (măsurat).
    for name in ("kernel-tools", "kernel-tools-libs", "kernel-headers"):
        lines.append(f"{name}\t(none):{NEW}\tx86_64\tkernel-{NEW}.src.rpm")
    lines += [
        "gpg-pubkey\t(none):b86b3716-61e69f29\t(none)\t(none)",
        "gpg-pubkey\t(none):11f63c51-3c7dc11d\t(none)\t(none)",
        "kernel-srpm-macros\t(none):1.0-14.el9\tnoarch\tkernel-srpm-macros-1.0-14.el9.src.rpm",
        # Nemăsurat în forma asta — un pachet cu epoch, din afara nucleului.
        "openssl-libs\t1:3.5.5-1.el9_8\tx86_64\topenssl-3.5.5-1.el9_8.src.rpm",
    ]
    return "\n".join(lines) + "\n"


def _host(release: str = RUNNING, rows: str | None = None) -> fix_state.HostState:
    """Trece prin PARSERUL și prin căutarea nucleului din cod, nu le ocolește:
    un test care construiește `HostState` de mână n-ar vedea o greșeală în ele."""
    packages, error = fix_state.parse_rpm_qa(rows if rows is not None else _rows())
    assert error is None, error
    srpm, error = fix_state.find_running_srpm(packages, release)
    assert error is None, error
    return fix_state.HostState(packages=packages, release=release, running_srpm=srpm)


def run(coro):
    return asyncio.run(coro)


# --- clasificarea -------------------------------------------------------------
@pytest.mark.parametrize("package", _KERNEL_PKGS)
@pytest.mark.parametrize("fixed", ["5.14.0-687.47.1.el9_8", "5.14.0-687.48.1.el9_8",
                                   "5.14.0-687.49.1.el9_8", "5.14.0-687.50.1.el9_8",
                                   NEW])
def test_every_measured_kernel_finding_is_pending_on_the_measured_host(package, fixed):
    """Cele 491 de constatări de pe producție, ca (pachet, reparație).

    Ce se strică dacă regula pică: operatorul vede din nou 491 de constatări
    „deschise" a căror singură remediere e o repornire, planificatorul schițează
    un plan `dnf update` care nu are ce instala, iar poarta îl refuză —
    exact cele patru zile de refuzuri din 25-29 septembrie.

    `kernel-devel`, `kernel-modules` și `kernel-modules-core` n-au reparația 51.1
    în datele reale (dnf nu le listează cu ea), dar clasificarea nu depinde de
    asta: o valoare care nu apare pe gazdă nu strică aserțiunea.
    """
    verdict = fix_state.classify(package, fixed, _host())

    assert verdict.state == PENDING, verdict
    assert verdict.installed == NEW
    assert verdict.running == "5.14.0-687.46.1.el9_8"


def test_a_fix_that_is_not_installed_stays_open_for_a_real_patch():
    """Reparația 687.52.1 NU e pe disc (cea mai nouă instalată e 687.51.1).

    Ce se strică: constatarea ar fi ascunsă ca „în așteptarea repornirii" deși o
    repornire n-ar repara nimic — o vulnerabilitate reală, nepetecită, dispărută
    din lista operatorului. E direcția periculoasă a acestei reparații, și de
    aceea are testul ei.
    """
    verdict = fix_state.classify("kernel-core", "5.14.0-687.52.1.el9_8", _host())

    assert verdict.state == NOT_PENDING
    assert verdict.installed == NEW
    assert "nu e instalată" in verdict.reason


def test_a_running_kernel_that_already_has_the_fix_is_never_pending():
    """Sistemul rulează deja 687.51.1, dar dnf listează totuși constatarea.

    Ce se strică: o contradicție între ce spune dnf și ce arată gazda ar fi
    rezolvată tăcut în favoarea „nu-i nimic". Rămâne deschisă, cu motivul în
    `raw.fix_state`, ca cineva să se uite la ea.
    """
    host = _host(release=f"{NEW}.x86_64")
    verdict = fix_state.classify("kernel-core", "5.14.0-687.47.1.el9_8", host)

    assert verdict.state == NOT_PENDING
    assert "contradicție" in verdict.reason


def test_a_running_kernel_exactly_equal_to_the_fix_is_never_pending():
    """Granița: versiunea care rulează e FIX cea care repară, nu mai nouă.

    Ce se strică: `classify` compară `>= 0`. Slăbit la `> 0`, egalitatea cade
    în ramura „așteaptă repornire", iar operatorul e trimis să repornească o
    gazdă care rulează deja exact build-ul reparat. Cazul e rar — dnf nu
    listează un aviz pe care kernelul pornit îl acoperă deja — dar testul
    vecin își spune în docstring că acoperă granița, fără s-o atingă: folosea
    47.1 față de 51.1, adică strict mai mic.
    """
    host = _host(release=f"{NEW}.x86_64")
    verdict = fix_state.classify("kernel-core", NEW, host)

    assert verdict.state == NOT_PENDING


def test_a_package_outside_the_running_kernel_is_never_pending():
    """`openssl-libs` are reparația instalată (1:3.5.5-1), iar dnf o listează
    totuși — de pildă fiindcă între dnf și `rpm -qa` cineva a rulat `dnf update`.

    Ce se strică: o bibliotecă ar fi declarată „așteaptă o repornire", deși nu
    face parte din nucleul care rulează. Regula NU generalizează la biblioteci:
    doar pachetele cu același `SOURCERPM` ca nucleul curent pot fi „instalat, dar
    nerulat".
    """
    verdict = fix_state.classify("openssl-libs", "1:3.5.5-1.el9_8", _host())

    assert verdict.state == NOT_PENDING
    assert "n-are nicio instanță din nucleul care rulează" in verdict.reason


def test_an_epoch_is_compared_and_not_dropped():
    """Un pachet din nucleul care rulează, cu o instanță cu epoch 1 la o versiune
    MAI MICĂ ca text decât reparația: epoch-ul câștigă, deci reparația e instalată.

    Sintetic — nu există așa ceva pe gazdă (237 de pachete de acolo au epoch, niciun
    pachet de nucleu). Ce se strică fără comparația cu epoch: `1:5.13.0-9` ar
    părea mai vechi decât `5.14.0-5`, iar reparația instalată ar fi raportată
    ca lipsă — planificatorul ar propune un `dnf update` fără efect.
    """
    rows = _rows() + (
        "kernel-x\t(none):5.14.0-1.el9\tx86_64\tkernel-5.14.0-687.46.1.el9_8.src.rpm\n"
        "kernel-x\t1:5.13.0-9.el9\tx86_64\tkernel-5.13.0-9.el9.src.rpm\n")
    verdict = fix_state.classify("kernel-x", "5.14.0-5.el9", _host(rows=rows))

    assert verdict.state == PENDING, verdict
    assert verdict.installed == "1:5.13.0-9.el9"


@pytest.mark.parametrize("package", ["kernel-core", "openssl-libs"])
def test_an_unreadable_host_is_unknown_never_fine(package):
    """Baza rpm nu s-a putut citi. Verdictul e „necunoscut", NU „reparația nu e
    instalată" și NU „e în regulă".

    Ce se strică: dacă necunoscutul s-ar citi ca „nu e în așteptare", o cădere
    trecătoare a lui `rpm` la 03:00 ar redeschide 491 de constatări și ar readuce
    planurile; dacă s-ar citi ca „în așteptare", ar ascunde constatări nedovedite.
    """
    host = fix_state.HostState(release=RUNNING, error="`rpm -qa` a eșuat")
    verdict = fix_state.classify(package, "5.14.0-687.47.1.el9_8", host)

    assert verdict.state == UNKNOWN
    assert verdict.installed is None and verdict.running is None


def test_a_finding_without_a_fixed_version_is_not_pending():
    """Fără versiune care repară nu e nimic de comparat, iar „instalat" n-are
    față de ce să fie. Rămâne deschisă, ca înainte."""
    assert fix_state.classify("kernel-core", None, _host()).state == NOT_PENDING
    assert fix_state.classify(None, "5.14.0-1", _host()).state == NOT_PENDING


def test_a_package_dnf_lists_but_rpm_does_not_have_is_not_pending():
    """dnf listează un pachet pe care `rpm -qa` nu-l are. Nu se poate spune că
    „așteaptă o repornire" despre ceva neinstalat."""
    assert fix_state.classify("kernel-nu-exista", "5.14.0-1", _host()).state == NOT_PENDING


# --- parsarea -----------------------------------------------------------------
def test_the_parser_reads_the_pseudo_packages_without_choking():
    """`gpg-pubkey` are `(none)` la ARCH și SOURCERPM. Un parser care le-ar
    refuza ar face din fiecare gazdă RPM una „necitibilă" — deci nicio
    constatare n-ar mai ieși vreodată din starea `unknown`."""
    packages, error = fix_state.parse_rpm_qa(_rows())

    assert error is None
    assert len(packages["gpg-pubkey"]) == 2
    assert packages["gpg-pubkey"][0].srpm == "(none)"
    assert len(packages["kernel-core"]) == 3


@pytest.mark.parametrize("bad", ["", "\n\n",
                                 "kernel\t(none):1-1\tx86_64\n",              # 3 câmpuri
                                 "kernel\t(none):1-1\tx86_64\tk.src.rpm\textra\n",
                                 "\t(none):1-1\tx86_64\tk.src.rpm\n"])          # fără nume
def test_a_malformed_or_empty_listing_is_an_error_not_a_smaller_host(bad):
    """O linie sărită în tăcere e o instanță lipsă, iar lipsa unei instanțe ar
    transforma „reparația e instalată" în „nu e" — sau invers. O ieșire goală pe
    o gazdă RPM înseamnă că nu s-a citit, nu că nu există pachete."""
    packages, error = fix_state.parse_rpm_qa(bad)

    assert packages == {} and error


def test_one_bad_line_spoils_the_whole_listing():
    """Nu se păstrează liniile bune: o listă „aproape întreagă" e exact
    tipul de răspuns care arată corect."""
    packages, error = fix_state.parse_rpm_qa(_rows() + "gunoi fără taburi\n")

    assert packages == {} and "linia" in error


# --- nucleul care rulează ---------------------------------------------------------
def test_the_running_kernel_is_found_by_the_dnf_rule():
    """`versiune-release.arch` == `uname -r`, ca în `running_kernel_pkgs` din dnf."""
    packages, _ = fix_state.parse_rpm_qa(_rows())

    srpm, error = fix_state.find_running_srpm(packages, RUNNING)

    assert error is None
    assert srpm == "kernel-5.14.0-687.46.1.el9_8.src.rpm"


def test_a_kernel_that_is_not_an_installed_package_is_unknown():
    """Nucleu compilat local, livepatch, sau pachet șters după pornire: nicio
    instanță nu se potrivește cu `uname -r`. Răspunsul cinstit e „nu știu" — o
    alegere pe ghicite ar mărturisi o stare pe care gazda n-a dovedit-o."""
    packages, _ = fix_state.parse_rpm_qa(_rows())

    srpm, error = fix_state.find_running_srpm(packages, "6.1.0-custom.x86_64")

    assert srpm is None and "niciun pachet instalat" in error


def test_a_release_string_that_matches_two_sources_is_refused():
    """Două pachete-sursă diferite cu același `versiune-release.arch`: șirul nu
    identifică un singur nucleu, deci nu se alege unul."""
    rows = _rows() + (
        "kernel-rt\t(none):5.14.0-687.46.1.el9_8\tx86_64\tkernel-rt-5.14.0-687.46.1.el9_8.src.rpm\n")
    packages, _ = fix_state.parse_rpm_qa(rows)

    srpm, error = fix_state.find_running_srpm(packages, RUNNING)

    assert srpm is None and "2 pachete-sursă" in error


# --- frontiera cu sistemul ----------------------------------------------------------
def test_reading_the_host_reports_why_it_could_not(monkeypatch):
    """`rpm` lipsă, cu cod nenul sau cu ieșire ilizibilă devine EROARE numită,
    nu o gazdă goală.

    Ce se strică: o gazdă „goală" ar clasifica orice ca „pachetul nu e
    instalat" și ar redeschide tot ce era în așteptare.
    """
    monkeypatch.setattr(fix_state, "_uname_release", lambda: RUNNING)

    async def missing():
        return 127, "", "rpm nu poate fi pornit: [Errno 2]"

    async def failing():
        return 1, "", "error: cannot open Packages database"

    async def garbage():
        return 0, "nu e tabulat\n", ""

    for stub, needle in ((missing, "rpm nu poate fi pornit"),
                         (failing, "cannot open Packages"),
                         (garbage, "linia 1")):
        monkeypatch.setattr(fix_state, "_run_rpm", stub)
        host = run(fix_state.read_host())
        assert host.error and needle in host.error, host
        assert host.running_srpm is None


def test_reading_the_host_needs_a_kernel_release(monkeypatch):
    """Fără `uname -r` nu se știe ce rulează. Nu se cheamă nici măcar rpm."""
    monkeypatch.setattr(fix_state, "_uname_release", lambda: None)

    async def boom():
        raise AssertionError("rpm nu trebuia chemat fără versiunea nucleului")

    monkeypatch.setattr(fix_state, "_run_rpm", boom)

    assert run(fix_state.read_host()).error


def test_reading_the_host_end_to_end_on_the_measured_listing(monkeypatch):
    """Frontiera întreagă cu ieșirea măsurată: nici o eroare, nucleul găsit."""
    monkeypatch.setattr(fix_state, "_uname_release", lambda: RUNNING)

    async def ok():
        return 0, _rows(), ""

    monkeypatch.setattr(fix_state, "_run_rpm", ok)
    host = run(fix_state.read_host())

    assert host.error is None
    assert host.running_srpm == "kernel-5.14.0-687.46.1.el9_8.src.rpm"
    assert fix_state.classify("kernel", "5.14.0-687.50.1.el9_8", host).state == PENDING


class _Proc:
    """Un `rpm` fals: ce citește frontiera, fără proces real."""

    def __init__(self, delay: float = 0.0, out: bytes = b"") -> None:
        self.delay, self.out, self.returncode, self.killed = delay, out, 0, False

    async def communicate(self):
        await asyncio.sleep(self.delay)
        return self.out, b""

    def kill(self):
        self.killed = True

    async def wait(self):
        return 0


def test_the_only_command_run_is_a_read_only_rpm_query(monkeypatch):
    """`rpm -qa --qf ...` și nimic altceva.

    Ce se strică dacă cineva „îmbogățește" comanda cu un pas care schimbă
    gazda: modulul afirmă că nu poate atinge sistemul, iar afirmația aceea e
    singurul motiv pentru care rulează în unitatea de scanare, sub
    `ProtectSystem=strict`, fără aprobare. Verificat pe argv-ul real trimis
    subprocesului, nu pe o constantă din modul.
    """
    seen: list[tuple] = []

    async def fake_exec(*argv, **kw):
        seen.append(argv)
        return _Proc(out=_rows().encode())

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    rc, out, _ = run(fix_state._run_rpm())

    assert rc == 0 and "kernel-core" in out
    assert len(seen) == 1
    assert seen[0][:3] == ("rpm", "-qa", "--qf")
    flags = [a for a in seen[0] if str(a).startswith("-")]
    assert flags == ["-qa", "--qf"], f"steaguri în plus pe comanda rpm: {flags}"


def test_a_hung_rpm_is_killed_and_reported_not_awaited_forever(monkeypatch):
    """Un `rpm` blocat pe o încuietoare a bazei nu are voie să țină scanarea
    până la `TimeoutStartSec` (patru ore) cu toate scanerele din coadă."""
    proc = _Proc(delay=5)

    async def fake_exec(*argv, **kw):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(fix_state, "RPM_TIMEOUT_S", 0.05)
    rc, _, err = run(fix_state._run_rpm())

    assert rc == 124 and err == "timeout"
    assert proc.killed, "procesul atârnat n-a fost oprit"


def test_a_missing_rpm_binary_is_an_error_not_an_exception(monkeypatch):
    async def fake_exec(*argv, **kw):
        raise FileNotFoundError(2, "No such file or directory", "rpm")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    rc, _, err = run(fix_state._run_rpm())

    assert rc == 127 and "rpm nu poate fi pornit" in err


# --- annotate ---------------------------------------------------------------------------
def _finding(package="kernel-core", fixed="5.14.0-687.47.1.el9_8", **raw):
    return {"scanner": "dnf", "package": package, "fixed_version": fixed,
            "cve": "CVE-2026-0001", "raw": {"advisory_line": "linia dnf", **raw}}


def test_annotate_writes_the_evidence_on_every_finding_and_keeps_the_rest(monkeypatch):
    """Dovada stă pe rând (`raw.fix_state`) ca operatorul să poată citi ce a văzut
    scanarea — iar `raw` se rescrie la fiecare upsert, deci dacă nu e pusă aici,
    dispare la următoarea scanare. Nu se pierde nimic din ce era deja în `raw`."""
    async def host():
        return _host()

    monkeypatch.setattr(fix_state, "read_host", host)
    findings = [_finding(), _finding("kernel-devel", "5.14.0-687.50.1.el9_8"),
                _finding("kernel-core", "5.14.0-687.52.1.el9_8")]

    facts = run(fix_state.annotate(findings))

    assert [f["raw"]["fix_state"]["state"] for f in findings] == [
        PENDING, PENDING, NOT_PENDING]
    assert all(f["raw"]["advisory_line"] == "linia dnf" for f in findings)
    assert findings[0]["raw"]["fix_state"]["running"] == "5.14.0-687.46.1.el9_8"
    assert facts == {"running_kernel": RUNNING, "error": None}


def test_annotate_never_raises_and_leaves_everything_unknown(monkeypatch):
    """Un defect în clasificare nu are voie să pice scanarea (ar rămâne fără
    constatări noi) — și nici să lase o gazdă „pe jumătate" clasificată."""
    async def boom():
        raise RuntimeError("defect neașteptat")

    monkeypatch.setattr(fix_state, "read_host", boom)
    findings = [_finding(), _finding("kernel-devel")]

    facts = run(fix_state.annotate(findings))

    assert [f["raw"]["fix_state"]["state"] for f in findings] == [UNKNOWN, UNKNOWN]
    assert "defect neașteptat" in facts["error"]


def test_annotate_reports_an_unreadable_host_in_its_facts(monkeypatch):
    """Scanarea trebuie să poată spune de ce n-a deosebit nimic — altfel „n-am
    putut citi" și „n-a fost nimic de deosebit" arată la fel în jurnal."""
    async def host():
        return fix_state.HostState(release=RUNNING, error="rpm a căzut")

    monkeypatch.setattr(fix_state, "read_host", host)
    findings = [_finding()]

    facts = run(fix_state.annotate(findings))

    assert findings[0]["raw"]["fix_state"] == {"state": UNKNOWN, "reason": "rpm a căzut"}
    assert facts["error"] == "rpm a căzut"


# --- ce se spune despre rând ---------------------------------------------------------------
def test_a_row_is_pending_only_by_the_flag_the_sql_computes():
    """`is_pending_row` citește booleanul din SQL (`pending_reboot_sql`) și atât.

    Ce se strică dacă ar deduce starea din altceva (`status`, `resolution`): un
    rând `open` obișnuit ar primi explicația „așteaptă o repornire", sau invers,
    unul care așteaptă ar primi „cere un plan" — două definiții ale aceleiași
    stări, care se despart la prima modificare.
    """
    assert fix_state.is_pending_row({"fix_pending_reboot": True, "status": "open"})
    assert not fix_state.is_pending_row({"fix_pending_reboot": False, "status": "open"})
    assert not fix_state.is_pending_row({"status": "open"}), (
        "un rând fără indicator e planificabil ca înainte — „nu se știe” nu e „așteaptă”")
    assert not fix_state.is_pending_row({"status": "deferred", "resolution": "orice"})


def test_the_explanation_says_what_to_do_and_that_sentinel_will_not():
    """Textul e ce citește operatorul. Trebuie să conțină cele trei fapte: reparația
    e instalată, ce o aplică, și că repornirea e decizia lui."""
    text = fix_state.PENDING_EXPLANATION_RO

    assert "instalată" in text and "repornire" in text
    assert "Sentinel nu repornește nimic" in text


def test_the_explanation_does_not_claim_the_finding_is_closed():
    """Constatarea rămâne deschisă (gazda e expusă până la repornire). Un text care
    ar spune „nu mai e deschisă" ar fi fals despre exact ce operatorul a cerut să
    rămână numărat."""
    text = fix_state.PENDING_EXPLANATION_RO

    assert "nu mai e deschisă" not in text
    assert "rămâne deschisă" in text and "expusă" in text


# --- reconcile: verdictul de azi față în față cu cel de ieri ---------------------------------
TODAY = "2026-09-30"


def _f(key: str, state: str, **extra) -> dict:
    fs = {"state": state, "reason": f"azi: {state}", **extra}
    return {"finding_key": key, "raw": {"advisory_line": "l", "fix_state": fs}}


def _prev(state: str | None, *, status: str = "open", **extra) -> dict:
    fs = {} if state is None else {"state": state, "reason": "ieri", **extra}
    return {"status": status, "fix_state": fs}


def test_unknown_does_not_erase_a_pending_verdict_proven_yesterday():
    """`rpm` cade la 03:00: verdictul de azi e `unknown`. Verdictul de ieri
    (`pending_reboot`, dovedit, constatarea continuu `open`) trebuie să rămână în
    `raw`, altfel upsertul îl rescrie ca necunoscut, planificatorul vede cele 491
    de constatări ca planificabile și cinci planuri `dnf update` revin.
    """
    findings = [_f("k1", UNKNOWN)]
    previous = {"k1": _prev(PENDING, installed="5.14.0-687.51.1.el9_8",
                            running="5.14.0-687.46.1.el9_8", since="2026-09-26")}

    out = fix_state.reconcile(findings, previous, today=TODAY)

    fs = findings[0]["raw"]["fix_state"]
    assert fs["state"] == PENDING
    assert fs["since"] == "2026-09-26", "a pierdut de când așteaptă"
    assert fs["installed"] == "5.14.0-687.51.1.el9_8" and fs["running"]
    assert fs["unread"] == "azi: unknown", "nu spune de ce n-a putut citi azi"
    assert findings[0]["raw"]["advisory_line"] == "l"
    assert (out.carried, out.pending, out.unknown) == (1, 1, 0)
    assert out.newly_pending == frozenset(), "un verdict păstrat nu e o intrare nouă"


def test_unknown_over_anything_else_stays_unknown():
    """Păstrarea e doar pentru un „în așteptare” dovedit și continuu deschis.
    `unknown` peste „nu așteaptă”, peste nimic (constatare nouă) sau peste un rând
    rezolvat rămâne `unknown` — nu se inventează un verdict care n-a existat."""
    for prev in (_prev(NOT_PENDING), _prev(UNKNOWN), None,
                 _prev(PENDING, status="resolved"),
                 _prev(PENDING, status="accepted_risk")):
        findings = [_f("k1", UNKNOWN)]
        previous = {} if prev is None else {"k1": prev}

        out = fix_state.reconcile(findings, previous, today=TODAY)

        assert findings[0]["raw"]["fix_state"]["state"] == UNKNOWN, prev
        assert (out.carried, out.unknown, out.pending) == (0, 1, 0), prev


def test_a_proven_not_pending_replaces_pending_and_is_counted_as_cleared():
    """Dovezile s-au citit și nu mai susțin starea (reparația a fost scoasă de pe
    disc, sau nucleul care rulează o are): verdictul nou câștigă, constatarea
    devine iar planificabilă. Ce se strică dacă `not_pending` ar fi tratat ca
    `unknown`: o constatare ar rămâne ascunsă de planificator la nesfârșit."""
    findings = [_f("k1", NOT_PENDING)]

    out = fix_state.reconcile(findings, {"k1": _prev(PENDING)}, today=TODAY)

    assert findings[0]["raw"]["fix_state"]["state"] == NOT_PENDING
    assert out.cleared == 1 and out.pending == 0 and out.carried == 0


def test_since_is_kept_while_pending_and_set_on_entry():
    """Reamintirea către operator spune de câte zile așteaptă: ziua primei
    constatări, dusă înainte — nu ziua scanării de azi."""
    kept = _f("kept", PENDING)
    entered = _f("entered", PENDING)

    out = fix_state.reconcile(
        [kept, entered], {"kept": _prev(PENDING, since="2026-09-26")}, today=TODAY)

    assert kept["raw"]["fix_state"]["since"] == "2026-09-26"
    assert entered["raw"]["fix_state"]["since"] == TODAY
    assert out.newly_pending == frozenset({"entered"})


def test_a_resolved_row_that_reappears_pending_is_a_new_entry():
    """`raw` al unui rând rezolvat nu se rescrie la închidere: păstrează verdictul de
    dinaintea repornirii. Dacă rândul reapare, verdictul acela nu e o stare care a
    durat — constatarea intră din nou în așteptare (și se anunță), cu `since` de azi."""
    f = _f("k1", PENDING)

    out = fix_state.reconcile(
        [f], {"k1": _prev(PENDING, status="resolved", since="2026-09-01")}, today=TODAY)

    assert out.newly_pending == frozenset({"k1"})
    assert f["raw"]["fix_state"]["since"] == TODAY


def test_a_pending_row_under_a_human_status_is_not_announced_again_every_scan():
    """`accepted_risk` (sau `false_positive`, `deferred` pus de om) rămâne cu verdictul
    `pending_reboot` scanare după scanare. „Intrare nouă” înseamnă că VERDICTUL a
    trecut în starea asta, nu că statusul e `open`: altfel același rând ar fi
    anunțat în fiecare noapte."""
    f = _f("k1", PENDING)

    out = fix_state.reconcile(
        [f], {"k1": _prev(PENDING, status="accepted_risk", since="2026-09-01")},
        today=TODAY)

    assert out.newly_pending == frozenset()
    assert f["raw"]["fix_state"]["since"] == "2026-09-01"


def test_a_finding_without_a_verdict_is_left_alone():
    """Scanerul apt nu pune `raw.fix_state`: `reconcile` nu are ce face cu el și nu
    inventează nimic — calea debian rămâne cum era."""
    f = {"finding_key": "k1", "raw": {"advisory_line": "l"}}

    out = fix_state.reconcile([f], {"k1": _prev(PENDING)}, today=TODAY)

    assert f["raw"] == {"advisory_line": "l"}
    assert out == fix_state.Outcome()


# --- ordinea în scanerul dnf ---------------------------------------------------------------
def test_a_refused_dnf_scan_never_reads_the_rpm_database(monkeypatch):
    """Un refuz de a raporta scanarea (aici: dnf a eșuat) trebuie să vină ÎNAINTE de
    `annotate`. Așa se așază orice gardă viitoare care refuză o listă în care nu are
    încredere: `annotate` citește `rpm -qa` și scrie verdicte pe fiecare constatare, deci
    rulat pe o listă aruncată ar consuma plafonul de timp și ar produce verdicte pentru
    nimic.

    Cu un control pozitiv (o scanare reușită CHEAMĂ `annotate`): altfel „nu s-a chemat”
    ar putea veni dintr-un `annotate` scos cu totul din scaner.
    """
    from sentinel.scan import os_packages

    calls: list[int] = []

    async def annotate(findings):
        calls.append(len(findings))
        return {"running_kernel": RUNNING, "error": None}

    monkeypatch.setattr(os_packages.fix_state, "annotate", annotate)

    async def failing(argv, timeout, env=None):
        return 1, "", "dnf a căzut"

    monkeypatch.setattr(os_packages, "_run", failing)
    findings, error, _ = run(os_packages.scan("rhel"))
    assert findings == [] and error == "dnf a căzut"
    assert calls == [], "`annotate` a rulat pe o scanare refuzată"

    async def working(argv, timeout, env=None):
        # Doua interogari dnf: cea CVE are constatarea, cea la nivel de aviz (fara
        # `cves`) nu are nimic de adaugat — ar fi fals sa-i dam aceeasi iesire.
        if "cves" not in argv:
            return 0, "", ""
        return 100, "CVE-2026-1111 Important/Sec.  kernel-core-5.14.0-687.47.1.el9_8.x86_64\n", ""

    monkeypatch.setattr(os_packages, "_run", working)
    findings, error, facts = run(os_packages.scan("rhel"))
    assert error is None and len(findings) == 1
    assert calls == [1], "o scanare reușită nu a cheamat `annotate`"
    assert facts["fix_state"] == {"running_kernel": RUNNING, "error": None}
