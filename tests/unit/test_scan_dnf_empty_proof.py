"""Un dnf gol nu e o gazdă curată decât dacă un control pozitiv o dovedește.

Eșecul pe care îl păzește fișierul ăsta, în ansamblu: `dnf updateinfo list cves
--security` întoarce cod 0 și zero linii ȘI când gazda e curată, ȘI când dnf n-a
văzut nicio sursă de advisory (toate depozitele dezactivate, doar depozite fără
advisory-uri). Orchestratorul citește zero linii ca „totul e reparat" și închide
fiecare constatare deschisă — operatorul are un panou curat pe o gazdă
exploatabilă. Măsurat pe gazda reală (dnf 4.14.0): patru scenarii de acest fel,
toate cu rc 0 și zero linii.

Controlul: `dnf -C ... updateinfo list --security --installed`, DOAR când
interogările principale n-au dat nimic. Pe o gazdă curată e non-gol (2654 de linii
măsurate, 30 sept 2026); pe un dnf orb e gol. Până pe 30 sept 2026 controlul era
`list cves --security --installed` (18575 de linii); a fost mutat pe interogarea
la nivel de aviz, iar fișierul `test_scan_dnf_advisories.py` spune de ce.

Capcana pe care testele de aici o țin sub observație: garda NU are voie să
depindă de numărul de constatări, de câte se rezolvă, sau de scanările
anterioare. Scanarea 134 din producție a fost `completed`, `findings_count 0`,
`resolved_findings 491` — operatorul repornise într-un nucleu deja instalat și
toate cele 491 s-au închis legitim. Nu mai există nicio scanare dnf cu
constatări, fiindcă gazda e curată: oricare dintre criteriile alea ar fi blocat
un rezultat corect, permanent.

Sunt exercitate `_scan_dnf` și `orchestrator._run_os_packages` REALE; se
înlocuiesc doar procesul dnf (`_run`), citirea bazei rpm și baza de date.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sentinel.db.repo import findings as fx
from sentinel.scan import fix_state, orchestrator, os_packages
from tests.unit._dnf_ceilings import dnf_ceiling_problems

ROOT = Path(__file__).resolve().parents[2]

# Forma măsurată pe gazda reală a `--installed`, la nivel de aviz: doar ID-uri de
# advisory (ALSA). Liniile CVE din varianta `cves` nu mai sunt recunoscute de control.
_INSTALLED = """\
ALSA-2024:9317  Low/Sec.       NetworkManager-1:1.48.10-2.el9_5.alma.1.x86_64
ALSA-2025:0377  Moderate/Sec.  NetworkManager-1:1.48.10-5.el9_5.x86_64
ALSA-2025:0001  Important/Sec. openssl-libs-1:3.5.5-1.el9_8.x86_64
"""

_AVAILABLE = ("CVE-2026-1111 Important/Sec.  "
              "kernel-core-5.14.0-687.47.1.el9_8.x86_64\n")


def run(coro):
    return asyncio.run(coro)


class _Host:
    """Trei „procese" dnf false și evidența a ce s-a cerut de la ele: interogarea
    CVE (`cves`), cea la nivel de aviz (fără `cves`) și controlul (`--installed`).

    Semnătura lui `fake_run` NU are implicit la `timeout`, ca `_run` adevărat:
    un apel care uită plafonul pică aici, nu în producție. Interogarea la nivel de
    aviz întoarce implicit „nimic", ca aceste teste să rămână despre ce erau —
    interogarea principală și controlul; ce face ea are fișierul lui.
    """

    def __init__(self, monkeypatch, *, main, control, stub_annotate=True,
                 advisories=(0, "", "")):
        self.calls: list[dict] = []
        self.annotated: list[int] = []

        async def fake_run(argv, timeout, env=None):
            self.calls.append({"argv": argv, "timeout": timeout})
            if "--installed" in argv:
                return control
            return main if "cves" in argv else advisories

        async def annotate(findings):
            self.annotated.append(len(findings))
            return {"running_kernel": None, "error": "stub"}

        monkeypatch.setattr(os_packages, "_run", fake_run)
        if stub_annotate:
            monkeypatch.setattr(os_packages.fix_state, "annotate", annotate)

    @property
    def controls(self) -> list[dict]:
        return [c for c in self.calls if "--installed" in c["argv"]]

    @property
    def advisory_queries(self) -> list[dict]:
        return [c for c in self.calls
                if "--installed" not in c["argv"] and "cves" not in c["argv"]]


def _scan(monkeypatch, *, main, control=(0, "", "")):
    host = _Host(monkeypatch, main=main, control=control)
    findings, error, facts = run(os_packages.scan("rhel"))
    return host, findings, error, facts


# --- cele trei stări ------------------------------------------------------------------------
def test_an_empty_answer_that_the_control_cannot_confirm_is_refused(monkeypatch):
    """Dnf orb (depozite dezactivate, doar depozite fără advisory-uri): interogarea
    principală zero linii, controlul zero linii. Fără garda asta scanarea se încheie
    `completed` cu zero constatări și orchestratorul închide TOT ce era deschis —
    panoul curat, gazda exploatabilă. Cu ea: scanare `failed`, nimic nu se mută."""
    host, findings, error, _ = _scan(monkeypatch, main=(0, "", ""), control=(0, "", ""))

    assert findings == []
    assert error, "un dnf orb a trecut drept „gazdă curată”"
    assert len(host.controls) == 1, "controlul nu a rulat"
    assert host.annotated == [], "`annotate` a rulat pe o scanare refuzată"


def test_an_empty_answer_that_the_control_confirms_is_a_clean_host(monkeypatch):
    """CEL CARE PICĂ DACĂ GARDA REFUZĂ PREA MULT. Gazda a instalat tot; dnf n-are ce
    să raporteze, dar controlul vede 4 linii instalate. Rezultatul e `[]` FĂRĂ eroare —
    exact scanarea 134 din producție (`completed`, 0 constatări, 491 rezolvate). Dacă
    garda ar refuza aici, gazda curată n-ar mai avea NICIODATĂ o scanare reușită, iar
    verificarea `scan:last:dnf` ar arde pentru totdeauna."""
    host, findings, error, _ = _scan(
        monkeypatch, main=(0, "", ""), control=(0, _INSTALLED, ""))

    assert error is None, f"o gazdă curată dovedită a fost refuzată: {error}"
    assert findings == []
    assert len(host.controls) == 1, (
        "control pozitiv: fără el testul ar trece și cu garda ștearsă")
    assert host.annotated == [0], "scanarea reușită trebuie să treacă prin `annotate`"


def test_a_scan_with_findings_never_runs_the_control(monkeypatch):
    """Rezultatul non-gol se dovedește singur: o linie CVE parsată e chiar dovada că dnf
    a citit advisory-uri. Rularea controlului aici ar costa 1,4-2,8 s și 1,5 MB de
    ieșire în fiecare noapte pentru nimic — și ar lega verdictul de un al doilea proces
    care poate pica independent de primul."""
    host, findings, error, _ = _scan(
        monkeypatch, main=(100, _AVAILABLE, ""), control=(1, "", "n-ar trebui chemat"))

    assert error is None and len(findings) == 1
    assert len(host.calls) == 2 and host.controls == [], (
        f"controlul a rulat pe o scanare cu constatări: {host.calls}")
    assert len(host.advisory_queries) == 1, (
        "singurele două procese sunt interogarea CVE și cea la nivel de aviz")
    assert host.annotated == [1]


# --- când controlul însuși nu poate spune ----------------------------------------------------
@pytest.mark.parametrize("control", [
    (1, "", "Cache-ul nu poate fi citit"),
    (1, _INSTALLED, ""),            # cod ≠ 0 cu ieșire: codul e dovada, nu ieșirea
    (124, "", "timeout"),           # cum întoarce `_run` un proces ucis la plafon
], ids=["rc1-empty", "rc1-with-output", "timeout"])
def test_a_control_that_cannot_run_makes_the_scan_fail(monkeypatch, control):
    """„Nu știu" nu e „curat”. Dacă al doilea proces pică, nu avem dovada că dnf a
    văzut ceva — deci scanarea eșuează în loc să închidă constatările. `rc 1 cu
    ieșire` e în listă dinadins: o ieșire parțială dintr-un proces care a murit nu
    dovedește nimic."""
    host, findings, error, _ = _scan(
        monkeypatch, main=(0, "", ""), control=control)

    assert findings == [] and error
    assert len(host.controls) == 1
    assert host.annotated == []


def test_the_timeout_and_the_empty_control_are_told_apart(monkeypatch):
    """Operatorul are de făcut lucruri diferite: la timeout se uită la gazda
    încărcată, la un control gol se uită la depozite. Același mesaj pentru ambele
    ar trimite după cauza greșită."""
    _, _, timed_out, _ = _scan(monkeypatch, main=(0, "", ""), control=(124, "", "timeout"))
    _, _, blind, _ = _scan(monkeypatch, main=(0, "", ""), control=(0, "", ""))

    assert timed_out and blind and timed_out != blind
    assert "plafon" in timed_out


def test_a_control_whose_lines_the_parser_cannot_read_makes_the_scan_fail(monkeypatch):
    """Control non-gol, dar nicio linie nu se potrivește cu `_ADVISORY_LINE`: dnf a
    schimbat formatul ieșirii. Aceeași primejdie ca la interogarea principală —
    parserul ar citi zero din orice — și validăm parserul interogării la nivel de aviz
    (`_uncovered_advisories`, cel care chiar citește rezultatul) pe singurul lucru pe
    care îl știm sigur non-gol, lista instalată (`list --security --installed`)."""
    host, findings, error, _ = _scan(
        monkeypatch, main=(0, "", ""),
        control=(0, "Updating Subscription Management repositories.\nfoo bar\n", ""))

    assert findings == [] and error
    assert "format" in error
    assert host.annotated == []


def _real_control_lines() -> list[str]:
    """Linii REALE din `list --security --installed` (dnf 4.14.0, producție, 30 sept 2026)."""
    fixtures = ROOT / "tests" / "fixtures" / "dnf-updateinfo"
    lines: list[str] = []
    for name in ("installed-alma-list-advisories.txt", "installed-epel-advisories.txt"):
        lines += (fixtures / name).read_text(encoding="utf-8").splitlines()
    return [ln for ln in lines if ln.strip()]


@pytest.mark.parametrize("reshape", [
    # coloane în stil dnf5: tipul și severitatea separate, o dată de emitere la coadă
    lambda ln: ln.replace("/Sec.", " security ").rstrip() + "  2026-09-01",
    # fără marcajul `/Sec.`, severitatea rămâne
    lambda ln: ln.replace("/Sec.", ""),
    # marcajul rămâne, se adaugă o coloană la coadă
    lambda ln: ln.rstrip() + "  2026-09-01",
    # marcajul și severitatea schimbate între ele
    lambda ln: ln.replace("/Sec.", "").replace("  ", "  Sec./", 1),
], ids=["dnf5-columns", "marker-gone", "extra-column", "swapped"])
def test_a_control_of_plausible_lines_the_parser_cannot_read_is_refused(
        monkeypatch, reshape):
    """Garda de format a controlului trebuie să judece FORMA liniei, nu înfățișarea ei.

    Ce se strică pentru operator dacă nu o face: dnf își schimbă coloanele, controlul
    tipărește în continuare mii de linii ne-goale care încep cu `ALSA-` sau
    `FEDORA-EPEL-`, o gardă care verifică doar „ne-goală", „destul de lungă",
    „începe cu un prefix de aviz" sau „conține /Sec." le lasă să treacă, iar
    `_uncovered_advisories` (același parser) citește apoi zero din ieșirea reală.
    Verificarea dnf-ului orb a spus „dnf vede avize", și fiecare constatare deschisă
    se închide pe o gazdă încă exploatabilă. Liniile de aici sunt cele REALE de pe
    producție, remodelate, deci fiecare e ne-goală, lungă, cu prefix de aviz și
    plauzibilă, iar niciuna nu se potrivește cu `_ADVISORY_LINE`. Liniile
    neschimbate sunt controlul pozitiv."""
    real = _real_control_lines()
    assert len(real) >= 10, "fixturile sunt goale: testul n-ar judeca nimic"

    _, _, accepted, _ = _scan(
        monkeypatch, main=(0, "", ""), control=(0, "\n".join(real) + "\n", ""))
    assert accepted is None, f"control pozitiv: liniile reale au fost refuzate: {accepted}"

    host, findings, error, _ = _scan(
        monkeypatch, main=(0, "", ""),
        control=(0, "\n".join(reshape(ln) for ln in real) + "\n", ""))

    assert not any(os_packages._ADVISORY_LINE.match(reshape(ln)) for ln in real), (
        "liniile remodelate se potrivesc totuși cu `_ADVISORY_LINE`: cazul nu testează nimic")
    assert findings == [] and error and "format" in error, error
    assert f"{len(real)} linii" in error
    assert host.annotated == []


def test_a_control_of_blank_lines_only_is_the_blind_case_not_a_format_change(monkeypatch):
    """Un control cu doar spații/rânduri goale e același lucru cu unul gol: dnf n-a
    văzut advisory-uri. Trimis la mesajul de format, operatorul ar căuta o schimbare
    de format dnf într-o gazdă care de fapt are depozitele oprite."""
    _, findings, error, _ = _scan(
        monkeypatch, main=(0, "", ""), control=(0, "\n   \n\t\n", ""))

    assert findings == [] and error
    assert "sursă de advisory-uri" in error and "format" not in error


# --- formatul interogării principale ---------------------------------------------------------
def test_output_with_no_line_the_parser_recognises_is_refused(monkeypatch):
    """Dnf a scris ceva, dar nicio linie nu se potrivește: fie s-a schimbat formatul,
    fie ne-a vorbit de eroare pe stdout. Cu zero potriviri, parserul ar produce zero
    constatări dintr-o ieșire NON-goală — aceeași închidere în masă ca la dnf orb, doar
    că nici controlul n-o mai prinde, fiindcă gazda are advisory-uri instalate.
    Controlul nu se rulează: nu el e întrebarea."""
    host, findings, error, _ = _scan(
        monkeypatch,
        main=(0, "Error: Failed to download metadata for repo 'baseos'\n", ""),
        control=(0, _INSTALLED, ""))

    assert findings == [] and error
    assert "format" in error
    assert host.controls == [], "controlul a rulat deși ieșirea principală e ilizibilă"
    assert host.annotated == []


def test_a_single_unmatched_line_among_matched_ones_is_still_tolerated(monkeypatch):
    """Garda de format cere ZERO potriviri, nu una fără potrivire. Ieșirea măsurată
    a interogării CVE amestecă linii RHSA/ALSA (care nu se potrivesc cu `_LINE`) cu
    cele CVE; un refuz la prima linie străină ar face scanarea să pice în fiecare
    noapte. (Interogarea la nivel de aviz e, dinadins, MAI strictă — vezi
    `test_scan_dnf_advisories.py`; aici e vorba doar de cea CVE.)"""
    out = ("RHSA-2026:0001  Important/Sec.  kernel-core-5.14.0-687.47.1.el9_8.x86_64\n"
           + _AVAILABLE)
    host, findings, error, _ = _scan(monkeypatch, main=(100, out, ""))

    assert error is None and [f["cve"] for f in findings] == ["CVE-2026-1111"]
    assert host.controls == []


def test_a_blank_only_output_counts_as_empty_not_as_unreadable(monkeypatch):
    """Doar rânduri goale: „n-a scris nimic", nu „a scris ceva ilizibil". Trebuie să
    ajungă la control, nu la mesajul de format."""
    host, findings, error, _ = _scan(
        monkeypatch, main=(0, "\n  \n", ""), control=(0, _INSTALLED, ""))

    assert error is None and findings == []
    assert len(host.controls) == 1


# --- forma comenzii de control ---------------------------------------------------------------
def test_the_control_is_cache_only_and_uses_the_scanners_own_cache(monkeypatch):
    """Controlul citește cache-ul scanerului, fără rețea. Fără `-C`, un dnf rulat ca
    utilizatorul neprivilegiat ar reconstrui metadatele (82 s măsurate, față de 2,4) —
    iar dacă rețeaua e exact ce lipsește, controlul ar pica împreună cu scanarea în loc
    s-o judece. Fără `--installed` ar repeta interogarea principală, care e goală
    prin ipoteză, deci ar refuza gazde curate."""
    host, *_ = _scan(monkeypatch, main=(0, "", ""), control=(0, _INSTALLED, ""))

    argv = host.controls[0]["argv"]
    assert argv[0] == "dnf"
    assert "-C" in argv, "controlul ar putea ieși în rețea"
    assert "--refresh" not in argv
    assert f"--setopt=cachedir={os_packages.CACHE_DIR}" in argv
    assert "--installed" in argv and "--security" in argv
    assert "cves" not in argv, (
        "controlul a revenit pe `list cves`: pe o gazdă ale cărei singure avize "
        "vizibile n-au CVE (măsurat: doar EPEL, 0 linii sub `cves`, 10 fără) ar "
        "refuza PERMANENT o gazdă pe care dnf o vede bine")
    assert host.controls[0]["timeout"] == os_packages.CONTROL_TIMEOUT_S, (
        "controlul își are plafonul lui, nu pe cel al dnf-ului principal")


# --- bugetul unității ------------------------------------------------------------------------
def test_the_controls_ceiling_is_part_of_the_worst_case():
    """Controlul rulează după dnf, în același proces, sub același `TimeoutStartSec`.
    Dacă plafonul lui nu e în `RHEL_STEP_CEILINGS_S`, `WORST_CASE_TIMEOUT_S` îl
    ignoră, iar testul care leagă suma scanerelor de bugetul unității trece pe un
    număr mai mic decât cel real — unitatea e omorâtă la mijloc, scanerul din coadă nu
    mai rulează și rândul lui rămâne `running` peste ultimul rezultat real."""
    steps = os_packages.RHEL_STEP_CEILINGS_S

    assert os_packages.CONTROL_TIMEOUT_S in steps
    assert os_packages.WORST_CASE_TIMEOUT_S >= (
        os_packages.TIMEOUT_S + os_packages.CONTROL_TIMEOUT_S
        + os_packages.ADVISORY_TIMEOUT_S + fix_state.WORST_CASE_TIMEOUT_S)


def test_the_control_asks_for_its_declared_ceiling_in_the_source():
    """Plafonul declarat trebuie să fie și cel cerut: un `timeout=30` scris de mână la
    apel ar lăsa constanta din tuplu să mintă despre bugetul real.

    Apelul se găsește după ce e scris în argv (`--installed`), nu după poziția lui
    `_installed_advisory_check` față de bannerul `# ====` următor: forma veche tăia
    sursa între cele două, așa că mutarea funcției la capătul fișierului o strica cu
    `ValueError: substring not found`, fără ca vreun plafon să se schimbe — un eșec
    care nu numea nimic și acuza ce nu trebuia. Citirea e a lui `_dnf_ceilings.py`, ca
    în celelalte două teste de sursă; aici se cere doar rolul `control`."""
    source = (ROOT / "sentinel" / "scan" / "os_packages.py").read_text(encoding="utf-8")
    problems = dnf_ceiling_problems(source, role="control")

    assert not problems, "\n".join(problems)


# --- ordinea față de `annotate` --------------------------------------------------------------
def test_the_refusal_comes_before_annotate_reads_the_rpm_database(monkeypatch):
    """Refuzul vine ÎNAINTE de `annotate`: `annotate` rulează `rpm -qa` și scrie
    verdicte pe fiecare constatare — pe o listă aruncată ar consuma plafonul de timp
    pentru nimic. Testat cu `read_host` adevărat înlocuit, nu cu `annotate`:
    a doua formă ar rămâne verde și dacă `annotate` ar fi mutat, dar ar citi rpm."""
    reads: list[int] = []

    async def read_host():
        reads.append(1)
        return fix_state.HostState(error="stub")

    async def fake_run(argv, timeout, env=None):
        return (0, "", "")

    monkeypatch.setattr(os_packages, "_run", fake_run)
    monkeypatch.setattr(os_packages.fix_state, "read_host", read_host)
    _, error, _ = run(os_packages.scan("rhel"))

    assert error and reads == [], "baza rpm a fost citită pentru o scanare refuzată"


# --- ce face orchestratorul cu refuzul --------------------------------------------------------
class _Db:
    """Un tabel `findings` în memorie, cu constatări deja deschise. Reține doar ce
    contează aici: dacă s-a cerut vreodată închiderea la dispariție, și starea
    rândurilor după."""

    def __init__(self, open_keys: list[str]) -> None:
        self.rows = {k: "open" for k in open_keys}
        self.sql: list[str] = []
        self.scan_status: list[str] = []

    async def fetchval(self, sql, *args):
        self.sql.append(sql)
        return 1

    async def execute(self, sql, *args):
        self.sql.append(sql)
        if "UPDATE scans SET status" in sql:
            self.scan_status.append(args[1])

    async def fetchrow(self, sql, *args):
        raise AssertionError("nicio constatare nu are ce upsert-a în testul ăsta")

    async def fetch(self, sql, *args):
        self.sql.append(sql)
        if "absent_from_latest_scan" in sql:
            seen = set(args[2])
            gone = [k for k, s in self.rows.items() if s == "open" and k not in seen]
            for k in gone:
                self.rows[k] = "resolved"
            return [{"id": i} for i, _ in enumerate(gone)]
        return []


def _orchestrate(monkeypatch, *, main, control):
    keys = [fx.finding_key("dnf", None, "kernel-core", f"CVE-2026-{n:04d}", None)
            for n in range(3)]
    db = _Db(keys)
    _Host(monkeypatch, main=main, control=control, stub_annotate=False)

    async def read_host():
        return fix_state.HostState(error="stub: rpm nu se citește în testul ăsta")

    async def no_kev(_db, _cves):
        return {}

    monkeypatch.setattr(os_packages.fix_state, "read_host", read_host)
    monkeypatch.setattr(orchestrator.kev, "lookup", no_kev)
    out = run(orchestrator._run_os_packages(db, "rhel", "schedule"))
    return db, out


def test_a_refused_dnf_scan_resolves_nothing(monkeypatch):
    """Lanțul întreg, cu `_scan_dnf` adevărat: dnf orb -> eroare -> scanare `failed` ->
    NICIO constatare închisă. Fără el, refuzul ar exista în scaner dar orchestratorul
    ar putea să-l ignore, și cele trei constatări deschise ar dispărea din panou."""
    db, out = _orchestrate(monkeypatch, main=(0, "", ""), control=(0, "", ""))

    assert out["status"] == "failed" and out["error"]
    assert db.scan_status == ["failed"]
    assert set(db.rows.values()) == {"open"}, "un refuz a închis constatări"
    assert not [s for s in db.sql if "absent_from_latest_scan" in s], (
        "s-a cerut închiderea la dispariție pentru o scanare care n-a putut privi")


def test_a_confirmed_clean_host_still_resolves_what_was_fixed(monkeypatch):
    """Control pozitiv al testului de mai sus, pe ACEEAȘI cale: aceleași trei
    constatări deschise, dar controlul vede pachete instalate — scanarea e `completed`
    și le închide. Fără el, testul cu refuzul ar trece și dacă orchestratorul n-ar mai
    închide NICIODATĂ nimic — iar scanarea 134 (491 rezolvate) ar fi imposibilă."""
    db, out = _orchestrate(monkeypatch, main=(0, "", ""), control=(0, _INSTALLED, ""))

    assert out["status"] == "completed" and out["findings"] == 0
    assert out["resolved"] == 3
    assert set(db.rows.values()) == {"resolved"}
