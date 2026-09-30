"""Un aviz de securitate fără CVE structurat nu are voie să lipsească din scanare.

Eșecul pe care îl păzește fișierul ăsta, în ansamblu: `dnf updateinfo list cves
--security` nu tipărește NIMIC pentru un aviz care nu declară un CVE ca referință
structurată. Măsurat pe producție, 30 septembrie 2026: zece pachete EPEL
(`suricata`, `libsodium`, `libssh2`, …) apar sub `list --security` și lipsesc sub
`list cves --security`. Ziua în care EPEL publică o actualizare de securitate
pentru unul dintre ele, scanerul ar raporta gazda curată, iar operatorul n-ar afla
niciodată — nici din panou, nici din Telegram, nici din `scan:last:dnf`, care ar
rămâne verde.

Azi NU e o expunere: la pachetele în așteptare cele două interogări dau aceleași opt
pachete. De aceea prima jumătate a fișierului e dovada că **schimbarea nu face nimic
pe gazda de azi** — ieșirea reală, de pe producție, a ambelor interogări, prin
parserul real, trebuie să dea exact constatările pe care interogarea CVE singură le
dă. A doua jumătate e cazul opus: un aviz EPEL fără CVE trebuie să devină constatare.

Fixturile din `tests/fixtures/dnf-updateinfo/` sunt ieșire REALĂ de pe gazdă (dnf
4.14.0, 30 sept 2026), nu inventată; `pending-*` sunt complete, celelalte sunt
felii din `--installed`. Singurul lucru construit de mână e marcat ca atare.

Sunt exercitate `_scan_dnf` și `orchestrator._run_os_packages` REALE; se înlocuiesc
doar procesul dnf (`_run`), citirea bazei rpm și baza de date.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from sentinel.db.repo.findings import finding_key
from sentinel.scan import fix_state, orchestrator, os_packages, prioritize

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "dnf-updateinfo"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


PENDING_CVES = _fixture("pending-list-cves.txt")
PENDING_ADVISORIES = _fixture("pending-list-advisories.txt")
EPEL = _fixture("installed-epel-advisories.txt")
ALMA_CVES = _fixture("installed-alma-list-cves.txt")
ALMA_ADVISORIES = _fixture("installed-alma-list-advisories.txt")


def run(coro):
    return asyncio.run(coro)


class _Host:
    """Procesul dnf fals: trei răspunsuri după forma comenzii, plus evidența
    apelurilor. Semnătura lui `fake_run` NU are implicit la `timeout`, ca `_run`
    adevărat."""

    def __init__(self, monkeypatch, *, cves=(0, "", ""), advisories=(0, "", ""),
                 control=(0, "", ""), stub_annotate=True):
        self.calls: list[dict] = []
        self.annotated: list[list[dict]] = []

        async def fake_run(argv, timeout, env=None):
            self.calls.append({"argv": argv, "timeout": timeout})
            if "--installed" in argv:
                return control
            return cves if "cves" in argv else advisories

        async def annotate(findings):
            self.annotated.append(list(findings))
            return {"running_kernel": None, "error": "stub"}

        monkeypatch.setattr(os_packages, "_run", fake_run)
        if stub_annotate:
            monkeypatch.setattr(os_packages.fix_state, "annotate", annotate)

    def of(self, kind: str) -> list[dict]:
        """Apelurile de un fel: `cves`, `advisories` sau `control`."""
        def kind_of(argv):
            if "--installed" in argv:
                return "control"
            return "cves" if "cves" in argv else "advisories"
        return [c for c in self.calls if kind_of(c["argv"]) == kind]


def _scan(monkeypatch, **kw):
    host = _Host(monkeypatch, **kw)
    findings, error, facts = run(os_packages.scan("rhel"))
    return host, findings, error, facts


def _reference_cve_findings(text: str) -> set[tuple[str, str, str]]:
    """(CVE, pachet, versiune care repară) — scris ALTFEL decât parserul, cu o altă
    expresie regulată, ca testul să nu fie parserul citit înapoi în el însuși."""
    out = set()
    for line in text.splitlines():
        m = re.match(r"^(CVE-\d{4}-\d+)\s+\S+\s+(\S+)$", line.strip())
        if not m:
            continue
        body = m.group(2).rsplit(".", 1)[0]                 # fără arhitectură
        name, _, rest = body.rpartition("-")                # fără release
        name, _, version = name.rpartition("-")             # fără versiune
        out.add((m.group(1), name, f"{version}-{rest}"))
    return out


# ===========================================================================
# 1. Pe gazda de azi, schimbarea nu face nimic
# ===========================================================================
def test_todays_real_pending_output_yields_exactly_what_the_cve_query_yields(monkeypatch):
    """Ieșirea REALĂ a ambelor interogări de pe producție (opt pachete `kernel*`,
    avizul ALSA-2026:71700, `Important/Sec.`) trebuie să dea exact constatările pe
    care interogarea CVE singură le dă.

    Ce se strică pentru operator dacă pică: în noaptea deploy-ului, fiecare din cele
    opt pachete ar primi, pe lângă cele 17 constatări cu CVE, una cu cheia avizului
    — 136 de constatări deja deschise plus 8 „vulnerabilități noi" fără CVE peste
    aceleași pachete, într-un mesaj Telegram care sună a incident. Iar dacă pică în
    sens invers (constatările cu CVE dispar), 136 s-ar închide ca „reparate"."""
    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, PENDING_CVES, ""), advisories=(0, PENDING_ADVISORIES, ""))

    assert error is None
    expected = _reference_cve_findings(PENDING_CVES)
    assert len(expected) == 8 * 17, "fixtura nu mai e ce era: opt pachete × 17 CVE"
    assert {(f["cve"], f["package"], f["fixed_version"]) for f in findings} == expected
    assert len(findings) == len(expected), "aceeași constatare de două ori"
    for f in findings:
        assert f["cve"], "constatare fără CVE peste un pachet cu CVE"
        assert "advisory_id" not in f, "o constatare CVE și-a luat un ID de aviz"
        assert f["finding_key"] == finding_key("dnf", None, f["package"], f["cve"], None)
        assert f["severity"] == "high"          # Important/Sec.
    # Controale pozitive: a doua interogare chiar a rulat și chiar a citit avize.
    assert len(host.of("advisories")) == 1
    assert host.of("control") == []


def test_todays_advisories_would_have_produced_findings_without_the_coverage_rule(
        monkeypatch):
    """Controlul pozitiv al testului de mai sus. Fără el, acela ar trece și dacă a
    doua interogare ar fi ignorată cu totul (o funcție care întoarce mereu `[]`):
    aici se vede că cele opt linii reale de aviz SUNT constatări când nu le acoperă
    nimic — deci ce le face să dispară azi e regula de acoperire, nu absența lor."""
    _Host(monkeypatch, advisories=(0, PENDING_ADVISORIES, ""))
    found, error = run(os_packages._uncovered_advisories(set()))

    assert error is None
    assert sorted(f["package"] for f in found) == sorted(
        {re.sub(r"-\d.*$", "", ln.split()[2]) for ln in
         PENDING_ADVISORIES.splitlines()})
    assert {f["advisory_id"] for f in found} == {"ALSA-2026:71700"}
    assert len(found) == 8


# ===========================================================================
# 2. Golul pe care îl închide: avizul fără CVE devine constatare
# ===========================================================================
def test_an_epel_advisory_with_no_cve_line_becomes_a_finding(monkeypatch):
    """Cele zece avize EPEL REALE, cu interogarea CVE goală (exact ce vede scanerul
    azi pentru ele): fiecare devine o constatare. Fără asta, prima actualizare de
    securitate EPEL pentru `suricata` ar lăsa gazda „curată" — panou gol, niciun
    mesaj, `scan:last:dnf` verde."""
    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, "", ""), advisories=(0, EPEL, ""),
        control=(1, "", "controlul nu are ce căuta aici"))

    assert error is None
    assert len(findings) == 10
    by_pkg = {f["package"]: f for f in findings}
    assert set(by_pkg) == {"jxl-pixbuf-loader", "libavif", "libdav1d", "libjxl",
                           "libsodium", "libssh2", "php-sodium",
                           "python3-configargparse", "rav1e-libs", "suricata"}
    s = by_pkg["suricata"]
    assert s["cve"] is None
    assert s["advisory_id"] == "FEDORA-EPEL-2026-eb3474ffec"
    assert s["severity"] == "high"                      # Important/Sec.
    assert by_pkg["libsodium"]["severity"] == "medium"  # Moderate/Sec.
    assert by_pkg["rav1e-libs"]["severity"] == "low"    # Low/Sec.
    assert s["fixed_version"] == "7.0.17-1.el9"
    assert s["ecosystem"] == "rpm" and s["scanner"] == "dnf"
    assert "FEDORA-EPEL-2026-eb3474ffec" in s["title"] and "suricata" in s["title"]
    assert s["raw"]["cve_known"] is False
    assert "severity_known" not in s["raw"], "o severitate cunoscută n-are ce marca"
    # O constatare parsată se dovedește singură: controlul nu rulează.
    assert host.of("control") == []
    # Trece prin `annotate` ca oricare alta (verdictul „reparație instalată?").
    assert [len(a) for a in host.annotated] == [10]


def test_the_finding_key_is_stable_and_cannot_meet_a_cve_keyed_one(monkeypatch):
    """Cheia e identitatea constatării: dacă se schimbă între scanări, aceeași
    constatare se închide și se redeschide în fiecare noapte (și se anunță ca nouă
    de fiecare dată); dacă două avize ale aceluiași pachet primesc aceeași cheie,
    unul dispare din panou; dacă una fără CVE poate egala una cu CVE, upsertul le
    contopește și una o suprascrie pe cealaltă.

    Cheia = `finding_key("dnf", None, pachet, ID-aviz, None)` — ID-ul avizului în
    locul CVE-ului, ca la GHSA în `trivy_fs`."""
    _, first, _, _ = _scan(monkeypatch, advisories=(0, EPEL, ""))
    _, second, _, _ = _scan(monkeypatch, advisories=(0, EPEL, ""))

    keys = [f["finding_key"] for f in first]
    assert keys == [f["finding_key"] for f in second], "cheia se schimbă între scanări"
    assert len(set(keys)) == len(keys) == 10
    suricata = next(f for f in first if f["package"] == "suricata")
    assert suricata["finding_key"] == finding_key(
        "dnf", None, "suricata", "FEDORA-EPEL-2026-eb3474ffec", None)

    # Două avize pentru ACELAȘI pachet sunt două constatări, nu una.
    two = ("FEDORA-EPEL-2026-aaaaaaaaaa Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
           "FEDORA-EPEL-2026-bbbbbbbbbb Important/Sec. suricata-7.0.18-1.el9.x86_64\n")
    _, pair, _, _ = _scan(monkeypatch, advisories=(0, two, ""))
    assert len({f["finding_key"] for f in pair}) == 2

    # Nicio cheie a lor nu e cheia unei constatări cu CVE: al patrulea câmp e un
    # ID de aviz, iar unul care ar arăta a CVE e refuzat (testul de mai jos).
    cve_keys = {finding_key("dnf", None, p, c, None)
                for c, p, _ in _reference_cve_findings(PENDING_CVES)}
    assert not cve_keys & set(keys)


def test_an_advisory_line_that_looks_like_a_cve_is_refused_not_keyed(monkeypatch):
    """`CVE-2026-1111 Important/Sec. suricata-…` în ieșirea la nivel de aviz ar da o
    constatare cu cheia `("dnf", pachet, "CVE-2026-1111")` — chiar cheia constatării
    cu CVE a aceluiași pachet. Upsertul le-ar contopi, iar `advisory_id` al uneia ar
    rămâne pe rândul celeilalte. E o schimbare de format, nu un aviz: scanarea
    eșuează, nu ghicește."""
    line = "CVE-2026-1111 Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
    host, findings, error, _ = _scan(monkeypatch, advisories=(0, line, ""))

    assert findings == [] and error
    assert "nu o recunoaște" in error and "CVE-2026-1111" in error
    assert host.annotated == []


# ===========================================================================
# 3. Fără dubluri: un pachet cu aviz CVE nu produce și o constatare de aviz
# ===========================================================================
def test_a_package_covered_by_a_cve_advisory_is_not_reported_twice(monkeypatch):
    """Aviz Alma REAL (NetworkManager, cu CVE-uri) alături de cele zece EPEL fără
    CVE, în aceeași scanare. Avizul Alma apare în AMBELE interogări — ca CVE-uri în
    prima, ca ID-ul ALSA în a doua — și trebuie să dea doar constatările cu CVE.

    Ce se strică dacă pică: fiecare aviz cu CVE de pe gazdă (2623 de pachete
    măsurate) ar apărea a doua oară, cu cheia avizului, în fiecare din cele două
    forme — panoul cu jumătate din rânduri duplicate."""
    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, ALMA_CVES, ""),
        advisories=(0, ALMA_ADVISORIES + EPEL, ""))

    assert error is None
    with_cve = [f for f in findings if f["cve"]]
    without = [f for f in findings if not f["cve"]]
    assert {f["cve"] for f in with_cve} == {"CVE-2024-6501", "CVE-2024-3661"}
    assert len(without) == 10 and all(
        f["advisory_id"].startswith("FEDORA-EPEL-") for f in without), (
        "un aviz ALSA, acoperit de constatarea lui cu CVE, a devenit constatare")
    assert len({f["finding_key"] for f in findings}) == len(findings)


def test_every_package_of_one_cve_counts_as_covered_not_just_the_first(monkeypatch):
    """CONSTRUIT DE MÂNĂ: un CVE care atinge DOUĂ versiuni ale aceluiași pachet.

    `cve_nvras.add()` stă înaintea deduplicării pe `(cve, nume)`. Mutat după ea,
    doar primul pachet al unui CVE s-ar înregistra ca acoperit, iar al doilea ar
    părea neacoperit — deci a doua interogare l-ar raporta încă o dată, cu cheia
    avizului, pentru ceva ce prima interogare vedea deja.

    Ce se strică dacă pică: un pachet cu două versiuni sub același CVE (kernel-ul
    de pe gazda asta e instalat în trei exemplare) apare de două ori în panou —
    o dată cu CVE-ul și o dată cu ALSA-ul — iar operatorul crede că are două
    probleme unde e una.
    """
    cves = "\n".join((
        "CVE-2026-1111  Important/Sec.  demo-1.0-1.el9.x86_64",
        "CVE-2026-1111  Important/Sec.  demo-2.0-1.el9.x86_64", ""))
    advisories = "\n".join((
        "ALSA-2026:1  Important/Sec.  demo-1.0-1.el9.x86_64",
        "ALSA-2026:1  Important/Sec.  demo-2.0-1.el9.x86_64", ""))

    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, cves, ""), advisories=(0, advisories, ""))

    assert error is None
    assert [f["cve"] for f in findings] == ["CVE-2026-1111"], (
        "a doua versiune a aceluiasi pachet, sub acelasi CVE, a fost raportata "
        "inca o data cu cheia avizului")
    assert not [f for f in findings if not f["cve"]]


def test_an_epel_advisory_that_does_declare_a_cve_is_keyed_by_the_cve(monkeypatch):
    """CONSTRUIT DE MÂNĂ (nu există încă un aviz EPEL cu CVE pe gazdă): dacă EPEL
    adaugă mâine o referință CVE avizului pentru `suricata`, ambele interogări îl
    văd, iar constatarea trebuie să fie cea cu CVE — o singură dată. Aceeași
    contopire ca mai sus, pe pachetul care contează."""
    cves = "CVE-2026-9999 Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
    advisories = "FEDORA-EPEL-2026-eb3474ffec Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
    _, findings, error, _ = _scan(
        monkeypatch, cves=(0, cves, ""), advisories=(0, advisories, ""))

    assert error is None
    assert [(f["cve"], f["package"]) for f in findings] == [("CVE-2026-9999", "suricata")]


def test_a_different_cve_less_advisory_for_the_same_package_is_not_hidden(monkeypatch):
    """CONSTRUIT DE MÂNĂ. `suricata` are un aviz cu CVE care livrează 7.0.17 și, mai
    nou, un aviz EPEL fără CVE care livrează 7.0.18. Acoperirea e pe PACHETUL EXACT
    (nvra), nu pe numele pachetului: 7.0.18 nu apare sub nicio linie CVE, deci e o
    constatare de sine stătătoare.

    Ce se strică dacă acoperirea ar fi pe nume: prima actualizare de securitate EPEL
    pentru orice pachet care are DEJA o constatare cu CVE ar fi ascunsă de ea —
    exact golul pe care schimbarea l-a făcut ca să-l închidă, păstrat pentru pachetele
    pe care Alma le-a mai atins vreodată."""
    cves = "CVE-2026-9999 Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
    advisories = ("FEDORA-EPEL-2026-aaaaaaaaaa Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
                  "FEDORA-EPEL-2026-bbbbbbbbbb Important/Sec. suricata-7.0.18-1.el9.x86_64\n")
    _, findings, error, _ = _scan(
        monkeypatch, cves=(0, cves, ""), advisories=(0, advisories, ""))

    assert error is None
    assert sorted((f["cve"] or f["advisory_id"], f["fixed_version"]) for f in findings) == [
        ("CVE-2026-9999", "7.0.17-1.el9"),
        ("FEDORA-EPEL-2026-bbbbbbbbbb", "7.0.18-1.el9")]


def test_the_same_advisory_line_twice_is_one_finding(monkeypatch):
    """Măsurat pe gazdă: 21 de linii `(ID, pachet)` apar de două ori, identice, în
    `list --security --installed` (cauza nu e verificată; după codul dnf, cheia
    listei include data `updated` a avizului). Cheia e aceeași, deci upsertul ar
    ține un rând — dar `findings_count` din `scans` și mesajul de Telegram ar
    număra două."""
    line = EPEL.splitlines()[-1] + "\n"
    _, findings, error, _ = _scan(monkeypatch, advisories=(0, line + line, ""))

    assert error is None and len(findings) == 1

    # Același aviz, același pachet, două versiuni: câștigă PRIMA linie, ca la cheia
    # (CVE, pachet) din interogarea CVE — o alegere, nu un accident al ordinii
    # în care dicționarul își suprascrie valorile.
    two = ("FEDORA-EPEL-2026-eb3474ffec Important/Sec. suricata-7.0.17-1.el9.x86_64\n"
           "FEDORA-EPEL-2026-eb3474ffec Important/Sec. suricata-7.0.18-1.el9.x86_64\n")
    _, findings, error, _ = _scan(monkeypatch, advisories=(0, two, ""))
    assert error is None
    assert [f["fixed_version"] for f in findings] == ["7.0.17-1.el9"]


# ===========================================================================
# 4. Severitatea: un cuvânt necunoscut nu pică scanarea și nu devine `info`
# ===========================================================================
@pytest.mark.parametrize("word,expected", [
    ("Critical", "critical"), ("Important", "high"),
    ("Moderate", "medium"), ("Low", "low")])
def test_the_four_advisory_severities_map_to_the_check_vocabulary(
        monkeypatch, word, expected):
    """`findings.severity` are un CHECK (`info|low|medium|high|critical`): un cuvânt
    nemapat ar face upsertul să pice, iar scanarea cu el."""
    line = f"FEDORA-EPEL-2026-0000000000 {word}/Sec. foo-1.0-1.el9.x86_64\n"
    _, findings, error, _ = _scan(monkeypatch, advisories=(0, line, ""))

    assert error is None and [f["severity"] for f in findings] == [expected]
    assert "severity_known" not in findings[0]["raw"]


@pytest.mark.parametrize("word", ["Unknown", "Importante", "Bogus"])
def test_an_unknown_severity_word_is_medium_and_says_so(monkeypatch, word):
    """`Unknown/Sec.` e ce tipărește dnf când avizul n-are severitate
    (`SECURITY2LABEL.get(sev, 'Unknown/Sec.')`); o etichetă tradusă sau nouă arată
    la fel. Nu pică scanarea (un aviz în plus nu poate opri lista să se
    actualizeze) și NU devine `info` (asta ar afirma „e neglijabil” și l-ar ascunde
    sub orice filtru de triaj): devine `medium` cu `raw.severity_known = False` —
    perechea folosită de `apt` și `trivy_fs` — iar cuvântul rămâne în `raw`."""
    line = f"FEDORA-EPEL-2026-0000000000 {word}/Sec. foo-1.0-1.el9.x86_64\n"
    _, findings, error, _ = _scan(monkeypatch, advisories=(0, line, ""))

    assert error is None and len(findings) == 1
    f = findings[0]
    assert f["severity"] == "medium" and f["severity"] != "info"
    assert f["raw"]["severity_known"] is False
    assert f["raw"]["severity_word"] == word
    assert "NU o evaluare" in f["description"], (
        "operatorul nu e avertizat că severitatea e una implicită")


# ===========================================================================
# 5. Prioritatea și ce nu poate o constatare fără CVE
# ===========================================================================
def test_a_cve_less_finding_is_ranked_by_advisory_severity_and_never_as_kev(monkeypatch):
    """Ce costă lipsa CVE-ului, ca număr: nicio potrivire KEV (deci fără +25), fără
    EPSS/CVSS. `prioritize.score` nu se uită la `cve`, deci o constatare fără CVE
    primește ce primește orice constatare `dnf` nefiind în KEV: severitatea avizului
    + 10 (expusă) + 5 (fix disponibil). Important -> 68 + 10 + 5 = 83.

    Ce se strică dacă cineva o face să nu fie clasabilă (prioritate 0/NULL): iese din
    orice listă sortată după prioritate — vizibilă în tabel, invizibilă în practică."""
    _, findings, _, _ = _scan(monkeypatch, advisories=(0, EPEL, ""))
    suricata = next(f for f in findings if f["package"] == "suricata")

    assert prioritize.score(suricata, exposed=True, criticality=3) == 83
    assert suricata.get("kev") is None and suricata.get("epss") is None


class _Db:
    """Un `db` în memorie, cu rânduri de `findings` deja deschise, care reține ce s-a
    upsert-at și ce s-a închis la dispariție."""

    def __init__(self, open_keys=()):
        self.rows = {k: "open" for k in open_keys}
        self.upserts: list[tuple] = []
        self.scan_status: list[str] = []
        self.sql: list[str] = []

    async def fetchval(self, sql, *args):
        self.sql.append(sql)
        return 1

    async def execute(self, sql, *args):
        self.sql.append(sql)
        if "UPDATE scans SET status" in sql:
            self.scan_status.append(args[1])

    async def fetchrow(self, sql, *args):
        self.upserts.append(args)
        is_new = args[0] not in self.rows
        self.rows.setdefault(args[0], "open")
        return {"is_new": is_new, "status": "open"}

    async def fetch(self, sql, *args):
        self.sql.append(sql)
        if "absent_from_latest_scan" in sql:
            seen = set(args[2])
            gone = [k for k, s in self.rows.items() if s == "open" and k not in seen]
            for k in gone:
                self.rows[k] = "resolved"
            return [{"id": i} for i, _ in enumerate(gone)]
        return []


def _orchestrate(monkeypatch, db, **kw):
    _Host(monkeypatch, stub_annotate=False, **kw)
    kev_asked: list[list[str]] = []

    async def read_host():
        return fix_state.HostState(error="stub: rpm nu se citește în testul ăsta")

    async def kev_lookup(_db, cves):
        kev_asked.append(list(cves))
        return {}

    monkeypatch.setattr(os_packages.fix_state, "read_host", read_host)
    monkeypatch.setattr(orchestrator.kev, "lookup", kev_lookup)
    out = run(orchestrator._run_os_packages(db, "rhel", "schedule"))
    return out, kev_asked


def test_the_orchestrator_stores_a_cve_less_finding_with_its_priority(monkeypatch):
    """Lanțul întreg pe `_run_os_packages` real: constatarea fără CVE ajunge în bază
    cu `cve` NULL, `advisory_id` completat și prioritatea calculată, iar căutarea KEV
    nu primește niciodată un `None` (ar pica `= ANY($1::text[])` cu NULL în listă sau
    ar potrivi ce nu trebuie)."""
    db = _Db()
    out, kev_asked = _orchestrate(monkeypatch, db, advisories=(0, EPEL, ""))

    assert out["status"] == "completed" and out["findings"] == 10 and out["new"] == 10
    assert kev_asked == [[]], f"KEV a primit {kev_asked}"
    by_key = {u[0]: u for u in db.upserts}
    key = finding_key("dnf", None, "suricata", "FEDORA-EPEL-2026-eb3474ffec", None)
    row = by_key[key]
    # ordinea argumentelor din `upsert_finding`: cve=3, advisory_id=4, severity=7,
    # kev=11, priority=18
    assert row[3] is None and row[4] == "FEDORA-EPEL-2026-eb3474ffec"
    assert row[7] == "high" and row[11] is False and row[18] == 83


def test_a_failed_advisory_query_resolves_nothing(monkeypatch):
    """Constatările fără CVE deja deschise NU sunt în lista unei scanări la care a
    doua interogare a căzut. Dacă scanarea ar continua cu doar constatările CVE,
    `mark_resolved_absent` le-ar închide pe TOATE ca „dispărute din ultima scanare"
    — panoul ar arăta reparat exact ce n-a mai fost privit."""
    key = finding_key("dnf", None, "suricata", "FEDORA-EPEL-2026-eb3474ffec", None)
    db = _Db([key])
    out, _ = _orchestrate(monkeypatch, db, cves=(0, PENDING_CVES, ""),
                          advisories=(1, "", "Cache-only enabled but no cache"))

    assert out["status"] == "failed" and "nivel de aviz" in out["error"]
    assert db.scan_status == ["failed"]
    assert db.rows == {key: "open"}
    assert not [s for s in db.sql if "absent_from_latest_scan" in s]


def test_a_cve_less_finding_is_kept_while_listed_and_closed_when_it_is_gone(monkeypatch):
    """Perechea de controale a testului de mai sus, pe aceeași cale. Cât timp avizul e
    listat, constatarea rămâne deschisă; când dispare dintr-o scanare REUȘITĂ (pachetul
    a fost actualizat), se închide. Fără a doua jumătate, testul cu interogarea căzută
    ar trece și dacă constatările fără CVE n-ar mai putea fi închise NICIODATĂ."""
    key = finding_key("dnf", None, "suricata", "FEDORA-EPEL-2026-eb3474ffec", None)

    db = _Db([key])
    out, _ = _orchestrate(monkeypatch, db, advisories=(0, EPEL, ""))
    assert out["status"] == "completed" and out["new"] == 9   # suricata nu e nouă
    assert db.rows[key] == "open" and out["resolved"] == 0

    db = _Db([key])
    gone = EPEL.replace(
        "FEDORA-EPEL-2026-eb3474ffec Important/Sec. suricata-7.0.17-1.el9.x86_64\n", "")
    out, _ = _orchestrate(monkeypatch, db, advisories=(0, gone, ""))
    assert out["status"] == "completed" and out["resolved"] == 1
    assert db.rows[key] == "resolved"


# ===========================================================================
# 6. Când a doua interogare nu poate spune, scanarea nu spune „curat”
# ===========================================================================
@pytest.mark.parametrize("advisories,fragment", [
    ((1, "", "Error: Cache-only enabled but no cache for 'appstream'"), "nivel de aviz"),
    ((1, EPEL, ""), "nivel de aviz"),             # cod ≠ 0 cu ieșire: codul e dovada
    ((124, "", "timeout"), "plafon"),
    ((0, "Updating Subscription Management repositories.\n", ""), "nu o recunoaște"),
    ((0, EPEL + "ceva străin\n", ""), "nu o recunoaște"),   # o singură linie străină
], ids=["rc1", "rc1-with-output", "timeout", "not-a-line", "one-foreign-line"])
def test_an_advisory_query_that_cannot_answer_fails_the_scan(
        monkeypatch, advisories, fragment):
    """„Nu știu” nu e „nu e nimic”. Interogarea la nivel de aviz e singura care vede
    avizele fără CVE: dacă pică, moare de timeout sau scrie ceva ce parserul nu
    înțelege, scanarea eșuează — nu se încheie cu constatările CVE, lăsând un aviz
    lipsă să pară reparat.

    Fiecare linie nevidă trebuie recunoscută (nu doar „cel puțin una”, ca la
    interogarea CVE): o linie sărită e un aviz care lipsește, iar `mark_resolved_
    absent` îl închide dacă era deschis."""
    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, PENDING_CVES, ""), advisories=advisories)

    assert findings == [] and error and fragment in error
    assert host.annotated == [], "`annotate` a rulat pe o scanare refuzată"
    assert host.of("control") == []


def test_a_broken_cve_format_is_refused_before_the_advisory_query_can_replace_it(
        monkeypatch):
    """Dacă formatul liniilor CVE s-ar schimba, interogarea CVE ar produce zero
    potriviri dintr-o ieșire ne-goală. Fără garda (a), a doua interogare ar găsi
    toate cele opt linii ALSA „neacoperite” (nicio linie CVE cu același pachet) și
    scanarea ar înlocui tacut cele 136 de constatări cu CVE prin 8 fără — 136
    închise ca „reparate”, 8 anunțate ca noi. Garda trebuie să tragă ÎNAINTE de a doua
    interogare."""
    broken = "".join(ln.replace("CVE-", "CVE:") + "\n" for ln in PENDING_CVES.splitlines())
    host, findings, error, _ = _scan(
        monkeypatch, cves=(0, broken, ""), advisories=(0, PENDING_ADVISORIES, ""))

    assert findings == [] and error and "format" in error
    assert host.of("advisories") == [], "a doua interogare a rulat după o ieșire ilizibilă"


# ===========================================================================
# 7. Controlul pozitiv: mutat pe interogarea la nivel de aviz
# ===========================================================================
def test_a_host_whose_only_advisories_declare_no_cve_is_not_refused_as_blind(monkeypatch):
    """Măsurat pe gazdă, doar depozitul `epel`: `list cves --security --installed` dă
    0 linii, `list --security --installed` dă 10. Cu controlul pe `cves`, o gazdă
    care vede bine avizele (toate fără CVE) ar fi refuzată PERMANENT ca „dnf orb”.

    Controlul aici e cel de la nivel de aviz; ambele interogări principale sunt goale
    (nimic în așteptare), controlul vede zece avize -> gazdă curată, fără eroare."""
    host, findings, error, _ = _scan(monkeypatch, control=(0, EPEL, ""))

    assert error is None and findings == []
    assert len(host.of("control")) == 1
    assert "cves" not in host.of("control")[0]["argv"]


def test_a_blind_dnf_is_still_refused_with_both_queries_empty(monkeypatch):
    """Perechea: interogări goale ȘI control gol = dnf orb. Fără ea, testul de mai
    sus ar trece și dacă scanarea ar accepta orice zero."""
    host, findings, error, _ = _scan(monkeypatch)

    assert findings == [] and error and "sursă de advisory-uri" in error
    assert len(host.of("control")) == 1


def test_a_control_of_cve_lines_only_is_not_recognised(monkeypatch):
    """Controlul citește acum liniile de aviz. Un control cu doar linii `CVE-…` nu e
    forma așteptată a interogării la nivel de aviz (ar fi ieșirea altei comenzi):
    refuzat ca format, nu acceptat ca dovadă."""
    _, findings, error, _ = _scan(
        monkeypatch, control=(0, "CVE-2026-1111 Important/Sec. foo-1.0-1.el9.x86_64\n", ""))

    assert findings == [] and error and "format" in error


# ===========================================================================
# 8. Forma comenzii și bugetul
# ===========================================================================
def test_the_advisory_query_is_cache_only_uses_the_scanners_cache_and_its_own_ceiling(
        monkeypatch):
    """`-C`: rulează DUPĂ dnf-ul principal, care a reimprospătat cache-ul; o a doua
    ieșire în rețea ar dubla riscul de timeout pentru nimic. `cachedir` = cel al
    scanerului (altfel, ca utilizator neprivilegiat, dnf ar reconstrui metadatele:
    82 s). Fără `cves` (asta e toată ideea) și fără `--installed` (asta e controlul).
    Plafonul e al ei, nu al dnf-ului principal."""
    host, *_ = _scan(monkeypatch, cves=(0, PENDING_CVES, ""),
                     advisories=(0, PENDING_ADVISORIES, ""))

    (call,) = host.of("advisories")
    assert call["argv"] == ["dnf", "-C", "-q",
                            f"--setopt=cachedir={os_packages.CACHE_DIR}",
                            "updateinfo", "list", "--security"]
    assert call["timeout"] == os_packages.ADVISORY_TIMEOUT_S


def test_the_advisory_querys_ceiling_is_part_of_the_worst_case():
    """A treia comandă rulează în același proces, sub același `TimeoutStartSec`. Dacă
    plafonul ei nu e în `RHEL_STEP_CEILINGS_S`, `WORST_CASE_TIMEOUT_S` o ignoră, iar
    testul care leagă suma scanerelor de bugetul unității trece pe un număr mai mic
    decât cel real."""
    steps = os_packages.RHEL_STEP_CEILINGS_S

    assert os_packages.ADVISORY_TIMEOUT_S in steps
    assert os_packages.WORST_CASE_TIMEOUT_S >= sum(steps)
    assert os_packages.WORST_CASE_TIMEOUT_S >= (
        os_packages.TIMEOUT_S + os_packages.ADVISORY_TIMEOUT_S
        + os_packages.CONTROL_TIMEOUT_S + fix_state.WORST_CASE_TIMEOUT_S)


def test_the_advisory_query_asks_for_its_declared_ceiling_in_the_source():
    """Plafonul declarat trebuie să fie și cel cerut: un `timeout=30` scris de mână la
    apel ar lăsa constanta din tuplu să mintă despre bugetul real."""
    source = (ROOT / "sentinel" / "scan" / "os_packages.py").read_text(encoding="utf-8")
    body = source[source.index("async def _uncovered_advisories"):]
    body = body[:body.index("\nasync def _installed_advisory_check")]

    assert "timeout=ADVISORY_TIMEOUT_S" in body, body[:400]


# ===========================================================================
# 9. Mesajul de pe Telegram
# ===========================================================================
def test_the_announcement_names_the_advisory_when_there_is_no_cve():
    """Mesajul „vulnerabilități noi” e singurul loc unde operatorul află de o
    constatare fără CVE. `fără CVE` singur nu-i spune ce să caute; ID-ul avizului da."""
    from sentinel.scan import announce

    msg = announce.build_message(
        [{"cve": None, "advisory_id": "FEDORA-EPEL-2026-eb3474ffec", "severity": "high",
          "package": "suricata", "installed_version": None,
          "fixed_version": "7.0.17-1.el9", "kev": False, "priority": 83}],
        host="gazda")

    assert "FEDORA-EPEL-2026-eb3474ffec" in msg and "fără CVE" not in msg


def test_the_announcement_still_says_no_cve_when_there_is_no_advisory_either():
    """Ramura `apt`: fără CVE și fără aviz, mesajul rămâne cum era."""
    from sentinel.scan import announce

    msg = announce.build_message(
        [{"cve": None, "severity": "medium", "package": "openssl",
          "installed_version": "3.0", "fixed_version": "3.1", "kev": False,
          "priority": 60}], host="gazda")

    assert "fără CVE" in msg
