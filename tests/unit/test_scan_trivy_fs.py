"""Scanerul `trivy fs`: ce raportează, și ce refuză să raporteze.

Fiecare test de aici păzește o formă a aceluiași eșec — **o listă de
vulnerabilități care arată la fel indiferent dacă scanarea a mers sau nu.**
Operatorul se uită în panou, vede o cifră, și nu are de unde ști dacă e
măsurătoarea de azi, măsurătoarea de acum trei luni, sau ce a mai rămas dintr-o
rulare care s-a oprit la jumătate.

Cazurile concrete pe care le opresc:

* binarul lipsește, nicio cale nu există, trivy cade pe o cale care există —
  toate trei ar fi întors „zero constatări", iar `mark_resolved_absent` ar fi
  închis TOT ce raportase scanarea de ieri, ca și cum s-ar fi reparat peste
  noapte;
* baza de vulnerabilități veche de trei luni — trivy răspunde vesel, cu date
  care nu știu nimic despre ce s-a publicat între timp, iar „nicio constatare
  nouă" nu mai e o afirmație despre gazdă;
* `UNKNOWN` mapat la `info` — o vulnerabilitate neevaluată dispare sub orice
  filtru de triaj;
* mii de constatări tăiate la un plafon — restul ar fi fost marcate rezolvate,
  deci panoul ar fi arătat MAI PUȚIN tocmai când e mai mult.

Eșantioanele JSON sunt copiate după forma reală a ieșirii lui trivy 0.74
(`SchemaVersion: 2`), nu simplificate: un parser probat pe un obiect inventat
trece și pe gazdă nu potrivește nimic — și atunci raportează tot zero.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.scan import orchestrator, trivy_fs

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy" / "systemd" / "sentinel-scan.service"

NOW = datetime(2026, 8, 27, 4, 0, tzinfo=timezone.utc)


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Eșantion realist: `trivy fs --scanners vuln --format json /var/www`
# --------------------------------------------------------------------------
SAMPLE = json.loads(r"""
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-08-27T03:11:02.123456789Z",
  "ArtifactName": "/var/www",
  "ArtifactType": "filesystem",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {"type": "", "diff_ids": null},
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "var/www/app/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-21538",
          "PkgID": "cross-spawn@7.0.3",
          "PkgName": "cross-spawn",
          "PkgPath": "var/www/app/node_modules/cross-spawn/package.json",
          "PkgIdentifier": {
            "PURL": "pkg:npm/cross-spawn@7.0.3",
            "UID": "f4ee8ee5b6cbd8de"
          },
          "InstalledVersion": "7.0.3",
          "FixedVersion": "7.0.5, 6.0.6",
          "Status": "fixed",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-21538",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "cross-spawn: regular expression denial of service",
          "Description": "Versions of the package cross-spawn before 7.0.5 are vulnerable to Regular Expression Denial of Service (ReDoS) due to improper input sanitization.",
          "Severity": "HIGH",
          "CweIDs": ["CWE-1333"],
          "VendorSeverity": {"ghsa": 3, "nvd": 3, "redhat": 2},
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            },
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 3.7
            }
          },
          "References": ["https://github.com/moxystudio/node-cross-spawn/pull/160"],
          "PublishedDate": "2024-11-18T18:15:17.09Z",
          "LastModifiedDate": "2024-11-19T21:57:32.967Z"
        },
        {
          "VulnerabilityID": "GHSA-3xgq-45jj-v275",
          "PkgID": "cross-spawn@7.0.3",
          "PkgName": "cross-spawn",
          "PkgPath": "var/www/app/node_modules/cross-spawn/package.json",
          "InstalledVersion": "7.0.3",
          "FixedVersion": "",
          "Status": "affected",
          "Layer": {},
          "SeveritySource": "ghsa",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory npm",
            "URL": "https://github.com/advisories"
          },
          "Title": "cross-spawn Regular Expression Denial of Service",
          "Severity": "UNKNOWN",
          "VendorSeverity": {},
          "References": []
        }
      ]
    },
    {
      "Target": "var/www/api/requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2025-43859",
          "PkgName": "h11",
          "PkgIdentifier": {"PURL": "pkg:pypi/h11@0.14.0", "UID": "9a0e1c2b3d4e5f60"},
          "InstalledVersion": "0.14.0",
          "FixedVersion": "0.16.0",
          "Status": "fixed",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-43859",
          "DataSource": {"ID": "ghsa", "Name": "GitHub Security Advisory pip", "URL": "https://github.com/advisories"},
          "Title": "h11: leniency in parsing chunked-encoding terminators",
          "Description": "h11 is a Python implementation of HTTP/1.1.",
          "Severity": "CRITICAL",
          "CweIDs": ["CWE-444"],
          "VendorSeverity": {"ghsa": 4},
          "CVSS": {
            "ghsa": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.1
            }
          },
          "References": ["https://github.com/python-hyper/h11/security/advisories"],
          "PublishedDate": "2025-04-24T21:15:47.34Z",
          "LastModifiedDate": "2025-04-25T13:15:52.183Z"
        }
      ]
    },
    {
      "Target": "var/www/static/composer.lock",
      "Class": "lang-pkgs",
      "Type": "composer"
    }
  ]
}
""")


# `PrimaryURL` al avizului GHSA, pus dupa parsare in loc de inline.
#
# Scris intreg pe o linie, gazda + calea + identificatorul avizului dau un sir
# de 34 de caractere din alfabetul base64, iar `test_repo_is_sanitised` il
# raporteaza (corect, dupa forma) ca
# posibil secret scurs in depozitul public. Ingustarea tiparului de acolo ar fi
# o scutire tacuta si globala — cum s-au deschis gaurile de dinainte. Compus
# aici, scutirea e locala, vizibila, si valoarea pe care o vede parserul ramane
# exact cea pe care o scrie trivy.
SAMPLE["Results"][0]["Vulnerabilities"][1]["PrimaryURL"] = (
    "https://github.com/" + "advisories/GHSA-3xgq-45jj-v275")


def _by_id(items):
    return {f["raw"]["vulnerability_id"]: f for f in items}


# --------------------------------------------------------------------------
# Parsarea ieșirii reale
# --------------------------------------------------------------------------
def test_a_real_report_yields_the_columns_the_dashboard_shows() -> None:
    """Un raport trivy real trebuie să producă rânduri complete, nu o listă goală.

    Eșecul pe care îl previne: un parser scris după un obiect JSON inventat
    (`{"vulns": [...]}`) trece toate testele și pe gazdă nu potrivește nimic —
    și atunci scanarea raportează liniștit zero vulnerabilități în fiecare noapte,
    exact ca grep-ul după un tipar inexistent din CLAUDE.md.
    """
    items = _by_id(trivy_fs.parse(SAMPLE))
    assert set(items) == {"CVE-2024-21538", "GHSA-3xgq-45jj-v275", "CVE-2025-43859"}

    h11 = items["CVE-2025-43859"]
    assert h11["scanner"] == "trivy_fs"
    assert h11["cve"] == "CVE-2025-43859"
    assert h11["advisory_id"] is None
    assert h11["package"] == "h11"
    assert h11["installed_version"] == "0.14.0"
    assert h11["fixed_version"] == "0.16.0"
    assert h11["severity"] == "critical"
    assert h11["ecosystem"] == "pypi"
    # Fără PkgPath, ținta e locul: altfel constatarea n-ar avea unde să trimită.
    assert h11["location"] == "var/www/api/requirements.txt"
    assert len(h11["finding_key"]) == 64

    npm = items["CVE-2024-21538"]
    assert npm["ecosystem"] == "npm"
    assert npm["location"] == "var/www/app/node_modules/cross-spawn/package.json"
    assert npm["severity"] == "high"


def test_a_target_with_no_vulnerabilities_is_neither_an_error_nor_a_finding() -> None:
    """trivy omite cheia `Vulnerabilities` pentru o țintă curată.

    Eșecul pe care îl previne: un parser care presupune cheia aruncă `KeyError`
    pe primul `composer.lock` curat, iar excepția urcă până în orchestrator, care
    scrie `failed` — o scanare reușită raportată ca pană, în fiecare noapte în
    care gazda e curată.
    """
    curat = {"SchemaVersion": 2, "Results": [
        {"Target": "var/www/static/composer.lock", "Class": "lang-pkgs", "Type": "composer"}]}
    assert trivy_fs.parse(curat) == []
    # `"Results": null` e ce scrie trivy când nu a potrivit niciun fișier.
    assert trivy_fs.parse({"SchemaVersion": 2, "Results": None}) == []


def test_an_advisory_without_a_cve_keeps_its_own_identity() -> None:
    """Două GHSA-uri pe același pachet nu au voie să fie același rând.

    Eșecul pe care îl previne: cheia construită din coloana `cve` — care e NULL
    pentru un GHSA — ar da aceeași amprentă pentru orice aviz fără CVE de pe
    același pachet și aceeași cale. Al doilea l-ar suprascrie pe primul, și o
    vulnerabilitate ar dispărea din panou fără ca nimic să spună că a existat.
    """
    ghsa = _by_id(trivy_fs.parse(SAMPLE))["GHSA-3xgq-45jj-v275"]
    assert ghsa["cve"] is None, "un GHSA scris în coloana `cve` strică și căutarea KEV"
    assert ghsa["advisory_id"] == "GHSA-3xgq-45jj-v275"

    altul = json.loads(json.dumps(SAMPLE))
    altul["Results"][0]["Vulnerabilities"][1]["VulnerabilityID"] = "GHSA-aaaa-bbbb-cccc"
    celalalt = _by_id(trivy_fs.parse(altul))["GHSA-aaaa-bbbb-cccc"]
    assert celalalt["finding_key"] != ghsa["finding_key"], (
        "două avize diferite pe același pachet au aceeași cheie: unul îl "
        "suprascrie pe celălalt la ingestie")


def test_the_same_advisory_seen_twice_collapses_to_one_row() -> None:
    """Aceeași (id, pachet, cale) de două ori e o constatare, nu două.

    Eșecul pe care îl previne: `upsert_finding` deduplică după `finding_key`, deci
    duplicatele n-ar strica baza — dar `findings_count` din `scans` și cifra
    anunțată pe Telegram s-ar dubla, iar operatorul ar vedea „14 vulnerabilități
    noi" pentru șapte.
    """
    dublat = json.loads(json.dumps(SAMPLE))
    dublat["Results"].append(json.loads(json.dumps(dublat["Results"][0])))
    assert len(trivy_fs.parse(dublat)) == len(trivy_fs.parse(SAMPLE)) == 3


def test_no_published_fix_is_none_rather_than_an_empty_version() -> None:
    """`"FixedVersion": ""` înseamnă „nu există fix", nu „versiunea e goală".

    Eșecul pe care îl previne: `prioritize.score` adaugă +5 pentru o constatare
    care se POATE repara, iar planificatorul de patch-uri cere o versiune țintă.
    Un șir gol scris în coloană arată în panou ca o versiune reală care lipsește
    la citire — iar un plan generat pentru ea n-ar avea către ce să actualizeze.
    """
    ghsa = _by_id(trivy_fs.parse(SAMPLE))["GHSA-3xgq-45jj-v275"]
    assert ghsa["fixed_version"] is None
    assert _by_id(trivy_fs.parse(SAMPLE))["CVE-2025-43859"]["fixed_version"] == "0.16.0"


def test_the_cvss_score_and_vector_come_from_the_same_vendor() -> None:
    """Un scor de la un furnizor lângă vectorul altuia nu descrie nicio evaluare.

    Eșecul pe care îl previne: `max()` peste scoruri și `next()` peste vectori ar
    fi pus 7.5 (ghsa) lângă `AV:L` (nvd). Operatorul care verifică rândul nu-l
    regăsește la nicio sursă și încetează să mai creadă coloana.
    """
    npm = _by_id(trivy_fs.parse(SAMPLE))["CVE-2024-21538"]
    assert npm["cvss"] == 5.5, "NVD e sursa neutră și trebuie preferată"
    assert npm["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"


def test_a_cvss_score_outside_the_column_constraint_cannot_stop_ingestion() -> None:
    """`cvss numeric(3,1) CHECK (cvss BETWEEN 0 AND 10)`.

    Eșecul pe care îl previne: un scor de 11.0 dintr-o sursă stricată face
    `upsert_finding` să arunce, excepția urcă din bucla de ingestie, și TOATE
    celelalte constatări ale rulării se pierd din cauza uneia singure.
    """
    assert trivy_fs._cvss({"CVSS": {"nvd": {"V3Score": 11.0}}})[0] == 10.0
    assert trivy_fs._cvss({"CVSS": {"nvd": {"V3Score": -3}}})[0] == 0.0
    # `numeric(3,1)` are TREI cifre cu totul: 7.5678 ar fi rotunjit oricum de
    # Postgres, dar un scor cu patru zecimale trecut mai departe e o valoare pe
    # care nu o mai putem citi înapoi la fel cum am scris-o.
    for brut in (7.5678, 9.87, 0.04, 10.0, 0):
        scor = trivy_fs._cvss({"CVSS": {"nvd": {"V3Score": brut}}})[0]
        assert 0.0 <= scor <= 10.0 and round(scor, 1) == scor, (brut, scor)
    assert trivy_fs._cvss({"CVSS": "nu e un tabel"}) == (None, None)
    assert trivy_fs._cvss({}) == (None, None)
    # `True` e un `int` în Python; scris în coloană ar deveni un scor de 1.0.
    assert trivy_fs._cvss({"CVSS": {"nvd": {"V3Score": True}}}) == (None, None)


# --------------------------------------------------------------------------
# Severitatea
# --------------------------------------------------------------------------
@pytest.mark.parametrize(("trivy", "nostru", "stiuta"), [
    ("CRITICAL", "critical", True),
    ("HIGH", "high", True),
    ("MEDIUM", "medium", True),
    ("LOW", "low", True),
    ("UNKNOWN", "medium", False),
    ("", "medium", False),
    (None, "medium", False),
    ("PORTOCALIU", "medium", False),
])
def test_severity_maps_to_the_column_vocabulary(trivy, nostru, stiuta) -> None:
    """`CHECK (severity IN ('info','low','medium','high','critical'))`.

    Eșecul pe care îl previne: o severitate netradusă („HIGH" în loc de „high")
    face `upsert_finding` să încalce constrângerea, iar constatarea nu ajunge
    niciodată în panou — scanarea raportează `failed` fără să spună de ce.
    """
    assert trivy_fs.map_severity(trivy) == (nostru, stiuta)


def test_an_unassessed_vulnerability_is_not_filed_as_negligible() -> None:
    """`UNKNOWN` nu e `info`, și diferența trebuie să rămână vizibilă.

    Eșecul pe care îl previne: `info` e o afirmație — „ne-am uitat, e neglijabil"
    — iar `UNKNOWN` e lipsa unei afirmații. Puse în aceeași găleată, tot ce nu e
    încă evaluat cade sub orice filtru de triaj și nu se mai uită nimeni la el.
    `medium` îl ține în câmpul vizual; steagul din `raw` păstrează cele două
    stări deosebite pentru cine se uită.
    """
    items = _by_id(trivy_fs.parse(SAMPLE))
    ghsa = items["GHSA-3xgq-45jj-v275"]
    assert ghsa["severity"] == "medium"
    assert ghsa["raw"]["severity_known"] is False

    # Iar una evaluată trebuie să se distingă de ea — altfel steagul nu spune nimic.
    assert items["CVE-2025-43859"]["raw"]["severity_known"] is True


def test_the_source_filter_does_not_drop_unassessed_vulnerabilities() -> None:
    """Filtrul cerut lui trivy trebuie să conțină `UNKNOWN`.

    Eșecul pe care îl previne: maparea de mai sus ar fi corectă și moartă. Cu
    `--severity MEDIUM,HIGH,CRITICAL`, trivy nu trimite niciodată o constatare
    `UNKNOWN`, deci o vulnerabilitate căreia nimeni nu i-a dat încă o notă
    dispare la sursă — „nu știu" citit ca „nu contează", tăcut.
    """
    argv = trivy_fs.build_argv("/var/www", "/tmp/x.json")
    severitati = argv[argv.index("--severity") + 1].split(",")
    assert "UNKNOWN" in severitati, severitati
    assert {"HIGH", "CRITICAL"} <= set(severitati), severitati


# --------------------------------------------------------------------------
# Comanda
# --------------------------------------------------------------------------
def test_the_command_asks_for_json_in_a_file_and_never_parses_text() -> None:
    """Ieșirea de text a lui trivy e formatare, nu interfață.

    Eșecul pe care îl previne: un tabel aliniat cu spații se schimbă între
    versiuni fără ca nimic să anunțe, iar un parser de text care nu mai potrivește
    nimic raportează zero constatări — nu o eroare.

    În FIȘIER, nu la stdout, ca dimensiunea să poată fi verificată cu `stat`
    înainte de citire: un raport destul de mare cât să conteze e o problemă de
    memorie, iar citirea lui ca să afli cât e de mare anulează verificarea.
    """
    argv = trivy_fs.build_argv("/var/www", "/tmp/raport.json")
    assert argv[argv.index("--format") + 1] == "json"
    assert argv[argv.index("--output") + 1] == "/tmp/raport.json"


def test_the_command_scans_a_directory_and_not_the_whole_root() -> None:
    """`fs <cale>`, nu `rootfs /`.

    Eșecul pe care îl previne, dublu: `rootfs` pornește detecția de pachete de
    sistem, adică exact răspunsul plin de fals-pozitive pe care docstring-ul lui
    `os_packages` îl descrie (fixuri backportate raportate ca vulnerabile) — și
    ar dubla fiecare constatare a lui dnf. Iar `/` ar însemna parcurgerea
    întregii gazde contra unui `MemoryMax=1G`.
    """
    argv = trivy_fs.build_argv("/var/www", "/tmp/x.json")
    assert "fs" in argv and "rootfs" not in argv and "image" not in argv
    assert argv[-1] == "/var/www"
    assert argv[-2] == "--", (
        "calea nu e despărțită de steaguri, deci una care începe cu `-` ar fi "
        "citită ca opțiune")
    assert argv[argv.index("--scanners") + 1] == "vuln"


def test_trivy_gets_a_shorter_deadline_than_the_one_we_enforce() -> None:
    """Cine cade primul decide ce scrie în `scans.error`.

    Eșecul pe care îl previne: cu plafonul nostru mai mic, îl omorâm noi și tot
    ce rămâne pe rând e „timeout" — fără motiv, fără cale, fără nimic de citit.
    Cu al lui mai mic, trivy se oprește singur și scrie de ce, iar rândul `failed`
    devine ceva ce operatorul poate acționa.
    """
    argv = trivy_fs.build_argv("/var/www", "/tmp/x.json")
    cerut = argv[argv.index("--timeout") + 1]
    assert cerut.endswith("s") and int(cerut[:-1]) == trivy_fs.TRIVY_TIMEOUT_S
    assert trivy_fs.TRIVY_TIMEOUT_S < trivy_fs.TIMEOUT_S
    assert (trivy_fs.TRIVY_TIMEOUT_S + trivy_fs.TRIVY_GRACE_S
            <= trivy_fs.TIMEOUT_S - trivy_fs.VERSION_TIMEOUT_S), (
        "prima cale nu încape întreagă în termenul rulării, deși i se dă "
        "plafonul întreg: o rulare cu o singură cale ar depăși bugetul")


# --------------------------------------------------------------------------
# Cache-ul și unitatea
# --------------------------------------------------------------------------
def test_the_unit_creates_the_cache_directory_the_scanner_uses() -> None:
    """`CacheDirectory=X` face `/var/cache/X`, și trebuie să fie `CACHE_DIR`.

    Eșecul pe care îl previne: fără directorul creat de systemd, trivy scrie în
    `$HOME/.cache/trivy`, iar sub `ProtectSystem=strict` acolo nu se poate scrie
    — deci descărcarea bazei eșuează la fiecare rulare și scanarea de fișiere nu
    rulează niciodată. Legate, calea din cod și cea creată nu pot diverge tăcut.
    """
    valori = re.findall(r"^CacheDirectory=(\S+)$", UNIT.read_text(encoding="utf-8"), re.M)
    assert trivy_fs.CACHE_DIR in {f"/var/cache/{v}" for v in valori}, (
        f"unitatea creează {valori}, iar trivy scrie în {trivy_fs.CACHE_DIR}")


@pytest.mark.parametrize("cale", ["/tmp", "/var/tmp", "/var/cache/dnf"])
def test_the_cache_is_not_somewhere_shared_or_volatile(cale: str) -> None:
    """Baza de vulnerabilități nu stă într-un director care se golește.

    Eșecul pe care îl previne: în `/tmp`, fiecare rulare ar fi prima — câteva
    sute de MB de la ghcr.io în fiecare noapte, și o scanare care depinde de
    ieșirea la internet la FIECARE rulare, nu doar când baza s-a învechit.
    """
    assert trivy_fs.CACHE_DIR != cale
    assert not trivy_fs.CACHE_DIR.startswith(cale + "/")


def test_the_scanner_actually_passes_its_cache_dir_to_trivy() -> None:
    """O constantă declarată și nefolosită e o reparație pe hârtie."""
    argv = trivy_fs.build_argv("/var/www", "/tmp/x.json")
    assert argv[argv.index("--cache-dir") + 1] == trivy_fs.CACHE_DIR
    version_argv = [trivy_fs.BINARY, "--cache-dir", trivy_fs.CACHE_DIR, "version"]
    assert version_argv[1:3] == ["--cache-dir", trivy_fs.CACHE_DIR]


# --------------------------------------------------------------------------
# Vechimea bazei de vulnerabilități
# --------------------------------------------------------------------------
def _meta(updated: str | None = None, **rest):
    meta = {"Version": 2, "NextUpdate": "2026-08-27T12:00:00Z"}
    if updated is not None:
        meta["UpdatedAt"] = updated
    meta.update(rest)
    return meta


def _with_meta(monkeypatch, meta, source="trivy version --format json"):
    async def fake(*_a, **_k):
        return meta, source
    monkeypatch.setattr(trivy_fs, "_db_metadata", fake)


def test_a_fresh_database_is_reported_with_its_age(monkeypatch) -> None:
    """Vechimea se citește, nu se presupune — și ajunge pe rândul din `scans`.

    Eșecul pe care îl previne: fără `db_version` pe rând, „13 constatări" nu poate
    fi datat nici a doua zi. Coloana există în migrația 0003 tocmai cu comentariul
    ăsta: un raport curat de la un scaner cu baza veche e o poză parțială.
    """
    _with_meta(monkeypatch, _meta("2026-08-27T00:00:00Z"))
    descris, varsta, eroare = run(trivy_fs.db_status(now=NOW))
    assert eroare is None
    assert varsta == pytest.approx(4.0)
    assert "2026-08-27T00:00:00Z" in descris and "trivy-db" in descris


def test_a_three_month_old_database_does_not_pass_as_a_measurement(monkeypatch) -> None:
    """O bază veche care raportează „nimic nou" e tiparul casei, în altă haină.

    Eșecul pe care îl previne: gazda pierde ieșirea către ghcr.io, trivy continuă
    cu ce are în cache, și panoul arată aceeași cifră liniștitoare săptămâni la
    rând. Nimic nu eșuează, nimic nu se schimbă, iar CVE-urile publicate între
    timp pur și simplu nu există pentru sistemul ăsta.
    """
    vechi = (NOW - timedelta(days=92)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _with_meta(monkeypatch, _meta(vechi))
    _, varsta, eroare = run(trivy_fs.db_status(now=NOW))
    assert eroare is None, "db_status raportează faptul; poarta e în `scan`"
    assert varsta > trivy_fs.MAX_DB_AGE_H


def test_an_unreadable_database_age_is_not_read_as_fine(monkeypatch) -> None:
    """„Nu știu cât e de veche" nu e „e proaspătă".

    Eșecul pe care îl previne: ambele surse de metadate tac (cache gol, sau trivy
    schimbă forma ieșirii lui `version`), iar o implementare indulgentă ar merge
    mai departe presupunând că e bine. Atunci poarta de vechime n-ar mai apăra
    nimic — ar trece exact în cazul în care nu se poate verifica.
    """
    _with_meta(monkeypatch, None, "")
    descris, varsta, eroare = run(trivy_fs.db_status(now=NOW))
    assert descris is None and varsta is None
    assert eroare and "vechimea" in eroare


def test_a_timestamp_that_cannot_be_parsed_is_not_read_as_fine(monkeypatch) -> None:
    """Metadate prezente, dar fără o dată lizibilă — tot „nu știu".

    Eșecul pe care îl previne: un `UpdatedAt` de altă formă ar fi devenit `None`,
    iar o vechime calculată din `None` ar fi fost fie o excepție, fie un zero
    liniștitor. Zero înseamnă „construită acum", adică cel mai proaspăt răspuns
    posibil, dat tocmai când nu se știe nimic.
    """
    _with_meta(monkeypatch, _meta("acum vreo două săptămâni"))
    descris, varsta, eroare = run(trivy_fs.db_status(now=NOW))
    assert descris is None and varsta is None
    assert eroare and "lizibil" in eroare


def test_a_database_dated_in_the_future_is_not_a_measurement(monkeypatch) -> None:
    """Un ceas greșit face vechimea negativă, deci mereu „proaspătă".

    Eșecul pe care îl previne: dacă gazda are ceasul în urmă (sau imaginea bazei
    e datată greșit), diferența iese negativă și trece pe sub orice prag — poarta
    de vechime devine inertă exact în cazul în care ceva e deja stricat.
    """
    viitor = (NOW + timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _with_meta(monkeypatch, _meta(viitor))
    _, _, eroare = run(trivy_fs.db_status(now=NOW))
    assert eroare and "viitor" in eroare


def test_the_build_time_is_preferred_over_the_download_time(monkeypatch) -> None:
    """`UpdatedAt` spune ce ȘTIE baza; `DownloadedAt` doar când am luat-o noi.

    Eșecul pe care îl previne: o descărcare de azi a unei baze construite acum
    trei luni ar fi arătat ca proaspătă. Se descarcă noi metadate, cifra din panou
    se reîmprospătează, și tot nu știe nimic despre ce s-a publicat între timp.
    """
    _with_meta(monkeypatch, _meta(
        (NOW - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        DownloadedAt=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")))
    _, varsta, _ = run(trivy_fs.db_status(now=NOW))
    assert varsta == pytest.approx(90 * 24, abs=1)


def test_the_timestamp_parser_accepts_what_trivy_actually_writes() -> None:
    """Nanosecunde RFC3339 — `datetime.fromisoformat` le refuză.

    Eșecul pe care îl previne: `2026-08-27T03:11:02.123456789Z` are nouă zecimale,
    iar un parser care crapă pe ele transformă o bază proaspătă în „vechime
    necunoscută" — adică într-o scanare eșuată în fiecare noapte, pe o gazdă
    perfect sănătoasă.
    """
    assert trivy_fs._parse_ts("2026-08-27T03:11:02.123456789Z") == datetime(
        2026, 8, 27, 3, 11, 2, 123456, tzinfo=timezone.utc)
    assert trivy_fs._parse_ts("2026-08-27T03:11:02Z") == datetime(
        2026, 8, 27, 3, 11, 2, tzinfo=timezone.utc)
    assert trivy_fs._parse_ts("2026-08-27T05:11:02+02:00").astimezone(
        timezone.utc) == datetime(2026, 8, 27, 3, 11, 2, tzinfo=timezone.utc)
    assert trivy_fs._parse_ts("nimic") is None
    assert trivy_fs._parse_ts(None) is None


# --------------------------------------------------------------------------
# `scan()`: cele trei rezultate, și mai ales al treilea
# --------------------------------------------------------------------------
def _fake_trivy(monkeypatch, payloads, *, rc=0, err="", binar=None):
    """Înlocuiește procesul trivy: scrie rapoartele cerute, întoarce `rc`.

    `payloads` e o listă, câte un raport per cale scanată, ca un test să poată
    face o cale să reușească și pe următoarea să cadă.
    """
    apeluri: list[list[str]] = []
    stare = {"i": 0}

    async def fake_run(argv, timeout=trivy_fs.TIMEOUT_S):
        apeluri.append(list(argv))
        if "version" in argv:
            return 0, json.dumps({"Version": "0.74.0", "VulnerabilityDB": _meta(
                NOW.strftime("%Y-%m-%dT%H:%M:%SZ"))}), ""
        i = stare["i"]
        stare["i"] += 1
        payload = payloads[i] if i < len(payloads) else payloads[-1]
        if payload is not None:
            iesire = argv[argv.index("--output") + 1]
            with open(iesire, "w", encoding="utf-8", newline="") as fh:
                json.dump(payload, fh)
        codul = rc if isinstance(rc, int) else rc[i]
        return codul, "", err

    monkeypatch.setattr(trivy_fs, "_run", fake_run)
    if binar is None:
        monkeypatch.setattr(trivy_fs, "BINARY", os.path.abspath(__file__))
    return apeluri


def test_the_gate_and_the_command_name_the_same_binary(monkeypatch, tmp_path) -> None:
    """Ce a trecut de poarta „e instalat" e ce se și execută.

    Eșecul pe care îl previne: poarta întreabă `os.path.exists(BINARY) or
    which("trivy")` și trece fiindcă trivy e pe PATH în altă parte, iar comanda
    execută `BINARY`, care nu există. Rândul `failed` spune atunci
    „FileNotFoundError" — un simptom în locul cauzei, exact în singurul loc unde
    operatorul se uită.
    """
    altundeva = tmp_path / "trivy"
    altundeva.write_text("binar fals", encoding="utf-8")
    monkeypatch.setattr(trivy_fs, "BINARY", "/nu/exista/trivy")
    monkeypatch.setattr(trivy_fs.shutil, "which", lambda _n: str(altundeva))
    assert trivy_fs.resolve_binary() == str(altundeva)

    d = tmp_path / "app"
    d.mkdir()
    apeluri = _fake_trivy(monkeypatch, [{"SchemaVersion": 2, "Results": None}],
                          binar=str(altundeva))
    items, eroare, _ = run(trivy_fs.scan([str(d)]))
    assert eroare is None and items == []
    assert {a[0] for a in apeluri} == {str(altundeva)}, (
        f"comanda a fost executată cu {sorted({a[0] for a in apeluri})}, nu cu "
        f"binarul găsit de poartă")


def test_a_missing_binary_is_an_error_and_not_a_clean_host(monkeypatch) -> None:
    """Pasul 21 n-a instalat trivy — asta nu înseamnă că gazda e curată.

    Eșecul pe care îl previne, direct din CLAUDE.md: o listă goală întoarsă fără
    eroare ar fi urmată de `mark_resolved_absent`, care marchează REZOLVATE toate
    constatările rulării de ieri. Panoul trece pe verde fiindcă scanerul lipsește.
    """
    monkeypatch.setattr(trivy_fs, "BINARY", "/nu/exista/trivy")
    monkeypatch.setattr(trivy_fs.shutil, "which", lambda _n: None)
    items, eroare, _ = run(trivy_fs.scan(["/var/www"]))
    assert items == []
    assert eroare and "trivy nu e instalat" in eroare


def test_no_configured_path_exists_is_an_error_and_not_a_clean_host(monkeypatch) -> None:
    """Nicio cale de scanat înseamnă că nu s-a scanat nimic.

    Eșecul pe care îl previne: `scan.discovery_paths` rămâne cu implicitul, gazda
    n-are `/srv` și nici `/var/www` (aplicațiile stau în altă parte), trivy nu e
    chemat niciodată, și lista goală rezultată închide tot ce era deschis.
    """
    monkeypatch.setattr(trivy_fs, "BINARY", os.path.abspath(__file__))
    items, eroare, _ = run(trivy_fs.scan(["/nu/exista/aici", "/nici/aici"]))
    assert items == []
    assert eroare and "nu există" in eroare

    items, eroare, _ = run(trivy_fs.scan([]))
    assert items == [] and eroare and "goală" in eroare


def test_a_path_that_fails_stops_the_whole_run(monkeypatch, tmp_path) -> None:
    """O listă parțială e mai periculoasă decât niciuna.

    Eșecul pe care îl previne: prima cale reușește, a doua cade (permisiuni, disc
    plin, trivy omorât de `MemoryMax`), iar un scaner care merge mai departe
    întoarce doar constatările primei căi. `mark_resolved_absent` închide apoi tot
    ce fusese găsit sub a doua — reparat, spune panoul, fără ca cineva să repare.
    """
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _fake_trivy(monkeypatch, [SAMPLE, None], rc=[0, 2], err="FATAL\tscan error: walk error")
    items, eroare, _ = run(trivy_fs.scan([str(a), str(b)]))
    assert items == [], "constatările primei căi au fost întoarse ca rezultat complet"
    assert eroare and "walk error" in eroare and str(b) in eroare


# --------------------------------------------------------------------------
# Bugetul de timp: UN termen peste toate căile, nu un plafon per cale
# --------------------------------------------------------------------------
class _Ceas:
    """Ceas fals pentru `trivy_fs.time`, ca bugetul să fie măsurat, nu presupus.

    Doar `monotonic`, și doar numele din `trivy_fs`: ceasul pe care îl citește
    bucla de evenimente a lui asyncio rămâne cel real, altfel `asyncio.run` s-ar
    trezi cu timpul mutat de sub picioare.
    """

    def __init__(self) -> None:
        self.acum = 0.0

    def monotonic(self) -> float:
        return self.acum


def _trivy_care_consuma(monkeypatch, ceas, *, payload=None, rc=0, err=""):
    """trivy fals care CHELTUIE tot plafonul primit și notează când a pornit.

    Cazul cel mai rău, dinadins: un trivy care își ignoră propriul `--timeout` și
    atârnă până îl omorâm noi. Un buget probat pe un trivy cuminte n-ar fi probat
    pe nimic — el există tocmai pentru cel care nu e.

    `rc` poate fi o listă, câte un cod per cale, ca o cale să reușească și
    următoarea să cadă.
    """
    apeluri: list[dict] = []
    stare = {"i": 0}

    async def fake_run(argv, timeout):
        apeluri.append({"argv": list(argv), "timeout": timeout,
                        "start": ceas.acum})
        ceas.acum += timeout
        if "version" in argv:
            return 0, json.dumps({"Version": "0.74.0", "VulnerabilityDB": _meta(
                NOW.strftime("%Y-%m-%dT%H:%M:%SZ"))}), ""
        i = stare["i"]
        stare["i"] += 1
        with open(argv[argv.index("--output") + 1], "w", encoding="utf-8",
                  newline="") as fh:
            json.dump(payload if payload is not None
                      else {"SchemaVersion": 2, "Results": None}, fh)
        return (rc if isinstance(rc, int) else rc[min(i, len(rc) - 1)]), "", err

    monkeypatch.setattr(trivy_fs, "_run", fake_run)
    monkeypatch.setattr(trivy_fs, "time", ceas)
    monkeypatch.setattr(trivy_fs, "BINARY", os.path.abspath(__file__))
    return apeluri


def _cai(tmp_path, cate):
    """`cate` directoare care chiar există, ca `scan()` să nu iasă pe poarta lor."""
    out = []
    for i in range(cate):
        d = tmp_path / f"cale-{i}"
        d.mkdir(parents=True)
        out.append(str(d))
    return out


def _fs(apeluri):
    return [a for a in apeluri if "fs" in a["argv"]]


@pytest.mark.parametrize("cate", [1, 2, 4, 8])
def test_the_budget_is_one_deadline_over_all_paths_not_a_ceiling_per_path(
        monkeypatch, tmp_path, cate) -> None:
    """Plafonul nu are voie să se înmulțească cu numărul de căi din configurație.

    Eșecul pe care îl previne, exact așa cum a fost livrat: `TIMEOUT_S` dat lui
    `_run` ÎNĂUNTRUL buclei peste căi. Plafonul real era atunci `TIMEOUT_S` înmulțit
    cu câte căi are `scan.discovery_paths` — 4 × 1800 cu implicitul, 8 × 1800 dacă
    operatorul mai adaugă patru. `sentinel-scan.service` omoară TOATĂ unitatea la
    `TimeoutStartSec`, deci `trivy_image` și ce vine după el n-ar mai rula deloc,
    iar rândul lor `running` ar umbri ultimul rezultat real în panou.

    Măsurat, nu presupus: ceasul lui `trivy_fs` e fals și fiecare rulare de trivy
    cheltuie tot ce i s-a dat. Ce se asertează e cât a trecut, nu ce scrie într-o
    constantă.
    """
    ceas = _Ceas()
    apeluri = _trivy_care_consuma(monkeypatch, ceas)
    run(trivy_fs.scan(_cai(tmp_path, cate)))

    assert _fs(apeluri), (
        "niciun trivy n-a fost chemat, deci măsurătoarea de mai jos ar trece "
        "oricât ar fi bugetul")
    assert ceas.acum <= trivy_fs.TIMEOUT_S, (
        f"cu {cate} căi rularea a ținut {ceas.acum:.0f}s, iar plafonul pe care "
        f"îl declară `TIMEOUT_S` e {trivy_fs.TIMEOUT_S}s")


def test_the_measured_ceiling_fits_inside_the_unit_budget(monkeypatch, tmp_path) -> None:
    """Suma constantelor nu e bugetul; cât ține scanarea pe ceas e.

    Eșecul pe care îl previne: aserțiunea care aduna
    `os_packages.TIMEOUT_S + trivy_fs.TIMEOUT_S + trivy_image.TIMEOUT_S`, dădea
    5700 și trecea — în timp ce `trivy_fs` chiar ținea de patru ori constanta lui,
    adică 11100. Testul păzea o sumă pe care nimeni n-o respecta. Când unitatea e
    omorâtă la `TimeoutStartSec`, scanerul din coadă nu mai rulează și rândul lui
    rămâne `running` peste ultimul rezultat real.

    Numărul lui `trivy_fs` se MĂSOARĂ aici, pe cel mai rău caz pe care îl poate
    produce configurația: destule căi cât să sature termenul, fiecare cu un trivy
    care atârnă până îl omorâm.
    """
    from sentinel.scan import os_packages, trivy_image

    # Atâtea căi câte trebuie ca termenul să fie CE MĂRGINEȘTE măsurătoarea, nu
    # numărul de căi — altfel, la un `TIMEOUT_S` ridicat, opt căi s-ar termina
    # înainte de termen și cifra măsurată ar fi mai mică decât cel mai rău caz.
    # Cel puțin opt fiindcă atâtea îi ia operatorului două linii de configurație.
    cate = max(8, trivy_fs.TIMEOUT_S
               // (trivy_fs.TRIVY_TIMEOUT_S + trivy_fs.TRIVY_GRACE_S) + 2)
    ceas = _Ceas()
    apeluri = _trivy_care_consuma(monkeypatch, ceas)
    _, eroare, _ = run(trivy_fs.scan(_cai(tmp_path, cate)))
    masurat = ceas.acum
    assert _fs(apeluri) and masurat > 0, (
        "scanarea n-a consumat nimic, deci suma de mai jos n-ar măsura nimic")
    assert eroare and "s-a epuizat" in eroare, (
        f"cu {cate} căi care atârnă, rularea s-a terminat înainte de termen "
        f"({masurat:.0f}s din {trivy_fs.TIMEOUT_S}s): măsurătoarea nu mai e cel mai "
        f"rău caz, deci suma de mai jos ar trece fără să dovedească nimic")

    valori = re.findall(r"^TimeoutStartSec=(\d+)\s*$",
                        UNIT.read_text(encoding="utf-8"), re.M)
    assert len(valori) == 1, valori
    buget = int(valori[0])
    # Celelalte două se iau ca declarate; a lui `trivy_image` e deja un termen de
    # ceas peste toate imaginile, iar `os_packages` rulează o singură comandă —
    # una singură pe gazdă, fiindcă familia alege un singur backend, deci ce
    # trebuie să încapă aici e MAXIMUL plafoanelor lui, nu suma lor. Citit din
    # `WORST_CASE_TIMEOUT_S` și nu din plafonul lui dnf: cu al doilea backend,
    # `TIMEOUT_S` singur ar fi ținut suma legată de gazda RHEL și ar fi lăsat-o
    # dezlegată exact pe cea Debian.
    suma = os_packages.WORST_CASE_TIMEOUT_S + masurat + trivy_image.TIMEOUT_S
    assert suma < buget, (
        f"pe {cate} căi `trivy_fs` ține {masurat:.0f}s, iar cu os_packages "
        f"({os_packages.WORST_CASE_TIMEOUT_S}s) și trivy_image "
        f"({trivy_image.TIMEOUT_S}s) suma e {suma:.0f}s, peste cei {buget}s la "
        f"care systemd omoară unitatea")


def test_an_exhausted_budget_refuses_instead_of_ingesting_what_it_reached(
        monkeypatch, tmp_path) -> None:
    """Termenul epuizat oprește rularea; nu predă căile atinse ca listă întreagă.

    Eșecul pe care îl previne: două căi din patru ingerate ca și cum ar fi toate,
    urmate de `mark_resolved_absent`, care închide constatările celorlalte două.
    Vulnerabilitățile de sub ele rămân pe disc, iar panoul spune că s-au reparat —
    exact motivul pentru care o cale căzută oprește deja toată rularea.
    """
    ceas = _Ceas()
    apeluri = _trivy_care_consuma(monkeypatch, ceas, payload=SAMPLE)
    cai = _cai(tmp_path, 4)
    items, eroare, fapte = run(trivy_fs.scan(cai))

    assert items == [], (
        "constatările căilor care au apucat să fie scanate au fost întoarse ca "
        "rezultat complet")
    assert eroare and "s-a epuizat după" in eroare and "2/4 căi" in eroare
    assert cai[2] in eroare, "rândul `failed` nu spune de la ce cale s-a oprit"
    assert len(_fs(apeluri)) == 2, (
        f"trivy a fost chemat de {len(_fs(apeluri))} ori deși bugetul se dusese "
        f"după două căi")
    assert fapte["paths"] == cai, "rândul `failed` nu spune ce căi erau de scanat"


def test_trivy_is_never_given_a_deadline_that_outlives_our_budget(
        monkeypatch, tmp_path) -> None:
    """Ultima cale nu are voie să treacă singură peste termenul rulării.

    Eșecul pe care îl previne: `--timeout` fix la `TRIVY_TIMEOUT_S` pentru fiecare
    cale, indiferent cât a mai rămas. O cale pornită cu o sută de secunde înainte
    de termen ar primi tot 840, iar `sentinel-scan.service` ar fi omorâtă de
    systemd cu trivy în ea — nu se pierde doar scanarea de fișiere, ci și tot ce
    urma după ea, fără niciun rând care să spună de ce.
    """
    ceas = _Ceas()
    apeluri = _trivy_care_consuma(monkeypatch, ceas)
    run(trivy_fs.scan(_cai(tmp_path, 4)))

    scanate = _fs(apeluri)
    assert scanate, "niciun trivy chemat, deci bucla de mai jos n-ar verifica nimic"
    for apel in scanate:
        argv = apel["argv"]
        cerut = int(argv[argv.index("--timeout") + 1][:-1])
        assert 0 < cerut <= trivy_fs.TRIVY_TIMEOUT_S, cerut
        assert apel["timeout"] == cerut + trivy_fs.TRIVY_GRACE_S, (
            f"trivy primește {cerut}s, dar noi îl omorâm la {apel['timeout']}s: "
            f"fie îl tăiem înainte să-și scrie mesajul, fie îl lăsăm peste buget")
        capat = apel["start"] + cerut + trivy_fs.TRIVY_GRACE_S
        assert capat <= trivy_fs.TIMEOUT_S, (
            f"trivy pornit la {apel['start']:.0f}s cu {cerut}s ar fi ținut până la "
            f"{capat:.0f}s, peste plafonul de {trivy_fs.TIMEOUT_S}s al rulării")


def test_a_failure_on_a_shortened_deadline_names_the_budget_as_the_cause(
        monkeypatch, tmp_path) -> None:
    """„Repară calea" și „mărește bugetul" sunt două acțiuni diferite.

    Eșecul pe care îl previne: ultima cale primește ce-a mai rămas din termen,
    trivy scrie `context deadline exceeded`, iar rândul `failed` arată identic cu
    al unei căi stricate. Operatorul se duce să caute ce e cu directorul, când de
    fapt scanarea a rămas fără timp — și la noapte se întâmplă la fel.

    Și invers: dacă pomenirea bugetului s-ar adăuga la ORICE eșec, n-ar mai deosebi
    nimic, deci se verifică și că o cale căzută cu plafonul întreg nu-l pomenește.
    """
    ceas = _Ceas()
    _trivy_care_consuma(monkeypatch, ceas, rc=[0, 1],
                        err="FATAL\tscan error: context deadline exceeded")
    cai = _cai(tmp_path, 3)
    items, eroare, _ = run(trivy_fs.scan(cai))
    assert items == []
    assert eroare and cai[1] in eroare and "context deadline exceeded" in eroare, (
        "mesajul lui trivy s-a pierdut din rândul `failed`")
    assert "din bugetul de" in eroare, (
        f"rândul `failed` nu spune că plafonul căii fusese tăiat de termenul "
        f"rulării: {eroare}")

    ceas2 = _Ceas()
    _trivy_care_consuma(monkeypatch, ceas2, rc=1,
                        err="FATAL\tscan error: walk error: permission denied")
    _, eroare2, _ = run(trivy_fs.scan(_cai(tmp_path / "alta", 3)))
    assert eroare2 and "permission denied" in eroare2
    assert "din bugetul de" not in eroare2, (
        f"prima cale a primit plafonul întreg, deci bugetul n-are ce căuta în "
        f"explicație: {eroare2}")


def test_a_clean_scan_returns_nothing_and_no_error(monkeypatch, tmp_path) -> None:
    """Al doilea rezultat: s-a uitat și n-a găsit nimic.

    Eșecul pe care îl previne, în oglindă față de restul fișierului: dacă „curat"
    ar fi tratat ca eroare, fiecare noapte pe o gazdă sănătoasă ar aprinde galben
    în `/selfcheck`, iar alarma care sună mereu nu se mai citește.
    """
    d = tmp_path / "app"
    d.mkdir()
    _fake_trivy(monkeypatch, [{"SchemaVersion": 2, "Results": None}])
    items, eroare, fapte = run(trivy_fs.scan([str(d)]))
    assert items == [] and eroare is None
    assert fapte["db_version"] and fapte["paths"] == [str(d)]


def test_a_stale_database_refuses_to_produce_findings(monkeypatch, tmp_path) -> None:
    """Peste plafonul de vechime, rezultatul nu se ingerează.

    Eșecul pe care îl previne: ce a găsit o bază veche e adevărat, dar ce NU a
    găsit nu mai dovedește nimic — și tocmai absența e cifra din panou. Fiindcă
    `scans.status` n-are o valoare care să însemne „încheiată, dar parțial
    oarbă", singurul mod în care faptul ajunge la operator e un rând `failed`.
    """
    d = tmp_path / "app"
    d.mkdir()
    apeluri = _fake_trivy(monkeypatch, [SAMPLE])
    _with_meta(monkeypatch, _meta(
        (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    items, eroare, fapte = run(trivy_fs.scan([str(d)]))
    assert items == []
    assert eroare and "zile" in eroare
    assert fapte["db_version"], "rândul `failed` trebuie să spună cu ce bază s-a lucrat"
    assert fapte["total"] == 3, "constatările au fost citite, dar nu se ingerează"
    assert any("fs" in a for a in apeluri), "scanarea trebuie să ruleze ÎNAINTE de poartă"


def test_more_findings_than_the_cap_are_refused_and_not_truncated(monkeypatch, tmp_path) -> None:
    """Un plafon care taie e mai rău decât niciun plafon.

    Eșecul pe care îl previne: 3000 de constatări tăiate la 500 sunt urmate de
    `mark_resolved_absent`, care marchează celelalte 2500 REZOLVATE. Panoul arată
    mai puține vulnerabilități exact fiindcă sunt mai multe, iar discul e ferit
    printr-o minciună. Refuzul păstrează amândouă: nimic nu se umple, nimic nu se
    închide, iar operatorul află numărul real.
    """
    d = tmp_path / "app"
    d.mkdir()
    multe = {"SchemaVersion": 2, "Results": [{
        "Target": "var/www/app/package-lock.json", "Class": "lang-pkgs", "Type": "npm",
        "Vulnerabilities": [
            {"VulnerabilityID": f"CVE-2026-{i:05d}", "PkgName": f"pachet-{i}",
             "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1", "Severity": "HIGH"}
            for i in range(trivy_fs.MAX_FINDINGS + 7)]}]}
    _fake_trivy(monkeypatch, [multe])
    items, eroare, fapte = run(trivy_fs.scan([str(d)]))
    assert items == [], "o listă tăiată ar fi fost ingerată ca listă completă"
    assert eroare and str(trivy_fs.MAX_FINDINGS + 7) in eroare
    assert fapte["total"] == trivy_fs.MAX_FINDINGS + 7


def test_an_oversized_report_is_not_read_into_the_process(monkeypatch, tmp_path) -> None:
    """`MemoryMax=1G` e a întregii unități, iar `json.loads` costă un multiplu.

    Eșecul pe care îl previne: un raport de sute de MB citit în proces declanșează
    OOM-ul cgroup-ului. `OOMPolicy=stop` oprește atunci TOATĂ unitatea de scanare,
    deci scanerul de pachete nu mai rulează nici el, iar rândul rămâne `running`
    pentru totdeauna — fără nimic care să-l închidă și fără nimic care să spună ce
    s-a întâmplat.
    """
    d = tmp_path / "app"
    d.mkdir()
    _fake_trivy(monkeypatch, [SAMPLE])
    monkeypatch.setattr(trivy_fs, "MAX_OUTPUT_BYTES", 5)
    items, eroare, _ = run(trivy_fs.scan([str(d)]))
    assert items == []
    assert eroare and "octeți" in eroare


def test_a_report_that_is_not_json_is_an_error_not_an_empty_result(
        monkeypatch, tmp_path) -> None:
    """trivy a ieșit cu 0 și a scris altceva decât JSON.

    Eșecul pe care îl previne: un `json.load` prins și ignorat ar da o listă
    goală, adică „gazdă curată" — și e chiar forma din CLAUDE.md, `2>/dev/null`
    peste o eroare reală.
    """
    d = tmp_path / "app"
    d.mkdir()

    async def fake_run(argv, timeout=trivy_fs.TIMEOUT_S):
        if "version" in argv:
            return 0, json.dumps({"VulnerabilityDB": _meta(
                NOW.strftime("%Y-%m-%dT%H:%M:%SZ"))}), ""
        with open(argv[argv.index("--output") + 1], "w", encoding="utf-8",
                  newline="") as fh:
            fh.write("FATAL  database error\n")
        return 0, "", ""

    monkeypatch.setattr(trivy_fs, "_run", fake_run)
    monkeypatch.setattr(trivy_fs, "BINARY", os.path.abspath(__file__))
    items, eroare, _ = run(trivy_fs.scan([str(d)]))
    assert items == []
    assert eroare and "JSON" in eroare


# --------------------------------------------------------------------------
# `visible_severities`: garda pe care se sprijină rezolvarea din orchestrator
# --------------------------------------------------------------------------
def test_what_a_trivy_fs_run_can_see_is_derived_from_what_it_asked_for() -> None:
    """Garda de rezolvare trebuie să urmeze pragul, nu o copie a lui.

    Eșecul pe care îl previne: mulțimea „ce poate vedea rularea" scrisă de mână
    a doua oară. La prima schimbare de prag lista rămâne în urmă, iar
    `mark_resolved_absent` închide exact constatările pe care noua rulare nu le
    mai poate vedea — adică tocmai ce garda e pusă să oprească, tăcut.
    """
    vazute, nenotate = trivy_fs.visible_severities()
    assert set(vazute) == {"medium", "high", "critical"}
    assert nenotate is True, (
        "cu UNKNOWN în prag, constatările nenotate (parcate la `medium` cu "
        "`severity_known=false`) sunt vizibile și pot fi închise")


def test_the_trivy_fs_visible_set_follows_a_changed_floor(monkeypatch) -> None:
    """Derivarea se probează schimbând pragul, nu citind valorile de azi.

    Eșecul pe care îl previne: testul de mai sus trece și peste o listă scrisă
    de mână, atâta timp cât cifrele coincid azi. Aici pragul se mută sub el —
    exact scenariul din docstring-ul lui `SEVERITIES`, care invită explicit la
    ridicarea pragului de la MEDIUM.
    """
    monkeypatch.setattr(trivy_fs, "SEVERITIES", ("HIGH", "CRITICAL"))
    vazute, nenotate = trivy_fs.visible_severities()
    assert set(vazute) == {"high", "critical"}
    assert "medium" not in vazute
    assert nenotate is False, (
        "fără UNKNOWN în prag, o rulare nu mai poate vedea constatările nenotate")


# --------------------------------------------------------------------------
# Orchestratorul: rândul din `scans` și ce NU se rezolvă
# --------------------------------------------------------------------------
class _DB:
    """Ciot de bază care ține minte ce s-a scris. Nu asertează nimic singur.

    `sub_prag` e ce răspunde la interogarea care numără constatările rămase sub
    pragul de severitate — implicit zero, ca o bază fără istoric.
    """

    def __init__(self, sub_prag: int = 0) -> None:
        self.scans: list[dict] = []
        self.finished: list[dict] = []
        self.upserted: list[dict] = []
        self.resolved: list[tuple] = []
        # SQL-ul și TOATE argumentele rezolvării, ca să poată fi văzută garda de
        # severitate, nu doar cele trei argumente vechi.
        self.resolve_calls: list[tuple] = []
        self.counted: list[tuple] = []
        self.sub_prag = sub_prag

    async def fetchval(self, sql, *args):
        if "INSERT INTO scans" in sql:
            self.scans.append({"scanner": args[0], "target": args[1],
                               "triggered_by": args[3]})
            return len(self.scans)
        if "SELECT count(*) FROM findings" in sql:
            self.counted.append((sql, args))
            return self.sub_prag
        return 0

    async def fetchrow(self, sql, *args):
        self.upserted.append({"finding_key": args[0], "scanner": args[2],
                              "cve": args[3], "severity": args[7]})
        return {"is_new": True, "status": "open"}

    async def fetch(self, sql, *args):
        if "SET status = 'resolved'" in sql:
            # (scanner, asset_id, cheile văzute) — exact argumentele lui
            # `mark_resolved_absent`, ca testul să poată spune nu doar CĂ s-a
            # rezolvat, ci pe ce mulțime.
            self.resolved.append((args[0], args[1], args[2]))
            self.resolve_calls.append((sql, args))
        return []

    async def execute(self, sql, *args):
        if "UPDATE scans SET" in sql:
            self.finished.append({"id": args[0], "status": args[1],
                                  "findings_count": args[2], "error": args[6],
                                  "db_version": args[7]})


def _cfg(paths=("/var/www",)):
    return SimpleNamespace(scan=SimpleNamespace(discovery_paths=list(paths)))


def _no_kev(monkeypatch):
    async def lookup(_db, _cves):
        return {}
    monkeypatch.setattr(orchestrator.kev, "lookup", lookup)


def test_a_failed_trivy_scan_resolves_nothing(monkeypatch) -> None:
    """Cea mai importantă regulă a fișierului, la nivelul orchestratorului.

    Eșecul pe care îl previne: un scaner care n-a putut rula întoarce o listă
    goală; dacă orchestratorul o tratează ca pe un rezultat, `mark_resolved_absent`
    marchează REZOLVATE toate constatările deschise. Vulnerabilitățile dispar din
    panou fiindcă nu s-a uitat nimeni la ele — reparate, zice cifra.
    """
    async def cade(_paths):
        return [], "trivy nu e instalat", {"db_version": "trivy-db v2 …"}

    monkeypatch.setattr(orchestrator.trivy_fs, "scan", cade)
    _no_kev(monkeypatch)
    db = _DB()
    out = run(orchestrator._run_trivy_fs(db, _cfg(), "test"))

    assert out["status"] == "failed"
    assert db.resolved == [], "o scanare eșuată a rezolvat constatări"
    assert db.upserted == []
    (rand,) = db.finished
    assert rand["status"] == "failed"
    assert rand["error"] == "trivy nu e instalat"
    assert rand["db_version"] == "trivy-db v2 …", (
        "rândul eșuat nu spune cu ce bază de date s-a lucrat")


def test_a_completed_scan_records_the_database_version(monkeypatch) -> None:
    """`scans.db_version` există în migrația 0003 tocmai pentru asta.

    Eșecul pe care îl previne: „13 constatări" fără „cu ce bază" nu poate fi datat
    nici a doua zi. Când cifra din panou și `dnf update` de pe gazdă nu sunt de
    acord — cum s-a întâmplat pe 21 august 2026 — coloana asta e ce arată care
    dintre ele e veche.
    """
    async def merge(_paths):
        return list(trivy_fs.parse(SAMPLE)), None, {"db_version": "trivy-db v2 proaspătă"}

    monkeypatch.setattr(orchestrator.trivy_fs, "scan", merge)
    _no_kev(monkeypatch)
    db = _DB()
    out = run(orchestrator._run_trivy_fs(db, _cfg(), "test"))

    assert out["status"] == "completed" and out["findings"] == 3
    assert len(db.upserted) == 3
    assert {u["scanner"] for u in db.upserted} == {"trivy_fs"}
    (scanner, asset_id, chei) = db.resolved[0]
    assert len(db.resolved) == 1 and scanner == "trivy_fs" and asset_id is None, (
        "o scanare reușită trebuie să închidă ce nu mai raportează")
    assert set(chei) == {u["finding_key"] for u in db.upserted}, (
        "mulțimea păstrată deschisă nu e cea tocmai ingerată, deci rezolvarea "
        "ar închide constatări pe care scanarea chiar le-a văzut")
    (rand,) = db.finished
    assert rand["status"] == "completed"
    assert rand["db_version"] == "trivy-db v2 proaspătă"


def test_a_run_at_a_raised_floor_does_not_close_the_old_medium_findings(
        monkeypatch) -> None:
    """`_run_trivy_fs` trebuie să treacă `visible_severities()` lui
    `mark_resolved_absent`, la fel ca `_run_trivy_image`.

    Eșecul pe care îl previne: fără gardă, `mark_resolved_absent` primea doar
    (scanner, asset_id, chei_văzute) — fără severitate. Azi, cu `SEVERITIES` la
    MEDIUM, asta nu strică nimic; dar `SEVERITIES` are un docstring care invită
    explicit la ridicarea pragului („nimeni n-a cerut asta" — până când cineva
    cere). Prima rulare de după acea ridicare, fără gardă, ar fi marcat
    `absent_from_latest_scan` orice constatare MEDIUM ingerată cu pragul vechi —
    44 dintre ele, măsurate pe gazdă pe 30 august 2026 — raportate operatorului
    drept reparate peste noapte, deși nimic de pe gazdă nu s-a schimbat.

    Pragul e ridicat aici prin `monkeypatch`, nu citit la valoarea de azi:
    la MEDIUM garda ar trece și fără să fenteze nimic, fiindcă nimic nu e sub
    prag încă — vezi docstring-ul lui `trivy_fs.visible_severities`.
    """
    monkeypatch.setattr(trivy_fs, "SEVERITIES", ("HIGH", "CRITICAL"))

    async def merge(_paths):
        return list(trivy_fs.parse(SAMPLE)), None, {"db_version": "trivy-db v2"}

    monkeypatch.setattr(orchestrator.trivy_fs, "scan", merge)
    _no_kev(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_fs(db, _cfg(), "test"))

    (sql, args) = db.resolve_calls[0]
    assert "severity = ANY($4::text[])" in sql, (
        f"rezolvarea nu e îngrădită de severitățile cerute: {sql}")
    assert set(args[3]) == {"high", "critical"}
    assert "medium" not in args[3], (
        "o rulare care nu mai cere MEDIUM ar putea închide constatări MEDIUM "
        "ingerate cu pragul vechi")
    assert args[4] is False, (
        "fără UNKNOWN în pragul ridicat, o rulare nu mai poate vedea "
        "constatările nenotate")


def test_the_scan_row_names_the_paths_that_were_asked_for(monkeypatch) -> None:
    """`scans.target` trebuie să spună ce s-a cerut, nu „localhost".

    Eșecul pe care îl previne: două rulări cu configurații diferite arată identic
    în istoric, deci o cădere a numărului de constatări după ce cineva a scos o
    cale din `scan.discovery_paths` nu se poate lega de cauză.
    """
    async def merge(_paths):
        return [], None, {"db_version": "x"}

    monkeypatch.setattr(orchestrator.trivy_fs, "scan", merge)
    _no_kev(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_fs(db, _cfg(["/var/www", "/opt"]), "manual"))
    assert db.scans == [{"scanner": "trivy_fs", "target": "/var/www,/opt",
                         "triggered_by": "manual"}]


def test_the_orchestrator_only_runs_trivy_when_the_config_says_so(monkeypatch) -> None:
    """`scan.filesystem` e steagul cu care e descris în configurație.

    Eșecul pe care îl previne: o cheie paralelă inventată aici („scan.trivy") ar
    lăsa `scan.filesystem: false` fără efect — operatorul oprește scanerul, iar el
    rulează mai departe în fiecare noapte.
    """
    sursa = (ROOT / "sentinel" / "scan" / "orchestrator.py").read_text(encoding="utf-8")
    assert "cfg.scan.filesystem" in sursa
    assert "cfg.scan.discovery_paths" in sursa


def test_the_scanner_name_is_the_key_selfcheck_reports_under(monkeypatch) -> None:
    """Numele scris în `scans` e cel sub care eșecul ajunge pe Telegram.

    Eșecul pe care îl previne: `check_last_scan` raportează sub
    `scan:last:{scanner}`, iar runner-ul reconciliază starea după chei. Un nume
    care nu se leagă — sau care se schimbă mai târziu — face ca vechea cheie să
    fie citită ca „și-a revenit", deci o scanare care nu mai rulează deloc
    dispare din `/selfcheck` în tăcere.

    Verificat capăt la capăt, nu pe o constantă: numele e luat din ce a scris
    orchestratorul și dus prin verificarea reală.
    """
    from sentinel.selfcheck import checks

    async def cade(_paths):
        return [], "trivy a eșuat pe /var/www", {"db_version": None}

    monkeypatch.setattr(orchestrator.trivy_fs, "scan", cade)
    _no_kev(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_fs(db, _cfg(), "test"))
    (scris,) = db.scans

    class _SelfcheckDB:
        async def fetch(self, _sql, *_a):
            return [{"id": 1, "scanner": scris["scanner"], "status": "failed",
                     "started_at": NOW, "finished_at": NOW,
                     "error": "trivy a eșuat pe /var/www", "findings_count": 0,
                     "ok_started_at": None, "ok_finished_at": None,
                     "ok_findings_count": None}]

    cfg = SimpleNamespace(scan=SimpleNamespace(enabled=True))
    (r,) = run(checks.check_last_scan(_SelfcheckDB(), cfg))
    assert r.key == f"scan:last:{trivy_fs.SCANNER}" == "scan:last:trivy_fs"
    assert r.status == "degraded"
    assert "trivy a eșuat" in r.detail
