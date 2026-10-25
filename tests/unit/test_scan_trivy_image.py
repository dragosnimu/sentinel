"""Scanerul `trivy image`: ce raportează, ce refuză, și când țipă.

Toate testele de aici păzesc aceeași familie de eșecuri ca la `trivy_fs` — **o
listă de vulnerabilități care arată la fel indiferent dacă scanarea a mers sau
nu** — plus una nouă, proprie containerelor: *nu s-a putut ajunge la docker*.

Cazurile concrete pe care le opresc:

* `scan.containers: true` pe o gazdă unde `sentinel` nu e în grupul `docker`.
  Fără testele de aici, `docker ps` eșuează, scanerul întoarce zero constatări,
  `mark_resolved_absent` închide tot ce raportase ieri, iar panoul trece pe verde
  fiindcă scanarea NU s-a făcut. Asta trebuie să fie un rând `failed` în `scans`
  și o cheie roșie în `/selfcheck`, nu o cifră liniștitoare;
* docker care lipsește cu totul — pe VM-ul de test nu e instalat. Aia nu e o
  eroare, e o gazdă fără containere, și n-are voie nici să scrie un rând
  `completed` cu zero constatări (migrația 0029 a scos `skipped` tocmai fiindcă
  „0 constatări" despre o scanare care n-a rulat e o minciună);
* clientul docker care pornește și iese cu 0 fără să fi vorbit cu daemonul —
  „codul de ieșire în loc de efectul", tiparul din CLAUDE.md;
* trivy care raportează despre ALTĂ imagine decât cea cerută (`--image-src`
  necontrolat îl lasă să cadă pe registry). Un raport corect despre altceva e mai
  rău decât o eroare;
* o listă parțială — o imagine care cade, un buget epuizat — ingerată ca și cum
  ar fi întreagă, după care restul imaginilor sunt marcate rezolvate;
* cheia de identitate: aceeași vulnerabilitate în cinci imagini trebuie să fie
  cinci constatări (cinci reconstrucții separate), iar o imagine reconstruită sub
  același tag trebuie să-și păstreze istoricul.

Eșantioanele JSON sunt după forma reală a ieșirii lui trivy 0.74 pentru
`trivy image` (`SchemaVersion: 2`, `ArtifactType: container_image`, cu blocul
`Metadata` pe care `trivy fs` nu-l are). Ce NU s-a putut proba aici: că binarul
real acceptă exact steagurile din `build_argv` — nu se descarcă și nu se rulează
trivy sau docker în teste.
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.db.repo import findings as fx
from sentinel.scan import orchestrator, trivy_fs, trivy_image

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "deploy" / "systemd" / "sentinel-scan.service"

DOCKER = "/usr/bin/docker"
TRIVY = "/usr/local/bin/trivy"

#: Două id-uri de imagine cu formă reală (64 de hex), scrise ca să se citească.
IMG_NGINX = "9c7a54a9a39c" + "0" * 52
IMG_APP = "1f3e5d7c9b8a" + "1" * 52

#: Digestul stratului și cel al manifestului din registry. Nici unul, nici altul
#: nu e citit de `parse` — sunt acolo ca eșantionul să aibă forma reală. Compuse,
#: nu scrise ca literal, ca să nu semene cu un secret în `test_repo_is_sanitised`:
#: un șir de 64 de hexa scris în clar e exact ce caută garda aia, și pe bună
#: dreptate — n-are cum să știe că ăsta e fabricat.
DIFF_ID = "2a1b3c4d5e6f" + "2" * 52
REPO_DIGEST = "6b7c8d9e0f1a" + "3" * 52


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Eșantion realist: `trivy image --scanners vuln --format json <id>`
# --------------------------------------------------------------------------
SAMPLE = json.loads(r"""
{
  "SchemaVersion": 2,
  "CreatedAt": "2026-08-27T03:14:51.482913744Z",
  "ArtifactName": "IMAGE_ID",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {"Family": "debian", "Name": "12.11"},
    "ImageID": "sha256:IMAGE_ID",
    "DiffIDs": ["sha256:DIFF_ID"],
    "RepoTags": ["nginx:1.27"],
    "RepoDigests": ["nginx@sha256:REPO_DIGEST"],
    "ImageConfig": {"architecture": "amd64", "os": "linux"}
  },
  "Results": [
    {
      "Target": "nginx:1.27 (debian 12.11)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-4001",
          "PkgID": "libxml2@2.9.14+dfsg-1.3~deb12u1",
          "PkgName": "libxml2",
          "InstalledVersion": "2.9.14+dfsg-1.3~deb12u1",
          "FixedVersion": "2.9.14+dfsg-1.3~deb12u2",
          "Status": "fixed",
          "Layer": {"Digest": "sha256:aa", "DiffID": "sha256:bb"},
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-4001",
          "DataSource": {"ID": "debian", "Name": "Debian Security Tracker"},
          "Title": "libxml2: heap buffer overflow in xmlParseChunk",
          "Description": "O supraîncărcare de buffer în libxml2.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": 9.8},
            "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L", "V3Score": 4.8}
          },
          "References": ["https://security-tracker.debian.org/tracker/CVE-2026-4001"]
        },
        {
          "VulnerabilityID": "CVE-2026-4002",
          "PkgID": "perl-base@5.36.0-7+deb12u1",
          "PkgName": "perl-base",
          "InstalledVersion": "5.36.0-7+deb12u1",
          "FixedVersion": "",
          "Status": "affected",
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-4002",
          "Title": "perl: unele lucruri neevaluate",
          "Severity": "UNKNOWN"
        }
      ]
    },
    {
      "Target": "usr/src/app/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "GHSA-7788-qqqq-wwww",
          "PkgID": "tar@6.1.11",
          "PkgName": "tar",
          "PkgPath": "usr/src/app/node_modules/tar/package.json",
          "InstalledVersion": "6.1.11",
          "FixedVersion": "6.2.1",
          "Status": "fixed",
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://github.com/advisories/GHSA-7788-qqqq-wwww",
          "Title": "tar: traversare de cale la despachetare",
          "Severity": "MEDIUM",
          "CVSS": {"ghsa": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "V3Score": 6.5}}
        }
      ]
    }
  ]
}
""".replace("IMAGE_ID", IMG_NGINX)
   .replace("DIFF_ID", DIFF_ID)
   .replace("REPO_DIGEST", REPO_DIGEST))

CLEAN = {"SchemaVersion": 2, "ArtifactName": IMG_APP, "ArtifactType": "container_image",
         "Metadata": {"ImageID": f"sha256:{IMG_APP}", "OS": {"Family": "alpine", "Name": "3.20"},
                      "RepoTags": ["app:latest"]},
         "Results": None}


def _by_id(items):
    return {i["raw"]["vulnerability_id"]: i for i in items}


# --------------------------------------------------------------------------
# Parsarea: forma reală a ieșirii `trivy image`
# --------------------------------------------------------------------------
def test_a_real_image_report_yields_the_columns_the_dashboard_shows() -> None:
    """Un parser probat pe un obiect inventat raportează zero pe gazdă.

    Eșecul pe care îl previne: `trivy image` scrie un raport cu `Metadata` și cu
    două clase de rezultate (`os-pkgs` și `lang-pkgs`) pe care `trivy fs` nu le
    are. Un parser care nu le potrivește întoarce listă goală, iar zero constatări
    despre nouă containere e citit ca „nimic în neregulă" — și, mai rău,
    `mark_resolved_absent` închide tot ce raportase rularea de ieri.
    """
    items = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX,
                              containers=("web", "web-2"))
    assert len(items) == 3, [i["title"] for i in items]
    byid = _by_id(items)

    v = byid["CVE-2026-4001"]
    assert v["cve"] == "CVE-2026-4001" and v["advisory_id"] is None
    assert v["package"] == "libxml2"
    assert v["installed_version"] == "2.9.14+dfsg-1.3~deb12u1"
    assert v["fixed_version"] == "2.9.14+dfsg-1.3~deb12u2"
    assert v["severity"] == "high"
    assert v["ecosystem"] == "deb"
    assert v["location"] == "nginx:1.27"
    # Scorul și vectorul din ACELAȘI furnizor (NVD, nu 9.8 lângă vectorul Red Hat).
    assert v["cvss"] == 9.8 and v["cvss_vector"].endswith("C:H/I:H/A:H")
    assert v["raw"]["image_id"] == f"sha256:{IMG_NGINX}"
    assert v["raw"]["image_os"] == "debian 12.11"
    assert v["raw"]["containers"] == ["web", "web-2"]

    # Fără fix publicat: None, nu "" — planificatorul cere o versiune țintă.
    assert byid["CVE-2026-4002"]["fixed_version"] is None
    # UNKNOWN nu e „neglijabil": rămâne `medium`, cu steagul care spune că nu s-a
    # știut. Vezi `trivy_fs.map_severity`.
    assert byid["CVE-2026-4002"]["severity"] == "medium"
    assert byid["CVE-2026-4002"]["raw"]["severity_known"] is False

    g = byid["GHSA-7788-qqqq-wwww"]
    assert g["cve"] is None and g["advisory_id"] == "GHSA-7788-qqqq-wwww"
    assert g["ecosystem"] == "npm"
    assert g["raw"]["pkg_path"] == "usr/src/app/node_modules/tar/package.json"
    # Calea rămâne în `raw`, dar `location` e imaginea: reparația e o singură
    # reconstrucție, nu una per fișier.
    assert g["location"] == "nginx:1.27"


def test_the_packages_of_the_image_distro_are_reported_here() -> None:
    """`trivy_fs` refuză pachetele de sistem; aici ele sunt singura sursă.

    Eșecul pe care îl previne: cineva citește docstring-ul lui `trivy_fs` („trivy
    nu are voie să raporteze pachete de sistem, dnf o face mai bine"), aplică
    regula și aici, și filtrează `Class: os-pkgs`. Dar dnf vede GAZDA; libxml2 din
    imaginea debian a containerului nu e văzut de nimeni altcineva pe mașina asta.
    Filtrată, o vulnerabilitate care rulează chiar acum devine invizibilă.
    """
    items = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX)
    clase = {i["raw"]["class"] for i in items}
    assert "os-pkgs" in clase and "lang-pkgs" in clase, clase
    assert _by_id(items)["CVE-2026-4001"]["package"] == "libxml2"


def test_a_clean_image_is_neither_an_error_nor_a_finding() -> None:
    """`"Results": null` e o imagine curată, nu un raport stricat.

    Eșecul pe care îl previne: un parser care cere o listă și crapă pe `null` face
    ca o imagine fără vulnerabilități să oprească toată rularea — deci imaginile
    de după ea nu se mai scanează și constatările lor se închid.
    """
    assert trivy_image.parse(CLEAN, reference="app:latest", image_id=IMG_APP) == []
    assert trivy_image.parse({"SchemaVersion": 2}, reference="x", image_id=IMG_APP) == []


# --------------------------------------------------------------------------
# Cheia de identitate: imaginea, nu containerul, nu digestul
# --------------------------------------------------------------------------
def test_the_key_does_not_depend_on_which_containers_run_the_image() -> None:
    """Un `docker compose up` nu are voie să rescrie istoricul unei constatări.

    Eșecul pe care îl previne: dacă numele containerului ar intra în cheie,
    fiecare repornire (containerele se recreează, nu se repornesc, la `compose
    up`) ar închide constatarea veche și ar deschide una nouă. „De cât timp e
    deschisă asta" — singura metrică de vulnerabilități care contează, și motivul
    pentru care există `finding_key` — s-ar reseta la fiecare deploy, iar canalul
    de Telegram ar anunța aceleași CVE-uri ca fiind noi.
    """
    a = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX,
                          containers=("web-1",))
    b = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX,
                          containers=("web-9f2c", "web-aa31"))
    assert {i["finding_key"] for i in a} == {i["finding_key"] for i in b}
    assert a[0]["raw"]["containers"] != b[0]["raw"]["containers"], (
        "containerele trebuie totuși raportate — informativ, nu în cheie"
    )


def test_a_rebuilt_image_under_the_same_tag_keeps_its_history() -> None:
    """Cheia e tagul, nu digestul, tocmai ca reconstrucția să nu reseteze nimic.

    Eșecul pe care îl previne: cu digestul în cheie, fiecare `docker build` ar
    rezolva toate constatările imaginii și ar deschide altele identice. Panoul ar
    arăta „reparate azi-noapte" pentru vulnerabilități care sunt încă acolo, iar
    vechimea lor — cifra pe care operatorul o folosește ca să prioritizeze — ar
    porni de la zero de fiecare dată.
    """
    vechi = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX)
    nou = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_APP)
    assert {i["finding_key"] for i in vechi} == {i["finding_key"] for i in nou}
    assert nou[0]["raw"]["image_id"] == f"sha256:{IMG_APP}", (
        "digestul trebuie să se vadă în `raw`, ca să se poată lega constatarea "
        "de conținutul exact"
    )


def test_a_container_restarted_onto_another_image_gets_another_key() -> None:
    """Repornit pe `nginx:1.28`, containerul nu mai are vulnerabilitățile lui 1.27.

    Eșecul pe care îl previne: dacă cheia n-ar depinde de imagine, constatările
    versiunii vechi ar rămâne lipite de container și ar fi raportate la infinit
    pentru un conținut care nu mai rulează — operatorul ar căuta un pachet care nu
    mai e acolo. Cu imaginea în cheie, cele vechi ies din rularea următoare și
    `mark_resolved_absent` le închide, ceea ce e adevărat: nu mai rulează.
    """
    vechi = trivy_image.parse(SAMPLE, reference="nginx:1.27", image_id=IMG_NGINX)
    nou = trivy_image.parse(SAMPLE, reference="nginx:1.28", image_id=IMG_NGINX)
    assert not ({i["finding_key"] for i in vechi} & {i["finding_key"] for i in nou})


def test_the_same_cve_in_five_images_is_five_findings() -> None:
    """Cinci imagini sunt cinci reconstrucții, deci cinci lucruri de făcut.

    Eșecul pe care îl previne: pliate într-un singur rând, cele cinci ar dispărea
    din panou în clipa în care PRIMA e reparată — celelalte patru ar rula mai
    departe, vulnerabile și invizibile. Iar operatorul n-ar avea de unde ști pe
    care dintre imagini să o reconstruiască.
    """
    imagini = ["nginx:1.27", "app:2.3", "redis:7", "worker:latest", "cron:1.0"]
    chei = set()
    for ref in imagini:
        for item in trivy_image.parse(SAMPLE, reference=ref, image_id=IMG_NGINX):
            if item["cve"] == "CVE-2026-4001":
                chei.add(item["finding_key"])
                assert item["location"] == ref, (
                    "constatarea trebuie să spună CARE imagine, altfel cele cinci "
                    "rânduri nu se pot deosebi în panou"
                )
    assert len(chei) == 5, chei


def test_the_key_is_the_one_the_repository_computes() -> None:
    """Cheia se calculează cu `fx.finding_key`, nu cu o formulă paralelă.

    Eșecul pe care îl previne: o a doua formulă aici ar diverge tăcut de cea din
    `sentinel/db/repo/findings.py` (de exemplu la ordinea câmpurilor), iar
    `mark_resolved_absent` — care compară chei — ar închide în fiecare noapte tot
    ce tocmai s-a ingerat, apoi l-ar redeschide. Fiecare rulare ar anunța aceleași
    vulnerabilități ca fiind noi.
    """
    item = _by_id(trivy_image.parse(SAMPLE, reference="nginx:1.27",
                                    image_id=IMG_NGINX))["CVE-2026-4001"]
    assert item["finding_key"] == fx.finding_key(
        "trivy_image", None, "libxml2", "CVE-2026-4001", "nginx:1.27")


# --------------------------------------------------------------------------
# Raportul trebuie să spună despre CE imagine e
# --------------------------------------------------------------------------
def test_a_report_about_another_image_is_refused() -> None:
    """Cod de ieșire 0 nu dovedește că s-a scanat imaginea cerută.

    Eșecul pe care îl previne: trivy rezolvă referința altundeva (registry,
    containerd) și raportează despre ALTĂ imagine. Constatările ar fi ingerate pe
    seama containerului care rulează la noi — corecte despre ceva, false despre
    gazda asta — iar operatorul ar reconstrui o imagine care n-are problema.
    """
    assert trivy_image.identity_mismatch(SAMPLE, IMG_NGINX) is None
    motiv = trivy_image.identity_mismatch(SAMPLE, IMG_APP)
    assert motiv and IMG_APP[:12] in motiv


def test_a_report_that_does_not_say_what_it_scanned_is_refused() -> None:
    """„Nu știu ce am scanat" nu e „am scanat ce trebuia".

    Eșecul pe care îl previne: dacă lipsa identității ar trece, verificarea de mai
    sus s-ar putea dezarma singură — orice schimbare de formă a ieșirii lui trivy
    care scoate `Metadata` ar transforma poarta într-o operație nulă, tăcut. Așa
    se strică în schimb zgomotos, cu un rând `failed`.
    """
    orb = {"SchemaVersion": 2, "Results": []}
    motiv = trivy_image.identity_mismatch(orb, IMG_NGINX)
    assert motiv and "nu spune ce imagine" in motiv


def test_the_artifact_name_alone_proves_the_identity() -> None:
    """Două surse de identitate, ca una singură să nu fie un punct unic de eșec.

    Eșecul pe care îl previne: dacă am cere doar `Metadata.ImageID`, o versiune de
    trivy care mută câmpul ar face scanarea de containere să eșueze în fiecare
    noapte pe o gazdă perfect sănătoasă — o alarmă falsă permanentă, adică exact
    genul de zgomot după care operatorul nu mai citește panoul.
    """
    doar_nume = {"SchemaVersion": 2, "ArtifactName": IMG_NGINX, "Results": []}
    assert trivy_image.identity_mismatch(doar_nume, IMG_NGINX) is None
    doar_meta = {"SchemaVersion": 2, "Metadata": {"ImageID": f"sha256:{IMG_NGINX}"}}
    assert trivy_image.identity_mismatch(doar_meta, IMG_NGINX) is None


# --------------------------------------------------------------------------
# Comanda
# --------------------------------------------------------------------------
def test_the_command_pins_the_image_source_to_the_local_daemon() -> None:
    """Fără `--image-src docker`, trivy poate scana o imagine din registry.

    Eșecul pe care îl previne: lanțul implicit al lui trivy e docker → containerd
    → podman → **remote**. Pe o gazdă unde socketul nu e accesibil, ultima verigă
    ar reuși: ar trage imaginea din registry și ar raporta despre ea. Rezultatul
    ar fi un panou plin de constatări despre un conținut care nu rulează aici —
    și, mai rău, o scanare care pare să meargă tocmai când permisiunea lipsește.
    """
    argv = trivy_image.build_argv(IMG_NGINX, "/tmp/x.json", TRIVY)
    assert argv[argv.index("--image-src") + 1] == "docker"


def test_the_command_scans_the_running_id_and_writes_json_to_a_file() -> None:
    """Se scanează conținutul care rulează, iar raportul nu trece prin stdout.

    Eșecul pe care îl previne (două, de fapt): dacă s-ar da tagul, un `docker
    pull` fără repornire ar face să se scaneze alt conținut decât cel care
    rulează; iar dacă raportul ar veni pe stdout, mărimea lui n-ar mai putea fi
    verificată cu `stat` ÎNAINTE să fie citită în proces — sub `MemoryMax=1G`,
    citirea ca să afli cât e de mare anulează verificarea.
    """
    argv = trivy_image.build_argv(IMG_NGINX, "/tmp/x.json", TRIVY)
    assert argv[-1] == IMG_NGINX and argv[-2] == "--"
    assert "image" in argv and "fs" not in argv and "rootfs" not in argv
    assert argv[argv.index("--format") + 1] == "json"
    assert argv[argv.index("--output") + 1] == "/tmp/x.json"
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert argv[argv.index("--cache-dir") + 1] == trivy_fs.CACHE_DIR, (
        "altă bază de vulnerabilități decât a lui trivy_fs ar însemna două "
        "vechimi diferite pentru aceeași gazdă"
    )
    assert argv[argv.index("--severity") + 1] == ",".join(trivy_image.SEVERITIES)


# --------------------------------------------------------------------------
# Pragul de severitate: al imaginilor, nu al fișierelor
# --------------------------------------------------------------------------
def test_the_image_floor_is_high_and_the_filesystem_one_stays_medium() -> None:
    """Cele două scanere NU au voie să împartă din nou o singură listă.

    Eșecul pe care îl previne, în amândouă direcțiile — și fiecare a fost trăit
    sau e la o linie distanță:

    * lipite pe valoarea lui `trivy_fs` (MEDIUM), scanarea de imagini se întoarce
      la 2838 de constatări (măsurate pe 29 august 2026, șase imagini). Atunci
      plafonul era 2500 și un refuz al întregii rulări, deci scanarea nu mai
      raporta NIMIC despre containere — `scan:last:trivy_image` roșu în
      `/selfcheck`. Cu bugetul de azi, pe imagine, 2838 ar încăpea; pragul rămâne
      la HIGH pentru că el e maneta pentru zgomotul din panou, nu plafonul;
    * lipite pe valoarea de aici (HIGH), scanarea de FIȘIERE tace despre
      constatările ei medii fără ca cineva să fi cerut asta: 92 de constatări azi,
      nicăieri lângă plafonul ei, deci ridicarea n-ar repara nimic și ar ascunde
      ceva. Operatorul a cerut pragul pentru imagini.
    """
    imagini = trivy_image.build_argv(IMG_NGINX, "/tmp/x.json", TRIVY)
    ceruta = imagini[imagini.index("--severity") + 1].split(",")
    assert "HIGH" in ceruta and "CRITICAL" in ceruta
    assert "MEDIUM" not in ceruta, (
        f"scanarea de imagini cere din nou MEDIUM: {ceruta} — pragul HIGH e "
        f"maneta pentru zgomotul din panou (MEDIUM a însemnat 2838 de "
        f"constatări pe șase imagini, pe 29 august 2026)")

    fisiere = trivy_fs.build_argv("/opt", "/tmp/y.json", TRIVY)
    ale_fisierelor = fisiere[fisiere.index("--severity") + 1].split(",")
    assert "MEDIUM" in ale_fisierelor, (
        f"scanarea de fișiere a pierdut MEDIUM: {ale_fisierelor} — nimeni n-a "
        f"cerut asta, iar constatările ei medii ar dispărea tăcut")

    # Și deosebirea în sine, nu doar valorile de azi: dacă cineva le unește iar
    # printr-un alias, aserțiunile de sus pot rămâne adevărate o vreme.
    assert trivy_image.SEVERITIES is not trivy_fs.SEVERITIES
    assert set(trivy_image.SEVERITIES) != set(trivy_fs.SEVERITIES)


def test_the_image_floor_still_asks_for_the_unscored_ones() -> None:
    """„Nu știu" nu are voie să cadă odată cu „nu contează".

    Eșecul pe care îl previne: `UNKNOWN` scos din listă odată cu MEDIUM. O
    vulnerabilitate căreia niciun furnizor nu i-a dat încă o notă nu e una mică —
    e una neevaluată, și dispărută din filtru dispare fără urmă, fix schimbul pe
    care `trivy_fs.map_severity` există ca să-l refuze. Operatorul a ridicat
    pragul; `UNKNOWN` nu e sub HIGH, e în afara scării.
    """
    argv = trivy_image.build_argv(IMG_NGINX, "/tmp/x.json", TRIVY)
    assert "UNKNOWN" in argv[argv.index("--severity") + 1].split(",")


def test_what_a_run_can_see_is_derived_from_what_it_asked_for() -> None:
    """Garda de rezolvare trebuie să urmeze pragul, nu o copie a lui.

    Eșecul pe care îl previne: mulțimea „ce poate vedea rularea" scrisă de mână a
    doua oară. La prima schimbare de prag lista rămâne în urmă, iar
    `mark_resolved_absent` închide exact constatările pe care noua rulare nu le
    mai poate vedea — adică tocmai ce garda e pusă să oprească, tăcut.
    """
    vazute, nenotate = trivy_image.visible_severities()
    assert set(vazute) == {"high", "critical"}
    assert nenotate is True, (
        "cu UNKNOWN în prag, constatările nenotate (parcate la `medium` cu "
        "`severity_known=false`) sunt vizibile și pot fi închise")
    assert "medium" not in vazute, (
        "un MEDIUM măsurat ar putea fi închis de o rulare care nu-l mai caută")


def test_the_visible_set_follows_a_changed_floor(monkeypatch) -> None:
    """Derivarea se probează schimbând pragul, nu citind valorile de azi.

    Eșecul pe care îl previne: testul de mai sus trece și peste o listă scrisă de
    mână, atâta timp cât cifrele coincid azi. Aici pragul se mută sub el.
    """
    monkeypatch.setattr(trivy_image, "SEVERITIES", ("MEDIUM", "HIGH", "CRITICAL"))
    vazute, nenotate = trivy_image.visible_severities()
    assert set(vazute) == {"medium", "high", "critical"}
    assert nenotate is False, (
        "fără UNKNOWN în prag, o rulare nu mai poate vedea constatările nenotate")


def test_trivy_gets_a_shorter_deadline_than_the_one_we_enforce() -> None:
    """Cine cade primul decide ce scrie în `scans.error`.

    Eșecul pe care îl previne: cu plafonul nostru mai mic, îl omorâm noi și pe
    rând rămâne doar „timeout" — fără imagine, fără motiv. Cu al lui mai mic,
    trivy se oprește singur și scrie de ce.
    """
    argv = trivy_image.build_argv(IMG_NGINX, "/tmp/x.json", TRIVY)
    cerut = argv[argv.index("--timeout") + 1]
    assert cerut.endswith("s") and int(cerut[:-1]) == trivy_image.TRIVY_TIMEOUT_S
    assert trivy_image.TRIVY_TIMEOUT_S + trivy_image.TRIVY_GRACE_S <= trivy_image.TIMEOUT_S


def test_every_scanner_ceiling_fits_inside_the_unit_budget() -> None:
    """Al patrulea scaner intră în sumă fără ca cineva să-și amintească.

    Eșecul pe care îl previne: `sentinel-scan.service` are `TimeoutStartSec`, iar
    systemd omoară TOATĂ unitatea la el. Un scaner adăugat fără să se recalculeze
    suma face ca ultimul din listă să nu apuce să ruleze — și, mai rău, rândul
    `running` rămas în urmă umbrește ultimul rezultat real în panou.

    Modulele se descoperă, nu se enumeră: o listă scrisă de mână se strică exact
    în runda în care contează, fiindcă cine adaugă scanerul nu știe că testul
    există. Iar lista descoperită se verifică să nu fie goală — o listă
    parametrizată ieșită goală și sărită tăcut e deja unul dintre eșecurile
    plătite cu o pană în repository-ul ăsta.
    """
    import importlib

    modules = []
    for path in sorted((ROOT / "sentinel" / "scan").glob("*.py")):
        if path.name.startswith("_"):
            continue
        mod = importlib.import_module(f"sentinel.scan.{path.stem}")
        if isinstance(getattr(mod, "TIMEOUT_S", None), int):
            modules.append(mod)

    nume = sorted(m.__name__ for m in modules)
    assert len(modules) >= 3, (
        f"s-au găsit doar {nume}; descoperirea nu mai vede scanerele, deci "
        f"testul ar trece oricât ar fi bugetul"
    )
    assert "sentinel.scan.trivy_image" in nume, nume

    valori = re.findall(r"^TimeoutStartSec=(\d+)\s*$",
                        UNIT.read_text(encoding="utf-8"), re.M)
    assert len(valori) == 1, valori
    suma = sum(m.TIMEOUT_S for m in modules)
    assert suma < int(valori[0]), (
        f"plafoanele scanerelor ({nume}) însumează {suma}s, iar unitatea e "
        f"omorâtă la {valori[0]}s: ultimul din listă poate să nu apuce să ruleze"
    )


# --------------------------------------------------------------------------
# Cele două stări ale lui docker
# --------------------------------------------------------------------------
def _fara_docker(monkeypatch, tmp_path):
    monkeypatch.setattr(trivy_image, "DOCKER_BINARY", str(tmp_path / "nu-exista"))
    monkeypatch.setattr(trivy_image.shutil, "which", lambda _n: None)
    monkeypatch.setattr(trivy_image, "SOCKET_PATHS",
                        (str(tmp_path / "a.sock"), str(tmp_path / "b.sock")))
    monkeypatch.delenv("DOCKER_HOST", raising=False)


def test_a_host_without_docker_is_not_an_error(monkeypatch, tmp_path) -> None:
    """VM-ul de test n-are docker. Aia e o gazdă fără containere, nu o pană.

    Eșecul pe care îl previne: tratată ca eroare, fiecare gazdă fără docker ar
    avea permanent o cheie roșie în `/selfcheck` pentru un scaner care n-are ce
    scana. Un panou roșu care nu poate fi făcut verde e un panou pe care nimeni
    nu-l mai citește — și atunci se pierde și alarma care conta.
    """
    _fara_docker(monkeypatch, tmp_path)
    proba = run(trivy_image.probe_docker())
    assert proba.state == trivy_image.DOCKER_ABSENT
    assert "Nu e o eroare" in proba.detail

    items, eroare, fapte = run(trivy_image.scan())
    assert items == [] and eroare is None
    assert fapte["docker"] == trivy_image.DOCKER_ABSENT


def test_a_socket_without_a_client_is_not_an_absent_host(monkeypatch, tmp_path) -> None:
    """Docker rulează pe gazdă și noi nu-l putem interoga — asta e o eroare.

    Eșecul pe care îl previne: dacă absența s-ar decide DOAR după binar, o gazdă
    cu containere pornite dar fără clientul `docker` în PATH-ul serviciului ar fi
    raportată drept „gazdă fără containere". Nouă containere vulnerabile ar
    dispărea din sistem în tăcere, sub o stare care spune explicit că e normală.
    """
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(trivy_image, "DOCKER_BINARY", str(tmp_path / "nu-exista"))
    monkeypatch.setattr(trivy_image.shutil, "which", lambda _n: None)
    monkeypatch.setattr(trivy_image, "SOCKET_PATHS", (str(sock),))
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    proba = run(trivy_image.probe_docker())
    assert proba.state == trivy_image.DOCKER_UNREACHABLE
    assert str(sock) in proba.detail


def test_docker_host_alone_is_not_an_absent_host(monkeypatch, tmp_path) -> None:
    """Configurația spune că există un docker; nu avem voie să declarăm absența.

    Eșecul pe care îl previne: același tipar care a costat deja o rundă în
    repository-ul ăsta, în cealaltă direcție — o regulă care se încrede doar în
    filesystem. Cu `DOCKER_HOST` setat, socketul local poate lipsi în mod legitim,
    iar „nu există niciun socket" nu mai dovedește nimic.
    """
    _fara_docker(monkeypatch, tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.9:2376")
    proba = run(trivy_image.probe_docker())
    assert proba.state == trivy_image.DOCKER_UNREACHABLE


def test_the_daemon_must_answer_not_just_the_client(monkeypatch, tmp_path) -> None:
    """„Comanda a ieșit cu 0" nu e „am vorbit cu daemonul".

    Eșecul pe care îl previne, tiparul-casă din CLAUDE.md: `docker version` fără
    format iese cu 0 și tipărește blocul CLIENTULUI chiar și când serverul nu
    răspunde. O poartă construită pe codul de ieșire ar fi trecut mereu, iar
    scanarea ar fi mers mai departe ca să întoarcă zero constatări dintr-un motiv
    care n-are nimic de-a face cu gazda.
    """
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(trivy_image, "SOCKET_PATHS", (str(sock),))
    monkeypatch.setattr(trivy_image, "resolve_docker", lambda: DOCKER)

    async def client_gol(argv, timeout=None):
        # Cod 0, ieșire goală: exact ce se întâmplă când `{{.Server.Version}}` nu
        # are ce să interpoleze.
        return 0, "\n", ""

    monkeypatch.setattr(trivy_fs, "_run", client_gol)
    proba = run(trivy_image.probe_docker())
    assert proba.state == trivy_image.DOCKER_UNREACHABLE


def test_a_socket_we_cannot_reach_names_the_group_that_owns_it(
        monkeypatch, tmp_path) -> None:
    """Mesajul trebuie să spună CE să repare, nu doar că nu merge.

    Eșecul pe care îl previne, cel mai important din fișier: `scan.containers:
    true` pe o gazdă unde `sentinel` nu e în grupul `docker`. Mesajul lui docker
    („permission denied") spune că nu se poate, nu de ce. Iar capcana de după e
    `usermod -aG`, care NU schimbă un proces deja pornit: operatorul adaugă
    grupul, vede `id sentinel` corect, și scanarea eșuează în continuare în
    fiecare noapte. De asta detaliul poartă și faptele socketului, și avertismentul
    despre verificarea efectului.
    """
    sock = tmp_path / "docker.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(trivy_image, "SOCKET_PATHS", (str(sock),))
    monkeypatch.setattr(trivy_image, "resolve_docker", lambda: DOCKER)

    async def refuzat(argv, timeout=None):
        return 1, "", ("permission denied while trying to connect to the Docker "
                       "daemon socket at unix:///run/docker.sock")

    monkeypatch.setattr(trivy_fs, "_run", refuzat)
    proba = run(trivy_image.probe_docker())

    assert proba.state == trivy_image.DOCKER_UNREACHABLE
    assert "permission denied" in proba.detail, "motivul lui docker s-a pierdut"
    assert str(sock) in proba.detail, "socketul nu e numit în mesaj"
    # Faptele, nu doar calea: fără ele mesajul spune CĂ nu se poate, nu de ce, iar
    # operatorul nu poate deosebi „lipsește grupul" de „mount read-only sub
    # `ProtectSystem=strict`". Calea singură apare și în mesajul de rezervă, deci
    # o aserțiune pe ea ar trece și cu faptele scoase.
    assert "scriibil de noi" in proba.detail, (
        f"faptele socketului lipsesc din mesaj: {proba.detail}")
    assert "mod 0" in proba.detail, "modul socketului lipsește din mesaj"
    assert "nu există" not in proba.detail, (
        "mesajul spune că socketul nu există, deși tocmai l-a citit")
    assert "sudo -u sentinel docker version" in proba.detail, (
        "mesajul nu spune cum se verifică EFECTUL adăugării în grup"
    )
    assert "id sentinel" in proba.detail


def test_an_unreachable_docker_is_an_error_and_not_zero_findings(
        monkeypatch, tmp_path) -> None:
    """Cerută și nefăcută, scanarea trebuie să țipe.

    Eșecul pe care îl previne, scris direct în CLAUDE.md: scanerul întoarce listă
    goală fără eroare, orchestratorul o ia drept rezultat, `mark_resolved_absent`
    închide tot ce raportase ieri, iar panoul trece pe verde exact fiindcă
    permisiunea lipsește.
    """
    proba = trivy_image.DockerProbe(trivy_image.DOCKER_UNREACHABLE,
                                    "socketul nu răspunde", DOCKER)
    items, eroare, fapte = run(trivy_image.scan(proba))
    assert items == []
    assert eroare == "socketul nu răspunde"
    assert fapte["docker"] == trivy_image.DOCKER_UNREACHABLE


def test_the_binary_gate_and_the_command_name_the_same_docker(
        monkeypatch, tmp_path) -> None:
    """Ce a trecut de poarta „e instalat" e ce se și execută."""
    altundeva = tmp_path / "docker"
    altundeva.write_text("binar fals", encoding="utf-8")
    monkeypatch.setattr(trivy_image, "DOCKER_BINARY", str(tmp_path / "nicaieri"))
    monkeypatch.setattr(trivy_image.shutil, "which", lambda _n: str(altundeva))
    assert trivy_image.resolve_docker() == str(altundeva)


# --------------------------------------------------------------------------
# Enumerarea: ce rulează, o singură dată per imagine
# --------------------------------------------------------------------------
class Fake:
    """Ține locul proceselor `docker` și `trivy`. Nu asertează nimic singur."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.docker_version = (0, "28.2.2\n", "")
        self.ps = (0, "", "")
        self.inspect = (0, "", "")
        self.trivy_rc = 0
        self.trivy_err = ""
        self.reports: dict[str, dict] = {}
        self.db_age_h = 1.0
        self.on_image = None

    def containers(self, rows) -> None:
        """`rows` = [(cid, image_id, referință, nume)]."""
        self.ps = (0, "\n".join(r[0] for r in rows) + "\n", "")
        self.inspect = (0, "\n".join(
            f"{cid}\tsha256:{img}\t{ref}\t/{name}" for cid, img, ref, name in rows) + "\n", "")

    async def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        if argv[0] == DOCKER:
            return {"version": self.docker_version, "ps": self.ps,
                    "inspect": self.inspect}[argv[1]]
        if "version" in argv:
            updated = datetime.now(timezone.utc) - timedelta(hours=self.db_age_h)
            return 0, json.dumps({"Version": "0.74.0", "VulnerabilityDB": {
                "Version": 2,
                "UpdatedAt": updated.strftime("%Y-%m-%dT%H:%M:%SZ")}}), ""
        image = argv[-1]
        if self.on_image is not None:
            self.on_image(image)
        payload = self.reports.get(image, self.reports.get("*"))
        if payload is not None:
            with open(argv[argv.index("--output") + 1], "w",
                      encoding="utf-8", newline="") as fh:
                json.dump(payload, fh)
        rc = self.trivy_rc(image) if callable(self.trivy_rc) else self.trivy_rc
        return rc, "", self.trivy_err


@pytest.fixture()
def gazda(monkeypatch):
    """O gazdă cu docker accesibil și trivy instalat."""
    fake = Fake()
    monkeypatch.setattr(trivy_fs, "_run", fake)
    monkeypatch.setattr(trivy_image, "resolve_docker", lambda: DOCKER)
    monkeypatch.setattr(trivy_fs, "resolve_binary", lambda: TRIVY)
    return fake


def test_only_the_images_of_running_containers_are_scanned(gazda) -> None:
    """Imaginile nefolosite sunt vulnerabilități pe care nimeni nu le execută.

    Eșecul pe care îl previne: `docker images` listează și resturile de build, și
    tagul anterior al fiecărei imagini. Raportate, ele umplu panoul cu zeci de
    constatări pe care nu le atinge niciun proces — iar un panou plin de ce nu
    contează e unul pe care operatorul încetează să-l citească, ceea ce îngroapă
    și constatările care contează.
    """
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    items, eroare, fapte = run(trivy_image.scan())

    assert eroare is None and len(items) == 3
    assert fapte["images"] == 1 and fapte["containers"] == 1
    subcomenzi = [c[1] for c in gazda.calls if c[0] == DOCKER]
    assert "images" not in subcomenzi, (
        f"s-a enumerat inventarul de imagini, nu doar ce rulează: {subcomenzi}")
    assert subcomenzi == ["version", "ps", "inspect"]


def test_two_containers_on_one_image_are_scanned_once(gazda) -> None:
    """Nouă containere pot fi șase imagini, și șase reconstrucții.

    Eșecul pe care îl previne: o scanare per container ar plăti de nouă ori
    bugetul de timp pentru șase răspunsuri, iar sub `TimeoutStartSec` comun asta
    e diferența dintre o rulare care se încheie și una omorâtă la mijloc.
    """
    gazda.containers([
        ("a" * 64, IMG_NGINX, "nginx:1.27", "web-1"),
        ("b" * 64, IMG_NGINX, "nginx:1.27", "web-2"),
        ("c" * 64, IMG_APP, "app:2.3", "app-1"),
    ])
    gazda.reports = {IMG_NGINX: SAMPLE, IMG_APP: CLEAN}
    items, eroare, fapte = run(trivy_image.scan())

    assert eroare is None
    scanate = [c[-1] for c in gazda.calls if "image" in c and c[0] == TRIVY]
    assert sorted(scanate) == sorted([IMG_APP, IMG_NGINX]), scanate
    assert fapte["images"] == 2 and fapte["containers"] == 3
    assert {i["location"] for i in items} == {"nginx:1.27"}


def test_the_reference_does_not_depend_on_the_order_docker_lists_them(gazda) -> None:
    """Ordinea lui `docker ps` nu are voie să decidă cheia unei constatări.

    Eșecul pe care îl previne: două containere pot numi aceeași imagine altfel
    (`nginx:1.27` și `docker.io/library/nginx:1.27`). Cu „primul văzut", o simplă
    repornire care schimbă ordinea listării ar muta constatările pe altă cheie —
    deci vechea cheie ar fi închisă ca rezolvată și una nouă ar fi anunțată pe
    Telegram, fără ca nimic pe gazdă să se fi schimbat.
    """
    a = trivy_image._display_reference(
        ["docker.io/library/nginx:1.27", "nginx:1.27"], IMG_NGINX)
    b = trivy_image._display_reference(
        ["nginx:1.27", "docker.io/library/nginx:1.27"], IMG_NGINX)
    assert a == b == "docker.io/library/nginx:1.27"
    # Fără niciun nume utilizabil rămâne digestul scurt — urât, dar stabil.
    assert trivy_image._display_reference([f"sha256:{IMG_NGINX}"], IMG_NGINX) == \
        f"sha256:{IMG_NGINX[:12]}"


def test_no_running_container_is_a_result_and_not_a_failure(gazda) -> None:
    """Ne-am uitat și nu rula nimic — asta e un răspuns, nu o imposibilitate.

    Eșecul pe care îl previne: dacă zero containere ar fi tratat ca eroare, o
    gazdă care tocmai și-a oprit stiva ar avea un rând `failed` în fiecare noapte
    pentru ceva ce nu e stricat. Și invers: aici NU se verifică nici trivy, nici
    vechimea bazei de vulnerabilități, fiindcă afirmația „nu rulează nimic" nu
    depinde de ele — un `failed` pentru o bază veche ar fi o alarmă falsă despre o
    scanare care n-avea ce să scaneze.
    """
    gazda.ps = (0, "\n", "")
    gazda.db_age_h = 24 * 90  # bază veche de trei luni, irelevantă aici
    items, eroare, fapte = run(trivy_image.scan())

    assert items == [] and eroare is None
    assert fapte["images"] == 0 and fapte["containers"] == 0
    assert [c[1] for c in gazda.calls if c[0] == DOCKER] == ["version", "ps"]


def test_a_container_that_stopped_mid_enumeration_does_not_fail_the_run(gazda) -> None:
    """Un container oprit între `ps` și `inspect` e chiar ce nu scanăm.

    Eșecul pe care îl previne: `docker inspect` iese cu 1 fiindcă unul dintre
    id-uri nu mai există, iar o regulă „cod diferit de zero = eroare" ar transforma
    o repornire obișnuită de container într-un rând `failed` — deci într-o noapte
    în care nu se scanează nimic, oricâte alte containere ar rula.
    """
    gazda.ps = (0, f"{'a' * 64}\n{'b' * 64}\n", "")
    gazda.inspect = (1, f"{'a' * 64}\tsha256:{IMG_NGINX}\tnginx:1.27\t/web\n",
                     "Error: No such container: bbbb")
    gazda.reports["*"] = SAMPLE
    items, eroare, fapte = run(trivy_image.scan())

    assert eroare is None and len(items) == 3
    assert fapte["images"] == 1


def test_inspect_failing_without_losing_a_container_is_an_error(gazda) -> None:
    """Un eșec care NU se explică prin containere dispărute rămâne un eșec.

    Eșecul pe care îl previne: dacă am ierta orice cod de ieșire al lui `docker
    inspect` de dragul cazului de mai sus, un daemon care începe să răspundă
    parțial ar produce liste incomplete acceptate ca întregi — și fiecare imagine
    lipsă și-ar vedea constatările închise ca rezolvate.
    """
    gazda.ps = (0, f"{'a' * 64}\n", "")
    gazda.inspect = (1, f"{'a' * 64}\tsha256:{IMG_NGINX}\tnginx:1.27\t/web\n",
                     "Error response from daemon: something else")
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "docker inspect" in eroare


def test_output_that_is_not_a_container_id_is_refused(gazda) -> None:
    """Nu construim o comandă dintr-o ieșire pe care n-o înțelegem.

    Eșecul pe care îl previne: `docker ps` care scrie un avertisment printre
    id-uri (o versiune de client care se plânge de API) ar face ca textul acela să
    ajungă argument pentru `docker inspect` și apoi pentru `trivy image`. În cel
    mai bun caz eșuează cu un mesaj de neînțeles; în cel mai rău, scanează
    altceva.
    """
    gazda.ps = (0, f"{'a' * 64}\nWARNING: API version mismatch\n", "")
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "nu sunt identificatori" in eroare


def test_docker_ps_failing_is_an_error_and_not_a_clean_host(gazda) -> None:
    """`docker ps` eșuat înseamnă că nu știm ce rulează."""
    gazda.ps = (1, "", "permission denied")
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "docker ps" in eroare


# --------------------------------------------------------------------------
# Plafoanele, ca refuz
# --------------------------------------------------------------------------
def test_too_many_images_are_refused_before_the_budget_is_spent(
        gazda, monkeypatch) -> None:
    """Un refuz în prima secundă, nu unul după a 3599-a.

    Eșecul pe care îl previne: pe o gazdă cu mult mai multe containere decât cea
    pentru care sunt calculate bugetele, scanarea ar consuma toată fereastra și
    s-ar tăia singură la termen — iar lista parțială rezultată ar face ca restul
    imaginilor să fie marcate rezolvate.
    """
    monkeypatch.setattr(trivy_image, "MAX_IMAGES", 2)
    gazda.containers([(f"{i:064x}", f"{i:064x}", f"img:{i}", f"c{i}")
                      for i in range(3)])
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "imagini unice" in eroare
    assert not [c for c in gazda.calls if c[0] == TRIVY], (
        "s-a cheltuit buget pe trivy deși plafonul era deja depășit")


def test_too_many_containers_are_refused(gazda, monkeypatch) -> None:
    """Plafonul de containere se aplică înainte de `docker inspect`."""
    monkeypatch.setattr(trivy_image, "MAX_CONTAINERS", 2)
    gazda.ps = (0, "\n".join(f"{i:064x}" for i in range(3)) + "\n", "")
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "peste plafonul" in eroare
    assert [c[1] for c in gazda.calls if c[0] == DOCKER] == ["version", "ps"]


def test_one_image_over_the_whole_budget_is_not_truncated_to_fit(
        gazda, monkeypatch) -> None:
    """O imagine peste tot bugetul nu se taie la buget; si fara ea nu ramane nimic.

    Eșecul pe care îl previne: 3000 de constatări tăiate la plafon ar fi urmate de
    `mark_resolved_absent`, care ar marca restul drept REZOLVATE. Panoul ar arăta
    mai puține vulnerabilități tocmai fiindcă sunt mai multe. Aici imaginea e
    SINGURA, deci rularea nu are ce preda: e un eșec cu numele imaginii, nu un
    `completed` cu zero constatări (minciuna din migrația 0029).
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 2)
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    items, eroare, fapte = run(trivy_image.scan())

    assert items == [], "constatările imaginii peste buget au fost ingerate (tăiate?)"
    assert eroare and "niciuna nu a putut fi ingerată" in eroare
    assert "nginx:1.27" in eroare and "3 constatări" in eroare, (
        f"eroarea nu numește imaginea și cât are: {eroare!r}")
    assert fapte["coverage"] is None, (
        "acoperirea e scrisă pe un drum de eroare, unde nu s-a ingerat nimic")


def test_the_budget_deadline_refuses_instead_of_ingesting_half(
        gazda, monkeypatch) -> None:
    """Bugetul epuizat oprește rularea; nu o predă pe jumătate.

    Eșecul pe care îl previne: cinci imagini din nouă ingerate ca și cum ar fi
    toate, urmate de `mark_resolved_absent`, care închide constatările celorlalte
    patru. Ele rulează mai departe, vulnerabile, iar panoul spune că s-au reparat.
    """
    monkeypatch.setattr(trivy_image, "TIMEOUT_S", 120)
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web"),
                      ("b" * 64, IMG_APP, "zz-app:2.3", "app")])
    gazda.reports = {IMG_NGINX: SAMPLE, IMG_APP: CLEAN}

    real = trivy_image.time.monotonic
    stare = {"sarit": False}

    def sari(image):
        # Prima imagine consumă tot bugetul; a doua nu mai are ce cheltui.
        if not stare["sarit"]:
            stare["sarit"] = True
            monkeypatch.setattr(trivy_image.time, "monotonic",
                                lambda: real() + 1000)

    gazda.on_image = sari
    items, eroare, _ = run(trivy_image.scan())

    assert items == []
    assert eroare and "bugetul de 120s s-a epuizat după 1/2 imagini" in eroare


def test_an_image_that_fails_stops_the_whole_run(gazda) -> None:
    """O imagine căzută nu are voie să lase restul să pară un rezultat întreg."""
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web"),
                      ("b" * 64, IMG_APP, "zz-app:2.3", "app")])
    gazda.reports = {IMG_NGINX: SAMPLE}
    gazda.trivy_rc = lambda image: 0 if image == IMG_NGINX else 1
    gazda.trivy_err = "FATAL unable to initialize a scanner"

    items, eroare, _ = run(trivy_image.scan())
    assert items == []
    assert eroare and "zz-app:2.3" in eroare and "unable to initialize" in eroare


def test_a_report_about_the_wrong_image_stops_the_run(gazda) -> None:
    """Verificarea de identitate e legată de `scan()`, nu doar declarată.

    Eșecul pe care îl previne: `identity_mismatch` scrisă și testată separat, dar
    neapelată din `scan()`. Ar fi o reparație pe hârtie — exact tiparul „constantă
    declarată și nefolosită" pentru care există deja un test în `trivy_fs`.
    """
    gazda.containers([("a" * 64, IMG_APP, "app:2.3", "app")])
    gazda.reports["*"] = SAMPLE  # raport despre IMG_NGINX, cerută IMG_APP
    items, eroare, _ = run(trivy_image.scan())
    assert items == []
    assert eroare and "nu e despre imaginea cerută" in eroare


def test_a_missing_trivy_is_an_error_when_there_are_images(gazda, monkeypatch) -> None:
    """Imagini care rulează și niciun scaner instalat nu e o gazdă curată.

    Eșecul pe care îl previne: pasul 21 n-a instalat trivy, scanerul întoarce o
    listă goală fără eroare, iar `mark_resolved_absent` închide constatările
    tuturor containerelor. Panoul trece pe verde fiindcă lipsește scanerul.
    """
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    monkeypatch.setattr(trivy_fs, "resolve_binary", lambda: None)
    items, eroare, _ = run(trivy_image.scan())
    assert items == [] and eroare and "trivy nu e instalat" in eroare


# --------------------------------------------------------------------------
# Baza de vulnerabilități — aceeași disciplină ca la `trivy_fs`
# --------------------------------------------------------------------------
def test_a_stale_database_refuses_to_produce_findings(gazda) -> None:
    """O bază veche de trei luni nu mai răspunde la întrebarea de azi.

    Eșecul pe care îl previne: gazda a pierdut ieșirea către ghcr.io, trivy merge
    mai departe cu ce are în cache și raportează vesel un rezultat care nu știe
    nimic despre ce s-a publicat între timp. „Nicio constatare nouă" încetează să
    fie o afirmație despre containere.
    """
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    gazda.db_age_h = 24 * 90
    items, eroare, fapte = run(trivy_image.scan())

    assert items == []
    assert eroare and "zile" in eroare
    assert fapte["db_version"], (
        "rândul `failed` trebuie să spună cu ce bază de date s-a lucrat")


def test_a_fresh_database_is_recorded_on_the_completed_row(gazda) -> None:
    """`scans.db_version` există în migrația 0003 tocmai pentru asta."""
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    _items, eroare, fapte = run(trivy_image.scan())
    assert eroare is None
    assert fapte["db_version"] and "trivy-db" in fapte["db_version"]


def test_the_database_is_checked_after_the_scan_not_before(gazda) -> None:
    """Scanarea e cea care împrospătează baza, deci vârsta se citește după.

    Eșecul pe care îl previne: verificată înainte, vârsta ar fi mereu a bazei
    dinaintea împrospătării — o gazdă sănătoasă ar fi raportată invechită în
    fiecare noapte, iar operatorul ar învăța să ignore avertismentul.
    """
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    run(trivy_image.scan())
    ordine = [c for c in gazda.calls if c[0] == TRIVY]
    versiuni = [i for i, c in enumerate(ordine) if "version" in c]
    imagini = [i for i, c in enumerate(ordine) if "image" in c]
    assert imagini and versiuni, ordine
    # NICIO citire a bazei înainte de scanare, nu doar „ultima e după": o
    # verificare strecurată la început ar raporta vârsta de dinainte de
    # împrospătare și ar face o gazdă sănătoasă să pară învechită în fiecare
    # noapte, chiar dacă mai există una corectă la sfârșit.
    assert min(versiuni) > max(imagini), (
        f"baza a fost citită înainte de a fi împrospătată de scanare: {ordine}")


# --------------------------------------------------------------------------
# Orchestratorul: rândul din `scans` și ce NU se rezolvă
# --------------------------------------------------------------------------
class _DB:
    """Ciot de bază care ține minte ce s-a scris. Nu asertează nimic singur.

    `sub_prag` e ce răspunde la interogarea care numără constatările rămase sub
    pragul de severitate — implicit zero, ca o bază fără istoric.
    """

    def __init__(self, sub_prag: int = 0, open_at_skipped: int = 0,
                 fail_upsert_after: int | None = None) -> None:
        self.scans: list[dict] = []
        self.finished: list[dict] = []
        self.upserted: list[dict] = []
        self.resolved: list[tuple] = []
        # SQL-ul și TOATE argumentele rezolvării, ca să poată fi văzută garda de
        # severitate, nu doar cele trei argumente vechi.
        self.resolve_calls: list[tuple] = []
        self.counted: list[tuple] = []
        self.sub_prag = sub_prag
        # Numaratoarea „cate au ramas deschise pe imaginile sarite" e o alta
        # interogare decat cea de sub prag; ordinea in care ruleaza fata de
        # rezolvare se aserteaza din `events`.
        self.open_at_skipped = open_at_skipped
        self.counted_at: list[tuple] = []
        self.events: list[str] = []
        self.fail_upsert_after = fail_upsert_after

    async def fetchval(self, sql, *args):
        if "INSERT INTO scans" in sql:
            self.scans.append({"scanner": args[0], "target": args[1],
                               "triggered_by": args[3]})
            return len(self.scans)
        if "SELECT count(*) FROM findings" in sql:
            if "location = ANY" in sql:
                self.events.append("count_at_skipped")
                self.counted_at.append((sql, args))
                return self.open_at_skipped
            self.counted.append((sql, args))
            return self.sub_prag
        return 0

    async def fetchrow(self, sql, *args):
        if (self.fail_upsert_after is not None
                and len(self.upserted) >= self.fail_upsert_after):
            raise RuntimeError("conexiunea cu baza a cazut la ingestie")
        self.upserted.append({"finding_key": args[0], "scanner": args[2],
                              "cve": args[3], "location": args[16]})
        return {"is_new": True, "status": "open"}

    async def fetch(self, sql, *args):
        if "SET status = 'resolved'" in sql:
            self.events.append("resolve")
            self.resolved.append((args[0], args[1], args[2]))
            self.resolve_calls.append((sql, args))
        return []

    async def execute(self, sql, *args):
        if "UPDATE scans SET" in sql:
            self.finished.append({"id": args[0], "status": args[1],
                                  "findings_count": args[2], "error": args[6],
                                  "db_version": args[7], "target": args[8],
                                  "sql": sql})


def _no_kev(monkeypatch):
    async def lookup(_db, _cves):
        return {}
    monkeypatch.setattr(orchestrator.kev, "lookup", lookup)


def _probe(monkeypatch, state, detail="detaliu"):
    async def probe():
        return trivy_image.DockerProbe(state, detail, DOCKER)
    monkeypatch.setattr(orchestrator.trivy_image, "probe_docker", probe)


def test_an_absent_docker_writes_no_scan_row_at_all(monkeypatch) -> None:
    """„0 constatări" despre o scanare care n-a rulat e minciuna din 0029.

    Eșecul pe care îl previne: un rând `completed` cu zero constatări pentru o
    gazdă fără docker. `check_last_scan` l-ar citi drept «ok | ultima rulare
    încheiată acum 1h, 0 constatări» — un panou verde peste o măsurătoare care nu
    s-a făcut niciodată. Migrația 0029 a scos `skipped` tocmai ca starea asta să
    nu poată fi reprezentată; consecința e că nu se scrie niciun rând.
    """
    _probe(monkeypatch, trivy_image.DOCKER_ABSENT, "docker nu e instalat")
    _no_kev(monkeypatch)
    db = _DB()
    out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["status"] == "not_applicable"
    assert db.scans == [], "s-a deschis un rând în `scans` pentru o gazdă fără docker"
    assert db.finished == [] and db.upserted == []
    assert db.resolved == [], (
        "o gazdă fără docker a închis constatări; absența unui runtime nu "
        "dovedește că vulnerabilitățile de ieri au dispărut")


def test_an_unreachable_docker_writes_a_failed_row_and_resolves_nothing(
        monkeypatch) -> None:
    """Cea mai importantă regulă a fișierului, la nivelul orchestratorului.

    Eșecul pe care îl previne: `sentinel` scos din grupul `docker` (sau serviciul
    nerepornit după ce a fost adăugat). Scanerul nu poate rula, iar dacă lipsa
    rezultatului ar fi tratată ca rezultat, toate constatările containerelor s-ar
    închide ca rezolvate în noaptea aia.
    """
    _probe(monkeypatch, trivy_image.DOCKER_UNREACHABLE,
           "permission denied la /run/docker.sock")
    _no_kev(monkeypatch)
    db = _DB()
    out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["status"] == "failed"
    assert db.resolved == [], "o scanare eșuată a rezolvat constatări"
    assert db.upserted == []
    (rand,) = db.finished
    assert rand["status"] == "failed"
    assert "permission denied" in rand["error"]
    (deschis,) = db.scans
    assert deschis["scanner"] == "trivy_image"
    assert deschis["triggered_by"] == "test"
    assert deschis["target"].startswith("docker: imaginile containerelor în rulare")


def test_a_completed_scan_ingests_and_closes_what_disappeared(monkeypatch) -> None:
    """Ce s-a văzut se ingerează; ce nu s-a mai văzut se închide — dar numai atunci.

    Eșecul pe care îl previne: mulțimea trimisă lui `mark_resolved_absent` nu e
    cea tocmai ingerată, deci rezolvarea ar închide chiar constatările pe care
    scanarea le-a văzut adineauri — iar rularea următoare le-ar redeschide și le-ar
    anunța ca noi pe Telegram, în fiecare noapte.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)

    async def merge(_probe):
        return (list(trivy_image.parse(SAMPLE, reference="nginx:1.27",
                                       image_id=IMG_NGINX)),
                None,
                {"db_version": "trivy-db v2 proaspătă", "images": 1,
                 "containers": 2, "references": ["nginx:1.27"]})

    monkeypatch.setattr(orchestrator.trivy_image, "scan", merge)
    db = _DB()
    out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["status"] == "completed" and out["findings"] == 3
    assert {u["scanner"] for u in db.upserted} == {"trivy_image"}
    assert {u["location"] for u in db.upserted} == {"nginx:1.27"}
    (scanner, asset_id, chei) = db.resolved[0]
    assert len(db.resolved) == 1 and scanner == "trivy_image" and asset_id is None
    assert set(chei) == {u["finding_key"] for u in db.upserted}
    (rand,) = db.finished
    assert rand["status"] == "completed"
    assert rand["db_version"] == "trivy-db v2 proaspătă"


def _merge_stub(monkeypatch, findings=None, facts=None):
    """`trivy_image.scan` înlocuit cu un rezultat gata făcut."""
    async def merge(_probe):
        return (list(findings if findings is not None
                     else trivy_image.parse(SAMPLE, reference="nginx:1.27",
                                            image_id=IMG_NGINX)),
                None,
                {"db_version": "trivy-db v2 proaspătă", "images": 1,
                 "containers": 2, "references": ["nginx:1.27"],
                 "severities": list(trivy_image.SEVERITIES), **(facts or {})})

    monkeypatch.setattr(orchestrator.trivy_image, "scan", merge)


def test_the_scan_row_says_at_what_threshold_it_looked(monkeypatch) -> None:
    """O scanare care se uită la mai puțin trebuie să SPUNĂ că se uită la mai puțin.

    Eșecul pe care îl previne: rândul din `scans` poartă „450 constatări" și
    nimic despre pragul la care au fost numărate. Citit ca stare a containerelor,
    numărul spune „atât au", când adevărul e „atât s-au căutat" — iar cele ~2388
    de constatări MEDIUM nu dispar de pe gazdă, doar din raport.

    Scris la DESCHIDEREA rândului, nu la încheiere, și de aceea se probează pe
    calea eșuată: rândul `failed` e chiar cel pe care se uită operatorul azi.
    """
    _probe(monkeypatch, trivy_image.DOCKER_UNREACHABLE, "permission denied")
    _no_kev(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_image(db, "test"))

    (deschis,) = db.scans
    assert trivy_image.severity_scope() in deschis["target"], (
        f"pragul nu e pe rândul din `scans`: {deschis['target']!r}")
    assert "HIGH" in deschis["target"] and "MEDIUM" not in deschis["target"]


def test_the_selfcheck_says_the_threshold_next_to_the_number(monkeypatch) -> None:
    """Cifra din `/selfcheck` nu are voie să circule fără domeniul ei.

    Eșecul pe care îl previne: «Scanarea „trivy_image" — ok, 450 constatări» pe
    Telegram. Operatorul citește „atâtea au containerele" și nu are de unde ști
    că MEDIUM nu s-a mai căutat de la ridicarea pragului. Absența unui semnal
    citită ca dovadă de bine — tiparul din CLAUDE.md.

    Capăt la capăt, nu pe o constantă: domeniul e cel pe care l-a scris
    orchestratorul în rând și e citit înapoi DIN rând de verificare.
    """
    from sentinel.selfcheck import checks

    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_image(db, "test"))
    (scris,) = db.scans
    acum = datetime.now(timezone.utc)

    class _SelfcheckDB:
        async def fetch(self, _sql, *_a):
            return [{"id": 1, "scanner": scris["scanner"], "status": "completed",
                     "started_at": acum, "finished_at": acum, "error": None,
                     "findings_count": 450, "target": scris["target"],
                     "ok_started_at": acum, "ok_finished_at": acum,
                     "ok_findings_count": 450, "ok_target": scris["target"]}]

        async def fetchval(self, _sql, *args):
            return (acum - args[0]).total_seconds()

    cfg = SimpleNamespace(scan=SimpleNamespace(enabled=True))
    (r,) = run(checks.check_last_scan(_SelfcheckDB(), cfg))
    assert r.status == "ok" and "450 constatări" in r.detail
    assert "HIGH" in r.detail, (
        f"numărul e spus fără pragul la care a fost măsurat: {r.detail!r}")
    assert trivy_image.severity_scope() in r.detail


def test_a_run_at_the_new_floor_does_not_close_the_old_medium_findings(
        monkeypatch) -> None:
    """2388 de vulnerabilități nu se repară într-o noapte fiindcă am încetat să le cerem.

    Eșecul pe care îl previne: `mark_resolved_absent` închide tot ce scanerul nu
    a mai raportat. După ridicarea pragului, „nu a mai raportat" acoperă două
    lucruri diferite — ce s-a reparat, și ce nu mai e căutat. Nediferențiate,
    prima rulare la HIGH ar fi marcat toate constatările MEDIUM ale imaginilor
    drept `absent_from_latest_scan`, iar panoul ar fi arătat o gazdă care s-a
    reparat singură peste noapte.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_image(db, "test"))

    (sql, args) = db.resolve_calls[0]
    assert "severity = ANY($4::text[])" in sql, (
        f"rezolvarea nu e îngrădită de severitățile cerute: {sql}")
    assert set(args[3]) == {"high", "critical"}
    assert "medium" not in args[3], (
        "o rulare care nu mai cere MEDIUM poate închide constatări MEDIUM")
    assert args[4] is True, (
        "constatările nenotate (`UNKNOWN`, parcate la `medium`) sunt cerute, "
        "deci ele TREBUIE să se poată închide când dispar")
    # Al doilea jumătate a predicatului. Fără ea, `UNKNOWN` — parcat de
    # `map_severity` la `medium`, la fel ca un MEDIUM măsurat — n-ar mai putea fi
    # deosebit de el, iar garda ar închide și ce apără, sau ar apăra și ce nu
    # trebuie. Aserțiune pe TEXT fiindcă aici nu există bază de date; că Postgres
    # acceptă expresia nu se poate proba de aici.
    assert "severity_known" in sql, (
        f"constatările nenotate nu sunt deosebite de un MEDIUM măsurat: {sql}")


# Ce fel de valoare acceptă fiecare turnare pe care o modelăm. `bool` înainte de
# `int`, fiindcă în Python `True` E un `int` și un `$N::int` care primește `True`
# n-ar mai fi prins.
_TURNARI = {
    "text[]": lambda v: isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v),
    "boolean": lambda v: isinstance(v, bool),
    "text": lambda v: isinstance(v, str),
    "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "bigint": lambda v: isinstance(v, int) and not isinstance(v, bool),
}


def test_the_severity_fence_numbers_its_parameters_correctly(monkeypatch) -> None:
    """Un `$N` greșit nu se vede la citire; se vede noaptea, ca scanare căzută.

    Eșecul pe care îl previne: predicatul de severitate e cusut în două
    interogări cu numerotări diferite — `$4/$5` la rezolvare, `$3/$4` la
    numărătoare. O nepotrivire între câți parametri poartă textul și câți se
    trimit e respinsă de Postgres la execuție: excepție în orchestrator, rând
    `failed` în fiecare noapte, nicio constatare ingerată — și niciun test de
    aici n-ar fi văzut-o, fiindcă în suită nu rulează nicio bază.

    Al doilea eșec, pe care versiunea de dinainte a testului NU-l prindea deși
    numele îl promitea: `_visible_sql(5, 4)` — parametrii INVERSAȚI. Mulțimea
    `$N` din text rămâne aceeași, deci o aserțiune doar pe numerotare trece.
    Ce se schimbă la inversare e perechea dintre `$N` și TIPUL valorii trimise
    pe poziția aia: lista de severități ajunge sub `::boolean` și steagul sub
    `::text[]`. Postgres refuză și asta, tot la execuție, tot noaptea — iar
    inversarea fusese prinsă până acum din întâmplare, de alt test.

    Cât se poate verifica fără gazdă: că textul și argumentele se potrivesc la
    număr ȘI la tip. Că expresia e SQL valid rămâne de probat pe Postgres.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB(sub_prag=7)
    run(orchestrator._run_trivy_image(db, "test"))

    perechi = [("rezolvare", db.resolve_calls[0]), ("numărătoare", db.counted[0])]
    assert len(perechi) == 2, "una dintre cele două interogări nu s-a executat"
    for eticheta, (sql, args) in perechi:
        numere = {int(n) for n in re.findall(r"\$(\d+)", sql)}
        assert numere == set(range(1, len(args) + 1)), (
            f"{eticheta}: textul folosește {sorted(numere)} dar se trimit "
            f"{len(args)} argumente: {sql}")

        turnari = {int(n): t.lower()
                   for n, t in re.findall(r"\$(\d+)::(\w+(?:\[\])?)", sql)}
        vazute = set()
        for n, cast in turnari.items():
            accepta = _TURNARI.get(cast)
            if accepta is None:      # turnare pe care testul n-o modelează
                continue
            vazute.add(cast)
            assert accepta(args[n - 1]), (
                f"{eticheta}: ${n} e turnat `{cast}` dar primește "
                f"{args[n - 1]!r} — parametrii gardei sunt inversați: {sql}")
        # Fără asta, o schimbare care scoate turnările din text ar lăsa bucla de
        # mai sus să nu verifice nimic și testul ar rămâne verde degeaba — exact
        # forma de listă parametrizată ieșită goală din CLAUDE.md.
        assert {"text[]", "boolean"} <= vazute, (
            f"{eticheta}: garda de severitate nu mai poartă ambele turnări "
            f"({sorted(vazute)}), deci potrivirea pe tip n-a verificat nimic: {sql}")


# Forma exactă a gărzii. Scrisă o dată aici, ca testul de mai jos să poată
# număra aparițiile ei față de aparițiile cheii pe care o apără.
_GARDA_NENOTAT = "COALESCE(raw->'severity_known' = 'false'::jsonb, false)"


def test_a_finding_with_no_scored_flag_at_all_stays_inside_the_fence(
        monkeypatch) -> None:
    """Un rând fără cheia `severity_known` n-are voie să cadă din AMBELE interogări.

    Eșecul pe care îl previne: `COALESCE(..., false)` scos din `_visible_sql`.
    `raw->'severity_known'` pe un rând care n-are cheia dă NULL, `... OR NULL`
    dă NULL, iar `NOT (... OR NULL)` dă tot NULL — deci rândul nu e nici închis
    de rezolvare, nici numărat de numărătoare. Nu rămâne „protejat": dispare din
    amândouă, adică nici nu se repară, nici nu se spune că e acolo. Asta e forma
    unei scurgeri, nu a unei decizii — și e singurul fel de defect pe care
    panoul îl arată ca liniște.

    Nu e teoretic: pe gazdă există 19 constatări `dnf` low/medium fără cheia
    aia, scrise înainte ca steagul să existe. Azi nu se scurg, fiindcă garda se
    aplică doar scanerelor care declară un prag și singurul care declară unul —
    `trivy_image` — își scrie steagul necondiționat. Garda e însă scrisă
    generic, iar docstring-ul lui `_visible_sql` o dă drept apărare centrală: în
    ziua în care al doilea scaner capătă un prag, rândurile fără cheie sunt ale
    lui, și nimic nu le-ar fi oprit.

    Se verifică pe textul care AJUNGE la bază, în amândouă interogările, nu pe
    constanta din modul — o gardă pusă într-o interogare și uitată în cealaltă e
    exact drift-ul pentru care `_visible_sql` e scris o singură dată. Că
    Postgres evaluează `COALESCE` așa cum spune docstring-ul nu se poate proba
    de aici; asta rămâne pentru gazdă.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB(sub_prag=7)
    run(orchestrator._run_trivy_image(db, "test"))

    for eticheta, (sql, _args) in (("rezolvare", db.resolve_calls[0]),
                                   ("numărătoare", db.counted[0])):
        assert "severity_known" in sql, (
            f"{eticheta}: constatările nenotate nu mai sunt deosebite deloc: {sql}")
        # Egalitate, nu „conține": fiecare apariție a cheii trebuie să fie
        # înăuntrul unui COALESCE cu implicit `false`. O a doua comparație goală
        # adăugată mai târziu ar reintroduce NULL-ul fără să scoată garda asta.
        assert sql.count("severity_known") == sql.count(_GARDA_NENOTAT), (
            f"{eticheta}: `raw->'severity_known'` apare "
            f"{sql.count('severity_known')} ori, dar numai "
            f"{sql.count(_GARDA_NENOTAT)} sub `COALESCE(..., false)` — un rând "
            f"fără cheia aia dă NULL și cade tăcut din amândouă interogările: {sql}")


def test_the_findings_left_below_the_floor_are_counted_and_said(
        monkeypatch, caplog) -> None:
    """Protejate și netrecute nicăieri ar fi doar o altă formă de tăcere.

    Eșecul pe care îl previne: constatările MEDIUM rămase deschise stau în panou
    arătând ca măsurătoarea de azi, deși nimic nu le-a mai verificat de la
    mutarea pragului. Operatorul trebuie să afle numărul de la noi, nu să-l
    deducă dintr-o cifră care a încetat să se miște.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB(sub_prag=2388)
    with caplog.at_level("WARNING", logger="sentinel.scan.orchestrator"):
        out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["below_floor_open"] == 2388
    assert db.counted, "nimeni n-a numărat ce a rămas sub prag"
    randuri = [r for r in caplog.records if r.levelname == "WARNING"]
    assert randuri, "numărul rămas sub prag nu ajunge în jurnal"
    assert getattr(randuri[0], "open", None) == 2388


def test_a_host_with_nothing_below_the_floor_says_nothing(monkeypatch, caplog) -> None:
    """Zero rămase nu are voie să producă un avertisment în fiecare noapte.

    Eșecul pe care îl previne: un `WARNING` nocturn cu „0 constatări sub prag"
    e zgomotul care îl învață pe operator să nu mai citească nivelul ăla — și
    atunci se pierde și avertismentul care conta.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch)
    db = _DB(sub_prag=0)
    with caplog.at_level("WARNING", logger="sentinel.scan.orchestrator"):
        out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["below_floor_open"] == 0
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


def test_the_orchestrator_only_runs_it_when_the_config_says_so() -> None:
    """`scan.containers` e cheia cu care e descris în configurație.

    Eșecul pe care îl previne: o cheie paralelă inventată aici ar lăsa
    `scan.containers: false` fără efect — operatorul oprește scanerul (și scoate
    apartenența la grupul `docker`), iar el încearcă mai departe în fiecare
    noapte și scrie un rând `failed` pe care nimeni nu-l poate face verde.
    """
    sursa = (ROOT / "sentinel" / "scan" / "orchestrator.py").read_text(encoding="utf-8")
    assert "cfg.scan.containers" in sursa
    from sentinel.config import ScanConfig
    assert isinstance(ScanConfig().containers, bool)


def test_the_scanner_name_is_the_key_selfcheck_reports_under(monkeypatch) -> None:
    """Numele scris în `scans` e cel sub care eșecul ajunge pe Telegram.

    Eșecul pe care îl previne: `check_last_scan` raportează sub
    `scan:last:{scanner}`. Un nume care nu se leagă face ca eșecul scanării de
    containere să nu apară niciodată în `/selfcheck` — deci un `scan.containers:
    true` fără acces la socket ar tăcea, exact ce nu trebuie să se întâmple.

    Verificat capăt la capăt, nu pe o constantă: numele e luat din ce a scris
    orchestratorul și dus prin verificarea reală.
    """
    from sentinel.selfcheck import checks

    _probe(monkeypatch, trivy_image.DOCKER_UNREACHABLE,
           "permission denied la /run/docker.sock")
    _no_kev(monkeypatch)
    db = _DB()
    run(orchestrator._run_trivy_image(db, "test"))
    (scris,) = db.scans
    acum = datetime.now(timezone.utc)

    class _SelfcheckDB:
        async def fetch(self, _sql, *_a):
            return [{"id": 1, "scanner": scris["scanner"], "status": "failed",
                     "started_at": acum, "finished_at": acum,
                     "error": "permission denied la /run/docker.sock",
                     "findings_count": 0, "ok_started_at": None,
                     "ok_finished_at": None, "ok_findings_count": None}]

    cfg = SimpleNamespace(scan=SimpleNamespace(enabled=True))
    (r,) = run(checks.check_last_scan(_SelfcheckDB(), cfg))
    assert r.key == f"scan:last:{trivy_image.SCANNER}" == "scan:last:trivy_image"
    assert r.status == "degraded"
    assert "permission denied" in r.detail


def test_the_scanner_name_is_in_the_migration_vocabulary() -> None:
    """Numele e cel din 0003, nu unul inventat aici.

    Eșecul pe care îl previne: două nume pentru același scaner (`containers` în
    cod, `trivy_image` în comentariul schemei) despart constatările în două
    familii care nu se rezolvă niciodată una pe alta.
    """
    sql = (ROOT / "sentinel" / "db" / "migrations" / "0003_vuln.sql").read_text(
        encoding="utf-8")
    assert f"| {trivy_image.SCANNER} " in sql or f"| {trivy_image.SCANNER}\n" in sql, (
        f"{trivy_image.SCANNER} nu e în vocabularul documentat al coloanei `scanner`")


def test_the_docker_group_cost_is_written_down_where_it_is_read() -> None:
    """Decizia că `sentinel` devine efectiv root trebuie să fie de negăsit greu.

    Eșecul pe care îl previne: apartenența la grupul `docker` e adăugată de
    instalator cu un `warn` care trece o dată prin terminal și dispare. Peste șase
    luni, cine citește modelul de amenințare găsește acolo că un daemon `sentinel`
    compromis e ținut în frâu de politica executorului — ceea ce nu mai e adevărat.
    """
    modul = (ROOT / "sentinel" / "scan" / "trivy_image.py").read_text(encoding="utf-8")
    assert "equivalent to root" in modul
    arh = (ROOT / "docs" / "ARHITECTURA.md").read_text(encoding="utf-8")
    assert "grupul `docker`" in arh and "echivalent cu root" in arh
    assert "scan.containers" in arh

    # Și acolo unde afirmația contrară era scrisă: rândul din modelul de
    # amenințare spunea că un daemon `sentinel` compromis e ținut în frâu de
    # politica executorului. Cu apartenența la grupul `docker` asta nu mai e
    # adevărat, iar un tabel care rămâne pe loc e mai rău decât unul care
    # lipsește — cine îl citește crede că are o limită pe care n-o are.
    (rand,) = [linie for linie in arh.splitlines()
               if linie.startswith("| Un daemon `sentinel` |")]
    assert "docker" in rand, (
        f"rândul din modelul de amenințare nu spune că `sentinel` e în grupul "
        f"docker: {rand}")


# --------------------------------------------------------------------------
# Bugetul pe imagine: o imagine care nu incape se numeste, nu orbeste flota
# --------------------------------------------------------------------------
#
# Rularea din 23 octombrie 2026 ingera 2532 de constatari fata de un plafon de
# 2500 si refuza TOT: aplicatiile operatorului (aproape nimic) se pierdeau
# impreuna cu `waha` (1602) si `snipe-it` (530). Testele de mai jos fixeaza
# comportamentul care il lasa sa vada ce incape si sa afle pe nume ce nu.
def _synthetic_report(image_id: str, *, critical: int = 0, high: int = 0,
                      unknown: int = 0, label: str = "x") -> dict:
    """Un raport `trivy image` cu exact atatea constatari din fiecare fel."""
    vulns = []
    for severity, count in (("CRITICAL", critical), ("HIGH", high),
                            ("UNKNOWN", unknown)):
        for _ in range(count):
            k = len(vulns)
            vulns.append({"VulnerabilityID": f"CVE-2026-{label}{k:05d}",
                          "PkgName": f"{label}-pkg{k}", "Severity": severity,
                          "InstalledVersion": "1.0", "FixedVersion": "1.1",
                          "Title": f"{label} {k}"})
    return {"SchemaVersion": 2, "ArtifactName": image_id,
            "Metadata": {"ImageID": f"sha256:{image_id}",
                         "OS": {"Family": "debian", "Name": "12"}},
            "Results": [{"Target": "t", "Class": "os-pkgs", "Type": "debian",
                         "Vulnerabilities": vulns}] if vulns else None}


def _image_id(n: int) -> str:
    return f"{n:064x}"


def _fleet(gazda, sizes: dict[str, int]) -> dict[str, str]:
    """Containere pentru `sizes` ({referinta: constatari}); intoarce {ref: id}."""
    ids = {ref: _image_id(i + 1) for i, ref in enumerate(sizes)}
    gazda.containers([(f"{i + 1:064x}"[::-1], ids[ref], ref, f"c{i}")
                      for i, ref in enumerate(sizes)])
    for ref, n in sizes.items():
        gazda.reports[ids[ref]] = _synthetic_report(ids[ref], high=n, label=f"i{ids[ref][-2:]}")
    return ids


def test_images_that_fit_are_ingested_when_another_one_blows_the_budget(
        gazda, monkeypatch) -> None:
    """O imagine uriasa nu are voie sa ia cu ea aplicatiile operatorului.

    Eșecul pe care îl previne: starea din 23 octombrie 2026. Un singur total peste
    plafon și rularea refuza totul — operatorul pierdea constatările propriilor
    aplicații, care sunt aproape nimic, odată cu cele două imagini străine care
    adunau 82%. Aici: două imagini mici încap, una uriașă nu, și ce încape trebuie
    să ajungă în bază.
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 10)
    _fleet(gazda, {"app-a": 3, "app-b": 4, "third-party": 50})
    items, eroare, fapte = run(trivy_image.scan())

    assert eroare is None, eroare
    assert {i["location"] for i in items} == {"app-a", "app-b"}
    assert len(items) == 7
    cov = fapte["coverage"]
    assert cov["ingested"] == ["app-a", "app-b"]
    (sarita,) = cov["skipped"]
    assert sarita["reference"] == "third-party"
    assert sarita["reason"] == trivy_image.REASON_IMAGE
    assert sarita["findings"] == 50, "imaginii sărite i se spune câte constatări are"


def test_an_image_over_the_budget_alone_is_skipped_whole_and_never_cut(
        gazda, monkeypatch) -> None:
    """Imaginea peste buget nu se ingerează „cât încape" — ori toată, ori deloc.

    Eșecul pe care îl previne: o imagine de 50 de constatări tăiată la 10 ar
    lăsa 40 de rânduri ale ei absente din `seen_keys`. Chiar cu garda pe
    `location` ele ar rămâne deschise, dar cele 10 ingerate ar fi reîmprospătate
    și celelalte 40 nu — o imagine pe jumătate măsurată, prezentată întreagă.
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 10)
    _fleet(gazda, {"app-a": 3, "third-party": 50})
    items, _eroare, fapte = run(trivy_image.scan())

    assert "third-party" not in {i["location"] for i in items}, (
        "constatări ale imaginii peste buget au ajuns în lista de ingerat")
    assert fapte["total"] == 3


def test_the_largest_image_is_the_one_left_out_when_the_sum_binds(
        gazda, monkeypatch) -> None:
    """Când suma depășește, cade imaginea cea mai MARE, nu una aleasă la întâmplare.

    Eșecul pe care îl previne: bugetul aplicat „în ordinea în care a venit
    docker", deci o aplicație mică a operatorului ar putea fi cea sărită iar o
    imagine străină de o mie de rânduri ar rămâne. Fiecare încape singură (3, 4,
    5 față de 10), dar împreună fac 12.
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 10)
    _fleet(gazda, {"zz-big": 5, "aa-small": 3, "mm-mid": 4})
    items, _eroare, fapte = run(trivy_image.scan())

    cov = fapte["coverage"]
    assert cov["ingested"] == ["aa-small", "mm-mid"]
    (sarita,) = cov["skipped"]
    assert (sarita["reference"], sarita["reason"]) == (
        "zz-big", trivy_image.REASON_BUDGET)
    assert cov["admitted_findings"] == 7 and len(items) == 7


def _fake_image(ref: str, n: int):
    # Id deterministic (`hash(str)` difera de la o rulare la alta): departajarea
    # testata e pe NUME, nu pe id.
    image = trivy_image.RunningImage(image_id=_image_id(ord(ref[0])),
                                     reference=ref, containers=())
    return image, [{"severity": "high"} for _ in range(n)]


def test_the_outcome_does_not_depend_on_the_order_images_arrive_in() -> None:
    """Aceeași flotă dă aceeași listă de sărite oricum le-ar enumera docker.

    Eșecul pe care îl previne: o repornire de container schimbă ordinea din
    `docker ps`, iar imaginea sărită se mută de la o noapte la alta fără ca ceva
    din flotă să se fi schimbat — constatările ei ar apărea și ar dispărea din
    panou după un criteriu pe care nimeni nu-l poate explica. Include două
    imagini cu ACELAȘI număr de constatări: departajarea trebuie să fie pe nume.
    Se compară cu definiția, nu cu o a doua copie a algoritmului: cel mai lung
    prefix, în ordinea (mărime, nume), a cărui sumă încape.
    """
    import itertools

    sizes = {"b": 2, "a": 2, "c": 5, "d": 1, "e": 5}
    # 10: d, a, b, c încap (sumă 10), iar e nu — dintre c și e, TOT ce le
    # deosebește e numele. Cu un buget de 9 ar cădea amândouă și departajarea n-ar
    # mai conta (un test care trece oricum nu apără nimic).
    budget = 10
    asteptat_ingerate = []
    total = 0
    for ref, n in sorted(sizes.items(), key=lambda kv: (kv[1], kv[0])):
        if total + n > budget:
            break
        asteptat_ingerate.append(ref)
        total += n
    assert asteptat_ingerate == ["d", "a", "b", "c"], (
        "fixtura nu mai testează departajarea")

    vazute = set()
    for perm in itertools.permutations(sizes):
        adm = trivy_image.Admission(budget)
        for ref in perm:
            adm.offer(*_fake_image(ref, sizes[ref]))
        cov = adm.coverage(len(sizes))
        vazute.add((tuple(cov["ingested"]),
                    tuple(sk["reference"] for sk in cov["skipped"])))
    assert vazute == {(("a", "b", "c", "d"), ("e",))}, (
        f"rezultatul depinde de ordinea sosirii: {sorted(vazute)}")


def test_an_oversized_report_skips_that_image_and_not_the_run(
        gazda, monkeypatch) -> None:
    """Un raport prea mare pentru memorie nu mai orbește toate containerele.

    Eșecul pe care îl previne: raportul unei singure imagini peste
    `MAX_OUTPUT_BYTES` întorcea o eroare pentru întreaga rulare — aceeași formă
    de orbire totală ca plafonul de constatări, de la o singură imagine. Mărimea
    e un fapt MĂSURAT despre imaginea aceea (o repetare nu o schimbă), spre
    deosebire de o cădere a lui trivy. Numărul ei de constatări nu se știe —
    raportul nu s-a citit — și se spune așa, nu ca zero.
    """
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web"),
                      ("b" * 64, IMG_APP, "zz-app:2.3", "app")])
    gazda.reports = {IMG_NGINX: SAMPLE, IMG_APP: CLEAN}
    mic = len(json.dumps(CLEAN))
    mare = len(json.dumps(SAMPLE))
    assert mic < mare
    monkeypatch.setattr(trivy_fs, "MAX_OUTPUT_BYTES", mic + 10)

    items, eroare, fapte = run(trivy_image.scan())
    assert eroare is None, eroare
    cov = fapte["coverage"]
    assert cov["ingested"] == ["zz-app:2.3"], (
        "imaginea curată (zero constatări) trebuie să conteze ca ingerată")
    (sarita,) = cov["skipped"]
    assert sarita["reference"] == "nginx:1.27"
    assert sarita["reason"] == trivy_image.REASON_REPORT
    assert sarita["findings"] is None, "un număr necitit a fost scris ca număr"
    assert items == []


def test_a_skipped_image_records_what_severities_the_operator_is_not_shown() -> None:
    """„O imagine sărită" cu 34 de CRITICAL nu e același lucru cu una cu 3 MEDIUM.

    Eșecul pe care îl previne: alerta spune doar numele și numărul total, iar
    operatorul nu poate judeca cât de urgent e să facă loc bugetului. Cifrele vin
    din ce s-a parsat (severitatea de la ingestie, steagul `severity_known`).
    """
    items = trivy_image.parse(
        _synthetic_report(_image_id(9), critical=2, high=3, unknown=4, label="q"),
        reference="r", image_id=_image_id(9))
    adm = trivy_image.Admission(5)
    adm.offer(trivy_image.RunningImage(_image_id(9), "r", ()), items)
    (sk,) = adm.skipped
    assert (sk.findings, sk.critical, sk.high, sk.unrated) == (9, 2, 3, 4)


# --- orchestratorul: garda pe imagine si ce scrie pe rand -------------------
def _coverage(skipped=(), ingested=("nginx:1.27",), images=None, admitted=3):
    return {"images": images if images is not None else len(skipped) + len(ingested),
            "ingested": list(ingested), "admitted_findings": admitted,
            "budget": trivy_image.MAX_FINDINGS,
            "skipped": [{"reference": ref, "image_id": _image_id(7),
                         "reason": trivy_image.REASON_BUDGET, "findings": n,
                         "critical": c, "high": h, "unrated": u,
                         "report_bytes": None}
                        for ref, n, c, h, u in skipped]}


WAHA = ("devlikeapro/waha:latest", 1602, 34, 918, 650)


def test_a_skipped_image_is_fenced_off_from_resolution(monkeypatch) -> None:
    """Imaginea sărită nu e imaginea reparată.

    Eșecul pe care îl previne: constatările lui `waha` lipsesc din `seen_keys`
    fiindcă rularea nu le-a luat, nu fiindcă s-au reparat. Fără `skip_locations`,
    `mark_resolved_absent` le-ar închide pe toate cele 1522 deschise ca
    `absent_from_latest_scan`, iar panoul ar anunța o imagine cu 34 de CRITICAL
    ca rezolvată într-o noapte în care nimeni n-a atins-o.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch, facts={"coverage": _coverage(skipped=[WAHA])})
    db = _DB(open_at_skipped=1522)
    run(orchestrator._run_trivy_image(db, "test"))

    (sql, args) = db.resolve_calls[0]
    assert "location = ANY" in sql, f"rezolvarea nu e îngrădită pe imagine: {sql}"
    assert ["devlikeapro/waha:latest"] in [list(a) for a in args if isinstance(a, list)], (
        f"imaginea sărită nu e între argumentele rezolvării: {args!r}")


def test_the_location_fence_is_numbered_after_the_severity_ones(monkeypatch) -> None:
    """Un `$N` greșit se vede noaptea, ca o scanare căzută — nu la citire.

    Eșecul pe care îl previne: garda pe `location` se adaugă după cea de
    severitate cu un număr calculat; cu garda de severitate absentă ocupă `$4`,
    cu ea prezentă `$6`. O numerotare scrisă de mână pentru un singur caz e
    respinsă de Postgres la execuție în celălalt: excepție în orchestrator, rând
    `failed`, nicio constatare ingerată — în fiecare noapte. Se verifică numărul
    ȘI tipul, ca la garda de severitate, plus că lista goală nu adaugă nimic.
    """
    class Rec:
        def __init__(self):
            self.calls = []

        async def fetch(self, sql, *args):
            self.calls.append((sql, args))
            return []

    async def lansat(**kw):
        db = Rec()
        await fx.mark_resolved_absent(db, "trivy_image", None, ["k"], **kw)
        return db.calls[0]

    for eticheta, kw, asteptat_param in (
            ("cu garda de severitate", dict(visible_severities=["high"],
                                            visible_unscored=True,
                                            skip_locations=["img:1"]), 6),
            ("fără garda de severitate", dict(skip_locations=["img:1"]), 4)):
        sql, args = run(lansat(**kw))
        numere = {int(n) for n in re.findall(r"\$(\d+)", sql)}
        assert numere == set(range(1, len(args) + 1)), (
            f"{eticheta}: textul folosește {sorted(numere)}, se trimit {len(args)}")
        assert f"location = ANY(${asteptat_param}::text[])" in sql, (
            f"{eticheta}: garda pe location nu e pe ${asteptat_param}: {sql}")
        assert args[asteptat_param - 1] == ["img:1"]
        # NULL-safe: un rând fără `location` nu aparține nicio imagini sărite.
        assert "NOT COALESCE(location = ANY" in sql and ", false)" in sql

    for gol in (None, []):
        sql, args = run(lansat(skip_locations=gol))
        assert "location" not in sql and len(args) == 3, (
            f"lista goală de imagini sărite a adăugat o gardă: {sql}")


def test_the_completed_row_names_what_was_skipped_and_what_it_covered(
        monkeypatch) -> None:
    """Rândul `completed` spune CE imagine lipsește, nu doar că ceva lipsește.

    Eșecul pe care îl previne: «nouă din unsprezece» fără nume nu e acționabil.
    Operatorul trebuie să afle de pe rând, fără jurnal: care imagine, câte
    constatări și câte CRITICAL nu i se arată, de ce, câte rânduri vechi au rămas
    deschise (citite din bază), și ce a acoperit rularea. `target` poartă
    domeniul în care e adevărată cifra de constatări.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch, facts={"images": 2, "coverage": _coverage(
        skipped=[WAHA], ingested=("nginx:1.27",), admitted=930)})
    db = _DB(open_at_skipped=1522)
    out = run(orchestrator._run_trivy_image(db, "test"))

    (rand,) = db.finished
    assert rand["status"] == "completed", (
        "o rulare care a ingerat restul nu e un eșec: cifra ei e adevărată")
    err = rand["error"]
    assert "devlikeapro/waha:latest" in err
    assert "1602 constatări" in err and "34 CRITICAL" in err and "918 HIGH" in err
    assert "1522" in err, "nu spune cât a rămas deschis pe imaginile sărite"
    assert "nginx:1.27" in err, "nu spune ce s-a ingerat"
    assert trivy_image.severity_scope() in rand["target"]
    assert "1 din 2 imagini ingerate" in rand["target"]
    assert out["skipped"] == ["devlikeapro/waha:latest"]
    assert out["skipped_open"] == 1522


def test_a_run_that_skipped_nothing_does_not_claim_a_caveat(monkeypatch) -> None:
    """Fără imagini sărite, rândul rămâne curat: nicio alarmă în fiecare noapte.

    Eșecul pe care îl previne: `error` completat pe fiecare rulare (de pildă cu
    «0 imagini sărite»). `check_last_scan` citește orice `error` de pe un rând
    `completed` ca „nu a acoperit tot" și ar da `degraded` permanent — alarma care
    sună mereu îl învață pe operator s-o ignore, inclusiv pe cea adevărată.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch, facts={"coverage": _coverage(ingested=("nginx:1.27",))})
    db = _DB()
    out = run(orchestrator._run_trivy_image(db, "test"))

    (rand,) = db.finished
    assert rand["status"] == "completed" and rand["error"] is None
    assert "1 din 1 imagini ingerate" in rand["target"]
    assert out["skipped"] == [] and db.counted_at == [], (
        "s-a făcut o interogare pentru imagini sărite când nu era niciuna")


def test_what_stays_open_is_counted_from_the_database_after_the_resolve(
        monkeypatch) -> None:
    """Numărul rămas deschis e citit DUPĂ rezolvare, din bază — nu presupus.

    Eșecul pe care îl previne: «rămân deschise N» calculat din ce intenționăm,
    adică confirmarea intenției în locul efectului. Dacă garda ar cădea, numărul
    intenționat ar spune tot N, iar cel citit din bază după rezolvare ar spune 0.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch, facts={"coverage": _coverage(skipped=[WAHA])})
    db = _DB(open_at_skipped=0)
    run(orchestrator._run_trivy_image(db, "test"))

    assert db.events.index("resolve") < db.events.index("count_at_skipped"), (
        f"numărătoarea rulează înaintea rezolvării: {db.events}")
    (rand,) = db.finished
    assert "(0)" in rand["error"], (
        "numărul din bază (0) nu ajunge pe rând; s-a scris altceva")


def test_an_ingest_that_dies_midway_names_the_skipped_but_not_the_ingested(
        monkeypatch) -> None:
    """Un rând `failed` după decizie păstrează imaginile sărite, dar nu minte.

    Eșecul pe care îl previne: două direcții. (1) Ingestia cade la a treia
    constatare și rândul `failed` poartă doar «conexiunea a căzut» — operatorul
    nu mai află că `waha` fusese oricum sărită. (2) Rândul ar scrie «Ingerate
    (1): nginx» deși ingestia n-a terminat: o afirmație despre un efect pe care
    nu l-am verificat.
    """
    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    _merge_stub(monkeypatch, facts={"coverage": _coverage(skipped=[WAHA])})
    db = _DB(fail_upsert_after=2)
    out = run(orchestrator._run_trivy_image(db, "test"))

    assert out["status"] == "failed"
    (rand,) = db.finished
    assert rand["status"] == "failed"
    assert "conexiunea cu baza a cazut" in rand["error"]
    assert "devlikeapro/waha:latest" in rand["error"]
    assert "Ingerate (" not in rand["error"], (
        "rândul cazut afirmă ce s-a ingerat, deși ingestia n-a terminat")
    assert db.resolved == [], "o ingestie căzută a rezolvat constatări"


def test_finish_scan_without_a_target_keeps_the_one_written_at_open() -> None:
    """Ceilalți scanere nu își pierd `target`-ul fiindcă `finish_scan` a învățat unul.

    Eșecul pe care îl previne: `SET target = $9` cu `None` din apelurile vechi —
    coloana e `NOT NULL`, deci fiecare rulare de `dnf` și `trivy_fs` ar cădea la
    închiderea rândului, iar rândurile ar rămâne `running` până la pragul de
    «blocat». `COALESCE` e ce face parametrul opțional.
    """
    class Rec:
        def __init__(self):
            self.calls = []

        async def execute(self, sql, *args):
            self.calls.append((sql, args))

    db = Rec()
    run(fx.finish_scan(db, 1, status="completed"))
    (sql, args) = db.calls[0]
    assert "COALESCE($9, target)" in sql, f"target fără COALESCE: {sql}"
    assert args[8] is None

    run(fx.finish_scan(db, 1, status="completed", target="nou"))
    assert db.calls[1][1][8] == "nou"


def test_count_open_at_locations_asks_nothing_when_nothing_was_skipped() -> None:
    """Fără imagini sărite nu se interoghează baza pentru ele.

    Eșecul pe care îl previne: o interogare în plus în fiecare noapte curată, a
    cărei cădere ar muta o rulare bună în `failed`. Un număr care nu se cere nu
    are cum să strice nimic.
    """
    class Rec:
        def __init__(self):
            self.calls = 0

        async def fetchval(self, sql, *args):
            self.calls += 1
            return 5

    db = Rec()
    assert run(fx.count_open_at_locations(db, "trivy_image", None, [])) == 0
    assert db.calls == 0
    assert run(fx.count_open_at_locations(db, "trivy_image", None, ["x"])) == 5


# --- flota de la 25 octombrie 2026, cu cifrele masurate ---------------------
#
# Flota: 11 imagini (waha, snipe-it si noua altele), aceeasi pe 23, 24 si 25
# octombrie — fiecare dintre cele trei randuri `failed` (208, 211, 214) spune
# "pe 11 imagini". Totalul e CITIT DIN TEXTUL ERORII, nu din `findings_count`:
# scanarea a REFUZAT in cele trei nopti, deci `findings_count` e 0 pe toate; cine
# verifica in baza vede 0 si crede ca seria minte. Totalul din eroare e 2540 pe
# 25 octombrie. `waha` (1602) si `snipe-it` (530) sunt masurate cu trivy pe gazda
# pe 23 octombrie; cele +8 aparute pana pe 25 nu se pot atribui unei imagini
# (un rand `failed` nu pastreaza defalcarea) si sunt puse pe `app-alpha`, deci
# DEFALCAREA celor noua e aproximativa, totalul de 2540 nu e.
#
# Numele aplicatiilor operatorului sunt inlocuite (repository-ul e public);
# imaginile straine (mariadb, postgres, waha, snipe-it) sunt cele reale.
# Format: {referinta: (CRITICAL, HIGH, UNKNOWN)}.
FLEET_OF_25_OCTOBER = {
    "devlikeapro/waha:latest": (34, 918, 650),
    "snipe/snipe-it:latest": (50, 479, 1),
    **{ref: (0, n, 0) for ref, n in {
        "app-alpha": 101, "mariadb:11.4.7": 70, "app-beta:latest": 46,
        "app-gamma:latest": 46, "app-delta": 43, "app-delta-worker": 43,
        "postgres:16-alpine": 27, "app-eps-api": 16, "app-eps-worker": 16}.items()},
}
# Ancora bugetului: totalul flotei pe care o ingereaza fixture-ul de mai jos, nu
# un numar tastat langa serie. Un test de comportament afirma acest total (vezi
# `test_the_same_night_fits_whole_under_the_real_budget`), asa ca a-l cobori
# inseamna a sparge acel test, nu a edita o lista.
FLEET_TOTAL = sum(sum(sev) for sev in FLEET_OF_25_OCTOBER.values())


def _the_fleet_of_25_october(gazda, monkeypatch):
    """Flota din 25 octombrie 2026, cap la cap: scanerul adevărat, orchestratorul
    adevărat, `check_last_scan` adevărat citind rândul pe care l-a scris
    orchestratorul. Întoarce `(rezultatul orchestratorului, baza, verificarea,
    referințele flotei)`.

    NU atinge `MAX_FINDINGS`: cine o apelează hotărăște ce buget vrea. Cifrele sunt
    în `FLEET_OF_25_OCTOBER`: `waha` 1602 și `snipe-it` 530 MĂSURATE pe 23
    octombrie, totalul de 2540 citit din eroarea rândului `failed` 214, împărțirea
    celorlalte nouă aproximativă.
    """
    from sentinel.selfcheck import checks

    flota = FLEET_OF_25_OCTOBER
    ids = {ref: _image_id(i + 1) for i, ref in enumerate(flota)}
    gazda.containers([(f"{i + 1:064x}"[::-1], ids[ref], ref, f"c{i}")
                      for i, ref in enumerate(flota)])
    for ref, (c, h, u) in flota.items():
        gazda.reports[ids[ref]] = _synthetic_report(
            ids[ref], critical=c, high=h, unknown=u, label=f"n{ids[ref][-2:]}")

    _probe(monkeypatch, trivy_image.DOCKER_READY)
    _no_kev(monkeypatch)
    db = _DB(open_at_skipped=1522)
    out = run(orchestrator._run_trivy_image(db, "schedule"))

    (rand,) = db.finished
    (deschis,) = db.scans
    acum = datetime.now(timezone.utc)

    class _SelfcheckDB:
        async def fetch(self, _sql, *_a):
            return [{"id": 1, "scanner": deschis["scanner"], "status": rand["status"],
                     "started_at": acum, "finished_at": acum, "error": rand["error"],
                     "findings_count": rand["findings_count"],
                     "target": rand["target"],
                     "ok_started_at": acum, "ok_finished_at": acum,
                     "ok_findings_count": rand["findings_count"],
                     "ok_target": rand["target"]}]

        async def fetchval(self, _sql, *args):
            return (acum - args[0]).total_seconds()

    cfg = SimpleNamespace(scan=SimpleNamespace(enabled=True))
    (r,) = run(checks.check_last_scan(_SelfcheckDB(), cfg))
    assert r.key == "scan:last:trivy_image"
    return out, db, r, set(flota)


def test_last_nights_fleet_ingests_ten_images_and_names_waha(
        gazda, monkeypatch) -> None:
    """Noaptea care a orbit panoul, rejucată cu cifrele ei reale ȘI cu plafonul ei.

    Eșecul pe care îl previne: 2540 de constatări pe 11 imagini față de plafonul
    de atunci, 2500 → «trivy image scan failed … nu se ingerează nimic» (exact
    ce au scris rândurile 208, 211 și 214, trei nopți la rând). Testul
    verifică ce face scanerul când suma DEPĂȘEȘTE bugetul — cade imaginea cea mai
    mare, `waha`, restul intră, garda ține deschise cele 1522 de rânduri ale ei,
    iar `scan:last:trivy_image` iese `degraded`, cu nume.

    Plafonul e FIXAT aici la 2500, nu citit din `MAX_FINDINGS`: ce descrie testul
    e forma nopții, nu valoarea de azi. Citit din constantă, testul a căzut în
    clipa în care bugetul a devenit mai mare decât flota (23 octombrie 2026), fiindcă
    flota încape — adică depindea de un număr pe care nu-l declara. Că 2540 încape
    sub bugetul real o spune testul de mai jos.
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 2500)
    out, db, r, flota = _the_fleet_of_25_october(gazda, monkeypatch)

    assert out["status"] == "completed", out
    assert out["findings"] == 938 and len(db.upserted) == 938
    assert "devlikeapro/waha:latest" not in {u["location"] for u in db.upserted}
    assert {u["location"] for u in db.upserted} == flota - {"devlikeapro/waha:latest"}
    assert out["skipped"] == ["devlikeapro/waha:latest"]
    # Garda ajunge la rezolvare: fără ea, cele 1522 de rânduri deschise ale lui
    # `waha` ar fi închise în noaptea în care nu s-a uitat nimeni la ele.
    (_sql, args_rezolvare) = db.resolve_calls[0]
    assert ["devlikeapro/waha:latest"] in [
        list(a) for a in args_rezolvare if isinstance(a, list)]

    assert r.status == "degraded", (
        "noaptea care înainte era roșie a devenit verde: " + r.status)
    assert "devlikeapro/waha:latest" in r.detail
    assert "34 CRITICAL" in r.detail and "918 HIGH" in r.detail
    assert "938 constatări" in r.detail and "10 din 11 imagini" in r.detail


def test_the_same_night_fits_whole_under_the_real_budget(
        gazda, monkeypatch) -> None:
    """Aceeași noapte, cu bugetul REAL: nicio imagine sărită, `ok`, nu `degraded`.

    Eșecul pe care îl previne: bugetul coborât (sau o constantă rescrisă) la nivelul
    flotei de azi — 2484 (22 oct), 2532 (23 oct), 2540 (25 oct), 2517 la o
    remasurare directă.
    Flota crește în trepte (vezi testul de mai jos), așa că un plafon lipit de ea
    cade la prima treaptă: `scan:last:trivy_image` trece `degraded`, runner-ul
    alertează, iar imaginea scoasă ar fi `waha`, cea cu 34 CRITICAL, ale cărei
    1522 de rânduri ar rămâne în panou învechite și nerezolvabile.

    Nu fixează bugetul: rulează cu cel din cod și spune ce se întâmplă cu flota
    măsurată. Dacă operatorul îl coboară, testul cade și trebuie să spună de ce.

    Totalul afirmat aici, 2540, e SCRIS LITERAL și nu citit din `FLEET_TOTAL`: e
    cifra din eroarea rândului 214, iar `FLEET_TOTAL` e ancora testului de buget de
    mai jos. Dacă ar fi derivat din aceeași sumă, cine coboară o imagine din flotă
    ca să coboare ancora ar coborî și aserțiunea, și nimic nu ar cădea.
    """
    out, db, r, flota = _the_fleet_of_25_october(gazda, monkeypatch)

    assert out["status"] == "completed", out
    assert out["skipped"] == [], (
        f"imagini sărite cu bugetul real {trivy_image.MAX_FINDINGS}: {out['skipped']}")
    assert out["findings"] == 2540 and len(db.upserted) == 2540
    assert {u["location"] for u in db.upserted} == flota
    (rand,) = db.finished
    assert rand["error"] is None, rand["error"]
    assert r.status == "ok", f"{r.status}: {r.detail}"
    assert "11 din 11 imagini" in r.detail, r.detail


# Totalurile rularilor `trivy_image` din `scans` de pe gazda, in ordine, pentru
# zece NOPTI CONSECUTIVE (citite pe 23 si 25 oct 2026; seria completa are 55 de
# rulari `completed`, 446-720 din 30 aug pana pe 16 oct):
#
#   16 oct 720 | 17 oct 1517 | 18 oct 1615 | 19 oct 1615 | 20 oct 1801 |
#   21 oct 1725 | 22 oct 2484 | 23 oct 2532 | 24 oct 2533 | 25 oct 2540
#
# ATENTIE: 23, 24 si 25 oct sunt nopti in care scanarea a REFUZAT (randurile
# `failed` 208, 211, 214; plafonul era 2500). Totalul lor e citit din textul
# `error` ("trivy a raportat N constatari"), NU din `findings_count`, care e 0 pe
# toate trei fiindca nu s-a ingerat nimic. Cine verifica in baza vede 0 si crede
# ca seria minte; nu minte.
#
# Fiecare salt mare e un EVENIMENT, nu zgomot: pe 17 oct a aparut `waha:latest`
# (800 din cele 806 randuri noi ale noptii), pe 20 oct `snipe-it` +186, pe 22 oct
# `waha` reimprospatata +698 si `snipe-it` +77. 2517 e o remasurare directa cu
# trivy a doua zi (nu e un rand din `scans`), deci nu intra in sir.
NIGHTLY_TOTALS = (720, 1517, 1615, 1615, 1801, 1725, 2484, 2532, 2533, 2540)
REMEASURED = 2517
# Calculat din sir, nu scris de mana: o cifra tastata se poate croi pe valoarea
# pe care o pazeste (1,44 = doar saltul din 22 oct a fost asa).
LARGEST_NIGHT_TO_NIGHT_GROWTH = max(
    later / earlier for earlier, later in zip(NIGHTLY_TOTALS, NIGHTLY_TOTALS[1:]))


def test_the_budget_covers_the_largest_observed_step() -> None:
    """Bugetul acoperă o noapte ca cea de azi crescută cu cea mai mare treaptă văzută.

    Eșecul pe care îl previne: un buget lipit de flota de azi (2600, 3000, 5000)
    trece testul cu flota rejucată și pică la prima treaptă — a doua apariție a
    unei imagini mari. Treapta cea mai mare din serie e 2,107 (16 → 17 oct, când a
    apărut `waha`), nu 1,44 (22 oct); cu 2540 × 2,107 = 5352 un buget de 5000 nu
    mai acoperă, `scan:last:trivy_image` trece `degraded`, runner-ul alertează, iar
    imaginea scoasă e cea mai mare, cea cu 34 CRITICAL.

    Cifrele sunt măsurători DATATE, nu o proprietate: dacă apare o treaptă mai
    mare, se adaugă în `NIGHTLY_TOTALS`, nu se slăbește aserțiunea. Nici un
    plafon fix nu e sigur la infinit — plasa pe imagine există pentru ce depășește.

    Ancora e `FLEET_TOTAL`, totalul flotei pe care o ingerează efectiv testele de
    comportament de mai sus, nu maximul unei liste: o listă tăiată (sau un
    `REMEASURED = 0`) cobora ancora și bugetul odată cu ea, cu 82 de teste verzi.
    Acum ancora se coboară doar schimbând imaginile fixture-ului, iar atunci pică
    testul care afirmă 2540 de constatări ingerate.
    """
    necesar = FLEET_TOTAL * LARGEST_NIGHT_TO_NIGHT_GROWTH
    assert trivy_image.MAX_FINDINGS >= necesar, (
        f"bugetul {trivy_image.MAX_FINDINGS} nu acoperă o noapte ca {FLEET_TOTAL} "
        f"crescută cu încă o treaptă de {LARGEST_NIGHT_TO_NIGHT_GROWTH:.3f}x "
        f"(= {necesar:.0f}); seria: {NIGHTLY_TOTALS}")


def test_the_fleet_fixture_is_not_older_than_the_newest_measurement() -> None:
    """Fixture-ul flotei nu rămâne în urma celei mai mari cifre măsurate.

    Eșecul pe care îl previne: apare o noapte de 2800, cineva o adaugă în
    `NIGHTLY_TOTALS` dar fixture-ul rămâne la 2540. Ancora bugetului (`FLEET_TOTAL`)
    ar fi atunci un număr deja depășit, iar testul de buget ar accepta un plafon
    prea mic pentru flota reală — `scan:last:trivy_image` ar trece `degraded` la
    prima treaptă și ar sări tocmai imaginea cu cele mai multe CRITICAL.

    Direcția e deliberat una singură: fixture-ul trebuie să fie ≥ maximul seriei.
    O noapte onestă mai MICĂ decât fixture-ul nu strică nimic, deci nu dă roșu
    (spre deosebire de `max(serie) == serie[-1]`, care ar da roșu fals).
    """
    cea_mai_mare = max(NIGHTLY_TOTALS + (REMEASURED,))
    assert FLEET_TOTAL >= cea_mai_mare, (
        f"fixture-ul flotei ({FLEET_TOTAL}) e mai mic decât cea mai mare cifră "
        f"măsurată ({cea_mai_mare}). Creșteți `FLEET_OF_25_OCTOBER` până la "
        f"{cea_mai_mare}, punând diferența pe imaginile care au crescut. "
        f"NU scurtați `NIGHTLY_TOTALS` și nu coborâți cifra măsurată ca să "
        f"treacă: fixture-ul e cea mai mare noapte măsurată VREODATĂ, nu flota "
        f"de azi, fiindcă bugetul trebuie să încapă și pe cea mai rea noapte "
        f"pe care am văzut-o. Dacă flota a scăzut onest, fixture-ul rămâne "
        f"unde e și testul ăsta tace.")


def test_the_series_keeps_its_largest_step() -> None:
    """Seria de mai sus păstrează saltul din 16 → 17 octombrie (2,107×).

    Eșecul pe care îl previne: cineva scurtează `NIGHTLY_TOTALS` ca să înceapă
    după 17 oct (sau o înlocuiește cu o cifră), iar factorul din testul de buget
    coboară la 1,44 fără ca vreun test să cadă — și atunci acceptă orice buget
    peste 3647. A fost exact defectul primei variante a testului, croită pe
    cifra pe care o păzea.
    """
    assert NIGHTLY_TOTALS[:2] == (720, 1517), NIGHTLY_TOTALS
    assert LARGEST_NIGHT_TO_NIGHT_GROWTH > 2.1, LARGEST_NIGHT_TO_NIGHT_GROWTH


def test_no_budget_number_is_written_into_the_scanner_logic() -> None:
    """Bugetul există într-un singur loc: constanta `MAX_FINDINGS`.

    Eșecul pe care îl previne: un `if total > 2500` (sau `Admission(6000)`) scris
    în logică. Operatorul schimbă `MAX_FINDINGS`, cifra din text și din
    `scans.error` se schimbă, iar scanerul continuă să decidă după alta — „nu a
    încăput" ar spune un buget, iar imaginile ar fi sărite după altul. Testele
    de comportament care monkeypatchuiesc constanta (10, 2) prind asta pentru
    `scan()`; ăsta o prinde oriunde altundeva în modul, inclusiv pe ramuri pe care
    nicio fixtură nu le atinge.

    Regula: orice literal întreg ≥ 1000 din modul e ÎNTREGUL membru drept al unei
    atribuiri la nivel de modul către un nume cu majuscule (`TIMEOUT_S = 3600`,
    `MAX_FINDINGS = 6000`). Plus: valoarea veche, 2500, nu mai apare ca întreg
    nicăieri. Ce NU prinde: un buget scris ca expresie (`25 * 100`) sau ca șir.
    """
    sursa = (ROOT / "sentinel" / "scan" / "trivy_image.py").read_text(encoding="utf-8")
    arbore = ast.parse(sursa)
    numite = {
        id(nod.value) for nod in arbore.body
        if isinstance(nod, ast.Assign) and isinstance(nod.value, ast.Constant)
        and all(isinstance(t, ast.Name) and t.id.isupper() for t in nod.targets)}
    mari = [nod for nod in ast.walk(arbore)
            if isinstance(nod, ast.Constant) and type(nod.value) is int
            and nod.value >= 1000]

    # Martorul pozitiv: regula chiar vede constantele pe care ar trebui să le
    # vadă. Fără el, un fișier mutat sau un parcurs gol ar face testul să treacă
    # pe nimic.
    assert trivy_image.MAX_FINDINGS in {nod.value for nod in mari}, (
        "regula nu vede literalul lui MAX_FINDINGS — testul ar trece pe nimic")
    assert any(id(nod) in numite for nod in mari)

    ratacite = [(nod.lineno, nod.value) for nod in mari if id(nod) not in numite]
    assert not ratacite, (
        f"literale întregi ≥ 1000 în afara unei constante de modul: {ratacite} — "
        f"un buget scris în logică nu se schimbă odată cu `MAX_FINDINGS`")
    vechi = [nod.lineno for nod in mari if nod.value == 2500]
    assert not vechi, f"2500 (bugetul de până pe 23 octombrie 2026) apare la {vechi}"


def test_the_budget_edges_are_inclusive() -> None:
    """Exact cât bugetul încape; un singur rând în plus nu.

    Eșecul pe care îl previne: `>` devenit `>=` într-una din cele două
    comparații. O imagine cu exact `MAX_FINDINGS` constatări ar fi sărită ca și
    cum ar depăși, iar o flotă a cărei sumă e exact bugetul ar pierde imaginea
    cea mai mare — adică un plafon de 2500 care se comportă ca unul de 2499, fără
    ca vreo cifră din text să arate asta.
    """
    singura = trivy_image.Admission(10)
    singura.offer(*_fake_image("x", 10))
    assert [sk.reference for sk in singura.skipped] == []
    assert singura.coverage(1)["ingested"] == ["x"]

    peste = trivy_image.Admission(10)
    peste.offer(*_fake_image("x", 11))
    assert [(sk.reference, sk.reason) for sk in peste.skipped] == [
        ("x", trivy_image.REASON_IMAGE)]

    suma = trivy_image.Admission(10)
    suma.offer(*_fake_image("a", 3))
    suma.offer(*_fake_image("b", 7))
    assert suma.skipped == [] and suma.total() == 10

    mai_mult = trivy_image.Admission(10)
    mai_mult.offer(*_fake_image("a", 3))
    mai_mult.offer(*_fake_image("b", 8))
    assert [(sk.reference, sk.reason) for sk in mai_mult.skipped] == [
        ("b", trivy_image.REASON_BUDGET)]


def test_a_long_list_of_skipped_images_is_named_up_to_a_count_bound() -> None:
    """Textul de pe rând și din `/selfcheck` nu crește cu flota.

    Eșecul pe care îl previne: patruzeci de imagini sărite scrise toate, într-o
    coloană care pleacă spre agregator cu o limită de 64 KB per coloană —
    depășită, valoarea e REFUZATĂ, nu tăiată — și într-un mesaj de Telegram. Cele
    mai mari (cele care contează) sunt numite primele; restul se numără, nu
    dispar.
    """
    cov = _coverage(images=40, ingested=("mica",), admitted=1, skipped=[
        (f"i-{i:02d}", 100 + i, 0, 0, 0) for i in range(39)])
    cov["skipped"].sort(key=lambda sk: -sk["findings"])
    text = trivy_image.coverage_caveat(cov, held_open=1000)

    assert text.count("constatări)") == trivy_image.MAX_NAMED_SKIPPED, (
        "numărul de imagini numite nu e cel din margine")
    assert "și încă 29 nenumite" in text, "cele peste margine nu sunt numărate"
    assert "i-38 (138" in text, "nu s-a numit cea mai mare"
    assert "i-00 (" not in text
    assert "(1000)" in text and "Ingerate (1)" in text, (
        "propozițiile de după nume au dispărut din text")


def test_long_names_cannot_push_the_closing_sentences_out_of_the_text() -> None:
    """Numele lungi sunt tăiate ele, nu propozițiile care vin după ele.

    Eșecul pe care îl previne: zece referințe de registry de câte o sută de
    caractere umplu singure textul, iar o tăiere la sfârșit scoate chiar
    propoziția care spune câte rânduri au rămas deschise și lista imaginilor
    ingerate. Prins de un test care punea toate cele 39 de nume lungi și nu mai
    găsea nici «și încă 29».
    """
    cov = _coverage(images=40, ingested=("mica",), admitted=1, skipped=[
        (f"registry.example/echipa/imagine-cu-nume-lung-{i:02d}:latest", 100 + i, 1, 2, 3)
        for i in range(39)])
    cov["skipped"].sort(key=lambda sk: -sk["findings"])
    text = trivy_image.coverage_caveat(cov, held_open=1000)

    assert len(text) <= trivy_image.MAX_ROW_TEXT
    assert 0 < text.count("imagine-cu-nume-lung") < trivy_image.MAX_NAMED_SKIPPED, (
        "marginea pe caractere nu a limitat numele")
    assert "imagine-cu-nume-lung-38" in text
    assert "nenumite aici" in text
    assert "(1000)" in text and "Ingerate (1)" in text and not text.endswith("…")

    uriasa = "r/" + "x" * 3000
    text = trivy_image.coverage_caveat(
        _coverage(skipped=[(uriasa, 5, 0, 5, 0)]), held_open=5)
    assert len(text) <= trivy_image.MAX_ROW_TEXT
    assert "x" * 200 not in text, "o referință uriașă a intrat întreagă în text"
    assert uriasa[:50] in text and "(5)" in text


def test_each_reason_for_skipping_is_said_in_its_own_words() -> None:
    """„Peste tot bugetul" și „nu a încăput laolaltă" cer remedii diferite.

    Eșecul pe care îl previne: ambele scrise ca „peste plafon". O imagine care
    singură depășește tot bugetul rămâne sărită orice ar face celelalte (se
    rezolvă prin imagine sau prin prag); una care doar n-a încăput revine când
    suma scade (se rezolvă prin buget). Operatorul care le citește la fel ia
    decizia greșită pentru una dintre ele.
    """
    cov = _coverage(skipped=[("uriasa", 9000, 1, 2, 3), WAHA, ("raport", 0, 0, 0, 0)])
    cov["skipped"][0]["reason"] = trivy_image.REASON_IMAGE
    cov["skipped"][2].update(reason=trivy_image.REASON_REPORT, findings=None)
    text = trivy_image.coverage_caveat(cov, held_open=3)

    assert "depășește singură tot plafonul" in text
    assert text.index("depășește singură") < text.index("uriasa")
    assert "încape singură, dar nu și laolaltă" in text
    assert text.index("încape singură") < text.index("devlikeapro/waha:latest")
    assert "raportul trivy e prea mare" in text
    assert "raport (numărul de constatări nu se știe" in text, (
        "un raport necitit e scris cu un număr inventat")

    # Singular și plural nu se amestecă într-o propoziție pentru operator.
    una = trivy_image.coverage_caveat(_coverage(skipped=[WAHA]), held_open=1)
    assert una.startswith("1 imagine din 2 NU a fost ingerată")
    assert "încape singură" in una and "încap singure" not in una
    # Nicio imagine ingerată se spune, nu se lasă o listă goală după două puncte.
    nimic = trivy_image.coverage_caveat(
        _coverage(skipped=[WAHA], ingested=()), held_open=1)
    assert "Ingerate (0): niciuna." in nimic


def test_the_hard_cap_on_the_row_text_holds_even_if_the_other_bounds_fail(
        monkeypatch) -> None:
    """Ultima plasă are propriul test, fiindcă nimic altceva nu o atinge.

    Eșecul pe care îl previne: marginile pe nume (număr, caractere, lungimea
    referinței) ajung la ~1600 de caractere; plafonul dur de 2000 nu se atinge
    niciodată cu ele întregi. O apărare pe care nicio intrare reală n-o declanșează
    poate fi ștearsă fără ca vreun test să pice — așa că aici marginile sunt
    ridicate și plafonul coborât, ca să se vadă că tăie și că o spune (`…`).
    """
    monkeypatch.setattr(trivy_image, "MAX_NAMED_SKIPPED_CHARS", 10**6)
    monkeypatch.setattr(trivy_image, "MAX_REFERENCE_CHARS", 10**6)
    monkeypatch.setattr(trivy_image, "MAX_ROW_TEXT", 300)
    text = trivy_image.coverage_caveat(
        _coverage(skipped=[("r/" + "x" * 3000, 5, 0, 5, 0)]), held_open=5)
    assert len(text) == 300 and text.endswith("…")
