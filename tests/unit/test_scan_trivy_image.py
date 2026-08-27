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

    # Fără fix publicat: None, nu "" — `prioritize.score` dă +5 pentru un fix.
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
    assert argv[argv.index("--severity") + 1] == ",".join(trivy_fs.SEVERITIES)


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


def test_more_findings_than_the_cap_are_refused_and_not_truncated(
        gazda, monkeypatch) -> None:
    """O listă tăiată e mai periculoasă decât niciuna.

    Eșecul pe care îl previne: 3000 de constatări tăiate la plafon ar fi urmate de
    `mark_resolved_absent`, care ar marca restul drept REZOLVATE. Panoul ar arăta
    mai puține vulnerabilități tocmai fiindcă sunt mai multe.
    """
    monkeypatch.setattr(trivy_image, "MAX_FINDINGS", 2)
    gazda.containers([("a" * 64, IMG_NGINX, "nginx:1.27", "web")])
    gazda.reports["*"] = SAMPLE
    items, eroare, fapte = run(trivy_image.scan())

    assert items == []
    assert eroare and "plafonul de 2" in eroare
    assert fapte["total"] == 3, "numărul real trebuie să ajungă pe rândul `failed`"


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
    """Ciot de bază care ține minte ce s-a scris. Nu asertează nimic singur."""

    def __init__(self) -> None:
        self.scans: list[dict] = []
        self.finished: list[dict] = []
        self.upserted: list[dict] = []
        self.resolved: list[tuple] = []

    async def fetchval(self, sql, *args):
        if "INSERT INTO scans" in sql:
            self.scans.append({"scanner": args[0], "target": args[1],
                               "triggered_by": args[3]})
            return len(self.scans)
        return 0

    async def fetchrow(self, sql, *args):
        self.upserted.append({"finding_key": args[0], "scanner": args[2],
                              "cve": args[3], "location": args[16]})
        return {"is_new": True, "status": "open"}

    async def fetch(self, sql, *args):
        if "SET status = 'resolved'" in sql:
            self.resolved.append((args[0], args[1], args[2]))
        return []

    async def execute(self, sql, *args):
        if "UPDATE scans SET" in sql:
            self.finished.append({"id": args[0], "status": args[1],
                                  "findings_count": args[2], "error": args[6],
                                  "db_version": args[7]})


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
    assert db.scans == [{"scanner": "trivy_image",
                         "target": "docker: imaginile containerelor în rulare",
                         "triggered_by": "test"}]


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
