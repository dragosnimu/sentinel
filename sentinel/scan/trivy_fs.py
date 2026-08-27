"""Filesystem vulnerabilities via `trivy fs` — the application dependencies dnf
cannot see.

## Why this scanner exists, and what it deliberately does NOT do

`os_packages.py` already answers "which RPMs need a security update", and its
docstring says why trivy must not be asked the same question: trivy matches
version strings, the vendor backports fixes without bumping them, and the result
is a wall of false positives that teaches the operator to stop reading the list.

So this scanner is pointed at the other half of the machine — the code the
operator deployed. npm, pip, composer, go, cargo lockfiles under
`scan.discovery_paths`. dnf knows nothing about any of them, and nothing else on
this host does either.

That is also why the command is `trivy fs <path>` and not `trivy rootfs /`:

  * `rootfs` declares "this directory is the root of a system" and turns the OS
    package database back on — the duplicate, false-positive answer above;
  * `/` would also mean walking every file on the host against `MemoryMax=1G`,
    to re-derive what dnf gives in 2,4 seconds;
  * `image` is for containers (`scan.containers`, not wired yet) and `repo`
    clones a remote git URL over the network, which is a different target.

JSON to a file, never text: `--format json --output <file>`. To a file rather
than to stdout so the size can be checked with `stat` BEFORE it is read into
this process — a JSON blob big enough to matter is a memory problem, and reading
it to find out how big it is defeats the check.

## Absence of a result is never reported as a clean host

Three outcomes, and the caller records all three:

    findings, error=None   trivy looked and this is what it saw
    [],       error=None   trivy looked and there was nothing
    [],       error="..."  trivy could NOT look — NOT the same as clean

The binary missing, no configured path existing, trivy exiting non-zero on a
path that does exist, the time budget running out before every path was
reached, output too large to parse, more findings than the cap, or a
vulnerability database whose age cannot be proved: every one of them is the
third case. The orchestrator writes a `failed` row and resolves nothing, so a
run that could not look never closes a finding.

## The vulnerability database is checked AFTER the scan, on purpose

trivy refreshes its database from ghcr.io on demand. On a host that lost egress
it keeps running against whatever it cached — and reports a clean-looking result
from data that predates the CVE being asked about. That is this repository's
house defect wearing a different hat, so the age is not assumed, it is read:

  * the scan runs first, because that is what refreshes the database;
  * then `trivy version --format json` is asked how old the database it just
    used is, falling back to `<cache>/db/metadata.json` if the CLI shape ever
    changes — two independent sources, and only both failing means "unknown";
  * "unknown" is an error, not a pass. `MAX_DB_AGE_H` is an error too.

`--skip-db-update` is deliberately NOT passed. It would freeze the database and
make the failure permanent and invisible; letting trivy refresh means a healthy
host stays fresh and a broken one trips the gate above.

Read-only throughout. This lists what is vulnerable; applying a fix is the patch
pipeline (P9), behind explicit approval.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.db.repo import findings as fx
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

#: Numele scanerului. Ajunge in `scans.scanner` si `findings.scanner`, iar
#: `check_last_scan` raporteaza sub `scan:last:{scanner}` — deci schimbarea lui
#: schimba si cheia din `/selfcheck` si din panou, si desparte constatarile de
#: aici de cele scrise pana atunci. Vocabularul e cel din migratia 0003.
SCANNER = "trivy_fs"

#: Unde pasul 21 pune binarul (`TOOLS_BIN_DIR`, implicit /usr/local/bin).
BINARY = "/usr/local/bin/trivy"

#: Cache-ul propriu de baza de vulnerabilitati.
#:
#: Creat de systemd prin `CacheDirectory=sentinel-trivy` in
#: `deploy/systemd/sentinel-scan.service`. Fara el, trivy scrie in
#: `$HOME/.cache/trivy`, iar sub `ProtectSystem=strict` acolo nu se poate scrie:
#: fiecare rulare ar reincerca descarcarea si ar esua. Cu el, baza se descarca o
#: data si se reimprospateaza incremental.
#:
#: Calea e repetata aici fiindca trivy o cere ca argument, iar
#: `test_scan_trivy_fs.py` cere ca cele doua sa fie ACEEASI — despartite, una
#: s-ar muta si cealalta ar scrie intr-un director pe care nu-l mai creeaza nimeni.
CACHE_DIR = "/var/cache/sentinel-trivy"

#: Plafonul nostru pentru o rulare intreaga, masurat ca TERMEN de ceas peste
#: toate caile — nu ca plafon per cale.
#:
#: `sentinel-scan.service` are `TimeoutStartSec=14400`. Bugetul unitatii se
#: imparte intre scanere, iar unul lent nu are voie sa omoare fereastra
#: celorlalti — de aceea fiecare scaner are plafonul lui, sub al unitatii, si
#: suma lor e legata de unitate printr-un test.
#:
#: Per cale, suma aia n-ar fi legata de nimic: `scan.discovery_paths` e
#: configuratie, iar nimic din cod nu-i marmureste lungimea. Cu implicitul de
#: patru cai plafonul REAL ar fi 4 x 1800, cu opt ar fi 8 x 1800 — adica peste
#: bugetul intregii unitati, iar `trivy_image` si ce vine dupa el n-ar mai apuca
#: sa ruleze deloc. E acelasi rationament ca la `trivy_image.TIMEOUT_S` si din
#: acelasi motiv: un plafon per element inmulteste bugetul cu numarul de
#: elemente, iar numarul de elemente nu-l alege cine a calculat bugetul.
#:
#: Deosebirea fata de imagini e de unde vine numarul: containerele se descopera
#: de pe gazda si au si un refuz explicit (`MAX_CONTAINERS`), pe cand caile le
#: scrie operatorul in configuratie — deci un refuz peste N cai ar transforma o
#: linie de configuratie legitima intr-o scanare care nu mai ruleaza. Termenul
#: de ceas margineste rularea fara sa refuze vreo configuratie.
#:
#: Ce se pierde: o cale lenta poate manca termenul si lasa restul nescanate.
#: Atunci rularea e o EROARE, nu un rezultat partial — exact ca o cale pe care
#: trivy a esuat, si din acelasi motiv: `mark_resolved_absent` ar inchide tot ce
#: statea sub caile la care nu s-a mai ajuns.
TIMEOUT_S = 1800

#: Plafonul pe care i-l dam LUI trivy, per cale. Sub al nostru dinadins: trivy
#: care se opreste singur scrie un mesaj de eroare pe care il putem raporta;
#: trivy omorat de noi lasa doar „timeout". Ordinea asta e diferenta dintre un
#: rand `failed` care spune ce s-a intamplat si unul care nu spune nimic.
#:
#: E un MAXIM, nu valoarea data mereu: ce primeste efectiv o cale e
#: `min(TRIVY_TIMEOUT_S, cat a mai ramas din termen)`, altfel ultima cale ar
#: putea trece singura peste termenul intregii rulari.
TRIVY_TIMEOUT_S = 840

#: Cat ii mai dam lui trivy dupa termenul LUI, ca sa apuce sa scrie eroarea
#: inainte sa-l omoram noi. Acelasi rol ca `trivy_image.TRIVY_GRACE_S`.
TRIVY_GRACE_S = 60

#: Cat asteptam dupa `trivy version` — o citire locala, nu o scanare.
VERSION_TIMEOUT_S = 60

#: Ce severitati cere trivy. Filtrul e la SURSA, nu la ingestie.
#:
#: La ingestie, ieftin nu e: trivy tot serializeaza fiecare constatare in JSON,
#: iar fisierul e citit intreg in proces inainte sa avem ce filtra — adica exact
#: costul de memorie de care ne pazim, platit integral ca sa aruncam rezultatul.
#: La sursa, randurile nici nu se nasc.
#:
#: `UNKNOWN` e INCLUS, si nu din neatentie: o vulnerabilitate careia nimeni nu
#: i-a dat inca o nota nu e una neimportanta. Scoasa din filtru, ar disparea
#: tacut — „nu stiu" citit ca „nu conteaza", fix ce interzice CLAUDE.md. Ce se
#: intampla cu ea la mapare e mai jos, la `map_severity`.
#:
#: `LOW` lipseste: pe un arbore de dependinte real e majoritatea volumului, si e
#: categoria pe care panoul n-a facut pe nimeni s-o repare vreodata.
SEVERITIES = ("UNKNOWN", "MEDIUM", "HIGH", "CRITICAL")

#: Plafonul de volum, ca REFUZ, nu ca trunchiere.
#:
#: O lista taiata la 500 din 3000 ar fi urmata de `mark_resolved_absent`, care ar
#: marca celelalte 2500 drept rezolvate — panoul ar arata mai putine
#: vulnerabilitati tocmai fiindca sunt prea multe. Deci peste plafon nu se
#: ingereaza nimic, se scrie un rand `failed` cu numarul real, si constatarile de
#: pana atunci raman deschise. Operatorul restrange `scan.discovery_paths` sau
#: ridica pragul de severitate; ce nu se intampla e ca discul sa se umple in
#: liniste in fiecare noapte.
MAX_FINDINGS = 500

#: Peste atat, iesirea nu se mai citeste in proces. `MemoryMax=1G` e a intregii
#: unitati, iar un `json.loads` pe 200 MB de text costa un multiplu din ei.
MAX_OUTPUT_BYTES = 64 * 1024 * 1024

#: Descrierile din baza trivy pot avea kilobytes. Taiate: coloana e text, dar
#: `findings` are retentie si e citita in panou.
MAX_DESCRIPTION = 2000

#: Peste cate ore baza de vulnerabilitati nu mai raspunde la intrebarea de azi.
#:
#: Doua saptamani. Upstream publica la 6 ore, deci o baza mai veche de atat
#: inseamna ca gazda n-a mai putut ajunge la ghcr.io de doua saptamani — o pana,
#: nu o intarziere. Peste prag scanarea se raporteaza `failed`: nu fiindca ce a
#: gasit ar fi fals, ci fiindca ce NU a gasit nu mai e o dovada de nimic, iar
#: `scans.status` n-are o valoare care sa insemne „incheiata, dar partial oarba".
MAX_DB_AGE_H = 14 * 24

#: De la cate ore se scrie un avertisment in jurnal, cat inca nu e pana.
WARN_DB_AGE_H = 48

#: Cat inainte are voie sa fie data bazei fata de ceasul nostru. Peste atat, unul
#: dintre cele doua ceasuri minte, si atunci nici varsta calculata din ele nu e o
#: masuratoare — deci nu se raporteaza ca una.
MAX_CLOCK_SKEW_H = 2

#: UNKNOWN lipseste dinadins; vezi `map_severity`.
_SEV = {"critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "negligible": "info"}

#: `Result.Type` al lui trivy -> vocabularul din migratia 0003.
_ECOSYSTEM = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "bun": "npm",
    "pip": "pypi", "poetry": "pypi", "pipenv": "pypi", "python-pkg": "pypi",
    "uv": "pypi",
    "composer": "composer", "composer-vendor": "composer",
    "gomod": "go", "gobinary": "go",
    "rpm": "rpm", "redhat": "rpm", "alma": "rpm", "rocky": "rpm",
    "oracle": "rpm", "amazon": "rpm", "centos": "rpm",
    "dpkg": "deb", "debian": "deb", "ubuntu": "deb",
    "jar": "maven", "pom": "maven", "gradle": "maven", "sbt": "maven",
    "cargo": "cargo", "nuget": "nuget", "dotnet-core": "nuget",
    "gemspec": "rubygems", "bundler": "rubygems",
}

#: Ordinea in care se crede un scor CVSS cand mai multi furnizori dau cate unul.
#: NVD intai fiindca e sursa neutra; restul sunt evaluari de vendor, iar un vendor
#: coboara scorul pentru distributia LUI, ceea ce aici ar fi o subestimare.
_CVSS_ORDER = ("nvd", "ghsa", "redhat", "oracle-oval", "bitnami", "cna")

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_TS = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|z|[+-]\d{2}:?\d{2})?$")


def _parse_ts(value: Any) -> datetime | None:
    """RFC3339 asa cum il scrie trivy, inclusiv nanosecunde.

    `datetime.fromisoformat` refuza fractiunile de 9 cifre, iar trivy le scrie —
    si un parser care crapa pe ele ar transforma o baza proaspata in „varsta
    necunoscuta", adica intr-o scanare esuata in fiecare noapte.
    """
    if not isinstance(value, str):
        return None
    m = _TS.match(value.strip())
    if not m:
        return None
    frac = (m.group("frac") or "0")[:6].ljust(6, "0")
    tz = (m.group("tz") or "Z").upper()
    if tz == "Z":
        offset = timezone.utc
    else:
        digits = tz.replace(":", "")
        sign = -1 if digits[0] == "-" else 1
        offset = timezone(sign * timedelta(hours=int(digits[1:3]),
                                           minutes=int(digits[3:5])))
    base = m.group("base").replace(" ", "T")
    try:
        naive = datetime.strptime(f"{base}.{frac}", "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return None
    return naive.replace(tzinfo=offset)


def map_severity(raw: Any) -> tuple[str, bool]:
    """Severitatea trivy -> (severitatea noastra, s-a stiut).

    `UNKNOWN` — si orice eticheta pe care n-o cunoastem — devine `medium`, cu
    `False` pe al doilea membru. E acelasi tratament pe care il da `os_packages`
    unei linii de advisory cu severitate necunoscuta (`_SEV.get(..., "medium")`)
    si acelasi implicit pe care il are coloana in migratia 0003.

    De ce nu `info`: `info` e o AFIRMATIE — „ne-am uitat, e neglijabil" — iar
    `UNKNOWN` e lipsa unei afirmatii. Puse in aceeasi galeata, tot ce nu e inca
    evaluat ajunge sub orice filtru de triaj si nu se mai uita nimeni la el.
    `medium` il tine in campul vizual; steagul din `raw` face ca cele doua stari
    sa ramana deosebite pentru cine se uita.
    """
    known = _SEV.get(str(raw).strip().lower())
    return (known, True) if known else ("medium", False)


def _cvss(entry: dict[str, Any]) -> tuple[float | None, str | None]:
    """Scorul si vectorul CVSS, din ACELASI furnizor.

    Nu cel mai mare scor langa cel mai lung vector: un scor de la NVD langa un
    vector de la Red Hat e o pereche care nu descrie nicio evaluare reala, si e
    chiar genul de rand pe care un operator il verifica si nu-l regaseste nicaieri.
    """
    table = entry.get("CVSS")
    if not isinstance(table, dict):
        return None, None
    order = [k for k in _CVSS_ORDER if k in table]
    order += sorted(k for k in table if k not in _CVSS_ORDER)
    for vendor in order:
        block = table.get(vendor)
        if not isinstance(block, dict):
            continue
        for score_key, vector_key in (("V4Score", "V4Vector"),
                                      ("V3Score", "V3Vector"),
                                      ("V2Score", "V2Vector")):
            score = block.get(score_key)
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                continue
            # Coloana e `numeric(3,1) CHECK (cvss BETWEEN 0 AND 10)`: un scor in
            # afara intervalului ar face `upsert_finding` sa arunce, adica o
            # singura constatare stricata ar opri toata ingestia.
            clamped = round(min(10.0, max(0.0, float(score))), 1)
            vector = block.get(vector_key)
            return clamped, (str(vector) if isinstance(vector, str) else None)
    return None, None


def _ecosystem(result_type: Any) -> str | None:
    if not isinstance(result_type, str) or not result_type.strip():
        return None
    raw = result_type.strip().lower()
    # Un tip nou al lui trivy se pastreaza ca atare in loc sa devina None:
    # „ecosistem pe care nu-l cunosc" e o informatie, absenta lui nu e.
    return _ECOSYSTEM.get(raw, raw)


def parse(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Un raport JSON al lui trivy -> constatari, in forma din `findings`.

    Functie PURA, ca sa poata fi probata pe iesire reala fara binarul si fara
    reteaua de care depinde el.
    """
    items: dict[str, dict[str, Any]] = {}
    results = payload.get("Results")
    if not isinstance(results, list):
        # `"Results": null` e ce scrie trivy cand nu a potrivit nimic. E un
        # rezultat gol, nu unul stricat.
        return []

    for result in results:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        ecosystem = _ecosystem(result.get("Type"))
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            # trivy omite cheia pentru o tinta curata. „Nimic aici", nu o eroare.
            continue

        for entry in vulns:
            if not isinstance(entry, dict):
                continue
            vuln_id = entry.get("VulnerabilityID")
            if not isinstance(vuln_id, str) or not vuln_id.strip():
                continue
            vuln_id = vuln_id.strip()
            package = entry.get("PkgName")
            package = package.strip() if isinstance(package, str) else ""
            # Calea pachetului daca o stim, altfel fisierul in care a fost gasit.
            raw_location = entry.get("PkgPath") or target
            location = str(raw_location) if raw_location else None

            cve = vuln_id if _CVE.match(vuln_id) else None
            severity, severity_known = map_severity(entry.get("Severity"))
            cvss, vector = _cvss(entry)
            fixed = entry.get("FixedVersion")
            installed = entry.get("InstalledVersion")
            title = entry.get("Title")
            description = entry.get("Description")

            # Cheia primeste `vuln_id`, NU coloana `cve`: un GHSA fara CVE ar
            # trimite None acolo, iar doua avize diferite pe acelasi pachet si
            # aceeasi cale ar produce aceeasi cheie — al doilea l-ar suprascrie
            # pe primul si o vulnerabilitate ar disparea fara urma.
            key = fx.finding_key(SCANNER, None, package or None, vuln_id, location)
            if key in items:
                continue

            items[key] = {
                "scanner": SCANNER,
                "cve": cve,
                "advisory_id": None if cve else vuln_id,
                "title": (title.strip()
                          if isinstance(title, str) and title.strip()
                          else f"{vuln_id} în {package or 'pachet necunoscut'}"),
                "description": (description[:MAX_DESCRIPTION]
                                if isinstance(description, str) and description.strip()
                                else None),
                "severity": severity,
                "cvss": cvss,
                "cvss_vector": vector,
                "package": package or None,
                "installed_version": (installed.strip()
                                      if isinstance(installed, str) and installed.strip()
                                      else None),
                # Sirul gol al lui trivy inseamna „nu exista fix publicat", iar
                # `prioritize.score` da +5 pentru un fix disponibil. Pastrat ca ""
                # ar fi citit tot ca fals de Python, dar in baza si in panou ar
                # arata ca o versiune goala — deci None, ca sa insemne acelasi
                # lucru peste tot.
                "fixed_version": (fixed.strip()
                                  if isinstance(fixed, str) and fixed.strip()
                                  else None),
                "location": location,
                "ecosystem": ecosystem,
                "finding_key": key,
                "raw": {
                    "vulnerability_id": vuln_id,
                    "severity_known": severity_known,
                    "severity_source": entry.get("SeveritySource"),
                    "primary_url": entry.get("PrimaryURL"),
                    "status": entry.get("Status"),
                    "target": target,
                    "class": result.get("Class"),
                    "trivy_type": result.get("Type"),
                },
            }
    return list(items.values())


async def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """O comanda cu un plafon EXPLICIT de asteptare.

    `timeout` n-are implicit dinadins. Cat asteptam depinde de ce rulam si de cat
    a mai ramas din termenul rularii, iar un implicit egal cu bugetul intregii
    rulari e chiar felul in care plafonul „pe rulare” ajunsese sa se aplice pe
    fiecare cale in parte.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def resolve_binary() -> str | None:
    """Calea binarului trivy, sau None daca nu e nicaieri.

    Rezolvata O DATA si dusa mai departe la fiecare comanda: poarta care
    raspunde „e instalat" si comanda care chiar se executa trebuie sa vorbeasca
    despre acelasi fisier. Despartite, garda ar putea trece pe `which` iar
    `exec` ar cadea pe `BINARY` — si atunci randul `failed` ar spune
    „FileNotFoundError" in loc de „trivy nu e instalat", adica un simptom in loc
    de cauza, in singurul loc unde operatorul se uita.
    """
    if os.path.exists(BINARY):
        return BINARY
    return shutil.which("trivy")


def build_argv(path: str, output: str, binary: str = BINARY,
               timeout_s: int = TRIVY_TIMEOUT_S) -> list[str]:
    """Comanda pentru o cale. Separata ca sa poata fi aserteata fara sa ruleze.

    `timeout_s` e parametru fiindca ultimei cai i se da doar cat a mai ramas din
    termenul rularii, nu plafonul intreg.
    """
    return [
        binary,
        "--cache-dir", CACHE_DIR,
        "fs",
        "--quiet",
        # Doar vulnerabilitati. `secret` si `misconfig` sunt scanere separate in
        # configuratie (`scan.secrets`), si pornite aici si-ar scrie constatarile
        # sub numele asta — un scaner care raporteaza munca altuia.
        "--scanners", "vuln",
        "--format", "json",
        "--output", output,
        "--severity", ",".join(SEVERITIES),
        # Fara apeluri de retea in timpul potrivirii (Maven Central, pentru
        # dependintele Java). Baza de vulnerabilitati se reimprospateaza in
        # continuare; ce se opreste aici sunt interogarile per-artefact, care pe
        # o gazda fara iesire nu esueaza repede, ci atarna pana la plafon.
        "--offline-scan",
        "--timeout", f"{timeout_s}s",
        # `--` inainte de cale: o cale de configuratie care incepe cu `-` ar fi
        # citita ca un steag, si atunci scanarea ar face altceva decat scrie aici.
        "--", path,
    ]


async def _db_metadata(binary: str = BINARY) -> tuple[dict[str, Any] | None, str]:
    """Metadatele bazei de vulnerabilitati: (dict, de unde).

    Doua surse fiindca prima e o interfata de linie de comanda, iar a doua un
    fisier pe disc: daca trivy schimba forma iesirii lui `version`, fisierul tot
    raspunde, si invers. Amandoua tacute inseamna ca varsta chiar nu se poate afla.
    """
    rc, out, _err = await _run(
        [binary, "--cache-dir", CACHE_DIR, "version", "--format", "json"],
        timeout=VERSION_TIMEOUT_S)
    if rc == 0 and out.strip():
        try:
            payload = json.loads(out)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            meta = payload.get("VulnerabilityDB")
            if isinstance(meta, dict) and meta:
                return meta, "trivy version --format json"

    path = os.path.join(CACHE_DIR, "db", "metadata.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None, ""
    if isinstance(payload, dict) and payload:
        return payload, path
    return None, ""


async def db_status(now: datetime | None = None,
                    binary: str = BINARY) -> tuple[str | None, float | None, str | None]:
    """(descrierea bazei, varsta in ore, eroare).

    Eroarea nu inseamna „a picat ceva": inseamna „nu pot dovedi ca baza asta stie
    ce s-a publicat saptamana trecuta". Apelantul o trateaza ca pe orice alta
    imposibilitate de a se uita.
    """
    meta, source = await _db_metadata(binary)
    if meta is None:
        return None, None, (
            "nu pot afla vechimea bazei de vulnerabilități trivy: nici "
            "`trivy version --format json`, nici "
            f"{CACHE_DIR}/db/metadata.json nu au răspuns cu metadate. Fără ea, "
            "un rezultat curat n-ar dovedi nimic")

    # `UpdatedAt` e cand a fost CONSTRUITA baza upstream; `DownloadedAt` doar
    # cand am luat-o noi. Intrebarea e ce STIE baza, deci prima intai, si abia
    # apoi a doua — care e mereu mai noua, adica raspunsul mai indulgent.
    stamp = _parse_ts(meta.get("UpdatedAt")) or _parse_ts(meta.get("DownloadedAt"))
    version = meta.get("Version")
    if stamp is None:
        return None, None, (
            f"metadatele bazei trivy (din {source}) nu conțin o dată lizibilă în "
            f"`UpdatedAt`/`DownloadedAt`, deci nu pot spune dacă baza e de azi "
            f"sau de acum trei luni")

    now = now or datetime.now(timezone.utc)
    age_h = (now - stamp).total_seconds() / 3600.0
    described = (f"trivy-db v{version} construită "
                 f"{stamp.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%SZ} "
                 f"(vechime {age_h:.0f}h)")

    if age_h < -MAX_CLOCK_SKEW_H:
        return described, age_h, (
            f"data bazei trivy e în viitor cu {-age_h:.0f}h față de ceasul "
            f"acestei gazde; unul dintre ceasuri e greșit, deci vechimea "
            f"calculată nu e o măsurătoare")
    return described, age_h, None


async def scan(paths: list[str]) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """Ruleaza trivy peste `paths`. Intoarce (constatari, eroare, fapte).

    `fapte` poarta `db_version` chiar si pe drumurile de eroare, ca randul
    `failed` din `scans` sa spuna pe ce baza de date s-a lucrat.
    """
    facts: dict[str, Any] = {"db_version": None, "paths": [], "total": 0}

    binary = resolve_binary()
    if binary is None:
        # Un binar lipsa NU e o gazda curata. Pasul 21 il instaleaza; daca nu e
        # acolo, ce lipseste e scanarea, nu vulnerabilitatile.
        return [], (f"trivy nu e instalat ({BINARY} lipsește) — scanarea de "
                    f"fișiere nu a putut rula, deci lista ei nu spune nimic "
                    f"despre starea gazdei"), facts

    wanted = [p for p in (paths or []) if isinstance(p, str) and p.strip()]
    if not wanted:
        return [], ("`scan.discovery_paths` e goală, deci nu s-a scanat nimic; o "
                    "listă goală de constatări ar fi fost citită ca „gazdă "
                    "curată”"), facts

    present = [p for p in wanted if os.path.isdir(p)]
    if not present:
        return [], ("niciuna dintre căile din `scan.discovery_paths` nu există pe "
                    f"gazdă ({', '.join(wanted)}) — nu s-a scanat nimic"), facts
    facts["paths"] = present

    workdir = tempfile.mkdtemp(prefix="sentinel-trivy-")
    items: list[dict[str, Any]] = []
    # Un singur termen peste toate caile (vezi `TIMEOUT_S`). `VERSION_TIMEOUT_S`
    # se scade din el fiindca dupa bucla mai urmeaza o comanda — `db_status` —
    # si fara rezerva asta o rulare care isi cheltuie bugetul in bucla ar depasi
    # TIMEOUT_S cu exact cat ia interogarea aia: un plafon care spune un numar si
    # tine altul.
    deadline = time.monotonic() + TIMEOUT_S - VERSION_TIMEOUT_S
    try:
        for index, path in enumerate(present):
            remaining = int(deadline - time.monotonic())
            if remaining <= TRIVY_GRACE_S:
                # Nu ingeram ce s-a apucat sa scaneze: `mark_resolved_absent` ar
                # inchide constatarile cailor la care nu s-a mai ajuns, ca si cum
                # s-ar fi reparat peste noapte. Acelasi refuz ca la o cale cazuta.
                return [], (f"bugetul de {TIMEOUT_S}s s-a epuizat după "
                            f"{index}/{len(present)} căi; nu ingerez o listă "
                            f"parțială, fiindcă restul căilor ar fi marcate "
                            f"rezolvate. Prima nescanată: {path}"), facts

            output = os.path.join(workdir, f"result-{index}.json")
            per_path = min(TRIVY_TIMEOUT_S, remaining - TRIVY_GRACE_S)
            rc, _out, err = await _run(
                build_argv(path, output, binary, timeout_s=per_path),
                timeout=per_path + TRIVY_GRACE_S)
            if rc != 0:
                # O cale care EXISTA si pe care trivy a esuat opreste toata
                # rularea. Alternativa — sa mergem mai departe cu restul — ar
                # produce o lista partiala, iar `mark_resolved_absent` ar inchide
                # tot ce era sub calea nescanata ca si cum ar fi fost reparat.
                #
                # Cand plafonul ei a fost taiat de termen, cauza se spune pe rand:
                # „calea e stricata” si „n-a mai fost timp” cer de la operator doua
                # lucruri diferite, iar mesajul lui trivy singur nu le deosebeste.
                detail = (err.strip().splitlines() or ["fără mesaj"])[-1]
                taiat = (f"; îi mai rămăseseră doar {per_path}s din bugetul de "
                         f"{TIMEOUT_S}s al rulării"
                         if per_path < TRIVY_TIMEOUT_S else "")
                return [], (f"trivy a eșuat pe {path} (cod {rc}): "
                            f"{detail[:300]}{taiat}"), facts
            try:
                size = os.stat(output).st_size
            except OSError as exc:
                return [], (f"trivy a raportat succes pe {path}, dar raportul "
                            f"{output} nu există: {exc}"), facts
            if size > MAX_OUTPUT_BYTES:
                return [], (f"raportul trivy pentru {path} are {size} octeți, peste "
                            f"plafonul de {MAX_OUTPUT_BYTES}; nu se citește în "
                            f"proces sub `MemoryMax=1G`"), facts
            try:
                with open(output, "r", encoding="utf-8", errors="replace") as handle:
                    payload = json.load(handle)
            except ValueError as exc:
                return [], (f"raportul trivy pentru {path} nu e JSON valid: "
                            f"{str(exc)[:200]}"), facts
            if not isinstance(payload, dict):
                return [], (f"raportul trivy pentru {path} nu e un obiect JSON, ci "
                            f"{type(payload).__name__}"), facts
            items.extend(parse(payload))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # Deduplicare intre cai: acelasi pachet vazut prin doua cai suprapuse
    # (/opt/app si /srv/app legate simbolic) e o singura constatare.
    unique = {f["finding_key"]: f for f in items}
    facts["total"] = len(unique)

    described, age_h, db_error = await db_status(binary=binary)
    facts["db_version"] = described
    if db_error:
        return [], db_error, facts
    if age_h is not None and age_h > MAX_DB_AGE_H:
        return [], (f"baza de vulnerabilități trivy are {age_h / 24:.0f} zile "
                    f"({described}); peste {MAX_DB_AGE_H // 24} zile un rezultat "
                    f"curat nu mai dovedește nimic despre CVE-urile publicate "
                    f"între timp. Verifică ieșirea gazdei către ghcr.io"), facts
    if age_h is not None and age_h > WARN_DB_AGE_H:
        log.warning("baza de vulnerabilități trivy nu s-a mai împrospătat",
                    extra={"age_h": int(age_h), "db_version": described})

    if len(unique) > MAX_FINDINGS:
        return [], (f"trivy a raportat {len(unique)} constatări ≥ MEDIUM, peste "
                    f"plafonul de {MAX_FINDINGS}; nu se ingerează nimic, fiindcă o "
                    f"listă tăiată ar face ca restul să fie marcate rezolvate. "
                    f"Restrânge `scan.discovery_paths` sau ridică pragul de "
                    f"severitate"), facts

    log.info("trivy fs scan parsed",
             extra={"findings": len(unique), "paths": len(present),
                    "db_version": described})
    return list(unique.values()), None, facts
