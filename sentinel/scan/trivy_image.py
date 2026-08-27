"""Container image vulnerabilities via `trivy image` — what the running
containers carry, which neither dnf nor `trivy fs` can see.

## The privilege this scanner costs, written down because it is permanent

`sentinel` is a member of the `docker` group, and talks to `/run/docker.sock`
directly. There is no proxy in front of it.

**On this host the `docker` group is equivalent to root.** Anyone who can reach
that socket can start a container that bind-mounts `/` and writes to it — no
exploit, just the documented API. So the consequence a future reader has to
carry is: *compromising the security agent now means root on the machine it
guards.* The threat-model row in `docs/ARHITECTURA.md` that used to say a
compromised `sentinel` daemon is contained by the executor's policy is no longer
true, and §3.14 there says so.

The operator was told this and accepted it deliberately, on the grounds that the
alternatives — a socket proxy, or a second privileged component that exports
images — are each more code running closer to root than one group membership.
This paragraph is not a complaint about that decision. It is the fact the next
person needs when they read `RestrictAddressFamilies=AF_UNIX` and wonder what it
is for.

If the trade is ever refused, the way out is `scan.containers: false` **and**
removing the group; leaving the membership with the scanner switched off keeps
all of the cost and none of the benefit.

## What is scanned: the images that RUN, not every image on disk

`docker images` on this host lists more than `docker ps` does — build leftovers,
the previous tag of everything, whatever a `docker compose pull` left behind. A
vulnerability in an image nobody executes is not reachable by anybody, and
putting it on the panel next to one that is reachable is how the panel stops
being read. That is this repository's oldest failure mode, and it costs nothing
to avoid here: scan what runs.

Two consequences, both deliberate, both visible to the operator:

  * a container that is **stopped** drops out of the next scan, and
    `mark_resolved_absent` closes its findings with `absent_from_latest_scan`.
    That is the honest reading of "only what runs": it stopped running, so it
    stopped being reachable. If it is started again the findings reopen, with
    their history intact, because the key below does not change;
  * a container **restarted onto a different image** closes the old image's
    findings and opens the new image's — which is exactly what happened.

Both of those are only allowed to happen when the scan actually looked. Every
error path below returns `[]` **with** an error, the orchestrator writes a
`failed` row, and nothing is resolved. A run that could not look never closes a
finding.

## The identity of a finding: the image, not the container, not the digest

`finding_key` is `sha256(scanner | asset | package | vuln_id | location)`, and
`location` here is the **image reference** — `nginx:1.25`, not the container name
and not the content digest. Three choices packed into one line, so:

  * **not the container name.** Nine containers can run six images; keying by
    container would report the same CVE nine times and suggest nine repairs
    where there are six. What the operator does about a vulnerable image is
    rebuild or re-pull the image, once, and every container on it is fixed;
  * **not the digest.** `sha256:...` changes on every rebuild, so keying by it
    would resolve every finding and open a brand-new one each time the image is
    rebuilt — and `findings` exists precisely to answer "how long has this been
    open" (migration 0003). A tag survives the rebuild; the finding it carries
    disappears when the rebuild actually fixed it, and stays otherwise;
  * **the same CVE in five images is five findings.** Five images are five
    separate rebuilds, on five separate schedules, each of which can be done or
    left undone independently. Collapsing them to one row would mean the row
    disappears when the first of the five is fixed, and the other four become
    invisible while still running.

What is scanned is still the **image ID the container is actually running**
(`docker inspect .Image`), not the tag: a tag that has been re-pulled without
restarting the container points at content that is not running. The tag is the
name; the ID is the thing. `identity_mismatch` then checks that trivy's report is
about the ID we asked for — an exit code of 0 is not evidence that trivy scanned
the image we meant rather than one it resolved from a registry.

## Why OS packages are reported here and refused in `trivy_fs`

`trivy_fs` says at length why trivy must not be pointed at the host's RPM
database: dnf answers that question better, and trivy's version matching turns
AlmaLinux's backported fixes into a wall of false positives.

None of that applies inside an image. Nothing else on this host can see a
container's package list — `dnf` sees the host, and the image is a different
distribution with a different vendor. And trivy matches images against that
vendor's own advisory feed (Debian's, Alpine's, Ubuntu's), which is the feed that
knows about its own backports. So `--scanners vuln` here reports both classes,
and it is the only source that reports either.

## Budgets: the unit is killed as a whole, so this scanner bounds itself

`sentinel-scan.service` has `TimeoutStartSec=14400` and `MemoryMax=1G` for the
**entire** pass, and `OOMPolicy=stop`. Two failure shapes follow:

  * time — `os_packages` takes 300s and `trivy_fs` 1800s of that budget, so this
    one takes at most `TIMEOUT_S`, measured against a wall-clock deadline across
    all images rather than per image. Per-image ceilings alone would let forty
    images spend forty times the intended budget and leave the scanners after us
    unrun. When the deadline is hit the run is an **error**, not a partial
    result, for the resolve reason above;
  * memory — images are scanned strictly one at a time, so the peak is one trivy
    process rather than N. That is the only lever this process has: `MemoryMax`
    belongs to the unit, and a limit imposed on the child from here (`RLIMIT_AS`)
    interacts badly with the Go runtime's address-space reservation. A single
    image large enough to reach 1 GB would still take the whole unit down with
    it — including `dnf`, which had already finished. That residual risk is real,
    it is not fixable from inside this file, and it is named here so the next
    person does not have to rediscover it.

## Two states of docker, and only one of them is an error

    absent       no `docker` binary, no socket, no DOCKER_HOST
                 → this host does not run containers. Not an error. No `scans`
                   row is written at all, because the only statuses available
                   are `running/completed/failed/timeout` (migration 0029 removed
                   `skipped` on purpose) and a `completed` row with zero findings
                   would be the exact lie that migration exists to prevent.

    unreachable  docker is here in some form and we could not talk to it
                 → an ERROR, loudly. Somebody asked for container scanning and it
                   is not happening. The commonest cause is the missing group
                   membership, and the message says so with the facts that prove
                   it: the socket's owning group, its mode, and the groups this
                   process actually has.

    ready        `docker version` returned a **server** version. Not "the client
                 ran", not "the socket file exists" — the daemon answered.

A `scan.containers: true` on a host where `sentinel` cannot reach the socket has
to scream, and this is the path on which it does.

Read-only throughout: `docker ps`, `docker inspect`, `trivy image`. This scanner
never starts, stops or pulls anything.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from sentinel.db.repo import findings as fx
from sentinel.logging_setup import get_logger
from sentinel.scan import trivy_fs

log = get_logger(__name__)

#: Numele scanerului, din vocabularul migratiei 0003 (`dnf | trivy_fs |
#: trivy_image | nuclei | ...`). E si cheia sub care `check_last_scan` raporteaza
#: (`scan:last:trivy_image`), deci schimbarea lui desparte constatarile de aici
#: de cele scrise pana atunci.
SCANNER = "trivy_image"

#: Unde sta clientul docker pe gazda. `resolve_docker` cade pe `which` daca nu e
#: acolo — aceeasi disciplina ca `trivy_fs.resolve_binary`: poarta care raspunde
#: „e instalat" si comanda care se executa trebuie sa vorbeasca despre acelasi
#: fisier.
DOCKER_BINARY = "/usr/bin/docker"

#: Socketurile pe care le stim. `/var/run` e de obicei o legatura catre `/run`,
#: deci ambele pot exista si pot fi acelasi lucru — nu conteaza, ne intereseaza
#: doar daca EXISTA vreunul, fiindca asta deosebeste „gazda nu are containere" de
#: „gazda are docker si noi nu ajungem la el".
SOCKET_PATHS = ("/run/docker.sock", "/var/run/docker.sock")

#: Bugetul de ceas al SCANERULUI, pentru toate imaginile la un loc.
#:
#: `sentinel-scan.service` are `TimeoutStartSec=14400`, iar systemd omoara toata
#: unitatea la el. os_packages ia 300, trivy_fs 1800; 3600 aici lasa 8700 pentru
#: nuclei si semgrep, care urmeaza. Masurat ca termen absolut, nu per imagine:
#: patruzeci de imagini cu cate un plafon propriu ar consuma de patruzeci de ori
#: bugetul si ar lasa scanerele de dupa nerulate.
TIMEOUT_S = 3600

#: Plafonul pe care i-l dam LUI trivy, per imagine. Sub al nostru dinadins:
#: trivy care se opreste singur scrie un mesaj pe care il putem raporta; trivy
#: omorat de noi lasa doar „timeout".
TRIVY_TIMEOUT_S = 600

#: Cat ii mai dam lui trivy dupa termenul lui, ca sa apuce sa scrie eroarea
#: inainte sa-l omoram noi.
TRIVY_GRACE_S = 60

#: Cat asteptam dupa `docker version|ps|inspect` — interogari locale pe un
#: socket, nu scanari. Daca daemonul e blocat, asta e cat de mult atarnam.
DOCKER_TIMEOUT_S = 30

#: Peste cate containere in rulare refuzam sa mai enumeram. Gazda operatorului
#: are noua. Un numar de ordinul sutelor inseamna alta gazda decat cea pentru
#: care sunt calculate bugetele de mai sus, si atunci un refuz explicit e mai
#: onest decat o rulare care se taie singura la termen.
MAX_CONTAINERS = 200

#: Peste cate imagini UNICE refuzam sa scanam. Plafon distinct de cel de timp,
#: fiindca se evalueaza INAINTE sa cheltuim ora: „prea multe" se afla din prima
#: secunda, nu dupa a 3599-a.
MAX_IMAGES = 40

#: Plafonul de volum, ca REFUZ, nu ca trunchiere — acelasi rationament ca la
#: `trivy_fs.MAX_FINDINGS`: o lista taiata ar fi urmata de
#: `mark_resolved_absent`, care ar marca restul drept rezolvate, si panoul ar
#: arata MAI PUTIN tocmai fiindca e mai mult.
#:
#: Numarul difera de cel de la `trivy_fs` (500) si asta e intentionat: o imagine
#: de baza debian sau ubuntu aduce singura ordinul sutelor de intrari >= MEDIUM,
#: iar sase-noua imagini inseamna ordinul miilor. Cu 500 aici scanerul ar refuza
#: in fiecare noapte si n-ar raporta niciodata nimic — un plafon care nu poate fi
#: respectat e o scanare oprita, nu o scanare prudenta.
#:
#: Daca panoul se dovedeste prea zgomotos, parghia e pragul de severitate, si e
#: decizia operatorului, nu a acestui fisier.
MAX_FINDINGS = 2500

#: Starile lui docker. Doar `unreachable` e o eroare; vezi docstring-ul de sus.
DOCKER_ABSENT = "absent"
DOCKER_READY = "ready"
DOCKER_UNREACHABLE = "unreachable"

#: Un id de container sau de imagine, asa cum il scrie docker cu `--no-trunc`.
#: Validat, nu presupus: daca `docker ps` intoarce altceva decat identificatori,
#: nu-i dam mai departe lui `docker inspect` si nu construim o comanda dintr-un
#: text pe care nu-l intelegem.
_HEX_ID = re.compile(r"^[0-9a-f]{64}$")

#: O „referinta" care de fapt e un digest sau un id — `sha256:ab12...`, sau hexul
#: gol. `docker inspect .Config.Image` intoarce asta pentru un container pornit
#: direct dupa id, si atunci nu e un nume pe care operatorul sa-l recunoasca.
_DIGEST_REF = re.compile(r"^(sha256:)?[0-9a-f]{12,64}$")


@dataclass(frozen=True)
class DockerProbe:
    """Ce am aflat despre docker, si din ce fapt.

    `detail` ajunge fie in jurnal (pentru `absent`), fie in `scans.error` si de
    acolo in `/selfcheck` (pentru `unreachable`), deci e scris pentru operator,
    nu pentru noi.
    """

    state: str
    detail: str
    binary: str | None


@dataclass(frozen=True)
class RunningImage:
    """O imagine unica dintre cele care ruleaza acum.

    `image_id` e ce se scaneaza (continutul care chiar ruleaza), `reference` e
    cheia de identitate a constatarii (numele care supravietuieste unei
    reconstructii). Vezi docstring-ul modulului pentru de ce sunt doua si nu unul.
    """

    image_id: str
    reference: str
    containers: tuple[str, ...]


def resolve_docker() -> str | None:
    """Calea clientului docker, sau None daca nu e nicaieri."""
    if os.path.exists(DOCKER_BINARY):
        return DOCKER_BINARY
    return shutil.which("docker")


def _group_names(gids: list[int]) -> list[str]:
    """Numele grupurilor, cu gid-ul ca rezerva. Gol daca platforma n-are `grp`."""
    try:
        import grp  # noqa: PLC0415 - lipseste pe Windows, unde ruleaza testele
    except ImportError:
        return [str(g) for g in gids]
    names = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except (KeyError, OverflowError, OSError):
            names.append(str(gid))
    return names


def socket_facts(path: str) -> str:
    """Cine detine socketul si cu ce grupuri rulam noi — fapte, nu ghicit.

    Mesajul lui docker („permission denied while trying to connect") spune CA nu
    se poate, nu DE CE. Diferenta dintre „lipseste apartenenta la grup" si
    „socketul e pe un mount read-only sub `ProtectSystem=strict`" se vede in
    proprietar, mod si in grupurile procesului — si numai a doua forma ii spune
    operatorului ce sa repare.
    """
    try:
        st = os.stat(path)
    except OSError as exc:
        return f"{path}: nu poate fi citit ({exc})"

    owner = f"gid {st.st_gid}"
    named = _group_names([st.st_gid])
    if named and named[0] != str(st.st_gid):
        owner = f"grupul `{named[0]}` (gid {st.st_gid})"

    ours = ""
    if hasattr(os, "getgroups"):
        try:
            ours = (f", iar procesul rulează cu grupurile "
                    f"{', '.join(_group_names(list(os.getgroups()))) or '(niciunul)'}")
        except OSError:
            ours = ""

    return (f"{path} e al {owner}, mod {oct(st.st_mode & 0o777)}, "
            f"scriibil de noi: {'da' if os.access(path, os.W_OK) else 'NU'}{ours}")


async def probe_docker() -> DockerProbe:
    """Absent, inaccesibil sau gata — si dovada pentru fiecare.

    Ordinea conteaza. „Absent" se afirma doar cand NICIUNUL dintre cele trei
    semne independente nu e prezent (binar, socket, `DOCKER_HOST`): o singura
    sursa ar fi ori increderea in filesystem, ori increderea in configuratie, si
    fiecare dintre ele s-a dovedit deja gresita in repository-ul asta, in
    directii opuse.

    „Gata" se afirma doar cand DAEMONUL a raspuns cu versiunea LUI. Un client
    care porneste si un fisier de socket care exista nu dovedesc niciunul ca s-a
    stabilit o conexiune — exact tiparul „cod de iesire in loc de efect".
    """
    binary = resolve_docker()
    sockets = [p for p in SOCKET_PATHS if os.path.exists(p)]
    host = (os.environ.get("DOCKER_HOST") or "").strip()

    if binary is None and not sockets and not host:
        return DockerProbe(
            DOCKER_ABSENT,
            f"docker nu e instalat pe gazda asta: nici clientul ({DOCKER_BINARY} "
            f"lipsește și nu e în PATH), nici vreun socket "
            f"({', '.join(SOCKET_PATHS)}), nici DOCKER_HOST. Nu e o eroare — e o "
            f"gazdă fără containere, deci nu există nimic de scanat",
            None)

    if binary is None:
        # Socket fara client: docker EXISTA pe gazda asta si totusi nu-l putem
        # interoga. E o eroare, nu o gazda curata.
        where = ", ".join(sockets) or f"DOCKER_HOST={host}"
        return DockerProbe(
            DOCKER_UNREACHABLE,
            f"docker rulează pe gazdă ({where}), dar clientul lipsește "
            f"({DOCKER_BINARY} nu există și `docker` nu e în PATH), deci "
            f"imaginile containerelor NU au fost scanate",
            None)

    # `--format {{.Server.Version}}`: raspunde doar daca s-a vorbit cu daemonul.
    # `docker version` fara format iese cu 0 si tipareste blocul clientului chiar
    # si cand serverul nu raspunde, deci ar fi fost o poarta care trece mereu.
    rc, out, err = await trivy_fs._run(
        [binary, "version", "--format", "{{.Server.Version}}"],
        timeout=DOCKER_TIMEOUT_S)
    server = ""
    for line in out.splitlines():
        if line.strip():
            server = line.strip()
    if rc == 0 and server:
        return DockerProbe(DOCKER_READY, f"docker daemon {server}", binary)

    reason = (err.strip().splitlines() or ["fără mesaj"])[-1].strip()[:300]
    evidence = "; ".join(socket_facts(p) for p in sockets)
    if not evidence:
        evidence = (f"niciunul dintre {', '.join(SOCKET_PATHS)} nu există"
                    + (f"; DOCKER_HOST={host}" if host else ""))
    return DockerProbe(
        DOCKER_UNREACHABLE,
        f"docker e instalat ({binary}), dar daemonul nu a răspuns (cod {rc}): "
        f"{reason or 'fără mesaj'}. {evidence}. Dacă lipsește apartenența la "
        f"grupul `docker`: `usermod -aG` NU schimbă un proces deja pornit, deci "
        f"verifică efectul cu `sudo -u sentinel docker version`, nu cu "
        f"`id sentinel`, și repornește sentinel-scan după ce o adaugi",
        binary)


def _display_reference(refs: list[str], image_id: str) -> str:
    """Numele sub care se raporteaza imaginea. Deterministic, dinadins.

    Doua containere pot numi aceeasi imagine altfel (unul `nginx:1.25`, altul
    `docker.io/library/nginx:1.25`). Daca am lua „primul vazut", ordinea lui
    `docker ps` ar decide cheia constatarii, iar o repornire de container ar
    rescrie istoricul unei vulnerabilitati fara ca nimic sa se fi schimbat. Deci
    cel mai mic in ordine lexicografica: acelasi set de nume da acelasi raspuns.

    Fara niciun nume utilizabil (container pornit direct dupa id, imagine cu
    tagul sters) ramane digestul scurt — urat, dar stabil si trasabil.
    """
    usable = sorted({r.strip() for r in refs
                     if r.strip()
                     and not _DIGEST_REF.match(r.strip())
                     and not r.strip().startswith("<")})
    return usable[0] if usable else f"sha256:{image_id[:12]}"


async def list_running_images(binary: str) -> tuple[list[RunningImage], str | None]:
    """Imaginile UNICE ale containerelor care ruleaza acum.

    Doua comenzi si nu una: `docker ps` nu poate da id-ul imaginii (sablonul lui
    nu are campul), iar `{{.Image}}` de acolo e referinta cu care a fost CREAT
    containerul — care poate sa fi fost reindreptata catre alt continut intre
    timp. `docker inspect .Image` da ce ruleaza cu adevarat.
    """
    rc, out, err = await trivy_fs._run(
        [binary, "ps", "--quiet", "--no-trunc"], timeout=DOCKER_TIMEOUT_S)
    if rc != 0:
        detail = (err.strip().splitlines() or ["fără mesaj"])[-1].strip()[:300]
        return [], (f"`docker ps` a eșuat (cod {rc}): {detail} — nu știu ce "
                    f"containere rulează, deci nu s-a scanat nicio imagine")

    ids = [line.strip() for line in out.splitlines() if line.strip()]
    unknown = [i for i in ids if not _HEX_ID.match(i)]
    if unknown:
        return [], (f"`docker ps --quiet --no-trunc` a întors {len(unknown)} "
                    f"rânduri care nu sunt identificatori de container "
                    f"(primul: {unknown[0][:60]!r}); nu construiesc o comandă "
                    f"dintr-o ieșire pe care n-o înțeleg")
    if not ids:
        return [], None
    if len(ids) > MAX_CONTAINERS:
        return [], (f"{len(ids)} containere rulează, peste plafonul de "
                    f"{MAX_CONTAINERS}; bugetele de timp și de memorie ale "
                    f"scanării sunt calculate pentru un ordin de mărime mai mic, "
                    f"deci refuz în loc să tai lista")

    rc, out, err = await trivy_fs._run(
        [binary, "inspect", "--type", "container",
         "--format", "{{.Id}}\t{{.Image}}\t{{.Config.Image}}\t{{.Name}}", *ids],
        timeout=DOCKER_TIMEOUT_S)

    rows: list[list[str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 4 or not _HEX_ID.match(parts[0].strip()):
            return [], (f"`docker inspect` a întors un rând pe care nu-l "
                        f"înțeleg: {line.strip()[:120]!r}")
        rows.append([p.strip() for p in parts])

    asked = set(ids)
    returned = {r[0] for r in rows}
    if not returned <= asked:
        return [], ("`docker inspect` a descris containere care nu au fost "
                    "cerute; ieșirea nu corespunde cererii, deci n-o folosesc")
    if rc != 0 and returned == asked:
        detail = (err.strip().splitlines() or ["fără mesaj"])[-1].strip()[:300]
        return [], f"`docker inspect` a eșuat (cod {rc}): {detail}"
    if rc != 0:
        # Ies rau DAR lipsesc exact containere din cele cerute: s-au oprit intre
        # `ps` si `inspect`. Un container oprit e chiar ce nu scanam, deci restul
        # ramane un rezultat intreg — nu unul partial care ar inchide constatari.
        log.info("containere oprite între enumerare și inspecție",
                 extra={"cerute": len(asked), "descrise": len(returned)})

    by_image: dict[str, dict[str, list[str]]] = {}
    for cid, image_id, config_image, name in rows:
        digest = image_id[7:] if image_id.startswith("sha256:") else image_id
        if not _HEX_ID.match(digest):
            return [], (f"`docker inspect` a dat pentru containerul {cid[:12]} "
                        f"un id de imagine pe care nu-l recunosc: "
                        f"{image_id[:80]!r}")
        entry = by_image.setdefault(digest, {"refs": [], "names": []})
        entry["refs"].append(config_image)
        entry["names"].append(name.lstrip("/") or cid[:12])

    if len(by_image) > MAX_IMAGES:
        return [], (f"{len(by_image)} imagini unice rulează, peste plafonul de "
                    f"{MAX_IMAGES}; refuz înainte să cheltui bugetul de "
                    f"{TIMEOUT_S}s, fiindcă o listă tăiată la jumătate ar face ca "
                    f"restul să fie marcate rezolvate")

    images = [RunningImage(image_id=digest,
                           reference=_display_reference(entry["refs"], digest),
                           containers=tuple(sorted(set(entry["names"]))))
              for digest, entry in by_image.items()]
    # Ordine stabila: aceleasi imagini se scaneaza in aceeasi ordine de la o
    # rulare la alta, deci un buget epuizat taie mereu in acelasi loc si nu
    # produce o alta constatare de fiecare data.
    images.sort(key=lambda i: (i.reference, i.image_id))
    return images, None


def build_argv(image_id: str, output: str, binary: str = trivy_fs.BINARY,
               timeout_s: int = TRIVY_TIMEOUT_S) -> list[str]:
    """Comanda pentru o imagine. Separata ca sa poata fi aserteata fara sa ruleze."""
    return [
        binary,
        "--cache-dir", trivy_fs.CACHE_DIR,
        "image",
        "--quiet",
        # Doar vulnerabilitati; `secret` si `misconfig` sunt scanere separate in
        # configuratie si aici si-ar scrie constatarile sub numele asta.
        "--scanners", "vuln",
        "--format", "json",
        # In fisier, nu la stdout: marimea se verifica cu `stat` INAINTE sa fie
        # citita in proces. Acelasi rationament ca la `trivy_fs`.
        "--output", output,
        "--severity", ",".join(trivy_fs.SEVERITIES),
        # Sursa imaginii, fixata. Fara steagul asta trivy incearca in lant
        # docker, containerd, podman si apoi REMOTE — iar „remote" inseamna ca ar
        # putea trage o imagine din registry si raporta despre ea in loc de cea
        # care ruleaza. O scanare care se uita la altceva decat crede e mai rea
        # decat una care esueaza.
        "--image-src", "docker",
        # Fara interogari per-artefact catre retea; baza de vulnerabilitati se
        # reimprospateaza in continuare.
        "--offline-scan",
        "--timeout", f"{timeout_s}s",
        "--", image_id,
    ]


def identity_mismatch(payload: dict[str, Any], image_id: str) -> str | None:
    """None daca raportul e despre imaginea ceruta, altfel de ce nu e.

    Codul de iesire 0 al lui trivy spune ca a scanat CEVA. Ce dovedeste ca a
    scanat imaginea care ruleaza pe gazda asta e ca raportul o numeste — de aceea
    `Metadata.ImageID` si `ArtifactName` sunt citite si comparate, nu presupuse.

    Lipsa amandurora e tot o nepotrivire: un raport care nu spune ce a scanat nu
    poate dovedi ca a scanat ce trebuia. „Nu știu" nu e „e bine".
    """
    meta = payload.get("Metadata")
    reported = meta.get("ImageID") if isinstance(meta, dict) else None
    artifact = payload.get("ArtifactName")
    candidates = [c.strip() for c in (reported, artifact)
                  if isinstance(c, str) and c.strip()]
    if not candidates:
        return ("raportul nu spune ce imagine a scanat (nici `Metadata.ImageID`, "
                "nici `ArtifactName`), deci nu pot dovedi că e despre imaginea "
                "care rulează")
    for candidate in candidates:
        hexid = candidate.lower()
        hexid = hexid[7:] if hexid.startswith("sha256:") else hexid
        if len(hexid) >= 12 and (image_id.startswith(hexid) or hexid.startswith(image_id)):
            return None
    return (f"am cerut sha256:{image_id[:12]}, iar raportul e despre "
            f"{candidates[0][:80]!r}")


def parse(payload: dict[str, Any], *, reference: str, image_id: str,
          containers: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Un raport `trivy image` -> constatari, in forma din `findings`.

    Functie PURA, ca sa poata fi probata pe iesire reala fara docker si fara
    trivy. Elementele comune cu `trivy_fs` — maparea severitatii, perechea
    CVSS, ecosistemul, plafonul descrierii — se IMPORTA de acolo: doua copii ale
    aceleiasi table de severitati ar diverge, iar prima divergenta ar fi tacuta.

    Ce e diferit fata de `trivy_fs` e asamblarea: `location` e referinta
    imaginii, nu calea fisierului, si de asta atarna toata cheia de identitate.
    """
    items: dict[str, dict[str, Any]] = {}
    results = payload.get("Results")
    if not isinstance(results, list):
        # `"Results": null` e ce scrie trivy cand nu a potrivit nimic — o imagine
        # curata, nu un raport stricat.
        return []

    meta = payload.get("Metadata")
    os_meta = meta.get("OS") if isinstance(meta, dict) else None
    os_name = None
    if isinstance(os_meta, dict):
        family = os_meta.get("Family")
        version = os_meta.get("Name")
        os_name = " ".join(str(x) for x in (family, version) if x) or None

    for result in results:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        ecosystem = trivy_fs._ecosystem(result.get("Type"))
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

            cve = vuln_id if trivy_fs._CVE.match(vuln_id) else None
            severity, severity_known = trivy_fs.map_severity(entry.get("Severity"))
            cvss, vector = trivy_fs._cvss(entry)
            fixed = entry.get("FixedVersion")
            installed = entry.get("InstalledVersion")
            title = entry.get("Title")
            description = entry.get("Description")
            pkg_path = entry.get("PkgPath")

            # `reference`, nu calea pachetului: reparatia e reconstruirea
            # imaginii, o data, si atunci trebuie sa fie o singura constatare
            # pentru toate locurile din imagine in care apare acelasi pachet.
            # Consecinta acceptata: acelasi pachet la doua cai in aceeasi
            # imagine se pliaza intr-un rand — calea fiecaruia ramane in `raw`.
            key = fx.finding_key(SCANNER, None, package or None, vuln_id, reference)
            if key in items:
                continue

            items[key] = {
                "scanner": SCANNER,
                "cve": cve,
                "advisory_id": None if cve else vuln_id,
                "title": (title.strip()
                          if isinstance(title, str) and title.strip()
                          else f"{vuln_id} în {package or 'pachet necunoscut'}"),
                "description": (description[:trivy_fs.MAX_DESCRIPTION]
                                if isinstance(description, str) and description.strip()
                                else None),
                "severity": severity,
                "cvss": cvss,
                "cvss_vector": vector,
                "package": package or None,
                "installed_version": (installed.strip()
                                      if isinstance(installed, str) and installed.strip()
                                      else None),
                # Sirul gol al lui trivy inseamna „nu exista fix publicat"; None
                # ca sa insemne acelasi lucru si in baza, si in panou.
                "fixed_version": (fixed.strip()
                                  if isinstance(fixed, str) and fixed.strip()
                                  else None),
                "location": reference,
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
                    # Ce ruleaza, nu doar cum se numeste: cu digestul in `raw`
                    # operatorul poate lega constatarea de continutul exact, chiar
                    # dupa ce tagul a fost reindreptat.
                    "image_id": f"sha256:{image_id}",
                    "image_ref": reference,
                    "image_os": os_name,
                    "pkg_path": pkg_path if isinstance(pkg_path, str) else None,
                    # Containerele sunt informative, NU fac parte din cheie: se
                    # sterg si se recreeaza, iar o cheie care depinde de ele ar
                    # rescrie istoricul la fiecare `docker compose up`.
                    "containers": list(containers),
                },
            }
    return list(items.values())


async def scan(probe: DockerProbe | None = None
               ) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """Scaneaza imaginile containerelor in rulare. (constatari, eroare, fapte).

    `fapte["docker"]` e mereu scris si e prima intrebare a apelantului: starea
    `absent` NU e o eroare si nu are voie sa deschida un rand in `scans`, fiindca
    singurele statusuri disponibile ar face-o sa arate ori ca un esec, ori ca o
    masuratoare cu zero constatari.
    """
    facts: dict[str, Any] = {"docker": None, "docker_detail": None,
                             "db_version": None, "containers": 0, "images": 0,
                             "references": [], "total": 0}

    probe = probe or await probe_docker()
    facts["docker"] = probe.state
    facts["docker_detail"] = probe.detail
    if probe.state == DOCKER_ABSENT:
        return [], None, facts
    if probe.state == DOCKER_UNREACHABLE or probe.binary is None:
        return [], probe.detail, facts

    images, error = await list_running_images(probe.binary)
    if error:
        return [], error, facts
    facts["images"] = len(images)
    facts["containers"] = sum(len(i.containers) for i in images)
    facts["references"] = [i.reference for i in images]

    if not images:
        # Zero containere in rulare e un REZULTAT, nu o imposibilitate: ne-am
        # uitat si nu rula nimic. Constatarile de ieri se inchid, si asta e
        # citirea corecta a regulii „doar ce ruleaza".
        #
        # Aici NU se verifica nici binarul trivy, nici vechimea bazei de
        # vulnerabilitati: afirmatia „nu ruleaza niciun container" nu depinde de
        # niciuna dintre ele, iar un rand `failed` pentru o baza invechita ar fi
        # o alarma falsa despre o scanare care n-avea ce sa scaneze.
        log.info("niciun container în rulare", extra={"scanner": SCANNER})
        return [], None, facts

    binary = trivy_fs.resolve_binary()
    if binary is None:
        return [], (f"{len(images)} imagini rulează, dar trivy nu e instalat "
                    f"({trivy_fs.BINARY} lipsește) — nu s-a scanat niciuna, deci "
                    f"lista goală nu spune nimic despre ele"), facts

    workdir = tempfile.mkdtemp(prefix="sentinel-trivy-image-")
    items: list[dict[str, Any]] = []
    deadline = time.monotonic() + TIMEOUT_S
    try:
        for index, image in enumerate(images):
            remaining = int(deadline - time.monotonic())
            if remaining <= TRIVY_GRACE_S:
                return [], (f"bugetul de {TIMEOUT_S}s s-a epuizat după "
                            f"{index}/{len(images)} imagini; nu ingerez o listă "
                            f"parțială, fiindcă restul imaginilor ar fi marcate "
                            f"rezolvate. Ultima începută: {image.reference}"), facts

            output = os.path.join(workdir, f"image-{index}.json")
            per_image = min(TRIVY_TIMEOUT_S, remaining - TRIVY_GRACE_S)
            rc, _out, err = await trivy_fs._run(
                build_argv(image.image_id, output, binary, timeout_s=per_image),
                timeout=per_image + TRIVY_GRACE_S)
            if rc != 0:
                # O imagine pe care trivy a esuat opreste toata rularea, la fel ca
                # o cale in `trivy_fs`: alternativa ar fi o lista partiala, iar
                # `mark_resolved_absent` ar inchide constatarile imaginii nescanate
                # ca si cum ar fi fost reparate peste noapte.
                detail = (err.strip().splitlines() or ["fără mesaj"])[-1].strip()
                return [], (f"trivy a eșuat pe imaginea {image.reference} "
                            f"(sha256:{image.image_id[:12]}, cod {rc}): "
                            f"{detail[:300]}"), facts
            try:
                size = os.stat(output).st_size
            except OSError as exc:
                return [], (f"trivy a raportat succes pe {image.reference}, dar "
                            f"raportul {output} nu există: {exc}"), facts
            if size > trivy_fs.MAX_OUTPUT_BYTES:
                return [], (f"raportul trivy pentru {image.reference} are {size} "
                            f"octeți, peste plafonul de "
                            f"{trivy_fs.MAX_OUTPUT_BYTES}; nu se citește în proces "
                            f"sub `MemoryMax=1G`"), facts
            try:
                with open(output, "r", encoding="utf-8", errors="replace") as handle:
                    payload = json.load(handle)
            except ValueError as exc:
                return [], (f"raportul trivy pentru {image.reference} nu e JSON "
                            f"valid: {str(exc)[:200]}"), facts
            if not isinstance(payload, dict):
                return [], (f"raportul trivy pentru {image.reference} nu e un "
                            f"obiect JSON, ci {type(payload).__name__}"), facts

            mismatch = identity_mismatch(payload, image.image_id)
            if mismatch:
                return [], (f"raportul trivy pentru {image.reference} nu e despre "
                            f"imaginea cerută: {mismatch}. Constatările lui ar fi "
                            f"fost puse pe seama unei imagini pe care nu le are"), facts

            items.extend(parse(payload, reference=image.reference,
                               image_id=image.image_id,
                               containers=image.containers))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    unique = {f["finding_key"]: f for f in items}
    facts["total"] = len(unique)

    # Vechimea bazei se verifica DUPA scanare, fiindca scanarea e cea care o
    # reimprospateaza. Aceeasi functie ca la `trivy_fs`, acelasi cache: e aceeasi
    # baza de date, iar doua praguri diferite pentru ea ar insemna ca aceeasi
    # gazda e si proaspata, si invechita, in acelasi timp.
    described, age_h, db_error = await trivy_fs.db_status(binary=binary)
    facts["db_version"] = described
    if db_error:
        return [], db_error, facts
    if age_h is not None and age_h > trivy_fs.MAX_DB_AGE_H:
        return [], (f"baza de vulnerabilități trivy are {age_h / 24:.0f} zile "
                    f"({described}); peste {trivy_fs.MAX_DB_AGE_H // 24} zile un "
                    f"rezultat curat nu mai dovedește nimic despre CVE-urile "
                    f"publicate între timp. Verifică ieșirea gazdei către "
                    f"ghcr.io"), facts
    if age_h is not None and age_h > trivy_fs.WARN_DB_AGE_H:
        log.warning("baza de vulnerabilități trivy nu s-a mai împrospătat",
                    extra={"age_h": int(age_h), "db_version": described})

    if len(unique) > MAX_FINDINGS:
        return [], (f"trivy a raportat {len(unique)} constatări ≥ MEDIUM pe "
                    f"{len(images)} imagini, peste plafonul de {MAX_FINDINGS}; nu "
                    f"se ingerează nimic, fiindcă o listă tăiată ar face ca restul "
                    f"să fie marcate rezolvate. Ridică pragul de severitate sau "
                    f"reduce numărul de imagini"), facts

    log.info("trivy image scan parsed",
             extra={"findings": len(unique), "images": len(images),
                    "containers": facts["containers"], "db_version": described})
    return list(unique.values()), None, facts
