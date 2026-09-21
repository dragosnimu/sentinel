"""What a finding sits on: the host OS, a container image, or an application.

The Vulnerabilities page used to print `findings.scanner` verbatim —
`trivy_image` — which answers "how was this found", not "what is it on". With
1055 open rows on the production host, an operator could not tell which of them
were the host's own packages and which were inside an image somebody else
builds; and those two lead to entirely different repairs (a `dnf update` in the
maintenance window versus an image rebuild and a redeploy).

## The classification is decided by the SCANNER, and only by the scanner

Each scanner is pointed at exactly one kind of thing, and says so in its own
docstring:

  * `dnf` / `apt` — the host's own package database (`os_packages.py`);
  * `trivy_image` — the image of a running container. `location` is the image
    reference by construction (`trivy_image.parse`: "`reference`, nu calea
    pachetului"), e.g. `mariadb:11.4.7`, `docker.n8n.io/n8nio/n8n`, `traefik`;
  * `trivy_fs` — an application's dependency manifest under a web root.
    `location` is `PkgPath` or the scanned target, i.e. a path.

`ecosystem` is deliberately NOT consulted, even though the column exists and is
populated. It describes the packaging format, not the thing that carries it: on
the production host `deb`, `go`, `npm` and `alpine` rows are all *inside
container images*, and only the `rpm` rows are the host itself. A page that read
`ecosystem` as a category would label a Debian package found inside a container
as the operating system of an AlmaLinux host. The scanner is the only field that
records what was looked at.

## An unrecognised scanner is reported as unrecognised

Scanners get added. A new one that nobody wired into this file must not be
quietly filed under one of the three: "I do not know what this sits on" and
"this is on the operating system" are different statements and only one of them
would be true. The unknown label keeps the scanner name and the raw location in
the text, because that is all the operator has left to go on.

Nothing here builds markup. The caller renders `label` and `detail` through
Jinja's autoescaping, and `location` is scanner output — untrusted text that has
passed through an image reference or a file path on a host under attack.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sentinel.scan import os_packages, trivy_fs, trivy_image

# The scanner names are imported, never retyped. `SCANNER_BY_FAMILY` is where a
# new distribution family's package scanner is named, and a hand-copied list
# here would be one source of truth too many — the copy would go stale on the
# day a family is added, and the symptom would be a page calling that host's own
# packages "necunoscut".
#
# `UNKNOWN_SCANNER` belongs in this set too: it is the name the OS-package step
# opens its `scans` row under when the family is not recognised. Unknown FAMILY
# is not unknown SUBJECT — whatever it managed to read, it read from the host's
# own package database.
OS_SCANNERS: frozenset[str] = frozenset(
    {*os_packages.SCANNER_BY_FAMILY.values(), os_packages.UNKNOWN_SCANNER})

KIND_OS = "os"
KIND_CONTAINER = "container"
KIND_APP = "app"
KIND_UNKNOWN = "unknown"

#: Ordinea în care se arată categoriile. Fixă, nu după numere: o listă care se
#: reordonează după cât de multe constatări are fiecare se citește altfel la
#: fiecare scanare, iar operatorul nu mai știe unde să se uite.
KINDS: tuple[str, ...] = (KIND_OS, KIND_CONTAINER, KIND_APP, KIND_UNKNOWN)

KIND_LABELS: dict[str, str] = {
    KIND_OS: "sistem de operare",
    KIND_CONTAINER: "container",
    KIND_APP: "aplicație",
    KIND_UNKNOWN: "necunoscut",
}


@dataclass(frozen=True)
class Subject:
    """What one finding is associated with.

    `kind` is for the caller to group or style by; `label` is what the operator
    reads in the column; `detail` is the long form for a `title` attribute —
    the scanner name and the raw location, which the label shortens or omits.
    """

    kind: str
    label: str
    detail: str


def _text(value: Any) -> str:
    """The trimmed string, or "" for anything that is not usable text.

    `location` is NULL for every one of the 477 open `dnf` findings, so "no
    location" is the common case and not an anomaly.
    """
    return value.strip() if isinstance(value, str) else ""


def _detail(scanner: str, location: str) -> str:
    # Nothing is dropped here: this is where the scanner name lives now that the
    # column no longer prints it, and where the full path goes when the label
    # shows only the last two components of it.
    name = scanner or "nedeclarat"
    return f"Scaner: {name} · {location}" if location else f"Scaner: {name}"


def _app_label(location: str) -> str:
    """`html/phpMyAdmin/composer.lock` -> `phpMyAdmin (composer.lock)`.

    The rule is mechanical, not a guess about project layouts: the last
    component is the file that was scanned, the one before it is where it lives.
    On the measured paths that yields the name the operator knows the
    application by, which a 56-character path does not — and the whole path
    stays in `detail`, so nothing is lost by shortening.

    `\\` is folded to `/` because a manifest path is untrusted text; `.` and
    `..` are dropped so a relative path does not present `..` as the name of an
    application.
    """
    parts = [p for p in location.replace("\\", "/").split("/") if p and p not in (".", "..")]
    if not parts:
        # A location made of nothing but separators. It exists, but it names
        # nothing, so the label must not pretend otherwise.
        return "Aplicație · cale necunoscută"
    if len(parts) >= 2:
        return f"Aplicație · {parts[-2]} ({parts[-1]})"
    return f"Aplicație · {parts[-1]}"


def describe(scanner: Any, location: Any) -> Subject:
    """Which of the three (or none of them) this finding is associated with.

    Pure: two fields in, a `Subject` out. It takes `Any` because the row comes
    from the database, where both columns are nullable and neither is validated
    on the way in.
    """
    name = _text(scanner)
    where = _text(location)

    if name in OS_SCANNERS:
        # The host's own packages. `location` is NULL here in practice; if a
        # future OS scanner sets one, it is in `detail` rather than changing
        # what the row is associated with.
        return Subject(KIND_OS, "Sistem de operare", _detail(name, where))

    if name == trivy_image.SCANNER:
        # The image reference verbatim — `mariadb:11.4.7`, `traefik`,
        # `docker.n8n.io/n8nio/n8n`. It is already the shortest thing that
        # identifies what to rebuild, so it is not parsed or shortened: a tag
        # stripped off here would merge two images the operator must tell apart.
        label = f"Container · {where}" if where else "Container · imagine necunoscută"
        return Subject(KIND_CONTAINER, label, _detail(name, where))

    if name == trivy_fs.SCANNER:
        label = _app_label(where) if where else "Aplicație · cale necunoscută"
        return Subject(KIND_APP, label, _detail(name, where))

    # Neither of the three, and no guessing. Both raw values go in the label,
    # not only in `detail`: a category the page cannot derive is exactly the
    # moment the operator needs to see what the row actually says.
    label = f"Necunoscut · {name}" if name else "Necunoscut · scaner nedeclarat"
    if where:
        label = f"{label} · {where}"
    return Subject(KIND_UNKNOWN, label, _detail(name, where))


@dataclass(frozen=True)
class Category:
    """Câte constatări deschise stau pe un fel de lucru, peste TOATE rândurile.

    `scanners` sunt numele de scaner care au căzut în categoria asta — nu o a
    doua hartă, ci chiar ce a răspuns `describe` pentru fiecare nume găsit în
    bază. Filtrarea paginii se face pe lista asta, deci nu există niciun drum
    prin care coloana să spună una și filtrul să aleagă alta.
    """

    kind: str
    label: str
    count: int
    scanners: tuple[str, ...]


def categories(open_by_scanner: Mapping[str, int]) -> list[Category]:
    """Numărătoarea pe categorii, din numărătoarea pe scanere.

    DE CE EXISTĂ, măsurat pe gazda de producție la 21 septembrie 2026: dintre
    cele 200 de rânduri pe care le duce tabelul, 183 sunt `trivy_image`, 17
    `trivy_fs` și **zero** `dnf` — primul rând `dnf` e al 373-lea în ordinea
    paginii. Gazda are 477 de constatări deschise pe pachetele ei, 470 dintre
    ele `high`, iar coloana „Asociat cu" calculată numai din rândurile afișate
    n-ar arăta niciodată categoria pe care operatorul a numit-o prima.

    „Nu e nimic pe sistemul de operare" și „nu ți-am putut arăta sistemul de
    operare" sunt două stări diferite, iar o coloană tăcută le confundă. De
    aceea numerele de aici vin dintr-o agregare peste toate rândurile deschise,
    nu din pagină.

    Cele trei categorii cunoscute apar întotdeauna, inclusiv pe zero: un „0
    container" e un fapt măsurat despre gazdă. `necunoscut` apare tot timpul în
    listă (apelantul decide dacă îl arată pe zero), fiindcă un scaner
    neclasificat trebuie să poată fi și numărat, și deschis.
    """
    per_kind: dict[str, int] = {k: 0 for k in KINDS}
    scanners: dict[str, list[str]] = {k: [] for k in KINDS}
    for scanner, n in open_by_scanner.items():
        # Aceeași funcție ca pentru celula din tabel. Orice altă potrivire aici
        # ar fi a doua sursă de adevăr, iar cele două s-ar contrazice exact pe
        # scanerul adăugat ultimul.
        kind = describe(scanner, None).kind
        per_kind[kind] += int(n)
        scanners[kind].append(scanner)
    return [Category(kind, KIND_LABELS[kind], per_kind[kind], tuple(sorted(scanners[kind])))
            for kind in KINDS]
