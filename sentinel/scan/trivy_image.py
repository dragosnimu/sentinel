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

## The severity floor is HIGH here and MEDIUM in `trivy_fs`, on purpose

`SEVERITIES` below says the whole of why. The short version: on 29 August 2026
the six running images carried 2838 findings at MEDIUM and above against the
`MAX_FINDINGS` cap of that day — 2500, and a refusal of the whole run, not the
6000 per-image budget it is since 23 October — so this scanner refused every
night and reported nothing whatsoever about the containers; at HIGH they carry
450. `trivy_fs` keeps MEDIUM — its 92 findings are nowhere near its own cap, and
nobody asked for it to change.

A scan that looks at less has to SAY it looks at less, or the number it reports
gets read as "the containers are clean" when it means "we did not look" — the
absence of a signal taken for evidence of health, which is this repository's
house defect. So the floor is not only a constant: `severity_scope()` is written
onto the `scans` row by the orchestrator, before the run starts, so it is there
even on a `failed` row, and `check_last_scan` reads it back out of the row and
says it next to the count.

And a run at this floor is not allowed to close what it can no longer see:
"no longer reported" would otherwise cover two different things — what was
fixed, and what is no longer looked for. `visible_severities()` is what
`mark_resolved_absent` is fenced with.

What the production database holds, read on 23 Oct 2026 (`psql -d sentinel` on
the host; the counts were taken after a query that has to return rows, so an
empty answer could not be a broken command):

  * `scans` has 57 `trivy_image` rows: 55 `completed` (30 Aug - 22 Oct) and 2
    `failed`, both on the volume cap — 29 Aug (2832 findings at MEDIUM, 6 images)
    and 23 Oct (2532 at the floor above, 11 images); the 29 Aug row records
    2832, the figure quoted elsewhere in this file was taken from trivy directly.
    The first version of this paragraph said the scanner had ONE run ever and had
    never ingested anything; that stopped being true the next night and the
    sentence stood for eight weeks;
  * `findings` holds 2687 rows of this scanner: 2484 open, 203 resolved. The
    resolve path has run on real data;
  * not one of them is a measured MEDIUM. The 701 open rows that say `medium`
    are all UNKNOWN, parked there by `map_severity` (`raw.severity_known =
    false`). The ~2388 MEDIUM findings of 29 Aug were never ingested — the floor
    was raised before the first run that succeeded. So the SEVERITY fence still
    protects zero rows on this host today, and saying otherwise would be the
    pattern this repository is named after. It stays for a future floor change
    or another install.

The LOCATION fence below protects real rows: on 23 Oct it is what keeps 1522
open `waha` findings from being announced as fixed.

## Ingest per image: a budget that skips, it does not refuse the whole run

`MAX_FINDINGS` used to be a refusal of the whole run: one finding over, and
nothing at all was ingested. That is correct as far as it goes — a list cut at
the cap would be followed by `mark_resolved_absent` and the rest announced as
fixed — but the failure mode was total blindness. On 23 Oct 2532 findings
(`waha` 1602, `snipe-it` 530, nine others ~400) were 32 over the cap of that
day, 2500, so the operator lost the findings on their own applications along
with the two third-party images that blew the budget. The night before the total
had been 2484, sixteen under. The total does not drift, it moves in steps, and
each step is an event — a third-party `:latest` image appearing or being
refreshed (720 -> 1517 on 17 Oct when `waha` appeared, +698 on 22 Oct when it was
refreshed) — so a total that sits near the cap crosses it the night an image
changes, with nobody having touched this scanner. That is why the cap is 6000
today and not 2500: the series, the reasoning and the measured costs are written
next to `MAX_FINDINGS`.

So the budget decides PER IMAGE, and an image that is not ingested is NAMED:

  * every image is scanned and parsed (strictly one at a time, as before);
  * an image that on its own has more findings than `MAX_FINDINGS`
    (`REASON_IMAGE`), or whose report is too large to read (`REASON_REPORT`), is
    not ingested. Not truncated: a partial image is the original sin, and
    ingesting only its CRITICALs would need a fence on (image, severity) while
    hiding its HIGHs. Its existing rows are left alone;
  * the rest are admitted smallest first until their sum would exceed
    `MAX_FINDINGS`; the ones that do not fit (`REASON_BUDGET`) are not ingested.
    Smallest first, not by name or by scan order, for two reasons: the outcome
    does not depend on the order docker lists containers, so a night's result
    can be explained; and the operator's own applications are the small ones, so
    the images that blow a budget are the large third-party ones, not them.
    The price is real and stated: when the sum binds, the LARGEST image is the
    one skipped, and the largest is not the least exposed. It is named every
    night it happens, and the number is the operator's to move;
  * the findings of a skipped image are not in `seen_keys`, so
    `mark_resolved_absent(skip_locations=...)` leaves its rows exactly as they
    were — open, with the date of the last run that did look. This is the same
    fence as `visible_severities`, on the other axis: where the run looked, not
    how hard. `location` is the image reference, which is already part of the
    key (see above), and `asset_id` stays `None` for this scanner on purpose.

One number, not two. A per-image cap only means something if it is LOWER than
the per-run one (an image over the whole run budget is over any larger per-image
cap too), and nothing in the data justifies a particular lower number: the
largest image on 23 Oct (`waha`, 1602) was 64% of that day's 2500 budget and is
27% of today's 6000, and a lower per-image cap would skip it permanently. So the
single `MAX_FINDINGS` is the run's budget and "an image alone over it" is its
degenerate case, reported under a different reason because the remedy differs —
an image alone over the budget stays skipped whatever the others do; one that
merely did not fit comes back when the sum drops.

The per-run sum is kept, and not as protection for the panel or for memory: it
bounds how much one night can write and how much of it is held at once
(`MAX_IMAGES` x a per-image bound of `MAX_FINDINGS` would be 40 x 6000 = 240 000
rows), and it is a tripwire — if a trivy release stops honouring `--severity`,
every image goes up together and the run says so instead of flooding `findings`.
What the number is, what it costs (with the figures, dated, and which of them
were NOT measured on the host) and why it is not 2500 are written next to
`MAX_FINDINGS`, as the severity floor's are next to `SEVERITIES`: one copy, so
the figures cannot drift apart.

What the operator sees: `scans.target` is rewritten when the row is closed, with
`N din M imagini ingerate` next to the severity floor — a count is only honest
next to what it counted; `scans.error` on a `completed` row carries the names of
the skipped images, with their counts and how many CRITICALs the operator is not
being shown, and `check_last_scan` reads that back as `degraded`. A `completed`
row with an `error` is the one place that column is not a failure: it is the run
saying what it did not cover. If NO image can be ingested the run is `failed`.

What is deliberately still a whole-run failure: trivy failing on an image, a
report that is not about the image asked for, an unreadable report, the deadline,
a stale vulnerability database. Those are "could not look" — transient, or a sign
the tool itself is wrong — and a run that is wrong about one image cannot vouch
for the others. Making them per-image as well is a separate decision.

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

#: Ce severitati cere trivy PENTRU IMAGINI. Lista proprie, nu
#: `trivy_fs.SEVERITIES`, si deosebirea e chiar rostul ei.
#:
#: Ridicata la HIGH pe 29 august 2026, la cererea explicita a operatorului. Ce
#: s-a masurat pe gazda in ziua aia, cu trivy 0.73.0, pe cele sase imagini care
#: rulau: 2838 de constatari de la MEDIUM in sus si 450 de la HIGH in sus, cu
#: `MAX_FINDINGS` la 2500 (plafonul de ATUNCI, un refuz al intregii rulari; azi e
#: 6000 pe imagine, vezi acolo). Adica scanarea refuza sa ingereze in fiecare
#: noapte — pe drept, vezi mai jos — deci despre containere nu se raporta nimic.
#: O singura imagine (`snipe-it`) aducea 75% din volumul de la MEDIUM. Cu plafonul
#: de azi cele 2838 ar incapea; pragul ramane la HIGH fiindca el e maneta pentru
#: zgomotul din panou, iar plafonul nu e (vezi `MAX_FINDINGS`).
#:
#: De ce o lista proprie si nu ridicarea celei din `trivy_fs`: constanta de acolo
#: e folosita de amandoua scanerele, deci ridicata acolo ar fi mutat si scanarea
#: de fisiere, care merge azi cu 92 de constatari si pe care nimeni n-a cerut
#: s-o schimbe. Nici nu se uita la acelasi lucru: sub `scan.discovery_paths` sunt
#: dependintele pe care le-a pus operatorul, si acolo un MEDIUM e o linie
#: intr-un lockfile pe care el o poate ridica singur; intr-o imagine, un MEDIUM e
#: aproape mereu un pachet al distributiei din imagine, reparabil doar printr-o
#: reconstructie care le repara oricum pe toate deodata.
#:
#: De ce NU o cheie de configuratie: pragul si `MAX_FINDINGS` sunt o PERECHE, iar
#: perechea are o stare in care scanarea nu mai raporteaza nimic — exact starea
#: din care iesim aici. O cheie reglabila separat de plafon o face din nou
#: atingibila dintr-un fisier de configuratie, tacut, in fiecare noapte. In plus
#: `sentinel.yaml` de pe gazda nu se regenereaza la deploy, deci o cheie noua
#: n-ar ajunge acolo si tot implicitul din cod ar decide. Daca se cere vreodata
#: reglabil, se adauga IMPREUNA cu validarea perechii — si aia e o decizie a
#: operatorului, nu a acestui fisier.
#:
#: `UNKNOWN` ramane in lista, si nu din inertie: o vulnerabilitate careia nimeni
#: nu i-a dat inca o nota nu e una mica. Scoasa, ar disparea tacut — „nu stiu"
#: citit ca „nu conteaza", fix ce interzice CLAUDE.md, si nici nu e ce a cerut
#: operatorul: el a ridicat pragul, iar UNKNOWN nu e sub HIGH, e in afara scarii.
#: Consecinta, scrisa ca sa nu surprinda pe nimeni: constatarile de aici pot avea
#: `severity = medium` chiar cu pragul la HIGH, fiindca `map_severity` parcheaza
#: `UNKNOWN` la `medium`; se deosebesc de un MEDIUM masurat prin
#: `raw.severity_known = false`.
#:
#: Ce se pierde, si e o pierdere reala: cele ~2388 de constatari MEDIUM din
#: imagini nu dispar de pe gazda, doar din raport. De aceea pragul se SPUNE
#: (`severity_scope`) si de aceea o rulare cu el nu are voie sa inchida
#: constatarile MEDIUM ingerate inainte (`visible_severities`).
SEVERITIES = ("UNKNOWN", "HIGH", "CRITICAL")

#: Bugetul de volum al UNEI rulari: cate constatari ingeram, la un loc, intr-o
#: noapte. Se aplica pe IMAGINE, nu pe rulare — vezi sectiunea „Ingest per image"
#: din docstring-ul modulului. O imagine care nu incape nu e ingerata si e
#: numita; restul se ingereaza. Niciodata trunchiere: o lista taiata ar fi urmata
#: de `mark_resolved_absent`, care ar marca restul drept rezolvate, iar garda pe
#: `location` (`skip_locations`) exista tocmai ca imaginea sarita sa ramana cum era.
#:
#: Pana pe 23 octombrie 2026 era un REFUZ al intregii rulari (acelasi rationament
#: ca la `trivy_fs.MAX_FINDINGS`, care ramane refuz: 92 de constatari fata de 500,
#: un singur set de cai). Aici a dus la orbire totala: 2532 de constatari fata de
#: plafonul de atunci, 2500, si operatorul pierdea si aplicatiile lui, nu doar
#: cele doua imagini care depasisera bugetul.
#:
#: 6000, pe 23 octombrie 2026, la decizia operatorului; era 2500. 5000 a fost
#: propus intai si respins la verificare: nu acopera 5335 (vezi mai jos). Argumentul,
#: ca sa nu se re-derive dintr-o data care a trecut:
#:
#:   * NU margineste zgomotul din panou. Randurile unei imagini sarite raman
#:     deschise (`skip_locations`), deci cele 1522 de constatari deschise ale lui
#:     `waha` sunt in panou si la 2500, si la 6000; sarita, ele nu dispar, doar se
#:     invechesc (data ultimei rulari care le-a vazut) si nu se mai pot rezolva —
#:     o reparatie nu s-ar mai inregistra. Maneta pentru zgomot e pragul de
#:     severitate (`SEVERITIES`), nu numarul asta;
#:   * margineste ce scrie o noapte si ce se tine in memorie deodata, iar
#:     amandoua sunt ieftine, vezi mai jos;
#:   * flota nu oscileaza, creste in TREPTE, si fiecare treapta e un EVENIMENT: o
#:     imagine tertă `:latest` care apare sau se reimprospateaza. Seria completa a
#:     rularilor `completed` din `scans` (55, citita pe 23 oct): 446-720 de la
#:     30 aug pana pe 16 oct (sapte saptamani), apoi 720 -> 1517 pe 17 oct (+800:
#:     apare `waha:latest`, 800 din cele 806 randuri noi ale noptii sunt ale ei),
#:     1615, 1615, 1801 pe 20 oct (+186, `snipe-it`), 1725, 2484 pe 22 oct (+698
#:     `waha`, reluata, si +77 `snipe-it`), 2532 pe 23 oct (randul `failed` 208, pe
#:     plafon). Rapoartele de la o noapte la alta: 2,107 / 1,065 / 1,0 / 1,115 /
#:     0,958 / 1,44 / 1,019. Cel mai mare salt e 2,107, pe 16 -> 17 oct; e acelasi
#:     fel de eveniment ca cel din 22 oct, deci nu exista motiv sa fie lasat
#:     deoparte. Un plafon lipit de flota cade la prima treapta: imaginea scoasa e
#:     cea mai MARE (cea cu 34 CRITICAL), `scan:last:trivy_image` trece `degraded`,
#:     iar runner-ul alerteaza. Cele trei citiri 2484 / 2532 / 2517 sunt din doua
#:     zile la capatul scarii, nu o banda: 2517 e o remasurare directa cu trivy a
#:     doua zi (nu e un rand din `scans`), la cateva zeci de 2532 — dar de cealalta
#:     parte a lui 2500, deci un plafon acolo ar fi depins si de zgomotul asta.
#:     6000 acopera o treapta de 2,107 peste noaptea de azi: 2532 x 2,107 = 5335.
#:     Orice plafon fix va fi depasit data viitoare cand apare o imagine mare;
#:     plasa pe imagine (`REASON_IMAGE`/`REASON_BUDGET`) exista pentru asta, si
#:     pentru un trivy care nu mai respecta `--severity`.
#:
#: Ce costa 6000. Citit de pe gazda pe 23 octombrie 2026 (jurnalul serviciilor si
#: `psql`, doar citire), cu rularea din 22 octombrie ca reper (2484 de constatari,
#: 777 noi), in afara de ce spune ca e extrapolat sau nemasurat:
#:
#:   * ingestia (de la «trivy image scan parsed» la «scan complete») a durat
#:     13,6 s, ~5,5 ms per constatare; cu totul, randul `scans` 205 a durat 58 s.
#:     Extrapolat liniar, ~33 s la 6000 — extrapolare, nu masuratoare;
#:   * toata trecerea de scanare a durat 5,5 minute (00:24:13 -> 00:29:46 UTC)
#:     din cele 14400 s ale unitatii, din care 3 min 48 s in `enrich`. Plafoanele
#:     documentate (300 + 1800 + `TIMEOUT_S`) sunt 5700 s si le pazeste un test;
#:     `TIMEOUT_S` acopera doar rularile trivy, ingestia si evaluarea vin DUPA el;
#:   * expedierea: un lot de `findings` e plafonat la 2000 de randuri
#:     (`ship.max_rows_per_batch`, `MAX_ROWS_PER_BATCH` la agregator), deci
#:     bugetul schimba NUMARUL loturilor, nu marimea lor. In noaptea de 22 oct au
#:     plecat `findings`x2000 si, la 3 s distanta (`DRAIN_PAUSE_S` + cererea),
#:     `findings`x502, fara niciun avertisment in jurnalul expeditorului; 6000 de
#:     randuri sunt trei-patru loturi (si randurile atinse de rezolvare), ~9-12 s,
#:     fata de `ship.timeout_s` 30 per cerere.
#:     Plafonul de octeti e `MAX_BODY_BYTES` = 2000 x 4096 = 8 192 000: lotul de
#:     22 oct a purtat 5 057 646 (62%), iar cele mai late 2000 de randuri
#:     `trivy_image` din baza insumeaza ~6,2 MB (~75%, masurat ca text JSON al
#:     randului, deci un reprezentant, nu octetii de pe sarma). Niciuna nu depinde
#:     de buget. Pe gazda, `sentinel.yaml` nu seteaza decat `ship.enabled`, deci
#:     `timeout_s` si `max_rows_per_batch` sunt implicitele din cod;
#:   * limita de 64 KB per coloana a agregatorului: singurul text scris de aici si
#:     tinut acolo e `scans.error`/`scans.target`, ambele marginite de
#:     `MAX_ROW_TEXT` (2000 de caractere) oricare ar fi bugetul — el intra in text
#:     doar ca un numar. Cel mai lung de pe gazda: 254 si 75 de caractere;
#:   * jurnalul: `scan pass done` scrie TOATE constatarile noi (`new_items`) pe o
#:     singura linie. Pe 22 oct, 777 de noi au fost 1,54 MB, taiati de jurnal in
#:     bucati de 48 KiB, ~2 KB per constatare noua; o noapte cu 6000 de noi ar
#:     fi ~12 MB. Cresterea bugetului nu schimba media, dar ridica cel mai rau
#:     caz. Lasat neschimbat aici;
#:   * memoria — NEMASURATA PE GAZDA. `MemoryPeak` e nesetat (`systemctl show`
#:     tipareste 2^64-1): cgroup-ul unitatii dispare cand serviciul `oneshot`
#:     iese, deci dupa rulare nu mai ramane nimic de citit. Singurele cifre sunt
#:     locale, cu tracemalloc pe un raport SINTETIC (Python 3.10 si 3.13; gazda
#:     ruleaza 3.12). Doua ordini de masurare dau doua cifre, si amandoua sunt
#:     adevarate despre altceva: cu raportul deja in memorie si doar `parse()`
#:     urmarit, ~1,2-1,6 KB (masurat de mine si de verificator) per constatare INDIFERENT de lungimea descrierii —
#:     asta e lista fara sirurile pe care le imparte cu raportul (o felie
#:     completa intoarce acelasi obiect in CPython). Dar constatarile TIN acele
#:     siruri vii dupa ce raportul e eliberat, iar asta e ce ramane tinut pe
#:     noapte: urmarind si `json.loads`, ~2,4-2,9 KB cu descrieri de lungimea
#:     medie din baza (560 de caractere) si ~3,9-4,3 KB cu descrieri la maxim
#:     (2000), adica ~15-26 MB la 6000 fata de `MemoryMax=1G`. Cifra scrisa aici
#:     pana pe 23 octombrie (~1,6 KB, ~4 MB la 2500) era a primei ordini si e
#:     retrasa ca figura de memorie tinuta. Ce domina de fapt varful nu e numarul
#:     asta: raportul unei imagini se citeste intreg INAINTE sa decida bugetul,
#:     iar `json.loads` ia de 1,8-2,7 ori marimea fisierului (masurat local),
#:     deci un raport la plafonul `trivy_fs.MAX_OUTPUT_BYTES` (64 MiB) ar fi
#:     ~120-180 MB indiferent de buget.
#:
#: Ce se schimba la plasa `--severity`. Un trivy care ar adauga brusc nivelul
#: MEDIUM ar umfla totalul cu un FACTOR, nu cu un numar: pe 29 august cele sase
#: imagini aveau 2838 de la MEDIUM in sus si 450 de la HIGH in sus, adica ~6,3x.
#: Aplicat flotei de azi (2532) ar da ~15 900, iar `waha` singura (1602) ~10 000 —
#: amandoua mult peste 6000, deci plasa ar suna oricum, ca `REASON_IMAGE`. Asta e o
#: IPOTEZA: raportul e masurat pe alte imagini (`snipe-it` aducea 75% din volumul
#: de la MEDIUM), iar trivy n-a fost rulat pe gazda cu MEDIUM de atunci.
#:
#: Cat timp bugetul se atinge, imaginea cea mai MARE e cea care se sare cand suma
#: depaseste — spus in text, in fiecare noapte in care se intampla.
MAX_FINDINGS = 6000

#: De ce nu a fost ingerata o imagine. Trei motive, pentru ca remediul difera:
#: `image` — singura depaseste tot bugetul (ramane sarita orice ar face celelalte,
#: se rezolva prin imagine sau prin prag); `budget` — incape singura, dar nu
#: laolalta cu cele mai mici (revine cand suma scade, se rezolva prin buget);
#: `report` — raportul ei e prea mare ca sa fie citit in proces, deci nici nu s-a
#: numarat.
REASON_IMAGE = "image"
REASON_BUDGET = "budget"
REASON_REPORT = "report"

#: Cate imagini se numesc in textul de pe rand, si cate caractere au voie sa
#: ocupe numele. Textul ajunge pe Telegram prin `/selfcheck` si in `scans.error`
#: (care pleaca spre agregator cu o limita de 64 KB per coloana — depasita, e
#: REFUZATA, nu taiata), deci e margine, nu stil. Doua margini pe fiecare lista,
#: numarul SI caracterele: zece nume de registry pot avea fiecare sute de
#: caractere. Cele peste margine se numara („si inca N"); lista intreaga e in
#: jurnal. Marginile sunt pe NUME, nu pe tot textul, ca propozitiile de dupa
#: ele (cate au ramas deschise) sa nu fie cele taiate.
MAX_NAMED_SKIPPED = 10
MAX_NAMED_SKIPPED_CHARS = 600
MAX_NAMED_INGESTED = 12
MAX_NAMED_INGESTED_CHARS = 300

#: O referinta mai lunga de-atat se taie in text (intreaga ramane in constatari).
MAX_REFERENCE_CHARS = 120

#: Plafon dur pe textul de pe rand, ultima plasa sub marginile de mai sus. Cu ele
#: textul cel mai lung posibil are ~1600 de caractere; peste asta ceva s-a rupt.
MAX_ROW_TEXT = 2000

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


def severity_scope() -> str:
    """Pragul de severitate, ca text, pentru locurile unde se CITESTE rezultatul.

    O singura sursa pentru toate: `scans.target` (scris de orchestrator la
    deschiderea randului, deci prezent si pe randurile `failed` si `running`),
    mesajul de refuz al plafonului, si — prin `target` — constatarea din
    `/selfcheck`. Compusa, nu scrisa de mana in fiecare loc: doua copii ar
    diverge exact cand cineva schimba `SEVERITIES`, iar atunci panoul ar declara
    alt prag decat cel cerut lui trivy. Un prag raportat gresit e mai rau decat
    unul neraportat — al doilea se vede ca lipsa, primul nu.
    """
    return "severități " + ",".join(SEVERITIES)


def visible_severities() -> tuple[tuple[str, ...], bool]:
    """Ce POATE vedea o rulare cu `SEVERITIES`, in vocabularul coloanei
    `findings.severity`: (severitatile notate, si daca vede si nenotatele).

    Exista fiindca `mark_resolved_absent` inchide tot ce scanerul nu a mai
    raportat, iar dupa ridicarea pragului „nu a mai raportat" acopera doua
    lucruri care nu inseamna acelasi lucru: ce s-a reparat, si ce nu mai e
    cautat. Fara garda asta, o instalare care ARE constatari MEDIUM ingerate
    le-ar anunta pe toate ca rezolvate intr-o noapte.

    Pe gazda de productie, citit pe 23 octombrie 2026, numarul ala e tot ZERO,
    dar din alt motiv decat se scria aici: scanerul a ingerat 2687 de randuri,
    iar niciunul nu e un MEDIUM masurat — cele 701 care spun `medium` sunt
    `UNKNOWN` parcate (`raw.severity_known = false`). Pragul a fost ridicat
    inainte de prima rulare reusita. Garda e scrisa pentru cazul general si
    pentru mutarea urmatoare de prag, nu pentru o pierdere observata aici — si
    asta se spune, ca sa nu para masurata.

    Derivata din `SEVERITIES` prin chiar maparea folosita la ingestie
    (`trivy_fs.map_severity`), nu scrisa inca o data ca lista: o a doua lista ar
    ramane in urma la prima schimbare de prag, si atunci garda ar inchide exact
    constatarile pe care noua rulare nu le mai poate vedea — adica ar face
    tacut chiar ce e pusa sa opreasca.

    Al doilea membru e separat de primul fiindca `UNKNOWN` nu are o severitate a
    lui la noi: `map_severity` il parcheaza la `medium` cu steagul `False`, iar
    un `medium` masurat si un `medium` nenotat trebuie deosebite — altfel garda
    ar lasa sa treaca fix constatarile MEDIUM pe care le apara.
    """
    scored: list[str] = []
    unscored = False
    for label in SEVERITIES:
        severity, known = trivy_fs.map_severity(label)
        if known:
            scored.append(severity)
        else:
            unscored = True
    return tuple(sorted(set(scored))), unscored


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


@dataclass(frozen=True)
class SkippedImage:
    """O imagine scanata (sau incercata) si NEingerata, cu de ce si cu cat.

    `findings` e `None` doar pentru `REASON_REPORT`: raportul n-a fost citit,
    deci nu stim cate sunt — iar „nu stim" nu se scrie ca 0. `critical`, `high` si
    `unrated` spun operatorului ce NU i se arata: 34 CRITICAL sarite si 3 LOW
    sarite nu se pot citi la fel.
    """

    reference: str
    image_id: str
    reason: str
    findings: int | None
    critical: int = 0
    high: int = 0
    unrated: int = 0
    report_bytes: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"reference": self.reference, "image_id": self.image_id,
                "reason": self.reason, "findings": self.findings,
                "critical": self.critical, "high": self.high,
                "unrated": self.unrated, "report_bytes": self.report_bytes}


def _skip(image: RunningImage, items: list[dict[str, Any]], reason: str) -> SkippedImage:
    """Inregistrarea unei imagini sarite, numarand ce are in raport."""
    return SkippedImage(
        reference=image.reference, image_id=image.image_id, reason=reason,
        findings=len(items),
        critical=sum(1 for f in items if f.get("severity") == "critical"),
        high=sum(1 for f in items if f.get("severity") == "high"),
        unrated=sum(1 for f in items
                    if (f.get("raw") or {}).get("severity_known") is False))


class Admission:
    """Ce imagini incap in bugetul de constatari al unei rulari.

    Functie de DIMENSIUNI, nu de ordinea in care vin: rezultatul final e cel mai
    lung prefix, in ordinea crescatoare a (numar de constatari, referinta, id), a
    carui suma incape in `budget`. Se obtine fara a tine toate imaginile in
    memorie: dupa fiecare imagine adaugata, cat timp suma depaseste bugetul se
    scoate cea mai mare. Memoria ramane marginita de buget plus imaginea curenta,
    iar o imagine scoasa o data nu mai poate reveni (suma doar creste), deci
    rezultatul incremental e acelasi cu cel calculat la sfarsit pe toate.

    Departajarea e totala (referinta, apoi id), deliberat: doua imagini cu acelasi
    numar de constatari ar fi altfel scoase in ordinea in care a listat docker
    containerele, iar o repornire ar muta vinovatul de la o noapte la alta.
    """

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self._held: dict[str, tuple[RunningImage, list[dict[str, Any]]]] = {}
        self.skipped: list[SkippedImage] = []

    def total(self) -> int:
        return sum(len(items) for _image, items in self._held.values())

    def offer(self, image: RunningImage, items: list[dict[str, Any]]) -> None:
        """O imagine cu constatarile ei, deja parsate."""
        if len(items) > self.budget:
            # Peste tot bugetul, singura: nu intra nici pe un camp gol. Constatarile
            # se arunca aici — de la ele ramane doar numaratoarea din `_skip`.
            self.skipped.append(_skip(image, items, REASON_IMAGE))
            return
        self._held[image.image_id] = (image, items)
        while self.total() > self.budget:
            victim, victim_items = max(
                self._held.values(),
                key=lambda held: (len(held[1]), held[0].reference, held[0].image_id))
            del self._held[victim.image_id]
            self.skipped.append(_skip(victim, victim_items, REASON_BUDGET))

    def refuse_report(self, image: RunningImage, size: int) -> None:
        """Raport prea mare ca sa fie citit: nici nu stim cate constatari are."""
        self.skipped.append(SkippedImage(
            reference=image.reference, image_id=image.image_id,
            reason=REASON_REPORT, findings=None, report_bytes=size))

    def admitted(self) -> list[tuple[RunningImage, list[dict[str, Any]]]]:
        return sorted(self._held.values(),
                      key=lambda held: (held[0].reference, held[0].image_id))

    def coverage(self, total_images: int) -> dict[str, Any]:
        """Ce a acoperit rularea, in forma care ajunge in `facts` si pe rand."""
        admitted = self.admitted()
        skipped = sorted(self.skipped,
                         key=lambda sk: (-(sk.findings or 0), sk.reference, sk.image_id))
        return {"images": total_images,
                "ingested": [image.reference for image, _items in admitted],
                "admitted_findings": self.total(),
                "budget": self.budget,
                "skipped": [sk.as_dict() for sk in skipped]}


def scan_target(coverage: dict[str, Any] | None = None) -> str:
    """`scans.target`: ce s-a cerut, si — dupa rulare — cat din el s-a acoperit.

    La deschiderea randului (`coverage=None`) e doar domeniul cerut: containerele
    in rulare, la pragul de severitate. La incheiere i se adauga „N din M imagini
    ingerate": o cifra de constatari spusa fara cate imagini acopera se citeste
    ca starea tuturor containerelor, iar aici „2132 de constatari" si „2532 de
    constatari" difera tocmai prin imaginile sarite.

    O singura functie pentru ambele momente, ca prefixul sa nu poata diverge: un
    rand `failed` si unul `completed` se citesc pe acelasi domeniu.
    """
    base = f"docker: imaginile containerelor în rulare, {severity_scope()}"
    if coverage is None:
        return base
    return f"{base}; {len(coverage['ingested'])} din {coverage['images']} imagini ingerate"


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _fit(items: list[str], max_count: int, max_chars: int) -> int:
    """Cate din `items` incap in ambele margini. Cel putin unul (taiat), daca exista.

    Primul intra mereu: o lista nevida care ar spune „si inca N" fara niciun nume
    ar fi exact „zece din unsprezece" fara nume, pe care textul asta il previne.
    """
    if not items:
        return 0
    used = len(_cut(items[0], max_chars))
    count = 1
    for item in items[1:]:
        if count >= max_count or used + 2 + len(item) > max_chars:
            break
        used += 2 + len(item)
        count += 1
    return count


def _describe_skipped(sk: dict[str, Any]) -> str:
    ref = _cut(sk["reference"], MAX_REFERENCE_CHARS)
    if sk["findings"] is None:
        return f"{ref} (numărul de constatări nu se știe: raportul nu s-a citit)"
    parts = []
    if sk["critical"]:
        parts.append(f"{sk['critical']} CRITICAL")
    if sk["high"]:
        parts.append(f"{sk['high']} HIGH")
    if sk["unrated"]:
        parts.append(f"{sk['unrated']} fără notă")
    detail = f": {', '.join(parts)}" if parts else ""
    return f"{ref} ({sk['findings']} constatări{detail})"


def coverage_caveat(coverage: dict[str, Any], held_open: int | None = None, *,
                    ingested_names: bool = True) -> str | None:
    """Textul pentru operator despre imaginile NEingerate. `None` daca nu e niciuna.

    E ce ajunge in `scans.error` al unui rand `completed` si, de acolo, in
    `/selfcheck`. Trebuie sa raspunda la ce ar intreba operatorul la 3 noaptea:
    CARE imagini, CATE constatari si cate CRITICAL nu i se arata, DE CE, si ce se
    intampla cu ce stia deja despre ele. „Zece din unsprezece" fara nume nu
    spune pe ce sa dea cu ochii.

    `held_open` e numarul de randuri deschise ramase pe imaginile sarite, CITIT
    din baza dupa rezolvare (efectul, nu intentia). `None` = nu s-a citit, si
    atunci propozitia nu se scrie deloc, nu se scrie cu un 0 inventat.

    `ingested_names=False` pentru calea in care ingestia a cazut la mijloc: acolo
    „ingerate: …" ar afirma un efect pe care nu l-am verificat.
    """
    skipped = coverage.get("skipped") or []
    if not skipped:
        return None

    budget = coverage["budget"]
    admitted = coverage["admitted_findings"]
    ordered: list[tuple[str, str]] = []
    for reason in (REASON_IMAGE, REASON_BUDGET, REASON_REPORT):
        ordered.extend((reason, _describe_skipped(sk))
                       for sk in skipped if sk["reason"] == reason)
    shown_n = _fit([desc for _reason, desc in ordered],
                   MAX_NAMED_SKIPPED, MAX_NAMED_SKIPPED_CHARS)
    parts: list[str] = []
    for reason in (REASON_IMAGE, REASON_BUDGET, REASON_REPORT):
        names = [desc for r, desc in ordered[:shown_n] if r == reason]
        if not names:
            continue
        one = sum(1 for sk in skipped if sk["reason"] == reason) == 1
        why = {
            REASON_IMAGE: (f"depășește singură tot plafonul de {budget}" if one
                           else f"depășesc singure tot plafonul de {budget}"),
            REASON_BUDGET: (f"încape singură, dar nu și laolaltă cu cele mai mici "
                            if one else
                            f"încap singure, dar nu și laolaltă cu cele mai mici ")
                           + f"(plafonul pe rulare e {budget}, {admitted} admise)",
            REASON_REPORT: ("raportul trivy e prea mare ca să fie citit în proces"
                            if one else
                            "rapoartele trivy sunt prea mari ca să fie citite în proces"),
        }[reason]
        parts.append(f"{why}: {', '.join(names)}")
    if len(ordered) > shown_n:
        parts.append(f"și încă {len(ordered) - shown_n} nenumite aici (lista "
                     f"întreagă e în jurnalul `sentinel-scan`)")

    verdict = ("1 imagine din" if len(skipped) == 1 else f"{len(skipped)} imagini din")
    verb = "NU a fost ingerată" if len(skipped) == 1 else "NU au fost ingerate"
    text = f"{verdict} {coverage['images']} {verb} — {'; '.join(parts)}."
    if held_open is not None:
        text += (f" Constatările lor deja deschise ({held_open}) rămân deschise, "
                 f"nereîmprospătate și nerezolvate — datează de la ultima rulare "
                 f"care le-a văzut.")
    if ingested_names:
        names = [_cut(n, MAX_REFERENCE_CHARS) for n in (coverage.get("ingested") or [])]
        k = _fit(names, MAX_NAMED_INGESTED, MAX_NAMED_INGESTED_CHARS)
        more = len(names) - k
        text += (f" Ingerate ({len(names)}): "
                 f"{', '.join(names[:k]) if k else 'niciuna'}"
                 f"{f' și încă {more}' if more else ''}.")
    return _cut(text, MAX_ROW_TEXT)


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
        # `SEVERITIES` de aici, NU `trivy_fs.SEVERITIES`: pragul imaginilor e la
        # HIGH, al fisierelor a ramas la MEDIUM. Filtrul e la SURSA din acelasi
        # motiv ca la `trivy_fs` — la ingestie, randurile ar fi deja serializate
        # in JSON si citite in proces inainte sa avem ce arunca.
        "--severity", ",".join(SEVERITIES),
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

    `fapte["coverage"]` e scris DOAR pe drumul de succes: ce imagini s-au ingerat
    si care au fost sarite (peste buget, sau cu raportul prea mare). Constatarile
    intoarse sunt ale celor ingerate; ale celor sarite nu sunt, iar apelantul le
    protejeaza de `mark_resolved_absent`. Pe orice drum de eroare e `None`.
    """
    # `severities` e scris din prima linie, nu la sfarsit: apelantul il duce in
    # sumar si in jurnal, iar o rulare care a esuat inainte sa vada vreo imagine
    # tot a fost o rulare cu pragul asta. Lipsa lui pe drumurile de eroare ar
    # face ca „ce s-a cautat" sa se stie doar cand s-a si gasit ceva.
    facts: dict[str, Any] = {"docker": None, "docker_detail": None,
                             "db_version": None, "containers": 0, "images": 0,
                             "references": [], "total": 0,
                             "severities": list(SEVERITIES),
                             # Ce imagini s-au ingerat si care nu, cu motivul.
                             # `None` pana se decide: pe un drum de eroare nu
                             # s-a ingerat NIMIC, si o acoperire „calculata"
                             # dar neaplicata ar fi o afirmatie despre un efect
                             # care n-a avut loc.
                             "coverage": None}

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
    admission = Admission(MAX_FINDINGS)
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
                # Un fapt MASURAT despre imaginea asta (marimea raportului), nu o
                # cadere a uneltei: o repetare nu il schimba. Se sare si se
                # numeste, ca o imagine cu raport urias sa nu orbeasca flota.
                # Nu se citeste in proces sub `MemoryMax=1G`.
                log.warning("raport trivy prea mare, imaginea nu se ingereaza",
                            extra={"image": image.reference, "bytes": size,
                                   "limit": trivy_fs.MAX_OUTPUT_BYTES})
                admission.refuse_report(image, size)
                continue
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

            admission.offer(image, parse(payload, reference=image.reference,
                                         image_id=image.image_id,
                                         containers=image.containers))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    coverage = admission.coverage(len(images))
    items = [f for _image, found in admission.admitted() for f in found]
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

    if not coverage["ingested"]:
        # Nicio imagine nu a putut fi ingerata: nimic de predat, deci rularea e
        # un ESEC, nu un `completed` cu zero constatari — acela ar fi exact
        # minciuna din 0029. Pragul se NUMESTE in mesaj, nu se scrie de mana.
        return [], (f"{len(images)} imagini rulează ({severity_scope()}), dar "
                    f"niciuna nu a putut fi ingerată; nu se ingerează nimic. "
                    f"{coverage_caveat(coverage, ingested_names=False)}"), facts

    facts["coverage"] = coverage
    log.info("trivy image scan parsed",
             extra={"findings": len(unique), "images": len(images),
                    "ingested": len(coverage["ingested"]),
                    "skipped": [sk["reference"] for sk in coverage["skipped"]],
                    "containers": facts["containers"], "db_version": described,
                    "severities": facts["severities"]})
    return list(unique.values()), None, facts
