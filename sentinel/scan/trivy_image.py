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
6000 per-image budget it was from 23 October (9000 since 18 November) — so this scanner refused every
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
changes, with nobody having touched this scanner. That is why the cap is 9000
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
    night it happens, and the number is the operator's to move. Since 18
    November 2026 that price is bounded in time by the rotation below: the
    largest image is skipped, but not on every night;
  * ROTATION (18 November 2026): smallest-first alone starves the largest image
    for good — the same image is the largest every night, so it is skipped every
    night, its rows go stale and no repair of it can ever be recorded. That is
    what happened to `devlikeapro/waha:latest` (2828 findings): skipped from the
    night the sum crossed the old budget, with nothing in the rule that would
    ever let it back in. So one image per run is given PRIORITY: the one that has
    gone longest without being seen, if it was PASSED OVER (below), is admitted
    first and the rest fill what is left smallest-first. See `plan_rotation` and `Admission` for the
    rule, its bound and what it costs;
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
18% of today's 9000 (27% of the 6000 before), and a lower per-image cap would
skip it permanently. So the single `MAX_FINDINGS` is the run's budget and "an image alone over it" is its
degenerate case, reported under a different reason because the remedy differs —
an image alone over the budget stays skipped whatever the others do; one that
merely did not fit comes back when the sum drops.

The per-run sum is kept, and not as protection for the panel or for memory: it
bounds how much one night can write and how much of it is held at once
(`MAX_IMAGES` x a per-image bound of `MAX_FINDINGS` would be 40 x 9000 = 360 000
rows), and it is a tripwire — if a trivy release stops honouring `--severity`,
every image goes up together and the run says so instead of flooding `findings`.
What the number is, what it costs (with the figures, dated, and which of them
were NOT measured on the host) and why it is not 2500 are written next to
`MAX_FINDINGS`, as the severity floor's are next to `SEVERITIES`: one copy, so
the figures cannot drift apart.

### Rotation: who has been passed over, and how that is known

The fact "when was this image last ingested" comes from `findings.last_seen`:
the upsert is the only writer of that column for this scanner, it is written
with `now()` by the database (no clock of this process is involved), and it moves
for every row the run reports. So `max(last_seen)` over an image's `location` is
the last night that image was ingested AND had a finding in it. No new table:
`scans` records counts and text, not images, and `scans.error` is prose.

What that fact cannot say, stated so nobody reads more into it:

  * an image whose last ingest reported ZERO findings, or whose findings are all
    resolved (`mysql:8.0` on the host: 113 rows, none open, last seen 20 Oct),
    looks stale although it was ingested last night. It also costs nothing —
    zero findings fit in any budget — so the rule below never lets it take the
    priority slot (the slot goes to an image that has findings to admit);
  * an image that has never had a finding has no row at all, i.e. "never
    ingested" and "ingested, clean" look the same. Same answer: it costs nothing;
  * the date is therefore worded in the operator text as "last finding seen",
    which is what it is, not "last ingested".

"Stale" alone is not the trigger. After a normal night every image carries the
same date, within seconds of each other (25 s across 25 images on 18 Nov), so
"the stalest" would be an arbitrary image, and promoting an arbitrary big one
would skip small ones for nothing. After a failed run or an outage ALL images are
equally old and nobody was neglected. The trigger is being PASSED OVER: an image
is overdue when its last sight is older than the newest sight in the fleet by more
than `ROTATION_MARGIN` — somebody else was ingested since, and it was not. That
needs no wall clock either, only the database's own timestamps. The margin is
12 hours: far above the spread inside one run, far below the nightly cadence; a
cadence faster than the margin would delay detection to the margin, not break it.

The rule, in `Admission` (round 2; round 1 is described at the end of this
section because its defect is the reason for this shape):

  * `plan_rotation` lists the overdue images of the running fleet, longest
    unseen first (never-seen before all). `scan_order` scans them first, in that
    order;
  * the overdue images that have findings (0 < findings <= `MAX_FINDINGS`) are
    admitted in that order, each if it still fits in what is left of the budget
    (one that does not fit is skipped and the next is tried). They are admitted
    BEFORE the plain rule, but they cost only their own findings: a small newcomer
    takes a few rows, not somebody else's place;
  * everything else is admitted by the plain smallest-first rule, in the budget
    that remains. With no overdue image the result is exactly the smallest-first
    of the previous section, so no small image is skipped to make room for a big
    one unless somebody has actually been passed over;
  * an image that was skipped although the plain rule, without rotation, would
    have admitted it is marked `displaced`, and the images admitted only thanks to
    rotation are named in the text.

Starvation bound, for an image X that fits alone and whose report is readable: if
the sum binds every night and nothing else changes, X is skipped at most ONE run
after it was last ingested — the next run finds it passed over, and if it is the
stalest overdue image with findings it is admitted first. Otherwise it is
admitted unless the overdue images STALER than itself, which are admitted before
it, leave no room: it waits at most as many runs as it takes to clear those, each
becoming fresh once admitted. With a fixed fleet that is at most n-1 extra runs,
n <= `MAX_IMAGES`. New images do not make that worse unless they are themselves
too big to fit beside X: a small newcomer (never seen, hence staler than X) is
admitted before X but leaves room for it; a big one takes the room once and is
then fresh. So the bound is 1 + the number of staler images that cannot fit
together with X, newcomers included: a stream of new images each too big to fit
beside X can keep delaying it, and that is not repaired here.

Round 1 gave ONE priority slot to the first overdue image with findings, never-seen
first. The verifier simulated the 18 November fleet at 1/10 scale with one small
new image per night: it took the slot every night, `waha` — who needed it — was
skipped 38 nights of 40 (digest-pinned images such as `traefik`, `whoami` and
`rustdesk` become "never seen" at every version bump; the image count rose on 6 of
the last 19 nights). The first repair of that — the slot only for an image the plain
rule would not admit — still starved an image that the plain rule admitted but the
lead displaced every night (a random fleet in the simulation test, 59 nights).
Admitting every overdue image first closes both.

KNOWN LIMIT, NOT FIXED: rotation is per REFERENCE (`location`), not per image ID.
Two image IDs under one reference (a re-pulled tag with only some containers
restarted) share the date and the rank. If one is admitted and the other does not
fit, the admitted one refreshes the shared date and the other looks "seen": it can
be skipped EVERY night without ever becoming overdue, and nothing in the operator
text says so. The old rule skipped it the same; the host has no such pair today (`findings.location` holds one row set per
reference, and the key does not include the digest on purpose). Also: a rejected
overdue image is not retained for a retry (memory), so the exactness of the
first-fit depends on `scan_order`; out of order, an image rejected earlier does not
come back.

What it costs: on a night with a big overdue image, smaller ones that the plain rule
would have admitted can be the ones skipped (marked `displaced` in the text). The
skip is named, with the date its last finding was seen.

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

import dataclasses
import json
import os
import re
import shutil
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
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
#: 9000 pe imagine, vezi acolo). Adica scanarea refuza sa ingereze in fiecare
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
#: 9000, pe 18 noiembrie 2026, la decizia operatorului; era 6000 (23 octombrie).
#: Impreuna cu ROTATIA (vezi „Rotation" in docstring-ul modulului), nu in locul ei.
#:
#: Ce s-a vazut. Totalurile rularilor `completed` din `scans`, citite pe 18
#: noiembrie 2026: 3418 (5 nov), 3146, 3214, 3218 (8 nov), 3218, 3426 (10 nov),
#: 3681, 3864 (12 nov), 4216, 4231 (14 nov), 4459 (15 nov), 4735 (16 nov), 5391
#: (17 nov), apoi 3185 pe 18 nov: 24 de imagini ingerate, iar `devlikeapro/waha:latest`
#: (2828 de constatari) SARITA cu `REASON_BUDGET`, fiindca 3185 + 2828 = 6013, adica
#: 13 peste plafon. Flota creste ~280 de constatari pe noapte, pe tot frontul (615
#: constatari noi in cele 24 de imagini ingerate in ultima noapte), nu printr-o
#: treapta de la o singura imagine — deci nu e un eveniment ca cele din octombrie,
#: ci o panta, si orice plafon fix o atinge. Pe gazda, `waha` are 2821 de constatari
#: deschise cu `last_seen` 17 noiembrie: sarita, a ramas deschisa, a imbatranit, si
#: o reparatie a ei nu s-ar mai putea inregistra.
#:
#: Ce schimba rotatia in rolul acestui numar. Pana acum plafonul hotara cine e
#: ASCUNS: cel mai mare, in fiecare noapte, la nesfarsit — nu exista nimic care sa
#: l-aduca inapoi. Acum hotaraste doar cine ASTEAPTA o noapte: imaginea trecuta cu
#: vederea intra prima la rularea urmatoare, deci cea mai mare e reimprospatata cel
#: putin o noapte din doua, oricat ar creste flota (cat timp incape singura). Plafonul
#: ramane o margine de volum si o alarma, nu maneta pentru ce se vede. Nu inlocuieste
#: rotatia: 9000 la panta de azi (6013 + 280/noapte) se atinge in ~11 nopti — o
#: EXTRAPOLARE liniara, seria are si trepte — si fara rotatie ar reaparea acelasi
#: defect, cu alta imagine in locul lui `waha`.
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
#:     (9000 acopera si 2540 x 2,107 = 5352 cu loc de ramas; dar panta din noiembrie
#:     nu e o treapta, vezi mai sus.)
#:     Orice plafon fix va fi depasit data viitoare cand apare o imagine mare;
#:     plasa pe imagine (`REASON_IMAGE`/`REASON_BUDGET`) exista pentru asta, si
#:     pentru un trivy care nu mai respecta `--severity`.
#:
#: Ce costa 9000. Fiecare cifra spune de unde vine: MASURAT (pe gazda, citit pe 18
#: noiembrie 2026, doar `psql` SELECT) sau EXTRAPOLAT (liniar din ce e masurat, nu
#: rulat la 9000). Cifrele din 23 octombrie, cu rularea din 22 octombrie ca reper
#: (2484 de constatari, 777 noi), sunt pastrate unde nu le-am remasurat:
#:
#:   * ingestia. MASURAT pe 18 nov: cele 3185 de constatari ingerate au `last_seen`
#:     intre 01:39:47 si 01:40:12, adica ~25 s, ~7,9 ms per constatare (pe 22 oct:
#:     13,6 s, ~5,5 ms; diferenta nu e explicata, n-am masurat de ce).
#:     EXTRAPOLAT la 9000: 50-71 s. Intreaga rulare (randul `scans`) a durat 257 s
#:     pe 18 nov (3185) si 218 s pe 17 nov (5391) — masurat; durata o dau rularile
#:     trivy pe cele 25 de imagini, nu numarul de constatari. Toata trecerea de
#:     scanare: 5,5 minute pe 22-23 oct, din cele 14400 s ale unitatii. Plafoanele
#:     documentate (300 + 1800 + `TIMEOUT_S`) sunt 5700 s si le pazeste un test;
#:     `TIMEOUT_S` acopera doar rularile trivy, ingestia si evaluarea vin DUPA el;
#:   * expedierea: un lot de `findings` e plafonat la 2000 de randuri
#:     (`ship.max_rows_per_batch`, `MAX_ROWS_PER_BATCH` la agregator), deci
#:     bugetul schimba NUMARUL loturilor, nu marimea lor: 9000 de randuri sunt cinci
#:     loturi (erau trei la 6000; 5391 pe 17 nov au fost tot trei). Ingestia atinge
#:     `last_seen` pe FIECARE rand raportat, deci tot ce e ingerat se reexpediaza
#:     in noaptea aia. Pe 22 oct au plecat `findings`x2000 si, la 3 s distanta
#:     (`DRAIN_PAUSE_S` + cererea), `findings`x502; cinci loturi ar fi ~15 s —
#:     EXTRAPOLAT — fata de `ship.timeout_s` 30 PER CERERE. Plafonul de octeti e
#:     `MAX_BODY_BYTES` = 2000 x 4096 = 8 192 000. MASURAT pe 18 nov: cele mai late
#:     2000 de randuri `trivy_image` din baza insumeaza 6 838 437 de caractere
#:     (83% din plafon; pe 23 oct erau ~6,2 MB, 75%) ca text JSON al randului, deci
#:     un reprezentant, nu octetii de pe sarma. Nu depinde de buget (un lot are cel
#:     mult 2000 de randuri), dar marja se subtiaza de la sine pe masura ce
#:     descrierile cresc, iar urmarirea ei nu e treaba acestui numar. Pe
#:     gazda, sectiunea `ship:` din `sentinel.yaml` seteaza `enabled`, `url` si
#:     `max_backfill_days: 3650` (citit de verificator pe 18 nov; eu nu am putut
#:     citi fisierul), dar nu `timeout_s` si nici `max_rows_per_batch`, deci acestea
#:     sunt implicitele din cod (30 s per cerere, 2000 de randuri). Prima varianta a
#:     acestui rand spunea ca nu se seteaza decat `enabled`: cifra citita pe 23 oct
#:     era incompleta, iar concluzia a ramas aceeasi;
#:   * limita de 64 KB per coloana a agregatorului: singurul text scris de aici si
#:     tinut acolo e `scans.error`/`scans.target`, ambele marginite de
#:     `MAX_ROW_TEXT` (2000 de caractere) oricare ar fi bugetul — el intra in text
#:     doar ca un numar. MASURAT pe 18 nov: cel mai lung `error` din ultimele 14
#:     zile are 606 de caractere (textul rotatiei, adaugat dupa aceasta data, il
#:     mareste cu ~300; il pazeste un test);
#:   * jurnalul: `scan pass done` scrie TOATE constatarile noi (`new_items`) pe o
#:     singura linie. Pe 22 oct, 777 de noi au fost 1,54 MB, taiati de jurnal in
#:     bucati de 48 KiB, ~2 KB per constatare noua; 615 noi pe 18 nov ar fi ~1,2
#:     MB. Cazul rau e prima ingestie a unei flote intregi: 9000 de noi ar fi ~18 MB
#:     (6000 -> ~12 MB). EXTRAPOLAT din cei ~2 KB, nemasurat la volumul asta.
#:     Cresterea bugetului nu schimba media, dar ridica cel mai rau caz. Lasat
#:     neschimbat aici;
#:   * memoria — NEMASURATA PE GAZDA. `MemoryPeak` e nesetat (`systemctl show`
#:     tipareste 2^64-1): cgroup-ul unitatii dispare cand serviciul `oneshot`
#:     iese, deci dupa rulare nu mai ramane nimic de citit. Singurele cifre sunt
#:     locale, cu tracemalloc pe un raport SINTETIC (Python 3.10 si 3.13; gazda
#:     ruleaza 3.12), de pe 23 oct, NEremasurate pe 18 nov. Doua ordini de masurare
#:     dau doua cifre, si amandoua sunt adevarate despre altceva: cu raportul deja
#:     in memorie si doar `parse()` urmarit, ~1,2-1,6 KB per constatare INDIFERENT
#:     de lungimea descrierii — asta e lista fara sirurile pe care le imparte cu
#:     raportul (o felie completa intoarce acelasi obiect in CPython). Dar
#:     constatarile TIN acele siruri vii dupa ce raportul e eliberat, iar asta e ce
#:     ramane tinut pe noapte: urmarind si `json.loads`, ~2,4-2,9 KB cu descrieri de
#:     lungimea medie din baza (560 de caractere) si ~3,9-4,3 KB cu descrieri la
#:     maxim (2000). EXTRAPOLAT la 9000: ~22-26 MB, ~35-39 MB la maxim (la 6000:
#:     ~15-26 MB), fata de `MemoryMax=1G`. Ce domina de fapt varful nu e numarul
#:     asta: raportul unei imagini se citeste intreg INAINTE sa decida bugetul, iar
#:     `json.loads` ia de 1,8-2,7 ori marimea fisierului (masurat local), deci un
#:     raport la plafonul `trivy_fs.MAX_OUTPUT_BYTES` (64 MiB) ar fi ~120-180 MB
#:     indiferent de buget. Admiterea tine in memorie cel mult bugetul plus imaginea
#:     curenta; rotatia nu schimba asta: imaginile restante se admit pe
#:     loc, in ordinea vechimii, si o respinsa nu se retine, deci suma tinuta ramane
#:     cel mult bugetul (restantele + restul), la fel ca inainte.
#:
#: Ce se schimba la plasa `--severity`. Un trivy care ar adauga brusc nivelul
#: MEDIUM ar umfla totalul cu un FACTOR, nu cu un numar: pe 29 august cele sase
#: imagini aveau 2838 de la MEDIUM in sus si 450 de la HIGH in sus, adica ~6,3x.
#: Aplicat flotei de azi (2532) ar da ~15 900, iar `waha` singura (1602) ~10 000 —
#: amandoua peste 9000 (15 900 si ~10 000 cu cifrele din 23 oct; cu cele de azi, 6013
#: si 2828, ar fi ~38 000 si ~17 800), deci plasa ar suna oricum, ca `REASON_IMAGE`.
#: Asta e o IPOTEZA: raportul e masurat pe alte imagini (`snipe-it` aducea 75% din
#: volumul de la MEDIUM), iar trivy n-a fost rulat pe gazda cu MEDIUM de atunci.
#:
#: Cat timp bugetul se atinge, imaginea cea mai MARE e cea care se sare cand suma
#: depaseste, in afara de imaginea-lider a rotatiei (vezi `Admission`) — spus in
#: text, in fiecare noapte in care se intampla.
MAX_FINDINGS = 9000

#: Cat de in urma fata de CEA MAI RECENTA constatare vazuta in flota trebuie sa fie
#: o imagine ca sa fie „trecuta cu vederea" (si deci candidata la prioritate). Nu o
#: varsta fata de ceasul acestui proces: se compara doua marci de timp puse de
#: baza (`last_seen = now()`), deci nicio abatere de ceas nu intra. 12 ore: mult
#: peste cat dureaza ingestia unei rulari (25 s pe 18 nov 2026 — imaginile aceleiasi
#: rulari poarta aceeasi data) si mult sub cadenta de o noapte. Vezi „Rotation" in
#: docstring-ul modulului.
ROTATION_MARGIN = timedelta(hours=12)

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

#: Cate imagini cu prioritate de rotatie se numesc in text (restul se numara), si
#: cate caractere au voie sa ocupe numele lor impreuna cu data: doua margini, ca la
#: celelalte liste. Doar numarul lasa trei referinte de 120 de caractere sa
#: umple ~500 de caractere si sa impinga textul peste `MAX_ROW_TEXT`.
MAX_NAMED_PROMOTED = 3
MAX_NAMED_PROMOTED_CHARS = 200

#: O referinta mai lunga de-atat se taie in text (intreaga ramane in constatari).
MAX_REFERENCE_CHARS = 120

#: Plafon dur pe textul de pe rand, ultima plasa sub marginile de mai sus. Cat de
#: lung poate ajunge cu ele, MASURAT pe 19 noiembrie 2026 (lungime netaiata, cu
#: plafonul ridicat): comentariul de dinainte spunea ~1600; verificatorul a
#: construit 1864, iar o cautare adversariala a dat 2034 (4 imagini cu prioritate
#: cu referinte de 120 de caractere, 5 sarite, 30 ingerate de cate 30) — peste
#: plafon, adica `…` la sfarsit si lista imaginilor ingerate taiata. De aceea
#: numele imaginilor cu prioritate au si margine pe caractere
#: (`MAX_NAMED_PROMOTED_CHARS`). Cu ea: maximul gasit e 1857 (doua cautari, 150 000
#: de configuratii aleatoare + 150 000 de pasi de urcare, semintele 7 si 11); suma
#: maximelor fiecarei componente luate separat e ~2000, deci NU e o margine
#: demonstrata, doar una cautata. Peste plafon NU se respinge nimic: `_cut` taie
#: sfarsitul (lista „Ingerate", ultima propozitie) si pune `…`; coloana din
#: agregator accepta 64 KB, deci plafonul e al nostru. Il acopera
#: `test_the_hard_cap_on_the_row_text_holds_even_if_the_other_bounds_fail` (taierea)
#: si `test_the_row_text_never_exceeds_its_cap_for_the_worst_inputs_found` (suma).
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
    #: Ultima zi (UTC) in care s-a vazut o constatare a imaginii, din
    #: `findings.last_seen`; `None` = nu s-a vazut niciodata. Conteaza doar daca
    #: `seen_known`: fara datele rotatiei „nu stim" nu are voie sa devina
    #: „niciodata".
    last_seen: str | None = None
    seen_known: bool = False
    #: Inlaturata DE imaginea cu prioritate de rotatie (ar fi incaput dupa regula
    #: „cele mai mici intai"), nu de imaginile mai mici. Textul de pe rand spune
    #: cele doua situatii diferit.
    displaced: bool = False

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "reference": self.reference, "image_id": self.image_id,
            "reason": self.reason, "findings": self.findings,
            "critical": self.critical, "high": self.high,
            "unrated": self.unrated, "report_bytes": self.report_bytes,
            "displaced": self.displaced}
        if self.seen_known:
            out["last_seen"] = self.last_seen
        return out


@dataclass(frozen=True)
class Rotation:
    """Ce imagini ale flotei au fost trecute cu vederea, cele mai vechi intai.

    `overdue` e lista de REFERINTE (= `location`), cea nevazuta de cel mai mult
    timp prima; cele fara nicio constatare in baza, inaintea tuturor. `last_seen`
    e doar pentru referintele flotei care au vreun rand, ca textul sa poata spune
    de cand.
    """

    overdue: tuple[str, ...]
    last_seen: Mapping[str, datetime]


def plan_rotation(references: Sequence[str],
                  last_seen: Mapping[str, datetime]) -> Rotation:
    """Imaginile trecute cu vederea, din `max(findings.last_seen)` per `location`.

    „Trecuta cu vederea" = ultima ei constatare vazuta e mai veche decat cea mai
    recenta din tot scanerul cu mai mult de `ROTATION_MARGIN`: altcineva a fost
    ingerat de atunci, ea nu. NU „cea mai veche": dupa o noapte obisnuita toate
    poarta aceeasi data si „cea mai veche" ar fi una la intamplare, iar dupa o
    rulare cazuta sau o pana toate sunt la fel de vechi si nimeni n-a fost lasat
    pe dinafara. Fara nicio constatare in baza (prima rulare) nu e nimeni trecut cu
    vederea.

    Pura, ca sa poata fi probata fara baza. Citirea din baza e
    `fx.last_seen_by_location`; aici nu se atinge ceasul.
    """
    latest = max(last_seen.values(), default=None)
    if latest is None:
        return Rotation((), {})
    cutoff = latest - ROTATION_MARGIN
    stale = [ref for ref in set(references)
             if ref not in last_seen or last_seen[ref] < cutoff]
    # (a vazut-o vreodata?, de cand, nume): False < True pune „niciodata" primele;
    # numele departajeaza total, ca ordinea sa nu depinda de `set`.
    stale.sort(key=lambda ref: (ref in last_seen, last_seen.get(ref, latest), ref))
    return Rotation(tuple(stale),
                    {ref: last_seen[ref] for ref in set(references) if ref in last_seen})


def scan_order(images: Sequence[RunningImage],
               rotation: Rotation | None) -> list[RunningImage]:
    """Ordinea in care se scaneaza: cele trecute cu vederea PRIMELE, cea mai veche
    inaintea celorlalte, apoi restul in ordinea (referinta, id).

    Nu e cosmetica: `Admission` primeste imaginile restante in ordinea asta si
    decide pe loc, fara sa tina ce a respins (memoria ramane marginita de buget).
    Fara nimeni trecut cu vederea ordinea e cea de pana acum.
    """
    rank = ({ref: n for n, ref in enumerate(rotation.overdue)}
            if rotation is not None else {})
    return sorted(images, key=lambda i: (
        rank.get(i.reference, len(rank)), i.reference, i.image_id))


def _day(moment: datetime) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(moment.timestamp()))


def _skip(image: RunningImage, items: list[dict[str, Any]], reason: str,
          seen: dict[str, Any] | None = None, *,
          displaced: bool = False) -> SkippedImage:
    """Inregistrarea unei imagini sarite, numarand ce are in raport."""
    return SkippedImage(
        reference=image.reference, image_id=image.image_id, reason=reason,
        findings=len(items),
        critical=sum(1 for f in items if f.get("severity") == "critical"),
        high=sum(1 for f in items if f.get("severity") == "high"),
        unrated=sum(1 for f in items
                    if (f.get("raw") or {}).get("severity_known") is False),
        displaced=displaced, **(seen or {}))


class Admission:
    """Ce imagini incap in bugetul de constatari al unei rulari.

    Regula de baza e functia de DIMENSIUNI, nu de ordinea in care vin: cel mai lung
    prefix, in ordinea crescatoare a (numar de constatari, referinta, id), a carui
    suma incape in `budget`. Dupa fiecare imagine adaugata, cat timp suma depaseste
    bugetul se scoate cea mai mare; memoria ramane marginita de buget plus imaginea
    curenta, iar o imagine scoasa nu mai poate reveni. Departajarea e totala, ca o
    repornire de container sa nu mute vinovatul de la o noapte la alta.

    ROTATIA pune inaintea regulii de baza imaginile TRECUTE CU VEDEREA (`Rotation`):
    cele cu 0 < constatari <= buget se admit in ordinea vechimii (cea nevazuta de cel
    mai mult timp prima), fiecare daca incape in ce a ramas din buget (cea care nu
    incape e sarita, urmatoarea se incearca). Restul se admit dupa regula de baza,
    in ce ramane. Asta inlocuieste „un singur loc pentru prima restanta" din runda 1,
    care avea doua defecte, ambele prinse de verificator:

      * locul se cheltuia pe imagini care ar fi incaput oricum (una noua si mica, o
        imagine fixata pe digest al carei digest s-a schimbat — „nevazuta" din nou),
        iar `waha` ramanea sarita cat timp apareau imagini noi;
      * un lider unic inlatura cea mai mare imagine ramasa, care putea fi chiar una
        mai veche decat el, in fiecare noapte.

    Acum o imagine mica trecuta cu vederea costa doar cele cateva constatari ale ei,
    nu locul altcuiva, iar cea mai veche dintre cele cu constatari e mereu prima.
    Imaginile fara constatari nu intra in lista restantelor (costa zero; una curata
    ar aparea „nevazuta" in fiecare noapte).

    Garantia depinde de ordinea sosirii: `scan` le aduce pe cele restante INAINTEA
    celorlalte si in ordinea vechimii (`scan_order`), iar o restanta respinsa nu e
    retinuta ca sa fie reincercata (memorie). Daca una mai veche ajunge dupa una mai
    noua, ia locul celei mai noi (care poate fi inlaturata), dar o imagine respinsa
    mai devreme nu mai revine; garantia pentru cea mai veche ramane. Nu e o cale
    parcursa de `scan`.

    Ce NU promite si marginea de infometare: in modulul scanerului.

    LIMITA CUNOSCUTA (nereparata): rotatia e pe REFERINTA (= `location`), nu pe id.
    Doua id-uri de imagine sub aceeasi referinta (un `:latest` re-tras cu doar o
    parte din containere repornite) impart data si rangul. Daca unul e admis si
    celalalt nu incape, data comuna se reimprospateaza prin cel admis si al doilea
    pare „vazut": poate fi SARIT in fiecare noapte, fara sa devina vreodata
    restant, si nimic din text nu o spune. Regula veche il sarea la fel; pe gazda
    nu exista o pereche asa la ultima verificare (a verificatorului, 18 noiembrie 2026).
    """

    def __init__(self, budget: int, rotation: Rotation | None = None) -> None:
        self.budget = budget
        self.rotation = rotation
        self._rank = ({ref: i for i, ref in enumerate(rotation.overdue)}
                      if rotation is not None else {})
        # Restantele admise (cu rangul lor) si restul, tinute separat: cele doua
        # clase au reguli diferite de scoatere.
        self._owed: dict[str, tuple[int, RunningImage, list[dict[str, Any]]]] = {}
        self._held: dict[str, tuple[RunningImage, list[dict[str, Any]]]] = {}
        self._skipped: list[SkippedImage] = []
        # (constatari, referinta, id) al fiecarei imagini care incape singura, ca la
        # sfarsit sa se poata spune ce ar fi admis regula de baza FARA rotatie.
        self._sizes: list[tuple[int, str, str]] = []
        self._settled = False

    def _owed_sum(self) -> int:
        return sum(len(items) for _rank, _image, items in self._owed.values())

    def _pool_sum(self) -> int:
        return sum(len(items) for _image, items in self._held.values())

    def _seen(self, image: RunningImage) -> dict[str, Any] | None:
        """Cand s-a vazut ultima constatare a imaginii; `None` fara rotatie."""
        if self.rotation is None:
            return None
        when = self.rotation.last_seen.get(image.reference)
        return {"seen_known": True,
                "last_seen": _day(when) if when is not None else None}

    def offer(self, image: RunningImage, items: list[dict[str, Any]]) -> None:
        """O imagine cu constatarile ei, deja parsate."""
        if self._settled:
            raise RuntimeError("Admission: imagine oferita dupa ce rezultatul a "
                               "fost citit")
        if len(items) > self.budget:
            # Peste tot bugetul, singura: nu intra nici pe un camp gol. Constatarile
            # se arunca aici — de la ele ramane doar numaratoarea din `_skip`.
            self._skipped.append(_skip(image, items, REASON_IMAGE, self._seen(image)))
            return
        self._sizes.append((len(items), image.reference, image.image_id))
        rank = self._rank.get(image.reference)
        if items and rank is not None:
            self._owed[image.image_id] = (rank, image, items)
            self._refit_owed()
        else:
            self._held[image.image_id] = (image, items)
        self._trim_pool()

    def _refit_owed(self) -> None:
        """First-fit in ordinea vechimii: cea care nu incape in restul bugetului e
        sarita, urmatoarea se incearca."""
        used = 0
        for ident, (rank, image, items) in sorted(
                self._owed.items(), key=lambda kv: (kv[1][0], kv[1][1].image_id)):
            if used + len(items) <= self.budget:
                used += len(items)
            else:
                del self._owed[ident]
                self._skipped.append(_skip(image, items, REASON_BUDGET,
                                           self._seen(image)))

    def _trim_pool(self) -> None:
        room = self.budget - self._owed_sum()
        while self._pool_sum() > room:
            victim, victim_items = max(
                self._held.values(),
                key=lambda held: (len(held[1]), held[0].reference, held[0].image_id))
            del self._held[victim.image_id]
            self._skipped.append(_skip(victim, victim_items, REASON_BUDGET,
                                       self._seen(victim)))

    def _plain_prefix(self) -> set[str]:
        """Id-urile pe care regula de baza, FARA rotatie, le-ar fi admis."""
        out: set[str] = set()
        total = 0
        for n, _ref, ident in sorted(self._sizes):
            if total + n > self.budget:
                break
            out.add(ident)
            total += n
        return out

    def _settle(self) -> None:
        """Marcheaza, o singura data, ce a fost inlaturat de rotatie."""
        if self._settled:
            return
        self._settled = True
        plain = self._plain_prefix()
        self._skipped = [
            dataclasses.replace(sk, displaced=True)
            if sk.reason == REASON_BUDGET and sk.image_id in plain else sk
            for sk in self._skipped]

    @property
    def skipped(self) -> list[SkippedImage]:
        self._settle()
        return self._skipped

    def total(self) -> int:
        return self._owed_sum() + self._pool_sum()

    def refuse_report(self, image: RunningImage, size: int) -> None:
        """Raport prea mare ca sa fie citit: nici nu stim cate constatari are."""
        self._skipped.append(SkippedImage(
            reference=image.reference, image_id=image.image_id,
            reason=REASON_REPORT, findings=None, report_bytes=size,
            **(self._seen(image) or {})))

    def admitted(self) -> list[tuple[RunningImage, list[dict[str, Any]]]]:
        both = [(image, items) for _rank, image, items in self._owed.values()]
        both += list(self._held.values())
        return sorted(both, key=lambda held: (held[0].reference, held[0].image_id))

    def promoted(self) -> list[RunningImage]:
        """Imaginile admise DOAR datorita rotatiei, cea mai veche intai: regula de
        baza, fara ea, nu le-ar fi admis."""
        plain = self._plain_prefix()
        return [image for _rank, image, _items in sorted(
                    self._owed.values(), key=lambda o: (o[0], o[1].image_id))
                if image.image_id not in plain]

    def rotation_facts(self) -> dict[str, Any] | None:
        """Ce a facut rotatia in rularea asta; `None` = nu s-a aplicat deloc."""
        if self.rotation is None:
            return None
        promoted = []
        for image in self.promoted():
            seen = self._seen(image)
            promoted.append({"reference": image.reference,
                             "last_seen": seen["last_seen"] if seen else None})
        return {"overdue": list(self.rotation.overdue), "promoted": promoted}

    def coverage(self, total_images: int) -> dict[str, Any]:
        """Ce a acoperit rularea, in forma care ajunge in `facts` si pe rand."""
        admitted = self.admitted()
        skipped = sorted(self.skipped,
                         key=lambda sk: (-(sk.findings or 0), sk.reference, sk.image_id))
        return {"images": total_images,
                "ingested": [image.reference for image, _items in admitted],
                "admitted_findings": self.total(),
                "budget": self.budget,
                "rotation": self.rotation_facts(),
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


def _seen_clause(sk: dict[str, Any]) -> str:
    """De cand datează ce stie baza despre imaginea sarita. Gol daca nu s-a citit.

    „Ultima constatare văzută", nu „ultima ingerare": data vine din
    `findings.last_seen`, care nu se misca la o ingerare fara nicio constatare.
    Lipsa cheii inseamna ca rotatia nu a avut datele, si atunci nu se spune nimic
    — „nu stim" nu se scrie ca „niciodata".
    """
    if "last_seen" not in sk:
        return ""
    if sk["last_seen"] is None:
        return "nicio constatare văzută până acum"
    return f"ultima constatare văzută: {sk['last_seen']}"


def _describe_skipped(sk: dict[str, Any]) -> str:
    ref = _cut(sk["reference"], MAX_REFERENCE_CHARS)
    seen = _seen_clause(sk)
    if sk["findings"] is None:
        detail = "numărul de constatări nu se știe: raportul nu s-a citit"
        return f"{ref} ({detail}{'; ' + seen if seen else ''})"
    parts = []
    if sk["critical"]:
        parts.append(f"{sk['critical']} CRITICAL")
    if sk["high"]:
        parts.append(f"{sk['high']} HIGH")
    if sk["unrated"]:
        parts.append(f"{sk['unrated']} fără notă")
    if seen:
        parts.append(seen)
    if sk.get("displaced"):
        parts.append("înlăturată de imaginea cu prioritate de rotație")
    detail = f": {', '.join(parts)}" if parts else ""
    return f"{ref} ({sk['findings']} constatări{detail})"


def _rotation_text(coverage: dict[str, Any], skipped: list[dict[str, Any]], *,
                   ingested_names: bool) -> str:
    """Propozitiile despre rotatie: ce s-a intamplat acum si ce regula se aplica.

    Doar fapte pe care rularea le poate sustine. „A fost ingerata cu prioritate" se
    scrie doar daca lista celor ingerate o contine (si nu pe calea in care ingestia
    a cazut la mijloc, unde nu stim ce a ajuns). Regula pentru rularile urmatoare e
    spusa ca regula, nu ca rezultat.
    """
    if "rotation" not in coverage:
        return ""   # acoperire fara date de rotatie (nu o produce `Admission`)
    rotation = coverage["rotation"]
    if rotation is None:
        return (" Rotația NU a fost aplicată în rularea asta (nu s-a citit când a "
                "fost văzută ultima oară fiecare imagine): imaginile sărite nu "
                "primesc prioritate data viitoare.")
    text = ""
    ingested = coverage.get("ingested") or []
    promoted = [p for p in (rotation.get("promoted") or [])
                if ingested_names and p["reference"] in ingested]
    if promoted:
        def _one(p: dict[str, Any]) -> str:
            since = (f"ultima constatare văzută: {p['last_seen']}" if p["last_seen"]
                     else "nicio constatare văzută până acum")
            return f"{_cut(p['reference'], MAX_REFERENCE_CHARS)} ({since})"
        described = [_one(p) for p in promoted]
        k = _fit(described, MAX_NAMED_PROMOTED, MAX_NAMED_PROMOTED_CHARS)
        more = len(promoted) - k
        names = ", ".join(described[:k]) + (f" și încă {more}" if more else "")
        verb = "a fost ingerată" if len(promoted) == 1 else "au fost ingerate"
        text += (f" Rotație: {names} {verb} cu prioritate de rotație, "
                 f"deși după regula «cele mai mici întâi» nu "
                 f"ar fi încăput.")
    if any(sk["reason"] == REASON_BUDGET for sk in skipped):
        text += (" Regula de rotație: la rulările următoare imaginile sărite pentru "
                 "buget sunt trecute cu vederea, iar cele nevăzute de cel mai mult "
                 "timp se ingerează primele, cât încap.")
    return text


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
            # „Celelalte", nu „cele mai mici": intr-o noapte cu imagine-lider unele
            # au fost inlaturate de lider (marcate pe nume), nu de imagini mai mici.
            REASON_BUDGET: ("încape singură, dar nu și laolaltă cu celelalte "
                            if one else
                            "încap singure, dar nu și laolaltă cu celelalte ")
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
    text += _rotation_text(coverage, skipped, ingested_names=ingested_names)
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


async def scan(probe: DockerProbe | None = None,
               last_seen: Mapping[str, datetime] | None = None
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

    `last_seen` = `max(findings.last_seen)` per `location`, citit de apelant din
    baza INAINTE de scanare (`fx.last_seen_by_location`); de el atarna rotatia.
    `None` = nu s-a putut citi: nu se aplica rotatie si coverage o spune
    (`rotation: None`), in loc sa para ca nimeni nu a fost trecut cu vederea. Un
    dictionar gol e altceva: baza a raspuns ca nu stie nimic despre scaner.
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

    rotation = (plan_rotation([i.reference for i in images], last_seen)
                if last_seen is not None else None)

    images = scan_order(images, rotation)

    workdir = tempfile.mkdtemp(prefix="sentinel-trivy-image-")
    admission = Admission(MAX_FINDINGS, rotation)
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
                    "rotation": coverage["rotation"],
                    "containers": facts["containers"], "db_version": described,
                    "severities": facts["severities"]})
    return list(unique.values()), None, facts
