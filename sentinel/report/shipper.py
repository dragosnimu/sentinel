"""Expedierea rândurilor către agregatorul extern.

Fratele mai mare al lui `beacon.py`, și deliberat NU același serviciu. Beaconul
trimite câteva contoare care trebuie să crească; expeditorul trimite conținut.
Purtarea beaconului — nu reîncearcă, nu blochează, nu scrie pe disc — e o
proprietate de securitate, iar unitatea lui are `ReadOnlyPaths=/etc/sentinel` și
`MemoryMax=128M`. **Un bug în expeditor nu are voie să fie o pană de heartbeat**,
deci expeditorul e alt proces, cu altă unitate și altă cheie
(`SENTINEL_SHIP_SECRET`, nu `SENTINEL_BEACON_SECRET`: o cheie comună înseamnă că
root pe A poate fabrica date pentru B).

## Regula pe care stă totul: cursorul avansează pe ECOU, nu pe 200

Un `200 OK` nu e dovada că datele au ajuns unde credem. Arată identic pentru:

* un edge CDN care servește un răspuns pus în cache;
* un vhost greșit rutat, care întoarce vesel pagina altcuiva;
* un agregator care a primit lotul și a ignorat tăcut un flux pe care nu-l
  cunoaște (`rows.detections` trimis către o versiune care știe doar `audit_log`).

În toate trei, un expeditor care avansează cursorul pe codul de stare pierde
rândurile **definitiv și în tăcere**: cursorul nu se mai întoarce niciodată, iar
pe agregator lipsa nu se vede, fiindcă nimeni nu știe ce trebuia să fie acolo.

Deci: cursorul unui flux avansează **numai** dacă răspunsul e JSON, spune
`ok: true`, și conține `accepted.<flux>` egal **exact** cu filigranul trimis
pentru fluxul ăla — același întreg, nu unul mai mare, nu un șir care seamănă cu
el. Orice altceva înseamnă „nu știu ce s-a întâmplat", iar tratamentul pentru
„nu știu" e retrimiterea: ingestia de la celălalt capăt e idempotentă
(`UNIQUE (instance_id, source_id)` + upsert), deci un lot retrimis e o operație
nulă, în timp ce un lot pierdut e pierdut.

## Coada e baza de date locală

Nu există coadă pe disc. **Cursorul care n-a avansat E coada** — două
reprezentări ale lui „încă netrimis" pot să nu fie de acord, iar dezacordul e
exact eșecul pentru care există `0010_ingest_cursors.sql`. Cursorul stă acolo,
sub numele `ship:<flux>`, cu valoarea ultimului `id` expediat.

Ordonarea pe `id` e corectă aici doar fiindcă `audit_log` are un singur scriitor,
iar acela serializează: `sentinel/db/repo/audit.py:record` ia
`SELECT … ORDER BY id DESC LIMIT 1 FOR UPDATE` înainte de INSERT, deci al doilea
scriitor așteaptă commit-ul primului și `id`-urile devin vizibile în ordinea în
care au fost atribuite. Fără lacătul ăla, o tranzacție care a luat `id`-ul 100 și
comite după ce am expediat 101 ar fi sărită pentru totdeauna — clasicul defect al
cursoarelor pe `id`. E o dependență reală între două module, deci e păzită de un
test (`test_the_id_cursor_is_safe_only_because_the_writer_serialises`).

## Al doilea fel de cursor, și ce costă

Un cursor pe `id` nu vede o entitate care se SCHIMBĂ: un incident închis, un
scor de actor recalculat, un finding rezolvat — niciunul nu-și schimbă `id`-ul,
deci niciunul nu trece vreodată de `WHERE id > cursor`. Fluxurile mutabile merg
de aceea pe `(updated_at, id)`, iar `updated_at` e ținut de un trigger
(`sentinel/db/migrations/0023_ship_watermarks.sql`), nu de fiecare modul din
`sentinel/db/repo/` care mută un rând: un trigger nu se uită.

Fiecare flux își declară felul în `Stream.cursor_kind`. Nu e o etichetă: din el
ies interogarea, forma filigranului și dacă ceasul contează sau nu.

**Prețul e că un cursor pe timp se încrede în ceasul serverului, iar `id`-ul nu.**
Două feluri de a pierde, amândouă tăcute dacă nu sunt căutate:

* **saltul înapoi** (NTP care pășește, o mașină virtuală restaurată dintr-un
  instantaneu, un `date` dat cu mâna) lasă filigranul ÎNAINTEA lui `now()`.
  Rândurile atinse de acum încolo primesc un `updated_at` mai mic decât el și nu
  mai sunt selectate niciodată. Nimic nu se plânge: cursorul e valid,
  interogarea e corectă, întoarce zero rânduri, iar expeditorul ar raporta
  „nimic de expediat" — adică succes;
* **saltul înainte** urcă filigranul în viitor. Cât ceasul rămâne acolo nu se
  pierde nimic. Se pierde când e corectat — fiindcă o corecție e chiar un salt
  înapoi, iar tot ce se atinge până când timpul real ajunge din urmă filigranul
  nu pleacă niciodată.

Ambele se citesc din ACELAȘI fapt observabil: **filigranul e înaintea ceasului
bazei**. E singura formă în care întrebarea are un răspuns, fiindcă un salt care
a fost și s-a dus nu lasă altă urmă. De aici, regula fără care tot mecanismul ar
minți:

> „n-am expediat nimic fiindcă nu s-a schimbat nimic" și „n-am expediat nimic
> fiindcă ceasul a sărit" NU au voie să arate la fel.

Ce face codul când găsește derapaj: **fluxul se oprește vizibil, nu se
expediază**. Nu fiindcă expedierea ar strica ceva — interogarea întoarce oricum
zero rânduri, deci „refuză" și „trimite" nu se deosebesc prin ce pleacă —, ci
fiindcă singura diferență e CE SE RAPORTEAZĂ, iar acolo e toată miza. Runda
iese cu `ok=False` și cu motivul numind ceasul, `check_ship_lag` scoate fluxul
din „la zi" și îl arată operatorului cu `timedatectl` în `action`.

Ce NU face, și e o decizie de operator, nu una de cod: **nu dă cursorul înapoi.**
O retragere la `now()` ar salva rândurile din fereastră (retrimiterea e gratuită,
ingestia e upsert), dar pe un ceas care oscilează ar retrage cursorul la fiecare
rundă și ar retrimite aceeași fereastră la nesfârșit — bucla invizibilă pe care
criteriul de acceptanță al lui E3 cere s-o măsurăm, nu s-o presupunem stinsă.
Alegerea între pierdere mărginită și cost nemărginit nu se ia dintr-un modul.

## Ce mai poate sări un cursor pe timp, în afară de ceas

`now()` e ora de ÎNCEPUT a tranzacției, iar ordinea commit-urilor nu e ordinea
începuturilor. O tranzacție începută la 10:00:00 și comisă la 10:00:05 face
rândul vizibil DUPĂ una începută la 10:00:02 și comisă la 10:00:03 — iar dacă
expeditorul a trecut între timp de 10:00:02, primul rând nu mai e selectat
niciodată. E exact defectul pe care capul secțiunii de mai sus îl descrie pentru
cursoarele pe `id` și pe care acolo îl închide lacătul din `audit.record`; aici
nu există lacăt, fiindcă sunt șapte tabele cu scriitori independenți.

Ce face codul, în doi pași care nu se pot înlocui unul pe altul:

* **mărginește** — nu expediază rândurile mai noi de `COMMIT_SAFETY_LAG_S`;
* **măsoară** — la runda următoare RE-numără fereastra pe care tocmai a citit-o.
  Fereastra e închisă (orice atingere nouă pune `updated_at = now()`, care e
  deasupra cursorului), deci orice rând găsit acolo în plus a fost comis cu
  întârziere, e sub filigran, și nu va pleca niciodată. Se raportează, cu numărul
  lor, și se ține minte în `ship:<flux>:lost` — vezi
  `_count_rows_that_appeared_below`.

Al doilea pas există fiindcă primul se sprijină pe o presupunere despre durata
tranzacțiilor, iar o presupunere care se strică fără să spună nimic e chiar
tiparul din CLAUDE.md. Fereastra face pierderea improbabilă; măsurătoarea o face
imposibil de tăcut.

## Ce nu se presupune deloc: că `updated_at` chiar se mișcă

Toată mecanica de mai sus se sprijină pe un trigger dintr-un fișier de migrație.
Un fișier pe disc nu e dovadă că nucleul l-a acceptat, iar `schema_version` spune
doar că instrucțiunile au rulat fără eroare pe versiunea de-atunci a fișierului.

Fără trigger, `updated_at` rămâne valoarea de la INSERT: rândul se schimbă,
momentul lui nu, cursorul trece o dată peste el și gata. De pe gazdă, asta arată
perfect sănătos — zero rânduri, ceas bun, restanță zero, unitate `active`.

Deci fiecare rundă a fiecărui flux mutabil întreabă `pg_trigger`
(`updated_at_trigger_installed`), iar lipsa OPREȘTE fluxul în loc să-l lase să
pară la zi. Aceeași întrebare se pune și în `check_ship_lag`, fiindcă expeditorul
nu are cale proprie către operator.

## Ce se întâmplă cu rândurile mai vechi decât `max_backfill_days`

Întrebarea are două răspunsuri greșite: să le sărim tăcut (o minciună — rândurile
nu ajung niciodată și nimic nu spune asta) și să încercăm la nesfârșit tot
istoricul (o cerere care expiră, se reia, și nu progresează niciodată).

Ce face codul ăsta, și distincția e toată:

* **Prima rundă a unui flux, când NU există cursor**, își pune un prag: ultimul
  `id` mai vechi decât `max_backfill_days`. Rândurile de sub prag nu vor pleca
  niciodată. Asta se scrie în jurnal atunci, cu numărul lor, ȘI se păstrează
  permanent, ca al doilea cursor `ship:<flux>:floor` — de unde `check_ship_lag`
  îl poate spune operatorului la fiecare rulare, luni mai târziu. Un fapt care
  trăiește doar într-o linie de jurnal e un fapt pierdut.
* **Odată ce cursorul există, nu se mai sare peste nimic, oricât ar rămâne în
  urmă.** O pană de o lună a agregatorului se recuperează integral, `max_rows_per_batch`
  rânduri per cerere, câte o rundă. Mărginirea cererii e `LIMIT`-ul, nu vechimea:
  o lună de restanță nu e o cerere mare, e multe cereri mici. Aici a sări peste
  ar fi chiar pierderea tăcută de date de mai sus, doar că declanșată de o pană.

## Un flux oprit nu are voie să încetinească fluxul sănătos

`collect_stream` izolează CE se strânge — un `incidents` poticnit nu mai oprește
`audit_log`. Dar cât timp runda întorcea un singur `ok` pentru toate fluxurile,
izolarea se pierdea imediat după: bucla număra eșecurile pe rundă, deci un
singur flux oprit urca pauza tuturor la 30s, 60s, 120s… până la `backoff_max_s`.

Măsurat pe 16 august 2026, cu `incidents` blocat pe un rând necodificabil și
`audit_log` cu 6000 de rânduri restanță: rundele ieșeau `ok=False` cu
`audit_shipped=2000`, iar pauza creștea la fiecare — 30s, 60s, 120s, …, 1920s.
În regim staționar asta înseamnă `audit_log` expediat o dată pe oră în loc de o
dată pe minut; la recuperarea unei restanțe, de `backoff_max_s / DRAIN_PAUSE_S`
ori mai încet. Iar apoi `check_ship_lag` arăta cheia roșie pe `audit_log`, cu un
remediu despre CDN și `HTTP 413` — în timp ce cauza era în `incidents`. Cauza
într-un flux, efectul în altul, exact tiparul pe care izolarea din
`collect_stream` fusese scrisă să-l scoată.

Deci **contorul de eșecuri consecutive e o proprietate a FLUXULUI, nu a buclei**.
Fiecare flux își are termenul lui (`ShipSchedule`): cel sănătos rămâne pe
`interval_s`, sau pe `DRAIN_PAUSE_S` cât mai are de drenat, cel oprit intră
singur în exponențială, iar bucla doarme până la cel mai apropiat termen și
strânge doar fluxurile al căror termen a venit.

Ce rămâne, dinadins, comun: **lotul**. Fluxurile scadente pleacă într-o singură
cerere semnată, fiindcă un lot per flux ar înmulți cererile și numerele de lot
fără să repare nimic din ce e mai sus. Deci un refuz al LOTULUI — rețea căzută,
non-2xx, 200 fără ecou — pică toate fluxurile care erau în el, și asta e corect:
cauza chiar e comună. Ce nu e comun sunt fluxurile care n-aveau nimic de trimis;
ele nu intră în exponențială fiindcă altul a fost refuzat.

## Ce NU poate face

Fluxul duce `id`, `prev_hash` și `entry_hash` neatinse, deci agregatorul poate
verifica **înlănțuirea** — că `prev_hash`-ul fiecărui rând e `entry_hash`-ul
celui dinainte —, ceea ce prinde inserarea, ștergerea și reordonarea. Asta e
proprietatea pe care `docs/PLAN-arhitectura-distribuita.md` §5 o declară azi
imposibilă.

Recalcularea lui `entry_hash` din CONȚINUT e altceva și nu e livrată de faza
asta: hash-ul se calculează peste un `json.dumps(..., sort_keys=True)` din
Python (`sentinel/db/repo/audit.py:_entry_hash`), cu `ensure_ascii=True` implicit
— adică exact perechea de serializatoare de uz general despre care
`sentinel/report/signing.py` argumentează pe o pagină că nu poate fi făcută să
coincidă între limbaje. Cine scrie E2.4 trebuie să știe asta ÎNAINTE, nu s-o
descopere ca pe un lanț „rupt" peste rânduri intacte.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID
from time import monotonic
from typing import Any

from sentinel.config import Config, get_secrets
from sentinel.db.engine import Database
from sentinel.identity import IdentityError, read_instance_id
from sentinel.logging_setup import get_logger
from sentinel.report.envelope import EnvelopeError, wrap
from sentinel.report.signing import CanonicalError, canonical, sign

log = get_logger(__name__)

SECRET_NAME = "SENTINEL_SHIP_SECRET"

# Aceleași antete ca la beacon, fiindcă e același receptor și aceeași verificare
# în trei pași. Scrise aici ca literali, nu importate din `beacon`, ca expeditorul
# de loturi să nu depindă de heartbeat — iar faptul că cele două perechi rămân
# egale, și egale cu numele din `aggregator/lib/`, e păzit de un test.
SIGNATURE_HEADER = "X-Sentinel-Signature"
INSTANCE_HEADER = "X-Sentinel-Instance"

BATCH_SEQ_KEY = "ship:seq"

# Cât din exponențială se taie ca jitter, și DOAR în jos.
#
# În sus, un jitter peste plafon face ca plafonul să nu mai fie plafon — iar
# plafonul e singura proprietate a backoff-ului care se poate afirma simplu
# („nicio pauză nu trece de `backoff_max_s`") și verifica într-un test.
JITTER_RATIO = 0.25

# Cât se așteaptă între două runde CÂND lotul a ieșit plin, adică se știe că mai
# sunt rânduri. Nu e configurabil: e diferența dintre a recupera o restanță în
# minute și a o recupera în ore, și nu e o alegere de operator.
DRAIN_PAUSE_S = 1.0

# Aceleași praguri ca la beacon, fiindcă înseamnă același lucru: un eșec care s-a
# repetat de atâtea ori la rând nu mai e o clipire de rețea.
_PROBE_ALARM_AT = (3, 30, 300)

# Cât de proaspăt trebuie să fie un rând ca să NU fie expediat încă, pe un flux
# mutabil.
#
# `updated_at` e `now()`, adică ora de început a tranzacției, iar ordinea
# commit-urilor nu e ordinea începuturilor. Fără fereastra asta, un rând atins de
# o tranzacție lungă devine vizibil după ce cursorul a trecut de momentul lui și
# nu mai e selectat NICIODATĂ — aceeași pierdere permanentă și tăcută pe care
# lacătul din `audit.record` o închide pentru cursorul pe `id`. Aici nu există un
# lacăt echivalent: sunt șapte tabele cu scriitori independenți, iar serializarea
# lor ca să se poată expedia ar fi coada care mișcă cîinele.
#
# Proprietatea cerută de la valoare: **mai mare decât cea mai lungă tranzacție
# care scrie într-o tabelă expediată.** 30 de secunde e cu mult peste orice cale
# de scriere din codul de azi (fiecare e o instrucțiune sau un lot mic), dar
# „cred că e destul" nu e o măsurătoare: dacă vreodată o tranzacție trece de
# atât, rândurile ei se pierd fără ca nimic să raporteze. Ce ar confirma
# valoarea, și nu se poate face din afara gazdei: cea mai mare valoare a lui
# `now() - xact_start` din `pg_stat_activity` peste o zi de funcționare.
#
# Nu e configurabil, ca `DRAIN_PAUSE_S`: e o proprietate a bazei, nu o alegere de
# operator. Costul e că o schimbare se vede pe agregator cu până la atâtea
# secunde întârziere.
COMMIT_SAFETY_LAG_S = 30.0

# Cursoare: fiecare flux își declară felul, iar din el ies interogarea, forma
# filigranului și dacă ceasul contează. Vezi capul modulului.
APPEND_ONLY = "append-only"
MUTABLE = "mutable"
# Aceleași nume ca `CursorKind` din `aggregator/lib/streams.ts`. Nu circulă pe
# sârmă — receptorul își citește felul din registrul lui —, deci nu sunt un
# contract și nu au un test trans-limbaj; sunt scrise la fel ca să nu descrie
# doi oameni același lucru în două vocabulare.
#: Al treilea fel: agregatele.
#:
#: Un rollup n-are nici `id`, nici `updated_at` — cheia lui e
#: `(bucket, asset_id, source, action)`, iar rândurile unui interval împart
#: exact același moment. Deci niciunul dintre celelalte două cursoare nu i se
#: potrivește: unul pe `id` n-are pe ce merge, iar unul pe `(updated_at, cheie)`
#: n-are nici coloana de timp, nici o cheie unică pe o singură coloană.
#:
#: Cursorul e un MOMENT singur, iar selecția e `bucket > cursor` peste
#: intervalele ÎNCHEIATE. Alegerea asta ține două proprietăți deodată:
#:
#:   * un rând pleacă o singură dată, deci „nimic nu s-a schimbat" înseamnă în
#:     continuare „zero rânduri expediate" — proprietatea pe care E3 o cere ca
#:     dovadă că nu există o buclă de retrimitere;
#:   * intervalul în curs nu pleacă niciodată pe jumătate, deci panoul nu arată
#:     o oră incompletă ca și cum ar fi completă.
#:
#: Prețul, spus pe față: panoul rămâne în urmă cu până la o oră plus cadența
#: mentenanței. Pentru un contor ORAR e prețul potrivit. Iar dacă serverul ar
#: recalcula vreodată un interval DUPĂ ce a fost expediat, schimbarea aia n-ar
#: mai pleca — mentenanța raportează `remaining_hours: 0.0`, adică își încheie
#: intervalele înainte de a trece mai departe, și pe asta se sprijină.
ROLLUP = "rollup"

CURSOR_KINDS = (APPEND_ONLY, MUTABLE, ROLLUP)

#: Câte chei se pot trimite într-o listă de reconciliere.
#:
#: Plafon de siguranță, nu reglaj: peste el lista se OMITE, nu se taie. O listă
#: tăiată ar spune receptorului „astea sunt toate cheile care există", iar el ar
#: șterge restul — adică o trunchiere tăcută ar deveni o pierdere de date. Nu e
#: în configurație tocmai fiindcă nimeni n-ar trebui s-o ridice: un flux care
#: trece de plafon are nevoie de altă proiectare, nu de un număr mai mare.
MAX_PRUNE_KEYS = 5000

#: Ce FEL de valoare e filigranul. Din el iese tipul SQL al comparației pe cheie
#: (`Stream.key_sql_type`) și valoarea de la prima semănare (`Stream.key_floor`),
#: deci lista asta e singurul loc unde se adaugă un fel nou.
WATERMARK_KINDS = ("int", "text")

#: Unitatile de interval acceptate pentru un flux de agregate.
#:
#: Lista ALBA fiindca valoarea ajunge in `date_trunc(...)` si intr-un literal de
#: interval, adica in textul instructiunii. Un camp liber acolo ar fi o cale de
#: injectie deschisa de o declaratie de flux.
ROLLUP_UNITS = ("minute", "hour", "day")


def _cursor_key(stream: "Stream", raw: Any) -> int | str:
    """Jumătatea-cheie a unui cursor mutabil, citită ca TIPUL fluxului.

    Coloana `collector_cursors.cursor` e text pentru toate fluxurile, fiindcă
    trebuie să poarte și chei care nu sunt numere. Conversia înapoi la tipul
    real se face AICI, într-un singur loc, din `watermark_kind`.

    Până pe 21 august 2026 conversia era un `int()` necondiționat, scris când
    toate fluxurile mutabile aveau cheie `id`. Fluxul cu cheie text a fost
    adăugat mai târziu și a picat la fiecare rundă cu `text > bigint`, fără să
    repornească serviciul și fără să schimbe nimic vizibil în afară de o linie
    de jurnal.
    """
    return str(raw) if stream.watermark_kind == "text" else int(raw)


async def _rollup_cursor(db: Any, stream: "Stream") -> tuple[datetime, str]:
    """De unde continuă un flux de agregate: perechea `(updated_at, bucket)`.

    Zero e valoarea corectă la prima rundă, nu un prag ca la celelalte fluxuri:
    un contor orar are prin construcție puține rânduri pe zi, iar istoricul lui
    e chiar ce vrea panoul.

    Cursorul a fost pe `bucket` singur până pe 24 august 2026, și aia era o
    greșeală măsurabilă: mentenanța scrie intervalul pentru fereastra SCURSĂ și
    îl COMPLETEAZĂ la rularea următoare, deci ora 04:00 pleca cu valoarea
    parțială iar cursorul trecea dincolo de ea pentru totdeauna. Pe gazda reală
    asta însemna 60 de evenimente expediate în loc de 1385 — de douăzeci de ori
    mai puțin, pe rânduri care existau la ambele capete.

    Pe `updated_at`, un interval recalculat trece din nou de cursor. `bucket` e
    departajarea, ca la orice flux mutabil: fără ea, două rânduri scrise în
    aceeași tranzacție ar împărți momentul, iar unul s-ar pierde la marginea
    lotului.
    """
    row = await db.fetchrow(
        "SELECT cursor, cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if row is not None and row["cursor_at"] is not None:
        return row["cursor_at"], str(row["cursor"])

    start = await db.fetchval("SELECT to_timestamp(0)")
    await db.execute(
        """
        INSERT INTO collector_cursors (name, cursor, cursor_at, updated_at)
        VALUES ($1, $2::timestamptz::text, $2::timestamptz, now())
        ON CONFLICT (name) DO NOTHING
        """,
        stream.cursor_name, start)
    # Re-citit, nu presupus: dacă `ON CONFLICT DO NOTHING` a găsit rândul deja
    # scris, valoarea care contează e a lui.
    written = await db.fetchrow(
        "SELECT cursor, cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if written is None or written["cursor_at"] is None:
        raise ShipClockError(
            f"cursorul {stream.cursor_name} nu s-a putut scrie sau citi înapoi")
    return written["cursor_at"], str(written["cursor"])


async def _collect_rollup(db: Any, cfg: Any, stream: "Stream") -> "Batch | None":
    """Intervalele ÎNCHEIATE, strict mai noi decât cursorul.

    Marginea de sus — intervalul în curs, tăiat cu `date_trunc` pe unitatea
    declarată de flux — e jumătatea care contează: fără ea, ora în curs ar pleca
    pe jumătate, iar panoul ar arăta un contor incomplet ca și cum ar fi final —
    un raport care minte liniștit, nu o întârziere.

    Strict `>`, nu `>=`: un rând pleacă o singură dată. Cu `>=`, intervalul de la
    graniță s-ar retrimite la fiecare rundă, iar „nimic nu s-a schimbat" n-ar mai
    însemna „zero rânduri expediate" — adică s-ar pierde chiar dovada că nu
    există o buclă de retrimitere.
    """
    # ÎNAINTE de orice citire, ca la fluxurile mutabile: de la 0025, filigranul
    # fluxului merge pe `updated_at`, iar `updated_at` se mișcă doar fiindcă un
    # trigger o mișcă. Fără el, interogarea de mai jos întoarce zero rânduri —
    # ceea ce arată exact ca „nimic nu s-a schimbat", în timp ce fiecare interval
    # recalculat se pierde definitiv. Adică chiar defectul reparat de 0025, întors
    # tăcut, fiindcă fișierul de migrație exista pe disc.
    if not await updated_at_trigger_installed(db, stream):
        raise ShipTriggerError(
            f"{stream.table}.{stream.time_column} nu e întreținută de niciun "
            f"trigger BEFORE UPDATE activ care să cheme set_updated_at(), deci "
            f"un interval RECALCULAT nu-și mai mută momentul și nu mai pleacă "
            f"niciodată. Panoul ar arăta valorile parțiale ca finale. "
            f"Repară cu `sentinel migrate`")

    cursor_at, cursor_key = await _rollup_cursor(db, stream)
    limit = int(cfg.ship.max_rows_per_batch)
    records = await db.fetch(
        f"SELECT {', '.join(select_columns(stream))} FROM {stream.table} "  # noqa: S608 - identificatori din STREAMS
        # AMBELE elemente ale perechii ca `timestamptz`, fiindca amandoua
        # COLOANELE sunt momente. Prima versiune scria `$2::text`, ca la
        # fluxurile cu cheie text, iar Postgres a refuzat pe loc:
        # «operator does not exist: timestamp with time zone > text». Fluxul a
        # tacut trei runde inainte sa se vada, si s-a vazut doar fiindca `ship`
        # numara esecurile consecutive.
        #
        # Nu `bucket::text`, desi ar fi compilat: textul unui `timestamptz` se
        # randeaza cu fusul SESIUNII si fara secundele fractionare, deci ordinea
        # lui lexicografica ar depinde de o setare, iar cursorul salvat de o
        # sesiune s-ar compara gresit in alta.
        #
        # `$2::text::timestamptz`, nu `$2::timestamptz`, si asta e a DOUA
        # respingere a aceleiasi idei: cursorul e stocat ca TEXT in
        # `collector_cursors.cursor`, iar asyncpg deduce tipul parametrului din
        # cast si refuza un sir acolo unde a cerut `timestamptz` — «invalid
        # input for query argument $2 ... expected a datetime». Lantul spune
        # amandoua: parametrul soseste text, comparatia se face pe momente.
        f"WHERE ({stream.time_column}, {stream.key_column}) > "
        f"($1::timestamptz, $2::text::timestamptz) "
        f"AND {stream.key_column} < date_trunc('{stream.rollup_unit}', now()) "
        f"ORDER BY {stream.time_column}, {stream.key_column} LIMIT $3",
        # Un rând ÎN PLUS, ca să se poată vedea dacă ultimul grup e tăiat. Fără
        # el, „am umplut lotul" și „grupul continuă dincolo de margine" arată
        # identic, iar deosebirea e chiar între a amâna câteva rânduri și a le
        # pierde definitiv.
        cursor_at, cursor_key, limit + 1)
    if not records:
        # Lot GOL, nu `None`: apelantul citește `b.stall` de pe fiecare element,
        # iar un `None` strecurat în listă îl face să cadă cu `AttributeError` —
        # adică un flux liniștit ar opri toată runda, pentru toate fluxurile.
        return Batch(stream=stream, rows=[], watermark="", full=False,
                     position=(cursor_at, cursor_key),
                     from_position=(cursor_at, cursor_key))

    def _grup(r: Any) -> tuple[Any, str]:
        return (r[stream.time_column], str(r[stream.key_column]))

    full = len(records) > limit
    if full:
        # Perechea `(updated_at, bucket)` NU e unică: mentenanța scrie toate
        # sursele unei ore în aceeași tranzacție, deci `nginx`, `sshd` și
        # `auditd` împart și momentul, și intervalul. Tăiat la mijlocul unui
        # asemenea grup, cursorul ar trece dincolo iar sursele rămase n-ar mai
        # pleca NICIODATĂ — tăcut, fiindcă un cursor care a trecut nu se întoarce.
        taiat_la_mijloc = _grup(records[limit]) == _grup(records[limit - 1])
        records = records[:limit]
        if taiat_la_mijloc:
            ultima = _grup(records[-1])
            intreg = [r for r in records if _grup(r) != ultima]
            if intreg:
                records = intreg
            else:
                # TOT lotul e un singur grup tăiat. Retras, lotul ar fi gol,
                # cursorul n-ar avansa, iar runda următoare ar citi exact
                # aceleași rânduri: flux oprit pe loc, tăcut. Deci grupul pleacă
                # ÎNTREG, peste plafon. Plafonul mărginește un lot obișnuit; nu
                # are voie să fie motivul pentru care nu mai pleacă nimic.
                #
                # `max_rows_per_batch` are marjă largă peste o oră reală (șase
                # surse), deci ramura asta e o plasă, nu o cale bătută.
                records = await db.fetch(
                    f"SELECT {', '.join(select_columns(stream))} "  # noqa: S608
                    f"FROM {stream.table} "
                    f"WHERE {stream.time_column} = $1::timestamptz "
                    f"AND {stream.key_column} = $2::text::timestamptz "
                    f"ORDER BY {stream.time_column}, {stream.key_column}",
                    ultima[0], ultima[1])

    rows: list[dict[str, Any]] = []
    for record in records:
        # Cheia pentru mesajele de eroare e chiar INTERVALUL: un agregat n-are
        # `id`, iar „rândul 3" nu i-ar spune nimic operatorului care caută.
        # Fără copii: `max_children=0`, fiindcă un agregat n-are coloane-tablou.
        row, _carried = encode_row(stream, record,
                                   record[stream.key_column], 0)
        rows.append(row)
    last = records[len(rows) - 1]

    return Batch(
        stream=stream, rows=rows,
        from_position=(cursor_at, cursor_key),
        # Pe sârmă pleacă cel mai mare INTERVAL din lot, ca la orice flux mutabil
        # cu filigran text. Se ia din rândurile CODIFICATE, nu din cele brute:
        # receptorul vede șiruri ISO, iar un maxim calculat peste `datetime`-uri
        # ar produce un filigran de alt tip decât cel pe care îl ecouă el.
        watermark=wire_watermark(
            [r[stream.key_column] for r in rows], stream.watermark_kind),
        full=full,
        position=(last[stream.time_column], str(last[stream.key_column])))


async def _advance_rollup(db: Any, stream: "Stream",
                          position: tuple[datetime, str],
                          rows: int) -> tuple[datetime | None, str | None]:
    """Mută cursorul, monoton pe PERECHE, și întoarce ce are baza după mutare.

    `CASE`, nu `GREATEST` pe fiecare jumătate separat: monotonia e a perechii.
    Comparată doar pe moment, două rânduri scrise în aceeași tranzacție s-ar
    retrimite la nesfârșit; comparată doar pe interval, un agregat recalculat
    și-ar pierde locul — chiar defectul pentru care filigranul s-a mutat pe
    `updated_at`.
    """
    moved = ("(collector_cursors.cursor_at, collector_cursors.cursor::timestamptz) "
             "< ($2::timestamptz, $3::text::timestamptz)")
    row = await db.fetchrow(
        f"""
        INSERT INTO collector_cursors (name, cursor, cursor_at, events_seen, updated_at)
        VALUES ($1, $3::text, $2::timestamptz, $4::bigint, now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = CASE WHEN {moved} THEN $3::text
                              ELSE collector_cursors.cursor END,
                cursor_at = CASE WHEN {moved} THEN $2::timestamptz
                                 ELSE collector_cursors.cursor_at END,
                events_seen = collector_cursors.events_seen + $4::bigint,
                updated_at = now()
        RETURNING cursor_at, cursor
        """,  # noqa: S608 - `moved` e un literal de mai sus, nu date
        stream.cursor_name, position[0], position[1], rows)
    if row is None:
        return None, None
    return row["cursor_at"], str(row["cursor"])


async def _prune_keys(db: Any, streams: list["Stream"]) -> dict[str, list[str]]:
    """Mulțimea COMPLETĂ de chei, pentru fluxurile din care sursa șterge.

    Interogată separat de lot, nu dedusă din rândurile lui: un lot poate fi tăiat
    de `max_rows_per_batch`, iar cheile lui ar fi atunci o listă parțială
    prezentată ca fiind completă — exact felul în care o reconciliere devine o
    ștergere de date.

    Peste `MAX_PRUNE_KEYS` lista se OMITE cu totul și se spune de ce. Omisă,
    receptorul nu șterge nimic și un rând fantomă mai trăiește o rundă; tăiată,
    ar fi șters rânduri reale. Prima greșeală se repară singură, a doua nu.

    O eroare aici nu are voie să pice lotul: rândurile sunt treaba, reconcilierea
    e igienă. De-asta întoarce un dicționar gol, nu ridică.
    """
    out: dict[str, list[str]] = {}
    for stream in streams:
        if not stream.prunes_at_source:
            continue
        try:
            rows = await db.fetch(
                f"SELECT {stream.key_column} AS k FROM {stream.table} "  # noqa: S608 - identificatori din STREAMS
                f"ORDER BY {stream.key_column} LIMIT $1",
                MAX_PRUNE_KEYS + 1)
            keys = [str(r["k"]) for r in rows]
            if len(keys) > MAX_PRUNE_KEYS:
                log.warning(
                    "lista de reconciliere e prea lungă, deci nu pleacă",
                    extra={"stream": stream.name, "limit": MAX_PRUNE_KEYS,
                           "action": "Receptorul nu va șterge rândurile rămase în "
                                     "urmă la sursă. Fluxul are nevoie de altă "
                                     "proiectare, nu de un plafon mai mare."})
                continue
            out[stream.name] = keys
        except Exception as exc:  # noqa: BLE001 - igiena nu pică lotul
            log.warning("lista de reconciliere nu s-a putut citi",
                        extra={"stream": stream.name, "detail": str(exc)[:160]})
    return out


def _key_sql(stream: "Stream") -> tuple[str, str, str]:
    """Cele trei bucăți de SQL în care apare jumătatea-cheie a cursorului.

    `(cheia stocată, cheia primită ca text, cheia întoarsă)`. Coloana
    `collector_cursors.cursor` e TEXT pentru toate fluxurile, deci un flux cu
    cheie întreagă trebuie convertit la comparație — altfel `'10' < '9'` și
    cursorul ar merge înapoi. Un flux cu cheie text se compară direct, pe octeți.

    Sunt împreună într-o singură funcție fiindcă trebuie să se schimbe împreună.
    Pe 21 august 2026 patru locuri au fost reparate și astea au rămas cu
    `::bigint` scris de mână; expeditorul a pornit, a încercat să lege șirul `'0'`
    la un parametru `bigint`, a căzut la pornire și a intrat în buclă de
    repornire până când systemd a renunțat. Toate cele opt fluxuri s-au oprit,
    nu doar cel reparat.
    """
    if stream.key_sql_type == "text":
        return "collector_cursors.cursor", "$3::text", "cursor AS cursor_key"
    return ("(collector_cursors.cursor)::bigint", "($3::bigint)::text",
            "cursor::bigint AS cursor_key")


def wire_watermark(keys: list[Any], kind: str = "int") -> Any:
    """Filigranul care pleacă pe sârmă pentru un lot cu cheile astea.

    E cel mai mare `id` DIN LOT, și e altceva decât poziția cursorului. Pe un
    flux mutabil ordinea de expediere e `(updated_at, id)`, deci ultimul rând
    trimis — cel care dă poziția locală — nu e cel cu `id`-ul cel mai mare. Dacă
    s-ar trimite `id`-ul lui, receptorul ar refuza lotul: el cere, la fiecare lot,
    ca filigranul să fie maximul cheilor pe care tocmai le-a primit, fiindcă un
    filigran mai mare i-ar cere expeditorului să treacă peste rânduri care n-au
    fost trimise niciodată.

    Funcție separată, deși e o linie, ca să existe un capăt care se poate CHEMA:
    acordul cu receptorul e ținut de `tests/unit/test_aggregator_watermark_form.py`,
    care trece rezultatul de aici prin ingestia reală a agregatorului. Un acord
    despre care ambele părți doar afirmă ceva nu e un acord verificat.

    `kind="text"` întoarce maximul pe OCTEȚI, nu pe lungime și nu pe vreo
    ordine locală. Trei locuri trebuie să fie de acord — aici, `reduce` din
    `lib/ingest.ts`, și `GREATEST` pe o coloană cu colație binară. Dacă ar
    diverge, ecoul n-ar mai potrivi, iar cursorul n-ar mai avansa niciodată pe un
    lot perfect valid: simptomul e „agregatorul nu confirmă", cauza e o colație.

    Filigranele SUCCESIVE nu cresc, și nu trebuie să crească: un rând vechi atins
    acum vine într-un lot al cărui maxim e mai mic decât al lotului dinainte. Ce
    crește monoton e poziția locală, `(updated_at, id)`, și ea nu pleacă nicăieri.
    """
    if not keys:
        # Un lot gol n-are filigran. Zero ar fi o valoare care arată ca un
        # filigran și nu e — exact felul în care se cere ecoul pentru nimic.
        raise ValueError("lot fără chei: nu există filigran de trimis")
    return max(keys)

_identity_failures = 0
_canonical_failures = 0


# ---------------------------------------------------------------------------
# Fluxurile. Adăugarea unuia e DATE, nu chirurgie.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ChildSpec:
    """O coloană-TABLOU care pleacă drept SUB-RÂNDURI, nu ca valoare.

    Postgres are tablouri; MariaDB nu. Ce e `bigint[]` pe server devine o tabelă
    de legătură la receptor, iar pe sârmă un TABLOU DE OBIECTE atârnat de rândul
    părinte.

    De obiecte, nu de scalari, și nu e o preferință de stil: contractul
    receptorului (`ChildStream` din `aggregator/lib/streams.ts`) cere forma asta
    fiindcă unele tabele de legătură au două câmpuri per element — `actor_attrs`
    are `kind` și `value`. Două forme de element ar fi însemnat două căi de
    validare, adică încă un loc în care cele două capete pot să nu fie de acord.
    Deci și un tablou de întregi pleacă tot ca obiecte cu un singur câmp.

    `column` e coloana de pe server. NU e în `Stream.columns`: acolo stau doar
    scalarii, iar testul de paritate compară scalarii cu scalarii. Se adaugă
    separat la `SELECT`.
    """

    column: str
    field: str


@dataclass(frozen=True)
class Stream:
    """Un flux expediabil, și CUM îi înaintează cursorul.

    Pe un flux `append-only`, `time_column` e folosită o singură dată, la
    așezarea pragului de backfill; expedierea merge exclusiv pe `id`, fiindcă un
    ceas nu e monoton și o coloană de timp nu spune nimic despre ordinea
    commit-urilor. Ăsta e cazul lui `audit_log` și rămâne cel preferat oriunde se
    poate.

    Pe un flux `mutable`, `time_column` E cursorul, împreună cu `key_column`:
    perechea `(updated_at, id)`. Un rând schimbat nu-și mută `id`-ul, deci un
    cursor pe `id` nu-l vede niciodată. Prețul — dependența de ceas — e plătit în
    `collect_stream` și raportat de `check_ship_lag`; vezi capul modulului.

    Tipul lui `key_column` NU e liber: trebuie să se potrivească cu
    `watermark_kind`, fiindcă același cursor e și jumătatea de departajare din
    `WHERE (updated_at, key) > (…)`, și jetonul care pleacă pe sârmă. Din
    `watermark_kind` iese `key_sql_type`, iar comparația se scrie CU EL — nu cu
    un `::bigint` fixat în șablon.

    Până pe 21 august 2026 șablonul avea `::bigint` scris de mână în patru locuri,
    deși protocolul purta deja filigran text. `selfcheck_state` (`key`) a fost
    declarat, a pornit, și a răspuns la fiecare rundă cu
    `operator does not exist: text > bigint` — starea de sănătate a gazdei n-a
    ajuns niciodată în panou. Fluxul părea viu: serviciul era `active`, își
    enumera fluxul la pornire, și nu se repornea niciodată.
    """

    name: str
    table: str
    columns: tuple[str, ...]
    time_column: str
    cursor_kind: str = APPEND_ONLY
    key_column: str = "id"
    #: Coloanele-tablou, desfăcute în sub-rânduri. Vezi `ChildSpec`.
    children: tuple[ChildSpec, ...] = ()
    #: Ce FEL de valoare e filigranul de pe sârmă: `"int"` sau `"text"`.
    #:
    #: `"int"` implicit — cazul fiecărui flux cu `id`. `"text"` pentru cele a
    #: căror cheie nu e un număr: `selfcheck_state` (`key`), `actors`
    #: (`actor_key`), rollup-urile (cheie compusă).
    #:
    #: Filigranul nu e o poziție, e un JETON DE ECOU: expeditorul avansează
    #: cursorul doar dacă receptorul îi întoarce exact valoarea trimisă. Deci nu
    #: trebuie să fie un întreg — trebuie doar să fie calculabil identic la
    #: ambele capete din conținutul lotului. Pe text, ordinea e cea pe octeți,
    #: aceeași pe care o face `max()` peste șiruri în Python, `reduce` la
    #: receptor și `GREATEST` pe o coloană cu colație binară.
    watermark_kind: str = "int"

    #: Sursa ȘTERGE rânduri din tabelul ăsta, nu doar le adaugă și le schimbă.
    #:
    #: Ingestia agregatorului e numai upsert, deci o ștergere la sursă nu ajunge
    #: niciodată dincolo. Măsurat pe 21 august 2026: serverul avea 43 de
    #: verificări, agregatorul 44 — a 44-a era una ștearsă cu zile în urmă, care
    #: rămăsese în panou în stare `unknown`. Un panou care arată o problemă
    #: rezolvată ca fiind încă deschisă e chiar clasa de defecte după care e
    #: numit depozitul.
    #:
    #: Pentru fluxurile cu steagul ăsta, lotul poartă și MULȚIMEA COMPLETĂ de
    #: chei de la sursă, iar receptorul șterge ce nu e în ea. E aceeași formă cu
    #: ștergerea de la sursă (`DELETE … WHERE NOT (key = ANY($1))`), dinadins:
    #: două mecanisme cu aceeași formă nu pot fi de acord pe jumătate.
    #:
    #: Se pune DOAR unde sursa chiar șterge. Verificat, nu presupus: singurul
    #: `DELETE` peste un tabel expediat e cel din `selfcheck/runner.py`.
    prunes_at_source: bool = False

    #: Cat de lat e un interval de agregat: `hour`, `minute`, `day`.
    #:
    #: Din el ies DOUA lucruri care trebuie sa fie de acord, si de-asta e un
    #: singur camp: ce se considera interval INCHEIAT
    #: (`date_trunc(unitate, now())`) si de cand se numara vechimea unui rand
    #: neexpediat (`bucket + 1 unitate`).
    #:
    #: A doua jumatate e cea care a costat. Eticheta unui interval e INCEPUTUL
    #: lui, deci `now() - bucket` e cel putin o unitate intreaga in clipa in care
    #: randul devine expediabil. Masurata asa, restanta unui contor orar pornea
    #: de la 60 de minute contra unui ragaz de 15 — deci fluxul nu putea fi
    #: niciodata `ok` cat avea ceva in asteptare, si trimitea o alerta „a ramas
    #: in urma" la fiecare ora. Alarma nu era despre server; era despre aritmetica.
    rollup_unit: str = "hour"

    def __post_init__(self) -> None:
        # La declarare, nu la prima rundă: un flux scris greșit trebuie să pice
        # la import, pe mașina celui care îl adaugă, nu peste săptămâni ca un
        # flux care tace.
        if self.cursor_kind not in CURSOR_KINDS:
            raise ValueError(
                f"fluxul {self.name}: cursor_kind={self.cursor_kind!r} nu e unul "
                f"dintre {CURSOR_KINDS}")
        if self.watermark_kind not in WATERMARK_KINDS:
            # Din `watermark_kind` iese tipul SQL al comparației. O valoare
            # necunoscută ar cădea pe ramura implicită și ar compara o cheie text
            # cu un `bigint` — adică exact pana din 21 august 2026, dar tăcută.
            raise ValueError(
                f"fluxul {self.name}: watermark_kind={self.watermark_kind!r} nu e "
                f"unul dintre {WATERMARK_KINDS}")
        if self.cursor_kind == ROLLUP:
            if self.time_column not in self.columns:
                raise ValueError(
                    f"fluxul de agregat {self.name}: {self.time_column!r} lipsește "
                    f"din columns, deci filigranul nu se poate citi din rând")
            if self.rollup_unit not in ROLLUP_UNITS:
                raise ValueError(
                    f"fluxul de agregat {self.name}: rollup_unit="
                    f"{self.rollup_unit!r} nu e unul dintre {ROLLUP_UNITS}; "
                    f"valoarea ajunge in textul instructiunii")
            if self.watermark_kind != "text":
                # Filigranul e un moment scris ISO. Trimis ca număr, cele două
                # capete ar trebui să fie de acord asupra unei conversii de timp
                # — încă un loc în care pot să nu fie.
                raise ValueError(
                    f"fluxul de agregat {self.name}: filigranul e un moment, deci "
                    f"watermark_kind trebuie să fie 'text', nu {self.watermark_kind!r}")
        if self.cursor_kind == MUTABLE:
            if self.time_column not in self.columns:
                # Coloana de timp E filigranul aici, deci trebuie să sosească în
                # rândul citit. Absentă, `collect_stream` ar cădea cu KeyError la
                # fiecare rundă, adică fluxul ar tăcea din prima zi.
                raise ValueError(
                    f"fluxul mutabil {self.name}: {self.time_column!r} lipsește "
                    f"din columns, deci filigranul nu se poate citi din rând")
            if self.key_column not in self.columns:
                raise ValueError(
                    f"fluxul mutabil {self.name}: {self.key_column!r} lipsește "
                    f"din columns, deci departajarea filigranului nu se poate citi")

    @property
    def key_sql_type(self) -> str:
        """Tipul cu care se leagă jumătatea-cheie a cursorului în SQL.

        Derivat din `watermark_kind`, nu declarat separat: un al doilea câmp ar
        putea fi pus în dezacord cu primul, iar dezacordul s-ar vedea ca un flux
        care tace — nu ca o eroare la declarare.
        """
        return "text" if self.watermark_kind == "text" else "bigint"

    @property
    def key_floor(self) -> str:
        """Ce se scrie în cursor la prima semănare. Text, fiindcă și coloana e.

        Pe un flux text, șirul GOL: e mai mic decât orice cheie tipăribilă, deci
        pragul nu taie nimic. Pe unul întreg, `'0'`. Semănat `'0'` pe un flux
        text, pragul ar exclude tăcut orice cheie care sortează sub caracterul
        `0` — iar simptomul ar fi „lipsesc niște rânduri din panou", descoperit
        târziu și pus pe seama expedierii.
        """
        return "" if self.watermark_kind == "text" else "0"

    @property
    def cursor_name(self) -> str:
        return f"ship:{self.name}"

    @property
    def floor_name(self) -> str:
        return f"ship:{self.name}:floor"

    @property
    def window_name(self) -> str:
        """Unde a fost cursorul înainte de ultima mutare, și câte rânduri s-au
        văzut atunci. Din perechea asta se poate întreba, o rundă mai târziu,
        dacă au apărut rânduri DEDESUBT — vezi `_count_rows_that_appeared_below`."""
        return f"ship:{self.name}:window"

    @property
    def lost_name(self) -> str:
        """Câte rânduri au apărut sub cursor de la instalare încoace, cumulat.

        Persistat din același motiv ca pragul de backfill: e o pierdere
        definitivă, iar un fapt care trăiește doar într-o linie de jurnal e un
        fapt pierdut pentru operatorul care se uită peste trei luni."""
        return f"ship:{self.name}:lost"


# Primul flux, și cel care nu se poate face altfel (E2.2). `audit_log` e
# append-only — deci fără mecanica `updated_at` pe care o cer entitățile
# mutabile —, e mic, și duce `prev_hash`/`entry_hash`, adică singura verificare
# care nu se poate face azi nicăieri în afara gazdei.
AUDIT_STREAM = Stream(
    name="audit_log",
    table="audit_log",
    # Toate coloanele tabelei. `params` inclus fiindcă intră în hash: un
    # agregator care primește rândul fără el nu poate spune nimic despre
    # conținut, doar despre înlănțuire.
    columns=("id", "at", "actor", "source", "operation", "target", "params",
             "result", "detail", "prev_hash", "entry_hash"),
    time_column="at",
)

# Primul flux MUTABIL, la amândouă capetele. Geamănul lui e `INCIDENTS` din
# `aggregator/lib/streams.ts`, iar acordul dintre cele două liste nu e o
# convenție: o coloană declarată la un singur capăt oprește fluxul la primul lot
# (câmp necunoscut, sau câmp lipsă — vezi `prepareRows`), iar de pe gazdă asta se
# vede doar ca „expedierea a rămas în urmă", fiindcă `ship_once` nu citește
# niciodată corpul unui răspuns non-2xx. De-aia egalitatea e ținută de un test
# care cheamă AMBELE surse, `tests/unit/test_aggregator_stream_columns.py`.
#
# Coloanele sunt TOATE cele ale tabelei `incidents` de pe server — 0001_core plus
# `auto_action`/`auto_action_at` din 0011 plus `updated_at` din 0023 — fiindcă
# replica nu poate arăta un incident despre care nu i s-a spus. Două merită
# numite:
#
#   * `updated_at` e coloana de ordonare a fluxului și trebuie să sosească în
#     rând: `_collect_mutable` își citește din ea poziția locală, iar
#     `Stream.__post_init__` refuză declarația fără ea. La receptor e
#     `0006_incident_updated_at.sql`;
#   * `ai_confidence` e `numeric(3,2)`, deci sosește din asyncpg ca `Decimal` și
#     pleacă drept ȘIR (`encode_value`). Receptorul îl verifică cu felul de
#     coloană `decimal`, nu `text` — vezi comentariul de la `Decimal` în
#     `encode_value` pentru de ce conversia asta e singura permisă.
#
# Ce pleacă din recunoașterea infrastructurii, și afirmația e despre CONȚINUT,
# nu despre schemă. Schema chiar n-are coloane de recunoaștere — alea sunt în
# `assets`, iar cele șapte refuzate sunt numite în
# `aggregator/migrations/0003_entities.sql`. Dar `summary`, `title` și
# `ai_verdict` sunt text liber scris de detectoare, iar detectoarele interpolează
# în el ce au găsit pe gazdă: `sentinel/detect/accounts.py` pune `/etc/passwd`,
# numele contului, uid-ul, shell-ul și home-ul, iar `sentinel/detect/intrusion.py`
# pune căile fișierelor scrise sub webroot. Măsurat pe gazdă în august 2026: 9
# din 1476 de rezumate conțineau o cale de sistem, plus 8 în `ai_verdict`.
#
# Deci fluxul ăsta poartă recunoaștere, puțină și legitimă — un incident fără ce
# anume s-a atins nu e triabil din afara gazdei —, și e numit ca atare în
# `aggregator/README.md`, „Ce poartă recunoaștere și pleacă totuși de pe gazdă".
# Comentariul de dinainte spunea „nimic": era adevărat despre coloane și fals
# despre ce e în ele, adică exact felul de afirmație care ține o decizie de
# operator în afara listei pe care operatorul o citește.
INCIDENT_STREAM = Stream(
    name="incidents",
    table="incidents",
    columns=("id", "fingerprint", "status", "severity", "ai_severity",
             "ai_verdict", "ai_confidence", "ai_analyzed_at", "title", "summary",
             "actor_key", "asset_id", "detection_count", "created_at",
             "first_detection_at", "last_detection_at", "acknowledged_by",
             "acknowledged_at", "resolved_at", "resolution_note", "notified_at",
             "auto_action", "auto_action_at", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    # Explicit, deși e implicitul: pe un flux mutabil cheia e a doua jumătate a
    # filigranului ȘI valoarea care pleacă pe sârmă, deci merită citită din
    # declarație, nu dedusă din faptul că nimeni n-a scris nimic.
    key_column="id",
)

# Cronologia incidentelor. Append-only la sursă: nimic din `sentinel/` nu face
# UPDATE pe `incident_timeline`, rândurile se adaugă și atât, deci cursorul merge
# pe `id` și nu depinde de niciun ceas.
#
# `incident_id` pleacă drept `incident_source_id` la receptor, și NU e o cheie
# străină acolo — nu există chei străine pe agregator, dinadins: cursoarele
# avansează independent pe flux, iar o intrare de cronologie poate ajunge
# legitim înaintea incidentului ei. Referința rămâne suspendată până sosește
# celălalt flux, iar `aggregator/lib/data/incidents.ts` citește cronologia
# filtrând pe `(instance_id, incident_source_id)`, nu urmând o legătură.
#
# `detail` e `jsonb NOT NULL` și poartă text liber scris de detectoare, deci
# aceeași notă de recunoaștere ca la `INCIDENT_STREAM`: puțină, legitimă, și
# numită în `aggregator/README.md`.
TIMELINE_STREAM = Stream(
    name="incident_timeline",
    table="incident_timeline",
    columns=("id", "incident_id", "at", "kind", "actor", "detail"),
    time_column="at",
)

# Detecțiile. Append-only la sursă, cursor pe `id`.
#
# `event_ids` NU e în listă, iar absența e o decizie, nu o scăpare: e un
# `bigint[]`, iar expeditorul nu trimite tablouri. Tabela `detection_events` de
# la receptor — motorul expedierii de dovezi — rămâne goală până când protocolul
# capătă sub-rânduri. O detecție ajunge deci cu tot ce cere triajul, dar fără
# rândurile brute la care trimite.
#
# `src_ip` e `inet` și `suppressed` e boolean; amândouă au avut nevoie de câte o
# extindere azi — o ramură în `encode_value` pentru adrese, respectiv un fel de
# coloană `bool` la receptor. Vezi comentariile de acolo.
#
# Recunoaștere: `evidence` e text liber scris de detectoare, deci aceeași notă ca
# la `INCIDENT_STREAM` — puțină, legitimă, numită în `aggregator/README.md`.
DETECTION_STREAM = Stream(
    name="detections",
    table="detections",
    columns=("id", "ts", "rule_id", "rule_family", "severity", "score",
             "actor_key", "asset_id", "incident_id", "src_ip", "dst_port",
             "evidence", "suppressed", "suppress_reason"),
    time_column="ts",
    # DOVEZILE. `event_ids` e `bigint[]`, iar de aici pleacă drept sub-rânduri
    # in `detection_events` la receptor — tabela care ESTE motorul expedierii de
    # dovezi (§E4 din plan).
    #
    # Nu e in `columns` dinadins: acolo stau scalarii, iar testul de paritate
    # compara scalarii cu scalarii. `select_columns` o adauga la `SELECT`.
    #
    # Fiecare element pleaca drept OBIECT cu un singur camp, nu ca intreg gol.
    # Motivul e in `ChildSpec`: contractul receptorului cere o singura forma de
    # element, fiindca doua ar fi doua cai de validare.
    children=(ChildSpec(column="event_ids", field="event_id"),),
)

# Constatarile scanerelor. MUTABIL: o constatare isi schimba starea - acceptata,
# amanata, rezolvata - fara sa-si mute `id`-ul, deci un cursor pe `id` n-ar mai
# vedea-o niciodata dupa prima sosire.
#
# `kev_due_date` e `date`, nu `timestamptz`, si e prima coloana de felul asta din
# tot protocolul. `encode_value` are nevoie de ramura ei ADAUGATA DUPA cea de
# `datetime`, fiindca `datetime` e o subclasa a lui `date`: in ordinea inversa,
# fiecare moment ar pleca drept zi si ora s-ar pierde.
#
# `raw` si `ai_assessment` sunt `jsonb`, deci pleaca drept text, ca `params`.
# `raw` poarta iesirea bruta a scanerului - versiuni de pachete, cai de fisiere -
# adica recunoastere, aceeasi nota ca la `INCIDENT_STREAM`.
FINDING_STREAM = Stream(
    name="findings",
    table="findings",
    columns=("id", "finding_key", "asset_id", "scanner", "cve", "advisory_id",
             "title", "description", "severity", "cvss", "cvss_vector",
             "epss", "kev", "kev_due_date", "package", "installed_version",
             "fixed_version", "location", "ecosystem", "priority", "status",
             "first_seen", "last_seen", "resolved_at", "resolution",
             "deferred_until", "accepted_by", "accepted_reason",
             "requires_manual_intervention", "scan_id", "raw",
             "ai_assessment", "ai_assessed_at", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="id",
)

# Blocarile. Mutabil: o blocare se dezactiveaza, i se numara loviturile, i se
# schimba termenul - toate fara `id` nou.
#
# `ip` e `inet`, deci are nevoie de ramura pentru adrese din `encode_value`.
# `hit_count` e citit din contorul nftables si e singurul raspuns cinstit la
# intrebarea daca blocarea a oprit ceva: o blocare cu zero lovituri n-a oprit
# nimic.
#
# Cele trei coloane derivate ale receptorului - `net_start_bin`, `net_end_bin`,
# `cidr_text` - NU sunt aici: se calculeaza la ingestie din `ip` + `prefix_len`,
# fiindca MariaDB n-are tipul `cidr`.
BLOCKLIST_STREAM = Stream(
    name="blocklist",
    table="blocklist",
    columns=("id", "ip", "prefix_len", "reason", "rule_id", "incident_id",
             "actor_key", "blocked_at", "expires_at", "ttl_seconds",
             "hit_count", "last_hit_at", "created_by", "active",
             "unblocked_at", "unblocked_by", "unblock_reason", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="id",
)

# Planurile de patch. Mutabil: un plan trece prin draft, validat, aprobat,
# aplicat - cu acelasi `id`.
#
# `finding_ids` NU e in lista: e `bigint[]`, iar expeditorul nu trimite tablouri.
# Tabela de legatura `patch_plan_findings` de la receptor ramane goala pana cand
# protocolul capata sub-randuri, exact ca `detection_events`.
#
# `plan_id` e `uuid`; asyncpg il intoarce ca obiect, deci `encode_value` are
# nevoie de ramura lui. `plan` e planul intreg ca `jsonb` si pleaca drept text -
# la receptor e doar pentru afisare, iar coloana de acolo poarta comentariul care
# spune ca agregatorul nu executa niciodata nimic din el.
PATCH_PLAN_STREAM = Stream(
    name="patch_plans",
    table="patch_plans",
    columns=("id", "plan_id", "plan_hash", "plan", "asset_id", "status",
             "risk_level", "blast_radius", "requires_reboot", "reversible",
             "estimated_downtime_s", "estimated_backup_mb", "confidence",
             "validation_errors", "validation_attempts", "generated_by",
             "model", "prompt_version", "generation_ms", "created_at",
             "approved_by", "approved_at", "scheduled_for", "rejected_by",
             "rejected_reason", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="id",
)


# Autodiagnosticul. PRIMUL FLUX CU FILIGRAN TEXT, la ambele capete.
#
# Cheia e `key text`, deci pana pe 20 august 2026 fluxul asta nu se putea
# expedia deloc: filigranul de pe sarma trebuia sa fie un intreg pozitiv. Ce s-a
# schimbat nu e o exceptie pentru el, e felul filigranului declarat pe flux —
# vezi `watermark_kind`.
#
# `key` se redenumeste in `check_key` la receptor fiindca `KEY` e cuvant
# rezervat in MariaDB.
#
# Fluxul ASTA e cel care umple pagina Servicii a panoului. Fara el, pagina
# exista si spune ca fluxul n-a sosit niciodata — ceea ce era adevarat.
SELFCHECK_STREAM = Stream(
    name="selfcheck_state",
    table="selfcheck_state",
    columns=("key", "status", "title", "detail", "facts", "since", "last_seen",
             "last_alert_at", "stale", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="key",
    watermark_kind="text",
    # Singurul tabel expediat din care sursa chiar șterge: `_reconcile_state`
    # face `DELETE … WHERE NOT (key = ANY($1))` după fiecare rulare completă.
    prunes_at_source=True,
)


# Rularile de scanare. Fluxul asta e cel care spune panoului CAND a fost masurata
# ultima oara lista de vulnerabilitati, si daca masuratoarea a REUSIT.
#
# Fara el, pagina de vulnerabilitati arata o cifra fara varsta. Pe 21 august 2026
# asta a costat: 31 de constatari reparate la 09:14 au ramas afisate ca deschise,
# fiindca scanarea de la 10:33 — cea care le-ar fi inchis — a esuat cu `timeout`,
# iar esecul n-a ajuns nicaieri. Operatorul a vazut 31 in panou si nimic in
# `dnf update`, si n-avea de unde sa stie care dintre ele minte.
#
# MUTABIL, nu append-only: rândul se scrie ca `running` si se COMPLETEAZA la
# final. Un cursor pe `id` l-ar prinde o singura data, in starea de atunci — deci
# ar expedia „ruleaza" pentru totdeauna si n-ar arata niciodata cum s-a incheiat.
# Exact informatia care lipsea. Coloana de filigran vine din 0024.
#
# `raw_output_path` NU pleaca: e o cale de pe gazda, adica o harta gratuita a
# masinii, si n-are cititor dincolo.
SCAN_STREAM = Stream(
    name="scans",
    table="scans",
    columns=("id", "scanner", "target", "asset_id", "status", "started_at",
             "finished_at", "duration_ms", "exit_code", "findings_count",
             "new_findings", "resolved_findings", "db_version", "error",
             "triggered_by", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="id",
)


# Contorul orar. Fluxul ăsta umple pagina Rapoarte a panoului — până acum ea
# exista și spunea că fluxul n-a sosit niciodată, ceea ce era adevărat: datele se
# calculau pe server (`event_rollup_1h: 12 rânduri pe 0,9 h` la fiecare rulare de
# mentenanță) și nu plecau nicăieri.
#
# Nu se reagregă nimic la receptor. `uniq_src` e un MAXIM peste minute, nu o
# sumă — o subestimare cunoscută, aleasă pe server. Recalculată dincolo din
# altceva, ar deveni un al doilea răspuns la aceeași întrebare.
EVENT_ROLLUP_1H = Stream(
    name="event_rollup_1h",
    table="event_rollup_1h",
    columns=("bucket", "asset_id", "source", "action", "n", "uniq_src",
             "bytes_in", "bytes_out", "p95_latency_ms", "updated_at"),
    # Filigranul merge pe `updated_at`, nu pe `bucket`: un interval RECALCULAT
    # trebuie sa plece din nou. Pe gazda reala, presupunerea contrara insemna 60
    # de evenimente expediate in loc de 1385 — vezi `0025_rollup_watermark.sql`.
    time_column="updated_at",
    key_column="bucket",
    cursor_kind=ROLLUP,
    watermark_kind="text",
)

# Sesiunile de login. MUTABIL: o sesiune se deschide, adună comenzi, se închide,
# și se promovează la interactivă când sosește prima comandă cu terminal — patru
# schimbări pe același `id`.
#
# `unexpected` NU e în listă, și absența e o decizie: e `text[]`, iar expeditorul
# nu trimite tablouri. Ce anume a fost neobișnuit rămâne pe gazdă; panoul extern
# vede că sesiunea a fost neobișnuită prin severitatea alertei, nu prin listă.
LOGIN_SESSION_STREAM = Stream(
    name="login_sessions",
    table="login_sessions",
    columns=("id", "session_key", "username", "auid", "src_ip", "terminal",
             "interactive", "opened_at", "closed_at", "closed_inferred",
             "command_count", "sudo_count", "updated_at"),
    time_column="updated_at",
    cursor_kind=MUTABLE,
    key_column="id",
)

# Istoricul de comenzi. Append-only la sursă: nimic nu atinge un rând după ce a
# fost scris, deci cursorul merge pe `id` — monoton, fără goluri, independent de
# ceas.
#
# E fluxul cu cel mai mare volum din toate: măsurat pe gazdă pe 24 august 2026,
# **~630 de comenzi pentru o singură logare interactivă** (un shell de login
# sursează `/etc/profile.d/*`, iar fiecare script de acolo pornește zeci de
# procese) și **~405 000 pentru un deploy**. Plafonul de lot îl mărginește ca pe
# oricare altul, iar restanța se vede în `check_ship_lag`.
#
# `argv` sosește DEJA REDACTAT de la colector (`sentinel/redact.py`). Nu se
# redactează aici: la momentul ăsta secretul ar fi deja în baza locală, în
# backup-urile ei, și doar copia externă ar fi curată.
SESSION_COMMAND_STREAM = Stream(
    name="session_commands",
    table="session_commands",
    columns=("id", "session_id", "session_key", "ts", "username", "exe", "argv",
             "cwd", "tty", "pid", "ppid", "success"),
    time_column="ts",
)


STREAMS: tuple[Stream, ...] = (AUDIT_STREAM, INCIDENT_STREAM, TIMELINE_STREAM,
                               DETECTION_STREAM, FINDING_STREAM,
                               BLOCKLIST_STREAM, PATCH_PLAN_STREAM,
                               SELFCHECK_STREAM, EVENT_ROLLUP_1H,
                               SCAN_STREAM, LOGIN_SESSION_STREAM,
                               SESSION_COMMAND_STREAM)


class ShipEncodingError(Exception):
    """Un rând conține ceva ce nu se poate trimite la fel la ambele capete.

    Nu se repară prin reîncercare și nu se ocolește sărind rândul: un flux care
    sare peste ce nu înțelege e chiar pierderea tăcută de date. Fluxul se
    blochează, vizibil, iar `check_ship_lag` o raportează ca rămânere în urmă.
    """


@dataclass(frozen=True)
class Batch:
    """Ce s-a strâns pentru un flux într-o rundă.

    `watermark` e ce pleacă pe sârmă și ce trebuie să se întoarcă prin ecou: un
    întreg pozitiv, cel mai mare `id` din lot. `position` e unde ajunge cursorul
    LOCAL după ce ecoul confirmă — egal cu `watermark` pe un flux append-only, și
    perechea `(updated_at, cheie)` a ULTIMULUI rând pe unul mutabil. Cele două nu
    se pot contopi: pe un flux mutabil ultimul rând în ordinea `(updated_at, id)`
    nu e cel cu `id`-ul cel mai mare, iar a folosi unul în locul celuilalt ar sări
    peste rânduri sau le-ar retrimite la nesfârșit.

    `stall` gol înseamnă „am putut să mă uit". Orice altceva e motivul pentru care
    fluxul NU se expediază runda asta, și e ce deosebește „n-am găsit nimic de
    trimis" de „nu m-am putut uita" — două stări care, contopite, transformă
    expeditorul în ceva care raportează succes când s-a oprit.
    """

    stream: Stream
    rows: list[dict[str, Any]]
    watermark: int
    full: bool          # lotul a ieșit la limită, deci mai sunt rânduri
    position: Any = None
    # De unde a pornit cursorul runda asta. Împreună cu `position` și cu numărul
    # de rânduri, e fereastra pe care o RE-numără runda următoare ca să vadă dacă
    # au apărut rânduri dedesubt — vezi `_count_rows_that_appeared_below`.
    from_position: Any = None
    stall: str = ""

    def __post_init__(self) -> None:
        if self.position is None and not self.stall:
            object.__setattr__(self, "position", self.watermark)


@dataclass(frozen=True)
class StreamOutcome:
    """Ce a produs o rundă PENTRU UN SINGUR FLUX.

    Există fiindcă un singur verdict pentru N fluxuri e chiar cuplajul descris în
    capul modulului: cu el, un `incidents` blocat pe un rând necodificabil trage
    `audit_log` în exponențială, deși `audit_log` a plecat întreg în aceeași
    rundă. Programul de reîncercare se construiește din verdictele astea, nu din
    `ShipResult.ok`.

    `ok` are aici înțelesul de la `ShipResult`, îngustat la un flux: ori n-a fost
    nimic de trimis, ori ce s-a trimis a fost confirmat prin ecou și cursorul
    chiar s-a mutat. `more` e „lotul a ieșit plin, deci mai sunt rânduri" — și
    tot per flux, fiindcă unul care drenează o restanță trebuie să revină peste
    `DRAIN_PAUSE_S` chiar dacă vecinul lui e liniștit.
    """

    ok: bool
    more: bool = False
    reason: str = ""


@dataclass(frozen=True)
class ShipResult:
    """Ce a produs o rundă.

    `ok` NU înseamnă „am primit 200". Înseamnă „runda s-a încheiat fără nimic
    nelămurit": ori n-a fost nimic de trimis, ori tot ce s-a trimis a fost
    confirmat prin ecou. Orice altceva e `False`.

    `ok` rămâne verdictul RUNDEI și e ce se citește într-un test sau într-un
    jurnal; programul de reîncercare NU se mai ia din el, ci din `streams` — vezi
    `StreamOutcome`. Câtă vreme se lua din el, un flux oprit oprea cadența
    tuturor.

    `streams` are o intrare pentru FIECARE flux cerut rundei, inclusiv pentru
    cele care n-au avut nimic de trimis. Un flux fără intrare ar fi un „nu știu",
    iar bucla îl tratează ca eșec și o spune în jurnal: „nu știu" și „a plecat"
    nu au voie să arate la fel.
    """

    ok: bool
    reason: str = ""
    advanced: dict[str, int] = field(default_factory=dict)
    more: bool = False
    streams: dict[str, StreamOutcome] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cursoare
# ---------------------------------------------------------------------------
async def _next_sequence(db: Database) -> int:
    """Număr de lot strict crescător, persistat.

    Geamăn cu `beacon._next_sequence` ca mecanism și separat ca valoare: două
    expeditoare care ar împărți un contor s-ar vedea unul pe altul ca reluare la
    celălalt capăt. Ținut în aceeași tabelă ca restul cursoarelor, ca să
    supraviețuiască repornirii fără o stare nouă de întreținut.
    """
    return int(await db.fetchval(
        """
        INSERT INTO collector_cursors (name, cursor, updated_at)
        VALUES ($1, '1', now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = ((collector_cursors.cursor)::bigint + 1)::text,
                updated_at = now()
        RETURNING cursor::bigint
        """,
        BATCH_SEQ_KEY) or 1)


async def _cursor_of(db: Database, stream: Stream, cfg: Config) -> int:
    """Cursorul fluxului, așezat la prag dacă e prima rundă.

    Pragul se calculează O SINGURĂ dată în viața instalării, fiindcă după aceea
    cursorul există. Vezi „Ce se întâmplă cu rândurile mai vechi" în capul
    modulului: de aici încolo nu se mai sare peste nimic.
    """
    existing = await db.fetchval(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if existing is not None:
        return int(existing)

    floor = int(await db.fetchval(
        f"SELECT coalesce(max(id), 0) FROM {stream.table} "  # noqa: S608 - identificatori din STREAMS
        f"WHERE {stream.time_column} < now() - make_interval(days => $1::int)",
        int(cfg.ship.max_backfill_days)) or 0)

    # Ambele rânduri într-o singură instrucțiune: scrise separat, o cădere între
    # ele ar lăsa un cursor fără prag, iar atunci `check_ship_lag` n-ar mai putea
    # spune niciodată câte rânduri n-au plecat.
    await db.execute(
        """
        INSERT INTO collector_cursors (name, cursor, updated_at)
        VALUES ($1, ($3::bigint)::text, now()), ($2, ($3::bigint)::text, now())
        ON CONFLICT (name) DO NOTHING
        """,
        stream.cursor_name, stream.floor_name, floor)

    if floor > 0:
        skipped = int(await db.fetchval(
            f"SELECT count(*) FROM {stream.table} WHERE id <= $1",  # noqa: S608
            floor) or 0)
        # WARNING, nu INFO: e o pierdere definitivă, chiar dacă e una cerută de
        # configurație. Și nu doar aici — pragul rămâne citibil în `ship:lag`,
        # fiindcă un fapt care trăiește într-o linie de jurnal e un fapt pierdut.
        log.warning(
            "shipper starts above a backfill floor",
            extra={"stream": stream.name, "floor_id": floor, "skipped_rows": skipped,
                   "max_backfill_days": cfg.ship.max_backfill_days,
                   "action": "Rândurile de sub prag nu vor fi expediate niciodată. "
                             "Dacă trebuiau, mărește ship.max_backfill_days ÎNAINTE "
                             "de prima rundă și șterge cursoarele ship:* — după ce "
                             "pragul e așezat, ridicarea limitei nu-l coboară."})

    # Re-citit, nu presupus: dacă `ON CONFLICT DO NOTHING` a găsit rândul deja
    # scris, valoarea care contează e a lui, nu a noastră.
    return int(await db.fetchval(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = $1",
        stream.cursor_name) or 0)


async def _advance(db: Database, stream: Stream, watermark: int, rows: int) -> int:
    """Mută cursorul și întoarce valoarea pe care baza o are DUPĂ mutare.

    Se întoarce ce s-a scris, nu ce s-a cerut: un `UPDATE` care n-a potrivit
    niciun rând iese cu succes, iar apelantul care nu se uită raportează o
    avansare care nu s-a întâmplat. `GREATEST` face mutarea monotonă — un cursor
    nu are voie să scadă nici dintr-o greșeală de cod, fiindcă asta ar retrimite
    la nesfârșit aceleași rânduri.
    """
    return int(await db.fetchval(
        """
        INSERT INTO collector_cursors (name, cursor, events_seen, updated_at)
        VALUES ($1, ($2::bigint)::text, $3::bigint, now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = GREATEST((collector_cursors.cursor)::bigint, $2::bigint)::text,
                events_seen = collector_cursors.events_seen + $3::bigint,
                updated_at = now()
        RETURNING cursor::bigint
        """,
        stream.cursor_name, watermark, rows) or 0)


# ---------------------------------------------------------------------------
# Cursoare pe timp: `(updated_at, cheie)`
# ---------------------------------------------------------------------------
class ShipStallError(Exception):
    """Un flux nu se poate expedia, și nu fiindcă n-are ce.

    Prinsă PER FLUX în `ship_once`. Există ca familie separată de erorile de bază
    de date fiindcă tratamentul e altul: o bază indisponibilă se reîncearcă, asta
    se spune. Comun tuturor subclaselor e că interogarea fluxului ar întoarce
    liniștită zero rânduri, adică ar arăta exact ca o gazdă pe care nu s-a
    schimbat nimic.
    """


class ShipClockError(ShipStallError):
    """Ceasul bazei e în urma filigranului unui flux.

    Până când timpul real ajunge din urmă filigranul, interogarea fluxului
    întoarce corect zero rânduri, iar rândurile atinse între timp nu vor fi
    selectate niciodată.
    """


class ShipTriggerError(ShipStallError):
    """Coloana `updated_at` a fluxului nu e întreținută de niciun trigger.

    Modul de eșec pentru care există, și e cel mai tăcut din tot fișierul: fără
    trigger, `updated_at` rămâne valoarea pusă de `DEFAULT now()` la INSERT.
    Rândul se schimbă, momentul lui nu. Cursorul trece o dată peste el și nu-l mai
    vede niciodată — iar de pe gazdă totul arată sănătos: interogarea întoarce
    zero rânduri, ceasul e bun, `pending` e zero, `check_ship_lag` spune „la zi",
    la nesfârșit.

    Un fișier de migrație pe disc nu e dovadă că nucleul l-a acceptat, iar
    `schema_version` spune doar că instrucțiunile au rulat fără eroare pe
    versiunea de-atunci a fișierului. Singurul fapt e `pg_trigger`, întrebat la
    rulare — inclusiv `tgenabled`, fiindcă și un `ALTER TABLE … DISABLE TRIGGER`,
    și un `ENABLE REPLICA TRIGGER` lasă rândul în catalog și opresc efectul pe o
    sesiune obișnuită.
    """


async def clock_ahead_s(db: Database, cursor_at: datetime) -> float:
    """Câte secunde e filigranul ÎNAINTEA ceasului bazei. Negativ = normal.

    Se întreabă baza, nu Python, și nu din pedanterie: `updated_at` e scris de
    `now()` din trigger, deci singura comparație care înseamnă ceva e cu același
    ceas. Un `datetime.now()` de aici ar măsura în plus decalajul dintre două
    procese de pe aceeași gazdă și ar numi „derapaj de ceas" ceva ce nu e.

    Sub funcționare normală rezultatul e cel mult `-COMMIT_SAFETY_LAG_S`: un
    filigran se așază pe un rând care era deja mai vechi de atât, iar `now()` doar
    crește după aceea. Orice valoare POZITIVĂ înseamnă deci că ceasul a mers
    înapoi cu mai mult decât fereastra de siguranță — nu că e „aproape".
    """
    ahead = await db.fetchval(
        "SELECT EXTRACT(EPOCH FROM ($1::timestamptz - now()))", cursor_at)
    if ahead is None:
        # Nu „zero". Un rezultat absent înseamnă că nu s-a putut compara, iar
        # „nu știu" raportat ca „e bine" e chiar minciuna pe care o caută
        # verificarea de mai jos.
        raise ShipClockError(
            "comparația dintre filigran și ceasul bazei nu a întors nimic")
    return float(ahead)


async def updated_at_trigger_installed(db: Database, stream: Stream) -> bool:
    """Baza chiar ține `updated_at` a tabelei fluxului? Întrebat, nu presupus.

    Fiecare condiție de mai jos corespunde unei forme de „e acolo și nu face
    nimic", și fiecare arată de pe gazdă exact ca „nu s-a schimbat nimic":

    * `tgfoid = to_regproc('set_updated_at')` — un trigger care cheamă altceva nu
      atinge coloana. `to_regproc`, nu `::regproc`: al doilea RIDICĂ dacă funcția
      nu există, iar excepția aia ar ajunge în ramura „bază indisponibilă" și s-ar
      reîncerca la nesfârșit în loc să numească lipsa;
    * `tgtype & 19 = 19` — bit 1 ROW, bit 2 BEFORE, bit 16 UPDATE. Un `AFTER` nu
      mai poate schimba `NEW`, iar un `FOR EACH STATEMENT` ratează un
      `UPDATE … WHERE status = 'open'` peste patruzeci de rânduri;
    * `tgenabled IN ('O', 'A')` — coloana are PATRU valori, nu două: `'O'`
      (origine, normalul), `'A'` (întotdeauna), `'D'` (dezactivat) și `'R'`, care
      se declanșează DOAR pe o sesiune cu `session_replication_role = 'replica'`.
      Un trigger `'R'` nu rulează pentru expeditor, deci un `<> 'D'` ar fi lăsat
      să treacă exact forma pe care verificarea asta o caută: prezent în catalog
      și fără efect. Se enumeră ce se ACCEPTĂ, nu ce se respinge — o listă de
      respinsuri e greșită de fiecare dată când apare o valoare nouă;
    * `NOT tgisinternal` — triggerele de cheie străină nu se pun la socoteală.

    `to_regclass($1)` întoarce NULL pentru o tabelă inexistentă, deci `count` iese
    0 și fluxul se oprește cu un mesaj, nu cu o urmă de excepție.
    """
    found = await db.fetchval(
        """
        SELECT count(*) FROM pg_trigger
        WHERE tgrelid = to_regclass($1)
          AND NOT tgisinternal
          AND tgfoid = to_regproc('set_updated_at')
          AND (tgtype & 19) = 19
          AND tgenabled IN ('O', 'A')
        """,
        stream.table)
    if found is None:
        # `count(*)` nu întoarce NULL niciodată. Dacă totuși, nu s-a putut întreba
        # — iar „n-am putut întreba" nu are voie să treacă drept „e instalat".
        raise ShipTriggerError(
            f"nu s-a putut citi pg_trigger pentru {stream.table}")
    return int(found) > 0


async def _mutable_cursor_of(db: Database, stream: Stream,
                             cfg: Config) -> tuple[datetime, int]:
    """Filigranul `(updated_at, cheie)` al unui flux mutabil, așezat la prag dacă
    e prima rundă.

    Pragul unui flux mutabil e un MOMENT, nu un `id`: rândurile neatinse de mai
    mult de `max_backfill_days` nu pleacă niciodată. Pe o schemă proaspăt migrată
    pragul nu taie nimic — 0023 dă tuturor rândurilor existente `updated_at` egal
    cu momentul migrației —, deci prima rundă duce starea curentă întreagă, lot cu
    lot. E purtarea dorită pentru un panou, și e scrisă aici ca să nu fie
    descoperită ca restanță bruscă.
    """
    row = await db.fetchrow(
        "SELECT cursor, cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if row is not None:
        if row["cursor_at"] is None:
            # Un cursor mutabil fără jumătatea de timp nu e „de la început": e un
            # rând scris de altcineva sau rămas dintr-o versiune care nu cunoștea
            # coloana. A-l citi ca zero ar retrimite toată tabela; a-l citi ca
            # `now()` ar sări tot ce e în urmă. Se refuză, vizibil.
            raise ShipClockError(
                f"cursorul {stream.cursor_name} nu are cursor_at, deci nu se "
                f"poate spune de unde continuă fluxul")
        return row["cursor_at"], _cursor_key(stream, row["cursor"])

    floor_at = await db.fetchval(
        "SELECT now() - make_interval(days => $1::int)",
        int(cfg.ship.max_backfill_days))

    # Ambele rânduri într-o singură instrucțiune, din același motiv ca la
    # cursorul pe `id`: o cădere între ele ar lăsa un cursor fără prag.
    await db.execute(
        """
        INSERT INTO collector_cursors (name, cursor, cursor_at, updated_at)
        VALUES ($1, $4, $3::timestamptz, now()), ($2, $4, $3::timestamptz, now())
        ON CONFLICT (name) DO NOTHING
        """,
        stream.cursor_name, stream.floor_name, floor_at, stream.key_floor)

    skipped = int(await db.fetchval(
        f"SELECT count(*) FROM {stream.table} "  # noqa: S608 - identificatori din STREAMS
        f"WHERE {stream.time_column} <= $1::timestamptz",
        floor_at) or 0)
    if skipped:
        log.warning(
            "shipper starts above a backfill floor",
            extra={"stream": stream.name, "floor_at": str(floor_at),
                   "skipped_rows": skipped,
                   "max_backfill_days": cfg.ship.max_backfill_days,
                   "action": "Rândurile neatinse de dinaintea pragului nu vor fi "
                             "expediate niciodată. Dacă trebuiau, mărește "
                             "ship.max_backfill_days ÎNAINTE de prima rundă și "
                             "șterge cursoarele ship:* — după ce pragul e așezat, "
                             "ridicarea limitei nu-l coboară."})

    # Re-citit, nu presupus: dacă `ON CONFLICT DO NOTHING` a găsit rândul deja
    # scris, valoarea care contează e a lui.
    written = await db.fetchrow(
        "SELECT cursor, cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if written is None or written["cursor_at"] is None:
        raise ShipClockError(
            f"cursorul {stream.cursor_name} nu s-a putut scrie sau citi înapoi")
    return written["cursor_at"], _cursor_key(stream, written["cursor"])


async def _advance_mutable(db: Database, stream: Stream,
                           position: tuple[datetime, int],
                           rows: int) -> tuple[datetime | None, int | None]:
    """Mută filigranul pe pereche și întoarce ce are baza DUPĂ mutare.

    `CASE`-ul face mutarea monotonă, exact ca `GREATEST` la cursorul pe `id`, dar
    pe perechea întreagă: comparat doar pe timp, două rânduri cu același
    `updated_at` s-ar retrimite la nesfârșit; comparat doar pe cheie, un rând
    atins din nou și-ar pierde locul.

    `cursor_at` NULL în rândul existent face comparația necunoscută, deci `CASE`
    cade pe ramura „nu muta" și apelantul vede că nu s-a mutat. E purtarea
    corectă: un filigran despre care nu se știe nimic nu are voie să fie sărit.
    """
    stored, incoming, returned = _key_sql(stream)
    moved = (f"(collector_cursors.cursor_at, {stored}) "
             f"< ($2::timestamptz, $3::{stream.key_sql_type})")
    row = await db.fetchrow(
        f"""
        INSERT INTO collector_cursors (name, cursor, cursor_at, events_seen, updated_at)
        VALUES ($1, {incoming}, $2::timestamptz, $4::bigint, now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = CASE WHEN {moved}
                              THEN {incoming}
                              ELSE collector_cursors.cursor END,
                cursor_at = CASE WHEN {moved}
                                 THEN $2::timestamptz
                                 ELSE collector_cursors.cursor_at END,
                events_seen = collector_cursors.events_seen + $4::bigint,
                updated_at = now()
        RETURNING cursor_at, {returned}
        """,  # noqa: S608 - bucățile vin din `_key_sql`, nu din date
        stream.cursor_name, position[0], position[1], rows)
    if row is None:
        return None, None
    return row["cursor_at"], row["cursor_key"]


async def _remember_window(db: Database, stream: Stream,
                           from_position: tuple[datetime, int], rows: int) -> None:
    """Ține minte fereastra pe care tocmai am citit-o, și câte rânduri erau în ea.

    Se scrie ÎNAINTE de mutarea cursorului, nu după. O cădere între cele două
    lasă un memo peste o fereastră care nu s-a mai deschis — iar atunci
    numărătoarea de mai jos iese ZERO față de un așteptat pozitiv, adică sub
    prag, adică tăcere. Invers — cursor mutat, memo nescris — ar fi lăsat
    fereastra nemăsurată, și n-am fi aflat niciodată.
    """
    _stored, incoming, _returned = _key_sql(stream)
    await db.execute(
        f"""
        INSERT INTO collector_cursors (name, cursor, cursor_at, events_seen, updated_at)
        VALUES ($1, {incoming}, $2::timestamptz, $4::bigint, now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = {incoming},
                cursor_at = $2::timestamptz,
                events_seen = $4::bigint,
                updated_at = now()
        """,  # noqa: S608 - bucățile vin din `_key_sql`, nu din date
        stream.window_name, from_position[0], from_position[1], rows)


async def _count_rows_that_appeared_below(db: Database, stream: Stream,
                                          cursor_at: datetime,
                                          cursor_key: int) -> int:
    """Câte rânduri au apărut în urma cursorului DUPĂ ce a trecut peste ele.

    Detectorul pierderii pe care `COMMIT_SAFETY_LAG_S` doar o MĂRGINEȘTE. `now()`
    e ora de început a tranzacției, deci un rând atins într-o tranzacție mai lungă
    decât fereastra devine vizibil cu un moment aflat deja sub cursor și nu mai e
    selectat niciodată. Fereastra face cazul improbabil; nu-l face imposibil, iar
    „improbabil și tăcut" e chiar felul de defect pentru care există fișierul ăsta.

    Cum se măsoară, fără să presupună nimic: runda trecută a citit fereastra
    `(memo, cursor]` și a văzut acolo N rânduri. Fereastra e închisă — nimic nu
    mai poate intra în ea LEGITIM, fiindcă orice atingere nouă pune `updated_at =
    now()`, care e deasupra cursorului. Deci dacă acum se numără mai mult de N,
    diferența sunt exact rândurile comise cu întârziere. Zero e normalul.

    Se numără, nu se citește un contor: numărătoarea e faptul, contorul ar fi
    intenția noastră despre el.
    """
    memo = await db.fetchrow(
        "SELECT cursor, cursor_at, events_seen FROM collector_cursors WHERE name = $1",
        stream.window_name)
    if memo is None or memo["cursor_at"] is None:
        # Prima rundă de după instalarea mecanismului. „Nu am cu ce compara" nu e
        # „zero pierderi", dar nici o constatare: nu s-a măsurat nimic încă.
        return 0

    seen_now = await db.fetchval(
        f"SELECT count(*) FROM {stream.table} "  # noqa: S608 - identificatori din STREAMS
        f"WHERE ({stream.time_column}, {stream.key_column}) > "
        f"($1::timestamptz, $2::{stream.key_sql_type}) "
        f"AND ({stream.time_column}, {stream.key_column}) <= "
        f"($3::timestamptz, $4::{stream.key_sql_type})",
        memo["cursor_at"], _cursor_key(stream, memo["cursor"]), cursor_at, cursor_key)
    if seen_now is None:
        raise ShipClockError(
            f"numărătoarea ferestrei lui {stream.name} nu a întors nimic")
    extra = int(seen_now) - int(memo["events_seen"])
    if extra <= 0:
        # Mai PUȚINE decât atunci înseamnă rânduri șterse între timp, ceea ce e
        # normal și nu e o pierdere de expediere.
        return 0

    total = int(await db.fetchval(
        """
        INSERT INTO collector_cursors (name, cursor, updated_at)
        VALUES ($1, ($2::bigint)::text, now())
        ON CONFLICT (name) DO UPDATE
            SET cursor = ((collector_cursors.cursor)::bigint + $2::bigint)::text,
                updated_at = now()
        RETURNING cursor::bigint
        """,
        stream.lost_name, extra) or extra)
    log.error(
        "rows appeared below the shipping cursor and will never be shipped",
        extra={"stream": stream.name, "rows": extra, "total_lost": total,
               "commit_safety_lag_s": COMMIT_SAFETY_LAG_S,
               "action": "O tranzacție de scriere a ținut mai mult decât "
                         "COMMIT_SAFETY_LAG_S din sentinel/report/shipper.py, deci "
                         "rândurile ei au devenit vizibile sub filigran. Măsoară: "
                         "SELECT max(now() - xact_start) FROM pg_stat_activity "
                         "WHERE xact_start IS NOT NULL; — apoi ridică fereastra "
                         "peste valoarea aia. Rândurile pierdute se recuperează "
                         "numai retrăgând filigranul cu mâna: docs/OPERARE.md, "
                         "„Rânduri apărute sub filigran”."})
    return extra


# ---------------------------------------------------------------------------
# Strângerea
# ---------------------------------------------------------------------------
def encode_value(value: Any, where: str) -> Any:
    """Valoarea unei coloane, în formă semnabilă.

    Contractul din `sentinel/report/signing.py` acceptă `None`, `bool`, `int`,
    `str`, listă și dicționar. Ce nu intră acolo se REFUZĂ, nu se convertește
    „evident": un `str(x)` peste orice a fost în coloană e un al doilea
    serializator, ascuns, pe care celălalt capăt nu-l cunoaște.

    `jsonb` sosește din asyncpg ca text și așa pleacă — dinadins. Despachetat
    într-un dicționar, `params` ar putea conține un `float` (o durată, un scor),
    iar contractul refuză float-urile: fluxul s-ar bloca definitiv pe un rând
    perfect valid. Expeditorul e un transport, nu un re-codificator.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        # DUPĂ `datetime`, nu înainte: `datetime` e o subclasă a lui `date`, deci
        # ordinea inversă ar trimite fiecare moment ca zi și ar pierde ora. O
        # coloană `date` — `findings.kev_due_date` e prima — ajunge aici, iar
        # fără linia asta fluxul ei ar muri la primul rând cu termen KEV.
        return value.isoformat()
    if isinstance(value, Decimal):
        # Regula „transport, nu re-codificator" de mai sus NU se aplică aici, și
        # merită spus de ce în loc să fie ocolită printr-un cast în interogare.
        # Ea există pentru conversiile CU PIERDERE sau AMBIGUE — cazul canonic
        # fiind `float`, unde `0.1` n-are reprezentare exactă și două
        # implementări pot scrie șiruri diferite. `Decimal` are formă canonică de
        # șir, iar drumul dus-întors e exact: `Decimal(str(x)) == x`.
        #
        # Rezolvat în codificator, nu în SQL: un `::text` într-o interogare
        # rezolvă o coloană și lasă următoarea coloană numerică să reinventeze
        # soluția. Aici se rezolvă o dată, pentru toate.
        #
        # Ce urmează din asta la celălalt capăt: pe sârmă ajunge TEXT, iar
        # `aggregator/lib/streams.ts` are un fel de coloană `decimal` care
        # verifică forma. Lăsat drept `text`, un șir stricat ar ajunge într-o
        # coloană `DECIMAL` și ar fi refuzat abia de MariaDB, cu un mesaj despre
        # tipuri în loc de unul despre date.
        return str(value)
    if isinstance(value, (IPv4Address, IPv6Address)):
        # A treia excepție de aceeași formă ca `Decimal`, și ultima de care
        # `detections` are nevoie. `asyncpg` întoarce o coloană `inet` ca obiect
        # de adresă, nu ca text, iar contractul de semnare nu-l cunoaște — fără
        # linia asta fluxul moare la primul rând cu `src_ip`, izolat (fiecare
        # flux are `try`-ul lui) dar MUT: se vede doar ca restanță în `ship:lag`.
        #
        # Conversia e permisă din același motiv ca la `Decimal`: forma de șir e
        # canonică și drumul dus-întors e exact — `ip_address(str(x)) == x`. Nu e
        # o conversie „evidentă" peste orice a fost în coloană, e una definită.
        #
        # Ce urmează la celălalt capăt: `aggregator/lib/streams.ts` are un fel de
        # coloană `inet` care cere un ȘIR și îi verifică forma canonică. Nota de
        # acolo spunea deja că adresa „pleacă de aici ca text" — era o
        # anticipare, nu un fapt, până azi.
        return str(value)
    if isinstance(value, UUID):
        # `patch_plans.plan_id` e `uuid`, iar asyncpg îl întoarce ca obiect.
        # Aceeași justificare ca la `Decimal` și la adrese: forma de șir e
        # canonică — minuscule, cu cratime — iar drumul dus-întors e exact,
        # `UUID(str(x)) == x`. Receptorul o primește ca text într-o coloană
        # `CHAR(36)`.
        return str(value)
    raise ShipEncodingError(
        f"{where}: tipul {type(value).__name__} nu se poate expedia. Coloanele "
        f"jsonb trebuie să sosească drept text; orice altceva are nevoie de o "
        f"conversie explicită în shipper.encode_value")


def select_columns(stream: Stream) -> tuple[str, ...]:
    """Ce se cere din bază: scalarii, plus coloanele-tablou ale copiilor.

    Separate în declarație, împreună în `SELECT`. Dacă ar fi împreună și în
    declarație, testul de paritate ar compara o coloană-tablou cu scalarii
    receptorului și ar cere ceva ce receptorul refuză ca de-al părintelui.
    """
    return stream.columns + tuple(child.column for child in stream.children)


def encode_row(stream: Stream, record: Any, key: Any,
               max_children: int) -> tuple[dict[str, Any], int]:
    """Un rând gata de trimis, plus câte sub-rânduri poartă.

    Un părinte cu mai mulți copii decât plafonul NU se sare: se oprește fluxul,
    zgomotos. Un rând sărit nu se mai întoarce niciodată — ce trece de cursor nu
    se retrimite —, iar o detecție cu o mie de evenimente e chiar aia pe care
    vrei s-o vezi.
    """
    row: dict[str, Any] = {
        column: encode_value(record[column], f"{stream.name}[{key}].{column}")
        for column in stream.columns
    }
    carried = 0
    for child in stream.children:
        values = record[child.column]
        values = [] if values is None else list(values)
        if len(values) > max_children:
            raise ShipEncodingError(
                f"{stream.name}[{key}].{child.column}: {len(values)} sub-rânduri, "
                f"peste plafonul de {max_children}. Receptorul ar refuza lotul cu "
                f"413, iar `ship_once` nu-i citește niciodată corpul — deci fluxul "
                f"s-ar opri arătând ca un agregator căzut. Se oprește AICI, cu "
                f"numele coloanei")
        row[child.column] = [
            {child.field: encode_value(
                value, f"{stream.name}[{key}].{child.column}[{index}]")}
            for index, value in enumerate(values)
        ]
        carried += len(values)
    return row, carried


async def collect_stream(db: Database, cfg: Config, stream: Stream) -> Batch:
    """Rândurile netrimise ale unui flux, cel mult `max_rows_per_batch`.

    Fiecare flux se strânge în `try`-ul LUI (`ship_once`), și asta a devenit
    obligatoriu odată cu al doilea flux: strânse împreună, un `incidents` cu o
    valoare pe care `encode_value` n-o cunoaște ar fi oprit și expedierea lui
    `audit_log`, adică fluxul care există tocmai ca lanțul de audit să poată fi
    verificat din afara gazdei. Blocajul ar fi rămas vizibil (`ship:lag`
    raportează restanța pe fiecare flux), dar cauza ar fi fost în alt flux decât
    efectul, iar asta se caută prost. Acum fluxul stricat rămâne pe loc și restul
    pleacă.

    Derapajul de ceas E deja izolat per flux — vezi `ShipClockError` de mai jos
    și `ship_once` —, fiindcă e prin natura lui al unui singur fel de cursor:
    un ceas care sare nu are ce strica unui flux pe `id`, iar a opri `audit_log`
    fiindcă `incidents` s-a poticnit ar fi chiar cauza-în-alt-flux de mai sus.
    """
    if stream.cursor_kind == ROLLUP:
        return await _collect_rollup(db, cfg, stream)
    if stream.cursor_kind == MUTABLE:
        return await _collect_mutable(db, cfg, stream)

    cursor = await _cursor_of(db, stream, cfg)
    limit = int(cfg.ship.max_rows_per_batch)
    records = await db.fetch(
        f"SELECT {', '.join(select_columns(stream))} FROM {stream.table} "  # noqa: S608
        f"WHERE id > $1 ORDER BY id LIMIT $2",
        cursor, limit)

    rows: list[dict[str, Any]] = []
    children = 0
    cut_short = False
    for record in records:
        row, carried = encode_row(stream, record, record["id"],
                                  int(cfg.ship.max_children_per_row))
        # Bugetul de sub-rânduri TAIE lotul, nu-l face refuzat. 2000 de detecții
        # cu câte cinci evenimente fiecare înseamnă 10000 de copii, peste plafonul
        # receptorului — iar un lot refuzat nu se micșorează nicăieri, se
        # retrimite identic la nesfârșit. Se trimit mai puțini părinți, iar restul
        # pleacă runda următoare: cursorul avansează, deci nu se pierde nimic.
        if rows and children + carried > int(cfg.ship.max_child_rows_per_batch):
            cut_short = True
            break
        rows.append(row)
        children += carried
    watermark = int(rows[-1]["id"]) if rows else cursor
    return Batch(stream=stream, rows=rows, watermark=watermark,
                 full=cut_short or len(rows) >= limit)


async def _collect_mutable(db: Database, cfg: Config, stream: Stream) -> Batch:
    """Rândurile schimbate ale unui flux mutabil, după `(updated_at, cheie)`.

    Ordinea din `ORDER BY` și comparația din `WHERE` sunt aceeași pereche, în
    aceeași ordine, dinadins: dacă ar diferi, rândurile de la marginea unui lot
    ar cădea între cele două și nu s-ar mai întoarce niciodată.

    Fereastra `COMMIT_SAFETY_LAG_S` taie coada proaspătă. Fără ea, un rând atins
    de o tranzacție lungă devine vizibil după ce cursorul a trecut de momentul lui.
    """
    # ÎNAINTE de orice citire a fluxului. Fără trigger, tot ce urmează e corect și
    # fără sens: interogarea întoarce zero rânduri fiindcă niciun `updated_at` nu
    # se mai mișcă, iar asta arată identic cu o tabelă în care nu s-a schimbat
    # nimic. Un fișier de migrație pe disc nu e dovadă că nucleul l-a acceptat.
    if not await updated_at_trigger_installed(db, stream):
        raise ShipTriggerError(
            f"{stream.table}.{stream.time_column} nu e întreținută de niciun "
            f"trigger BEFORE UPDATE activ care să cheme set_updated_at(), deci "
            f"momentul unui rând nu se mai schimbă când rândul se schimbă. "
            f"Fluxul nu se expediază: ar părea la zi și n-ar duce nicio "
            f"modificare. Repară cu `sentinel migrate`")

    cursor_at, cursor_key = await _mutable_cursor_of(db, stream, cfg)

    ahead = await clock_ahead_s(db, cursor_at)
    if ahead > 0:
        # Aici se decide diferența dintre „nu s-a schimbat nimic" și „ceasul a
        # sărit". Fără ramura asta, interogarea de mai jos ar întoarce corect zero
        # rânduri și runda ar raporta succes — la nesfârșit, în timp ce tot ce se
        # atinge pe gazdă se pierde definitiv.
        return Batch(
            stream=stream, rows=[], watermark=0, full=False,
            stall=(f"ceasul bazei e cu {ahead:.0f}s în urma filigranului "
                   f"({cursor_at.isoformat()}). Din fluxul „{stream.name}” nu "
                   f"pleacă nimic în următoarele {ahead:.0f} de secunde, iar tot "
                   f"ce se schimbă în răstimpul ăsta rămâne SUB filigran și nu va "
                   f"fi expediat NICIODATĂ — nici după ce ceasul se repară. "
                   f"Singura cale de recuperare e o resincronizare, retrăgând "
                   f"filigranul cu mâna (docs/OPERARE.md, „Expedierea s-a oprit "
                   f"din cauza ceasului”)"))

    # După verificarea ceasului: pe un filigran rămas în viitor, fereastra
    # dinainte n-are ce spune, iar numărătoarea ar fi zgomot peste o problemă
    # deja raportată.
    await _count_rows_that_appeared_below(db, stream, cursor_at, cursor_key)

    limit = int(cfg.ship.max_rows_per_batch)
    records = await db.fetch(
        f"SELECT {', '.join(stream.columns)} FROM {stream.table} "  # noqa: S608
        f"WHERE ({stream.time_column}, {stream.key_column}) > "
        f"($1::timestamptz, $2::{stream.key_sql_type}) "
        f"AND {stream.time_column} <= now() - make_interval(secs => $3::double precision) "
        f"ORDER BY {stream.time_column}, {stream.key_column} LIMIT $4",
        cursor_at, cursor_key, COMMIT_SAFETY_LAG_S, limit)

    rows: list[dict[str, Any]] = []
    keys: list[int] = []
    children = 0
    cut_short = False
    for record in records:
        key = record[stream.key_column]
        wants_text = stream.watermark_kind == "text"
        bad = (not isinstance(key, str) or key == "") if wants_text else (
            isinstance(key, bool) or not isinstance(key, int))
        if bad:
            # Filigranul de pe sârmă e un întreg pozitiv, iar un `str(key)` sau un
            # `hash(key)` de aici ar fi un filigran inventat, pe care ecoul l-ar
            # confirma fără să însemne nimic. Se oprește, cu numele coloanei.
            asteptat = "un șir nevid" if wants_text else "întreagă"
            raise ShipEncodingError(
                f"{stream.name}.{stream.key_column}: departajarea filigranului "
                f"unui flux mutabil trebuie să fie {asteptat}, nu "
                f"{type(key).__name__}. Agregatorul cere `cursors.{stream.name}` "
                f"de felul declarat, iar un filigran de alt fel e refuzat acolo "
                f"fără ca `ship_once` să-i citească vreodată motivul")
        row, carried = encode_row(stream, record, key,
                                  int(cfg.ship.max_children_per_row))
        if rows and children + carried > int(cfg.ship.max_child_rows_per_batch):
            cut_short = True
            break
        keys.append(key)
        rows.append(row)
        children += carried

    if not rows:
        return Batch(stream=stream, rows=[], watermark=0, full=False,
                     position=(cursor_at, cursor_key),
                     from_position=(cursor_at, cursor_key))

    # Ultimul rând INCLUS, nu ultimul citit: cu lotul tăiat de bugetul de
    # sub-rânduri cele două diferă, iar poziția luată din al doilea ar sări peste
    # părinții rămași — exact pierderea tăcută pe care cursorul o previne.
    last = records[len(rows) - 1]
    return Batch(
        stream=stream, rows=rows,
        from_position=(cursor_at, cursor_key),
        # Pe sârmă pleacă cel mai mare `id` din lot, fiindcă asta cere receptorul.
        # Ultimul rând în ordinea `(updated_at, id)` nu e el, deci filigranul
        # LOCAL e altul — vezi `Batch` și `wire_watermark`.
        watermark=wire_watermark(keys, stream.watermark_kind),
        full=cut_short or len(rows) >= limit,
        position=(last[stream.time_column], last[stream.key_column]))


# ---------------------------------------------------------------------------
# Răspunsul: ecoul, nu codul de stare
# ---------------------------------------------------------------------------
def accepted_watermarks(body: str, sent: dict[str, int | str],
                        ) -> tuple[dict[str, int | str], str]:
    """(fluxurile confirmate, motivul pentru ce n-a fost confirmat).

    Un flux e confirmat DOAR dacă `accepted.<flux>` e exact întregul trimis.
    Fiecare refuz de mai jos corespunde unui răspuns care, altfel, arată exact
    ca un succes:

    * corp care nu e JSON → o pagină de la un CDN sau de la alt vhost;
    * `ok` lipsă sau fals → receptorul spune singur că n-a preluat;
    * `accepted` fără fluxul nostru → agregator care nu cunoaște fluxul și l-a
      ignorat tăcut, adică pierderea permanentă pentru care există regula;
    * valoare diferită, sau de alt TIP DECÂT CEL TRIMIS → nu vorbim despre
      același lot.

    `True` e exclus explicit: în Python `True == 1`, deci un `{"audit_log": true}`
    ar confirma filigranul 1 fără ca nimeni să scrie asta.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return {}, "răspunsul nu e JSON"
    if not isinstance(parsed, dict):
        return {}, "răspunsul nu e un obiect JSON"
    if parsed.get("ok") is not True:
        return {}, f"răspunsul nu spune ok:true (ok={parsed.get('ok')!r})"
    accepted = parsed.get("accepted")
    if not isinstance(accepted, dict):
        return {}, "răspunsul nu conține un obiect `accepted`"

    confirmed: dict[str, int | str] = {}
    problems: list[str] = []
    for name, watermark in sent.items():
        echoed = accepted.get(name)
        if echoed is None:
            problems.append(f"{name}: lipsește din `accepted`")
            continue
        if type(echoed) is not type(watermark):
            # Tipul TRIMIS e referința, nu „întreg". Până pe 21 august 2026 aici
            # scria `not isinstance(echoed, int)`, scris când toate filigranele
            # erau numere. Fluxul cu filigran text a trecut de SQL, a plecat, a
            # fost acceptat, iar agregatorul i-a ecouat înapoi exact șirul
            # trimis — și tot n-a fost confirmat, fiindcă verificarea cerea un
            # întreg. Rândurile se retrimiteau la fiecare rundă, la nesfârșit.
            #
            # Comparația e pe tip exact, nu `isinstance`: `True` e `bool`, deci
            # cade singur (în Python `True == 1`, iar un `{"audit_log": true}` ar
            # fi confirmat altfel filigranul 1 fără ca nimeni să scrie asta). La
            # fel cade și un `346.0` întors ca float de un receptor neglijent.
            problems.append(
                f"{name}: filigran de tip {type(echoed).__name__}, "
                f"trimis {type(watermark).__name__}")
            continue
        if echoed != watermark:
            problems.append(f"{name}: ecou {echoed} pentru filigranul {watermark}")
            continue
        confirmed[name] = watermark
    return confirmed, "; ".join(problems)


# ---------------------------------------------------------------------------
# O rundă
# ---------------------------------------------------------------------------
# Tipurile de excepție pe care le ridică un defect al CODULUI de aici, nu baza.
#
# `except Exception` din bucla de strângere prinde tot ce nu e `ShipStallError`
# sau `ShipEncodingError`, și asta rămâne cum e: fluxul trebuie să cadă singur și
# vizibil orice ar fi, fiindcă alternativa e o rundă care se oprește pe jumătate
# fără să spună. Ce era greșit e că ieșea într-un SINGUR fel — „shipper could not
# read the local database" —, deci un `AttributeError` din `collect_stream` îl
# trimitea pe operator să caute în Postgres o cauză care e în Python. Două cauze
# cu remedii diferite ajungeau la el cu aceleași cuvinte, exact ce
# `test_two_different_causes_never_reach_the_operator_with_the_same_words` există
# să interzică.
#
# Departajarea e după TIP, fiindcă alt semnal nu există: driverul nu ridică
# `AttributeError`/`TypeError`/`KeyError`/`IndexError`/`NameError` pentru o bază
# bolnavă, iar Python le ridică tocmai pentru un defect de program. Limita ei se
# scrie aici, nu se presupune: un defect al nostru care iese ca `ValueError` — sau
# ca orice tip al driverului — rămâne clasificat „baza locală". Necunoscutul cade
# pe partea prudentă, adică pe cea care nu acuză codul nostru fără dovadă; efectul
# e că departajarea poate rata un defect al nostru, niciodată invers.
#
# Ce NU se schimbă în niciunul dintre cazuri, și de-aia ramura e reparație și nu
# mușamalizare: fluxul eșuează, intră singur în exponențială, iar restanța lui se
# vede în `ship:lag`. Se schimbă doar unde e trimis operatorul.
_OUR_DEFECT = (AttributeError, TypeError, KeyError, IndexError, NameError)


def _round_failed(streams: tuple[Stream, ...], reason: str) -> ShipResult:
    """Runda a căzut ÎNAINTE ca vreun flux să fi apucat să plece.

    Fără identitate: cauza e a rundei, nu a unui flux, deci fiecare flux cerut
    intră în exponențială. Scris o dată, nu la fiecare ramură, ca să nu rămână
    un flux fără verdict: un flux fără verdict e „nu știu", iar bucla îl
    tratează ca eșec și o spune în jurnal, ceea ce e corect dar e zgomot pe care
    nu-l vrem dintr-o scăpare de aici.

    O eroare de BAZĂ nu mai trece pe aici, și asta e reparația din 16 august
    2026: `try`-ul stătea în jurul întregii bucle de strângere, deci o derivă de
    schemă sau un timeout de instrucțiune pe `incidents` doborau și `audit_log`
    — chiar cuplajul pe care `collect_stream` există să-l scoată. Acum fiecare
    flux își are `try`-ul lui și cade singur.
    """
    return ShipResult(False, reason,
                      streams={s.name: StreamOutcome(False, reason=reason)
                               for s in streams})


async def ship_once(db: Database, cfg: Config, secret: str,
                    streams: tuple[Stream, ...] | None = None) -> ShipResult:
    """Un lot. Avansează cursoarele doar pentru fluxurile confirmate prin ecou.

    `streams` e ce se strânge runda ASTA, implicit tot `STREAMS`. Bucla nu dă
    întotdeauna tot: fiecare flux își are termenul lui (`ShipSchedule`), iar unul
    intrat în exponențială n-are ce căuta în lotul următor al celui sănătos —
    vezi „Un flux oprit nu are voie să încetinească fluxul sănătos" în capul
    modulului.

    Rezultatul poartă un verdict PER FLUX în `ShipResult.streams`, și fiecare
    ramură de mai jos îl scrie pentru fluxurile pe care le privește: unde cauza e
    a lotului (rețea, non-2xx, ecou lipsă, lot nesemnabil) cad toate fluxurile
    DIN lot, unde e a unui flux (ceas, trigger, rând necodificabil, eroare de
    bază, ecou parțial, cursor nemutat) cade numai el. Singura cauză care rămâne
    a RUNDEI e lipsa identității, fiindcă fără ea niciun flux nu poate pleca.

    Clasificarea asta e o taxonomie, nu o colecție de ramuri, iar de la 16 august
    2026 e păzită de DOUĂ gărzi în `tests/unit/test_shipper.py`, fiindcă una
    singură n-a ajuns. Amândouă pornesc din același tabel de cazuri; ce compară cu
    el e altceva la fiecare.

    **Prima gardă e pe LINIE și pe ACOPERIRE, și dovedește exact un lucru.**
    Mulțimea ieșirilor se derivă din codul ăsta — `return`-urile CU valoare și
    instrucțiunile care scriu în `outcomes` / `outcome`, din `ship_once`,
    `run_forever`, `_round_failed` și din funcțiile cuibărite în ele — iar cerința
    e ca fiecare INSTRUCȚIUNE din mulțime să fie executată de vreun rând al
    tabelului. Cum e construit verdictul înăuntru nu contează: prin
    `StreamOutcome(...)`, printr-un alias, sau refolosind `batch_failed`, un
    `return` nou e un sit nou. Forma dinaintea ei recunoștea ortografia
    `StreamOutcome(` și a fost evadată de două ori în aceeași zi, exact de idiomul
    casei și de un alias.

    Ce NU dovedește, și se scrie aici fiindcă propoziția asta a fost deja crezută
    mai mult decât face: nu spune nimic despre DECIZIILE dinăuntrul unei
    instrucțiuni. O ramură nouă pusă într-o instrucțiune pe care tabelul o execută
    deja e invizibilă pentru ea — oricum ar fi scrisă, oriunde ar fi definit ce
    cheamă. Două exemple din chiar fișierul ăsta: `isinstance(exc, _OUR_DEFECT)`
    de mai sus are ambele laturi ieșind prin aceeași scriere de verdict, deci prima
    gardă nu le poate departaja; iar `more=batch.full and len(advanced) < 2` pe
    linia care scrie verdictul unui flux confirmat trece pe lângă ea neatins, deși
    pune un flux cu restanță înapoi pe `interval_s` în loc de `DRAIN_PAUSE_S`.
    Amândouă se departajează dintr-un RÂND al tabelului, nu din citirea textului.

    **A doua gardă e pe SITUAȚII**, tocmai fiindcă predicatul pe sintaxă a fost
    evadat de trei ori, de fiecare dată mutând decizia undeva unde citirea
    fișierului nu mai răspunde. Ea cere ca tabelul să PRODUCĂ, măsurat, situațiile
    pe care expeditorul e judecat: două fluxuri care își avansează cursorul în
    aceeași rundă, două care drenează în aceeași rundă, un flux în lotul comun și
    unul în afara lui, o rundă cerută pentru un singur flux, și restul. Nici ea nu
    e completă — limita ei e măsurată, nu presupusă, și scrisă deasupra taxonomiei.
    """
    import httpx

    global _identity_failures, _canonical_failures

    selected = tuple(STREAMS if streams is None else streams)

    try:
        instance_id = read_instance_id()
    except IdentityError as exc:
        # Runda se ratează, bucla nu — exact ca la beacon. Aici miza e alta și e
        # mai mare: fără identitate, rândurile ar ajunge în istoria instanței
        # `default`, amestecate cu ale oricărei alte gazde care nu se poate citi
        # pe sine, iar `audit_log`-ul a două servere într-un singur lanț e un
        # lanț care arată rupt în permanență.
        _identity_failures += 1
        log.warning("shipper has no instance identity",
                    extra={"detail": str(exc)[:220],
                           "consecutive": _identity_failures})
        if _identity_failures in _PROBE_ALARM_AT:
            log.error(
                "shipper still has no instance identity",
                extra={"consecutive": _identity_failures,
                       "action": "./scripts/deploy.sh --host <gazdă> "
                                 "--user <utilizator> — creează identitatea "
                                 "lipsă. Dacă fișierul există dar nu e o "
                                 "identitate: od -c /etc/sentinel/instance_id, "
                                 "șterge-l, apoi rulează deploy-ul."})
        return _round_failed(selected, "fără identitate de instalare")
    if _identity_failures:
        log.info("shipper has an instance identity again",
                 extra={"after_failures": _identity_failures})
        _identity_failures = 0

    batches: list[Batch] = []
    unencodable: dict[str, str] = {}
    # Valoarea e textul GATA de citit al operatorului, cu tot cu cine e de vină —
    # „baza locală: …" sau „defect în expeditor: …". Prefixul se pune o dată,
    # acolo unde se știe tipul excepției, fiindcă altfel cele trei locuri care-l
    # citesc mai jos ar trebui să reconstruiască fiecare aceeași departajare.
    unreadable: dict[str, str] = {}
    for stream in selected:
        try:
            batches.append(await collect_stream(db, cfg, stream))
        except ShipStallError as exc:
            # Izolat pe flux: și un ceas sărit, și un trigger lipsă sunt
            # proprietăți ale unui singur flux, iar un flux pe `id` nu are de
            # ce să tacă din cauza lor.
            batches.append(Batch(stream=stream, rows=[], watermark=0,
                                 full=False, stall=str(exc)[:220]))
        except ShipEncodingError as exc:
            # Blocaj vizibil, nu sărire tăcută (vezi `ShipEncodingError`) —
            # și tot pe un singur flux, de când `STREAMS` are două.
            #
            # Prins AICI, nu în jurul buclei, fiindcă altfel un
            # `incidents.ai_verdict` cu un tip pe care `encode_value` nu-l
            # cunoaște ar opri și `audit_log`: adică singura copie a lanțului
            # de audit din afara gazdei ar tăcea din cauza altei tabele, iar
            # cauza s-ar căuta în alt flux decât efectul. E cerința scrisă în
            # capul lui `collect_stream` pentru ziua în care apare al doilea
            # flux; ziua aia e azi.
            #
            # NU intră în `stall`: acolo mesajul către operator numește
            # `timedatectl`, iar un rând necodificabil n-are nicio treabă cu
            # ceasul. Două cauze cu aceeași urmare pentru flux, dar cu
            # remedii diferite, nu au voie să iasă cu același text.
            log.error("shipper cannot encode a row",
                      extra={"stream": stream.name, "detail": str(exc)[:220],
                             "action": "Fluxul stă pe loc până când rândul se poate "
                                       "codifica. `ship:lag` raportează rămânerea în urmă."})
            unencodable[stream.name] = str(exc)[:120]
        except Exception as exc:  # noqa: BLE001 - orice altceva: baza SAU noi
            # PE FLUX, nu pe rundă. Cât timp `try`-ul înconjura toată bucla, o
            # derivă de schemă sau un timeout de instrucțiune pe `incidents`
            # întorcea `_round_failed(selected)`, adică punea în exponențială și
            # `audit_log` — care nici măcar nu fusese atins de eroare, fiindcă
            # se strânge înaintea lui. Măsurat: o rundă `audit_log` pierdută la
            # fiecare rundă a fluxului stricat. Contrazicea chiar capul lui
            # `collect_stream`: „fluxul stricat rămâne pe loc și restul pleacă".
            #
            # `str(exc)`, nu doar tipul: numele coloanei care lipsește e singura
            # informație din care se poate porni, iar `check_ship_lag` nu vede
            # excepția asta deloc — el are propriile interogări.
            #
            # Dar CINE e de vină se spune, fiindcă remediul e altul: la „baza
            # locală" operatorul se duce la Postgres, iar pentru un
            # `AttributeError` din `collect_stream` acolo nu e nimic de găsit — a
            # fost trimis să caute cauza noastră în casa altuia. Vezi `_OUR_DEFECT`
            # pentru cât de departe merge departajarea și unde se oprește.
            if isinstance(exc, _OUR_DEFECT):
                log.error(
                    "shipper has a defect in its own collection code",
                    extra={"stream": stream.name, "type": type(exc).__name__,
                           "detail": str(exc)[:220],
                           "action": "NU e baza de date, e un defect al "
                                     "expeditorului: journalctl -u sentinel-shipper "
                                     "-n 50. Fluxul stă pe loc până se repară "
                                     "codul; `ship:lag` raportează rămânerea în "
                                     "urmă între timp."})
                unreadable[stream.name] = (
                    f"defect în expeditor: {type(exc).__name__}: {str(exc)[:100]}")
            else:
                log.warning("shipper could not read the local database",
                            extra={"stream": stream.name, "detail": str(exc)[:220]})
                unreadable[stream.name] = f"baza locală: {str(exc)[:120]}"

    stalled = {b.stream.name: b.stall for b in batches if b.stall}
    for name, why in stalled.items():
        # ERROR, nu WARNING: efectul e pierdere definitivă de rânduri, nu o
        # întârziere. `action` numește comanda care arată ceasul, fiindcă simptomul
        # („nu mai pleacă nimic dintr-un flux") nu seamănă deloc cu cauza.
        log.error(
            "shipper stream cannot advance its time cursor",
            extra={"stream": name, "detail": why,
                   "action": "timedatectl status ; chronyc tracking — un ceas dat "
                             "înapoi oprește fluxul până când timpul real ajunge "
                             "din urmă filigranul, iar ce se schimbă între timp nu "
                             "se mai expediază niciodată. Filigranul NU se retrage "
                             "automat: ar retrimite la nesfârșit pe un ceas care "
                             "oscilează. Retragerea e o decizie de operator — "
                             "docs/OPERARE.md, „Expedierea s-a oprit din cauza "
                             "ceasului”."})

    # Verdictul de pornire al fiecărui flux CERUT rundei, nu al fiecărui lot
    # strâns: un flux oprit de `ShipEncodingError` nu lasă niciun lot în urmă,
    # iar lipsa lui de aici l-ar face să pară că nu i s-a cerut nimic — adică
    # exact „nu știu" citit ca „e bine". `True` e provizoriu: fluxurile care chiar
    # au rânduri își primesc verdictul după ecou, mai jos.
    outcomes: dict[str, StreamOutcome] = {}
    for stream in selected:
        if stream.name in unreadable:
            outcomes[stream.name] = StreamOutcome(
                False, reason=unreadable[stream.name])
        elif stream.name in unencodable:
            outcomes[stream.name] = StreamOutcome(
                False, reason=f"rând necodificabil: {unencodable[stream.name]}")
        elif stream.name in stalled:
            outcomes[stream.name] = StreamOutcome(False, reason=stalled[stream.name])
        else:
            outcomes[stream.name] = StreamOutcome(True)

    pending = [b for b in batches if b.rows]
    if not pending:
        if unreadable:
            # Fără etichetă comună înaintea listei, spre deosebire de cele două
            # ramuri de mai jos: aici cauzele pot fi două — baza, sau un defect al
            # nostru —, iar `unreadable` poartă deja pe fiecare flux pe a lui. O
            # etichetă pusă în față ar spune „baza locală" și peste un flux care
            # a căzut din codul nostru, adică exact contopirea de reparat.
            return ShipResult(False, "; ".join(
                f"{name}: {why}" for name, why in unreadable.items())[:200],
                streams=outcomes)
        if unencodable:
            return ShipResult(False, "rând necodificabil: " + "; ".join(
                f"{name}: {why}" for name, why in unencodable.items())[:200],
                streams=outcomes)
        if stalled:
            # Aici e toată regula: o rundă în care nu s-a expediat nimic fiindcă
            # nu se poate NU are voie să iasă la fel ca una în care nu s-a
            # expediat nimic fiindcă nu era nimic.
            return ShipResult(False, "cursor pe timp oprit: " + "; ".join(
                f"{name}: {why}" for name, why in stalled.items())[:200],
                streams=outcomes)
        # Nu se trimite un lot gol. Nu dovedește nimic despre legătură — asta e
        # treaba beaconului — și ar fi trafic la fiecare interval pe o gazdă
        # liniștită. „Curent" se citește oricum din cursor, nu din trafic.
        return ShipResult(True, "nimic de expediat", streams=outcomes)

    def batch_failed(why: str) -> dict[str, StreamOutcome]:
        """Verdictele per flux când a căzut LOTUL COMUN.

        Cad fluxurile care erau ÎN el, și numai ele. Unul care n-avea nimic de
        trimis nu e cu nimic mai rău fiindcă vecinul a fost refuzat, iar pus în
        exponențială din solidaritate ar fi chiar cuplajul de reparat: o gazdă
        liniștită pe `incidents` ar expedia `audit_log` din oră în oră fiindcă
        agregatorul a respins o dată un lot.
        """
        return {**outcomes,
                **{b.stream.name: StreamOutcome(False, reason=why) for b in pending}}

    # Cine e în lot și cu câte rânduri. Intră în jurnal la fiecare refuz al
    # lotului fiindcă acolo se uită operatorul după un `HTTP 413`, iar întrebarea
    # lui e „al cui rând l-a produs" — la care „expedierea a rămas în urmă" nu
    # răspunde. Fără linia asta, singurul flux numit ar fi cel cu cheia roșie, și
    # aia e cheia efectului, nu a cauzei.
    composition = ", ".join(f"{b.stream.name}×{len(b.rows)}" for b in pending)

    payload: dict[str, Any] = {
        "instance_id": instance_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        # Neatins, NU `int(...)`: o conversie tăcută aici ar repara exact ce
        # trebuie să refuze contractul din signing.py. `_coerce` din config.py
        # închide gaura la sursă (`300.0` devine `300`, `300.5` e refuzat la
        # pornire), deci ce trece pe aici e deja întreg — iar dacă vreodată nu
        # mai e, vrem să se vadă în jurnal cu numele câmpului, nu să se piardă.
        "max_age_s": cfg.ship.max_age_s,
        "cursors": {b.stream.name: b.watermark for b in pending},
        "rows": {b.stream.name: b.rows for b in pending},
    }

    # Reconcilierea călătorește CU lotul, nu pe un drum al ei. Fluxul care are
    # nevoie de ea își retrimite oricum toate rândurile la fiecare rulare a
    # autoverificării — `last_seen = now()` atinge fiecare rând, deci `updated_at`
    # se mișcă —, deci un lot există la fiecare câteva minute și lista are cu ce
    # merge. Un drum separat ar fi însemnat o a doua cale de trimitere, cu
    # propriile ei moduri de eșec, pentru un caz pe care primul îl acoperă.
    prune = await _prune_keys(db, [b.stream for b in pending])
    if prune:
        payload["prune"] = prune

    try:
        # Contractul se verifică ÎNAINTE de a consuma un număr de lot: o rundă
        # care n-a trimis nimic nu are voie să lase în urmă gaura pe care
        # celălalt capăt o citește ca lot pierdut.
        canonical(payload)
        payload["batch_seq"] = await _next_sequence(db)
        body = canonical(payload)
        signature = sign(payload, secret)
    except CanonicalError as exc:
        _canonical_failures += 1
        log.warning("shipper batch is not signable",
                    extra={"detail": str(exc)[:220],
                           "consecutive": _canonical_failures})
        if _canonical_failures in _PROBE_ALARM_AT:
            log.error(
                "shipper batch keeps failing the signing contract",
                extra={"consecutive": _canonical_failures,
                       "detail": str(exc)[:220],
                       "action": "Câmpul numit în `detail` iese din contractul din "
                                 "sentinel/report/signing.py. Fluxul stă pe loc "
                                 "până se repară — nu se sare peste rând."})
        unsignable = f"lot nesemnabil: {str(exc)[:120]}"
        return ShipResult(False, unsignable, streams=batch_failed(unsignable))
    if _canonical_failures:
        log.info("shipper batch is signable again",
                 extra={"after_failures": _canonical_failures})
        _canonical_failures = 0

    # Plicul, DUPĂ semnătură și peste octeții deja semnați.
    #
    # Ordinea nu e un detaliu: semnătura e peste forma canonică DINĂUNTRU, iar
    # plicul e transport. `sentinel/report/signing.py` și `aggregator/lib/verify.ts`
    # rămân gemeni identici la octet, fiindcă nici unul dintre ei nu vede plicul.
    # Cine ar muta `sign()` peste `envelope.wrap(...)` „ca să fie mai simplu" ar
    # rupe contractul ăla, iar simptomul ar fi 401 la fiecare lot — adică exact ce
    # arată o cheie greșită. Vezi capul lui `envelope.py` pentru pana care a cerut
    # plicul și pentru cât de puțin trebuie ca marginea să dea 403.
    try:
        packet = wrap(body)
    except EnvelopeError as exc:
        log.error("shipper batch could not be wrapped for transport",
                  extra={"detail": str(exc)[:220], "batch_seq": payload["batch_seq"],
                         "batch_streams": composition,
                         "action": "Lotul NU a plecat și cursorul NU a avansat. "
                                   "E un defect în sentinel/report/envelope.py, "
                                   "nu o problemă de rețea."})
        unwrappable = f"lot neîmpachetabil: {str(exc)[:120]}"
        return ShipResult(False, unwrappable, streams=batch_failed(unwrappable))

    # Raportul obținut, în jurnal, fiindcă altfel câștigul e o presupunere: pe
    # loturi de comenzi (`systemctl` și `sleep` de zeci de mii de ori) se măsoară
    # între 8× și 26×, iar dacă vreodată scade la 1× înseamnă că altceva s-a
    # schimbat în conținut. E o linie pe LOT EXPEDIAT — câteva pe oră pe o gazdă
    # liniștită, una pe secundă cât ține o drenare.
    log.info("shipper batch wrapped for transport",
             extra={"batch_seq": payload["batch_seq"], "batch_streams": composition,
                    "signed_bytes": packet.inner_bytes, "wire_bytes": len(packet.wire),
                    "padding_bytes": packet.padding_bytes,
                    "ratio": round(packet.ratio, 1)})

    headers = {
        SIGNATURE_HEADER: signature,
        # Antetele rămân ÎN AFARA plicului. `X-Sentinel-Instance` e citit ca să
        # se găsească cheia, adică înaintea oricărei verificări; pus înăuntru,
        # receptorul ar trebui să desfacă plicul ca să afle cu ce cheie să
        # verifice ce a desfăcut.
        #
        # Din payload, nu dintr-o a doua citire a fișierului: receptorul cere
        # `payload.instance_id == antet` și refuză cu 401 dacă diferă.
        INSTANCE_HEADER: payload["instance_id"],
        # Plicul E tot JSON, deci tipul nu se schimbă. Un tip binar ar fi altă
        # cerere pentru marginea găzduirii, iar tabelul de măsurători din
        # `envelope.py` nu conține niciun rând despre ea.
        "Content-Type": "application/json",
        # Un lot pus în cache ar face agregatorul să vadă la nesfârșit ultimul
        # răspuns bun — adică un ecou vechi peste un filigran nou.
        "Cache-Control": "no-store",
    }
    try:
        async with httpx.AsyncClient(timeout=cfg.ship.timeout_s) as client:
            response = await client.post(cfg.ship.url, content=packet.wire,
                                         headers=headers)
    except Exception as exc:  # noqa: BLE001 - orice problemă de rețea, aceeași reacție
        log.warning("aggregator unreachable",
                    extra={"detail": str(exc)[:200], "batch_seq": payload["batch_seq"],
                           "batch_streams": composition})
        unreachable = f"agregator inaccesibil: {str(exc)[:120]}"
        return ShipResult(False, unreachable, streams=batch_failed(unreachable))

    if response.status_code // 100 != 2:
        # `batch_streams` e ce lipsea când operatorul a fost trimis să caute „un
        # rând de audit uriaș" pentru un 413 produs de rândurile altui flux.
        log.warning("aggregator rejected the batch",
                    extra={"status": response.status_code, "body": response.text[:200],
                           "batch_seq": payload["batch_seq"],
                           "batch_streams": composition})
        rejected = f"HTTP {response.status_code} pe lotul comun ({composition})"
        return ShipResult(False, rejected, streams=batch_failed(rejected))

    confirmed, problem = accepted_watermarks(response.text, payload["cursors"])
    if not confirmed:
        # 200 fără ecou. Cazul pentru care există toată regula, și singurul în
        # care un expeditor naiv ar fi raportat succes și ar fi pierdut rândurile.
        log.error("aggregator answered 200 without echoing the watermark",
                  extra={"detail": problem, "batch_seq": payload["batch_seq"],
                         "sent": payload["cursors"], "body": response.text[:200],
                         "batch_streams": composition,
                         "action": "Cursorul NU a avansat, deci rândurile se "
                                   "retrimit. Verifică dacă ship.url ajunge la "
                                   "agregator și nu la un CDN sau la alt vhost."})
        no_echo = f"200 fără ecou: {problem}"
        return ShipResult(False, no_echo, streams=batch_failed(no_echo))

    advanced: dict[str, int] = {}
    for batch in pending:
        watermark = confirmed.get(batch.stream.name)
        if watermark is None:
            # Acceptare parțială: fluxul ăsta nu a fost confirmat, restul da.
            # Numai el intră în exponențială — un flux necunoscut receptorului nu
            # e un motiv ca cel cunoscut să încetinească.
            outcomes[batch.stream.name] = StreamOutcome(
                False, reason=f"neconfirmat de agregator: {problem[:140]}")
            continue
        # Se mută `position`, nu `watermark`. Pe un flux append-only sunt același
        # număr; pe unul mutabil, `watermark` e cel mai mare `id` din lot (ce cere
        # receptorul) iar `position` e perechea ultimului rând în ordinea
        # expedierii. Mutat cursorul pe `watermark`, s-ar sări peste rândurile
        # dintre ultimul expediat și `id`-ul ăla.
        if batch.stream.cursor_kind == ROLLUP:
            written: Any = await _advance_rollup(
                db, batch.stream, batch.position, len(batch.rows))
            asked: Any = tuple(batch.position)
        elif batch.stream.cursor_kind == MUTABLE:
            # Memo-ul ÎNAINTE de mutare: vezi `_remember_window` pentru de ce
            # ordinea asta și nu cealaltă.
            await _remember_window(db, batch.stream, batch.from_position,
                                   len(batch.rows))
            written = await _advance_mutable(
                db, batch.stream, batch.position, len(batch.rows))
            asked = tuple(batch.position)
        else:
            written = await _advance(db, batch.stream, batch.position, len(batch.rows))
            asked = batch.position
        if written != asked:
            # Efectul, nu intenția: dacă baza n-a scris ce am cerut, spunem asta
            # în loc să raportăm o avansare care nu s-a întâmplat.
            log.warning("cursor did not move where it was told",
                        extra={"stream": batch.stream.name, "asked": str(asked),
                               "stored": str(written)})
            outcomes[batch.stream.name] = StreamOutcome(
                False, reason=f"cursorul nu s-a mutat unde i s-a spus "
                              f"(cerut {asked}, scris {written})"[:200])
            continue
        advanced[batch.stream.name] = watermark
        # `more` per flux, nu pe rundă: cel care mai are de drenat revine peste
        # `DRAIN_PAUSE_S`, cel liniștit peste `interval_s`, și niciunul nu-l
        # așteaptă pe celălalt.
        outcomes[batch.stream.name] = StreamOutcome(True, more=batch.full)

    if problem:
        # `body` e obligatoriu aici, nu decorativ. `detail` spune doar CE flux nu
        # a fost confirmat — „detections: lipsește din `accepted`" —, adică fix
        # ce se putea deduce și fără el. DE CE stă pe loc știe numai agregatorul,
        # iar singurul loc în care o spune e corpul răspunsului („fluxul nu e
        # cunoscut, are nevoie de o migrație a agregatorului"). Fără linia asta,
        # explicația aia nu ajunge nicăieri: celelalte două ramuri care scriu
        # corpul sunt non-2xx și `if not confirmed`, iar o acceptare PARȚIALĂ nu
        # e niciuna dintre ele. Operatorul ar afla care flux tace, niciodată de ce.
        log.warning("some streams were not confirmed",
                    extra={"detail": problem, "advanced": advanced,
                           "batch_streams": composition,
                           "body": response.text[:200]})
    more = any(b.full for b in pending if b.stream.name in advanced)
    # Un flux oprit — de ceas, de trigger, sau de un rând pe care nu-l poate
    # codifica — ține RUNDA pe `False` chiar dacă restul a plecat, fiindcă runda
    # chiar n-a fost curată și asta se citește în jurnal. Ce NU se mai construiește
    # din valoarea asta e programul de reîncercare: bucla îl ia din
    # `ShipResult.streams`, unde fiecare flux răspunde numai pentru el.
    reason = "; ".join(p for p in (
        problem,
        "; ".join(f"{name}: {why}" for name, why in stalled.items()),
        "; ".join(f"{name}: rând necodificabil: {why}"
                  for name, why in unencodable.items()),
        "; ".join(f"{name}: {why}" for name, why in unreadable.items()),
    ) if p)[:200]
    return ShipResult(
        bool(advanced) and not problem and not stalled and not unencodable
        and not unreadable,
        reason, advanced, more, outcomes)


# ---------------------------------------------------------------------------
# Programul: exponențial, cu jitter, plafonat — și calculabil dintr-o funcție
# ---------------------------------------------------------------------------
def next_delay(consecutive_failures: int, ship: Any,
               rand: Any = random.random) -> float:
    """Câte secunde până la runda următoare.

    Funcție pură, cu sursa de aleator ca argument. Un `random()` chemat direct
    din buclă face programul de reîncercare imposibil de afirmat într-un test —
    și atunci singurul lucru testat despre backoff e că există.

    Jitterul taie doar în jos (vezi `JITTER_RATIO`), deci `backoff_max_s` rămâne
    un plafon adevărat, nu o medie.
    """
    if consecutive_failures <= 0:
        return float(ship.interval_s)
    # Exponentul se mărginește înainte de ridicarea la putere: `2 ** 100000` e o
    # ridicare la putere pe întregi mari calculată degeaba, la fiecare rundă, pe
    # o gazdă care e deja în pană.
    exponent = min(consecutive_failures - 1, 32)
    step = min(float(ship.backoff_base_s) * (2 ** exponent), float(ship.backoff_max_s))
    return step * (1.0 - JITTER_RATIO * rand())


class ShipSchedule:
    """Termenul următor al FIECĂRUI flux, ținut separat.

    Eșecul pentru care există e scris pe larg în capul modulului („Un flux oprit
    nu are voie să încetinească fluxul sănătos"): cât timp bucla număra eșecurile
    pe rundă, un `incidents` blocat pe un rând necodificabil ducea `audit_log` de
    la o rundă pe minut la una pe `backoff_max_s`, iar cheia roșie apărea pe
    `audit_log` cu remedii care n-aveau legătură cu cauza.

    Ce ține: câte eșecuri LA RÂND are fiecare flux, și când îi vine rândul. Un
    flux pe care nu-l cunoaște e scadent imediat — un flux nou-înregistrat nu
    așteaptă un termen pe care nu i l-a pus nimeni, iar `STREAMS` se citește la
    fiecare rundă, deci lista chiar poate crește sub el.

    Ceasul vine ca argument, ca `rand` la `next_delay` și din același motiv: un
    `monotonic()` chemat înăuntru face programul imposibil de afirmat într-un
    test, iar atunci singurul lucru probat despre el e că există. Din același
    motiv nu ține timp „relativ" scăzând pauzele dormite: o rundă cu un
    `ship.timeout_s` întreg în ea ar întinde tăcut cadența tuturor celorlalte
    fluxuri, iar diferența nu s-ar vedea nicăieri.
    """

    def __init__(self) -> None:
        self._failures: dict[str, int] = {}
        self._due_at: dict[str, float] = {}

    def failures(self, name: str) -> int:
        return self._failures.get(name, 0)

    def due(self, streams: tuple[Stream, ...], now: float) -> tuple[Stream, ...]:
        """Fluxurile al căror termen a venit, în ordinea din `STREAMS`."""
        return tuple(s for s in streams if self._due_at.get(s.name, now) <= now)

    def record(self, name: str, outcome: StreamOutcome, ship: Any, now: float,
               rand: Any = random.random) -> float:
        """Așază termenul următor al unui flux din verdictul lui. Întoarce pauza.

        Trei cadențe, și niciuna împrumutată de la alt flux: `DRAIN_PAUSE_S` cât
        mai are de drenat, `interval_s` în regim staționar, exponențiala lui
        `next_delay` cât e oprit.
        """
        if outcome.ok:
            self._failures[name] = 0
            delay = DRAIN_PAUSE_S if outcome.more else float(ship.interval_s)
        else:
            self._failures[name] = self._failures.get(name, 0) + 1
            delay = next_delay(self._failures[name], ship, rand)
        self._due_at[name] = now + delay
        return delay

    def sleep_for(self, streams: tuple[Stream, ...], now: float, ship: Any) -> float:
        """Până la cel mai apropiat termen — nu până la cel mai îndepărtat.

        Un `max` aici ar face ca fluxul sănătos să aștepte exponențiala celui
        oprit, adică exact defectul reparat, mutat cu un nivel mai jos.
        """
        deadlines = [self._due_at[s.name] for s in streams if s.name in self._due_at]
        if not deadlines:
            # Niciun termen scris încă. Nu e „acum" — un zero aici ar fi o buclă
            # strânsă peste o listă de fluxuri goală.
            return float(ship.interval_s)
        return max(0.0, min(deadlines) - now)


async def run_forever(db: Database, cfg: Config) -> None:
    secret = get_secrets().get(SECRET_NAME) or ""
    # `or`, nu `and`. Cu `and`, un `enabled: false` peste un `url` și o cheie
    # rămase în fișier de la o probă ar porni bucla: expedierea „oprită în
    # configurație" ar trimite rânduri, iar `check_ship_lag` ar raporta liniștit
    # „oprită" fiindcă tot pe `enabled` se uită. Cele trei condiții sunt
    # alternative, nu cumulative — oricare lipsește, nu se poate expedia onest.
    if not cfg.ship.enabled or not cfg.ship.url or not secret:
        # O dată, limpede, apoi liniște — ca la beacon. Serviciul iese cu 0, iar
        # unitatea are `Restart=on-failure` tocmai ca ieșirea asta să nu devină
        # o buclă de reporniri.
        log.info("shipper disabled",
                 extra={"enabled": cfg.ship.enabled,
                        "has_url": bool(cfg.ship.url),
                        "has_secret": bool(secret)})
        return

    log.info("shipper started",
             extra={"interval_s": cfg.ship.interval_s,
                    "streams": [s.name for s in STREAMS],
                    "max_rows_per_batch": cfg.ship.max_rows_per_batch})
    schedule = ShipSchedule()
    while True:
        # Citit la fiecare rundă, nu legat o dată: `STREAMS` e ce expediază
        # instalarea asta, iar un implicit legat la pornire ar fi înghețat lista.
        streams = STREAMS
        due = schedule.due(streams, monotonic())
        if due:
            result = await ship_once(db, cfg, secret, due)
            # Ceasul se recitește DUPĂ rundă: termenul următor al unui flux se
            # măsoară de la sfârșitul lucrului, nu de la începutul lui, altfel un
            # `ship.timeout_s` întreg s-ar scădea tăcut din fiecare pauză.
            now = monotonic()
            for stream in due:
                outcome = result.streams.get(stream.name)
                if outcome is None:
                    # „Nu știu" nu e „a plecat". Tratat ca succes, un flux despre
                    # care runda n-a spus nimic ar reveni la `interval_s` la
                    # nesfârșit, fără nicio urmă.
                    outcome = StreamOutcome(
                        False, reason="runda nu a raportat niciun verdict pentru "
                                      "fluxul ăsta")
                    log.error(
                        "shipper round returned no verdict for a stream",
                        extra={"stream": stream.name, "detail": result.reason,
                               "action": "E un defect în ship_once: o ramură care "
                                         "iese fără să scrie `streams`. Fluxul e "
                                         "tratat ca eșuat, deci intră în backoff "
                                         "în loc să pară la zi."})
                before = schedule.failures(stream.name)
                schedule.record(stream.name, outcome, cfg.ship, now)
                # Doar în jurnal, ca înainte. Alerta către operator e a
                # autodiagnosticului (`ship:lag`), fiindcă acolo se vede EFECTUL —
                # cât a rămas în urmă — nu doar că o cerere a eșuat. Ce s-a
                # schimbat e că linia NUMEȘTE fluxul: cu un contor global,
                # operatorul afla că „expedierea" eșuează, nu care parte din ea.
                if outcome.ok:
                    if before:
                        log.info("shipper stream is delivering again",
                                 extra={"stream": stream.name,
                                        "after_failures": before})
                elif schedule.failures(stream.name) in _PROBE_ALARM_AT:
                    log.error("shipper stream has been failing",
                              extra={"stream": stream.name,
                                     "consecutive": schedule.failures(stream.name),
                                     "detail": outcome.reason})
        await asyncio.sleep(schedule.sleep_for(streams, monotonic(), cfg.ship))


# ---------------------------------------------------------------------------
# Ce vede autodiagnosticul
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StreamLag:
    """Cât a rămas în urmă un flux.

    `cursor is None` înseamnă că expeditorul n-a scris NICIODATĂ un cursor pe
    gazda asta, ceea ce nu e nici „la zi", nici „în urmă": e „nu a rulat". Cele
    trei nu au voie să arate la fel.

    `clock_ahead_s is None` înseamnă că fluxul NU merge pe timp, deci întrebarea
    despre ceas nu i se pune. Nu e „ceasul e bun": pe un flux mutabil valoarea e
    întotdeauna un număr, iar dacă nu s-a putut măsura, `lag` ridică în loc să
    întoarcă `None` — un „nu știu" citit ca „nu se aplică" ar ascunde chiar
    oprirea pe care măsurătoarea o caută.
    """

    stream: str
    cursor: int | None
    floor: int | None
    pending: int
    oldest_pending_min: float | None
    clock_ahead_s: float | None = None
    cursor_at: datetime | None = None
    floor_at: datetime | None = None
    # `None` = fluxul nu are nevoie de trigger (cursor pe `id`). `False` e o
    # constatare, nu o absență: coloana nu se mai mișcă, deci fluxul e mort și
    # arată la zi.
    updated_at_trigger: bool | None = None
    # Cumulat, de la instalare. Rândurile astea nu mai pleacă niciodată.
    lost_below_cursor: int = 0
    # Gol = s-a putut măsura. Orice altceva e motivul pentru care fluxul ĂSTA nu
    # s-a putut citi, și atunci restul câmpurilor nu spun nimic: nu sunt „zero",
    # sunt neîntrebate. Vezi `lag` pentru de ce e un câmp și nu o excepție.
    error: str = ""


async def lag(db: Database,
              streams: tuple[Stream, ...] | None = None) -> list[StreamLag]:
    """Restanța fiecărui flux, citită din bază. Un flux ilizibil o spune, în el.

    Numele cursoarelor vin din `STREAMS`, nu scrise a doua oară în
    `selfcheck/checks.py`: o verificare care întreabă de un cursor pe care nu-l
    scrie nimeni raportează „la zi" pentru totdeauna.

    `None`, nu `STREAMS` ca implicit: un implicit se leagă o singură dată, la
    definirea funcției, deci ar fi înghețat lista de fluxuri de la import și
    verificarea s-ar fi uitat la altceva decât expediază expeditorul.

    **Fiecare flux se măsoară în `try`-ul lui**, și asta e reparația din 16
    august 2026. Cât timp o excepție urca din funcția asta, `check_ship_lag` o
    prindea și întorcea O SINGURĂ cheie, `ship:lag | unknown`. Iar runner-ul
    șterge ce o rulare completă n-a emis, deci `ship:lag:audit_log` dispărea din
    panou. Măsurat pe gazda de producție (schema_version=22, migrația 0023
    neaplicată): `collector_cursors` n-are `cursor_at`, interogarea fluxului
    mutabil ridică, iar fluxul append-only — care n-are nevoie nici de trigger,
    nici de `cursor_at` — devenea invizibil fiindcă vecinul lui nu s-a putut
    citi. O gardă care ascunde altă gardă.

    Nu se întoarce o restanță plauzibilă și nu se sare peste flux: fluxul rămâne
    în listă, cu `error` scris, iar `check_ship_lag` îl arată ca `unknown`. „Nu
    știu" și „e bine" nu au voie să arate la fel, dar nici „nu știu" și „nu
    există".
    """
    out: list[StreamLag] = []
    for stream in (STREAMS if streams is None else streams):
        try:
            out.append(await _stream_lag(db, stream))
        except Exception as exc:  # noqa: BLE001 - un flux ilizibil e o stare, nu o pană
            out.append(StreamLag(stream.name, None, None, 0, None,
                                 error=str(exc)[:140]))
    return out


async def _stream_lag(db: Database, stream: Stream) -> StreamLag:
    """Restanța unui SINGUR flux. Ridică dacă nu se poate citi — vezi `lag`."""
    if stream.cursor_kind == ROLLUP:
        return await _rollup_lag(db, stream)
    if stream.cursor_kind == MUTABLE:
        return await _mutable_lag(db, stream)
    cursor = await db.fetchval(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    floor = await db.fetchval(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = $1",
        stream.floor_name)
    if cursor is None:
        return StreamLag(stream.name, None, None, 0, None)
    row = await db.fetchrow(
        f"SELECT count(*) AS pending, "  # noqa: S608 - identificatori din STREAMS
        f"EXTRACT(EPOCH FROM (now() - min({stream.time_column})))/60 AS oldest_min "
        f"FROM {stream.table} WHERE id > $1",
        int(cursor))
    oldest = row["oldest_min"] if row else None
    return StreamLag(
        stream=stream.name,
        cursor=int(cursor),
        floor=int(floor) if floor is not None else None,
        pending=int(row["pending"]) if row else 0,
        oldest_pending_min=float(oldest) if oldest is not None else None)


async def _rollup_lag(db: Database, stream: Stream) -> StreamLag:
    """Restanța unui flux de agregate: câte intervale ÎNCHEIATE n-au plecat.

    Numărate cu aceeași clauză cu care sunt și expediate. O restanță măsurată
    peste intervalul în curs ar arăta permanent unu, iar `check_ship_lag` ar
    ține o alarmă aprinsă pe purtarea corectă a mecanismului — adică operatorul
    ar învăța s-o ignore, și atunci n-ar mai vedea nici restanța adevărată.
    """
    # O singură coloană, deci `fetchval` — și asta nu e o preferință de stil.
    # Citit cu `fetchrow`, un flux al cărui rând nu se poate citi deloc ar ieși
    # de aici cu „n-a plecat niciodată": o stare REALĂ, plauzibilă, și greșită.
    # `check_ship_lag` ar scrie-o ca verdict, iar `_reconcile_state` ar șterge
    # restanța adevărată — adică operatorul ar vedea o revenire care nu s-a
    # întâmplat. Excepția care iese de aici devine `unknown`, care e răspunsul
    # corect la o întrebare fără răspuns.
    cursor_at = await db.fetchval(
        "SELECT cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if cursor_at is None:
        return StreamLag(stream.name, None, None, 0, None,
                         updated_at_trigger=False)
    cursor_key = str(await db.fetchval(
        "SELECT cursor FROM collector_cursors WHERE name = $1",
        stream.cursor_name) or "")
    counted = await db.fetchrow(
        f"SELECT count(*) AS pending, "  # noqa: S608 - identificatori din STREAMS
        # Vechimea se numara de la momentul in care randul a devenit
        # EXPEDIABIL — sfarsitul intervalului lui —, nu de la eticheta. Eticheta
        # e inceputul, deci masurata de acolo, restanta unui contor orar porneste
        # de la 60 de minute in clipa in care apare, si trece de orice ragaj
        # rezonabil inainte sa fi trecut o secunda.
        f"EXTRACT(EPOCH FROM (now() - (min({stream.key_column})"
        f" + interval '1 {stream.rollup_unit}')))/60 AS oldest_min "
        f"FROM {stream.table} "
        f"WHERE ({stream.time_column}, {stream.key_column}) > "
        f"($1::timestamptz, $2::text::timestamptz) "
        f"AND {stream.key_column} < date_trunc('{stream.rollup_unit}', now())",
        cursor_at, cursor_key)
    oldest = counted["oldest_min"] if counted else None
    return StreamLag(
        stream=stream.name,
        cursor=cursor_at.isoformat(),
        floor=None,
        pending=int(counted["pending"]) if counted else 0,
        oldest_pending_min=float(oldest) if oldest is not None else None,
        clock_ahead_s=await clock_ahead_s(db, cursor_at),
        cursor_at=cursor_at,
        # SE SPRIJINĂ pe trigger, de la 0025. Comentariul de aici spunea până în
        # 24 august că nu — „cheia lui e momentul intervalului, scris o dată de
        # mentenanță" — și pe presupunerea aia s-a pierdut de zece ori mai multe
        # evenimente decât se vedeau în panou. Se sondează, nu se afirmă.
        updated_at_trigger=await updated_at_trigger_installed(db, stream))


async def _mutable_lag(db: Database, stream: Stream) -> StreamLag:
    """Restanța și starea ceasului pentru un flux pe `(updated_at, cheie)`.

    Măsurarea ceasului se face AICI, nu doar în expeditor, fiindcă expeditorul nu
    are cale proprie către operator — capul modulului spune de ce. Fără ea,
    fluxul oprit de ceas apare cu `pending = 0`, adică exact ca unul la zi: sub
    filigranul rămas în viitor nu mai intră nimic în numărătoare.
    """
    # Prima întrebare, și înaintea cursorului: fără trigger nu se mișcă nimic,
    # deci restanța ar fi zero și fluxul ar apărea la zi pe vecie. Expeditorul se
    # oprește pe aceeași constatare — dar el n-are cale către operator, iar dacă
    # verificarea nu întreabă și ea, singurul semn ar fi o unitate care rulează
    # și nu trimite.
    has_trigger = await updated_at_trigger_installed(db, stream)
    if not has_trigger:
        # Se OPREȘTE pe constatarea asta, nu doar o notează. Ce urmează are sens
        # numai pe un flux al cărui filigran chiar se mișcă: fără trigger,
        # `cursor_at`, restanța și starea ceasului sunt măsurători peste ceva
        # oprit, iar pe o gazdă unde 0023 n-a ajuns nici nu se pot face —
        # `collector_cursors` n-are coloana `cursor_at`, deci interogarea
        # următoare ridică. Atunci fluxul ăsta ieșea `unknown` cu „column
        # cursor_at does not exist", adică simptomul migrației lipsă în locul
        # cauzei ei, iar operatorul primea „sentinel migrate ; journalctl" în loc
        # de remediul care numește triggerul.
        #
        # Ce NU se întoarce de aici: un cursor. Câmpurile rămân cele de
        # „neîntrebat", fiindcă un `cursor=None` care ar însemna „expeditorul
        # n-a scris niciodată nimic" ar fi tocmai un „nu știu" citit ca stare.
        # `check_ship_lag` judecă triggerul PRIMUL și iese pe el, deci nu citește
        # niciunul dintre ele.
        return StreamLag(stream.name, None, None, 0, None,
                         updated_at_trigger=False)

    row = await db.fetchrow(
        "SELECT cursor, cursor_at FROM collector_cursors WHERE name = $1",
        stream.cursor_name)
    if row is None:
        return StreamLag(stream.name, None, None, 0, None,
                         updated_at_trigger=has_trigger)
    if row["cursor_at"] is None:
        # Ridică, nu întoarce o restanță plauzibilă: `check_ship_lag` traduce
        # excepția în `unknown`, iar „nu pot spune" e starea corectă pentru un
        # filigran pe jumătate scris.
        raise ShipClockError(
            f"cursorul {stream.cursor_name} nu are cursor_at, deci restanța "
            f"fluxului mutabil nu se poate calcula")

    cursor_at = row["cursor_at"]
    cursor_key = _cursor_key(stream, row["cursor"])
    ahead = await clock_ahead_s(db, cursor_at)
    floor_at = await db.fetchval(
        "SELECT cursor_at FROM collector_cursors WHERE name = $1", stream.floor_name)

    counted = await db.fetchrow(
        f"SELECT count(*) AS pending, "  # noqa: S608 - identificatori din STREAMS
        f"EXTRACT(EPOCH FROM (now() - min({stream.time_column})))/60 AS oldest_min "
        f"FROM {stream.table} "
        f"WHERE ({stream.time_column}, {stream.key_column}) > "
        f"($1::timestamptz, $2::{stream.key_sql_type})",
        cursor_at, cursor_key)
    oldest = counted["oldest_min"] if counted else None
    lost = await db.fetchval(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = $1",
        stream.lost_name)
    return StreamLag(
        stream=stream.name,
        cursor=cursor_key,
        floor=None,
        pending=int(counted["pending"]) if counted else 0,
        oldest_pending_min=float(oldest) if oldest is not None else None,
        clock_ahead_s=ahead,
        cursor_at=cursor_at,
        floor_at=floor_at,
        updated_at_trigger=has_trigger,
        lost_below_cursor=int(lost or 0))
