"""Semnalul periodic către un martor din afara gazdei.

Un agent de securitate găzduit nu poate garanta că raportează propria
dispariție: cine îl oprește controlează și canalul prin care ar fi anunțat.
Toate alertele Sentinel pleacă de pe serverul monitorizat, deci `systemctl stop`
pe serviciile potrivite produce tăcere completă și nicio urmă în afara gazdei.

Modulul ăsta e jumătatea de pe server a reparației. Trimite periodic un semnal
unui martor extern; **absența semnalului devine alarma**, iar decizia de a suna
stă pe o mașină pe care atacatorul nu o controlează.

## De ce nu un simplu „sunt viu"

Un ping fără conținut e falsificabil de orice linie de cron, inclusiv a
atacatorului, și e minciuna cea mai comodă: procesul răspunde, deci pare că
merge. Semnalul poartă **cifre care trebuie să crească** — ultimul eveniment
ingerat, cât a consumat detecția, verdictul autodiagnosticului. Un martor care
primește semnale cu contoare înțepenite știe că procesul trăiește și conducta e
moartă, ceea ce e un mod real de a cădea și e complet invizibil altfel.

## Ce nu poate face

Cheia de semnare stă pe mașina monitorizată. Un atacator cu root o citește și
poate fabrica semnale cu cifre care cresc. `audit_head` ridică bariera — capul
lanțului de hash-uri din jurnalul de audit trebuie menținut consistent, nu doar
incrementat — dar nu o face absolută.

Cu o precizare care contează, fiindcă altfel bariera pare mai înaltă decât e:
martorul doar compară capul primit cu cel dinainte („s-a mișcat ceva"). Nu
verifică înlănțuirea și nici nu poate, din ce primește azi — pentru asta i-ar
trebui în semnal și `prev_hash`-ul, și `id`-ul capului, plus codul care le
compară la celălalt capăt. Și fiindcă acolo „capul s-a schimbat" înseamnă
„contoarele s-au mișcat", o intrare de audit scrisă în timpul unei pene de
ingestie amână alarma de conductă moartă cu până la 15 minute — vezi §3.2 din
docs/PLAN-arhitectura-distribuita.md.

Prinde sigur: serviciu oprit, proces căzut, OOM, disc plin, gazdă repornită,
rețea tăiată, ingestie blocată cu procesul viu, atacator care oprește Sentinel
fără să se gândească la consecințe. Nu prinde sigur un atacator informat și
răbdător. Nimic găzduit nu poate.

## Serviciu propriu, nu inclus în altul

Ca să raporteze DESPRE celelalte servicii în loc să moară ÎMPREUNĂ cu ele.
Ambele moduri de eșec ajung astfel la martor: dacă expeditorul cade, semnalul
dispare; dacă altceva cade, semnalul sosește cu contoare care nu mai avansează.

## Cine trimite: identitatea de instalare

Semnalul poartă `instance_id`, iar antetul `X-Sentinel-Instance` poartă exact
aceeași valoare. Martorul verifică trei lucruri, în ordinea asta: găsește cheia
după antet, verifică HMAC-ul peste octeții bruți, apoi cere
`payload.instance_id == antet` (`aggregator/app/api/sentinel/beat/route.ts`). Al
treilea pas e cel care face ca deținătorul cheii lui A să nu poată raporta în
numele lui B, deci valoarea se ia O SINGURĂ dată, din `payload`, și se pune și
în antet de acolo — nu se citește de două ori, ca să nu poată devia una de
cealaltă.

`instance_label` vine din `sentinel.yaml`, e cosmetic și nu e niciodată cheie:
martorul îl folosește doar ca să scrie „eticheta (id)" într-un mesaj, și cade
înapoi pe id când e gol. Se trimite mereu, inclusiv gol — un semnal a cărui
FORMĂ depinde de configurație e un semnal cu două forme canonice, iar forma
canonică e chiar lucrul peste care se semnează.

## Ce face când NU-și poate citi identitatea

Valoarea vine dintr-un singur loc, `/etc/sentinel/instance_id`, și nu are
valoare de rezervă — `sentinel/identity.py` ridică `IdentityError` tocmai ca să
nu existe una. Aici asta trebuie tradus într-o purtare, iar ambele variante
evidente sunt greșite:

* **A trimite fără identitate** nu e o omisiune, e o afirmație. Martorul pune
  semnalul în găleata `default`, împreună cu orice altă gazdă care nu se poate
  citi pe sine: două servere, o singură istorie, amândouă verzi. E exact eșecul
  pentru care există identitatea, doar că deghizat în succes.
* **A tăcea de tot, ca serviciu oprit** — adică a ieși din buclă — l-ar face pe
  martor să vadă o gazdă moartă și să sune o alarmă critică despre un server
  care funcționează. O alarmă care se aprinde pentru o problemă de configurare e
  felul în care operatorul învață să nu mai citească singurul canal care nu are
  voie să fie ignorat.

A treia variantă, și cea implementată: **runda se ratează, bucla nu.** Semnalul
nu pleacă — nu există nume sub care ar putea pleca onest — dar procesul rămâne
în picioare, la aceeași cadență, recitind fișierul la fiecare rundă; în clipa în
care identitatea apare, semnalul reîncepe fără repornire. Runda ratată se
raportează ca eșec de transmisie (`send_once` întoarce `False`) și urcă pe
aceeași scară 3/30/300 ca restul, cu propriul mesaj și cu comanda de reparare în
el. Nu se consumă nici măcar un număr de secvență: o rundă care n-a trimis nimic
nu are voie să lase urme care să arate ca o rundă care a trimis.

**De ce asta NU produce alarma falsă de mai sus.** Martorul alarmează despre o
instanță doar dacă instanța aia a primit vreodată un semnal: `judge()` întoarce
„în regulă" când nu există `last`, iar `/check` o raportează ca `no-beat` —
vizibilă, NEcontabilizată la „ok", și niciodată alertată. O gazdă care nu-și
poate citi identitatea n-a trimis niciodată sub identitatea aia, deci acolo
ajunge: în singura stare pe care martorul o are pentru „configurată, încă n-a
vorbit". Asta e și descrierea onestă a situației.

Rămâne o singură găleată în care se poate ajunge la „a bătut, apoi a tăcut":
`default`, toleranța pentru expeditorul care e în producție de dinaintea
identității. Fereastra aia se închide MECANIC, nu prin documentație: `install.sh`
apelează `ensure_instance_id` necondiționat, în afara marcajelor de pas, deci
orice deploy care aduce codul ăsta aduce și fișierul; iar dacă tot nu poate,
refuză să repornească beaconul, ca procesul vechi să continue să bată în loc să
amuțească cel nou. Prima variantă a schimbării ăsteia lăsa fereastra deschisă și
o explica în `docs/DEPLOYMENT.md` — pe gazda de producție asta însemna alarmă
critică la 3–8 minute după deploy, repetată la 4 ore, despre un server sănătos.
O gazdă nu citește documentație.

Ce rămâne de făcut cu mâna e la CELĂLALT capăt și e scris în `docs/DEPLOYMENT.md`
§7: cheia noii instanțe pusă la martor, apoi `default` retras — retragerea cere
ștergerea fișierului lui de stare, fiindcă martorul consideră membră orice
instanță al cărei fișier se identifică singur, indiferent de chei.

**Consecința care rămâne, scrisă ca să nu fie descoperită ca surpriză.** Pe o
INSTALARE NOUĂ căreia îi lipsește identitatea, gazda e tăcută pe TOATE canalele
deodată: expeditorul nu trimite, martorul n-a auzit niciodată identificatorul ăla
deci nu are ce declara tăcut, iar `check_instance_identity` raportează `unknown`,
pe care `CheckResult.bad` nu-l numără — deci nu pleacă nici alertă Telegram.
Rămân doar liniile din jurnal și titlul lui `/selfcheck`. Pe calea de
ACTUALIZARE se întâmplă opusul, din aceeași cauză: găleata `default` tace și
martorul strigă, cu mesajul greșit. Ce ar închide gaura e ca `unknown` să
alerteze, dar aia e o schimbare de politică pentru toate verificările din
`selfcheck/checks.py`, nu pentru asta.

## Alertele duble

Sentinel are propriul canal de alertare pe Telegram. Martorul are al lui. Când
autodiagnosticul cade, ambele pot spune același lucru operatorului, la câteva
secunde distanță — măsurat, 131 de ori în 7 zile pentru un singur fel de
mesaj. `collect()` duce acum și faptul care rezolvă asta: ce a livrat
CONFIRMAT principalul, recent, pe felul pe care martorul îl poate dubla
(`alerted_kinds`, vezi constanta `ALERT_SUPPRESSION_WINDOW_S` mai jos pentru
fereastra și raționamentul). Suprimarea propriu-zisă e decizia martorului —
`aggregator/app/api/sentinel/check/route.ts` — nu a acestui modul, care doar
raportează faptul.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from sentinel.config import Config, get_secrets
from sentinel.db.engine import Database
from sentinel.identity import IdentityError, read_instance_id
from sentinel.logging_setup import get_logger

# Reexportate dinadins: `beacon.canonical` și `beacon.sign` rămân numele sub care
# sunt chemate din restul depozitului. Definiția e una singură, în signing.py,
# fiindcă din E2 mai semnează și expeditorul de loturi — două copii ale unei
# funcții al cărei contract E identitatea de octeți sunt două lucruri care pot
# devia una de cealaltă.
from sentinel.report.signing import CanonicalError, canonical, sign

log = get_logger(__name__)

SECRET_NAME = "SENTINEL_BEACON_SECRET"
SIGNATURE_HEADER = "X-Sentinel-Signature"
# Numele antetului e comparat de martor în minuscule (`req.headers.get` pe
# `INSTANCE_HEADER = "x-sentinel-instance"`; antetele HTTP sunt insensibile la
# majuscule), deci forma de aici e doar cea citită de om.
INSTANCE_HEADER = "X-Sentinel-Instance"
SEQUENCE_KEY = "beacon:seq"

# Urma pe care o lasă REZULTATUL unei runde, nu doar faptul că a fost una.
#
# `beacon:seq` crește la fiecare rundă care ajunge să semneze, indiferent dacă
# martorul a acceptat ceva — deci din el nu se poate afla nimic despre livrare.
# Iar `send_once` raportează eșecul doar în jurnal, dinadins (alerta pentru „nu
# ajung la martor" nu are voie să plece prin canalul care s-ar putea să fie
# stricat). Consecința, măsurată: pe o instalare NOUĂ în care fiecare bătaie e
# refuzată, unitatea rămâne `active`, martorul ține instanța în `no-beat` — care
# nu se numără și nu alarmează — și nimic de pe gazdă nu contrazice asta.
#
# Cele două valori de aici sunt faptele din care `selfcheck/checks.py` poate
# spune diferența dintre „trimit și sunt primit", „trimit și sunt refuzat de
# fiecare dată" și „nu știu încă":
#
#   `beacon:delivered` — `cursor` e `seq`-ul ULTIMEI bătăi acceptate, iar
#       `updated_at` momentul acceptării. Lipsa rândului înseamnă „niciodată
#       acceptat", care e o stare, nu o absență de informație;
#   `beacon:refused`   — câte runde LA RÂND s-au întors fără acceptare, zero
#       imediat ce una reușește. Contorul, nu doar momentul, fiindcă o gazdă
#       care n-a bătut niciodată n-are moment de la care să se măsoare, iar
#       imediat după un deploy „încă n-a acceptat nimeni nimic" e adevărat
#       despre orice instalare sănătoasă.
#
# Se scriu în `collector_cursors`, ca restul cursoarelor, ca să nu apară o stare
# nouă de întreținut. Prefixul `beacon:` le ține departe de `ship:*` și de
# `detect:*`, care se citesc cu `::bigint` de alte interogări.
DELIVERED_KEY = "beacon:delivered"
REFUSED_KEY = "beacon:refused"

# Cât din etichetă are rost să plece. Geamănul e `MAX_LABEL` din
# `aggregator/app/api/sentinel/beat/route.ts`, care taie oricum la aceeași
# lungime — se taie și aici ca o valoare scăpată de sub control din
# `sentinel.yaml` să nu umfle FIECARE semnal cu ceva ce martorul aruncă.
MAX_LABEL = 64

# ---------------------------------------------------------------------------
# Alertele duble: ce a livrat Sentinel însuși recent, pe felurile pe care
# martorul le poate dubla
# ---------------------------------------------------------------------------
# Măsurat pe gazdă, 7 zile: 131 de notificări `kind='selfcheck'` livrate de
# Sentinel pe Telegram — și tot atâtea alerte „selfcheck" trimise separat de
# martorul extern, despre EXACT aceeași defecțiune. Câmpul de mai jos duce un
# singur fapt în plus, ca `check/route.ts` să poată tăcea a doua voce: a
# livrat principalul, CONFIRMAT — `state='sent'`, nu doar pus în coadă, vezi
# `sentinel/telegram/bot.py:1230` — o notificare de felul ăsta în ultimele
# `ALERT_SUPPRESSION_WINDOW_S` secunde?
#
# **Fereastra trebuie să acopere runda de `/check` care observă PRIMA
# livrarea, nu doar cadențele proprii ale expeditorului.** Varianta inițială
# (180 s) era prinsă doar între `interval_s` al beaconului (60 s) și cadența
# autoverificării (300 s) — corectă ca margine de jos, insuficientă ca margine
# de sus. `docs/DEPLOYMENT.md` §7 documentează, măsurat pe instalarea asta, că
# `/check` rulează din cronul găzduirii cu **latență de până la 5 minute**
# (300 s) — e chiar fraza „180 de secunde plus latența cronului (până la 5
# minute)" de acolo, despre pragul lui `silent`, dar latența cronului e un
# fapt despre CRON, nu despre `silent`, și se aplică la fel aici. Iar starea pe
# care o citește `/check` e cea din ULTIMUL semnal primit, care poate fi el
# însuși cu până la `interval_s` (60 s) în urmă față de momentul citirii —
# `alerted_kinds` se calculează la TRIMITEREA semnalului, nu la citirea lui.
# Cu 180 s, o livrare la T devine invizibilă pentru orice rundă de `/check`
# care ajunge după T+180, iar un cron cu latență de 5 minute ajunge acolo des.
# Exact dubla pe care mecanismul ăsta există s-o închidă.
#
# 360 s = 300 (latența documentată a cronului) + 60 (`interval_s` al
# beaconului, marja pentru relanseul prin care semnalul ajunge la martor). Nu
# e o rotunjire de mijloc, e suma a două cifre măsurate.
#
# **De ce peste 300 nu mai maschează o defecțiune NOUĂ, cum se temea varianta
# veche.** O defecțiune chiar nouă (o cheie de `selfcheck` diferită, sau
# aceeași revenită și căzută din nou) produce o notificare NOUĂ, livrată de
# `_push_loop` în cel mult 15 s — deci `alerted_kinds.selfcheck` redevine
# adevărat, despre problema curentă, mult mai repede decât orice fereastră
# discutată aici. Lărgirea nu ține o livrare veche vie artificial de mult;
# ea doar acoperă golul dintre o livrare reală și runda de `/check` care ar
# fi trebuit s-o vadă.
#
# **Grija de la capătul celălalt** — martorul tăcând mult după ce principalul
# a amuțit de tot — rămâne mărginită structural, nu de fereastra asta: dacă
# Sentinel chiar tace (procesul, nu doar canalul Telegram), beaconul nu mai
# trimite NIMIC, iar `silent` (declanșat după 180 s de tăcere reală,
# `MISSED_BEATS_BEFORE_ALARM × interval_s`) nu e NICIODATĂ suprimabil — vezi
# `SUPPRESSIBLE_KINDS` din `aggregator/lib/verify.ts`. Fereastra asta poate
# masca o problemă NOUĂ doar în compunerea îngustă în care Sentinel bate
# normal mai departe ȘI o livrare anterioară a reușit o dată ȘI mecanismul de
# livrare Telegram s-a stricat exact după aceea, fără să treacă prin
# `_send_direct` — 360 s lărgește expunerea aia cu 180 s față de varianta
# veche, nu cu ore.
#
# **Nu acoperă `stalled`, dinadins.** Sentinel n-are un fel de notificare
# propriu pentru „bucla de detecție s-a oprit" — verificarea care ar prinde-o
# (`check_detection_loop`) scrie tot pe coada `kind='selfcheck'`, amestecată cu
# ORICE altă verificare căzută (executor, patch, reputație...). A trata „am
# livrat un selfcheck" ca dovadă că s-a anunțat ANUME blocajul ar suprima un
# `stalled` real pe baza unui mesaj fără nicio legătură — exact flag-ul
# grosier pe care martorul nu are voie să-l aibă (vezi granularitatea din
# `aggregator/lib/verify.ts`). Rămâne nesuprimat.
ALERT_SUPPRESSION_WINDOW_S = 360

# `EXISTS`, nu `count(*)`: martorul primește un bool peste fir, nu un număr a
# cărui singură întrebuințare e „zero sau nu". Fereastra intră ca PARAMETRU
# (`$1`, prin `make_interval`), nu ca literal interpolat în șir — nu fiindcă ar
# fi injectabilă (e o constantă a codului, nu o intrare externă), ci ca
# instrucțiunea să rămână un literal Python simplu, pe care
# `tests/unit/test_beacon_sql_schema.py` chiar îl poate citi static. O
# interogare asamblată din bucăți (f-string, concatenare) e invizibilă pentru
# lint-ul ăla — exact felul de gol care a lăsat coloana greșită din
# `AUDIT_HEAD_SQL` să reziste un an.
SELFCHECK_DELIVERED_SQL = (
    "SELECT EXISTS (SELECT 1 FROM notifications WHERE kind = 'selfcheck' "
    "AND state = 'sent' AND sent_at > now() - make_interval(secs => $1))"
)

# Capul lanțului de audit, definit exact ca în sentinel/db/repo/audit.py: ultima
# intrare după `id`, coloana `entry_hash`. Cele două definiții trebuie să rămână
# aceeași — dacă scriitorul înlănțuie pe altceva decât raportează sonda, martorul
# vede un cap care sare fără motiv.
#
# Interogarea a cerut o coloană `hash` care nu a existat niciodată (tabela are
# `prev_hash` și `entry_hash`), deci sonda pica la fiecare rundă de la instalare
# și martorul primea în locul capului un șir gol. Vezi
# tests/unit/test_beacon_sql_schema.py.
AUDIT_HEAD_SQL = "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"

# „N-am putut citi" și „nu e nimic de citit" sunt stări diferite și nu au voie să
# arate la fel la celălalt capăt: un jurnal de audit gol (instalare proaspătă)
# trimite `""`, iar o sondă care a eșuat trimite valoarea asta. Numai a doua
# înseamnă că bariera anti-falsificare lipsește din semnal. Nu se poate confunda
# cu un cap real — acela are 64 de caractere hexazecimale.
AUDIT_HEAD_UNAVAILABLE = "unavailable"

# Câte runde consecutive a eșuat fiecare sondă. Procesul rulează la nesfârșit,
# deci fără contorul ăsta o sondă ruptă din prima zi arată în jurnal exact ca una
# care a clipit o dată — care e chiar felul în care interogarea de mai sus a
# supraviețuit un an de avertismente citite și ignorate. Aceleași praguri ca la
# eșecul de transmisie, ca să însemne același lucru.
_PROBE_ALARM_AT = (3, 30, 300)
_probe_failures: dict[str, int] = {}

# Câte runde la rând n-a existat identitate. Aceeași scară, din același motiv:
# fișierul se recitește la fiecare rundă, deci fără contor o gazdă care n-a avut
# NICIODATĂ identitate arată în jurnal exact ca una care a clipit o dată în
# timpul unei instalări.
_identity_failures = 0

# Câte runde la rând a refuzat forma canonică payload-ul. Aceeași scară, din
# același motiv: un câmp adăugat greșit refuză FIECARE rundă, la nesfârșit, iar
# fără contor arată în jurnal exact ca o clipire.
_canonical_failures = 0


async def _next_sequence(db: Database) -> int:
    """Număr strict crescător, persistat.

    Martorul refuză un `seq` care scade sau se repetă, ceea ce face inutilă
    reluarea unui semnal valid capturat. Ținut în aceeași tabelă ca restul
    cursoarelor, nu într-un fișier: supraviețuiește repornirii și nu adaugă o
    stare nouă de întreținut.
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
        SEQUENCE_KEY) or 1)


async def _record_delivery(db: Database, seq: int, accepted: bool) -> None:
    """Ce a răspuns martorul, scris undeva de unde poate citi altcineva.

    **Nu ridică niciodată.** O bază care nu răspunde e deja raportată de
    `check_database`; dacă ar putea opri runda de aici, un defect al urmei ar
    deveni un defect al semnalului — adică fix inversul a ceea ce urma există să
    prevină.

    Nu se scrie pentru rundele care nu ating rețeaua (`IdentityError`,
    `CanonicalError`). Alea nu sunt „martorul m-a refuzat", au contoarele lor și
    propria verificare (`check_instance_identity`), iar amestecate ar face
    contorul de refuzuri să numească o cauză greșită în mesajul către operator.
    """
    try:
        if accepted:
            await db.execute(
                """
                INSERT INTO collector_cursors (name, cursor, updated_at)
                VALUES ($1, $2, now())
                ON CONFLICT (name) DO UPDATE
                    SET cursor = EXCLUDED.cursor, updated_at = now()
                """,
                DELIVERED_KEY, str(seq))
            # Zero, nu ștergere: rândul șters ar face „a mers de la prima rundă"
            # nedistinct de „codul care scrie urma n-a rulat încă".
            await db.execute(
                """
                INSERT INTO collector_cursors (name, cursor, updated_at)
                VALUES ($1, '0', now())
                ON CONFLICT (name) DO UPDATE
                    SET cursor = '0', updated_at = now()
                """,
                REFUSED_KEY)
        else:
            await db.execute(
                """
                INSERT INTO collector_cursors (name, cursor, updated_at)
                VALUES ($1, '1', now())
                ON CONFLICT (name) DO UPDATE
                    SET cursor = ((collector_cursors.cursor)::bigint + 1)::text,
                        updated_at = now()
                """,
                REFUSED_KEY)
    except Exception as exc:  # noqa: BLE001
        log.warning("beacon could not record the delivery outcome",
                    extra={"detail": str(exc)[:200], "seq": seq,
                           "accepted": accepted})


async def collect(db: Database, cfg: Config) -> dict[str, Any]:
    """Contoarele care trebuie să avanseze, plus verdictul propriu.

    **Ridică `IdentityError` dacă gazda nu-și poate citi identitatea**, și e
    singurul lucru din funcția asta care poate ridica. Nu e o inconsecvență față
    de toleranța de mai jos: contoarele sunt CONȚINUTUL semnalului, iar
    identitatea e ADRESA lui. Un semnal căruia îi lipsește un contor ajunge
    întreg la destinatarul potrivit și se citește ca „nu știu cifra asta"; unul
    căruia îi lipsește adresa ajunge în istoria altcuiva. Vezi secțiunea „Ce face
    când NU-și poate citi identitatea" din capul modulului.

    Fiecare interogare e tolerantă la lipsă: pe o instalare parțială sau în
    timpul unei migrări, un tabel absent nu are voie să oprească semnalul. Un
    heartbeat care tace fiindcă o interogare secundară a eșuat produce exact
    alarma falsă pe care sistemul ăsta trebuie să nu o dea.

    Toleranța se oprește însă la a ascunde eșecul: valoarea de rezervă a fiecărei
    sonde ajunge în semnal, deci trebuie să se deosebească de o valoare reală
    acolo unde se poate. Pentru `audit_head` se poate (vezi
    `AUDIT_HEAD_UNAVAILABLE`); pentru contoarele numerice nu — martorul le trece
    prin `Number(x || 0)`, deci un eșec de sondă ajunge acolo drept `0` și nu se
    distinge de „încă niciun eveniment". Ca să se distingă, are nevoie de o
    schimbare la martor.

    Pentru `alerted_kinds` valoarea de rezervă e mai simplă, fiindcă merge într-o
    singură direcție: `False` înseamnă „nu știu dacă a livrat", iar martorul
    citește `False` ca „nu suprim", niciodată ca „a livrat, deci tac". O sondă
    eșuată aici nu ascunde nimic — cel mult pierde o suprimare legitimă, ceea ce
    înseamnă o alertă în plus pe Telegram, nu una lipsă. Vezi „Alertele duble" în
    capul modulului.
    """
    # Prima linie, înaintea oricărei interogări: fără identitate semnalul nu are
    # unde pleca, deci nu are rost nici măcar strâns.
    instance_id = read_instance_id()

    async def val(sql: str, default: Any = None, *args: Any) -> Any:
        try:
            out = await db.fetchval(sql, *args)
        except Exception as exc:  # noqa: BLE001
            n = _probe_failures[sql] = _probe_failures.get(sql, 0) + 1
            log.warning("beacon probe failed",
                        extra={"sql": sql[:60], "detail": str(exc), "consecutive": n})
            if n in _PROBE_ALARM_AT:
                # O sondă care a eșuat de atâtea ori la rând nu e o bază de date
                # ocupată, e o interogare greșită sau un tabel care lipsește.
                log.error("beacon probe keeps failing",
                          extra={"sql": sql[:60], "consecutive": n})
            return default
        if _probe_failures.pop(sql, 0):
            log.info("beacon probe works again", extra={"sql": sql[:60]})
        return out

    last_event = await val("SELECT max(id) FROM raw_events", 0)
    detect_cursor = await val(
        "SELECT cursor::bigint FROM collector_cursors WHERE name = 'detect:events'", 0)
    incidents_open = await val(
        "SELECT count(*) FROM incidents WHERE status = 'open'", 0)
    blocklist = await val(
        "SELECT count(*) FROM blocklist WHERE unblocked_at IS NULL", 0)
    audit_head = await val(AUDIT_HEAD_SQL, AUDIT_HEAD_UNAVAILABLE)
    # Implicit `False`, direcția sigură: dacă sonda eșuează, martorul trebuie să
    # alerteze crezând că nu s-a livrat nimic, nu să tacă crezând că s-a livrat.
    selfcheck_delivered = await val(
        SELFCHECK_DELIVERED_SQL, False, ALERT_SUPPRESSION_WINDOW_S)

    sc = None
    try:
        sc = await db.fetchrow(
            "SELECT worst_status, checks_run, checks_bad, started_at "
            "FROM selfcheck_runs ORDER BY started_at DESC LIMIT 1")
    except Exception:  # noqa: BLE001
        pass

    return {
        "instance_id": instance_id,
        # `cfg.instance_label`, nu `getattr(cfg, "instance_label", "")`: un
        # `getattr` cu valoare de rezervă peste un câmp care nu există a produs
        # deja o verificare moartă în selfcheck/checks.py, care nu a rulat
        # niciodată și a trecut verde un an. Dacă lipsește câmpul, asta trebuie
        # să se vadă la prima rundă, nu să se toarne tăcut într-un șir gol.
        #
        # `str(...)` NU e paranoia și nu e simetric cu de mai sus. `_coerce` din
        # sentinel/config.py întoarce neatinse valorile adnotate `str`, deci
        # TIPUL îl alege YAML: `instance_label: 01` e un int, `2026-08-12` e o
        # dată, `1.5` un float. Un `.strip()` peste oricare dintre ele ridică
        # AttributeError, `send_once` prinde doar `IdentityError`, iar unitatea
        # are `Restart=on-failure` cu `StartLimitBurst=10` — adică o etichetă
        # COSMETICĂ scrisă fără ghilimele opreşte definitiv semnalul, fix
        # rezultatul împotriva căruia argumentează docstring-ul modulului. Un
        # câmp care nu poate schimba nicio decizie nu are voie să poată opri
        # procesul, deci se convertește în loc să se valideze: un `ConfigError`
        # ar refuza pornirea TUTUROR serviciilor pentru un nume afișat.
        "instance_label": str(cfg.instance_label or "").strip()[:MAX_LABEL],
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "max_age_s": cfg.beacon.max_age_s,
        "interval_s": cfg.beacon.interval_s,
        "last_event_id": int(last_event or 0),
        "detect_cursor": int(detect_cursor or 0),
        "incidents_open": int(incidents_open or 0),
        "blocklist_size": int(blocklist or 0),
        # `None` înseamnă jurnal de audit gol, nu sondă eșuată: pe eșec, `val` a
        # întors deja `AUDIT_HEAD_UNAVAILABLE`, care e adevărat și trece de `or`.
        "audit_head": (audit_head or "")[:64],
        # Ce a livrat CONFIRMAT principalul, recent, pe felurile pe care
        # martorul le poate dubla. Un expeditor mai vechi nu trimite cheia asta
        # deloc — martorul cade înapoi pe „nu știu" și alertează ca azi, vezi
        # `aggregator/app/api/sentinel/beat/route.ts`.
        "alerted_kinds": {"selfcheck": bool(selfcheck_delivered)},
        "selfcheck": {
            "worst": sc["worst_status"] if sc else "unknown",
            "checks": int(sc["checks_run"]) if sc else 0,
            "bad": int(sc["checks_bad"]) if sc else 0,
            "ran_at": sc["started_at"].isoformat() if sc else None,
        },
    }


async def send_once(db: Database, cfg: Config, secret: str) -> bool:
    """Un semnal. `True` dacă martorul l-a acceptat.

    Eșecul e raportat în jurnal și nimic mai mult: un martor indisponibil nu are
    voie să devină o problemă a serverului monitorizat. Dacă găzduirea martorului
    cade, Sentinel continuă să apere serverul exact ca înainte.

    `False` acoperă acum și două cazuri în care runda nu atinge rețeaua și nu
    consumă un număr de secvență, fiindcă o rundă care n-a trimis nimic nu are
    voie să lase în urmă urmele uneia care a trimis: „n-am cu ce semna cine
    sunt" (`IdentityError`) și „ce am strâns nu se poate semna la fel la ambele
    capete" (`CanonicalError`, vezi contractul din `sentinel/report/signing.py`).
    """
    import httpx

    global _identity_failures, _canonical_failures

    try:
        payload = await collect(db, cfg)
    except IdentityError as exc:
        # Runda se ratează, bucla nu. Vezi „Ce face când NU-și poate citi
        # identitatea" în capul modulului: nu există nume sub care semnalul ăsta
        # ar putea pleca onest, iar `default` e numele altcuiva.
        _identity_failures += 1
        log.warning("beacon has no instance identity",
                    extra={"detail": str(exc)[:220],
                           "consecutive": _identity_failures})
        if _identity_failures in _PROBE_ALARM_AT:
            # Acțiunea acoperă AMBELE cauze, fiindcă tratamentul diferă. Un
            # deploy obișnuit creează fișierul lipsă — `ensure_instance_id`
            # rulează necondiționat. Un fișier care EXISTĂ dar nu e o identitate
            # nu se rescrie de nimeni, dinadins: instalatorul refuză, ca să nu
            # distrugă o valoare care poate a ajuns deja la un agregator. Ăla
            # cere un om care se uită în el și îl șterge.
            log.error(
                "beacon still has no instance identity",
                extra={"consecutive": _identity_failures,
                       "action": "./scripts/deploy.sh --host <gazdă> "
                                 "--user <utilizator> — creează identitatea "
                                 "lipsă. Dacă fișierul există dar nu e o "
                                 "identitate: od -c /etc/sentinel/instance_id, "
                                 "șterge-l, apoi rulează deploy-ul."})
        return False
    if _identity_failures:
        log.info("beacon has an instance identity again",
                 extra={"after_failures": _identity_failures})
        _identity_failures = 0

    try:
        # Contractul se verifică pe payload-ul strâns, ÎNAINTE de a consuma un
        # număr de secvență — o rundă care n-a trimis nimic nu are voie să lase
        # urme care arată ca o rundă care a trimis. `seq` e un întreg, deci a
        # doua chemare nu poate refuza ce-a acceptat prima; e în `try` fiindcă
        # „nu poate" scris în comentariu și „nu poate" impus de cod sunt lucruri
        # diferite, iar aici o excepție nesprijinită oprește tot serviciul.
        canonical(payload)
        payload["seq"] = await _next_sequence(db)
        body = canonical(payload)
        signature = sign(payload, secret)
    except CanonicalError as exc:
        # Un payload în afara contractului nu se trimite „cum e": octeții ar fi
        # acceptați de martorul de azi (verifică HMAC peste ce primește) și
        # respinși de agregatorul din E2, care recalculează forma canonică. Un
        # câmp care se semnează la un capăt și nu se poate reproduce la celălalt
        # e o pană tăcută cu întârziere.
        _canonical_failures += 1
        log.warning("beacon payload is not signable",
                    extra={"detail": str(exc)[:220],
                           "consecutive": _canonical_failures})
        if _canonical_failures in _PROBE_ALARM_AT:
            log.error(
                "beacon payload keeps failing the signing contract",
                extra={"consecutive": _canonical_failures,
                       "detail": str(exc)[:220],
                       "action": "Câmpul numit în `detail` iese din contractul "
                                 "din sentinel/report/signing.py. Dacă vine din "
                                 "sentinel.yaml, scrie-l ca întreg (`60`, nu "
                                 "`60.0`); altfel e o regresie de cod."})
        return False
    if _canonical_failures:
        log.info("beacon payload is signable again",
                 extra={"after_failures": _canonical_failures})
        _canonical_failures = 0

    headers = {
        SIGNATURE_HEADER: signature,
        # Din payload, nu dintr-o a doua citire a fișierului: martorul cere
        # `payload.instance_id == antet` și refuză cu 401 dacă diferă, iar două
        # citiri independente pot să nu fie de acord — o rotire de fișier între
        # ele, sau pur și simplu o linie schimbată mai târziu în alt loc.
        INSTANCE_HEADER: payload["instance_id"],
        "Content-Type": "application/json",
        # Prin CDN, un semnal pus în cache ar face martorul să vadă la nesfârșit
        # ultimul răspuns bun — adică fix minciuna pe care o prevenim.
        "Cache-Control": "no-store",
    }
    accepted = False
    try:
        async with httpx.AsyncClient(timeout=cfg.beacon.timeout_s) as client:
            r = await client.post(cfg.beacon.url, content=body, headers=headers)
        if r.status_code // 100 == 2:
            accepted = True
        else:
            log.warning("beacon rejected",
                        extra={"status": r.status_code, "body": r.text[:200],
                               "seq": payload["seq"]})
    except Exception as exc:  # noqa: BLE001 - orice problemă de rețea, aceeași reacție
        log.warning("beacon unreachable",
                    extra={"detail": str(exc)[:200], "seq": payload["seq"]})
    # După ce verdictul e stabilit, și în afara lui `try`: urma se scrie pentru
    # AMBELE rezultate, iar o problemă la scrierea ei nu are voie să schimbe ce
    # s-a întâmplat de fapt pe fir. Vezi `_record_delivery`.
    await _record_delivery(db, int(payload["seq"]), accepted)
    return accepted


async def run_forever(db: Database, cfg: Config) -> None:
    secret = get_secrets().get(SECRET_NAME) or ""
    if not cfg.beacon.enabled or not cfg.beacon.url or not secret:
        # O dată, limpede, apoi liniște. Un expeditor care încearcă la nesfârșit
        # o adresă goală umple jurnalul și ascunde problemele reale.
        log.info("beacon disabled",
                 extra={"enabled": cfg.beacon.enabled,
                        "has_url": bool(cfg.beacon.url),
                        "has_secret": bool(secret)})
        return

    log.info("beacon started", extra={"interval_s": cfg.beacon.interval_s})
    consecutive_failures = 0
    while True:
        ok = await send_once(db, cfg, secret)
        if ok:
            if consecutive_failures:
                log.info("beacon reachable again",
                         extra={"after_failures": consecutive_failures})
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            # Doar în jurnal. Alerta pentru „martorul nu răspunde" e a
            # autodiagnosticului; dacă ar fi aici, ar pleca prin exact canalul
            # care s-ar putea să fie stricat.
            #
            # Contorul de aici trăiește în proces, deci nu poate fi citit de
            # autodiagnostic și nu supraviețuiește unei reporniri — de-aia
            # `_record_delivery` scrie același fapt în baza de date, de unde îl
            # ia `check_beacon_delivery`. Propoziția de mai sus a fost, până pe
            # 15 august 2026, o delegare către o verificare care nu exista.
            if consecutive_failures in (3, 30, 300):
                log.error("beacon has been failing",
                          extra={"consecutive": consecutive_failures})
        await asyncio.sleep(cfg.beacon.interval_s)
