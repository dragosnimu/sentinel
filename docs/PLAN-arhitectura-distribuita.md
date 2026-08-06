# Plan — arhitectură distribuită: logica pe server, martorul în afara lui

**Status:** propunere, neimplementată. Cere trei decizii de la operator (§7).
**Problema pe care o rezolvă:** un atacator cu root pe serverul monitorizat poate
opri toate serviciile Sentinel, iar în arhitectura de azi nimeni nu află.

---

## 1. Evaluarea propunerii

Propunerea a fost: *logica rămâne pe server, frontendul și heartbeatul se mută
într-o aplicație Next.js pe găzduirea existentă.*

Cele două jumătăți au merite foarte diferite și merită decise separat.

### 1.1 Heartbeatul pe altă gazdă — da, fără rezerve

E fix reparația de care e nevoie, din motivul corect: **absența semnalului
devine ea însăși alarma, iar judecata stă unde atacatorul nu ajunge.**

Un agent găzduit nu poate garanta că raportează propria dispariție, fiindcă cine
îl oprește controlează și canalul. Singura ieșire e ca altcineva să observe
tăcerea. Găzduirea existentă e un candidat bun: alt furnizor, altă suprafață de
atac, deja plătită, deja Next.js cu randare pe server.

### 1.2 Mutarea panoului operațional — nu, în forma cerută

Argumentul intuitiv e „scoatem panoul de pe serverul de securitate, deci
micșorăm suprafața expusă". În cazul ăsta cumpără mai puțin decât pare, din
patru motive concrete.

**Datele tot trebuie să ajungă undeva.** Ori Next.js cheamă un API pe serverul
Sentinel — și atunci serverul expune în continuare un endpoint autentificat spre
internet, doar de altă formă, plus o suprafață API nouă de securizat — ori
serverul împinge datele spre găzduire, și atunci găzduirea partajată ajunge să
țină tot istoricul de securitate: fiecare incident, fiecare adresă blocată,
fiecare vulnerabilitate. A doua variantă e o schimbare de graniță de încredere
mult mai mare decât pare la prima vedere.

**Panoul actual nu e veriga slabă.** Are Argon2id, TOTP obligatoriu, CSRF, CSP
strict, limitare de rată și `IPAddressDeny=any` pe proces. O rescriere în Next.js
înseamnă reimplementarea întregii autentificări, iar implementarea nouă pornește
de la zero teste. Riscul de regresie e real; câștigul, marginal.

**Arhitectura presupune deja că panoul poate fi compromis.** Procesul web nu
vorbește niciodată cu executorul: scrie un rând în `action_requests`, iar
acțiunile distructive cer confirmare pe Telegram. Compromiterea panoului nu e
fatală azi. Mutarea lui nu schimbă asta.

**Acțiunile tot trebuie să ajungă la server.** Blocare, aprobare de patch,
deblocare — toate se execută pe gazdă. Un panou pe altă mașină are nevoie de un
canal de comandă către server, adică exact suprafața pe care voiai să o elimini,
reconstruită de la zero și fără testele existente.

### 1.3 Ce recomand în schimb

Împărțirea pe criteriul „cine are nevoie de date, și cine are nevoie doar să
observe":

| Componentă | Unde | De ce |
|---|---|---|
| Colectare, detecție, profil, executor, bază de date | **rămân pe server** | acolo sunt datele și acolo se execută acțiunile |
| Panou operațional (incidente, patch-uri, blocklist, acțiuni) | **rămâne pe server** | autentificare deja întărită și testată; mutarea creează un canal de comandă nou |
| **Martorul de heartbeat** | **Next.js** | trebuie să fie în afara razei atacatorului |
| **Pagina publică de stare** | **Next.js** | răspunde la „mai trăiește?" fără autentificare și fără date sensibile |
| **Arhiva de dovezi** | **Next.js** | ce a plecat de pe mașină nu mai poate fi șters de pe ea |

Ultima linie e, după părerea mea, mai valoroasă decât heartbeatul în sine — vezi
§4.

---

## 2. Constrângerea care decide fezabilitatea

**O rută API se execută doar când primește o cerere. Un martor care rulează doar
la cerere nu poate observa o absență.**

Cineva trebuie să întrebe periodic „a fost liniște prea mult?". Trei variante,
în ordinea preferinței:

1. **Cron pe găzduire** care cheamă `/api/sentinel/check`. Simplu, fără terți,
   sub controlul tău. *De verificat dacă planul include cron.*
2. **Endpointul care se auto-denunță:** `/api/sentinel/status` întoarce `200`
   când ultimul semnal e proaspăt și `503` când e vechi. Orice monitor de
   uptime, inclusiv unul gratuit, alertează pe `503`. Nu cere cron, dar adaugă
   un terț în lanț.
3. **Agentul programat din cloud**, care există deja. Prea rar pentru asta — o
   dată pe zi înseamnă până la 24h de tăcere neobservată.

Recomandarea: **1 ca principal, 2 ca plasă de siguranță.** Costă aproape nimic
să le ai pe amândouă, și se acoperă reciproc.

### CDN-ul e o capcană aici

Găzduirea servește prin CDN (`Server: hcdn`, `x-nextjs-cache: HIT`). O rută API
de heartbeat pusă în cache ar întoarce vesel ultimul răspuns bun ore în șir,
adică exact minciuna pe care sistemul ăsta există ca să o prevină. Toate rutele
din §3 trebuie marcate `dynamic = 'force-dynamic'` și servite cu
`Cache-Control: no-store`, iar asta trebuie **verificat pe mediul real**, nu
presupus din configurație.

---

## 3. Fluxul de heartbeat

### 3.1 Ce se trimite

Nu „sunt viu" — **cifre care trebuie să crească**. Un ping fără conținut e
falsificabil de orice `curl` din cron, inclusiv al atacatorului.

```
POST https://<gazdă>/api/sentinel/beat        la fiecare 60 s
{
  "seq":            18342,            // strict crescător, detectează reluarea
  "sent_at":        "2026-08-10T06:00:00Z",
  "last_event_id":  4192883,          // avansează dacă ingestia trăiește
  "detect_cursor":  4192801,          // avansează dacă detecția consumă
  "selfcheck": { "worst": "ok", "checks": 32, "bad": 0, "ran_at": "..." },
  "incidents_open": 3,
  "blocklist_size": 17,
  "audit_head":     "sha256:...",     // capul lanțului de audit (vezi §5)
  "version":        "commit scurt"
}
```

Semnat HMAC-SHA256 peste corpul canonic, în antetul `X-Sentinel-Signature`.
Semnătura acoperă și `sent_at`, iar martorul refuză orice semnal mai vechi de
120 s — altfel un semnal valid capturat o dată poate fi reluat la nesfârșit.

### 3.2 Când alertează martorul

| Condiție | Ce înseamnă | Severitate |
|---|---|---|
| niciun semnal de peste 3 intervale | serviciile oprite, gazda căzută, rețea tăiată | critic |
| semnale sosesc, `last_event_id` staționar peste 15 min | procesul trăiește, ingestia e moartă | critic |
| `detect_cursor` rămâne în urmă și crește decalajul | detecția nu consumă ce se colectează | critic |
| `seq` scade sau se repetă | reluare, sau două expeditoare | critic |
| `selfcheck.worst` diferit de `ok` | Sentinel raportează singur o problemă | după caz |
| semnătură invalidă | cheie schimbată, sau cineva încearcă | critic |

Alerta pleacă **de pe găzduire**, cu propriile credențiale Telegram. Dacă ar
folosi tokenul de pe serverul monitorizat, ar depinde de exact ce s-a stricat.

---

## 4. Arhiva de dovezi — partea subestimată

Azi, un atacator cu root poate șterge tot: `DROP TABLE raw_events` și istoricul
dispare. Nu doar că nu afli ce s-a întâmplat — nu mai poți nici demonstra că s-a
întâmplat.

Odată ce există o conductă către altă gazdă, aceeași conductă poate duce
**incidentele și detecțiile, doar la adăugare**. Ce a plecat de pe mașină nu mai
poate fi șters de pe mașină.

```
POST /api/sentinel/evidence     la fiecare incident nou, cu reîncercare
```

Martorul le stochează fără să le poată modifica sau șterge prin API. Valoarea:
după o compromitere, ai istoricul dinaintea ei — inclusiv ce a făcut atacatorul
înainte să-și dea seama că e văzut.

Volumul e mic: incidente și detecții, nu evenimente brute. Ordinul de mărime e
zeci pe zi, nu zeci de mii.

---

## 5. Ce apără asta, și ce nu

Onestitatea aici contează mai mult decât în restul documentului, fiindcă e ușor
de crezut că problema a fost rezolvată complet.

**Prinde sigur:** serviciu oprit, proces căzut, OOM, disc plin, gazdă repornită,
rețea tăiată, bază de date moartă, ingestie blocată cu procesul viu, atacator
care oprește Sentinel fără să se gândească la consecințe.

**Nu prinde sigur:** un atacator informat și răbdător. Cheia HMAC e pe mașina pe
care a compromis-o. O citește și poate fabrica semnale cu cifre care cresc.

Atenuare parțială, nu soluție: `audit_head` e capul lanțului de hash-uri din
jurnalul de audit, iar martorul verifică continuitatea. Ca să falsifice
convingător, atacatorul trebuie să mențină consistent un lanț criptografic, nu
doar să incrementeze un număr. E o barieră reală, dar nu una absolută.

**Formularea corectă pentru un client:** heartbeatul transformă tăcerea în
alarmă și scoate dovezile de pe mașina compromisă. Nu face imposibilă
falsificarea de către cineva care deja deține gazda — nimic găzduit nu poate.

---

## 6. Etape

Fiecare etapă e livrabilă și utilă singură. Dacă te oprești după E2, ai deja
partea care contează cel mai mult.

### E0 — Verificarea premiselor (o oră, înainte de orice cod)
Fără astea, restul planului e speculație:
- planul de găzduire suportă **cron**? La ce interval minim?
- aplicația Next.js are **stocare persistentă**? Bază de date, sau doar disc?
- se poate exclude o rută din **cache-ul CDN**, verificat cu o cerere reală?
- **conexiuni de ieșire** permise din rutele API, pentru apelul Telegram?

### E1 — Expeditorul, pe server
`sentinel/report/beacon.py` + `sentinel-beacon.timer` la 60 s. Citește
contoarele, semnează, trimite. Nu are voie să scrie nimic și nu are voie să
blocheze nimic dacă găzduirea nu răspunde — un martor indisponibil nu e o
problemă de securitate a serverului monitorizat.
Teste: semnătură, `seq` monotonă, comportament la martor căzut.

### E2 — Martorul, pe Next.js
`/api/sentinel/beat` (primește), `/api/sentinel/check` (evaluează, chemat de
cron), `/api/sentinel/status` (200/503 pentru monitoare externe). Stocare:
ultimele N semnale plus starea de alertare. Telegram cu credențiale proprii.
**Aici se închide gaura.**

### E3 — Pagina de stare
Public, sau protejată cu un secret în URL. Arată: trăiește, de când, contoarele
avansează, verdictul autodiagnosticului, câte incidente deschise. Fără date
sensibile, fără acțiuni. Răspunde de pe telefon la „mai merge?" fără să te
autentifici nicăieri.

### E4 — Arhiva de dovezi
Conducta de incidente, cu reîncercare și coadă locală pentru perioadele în care
martorul e inaccesibil.

### E5 — Documentație și predare
Instalare pe a doua gazdă, rotația cheii HMAC, ce faci când martorul alertează,
și **testul de acceptanță**: oprești Sentinel de tot și cronometrezi cât durează
până sună telefonul. Dacă nu sună, nimic din planul ăsta nu contează.

---

## 7. Ce trebuie decis

1. **Panoul operațional rămâne pe server?** Recomand da, din §1.2. Dacă vrei
   totuși să se mute, planul se dublează în dimensiune și trebuie discutat
   separat unde ajung datele.
2. **Cron pe găzduire există?** Dacă nu, martorul se bazează pe varianta cu
   `503` plus un monitor extern, și trebuie ales care.
3. **Un bot Telegram separat pentru martor, sau același?** Separat e mai curat —
   dacă tokenul de pe serverul monitorizat se scurge, canalul de alarmă rămâne
   nealterat. Costă un bot nou și o comandă `/start`.

---

## 8. Ce nu rezolvă planul ăsta

- Un atacator care compromite **ambele** gazde.
- Falsificarea informată, descrisă în §5.
- Nu e backup: arhiva de dovezi ține incidente, nu date de aplicație.
- Nu înlocuiește Telegram ca panou de comandă. Rămâne canalul prin care
  acționezi; martorul doar observă.
