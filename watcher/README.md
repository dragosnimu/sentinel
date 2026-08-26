# Martorul extern — aplicație Next.js de sine stătătoare

Jumătatea din afara serverului monitorizat. Primește semnalul periodic de la
Sentinel, iar când semnalul se oprește sau contoarele încetează să avanseze,
alertează pe Telegram — **de pe altă mașină decât cea compromisă.**

Asta e toată ideea: un agent găzduit nu poate garanta că raportează propria
dispariție, fiindcă cine îl oprește controlează și canalul.

E o aplicație completă, nu un set de fișiere de copiat undeva. Trei dependențe
de rulare în total — Next, React, React DOM — fiindcă fiecare dependență a unei
componente de securitate e suprafață de atac, iar o pagină care arată un singur
verdict nu are nevoie de un sistem de design. Cele de dezvoltare (TypeScript,
`tsx` pentru rulat testele) nu ajung în aplicația servită.

## Ce conține

```
app/page.tsx                       pagina de stare (singura interfață)
app/api/sentinel/beat/route.ts     primește semnalul
app/api/sentinel/check/route.ts    întreabă „a tăcut?" și alertează
app/api/sentinel/status/route.ts   200 dacă e viu, 503 dacă nu
lib/instances.ts                   cine e expeditorul, cu ce cheie, și cine e retras
lib/store.ts  lib/verify.ts  lib/telegram.ts
```

## Instalare pe Hostinger

Panoul hPanel, secțiunea Node.js (sau Website → Hosting → Node.js, în funcție
de plan). Aplicația e construită cu `output: "standalone"`, deci merge și pe
planuri fără npm pe server.

**Varianta A — build pe server**, dacă planul permite:

```bash
npm ci
npm run build
npm start          # sau comanda de start din panou
```

**Varianta B — build local, urci rezultatul.** Necesară pe planurile fără
toolchain de build:

```bash
npm ci && npm run build
# urci: .next/standalone/, .next/static/ (în .next/standalone/.next/static/),
#       public/ dacă există
# pornire: node server.js
```

Variabilele de mediu se pun în panou, nu într-un fișier urcat. Vezi
`.env.example` pentru lista completă.

**Domeniu:** un subdomeniu separat e mai curat decât o cale pe site-ul
principal — de exemplu `martor.domeniul-tau`. Ține martorul independent de
publicarea site-ului, ca o schimbare de conținut să nu îl poată opri din
greșeală.

## Variabile de mediu

| Variabilă | Ce e |
|---|---|
| `SENTINEL_BEACON_SECRET` | cheia HMAC a instanței `default`. **Aceeași** valoare ca pe serverul monitorizat |
| `SENTINEL_INSTANCE_SECRETS` | opțional; cheile celorlalte instanțe, ca hartă JSON `{"<instance_id>":"<cheie>"}` **sau** ca perechi `<instance_id>:<cheie>,<instance_id>:<cheie>` — a doua formă e obligatorie pe găzduirea care elimină `{`, `}`, `"` din valori (vezi `INCARCARE-HOSTINGER.md`) |
| `SENTINEL_RETIRED_INSTANCES` | opțional; identitățile RETRASE — servere dezafectate despre care martorul nu mai așteaptă nimic. Aceiași separatori ca mai sus: `<instance_id>,<instance_id>` |
| `SENTINEL_CHECK_SECRET` | secret separat, protejează ruta `/check` |
| `TELEGRAM_BOT_TOKEN` | același bot ca Sentinel (vezi mai jos) |
| `TELEGRAM_CHAT_ID` | unde ajung alertele |
| `SENTINEL_STATE_PATH` | opțional; calea de BAZĂ a stării. Fiecare instanță primește un fișier vecin, `<bază>.<instance_id>.json`. Implicit în `cwd` |

Generarea secretelor, **câte unul separat per instanță**:

```bash
openssl rand -hex 32
```

O cheie comună mai multor servere înseamnă că un atacator cu root pe unul poate
fabrica semnale pentru toate celelalte — inclusiv un „e viu" fals pentru unul pe
care tocmai l-a oprit.

## Mai multe servere

Fiecare instanță se identifică prin antetul `X-Sentinel-Instance` și prin
`instance_id` în payload; martorul cere ca cele două să coincidă și verifică
semnătura cu cheia instanței din antet. Un server care nu trimite niciuna dintre
ele intră ca instanța `default`, verificată cu `SENTINEL_BEACON_SECRET` — așa
poate fi actualizat martorul înaintea serverelor.

```bash
# starea agregată: 503 dacă ORICARE instanță tace
curl -s https://DOMENIUL-TAU/api/sentinel/status

# o singură instanță
curl -s "https://DOMENIUL-TAU/api/sentinel/status?instance=<instance_id>"
```

`/status` întoarce 200 doar pentru un semnal proaspăt. Orice altceva e 503,
cu motivul în corp:

| `status` | Ce înseamnă |
|---|---|
| `ok` | semnal proaspăt |
| `silent` / `stalled` / `selfcheck` | verdictele obișnuite |
| `no-beat` | instanța e cunoscută și nu a trimis niciodată nimic. Se VEDE, dar nu se numără în verdictul agregat — altfel o cheie rămasă în configurație ar ține plasa de siguranță roșie la nesfârșit |
| `unreadable` | are fișier de stare și nu poate fi citit |
| `unknown` | s-a cerut `?instance=<id>` pentru un id care nu e în registru — fără cheie configurată **sau retras** |
| `unconfigured` | nicio instanță nu are cheie |
| `state-volatile` | starea se scrie în directorul aplicației, deci următoarea publicare o șterge |

**`SENTINEL_STATE_PATH` nu e opțional în practică.** Fără el, starea stă în
directorul aplicației, iar acela se rescrie la fiecare publicare — la următoarea,
tot ce alarmează acum e uitat, iar un server căzut redevine „niciun semnal încă"
și nu mai alertează nimeni. Martorul refuză să pară sănătos în situația asta:
`/status` întoarce 503 `state-volatile` și pagina poartă un avertisment, până
când calea e mutată în afara directorului aplicației.

O instanță în `no-beat` nu alarmează niciodată, oricât ar sta acolo — inclusiv
una care ALARMA și în care martorul a recăzut fiindcă și-a pierdut starea. Nu
există un cronometru care să transforme „`no-beat` de prea mult timp" în alarmă:
i-ar trebui un reper de timp păstrat exact în starea care s-a pierdut.

**Cine e o instanță.** Fiecare fișier de stare poartă înăuntru identitatea lui,
iar un fișier e al instanței `X` doar dacă spune chiar `X`. E instanță:

- orice fișier care se identifică pe sine — **inclusiv al unui server căruia i
  s-a șters cheia**; acela nu dispare, ci tace și alertează;
- orice identificator cu cheie configurată, chiar fără fișier — starea
  `no-beat`, vizibilă dar necontabilizată.

**Nu** e instanță o copie: ea poartă identitatea originalului, care nu se
potrivește cu numele ei nou. Copia de siguranță pusă lângă starea reală înainte
de o publicare e ignorată, cu o linie în jurnal — altfel ar fi devenit un server
tăcut, adică o alarmă critică despre o mașină care nu există.

Regula are ambele direcții dinadins: o virgulă greșită în
`SENTINEL_INSTANCE_SECRETS` nu mai șterge serverele de pe hartă, ci le face să
alerteze.

## Retragerea unei identități

Un server dezafectat lasă în urmă o identitate care tace pentru totdeauna. Dacă
a bătut vreodată, tăcerea ei nu e `no-beat` — care nu se numără — ci `silent`,
care se numără. Măsurat pe 15 august 2026, cu identitatea moștenită pe care
serverul real nu o mai folosește de când poartă `instance_id`:

```
<instance_id>  ok      age_s 54
default        silent  age_s 63967
agregat: HTTP 503
```

Adică plasa de siguranță roșie la nesfârșit și o alertă critică la fiecare patru
ore despre un server care nu există, în timp ce toate serverele reale sunt
sănătoase. **O alarmă care nu se poate opri e o alarmă pe care operatorul o
oprește** — și atunci nu o mai citește nici pe cea adevărată.

Reparația evidentă — „scoate variabila care ține identitatea în registru" — **nu
e disponibilă pe găzduirea martorului.** Măsurat în aceeași zi și confirmat de
operator: variabilele de mediu **nu se pot șterge** (ștergerea din formular nu se
propagă, variabila reapare) și **nu pot avea valoare goală** (panoul cere o
valoare). Retragerea nu se poate deci exprima prin absență, și are nevoie de o
declarație proprie:

```
SENTINEL_RETIRED_INSTANCES=<instance_id>,<instance_id>
```

Separatorii sunt `,`, `;` și linia nouă, ca la `SENTINEL_INSTANCE_SECRETS`, din
același motiv: un separator pe care parserul nu-l cunoaște ar face a doua
identitate să dispară tăcut, iar ea ar continua să alarmeze.

### Precondiția: nimeni nu mai bate sub identitatea aia

**Nu retrage o identitate sub care mai trimite un server viu.** O identitate
retrasă iese din registru, deci serverul care bate sub ea dispare de pe **toate**
suprafețele — `/status`, `/check`, pagină — și nu mai produce nicio alertă.
Măsurat: un server actualizat plus unul vechi care încă trimite fără antet, cu
`SENTINEL_RETIRED_INSTANCES=default`:

```
beat de la serverul vechi  -> 401 refuzat
/status agregat            -> 200 "ok", doar serverul actualizat în listă
/check                     -> ok=true, zero mesaje pe Telegram
```

O mașină monitorizată vie, invizibilă, cu martorul raportând „ok" — exact
minciuna împotriva căreia există martorul.

**`default` e cazul cel mai expus**, și e chiar identitatea pe care ai vrea s-o
retragi prima. Nu e „o identitate care s-ar putea tasta greșit": e prin
construcție găleata comună a **fiecărui server care nu trimite încă**
`X-Sentinel-Instance`, adică chiar toleranța pentru care trecerea pe mai multe
instanțe e posibilă fără să taie semnalul serverelor existente. Retrage-o abia
după ce fiecare server real apare în `/status` sub `instance_id`-ul lui, iar
`age_s` al lui `default` crește de la o interogare la alta — semnul că nimeni nu
mai bate sub ea. Procedura completă la upgrade e în `docs/DEPLOYMENT.md` §7.

**Retras înseamnă că identitatea nu mai există**, pe toate suprafețele:

- **iese din registru** — tăcerea ei nu mai intră în verdictul agregat și `/check`
  nu mai alertează despre ea;
- **fișierul ei de stare rămas pe disc nu mai e al ei** — e ignorat ca fișier
  străin. Nu devine `unreadable` nici dacă e stricat: `unreadable` e roșu, iar un
  fișier abandonat dinadins nu e o defecțiune a martorului;
- **cheia ei nu mai autentifică.** Retragerea e o REVOCARE, altfel cine deține
  cheia unei mașini scoase din uz păstrează o intrare validă la martor, iar
  starea scrisă de el n-ar mai fi citită de nimeni. Semnalele ei primesc `401`,
  exact ca o instanță necunoscută — un cod propriu ar spune unui necunoscut că
  identificatorul a existat cândva aici. Deosebirea trăiește în jurnal;
- **`?instance=<retrasă>`** întoarce `503 unknown`. Verde nu e o opțiune: cine
  întreabă despre un id anume a declarat că se așteaptă să existe.

**Retragerea bate cheia.** O identitate scrisă și în `SENTINEL_INSTANCE_SECRETS`,
și în lista de retrase rămâne retrasă, și nu e tratată ca eroare — cheia
instanței `default` stă în `SENTINEL_BEACON_SECRET`, care nu se poate nici
șterge, nici goli, deci suprapunerea e starea normală după o retragere, nu o
greșeală. Cheia rămasă nu mai deschide nimic la martor, dar **merită rotită la
sursă**: pe serverul dezafectat e încă un secret valid scris pe disc.

O intrare scrisă greșit nu retrage nimic și **nu oprește martorul**: se numără în
jurnal — numărul, niciodată valoarea — și restul listei se aplică. Un `500` ar fi
oprit înregistrarea semnalelor pentru toate serverele sănătoase din cauza unei
propoziții despre unul mort.

**Ce nu e o retragere: ștergerea unei chei.** Un server viu căruia i s-a șters
cheia rămâne membru prin fișierul care se identifică singur, tace și alertează —
fiindcă acolo cauza obișnuită e o virgulă greșită într-un formular, nu o
decizie. Retragerea cere identitatea scrisă în litere.

Costul, scris ca să nu fie descoperit mai târziu: **o identitate retrasă din
greșeală tace fără să alarmeze**, fiindcă martorul nu o mai așteaptă. Singura
urmă rămâne linia din jurnal scrisă când o identitate retrasă chiar trimite, iar
jurnalul găzduirii e o suprafață slabă. Verifică lista după fiecare editare.

Semnalul agregat e un singur bit pentru N servere: cât timp unul e jos,
răspunsul rămâne 503 și revenirea altuia nu se vede în el. E acceptabil pentru
ce e — o plasă de siguranță pentru un monitor de uptime. Pentru „care anume"
există `?instance=`, corpul răspunsului, alerta de pe Telegram (care numește
instanța) și pagina.

## Rularea testelor

```bash
npm test        # node:test + tsx
npm run typecheck
```

## Cine întreabă „a tăcut?"

**Ruta `/check` nu se execută singură.** O rută API rulează doar când primește o
cerere, iar un martor care rulează doar la cerere nu poate observa o absență.
Cineva trebuie să întrebe periodic. Două variante, ideal amândouă:

**Cron pe găzduire**, la fiecare 5 minute:

```
*/5 * * * * curl -fsS "https://DOMENIUL-TAU/api/sentinel/check?key=SECRETUL_DE_CHECK" >/dev/null
```

**Un monitor de uptime** îndreptat spre `/api/sentinel/status`. Întoarce `503`
când semnalul e vechi, deci alertarea proprie a monitorului devine escaladarea
ta. Nu cere cron, dar adaugă un terț în lanț.

## Verificat local, înainte de a-l primi

Aplicația a fost compilată și rulată, iar drumul complet a fost testat cu
expeditorul real din Python: 16 verificări cap-coadă, toate trecute — semnal
autentic acceptat, semnătură invalidă refuzată cu 401, reluare refuzată cu 409,
semnal vechi refuzat cu 400, ruta de check protejată, contoarele care nu
avansează detectate corect, pagina randată, `no-store` prezent.

Plus alarma însăși: cu ultimul semnal îmbătrânit la 10 minute, `/status` a
căzut la 503 și `/check` a produs verdictul `silent`.

Ce NU e verificat e comportamentul pe Hostinger — CDN-ul, persistența
fișierului de stare între publicări, cronul. Alea se verifică o singură dată,
mai jos, și merită făcute înainte să te bazezi pe martor.

## Verificarea de acceptanță

Fără ea nu știi dacă funcționează, iar un martor despre care crezi că
funcționează e mai rău decât niciunul.

```bash
# 1. Semnalul sosește
curl -s https://DOMENIUL-TAU/api/sentinel/status
#    -> {"status":"ok","age_s":<sub 60>}
#    Înainte de primul semnal: 503 cu {"status":"no-beat"}. Dinadins — o stare
#    pe care martorul nu a citit-o niciodată nu are voie să fie verde.

# 2. O semnătură greșită e refuzată
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'X-Sentinel-Signature: gresit' -d '{}' \
  https://DOMENIUL-TAU/api/sentinel/beat
#    -> 401

# 3. Ruta de check nu e deschisă
curl -s -o /dev/null -w '%{http_code}\n' https://DOMENIUL-TAU/api/sentinel/check
#    -> 401

# 4. CDN-ul nu pune în cache. Două cereri la câteva secunde distanță trebuie
#    să dea `age_s` DIFERIT. Dacă e identic, ruta e în cache și martorul va
#    minți exact când contează.
curl -s https://DOMENIUL-TAU/api/sentinel/status; sleep 5
curl -s https://DOMENIUL-TAU/api/sentinel/status

# 5. Testul care contează: oprești Sentinel de tot și cronometrezi.
#    Pe server:  systemctl stop sentinel-beacon
#    Așteaptă ~3 intervale + până la următorul cron. Trebuie să sune telefonul.
#    Dacă nu sună, nimic din tot mecanismul ăsta nu contează.
```

## De ce același bot Telegram

Un atacator cu root pe serverul monitorizat citește tokenul și poate trimite
mesaje care par ale Sentinel — inclusiv un „totul e în regulă" fals, chiar
înaintea alertei reale. Ce **nu** poate face e să oprească martorul să trimită,
iar asta e proprietatea pentru care există tot mecanismul.

Atenuarea: mesajele martorului poartă prefixul `🛰 MARTOR EXTERN`, pe care codul
de pe server nu îl produce niciodată. Nu e o dovadă criptografică — nimic trimis
prin Telegram nu poate fi — dar face confuzia deliberată vizibilă.

Un bot separat ar fi mai curat. Costă un `/start` în plus și un chat id nou.

## Ce nu apără

Cheia HMAC stă pe mașina monitorizată. Un atacator cu root o citește și poate
fabrica semnale cu contoare care cresc. `audit_head` ridică bariera — capul
lanțului de hash-uri din jurnalul de audit trebuie menținut consistent, nu doar
incrementat — dar nu o face absolută.

Prinde sigur: serviciu oprit, proces căzut, OOM, disc plin, gazdă repornită,
rețea tăiată, ingestie blocată cu procesul viu, atacator care oprește Sentinel
fără să se gândească la consecințe.

Nu prinde sigur un atacator informat și răbdător. Nimic găzduit nu poate.
