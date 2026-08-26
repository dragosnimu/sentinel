# Instalarea martorului pe găzduire

Procedura de mai jos **a fost executată și a funcționat** pe o găzduire
Hostinger reală, pe 7 august 2026. Nu e o presupunere.

Domeniul martorului nu apare nicăieri în acest depozit, dinadins. E singura
mașină pe care un atacator cu root pe serverul monitorizat nu o controlează, și
primul lucru pe care l-ar căuta e unde anume pleacă semnalul. Un depozit public
nu e locul în care să afle.

## De ce nu prin ecranul de încărcare

Încărcarea manuală a arhivei prin panou a fost respinsă de trei ori, cu
„Framework neacceptat sau structură de proiect nevalidă", deși Next.js e în
lista de framework-uri suportate. Cauza a fost arhiva, nu frameworkul:

**API-ul cere ca arhiva să conțină DOAR fișiere sursă** — fără `node_modules/`,
fără directorul de build (`.next/`), fără nimic din ce e listat în `.gitignore`.
Prima arhivă trimisă avea și `.next/`, și `node_modules/`. A fost respinsă
corect.

Deploy-ul prin API face același lucru mult mai transparent: dacă build-ul cade,
jurnalele spun de ce, în loc să primești un mesaj generic.

## Ce se trimite

```
app/  lib/  public/
package.json  package-lock.json  tsconfig.json  next.config.mjs
```

Atât. Aproximativ 25 KB. Build-ul instalează dependențele singur pe server.

`tests/` și `run-tests.mjs` NU se trimit: rulează local, prin `npm test`.
`run-tests.mjs` e învelișul care caută fișierele de test cu `readdirSync` în loc
să dea un glob lui `node --test` — pe Node 20, versiunea de pe platformă,
`--test tests/` raportează zero teste și iese cu 0, iar un script de teste care
raportează succes fără să fi rulat nimic ascunde exact jumătatea care dovedește
contractul de semnare. Dacă `npm ci` pe
platformă devine lent din cauza dependențelor de dezvoltare (`tsx` aduce
`esbuild`), `npm ci --omit=dev` construiește la fel — nimic din ele nu ajunge în
aplicația servită.

## Deploy

Cu serverele MCP Hostinger configurate, e o singură operație: se construiește
arhiva din sursă și se apelează `hosting_deployJsApplication` cu domeniul și
calea arhivei. Platforma detectează singură `app_type: next`,
`output_directory: .next` și `build_script: build` din `package.json`.

Rezultatul primului deploy real:

```
Next.js 15.5.23 · Node 20 · compilat în 3,8 s

Route (app)
┌ ƒ /                       ← dinamică
├ ƒ /api/sentinel/beat      ← dinamică
├ ƒ /api/sentinel/check     ← dinamică
└ ƒ /api/sentinel/status    ← dinamică
```

Toate rutele dinamice. O rută de heartbeat prerandată static ar fi inutilă în
modul cel mai tăcut cu putință, deci asta se verifică de fiecare dată.

## Variabilele de mediu

Se pun în panou, la aplicația Node.js. **Nu există API pentru ele** — e singurul
pas care rămâne manual.

| Variabilă | Valoare |
|---|---|
| `SENTINEL_BEACON_SECRET` | `openssl rand -hex 32` — aceeași valoare și în `/etc/sentinel/secrets.env` pe serverul monitorizat |
| `SENTINEL_INSTANCE_SECRETS` | opțional; **aici se scrie `<instance_id>:<cheie>,<instance_id>:<cheie>`**, nu JSON — vezi mai jos de ce; câte o cheie distinctă per server suplimentar |
| `SENTINEL_RETIRED_INSTANCES` | opțional; identitățile scoase din uz, `<instance_id>,<instance_id>` — vezi „Cum se retrage o identitate" mai jos. E singura cale: aici o variabilă nu se poate șterge |
| `SENTINEL_CHECK_SECRET` | `openssl rand -hex 32` — alta, diferită |
| `TELEGRAM_BOT_TOKEN` | același bot ca Sentinel |
| `TELEGRAM_CHAT_ID` | unde ajung alertele |
| `SENTINEL_STATE_PATH` | o cale **în afara** directorului aplicației. E o cale de BAZĂ: fiecare instanță primește un fișier vecin, `<bază>.<instance_id>.json`, deci **directorul** trebuie să fie scriibil |

Ultima nu e opțională în practică. Implicit, starea se scrie în directorul de
lucru al aplicației, iar acela e rescris la fiecare deploy — martorul ar uita
tot și ar porni de la „niciun semnal încă" de fiecare dată când publici.
Pune-o în directorul home, deasupra lui `public_html`.

**Martorul verifică singur asta și refuză să pară sănătos dacă e greșit.** Cât
timp calea de stare se rezolvă în interiorul directorului aplicației,
`/api/sentinel/status` întoarce `503` cu `{"status":"state-volatile"}` și pagina
poartă un avertisment. Nu e doar în jurnal, dinadins: un defect care ștergea
servere de pe hartă a stat deja o dată ascuns într-un jurnal Node pe care nu-l
citea nimeni.

### Dacă `state-volatile` apare pe o configurație corectă

Verificarea compară calea stării cu **directorul de lucru al procesului**, și
poate greși în două feluri, amândouă în direcția asta:

- managerul de procese pornește aplicația *din* directorul home, chiar cel în
  care ai pus starea — atunci calea e în siguranță, dar arată ca fiind
  înăuntru;
- calea persistentă e legată simbolic în arborele aplicației; verificarea nu
  urmărește legăturile simbolice.

**Prima probă de acceptanță de după deploy stabilește care e cazul.** Dacă
`/status` raportează `state-volatile` în timp ce `SENTINEL_STATE_PATH` chiar
arată în afara a ceea ce se rescrie la publicare, **verificarea greșește, nu
configurația.** Ce faci atunci:

1. confirmă prin efect, nu prin presupunere: publică din nou și verifică dacă
   fișierele de stare mai există după (`ls` în directorul din
   `SENTINEL_STATE_PATH`). Dacă supraviețuiesc, configurația e bună;
2. mută starea într-o cale absolută care nu e nici înăuntrul, nici legată
   simbolic în directorul de lucru al aplicației — asta stinge avertismentul
   fără să schimbe nimic în cod;
3. dacă nici asta nu se poate pe planul tău, notează-o ca abatere cunoscută și
   tratează `state-volatile` ca zgomot **doar după** ce ai făcut pasul 1.

Alarma e făcută dinadins să nu poată fi oprită din altă parte decât din
configurație: un martor care uită la fiecare publicare arată exact ca unul
sănătos, iar asta e minciuna pentru care există.

Fiecare instanță primește un fișier vecin, `<bază>.<instance_id>.json`. Un
fișier care doar seamănă cu ele — o copie de siguranță făcută înainte de o
publicare — **nu** devine un server: instanțele se enumeră din cheile
configurate, nu din ce e pe disc. Copia e ignorată, cu o linie în jurnal.

După ce le setezi, aplicația trebuie repornită ca să le citească. Cu MCP-ul,
asta e `hosting_restartNode_jsApplicationV1`; din panou, butonul de restart.

### Ce face panoul cu valorile — măsurat pe 14 august 2026

Trei constatări, toate verificate pe instalarea reală, nu presupuse:

1. **Panoul elimină `{`, `}` și `"` din valorile variabilelor.** După importul
   unui fișier `.env` care conținea
   `SENTINEL_INSTANCE_SECRETS={"<instance_id>":"<cheie>"}`, valoarea stocată,
   inspectată în panou, **nu avea nici acolade, nici ghilimele**. Adică o hartă
   JSON nu poate supraviețui aici, oricât de corect e scrisă.
2. **Formularul pe rânduri nu propagă nici editările, nici ștergerile.** O
   variabilă ștearsă reapare după „aplică modificările". Singura operație care a
   schimbat efectiv valoarea a fost **importul unui fișier `.env`**.
3. Consecința de la punctul 1, în derulare opt ore: `JSON.parse` arunca la
   fiecare cerere, martorul nu avea nicio cheie pentru instanța reală, răspundea
   401 la fiecare bătaie și **nu înregistra nimic**, cu ambele capete pornite.

### Unde se construiește fișierul de import — și de ce nu în depozit

Din punctul 2 de mai sus reiese că **importul unui fișier `.env` e singura
operație care schimbă efectiv o valoare**. Deci fișierul ăla se scrie de fiecare
dată: la instalare, și la fiecare rotire de cheie.

**Se construiește în afara arborelui de lucru.** Un director propriu în `home`
sau în `%TEMP%` — orice, numai nu depozitul:

```bash
mkdir -p ~/sentinel-import && chmod 700 ~/sentinel-import
$EDITOR ~/sentinel-import/hostinger.env      # se importă din panou, apoi:
shred -u ~/sentinel-import/hostinger.env     # sau rm, dacă nu ai shred
```

Motivul nu e igiena, e ireversibilitatea. Depozitul e public, iar `git add -A`
ia tot ce e neurmărit și neignorat. Un secret ajuns în istoric nu se mai poate
lua înapoi prin ștergere din arbore — rămâne în obiectele publicate, iar
singurul remediu real e rotirea cheii la ambele capete, adică exact operația
manuală de mai sus, făcută sub presiune.

**Măsurat pe 15 august 2026**, nu presupus: în rădăcina depozitului stătea un
astfel de fișier, neurmărit ȘI neignorat, cu chei de instanță în el. Garda de
sanitizare îl enumera și nu-l prindea, fiindcă numele variabilei e la plural,
iar tiparul ei cerea ca după `secret` să urmeze imediat `=`. Tiparul a fost
lărgit, dar asta e a treia linie de apărare, nu prima.

A doua linie e `.gitignore`, care acoperă acum familia de nume (`*.env`,
`*env*.txt`, `variabile*.txt`, pe lângă `.env` și `credentiale*.txt`). Rămâne a
doua fiindcă acoperă numele la care ne-am gândit; prima linie — fișierul nu se
scrie deloc în arbore — nu depinde de asta.

După import, valoarea trăiește în două locuri, amândouă în afara depozitului:
în panoul găzduirii și în `/etc/sentinel/secrets.env` pe serverul monitorizat.

De aceea `SENTINEL_INSTANCE_SECRETS` acceptă și forma fără cele trei caractere:

```
<instance_id>:<cheie hexa>,<instance_id>:<cheie hexa>
```

Perechile se despart prin **`,`, `;` sau linie nouă** — oricare din trei, și se
pot amesteca. Spațiile din jurul lui `:` și al separatorului se ignoră, iar
cheia se ia după PRIMUL `:`. JSON rămâne acceptat pentru gazdele care nu strică
valorile — formatul se alege după primul caracter nespațiu: `{` înseamnă JSON,
orice altceva înseamnă perechi.

**Spațiul NU desparte perechi**, dinadins: e singurul caracter pe care un
formular web îl adaugă singur în jurul lui `:` și `,`, iar dacă ar despărți, o
valoare bună cu un spațiu în plus s-ar rupe în bucăți. O valoare scrisă cu
spațiu între perechi — `a1b2c3:cheie d4e5f6:cheie` — e **refuzată**: 500 „nu
sunt configurat", plus o linie în jurnal care spune câte intrări s-au ignorat.
Aceeași regulă acoperă orice alt separator neanticipat: cheia are voie să
conțină doar caractere de cheie (hexa, base64, base64url și `:`), deci un
caracter străin ajuns în ea înseamnă că segmentul a înghițit altceva, și se
refuză zgomotos în loc să fie citit pe jumătate.

Motivul e măsurat: cu un singur separator presupus, o valoare scrisă cu linie
nouă sau cu `;` se citea ca O SINGURĂ pereche, iar a doua pereche devenea tăcut
parte din cheia primei. Rezultatul era 401 la fiecare bătaie de la amândouă
serverele, **cu jurnalul gol** — al doilea server nici nu ajungea în lista de
instanțe așteptate, deci nici tăcerea lui nu alarma.

Ce **nu** se poate detecta, scris aici ca să nu fie descoperit la a treia oră de
căutat: un separator șters fără să fie înlocuit cu nimic (`a1b2c3:cheieD4e5f6:cheie`)
arată exact ca o singură cheie care conține `:`, iar `:` e permis în cheie
dinadins. Simptomul e 401 pentru primul server. Dacă ajungi acolo, compară
lungimea cheii din panou cu cea de pe serverul monitorizat.

Efectul secundar util: o hartă JSON din care panoul a scos `{`, `}` și `"` E
deja forma de perechi. Dacă valoarea rămasă în panou arată exact
`<instance_id>:<cheie>`, martorul o citește ca atare după repornire — dar asta
**se confirmă prin efect** (o bătaie care ajunge la 200 și apare în `/status`),
nu fiindcă scrie aici.

Ce e tratat ca valoare STRICATĂ, adică 500 „nu sunt configurat", nu 401:

- valoare nevidă din care nu iese nicio pereche — de pildă doar identificatorul,
  fără `:` și fără cheie. Exact ce era în câmp pe 14 august: arăta configurat și
  nu producea nimic;
- același identificator de două ori — două chei pentru aceeași identitate
  înseamnă că nu știm care e cea bună, iar „ultima câștigă" ar alege tăcut;
- JSON care nu se parsează sau care nu e obiect.

Un identificator scris greșit, singur între altele bune, **nu** strică restul:
instanța aia rămâne necunoscută, tace, și alarmează prin tăcere.

### Cum se retrage o identitate — și de ce nu prin ștergerea unei variabile

Constatarea 2 de mai sus are o consecință care se vede abia când scoți un server
din uz. **Măsurat pe 15 august 2026**, pe instalarea reală:

- o variabilă de mediu **nu se poate șterge** — ștergerea din formular nu se
  propagă, iar variabila reapare după „aplică modificările";
- o variabilă **nu poate avea valoare goală** — panoul cere o valoare.

Deci „scoate `SENTINEL_BEACON_SECRET` și instanța `default` dispare din registru"
**nu e o operație disponibilă aici.** Iar problema pe care ar fi rezolvat-o e
reală: o identitate care a bătut cândva nu e `no-beat` (care nu se numără), ci
`silent` (care se numără). Starea măsurată în ziua aia:

```
<instance_id>  ok      age_s 54
default        silent  age_s 63967
agregat: HTTP 503
```

`/status` roșu la nesfârșit și o alertă critică la fiecare patru ore despre un
server care nu există, cu toate serverele reale verzi.

Retragerea se declară deci explicit, într-o variabilă proprie:

```
SENTINEL_RETIRED_INSTANCES=default
```

Separatorii sunt aceiași ca la chei — `,`, `;` sau linie nouă — și tot fără `{`,
`}` și `"`, din același motiv: panoul le elimină.

Ce se întâmplă după repornire, verificat prin **efect**, nu fiindcă scrie aici:

```bash
# 1. identitatea a ieșit din registru: nu mai apare în listă
curl -s https://DOMENIUL-TAU/api/sentinel/status
#    -> "instances" nu o mai conține, iar codul e 200 dacă restul sunt verzi

# 2. întrebată direct, e necunoscută — nu verde
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://DOMENIUL-TAU/api/sentinel/status?instance=default"
#    -> 503, cu {"status":"unknown"}

# 3. cheia ei nu mai autentifică: retragerea E o revocare
#    (de pe serverul dezafectat, dacă mai există, sau cu un curl semnat)
#    -> 401
```

Dacă pasul 1 arată identitatea în continuare, **valoarea nu a ajuns în proces**:
verifică în jurnalul de execuție linia `intrări ignorate din
SENTINEL_RETIRED_INSTANCES` (spune CÂTE, niciodată ce conțineau) și repornește
aplicația — variabilele se citesc la pornire.

Fișierul de stare al identității rămâne pe disc și devine un fișier străin:
ignorat, numărat în linia despre fișiere ignorate. **Nu** e raportat `unreadable`
nici dacă e stricat — aia e roșu, iar un fișier abandonat dinadins nu e o
defecțiune a martorului. Se poate șterge, dar nu e nevoie.

Cheia rămasă în `SENTINEL_BEACON_SECRET` (sau în `SENTINEL_INSTANCE_SECRETS`) nu
mai deschide nimic — retragerea bate cheia, și suprapunerea NU e tratată ca
eroare, tocmai fiindcă variabila nu se poate șterge. **Rotește totuși cheia la
sursă**: pe serverul dezafectat e încă un secret valid scris pe disc.

Ce **nu** e o retragere: ștergerea unei chei. Un server viu căruia i s-a șters
cheia rămâne membru, tace și alertează — acolo cauza obișnuită e o virgulă
greșită, nu o decizie. Și invers, prețul retragerii: o identitate retrasă **din
greșeală** tace fără să alarmeze, fiindcă martorul nu o mai așteaptă. Singura
urmă e o linie în jurnal atunci când o identitate retrasă chiar trimite, iar
jurnalul găzduirii e o suprafață slabă. Recitește lista după fiecare editare.

## Cum se verifică

`beat` întoarce **500 cât timp `SENTINEL_BEACON_SECRET` lipsește** — codul
refuză să pretindă că verifică semnături fără cheie. După configurare, o
semnătură invalidă trebuie să dea 401. Diferența dintre 500 și 401 e exact
diferența dintre „nu sunt configurat" și „te-am refuzat".

```bash
B=https://SUBDOMENIUL-TAU

curl -s $B/api/sentinel/status          # {"status":"ok","last_seen":...}
curl -s -o /dev/null -w '%{http_code}\n' $B/api/sentinel/check      # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
     -H 'X-Sentinel-Signature: gresit' -d '{}' $B/api/sentinel/beat  # 401
```

### Jurnalul de execuție: singura suprafață care numește cauza

`curl` spune DACĂ e stricat, nu DE CE. 500 „nu sunt configurat" are trei cauze
posibile (vezi lista de mai sus), iar răspunsul e deliberat sărac în detalii: un
endpoint care explică ce anume l-a supărat ajută la ghicit. La 401 e la fel.
**Probele HTTP nu pot deosebi cauzele, prin proiectare** — deci cine
diagnostichează o configurație refuzată începe de la jurnal, nu de la `curl`.

hPanel → **Site-uri web** → `<domeniul martorului>` → **Jurnale runtime**, în
meniul din stânga, imediat sub „Variabile de mediu". Pagina are căutare liberă
în înregistrări, filtru **Timp** (implicit „Ultima oră"), filtru **Nivel de
gravitate**, un comutator **Live** pentru urmărire în timp real, și un rezumat
„Volum jurnal" cu numărul de **Probleme** și **Erori** plus data ultimei
implementări.

Liniile scrise de martor prin `console.error` apar acolo marcate ca erori.
Exemplu real, exact cum s-a văzut pe 14 august 2026:

```
[watcher] SENTINEL_INSTANCE_SECRETS nu e JSON valid
[watcher] nicio cheie de instanță configurată
```

Asta a fost diagnosticul: nu „refuz", ci „nu pot citi valoarea".

**Pornirea aplicației apare de două ori** în jurnal — sunt două procese Next.js
— deci fiecare mesaj de configurare apare dublat. Nu sunt două defecte
distincte, e același mesaj din două procese.

**Capcana CDN.** Găzduirea servește prin CDN (`Server: hcdn`). O rută de
heartbeat pusă în cache ar întoarce ultimul răspuns bun ore în șir — fix
minciuna pe care mecanismul există ca să o prevină. Verificarea decisivă cere
un semnal deja sosit, ca `age_s` să aibă ce schimba:

```bash
curl -s $B/api/sentinel/status; sleep 6; curl -s $B/api/sentinel/status
```

`age_s` TREBUIE să difere. La primul deploy, antetele arătau
`Cache-Control: no-store` și niciun `x-nextjs-cache`, ceea ce e un semn bun —
dar dovada o dă doar valoarea care se schimbă.

## Testul care contează cu adevărat

După ce expeditorul de pe server e pornit și semnalele sosesc:

```
pe serverul monitorizat:  systemctl stop sentinel-beacon
```

Aștepți trei intervale plus până la următorul cron. **Trebuie să sune
telefonul.** Dacă nu sună, nimic din tot mecanismul ăsta nu contează.
