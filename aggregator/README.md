# Agregatorul extern — stratul de date

Aplicația care primește și păstrează ce expediază instanțele Sentinel
(`sentinel/report/shipper.py`). Rulează pe aceeași găzduire ca martorul, dar e
**altă aplicație**: martorul trebuie să rămână mic și publicabil independent, ca
lucrul care raportează moartea Sentinelului să nu împartă runtime, bază de date
și ciclu de publicare cu o aplicație mult mai mare. Argumentul lung e în
docstring-ul lui `watcher/lib/store.ts`.

## Ce e livrat aici (E2.4a, plus E3b/1–2) și ce nu

| Livrat | Nu încă |
|---|---|
| schema (`migrations/`) | verificarea lanțului de hash-uri (E2.4b) |
| runner de migrații granular pe instrucțiune | panoul read-only (E3) |
| cifrarea secretelor de instanță în repaus | restul fluxurilor (E3) |
| stratul de conexiune (pool) | crearea și înrolarea conturilor (fără ea, panoul n-are cu ce autentifica) |
| schema și primitivele de autentificare (`0008_auth.sql`, `lib/auth/`) | aplicarea lui `user_instances` în stratul de date (E3b/3) |
| rutele `/login`, `/totp`, `/logout`, cu CSRF, limitare de rată, CSP și `no-store` | |
| ruta `POST /api/sentinel/sync`, fluxul `audit_log` | **alertarea** unei rupturi de lanț |
| înregistrarea instanțelor (`npm run instance`) | |
| verificarea lanțului de audit (`npm run verify-chain`) | |
| runner de teste | |

Next.js a intrat odată cu prima rută, nu înainte: o dependență de 300 MB pentru
un director fără rute e doar ceva de actualizat. Versiunile sunt aceleași ca în
`watcher/package.json`, ca aceeași găzduire să nu ajungă să ruleze două runtime-uri.

## Rulare

```bash
npm install
npm test          # suita; pică dacă n-a rulat niciun fișier
npm run typecheck
npm run build     # verifică ȘI tipurile testelor; `next build` e ce rulează pe găzduire
npm start
```

Migrațiile, în ordinea în care merită folosite:

```bash
npm run migrate -- --syntax-check   # cere SERVERULUI să analizeze fiecare
                                    # instrucțiune (PREPARE/DEALLOCATE).
                                    # Nu creează și nu șterge nimic.
npm run migrate -- --dry-run        # ce ar aplica, citit din information_schema
                                    # și din registru. Nu scrie nimic.
npm run migrate                     # aplică ce lipsește
```

`--syntax-check` și `--dry-run` se pot rula pe baza de producție: prima cere
doar o analiză, a doua doar citește.

Verdictul `NEVERIFICAT` **nu** înseamnă „bine": înseamnă că serverul a spus că nu
poate pregăti instrucțiunea aia, deci despre ea nu s-a aflat nimic. Cât de des se
întâmplă ține de VERSIUNEA serverului, nu de schema noastră — iar aici
documentația a prezis greșit: se scria că `CREATE TRIGGER` nu se poate pregăti,
deci că despre triggere analiza nu spune nimic. **Măsurat pe gazdă, 15 august
2026, MariaDB 11.8.8:** `0 respinse, 0 NEVERIFICATE` peste toate cele șase
instrucțiuni din `0001_core.sql`, inclusiv cele două triggere, iar aplicarea de
după le-a creat pe amândouă. Verificarea e mai puternică decât o descria textul —
dar pe altă versiune verdictul se poate întoarce, și de-aia ramura rămâne.

## Publicarea pe găzduire — ce intră în arhivă

Procedura de publicare (arhivă de surse, fără `node_modules/` și fără `.next/`)
e cea din `watcher/INCARCARE-HOSTINGER.md`. Lista de fișiere de acolo **nu se
aplică neschimbată aici**:

```
app/  lib/  public/  migrations/
package.json  package-lock.json  tsconfig.json  next.config.mjs
```

Diferența față de martor e `migrations/`, și e obligatorie, nu opțională.
`lib/schema-guard.ts` verifică schema LA SERVIRE, prin `discover(MIGRATIONS_DIR)`
din `lib/migrate.ts` — iar `MIGRATIONS_DIR` e calculat din `import.meta.url`,
pe care compilarea îl înlocuiește cu calea absolută de pe mașina de BUILD. La
runtime, deci, `discover()` face `readdirSync` pe `<rădăcina aplicației
publicate>/migrations`. Fără `migrations/` în arhivă, garda nu poate citi
directorul (`ENOENT`) chiar la prima cerere — vezi
`kind: "migrations-unreadable"` din `lib/schema-guard.ts` pentru ce vede
operatorul atunci și cum se deosebește de o bază picată.

`bin/` (inclusiv `bin/migrate.ts`, care rulează efectiv migrațiile) **nu**
intră în arhivă — rămâne neschimbat față de martor. Migrarea se rulează de pe
mașina operatorului, cu `npm run migrate`, spre baza de la distanță (vezi
„Rulare" mai sus); pe găzduire nu rulează niciodată `bin/migrate.ts`, doar
citește conținutul din `migrations/` ca să-l compare cu registrul.

## Configurație

Totul din mediu, nimic în cod — numele bazei și al utilizatorului conțin
identificatorul de cont al găzduirii, iar depozitul e public.

| Variabilă | Obligatorie | Implicit |
|---|---|---|
| `AGGREGATOR_DB_HOST` | nu | `127.0.0.1` |
| `AGGREGATOR_DB_PORT` | nu | `3306` |
| `AGGREGATOR_DB_USER` | **da** | — |
| `AGGREGATOR_DB_PASSWORD` | **da** | — |
| `AGGREGATOR_DB_NAME` | **da** | — |
| `AGGREGATOR_DB_POOL_SIZE` | nu | `8` (max 64) |
| `AGGREGATOR_DB_CONNECT_TIMEOUT_MS` | nu | `10000` |
| `SENTINEL_AGGREGATOR_SECRET` | **da** | — (min. 32 de caractere) |
| `SENTINEL_SESSION_SECRET` | **da** | — (min. 32 de caractere) |
| `AGGREGATOR_CLIENT_IP_HEADER` | nu | — (nesetat = **nicio adresă de încredere**; vezi mai jos) |

O variabilă obligatorie lipsă — sau salvată goală, cazul obișnuit într-un
formular web — e o eroare care o numește, nu o cădere tăcută pe un implicit.

`SENTINEL_AGGREGATOR_SECRET` e secretul principal din care se derivă, prin
HKDF-SHA256, cheile de cifrare. **Nu** e secretul de sesiune: rotirea aceluia
trebuie să deconecteze utilizatorii, nu să facă indescifrabile cheile de
ingestie ale tuturor instanțelor. Pierderea lui înseamnă rescrierea secretelor
de instanță, nu pierderea datelor.

`SENTINEL_SESSION_SECRET` e celălalt capăt al aceleiași separări: din el se
derivă cheia cu care sunt cifrate secretele TOTP ale panoului. **Rotirea lui
cere reînrolarea TOTP a fiecărui utilizator** — secretele din bază nu se mai
descifrează —, dar nu atinge cheile de ingestie, deci sincronizarea instanțelor
merge mai departe. Cele două se citesc prin funcții separate (`lib/env.ts`)
tocmai ca lipsa uneia să nu oprească ce ține cealaltă; ținut de
`tests/env.test.ts`.

## Modul strict al sesiunii — de ce îl pune aplicația, și cum se probează

**Măsurat pe gazdă, 17 august 2026, MariaDB 11.8.8:**

    @@version             11.8.8-MariaDB-log
    @@sql_mode            NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
    @@time_zone           SYSTEM        @@system_time_zone   UTC
    @@max_allowed_packet  1073741824    @@max_connections    2000

`sql_mode` **nu are `STRICT_TRANS_TABLES`.** Sub un mod nestrict, un șir mai lung
decât coloana nu e refuzat, e **tăiat**, cu un avertisment pe care nu-l citește
nimeni; iar un `NULL` într-o coloană `NOT NULL` dintr-un `INSERT` cu mai multe
rânduri devine `''`. Instrucțiunea reușește. Rândul e **prezent**.

Și asta e exact ce cumpără agregatorul: `countPresent` (`lib/ingest.ts`) numără
PREZENȚA. Un rând tăiat e numărat drept bun, deci filigranul se ecouă, deci
cursorul expeditorului trece peste el — **definitiv**, fiindcă nimic nu se mai
întoarce după un rând pe care emitentul îl crede livrat. Pe autentificare,
același mod face dintr-un nume cu diacritice un cont scris cu `?`, sub o cheie
unică, pe care nimeni nu-l mai poate retasta.

Nu se cere nimic de la găzduire. **Aplicația își pune singură modul, pe sesiune,
la fiecare conexiune** (`lib/db.ts`), din singurele două funcții care ating
driverul — pool-ul rutelor și conexiunea singură a uneltelor din `bin/` și a
runnerului de migrații. Că sunt exact două, și că nimeni nu rescrie `sql_mode`
mai târziu pe o sesiune pornită, o țin recensămintele din
`tests/db-strict-mode.test.ts`. Ele numără **numele** — `mysql` și `sql_mode` —
în codul fișierelor livrate, nu ortografia importului și nici forma
instrucțiunii: amândouă ortografiile au fost deja evadate, una de un literal de
șablon la specificator, cealaltă de a cincea scriere MariaDB a aceleiași
atribuiri.

„Cod" înseamnă ce rămâne după ce **lexerul** scoate comentariile — parserul din
`typescript` pentru `.ts` și rudele lui, `splitStatements` pentru `.sql` —, nu
„ce nu stă pe o linie care începe cu `//`". Deosebirea a costat: o scuză de un
rând scrisă pe **aceeași linie** cu gestul (`/* temporar */ SET STATEMENT
sql_mode = '' FOR …`) a lăsat suita verde, de două ori, cu o atribuire vie și cu
o a doua cale de conectare în ea.

Instrucțiunea **adaugă**, nu înlocuiește:

```sql
SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''),
    'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO');
```

| Mod | De ce |
|---|---|
| `STRICT_TRANS_TABLES` | blocantul, pe instrucțiunile fără `IGNORE`: tăierea și `NULL`-ul convertit devin erori, deci „prezent" redevine „prezent întreg". Pe `INSERT IGNORE`, vezi mai jos |
| `NO_ZERO_DATE`, `NO_ZERO_IN_DATE` | `expires_at` se compară cu ora serverului la fiecare cerere (o sesiune cu dată zero nu expiră), iar rapoartele și retenția ordonează pe timp, unde un zero stă înaintea a tot |
| `ERROR_FOR_DIVISION_BY_ZERO` | `x/0` într-un `INSERT`/`UPDATE` devine eroare, nu `NULL` tăcut. Face parte din implicitul de fabrică al MariaDB, deci se știe sigur că serverul îl acceptă |

**`STRICT_ALL_TABLES` nu e pus**: pe o tabelă netranzacțională el întrerupe
instrucțiunea la mijloc și lasă rândurile scrise până acolo — un `INSERT` intrat
pe jumătate, mai rău pentru o replică decât oricare capăt. Toate tabelele din
`migrations/` sunt `ENGINE=InnoDB`, deci `STRICT_TRANS_TABLES` le acoperă deja.

Se adaugă la ce e deja acolo ca să nu se piardă `NO_ENGINE_SUBSTITUTION` (pus de
gazdă, util: un motor lipsă devine eroare, nu o substituție tăcută) și ca să nu
fim nevoiți să scriem `NO_AUTO_CREATE_USER`, pe care MariaDB l-a depreciat — un
mod scris pe față și scos într-o versiune viitoare înseamnă că **fiecare**
conexiune eșuează în ziua actualizării.

### Ce NU acoperă modul strict: `INSERT IGNORE`, adică fluxul viu

`writeSql` (`lib/ingest.ts`) scrie cu `INSERT IGNORE` pe fluxurile append-only și
pe tabelele de legătură care sunt numai identitate — acolo intră `audit_log` →
`audit_entries`, **singurul flux înregistrat azi în producție**. Tabelele de
legătură ar intra tot acolo (patru din cele cinci sunt numai identitate, deci
n-au ce pune în clauza de actualizare), dar azi **nu se scrie niciuna**: niciun
flux din `lib/streams.ts` nu declară `children`. Nu e o alegere: `migrations/0001_core.sql` pune pe
`audit_entries` un trigger `BEFORE UPDATE` care refuză orice rescriere, deci
ramura de UPDATE a lui `ON DUPLICATE KEY` ar eșua la primul rând deja prezent, iar
idempotența nu se poate face acolo decât cu `IGNORE`.

Iar `IGNORE` e chiar modificatorul care coboară erorile de DATE înapoi la
avertismente și scrie rândul ajustat. **MariaDB** o documentează, pentru familia
noastră de versiuni, în două feluri care se sprijină unul pe altul: pagina
`IGNORE` enumeră codurile convertite în avertisment — 1022, 1048, 1062, 1242,
1264, **1265**, 1292, 1366, 1369, 1451, 1452, 1526, 1586, 1591, 1748 — și spune
pe față că sub `IGNORE` modurile `STRICT_TRANS_TABLES`, `STRICT_ALL_TABLES`,
`NO_ZERO_IN_DATE` și `NO_ZERO_DATE` sunt ignorate. Deci acolo modul strict nu se
aplică deloc: un șir prea lung nu ridică 1406, se taie cu 1265 („Data truncated
for column"), iar 1265 e la rândul lui coborât la avertisment.

**Nu a fost măsurat pe gazda noastră**; pasul 4 al probei de mai jos există exact
ca să răspundă, și rămâne singura măsurătoare pe 11.8.8.

Deci, pe calea aia, apărarea nu e `sql_mode`, e `checkString` + `column.maxBytes`
din `lib/ingest.ts`: un șir mai lung decât coloana e **refuzat** cu lotul cu tot,
înainte să se construiască vreo instrucțiune — apărare de aplicație, care nu
depinde de serverul altcuiva, dar care e și singura de acolo.

Ce cumpără modul strict, și de ce rămâne net pozitiv: fluxurile mutabile
(`incidents` → `incident_entries`, scris cu `ON DUPLICATE KEY UPDATE`, fără
`IGNORE`), scrierile de autentificare, migrațiile, datele zero, împărțirea la
zero.

### Proba prin EFECT, pe gazdă — ce trebuie rulat și ce răspuns e bun

Suita de aici probează că fiecare cale de conectare **emite** instrucțiunea și că
nu există o a treia cale. Ce nu poate proba de pe o mașină fără MariaDB e că
serverul **chiar refuză** o scriere care ar fi fost tăiată — și, la pasul 4, dacă
`IGNORE` îl scutește de refuz. Aia se rulează o dată, cu clientul `mysql`, cu
contul aplicației, **într-o singură sesiune**:

```sql
-- 1. Sesiunea, exact ca aplicația.
SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''),
    'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO');
SELECT @@SESSION.sql_mode;
-- BUN: cele patru moduri de mai sus, PLUS NO_AUTO_CREATE_USER și
--      NO_ENGINE_SUBSTITUTION, care erau acolo.
-- RĂU: lipsește vreunul dintre cele patru, sau au dispărut cele două ale gazdei.

-- 2. Aceeași instrucțiune a doua oară. Acum lista conține valori repetate.
SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''),
    'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO');
-- BUN: Query OK. (Un `sql_mode` cu valori repetate e acceptat, deci a doua
--      conexiune a aceluiași proces nu are de ce să eșueze.)
-- RĂU: ERROR 1231 — atunci raportează-l: instrucțiunea trebuie schimbată.

-- 3. EFECTUL. O tabelă temporară, ca să nu fie atinsă nicio dată reală.
CREATE TEMPORARY TABLE sentinel_strict_probe (
    username VARCHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    at       DATETIME(6) NOT NULL
) ENGINE=InnoDB;

INSERT INTO sentinel_strict_probe (username, at) VALUES ('abcdefgh', UTC_TIMESTAMP(6));
-- BUN: ERROR 1406 (22001): Data too long for column 'username' at row 1
-- RĂU: Query OK, 1 row affected, 1 warning  ← modul NU e strict. Nu publica.

INSERT INTO sentinel_strict_probe (username, at) VALUES ('abc', '0000-00-00 00:00:00');
-- BUN: ERROR 1292 (22007): Incorrect datetime value: '0000-00-00 00:00:00'
-- RĂU: Query OK cu avertisment  ← NO_ZERO_DATE nu s-a aplicat.

-- Bilanțul pasului 3, luat ACUM: pasul 4 inserează dinadins un rând, deci după
-- el numărul nu mai deosebește „strict” de „nestrict”.
SELECT COUNT(*) FROM sentinel_strict_probe;
-- BUN: 0 — amândouă inserările au fost REFUZATE, deci n-a intrat nimic.
-- RĂU: 1 sau 2  ← una dintre ele a intrat, adică TĂIATĂ sau cu data zero — fix
--      rândul pe care countPresent l-ar număra drept bun. Nu publica.

-- 4. Ce NU acoperă modul strict: INSERT IGNORE.
--    audit_entries e append-only prin trigger (0001_core.sql), deci writeSql
--    din lib/ingest.ts e OBLIGAT să scrie acolo cu INSERT IGNORE.
INSERT IGNORE INTO sentinel_strict_probe (username, at)
    VALUES ('abcdefgh', UTC_TIMESTAMP(6));
SHOW WARNINGS;
SELECT username, CHAR_LENGTH(username) FROM sentinel_strict_probe;

-- AȘTEPTAT (și atunci afirmația din lib/db.ts și cea din secțiunea de mai sus
-- sunt cele scrise azi):
--   Query OK, 1 row affected, 1 warning
--   Warning | 1265 | Data truncated for column 'username' at row 1
--   'abcd' | 4      ← rând PREZENT și TĂIAT, SUB mod strict.
--   SELECT-ul citește TOATĂ tabela, deci rândul ăsta trebuie să fie SINGURUL:
--   dacă mai apare unul, a intrat de la pasul 3, iar bilanțul de dinainte a
--   fost citit greșit.
--   Numărul avertismentului poate fi și 1406; ce decide e RÂNDUL: dacă e acolo,
--   IGNORE a coborât eroarea la avertisment, iar pe calea aia apărarea reală e
--   checkString/maxBytes din lib/ingest.ts, nu sql_mode.
--
-- DACĂ ÎN SCHIMB apare ERROR 1406 (22001) și SELECT-ul nu întoarce niciun rând:
--   MariaDB 11.8 nu mai coboară eroarea la avertisment sub IGNORE. Atunci modul
--   strict acoperă și calea vie — dar scrie NUMĂRUL de versiune lângă afirmație,
--   în README și în lib/db.ts, fiindcă e o purtare specifică versiunii.

DROP TEMPORARY TABLE sentinel_strict_probe;
```

Bilanțul se ia **înaintea** pasului 4, nu după, și fără niciun `DELETE` între ele.
Prima formă a probei ștergea tabela ca „pasul 5 să rămână valabil" — un `DELETE`
fără `WHERE`, deci numărul de după ieșea 0 și când modul **nu** era strict, iar
ramura `RĂU` nu se putea atinge niciodată. Adică exact defectul pe care îl caută
toată secțiunea, strecurat în singura procedură care poate dovedi efectul pe
gazdă: o verificare al cărei răspuns bun vine la fel și când lucrul a eșuat.

Dacă contul n-are dreptul `CREATE TEMPORARY TABLES`, aceleași două inserări se
pot face într-o tabelă reală înăuntrul unui `START TRANSACTION` încheiat cu
`ROLLBACK` — dar atunci scrie în raport că proba a atins o tabelă de producție.

**A doua probă, gratis:** `npm run migrate -- --dry-run` pe gazdă. Conexiunea
singură pune modul, îl **citește înapoi** și aruncă dacă lipsește ceva, deci o
comandă care se termină normal e dovada că serverul ăla onorează instrucțiunea.
O comandă care se oprește cu „sesiunea MariaDB nu a putut fi pusă în mod strict"
este eșecul zgomotos, și e răspunsul care cere raportat, nu ocolit.

## Limitele, și de ce sunt scrise la ambele capete

| Limită | Valoare | Unde mai e scrisă |
|---|---|---|
| rânduri per flux, per lot | 2000 | `ship.max_rows_per_batch` ≤ 2000 (`sentinel/config.py`) |
| fereastra de prospețime | 86400 s | `ship.max_age_s` ≤ 86400 (`sentinel/config.py`) |
| corpul cererii | 2000 × 4 KiB | derivat din limita de rânduri (`lib/ingest.ts`) |

Un plafon al receptorului mai mic decât ce acceptă `load_config` **oprește fluxul
pentru totdeauna**: `ship_once` tratează orice răspuns non-2xx la fel, nu citește
niciodată corpul, și nimic nu micșorează un lot refuzat — deci arată exact ca un
agregator căzut, cu backoff până la o oră. Acordul e ținut de un test care pică
dacă vreunul dintre capete se mișcă
(`tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`), iar
o constantă nouă care nu e nici verificată acolo, nici declarată „numai la
receptor", pică suita (`..._is_either_agreed_or_declared_receiver_only`).

De ce 2000 și nu mai mult: costul unui lot mare nu e memoria, sunt dus-întorsurile
către bază — ingestia scrie și apoi NUMĂRĂ, deci 2000 de rânduri sunt deja ~34 de
instrucțiuni într-un singur `ship.timeout_s`. Mărimea lotului nu e oricum levierul
pentru o restanță: loturile pline pleacă la o secundă distanță (`DRAIN_PAUSE_S`).

Limita de corp are un rest cunoscut: `params` și `detail` sunt nemărginite la
sursă, deci un singur rând legitim de câțiva megaocteți o poate depăși, iar
expeditorul nu cunoaște numărul. Atunci fluxul se oprește VIZIBIL (413 și
`ship:lag`), nu tăcut — dar se oprește, și nu se poate debloca de pe gazda
monitorizată. E o decizie de operator luată în august 2026: o margine la
expeditor ar da codului de pe mașina monitorizată un cuvânt de spus despre ce
anume din propria istorie are voie să plece de acolo. Consecința e scrisă și în
mesajul verificării `ship:lag`, unde o vede operatorul gazdei Sentinel.

## Ce poartă recunoaștere și pleacă totuși de pe gazdă

`migrations/0003_entities.sql` refuză șapte coloane din `assets` — `vhost_file`,
`webroot`, `repo_path`, `repo_remote`, `repo_branch`, `container_image`,
`databases` — fiindcă împreună sunt o hartă gratuită a infrastructurii, iar un
agregator compromis ar da unui atacator partea scumpă a unui atac despre un
server pe care nu l-a atins încă. Absența lor e păzită de un test.

Restul acestei secțiuni e **lista completă a coloanelor al căror conținut nu e
mărginit de schemă**, cu motivul fiecărei familii. Nu e o scuză, e o listă: dacă
operatorul răstoarnă vreuna dintre decizii, aici se vede ce anume se răstoarnă.

**Împărțirea e după DECIZIE, nu după tip.** A fost după tip până în august 2026,
iar diferența a costat exact ce costă de obicei: garda cerea să fie numite doar
coloanele `JSON`, `MEDIUMTEXT` și `LONGTEXT`, așa că `incident_entries.summary`
și `incident_entries.title` — `TEXT`, deci nevăzute de regulă — au ajuns pe
agregator fără ca nimeni să pună întrebarea. Iar ele poartă recunoaștere: pe
gazdă, 9 rezumate din 1476 conțineau o cale de sistem, fiindcă detectoarele
interpolează în text ce au găsit (`/etc/passwd`, numele contului, uid-ul,
shell-ul, home-ul, căile fișierelor scrise sub webroot). „Tipul e mărginit" și
„conținutul e mărginit" sunt două afirmații diferite, iar prima nu o dovedește
pe a doua.

### Coloanele ENUMERABILE: se știe ce e în ele

| Coloană | Ce poartă | De ce pleacă |
|---|---|---|
| `finding_entries.location` | cale, imagine sau URL | fără ea constatarea nu e nici confirmabilă, nici reparabilă |
| `scan_entries.target` | ce s-a scanat | la fel; un rând de scanare fără țintă nu spune nimic |
| `patch_step_entries.cwd` | directorul comenzii | urma criminalistică a unui plasture eșuat |

Cazul pe care operatorul l-a decis explicit: recunoașterea scumpă e faptul că
replica are constatările **deloc** — „gazda X are CVE-ul Y nepatchuit, expus în
internet" —, iar locația adaugă puțin peste asta.

### Coloanele NEMĂRGINITE: nimeni nu poate spune ce va fi în ele

Astea sunt blobul altcuiva, și sunt numite ca **RISC**, nu acceptate tăcut.
Diferența față de cele trei de sus e că **nu se pot enumera**: nimeni nu poate
spune azi ce va scrie un scaner în ieșirea lui peste șase luni, ce fapte va
atașa o verificare nouă, sau ce va cuprinde ieșirea unei comenzi. Ce e acolo azi
nu mărginește ce va fi mâine, iar o coloană `JSON` nu are cum să refuze.

| Coloană | Ce e azi |
|---|---|
| `audit_entries.params` | parametrii oricărei operații consemnate |
| `audit_entries.detail` | textul liber al operației |
| `detection_entries.evidence` | ce a declanșat regula: linii de jurnal, căi, cereri |
| `incident_entries.ai_verdict` | textul modelului despre incident |
| `incident_timeline_entries.detail` | ce s-a schimbat la fiecare pas |
| `selfcheck_state_entries.facts` | scalari plus `{"file": …, "db": …}` |
| `finding_entries.raw` | ieșirea brută a scanerului |
| `finding_entries.ai_assessment` | evaluarea de exploatabilitate |
| `patch_plan_entries.plan` | planul întreg: `argv`, căi, praguri |
| `patch_plan_entries.validation_errors` | de ce a respins validatorul planul |
| `patch_execution_entries.result` | rezultatul execuției |
| `patch_step_entries.argv` | argumentele comenzii care s-a rulat |
| `patch_step_entries.stdout` | ieșirea comenzii, trunchiată și redactată PE SERVER |
| `patch_step_entries.stderr` | idem |

`plan` și `argv` sunt prevăzute de arhitectură ca date de afișat, iar coloanele
poartă comentariul chiar în schemă: *agregatorul nu execută asta niciodată*.
`stdout` și `stderr` trec prin redactorul de credențiale **pe serverul
monitorizat**, înainte de expediere; replica nu redactează nimic și nu are cum —
n-are de unde ști ce e secret în textul altcuiva.

### Coloanele `TEXT`: tipul nu mărginește nimic, deci sunt împărțite după conținut

`TEXT` în MariaDB e un bloc de 64 KiB. Ce mărginește conținutul, când e
mărginit, e o regulă de pe **serverul monitorizat** — un `CHECK` din
`sentinel/db/migrations/`, sau un vocabular fix al codului care scrie coloana.
Replica nu are regulile alea (`fara CHECK` e scris în comentariul fiecărei
coloane, dinadins: o replică nu respinge istorie legitimă), deci mărginirea e o
proprietate a sursei, nu a schemei de aici. De-aia familiile de mai jos, și de-aia
fiecare își spune TEMEIUL: o coloană așezată în familia potrivită din motivul
greșit e o decizie pe care operatorul n-o poate răsturna, fiindcă i s-a spus
altceva decât e.

**Vocabular fix pe server — nu poartă recunoaștere.** Valorile sunt o listă
închisă (`open|resolved`, `info|…|critical`, `rpm|npm|pypi|…`), iar o valoare
nouă e o schimbare de cod pe gazdă, nu date ale altcuiva:
`actor_entries.kind`, `asset_entries.kind`, `audit_entries.source`,
`audit_entries.operation`, `audit_entries.result`, `blocklist_entries.rule_id`,
`detection_entries.rule_id`,
`detection_entries.rule_family`, `detection_entries.severity`,
`finding_entries.scanner`, `finding_entries.severity`,
`finding_entries.ecosystem`, `finding_entries.status`,
`incident_entries.status`, `incident_entries.severity`,
`incident_entries.ai_severity`, `incident_timeline_entries.kind`,
`outage_entries.kind`, `patch_execution_entries.mode`,
`patch_execution_entries.status`, `patch_plan_entries.status`,
`patch_plan_entries.risk_level`,
`patch_step_entries.phase`,
`patch_step_entries.status`, `scan_entries.scanner`, `scan_entries.status`,
`selfcheck_run_entries.worst_status`, `selfcheck_state_entries.status`.

**Ieșire de model, îngustată de un validator — nu vocabular de cod.**
`patch_step_entries.step_id`. A stat în familia de mai sus pe un temei greșit:
valoarea nu vine dintr-o listă închisă scrisă în cod, ci din PLAN
(`sentinel/patch/runner.py`, `str(step.get("id") or …)`), iar planul e generat
de un model. Singura mărginire e expresia din `sentinel/patch/validator.py` —
`^[a-z0-9_]{2,16}$` —, aceeași și în schema planului
(`.claude/skills/sentinel-soc/assets/patch_plan.schema.json`). Deci o valoare
nouă **nu** e o schimbare de cod pe gazdă, e un răspuns nou al modelului.
Riscul de conținut e mic — cel mult 16 caractere din `[a-z0-9_]`, în care nu
încape nici o cale, nici un nume de gazdă întreg —, dar secțiunea asta există ca
operatorul să poată răsturna decizia în cunoștință de cauză, iar asta cere ca
TEMEIUL scris aici să fie cel adevărat. Temeiul e expresia validatorului; dacă
ea se lărgește vreodată, coloana își schimbă familia.

**Coloană pe care n-o scrie nimeni.** `patch_plan_entries.prompt_version`
există în ambele scheme (`sentinel/db/migrations/0004_patch.sql`,
`aggregator/migrations/0005_patch.sql`) și nu are niciun producător:
`INSERT INTO patch_plans` din `sentinel/db/repo/patches.py` nu o numește, iar
în tot codul nu apare decât în cele două fișiere de schemă și în schema
planului. Rămâne NULL, deci azi nu pleacă nimic prin ea — și „vocabular fix" nu
e un răspuns pentru o coloană pe care n-o scrie nimic. Când capătă un
producător, întrebarea din capul secțiunii i se pune atunci, iar locul ei aici
e rândul ăsta, ca să nu fie clasificată din inerție.

**Cine a făcut ceva — identități, nu infrastructură.** Poartă un id de Telegram,
un nume de utilizator sau `auto`. Recunoașterea din ele e despre OAMENI, iar
asta e chiar ce face un jurnal de audit verificabil din afara gazdei:
`audit_entries.actor`, `blocklist_entries.created_by`,
`blocklist_entries.unblocked_by`, `finding_entries.accepted_by`,
`incident_entries.acknowledged_by`, `incident_timeline_entries.actor`,
`patch_execution_entries.triggered_by`, `patch_plan_entries.generated_by`,
`patch_plan_entries.model`, `patch_plan_entries.approved_by`,
`patch_plan_entries.rejected_by`, `scan_entries.triggered_by`. Una singură
numește un cont de pe gazdă și e cea mai apropiată de recunoaștere:
`patch_step_entries.run_as`.

**Text liber — POARTĂ recunoaștere, la fel ca familia nemărginită de mai sus.**
Scris de detectoare, de scanere sau de operator, cu ce s-a găsit interpolat în
el. Aici stă cazul care a scăpat de gardă:

| Coloană | Ce poartă | De ce pleacă |
|---|---|---|
| `incident_entries.title`, `incident_entries.summary` | numele contului, uid, shell, home, `/etc/passwd`, căile fișierelor scrise sub webroot | un incident despre care nu se știe ce s-a atins nu e triabil din afara gazdei — și ăsta e tot rostul replicii |
| `incident_entries.resolution_note`, `blocklist_entries.reason`, `blocklist_entries.unblock_reason`, `detection_entries.suppress_reason`, `finding_entries.accepted_reason`, `finding_entries.resolution`, `actor_entries.notes` | ce a scris operatorul când a decis | decizia fără motivul ei nu se poate revizui mai târziu |
| `audit_entries.target` | ținta operației: IP, cale, nume de serviciu | un rând de audit fără țintă nu spune nimic |
| `asset_entries.name` | numele activului: vhost, serviciu, container | fără el, un activ e un id; cele șapte coloane SCUMPE ale lui `assets` sunt refuzate în `0003_entities.sql` |
| `finding_entries.package`, `finding_entries.installed_version`, `finding_entries.fixed_version`, `finding_entries.cve`, `finding_entries.advisory_id`, `finding_entries.cvss_vector`, `finding_entries.title`, `finding_entries.description` | ce e instalat pe gazdă și în ce versiune | e chiar decizia din prima secțiune: recunoașterea scumpă e că replica are constatările deloc |
| `actor_attrs.value` | ce s-a aflat despre un actor: ASN, țară, reverse DNS | fără valoare, atributul e un nume gol |
| `selfcheck_state_entries.title`, `selfcheck_state_entries.detail` | ce verifică o probă și ce a găsit: unități, căi, praguri | panoul de sănătate al replicii nu poate arăta „degradat" fără să spună ce |
| `session_command_entries.argv` | **linia de comandă întreagă**, rulată de cineva logat pe gazdă: căi, nume de fișiere, ținte de rețea, nume de servicii și containere | e chiar istoricul; fără ea, «cineva a rulat 412 comenzi» nu răspunde la nicio întrebare. **Sosește REDACTAT** — valorile care arată a secret sunt tăiate pe gazdă, la colectare (`sentinel/redact.py`), deci nu ajung niciodată aici. Redactarea e o listă de tipare, nu o garanție, iar limita ei e scrisă în `docs/SECURITATE.md` |
| `outage_entries.cause`, `scan_entries.error`, `scan_entries.db_version`, `patch_execution_entries.error`, `patch_execution_entries.rollback_reason`, `patch_plan_entries.blast_radius`, `patch_plan_entries.rejected_reason` | textul unui eșec, cu ce a fost în el | o pană fără cauză e o pană pe care nimeni n-o poate repara de la distanță |

Tabelele de mai sus sunt ținute complete de un test
(`tests/schema.test.ts`, „fiecare coloană nemărginită dintr-o replică e numită în
README"): o coloană `JSON`, `MEDIUMTEXT`, `LONGTEXT` sau `TEXT` adăugată într-o
tabelă replicată pică suita până e trecută aici. Lista dinaintea testului avea
trei intrări din paisprezece. Lărgită la `TEXT`, garda vede **89** de coloane în
loc de 14 — de-aia se lărgește în loc să se restrângă când scoate ceva la
iveală: o gardă care tace pentru că a fost îngustată nu mai e o gardă, e o
listă de scutiri fără nume.

**Asimetria, scrisă pe față:** o coloană neexpediată se poate adăuga oricând
printr-o migrație ulterioară; datele ajunse pe agregator **nu se retrag**. Deci
orice îndoială se rezolvă în direcția „nu pleacă", iar lista de mai sus e locul
unde se pune întrebarea înainte, nu după.

## Autentificarea panoului (E3b, piesa 1: schema și primitivele)

Ștacheta e `sentinel/web/security.py`, iar acordul dintre cele două capete e
ținut de `tests/unit/test_aggregator_auth_parity.py` — care nu compară numere
scrise în două locuri: pune hashul produs aici în fața verificatorului REAL al
serverului și cere aceleași coduri TOTP de la `pyotp` și de la implementarea de
aici.

**Tabelele din `migrations/0008_auth.sql` NU sunt o replică.** `users`,
`sessions` și `login_attempts` există și pe serverul monitorizat, iar ALEA nu
pleacă niciodată de acolo: conțin adresele IP ale operatorului și datele lui
personale. Astea sunt ale agregatorului, populate local de panoul lui.
Coincidența de nume e capcana, deci cele patru sunt trecute explicit în
`AGGREGATOR_OWNED` (`tests/schema.test.ts`), unde decid ce reguli li se aplică:
regulile REPLICII (o singură cheie unică începută cu `instance_id`,
contabilitatea sosirii, fiecare coloană nemărginită numită mai jos) NU li se
aplică, fiindcă nu sosesc de nicăieri. Din același motiv nu apar în listele de
coloane din secțiunea de mai sus: acolo se pune întrebarea „ce pleacă de pe
gazda monitorizată", iar din tabelele astea nu pleacă și nu vine nimic.

| Proprietate | Ce e livrat |
|---|---|
| Parolă | Argon2id `t=3, m=65536 KiB, p=2`, sare 16 octeți, hash 32 — identic cu `security.py:73-80` |
| Prag de timp | verificare pe hash-fantomă la utilizator necunoscut, **măsurată** în `tests/auth-password.test.ts` |
| TOTP | 6 cifre, 30 s, ±1 fereastră, contor consumat cu `<` strict în SQL |
| TOTP în repaus | AES-256-GCM prin `SecretBox` (`lib/crypto.ts`), cheie din `SENTINEL_SESSION_SECRET`, AAD `user:<id>`+coloană |
| Sesiune | jeton opac 256 de biți, în bază doar `sha256`; `pending_totp` coloană reală; jeton ROTIT la promovarea TOTP |
| Vârf de memorie | o singură verificare Argon2id în zbor (`MAX_CONCURRENT_ARGON2`), coadă de 16, apoi refuz — **măsurat** în `tests/auth-password-burst.test.ts` |

**Nu e livrat aici:** aplicarea lui `user_instances` în stratul de date. Tabela
de drepturi există, goală: **un utilizator nou vede zero instanțe, nu toate.**
Rutele, formularele, CSRF, limitarea de rată și CSP sunt piesa 2, mai jos.

**Nici crearea unui cont nu e livrată.** Nu există încă niciun instrument care
să scrie un rând în `users` și să înroleze al doilea factor, deci panoul nu poate
autentifica pe nimeni până nu apare unul. Validarea ASCII a numelui e deja în cod
(`lib/auth/users.ts`), ca refuzul să fie al aplicației și nu al bazei: coloana e
`ascii_bin`, iar sub un mod nestrict un nume cu diacritice ar deveni un cont
scris cu `?`, pe care nimeni nu-l mai poate retasta, cu o cheie unică peste el.
Modul strict îl pune acum aplicația, pe fiecare sesiune (vezi „Modul strict al
sesiunii" mai sus); validarea în cod rămâne fiindcă e cea care dă un mesaj.

### Trei lucruri măsurate, și unul NEMĂSURAT

**`GENERATED ALWAYS AS` nu poate ține unicitatea parțială.** MariaDB refuză și
`IF`, și `CASE`, în coloane generate, `STORED` și `VIRTUAL` deopotrivă (ERROR
1901, măsurat pe gazdă pe 13 august 2026). Deci `sessions.active_token_hash` e o
coloană obișnuită, întreținută de două triggere, cu o cheie unică pe ea: două
sesiuni ACTIVE cu același jeton sunt refuzate de bază, oricâte revocate pot
purta aceeași valoare (NULL-urile nu se ciocnesc), iar revocarea eliberează
jetonul.

**`--syntax-check` acoperă și triggerele**, contrar documentației: măsurat pe
gazdă pe 15 august 2026, MariaDB 11.8.8 pregătește `CREATE TRIGGER`. Deci
migrația asta se poate verifica pe baza de producție înainte să fie aplicată.

**Ce NU s-a măsurat: dacă Argon2id la `m=65536` încape în planul de găzduire.**
E0 cerea o rută de unică folosință care hashuiește o dată și întoarce timpul și
memoria; măsurătoarea aia nu există nicăieri în depozit, iar întrebarea e scrisă
ca decizie deschisă a operatorului în `docs/PLAN-arhitectura-distribuita.md` §7,
punctul 4. Parametrul **nu se coboară**: planul o interzice explicit și cere ca
lipsa măsurătorii să fie raportată ca atare. Dacă găzduirea refuză alocarea,
eșecul e zgomotos (eroare la hashing sau proces omorât), nu o autentificare mai
slabă.

**Ce S-A măsurat, în lipsa aceleia: cum se poartă memoria cu concurența.** Pe
Node 24, cu chiar parametrii livrați, verificări pornite simultan: 1 → 135 ms și
130 MiB rss; 8 → 1071 ms și 578 MiB; 16 → 2203 ms și 1091 MiB. Memoria crește
liniar (64 MiB per verificare) ȘI timpul crește liniar, deci concurența nu
cumpără debit și costă memoria întreagă. Pe găzduirea partajată același proces
Node servește și `/api/sentinel/sync`, deci o rafală de POST-uri pe `/login` —
cereri care nu au nevoie de niciun cont — ar putea omorî procesul care ingerează
arhiva de dovezi a TUTUROR instanțelor. De-aia `lib/auth/password.ts` are un
semafor: o singură verificare în zbor, cel mult 16 în așteptare, iar peste atât
`PasswordBusyError` — pe care ruta din piesa 2 o dă drept **503 cu
`Retry-After`**, nu 401 și nu 500, și n-o numără ca încercare eșuată. Aritmetica
serverului (nginx 5/min plus blocarea per cont) e a doua apărare, livrată în
piesa 2 ca cele trei straturi de mai jos; ea numără cereri, nu octeți.

Implementarea folosește `hash-wasm`, nu `@node-rs/argon2`, din aceeași lipsă de
măsurătoare: un modul nativ e un pariu pe ABI-ul gazdei, iar eșecul lui e la
ÎNCĂRCARE — panoul întreg n-ar porni. Formatul hashului e PHC codificat, identic
cu ce produce `argon2-cffi`, deci trecerea la modulul nativ, dacă se măsoară
vreodată că merită, nu invalidează niciun hash existent.

## Autentificarea panoului (E3b, piesa 2: rutele)

    GET  /login   → formular + jeton CSRF SEMNAT, fără stare, fără scriere în bază
    POST /login   → parola verificată → sesiune `pending_totp = 1` → 303 /totp
    GET  /totp    → formular (cere sesiunea în așteptare)
    POST /totp    → codul verificat → jeton ROTIT, `pending_totp = 0` → 303 /
    POST /logout  → sesiune revocată, cookie-uri șterse (GET → 405)

Randate pe server, **fără niciun JavaScript de client** și fără niciun `style=`.
Nu e minimalism: politica de conținut de mai jos n-are `unsafe-inline`, iar
alternativa — un nonce per răspuns — are pe un CDN un mod de eșec anume. O pagină
ajunsă în cache poartă un nonce expirat, pagina se strică pentru toată lumea
deodată, și reparația evidentă sub presiune e adăugarea lui `unsafe-inline`.
Zero JavaScript nu poate ajunge acolo.

| Proprietate | Ce e livrat |
|---|---|
| CSRF post-autentificare | jeton per sesiune, comparat cu `timingSafeEqual` |
| CSRF pre-autentificare | nonce semnat HMAC, datat, în cookie; nonce-ul gol în formular; 15 minute. **Nicio scriere în bază la afișarea formularului** |
| Alegerea între ele | există sesiune → jetonul SESIUNII; nu există → cel pre-auth. Aceeași regulă ca middleware-ul serverului |
| CSP | identică cu `deploy/nginx/sentinel-security-headers.conf`, ținută de `tests/unit/test_aggregator_csp_parity.py` |
| Cache | `no-store` pe fiecare răspuns + `force-dynamic` pe fiecare rută + antetul global din `next.config.mjs` |
| Cookie de sesiune | `HttpOnly; Secure; SameSite=Strict; Path=/` |
| Corpul formularului | mărginit la 8 KiB **la citire**, în bucăți; peste atât, 413 fără să se aloce restul |
| Coada Argon2 plină | **503 cu `Retry-After`**, niciodată 401, și nu se numără ca încercare eșuată |

**Verificările de origine ale Server Actions nu sunt un substitut.** Rutele sunt
Route Handlers, deci verificarea nici nu se aplică; iar `Origin` oricum nu spune
că formularul a fost SERVIT de noi, care e chiar ce dovedește perechea
cookie/câmp. Fără ea, o pagină ostilă postează `/login` cu credențiale alese de
ea, iar victima ajunge autentificată în contul atacatorului fără să observe.

### Limitarea de rată: trei straturi, dintre care unul e stins implicit

| Strat | Prag | Stare |
|---|---|---|
| per utilizator | 5 eșecuri / 15 min → 429 | activ |
| per sursă | 20 de eșecuri / 15 min | **stins**, dacă nu se configurează antetul |
| global | 200 de eșecuri / 15 min → 503 | activ |

**Toate trei au aceeași formă: o fereastră alunecătoare peste `login_attempts`,
iar refuzul niciunuia dintre ele nu se scrie acolo.** Regula e executabilă, nu
doar scrisă: scrierea în tabelă cere un permis emis exclusiv de `checkThrottles`
(`lib/auth/gate.ts`), iar `tests/auth-attempts-writers.test.ts` numără căile care
pot ajunge la tabelă. Până pe 17 august 2026 stratul per cont era altfel — un
contor MONOTON în `users.failed_attempts`, golit doar la capătul etapei TOTP —
și din asta ieșea o blocare permanentă la 4 cereri pe oră, cu parola corectă a
operatorului primind 429. Coloanele `users.failed_attempts` și
`users.locked_until` au rămas în schemă, dar nimic din cod nu le mai citește și
nu le mai scrie; oprirea unui cont se face cu `disabled`.

**Avertismentul, pe scurt: găzduirea servește prin CDN** (`Server: hcdn`, văzut
pe răspunsuri — `watcher/INCARCARE-HOSTINGER.md`). CDN-ul termină conexiunea,
deci procesul Node nu vede niciodată adresa clientului: singura sursă e un antet.
**Ce antet pune Hostinger, și dacă îl curăță la margine, NU s-a putut măsura de
pe mașina de dezvoltare** — nu există acces la marginea CDN-ului, iar o cerere de
probă ar arăta doar ce vede aplicația, nu dacă valoarea a fost înlocuită sau doar
transmisă mai departe.

Deci implicitul e „nu am adresa clientului", iar consecințele sunt duse până la
capăt:

* stratul per sursă **nu se aplică**. Nu „se aplică mai slab": aplicat pe o
  valoare pe care o alege clientul, ar fi mai rău decât inutil — cine trimite 20
  de încercări eșuate cu adresa operatorului în antet **blochează operatorul**,
  din afară, fără să știe nicio parolă;
* coloanele `INET6` (`login_attempts.ip`, `sessions.created_ip`,
  `users.last_login_ip`) rămân **NULL**. O coloană tipată care conține o adresă
  aleasă de atacator nu e o urmă de audit, e o minciună cu index pe ea. Valoarea
  pretinsă se scrie în `login_attempts.detail`, marcată `ip-pretins(...)`;
* compensarea e la stratul care rămâne: **plafonul per cont scade de la 10 la 5**.

**Cum se activează stratul per sursă.** Se măsoară pe gazdă ce antet sosește:

```bash
# pe gazdă, într-o rută de probă sau în jurnalul aplicației
curl -s -H 'X-Forwarded-For: 203.0.113.1' https://<domeniu>/login -o /dev/null -D -
```

Dacă antetul ajunge la aplicație **cu valoarea inventată de tine**, marginea nu-l
curăță și nu se poate avea încredere în el. Dacă sosește un antet pe care
marginea îl SCRIE (și care ignoră ce a trimis clientul), numele lui se pune în
`AGGREGATOR_CLIENT_IP_HEADER`. Aplicația mai verifică o dată, la fiecare cerere,
efectul și nu declarația: **dacă antetul declarat sosește ca listă** (`a, b`),
înseamnă că marginea a adăugat la ce era, nu că a înlocuit — și atunci nu se are
încredere în el, oricât ar spune configurația.

**Ce costă plafonul global, spus pe față:** e o pârghie de negare de serviciu
prin construcție — cine produce destule eșecuri închide autentificarea pentru
toți, inclusiv pentru operator. Nu există variantă fără costul ăsta; un plafon
care nu se aplică nu e un plafon. Atenuările: pragul e sus, răspunsul e 503 cu
`Retry-After` (nu o blocare), fereastra e alunecătoare și scurtă, iar refuzul
**nu se scrie** în `login_attempts` — altfel plafonul, o dată atins, s-ar hrăni
singur și nu s-ar mai stinge niciodată. **Dacă pragul se dovedește prea jos în
practică, se ridică; nu se scoate.**

Aceeași alegere are și refuzul per cont, și e a doua față a aceleiași monede:
fără un strat per sursă în care să te poți încrede, un atacator care ȘTIE numele
contului îl poate ține afară **cât timp susține 5 eșecuri la fiecare 15 minute**
(~20 de cereri pe oră). Ce s-a scos e „permanent" și „gratuit", nu „posibil":
fereastra se golește singură la 15 minute după ce atacatorul se oprește, fără
nimic de făcut pe gazdă. Pe server, `security.py` are ambele straturi tocmai ca
să nu fie așa. Aici nu se poate, iar asta e o constatare, nu o omisiune.

**Decizia care rămâne a operatorului**, fiindcă e un compromis între două
proprietăți reale, nu un defect: refuzul per cont s-ar putea aplica DOAR
parolelor greșite, lăsând o parolă corectă să treacă mai departe la al doilea
factor. Atunci nimeni care nu știe parola n-ar mai putea ține operatorul afară —
important, fiindcă panoul agregatorului n-are ieșire de urgență, cum are cel de
pe server prin tunelul ssh. Costul: cine tocmai a ghicit parola în timpul unei
rafale ar putea s-o folosească imediat, nu peste o fereastră. Azi e implementată
varianta care refuză și parola corectă.

### Verificarea pe gazdă, după publicare — ce NU se poate dovedi de aici

Suita probează antetele citindu-le din răspunsuri REALE
(`tests/auth-routes.test.ts`), dar niciun test de pe mașina de dezvoltare nu
poate spune că **marginea CDN-ului** le respectă. Proba e cea din
`watcher/INCARCARE-HOSTINGER.md`, adaptată:

```bash
curl -s -D - -o /dev/null https://<domeniu>/login | grep -i -E 'cache-control|content-security|set-cookie|x-nextjs-cache'
sleep 6
curl -s -D - -o /dev/null https://<domeniu>/login | grep -i 'set-cookie'
```

`sentinel_csrf` **TREBUIE să difere între cele două cereri**: e valoarea care se
schimbă la fiecare răspuns, deci două valori identice înseamnă o pagină servită
din cache — iar o pagină de login din cache poartă un jeton CSRF care nu e al
browserului care o primește. Antetele arătate de `curl` sunt un semn bun; dovada
o dă valoarea care se schimbă.

## Autorizarea multi-instanță și conturile (E3b, piesa 3)

    GET  /api/panel/instances        instanțele pe care le vede contul
    GET  /api/panel/incidents        incidentele lor  (?limit=<n>, cel mult 200)
    GET  /api/panel/incidents/<id>   un incident, cu cronologia lui

Panoul propriu-zis — HTML — e E3c. Aici e stratul de date de sub el, cu
autorizarea în el.

**Autorizarea e în stratul de date, nu în interfață.** Fiecare funcție din
`lib/data/` primește `allowedInstanceIds` ca parametru obligatoriu, iar fiecare
interogare poartă `WHERE instance_id IN (?, …)` cu instanțele legate ca
parametri. Lista vine dintr-un `SELECT` peste `user_instances`, făcut la FIECARE
cerere: un drept retras dispare la cererea următoare, nu la următorul login —
sesiunile trăiesc 12 ore. Domeniul e un obiect înregistrat, nu un tablou de
șiruri: unul fabricat (dintr-un parametru de URL, dintr-un câmp de formular)
aruncă la execuție, iar un apel fără el nu compilează.

**Un cont nou vede ZERO instanțe.** Absența unui rând în `user_instances`
înseamnă „niciuna", nu „toate"; drepturile se dau cu `grant`, explicit.

**404, niciodată 403.** Un incident al unei instanțe pe care contul n-o vede
primește exact răspunsul unui id care nu există nicăieri — același cod, același
corp, aceleași antete. Un 403 ar confirma că obiectul există, iar cine cere
id-uri la rând ar afla harta celuilalt server fără să vadă vreun rând.

### Conturile

Se creează DOAR de pe linia de comandă, ca pe serverul monitorizat
(`sentinel web --create-admin`). Un panou care poate crea conturi transformă o
compromitere a interfeței într-o preluare.

```
npm run user -- create <utilizator> --role owner|operator|viewer
npm run user -- enroll-totp <utilizator>
npm run user -- grant  <utilizator> <instanță> [--role ...]
npm run user -- revoke <utilizator> <instanță>
npm run user -- list
```

**Parola nu se dă pe linia de comandă** — `argv` se vede în lista de procese a
găzduirii partajate și rămâne în istoricul shellului. Unealta REFUZĂ un
`--password` în loc să-l ignore: valoarea e deja publicată în clipa aia. Se
tastează, fără ecou, sau vine printr-o conductă:

```
pass show panou/ana | npm run user -- create ana --role owner
```

Cere `SENTINEL_SESSION_SECRET` în mediu (cifrează secretul TOTP în repaus) și
datele de conectare, ca `npm run migrate`.

Înrolarea celui de-al doilea factor e în același pas și **se confirmă cu un cod
adevărat**: URI-ul `otpauth://` și secretul base32 se afișează o singură dată,
iar contul rămâne fără al doilea factor — deci nu se poate autentifica — până
când cineva dovedește că poate produce un cod din el. Dacă pasul ăla eșuează,
comanda iese cu cod nenul și spune ce să rulezi. Fără QR: ar fi însemnat o
dependență nouă pentru o operație care se face de câteva ori în viața unei
instalări.

Codul folosit la confirmare e CONSUMAT (contorul anti-reluare), deci prima
autentificare cere codul următor. `npm run user -- list` arată `2FA NU` pentru
conturile la care înrolarea n-a fost dusă la capăt și `nicio instanță` pentru
cele care ar vedea un panou gol — ambele stări arată, altfel, ca un cont sănătos.

## Cheile de instanță

Nu sunt în mediu, ci în tabela `instances`, cifrate în repaus. Ruta de ingestie
caută cheia după antetul `X-Sentinel-Instance`, o decriptează cu
`SENTINEL_AGGREGATOR_SECRET` și verifică semnătura cu ea. O instanță fără cheie
instalată primește **500 „nu sunt configurat"**, nu 401 — cele două cer reacții
diferite, iar codul de stare e tot ce se vede dintr-un `curl`.

`enabled = 0` oprește ingestia unei instanțe fără să-i șteargă istoria.

## Înregistrarea unei instanțe — procedura completă

Fără pasul ăsta ruta răspunde `500 nu sunt configurat` oricui, la infinit, și
nicio configurare pe serverul monitorizat nu o schimbă: cheia se instalează
AICI.

```bash
npm run instance -- list
npm run instance -- register <instance_id> [--label "text"]
npm run instance -- rotate   <instance_id>
npm run instance -- disable  <instance_id>
npm run instance -- enable   <instance_id>
```

**Secretul nu se dă niciodată ca argument.** `argv` se vede în lista de procese
(`ps`, `/proc/<pid>/cmdline`) — pe o găzduire partajată, de către alți
utilizatori — și rămâne în istoricul shellului. Instrumentul îl citește din
`SENTINEL_SHIP_SECRET`, dintr-o conductă, sau de la un prompt care nu afișează
nimic. Dacă îl scrii totuși ca argument, comanda se oprește și îți spune să-l
rotești.

### 1. Pe serverul monitorizat: ce trebuie luat de acolo

```bash
cat /etc/sentinel/instance_id        # identitatea; 32 de caractere hexa
grep '^SENTINEL_SHIP_SECRET=' /etc/sentinel/secrets.env
```

Dacă secretul nu există încă, generează-l și adaugă-l în `secrets.env` (nu în
`sentinel.yaml`), apoi repornește expeditorul:

```bash
openssl rand -hex 32
```

E **altă** valoare decât `SENTINEL_BEACON_SECRET`, dinadins: o cheie comună ar
însemna că root pe un server poate fabrica loturi în numele altuia.

### 2. Pe agregator: înregistrarea

Migrațiile întâi (`npm run migrate`), altfel nu există tabela. Apoi, cu secretul
adus dintr-o magazie de parole și fără să treacă prin istoric:

```bash
pass show sentinel/<instanță>/ship | npm run instance -- register <instance_id>
```

sau, dintr-un terminal, cu prompt ascuns:

```bash
npm run instance -- register <instance_id>
```

Valoarea trebuie dată **exact** cum o citește serverul: fără ghilimele, fără
spații la capete și fără sfârșituri de linie. `sentinel/config.py` le taie când
citește `secrets.env`, deci o valoare cu ghilimele ar fi sigilată aici altfel
decât e semnată acolo, iar fiecare lot ar primi 401 — imposibil de deosebit de o
cheie greșită. Instrumentul refuză o astfel de valoare în loc s-o repare tăcut,
iar refuzul spune ce e în neregulă cu forma, niciodată valoarea.

„Spațiu" înseamnă aici ce consideră **Python** spațiu, nu ce consideră
JavaScript: cele două clase diferă, iar diferența e ținută în acord de
`tests/unit/test_aggregator_secret_form.py::test_what_the_tool_seals_is_what_the_server_signs`,
care trece un corpus comun prin `load_secrets` real și prin instrument.

Comanda scrie rândul și apoi **citește secretul înapoi pe drumul rutei**. Linia
`confirmat prin citire înapoi` înseamnă că sigiliul chiar se deschide cu
`SENTINEL_AGGREGATOR_SECRET`-ul acestei instalări; fără ea, nu s-a dovedit nimic.

### 3. Verificarea

```bash
npm run instance -- list
```

`cheie ok` = sigiliul se deschide. `CHEIE ILIZIBILĂ` = `SENTINEL_AGGREGATOR_SECRET`
a fost rotit după înregistrare, sau rândul a fost umblat — ruta va răspunde 500
pentru instanța aia; repară cu `rotate`. `FĂRĂ CHEIE` = rândul există dar nu a
fost niciodată înregistrat complet.

### 4. Pe serverul monitorizat: pornirea expedierii

`ship.enabled: true` și `ship.url` în `/etc/sentinel/sentinel.yaml`, apoi
`systemctl restart sentinel-shipper`. Verificarea `ship:lag` din `/dashboard`
spune dacă loturile chiar intră.

### Rotirea, oprirea, și ce NU face instrumentul

`register` pe o identitate deja înregistrată **eșuează** și trimite la `rotate`:
cine rulează comanda a doua oară, crezând că prima n-a mers, nu are voie să
invalideze o cheie funcțională. Rotirea e o comandă separată, cerută explicit, și
merge și pe o instanță oprită — exact ce faci după o compromitere.

`disable` oprește ingestia unei instanțe (ruta îi refuză loturile cu 401) și îi
**păstrează istoria**. Nu există ștergere: `audit_entries` e o arhivă, iar
rândurile unei instanțe despre care nu mai spune nimic nimic ar fi mai rele decât
un rând marcat oprit.

## Verificarea lanțului de audit

`docs/PLAN-arhitectura-distribuita.md` §5 scria că sistemul „nu verifică
înlănțuirea și nici nu are cu ce". Acum are: serverul expediază `id`, `prev_hash`
și `entry_hash` neatinse, iar agregatorul cere ca `prev_hash`-ul fiecărui rând să
fie `entry_hash`-ul celui dinainte. E o dovadă pe care mașina monitorizată **nu
și-o poate da singură** — root pe ea poate rescrie și jurnalul, și verificatorul.

**Când se verifică:**

* **la fiecare lot**, incluzând joncțiunea cu lotul dinainte (acolo ar tăia
  cineva; o verificare doar în interiorul lotului ar găsi un lot perfect legat);
* **programat**, peste tot ce e stocat: `npm run verify-chain`, din cron. O
  ruptură poate fi introdusă și de altcineva decât conducta.

**Ce prinde:** ștergerea unui rând, inserarea, reordonarea.
**Ce NU prinde:** falsificarea informată. Cine are root pe serverul monitorizat
poate recalcula un lanț întreg, fals dar consistent, și îl poate expedia.
Verificarea e structurală: nu recalculează `entry_hash` din conținut, fiindcă
asta ar cere identitate de octeți între serializatorul Python al serverului și
unul TypeScript — vezi `sentinel/report/signing.py`. §5 spune același lucru;
nimic de aici nu pretinde mai mult.

**Un gol nu e o ruptură.** Un rând al cărui predecesor n-a ajuns încă arată exact
ca unul al cărui predecesor a fost șters. Le separă filigranul confirmat: sub el
nu mai poate exista niciun rând pe drum, fiindcă expeditorul trimite în ordinea
`id` și cursorul avansează doar pe ecou. Peste filigran, aceeași nepotrivire e
`unknown`, nu ruptură. Golurile de NUMEROTARE nu contează deloc — lanțul se leagă
prin hash, iar `audit_log.id` poate avea goluri de la tranzacții anulate.

**Un lot cu lanțul rupt SE PREIA.** Refuzul ar fi transformat detecția într-o
pârghie de negare a dovezilor: cine poate rupe lanțul o dată ar opri prin asta
toate expedierile viitoare, fix când arhiva începe să conteze. Rândurile intră,
filigranul se ecouă, ruptura se consemnează.

**Unde se consemnează:** `audit_chain_state`, un rând per instanță. **Lipsa
rândului înseamnă „niciodată verificat"** — nu există valoare implicită care să
semene cu „bine".

Cine are voie să scrie ce, fiindcă aici a fost un defect real: `status` e o
propoziție despre TOT lanțul, nu despre lotul care tocmai a sosit. O verificare
de la ingestie pornește deasupra unei rupturi vechi, n-are cum s-o vadă, și **nu
are autoritatea** să scrie `ok` peste ea — altfel o ruptură reală ar fi ștearsă
de următorul lot, adică în cel mult un `ship.interval_s`. Deci:

| verdict | ce scrie |
|---|---|
| ruptură (oricine o vede) | `status='broken'`, rândul rupt, momentul PRIMEI observații |
| `ok` de la capătul de jos | `status='ok'`, curăță pointerul rupturii, mută capătul de jos |
| fereastră care n-a pornit de jos | doar `verified_through` (monoton) și ultima rulare |

O ruptură se poate „vindeca" doar printr-o trecere completă care nu mai găsește
nimic. `broken_at` **nu se șterge niciodată**: „copia asta a fost văzută ruptă
odată" e un fapt permanent despre ea. `status='ok'` cu `broken_at` nenul se
citește exact așa — „acum se leagă, dar a fost ruptă atunci".

**Capătul de jos contează prin DIRECȚIE.** Dacă urcă, rândurile de la început au
dispărut (trunchiere). Dacă coboară, a sosit istorie mai veche — o cale pe care
serverul o recomandă singur când operatorul se lovește de pragul de backfill —
și nu e o ruptură. Dacă rămâne pe loc iar `prev_hash`-ul lui se schimbă, e o
rescriere.

### Alertarea NU e livrată

Agregatorul nu are niciun canal de alertare. Martorul are Telegram
(`watcher/lib/telegram.ts`); ăsta nu. Deci o ruptură detectată azi ajunge în trei
locuri, toate slabe:

1. rândul din `audit_chain_state` — durabil, dar nimeni nu-l citește singur;
2. o linie în jurnalul găzduirii (`LANȚ RUPT`) — jurnalul ăla nu se citește;
3. codul de ieșire 1 al lui `npm run verify-chain` — util DOAR dacă operatorul
   își leagă cronul de el (poștă la ieșire non-zero, de pildă). Nu e livrat aici.

Ce s-a respins, și de ce: **refuzul lotului** (ar fi făcut din detecție o pârghie
de negare a dovezilor); **un al doilea canal Telegram în agregator** (planul cere
explicit ca escaladarea să treacă prin canalul existent, iar un canal nou ridică
întrebări de credențiale și de rată care nu se rezolvă în graba asta).

**Rămâne pentru E3**, odată cu panoul: `audit_chain_state` e citit acolo, iar
starea `broken` devine vizibilă. Până atunci, verificarea PRODUCE dovada și o
păstrează, dar nu o duce la operator.

## De citit înainte de a schimba ceva

* `migrations/0001_core.sql` — cele trei reguli (identitate reală, fără chei
  străine, fără recrearea indexurilor unice parțiale ale serverului) sunt scrise
  în capul fișierului, cu motivul fiecăreia. Tot acolo e și de ce ingestia nu
  poate folosi `ON DUPLICATE KEY UPDATE` pe `audit_entries`.
* `lib/migrate.ts` — de ce se înregistrează instrucțiuni, nu fișiere.
* `lib/crypto.ts` — de ce AAD, și ce se pierde fără el.
* `lib/db.ts` — de ce pool-ul e de 8 și nu de 2000.
* `lib/ingest.ts` — de ce se numără rândurile în loc să se creadă `INSERT`-ul, și
  ce înseamnă exact filigranul ecouat.
* `app/api/sentinel/sync/route.ts` — ordinea celor trei verificări, și de ce un
  flux necunoscut nu poate primi 200.
* `lib/chain.ts` — cum se deosebește un gol de o ruptură, și de ce un lot cu
  lanțul rupt se preia în loc să fie refuzat.
