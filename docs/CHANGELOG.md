# Changelog

## 0.22.4 — Scanerul de pachete știe pe ce distribuție e, iar eșecul lui nu mai e un zero

Instalatorul trece pe Ubuntu de pe 27 august, dovedit pe un VM real. Runtime-ul
nu trecea: `dnf updateinfo` era singurul scaner de pachete de sistem, iar
orchestratorul îi logha eroarea și mergea mai departe. Pe Ubuntu, scanarea de
vulnerabilități de sistem era deci **moartă**, iar panoul arăta verde cu zero
vulnerabilități — absența unei constatări citită ca sănătate, la scara
produsului.

* **Familia vine din configurație, nu dintr-o a doua detecție.** `distro_detect`
  decide la instalare, `install.sh` scrie `platform.family` în `sentinel.yaml`,
  Python citește de acolo. Nimic din runtime nu se uită în `/etc/os-release`:
  două detecții sunt două surse de adevăr, iar cele două se contrazic exact pe
  gazda unde contează. O valoare necunoscută e **refuzată la încărcare**, nu
  tolerată prin revenirea la implicit;
* **O configurație fără secțiunea `platform` rămâne `rhel`, explicit.**
  `install_config` nu suprascrie o configurație vie, deci gazda de producție nu
  primește cheia de la sine — implicitul e singurul lucru care îi păstrează
  comportamentul. Iar numele scanerului de pe `rhel` rămâne **`dnf`**: cheia
  `scan:last:dnf` din `selfcheck_state` are istoric din 21 august, și o
  redenumire l-ar fi aruncat, exact cum era să se întâmple la `audit:records`;
* **Pe debian rulează `apt-get -s dist-upgrade`, filtrat pe depozitul de
  securitate.** Ce se pierde față de RHEL, spus pe față: `apt` nu poartă CVE și
  nu poartă severitate, deci constatările ies cu `cve: null` și cu severitatea
  `medium` marcată `severity_known: False` — aceeași convenție pe care
  `trivy_fs` o folosește pentru `UNKNOWN`. Calea de patch eșuează închis fără o
  regulă scrisă pentru ea: fără CVE nu există potrivire KEV, deci nu există plan;
* **Un scaner care nu poate rula scrie un rând `failed` și nu rezolvă nimic.**
  Rândul din `scans` se deschide înainte de orice apel, sub numele pe care îl dă
  familia. Backend-ul apt refuză să raporteze „curat" fără indexuri de pachete,
  fără index de securitate, sau când nu înțelege o linie `Inst` — o linie sărită
  în tăcere nu e doar una neraportată, `mark_resolved_absent` i-ar închide
  constatarea;
* **`_run` a rămas fără implicit pentru `timeout`.** Cu două backend-uri, un
  implicit e plafonul unuia moștenit tăcut de celălalt — același defect scos din
  `trivy_fs._run`, unde bugetul unei rulări devenise unul per apel.

Neverificat, și rămâne așa până există o gazdă Debian de probă: formatul liniei
`Inst`, prezența câmpului de origine, numele buzunarelor de securitate și
conținutul lui `/var/lib/apt/lists`.

## 0.22.3 — Contul era corect, cheia era greșită; iar autodiagnosticul spunea „ok"

Trei lucruri măsurate pe gazdă pe 25 august 2026, toate cu aceeași formă:
mecanismul confirma ce s-a scris undeva, nu ce se întâmplă.

* **Cheia de livrare are implicit, ca și contul.** `sentinel-deploy` (uid 1002)
  autorizează exact o cheie — `~/.ssh/sentinel_deploy` —, iar cheia numită în
  invocația folosită până acum are altă amprentă și primește `Permission denied
  (publickey)`. Implicitul de cont livrat singur lăsa deci o singură ieșire la
  îndemână: `--user` înapoi pe contul operatorului, adică filtrul inert la loc.
  Cheia implicită LIPSĂ e doar un avertisment — un agent ssh sau un
  `IdentityFile` din `~/.ssh/config` sunt tot atât de legitime;
* **`history:filter` întreabă acum datele, nu configurația.** Pe listă goală
  ieșea `ok` înainte de orice SQL. Citit pe gazdă: `sentinel.yaml` din 20 august
  n-are secțiunea `history:`, iar `sentinel.yaml.new` din 25 august nu o are nici
  el — filtrul n-a ajuns niciodată acolo —, în timp ce contul de deploy scrisese
  **1 266 de comenzi fără terminal în 48 de ore**. Verificarea scrisă ca să
  deosebească intenția de efect raporta `ok` peste exact starea pe care exista
  s-o vadă.
  Acum se întreabă *cine scrie comenzi fără terminal și cu ce ritm* — peste
  **20 000 într-o oră** e automatizare (un deploy face 405 777 în 140 s; cea mai
  încărcată oră de om măsurată are 2 438) — și, separat, dacă `sentinel.yaml.new`
  cere un cont pe care configurația încărcată NU-l are. Comparația e orientată
  dinadins: încărcată care aruncă mai mult decât cere `.new` e o alegere a
  operatorului peste un `.new` rămas în urmă, iar pe egalitate constatarea ar fi
  rămas roșie pentru totdeauna imediat ce cineva adaugă contul de mână — exact
  reacția pe care mesajul o cere. Felia citită e mărginită la 60 000 de
  comenzi (`EXPLAIN` pe gazdă: 4 239, față de 50 283 nemărginit) și raportul
  spune ce interval a acoperit;
* **`--list-sessions` nu mai costă 18,4 secunde.** Măsurat: `Execution Time:
  18395.833 ms`, trei procese de fundal, 243 723 de citiri din heap, agregare
  peste 2,85 milioane de rânduri — plătite exact înainte de curățare și pe o
  gazdă care în aceeași zi a dat `504` pe panou, deci unealta de curățat putea
  lua jos gazda pe care o curăță. Numărătoarea se oprește acum la 2000 pe
  sesiune (`2000+` în coloană), cifra rămâne luată din TABELĂ, iar unde nici
  atât nu încape coloana devine `?` — „n-am măsurat" nu e „zero".

Mărunte, din aceeași rundă:

* proba de colație a replicii citea `Number(null)` ca `0`, iar trei din cele
  patru răspunsuri sunt așteptate `0`: pica închis din noroc, fiindcă al
  patrulea așteaptă `1`. Acum ce nu e număr e refuzat pe față;
* aceeași probă rulează și în modul uscat, unde **nu aruncă**: cifra pe care
  operatorul o citește ca să decidă e validată, iar dacă serverul nu aplică
  regula, raportul o spune în loc să oprească o numărătoare inofensivă;
* **`0028_commands_purged.sql` se aplică ÎNAINTE de prima rulare** a scriptului,
  altfel `--list-sessions` moare cu `column s.commands_purged does not exist`
  (verificat pe gazdă). Scris acum acolo unde îl citește operatorul.

## 0.22.2 — Filtrul era corect și se uita la contul greșit

`0.22.1` a livrat filtrul de istoric și l-a probat comparând două nume din
depozit. Măsurat pe gazdă pe 25 august 2026, filtrul ar fi șters **1 143 din
2 978 485 de rânduri**: furtuna de 405 777 de comenzi nu era pe
`sentinel-deploy`, era pe contul de logare al operatorului, fiindcă
`scripts/deploy.sh` cerea `--user` iar `auid` e uid-ul de LOGARE și
supraviețuiește lui `sudo`.

* **Deploy-ul rulează implicit ca `sentinel-deploy`**, în `scripts/deploy.sh` și
  `scripts/deploy.ps1`. Contul e cel pe care pasul 36 al instalatorului îl
  creează cu `NOPASSWD: ALL` și cel numit în `history.skip_command_accounts`;
* **filtrul prinde și ortografia numerică**. Același cont ajunge în tabelă și ca
  `auid` numeric — **87 935 de rânduri** scrise ca `username = '1000'` — când
  nici auditd, nici `pwd` nu rezolvă un nume. Conturile configurate se rezolvă
  la uid la încărcarea configurației, iar un cont care nu se rezolvă e RAPORTAT,
  nu înghițit;
* **autodiagnostic `history:filter`**: citește cheia înapoi din configurația
  încărcată și raportează conturile, dacă se rezolvă, și dacă s-au SCRIS rânduri
  pe care regula le interzice. Lista goală e o stare validă și apare ca atare;
* **mod pe sesiune** în amândouă scripturile de curățare, plus `--list-sessions`
  ordonat după numărul de comenzi. Istoricul de dinaintea filtrului nu e pe
  contul de automatizare și e amestecat cu diagnosticele operatorului: granița
  se citește, nu se codifică;
* **`commands_purged`** pe `login_sessions` și pe `login_session_entries`.

### Verificarea care nu verifica nimic

`docs/ISTORIC-SESIUNI.md` propunea

    journalctl -u sentinel-ingest | grep commands_skipped

și potrivea ÎNTOTDEAUNA: `commands_skipped` e mereu în `extra`, iar
`JSONFormatter` scrie și zerourile. Nu deosebea «am aruncat 405 777 de rânduri»
de «secțiunea n-a fost îmbinată niciodată» — adică exact întrebarea. Pe gazdă
existau, din 20 august, ȘI `sentinel.yaml.new` ȘI `inventory.yaml.new`
nefuzionate, deci avertismentul lui `install_config` e demonstrat că nu se
citește.

Și testul care păzea filtrul compara numele din `install.sh` cu numele din
`sentinel.yaml.tmpl` — două fișiere din depozit, amândouă în dezacord cu gazda.
A fost înlocuit cu unul care asertează pe DECIZIE: dându-se fluxul unui deploy
adevărat, proiecția aruncă rândurile și le numără.

### `command_count` nu mai pretinde rânduri care nu există

`command_count` e un contor memorat al rândurilor din `session_commands`, iar
panoul și rezumatul de închidere de pe Telegram îl citesc pe el. După prima
curățare, sesiunea 2521 ar fi arătat **«558 079 comenzi» deasupra unui tabel
gol** — fix eșecul pentru care există `_refresh_counters`.

Ce s-a ales, și de ce amândouă: `command_count` se **renumără din tabelă**
(invariantul rămâne cel de dinainte), iar cât a căzut intră în
**`commands_purged`**. «Câte rânduri sunt» și «câte au fost» sunt două afirmații
diferite, iar a doua e chiar faptul din care s-a născut filtrul — ștearsă,
peste trei luni nimeni nu mai poate răspunde la «de ce e filtrul ăsta aici».

Pe replică se scrie numai `commands_purged`: `command_count` de acolo e o
afirmație a gazdei, adusă de expediere și rescrisă la fiecare lot.

### Cele trei motoare dau acum același răspuns

`is_interactive` făcea `.strip()`, niciun predicat SQL nu-l făcea, iar colația
`utf8mb4_unicode_ci` a replicii făcea `IN` și `REGEXP` insensibile la majuscule.
Măsurat pe cele trei implementări:

| tty | filtrul viu | curățarea pe PG | replica |
|---|---|---|---|
| `' pts0'` | păstrat | **șters** | păstrat |
| `'pts0\n'` | păstrat | **șters** | păstrat |
| `'PTS0'` | aruncat | șters | **păstrat** |

Marginile de spațiu sunt acum în chiar tipar — `^[ \t\n\r\f\v]*(pts[0-9]+|tty[0-9]+)[ \t\n\r\f\v]*$`,
literalmente același șir în toate trei — iar predicatul replicii poartă `COLLATE
utf8mb4_bin`. Colația nu e crezută pe cuvânt: înainte de prima ștergere,
scriptul întreabă serverul cu chiar construcția din predicat și se oprește dacă
răspunsul nu e cel al gazdei.

## 0.22.1 — Un deploy nu mai scrie 405 777 de rânduri

Măsurat pe gazdă: o singură livrare a produs **405 777 de comenzi în 140 de
secunde** — `systemctl` de 320 591 de ori și `sleep` de 173 376, adică buclele
de așteptare ale instalatorului —, iar replica de pe agregator a crescut de la
83 MB la **909 MB în câteva ore**.

* **`history.skip_command_accounts`** în `sentinel.yaml` (implicit
  `sentinel-deploy`): comenzile conturilor de automatizare **rulate fără
  terminal real** nu mai ajung în `session_commands`. Lista goală înseamnă „nu
  se aruncă nimic", adică exact comportamentul de dinainte;
* **rândurile aruncate se numără** și ajung în jurnal, ca `commands_skipped` —
  fără contor, „n-a rulat nimeni nimic" și „am aruncat 405 777 de rânduri
  conform politicii" ar arăta identic;
* **două scripturi pentru istoricul deja strâns**, uscate implicit și în tranșe
  de 5000: `scripts/purge-automation-commands.py` (gazdă, PostgreSQL) și
  `npm run purge-automation` (replică, MariaDB). Raportează mărimea înainte și
  după, și renumără ce a rămas în loc să creadă codul de retur al lui `DELETE`.

### Filtrul e pe terminalul COMENZII, nu pe cont

Asta e miezul, nu un detaliu de implementare. O sesiune devine `interactive`
abia la prima comandă cu `tty` real, iar alerta de logare cere `interactive =
true`. O regulă „tot ce rulează contul X" ar fi aruncat și comanda aia: sesiunea
n-ar fi fost promovată niciodată, alerta n-ar fi plecat niciodată, iar contul de
automatizare — care are `sudo NOPASSWD: ALL` — ar fi devenit **o cale de intrare
tăcută**, exact acolo unde s-ar uita cineva care știe că există.

Cu regula pe `tty`, `ssh sentinel-deploy@gazdă` cu shell adevărat capătă `pts0`:
comenzile se păstrează, sesiunea se promovează, alerta pleacă.

### Ce NU s-a schimbat

**Regulile auditd.** Un `-F auid!=<uid>` ar fi oprit emisia din nucleu și ar fi
făcut contul complet neînregistrat. Jurnalul de pe disc rămâne sursa completă —
cu fereastra lui de rotație, care e scrisă acum în
[ISTORIC-SESIUNI.md](ISTORIC-SESIUNI.md).

**Rândurile de sesiune.** „S-a deschis o sesiune de deploy" e faptul cu valoare
de securitate; cele ~161 de sesiuni nu ocupă nimic.

### Ce trebuie făcut de mână pe o gazdă care rulează deja

Instalatorul nu rescrie un `sentinel.yaml` existent — scrie `sentinel.yaml.new`
și avertizează. Până când secțiunea `history:` e mutată de mână, lista e goală,
iar goală înseamnă că **nu se aruncă nimic**.

## 0.22.0 — Cine s-a logat, și ce a rulat

Sentinel vedea cine BATE la ușă — 9200 de încercări eșuate la două zile — și nu
vedea nimic din ce se întâmpla după ce cineva intra. Acum vede amândouă.

* **alertă pe Telegram la fiecare sesiune interactivă**, cu rezumat la închidere
  și butoane „am văzut" / „nu sunt eu". Netăcibilă, ca `panic` și `watchdog`;
* **istoricul complet al comenzilor** — fiecare `execve` dintr-o sesiune cu
  login, cu argumente, terminal și proces părinte. Nelimitat pe gazdă, 180 de
  zile pe agregator;
* **butonul „nu sunt eu"** blochează adresa ȘI închide sesiunea, refuzând să
  blocheze o adresă din allowlist;
* **pagina „Sesiuni"** în panoul extern;
* **cont separat pentru automatizări** (`sentinel-deploy`), pasul 36 al
  instalării;
* **autodiagnostic pentru înregistrările pierdute de nucleu**.

Totul e descris în [ISTORIC-SESIUNI.md](ISTORIC-SESIUNI.md), inclusiv ce NU se
înregistrează.

### Numărul care schimbă așteptările

**O logare interactivă produce ~630 de comenzi.** Nu e o eroare: un shell de
login sursează `/etc/profile.d/*`, iar `xargs`, `grep` și `tclsh` apar de câte 76
de ori fiecare. Un deploy produce **~405 000**, în două minute — buclele de așteptare ale
instalatorului: `systemctl is-active` de 320 591 de ori, `sleep` de 173 376.

De-aia lista implicită din panou e de SESIUNI, nu de comenzi, iar alerta pleacă
numai pentru sesiunile cu terminal: măsurat pe șapte zile, gazda a avut 557 de
sesiuni fără terminal și 29 cu. Un mesaj pe fiecare ar fi fost ~80 pe zi, dintre
care 75 despre propriile automatizări — iar un canal cu optzeci de mesaje pe zi
se oprește într-o săptămână.

### Trei defecte în cod care rula deja

Găsite construind asta, nu căutându-le:

* `username` era **gol la fiecare logare reușită** — câmpurile îmbogățite ale
  lui auditd (`AUID="…"`) erau aruncate, fiindcă `_FIELD` cerea chei numai din
  litere mici;
* `(unknown)` — contul inventat de fiecare atac brute-force, 9200 la două zile —
  ar fi devenit un nume de utilizator, primul în orice clasament;
* `res` înghițea ghilimeaua de închidere: `success'UID="root"` în loc de
  `success`. Verificarea de reușită **respingea fiecare logare prin sshd**.

### Și trei pe care le-am făcut noi

Scrise fiindcă `CLAUDE.md` cere ca tiparul să fie citibil:

* `USER_END` citit ca ieșire din sesiune. E perechea lui `USER_START` — PAM
  deschide un strat pentru fiecare `sudo`. **1534 de comenzi orfane din 14 157**,
  plus un rând-fantomă la fiecare închidere în plus;
* `terminal` din `USER_LOGIN` citit ca terminal. E numele SERVICIULUI: chiar cu
  pty forțat scrie `ssh`. Fiecare sesiune ieșea neinteractivă, deci alerta n-ar
  fi plecat niciodată — iar tăcerea aia arată exact ca „nu s-a logat nimeni";
* `$2 - interval` fără cast. Postgres deduce `interval` pentru parametru, iar
  comparația devine `timestamptz >= interval`. **Ingestia a fost picată douăzeci
  de minute, pentru toate sursele.**

Ultimul, plus un `json` neimportat care a oprit coada de notificări întreagă, au
trecut de suita verde. Cauza comună: dublele de test primesc SQL-ul ca text și
valorile ca obiecte Python — nimic din ele nu leagă tipuri, deci nimic nu poate
observa că baza n-ar accepta perechea. De acolo a ieșit
`tests/security/test_sql_parameters_are_typed.py`, care caută în sursă ce un
dublu nu poate vedea.

### Ce nu se înregistrează, spus pe față

`docker exec -it <container> bash` dă un shell ale cărui comenzi NU apar:
procesele din container n-au `auid`. Intrarea în container se înregistrează, cu
tot cu argumente; ce urmează, nu. Închiderea găurii ar însemna auditarea
fiecărui `execve` de pe gazdă — zeci de mii pe oră, adică exact ce refuză antetul
fișierului de reguli cu „aici mor seturile de reguli audit".

Iar redactarea secretelor din `argv` e o listă de tipare, nu o garanție: un token
pus ca argument pozițional sau o parolă care arată ca un cuvânt obișnuit trec
întregi. `docs/SECURITATE.md` §8b spune exact ce nu prinde.

## 0.21.0 — Rezumatul care nu mai minte

Panoul agregatorului avea două grafice: evenimente pe oră și un clasament de
surse. Cifrele din ele erau **de zece până la douăzeci de ori mai mici decât
realitatea**, iar asta nu se vedea nicăieri: barele erau proporționale între
ele, axa pornea de la zero, orele lipsă erau marcate. Un raport care minte
liniștit.

    interval   server                 agregator
    04:00      6 rânduri, 1385 ev     5 rânduri,   60 ev
    05:00      6 rânduri,  977 ev     5 rânduri,   22 ev
    07:00      6 rânduri, 1312 ev     6 rânduri,   17 ev

### Cauza: un interval scris de două ori, expediat o dată

`maintenance_service` scrie agregatul pentru fereastra SCURSĂ, nu pentru ora
încheiată — raportul lui spune „12 rânduri pe 0,9h". Deci ora 04:00 e scrisă o
dată la 04:56, cu cât se adunase, și COMPLETATĂ la 05:56.

Cursorul expedierii mergea strict pe `bucket`: odată ce ora se încheia după ceas,
rândurile plecau — versiunea parțială — iar cursorul trecea dincolo și nu se mai
întorcea niciodată.

Comentariul din `shipper.py` scria pe față presupunerea pe care se sprijinea:
*„dacă serverul ar recalcula vreodată un interval DUPĂ ce a fost expediat,
schimbarea aia n-ar mai pleca — mentenanța își încheie intervalele înainte de a
trece mai departe, și pe asta se sprijină".* Presupunerea era falsă. Scrisă,
măcar s-a putut găsi.

Reparația e cea de la orice entitate care se schimbă după ce a fost scrisă:
filigran pe `(updated_at, bucket)`, întreținut de trigger (migrațiile 0025 pe
server, 0014 pe agregator). Un interval recalculat își mută momentul, trece din
nou de cursor, și suprascrie prin upsert versiunea parțială.

Fluxul a căpătat și **poarta de trigger** pe care o aveau deja fluxurile
mutabile: fără trigger, interogarea întoarce zero rânduri, iar zero rânduri arată
identic cu „nimic nu s-a schimbat". Un fișier de migrație pe disc nu e dovadă că
nucleul l-a acceptat.

### Perechea nu e unică, și asta pierdea surse

Mentenanța scrie toate sursele unei ore în aceeași tranzacție, deci `nginx`,
`sshd` și `auditd` împart și `updated_at`, și `bucket`. Tăiat la mijlocul unui
asemenea grup, cursorul ar fi trecut dincolo iar sursele rămase n-ar mai fi
plecat niciodată. Lotul cere acum un rând în plus decât plafonul, ca să vadă dacă
grupul e tăiat, și se retrage la ultima graniță de grup. Când tot lotul e un
singur grup, grupul pleacă întreg — peste plafon: plafonul mărginește un lot
obișnuit, n-are voie să fie motivul pentru care nu mai pleacă nimic.

### Aceeași linie, respinsă de două ori

Perechea a fost scrisă întâi `($1::timestamptz, $2::text)` — Postgres a refuzat
la compilare, fiindcă `bucket` e un moment. Apoi `($1::timestamptz,
$2::timestamptz)` — asyncpg a refuzat la legare, fiindcă valoarea vine din
`collector_cursors.cursor`, care e text. Răspunsul e lanțul
`$2::text::timestamptz`: parametrul SOSEȘTE text, comparația se face pe momente.

Amândouă au trecut de suita verde fiindcă dublul de test modela doar FORMA
instrucțiunii și compara apoi valorile în Python, unde un `datetime` și un `str`
se compară fără să se plângă. Dublul cere acum ambele capete ale fiecărui lanț de
cast: tipul în care intră comparația, și tipul pe care îl cere driverul de la
apelant.

### Rezumatul, refăcut

Pagina `/panel` are acum ce are panoul serverului, și în plus tendințe:

* **șase cartonașe** — adrese distincte, detecții, evenimente, incidente
  deschise, vulnerabilități neaplicate, blocări active — primele trei cu
  tendința față de fereastra dinaintea lor. Sub `10` rânduri se scrie diferența
  brută, nu procentul: `1 → 3` e „+200%" și nu înseamnă nimic;
* **graficul orar STIVUIT pe sursă**, 48 de ore. Un total spune „a fost trafic";
  stivuit spune cine l-a produs, iar `sshd` care ia locul lui `nginx` fără ca
  totalul să se miște e chiar ce trebuie văzut. Peste cinci surse, restul se
  ADUNĂ într-o bandă numită — nu se taie, ca înălțimea stivei să rămână totalul
  orei;
* **banda de severități** a incidentelor deschise. O felie cu măcar un incident
  primește o lățime minimă: un `critical` singur, între o mie de `low`, ar fi
  avut o lățime subpixel și AR FI DISPĂRUT;
* **trei clasamente** — adrese, reguli, surse — fiecare cu a doua dimensiune
  (câte reguli a atins o adresă, câte adrese a prins o regulă, din câte ore vine
  o sursă);
* **cronologia**, detecții și blocări într-o singură listă în ordinea timpului.
  Separate, cititorul ar trebui să împerecheze singur „am fost atacat de X" cu
  „am blocat X" — iar legătura dintre ele e chiar ce vrea să vadă.

Tot SVG generat pe server, cu geometria în ATRIBUTE: politica paginii n-are
`unsafe-inline`, deci un grafic dimensionat prin `style=` n-ar apărea deloc.

### Ce nu se poate arăta, și se spune

**Originea pe țară și pe operatorul de rețea** vine din fluxul `actors`, care nu
se expediază la niciun capăt. **Istoricul de disponibilitate al serviciilor** ar
veni din `availability_rollup`, la fel. Niciuna nu se aproximează din ce e la
îndemână: un panou care desenează o hartă din altceva arată la fel de convingător
ca unul care o desenează din date reale, iar cine se uită n-are cum să
deosebească.

Citirile paginii sunt mărginite la 5000 de rânduri fiecare — baza e partajată.
Când plafonul e atins, **scrie pe pagină**: un plafon tăcut arată exact ca „atât
a fost".

### Fusul orar al unui moment scris ca text

MariaDB întoarce `DATETIME(6)` ca `"2026-08-16 10:00:00.000"` — fără fus.
`new Date(...)` pe forma asta îl citește ca oră LOCALĂ. Pe o gazdă pe fusul
României, fiecare moment ar fi alunecat cu două-trei ore: cronologia ar fi rămas
în ordine, doar cu ore greșite. Prins de dublul care formatează exact ca MariaDB.

## 0.20.0 — Ore de liniște

Un canal care te trezește la 3 dimineața pentru o scanare de porturi e un canal
pe care îl oprești definitiv într-o săptămână — iar un canal oprit definitiv e
mai rău decât niciunul: arată ca acoperire și nu e. `/mute` există ca să
păstreze canalul folosibil, nu ca să-l facă mai tăcut.

```
/mute 22:00-06:00     în fiecare noapte
/mute 2h              pauză unică (maxim 24h)
/mute off             oprește tot
```

Două mecanisme separate deliberat: un interval recurent (cazul normal) și o
pauză până la un moment (fereastră de mentenanță, test zgomotos). **Nu există
mute nelimitat** — `/mute 7d` e limitat la 24h, fiindcă un mute pe care trebuie
să-ți amintești să-l anulezi e unul pe care nu-l vei anula.

`telegram_chats.muted_until` exista din 0006 și nu era citită niciodată;
`telegram.quiet_hours` exista în config și nu era citită niciodată. Al treilea
config mort găsit în proiectul ăsta — de data asta implementat, nu șters.

### Ce nu se poate tăcea

Tăcerea trebuie să fie sigură. Alertele critice, PANIC, watchdog-ul, eșecurile
de patch și lockout-ul ignoră orice interval. Lista trăiește în cod, nu în
configurație: *care alerte pot fi tăcute* e o proprietate de siguranță, iar un
fișier de configurație e locul greșit în care să lași pe cineva s-o tacă și pe
ultima.

Restul sunt **reținute, nu pierdute** — `notified_at` rămâne gol și pleacă după
ce se termină intervalul, ca rezumat dacă s-au adunat prea multe. Iar dacă
interogarea preferințelor eșuează, botul alertează oricum: o eroare de bază de
date nu are voie să tacă un canal de securitate.

### Ora e locală, și rămâne locală peste schimbarea orei

Cine scrie „22:00" se referă la 22:00 unde stă el; serverul rulează pe UTC. O
eroare de trei ore aici ar tăcea exact serile pe care operatorul voia să le
acopere.

Fusul se rezolvă **după nume**, din `/etc/timezone` sau din simlink-ul
`/etc/localtime` — nu prin `datetime.now().astimezone()`, care dă un decalaj
FIX („+03:00", nu „Europe/Bucharest"). Un decalaj fix nu are reguli de oră de
vară, deci în noaptea în care se schimbă ora sfârșitul unei ferestre 22:00-06:00
s-ar calcula cu o oră greșit. O dată pe an, pe întuneric, exact când nimeni nu
se uită.

`tzdata` a intrat în dependențele de dezvoltare: Linux are tzdb de sistem,
Windows nu, iar fără el testele de fus cădeau pe fusul gazdei și nu mai testau
ce pretindeau.

### Setat pe server

`22:00-06:00`, fus `Europe/Bucharest`, verificat oră cu oră peste toată noaptea:
activ la 21:00, liniște de la 22:00 până la 05:59, activ din nou la 06:00.

---

## 0.19.1 — Documentația urmează installer-ul

Wizard-ul exista, dar documentația încă trimitea oamenii direct la
`deploy.sh` cu opt argumente. Acum [DEPLOYMENT.md](DEPLOYMENT.md) **începe** cu
el: §3.1 e calea recomandată, §3.2 rămâne calea manuală, pentru CI și pentru
cazul în care vrei fiecare parametru explicit.

**Ce s-a corectat, nu doar adăugat:**

- **Două comenzi din documentație nu funcționau dacă le copiai.** O rescriere
  anterioară lăsase `\n` literal în mijlocul lor, în loc de continuarea de
  linie — `deploy.sh ... --dry-run` din §3.2 și `diff` din §6.4. Un exemplu care
  nu rulează e mai rău decât niciun exemplu: îl încerci, eșuează, și nu știi
  dacă de vină e comanda sau serverul.
- **Tabelul de cerințe cerea încă AlmaLinux 9.x** și porturile 80/443 libere —
  ambele neadevărate de câteva versiuni. Acum: familia RHEL sau Debian, systemd
  obligatoriu, Python ≥3.10, portul panoului liber.
- **Secțiunea 2 avea două §2.1 și două §2.2**, iar lista numerotată „ce îți
  trebuie pregătit" era ruptă în două de subsecțiuni intercalate: punctul 1
  (DNS), apoi certificatul și portul, apoi punctele 2 și 3 (Telegram, cheia AI).
  Renumerotată 2.1–2.5, cu lista întreagă la un loc.
- **Stadiul livrării spunea „faza curentă: P0".** Acum P0–P9 livrate, P10 în
  curs, cu lipsurile enumerate.

**Adăugat:** [ARHITECTURA.md §3.12](ARHITECTURA.md) — de ce installer și nu
pachet `.rpm`/`.deb`. Pe scurt: un pachet e bun la copiat fișiere și prost la
tot ce face de fapt instalarea asta — să afle cine deține 443, să te întrebe de
pe ce adresă administrezi *înainte* să existe vreo regulă de blocare, să testeze
provocarea ACME înainte să consume din rate-limit-ul Let's Encrypt, să facă
rollback dacă un serviciu al tău s-a oprit.

Și în [DEPANARE.md](DEPANARE.md): reluarea cu `wizard.sh --config`, plus
eșecurile frecvente pe pași scrise pentru ambele familii de distribuții
(`initdb` nu se rulează pe Debian — clusterul e creat de postinst; headerele
Python se numesc `python3-dev`, nu `python3.N-devel`).

---

## 0.18.0 — P9.3: Generarea planurilor + interfața de patch-uri

**Transport: Messages API, nu `claude -p` headless.** Planul original prevedea
transportul headless fiindcă un plan complex chiar are nevoie să citească fișiere
de pe host (`composer.lock`, un vhost nginx). Pentru un pachet RPM pe AlmaLinux —
adică exact ce produce `dnf updateinfo` — fiecare fapt care contează (pachet,
versiune instalată, versiune care repară, unitate systemd) e deja cunoscut
determinist. A trimite exact acele fapte e mai ieftin **și mai sigur** decât a da
unui model un shell, și nu cere Node pe server (unde oricum e v16, iar CLI-ul
cere 18+). Transportul headless rămâne pentru planuri de aplicații complexe.

**Bucla de generare e intenționat neiertătoare:** cere plan → validează → dacă e
invalid, cere ÎNCĂ O DATĂ cu erorile exacte reinjectate → dacă tot e invalid, se
salvează ca `rejected_invalid` și se oprește. Un plan nu e niciodată reparat
manual până devine valid. Modelul e unealtă de redactare; validatorul e
autoritatea, și nu negociază.

**Interfața:** `/patches` (planuri + puncte de restaurare), `/patches/<id>`
(fiecare fază, JSON-ul complet, execuțiile, pașii). **Aprobarea nu se face din
web** — fluxul cu token în doi pași leagă aprobarea de chat și de hash, iar o a
doua suprafață ar însemna încă un loc unde se poate greși. Web-ul oferă ce e greu
pe telefon: citirea planului întreg. Dry-run se poate din ambele, fiindcă nu
schimbă nimic.

**Verificat pe server, cu apeluri reale.** Prima încercare a produs exact ce
trebuia:
```
apply:    dnf -y update curl
rollback: dnf -y downgrade curl-7.76.1-29.el9    ← fixează versiunea veche corect
```
validat din prima, cost $0.12.

### Două lucruri descoperite prin testare live

**1. Generam planuri imposibile.** Primul test a țintit `nginx`, care e marcat
`protected` în inventar — iar validatorul refuză din principiu orice plan automat
pentru un asset protejat. Modelul a recunoscut situația și a refuzat corect să
scrie pași de aplicare, ceea ce a făcut planul invalid din alt motiv. Rezultat:
$0.13 cheltuiți pe o respingere garantată. Garda e acum **înaintea** apelului la
model, împreună cu una pentru „nu se cunoaște versiunea care repară".
Assets protejate pe acest server: `nginx`, `sshd`, `docker`, `sentinel.web`.

**2. Un backup gol era raportat ca reușit.** Modelul a scris `rpm_state` cu
sursa `/var/lib/rpm` în loc de numele pachetului. `rpm -q /var/lib/rpm` eșuează —
dar executorul verifica codul de ieșire **doar** pentru `kind == "path"`. Deci
scria un artefact gol și returna `ok=True` cu un checksum perfect valid al
nimicului. **E cel mai periculos tip de eșec: arată ca o cale de întoarcere exact
până în clipa în care ai nevoie de ea.** Acum orice tip cu ieșire non-zero sau
artefact de dimensiune zero e respins. Verificat live: refuzat corect.

**487 teste trec** (+5). Promptul explică acum și ce înseamnă `source` pentru
fiecare tip de backup, și limita de 16 caractere pentru id-uri.

## 0.17.0 — P9.2: Aprobarea patch-urilor

Poarta dintre „există un plan" și „mașina s-a schimbat".

**Problema de rezolvat:** un buton Telegram trăiește în istoricul unui chat
pentru totdeauna și poate fi apăsat oricând, de oricine vede acel chat. Deci
butonul **nu trebuie să FIE autoritatea** — trebuie să poarte o referință către
una. Autoritatea stă în `approval_tokens` (migrația 0013).

**Patru proprietăți, fiecare închizând o gaură concretă:**
- **Legat de `(chat_id, plan_id, plan_hash)`** — un token dintr-un chat e inutil
  în altul, iar unul pentru un plan nu poate aproba altul. Legarea **hash-ului**
  e ce face ca un plan regenerat să omoare toate butoanele deja trimise: octeții
  s-au schimbat, deci niciun token vechi nu mai corespunde.
- **O singură folosire, atomic** — `used_at` se scrie în ACELAȘI `UPDATE` care îl
  consumă. Un check-then-act ar lăsa un dublu-tap, un callback reîncercat sau doi
  operatori simultani să treacă toți de verificare înainte ca vreunul să scrie.
- **TTL scurt** — o aprobare e o decizie despre mașina așa cum e *acum*, nu o
  permisiune permanentă descoperită într-un log de chat peste o lună.
- **Două etape** — primul tap **nu aplică nimic**: emite un al doilea token și
  reafirmă consecințele (downtime, impact, avertisment dacă e ireversibil sau
  cere reboot). „Ești sigur?" e o poartă reală doar dacă al doilea ecran aduce
  informație pe care primul n-o avea.

**Dry-run nu cere aprobare** — a vedea ce S-AR întâmpla nu e o schimbare, iar
ceremonia inutilă îi învață pe oameni să sară peste ceremonie. Rolul se verifică
totuși, o singură dată, în router, înaintea oricărei ramuri.

Comenzi noi: `/patches` (planuri în așteptare), `/patch <id>` (trimite planul cu
butoane). Butoanele de patch sunt rutate **înaintea** handler-ului generic, ca un
token să nu cadă niciodată în handler-ul de blocare, care l-ar trata ca adresă IP.

**Verificat pe server, cu tentative reale de ocolire:**
| Tentativă | Rezultat |
|---|---|
| Refolosirea aceluiași token | REFUZAT |
| Token folosit din alt chat | REFUZAT |
| Token de patch folosit ca token de blocare | REFUZAT |
| Aprobare cu hash diferit de plan | REFUZAT |
| Folosire după revocare | REFUZAT |

**Găsit și reparat pe parcurs:** două migrații cu numărul 0013 (una ștearsă local
rămăsese pe server — `tar -xzf` suprapune, nu șterge). Efectul e sever: `migrate`
refuză să ruleze **deloc**, deci întreaga schemă încremenește. Am adăugat două
teste care prind asta înainte de build: versiuni unice și fără goluri.

**479 teste trec** (+17, dintre care 15 verifică exclusiv proprietățile de
securitate ale token-ului).

**Rămâne P9.3:** generarea planurilor cu `claude -p` (`--permission-mode plan`,
read-only structural) și pagina web de planuri.

## 0.16.0 — P9.1: Patching — fundația de execuție sigură

Faza cea mai periculoasă: rulează comenzi ca root pe o mașină vie. Nu a fost
construită partea de generare a planurilor (P9.3) — a fost construită **plasa de
siguranță**, pentru că ordinea inversă e felul în care se sparg servere.

Validatorul exista din P0 (682 linii) și s-a dovedit excelent: a respins trei
greșeli reale de design în timp ce scriam fixture-ul de test — un pas de rollback
care declanșa la rândul lui rollback (recursiv), un backup fără verificare de
spațiu pe disc, și o referință la `/var/backups/sentinel` (cale protejată).

**`patch/runner.py`** — motorul de execuție. Fiecare regulă există pentru că
alternativa e un server stricat la 3 dimineața:
1. **Revalidare la execuție** — un rând în bază nu e o promisiune; constantele se
   schimbă, codul se redeployează.
2. **Aprobarea se verifică pe hash**, în interiorul `UPDATE`-ului. Un check-then-act
   ar aproba un plan pe care nimeni nu l-a văzut, dacă s-ar regenera între timp.
3. **Baza se scrie ÎNAINTE de fiecare comandă.** Un crash la mijloc trebuie să lase
   un rând care spune ce comandă era în zbor.
4. **Eșec în apply → rollback imediat.** Un rollback eșuat e stare separată
   (`rollback_failed`), pentru că e o situație mai gravă și nu trebuie să arate la fel.
5. **Eșec înainte de orice modificare → abort fără rollback** — nimic nu s-a
   schimbat, iar un rollback inutil e un risc în plus.
6. Nicio cale nu lasă execuția în `running`, nici măcar la crash.

**`patch/checks.py`** — evaluează verificările structurate (`systemd`, `command`,
`file_exists`, `disk_free`, `no_open_incident`…). O verificare care **nu poate fi
evaluată este EȘUATĂ**, niciodată trecută: „n-am putut afla" tratat ca „e bine" e
felul în care un patch merge mai departe pe o mașină pe care nimeni n-a verificat-o.

**`patch/backup.py`** + două operații noi de executor:
- `backup_finalize` — resigilează punctul: **recalculează** checksum-urile citind
  artefactele înapoi (nu are încredere în cifrele venite de peste graniță), scrie
  `manifest.json` și generează `restore.sh`.
- `backup_prune` — ștergere cu ușa cea mai îngustă posibilă: id-ul e curățat de
  orice separator, calea rezolvată trebuie să fie copil **direct** al rădăcinii de
  backup (reverificat *după* resolve, ca un symlink plantat să nu redirecteze), și
  refuză symlink-uri. `rm` rămâne interzis în allowlist-ul de patch-uri.

**Decizia care contează cel mai mult:** `restore.sh` e generat **în interiorul
executorului**, din ce vede el pe disc. Apelantul trimite doar un id. Scrierea de
text venit din partea neprivilegiată într-un fișier executabil deținut de root
este exact felul în care o graniță de privilegii devine un rootkit.

**Verificat pe server, end-to-end:** punct de restaurare real creat pentru
`/etc/hostname` (0700 dir / 0600 artefacte / 0700 script), manifest cu sha256,
`restore.sh` fără dependențe. **Apoi am corupt deliberat arhiva: scriptul a refuzat
restaurarea și a ieșit cu 1 înainte să atingă ceva.** Prune verificat, punct șters
curat.

**Retenție** (`prunable_restore_points`): niciodată nu se șterge un punct cu
`retention_hold`, niciodată unul mai nou decât fereastra, și — cel mai important —
**niciodată ultimul punct al unui asset**, oricât de vechi. O retenție care poate
șterge singura cale de întoarcere a unei mașini nepatch-uite de luni de zile nu e
retenție, e pierdere de date pe cronometru.

**462 teste trec** (+28), dintre care 16 sunt invariante de siguranță care verifică
exclusiv că lucruri periculoase sunt **refuzate**.

**Rămâne pentru P9.2/P9.3:** aprobarea în doi pași pe Telegram cu token legat de
`(chat_id, plan_id, plan_hash)`, pagina web de planuri, și generarea planurilor cu
`claude -p` (`--permission-mode plan`, read-only structural).

## 0.12.1 — Audit de acoperire a logurilor

Verificare cerută înainte de P9: *chiar* se citesc toate logurile de sistem și de
aplicație? Răspunsul a fost nu. Auditul a comparat ce surse există pe host cu ce
ajunge efectiv în `raw_events` și a găsit șapte probleme, două critice.

**1. Detecția SSH era oarbă (CRITIC).** OpenSSH 9.8+ mută autentificarea într-un
proces separat, deci evenimentele apar sub `_COMM=sshd-session`. Filtrul journald
căuta doar `sshd` și prindea exclusiv mesajele listener-ului. Efect real măsurat:
niciun eveniment sshd în DB din 31 iulie, în timp ce jurnalul conținea 118
evenimente de autentificare în ultimele 3 ore. **Regula principală de detecție
(brute-force SSH) nu avea intrare.** Filtrul acoperă acum `sshd-session`, `sshd`,
`sudo`, `su`.

**2. Suricata îneca baza (CRITIC).** 96.000 din cele 99.000 evenimente/zi erau
diagnostice ale motorului (`SURICATA IPv4 truncated packet`, `AF-PACKET truncated
packet`, `TCPv4 invalid checksum` — sev 3), produse de segmentation offload pe
placa de rețea, nu de un atac. Îngropau cele ~150 de alerte reale și umflau
partițiile. Reparat pe două niveluri: colectorul respinge diagnosticele de motor
pe care Suricata însuși le marchează informative, iar pe server regulile
`decoder-events` / `stream-events` sunt dezactivate prin `disable.conf` ca
`eve.json` să nu mai crească deloc. **Verificat: 0 zgomot, 25 alerte reale / 5 min.**

**3. Config-ul pretindea acoperire inexistentă.** `auditd`, `docker` și `fim` erau
`true`, dar nu exista niciun colector pentru ele. `docker`/`fim` sunt acum `false`
cu notă explicită (lacună cunoscută), iar auditd a fost implementat.

**4. auditd — colector nou.** Citește `/var/log/audit/audit.log` și păstrează doar
tipurile relevante (`USER_AUTH`, `USER_LOGIN`, `USER_CMD`, `ANOM_ABEND`, `AVC`,
modificări de conturi, `CONFIG_CHANGE`); `SYSCALL`/`PATH` — potopul — sunt
respinse. Accesul se face prin `log_group = sentinel` în `auditd.conf`, calea
documentată care supraviețuiește rotației (fișierul era `0600 root:root`).

**5. sudo/su — colector nou.** Escaladarea de privilegii e pasul dintre „un cont e
compromis" și „hostul e compromis". `TTY=` e opțional în regex: sudo neinteractiv
(cron, `sudo -n`, scripturi de deploy) îl omite, iar cerându-l se pierdea exact
folosirea automată de privilegii.

**6. Bug găsit de teste:** auditd împachetează câmpuri în `msg='...'`, deci ultimul
câmp sosea cu apostrof lipit (`res=failed'`) — fiecare autentificare **eșuată** era
înregistrată ca reușită.

**7. Parsarea timestamp-ului Suricata** a fost rescrisă cu regex propriu:
`fromisoformat` respinge pe Python <3.11 atât offsetul fără două puncte cât și
părțile fracționare care nu au exact 3 sau 6 cifre.

**Stare finală verificată pe server** (5 minute reale): auditd 45, suricata 25
(zero zgomot), sshd 14, nginx 5, sudo 2. 391 teste trec (+22, dintre care 3
regresii care încuie exact eșecurile de mai sus).

**Lacune rămase, declarate onest:** loguri de containere Docker (9 containere
rulează, inclusiv aplicații web expuse), monitorizare de integritate a fișierelor
dedicată (auditd acoperă parțial), `nginx error.log`, logurile aplicațiilor din
containere (mariadb, n8n, snipeit).

## 0.12.0 — P8: Stratul AI

### P8.1 — Triaj AI de incidente

Detecția deterministă predă, Claude adaugă judecată. Claude **nu** calculează
scoruri și **nu** ia decizii de blocare — primește ieșirile deterministe și produce
ce face bine un model: severitatea reală în banda ambiguă, verdictul de fals-pozitiv
și un rezumat în română. Verdictul AI se stochează **lângă** cel determinist
(`incidents.ai_*`), niciodată peste — un dezacord rămâne vizibil.

- **Client** (`ai/client.py`): Messages API direct prin httpx (fără SDK), output
  structurat prin tool forțat, prompt caching pe system, **degradare grațioasă** —
  orice eșec (timeout, rețea, non-200) → `ok=False`, verdictul determinist rămâne,
  detecția nu e afectată.
- **Buget** (`ai/budget.py`, tabelul `ai_usage` din 0006): fiecare apel își
  înregistrează tokenii + costul estimat; `allowed()` verificat **înainte** de fiecare
  apel → la atingerea plafonului zilnic/lunar nu se mai apelează modelul. O furtună
  de evenimente costă mărginit.
- **Anti prompt-injection** (`ai/prompts.py`): tot conținutul controlat de atacator
  (loguri, path-uri, user-agent) e împachetat în `<date_neincrezute>`, marcajul de
  închidere injectat e neutralizat, iar system prompt-ul declară zona drept date, nu
  instrucțiuni. În plus, modelul poate returna **doar** un verdict structurat — o
  injecție reușită schimbă o etichetă, niciodată sistemul.
- **Worker** (`ai/worker.py` + serviciul `sentinel ai`): triază incidentele deschise
  ≥ `triage_min_severity` (high) netriajate, câteva pe pas, gated pe buget. Non-critic:
  dacă moare, restul agentului merge neatins.
- UI: card „Analiză AI" pe pagina de incident (severitate AI, fals-pozitiv, acțiune,
  încredere, avertisment de injection).

**Verificat pe server (apeluri reale la API):** incident #1 (brute-force SSH) →
AI critical, „blochează", încredere 0.95, rezumat RO corect, cost $0.00292. Serviciul
a recalibrat incident #58 (IDS pe IP-ul de admin) de la high la **medium** — a
recunoscut trafic legitim. Buget urmărit, plafon $5/zi. 375 teste trec (+15 pentru
buget/anti-injection/validare verdict).

**Amânat pentru P8.2** (cu notă): corelare campanii, comentariu de predicție pe
baseline, rapoarte zilnice RO, `/ask`, transport headless `claude -p` (pentru planuri
de patch — vine cu P9).

## 0.11.0 — P7: Scanare vulnerabilități

### P7.1 — Pachete OS + KEV + prioritizare

Prima felie verticală de scanare, deterministă și sigură (fără exploatare activă,
fără instalări riscante).

- **Scaner pachete OS** (`scan/os_packages.py`): `dnf updateinfo list cves --security`
  — autoritativ pe AlmaLinux. Știe de patch-urile **backportate** (CVE reparat fără
  bump de versiune upstream), deci **zero fals-pozitive** pe care le-ar produce un
  scanner generic de string-uri de versiune. Read-only: listează ce e disponibil,
  nu instalează nimic (aplicarea = P9).
- **KEV** (`intel/kev.py` + migrația 0012): oglindă locală a catalogului CISA Known
  Exploited (fetch HTTPS, refresh zilnic). Cel mai puternic semnal — CVE exploatat
  *acum*.
- **Prioritizare** (`scan/prioritize.py`): scor 0..100 din `severitate/CVSS × EPSS ×
  KEV × expus × criticitate × fix disponibil`. Un CVSS 6.5 pe lista KEV întrece un
  9.8 pe care nu-l exploatează nimeni.
- **Repo findings** (`db/repo/findings.py`): dedup pe `finding_key`, `last_seen`
  avansează, iar ce nu mai apare într-o scanare e marcat `resolved` automat.
- **Orchestrator** (`scan/orchestrator.py`) + serviciul `sentinel scan` (one-shot,
  declanșat de `sentinel-scan.timer` în fereastra 03:00–05:00) + pagina web
  `/findings` (prioritizată, KEV evidențiat).

**Verificat pe server:** scanare reală → **4636 findings** (6 critice, 2527 mari),
din care **43 KEV**. Top prioritate = bug-uri de kernel KEV (CVE-2026-31431,
CVE-2024-53197…) la prio=100, cu versiunea de fix. Catalog KEV: 1656 CVE-uri.
`/findings` → 303 (login). Timer nocturn activat. 367 teste trec (+16 pentru
prioritizare/parsare dnf/finding_key).

**Amânat pentru P7.2** (cu notă onestă): trivy (containere/fs — necesită instalare),
nuclei DAST (activ, cere `confirmed_by_operator`), semgrep (opt-in/repo), EPSS
(feed mare), lynis, verificări web proprii (TLS/headere/`.git` expuse).

## 0.10.0 — P6: Autonomie + Suricata + baseline

### P6.1 — Decidentul de auto-block (observe vs armat)

Detecția capătă un braț de răspuns. `respond/decider.py` rulează în `sentinel-detect`,
imediat după ce se scrie un incident, și decide ce se întâmplă cu un actor de rețea.
**Nu vorbește niciodată direct cu Telegram sau cu socket-ul executorului** pentru
mesagerie: își scrie decizia pe incident (`incidents.auto_action`, migrația 0011),
iar bucla de push modelează alerta. Astfel serviciul detect n-are nevoie de token
Telegram, iar alerta și acțiunea nu pot fi în dezacord (citesc aceeași coloană).

Garduri, în ordine (oricare oprește blocarea; modul armat notează de ce):
1. actorul trebuie să fie un IP real (o cheie de campanie n-are ce bloca);
2. severitate ≥ prag (`min_severity`, implicit `high`) — zgomotul nu armează;
3. actor ne-allowlistat și non-scanner cunoscut;
4. fără CIDR dacă nu e permis explicit — un /24 taie o clădire NAT-uită;
5. blocklist sub `max_elements`;
6. sub `max_per_minute` — plasa de siguranță pentru un detector scăpat.

Executorul reverifică never-block deasupra tuturor — deci nici măcar un bug aici
nu poate izola IP-ul de admin.

- **Mod observă** (livrat, `enabled: false`): fiecare incident de rețea → alertă cu
  buton de block manual; incidentul e marcat `observed` (feed „ar fi blocat" pentru
  cele 72h de calibrare).
- **Mod armat** (`enabled: true`): decidentul blochează prin `respond.actions.block`
  (`by=auto:<regulă>`), alerta arată „🛡️ Blocat automat" cu buton de **deblocare**.
- Config nou: `response.auto_block.min_severity` (validat). Buton `unblk:` în
  `on_callback`. `blocklist.count_auto_since()` pentru plafonul de rată.

**Verificat pe server:** observe → incident #41 `high`, `auto_action=observed`, nftables
gol; armat (izolat, config live neatins) → decident `blocked`, nftables=1,
`auto_action=blocked`. Config live rămâne `enabled=false`. 344 teste trec (+15 pentru
decident și suprafața Telegram).

### P6.2 — Baseline sezonier robust

`predict/baseline.py` — mediană + MAD per (asset, metric, oră-din-săptămână),
scor robust `z = 0.6745·(x−median)/MAD`. Nu media/stddev: traficul de atac distruge
media, mediana abia se mișcă. Sezonalitatea (0..167) exprimă „1200 cereri la 04:00
duminică e anormal, la 14:00 marți nu". **Warm-up obligatoriu 14 zile** — până atunci
`warm=false` și regula de anomalie înregistrează dar **nu alertează** (altfel ai 300
de fals-pozitive în ziua 1).

- Evenimentele nu sunt mapate la asset la ingest pe acest host, așa că actualizatorul
  rezolvă `source→asset` după nume (sshd → asset sshd). Metrici: `requests_per_min`
  (nginx), `failed_auth_per_min` (sshd).
- Regula `anomaly.volume` (în `detect/rules.py`): compară ultimul minut complet cu
  baseline-ul orei curente; dormantă cât timp nu e warm; subiectul e un asset, nu un
  IP (`actor_key="host:<serviciu>"`), deci decidentul **nu** o auto-blochează.
- Actualizatorul rulează orar în `sentinel-detect`.

**Verificat pe server:** baseline populat (sshd 4 buckets, nginx 16 buckets), toate
`warm=false`, `learning=true`, 0 detecții de anomalie (dormant corect). 352 teste trec
(+8 pentru matematica de baseline).

### P6.3 — Suricata (NIDS)

Inspecție de trafic la nivel de pachet. `collectors/suricata_eve.py` citește
`eve.json` și păstrează **doar** `event_type=alert` — restul (flow/stats/dns)
e firehose fără valoare de securitate și ar îngropa partițiile. Legat în
`sentinel-ingest` prin același tailer inode-aware ca nginx. Regula `ids.suricata`
grupează alertele proaspete per IP sursă (severitate 1→high, 2→medium, 3 ignorat).

**Instalare** (`step_suricata` rescris): NU înlocuiește `suricata.yaml` din
distribuție (e complet, trece `-T`); pune deasupra doar specificul gazdei —
`OPTIONS` (af-packet pe interfață, `HOME_NET` pe IP-ul public, `-F` fișier BPF),
drop-in `MemoryMax=1G`, ACL pentru `sentinel` pe `/var/log/suricata`, ET Open via
`suricata-update`. **Fluxul UniFi udp/514 e exclus prin BPF** în kernel (protejează
discul — footgun-ul din plan).

**Verificat pe server:** Suricata 7.0.15, 68083 reguli, `-T OK`, 511 MB (sub cap
1G), eve.json crește. Alerte reale ET Open → `raw_events source=suricata` (20) →
incidente IDS (`ET DROP Dshield`, `ET COMPROMISED Hostile Host` pe 203.0.113.47).
Zgomotul informativ (sev 3: DNS Telegram, SSH-Go) filtrat corect. Auto-block rămâne
oprit, deci alertele IDS ajung ca notificări cu buton, nu blocări. 360 teste trec
(+8 pentru colectorul Suricata).

**Notă de tuning:** Suricata flaghează și trafic legitim (IP-ul de admin a produs
un incident IDS high). Executorul refuză oricum never-block IP-ul de admin; fereastra
de 72h e pentru a găsi și pune în allowlist astfel de surse înainte de a arma.

## 0.9.0 — P5: Răspuns (blocare IP)

„Văd atacatorul" devine „îl blochez cu un buton". Infrastructura (executorul root,
tabela nftables cu seturi TTL, watchdog-ul) exista din P1; P5 conectează
**suprafața de control**. Auto-block rămâne oprit — blocarea e la comandă.

- `respond/actions.py` — block/unblock/allow/flush async peste `ExecutorClient`
  (apel de socket blocant rulat în thread, ca să nu înghețe event loop-ul).
  Precheck client-side prietenos (loopback/RFC1918 → mesaj clar), dar **executorul
  rămâne autoritatea** — reverifică never-block la fiecare cerere. Fiecare acțiune
  scrie un rând de istoric + o intrare de audit cu lanț de hash.
- `db/repo/blocklist.py` — istoricul: cine, ce, de ce, TTL, când s-a ridicat.
- **Telegram**: `/block <ip> [1h|30m|perm]` cu **buton de confirmare inline**,
  `/unblock`, `/blocklist`, `/panic` (golire cu confirmare). Roluri: doar
  owner/operator pot acționa; un viewer e read-only.
- **Pagina `/blocklist`** — vizualizare + deblocare. **Blocarea NU se face din web**:
  un dashboard compromis nu trebuie să poată izola pe cineva. Web-ul poate doar
  *anula* un blocaj, niciodată crea unul.
- **Buton de block direct pe alertă**: push-ul automat de incident pentru un actor
  de rețea poartă un buton `🚫 Blochează <ip> (24h)` + `❌ Ignoră`. Apăsarea trece
  prin exact același `on_callback` ca `/block` — deci verificarea de rol (viewer =
  refuzat) și garda never-block a executorului (IP de admin = refuzat) rămân active.
  Butonul apare **doar** dacă `actor_key` chiar e un IP (nu o cheie de campanie).

**Verificat pe serverul real:** blocarea unui atacator real (`203.0.113.47`) a
apărut în setul nftables; **executorul a refuzat blocarea IP-ului de admin**
(`198.51.100.25`), care e oricum protejat de allowlist-ul nftables (accept înaintea
drop-ului); TTL scris corect; `/panic` (flush) a golit setul. **332 de teste
trec** (+13 pentru P5).

**Corecții anti-lockout găsite live** (de-asta se rulează pe host):
1. `/run/sentinel` era `750 root:root` — user-ul `sentinel` nu putea traversa la
   socket (socket-ul e group-ok, dar dir-ul nu). Executorul îl setează acum
   `root:sentinel`.
2. Executorul **bloca IP-ul de admin**: `response.extra_allowlist` era gol, iar
   parserul lui stdlib nu citea formatul inline `["..."]` scris de installer. Acum
   installer-ul seed-uiește IP-ul de admin acolo, iar parserul citește ambele
   stiluri YAML. Verificat: executorul refuză acum `198.51.100.25`. (Al doilea
   strat — allowlist-ul nftables — a prevenit lockout-ul cât timp primul avea
   gaura.)

**Încă două corecții găsite live la verificarea finală:**
3. **Auditul executorului nu se scria deloc** (`Permission denied`). Cauza:
   unitul rulează `User=root` dar cu un `CapabilityBoundingSet` minimal care
   **omite intenționat `CAP_DAC_OVERRIDE`**; `/var/lib/sentinel` e `750
   sentinel:sentinel`, deci root-ca-„other" n-avea drept de scriere. În loc să
   lărgesc capabilitățile crown-jewel-ului, auditul s-a mutat în
   `/var/lib/sentinel/executor/` (dir `root:root 0750`, creat de installer) — un
   loc pe care executorul îl deține și în care scrie fără privilegii în plus.
   Verificat: lanțul de hash `prev_hash → entry_hash` se scrie și se continuă
   corect între cereri.
4. **PANIC golea o singură dată** (doar la apariția fișierului). Acum
   panic-watcher-ul golește la **fiecare** ciclu de 10s cât timp `/etc/sentinel/PANIC`
   există — un detector care ar adăuga blocuri în timpul PANIC îi găsește mereu
   dispăruți. Verificat live: `before=1 → (12s) → 0`.

**Criteriu de acceptanță P5 îndeplinit:** blocare manuală → nftables; TTL; flush
prin PANIC (continuu); allowlist protejează IP-ul de admin (ambele straturi);
audit cu lanț de hash scris de executor. Auto-block încă oprit.

## 0.8.0 — P4: Detecție + Telegram

Faza care transformă evenimentele în **incidente** și te anunță pe **Telegram**.
Încă fără blocare — doar detectează și raportează.

**Motor de detecție** (`detect/`): reguli deterministe peste raw_events, rulate de
`sentinel-detect` la fiecare 10s. `auth.ssh_bruteforce` (N eșecuri de la un IP
într-o fereastră → severitate după volum) și `web.enumeration` (multe 404 pe căi
distincte → scaner). Un actor din allowlist e sărit înainte de orice scriere.
Incidentele se **deduplică pe fingerprint** — un brute-force în desfășurare e UN
incident care crește, nu o mie de alerte identice; severitatea doar urcă.

**Bot Telegram** (`telegram/`): long-polling, read-only. Comenzi `/status`,
`/incidents`, `/incident <id>`, `/services`, `/health`, verificate contra
allowlist-ului de chat_id (un chat neautorizat primește tăcere). **Push**: un task
asyncio trimite incidentele noi peste pragul de severitate și le marchează.

**Pagina `/incidents`** + detaliu per incident, cu detecțiile și evidența.
Titlurile/sumarele conțin text ales de atacator — escapat de Jinja.

**Verificat pe serverul real:** un brute-force SSH simulat (12 eșecuri de pe
loopback) a produs un incident `high` în **<60s**, iar botul a trimis push pe
Telegram — împreună cu **atacatorii reali** prinși în paralel (`203.0.113.48`,
`203.0.113.47`, `203.0.113.49`). Dedup verificat: detecții repetate → un incident
care crește. **319 de teste trec** (+6 pentru P4).

**Corecții găsite live:** cititorul journald se bloca după rotația jurnalului
(lipsea `process()`); `array_agg` peste set gol returna NULL pe coloane NOT NULL în
upsert-ul de actor (COALESCE la `{}`).

**Criteriu de acceptanță P4 îndeplinit:** brute-force SSH → incident în UI **și**
push Telegram în <60s, fără blocare.

## 0.7.0 — P3: Ingestie de evenimente

Prima fază care vede lumea din afară. Colectori care citesc logurile, le
normalizează într-un model canonic de eveniment, le îmbogățesc și le scriu — plus
o pagină Evenimente în timp aproape real.

**Ce s-a construit:**

- `collectors/sshd.py`, `collectors/nginx.py` — parsere **pure** (fără I/O,
  testate) care transformă o linie de log în `model.Event`. sshd: eșecuri/reușite
  de autentificare + invalid user (semnalul de brute-force). nginx: format
  combined, cu vhost opțional; metoda, calea, query, UA, referer — toate
  controlate de client, stocate verbatim, escapate la afișare.
- `collectors/journald_reader.py` — citește journalul sshd prin `systemd.journal`,
  reluând din cursorul salvat (fără replay, fără gol).
- `collectors/nginx_tail.py` — tailer conștient de inode; rotația logrotate e
  sigură (inode nou → citire de la 0), iar prima vizită **tailează** în loc să
  reia istoricul.
- `enrich/geoip.py` — țară/ASN din baze MaxMind locale, **opțional** (no-op fără
  ele, fără rețea la lookup).
- `db/repo/events.py` + migrația **0010** (`collector_cursors`) — insert în lot,
  cursor persistat în aceeași tranzacție cu lotul, interogări pentru pagină.
- `services/ingest_service.py` — daemonul: la fiecare interval citește ce e nou,
  normalizează, îmbogățește, scrie un lot, apoi avansează cursoarele — deci un
  crash re-citește câteva evenimente, nu le pierde.
- **Pagina `/events`** — evenimente cu filtrare (sursă, fereastră, IP), sumar pe
  sursă și top-uri de IP-uri cu numărul de `auth_fail`, reîmprospătare la 15s.
  Fără JS inline (CSP strict).

**Permisiuni:** ingest rulează ca `sentinel` neprivilegiat. Instalarea acordă
acces de citire la logurile nginx printr-un ACL per-user (supraviețuiește rotației),
least-privilege — doar citire.

**Verificat pe serverul real:** daemonul a captat imediat brute-force SSH viu de
pe internet (`auth_fail user=root from 203.0.113.47`, `user=amanda`), cererile
nginx, o cerere de test apare **exact o dată** (fără duplicare). Payload XSS
într-un User-Agent e escapat, nu executat. **313 de teste trec** (+10 pentru P3).

**Criteriu de acceptanță P3 îndeplinit:** evenimente în timp real; sshd
brute-force vizibil în <60s.

## 0.6.0 — P2: Inventar și disponibilitate

Prima fază cu **date reale pe dashboard**. Peste schema deja existentă (0005),
stratul Python + o pagină web nouă.

**Sondarea HTTP** cere `/`, nu `/healthz`, și tratează orice răspuns sub 500 ca
activ (un 301/302/401/404 e un răspuns normal, nu o pană) — altfel fiecare
aplicație terță fără `/healthz` ar apărea „degradată". Încearcă schema probabilă
și revine la cealaltă, deci un serviciu pe un port TLS nestandard (Webmin pe
10000) e sondat corect. Serviciile cu unit systemd se pot sonda prin
`systemctl is-active` — mai fiabil decât HTTP pentru un panou de administrare cu
restricții de IP.

**Ce s-a construit:**

- `db/repo/assets.py`, `health.py`, `capacity.py` — inventarul de servicii, probe
  de disponibilitate cu pene, eșantioane de capacitate. Flagurile `protected` și
  `confirmed_by_operator` sunt setate de operator, niciodată de discovery, și nu
  sunt suprascrise la re-sincronizare.
- `scan/inventory.py` — încarcă `inventory.yaml` (sursa de adevăr) și sincronizează
  asset-urile în DB; editarea inventarului are efect la următorul tick, fără
  restart.
- `health/prober.py` — sondează fiecare asset după tip: **http** (cerere pe
  loopback, nu prin nginx — măsoară serviciul, nu rețeaua), **tcp**, **systemd**
  (`systemctl is-active`), **docker** (`docker inspect`). O serie de eșecuri
  deschide o pană; recuperarea o închide. Disponibilitatea se calculează din
  eșantioane, nu din pene, deci un serviciu care oscilează arată uptime-ul real.
- `health/capacity.py` — CPU, load, RAM, disc, conexiuni, RSS pe serviciu (psutil).
- `health/sla.py` — rollup zilnic de disponibilitate cu percentile de latență.
- `services/health_service.py` — `sentinel health`, oneshot la 30s prin timer;
  o probă blocată e omorâtă de systemd și următorul tick pornește curat.
- **Pagina `/services`** — fiecare serviciu real up/down live, latență, uptime
  24h, plus un grafic uptime ca **SVG inline server-rendered** (fără bibliotecă de
  charting, deci CSP-ul strict rămâne intact, fără JS). Meta-refresh la 30s pentru
  partea „live". Card de capacitate a gazdei.

**Verificat pe serverul real:** cele 3 asset-uri din inventar (sentinel.web, sshd,
postgresql) sondate toate up (12-38ms), capacitatea eșantionată, timer-ul de
health activ la 30s, pagina în spatele auth. **303 de teste trec** (+8 pentru P2).

**Criteriu de acceptanță P2 îndeplinit:** dashboard-ul arată fiecare serviciu real
up/down live + grafic uptime 24h.

## 0.5.7 — Login imposibil: middleware-ul CSRF golea formularul

Dashboard-ul se încărca, contul exista, parola era corectă — dar orice login
dădea „Utilizator sau parolă incorectă". În baza de date, fiecare încercare avea
username-ul trimis **gol** (`''`), deși formularul îl conținea.

Cauza: `CSRFMiddleware` era `BaseHTTPMiddleware` și citea `await request.form()`
ca să ia token-ul CSRF din formular. Comentariul din cod chiar susținea că e sigur
(„Starlette caches it") — **fals** pentru `BaseHTTPMiddleware`: `call_next` dă
handler-ului un canal `receive` nou, iar body-ul consumat în middleware ajunge la
handler **gol**. CSRF-ul trecea (middleware-ul îl citise), dar `username` și
`password` soseau goale la endpoint. TestClient nu reproduce comportamentul, deci
toate testele treceau în timp ce login-ul real era imposibil pe uvicorn.

Reparat: `CSRFMiddleware` e acum middleware **ASGI pur**. Tamponează body-ul o
dată și îl **reia** — o dată pentru parsarea token-ului, o dată pentru handler.
Verificat pe serverul real: un POST de login înregistrează acum username-ul trimis
efectiv, nu `''`. Un test structural respinge revenirea la `BaseHTTPMiddleware`.
**295 de teste trec.**

## 0.5.6 — Certbot: verificarea ACME rata emiterea

Instalarea a **reușit complet** — dashboard live, admin creat cu TOTP — dar servea
certificatul self-signed placeholder: certbot fusese sărit. Cauza: în modul
`auto`, `obtain_certificate` testează întâi calea ACME cu `acme_challenge_reachable`,
iar acea verificare rula **imediat după** `systemctl reload nginx`. Un reload e
grațios și asincron, deci o singură sondă poate ateriza în fereastra în care
workerii vechi încă răspund fără noua locație `:80` — fals-negativ → certbot sărit
→ self-signed pe un dashboard funcțional (non-fatal prin design, deci instalarea
a mers mai departe).

Reparat: sonda ACME se reîncearcă de 5 ori (2s între) ca reload-ul să se așeze.
Certificatul real a fost emis pe serverul curent (webroot ACME verificat că
răspunde 200), vhost-ul îl referă, iar dashboard-ul răspunde acum din internet cu
cert Let's Encrypt valid și redirect HTTP→HTTPS. **294 de teste trec.**

## 0.5.5 — Verificarea finală rollback-uia o instalare reușită

Cel mai costisitor bug: instalarea a trecut de TOATE pașii reali — nginx + certbot,
user admin, Suricata, smoke test — și apoi pasul 38 (`verify_nothing_broken`) a
declanșat un **rollback automat al unei instalări perfect funcționale**.

Cauza: `assert_nothing_broken` compară serviciile de dinainte cu cele de acum
folosind `comm`, care verifică sortarea cu collation-ul locale-ului. Un `sort`
simplu folosește tot locale, dar numele de servicii au `@`, `-`, `.`, iar
port-urile erau sortate numeric în timp ce `comm` compară lexical. Baseline
capturat într-o rulare, comparat în alta cu collation diferit → `comm: file N is
not in sorted order` + ieșire-gunoi → citită drept „un serviciu s-a oprit" →
rollback.

Reparat: ambele intrări se re-sortează cu `LC_ALL=C` (byte order, determinist)
chiar înainte de `comm`, pentru servicii, porturi și containere. `capture_baseline`
scrie și el cu `LC_ALL=C`. Un test static respinge orice `comm` fără `LC_ALL=C` în
scripturile de deploy. Verificat prin simularea scenariului cu nume de servicii cu
`@`/`-`. **294 de teste trec.**

## 0.5.4 — nginx 1.20 (AlmaLinux 9): compatibilitate vhost

Trei erori nginx, toate prinse **proactiv** rulând `nginx -t` cu vhost-ul real pe
server înainte de a da înapoi utilizatorului — nu una câte una. Protecția din
`step_nginx_shared` funcționase corect la prima: a detectat `nginx -t` picat,
și-a șters propriile fișiere și a lăsat nginx valid, site-urile operatorului
neatinse.

- **`http2 on;` e nginx 1.25.1+.** AlmaLinux 9 livrează 1.20.1, care îl respinge
  cu `unknown directive "http2"`. Toate trei șabloanele folosesc acum
  `listen ... ssl http2`, forma care merge pe 1.20→curent. Un test static o
  păzește.
- **`proxy_read_timeout` duplicat.** Locația `/stream` (SSE) includea
  `proxy-params.conf` (care seta timeout-ul) și îl redeclara. Timeout-urile s-au
  mutat la nivel de `server` (moștenite de toate locațiile), deci `/stream` poate
  suprascrie `read_timeout` la 3600s fără conflict.
- **`proxy_http_version` duplicat.** Aceeași cauză — `/stream` repeta directive pe
  care include-ul le oferă deja. Acum adaugă doar ce diferă.

`nginx -t` trece acum cu vhost-ul complet, verificat pe nginx 1.20.1 de pe host.
**293 de teste trec.**

## 0.5.3 — Runtime pe server: migrații și logging

Cu accesul SSH am condus eu pașii Python până la capăt pe host, în loc să dau
înapoi utilizatorului o eroare pe rând. Trei bug-uri de runtime, toate reparate și
**verificate direct pe server**:

**Logging: chei rezervate în `extra=`.** `migrate.py` loga
`extra={"name": m.name}`, dar `name` e un atribut al `LogRecord`, iar logging-ul
aruncă `KeyError` la coliziune — la `makeRecord`, înainte de orice filtru. A oprit
migrarea la mijloc. Redenumit în `migration`. Un test static respinge toate cele
~20 de chei rezervate în orice `extra=` din cod.

**Migrații: funcții non-IMMUTABLE în index-uri.** Postgres refuză o funcție
STABLE într-un index. `0002` avea `now()` într-un predicat parțial, `0008` avea
`date_trunc('hour', detected_at)` (STABLE pe `timestamptz`) într-o expresie de
index. Reparate: index compus în loc de predicat cu `now()`, și o coloană stocată
`detected_hour` în loc de `date_trunc` în index. Un test static prinde clasa
(`now`, `date_trunc`, `extract`, `current_*`, `to_char` în orice `CREATE INDEX`).

**Verificat pe host, capăt la capăt:** toate cele 9 migrații se aplică; serviciul
web pornește, se conectează la Postgres și ascultă pe 127.0.0.1:8787; `config-check`
trece; autentificarea scram a bazei întoarce `1`. **292 de teste trec.**

## 0.5.2 — Reanaliză: rezistența la resume

După prea multe erori punctuale la primul deploy, o revizuire a întregului flux
de instalare a scos la iveală cauza comună: **stare derivată calculată o singură
dată, într-un pas marker-gated, dar folosită de pașii de după.** Variabilele
trăiesc doar în procesul curent; markerele persistă pe disc. Deci orice resume
sărea pasul care calcula starea, iar restul rulau fără ea.

**`resolve_config` rulează acum necondiționat, la fiecare invocare** — nu mai e un
pas. Rezolvă `PUBLIC_PORT` (443 în shared), `ADMIN_IP`, `SURICATA_OK`, `BPF_HINT`,
`NGINX_WAS_PREEXISTING` și validează modul nginx, sursând `preflight.env` de
fiecare dată. Asta a fost cauza erorii „nginx_mode is 'shared' but public_port is
8443" la resume: reasignarea `PUBLIC_PORT=443` trăia într-un pas pe care resume-ul
îl sărea.

**`SNAPSHOT_DIR` se stabilizează pe resume.** Era construit dintr-un timestamp
per-rulare, deci un proces reluat arăta spre un director pe care pasul de snapshot
nu-l crease — rupând backup-ul configurației nginx și rollback-ul automat.
`resolve_config` îl rezolvă din symlink-ul `predeploy-latest`.

**Config imbricat: `dict` în loc de dataclass.** Cu `from __future__ import
annotations`, `field.type` e un string, deci `is_dataclass("WebConfig")` era False
și secțiunile imbricate rămâneau dict-uri brute — `cfg.web.nginx_mode` crăpa la
migrare. Reparat cu `get_type_hints`. Patru teste noi încarcă YAML real, gaura pe
care testele existente (care foloseau `Config()` cu defaults) n-o acopereau.

**`rollback.sh` șterge markerele de instalare la final.** Le păstra, deci un
reinstall după rollback sărea pași ale căror fișiere tocmai fuseseră șterse — un
sistem pe jumătate instalat care se raporta complet.

**`pg_hba.conf`: regulile scram erau adăugate DUPĂ defaults.** `pg_hba` e
prima-regulă, iar AlmaLinux livrează `host all all 127.0.0.1/32 ident`. Regulile
noastre scram, adăugate la sfârșit, nu erau atinse niciodată — orice conexiune ca
`sentinel` pica cu „Ident authentication failed". Acum se **inserează înaintea**
defaults (awk, idempotent). Reparat și pe serverul curent, cu autentificarea
verificată direct. `deploy/postgres/fix-pg-hba.sh` repară un host care a luat calea
veche.

Fluxul de generare a configului a fost verificat prin simulare pentru ambele
moduri (shared → 443, dedicated → 8443), încărcat și validat. **290 de teste trec.**

## 0.5.1 — Corecții din primul deploy real

Trei probleme prinse instalând efectiv pe server, toate reparate cu verificare
contra mașinii reale.

**`psql -c` nu interpolează `:'pw'`.** Rolul de bază se crea cu
`psql -c "CREATE ROLE sentinel LOGIN PASSWORD :'pw'"`, dar `-c` tratează șirul
drept SQL pur pentru server — interpolarea `:'variabilă'` e o funcție client-side
activă doar pentru input din stdin sau `-f`. `:'pw'` ajungea literal la parser:
`syntax error at or near ":"`. Reparat trimițând statement-ul pe stdin
(`printf ... | psql -v pw=…`), ceea ce păstrează și parola în afara liniei de
comandă, scopul inițial al lui `:'pw'`.

**`Test-Ssh` omora deploy-ul la sondajul sudo.** `sudo -n true` (sonda care
verifică dacă sudo cere parolă) scrie pe stderr, iar sub `$ErrorActionPreference
= 'Stop'` PowerShell 5.1 promovează asta la eroare terminantă — scriptul murea
înainte să apuce să ceară parola. Reparat coborând preferința local pe durata
apelului.

**Credențialele sudo nu persistă între sesiuni SSH pe Windows.** OpenSSH pe
Windows nu suportă multiplexarea conexiunilor (ControlMaster), deci `sudo -v`
într-o sesiune și `sudo -n install` în alta nu împart cache-ul. Documentat: pe
Windows, deploy-ul are nevoie de o regulă NOPASSWD pentru utilizatorul de deploy,
sau rulare din Git Bash unde ControlMaster funcționează.

## 0.5.0 — Alternativa: vhost pe 80 și 443

`--nginx-mode shared` pune Sentinel ca vhost pe nginx-ul existent, în loc de un
listener propriu pe `:8443`. `dedicated` rămâne implicit.

**284 de teste trec.**

### De ce merită păstrate ambele

Sunt răspunsuri la două situații diferite, nu o preferință de stil:

| | `dedicated` | `shared` |
|---|---|---|
| Cerință | Niciuna | nginx trebuie să dețină 80/443 |
| URL | `https://sentinel.exemplu.ro:8443` | `https://sentinel.exemplu.ro` |
| Certificat | Webroot prin serviciul de pe `:80`, sau DNS-01 | Funcționează din prima — servește singur provocarea ACME |
| Firewall provider | Portul 8443 de deschis | Nimic |
| Ce atinge | Nimic existent | `/etc/nginx/conf.d/`, partajat cu site-urile tale |

Dacă pe `:80` e Apache sau Caddy, `shared` nu e aplicabil și instalarea refuză
explicit în loc să scrie un vhost nginx pe care nimeni nu îl citește.

Câștigul principal al modului `shared` e că **rezolvă blocajul certificatului din
0.4.0**: vhost-ul are propriul bloc `:80` cu `location ^~ /.well-known/acme-challenge/`,
deci HTTP-01 funcționează fără nicio intervenție în configurația ta. Nu mai există
pas manual, nu mai există `--cert-mode dns` ca ultimă soluție.

### Costul, spus direct

Modul `shared` scrie într-un director partajat cu vhost-urile tale. Un config
invalid al nostru face `nginx -t` să eșueze pentru **tot** serverul. Un `reload`
ar fi doar refuzat — site-urile ar continua să ruleze — dar următorul *restart*,
din orice motiv nelegat, n-ar mai porni nginx deloc. Aia e o pană latentă cu
numele nostru pe ea, declanșată luni mai târziu.

Deci, în ordine: refuză dacă nginx nu deține 80/443; **refuză dacă `nginx -t`
eșuează deja înainte să atingem ceva** (nu adăugăm un vhost la un nginx rupt, ca
să nu devenim suspectul principal pentru o pană care nu e a noastră); instalează
și retestează; **la eșec își șterge propriile fișiere** și confirmă că nginx a
redevenit valid.

Vhost-ul e limitat prin `server_name`, nu declară `default_server`, iar zonele de
rate-limit și cache-ul TLS sunt prefixate `sentinel_` — un vhost partajat nu
consumă numele altuia. Dacă totuși devine cel implicit, instalarea îți spune să
adaugi `default_server` în vhost-ul **tău**, pentru că altfel am decide noi care
dintre site-urile tale răspunde la un Host necunoscut.

### Rollback

`rollback.sh` detectează modul instalat și **nu restaurează snapshot-ul
`/etc/nginx` în modul `shared`**. Ar anula și modificările făcute de tine la
site-urile tale după deploy — un rollback al Sentinel care șterge, tăcut, munca
altcuiva. Ștergerea fișierelor noastre e undo-ul complet acolo.

### Corecție: adresa de admin nu ajungea în allowlist

La preflight, `sudo` șterge `SSH_CLIENT` din mediu, deci detecția adresei de la
care administrezi eșua — nu pentru că rulai local, ci pentru că sudo scrisese
mediul. La instalarea reală asta ar fi lăsat allowlist-ul **gol**, exact starea
în care prima blocare automată te poate scoate afară. Garanția anti-lockout
depindea de o variabilă pe care sudo o elimină.

Reparat prin captura adresei **client-side**, printr-o comandă SSH non-sudo unde
`SSH_CONNECTION` încă există, și pasarea ei explicită ca `--admin-ip` atât la
preflight cât și la install. `preflight.sh` acceptă acum flagul; un `--admin-ip`
dat manual câștigă în fața valorii scrise de preflight. Un test verifică tot
lanțul, fiindcă e o proprietate de siguranță, nu o comoditate.

Un al doilea bug pe același traseu, prins la prima rulare: captura din
PowerShell, `(Get-SshOutput '…' -split '\s+')[0]`, citea `-split` ca argument al
funcției, deci nu împărțea nimic, iar `[0]` indexa primul *caracter* — `86.35…`
devenea `8`. Împărțit în două instrucțiuni, plus o gardă care refuză orice nu e
IPv4 înainte de a-l pune în allowlist.

Corectat și sumarul de preflight: în modul `shared` afișa `https://…:8443` și
„deschide portul", deși în shared nu e niciun port de deschis.

### Corecții: `deploy.ps1` nu pornea deloc

Trei bug-uri, găsite la prima rulare reală, toate fatale la **parsare** — deci
scriptul murea înainte de prima linie, cu erori care arătau spre cod nevinovat:

- **`?.` (null-conditional) e sintaxă PowerShell 7.** Windows livrează 5.1, exact
  shell-ul pentru care scriptul există. Îl verificasem cu `pwsh` 7, unde trece.
  Înlocuit cu o funcție `Find-Tool` explicită.
- **String-uri cu ghilimele duble imbricate în `$(...)`** — parser-ul 5.1 nu le
  poate procesa. Precalculate în `$keyArg`, `$resumeCmd`, `$dashLine`, ceea ce se
  citește oricum mai bine.
- **Fișier UTF-8 fără BOM.** 5.1 îl decodează ca ANSI, deci fiecare em dash
  ieșea `â€"`. BOM-ul e singura cale in-band de a-i spune că e UTF-8.

Verificarea rulează acum pe **ambele** versiuni, iar două teste noi păzesc
regresia: una respinge sintaxa 7-only pe linii care nu sunt comentarii, alta cere
BOM la orice `.ps1` cu caractere non-ASCII. Un `pwsh -Command` nu prinde niciunul
dintre cazuri, fiindcă `pwsh` **este** 7.

**Al patrulea, cel mai urât: `Invoke-Ssh` returna un array.** O funcție
PowerShell returnează *tot* ce se scrie în output stream, deci `& ssh ...` urmat
de `return $LASTEXITCODE` întorcea `@('connected', 0)`. Comparația `-ne 0`
filtrează elementele nenule, obținea `'connected'`, care e truthy — deci
verificarea de conectivitate eșua **exact pentru că reușise**. Se inversa doar la
succes, cel mai prost mod posibil în care o verificare poate fi greșită.

Afecta patru locuri: sondajul SSH, rollback-ul (mereu „reported errors"),
dry-run-ul (`exit` cu un array) și pornirea instalării.

Împărțit în două funcții, fiindcă „returnează codul de ieșire" și „lasă
operatorul să vadă și să tasteze o parolă" nu pot fi făcute de aceeași funcție:
`Test-Ssh` rulează pentru cod, cu output-ul aruncat, deci returnează un `int`
curat; `Invoke-SshLive` nu returnează nimic și nu capturează nimic, deci ssh
moștenește consola — sudo poate cere parola, iar output-ul apare pe loc în loc să
fie tamponat pe linii. Codul se citește din `$LASTEXITCODE` după apel.

Un test static păzește regresia: orice funcție `.ps1` care conține
`return $LASTEXITCODE` trebuie să trimită output-ul nativ în afara pipeline-ului.

Adăugat și `[Alias('SshHost','Server','H')]` pe `-HostName`: `-Host` nu poate fi
un nume de parametru (PowerShell rezervă `$Host`), dar e ce încearcă toată lumea.

`preflight.sh` acceptă acum `--nginx-mode`. În `shared` nu mai cere portul 8443
liber — un deploy care nu îl leagă nu are motiv să eșueze pentru el.

### Configurație

`web.nginx_mode` acceptă `dedicated` sau `shared`. `RESERVED_BIND_PORTS` distinge
acum între **a lega** un port și **a apărea** într-un URL: în `shared`, 443 e un
port public legitim pentru că nginx îl ține deja, dar `web.port` — portul pe care
ascultă efectiv procesul — rămâne interzis pe 22/80/443 în ambele moduri.

## 0.4.0 — Port dedicat: 80 și 443 rămân ale tale

Serverul rulează deja alte servicii pe 80 și 443. Dashboard-ul se mută pe
**8443** (configurabil cu `--web-port`), iar Sentinel nu mai atinge porturile
standard. Un agent de monitorizare care înlocuiește serviciul pe care îl
monitorizează și-a inversat scopul.

**273 de teste trec.**

### Blocajul real: certificatul

`certbot --nginx` **nu mai funcționează.** Provocarea HTTP-01 are nevoie de `:80`,
TLS-ALPN-01 de `:443` — ambele ocupate. Asta nu e un detaliu de configurare, e
singurul lucru care stă între „instalat" și „HTTPS valid din internet", adică
criteriul de acceptanță al P1.

Patru moduri, prin `--cert-mode`:

| Mod | Ce face |
|---|---|
| `auto` *(implicit)* | **Testează efectiv** dacă serviciul de pe `:80` poate servi provocarea ACME — scrie un token, îl cere din exterior prin HTTP, îl șterge. Emite doar dacă a reușit |
| `webroot` | Presupune că poate și încearcă direct |
| `dns` | Provocare DNS-01, fără niciun port |
| `selfsigned` / `none` | Sare peste emitere / folosește un certificat existent |

Verificarea prealabilă din `auto` contează: fără ea, certbot ar eșua **după** o
încercare de autorizare, ceea ce consumă din rate-limit-ul Let's Encrypt. Și un
certificat lipsă nu mai eșuează instalarea — un avertisment de browser nu merită
un rollback al unui dashboard funcțional. Reia doar pasul de certificat cu
`--cert-mode webroot --from-step 33`.

Sentinel **nu** adaugă singur blocul `/.well-known/acme-challenge/` în
configurația serviciului de pe `:80`, deși ar putea. Aceea e configurația ta, iar
un agent de monitorizare care editează vhost-ul aplicației tale de producție ca
efect secundar al instalării e exact dauna colaterală pe care restul acestui
installer o evită. Îți spune exact ce să adaugi, pentru nginx, Apache și Caddy.

### Al doilea blocaj, mai puțin evident: nginx refuza să pornească

`nginx.conf` implicit pe AlmaLinux conține un server block legat de `:80`. Cu
portul ocupat de altcineva, `systemctl start nginx` eșuează cu
`bind() to 0.0.0.0:80 failed` — iar eșecul arată ca un bug în Sentinel, nu ca un
conflict de porturi.

Sentinel nu are nevoie de `:80` deloc, deci listener-ul e comentat — **dar numai
dacă nginx a fost instalat de noi.** Dacă era deja acolo servind site-urile tale,
`nginx.conf` e al tău și nu se atinge; instalarea îți spune ce să verifici.
Detecția se face *înainte* de `dnf install`, altfel n-ai cum să mai distingi.

### Restul

- Catch-all-ul de 444 se leagă acum **doar** pe portul lui Sentinel. Nu revendică
  `default_server` pe 80 sau 443 — acelea sunt ale serviciilor tale, iar
  preluarea default-ului lor le-ar strica vhost-ul sau ar face nginx să refuze să
  pornească.
- Preflight nu mai cere 80/443 libere. Le *raportează*, și dacă nginx le deține
  semnalează două lucruri: provocarea ACME e ușoară, și ai putea servi
  dashboard-ul ca vhost normal pe `:443` sub alt `server_name` în loc de un port
  separat — Sentinel nu face asta automat, din același motiv ca mai sus.
- Smoke-test-ul verifică loopback și exterior **separat**, ca un eșec să spună
  care strat e greșit. „Merge pe 127.0.0.1 dar nu din exterior" înseamnă firewall
  de provider, nu Sentinel.
- `80`, `443` și `22` sunt în `RESERVED_PORTS`: validarea configului le refuză
  chiar dacă cineva editează `sentinel.yaml` de mână. Plus un test care verifică
  că template-urile nginx nu hardcodează niciun port.

### Note

Portul 8443 trebuie deschis în firewall-ul providerului. nftables pe gazdă e
deny-lister cu `policy accept` și nu îl blochează, dar un security group de cloud
o face — iar simptomul e „nu merge din exterior" cu Sentinel perfect funcțional.

---

## 0.3.1 — Vhost dedicat: sentinel.exemplu.ro

Dashboard-ul se servește pe un subdomeniu propriu. Vhost propriu, loguri
proprii, rate-limit propriu, CSP propriu — un `/sentinel` pe un site existent
ar fi moștenit configurația și antetele acelui site.

### Găsit la configurare: dashboard-ul răspundea pe IP brut

Vhost-ul nu declara `default_server`, iar nginx face implicit primul server
block. Fiind singurul pe gazdă, Sentinel ar fi răspuns la **orice** Host —
inclusiv o scanare pe `https://203.0.113.10`, care ar fi returnat pagina de
login și ar fi anunțat exact ce rulează acolo și unde să se îndrepte un atac pe
credențiale.

`sentinel-default-deny.conf` închide conexiunea cu **444** (fără răspuns, nu 403
sau 404 — acelea confirmă că serverul ascultă și e dispus să vorbească). Se
instalează **doar** dacă nimic altceva nu revendică deja `default_server`: două
pe aceeași adresă fac nginx să refuze să pornească, iar preluarea default-ului
altcuiva ar fi exact tipul de daună colaterală pe care Sentinel trebuie să o
evite. Dacă e sărit, instalarea spune de ce și ce să verifici manual.

`smoke-test.sh` verifică acum ambele: o cerere pe IP brut și un Host necunoscut
trebuie să nu primească răspuns. Fără test, regresia ar fi invizibilă.

### Numele vhost-ului nu este secret

`sentinel.exemplu.ro` apare în logurile **Certificate Transparency** din clipa în
care Let's Encrypt emite certificatul. CT e obligatoriu și public — oricine poate
căuta `exemplu.ro` pe crt.sh și vedea fiecare subdomeniu pentru care s-a cerut
vreodată un certificat.

Documentat explicit în `SECURITATE.md`, pentru că e genul de lucru pe care e
ușor să-l presupui altfel. Consecința: apărarea stă pe straturile reale (TOTP,
Argon2id, rate-limit, fail2ban, allowlist de IP), nu pe faptul că adresa e greu
de ghicit. Un wildcard prin DNS-01 ar ține numele în afara CT, dar subdomeniul
rămâne rezolvabil pentru cine îl ghicește — merită doar dacă ai deja wildcard.

---

## 0.3.0 — P1: fundația pe server

Dashboard-ul funcționează end-to-end: login cu parolă + TOTP peste HTTPS,
sesiuni, audit, și watchdog-ul anti-lockout. **266 de teste trec.**

### Ce poți face acum

```bash
sudo sentinel web --create-admin          # cont + QR TOTP, afișat o singură dată
sudo sentinel web --list-users
sudo sentinel web --set-password --username <u>   # revocă și sesiunile
sudo sentinel web --enroll-totp --username <u>    # telefon pierdut
sudo sentinel web --unlock --username <u>
```

Apoi `https://<domeniu>` → login → cod TOTP → panou cu starea reală a sistemului.

### Decizii care contează

**Parole.** Argon2id, 64 MB și 3 treceri — ~150 ms per verificare. Memoria e
constrângerea: 64 MB se alocă per verificare concurentă, iar nginx limitează
`/login` la 5/min per adresă. Nu ridica `memory_cost` fără să refaci aritmetica
față de RAM-ul disponibil.

**Enumerarea utilizatorilor.** Un username inexistent tot costă o verificare
Argon2 completă, contra unui hash fals generat la import. Fără asta, timpul de
răspuns spune atacatorului care conturi există — primul pas al oricărui atac pe
credențiale. Există un test care măsoară asta.

**Secretele TOTP sunt criptate la rest**, cu o cheie derivată HKDF din
`SENTINEL_SESSION_SECRET`. Un dump al bazei de date nu produce al doilea factor
funcțional — care e tot rostul celui de-al doilea factor. Chei separate per scop:
refolosirea aceluiași secret pentru semnarea cookie-urilor și pentru criptarea
TOTP ar face ca o slăbiciune într-un context să devină slăbiciune în celălalt.

**Codurile TOTP nu pot fi refolosite.** Contorul acceptat se consumă în baza de
date cu o comparație strict-mai-mare, atomic în SQL. Verificarea fără consum ar
lăsa codul valid tot restul fereastrei de 30 de secunde — suficient pentru
cineva care citește peste umăr, sau pentru replay-ul unui form post capturat.

**Autentificarea în doi pași e o stare în baza de date**, nu un flag în cookie.
O sesiune cu parola acceptată ajunge la `/totp` și nowhere else, iar niciun
tamper pe cookie nu schimbă asta — rândul însuși spune că sesiunea e neterminată.
La confirmarea celui de-al doilea factor **tokenul se rotește**: dacă cookie-ul
intermediar s-a scurs între etape, valoarea scursă e acum inutilă.

**Tokenul de sesiune e stocat ca SHA-256**, nu în clar. Un dump al bazei nu
oferă nicio sesiune vie — exact motivul pentru care parolele se hashuiesc,
aplicat lucrului care e la fel de bun ca o parolă.

**Lockout per-utilizator ȘI per-sursă.** Doar per-utilizator ar permite blocarea
unui username cunoscut ca refuz de serviciu; doar per-sursă ar lăsa o încercare
distribuită să treacă.

**Expirare absolută, nu glisantă.** `last_seen_at` se actualizează, dar expirarea
nu se prelungește: o expirare glisantă înseamnă că un cookie furat rămâne valid
cât timp hoțul continuă să-l folosească.

**Administrarea conturilor e pe server, nu în interfață.** Un dashboard care își
poate schimba propriile roluri sau parole transformă o compromitere de interfață
într-o preluare de control.

**Zero JavaScript în P1.** Pagina de login și panoul sunt HTML și CSS. De-asta
CSP-ul poate fi `script-src 'self'` fără `unsafe-inline`, fără excepții — și
de-asta un XSS aici n-ar avea de unde să încarce payload și unde să trimită date.
`scripts/vendor-assets.sh` descarcă uPlot și htmx cu verificare de checksum când
sosesc graficele în P2; nu sunt commituite, pentru că un blob minificat în git e
nerevizuibil.

### Gap real închis din P0

`sentinel-watchdog.timer` era activat de `install.sh` și unitatea systemd indica
`respond/watchdog.py` — **care nu exista**. Iar executorul rulează din P1
încolo, deci blocarea era posibilă fără deadman.

Scris acum: root, la 60 de secunde, fără nicio dependență de baza de date sau de
restul pachetului. Golește blocklist-ul când există `/etc/sentinel/PANIC`, când
`/healthz` e jos peste 5 minute, când `sentinel-detect` e failed sau în restart
loop, sau când blocklist-ul depășește plafonul. Funcția de decizie e pură, ca
fiecare ramură să fie testabilă fără server — și fiecare ramură **este** testată,
pentru că modul de eșec al componentei ăsteia este „operatorul nu mai poate intra
pe propriul server".

### Bug-uri prinse la verificare

- **`GET /login` scria un rând în baza de date.** Prima versiune ținea tokenul
  CSRF pre-autentificare într-o sesiune temporară — deci fiecare afișare a
  paginii de login era un INSERT, iar 10.000 de cereri pe minut umpleau tabela.
  Înlocuit cu un token semnat, stateless. (Și `user_id=0` ar fi încălcat cheia
  străină oricum.)
- **Butonul „Anulează" din pagina TOTP era o buclă infinită.** Posta la
  `/logout`, care cerea o sesiune *completă* și redirecta o sesiune `pending`
  înapoi la `/totp`. Nu exista cale de abandonare a unui login pe jumătate.
- **Un 404 nu primea pagina de eroare.** Handler-ul era înregistrat pe
  `HTTPException` din FastAPI, dar router-ul aruncă varianta din Starlette pentru
  o cale nepotrivită — deci un 404 răspundea cu JSON brut.
- **Testul de CRLF a prins două editări proprii.** `write_text` pe Windows
  traduce `\n` în `\r\n`, ceea ce pe Linux dă `bad interpreter: /bin/bash^M`.
  A meritat existența de două ori.

### Note

`datetime.UTC` (3.11+) înlocuit cu `timezone.utc`, echivalent și disponibil pe
3.10 — codul rămâne corect pe ținta 3.12, dar suita de teste devine rulabilă și
pe interpretoare mai vechi. `security.py` importă `Database` doar sub
`TYPE_CHECKING`, deci primitivele de parolă, TOTP și CSRF pot fi importate și
revizuite fără driver de bază de date.

---

## 0.2.0 — Standalone

Sentinel nu mai presupune nimic despre ce altceva rulează pe server. Nicio
integrare, nicio dependență, niciun IP sau path specific unei anumite instalări
în cod.

Refactorul nu a fost o ștergere: constrângerile care erau *principii* îmbrăcate
în detalii specifice au fost **generalizate**, nu eliminate. Protecțiile reale
au rămas; doar au încetat să fie corecte pe exact un server.

### Ce s-a schimbat de fapt

| Înainte | Acum |
|---|---|
| Listă hardcodată de porturi ale altui produs | Preflight descoperă ce ascultă deja și refuză să ia un port ocupat |
| Aserțiune de sănătate pe un stack anume | **Baseline generic**: preflight înregistrează fiecare serviciu activ, port în ascultare și container; instalarea compară la final și face rollback automat dacă ceva s-a oprit |
| Path-uri specifice în lista de căi protejate | Un *floor* hardcodat (`/opt/sentinel`, `/etc/sentinel`, `/root/.ssh`, `/etc/ssh`, `/etc/shadow`, `/boot`…) + `patch.extra_protected_paths` pe care îl completezi tu |
| Un IP public în lista never-block | Doar intervale universale (loopback, RFC1918, link-local) + `response.extra_allowlist` pe care îl vezi și îl schimbi |
| Filtru BPF Suricata hardcodat pe o adresă | **Preflight eșantionează interfața 10 secunde**, identifică fluxurile dominante și îți spune dacă ai nevoie de un filtru — apoi îl pre-completează |
| Colector opțional pentru un SIEM extern | Eliminat. Sentinel nu mai are nicio dependență externă în afara Anthropic (opțional) și Telegram |
| Excluderi auditd pentru directoarele altui produs | Excluderi generice (Docker, Sentinel însuși) + instrucțiune să adaugi ce scrie continuu pe gazda ta |

### Teste noi

Două invariante care fac generalizarea verificabilă, nu doar declarată:

- `test_never_block_list_contains_no_deployment_specific_addresses` — nicio
  adresă rutabilă global nu poate fi hardcodată în lista never-block. Ar fi
  corectă pe exact o instalare, greșită pe toate celelalte, și invizibilă:
  nimeni nu citește un fișier de constante căutând surprize.
- `test_no_deployment_specific_addresses_are_hardcoded` — scanează codul,
  template-urile și configurațiile livrate pentru IP-uri publice. Intervalele
  RFC 5737 de documentație sunt permise; restul nu.

Suita completă rămâne verde.

---

## 0.1.0 — P0: schelet, skill, agenți, deployment

Prima livrare. Conține tot ce trebuie pentru a instala Sentinel pe server și
pentru a-i da agentului AI contextul și regulile cu care lucrează. Componentele
runtime (colectare, detecție, bot, dashboard) urmează în P1–P5.

### Livrabile cerute explicit

- **Skill Claude Code** `.claude/skills/sentinel-soc/` — `SKILL.md` cu
  frontmatter, 10 fișiere de referință (arhitectură, schema DB, catalog de
  detecții, metodologie de triaj, schema planurilor de patch, backup/restore,
  suprafața Telegram, mediul serverului, modelul de predicție, ghid de stil RO),
  5 scripturi read-only de acces la date, schema JSON autoritativă și
  template-uri RO.
- **Patru definiții de agent** în `.claude/agents/`: `sentinel-soc-analyst`
  (triaj, corelare, predicții, rapoarte), `sentinel-patch-engineer` (proceduri
  de patch), `sentinel-vuln-analyst` (interpretare scanere),
  `sentinel-deployer` (asistență la instalare).
- **Document de deployment** — `docs/DEPLOYMENT.md`, pas cu pas, în română.
- **Script automat de deployment prin SSH** — `scripts/deploy.sh` (Git Bash/WSL)
  și `scripts/deploy.ps1` (PowerShell), plus `deploy/install.sh` pe server:
  idempotent, numerotat pe pași, reluabil cu `--from-step`, cu rollback.

### Infrastructură

- Schema PostgreSQL completă: 8 migrații, partiționare zilnică pe `raw_events`,
  `health_samples` și `capacity_samples`, funcții de retenție și rollup,
  `audit_log` append-only cu lanț de hash și trigger care refuză UPDATE/DELETE
  la nivel de bază de date.
- Tabela nftables `inet sentinel`: `policy accept`, allowlist evaluat înaintea
  blocklist-ului, seturi cu TTL în kernel, chain `forward` pentru porturile
  publicate de containere.
- Unități systemd cu hardening per rol; `sentinel-web` are `IPAddressDeny=any`,
  `sentinel-executor` are un `CapabilityBoundingSet` minim.
- nginx cu TLS, HSTS, `limit_req` pe login, CSP strict fără `unsafe-inline` și
  fără CDN, plus certificat placeholder ca `nginx -t` să treacă înainte de
  certbot.
- Reguli auditd înguste (fiecare watch corespunde unei reguli de detecție) și
  jail-uri fail2ban pentru login-ul dashboard-ului.

### Executorul root

`executor/` — singura componentă care rulează ca root. ~400 de linii,
stdlib-only, fără niciun import din pachetul `sentinel`. Verifică
`SO_PEERCRED`, validează contra unei politici hardcodate în cod, scrie el
însuși rândurile de audit, și rulează un watcher propriu pentru
`/etc/sentinel/PANIC` independent de timer-ul systemd.

### Validatorul de planuri de patch

`sentinel/patch/validator.py` — poarta dintre „un model a scris o procedură" și
„root o rulează pe producție". Respinge: comenzi ca string, binare în afara
allowlist-ului (`sh`, `bash`, `env`, `sudo`, `python` lipsesc deliberat),
metacaractere de shell, căi protejate, comenzi nedeterministe (`git pull`,
`npm install`, `:latest`), planuri reversibile fără rollback, pași
neidempotenți fără backup, backup fără verificare de spațiu liber, baze de date
neincluse în backup, și lipsa flag-ului `requires_reboot` pentru
kernel/glibc/systemd/openssl.

### Teste

Suita de securitate include: intrări ostile pentru politica executorului,
invariantul „executorul nu importă nimic din `sentinel/`", verificarea că cele
două copii ale constantelor de siguranță sunt de acord, interdicția repo-wide
pentru `shell=True` / `os.system` / `eval` (prin `tokenize`, ca să nu confunde o
mențiune din docstring cu o utilizare), detectarea CRLF, și aserțiunea că
`policy accept` este încă politica lanțului de bază nftables.

### Alegeri de siguranță implicite

- **Auto-block dezactivat la instalare.** Primele 72 de ore sunt în mod
  „observă": operatorul primește pe Telegram ce *ar fi* fost blocat, cu buton.
- **Blocurile nu se persistă** în nftables. Reboot-ul este mereu o ieșire.
- **Suricata gated pe RAM** — sub 2,5 GB disponibili nu se instalează, iar
  Sentinel rulează log-only.

### Corecții făcute la verificare

- `install.sh` scria un drop-in systemd în `/etc/systemd/system/service.d/`,
  care s-ar fi aplicat **tuturor** serviciilor de pe host, inclusiv Docker.
  Eliminat; hardening-ul stă inline în fiecare unitate.
- `install.sh` nu instala `sentinel-proxy-params.conf`, pe care vhost-ul îl
  include, și nu genera certificatul placeholder — `nginx -t` ar fi eșuat
  înainte ca certbot să apuce să ruleze.
- `deploy.sh` folosea `bash -s` cu secretele pe stdin; `bash -s` consumă stdin
  ca script, deci secretele nu ar fi ajuns niciodată. Acum `install.sh` se
  execută ca fișier de pe server, iar stdin rămâne al datelor.
- `install.sh` prompta pentru confirmare după ce citise stdin până la EOF, ceea
  ce ar fi produs un abort. Acum detectează stdin non-TTY (confirmarea a fost
  deja luată local de `deploy.sh`).

### Cunoscut ca lipsă în această fază

Configurația Suricata (P6), manifestul de binare externe cu checksum-uri (P7)
și `deploy/upgrade.sh`. Toate sunt referite cu guard în `install.sh` și sar
curat.
