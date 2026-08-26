# Cine s-a logat, și ce a rulat

Sentinel anunță pe Telegram fiecare sesiune interactivă și înregistrează
**fiecare comandă** rulată de oricine s-a autentificat pe gazdă. Documentul ăsta
spune ce se înregistrează, ce nu, și de ce fiecare alegere e cea care e.

Cerut de operator pe 24 august 2026.

---

## Ce vezi pe Telegram

**La deschiderea unei sesiuni interactive:**

```
🔐 Logare pe server
Cont: operator
De la: 198.51.100.7
Terminal: pts1
Când: 2026-08-24 14:39 UTC

Nimic neobișnuit: cont, adresă și oră cunoscute.
```

Cu două butoane: **„Am văzut"** și **„Nu sunt eu"**.

**La închiderea ei:**

```
🔓 Sesiune încheiată
Cont: operator · de la 198.51.100.7
Durată: 1h 35m · 412 comenzi · 3 privilegiate

Comenzi privilegiate:
· sudo systemctl restart nginx
· sudo -n dnf -y update
· sudo tee /etc/sentinel/sentinel.yaml
```

Când ceva e neobișnuit — cont, adresă sau oră nemaivăzute — mesajul o spune, iar
severitatea urcă de la `info` la `high`.

### Ce NU produce niciun mesaj

**Sesiunile fără terminal.** Un `ssh gazdă "comandă"` — deploy, rsync,
diagnostic — nu alertează. Comenzile lui **se înregistrează**, complet; doar
mesajul lipsește.

Motivul e o măsurătoare, nu o preferință. Pe șapte zile, gazda a avut **557 de
sesiuni fără terminal și 29 cu**. Un mesaj pe fiecare ar fi însemnat ~80 pe zi,
dintre care 75 despre propriile automatizări — iar un canal cu optzeci de mesaje
pe zi se oprește într-o săptămână. Un canal oprit e mai rău decât niciunul:
arată ca acoperire și nu e.

### Alerta nu se poate tăcea

`login` e în `NEVER_MUTED_KINDS` (`sentinel/telegram/quiet.py`), alături de
`panic` și `watchdog`. Cineva care intră la 3 dimineața e chiar motivul pentru
care există alerta.

A doua jumătate a cerinței — *„atenție să nu generezi fals pozitiv"* — e ce face
prima suportabilă. O alertă care nu poate fi tăcută trebuie să fie rară și
adevărată, altfel scutirea de la orele de liniște devine chiar mecanismul prin
care canalul e abandonat.

---

## Butonul „Nu sunt eu"

Face **două** lucruri: blochează adresa și **închide sesiunea**. Blocarea
oprește următoarea conexiune; cine e deja înăuntru rămâne înăuntru. Prima fără a
doua e o reparație care arată completă.

Ordinea e blocare-apoi-închidere, dinadins: invers, cine e închis se poate
reconecta în secunda dintre cele două.

### Nu te poate încuia afară

Dacă adresa e în `allowlist`, butonul **refuză să blocheze** și o spune:

```
⚠️ 198.51.100.7 e în allowlist — NU am blocat-o.
Ar fi însemnat să te închizi singur afară. Dacă chiar vrei: /block 198.51.100.7
```

Sesiunea se închide oricum — asta nu te lasă pe dinafară, doar te deconectează.

Costul, spus pe față: **dacă cineva chiar intră de pe adresa ta, butonul nu-l
scoate.** Rămân `/block`, care n-are garda asta, și consola VPS-ului.

### Deblocarea readuce accesul, nu sesiunea

`/unblock <ip>`, sau butonul din mesajul de confirmare. O sesiune închisă nu se
poate redeschide — și e bine să știi asta înainte de a apăsa.

---

## Ce e „neașteptat"

Trei lucruri, învățate din ce se întâmplă:

| Faptul | Cum se învață |
|---|---|
| **cont nemaivăzut** | prima logare a unui cont; a doua nu mai surprinde |
| **adresă nemaivăzută** | idem |
| **oră nefirească** (01:00–05:59 UTC) | **nu se învață niciodată** |

Ora e o *margine*, nu un obicei: cine se loghează la 4 dimineața de trei ori nu
face ora aia obișnuită.

**În primele 14 zile nu se ridică niciun incident** — doar mesaje. Altfel prima
săptămână ar produce un incident la fiecare logare, exact când încă nu știi dacă
sistemul e de încredere. Fereastra se măsoară de la cel mai vechi fapt din
`login_baseline`, deci e derivată din conținut, nu dintr-o dată scrisă separat.

Consecința, spusă pe față: **o adresă de atacator devine „obișnuită" după prima
ei logare.** Ce face asta suportabil e că prima a produs și mesaj, și incident.

---

## Istoricul de comenzi

### Ce se înregistrează

**Fiecare `execve` dintr-o sesiune cu login.** Nu comenzile pe care le-ai tastat
— tot ce pornește din ele.

Asta e mai mult decât te aștepți, și e important să știi cifra înainte de a te
uita prima oară:

| Ce | Câte comenzi |
|---|---|
| o logare interactivă, fără să faci nimic | **~630** |
| un deploy | **~405 000** |
| gazda în repaus | 0 |

Cele 630 sunt shell-ul de login care sursează `/etc/profile.d/*`: `xargs`,
`grep`, `tclsh` apar de câte 76 de ori fiecare. Nu e o eroare — e granularitatea
la care nucleul vede lucrurile.

Filtrul care face asta suportabil e `-F auid!=unset` din
`deploy/audit/sentinel.rules`: procesele fără sesiune de login — toți daemonii,
toate cele șase containere Docker, tot cronul — nu ajung niciodată la regulă.

### Ce NU se înregistrează

**Ce se rulează într-un container.** `docker exec -it <container> bash` dă un
shell ale cărui comenzi nu apar: procesele din container n-au `auid`. **Intrarea
în container SE înregistrează**, cu tot cu argumente, deci momentul e vizibil;
ce urmează, nu.

E o gaură reală, cunoscută, și e exact calea pe care ar folosi-o cineva care
știe ce face. Închiderea ei ar însemna auditarea fiecărui `execve` de pe gazdă —
adică zeci de mii de înregistrări pe oră, ceea ce antetul fișierului de reguli
refuză cu „aici mor seturile de reguli audit".

**Comenzile fără terminal ale conturilor de automatizare.** Din 25 august 2026,
un cont trecut în `history.skip_command_accounts` (implicit `sentinel-deploy`)
nu-și mai vede în `session_commands` comenzile rulate **fără terminal real**.

Motivul e cifra din tabelul de mai sus: un singur deploy a produs **405 777 de
comenzi în 140 de secunde** — `systemctl` de 320 591 de ori și `sleep` de
173 376, adică buclele de așteptare ale instalatorului —, iar replica externă a
crescut de la 83 MB la **909 MB în câteva ore**.

Ce rămâne, dinadins:

* **regulile auditd sunt neatinse.** `/var/log/audit/audit.log` are în
  continuare fiecare `execve` al contului. Un `-F auid!=<uid>` ar fi oprit
  emisia din nucleu — adică `sudo -u sentinel-deploy bash` ar fi devenit complet
  neînregistrat, o gaură fix acolo unde ar căuta cineva. Se taie doar proiecția
  în bază;
* **rândul de sesiune rămâne.** „S-a deschis o sesiune de deploy" e faptul cu
  valoare de securitate, iar cele ~161 de sesiuni nu ocupă nimic;
* **o logare interactivă pe contul de automatizare se înregistrează întreagă.**
  Filtrul se uită la terminalul COMENZII, nu la contul sesiunii. `ssh
  sentinel-deploy@gazdă` cu shell adevărat capătă `pts0`, deci comenzile se
  păstrează, sesiunea se promovează la `interactive` și **alerta de logare
  pleacă**. Cu un filtru pe cont, sesiunea n-ar fi fost promovată niciodată, iar
  contul de automatizare — care are `sudo NOPASSWD: ALL` — ar fi devenit singura
  cale de intrare pe care Sentinel tace.

**Nu se taie în tăcere.** Rândurile aruncate se numără, ajung în jurnal ca
`commands_skipped`, iar **autodiagnosticul citește cheia înapoi**:

```bash
sudo -u sentinel /opt/sentinel/venv/bin/sentinel selfcheck --print | grep -A3 history
```

**Verdictul nu mai pleacă de la configurație.** Prima scriere a verificării
citea cheia și, pe lista goală, ieșea `ok` înainte de orice SQL. Citit pe gazdă
pe 25 august 2026: `/etc/sentinel/sentinel.yaml` e din 20 august și n-are
secțiunea `history:`, iar `sentinel.yaml.new` — din 25 august, scris de
instalator și neîmbinat — **n-o are nici el**; filtrul n-a ajuns niciodată acolo.
Contul de deploy scrisese totuși **1 266 de comenzi fără terminal în 48 de ore**.
Deci verificarea scrisă tocmai ca să deosebească intenția de efect raporta `ok`
peste starea pe care exista s-o vadă.

Acum întâi se întreabă DATELE — *cine scrie comenzi fără terminal, și cu ce
ritm* —, și abia apoi configurația spune dacă ăla e un cont pe care cineva a
cerut să-l arunce:

| ce raportează | ce înseamnă |
|---|---|
| `degraded`, „scrise pe un cont din afara filtrului" | cineva scrie peste **20 000 de comenzi fără terminal pe oră** sub un cont pe care filtrul nu-l cunoaște. Ritm de automatizare, nu de om: un deploy a scris 405 777 de rânduri în 140 de secunde, iar cea mai încărcată oră de muncă omenească măsurată a avut 2 438 |
| `degraded`, „configurat, dar nu e în vigoare" | s-au SCRIS rânduri pe care regula le interzice. Configurația nu e cea pe care o citește serviciul, sau procesul rulează codul vechi |
| `degraded`, „configurația filtrului n-a fost îmbinată" | `sentinel.yaml.new` cere alte conturi decât cele încărcate. Ăsta e discriminatorul dintre «am ales să nu arunc nimic» și «nimeni n-a îmbinat fișierul» |
| `degraded`, „numește conturi care nu există" | contul configurat nu e pe gazdă. Comparația e pe egalitate exactă, deci filtrul nu poate potrivi niciun rând |
| `unknown` | baza de conturi nu se poate citi (uid-urile lipsesc din filtru), sau `.new` există și nu se poate citi. „Nu știu" nu e „e în regulă" |
| `ok`, „nu aruncă nimic" | lista încărcată e goală, `.new` nu cere altceva, iar datele n-au arătat nicio furtună. Stare validă — e implicitul |

Întrebarea pusă datelor **nu știe nimic** despre `deploy.sh`, despre `--user`
sau despre secțiuni de YAML, deci prinde la fel de bine o invocație cu contul
vechi, un cont nou apărut și o configurație neîmbinată. E mărginită dinadins:
citește cele mai recente **60 000** de comenzi din fereastra de 48 de ore, nu
toată fereastra — rulează la 5 minute pe o tabelă de milioane de rânduri, iar
`EXPLAIN` pe gazdă dă 4 239 pentru felie și 50 283 pentru varianta nemărginită.
De aceea raportul spune și **ce interval a acoperit felia**: „am văzut ultimele
20 de minute" și „am văzut 48 de ore" sunt afirmații diferite.

Ritmul se numără **pe oră**, nu ca medie pe toată felia: o rafală de două minute
diluată într-o fereastră de două zile ar ieși «26 pe oră» și n-ar semăna cu
nimic. Ora e chiar unitatea în care s-au măsurat și furtuna, și munca de om.

**Ce nu prinde**, spus pe față: pe 25 august, un deploy rulat sub
`sentinel-deploy` a scris ~1 300 de comenzi fără terminal cu totul (`systemctl`
247, `sleep` 92) — cu două ordine de mărime sub furtuna de dinainte, deci sub
prag. E voit: răul pe care filtrul îl repară e tabela crescută cu sute de mii de
rânduri, nu cu o mie. Dacă se măsoară vreodată o livrare care umple tabela
stând sub prag, atunci pragul e greșit, nu regula.

**Verificarea care era scrisă aici înainte nu funcționa.** Era

```bash
journalctl -u sentinel-ingest | grep commands_skipped
```

și potrivea ÎNTOTDEAUNA: `commands_skipped` e mereu în `extra`, iar
`JSONFormatter` scrie și zerourile. Nu deosebea «am aruncat 405 777 de rânduri»
de «secțiunea n-a fost îmbinată niciodată» — adică exact întrebarea. E tiparul
pe care `CLAUDE.md` îl numește: un grep după un șablon care potrivește orice.

**Contul se scrie în două ortografii.** `sentinel/collectors/auditd.py` pune în
`username` numele contului când auditd sau `pwd` îl rezolvă, și `auid`-ul
NUMERIC ca șir când niciunul nu poate. Măsurat pe gazdă pe 25 august 2026:
**87 935 de rânduri** scrise ca `username = '1000'` pentru un cont care are
milioane sub numele lui. De aceea conturile configurate se rezolvă la uid la
încărcarea configurației, iar filtrul potrivește pe nume SAU pe uid ca șir.

Marginea, spusă pe față: un uid supraviețuiește contului care l-a avut. Dacă
`sentinel-deploy` e șters și un cont de om primește același uid, comenzile lui
FĂRĂ TERMINAL ar fi aruncate până la următoarea repornire a serviciului, care
reface maparea. E compromisul ales, nu unul scăpat din vedere: alternativa e să
lași necurățate zeci de mii de rânduri pe cont.

**Pe gazdele care rulau deja, nu se aplică singur.** Instalatorul NU rescrie un
`sentinel.yaml` existent — scrie `sentinel.yaml.new` și avertizează —, deci
secțiunea trebuie mutată de mână. Până atunci lista e goală, iar goală înseamnă
„nu se aruncă nimic", adică exact comportamentul de dinainte.

### Secretele sunt tăiate înainte de bază

`argv` e vizibil în `/proc` pentru orice utilizator, iar de-asta
`scripts/deploy.sh` trimite secretele pe stdin, niciodată în argv. Restul lumii
nu respectă regula: `mysql -pparola`, `curl -H "Authorization: Bearer …"`.

`sentinel/redact.py` taie valorile care arată a secret **la colectare**, înainte
ca rândul să atingă baza. Redactat la citire, secretul ar rămâne în tabelă, în
backup și în replica externă.

**Nu e o garanție.** E o listă de tipare, iar un secret care nu seamănă cu
niciunul trece întreg: `curl https://api/x?k=SECRET`, un token pus ca argument
pozițional, o parolă care arată ca un cuvânt obișnuit. Limita e scrisă și în
`docs/SECURITATE.md`.

### Cât se păstrează

* **pe gazdă: nelimitat.** Întrebarea „ce a rulat cineva acum trei luni" e chiar
  cazul de folosință. La ~100 000 de comenzi pentru 22 MB, ordinul de mărime e
  ~10 GB/an; gazda are 91 GB liberi.
* **pe agregator, două ferestre**, fiindcă una singură n-a ținut:
  * comenzile sesiunilor **fără terminal — 14 zile**;
  * comenzile oamenilor, și cele fără sesiune cunoscută — **180 de zile**.

Măsurat pe 25 august 2026, la câteva ore după pornire: replica a crescut de la
83 MB la **909 MB**, iar `session_command_entries` era, singură, mai mare decât
celelalte unsprezece tabele la un loc. Cauza e chiar deploy-ul: buclele de
așteptare ale instalatorului — `systemctl is-active` de 320 591 de ori, `sleep`
de 173 376 — într-o singură rulare.

Găzduirea e partajată și are cotă. O bază plină nu se manifestă ca „tabela e
mare"; se manifestă ca **ingestia refuzată pentru toate cele douăsprezece
fluxuri** — panoul îngheață în întregime din cauza unei singure tabele.

Ce se pierde după paisprezece zile: din panoul EXTERN nu se mai poate răspunde
la „ce a rulat deploy-ul din 3 martie". De pe gazdă, da — acolo rândurile rămân.
Ce nu se pierde e partea care contează pentru securitate: comenzile oamenilor, și
faptul că sesiunea a existat.

Tăierea se face din cron, iar ruta o face în tranșe de 5000 ca lock-ul InnoDB să
dureze milisecunde:

```
0 4 * * *  curl -sS "https://<domeniu>/api/sentinel/retention?key=<SENTINEL_CHECK_SECRET>"
```

### Curățarea a ce s-a strâns deja

Filtrul de mai sus oprește rândurile NOI. Cele scrise înainte de el se șterg cu
două scripturi — unul pe fiecare bază, fiindcă cele două n-au în comun decât
regula: pe gazdă parola stă în `/etc/sentinel/secrets.env` și se vorbește cu
PostgreSQL, pe replică datele de conectare sunt variabile de mediu ale găzduirii
și se vorbește cu MariaDB.

Amândouă șterg **în tranșe de 5000** ca lock-urile să dureze milisecunde,
amândouă sunt **uscate implicit**, și amândouă au **două moduri**, fiindcă sunt
două probleme diferite.

**Migrația se aplică ÎNAINTE de prima rulare.** `commands_purged` e o coloană
nouă, iar scriptul o citește chiar în listare. Pe o bază nemigrată,
`--list-sessions` moare cu `column s.commands_purged does not exist` — verificat
pe gazdă. Deci: `sudo sentinel migrate` (`0028_commands_purged.sql`) înaintea
scriptului de pe gazdă, `npm run migrate` (`0016_commands_purged.sql`) înaintea
celui de pe replică.

#### Modul pe cont: exact regula filtrului

Cont de automatizare ȘI fără terminal real, cu ambele ortografii ale contului
(nume și uid).

```bash
# gazda (PostgreSQL, session_commands)
sudo -u sentinel /opt/sentinel/venv/bin/python \
     scripts/purge-automation-commands.py                 # numără, nu șterge
sudo -u sentinel /opt/sentinel/venv/bin/python \
     scripts/purge-automation-commands.py --apply

# replica (MariaDB, session_command_entries) — se rulează PE găzduire
npm run purge-automation -- --accounts sentinel-deploy
npm run purge-automation -- --accounts sentinel-deploy --apply
```

Replica n-are `/etc/passwd`-ul gazdei, deci nu poate rezolva singură uid-urile.
Rularea de pe gazdă tipărește linia `caut ca : …` cu toate ortografiile pe care
le caută; alea se dau la `--accounts` pe replică.

#### Modul pe sesiune: istoricul de DINAINTEA contului de deploy

Cele ~2,9 milioane de rânduri vechi **nu sunt pe contul de automatizare**.
`scripts/deploy.sh` se rula cu contul de logare al operatorului, iar `auid` e
uid-ul de LOGARE și supraviețuiește lui `sudo` — deci fiecare deploy și-a scris
comenzile sub numele lui. Măsurat pe 25 august 2026, filtrul pe cont ar șterge
din ele **1 143 din 2 978 485**.

Pe același cont stau și diagnosticele rulate de la distanță de operator —
`psql` 69 977, `find` 90 659, `cat` 100 938, `ps` 38 051 —, care **trebuie
păstrate**. Nicio regulă pe cont nu le poate deosebi: e același cont. Ce le
deosebește e sesiunea.

```bash
# ce sesiuni fără terminal există, cele mai grase întâi. Nu șterge nimic.
sudo -u sentinel /opt/sentinel/venv/bin/python \
     scripts/purge-automation-commands.py --list-sessions

# uscat, apoi pe bune
sudo -u sentinel /opt/sentinel/venv/bin/python \
     scripts/purge-automation-commands.py --sessions 2521,2530
sudo -u sentinel /opt/sentinel/venv/bin/python \
     scripts/purge-automation-commands.py --sessions 2521,2530 --apply

# pe replică, identificatorii sunt ai unei anume instanțe
npm run purge-automation -- --list-sessions
npm run purge-automation -- --instance <id> --sessions 2521,2530 --apply
```

**Granița se citește, nu e codificată.** O sesiune de deploy are 250 000–560 000
de comenzi, o sesiune de diagnostic a unui om are sute: trei ordine de mărime,
evidente în listă. Un prag scris în cod ar fi o presupunere despre o gazdă pe
care scriptul n-o cunoaște, iar decizia ce e zgomot și ce e istoric e a
operatorului.

**Numărătoarea din listare se oprește la 2000 pe sesiune**, iar coloana arată
`2000+` când s-a atins plafonul. Varianta exactă costa, măsurat pe gazdă,
`Execution Time: 18395.833 ms` cu trei procese de fundal și 243 723 de citiri
din heap — plătite exact înainte de curățare, când tabela e cea mai mare, pe o
gazdă care în aceeași zi a dat `504` pe panou. Nici `statement_timeout` n-o
oprea: scriptul îl pune pe `0` fiindcă `VACUUM` are nevoie de asta. Pentru o
alegere între „sute" și „sute de mii", `2000+` spune tot atât cât `558 079`, iar
cifra exactă apare oricum în `--sessions <id>` fără `--apply`, înainte de orice
ștergere. Lângă ea se arată și `command_count`, contorul memorat: dacă cele două
nu seamănă, contorul a rămas în urmă, iar asta se vede în loc să fie ales tăcut
de cod. Pe o gazdă cu prea multe sesiuni ca să încapă în buget, coloana devine
`?` și scriptul spune că n-a măsurat — `?` și `0` nu au voie să arate la fel.

Modul pe sesiune șterge **tot** ce a rulat sesiunea aleasă, indiferent de cont și
de terminal. Două lucruri îl opresc: un identificator care nu există și o
sesiune `interactive` — adică una în care cineva chiar a tastat. Amândouă sunt
refuzuri, cu mesaj, nu rulări care raportează zero.

Pe replică, `--sessions` cere și `--instance`: `session_source_id` e
`login_sessions.id` de pe gazdă, iar el se renumerotează de la 1 pe fiecare
server.

#### Contoarele sesiunii se aduc la zi

`login_sessions` nu se șterge niciodată — «s-a deschis o sesiune de deploy» e
faptul cu valoare de securitate. Dar `command_count` de pe rândul ei e un contor
MEMORAT al rândurilor care tocmai au căzut, iar panoul și rezumatul de închidere
de pe Telegram îl citesc pe el, nu tabela. Lăsat neatins, sesiunea 2521 ar arăta
**«558 079 comenzi» deasupra unui tabel gol**.

Deci, după ștergere, pe gazdă:

* `command_count` și `sudo_count` se **renumără din tabelă** — invariantul lui
  `_refresh_counters` rămâne cel de dinainte: numărate, nu incrementate;
* câte au căzut intră în **`commands_purged`** (coloană nouă,
  `0028_commands_purged.sql`).

Amândouă, fiindcă sunt două afirmații diferite: câte rânduri SUNT, și câte au
FOST. «Sesiunea asta a rulat 558 079 de comenzi în 140 de secunde» e chiar
faptul din care s-a născut filtrul; șters odată cu rândurile, peste trei luni
nimeni nu mai poate răspunde la «de ce e filtrul ăsta aici».

Pe replică se scrie **numai `commands_purged`**. `command_count` de acolo e o
afirmație a GAZDEI, adusă de expediere și rescrisă la fiecare lot: pusă pe zero
de pe replică, s-ar întoarce la următoarea expediere. Ce știe replica, și numai
ea, e câte rânduri a șters EA — iar «558 079 comenzi, 558 079 șterse din arhiva
asta» e adevărat și citibil.

**Contra-cazul rămâne deschis, și se spune aici ca să nu fie descoperit mai
târziu:** dacă se curăță GAZDA și nu replica, gazda renumără `command_count` din
tabela ei și expediază cifra nouă, unde rândurile sunt toate la locul lor.
Panoul arată atunci «0 comenzi (0 șterse)» deasupra unui tabel plin — aceeași
minciună, în direcția opusă. Ce ar închide-o e o afirmație a replicii despre
PROPRIILE ei rânduri; deocamdată nu există. Practic: curăță-le pe amândouă, sau
citește cifra din arhivă știind de unde vine.

#### Colația replicii nu e crezută pe cuvânt

Coloanele replicii sunt `utf8mb4_unicode_ci`, iar sub ea `username IN (?)` e
insensibil la majuscule și la spațiile de umplere, și `REGEXP` e insensibil la
majuscule. PostgreSQL și Python nu fac niciuna. Pe aceleași date, `'PTS0'` era
ARUNCAT de filtrul viu și PĂSTRAT de replică, iar `'SENTINEL-DEPLOY'` era socotit
contul pe replică și nu pe gazdă.

Predicatul de pe replică poartă acum `COLLATE utf8mb4_bin`. Dar scris în
predicat nu înseamnă aplicat de server, deci înainte de prima ștergere scriptul
**întreabă serverul**, cu chiar construcția din predicat, și se oprește dacă
răspunsul nu e cel al gazdei. Un cod de ieșire nu e dovadă de efect.

Ștergerea de pe gazdă **nu se propagă** la replică: singurul flux care șterge la
sursă și oglindește ștergerea e `selfcheck_state`. De-asta sunt două rulări, nu
una.

**Spațiul nu se întoarce singur, pe niciuna dintre baze.** `DELETE` raportează
rândurile șterse și lasă fișierul la fel de mare — spațiul devine reutilizabil
de tabelă, nu liber pe disc. Scripturile o spun și numesc pasul care lipsește:

* pe gazdă, `VACUUM FULL session_commands`. **Nu se rulează din script**:
  rescrie tabela sub `ACCESS EXCLUSIVE`, deci ingestia și panoul așteaptă cât
  durează, și cere încă o dată dimensiunea tabelei liberă pe disc. Gazda are 91
  GB liberi, deci fișierul mare nu costă nimic acolo — costul lock-ului e mai
  mare decât câștigul;
* pe replică, `--optimize`, care rulează `OPTIMIZE TABLE`. **Aici se oferă**,
  fiindcă acolo fișierul mare CHIAR e problema: găzduirea are cotă, iar o bază
  plină înseamnă ingestia refuzată pentru toate fluxurile. Rămâne opțional și
  explicit, fiindcă rescrierea are nevoie de încă o dată dimensiunea tabelei —
  pe o cotă aproape plină, exact ce lipsește.

Raportul fiecărui script spune mărimea înainte și după, câte rânduri au căzut,
și — renumărat după ștergere, nu dedus din codul de retur — câte mai potrivesc
regula.

Gazda are 91 GB liberi; 128 × 5 înseamnă 640 MB.

---

## Contul separat pentru automatizări

Pasul 36 al instalării creează `sentinel-deploy`: cont propriu, `sudo` fără
parolă, director `.ssh` gata.

**Cheia nu se generează pe gazdă.** Jumătatea privată nu trebuie să existe
niciodată acolo:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sentinel_deploy -C sentinel-deploy
ssh-copy-id -i ~/.ssh/sentinel_deploy.pub sentinel-deploy@<gazdă>
```

Livrarea merge pe el **implicit**, din 25 august 2026 — și pe cheia lui, tot
implicit:

```bash
bash scripts/deploy.sh --host <gazdă> …                      # --user sentinel-deploy, --key ~/.ssh/sentinel_deploy
bash scripts/deploy.sh --user altcineva --key ~/.ssh/alta …  # numai dacă ai instalat cu alt DEPLOY_ACCOUNT
```

**Contul și cheia sunt o singură decizie.** `sentinel-deploy` autorizează cheia
asta și nicio alta, deci implicitul de cont livrat singur era o cale de eșec: cu
o cheie veche, prima conexiune primește `Permission denied (publickey)`, iar
singura ieșire la îndemână e să pui `--user` înapoi pe contul tău — adică exact
starea în care filtrul e inert. Cheia implicită lipsă e doar un avertisment, nu
o oprire: un agent ssh sau un `IdentityFile` din `~/.ssh/config` sunt tot atât
de legitime, și scriptul nu le poate vedea.

Implicitul nu e o comoditate. `--user` era obligatoriu, deci fiecare rulare
numea contul de logare al operatorului, iar `auid` supraviețuiește lui `sudo`:
toate cele 405 777 de comenzi fără terminal ale unui deploy ajungeau sub numele
lui, care NU e în `history.skip_command_accounts` și nici nu are voie să fie —
sub același nume rulează și diagnosticele lui, care se păstrează. Filtrul era
corect și complet inert.

### De ce contează

Până la el, „fără terminal" e singurul lucru care deosebește o automatizare de
tine — iar asta e o presupunere, nu o graniță. Măsurat pe 24 august 2026, gazda
avea **exact o cheie autorizată**, folosită și de operator, și de scripturi. Nu
exista nimic care să le deosebească: nici amprenta cheii, nici adresa, nici
contul.

Cu contul separat, discriminatorul devine **identitatea**: o sesiune pe contul de
deploy e o automatizare, iar o sesiune *fără terminal pe contul tău* redevine o
surpriză.

### `sudo ALL`, și de ce

Regula lui `sudoers` e `NOPASSWD: ALL`, nu o listă de comenzi. Instalatorul
rulează `dnf`, `systemctl`, `nft`, `useradd`, `install`, `tee` și încă multe, iar
o listă care rămâne în urmă face un deploy să pice la jumătate — cel mai
periculos moment în care poate pica.

Ce face asta suportabil e că **contul e vizibil**: fiecare comandă a lui trece
prin regulile auditd și ajunge în `/var/log/audit/audit.log`, cu argumente.
Compromisul e „nelimitat dar complet înregistrat" în locul lui „limitat, în
urmă, și tot înregistrat" — iar al doilea doar pare mai sigur.

**Cât ține „complet", de pe 25 august 2026.** Din baza cu retenție nelimitată,
comenzile lui FĂRĂ TERMINAL nu mai intră (vezi mai sus). Rămân două lucruri, cu
ferestre diferite:

* **sesiunile lui, permanent**, cu ora, adresa și contorul lor — deci „când a
  intrat automatizarea" se poate răspunde oricând;
* **comenzile, cât ține jurnalul de audit de pe disc.** Ăla e `max_log_file = 8`
  MB × `num_logs = 5`, iar un singur deploy scrie ~25 MB — **două deploy-uri
  rotesc tot jurnalul**. Dacă vrei ca sursa completă să chiar fie completă mai
  mult de-atât, lărgește-l, cum scrie și mai sus:
  `max_log_file = 128` în `/etc/audit/auditd.conf`.

Iar comenzile TASTATE pe contul ăsta — o logare interactivă, cu `pts0` — rămân
în bază ca ale oricui altcuiva, și produc alertă.

---

## Ce s-a spart pe drum

Scris aici fiindcă `CLAUDE.md` cere ca tiparul să fie citibil, nu ca livrarea să
pară curată:

| Ce | Consecința |
|---|---|
| `USER_END` citit ca ieșire din sesiune | e perechea lui `USER_START`, nu a lui `USER_LOGIN`. 1534 de comenzi orfane din 14 157, plus un rând-fantomă la fiecare închidere în plus |
| `res` înghițea ghilimeaua de închidere | `success'UID="root"` în loc de `success`; **fiecare logare prin sshd era respinsă** |
| `terminal` din `USER_LOGIN` citit ca terminal | e numele SERVICIULUI; chiar cu pty forțat scrie `ssh`. Fiecare sesiune ieșea neinteractivă |
| `$2 - interval` fără cast | Postgres deduce `interval` pentru parametru. **Ingestia a fost picată 20 de minute**, pentru toate sursele |
| `json` neimportat în bot | **coada de notificări s-a oprit complet**, pentru orice fel de veste |

Ultimele două au trecut de suita verde. Cauza comună: dublele de test primesc
SQL-ul ca text și valorile ca obiecte Python — nimic din ele nu leagă tipuri. De
acolo a ieșit `tests/security/test_sql_parameters_are_typed.py`, care caută în
sursă ce un dublu nu poate vedea.
