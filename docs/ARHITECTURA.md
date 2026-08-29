# Arhitectura Sentinel

De ce arată așa, nu doar cum arată. Deciziile de proiectare care contează sunt
explicate aici, împreună cu ce s-a respins și motivul.

---

## 1. Problema

Un server Linux expus la internet rulează aplicații, dar nu are nicio
monitorizare de securitate: nimeni nu vede tentativele de intruziune, nimeni nu
blochează atacatorii, vulnerabilitățile se acumulează necunoscute, iar când
ceva se strică afli de la utilizatori.

Sentinel acoperă exact acest gol, **de sine stătător**: nu depinde de niciun
SIEM, de niciun agent extern și de niciun serviciu în afara gazdei pe care
rulează. Singurele dependențe externe sunt API-ul Anthropic (opțional — fără el
rulează determinist) și Telegram (pentru alertare).

Este însă un *musafir* pe serverul respectiv: ceva rula acolo înaintea lui, iar
acel ceva este motivul pentru care serverul există. Aproape toate deciziile de
mai jos decurg din asta.

---

## 2. Imaginea de ansamblu

```
                 ┌──────────── HOST Linux (systemd) ──────────────────┐
 internet ─▶ nginx :8443       ─▶ 127.0.0.1:8787  sentinel-web
                  │ TLS, HSTS, limit_req              │ doar citește
                  ▼                                   ▼
 eth0 ─▶ suricata ─▶ eve.json ──┐          PostgreSQL 16 @127.0.0.1
 journald / nginx / auditd ─────┼─▶ sentinel-ingest ─▶ raw_events
 docker events ─────────────────┘             │
                                              ▼
                                    sentinel-detect
                                       │                        │
                                       ▼                        ▼
                              decizie auto-block         sentinel-ai
                                       │                Messages API │ claude -p
                                       ▼ unix socket (SO_PEERCRED)
                              sentinel-executor  [root]
                                       ▼
                              nftables  table inet sentinel
```

Tot ce e durabil trece prin PostgreSQL. Nu există broker de mesaje.

---

## 3. Decizii care contează

### 3.1 `policy accept` — Sentinel e deny-lister, nu firewall

Lanțul nftables de bază acceptă implicit. Sentinel adaugă doar reguli de drop
pentru adrese specifice.

Consecința: **Sentinel nu te poate bloca prin eșec.** Dacă procesul moare, dacă
baza de date pică, dacă configurația e greșită sau dacă tabela nu se încarcă,
traficul trece. Singurul mod în care te poate bloca este blocându-te explicit —
iar pentru asta există allowlist-ul hard-codat, butonul de deblocare pe fiecare
mesaj, watchdog-ul și fișierul PANIC.

Alternativa (default-deny, ca un firewall clasic) ar fi mai „sigură" pe hârtie
și dramatic mai periculoasă în practică pe un server administrat de la distanță.

### 3.2 Blocurile nu se persistă

Tabela nu se scrie niciodată în `/etc/sysconfig/nftables.conf`. La boot,
`blocklist.py` re-aplică din baza de date blocurile neexpirate.

Reboot-ul e întotdeauna o ieșire. Deliberat.

### 3.3 TTL în kernel, nu în cron

Seturile au `flags timeout`. Kernelul expiră elementele. Fără cron sweeper,
fără drift dacă Sentinel e oprit, și un blocaj pus de un daemon care apoi moare
expiră oricum la timp.

### 3.4 Un singur component root, de ~400 de linii

`sentinel-executor` este singurul proces care rulează ca root. Restul rulează ca
`sentinel`, neprivilegiat.

Executorul:
- e stdlib-only și **nu importă nimic din pachetul `sentinel`** — o compromitere
  a codebase-ului principal nu ajunge în el;
- verifică `SO_PEERCRED` pe fiecare conexiune;
- validează fiecare cerere contra unei politici **hard-codate în cod**, nu în
  config și nu în baza de date, deci o compromitere a bazei nu o poate lărgi;
- **scrie el însuși rândul de audit**, deci un apelant compromis nu poate nici
  falsifica, nici omite o intrare.

Dacă depășește ~600 de linii, ceva e greșit.

### 3.5 Web-ul nu vorbește niciodată cu executorul

Dashboard-ul este public, deci este componenta cea mai expusă. Nu are drum
către acțiuni privilegiate: scrie un rând în `action_requests`, iar responder-ul
îl preia și cere confirmare pe Telegram pentru clasele distructive.

O compromitere a dashboard-ului scurge date de securitate. Nu poate bloca,
debloca, aplica patch-uri sau reporni nimic. `IPAddressDeny=any` în unitate
înseamnă că nici măcar nu are rețea în care să pivoteze.

### 3.6 AI-ul e în afara căii critice

Detecția, scorarea, decizia de blocare și notificarea sunt complet
deterministe. Claude intervine **după** ce incidentul există, e vizibil și s-a
acționat asupra lui.

Dacă API-ul cade sau bugetul se epuizează: verdictul determinist rămâne,
incidentele se deschid, blocurile se aplică, Telegram notifică. Mesajele sunt
marcate „(analiză AI indisponibilă)".

Asta nu e o optimizare de cost — e ce face sistemul utilizabil. Un SOC care se
oprește când un API extern are o problemă nu e un SOC.

### 3.7 Două transporturi Claude

| Transport | Pentru | De ce |
|---|---|---|
| Messages API direct | triaj, corelare, predicții, rapoarte | Rapid, ieftin, output structurat, prompt caching. Nu are nevoie de acces la fișiere |
| `claude -p` headless | planuri de patch, `/ask` | Astea chiar trebuie *să se uite la server*: vhost-ul nginx, unitatea systemd, `composer.lock`, ieșirea `dnf` |

CLI-ul rulează cu `--permission-mode plan` și un allowlist read-only de tool-uri.
Asta face ca o injecție de prompt dintr-o linie de log să fie **structural
incapabilă** să modifice sistemul, nu doar improbabil să reușească.

### 3.8 PostgreSQL, nu SQLite

Factorul decisiv: **mai mulți scriitori concurenți.** Șase daemoni separați.
SQLite ar fi forțat totul într-un singur proces plus o coadă IPC — o arhitectură
mai proastă pentru o economie marginală.

În plus: partiționare declarativă (retenția devine `DETACH` + `DROP`, instant,
fără bloat, în loc de un `DELETE` care lasă tabela la fel de mare), JSONB+GIN
pentru payload-ul brut, window functions pentru baseline, `percentile_cont`
pentru latențe.

Nu TimescaleDB: ar cere un repo terț într-un tool de securitate, iar
partiționarea nativă plus tabele de rollup acoperă nevoia la volumul ăsta.

### 3.9 Server-rendered, fără CDN, fără build step

Jinja2 + HTMX + uPlot, toate vendorizate local.

Pe un dashboard de securitate, un `<script src="https://cdn...">` ar fi ironic:
un terț care poate injecta cod în interfața ta de securitate, plus o scurgere a
existenței dashboard-ului către acel terț. Fără CDN, CSP-ul poate fi strict
(`script-src 'self'`, fără `unsafe-inline`), ceea ce înseamnă că un XSS în
dashboard nu are de unde să încarce payload și unde să trimită date.

Bonus: fără npm în lanțul de aprovizionare al unui tool de securitate, și fără
build step pe server.

### 3.10 Telegram prin long polling, nu webhook

Fără port de intrare, fără endpoint public de spoofat sau inundat. Și
funcționează chiar dacă nginx sau TLS e stricat — ceea ce contează, pentru că
Telegram este canalul de urgență, iar momentul în care ai cea mai mare nevoie de
el este momentul în care dashboard-ul e inaccesibil.

**Fiecare mesaj spune de pe ce instanță vine.** Un rând în față, `Instanță:
eticheta (id scurt)` — aceeași convenție ca panoul (`nameOf` din ruta de check a
agregatorului), cu id-ul tăiat la 8 caractere. Eticheta vine din
`instance_label` din `sentinel.yaml` și e opțională; fără ea rămâne id-ul scurt,
care e un prefix al lui `/etc/sentinel/instance_id`. Nu e configurabil pornit/
oprit: pe 27 august 2026 două instanțe au alertat în același chat nouăsprezece
ore, iar ziua în care apare a doua instanță e exact ziua în care nimeni nu se
gândește să pornească lucrul care le deosebește. Dacă identitatea nu se poate
citi, mesajul pleacă și spune că nu știe. Vezi `sentinel/telegram/identity.py`.

### 3.10b Ora afișată e ora ta, și spune care e

Baza scrie și păstrează UTC — asta nu se schimbă. Ce se citește, se citește în
`timezone` din `sentinel.yaml`, cu marcajul fusului în text: `24.08 08:54
EEST`. Un singur mecanism, `sentinel/util/tz.py`, folosit de Telegram, de panou
(filtrul Jinja `| ora`), de autoverificare și de detecție; `telegram/quiet.py`
îl reexportă, ca ferestrele de liniște și orele afișate să nu poată fi de acord
pe jumătate.

Nu e doar afișare. Fereastra „ore nefirești" din `detect/logins.py` se compara
cu ora **UTC**, iar cu Bucureștiul la UTC+3 asta însemna 04:00–08:59 local: o
logare la 08:54 era semnalată, iar una la 03:00 — 00:00 UTC — nu era semnalată
deloc. Se evaluează acum în fusul configurat.

`ZoneInfo`, niciodată un decalaj fix: un decalaj n-are reguli de oră de vară,
deci în noaptea în care se schimbă ceasurile totul se calculează cu o oră
greșit. Un fus necunoscut coboară zgomotos și **nu** face ora să dispară din
mesaj — marcajul spune în ce fus a ieșit până la urmă.

**Excepție, deliberată:** graficele din pagina de rapoarte etichetează capete de
găleată aliniate în UTC (`date_trunc(..., AT TIME ZONE 'UTC')`). O galeată
zilnică scrisă în ora locală ar numi „27.08" un interval care începe la 03:00,
deci acolo etichetele rămân UTC până când se decide mutarea granițelor.

### 3.11 Suricata, gated pe RAM

Dacă `MemAvailable` era sub 2,5 GB la instalare, Suricata nu se instalează, iar
Sentinel rulează log-only.

Detecția funcționează în continuare — pierde doar vizibilitatea la nivel de
pachet. Alternativa (a o instala oricum) ar însemna ca OOM killer-ul să aleagă
cel mai mare proces de pe gazdă — de obicei aplicația pe care Sentinel venise
să o protejeze.

**Filtrul BPF se măsoară, nu se ghicește.** Unele gazde duc un flux de volum
mare fără valoare de securitate (telemetrie, syslog, replicare backup); dacă
Suricata îl inspectează, discul se umple în câteva ore. Preflight eșantionează
interfața 10 secunde, identifică fluxurile dominante și îți spune dacă ai
nevoie de un filtru — în loc ca proiectul să hardcodeze adresa cuiva.

### 3.12 Un installer care întreabă, nu un pachet care presupune

Livrarea nu se face ca `.rpm` sau `.deb`. Un pachet e excelent la copiat fișiere
și prost la tot ce face de fapt instalarea asta: să afle cine deține portul 443,
să te întrebe de pe ce adresă administrezi înainte să existe vreo regulă de
blocare, să testeze dacă provocarea ACME poate fi servită înainte să consume din
rate-limit-ul Let's Encrypt, și să facă rollback dacă un serviciu al tău s-a
oprit. Un `%post` de RPM care ar încerca astea ar fi un installer prost deghizat
într-un pachet.

Deci: [`scripts/wizard.sh`](../scripts/wizard.sh) întreabă,
[`deploy/preflight.sh`](../deploy/preflight.sh) verifică,
[`deploy/install.sh`](../deploy/install.sh) face — și doar după confirmare.

**Diferențele între distribuții stau într-un singur fișier**,
[`deploy/lib/distro.sh`](../deploy/lib/distro.sh): manager de pachete, numele
pachetelor pentru aceleași roluri, inițializarea PostgreSQL (RHEL cere `initdb`;
Debian creează clusterul în postinst, iar un `initdb` manual acolo ar produce un
al doilea cluster nefolosit pe alt port), calea configurațiilor, fișierul de
opțiuni al Suricatei, SELinux față de AppArmor. Restul installer-ului nu știe pe
ce distribuție rulează — și un test respinge orice `dnf` sau `apt-get` direct
strecurat înapoi în el, fiindcă suportul pentru a doua familie ar deveni
altminteri ficțiune care eșuează la jumătatea instalării.

O distribuție din afara celor două familii e **refuzată pe nume**. O gazdă pe
care instalarea a eșuat vizibil e recuperabilă; una care pare protejată și nu e,
nu.


### 3.13 Filigranul entităților mutabile: trigger, nu tabelă outbox

Ce pleacă spre agregatorul extern se citește cu un cursor. Pentru `audit_log` —
append-only, un singur scriitor serializat — cursorul e ultimul `id` expediat:
monoton, fără goluri, **independent de ceas**.

Entitățile care se schimbă nu pot folosi asta. Un incident închis nu-și schimbă
`id`-ul, deci `WHERE id > cursor` nu-l vede niciodată. Cursorul lor e
`(updated_at, id)`, iar `updated_at` e ținut de un trigger `BEFORE UPDATE` pe
fiecare tabelă expediată (`sentinel/db/migrations/0023_ship_watermarks.sql`).

Alternativa era o tabelă outbox: exactă, ordonată, independentă de ceas. A fost
respinsă fiindcă cere editat fiecare modul din `sentinel/db/repo/` care mută o
entitate expediată — și fiecare editare e un loc unde se poate uita. Un `UPDATE`
scris peste șase luni pe o cale nouă nu scrie în outbox, rândul lui nu pleacă
niciodată, și nimic nu raportează lipsa. **Un trigger nu se uită.** Costul —
un rând atins la mijlocul ferestrei se trimite de două ori — e inofensiv, fiindcă
ingestia agregatorului e upsert.

**Prețul real e altul, și e plătit explicit: un cursor pe timp se încrede în
ceasul serverului.** Un salt înapoi lasă filigranul înaintea lui `now()`, iar
fluxul se oprește — interogarea rămâne validă, întoarce zero rânduri, și arată
identic cu o gazdă pe care nu s-a schimbat nimic. Deci derapajul se măsoară
(filigranul comparat cu `now()` al bazei), oprește runda cu eroare, și ajunge la
operator ca o constatare cu titlu propriu. Regula pe care stă tot: **„n-am
expediat nimic fiindcă nu s-a schimbat nimic" și „n-am expediat nimic fiindcă
ceasul a sărit" nu au voie să arate la fel.**

Ce NU face agentul: nu retrage filigranul singur. Ar salva rândurile din
fereastră, dar pe un ceas care oscilează ar retrimite aceeași fereastră la
fiecare rundă, la nesfârșit. Alegerea dintre o pierdere mărginită și un cost
nemărginit e a operatorului — procedura e în `docs/OPERARE.md` §13.

Ceasul nu e singura presupunere pe care mecanismul o face, iar celelalte două
sunt și ele măsurate în loc să fie crezute:

* **ordinea commit-urilor.** `now()` e ora de început a tranzacției, deci un rând
  atins într-o tranzacție lungă poate deveni vizibil deja *sub* filigran.
  Expeditorul mărginește cazul (nu trimite rândurile mai proaspete de 30 de
  secunde) **și îl măsoară**: la runda următoare re-numără fereastra tocmai
  citită, care e închisă prin construcție, deci orice rând găsit acolo în plus a
  fost comis cu întârziere. Se raportează cu numărul lui și se ține minte
  (`docs/OPERARE.md` §14). Mărginirea singură ar fi o presupunere care se strică
  fără să spună nimic;
* **că `updated_at` chiar se mișcă.** Toată mecanica stă pe un trigger dintr-un
  fișier de migrație, iar un fișier pe disc nu e dovadă că nucleul l-a acceptat.
  Fără trigger, fluxul e mort și arată perfect sănătos: zero rânduri, ceas bun,
  restanță zero, unitate `active`. Deci fiecare rundă întreabă `pg_trigger` —
  inclusiv `tgenabled`, fiindcă un trigger dezactivat rămâne în catalog — și
  lipsa **oprește** fluxul în loc să-l lase să pară la zi (`docs/OPERARE.md` §15).


### 3.14 Scanarea containerelor costă un privilegiu, și el se scrie aici

`sentinel` e **membru al grupului `docker`** și vorbește direct cu
`/run/docker.sock`. Nu există niciun proxy între ele.

**Pe gazda asta, grupul `docker` e echivalent cu root.** Cine ajunge la socket
poate porni un container care montează `/` și scrie în el — fără exploit, doar
cu API-ul documentat. Consecința, spusă fără menajamente: *o compromitere a
agentului de securitate înseamnă acum root pe mașina pe care o păzește.*

Operatorul a fost informat și a acceptat schimbul, deliberat, în august 2026.
Alternativele — un proxy peste socket, sau o a doua componentă privilegiată care
exportă imaginile — sunt fiecare mai mult cod care rulează mai aproape de root
decât o apartenență la grup. Nu e o decizie ascunsă și nu e una la care se poate
ajunge din greșeală: se dă în [`deploy/install.sh`](../deploy/install.sh) și se
scoate împreună cu `scan.containers: false`. Lăsată pe loc cu scanerul oprit,
păstrează tot costul și niciun beneficiu.

Ce se scanează: **imaginile containerelor care rulează**, nu tot inventarul de
imagini de pe disc. O vulnerabilitate într-o imagine pe care n-o execută nimeni
nu e accesibilă nimănui, iar pusă în panou lângă una care rulează transformă
panoul în ceva ce nu se mai citește. Cheia unei constatări e **referința
imaginii** — `nginx:1.27` — fiindcă reparația e o reconstrucție de imagine, o
dată, pentru toate containerele care o folosesc; ce se scanează e totuși id-ul
imaginii care rulează cu adevărat, ca un tag reindreptat fără repornire să nu
schimbe răspunsul.

Absența lui docker **nu** e o eroare: e o gazdă fără containere, și nu scrie
niciun rând în `scans`. Docker prezent dar inaccesibil **e** o eroare, cu rând
`failed` și cheie roșie în `/selfcheck`: cineva a cerut scanarea și ea nu se
face. Detaliile sunt în docstring-ul lui
[`sentinel/scan/trivy_image.py`](../sentinel/scan/trivy_image.py).

**Pragul de severitate al imaginilor e HIGH, al fișierelor a rămas MEDIUM.**
Ridicat pe 29 august 2026, la cererea operatorului: pe cele șase imagini care
rulau, trivy 0.73.0 dădea 2838 de constatări de la MEDIUM în sus față de un
plafon de refuz de 2500, deci scanarea refuza să ingereze în fiecare noapte și
nu raporta *nimic* despre containere; la HIGH sunt 450. `trivy_fs` n-a fost
atins — 92 de constatări, nicăieri lângă plafonul lui.

O scanare care se uită la mai puțin trebuie să **spună** că se uită la mai
puțin, altfel „0 vulnerabilități medii pe containere" se citește ca „containerele
sunt curate" când înseamnă „nu ne-am uitat". Deci pragul se scrie în
`scans.target` la deschiderea rândului — e acolo și pe rândurile `failed` — iar
`check_last_scan` îl citește înapoi *din rând* și îl spune lângă numărul de
constatări. Din rând, nu din constantele de azi: altfel o cifră măsurată la alt
prag ar fi reetichetată cu cel curent.

Și cele ~2388 de constatări MEDIUM ingerate de rulările de dinainte **nu** se
închid: `mark_resolved_absent` primește severitățile pe care rularea chiar le
putea vedea, fiindcă „nu mai e raportată" acoperă două lucruri diferite — ce s-a
reparat, și ce nu mai e căutat. Ele rămân deschise, iar câte sunt se scrie în
jurnal la `WARNING` după fiecare rulare.

### 3.15 Familia se detectează o dată, la instalare

Runtime-ul Python **nu se uită în `/etc/os-release`**. `distro_detect` din
[`deploy/lib/distro.sh`](../deploy/lib/distro.sh) decide familia la instalare,
`install.sh` o scrie în `sentinel.yaml` ca `platform.family`, iar codul o citește
de acolo.

Motivul e tiparul din `CLAUDE.md`: două detecții sunt două surse de adevăr, iar
două surse de adevăr se contrazic exact pe gazda unde contează. Valoarea nu
trece nici prin `preflight.env` — fișierul acela e citit de `resolve_config`
*după* detecția pe care install.sh o face oricum la pornire, deci un fișier
rămas de la o rulare anterioară pe altă gazdă ar fi putut suprascrie răspunsul
viu.

O valoare necunoscută e refuzată la încărcarea configurației, nu tolerată prin
revenirea la implicit. `family: ubuntu` arată corect și nu selectează niciun
scaner; dacă ar fi tolerat, gazda ar rula `dnf`, n-ar găsi comanda, iar pagina
de vulnerabilități ar arăta zero.

**Implicitul e `rhel`, și e explicit.** Instalările care preced cheia rulează
toate pe AlmaLinux, iar `install_config` refuză să suprascrie un `sentinel.yaml`
viu — scrie `.new` și avertizează. Deci gazdele existente nu primesc cheia
niciodată, iar implicitul e singurul lucru care le păstrează comportamentul.

Numele scanerului de pe familia `rhel` **rămâne `dnf`**, și nu din inerție:
`check_last_scan` raportează sub `scan:last:{scanner}`, iar `selfcheck_state` de
pe gazda de producție are cheia `scan:last:dnf` cu istoric din 21 august 2026.
Redenumită, cheia veche ar fi reconciliată afară și în locul ei ar apărea una cu
`since = now()` — aceeași pierdere de istoric prinsă pe 25 august la
`audit:records`.

### 3.16 Scanarea de pachete pe Debian nu e la fel de bună, și o spune

| Familie | Scaner | Ce dă |
|---|---|---|
| rhel | `dnf updateinfo list cves --security` | CVE, severitatea din aviz, versiunea care repară |
| debian | `apt-get -s dist-upgrade` | pachetul și versiunea, **fără CVE, fără severitate** |

Pe RHEL metadatele furnizorului sunt adevărul: știu despre remedieri
*backportate*, adică un CVE reparat într-un șir de versiune vechi. Scanerele
generice le raportează ca vulnerabile și produc un zid de fals-pozitive — de
aceea `trivy_fs` e îndreptat spre dependențele aplicațiilor, nu spre pachetele
sistemului.

Pe Debian și Ubuntu nu există echivalent local. Metadatele de securitate stau în
fluxul OVAL al Canonical și în trackerul de securitate Debian — amândouă
servicii de rețea, niciunul pe gazdă. Ce poate răspunde `apt`, offline și
corect, e o întrebare mai îngustă: **ce pachete instalate au o actualizare care
așteaptă în depozitul de securitate** al distribuției (`noble-security`,
`bookworm-security`, buzunarele Ubuntu Pro).

Deci o constatare pe Debian spune „există o actualizare de securitate pentru
openssl". Nu spune „openssl are CVE-2026-1234". `cve` e null, severitatea e
`medium` cu `raw.severity_known = False` — aceeași pereche pe care
`trivy_fs.map_severity` o dă pentru `UNKNOWN`, și din același motiv: `info` e o
afirmație, iar absența unei note nu e — și descrierea constatării **își scrie
singură** că severitatea nu e o evaluare.

Calea de patch **eșuează închis**, fără o regulă scrisă pentru ea:
`generate_for_kev` alege pe `findings.kev`, iar `kev` se pune doar când CVE-ul
constatării e în oglinda KEV. Fără CVE nu există potrivire, deci nu există plan.

Ce s-a evaluat și de ce nu s-a ales, acum:

| Opțiune | De ce nu (încă) |
|---|---|
| `trivy rootfs /` | Trivy **e** pe gazdă acum (pasul 21) și baza lui poartă avize `deb`, deci ar da CVE-uri pe Debian. Dar ar fi **un al doilea scaner de pachete de sistem**, cu alt spațiu de chei și alt profil de fals-pozitive, iar `trivy_fs` evită dinadins `rootfs` tocmai fiindcă acolo reaprinde baza de pachete a sistemului. Care dintre cele două e sursa pe Debian e o decizie de proiectare, nu o reconciliere |
| `debsecan` | Nu e instalat implicit, interoghează trackerul Debian prin rețea, iar pe Ubuntu acoperirea diferă de realitate |
| `apt list --upgradable` | Îți spune singur, în stderr, că nu are o interfață stabilă. `apt-get -s` are aceeași informație plus depozitul de origine |
| `ubuntu-security-status` / `pro` | Doar Ubuntu, nu Debian, și dă numere agregate, nu pachete |

**Un scaner care raportează mai puțin decât știe e mai bun decât unul care pare
complet.**

### 3.17 Absența unui rezultat nu e zero

Bug-ul care a produs secțiunile de mai sus: pe Ubuntu, runtime-ul rula `dnf`,
comanda nu exista, eroarea se scria în jurnal și pasul continua. Panoul arăta
zero vulnerabilități pe o gazdă pe care nu se scanase niciodată nimic.

Patru lucruri împiedică repetarea:

1. Rândul din `scans` se deschide **înainte** ca scanerul să fie întrebat ceva,
   sub numele pe care îl dă FAMILIA — deci un scaner lipsă lasă un rând `failed`,
   nu tăcere. Tăcerea e starea care se citește ca „nicio vulnerabilitate".
2. Un scaner care a eșuat **nu rezolvă nimic**. `mark_resolved_absent` rulează
   doar după o scanare încheiată; altfel o comandă lipsă ar marca fiecare
   constatare deschisă drept reparată, iar operatorului i s-ar arăta o gazdă
   care s-a vindecat singură peste noapte. Același refuz ca la `trivy_fs`.
3. Backend-ul apt refuză să raporteze „curat" când nu poate dovedi că s-a uitat:
   fără indexuri de pachete (`apt-get update` n-a rulat niciodată), fără niciun
   index de securitate (depozitul de securitate nu e configurat, deci gazda nu
   primește actualizări deloc), sau cu linii `Inst` pe care nu le înțelege —
   toate sunt erori, nu zero. O linie `Inst` sărită în tăcere n-ar fi doar una
   neraportată: `mark_resolved_absent` i-ar închide constatarea.
4. Vechimea indexurilor pleacă în `scans.db_version`, și pe rândurile `failed`,
   fiindcă un raport curat dintr-un index de trei săptămâni e o imagine parțială
   — iar „ce a văzut scanarea" fără „cu ce s-a uitat" e o cifră căreia nu i se
   mai poate afla valabilitatea nici a doua zi.

Ce **nu** e verificat pe o gazdă reală: formatul exact al liniei `Inst`, numele
buzunarelor de securitate și conținutul lui `/var/lib/apt/lists`. Nimic din
mediul de test nu rulează apt. Forma e fixată din sursa lui apt, iar punctul 3
de mai sus e ce transformă o presupunere greșită într-un eșec zgomotos în loc de
o listă mai scurtă.

---

## 4. Predicția — ce este de fapt

Nu este machine learning. Este statistică robustă, o mașină de stări și
frecvențe empirice din istoricul propriu al serverului — fiecare explicabilă
unui operator la 3 dimineața și verificabilă ulterior.

### 4.1 Baseline

Mediană și MAD, nu medie și deviație standard: traficul de atac distruge media,
mediana abia se mișcă. Scor = `0.6745 × (x − mediană) / MAD`.

Plus profil de sezonalitate oră-din-săptămână pe 4 săptămâni, ca „1200 de cereri
la 04:00 duminică" să fie anormal chiar dacă 1200 la 14:00 marți nu este.

**Warm-up obligatoriu de 14 zile.** Cât timp `baselines.warm = false`,
detecțiile de anomalie se înregistrează dar nu alertează. Fără asta ai câteva
sute de fals-pozitive în ziua unu.

### 4.2 Lanțul de atac

Fiecare actor are un stadiu 0–6: `observed → recon → enumeration →
credential_attack → exploitation → post_exploitation → impact`.

Tranzițiile se salvează în `killchain_transitions`. Matricea de tranziție e o
agregare simplă peste acea tabelă, motiv pentru care o predicție poate fi
formulată întotdeauna ca „31 din 87 de actori cu tipar similar".

Stadiile 5 și 6 nu sunt predicții — înseamnă că ceva s-a întâmplat deja pe acest
host. Escaladare la `critical`, gata cu raționamentul probabilistic.

### 4.3 Intersecția expunerii — cel mai valoros semnal

```
actorul sondează /wp-content/plugins/foo/
  × asset-ul rulează php-wordpress
  × finding deschis: CVE-2026-1234 în wp-plugin-foo 1.2.3, EPSS 0,72, KEV
  ⇒ țintă predictibilă de exploatare
```

Zero statistică, zero ML, și de departe cel mai acționabil output al sistemului.

Cazul negativ contează la fel: „sondează pentru phpMyAdmin, care nu e instalat"
plafonează severitatea și îți spune că nu ai fost niciodată expus.

### 4.4 Calibrare

Fiecare predicție se scrie în `predictions` și se punctează ulterior. Pagina de
analytics arată un **scor Brier**.

Asta e ideea: o predicție pe care nimeni nu o verifică e marketing, iar numerele
inventate ies la iveală într-o săptămână.

---

## 5. Modelul de amenințare

```
trafic atacator          →  neîncrezut, întotdeauna
raw_events.raw           →  conținut neîncrezut, stocat verbatim, niciodată interpolat
sesiune web              →  autentificată, dar NU de încredere pentru acțiuni privilegiate
chat_id Telegram         →  autentificat, cu rol, tot cu dublă confirmare
daemoni sentinel         →  de încredere să CEARĂ; NU de încredere să AUTORIZEZE
politica executorului    →  autoritatea. Refuză și un apelant de încredere
```

Ce obține un atacator:

| Compromite | Obține |
|---|---|
| Dashboard-ul web | Acces de citire la datele de securitate. Nu poate acționa |
| Tokenul botului Telegram | Poate *cere* acțiuni — limitat de allowlist-ul de chat_id, roluri, dubla confirmare și politica executorului |
| Un daemon `sentinel` | Poate cere acțiuni executorului, care le validează independent — **dar** de la §3.14 încoace, `sentinel` e în grupul `docker`, iar grupul ăla e root pe gazda asta. Compromiterea unui daemon nu mai e ținută în frâu de politica executorului |
| Executorul | Root. De asta are 400 de linii și o suită proprie de teste ostile |

### Injecție de prompt

Liniile de log și path-urile HTTP sunt scrise de atacator. Apărarea are trei
straturi:

1. Conținutul e împachetat în `<untrusted_data>`, iar system prompt-ul declară
   explicit că e dată, nu instrucțiune.
2. CLI-ul rulează `--permission-mode plan` cu allowlist read-only.
3. `deploy/claude-workspace/settings.json` interzice explicit Write, Edit,
   WebFetch, sudo, systemctl, nft și restul.

Există un test obligatoriu în `tests/security/` care plantează
`IGNORE PREVIOUS INSTRUCTIONS...` într-un access log, forțează un triaj și
verifică că nu s-a executat nimic.

---

## 6. Degradare

| Cade | Rezultat |
|---|---|
| API Anthropic | Verdictele deterministe rămân. Mesaje marcate „(analiză AI indisponibilă)". Generarea de patch-uri returnează eroare, niciodată un plan parțial |
| Telegram | Notificările se acumulează în coadă. Dashboard-ul funcționează. Auto-block funcționează — doar nu afli, de asta adâncimea cozii e pe pagina de sănătate |
| PostgreSQL | Ingest buferează scurt, apoi renunță cu contor. Detect se oprește. Executorul continuă — blocurile existente rămân, TTL-urile expiră în kernel |
| Suricata | Detecția pe loguri continuă. Regulile NIDS tac. Banner în UI |
| `sentinel-detect` în restart loop | Watchdog-ul golește blocklist-ul și alertează. Deliberat: un detector care nu poate rula nu trebuie să lase drop-uri învechite în kernel |

---

## 7. Faze de livrare

| Fază | Conținut | Criteriu de acceptanță |
|---|---|---|
| **P0** ✅ | Schelet, skill, agenți, schema DB, tooling deployment, docs | `pytest` verde; migrațiile se aplică; skill-ul e descoperit local |
| **P1** ✅ | Fundația pe server: Postgres, venv, dashboard cu login TOTP, nginx + certbot, watchdog anti-lockout, rollback | Login HTTPS cu TOTP din internet; nimic din ce rula nu s-a oprit; `--rollback` curăță complet |
| **P2** ✅ | Inventar + disponibilitate: discovery, health prober, capacity, pagina Servicii | Dashboard-ul arată fiecare serviciu real, up/down live + uptime 24h |
| **P3** ✅ | Ingestie: colectori, normalizare, enrichment geo/ASN, partiționare, pagina Evenimente | Evenimente în timp real; creșterea discului măsurată 48h și în buget |
| **P4** ✅ | Detecție + Telegram read-only | Brute-force SSH simulat → incident în UI **și** push Telegram în <60s. **Fără blocare** |
| **P5** ✅ | Răspuns: executor, nftables, blocklist, watchdog, comenzi de blocare | Blocare verificată de pe a doua rețea; TTL; `/panic`; watchdog. **Auto-block încă oprit** |
| **P6** ✅ | Autonomie + Suricata + baseline | Auto-block pe praguri conservatoare; 72h de calibrare |
| **P7** ✅ | Scanare vulnerabilități | Scanare completă în fereastra nocturnă, fără impact pe latența celorlalte servicii |
| **P8** ✅ | Stratul AI | Verdict AI în <2 min pe un incident HIGH; degradare curată; raport zilnic RO |
| **P9** ✅ | Patching | Canary: generare → dry-run → aplicare → rupere deliberată → rollback automat verificat |
| **P10** ⏳ | Analytics + hardening final + docs | `TESTARE.md` complet; `systemd-analyze security` ≤3.0 pe toate unitățile |

Fiecare fază se termină cu tot ce rula înainte încă rulând. Fără excepții:
preflight înregistrează serviciile, porturile și containerele active, iar
instalarea compară la final și face rollback automat dacă ceva s-a oprit.

---

## 8. Ce s-a respins, și de ce

| Respins | Motiv |
|---|---|
| Zeek în loc de Suricata | Metadate mai bogate, dar mult mai mult RAM și mult mai multe date de stocat, pe un box care rulează deja un JVM. Compromis greșit aici |
| eBPF propriu | Cost mare de inginerie, fără corpus de semnături, fără comunitate. Nejustificat |
| Doar loguri, fără NIDS | Ratează exploit-uri non-HTTP, scanări pe porturi fără logging aplicativ, și amprente TLS/JA4 |
| Docker pentru Sentinel | Monitorizarea traficului și controlul nftables pe host ar cere host network + NET_ADMIN, ceea ce anulează izolarea pe care ai fi cumpărat-o |
| Dependența de un SIEM extern | Ar însemna că Sentinel se oprește când se oprește altceva. Un agent de securitate care are nevoie de un al doilea sistem ca să funcționeze are dublul suprafeței de eșec |
| Redis / RabbitMQ | Încă un daemon, încă o suprafață de atac, încă un consumator de RAM. PostgreSQL `LISTEN/NOTIFY` + `FOR UPDATE SKIP LOCKED` acoperă nevoia |
| SPA (React/Vue) | Build step pe server, npm în lanțul de aprovizionare, CSP mai slab, pagină mai grea |
| Chart.js | ~200 KB față de ~45 KB pentru uPlot, și mult mai lent pe zeci de mii de puncte — iar paginile de analytics sunt toate serii temporale |
| Down-migrations | Inversarea unei schimbări de schemă pe o bază de date de securitate live este o fantezie. Calea de întoarcere e snapshot-ul |
| `sudo` în loc de daemon executor | O regulă sudoers suficient de largă ca să fie utilă e suficient de largă ca să fie o escaladare de privilegii |
| Webhook Telegram | Port de intrare, endpoint public, și inutilizabil exact când nginx e stricat |
| LSTM / autoencoder pentru anomalii | Neexplicabil la 3 dimineața, imposibil de calibrat onest, și nu mai bun decât mediană+MAD la scara asta |
