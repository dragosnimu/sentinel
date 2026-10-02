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

O rulare la pragul ăsta nu are voie să închidă ce nu mai poate vedea:
`mark_resolved_absent` primește severitățile pe care rularea chiar le putea
vedea, fiindcă „nu mai e raportată" acoperă două lucruri diferite — ce s-a
reparat, și ce nu mai e căutat. Câte rămân deschise sub prag se scrie în jurnal
la `WARNING` după fiecare rulare.

**Pe gazda asta, garda protejează zero rânduri, și e cinstit s-o spunem aici.**
Măsurat pe 29 august 2026: `trivy_image` are o singură rulare, vreodată, și
aceea `failed` — plafonul a respins-o. În `findings` nu există niciun rând
`trivy_image` (doar `dnf` 5207 și `trivy_fs` 92). Deci cele ~2388 de constatări
MEDIUM n-au fost niciodată ingerate; ele există pe gazdă, dar nu în baza asta,
iar `count_open_outside_severities` va întoarce 0 la fiecare rulare — deci
`WARNING`-ul nu se va aprinde. Garda rămâne corectă pentru o mutare viitoare de
prag sau pentru altă instalare, dar nu apără nimic azi.

Singurul loc unde se vede că 2388 de constatări nu mai sunt căutate e textul din
`scans.target`. Panoul de vulnerabilități numără pe severitate, fără să spună
pragul fiecărui scaner — cine filtrează „medium" acolo nu are din ce afla că
imaginile lipsesc din numărătoare. Asta e limita apărării, nu o regresie:
înainte, scanarea nu raporta absolut nimic.

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
| rhel | `dnf updateinfo list --security` | avizele **fără CVE structurat** (EPEL), pe care `list cves` nu le tipărește: `cve` nul, `advisory_id` = avizul, fără potrivire KEV |
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

Citit de pe o gazdă Ubuntu reală (24.04.4 LTS, apt 2.8.3) pe 14 septembrie 2026:
formatul liniei `Inst` — 15 linii fixate verbatim în teste, una cu un grup de
paranteze drepte după paranteza rotundă —, numele buzunarului de securitate
(`Ubuntu:24.04/noble-security`) și listarea completă a lui `/var/lib/apt/lists`.

**Cifrele nu se mai scriu aici.** Câte indexuri de pachete are gazda și câte
dintre ele intră la „de securitate" se derivă în `tests/unit/test_scan.py`,
rulând chiar regula codului peste listarea fixată ca fixtură — scrise de mână în
proză, au fost greșite de două ori la rând, și o cifră dintr-un paragraf nu se
poate reverifica. Numele oglinzilor din fixtură sunt înlocuite, fiindcă
repository-ul e public și oglinzile spun de unde se aprovizionează gazda; restul
fiecărui nume e verbatim, scris pe coloane (`_` redat ca spațiu, cu motivul
lângă fixtură) și refăcut de test. Ce **nu** e verificat: buzunarele
Debian și cele Ubuntu Pro. Nimic din mediul de test nu rulează apt, deci forma
rămâne fixată dintr-o măsurătoare și din sursa lui apt, iar punctul 3 de mai sus
e ce transformă o presupunere greșită într-un eșec zgomotos în loc de o listă
mai scurtă.

### 3.17b Reparația instalată nu e reparația care rulează

Măsurat pe producție la 29 septembrie 2026: 491 de constatări `dnf` deschise,
toate pachete `kernel*`, iar reparația cea mai nouă de care aveau nevoie
(5.14.0-687.51.1) era deja pe disc. `uname -r` arăta 687.46.1, cel mai vechi din
cele trei nuclee instalate. `dnf --assumeno update kernel-core` răspundea „Nothing
to do", iar planificatorul propunea totuși `dnf -y update kernel*` — cinci
planuri (unul pe pachet), fiecare declarat nereversibil și refuzat de poarta de
etapa 1, patru zile la rând. Planurile n-aveau ce instala; problema nu era
patch-ul, ci o repornire.

**De ce le listează `dnf` mai departe.** `updateinfo list --security` compară
avizele cu pachetele cele mai noi instalate *plus* cele ale nucleului care
rulează (`running_kernel_pkgs`, citit din sursa lui dnf de pe gazdă: toate
pachetele cu același `SOURCERPM` ca nucleul curent). Cu nucleul vechi în
execuție, avizele mai noi decât el rămân în listă oricâte nuclee noi s-ar
instala. Deci scanarea nu greșea — nu avea cum să spună diferența.

**Ce face acum.** `sentinel/scan/fix_state.py` citește o dată pe scanare
`rpm -qa` (0,69 s, măsurat sub restricțiile unității) și `uname -r`, și dă fiecărei
constatări `dnf` unul din trei verdicte, scris în `findings.raw.fix_state`:

| Verdict | Dovada | Ce se întâmplă |
|---|---|---|
| `pending_reboot` | o instanță instalată ≥ versiunea care repară ȘI instanța din nucleul care rulează < ea | constatarea rămâne `open`; planificatorul nu redactează plan; `/planifica` explică |
| `not_pending` | dovezile s-au citit și nu susțin starea (reparația nu e instalată, sau rulează deja și dnf o listează totuși) | verdictul înlocuiește pe cel vechi; constatarea redevine planificabilă |
| `unknown` | dovezile nu s-au putut citi | **nu șterge** un `pending_reboot` dovedit ieri; peste nimic rămâne `unknown` (planificabil ca înainte) |

**Statusul nu se mișcă.** Constatarea e `open` și numărată — inclusiv ca KEV: gazda
rulează încă nucleul vulnerabil. Prima variantă o muta în `deferred` și ar fi scos
din „KEV deschise" cinci din cele șapte, adică un panou cu „2 KEV" peste un nucleu
cu un CVE exploatat activ (decizie a operatorului, 29 septembrie 2026: rămân
numărate). Așa că nu există migrație, stare nouă sau grup nou în agregator, iar
panoul, raportul zilnic, `ai/ask` și predicția de expunere merg neschimbate.

**Cine citește verdictul.** Numai cine ACȚIONEAZĂ pe constatare, printr-un predicat
unic, `findings.pending_reboot_sql` (`open` ȘI `raw.fix_state.state =
'pending_reboot'`, niciodată NULL): `planner.generate_for_kev` (în SQL, ca rândurile
astea — KEV, deci primele după prioritate — să nu ocupe cele trei sloturi ale
trecerii), `planner.generate` (refuzul pentru `/planifica` și orice alt apelant),
`/planifica`, `/vuln` și `/vulnerabilitati` (marca 🔁). Verdictul stă în `raw`, nu
într-o coloană, deci nu e nevoie de migrație; costul e că upsertul rescrie `raw` la
fiecare scanare, iar „`unknown` nu șterge" cere `fix_state.reconcile`, care citește
verdictul de ieri ÎNAINTE de upsert și îl duce înainte. O coloană ar fi făcut asta
de la sine (upsertul n-o atinge) și ar fi fost tipată, dar ar fi cerut o migrație.

**Ce vede operatorul.** Constatarea nu mai are plan și nici refuzul care o făcea
vizibilă, deci canalul Telegram e singurul ei semn de viață:

  * **la intrarea în stare**, un mesaj integral: ce se închide (CVE-uri *distincte*,
    cu KEV numite), ce e pe disc față de ce rulează, că gazda rămâne expusă și
    constatările deschise până la repornire, că repornirea e decizia lui, și comanda
    pentru ce Sentinel nu poate verifica — nucleul implicit la pornire (`/boot/grub2`
    e 0700 root, iar `grubby --default-kernel` rulat neprivilegiat tipărește `/boot`
    și iese cu 0);
  * **în fiecare scanare** cât timp un KEV așteaptă, o reamintire scurtă (doar KEV,
    „de N zile"), oprită de repornire — un mesaj trimis o singură dată se poate rata,
    iar altfel un KEV ar fi `open`, numărat, fără plan și fără nicio veste;
  * `/planifica <id>` refuză cu motivul adevărat (reparația e instalată, o repornire
    o aplică), nu cu „nu mai e deschisă"; `/vuln` arată ce e pe disc, ce rulează și de
    când; `/vulnerabilitati` marchează rândul cu 🔁.

**Drumul înapoi.** După repornire nucleul care rulează are reparația, `dnf` nu mai
listează avizul, iar scanarea închide singură constatarea (`mark_resolved_absent`) —
nu există „redeschidere", fiindcă `status` n-a fost mutat. Verificat pe producție,
29 septembrie 2026: 491 de constatări `dnf` rezolvate de scanarea de după repornire.

**Ce NU face.** Nu repornește nimic. Nu generalizează la „bibliotecă actualizată,
proces care o ține mapată": cazul acela e invers (dnf nu mai listează avizul, deci
constatarea se închide prematur), iar `dnf needs-restarting` lucrează pe procese,
nu pe CVE-uri — o decizie de proiectare separată. Nu grupează planurile pe
tranzacție: dacă apare un kernel KEV cu reparația NEINSTALATĂ, planificatorul
scrie din nou câte un plan pe pachet.

### 3.17c Semaforul de risc: arborele CISA SSVC, nu un prag

**Ce era.** `findings.priority` era o sumă de puncte (bază + KEV + EPSS×20 +
expunere + criticitate) tăiată la 100. Pe producție, la 2 octombrie 2026:
6912 de constatări `dnf` fără niciun CVSS, nicio constatare cu EPSS (nimic nu
populase coloana), iar 212 din cele 218 `dnf` deschise stăteau în aceeași găleată
de 10 puncte (80–90). Un număr care nu mai deosebea nimic.

**Ce e acum.** Culoarea (`risk_color`) e decizia arborelui **CISA SSVC**
(`sentinel/scan/ssvc.py`, 36 de rânduri copiate din
`cisa_coordinator_2_0_3.csv` al CERT/CC și păzite de un test care le compară cu
fișierul publicat): roșu = *Act*, galben = *Attend*, verde = *Track* / *Track\**,
**gri = nu se poate decide**. Nicio culoare nu iese dintr-un prag inventat aici.
Cele patru puncte de decizie și de unde vin. **Fiecare își scrie sursa în
`findings.risk` (`points.<punct>.basis`)**, iar o valoare luată de la CISA își scrie și
ziua evaluării (`as_of`): e o fotografie, și trebuie să se vadă cât e de veche.

| Punct | Sursa la noi (în ordine) |
|---|---|
| Exploitation | (1) în CISA KEV → `active`, `basis = kev`; (2) valoarea publicată de CISA (Vulnrichment: `none` / `poc` / `active`), `basis = vulnrichment`; (3) CISA n-a evaluat CVE-ul și nu e în KEV → `none`, `basis = kev_absent` (**presupunere a Sentinel**, vezi mai jos). **EPSS nu intră.** |
| Automatable | valoarea publicată de CISA; doar dacă lipsește, vectorul CVSS (`AV:N/AC:L/PR:N/UI:N`; la v4 și `AT:N`, iar `AU` are prioritate): `basis = cvss_vector` |
| Technical Impact | valoarea publicată de CISA; doar dacă lipsește, vectorul CVSS (`C:H` **și** `I:H` → `total`; SSVC vorbește despre *sistem*, CVSS `C:H` despre *componentă*, vezi „Euristica din vector" mai jos): `basis = cvss_vector` |
| Mission and Well-Being | criticitatea activului (1–2 mică, 3 medie, 4–5 mare) — **decizia operatorului**; acum 3 pentru toate |

Două axe, afișate separat: *importanța* (CVSS-ul sursei alese) și *urgența* (decizia;
coborâtă o treaptă când reparația e instalată și lipsește doar o repornire —
importanța nu se mișcă). Numărul de ordonare e `probabilitate × impact` (EPSS, sau
1,0 pentru KEV sau pentru o exploatare activă publicată de CISA, înmulțit cu CVSS/10):
o medie ar pune egal un CVSS 9,8 cu EPSS 0,001 și unul de 5,0 cu EPSS 0,6. Se
folosește în interiorul unei culori, cum recomandă chiar documentația SSVC, **cu o
singură excepție, a Sentinel și numită ca atare**: suprapunerea EPSS de mai jos.

**De ce Exploitation nu vine din EPSS.** SSVC definește Exploitation ca stare
*observată* (none / PoC / active); EPSS e o *previziune*. A deriva o observație dintr-o
previziune e aceeași greșeală ca media dintre CVSS și EPSS. Prima variantă o făcea
(`EPSS ≥ 0,90` → active, `≥ 0,50` → PoC) și cele două cifre erau alegerile noastre, nu
reguli publicate: documentația SSVC (`using_epss/epss_probability.md`) pomenește 90%
doar ca *exemplu* („let's say you decide…"), iar banda „more likely than not" (55–75%)
are acolo efectul *PoC → Active*, nu *none → PoC*. Pragurile au fost **scoase**, nu
doar etichetate. Măsurat pe CVE-urile gazdei (corpusul de mai jos), pragul greșea în
ambele sensuri: cele trei CVE-uri din KEV au EPSS 0,006–0,014, iar două CVE-uri cu EPSS
0,92 (CVE-2023-45288) și 0,99 (CVE-2025-29927) au la CISA `none`.

**Costul, spus pe față — și ce s-a făcut cu el.** CVE-2025-29927 (ocolire de
autentificare în Next.js, EPSS 0,992, exploit public) era singurul roșu al primei variante.
CISA îl are `none` din 8 aprilie 2025: fotografia a rămas în urmă (542 de zile la 2
octombrie 2026). După runda 2 era **verde (Track)**, și documentul spunea că „numărul
de ordonare îl pune primul dintre verzi". **Fraza era falsă.** Măsurat pe cele 812 de
rânduri deschise, rândul stătea pe locul **40**: sub cele 2 galbene, sub 22 de rânduri
gri GHSA (prioritate 54–58) și sub 15 rânduri verzi Track\* (prioritate 20, față de 17
al lui). Banda hotărăște înaintea numărului, iar Track\* are o bandă deasupra lui Track,
deci un verde Track nu poate fi „primul" decât între Track-uri. Corectura nu e o frază
mai bună, ci regula de mai jos: cu ea, rândul e **galben (Attend, `basis = epss_overlay`)**
și stă pe locul **1** din 812 (prioritate 77, deasupra celor două KEV de la 74–75; vezi
mai jos de ce).

**Regula Sentinel: EPSS peste o fotografie CISA veche.** *Aprobată de operator la 180 de
zile. **Nu e regulă SSVC și nu e regulă FIRST**: nicio sursă nu o spune, iar cele două cifre
(180 de zile, EPSS ≥ 0,5) sunt ALE NOASTRE — după ce rundele 1 și 2 scoseseră două cifre
EPSS ale Sentinel, aici revin două, la culoare în loc de punctul Exploitation.* Dacă
evaluarea CISA a exploatării (`none` sau `poc`) are **mai mult de 180 de zile** ȘI EPSS-ul
de azi (proaspăt) e **cel puțin 0,5**, culoarea nu coboară sub galben: decizia devine
`attend`, iar `findings.risk.overlay` spune `basis = epss_overlay`, decizia pe care ar fi
dat-o SSVC singur (`ssvc_decision`), vârsta și data fotografiei, EPSS-ul și cele două praguri
aplicate. Punctele de decizie rămân neatinse (Exploitation rămâne `none`, de la CISA, cu data
lui): suprapunerea nu rescrie o observație, ridică o culoare.

*Ce o face apărabilă* nu e că EPSS e mare — asta singur e o previziune, exact ce am
scos din decizie —, ci că **observația pe care EPSS-ul o contrazice n-a mai fost
reîmprospătată**. Dintre cele 196 de evaluări CISA ale gazdei, 75 au peste 180 de zile, 44
peste un an, iar mediana e de 141 de zile.

*Se aplică:* după coborârea pentru repornire (podeaua e podea, deci un rând reparat care
așteaptă o repornire rămâne galben, cu 🔁), indiferent de misiune (la misiune mică, aceleași
trei rânduri urcă tot la galben). *Nu se aplică:* unui **gri** (necunoscutul nu devine galben);
unui CVE a cărui exploatare e deja `active` sau în KEV (nu e o observație contrazisă);
unui CVE pe care CISA nu l-a evaluat (`kev_absent`: n-a existat nicio observație, doar
presupunerea noastră — dacă ar trebui și acolo o podea EPSS e **altă decizie**; pe gazdă,
niciunul din cele 395 de rânduri `kev_absent` nu are EPSS ≥ 0,5, deci azi întrebarea e
teoretică); unui EPSS lipsă sau mai vechi decât `epss.MAX_AGE_DAYS` (nefolosit, ca peste
tot). O evaluare CISA fără dată nu poate fi dovedită proaspătă și se tratează ca veche.

*Cifra 0,5, măsurată pe cele 406 CVE-uri distincte deschise (403 au EPSS).* Primele valori
sunt 0,99225 (CVE-2025-29927), 0,91969 (CVE-2023-45288), 0,5918 (CVE-2024-46982), apoi
**0,04561** (CVE-2022-41723), 0,04002, 0,03995… Golul e real și e cel mai larg din set
(0,55): **orice prag din (0,0456; 0,5918] prinde aceleași trei CVE-uri**, deci 0,5 ar
prinde aceleași rânduri ca 0,1. Dar golul e al gazdei, nu al lumii: în fișierul FIRST din
1 octombrie (381.682 de CVE-uri), 30.661 (8,0%) au EPSS ≥ 0,05 și 4.317 (1,13%) au ≥ 0,5. Pe
altă gazdă sau în altă zi, rândurile dintre 0,05 și 0,5 pot fi zeci, nu zero. **Ce cumpără
cifra:** nu e validată de date, ci de înțeles („mai probabil decât nu"). Și mai e un
detaliu: 0,5 stă la doar 0,09 sub cel mai slab din cele trei (CVE-2024-46982, 0,5918, 744 de
zile): o scădere zilnică de EPSS cu 0,09 îl duce înapoi pe verde fără ca ceva să se fi
reparat.

*Efect, pe cele 812 de rânduri deschise (instantaneu citit de pe gazdă la 2 octombrie 2026,
fără a o mai citi acum; sursele CISA/FIRST/Red Hat/OSV, vii):*

| Misiune | Fără regulă | Cu regula | Ce se mută |
|---|---|---|---|
| mică | roșu 0 · galben 0 · gri 22 · verde 790 | roșu 0 · galben **3** · gri 22 · verde 787 | cele 3 CVE-uri, la galben |
| medie | roșu 0 · galben 2 · gri 22 · verde 788 | roșu 0 · galben **5** · gri 22 · verde 785 | CVE-2025-29927, CVE-2023-45288, CVE-2024-46982: verde → galben |
| mare | roșu 2 · galben 231 · gri 22 · verde 557 | roșu 2 · galben 231 · gri 22 · verde 557 | nimic: la misiune mare cele trei sunt deja Attend din arbore |

*Ordinea, un efect de reținut:* în interiorul galbenului rândurile se ordonează tot după
`probabilitate × impact`, iar un KEV are probabilitate 1,0 și CVSS 7,5–7,8 (scor 0,75–0,78),
pe când CVE-2025-29927 are 0,992 × 9,1 = 0,903. Rezultatul: CVE-2025-29927 stă pe locul 1,
**deasupra celor două CVE-uri din KEV** (locurile 2–3), CVE-2023-45288 pe locul 4, CVE-2024-46982
pe 5; apoi cele 22 de rânduri gri. Nu e o greșeală de calcul, e regula de ordonare deja
documentată; dacă operatorul vrea ca o exploatare *observată* să stea mereu deasupra uneia
*prezisă*, e o a doua regulă.

*Unde se spune pe ecran, ca regula Sentinel și nu a SSVC:* eticheta rândului („🟡 Attend —
accelerat (regula Sentinel, nu SSVC)"), motivul scurt („regula Sentinel (EPSS)"), legenda
listei din Telegram (numai când un astfel de rând e pe ecran), propoziția din `/vuln <id>`
și din detaliul panoului (cu data, vârsta, EPSS-ul, pragurile și ce ar fi dat SSVC), nota
paginii de vulnerabilități (serverul și agregatorul) și nota cardului „galbene" din
analize.

**Cifra Sentinel care a rămas:** `risk.UNPUBLISHED_EXPLOITATION = "none"`. Pe gazda de
producție (2 octombrie 2026) CISA a publicat puncte pentru **196 din cele 406 CVE-uri
distincte deschise = 48,3%**, iar acoperirea depinde de ecosistem, nu de gazdă: npm 78/78,
composer 36/36, go 45/57, alpine 13/16, **deb 13/185 (7%)**, rpm 6/32 (19%). Pe rânduri,
Exploitation vine din presupunerea `kev_absent` la **395 din 812 = 49%**. (O versiune
anterioară a acestui text spunea 80%: era media unui eșantion de 78 de CVE-uri, în mare
parte npm/composer, fără niciunul din cele 185 de CVE-uri Debian — în majoritate
`linux-libc-dev` — pe care CISA nu le-a evaluat aproape deloc. Curba pe ani din eșantionul
Red Hat de 320 de CVE-uri, 2019–2026, rămâne adevărată: 8–15% pe 2019–2021, 62–78% pe
2022–2024, ~40% pe 2025–2026; cifra pe gazdă nu era.) Pentru restul, „nu e în KEV"
înseamnă „nimeni nu l-a văzut exploatat activ" — nu spune nimic despre un exploit public,
deci `none` e o presupunere, iar `basis = kev_absent` o spune. **Presupunerea hotărăște,
așadar, despre jumătate din rânduri.** La misiune medie nu mută nicio culoare (între `none`
și `poc` arborele schimbă doar Track ↔ Track\*, ambele verzi; la misiune mare un Track\*
devine Attend). Cu `None`, toate aceste rânduri ar fi gri: 49% din pagină. Se schimbă într-un
loc.

**Gri nu e verde.** O decizie se ia numai cu toate cele patru puncte cunoscute.
Lipsește unul — niciun vector și niciun punct publicat, un aviz fără CVE, oglinda KEV
veche, sau CVE-ul pe care încă n-am apucat să-l întrebăm la CISA (rând absent: sursa
e căzută sau trecerea n-a ajuns la el) — și constatarea e gri, cu motivul și cu cele
două capete posibile („între Track și Attend") în `findings.risk`. Gri se ordonează
deasupra verdelui. **„CISA n-a evaluat CVE-ul" nu e „necunoscut"**: e un răspuns (rândul
există, fără puncte), și primește culoare. EPSS lipsă sau vechi nu mai face un rând gri;
rămâne fără număr de ordonare.

**Un parser orb arată ca „CISA n-a evaluat nimic".** Dacă CISA își schimbă `orgId`, rolul
sau forma răspunsului, fiecare CVE ar părea neevaluat și Exploitation ar cădea pe
`none` în tăcere. O trecere care primește cel puțin 20 de CVE-uri și niciun punct CISA
devine **suspectă**, nu orbă: doar 7% dintre CVE-urile Debian au puncte CISA, deci un lot
de 20–30 de CVE-uri noi de `linux-libc-dev` are zero puncte cu probabilitatea 0,93^20 ≈ 23%
(0,93^30 ≈ 11%) fără ca parserul să fi greșit, iar alarma ar fi ținut `degraded` până la două zile
(`UNENRICHED_DAYS`). O alarmă care sună după *compoziția* lotului învață operatorul s-o
ignore. De aceea suspiciunea se verifică cu un **control pozitiv**: în aceeași trecere se
cere LIVE de la serviciu un CVE cunoscut că poartă puncte (`CANARY_CONTROL_CVE`,
CVE-2025-29927) și se trece prin același parser. Controlul DĂ puncte → lotul era doar
neevaluat, nicio alarmă. Controlul vine FĂRĂ puncte → parser orb: `blind` în
`intel_state`, iar autoverificarea (`risk:vulnrichment`) trece pe `degraded`. Controlul nu
se poate citi (cerere picată, 404) → „nu se poate spune" nu e „în regulă": se marchează
tot `blind`, cu motivul „nu se poate spune dacă e parser orb sau doar un lot neevaluat" în eroare. Controlul se cere live, nu din
fixture: o înregistrare reținută doar ar dovedi că parserul înțelege formatul VECHI.
Parserul e probat pe răspunsuri reale înregistrate (`tests/fixtures/intel/cveawg_*.json`).

**Euristica din vector (rezerva) față de valorile CISA.** Pe cele 189 de CVE-uri ale
gazdei cu ambele (vector și valoare CISA): Automatable din vector se potrivește cu CISA în
151 de cazuri (80%); Technical Impact cu regula `C:H` **și** `I:H` în **179 (95%)**, cu
regula `C:H` **sau** `I:H` în 149 (79%). Din cele 20 de CVE-uri cu `C:H` fără `I:H`, **19
sunt `partial`** la CISA.

*De ce „și", și de ce nu se schimbă la loc din textul definiției.* Definiția SSVC a lui
`total` e „control total asupra comportamentului software-ului **sau** dezvăluirea totală a
întregii informații **de pe sistem**" — două căi, și `C:H` pare a doua. Dar cele două scări
nu măsoară același lucru: SSVC vorbește despre *sistem*, iar CVSS `C:H` e pierdere totală
„în interiorul **componentei** afectate". Citit ca `total`, `C:H` supra-citește CVSS-ul;
practica CISA e citirea apropiată de definiție, nu o abatere de ea. Rezerva a fost scrisă
întâi cu „și", apoi schimbată în „sau" la instrucțiunea din runda 2 („definiția spune sau"),
și **instrucțiunea a fost greșită**: corectată în runda 3, pe dovada de mai sus. Același
text e în docstring-ul `cvss.py`, ca următorul care citește definiția să nu o schimbe la loc.

*Pe gazdă schimbarea nu mută nicio culoare* (nici la misiune medie, nici la mare), fiindcă cu
Exploitation `none` Technical Impact nu decide culoarea — arborele schimbă doar Track ↔
Track\* —, iar singurele rânduri cu `poc` sau `active` au valoarea publicată de CISA. 21 de
rânduri își schimbă doar valoarea *înregistrată* a Technical Impact (`total` → `partial`,
`basis = cvss_vector`). Contează pentru un CVE neevaluat de CISA care e totuși în KEV.

**Măsurat, cu limitele lui.** Până în runda 2 corpusul era cele 78 de CVE-uri-exemplu din
`tests/fixtures/cvss_measured_pairs.csv` (constatări trivy reale, în mare parte npm/composer —
de aici și acoperirea CISA de 80% care nu era a gazdei). Din runda 2 se măsoară pe **cele 812
de rânduri deschise**, instantaneu citit de pe gazdă (doar citire, 2 octombrie 2026),
încărcat într-un Postgres 16 de unică folosință cu migrațiile 0001–0048, cu sursele reale
(CISA prin înregistrarea CVE, EPSS din 1 octombrie, Red Hat, OSV) și cu `enrich.run` real —
nu cu o simulare a lui. Ce **nu** are măsurarea: starea gazdei de după instantaneu, și
rulările cu `criticality` legat de un activ real (toate rândurile sunt `medium`, ca pe gazdă).

| Misiune | Regula | roșu | galben | gri | verde |
|---|---|---|---|---|---|
| medie | runda 2 | 0 | 2 | 22 | 788 |
| medie | runda 3 (cu suprapunerea EPSS) | **0** | **5** | 22 | 785 |
| mare | runda 2 | 2 | 231 | 22 | 557 |
| mare | runda 3 (cu suprapunerea EPSS) | 2 | 231 | 22 | 557 |

Roșul gazdei la misiune medie e **zero**: singurul roșu al primei variante venea dintr-o
previziune, iar acum e galben din regula Sentinel. Cele două galbene care erau deja sunt
CVE-2026-53266 și CVE-2026-53362 (ambele KEV, `linux-libc-dev`).

**⚠ Misiunea e intrarea cea mai grea, și e o decizie a operatorului.** Constatările
primesc `criticality = 3` (medie) fiindcă legarea de un activ din inventar e muncă
amânată. Aceleași 812 de rânduri, cu regula curentă (Exploitation din CISA/KEV, suprapunerea
EPSS): misiune **mică** → 0 roșii, 3 galbene, 22 gri, 787 verzi; **medie** → 0 roșii, 5 galbene,
22 gri, 785 verzi; **mare** → 2 roșii, 231 galbene, 22 gri, 557 verzi. (Cifrele din runda 1,
cu Exploitation din EPSS — 4 roșii și 273 galbene la misiune mare — nu mai sunt valabile.)
Diferența dintre medie și mare e de aproape 230 de rânduri: cine hotărăște misiunea hotărăște
cea mai mare parte a paginii. Se schimbă într-un loc (`enrich.DEFAULT_CRITICALITY`), iar
pagina spune pe față ce a presupus.

**Alte lucruri pe care arborele le face și pe care operatorul trebuie să le știe:**

  * **Un KEV poate fi verde.** `active / neautomatizabil / impact parțial / misiune
    medie` e *Track*. KEV rămâne vizibil (🔥, antet, cardul KEV, mesajele de după
    scanare, planificatorul, reamintirile de repornire), dar culoarea nu-l mai
    urcă. Dacă se vrea „KEV ⇒ cel puțin galben", e o a doua regulă pusă peste arbore,
    nu o schimbare în el.
  * **Arborele CISA nu e singurul.** Pagina CISA îl descrie ca fiind pentru
    vulnerabilități care privesc guvernul SUA; pentru cine *aplică* patch-uri, SEI are
    arborele „Deployer" (expunerea sistemului, impactul uman) și CISA a publicat în 2026
    BOD 26-04 (KEV, expus public, automatizabil, impact → 3 / 14 / 60 de zile). Alegerea
    arborelui e a operatorului; tabelul e izolat într-un singur fișier ca să poată fi
    înlocuit.
  * **CISA publică cele trei puncte** (programul Vulnrichment, în înregistrarea CVE) și
    le folosim întâi; vectorul CVSS rămâne doar rezerva pentru CVE-urile pe care CISA
    nu le-a evaluat (`cvss.py`, euristici numite ca atare).

**Surse, toate gratuite și fără cheie, oglindite local** (`sentinel/intel/`, ca
`kev.py`: o cădere nu e o scanare eșuată, dar se scrie în `intel_state` și ajunge în
autoverificare):

  * **CISA Vulnrichment** — `https://cveawg.mitre.org/api/cve/<CVE>`: containerul
    ADP „CISA-ADP" din înregistrarea CVE, o cerere pe CVE, doar pentru ce lipsește sau a
    îmbătrânit (evaluat: 7 zile; existent dar neevaluat: 2 zile — cifre ale Sentinel,
    mută doar cât de repede ajunge o evaluare nouă). Dă Exploitation, Automatable,
    Technical Impact și **momentul evaluării din înregistrare** (`ssvc_at`). Răspunsurile
    stau în tabela `vulnrichment`, deci trecerea de evaluare nu atinge rețeaua pentru ce
    a fost deja întrebat. Un `found` fără puncte nu șterge puncte deja stocate.
    **De ce nu `CVEProject/cvelistV5` (aceeași înregistrare, ca depozit git):** o clonă
    completă are 3,0 GB (arhiva zilnică 618 MB); una parțială cu `sparse-checkout` pentru
    80 de CVE-uri are 50 MB, crește cu ~10 MB pe zi și durează ~17 s la fiecare reîmprospătare
    (un `fetch` fără nimic nou: 10–43 s), plus `git`, un director scriibil și lista de căi de
    menținut — pentru exact aceleași trei valori. Per CVE: 19 s și 734 KiB pentru 80 de
    înregistrări, zero disc. Nu se construiesc amândouă.
  * **EPSS** — fișierul zilnic (2,7 MB, 381.000 de rânduri), nu API-ul pe CVE-uri.
    API-ul **taie în tăcere**: o cerere cu 300 de CVE-uri a întors `HTTP 200` cu
    `"data":[]`. Fișierul se refuză dacă e trunchiat, fără `score_date` sau sub 100.000
    de rânduri; se păstrează doar CVE-urile cerute.
  * **Red Hat** — o cerere pe CVE (`cve/<CVE>.json`; lista nu poate fi filtrată pe CVE
    și n-are justificarea). Doar pentru ce lipsește sau a îmbătrânit; 1482 de cereri
    secvențiale au durat 707 s, deci o trecere normală e câteva zeci. Dă CVSS, severitate,
    avizul și **justificarea scrisă**, care rămâne pe server (se vede în `/vuln`).
  * **OSV** — vectorul (nu scorul; îl calculăm pentru v3) și aliasurile CVE ale
    avizelor GHSA. Forma „în bloc" (`querybatch`) răspunde la altă întrebare.
  * Preferința: furnizorul înainte de rest (Red Hat pentru rpm), apoi dovada
    scanerului, apoi OSV; **sursa care a decis se numește**. Scor și vector din
    aceeași sursă, niciodată amestecate.

**Cine rulează trecerea.** `sentinel/scan/enrich.py`, din două locuri: la sfârșitul
scanării și din mentenanța orară (scorurile se mișcă și fără scanare; prima evaluare
de după livrare vine în maxim o oră). Scrie **doar ce s-a schimbat**: un trigger
ridică `updated_at` la orice UPDATE, iar expeditorul copiază după el.
`upsert_finding` nu mai atinge `priority`/`epss`/`cvss`-ul adus de noi.

**Anunțuri.** Doar *trecerile în roșu*, o singură dată pe constatare
(`risk_red_announced_at`, revendicat atomic): prima evaluare a unui rând e punctul
de plecare, nu o veste; o constatare nouă o anunță mesajul „vulnerabilități noi"
(care îi poartă culoarea); un EPSS care oscilează nu redeschide canalul.

**Trei suprafețe, aceeași culoare, cantități diferite.**

| Suprafața | Ce arată | De ce |
|---|---|---|
| Telegram | semafor în antet, un punct colorat + un motiv scurt pe rând; în `/vuln` cele patru puncte, sursa CVSS, EPSS cu percentilă, justificarea furnizorului | câteva rânduri pe un telefon; detaliul se cere |
| Panoul fiecărui server | tabel: culoare + decizie + motiv, CVSS cu sursă, EPSS cu percentilă, pastile de culoare (gri mereu), filtru `?culoare=`, presupunerea despre misiune | e locul unde se citește lista întreagă |
| Agregatorul | culoare + decizie + un motiv, CVSS, EPSS; pastile și cardul de pe prima pagină | vede mai multe gazde; nu amestecă |

Agregatorul **nu amestecă gazdele**: culoarea unui rând e verdictul gazdei lui (cu
criticitatea, expunerea și repornirea ei). Un CVE reparat pe o gazdă și nu pe
cealaltă apare ca două rânduri, fiecare cu starea lui; pastilele sunt per gazdă și
niciun rând nu „se vindecă" pe baza altuia. `risk` nu poartă proză (doar cifre,
vocabular, id-uri, vectori): marginea agregatorului puncteaza conținutul care seamănă
cu linii de comandă, iar justificarea Red Hat rămâne pe server.

**⚠ Ordinea de livrare.** Receptorul refuză un câmp necunoscut ȘI unul care lipsește.
Deci: (1) agregatorul (migrația `0017_finding_risk.sql` + codul), apoi (2) fiecare
server, pe rând. Cât timp un server n-a primit versiunea nouă, fluxul lui `findings`
stă oprit (nu pierde nimic) și se vede în `ship:lag`. Același tipar ca la
`updated_at` (migrația 0010 a agregatorului).

**Ce a rămas deschis, fiindcă nu e o decizie a codului:** misiunea (de mai sus),
arborele (de mai sus), KEV-ul verde, Vulnrichment, și acoperirea — niciun ecosistem
`pip`/PyPI nu e scanat, nici venv-ul propriu al lui Sentinel, iar `trivy_fs` se uită
doar la `scan.discovery_paths`. Nu s-a atins aici.

### 3.18 Al zecelea colector se uită la ce PLEACĂ, nu la ce intră

Toate celelalte nouă mecanisme privesc înăuntru: sshd, nginx, Suricata, auditd.
Un server deja compromis nu mai generează neapărat niciunul dintre semnalele
alea a doua oară — sună acasă. `sentinel/collectors/conntrack.py` e singurul
care poate prinde o compromitere reușită, nu doar o tentativă, citind
`/proc/net/nf_conntrack` (nu binarul `conntrack`, care nu e instalat) la
fiecare 60 de secunde, nu la fiecare tur de ingestie.

**Direcția e partea grea, de trei ori.** Conntrack ține tuplul ORIGINAL și
tuplul de RĂSPUNS pentru fiecare conexiune; un `grep dst=` naiv pe gazda de
test a găsit 81 de „destinații" în 24h, din care 57 erau SSH-uri PRIMITE,
citite din tuplul greșit. Discriminatorul — gazda e inițiatoare doar dacă
`src=` din tuplul ORIGINAL e o adresă a ei — a redus cifra la 5, dar a picat
de încă două ori înainte să fie corect:

1. **Egresul containerelor era invizibil.** Docker rescrie sursa cu
   MASQUERADE doar la ieșire; tuplul ORIGINAL păstrat de conntrack e cel
   DINAINTE de NAT, deci poartă adresa containerului pe bridge (172.x), nu a
   gazdei. O verificare pe adrese exacte arunca exact cazul pe care
   detectorul îl caută — un container compromis care sună acasă. Reparat prin
   `HostIdentity`, care ține și subrețelele private ale gazdei (construite din
   rutele local-atașate citite din `/proc/net/route`), nu doar adresele ei.
2. **Lărgirea a înghițit segmentul public.** Aplicat la fel pe interfața
   publică, `eth0` fiind un `/21` pe gazda măsurată, „subrețeaua proprie" a
   ajuns să însemne ~2.000 de adrese ale ALTOR clienți de la același
   furnizor. Un scan SSH primit de la un vecin de pe segment trecea de
   verificarea de direcție cu adresa publică a gazdei drept „destinație nouă"
   — capcana de la punctul 1, renăscută pe altă rețea. Reparat prin două căi
   independente: `networks` ține doar subrețele PRIVATE (interfața publică
   rămâne acoperită exact de propria adresă, nu de tot segmentul), și
   `is_outbound` refuză separat orice destinație care e ea însăși a gazdei —
   o conexiune de ieșire reală nu se sună niciodată pe sine.

Ipoteza care rămâne, scrisă explicit în docstring-ul lui `HostIdentity`: orice
subrețea privată din `networks` e presupusă accesibilă DOAR prin NAT-ul
propriu al gazdei (un bridge Docker, un concentrator VPN găzduit local). O
gazdă care rutează o rețea privată STRĂINĂ printr-o interfață — fără s-o
stăpânească — ar vedea traficul ăla citit greșit ca al ei. Adevărat pentru un
VPS singular cu Docker, cazul măsurat; de reverificat înainte de refolosire pe
o gazdă care rutează LAN-ul altcuiva.

**Volumul e mărginit din două direcții diferite.** Deduplicarea (`DEDUP_WINDOW_S`,
o oră) mărginește o destinație REPETATĂ — o conexiune stabilă produce un rând
pe oră, nu unul pe eșantion. Nu mărginește însă un eșantion plin de destinații
niciodată văzute: un scanner pornit de pe gazdă ar produce mii de destinații
„noi" într-un singur eșantion, fără plafon. `MAX_NEW_PER_SAMPLE` (50) e
plafonul absolut pentru cazul ăsta, ales deliberat mare — atingerea lui
înseamnă un eveniment activ chiar acum, iar rafala e ea însăși parte din
semnal — și raportat zgomotos de fiecare dată când se declanșează, nu doar la
prima schimbare de stare, fiindcă „văzut N, păstrat 50" e o informație diferită
la fiecare eșantion.

**Semnalul principal e noutatea, nu volumul.** O destinație de ieșire
niciodată contactată e o nouă dimensiune (`outbound_dst`) în motorul deja
existent din `predict/behaviour.py`; volumul pe oră-din-săptămână e al doilea
semnal, prin `predict/baseline.py`, dependent de un asset `kind: host` pe
care operatorul trebuie să-l adauge — până atunci metrica stă tăcută, la fel
ca oricare alta din listă a cărei asset lipsește.

**Limitele, scrise, nu ascunse.** Eșantionarea o dată pe minut ratează orice
conexiune care se deschide și se închide între două eșantioane — prinde C2
persistent și exfiltrare lentă, nu o cerere rapidă. Egresul prin `macvlan`
sau `ipvlan` (containerul primește o adresă pe LAN-ul fizic, fără nicio
subrețea de interfață locală care s-o revendice) rămâne invizibil — cazul
măsurat aici e bridge networking standard. IPv6 e doar pe adresă exactă, nu pe
subrețea: nucleul scrie adresele IPv6 neabreviat, `psutil` le întoarce
abreviat, iar o comparație de șiruri n-ar potrivi niciodată aceeași adresă —
latent pe gazda măsurată (IPv6 dezactivat, zero intrări), nu reparat.

### 3.19 Un backup nedovedit e o ipoteză — exercițiul de restaurare, izolat

Măsurat pe gazdă la 1 septembrie 2026: nouă execuții de patch, trei puncte de
restaurare, **zero restaurări încercate vreodată**. `verified_at` pe fiecare
punct e egal cu `created_at` — verificarea existentă confirmă fișierul tocmai
scris, în aceeași secundă, nu că se mai poate citi înapoi o lună mai târziu.

`sentinel-restore-drill.timer` rulează lunar exact acest test, fără operator,
fără să atingă vreodată un fișier real. Constrângerea structurală: arhivele
sunt sub `/var/backups/sentinel/<id>/`, `0700 root:root`, deci extragerea și
re-verificarea checksum-urilor trebuie să ruleze în `sentinel-executor` — un
serviciu neprivilegiat nu poate nici măcar citi arhiva. Executorul extrage
fiecare arhivă cu `-C <director-izolat-propriu>` (niciodată `-C /`, ceea ce ar
face `restore.sh`), sub `--one-top-level`, apoi șterge directorul izolat
înainte să răspundă — vezi `op_restore_drill_verify`.

**Descoperirea care a rezultat din construirea exercițiului, nu dintr-o
căutare anume:** arhivele `tar.zst` create de `op_backup_create` erau
împachetate cu `tar --zstd -cf artefact -C <părinte> <nume-final>` — adică
membrii arhivei purtau doar ULTIMA componentă a căii (`nginx/...`), nu calea
întreagă relativă la rădăcină (`etc/nginx/...`). `restore.sh` extrage cu
`-C /`, deci o restaurare reală ar fi scris la `/nginx/...`, nu la
`/etc/nginx/...` — pentru orice sursă cu mai mult de o componentă sub
rădăcină, ceea ce înseamnă aproape orice cale reală de backup. Verificat
direct, cu `tar` simplu (fără zstd) și `tar -tf`: membrii arhivei confirmau
exact acest lucru. Exercițiul de restaurare prinde defectul ăsta structural —
verdictul `structure_mismatch`, arhivă cu checksum bun, extrasă fără eroare,
dar care nu reproduce nicio sursă declarată la calea ei — fără să presupună
dinainte care e defectul.

**Reparat**, în aceeași funcționalitate, după ce prima predare l-a lăsat
descris dar netratat pe motiv de sferă: `op_backup_create` arhivează acum cu
`tar --zstd -cf artefact -C / <cale-relativă-la-rădăcină>`, deci membrii
arhivei poartă calea întreagă (`etc/nginx/...`), iar o extragere cu `-C /`
aterizează exact unde a fost sursa. Motivul răsturnării: pe gazdă existau
zero arhive `tar.zst` — singurul punct viu era doar informativ — deci fără
reparație, primul exercițiu ar fi ales acel punct, ar fi ieșit
`informational_only`, iar orice punct viitor de tip `path` ar fi ieșit
permanent `structure_mismatch` din cauza unui defect din altă componentă;
Funcționalitatea 08 nu poate produce nimic din asta. Dovedit prin execuție
reală de `tar` (creare ȘI extragere, inclusiv `--one-top-level`), nu prin
aserțiune statică pe forma comenzii — vezi
`tests/security/test_backup_create_path_structure.py`. Punctele de restaurare
EXISTENTE, arhivate în formatul vechi, rămân corect `structure_mismatch` —
chiar nu se pot restaura, iar exercițiul n-are voie să le trateze retroactiv
ca valide.

**Ce compară exercițiul, și de ce e suficient:** checksum-ul recalculat de pe
disc (nu cel ținut minte din baza de date) pentru fiecare artefact, plus —
doar pentru arhive — dacă arborele extras conține sursele declarate în
manifestul din bază, la calea absolută unde ar trebui să existe. Un punct
numai cu artefacte informative (`rpm_state`, `git_ref`) nu poate ieși
niciodată „reușit": `restore.sh` însuși nu le restaurează, doar le numește —
verificarea nu are voie să pretindă mai mult decât mecanismul real.

**Ce înregistrează:** `restore_drills` (extinsă cu `automated`, ca rândul
scris manual pe canary din §6 al `docs/PATCHING.md` să nu se amestece cu cel
scris de timer) și `restore_drill_items`, un rând pe artefact — separarea
există ca Funcționalitatea 08 să poată întreba „s-a dovedit vreodată că
punctul ăsta, sau felul ăsta de artefact, se poate întoarce?" fără să
moștenească ambiguitatea dintre „informativ" și „restaurat".

**„Nimic de dovedit" nu e „a picat", și verificarea de sănătate le desparte.**
Prima predare a acestei funcționalități le amestecase: un punct numai
informativ ieșea `degraded`, titlu „Exercițiul de restaurare a picat" — deși
exercițiul rulase corect, doar n-avea nicio arhivă de extras. `check_restore_drill`
raportează acum acest caz `ok`, cu titlu propriu și `facts.nothing_to_prove =
true`, ca să nu fie confundat nici cu eșecul real (checksum greșit, arhivă
coruptă, `structure_mismatch` pe o arhivă care CHIAR exista), nici cu succesul
dovedit prin extragere. Un punct amestecat — artefact informativ lângă o
arhivă coruptă — tot iese eșec real: prezența informativului nu maschează
problema de lângă el. Vezi `_drill_had_nothing_to_prove` în
`sentinel/selfcheck/checks.py`.

### 3.20 Marcajele de instalare vechi nu se mai migrează — se abandonează

Până pe 8 septembrie 2026, marcajele de instalare (`STATE_MARKERS`) stăteau la
`/var/lib/sentinel/.install-state`, sub un director `0750 sentinel:sentinel`.
Serviciul are nevoie de scriere pe părinte pentru propria stare de rulare
(`geoip/`, `cursors/`) — dar același bit de scriere pe părinte îi dă și
dreptul să redenumească `.install-state` din drum și să planteze acolo
propriul `preflight.env`. `resolve_config` din `install.sh` face `source`
peste fișierul ăla ca root, la fiecare rulare: un `preflight.env` plantat e
execuție de cod arbitrar ca root, iar la o actualizare pasul care l-ar fi
rescris dintr-o verificare de încredere e marcat deja făcut și e sărit, deci
nimic nu-l reîmprospătează înainte de acel `source`.

Reparația mută marcajele într-un director dedicat, `/var/lib/sentinel-install`
— NU sub `/var/lib/sentinel`, ci alături de el, cu părintele (`/var/lib`)
root-owned. Asta închide ruta de scriere structural: `sentinel` nu mai are
niciun bit de scriere pe niciun strămoș al căii, deci nu mai poate nici
redenumi, nici planta nimic acolo, indiferent de ce verificare ar mai exista
deasupra.

**Ce s-a respins: mutarea automată a marcajelor vechi.** Trei runde (8-9
septembrie 2026) au încercat să facă sigură o migrare care mută conținutul
vechii locații în cea nouă la prima instalare de după reparație, ca o gazdă
existentă să nu piardă pașii deja făcuți:

| Rundă | Ocolire găsită |
|---|---|
| 1 | Un symlink plantat la calea VECHE, urmat de `mv -f`, muta conținutul țintei alese de atacator în directorul nou, root-owned — și era re-armabil la fiecare rulare, fiindcă părintele rămânea scriibil |
| 2 | Un director root-owned existent (`executor/`, creat pentru `audit.jsonl`-ul executorului), redenumit de `sentinel` peste calea veche, trecea orice verificare bazată doar pe proprietate — proprietatea era reală, doar numele mințea |
| 3 | Un symlink plantat la calea NOUĂ (după ce prima migrare reușise), urmat din nou de operațiile ulterioare care presupuneau că o cale root-owned rămâne root-owned |

Fiecare reparație a închis exact ocolirea rundei anterioare, și nici una alta
— semnul că problema nu era o verificare insuficient de strictă, ci forma
însăși: un proces root ia o decizie de încredere, din rezultatele unor
`stat()`, despre ceva aflat într-un director pe care un cont mai puțin
privilegiat îl poate redenumi oricând, inclusiv exact între verificare și
folosire. Nicio verificare suplimentară nu închide o cursă pe care contul
atacat o poate rearma la nesfârșit, cât timp mai deține scrierea pe părinte.

**Decizia (13 septembrie 2026): nu se mai migrează nimic.** Directorul vechi
e abandonat, nu curățat și nu mutat — conținutul lui e tratat ca absent, de
oriunde ar citi altcineva altfel decât `install.sh`/`common.sh`. Nimic aflat
sub un director scriibil de `sentinel` n-a fost vreodată suficient de
încrezător ca să merite promovat într-un director root-only doar fiindcă a
fost mutat acolo — migrarea încerca să spele exact ce mutarea locației (mai
sus) a făcut deja de prisos.

**Costul, scris ca atare:** o gazdă care se actualizează peste această
reparație are marcajele „pierdute" la calea nouă, deci fiecare pas gardat de
marcaj rulează încă o dată. Fiecare pas al instalatorului e scris să fie
sigur la o rerulare — e chiar contractul mecanismului de idempotență (vezi
`deploy/lib/common.sh`) — cu O SINGURĂ excepție, deja cunoscută și deja
apărată separat: faptul write-once `nginx_preexisting` (vezi și §3.15,
`nginx_preexisting_resolve` din `install.sh`), care decide dacă instalatorul
are voie să editeze `nginx.conf`-ul operatorului. Pierderea lui ar fi
periculoasă într-o singură direcție (o gazdă unde Sentinel a instalat propriul
nginx ar fi redetectată drept „nginx era dinainte", ceea ce face instalatorul
MAI conservator, nu mai puțin) — dar mecanismul are deja, dintr-o reparație
anterioară (26 august 2026), o plasă de siguranță care citește direct calea
veche pentru exact acest caz: un `head -1`/`grep` mărginit la o valoare „0"
sau „1", niciodată un `source`. Extinsă acum să citească ambele forme istorice
(faptul scris la vechea locație, și linia și mai veche din `preflight.env`),
plasa asta rămâne sigură din exact motivul pentru care restul mecanismului nu
e: nu ia nicio decizie de încredere structurală, doar extrage o valoare deja
constrânsă la un bit înainte să fie folosită.

`assert_root_owned_state_file` (verificarea de proprietate pe orice fișier
sursat din noul director) rămâne neatinsă — apără un caz diferit și real:
„nu pot verifica" tratat la fel ca „proprietar greșit", niciodată ca „e
curat", pentru orice a rămas pe disc de la o versiune mai veche sau mai
permisivă. Ocolirea rundei 2 (redenumirea unui director root-owned) NU ajunge
la ea: acea verificare cere scriere pe PĂRINTELE noii locații, iar `sentinel`
nu are niciuna.

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
