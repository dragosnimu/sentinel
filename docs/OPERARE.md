# Operare zilnică

Ce faci când primești o alertă, și ce verifici periodic.

---

## 1. A sunat telefonul — ce fac

### 🔴 CRITIC

Înseamnă „lasă ce faci". Sentinel emite `critical` doar pentru lucruri
acționabile acum; dacă începe să apară pentru altceva, regula trebuie
reclasificată, nu canalul pus pe mute.

1. **Citește prima linie.** E scrisă ca să fie de ajuns pe ecranul blocat.
2. `/incident <id>` pentru dosarul complet: cronologie, actor, evidențe,
   verdictul AI, acțiuni recomandate ordonate.
3. Acțiunile recomandate sunt concrete. Prima este de obicei ce trebuie făcut.

Cazuri critice și ce înseamnă:

| Alertă | Ce s-a întâmplat |
|---|---|
| `auth.ssh_success_after_failures` | Cineva a intrat pe SSH după încercări eșuate. Verifică dacă ai fost tu, apoi ce a făcut sesiunea |
| `web.rce` | Tentativă de injecție de comandă. Aproape niciodată fals pozitiv |
| `host.webroot_write` | Fișier scris într-un webroot în afara unei ferestre de deploy. Semn clasic de webshell |
| `host.new_suid` | Binar SUID nou. Persistență |
| `auth.new_user` / `new_ssh_key` | Utilizator sau cheie adăugată. Persistență |
| `availability.capacity_memory` | `MemAvailable` sub 500 MB. **OOM killer-ul e pe cale să omoare cel mai mare proces — de obicei aplicația, nu Sentinel.** Vezi DEPANARE §2 |

### 🟠 RIDICAT

Se rezolvă în aceeași zi, nu în același minut. De obicei atac oportunist real:
brute force, scanare agresivă, payload web.

Dacă auto-block e pornit, sursa e deja blocată și mesajul are `↩️ Deblochează`.
Dacă e oprit (primele 72h), ai `🚫 Blochează acum`.

**Blocarea IP-ului nu rezolvă vulnerabilitatea.** Dacă verdictul conține o
intersecție de expunere (`exposure_crossing.matched: true`), următorul atacator
va veni de pe altă adresă. A doua acțiune recomandată e patch-ul; ea contează.

### 🟡 MEDIU și mai jos

Nu necesită reacție imediată. Se agregă în digest și apar în raportul zilnic.

---

## 2. Butonul „Fals pozitiv"

Folosește-l. Nu doar închide incidentul: scrie o intrare de suprimare **îngustă**
(regulă + tipar + asset, nu regula întreagă) și alimentează datele de calibrare.
Este mecanismul prin care rata de fals-pozitive scade.

Dacă același fals pozitiv se repetă, cauza e aproape sigur o intrare lipsă în
allowlist, nu un prag greșit. Candidații obișnuiți: monitorul de uptime,
runner-ul de CI, validatorul Let's Encrypt, crawlerele, edge-urile CDN, IP-ul tău
mobil.

---

## 3. Rutina

### Zilnic — 2 minute

Raportul de la 08:00. Dacă nu s-a întâmplat nimic, nu vine (setare
`skip_if_empty`), ca să nu te antrenezi să ignori mesajul de dimineață.

Uită-te la secțiunea „Ce necesită o decizie". Dacă e goală, ai terminat.

### Săptămânal — 15 minute

```
/status
/vulns kev
/health
/budget
```

- **KEV deschise** sunt vulnerabilități exploatate activ în lume, pe sistemele
  tale. Ele au prioritate peste orice CVSS mai mare care nu e în KEV.
- **`/health`** — dacă adâncimea cozii AI crește, worker-ul e blocat. Dacă
  feed-urile de threat intel sunt vechi, rata de fals-pozitive va crește.
- **`/budget`** — dacă cheltuiala crește neașteptat, vezi DEPANARE §8.

Verifică și vechimea vulnerabilităților deschise: numărul care ar trebui să
scadă e vechimea medie, nu numărul total.

### Lunar — 30 minute

```bash
./scripts/smoke-test.sh --host ... --user ... --key ... --domain ...
```

Plus:
- Raportul lunar: `/report luna`
- Calibrarea predicțiilor (scorul Brier din raport). Dacă e prost, e vizibil —
  asta e ideea
- Puncte de restaurare: `/restore` — există unul recent pentru fiecare asset?
- Creșterea discului și data proiectată de umplere

### Trimestrial — 1 oră

**Testul de restaurare.** Un backup pe care nimeni nu l-a restaurat nu e backup.

Sentinel îți amintește la 90 de zile. Procedura completă în
[PATCHING.md](PATCHING.md) §6.

---

## 4. Când vrei să faci mentenanță planificată

Ca să nu primești alerte de disponibilitate în timp ce lucrezi:

```sql
INSERT INTO maintenance_windows (asset_id, starts_at, ends_at, reason, created_by)
VALUES (12, now(), now() + interval '2 hours', 'upgrade planificat', 'operator');
```

Suprimă regulile `availability.*` și `host.*` pentru asset-ul respectiv pe
durata ferestrei. Întreruperile din interiorul ei sunt marcate `planned` și nu
poluează cifra de disponibilitate.

---

## 5. Ce înseamnă cifrele

**Nivelul de amenințare (0–100)** din `/status` este un scor compozit
determinist: stadii în lanțul de atac, timp petrecut la stadiu, rata de
detecții, hit-uri pe feed-uri de reputație, intersecții de expunere,
criticitatea țintelor. Nu e o predicție — e o măsură a ce se întâmplă acum.

**Probabilitățile din predicții** sunt frecvențe empirice din istoricul propriu
al serverului: „31 din 87 de actori cu tipar similar în ultimele 60 de zile".
Numitorul e afișat. Sub 20, Sentinel spune că datele sunt insuficiente în loc să
inventeze un procent.

**Scorul Brier** măsoară cât de bune sunt predicțiile. Mai mic e mai bine; 0,25
este echivalentul aruncării cu banul. E în raport pentru că o predicție pe care
nimeni nu o verifică e marketing.

**Prioritatea vulnerabilităților (0–100)** combină CVSS, EPSS, apartenența la
KEV, expunerea la internet, criticitatea asset-ului și disponibilitatea unui
fix. **Sortează după ea, nu după CVSS.** Un CVSS 7,5 în KEV pe o aplicație
expusă contează mai mult decât un CVSS 9,8 într-o bibliotecă neatinsă de
trafic.

---

## 6. Ce să nu faci

- **Nu pune canalul pe mute.** Găsește regula zgomotoasă. DEPANARE §5.
- **Nu porni auto-block înainte de 72h de calibrare.** Vei bloca monitorul de
  uptime, validatorul ACME sau propriul telefon.
- **Nu edita `/etc/sentinel/*.yaml` fără restart** al serviciului corespunzător.
- **Nu aplica un patch fără dry-run** prima dată pe un asset.
- **Nu testa brute-force de pe IP-ul de pe care administrezi.** Folosește un
  hotspot sau un al doilea VPS.
- **Nu atinge nimic marcat `protected: true`** sau aflat sub o cale din
  `patch.extra_protected_paths`. Nu sunt ale lui Sentinel.
- **Nu șterge `/root/.pgpass` sau `/root/.aws/credentials`** doar pentru că
  arată a fișiere de credențiale rătăcite. Sunt momeli — §16 — și un fișier
  care nu ar trebui să existe e exact ce trebuie să pară.

---

## 7. Comenzi de referință

```bash
# Loguri lizibile
./scripts/tail-logs.sh --host ... --user ... --key ...
./scripts/tail-logs.sh --host ... --unit sentinel-detect --errors

# Interogări read-only (catalogul complet: rulează fără argumente)
SQ=/opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py
sudo /opt/sentinel/venv/bin/python $SQ open_incidents --format table
sudo /opt/sentinel/venv/bin/python $SQ top_actors --param since=24h --format table
sudo /opt/sentinel/venv/bin/python $SQ kev_findings --format table
sudo /opt/sentinel/venv/bin/python $SQ detections_by_rule --param since=24h --format table
sudo /opt/sentinel/venv/bin/python $SQ availability --param since=30d --format table

# Stare
sudo sentinel config-check -v
sudo nft list table inet sentinel
systemctl status 'sentinel-*'
```

---

## 8. Autoverificarea — „chiar funcționează?"

Întrebarea la care `systemctl status` nu răspunde. A răspuns „activ" în timpul
fiecărei pene reale pe care a avut-o instalarea asta: o zi cu tabela nftables
inexistentă, 21 de ore cu cititorul journald înghețat. Procesele rulau. Nu
făceau nimic.

De aceea fiecare verificare întreabă dacă o funcție **își produce efectul**, nu
dacă procesul ei există.

```
/selfcheck                    din Telegram, starea completă
sentinel selfcheck --print    pe server, cu cod de ieșire 0/1/2
```

Rulează automat la 5 minute și la 90 de secunde după boot. Alertează pe Telegram
**la schimbare**: o dată când se strică, o dată când revine, și o reamintire la
4 ore cât timp rămâne stricat. Alertele astea ignoră orele de liniște.

### Ce verifică, și de ce fiecare

| Grup | Ce dovedește |
|---|---|
| `unit:*` | Procesul există. Cea mai slabă dovadă din listă, și e prima doar fiindcă e cea așteptată |
| `ingest:*` | Fiecare colector a scris un rând recent. **Asta prinde orbirea** |
| `detect:cursor` | Detectorul consumă ce scriu colectorii. Ingestia într-o tabelă pe care n-o citește nimeni e o imitație convingătoare de funcționare |
| `nft:table`, `nft:count` | Kernelul chiar are tabela, iar baza spune același lucru ca el |
| `executor:socket` | Singura componentă privilegiată răspunde |
| `code:current` | Serviciile rulează codul instalat, nu pe cel dinaintea ultimului deploy |
| `alert:telegram` | Canalul care duce toate celelalte alerte chiar livrează |
| `identity:instance` | Gazda mai are identitatea cu care a fost instalată — vezi §12 |
| `db:*`, `res:*` | Fundațiile: bază accesibilă, schemă la zi, disc și memorie |

### O sursă tăcută nu e mereu un defect

O gazdă unde nu s-a întâmplat nimic arată identic cu una unde nimeni nu se mai
uită. Discriminarea: un colector care a amuțit **în timp ce vecinii lui scriu**
e stricat. Toți tăcuți deodată e o noapte liniștită, raportată o singură dată.

Fără regula asta ai fi primit șase alerte pentru un singur defect, și ai fi
oprit canalul într-o săptămână.

### Nu repară nimic

Deliberat. O autoverificare care repară ce găsește e una ale cărei descoperiri
nu mai sunt citite, iar un restart automat de daemon de securitate transformă un
defect vizibil într-unul intermitent. Îți spune ce s-a stricat și ce comandă
rezolvă; decizia rămâne a ta.

Singura excepție e la celălalt capăt: dacă **botul însuși** e căzut, mesajul nu
se pune în coada lui, ci se trimite direct. Un mesaj despre un bot mort, pus în
coada acelui bot, e un mesaj pe care nu-l citește nimeni.

---

## 9. După o repornire

Blocările nu se persistă — asta e intenționat, și e cea mai ieftină protecție
împotriva blocării propriei adrese. Ce se întâmplă automat:

1. **Executorul recreează tabela** la pornire, cu allowlistul, înainte să
   accepte vreo comandă. Allowlistul se persistă tocmai fiindcă o tabelă cu
   reguli de drop și fără el e felul în care îți dai singur firewall.
2. **`sentinel-reconcile` corectează evidența.** Kernelul e adevărul despre cine
   e blocat; după o repornire, adevărul e „nimeni". Blocările din bază care nu
   mai există în kernel sunt marcate ca eliberate, cu motiv scris.

Nimic nu se reblochează singur. Dacă atacatorii sunt încă activi, detectorul îi
prinde din nou în câteva minute.

```bash
sentinel reconcile              # manual, oricând
sentinel reconcile --reapply    # inversul: reaplică blocările din bază
```

`--reapply` există pentru cine nu vrea ca un reboot de la 4 dimineața să
elibereze toți atacatorii. Nu e implicit, fiindcă pornirea lui elimină tăcut
exact ieșirea de siguranță pe care se bazează restul designului.

---

## 10. Cât de expuse sunt serviciile

```bash
systemd-analyze security 'sentinel-*'
```

Zece din douăsprezece unități sunt sub 3.0. Cele două care nu sunt, rulează ca
root, și niciun set de directive nu duce un serviciu root sub 3.0 — `User=root`
singur costă 0.4, iar familia „rulează ca root" domină scorul.

| Unitate | Scor | De ce |
|---|---|---|
| `sentinel-executor` | 4.8 | Singura componentă privilegiată. Rulează managerul de pachete în numele tău, deci `NoNewPrivileges` și `PrivateDevices` ar arăta mai bine și ar strica patch-ingul exact când ai nevoie de el |
| `sentinel-watchdog` | 6.1 | Deadman-ul anti-lockout. Trebuie să funcționeze **precis când tot restul a eșuat**, deci nu depinde de nimic și rămâne minimal. Fiecare directivă adăugată acolo e încă un fel în care ar putea să nu pornească — singurul eșec fără recuperare |

Restul (web, detect, telegram, ingest, ai, scan, health, maintenance, selfcheck,
reconcile) sunt între **1.1 și 2.6**.

---

## 11. Rotirea parolei bazei de date

Se rotește când a fost văzută de cineva care nu trebuia, când pleacă un om care
o știa, sau când ai un motiv să crezi că gazda a fost atinsă. Nu e o operație de
rutină și nu are nevoie să fie.

### Ce se schimbă, și de ce sunt inseparabile

Parola trăiește în **două** locuri, iar între ele nu există nicio sincronizare
automată:

| Unde | Cine o scrie | Ce se întâmplă dacă rămâne veche |
|---|---|---|
| Rolul `sentinel` din PostgreSQL | pasul **22**, `ALTER ROLE sentinel PASSWORD` | daemonii se conectează cu ce au și merg mai departe |
| `/etc/sentinel/secrets.env` | pasul **27**, rescrie fișierul | daemonii primesc parola veche și baza îi refuză |

Doi pași care rulează la **fiecare** trecere a instalatorului fac ca separarea
lor să fie imposibilă: `migrate` (pasul 28), care se conectează la bază cu ce
scrie în `secrets.env`, și `start_services` (pasul 32), care repornește toți
daemonii. Amândoi sunt în `ALWAYS_STEPS`.

Deci, dacă forțezi un singur pas:

- **doar 22**: baza are parola nouă, `secrets.env` pe cea veche. Pasul 28 nu se
  mai poate conecta și instalarea moare acolo, înainte de repornirea
  serviciilor. Daemonii porniți merg mai departe pe conexiunile deja deschise și
  cad la prima reconectare — o gazdă care pare vie și se strică mai târziu.
- **doar 27**: exact invers, iar pasul 28 pică la fel. Dacă ai reporni
  serviciile după, ar porni direct în eșec de autentificare.

Nicio ordine nu duce la o gazdă întreagă, iar a doua rulare, cea care ar
„completa" prima, pornește de la o instalare deja eșuată. De aceea se forțează
**amândoi pașii într-o singură rulare**; lista de la `--force-step` există exact
pentru asta.

### Procedura

```bash
# 1. Pune valoarea nouă în secrets/.env.local (local, nu pe server).
#    Generarea: openssl rand -base64 32   — fără caractere care cer ghilimele.
#    Amprenta VALORII, nu a liniei. Ghilimelele din jur sunt scoase de installer
#    înainte de scriere, deci se scot și aici — altfel amprentele diferă după o
#    rotire perfect corectă și crezi că a eșuat:
NOUA=$(sed -n 's/^SENTINEL_DB_PASSWORD=//p' secrets/.env.local \
       | sed -e 's/^"//' -e 's/"$//' | sha256sum)

# 2. Verifică întâi că valoarea nouă chiar E nouă.
VECHEA=$(ssh ... "sudo sed -n 's/^SENTINEL_DB_PASSWORD=//p' /etc/sentinel/secrets.env" \
         | sha256sum)
[ "$NOUA" = "$VECHEA" ] && echo "IDENTICE — nu ai pus încă valoarea nouă"
#    Dacă sunt identice, oprește-te aici. Rotirea ar rula fără să schimbe nimic,
#    dovada (c) de mai jos ar pica, iar textul ei te-ar trimite să cauți un pas
#    22 care de fapt a rulat. S-a întâmplat.

# 3. Notează ce chei are gazda ACUM — numele, niciodată valorile. Pasul 27
#    rescrie fișierul de la zero; asta e lista pe care o compari după.
ssh ... "sudo grep -oE '^[A-Za-z_][A-Za-z0-9_]*' /etc/sentinel/secrets.env | sort" \
    > /tmp/chei-inainte.txt

# 4. O singură rulare, ambii pași:
./scripts/deploy.sh --host ... --user ... --key ... --domain ... \
    --force-step 22,27
```

Din PowerShell, identic:

```powershell
.\scripts\deploy.ps1 -HostName ... -User ... -Key ... -Domain ... -ForceStep 22,27
```

Instalatorul refuză din start o listă care nu e formată din numere și una care
conține un pas inexistent, refuză combinația `--force-step N` sub
`--from-step M`, și se oprește la final dacă vreunul dintre pașii ceruți nu a
rulat efectiv. Nu poate „reuși pe jumătate".

### Cum dovedești că s-a întâmplat

Codul de ieșire nu dovedește nimic aici — el spune doar că scriptul a ajuns la
capăt. Patru fapte observabile, în ordinea asta:

```bash
# a) NICIO cheie nu a dispărut. Pasul 27 rescrie fișierul de la zero, deci asta
#    se verifică prima: e singura care prinde pierderea unei chei despre care
#    nici tu, nici instalatorul nu vă gândeați în ziua aia.
ssh ... "sudo grep -oE '^[A-Za-z_][A-Za-z0-9_]*' /etc/sentinel/secrets.env | sort" \
    > /tmp/chei-dupa.txt
diff /tmp/chei-inainte.txt /tmp/chei-dupa.txt     # trebuie să nu spună nimic

# b) Fișierul de pe gazdă poartă valoarea nouă. Compari amprentele, nu valorile.
ssh ... "sudo sed -n 's/^SENTINEL_DB_PASSWORD=//p' /etc/sentinel/secrets.env" | sha256sum
#    Trebuie să fie amprenta de la pasul 1. Dacă e cea veche, pasul 27 nu a rulat.

# c) Parola VECHE este refuzată de bază. Ăsta e testul care contează:
#    dacă vechea valoare încă merge, nu s-a rotit nimic.
ssh ... "PGPASSWORD='<parola-veche>' psql -h 127.0.0.1 -U sentinel -d sentinel -c 'select 1'"
#    Aștepți un refuz de autentificare pentru utilizatorul sentinel
#    (`password authentication failed`), nu un rând de rezultat.

# d) Serviciile s-au reconectat, iar martorul din afară aude din nou.
ssh ... "sudo sentinel config-check -v"
#    Linia `secrets:` trebuie să fie OK. Dacă spune MISSING, îți dă numele cheii.
ssh ... "sudo sentinel selfcheck --print"
#    Grupurile db:* și ingest:* verzi.
ssh ... "journalctl -u sentinel-beacon -n 20 --no-pager"
#    Aștepți `beacon started`. `beacon disabled` înseamnă că unitatea a pornit,
#    a văzut că nu are cheie și a ieșit — cu cod 0.
```

Apoi, pe panoul martorului extern, **„Ultimul semnal"** trebuie să arate sub un
minut (intervalul e 60s). Ăsta e singurul rând din care se citește dovada fără
secret: numărul semnalului și contoarele apar doar în vizualizarea detaliată, la
`?key=<SENTINEL_CHECK_SECRET>`. Dacă vrei să vezi `seq` crescând, folosește
cheia; altfel te uiți la vârsta ultimului semnal, care e suficientă.

De ce toate patru: (b) fără (c) spune doar că fișierul a fost scris, nu că
`ALTER ROLE` a avut loc; (c) fără (d) spune că parola veche a murit, nu că
serviciile au primit-o pe cea nouă; iar (a) există fiindcă (b), (c) și (d) pot
trece toate în timp ce o cheie fără legătură a fost ștearsă din fișier.

**Beaconul nu se verifică prin `systemctl`.** Când cheia lipsește, procesul
spune o dată în jurnal și iese cu **0** — deliberat, ca să nu intre în buclă
când martorul nu e configurat. Deci `systemctl restart` întoarce 0, instalatorul
scrie `sentinel-beacon.service enabled and restarted`, iar unitatea e oprită.
Singurele dovezi sunt linia din jurnal și semnalul ajuns la martor.

Dacă (c) încă acceptă parola veche, **nu reporni serviciile** și nu relua
deploy-ul înainte de a înțelege de ce. Două cauze, în ordinea probabilității:
valoarea din `.env.local` era aceeași cu cea de pe gazdă (de asta există pasul 2
al procedurii), sau pasul 22 chiar nu a rulat. O a doua rulare care forțează
doar 27 e exact eroarea descrisă mai sus.

### Celelalte secrete

`ANTHROPIC_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` și
`TELEGRAM_APPLY_PIN` trăiesc doar în `secrets.env`, deci se rotesc cu
`--force-step 27` singur. Cheile generate pe gazdă (sesiuni web, TOTP) sunt
păstrate de pasul 27 dacă există deja; rotirea lor deconectează sesiunile și
invalidează înrolările TOTP, deci nu se face din reflex.

`SENTINEL_BEACON_SECRET` e altfel: e o cheie **comună** cu martorul din afară.
Nu o generează instalatorul și nu are voie să o genereze — o valoare nouă doar
pe o parte înseamnă că beaconul semnează fericit, iar martorul respinge fiecare
semnal ca semnătură greșită, ceea ce arată la fel ca o gazdă tăcută. Se rotește
schimbând-o în **ambele** locuri, iar dovada e (d) de mai sus.

De pe 19 august 2026, `SENTINEL_BEACON_SECRET` și `SENTINEL_SHIP_SECRET` pot fi
puse **prin canalul de livrare**, nu doar de mână pe gazdă. Sunt în
`OPERATOR_SECRET_KEYS`, nu în `GENERATED_SECRET_KEYS` — distincția contează și
rămâne: instalatorul le acceptă, dar nu le inventează niciodată. O valoare
născută aici ar fi jumătate dintr-o pereche a cărei cealaltă jumătate e la
martor, respectiv la agregator.

Înainte, prima punere a oricăreia cerea scris direct în `secrets.env` ca root,
iar rulările următoare doar o purtau mai departe. Pentru o funcție livrată, asta
însemna o procedură documentată care începea cu un pas nedocumentat.

Pasul 27 duce mai departe orice cheie găsită deja în `secrets.env`, nu doar pe
cele pe care le cunoaște. Nu a fost mereu așa: până în august 2026 rescria
fișierul din două liste fixe și ștergea restul, iar cheia beaconului era exact
„restul". Verificarea (a) e acolo pentru clasa asta de defect, nu pentru cazul
ăla anume — el e reparat.

---

## 12. Identitatea instalării

Un panou extern care adună mai multe instalări le deosebește după o singură
valoare: **`instance_id`**, 32 de caractere hexa (`openssl rand -hex 16`), în
`/etc/sentinel/instance_id`, mod `0640 root:sentinel`.

**Se generează o dată și nu se regenerează niciodată.** Fiecare deploy verifică
fișierul; dacă lipsește îl creează, iar dacă există doar îi reafirmă drepturile
și îl lasă în pace. Regenerarea ar rupe istoria serverului în două pe agregator,
iar ruptura nu produce nicio eroare nicăieri: cifrele doar încetează să însemne
ce spun.

Verificarea asta **nu** e legată de un pas al instalatorului, dinadins: pașii
sunt marcați ca făcuți și sărite la re-rulare, deci o gazdă instalată înainte ca
identitatea să existe n-ar fi căpătat-o niciodată dintr-un upgrade obișnuit — iar
beaconul nou, repornit fără ea, ar fi amuțit.

De ce nu hostname-ul: se schimbă (redenumire, migrare, un panou care recreează
VPS-ul), iar identitatea schimbată e o istorie bifurcată; pe un panou partajat e
și recunoaștere gratuită, fiindcă spune cui se uită cum se cheamă mașinile tale.
De ce nu `/etc/machine-id`: o mașină clonată îl moștenește, iar identitatea
duplicată e singurul eșec din familia asta care nu produce niciun raport de
defecțiune nicăieri.

**Nu e un secret și nu e o cheie.** Semnarea semnalului se face cu
`SENTINEL_BEACON_SECRET`; identitatea doar spune cine trimite.

### `instance_label` — numele pe care îl citești tu

În `/etc/sentinel/sentinel.yaml`, la rădăcină:

```yaml
instance_label: "prod-web-1"
```

Pur cosmetic, exact ca `hostname` de deasupra lui: apare în alerta martorului ca
`eticheta (id)`, ca să nu cauți după 32 de caractere hexa care server a tăcut.
Gol e o valoare validă și e valoarea implicită — atunci alerta poartă doar
identitatea. **Niciodată cheie:** nimic nu rutează, nu autentifică și nu
deduplică după el. Dacă ar face-o, oricine poate edita `sentinel.yaml` ar putea
muta un server în istoria altuia.

### Cele două reprezentări, și de ce sunt două

Fișierul e **autoritatea**. Rândul din tabela `instance_identity` e o
**oglindă** a lui, scrisă de `sentinel migrate` — care rulează la fiecare
instalare — și niciodată suprascrisă.

Copia nu e redundanță, e martorul. Un backup al bazei luat pe serverul A și
restaurat pe o clonă a lui B aduce datele lui A peste fișierul lui B. Fără o a
doua reprezentare pe care s-o contrazică, asta bifurcă tăcut un server în două
pe agregator.

### Când `/selfcheck` spune ceva despre identitate

| Ce vezi | Ce înseamnă | Ce faci |
|---|---|---|
| 🟡 **Identitatea instalării nu corespunde** | Fișierul spune una, baza alta. Aproape întotdeauna: bază restaurată pe altă mașină | Vezi mai jos — **nu** rescrie nimic până nu știi care e care |
| ⚪ **Nu pot citi identitatea instalării** | Fișierul lipsește, e gol, are altă formă, sau procesul n-are drepturi pe el | `ls -l /etc/sentinel/instance_id`. Lipsă → un deploy obișnuit îl creează. Există dar nu e o identitate → `od -c`, îl ștergi, apoi deploy. Vezi DEPLOYMENT.md §7 |
| 🟡 **Oglinda identității nu s-a scris** | Scriitorul a rulat și rândul tot nu e în bază | `sentinel migrate`, apoi `journalctl -u sentinel-selfcheck -n 50`; textul constatării poartă rezultatul înregistrat de ultima încercare |
| 🟢 „oglinda nu e scrisă încă, iar scriitorul nu a rulat niciodată aici" | Starea normală între instalarea codului și `sentinel migrate` | Nimic. Se rezolvă la prima migrare |

**Nepotrivirea nu e o pană.** Pe gazda asta nu s-a oprit nimic: se colectează,
se detectează, se blochează. Ce e stricat e cui i se atribuie datele în afara
ei — de aceea e 🟡 și nu 🔴.

### Ce faci la o nepotrivire

```bash
# Ce spune fiecare capăt. `first_seen` e din viața gazdei DINAINTE, dacă baza
# a venit de altundeva — jumătate din răspunsul la „de unde a apărut asta aici".
cat /etc/sentinel/instance_id
sudo -u postgres psql sentinel -c 'SELECT * FROM instance_identity'
```

Apoi decizi ce e adevărat, și doar tu poți:

* **Ai restaurat o bază de pe alt server pe mașina asta** (cazul obișnuit).
  Fișierul are dreptate; rândul e al altcuiva. Ștergi rândul și lași
  `sentinel migrate` să-l rescrie:
  `sudo -u postgres psql sentinel -c 'DELETE FROM instance_identity'` apoi
  `sudo sentinel migrate`. Datele rămân, dar de acum sunt atribuite gazdei
  ăsteia.
* **Ai clonat mașina și vrei două servere distincte.** Clona trebuie să capete
  identitate proprie: ștergi fișierul de pe ea și rulezi un deploy, care îl
  recreează (DEPLOYMENT.md §7). Apoi tratezi cazul de mai sus.
* **Nu știi ce s-a întâmplat.** Nu rescrie nimic. Atâta timp cât cele două se
  contrazic, constatarea rămâne pe `/selfcheck`, și asta e tot ce faci pierzând
  — o linie galbenă. O scriere greșită șterge dovada.

Scriitorul oglinzii **nu rezolvă niciodată singur** o nepotrivire: dacă tabela
ține alt identificator, `sentinel migrate` tipărește un avertisment, scrie o
linie de ERROR în jurnal și lasă rândul neatins. A „repara" scriind ar șterge
exact dovada pentru care există mecanismul.

---

## 13. Expedierea s-a oprit din cauza ceasului

Ce vezi pe `/selfcheck` sau în alertă:

> 🟡 **Expedierea fluxului „incidents" e oprită de ceasul serverului**
> filigranul e cu 3600 s înaintea ceasului bazei — ceasul a mers înapoi.

### Ce s-a întâmplat

Fluxurile care duc **entități ce se schimbă** — incidente, blocări, findings,
planuri de patch, active — nu pot folosi un cursor pe `id`: un incident închis
nu-și schimbă `id`-ul, deci `WHERE id > cursor` nu-l vede niciodată. Cursorul lor
e perechea `(updated_at, id)`, iar `updated_at` e ceasul bazei.

Asta cumpără capacitatea de a expedia o schimbare și plătește cu o dependență:
**dacă ceasul merge înapoi, expedierea fluxului se oprește.** Rândurile atinse de
atunci încolo primesc un `updated_at` mai mic decât filigranul, deci nu mai sunt
selectate niciodată. Interogarea rămâne validă și întoarce zero rânduri — exact
ce întoarce o gazdă pe care nu s-a schimbat nimic.

Constatarea asta există tocmai ca cele două să nu arate la fel. Fără ea ai fi
citit „la zi", verde, în timp ce nimic nu mai pleacă.

Cauzele obișnuite, în ordinea probabilității:

* `chronyd` a pășit înapoi după ce a pierdut contactul cu sursele și l-a
  recăpătat (`chronyc tracking`, câmpul `System time`);
* mașina virtuală a fost restaurată dintr-un instantaneu mai vechi;
* cineva a rulat `date -s` sau a oprit sincronizarea;
* ceasul o luase **înainte** și tocmai a fost corectat. E același lucru: o
  corecție în jos e un salt înapoi.

### Ce faci

```bash
timedatectl status          # NTP activ? ceasul sistemului sincronizat?
chronyc tracking            # System time, Last offset, Leap status
journalctl -u chronyd -n 50
```

Repari sursa de timp. **Atât.** După ce ceasul e corect, expedierea repornește
singură în momentul în care timpul real trece de filigran — nu e nevoie de nicio
comandă. Constatarea de pe `/selfcheck` se stinge la următoarea rulare.

Cât durează îți spune chiar constatarea: numărul de secunde din text e cât mai
are de așteptat.

### Ce s-a pierdut, și de ce agentul nu repară singur

Tot ce s-a schimbat între saltul înapoi și clipa în care timpul real ajunge din
urmă filigranul **nu va fi expediat niciodată**. Rândurile sunt intacte pe gazdă;
copia din afara ei nu le are. Un incident închis în fereastra aia rămâne deschis
pe agregator până la următoarea lui atingere.

Se putea repara automat, retrăgând filigranul la ora curentă: rândurile din
fereastră s-ar retrimite, iar retrimiterea e gratuită (ingestia e upsert). **Nu
se face, dinadins.** Pe un ceas care oscilează — și un ceas care a sărit o dată
e chiar ăla —, retragerea s-ar întâmpla la fiecare rundă, iar aceeași fereastră
ar pleca la nesfârșit. Costul nu se vede nicăieri până când îl spune factura de
trafic a agregatorului.

Alegerea între o pierdere mărginită și un cost nemărginit e a ta, nu a agentului.
Dacă vrei rândurile înapoi, după ce ceasul e reparat:

```bash
# Doar cu ceasul deja corect, și doar dacă înțelegi ce retrimiți.
# <flux> e numele din constatare: incidents, blocklist, findings, ...
sudo -u postgres psql sentinel -c   "UPDATE collector_cursors SET cursor_at = now() - interval '2 hours'    WHERE name = 'ship:<flux>'"
```

Intervalul trebuie să acopere fereastra pierdută. Cu cât e mai mare, cu atât se
retrimit mai multe rânduri deja ajunse — inofensiv, dar plătit în trafic.

### Ce NU e cazul ăsta

* **„Expedierea fluxului … a rămas în urmă"** — altă constatare, altă cauză:
  agregatorul nu confirmă. Acolo se caută în `journalctl -u sentinel-shipper`.
* **`audit_log`** nu poate ajunge aici niciodată. E append-only, cursorul lui e
  pe `id`, iar `id`-urile nu depind de ceas. Lanțul de audit pleacă de pe gazdă
  și cu ceasul stricat.

---

## 14. Rânduri apărute sub filigran

Ce vezi în jurnal (`journalctl -u sentinel-shipper`):

> `rows appeared below the shipping cursor and will never be shipped`
> `stream=incidents rows=3 total_lost=3`

și, pe `/selfcheck`, o notă lipită de fluxul respectiv: *„3 rânduri au apărut sub
filigran după ce a trecut peste ele … și nu vor pleca niciodată"*.

### Ce s-a întâmplat

`updated_at` primește `now()`, care în PostgreSQL e **ora de început a
tranzacției**, nu a instrucțiunii. Ordinea commit-urilor nu e ordinea
începuturilor: o tranzacție pornită la 10:00:00 și comisă la 10:00:40 face rândul
vizibil *după* una pornită la 10:00:20 și comisă la 10:00:21. Dacă expeditorul a
trecut între timp de 10:00:00, rândul apare sub filigran și nu mai e selectat
niciodată.

Împotriva asta, expeditorul nu trimite rândurile mai proaspete de
`COMMIT_SAFETY_LAG_S` (30 de secunde, în `sentinel/report/shipper.py`). Fereastra
mărginește problema; **nu o elimină.** O tranzacție de scriere mai lungă de atât
o produce oricum.

Mesajul de mai sus e măsurătoarea, nu o estimare: fereastra citită la runda
precedentă e închisă — orice atingere nouă pune `updated_at = now()`, care e
deasupra cursorului — deci fiecare rând găsit în plus acolo a fost comis cu
întârziere.

### Ce faci

```bash
# Cea mai lungă tranzacție deschisă acum. Rulează de câteva ori în timpul
# vârfului de activitate, nu o dată la miezul nopții.
sudo -u postgres psql sentinel -c   "SELECT pid, state, now() - xact_start AS durata, query
   FROM pg_stat_activity WHERE xact_start IS NOT NULL
   ORDER BY xact_start LIMIT 5"
```

Dacă vezi tranzacții care trec de 30 de secunde, **cauza e acolo**, nu în
expeditor: o cale de cod care ține o tranzacție deschisă peste o cerere de rețea,
un `psql` uitat deschis într-un `BEGIN`, un job de întreținere. Repar-o, sau
ridică `COMMIT_SAFETY_LAG_S` peste durata măsurată — costul e că o schimbare
apare pe agregator cu atâtea secunde mai târziu.

### Cum recuperezi rândurile pierdute

Ele sunt intacte pe gazdă; doar copia din afara ei nu le are. Se recuperează
retrăgând filigranul, ceea ce retrimite o fereastră de rânduri deja ajunse —
inofensiv (ingestia e upsert), plătit în trafic:

```bash
# Intervalul trebuie să acopere momentul tranzacției lungi.
sudo -u postgres psql sentinel -c   "UPDATE collector_cursors SET cursor_at = now() - interval '1 hour'    WHERE name = 'ship:incidents'"
```

Contorul nu se resetează singur, dinadins: e istoria pierderilor instalării, nu
o stare curentă. Dacă vrei să pornești de la zero după ce ai recuperat:
`DELETE FROM collector_cursors WHERE name = 'ship:incidents:lost'`.

---

## 15. Filigranul nu e întreținut — trigger lipsă

Ce vezi pe `/selfcheck`:

> 🟡 **Expedierea fluxului „incidents" nu are filigran întreținut**

### Ce s-a întâmplat

Coloana `updated_at` a tabelei există, dar **niciun trigger activ nu o mai
actualizează**. Rândul se schimbă, momentul lui rămâne cel de la INSERT. Cursorul
trece o dată peste el și nu-l mai vede niciodată.

Ăsta e cel mai tăcut mod de eșec din tot mecanismul, și de-aia e verificat la
fiecare rulare în loc să fie presupus din migrație: fără el, interogarea întoarce
zero rânduri, ceasul e bun, restanța e zero, unitatea e `active` — totul arată
sănătos, la nesfârșit.

Cauze: migrația `0023` n-a fost aplicată pe gazda asta; a fost aplicată și
nucleul a respins ceva; sau cineva a rulat `ALTER TABLE … DISABLE TRIGGER`, ceea
ce lasă rândul în catalog și oprește efectul.

**Un fișier de migrație pe disc nu e dovadă că a fost încărcat**, iar
`schema_version` spune doar că instrucțiunile au rulat fără eroare pe versiunea
de-atunci a fișierului. Faptul e în `pg_trigger`.

### Ce faci

```bash
sudo sentinel migrate

# Apoi verifici EFECTUL, nu fișierul:
sudo -u postgres psql sentinel -c   "SELECT tgrelid::regclass AS tabela, tgname, tgenabled
   FROM pg_trigger WHERE NOT tgisinternal
     AND tgfoid = to_regproc('set_updated_at') ORDER BY 1"
```

Trebuie să apară șapte rânduri — `actors`, `assets`, `blocklist`, `findings`,
`incidents`, `patch_plans`, `selfcheck_state` — toate cu `tgenabled = 'O'`.

`tgenabled` are patru valori, și doar două înseamnă „rulează":

| Valoare | Ce înseamnă | Fluxul merge? |
|---|---|---|
| `'O'` | origine — normalul | da |
| `'A'` | întotdeauna, inclusiv pe sesiuni de replicare | da |
| `'D'` | dezactivat (`ALTER TABLE … DISABLE TRIGGER`) | **nu** |
| `'R'` | doar pe o sesiune cu `session_replication_role = 'replica'` (`ENABLE REPLICA TRIGGER`) | **nu** |

`'D'` și `'R'` sunt amândouă „prezent în catalog și fără efect pentru noi" — un
trigger `'R'` nu se declanșează pe conexiunea obișnuită a expeditorului. De aceea
verificarea enumeră ce acceptă (`'O'`, `'A'`), nu ce respinge.

**`audit_log` nu trebuie să apară acolo, niciodată.** E append-only, cu un
trigger care ridică excepție la UPDATE (`0002_response.sql`); fluxul lui merge pe
`id` și nu depinde de niciun ceas.

Cât timp constatarea e pe `/selfcheck`, fluxul e **oprit** — dinadins. Un flux
care ar continua ar părea la zi și n-ar duce nicio modificare, ceea ce e mai rău
decât o linie galbenă.

## 16. Momelile (fișiere-canar)

Doi fișiere pe gazdă n-au niciun motiv legitim să fie citite, niciodată:
`/root/.pgpass` și `/root/.aws/credentials`. Conținutul lor e fals — o parolă și
o pereche de chei care nu funcționează nicăieri — pus acolo deliberat, ca momeală.
O citire a oricăruia dintre ele produce un incident `critical` care trece de
orice fereastră de liniște: nimic de pe gazdă n-are motiv să le deschidă, deci o
citire înseamnă că cineva e deja înăuntru și caută credențiale.

**Nu le șterge și nu le edita.** Dacă dai peste ele într-un `find` sau într-un
backup și arată a fișiere uitate de altcineva, nu sunt — sunt puse de instalator,
la fiecare deploy, dacă lipsesc.

### Le poți muta

Locul lor implicit e ghicibil de oricine citește codul — depozitul e public. Dacă
vrei momeli pe căi specifice gazdei tale (de exemplu, o cale care seamănă cu ce
chiar folosești pe serverul ăsta, nu cu implicitul din depozit), setează înainte
de instalare:

```bash
export CANARY_PGPASS_PATH=/root/altundeva/.pgpass
export CANARY_AWS_CREDS_PATH=/root/altundeva/credentials
```

Instalatorul plantează momelile la căile alea în loc de cele implicite, și tot
el le arată regulii de audit — nu trebuie schimbat nimic altundeva. Câștigul e
strict împotriva unui atacator care a citit exact acest depozit și evită căile
implicite pe motiv că par o momeală; oricine altcineva le caută oricum pe căile
canonice (`.pgpass`, `.aws/credentials`), indiferent de ce repository există.

### Cum știe instalatorul care momeală e a lui

La plantare, instalatorul scrie mărimea fișierului (în octeți) în
`/etc/sentinel/canary-state`. La un redeploy, dacă fișierul e deja acolo,
decizia „e a mea" se ia comparând mărimea CURENTĂ, luată cu `stat`, cu cea
înregistrată — niciodată deschizând fișierul. Asta e dinadins: o deschidere a
momelii de către instalatorul însuși, odată ce regula `sentinel_bait` e armată
dintr-un deploy anterior, nu se deosebește de o citire a unui atacator, iar
exact asta a produs un `critical` fals la fiecare livrare, până pe 31 august
2026. Marcajul de text (`sentinel-canary`) a rămas în conținut, dar nu mai e
citit de nimic automat — e acolo pentru un om care se uită la un dump.

**Editare a operatorului care păstrează mărimea** (de exemplu, o parolă falsă
înlocuită cu alta la fel de lungă): lăsată în pace, tot sub urmărire `critical`.

**Editare care schimbă mărimea, sau un fișier real mutat pe aceeași cale**:
instalatorul nu mai poate deosebi cele două fără să deschidă fișierul, așa că
nu încearcă — tratează calea ca „fără evidență", exact ca pe un fișier străin:
avertizează, scoate urmărirea de audit pentru calea aia din fișierul instalat,
dar nu atinge niciodată conținutul. Nu repurpoza o cale de momeală pentru ceva
real; alege o cale nouă, din afara celor două de mai sus.

**O gazdă restaurată dintr-un backup dinainte ca `canary-state` să existe**
își pierde evidența propriilor momeli. Consecința e aceeași ca mai sus —
avertisment, urmărire scoasă din nucleu — niciodată o citire tăcută ca să
recupereze clasificarea. Vizibil în ieșirea deploy-ului, nu tăcut: rulează
din nou pasul după ce ștergi fișierele vechi, ca să fie replantate și
înregistrate.
