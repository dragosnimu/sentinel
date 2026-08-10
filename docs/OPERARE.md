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

Pasul 27 duce mai departe orice cheie găsită deja în `secrets.env`, nu doar pe
cele pe care le cunoaște. Nu a fost mereu așa: până în august 2026 rescria
fișierul din două liste fixe și ștergea restul, iar cheia beaconului era exact
„restul". Verificarea (a) e acolo pentru clasa asta de defect, nu pentru cazul
ăla anume — el e reparat.
