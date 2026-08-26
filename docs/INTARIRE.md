# Întărirea serverului — ghid contextual

Măsurat pe gazda de producție, **10 august 2026**. Nu e o listă generică de
bune practici: fiecare punct pornește de la un fapt citit de pe server în ziua
aceea, iar ordinea e dată de risc real, nu de severitatea din scanner.

Fiecare procedură are patru părți: **ce dovedește că e o problemă**, **comanda**,
**cum verifici efectul** (nu codul de ieșire), și **cum dai înapoi**.

> Regula de aur a acestui ghid: după fiecare comandă, verifică *faptul*, nu
> raportul. Un `systemctl reload` care întoarce 0 nu dovedește că fișierul de
> configurare a fost acceptat. Un pachet instalat nu dovedește că procesul care
> îl folosea l-a reîncărcat.

---

## Ce spun datele, pe scurt

| Ce arată panoul | Ce e de fapt |
|---|---|
| 31 vulnerabilități deschise | **2 pachete** de actualizat. 29 sunt învechite |
| „kernel vulnerabil" (5 CVE) | kernelul care rulează e **mai nou** decât toate reparațiile cerute |
| Suricata — nicio constatare | **are** actualizare de securitate, scannerul n-a văzut-o |
| 594 incidente deschise | zgomot de internet; 3 critice, dintre care 2 false |
| Patch-uri | 2 eșuate, 2 respinse, **zero reușite** |

Iar cel mai grav lucru de pe server nu apare în niciun panou.

---

## 0. Credențiale lizibile de oricine, în `/tmp` — URGENT

**Dovada**, citită azi:

```
/tmp/sentinel-deploy-20260805-085315/credentiale.txt   mod 644
/tmp/sentinel-deploy-20260805-085344/credentiale.txt   mod 644
/tmp/sentinel-deploy-20260805-085404/credentiale.txt   mod 644
/tmp: mod 1777
conturi cu shell valid: deploy, al-doilea-cont
```

Fișierul e în `.gitignore`, deci niciun revizor nu l-a văzut vreodată. Dar `tar`
nu citește `.gitignore`, iar lista de excluderi din `scripts/deploy.sh` nu-l
conține — deci pleacă în pachet la fiecare deploy și e extras pe gazdă.
Curățarea finală rulează doar pe calea de succes; cele trei rămase sunt de la
rulări întrerupte pe 5 august.

Conțin cheia API Anthropic, tokenul botului Telegram și chat id-ul. `/tmp` are
bitul sticky, dar modul 644 înseamnă că **orice cont local le poate citi**.

### Ștergere

```bash
sudo rm -rf /tmp/sentinel-deploy-*
```

**Verifică efectul:**

```bash
find /tmp -maxdepth 2 -name 'credentiale*' 2>/dev/null; echo "cod: $?"
```

Nu trebuie să afișeze nimic.

**Rollback:** niciunul, și nu e nevoie. Directoarele acelea sunt copii de
lucru ale unui deploy încheiat; `rollback.sh` folosit de scriptul de deploy
trăiește în `/opt/sentinel/deploy`, nu acolo.

### Rotirea a ceea ce a fost expus

Cinci zile lizibile local. Nu știm dacă au fost citite; știm că puteau fi.

- **Cheia Anthropic** — din consola Anthropic, revocă și generează alta.
- **Tokenul botului** — în Telegram, la `@BotFather`: `/revoke`, alege botul.
  Vechiul token moare pe loc.

Apoi pune valorile noi în `secrets/.env.local` pe stația de lucru și aplică-le
prin calea sancționată — vezi `docs/OPERARE.md` §11, procedura de rotire.

**Verifică efectul:** botul trebuie să răspundă la `/status` după deploy. Dacă
tokenul vechi ar mai fi valid, ar răspunde *și* la el — de aceea revocarea
contează mai mult decât înlocuirea.

---

## 1. Autentificarea cu parolă pe SSH

**Dovada:**

```
sshd -T | grep passwordauthentication   ->  passwordauthentication yes
incidente deschise: 140 high, majoritatea brute-force SSH
```

Ai chei publice funcționale (`pubkeyauthentication yes`, deploy-ul rulează pe
cheie). Parola rămasă activă nu-ți dă nimic în plus și e chiar suprafața pe
care o lovesc cele 140 de incidente.

`permitrootlogin no` e deja corect.

### Backup înainte

```bash
sudo cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak-$(date +%F-%H%M)
```

### Comanda

```bash
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
```

**Deschide o a doua sesiune SSH acum și las-o deschisă.** Nu închide sesiunea
curentă până nu confirmi că te poți autentifica din nou.

### Validare înainte de aplicare

```bash
sudo sshd -t && echo "configurare valida"
```

Dacă nu tipărește `configurare valida`, **oprește-te** și restaurează backupul.

### Aplicare

```bash
sudo systemctl reload sshd
```

**Verifică efectul, nu codul de ieșire:**

```bash
sudo sshd -T | grep -E '^passwordauthentication'
```

Trebuie să spună `no`. `reload` întoarce 0 și când configurarea a fost respinsă
— de aceea citim starea efectivă, nu rezultatul comenzii.

Apoi, dintr-o fereastră nouă:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no deploy@203.0.113.10
```

Trebuie să fie **refuzat**. Dacă intră, schimbarea n-a avut efect.

### Rollback

```bash
sudo cp -a /etc/ssh/sshd_config.bak-* /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd
```

**Dacă ai pierdut accesul:** consola VPS de la furnizor e singura cale. De
aceea se testează accesul la consolă *înainte*, nu după.

### Opțional, în același fișier

`x11forwarding yes` nu are ce căuta pe un server fără interfață grafică.
`maxauthtries 6` poate coborî la 3. Amândouă cu aceeași procedură de validare.

---

## 2. Servicii publicate pe toate interfețele

**Dovada** — ce ascultă pe `0.0.0.0`, măsurat azi:

```
:22    sshd            necesar
:80    nginx           necesar
:443   nginx           necesar
:10050 zabbix_agentd   monitorizare
:3001  docker-proxy -> bet-calculator
:8000  docker-proxy -> snipeit
:88    docker-proxy -> n8n traefik
:444   docker-proxy -> n8n traefik
:6333  docker-proxy -> qdrant
:6334  docker-proxy -> qdrant
```

Două containere sunt deja corect legate pe loopback — `aplicatie-interna_app` pe
`127.0.0.1:3000` și `n8n` pe `127.0.0.1:5678`. Restul sunt publice.

**Qdrant pe 6333 cere cheie API** — verificat, nu presupus:
`GET /collections` întoarce `401 Must provide an API key or an Authorization
bearer token`. Prima versiune a acestui ghid spunea că e probabil fără
autentificare, pe baza configurației implicite a produsului. Era o presupunere,
și era greșită.

Rămâne totuși expus: un serviciu de date accesibil din internet, fără TLS, a
cărui singură apărare e o cheie care circulă în clar la fiecare cerere.

### Verifică întâi dacă e chiar deschis din exterior

nftables de pe gazdă e `policy accept`, dar furnizorul poate avea un filtru.
De pe altă mașină, nu de pe server:

```bash
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://203.0.113.10:6333/collections
```

`200` înseamnă expus și fără autentificare. Timeout înseamnă că te apără altceva
— dar nu te baza pe asta, verifică ce anume.

### Remediul: leagă pe loopback în loc de toate interfețele

Pentru fiecare container care nu trebuie să fie public, în `docker-compose.yml`
al lui, schimbă maparea din:

```
ports:
  - "6333:6333"
```

în:

```
ports:
  - "127.0.0.1:6333:6333"
```

**Backup înainte:**

```bash
sudo cp -a docker-compose.yml docker-compose.yml.bak-$(date +%F-%H%M)
```

**Aplicare** (din directorul containerului):

```bash
sudo docker compose up -d
```

**Verifică efectul:**

```bash
sudo ss -tlnp | grep 6333
```

Trebuie să arate `127.0.0.1:6333`, nu `0.0.0.0:6333`.

Și confirmă că aplicația ta încă funcționează — dacă vreun serviciu o accesa
prin IP-ul public, se va rupe. De aceea se face unul câte unul.

**Rollback:**

```bash
sudo cp -a docker-compose.yml.bak-* docker-compose.yml && sudo docker compose up -d
```

### Dacă un serviciu trebuie să rămână public

Pune-l în spatele nginx, cu TLS și autentificare, cum e deja `aplicatie-interna`. Un
port de aplicație expus direct nu are nici jurnal de acces util, nici limitare
de rată, nici certificat.

---

## 3. Cele două pachete care chiar au nevoie de actualizare

**Dovada:**

```
instalat: libarchive-3.5.3-9.el9_7    ->  ALSA-2026:52674           3.5.3-11.el9_8
instalat: suricata-7.0.15-1.el9       ->  FEDORA-EPEL-2026-d4d937   7.0.16-1.el9
dnf check-update: 2 pachete
```

Suricata e chiar sonda de detecție a lui Sentinel. Nu apare în lista de
vulnerabilități — vezi §4.

### Backup

Punctul de întoarcere pentru pachete e tranzacția `dnf`, nu o copie de fișiere.
Notează numărul tranzacției **înainte**:

```bash
sudo dnf history list | head -3
```

### Comanda

```bash
sudo dnf -y update --security
```

**Verifică efectul:**

```bash
rpm -q libarchive suricata
```

Trebuie să arate `3.5.3-11.el9_8` și `7.0.16-1.el9`.

### Procesele trebuie repornite ca să folosească versiunea nouă

Un pachet actualizat pe disc nu înseamnă că procesul care rula biblioteca veche
a reîncărcat-o.

```bash
sudo needs-restarting -s
```

Pentru Suricata, repornirea e explicită:

```bash
sudo systemctl restart suricata
```

**Verifică efectul, nu `is-active`:**

```bash
systemctl show suricata -p NRestarts -p ActiveState --value
suricata --build-info | head -2
```

`NRestarts` trebuie să fie 0 după repornire — dacă crește, serviciul e în buclă.
Și confirmă că Sentinel primește iar evenimente:

```bash
sudo -u postgres psql -d sentinel -tAc \
  "select max(ts) from raw_events where source='suricata';"
```

Trebuie să fie din ultimul minut.

### Rollback

```bash
sudo dnf history undo <numarul-tranzactiei>
```

Numărul e cel notat înainte, plus unu — `dnf history list` îl arată pe primul
rând după actualizare. Apoi repornește ce ai repornit și verifică din nou
evenimentele.

---

## 4. Lista de vulnerabilități minte în ambele direcții

**Dovada:**

```
kernel care ruleaza:  5.14.0-687.36.1.el9_8
findings deschise cer: 687.33 (3 CVE), 687.34 (1 CVE), 687.36 (2 CVE)
```

Toate cele 29 de constatări despre kernel sunt **deja satisfăcute** de kernelul
care rulează. Rămân deschise fiindcă nimic nu le reevaluează după o actualizare.

În sens invers: Suricata **are** o actualizare de securitate și **nu apare**
deloc în constatări. Scannerul acoperă depozitele de bază, nu și EPEL.

Un panou care arată 31 de probleme când există una, și ratează o alta, e mai
periculos decât unul gol: te învață că roșul nu înseamnă nimic.

### Ce faci acum

Rulează o scanare nouă după actualizarea de la §3 și vezi dacă se închid:

```bash
sudo systemctl start sentinel-scan
```

**Verifică efectul:**

```bash
sudo -u postgres psql -d sentinel -tAc \
  "select status, count(*) from findings group by 1;"
```

Dacă cele 29 rămân deschise după o scanare reușită, defectul e în reconcilierea
constatărilor, nu în date — și e o reparație de cod, nu una de server. Notează-l
și spune-mi.

**Rollback:** niciunul. O scanare nu schimbă nimic pe gazdă.

---

## 5. Sentinel nu blochează nimic

**Dovada:**

```
/etc/sentinel/sentinel.yaml:  auto_block: enabled: false
nftables blocklist_v4:        24 adrese (puse manual sau de reguli)
incidente deschise:           451 medium, 140 high, 3 critical
```

Auto-block e dezactivat de la instalare — corect ca punct de plecare, fiindcă
primele 72 de ore sunt mod „observă". Au trecut zece zile.

### Înainte de a-l porni

Verifică ce **ar fi** fost blocat. Dacă în lista aia apare un monitor de uptime,
Let's Encrypt, un crawler legitim sau IP-ul tău mobil, oprește-te și pune-le în
allowlist întâi.

```bash
sudo -u postgres psql -d sentinel -P pager=off -c \
  "select actor_key, count(*) from incidents where status='open' and severity in ('high','critical') group by 1 order by 2 desc limit 15;"
```

Și confirmă că adresa de pe care administrezi e în allowlist:

```bash
sudo nft list set inet sentinel allowlist_v4
```

**Dacă nu e acolo, nu porni auto-block.** Verificarea automată care ar fi trebuit
să te apere de asta nu există — a fost ștearsă azi, fiindcă nu rulase niciodată
(citea un câmp de configurare inexistent). Până e rescrisă, verificarea asta e
manuală și obligatorie.

### Backup

```bash
sudo cp -a /etc/sentinel/sentinel.yaml /etc/sentinel/sentinel.yaml.bak-$(date +%F-%H%M)
```

### Comanda

```bash
sudo sed -i '/auto_block:/,/enabled:/ s/enabled: false/enabled: true/' /etc/sentinel/sentinel.yaml
```

**Validează înainte de repornire:**

```bash
sudo /opt/sentinel/bin/sentinel config-check -v
```

### Aplicare

```bash
sudo systemctl restart sentinel-detect
```

**Verifică efectul:**

```bash
systemctl show sentinel-detect -p NRestarts --value
sudo /opt/sentinel/bin/sentinel config-check -v | grep -i block
```

### Ieșiri de urgență, dacă blochează ce nu trebuie

```bash
sudo touch /etc/sentinel/PANIC
```

Golește blocklistul în cel mult 60 de secunde, prin watchdog-ul care rulează ca
root, independent de baza de date. Blocările nu se persistă peste reboot, deci
o repornire e a doua ieșire.

### Rollback

```bash
sudo cp -a /etc/sentinel/sentinel.yaml.bak-* /etc/sentinel/sentinel.yaml && sudo systemctl restart sentinel-detect
```

---

## 6. Dashboard-ul acceptă orice sursă

**Dovada:**

```
/etc/sentinel/sentinel.yaml:  ip_allowlist: []
config-check: "web ip allowlist: empty — the dashboard accepts any source
               that reaches nginx"
```

Panoul are TLS, Argon2id, TOTP obligatoriu, limitare de rată și fail2ban în
plan. Dar e expus public, iar `ip_allowlist` e cea mai ieftină întărire rămasă.

Nu o completez eu — depinde de unde administrezi. Dacă lucrezi de pe o adresă
fixă sau dintr-un interval cunoscut, adaugă-l; dacă administrezi de pe mobil,
Telegram rămâne canalul „de oriunde" și poți lăsa panoul deschis conștient.

### Backup, comandă, verificare

Aceeași procedură ca §5: copiază `sentinel.yaml`, editează `web.ip_allowlist`,
`config-check -v`, `systemctl restart sentinel-web`, apoi **verifică din
exterior** că o adresă neinclusă chiar primește refuz — nu presupune.

---

## 7. fail2ban e instalat și oprit

**Dovada:**

```
systemctl is-active fail2ban  ->  inactive
```

Planul de instalare îl prevede ca a doua plasă sub Sentinel, pentru SSH și
pentru panou. Dacă aplici §1 (parola oprită pe SSH), câștigul scade mult —
brute-force-ul pe chei nu duce nicăieri. Decide dacă mai merită.

Dacă îl pornești, allowlistul lui trebuie să conțină aceleași adrese ca al lui
Sentinel, altfel ai două mecanisme care se pot bloca reciproc pe tine.

---

## 8. Trei kernele instalate

**Dovada:**

```
kernel-5.14.0-687.29.1
kernel-5.14.0-687.31.1
kernel-5.14.0-687.36.1   <- cel care rulează
```

Nu e o vulnerabilitate — un kernel neîncărcat nu se execută. E igienă de spațiu
și claritate. `dnf` păstrează implicit ultimele trei; dacă vrei să cureți:

```bash
sudo dnf -y remove --oldinstallroot $(rpm -q kernel | grep -v $(uname -r))
```

**Nu rula asta fără să verifici întâi ce ar șterge.** Varianta sigură:

```bash
sudo dnf repoquery --installonly --latest-limit=-1 -q
```

Arată exact ce ar fi eliminat. Păstrează **cel puțin două** kernele — cel care
rulează și unul anterior funcțional, ca ieșire dacă o actualizare viitoare nu
pornește.

---

## Ordinea recomandată

1. **§0** — azi, acum. Secretele sunt lizibile de un al doilea cont local.
2. **§1** — SSH cu parolă oprit. Cel mai mare câștig pentru cel mai mic risc.
3. **§2** — Qdrant pe loopback. Restul containerelor, unul câte unul.
4. **§3** — cele două pachete, cu repornirea Suricata verificată pe evenimente.
5. **§4** — scanare nouă, ca lista să însemne iar ceva.
6. **§5** — auto-block, doar după verificarea allowlistului.
7. **§6, §7, §8** — când ai timp.

Între §1 și §2, nu face mai mult de o schimbare odată fără să verifici efectul.
Fiecare are rollback scris; două aplicate împreună îți iau posibilitatea de a
ști care a stricat ce.

---

## Ce nu e în ghid, și de ce

**Patch-urile automate.** Sentinel are un motor de generare de proceduri de
patch cu backup și rollback, dar starea lui azi e: 2 planuri eșuate, 2 respinse
ca invalide, **zero reușite**. Până când unul trece capăt-la-capăt, actualizările
se fac manual, cum e la §3.

**Cele 3 incidente critice.** Două sunt false — unul e Sentinel care se
detectează pe sine în timpul unui deploy, celălalt avea evidență coruptă și e
în reparație. Al treilea e un brute-force real din 31 iulie, stins de mult.
Închide-le manual după ce reparațiile ajung pe server; cât timp incidentul cu
cheile SSH rămâne deschis, o schimbare reală de cheie se pliază peste el fără
să-ți trimită notificare.

**Suricata în mod IDS.** Rulează și scrie evenimente, dar nu blochează. Trecerea
în IPS e o schimbare cu risc de întrerupere a traficului legitim și nu se face
fără o fereastră de mentenanță și un plan de întoarcere. Nu e o comandă, e un
proiect.
