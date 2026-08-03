# Ghid de instalare — Sentinel

Instalarea agentului de cybersecurity Sentinel pe VPS-ul AlmaLinux 9.7 de la
`203.0.113.10`.

Sentinel este de sine stătător: nu depinde de niciun SIEM, de niciun agent
extern și de niciun serviciu în afara gazdei pe care rulează.

> **Regula zero: ce rula deja pe server nu se strică.** Sentinel este un
> musafir. Preflight înregistrează fiecare serviciu activ, fiecare port în
> ascultare și fiecare container care rulează; instalarea compară cu acel
> baseline la final și **face rollback automat** dacă ceva s-a oprit.

---

## 1. Ce vei obține

| Componentă | Ce face |
|---|---|
| `sentinel-ingest` | Colectează evenimente: journald, sshd, nginx, auditd, Suricata, Docker |
| `sentinel-detect` | Reguli, praguri, baseline statistic, actori, incidente, decizia de blocare |
| `sentinel-ai` | Triaj, corelare, predicții, rapoarte, generare planuri de patch |
| `sentinel-telegram` | Bot cu comenzi și butoane, long polling |
| `sentinel-web` | Dashboard pe `127.0.0.1:8787`, expus prin nginx cu TLS |
| `sentinel-executor` | **Singura componentă root.** Acțiuni privilegiate, peste unix socket |
| `sentinel-watchdog` | Deadman anti-lockout, la fiecare 60s, independent de restul |
| timere | Scanare nocturnă, probe de disponibilitate, mentenanță orară |

Porturi noi ocupate: **80**, **443** (nginx), **8787** și **5432** (doar
### Două moduri de expunere — alege înainte de deploy

| | `dedicated` *(implicit)* | `shared` |
|---|---|---|
| **Cum** | Listener nginx propriu pe `:8443` | Vhost pe nginx-ul existent, selectat prin `server_name` |
| **URL** | `https://sentinel.exemplu.ro:8443` | `https://sentinel.exemplu.ro` |
| **Redirect HTTP→HTTPS** | Nu (Sentinel nu deține `:80`) | Da |
| **Certificat** | Webroot servit de serviciul de pe `:80`, sau DNS-01 | **Funcționează din prima** — Sentinel servește singur provocarea ACME din propriul bloc `:80` |
| **Firewall provider** | Trebuie deschis portul 8443 | Nimic de deschis |
| **Ce atinge** | Nimic din ce există. Doar `nginx.conf`, și doar dacă a instalat el nginx | Scrie în `/etc/nginx/conf.d/`, director partajat cu site-urile tale |
| **Cerință** | Niciuna | nginx trebuie să fie cel care deține 80/443 |

**Recomandarea, pe serverul tău:** dacă nginx deține 80/443 — și preflight îți
spune asta explicit — folosește `shared`. E mai simplu în toate privințele care
contează, iar certificatul nu mai are nevoie de nicio intervenție.

```bash
# shared — nginx deține deja 80/443
./scripts/deploy.sh --host 203.0.113.10 --user deploy     --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --nginx-mode shared

# dedicated — altceva (Apache, Caddy, un container) deține 80/443
./scripts/deploy.sh --host 203.0.113.10 --user deploy     --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

#### Ce protejează modul shared

Riscul evident e că un vhost greșit al nostru face `nginx -t` să eșueze pentru
**tot** serverul. Un `reload` ar fi doar refuzat, deci site-urile tale ar
continua să ruleze — dar următorul *restart*, din orice motiv nelegat, n-ar mai
porni nginx deloc. Aia e o pană latentă cu numele nostru pe ea.

Deci instalarea, în ordinea asta:

1. **Refuză** dacă nginx nu e cel care deține 80/443 — un vhost nginx nu ajută
   dacă Apache ascultă acolo.
2. **Refuză** dacă `nginx -t` eșuează deja înainte să atingem ceva. Nu adăugăm un
   vhost la un nginx rupt: am deveni suspectul principal pentru o pană care nu e
   a noastră.
3. Instalează vhost-ul și rulează `nginx -t` din nou. **La eșec își șterge
   imediat fișierele** și confirmă că nginx a redevenit valid. Un config care nu
   trece `nginx -t` nu are voie să rămână pe disc.
4. Testează dacă vhost-ul nostru a devenit accidental cel implicit — și dacă da,
   îți spune să adaugi `default_server` în vhost-ul **tău**. Nu îl adăugăm noi:
   ar schimba care dintre site-urile tale răspunde la un Host necunoscut.

Fiecare server block e limitat prin `server_name`, zonele de rate-limit sunt
prefixate cu `sentinel_`, iar logurile sunt separate. Un test verifică toate
astea, plus că nu apare `default_server` nicăieri în template.

Rollback-ul în modul shared **nu** restaurează snapshot-ul `/etc/nginx`: ar anula
și modificările făcute de tine la site-urile tale după deploy. Șterge doar
fișierele noastre, care e undo-ul complet și corect acolo.

---

**Porturi (mod `dedicated`):**

| Port | Legat pe | Ce e |
|---|---|---|
| `8443/tcp` | public | Dashboard-ul (nginx, TLS). Configurabil cu `--web-port` |
| `8787/tcp` | `127.0.0.1` | Aplicația (uvicorn) |
| `5432/tcp` | `127.0.0.1` | PostgreSQL |

**80 și 443 rămân ale serviciilor tale.** Sentinel nu le atinge: un agent de
monitorizare care înlocuiește serviciul pe care îl monitorizează și-a inversat
scopul. Trei consecințe:

1. **URL-ul conține portul:** `https://sentinel.exemplu.ro:8443`
2. **Nu există redirect de la HTTP.** O cerere pe `http://sentinel.exemplu.ro`
   ajunge la serviciul care deține `:80`, nu la Sentinel.
3. **Certificatul nu poate veni din provocarea HTTP-01 a lui certbot**, care are
   nevoie de `:80`. Vezi §2.1.

Preflight verifică întâi că portul cerut e liber și raportează ce deține 80/443
— fără să atingă nimic.

---

## 2. Înainte de a începe

### 2.1 Cerințe pe server

| Cerință | Valoare | Ce se întâmplă dacă nu |
|---|---|---|
| OS | AlmaLinux / RHEL 9.x | Preflight oprește instalarea |
| RAM disponibil | ≥ 2,5 GB | Sub 2,5 GB → Suricata e sărită (mod log-only, în continuare util). **Sub 1,5 GB → abort**: OOM killer-ul alege cel mai mare proces, de obicei aplicația ta |
| Disc liber | ≥ 10 GB pe `/`, ≥ 8 GB pe `/var` | Preflight oprește |
| Porturi 80, 443 | libere | Preflight oprește |
| `firewalld` | inactiv | Preflight oprește (poți forța cu `--allow-firewalld`) |
| Servicii existente | funcționale | Preflight le înregistrează; instalarea face rollback automat dacă vreunul se oprește |
| sudo | funcțional | Ți se cere parola o dată |

Verifică rapid, înainte de orice:

```bash
ssh deploy@203.0.113.10 'free -h; df -h /; systemctl is-active firewalld'
```

### 2.2 Ce îți trebuie pregătit

1. **Înregistrarea DNS.** Un A record pentru subdomeniul dashboard-ului:

   ```
   sentinel.exemplu.ro.    A    203.0.113.10
   ```

   Verifică propagarea înainte de deploy — preflight oprește instalarea dacă
   numele nu rezolvă către acest server, pentru că altfel certbot eșuează la
   provocarea HTTP-01:

   ```bash
   dig +short sentinel.exemplu.ro
   ```

   Fără domeniu, dashboard-ul rulează cu certificat self-signed și primești
   warning la fiecare vizită — ceea ce te antrenează să dai click prin
   avertismente TLS, exact obiceiul pe care se bazează un atacator.

   **De ce un subdomeniu separat și nu o cale pe un site existent:** vhost
   propriu, loguri proprii, rate-limit propriu și CSP propriu. Un `/sentinel`
   pe un site care mai servește și altceva ar moșteni configurația și
   antetele acelui site.

### 2.1 Certificatul — partea care necesită o decizie

`certbot --nginx` **nu funcționează aici.** Provocarea HTTP-01 are nevoie de
portul 80, iar Sentinel nu îl deține. TLS-ALPN-01 are nevoie de 443, la fel
ocupat. Rămân două căi, plus o rezervă.

Instalarea acceptă `--cert-mode`:

| Mod | Ce face | Când |
|---|---|---|
| `auto` *(implicit)* | Testează efectiv dacă serviciul de pe `:80` poate servi provocarea ACME. Dacă da, emite certificatul; dacă nu, rămâne pe self-signed și îți spune exact ce să adaugi | Începe cu asta |
| `webroot` | Presupune că poate și încearcă direct | După ce ai adăugat blocul de mai jos |
| `dns` | Provocare DNS-01 | Nu vrei să atingi serviciul de pe `:80` |
| `selfsigned` | Sare peste emitere | Test intern, fără domeniu public |
| `none` | Folosește un certificat pe care l-ai emis deja | Ai rulat certbot manual |

`auto` **testează înainte să încerce** — scrie un token, îl cere din exterior
prin HTTP, îl șterge. Fără verificarea asta, certbot ar eșua după o încercare de
autorizare, ceea ce consumă din rate-limit-ul Let's Encrypt și, în varianta
naivă, ar declanșa rollback pentru ceva reparabil în cinci minute.

**Varianta A — lași serviciul de pe :80 să servească provocarea.** O singură
adăugare în configurația *acelui* serviciu:

```nginx
# în vhost-ul care deține :80, pentru sentinel.exemplu.ro
location ^~ /.well-known/acme-challenge/ {
    root /var/lib/letsencrypt;
    default_type "text/plain";
    allow all;
}
```

Apache:
```apache
Alias /.well-known/acme-challenge/ /var/lib/letsencrypt/.well-known/acme-challenge/
<Directory "/var/lib/letsencrypt/.well-known/acme-challenge/">
    Require all granted
</Directory>
```

Apoi reîncarcă acel serviciu și rulează instalarea cu `--cert-mode webroot`.

Sentinel **nu** face asta automat, deși ar putea: configurația aceea e a ta, iar
un agent de monitorizare care editează vhost-ul aplicației tale de producție ca
efect secundar al instalării e exact dauna colaterală pe care restul acestui
installer o evită.

**Varianta B — DNS-01, fără să atingi nimic.** Nu are nevoie de niciun port:

```bash
sudo dnf install python3-certbot-dns-cloudflare   # sau plugin-ul registrarului tău
sudo certbot certonly --dns-cloudflare -d sentinel.exemplu.ro     --agree-tos -m tu@exemplu.ro --non-interactive
```

Apoi instalează cu `--cert-mode none` — Sentinel găsește certificatul și îl
folosește.

**Dacă niciuna nu e gata la momentul deploy-ului:** instalarea reușește oricum,
cu certificat self-signed. Dashboard-ul funcționează, browserul avertizează, și
poți relua doar pasul de certificat mai târziu:

```bash
sudo /opt/sentinel/deploy/install.sh --domain sentinel.exemplu.ro     --web-port 8443 --cert-mode webroot --from-step 33
```

### 2.2 Portul trebuie deschis în firewall-ul providerului

nftables pe această gazdă e deny-lister cu `policy accept`, deci **nu** blochează
portul 8443. Dar un security group de cloud sau un firewall de la provider o
face. Deschide-l înainte de deploy, altfel verificarea externă din smoke-test
eșuează deși Sentinel funcționează perfect.

Verifică din exterior:

```bash
curl -sk -o /dev/null -w '%{http_code}
' https://sentinel.exemplu.ro:8443/healthz
```

2. **Un bot Telegram nou.** Scrie-i lui [@BotFather](https://t.me/BotFather):
   ```
   /newbot
   ```
   Alege un nume și un username. Primești un token de forma
   `1234567890:AAG...`. **Creează un bot nou, dedicat** — nu refolosi unul care
   duce deja alte notificări; amestecarea alertelor de rutină cu cele de
   securitate este exact modul în care alertele de securitate ajung să nu mai
   fie citite.

   Apoi ia-ți chat id-ul numeric de la [@userinfobot](https://t.me/userinfobot).
   Nu username-ul — id-ul numeric.

3. **O cheie API Anthropic** (`sk-ant-...`), din consola Anthropic.
   **Pune o limită de cheltuială pe cheie acolo.** Plafonul din `sentinel.yaml`
   e prima linie de apărare, nu singura.

   Fără cheie, Sentinel rulează determinist: detecția, blocarea, alertarea și
   scanarea funcționează în continuare; mesajele sunt marcate
   „(analiză AI indisponibilă)".

### 2.3 Pregătire anti-lockout — nu sări peste

Înainte de instalare:

1. **Deschide o a doua sesiune SSH** și las-o deschisă. Ideal de pe altă rețea
   (hotspot mobil).
2. **Testează accesul la consola VPS-ului** de la provider. Testează-l efectiv,
   nu presupune că funcționează.
3. Memorează ieșirile de urgență:
   ```bash
   touch /etc/sentinel/PANIC    # watchdog-ul golește blocklist-ul în ≤60s
   reboot                        # blocurile nu se persistă niciodată
   ```

Sentinel folosește `policy accept` pe lanțul nftables. Este un **deny-lister**,
nu un firewall: nu te poate bloca prin eșec sau prin configurare greșită — doar
blocându-te explicit. Asta elimină majoritatea riscului de lockout din start.

---

## 3. Instalare

### Pasul 1 — Pregătește secretele local

Din Git Bash sau WSL, în directorul proiectului:

```bash
./scripts/secrets-init.sh
```

Valorile se citesc mascat, nu apar pe ecran și nu intră în istoricul
shell-ului. Se scriu în `secrets/.env.local`, care este gitignored și exclus din
arhiva de deploy. Ajung pe server **doar prin stdin-ul conexiunii SSH** —
niciodată ca argument de linie de comandă, unde `ps` pe server le-ar arăta.

Parola bazei de date se generează automat; nu trebuie să o inventezi sau să o
vezi vreodată.

### Pasul 2 — Verificare fără modificări

```bash
./scripts/deploy.sh --host 203.0.113.10 --user deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro \n    --web-port 8443 --dry-run
```

Rulează **doar** preflight-ul. Nu modifică absolut nimic pe server.

Citește rezultatul. Eșecurile blocante trebuie rezolvate; avertismentele sunt
informative. Cele mai frecvente:

| Mesaj | Ce înseamnă |
|---|---|
| `MemAvailable is N MB` sub 2500 | Suricata va fi sărită. Mod log-only, în continuare bun |
| `port 80 is in use` | Altceva ascultă acolo. Află ce cu `ss -tlnp` înainte să presupui că poți lua portul |
| `DOMAIN does not resolve` | Creează înregistrarea A și așteaptă propagarea |
| `services … no longer running` | Instalarea a oprit ceva. Rollback automat. Compară cu `baseline-services.txt` înainte să reîncerci |
| `CRLF line endings found` | Repo clonat pe Windows fără `.gitattributes` aplicat. Re-clonează |

### Pasul 3 — Instalarea propriu-zisă

```bash
./scripts/deploy.sh --host 203.0.113.10 --user deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

Sau, în modul `shared`, dacă nginx deține deja 80/443:

```bash
./scripts/deploy.sh --host 203.0.113.10 --user deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --nginx-mode shared
```

Din PowerShell, echivalent:

```powershell
.\scripts\deploy.ps1 -HostName 203.0.113.10 -User deploy -Key "$HOME\.ssh\sentinel_deploy" -Domain sentinel.exemplu.ro -NginxMode shared
```

Parametrul se numește `-HostName`, nu `-Host`: PowerShell rezervă `$Host` pentru
obiectul consolei. Aliasurile `-SshHost`, `-Server` și `-H` funcționează, pentru
că sunt ce încearcă toată lumea prima dată.

`deploy.ps1` rulează pe **Windows PowerShell 5.1**, cel livrat cu Windows — nu-ți
trebuie `pwsh` 7 instalat. Ăsta e singurul motiv pentru care scriptul există; dacă
ar cere 7, ai putea la fel de bine folosi Git Bash. Două teste păzesc asta:
`tests/security/test_no_shell.py` respinge sintaxa care parsează doar pe 7 (`?.`,
`??`, string-uri cu ghilimele imbricate în `$()`) și cere BOM UTF-8, fără care 5.1
citește fișierul ca ANSI și scrie diacriticele greșit.

Scriptul îți reamintește să ai a doua sesiune SSH deschisă și îți cere
confirmarea. Apoi rulează, numerotat pe pași, 10–20 de minute pe un host curat.

Instalarea se termină cu:
1. o comparație cu baseline-ul preluat la preflight — dacă un serviciu care
   rula s-a oprit, rollback automat;
2. **un mesaj de test pe Telegram.** Primirea lui *este* dovada că tot lanțul
   funcționează: config încărcat, secrete citite, rețea, token valid, chat id
   corect. Un log verde de instalare dovedește mult mai puțin.

### Pasul 4 — Verificare

```bash
./scripts/smoke-test.sh --host 203.0.113.10 --user deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

Verifică serviciile, baza de date, tabela nftables, dashboard-ul, headerele de
securitate, permisiunile pe `secrets.env`, resursele — și, la final, că nimic
din ce rula înainte nu s-a oprit.

### Pasul 5 — Cont admin și 2FA

Dacă instalarea nu a creat contul, creează-l:

```bash
ssh deploy@203.0.113.10 'sudo sentinel web --create-admin'
```

Ți se cer un nume de utilizator și o parolă (minim 12 caractere), apoi se
afișează codul QR pentru TOTP. **Se afișează o singură dată** — secretul este
stocat criptat în baza de date, deci nu poate fi reafișat.

Scanează-l imediat cu Google Authenticator, Aegis, 1Password sau echivalent.
Comanda cere apoi un cod ca să *confirme* înrolarea: fără pasul ăsta, o scanare
întreruptă ar lăsa un cont care cere un al doilea factor pe care nu îl are
nimeni — blocat, fără cale de intrare.

#### Administrarea conturilor

Se face pe server, nu din interfață. Un dashboard care își poate schimba propriile
roluri sau parole transformă o compromitere de interfață într-o preluare de
control: un atacator cu o sesiune s-ar promova la `owner`.

```bash
sudo sentinel web --list-users
sudo sentinel web --create-admin --username <user> --role operator
sudo sentinel web --set-password --username <user>     # revocă și sesiunile
sudo sentinel web --enroll-totp --username <user>      # telefon pierdut
sudo sentinel web --revoke-sessions --username <user>
sudo sentinel web --unlock --username <user>           # după 5 încercări eșuate
```

Roluri: `owner` (tot), `operator` (blocare, deblocare, scanare — fără aplicare de
patch-uri, fără config), `viewer` (doar citire).

---

## 4. După instalare

### 4.1 Revizuiește inventarul

```bash
ssh deploy@203.0.113.10 'sudo cat /etc/sentinel/inventory.yaml'
```

Descoperirea **propune**; tu confirmi. Două câmpuri contează:

- **`protected: true`** — niciun plan de patch automat nu va fi generat vreodată
  pentru acest asset. Deja setat pe componentele Sentinel. **Pune-l pe orice
  altceva nu vrei să fie atins automat** — un stack livrat de altcineva, o bază
  de date critică. Adaugă și căile lui în `patch.extra_protected_paths`.
- **`confirmed_by_operator: true`** — necesar înainte ca Sentinel să scaneze
  activ (DAST) un asset. Faptul că descoperirea a găsit un serviciu nu este o
  autorizație să-l atace: aia e decizia ta, și trebuie să fie, pentru că
  scanarea a ceva ce nu-ți aparține este o problemă juridică, nu tehnică.

### 4.2 Primele 72 de ore — modul „observă"

**Auto-block este dezactivat la instalare. Lasă-l așa 72 de ore.**

În acest timp primești pe Telegram exact ce *ar fi* fost blocat, cu buton
„🚫 Blochează acum". Folosește perioada ca să găsești fals-pozitivele reale:

- monitoare de uptime externe
- validarea Let's Encrypt (`/.well-known/acme-challenge/`)
- crawlere de motoare de căutare
- edge-uri CDN
- IP-ul tău mobil
- intervale NAT de birou — un singur actor rău blochează toată clădirea

Adaugă ce găsești în `allowlist` din `inventory.yaml` sau în
`response.extra_allowlist`.

După 72 de ore liniștite:

```bash
ssh deploy@203.0.113.10 \
  'sudo sed -i "s/enabled: false/enabled: true/" /etc/sentinel/sentinel.yaml && \
   sudo systemctl restart sentinel-detect'
```

### 4.3 Ce e accesibil public, și ce nu

Doar `https://sentinel.exemplu.ro:8443` ajunge la dashboard. Orice altceva pe
acel port — un IP brut, un Host greșit, un scanner care sondează adresa direct —
primește 444 (conexiune închisă fără răspuns), din `sentinel-default-deny.conf`.

Catch-all-ul e limitat la portul lui Sentinel. Nu revendică `default_server` pe
80 sau 443: acelea sunt ale serviciilor tale, iar preluarea default-ului lor ar
strica-le vhost-ul sau ar face nginx să refuze să pornească.

Verifică:

```bash
# IP brut pe portul Sentinel: aștept 000 (conexiune închisă)
curl -sk -o /dev/null -w '%{http_code}
' https://203.0.113.10:8443/
# Numele corect: aștept 200 sau 302
curl -s  -o /dev/null -w '%{http_code}
' https://sentinel.exemplu.ro:8443/
```

Primul returnează `000` pentru că nginx a închis conexiunea — corect. Dacă
returnează `200`, catch-all-ul nu s-a instalat (probabil pentru că un alt vhost
revendica deja `default_server`) și pagina de login e servită pe IP brut.

**Numele nu e secret.** `sentinel.exemplu.ro` apare în logurile Certificate
Transparency din clipa emiterii certificatului — oricine poate căuta `exemplu.ro`
pe crt.sh. Nu te baza pe obscuritatea numelui; bazează-te pe straturile din
[SECURITATE.md](SECURITATE.md) §4.

### 4.4 Recomandare: restrânge dashboard-ul la IP-urile tale

Cea mai ieftină întărire disponibilă pentru un dashboard de securitate public,
și nu costă nimic operațional — Telegram rămâne canalul „de oriunde" și nu
depinde de dashboard.

În `/etc/nginx/conf.d/sentinel.conf`, decomentează și completează:

```nginx
allow 203.0.113.0/24;      # birou
allow 198.51.100.42/32;    # acasă
deny  all;
```

Apoi `nginx -t && systemctl reload nginx`.

---

## 5. Operare zilnică

```bash
# Loguri, formatate lizibil
./scripts/tail-logs.sh --host 203.0.113.10 --user deploy --key ~/.ssh/sentinel_deploy

# Doar un serviciu, doar erori
./scripts/tail-logs.sh --host ... --unit sentinel-detect --errors

# Starea configurației
ssh deploy@203.0.113.10 'sudo sentinel config-check -v'
```

Pe Telegram: `/status`, `/incidents`, `/blocklist`, `/vulns`, `/health`,
`/budget`. Lista completă în [TELEGRAM.md](TELEGRAM.md).

---

## 6. Când ceva merge prost

### 6.1 Instalarea a eșuat la un pas

Instalatorul e numerotat pe pași, idempotent și reluabil. Fiecare pas are un
marker în `/var/lib/sentinel/.install-state/`.

```bash
# Repari cauza, apoi continui de la pasul respectiv
./scripts/deploy.sh --host ... --user ... --key ... --from-step 22

# Sau reiei un singur pas
ssh ... 'sudo /opt/sentinel/deploy/install.sh --force-step 29'
```

### 6.2 M-am blocat singur

**Ordine, de la cel mai rapid:**

1. Din a doua sesiune SSH (sau consola provider):
   ```bash
   sudo touch /etc/sentinel/PANIC
   ```
   Watchdog-ul golește blocklist-ul în ≤60 secunde. Rulează ca root, la fiecare
   minut, independent de baza de date, de executor și de web — exact pentru
   situația asta.

2. Din Telegram: `/panic` (dublă confirmare).

3. Reboot. Blocurile nu se persistă niciodată în nftables.

4. Din consola provider:
   ```bash
   nft delete table inet sentinel
   ```

### 6.3 Rollback complet

```bash
./scripts/deploy.sh --host 203.0.113.10 --user deploy \
    --key ~/.ssh/sentinel_deploy --rollback
```

Oprește și dezactivează toate unitățile, șterge tabela nftables (deci toate
blocurile), restaurează nginx și `/etc/sentinel` din snapshot-ul pre-deploy,
verifică că nimic din ce rula înainte de instalare nu a rămas oprit.

**Nu** dezinstalează pachetele — a face downgrade la nginx sau PostgreSQL ca să
anulezi o instalare e mult mai periculos decât a le lăsa. **Nu** șterge baza de
date decât cu `--purge`; acolo e tot istoricul de securitate.

### 6.4 Un serviciu care rula s-a oprit

Dacă smoke-test-ul sau instalarea semnalează asta:

```bash
ssh deploy@203.0.113.10
systemctl --failed
diff <(systemctl list-units --type=service --state=running --no-legend --plain \n        | awk '{print $1}' | sort) \n     /var/lib/sentinel/.install-state/baseline-services.txt
free -h                    # cauza cea mai probabilă
```

Cauza cea mai probabilă este presiunea de memorie: OOM killer-ul alege cel mai
mare proces. Verifică `MemAvailable`. Dacă e sub 500 MB, oprește temporar
scanările (`sudo systemctl stop sentinel-scan.timer`) și adaugă swap. Dacă tot
nu se rezolvă, fă rollback — Sentinel nu merită o întrerupere a producției.

---

## 7. Upgrade

```bash
git pull
./scripts/deploy.sh --host ... --user ... --key ... --domain ...
```

Instalarea e idempotentă; pașii deja făcuți sunt sărite, codul se
reinstalează, migrațiile noi se aplică.

**Migrațiile sunt forward-only.** Nu există down-migration — inversarea unei
schimbări de schemă pe o bază de date de securitate live este o fantezie, iar
pretinzând altceva încurajezi pe cineva să încerce în timpul unui incident.
Calea de întoarcere este snapshot-ul pre-deploy.

Verifică înainte dacă release-ul aduce migrații noi:

```bash
git diff --name-only HEAD@{1} -- sentinel/db/migrations/
```

---

## 8. Referință rapidă

| Ce | Unde |
|---|---|
| Configurație | `/etc/sentinel/sentinel.yaml` |
| Inventar | `/etc/sentinel/inventory.yaml` |
| Praguri detecție | `/etc/sentinel/detection.yaml` |
| Notificări | `/etc/sentinel/notifications.yaml` |
| Secrete | `/etc/sentinel/secrets.env` (0640 root:sentinel) |
| Cod | `/opt/sentinel/lib/sentinel/` |
| Executor (root) | `/opt/sentinel/libexec/sentinel_executor.py` |
| Workspace Claude | `/opt/sentinel/claude-workspace/` |
| Backup-uri | `/var/backups/sentinel/` |
| Snapshot pre-deploy | `/var/backups/sentinel/predeploy-latest` |
| Loguri | `journalctl -u 'sentinel-*'` |
| Fișier PANIC | `/etc/sentinel/PANIC` |

```bash
systemctl status 'sentinel-*'              # starea tuturor unităților
sudo nft list table inet sentinel          # ce e blocat acum
sudo sentinel config-check -v              # config + secrete
sudo sentinel migrate --dry-run            # migrații în așteptare
systemd-analyze security 'sentinel-*'      # scor de hardening (țintă ≤3.0)
```

---

## 9. Stadiul livrării

Livrare pe faze. Faza curentă: **P0 — schelet, skill, agenți, tooling de
deployment, documentație.**

Ce funcționează acum: preflight, instalare, PostgreSQL + schema completă,
tabela nftables, unitățile systemd, nginx + Let's Encrypt, workspace-ul Claude
cu skill-ul și agenții, validatorul de planuri de patch, rollback.

Ce urmează, în ordine: **P1** fundația pe server cu login TOTP · **P2** inventar
și disponibilitate · **P3** ingestie · **P4** detecție + Telegram · **P5**
răspuns și blocare · apoi P6–P10 (autonomie, scanare, AI, patching, analytics).

Detalii în [ARHITECTURA.md](ARHITECTURA.md).
