# Ghid de instalare — Sentinel

Instalarea agentului de cybersecurity Sentinel pe un server Linux. Exemplele
folosesc gazda `203.0.113.10` cu domeniul `sentinel.exemplu.ro`.

Sentinel este de sine stătător: nu depinde de niciun SIEM, de niciun agent
extern și de niciun serviciu în afara gazdei pe care rulează.

**Ai nevoie de o singură comandă.** [§3.1](#31-calea-recomandată--wizard-ul) e
tot ce trebuie citit ca să instalezi; restul documentului explică deciziile pe
care wizard-ul ți le pune și ce faci când ceva nu merge.

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

Porturi noi ocupate: **8443** (nginx, public — configurabil), **8787** legat pe
`127.0.0.1`, și portul PostgreSQL: **5432 dacă e liber**, altfel primul port
liber de deasupra lui. Instalatorul îl citește de la cluster după instalare și
îl scrie în `sentinel.yaml` — nu îl presupune. Motivul e o gazdă reală pe care
`0.0.0.0:5432` era deja ținut de un PostgreSQL dintr-un container cu
`network_mode: host`: presupunerea ar fi legat Sentinel la baza altcuiva.
Porturile 80 și 443 rămân ale serviciilor tale; detaliile mai jos.

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
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --nginx-mode shared

# dedicated — altceva (Apache, Caddy, un container) deține 80/443
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

`--user sentinel-deploy` e **implicitul** din 25 august 2026 și e scris mai sus
doar ca să se vadă; îl dai explicit numai dacă ai instalat cu alt
`DEPLOY_ACCOUNT`. Motivul e în `docs/ISTORIC-SESIUNI.md`: `auid` e uid-ul de
LOGARE și supraviețuiește lui `sudo`, deci un deploy rulat sub contul tău își
scrie cele ~405 000 de comenzi sub numele tău, unde filtrul de istoric nu le
poate deosebi de munca ta.

`--key ~/.ssh/sentinel_deploy` e **tot implicit**, din același motiv și în
aceeași măsură: contul ăla autorizează cheia asta și nicio alta, deci un
implicit de cont fără implicitul de cheie e `Permission denied (publickey)` la
prima conexiune — iar reflexul care rezolvă asta e `--user` înapoi pe contul
tău, adică filtrul inert la loc. Dacă fișierul nu există, scriptul spune și
merge mai departe: un agent ssh sau un `IdentityFile` din `~/.ssh/config` sunt
la fel de legitime și nu se văd de aici.

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
| `5432/tcp` *(sau primul liber)* | `127.0.0.1` | PostgreSQL. Fixabil cu `--db-port` |

**80 și 443 rămân ale serviciilor tale.** Sentinel nu le atinge: un agent de
monitorizare care înlocuiește serviciul pe care îl monitorizează și-a inversat
scopul. Trei consecințe:

1. **URL-ul conține portul:** `https://sentinel.exemplu.ro:8443`
2. **Nu există redirect de la HTTP.** O cerere pe `http://sentinel.exemplu.ro`
   ajunge la serviciul care deține `:80`, nu la Sentinel.
3. **Certificatul nu poate veni din provocarea HTTP-01 a lui certbot**, care are
   nevoie de `:80`. Vezi §2.3.

Preflight verifică întâi că portul cerut e liber și raportează ce deține 80/443
— fără să atingă nimic.

---

## 2. Înainte de a începe

### 2.1 Cerințe pe server

| Cerință | Valoare | Ce se întâmplă dacă nu |
|---|---|---|
| OS | familia **RHEL** (AlmaLinux, Rocky, RHEL, CentOS Stream, Fedora) sau familia **Debian** (Debian, Ubuntu) | Preflight refuză pe nume — vezi mai jos |
| systemd | obligatoriu | Preflight oprește instalarea |
| Python | ≥ 3.10 | Instalarea îl aduce din depozitele distribuției |
| RAM disponibil | ≥ 2,5 GB | Sub 2,5 GB → Suricata e sărită (mod log-only, în continuare util). **Sub 1,5 GB → abort**: OOM killer-ul alege cel mai mare proces, de obicei aplicația ta |
| Disc liber | ≥ 10 GB pe `/`, ≥ 8 GB pe `/var` | Preflight oprește |
| Portul public al panoului | liber (implicit 8443) | Preflight oprește |
| `firewalld` | inactiv | Preflight oprește (poți forța cu `--allow-firewalld`) |
| Servicii existente | funcționale | Preflight le înregistrează; instalarea face rollback automat dacă vreunul se oprește |
| sudo | funcțional | Ți se cere parola o dată |

**O distribuție nesuportată e refuzată, nu instalată pe jumătate.** O mașină
care *pare* protejată și nu e, e mai rea decât una la care instalarea a eșuat
vizibil. Tot ce diferă între cele două familii — managerul de pachete,
inițializarea PostgreSQL, calea configurațiilor, fișierul de opțiuni al
Suricatei, SELinux față de AppArmor — stă într-un singur loc,
[`deploy/lib/distro.sh`](../deploy/lib/distro.sh), iar un test verifică mecanic
că nu a rămas niciun `dnf` sau `apt-get` direct în installer.

**Scanarea de vulnerabilități de sistem nu e la fel de bogată pe cele două
familii, și trebuie să știi asta înainte de deploy.** Pe RHEL, `dnf updateinfo`
dă CVE, severitate și versiunea care repară, direct din avizele furnizorului. Pe
Debian și Ubuntu, `apt` nu poartă aceste metadate: Sentinel raportează
**pachetele cu o actualizare care așteaptă în depozitul de securitate**, fără CVE
și fără severitate. E o listă acționabilă, dar e mai puțin decât pe RHEL, fiecare
constatare o spune în propria descriere, și niciun plan de patch nu se generează
din ele. Detaliile și ce ar fi nevoie ca să se închidă golul:
[ARHITECTURA.md §3.16](ARHITECTURA.md).

Familia se scrie în `sentinel.yaml` ca `platform.family`, o singură dată, de
installer. **Pe o gazdă instalată înainte de cheia asta nu apare de la sine** —
`install_config` nu suprascrie o configurație vie, scrie `sentinel.yaml.new` —
iar implicitul e `rhel`, deci comportamentul rămâne neschimbat. Dacă gazda aia e
Debian sau Ubuntu, secțiunea trebuie adăugată de mână, altfel rulează `dnf`:

```yaml
platform:
  family: rhel      # sau: debian
```

**Python 3.10 e pragul** fiindcă îl are deja fiecare țintă suportată, fără
depozit terț: Ubuntu 22.04 are 3.10, Debian 12 are 3.11, AlmaLinux 9 are
3.11/3.12 în AppStream, Ubuntu 24.04 are 3.12.

Verifică rapid, înainte de orice:

```bash
ssh deploy@203.0.113.10 'cat /etc/os-release | head -2; free -h; df -h /; systemctl is-active firewalld'
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

### 2.3 Certificatul — partea care necesită o decizie

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
sudo dnf install python3-certbot-dns-cloudflare      # RHEL, Alma, Rocky, Fedora
sudo apt-get install python3-certbot-dns-cloudflare  # Debian, Ubuntu
# sau plugin-ul registrarului tău
sudo certbot certonly --dns-cloudflare -d sentinel.exemplu.ro \
    --agree-tos -m tu@exemplu.ro --non-interactive
```

Apoi instalează cu `--cert-mode none` — Sentinel găsește certificatul și îl
folosește.

**Dacă niciuna nu e gata la momentul deploy-ului:** instalarea reușește oricum,
cu certificat self-signed. Dashboard-ul funcționează, browserul avertizează, și
poți relua doar pasul de certificat mai târziu:

```bash
sudo /opt/sentinel/deploy/install.sh --domain sentinel.exemplu.ro \
    --web-port 8443 --cert-mode webroot --from-step 33
```

### 2.4 Portul trebuie deschis în firewall-ul providerului

nftables pe această gazdă e deny-lister cu `policy accept`, deci **nu** blochează
portul 8443. Dar un security group de cloud sau un firewall de la provider o
face. Deschide-l înainte de deploy, altfel verificarea externă din smoke-test
eșuează deși Sentinel funcționează perfect.

Verifică din exterior:

```bash
curl -sk -o /dev/null -w '%{http_code}
' https://sentinel.exemplu.ro:8443/healthz
```

### 2.5 Pregătire anti-lockout — nu sări peste

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

Două căi, același rezultat. **Wizard-ul (§3.1) e cel recomandat** — pune
întrebările, verifică ce poate verifica singur și cheamă exact aceleași
scripturi. Calea manuală (§3.2) rămâne documentată pentru automatizare și
pentru cazurile în care vrei să vezi fiecare parametru pe linia de comandă.

### 3.1 Calea recomandată — wizard-ul

```bash
git clone https://github.com/dragosnimu/sentinel.git
cd sentinel
./scripts/wizard.sh
```

Wizard-ul își dă seama singur unde rulează. Pe laptopul tău întreabă o țintă și
instalează prin SSH; pe server sare peste jumătatea de SSH și instalează local.
Nu ai de ales modul — e dedus din context și ți se arată.

**Cele trei reguli pe care le respectă**, și de ce fiecare contează:

1. **Nimic nu se ghicește tăcut.** Unde există un default rezonabil, e afișat
   între paranteze și îl poți accepta cu Enter; unde nu există, întreabă. Un
   installer care alege singur portul, utilizatorul sau modul nginx te lasă cu
   o instalare pe care nu o poți explica peste trei luni.
2. **Secretele nu ajung în tabela de procese.** Tokenul de bot și cheia API se
   citesc cu ecoul terminalului stins și călătoresc pe stdin — niciodată ca
   argument, fiindcă `ps` arată argumentele oricărui proces către orice cont de
   pe gazdă.
3. **Nimic nu se modifică înainte de rezumat.** Tot ce se întâmplă până la
   confirmare sunt întrebări și verificări read-only. Un installer care a
   editat deja nginx în momentul în care te întreabă dacă e în regulă te minte.

**Ce te întreabă**, în ordine:

| Secțiune | Ce | Obligatoriu |
|---|---|---|
| 1. Unde instalăm | aici sau alt server; adresă, utilizator sudo, port și cheie SSH | da (în modul SSH) |
| 2. Verific serverul | *nu întreabă nimic* — detectează distribuția, RAM, disc, cine deține 80/443, dacă portul cerut e liber | — |
| 3. Interfața web | domeniul panoului; mod nginx `shared` sau `dedicated`; portul public | domeniul |
| 4. Siguranță | adresa ta publică, cea de pe care administrezi — intră în lista never-block | da |
| 5. Telegram | token bot + chat id | opțional |
| 6. Analiză AI | cheie API Anthropic | opțional |
| 7. Opțiuni | Suricata da/nu | are default |

Modul nginx nu ți se oferă la întâmplare: dacă verificarea de la pasul 2 a găsit
nginx pe 80/443, `shared` e prima opțiune; dacă acolo e altceva — Apache, Caddy,
un container — opțiunea nici nu apare, fiindcă un vhost nginx nu ajută când
nginx nu deține portul.

**Adresa ta publică** e propusă automat din conexiunea curentă, dar confirm-o:
e singurul lucru care garantează că nu te poți bloca singur afară. Verificarea
o poți face oricând cu `curl -s https://ifconfig.me`.

**Modurile de rulare:**

```bash
./scripts/wizard.sh                    # interactiv
./scripts/wizard.sh --dry-run          # întreabă și verifică, nu modifică nimic
./scripts/wizard.sh --save prod.conf   # interactiv, ține minte răspunsurile
./scripts/wizard.sh --config prod.conf # neasistat — al doilea server, sau o refacere
./scripts/wizard.sh --yes              # sare peste confirmarea finală
./scripts/wizard.sh --help
```

**Rulează întâi `--dry-run`.** Costă două minute și îți arată exact ce va găsi
instalarea: distribuția detectată, memoria, discul, ce deține 80/443, dacă
portul panoului e liber. Nu atinge nimic.

Fișierul salvat cu `--save` **conține tokenul de bot și cheia API**, deci se
scrie cu `umask 077` și `chmod 0600`, și o spune în prima lui linie. Tratează-l
ca pe un secret: nu îl pune în repo, nu îl trimite pe chat.

**Ce nu face wizard-ul:** nu creează înregistrarea DNS, nu deschide portul în
firewall-ul providerului și nu obține certificatul dacă nici modul `auto` nu
poate. Astea rămân în §2 — le verifică și îți spune, dar nu le poate face în
locul tău.

La final îți afișează URL-ul panoului, comanda de creare a contului admin și
ieșirile de urgență.

### 3.2 Calea manuală — `deploy.sh`

Aceiași pași, executați de tine. Utilă pentru CI, pentru un runbook propriu, sau
când vrei să vezi fiecare parametru explicit.

#### Pasul 1 — Pregătește secretele local

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

#### Pasul 2 — Verificare fără modificări

```bash
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro \
    --web-port 8443 --dry-run
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

#### Pasul 3 — Instalarea propriu-zisă

```bash
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

Sau, în modul `shared`, dacă nginx deține deja 80/443:

```bash
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --nginx-mode shared
```

Din PowerShell, echivalent:

```powershell
.\scripts\deploy.ps1 -HostName 203.0.113.10 -User sentinel-deploy -Key "$HOME\.ssh\sentinel_deploy" -Domain sentinel.exemplu.ro -NginxMode shared
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

   Pasul 39 raportează ce a răspuns Telegram, nu ce a încercat el să facă:
   verde doar dacă API-ul a întors un `message_id` pentru fiecare chat permis,
   albastru dacă Telegram e dezactivat din config (nu s-a trimis nimic, și nici
   nu era ce), galben în rest — inclusiv dacă nu se întoarce în 60 de secunde.
   Galben înseamnă „canalul de alertare NU e dovedit", nu „instalarea a picat".
   Îl poți relua oricând, singur:

   ```bash
   sudo /opt/sentinel/bin/sentinel telegram --send-test
   ```

### 3.3 Verificare

```bash
./scripts/smoke-test.sh --host 203.0.113.10 --user sentinel-deploy \
    --key ~/.ssh/sentinel_deploy --domain sentinel.exemplu.ro --web-port 8443
```

Verifică serviciile, baza de date, tabela nftables, dashboard-ul, headerele de
securitate, permisiunile pe `secrets.env`, resursele — și, la final, că nimic
din ce rula înainte nu s-a oprit.

### 3.4 Cont admin și 2FA

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
./scripts/tail-logs.sh --host 203.0.113.10 --user sentinel-deploy --key ~/.ssh/sentinel_deploy

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

# Sau reiei pași anume, chiar dacă sunt marcați ca făcuți
./scripts/deploy.sh --host ... --user ... --key ... --force-step 29
./scripts/deploy.sh --host ... --user ... --key ... --force-step 22,27
```

**Cele două flaguri nu fac același lucru, și diferența costă.**

| Flag | Ce face |
|---|---|
| `--from-step N` | Sare peste pașii de **sub** N. De la N în sus, un marker existent tot câștigă — deci **nu re-rulează** nimic deja făcut. E pentru reluarea unei instalări întrerupte |
| `--force-step L` | Șterge markerele pașilor din listă, ca să ruleze din nou. Un număr, sau o listă separată prin virgulă: `--force-step 22,27` |

Un `--from-step 22` pe o gazdă unde pasul 22 e deja marcat afișează
`(already done)` și trece mai departe. De la versiunea asta o spune în galben și
o rezumă la final, cu numerele care ar fi trebuit date lui `--force-step` — după
o rotire de parolă în care mesajul a trecut neobservat într-o ieșire de 100 de
linii, iar rularea s-a încheiat cu „installation finished".

Lista există pentru că **unii pași sunt o singură operație**: rotirea parolei
bazei cere 22 (`ALTER ROLE`) și 27 (`secrets.env`) în aceeași trecere, fiindcă
serviciile sunt repornite la sfârșitul ei. Procedura completă, cu felul în care
dovedești că s-a întâmplat, e în [OPERARE.md](OPERARE.md) §11.

Instalatorul refuză din start o listă care nu e formată din numere
(`--force-step 22,twenty-seven`), un pas care nu există (`--force-step 22,72`)
și un `--force-step` sub `--from-step`; iar la final se oprește dacă un pas
cerut nu a rulat efectiv. Nu poate reuși pe jumătate.

Dacă ai instalat cu wizard-ul, îl poți relua pur și simplu: pașii deja făcuți
sunt sărite. Ca să nu răspunzi din nou la toate întrebările, salvează-le de la
început cu `--save`:

```bash
./scripts/wizard.sh --save prod.conf     # prima dată
./scripts/wizard.sh --config prod.conf   # reluare, fără întrebări
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
./scripts/deploy.sh --host 203.0.113.10 --user sentinel-deploy \
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
diff <(systemctl list-units --type=service --state=running --no-legend --plain \
        | awk '{print $1}' | sort) \
     /var/lib/sentinel/.install-state/baseline-services.txt
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
./scripts/wizard.sh --config prod.conf        # dacă ai salvat răspunsurile
./scripts/deploy.sh --host ... --user ... --key ... --domain ...   # sau explicit
```

Instalarea e idempotentă; pașii deja făcuți sunt sărite, codul se
reinstalează, migrațiile noi se aplică.

**De pe 26 august 2026 un re-deploy durează cu ~3 minute mai mult.** Pasul 35
(Suricata) a intrat în `ALWAYS_STEPS`, deci rulează la fiecare trecere, nu doar
la prima instalare: altfel o reparație a felului în care e pornit demonul nu
ajunge niciodată pe o gazdă deja instalată. Costul e `suricata-update` plus
`suricata -T` peste tot setul de reguli — măsurat pe VM-ul de test (Ubuntu
24.04.4): 332 s cu pasul în listă, 148 s fără el, din care 132 s sunt
`suricata -T` singur. **IDS-ul nu se repornește** dacă procesul care rulează
poartă deja opțiunile scrise; în log apare `suricata already runs with these
options; not restarting it`.

**Migrațiile sunt forward-only.** Nu există down-migration — inversarea unei
schimbări de schemă pe o bază de date de securitate live este o fantezie, iar
pretinzând altceva încurajezi pe cineva să încerce în timpul unui incident.
Calea de întoarcere este snapshot-ul pre-deploy.

Verifică înainte dacă release-ul aduce migrații noi:

```bash
git diff --name-only HEAD@{1} -- sentinel/db/migrations/
```

### Identitatea instalării, la un upgrade

`instance_id` — valoarea după care un panou extern deosebește serverele — se
creează în `/etc/sentinel/instance_id`. **Deploy-ul obișnuit de mai sus o
asigură la fiecare rulare**, inclusiv pe o gazdă instalată înainte ca ea să
existe: apelul nu e supus marcajelor de pas, exact ca `resolve_config`, tocmai
fiindcă pasul 27 e marcat ca făcut din ziua instalării și nu e în
`ALWAYS_STEPS`. N-ai de făcut nimic special.

`--force-step 27` **nu** e calea pentru asta și nu o repară — pasul acela
rescrie `secrets.env`. Îl folosești doar în cazul rar în care fișierul există
dar nu e o identitate (octeți NUL după o cădere de curent, valoare pusă de
mână): instalatorul refuză deliberat să rescrie așa ceva, avertizează, iar tu
te uiți în el, îl ștergi și ceri pasul:

```bash
ssh <utilizator>@<gazdă> 'sudo od -c /etc/sentinel/instance_id'
./scripts/deploy.sh --host <gazdă> --user <utilizator> --force-step 27
```

Dovada că gazda are identitate e valoarea de pe disc, nu codul de ieșire al
deploy-ului:

```bash
ssh <utilizator>@<gazdă> 'sudo cat /etc/sentinel/instance_id'   # 32 hexa
ssh <utilizator>@<gazdă> 'sudo sentinel selfcheck --print | grep identity'
```

Generarea nu se repetă: pe o gazdă care are deja o identitate validă, deploy-ul
îi reafirmă drepturile și o lasă în pace (vezi OPERARE.md §12).

**La prima trecere vei primi o alertă critică despre `default`. Este așteptată.**
Din clipa în care gazda are identitate, beaconul trimite sub ea — o instanță pe
care martorul nu o cunoaște încă, deci o refuză cu 401. Iar instanța `default`,
sub care gazda bătea până atunci, nu mai primește nimic, și după 180 de secunde
plus latența cronului (până la 5 minute) martorul o declară tăcută: **🔴 default
— silent**, la 3–8 minute după deploy.

**Nu retragi `default` ca să eviți alerta.** Se poate, tehnic — martorul are
acum `SENTINEL_RETIRED_INSTANCES`, iar o identitate retrasă e refuzată cu 401
înainte de orice scriere, deci beaconul vechi nu-i mai poate recrea fișierul de
stare. Tocmai de-aia e periculos: `default` e găleata comună a **fiecărui**
server care nu trimite încă `X-Sentinel-Instance`. Retrasă prea devreme, ea
scoate din registru serverele alea — dispar de pe `/status`, de pe pagină și din
`/check`, fără nicio alertă, în timp ce martorul raportează „ok".

Deci: **așteaptă exact o alertă, și tratează orice a doua ca reală.** Un operator
căruia i se promite că nu va primi niciuna tratează alerta primită ca pe un
incident, iar unul care nu e prevenit deloc învață că alertele martorului sunt
zgomot — amândouă mai scumpe decât o propoziție.

Pașii de mai jos o fac cât mai scurtă:

1. **înainte de deploy**, citești identitatea dacă gazda are deja una
   (comanda de mai sus). Dacă nu are, faci deploy-ul, apoi o citești — între
   deploy și pasul 2 martorul nu primește semnale de la gazda asta;
2. adaugi identitatea și cheia ei în `SENTINEL_INSTANCE_SECRETS` la martor;
3. confirmi în jurnal că semnalul e acceptat:
   `journalctl -u sentinel-beacon -n 20` — un `beacon rejected` cu `status 401`
   înseamnă că pasul 2 nu a ajuns unde credeai;
4. **retragi `default` doar după ce ai dovedit că nimeni nu mai bate sub ea.**
   Dovada nu e „am actualizat toate gazdele", e citită din martor: fiecare server
   real apare în `/status` sub `instance_id`-ul lui, iar `default` apare cu
   **`"status": "silent"`**.

   ```bash
   curl -s https://<domeniul-martorului>/api/sentinel/status
   ```

   `silent` e verdictul pe care îl calculează martorul însuși (`aggregator/lib/verify.ts`),
   după ce trec trei intervale ratate — `max(interval_s, 30) * 3`, adică 180 de
   secunde la configurația implicită. **Un server care încă bate nu poate produce
   verdictul ăsta.**

   Nu te uita la `age_s` și nu-l compara între două interogări. O versiune
   anterioară a pasului ăstuia cerea exact asta — două interogări la 30 de
   secunde, cu `age_s` în creștere — și e nesigură: 30 de secunde e jumătate din
   intervalul implicit de bătaie, deci ambele probe pot cădea în același gol
   dintre două bătăi, iar `age_s` crește cu exact 30 ori de câte ori nicio bătaie
   nu nimerește fereastra. Măsurat: `age_s 15 → 45`, „a crescut", în timp ce
   serverul bătuse cu 15 secunde înainte de prima interogare și bătea din nou la
   15 secunde după a doua. Rândul de alături spunea `"status": "ok"`, dar pasul
   nu cerea nimănui să se uite acolo.

   Abia atunci adaugi `default` în `SENTINEL_RETIRED_INSTANCES` la martor și
   repornești aplicația — variabilele se citesc la pornire. Verifici prin efect:
   `default` dispare din `instances`, iar
   `/api/sentinel/status?instance=default` întoarce `503 unknown`.

   **Ștergerea `SENTINEL_BEACON_SECRET` nu e o retragere** și nici nu e posibilă
   pe găzduirea martorului (o variabilă nu se poate șterge și nu poate fi goală —
   măsurat, vezi `watcher/INCARCARE-HOSTINGER.md`). Chiar dacă ar fi: martorul
   consideră membră orice instanță al cărei fișier de stare se identifică singur,
   indiferent de chei (`aggregator/lib/store.ts`, sursa 1), deci `default` ar rămâne
   pe hartă și ar alarma critic la fiecare 4 ore.

   **Ștergerea fișierului ei de stare** — procedura dinainte — nu e nici ea o
   retragere: nu revocă cheia. Cine deține `SENTINEL_BEACON_SECRET` poate
   continua să scrie sub `default`, iar fișierul reapare la primul semnal.
   Retragerea taie ambele: identitatea iese din registru **și** cheia ei nu mai
   autentifică. Cheia rămâne totuși scrisă pe gazda dezafectată — **rotește-o**.

Cât timp gazda **nu** are identitate, beaconul nu trimite nimic și spune de ce
în jurnal (`beacon has no instance identity`). Asta e intenționat: un semnal
fără nume ar ateriza în găleata comună `default`, amestecând istoria gazdei
ăsteia cu a oricărei alte gazde neidentificate — exact lucrul pentru care există
identitatea. De aceea deploy-ul asigură fișierul înainte să repornească
serviciile, și de aceea refuză să repornească beaconul dacă tot nu poate: un
proces vechi care încă bate e mai bun decât unul nou care tace.

---

## 8. Referință rapidă

| Ce | Unde |
|---|---|
| Configurație | `/etc/sentinel/sentinel.yaml` |
| Inventar | `/etc/sentinel/inventory.yaml` |
| Praguri detecție | `/etc/sentinel/detection.yaml` |
| Notificări | `/etc/sentinel/notifications.yaml` |
| Secrete | `/etc/sentinel/secrets.env` (0640 root:sentinel) |
| Identitatea instalării | `/etc/sentinel/instance_id` (0640 root:sentinel) — OPERARE.md §12 |
| Cod | `/opt/sentinel/lib/sentinel/` |
| Executor (root) | `/opt/sentinel/libexec/sentinel_executor.py` |
| Workspace Claude | `/opt/sentinel/claude-workspace/` |
| Backup-uri | `/var/backups/sentinel/` |
| Snapshot pre-deploy | `/var/backups/sentinel/predeploy-latest` |
| Loguri | `journalctl -u 'sentinel-*'` |
| Fișier PANIC | `/etc/sentinel/PANIC` |
| Wizard de instalare | `./scripts/wizard.sh` (în repo) |
| Abstractizarea de distribuție | `deploy/lib/distro.sh` (în repo) |

```bash
systemctl status 'sentinel-*'              # starea tuturor unităților
sudo nft list table inet sentinel          # ce e blocat acum
sudo sentinel config-check -v              # config + secrete
sudo sentinel migrate --dry-run            # migrații în așteptare
systemd-analyze security 'sentinel-*'      # scor de hardening (țintă ≤3.0)
```

---

## 9. Stadiul livrării

Livrare pe faze, fiecare verificată pe un server real înainte de următoarea.
**P0–P9 sunt livrate.** 514 teste automate, dintre care 31 verifică faptul că
ceva periculos este *refuzat*, nu că ceva funcționează.

| Fază | Ce a adus |
|---|---|
| P0 | Schelet, schema planurilor de patch + validator, skill, tooling de deployment |
| P1 | Dashboard HTTPS, Argon2id + TOTP, sesiuni, watchdog anti-lockout |
| P2 | Inventar de assets, probe de disponibilitate, istoric |
| P3 | Ingestie: journald (sshd, sudo/su), nginx, auditd, îmbogățire geo/ASN |
| P4 | Reguli de detecție, incidente, alertare Telegram |
| P5 | Răspuns: blocklist nftables, blocare dintr-un tap, `/panic`, audit cu lanț de hash |
| P6 | Decizia de auto-block (observă/armat), baseline sezonier, Suricata IDS |
| P7 | Scanare de vulnerabilități: `dnf updateinfo` (RHEL) sau `apt-get -s` pe depozitul de securitate (Debian/Ubuntu, fără CVE), trivy pe fișiere și imagini, oglindă CISA KEV, prioritizare |
| P8 | Triaj AI cu plafon dur de tokeni și izolare anti prompt-injection |
| P9 | Patching: generare de planuri, aprobare în doi pași, backup verificat, rollback automat |
| P10 | Analytics extins, hardening final, documentație completă — **în curs** |

**Auto-block-ul se livrează dezactivat.** Mecanismul e complet și testat, dar
primele zile sunt menite să fie doar de observare: afli ce *ar fi* fost blocat,
cu buton, ca fals-pozitivele să iasă la suprafață înainte să fie tăiat ceva la
3 dimineața. Planurile de patch se generează automat; aplicarea unuia cere
mereu două confirmări explicite.

Lipsuri, declarate în loc să fie ascunse: logurile din containere nu sunt
colectate (doar cele ale gazdei), nu există monitor dedicat de integritate a
fișierelor dincolo de ce acoperă auditd, iar tipurile de verificare
`http`/`tcp`/`docker` din planurile de patch sunt declarate dar încă
neimplementate în runner. Calea de instalare Debian/Ubuntu este scrisă și
acoperită de teste, dar **nu a fost încă rulată complet pe o gazdă Debian
reală** — pe RHEL este verificată în producție.

Detalii în [ARHITECTURA.md](ARHITECTURA.md) și în
[CHANGELOG.md](CHANGELOG.md).
