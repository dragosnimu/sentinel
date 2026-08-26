# Aplicații web — inventar, versiuni, plan de întărire

Scanat pe gazda de producție, **10 august 2026**, prin interogarea directă a
containerelor și a proceselor. Versiunile de mai jos sunt citite din aplicații,
nu din inventar sau din documentație.

Complementar lui `docs/INTARIRE.md`, care acoperă gazda. Acesta acoperă ce
rulează *deasupra* ei.

---

## Inventarul, cu versiunile reale

| Aplicație | Versiune | Stivă | Cum e expusă |
|---|---|---|---|
| **Snipe-IT** | v8.7.0-pre (build 23531) | PHP 8.3.6, Laravel 12.59.0, Apache 2.4.58 | `0.0.0.0:8000`, **HTTP simplu** |
| **aplicatie-interna** | — | container propriu | `127.0.0.1:3000` + nginx TLS |
| **n8n** | 1.112.4 | Node 22.19.0 | `127.0.0.1:5678`, prin traefik |
| **traefik** | 3.5.2 | — | `0.0.0.0:88`, `0.0.0.0:444` |
| **qdrant** | 1.14.1 | — | `0.0.0.0:6333-6334`, cere cheie API |
| **bet-calculator** | — | container propriu | `0.0.0.0:3001` |
| **Zabbix web** | 6.4.21 | PHP pe gazdă (php-fpm) | vezi §4 |
| mariadb | 11.4.7 | — | intern containerului |
| postgres | 16-alpine | — | intern containerului |

**PHP există în două locuri diferite**: 8.3.6 în containerul Snipe-IT și 8.2.33
pe gazdă (29 de pachete RPM, `php-fpm` activ). Sunt instalări separate, cu
suprafețe separate.

---

## 1. Snipe-IT circulă în clar, pe un port public

Cea mai gravă constatare din scanare.

**Dovada:**

```
0.0.0.0:8000 -> snipeit-app-1, Apache/2.4.58 (Ubuntu)
GET /login -> 200
Set-Cookie: snipeit_session=…; HttpOnly; SameSite=Lax
Set-Cookie: XSRF-TOKEN=…
niciun vhost nginx nu referă portul 8000
```

Cookie-ul de sesiune are `HttpOnly` și `SameSite=Lax` — corect. Nu are `Secure`,
și **nici n-ar avea sens să-l aibă**: nu există TLS. Aplicația e servită direct
de Apache-ul din container, pe HTTP, către internet.

Consecința e simplă: cine e pe traseu vede sesiunea și o poate refolosi. Nu e o
vulnerabilitate a Snipe-IT, e o lipsă de transport. Iar Snipe-IT ține inventarul
de active — numere de serie, chei de licență, cine ce are.

Notă bună: `/.env` întoarce 403 și `/.git/config` 404, deci Apache-ul din imagine
blochează corect fișierele sensibile. `/setup` redirecționează, nu e deschis.

### Remediul: pune-l în spatele nginx, cum e deja aplicatie-interna

Ai deja infrastructura — nginx cu Let's Encrypt și un vhost funcțional pentru
`aplicatie-interna.exemplu.ro`. Snipe-IT are nevoie de același tratament.

**Pasul 1 — subdomeniu și certificat.** Adaugă un `A` pentru subdomeniu către
gazdă, apoi:

```bash
sudo certbot certonly --webroot -w /var/lib/letsencrypt -d inventar.exemplu.ro
```

**Verifică efectul:**

```bash
sudo certbot certificates | grep -A2 inventar
```

**Pasul 2 — vhost.** Copiază structura de la `aplicatie-interna`, cu `proxy_pass` către
`http://127.0.0.1:8000`. Înainte de reîncărcare:

```bash
sudo nginx -t
```

**Reîncărcare și dovada efectului** — nu codul de ieșire:

```bash
sudo systemctl reload nginx && sleep 2 && ps -o pid,lstart -C nginx | head -3
```

PID-urile lucrătorilor trebuie să fie noi. `reload` întoarce 0 și când
configurarea a fost respinsă, iar lucrătorii vechi continuă să servească — asta
a costat trei zile pe serverul ăsta în iulie.

**Pasul 3 — leagă containerul pe loopback.** În `docker-compose.yml` al
Snipe-IT:

```
ports:
  - "127.0.0.1:8000:80"
```

Backup întâi:

```bash
sudo cp -a docker-compose.yml docker-compose.yml.bak-$(date +%F-%H%M)
```

Aplicare:

```bash
sudo docker compose up -d
```

**Verifică efectul:**

```bash
sudo ss -tlnp | grep :8000
```

Trebuie `127.0.0.1:8000`, nu `0.0.0.0:8000`.

**Pasul 4 — spune-i aplicației că e în spatele unui proxy TLS.** Altfel Laravel
generează URL-uri `http://` și cookie-ul rămâne fără `Secure`. În `.env`-ul
Snipe-IT:

```
APP_URL=https://inventar.exemplu.ro
SESSION_SECURE_COOKIE=true
```

**Verifică efectul:**

```bash
curl -s -I https://inventar.exemplu.ro/login | grep -i set-cookie
```

Trebuie să conțină `Secure`.

**Rollback complet:** restaurează `docker-compose.yml` din backup, `docker
compose up -d`, șterge vhostul nou, `nginx -t`, `reload`. Aplicația revine pe
`0.0.0.0:8000` exact ca înainte.

---

## 2. Etichetele `:latest` — două imagini vechi, nu toate

**Corecție.** Prima versiune a acestei secțiuni spunea că *toate* imaginile sunt
vechi de 6–15 luni. Era greșit. Măsurasem printr-un lanț de `docker inspect` pe
care nu l-am verificat contra unei a doua metode, iar cifrele pentru Snipe-IT și
qdrant erau false. Nu pot reconstrui exact ce am citit atunci. Ce urmează e
măsurat cu `docker images`, confirmat prin versiunile raportate de aplicațiile
care rulează.

**Starea reală, 11 august 2026:**

```
snipe/snipe-it:latest    creata acum 18 ore     -> recenta
qdrant/qdrant:latest     creata acum 6 zile     -> recenta
bet-deploy-*             creata acum 10 zile    -> recenta
aplicatie-interna-app           creata acum 4 luni
n8nio/n8n                creata 2025-09-23      -> ~11 luni
traefik:latest           creata 2025-09-09      -> ~11 luni
```

Confirmarea independentă: containerul Snipe-IT raportează el însuși
`v8.7.0-pre - build 23531` și Laravel 12.59.0, coerent cu o imagine de ieri.

**Deci problema e reală, dar restrânsă la două**: n8n și traefik. n8n publică
versiuni săptămânal; la unsprezece luni distanță, e mult în urmă.

Rămâne valabil și argumentul despre etichetă: `:latest` nu înseamnă „ultima
versiune", ci „ce era ultima când s-a tras imaginea". Faptul că unele containere
sunt la zi înseamnă că cineva a tras recent, nu că mecanismul le ține la zi.

### Remediul, în două mișcări

**Întâi fixează versiunile explicit** — ca să știi ce rulezi:

```bash
sudo docker inspect --format '{{.Config.Image}} {{index .RepoDigests 0}}' qdrant
```

Pune digest-ul sau eticheta de versiune exactă în `docker-compose.yml`, în locul
lui `latest`. De acum, o schimbare de versiune e o schimbare vizibilă în fișier,
nu un accident la următorul `pull`.

**Apoi actualizează n8n și traefik.** Backup înainte — pentru aplicații cu
stare, imaginea nu e de ajuns:

```bash
sudo docker compose exec -T snipeit-db mysqldump -u root -p"$PAROLA" --all-databases > /var/backups/snipeit-$(date +%F).sql
```

Actualizare, din directorul fiecărui compose:

```bash
sudo docker compose pull && sudo docker compose up -d
```

**Verifică efectul** — nu că a pornit containerul, ci că aplicația răspunde:

```bash
sudo docker ps --format '{{.Names}}	{{.Status}}'
curl -s -o /dev/null -w '%{http_code}
' http://127.0.0.1:8000/login
```

Și pentru aplicațiile care rulează migrații la pornire:

```bash
sudo docker compose logs --tail=40 <serviciu> | grep -iE 'migrat|error'
```

**Rollback:** revino la digest-ul anterior în `docker-compose.yml` și
`docker compose up -d`. Pentru date, restaurează dump-ul — de aceea se face
înainte, nu după. **O migrație de bază de date aplicată nu se dă înapoi prin
schimbarea imaginii.**

---

## 3. Apache 2.4.58 în imaginea Snipe-IT

**Dovada:** `Server: Apache/2.4.58 (Ubuntu)` — versiunea din Ubuntu 24.04,
lansată la începutul lui 2024.

Nu e o vulnerabilitate pe care s-o poți repara direct: vine din imaginea
`snipe/snipe-it`, nu din configurația ta. Se repară prin §2, actualizând
imaginea. Îl notez fiindcă e semnalul cel mai vizibil al vechimii imaginii —
și fiindcă antetul `Server` îl anunță public.

După actualizare, ascunde versiunea:

```
ServerTokens Prod
ServerSignature Off
```

Se pune prin volum montat peste configurația Apache din container. **Verifică
efectul:**

```bash
curl -s -I https://inventar.exemplu.ro/login | grep -i '^server'
```

Trebuie să spună doar `Apache`, fără număr.

---

## 4. Două versiuni de Zabbix și un php-fpm fără consumator

**Dovada:**

```
zabbix-6.0.44-1.el9            (LTS, suportat)
zabbix-web-6.4.21-release1     (6.4 a ieșit din suport)
zabbix-web-mysql-6.4.21
php-fpm: active,  29 pachete PHP,  0 porturi TCP
sockets: /run/php-fpm/www.sock, /run/php-fpm/zabbix.sock,
         /var/opt/remi/php82/run/php-fpm/www.sock
nginx: /etc/nginx/conf.d/php-fpm.conf, /etc/nginx/default.d/php.conf
```

Serverul are **agentul** Zabbix 6.0.44 (LTS) și, separat, **frontendul web**
6.4.21, care nu mai primește actualizări de securitate. Frontendul rulează prin
`php-fpm` pe gazdă.

Am verificat dacă e accesibil: pe serverul implicit, `/index.php` întoarce 404
și `/` la fel. Deci **nu e servit acum**. Dar calea de execuție PHP există în
configurația nginx, iar frontendul e instalat pe disc.

### Decizia e a ta, și sunt trei variante oneste

**(a) Nu-l folosești** — atunci scoate-l. E cea mai curată:

```bash
sudo dnf -y remove zabbix-web zabbix-web-mysql zabbix-web-deps
sudo systemctl disable --now php-fpm
```

**Verifică efectul:**

```bash
systemctl is-active php-fpm; rpm -qa 'zabbix-web*' | wc -l
```

`inactive` și `0`.

**Rollback:** `sudo dnf -y install zabbix-web zabbix-web-mysql` și
`systemctl enable --now php-fpm`. Configurația din `/etc/zabbix/web/` nu se
șterge la dezinstalare, deci revine cu setările ei.

**(b) Îl folosești** — atunci actualizează-l la 6.0 LTS, ca să se potrivească cu
agentul și să primească reparații:

```bash
sudo dnf -y --releasever=9 --setopt=module_platform_id=platform:el9 \
     downgrade zabbix-web zabbix-web-mysql zabbix-web-deps
```

Notează tranzacția `dnf` înainte (`dnf history list | head -3`) — rollback-ul e
`dnf history undo <numar>`.

**(c) Îl lași** — dar atunci scrie undeva de ce, fiindcă peste șase luni nimeni
nu-și va aminti că un frontend EOL stă instalat dinadins.

**Nu recomand (c).** Un frontend web EOL, cu PHP activ pe gazdă, care astăzi nu
e rutat — e exact configurația care devine o problemă când cineva adaugă un
vhost și include `default.d/*.conf` fără să se uite ce e acolo.

---

## 5. Traefik pe 88 și 444, în paralel cu nginx

**Dovada:**

```
0.0.0.0:88   -> n8n-compose-traefik-1
0.0.0.0:444  -> n8n-compose-traefik-1
0.0.0.0:80   -> nginx
0.0.0.0:443  -> nginx
```

Ai două terminatoare HTTP pe aceeași mașină, pe porturi diferite. Traefik 3.5.2
e rezonabil de recent, dar înseamnă a doua configurație de TLS, a doua politică
de antete, a doua sursă de jurnale — și doar una dintre ele e monitorizată de
Sentinel (colectorul citește `/var/log/nginx/`).

**Ce câștigi consolidând:** un singur loc unde se termină TLS, un singur set de
jurnale în care Sentinel vede totul, o singură politică de limitare a ratei.

Nu e o comandă; e o mutare de arhitectură. Dacă n8n e folosit doar de tine,
varianta cea mai simplă e să nu-l expui deloc: traefik pe `127.0.0.1` și acces
prin tunel SSH.

**Verifică întâi dacă e chiar folosit din exterior:**

```bash
sudo tail -200 /var/log/nginx/access.log | grep -c ':88\|:444'
sudo docker logs --since 168h n8n-compose-traefik-1 2>&1 | grep -cE '^[0-9]+\.'
```

Dacă în ultima săptămână nu l-a atins nimeni din afară, decizia e ușoară.

---

## 6. Ce nu apare în scanarea de vulnerabilități, și de ce

Scanerul lui Sentinel rulează `dnf updateinfo --security`, care acoperă
**pachetele RPM de pe gazdă**. Nu vede:

- versiunile din interiorul containerelor (Snipe-IT, Laravel, Apache, n8n);
- dependențele PHP ale aplicațiilor (`composer.lock`);
- pachetele npm din imaginile Node.

De aceea lista arăta 31 de constatări despre kernel și niciuna despre o imagine
veche de cincisprezece luni.

Planul prevede `trivy` exact pentru asta — scanare de imagini, sisteme de
fișiere, dependențe. Nu e instalat pe gazdă. Când îl activezi, el e cel care
transformă §2 din „imagini vechi" în „aceste CVE, în acest strat".

Până atunci, verificarea manuală, pentru fiecare imagine:

```bash
sudo docker image inspect --format '{{.Created}}  {{index .RepoTags 0}}' $(sudo docker ps -q) | sort
```

Orice imagine mai veche de trei luni merită o privire; mai veche de un an,
merită o actualizare planificată.

---

## Ordinea recomandată

1. **§1** — Snipe-IT în spatele nginx, cu TLS. Sesiuni în clar pe un port public
   e singura constatare de aici care se exploatează pasiv, doar ascultând.
2. **§4** — decide ce faci cu frontendul Zabbix EOL. Dacă nu-l folosești, cinci
   minute.
3. **§2** — fixează versiunile în `docker-compose.yml`. Nu actualizează nimic,
   dar oprește deriva și îți arată ce ai.
4. **§2 partea a doua** — actualizează imaginile, una câte una, cu backup de
   bază de date înainte. Începe cu qdrant (fără stare complexă), termină cu
   Snipe-IT (migrații).
5. **§5** — decide dacă n8n trebuie să fie public.
6. **§3** — vine odată cu §2.

Ca și la ghidul de gazdă: o schimbare odată, cu verificarea efectului între ele.
Două aplicate împreună îți iau posibilitatea de a ști care a stricat ce.
