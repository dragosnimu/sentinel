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
| Un daemon `sentinel` | Poate cere acțiuni executorului, care le validează independent |
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
