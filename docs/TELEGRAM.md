# Telegram — comenzi și fluxuri

Botul este canalul principal de control. Funcționează prin long polling: fără
port de intrare, fără endpoint public, și rămâne funcțional chiar dacă nginx sau
TLS s-au stricat — adică exact când ai cea mai mare nevoie de el.

---

## 1. Configurare inițială

1. `/newbot` la [@BotFather](https://t.me/BotFather). Primești tokenul.
2. Chat id-ul numeric de la [@userinfobot](https://t.me/userinfobot).
3. Ambele intră în `secrets/.env.local` prin `./scripts/secrets-init.sh`.
4. Chat id-ul ajunge în `telegram.allowed_chat_ids` din `sentinel.yaml`.

**Bot nou, dedicat.** Nu refolosi unul care duce deja alte notificări —
amestecarea alertelor de rutină cu cele de securitate este exact modul în care
alertele de securitate ajung să nu mai fie citite.

Scrie-i botului `/start` după instalare.

---

## 2. Autorizare

Doar chat id-urile din `allowed_chat_ids` sunt procesate. Verificarea se face ca
middleware, **pe fiecare tip de update** — `message`, `callback_query`,
`edited_message`, `my_chat_member`. Bug-ul clasic e să verifici doar `message` și
să lași callback-urile deschise; există un test pentru asta.

Un chat nepermis primește **zero răspuns** (nu confirmăm nici măcar că botul
există) și generează o linie de log pe oră.

| Rol | Poate |
|---|---|
| `owner` | Tot. Ar trebui să fie un singur chat id |
| `operator` | Blocare, deblocare, scanare. **Nu** aplicare de patch-uri, **nu** config |
| `viewer` | Doar citire |

**Într-un grup, autorizarea e a grupului, nu a persoanei.** `_authorized`
compară doar `chat.id` cu `allowed_chat_ids`; expeditorul nu e verificat
niciodată — `update.effective_user` nu e citit nicăieri pe calea de autorizare.
Dacă id-ul unui grup e în allowlist, **orice membru al grupului** poate da
comenzi. Dacă grupul e și `owner_chat_id`, orice membru are drepturi de owner,
inclusiv blocare de adrese pe o instalare cu auto-block activ.

Consecința practică: a adăuga pe cineva în grup înseamnă a-i da drepturile
grupului. Nu există un nivel „doar vede alertele" — rolurile din tabelul de mai
sus se aplică pe chat, iar într-un grup chatul e unul singur pentru toți.

Paragraful ăsta spunea până pe 5 septembrie 2026 exact pe dos: că expeditorul e
verificat și el, și că apartenența la grup nu e autentificare. În cod nu a fost
adevărat niciodată. Corectat după ce documentul a fost citit ca să se scrie
procedura pentru mai multe instanțe.

---

## 3. Comenzi

### Stare

| Comandă | Ce face |
|---|---|
| `/start`, `/help` | Meniu cu butoane |
| `/status` | Un ecran: servicii up/down, incidente deschise pe severitate, IP-uri blocate, vulnerabilități critice, nivel de amenințare 0–100, buget AI |
| `/services` | Per serviciu: stare, uptime azi/7z/30z, timp de răspuns |
| `/incidents [n]` | Ultimele n incidente (implicit 10), cu buton `Detalii` |
| `/incident <id>` | Dosarul complet: cronologie, actor, evidențe, verdict AI, acțiuni recomandate |
| `/actor <ip>` | Profil: geo/ASN, reputație, stadiu în lanțul de atac, istoric |
| `/top [24h\|7d]` | Top IP-uri, țări, ASN-uri, endpoint-uri țintite |
| `/traffic [asset]` | Volum curent față de banda așteptată |

### Răspuns

| Comandă | Ce face |
|---|---|
| `/block <ip> [ttl] [motiv]` | Validează IP-ul, verifică allowlist-ul. TTL implicit 24h. Confirmare pentru permanent și pentru orice mai larg de /24 |
| `/unblock <ip>` | Imediat |
| `/blocklist [n]` | Blocurile active cu TTL rămas, motiv, contor de hit-uri, buton `Deblochează` pe fiecare |
| `/allow <ip> [motiv]` | Adaugă în allowlist. Necesită confirmare |
| `/watch <ip>` | Monitorizează fără să blocheze |
| `/mute` | Ore de liniște — vezi §3.1 |
| `/unmute` | Repornește alertele, oprind ambele mecanisme |
| `/panic` | **Golește tot blocklist-ul, imediat.** Dublă confirmare. Disponibilă chiar și pe mute |

### 3.1 Ore de liniște

Un canal care te trezește la 3 dimineața pentru o scanare de porturi e un canal
pe care îl vei opri definitiv într-o săptămână — iar un canal oprit definitiv e
mai rău decât niciunul: arată ca acoperire și nu e. De asta există `/mute`.

```
/mute 22:00-06:00     în fiecare noapte, între aceste ore
/mute 2h              pauză unică (maxim 24h)
/mute off             oprește tot
/mute                 starea curentă
```

**Se setează per chat**, nu global. Cel care scrie comanda e cel pe care îl
trezește telefonul, iar o setare comună ar lăsa un operator să tacă telefonul
altuia.

**Orele sunt locale.** Serverul rulează pe UTC, dar cine scrie „22:00" se referă
la 22:00 unde stă el. Fusul se citește după nume din `/etc/timezone` sau din
`/etc/localtime` — nu ca decalaj fix — ca noaptea în care se schimbă ora să nu
mute sfârșitul intervalului cu o oră.

**Nu există mute nelimitat.** `/mute 7d` e limitat la 24 de ore. Un mute pe care
trebuie să-ți amintești să-l anulezi e unul pe care nu-l vei anula.

#### Ce trece oricum

Tăcerea trebuie să fie sigură. Astea ignoră orice interval, orice pauză și orice
configurație:

| | De ce |
|---|---|
| Alertele **critice** | Dacă nu merită trezirea, nu erau critice |
| **PANIC** și **watchdog** | Îți spun că propria plasă de siguranță s-a declanșat |
| **Patch eșuat** sau **revenit** | Ceva pe gazdă s-a schimbat și apoi s-a schimbat înapoi. Nu se amână până dimineață |
| **Lockout** | S-ar putea să fii blocat afară chiar acum |

Lista trăiește în cod (`sentinel/telegram/quiet.py`), nu în configurație:
*care alerte pot fi tăcute* e o proprietate de siguranță, iar un fișier de
configurație e locul greșit în care să lași pe cineva s-o tacă și pe ultima.

#### Ce se întâmplă cu restul

Sunt **reținute, nu pierdute.** Rândurile rămân cu `notified_at` gol și pleacă
la primul ciclu după ce se termină intervalul. Dacă s-au adunat mai multe decât
`digest_threshold`, sosesc ca un singur rezumat — să te trezești la șaizeci de
notificări e, practic, la fel cu a nu te trezi la niciuna.

Dacă interogarea preferințelor eșuează, botul **alertează oricum**. E singura
direcție sigură: o eroare de bază de date nu are voie să tacă un canal de
securitate.

### Vulnerabilități și patching

| Comandă | Ce face |
|---|---|
| `/scan [all\|os\|web\|code\|<asset>]` | Pornește o scanare |
| `/vulns [critical\|high\|kev]` | Listă prioritizată |
| `/vuln <id>` | Detaliu + buton `Generează plan de patch` |
| `/patch <finding_id>` | Generează un plan (AI) |
| `/patches` | Planuri după stare |
| `/plan <plan_id>` | Planul complet cu butoane de acțiune |
| `/restore` | Puncte de restaurare; restaurarea cere dublă confirmare |

### Rapoarte

| Comandă | Ce face |
|---|---|
| `/report [zi\|saptamana\|luna]` | Generează și trimite raportul |
| `/predict` | Predicțiile curente cu probabilități și nota de calibrare |
| `/ask <întrebare>` | Întrebare liberă peste baza de date, read-only. Limitată ca rată și ca buget |

### Administrare

| Comandă | Ce face |
|---|---|
| `/health` | Sănătatea Sentinel: fiecare unitate, dimensiunea DB, adâncimea cozilor, prospețimea feed-urilor, ultimul apel AI reușit |
| `/version` | Versiune, git sha, momentul deploy-ului |
| `/config get\|set <key> [val]` | Doar parametri permiși (praguri, TTL-uri, ore liniștite). Niciodată secrete, căi sau allowlist-uri de comenzi |
| `/budget` | Cheltuiala AI azi și luna asta față de plafon |

---

## 4. Butoane

| Context | Butoane |
|---|---|
| Incident | `🔍 Detalii` · `🚫 Blochează IP` · `👁 Watch` · `✅ Fals pozitiv` · `🔇 Suprimă regula 1h` |
| Auto-block | `↩️ Deblochează` · `🔒 Permanentizează` · `📊 Vezi activitatea` |
| Mod observă (auto-block oprit) | `🚫 Blochează acum` · `👁 Watch` · `✅ Fals pozitiv` |
| Vulnerabilitate | `📄 Detalii` · `🛠 Generează plan` · `😴 Amână 7 zile` · `🙈 Acceptă riscul` |
| Plan de patch | `📄 Vezi` · `🧪 Dry-run` · `✅ Aplică` · `⏰ Programează` · `❌ Respinge` |
| Serviciu picat | `🔄 Restart serviciu` · `📜 Ultimele loguri` · `🔇 Mute 30m` |

Două butoane merită explicate:

**`↩️ Deblochează`** apare pe *fiecare* mesaj de auto-block. O blocare greșită
este la un tap distanță de anulare. Această proprietate este ce face auto-block-ul
acceptabil.

**`✅ Fals pozitiv`** nu doar închide incidentul: scrie o intrare de suprimare
îngustă *și* alimentează datele de calibrare. Este mecanismul prin care rata de
fals-pozitive scade în timp. Folosește-l.

---

## 5. Securitatea butoanelor

Telegram limitează `callback_data` la 64 de octeți și îl trimite înapoi de la
client — deci poate fi rejucat și modificat.

Sentinel pune în el **doar un token opac**. Payload-ul real stă pe server, în
`telegram_callbacks`: single-use, cu TTL, semnat HMAC cu o cheie **separată de
tokenul botului** (un token de bot scurs nu trebuie să permită și falsificarea
aprobărilor).

Pentru patch-uri, tokenul e legat de `plan_hash`. **Dacă planul se regenerează,
hash-ul se schimbă și toate butoanele din mesajele anterioare mor.** Nu poți
aproba planul A și să se execute planul B.

`✅ Aplică` nu execută niciodată direct. Deschide o a doua confirmare care
restatează ținta, downtime-ul estimat și dimensiunea backup-ului — ca un tap
greșit pe un mesaj vechi să fie vizibil înainte să facă ceva.

Toate argumentele sunt tipizate și validate înainte să ajungă la vreun handler:
IP-urile prin `ipaddress`, id-urile ca întregi, TTL-urile mărginite între 60s și
30 de zile, motivele limitate ca lungime și curățate de caractere de control.
`/block '; rm -rf /'` este respins de validarea IP-ului, nu de un filtru de
escaping.

---

## 6. Volumul notificărilor

Modul de eșec pe care aceste setări îl previn este oboseala de alerte. Un canal
care sună de patruzeci de ori pe zi ajunge pe mute, iar un canal pe mute nu
protejează nimic.

- **Critic** trece întotdeauna: peste ore liniștite, peste mute, fără digest.
  Dacă nu merită să trezești pe cineva, nu e critic — reclasifică regula.
- **Mediu** intră în digest: peste 10 notificări în 5 minute devin un singur
  mesaj cu totaluri și link către dashboard.
- **Deduplicare**: același fingerprint de incident nu re-notifică timp de 30 de
  minute, oricâte detecții acumulează. Un atac prin forță brută este un mesaj,
  nu patru sute. O escaladare de severitate trece totuși.

Toate setările în `/etc/sentinel/notifications.yaml`.

---

## 7. Dacă tokenul botului se scurge

Tokenul este planul de control. Cine îl are poate cere deblocări, poate opri
alertele și poate aproba patch-uri — limitat de allowlist-ul de chat_id, de
roluri și de dubla confirmare, dar tot prea mult.

1. `/revoke` la @BotFather, imediat.
2. Token nou, `./scripts/secrets-init.sh --force`, redeploy.
3. Verifică `audit_log` pentru ce s-a cerut între timp:
   ```bash
   sudo -u postgres psql sentinel -c \
     "SELECT at, actor, operation, target, result FROM audit_log
      WHERE source='telegram' AND at > now() - interval '7 days' ORDER BY at DESC"
   ```

Ca apărare în adâncime, dacă telefonul poate fi pierdut sau furat: setează
`TELEGRAM_APPLY_PIN` în `secrets.env` și `telegram.require_pin_for_apply: true`.
Aplicarea patch-urilor și modificarea allowlist-ului vor cere un PIN — ceva ce
hoțul nu are.

---

## 8. Mai multe instanțe pe același Telegram

### De ce nu merge pur și simplu cu același bot

Telegram acceptă **un singur cititor de actualizări per token**. Două instanțe
Sentinel configurate cu același `TELEGRAM_BOT_TOKEN` intră amândouă în
`getUpdates` și primesc:

```
Conflict: terminated by other getUpdates request; make sure that only one bot instance is running
```

Nu e tranzitoriu — se repetă la fiecare ciclu, iar canalul de comandă al
**ambelor** instanțe devine nefiabil. Măsurat pe 4 septembrie 2026: 32 de erori
în 30 de minute pe instanța de producție, imediat după ce a doua gazdă a pornit
cu tokenul copiat.

**Trimiterea nu are limita asta.** Restricția e doar pe `getUpdates`; oricâte
instanțe pot trimite prin același token. Dar expeditorul lui Sentinel trăiește
înăuntrul demonului care interoghează: `run_polling` cheamă `post_init`, iar
`post_init` pornește bucla care golește coada `notifications`. Fără interogare nu
pleacă nicio alertă. „Trimite dar nu asculta" **nu există** ca opțiune de
configurare, și de-asta soluția nu e un token comun.

### Soluția: un grup, un bot per instanță

- fiecare instanță are botul și tokenul ei → niciun conflict;
- toate boturile sunt membre ale aceluiași grup → un singur fir de citit;
- boturile pot purta **același nume afișat** — BotFather cere username unic, nu
  nume unic, deci în grup arată ca un singur expeditor;
- **butoanele se rutează singure.** Un `callback_query` se întoarce la botul care
  a trimis acel mesaj, deci apăsarea pe o alertă venită de la instanța A ajunge
  la A. Nu e nevoie nici de identitate de instanță în payload, nici de vreun
  canal de control între gazde.

### Procedura

1. `/newbot` la BotFather pentru fiecare instanță nouă. Cu `/setname` le dai
   tuturor același nume afișat.
2. Creezi un grup și adaugi toate boturile. Nu au nevoie de drepturi de
   administrator; membru simplu e de ajuns.
3. Trimiți `/start@<username>` în grup pentru fiecare bot nou — altfel coada lui
   de actualizări poate fi goală la pasul următor.
4. Afli id-ul grupului, interogând **botul instanței noi**, cu serviciul ei încă
   oprit ca să nu existe conflict:

```bash
sudo -n python3 - <<'PY'
import json, socket, urllib.request
_o = socket.getaddrinfo
socket.getaddrinfo = lambda *a, **k: [x for x in _o(*a, **k) if x[0] == socket.AF_INET]
tok = [l.split('=', 1)[1].strip() for l in open('/etc/sentinel/secrets.env')
       if l.startswith('TELEGRAM_BOT_TOKEN=')][0]
d = json.load(urllib.request.urlopen(
    f'https://api.telegram.org/bot{tok}/getUpdates?timeout=0', timeout=15))
for u in d.get('result', []):
    c = (u.get('message') or u.get('my_chat_member') or {}).get('chat')
    if c: print(c['id'], c.get('type'), c.get('title'))
PY
```

   Tokenul e citit din fișier, nu dat pe linia de comandă — altfel ajunge în
   `ps` și în istoricul shell-ului. IPv4 e forțat fiindcă o gazdă cu rută IPv6
   nefuncțională blochează cererea la `connect`, iar `timeout` o face să
   eșueze în loc să atârne.

5. Pe fiecare gazdă, în `/etc/sentinel/secrets.env`: token propriu,
   `TELEGRAM_CHAT_ID` = id-ul grupului, și **`TELEGRAM_CALLBACK_HMAC_KEY`
   propriu** (`openssl rand -hex 32`). Cheia aia nu are voie să fie comună — cu
   ea comună, un buton emis de o instanță e acceptat ca valid de cealaltă, care
   îl execută pe propriile date.
6. În `sentinel.yaml`: `instance_label` distinct, id-ul grupului în
   `allowed_chat_ids` și în `owner_chat_id`. Grupul **trebuie** să fie owner sau
   operator, altfel butoanele apăsate acolo nu fac nimic.
7. `sentinel config-check`, apoi repornire și dovada:

```bash
sudo -u sentinel /opt/sentinel/bin/sentinel telegram --send-test
```

   Răspunsul util e `delivered (message_id=N)`. Un cod HTTP 200 fără
   `message_id` nu e livrare.

### Verificarea, prin efect

Pe **fiecare** gazdă, după repornire:

```bash
sudo journalctl -u sentinel-telegram --since '10 min ago' | grep -c Conflict
```

Zero pe toate. Apoi apeși un buton pe o alertă reală venită de la fiecare
instanță — ăsta e singurul test care dovedește rutarea, fiindcă livrarea
mesajului și rutarea callback-ului sunt lucruri diferite.

### Capcane

**Apartenența la grup e autoritate.** Vezi §2: autorizarea se face pe `chat.id`,
nu pe expeditor. Oricine e în grup are drepturile grupului, pe toate instanțele
deodată, inclusiv blocare de adrese acolo unde auto-block e activ.

**Conversia în supergrup schimbă id-ul.** Se întâmplă automat la anumite acțiuni
— membri mulți, grup făcut public, istoric activat pentru membri noi. Id-ul sare
din `-5xxxxxxxxxx` în `-100xxxxxxxxxx`, iar alertele **tac pe toate gazdele fără
nicio eroare vizibilă**. Dacă alertele dispar după ce ai umblat prin setările
grupului, asta e prima ipoteză.

**Nu adăuga o a doua secțiune `telegram:` în `sentinel.yaml`.** YAML acceptă
cheia duplicată tăcut și câștigă ultima; o secțiune nouă pusă în capul
fișierului e ignorată complet în favoarea celei originale de mai jos, iar
simptomul e că mesajele pleacă spre chat-ul vechi. `config-check` nu semnalează
duplicatul. Caută secțiunea existentă și modific-o pe ea.

**Păstrează chat-ul privat în `allowed_chat_ids`** dacă îl vrei în continuare;
doar `owner_chat_id` se mută pe grup. Cu ambele în listă, `--send-test` livrează
în amândouă.

