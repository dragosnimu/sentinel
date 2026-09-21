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
să lași callback-urile deschise; §2.1 detaliază de ce verificarea rămâne
aceeași pe toate patru, și unde exact a picat asta o dată.

Un chat nepermis primește **zero răspuns** (nu confirmăm nici măcar că botul
există) și generează o linie de log pe oră.

| Rol | Poate |
|---|---|
| `owner` | Tot |
| `operator` | Tot ce poate `owner`, inclusiv aprobarea planurilor de patch |
| `viewer` | Doar citire |

**Corectat pe 8 septembrie 2026:** rândul lui `operator` spunea până acum
„nu aplicare de patch-uri, nu config" — n-a fost niciodată adevărat în cod.
`on_patch_callback` (aprobarea planurilor, `sentinel/telegram/bot.py`) și
fiecare comandă de răspuns verifică aceeași funcție, `_can_act`, care nu
deosebește `owner` de `operator` — vede doar „e unul din cele două, sau
niciun rol nu e configurat". Un `operator` care apasă „✅ Aplică" pe un plan
de patch chiar îl aplică. Dacă separarea asta contează pentru instalarea ta,
e o schimbare de proiectare (cine anume poate autoriza o modificare pe
gazdă), nu o corectare de o linie — cere o decizie a operatorului, nu una
luată tăcut într-o trecere de reparații.

**Într-un grup, autorizarea de bază e a grupului, nu a persoanei.**
`_authorized` compară `chat.id` cu `allowed_chat_ids` — dacă id-ul unui grup e
în allowlist, **orice membru al grupului** poate trece de acest prim pas. Dacă
grupul e și `owner_chat_id`, orice membru moștenește rolul de owner, inclusiv
blocare de adrese pe o instalare cu auto-block activ. Măsurat pe 5 septembrie
2026: două instanțe Sentinel, un singur grup partajat drept `owner_chat_id` pe
amândouă — a adăuga o persoană în grup îi dădea drepturi de owner pe două
servere de producție deodată.

Paragraful ăsta spunea până pe 5 septembrie 2026 exact pe dos: că expeditorul e
verificat întotdeauna, și că apartenența la grup nu e autentificare. Nu a fost
niciodată adevărat în cod. Corectat, și completat acum cu mecanismul care chiar
există:

### 2.1 `telegram.allowed_user_ids` — restrângerea opțională pe expeditor

`allowed_user_ids` e o listă de id-uri Telegram de UTILIZATOR (nu de chat),
verificată **în plus** față de `allowed_chat_ids`, **doar** pentru un chat care
nu e privat. Într-un chat privat `chat.id` chiar este id-ul persoanei, deci
verificarea de expeditor n-ar adăuga nimic — și ar putea strica singurul acces
al operatorului dacă acesta uită să-și adauge propriul id privat pe lista de
utilizatori. De asta un chat privat e scutit, chiar dacă lista e completată.

> **Ordinea contează: mai întâi codul, apoi configurația.** `config.py` respinge
> orice cheie pe care n-o cunoaște, cu `ConfigError: unknown configuration key`.
> Dacă scrii `allowed_user_ids` în `sentinel.yaml` **înainte** ca versiunea asta
> să fie livrată pe gazdă, fiecare unitate care încarcă configurația —
> `sentinel-health`, `-maintenance`, `-selfcheck`, `-watchdog` — începe să pice,
> iar o repornire a lui `sentinel-telegram` în fereastra aia oprește chiar
> canalul prin care ai fi aflat. Configurațiile gazdelor sunt scrise de mână și
> nu se regenerează la livrare, deci nimic nu te oprește să faci pașii în
> ordinea greșită. Livrează întâi, editează pe urmă.

> **Pe o instanță unde grupul e singurul chat permis**, o listă de utilizatori
> greșită te încuie afară complet: nu mai există chat privat prin care să intri.
> Verifică id-ul înainte, nu după.

**Implicit, lista e goală, și asta înseamnă exact comportamentul de dinainte de
5 septembrie 2026** — doar verificarea de chat. O instalare care actualizează
codul fără să atingă `allowed_user_ids` nu pierde niciun acces, inclusiv unul
în care grupul e `owner_chat_id`. Completarea listei e alegerea operatorului,
nu ceva impus la actualizare.

Când lista e completată și chatul e un grup (sau un canal): expeditorul
(`update.effective_user.id`) trebuie să fie și el pe listă. Un update pentru
care Telegram nu dă niciun expeditor — o postare de canal, de exemplu, unde
autorul nu e niciodată expus botului, doar canalul ca `sender_chat` — e
**refuzat**, nu acceptat implicit: o acțiune pe care nimeni nu poate fi numit
responsabil nu e una pe care acest bot o face.

Verificarea se face ca middleware, **pe fiecare tip de update** — `message`,
`callback_query`, `edited_message`, `my_chat_member` — fiindcă citește doar
`update.effective_chat` și `update.effective_user`, aceleași două proprietăți
pe care python-telegram-bot le completează identic indiferent de tipul real al
update-ului. Bug-ul clasic e să verifici doar `message` și să lași
callback-urile deschise; `on_flush_callback` (butonul PANIC) chiar avea acest
bug — verifica doar rolul (`_can_act`), nu și `_authorized` — până pe 6
septembrie 2026, și era singurul buton pe care un membru neautorizat al
grupului tot îl putea apăsa după ce toate celelalte căi fuseseră închise.
`tests/security/test_telegram_group_sender_check.py` acoperă toate patru.

Consecința practică, dincolo de `allowed_user_ids`: a adăuga pe cineva într-un
grup din allowlist tot înseamnă a-i da drepturile chatului, dacă lista de
utilizatori nu e completată. Nu există un nivel „doar vede alertele" separat de
asta — rolurile din tabelul de mai sus se aplică pe chat, iar restrângerea pe
persoană e un mecanism suplimentar, nu unul implicit.

---

## 3. Comenzi

**Tabelul ăsta a fost corectat pe 8 septembrie 2026** — enumera în jur de
cincisprezece comenzi care nu există în cod (`/allow`, `/scan`, `/restore`,
`/actor`, `/top`, `/traffic`, `/watch`, `/plan`, `/report`, `/predict`,
`/version`, `/config`, `/budget`…) și lipsea câteva care există
(`/dashboard`, `/evenimente`, `/expuneri`, `/rezolva`, `/fp`, `/stiu`,
`/comportament`, `/intreaba`). Lista de mai jos e derivată din
`sentinel/telegram/bot.py::COMMANDS` — aceeași tabelă din care botul își
publică propriul meniu (`/ajutor` arată exact asta) —, nu scrisă separat.
Fiecare comandă are un nume canonic (primul din paranteza de alias) și, unde
există, câteva alias-uri românești sau englezești care fac același lucru.

### Stare (doar citire)

| Comandă | Alias-uri | Ce face |
|---|---|---|
| `/ajutor` | `/start`, `/help` | Meniu cu toate comenzile, pe grupe |
| `/dashboard` | `/panou` | Verdict, cifre, observații, top atacatori |
| `/status` | — | O linie: incidente deschise și servicii |
| `/incidente` | `/incidents` | Ultimele incidente deschise |
| `/incident <id>` | — | Dosarul unui incident: cronologie, actor, evidențe |
| `/vulnerabilitati [filtru]` | `/vulns` | Vulnerabilități deschise, prioritizate. Filtru: `kev`, `critice`, `mari`, sau categoria pe care stau — `sistem`, `container`, `aplicatie`, `necunoscut` (aceleași ca pastilele din panou). Filtrul se aplică în interogare, iar antetul spune câte se arată, câte sunt în categoria cerută și câte sunt deschise în total. Un filtru neînțeles e spus, nu ignorat |
| `/vuln <id>` | — | Detaliul unei vulnerabilități, căutat după id (nu printre primele N) — inclusiv una deja rezolvată, care se spune ca atare |
| `/evenimente [ip]` | `/events` | Evenimente brute, opțional filtrate pe un IP |
| `/servicii` | `/services` | Fiecare serviciu: activ, degradat sau picat |
| `/health` | `/sanatate` | Capacitatea gazdei: CPU, RAM, disc, conexiuni |
| `/selfcheck` | `/autoverificare` | Chiar funcționează Sentinel? fiecare componentă |
| `/comportament` | `/behaviour`, `/profil` | Ce a învățat agentul despre ce e normal aici |
| `/blocklist` | `/blocate` | Ce IP-uri sunt blocate acum, și până când |
| `/expuneri` | `/exposures`, `/expunere` | Ce ascultă pe toate interfețele, și dacă e intenționat |
| `/patches` | `/patch`, `/patchuri` | Planuri de patch în așteptare; `/patch 3` pentru unul |
| `/intreaba <întrebare>` | `/ask` | Întrebare liberă peste baza de date, read-only |

### Răspuns (schimbă starea — vezi §8 pentru mențiunea în grup)

| Comandă | Alias-uri | Ce face |
|---|---|---|
| `/rezolva <id> [notă]` | `/resolve` | Închide un incident |
| `/fp <id>` | `/falspozitiv` | Închide un incident ca fals-pozitiv |
| `/stiu <cheie> [nu]` | `/ack` | Marchează o expunere ca intenționată, sau anulează marcajul |
| `/planifica <id vuln>` | `/genereaza` | Cere un plan de remediere pentru o vulnerabilitate anume — vezi §3.2 |
| `/block <ip> [durată]` | `/blocheaza` | Blochează un IP, cu confirmare. Durata: `1h`, `30m`, secunde, sau `perm` — între 60s și 30 de zile |
| `/unblock <ip>` | `/deblocheaza` | Deblochează un IP |
| `/panic` | — | **Golește tot blocklist-ul, imediat.** Dublă confirmare. Disponibilă chiar și pe mute |
| `/mute` | `/liniste` | Ore de liniște pentru acest chat — vezi §3.1 |
| `/unmute` | — | Repornește alertele, oprind ambele mecanisme |

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

Planurile de patch se **aprobă** prin butoane, nu prin comenzi separate de tipul
`/plan` sau `/restore` — vezi `/patches` mai sus și §4 pentru fluxul de
aprobare în doi pași. A **cere** un plan e altceva, și pentru asta există
`/planifica` (§3.2). `/plan`, `/restore`, `/scan`, `/report`, `/predict`,
`/version`, `/config` și `/budget` nu există în cod; erau documentate aici fără
să fi fost implementate vreodată.

### 3.2 `/planifica <id vulnerabilitate>` — cere un plan

Generarea automată (`planner.generate_for_kev`) redactează planuri doar pentru
vulnerabilitățile din catalogul KEV care au și o versiune care le repară.
Deliberat: un apel la model costă bani, iar un plan pentru ceva ce nimeni nu
exploatează „poate aștepta să ceară un om". Pe gazdă, mulțimea aceea e goală —
1028 de findinguri deschise, 857 cu remediere cunoscută, un singur KEV și niciun
KEV cu remediere (măsurat pe 15 septembrie 2026). Rezultatul: ultimul plan
generat pe 3 august, și nicio cale prin care omul să ceară.

```
/planifica 7      cere un plan pentru VULNERABILITATEA #7 (id din /vulnerabilitati)
/patch 3          arată PLANUL #3 (alt id, alt lucru)
```

Ce se întâmplă:

1. Se verifică, din bază, cinci lucruri, înainte de orice cost: findingul
   există, e încă deschis, e un pachet al gazdei, are o versiune care îl repară,
   și nu are deja un plan viu. Un plan viu **nu** e înlocuit — răspunsul trimite
   la el. Ca să ceri altul, respinge-l întâi de pe butonul lui.
2. Cererea pleacă într-un task separat, iar botul confirmă imediat: generarea
   ține zeci de secunde, iar botul răspunde la comenzi una câte una. Cât timp
   rulează, o a doua apăsare pe același finding e refuzată, și nu pot rula mai
   mult de două generări deodată.
3. Rezultatul vine ca mesaj separat, oricare ar fi el: planul cu butoanele de
   aprobare, sau motivul exact — erorile validatorului (planul respins rămâne în
   bază ca dovadă), plafonul de buget cu cifrele lui, sau faptul că asset-ul e
   protejat și se aplică manual.

**Ce se poate planifica** (adăugat pe 15 septembrie 2026): doar pachetele de
sistem ale gazdei — `rpm` pe familia `rhel`, `deb` pe `debian`, după
`platform.family`. Din cele 857 de findinguri cu remediere cunoscută ale gazdei
de producție, 407 sunt `npm`, `alpine`, `go`, `composer` sau `deb` găsite de
Trivy în imagini de container și în lockfile-uri de aplicație — iar primele 12
după prioritate sunt toate din categoria aia. Ele nu se repară de pe gazdă:
`npm`, `pip`, `composer`, `docker` și `git` au fost scoase din allowlist-ul
executorului (§10 din `docs/PATCHING.md`), iar planner-ul scrie pentru `dnf`.
Cererea e deci refuzată pe loc, cu motivul — altfel costa până la două apeluri
Opus ca să se termine în `rejected_invalid` sau într-un plan `dnf` plauzibil
pentru un pachet Alpine, care pică abia la dry-run.

**Verdictul de întoarcere**, scris sub plan, lângă butoane: aceeași funcție pe
care o folosește fereastra săptămânală (`patch/window.py:evaluate`), nu o copie
a ei. Trei stări:

| Verdict | Ce înseamnă | Butonul „Aplică" |
|---|---|---|
| întoarcere dovedită | planul are un backup `path` și ultimul exercițiu de restaurare a dovedit o arhivă restaurabilă, recent | rămâne |
| întoarcere **nedovedită** | nu există (încă) dovadă — azi, pe amândouă gazdele, e cazul fiecărui plan: niciun exercițiu n-a atins vreodată o arhivă | rămâne, cu verdictul scris lângă el |
| **fără cale de întoarcere** | planul se declară irevocabil, sau ultimul exercițiu a găsit o arhivă care nu se reface | **retras** — rămân doar Dry-run și Respinge |

Butonul se retrage doar în ultima stare: ascuns și la „nedovedită", n-ar apărea
niciodată, iar comanda ar fi inutilă din prima zi. Retragerea e a MESAJULUI
acesta: `/patch <id>` arată planul cu butoanele lui obișnuite, fiindcă poarta de
execuție rămâne, ca până acum, `window_halt` din a doua atingere.

Un plan cerut așa și neatins **expiră după 72 de ore** (`PLAN_TTL_HOURS`),
prin trecerea orară de mentenanță — altfel findingul lui n-ar mai putea primi
niciodată alt plan.

Comanda cere rol de **operator sau owner**: cheltuie un apel la model.

---

## 4. Butoane

**Corectat pe 8 septembrie 2026** — tabelul enumera butoane fără niciun
producător în cod (`🔍 Detalii`, `👁 Watch`, `🔇 Suprimă regula 1h`,
`🔒 Permanentizează`, `📊 Vezi activitatea`, tot rândul „Vulnerabilitate" și
tot rândul „Serviciu picat"). Ce chiar există:

| Context | Butoane |
|---|---|
| Incident, cu actor IP | `🚫 Blochează <ip> (Nh)` · `❌ Ignoră` — sau, dacă auto-block a acționat deja, `↩️ Deblochează <ip>` · `✔️ OK, lasă blocat` |
| `/block` (confirmare) | `✅ Blochează <ip> (durată)` · `❌ Anulează` |
| `/panic` (confirmare) | `🚨 Golește TOT blocklistul` · `❌ Anulează` |
| Logare neobișnuită | `✔️ Am văzut` · `🚨 Nu sunt eu` (blochează adresa sesiunii ȘI o închide) |
| Plan de patch | `🧪 Dry-run` · `✅ Aplică…` · `❌ Respinge`, apoi la a doua atingere `✅ DA, aplică acum` · `❌ Renunț` |

**`✅ Fals pozitiv`, „Watch" și butoanele de pe o vulnerabilitate sau pe un
serviciu picat nu există** — dacă operatorul are nevoie de ele, e o comandă
de scris, nu o corectare de documentație.

---

## 5. Securitatea butoanelor

Telegram limitează `callback_data` la 64 de octeți și îl trimite înapoi de la
CLIENT, nu de la server — deci poate fi rejucat și modificat de oricine poate
vedea mesajul, nu doar reluat identic.

**Pentru `blk:`/`unblk:`** (blocare/deblocare manuală sau din alerta unui
incident): payload-ul e semnat inline, în `callback_data` însuși —
`sentinel/telegram/callback_sign.py`. IP-ul e codat binar (`ip.packed` +
base64, nu text — un IPv6 necomprimat n-ar încăpea altfel în 64 de octeți),
alături de TTL, id-ul incidentului care a emis butonul (0 pentru o comandă
manuală, fără incident) și momentul emiterii, totul acoperit de o etichetă
HMAC-SHA256 trunchiată, semnată cu **`TELEGRAM_CALLBACK_HMAC_KEY`** — o cheie
separată de tokenul botului, ca un token de bot scurs să nu permită și
falsificarea unei blocări. Verificată la apăsare: o semnătură care nu se
potrivește sau un buton mai vechi decât `callback_ttl_s` (implicit 600s) e
refuzat, nu executat — mesajul spune „buton expirat, folosește /block" (sau
`/unblock`), nu doar „eroare". **Coloana `telegram_callbacks` din schema de
migrare rămâne nescrisă** — varianta implementată e cea descrisă mai sus, nu
un tabel de tokene single-use pe server; dacă varianta cu tabel e preferată
mai târziu, e o schimbare de proiectare, nu o extindere a asteia.

**O semnătură validă rejucată ÎN interiorul TTL-ului tot funcționează.**
Schema n-are unicitate per-token — doar expirare — deci fereastra practică de
rejucare e cea a `callback_ttl_s` (implicit 600s), nu zero.

**Butonul „🚨 Nu sunt eu"** (`nteu:`, de pe fiecare alertă de logare) e semnat
la fel, cu o formă mai scurtă (`nteu:id_b36:issued_b36:sig` —
`sentinel/telegram/callback_sign.py::sign_session_action`): fără IP, TTL sau
`ref`, fiindcă la momentul emiterii nu există o adresă de purtat — se
citește din `login_sessions` abia la apăsare (vezi §4). TTL-ul de verificare
nu e purtat în payload, ci e o constantă a botului (`bot.NTEU_TTL_S`, 7
zile) — mult mai lung decât `callback_ttl_s`, fiindcă butonul e gândit să
fie apăsat ore mai târziu, nu în minutele imediat următoare unei alerte.
Fără semnătură, orice membru cu drept de acțiune al chatului putea trimite
manual `nteu:<id secvențial>` și termina orice sesiune ghicită — inclusiv una
de pe o adresă din allowlist, unde efectul e să-ți închizi singur propriul
SSH.

**Pentru planurile de patch** (`pap1:`/`pap2:`/`pdry:`/`prej:`), mecanismul e
diferit și mai vechi: tokenul din `callback_data` e opac, iar payload-ul real
stă pe server, în `approval_tokens` — single-use, cu TTL, legat de
`(chat, plan, plan_hash)`. **Dacă planul se regenerează, hash-ul se schimbă
și toate butoanele din mesajele anterioare mor.** Nu poți aproba planul A și
să se execute planul B.

`✅ Aplică` nu execută niciodată direct. Deschide o a doua confirmare care
restatează ținta, downtime-ul estimat și dimensiunea backup-ului — ca un tap
greșit pe un mesaj vechi să fie vizibil înainte să facă ceva.

Toate argumentele sunt tipizate și validate înainte să ajungă la vreun handler:
IP-urile prin `ipaddress`, id-urile ca întregi, TTL-urile mărginite între 60s și
30 de zile, motivele limitate ca lungime și curățate de caractere de control.
`/block '; rm -rf /'` este respins de validarea IP-ului, nu de un filtru de
escaping.

### 5.1 La livrare: butoanele vechi mor

`TELEGRAM_CALLBACK_HMAC_KEY` e citită și verificată abia din versiunea asta —
înainte, câmpul era cerut la `sentinel config-check` și necitit de nimic.
Orice buton `blk:`/`unblk:` trimis de o versiune ANTERIOARĂ acestei livrări
poartă adresa ca text simplu, fără semnătură: după livrare, `on_callback` îl
respinge ca „nevalid" (nu se poate decoda ca payload semnat), nu ca „expirat".
Același destin îl are un buton `nteu:` emis de o instalare mai veche decât
semnarea lui — `on_callback` îl respinge la fel, nu îl execută pe formatul
vechi. **Alertele deja trimise în chat, din instalarea veche, nu mai pot fi
blocate/închise din buton — doar prin `/block <ip>` scris de mână.** Nu e o
pierdere: e limita firească a unei semnături introduse retroactiv. Ordinea
de livrare care contează:

1. `TELEGRAM_CALLBACK_HMAC_KEY` trebuie să existe în `secrets.env` (`openssl
   rand -hex 32`) ÎNAINTE de repornirea lui `sentinel-telegram` — altfel
   procesul nu pornește (`Secrets.require` ridică la construirea aplicației).
2. Imediat după repornire, butoanele vechi din chat devin inerte. Alertele
   NOI (de după repornire) au butoane funcționale.
3. Dacă instalarea are `allowed_user_ids` de completat (§2.1) și HMAC-ul de
   introdus în aceeași fereastră de mentenanță, ordinea dintre ele nu
   contează una față de alta — dar amândouă trebuie să fie deja în cod și
   livrate PE GAZDĂ înainte de a fi scrise în configurație, din același motiv
   ca la §2.1: o cheie de configurare pe care codul vechi n-o cunoaște oprește
   fiecare unitate care încarcă `sentinel.yaml`.

---

## 6. Volumul notificărilor

**Corectat pe 8 septembrie 2026** — secțiunea vorbea despre o fereastră de
5 minute și un fișier `/etc/sentinel/notifications.yaml` pe care nimic în cod
nu le citește. Ce chiar există, verificat în `sentinel/telegram/bot.py`:

- **Critic** trece întotdeauna: peste ore liniștite, peste mute, fără digest
  — `passes_anyway` din `telegram/quiet.py`.
- **Digestul e după NUMĂR de incidente în așteptare, nu după un interval de
  timp.** Când mai multe de `telegram.digest_threshold` (implicit 10, dar
  niciodată mai puțin de 6) așteaptă să fie trimise ÎN ACELAȘI CICLU al
  buclei de push (la 15 secunde), pleacă ca un singur mesaj cu totaluri pe
  severitate, nu unul per incident. Nu e restrâns la severitatea „medie" —
  un lot mixt de incidente intră în digest la fel.
- **Fingerprint-ul unui incident DESCHIS se actualizează, nu se dublează**:
  o nouă detecție pe același `fingerprint`, cât timp incidentul e încă
  `open`/`acknowledged`, crește `detection_count` pe rândul existent
  (`sentinel/db/repo/incidents.py::upsert_incident`) în loc să deschidă un
  incident nou — un atac prin forță brută rămâne un singur incident, nu
  patru sute. Dacă asta se traduce și într-o singură alertă Telegram (nu doar
  un singur RÂND în bază) depinde de codul care decide când să împingă
  push-ul unui incident existent — cod din afara acestui fișier
  (`sentinel/detect/`), neverificat aici.

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

**Corectat pe 8 septembrie 2026** — rândul de mai jos spunea că PIN-ul acoperă
și „modificarea allowlist-ului"; nu există nicio asemenea comandă (vezi §3),
iar afirmația n-a fost niciodată adevărată în cod. PIN-ul condiționează DOAR
a doua confirmare la aplicarea unui plan de patch.

Ca apărare în adâncime, dacă telefonul poate fi pierdut sau furat: setează
`TELEGRAM_APPLY_PIN` în `secrets.env` și `telegram.require_pin_for_apply: true`.
A doua atingere de pe „✅ Aplică" nu mai rulează planul direct — botul cere un
răspuns (reply, în chat, la promptul lui) cu PIN-ul, în cel mult 5 minute, cu
maxim 3 încercări greșite înainte să anuleze cererea și să ceară planul din
nou (`sentinel/telegram/patch_flow.py::on_pin_reply`). Fără PIN-ul corect,
`approve_plan` nu se cheamă deloc — hoțul care are telefonul deblocat tot nu
poate aplica un patch fără să știe și PIN-ul.

**Corectat pe 8 septembrie 2026, runda 3: răspunsul cu PIN-ul nu mai e
jurnalizat.** Handlerul care primește replica (`sentinel/telegram/bot.py::
_pin_guard`) nu e cel folosit pentru comenzi obișnuite (`_guard`) — acela
scrie textul mesajului acceptat în journald la fiecare comandă, ceea ce
pentru un PIN ar însemna PIN-ul însuși, corect SAU greșit, în clar, citibil
de uid-ul `sentinel` pe ambele gazde. `_pin_guard` nu scrie niciodată textul
mesajului și nu numără răspunsul ca o comandă — jurnalizează o singură
linie, `"pin attempt"`, doar cu rezultatul (`ok`/`wrong`/`expired`/`ignored`)
și chat_id-ul. Un răspuns obișnuit trimis în chat cât timp, din întâmplare,
un PIN e în așteptare — o replică la altceva — nu produce nicio linie: nu e
o încercare de PIN, și numărarea lui ca atare (chiar și fără textul lui) ar
fi exact defectul „înghite orice a sosit" pe care verificarea promptului
(mai sus, §17 din OPERARE.md) există să-l închidă.

**Ce rămâne adevărat indiferent de jurnal**: PIN-ul tastat ca răspuns e un
mesaj Telegram obișnuit și rămâne în istoricul conversației — Telegram nu-l
șterge. Jurnalul botului nu-l mai poartă, dar istoricul chatului tot îl
poartă; vezi OPERARE.md §17 pentru nota operațională completă despre asta.

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

### Comenzile scrise de mână nu se rutează singure

Butoanele se rutează singure (mai sus); o **comandă tastată** (`/block ...`),
nu. Ambele boturi citesc din același grup, deci un `/block 203.0.113.7` scris
FĂRĂ nicio mențiune ajunge la amândouă deodată — și fiecare îl execută pe
propria gazdă. O singură comandă tastată o dată blochează aceeași adresă pe
două servere de producție.

**Decizie, luată și documentată aici** (8 septembrie 2026), nu doar codată
tăcut: comenzile care schimbă starea (`/block`, `/unblock`, `/panic`,
`/mute`, `/unmute`, `/rezolva`, `/fp`, `/stiu` — tabelul §3, coloana
„Răspuns") CER mențiunea botului într-un chat care nu e privat:

```
/block@sentinel_gazda_a_bot 203.0.113.7 1h
```

Fără ea, botul răspunde cu un indiciu (numele lui propriu, citit din
Telegram — nu dintr-o valoare de configurare) și NU execută nimic. Comenzile
doar-citire (`/status`, `/incidente`, `/selfcheck`, `/dashboard`…) rămân fără
mențiune — **ambele boturi răspund**, dar informația repetată e zgomot, nu o
acțiune dublă, și cerința ar fi doar frecare fără niciun folos pentru ele.

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

**Apartenența la grup e autoritate, dacă `allowed_user_ids` rămâne gol.** Vezi
§2.1: fără acea listă, autorizarea de bază se face pe `chat.id`, nu pe
expeditor, deci oricine e în grup are drepturile grupului, pe toate instanțele
deodată, inclusiv blocare de adrese acolo unde auto-block e activ. Cu grupul ăsta
partajat între mai multe instanțe, aici e locul unde completarea listei
contează cel mai mult: fiecare instanță își citește propriul
`allowed_user_ids` din `sentinel.yaml`, deci restrângerea poate diferi de la o
gazdă la alta chiar dacă grupul e același.

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

