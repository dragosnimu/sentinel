# Martorul extern — aplicație Next.js de sine stătătoare

Jumătatea din afara serverului monitorizat. Primește semnalul periodic de la
Sentinel, iar când semnalul se oprește sau contoarele încetează să avanseze,
alertează pe Telegram — **de pe altă mașină decât cea compromisă.**

Asta e toată ideea: un agent găzduit nu poate garanta că raportează propria
dispariție, fiindcă cine îl oprește controlează și canalul.

E o aplicație completă, nu un set de fișiere de copiat undeva. Trei dependențe
în total — Next, React, React DOM — fiindcă fiecare dependență a unei componente
de securitate e suprafață de atac, iar o pagină care arată un singur verdict nu
are nevoie de un sistem de design.

## Ce conține

```
app/page.tsx                       pagina de stare (singura interfață)
app/api/sentinel/beat/route.ts     primește semnalul
app/api/sentinel/check/route.ts    întreabă „a tăcut?" și alertează
app/api/sentinel/status/route.ts   200 dacă e viu, 503 dacă nu
lib/store.ts  lib/verify.ts  lib/telegram.ts
```

## Instalare pe Hostinger

Panoul hPanel, secțiunea Node.js (sau Website → Hosting → Node.js, în funcție
de plan). Aplicația e construită cu `output: "standalone"`, deci merge și pe
planuri fără npm pe server.

**Varianta A — build pe server**, dacă planul permite:

```bash
npm ci
npm run build
npm start          # sau comanda de start din panou
```

**Varianta B — build local, urci rezultatul.** Necesară pe planurile fără
toolchain de build:

```bash
npm ci && npm run build
# urci: .next/standalone/, .next/static/ (în .next/standalone/.next/static/),
#       public/ dacă există
# pornire: node server.js
```

Variabilele de mediu se pun în panou, nu într-un fișier urcat. Vezi
`.env.example` pentru lista completă.

**Domeniu:** un subdomeniu separat e mai curat decât o cale pe site-ul
principal — de exemplu `martor.domeniul-tau`. Ține martorul independent de
publicarea site-ului, ca o schimbare de conținut să nu îl poată opri din
greșeală.

## Variabile de mediu

| Variabilă | Ce e |
|---|---|
| `SENTINEL_BEACON_SECRET` | cheia HMAC. **Aceeași** valoare ca pe serverul monitorizat |
| `SENTINEL_CHECK_SECRET` | secret separat, protejează ruta `/check` |
| `TELEGRAM_BOT_TOKEN` | același bot ca Sentinel (vezi mai jos) |
| `TELEGRAM_CHAT_ID` | unde ajung alertele |
| `SENTINEL_STATE_PATH` | opțional; unde se scrie starea. Implicit în `cwd` |

Generarea celor două secrete:

```bash
openssl rand -hex 32
```

## Cine întreabă „a tăcut?"

**Ruta `/check` nu se execută singură.** O rută API rulează doar când primește o
cerere, iar un martor care rulează doar la cerere nu poate observa o absență.
Cineva trebuie să întrebe periodic. Două variante, ideal amândouă:

**Cron pe găzduire**, la fiecare 5 minute:

```
*/5 * * * * curl -fsS "https://DOMENIUL-TAU/api/sentinel/check?key=SECRETUL_DE_CHECK" >/dev/null
```

**Un monitor de uptime** îndreptat spre `/api/sentinel/status`. Întoarce `503`
când semnalul e vechi, deci alertarea proprie a monitorului devine escaladarea
ta. Nu cere cron, dar adaugă un terț în lanț.

## Verificat local, înainte de a-l primi

Aplicația a fost compilată și rulată, iar drumul complet a fost testat cu
expeditorul real din Python: 16 verificări cap-coadă, toate trecute — semnal
autentic acceptat, semnătură invalidă refuzată cu 401, reluare refuzată cu 409,
semnal vechi refuzat cu 400, ruta de check protejată, contoarele care nu
avansează detectate corect, pagina randată, `no-store` prezent.

Plus alarma însăși: cu ultimul semnal îmbătrânit la 10 minute, `/status` a
căzut la 503 și `/check` a produs verdictul `silent`.

Ce NU e verificat e comportamentul pe Hostinger — CDN-ul, persistența
fișierului de stare între publicări, cronul. Alea se verifică o singură dată,
mai jos, și merită făcute înainte să te bazezi pe martor.

## Verificarea de acceptanță

Fără ea nu știi dacă funcționează, iar un martor despre care crezi că
funcționează e mai rău decât niciunul.

```bash
# 1. Semnalul sosește
curl -s https://DOMENIUL-TAU/api/sentinel/status
#    -> {"status":"ok","age_s":<sub 60>}

# 2. O semnătură greșită e refuzată
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'X-Sentinel-Signature: gresit' -d '{}' \
  https://DOMENIUL-TAU/api/sentinel/beat
#    -> 401

# 3. Ruta de check nu e deschisă
curl -s -o /dev/null -w '%{http_code}\n' https://DOMENIUL-TAU/api/sentinel/check
#    -> 401

# 4. CDN-ul nu pune în cache. Două cereri la câteva secunde distanță trebuie
#    să dea `age_s` DIFERIT. Dacă e identic, ruta e în cache și martorul va
#    minți exact când contează.
curl -s https://DOMENIUL-TAU/api/sentinel/status; sleep 5
curl -s https://DOMENIUL-TAU/api/sentinel/status

# 5. Testul care contează: oprești Sentinel de tot și cronometrezi.
#    Pe server:  systemctl stop sentinel-beacon
#    Așteaptă ~3 intervale + până la următorul cron. Trebuie să sune telefonul.
#    Dacă nu sună, nimic din tot mecanismul ăsta nu contează.
```

## De ce același bot Telegram

Un atacator cu root pe serverul monitorizat citește tokenul și poate trimite
mesaje care par ale Sentinel — inclusiv un „totul e în regulă" fals, chiar
înaintea alertei reale. Ce **nu** poate face e să oprească martorul să trimită,
iar asta e proprietatea pentru care există tot mecanismul.

Atenuarea: mesajele martorului poartă prefixul `🛰 MARTOR EXTERN`, pe care codul
de pe server nu îl produce niciodată. Nu e o dovadă criptografică — nimic trimis
prin Telegram nu poate fi — dar face confuzia deliberată vizibilă.

Un bot separat ar fi mai curat. Costă un `/start` în plus și un chat id nou.

## Ce nu apără

Cheia HMAC stă pe mașina monitorizată. Un atacator cu root o citește și poate
fabrica semnale cu contoare care cresc. `audit_head` ridică bariera — capul
lanțului de hash-uri din jurnalul de audit trebuie menținut consistent, nu doar
incrementat — dar nu o face absolută.

Prinde sigur: serviciu oprit, proces căzut, OOM, disc plin, gazdă repornită,
rețea tăiată, ingestie blocată cu procesul viu, atacator care oprește Sentinel
fără să se gândească la consecințe.

Nu prinde sigur un atacator informat și răbdător. Nimic găzduit nu poate.
