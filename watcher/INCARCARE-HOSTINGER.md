# Instalarea martorului pe găzduire

Procedura de mai jos **a fost executată și a funcționat** pe
`sentinel.exemplu.eu`, pe 7 august 2026. Nu e o presupunere.

## De ce nu prin ecranul de încărcare

Încărcarea manuală a arhivei prin panou a fost respinsă de trei ori, cu
„Framework neacceptat sau structură de proiect nevalidă", deși Next.js e în
lista de framework-uri suportate. Cauza a fost arhiva, nu frameworkul:

**API-ul cere ca arhiva să conțină DOAR fișiere sursă** — fără `node_modules/`,
fără directorul de build (`.next/`), fără nimic din ce e listat în `.gitignore`.
Prima arhivă trimisă avea și `.next/`, și `node_modules/`. A fost respinsă
corect.

Deploy-ul prin API face același lucru mult mai transparent: dacă build-ul cade,
jurnalele spun de ce, în loc să primești un mesaj generic.

## Ce se trimite

```
app/  lib/  public/
package.json  package-lock.json  tsconfig.json  next.config.mjs
```

Atât. Aproximativ 25 KB. Build-ul instalează dependențele singur pe server.

## Deploy

Cu serverele MCP Hostinger configurate, e o singură operație: se construiește
arhiva din sursă și se apelează `hosting_deployJsApplication` cu domeniul și
calea arhivei. Platforma detectează singură `app_type: next`,
`output_directory: .next` și `build_script: build` din `package.json`.

Rezultatul primului deploy real:

```
Next.js 15.5.23 · Node 20 · compilat în 3,8 s

Route (app)
┌ ƒ /                       ← dinamică
├ ƒ /api/sentinel/beat      ← dinamică
├ ƒ /api/sentinel/check     ← dinamică
└ ƒ /api/sentinel/status    ← dinamică
```

Toate rutele dinamice. O rută de heartbeat prerandată static ar fi inutilă în
modul cel mai tăcut cu putință, deci asta se verifică de fiecare dată.

## Variabilele de mediu

Se pun în panou, la aplicația Node.js. **Nu există API pentru ele** — e singurul
pas care rămâne manual.

| Variabilă | Valoare |
|---|---|
| `SENTINEL_BEACON_SECRET` | `openssl rand -hex 32` — aceeași valoare și în `/etc/sentinel/secrets.env` pe serverul monitorizat |
| `SENTINEL_CHECK_SECRET` | `openssl rand -hex 32` — alta, diferită |
| `TELEGRAM_BOT_TOKEN` | același bot ca Sentinel |
| `TELEGRAM_CHAT_ID` | unde ajung alertele |
| `SENTINEL_STATE_PATH` | o cale **în afara** directorului aplicației |

Ultima nu e opțională în practică. Implicit, starea se scrie în directorul de
lucru al aplicației, iar acela e rescris la fiecare deploy — martorul ar uita
tot și ar porni de la „niciun semnal încă" de fiecare dată când publici.
Pune-o în directorul home, deasupra lui `public_html`.

După ce le setezi, aplicația trebuie repornită ca să le citească. Cu MCP-ul,
asta e `hosting_restartNode_jsApplicationV1`; din panou, butonul de restart.

## Cum se verifică

`beat` întoarce **500 cât timp `SENTINEL_BEACON_SECRET` lipsește** — codul
refuză să pretindă că verifică semnături fără cheie. După configurare, o
semnătură invalidă trebuie să dea 401. Diferența dintre 500 și 401 e exact
diferența dintre „nu sunt configurat" și „te-am refuzat".

```bash
B=https://SUBDOMENIUL-TAU

curl -s $B/api/sentinel/status          # {"status":"ok","last_seen":...}
curl -s -o /dev/null -w '%{http_code}\n' $B/api/sentinel/check      # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
     -H 'X-Sentinel-Signature: gresit' -d '{}' $B/api/sentinel/beat  # 401
```

**Capcana CDN.** Găzduirea servește prin CDN (`Server: hcdn`). O rută de
heartbeat pusă în cache ar întoarce ultimul răspuns bun ore în șir — fix
minciuna pe care mecanismul există ca să o prevină. Verificarea decisivă cere
un semnal deja sosit, ca `age_s` să aibă ce schimba:

```bash
curl -s $B/api/sentinel/status; sleep 6; curl -s $B/api/sentinel/status
```

`age_s` TREBUIE să difere. La primul deploy, antetele arătau
`Cache-Control: no-store` și niciun `x-nextjs-cache`, ceea ce e un semn bun —
dar dovada o dă doar valoarea care se schimbă.

## Testul care contează cu adevărat

După ce expeditorul de pe server e pornit și semnalele sosesc:

```
pe serverul monitorizat:  systemctl stop sentinel-beacon
```

Aștepți trei intervale plus până la următorul cron. **Trebuie să sune
telefonul.** Dacă nu sună, nimic din tot mecanismul ăsta nu contează.
