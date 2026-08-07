# Ce încarci pe Hostinger

Ecranul cere o arhivă `.zip`, `.tar.gz` sau `.tgz`. Sunt două, pentru două
situații. Alege una singură.

## Dacă planul tău compilează aplicația (are „Build command" în panou)

**`sentinel-watcher-sursa.zip`** — 26 KB.

În panou:
```
Build command:  npm ci && npm run build
Start command:  npm start
```

## Dacă planul tău NU compilează, sau nu ești sigur

**`sentinel-watcher-standalone.tar.gz`** — 17 MB, deja compilat, cu
dependențele incluse.

În panou:
```
Startup file:  server.js
```
Fără build command. Nu rula `npm install` — dependențele sunt deja înăuntru.

**Asta e varianta sigură.** Dacă nu știi ce suportă planul tău, ia-o pe ea.

---

## După încărcare, în ambele cazuri

Variabilele de mediu se pun **în panou**, nu într-un fișier urcat:

| Variabilă | Valoare |
|---|---|
| `SENTINEL_BEACON_SECRET` | `openssl rand -hex 32` — aceeași și pe serverul monitorizat |
| `SENTINEL_CHECK_SECRET` | `openssl rand -hex 32` — alta, diferită |
| `TELEGRAM_BOT_TOKEN` | același bot ca Sentinel |
| `TELEGRAM_CHAT_ID` | unde vin alertele |
| `SENTINEL_STATE_PATH` | o cale în afara aplicației, ex. `/home/UTILIZATOR/sentinel-watcher.json` |

Ultima contează mai mult decât pare: dacă directorul aplicației se șterge la
fiecare publicare, martorul uită tot și pornește de la „niciun semnal încă".

## Verifică în ordinea asta

```bash
# 1. Aplicația trăiește
curl -s https://SUBDOMENIUL-TAU/api/sentinel/status
#    -> {"status":"ok","last_seen":null}   (null e normal, încă n-a venit semnal)

# 2. Nu e deschisă
curl -s -o /dev/null -w '%{http_code}\n' https://SUBDOMENIUL-TAU/api/sentinel/check
#    -> 401

# 3. CDN-ul nu pune în cache. Rulează de două ori la 5 secunde: `age_s` TREBUIE
#    să difere. Dacă e identic, martorul va raporta la nesfârșit ultima stare
#    bună — exact minciuna pe care există ca să o prevină.
curl -s https://SUBDOMENIUL-TAU/api/sentinel/status; sleep 5
curl -s https://SUBDOMENIUL-TAU/api/sentinel/status
```

Abia apoi configurezi expeditorul pe server.

## Ce a fost verificat local

Arhiva standalone a fost extrasă curat și pornită cu `node server.js` — exact
ce va face găzduirea. Pagina se randează, CSS-ul se servește, rutele API
răspund, semnătura invalidă e refuzată cu 401, ruta de check cere cheia, iar un
semnal real trimis din codul Python de pe server a fost acceptat.

Ce NU e verificat: comportamentul CDN-ului Hostinger și dacă fișierul de stare
supraviețuiește unei publicări. Alea se văd doar acolo, cu verificările de mai
sus.
