# Martorul extern — instalare pe găzduirea Next.js

Jumătatea din afara serverului monitorizat. Primește semnalul periodic de la
Sentinel, iar când semnalul se oprește sau contoarele încetează să avanseze,
alertează pe Telegram — **de pe altă mașină decât cea compromisă.**

Asta e toată ideea: un agent găzduit nu poate garanta că raportează propria
dispariție, fiindcă cine îl oprește controlează și canalul.

## Ce se copiază

```
app/api/sentinel/beat/route.ts     primește semnalul
app/api/sentinel/check/route.ts    întreabă „a tăcut?" și alertează
app/api/sentinel/status/route.ts   200 dacă e viu, 503 dacă nu
lib/store.ts  lib/verify.ts  lib/telegram.ts
```

Se pun peste structura `app/` existentă. Importurile folosesc aliasul `@/lib/…`;
dacă proiectul tău nu îl are configurat în `tsconfig.json`, schimbă-le în căi
relative.

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
