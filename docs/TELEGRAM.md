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

Grupurile sunt respinse dacă id-ul grupului nu e explicit în allowlist **și**
expeditorul nu e și el permis — apartenența la un grup Telegram nu este
autentificare.

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
| `/mute <minute>` | Suprimă notificările non-critice. Cele critice trec întotdeauna |
| `/panic` | **Golește tot blocklist-ul, imediat.** Dublă confirmare. Disponibilă chiar și pe mute |

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
