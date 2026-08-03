# Patching sigur

Cum generează Sentinel o procedură de patch, ce o oprește să fie periculoasă, și
ce faci când eșuează.

---

## 1. Principiul

**Generarea este automată. Aplicarea nu este niciodată.**

Un plan scris de un model nu ajunge la execuție fără să treacă printr-un
validator determinist, iar apoi prin două confirmări explicite ale tale.

---

## 2. Fluxul

```
finding (vulnerabilitate deduplicată, prioritizată)
   ↓  /patch <id>  sau  butonul din UI  sau  jobul nocturn pentru KEV critice
context: asset, stack, unit, webroot, repo, baze de date, patch-uri anterioare
   ↓
claude -p --permission-mode plan  →  subagentul sentinel-patch-engineer
   ↓  citește fișierele REALE de pe server (nginx -T, systemctl cat, lockfile, rpm -q)
plan JSON
   ↓
VALIDATOR DETERMINIST  ──✗──▶  un retry cu erorile reinjectate
   ↓ ✓                    ──✗──▶  rejected_invalid, operatorul e informat
plan stocat + hash
   ↓
mesaj Telegram cu butoane
   ↓  ✅ Aplică  →  a doua confirmare (restatează ținta, downtime, backup)
executor (root), pas cu pas
   ↓
preflight → backup → apply → health check → post-verificare
   ↓ ✗ oricând
ROLLBACK AUTOMAT + notificare obligatorie
```

---

## 3. Ce oprește validatorul

Non-negociabil, în `sentinel/patch/validator.py`:

| Regulă | De ce |
|---|---|
| Fiecare comandă e **listă argv**, niciodată string | Nu există shell. Un string nu poate fi executat, iar prezența lui înseamnă că planul a fost scris pentru un shell care nu există |
| `argv[0]` în allowlist | `sh`, `bash`, `env`, `sudo`, `python` lipsesc deliberat — ar transforma allowlist-ul în nimic |
| Fără metacaractere de shell | `\|`, `;`, `&&`, `$(`, `>`, backtick. Un pipeline se sparge în pași |
| Căi interzise | `/opt/sentinel`, `/etc/sentinel`, `/root/.ssh`, `/etc/ssh`, `/etc/shadow`, `/etc/sudoers`, `/boot`, `firewalld`, `nft` — plus tot ce ai pus în `patch.extra_protected_paths` |
| Backup obligatoriu | Dacă vreun pas de aplicare nu e idempotent |
| Rollback obligatoriu | Dacă planul se declară reversibil. Dacă nu poate scrie unul, trebuie să declare `reversible: false` — planul devine `high_risk` și cere aprobare suplimentară. **Nu are voie să inventeze un rollback** |
| Backup de bază de date | Dacă asset-ul are baze de date înregistrate. Un backup doar de fișiere nu anulează schimbări de schemă |
| Preflight blocant | Minim unul. Altfel nimic nu împiedică patch-ul să ruleze peste o stare neașteptată |
| `disk_free` în preflight | Dacă există backup. Un backup într-un filesystem plin eșuează la jumătate și nu lasă cale de întoarcere |
| `requires_reboot` | Obligatoriu pentru kernel, glibc, systemd, openssl, dbus. Declanșează o aprobare separată |
| Comenzi nedeterministe respinse | `git pull` (folosește `git checkout <sha>`), `npm install` (folosește `npm ci`), `:latest` (pin pe digest) |
| `timeout_s` pe fiecare pas | Un pas blocat oprește coada |

Un plan invalid de două ori se stochează ca `rejected_invalid` și ți se spune că
AI-ul nu a putut produce o procedură sigură. **Este un rezultat acceptabil** — și
mult mai bun decât un plan plauzibil care rupe producția.

---

## 4. Aprobarea

Mesajul Telegram arată: asset, CVE + EPSS + insignă KEV, nivel de risc, downtime
estimat, rezumatul backup-ului, numărul de pași.

`✅ Aplică` **nu execută niciodată direct.** Deschide o a doua confirmare care
restatează ținta exactă:

> „Confirmi aplicarea planului `abc123` pe `blog.exemplu.ro`?
>  Downtime estimat 25s. Backup: 340 MB. Rollback automat: DA."

Tokenul de confirmare este single-use, cu TTL de 10 minute, și legat de
`(chat_id, plan_id, plan_hash)`.

**Dacă planul se regenerează, hash-ul se schimbă și toate butoanele din mesajele
anterioare mor.** Nu poți aproba planul A și să se execute planul B.

Butonul `🧪 Dry-run` execută preflight-ul și verificările fără să schimbe nimic.
Folosește-l prima dată pe fiecare asset.

---

## 5. Backup și restaurare

```
/var/backups/sentinel/<restore_point_id>/
├── manifest.json      fiecare item: tip, sursă, artefact, dimensiune, sha256, comandă de restaurare
├── restore.sh         STANDALONE — funcționează cu Sentinel complet oprit
└── artefacte comprimate zstd
```

`restore.sh` este calea manuală de scăpare. Funcționează fără Sentinel pornit și
fără baza de date — exact situația în care îl vei citi.

Checksum-urile se verifică imediat după creare. O nepotrivire **oprește patch-ul
înainte de orice pas de aplicare**.

Preflight-ul cere de **3× dimensiunea estimată** liberă.

### Retenție

Se păstrează ultimele 10 puncte, **și** tot ce e mai nou de 30 de zile, **și
întotdeauna cel mai recent punct reușit per asset**, indiferent de vechime
(`retention_hold`).

Nu se șterge niciodată singura cale de întoarcere. Dacă retenția ar lăsa un
asset cu zero puncte, păstrează unul și loghează.

---

## 6. Testul trimestrial de restaurare

Un backup pe care nimeni nu l-a restaurat nu este un backup.

Sentinel îți amintește la 90 de zile. Procedura, pe canary, nu pe producție:

```bash
# 1. Alege un punct de restaurare recent
/restore

# 2. Oprește TOT Sentinel — testezi calea manuală, nu pe cea automată
sudo systemctl stop 'sentinel-*'

# 3. Restaurează
sudo /var/backups/sentinel/<id>/restore.sh

# 4. Verifică serviciul
systemctl status <unit> && curl -sI https://<asset>/

# 5. Repornește Sentinel
sudo systemctl start sentinel-executor sentinel-web
```

Înregistrează rezultatul:
```sql
INSERT INTO restore_drills (restore_point_id, performed_by, succeeded, notes)
VALUES (<id>, 'operator', true, 'test trimestrial');
```

---

## 7. Când un patch eșuează

### Rollback automat a reușit

Serviciul e pe versiunea anterioară. Nu trebuie să faci nimic imediat.

Primești o notificare **indiferent de setările de mute** — un rollback înseamnă
că ceva a mers prost pe un server de producție.

Citește urma:

```bash
SQ=/opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py
sudo /opt/sentinel/venv/bin/python $SQ patch_steps --param execution_id=<id> --format table
```

Rândurile din `patch_steps` se scriu **înainte** de pasul următor, deci ai urma
completă chiar dacă procesul a murit la mijloc. Ultimul rând cu
`status='running'` este pasul care a eșuat.

### Rollback-ul a eșuat

`status='rollback_failed'`. Cazul cel mai prost, și alertează întotdeauna.

```bash
ls /var/backups/sentinel/
sudo /var/backups/sentinel/<restore_point_id>/restore.sh
```

### Patch-ul a reușit dar finding-ul persistă

Post-verificarea re-rulează exact verificarea pe care o va face scanerul la
următoarea rulare. Dacă tot se declanșează, statusul devine
`apply_succeeded_but_not_resolved`.

Nu e o eroare — e informație. Înseamnă de obicei că versiunea corectată nu
rezolvă de fapt CVE-ul, sau că mai există o instalare a aceleiași componente în
altă parte.

---

## 8. Ce nu se patchează niciodată automat

| Asset | De ce |
|---|---|
| Sentinel însuși | Upgrade-urile trec prin `deploy/upgrade.sh` |
| Orice din `patch.extra_protected_paths` | Ce ai declarat tu ca fiind în afara limitelor: alt produs, o bază de date critică, un mount al altcuiva |
| `sshd` | `sshd_config` e pe lista de căi interzise. O configurație SSH greșită înseamnă pierderea accesului |
| Orice cu `protected: true` | Setat de tine în `inventory.yaml` |

Pentru acestea, `sentinel-vuln-analyst` marchează finding-ul
`requires_manual_intervention: true` cu o explicație scrisă, iar
`sentinel-patch-engineer` returnează un obiect de eroare cu
`reason_code: protected_asset` și, dacă există, o procedură manuală.

Kernel, glibc, systemd, openssl și dbus se pot patcha, dar planul trebuie să
declare `requires_reboot: true`, ceea ce cere o aprobare separată — ca să nu fii
surprins de un restart.

---

## 9. Prima dată pe un asset nou

1. `/vuln <id>` → `🛠 Generează plan`
2. `📄 Vezi` — citește-l efectiv. Verifică:
   - versiunea din preflight corespunde cu ce e instalat
   - backup-ul acoperă **și** fișierele **și** baza de date
   - rollback-ul e o comandă reală, nu „restaurează din backup"
   - downtime-ul estimat e plauzibil
   - presupunerile din `assumptions_ro` sunt adevărate
3. `🧪 Dry-run`
4. `⏰ Programează 03:00` dacă asset-ul are trafic
5. `✅ Aplică` → confirmă

Pentru orice asset cu `criticality ≥ 4`, fă prima dată exercițiul pe un canary,
inclusiv ruperea deliberată a health check-ului ca să verifici că rollback-ul
chiar funcționează.
