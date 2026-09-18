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
   ↓  /planifica <id vuln>  sau  jobul nocturn pentru KEV cu remediere cunoscută
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

### `pkg_version` — RHEL și Debian, cu epoch

Verificarea de versiune de pachet (`preflight`/`post_verification`, `kind:
pkg_version`) compară `equals`/`at_least` contra versiunii instalate — reparat
8 septembrie 2026, verificarea acceptase orice pachet instalat, indiferent de
versiune, până atunci.

Pe `platform.family: rhel` folosește `rpm -q --qf
%{EPOCH}:%{VERSION}-%{RELEASE}\n` — epoch inclus explicit (producția are 237
de pachete cu unul: `nginx 2:1.20.1-…`, `openssl 1:3.5.5-…`) și `\n` ca separator
de linie, fiindcă `rpm -q` fără restricție de versiune scrie o linie PE
INSTANȚĂ instalată — `kernel` are de obicei mai multe deodată. Cea mai nouă
instanță (comparată corect, nu prima din listă) e cea folosită. Comparația
însăși e o portare linie-cu-linie a `rpmvercmp` din rpm — epoch numeric întâi,
apoi versiune, apoi release, cu `~` (pre-release, sortează înaintea a orice) și
`^` (post-release, sortează după bază dar înaintea unui segment real următor)
tratate separat de restul.

Pe `platform.family: debian` folosește `dpkg-query -W -f '${Version}\n'` și o
portare a algoritmului de comparare al `dpkg --compare-versions`
(`epoch:upstream_version-debian_revision`, `~` cu aceeași semantică ca la rpm).
`dpkg-query` a intrat în allowlist-ul binarelor executorului
(`executor/policy.py:BINARY_ALLOWLIST`) doar-citire, în runda a doua — dacă
gazda rulează un executor mai vechi, care nu-l are încă, verificarea eșuează
CLOSED cu mesajul explicit „dpkg-query nu e permis de executor pe această
gazdă încă", nu cu un „neimplementat" generic care ar deveni fals de îndată ce
executorul e la zi.

Ambele formate de interogare scriu literal cele două caractere backslash-n în
argv, NICIODATĂ un octet de linie nouă real — `executor/policy.py:
SHELL_METACHARACTERS` refuză orice element de argv care conține un `\n`
adevărat, deci o linie nouă reală aici ar face executorul să refuze
interogarea de fiecare dată. `rpm`/`dpkg-query` își interpretează singure
`\n`-ul din formatul de interogare ca linie nouă în IEȘIREA lor — exact ca la
un prompt de shell, unde shell-ul (nu rpm) ar fi cel care ar transforma o
linie nouă reală în altceva dacă ar fi tastată direct.

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

Rândul de mai sus are `automated = false` (implicit) — vezi §6b pentru rândurile
scrise automat, care nu trebuie amestecate cu astea.

---

## 6b. Exercițiul lunar, automat

Pe lângă testul trimestrial de mai sus, `sentinel-restore-drill.timer` rulează
lunar, singur, fără operator: alege un punct de restaurare (cel niciodată
testat, sau cel mai vechi testat), cere executorului să-i extragă arhivele
într-un director IZOLAT — niciodată `/`, niciodată producție — și verifică
checksum-urile plus faptul că arborele extras chiar conține sursele declarate.
Rezultatul intră în `restore_drills` (`automated = true`) și
`restore_drill_items`, câte un rând pe artefact, și ajunge în `/selfcheck`
prin `check_restore_drill`.

**Dovedește mai puțin decât testul trimestrial** — checksum și structură de
arhivă, nu că serviciul chiar pornește pe fișierele restaurate — dar rulează
în fiecare lună, nu o dată la trei. Un punct numai cu artefacte informative
(`rpm_state`, `git_ref`, fără nicio arhivă `tar.zst`) nu poate ieși niciodată
„reușit": nimic din el a fost extras, deci nimic din el a fost dovedit. Vezi
docstring-ul lui `sentinel/patch/restore_drill.py` și
`executor/commands.py:op_restore_drill_verify` pentru mecanism.

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

1. `/vuln <id>` → `/planifica <id>`
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

---

<!-- Secțiune adăugată în runda de securitate din 8 septembrie 2026 —
     delimitată intenționat, nu reflow peste restul fișierului. -->

## 10. Binarele permise într-un pas de plan (îngustat 8 septembrie 2026)

Verificatorul rundei 1 a rulat allowlist-ul de-atunci (32 de binare, cu o
listă de interdicții peste câteva dintre cele mai riscante) pe binare reale și
a obținut root prin `patch_step_exec` pe șase căi separate: `git
--exec-path=/var/lib/sentinel evilcmd`, `sed -n '2e ...'`, `rpm -i evil.rpm`,
`dnf install evil.rpm`, `npm install <url>`, `pip install --find-links=...` și
câteva combinații de flag-uri `docker`. Fiecare dintre binarele acelea are o
suprafață de scripting/hook proprie ce nu poate fi enumerată exhaustiv — `-c`
la git, comanda `e` la sed, hook-urile de ciclu de viață la npm/pip, docker
fiind prin definiție o telecomandă către gazdă. Reparația nu a fost o listă de
interdicții mai bună; a fost scoaterea binarelor de pe allowlist.

**Allowlist-ul curent** (`executor/policy.py:BINARY_ALLOWLIST`, oglindit
byte-cu-byte în `sentinel/constants.py:PATCH_BINARY_ALLOWLIST` — vezi
`test_policy_agrees_with_sentinel_constants`), fiecare cu o gramatică
POZITIVĂ (subcomenzi permise, flag-uri permise, formă a argumentelor
poziționale), nu o listă de interdicții:

| Binar | Formă permisă |
|---|---|
| `dnf` | `{upgrade,update,install,downgrade,reinstall,remove,clean,check-update,makecache}` + `-y`, `--setopt=install_weak_deps=False`, `--enablerepo=`/`--disablerepo=<nume simplu>`. Fără `.rpm`/`.deb` local, fără `-c`, fără `--installroot`, fără `dnf shell` |
| `apt-get` / `apt` | `{install,upgrade,dist-upgrade,update,remove,autoremove}` + `-y`, `-o Dpkg::Options::=--force-confold`, `--allow-downgrades` (doar cu `install` și doar dacă FIECARE pachet are `=versiune`). Pachetul poate fi `nume[:arh][=versiune]`, versiunea strict `[A-Za-z0-9.+~:-]`. Fără `.deb` local (verificat pe specificația întreagă, deci și `foo=1.0.deb`), fără `--only-upgrade` |
| `rpm` | doar interogare/verificare: `-q`, `-qa`, `-V`, `--qf`/`--queryformat <format fără %( sau lua:>`. Fără `-i/-U/-e/--import/--dbpath/--root/--eval/--pipe` |
| `dpkg-query` | `-W`, `-l`, `-s`, `-f`/`--showformat <format>` — nou în această rundă |
| `dpkg` | doar `--compare-versions VERSION OP VERSION` — nou în această rundă |
| `systemctl` | exact `systemctl ACȚIUNE UNITATE`, ACȚIUNE ∈ {start,stop,restart,reload,status,is-active}; `link`/`enable`/`mask`/`daemon-reload` refuzate, unități de tipul `sshd.service` refuzate — neschimbat din runda 1 |
| `tar` | `-c`/`-x`/`-t` (exact unul) cu `-f`, `-z`/`-j`/`-J`/`--zstd`, `-C`/`--directory`, `--one-top-level`, `-p`, `--no-same-owner`/`--same-owner` — listă pozitivă, nu interdicții |
| `cp`, `mv`, `mkdir` | un set restrâns de flag-uri obișnuite (recursiv, forțat, verbose, etc.) |
| `install` | flag-uri obișnuite; **fără `--strip-program=`** — rulează comanda dată ca root, echivalentul lui `--to-command` la tar |
| `chmod` | modul (poziția întâi) trebuie octal sau simbolic recunoscut; fără `--reference=` |
| `chown` | proprietarul (poziția întâi) trebuie `user[:grup]`, fără `/` |
| `nginx` | exact `nginx -t` — reload/restart trec prin `systemctl` |
| `test` | exact `test -e CALE` — singura formă pe care `sentinel/patch/checks.py` o construiește |
| `sha256sum` | exact `sha256sum CALE` — la fel |

**Scoase de pe allowlist** (fără nicio gramatică, pentru că niciuna n-ar fi
cinstită): `docker`, `git`, `npm`, `yarn`, `composer`, `pip`/`pip3`, `wp`,
`sed`, `curl`, `httpd`, `apachectl`, `mysqldump`, `mysql`, `pg_dump`, `psql`,
`zstd`, `gzip`, `ln`, `certbot` — niciunul nu are un apelant real în acest
depozit azi, și mai multe au propriul mecanism de shell-escape (`\!` la
psql) sau de hook (npm/pip). **`rm` NU a fost adăugat** deși verificatorul
rundei 1 l-a recomandat: `tests/security/test_patch_safety.py` codifică deja
decizia că ștergerea trece doar prin `op_backup_prune`, operație îngustă,
legată de cale — nu printr-un argv general.

Adăugarea unui binar înapoi pe listă e o decizie separată, cu gramatică
proprie scrisă și testată — nu un efect secundar al altui bilet (vezi §3 mai
sus, care spunea deja asta despre `dpkg`/`dpkg-query` înainte să fie
adăugate).

### Actualizarea unui pachet Debian e fixată pe versiune, în ambele direcții

`apt` nu are `downgrade`. Singura formă de revenire e `install pachet=versiune`,
iar `--allow-downgrades` e necesar fiindcă versiunea de întoarcere e mai mică
decât cea instalată. De aici rețeta pe care o învață promptul planificatorului
(`sentinel/patch/planner.py:_update_recipe_doc`) și pe care o acceptă amândouă
părțile:

| fază | comandă / verificare |
|---|---|
| preflight | `pkg_version {name: <pachet>, equals: <versiunea instalată>}` |
| apply | `apt-get -y install <pachet>=<versiunea care repară>` |
| rollback | `apt-get -y install --allow-downgrades <pachet>=<versiunea instalată>` |
| post_verification | `pkg_version {name: <pachet>, at_least: <versiunea care repară>}` |

Preflight-ul nu e decor: dacă versiunea din baza de date a rămas în urma celei
de pe gazdă, rollback-ul ar fixa o versiune greșită, deci planul se oprește
înainte să schimbe ceva.

`--allow-downgrades` fără `=versiune` e REFUZAT de executor: fără pin, apt
alege orice candidat mai vechi, iar cel mai vechi candidat e chiar versiunea
vulnerabilă pe care patch-ul a scos-o. `--only-upgrade` nu e acceptat deloc —
sub forma fixată nu spune nimic în plus față de pin, iar fiecare flag pe un
allowlist citit de un proces root e un cost permanent.

Onest: un rollback fixat pe versiune poate eșua la rulare dacă versiunea aia nu
mai e în arhivă. E mult mai bun decât unul care sigur nu restaurează nimic, dar
nu e o garanție, și planul trebuie s-o spună în `restore_instructions_ro`.

### Validatorul nu mai are o părere proprie despre argv

`sentinel/patch/validator.py` importă `executor.policy` și îl întreabă pe EL
dacă o comandă din plan are voie să ruleze (`_validate_executor_grammar`).
Până în runda a treia avea o gramatică proprie, iar cele două au divergit exact
cât n-a comparat nimeni: validatorul accepta `apt-get -y install --only-upgrade
<pachet>`, pe care executorul îl refuză la primul pas de aplicare — deci
fiecare plan Debian ajuns pe Telegram era garantat să moară în mijlocul
aplicării.

Importul e leneș, iar eșecul lui e o EROARE PE PLAN, nu o excepție la import:
`sentinel/telegram/patch_flow.py` importă validatorul, iar un fișier lipsă n-are
voie să oprească botul. Un validator care nu poate citi gramatica nu știe dacă
planul e sigur, deci refuză și spune de ce.

Și pentru verificări, nu doar pentru pași. `sentinel/patch/checks.py`
CONSTRUIEȘTE un argv pentru șase din cele unsprezece tipuri de verificare —
`command`, `systemd`, `file_exists`, `file_absent`, `file_sha256`,
`pkg_version` — și îl trimite pe același drum `patch_step_exec`. Docstring-ul
lui spunea până în runda a patra că „doar tipul `command` ajunge la executor",
iar validatorul l-a crezut: o verificare de sănătate pe `dbus.service` (unitate
din `UNCONTROLLABLE_UNITS`), un `file_exists` pe `/etc/shadow` sau un
`pkg_version` pe un nume care conține `passwd` treceau validarea și erau
refuzate abia la rulare. Pentru o verificare de sănătate, refuzul vine DUPĂ
pasul de aplicare: pachetul e deja actualizat, verificarea nu se poate evalua,
iar runner-ul dă înapoi un patch care reușise.

Construcția argv-ului stă acum într-o singură funcție, `checks.argv_for(check,
family)`, chemată și de `_dispatch` (ca să execute) și de validator (ca să
întrebe `check_argv`). Nu o a doua listă de tipuri în validator: un tip nou de
verificare e acoperit din ziua în care e adăugat, iar
`tests/security/test_plan_argvs_match_executor_policy.py` generează acoperirea
din `CHECK_KINDS`, nu dintr-o listă scrisă de mână.

Un plan salvat care verifică `dbus.service` nu mai validează de acum. Asta e
intenția — planul chiar nu se poate verifica pe gazda asta — dar înseamnă că
planurile deja stocate cu astfel de verificări trec în `rejected_invalid` la
prima încercare de rulare.

Instalatorul (pasul 24) pune același `policy.py` în două locuri:
`/opt/sentinel/libexec/policy.py`, pe care îl rulează procesul root, și
`/opt/sentinel/lib/executor/policy.py`, pe care îl importă validatorul —
amândouă root:root 0644, deci partea neprivilegiată citește regulile fără să le
poată schimba. Pasul verifică apoi importul chiar ca utilizatorul `sentinel`,
nu doar prezența fișierului.

### Legarea `patch_step_exec` de un plan aprobat

O gramatică spune că o comandă e bine formată. Nu spune că operatorul a
aprobat-o PE ACEEA. `dnf -y install un-pachet-plauzibil` trece de gramatică
fără să fi trecut vreodată prin cele două confirmări din Telegram.

Executorul are acum un registru în memorie: `register_plan(plan_hash, steps,
ttl_s, approval_token)`, unde `approval_token` e HMAC-SHA256 peste
`plan_hash` cu cheia `SENTINEL_EXECUTOR_APPROVAL_KEY` din
`/etc/sentinel/secrets.env`. Un apel REAL (nu dry-run) către `patch_step_exec`
trebuie acum să trimită `plan_hash` + `step_index`, iar executorul refuză
dacă argv nu e identic, byte cu byte, cu pasul înregistrat la acel index.
Dry-run rămâne fără nevoie de aprobare — nu execută nimic, deci n-are ce
proteja legarea.

**Linia necesară în `secrets.env`** (instalatorul trebuie s-o genereze —
neschimbat aici, `deploy/install.sh` nu e proprietatea acestei runde):

```
SENTINEL_EXECUTOR_APPROVAL_KEY=<hex aleator de minim 32 octeți, ex. openssl rand -hex 32>
```

**Fără cheie, `patch_step_exec` e dezactivat pe gazda aia** — orice apel real
refuză, cu un motiv explicit, nu o eroare ambiguă. Închis implicit, nu deschis
implicit.

**Cablarea rămasă, pentru runda care deține `runner.py`/`checks.py`:**
`sentinel/patch/runner.py` trebuie să apeleze
`ExecutorClient.register_plan(plan_hash, steps, ttl_s=…, approval_token=…)`
o dată, imediat după ce planul e confirmat aprobat (lângă verificarea
`row.status != "approved"` din `run_plan`), cu `steps` fiind lista aplatizată
a TUTUROR comenzilor pe care planul le va trimite spre `patch_step_exec` — nu
doar `apply`/`rollback`, ci și verificările `command`/`systemd`/`file_exists`/
`file_absent`/`file_sha256` pe care `sentinel/patch/checks.py` le construiește
pentru `preflight`/`health_check`/`post_verification`. Fiecare apel către
`patch_step_exec`, din ambele fișiere, trebuie apoi să trimită `plan_hash` +
indicele corespunzător din acea listă aplatizată. **Până nu se face asta în
ambele fișiere, o rulare `mode="apply"` refuză la primul preflight real** —
un `mode="dry_run"` rămâne neafectat, pentru că verificările sunt simulate
local în `runner.py` fără să atingă executorul. Textul exact al liniei și
limitarea recunoscută (uid-ul `sentinel` poate citi aceeași cheie din
`secrets.env`) sunt în `executor/README.md`, secțiunea „Binding to an
approved plan".
