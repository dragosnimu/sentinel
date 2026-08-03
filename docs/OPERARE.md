# Operare zilnică

Ce faci când primești o alertă, și ce verifici periodic.

---

## 1. A sunat telefonul — ce fac

### 🔴 CRITIC

Înseamnă „lasă ce faci". Sentinel emite `critical` doar pentru lucruri
acționabile acum; dacă începe să apară pentru altceva, regula trebuie
reclasificată, nu canalul pus pe mute.

1. **Citește prima linie.** E scrisă ca să fie de ajuns pe ecranul blocat.
2. `/incident <id>` pentru dosarul complet: cronologie, actor, evidențe,
   verdictul AI, acțiuni recomandate ordonate.
3. Acțiunile recomandate sunt concrete. Prima este de obicei ce trebuie făcut.

Cazuri critice și ce înseamnă:

| Alertă | Ce s-a întâmplat |
|---|---|
| `auth.ssh_success_after_failures` | Cineva a intrat pe SSH după încercări eșuate. Verifică dacă ai fost tu, apoi ce a făcut sesiunea |
| `web.rce` | Tentativă de injecție de comandă. Aproape niciodată fals pozitiv |
| `host.webroot_write` | Fișier scris într-un webroot în afara unei ferestre de deploy. Semn clasic de webshell |
| `host.new_suid` | Binar SUID nou. Persistență |
| `auth.new_user` / `new_ssh_key` | Utilizator sau cheie adăugată. Persistență |
| `availability.capacity_memory` | `MemAvailable` sub 500 MB. **OOM killer-ul e pe cale să omoare cel mai mare proces — de obicei aplicația, nu Sentinel.** Vezi DEPANARE §2 |

### 🟠 RIDICAT

Se rezolvă în aceeași zi, nu în același minut. De obicei atac oportunist real:
brute force, scanare agresivă, payload web.

Dacă auto-block e pornit, sursa e deja blocată și mesajul are `↩️ Deblochează`.
Dacă e oprit (primele 72h), ai `🚫 Blochează acum`.

**Blocarea IP-ului nu rezolvă vulnerabilitatea.** Dacă verdictul conține o
intersecție de expunere (`exposure_crossing.matched: true`), următorul atacator
va veni de pe altă adresă. A doua acțiune recomandată e patch-ul; ea contează.

### 🟡 MEDIU și mai jos

Nu necesită reacție imediată. Se agregă în digest și apar în raportul zilnic.

---

## 2. Butonul „Fals pozitiv"

Folosește-l. Nu doar închide incidentul: scrie o intrare de suprimare **îngustă**
(regulă + tipar + asset, nu regula întreagă) și alimentează datele de calibrare.
Este mecanismul prin care rata de fals-pozitive scade.

Dacă același fals pozitiv se repetă, cauza e aproape sigur o intrare lipsă în
allowlist, nu un prag greșit. Candidații obișnuiți: monitorul de uptime,
runner-ul de CI, validatorul Let's Encrypt, crawlerele, edge-urile CDN, IP-ul tău
mobil.

---

## 3. Rutina

### Zilnic — 2 minute

Raportul de la 08:00. Dacă nu s-a întâmplat nimic, nu vine (setare
`skip_if_empty`), ca să nu te antrenezi să ignori mesajul de dimineață.

Uită-te la secțiunea „Ce necesită o decizie". Dacă e goală, ai terminat.

### Săptămânal — 15 minute

```
/status
/vulns kev
/health
/budget
```

- **KEV deschise** sunt vulnerabilități exploatate activ în lume, pe sistemele
  tale. Ele au prioritate peste orice CVSS mai mare care nu e în KEV.
- **`/health`** — dacă adâncimea cozii AI crește, worker-ul e blocat. Dacă
  feed-urile de threat intel sunt vechi, rata de fals-pozitive va crește.
- **`/budget`** — dacă cheltuiala crește neașteptat, vezi DEPANARE §8.

Verifică și vechimea vulnerabilităților deschise: numărul care ar trebui să
scadă e vechimea medie, nu numărul total.

### Lunar — 30 minute

```bash
./scripts/smoke-test.sh --host ... --user ... --key ... --domain ...
```

Plus:
- Raportul lunar: `/report luna`
- Calibrarea predicțiilor (scorul Brier din raport). Dacă e prost, e vizibil —
  asta e ideea
- Puncte de restaurare: `/restore` — există unul recent pentru fiecare asset?
- Creșterea discului și data proiectată de umplere

### Trimestrial — 1 oră

**Testul de restaurare.** Un backup pe care nimeni nu l-a restaurat nu e backup.

Sentinel îți amintește la 90 de zile. Procedura completă în
[PATCHING.md](PATCHING.md) §6.

---

## 4. Când vrei să faci mentenanță planificată

Ca să nu primești alerte de disponibilitate în timp ce lucrezi:

```sql
INSERT INTO maintenance_windows (asset_id, starts_at, ends_at, reason, created_by)
VALUES (12, now(), now() + interval '2 hours', 'upgrade planificat', 'operator');
```

Suprimă regulile `availability.*` și `host.*` pentru asset-ul respectiv pe
durata ferestrei. Întreruperile din interiorul ei sunt marcate `planned` și nu
poluează cifra de disponibilitate.

---

## 5. Ce înseamnă cifrele

**Nivelul de amenințare (0–100)** din `/status` este un scor compozit
determinist: stadii în lanțul de atac, timp petrecut la stadiu, rata de
detecții, hit-uri pe feed-uri de reputație, intersecții de expunere,
criticitatea țintelor. Nu e o predicție — e o măsură a ce se întâmplă acum.

**Probabilitățile din predicții** sunt frecvențe empirice din istoricul propriu
al serverului: „31 din 87 de actori cu tipar similar în ultimele 60 de zile".
Numitorul e afișat. Sub 20, Sentinel spune că datele sunt insuficiente în loc să
inventeze un procent.

**Scorul Brier** măsoară cât de bune sunt predicțiile. Mai mic e mai bine; 0,25
este echivalentul aruncării cu banul. E în raport pentru că o predicție pe care
nimeni nu o verifică e marketing.

**Prioritatea vulnerabilităților (0–100)** combină CVSS, EPSS, apartenența la
KEV, expunerea la internet, criticitatea asset-ului și disponibilitatea unui
fix. **Sortează după ea, nu după CVSS.** Un CVSS 7,5 în KEV pe o aplicație
expusă contează mai mult decât un CVSS 9,8 într-o bibliotecă neatinsă de
trafic.

---

## 6. Ce să nu faci

- **Nu pune canalul pe mute.** Găsește regula zgomotoasă. DEPANARE §5.
- **Nu porni auto-block înainte de 72h de calibrare.** Vei bloca monitorul de
  uptime, validatorul ACME sau propriul telefon.
- **Nu edita `/etc/sentinel/*.yaml` fără restart** al serviciului corespunzător.
- **Nu aplica un patch fără dry-run** prima dată pe un asset.
- **Nu testa brute-force de pe IP-ul de pe care administrezi.** Folosește un
  hotspot sau un al doilea VPS.
- **Nu atinge nimic marcat `protected: true`** sau aflat sub o cale din
  `patch.extra_protected_paths`. Nu sunt ale lui Sentinel.

---

## 7. Comenzi de referință

```bash
# Loguri lizibile
./scripts/tail-logs.sh --host ... --user ... --key ...
./scripts/tail-logs.sh --host ... --unit sentinel-detect --errors

# Interogări read-only (catalogul complet: rulează fără argumente)
SQ=/opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py
sudo /opt/sentinel/venv/bin/python $SQ open_incidents --format table
sudo /opt/sentinel/venv/bin/python $SQ top_actors --param since=24h --format table
sudo /opt/sentinel/venv/bin/python $SQ kev_findings --format table
sudo /opt/sentinel/venv/bin/python $SQ detections_by_rule --param since=24h --format table
sudo /opt/sentinel/venv/bin/python $SQ availability --param since=30d --format table

# Stare
sudo sentinel config-check -v
sudo nft list table inet sentinel
systemctl status 'sentinel-*'
```
