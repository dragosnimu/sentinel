# Depanare

Ordonat după cât de urgent este, nu după cât de frecvent.

---

## 1. M-am blocat singur

**Încearcă în ordinea asta. Prima variantă durează sub un minut.**

### 1.1 Din a doua sesiune SSH (sau consola provider)

```bash
sudo touch /etc/sentinel/PANIC
```

Watchdog-ul golește blocklist-ul în ≤60 secunde. Rulează ca root, la fiecare
minut, și nu depinde de baza de date, de executor sau de web — exact pentru
situația asta.

Verifici:
```bash
sudo nft list set inet sentinel blocklist_v4
journalctl -u sentinel-watchdog -n 20
```

**Șterge fișierul după ce ai rezolvat cauza**, altfel blocarea rămâne oprită:
```bash
sudo rm /etc/sentinel/PANIC
```

### 1.2 Din Telegram

```
/panic
```
Dublă confirmare. Disponibilă chiar și când ai pus mute.

### 1.3 Reboot

Blocurile nu se persistă niciodată în nftables. Un reboot le șterge pe toate.
Sentinel le re-aplică pe cele neexpirate din baza de date la pornire — deci
dacă blocarea greșită era permanentă, combină cu pasul următor.

### 1.4 Din consola provider

```bash
nft delete table inet sentinel
```
Tabela dispare complet. Nimic nu mai e blocat.

### 1.5 Blocarea revine după reboot

Era în baza de date. Scoate-o:

```bash
sudo -u postgres psql sentinel -c \
  "UPDATE blocklist SET active=false, unblocked_at=now(), unblocked_by='manual' WHERE ip='<IP>'"
sudo systemctl restart sentinel-detect
```

Și adaug-o în allowlist ca să nu se repete: `/allow <ip> motiv` sau în
`response.extra_allowlist` din `sentinel.yaml`.

---

## 2. Ceva ce rula înainte s-a oprit

Prima verificare, întotdeauna:

```bash
free -h
systemctl --failed
```

**Cauza cea mai probabilă este presiunea de memorie.** OOM killer-ul alege cel
mai mare proces, care pe majoritatea serverelor este aplicația pe care Sentinel
venise să o protejeze — nu Sentinel. Simptomul e „site-ul e picat”, fără nimic
care să arate evident spre agentul de monitorizare care a cauzat-o.

```bash
# Cine a fost omorât
sudo journalctl -k | grep -i 'killed process'

# Ce consumă acum
systemctl show 'sentinel-*' -p MemoryCurrent --value
sudo docker stats --no-stream 2>/dev/null

# Ce rula înainte de instalare, și ce lipsește acum
diff <(systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}' | sort)      /var/lib/sentinel/.install-state/baseline-services.txt
```

Măsuri imediate:

```bash
# Oprește scanările — ele sunt vârfurile de memorie
sudo systemctl stop sentinel-scan.timer

# Dacă Suricata rulează și RAM-ul e la limită
sudo systemctl stop suricata
sudo sed -i 's/^  enabled: true/  enabled: false/' /etc/sentinel/sentinel.yaml

# Repornește ce s-a oprit
sudo systemctl start <serviciu>
```

Dacă nu se rezolvă, fă rollback complet. Sentinel nu merită o întrerupere a
producției:

```bash
./scripts/deploy.sh --host ... --user ... --key ... --rollback
```

Pe termen lung: adaugă 2 GB swap, sau mută Sentinel pe o gazdă cu mai mult RAM.

---

## 3. Instalarea a eșuat

Instalatorul e numerotat pe pași, idempotent și reluabil. Markerii sunt în
`/var/lib/sentinel/.install-state/`.

```bash
ls /var/lib/sentinel/.install-state/    # ce a reușit
```

Repari cauza, apoi:

```bash
./scripts/deploy.sh --host ... --user ... --key ... --from-step 22
```

| Pas | Eșec frecvent | Rezolvare |
|---|---|---|
| 20 packages | Repo indisponibil | `sudo dnf clean all && sudo dnf makecache` |
| 21 external_tools | `checksum mismatch` | **Nu ocoli asta.** Ori download corupt, ori mirror compromis. Reîncearcă; dacă persistă, investighează |
| 22 postgres | `initdb` eșuează | `/var/lib/pgsql/data` există deja și nu e gol |
| 23 venv | `pip install` eșuează | Lipsesc `gcc`/`python3.12-devel`, sau nu e rețea |
| 28 migrate | Nu se conectează | Parola rolului nu corespunde. Reia pasul 22 cu `--force-step 22` |
| 33 nginx | certbot eșuează | DNS nu rezolvă aici, sau portul 80 nu e accesibil din internet |

Dacă nimic nu ajută:

```bash
./scripts/deploy.sh --host ... --user ... --key ... --rollback
```

---

## 4. Un serviciu nu pornește

```bash
sudo systemctl status sentinel-detect
sudo journalctl -u sentinel-detect -n 50 --no-pager
```

| Simptom | Cauză probabilă |
|---|---|
| `configuration error: ...` | `sudo sentinel config-check -v` îți spune exact ce |
| `SecretMissingError` | Lipsește o cheie din `secrets.env`. `config-check` listează care |
| `could not connect to the database` | `systemctl status postgresql`; verifică `pg_hba.conf` |
| `Permission denied` pe un log | Utilizatorul `sentinel` nu e în grupul `adm` sau `systemd-journal` |
| Restart loop | Watchdog-ul va goli blocklist-ul după 5 restarturi în 5 minute. E intenționat |
| `status=203/EXEC` | Fișierul nu e executabil, sau are CRLF (`bad interpreter`) |

Verificare rapidă de CRLF:
```bash
file /opt/sentinel/deploy/install.sh    # "CRLF line terminators" = problema
```

---

## 5. Prea multe alerte

**Nu pune mute pe canal.** Un canal pe mute nu protejează nimic. Găsește regula.

```bash
sudo /opt/sentinel/venv/bin/python \
  /opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py \
  detections_by_rule --param since=24h --format table
```

Regula zgomotoasă e prima în listă. Apoi:

1. **Verifică allowlist-ul înainte de a schimba pragul.** Majoritatea
   problemelor de „regulă zgomotoasă" sunt de fapt o intrare lipsă pentru un
   monitor de uptime, un crawler, un edge CDN sau propriul CI.
2. Citește profilul de fals-pozitive al regulii în
   `.claude/skills/sentinel-soc/references/detection-catalog.md`. Fiecare regulă
   are unul documentat.
3. Apasă `✅ Fals pozitiv` pe incidentele nerelevante — scrie o suprimare
   îngustă *și* alimentează calibrarea.
4. Abia apoi ajustează pragul în `/etc/sentinel/detection.yaml` și
   `sudo systemctl restart sentinel-detect`.

### Cazuri cunoscute, deja suprimate

| Semnal | Explicație |
|---|---|
| `tcpdump` recurent ca root | De obicei un sampler de metrici legitim. Verifică `detection.yaml` → `host.pkt_capture.exclude_cmdline` |
| Volum mare de la o sursă din `extra_allowlist` | Ceva ce ai declarat explicit ca legitim |
| Containere repornind | Operare normală Docker. Exclus deliberat din regulile auditd |
| Rafale HTTPS de ieșire 03:00–05:00 | Fereastra de scanare: DB Trivy, template-uri nuclei, feed-uri |
| Hit-uri pe `/.well-known/acme-challenge/` | Reînnoire certbot. Allowlisted |

---

## 6. O anomalie evidentă nu a alertat

Verifică întâi baseline-ul:

```bash
sudo -u postgres psql sentinel -c \
  "SELECT metric, count(*) FILTER (WHERE warm) AS warm,
          count(*) FILTER (WHERE NOT warm) AS cold
   FROM baselines GROUP BY metric"
```

Dacă `warm` e zero, ești în warm-up-ul de 14 zile. Regulile de anomalie se
înregistrează dar **nu alertează** în perioada asta. E comportament corect, nu
bug: fără el ai câteva sute de fals-pozitive în ziua unu.

Al doilea lucru de verificat, dacă întrebarea e „de ce nu a blocat":

```bash
grep -A3 'auto_block:' /etc/sentinel/sentinel.yaml
```

`enabled: false` este starea implicită și cea intenționată pentru primele 72 de
ore.

---

## 7. Dashboard-ul nu răspunde

```bash
# Aplicația în sine
curl -sI http://127.0.0.1:8787/healthz          # aplicația
curl -skI https://127.0.0.1:8443/healthz        # nginx în fața ei

# Proxy-ul
sudo nginx -t && sudo systemctl status nginx
sudo tail -50 /var/log/nginx/sentinel-error.log
```

| Simptom | Cauză |
|---|---|
| `502 Bad Gateway` | `sentinel-web` e picat. `journalctl -u sentinel-web -n 50` |
| `403` de la nginx | Ai completat `allow`/`deny` în vhost și IP-ul tău nu e acolo |
| `429` | Rate limit. `/login` are 5/min pe adresă. Așteaptă |
| Conexiune refuzată din exterior, dar loopback merge | Portul 8443 nu e deschis în firewall-ul providerului. Sentinel e în regulă |
| nginx nu pornește: `bind() to 0.0.0.0:80 failed` | Un server block din `nginx.conf` concurează pentru `:80`. Instalarea îl comentează doar dacă a instalat ea nginx; altfel e al tău |
| Avertisment TLS | certbot nu a rulat, sau certificatul a expirat |
| Cont blocat | 5 încercări eșuate. Se deblochează în 15 minute |

Certificat expirat:
```bash
sudo certbot renew --dry-run       # de ce eșuează
sudo certbot renew --force-renewal
sudo systemctl reload nginx
```

O reînnoire eșuată în tăcere este cauza clasică pentru „dashboard-ul a picat
brusc după 90 de zile". Regula `tls.expiring` alertează cu 14 zile înainte
tocmai pentru asta.

---

## 8. Cheltuiala AI

```
/budget
```

sau:
```bash
sudo /opt/sentinel/venv/bin/python \
  /opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py ai_budget
```

Dacă e mai mare decât te așteptai:

1. Ridică `ai.triage_min_severity` la `critical`.
2. Verifică dacă o furtună de evenimente a generat multe joburi:
   ```bash
   ... sentinel_query.py ai_queue --format table
   ```
   Deduplicarea ar trebui să prevină asta; dacă nu a făcut-o, un fingerprint de
   incident e prea granular.
3. Coboară `ai.daily_budget_usd`. E o oprire hard, nu un avertisment.

Dacă bugetul e epuizat, joburile se marchează `skipped` cu motiv. Detecția,
blocarea și alertarea nu sunt afectate.

---

## 9. Discul se umple

```bash
df -h
sudo du -sh /var/lib/pgsql/data /var/log/suricata /var/backups/sentinel
```

| Vinovat | Rezolvare |
|---|---|
| `/var/log/suricata/eve.json` | Suricata inspectează un flux de volum mare. **Verifică imediat**: `grep bpf /etc/suricata/suricata.yaml`; dacă e gol, rulează preflight ca să afli ce să excluzi |
| Partiții `raw_events` | `sudo -u postgres psql sentinel -c "SELECT sentinel_emergency_retention(7)"` |
| `/var/backups/sentinel` | Puncte de restaurare. Vezi ce e protejat: `SELECT * FROM restore_points WHERE retention_hold` |

Garda de disc scade automat retenția sub 15% liber și alertează. Dacă ai ajuns
la 100%, ea nu a apucat să ruleze — probabil pentru că `sentinel-maintenance` nu
mai rula.

---

## 10. Un patch a eșuat

```bash
sudo /opt/sentinel/venv/bin/python \
  /opt/sentinel/claude-workspace/.claude/skills/sentinel-soc/scripts/sentinel_query.py \
  patch_steps --param execution_id=<id> --format table
```

Rândurile din `patch_steps` se scriu **înainte** de pasul următor, deci ai urma
completă chiar dacă procesul a murit la mijloc. Citește-le în ordine: ultimul
rând cu `status='running'` este pasul care a eșuat.

Dacă rollback-ul automat a reușit, serviciul e pe versiunea anterioară și nu
trebuie să faci nimic. Dacă a eșuat (`status='rollback_failed'`), restaurează
manual:

```bash
ls /var/backups/sentinel/
sudo /var/backups/sentinel/<restore_point_id>/restore.sh
```

`restore.sh` e standalone. Funcționează cu Sentinel complet oprit și fără baza
de date — exact situația în care îl vei citi.

---

## 11. Lanțul de audit e rupt

Alerta `audit_chain_broken` înseamnă că `entry_hash` nu se leagă de `prev_hash`
undeva.

```bash
sudo -u postgres psql sentinel -c \
  "SELECT id, at, actor, operation FROM audit_log ORDER BY id DESC LIMIT 50"
```

Două explicații posibile:

1. **Baza de date a fost restaurată** dintr-un backup peste rânduri mai noi.
   Benign, dar confirmă că știi de ce.
2. **Cineva a modificat tabela.** Există un trigger care refuză UPDATE și DELETE,
   deci pentru asta ar fi trebuit acces de superuser la PostgreSQL. Tratează ca
   pe o compromitere: verifică `login_attempts`, `sessions` și accesul SSH.

---

## 12. Diagnostic complet, de pus într-un raport

```bash
ssh deploy@203.0.113.10 'bash -s' <<'EOF'
echo "=== VERSION ==="   ; cat /opt/sentinel/VERSION
echo "=== UNITS ==="     ; systemctl list-units 'sentinel-*' --no-pager
echo "=== FAILED ==="    ; systemctl --failed --no-pager
echo "=== MEM/DISK ==="  ; free -h; df -h /
echo "=== NFT ==="       ; sudo nft list table inet sentinel | head -60
echo "=== PORTS ==="     ; sudo ss -tlnp
echo "=== CONFIG ==="    ; sudo /opt/sentinel/bin/sentinel config-check -v
echo "=== BASELINE ===" ; diff <(systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}' | sort) /var/lib/sentinel/.install-state/baseline-services.txt
echo "=== HARDENING ==="; systemd-analyze security 'sentinel-*' 2>/dev/null | head -20
echo "=== ERRORS ==="    ; sudo journalctl -u 'sentinel-*' -p err -n 40 --no-pager
EOF
```
