# Plan de patch — {{ asset_name }}

**ID plan:** `{{ plan_id }}` · **hash:** `{{ plan_hash_short }}`
**Generat:** {{ created_at_local }} · **Model:** {{ model }}
**Stare:** {{ status }}

---

## Rezumat

{{ summary_ro }}

| | |
|---|---|
| **Risc** | {{ risk_level_ro }} · impact {{ blast_radius_ro }} |
| **Downtime estimat** | {{ estimated_downtime_s }} s |
| **Necesită reboot** | {{ requires_reboot_ro }} |
| **Reversibil** | {{ reversible_ro }} |
| **Fereastră de mentenanță** | {{ maintenance_window_ro }} |
| **Încredere** | {{ confidence_pct }} % |
| **Backup total estimat** | {{ backup_total_mb }} MB |

{% if assumptions_ro %}
**Presupuneri făcute la generare** — verifică-le înainte de aprobare:
{% for a in assumptions_ro %}
- {{ a }}
{% endfor %}
{% endif %}

---

## Vulnerabilități rezolvate

{% for v in vulnerabilities %}
### {{ v.cve or "Fără CVE" }} — `{{ v.package }}`

- **CVSS:** {{ v.cvss or "n/a" }} · **EPSS:** {{ v.epss_pct or "n/a" }} {% if v.kev %}· ⚠️ **listat în CISA KEV**{% endif %}
- **Instalat:** `{{ v.current }}` → **corectat în:** `{{ v.fixed_in }}`
- Finding: `#{{ v.finding_id }}`
{% endfor %}

---

## 1. Verificări preliminare

Rulate înainte de orice modificare. Un eșec la o verificare `blocantă` oprește
procedura fără să se fi schimbat nimic.

{% for c in preflight %}
- `{{ c.id }}` — {{ c.desc_ro }} {% if c.blocking %}**(blocantă)**{% endif %}
  `{{ c.check_summary }}`
{% endfor %}

---

## 2. Backup

{% if backup %}
Creat în `/var/backups/sentinel/{{ restore_point_id or "<id>" }}/`, cu
`manifest.json` (sha256 per artefact) și `restore.sh` care funcționează
**fără Sentinel pornit**.

{% for b in backup %}
- `{{ b.id }}` — {{ b.desc_ro }}
  Tip: `{{ b.kind }}` · Sursă: `{{ b.source }}` · Estimat: {{ b.estimated_size_mb }} MB
  Restaurare: `{{ b.restore_argv | join(" ") }}`
{% endfor %}
{% else %}
**Fără backup** — toți pașii de aplicare sunt idempotenți și reversibili prin
rollback direct.
{% endif %}

---

## 3. Aplicare

{% for s in apply %}
### Pasul {{ loop.index }} — `{{ s.id }}`

{{ s.desc_ro }}

```
{{ s.argv | join(" ") }}
```

Utilizator: `{{ s.run_as }}`{% if s.cwd %} · Director: `{{ s.cwd }}`{% endif %} · Timeout: {{ s.timeout_s }}s · La eșec: **{{ s.on_failure_ro }}**
{% endfor %}

---

## 4. Verificări de sănătate

Rulate imediat după aplicare. Un eșec la o verificare blocantă declanșează
**rollback automat**.

{% for c in health_check %}
- `{{ c.id }}` — {{ c.desc_ro }} {% if c.blocking %}**(blocantă → rollback)**{% endif %}
  `{{ c.check_summary }}`
{% endfor %}

---

## 5. Rollback automat

{% if rollback %}
{% for s in rollback %}
{{ loop.index }}. {{ s.desc_ro }}
   ```
   {{ s.argv | join(" ") }}
   ```
{% endfor %}
{% else %}
**Nu există rollback automat** — modificarea a fost marcată ca ireversibilă.
Singura cale de întoarcere este restaurarea manuală din backup (secțiunea 7).
{% endif %}

---

## 6. Verificare finală

Confirmă că vulnerabilitatea chiar a fost rezolvată. Se re-rulează exact
verificarea pe care o va face scanerul la următoarea rulare.

{% for c in post_verification %}
- `{{ c.id }}` — {{ c.desc_ro }}
  `{{ c.check_summary }}`
{% endfor %}

---

## 7. Restaurare manuală

De folosit dacă Sentinel nu funcționează sau rollback-ul automat a eșuat.

```
{{ restore_instructions_ro }}
```

---

{% if notes_ro %}
## Note

{{ notes_ro }}

---
{% endif %}

## Aprobare

Aplicarea necesită două confirmări explicite pe Telegram. Tokenul de aprobare
este legat de hash-ul `{{ plan_hash_short }}` — dacă planul este regenerat,
butoanele din mesajele anterioare devin invalide.

**Comandă:** `/plan {{ plan_id }}`
