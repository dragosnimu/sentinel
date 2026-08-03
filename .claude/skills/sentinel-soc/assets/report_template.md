# Raport de securitate — {{ period_label_ro }}

**Server:** {{ hostname }} · **Perioadă:** {{ period_start }} – {{ period_end }}
**Generat:** {{ generated_at }}

---

## Ce necesită o decizie

{% if decisions %}
{% for d in decisions %}
{{ loop.index }}. **{{ d.title_ro }}**
   {{ d.detail_ro }}
   → {{ d.action_ro }}
{% endfor %}
{% else %}
Nimic. Nicio vulnerabilitate critică deschisă, niciun incident nerezolvat,
niciun serviciu degradat.
{% endif %}

---

## Ce s-a schimbat față de perioada anterioară

{% for c in changes %}
- {{ c.icon }} {{ c.text_ro }} ({{ c.previous }} → {{ c.current }})
{% endfor %}

---

## Incidente

**Total:** {{ incidents.total }} ({{ incidents.delta_ro }} față de perioada anterioară)

| Severitate | Număr | Rezolvate | Deschise |
|---|---|---|---|
| CRITIC | {{ incidents.critical.total }} | {{ incidents.critical.resolved }} | {{ incidents.critical.open }} |
| RIDICAT | {{ incidents.high.total }} | {{ incidents.high.resolved }} | {{ incidents.high.open }} |
| MEDIU | {{ incidents.medium.total }} | {{ incidents.medium.resolved }} | {{ incidents.medium.open }} |
| SCĂZUT | {{ incidents.low.total }} | {{ incidents.low.resolved }} | {{ incidents.low.open }} |

**Timp mediu până la detecție (MTTD):** {{ incidents.mttd_ro }}
**Timp mediu până la răspuns (MTTR):** {{ incidents.mttr_ro }}
**Fals pozitive marcate:** {{ incidents.false_positives }} ({{ incidents.fp_rate_pct }} % din total)

{% if incidents.notable %}
### Incidente notabile

{% for i in incidents.notable %}
**#{{ i.id }} — {{ i.title_ro }}** ({{ i.severity_ro }}, {{ i.when_ro }})
{{ i.summary_ro }}
Rezolvare: {{ i.resolution_ro }}
{% endfor %}
{% endif %}

---

## Atacatori

**Actori unici:** {{ actors.unique }} · **Blocați:** {{ actors.blocked }} ·
**Reveniți după deblocare:** {{ actors.returned }}

### Top surse

{% for a in actors.top %}
{{ loop.index }}. `{{ a.ip }}` — {{ a.country }} / {{ a.asn }} · {{ a.detections }} detecții · stadiu {{ a.stage }}/6 {% if a.blocked %}· blocat{% endif %}
{% endfor %}

### Top ținte

{% for t in actors.top_targets %}
- `{{ t.asset }}` — {{ t.attempts }} tentative ({{ t.top_rule }})
{% endfor %}

**Eficiența blocării:** {{ actors.block_effectiveness_ro }}

---

## Vulnerabilități

| | Deschise | Noi | Rezolvate | Vechime medie |
|---|---|---|---|---|
| CRITIC | {{ vulns.critical.open }} | {{ vulns.critical.new }} | {{ vulns.critical.resolved }} | {{ vulns.critical.age_ro }} |
| RIDICAT | {{ vulns.high.open }} | {{ vulns.high.new }} | {{ vulns.high.resolved }} | {{ vulns.high.age_ro }} |
| MEDIU | {{ vulns.medium.open }} | {{ vulns.medium.new }} | {{ vulns.medium.resolved }} | {{ vulns.medium.age_ro }} |

**Listate în CISA KEV și încă deschise:** {{ vulns.kev_open }}
{% if vulns.kev_open > 0 %}
{% for v in vulns.kev_list %}
- ⚠️ `{{ v.cve }}` în `{{ v.package }}` pe `{{ v.asset }}` — deschis de {{ v.age_ro }}, fix disponibil: `{{ v.fixed_in }}`
{% endfor %}
{% endif %}

**Scanări rulate:** {{ vulns.scans_run }} · **Eșuate:** {{ vulns.scans_failed }}

---

## Patching

**Planuri generate:** {{ patches.generated }} · **Aplicate:** {{ patches.applied }} ·
**Rollback-uri:** {{ patches.rolled_back }} · **Respinse la validare:** {{ patches.rejected_invalid }}

{% for p in patches.list %}
- `{{ p.plan_id_short }}` — {{ p.asset }} · {{ p.status_ro }} · {{ p.when_ro }}{% if p.rollback_reason %} · rollback: {{ p.rollback_reason_ro }}{% endif %}
{% endfor %}

**Puncte de restaurare disponibile:** {{ patches.restore_points }} ({{ patches.restore_points_size_gb }} GB)
{% if patches.drill_due %}
⚠️ Testul trimestrial de restaurare este scadent din {{ patches.drill_due_since_ro }}.
{% endif %}

---

## Disponibilitate și capacitate

### Servicii

| Serviciu | Uptime | p95 latență | Incidente |
|---|---|---|---|
{% for s in availability.services %}
| `{{ s.name }}` | {{ s.uptime_pct }} % | {{ s.p95_ms }} ms | {{ s.incidents }} |
{% endfor %}

{% if availability.downtime_events %}
### Întreruperi

{% for d in availability.downtime_events %}
- `{{ d.asset }}` — {{ d.duration_ro }}, {{ d.when_ro }}. Cauză: {{ d.cause_ro }}
{% endfor %}
{% endif %}

### Capacitate

- **CPU:** medie {{ capacity.cpu_avg }} %, vârf {{ capacity.cpu_max }} %
- **RAM:** disponibil minim {{ capacity.mem_min_mb }} MB {% if capacity.mem_warning %}⚠️ {{ capacity.mem_warning_ro }}{% endif %}
- **Disc:** {{ capacity.disk_used_pct }} % ocupat{% if capacity.disk_full_eta %} · plin estimat în {{ capacity.disk_full_eta_ro }}{% endif %}
- **Bază de date Sentinel:** {{ capacity.db_size_gb }} GB

---

## Predicții — calibrare

Sentinel înregistrează fiecare predicție și o punctează ulterior. Aceasta este
performanța reală, nu una declarată.

- **Predicții făcute:** {{ predictions.made }}
- **Adeverite:** {{ predictions.correct }} ({{ predictions.accuracy_pct }} %)
- **Scor Brier:** {{ predictions.brier }} {{ predictions.brier_interpretation_ro }}

{{ predictions.commentary_ro }}

---

## Sănătatea Sentinel

- **Servicii active:** {{ health.units_up }}/{{ health.units_total }}
- **Evenimente procesate:** {{ health.events_processed }}
- **Cost AI:** {{ health.ai_cost_usd }} USD ({{ health.ai_budget_pct }} % din buget)
- **Apeluri AI eșuate:** {{ health.ai_failures }}
- **Prospețime feed-uri threat intel:** {{ health.feeds_freshness_ro }}
{% if health.issues %}
{% for i in health.issues %}
- ⚠️ {{ i }}
{% endfor %}
{% endif %}

---

{% if recommendations %}
## Recomandări

{% for r in recommendations %}
{{ loop.index }}. **{{ r.title_ro }}** ({{ r.effort_ro }} efort, {{ r.impact_ro }} impact)
   {{ r.detail_ro }}
{% endfor %}
{% endif %}

---

*Raport generat automat de Sentinel {{ version }}. Detalii complete:
{{ dashboard_url }}*
