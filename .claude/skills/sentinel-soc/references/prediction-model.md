# Prediction model

What Sentinel actually computes, so that when you narrate a prediction you are
interpreting a real number rather than inventing one.

Nothing here is machine learning. It is baselines, a state machine, empirical
frequencies from this host's own history, and a set join. That is deliberate:
every prediction has to be explainable to an operator at 3 a.m. and falsifiable
afterwards.

---

## Kill-chain stages

Each actor carries a stage. An actor is a source IP, or a *cluster* keyed by
`/24 + ASN + user-agent/JA4 fingerprint` when several IPs behave as one.

| Stage | Name | Evidence that moves an actor here |
|---|---|---|
| 0 | `observed` | Any traffic at all |
| 1 | `recon` | Port scan, `robots.txt`, `/.well-known`, banner grab, TLS handshake with no request |
| 2 | `enumeration` | 404 storms, dirbusting, admin-panel probing, user enumeration, version fingerprinting |
| 3 | `credential_attack` | Failed logins over threshold, password spraying, default-credential attempts |
| 4 | `exploitation` | Payload signatures (SQLi, RCE, LFI, traversal), Suricata exploit sigs, upload attempts |
| 5 | `post_exploitation` | New listening port, webroot file write, unexpected outbound, new process, new cron/user/authorized_key |
| 6 | `impact` | Data-volume anomaly, service degradation, mass deletion |

Stages only advance. A quiet actor keeps its stage; `stage_entered_at` tells you
how long they have been there, which is often more informative than the stage.

**Stage 5 and 6 are not predictions.** They mean something already happened on
this host. Escalate to `critical` and stop reasoning about probability.

---

## The transition matrix

`killchain_transitions` records every stage change with the elapsed time and an
evidence pattern. From it, Sentinel computes:

```
P(reach stage n+1 within H minutes | currently at stage n, evidence pattern E)
```

as a straight empirical frequency over a trailing 60-day window, restricted to
actors whose evidence pattern matches. The dossier hands you the numerator and
denominator. **Use them verbatim.**

Correct:

> „Actorul este în stadiul 2 (enumerare) de 14 minute. Din 87 de actori cu
> tipar similar în ultimele 60 de zile, 31 (36%) au avansat la atac pe
> credențiale în ≤30 min."

Wrong — no basis, and unscoreable:

> „Există o probabilitate ridicată ca acest atac să escaladeze."

If the denominator is small (< 20), say so and widen the horizon or drop the
probability entirely. A prediction from 3 prior observations is noise wearing a
percentage sign.

Every probability you state is written to `predictions` and scored against what
actually happened. The analytics page shows the Brier score. Inventing numbers
shows up there within a week.

---

## Baselines

Per `(asset_id, metric, hour_of_week)`, over a trailing 4 weeks:

- **Median and MAD**, not mean and standard deviation. Attack traffic destroys
  the mean; the median barely moves. The anomaly score is a robust z-score:
  `0.6745 × (x − median) / MAD`.
- **EWMA** for the short-term level, α tuned per metric.
- **Hour-of-week seasonality**, so "1200 requests at 04:00 on a Sunday" is
  anomalous even though 1200 at 14:00 on a Tuesday is not.

Metrics tracked: requests/min, 4xx rate, 401/403 rate, unique source IPs,
new-country ratio, failed auth/min, bytes out, p95 latency, connection count.

**The 14-day warm-up matters.** While `baselines.warm = false`, anomaly
detections are recorded but not alerted, and the UI shows *„învățare în curs"*.
If someone asks why an obvious spike did not alert, check `warm` first — that is
usually the answer, and it is correct behaviour, not a bug.

An anomaly score alone is weak evidence. `|z| > 3.5` with no rule match is worth
a `low`; the same score alongside a signature match is worth escalating.

---

## Campaign correlation

Concurrent actors are clustered by shared `/24`, ASN, user-agent, JA4 TLS
fingerprint, request-path sequence and inter-arrival timing. Purely set
operations — no clustering algorithm, no threshold to tune badly.

Its predictive use: if a campaign has previously hit assets A then B then C in
that order, and it is currently on A and B, C is the next target. State that as
an ordering observation with the count of prior campaigns it is based on.

---

## Exposure crossing — the strongest signal

Join what an actor is **probing** against what the scanner knows is
**vulnerable** on the probed asset.

```
actor probes /wp-content/plugins/foo/
  × asset blog.example.com runs php-wordpress
  × open finding 881: CVE-2026-1234 in wp-plugin-foo 1.2.3, EPSS 0.72, KEV
  ⇒ predicted exploitation target
```

No ML, no probability model, and by far the most actionable output the system
produces. When it fires, it goes in the verdict as
`exposure_crossing.matched: true` with the finding ids, and it raises severity
by the matrix in `incident-triage.md`.

The negative case is worth stating too. *"Sondează pentru phpMyAdmin, care nu
este instalat"* caps the severity and tells the operator they were never
exposed — which is information, not noise.

---

## Risk score

A composite 0–100 per actor, per asset and globally. Deterministic, computed in
`predict/risk_score.py` from: kill-chain stage, dwell time at stage, detection
rate, reputation feed hits, exposure crossings, target criticality and whether
the actor has adapted after a block.

You do not compute it. You may explain what is driving it — the dossier gives
you the component breakdown.

---

## Forecasting

Expected-volume bands for the next 24 h come from the hour-of-week median and
MAD profile, rendered as a shaded band with actuals overlaid. Holt-Winters is
available but at this scale a seasonal median+MAD band is as accurate and is
explainable, which matters more.

Do not describe this as a forecast model. It is "the usual range for this hour,
from the last four weeks".

---

## How to phrase a prediction

Every prediction needs four parts: **the subject**, **the event**, **the
number**, **the basis**.

> „Actorul `203.0.113.44` (AS12345, RO), stadiul 2 de 14 minute.
> **36%** șanse de avansare la atac pe credențiale în următoarele 30 min
> (31 din 87 de actori cu tipar similar, ultimele 60 de zile).
> Ținta cea mai probabilă: `admin.example.com` — formular de login expus, fără rate-limit.
> Acțiune preventivă: blocare 2h."

And when the data does not support one:

> „Date insuficiente pentru o estimare — doar 4 actori cu acest tipar în
> istoricul disponibil. Recomand monitorizare, fără blocare preventivă."

That second form is a good answer. Use it.
