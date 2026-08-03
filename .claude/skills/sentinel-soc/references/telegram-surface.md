# Telegram surface

The command set, the button flows, and the formatting rules your output must
satisfy when it is destined for a Telegram message.

---

## Formatting constraints

- **MarkdownV2.** These characters must be backslash-escaped anywhere they
  appear in text: ``_ * [ ] ( ) ~ ` > # + - = | { } . !``
  The formatter escapes automatically, but if you emit pre-formatted markup you
  own the escaping. Safest: emit plain text and let `formatting.py` decorate it.
- **4096 characters per message.** Longer output is truncated with a link to the
  dashboard. Write for the limit; do not rely on truncation.
- **Lead with the decision.** The first line is what gets read on a lock screen.
  Detail goes below.
- **No tables.** They do not render. Use short labelled lines.
- **Romanian**, per `romanian-style.md`.

Message skeleton:

```
🔴 CRITIC · Atac țintit pe blog.example.com

203.0.113.44 (AS12345, RO) exploatează CVE-2026-1234 — plugin foo 1.2.3, KEV.
Stadiu 4/6. Blocat automat 24h.

Recomandat: patch în fereastra 03:00. 36% șanse de escaladare în 30 min.
```

Severity markers: 🔴 `CRITIC` · 🟠 `RIDICAT` · 🟡 `MEDIU` · 🔵 `SCĂZUT` · ⚪ `INFO`

---

## Commands

### Status and monitoring

| Command | Behaviour |
|---|---|
| `/start`, `/help` | Menu with inline buttons |
| `/status` | One screen: services up/down, open incidents by severity, blocked IPs, open critical vulnerabilities, threat level 0–100, AI budget used |
| `/services` | Per-service state, uptime today/7d/30d, response time |
| `/incidents [n]` | Last n incidents (default 10), severity marker, `Detalii` button each |
| `/incident <id>` | Full dossier: timeline, actor, evidence, AI verdict, recommended actions, buttons |
| `/actor <ip>` | Actor profile: geo/ASN, reputation, kill-chain stage, history, first/last seen |
| `/top [24h\|7d]` | Top attacking IPs, countries, ASNs, targeted endpoints |
| `/traffic [asset]` | Current volume vs. the expected band |

### Response

| Command | Behaviour |
|---|---|
| `/block <ip> [ttl] [motiv]` | Validates the IP, checks the allowlist. Default TTL 24 h. Confirmation required for permanent blocks and for anything wider than /24 |
| `/unblock <ip>` | Immediate |
| `/blocklist [n]` | Current blocks with remaining TTL, reason, hit counter, `Deblochează` button each |
| `/allow <ip> [motiv]` | Add to the never-block allowlist. Requires confirmation |
| `/watch <ip>` | Monitor without blocking |
| `/mute <minute>` | Suppress non-critical notifications. Critical always passes |
| `/panic` | **Flush the entire blocklist immediately.** Double confirmation. Always available, even when muted |

### Vulnerabilities and patching

| Command | Behaviour |
|---|---|
| `/scan [all\|os\|web\|code\|<asset>]` | Trigger a scan, report progress |
| `/vulns [critical\|high\|kev]` | Prioritised list |
| `/vuln <id>` | Detail, plus a `Generează plan de patch` button |
| `/patch <finding_id>` | Generate a plan — this is where you get invoked |
| `/patches` | Plans by state: draft / approved / applied / rolled-back |
| `/plan <plan_id>` | Full plan text with action buttons |
| `/restore` | List restore points; restore requires double confirmation |

### Reporting and AI

| Command | Behaviour |
|---|---|
| `/report [zi\|saptamana\|luna]` | Generate and send the report |
| `/predict` | Current predictions with probabilities and the calibration note |
| `/ask <întrebare>` | Free-form question over the database, read-only. Rate-limited and budget-capped |

### Admin

| Command | Behaviour |
|---|---|
| `/health` | Sentinel's own health: each unit, DB size, queue depths, feed freshness, last successful AI call |
| `/version` | Version, git sha, deploy timestamp |
| `/config get\|set <key> [val]` | Whitelisted tunables only — thresholds, TTLs, quiet hours. Never secrets, never paths, never command allowlists |
| `/budget` | AI spend today and this month against the cap |

---

## Button flows

| Context | Buttons |
|---|---|
| Incident push | `🔍 Detalii` · `🚫 Blochează IP` · `👁 Watch` · `✅ Fals pozitiv` · `🔇 Suprimă regula 1h` |
| Auto-block notice | `↩️ Deblochează` · `🔒 Permanentizează` · `📊 Vezi activitatea` |
| Observe-mode notice (auto-block off) | `🚫 Blochează acum` · `👁 Watch` · `✅ Fals pozitiv` |
| Vulnerability | `📄 Detalii` · `🛠 Generează plan` · `😴 Amână 7 zile` · `🙈 Acceptă riscul` |
| Patch plan | `📄 Vezi` · `🧪 Dry-run` · `✅ Aplică` · `⏰ Programează` · `❌ Respinge` |
| Service down | `🔄 Restart serviciu` · `📜 Ultimele loguri` · `🔇 Mute 30m` |

`↩️ Deblochează` is present on **every** auto-block message. A bad block is one
tap from reversal — that is the property that makes auto-blocking acceptable at
all.

`✅ Aplică` never executes. It opens a second confirmation restating the target,
the estimated downtime and the backup size, with `DA, aplică` / `Anulează`.

---

## Security properties you should be aware of

You do not implement these, but they constrain what your output can contain.

- **Callback data carries only an opaque token**, never parameters. The real
  payload lives server-side in `telegram_callbacks`, single-use, HMAC-signed,
  TTL-bound. Never suggest encoding an IP, a plan id or a command into callback
  data.
- **Approval tokens bind to `plan_hash`.** Regenerating a plan changes the hash
  and kills every outstanding button. If a plan is regenerated, say so — the
  operator's old message is now dead and they need the new one.
- **`allowed_chat_ids` is checked on every update type**, not just messages.
- **Roles**: `owner` (everything), `operator` (block/unblock/scan; no patch
  apply, no config), `viewer` (read-only). If asked about an action the caller's
  role does not permit, say so rather than describing how to bypass it.
- **All arguments are typed and validated** before reaching any handler. IPs go
  through `ipaddress`, ids are ints, TTLs are bounded 60 s–30 d, reasons are
  length-capped and stripped of control characters.
- Destructive actions always take two steps, and the confirmation restates the
  exact target so a mis-tap on a stale message is visible.
