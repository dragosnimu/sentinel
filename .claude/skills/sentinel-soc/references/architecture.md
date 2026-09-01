# Architecture

What each component does, how they talk, and where the boundaries are. Read
this when you need to know *which* part of the system produced a piece of data,
or where to look for something.

---

## Processes

| Unit | User | Responsibility |
|---|---|---|
| `sentinel-ingest` | `sentinel` | All collectors. Tails logs, reads journald, polls Docker. Normalises to canonical events, enriches with geo/ASN/reputation, writes `raw_events`. |
| `sentinel-detect` | `sentinel` | Rule engine, sliding-window counters, statistical baselines, actor state machine, kill-chain transitions, incident open/append/close, auto-block decision. |
| `sentinel-ai` | `sentinel` | Consumes the `ai_jobs` queue: triage, correlation, prediction commentary, reports, patch plans. This is where you run. |
| `sentinel-telegram` | `sentinel` | Long-polling bot. Command handlers and the outbound notification queue. |
| `sentinel-web` | `sentinel` | uvicorn on `127.0.0.1:8787`. Read-only against the database plus an SSE hub. `IPAddressDeny=any` except loopback. |
| `sentinel-executor` | **root** | The only privileged component. Unix socket at `/run/sentinel/executor.sock`. |
| `sentinel-scan` (timer) | `sentinel` | Discovery and vulnerability scanning. Nightly plus on demand. `Nice=19`, `IOSchedulingClass=idle`. |
| `sentinel-health` (timer) | `sentinel` | Availability and capacity probes, every 30 s. |
| `sentinel-maintenance` (timer) | `sentinel` | Hourly: retention, partition management, rollups, intel refresh, disk guard, cert expiry. |
| `sentinel-watchdog` (timer) | **root** | Every 60 s. Anti-lockout deadman. Independent of every other daemon. |
| `suricata` | root | NIDS. Optional, RAM-gated at install. |

Separate processes rather than one: a Trivy memory spike must not stop
detection, the web process must not be able to reach executor logic in-process,
and systemd hardening can be tightened per role.

---

## How they communicate

**Everything durable goes through PostgreSQL.** There is no Redis, no message
broker — one fewer daemon, one fewer attack surface, one fewer RAM consumer.

| Path | Mechanism |
|---|---|
| ingest → detect | `LISTEN/NOTIFY` on channel `sentinel_events` plus a watermark row. Detect also polls on a 250 ms floor, so a lost NOTIFY is harmless. |
| detect / telegram / web → ai | Rows in `ai_jobs`, state machine `queued → running → done \| failed`, claimed with `SELECT … FOR UPDATE SKIP LOCKED`. |
| anything → executor | Newline-delimited JSON over the unix socket. `SO_PEERCRED` check that the peer uid is `sentinel`. Strict schema validation. The executor writes the audit row itself — the caller never does. |
| web → destructive action | The web app **never** talks to the executor. It writes an `action_requests` row. The responder picks it up, and for destructive classes requires a Telegram confirmation first. A compromised dashboard therefore cannot block or unblock anything on its own. |
| detect / patch runner → executor | Direct socket calls, since these are already trusted daemons. |
| anything → operator | `notifications` queue consumed by `sentinel-telegram`, with dedup, mute windows and digesting. |

---

## Event flow, end to end

```
packet or log line
  ↓ collector           (inode-aware tailer, journald cursor, or eve.json tail)
  ↓ parser              source-specific
  ↓ canonical Event     {ts, source, asset_id, src_ip, dst_port, action, http.*, user, raw}
  ↓ enrichment          geoip / ASN / reputation / asset lookup — all in-memory caches
  ↓ raw_events          partitioned daily
  ↓ detect engine
      (a) signature and pattern rules  → detection
      (b) threshold and rate rules     → detection
      (c) baseline anomaly (EWMA+MAD)  → detection with a score
  ↓ actor state machine  per src_ip and per actor-cluster; kill-chain stage update
  ↓ incident             open or append; fingerprint = rule_family + actor + asset + 15-min bucket
  ↓ severity             deterministic; if ≥ HIGH or inside the ambiguity band → enqueue ai_job(triage)
  ↓ response             if rule.auto_block and not allowlisted and rate caps OK → executor
  ↓ notification         Telegram push + web SSE + audit_log
```

The AI step is **off the hot path**. An incident exists, is visible, and has
been acted on before you ever see it. Your verdict enriches it; it does not
gate it.

---

## The executor protocol

Request, one JSON object per line:

```json
{"id":"<uuid>","op":"block_ip","args":{"ip":"203.0.113.44","ttl":86400,"reason":"ssh brute force","incident_id":42}}
```

Response:

```json
{"id":"<uuid>","ok":true,"result":{"applied":true,"expires_at":"..."},"audit_id":9182}
```

Allowed operations — this is the complete list, and it is deliberately short:

| op | Effect |
|---|---|
| `block_ip` / `unblock_ip` | Add or remove an element in the nftables blocklist set, with TTL |
| `allow_ip` / `disallow_ip` | Manage the allowlist set |
| `flush_blocklist` | Empty the blocklist (panic path) |
| `list_sets` | Read current nftables set contents |
| `backup_create` / `backup_restore` | Create or replay a restore point |
| `restore_drill_verify` | Extract a restore point's archives into an isolated, disposable directory and verify them — never `/`. Used by the monthly restore drill |
| `patch_step_exec` | Execute one validated argv from an approved patch plan |
| `service_action` | `start` / `stop` / `restart` / `reload` on a unit in the inventory |
| `read_privileged_file` | Read a specific allowlisted path (e.g. `/var/log/audit/audit.log`) |

Every op validates its arguments against a hard-coded policy in
`executor/policy.py` before doing anything. The policy is in **code**, not
config and not the database, so a database compromise cannot widen it.

---

## Trust boundaries

```
attacker traffic          →  untrusted, always
raw_events.raw            →  untrusted content, stored verbatim, never interpolated
web UI session            →  authenticated but NOT trusted for privileged actions
Telegram chat_id          →  authenticated, role-scoped, still requires 2-step confirm
sentinel daemons          →  trusted to request; NOT trusted to authorise
executor policy           →  the authority. Refuses even a trusted caller.
```

The practical consequence: compromising the web UI gets an attacker read access
to security data. Compromising the Telegram bot token gets them the ability to
*request* actions, still gated by confirmation and by executor policy.
Compromising the executor gets them root — which is why it is ~400 lines,
stdlib-only, imports nothing from `sentinel/`, and has its own hostile-input
test suite.

---

## The two Claude transports

| Transport | Used for | Why |
|---|---|---|
| Messages API direct (`sentinel/ai/client.py`) | triage, correlation, prediction, reports | Fast, cheap, structured output, prompt caching on the large system block. Needs no filesystem access. |
| Headless CLI (`claude -p`, `sentinel/ai/cli_bridge.py`) | patch plans, `/ask` | These need to *look at the server*: read the nginx vhost, the systemd unit, `composer.lock`, `dnf` output. |

The CLI runs as user `sentinel` with `cwd` and `HOME` both set to
`/opt/sentinel/claude-workspace`, so this skill is discovered as a project skill
and as a personal skill. It runs with `--permission-mode plan` and a read-only
tool allowlist, which is what makes prompt injection from a log line structurally
unable to change the system rather than merely unlikely to.

---

## Degradation

Every dependency has a defined failure mode. When something looks broken, check
here before assuming a bug:

| Failing | Result |
|---|---|
| Anthropic API | Deterministic verdicts stand. Messages tagged `(analiză AI indisponibilă)`. Patch generation returns an error, never a partial plan. |
| Telegram | Notifications queue up (bounded). Dashboard unaffected. Auto-block still works — you just do not hear about it, which is why the queue depth is on the health page. |
| PostgreSQL | Ingest buffers to disk briefly, then drops with a counter. Detect stops. Executor keeps working — existing blocks stay, TTLs still expire in the kernel. |
| Suricata | Log-based detection continues. NIDS-sourced rules go quiet. Banner in the UI. |
| `sentinel-detect` in a restart loop | The watchdog flushes the blocklist and alerts. Deliberate: a detector that cannot run must not leave stale blocks. |
