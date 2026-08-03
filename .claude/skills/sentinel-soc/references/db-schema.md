# Database schema

PostgreSQL 16, database `sentinel`, on `127.0.0.1:5432`. All timestamps are
`timestamptz` in UTC; render them in `Europe/Bucharest` for the operator.

Prefer `scripts/sentinel_query.py` over raw SQL — the named catalog covers the
common questions and is parameterised. Use this reference when you need a query
the catalog does not have.

---

## Assets and inventory

### `assets`
The things Sentinel protects. Populated by discovery, corrected by the operator.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial PK` | |
| `name` | `text UNIQUE` | `blog.example.com`, `sshd`, `postgres` |
| `kind` | `text` | `web`\|`service`\|`container`\|`database`\|`host` |
| `bind_addr` | `inet` | |
| `port` | `int` | |
| `is_internet_exposed` | `bool` | Confirmed by an external reachability probe, not just by a `0.0.0.0` bind |
| `criticality` | `int` | 1–5, operator-set. Feeds vulnerability prioritisation |
| `systemd_unit` | `text` | |
| `container_id` / `container_image` | `text` | |
| `vhost_file` / `webroot` | `text` | |
| `repo_path` / `repo_remote` / `repo_branch` | `text` | |
| `stack` | `text` | `php-wordpress`, `node-express`, `python-fastapi`, `rpm`, … |
| `databases` | `jsonb` | `[{engine,name,host,port}]` — what a backup step must dump |
| `protected` | `bool` | **`true` ⇒ no automated patch plan, ever.** Sentinel's own components, and anything the operator has declared off limits |
| `confirmed_by_operator` | `bool` | **Active scanning (DAST) requires this** |
| `tags` | `text[]` | |
| `first_seen` / `last_seen` | `timestamptz` | |

### `asset_drift`
Discovery findings that contradict the operator-maintained inventory. Reviewed,
never silently applied.

---

## Events — high volume, partitioned daily by `ts`

### `raw_events` (partitioned)

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | |
| `ts` | `timestamptz` | Partition key |
| `source` | `text` | `sshd`\|`nginx`\|`apache`\|`auditd`\|`suricata`\|`docker`\|`journald`\|`fim`\|`conntrack` |
| `asset_id` | `bigint` | Nullable — not every event maps to an asset |
| `src_ip` / `dst_ip` | `inet` | |
| `src_port` / `dst_port` | `int` | |
| `proto` | `text` | |
| `action` | `text` | `accept`\|`deny`\|`auth_fail`\|`auth_ok`\|`request`\|`exec`\|… |
| `username` | `text` | |
| `http_method` / `http_path` / `http_status` / `http_ua` / `http_host` | | **Attacker-controlled. Untrusted.** |
| `bytes_in` / `bytes_out` | `bigint` | |
| `geo_country` / `geo_asn` / `geo_as_org` | | From the mmdb |
| `reputation` | `text[]` | Feed names that list this IP |
| `raw` | `jsonb` | Original parsed payload. GIN-indexed |

Retention: 30 days. Older partitions are `DETACH`ed and dropped — instant, no
bloat. The disk guard drops early if free space < 15%.

### `event_rollup_1m` / `event_rollup_1h`
Pre-aggregated counters per `(bucket, asset_id, source, action)`: `n`,
`uniq_src`, `bytes_in`, `bytes_out`, `p95_latency_ms`. Retention 90 d / 400 d.
**Use these for anything covering more than ~24 hours** — querying `raw_events`
across weeks is slow and usually unnecessary.

---

## Detections, actors, incidents

### `detections`
One row per rule match. Cheap, numerous, mostly uninteresting on their own.

| Column | Notes |
|---|---|
| `rule_id` | Namespaced string: `auth.ssh_bruteforce`, `web.sqli`, `host.new_listener` |
| `rule_family` | `auth`\|`web`\|`scan`\|`host`\|`dos`\|`anomaly`\|`availability`\|`tls` |
| `severity` | `info`\|`low`\|`medium`\|`high`\|`critical` |
| `score` | `numeric` — anomaly z-score where applicable |
| `actor_key` | Joins to `actors` |
| `asset_id`, `src_ip`, `evidence` (`jsonb`), `event_ids` (`bigint[]`) | |
| `incident_id` | Set when folded into an incident |

### `actors`
Rolling profile per source. `actor_key` is the IP for single sources, or
`cluster:<hash>` for a correlated group (same /24 + ASN + UA/JA4 fingerprint).

| Column | Notes |
|---|---|
| `killchain_stage` | `0`–`6`. See `prediction-model.md` |
| `stage_entered_at` | How long they have been at the current stage — this matters for prediction |
| `first_seen` / `last_seen` / `event_count` / `detection_count` | |
| `countries` / `asns` / `user_agents` / `targeted_assets` | Arrays |
| `reputation` | `text[]` |
| `risk_score` | `0`–`100`, composite, deterministic |
| `is_allowlisted` / `is_blocked` | |

### `incidents`
What a human actually looks at.

| Column | Notes |
|---|---|
| `fingerprint` | `rule_family + actor_key + asset_id + 15-min bucket`. Dedup key |
| `status` | `open`\|`acknowledged`\|`resolved`\|`false_positive`\|`suppressed` |
| `severity` | Deterministic severity |
| `ai_severity` / `ai_verdict` (`jsonb`) / `ai_confidence` / `ai_analyzed_at` | Your output lands here |
| `title` / `summary` | Romanian |
| `detection_count`, `first_detection_at`, `last_detection_at` | |
| `actor_key`, `asset_id` | |
| `acknowledged_by`, `resolved_at`, `resolution_note` | |

`incident_timeline` holds the ordered event/action history per incident.

---

## Response

### `blocklist`
The database's view of what is blocked. The kernel's nftables sets are the
authority; a reconcile loop keeps them consistent.

| Column | Notes |
|---|---|
| `ip` | `inet` |
| `reason`, `rule_id`, `incident_id` | Why |
| `blocked_at`, `expires_at` | `NULL` expiry = permanent, operator-only |
| `ttl_seconds`, `hit_count` | `hit_count` from the nft counter — did blocking help? |
| `created_by` | `auto`\|`telegram:<chat_id>`\|`operator` |
| `active`, `unblocked_at`, `unblocked_by` | |

### `allowlist`
Never-block entries. The **hard-coded** list in `executor/policy.py` is separate
and takes precedence; this table is the operator-managed addition to it.

### `action_requests`
Queued actions from the web UI or the AI, awaiting approval or execution.
State: `pending → awaiting_confirmation → approved → executing → done|failed|rejected`.

### `audit_log`
Append-only, hash-chained (`prev_hash`, `entry_hash`). Every privileged
operation, every Telegram command, every login, every config change. Written by
the executor for privileged ops, so a compromised caller cannot forge or omit
an entry. Chain breaks are detectable and alert.

---

## Vulnerabilities

### `scans`
One row per scan run: `scanner`, `target`, `started_at`, `finished_at`,
`status`, `findings_count`, `raw_output_path`, `duration_ms`, `exit_code`.

### `findings`
Deduplicated vulnerabilities. `finding_key` is stable across scans, so a
finding has a *history*, not a new row each night.

| Column | Notes |
|---|---|
| `finding_key` | `sha256(scanner + asset + package + cve + location)` |
| `cve`, `cvss`, `severity` | |
| `epss` | `numeric` — probability of exploitation in the next 30 days |
| `kev` | `bool` — in the CISA Known Exploited Vulnerabilities catalog |
| `package`, `installed_version`, `fixed_version`, `location` | |
| `priority` | `0`–`100`, computed. **Rank by this, not by CVSS** |
| `status` | `open`\|`patch_planned`\|`patching`\|`resolved`\|`accepted_risk`\|`deferred`\|`false_positive` |
| `first_seen`, `last_seen`, `resolved_at` | |
| `deferred_until`, `accepted_by`, `accepted_reason` | |

Priority formula (deterministic, in `scan/prioritize.py`):
`CVSS` × `EPSS` × `KEV multiplier` × `internet-exposed multiplier` ×
`asset criticality` × `fix availability`. A CVSS 7.5 in a KEV-listed,
internet-facing app outranks a CVSS 9.8 in an unexposed local library.

---

## Patching

### `patch_plans`

| Column | Notes |
|---|---|
| `plan` | `jsonb` — the full validated plan |
| `plan_hash` | `sha256`. Telegram approval tokens bind to this. Regenerate the plan ⇒ every outstanding button dies |
| `status` | `draft`\|`validated`\|`rejected_invalid`\|`approved`\|`scheduled`\|`applying`\|`applied`\|`rolled_back`\|`failed`\|`rejected` |
| `asset_id`, `finding_ids` (`bigint[]`) | |
| `risk_level`, `requires_reboot`, `estimated_downtime_s` | |
| `validation_errors` | `jsonb` — why a `rejected_invalid` plan failed |
| `generated_by`, `generation_ms`, `model` | |
| `approved_by`, `approved_at` | |

### `patch_executions` / `patch_steps`
`patch_steps` holds one row per step: `phase` (`preflight`\|`backup`\|`apply`\|
`health_check`\|`rollback`\|`post_verification`), `argv`, `exit_code`,
`stdout`/`stderr` (truncated to 64 KB, secrets redacted), `duration_ms`,
`started_at`, `finished_at`.

**Rows are flushed before the next step starts.** A crash mid-patch leaves a
complete forensic trail. When diagnosing a failed patch, read these in order.

### `restore_points`
`path`, `manifest` (`jsonb` — every item with size and sha256), `size_bytes`,
`asset_id`, `plan_id`, `created_at`, `verified_at`, `retention_hold`.

`retention_hold` protects the most recent successful point per asset from
garbage collection regardless of age. There is never zero ways back.

---

## Health and availability

### `health_samples`
Every 30 s per asset: `status` (`up`\|`degraded`\|`down`), `latency_ms`,
`http_status`, `error`. Partitioned daily, 30-day retention.

### `availability_rollup`
Per `(asset_id, day)`: `samples`, `up_samples`, `degraded_samples`,
`down_samples`, `uptime_pct`, `p50_latency_ms`, `p95_latency_ms`,
`incidents_count`. This is what the SLA views read.

### `capacity_samples`
Host-level, every 30 s: `cpu_pct`, `load1/5/15`, `mem_used_mb`,
`mem_available_mb`, `swap_used_mb`, `disk_used_pct` per mount, `inode_used_pct`,
`conn_count`, `per_service_rss` (`jsonb`).

Used for the projected disk-full date, and for the "did the nightly scan hurt
anything" question — compare `p95_latency_ms` for the host's own services inside
and outside the scan window.

---

## Prediction

### `baselines`
Per `(asset_id, metric, hour_of_week)`: `median`, `mad`, `ewma`, `sample_count`,
`updated_at`, `warm` (bool). **`warm = false` ⇒ inside the 14-day warm-up;
anomaly detections are recorded but not alerted.** If someone asks why an
obvious anomaly did not alert, check this first.

### `killchain_transitions`
`actor_key`, `from_stage`, `to_stage`, `at`, `elapsed_s`, `evidence_pattern`.
The empirical transition matrix is computed from this table.

### `predictions`
`made_at`, `actor_key`, `asset_id`, `predicted_stage`, `probability`,
`horizon_minutes`, `basis` (`jsonb`), then later `outcome` (`bool`),
`scored_at`. The Brier score on the analytics page comes from here.

**Every prediction you state must be recorded here so it can be scored.** A
prediction that is never checked is marketing.

---

## Auth, AI, audit

### `users` / `sessions`
`users`: `username`, `password_hash` (Argon2id), `totp_secret` (encrypted),
`role` (`owner`\|`operator`\|`viewer`), `failed_attempts`, `locked_until`.

### `telegram_callbacks`
`token`, `chat_id`, `action`, `params` (`jsonb`), `plan_hash`, `expires_at`,
`used_at`. Single-use, HMAC-signed. Callback data carries only the opaque
token — never parameters.

### `ai_jobs`
`kind` (`triage`\|`correlate`\|`predict`\|`report`\|`patch_plan`\|`ask`),
`payload`, `state`, `attempts`, `result`, `error`, `enqueued_at`,
`started_at`, `finished_at`, `dedup_key`.

### `ai_usage`
`job_id`, `model`, `input_tokens`, `output_tokens`, `cache_read_tokens`,
`cost_usd`, `at`. Feeds `/budget` and the circuit breaker.

---

## Query patterns worth knowing

- **Anything over 24 hours: use the rollups.** `raw_events` across weeks is
  slow and the aggregate is what you wanted anyway.
- **Always filter `raw_events` on `ts`** so partition pruning applies.
- Actor history: join `detections` → `actors` on `actor_key`, not on `src_ip` —
  an actor may be a cluster spanning many IPs.
- "Did blocking work?" is `blocklist.hit_count` after the block, plus whether
  the same `actor_key` reappears from a different IP.
- Finding age: `now() - findings.first_seen` where `status = 'open'`. This is
  the number that should be going down.
