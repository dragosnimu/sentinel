# Detection catalog

Every rule, what it means, how it is tuned, and its known false positives.
Read the relevant row before judging whether a detection is real.

Thresholds live in `/etc/sentinel/detection.yaml` and in
`sentinel/detect/rules.d/*.yml`. The values below are the shipped defaults;
check the config for the live values before quoting a number to the operator.

---

## `auth` — authentication attacks

| Rule id | Fires when | Default severity | Auto-block | Known false positives |
|---|---|---|---|---|
| `auth.ssh_bruteforce` | ≥ 10 failed SSH auths from one source in 120 s | `high` | yes | A misconfigured backup agent or CI runner with a stale key. Check `username` — a real attacker cycles usernames, a broken client repeats one |
| `auth.ssh_spray` | ≥ 8 distinct usernames from one source in 300 s, ≤ 3 attempts each | `high` | yes | Rare. Spraying is almost always real, and more serious than brute force — it implies a user list |
| `auth.ssh_success_after_failures` | Successful auth from a source with ≥ 5 prior failures in 600 s | `critical` | no | An operator fat-fingering a passphrase. Check whether the key fingerprint is known before escalating |
| `auth.web_login_bruteforce` | ≥ 15 4xx on a known login path from one source in 120 s | `high` | yes | A user with a saved wrong password and an aggressive retry loop |
| `auth.basic_auth_bruteforce` | ≥ 20 401s from one source in 120 s | `medium` | yes | Monitoring probes hitting a protected endpoint without credentials — allowlist the monitor |
| `auth.default_creds` | Request bodies or paths matching known default-credential patterns | `high` | yes | Penetration tests you authorised |
| `auth.sudo_failures` | ≥ 3 failed `sudo` in 300 s for one user | `medium` | no | Genuine typos. Correlate with an active session before treating it as lateral movement |
| `auth.new_user` / `auth.new_ssh_key` | `useradd`, or a write to any `authorized_keys` | `critical` | no | Legitimate provisioning. Always worth an alert — this is a classic persistence step |

## `scan` — reconnaissance

| Rule id | Fires when | Default severity | Auto-block | Known false positives |
|---|---|---|---|---|
| `scan.horizontal` | One source touches ≥ 15 distinct ports in 60 s | `medium` | yes | Internet-measurement projects (Shodan, Censys, Rapid7). Reputation feeds usually tag them — check `actors.reputation` before escalating |
| `scan.vertical` | One source touches ≥ 50 distinct hosts (only meaningful on multi-IP hosts) | `medium` | yes | — |
| `scan.syn_sweep` | Suricata SYN-scan signature | `medium` | yes | Requires Suricata; absent in log-only mode |
| `scan.tls_no_request` | TLS handshake completed, no HTTP request, ≥ 5 times in 60 s | `low` | no | Health checkers and uptime monitors. Allowlist yours |

## `web` — application attacks

| Rule id | Fires when | Default severity | Auto-block | Known false positives |
|---|---|---|---|---|
| `web.sqli` | SQLi payload patterns in path, query or body | `high` | yes | Search boxes where users legitimately type `'` or `--`. Check whether the request hit a search endpoint and returned 200 |
| `web.xss` | XSS payload patterns | `medium` | yes | Same: user-generated content submitted through a legitimate form |
| `web.lfi_traversal` | `../`, `..%2f`, `/etc/passwd`, null bytes in a path | `high` | yes | Badly-encoded legitimate URLs; rare |
| `web.rce` | Command-injection patterns, `${jndi:`, template-injection markers | `critical` | yes | Almost never a false positive. Treat as real |
| `web.upload_attempt` | POST/PUT of an executable extension to a webroot | `high` | yes | CMS media uploads by an authenticated user. Check whether the session was authenticated |
| `web.sensitive_path` | `.env`, `.git/config`, `backup.sql`, `.DS_Store`, `phpinfo.php`, `/actuator`, `/server-status` | `medium` | yes | Your own security scanner. The scanner source is allowlisted |
| `web.admin_probe` | `/wp-admin`, `/phpmyadmin`, `/administrator`, `/manager/html` when not present | `low` | no | Constant internet background noise. Individually meaningless; matters as part of a sequence |
| `web.enumeration` | ≥ 60 4xx from one source in 60 s | `medium` | yes | A crawler following broken links. Distinguish by whether the 404 paths appear in your own HTML |
| `web.shellshock` / `web.log4shell` / named CVE probes | Signature match | `high` | yes | — |

## `dos` — availability attacks

| Rule id | Fires when | Default severity | Auto-block | Known false positives |
|---|---|---|---|---|
| `dos.request_rate` | Requests/min from one source > baseline + 6·MAD, floor 300/min | `medium` | yes | A legitimate burst — a newsletter send, a link going viral. Check whether many sources rose together; a real DoS is usually distributed |
| `dos.conn_flood` | Concurrent connections from one source > 200 | `medium` | yes | NAT'd office ranges. **Blocking by /24 is off by default for exactly this reason** |
| `dos.slowloris` | ≥ 50 connections open > 60 s with no complete request | `high` | yes | — |

## `host` — host integrity

| Rule id | Fires when | Default severity | Auto-block | Known false positives |
|---|---|---|---|---|
| `host.new_listener` | A listening socket appears that is not in the inventory | `high` | n/a | Legitimate deploys. Reconcile against `inventory.yaml` and `asset_drift` |
| `host.webroot_write` | A file written under a webroot outside a deploy window | `critical` | n/a | CMS caches and log files inside the webroot. Tune the exclusion list per asset |
| `host.new_suid` | A new SUID binary appears | `critical` | n/a | Package installs. Correlate with `dnf` history |
| `host.cron_change` | Any change under `/etc/cron*` or a user crontab | `high` | n/a | Legitimate admin work |
| `host.unexpected_outbound` | Outbound to a destination not in the expected set | `high` | n/a | New package repos, new CDN endpoints, certbot |
| `host.pkt_capture` | `tcpdump`/`tshark` running, or an interface in promiscuous mode | `medium` | n/a | A legitimate metrics sampler on this host. Check `detection.yaml` → `host.pkt_capture.exclude_cmdline` before escalating |
| `host.systemd_unit_added` | A new unit file appears | `high` | n/a | Deploys |

## `anomaly` — statistical

| Rule id | Fires when | Default severity | Auto-block |
|---|---|---|---|
| `anomaly.traffic_volume` | Robust z-score > 4 on requests/min for an asset | `low` | no |
| `anomaly.error_rate` | z > 4 on 4xx or 5xx rate | `low` | no |
| `anomaly.new_country` | New-country ratio z > 4 | `info` | no |
| `anomaly.bytes_out` | z > 4 on bytes out — possible exfiltration | `medium` | no |

**All `anomaly.*` rules are suppressed while `baselines.warm = false`.** They
are recorded, not alerted. Anomaly alone never auto-blocks.

## `availability` / `tls`

| Rule id | Fires when | Default severity |
|---|---|---|
| `availability.service_down` | 3 consecutive failed probes | `high` |
| `availability.service_degraded` | p95 latency > 3× the 7-day baseline | `medium` |
| `availability.capacity_disk` | Disk > 85%, or projected full in < 7 days | `high` |
| `availability.capacity_memory` | `MemAvailable` < 500 MB | `critical` |
| `tls.expiring` | Certificate expires in < 14 days | `medium` (`high` under 7 days) |
| `tls.invalid_chain` / `tls.weak_protocol` | Chain or protocol problem | `medium` |

`availability.capacity_memory` is `critical` on this host specifically: memory
pressure ends with the OOM killer choosing the largest process, which is
usually the application this host exists to run — not Sentinel. See
`environment.md`.

---

## Suppression

An operator marking an incident *„Fals pozitiv"* in Telegram writes a
suppression entry keyed on `(rule_id, actor pattern, asset)` **and** records
tuning data. That feedback is how the false-positive rate goes down. When you
classify something as `false_positive`, name the rule and the specific condition
that misfired — that is what makes the suppression narrow rather than blanket.

Maintenance windows suppress `availability.*` and `host.*` for their duration.
If an incident falls inside one, check before escalating.

---

## Auto-block policy

Auto-block only fires when **all** of these hold: the rule has
`auto_block: true` · `response.auto_block.enabled` is true in config · the actor
is not allowlisted · the rate caps are not exceeded (60 blocks/min, 20 000
elements) · the actor is not classified as a known research scanner.

**Ships disabled.** The first 72 hours are observe-only: the operator gets a
Telegram message saying what *would* have been blocked, with a button to do it.
If someone asks why an obvious attacker was not blocked, check
`response.auto_block.enabled` before looking for a bug.

Default TTLs: `scan.*` 1 h · `web.*` 6 h · `auth.*` 24 h · `dos.*` 2 h.
Permanent blocks are operator-only and never automatic.
