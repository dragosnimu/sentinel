# Environment — this server

Read this before proposing any change.

Sentinel is a guest on this machine. Something else was here first, and that
something is why the server exists. The constraints below exist so that
installing a security agent does not become the incident it was meant to
prevent.

---

## What Sentinel owns

Everything here is Sentinel's, and nothing here belongs to anything else.

| Port | Bound to | Service |
|---|---|---|
| `80/tcp`, `443/tcp` | public | nginx (TLS termination for the dashboard) |
| `8787/tcp` | `127.0.0.1` only | `sentinel-web` (uvicorn) |
| `5432/tcp` | `127.0.0.1` only | PostgreSQL |

```
/opt/sentinel/                lib/ bin/ libexec/ venv/ claude-workspace/
/etc/sentinel/                sentinel.yaml inventory.yaml detection.yaml
                              notifications.yaml secrets.env (0640 root:sentinel)
/var/lib/sentinel/            state, cursors, geoip db, intel feeds, install markers
/var/backups/sentinel/        restore points
/run/sentinel/executor.sock   privileged-action socket
/etc/sentinel/PANIC           if this file exists, the watchdog flushes all blocks
```

Units: `sentinel-ingest`, `sentinel-detect`, `sentinel-ai`, `sentinel-telegram`,
`sentinel-web`, `sentinel-executor` (root), plus the `sentinel-scan`,
`sentinel-health`, `sentinel-maintenance` and `sentinel-watchdog` timers.

**Sentinel does not patch Sentinel.** `/opt/sentinel` and `/etc/sentinel` are on
the protected-paths list; upgrades go through `deploy/upgrade.sh`, run by the
operator.

---

## What Sentinel does not own

This is the part that requires judgement, because it differs per deployment.

### The asset inventory is the authority

`/etc/sentinel/inventory.yaml` is what the operator has confirmed. Two fields
decide what you may propose:

| Field | Meaning |
|---|---|
| `protected: true` | **No automated patch plan may ever exist for this asset.** Its availability is monitored, so the operator knows if it dies, but nothing automated touches it |
| `confirmed_by_operator: false` | **No active scanning (DAST).** Discovery finding a service is not authorisation to attack it |

Before writing any plan:

```bash
scripts/asset_context.py --asset-id <id>
```

It returns `protected` and a `notes` list that spells out any restriction. If
`protected` is true, return the error object with
`reason_code: protected_asset` — there is no workaround, and looking for one is
the wrong instinct.

### Protected paths

The hard floor, in `sentinel/constants.py` and `executor/policy.py`:

```
/opt/sentinel  /etc/sentinel  /var/lib/sentinel  /var/backups/sentinel
/root/.ssh  /etc/ssh  /etc/passwd  /etc/shadow  /etc/sudoers  /etc/sudoers.d
/boot
```

**Plus everything in `patch.extra_protected_paths`** in the config. That is
where the operator lists this deployment's own untouchables: another product's
install directory, a database they would rather upgrade by hand, a mount
someone else manages.

Read that config value before writing a plan. It is deployment-specific, so it
is the one place where a plan that would be fine on another server is wrong on
this one.

### Never-block addresses

Hard-coded (universal): loopback, RFC1918, link-local, multicast, broadcast.

**Plus everything in `response.extra_allowlist`.** That is where the operator
puts their uptime monitor, their CI runner, their office range, and any
high-volume source that must not be cut off. Check it before recommending a
block — recommending a block the executor will refuse wastes the operator's
attention and makes your next recommendation less trusted.

---

## Resource budget

Sentinel shares this host. Every resource it takes is one the actual workload
does not have, and the OOM killer chooses the largest process — which is
usually the application, not Sentinel. That failure appears as "the site is
down", with nothing obviously pointing at the monitoring agent that caused it.

Consequences for anything you propose:

- **Never propose a change that increases steady-state memory** without saying
  what it costs and what it displaces.
- **Never propose running a scanner** (Trivy, semgrep, nuclei) outside the
  configured night window, or in parallel with another scan. They spike to
  hundreds of megabytes.
- `systemctl show sentinel-<unit> -p MemoryCurrent` is the fast check.
- Every unit has a `MemoryMax`. If one is being hit, the answer is usually to
  narrow what it does, not to raise the ceiling.

Check `suricata.enabled` before referring to NIDS data. If it is `false`,
`eve.json` does not exist and Sentinel is in log-only mode — the installer skips
Suricata when there was not enough memory headroom at install time. Detection
still works; it has no packet-level visibility.

---

## Traffic Suricata does not see

`suricata.bpf_filter` may exclude a high-volume flow — bulk telemetry, a syslog
feed, backup replication. Preflight samples the interface and the operator sets
this if a dominant flow exists.

If you are analysing an incident and the network evidence seems thin, check
whether the relevant traffic is inside that filter. It is a legitimate blind
spot, not a bug, and it is worth stating explicitly in a verdict rather than
reasoning as though you had full visibility.

---

## Network egress Sentinel depends on

When something "stopped working", this is often the real answer:

| Destination | Used by | Degradation if blocked |
|---|---|---|
| `api.anthropic.com` | AI triage, patch plans, reports | Deterministic verdicts only, tagged `(analiză AI indisponibilă)` |
| `api.telegram.org` | Bot | No alerts, no commands. Dashboard still works |
| Let's Encrypt ACME | certbot renewal | Cert expires within 90 days → dashboard unreachable |
| Threat-intel feeds | reputation enrichment | Stale reputation, higher false-positive rate |
| EPSS / CISA KEV | vulnerability prioritisation | Prioritisation falls back to CVSS alone |
| Trivy / nuclei DB updates | scanners | Scans run against a stale database |

These are allowlisted from blocking. A self-inflicted block of
`api.telegram.org` would be silent — no error, no alert, just a system that has
quietly stopped telling anyone anything — so the executor refuses it.

---

## Things that look like incidents but are not

Check here before escalating:

| Signal | Explanation |
|---|---|
| A recurring `tcpdump` or packet capture as root | Often a legitimate metrics sampler. Check `detection.yaml` → `host.pkt_capture.exclude_cmdline`; if the command matches, it is expected |
| Container churn under `/var/lib/docker` | Normal Docker operation. Deliberately excluded from the auditd rules |
| Nightly bursts of outbound HTTPS 03:00–05:00 | The scan window: Trivy DB, nuclei templates, intel feeds |
| Connections to `127.0.0.1:5432` from Sentinel units | The database |
| Hits on `/.well-known/acme-challenge/` | certbot renewal. Allowlisted |
| A successful dashboard login from an unfamiliar address | Check the audit log and `login_attempts` before calling it a compromise. The operator travels |
| High-volume traffic from a source in `extra_allowlist` | Something the operator has explicitly declared legitimate |

When you are unsure whether a signal is routine on **this** host, say so rather
than guessing. The operator knows what their server does; you know what the
data shows. A verdict that says "this looks like X, but if `<service>` normally
does Y then it is routine" is more useful than a confident wrong classification.
