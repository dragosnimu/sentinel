# Patch plan schema

The authoritative machine-readable schema is
`assets/patch_plan.schema.json`. This document explains it and shows worked
examples. **Read both before writing a plan. Never write one from memory.**

A plan you produce is validated deterministically before anyone sees it. If it
fails validation you get one retry with the errors; if it fails again the plan
is stored as `rejected_invalid` and the operator is told the AI could not
produce a safe procedure. That outcome is acceptable. A plausible-looking plan
that breaks production is not.

---

## Hard rules — the validator enforces every one of these

1. **Every command is an argv array of strings.** Never a single string.
   No shell metacharacters anywhere: no `|`, `>`, `<`, `&&`, `;`, `$(`, backticks,
   `*` globs. There is no shell. If you need a pipeline, split it into steps or
   call a helper.

   ```jsonc
   "argv": ["dnf", "-y", "update", "nginx"]          // correct
   "argv": "dnf -y update nginx"                      // rejected
   "argv": ["sh", "-c", "dnf -y update nginx"]        // rejected: sh not allowlisted
   ```

2. **`argv[0]` must be in the binary allowlist:**
   `dnf`, `rpm`, `systemctl`, `nginx`, `httpd`, `apachectl`, `docker`, `git`,
   `npm`, `yarn`, `composer`, `pip`, `pip3`, `wp`, `mysqldump`, `mysql`,
   `pg_dump`, `psql`, `tar`, `zstd`, `cp`, `mv`, `ln`, `mkdir`, `chown`,
   `chmod`, `sed`, `install`, `certbot`, `curl`, `test`, and anything under
   `/opt/sentinel/bin/`.

3. **Forbidden targets — any path or flag touching these rejects the plan:**
   `/opt/sentinel`, `/etc/sentinel`, everything in `patch.extra_protected_paths`,
   `/root/.ssh`, `/etc/ssh/sshd_config`, `firewalld`, `nft`, `iptables`,
   `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.
   Also rejected regardless of path: `mkfs`, `dd`, `rm -rf /`, `chmod 777 /`,
   `> /dev/sd*`, `userdel`, `usermod`.

4. **Structural requirements:**
   - `backup` with ≥ 1 item if any `apply` step is not idempotent.
   - `rollback` with ≥ 1 step if `risk.reversible` is `true`.
     If you cannot write a rollback, set `reversible: false` — the plan is then
     auto-flagged `high_risk` and needs extra approval. Do not fake a rollback.
   - ≥ 1 `health_check`.
   - ≥ 1 `post_verification`.
   - ≥ 1 blocking `preflight`.

5. **`risk.requires_reboot: true`** is mandatory if the plan touches
   `kernel*`, `glibc`, `systemd`, `openssl`, `dbus`, or any package whose
   advisory says a reboot is needed. Such plans require a separate reboot
   approval from the operator.

6. **`protected: true` assets get no plan at all.** Return an error object
   explaining that manual intervention is required.

7. **Timeouts are mandatory** on every step. Nothing runs unbounded.

---

## Structure

```jsonc
{
  "plan_id": "<uuid>",                    // generated for you; echo if present
  "schema_version": 1,
  "target": {
    "asset_id": 12,
    "asset_name": "blog.example.com",
    "stack": "php-wordpress",
    "systemd_unit": "php-fpm.service",
    "webroot": "/var/www/blog",
    "repo": "/var/www/blog",
    "databases": [{"engine": "mariadb", "name": "blog", "host": "127.0.0.1", "port": 3306}],
    "protected": false
  },

  "vulnerabilities": [
    {"finding_id": 881, "cve": "CVE-2026-1234", "cvss": 9.8, "epss": 0.72,
     "kev": true, "package": "wp-plugin-foo", "current": "1.2.3", "fixed_in": "1.2.7"}
  ],

  "risk": {
    "level": "medium",                    // low | medium | high | critical
    "blast_radius": "single-service",     // single-service | multi-service | host-wide
    "estimated_downtime_s": 25,
    "requires_reboot": false,
    "reversible": true,
    "confidence": 0.86,                   // your confidence the plan is correct AND complete
    "assumptions_ro": ["Plugin-ul a fost instalat prin WP-CLI, nu manual."]
  },

  "maintenance_window": {"required": true, "suggested": "03:00-05:00 Europe/Bucharest"},

  "preflight":  [ /* Check[] */ ],
  "backup":     [ /* BackupItem[] */ ],
  "apply":      [ /* Step[] */ ],
  "health_check": [ /* Check[] */ ],
  "rollback":   [ /* Step[] */ ],
  "post_verification": [ /* Check[] */ ],

  "restore_instructions_ro": "Text pentru operator, în română, pentru restaurarea manuală.",
  "notes_ro": "Orice altceva ce operatorul trebuie să știe înainte de a aproba."
}
```

### `Step`

```jsonc
{
  "id": "ap1",
  "desc_ro": "Actualizează plugin-ul foo la 1.2.7",
  "argv": ["wp", "plugin", "update", "foo", "--version=1.2.7", "--path=/var/www/blog"],
  "cwd": "/var/www/blog",
  "run_as": "apache",                     // root | the service account. Least privilege that works
  "timeout_s": 120,
  "idempotent": false,
  "expect_exit": [0],
  "on_failure": "rollback"                // rollback | abort | continue
}
```

`on_failure: "continue"` is only ever valid for cleanup steps. If you find
yourself using it to make a fragile plan pass, the plan is wrong.

### `Check`

```jsonc
{
  "id": "hc1",
  "desc_ro": "Site-ul răspunde 200 după patch",
  "check": {"kind": "http", "url": "https://blog.example.com/", "expect_status": 200,
            "timeout_s": 10, "retries": 5, "retry_delay_s": 3},
  "blocking": true
}
```

Available `check.kind` values:

| kind | Fields | Use |
|---|---|---|
| `http` | `url`, `expect_status`, `expect_body_contains?`, `timeout_s`, `retries`, `retry_delay_s` | Web assets |
| `tcp` | `host`, `port`, `timeout_s` | Non-HTTP services |
| `systemd` | `unit`, `expect_state` (`active`) | Any unit |
| `docker` | `container`, `expect_status` (`running`\|`healthy`) | Containers |
| `pkg_version` | `name`, `equals` \| `at_least` | Confirm what is installed *before* patching |
| `file_exists` / `file_absent` | `path` | |
| `file_sha256` | `path`, `sha256` | |
| `disk_free` | `path`, `min_bytes` | Always in preflight before a backup |
| `no_open_incident` | `asset_id` | Do not patch during an active attack |
| `command` | `argv`, `expect_exit`, `expect_stdout_contains?` | Escape hatch; still allowlisted |

`blocking: true` in `preflight` aborts before anything changes.
`blocking: true` in `health_check` triggers `rollback`.

### `BackupItem`

```jsonc
{
  "id": "bk1",
  "desc_ro": "Arhivează directorul plugin-ului",
  "kind": "path",                         // path | mysql | postgres | docker_volume | rpm_state | git_ref
  "source": "/var/www/blog/wp-content/plugins/foo",
  "estimated_size_mb": 12,
  "restore_argv": ["tar", "--zstd", "-xf", "{artifact}", "-C", "/var/www/blog/wp-content/plugins"]
}
```

`{artifact}` is substituted by the runner with the real artifact path. The
runner builds the *creation* command from `kind` + `source`; you supply the
*restore* command, because that is the part that needs judgement.

See `backup-restore.md` for the correct `kind` and restore command per stack.

---

## Method for writing a good plan

**Look at the machine. Do not assume.**

```bash
# What is actually installed?
rpm -q nginx                                    # or: wp plugin get foo --path=...
systemctl cat php-fpm.service | head -40
nginx -T | grep -A20 "server_name blog"
cat /var/www/blog/wp-config.php | grep DB_NAME   # never echo credentials
ls -la /var/www/blog/wp-content/plugins/foo
```

Then:

1. **Confirm the current version matches the finding.** If the finding says
   1.2.3 and the box has 1.2.9, the finding is stale — say so and return an
   error rather than a plan.
2. **Find the real data.** A WordPress patch that backs up files and forgets the
   database is not a backup. A Node app with a SQLite file in a directory you
   did not archive is not backed up either.
3. **Find the real restart mechanism.** `systemctl restart php-fpm` and
   `systemctl reload nginx` are different things with different downtime.
   Prefer `reload` where it works.
4. **Estimate downtime honestly** from what you are doing, and put the number in
   `estimated_downtime_s`. The operator sees it before approving.
5. **Write the rollback first, then the apply.** If you cannot describe the way
   back, you do not understand the change well enough to make it.
6. **Validate**: `scripts/validate_patch_plan.py --stdin`. Fix, re-run.

---

## Worked example — RPM package (the easy case)

```jsonc
{
  "schema_version": 1,
  "target": {"asset_id": 3, "asset_name": "nginx", "stack": "rpm",
             "systemd_unit": "nginx.service", "protected": false, "databases": []},
  "vulnerabilities": [{"finding_id": 402, "cve": "CVE-2026-9999", "cvss": 7.5,
                       "epss": 0.31, "kev": false, "package": "nginx",
                       "current": "1.20.1-14.el9", "fixed_in": "1.20.1-16.el9_5"}],
  "risk": {"level": "low", "blast_radius": "single-service", "estimated_downtime_s": 2,
           "requires_reboot": false, "reversible": true, "confidence": 0.94,
           "assumptions_ro": ["Configurația nginx nu depinde de module eliminate în versiunea nouă."]},
  "maintenance_window": {"required": false, "suggested": null},

  "preflight": [
    {"id": "pf1", "desc_ro": "Versiunea instalată corespunde finding-ului",
     "check": {"kind": "pkg_version", "name": "nginx", "equals": "1.20.1-14.el9"}, "blocking": true},
    {"id": "pf2", "desc_ro": "Serviciul este sănătos înainte de patch",
     "check": {"kind": "systemd", "unit": "nginx.service", "expect_state": "active"}, "blocking": true},
    {"id": "pf3", "desc_ro": "Spațiu liber suficient pentru backup",
     "check": {"kind": "disk_free", "path": "/var/backups/sentinel", "min_bytes": 209715200}, "blocking": true},
    {"id": "pf4", "desc_ro": "Configurația nginx curentă este validă",
     "check": {"kind": "command", "argv": ["nginx", "-t"], "expect_exit": [0]}, "blocking": true},
    {"id": "pf5", "desc_ro": "Niciun incident deschis pe acest asset",
     "check": {"kind": "no_open_incident", "asset_id": 3}, "blocking": true}
  ],

  "backup": [
    {"id": "bk1", "desc_ro": "Salvează starea RPM pentru downgrade",
     "kind": "rpm_state", "source": "nginx", "estimated_size_mb": 1,
     "restore_argv": ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"]},
    {"id": "bk2", "desc_ro": "Arhivează configurația nginx",
     "kind": "path", "source": "/etc/nginx", "estimated_size_mb": 2,
     "restore_argv": ["tar", "--zstd", "-xf", "{artifact}", "-C", "/"]}
  ],

  "apply": [
    {"id": "ap1", "desc_ro": "Actualizează pachetul nginx",
     "argv": ["dnf", "-y", "update", "nginx"], "run_as": "root",
     "timeout_s": 300, "idempotent": true, "expect_exit": [0], "on_failure": "rollback"},
    {"id": "ap2", "desc_ro": "Verifică sintaxa configurației după actualizare",
     "argv": ["nginx", "-t"], "run_as": "root",
     "timeout_s": 30, "idempotent": true, "expect_exit": [0], "on_failure": "rollback"},
    {"id": "ap3", "desc_ro": "Reîncarcă nginx fără downtime",
     "argv": ["systemctl", "reload", "nginx"], "run_as": "root",
     "timeout_s": 30, "idempotent": true, "expect_exit": [0], "on_failure": "rollback"}
  ],

  "health_check": [
    {"id": "hc1", "desc_ro": "nginx este activ",
     "check": {"kind": "systemd", "unit": "nginx.service", "expect_state": "active"}, "blocking": true},
    {"id": "hc2", "desc_ro": "Dashboard-ul răspunde",
     "check": {"kind": "http", "url": "https://127.0.0.1/healthz", "expect_status": 200,
               "timeout_s": 10, "retries": 5, "retry_delay_s": 3}, "blocking": true}
  ],

  "rollback": [
    {"id": "rb1", "desc_ro": "Revino la versiunea anterioară a pachetului",
     "argv": ["dnf", "-y", "downgrade", "nginx-1.20.1-14.el9"], "run_as": "root",
     "timeout_s": 300, "idempotent": true, "expect_exit": [0], "on_failure": "abort"},
    {"id": "rb2", "desc_ro": "Repornește nginx",
     "argv": ["systemctl", "restart", "nginx"], "run_as": "root",
     "timeout_s": 60, "idempotent": true, "expect_exit": [0], "on_failure": "abort"}
  ],

  "post_verification": [
    {"id": "pv1", "desc_ro": "Versiunea instalată este cea corectată",
     "check": {"kind": "pkg_version", "name": "nginx", "at_least": "1.20.1-16.el9_5"}, "blocking": true}
  ],

  "restore_instructions_ro": "Dacă totul eșuează: dnf -y downgrade nginx-1.20.1-14.el9 && tar --zstd -xf /var/backups/sentinel/<id>/etc-nginx.tar.zst -C / && systemctl restart nginx",
  "notes_ro": "Reload, nu restart — conexiunile existente nu sunt întrerupte. Downtime real așteptat: sub 1 secundă."
}
```

Note what makes it a good plan: preflight confirms the version *before*
changing anything, `nginx -t` runs both before and after, the rollback is a
real downgrade to a specific version rather than a vague "restore", and the
post-verification re-checks the thing the scanner will check tonight.

---

## Common mistakes that get plans rejected

| Mistake | Fix |
|---|---|
| `"argv": ["bash", "-c", "..."]` | Split into steps. `bash` is not allowlisted for a reason |
| Backup of files but not the database | Add a `mysql`/`postgres` backup item. Check `target.databases` |
| `rollback` that says "restore from backup" without an argv | Write the actual restore command |
| `systemctl restart` where `reload` works | Unnecessary downtime |
| No `pkg_version` preflight | You are patching a version you did not confirm is installed |
| `expect_exit: [0, 1]` to make a flaky step pass | Understand why it returns 1 |
| Missing `timeout_s` | Mandatory. A hung step blocks the queue |
| `git pull` in `apply` | Non-deterministic. Use an explicit `git checkout <sha-or-tag>` |
| `npm install` without a lockfile step | Use `npm ci`, which respects the lockfile |
| Guessing the webroot | Read `nginx -T`. It is right there |
