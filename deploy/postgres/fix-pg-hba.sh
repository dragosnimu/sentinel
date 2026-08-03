#!/usr/bin/env bash
# One-off remediation for a pg_hba.conf where Sentinel's scram rules were
# appended AFTER the distribution's `host all all 127.0.0.1/32 ident` line and
# so never matched. Drops any existing sentinel rule lines and re-inserts them
# ahead of the first active rule. Idempotent. install.sh does this correctly for
# fresh installs; this repairs a host that took the old appended path.
set -euo pipefail

hba=/var/lib/pgsql/data/pg_hba.conf
[[ -f "$hba" ]] || { echo "no $hba"; exit 1; }

cp -a "$hba" "${hba}.bak-sentinel"

awk '
  /[[:space:]]sentinel[[:space:]]/ { next }        # drop existing sentinel rule lines
  !ins && /^[[:space:]]*(local|host|hostssl|hostnossl)[[:space:]]/ {
    print "# --- Sentinel (scram, loopback only) — inserted before defaults ---"
    print "local   sentinel   sentinel                          scram-sha-256"
    print "host    sentinel   sentinel   127.0.0.1/32           scram-sha-256"
    print "host    sentinel   sentinel   ::1/128                scram-sha-256"
    print "host    sentinel   all        0.0.0.0/0              reject"
    print "host    sentinel   all        ::/0                   reject"
    ins = 1
  }
  { print }
' "$hba" > "${hba}.new"

install -m 0600 -o postgres -g postgres "${hba}.new" "$hba"
rm -f "${hba}.new"
systemctl reload postgresql
echo "pg_hba.conf repaired and postgresql reloaded"
