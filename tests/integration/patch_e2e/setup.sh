#!/usr/bin/env bash
# Pune executorul REAL într-un container cu systemd ca PID 1, în aceeași
# configurație de fișiere ca pe gazdă. Rulează DOAR în containerul de probă
# (vezi run.sh) — refuză orice altceva.
#
# Ce NU e real aici, spus ca să nu se creadă altceva: `nft` e un stub (executorul îl
# cheamă la pornire ca să-și asigure tabela, iar un container n-are regulile
# gazdei). Tot restul — systemd 252, dnf, rpm, unitatea `sentinel-executor.service`
# cu sandbox-ul ei, executorul, utilizatorul `sentinel`, socketul, directorul de audit
# 0700 root — e cel de pe producție.
set -euo pipefail

# Gardă: nu se instalează nimic dacă nu suntem într-un container. Un script de
# instalare care a rulat pe gazda greșită e exact ce interzice CLAUDE.md.
if [[ ! -e /.dockerenv && ! -e /run/.containerenv ]]; then
    echo "REFUZ: nu e un container. Acest script se rulează numai în containerul de probă." >&2
    exit 64
fi
if [[ "$(ps -p 1 -o comm= | tr -d ' ')" != "systemd" ]]; then
    echo "REFUZ: PID 1 nu e systemd; fără el calea tranzitorie nu se poate încerca." >&2
    exit 65
fi

STAGE="${1:?usage: setup.sh /path/to/repo-copy}"

# cronie: a service the probe can start and stop (crond.service) without touching anything real.
dnf -y -q install python3.12 zstd tar util-linux findutils procps-ng cronie >/dev/null
id sentinel >/dev/null 2>&1 || useradd -r -m -s /bin/bash sentinel

# --- directoarele și drepturile, ca în deploy/tmpfiles/sentinel.conf -----------
install -d -m 0755 -o root -g root /opt/sentinel /opt/sentinel/libexec
install -d -m 0750 -o root -g sentinel /etc/sentinel
install -d -m 2750 -o sentinel -g sentinel /var/lib/sentinel
install -d -m 0700 -o root -g root /var/lib/sentinel-executor /var/backups/sentinel

# --- executorul, root:root 0644, ca la pasul 24 al instalatorului -------------
for f in sentinel_executor.py policy.py commands.py transient_unit.py; do
    install -m 0644 -o root -g root "$STAGE/executor/$f" "/opt/sentinel/libexec/$f"
done
python3.12 -m venv /opt/sentinel/venv

# --- stubul nft ----------------------------------------------------------------
printf '#!/bin/sh\nexit 0\n' > /usr/sbin/nft
chmod 0755 /usr/sbin/nft

# --- vechiul loc al cheii: secrets.env, 0640 root:sentinel ---------------------
# Rămâne aici ca să se poată DOVEDI că o cheie citibilă de `sentinel` nu mai
# aprobă nimic. Valoarea e derivată, nu un secret.
old_key="$(printf 'old-key-readable-by-sentinel' | sha256sum | cut -d' ' -f1)"
install -m 0640 -o root -g sentinel /dev/null /etc/sentinel/secrets.env
printf 'SENTINEL_EXECUTOR_APPROVAL_KEY=%s\n' "$old_key" > /etc/sentinel/secrets.env

# --- unitatea REALĂ, nemodificată ----------------------------------------------
install -m 0644 -o root -g root "$STAGE/deploy/systemd/sentinel-executor.service" \
    /etc/systemd/system/sentinel-executor.service

# --- mediul pentru partea neprivilegiată (botul / runner-ul) -------------------
if [[ ! -x /opt/e2e/venv/bin/python ]]; then
    install -d -m 0755 /opt/e2e
    python3.12 -m venv /opt/e2e/venv
    /opt/e2e/venv/bin/pip install -q asyncpg pydantic pyyaml pytest 2>&1 | tail -2
fi

systemctl daemon-reload
echo "setup ok"
