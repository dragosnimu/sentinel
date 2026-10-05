#!/usr/bin/env bash
# Pune executorul REAL într-un container Debian/Ubuntu cu systemd ca PID 1, în aceeași
# configurație de fișiere ca pe gazdă. Geamănul lui setup.sh pentru familia `debian`
# (gazda n8n e Ubuntu: acolo `apt-get` e singurul manager de pachete, deci o cale de
# pachete care nu merge pe apt înseamnă o gazdă pe care nu se poate aplica nimic).
# Rulează DOAR în containerul de probă (vezi run.sh) — refuză orice altceva.
#
# Ce NU e real aici, spus ca să nu se creadă altceva: `nft` e un stub; imaginea e
# Ubuntu 24.04 (systemd 255), nu 26.04 de pe gazdă; și nu e testat un pachet cu
# întrebări debconf sau cu `needrestart` activ în mod interactiv. Tot restul — unitatea
# `sentinel-executor.service` cu sandbox-ul ei, executorul, utilizatorul `sentinel`,
# socketul, directorul de audit 0700 root, `apt-get`/`dpkg` — e cel de pe producție.
set -euo pipefail

if [[ ! -e /.dockerenv && ! -e /run/.containerenv ]]; then
    echo "REFUZ: nu e un container. Acest script se rulează numai în containerul de probă." >&2
    exit 64
fi
if [[ "$(ps -p 1 -o comm= | tr -d ' ')" != "systemd" ]]; then
    echo "REFUZ: PID 1 nu e systemd; fără el calea tranzitorie nu se poate încerca." >&2
    exit 65
fi

STAGE="${1:?usage: setup_debian.sh /path/to/repo-copy}"
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-venv python3-pip tar zstd util-linux \
    procps >/dev/null
id sentinel >/dev/null 2>&1 || useradd -r -m -s /bin/bash sentinel

# --- directoarele și drepturile, ca în deploy/tmpfiles/sentinel.conf -----------
install -d -m 0755 -o root -g root /opt/sentinel /opt/sentinel/libexec
install -d -m 0750 -o root -g sentinel /etc/sentinel
install -d -m 2750 -o sentinel -g sentinel /var/lib/sentinel
install -d -m 0700 -o root -g root /var/lib/sentinel-executor /var/backups/sentinel

for f in sentinel_executor.py policy.py commands.py transient_unit.py; do
    install -m 0644 -o root -g root "$STAGE/executor/$f" "/opt/sentinel/libexec/$f"
done
python3 -m venv /opt/sentinel/venv

printf '#!/bin/sh\nexit 0\n' > /usr/sbin/nft
chmod 0755 /usr/sbin/nft

install -m 0640 -o root -g sentinel /dev/null /etc/sentinel/secrets.env

install -m 0644 -o root -g root "$STAGE/deploy/systemd/sentinel-executor.service" \
    /etc/systemd/system/sentinel-executor.service

if [[ ! -x /opt/e2e/venv/bin/python ]]; then
    install -d -m 0755 /opt/e2e
    python3 -m venv /opt/e2e/venv
    /opt/e2e/venv/bin/pip install -q asyncpg pydantic pyyaml pytest 2>&1 | tail -2
fi

systemctl daemon-reload
echo "setup ok"
