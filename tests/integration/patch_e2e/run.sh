#!/usr/bin/env bash
# Rulează proba de capăt-la-capăt a fluxului de patch într-un container cu systemd.
#
#   tests/integration/patch_e2e/run.sh [CALEA_CLONEI]     (implicit: depozitul curent)
#   E2E_DISTRO=debian tests/integration/patch_e2e/run.sh   (Ubuntu + apt, ca gazda n8n)
#
# De ce există. Fiecare verdict al căii de pachete a fost odată corect în teste și
# greșit pe un sistem real (`--pipe` a întors 0 cu pachetul neinstalat; `--collect` a
# șters verdictul). Un plan care ajunge `applied` într-un test cu un `subprocess`
# înlocuit nu dovedește nimic despre pachet. Aici executorul rulează sub propria
# unitate systemd, `dnf` instalează un pachet adevărat printr-o unitate tranzitorie
# a lui PID 1, iar testul întreabă `rpm` — nu executorul — dacă pachetul s-a schimbat.
#
# Ce se ATINGE: numai un container nou, șters la sfârșit. NU se rulează pe o gazdă:
# `setup.sh` și testul refuză dacă nu sunt într-un container cu systemd ca PID 1.
# Cere docker. Pe Git Bash pe Windows, MSYS_NO_PATHCONV=1 e pus aici, altfel
# `/sys/fs/cgroup` e rescris într-o cale Windows.
set -euo pipefail
export MSYS_NO_PATHCONV=1

REPO="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
NAME="sentinel-e2e-$$"
DISTRO="${E2E_DISTRO:-rhel}"
if [[ "$DISTRO" == "debian" ]]; then
    # Familia `debian` are propria imagine (Ubuntu + systemd + needrestart), propriul setup
    # și propriul fișier de probe: pe gazda n8n `apt-get` e singurul manager de pachete.
    IMAGE="${E2E_IMAGE:-sentinel-e2e-ubuntu-systemd}"
    SETUP=setup_debian.sh
    TESTS=tests/integration/test_patch_apply_end_to_end_apt.py
    if [[ -z "${E2E_IMAGE:-}" ]] && ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        # docker.exe on Windows does not read MSYS paths (`/c/dev/...`), and MSYS_NO_PATHCONV
        # is set above, so the build context is converted by hand where cygpath exists.
        HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        CTX="$HERE"
        if command -v cygpath >/dev/null 2>&1; then CTX="$(cygpath -w "$HERE")"; fi
        docker build -t "$IMAGE" -f "$CTX/Dockerfile.debian" "$CTX"
    fi
else
    IMAGE="${E2E_IMAGE:-almalinux/9-init}"
    SETUP=setup.sh
    TESTS=tests/integration/test_patch_apply_end_to_end.py
fi

cleanup() {
    [[ -n "${KEEP:-}" ]] || docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$NAME" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$IMAGE" >/dev/null

# systemd trebuie să fie pe picioare; fără el nu există nimic de probat.
for _ in $(seq 1 60); do
    state="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
    [[ "$state" == "running" || "$state" == "degraded" ]] && break
    sleep 1
done
[[ "$state" == "running" || "$state" == "degraded" ]] || { echo "systemd nu a pornit ($state)" >&2; exit 1; }

# O COPIE a depozitului, nu un mount: ce rulează e ce e copiat, iar containerul nu
# poate scrie înapoi în depozit.
docker exec "$NAME" mkdir -p /opt/e2e/repo
# Doar ce folosește proba: un `docker cp` al întregului depozit ar duce și
# `aggregator/node_modules`.
tar --exclude=__pycache__ --exclude=node_modules -C "$REPO" -cf -     executor sentinel tests scripts deploy docs pyproject.toml     | docker exec -i "$NAME" tar -C /opt/e2e/repo -xf -

docker exec "$NAME" bash "/opt/e2e/repo/tests/integration/patch_e2e/$SETUP" /opt/e2e/repo
docker exec -e SENTINEL_E2E_CONTAINER=1 -e PYTHONDONTWRITEBYTECODE=1 -e "E2E_FAMILY=$DISTRO" \
    -w /opt/e2e/repo "$NAME" \
    /opt/e2e/venv/bin/python -B -m pytest "$TESTS" \
    -p no:cacheprovider -rsx "${@:2}"
