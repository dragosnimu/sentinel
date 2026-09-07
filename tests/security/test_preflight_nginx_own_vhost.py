"""Preflight told an upgrade to stop Sentinel in order to deploy Sentinel.

Measured 7 Sep 2026 on the second production host (Ubuntu 24.04.4,
`--nginx-mode dedicated --web-port 8443`, installed 4 Sep): a repeat
`scripts/deploy.ps1 ... -DryRun` produced

    [x] port 8443 is in use by "nginx",pid=812,fd=8. Sentinel needs it.
        Pick another with --web-port, or stop that service.

The process on 8443 was `nginx.service` serving Sentinel's OWN vhost —
`/etc/nginx/conf.d/sentinel.conf`, written by `deploy/install.sh`'s
`step_nginx` and reloaded by every install. In dedicated mode the public port
is always held by nginx, not by a `sentinel-*` unit (the dashboard itself
listens on 127.0.0.1:8787, proxied) — so the existing `unit == sentinel-*`
exemption a few lines below, which fixed the exact same problem for 8787,
never applied here.

The fix is narrower than "nginx holds the port, so it must be fine": it has
to fail again the moment nginx holds the port for SOMEONE ELSE's site,
because that IS a real conflict Sentinel's installer would otherwise silently
try to rewrite. So the check reads the vhost FILE, not just the unit name.

These tests run the `for port in "${SENTINEL_PORTS[@]}"; do ... done` loop
exactly as shipped in `deploy/preflight.sh`, with `port_free`, `port_owner`
and `port_owner_unit` stubbed to fixed answers — the plumbing that turns a PID
into a unit name is already covered, separately, in
tests/unit/test_preflight_port_owner.py. What is under test here is the
DECISION the loop takes once it already knows who holds the port, read from
`FAIL_COUNT` / `WARN_COUNT`, not from a string in the file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PREFLIGHT = (REPO / "deploy" / "preflight.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")

_NO_BASH = ("bash lipsește din PATH, deci verificarea nu a fost rulată. "
            "Asta e „neverificat”, nu „în regulă”.")

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


def _port_loop_block() -> str:
    """Bucla `for port in "${SENTINEL_PORTS[@]}"; do ... done`, octeții livrați.

    Extragerea e verificată imediat, ca la `_ufw_block()` din
    test_preflight_ufw.py: un extractor care ratează jumătate din buclă ar
    produce un shell care nu rulează deloc, iar unul care ia o linie goală ar
    face fiecare test de mai jos să treacă degeaba.
    """
    lines = PREFLIGHT.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.strip() == 'for port in "${SENTINEL_PORTS[@]}"; do')
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "done")
    block = "\n".join(lines[start:end + 1])
    assert "SENTINEL_VHOST_CONF" in block, "extragerea a ratat ramura nouă"
    assert "nginx.service" in block
    assert "sentinel-*" in block, "extragerea a ratat ramura veche, de la 8787"
    return block + "\n"


def _p(path: Path) -> str:
    return str(path).replace("\\", "/")


def _run(tmp_path: Path, *, unit: str, vhost_content: str | None,
         public_port: str = "8443", sentinel_ports: str = '"8443"',
         vhost_exists: bool = True) -> tuple[int, int, str]:
    """(FAIL_COUNT, WARN_COUNT, tot ce s-a tipărit).

    `port_free` e forțat mereu fals: fiecare port din `SENTINEL_PORTS` intră
    pe ramura „ocupat", exact ramura pe care o testăm. `port_owner_unit` e
    fixat la `unit`, indiferent de portul cerut — testele care au nevoie de
    unități diferite pentru porturi diferite rulează cu un singur port în
    `SENTINEL_PORTS`, ca să nu amestece contoare de la ramuri neatinse aici.
    """
    vhost = tmp_path / "sentinel.conf"
    if vhost_exists:
        vhost.write_text(vhost_content or "", encoding="utf-8", newline="\n")

    script = tmp_path / "harness.sh"
    script.write_text(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'SENTINEL_PUBLIC_PORT="{public_port}"\n'
        f'SENTINEL_PORTS=({sentinel_ports})\n'
        f'SENTINEL_VHOST_CONF="{_p(vhost)}"\n'
        'port_free() { return 1; }\n'
        'port_owner() { printf "someproc\\n"; }\n'
        f'port_owner_unit() {{ printf "%s\\n" "{unit}"; }}\n'
        + _port_loop_block()
        + 'printf "COUNTS %d %d\\n" "$FAIL_COUNT" "$WARN_COUNT"\n',
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1"}
    proc = subprocess.run([BASH, _p(script)], cwd=REPO / "deploy",
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    counts = next(l for l in proc.stdout.splitlines() if l.startswith("COUNTS"))
    _, fails, warns = counts.split()
    return int(fails), int(warns), proc.stdout + proc.stderr


def test_nginx_holding_the_public_port_for_sentinels_own_vhost_passes(tmp_path):
    """Cazul măsurat pe gazdă, reparat: nginx ține portul public, vhost-ul
    scris de installer ascultă chiar acolo — asta e un upgrade normal, nu un
    conflict, și nu are voie să blocheze deploy-ul."""
    fails, warns, out = _run(
        tmp_path, unit="nginx.service",
        vhost_content="listen 8443 ssl http2;\nlisten [::]:8443 ssl http2;\n")
    assert (fails, warns) == (0, 0), out
    assert "the running Sentinel" in out
    assert "rewrites it and reloads" in out


def test_nginx_holding_the_port_with_no_sentinel_vhost_still_fails(tmp_path):
    """nginx ține portul, dar fișierul vhost al lui Sentinel nu există —
    e site-ul altcuiva, iar un `ok` aici l-ar face pe installer să încerce să
    rescrie o configurație care nu e a lui."""
    fails, _, out = _run(tmp_path, unit="nginx.service", vhost_content=None,
                          vhost_exists=False)
    assert fails > 0, out
    assert "Sentinel needs it" in out


def test_vhost_present_but_listening_on_a_different_port_still_fails(tmp_path):
    """Fișierul există dar nu ascultă pe portul cerut — probabil un vhost
    vechi, dintr-o instalare cu alt --web-port. Nu e dovada că ACEST port e
    al lui Sentinel."""
    fails, _, out = _run(tmp_path, unit="nginx.service",
                          vhost_content="listen 9443 ssl http2;\n")
    assert fails > 0, out


def test_a_commented_out_listen_line_does_not_count(tmp_path):
    """`# listen 8443 ssl http2;` nu e o directivă activă — nginx nu a
    parsat-o. Ancora `^[[:space:]]*` din fața lui `listen` e ce respinge
    comentariul: `grep -E` caută nepoziționat implicit, deci fără ancoră
    „# listen 8443” tot ar conține subșirul „listen 8443” și ar potrivi.
    (A existat aici o etapă `grep -v '^[[:space:]]*#'` menită să scoată
    comentariile înainte — era moartă, fiindcă regexul ancorat de mai jos
    refuza deja să potrivească altundeva decât la începutul liniei, deci nu
    vedea un comentariu diferit după ea; a fost eliminată fiindcă transforma
    un SIGPIPE într-un eșec de preflight raportat, de îndată ce vhost-ul are
    destule linii ca să depășească memoria tampon a unei conducte)."""
    fails, _, out = _run(tmp_path, unit="nginx.service",
                          vhost_content="    # listen 8443 ssl http2;\n")
    assert fails > 0, out


@pytest.mark.parametrize("line", [
    # sufix: 8443 e prefixul lui 84430
    "listen 84430 ssl http2;",
    # prefix: 8443 e sufixul lui 18443 — un `listen.*8443` ar trece aici,
    # și niciun alt test din fișier nu-l prindea
    "listen 18443 ssl http2;",
    "listen 127.0.0.1:18443;",
])
def test_a_neighbouring_port_number_in_the_vhost_does_not_count(tmp_path, line):
    """`listen 84430` sau `listen 18443` nu sunt reguli pentru 8443. O
    potrivire de prefix SAU de sufix ar trece exact pe vhost-ul greșit —
    aceeași greșeală pe care repository-ul a mai făcut-o o dată, la ufw."""
    fails, _, out = _run(tmp_path, unit="nginx.service",
                          vhost_content=line + "\n")
    assert fails > 0, out


def test_port_8787_held_by_nginx_still_fails(tmp_path):
    """Ramura e doar pentru portul PUBLIC. 8787 e portul intern al panoului —
    dacă nginx l-ar ține din vreun motiv (o gazdă configurată greșit, un alt
    vhost), nu e „Sentinel-ul care rulează", și nu are voie să treacă tăcut."""
    fails, _, out = _run(
        tmp_path, unit="nginx.service", public_port="8443",
        sentinel_ports='"8787"',
        vhost_content="listen 8787 ssl http2;\n")
    assert fails > 0, out


def test_the_old_sentinel_unit_exemption_for_8787_still_works(tmp_path):
    """Ramura nouă nu are voie să înlocuiască sau să umbrească ramura veche:
    portul 8787 ținut de propriul serviciu sentinel-web trebuie să rămână un
    upgrade normal, exact ca înainte de schimbarea asta."""
    fails, warns, out = _run(
        tmp_path, unit="sentinel-web.service", public_port="8443",
        sentinel_ports='"8787"', vhost_content=None, vhost_exists=False)
    assert (fails, warns) == (0, 0), out
    assert "the running Sentinel" in out


# ---------------------------------------------------------------------------
# Verificarea unității, nu doar a fișierului vhost.
#
# Toate testele de mai sus care blochează folosesc un vhost invalid sau lipsă.
# Niciunul nu dovedește că verificarea `"$unit" == "nginx.service"` face ceva
# — un vhost VALID cu o unitate care nu e nginx.service ar trece la fel de
# bine dintr-o ramură care ar verifica DOAR fișierul. Testele de aici fixează
# un vhost valid, corect pe portul cerut, și variază DOAR unitatea.
# ---------------------------------------------------------------------------
def test_an_empty_unit_still_fails_even_with_a_valid_vhost_present(tmp_path):
    """Un nginx în container (docker/podman) întoarce o unitate GOALĂ de la
    `port_owner_unit` — PID-ul trăiește în cgroup-ul containerului, nu într-o
    unitate systemd cunoscută. Ramura nu are voie să citească „nu pot numi
    unitatea” drept „trebuie să fie nginx-ul lui Sentinel”: un proxy străin,
    tot într-un container, pe același port, ar trece direct dacă ar conta
    doar fișierul vhost."""
    fails, _, out = _run(tmp_path, unit="",
                          vhost_content="listen 8443 ssl http2;\n")
    assert fails > 0, out


def test_a_foreign_service_holding_the_port_still_fails_even_with_the_vhost_present(tmp_path):
    """Verificarea se face pe UNITATE, nu doar pe fișier: un alt reverse
    proxy (traefik, caddy, haproxy) poate rula pe gazdă cu fișierul vhost al
    lui Sentinel încă prezent, rămas de la o instalare anterioară, ștearsă
    între timp. Trecerea doar pentru că fișierul se potrivește l-ar face pe
    installer să încerce să rescrie o configurație pe care nginx nici nu o
    citește."""
    fails, _, out = _run(tmp_path, unit="traefik.service",
                          vhost_content="listen 8443 ssl http2;\n")
    assert fails > 0, out


def test_unit_name_with_trailing_whitespace_still_fails(tmp_path):
    """`port_owner_unit` trebuie tratat ca întorcând un nume exact — un spațiu
    rămas dintr-o particularitate de shell nu are voie să treacă printr-o
    comparație mai permisivă decât `==`."""
    fails, _, out = _run(tmp_path, unit="nginx.service ",
                          vhost_content="listen 8443 ssl http2;\n")
    assert fails > 0, out


def test_unit_name_with_different_case_still_fails(tmp_path):
    """Comparația e exactă ca șir, nu insensibilă la majuscule — „Nginx.service”
    nu e un nume real de unitate systemd, iar tratarea lui ca o potrivire ar
    însemna să citești starea configurației mai relaxat decât o citește
    systemd însuși."""
    fails, _, out = _run(tmp_path, unit="Nginx.service",
                          vhost_content="listen 8443 ssl http2;\n")
    assert fails > 0, out
