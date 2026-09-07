"""Preflight-ul nu avea voie să treacă peste un ufw activ fără să spună nimic.

Măsurat pe un Ubuntu 24.04.4 curat, înainte de reparație: `ufw status` →
`active`, cu 22/tcp permis și nimic altceva. Secțiunea „Firewall" din
`deploy/preflight.sh` a tipărit

    [+] firewalld inactive (as expected)
    [+] nftables available

și a ieșit cu 0. Cuvântul „ufw" nu apărea nicăieri în fișier.

Ce s-ar fi întâmplat mai departe: instalarea își pune allowlist-ul în
`table inet sentinel`, fiecare pas raportează succes, iar panoul nu răspunde.
Un `accept` din lanțul Sentinel NU anulează un `drop` din lanțul ufw — netfilter
evaluează toate lanțurile înregistrate pe hook, și un singur drop încheie
pachetul. Nimic din jurnalele gazdei nu spune de ce.

Testele de mai jos rulează BLOCUL LIVRAT din preflight.sh, cu un `ufw` momeală
care întoarce ieșiri reale de `ufw status verbose`, și se uită la contoarele
`FAIL_COUNT` / `WARN_COUNT` — adică la decizia luată, nu la prezența unui nume
de variabilă în fișier.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PREFLIGHT = (REPO / "deploy" / "preflight.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")

_NO_BASH = ("bash lipsește din PATH, deci verificarea ufw NU a fost rulată. "
            "Asta e „neverificat”, nu „în regulă”.")

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


def _ufw_block() -> str:
    """Blocul `if have ufw` exact așa cum se livrează.

    Extras după `fi` de la coloana 0, fiindcă blocul are `if`-uri interioare
    indentate. Extragerea e verificată imediat: un extractor care ia jumătate de
    bloc ar produce un shell care nu rulează, iar unul care ia o linie goală ar
    face fiecare test de mai jos să treacă degeaba.
    """
    lines = PREFLIGHT.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "if have ufw; then")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "fi")
    block = "\n".join(lines[start:end + 1])
    assert "ufw status verbose" in block, "extragerea a ratat corpul blocului"
    assert "ALLOW" in block
    assert block.count("if ") >= 2
    return block + "\n"


UFW_ACTIVE_ONLY_SSH = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

UFW_ACTIVE_PORT_OPEN = UFW_ACTIVE_ONLY_SSH + """8443/tcp                   ALLOW IN    Anywhere
8443/tcp (v6)              ALLOW IN    Anywhere (v6)
"""

UFW_ACTIVE_PORT_SCOPED = UFW_ACTIVE_ONLY_SSH + """8443                       ALLOW IN    10.30.1.132
"""

UFW_ACTIVE_NEIGHBOURING_PORT = UFW_ACTIVE_ONLY_SSH + """84430/tcp                  ALLOW IN    Anywhere
"""

UFW_DEFAULT_ALLOW_IN = """Status: active
Logging: on (low)
Default: allow (incoming), allow (outgoing), disabled (routed)
New profiles: skip
"""

UFW_INACTIVE = "Status: inactive\n"


def _run(tmp_path: Path, *, status: str | None, port: str = "8443",
         mode: str = "dedicated", allow_ufw: str = "0",
         installed: bool = True) -> tuple[int, int, str]:
    """(FAIL_COUNT, WARN_COUNT, tot ce s-a tipărit)."""
    binpath = tmp_path / "bin"
    binpath.mkdir(exist_ok=True)
    if installed:
        if status is None:
            # `ufw status` fără root: nu tipărește nimic și iese cu eroare.
            body = "exit 1\n"
        else:
            fixture = tmp_path / "ufw-status.txt"
            fixture.write_text(status, encoding="utf-8", newline="\n")
            body = f'cat "{str(fixture).replace(chr(92), "/")}"\n'
        stub = binpath / "ufw"
        stub.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8",
                        newline="\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    script = tmp_path / "harness.sh"
    script.write_text(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'SENTINEL_PUBLIC_PORT="{port}"\n'
        f'NGINX_MODE="{mode}"\n'
        + _ufw_block()
        + 'printf "COUNTS %d %d\\n" "$FAIL_COUNT" "$WARN_COUNT"\n',
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1", "ALLOW_UFW": allow_ufw,
           "PATH": str(binpath).replace("\\", "/") + os.pathsep + os.environ.get("PATH", "")}
    if not installed:
        # `have ufw` trebuie să fie fals: PATH-ul momeală e gol, dar PATH-ul
        # moștenit ar putea avea un ufw real pe o mașină Linux.
        env["PATH"] = str(binpath).replace("\\", "/")
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=REPO / "deploy", capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    counts = next(l for l in proc.stdout.splitlines() if l.startswith("COUNTS"))
    _, fails, warns = counts.split()
    return int(fails), int(warns), proc.stdout + proc.stderr


def test_an_active_ufw_that_does_not_allow_the_port_stops_the_deploy(tmp_path):
    """Eșecul pe care îl previne, măsurat: instalarea se termină raportând
    succes complet și panoul nu răspunde de pe nicio adresă. Operatorul are un
    deploy „reușit" și un serviciu invizibil, fără nimic în jurnale."""
    fails, warns, out = _run(tmp_path, status=UFW_ACTIVE_ONLY_SSH)
    assert fails > 0, "preflight-ul a trecut peste un ufw care taie portul panoului"
    # Mesajul trebuie să numească portul concret și comanda de deschidere:
    # un „firewall-ul blochează ceva" trimite operatorul să caute singur.
    assert "8443/tcp" in out
    assert "ufw allow 8443/tcp" in out


def test_the_message_names_the_scoped_command_too(tmp_path):
    """Un operator care nu vrea portul deschis către internet trebuie să vadă
    varianta îngustă aici, altfel singura ieșire pare să fie deschiderea largă."""
    _, _, out = _run(tmp_path, status=UFW_ACTIVE_ONLY_SSH)
    assert "ufw allow from <your-ip> to any port 8443 proto tcp" in out


def test_an_open_port_passes(tmp_path):
    """Cealaltă jumătate. Un test care ar pica pe ORICE ufw activ ar bloca
    fiecare instalare Ubuntu legitimă, iar reparația s-ar da înapoi."""
    fails, warns, out = _run(tmp_path, status=UFW_ACTIVE_PORT_OPEN)
    assert (fails, warns) == (0, 0), out
    assert "port 8443 is allowed" in out


def test_a_rule_scoped_to_one_address_also_passes(tmp_path):
    """`ufw allow from 10.30.1.132 to any port 8443` e răspunsul corect pentru
    un panou care nu trebuie expus. Dacă verificarea l-ar respinge, ar cere
    operatorului să deschidă portul mai larg decât vrea."""
    fails, _, out = _run(tmp_path, status=UFW_ACTIVE_PORT_SCOPED)
    assert fails == 0, out


def test_a_neighbouring_port_number_does_not_count_as_the_port(tmp_path):
    """`84430/tcp ALLOW` nu e o regulă pentru 8443. O potrivire de prefix ar
    face verificarea să treacă exact pe gazdele unde n-ar trebui — și e forma
    de bug pe care repository-ul ăsta a mai avut-o o dată, la versiunile de
    unelte externe."""
    fails, _, out = _run(tmp_path, status=UFW_ACTIVE_NEIGHBOURING_PORT)
    assert fails > 0, out


def test_an_inactive_ufw_is_not_a_problem(tmp_path):
    fails, warns, out = _run(tmp_path, status=UFW_INACTIVE)
    assert (fails, warns) == (0, 0), out
    assert "inactive" in out


def test_a_default_allow_incoming_policy_is_not_a_problem(tmp_path):
    """`Default: allow (incoming)` nu blochează nimic. Un fail acolo ar fi un
    refuz pentru o gazdă pe care instalarea ar fi mers."""
    fails, warns, out = _run(tmp_path, status=UFW_DEFAULT_ALLOW_IN)
    assert (fails, warns) == (0, 0), out


def test_a_status_that_cannot_be_read_is_unknown_and_not_fine(tmp_path):
    """„Nu am putut citi" și „e în regulă" sunt stări diferite. `ufw status`
    cere root, iar preflight-ul se rulează și de mână. Un `ok` acolo e chiar
    felul în care o unealtă de monitorizare minte."""
    fails, warns, out = _run(tmp_path, status=None)
    assert warns > 0, "un ufw necitit a fost raportat ca fiind în regulă"
    assert fails == 0, "necunoscutul nu are voie să oprească deploy-ul ca o certitudine"
    assert "UNKNOWN" in out


def test_a_host_without_ufw_says_nothing_about_it(tmp_path):
    """AlmaLinux nu are ufw. O linie despre el acolo e zgomot într-un ecran în
    care fiecare linie trebuie citită."""
    fails, warns, out = _run(tmp_path, status=None, installed=False)
    assert (fails, warns) == (0, 0), out
    assert "ufw" not in out


def test_shared_mode_does_not_demand_a_port_sentinel_never_opens(tmp_path):
    """În modul shared Sentinel răspunde pe 80/443 ale nginx-ului existent, pe
    care ufw le permite deja sau site-urile operatorului ar fi căzute. Un fail
    acolo ar bloca un deploy pentru un port pe care nimeni nu-l folosește."""
    fails, warns, out = _run(tmp_path, status=UFW_ACTIVE_ONLY_SSH, mode="shared")
    assert (fails, warns) == (0, 0), out


def test_allow_ufw_downgrades_the_refusal_to_a_warning_that_still_names_the_command(tmp_path):
    """Portița, ca la `--allow-firewalld`. Trebuie să rămână un avertisment care
    spune ce va fi nefuncțional, nu o linie verde."""
    fails, warns, out = _run(tmp_path, status=UFW_ACTIVE_ONLY_SSH, allow_ufw="1")
    assert fails == 0
    assert warns > 0
    assert "ufw allow 8443/tcp" in out


def test_the_port_checked_is_the_one_the_deploy_was_asked_for(tmp_path):
    """`--web-port 9443` cu o regulă pentru 8443 nu e o gazdă pregătită. O
    verificare pe un port fix ar trece exact pe instalarea neobișnuită."""
    fails, _, out = _run(tmp_path, status=UFW_ACTIVE_PORT_OPEN, port="9443")
    assert fails > 0, out
    assert "9443/tcp" in out


def test_the_installer_can_pass_the_escape_hatch_through(tmp_path):
    """Steagul trebuie să existe și în `install.sh`, altfel mesajul trimite
    operatorul către o opțiune inexistentă — iar „unknown argument" e felul în
    care instalarea se oprește pentru un motiv care n-are legătură cu firewall-ul.
    """
    install = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "--allow-ufw)" in install
    assert "export ALLOW_UFW=1" in install


# ---------------------------------------------------------------------------
# --allow-ufw ca ARGUMENT de linie de comandă, nu doar ca variabilă de mediu
# deja setată.
#
# Testele de mai sus, cu `allow_ufw="1"` trecut prin ALLOW_UFW în mediu,
# acoperă drumul pe care îl folosește install.sh (exportă variabila înainte
# să cheme acest script, în același proces shell). Măsurat pe gazda a doua
# (7 sep 2026): scripts/deploy.sh și scripts/deploy.ps1 rulează preflight-ul
# de sine stătător, pe --dry-run, printr-un `sudo` NOU — care nu moștenește
# o variabilă de shell, doar argumentele. Un preflight.sh care citește doar
# ALLOW_UFW din mediu ar accepta steagul pe hârtie (--help l-ar lista) și l-ar
# ignora tăcut pe singurul drum prin care un operator îl poate folosi de fapt.
# ---------------------------------------------------------------------------
def _arg_parse_block() -> str:
    """Bucla `while [[ $# -gt 0 ]]; do ... done` de parsare a argumentelor,
    octeții livrați. Extrasă separat de `_ufw_block()`, ca să poată fi rulată
    ÎNAINTE de el, cu argumente reale în `$@` — exact ordinea în care rulează
    scriptul livrat."""
    lines = PREFLIGHT.splitlines()
    start = next(i for i, l in enumerate(lines)
                 if l.strip() == "while [[ $# -gt 0 ]]; do")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "done")
    block = "\n".join(lines[start:end + 1])
    assert "--allow-ufw" in block, "extragerea a ratat parsarea --allow-ufw"
    assert "--allow-firewalld" in block
    return block + "\n"


def _run_cli(tmp_path: Path, *, status: str | None, cli_args: str,
            port: str = "8443", mode: str = "dedicated") -> tuple[int, int, str]:
    """La fel ca `_run`, dar consimțământul vine dintr-un argument de linie de
    comandă parsat de bucla livrată (`$@`), nu dintr-o variabilă de mediu
    pre-setată de test."""
    binpath = tmp_path / "bin"
    binpath.mkdir(exist_ok=True)
    fixture = tmp_path / "ufw-status.txt"
    fixture.write_text(status or "", encoding="utf-8", newline="\n")
    body = ("exit 1\n" if status is None
            else f'cat "{str(fixture).replace(chr(92), "/")}"\n')
    stub = binpath / "ufw"
    stub.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    script = tmp_path / "harness.sh"
    script.write_text(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        'DOMAIN=""\n'
        f'NGINX_MODE="{mode}"\n'
        'ADMIN_IP=""\n'
        f'SENTINEL_PUBLIC_PORT="{port}"\n'
        f'set -- {cli_args}\n'
        + _arg_parse_block()
        + _ufw_block()
        + 'printf "COUNTS %d %d\\n" "$FAIL_COUNT" "$WARN_COUNT"\n',
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1",
           "PATH": str(binpath).replace("\\", "/") + os.pathsep + os.environ.get("PATH", "")}
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=REPO / "deploy", capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    counts = next(l for l in proc.stdout.splitlines() if l.startswith("COUNTS"))
    _, fails, warns = counts.split()
    return int(fails), int(warns), proc.stdout + proc.stderr


def test_the_allow_ufw_flag_is_reachable_from_the_command_line(tmp_path):
    """Defectul măsurat pe gazda a doua: `--allow-ufw` exista în `--help` și
    era ignorat pe singurul drum prin care scripts/deploy.sh și deploy.ps1 îl
    pot transmite — un `sudo` nou, care nu moștenește ALLOW_UFW din mediu."""
    fails, warns, out = _run_cli(tmp_path, status=UFW_ACTIVE_ONLY_SSH,
                                 cli_args="--allow-ufw")
    assert fails == 0, out
    assert warns > 0, out
    assert "ufw allow 8443/tcp" in out


def test_without_the_cli_flag_an_active_ufw_still_blocks(tmp_path):
    """Comportamentul de azi, neschimbat: fără steag, un ufw activ care nu
    permite portul tot oprește deploy-ul — altfel steagul ar deveni implicit."""
    fails, _, out = _run_cli(tmp_path, status=UFW_ACTIVE_ONLY_SSH, cli_args="")
    assert fails > 0, out


def test_the_web_port_flag_and_the_allow_ufw_flag_compose(tmp_path):
    """Ambele argumente vin din același `$@` — `--web-port` trebuie să
    schimbe și portul verificat de ramura ufw când `--allow-ufw` e prezent
    tot acolo, nu doar când e singurul argument."""
    fails, warns, out = _run_cli(
        tmp_path, status=UFW_ACTIVE_ONLY_SSH,
        cli_args="--web-port 9443 --nginx-mode dedicated --allow-ufw",
        port="9443")
    assert fails == 0, out
    assert warns > 0, out
    assert "9443/tcp" in out


# ---------------------------------------------------------------------------
# `bash deploy/preflight.sh --help` chiar arată steagul, nu doar acceptă
# argumentul.
#
# Măsurat înainte de reparație: `--help` tipărea un interval fix `sed -n
# '2,15p'`, scris când singurele argumente erau --domain și --web-port —
# `--admin-ip`, `--allow-ufw` și `--allow-firewalld` au fost adăugate mai
# târziu fără să mute intervalul. Un operator care rulează `--help` ca să
# afle ce poate transmite prin `scripts/deploy.sh` nu vedea niciunul dintre
# cele trei. Aceeași precauție ca `test_help_still_prints_the_flags_it_documents`
# din tests/unit/test_force_step_list.py, pentru install.sh.
# ---------------------------------------------------------------------------
def test_help_output_actually_shows_the_new_flags():
    """Dacă intervalul `sed -n 'N,Mp'` din antet redevine prea îngust — de
    exemplu fiindcă un paragraf nou a fost adăugat deasupra fără să mute M —
    `--help` ar tăcea din nou despre `--admin-ip`/`--allow-ufw`/
    `--allow-firewalld`, exact cum a tăcut prima dată.

    Cele trei nume apar deja în linia de sinopsis de sus (`[--allow-ufw]
    [--allow-firewalld]`), care intra oricum în vechiul interval `2,15p` —
    deci o simplă căutare a numelor n-ar fi picat la vechea tăiere. Ce nu
    intra în vechiul interval e explicația de la `--allow-firewalld`, ultima
    linie din bloc; aceea e ce dovedește că intervalul chiar a fost mutat, nu
    doar că cele trei nume există undeva mai sus."""
    import re
    match = re.search(r"--help\|-h\)\s*sed -n '(\d+),(\d+)p'", PREFLIGHT)
    assert match, "handler-ul --help nu mai e un interval sed peste antet"
    first, last = int(match.group(1)), int(match.group(2))
    shown = "\n".join(PREFLIGHT.splitlines()[first - 1:last])
    assert "--admin-ip" in shown
    assert "--allow-ufw" in shown
    assert "--allow-firewalld" in shown
    assert "same consent, for firewalld." in shown, \
        "intervalul e prea scurt — taie explicația lui --allow-firewalld"
