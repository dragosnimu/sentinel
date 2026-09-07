"""`deploy/tmpfiles/sentinel.conf` trebuie reaplicat la FIECARE deploy, nu doar
la instalarea inițială.

Motivul e măsurat, nu ipotetic: `d /var/lib/sentinel-watchdog 2750 root
sentinel -` a fost adăugat pe 7 septembrie 2026, la mult timp după ce pasul 19
(`user_and_dirs`) era deja marcat făcut pe gazda de producție. Pasul 19 nu e în
`ALWAYS_STEPS`, deci fără o cale separată o gazdă existentă n-ar primi
NICIODATĂ linia nouă — `sentinel-watchdog.service` ar găsi directorul lipsă la
nesfârșit, iar flush-ul anti-lockout pentru un dashboard picat n-ar mai putea
porni vreodată. Vezi `sentinel/respond/watchdog.py` și
`sentinel/selfcheck/checks.py::check_watchdog_state`.

Testul de mai jos rulează FUNCȚIA LIVRATĂ `ensure_tmpfiles_applied` din
`deploy/install.sh`, cu `install` și `systemd-tmpfiles` momeli executabile pe
PATH, într-un scenariu în care pasul 19 e ÎNCĂ marcat făcut — exact forma unei
gazde existente la un deploy repetat.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipsește din PATH")]


def _func(name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", INSTALL, re.S | re.M)
    assert match, f"funcția {name} nu mai există în deploy/install.sh"
    return match.group(0)


def _write_stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# Momeli: doar înregistrează chemarea și argumentele. NU ating vreo cale reală
# de sistem (`/usr/lib/tmpfiles.d`) — mașina care rulează testul, pe Windows sau
# Linux, n-are voie să vadă vreo scriere acolo dintr-un test.
LOGGING_STUB = "printf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$CALLS\"\n"


def test_tmpfiles_reapply_runs_even_when_step_19_is_already_marked_done(tmp_path):
    """Pasul 19 marcat `done` (gazda existentă) nu are voie să oprească
    reaplicarea tmpfiles — `ensure_tmpfiles_applied` trebuie chemată
    necondiționat, exact ca `ensure_docker_access`."""
    calls = tmp_path / "calls.txt"
    stubs = tmp_path / "bin"
    _write_stub(stubs, "install", LOGGING_STUB)
    _write_stub(stubs, "systemd-tmpfiles", LOGGING_STUB)

    state_dir = tmp_path / "state"
    markers = state_dir / ".install-state"
    markers.mkdir(parents=True)
    (markers / "19_user_and_dirs").write_text("2026-08-01T00:00:00Z", encoding="utf-8")

    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\n"
        f'SCRIPT_DIR="{(REPO / "deploy").as_posix()}"\n'
        "source ./lib/common.sh\n"
        + _func("ensure_tmpfiles_applied") + "\n"
        # Corpul real al pasului 19 nu contează aici — doar dacă rulează sau nu.
        'step_user_and_dirs() { printf STEP19-RAN >> "$CALLS"; }\n'
        "run_step 19 user_and_dirs step_user_and_dirs\n"
        "ensure_tmpfiles_applied\n",
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1",
           "CALLS": str(calls).replace("\\", "/"),
           "SENTINEL_STATE_DIR": str(state_dir).replace("\\", "/"),
           "PATH": str(stubs).replace("\\", "/") + os.pathsep + os.environ.get("PATH", "")}

    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=str(REPO / "deploy"), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    log = calls.read_text(encoding="utf-8") if calls.exists() else ""
    assert "STEP19-RAN" not in log, (
        "pasul 19 nu are voie să ruleze din nou doar fiindcă a fost marcat — "
        "altfel testul ăsta n-ar dovedi nimic despre gazde EXISTENTE"
    )
    assert "install " in log, (
        "ensure_tmpfiles_applied nu a rulat deloc — pe o gazdă unde pasul 19 e "
        "marcat de mult, tmpfiles.conf n-ar mai fi reaplicat niciodată"
    )
    assert "systemd-tmpfiles --create" in log, (
        "install a copiat fișierul, dar systemd-tmpfiles --create nu a rulat — "
        "un fișier pe disc nu e dovadă că directorul chiar a fost creat"
    )
    # Sursa dată lui `install` trebuie să fie sentinel.conf-ul REAL din repo, nu
    # o copie: SCRIPT_DIR e cel calculat de install.sh la rulare reală.
    assert "deploy/tmpfiles/sentinel.conf" in log.replace("\\", "/")


def test_the_call_is_present_and_unconditional_in_main():
    """La fel ca `ensure_docker_access`: apelul trebuie să existe în afara
    oricărui `run_step`, altfel un `--force-step 19` seamănă cu un deploy
    normal, dar fără el gazda nu mai primește niciodată linia tmpfiles nouă."""
    sequence = re.search(r"^(    run_step  1 preflight.*?run_step 40 notify.*?)$",
                         INSTALL, re.S | re.M)
    assert sequence, "nu mai găsesc secvența de pași din install.sh"
    body = sequence.group(1)

    call = re.search(r"^\s*ensure_tmpfiles_applied\s*$", body, re.M)
    assert call, "`ensure_tmpfiles_applied` nu e chemată necondiționat în main"

    step19 = re.search(r"^\s*run_step 19 user_and_dirs", body, re.M)
    assert step19, "pasul 19 nu mai există în secvență"
    assert step19.start() < call.start(), (
        "apelul trebuie să fie DUPĂ pasul 19, nu înainte — altfel gazdele fără "
        "user/grup sentinel n-ar avea unde scrie fișierul"
    )


def test_step_19_no_longer_applies_tmpfiles_itself():
    """Dublă acordare, un adevăr fiecare, e exact tiparul de bug din CLAUDE.md:
    dacă pasul 19 mai are propria lui copie a liniilor, o divergență între cele
    două locuri s-ar putea corecta pe jumătate și ar arăta reparat."""
    step19 = _func("step_user_and_dirs")
    assert "systemd-tmpfiles --create" not in step19, step19
    assert "ensure_tmpfiles_applied" in step19, (
        "pasul 19 trebuie să cheme funcția comună, nu s-o fi pierdut din instalarea inițială"
    )
