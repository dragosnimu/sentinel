"""Pasul 24 nu are voie să raporteze succes fără să DOVEDEASCĂ importul.

`sentinel/patch/validator.py` importă `executor.policy` și îl întreabă pe el
dacă o comandă dintr-un plan are voie să ruleze ca root. Copia pe care o
importă e scrisă de instalator în `/opt/sentinel/lib/executor/policy.py`. Dacă
fișierul lipsește, e nelizibil pentru utilizatorul `sentinel`, sau e umbrit de
altceva, TOATE planurile de patch sunt refuzate cu `executor_policy_unreadable`
— iar operatorul află ore mai târziu, pe Telegram, nu la deploy.

Instalatorul face de-aia o probă reală. Testele de aici verifică DECIZIA
probei, nu prezența ei în text, fiindcă verificatorul rundei 3 a demonstrat că
prezența nu e suficientă: a mutat proba de sub `sudo -u sentinel` la root și a
schimbat `die` în `warn`, iar suita întreagă (5388 de teste) a rămas verde de
ambele dăți. Un guard care supraviețuiește propriei desființări e chiar tiparul
din CLAUDE.md — mecanismul există, deploy-ul raportează succes oricum.

Blocul se EXECUTĂ aici, cu momeli: un `sudo` care își notează argumentele și un
`python` care poate fi făcut să pice. Așa se vede efectul (cine rulează proba,
și dacă eșecul chiar oprește instalarea), nu intenția.
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


def _proof_block() -> str:
    """Blocul de probă exact cum se livrează, nu o copie a lui.

    Refuză zgomotos dacă nu mai există: o schimbare care îl scoate trebuie să
    strice testul ăsta cu un mesaj clar, nu să-l lase să potrivească pe nimic.
    """
    match = re.search(
        r"^    local import_err\n(.*?^    fi)$", INSTALL, re.S | re.M)
    assert match, (
        "blocul care dovedește importul lui executor.policy nu mai există în "
        "deploy/install.sh (căutat de la `local import_err` până la `fi`)")
    block = match.group(0)
    assert "import executor.policy" in block, block
    return block


def _write_stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run(tmp_path: Path, *, python_exit: int) -> tuple[subprocess.CompletedProcess, str]:
    """Rulează blocul livrat, cu `sudo` și `python` momeli.

    `sudo` își notează argumentele și apoi EXECUTĂ restul comenzii, ca proba
    să ajungă chiar la interpretorul momeală — altfel testul ar măsura doar
    dacă s-a chemat `sudo`, nu dacă proba s-a și executat.
    """
    calls = tmp_path / "calls.txt"
    stubs = tmp_path / "bin"
    _write_stub(stubs, "sudo",
                'printf "sudo %s\\n" "$*" >> "$CALLS"\n'
                'while [[ "$1" == "-u" ]]; do shift 2; done\n'
                'exec "$@"\n')

    prefix = tmp_path / "opt"
    venv_bin = prefix / "venv" / "bin"
    _write_stub(venv_bin, "python",
                'printf "python %s\\n" "$*" >> "$CALLS"\n'
                f'echo "ModuleNotFoundError: probă" >&2\nexit {python_exit}\n')

    script = tmp_path / "run.sh"
    script.write_text(
        "set -uo pipefail\n"
        f'SCRIPT_DIR="{(REPO / "deploy").as_posix()}"\n'
        "source ./lib/common.sh\n"
        f'SENTINEL_PREFIX="{prefix.as_posix()}"\n'
        "proof() {\n" + _proof_block() + "\n}\n"
        "proof\n"
        'printf "REACHED-THE-END\\n" >> "$CALLS"\n',
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1",
           "CALLS": str(calls).replace("\\", "/"),
           "PATH": str(stubs).replace("\\", "/") + os.pathsep + os.environ.get("PATH", "")}
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=str(REPO / "deploy"), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    return proc, (calls.read_text(encoding="utf-8") if calls.exists() else "")


def test_the_proof_runs_as_the_sentinel_user_not_as_root(tmp_path):
    """Rulată ca root, proba nu dovedește nimic despre ce poate citi
    `sentinel`: root citește și fișiere cu drepturi greșite, și directoare
    netraversabile pentru utilizatorul neprivilegiat. Instalatorul ar raporta
    „importul merge", iar `sentinel-telegram` ar refuza apoi fiecare plan.

    Verificatorul rundei 3 a scos exact `sudo -u "$SENTINEL_USER"` și n-a
    picat niciun test din 5388.
    """
    proc, log = _run(tmp_path, python_exit=0)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "python" in log, (
        "proba nu a executat niciun interpretor — nu s-a verificat nimic")
    sudo_lines = [ln for ln in log.splitlines() if ln.startswith("sudo ")]
    assert sudo_lines, (
        "proba a rulat DIRECT, nu prin `sudo -u`. Ca root, importul reușește "
        "chiar și acolo unde utilizatorul `sentinel` n-ar putea citi fișierul")
    assert any("-u sentinel" in ln for ln in sudo_lines), (
        f"proba nu rulează ca utilizatorul `sentinel`: {sudo_lines!r}")
    assert any("PYTHONPATH=" in ln and "/lib" in ln for ln in sudo_lines), (
        "proba nu folosește calea de import a pachetului (PYTHONPATH=.../lib), "
        f"deci n-o verifică pe cea reală: {sudo_lines!r}")


def test_a_failed_import_stops_the_install(tmp_path):
    """`die`, nu `warn`. Cu `warn`, pasul 24 se termină „cu succes", deploy-ul
    merge mai departe, serviciile pornesc — și fiecare plan de patch e refuzat
    de-atunci încolo, fără ca nimic din instalare să fi spus asta.

    Verificatorul rundei 3 a schimbat `die` în `warn` și n-a picat niciun test.
    """
    proc, log = _run(tmp_path, python_exit=1)

    assert proc.returncode != 0, (
        "un import eșuat NU a oprit pasul — instalarea ar raporta succes cu "
        "validatorul de planuri mort:\n" + proc.stdout + proc.stderr)
    assert "REACHED-THE-END" not in log, (
        "execuția a continuat după eșecul probei; `die` a devenit `warn`")


def test_the_failure_message_carries_the_interpreter_error(tmp_path):
    """Un guard care se oprește fără să spună DE CE trimite operatorul să caute
    singur. Eroarea reală a interpretorului trebuie să ajungă în mesaj — motivul
    pentru care proba nu redirectează spre /dev/null (vezi tabelul din
    CLAUDE.md: `augenrules --load 2>/dev/null`)."""
    proc, _ = _run(tmp_path, python_exit=1)

    combined = proc.stdout + proc.stderr
    assert "ModuleNotFoundError: probă" in combined, (
        "eroarea interpretorului a fost înghițită; mesajul de oprire nu spune "
        f"de ce a picat importul:\n{combined}")
