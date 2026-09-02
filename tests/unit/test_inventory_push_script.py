"""`scripts/inventory-push.sh` — the reviewed path onto the host, end to end.

Runs the REAL script against fake `ssh`/`scp` shims on PATH, not a rewritten
copy of its logic — a test that reimplements the script proves the
reimplementation, not the script that operators actually run.

Panele pe care le previne fiecare test, în termeni de operator:

  * **Un inventar real ajunge în depozitul public.** Fișierul exact de acest
    fel a scăpat o dată deja din acest depozit (vezi
    `deploy/config/inventory-filled.yaml.example`). Scriptul refuză să
    pornească dacă `--file` arată spre o cale nescutită de `.gitignore`,
    ÎNAINTE să atingă rețeaua.
  * **O retragere aplicată fără să fi fost arătată operatorului.** Dacă orice
    activ ar fi retras fără promptul „Continui? [da/NU]", un `NU` sau un enter
    gol tot ar scrie fișierul.
  * **„Nu am putut citi" tratat ca „gazda nu are nimic".** O eroare de sudo pe
    citirea inventarului curent nu are voie să arate ca o instalare nouă — ar
    face fiecare activ existent să pară „adăugat", iar o retragere reală
    ascunsă în spatele unui refuz de citire ar trece nedetectată.
  * **`--dry-run` scrie ceva.** Diferența dintre „arată-mi ce s-ar schimba" și
    „aplică" trebuie să fie reală, nu doar un mesaj diferit pe același efect.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "inventory-push.sh"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")

VALID_INVENTORY = """\
assets:
  - name: sshd
    kind: service
"""

SECOND_ASSET_INVENTORY = """\
assets:
  - name: sshd
    kind: service
  - name: postgresql
    kind: database
"""


def _fake_bin(tmp_path: Path) -> Path:
    """A directory with fake `ssh`/`scp`, shadowing the real ones on PATH.

    `ssh` dispatches on the trailing command string the script sends it;
    unrecognised commands fail loudly (exit 99) instead of silently
    succeeding, so a script change that starts sending a NEW remote command
    fails this suite instead of passing it by accident.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()

    ssh_script = bindir / "ssh"
    ssh_script.write_text(
        "#!/usr/bin/env bash\n"
        'cmd="${@: -1}"\n'
        'case "$cmd" in\n'
        '  "echo connected")\n'
        '    [[ "${FAKE_SSH_CONNECT_OK:-1}" == "1" ]] && { echo connected; exit 0; } || exit 1 ;;\n'
        "  sudo\\ -n\\ cat*)\n"
        "    # cmd-ul real cere \"2>&1\" — pe o gazdă adevărată shell-ul de la\n"
        "    # distanță ar fi combinat deja stderr în stdout până la ssh; fake-ul\n"
        "    # scrie deci direct pe STDOUT, nu pe stderr, ca simularea să fie fidelă.\n"
        '    if [[ -n "${FAKE_REMOTE_INVENTORY_FILE:-}" && -f "${FAKE_REMOTE_INVENTORY_FILE}" ]]; then\n'
        '      cat "${FAKE_REMOTE_INVENTORY_FILE}"; exit 0\n'
        '    elif [[ -n "${FAKE_REMOTE_CAT_ERROR:-}" ]]; then\n'
        '      echo "${FAKE_REMOTE_CAT_ERROR}"; exit 1\n'
        "    else\n"
        '      echo "cat: /etc/sentinel/inventory.yaml: No such file or directory"; exit 1\n'
        "    fi ;;\n"
        "  chmod\\ 600*)\n"
        "    exit 0 ;;\n"
        "  sudo\\ -n\\ install*)\n"
        '    cp "${FAKE_APPLIED_STAGING}" "${FAKE_APPLIED_FILE}"; exit 0 ;;\n'
        "  *)\n"
        '    echo "fake ssh: unrecognised command: $cmd" >&2; exit 99 ;;\n'
        "esac\n",
        encoding="utf-8", newline="\n",
    )
    scp_script = bindir / "scp"
    scp_script.write_text(
        "#!/usr/bin/env bash\n"
        "src=\"\"\n"
        'for a in "$@"; do [[ -f "$a" ]] && src="$a"; done\n'
        'cp "$src" "${FAKE_APPLIED_STAGING}"\n'
        "exit 0\n",
        encoding="utf-8", newline="\n",
    )
    scripts = [ssh_script, scp_script]

    # On this dev machine `python3` resolves to Windows' broken Store-alias
    # stub, not a real interpreter — a Windows-only PATH quirk, not something
    # the shipped script gets wrong (the real hosts it runs against are
    # Linux, with a real `python3`). Shadow it here with whatever `python`
    # this sandbox actually has, so the test measures the SCRIPT, not the
    # environment's `python3` shim.
    real_python = shutil.which("python") or shutil.which("python3")
    if real_python:
        py_shim = bindir / "python3"
        py_shim.write_text(
            "#!/usr/bin/env bash\n"
            f'exec "{Path(real_python).as_posix()}" "$@"\n',
            encoding="utf-8", newline="\n",
        )
        scripts.append(py_shim)

    for f in scripts:
        f.chmod(f.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _run(tmp_path: Path, *args: str, input_text: str = "", env_extra: dict | None = None):
    bindir = _fake_bin(tmp_path)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    applied = tmp_path / "applied-inventory.yaml"
    staging = tmp_path / "staging-upload.yaml"
    env["FAKE_APPLIED_FILE"] = str(applied)
    env["FAKE_APPLIED_STAGING"] = str(staging)
    env.update(env_extra or {})
    # Octeți bruți, nu `text=True`: `subprocess.run` nu acceptă `newline=` pe
    # Python 3.10, iar fără el modul text ar traduce `\n` din `input_text` în
    # `os.linesep` la scriere — pe Windows, `\r\n`. `read -r` din script ar
    # citi atunci `da\r`, diferit de `da`, iar promptul de confirmare ar
    # respinge chiar răspunsul „da" pe care testul îl dă.
    proc = subprocess.run(
        [BASH, str(SCRIPT), "--host", "example.invalid", "--user", "deploy", *args],
        input=input_text.encode("utf-8"), capture_output=True,
        env=env, cwd=str(ROOT),
    )
    proc.stdout = proc.stdout.decode("utf-8", errors="replace")
    proc.stderr = proc.stderr.decode("utf-8", errors="replace")
    return proc, applied


def test_first_install_no_host_file_needs_no_confirmation_and_applies(tmp_path):
    # Falsă dacă „No such file" ar cere confirmare ca o retragere reală, sau
    # dacă instalarea nouă n-ar scrie deloc fișierul.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied = _run(tmp_path, "--file", str(local))
    assert proc.returncode == 0, proc.stderr
    assert "primul install" not in proc.stdout  # nu inventăm text; doar verificăm efectul
    assert applied.exists(), "fișierul n-a fost scris pe gazdă la o instalare nouă"
    assert applied.read_text(encoding="utf-8") == VALID_INVENTORY


def test_retirement_without_confirmation_writes_nothing(tmp_path):
    # ESTE testul care contează cel mai mult: un „nu" sau un rând gol la
    # promptul de retragere nu are voie să lase fișierul scris pe gazdă.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")  # doar sshd
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(SECOND_ASSET_INVENTORY, encoding="utf-8", newline="\n")  # sshd + postgresql

    proc, applied = _run(
        tmp_path, "--file", str(local), input_text="nu\n",
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode != 0, "scriptul n-a ieșit cu eroare la un refuz de confirmare"
    assert "SE RETRAG" in proc.stdout
    assert "postgresql" in proc.stdout
    assert not applied.exists(), "fișierul a fost scris pe gazdă fără confirmare"


def test_retirement_confirmed_with_da_applies(tmp_path):
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(SECOND_ASSET_INVENTORY, encoding="utf-8", newline="\n")

    proc, applied = _run(
        tmp_path, "--file", str(local), input_text="da\n",
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()
    assert applied.read_text(encoding="utf-8") == VALID_INVENTORY


def test_dry_run_never_writes_even_with_retirement(tmp_path):
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(SECOND_ASSET_INVENTORY, encoding="utf-8", newline="\n")

    proc, applied = _run(
        tmp_path, "--file", str(local), "--dry-run",
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert "SE RETRAG" in proc.stdout
    assert not applied.exists(), "--dry-run a scris pe gazdă"


def test_no_change_needs_no_confirmation(tmp_path):
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")  # identic

    proc, applied = _run(
        tmp_path, "--file", str(local),  # fără input pentru prompt: n-are voie să ceară unul
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()


def test_a_remote_read_error_is_not_treated_as_an_empty_host(tmp_path):
    # Falsă dacă un refuz de sudo sau o conexiune căzută la mijloc ar fi
    # confundate cu „gazda n-are încă inventar" — o retragere reală ascunsă în
    # spatele unei erori de citire ar trece nearătată, iar fișierul s-ar scrie
    # peste o stare pe care scriptul n-a putut-o vedea.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied = _run(
        tmp_path, "--file", str(local),
        env_extra={"FAKE_REMOTE_CAT_ERROR": "sudo: a password is required"},
    )
    assert proc.returncode != 0, "o eroare de citire a fost tratată ca succes"
    assert not applied.exists(), "fișierul a fost scris fără să se fi putut citi starea curentă"


def test_local_file_that_fails_validation_never_touches_ssh(tmp_path):
    # Falsă dacă un fișier local stricat ar ajunge totuși să deschidă o
    # conexiune SSH — comanda de conectare ar apărea ca invocată în fake-ul
    # de mai sus, care ar tolera-o; aici verificăm direct că nu s-a scris nimic
    # și codul de ieșire e ne-zero, fără să existe vreun fake configurat.
    local = tmp_path / "inventory.yaml"
    local.write_text("assets: not-a-list\n", encoding="utf-8", newline="\n")
    proc, applied = _run(tmp_path, "--file", str(local))
    assert proc.returncode != 0
    assert not applied.exists()


def test_refuses_a_tracked_file_inside_the_repo(tmp_path):
    # Falsă dacă scriptul ar accepta să citească un inventar real de pe o cale
    # din depozit pe care git n-o ignoră — exact felul de fișier care a scăpat
    # o dată deja (deploy/config/inventory-filled.yaml.example).
    target = ROOT / "tests" / "unit" / "_tmp_not_ignored_inventory.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied = _run(tmp_path, "--file", str(target))
        assert proc.returncode != 0
        assert "gitignor" in proc.stderr.lower() or "leaked" in proc.stderr.lower() \
            or "NOT gitignored" in proc.stderr
        assert not applied.exists()
    finally:
        target.unlink(missing_ok=True)


def test_allows_a_tracked_file_with_allow_tracked_flag(tmp_path):
    target = ROOT / "tests" / "unit" / "_tmp_not_ignored_inventory.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied = _run(tmp_path, "--file", str(target), "--allow-tracked")
        assert proc.returncode == 0, proc.stderr
        assert applied.exists()
    finally:
        target.unlink(missing_ok=True)


def test_scratchpad_relative_path_is_gitignored_and_proceeds(tmp_path):
    # Controlul direcției bune: `scratchpad/` chiar E scutit de `.gitignore`,
    # deci un fișier real acolo nu trebuie refuzat.
    scratch_dir = ROOT / "scratchpad"
    scratch_dir.mkdir(exist_ok=True)
    target = scratch_dir / "_tmp_inventory_push_test.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied = _run(tmp_path, "--file", str(target))
        assert proc.returncode == 0, proc.stderr
        assert applied.exists()
    finally:
        target.unlink(missing_ok=True)
