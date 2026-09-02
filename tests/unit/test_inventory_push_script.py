"""`scripts/inventory-push.sh` — the reviewed path onto the host, end to end.

Runs the REAL script against fake `ssh`/`scp` shims on PATH, not a rewritten
copy of its logic — a test that reimplements the script proves the
reimplementation, not the script that operators actually run.

Panele pe care le previne fiecare test, în termeni de operator:

  * **Un fișier local trunchiat retrage tot ce era pe gazdă — pe hârtie.**
    `sentinel.scan.inventory.sync` tratează o listă goală ca „nimic de
    retras", niciodată ca „retrage tot" (`inventory.py:sync`, secțiunea „De
    ce un fișier gol nu retrage nimic"). Un fișier local gol care totuși
    trece de `load()` (`assets: []`, cheia `assets:` lipsă, sau un fișier de
    zero octeți) nu are voie să ajungă la un diff care arată o retragere pe
    care gazda n-o va face niciodată.
  * **Un inventar real ajunge în depozitul public.** Fișierul exact de acest
    fel a scăpat o dată deja din acest depozit (vezi
    `deploy/config/inventory-filled.yaml.example`). Scriptul refuză să
    pornească dacă `--file` arată spre o cale nescutită de `.gitignore`,
    indiferent CUM a fost tastată calea aia — literă de unitate mare/mică,
    nume scurt 8.3 pe Windows — nu doar în ortografia „canonică".
  * **O retragere aplicată fără să fi fost arătată operatorului.** Dacă orice
    activ ar fi retras fără promptul „Continui? [da/NU]", un `NU` sau un enter
    gol tot ar scrie fișierul.
  * **„Nu am putut citi" tratat ca „gazda nu are nimic".** O eroare de sudo
    sau de driver care conține din întâmplare fraza „No such file or
    directory" (dar NU despre calea inventarului) nu are voie să treacă drept
    „prima instalare".
  * **Un `python3` care nu rulează raportează un fișier valid ca stricat.** Pe
    Windows, `python3` poate fi stub-ul Magazinului Microsoft — prezent,
    executabil, dar care nu rulează Python. Scriptul trebuie să găsească un
    interpret care CHIAR rulează, nu doar unul care există pe PATH.
  * **`--dry-run` scrie ceva.** Diferența dintre „arată-mi ce s-ar schimba" și
    „aplică" trebuie să fie reală, nu doar un mesaj diferit pe același efect.

Fake-urile de `ssh`/`scp` țin un JURNAL al fiecărei invocări (`FAKE_SSH_LOG`,
`FAKE_SCP_LOG`), nu doar un cod de întoarcere — testele care promit „nu atinge
SSH" verifică jurnalul, nu doar codul de ieșire al scriptului (un test care
verifică doar rezultatul, când numele promite un efect secundar anume, nu
dovedește efectul secundar).
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

EMPTY_ASSETS_LIST = "assets: []\n"
NO_ASSETS_KEY = "allowlist: []\n"
ZERO_BYTES = ""


def _fake_bin(tmp_path: Path, *, broken_python3: bool = False) -> Path:
    """A directory with fake `ssh`/`scp`, shadowing the real ones on PATH.

    `ssh` dispatches on the trailing command string the script sends it;
    unrecognised commands fail loudly (exit 99) instead of silently
    succeeding, so a script change that starts sending a NEW remote command
    fails this suite instead of passing it by accident.

    Both `ssh` and `scp` append every invocation to `FAKE_SSH_LOG` /
    `FAKE_SCP_LOG` (when set) — a JOURNAL, not just an exit code, so a test
    that promises "never touches SSH" can check that no line was ever
    written, not infer it from the script's own return code.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()

    ssh_script = bindir / "ssh"
    ssh_script.write_text(
        "#!/usr/bin/env bash\n"
        'cmd="${@: -1}"\n'
        '[[ -n "${FAKE_SSH_LOG:-}" ]] && printf "%s\\n" "$cmd" >> "${FAKE_SSH_LOG}"\n'
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
        '[[ -n "${FAKE_SCP_LOG:-}" ]] && printf "%s\\n" "$*" >> "${FAKE_SCP_LOG}"\n'
        "src=\"\"\n"
        'for a in "$@"; do [[ -f "$a" ]] && src="$a"; done\n'
        'cp "$src" "${FAKE_APPLIED_STAGING}"\n'
        "exit 0\n",
        encoding="utf-8", newline="\n",
    )
    scripts = [ssh_script, scp_script]

    # On this dev machine (and on a real operator's Windows machine) `python3`
    # can resolve to Windows' broken Store-alias stub, not a real interpreter.
    # Shadow it here with whatever `python` this sandbox actually has, so
    # every test measures the SCRIPT's `resolve_python`, not the ambient
    # environment's own `python3` shim — UNLESS `broken_python3` asks for the
    # stub to be simulated on purpose, to prove the fallback to `python` works.
    real_python = shutil.which("python") or shutil.which("python3")
    if real_python:
        if broken_python3:
            stub = bindir / "python3"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                'echo "Python was not found; run without arguments to install from the Microsoft Store" >&2\n'
                "exit 9009\n",
                encoding="utf-8", newline="\n",
            )
            scripts.append(stub)
            working = bindir / "python"
        else:
            working = bindir / "python3"
        working.write_text(
            "#!/usr/bin/env bash\n"
            f'exec "{Path(real_python).as_posix()}" "$@"\n',
            encoding="utf-8", newline="\n",
        )
        scripts.append(working)

    for f in scripts:
        f.chmod(f.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _run(tmp_path: Path, *args: str, input_text: str = "",
          env_extra: dict | None = None, broken_python3: bool = False):
    bindir = _fake_bin(tmp_path, broken_python3=broken_python3)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    applied = tmp_path / "applied-inventory.yaml"
    staging = tmp_path / "staging-upload.yaml"
    ssh_log = tmp_path / "ssh.log"
    scp_log = tmp_path / "scp.log"
    env["FAKE_APPLIED_FILE"] = str(applied)
    env["FAKE_APPLIED_STAGING"] = str(staging)
    env["FAKE_SSH_LOG"] = str(ssh_log)
    env["FAKE_SCP_LOG"] = str(scp_log)
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
    return proc, applied, ssh_log, scp_log


def _log_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------------------------------------------------------
# Fișier local gol / trunchiat: refuz ÎNAINTE de orice conexiune
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [EMPTY_ASSETS_LIST, NO_ASSETS_KEY, ZERO_BYTES],
                          ids=["assets-empty-list", "no-assets-key", "zero-bytes"])
def test_empty_local_file_is_refused_before_any_ssh(tmp_path, body):
    # ESTE testul pentru divergența raportată de verificator: un fișier local
    # care declară 0 active nu are voie să ajungă la un diff care arată o
    # retragere pe care `sync` n-o va face niciodată.
    local = tmp_path / "inventory.yaml"
    local.write_text(body, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(local))
    assert proc.returncode != 0, proc.stdout
    assert not applied.exists()
    assert _log_lines(ssh_log) == [], "un fișier local gol a deschis totuși o conexiune SSH"
    assert _log_lines(scp_log) == []


def test_empty_local_file_refused_even_with_yes(tmp_path):
    # --yes nu are voie să treacă peste refuzul de mai sus: altfel un fișier
    # trunchiat din greșeală, împins printr-o automatizare cu --yes, ar goli
    # tăcut inventarul de pe gazdă fără nicio întrebare.
    local = tmp_path / "inventory.yaml"
    local.write_text(EMPTY_ASSETS_LIST, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(local), "--yes")
    assert proc.returncode != 0, proc.stdout
    assert not applied.exists()
    assert _log_lines(ssh_log) == []


def test_nonempty_local_file_with_only_kept_assets_still_proceeds(tmp_path):
    # Controlul direcției bune: refuzul e pe LISTA GOALĂ, nu pe orice fișier
    # care nu adaugă active noi.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local),
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()


# ---------------------------------------------------------------------------
# Instalare nouă / retragere / dry-run
# ---------------------------------------------------------------------------

def test_first_install_no_host_file_needs_no_confirmation_and_applies(tmp_path):
    # Falsă dacă „No such file" ar cere confirmare ca o retragere reală, sau
    # dacă instalarea nouă n-ar scrie deloc fișierul.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(local))
    assert proc.returncode == 0, proc.stderr
    assert applied.exists(), "fișierul n-a fost scris pe gazdă la o instalare nouă"
    assert applied.read_text(encoding="utf-8") == VALID_INVENTORY
    assert any("sudo -n cat" in line for line in _log_lines(ssh_log))
    assert any("sudo -n install" in line for line in _log_lines(ssh_log))


def test_retirement_without_confirmation_writes_nothing(tmp_path):
    # ESTE testul care contează cel mai mult: un „nu" sau un rând gol la
    # promptul de retragere nu are voie să lase fișierul scris pe gazdă.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")  # doar sshd
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(SECOND_ASSET_INVENTORY, encoding="utf-8", newline="\n")  # sshd + postgresql

    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local), input_text="nu\n",
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode != 0, "scriptul n-a ieșit cu eroare la un refuz de confirmare"
    assert "SE RETRAG" in proc.stdout
    assert "postgresql" in proc.stdout
    assert not applied.exists(), "fișierul a fost scris pe gazdă fără confirmare"
    assert _log_lines(scp_log) == [], "upload-ul a pornit fără confirmare"


def test_retirement_confirmed_with_da_applies(tmp_path):
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(SECOND_ASSET_INVENTORY, encoding="utf-8", newline="\n")

    proc, applied, ssh_log, scp_log = _run(
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

    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local), "--dry-run",
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert "SE RETRAG" in proc.stdout
    assert not applied.exists(), "--dry-run a scris pe gazdă"
    assert _log_lines(scp_log) == []


def test_no_change_needs_no_confirmation(tmp_path):
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    remote = tmp_path / "remote-current.yaml"
    remote.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")  # identic

    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local),  # fără input pentru prompt: n-are voie să ceară unul
        env_extra={"FAKE_REMOTE_INVENTORY_FILE": str(remote)},
    )
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()


# ---------------------------------------------------------------------------
# „Nu se poate citi" vs. „gazdă nouă"
# ---------------------------------------------------------------------------

def test_a_remote_read_error_is_not_treated_as_an_empty_host(tmp_path):
    # Falsă dacă un refuz de sudo sau o conexiune căzută la mijloc ar fi
    # confundate cu „gazda n-are încă inventar" — o retragere reală ascunsă în
    # spatele unei erori de citire ar trece nearătată, iar fișierul s-ar scrie
    # peste o stare pe care scriptul n-a putut-o vedea.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local),
        env_extra={"FAKE_REMOTE_CAT_ERROR": "sudo: a password is required"},
    )
    assert proc.returncode != 0, "o eroare de citire a fost tratată ca succes"
    assert not applied.exists(), "fișierul a fost scris fără să se fi putut citi starea curentă"


def test_a_missing_cat_binary_is_not_treated_as_a_missing_inventory_file(tmp_path):
    # ESTE cazul adversarial raportat: mesajul conține fraza "No such file or
    # directory", dar despre BINARUL `cat`, nu despre calea inventarului. Un
    # tipar neancorat pe cale ar citi asta ca „prima instalare" și ar
    # continua direct la scriere.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local),
        env_extra={"FAKE_REMOTE_CAT_ERROR": "sudo: /usr/bin/cat: No such file or directory"},
    )
    assert proc.returncode != 0, "eroarea despre binarul cat a fost citită ca inventar lipsă"
    assert not applied.exists()


def test_the_real_missing_inventory_message_is_still_recognised(tmp_path):
    # Controlul direcției bune pentru testul de mai sus: mesajul REAL al lui
    # `cat` pentru calea inventarului tot trebuie recunoscut ca „prima
    # instalare", altfel ancorarea a devenit prea strictă.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local),
        env_extra={"FAKE_REMOTE_CAT_ERROR":
                   "cat: /etc/sentinel/inventory.yaml: No such file or directory"},
    )
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()


# ---------------------------------------------------------------------------
# `python3` care nu rulează
# ---------------------------------------------------------------------------

def test_broken_python3_stub_falls_back_to_python(tmp_path):
    # Falsă dacă scriptul s-ar opri la stub-ul Magazinului Microsoft cu un
    # mesaj care spune că FIȘIERUL e stricat, când de fapt interpretul e cel
    # nefuncțional. Vezi capul fișierului.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(
        tmp_path, "--file", str(local), broken_python3=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "does not pass" not in proc.stderr
    assert applied.exists()


# ---------------------------------------------------------------------------
# Validare locală: nu atinge SSH deloc (dovedit prin jurnal, nu prin cod de ieșire)
# ---------------------------------------------------------------------------

def test_local_file_that_fails_validation_never_touches_ssh(tmp_path):
    # Numele promite un efect secundar — "nu atinge SSH" — și îl verifică prin
    # JURNALUL fake-ului, nu doar prin codul de ieșire: un cod de ieșire
    # nenul e compatibil și cu „a deschis SSH și a picat mai târziu".
    local = tmp_path / "inventory.yaml"
    local.write_text("assets: not-a-list\n", encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(local))
    assert proc.returncode != 0
    assert not applied.exists()
    assert _log_lines(ssh_log) == [], "validarea locală a deschis totuși o conexiune SSH"
    assert _log_lines(scp_log) == []


# ---------------------------------------------------------------------------
# Garda anti-scurgere: fișier din depozit, în orice ortografie de cale
# ---------------------------------------------------------------------------

def test_refuses_a_tracked_file_inside_the_repo(tmp_path):
    # Falsă dacă scriptul ar accepta să citească un inventar real de pe o cale
    # din depozit pe care git n-o ignoră — exact felul de fișier care a scăpat
    # o dată deja (deploy/config/inventory-filled.yaml.example).
    target = ROOT / "tests" / "unit" / "_tmp_not_ignored_inventory.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(target))
        assert proc.returncode != 0
        assert "gitignor" in proc.stderr.lower() or "NOT gitignored" in proc.stderr
        assert not applied.exists()
        assert _log_lines(ssh_log) == []
    finally:
        target.unlink(missing_ok=True)


def test_refuses_a_tracked_file_by_lowercase_drive_and_directory_spelling(tmp_path):
    # ESTE cazul adversarial raportat: aceeași cale din testul de mai sus,
    # scrisă cu litera de unitate și directorul cu litere mici. Un prefix pe
    # ȘIRURI n-o vede ca fiind sub REPO_ROOT (care vine din `pwd`, cu
    # majusculele originale); `git rev-parse --show-toplevel` o vede oricum,
    # fiindcă rezolvă prin filesystem, nu prin text — vezi capul scriptului.
    target = ROOT / "tests" / "unit" / "_tmp_not_ignored_inventory.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    lowered = str(target).lower()
    assert lowered != str(target), "calea nu conține nicio literă mare de schimbat pe mașina asta"
    try:
        proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", lowered)
        assert proc.returncode != 0, \
            "o cale scrisă cu litere mici a ocolit garda anti-scurgere"
        assert not applied.exists()
        assert _log_lines(ssh_log) == []
    finally:
        target.unlink(missing_ok=True)


def test_allows_a_tracked_file_with_allow_tracked_flag(tmp_path):
    target = ROOT / "tests" / "unit" / "_tmp_not_ignored_inventory.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(target), "--allow-tracked")
        assert proc.returncode == 0, proc.stderr
        assert applied.exists()
    finally:
        target.unlink(missing_ok=True)


def test_a_file_ignored_by_git_proceeds_without_allow_tracked(tmp_path):
    # Controlul direcției bune: `scratchpad/` chiar E scutit de `.gitignore`,
    # deci un fișier real acolo, la o cale absolută obișnuită, nu trebuie
    # refuzat.
    scratch_dir = ROOT / "scratchpad"
    scratch_dir.mkdir(exist_ok=True)
    target = scratch_dir / "_tmp_inventory_push_test.yaml"
    target.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    try:
        proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(target))
        assert proc.returncode == 0, proc.stderr
        assert applied.exists()
    finally:
        target.unlink(missing_ok=True)


def test_a_file_outside_any_git_repo_proceeds(tmp_path):
    # Un fișier local ținut cu totul în afara depozitului — cazul obișnuit —
    # nu trebuie să declanșeze deloc garda anti-scurgere: `git rev-parse
    # --show-toplevel` din directorul lui eșuează (nu e sub niciun depozit),
    # iar scriptul trebuie să treacă mai departe, nu să blocheze pe o eroare
    # de la git.
    local = tmp_path / "inventory.yaml"
    local.write_text(VALID_INVENTORY, encoding="utf-8", newline="\n")
    proc, applied, ssh_log, scp_log = _run(tmp_path, "--file", str(local))
    assert proc.returncode == 0, proc.stderr
    assert applied.exists()
