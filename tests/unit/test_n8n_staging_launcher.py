"""`scripts/n8n-staging.sh` — lansatorul de pe stația operatorului.

`ssh` momeală EXECUTĂ de-adevărat comanda primită (un bash, cu stdin-ul lansatorului), iar `sudo` momeală doar sare peste `-n`: lanțul
complet lansator -> ssh -> `bash -s` -> biblioteca de pe gazdă -> docker momeală rulează pe codul livrat. De aceea un test de aici
poate arăta că biblioteca ajunge pe stdin întreagă și că argumentele ajung citate, nu doar că lansatorul «a chemat ssh».

Ce NU dovedește: un ssh, un sudo sau o gazdă reale; doar șirul de comandă și ce primește scriptul de pe gazdă.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from _n8n_staging_world import LAUNCHER, UMASK_PREFIX, World
from _su_shell import BASH, posix, write_exec
from test_n8n_staging_host import add_network, add_volume, patch_state, LABEL

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

SSH = """#!/usr/bin/env bash
cmd="${@: -1}"
printf '%s\\n' "$cmd" >> "$FAKE_SSH_LOG"
printf '%s\\n' "$*" >> "$FAKE_SSH_ARGV_LOG"
exec bash -c "$cmd"
"""
SUDO = """#!/usr/bin/env bash
[[ "${1:-}" == -n ]] && shift
exec "$@"
"""


def run_launcher(w: World, *args: str, key: bool = True):
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    write_exec(w.bin / "sudo", SUDO)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"), HOME=posix(w.tmp))
    base = ["--host", "n8n.example.invalid", "--user", "dragos", "--port", "2222"] + (["--key", posix(w.tmp / "k")] if key else [])
    proc = subprocess.run([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", posix(LAUNCHER), *base, *args],
                          capture_output=True, env=env, timeout=600)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    log = (w.tmp / "ssh.log").read_text(encoding="utf-8").splitlines() if (w.tmp / "ssh.log").exists() else []
    return proc.returncode, out, log


@pytest.fixture
def w(tmp_path):
    world = World(tmp_path)
    yield world
    world.close()


BAD_VERSIONS = ["latest", "3.0", "3.0.1;reboot", "$(id)", "3.0.1 && id", "3.0.x", "", "v3.0.1"]


@pytest.mark.parametrize("bad", BAD_VERSIONS)
def test_a_bad_version_is_refused_before_any_connection(w, bad):
    """Versiunea ajunge într-un șir de comandă ssh executat ca root. Refuzată AICI, înainte de orice conexiune: jurnalul ssh e gol, iar
    ieșirea e 2."""
    rc, out, log = run_launcher(w, "up", "--version", bad)
    assert rc == 2 and log == [], (rc, out, log)
    assert w.docker_log() == []


@pytest.mark.parametrize("args", [["up"], ["up", "--version"], ["frobnicate"], ["up", "3.0.1"], ["down", "--yes"], ["logs", "--tail", "x"], []])
def test_unknown_subcommands_and_missing_values_are_refused_before_any_connection(w, args):
    """`up` fără `--version`, o subcomandă inventată sau un argument în plus nu se «ghicesc»: ieșire 2, nicio conexiune."""
    rc, out, log = run_launcher(w, *args)
    assert rc == 2 and log == [], (rc, out, log)


@pytest.mark.parametrize("host", ["-oProxyCommand=id", "-x", "a b", "h;id", "$(id)", ""])
def test_a_host_that_would_become_an_ssh_option_is_refused(w, host):
    """`--host -oProxyCommand=...` ar deveni o opțiune ssh și ar rula o comandă LOCAL, pe stația operatorului. Numele gazdei trebuie să
    înceapă cu o literă sau cifră și să aibă doar caractere de nume de gazdă."""
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"))
    proc = subprocess.run([BASH, posix(LAUNCHER), "--host", host, "--key", posix(w.tmp / "k"), "status"], capture_output=True, env=env, timeout=60)
    assert proc.returncode == 2, proc.stderr
    assert not (w.tmp / "ssh.log").exists()


@pytest.mark.parametrize("port", ["0", "70000", "22;id", "abc", "-1", ""])
def test_a_bad_port_is_refused_before_any_connection(w, port):
    """Un port care ajunge în aritmetica bash a dat cod arbitrar în smoke-test.sh. Aici e validat ca număr 1-65535 înainte de orice altceva."""
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"))
    proc = subprocess.run([BASH, posix(LAUNCHER), "--host", "h.example", "--port", port, "--key", posix(w.tmp / "k"), "status"],
                          capture_output=True, env=env, timeout=60)
    assert proc.returncode == 2, proc.stderr
    assert not (w.tmp / "ssh.log").exists()


def test_the_host_script_travels_on_stdin_and_arguments_arrive_as_separate_words(w):
    """Scriptul de pe gazdă nu se salvează acolo: ajunge pe stdin într-un `sudo -n bash -s` și rulează întreg (dovada: efectele lui în
    docker). Argumentele ajung ca cuvinte separate, citate pentru ssh."""
    rc, out, log = run_launcher(w, "down")
    assert rc == 0, out
    assert log[-1] == "sudo -n bash -s -- down", log
    assert "nimic de șters" in out                      # biblioteca a rulat întreagă, de pe stdin
    rc2, out2, log2 = run_launcher(w, "logs", "--tail", "50")
    assert log2[-1] == "sudo -n bash -s -- logs --tail 50", log2
    rc3, out3, log3 = run_launcher(w, "up", "--version", "3.0.9")
    assert log3[-1] == "sudo -n bash -s -- up --version 3.0.9", log3
    assert rc3 == 1                                      # 3.0.9 nu există în registrul momelii: se oprește la pull, nimic creat
    assert "REFUZAT sau EȘUAT (cod 1)" in out3


def test_a_full_up_prints_the_exact_tunnel_command_with_this_workstations_key_user_and_port(tmp_path):
    """Operatorul trebuie să primească o comandă de tunel pe care o poate lipi: cu adresa containerului raportată de gazdă, cu cheia, portul
    și contul PE CARE le-a dat lansatorului (nu un șablon cu <utilizator>)."""
    w = World(tmp_path)
    try:
        rc, out, log = run_launcher(w, "up", "--version", "3.0.1")
        assert rc == 0, out
        key = posix(w.tmp / "k")
        assert f"ssh -N -L 5679:172.30.0.2:5678 -p 2222 -i '{key}' dragos@n8n.example.invalid" in out, out
        assert "http://localhost:5679/" in out
    finally:
        w.close()


@pytest.mark.parametrize("scenario,expected_rc,needle", [
    ("egress", 5, "S-A VĂZUT IEȘIRE DIN CONTAINER"),
    ("prod_changed", 4, "PRODUCȚIA S-A SCHIMBAT (cod 4)"),
    ("unknown", 3, "NECUNOSCUT (cod 3)"),
])
def test_the_exit_code_of_the_host_script_reaches_the_operator_with_its_meaning(tmp_path, scenario, expected_rc, needle):
    """Codurile 3 («n-am putut măsura»), 4 («producția s-a schimbat») și 5 («ieșire din container») sunt cele care cer atenția operatorului;
    ele trebuie să ajungă ca atare prin ssh, cu o explicație, nu comprimate în 1."""
    w = World(tmp_path)
    try:
        if scenario == "egress":
            patch_state(w, probe_run={"tcp": True})
        elif scenario == "prod_changed":
            add_network(w, "n8n-staging-net", {LABEL: "1"})
            patch_state(w, mutate_prod_on="volume ls", mutate_prod="restart_count")
            rc, out, _ = run_launcher(w, "down")
            assert rc == expected_rc and needle in out, out
            return
        else:
            w.set_free("n/a")
        rc, out, _ = run_launcher(w, "up", "--version", "3.0.1")
        assert rc == expected_rc and needle in out, out
    finally:
        w.close()


def test_the_launcher_refuses_a_host_script_with_carriage_returns(w):
    """Un CR într-un .sh devine `bad interpreter: bash^M` pe gazdă (sau, într-un `bash -s`, comenzi cu un CR la coadă). Într-o copie a
    depozitului cu biblioteca scrisă CRLF, lansatorul refuză să trimită: ieșire 2, nicio conexiune."""
    from _n8n_staging_world import HOST_LIB
    repo = w.tmp / "repo"
    (repo / "scripts" / "lib").mkdir(parents=True)
    shutil.copy(LAUNCHER, repo / "scripts" / "n8n-staging.sh")
    crlf = HOST_LIB.read_bytes().replace(b"\n", b"\r\n")
    (repo / "scripts" / "lib" / "n8n-staging-host.sh").write_bytes(crlf)
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    write_exec(w.bin / "sudo", SUDO)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"))
    proc = subprocess.run([BASH, posix(repo / "scripts" / "n8n-staging.sh"), "--host", "h.example", "--key", posix(w.tmp / "k"), "status"],
                          capture_output=True, env=env, timeout=60)
    assert proc.returncode == 2 and "conține CR" in proc.stderr.decode("utf-8", "replace"), proc.stderr
    assert not (w.tmp / "ssh.log").exists()


# ----------------------------------------------------------------------------------------------------------------------
# runda 2: opțiuni fără valoare, praguri validate și trimise
# ----------------------------------------------------------------------------------------------------------------------

def run_raw(w: World, *args: str):
    """Lansatorul cu EXACT argumentele date (fără --host/--key adăugate), ca o opțiune să poată fi ultimul argument."""
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    write_exec(w.bin / "sudo", SUDO)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"), HOME=posix(w.tmp))
    proc = subprocess.run([BASH, posix(LAUNCHER), *args], capture_output=True, env=env, timeout=120)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    log = (w.tmp / "ssh.log").read_text(encoding="utf-8").splitlines() if (w.tmp / "ssh.log").exists() else []
    return proc.returncode, out, log


VALUE_LESS = [
    ["--host"], ["--host", "h.example", "--user"], ["--host", "h.example", "--key"], ["--host", "h.example", "--port"],
    ["--host", "h.example", "up", "--version"], ["--host", "h.example", "up", "--version", "3.0.1", "--health-timeout"],
    ["--host", "h.example", "up", "--version", "3.0.1", "--cpus"], ["--host", "h.example", "up", "--version", "3.0.1", "--memory"],
    ["--host", "h.example", "logs", "--tail"],
]


@pytest.mark.parametrize("args", VALUE_LESS, ids=[" ".join(a) for a in VALUE_LESS])
def test_an_option_given_as_the_last_argument_without_a_value_exits_2_with_a_message(w, args):
    """`--host` sau `--key` ca ultim argument făcea `shift 2` să cadă sub `set -e`: ieșire 1, FĂRĂ niciun mesaj, iar operatorul nu știa ce a greșit.
    Acum ieșire 2 și un mesaj care numește opțiunea, înainte de orice conexiune."""
    rc, out, log = run_raw(w, *args)
    assert rc == 2 and "cere o valoare" in out and args[-1] in out, (rc, out)
    assert log == []


def test_a_second_subcommand_is_refused(w):
    """`up --version 3.0.1 down` nu are voie să devină «down» pe tăcute: o singură subcomandă pe rulare."""
    rc, out, log = run_raw(w, "--host", "h.example", "up", "--version", "3.0.1", "down")
    assert rc == 2 and "o singură subcomandă" in out and log == [], out


THRESHOLD_BAD = [("--health-timeout", v) for v in ("59", "7201", "abc", "60;id", "-60", "1e3")] \
    + [("--cpus", v) for v in ("0", "0.24", "2.01", "3", "1.234", "1;id", "abc")] \
    + [("--memory", v) for v in ("100m", "511m", "7g", "6145m", "3", "3gb", "$(id)", "")]


@pytest.mark.parametrize("flag,bad", THRESHOLD_BAD, ids=[f"{f}={v or 'empty'}" for f, v in THRESHOLD_BAD])
def test_threshold_flags_are_validated_in_the_launcher_before_any_connection(w, flag, bad):
    """Pragurile trec prin ssh și ajung în aritmetică și în `docker create` pe gazdă: refuzate AICI, strict, înainte de orice conexiune (ieșire 2)."""
    rc, out, log = run_launcher(w, "up", "--version", "3.0.1", flag, bad)
    assert rc == 2 and log == [], (rc, out, log)
    assert w.docker_log() == []


def test_valid_threshold_flags_are_forwarded_as_separate_arguments(w):
    """`sudo` curăță mediul, deci `--health-timeout`, `--cpus` și `--memory` ajung pe gazdă DOAR ca argumente, în ordinea fixă, citate."""
    rc, out, log = run_launcher(w, "up", "--version", "3.0.9", "--memory", "2g", "--cpus", "0.5", "--health-timeout", "3600")
    assert log[-1] == "sudo -n bash -s -- up --version 3.0.9 --health-timeout 3600 --cpus 0.5 --memory 2g", log
    assert rc == 1                                       # 3.0.9 nu există în registrul momelii: se oprește la pull, nimic creat
