"""`scripts/compose-pin.sh` — lansatorul de pe stația operatorului.

`ssh` momeală EXECUTĂ de-adevărat comanda primită (un bash, cu stdin-ul lansatorului), iar `sudo` momeală doar sare peste `-n`: lanțul
complet lansator -> ssh -> `bash -s` -> biblioteca de pe gazdă -> docker momeală rulează pe codul livrat. De aceea un test de aici poate
arăta că biblioteca ajunge pe stdin întreagă, că planul precede scrierea și că scrierea e legată de suma din plan, nu doar că lansatorul
«a chemat ssh».

Ce NU dovedește: un ssh, un sudo sau o gazdă reale; doar șirul de comandă și ce primește scriptul de pe gazdă.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess

import pytest

from _compose_pin_world import COMPOSE, HOST_LIB, LAUNCHER, UMASK_PREFIX, World, sha
from _su_shell import BASH, posix, write_exec

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

SSH = """#!/usr/bin/env bash
cmd="${@: -1}"
printf '%s\\n' "$cmd" >> "$FAKE_SSH_LOG"
printf '%s\\n' "$*" >> "${FAKE_SSH_ARGV_LOG:-/dev/null}"
if [[ "$cmd" == "echo conectat" && -n "${FAKE_SSH_DOWN:-}" ]]; then exit 255; fi
if [[ "$cmd" == *"bash -s"* && -n "${FAKE_SSH_DROP:-}" ]]; then cat > /dev/null; exit 255; fi
tee -a "$FAKE_SSH_STDIN" 2>/dev/null | bash -c "$cmd"
rc="${PIPESTATUS[1]}"
if [[ "$cmd" == *"bash -s"* && -n "${FAKE_SSH_DROP_AFTER:-}" ]]; then exit 255; fi
if [[ "$cmd" == *--plan* && -n "${FAKE_MUTATE_AFTER_PLAN:-}" ]]; then printf '# adăugat între plan și scriere\\n' >> "$FAKE_MUTATE_AFTER_PLAN"; fi
exit "$rc"
"""
SUDO = """#!/usr/bin/env bash
[[ "${1:-}" == -n ]] && shift
exec "$@"
"""

TRAEFIK_PIN = "traefik=traefik:v3.8.0"


def run_launcher(w: World, *args: str, stdin: str = "", key: bool = True, host: bool = True, env_extra: dict | None = None, launcher=LAUNCHER):
    (w.tmp / "k").write_text("x", encoding="utf-8")
    write_exec(w.bin / "ssh", SSH)
    write_exec(w.bin / "sudo", SUDO)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_STDIN=posix(w.tmp / "ssh-stdin.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"),
                HOME=posix(w.tmp), **(env_extra or {}))
    base = (["--host", "n8n.example.invalid", "--user", "dragos", "--port", "2222"] if host else []) + (["--key", posix(w.tmp / "k")] if key else [])
    proc = subprocess.run([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", posix(launcher), *base, *args],
                          input=stdin.encode(), capture_output=True, env=env, timeout=300)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    log = (w.tmp / "ssh.log").read_text(encoding="utf-8").splitlines() if (w.tmp / "ssh.log").exists() else []
    return proc.returncode, out, log


def run_verbatim(w: World, line: str | list[str], *, stdin: str = "", env_extra: dict | None = None):
    """Rulează o comandă TIPĂRITĂ de lansator (o linie de sfat) EXACT cum a fost tipărită: se desparte ca de shell, `./scripts/compose-pin.sh` devine
    lansatorul, și NU se adaugă niciun argument de bază (gazdă, port, cheie, proiect trebuie să fie deja în ea)."""
    argv = list(line) if isinstance(line, list) else shlex.split(line.strip())
    assert argv[0] == "./scripts/compose-pin.sh", line
    argv = [re.sub(r"^C:/", "/c/", a) for a in argv[1:]]          # Windows: MSYS a scris calea copiei ca C:/..; gazda reală o scrie cum a primit-o
    write_exec(w.bin / "ssh", SSH)
    write_exec(w.bin / "sudo", SUDO)
    env = w.env(FAKE_SSH_LOG=posix(w.tmp / "ssh.log"), FAKE_SSH_STDIN=posix(w.tmp / "ssh-stdin.log"), FAKE_SSH_ARGV_LOG=posix(w.tmp / "ssh-argv.log"),
                HOME=posix(w.tmp), **(env_extra or {}))
    proc = subprocess.run([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", posix(LAUNCHER), *argv], input=stdin.encode(), capture_output=True, env=env, timeout=300)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    return proc.returncode, out


def advice_lines(out: str, sub: str) -> list[str]:
    """Liniile de sfat tipărite pentru subcomanda `sub` (cele care conțin `./scripts/compose-pin.sh ... SUB ...`), fără prefixul de culoare."""
    lines = []
    for l in out.splitlines():
        i = l.find("./scripts/compose-pin.sh ")
        if i >= 0 and f" {sub} " in l[i:]:
            lines.append(l[i:])
    return lines


def remote_runs(log: list[str]) -> list[str]:
    return [l for l in log if "bash -s" in l]


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def pin_args(w: World, *pins: str, extra: tuple[str, ...] = ()) -> list[str]:
    args = ["pin", "--file", w.fpath]
    for p in pins:
        args += ["--pin", p]
    return args + list(extra)



BAD_ARGS = [
    ("no_subcommand", ["--file", "/srv/x.yml"], "lipsește subcomanda"),
    ("two_subcommands", ["show", "pin", "--file", "/srv/x.yml"], "o singură subcomandă"),
    ("no_file", ["show"], "--file este obligatoriu"),
    ("relative_file", ["show", "--file", "srv/x.yml"], "--file refuzat"),
    ("dotdot_file", ["show", "--file", "/srv/../etc/x.yml"], "--file refuzat"),
    ("space_file", ["show", "--file", "/srv/a b.yml"], "--file refuzat"),
    ("injection_file", ["show", "--file", "/srv/x.yml;id"], "--file refuzat"),
    ("trailing_slash_file", ["show", "--file", "/srv/"], "--file refuzat"),
    ("pin_without_pins", ["pin", "--file", "/srv/x.yml"], "cel puțin un --pin"),
    ("pin_without_equals", ["pin", "--file", "/srv/x.yml", "--pin", "traefik"], "SERVICIU=REF"),
    ("latest", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:latest"], "latest"),
    ("no_tag", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik"], "nici etichetă, nici digest"),
    ("empty_tag", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:"], "eticheta e goală"),
    ("empty_ref", ["pin", "--file", "/srv/x.yml", "--pin", "traefik="], "REF refuzat"),
    ("command_substitution_ref", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:$(id)"], "REF refuzat"),
    ("semicolon_ref", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:v3;reboot"], "REF refuzat"),
    ("short_digest", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik@sha256:abc"], "digestul"),
    ("bad_service", ["pin", "--file", "/srv/x.yml", "--pin", "tra efik=traefik:v3"], "nume de serviciu invalid"),
    ("duplicate_service", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:v3.8.0", "--pin", "traefik=traefik:v3.9.0"], "în două --pin"),
    ("show_with_pin", ["show", "--file", "/srv/x.yml", "--pin", "traefik=traefik:v3.8.0"], "doar pentru pin"),
    ("floating_stable", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:stable"], "FLOTANTĂ"),
    ("floating_major", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:v3"], "FLOTANTĂ"),
    ("floating_minor", ["pin", "--file", "/srv/x.yml", "--pin", "traefik=traefik:v3.8"], "FLOTANTĂ"),
    ("floating_variant", ["pin", "--file", "/srv/x.yml", "--pin", "postgres=postgres:16-alpine"], "FLOTANTĂ"),
    ("recreate_without_service", ["recreate", "--file", "/srv/x.yml"], "recreate cere --service"),
    ("recreate_bad_service", ["recreate", "--file", "/srv/x.yml", "--service", "tra efik"], "nume de serviciu invalid"),
    ("recreate_duplicate_service", ["recreate", "--file", "/srv/x.yml", "--service", "a,b,a"], "de două ori"),
    ("service_on_pin", ["pin", "--file", "/srv/x.yml", "--pin", "t=t:1.0.0", "--service", "t"], "doar pentru recreate"),
    ("force_on_pin", ["pin", "--file", "/srv/x.yml", "--pin", "t=t:1.0.0", "--force"], "doar pentru restore"),
    ("backup_elsewhere", ["restore", "--file", "/srv/x.yml", "--backup", "/etc/passwd"], "--backup refuzat"),
    ("backup_sums_file", ["restore", "--file", "/srv/x.yml", "--backup", "/srv/x.yml.pin-bak-2026.sums"], "--backup refuzat"),
    ("show_with_yes", ["show", "--file", "/srv/x.yml", "--yes"], "show nu primește"),
    ("bad_project", ["show", "--file", "/srv/x.yml", "--project", "Bad Name"], "--project refuzat"),
    ("unknown_arg", ["show", "--file", "/srv/x.yml", "--wat"], "argument necunoscut"),
    ("file_without_value", ["show", "--file"], "cere o valoare"),
]


@pytest.mark.parametrize("name,args,why", BAD_ARGS, ids=[b[0] for b in BAD_ARGS])
def test_bad_arguments_exit_2_before_any_connection(w, name, args, why):
    """Un argument greșit trebuie să iasă cu 2, cu motiv, înainte de ssh: un `latest` sau un `$(id)` care ar ajunge pe gazdă ar fi, în cel
    mai bun caz, un pin fals, în cel mai rău, o comandă."""
    rc, out, log = run_launcher(w, *args)
    assert rc == 2, out
    assert why in out, out
    assert log == [], "a deschis ssh cu un argument invalid"


@pytest.mark.parametrize("opts,why", [(["--host", "-oProxyCommand=x"], "--host refuzat"), (["--user", "Root;id"], "--user refuzat"),
                                      (["--port", "0"], "1-65535"), (["--port", "70000"], "1-65535"), (["--port", "abc"], "--port cere un număr")])
def test_connection_options_are_validated(w, opts, why):
    """Un `--host` care începe cu `-` devine o opțiune ssh (ProxyCommand = execuție locală); un utilizator sau un port nevalid nu
    trebuie să ajungă în comanda ssh."""
    rc, out, log = run_launcher(w, "show", "--file", "/srv/x.yml", *opts, host=True)
    assert rc == 2 and why in out and log == []


def test_missing_host_and_missing_key_file_exit_2(w):
    """Fără --host nu există gazdă; o cheie care nu există nu trebuie să cadă pe «ssh va alege o identitate»."""
    rc, out, log = run_launcher(w, "show", "--file", "/srv/x.yml", host=False)
    assert rc == 2 and "--host este obligatoriu" in out
    rc, out, log = run_launcher(w, "show", "--file", "/srv/x.yml", "--key", posix(w.tmp / "nu-exista"), key=False)
    assert rc == 2 and "cheia ssh nu există" in out and log == []


def test_host_library_arrives_whole_on_stdin_and_arguments_are_quoted(w):
    """Octeții care rulează pe gazdă trebuie să fie cei din depozit (nimic lăsat pe gazdă, nimic trunchiat), iar argumentele trec prin
    `printf %q`."""
    rc, out, log = run_launcher(w, "show", "--file", w.fpath)
    assert rc == 0, out
    runs = remote_runs(log)
    assert len(runs) == 1 and runs[0].startswith("sudo -n bash -s -- show --file ")
    assert sha((w.tmp / "ssh-stdin.log").read_bytes()) == sha(HOST_LIB.read_bytes())
    assert "3 servicii" in out and "cod 0" in out


def test_library_with_carriage_returns_is_refused(w, tmp_path):
    """Un CR într-un .sh devine `bad interpreter: bash^M` pe gazdă; lansatorul trebuie să-l refuze pe octeți, aici, înainte de ssh."""
    root = tmp_path / "copy"
    (root / "scripts" / "lib").mkdir(parents=True)
    shutil.copy(LAUNCHER, root / "scripts" / "compose-pin.sh")
    (root / "scripts" / "lib" / "compose-pin-host.sh").write_bytes(HOST_LIB.read_bytes().replace(b"\n", b"\r\n"))
    rc, out, log = run_launcher(w, "show", "--file", "/srv/x.yml", launcher=root / "scripts" / "compose-pin.sh")
    assert rc == 2 and "conține CR" in out and log == []


def test_yes_skips_the_prompt_and_writes_directly(w):
    """--yes e pentru rulări automate: o singură trecere pe gazdă, fără plan și fără întrebare."""
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN, extra=("--yes",)))
    assert rc == 0, out
    runs = remote_runs(log)
    assert len(runs) == 1 and "--plan" not in runs[0] and "--expect-sha256" not in runs[0]
    assert "--pin traefik=traefik:v3.8.0" in runs[0]
    assert b'image: "traefik:v3.8.0"' in w.original
    assert "Continui" not in out


def test_confirmation_runs_a_plan_then_writes_bound_to_the_planned_sum(w):
    """Fără --yes, operatorul vede diff-ul ÎNAINTE să spună «da», iar scrierea e legată de suma fișierului din plan: planul nu scrie, iar
    scrierea vine abia după «da»."""
    original = w.original
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN), stdin="da\n")
    assert rc == 0, out
    runs = remote_runs(log)
    assert len(runs) == 2 and "--plan" in runs[0] and "--plan" not in runs[1]
    assert f"--expect-sha256 {sha(original)}" in runs[1]
    assert out.index("plan: nimic nu s-a scris") < out.index("scris atomic")
    assert "NU se recreează niciun container acum" in out
    assert b'image: "traefik:v3.8.0"' in w.original and len(w.backups()) == 1


@pytest.mark.parametrize("answer", ["", "nu\n", "DA\n", "y\n", "daa\n"])
def test_anything_but_exactly_da_cancels_with_nothing_changed(w, answer):
    """Un Enter, «DA», «y» sau «daa» nu sunt «da» (spațiile de la capete le taie `read`, ca la system-update.sh): scrierea unui fișier de producție cere cuvântul exact. Se anulează cu 1, iar pe gazdă nu
    s-a rulat decât planul (nimic scris, nicio copie)."""
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN), stdin=answer)
    assert rc == 1, out
    assert "anulat" in out
    assert len(remote_runs(log)) == 1 and "--plan" in remote_runs(log)[0]
    assert w.original == COMPOSE.encode() and w.backups() == []


def test_refused_plan_never_asks_for_confirmation(w):
    """Dacă planul e refuzat (aici, eticheta nu e imaginea care rulează), a cere «da» ar fi o întrebare fără obiect; ieșirea e a gazdei."""
    rc, out, log = run_launcher(w, *pin_args(w, "traefik=traefik:v3.9.0"), stdin="da\n")
    assert rc == 1, out
    assert "NU este imaginea care rulează" in out and "Continui" not in out
    assert len(remote_runs(log)) == 1 and w.original == COMPOSE.encode()


def test_file_changed_between_plan_and_confirmation_is_refused_by_the_host(w):
    """Între «am văzut diff-ul» și «da» fișierul se schimbă: fără suma legată de plan, «da»-ul ar acoperi o modificare nevăzută."""
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN), stdin="da\n", env_extra={"FAKE_MUTATE_AFTER_PLAN": posix(w.file)})
    assert rc == 1, out
    assert "de când l-ai văzut" in out
    assert b'image: "traefik"' in w.original and b"traefik:v3.8.0" not in w.original and w.backups() == []


def test_nothing_to_do_does_not_prompt(w):
    """Un pin deja scris nu are ce confirma: fără întrebare, ieșire 0."""
    assert run_launcher(w, *pin_args(w, TRAEFIK_PIN, extra=("--yes",)))[0] == 0
    before = w.original
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN), stdin="")
    assert rc == 0, out
    assert "nimic de făcut" in out and "Continui" not in out and len(remote_runs(log)) == 2
    assert w.original == before


def test_host_exit_codes_are_passed_through_with_their_meaning(w):
    """3 («necunoscut») și 4 («producția s-a schimbat») nu sunt «bine» și nu sunt «refuzat»: lansatorul trebuie să le păstreze și să le
    numească, nu să le turtească în 1."""
    w.load()
    del w.state["containers"]["root-traefik-1"]
    w.save()
    rc, out, _ = run_launcher(w, *pin_args(w, TRAEFIK_PIN, extra=("--yes",)))
    assert rc == 3 and "NECUNOSCUT (cod 3)" in out
    w2 = World(w.tmp / "second")
    w2.add_hook(on="config-json:2", action="container", name="root-n8n-1", field="restart")
    rc, out, _ = run_launcher(w2, *pin_args(w2, TRAEFIK_PIN, extra=("--yes",)))
    assert rc == 4 and "UN CONTAINER AL PROIECTULUI S-A SCHIMBAT (cod 4)" in out


def test_unreachable_host_and_dropped_session(w):
    """Gazda care nu răspunde iese cu 1, înainte de a trimite ceva; un ssh căzut în timpul rulării iese cu 255 și spune cum să afle
    starea (`show`), fiindcă fișierul poate fi editat sau nu."""
    rc, out, log = run_launcher(w, "show", "--file", w.fpath, env_extra={"FAKE_SSH_DOWN": "1"})
    assert rc == 1 and "nu pot ajunge la" in out and remote_runs(log) == []
    rc, out, log = run_launcher(w, *pin_args(w, TRAEFIK_PIN, extra=("--yes",)), env_extra={"FAKE_SSH_DROP": "1"})
    assert rc == 255 and "ssh a căzut" in out and "show --file" in out
