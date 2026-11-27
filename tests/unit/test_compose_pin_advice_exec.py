"""Comenzile TIPĂRITE de lansator, EXECUTATE întocmai prin lansator, în lumea momeală.

De ce există: de trei ori o linie de sfat a căzut când rulată ca atare (un pin flotant «recreate-abil» care nu era; un rollback după un refuz; o comandă fără
`--project`, deși proiectul fusese dat și autodetectarea alege altul). Fiecare avea testul ei punctual, deci a patra variantă a aceleiași proprietăți trecea. Aici
proprietatea e testată ca atare: se ia fiecare linie tipărită (recreate, show, restore, re-pin), se desparte ca de shell și se rulează FĂRĂ niciun argument adăugat,
iar rezultatul trebuie să fie ce promite sfatul. Cazurile includ un proiect pe care autodetectarea îl alege greșit (containere pornite din alte fișiere compose)
și o conexiune cu port și cheie nestandard (cu spațiu în calea cheii).

Ce NU dovedește: un ssh, un sudo sau o gazdă reale.
"""

from __future__ import annotations

import shlex
import shutil

import pytest

from _compose_pin_world import COMPOSE, TRAEFIK_ID, World, sha
from _su_shell import write_exec
from test_compose_pin_launcher import advice_lines, run_launcher, run_verbatim

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

TRAEFIK_PIN = "traefik=traefik:v3.8.0"


def two_file_project(tmp_path) -> World:
    """Un proiect `root` pornit din DOUĂ fișiere compose: eticheta `config_files` a containerelor nu e acest fișier, deci autodetectarea după fișier nu găsește
    niciun proiect (și cade pe numele directorului). Singura cale spre proiectul corect e `--project root`."""
    w = World(tmp_path)
    w.load()
    for c in w.state["containers"].values():
        c["labels"]["com.docker.compose.project.config_files"] = "/etc/base.yml,/etc/override.yml"
    w.save()
    return w


def pin_with_project(w: World, *extra: str, pin: str = TRAEFIK_PIN, **kw):
    return run_launcher(w, "pin", "--file", w.fpath, "--project", "root", "--pin", pin, "--yes", *extra, **kw)


def ssh_argv(w: World) -> list[str]:
    p = w.tmp / "ssh-argv.log"
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


def test_the_scenario_is_not_vacuous_autodetect_really_picks_the_wrong_project(tmp_path):
    """Fără --project, pe acest proiect, comanda cade (cod 3): altfel testele de mai jos n-ar dovedi nimic despre --project."""
    w = two_file_project(tmp_path)
    rc, out, _ = run_launcher(w, "show", "--file", w.fpath)
    assert rc == 3 and "niciun container nu a fost creat din" in out, out
    rc, out, _ = run_launcher(w, "show", "--file", w.fpath, "--project", "root")
    assert rc == 0, out


def test_every_advised_command_runs_verbatim_and_does_what_it_claims_with_an_explicit_project(tmp_path):
    """Sfaturile după `pin --project root`: `recreate` (pasul următor), `show` (după un ssh căzut) și `restore` (rollback după un up care a pornit și a picat) sunt
    rulate ca atare. Fiecare trebuie să poarte --project root și conexiunea (host, cont, port, cheie), iar efectul să fie cel promis."""
    w = two_file_project(tmp_path)
    rc, out, _ = pin_with_project(w)
    assert rc == 0, out
    original = COMPOSE.encode()
    # `show`, din mesajul de ssh căzut (înainte de up): rulat ca atare, vede drift-ul
    rc, drop_out, _ = run_launcher(w, "recreate", "--file", w.fpath, "--project", "root", "--service", "traefik", "--yes", env_extra={"FAKE_SSH_DROP": "1"})
    assert rc == 255, drop_out
    show_line = advice_lines(drop_out, "show")[0]
    for part in ("--host n8n.example.invalid", "--user dragos", "--port 2222", "--key", "--project root", f"--file {w.fpath}"):
        assert part in show_line, show_line
    rc, shown = run_verbatim(w, show_line)
    assert rc == 0 and "config-hash : DRIFT" in shown, shown
    # `recreate`, din pasul următor al pin-ului: rulat ca atare (cu «da»), recreează și închide drift-ul
    recreate_line = advice_lines(out, "recreate")[0]
    assert "--project root" in recreate_line and "--service traefik" in recreate_line, recreate_line
    old_id = w.container("root-traefik-1")["id"]
    rc, done = run_verbatim(w, recreate_line, stdin="da\n")
    assert rc == 0 and "DOVEDIT: traefik" in done, done
    assert w.container("root-traefik-1")["id"] != old_id
    rc, after = run_verbatim(w, show_line)
    assert rc == 0 and "config-hash : la zi" in after.split("traefik: ")[1].split("\n[")[0], after
    # conexiunea din linii a ajuns în ssh: portul și cheia nestandard
    assert any("-p 2222" in a and "-i " in a and "/k " in a + " " for a in ssh_argv(w)), ssh_argv(w)[-3:]
    # `restore` din rollback-ul unui up care a pornit și a picat (alt pin, pe aceeași gazdă)
    w2 = two_file_project(tmp_path / "w2")
    assert pin_with_project(w2)[0] == 0
    w2.patch(up_stale_label=True)
    rc, bad = run_launcher(w2, "recreate", "--file", w2.fpath, "--project", "root", "--service", "traefik", "--yes")[:2]
    assert rc == 1 and "ROLLBACK (nu se face singur" in bad, bad
    restore_line = advice_lines(bad, "restore")[0]
    assert "--project root" in restore_line, restore_line
    rc, restored = run_verbatim(w2, restore_line, stdin="da\n")
    assert rc == 0 and w2.original == original and "restaurat și DOVEDIT" in restored, restored


def test_without_the_project_the_same_advice_would_fail(tmp_path):
    """Contrapartida: aceleași linii FĂRĂ --project cad (cod 3): dovedește că prezența lui în sfat e ce le face să meargă, nu o coincidență."""
    w = two_file_project(tmp_path)
    rc, out, _ = pin_with_project(w)
    line = advice_lines(out, "recreate")[0]
    assert " --project root" in line
    rc, failed = run_verbatim(w, line.replace(" --project root", ""), stdin="da\n")
    assert rc == 3, failed


def test_floating_pin_alternatives_are_commands_that_run_verbatim(tmp_path):
    """Un pin flotant nu are un pas următor, dar are DOUĂ alternative tipărite ca comenzi: re-fixarea (se completează doar versiunea) și restore cu copia exactă.
    Ambele, rulate ca atare cu --project, fac ce spun."""
    original = COMPOSE.encode()
    w = two_file_project(tmp_path / "a")
    w.load()
    w.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w.save()
    rc, out, _ = pin_with_project(w, "--allow-floating-tag", pin="traefik=traefik:v3.8")
    assert rc == 0 and "NU EXISTĂ O COMANDĂ DE RULAT" in out, out
    repin = advice_lines(out, "pin")[0]
    toks = shlex.split(repin)
    assert any("<MAJOR.MINOR.PATCH>" in x for x in toks) and "--project" in toks and toks[toks.index("--project") + 1] == "root", repin
    argv_line = [x.replace("<MAJOR.MINOR.PATCH>", "v3.8.0") for x in toks]
    rc, fixed = run_verbatim(w, argv_line, stdin="da\n")
    assert rc == 0 and 'image: "traefik:v3.8.0"' in w.original.decode(), fixed
    assert "COMPOSE_PIN_NEXT=recreate traefik" in fixed, "după re-fixare, pasul următor devine `recreate`"
    # alternativa 2 pe o lume proaspătă: restore cu --backup, ca atare
    w2 = two_file_project(tmp_path / "b")
    w2.load()
    w2.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w2.save()
    rc, out2, _ = pin_with_project(w2, "--allow-floating-tag", pin="traefik=traefik:v3.8")
    restore = advice_lines(out2, "restore")[0]
    assert "--backup" in restore and "--project root" in restore
    rc, back = run_verbatim(w2, restore, stdin="da\n")
    assert rc == 0 and w2.original == original, back


def test_advice_carries_a_key_path_with_a_space_and_a_non_default_port(tmp_path):
    """Cheia cu spațiu în cale și portul nestandard trebuie să supraviețuiască citării: linia, desfăcută ca de shell, ajunge în ssh cu aceeași cheie și același port."""
    w = two_file_project(tmp_path)
    key_dir = w.tmp / "my keys"
    key_dir.mkdir()
    (key_dir / "id k").write_text("x", encoding="utf-8")
    key = (key_dir / "id k").as_posix()
    rc, out, _ = run_launcher(w, "pin", "--file", w.fpath, "--project", "root", "--pin", TRAEFIK_PIN, "--yes", "--key", key, key=False)
    assert rc == 0, out
    line = advice_lines(out, "recreate")[0]
    tokens = shlex.split(line)
    assert tokens[tokens.index("--key") + 1] == key and tokens[tokens.index("--port") + 1] == "2222", line
    rc, done = run_verbatim(w, line, stdin="da\n")
    assert rc == 0, done
    argv = ssh_argv(w)[-1]
    norm = lambda s: s.replace("C:/", "/c/")          # Windows: calea cheii apare ca C:/.. (test) sau /c/.. (după conversia MSYS); aceeași cale
    assert f"-i {norm(key)}" in norm(argv) and "-p 2222" in argv, argv


def test_system_update_advice_carries_the_connection_but_not_a_compose_file(tmp_path):
    """Pentru o versiune nouă, comanda system-update ia gazda, contul, portul și cheia (nu un fișier compose); proiectul e argumentul lui --accept-drift."""
    w = two_file_project(tmp_path)
    w.load()
    w.state["known_pulls"]["docker.n8n.io/n8nio/n8n:2.49.7"] = "sha256:" + "17" * 32
    w.save()
    rc, out, _ = run_launcher(w, "pin", "--file", w.fpath, "--project", "root", "--pin", "n8n=docker.n8n.io/n8nio/n8n:2.49.7", "--allow-version-change", "--yes")
    assert rc == 0, out
    lines = [l[l.find("./scripts/system-update.sh"):] for l in out.splitlines() if "./scripts/system-update.sh" in l]
    assert lines, out
    for l in lines:
        toks = shlex.split(l)
        assert "--host" in toks and "--user" in toks and "--port" in toks and "--key" in toks and "--file" not in toks, l
        assert toks[toks.index("--accept-drift") + 1] == "root", l
