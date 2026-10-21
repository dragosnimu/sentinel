"""`install_vps_watchdog` din `deploy/install.sh` - FUNCTIA LIVRATA, cu `install` si
`systemctl` inlocuite de fals-uri pe PATH.

Watchdog-ul de gazda reporneste containere ca root si trimite sub numele botului
Sentinel. Trait pana acum doar pe gazda, copiat de mana. Instalatorul trebuie sa
il aduca sub revizie FARA sa schimbe vreo gazda care n-a cerut-o si FARA sa
inlocuiasca in tacere o instalare existenta cu una care nu mai verifica
domeniile clientilor.

Ce simuleaza si ce NU are mediul asta:

  * `install` e un fals care copie (fara -o/-g: nu exista `root` aici), deci
    proprietarul si modurile reale nu se dovedesc; se verifica doar ce argumente
    primeste.
  * `systemctl` e un fals care raspunde din variabile de mediu. NU se dovedeste ca
    systemd real incarca unitatea sau ca timerul chiar porneste: asta se vede doar
    pe gazda (`systemctl show vps-watchdog.timer`).
  * Prima RULARE a serviciului nu se poate dovedi la instalare (timerul o porneste
    peste un minut); instalatorul o spune, nu o presupune.
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
SRC_DIR = REPO / "deploy" / "vps-watchdog"

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipseste din PATH")]

OLD_SCRIPT = b"#!/usr/bin/env bash\n# copia veche, scrisa de mana pe gazda\n"


def _func(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", INSTALL, re.S | re.M)
    assert match, f"functia {name} nu mai exista in deploy/install.sh"
    return match.group(0)


def _defaults() -> str:
    lines = re.findall(r"^VPS_WATCHDOG_(?:DIR|UNIT_DIR)=.*$", INSTALL, re.M)
    assert len(lines) == 2, lines
    return "\n".join(lines) + "\n"


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class Env:
    def __init__(self, root: Path, *, with_conf: bool, package: Path | None = None):
        self.root = root
        self.bin = root / "bin"
        self.calls = root / "calls.log"
        self.dir = root / "opt-vps-watchdog"
        self.udir = root / "units"
        self.conf = root / "vps-watchdog.conf"
        self.udir.mkdir(parents=True)
        # SCRIPT_DIR = un "deploy/" cu vps-watchdog/ copiat din cel real.
        self.script_dir = root / "deploy"
        self.script_dir.mkdir()
        shutil.copytree(package or SRC_DIR, self.script_dir / "vps-watchdog")
        if with_conf:
            self.conf.write_text('HEALTH_DOMAINS="app.example.org"\n', encoding="utf-8")
        _stub(self.bin, "install",
              'echo "install $*" >> "$CALLS"\n'
              'if [ "$1" = "-d" ]; then mkdir -p "${@: -1}"; exit 0; fi\n'
              '[ -n "${FAKE_INSTALL_NOOP:-}" ] && exit 0\n'
              'cp "${@: -2:1}" "${@: -1}"\n')
        _stub(self.bin, "systemctl",
              'echo "systemctl $*" >> "$CALLS"\n'
              'case "$1" in\n'
              '  show) echo "${FAKE_NEED_RELOAD:-no}" ;;\n'
              '  is-enabled) echo "${FAKE_ENABLED:-enabled}"; [ "${FAKE_ENABLED:-enabled}" = enabled ] ;;\n'
              '  is-active) echo "${FAKE_ACTIVE:-active}"; [ "${FAKE_ACTIVE:-active}" = active ] ;;\n'
              '  restart) exit "${FAKE_RESTART_RC:-0}" ;;\n'
              '  *) exit 0 ;;\n'
              'esac\n')

    def run(self, **env_extra):
        script = self.root / "run.sh"
        script.write_text(
            "set -euo pipefail\n"
            f'SCRIPT_DIR="{self.script_dir.as_posix()}"\n'
            f'source "{(REPO / "deploy" / "lib" / "common.sh").as_posix()}"\n'
            + _defaults() + _func("install_vps_watchdog") + "\n"
            "install_vps_watchdog\n",
            encoding="utf-8", newline="\n")
        env = {**os.environ, "NO_COLOR": "1",
               "CALLS": self.calls.as_posix(),
               "VPS_WATCHDOG_DIR": self.dir.as_posix(),
               "VPS_WATCHDOG_UNIT_DIR": self.udir.as_posix(),
               "VPS_WATCHDOG_CONF": self.conf.as_posix(),
               "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        env.update(env_extra)
        proc = subprocess.run([BASH, script.as_posix()], cwd=str(REPO / "deploy"),
                              capture_output=True, env=env, timeout=120)
        self.stdout = proc.stdout.decode("utf-8", errors="replace")
        self.stderr = proc.stderr.decode("utf-8", errors="replace")
        self.rc = proc.returncode
        self.log = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        return self


def _bytes(p: Path) -> bytes:
    return p.read_bytes()


def test_a_host_that_did_not_opt_in_is_not_touched(tmp_path):
    """Watchdog-ul reporneste containere. Instalat pe fiecare gazda, ar schimba
    una pe care nimeni n-a cerut-o (a doua gazda Sentinel are n8n in docker).
    Fara conf nu se instaleaza, nu se copie nimic, nu se atinge systemd."""
    e = Env(tmp_path, with_conf=False).run()
    assert e.rc == 0, e.stdout + e.stderr
    assert e.log == "", f"s-a atins ceva fara conf: {e.log}"
    assert not e.dir.exists() and not list(e.udir.iterdir())
    assert "not installed" in e.stdout and "vps-watchdog.conf" in e.stdout


def test_an_existing_hand_copied_install_is_left_alone_without_the_conf(tmp_path):
    """Pe gazda de productie ruleaza deja copia scrisa de mana, cu domeniile
    clientilor in ea. Daca instalatorul ar pune peste ea versiunea din depozit,
    FARA conf, verificarile de domeniu ar disparea in tacere sub un instalator
    verde ("necunoscut" devenit "bine"). Copia veche ramane, iar operatorul afla
    de ce."""
    e = Env(tmp_path, with_conf=False)
    e.dir.mkdir()
    (e.dir / "watchdog.sh").write_bytes(OLD_SCRIPT)
    e.run()
    assert e.rc == 0, e.stdout + e.stderr
    assert _bytes(e.dir / "watchdog.sh") == OLD_SCRIPT, "copia veche a fost inlocuita"
    assert e.log == ""
    assert "unreviewed" in e.stderr and "vps-watchdog.conf" in e.stderr


def test_with_the_conf_present_the_repository_files_are_installed_and_the_timer_restarted(tmp_path):
    """Efectul, nu intentia: fisierele de pe disc sunt octet cu octet cele din
    depozit, modurile ceruta sunt 0755/0644, systemd a fost rugat sa reciteasca
    unitatile INAINTE de pornire, iar timerul e repornit (nu `enable --now`, care
    pe un timer deja activ nu face nimic)."""
    e = Env(tmp_path, with_conf=True).run()
    assert e.rc == 0, e.stdout + e.stderr
    assert _bytes(e.dir / "watchdog.sh") == _bytes(SRC_DIR / "watchdog.sh")
    assert _bytes(e.udir / "vps-watchdog.service") == _bytes(SRC_DIR / "vps-watchdog.service")
    assert _bytes(e.udir / "vps-watchdog.timer") == _bytes(SRC_DIR / "vps-watchdog.timer")
    assert re.search(r"install -m 0755 .*watchdog\.sh ", e.log)
    assert len(re.findall(r"install -m 0644 ", e.log)) == 2
    lines = e.log.splitlines()
    idx = {k: next(i for i, l in enumerate(lines) if l.startswith(k)) for k in
           ("systemctl daemon-reload", "systemctl restart vps-watchdog.timer")}
    assert idx["systemctl daemon-reload"] < idx["systemctl restart vps-watchdog.timer"]
    assert "systemctl enable vps-watchdog.timer" in e.log
    assert "[+] vps-watchdog:" in e.stdout and e.stderr == ""
    assert "proof it ran" in e.stdout  # nu pretinde ca a dovedit o rulare


def test_an_install_that_wrote_nothing_is_not_reported_as_done(tmp_path):
    """`install` poate iesi cu 0 si totusi lasa o copie veche (disc plin gestionat
    prost, mount in citire). Instalatorul compara fisierele cu depozitul, nu se
    increde in codul de iesire: o copie veche ramasa e raportata, nu "instalata"."""
    e = Env(tmp_path, with_conf=True)
    e.dir.mkdir()
    (e.dir / "watchdog.sh").write_bytes(OLD_SCRIPT)
    e.run(FAKE_INSTALL_NOOP="1")
    assert "is not the repository's file" in e.stderr, e.stderr
    assert "[+] vps-watchdog:" not in e.stdout


def test_a_unit_systemd_has_not_reloaded_is_not_reported_as_done(tmp_path):
    """`daemon-reload` iesind cu 0 nu dovedeste ca systemd tine unitatea de pe
    disc. NeedDaemonReload=yes inseamna ca ruleaza inca o versiune veche - de
    exemplu fara TimeoutStartSec, cu un oneshot care se poate agata pentru
    totdeauna."""
    e = Env(tmp_path, with_conf=True).run(FAKE_NEED_RELOAD="yes")
    assert "NeedDaemonReload='yes'" in e.stderr, e.stderr
    assert "[+] vps-watchdog:" not in e.stdout


@pytest.mark.parametrize("var,value,needle", [
    ("FAKE_ACTIVE", "inactive", "is 'inactive', not active"),
    ("FAKE_ENABLED", "disabled", "is 'disabled', not enabled"),
    ("FAKE_RESTART_RC", "1", "restart vps-watchdog.timer failed"),
])
def test_a_timer_that_is_not_running_is_not_reported_as_done(tmp_path, var, value, needle):
    """Un timer instalat dar oprit e un watchdog care nu mai ruleaza, sub un
    instalator verde. Starea se CITESTE inapoi de la systemd, nu se deduce din
    faptul ca `enable` a fost chemat."""
    e = Env(tmp_path, with_conf=True).run(**{var: value})
    assert needle in e.stderr, e.stderr
    assert "[+] vps-watchdog:" not in e.stdout


def test_a_script_that_does_not_parse_never_replaces_the_working_one(tmp_path):
    """Un `if` neinchis pus peste copia care merge ar produce un watchdog care
    moare la prima linie - iar singurul simptom e tacerea. `bash -n` inainte de
    orice copie; copia veche ramane."""
    broken = tmp_path / "pkg"
    shutil.copytree(SRC_DIR, broken)
    (broken / "watchdog.sh").write_text("#!/usr/bin/env bash\nif true; then\n",
                                        encoding="utf-8", newline="\n")
    root = tmp_path / "root"
    root.mkdir()
    e = Env(root, with_conf=True, package=broken)
    e.dir.mkdir()
    (e.dir / "watchdog.sh").write_bytes(OLD_SCRIPT)
    e.run()
    assert "does not parse" in e.stderr, e.stderr
    assert _bytes(e.dir / "watchdog.sh") == OLD_SCRIPT
    assert "install " not in e.log and "restart" not in e.log


def test_a_package_missing_a_file_changes_nothing(tmp_path):
    """Un pachet fara timer ar instala scriptul si serviciul fara cine sa le
    porneasca. Fie toate trei, fie nimic."""
    partial = tmp_path / "pkg"
    shutil.copytree(SRC_DIR, partial)
    (partial / "vps-watchdog.timer").unlink()
    root = tmp_path / "root"
    root.mkdir()
    e = Env(root, with_conf=True, package=partial).run()
    assert "is not in this package" in e.stderr, e.stderr
    assert e.log == "" and not e.dir.exists()


def test_the_installer_calls_it_from_the_always_running_auxiliary_step():
    """O functie neapelata e acelasi lucru cu un fisier nescris. Pasul 37
    (`auxiliary`) ruleaza la FIECARE deploy; unul marcat o data (ca 19) nu ar mai
    ajunge niciodata pe o gazda care isi creeaza conf-ul mai tarziu."""
    body = _func("step_auxiliary")
    assert re.search(r"^\s*install_vps_watchdog\s*$", body, re.M), body
    always = re.search(r'^ALWAYS_STEPS="([^"]*)"',
                       (REPO / "deploy" / "lib" / "common.sh").read_text(encoding="utf-8"), re.M)
    assert "auxiliary" in always.group(1).split()


def test_the_units_are_not_in_the_directory_the_installer_globs_for_every_host():
    """`step_systemd` instaleaza TOT din deploy/systemd/*.service pe FIECARE gazda
    si `scripts/smoke-test.sh` / test_systemd_hardening.py presupun ca fiecare e un
    serviciu `sentinel`. Unitatea de aici ruleaza ca root si reporneste containere:
    pusa acolo, ar ajunge si pe gazdele care n-au cerut-o."""
    assert not list((REPO / "deploy" / "systemd").glob("vps-watchdog*")), \
        "vps-watchdog.* a ajuns in deploy/systemd/ - se instaleaza pe orice gazda"
