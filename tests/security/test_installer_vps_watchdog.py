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
    """Caile si semnatura traiesc in lib/common.sh (impartite cu rollback.sh); harness-ul
    face `source common.sh`, deci doar se verifica ca sunt acolo si NU in install.sh."""
    common = (REPO / "deploy" / "lib" / "common.sh").read_text(encoding="utf-8")
    names = re.findall(r"^VPS_WATCHDOG_(DIR|UNIT_DIR|MARKER)=", common, re.M)
    assert sorted(names) == ["DIR", "MARKER", "UNIT_DIR"], names
    assert not re.search(r"^VPS_WATCHDOG_(?:DIR|UNIT_DIR|MARKER)=", INSTALL, re.M), \
        "install.sh isi defineste propriile cai: rollback.sh si el ar putea diverge"
    return ""


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


def test_the_install_signs_what_it_put_on_the_host_and_only_then(tmp_path):
    """`rollback.sh` scoate watchdog-ul DOAR daca exista semnatura instalatorului: pe
    productie ruleaza de saptamani o copie facuta de mana, iar un rollback automat
    (install.sh il porneste singur cand o poarta de sanatate pica) care ar scoate-o
    dupa nume ar sterge un serviciu pe care deploy-ul nu l-a atins. Semnatura apare
    cand instalatorul a copiat fisierele - nu pe o gazda care n-a cerut instalarea,
    nu cand scriptul nu trece `bash -n`."""
    signed = Env(tmp_path / "signed", with_conf=True).run()
    marker = signed.dir / ".installed-by-sentinel"
    assert marker.is_file(), signed.stdout + signed.stderr
    assert marker.read_text(encoding="utf-8").startswith("installed by deploy/install.sh at ")

    not_opted_in = Env(tmp_path / "optout", with_conf=False).run()
    assert not (not_opted_in.dir / ".installed-by-sentinel").exists()

    broken = tmp_path / "pkg"
    shutil.copytree(SRC_DIR, broken)
    (broken / "watchdog.sh").write_text("#!/usr/bin/env bash\nif true; then\n",
                                        encoding="utf-8", newline="\n")
    bad = Env(tmp_path / "broken", with_conf=True, package=broken).run()
    assert "does not parse" in bad.stderr
    assert not (bad.dir / ".installed-by-sentinel").exists()


def test_a_signature_that_cannot_be_written_is_reported_not_swallowed(tmp_path):
    """Fara semnatura, rollback-ul nu mai scoate nimic: instalatorul ar spune "gata"
    si, la prima revenire, watchdog-ul (care reporneste containere) ar ramane. Se
    raporteaza, nu se trece cu vederea."""
    e = Env(tmp_path, with_conf=True)
    (e.dir / ".installed-by-sentinel").mkdir(parents=True)   # nu se poate scrie un fisier peste un director
    e.run()
    assert "could not write" in e.stderr and "rollback.sh will not remove" in e.stderr, e.stderr
    assert "[+] vps-watchdog:" not in e.stdout


OLD_UNIT = b"[Service]\n# unitatea veche, scrisa de mana\nExecStart=/opt/vps-watchdog/watchdog.sh\n"
BACKUPS = ("watchdog.sh", "vps-watchdog.service", "vps-watchdog.timer")


def _hand_copied_host(root: Path, **kw) -> Env:
    """O gazda cu un watchdog facut de mana: script si unitati la locul lor, FARA semnatura."""
    e = Env(root, with_conf=True, **kw)
    e.dir.mkdir()
    (e.dir / "watchdog.sh").write_bytes(OLD_SCRIPT)
    (e.udir / "vps-watchdog.service").write_bytes(OLD_UNIT)
    (e.udir / "vps-watchdog.timer").write_bytes(OLD_UNIT + b"# timer\n")
    return e


def test_adopting_a_hand_copied_install_keeps_the_old_files_for_the_operator(tmp_path):
    """Pe productie scriptul vechi e SINGURA evidenta a celor trei domenii de client pe care le
    verifica (depozitul e public, domeniile stau doar in conf). Adoptarea il suprascrie cu
    versiunea din depozit; daca apoi o poarta de sanatate pica si rollback-ul scoate
    watchdog-ul, ce verifica gazda s-a pierdut fara urma. Inainte de suprascriere se pastreaza
    o copie a scriptului si a celor doua unitati, octet cu octet, ca operatorul sa le
    restaureze de mana; instalatorul spune unde sunt si ca NU le restaureaza."""
    e = _hand_copied_host(tmp_path)
    old = {n: (e.dir / n).read_bytes() if n == "watchdog.sh" else (e.udir / n).read_bytes() for n in BACKUPS}
    e.run()
    assert e.rc == 0, e.stdout + e.stderr
    for name in BACKUPS:
        assert (e.dir / f"{name}.pre-adoption").read_bytes() == old[name], name
    assert _bytes(e.dir / "watchdog.sh") == _bytes(SRC_DIR / "watchdog.sh"), "adoptarea nu a instalat"
    assert (e.dir / ".installed-by-sentinel").is_file()
    assert "kept, not restored" in e.stdout and "watchdog.sh.pre-adoption" in e.stdout, e.stdout


def test_a_host_the_installer_never_adopted_gets_no_backup_files(tmp_path):
    """Copiile `.pre-adoption` inseamna "aici a fost o instalare straina". Pe o gazda curata,
    sau la a doua rulare peste o instalare a noastra (semnatura exista), nu se creeaza: un
    fisier de felul asta aparut din nimic ar trimite operatorul sa restaureze ceva ce nu a
    existat - sau, mai rau, o copie a fisierului NOSTRU pusa drept "original"."""
    fresh = Env(tmp_path / "fresh", with_conf=True).run()
    assert fresh.rc == 0 and not list(fresh.dir.glob("*.pre-adoption")), list(fresh.dir.iterdir())
    fresh.run()   # a doua rulare, acum cu semnatura
    assert not list(fresh.dir.glob("*.pre-adoption")), list(fresh.dir.iterdir())
    assert "kept, not restored" not in fresh.stdout


def test_the_adoption_backup_is_never_replaced_by_a_later_run(tmp_path):
    """`cp -n`, o singura data: daca semnatura dispare (rollback) si cineva copiaza iar de
    mana un script, a doua adoptare nu are voie sa scrie peste prima copie - ar pierde
    originalul cu domeniile clientilor in favoarea unui fisier mai nou."""
    e = _hand_copied_host(tmp_path)
    (e.dir / "watchdog.sh.pre-adoption").write_bytes(b"#!/usr/bin/env bash\n# PRIMA copie\n")
    e.run()
    assert e.rc == 0, e.stdout + e.stderr
    assert (e.dir / "watchdog.sh.pre-adoption").read_bytes() == b"#!/usr/bin/env bash\n# PRIMA copie\n"
    assert _bytes(e.dir / "watchdog.sh") == _bytes(SRC_DIR / "watchdog.sh")


def test_an_adoption_that_cannot_keep_a_copy_installs_nothing(tmp_path):
    """Daca copia veche nu se poate face (disc plin, director doar-citire), nu se
    suprascrie nimic: o adoptare fara copie sterge singura evidenta a domeniilor. Verdictul
    vine din compararea copiei cu originalul, nu din codul de iesire al lui `cp` (care aici
    iese cu 0 fara sa fi scris nimic, cum face un `cp -n` peste o cale deja ocupata)."""
    e = _hand_copied_host(tmp_path)
    _stub(e.bin, "cp", 'echo "cp: silent no-op" >&2\nexit 0\n')
    e.run()
    assert "could not keep a copy" in e.stderr and "nothing installed or changed" in e.stderr, e.stderr
    assert _bytes(e.dir / "watchdog.sh") == OLD_SCRIPT, "copia veche a fost inlocuita fara backup"
    assert not (e.dir / ".installed-by-sentinel").exists()
    assert not re.search(r"install -m ", e.log) and "restart" not in e.log, e.log   # niciun fisier copiat


def test_a_host_with_the_units_but_no_script_directory_can_still_be_adopted(tmp_path):
    """Unitatile pot sta in /etc/systemd/system fara ca /opt/vps-watchdog sa existe (script
    mutat, director sters). Copiile se pun langa script: fara directorul creat INAINTE,
    `cp` ar esua, adoptarea ar fi refuzata ("nu pot pastra o copie") si gazda n-ar putea fi
    adusa niciodata sub revizie de instalator."""
    e = Env(tmp_path, with_conf=True)
    (e.udir / "vps-watchdog.service").write_bytes(OLD_UNIT)
    (e.udir / "vps-watchdog.timer").write_bytes(OLD_UNIT + b"# timer\n")
    assert not e.dir.exists()
    e.run()
    assert e.rc == 0 and "could not keep a copy" not in e.stderr, e.stdout + e.stderr
    assert (e.dir / "vps-watchdog.service.pre-adoption").read_bytes() == OLD_UNIT
    assert (e.dir / "vps-watchdog.timer.pre-adoption").read_bytes() == OLD_UNIT + b"# timer\n"
    assert _bytes(e.dir / "watchdog.sh") == _bytes(SRC_DIR / "watchdog.sh")
