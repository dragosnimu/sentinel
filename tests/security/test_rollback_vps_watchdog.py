"""`deploy/rollback.sh` si `vps-watchdog` - FRAGMENTUL LIVRAT, cu `systemctl` fals.

Rollback-ul oprea doar unitatile `sentinel-*`. `vps-watchdog` nu se numeste asa (si
nu are voie sa se mute in deploy/systemd/ ca sa fie gasit: pe acolo instalatorul
pune TOT pe FIECARE gazda, iar asta reporneste containere ca root). Deci un rollback
lasa instalat si pornit un serviciu care reporneste containere singur.

Reparatia are doua jumatati care trebuie sa se potriveasca: instalatorul scrie o
semnatura (`.installed-by-sentinel`) dupa ce a copiat fisierele, iar rollback-ul scoate
watchdog-ul NUMAI cand semnatura exista. Fara ea, un rollback automat (install.sh
il porneste cand o poarta de sanatate pica) ar sterge dupa nume o copie facuta de mana
pe care deploy-ul nu a atins-o - exact situatia gazdei de productie.

Ce simuleaza si ce NU are mediul asta:

  * `systemctl` e un fals cu stare (fisiere `<unitate>.active` / `.enabled`), care
    raspunde ca systemd real la `is-active` / `is-enabled` DUPA ce rollback-ul a
    actionat. NU se dovedeste ca systemd real opreste un oneshot aflat la jumatatea
    unui `docker restart`; se dovedeste ca rollback-ul CITESTE starea inapoi si nu
    raporteaza "scos" cand starea spune altceva.
  * Linkul `timers.target.wants/` e un fisier obisnuit (Windows n-are symlink-uri
    sigure aici); se verifica doar ca rollback-ul il scoate.
  * Fragmentul rulat e cel dintre marcajele `vps-watchdog: begin/end` din rollback.sh,
    nu tot scriptul (care cere nft, nginx, postgres reale).
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
ROLLBACK = (REPO / "deploy" / "rollback.sh").read_text(encoding="utf-8")
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
SRC_DIR = REPO / "deploy" / "vps-watchdog"

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipseste din PATH")]

HAND_COPIED = b"#!/usr/bin/env bash\n# copia veche, scrisa de mana pe gazda\n"


def _snippet() -> str:
    start = ROLLBACK.index("# --- vps-watchdog: begin ---")
    end = ROLLBACK.index("# --- vps-watchdog: end ---")
    assert 0 < start < end, "rollback.sh nu mai are marcajele pe care testul le decupeaza"
    return ROLLBACK[start:end]


def _func(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", INSTALL, re.S | re.M)
    assert match, f"functia {name} nu mai exista in deploy/install.sh"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# systemctl cu stare. FAKE_STUCK_ACTIVE: `stop`/`disable --now` nu opresc nimic (un
# oneshot prins la jumatatea unei reporniri); FAKE_STUCK_ENABLED: `disable` nu are efect.
SYSTEMCTL = r'''
echo "systemctl $*" >> "$CALLS"
cmd="$1"; shift
now=0; args=()
for a in "$@"; do
  case "$a" in --now) now=1 ;; -*) ;; *) args+=("$a") ;; esac
done
case "$cmd" in
  disable)
    for u in "${args[@]}"; do
      [ -z "${FAKE_STUCK_ENABLED:-}" ] && { rm -f "$SC/$u.enabled"; rm -f "$UNITS/timers.target.wants/$u"; }
      [ "$now" = 1 ] && [ -z "${FAKE_STUCK_ACTIVE:-}" ] && rm -f "$SC/$u.active"
    done ;;
  stop)
    for u in "${args[@]}"; do [ -z "${FAKE_STUCK_ACTIVE:-}" ] && rm -f "$SC/$u.active"; done ;;
  enable)  for u in "${args[@]}"; do touch "$SC/$u.enabled"; done ;;
  restart) for u in "${args[@]}"; do touch "$SC/$u.active"; done ;;
  is-active)
    if [ -f "$SC/${args[0]}.active" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  is-enabled)
    if [ -f "$SC/${args[0]}.enabled" ]; then echo enabled; exit 0; fi
    echo disabled; exit 1 ;;
  show) echo no ;;
  *) exit 0 ;;
esac
'''


class Box:
    """Un 'host': /opt/vps-watchdog, /etc/systemd/system, starea systemd, apelurile."""

    def __init__(self, root: Path):
        self.root = root
        self.opt = root / "opt-vps-watchdog"
        self.units = root / "units"
        self.sc = root / "systemd-state"
        self.bin = root / "bin"
        self.calls = root / "calls.log"
        self.conf = root / "vps-watchdog.conf"
        for d in (self.opt / "state", self.units / "timers.target.wants", self.sc, self.bin):
            d.mkdir(parents=True, exist_ok=True)
        _stub(self.bin, "systemctl", SYSTEMCTL)

    @property
    def marker(self) -> Path:
        return self.opt / ".installed-by-sentinel"

    def put_watchdog(self, *, signed: bool, running: bool = True) -> None:
        """O instalare existenta: script, doua unitati, link de pornire, stare systemd."""
        (self.opt / "watchdog.sh").write_bytes(HAND_COPIED)
        (self.opt / "state" / "problems.state").write_text("cap:disk|x\n", encoding="utf-8")
        (self.units / "vps-watchdog.service").write_text("[Service]\n", encoding="utf-8")
        (self.units / "vps-watchdog.timer").write_text("[Timer]\n", encoding="utf-8")
        (self.units / "timers.target.wants" / "vps-watchdog.timer").write_text("", encoding="utf-8")
        for u in ("vps-watchdog.timer", "vps-watchdog.service"):
            if running:
                (self.sc / f"{u}.active").write_text("", encoding="utf-8")
        (self.sc / "vps-watchdog.timer.enabled").write_text("", encoding="utf-8")
        if signed:
            self.marker.write_text("installed by deploy/install.sh at 2026-10-21T00:00:00Z\n",
                                   encoding="utf-8")

    def _env(self, **extra) -> dict:
        env = {**os.environ, "NO_COLOR": "1",
               "CALLS": self.calls.as_posix(), "SC": self.sc.as_posix(),
               "UNITS": self.units.as_posix(),
               "VPS_WATCHDOG_DIR": self.opt.as_posix(),
               "VPS_WATCHDOG_UNIT_DIR": self.units.as_posix(),
               "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        env.update(extra)
        return env

    def _run_script(self, body: str, **extra) -> "Box":
        script = self.root / "run.sh"
        script.write_text(
            "set -euo pipefail\n"
            f'source "{(REPO / "deploy" / "lib" / "common.sh").as_posix()}"\n'
            + body + '\necho "FAIL_COUNT=${FAIL_COUNT}"\n',
            encoding="utf-8", newline="\n")
        proc = subprocess.run([BASH, script.as_posix()], cwd=str(REPO / "deploy"),
                              capture_output=True, env=self._env(**extra), timeout=120)
        self.stdout = proc.stdout.decode("utf-8", errors="replace")
        self.stderr = proc.stderr.decode("utf-8", errors="replace")
        self.rc = proc.returncode
        self.log = self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""
        m = re.search(r"FAIL_COUNT=(\d+)", self.stdout)
        self.fail_count = int(m.group(1)) if m else None
        return self

    def rollback(self, **extra) -> "Box":
        return self._run_script(_snippet(), **extra)

    def install(self, **extra) -> "Box":
        """install_vps_watchdog, FUNCTIA LIVRATA, cu `install` copiind si conf prezent."""
        self.conf.write_text('HEALTH_DOMAINS="app.example.org"\n', encoding="utf-8")
        _stub(self.bin, "install",
              'echo "install $*" >> "$CALLS"\n'
              'if [ "$1" = "-d" ]; then mkdir -p "${@: -1}"; exit 0; fi\n'
              'cp "${@: -2:1}" "${@: -1}"\n')
        sd = self.root / "deploy"
        if not sd.exists():
            shutil.copytree(SRC_DIR, sd / "vps-watchdog")
        body = (f'SCRIPT_DIR="{sd.as_posix()}"\n' + _func("install_vps_watchdog") + "\n"
                "install_vps_watchdog\n")
        return self._run_script(body, VPS_WATCHDOG_CONF=self.conf.as_posix(), **extra)


def _units_gone(b: Box) -> list[str]:
    left = []
    for p in (b.units / "vps-watchdog.service", b.units / "vps-watchdog.timer",
              b.units / "timers.target.wants" / "vps-watchdog.timer", b.opt / "watchdog.sh"):
        if p.exists():
            left.append(p.name)
    return left


def test_rollback_removes_the_watchdog_the_installer_put_there(tmp_path):
    """Dupa un rollback, `vps-watchdog` nu mai are voie sa ruleze: reporneste containere
    ca root, singur, la fiecare minut. Efectul, nu intentia: unitatile si scriptul au
    disparut, nici timerul nici serviciul nu sunt active sau activate, timerul e oprit
    INAINTE de serviciu (altfel il porneste la loc), iar systemd a recitit unitatile
    inainte sa fie intrebat. Starea (/opt/vps-watchdog/state) ramane, ca in rollback
    pentru /var/lib/sentinel."""
    b = Box(tmp_path)
    b.put_watchdog(signed=True)
    b.rollback()
    assert b.rc == 0 and b.fail_count == 0, b.stdout + b.stderr
    assert _units_gone(b) == []
    assert not b.marker.exists()
    assert not list(b.sc.iterdir()), "systemd mai are stare pentru unitati scoase"
    assert (b.opt / "state" / "problems.state").exists(), "starea watchdog-ului a fost stearsa"
    lines = [l for l in b.log.splitlines()]
    idx = {k: next(i for i, l in enumerate(lines) if l.startswith(k)) for k in
           ("systemctl disable --now vps-watchdog.timer", "systemctl stop vps-watchdog.service",
            "systemctl daemon-reload")}
    assert idx["systemctl disable --now vps-watchdog.timer"] < idx["systemctl stop vps-watchdog.service"] \
        < idx["systemctl daemon-reload"], lines
    last_check = max(i for i, l in enumerate(lines) if l.startswith("systemctl is-active"))
    assert last_check > idx["systemctl daemon-reload"], "starea nu s-a citit inapoi dupa reincarcare"
    assert "vps-watchdog removed" in b.stdout


def test_rollback_leaves_a_watchdog_it_did_not_install_alone(tmp_path):
    """Pe gazda de productie ruleaza o copie facuta de mana, cu aceleasi nume de unitati.
    Un rollback automat (porneste singur cand o poarta de sanatate pica) care ar scoate-o
    dupa nume ar sterge un serviciu pe care deploy-ul nu l-a atins - si ar lasa gazda
    fara alerte de disponibilitate. Fara semnatura: nimic atins, iar operatorul afla
    ca serviciul ramane si cum il scoate."""
    b = Box(tmp_path)
    b.put_watchdog(signed=False)
    b.rollback()
    assert b.rc == 0 and b.fail_count == 0, b.stdout + b.stderr
    assert (b.opt / "watchdog.sh").read_bytes() == HAND_COPIED
    assert (b.units / "vps-watchdog.timer").exists() and (b.units / "vps-watchdog.service").exists()
    assert (b.sc / "vps-watchdog.timer.active").exists() and (b.sc / "vps-watchdog.timer.enabled").exists()
    assert b.log == "", f"systemctl a fost chemat pe o instalare straina: {b.log}"
    assert "did not put it there" in b.stderr and "left running" in b.stderr, b.stderr


@pytest.mark.parametrize("stuck", ["FAKE_STUCK_ACTIVE", "FAKE_STUCK_ENABLED"])
def test_rollback_does_not_report_a_unit_gone_that_systemd_still_has(tmp_path, stuck):
    """`systemctl disable --now` iesind cu 0 e semnalul trimis, nu dovada: un oneshot
    prins la jumatatea unei reporniri de container ramane activ, iar un `disable` fara
    efect lasa timerul activat. Rollback-ul care ar scrie "scos" ar lasa un serviciu
    care reporneste containere. Aici starea citita inapoi contrazice: trebuie esec
    (cod nenul din rollback), nu "ok"; semnatura ramane, ca o a doua rulare sa termine."""
    b = Box(tmp_path)
    b.put_watchdog(signed=True)
    b.rollback(**{stuck: "1"})
    assert b.fail_count == 1, (b.fail_count, b.stdout, b.stderr)
    assert "NOT fully removed" in b.stderr and "still" in b.stderr, b.stderr
    assert "vps-watchdog removed" not in b.stdout
    assert b.marker.exists(), "semnatura a disparut: a doua rulare n-ar mai scoate nimic"
    # Chiar si cand `disable` n-a avut efect, linkul de pornire nu ramane agatat de o
    # unitate care nu mai exista.
    assert not (b.units / "timers.target.wants" / "vps-watchdog.timer").exists()
    # martorul: aceeasi gazda, fara blocaj, se curata complet
    ok = Box(tmp_path / "ok")
    ok.put_watchdog(signed=True)
    ok.rollback()
    assert ok.fail_count == 0 and _units_gone(ok) == []


def test_rollback_with_no_watchdog_at_all_is_a_quiet_noop(tmp_path):
    """O gazda fara watchdog (a doua gazda Sentinel nu l-a cerut) trece prin rollback fara
    sa fie atinsa si fara sa raporteze un esec."""
    b = Box(tmp_path)
    b.rollback()
    assert b.rc == 0 and b.fail_count == 0, b.stdout + b.stderr
    assert b.log == "" and b.stderr == ""
    assert "no vps-watchdog installed" in b.stdout


def test_what_the_installer_installs_the_rollback_removes(tmp_path):
    """Cele doua jumatati impreuna, pe aceeasi gazda fabricata: instalatorul LIVRAT pune
    fisierele, semnatura si porneste timerul (starea systemd o confirma), apoi
    rollback-ul LIVRAT le scoate pe toate. Daca instalatorul si-ar schimba calea sau
    numele semnaturii fara rollback, instalarea ar ramane pe gazda dupa un 'rollback
    complet' - singurul loc unde se vede nepotrivirea e un test care le ruleaza pe amandoua."""
    b = Box(tmp_path)
    b.install()
    assert b.rc == 0 and "[+] vps-watchdog:" in b.stdout, b.stdout + b.stderr
    assert b.marker.is_file()
    assert (b.opt / "watchdog.sh").read_bytes() == (SRC_DIR / "watchdog.sh").read_bytes()
    assert (b.sc / "vps-watchdog.timer.active").exists() and (b.sc / "vps-watchdog.timer.enabled").exists()
    b.rollback()
    assert b.rc == 0 and b.fail_count == 0, b.stdout + b.stderr
    assert _units_gone(b) == [] and not b.marker.exists()
    assert not (b.sc / "vps-watchdog.timer.active").exists()
    assert not (b.sc / "vps-watchdog.timer.enabled").exists()


def test_the_fragment_is_the_one_rollback_actually_runs():
    """Martor pentru decuparea de mai sus: fragmentul testat sta in `rollback.sh` INTRE
    pasul 1 (sentinel-*) si pasul 2 (firewall), adica ruleaza pe calea normala - nu e un
    bloc mort lasat dupa un `exit`."""
    step1 = ROLLBACK.index('section "1. Oprire servicii"')
    begin = ROLLBACK.index("# --- vps-watchdog: begin ---")
    step2 = ROLLBACK.index('section "2. Firewall"')
    assert step1 < begin < step2
    assert not re.search(r"^\s*exit\b", ROLLBACK[step1:step2], re.M)


def _real_rm() -> str:
    found = subprocess.run([BASH, "-c", "command -v rm"], capture_output=True, text=True).stdout.strip()
    assert found, "nu gasesc rm"
    return found


def test_rollback_reports_a_script_it_could_not_delete_and_still_finishes(tmp_path):
    """`rm -f` care nu poate sterge (fisier imutabil, sistem de fisiere doar-citire) iese
    nenul, iar rollback.sh ruleaza sub `set -e`: fara `|| true`, TOT rollback-ul se opreste
    acolo - fara verdict despre watchdog, cu firewall-ul si nginx-ul inca neatinse, dupa un
    deploy deja picat. Cu el, citirea inapoi gaseste fisierul ramas si il numeste: esec
    raportat, semnatura pastrata, restul rollback-ului continua (aici: ajunge la
    FAIL_COUNT-ul de dupa fragment). Fara citirea inapoi, aceeasi gazda ar fi raportat
    "scos" cu scriptul care reporneste containere inca pe disc."""
    b = Box(tmp_path)
    b.put_watchdog(signed=True)
    _stub(b.bin, "rm",
          'refused=0; args=()\n'
          'for a in "$@"; do\n'
          '  case "$a" in\n'
          '    */watchdog.sh) echo "rm: cannot remove \'$a\': Operation not permitted" >&2; refused=1 ;;\n'
          '    *) args+=("$a") ;;\n'
          '  esac\n'
          'done\n'
          f'"{_real_rm()}" "${{args[@]}}" || exit $?\n'
          'exit $refused\n')
    b.rollback()
    assert b.fail_count == 1, (b.fail_count, b.rc, b.stdout, b.stderr)   # None = rollback-ul s-a oprit
    assert "watchdog.sh still exists" in b.stderr and "NOT fully removed" in b.stderr, b.stderr
    assert "vps-watchdog removed" not in b.stdout
    assert (b.opt / "watchdog.sh").exists() and b.marker.exists()
    assert not (b.units / "vps-watchdog.timer").exists(), "nici macar unitatile nu s-au sters"


def test_rollback_names_what_the_host_lost_and_keeps_the_old_copy_for_the_operator(tmp_path):
    """Dupa ce instalatorul a adoptat un watchdog facut de mana si un rollback il scoate, gazda
    ramane FARA alerte de disponibilitate, iar copia veche (singura evidenta a domeniilor
    clientilor) e tot ce a mai ramas din ce verifica ea. Un `info` pierdut printre zeci de
    linii nu spune asta: trebuie `warn` care numeste pierderea si calea copiei. Copia NU se
    pune la loc singura - ar readuce un script nerevizuit care reporneste containere ca root,
    ca efect lateral al unei porti de sanatate picate. Martor: fara copie, avertismentul
    spune doar ca alertele lipsesc."""
    b = Box(tmp_path)
    b.put_watchdog(signed=True)
    saved = []
    for name in ("watchdog.sh", "vps-watchdog.service", "vps-watchdog.timer"):
        path = b.opt / f"{name}.pre-adoption"
        path.write_bytes(HAND_COPIED + name.encode())
        saved.append(path)
    b.rollback()
    assert b.rc == 0 and b.fail_count == 0, b.stdout + b.stderr
    for path in saved:
        assert str(path.as_posix()) in b.stderr, (path, b.stderr)
        assert path.read_bytes().startswith(HAND_COPIED), "copia veche a fost atinsa"
    assert "NO vps-watchdog" in b.stderr and "NOT restored" in b.stderr, b.stderr
    assert not (b.opt / "watchdog.sh").exists(), "rollback-ul a restaurat singur copia veche"
    assert b.opt.joinpath("state", "problems.state").exists()

    bare = Box(tmp_path / "bare")
    bare.put_watchdog(signed=True)
    bare.rollback()
    assert bare.fail_count == 0 and "NO vps-watchdog" in bare.stderr, bare.stderr
    assert "NOT restored" not in bare.stderr and ".pre-adoption" not in bare.stderr, bare.stderr


def _verify_step(box: Box, *, rollback_removes: bool, adopted: bool) -> Box:
    """`step_verify_nothing_broken`, FUNCTIA LIVRATA, cu poarta de sanatate cazuta si un
    rollback.sh fals care sterge (sau nu) scriptul watchdog-ului."""
    sd = box.root / "deploy"
    sd.mkdir(exist_ok=True)
    rb = sd / "rollback.sh"
    rb.write_text("#!/usr/bin/env bash\n"
                  + (f'rm -f "{(box.opt / "watchdog.sh").as_posix()}"\n' if rollback_removes else "")
                  + "exit 0\n", encoding="utf-8", newline="\n")
    rb.chmod(rb.stat().st_mode | stat.S_IEXEC)
    box.opt.mkdir(parents=True, exist_ok=True)
    if adopted:
        (box.opt / "watchdog.sh.pre-adoption").write_bytes(HAND_COPIED)
    (box.opt / "watchdog.sh").write_bytes(b"#!/usr/bin/env bash\n# a depozitului\n")
    body = (f'SCRIPT_DIR="{sd.as_posix()}"\nSNAPSHOT_DIR="{box.root.as_posix()}/snap"\n'
            f'STATE_MARKERS="{box.root.as_posix()}/markers"\n'
            "assert_nothing_broken() { return 1; }\n"
            + _func("step_verify_nothing_broken") + "\nstep_verify_nothing_broken\n")
    return box._run_script(body)


def test_the_failure_summary_names_the_watchdog_the_rollback_removed(tmp_path):
    """Cand poarta de sanatate cade, install.sh porneste rollback-ul si moare cu un mesaj
    final - singurul loc pe care operatorul il citeste cu adevarat. Daca rollback-ul a scos
    un watchdog ADOPTAT, mesajul trebuie sa spuna ca gazda a ramas fara alerte si unde e
    copia veche; daca rollback-ul NU l-a scos (scriptul e inca acolo) sau nu exista copie
    veche, nu are voie sa pretinda o pierdere care n-a avut loc."""
    lost = _verify_step(Box(tmp_path / "lost"), rollback_removes=True, adopted=True)
    assert lost.rc == 1, lost.stderr
    assert "LOST" in lost.stderr and ".pre-adoption" in lost.stderr and "by hand" in lost.stderr, lost.stderr
    assert "Rolled back." in lost.stderr

    still_there = _verify_step(Box(tmp_path / "there"), rollback_removes=False, adopted=True)
    assert still_there.rc == 1 and "Rolled back." in still_there.stderr
    assert "LOST" not in still_there.stderr, still_there.stderr

    never_adopted = _verify_step(Box(tmp_path / "plain"), rollback_removes=True, adopted=False)
    assert never_adopted.rc == 1 and "Rolled back." in never_adopted.stderr
    assert "LOST" not in never_adopted.stderr, never_adopted.stderr
