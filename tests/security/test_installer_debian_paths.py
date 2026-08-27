"""Ce se rupe pe Debian/Ubuntu fără să spună nimic — și ce NU are voie să se
rupă pe AlmaLinux când repari asta.

Instalarea a fost măsurată pe un Ubuntu 24.04.4 curat. Ce s-a văzut acolo, în
ordinea în care a apărut:

  * `python3` e 3.12.3, deci `python_find` reușește, deci blocul care instala
    grupul Python era sărit cu totul — și `python3.12 -m venv` murea la pasul 23
    cu „ensurepip is not available", fiindcă `python3.12-venv` e alt pachet;
  * `/etc/pki/tls` nu există deloc, deci certificatul-substituent nu se scria și
    vhostul arăta către un fișier care n-avea să apară;
  * `rpm -qa` scria un fișier GOL în instantaneul de pre-deploy, tăcut, iar
    acela e punctul la care se întoarce rollback-ul;
  * `auditctl` nu exista, deci nicio regulă `sentinel_*` nu se încărca, iar
    configurația spunea în continuare `ingest.auditd: true` peste un fișier care
    nu se creează niciodată.

Fiecare test de mai jos rulează funcția LIVRATĂ din `deploy/lib/distro.sh` sau
din `deploy/install.sh`, cu unelte-momeală pe PATH, și se uită la ce a ieșit.
Aserțiunile pe familia `rhel` compară cu constanta istorică — șirul exact care
era scris cu mâna în cod înainte de abstractizare — fiindcă producția rulează
AlmaLinux și calea aia n-are voie să se schimbe.
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
DISTRO_SH = REPO / "deploy" / "lib" / "distro.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
DISTRO = DISTRO_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")

_NO_BASH = (
    "bash lipsește din PATH, deci funcțiile din distro.sh NU au fost rulate. "
    "Asta e „neverificat”, nu „în regulă”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


# ---------------------------------------------------------------------------
# Unelte pentru rulat shell-ul livrat
# ---------------------------------------------------------------------------
def _func(source: str, name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> Path:
    """O comandă-momeală, executabilă, prima pe PATH."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _run(script: str, tmp_path: Path, extra_path: Path | None = None,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    path = tmp_path / "harness.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    environ = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        environ["PATH"] = (str(extra_path).replace("\\", "/") + os.pathsep
                           + environ.get("PATH", ""))
    if env:
        environ.update(env)
    return subprocess.run(
        [BASH, str(path).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


def _distro_call(tmp_path: Path, family: str, call: str,
                 extra_path: Path | None = None) -> subprocess.CompletedProcess:
    """Sursă `lib/distro.sh` cu o familie fixată, apoi cheamă `call`."""
    return _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        f"{call}\n",
        tmp_path, extra_path=extra_path)


# ---------------------------------------------------------------------------
# tls_dir — A2
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("family,expected", [("rhel", "/etc/pki/tls"),
                                             ("debian", "/etc/ssl")])
def test_tls_dir_gives_each_family_a_directory_that_exists_there(
        tmp_path, family, expected):
    """`/etc/pki` nu există pe Ubuntu — măsurat pe 24.04.4. `openssl req -out`
    către el eșuează, certificatul-substituent nu se scrie, iar nginx refuză să
    pornească pe un fișier lipsă cu o eroare despre TLS, nu despre cale.

    Pentru `rhel`, `/etc/pki/tls` e constanta istorică: exact ce era scris cu
    mâna în `ensure_placeholder_certificate` și în cele trei șabloane nginx.
    """
    proc = _distro_call(tmp_path, family, "tls_dir")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


def test_the_installer_no_longer_names_the_rpm_path_by_hand():
    """O singură cale rămasă scrisă cu mâna e de ajuns: certificatul se scrie
    într-un loc, iar vhostul arată către altul, și abia nginx spune ceva."""
    offenders = [f"{n}:{i}" for n, text in
                 (("install.sh", INSTALL),
                  *((p.name, p.read_text(encoding="utf-8"))
                    for p in sorted((REPO / "deploy" / "nginx").glob("*.tmpl"))))
                 for i, line in enumerate(text.splitlines(), 1)
                 if "/etc/pki" in line and not line.strip().startswith("#")]
    assert not offenders, f"cale RPM scrisă cu mâna: {offenders}"


# ---------------------------------------------------------------------------
# pkg_list — B3
# ---------------------------------------------------------------------------
def test_pkg_list_on_rhel_still_asks_rpm(tmp_path):
    """Constanta istorică: era `rpm -qa | sort`. Instantaneul de pre-deploy e
    ținta rollback-ului; dacă lista pachetelor se schimbă pe AlmaLinux,
    operatorul compară cu altceva decât cu ce compara ieri."""
    binpath = tmp_path / "bin"
    _stub(binpath, "rpm", 'printf "%s\\n" "$@" > "$RPM_ARGS_FILE"\n'
                          'printf "zzz-1.0\\naaa-2.0\\n"\n')
    proc = _distro_call(tmp_path, "rhel", "pkg_list", extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    # Sortat, ca înainte.
    assert proc.stdout == "aaa-2.0\nzzz-1.0\n"


def test_pkg_list_on_debian_is_not_empty(tmp_path):
    """`rpm -qa` pe Ubuntu scria un fișier GOL, tăcut. Instantaneul care
    alimentează rollback-ul spunea atunci „gazda asta n-avea niciun pachet"."""
    binpath = tmp_path / "bin"
    _stub(binpath, "dpkg-query", 'printf "zzz 1.0 amd64\\naaa 2.0 amd64\\n"\n')
    proc = _distro_call(tmp_path, "debian", "pkg_list", extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["aaa 2.0 amd64", "zzz 1.0 amd64"]


def test_the_snapshot_says_so_when_it_could_not_list_the_packages(tmp_path):
    """Eșecul pe care îl previne: rollback-ul îi arată operatorului un fișier
    gol ca fiind „ce era pe gazdă înainte de deploy". Un `|| true` peste un
    redirect a produs exact asta, timp în care nimeni n-a avut de ce să se uite.
    """
    snapdir = tmp_path / "snap"
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        # Nicio funcție pkg_list definită: exact cazul „nu se poate afla".
        f'snapshot_create "{str(snapdir).replace(chr(92), "/")}"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (snapdir / "packages.txt").exists(), \
        "s-a scris o listă de pachete goală în loc să se spună că nu se știe"
    assert "could not list the installed packages" in proc.stderr


def test_the_snapshot_records_the_packages_when_it_can(tmp_path):
    """Cealaltă jumătate: dacă testul de mai sus ar trece și pe un instantaneu
    care nu scrie NICIODATĂ lista, n-ar păzi nimic."""
    snapdir = tmp_path / "snap"
    binpath = tmp_path / "bin"
    _stub(binpath, "dpkg-query", 'printf "aaa 1.0 amd64\\nbbb 2.0 amd64\\n"\n')
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        f'snapshot_create "{str(snapdir).replace(chr(92), "/")}"\n',
        tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (snapdir / "packages.txt").read_text(encoding="utf-8").splitlines() == \
        ["aaa 1.0 amd64", "bbb 2.0 amd64"]


# ---------------------------------------------------------------------------
# python_support_pkgs + ensure_python_build_deps — A1
# ---------------------------------------------------------------------------
def _fake_python(directory: Path, name: str = "fakepy") -> Path:
    """Un interpretor-momeală care răspunde la exact cele trei întrebări pe care
    le pune instalatorul, și minte controlat prin variabile de mediu.

    `FAKE_VENV_MARKER` și `FAKE_INCLUDE` sunt fișiere: existența lor decide
    răspunsul, ca un `pkg_install` momeală să le poată crea și testul să vadă
    diferența dintre „am instalat" și „acum chiar merge".
    """
    return _stub(directory, name, """
case "${2:-}" in
    *ensurepip*)    [[ -f "$FAKE_VENV_MARKER" ]] || exit 1 ;;
    *sysconfig*)    printf '%s\\n' "$FAKE_INCLUDE" ;;
    *version_info*) printf '%s\\n' "${FAKE_VERSION:-3.12}" ;;
    *)              exit 1 ;;
esac
exit 0
""")


@pytest.mark.parametrize("family,version,expected", [
    # Constanta istorică pentru rhel: venv e în pachetul interpretorului acolo,
    # deci singurul lucru care lipsește vreodată sunt headerele.
    ("rhel", "3.11", ["python3.11-devel"]),
    ("rhel", "3.12", ["python3.12-devel"]),
    # Pe Ubuntu 24.04 astea două sunt exact pachetele pe care `dpkg -l` le
    # raporta ca `un` în timp ce instalarea se declara terminată cu pasul 20.
    ("debian", "3.12", ["python3.12-venv", "python3.12-dev"]),
    ("debian", "3.13", ["python3.13-venv", "python3.13-dev"]),
])
def test_the_package_names_follow_the_chosen_interpreter(
        tmp_path, family, version, expected):
    """`python3-dev` și `python3-venv` sunt metapachete care arată către python3
    IMPLICIT al distribuției. Pe o gazdă unde interpretorul ales e python3.13,
    ele instalează headerele lui 3.12 și compilarea eșuează pe alt Python.h —
    fără ca nimic să spună că s-au instalat headerele altei versiuni."""
    binpath = tmp_path / "bin"
    _fake_python(binpath)
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        "python_support_pkgs fakepy\n",
        tmp_path, extra_path=binpath, env={"FAKE_VERSION": version})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == expected, proc.stdout


def test_no_package_names_are_guessed_for_an_interpreter_that_will_not_answer(
        tmp_path):
    """„Nu știu ce versiune e" și „e 3.12" sunt stări diferite. Ghicind, am
    instala headerele altcuiva și am raporta succes."""
    binpath = tmp_path / "bin"
    _stub(binpath, "mutepy", "exit 1\n")
    proc = _distro_call(tmp_path, "debian", "python_support_pkgs mutepy || true",
                        extra_path=binpath)
    assert proc.stdout.strip() == ""


def _build_deps_harness(tmp_path: Path, *, has_venv: bool, has_headers: bool,
                        install_fixes: bool):
    """Rulează `ensure_python_build_deps` LIVRATĂ, cu un `pkg_install` momeală.

    Întoarce procesul ȘI ce a cerut momeala să se instaleze.

    `install_fixes` spune dacă instalarea chiar repară ceva. Cu `False`,
    `pkg_install` întoarce 0 și nu schimbă nimic — exact tiparul din CLAUDE.md,
    „codul de ieșire în locul efectului".
    """
    binpath = tmp_path / "bin"
    _fake_python(binpath)
    include = tmp_path / "include"
    include.mkdir()
    marker = tmp_path / "venv-ok"
    if has_venv:
        marker.write_text("", encoding="utf-8")
    if has_headers:
        (include / "Python.h").write_text("", encoding="utf-8")

    fixups = (f'touch "$FAKE_VENV_MARKER"; touch "$FAKE_INCLUDE/Python.h"'
              if install_fixes else 'true')
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        # Momeala: raportează succes, face (sau nu) ceva. Ce a cerut se scrie
        # într-un FIȘIER, nu pe stderr — `ensure_python_build_deps` rulează
        # `pkg_install … >/dev/null 2>&1`, deci o aserțiune pe stderr ar fi
        # goală și ar trece la fel de bine când nu se instalează nimic.
        f'pkg_install() {{ printf "pkg_install %s\\n" "$*" >> "$PKG_INSTALL_LOG"; {fixups}; return 0; }}\n'
        + _func(INSTALL, "python_can_venv") + "\n"
        + _func(INSTALL, "python_has_headers") + "\n"
        + _func(INSTALL, "ensure_python_build_deps") + "\n"
        "ensure_python_build_deps fakepy\n"
    )
    log = tmp_path / "pkg-install.log"
    log.write_text("", encoding="utf-8", newline="\n")
    proc = _run(script, tmp_path, extra_path=binpath, env={
        "FAKE_VENV_MARKER": str(marker).replace("\\", "/"),
        "FAKE_INCLUDE": str(include).replace("\\", "/"),
        "PKG_INSTALL_LOG": str(log).replace("\\", "/"),
    })
    return proc, log.read_text(encoding="utf-8")


def test_an_interpreter_that_can_already_build_a_venv_installs_nothing(tmp_path):
    """Non-regresie pe AlmaLinux: acolo ambele fapte sunt deja adevărate, deci
    pasul 20 nu are voie să atingă niciun pachet Python în plus."""
    proc, installed = _build_deps_harness(tmp_path, has_venv=True,
                                          has_headers=True, install_fixes=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert installed == "", f"s-a instalat ceva unde nu lipsea nimic: {installed!r}"


def test_the_missing_venv_module_is_installed_and_then_re_checked(tmp_path):
    """Cazul Ubuntu 24.04: interpretorul trece pragul de versiune, deci vechiul
    cod sărea peste instalare cu totul, iar pasul 23 murea cu «ensurepip is not
    available» — două sute de linii mai încolo, cu simptomul în loc de cauză."""
    proc, installed = _build_deps_harness(tmp_path, has_venv=False,
                                          has_headers=False, install_fixes=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Numele exacte, nu doar „s-a instalat ceva".
    assert installed.strip() == "pkg_install python3.12-venv python3.12-dev"
    assert "installing python3.12-venv python3.12-dev" in proc.stdout
    assert "can build a venv and has its headers" in proc.stdout


@pytest.mark.parametrize("has_venv,has_headers,expected", [
    (False, True, "ensurepip"),
    (True, False, "Python.h"),
    (False, False, "ensurepip"),
])
def test_a_package_manager_that_returned_zero_is_not_proof(
        tmp_path, has_venv, has_headers, expected):
    """ACESTA e testul central. `pkg_install` raportează succes și nu repară
    nimic — pachet inexistent în depozit, oglindă veche, nume schimbat între
    versiuni. Dacă pasul 20 crede codul de ieșire, instalarea merge mai departe
    și moare la pasul 23 într-un compilator, sau, mai rău, produce un venv fără
    `systemd-python` și un colector care nu citește niciodată journald."""
    proc, installed = _build_deps_harness(tmp_path, has_venv=has_venv,
                                          has_headers=has_headers,
                                          install_fixes=False)
    assert installed.strip(), \
        "momeala n-a fost chemată deloc, deci nu se testează ce face pasul cu rezultatul ei"
    assert proc.returncode != 0, \
        "pasul 20 a trecut mai departe cu un interpretor care nu poate face venv"
    assert "still cannot build" in proc.stderr
    assert expected in proc.stderr


def test_step_20_asks_for_the_build_deps_every_time_not_only_when_python_is_missing():
    """Cauza exactă a lui A1: blocul Python rula doar în ramura
    `if ! python_find`. Pe Ubuntu `python_find` reușește, deci nu rula
    niciodată. Apelul trebuie să fie în AFARA acelei ramuri."""
    body = _func(INSTALL, "step_packages")
    assert "ensure_python_build_deps" in body
    branch = body.split("if ! python_find", 1)[1].split("\n    fi\n", 1)[0]
    assert "ensure_python_build_deps" not in branch, \
        "apelul e din nou închis în ramura care se sare pe Ubuntu"


# ---------------------------------------------------------------------------
# auditd — B1
# ---------------------------------------------------------------------------
def _auditd_harness(tmp_path: Path, *, active_at_start: bool,
                    start_activates: bool, start_creates_log: bool,
                    stale_log: bool = False):
    """Rulează `ensure_auditd_running` LIVRATĂ, cu `systemctl` momeală.

    Întoarce (returncode, ce s-a cerut lui systemctl, dacă logul a apărut).

    `start_activates` și `start_creates_log` sunt separate pentru că exact așa
    s-a purtat gazda reală: pachetul a lăsat unitatea `enabled` și `inactive`,
    iar `/var/log/audit` era gol. O reparație care crede codul de ieșire al lui
    `systemctl` raportează succes pe amândouă.
    """
    binpath = tmp_path / "bin"
    state = tmp_path / "state"
    calls = tmp_path / "systemctl-calls.log"
    log = tmp_path / "audit.log"
    state.write_text("active" if active_at_start else "inactive",
                     encoding="utf-8", newline="\n")
    calls.write_text("", encoding="utf-8", newline="\n")
    if stale_log or (active_at_start and start_creates_log):
        log.write_text("", encoding="utf-8", newline="\n")

    _stub(binpath, "systemctl", """
printf '%s\\n' "$*" >> "$SYSTEMCTL_CALLS"
case "$1" in
    is-active)
        state="$(cat "$SYSTEMCTL_STATE")"
        if [[ "${2:-}" == "--quiet" ]]; then
            [[ "$state" == "active" ]] || exit 3
        else
            printf '%s\\n' "$state"
            [[ "$state" == "active" ]] || exit 3
        fi
        ;;
    enable)
        [[ "${START_ACTIVATES:-0}" == "1" ]] && printf 'active\\n' > "$SYSTEMCTL_STATE"
        [[ "${START_CREATES_LOG:-0}" == "1" ]] && : > "$AUDITD_LOG_PATH"
        ;;
esac
exit 0
""")
    _stub(binpath, "auditctl", "exit 0\n")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'AUDITD_LOG_PATH="{str(log).replace(chr(92), "/")}"\n'
        # Fereastra livrată e de 10 secunde; aici e scurtată ca testul care
        # așteaptă degeaba să nu coste zece secunde. Valoarea livrată e pinuită
        # separat, mai jos.
        "AUDITD_LOG_WAIT_S=2\n"
        + _func(INSTALL, "ensure_auditd_running") + "\n"
        "ensure_auditd_running\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath, env={
        "SYSTEMCTL_STATE": str(state).replace("\\", "/"),
        "SYSTEMCTL_CALLS": str(calls).replace("\\", "/"),
        "AUDITD_LOG_PATH": str(log).replace("\\", "/"),
        "START_ACTIVATES": "1" if start_activates else "0",
        "START_CREATES_LOG": "1" if start_creates_log else "0",
    })
    return proc.returncode, calls.read_text(encoding="utf-8"), log.exists()


def test_an_installed_but_unstarted_auditd_is_started(tmp_path):
    """Eșecul măsurat pe Ubuntu 24.04.4: după `apt install auditd`, systemd
    raportează unitatea `enabled` și `is-active` spune `inactive`, iar
    /var/log/audit e gol. Pachetul e instalat, regulile se scriu la pasul 37, și
    nu se colectează absolut nimic până la următorul reboot — adică același
    rezultat ca fără pachet, pe un drum mai lung."""
    rc, calls, log_exists = _auditd_harness(
        tmp_path, active_at_start=False, start_activates=True,
        start_creates_log=True)
    assert rc == 0, calls
    assert "enable --now auditd" in calls
    assert log_exists


def test_an_auditd_that_is_already_running_is_left_alone(tmp_path):
    """Pe fiecare gazdă RHEL auditd rulează deja. Un `restart` acolo ar fi o
    schimbare adusă unui serviciu care era în regulă — și auditd nu e un
    serviciu pe care îl clatini fără motiv."""
    rc, calls, _ = _auditd_harness(tmp_path, active_at_start=True,
                                   start_activates=False, start_creates_log=True)
    assert rc == 0, calls
    assert "enable" not in calls, f"s-a atins un auditd care mergea: {calls!r}"
    assert "restart" not in calls


def test_a_systemctl_that_returned_zero_is_not_proof_the_daemon_runs(tmp_path):
    """`systemctl enable --now` iese cu 0 și lasă serviciul oprit — exact ce
    face un `enable` peste o unitate mascată, sau o pornire care eșuează după ce
    comanda s-a întors. Dacă pasul 20 crede codul de ieșire, spune «auditd
    running» peste o gazdă care nu colectează nimic."""
    rc, calls, _ = _auditd_harness(tmp_path, active_at_start=False,
                                   start_activates=False, start_creates_log=False)
    assert rc != 0, calls
    assert "enable --now auditd" in calls


def test_a_stale_log_from_a_dead_auditd_is_not_taken_for_a_running_one(tmp_path):
    """Un auditd oprit lasă `/var/log/audit/audit.log` pe disc. Fără verificarea
    stării DUPĂ pornire, prezența fișierului ar fi luată drept dovadă că
    demonul merge — pasul 20 ar spune «auditd running and writing», iar
    colectorul ar citi la nesfârșit un fișier în care nu mai scrie nimeni.

    Asta e ce deosebește verificarea de aici de o simplă căutare de fișier."""
    rc, calls, _ = _auditd_harness(tmp_path, active_at_start=False,
                                   start_activates=False, start_creates_log=False,
                                   stale_log=True)
    assert rc != 0, calls
    assert "enable --now auditd" in calls


def test_a_running_auditd_without_its_log_is_not_reported_as_working(tmp_path):
    """Un auditd pornit care scrie în altă parte (sau deloc) e un colector care
    deschide un fișier inexistent. „Serviciul e pornit" și „colectorul are ce
    citi" sunt afirmații diferite."""
    rc, calls, log_exists = _auditd_harness(
        tmp_path, active_at_start=False, start_activates=True,
        start_creates_log=False)
    assert rc != 0, calls
    assert not log_exists


def test_the_shipped_wait_for_the_log_is_a_real_window():
    """Fișierul nu apare în aceeași microsecundă cu unitatea. O verificare
    instantanee ar raporta un auditd perfect funcțional drept stricat, la
    fiecare instalare pe o gazdă lentă."""
    assert re.search(r"^AUDITD_LOG_WAIT_S=(\d+)$", INSTALL, re.M), \
        "fereastra de așteptare a dispărut din install.sh"
    seconds = int(re.search(r"^AUDITD_LOG_WAIT_S=(\d+)$", INSTALL, re.M).group(1))
    assert seconds >= 5, f"fereastra de {seconds}s e prea scurtă pentru o gazdă încărcată"


def test_step_20_looks_at_auditd_at_all():
    """Pachetul adăugat în `pkg_names_core` nu ajunge: dacă pasul 20 nu se uită
    niciodată la el, gazda rămâne cu unitatea oprită și nimeni nu spune nimic."""
    body = _func(INSTALL, "step_packages")
    assert "ensure_auditd_running" in body
    assert "auditctl" in body


def test_auditd_is_installed_on_debian_and_not_pretended_on_rhel(tmp_path):
    """Pe Ubuntu 24.04.4 `auditctl` nu există. Fără el nu se încarcă
    `sentinel_identity`, `sentinel_ssh`, `sentinel_cron`, `sentinel_systemd`,
    `sentinel_webroot`, `sentinel_exec`, `sentinel_priv`, `sentinel_cmd` — deci
    nicio detecție `host.*` și nici `auth.new_user` / `auth.new_ssh_key`. Pasul
    37 avertiza o dată și instalarea raporta succes.

    Pe rhel lista rămâne cea istorică: auditd e preinstalat acolo, iar lista
    asta e o cale de `die`."""
    debian = _distro_call(tmp_path, "debian", "pkg_names_core").stdout.split()
    rhel = _distro_call(tmp_path, "rhel", "pkg_names_core").stdout.split()
    assert "auditd" in debian
    assert rhel == ["gcc", "systemd-devel", "pkgconf-pkg-config", "nginx",
                    "nftables", "acl", "ca-certificates", "curl", "tar",
                    "zstd", "jq"], rhel


def test_the_config_does_not_claim_auditd_on_a_host_without_it(tmp_path):
    """O configurație care minte e mai rea decât un pachet lipsă: colectorul
    deschide la nesfârșit `/var/log/audit/audit.log`, nu găsește nimic, și
    panoul rămâne verde. Pachetul lipsă măcar se vede."""
    binpath = tmp_path / "bin"          # gol: fără `auditctl` pe PATH
    binpath.mkdir()
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'AUDITD_LOG_PATH="{str(tmp_path / "nu-exista").replace(chr(92), "/")}"\n'
        + _func(INSTALL, "auditd_feeds_the_collector") + "\n"
        'if auditd_feeds_the_collector; then echo true; else echo false; fi\n',
        tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "false"


def test_the_config_claims_auditd_when_the_log_is_really_there(tmp_path):
    """Cealaltă jumătate. Un test care întoarce «false» în orice situație ar
    dezactiva colectarea auditd pe producție, unde ea funcționează."""
    binpath = tmp_path / "bin"
    _stub(binpath, "auditctl", "exit 0\n")
    log = tmp_path / "audit.log"
    log.write_text("", encoding="utf-8")
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'AUDITD_LOG_PATH="{str(log).replace(chr(92), "/")}"\n'
        + _func(INSTALL, "auditd_feeds_the_collector") + "\n"
        'if auditd_feeds_the_collector; then echo true; else echo false; fi\n',
        tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "true"


def test_the_template_no_longer_hardcodes_the_auditd_switch():
    """Dacă șablonul rămâne `auditd: true`, verificarea de mai sus nu ajunge
    nicăieri — exact felul în care o reparație arată făcută și nu e."""
    tmpl = (REPO / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(
        encoding="utf-8")
    assert "auditd: @@AUDITD_ENABLED@@" in tmpl
    assert re.search(r"^\s*auditd:\s*true\s*$", tmpl, re.M) is None
    # Și substituția chiar există în pasul care scrie fișierul.
    assert "s|@@AUDITD_ENABLED@@|" in _func(INSTALL, "step_configs")
