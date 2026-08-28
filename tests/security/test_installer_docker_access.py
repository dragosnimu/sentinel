"""Accesul lui `sentinel` la socketul docker, și ce scrie instalatorul despre el.

Ce se strică pentru operator dacă pasul ăsta minte, în ordinea în care doare:

  * **`scan.containers: true` pe o gazdă fără cale de acces.** `trivy_image`
    deschide rândul din `scans` înainte să întrebe ceva, deci un daemon care nu
    răspunde lasă un rând `failed` în FIECARE noapte și cheia
    `scan:last:trivy_image` roșie în `/selfcheck`. Nimeni nu poate curăța asta de
    pe gazdă: scanerul nu poate să-și acorde singur apartenența la grup.
  * **`scan.containers: false` pe o gazdă care are containere.** Tăcere care
    arată exact ca sănătate — tiparul din §3.17, „absența unui rezultat nu e
    zero", de partea cealaltă.
  * **„adăugat" raportat fără efect.** Tiparul din CLAUDE.md: `usermod -aG` iese
    cu 0 și când grupul nu duce nicăieri, iar `id -nG sentinel | grep -qx docker`
    dovedește doar o linie din `/etc/group`. Faptul observabil e un răspuns al
    DAEMONULUI ca acel utilizator.
  * **eroarea daemonului pierdută.** O versiune anterioară a funcției întorcea
    versiunea pe stdout, deci apelantul o citea cu `$(…)` și atribuirea lui
    `DOCKER_PROBE_ERR` murea cu subshell-ul: operatorul primea „fără mesaj" în
    locul liniei care îi spunea ce să repare.

Fiecare test de mai jos rulează FUNCȚIILE LIVRATE din `deploy/install.sh`, cu
`docker` și `runuser` momeli executabile pe PATH, și se uită la ce a rămas în
`DOCKER_ACCESS_STATE`, în `SCAN_CONTAINERS` și în ce s-a chemat.

Ce e MĂSURAT pe VM-ul de test (10.30.1.134, Ubuntu 24.04.4, docker 29.1.3,
28 august 2026) și ce e doar reprodus de momeli:

  * măsurat: `docker version --format '{{.Server.Version}}'` ca un utilizator din
    afara grupului iese cu 1 și scrie pe stderr „permission denied while trying
    to connect to the docker API at unix:///var/run/docker.sock";
  * măsurat: cu daemonul oprit, aceeași comandă iese cu 1 și scrie „Cannot
    connect to the Docker daemon … Is the docker daemon running?" — și pentru
    root, și pentru `sentinel`;
  * măsurat: `usermod -aG docker sentinel` pe un utilizator deja în grup iese cu
    0 și lasă `/etc/group` octet cu octet identic;
  * măsurat: `runuser -u sentinel -- docker version --format …` întoarce
    versiunea serverului, deși `sentinel` are `/sbin/nologin`;
  * NEmăsurat, reprodus de momeală: un client care iese cu **0** fără să fi
    vorbit cu serverul. Pe 29.1.3 chiar și `docker version` fără format iese cu
    1 când daemonul e mut. Testul care cere o versiune NEVIDĂ păzește totuși
    exact simplificarea care ar transforma verificarea într-o poartă ce trece
    mereu — și clienții mai vechi, și învelișurile peste alt runtime, chiar ies
    cu 0.
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
INSTALL_SH = REPO / "deploy" / "install.sh"
INSTALL = INSTALL_SH.read_text(encoding="utf-8")
TMPL = (REPO / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")

BASH = shutil.which("bash")
AWK = shutil.which("awk")

_NO_BASH = (
    "bash sau awk lipsește din PATH, deci NU au rulat: verificarea de efect care "
    "cere o versiune de SERVER, deosebirea dintre grup lipsă / apartenență "
    "neacordată / daemon mut, și drumul erorii daemonului către operator. Nu e "
    "„în regulă”, e „neverificat”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None or AWK is None, reason=_NO_BASH)]

# Numele grupului scris cu mâna în `step_user_and_dirs` până în august 2026, pe
# gazda de producție AlmaLinux care chiar are docker. Calea aia nu are voie să
# se schimbe la o refacere a pasului.
HISTORIC_DOCKER_GROUP = "docker"

# Aceleași căi ca `SOCKET_PATHS` din sentinel/scan/trivy_image.py. Legate aici
# fiindcă instalatorul și scanerul trebuie să se uite la același socket: dacă
# diverg, instalatorul acordă acces la unul și scanerul îl caută pe celălalt.
HISTORIC_SOCKET_PATHS = ("/run/docker.sock", "/var/run/docker.sock")


# ---------------------------------------------------------------------------
# Unelte pentru rulat shell-ul livrat
# ---------------------------------------------------------------------------
def _func(name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", INSTALL, re.S | re.M)
    assert match, f"funcția {name} nu mai există în deploy/install.sh"
    return match.group(0)


def _assign(name: str) -> str:
    """O atribuire de nivel zero, luată din fișierul livrat."""
    match = re.search(rf"^{re.escape(name)}=.*$", INSTALL, re.M)
    assert match, f"{name} nu mai e definit în deploy/install.sh"
    return match.group(0)


SHIPPED_FUNCS = ("docker_is_present", "docker_server_version_as",
                 "sentinel_in_docker_group", "config_containers_setting",
                 "ensure_docker_access")
SHIPPED_VARS = ("DOCKER_SOCKET_PATHS", "DOCKER_CLIENT_PATH", "DOCKER_GROUP",
                "DOCKER_ACCESS_STATE", "SCAN_CONTAINERS",
                "DOCKER_SERVER_VERSION", "DOCKER_PROBE_ERR")


def _write_stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# Momeala pentru `docker`. Două scenarii pe utilizator, prin variabile de mediu,
# fiindcă asta e chiar deosebirea pe care funcția o măsoară.
#
#   ok:VERSIUNE  daemonul răspunde
#   denied       cod 1 + linia de permisiune MĂSURATĂ pe VM
#   down         cod 1 + linia de daemon oprit MĂSURATĂ pe VM
#   zero         cod 0 și NICIO versiune de server — trapa „codul de ieșire"
#   grant        refuzat la prima chemare, servit la a doua — ce se întâmplă când
#                `usermod` chiar a schimbat ceva
DOCKER_STUB = r"""
who="${DOCKER_STUB_WHO:-root}"
if [ "$who" = root ]; then spec="${DOCKER_STUB_ROOT:-down}"
else spec="${DOCKER_STUB_SENTINEL:-denied}"; fi
printf 'docker[%s] %s\n' "$who" "$*" >> "$CALLS"
if [ "$spec" = grant ]; then
    n=0
    [ -f "$CALLS.n" ] && n="$(cat "$CALLS.n")"
    n=$((n + 1)); printf '%s' "$n" > "$CALLS.n"
    if [ "$n" -ge 2 ]; then spec="ok:29.1.3"; else spec=denied; fi
fi
formatted=0
[ "${2:-}" = --format ] && formatted=1
case "$spec" in
    ok:*)
        if [ "$formatted" = 1 ]; then printf '%s\n' "${spec#ok:}"; exit 0; fi
        printf 'Client:\n Version: 29.1.3\nServer:\n Version: %s\n' "${spec#ok:}"
        exit 0 ;;
    denied)
        printf 'Client:\n Version: 29.1.3\n'
        printf 'permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n' >&2
        exit 1 ;;
    down)
        printf 'Client:\n Version: 29.1.3\n'
        printf 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n' >&2
        exit 1 ;;
    zero)
        # Clientul pornește, tipărește blocul lui și iese cu 0 fără să fi vorbit
        # cu vreun server. Cu `--format` nu are ce tipări, deci nu tipărește
        # nimic — și tot iese cu 0.
        [ "$formatted" = 1 ] || printf 'Client:\n Version: 29.1.3\n'
        exit 0 ;;
esac
"""

# Momeala pentru `runuser`. Execută comanda DIRECT, ca originalul cu `-u`, și
# doar marchează în mediu cine a cerut-o.
RUNUSER_STUB = r"""
printf 'runuser %s\n' "$*" >> "$CALLS"
user=""
while [ $# -gt 0 ]; do
    case "$1" in
        -u) user="$2"; shift 2 ;;
        --) shift; break ;;
        *)  break ;;
    esac
done
export DOCKER_STUB_WHO="$user"
exec "$@"
"""

HARNESS = """
set -euo pipefail
source ./lib/common.sh

SENTINEL_USER=sentinel
SENTINEL_CONFIG_DIR="$CFG"

{constants}

# Socketurile și clientul mutate în tmp: mașina care rulează testul nu are /run,
# și exact de asta sunt variabile în fișierul livrat.
DOCKER_SOCKET_PATHS=({sockets})
DOCKER_CLIENT_PATH="{client}"

{functions}

usermod() {{ printf 'usermod %s\\n' "$*" >> "$CALLS"; return "${{USERMOD_RC:-0}}"; }}
getent()  {{ printf 'getent %s\\n'  "$*" >> "$CALLS"; [[ "${{GROUP_EXISTS:-1}}" == 1 ]]; }}
id()      {{ printf '%s\\n' "${{ID_GROUPS:-sentinel adm}}"; }}

# `have` livrată, cu un set de comenzi declarate absente. Mașina care rulează
# testul poate avea un `docker` sau un `sudo` real, iar ramurile măsurate mai jos
# sunt tocmai cele în care nu le are — deci absența se impune, nu se speră.
# Restul căutării rămâne cea livrată.
_ABSENT=" {absent} "
have() {{
    case "$_ABSENT" in *" $1 "*) return 1 ;; esac
    command -v "$1" >/dev/null 2>&1
}}

ensure_docker_access
rc=$?
printf 'STATE=%s\\nCONTAINERS=%s\\nRC=%s\\n' \\
    "$DOCKER_ACCESS_STATE" "$SCAN_CONTAINERS" "$rc"
"""


def run_access(tmp_path: Path, *, sockets: tuple[str, ...] = (),
               docker: str | None = "denied", root_docker: str = "down",
               have_runuser: bool = True, group_exists: bool = True,
               usermod_rc: int = 0, id_groups: str = "sentinel adm",
               config: str | None = None,
               family: str = "rhel") -> dict:
    """Rulează `ensure_docker_access` livrată, cu gazda descrisă de argumente."""
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (cfg / "sentinel.yaml").write_text(config, encoding="utf-8", newline="\n")
    calls = tmp_path / "calls.txt"
    stubs = tmp_path / "bin"
    stubs.mkdir(parents=True, exist_ok=True)

    absent = []
    if docker is None:
        absent.append("docker")
    else:
        _write_stub(stubs, "docker", DOCKER_STUB)
    if have_runuser:
        _write_stub(stubs, "runuser", RUNUSER_STUB)
    else:
        absent += ["runuser", "sudo"]

    sock_paths = [str(tmp_path / s).replace("\\", "/") for s in sockets] \
        or [str(tmp_path / "no-such.sock").replace("\\", "/")]
    for s in sock_paths:
        if sockets:
            Path(s).write_text("", encoding="utf-8")

    script = tmp_path / "harness.sh"
    script.write_text(
        HARNESS.format(
            constants="\n".join(_assign(v) for v in SHIPPED_VARS),
            functions="\n".join(_func(f) for f in SHIPPED_FUNCS),
            sockets=" ".join(f'"{s}"' for s in sock_paths),
            client=str(tmp_path / "no-such-docker").replace("\\", "/"),
            absent=" ".join(absent)),
        encoding="utf-8", newline="\n")

    env = {**os.environ, "NO_COLOR": "1",
           "CFG": str(cfg).replace("\\", "/"),
           "CALLS": str(calls).replace("\\", "/"),
           "DISTRO_FAMILY": family,
           "DOCKER_STUB_SENTINEL": docker or "denied",
           "DOCKER_STUB_ROOT": root_docker,
           "GROUP_EXISTS": "1" if group_exists else "0",
           "USERMOD_RC": str(usermod_rc),
           "ID_GROUPS": id_groups,
           "PATH": str(stubs).replace("\\", "/") + os.pathsep + os.environ.get("PATH", "")}
    env.pop("DOCKER_HOST", None)

    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=str(REPO / "deploy"), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    out = proc.stdout + proc.stderr
    return {
        "proc": proc, "out": out,
        "state": _tagged(proc.stdout, "STATE"),
        "containers": _tagged(proc.stdout, "CONTAINERS"),
        "calls": calls.read_text(encoding="utf-8") if calls.exists() else "",
    }


def _tagged(text: str, tag: str) -> str:
    match = re.search(rf"^{tag}=(.*)$", text, re.M)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# Garda: harnessul chiar rulează funcția livrată
# ---------------------------------------------------------------------------
def test_the_harness_actually_reaches_the_shipped_function(tmp_path):
    """Păzește restul fișierului.

    Dacă harnessul se oprește mai devreme — o funcție redenumită, o momeală
    neexecutabilă — fiecare aserțiune „nu s-a acordat nimic" de mai jos trece
    fiindcă n-a rulat nimic. Adică exact aserțiunea care nu verifică nimic.
    """
    out = run_access(tmp_path, docker="ok:29.1.3")
    assert out["proc"].returncode == 0, out["out"]
    assert out["state"], out["out"]
    assert "docker[sentinel] version --format" in out["calls"], out["calls"]


# ---------------------------------------------------------------------------
# absent — o gazdă fără containere nu e o eroare
# ---------------------------------------------------------------------------
def test_a_host_without_docker_writes_false_and_is_not_an_error(tmp_path):
    """Fără asta, o gazdă fără containere primește `scan.containers: true`, iar
    `trivy_image` scrie un rând `failed` în fiecare noapte despre un daemon care
    n-a existat niciodată — zgomot pe care operatorul îl învață să-l ignore, și
    odată cu el cheia care ar fi contat.
    """
    out = run_access(tmp_path, docker=None, have_runuser=False)
    assert out["proc"].returncode == 0, out["out"]
    assert out["state"] == "absent", out["out"]
    assert out["containers"] == "false", out["out"]
    assert "usermod" not in out["calls"], out["calls"]
    assert "Nu e o eroare" in out["out"], out["out"]


# ---------------------------------------------------------------------------
# Verificarea de EFECT: o versiune de server, nu un cod de ieșire
# ---------------------------------------------------------------------------
def test_a_zero_exit_without_a_server_version_is_never_reported_as_access(tmp_path):
    """Trapa din CLAUDE.md, în forma ei din pasul ăsta.

    Un client care pornește și iese cu 0 fără să fi vorbit cu vreun daemon ar
    trece orice poartă construită pe codul de ieșire. Ce ar rămâne în urmă:
    `scan.containers: true` pe o gazdă unde scanarea nu se poate face, deci un
    rând `failed` în fiecare noapte și `scan:last:trivy_image` roșu — și un
    instalator care a raportat „adăugat".

    Momeala iese cu 0 la AMBELE forme; doar `--format '{{.Server.Version}}'`
    rămâne fără ieșire, ceea ce e singurul lucru care o deosebește de un succes.
    """
    out = run_access(tmp_path, docker="zero", root_docker="ok:29.1.3",
                     id_groups="sentinel adm")
    assert out["proc"].returncode == 0, out["out"]
    assert out["state"] not in ("ready", "granted"), \
        f"cod 0 fără versiune de server a fost citit ca acces: {out['out']}"
    assert out["containers"] == "false", out["out"]

    # Și dovada că momeala chiar e trapa: forma FĂRĂ `--format` iese cu 0.
    naive = subprocess.run(
        [BASH, str(tmp_path / "bin" / "docker").replace("\\", "/"), "version"],
        capture_output=True, text=True,
        env={**os.environ, "DOCKER_STUB_WHO": "sentinel",
             "DOCKER_STUB_SENTINEL": "zero",
             "CALLS": str(tmp_path / "calls.txt").replace("\\", "/")})
    assert naive.returncode == 0, \
        "momeala nu mai e trapa: `docker version` fără format nu mai iese cu 0"
    assert "Server" not in naive.stdout


def test_a_reachable_daemon_grants_nothing_on_a_second_deploy(tmp_path):
    """Idempotența, dovedită prin efect și nu presupusă.

    Funcția rulează la FIECARE deploy. Dacă ar acorda întâi și ar măsura după,
    fiecare rulare ar scrie în `/etc/group` și ar tipări un avertisment despre un
    privilegiu echivalent cu root pe o gazdă unde nu s-a schimbat nimic —
    avertismentul pe care operatorul trebuie să-l citească exact atunci când e
    nou.
    """
    out = run_access(tmp_path, docker="ok:29.1.3", id_groups="sentinel adm docker")
    assert out["state"] == "ready", out["out"]
    assert out["containers"] == "true", out["out"]
    assert "usermod" not in out["calls"], \
        f"a doua rulare a mai atins /etc/group: {out['calls']}"
    assert "Nimic de acordat" in out["out"]


def test_membership_that_takes_effect_is_reported_with_the_restart_caveat(tmp_path):
    """Cazul de bază — și avertismentul fără care operatorul crede că a terminat.

    systemd rezolvă grupurile suplimentare la PORNIREA unității. Un proces
    `sentinel` deja pornit păstrează setul vechi, iar `daemon-reload` nu schimbă
    nimic. Fără linia asta în ieșirea pasului, operatorul se uită la un
    `id sentinel` corect și la o scanare care eșuează, și nu are cum să lege
    cele două.
    """
    # Prima interogare e refuzată, a doua reușește: exact ce se întâmplă când
    # `usermod` chiar a schimbat ceva. `docker` momeală citește variabila la
    # fiecare pornire, deci se schimbă între cele două chemări prin CALLS.
    out = run_access(tmp_path, docker="grant", root_docker="ok:29.1.3",
                     id_groups="sentinel adm docker")
    assert out["state"] == "granted", out["out"]
    assert out["containers"] == "true", out["out"]
    assert "usermod -aG docker sentinel" in out["calls"], out["calls"]
    assert "Type=oneshot" in out["out"] and "daemon-reload" in out["out"], \
        f"pasul nu spune că un proces deja pornit păstrează grupurile vechi: {out['out']}"


# ---------------------------------------------------------------------------
# Apartenența care NU s-a putut acorda — spusă, nu raportată drept „adăugat"
# ---------------------------------------------------------------------------
def test_a_missing_docker_group_is_named_and_nothing_claims_it_was_added(tmp_path):
    """`getent group docker` care eșuează pe o gazdă unde clientul EXISTĂ nu e
    cazul „fără containere": e un client care nu duce nicăieri — un înveliș peste
    alt runtime, sau un pachet pe jumătate instalat. Raportat ca „adăugat", ar
    lăsa `scan.containers: true` peste o cale de acces care nu există.
    """
    out = run_access(tmp_path, docker="denied", root_docker="ok:29.1.3",
                     group_exists=False)
    assert out["state"] == "denied", out["out"]
    assert out["containers"] == "false", out["out"]
    assert "usermod" not in out["calls"], \
        f"a chemat usermod pentru un grup care nu există: {out['calls']}"
    # Două locuri, fiindcă nu se ajunge mereu la al doilea: cu un DOCKER_HOST
    # peste TCP, un grup inexistent nu împiedică daemonul să răspundă, iar
    # ramura de diagnostic de la final nu se mai atinge.
    assert f"grupul {HISTORIC_DOCKER_GROUP} nu există pe gazda asta, deci " \
           "apartenența NU poate fi acordată" in out["out"], out["out"]
    assert f"cauza vizibilă: grupul {HISTORIC_DOCKER_GROUP} nu există" in out["out"], \
        out["out"]


def test_a_usermod_that_did_not_take_is_a_denial_not_a_success(tmp_path):
    """`usermod -aG` iese cu 0 și când nu s-a schimbat nimic util. Dacă pasul ar
    crede codul de ieșire, ar scrie `true` peste o gazdă fără acces — și rândul
    `failed` de la 3 dimineața ar fi singurul care ar spune-o.
    """
    out = run_access(tmp_path, docker="denied", root_docker="ok:29.1.3",
                     id_groups="sentinel adm")
    assert out["state"] == "denied", out["out"]
    assert out["containers"] == "false", out["out"]
    assert "usermod -aG docker sentinel" in out["calls"], out["calls"]
    assert "tot nu arată docker" in out["out"], out["out"]
    assert "FALSE" in out["out"]


def test_the_daemon_error_reaches_the_operator(tmp_path):
    """Defectul cu substituția de comandă.

    `DOCKER_PROBE_ERR` era atribuit ÎNĂUNTRUL unui `$(…)`, deci murea cu
    subshell-ul și operatorul primea „fără mesaj" — adică fix linia care îi
    spunea dacă are de pornit un daemon sau de reparat un grup. Aici se cere
    textul daemonului, nu doar o stare.
    """
    out = run_access(tmp_path, docker="denied", root_docker="ok:29.1.3",
                     id_groups="sentinel adm")
    assert "permission denied while trying to connect to the docker API" in out["out"], \
        out["out"]
    assert "fără mesaj" not in out["out"], out["out"]


def test_a_daemon_silent_to_root_too_is_unproven_rather_than_a_denial(tmp_path):
    """„Nu știu" și „e în regulă" sunt stări diferite, și la fel „nu știu" și
    „refuzat".

    Daemonul oprit nu spune nimic despre apartenență: `sentinel` E în
    `/etc/group`, calea de acces există, doar serviciul e jos. Scris ca `false`,
    instalatorul ar opri singur scanarea containerelor pe o gazdă care le are,
    iar `install_config` nu rescrie un `sentinel.yaml` viu — deci `false` ar
    rămâne acolo și după ce operatorul pornește docker.

    Deci `true`, dar spus pe față că EFECTUL nu a fost văzut.
    """
    out = run_access(tmp_path, docker="down", root_docker="down",
                     id_groups="sentinel adm docker")
    assert out["state"] == "unproven", out["out"]
    assert out["containers"] == "true", out["out"]
    assert "nu a putut fi dovedit" in out["out"], out["out"]
    assert "Is the docker daemon running?" in out["out"], out["out"]
    assert "nu răspunde nici lui root" in out["out"], out["out"]


def test_no_way_to_ask_as_the_user_is_unproven_and_says_so(tmp_path):
    """Fără `runuser` și fără `sudo` nu există niciun mod de a proba efectul.
    Raportat ca succes, ar fi cea mai curată formă a bug-ului din CLAUDE.md:
    „am verificat" acolo unde nu s-a putut verifica nimic.
    """
    out = run_access(tmp_path, docker="denied", have_runuser=False,
                     id_groups="sentinel adm docker")
    assert out["state"] == "unproven", out["out"]
    assert "nu am cum să rulez docker CA sentinel" in out["out"], out["out"]
    assert "docker[" not in out["calls"], \
        f"a rulat docker deși n-avea cum s-o facă drept sentinel: {out['calls']}"


# ---------------------------------------------------------------------------
# Alegerea operatorului din §3.14
# ---------------------------------------------------------------------------
def test_an_operator_who_turned_scanning_off_is_not_re_granted_the_group(tmp_path):
    """§3.14: ieșirea din schimb e `scan.containers: false` ÎMPREUNĂ cu scoaterea
    din grup. Funcția asta rulează la fiecare deploy — dacă ar re-acorda
    apartenența oricum, ar readuce un privilegiu echivalent cu root la fiecare
    actualizare, pe o gazdă unde scanarea e oprită: tot costul și niciun
    beneficiu, iar operatorul n-ar afla decât citind `/etc/group`.
    """
    out = run_access(tmp_path, docker="denied",
                     config="scan:\n  containers: false\n")
    assert out["state"] == "disabled", out["out"]
    assert out["containers"] == "false", out["out"]
    assert "usermod" not in out["calls"], out["calls"]
    assert "docker[" not in out["calls"], out["calls"]
    # Și nu e o fundătură tăcută: se spune cum se pornește înapoi.
    assert "scan.containers: true" in out["out"], out["out"]


def test_containers_is_read_from_the_scan_block_and_not_from_any_key_named_so(
        tmp_path):
    """Un `grep containers:` peste tot fișierul citește prima potrivire, oriunde
    ar fi ea. Pe o configurație unde altă secțiune are o cheie cu același nume,
    instalatorul ar crede că operatorul a oprit scanarea și n-ar mai acorda
    niciodată accesul — o capacitate pierdută pe tăcute, din cauza unui cuvânt.
    """
    out = run_access(
        tmp_path, docker="ok:29.1.3", id_groups="sentinel adm docker",
        config=("inventory:\n  containers: false\n"
                "scan:\n  os_packages: true\n  containers: true\n"))
    assert out["state"] == "ready", out["out"]
    assert out["containers"] == "true", out["out"]


def test_a_host_with_no_configuration_yet_is_not_read_as_a_refusal(tmp_path):
    """Instalarea nouă: nu există `sentinel.yaml`. „Nu pot citi" tratat ca
    „false" ar face ca prima instalare de pe orice gazdă să iasă cu scanarea
    containerelor oprită — și, fiindcă fișierul se scrie o singură dată, oprită
    pentru totdeauna.
    """
    out = run_access(tmp_path, docker="ok:29.1.3", id_groups="sentinel adm docker",
                     config=None)
    assert out["state"] == "ready", out["out"]
    assert out["containers"] == "true", out["out"]


def test_an_unreachable_daemon_says_the_live_config_still_claims_true(tmp_path):
    """`install_config` nu rescrie un `sentinel.yaml` viu — scrie `.new` lângă
    el. Deci pe o gazdă deja instalată, `SCAN_CONTAINERS=false` NU ajunge în
    fișierul pe care îl citește scanerul, iar eșecul nocturn continuă. Fără
    linia asta, operatorul citește „se scrie false" și pleacă liniștit.
    """
    out = run_access(tmp_path, docker="denied", root_docker="ok:29.1.3",
                     id_groups="sentinel adm",
                     config="scan:\n  containers: true\n")
    assert out["state"] == "denied", out["out"]
    assert "sentinel.yaml.new" in out["out"], out["out"]


# ---------------------------------------------------------------------------
# Neregresie RHEL — producția e AlmaLinux ȘI are docker
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("family", ["rhel", "debian"])
def test_the_grant_is_identical_on_both_families(tmp_path, family):
    """Producția e AlmaLinux cu docker, deci acolo pasul chiar acordă
    apartenența. O ramificare pe familie strecurată aici ar schimba exact gazda
    pe care nimeni n-o testează înainte.

    `docker` e constanta istorică: numele scris cu mâna în `step_user_and_dirs`
    înainte ca pasul să fie refăcut.
    """
    out = run_access(tmp_path, docker="grant", root_docker="ok:29.1.3",
                     id_groups="sentinel adm docker", family=family)
    assert out["state"] == "granted", out["out"]
    assert out["containers"] == "true", out["out"]
    assert f"usermod -aG {HISTORIC_DOCKER_GROUP} sentinel" in out["calls"], out["calls"]


def test_the_installer_still_uses_the_historic_group_and_socket_paths():
    """Grupul și socketurile sunt legătura dintre instalator și scaner. Dacă
    instalatorul acordă acces la un socket și `trivy_image` caută altul, pasul
    raportează succes despre o cale pe care nimeni n-o folosește.
    """
    assert _assign("DOCKER_GROUP") == f"DOCKER_GROUP={HISTORIC_DOCKER_GROUP}"
    shipped = _assign("DOCKER_SOCKET_PATHS")
    for path in HISTORIC_SOCKET_PATHS:
        assert path in shipped, shipped
    scanner = (REPO / "sentinel" / "scan" / "trivy_image.py").read_text(
        encoding="utf-8")
    for path in HISTORIC_SOCKET_PATHS:
        assert f'"{path}"' in scanner, \
            f"{path} nu mai e în SOCKET_PATHS din trivy_image.py"


# ---------------------------------------------------------------------------
# Configurația: ce se scrie, și refuzul de a ghici
# ---------------------------------------------------------------------------
def test_the_template_no_longer_hardcodes_the_container_switch():
    """Dacă șablonul rămâne `containers: true`, tot ce e măsurat mai sus nu
    ajunge nicăieri — exact felul în care o reparație arată făcută și nu e.
    Precedentele sunt `auditd: @@AUDITD_ENABLED@@` și
    `family: @@PLATFORM_FAMILY@@`.
    """
    assert "containers: @@SCAN_CONTAINERS@@" in TMPL
    assert re.search(r"^\s*containers:\s*(true|false)\s*$", TMPL, re.M) is None
    assert "s|@@SCAN_CONTAINERS@@|${SCAN_CONTAINERS}|g" in _func("step_configs"), \
        "pasul 26 nu mai substituie valoarea măsurată"


def test_step_26_refuses_to_write_a_value_nobody_measured(tmp_path):
    """O configurație care minte e mai rea decât o capacitate lipsă.

    Dacă `ensure_docker_access` ajunge vreodată să nu ruleze înaintea pasului 26
    — o reordonare în `main`, un `return` timpuriu — alternativa tăcută e un
    `containers:` gol în YAML, care se încarcă drept null și pornește scanarea.
    Aici pasul se oprește în loc să ghicească.
    """
    script = tmp_path / "guard.sh"
    script.write_text(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "SCAN_CONTAINERS=\"\"\n"
        + _func("step_configs") + "\n"
        "step_configs\n",
        encoding="utf-8", newline="\n")
    proc = subprocess.run([BASH, str(script).replace("\\", "/")],
                          cwd=str(REPO / "deploy"), capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, "NO_COLOR": "1"})
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "ensure_docker_access did not run" in proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Locul apelului în `main`
# ---------------------------------------------------------------------------
def test_the_call_is_unconditional_and_runs_before_the_config_is_written():
    """De ce nu în pasul 19: 19 e marcat din ziua instalării și nu e în
    ALWAYS_STEPS, deci pe o gazdă unde docker apare mai târziu apartenența nu
    s-ar mai acorda niciodată, în tăcere. De ce înainte de 26: pasul 26 e cel
    care scrie `scan.containers` din măsurătoare. De ce înainte de 32: systemd
    rezolvă grupurile la pornirea unității, iar 32 e cel care repornește
    unitățile — o apartenență acordată după el n-ar ajunge la niciun proces până
    la deploy-ul următor.

    Se citește din secvența livrată, fiindcă un comentariu nu ordonează nimic.
    """
    sequence = re.search(r"^(    run_step  1 preflight.*?run_step 40 notify.*?)$",
                         INSTALL, re.S | re.M)
    assert sequence, "nu mai găsesc secvența de pași din install.sh"
    body = sequence.group(1)

    call = re.search(r"^\s*ensure_docker_access\s*$", body, re.M)
    assert call, "`ensure_docker_access` nu e chemată în secvența din main"

    def at(pattern: str) -> int:
        match = re.search(pattern, body, re.M)
        assert match, pattern
        return match.start()

    assert at(r"^\s*run_step 19 user_and_dirs") < call.start()
    assert call.start() < at(r"^\s*run_step 26 configs")
    assert call.start() < at(r"^\s*run_step 32 start_services")

    # Și nu a rămas o a doua acordare în pasul 19: două locuri sunt două
    # adevăruri, iar cel din 19 e supus marcajului.
    step19 = _func("step_user_and_dirs")
    assert "usermod -aG docker" not in step19, step19
    assert "getent group docker" not in step19, step19
