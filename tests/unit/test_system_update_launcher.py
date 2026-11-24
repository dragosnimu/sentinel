"""`scripts/system-update.sh` — lansatorul de pe stația operatorului.

`ssh` momeală EXECUTĂ de-adevărat comanda primită, într-un bash, în loc să recunoască șirul. Un
`sudo` momeală marchează „am devenit root" (`FAKE_IS_ROOT=1`), iar un `cd` suprascris (prin BASH_ENV)
refuză directorul rezervat root-ului când nu suntem root — modelul de permisiuni al gazdei: directorul
de lucru e root 0700, iar un `cd` rulează ca `sentinel-deploy`. O versiune anterioară a testului
recunoștea șirul «cd … sha256sum» fără să-l execute și n-a văzut că `cd` cade pe gazdă cu Permission
denied, adică orice fază murea la pasul sumelor.

Ce NU dovedește: un ssh, un sudo sau o gazdă reale; doar că șirul de comandă trimis de lansator se
execută corect sub modelul de mai sus și că nu tipărește «totul dovedit» când sumele nu se potrivesc.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from _su_shell import BASH, LAUNCHER, LIB_DIR, posix, write_exec

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

CD_GUARD = r'''cd() {
    if [[ "${FAKE_IS_ROOT:-}" != 1 ]]; then
        case "${1:-}" in
            "$FAKE_ROOT_ONLY"|"$FAKE_ROOT_ONLY"/*) echo "bash: cd: ${1}: Permission denied" >&2; return 1 ;;
        esac
    fi
    builtin cd "$@"
}
'''

SSH = """#!/usr/bin/env bash
cmd="${@: -1}"
printf '%s\\n' "$cmd" >> "$FAKE_SSH_LOG"
export BASH_ENV="$FAKE_CD_GUARD"
exec bash -c "$cmd"
"""

SUDO = """#!/usr/bin/env bash
export FAKE_IS_ROOT=1
[[ "${1:-}" == -n ]] && shift
case "$1" in
  install) mkdir -p "${@: -1}"; exit $? ;;   # modurile 0700 nu există pe NTFS; permisiunile le modelează cd-ul
  chmod) exit 0 ;;
  /usr/bin/bash) printf '%s\\n' "$*" >> "$FAKE_PHASE_LOG"; exit "$FAKE_REMOTE_RC" ;;
  tar) "$@"; rc=$?; [[ -z "${FAKE_CORRUPT:-}" ]] || printf 'x' >> "$FAKE_ROOT_ONLY/system-update-lib.sh"; exit $rc ;;
esac
exec "$@"
"""

# sha256sum din Git Bash scrie `hash *nume`; momeala o imită pe orice platformă, dar doar pentru
# partea LOCALĂ (pe „gazdă" — sub sudo — scrie ca Linux: două spații).
SHA = """#!/usr/bin/env bash
if [[ "${FAKE_IS_ROOT:-}" == 1 ]]; then exec /usr/bin/sha256sum "$@"; fi
/usr/bin/sha256sum "$@" | sed "s/  / */"
"""


def run_launcher(tmp: Path, *args: str, remote_rc: int = 0, stdin: str = "", corrupt: bool = False):
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    remote = tmp / "remote-bin"
    (tmp / "k").write_text("x", encoding="utf-8")
    (tmp / "cdguard.sh").write_text(CD_GUARD, encoding="utf-8", newline="\n")
    write_exec(bindir / "ssh", SSH)
    write_exec(bindir / "sudo", SUDO)
    write_exec(bindir / "sha256sum", SHA)
    env = dict(os.environ)
    env.update(PATH=f"{bindir}{os.pathsep}{env['PATH']}", FAKE_SSH_LOG=posix(tmp / "ssh.log"),
               FAKE_PHASE_LOG=posix(tmp / "phase.log"), FAKE_REMOTE_RC=str(remote_rc),
               FAKE_CD_GUARD=posix(tmp / "cdguard.sh"), FAKE_ROOT_ONLY=posix(remote),
               SU_REMOTE_BIN=posix(remote))
    if corrupt:
        env["FAKE_CORRUPT"] = "1"
    proc = subprocess.run([BASH, posix(LAUNCHER), "--host", "example.invalid", "--key", posix(tmp / "k"), *args],
                          input=stdin.encode(), capture_output=True, env=env, timeout=120)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    log = (tmp / "ssh.log").read_text(encoding="utf-8").splitlines() if (tmp / "ssh.log").exists() else []
    phase = (tmp / "phase.log").read_text(encoding="utf-8").splitlines() if (tmp / "phase.log").exists() else []
    return proc, out, log, phase, remote


def test_the_checksum_step_survives_a_root_only_directory(tmp_path):
    """Directorul de lucru de pe gazdă e root 0700. Un `cd` făcut ca `sentinel-deploy` cade cu
    Permission denied, iar lansatorul murea la pasul sumelor («nu pot citi sumele de pe gazdă») la
    FIECARE fază — nicio actualizare nu pornea. Comanda trimisă se execută aici sub modelul de
    permisiuni al gazdei, deci un `cd` în directorul root-only ar pica testul."""
    proc, out, log, phase, remote = run_launcher(tmp_path, "--phase", "verify")
    assert proc.returncode == 0, out
    assert "sumele SHA-256 coincid" in out
    assert any(l.endswith("system-update-host.sh' verify") for l in log), log
    assert phase and phase[0].endswith("system-update-host.sh verify"), phase
    assert {p.name for p in remote.iterdir()} >= {"system-update-host.sh", "system-update-lib.sh"}
    for f in remote.iterdir():
        assert hashlib.sha256(f.read_bytes()).hexdigest() == hashlib.sha256((LIB_DIR / f.name).read_bytes()).hexdigest()


def test_launcher_refuses_to_run_when_the_host_copy_does_not_hash_like_the_repo(tmp_path):
    """`tar` ieșit cu 0 nu dovedește că fișierul de pe gazdă are aceiași octeți (disc plin, fișier
    vechi rămas). Se rulează ca root: suma citită DE PE GAZDĂ trebuie să coincidă, altfel nu pornește
    nicio fază."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "verify", corrupt=True)
    assert proc.returncode == 1 and "NU sunt cele din depozit" in out
    assert phase == []


def test_launcher_forwards_the_phase_and_the_exit_code_and_quotes_arguments(tmp_path):
    """Codul 3 («n-am putut măsura») trebuie să ajungă la operator ca 3; argumentele merg către
    gazdă citate, iar faza reboot primește `--yes` doar de la lansator, după confirmare."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "containers", "--dry-run", "--rebuild", "a,b", remote_rc=3)
    assert proc.returncode == 3 and "NECUNOSCUT" in out
    assert len(phase) == 1 and phase[0].endswith("containers --dry-run --rebuild a,b")
    assert log[-1].endswith(r"containers --dry-run --rebuild a\,b"), log[-1]
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    p2, _, _, phase2, _ = run_launcher(tmp2, "--phase", "reboot", stdin="nu\n")
    assert p2.returncode != 0 and phase2 == []
    tmp3 = tmp_path / "c"
    tmp3.mkdir()
    p3, _, _, phase3, _ = run_launcher(tmp3, "--phase", "reboot", "--yes")
    assert p3.returncode == 0 and phase3 and phase3[0].endswith("reboot --yes")


def test_launcher_rejects_shell_metacharacters_and_unknown_phases_before_any_network(tmp_path):
    """Fiecare argument ajunge într-un șir de comandă ssh: un `;` ar fi o comandă pe gazda de
    producție, rulată ca root prin sudo. Refuzat local, înainte de orice conexiune."""
    for i, bad in enumerate((["--phase", "os", "x;reboot"], ["--phase", "os", "a b"], ["--phase", "nu-exista"],
                             ["--phase", "os", "$(id)"])):
        sub = tmp_path / f"t{i}"
        sub.mkdir()
        proc, out, log, _, _ = run_launcher(sub, *bad, "--yes")
        assert proc.returncode != 0 and log == [], (bad, out)


def test_phase_must_be_exactly_one_known_token(tmp_path):
    """`--phase "backup os"` trecea verificarea pe subșir și ajungea ca două nume într-un argument. Faza
    e exact UN cuvânt din listă; orice altceva e refuzat local, înainte de orice conexiune."""
    for i, bad in enumerate(("backup os", "os ", " os", "os;reboot", "OS", "")):
        sub = tmp_path / f"p{i}"
        sub.mkdir()
        proc, out, log, _, _ = run_launcher(sub, "--phase", bad, "--yes")
        assert proc.returncode != 0 and log == [], (bad, out)


def test_launcher_forwards_retry_failed_with_its_project_list_to_the_containers_phase(tmp_path):
    """`--retry-failed pg,clin` e singurul drum spre verde pentru un serviciu `failed`. Dacă lansatorul îl
    refuză (virgula în lista de caractere permise), îl pierde sau îl desparte de valoarea lui, operatorul
    nu mai poate debloca faza fără să intre pe gazdă. Ajunge la faza de pe gazdă exact ca două argumente
    consecutive, citat pentru ssh, după confirmarea cerută de faza containers."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "containers", "--retry-failed", "pg,clin", "--yes")
    assert proc.returncode == 0, out
    assert len(phase) == 1 and phase[0].endswith("containers --retry-failed pg,clin"), phase
    assert log[-1].endswith(r"containers --retry-failed pg\,clin"), log[-1]


@pytest.mark.parametrize("opt", ["--rebuild", "--accept-drift", "--only", "--retry-failed", "--acknowledge"])
def test_a_list_option_never_swallows_dry_run_so_a_mistyped_simulation_cannot_start_for_real(tmp_path, opt):
    """`--phase containers --rebuild --dry-run`: lansatorul vedea `--dry-run` între argumente și sărea confirmarea, iar gazda
    îl citea ca VALOARE a lui --rebuild și pornea rularea în serios (recreări de producție, fără nicio confirmare). Acum o
    listă care lipsește sau începe cu `-` se refuză aici: cod nenul, nicio conexiune ssh, nicio fază pornită."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "containers", opt, "--dry-run")
    assert proc.returncode != 0 and log == [] and phase == [], (out, log, phase)
    assert "nu s-a pornit nimic" in out
    sub = tmp_path / "missing"
    sub.mkdir()
    proc2, out2, log2, phase2, _ = run_launcher(sub, "--phase", "containers", opt)       # valoarea lipsește de tot
    assert proc2.returncode != 0 and log2 == [] and phase2 == [], out2
    # Același cod de ieșire, aceeași tăcere de rețea are și un EOF la întrebarea «Continui?» (stdin gol = «anulat»): testul de mai sus nu
    # deosebea refuzul valorii lipsă de o confirmare nedată. Refuzul se recunoaște după mesajul lui, iar confirmarea nu s-a cerut deloc.
    assert f"{opt} cere o listă de proiecte (lipsește valoarea)" in out2, out2
    assert "Continui?" not in out2 and "anulat" not in out2, out2


def test_the_launcher_decides_dry_run_like_the_host_does(tmp_path):
    """Un `--dry-run` real (și doar el) sare confirmarea. `--only pg --dry-run` e simulare; `--stable --dry-run` NU e: gazda
    citește `--dry-run` ca valoare a lui --stable (îl va refuza cu 2), iar lansatorul trebuie să ceară confirmarea, nu să
    presupună o simulare."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "containers", "--only", "pg", "--dry-run", "--rebuild", "pg")
    assert proc.returncode == 0 and phase and phase[0].endswith("containers --only pg --dry-run --rebuild pg"), (out, phase)
    sub = tmp_path / "stable"
    sub.mkdir()
    p2, o2, log2, phase2, _ = run_launcher(sub, "--phase", "containers", "--stable", "--dry-run")
    assert p2.returncode != 0 and phase2 == [], (o2, phase2)          # fără răspuns «da» la confirmare, nu pornește nimic


def test_launcher_forwards_acknowledge_with_its_project_service_keys(tmp_path):
    """`--acknowledge pg/db` e singura ieșire pentru un eșec preluat al unui serviciu care nu mai există. Dacă lansatorul îl refuză (bara `/` în lista
    de caractere permise), îl pierde sau îl desparte de valoarea lui, operatorul nu poate urma mesajul fără să intre pe gazdă. Ajunge ca două argumente
    consecutive, citat pentru ssh; fiind o rulare care schimbă gazda (nu `--dry-run`), cere confirmarea."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "containers", "--acknowledge", "pg/db,clin/app", "--yes")
    assert proc.returncode == 0, out
    assert len(phase) == 1 and phase[0].endswith("containers --acknowledge pg/db,clin/app"), phase


def test_the_launcher_never_calls_a_code_0_run_all_proven_without_the_acknowledged_case(tmp_path):
    """Codul 0 al gazdei înseamnă «nimic eșuat», nu «totul dovedit»: cu un `--acknowledge` în picioare, linia REZULTAT spune «DOVEDIT, cu N servicii recunoscute de
    operator» și serviciile rămân NERESOLVATE în fapt. Un lansator care ar tipări doar «totul dovedit» la cod 0 ar șterge exact acel cuvânt pe care operatorul îl
    citește la sfârșit (mutația V9), iar un `--help` care spune «0 = totul dovedit» la fel."""
    proc, out, log, phase, _ = run_launcher(tmp_path, "--phase", "verify")
    assert proc.returncode == 0, out
    line = [l for l in out.splitlines() if "cod 0" in l]
    assert line and "«DOVEDIT, cu N servicii recunoscute de operator»" in line[0] and "NERESOLVATE în fapt" in line[0], out
    sub = tmp_path / "help"
    sub.mkdir()
    helped = subprocess.run([BASH, posix(LAUNCHER), "--help"], capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
    assert "0 = totul dovedit;" not in helped and "DOVEDIT, cu N servicii recunoscute de operator" in helped, helped


def test_the_launcher_help_and_the_host_usage_say_that_gone_means_no_container_at_all(tmp_path):
    """Runda 12, decizia operatorului: «dispărut» = fără NICIUN container, în nicio stare. Textul din `--help` (X1, runda 11: mutația care scoate propoziția trecea) și
    antetul fazei de pe gazdă erau singurul loc în care operatorul citește când se închide un episod de la sine. Dacă spun «niciun container `running`» (sau tac), un
    operator ar crede că un container oprit ori în buclă se închide singur la un baseline nou — și ar lăsa un serviciu mort fără nicio urmă roșie. Ambele texte spun că
    `dispărut` = absent, că un container oprit/în buclă/în pauză/creat/mort NU a dispărut și că o listă goală nu închide nimic."""
    from _su_shell import HOST_SH

    helped = subprocess.run([BASH, posix(LAUNCHER), "--help"], capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
    assert "DISPĂRUT din baseline-ul nou (nu mai are niciun container, în nicio stare" in helped, helped
    assert "NU a dispărut: eșecul rămâne roșu" in helped and "listă de containere măsurată dar GOALĂ nu închide nimic" in helped, helped
    assert "niciun container `running`" not in helped, helped
    usage = subprocess.run([BASH, "-c", f"source '{posix(HOST_SH)}'; usage"], capture_output=True, timeout=60).stdout.decode("utf-8", "replace")
    assert "NICIUN container, în nicio stare" in usage and "NU a dispărut și rămâne roșu" in usage and "o listă măsurată dar goală e suspectă și nu închide nimic" in usage, usage
    assert "niciun container `running`" not in usage, usage
