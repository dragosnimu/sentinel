"""Harnașul comun al testelor pentru `scripts/lib/system-update-*.sh` — fără `test_` în nume,
ca pytest să nu-l colecteze.

Rulează codul LIVRAT (`scripts/lib/`), nu o copie rescrisă: un test care reimplementează
decizia dovedește reimplementarea, nu scriptul pe care îl rulează operatorul. Binarele pe
care codul le atinge (`docker`, `systemctl`, `flock`, `id`, `systemd-run`, `runuser`, `mysqldump`)
sunt momeli pe PATH, iar fiecare își notează apelurile într-un JURNAL: testele care promit
„nu schimbă nimic" citesc jurnalul, nu codul de ieșire.

Ce NU are mediul ăsta, și ce înseamnă asta pentru ce dovedesc testele:
  * un `docker`, `dnf`, `systemd` reale. Momeala de docker (`_fake_docker.py`) reproduce
    formele de ieșire MĂSURATE pe gazdă pe 19 noiembrie 2026 (doar citire): tiparul
    `\\unrestrict`/`--`/marcaj de la coada unui pg_dumpall 16, `-- Dump completed on` de la
    mariadb-dump 11.4, `docker inspect -f` cu câmpurile pe care le cere codul. Dacă gazda
    schimbă forma, testele rămân verzi — de aceea codul cere fiecare fapt din două locuri
    (antet ȘI coadă la dump-uri, ID de imagine ȘI moment de creare la containere);
  * un `flock` (Git Bash nu-l are): momeala întoarce 0, deci excluderea reciprocă a
    rulărilor NU e probată aici;
  * simboluri reale pe Windows: baseline-ul se așază cu `BASE=...` după `init_state`, nu
    prin legătura `current`, deci publicarea atomică a baseline-ului NU e probată aici.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB_DIR = ROOT / "scripts" / "lib"
HOST_SH = LIB_DIR / "system-update-host.sh"
LIB_SH = LIB_DIR / "system-update-lib.sh"
LAUNCHER = ROOT / "scripts" / "system-update.sh"
FAKE_DOCKER_PY = Path(__file__).with_name("_fake_docker.py")

BASH = shutil.which("bash")


def posix(p: Path | str) -> str:
    return Path(p).as_posix()


def write_exec(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_bin(tmp: Path, extra: dict[str, str] | None = None, *, docker: bool = False) -> Path:
    """Un director de momeli, pus în fața PATH-ului. `extra` = nume -> corp de script bash."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    write_exec(bindir / "id", '#!/usr/bin/env bash\n[[ "${1:-}" == -u ]] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')
    write_exec(bindir / "flock", "#!/usr/bin/env bash\nexit 0\n")
    if docker:
        # Înainte de a delega momelii Python, notează ce descriptori de blocare sunt DESCHIȘI în această comandă
        # (10-15): un copil care îi moștenește ar ține blocarea fazei după ce faza a ieșit.
        write_exec(bindir / "docker", (
            '#!/usr/bin/env bash\n'
            'if [[ -n "${FAKE_DOCKER_FDS:-}" ]]; then exec 3>&2 2>/dev/null; open=""; for n in 10 11 12 13 14 15; do true >&$n && open+="$n "; done; exec 2>&3 3>&-;'
            ' printf "%s|%s\\n" "$*" "$open" >> "$FAKE_DOCKER_FDS"; fi\n'
            f'exec "{posix(sys.executable)}" "{posix(FAKE_DOCKER_PY)}" "$@"\n'))
    for name, body in (extra or {}).items():
        write_exec(bindir / name, "#!/usr/bin/env bash\n" + body)
    return bindir


def env_for(tmp: Path, bindir: Path, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    env["SU_STATE"] = posix(tmp / "state")
    env["SU_RUN_DIR"] = posix(tmp / "run")
    env["SU_PYTHON"] = posix(sys.executable)
    env["SU_STABLE_S"] = "0"
    env["SU_POLL_S"] = "0"
    env["SU_GAP_S"] = "0"
    env["SU_FOLLOW_S"] = "0"
    env["FAKE_DOCKER_LOG"] = posix(tmp / "docker.log")
    env["FAKE_DOCKER_STATE"] = posix(tmp / "docker-state.json")
    env["FAKE_DOCKER_FDS"] = posix(tmp / "docker-fds.log")
    env["SU_MIN_BOOT_FILE_BYTES"] = "1000"
    env.update(extra)
    return env


def run_bash(script: str, env: dict[str, str] | None = None, cwd: Path | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess:
    """Rulează `script` într-un bash. Octeți bruți și decodare explicită, ca `\\r\\n` din
    modul text de pe Windows să nu schimbe ce citește `read -r`."""
    assert BASH, "bash lipsește din PATH, deci codul LIVRAT n-a fost rulat"
    proc = subprocess.run([BASH, "-c", script], capture_output=True, env=env or dict(os.environ),
                          cwd=str(cwd or ROOT), timeout=timeout)
    proc.stdout = proc.stdout.decode("utf-8", errors="replace")
    proc.stderr = proc.stderr.decode("utf-8", errors="replace")
    return proc


def lib_table(cases: list[tuple[str, str]]) -> dict[str, str]:
    """Rulează într-un SINGUR bash toate cazurile `(id, expresie)`; fiecare expresie tipărește
    un cuvânt. Un bash pe caz ar fi minute întregi pe Windows."""
    lines = [f"source '{posix(LIB_SH)}'"]
    for case_id, expr in cases:
        lines.append(f"printf '%s=%s\\n' '{case_id}' \"$({expr})\"")
    proc = run_bash("\n".join(lines))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    assert set(out) == {c for c, _ in cases}, f"tabelul n-a întors toate cazurile: {proc.stdout}{proc.stderr}"
    return out


def rc_of(expr: str, stdin: str = "") -> int:
    """Codul de ieșire al unei expresii din biblioteca de decizii."""
    script = f"source '{posix(LIB_SH)}'\n{expr}"
    assert BASH
    proc = subprocess.run([BASH, "-c", script], input=stdin.encode("utf-8"), capture_output=True)
    return proc.returncode


def host_run(tmp: Path, body: str, bindir: Path, **env_extra: str) -> subprocess.CompletedProcess:
    """Încarcă system-update-host.sh (fără să pornească `main`: garda BASH_SOURCE) și rulează
    `body` sub `set -euo pipefail`, ca scriptul real."""
    (tmp / "state").mkdir(exist_ok=True)
    (tmp / "run").mkdir(exist_ok=True)
    script = f"set -euo pipefail\nsource '{posix(HOST_SH)}'\n{body}\n"
    return run_bash(script, env_for(tmp, bindir, **env_extra))


def docker_state(tmp: Path, state: dict) -> None:
    (tmp / "docker-state.json").write_text(json.dumps(state), encoding="utf-8")


def docker_log(tmp: Path) -> list[list[str]]:
    p = tmp / "docker.log"
    if not p.exists():
        return []
    return [line.split("\t") for line in p.read_text(encoding="utf-8").splitlines() if line]
