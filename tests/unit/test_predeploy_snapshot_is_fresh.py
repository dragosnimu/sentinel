"""Instantaneul de pre-deploy trebuie să fie de dinaintea ACESTUI deploy.

Eșecul pe care îl previne, în termeni de ce se strică pentru operator: instalarea
se termină, tipărește o comandă de rollback, iar comanda aia readuce gazda la o
stare de acum trei săptămâni. E mai rău decât să nu existe rollback — un rollback
lipsă se vede, unul învechit se citește ca plasă de siguranță.

Măsurat pe 21 august 2026: deploy-ul a anunțat
`Snapshot: …/predeploy-20260730-120223`, iar toate fișierele din el erau datate
31 iulie. Două mecanisme se compuneau, și fiecare părea rezonabil singur:

  1. pasul 18 era marcat „făcut" din prima instalare, deci sărit definitiv;
  2. `resolve_config` rescria calea instantaneului cu ținta simbolicului
     `predeploy-latest` — potrivit pentru o rulare întreruptă și reluată, greșit
     pentru un deploy nou peste săptămâni, fiindcă simbolicul supraviețuiește
     rulării care l-a făcut.

Nimic nu raporta o eroare. Instalarea era verde de la un capăt la altul.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "deploy" / "install.sh"
COMMON = ROOT / "deploy" / "lib" / "common.sh"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")


def _sh(script: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True)


def _posix(p: Path) -> str:
    return str(p).replace("\\", "/")


def test_the_snapshot_step_reruns_even_when_it_is_marked_done() -> None:
    """Pasul 18 rulează la fiecare deploy, chiar marcat „făcut".

    Se rulează `run_step` REAL, luat din `common.sh`, cu un director de stare în
    care marcajul există deja. Dacă `snapshot` iese din `ALWAYS_STEPS`, corpul nu
    mai e chemat și testul pică — adică exact regresia din august.
    """
    out = _sh(
        f'set -euo pipefail\n'
        f'export SENTINEL_STATE_DIR="$(mktemp -d)"\n'
        # SENTINEL_INSTALL_STATE_DIR alături de SENTINEL_STATE_DIR: STATE_MARKERS
        # vine din primul, nu din al doilea, de la 8 sep 2026 — common.sh moare
        # dacă vede starea redirecționată fără ca directorul de instalare s-o
        # urmeze, ca acest harness să nu scrie în /var/lib/sentinel-install REAL
        # pe o mașină unde rulează ca root.
        f'export SENTINEL_INSTALL_STATE_DIR="$(mktemp -d)"\n'
        f'source "{_posix(COMMON)}"\n'
        f'mkdir -p "$STATE_MARKERS"; touch "$STATE_MARKERS/18_snapshot"\n'
        f'step_done 18_snapshot || {{ echo "PREGATIRE-GRESITA"; exit 1; }}\n'
        f'corp() {{ echo "CORPUL-A-RULAT"; }}\n'
        f'run_step 18 snapshot corp\n')
    assert "PREGATIRE-GRESITA" not in out.stdout, (
        "marcajul nu s-a scris, deci testul n-ar fi probat nimic")
    assert "CORPUL-A-RULAT" in out.stdout, (
        "pasul de instantaneu a fost sărit fiindcă era marcat ca deja făcut, "
        f"deci deploy-ul ar anunța un punct de restaurare vechi. "
        f"Ieșire: {out.stdout!r} {out.stderr!r}")


def test_a_step_that_is_not_always_is_still_skipped_when_done() -> None:
    """Cealaltă jumătate a aceleiași aserțiuni.

    Fără ea, un `ALWAYS_STEPS` care ar conține din greșeală tot ar face testul de
    mai sus să treacă degeaba: n-ar mai proba nimic despre `snapshot`.
    """
    out = _sh(
        f'set -euo pipefail\n'
        f'export SENTINEL_STATE_DIR="$(mktemp -d)"\n'
        # SENTINEL_INSTALL_STATE_DIR alături de SENTINEL_STATE_DIR: STATE_MARKERS
        # vine din primul, nu din al doilea, de la 8 sep 2026 — common.sh moare
        # dacă vede starea redirecționată fără ca directorul de instalare s-o
        # urmeze, ca acest harness să nu scrie în /var/lib/sentinel-install REAL
        # pe o mașină unde rulează ca root.
        f'export SENTINEL_INSTALL_STATE_DIR="$(mktemp -d)"\n'
        f'source "{_posix(COMMON)}"\n'
        f'mkdir -p "$STATE_MARKERS"; touch "$STATE_MARKERS/29_nftables"\n'
        f'corp() {{ echo "CORPUL-A-RULAT"; }}\n'
        f'run_step 29 nftables corp\n')
    assert "CORPUL-A-RULAT" not in out.stdout, (
        "un pas idempotent a re-rulat: `ALWAYS_STEPS` a devenit prea larg, iar "
        "re-crearea tabelei nftables golește seturile — adică deblochează tăcut "
        "fiecare atacator blocat acum")


# ---------------------------------------------------------------------------
# A doua jumătate: ce cale primește instantaneul
# ---------------------------------------------------------------------------

def _snapshot_dir(from_step: str, latest_points_to: Path | None,
                  tmp: Path, make_link=None) -> str:
    """Rulează BUCATA din `resolve_config` care alege calea instantaneului.

    Tăiată din fișierul livrat, nu rescrisă: un test care retipărește logica
    verifică copia lui, nu codul care ajunge pe gazdă.

    Simbolicul `predeploy-latest` vine din `make_link` (tests/_symlinks.py): un
    symlink adevărat unde se poate, altfel legătura proprie a runtime-ului MSYS,
    pe care `[[ -L ]]` și `readlink -f` din bash o văd ca pe un symlink spre un
    director. Pe Windows fără elevare testele cu simbolic NU mai sar — sărite, ar fi
    lăsat condiția `FROM_STEP > 18` fără niciun observator.
    """
    text = INSTALL.read_text(encoding="utf-8")
    match = re.search(
        r"    # Stabilise the snapshot directory.*?\n    fi\n", text, re.S)
    assert match, "bucata care alege calea instantaneului nu a fost găsită"

    backup = tmp / "backups"
    backup.mkdir(exist_ok=True)
    if latest_points_to is not None:
        latest_points_to.mkdir(parents=True, exist_ok=True)
        make_link(backup / "predeploy-latest", latest_points_to)

    body = match.group(0).replace("local ", "")
    out = _sh(
        f'set -uo pipefail\n'
        f'SENTINEL_BACKUP_DIR="{_posix(backup)}"\n'
        f'SNAPSHOT_DIR="{_posix(backup)}/predeploy-PROASPAT"\n'
        f'FROM_STEP="{from_step}"\n'
        f'{body}\n'
        f'printf "%s" "$SNAPSHOT_DIR"\n')
    return out.stdout.strip()


def test_a_plain_deploy_keeps_its_own_fresh_snapshot_path(tmp_path, make_link) -> None:
    """Un deploy obișnuit NU moștenește instantaneul rulării anterioare.

    Simbolicul `predeploy-latest` există — e chiar situația de pe gazda reală,
    unde arăta spre un director din 31 iulie. Calea aleasă trebuie să rămână cea
    a rulării curente.

    Falsificat făcând condiția din `resolve_config` mereu adevărată (scoțând
    `FROM_STEP > 18`): deploy-ul adoptă instantaneul vechi și testul trebuie să-l vadă.
    """
    vechi = tmp_path / "backups" / "predeploy-20260730-120223"
    ales = _snapshot_dir(from_step="", latest_points_to=vechi, tmp=tmp_path,
                         make_link=make_link)
    assert ales.endswith("predeploy-PROASPAT"), (
        f"deploy-ul a adoptat instantaneul vechi ({ales}) — comanda de rollback "
        f"pe care o tipărește ar restaura starea de atunci")


def test_a_resume_above_the_snapshot_step_does_adopt_the_existing_one(
        tmp_path, make_link) -> None:
    """`--from-step 30` sare peste pasul 18, deci trebuie să adopte simbolicul.

    Fără ramura asta, pașii 33 și 38 ar scrie și ar citi dintr-un director pe
    care nu l-a creat nimeni — chiar eșecul pentru care logica a fost scrisă
    inițial. Reparația îngustează condiția; nu o șterge.

    Falsificat scoțând adoptarea (`SNAPSHOT_DIR="$resolved"`) din `resolve_config` —
    reluarea ar rămâne pe calea proaspătă, inexistentă, și testul trebuie să o vadă.
    """
    vechi = tmp_path / "backups" / "predeploy-20260730-120223"
    ales = _snapshot_dir(from_step="30", latest_points_to=vechi, tmp=tmp_path,
                         make_link=make_link)
    assert ales.endswith("predeploy-20260730-120223"), (
        f"o reluare peste pasul 18 nu a găsit instantaneul existent ({ales}); "
        f"pașii de nginx și de rollback ar scrie într-un director inexistent")


def test_a_resume_with_no_symlink_at_all_falls_back_to_the_fresh_path(
        tmp_path) -> None:
    """Fără simbolic, calea rămâne cea a rulării — nu goală, nu inventată."""
    ales = _snapshot_dir(from_step="30", latest_points_to=None, tmp=tmp_path)
    assert ales.endswith("predeploy-PROASPAT")
