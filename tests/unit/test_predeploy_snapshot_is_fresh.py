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


def _can_symlink(tmp: Path) -> bool:
    """Poate mașina asta să facă un simbolic către un director?

    Pe Windows fără elevare, nu — iar cele două teste care depind de el n-ar mai
    proba nimic dacă le-am slăbi ca să treacă. Sar VIZIBIL, cu motivul scris,
    fiindcă un test sărit în tăcere e mai rău decât unul care lipsește: pare
    acoperire.
    """
    tinta = tmp / "_probă_țintă"
    tinta.mkdir(exist_ok=True)
    try:
        (tmp / "_probă_legătură").symlink_to(tinta, target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    return True


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
                  tmp: Path) -> str:
    """Rulează BUCATA din `resolve_config` care alege calea instantaneului.

    Tăiată din fișierul livrat, nu rescrisă: un test care retipărește logica
    verifică copia lui, nu codul care ajunge pe gazdă.
    """
    text = INSTALL.read_text(encoding="utf-8")
    match = re.search(
        r"    # Stabilise the snapshot directory.*?\n    fi\n", text, re.S)
    assert match, "bucata care alege calea instantaneului nu a fost găsită"

    backup = tmp / "backups"
    backup.mkdir(exist_ok=True)
    if latest_points_to is not None:
        latest_points_to.mkdir(parents=True, exist_ok=True)
        (backup / "predeploy-latest").symlink_to(
            latest_points_to, target_is_directory=True)

    body = match.group(0).replace("local ", "")
    out = _sh(
        f'set -uo pipefail\n'
        f'SENTINEL_BACKUP_DIR="{_posix(backup)}"\n'
        f'SNAPSHOT_DIR="{_posix(backup)}/predeploy-PROASPAT"\n'
        f'FROM_STEP="{from_step}"\n'
        f'{body}\n'
        f'printf "%s" "$SNAPSHOT_DIR"\n')
    return out.stdout.strip()


def test_a_plain_deploy_keeps_its_own_fresh_snapshot_path(tmp_path) -> None:
    """Un deploy obișnuit NU moștenește instantaneul rulării anterioare.

    Simbolicul `predeploy-latest` există — e chiar situația de pe gazda reală,
    unde arăta spre un director din 31 iulie. Calea aleasă trebuie să rămână cea
    a rulării curente.
    """
    if not _can_symlink(tmp_path):
        pytest.skip("mașina nu poate crea simbolice către directoare "
                    "(Windows fără elevare); testul ar fi fără dinți")
    vechi = tmp_path / "backups" / "predeploy-20260730-120223"
    ales = _snapshot_dir(from_step="", latest_points_to=vechi, tmp=tmp_path)
    assert ales.endswith("predeploy-PROASPAT"), (
        f"deploy-ul a adoptat instantaneul vechi ({ales}) — comanda de rollback "
        f"pe care o tipărește ar restaura starea de atunci")


def test_a_resume_above_the_snapshot_step_does_adopt_the_existing_one(
        tmp_path) -> None:
    """`--from-step 30` sare peste pasul 18, deci trebuie să adopte simbolicul.

    Fără ramura asta, pașii 33 și 38 ar scrie și ar citi dintr-un director pe
    care nu l-a creat nimeni — chiar eșecul pentru care logica a fost scrisă
    inițial. Reparația îngustează condiția; nu o șterge.
    """
    if not _can_symlink(tmp_path):
        pytest.skip("mașina nu poate crea simbolice către directoare "
                    "(Windows fără elevare); testul ar fi fără dinți")
    vechi = tmp_path / "backups" / "predeploy-20260730-120223"
    ales = _snapshot_dir(from_step="30", latest_points_to=vechi, tmp=tmp_path)
    assert ales.endswith("predeploy-20260730-120223"), (
        f"o reluare peste pasul 18 nu a găsit instantaneul existent ({ales}); "
        f"pașii de nginx și de rollback ar scrie într-un director inexistent")


def test_a_resume_with_no_symlink_at_all_falls_back_to_the_fresh_path(
        tmp_path) -> None:
    """Fără simbolic, calea rămâne cea a rulării — nu goală, nu inventată."""
    ales = _snapshot_dir(from_step="30", latest_points_to=None, tmp=tmp_path)
    assert ales.endswith("predeploy-PROASPAT")
