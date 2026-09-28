"""Rollback-ul curăța doar `STATE_MARKERS` — calea VECHE supraviețuia.

Măsurat (R3-2, verificatorul, 8 sep 2026): pe o gazdă instalată de arborele
DINAINTE de 8 septembrie, marcajele de pas trăiau la
`${SENTINEL_STATE_DIR}/.install-state`, nu la calea nouă
(`SENTINEL_INSTALL_STATE_DIR`). `rollback.sh` ștergea doar
`${STATE_MARKERS}` (calea nouă) și lăsa `${SENTINEL_STATE_DIR}` intact —
inclusiv `.install-state`, care rămânea acolo. La următoarea instalare,
`migrate_legacy_state_markers` din `deploy/lib/common.sh` mută automat orice
marcaj legitim găsit acolo înapoi în `STATE_MARKERS` — deci o instalare de
după `--purge`, care a scos un rol prin rollback, ar sări din nou pașii al
căror marcaj tocmai a fost readus, pe o gazdă despre care rollback-ul tocmai
a raportat „curățat".

Reparația: rollback.sh șterge acum și calea veche, folosind constanta
LITERALĂ `_LEGACY_STATE_MARKERS` din `deploy/lib/common.sh` (sourced de
rollback.sh), nu o recalculare proprie care ar putea diverge dacă acea cale
se mai mută vreodată.

Testele de aici rulează EXACT fragmentul livrat din `deploy/rollback.sh`
(decupat între aceleași marcaje folosite la scriere), nu o reimplementare.
"""
from __future__ import annotations

import os
import re
import shutil
import stat as stat_module
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ROLLBACK_SH = REPO / "deploy" / "rollback.sh"
ROLLBACK = ROLLBACK_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipsește din PATH — netestat, nu curat")]


def _p(path: Path) -> str:
    return str(path).replace("\\", "/")


def _cleanup_snippet() -> str:
    """Fragmentul EXACT livrat din `rollback.sh`: de la comentariul care
    precede curățarea lui `STATE_MARKERS` până la `fi`-ul care închide
    curățarea căii vechi — nu tot scriptul, care ar cere `nft`, `systemctl`,
    `sudo -u postgres` reale."""
    start_marker = "# Done here, at the very end,"
    end_marker = 'section "Rollback complet"'
    start = ROLLBACK.index(start_marker)
    end = ROLLBACK.index(end_marker)
    assert 0 < start < end, "rollback.sh nu mai are marcajele pe care testul le decupează"
    return ROLLBACK[start:end]


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    harness = tmp_path / "harness.sh"
    harness.write_text(script, encoding="utf-8", newline="\n")
    env = {**os.environ, "NO_COLOR": "1"}
    return subprocess.run(
        [BASH, _p(harness)], cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )


def _harness(tmp_path: Path, sentinel_state_dir: Path, install_state_dir: Path) -> str:
    return (
        "set -euo pipefail\n"
        f'export SENTINEL_STATE_DIR="{_p(sentinel_state_dir)}"\n'
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(install_state_dir)}"\n'
        "source ./lib/common.sh\n"
        + _cleanup_snippet()
        + '\necho "SNIPPET_DONE"\n'
    )


# ---------------------------------------------------------------------------
# Cazul confirmat: calea veche supraviețuia rollback-ului
# ---------------------------------------------------------------------------
def test_rollback_removes_the_legacy_state_markers_directory_too(tmp_path):
    """Reparația R3-2, direct: un `.install-state` rămas de la o instalare
    veche trebuie șters de rollback, nu doar calea nouă.

    Falsificat scoțând blocul nou (curățarea `_LEGACY_STATE_MARKERS`) din
    `rollback.sh` — testul trebuie să vadă directorul vechi supraviețuind.
    """
    sentinel_state_dir = tmp_path / "sentinel_state"
    legacy = sentinel_state_dir / ".install-state"
    legacy.mkdir(parents=True)
    (legacy / "22_postgres").write_text("2026-01-01T00:00:00Z\n", encoding="utf-8", newline="\n")

    install_state_dir = tmp_path / "install_state"
    install_state_dir.mkdir(parents=True)
    (install_state_dir / "33_nginx").write_text("x\n", encoding="utf-8", newline="\n")

    proc = _run(_harness(tmp_path, sentinel_state_dir, install_state_dir), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SNIPPET_DONE" in proc.stdout, proc.stdout + proc.stderr
    assert not legacy.exists(), (
        "directorul vechi de marcaje (.install-state) a supraviețuit rollback-ului — "
        "următoarea instalare le mută înapoi și sare pași care tocmai au fost anulați")


def test_rollback_still_removes_the_new_state_markers_directory(tmp_path):
    """Regresie: blocul EXISTENT (calea nouă) nu trebuie stricat de adăugarea
    celui nou pentru calea veche."""
    sentinel_state_dir = tmp_path / "sentinel_state"
    sentinel_state_dir.mkdir(parents=True)

    install_state_dir = tmp_path / "install_state"
    install_state_dir.mkdir(parents=True)
    (install_state_dir / "33_nginx").write_text("x\n", encoding="utf-8", newline="\n")

    proc = _run(_harness(tmp_path, sentinel_state_dir, install_state_dir), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not install_state_dir.exists(), \
        "STATE_MARKERS (calea nouă) n-a mai fost șters — regresie pe blocul existent"


def test_rollback_legacy_cleanup_is_a_no_op_when_nothing_legacy_exists(tmp_path):
    """Nicio cale veche pe gazda asta (instalată deja cu arborele nou) —
    fragmentul nu are voie să pice sub `set -euo pipefail` doar fiindcă
    directorul nu există."""
    sentinel_state_dir = tmp_path / "sentinel_state"
    sentinel_state_dir.mkdir(parents=True)   # SENTINEL_STATE_DIR există; .install-state NU

    install_state_dir = tmp_path / "install_state"
    install_state_dir.mkdir(parents=True)

    proc = _run(_harness(tmp_path, sentinel_state_dir, install_state_dir), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SNIPPET_DONE" in proc.stdout, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# `rm -rf` pe un symlink șterge linkul, nu urmează ținta
# ---------------------------------------------------------------------------
def _symlink_capable(tmp_path: Path) -> bool:
    """Sondă reală, nu presupunere: pe Windows fără
    `SeCreateSymbolicLinkPrivilege`, `Path.symlink_to` ridică `OSError`."""
    target = tmp_path / "_symprobe_target"
    link = tmp_path / "_symprobe_link"
    target.mkdir()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return False
    return link.is_symlink()


def test_a_symlink_at_the_legacy_path_is_removed_without_following_it(tmp_path):
    """Dacă `.install-state` a rămas un symlink (planted de `sentinel`, care
    deține părintele) către alt director real, `rm -rf` pe calea veche
    trebuie să șteargă LINKUL, nu conținutul țintei — un `rm -rf` care ar
    urma linkul (de pildă printr-un glob cu slash final) ar goli directorul
    țintă.

    Falsificat schimbând `rm -rf -- "${_LEGACY_STATE_MARKERS}"` într-o formă
    care urmează linkul (ex. adăugând `/` la coadă) — testul trebuie să vadă
    `victim/secret` dispărut.
    """
    if not _symlink_capable(tmp_path):
        pytest.skip("mediul ăsta nu poate crea symlinkuri reale (fără "
                    "SeCreateSymbolicLinkPrivilege) — netestat, nu curat")

    sentinel_state_dir = tmp_path / "sentinel_state"
    sentinel_state_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "secret").write_text("root ALL=(ALL) ALL\n", encoding="utf-8", newline="\n")

    legacy = sentinel_state_dir / ".install-state"
    legacy.symlink_to(victim, target_is_directory=True)

    install_state_dir = tmp_path / "install_state"
    install_state_dir.mkdir(parents=True)

    proc = _run(_harness(tmp_path, sentinel_state_dir, install_state_dir), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not legacy.exists() and not legacy.is_symlink(), "linkul n-a fost șters"
    assert (victim / "secret").read_text(encoding="utf-8") == "root ALL=(ALL) ALL\n", (
        "conținutul directorului țintit de symlink a fost șters — linkul a fost urmat")
