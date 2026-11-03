"""Rollback-ul curăța doar `STATE_MARKERS` — calea VECHE supraviețuia.

Măsurat (R3-2, verificatorul, 8 sep 2026): pe o gazdă instalată de arborele
DINAINTE de 8 septembrie, marcajele de pas trăiau la
`${SENTINEL_STATE_DIR}/.install-state`, nu la calea nouă
(`SENTINEL_INSTALL_STATE_DIR`). `rollback.sh` ștergea doar
`${STATE_MARKERS}` (calea nouă) și lăsa `${SENTINEL_STATE_DIR}` intact —
inclusiv `.install-state`, care rămânea acolo. Atunci, o funcție de migrare din
`deploy/lib/common.sh` muta automat orice marcaj găsit acolo înapoi în
`STATE_MARKERS`; decizia de a o scoate e din 13 septembrie 2026
(`docs/ARHITECTURA.md`), iar proiectarea fără migrare a aterizat în `87db51a`.
Funcția nu apare în niciun `deploy/` comis — `git log --all -S` nu găsește
nimic — deci data e a deciziei, nu una pe care istoria o poate confirma.
Nimic din `deploy/` nu mai mută calea veche; vezi
`test_installer_state_markers.py`. Rămâne însă
o CITIRE: `nginx_preexisting_resolve` din `install.sh` mai ia din calea veche
faptul scris o singură dată și o linie din `preflight.env`, ca o gazdă
instalată de arborele vechi să-și păstreze răspunsul. Deci un `.install-state`
lăsat de un `--purge` ar da următoarei instalări răspunsul de ieri, pe o
gazdă despre care rollback-ul tocmai a raportat „curățat".

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
from _symlinks import is_link, present

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
@pytest.mark.parametrize("target_exists", [
    pytest.param(True, id="live"),
    pytest.param(False, id="dangling"),
])
def test_a_symlink_at_the_legacy_path_is_removed_without_following_it(tmp_path, make_link,
                                                                      target_exists):
    """Dacă `.install-state` a rămas un symlink (planted de `sentinel`, care
    deține părintele) către alt director real, `rm -rf` pe calea veche
    trebuie să șteargă LINKUL, nu conținutul țintei — un `rm -rf` care ar
    urma linkul (de pildă printr-un glob cu slash final) ar goli directorul
    țintă.

    Falsificat schimbând `rm -rf -- "${_LEGACY_STATE_MARKERS}"` într-o formă
    care urmează linkul (ex. adăugând `/` la coadă) — testul trebuie să vadă
    `victim/secret` dispărut.

    Pentru operator: un `--purge` care urmează linkul plantat golește un director
    care nu e al Sentinel (ca root), în loc să șteargă doar linkul și să raporteze
    „curățat".

    Linkul vine din `make_link` (tests/_symlinks.py): symlink adevărat unde se poate,
    altfel legătura proprie a runtime-ului MSYS, pe care `rm` din Git Bash o tratează
    ca pe un symlink (măsurat: `rm -rf L` șterge legătura și lasă ținta, `rm -rf L/`
    golește ținta — identic cu GNU rm pe WSL). Pe Windows fără privilegiu nu se sare,
    fiindcă garda ar rămâne fără observator. `legacy.exists()` din pathlib nu vede
    legătura MSYS, deci „linkul a dispărut" se întreabă bash-ului (`present`) — altfel
    aserțiunea ar fi adevărată oricum.

    Două forme ale aceleiași legături, fiindcă garda din `rollback.sh` are două clauze
    (`-e` și `-L`) și fiecare are nevoie de propriul observator. Legătura VIE (ținta
    există) e văzută de `-e`, deci aici clauza `-L` nu e exersată: ștergerea ei lasă
    testul verde. O legătură ATÂRNÂNDĂ (ținta lipsește: `-e` e fals, doar `-L` o prinde)
    e singura care o exersează — fără ea, `|| -L` se poate șterge și un `--purge` lasă
    legătura la calea veche, raportând „curățat". Falsificat scoțând `|| -L` din
    condiția din `rollback.sh`: forma `dangling` pică, `live` rămâne verde (de aceea
    sunt două forme, nu una). Parametrul schimbă doar ținta legăturii; aserțiunile
    formei `live` (ținta neatinsă, legătura dispărută) sunt aceleași ca înainte.
    """
    sentinel_state_dir = tmp_path / "sentinel_state"
    sentinel_state_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    secret = victim / "secret"
    if target_exists:
        victim.mkdir()
        secret.write_text("root ALL=(ALL) ALL\n", encoding="utf-8", newline="\n")

    legacy = sentinel_state_dir / ".install-state"
    make_link(legacy, victim)
    assert is_link(legacy) and present(victim) == target_exists, (
        "precondiția: legătura trebuie să fie vie în forma `live` și atârnândă în `dangling` — "
        "altfel forma `dangling` ar rula a doua oară cazul viu și clauza `-L` ar rămâne neexersată")

    install_state_dir = tmp_path / "install_state"
    install_state_dir.mkdir(parents=True)

    proc = _run(_harness(tmp_path, sentinel_state_dir, install_state_dir), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not present(legacy), "linkul n-a fost șters"
    if target_exists:
        assert secret.read_text(encoding="utf-8") == "root ALL=(ALL) ALL\n", (
            "conținutul directorului țintit de symlink a fost șters — linkul a fost urmat")
