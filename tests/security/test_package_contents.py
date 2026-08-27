"""Ce ajunge în pachetul de deploy — citit din arhivă, nu din lista de excluderi.

O listă de `--exclude` e o intenție. Arhiva e efectul. Distincția e tot rostul
fișierului ăstuia, și e aceeași cu cea din `CLAUDE.md`: un `--exclude` scris
greșit, pus după `-czf`, sau un tipar care nu se potrivește cu forma numelui din
arhivă (`./scratchpad` față de `scratchpad`) iese cu 0 și produce un pachet care
conține exact ce credeai că ai scos.

Deci testele de aici **construiesc o arhivă cu comanda `tar` decupată din
`scripts/deploy.sh`** și se uită în ea cu `tar -tzf`. Comanda e decupată, nu
rescrisă: un harness care reimplementează ce verifică a trecut deja verde peste
cod rupt în depozitul ăsta.

## De ce scratchpad/ e cazul care a cerut fișierul

Acolo își țin harness-urile de falsificare copiile de lucru — instantanee `.bak`
ale lui `install.sh`, `config.py`, `signing.py`, `beacon.py`. Trei motive
separate pentru care nu are voie să plece nicăieri, și plafonul de 20 MB nu vede
niciunul:

* e sursă pe care nimic de pe gazdă nu o rulează;
* e o A DOUA copie a unor fișiere a căror unicitate e chiar ideea;
* un harness rămas acolo poate fi rulat mai târziu peste un arbore mai nou — ceea
  ce a stricat arborele de lucru de două ori în timpul lui E2.2.

## Cealaltă jumătate: ce TREBUIE să plece

Un test care verifică doar excluderile e un test pe care îl treci excluzând tot.
Aceleași arhive se verifică și pentru prezența fișierelor fără de care
instalarea nu are ce rula — inclusiv `deploy/tools/`, care e sub `deploy/` și
NU are voie să fie prins de vreo excludere lăsată prea largă.

Și `.claude/skills` cu `.claude/agents`, care sunt cazul trăit: un
`--exclude='./.claude'` cerut din grabă a tăiat sursa lui
`cp -r "${SRC_ROOT}/.claude/skills"` din pasul 25 al instalării. Nimic de aici
nu acoperea dependența aia, deci excluderea a trecut de suită și a murit pe
gazdă, la instalare.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"
INSTALL_SH = REPO / "deploy" / "install.sh"

#: Sursa fiecărui `cp -r` din pasul 25, adică ce trebuie să fie în arhivă.
_CP_DIN_ARHIVA = re.compile(r'cp\s+-r\s+"\$\{SRC_ROOT\}/([^"]+)"')

BASH = shutil.which("bash")
TAR = shutil.which("tar")

needs_bash = pytest.mark.skipif(BASH is None, reason="no bash on PATH")
needs_tar = pytest.mark.skipif(TAR is None, reason="no tar on PATH")


# Un depozit în miniatură: câte un fișier din fiecare loc care contează. Nu o
# copie a depozitului real — testul trebuie să pice fiindcă s-a schimbat
# excluderea, nu fiindcă a apărut un director nou în arbore.
FAKE_REPO: dict[str, bytes] = {
    # Trebuie să plece.
    "deploy/install.sh": b"#!/usr/bin/env bash\nexit 0\n",
    "deploy/systemd/sentinel-shipper.service": b"[Unit]\n",
    "deploy/tools/manifest.txt": b"sha256  ceva\n",
    "deploy/config/sentinel.yaml.tmpl": b"ship:\n  enabled: false\n",
    "sentinel/report/shipper.py": b"# expeditorul\n",
    "executor/policy.py": b"# politica\n",
    "scripts/smoke-test.sh": b"#!/usr/bin/env bash\n",
    "requirements.txt": b"httpx\n",
    "VERSION": b"1.0.0\n",
    # Pasul 25 al instalării le copiază DIN arhivă în spațiul de lucru al
    # CLI-ului headless de pe gazdă.
    ".claude/skills/sentinel-soc/SKILL.md": b"# skill\n",
    ".claude/skills/sentinel-soc/scripts/health_snapshot.py":
        b"#!/usr/bin/env python3\n",
    ".claude/agents/code-writer.md": b"# scriitorul\n",
    # Nu are voie să plece.
    "scratchpad/e22-shipper/falsify.py": b"# harness\n",
    "scratchpad/e22-shipper/backup/sentinel__config.py": b"# copie de lucru\n",
    "scratchpad/README.md": b"scratch\n",
    "secrets/.env.local": b"SENTINEL_DB_PASSWORD=nu\n",
    "tests/unit/test_shipper.py": b"# teste\n",
    "docs/DEPLOYMENT.md": b"# doc\n",
    "watcher/lib/verify.ts": b"// martorul\n",
    "aggregator/migrations/0001_core.sql": b"-- @guard table instances\n",
    "sentinel/__pycache__/config.cpython-310.pyc": b"\x00",
    "sentinel/config.pyc": b"\x00",
    ".git/config": b"[core]\n",
    ".claude/worktrees/sesiune/deploy/install.sh": b"#!/usr/bin/env bash\n",
}


def _sub_calea(names: list[str], prefix: str) -> list[str]:
    """Numele din arhivă aflate sub `prefix`, unde `prefix` poate fi o CALE.

    `n.split("/")[0] == prefix` mergea cât timp fiecare excludere era un
    director de la rădăcină. `.claude/worktrees` nu e, iar o comparație pe
    primul segment n-ar fi găsit niciodată nimic acolo — adică ar fi raportat
    „nimic scurs" despre o excludere ștearsă cu totul.
    """
    return [n for n in names if n == prefix or n.startswith(prefix + "/")]


def _posix(path: Path) -> str:
    """O cale pe care tar-ul din bash o acceptă.

    Tar-ul din Git Bash citește `C:\\Users\\...` ca gazdă la distanță și moare cu
    „Cannot connect to C:" — un eșec care nu are nimic de-a face cu excluderile.
    """
    if os.name != "nt":
        return str(path)
    cygpath = shutil.which("cygpath")
    if cygpath is None:
        return path.as_posix()
    out = subprocess.run([cygpath, "-u", str(path)], capture_output=True, text=True)
    return out.stdout.strip() or path.as_posix()


def lift_tar_command() -> str:
    """Comanda `tar` de împachetare, decupată verbatim din deploy.sh.

    Decupată, nu rescrisă. O copie a listei de excluderi într-un test e încă o
    listă care poate să nu fie de acord cu cea livrată — adică exact clasa de
    defect pe care fișierul ăsta există s-o închidă.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    match = re.search(r"^tar --exclude=.*?-czf \"\$TARBALL\" -C \"\$REPO_ROOT\" \.$",
                      text, re.S | re.M)
    assert match, "deploy.sh no longer builds the package with a tar command this test can lift"
    return match.group(0)


def build_package(workdir: Path, members: dict[str, bytes] | None = None) -> list[str]:
    """Numele din arhiva produsă de comanda livrată, normalizate fără `./`."""
    stage = workdir / "repo"
    for rel, data in (members or FAKE_REPO).items():
        target = stage / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    tarball = workdir / "pkg.tar.gz"

    script = (
        "set -eu\n"
        f'TARBALL="{_posix(tarball)}"\n'
        f'REPO_ROOT="{_posix(stage)}"\n'
        + lift_tar_command() + "\n"
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert proc.returncode == 0, proc.stdout + proc.stderr

    with tarfile.open(tarball, "r:gz") as tf:
        names = tf.getnames()
    return [n[2:] if n.startswith("./") else n for n in names]


@pytest.fixture(scope="module")
def packaged(tmp_path_factory) -> list[str]:
    """O singură arhivă pentru tot fișierul.

    `tar` de paisprezece ori peste același arbore fabricat costă timp și nu
    dovedește nimic în plus: toate aserțiunile de mai jos privesc ACEEAȘI listă
    de nume, produsă de aceeași comandă.
    """
    if BASH is None or TAR is None:
        pytest.skip("no bash/tar on PATH")
    return build_package(tmp_path_factory.mktemp("pkg"))


# ---------------------------------------------------------------------------
# Ce nu are voie să plece
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
def test_the_verification_scratch_never_reaches_the_server(packaged):
    """Harness-urile de falsificare și copiile lor `.bak` nu au ce căuta în pachet.

    Trei riscuri distincte, niciunul văzut de plafonul de 20 MB: sursă pe care
    nimic de pe gazdă nu o rulează; a doua copie a unor fișiere a căror unicitate
    e chiar ideea (`install.sh`, `signing.py`); și un harness care poate fi rulat
    mai târziu, cu un manifest vechi, peste un arbore mai nou — ceea ce a
    clobberit arborele de lucru de două ori în E2.2.

    Verificat pe ARHIVĂ. O aserțiune pe lista de excluderi ar trece și peste un
    `--exclude` pus după `-czf`, care nu exclude nimic și iese cu 0.
    """
    leaked = _sub_calea(packaged, "scratchpad")
    assert leaked == [], f"pachetul conține scratchpad/: {leaked}"


@needs_bash
@needs_tar
@pytest.mark.parametrize("prefix",
                         ["secrets", "tests", "docs", "watcher", "aggregator",
                          ".git", ".claude/worktrees"])
def test_what_was_already_excluded_stays_excluded(packaged, prefix):
    """Adăugarea unei excluderi nu are voie să strice pe celelalte.

    `secrets/` e cel care contează: un tarball aterizează în /tmp pe server și
    rămâne acolo. Secretele circulă doar pe stdin.

    `aggregator/` e cel adăugat ultimul, și e acolo din același motiv ca
    `watcher/`: rulează pe găzduirea externă, iar valoarea lui e că ține arhiva
    a ce a plecat de pe mașina asta. O copie a schemei lui pe gazda arhivată nu
    e o scurgere de secrete, dar e o hartă a arhivei pe chiar mașina de la care
    arhiva se apără — și nimic din `deploy/` sau `sentinel/` nu o citește.

    `.claude/worktrees` e singura parte din `.claude/` care nu pleacă, și
    îngustimea aia e tot rostul liniei. Un worktree de agent e un al doilea
    checkout al depozitului — 6,6 MB față de 228 KB de skills — deci el e ce ar
    împinge arhiva peste `PACKAGE_MAX_KB`. Restul lui `.claude/` TREBUIE să
    plece, fiindcă pasul 25 al instalării copiază din arhivă `.claude/skills` și
    `.claude/agents`; `--exclude='./.claude'` a fost cerut o dată și a omorât
    instalarea acolo (`cp: cannot stat`, ieșire 1). Vezi
    `test_the_package_carries_what_step_25_copies_out_of_it`, care păzește
    direcția cealaltă.
    """
    leaked = _sub_calea(packaged, prefix)
    assert leaked == [], f"pachetul conține {prefix}/: {leaked}"


@needs_bash
@needs_tar
def test_compiled_python_does_not_travel(packaged):
    """`.pyc` dintr-un arbore Windows nu se potrivește cu interpretorul gazdei, iar
    un `__pycache__` vechi lângă o sursă nouă e chiar felul în care CPython ajunge
    să ruleze cod pe care nimeni nu-l mai are pe disc."""
    assert not [n for n in packaged if n.endswith(".pyc") or "__pycache__" in n], packaged


# ---------------------------------------------------------------------------
# Ce TREBUIE să plece — jumătatea fără de care testele de mai sus se trec
# excluzând tot
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
@pytest.mark.parametrize("member", [
    "deploy/install.sh",
    "deploy/systemd/sentinel-shipper.service",
    "deploy/tools/manifest.txt",
    "deploy/config/sentinel.yaml.tmpl",
    "sentinel/report/shipper.py",
    "executor/policy.py",
    "scripts/smoke-test.sh",
    "requirements.txt",
    "VERSION",
])
def test_what_the_installer_needs_is_still_in_the_package(packaged, member):
    """Cealaltă direcție, și cea care se uită ușor.

    O excludere prea largă nu produce un mesaj: produce un install care moare
    târziu, pe gazdă, la un fișier care lipsește. `deploy/tools/` e cazul cel mai
    aproape de margine — e sub `deploy/`, care pleacă întreg, deci orice tipar
    scris mai lax decât `./scratchpad` l-ar putea prinde.
    """
    assert member in packaged, f"{member} nu mai e în pachet"


def _ce_scoate_pasul_25_din_arhiva() -> list[str]:
    """Căile pe care pasul 25 le copiază DIN arhivă, citite din `install.sh`.

    Citite, nu scrise a doua oară aici: o listă copiată într-un test e încă o
    listă care poate să nu fie de acord cu instalatorul livrat — exact clasa de
    defect pe care fișierul ăsta o închide pentru excluderi.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    corp = text[text.index("step_claude_workspace() {"):]
    corp = corp[:corp.index("\n}\n")]
    cai = _CP_DIN_ARHIVA.findall(corp)
    assert cai, (
        "n-am găsit niciun `cp -r \"${SRC_ROOT}/…\"` în `step_claude_workspace` "
        "din deploy/install.sh; dacă pasul 25 a fost rescris, testul de mai jos "
        "nu mai verifică nimic și trebuie rescris odată cu el")
    return cai


@needs_bash
@needs_tar
def test_the_package_carries_what_step_25_copies_out_of_it(packaged):
    """Ce copiază instalarea din arhivă trebuie să fie ÎN arhivă.

    Eșecul pe care îl previne, trăit pe 26 august 2026: s-a cerut
    `--exclude='./.claude'` „ca să nu plece starea de lucru a agenților".
    `step_claude_workspace` face `cp -r "${SRC_ROOT}/.claude/skills"` și la fel
    pentru `agents`, unde `SRC_ROOT` e chiar arhiva asta dezarhivată. Excluderea
    a tăiat sursa acelui `cp`, iar cu `set -euo pipefail` instalarea a murit la
    pasul 25 cu `cp: cannot stat`, ieșire 1. Nicio aserțiune din depozit nu
    atingea dependența, deci schimbarea a trecut verde și a picat pe gazdă.

    Și previne reparația greșită a aceluiași lucru: dacă cineva face `cp`-ul
    tolerant, instalarea trece, iar CLI-ul Claude de pe server rămâne fără skill
    și fără cele șase definiții de agenți — generarea planurilor de patch,
    `/ask` și dosarele de incident dispar fără ca nimic să raporteze un defect.
    Aici se verifică arhiva, adică sursa acelui `cp`, nu toleranța lui.
    """
    for cale in _ce_scoate_pasul_25_din_arhiva():
        continut = _sub_calea(packaged, cale)
        assert continut, (
            f"pasul 25 din deploy/install.sh copiază `${{SRC_ROOT}}/{cale}` din "
            f"arhivă, iar arhiva nu conține nimic sub `{cale}`. Ori o excludere "
            f"l-a tăiat, ori depozitul fabricat de aici nu mai plantează nimic "
            f"acolo — în ambele cazuri instalarea moare la pasul 25.")


# ---------------------------------------------------------------------------
# Cele două scripturi de deploy trebuie să excludă la fel
# ---------------------------------------------------------------------------
def _excludes(text: str) -> set[str]:
    return set(re.findall(r"--exclude='([^']+)'", text))


def test_both_deploy_scripts_exclude_the_same_things():
    """Un deploy de pe Windows care trimite ce un deploy de pe Linux exclude e
    aceeași gaură, doar pe alt drum.

    Ce dovedește: cele două liste sunt egale ca mulțime. Ce NU dovedește:
    că PowerShell chiar produce arhiva asta — comanda din `.ps1` nu se poate
    rula sub bash, deci efectul e verificat doar pentru `deploy.sh`. Scris aici
    ca să nu fie citit ca mai mult decât e.
    """
    sh = _excludes(DEPLOY_SH.read_text(encoding="utf-8"))
    ps = _excludes(DEPLOY_PS1.read_text(encoding="utf-8"))
    assert sh == ps, f"doar în deploy.sh: {sh - ps} · doar în deploy.ps1: {ps - sh}"
    assert "./scratchpad" in sh
