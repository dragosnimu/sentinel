"""Ce ajunge în pachetul de deploy — citit din arhivă, nu din intenția care o construiește.

Până pe 8 septembrie 2026, pachetul se construia cu `tar -C "$REPO_ROOT" .`
minus o listă de `--exclude` întreținută de mână. `credentiale.txt` (2352 B) și
`env.txt` (129 B) stăteau la rădăcina depozitului, prinse de `.gitignore`
(`credentiale*.txt`, `*env*.txt`), niciodată `git add`-uite — și tot au ajuns în
arhivă, lizibile de oricine, în `/tmp` pe o gazdă, fiindcă lista de excludere nu
auzise niciodată de niciunul dintre cele două nume. O listă de excludere trebuie
anunțată despre fiecare fișier secret care va exista vreodată, pe nume, înainte
să fie creat; `git ls-files` știe deja, din clipa în care fișierul e creat,
fiindcă `.gitignore` i-a spus o singură dată.

Mecanismul nou, în `scripts/lib/build-package.sh` (și geamănul lui
`scripts/lib/Build-Package.ps1`): pachetul e `git ls-files` minus câteva
pathspec-uri care taie CATEGORII pe care git LE urmărește dar care n-au voie pe
fir (`tests/`, `docs/`, `watcher/`, `aggregator/`, `secrets/`,
`scratchpad/`, `.claude/worktrees/`). Un fișier neurmărit de git nu poate intra
în arhivă, indiferent cum se numește data viitoare.

Testele de aici NU reimplementează mecanismul — sursează funcția reală din
`scripts/lib/build-package.sh` și o rulează într-un depozit git fabricat, apoi
se uită în arhiva REZULTATĂ cu `tar -tzf`. Arhiva e efectul; o aserțiune pe
lista de pathspec-uri ar trece și peste unul scris greșit sau pus după `--`
fără efect.

## De ce scratchpad/ e cazul care a cerut fișierul, inițial

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
BUILD_SH = REPO / "scripts" / "lib" / "build-package.sh"
BUILD_PS1 = REPO / "scripts" / "lib" / "Build-Package.ps1"
INSTALL_SH = REPO / "deploy" / "install.sh"
GITIGNORE = REPO / ".gitignore"

#: Sursa fiecărui `cp -r` din pasul 25, adică ce trebuie să fie în arhivă.
_CP_DIN_ARHIVA = re.compile(r'cp\s+-r\s+"\$\{SRC_ROOT\}/([^"]+)"')

BASH = shutil.which("bash")
TAR = shutil.which("tar")
GIT = shutil.which("git")
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")

needs_bash = pytest.mark.skipif(BASH is None, reason="no bash on PATH")
needs_tar = pytest.mark.skipif(TAR is None, reason="no tar on PATH")
needs_git = pytest.mark.skipif(GIT is None, reason="no git on PATH")
needs_powershell = pytest.mark.skipif(POWERSHELL is None, reason="no powershell on PATH")


# Un depozit în miniatură: câte un fișier din fiecare loc care contează. Nu o
# copie a depozitului real — testul trebuie să pice fiindcă s-a schimbat o
# excludere, nu fiindcă a apărut un director nou în arbore.
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
    # Nu are voie să plece — categorii pe care git LE urmărește, tăiate de
    # pathspec-urile din build-package.sh/.ps1.
    "tests/unit/test_shipper.py": b"# teste\n",
    "docs/DEPLOYMENT.md": b"# doc\n",
    "watcher/lib/verify.ts": b"// martorul\n",
    "aggregator/migrations/0001_core.sql": b"-- @guard table instances\n",
    # Nu are voie să plece — categorii pe care git NU le urmărește deloc,
    # fiindcă .gitignore (copiat identic în depozitul fabricat, mai jos) le
    # prinde înainte ca vreun pathspec să mai fie nevoie.
    "scratchpad/e22-shipper/falsify.py": b"# harness\n",
    "scratchpad/e22-shipper/backup/sentinel__config.py": b"# copie de lucru\n",
    "scratchpad/README.md": b"scratch\n",
    "secrets/.env.local": b"SENTINEL_DB_PASSWORD=nu\n",
    "sentinel/__pycache__/config.cpython-310.pyc": b"\x00",
    "sentinel/config.pyc": b"\x00",
    ".claude/worktrees/sesiune/deploy/install.sh": b"#!/usr/bin/env bash\n",
    # Cazul confirmat pe 8 septembrie 2026: neurmărit, NEIGNORAT de o listă de
    # excludere care nu auzise de nume — dar prins de .gitignore, deci
    # niciodată `git add`-uit, deci nu poate exista în `git ls-files`.
    "credentiale.txt": b"parola panoului: nu\n",
    "env.txt": b"SENTINEL_BEACON_SECRET=nu\n",
}


def _posix(path: Path) -> str:
    """O cale pe care tar-ul și git-ul din bash le acceptă.

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


def _sub_calea(names: list[str], prefix: str) -> list[str]:
    """Numele din arhivă aflate sub `prefix`, unde `prefix` poate fi o CALE.

    `n.split("/")[0] == prefix` mergea cât timp fiecare excludere era un
    director de la rădăcină. `.claude/worktrees` nu e, iar o comparație pe
    primul segment n-ar fi găsit niciodată nimic acolo — adică ar fi raportat
    „nimic scurs" despre o excludere ștearsă cu totul.
    """
    return [n for n in names if n == prefix or n.startswith(prefix + "/")]


def _fabrica_depozit_git(stage: Path, members: dict[str, bytes]) -> None:
    """Scrie `members` pe disc, apoi îl transformă într-un depozit git — cu
    ACELAȘI `.gitignore` ca depozitul real, copiat, nu retranscris.

    Fără commit: `git ls-files` citește indexul, iar `git add` populează
    indexul fără să ceară `user.name`/`user.email`. Fișierele prinse de
    `.gitignore` rămân neurmărite, exact ca la un `git add -A .` real —
    testul verifică deci și stratul `.gitignore`, nu doar pathspec-urile din
    `build_sentinel_package`.
    """
    for rel, data in members.items():
        target = stage / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    shutil.copy(GITIGNORE, stage / ".gitignore")
    subprocess.run(["git", "init", "-q"], cwd=stage, check=True)
    subprocess.run(
        ["git", "-c", "core.autocrlf=false", "add", "-A", "."],
        cwd=stage, check=True, capture_output=True,
    )


def build_package(workdir: Path, members: dict[str, bytes] | None = None) -> list[str]:
    """Numele din arhiva produsă de `build_sentinel_package`, normalizate.

    Sursează funcția REALĂ din `scripts/lib/build-package.sh` — nu o
    reimplementare, nu un fragment decupat cu regex — și o rulează peste un
    depozit git fabricat. Un harness care reimplementează ce verifică a trecut
    deja verde peste cod rupt în depozitul ăsta.
    """
    stage = workdir / "repo"
    stage.mkdir(exist_ok=True)
    _fabrica_depozit_git(stage, members or FAKE_REPO)
    tarball = workdir / "pkg.tar.gz"

    script = (
        "set -eu\n"
        f'source "{_posix(BUILD_SH)}"\n'
        f'build_sentinel_package "{_posix(tarball)}" "{_posix(stage)}"\n'
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

    `git init` + `tar` de paisprezece ori peste același arbore fabricat costă
    timp și nu dovedește nimic în plus: toate aserțiunile de mai jos privesc
    ACEEAȘI listă de nume, produsă de aceeași comandă.
    """
    if BASH is None or TAR is None or GIT is None:
        pytest.skip("no bash/tar/git on PATH")
    return build_package(tmp_path_factory.mktemp("pkg"))


# ---------------------------------------------------------------------------
# Cazul confirmat pe 8 septembrie 2026 — motivul întregului fișier
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
@needs_git
@pytest.mark.parametrize("nume", ["credentiale.txt", "env.txt"])
def test_a_gitignored_root_secret_never_reaches_the_package(packaged, nume):
    """`credentiale.txt` și `env.txt`, prinse de `.gitignore`, niciodată
    `git add`-uite — găsite totuși în tarball-ul vechi, lizibil de oricine în
    `/tmp` pe o gazdă. Falsificat revenind la `tar -C "$REPO_ROOT" .` minus o
    listă de `--exclude` care nu conține niciunul din cele două nume.
    """
    assert nume not in packaged, f"{nume} e în pachet — .gitignore nu a oprit-o"


@needs_bash
@needs_tar
@needs_git
def test_build_sentinel_package_refuses_a_non_git_directory(tmp_path):
    """Fără `.git`, funcția nu are cum să știe ce e ignorat — și nu are voie să
    presupună „trimite tot", care e exact gaura pe care mecanismul o închide.
    Ieșirea 2 ("necunoscut") nu e ieșirea 0 ("curat"); confundarea lor a produs
    fiecare bug documentat în `CLAUDE.md`.

    Falsificat înlocuind refuzul cu un `tar -C "$repo_root" -czf ... .` de
    rezervă în `build_sentinel_package` — testul trebuie să pice pe asta.
    """
    out = tmp_path / "no-git.tar.gz"
    script = (
        "set -u\n"
        f'source "{_posix(BUILD_SH)}"\n'
        f'build_sentinel_package "{_posix(out)}" "{_posix(tmp_path)}"\n'
        'echo "RC=$?"\n'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert "RC=2" in proc.stdout, proc.stdout + proc.stderr
    assert not out.exists(), "un pachet a fost scris deși directorul nu e un depozit git"


# ---------------------------------------------------------------------------
# Ce nu are voie să plece
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
@needs_git
def test_the_verification_scratch_never_reaches_the_server(packaged):
    """Harness-urile de falsificare și copiile lor `.bak` nu au ce căuta în pachet.

    Trei riscuri distincte, niciunul văzut de plafonul de 20 MB: sursă pe care
    nimic de pe gazdă nu o rulează; a doua copie a unor fișiere a căror unicitate
    e chiar ideea (`install.sh`, `signing.py`); și un harness care poate fi rulat
    mai târziu, cu un manifest vechi, peste un arbore mai nou — ceea ce a
    clobberit arborele de lucru de două ori în E2.2.

    Verificat pe ARHIVĂ, nu pe lista de pathspec-uri.
    """
    leaked = _sub_calea(packaged, "scratchpad")
    assert leaked == [], f"pachetul conține scratchpad/: {leaked}"


@needs_bash
@needs_tar
@needs_git
@pytest.mark.parametrize("prefix",
                         ["secrets", "tests", "docs", "watcher", "aggregator",
                          ".claude/worktrees"])
def test_what_was_already_excluded_stays_excluded(packaged, prefix):
    """Adăugarea unui pathspec nu are voie să strice pe celelalte.

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
    `.claude/agents`. Vezi `test_the_package_carries_what_step_25_copies_out_of_it`,
    care păzește direcția cealaltă.

    `secrets`, `tests`, `docs`, `watcher`, `aggregator` sunt urmărite de git
    (categorii reale din depozit), deci testul ăsta exercită efectiv
    pathspec-urile din `build_sentinel_package`. `.claude/worktrees` NU e
    urmărit — .gitignore l-a oprit deja — dar pathspec-ul rămâne, ca a doua
    linie de apărare dacă cineva îl adaugă vreodată cu `git add -f`.
    """
    leaked = _sub_calea(packaged, prefix)
    assert leaked == [], f"pachetul conține {prefix}/: {leaked}"


@needs_bash
@needs_tar
@needs_git
def test_compiled_python_does_not_travel(packaged):
    """`.pyc` dintr-un arbore Windows nu se potrivește cu interpretorul gazdei, iar
    un `__pycache__` vechi lângă o sursă nouă e chiar felul în care CPython ajunge
    să ruleze cod pe care nimeni nu-l mai are pe disc. Niciun pathspec nu-i
    nevoie: `.gitignore` le oprește înainte să existe în index."""
    assert not [n for n in packaged if n.endswith(".pyc") or "__pycache__" in n], packaged


# ---------------------------------------------------------------------------
# Ce TREBUIE să plece — jumătatea fără de care testele de mai sus se trec
# excluzând tot
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
@needs_git
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

    Un pathspec prea larg nu produce un mesaj: produce un install care moare
    târziu, pe gazdă, la un fișier care lipsește. `deploy/tools/` e cazul cel mai
    aproape de margine — e sub `deploy/`, care pleacă întreg.
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
@needs_git
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
    și fără cele șase definiții de agenți. Aici se verifică arhiva, adică sursa
    acelui `cp`, nu toleranța lui.
    """
    for cale in _ce_scoate_pasul_25_din_arhiva():
        continut = _sub_calea(packaged, cale)
        assert continut, (
            f"pasul 25 din deploy/install.sh copiază `${{SRC_ROOT}}/{cale}` din "
            f"arhivă, iar arhiva nu conține nimic sub `{cale}`. Ori un pathspec "
            f"l-a tăiat, ori depozitul fabricat de aici nu mai plantează nimic "
            f"acolo — în ambele cazuri instalarea moare la pasul 25.")


# ---------------------------------------------------------------------------
# Bash și PowerShell trebuie să excludă la fel
# ---------------------------------------------------------------------------
def _pathspecuri(text: str) -> set[str]:
    """Fiecare `':!ceva'` dintr-un fișier — pathspec-ul de excludere pentru
    `git ls-files`, indiferent dacă e scris în bash (`\\` la capăt de linie)
    sau în PowerShell (`` ` `` la capăt de linie); sintaxa `':!ceva'` e
    identică în ambele."""
    return set(re.findall(r"':!([^']+)'", text))


def test_both_packaging_libraries_exclude_the_same_things():
    """Un deploy de pe Windows care trimite ce un deploy de pe Linux exclude e
    aceeași gaură, doar pe alt drum.

    Ce dovedește: cele două liste de pathspec-uri sunt egale ca mulțime. Ce NU
    dovedește: că `Build-Package.ps1` chiar produce arhiva asta — comanda lui nu
    se poate rula sub bash, deci EFECTUL e verificat doar pentru
    `build-package.sh` (vezi `packaged` mai sus) și, unde PowerShell e
    disponibil, în `test_powershell_twin_excludes_the_same_gitignored_secret`
    de mai jos.
    """
    sh = _pathspecuri(BUILD_SH.read_text(encoding="utf-8"))
    ps = _pathspecuri(BUILD_PS1.read_text(encoding="utf-8-sig"))
    assert sh == ps, f"doar în build-package.sh: {sh - ps} · doar în Build-Package.ps1: {ps - sh}"
    assert "secrets" in sh


def test_neither_deploy_script_still_builds_the_package_with_an_exclude_list():
    """Regresie directă: dacă `--exclude=` reapare în punctul de împachetare din
    `deploy.sh` sau `deploy.ps1`, mecanismul vechi a fost adus înapoi — cel care
    a lăsat `credentiale.txt` și `env.txt` să plece, fiindcă o listă de
    excludere nu poate fi anunțată despre un nume înainte să existe.
    """
    for path, encoding in ((DEPLOY_SH, "utf-8"), (DEPLOY_PS1, "utf-8-sig")):
        text = path.read_text(encoding=encoding)
        assert "--exclude=" not in text, (
            f"{path.name} construiește pachetul cu --exclude= — ar trebui să "
            f"cheme build_sentinel_package / Build-Package.ps1")


@needs_powershell
@needs_git
@pytest.mark.parametrize("nume", ["credentiale.txt", "env.txt"])
def test_powershell_twin_excludes_the_same_gitignored_secret(tmp_path, nume):
    """Geamănul PowerShell al testului de mai sus — verificat pe efect, nu doar
    pe lista de pathspec-uri, acolo unde `powershell.exe` există să-l ruleze.
    """
    stage = tmp_path / "repo"
    stage.mkdir()
    _fabrica_depozit_git(stage, FAKE_REPO)
    tarball = tmp_path / "pkg-ps.tar.gz"

    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-Command",
         f'& "{BUILD_PS1}" -Tarball "{tarball}" -RepoRoot "{stage}"; exit $LASTEXITCODE'],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert tarball.exists(), "Build-Package.ps1 a raportat succes fără să scrie pachetul"

    with tarfile.open(tarball, "r:gz") as tf:
        names = [n[2:] if n.startswith("./") else n for n in tf.getnames()]
    assert nume not in names, f"{nume} e în pachetul PowerShell — .gitignore nu a oprit-o"


@needs_powershell
@needs_git
def test_powershell_twin_also_refuses_an_untracked_shipped_file(tmp_path):
    """Geamănul PowerShell al gărzii pentru fișiere neurmărite — verificat pe
    efect, nu doar pe faptul că `Build-Package.ps1` conține textul potrivit.
    Un deploy de pe Windows are dreptul la aceeași protecție ca unul de pe
    Linux, altfel gaura confirmată pe 8 septembrie 2026 rămâne deschisă pe
    jumătate din căile de livrare.
    """
    stage = tmp_path / "repo"
    stage.mkdir()
    _fabrica_depozit_git(stage, FAKE_REPO)
    (stage / "sentinel" / "telegram").mkdir(parents=True, exist_ok=True)
    (stage / "sentinel" / "telegram" / "callback_sign.py").write_bytes(b"# neurmarit\n")
    tarball = tmp_path / "pkg-ps.tar.gz"

    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-Command",
         f'& "{BUILD_PS1}" -Tarball "{tarball}" -RepoRoot "{stage}"; exit $LASTEXITCODE'],
        capture_output=True, text=True,
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "callback_sign.py" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr
    assert not tarball.exists(), "Build-Package.ps1 a scris un pachet deși exista un fișier neurmărit"


# ---------------------------------------------------------------------------
# Copia extrasă pe server nu are voie să supraviețuiască unui eșec
# ---------------------------------------------------------------------------
def _lift_cleanup_function() -> str:
    """Funcția `cleanup` decupată verbatim din `deploy.sh` — capcana EXIT care
    trebuie să șteargă arborele extras de pe server la orice ieșire, nu doar la
    succes. Decupată, nu rescrisă: o reimplementare aici ar verifica o funcție
    care nu mai există în fișierul livrat.
    """
    text = DEPLOY_SH.read_text(encoding="utf-8")
    match = re.search(r"^cleanup\(\) \{\n.*?\n\}\n", text, re.S | re.M)
    assert match, "deploy.sh nu mai are o funcție `cleanup() { ... }` pe care testul ăsta o poate decupa"
    return match.group(0)


@needs_bash
def test_cleanup_removes_the_remote_extracted_copy_on_every_exit(tmp_path):
    """Până pe 8 septembrie 2026, arborele extras la `$REMOTE_DIR` era șters
    doar pe calea de succes — un `die` oriunde între extragere și acel punct
    (transfer eșuat, verificare CRLF picată, instalare eșuată) lăsa arborele în
    `/tmp`, lizibil de oricine, până la următorul deploy reușit pe aceeași
    gazdă. Funcția `cleanup`, prinsă pe `trap cleanup EXIT`, rulează la ORICE
    ieșire — verificat aici chemând-o direct, cu un `ssh_run` fals care doar
    înregistrează ce i s-a cerut, fără nicio conexiune reală.

    Apelul real din `cleanup()` redirectă stdout/stderr-ul lui `ssh_run` la
    `/dev/null` (rulează tăcut în producție), deci stub-ul scrie într-un
    FIȘIER, nu pe stdout — altfel testul ar „vedea" tăcere indiferent ce face
    codul.

    Falsificat scoțând linia care șterge `$REMOTE_DIR` din `cleanup()` — testul
    trebuie să pice pe asta, nu doar să treacă „din întâmplare" fiindcă
    `ssh_run` fals nu face nimic oricum.
    """
    log = tmp_path / "ssh_run.log"
    script = (
        "set -u\n"
        'REMOTE_DIR=/tmp/sentinel-deploy-FALSIFICAT\n'
        'MUX=no\n'
        f'ssh_run() {{ printf "%s\\n" "$*" >> "{_posix(log)}"; return 0; }}\n'
        + _lift_cleanup_function() + "\n"
        "cleanup || true\n"
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    apeluri = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    tinta = "rm -rf '/tmp/sentinel-deploy-FALSIFICAT'"
    assert any(tinta in apel for apel in apeluri), (
        f"cleanup() nu a cerut ștergerea lui $REMOTE_DIR; apeluri către ssh_run: {apeluri}")


# ---------------------------------------------------------------------------
# Fișiere neurmărite, neignorate -- 8 septembrie 2026, cazul viu
# ---------------------------------------------------------------------------
@needs_bash
@needs_tar
@needs_git
def test_an_untracked_shipped_file_refuses_the_build(tmp_path):
    """`sentinel/telegram/callback_sign.py`, cazul viu: fișier nou, neurmărit,
    importat de `bot.py`-ul deja urmărit din același commit. Pachetul vechi,
    construit din `git ls-files`, îl excludea tăcut — nu era în index —, dar
    `bot.py` pleca oricum, iar gazda a intrat în buclă de crash la import,
    peste un deploy verde și o suită de teste verde (nimic nu lipsea din
    arborele de lucru, doar din indexul lui git).

    `--yes` la `deploy.sh` nu ocolește asta — e o poartă de corectitudine, nu
    un prompt de confirmare, iar `build_sentinel_package` nici nu se uită la
    variabila aia.

    Falsificat scoțând verificarea `git ls-files --others --exclude-standard`
    din `build_sentinel_package` — testul trebuie să vadă `RC=0` și fișierul
    în arhivă.
    """
    stage = tmp_path / "repo"
    stage.mkdir()
    _fabrica_depozit_git(stage, FAKE_REPO)
    (stage / "sentinel" / "telegram").mkdir(parents=True, exist_ok=True)
    (stage / "sentinel" / "telegram" / "callback_sign.py").write_bytes(b"# neurmarit\n")

    tarball = tmp_path / "pkg.tar.gz"
    script = (
        "set -u\n"   # nu -e: comanda de mai jos e AȘTEPTATĂ să iasă nenul
        f'source "{_posix(BUILD_SH)}"\n'
        f'build_sentinel_package "{_posix(tarball)}" "{_posix(stage)}"\n'
        'echo "RC=$?"\n'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert "RC=3" in proc.stdout, proc.stdout + proc.stderr
    assert "callback_sign.py" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr
    assert not tarball.exists(), "un pachet a fost scris deși exista un fișier neurmărit"


@needs_bash
@needs_tar
@needs_git
def test_an_ignored_untracked_file_does_not_refuse_the_build(tmp_path):
    """Diferența față de testul de mai sus: un fișier prins de `.gitignore`
    (un `.pyc`, de pildă) trebuie să lipsească TĂCUT din pachet, exact ca
    până acum — nu e o intrare `git add` uitată, e ceva ce nu are ce căuta în
    git deloc. Refuzul de mai sus nu are voie să devină „orice fișier de pe
    disc care nu e în arhivă oprește build-ul", altfel fiecare build ar pica
    pe un `__pycache__/` rămas pe disc.

    Falsificat scoțând `--exclude-standard` din comanda `git ls-files
    --others` din `build_sentinel_package` — testul trebuie să vadă `RC=3` în
    loc de un pachet construit.
    """
    stage = tmp_path / "repo"
    stage.mkdir()
    _fabrica_depozit_git(stage, FAKE_REPO)
    (stage / "sentinel" / "extra_pycache").mkdir(parents=True, exist_ok=True)
    (stage / "sentinel" / "extra_pycache" / "mod.pyc").write_bytes(b"\x00")

    tarball = tmp_path / "pkg.tar.gz"
    script = (
        "set -eu\n"
        f'source "{_posix(BUILD_SH)}"\n'
        f'build_sentinel_package "{_posix(tarball)}" "{_posix(stage)}"\n'
        'echo "RC=$?"\n'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert tarball.exists(), "pachetul n-a fost construit deși singurul fișier neurmărit e ignorat"


# ---------------------------------------------------------------------------
# Capcana RETURN nu are voie să iasă din funcție
# ---------------------------------------------------------------------------
@needs_bash
def test_sourcing_build_package_does_not_leave_a_return_trap_armed(tmp_path):
    """Un `trap ... RETURN` pus ÎN INTERIORUL funcției rămâne înarmat în
    shell-ul APELANTULUI după ce funcția se întoarce — fișierul ăsta e
    `source`-uit, niciodată executat ca proces propriu (`deploy.sh`,
    `wizard.sh`). Un `source` ULTERIOR, al oricărui alt fișier, în același
    shell, lovește capcana aia la ÎNTOARCEREA LUI, nu doar a funcției care a
    pus-o. Reprodus cu un fișier trivial care doar setează o variabilă: sub
    capcana veche, sursarea lui moare cu "$list: unbound variable" — o
    variabilă locală lui `build_sentinel_package`, de mult ieșită din scop.

    Falsificat punând la loc `trap 'rm -f "$list"' RETURN` în
    `build_sentinel_package` — testul trebuie să piardă pe eroarea aia.
    """
    trivial = tmp_path / "trivial.sh"
    trivial.write_text("SOME_VAR=1\n", encoding="utf-8", newline="\n")

    script = (
        "set -euo pipefail\n"
        f'source "{_posix(BUILD_SH)}"\n'
        'stage="$(mktemp -d)"\n'
        'git -C "$stage" init -q\n'
        'echo x > "$stage/x.txt"\n'
        'git -C "$stage" add -A\n'
        'out="$(mktemp -u).tar.gz"\n'
        'build_sentinel_package "$out" "$stage" >/dev/null 2>&1 || true\n'
        f'source "{_posix(trivial)}"\n'
        'echo "SOURCED_OK SOME_VAR=$SOME_VAR"\n'
    )
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SOURCED_OK SOME_VAR=1" in proc.stdout, proc.stdout + proc.stderr
