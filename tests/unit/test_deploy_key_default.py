"""Contul implicit de livrare fără cheia lui e o cale de eșec, nu o comoditate.

Pe 25 august 2026 `--user` a primit implicitul `sentinel-deploy`, ca `auid`-ul
deploy-ului să nu mai fie al operatorului și filtrul de istoric să nu mai fie
inert. Verificarea de pe gazdă a arătat de ce jumătatea aia nu e de ajuns:
contul are în `authorized_keys` **o singură** cheie, iar amprenta ei e a lui
`~/.ssh/sentinel_deploy`. Cheia numită în invocația pe care o folosea operatorul
are altă amprentă și nu e autorizată pe contul ăsta — citit prin ssh, nu dedus.

Deci, cu implicitul de cont livrat singur, operatorul avea de ales între:

  * păstrează `--user` vechi → filtrul nu potrivește nimic, tabela crește cu
    ~405 000 de rânduri la fiecare rulare;
  * lasă implicitul → `Permission denied (publickey)` la prima conexiune, și
    reflexul care repară asta e chiar `--user` înapoi pe contul lui.

Testele de aici rulează BUCATA LIVRATĂ, decupată din `scripts/deploy.sh`, și se
uită la ce ajunge în `SSH_OPTS` — nu la faptul că numele cheii apare pe undeva
prin fișier. O aserțiune pe prezența unui nume nu spune nimic despre decizia
luată din el; asta a mai costat o dată aici.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"

BASH = shutil.which("bash")


def _env(**extra: str) -> dict[str, str]:
    """Mediul apelantului plus suprascrierile.

    Nu unul minimal: pe Windows, `CreateProcess` rezolvă executabilul cu PATH-ul
    primit, iar unul construit de mână găsește bash-ul din WSL în locul celui din
    Git Bash — care eșuează cu o eroare de serviciu Windows ce nu seamănă deloc a
    test picat.
    """
    return {**os.environ, "NO_COLOR": "1", **extra}


def _fragment(pattern: str) -> str:
    """O bucată decupată verbatim din `deploy.sh`, nu rescrisă aici."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    m = re.search(pattern, text, re.S | re.M)
    assert m, f"bucata căutată nu mai există în deploy.sh: {pattern}"
    return m.group(0)


def _run(fake_home: Path, given_key: str = "") -> subprocess.CompletedProcess:
    """Alegerea cheii, rulată exact cum e livrată, cu un `$HOME` fabricat.

    Se pun în jur doar lucrurile pe care bucata le găsește deja definite în
    script (`USER`, `HOST`, ajutoarele de tipărire). Restul — implicitul cheii ȘI
    ramurile care îl folosesc — sunt decupate din fișier.
    """
    # `[^\n]*` și nu `.*`: cu `re.S`, punctul potrivește și linia nouă, deci o
    # decupare „până la capătul liniei" ar aduce tot restul fișierului.
    implicit = _fragment(r"^DEPLOY_KEY_DEFAULT=[^\n]*")
    bloc = _fragment(r'^# No --key: fall back.*?SCP_OPTS\+=\(-i "\$KEY"\)\nfi$')
    script = "\n".join([
        'info() { printf "INFO %s\\n" "$*"; }',
        'warn() { printf "WARN %s\\n" "$*" >&2; }',
        'die()  { printf "ERR %s\\n" "$*" >&2; exit 1; }',
        'HOST="203.0.113.10"',
        'DEPLOY_USER_DEFAULT="sentinel-deploy"',
        'USER="$DEPLOY_USER_DEFAULT"',
        "SSH_OPTS=(); SCP_OPTS=()",
        f'KEY="{given_key}"',
        implicit,
        bloc,
        '(( ${#SSH_OPTS[@]} )) && printf "OPT %s\\n" "${SSH_OPTS[@]}"',
        "exit 0",
    ])
    home = str(fake_home).replace("\\", "/")
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                          env=_env(HOME=home))


def _cheie(home: Path, nume: str = "sentinel_deploy") -> Path:
    ssh = home / ".ssh"
    ssh.mkdir(parents=True, exist_ok=True)
    cale = ssh / nume
    cale.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    return cale


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_without_key_the_default_one_is_the_identity_ssh_gets(tmp_path):
    """Fără `--key`, conexiunea trebuie să plece cu cheia contului implicit.

    Altfel ssh alege singur o identitate, iar pe mașina operatorului aia e cheia
    logării lui — pe care `sentinel-deploy` o refuză. Un deploy care nu pornește
    e reparat cel mai repede punând `--user` înapoi, adică revenind la starea în
    care filtrul de istoric nu potrivește nimic.
    """
    cheie = _cheie(tmp_path)
    proc = _run(tmp_path)
    assert proc.returncode == 0, proc.stderr

    optiuni = [l[4:] for l in proc.stdout.splitlines() if l.startswith("OPT ")]
    assert "-i" in optiuni, f"nicio identitate dată lui ssh: {optiuni}"
    dat = optiuni[optiuni.index("-i") + 1]
    assert Path(dat).name == cheie.name, (
        f"ssh primește {dat!r}, nu cheia contului implicit")
    assert dat.endswith(".ssh/sentinel_deploy"), dat


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_an_explicit_key_still_wins(tmp_path):
    """`--key` dat de om nu are voie să fie înlocuit de implicit.

    Gazda altcuiva, un cont instalat cu alt `DEPLOY_ACCOUNT`, o cheie cu alt
    nume: toate sunt legitime, iar un implicit care s-ar suprapune peste ce a
    cerut operatorul ar deschide altă sesiune decât cea cerută.
    """
    _cheie(tmp_path)                      # implicitul EXISTĂ, deci ar putea intra
    alta = _cheie(tmp_path, "alta_cheie")
    proc = _run(tmp_path, given_key=str(alta).replace("\\", "/"))
    assert proc.returncode == 0, proc.stderr

    optiuni = [l[4:] for l in proc.stdout.splitlines() if l.startswith("OPT ")]
    dat = optiuni[optiuni.index("-i") + 1]
    assert Path(dat).name == "alta_cheie", (
        f"implicitul a înlocuit cheia cerută explicit: {dat!r}")


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_a_missing_default_key_warns_and_does_not_stop_the_run(tmp_path):
    """Cheia implicită lipsă e „nu știu", nu „ești greșit".

    Un agent ssh, un `IdentityFile` din `~/.ssh/config`, o cheie cu alt nume —
    scriptul nu vede niciuna dintre ele. Transformat în oprire, implicitul ăsta
    ar strica livrarea pe mașini pe care mergea. Dar tăcerea ar fi la fel de rea:
    ssh ar alege identitatea logării, iar mesajul primit — `Permission denied
    (publickey)` — nu spune nimic despre cheia care lipsește.
    """
    proc = _run(tmp_path)                 # niciun ~/.ssh/sentinel_deploy
    assert proc.returncode == 0, proc.stderr
    assert "OPT -i" not in proc.stdout, (
        "s-a dat lui ssh o cale de cheie care nu există")
    assert "sentinel_deploy" in proc.stderr, proc.stderr
    assert "publickey" in proc.stderr, (
        "avertismentul nu numește eroarea pe care operatorul chiar o vede")


@pytest.mark.skipif(BASH is None, reason="no bash on PATH")
def test_a_key_path_that_does_not_exist_is_still_refused(tmp_path):
    """Ramura veche rămâne: un `--key` greșit tastat se oprește aici.

    Fără ea, greșeala pleacă spre ssh, care încearcă altă identitate și dă tot
    `Permission denied (publickey)` — un mesaj care arată identic cu «cheia nu e
    autorizată pe cont» și trimite căutarea în partea greșită.
    """
    proc = _run(tmp_path, given_key=str(tmp_path / "nu-exista").replace("\\", "/"))
    assert proc.returncode != 0
    assert "SSH key not found" in proc.stderr


def test_both_wrappers_default_to_the_same_key_name():
    """Cele două căi de livrare trebuie să pornească aceeași cheie.

    E o aserțiune pe NUME, și se spune aici: nu poate ști ce e în
    `authorized_keys` de pe gazdă. Ce poate ști e că bash-ul și PowerShell-ul nu
    s-au despărțit unul de altul — despărțirea lor ar însemna că o cale de
    livrare merge și cealaltă primește `Permission denied`, în funcție de la ce
    mașină livrezi.
    """
    sh = DEPLOY_SH.read_text(encoding="utf-8")
    m = re.search(r'^DEPLOY_KEY_DEFAULT="([^"]+)"$', sh, re.M)
    assert m, "deploy.sh nu mai are un implicit de cheie în forma citită aici"
    assert m.group(1) == "${HOME}/.ssh/sentinel_deploy", m.group(1)

    ps1 = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    m = re.search(r"\$DeployKeyDefault = Join-Path \$HOME '([^']+)'", ps1)
    assert m, "deploy.ps1 nu mai are un implicit de cheie în forma citită aici"
    assert m.group(1) == ".ssh\\sentinel_deploy", m.group(1)
    # Și că e chiar folosit: definit fără să fie pus în `-i`, ar fi decor.
    assert re.search(r"if \(-not \$Key\) \{\s*\n\s*if \(Test-Path \$DeployKeyDefault\)",
                     ps1), "implicitul din deploy.ps1 nu e legat de nicio ramură"
