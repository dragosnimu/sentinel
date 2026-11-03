"""Legături simbolice pentru teste, și pe mașina care nu are dreptul să le creeze. Nu e modul de test.

De ce există: pe Windows fără `SeCreateSymbolicLinkPrivilege` (mașina pe care rulează de fapt
suita — nu există CI), `os.symlink` ridică `WinError 1314`, iar testele care aveau nevoie de o
legătură SĂREAU. Un skip pe singura mașină care rulează testul înseamnă că garda pe care o
păzea nu are niciun observator nicăieri: pare acoperire și nu e.

Ce face în loc: fiecare script livrat rulează sub bash (Git Bash / MSYS pe Windows), iar
garda care contează e `[[ -L ]]`, `readlink`, `rm`, `[[ -f ]]` din ACEL bash. Runtime-ul MSYS
creează fără niciun privilegiu legături simbolice proprii (`MSYS=winsymlinks:lnk` -> un fișier
`.lnk` pe disc, pe care bash-ul îl vede ca symlink: `-L` adevărat, `readlink` întoarce textul
țintei, `-e`/`-f`/`-d` urmează ținta, `rm` șterge legătura și nu ținta). Măsurat 3 noiembrie
2026 pe Git Bash 5.2.37 (msys): același rezultat ca un symlink real pe WSL la `-L`, `-e`, `-f`,
`-d`, `readlink`, `rm -rf L`, `rm -rf L/`. Spre deosebire de o joncțiune NTFS, poate fi
legătură spre un FIȘIER (`[[ -f L && ! -L L ]]` se poate exersa) și păstrează textul țintei.

Ce NU are, spus ca să nu fie descoperit târziu:
  * Python nu o vede ca legătură — pe disc e fișierul `NUME.lnk`; `Path.is_symlink()` și
    `Path.exists()` pe `NUME` mint (fals, respectiv fals). De-aia testele întreabă bash-ul prin
    `is_link` / `present`, nu `pathlib`. Pe Linux cele două întrebări dau același răspuns.
  * Fișierul `.lnk` are atributul read-only, deci `shutil.rmtree` simplu pe un arbore care
    îl conține cade cu `PermissionError` și lasă resturi. Fixture-ul `make_link` din
    `conftest.py` le șterge cu `rm -f` din bash la teardown, și teardown-ul rulează și când
    testul pică.

Ordinea încercărilor: `os.symlink` (symlink adevărat: Linux, WSL, Windows cu privilegiu), apoi
legătura MSYS. După crearea oricăreia, precondiția e VERIFICATĂ cu același bash care rulează
testul (`-L` adevărat; `-e` și tipul fișier/director cum le-am cerut), nu presupusă. Dacă
nici una nu merge sau verificarea pică, testul SARE cu motivul scris — niciodată trece.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

BASH = shutil.which("bash")


def _posix(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _sh(script: str, *args: Path | str, env: dict[str, str] | None = None
        ) -> subprocess.CompletedProcess:
    assert BASH is not None, "bash lipsește din PATH — nu se poate întreba despre legături"
    return subprocess.run([BASH, "-c", script, "sh", *(_posix(a) for a in args)],
                          capture_output=True, text=True, env=env)


def is_link(path: Path) -> bool:
    """Bash-ul întreabă `[ -L ]` — același test pe care îl face codul livrat.

    NU `Path.is_symlink()`: pe Windows legătura MSYS e un `NUME.lnk` pentru Python."""
    return _sh('[ -L "$1" ]', path).returncode == 0


def present(path: Path) -> bool:
    """Există ceva la `path` — legătură (și atârnândă), fișier sau director.

    NU `Path.exists()`: nu vede legătura MSYS, deci «linkul a dispărut» ar fi mereu adevărat."""
    return _sh('[ -L "$1" ] || [ -e "$1" ]', path).returncode == 0


class LinkMaker:
    """Creează legături și le curăță. Se obține din fixture-ul `make_link`, nu direct."""

    def __init__(self) -> None:
        self._made: list[Path] = []

    def __call__(self, link: Path, target: Path) -> str:
        """Face din `link` o legătură spre `target` și întoarce cum a făcut-o.

        Starea lui `target` LA APEL (există? director? fișier?) e ceea ce se verifică după
        creare: o țintă care nu există dă o legătură atârnândă, una existentă o legătură vie
        de același tip. Se înregistrează la curățare ÎNAINTE de creare, ca o creare căzută la
        jumătate să nu lase nimic în urmă."""
        link, target = Path(link), Path(target)
        self._made.append(link)
        live, is_dir = target.exists(), target.is_dir()
        how = self._create(link, target, is_dir)
        self._verify(link, how, live, is_dir)
        return how

    @staticmethod
    def _create(link: Path, target: Path, is_dir: bool) -> str:
        try:
            os.symlink(target, link, target_is_directory=is_dir)
            return "symlink"
        except (OSError, NotImplementedError) as symlink_err:
            if os.name != "nt":
                pytest.skip(f"nu pot crea un symlink aici ({symlink_err!r}); ramura care "
                            "depinde de legătură nu e verificată pe această mașină")
            refused = symlink_err
        made = _sh('ln -s -- "$1" "$2"', target, link,
                   env={**os.environ, "MSYS": "winsymlinks:lnk"})
        if made.returncode != 0:
            pytest.skip(f"nu pot crea nici symlink ({refused!r}), nici legătură MSYS "
                        f"({made.stdout.strip()} {made.stderr.strip()}); ramura care depinde "
                        "de legătură nu e verificată pe această mașină")
        return "legătură MSYS (.lnk)"

    @staticmethod
    def _verify(link: Path, how: str, live: bool, is_dir: bool) -> None:
        checked = _sh(
            '[ -L "$1" ] || exit 10\n'
            'if [ -e "$1" ]; then\n'
            '  [ "$2" = live ] || exit 11\n'
            '  if [ -d "$1" ]; then [ "$3" = dir ] || exit 12; '
            '  else [ -f "$1" ] && [ "$3" = file ] || exit 13; fi\n'
            'else [ "$2" = dangling ] || exit 14; fi\n',
            link, "live" if live else "dangling", "dir" if is_dir else "file")
        if checked.returncode != 0:
            pytest.skip(f"{how} creată, dar bash nu o vede cum a fost cerută (cod "
                        f"{checked.returncode}: 10 nu e legătură, 11 țintă vie în loc de "
                        "atârnândă, 12/13 tip greșit, 14 atârnândă în loc de vie): "
                        "precondiția testului nu e stabilită pe această mașină")

    def cleanup(self) -> None:
        """Șterge legăturile făcute; ridică dacă una a rămas (nu tace)."""
        left: list[Path] = []
        for link in reversed(self._made):
            _sh('rm -f -- "$1"', link)
            if present(link):
                for fallback in (link.unlink, link.rmdir):
                    try:
                        fallback()
                        break
                    except OSError:
                        continue
            lnk = link.with_name(link.name + ".lnk")
            if lnk.exists():
                try:
                    lnk.chmod(0o600)
                    lnk.unlink()
                except OSError:
                    pass
            if present(link) or lnk.exists():
                left.append(link)
        self._made.clear()
        if left:
            raise AssertionError(
                f"legăturile {left} au rămas după curățare — un rmtree ulterior pe arborele "
                "temporar ar cădea sau ar urma ținta")
