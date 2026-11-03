"""`tests/_symlinks.py` — ajutorul care a scos cinci skip-uri de pe singura mașină care rulează suita.

Eșecul pe care îl previne, pentru operator: ajutorul ar putea ÎNCETA să producă legături fără ca
nimeni să observe. Cele cinci teste de gardă (marcajele de instalare, rollback, instantaneul
de pre-deploy, faptul nginx) trec când legătura există și pică sau sar când nu; dacă ajutorul
ar crea în tăcere o COPIE (`ln -s` sub MSYS copiază când `MSYS` nu cere legături — măsurat:
rc=0, fișier obișnuit), testele de gardă ar rula pe un fișier obișnuit și ar raporta o
acoperire pe care n-o au. Aici se fixează ce garantează ajutorul, independent de consumatori.
"""
from __future__ import annotations

import shutil

import pytest
from _symlinks import LinkMaker, _sh, is_link, present

pytestmark = pytest.mark.skipif(shutil.which("bash") is None,
                                reason="fără bash în PATH — netestat, nu curat")


def _lnk_files(directory) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.suffix == ".lnk")


def test_each_kind_of_link_is_seen_by_bash_as_what_it_was_asked_to_be(tmp_path, make_link):
    """Legătură spre director, spre fișier și atârnândă: bash-ul trebuie să le vadă `-L`, iar
    `-e`/`-d`/`-f` să urmeze ținta (sau să fie false când ținta lipsește). Fără asta, un test
    de gardă care are nevoie de un FIȘIER-legătură (`[[ -f L && ! -L L ]]`) ar primi un
    director, iar clauza `-L` n-ar mai fi exersată."""
    directory = tmp_path / "d"
    directory.mkdir()
    regular = tmp_path / "f"
    regular.write_text("1\n", encoding="utf-8", newline="\n")
    make_link(tmp_path / "to_dir", directory)
    make_link(tmp_path / "to_file", regular)
    make_link(tmp_path / "to_nothing", tmp_path / "gone")

    def shape(name: str) -> str:
        probe = _sh('printf "L=%s e=%s d=%s f=%s" "$([ -L "$1" ] && echo 1 || echo 0)" '
                    '"$([ -e "$1" ] && echo 1 || echo 0)" "$([ -d "$1" ] && echo 1 || echo 0)" '
                    '"$([ -f "$1" ] && echo 1 || echo 0)"', tmp_path / name)
        return probe.stdout

    assert shape("to_dir") == "L=1 e=1 d=1 f=0"
    assert shape("to_file") == "L=1 e=1 d=0 f=1"
    assert shape("to_nothing") == "L=1 e=0 d=0 f=0"
    # martorul pozitiv: ceva care NU e legătură trebuie să dea alt răspuns, altfel
    # sonda ar spune «legătură» despre orice.
    assert shape("d") == "L=0 e=1 d=1 f=0"
    assert shape("f") == "L=0 e=1 d=0 f=1"
    assert is_link(tmp_path / "to_nothing") and present(tmp_path / "to_nothing")
    assert not is_link(directory) and present(directory)
    assert not present(tmp_path / "never_made")


def test_a_copy_is_not_accepted_as_a_link(tmp_path):
    """Ce se întâmplă dacă legătura NU e legătură: verificarea o refuză (testul sare cu motivul
    scris), nu o lasă să treacă. Aici ce se verifică e un director obișnuit, cerut ca legătură
    — exact ce ar produce `ln -s` sub MSYS fără `winsymlinks:lnk`."""
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
        LinkMaker._verify(plain, "o copie", True, True)
    # martor pozitiv pe aceeași funcție: o legătură adevărată, cerută corect, NU sare.
    maker = LinkMaker()
    try:
        maker(tmp_path / "real_link", plain)
        LinkMaker._verify(tmp_path / "real_link", "legătură", True, True)
    finally:
        maker.cleanup()


@pytest.mark.parametrize("live, is_dir", [
    pytest.param(False, True, id="expected-dangling-but-target-exists"),
    pytest.param(True, False, id="expected-a-file-but-target-is-a-directory"),
])
def test_a_link_of_the_wrong_shape_is_refused(tmp_path, live, is_dir):
    """O legătură vie cerută atârnândă, sau spre director cerută spre fișier: precondiția
    testului de gardă n-ar fi cea scrisă în el, deci ajutorul sare în loc să o lase."""
    directory = tmp_path / "d"
    directory.mkdir()
    maker = LinkMaker()
    try:
        maker(tmp_path / "link", directory)
        with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
            LinkMaker._verify(tmp_path / "link", "legătură", live, is_dir)
    finally:
        maker.cleanup()


def test_cleanup_removes_every_link_and_nothing_else(tmp_path):
    """După `cleanup`, nici o legătură (și nici un `.lnk` read-only) nu rămâne în arbore, iar
    țintele sunt neatinse. Un `.lnk` rămas face un `shutil.rmtree` ulterior pe arborele
    temporar să cadă cu `PermissionError` și să lase resturi — un test fără legătură cu
    acesta ar pica."""
    directory = tmp_path / "d"
    directory.mkdir()
    (directory / "secret").write_text("S\n", encoding="utf-8", newline="\n")
    regular = tmp_path / "f"
    regular.write_text("1\n", encoding="utf-8", newline="\n")
    maker = LinkMaker()
    names = ["to_dir", "to_file", "to_nothing"]
    maker(tmp_path / "to_dir", directory)
    maker(tmp_path / "to_file", regular)
    maker(tmp_path / "to_nothing", tmp_path / "gone")
    assert all(present(tmp_path / n) for n in names), "precondiția: legăturile există"

    maker.cleanup()

    assert not [n for n in names if present(tmp_path / n)], "legături rămase după cleanup"
    assert _lnk_files(tmp_path) == [], "fișiere .lnk rămase după cleanup"
    assert (directory / "secret").read_text(encoding="utf-8") == "S\n", "ținta a fost atinsă"
    assert regular.read_text(encoding="utf-8") == "1\n", "ținta-fișier a fost atinsă"
    shutil.rmtree(tmp_path / "d")  # un rmtree ulterior nu trebuie să cadă
