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
import subprocess
from pathlib import Path

import _symlinks
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


@pytest.mark.parametrize("target_exists, live, is_dir, code", [
    pytest.param(True, False, True, 11, id="expected-dangling-but-target-exists"),
    pytest.param(True, True, False, 12, id="expected-a-file-but-target-is-a-directory"),
    pytest.param(False, True, True, 14, id="expected-live-but-link-is-dangling"),
])
def test_a_link_of_the_wrong_shape_is_refused(tmp_path, target_exists, live, is_dir, code):
    """O legătură vie cerută atârnândă, spre director cerută spre fișier, sau atârnândă cerută
    vie: precondiția testului de gardă n-ar fi cea scrisă în el, deci ajutorul sare în loc să o
    lase. Un test de gardă care are nevoie de o legătură VIE (`[[ -f L && ! -L L ]]`) ar rula
    pe una atârnândă și ar raporta o acoperire pe care n-o are.

    Fiecare rând fixează CODUL clauzei care a respins (`cod 11:` etc.), nu doar faptul că a
    sărit: altfel o altă clauză (de pildă `-L` fals, cod 10) ar satisface rândul, iar clauza
    pe care rândul pretinde că o exersează ar putea fi ștearsă fără ca nimic să roșească.
    Rândul 14 e cel care exersează ramura `else` din `_verify`: singura în care legătura NU
    urmează o țintă.

    Falsificat înlocuind clauza `[ "$2" = dangling ] || exit 14` cu `true`: rândul 14 pică
    (nu mai sare), celelalte două rămân verzi."""
    target = tmp_path / "d"
    if target_exists:
        target.mkdir()
    maker = LinkMaker()
    try:
        maker(tmp_path / "link", target)
        with pytest.raises(pytest.skip.Exception, match=f"cod {code}:"):
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


def test_a_taken_path_is_refused_before_anything_is_created(tmp_path):
    """Ajutorul șterge la curățare tot ce se află la calea cerută. Dacă acolo ar fi deja ceva
    al testului (un fișier, un director cu date), curățarea l-ar șterge: calea trebuie să fie
    liberă, altfel e o greșeală de test, spusă înainte de orice creare."""
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "data").write_text("d\n", encoding="utf-8", newline="\n")
    maker = LinkMaker()
    try:
        maker(taken, tmp_path)
    except AssertionError as refusal:
        assert "există deja" in str(refusal), refusal
    except pytest.skip.Exception:
        # fără garda de cale liberă, `ln -s` ar fi pus o legătură ÎNĂUNTRUL directorului,
        # verificarea ar fi respins-o, iar testul ar fi SĂRIT în loc să pice
        pytest.fail("calea ocupată n-a fost refuzată la creare; a ajuns să sară mai târziu")
    else:
        pytest.fail("calea ocupată a fost acceptată")
    finally:
        maker.cleanup()
    assert (taken / "data").read_text(encoding="utf-8") == "d\n", "ajutorul a șters datele testului"


def test_a_refused_copy_is_removed_by_cleanup_without_touching_the_source(tmp_path, monkeypatch):
    """`ln -s` sub MSYS fără `winsymlinks:lnk` face o COPIE (rc 0). Verificarea o respinge (testul
    sare), dar copia e un director cu conținut: dacă curățarea n-o șterge, un `rmtree`
    ulterior pe arborele temporar o parcurge, iar testul care a sărit ar lăsa și o eroare
    de teardown. Aici copia e simulată (nu pot cere nucleului să greșească): proprietatea
    verificată e a curățării, nu a lui `ln`."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "secret").write_text("S\n", encoding="utf-8", newline="\n")

    def _copy_instead_of_link(link, target, is_dir):
        shutil.copytree(target, link)
        return "copie"

    monkeypatch.setattr(LinkMaker, "_create", staticmethod(_copy_instead_of_link))
    maker = LinkMaker()
    with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
        maker(tmp_path / "copy", source)
    assert present(tmp_path / "copy") and not is_link(tmp_path / "copy"), "precondiția: există o copie"

    maker.cleanup()

    assert not present(tmp_path / "copy"), "copia respinsă a rămas după cleanup"
    assert (source / "secret").read_text(encoding="utf-8") == "S\n", "sursa a fost atinsă"


def _rm_that_does_nothing(monkeypatch):
    """Înlocuiește `_sh` din `_symlinks` cu unul pentru care `rm` iese cu 0 fără să șteargă.

    Doar `rm`: `present` (și orice altă întrebare către bash) rămâne cel real, altfel testul ar
    afirma despre o sondă stricată. Simulează ce nu pot cere de la sistem — un `rm` care eșuează —
    deci nu are proprietățile unui `rm` real (fișier blocat de antivirus, bash căzut la jumătate);
    verifică ce face curățarea CÂND pasul bash nu șterge, nu de ce n-ar șterge."""
    real_sh = _symlinks._sh

    def _sh(script, *args, **kwargs):
        if script.startswith("rm "):
            return subprocess.CompletedProcess(["rm"], 0, "", "")
        return real_sh(script, *args, **kwargs)

    monkeypatch.setattr(_symlinks, "_sh", _sh)


def test_cleanup_raises_when_something_survives_every_removal_step(tmp_path, monkeypatch):
    """Teardown-ul care a lăsat resturi trebuie să cadă, nu să tacă. Raise-ul e singurul lucru
    care transformă o curățare eșuată într-o eroare vizibilă: fără el, o legătură rămasă într-un
    arbore temporar face un `rmtree` ulterior să cadă (sau să urmeze ținta), la un test fără
    nicio legătură cu ea, iar cauza nu mai poate fi găsită.

    Rămășița e un director NEGOL la calea cerută (copia pe care a respins-o verificarea): `rm`
    e dezactivat, iar nici `unlink`, nici `rmdir` nu pot șterge un director cu conținut, deci
    nu mai există nicio cale de a-l scoate. O LEGĂTURĂ n-ar merge aici: fallback-urile din
    curățare o șterg singure (vezi testul de după), deci n-ar ajunge niciodată la raise.

    Falsificat înlocuind `if left:` cu `if left and False:`: curățarea trece liniștit
    peste director, iar testul trebuie să vadă că nu a ridicat."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "secret").write_text("S\n", encoding="utf-8", newline="\n")

    def _copy_instead_of_link(link, target, is_dir):
        shutil.copytree(target, link)
        return "copie"

    monkeypatch.setattr(LinkMaker, "_create", staticmethod(_copy_instead_of_link))
    maker = LinkMaker()
    with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
        maker(tmp_path / "copy", source)
    _rm_that_does_nothing(monkeypatch)
    try:
        with pytest.raises(AssertionError, match="au rămas"):
            maker.cleanup()
        assert (tmp_path / "copy" / "secret").exists(), "precondiția: rămășița chiar există"
    finally:
        monkeypatch.undo()
        shutil.rmtree(tmp_path / "copy", ignore_errors=True)  # un director obișnuit: rmtree merge
    assert not (tmp_path / "copy").exists(), "testul însuși a lăsat copia în urmă"


def test_cleanup_clears_an_empty_directory_when_the_bash_rm_leaves_it_behind(tmp_path,
                                                                           monkeypatch):
    """Copia respinsă a unei ținte GOALE e un director gol la calea cerută: dacă pasul `rm` din
    bash nu-l scoate, `link.unlink()` cade (director), iar `link.rmdir()` e singurul pas rămas.
    Fără el, curățarea ar raporta „au rămas" pentru un director pe care îl putea șterge, iar
    testul care a sărit ar lăsa și o eroare de teardown.

    Doar acesta e cazul în care `rmdir` face ceva: pe Windows `Path.unlink()` scoate deja o
    legătură-director (reparse point), iar pe Linux o legătură adevărată, deci `rmdir` e
    atins numai de un director GOL obișnuit. Perechea testului de mai sus (aceeași stare,
    dar director NEGOL: nu se poate șterge, curățarea ridică) — împreună fixează că `rmdir`
    șterge ce poate și că nu ascunde ce nu poate.

    `rm`-ul care nu șterge e SIMULAT: un `rm` real care eșuează pe un director gol nu l-am
    putut produce (un handle deschis ar împiedica și `rmdir`, deci cele două ar eșua
    împreună). Testul dovedește ce face curățarea când pasul bash nu a șters, nu că pasul
    bash eșuează în practică; ramura rămâne ca ultim pas al lanțului pentru cazul acela,
    iar acesta e singurul ei observator.

    Falsificat reducând `(link.unlink, link.rmdir)` la `(link.unlink,)`: directorul rămâne,
    curățarea ridică."""
    source = tmp_path / "source"
    source.mkdir()

    def _copy_instead_of_link(link, target, is_dir):
        shutil.copytree(target, link)
        return "copie"

    monkeypatch.setattr(LinkMaker, "_create", staticmethod(_copy_instead_of_link))
    maker = LinkMaker()
    with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
        maker(tmp_path / "copy", source)
    assert present(tmp_path / "copy") and not is_link(tmp_path / "copy"), (
        "precondiția: există un director obișnuit la calea cerută")
    assert not any((tmp_path / "copy").iterdir()), "precondiția: directorul e GOL"
    _rm_that_does_nothing(monkeypatch)
    try:
        maker.cleanup()  # nu are voie să ridice: rmdir a scos directorul gol
        assert not present(tmp_path / "copy"), "directorul gol a rămas după fallback"
        assert source.is_dir(), "sursa a fost atinsă"
    finally:
        monkeypatch.undo()
        if (tmp_path / "copy").is_dir():
            (tmp_path / "copy").rmdir()  # un director gol obișnuit: rmdir merge


def test_cleanup_still_clears_a_link_when_the_bash_rm_leaves_it_behind(tmp_path, monkeypatch):
    """Dacă pasul `rm -rf` din bash nu șterge legătura, curățarea o scoate prin numele pe care
    îl vede Python: `link.unlink()` pe Linux/WSL (symlink adevărat) sau fișierul `NUME.lnk`
    (read-only, deci după `chmod`) pe Windows. Fără ele, un `.lnk` rămas ar face un `rmtree`
    ulterior pe arborele temporar să cadă cu `PermissionError [WinError 5]` și să lase resturi
    la un test fără legătură cu acesta.

    `rm`-ul care nu șterge e SIMULAT (un `rm` real care eșuează nu l-am putut produce), deci
    testul dovedește ce face curățarea când pasul bash nu a șters, nu că pasul bash eșuează în
    practică. Fiecare ramură are observatorul ei pe propria platformă: pe Windows, scoaterea
    `chmod`-ului dinaintea `unlink` face curățarea să ridice (fișierul `.lnk` e read-only); pe
    Linux, scoaterea buclei `unlink`/`rmdir`. Pe cealaltă platformă mutația respectivă nu are
    efect (ramura nu rulează acolo), deci falsificarea se face pe ambele. Ramura `if lnk.exists()`
    în sine are un observator fără nimic simulat: testul următor.

    Dacă ceva pică, `finally` șterge legătura cu `rm` real (patch-ul e anulat înainte), ca
    arborele temporar să nu rămână cu un `.lnk` read-only."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("K\n", encoding="utf-8", newline="\n")
    maker = LinkMaker()
    maker(tmp_path / "link", target)
    assert is_link(tmp_path / "link"), "precondiția: există o legătură"
    _rm_that_does_nothing(monkeypatch)
    try:
        maker.cleanup()  # nu are voie să ridice: fallback-ul a scos legătura
        assert not present(tmp_path / "link"), "legătura a rămas după fallback"
        assert not _lnk_files(tmp_path), "fișier .lnk rămas după fallback"
        assert (target / "keep").read_text(encoding="utf-8") == "K\n", "ținta a fost atinsă"
    finally:
        monkeypatch.undo()
        _sh('rm -rf -- "$1"', tmp_path / "link")
    shutil.rmtree(tmp_path / "target")  # un rmtree ulterior nu trebuie să cadă


def test_cleanup_removes_a_half_made_lnk_that_bash_cannot_see(tmp_path, monkeypatch):
    """Un `NUME.lnk` care nu e o scurtătură MSYS validă (scris pe jumătate, trunchiat) nu e văzut
    de bash la numele `NUME`: `[ -L NUME ]` și `[ -e NUME ]` sunt false (măsurat pe Git Bash
    5.2.37), deci pasul `rm -rf NUME` nu are ce șterge. Doar numele pe care îl vede Python
    (`NUME.lnk`) îl scoate. Fără ramura aceea, fișierul rămâne în arborele temporar, read-only,
    iar un `rmtree` ulterior cade cu `PermissionError` la un test fără legătură cu acesta.

    Aici ramura Python-name nu depinde de un `rm` simulat: bash chiar nu vede nimic. Fișierul
    e făcut read-only (cum îl lasă `ln`), deci și `chmod`-ul dinaintea ștergerii e exersat pe
    Windows; pe Linux un fișier `NUME.lnk` obișnuit se șterge oricum, iar testul rămâne o
    probă a ramurei, nu a atributului.

    Falsificat scoțând ramura `if lnk.exists():` (curățarea ridică: a rămas ceva) și
    înlocuind `if present(link) or lnk.exists():` cu `if present(link):` (nu ridică, dar
    fișierul rămâne: aserțiunea de la sfârșit)."""
    target = tmp_path / "target"
    target.mkdir()
    half_made = tmp_path / "link.lnk"

    def _half_made_lnk(link, target, is_dir):
        half_made.write_bytes(b"not a shortcut")
        half_made.chmod(0o444)
        return "legătură întreruptă"

    monkeypatch.setattr(LinkMaker, "_create", staticmethod(_half_made_lnk))
    maker = LinkMaker()
    try:
        with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
            maker(tmp_path / "link", target)
        assert half_made.exists() and not present(tmp_path / "link"), (
            "precondiția: fișierul există, dar bash nu vede nimic la numele `link`")

        maker.cleanup()  # nu are voie să ridice: Python-name a scos fișierul

        assert not half_made.exists(), "fișierul .lnk pe jumătate a rămas după cleanup"
    finally:
        monkeypatch.undo()
        if half_made.exists():
            half_made.chmod(0o600)
            half_made.unlink()
    shutil.rmtree(target)  # un rmtree ulterior nu trebuie să cadă


def test_cleanup_reports_a_half_made_lnk_it_could_not_remove(tmp_path, monkeypatch):
    """Dacă nici numele Python nu poate scoate fișierul (blocat de un alt proces, antivirus),
    curățarea trebuie să ridice: altfel testul ar trece, iar `.lnk`-ul ar rămâne în arbore și
    ar strica `rmtree`-ul de la sfârșitul sesiunii.

    Fișierul e unul pe care bash nu-l vede (`present(link)` fals), deci singurul lucru care îl
    ține în lista de rămășițe e `lnk.exists()` din verificarea finală: dacă verificarea s-ar
    uita doar la numele bash, curățarea ar tăcea. `Path.unlink` e SIMULAT ca blocat (pe Linux
    un fișier deschis se șterge oricum, deci nu am cum să-l blochez cu adevărat), deci testul
    dovedește ce raportează curățarea când ștergerea eșuează, nu că fișierul se blochează.

    Falsificat înlocuind `if present(link) or lnk.exists():` cu `if present(link):`."""
    target = tmp_path / "target"
    target.mkdir()
    half_made = tmp_path / "link.lnk"

    def _half_made_lnk(link, target, is_dir):
        half_made.write_bytes(b"not a shortcut")
        return "legătură întreruptă"

    monkeypatch.setattr(LinkMaker, "_create", staticmethod(_half_made_lnk))
    maker = LinkMaker()
    try:
        with pytest.raises(pytest.skip.Exception, match="nu e stabilită"):
            maker(tmp_path / "link", target)
        assert half_made.exists() and not present(tmp_path / "link"), (
            "precondiția: fișierul există, dar bash nu vede nimic la numele `link`")

        def _locked(self, missing_ok=False):
            raise PermissionError(32, "fișier blocat (simulat)")

        monkeypatch.setattr(Path, "unlink", _locked)
        with pytest.raises(AssertionError, match="au rămas"):
            maker.cleanup()
    finally:
        monkeypatch.undo()
        if half_made.exists():
            half_made.chmod(0o600)
            half_made.unlink()
    shutil.rmtree(target)  # un rmtree ulterior nu trebuie să cadă
