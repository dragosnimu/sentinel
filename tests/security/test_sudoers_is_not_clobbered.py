"""Pasul care creează contul de automatizare nu are voie să calce peste sudoers.

## Eșecul, întâmplat

Pe 25 august 2026, `step_deploy_account` a scris `/etc/sudoers.d/sentinel-deploy`
— numele evident. Pe gazda de producție, fișierul cu ACEL nume exista deja: era
regula `NOPASSWD` scrisă de mână de operator, fiindcă `docs/CHANGELOG.md` 0.6.0
spune că un deploy pornit de pe Windows are nevoie de una.

A fost suprascris. Nimic n-a eșuat: `visudo -cf` a validat fișierul nou, pasul a
raportat succes, iar `sudo` fără parolă al operatorului pur și simplu n-a mai
existat — descoperit abia la următoarea comandă privilegiată.

E tiparul din `CLAUDE.md` într-o formă nouă: nu „am confirmat intenția în locul
efectului", ci **„am confirmat efectul pe care l-am vrut, fără să mă uit la cel
pe care l-am produs"**. Fișierul CHIAR a fost scris corect. Doar că peste altceva.

## Ce se cere aici

Trei lucruri, fiindcă oricare singur ar fi ocolit de următoarea versiune:

1. numele fișierului să nu fie unul pe care l-ar alege și un om;
2. pasul să REFUZE să scrie peste un fișier fără marcajul lui;
3. marcajul să fie chiar scris, altfel verificarea de la punctul 2 n-are ce găsi
   la a doua rulare și pasul s-ar refuza pe sine.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")

#: Corpul pasului, tăiat din script. Se caută în el, nu în tot fișierul: o
#: potrivire dintr-un alt pas ar face testul să treacă despre alt cod.
STEP = INSTALL.split("step_deploy_account() {", 1)[-1].split("\nstep_", 1)[0]


def _assigned(name: str) -> str | None:
    """Valoarea atribuită unei variabile locale în pas, sau `None`.

    Se citește ATRIBUIREA, nu se caută șirul oriunde în corp — iar diferența e
    ce a lăsat prima falsificare să treacă: mesajul de avertizare conține un
    exemplu de cale (`/etc/sudoers.d/50-operator`), iar un test care caută un
    tipar „undeva în pas" îl găsea acolo și trecea verde chiar după ce codul
    revenise la numele periculos.

    O gardă care se poate satisface din propriul text de ajutor nu păzește nimic.
    """
    m = re.search(rf"^\s*local {re.escape(name)}=(\S+)\s*$", STEP, re.M)
    return m.group(1) if m else None


def test_the_step_exists_at_all() -> None:
    """Garda tăierii de mai sus: pe un `install.sh` din care pasul a dispărut,
    `STEP` ar fi tot fișierul, iar fiecare test de mai jos ar trece degeaba."""
    assert "step_deploy_account() {" in INSTALL
    assert len(STEP) < len(INSTALL) / 2
    assert "sudoers" in STEP


def test_the_sudoers_file_is_not_a_name_a_human_would_pick() -> None:
    """`/etc/sudoers.d/sentinel-deploy` e numele pe care l-a ales operatorul.

    Se citește VALOAREA lui `sudoers=`, nu se caută un tipar prin pas: prima
    versiune a testului trecea și după ce codul revenea la numele periculos,
    fiindcă mesajul de ajutor de mai jos conține el însuși o cale cu prefix
    numeric.
    """
    cale = _assigned("sudoers")
    assert cale is not None, "pasul nu mai atribuie niciun fișier de sudoers"
    assert cale.startswith("/etc/sudoers.d/"), cale

    nume = cale.rsplit("/", 1)[-1]
    assert nume != "sentinel-deploy", (
        "pasul scrie exact în fișierul în care operatorul își ține regula lui — "
        "asta e chiar paguba din 25 august 2026")
    assert re.match(r"^\d+-", nume), (
        f"{nume} n-are prefix numeric, deci ordinea de citire e la voia "
        f"întâmplării într-un director în care ultimul câștigă")


def test_the_step_refuses_to_overwrite_a_file_it_did_not_write() -> None:
    """Regula care ar fi oprit paguba.

    Un fișier de sudoers pe care nu l-am scris noi e accesul cuiva. Se pierde o
    dată și se descoperă la următoarea comandă privilegiată — adică exact când
    omul are nevoie de el.

    Se cere CONDIȚIA, cu tot cu ce compară: un `if false` lăsa prima versiune a
    testului verde, fiindcă ea căuta doar prezența unui `grep` undeva în pas.
    """
    conditie = re.search(r"^\s*if \[\[ -e \"\$sudoers\" \]\] && ! grep -qF "
                         r"\"\$marker\" \"\$sudoers\"; then\s*$",
                         STEP, re.M)
    assert conditie, (
        "pasul nu mai verifică, înainte de a scrie, dacă fișierul există și "
        "poartă marcajul lui. Fără condiția asta scrie peste orice")

    # Refuzul trebuie să fie o IEȘIRE, nu o avertizare urmată de scriere.
    assert STEP.index("return 0") < STEP.index("chmod 0440"), (
        "pasul avertizează și scrie oricum — o avertizare urmată de paguba pe "
        "care o descrie e mai rea decât tăcerea, fiindcă arată ca o alegere")


def test_the_marker_is_actually_written() -> None:
    """Fără marcaj scris, verificarea de mai sus n-ar găsi nimic la a doua
    rulare, iar pasul s-ar refuza pe sine — o instalare care merge o dată."""
    assert "marker=" in STEP
    scrieri = re.findall(r'printf [^\n]*"\$marker"', STEP)
    assert scrieri, "marcajul se caută, dar nu se scrie niciodată"


def test_the_step_tells_the_operator_what_the_old_version_broke() -> None:
    """Pe gazdele care au rulat prima versiune, paguba e deja făcută.

    Nu se repară automat — nu știm ce scria în regula lor, iar a ghici într-un
    fișier de sudoers e mai rău decât a spune ce s-a întâmplat. Dar TREBUIE spus:
    altfel operatorul află singur, peste săptămâni, dintr-un `sudo` care cere
    parolă fără motiv.

    Se citește VALOAREA lui `clobbered=`: prima versiune a testului trecea și cu
    `clobbered=/dev/null`, fiindcă numele vechi apare oricum în textul
    mesajului.
    """
    vechi = _assigned("clobbered")
    assert vechi == "/etc/sudoers.d/sentinel-deploy", (
        f"pasul se uită la {vechi!r} în loc de fișierul pe care versiunea veche "
        f"îl scria, deci gazdele deja stricate nu află niciodată de ce le cere "
        f"sudo o parolă")
    assert "visudo -c" in STEP, "sfatul dat operatorului nu include validarea"


@pytest.mark.parametrize("interzis", ["rm -rf /etc/sudoers", "> /etc/sudoers\n",
                                      "chmod 0777", "chmod 777"])
def test_the_step_never_touches_the_main_sudoers_file(interzis: str) -> None:
    """`/etc/sudoers` însuși nu se atinge niciodată.

    O eroare de sintaxă acolo face `sudo` să refuze totul pentru toată lumea,
    inclusiv pentru operatorul care încearcă să repare — iar asta e o încuiere
    adevărată, nu o parolă în plus.
    """
    assert interzis not in STEP
