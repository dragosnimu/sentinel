"""Un comentariu care spune că ceva e păzit de un test trebuie să NUMEASCĂ testul.

De trei runde la rând, aceeași formă de defect a trecut de revizuire: un
comentariu afirma că o proprietate e ținută de un test, iar testul nu exista.

  * `refused` din ruta de sincronizare — comentariul spunea că motivul ajunge în
    jurnalul de pe server. Nu ajungea: `ship_once` scrie corpul răspunsului doar
    pe două ramuri, iar acceptarea parțială nu e niciuna dintre ele;
  * `STREAM_RANK` — ordinea gravității, prezentată ca proiectare, fără niciun
    test care să atingă un lot cu două fluxuri;
  * `serverSecretForm` — „acordul cu parserul serverului e ținut de un test care
    trece același corpus prin amândouă". Testul nu exista, și fiindcă nu exista
    trecuse o divergență reală: `str.strip()` taie cinci caractere pe care
    `String.prototype.trim` nu le taie, deci instrumentul sigila o cheie și
    serverul semna alta.

Toate trei au fost găsite de un om care citea codul. Recensământul de constante
a arătat că întrebarea unui revizor se poate muta în suită, unde nu depinde de
cine se uită; testul ăsta face același lucru pentru afirmațiile despre teste.

Ce apără, exact: un comentariu care spune „e păzit de un test" e o dovadă
raportată. Dacă e falsă, revizorul următor o crede — asta e chiar valoarea unui
depozit care își explică motivele, și de-aia o afirmație falsă costă aici mai
mult decât în altă parte.

## Ce NU face — citit înainte de a te sprijini pe el

Două limite, amândouă reale:

* **Nu verifică dacă testul numit chiar probează ce spune comentariul.** Aia nu
  poate face decât un om. Se verifică doar că referința EXISTĂ.
* **Prinde FORMULĂRI, nu ideea.** Lista de verbe de mai jos e cea cu care sunt
  scrise afirmațiile astea aici; o afirmație parafrazată altfel — „suita nu lasă
  asta să treacă", „am probat manual înainte de livrare" — trece nevăzută.
  Măsurat pe un set de parafraze, plasa prinde o parte, nu tot.

E o treaptă joasă, aleasă dinadins: închide exact clasa care a scăpat de trei
ori, fără să ceară nimic ce nu se poate decide mecanic. Nu e o dovadă că toate
afirmațiile din depozit sunt adevărate.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"

# Directoarele cu cod livrat ale agregatorului. Testele nu se scanează: acolo o
# frază despre teste e descrierea testului însuși.
SOURCE_DIRS = ("lib", "bin", "app")

# Verbele care transformă o propoziție în AFIRMAȚIE DESPRE O PROBĂ, urmate în
# aceeași frază de cuvântul „test".
#
# Scrise FĂRĂ diacritice, fiindcă textul scanat e trecut prin `_fold` înainte de
# potrivire. Motivul e o gaură măsurată: `ținut` se poate scrie cu virgulă
# dedesubt (U+021B, forma corectă, 145 de fișiere aici), cu sedilă (U+0163, 6
# fișiere aici) sau fără diacritice — trei șiruri diferite pentru același cuvânt.
# Un tipar scris într-una dintre ele lasă celelalte două să treacă, iar cine
# scrie comentariul nu alege conștient care variantă folosește: o alege
# tastatura. O afirmație falsă care ocolește paza printr-o sedilă e exact
# categoria pe care testul ăsta există ca s-o închidă.
#
# Lista de verbe e îngustă, și cifra e măsurată: peste codul de azi găsește 6
# afirmații, cu 0 false pozitive. Verbele fără „test" în frază — „`GET_LOCK` e
# legat de SESIUNE", „ăsta CHIAR e păzit de build", „plafonul rămâne legat de
# numărul de rânduri" — NU se potrivesc, și e chiar ce trebuie: sunt propoziții
# despre altceva.
#
# LIMITA, spusă pe față ca să nu fie citită mai larg decât e: tiparul prinde
# FORMULĂRILE de mai jos, nu ideea. „Suita nu lasă asta să treacă" sau „am probat
# manual" nu se potrivesc și nu vor fi prinse. E o plasă pentru felul în care
# scriem noi afirmațiile astea aici, nu o dovadă că nu există altele.
CLAIM = re.compile(
    r"(tinut|tinuta|tinute|tine|tinand|pazit|pazita|pazite|pazeste|pazesc"
    r"|aparat|aparata|apara|verificat|verificata|verifica"
    r"|probat|probata|probeaza|prins|prinsa|prinde"
    r"|dovedit|dovedita|dovedeste|dovedesc|acoperit|acoperita|acopera"
    r"|garantat|garanteaza|asigurat|asigura|exista un test|are un test|un test care)"
    r"[^.;]{0,160}?\btest\w*",
    re.IGNORECASE | re.UNICODE,
)


def _fold(text: str) -> str:
    """Textul fără diacritice, cu lungimea NESCHIMBATĂ.

    Lungimea contează: potrivirile se caută în textul pliat, iar zona de
    referință și numărul liniei se taie din cel ORIGINAL. Dacă pliarea ar muta
    pozițiile, referința găsită ar fi a altei fraze — deci fiecare caracter se
    înlocuiește cu baza lui doar când baza e tot un singur caracter.

    Acoperă amândouă convențiile românești (virgulă dedesubt și sedilă) și
    scrierea fără diacritice, fiindcă toate trei apar deja în depozit.
    """
    out: list[str] = []
    for ch in text:
        base = "".join(c for c in unicodedata.normalize("NFKD", ch)
                       if not unicodedata.combining(c))
        out.append(base if len(base) == 1 else ch)
    return "".join(out)

# Cât din text se citește după afirmație, căutând referința. Trei-patru rânduri
# de comentariu: destul cât să încapă un nume lung rupt pe rânduri, prea puțin
# cât să prindă din întâmplare referința altei afirmații.
LOOKAHEAD = 400

PY_REF = re.compile(r"tests/[\w/]+\.py(?:::(\w+))?")
TS_REF = re.compile(r"tests/[\w.-]+\.test\.tsx?")
BARE_PY = re.compile(r"\btest_[a-z0-9_]+\b")
# Ghilimelele românești se închid în depozitul ăsta și cu `”`, și cu `"` — ambele
# forme apar în comentariile existente. O expresie care ar cere doar prima ar
# rata tăcut jumătate din titluri, adică ar lăsa referința neverificată exact
# unde pare verificată.
TITLE = re.compile("„([^”\"]{6,})[”\"]")


def _sources() -> list[Path]:
    found: list[Path] = []
    for folder in SOURCE_DIRS:
        found.extend(sorted((AGGREGATOR / folder).rglob("*.ts")))
    return found


def _python_test_names() -> set[str]:
    names: set[str] = set()
    for path in (REPO / "tests").rglob("*.py"):
        names.update(re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"),
                                re.MULTILINE))
    return names


def _typescript_test_titles() -> set[str]:
    titles: set[str] = set()
    for path in (AGGREGATOR / "tests").glob("*.test.ts*"):
        text = path.read_text(encoding="utf-8")
        # `test("titlu", ...)` și `test("bucata unu" + "bucata doi", ...)`: se
        # ia prima bucată, fiindcă un titlu rupt în două rămâne recognoscibil
        # după ea.
        titles.update(re.findall(r'test\(\s*"([^"]+)"', text))
    return titles


def _resolve(reference_zone: str, py_names: set[str], ts_titles: set[str]) -> str | None:
    """Referința găsită, sau `None` dacă afirmația nu numește nimic real."""
    for match in PY_REF.finditer(reference_zone):
        path = REPO / match.group(0).split("::")[0]
        if not path.is_file():
            return None
        name = match.group(1)
        if name and name not in path.read_text(encoding="utf-8"):
            return None
        return match.group(0)

    for match in TS_REF.finditer(reference_zone):
        if not (AGGREGATOR / match.group(0)).is_file():
            return None
        # Un fișier de test e o referință valabilă, dar dacă în zonă e și un
        # titlu între ghilimele românești, el trebuie să existe.
        for title in TITLE.findall(reference_zone):
            if not any(t.startswith(title[:40]) for t in ts_titles):
                return None
        return match.group(0)

    for name in BARE_PY.findall(reference_zone):
        if name in py_names:
            return name
        return None

    return None


def test_every_claim_about_a_test_names_one_that_exists():
    """Eșecul pe care îl previne: o dovadă raportată care nu există.

    Un comentariu care spune „e ținut de un test" e citit de următorul om ca un
    fapt verificat — și tocmai fiindcă depozitul ăsta își explică motivele, e
    crezut. De trei ori la rând afirmația a fost falsă, iar de fiecare dată
    dedesubtul ei era un defect real.
    """
    py_names = _python_test_names()
    ts_titles = _typescript_test_titles()
    assert len(py_names) > 100, f"doar {len(py_names)} teste Python găsite"
    assert len(ts_titles) > 50, f"doar {len(ts_titles)} teste TypeScript găsite"

    claims = 0
    unnamed: list[str] = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        folded = _fold(text)
        assert len(folded) == len(text), f"{path}: plierea a mutat pozițiile"
        for match in CLAIM.finditer(folded):
            claims += 1
            line = text.count("\n", 0, match.start()) + 1
            # Zona se taie din textul ORIGINAL: căile și titlurile se compară cu
            # ce e chiar în suită, cu diacritice cu tot.
            zone = " ".join(text[match.start():match.start() + LOOKAHEAD].split())
            if _resolve(zone, py_names, ts_titles) is None:
                unnamed.append(f"{path.relative_to(REPO)}:{line}  „{zone[:110]}…”")

    # Bucla goală ar trece verde — chiar tiparul din CLAUDE.md. Cifra e cea
    # măsurată când a fost scris testul; scade doar dacă cineva ȘTERGE o
    # afirmație, iar atunci merită observat.
    assert claims >= 6, (
        f"doar {claims} afirmații despre teste găsite în {len(_sources())} fișiere; "
        f"tiparul nu mai prinde nimic, deci nu mai apără nimic")

    assert not unnamed, (
        "afirmații despre teste care nu numesc niciun test existent:\n  "
        + "\n  ".join(unnamed)
        + "\n\nScrie calea testului (`tests/unit/x.py::test_y`, "
          "`tests/x.test.ts`) sau titlul lui între ghilimele — ori șterge "
          "afirmația. Un comentariu care spune că o proprietate e păzită, fără "
          "ca paza să existe, e o dovadă raportată care nu există.")
