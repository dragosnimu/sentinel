"""`VERSION` și primul titlu din `docs/CHANGELOG.md` numesc aceeași versiune.

Eșecul pe care îl previne, în termeni de ce vede operatorul: bara laterală a panoului (și cea
a agregatorului) arată numărul din `VERSION`, iar changelog-ul proiectului spune, de săptămâni,
că s-a livrat altceva. Operatorul citește „0.18.0" pe ecran și „0.22.7" în istoricul livrărilor
și nu are de unde ști care dintre ele minte.

Asta s-a și întâmplat: la `caf0681` (3 aug 2026) changelog-ul a trecut la `0.19.1` iar `VERSION`
a rămas `0.18.0`. Până la `8d0b2d5` — 213 commit-uri mai târziu — erau `0.18.0` și `0.22.7`, patru
versiuni minore între ele, și nimic nu s-a plâns două luni. Testul ăsta ar fi fost roșu pe fiecare
dintre ele. Cifra ajunsese să conteze abia când a vrut cineva s-o pună pe ecran.

Ce înseamnă „versiunea din titlu":

* se citește PRIMUL titlu `## ` din fișier — cel mai de sus. O intrare adăugată sub cea mai
  nouă nu poate satisface testul, fiindcă nu e cea pe care o citește un om care deschide fișierul;
* titlul trebuie să fie un titlu de-adevăratelea, nu ceva care doar arată ca unul: nu contează
  liniile din blocuri de cod (``` sau ~~~), din comentarii HTML, indentate cu 4+ spații ori de
  nivel `###`;
* numărul e primul cuvânt după `## `, comparat ÎNTREG cu `VERSION` — nu cu începutul lui.
  `0.22.80`, `0.22.8.`, `0.22.8-rc1` sau `0.22.8—titlu` (fără spațiu înainte de linioară) nu
  sunt `0.22.8`: un prefix care se potrivește ar lăsa `0.22.80` să treacă drept `0.22.8`;
* spațiile de la capătul liniei, CRLF-ul și un BOM la începutul fișierului nu schimbă ce spune
  titlul și nu-l pot ascunde: fișierul se citește cu `utf-8-sig`, altfel un BOM ar face ca
  prima linie să nu mai fie recunoscută ca titlu și testul ar citi în locul ei pe următoarea;
* un titlu de sus care nu e o versiune (`## Unreleased`) face testul roșu, intenționat: nu
  există convenția asta aici, iar a o introduce e o decizie care se ia, nu o scăpare.

Regula e verificată de două ori: o funcție pură (`disagreement`) e pusă să refuze fiecare
încercare de a-o păcăli (tabelul `EVASIONS`), apoi ACEEAȘI funcție e rulată pe fișierele reale.
Un test doar pe fișierele reale ar fi verde azi și n-ar dovedi că regula distinge ceva.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
VERSION_FILE = REPO / "VERSION"
CHANGELOG = REPO / "docs" / "CHANGELOG.md"

# Caractere invizibile / ambigue în editor: scrise prin cod, ca să se vadă ce sunt.
LINE_SEP = chr(0x2028)  # separator Unicode de linie: NU e sfârșit de linie în Markdown
FULLWIDTH_ZERO = chr(0xFF10)  # `\d` din Python îl primește ca cifră; `[0-9]` nu
BOM = chr(0xFEFF)
DASH = "—"  # linioara lungă din titlurile reale: `## 0.22.8 — titlu`

# Forma X.Y.Z, cu pre-versiune / build opționale, cu cifre ASCII: `\d` din Python primește și
# cifre non-ASCII fără `re.ASCII`.
_VERSION_SHAPE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?")
# Un titlu ATX de nivel 2: 0-3 spații, `##`, apoi spațiu/tab sau sfârșit de linie. `###` nu intră.
_H2 = re.compile(r"^ {0,3}##(?:[ \t]+(.*))?$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def top_header_token(raw: bytes) -> tuple[int, str] | None:
    """(număr de linie, primul cuvânt) al primului titlu `## ` real, sau `None` dacă nu e niciunul."""
    text = raw.decode("utf-8-sig")
    # Linii ca în Markdown (\n, \r\n, \r) — nu `splitlines()`, care taie și la U+2028, \x0b, \x85:
    # un `## ` după un astfel de caracter, în mijlocul unui paragraf, n-a început niciun titlu.
    fence: str | None = None  # marcajul care a deschis blocul de cod curent
    in_comment = False
    for lineno, line in enumerate(re.split(r"\r\n|\r|\n", text), start=1):
        if fence is not None:
            m = _FENCE.match(line)
            # Închide doar același caracter, cel puțin la fel de lung, fără nimic după el.
            if (m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence)
                    and not m.group(2).strip()):
                fence = None
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        m = _FENCE.match(line)
        # Un gard cu backtick-uri nu are voie să aibă backtick în restul liniei (altfel e cod inline).
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            fence = m.group(1)
            continue
        if "<!--" in line and "-->" not in line.split("<!--")[-1]:
            in_comment = True
            continue
        h = _H2.match(line)
        if h:
            words = (h.group(1) or "").split()
            return lineno, (words[0] if words else "")
    return None


def disagreement(changelog: bytes, version: str) -> str | None:
    """De ce nu se potrivesc, ca text pentru operator; `None` dacă `version` e titlul de sus."""
    if not _VERSION_SHAPE.fullmatch(version):
        return f"VERSION nu e o versiune (X.Y.Z): {version!r}"
    top = top_header_token(changelog)
    if top is None:
        return "docs/CHANGELOG.md nu are niciun titlu `## ` — nu se poate citi versiunea livrată"
    lineno, token = top
    if token != version:
        return (f"primul titlu din docs/CHANGELOG.md (linia {lineno}) spune {token!r}, "
                f"dar VERSION spune {version!r} — una s-a mutat fără cealaltă")
    return None


def _cl(*lines: str, eol: str = "\n") -> bytes:
    return (eol.join(lines) + eol).encode("utf-8")


# (nume, changelog, VERSION, se potrivesc?). Fiecare rând „False" e o încercare de a păcăli regula.
EVASIONS = [
    ("agree", _cl("# Changelog", "", f"## 0.22.8 {DASH} t", "", "text", f"## 0.22.7 {DASH} u"),
     "0.22.8", True),
    # --- cele două direcții în care se desparte în realitate ---
    ("version bumped alone",
     _cl("# Changelog", "", f"## 0.22.8 {DASH} t"), "0.22.9", False),
    ("header added alone, VERSION stays",
     _cl("# Changelog", f"## 0.22.9 {DASH} t", f"## 0.22.8 {DASH} u"), "0.22.8", False),
    # --- numărul corect, dar nu în titlul de sus ---
    ("right number but not the top header",
     _cl(f"## 0.23.0 {DASH} t", f"## 0.22.8 {DASH} u"), "0.22.8", False),
    ("right number only as the last header",
     _cl(f"## 0.23.0 {DASH} t", f"## 0.22.9 {DASH} u", f"## 0.22.8 {DASH} v"), "0.22.8", False),
    # --- potriviri pe prefix / separator ---
    ("0.22.80 is not 0.22.8", _cl(f"## 0.22.80 {DASH} t"), "0.22.8", False),
    ("0.22.8 is not 0.22.80", _cl(f"## 0.22.8 {DASH} t"), "0.22.80", False),
    ("trailing dot", _cl(f"## 0.22.8. {DASH} t"), "0.22.8", False),
    ("pre-release suffix", _cl(f"## 0.22.8-rc1 {DASH} t"), "0.22.8", False),
    ("no space before the dash", _cl(f"## 0.22.8{DASH}t"), "0.22.8", False),
    ("v prefix", _cl(f"## v0.22.8 {DASH} t"), "0.22.8", False),
    ("fullwidth digits", _cl(f"## {FULLWIDTH_ZERO}.22.8 {DASH} t"), "0.22.8", False),
    # --- ce arată a titlu și nu e ---
    ("h3 above the real header",
     _cl(f"### 0.22.8 {DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("h1 is not a release header",
     _cl(f"# 0.22.8 {DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("no space after ##", _cl(f"##0.22.8 {DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("inline html comment", _cl("<!-- ## 0.22.8 -->", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("multi-line html comment",
     _cl("<!--", f"## 0.22.8 {DASH} t", "-->", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("backtick fence",
     _cl("```", f"## 0.22.8 {DASH} t", "```", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("tilde fence",
     _cl("~~~", f"## 0.22.8 {DASH} t", "~~~", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("fence with info string",
     _cl("```markdown", f"## 0.22.8 {DASH} t", "```", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("shorter marker does not close a longer fence",
     _cl("````", "```", f"## 0.22.8 {DASH} t", "````", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("a different fence character does not close the fence",
     _cl("```", "~~~", f"## 0.22.8 {DASH} t", "```", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("a closing marker followed by text does not close the fence",
     _cl("```", "``` not a close", f"## 0.22.8 {DASH} t", "```", f"## 0.22.7 {DASH} u"),
     "0.22.8", False),
    ("indented code block",
     _cl(f"    ## 0.22.8 {DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", False),
    ("fence never closed hides the rest",
     _cl("```", f"## 0.22.8 {DASH} t"), "0.22.8", False),
    ("one leading space above the real header counts as the top",
     _cl(f" ## 0.23.0 {DASH} t", f"## 0.22.8 {DASH} u"), "0.22.8", False),
    # --- ...și invers: ce e ignorat nu are voie să strice un titlu real ---
    ("fence above the real header is skipped, header agrees",
     _cl("```", f"## 9.9.9 {DASH} x", "```", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("inline comment above the real header does not swallow it",
     _cl("<!-- note -->", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("comment above the real header is skipped, header agrees",
     _cl("<!-- ## 9.9.9 -->", "<!--", "## 8.8.8", "-->", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("fence closed, later header is not swallowed",
     _cl("~~~", "x", "~~~", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("h3 and prose above the real header are skipped",
     _cl("# Changelog", "", f"### 9.9.9 {DASH} x", "text", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("backticks in the rest of the line make it inline code, not a fence",
     _cl("```not a fence```", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    # --- ce nu schimbă ce spune titlul ---
    ("trailing whitespace", _cl(f"## 0.22.8 {DASH} t   ", f"## 0.22.7 {DASH} u"), "0.22.8", True),
    ("title-less header", _cl("## 0.22.8   ", f"## 0.22.7 {DASH} u"), "0.22.8", True),
    ("up to three leading spaces is still a header", _cl(f"   ## 0.22.8 {DASH} t"), "0.22.8", True),
    ("tab after the number", _cl(f"## 0.22.8\t{DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", True),
    ("U+2028 inside a paragraph is not a line break, so no header starts after it",
     _cl(f"text{LINE_SEP}## 0.23.0 {DASH} x", f"## 0.22.8 {DASH} t"), "0.22.8", True),
    ("lone CR is a line break",
     f"text\r## 0.23.0 {DASH} x\n## 0.22.8 {DASH} t\n".encode("utf-8"), "0.22.8", False),
    ("crlf", _cl(f"## 0.22.8 {DASH} t", f"## 0.22.7 {DASH} u", eol="\r\n"), "0.22.8", True),
    ("bom on the first line",
     b"\xef\xbb\xbf" + _cl(f"## 0.22.8 {DASH} t", f"## 0.22.7 {DASH} u"), "0.22.8", True),
    ("bom on the first line does not hide a newer header",
     b"\xef\xbb\xbf" + _cl(f"## 0.23.0 {DASH} t", f"## 0.22.8 {DASH} u"), "0.22.8", False),
    # --- cazuri în care nu se poate ști: nu se pretinde acord ---
    ("no header at all", _cl("# Changelog", "text"), "0.22.8", False),
    ("empty file", b"", "0.22.8", False),
    ("empty ## heading on top", _cl("##", f"## 0.22.8 {DASH} t"), "0.22.8", False),
    ("non-version heading on top", _cl("## Unreleased", f"## 0.22.8 {DASH} t"), "0.22.8", False),
    ("empty VERSION and empty heading must not agree", _cl("##"), "", False),
    ("empty VERSION", _cl(f"## 0.22.8 {DASH} t"), "", False),
    ("VERSION with a BOM", _cl(f"## 0.22.8 {DASH} t"), BOM + "0.22.8", False),
    ("VERSION that is not a version", _cl("## latest"), "latest", False),
]


@pytest.mark.parametrize("changelog,version,agree", [e[1:] for e in EVASIONS],
                         ids=[e[0] for e in EVASIONS])
def test_rule_tells_agreement_from_look_alikes(changelog, version, agree):
    """Regula dă „se potrivește" doar pentru un acord real și îl refuză pe orice care doar îi seamănă.

    Previne: o regulă care există dar nu face nimic — `startswith`, „oricare titlu", un titlu dintr-un
    bloc de cod — și care ar lăsa panoul să arate o cifră pe care changelog-ul n-o mai spune,
    cu testul verde.
    """
    assert (disagreement(changelog, version) is None) is agree, disagreement(changelog, version)


def test_evasion_table_is_not_hollow():
    """Tabelul are rânduri de ambele feluri; unul gol sau doar „verde" ar fi sărit/trecut tăcut.

    Previne: o parametrizare ieșită goală (pytest o sare fără zgomot) sau un tabel în care toate
    rândurile așteaptă „se potrivește", deci un test care nu poate pica.
    """
    assert sum(1 for e in EVASIONS if e[3]) >= 5
    assert sum(1 for e in EVASIONS if not e[3]) >= 25


def test_version_file_names_the_top_changelog_header():
    """`VERSION` e versiunea din primul titlu al changelog-ului — cifra de pe ecran e cea livrată.

    Previne: panoul care arată `0.18.0` când proiectul însuși spune că `0.22.7` s-a livrat de
    săptămâni. Se desparte când se mută una fără cealaltă: o livrare care ridică `VERSION` fără
    intrare în changelog, sau o intrare în changelog fără ridicarea lui `VERSION`.
    """
    # Citit ca aplicația (`sentinel._read_version`): utf-8 și `.strip()`.
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    why = disagreement(CHANGELOG.read_bytes(), version)
    assert why is None, why
