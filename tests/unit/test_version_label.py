"""Nota de versiune din bara laterală: de unde vine, când spune „beta", și ce NU face.

Eșecurile pe care le previne, în termeni de ce vede operatorul:

* panoul arată `0.18.0` la nesfârșit, deși `VERSION` s-a mutat, fiindcă cifra a fost scrisă într-un
  șablon în loc să fie citită de la sursă (testele de drift: schimbă sursa, cer ca pagina s-o urmeze);
* cuvântul „beta" rămâne pe pagină după `1.0.0` — o etichetă care minte, fiindcă nu mai e legată
  de cifră;
* „beta" apare peste o versiune care nu s-a putut citi (`0.0.0+unknown`, fallback-ul lui
  `sentinel._read_version`) — o afirmație fără fapt în spate;
* un `version=` pus în contextul unei pagini (testele existente îl pun) schimbă ce spune bara;
* regula din Python se desparte de cea din agregator (`aggregator/lib/version.ts`): se compară
  expresia regulată, la octet;
* foaia de stil nu are regula pentru clasa emisă, sau o folosește pe o variabilă nedefinită — nota
  ar apărea ca text simplu, ori în culoarea moștenită, fără nicio eroare.

Fraza „sub 1.0 pentru că e beta" e o constrângere asupra numărului, nu o aserțiune de aici: un test
care cere `VERSION < 1.0` ar deveni roșu exact în ziua în care cuvântul trebuie să dispară singur.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
CSS = REPO / "sentinel" / "web" / "static" / "css" / "sentinel.css"
VERSION_TS = REPO / "aggregator" / "lib" / "version.ts"

# Aceleași cazuri ca în `aggregator/tests/version.test.ts` (tabelul „regula de etapă").
CASES = [
    ("0.1.0", "beta"), ("0.18.0", "beta"), ("0.99.99", "beta"),
    ("1.0.0", "stable"), ("1.2.3", "stable"), ("10.0.0", "stable"),
    ("1.0.0-rc1", "beta"), ("1.2.3+build5", "stable"), ("0.0.0+unknown", "unknown"),
    ("", "unknown"), ("x", "unknown"), ("1.0", "unknown"), ("1.0.0\n", "unknown"),
    ("1.0.0-<b>x</b>", "unknown"),
    # Cifre care nu sunt 0-9: `\d` din Python le primește fără `re.ASCII`, cel din JavaScript nu.
    ("\uff11.0.0", "unknown"), ("0.\u0663.0", "unknown"),
]


def _sidebar_html(monkeypatch, source_version: str, **extra_ctx) -> str:
    """Bara laterală randată de `base.html` cu `sentinel.__version__` mutat la `source_version`.

    Mediul se construiește DUPĂ mutare, ca în aplicație: globalele se calculează la construire.
    """
    import sentinel
    from sentinel.web.jinja import build_env

    monkeypatch.setattr(sentinel, "__version__", source_version)
    env = build_env("Europe/Bucharest")
    page = env.from_string('{% extends "base.html" %}')
    html = page.render(user=SimpleNamespace(username="op", role="owner"), active="dashboard",
                       csrf_token="t", **extra_ctx)
    return html.split('<aside class="sidebar">')[1].split("</aside>")[0]


def _text(fragment: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", fragment).split())


def _note(side: str) -> str:
    m = re.search(r'<p class="version-foot".*?</p>', side, flags=re.S)
    assert m, "bara laterală n-are nota de versiune"
    return m.group(0)


@pytest.mark.parametrize("version,stage", CASES)
def test_release_stage_table(version, stage):
    """Eșecul pe care îl previne: pragul „sub 1.0" se mută (`<= 1`, `< 2`) sau o versiune
    necitită primește «beta» — operatorul citește o afirmație pe care nimic n-o susține."""
    from sentinel.web.jinja import release_stage

    assert release_stage(version) == stage


def test_the_version_the_sidebar_shows_is_the_VERSION_file(monkeypatch):
    """Eșecul pe care îl previne: bara arată altceva decât fișierul `VERSION`. Citit SEPARAT de
    pachet — `sentinel.__version__` e chiar mecanismul de sub test."""
    import sentinel

    on_disk = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    assert sentinel.__version__ == on_disk, "sentinel.__version__ nu vine din VERSION"

    side = _sidebar_html(monkeypatch, on_disk)
    assert f"Versiune {on_disk}" in _text(_note(side))


def test_the_sidebar_follows_the_source_when_it_moves(monkeypatch):
    """DRIFT. Eșecul pe care îl previne: cifra scrisă în șablon sau memorată la import — panoul
    spune `0.18.0` și după ce `VERSION` a ajuns `0.99.7`."""
    side = _sidebar_html(monkeypatch, "0.99.7")
    assert _text(_note(side)) == "Versiune 0.99.7 · beta"
    assert "0.18" not in side


def test_beta_disappears_by_itself_at_1_0(monkeypatch):
    """Eșecul pe care îl previne: „beta" rămâne după 1.0.0. Cuvântul e derivat din cifră, deci
    ziua în care `VERSION` devine 1.0.0 îl scoate fără ca cineva să-și amintească."""
    side = _sidebar_html(monkeypatch, "1.0.0")
    assert _text(_note(side)) == "Versiune 1.0.0"
    assert "beta" not in side.lower()


def test_an_unreadable_version_is_unknown_and_never_beta(monkeypatch):
    """Eșecul pe care îl previne: `0.0.0+unknown` (ce dă `_read_version` fără fișier) se afișează
    ca «Versiune 0.0.0+unknown · beta». Reproducem fallback-ul prin mecanismul lui: fișierul
    `VERSION` ilizibil, nu un șir scris de mână."""
    import sentinel

    def refuse(self, *a, **k):
        raise OSError("VERSION nu se poate citi")

    with monkeypatch.context() as m:
        m.setattr(Path, "read_text", refuse)
        fallback = sentinel._read_version()
    assert fallback == "0.0.0+unknown", "fallback-ul lui _read_version s-a schimbat"

    side = _sidebar_html(monkeypatch, fallback)
    assert _text(_note(side)) == "Versiune necunoscută"
    assert "beta" not in side.lower() and "0.0.0" not in side


def test_a_page_context_version_cannot_change_the_note(monkeypatch):
    """Eșecul pe care îl previne: testele de pagini pun `version="1"` în context; subsolul îl
    ascultă, bara NU — altfel o pagină ar putea s-o contrazică (`release`, nu `version`)."""
    side = _sidebar_html(monkeypatch, "0.18.0", version="7.7.7")
    assert "7.7.7" not in side
    assert _text(_note(side)) == "Versiune 0.18.0 · beta"


def test_the_note_sits_under_the_user_and_the_logout_button(monkeypatch):
    """Eșecul pe care îl previne: nota între linkurile de navigare, sau înaintea lui «Ieșire» —
    ar împinge butonul de ieșire în sus și ar concura cu navigarea. Ordinea: navigare, utilizator,
    ieșire, notă; plus: o singură dată în bară."""
    side = _sidebar_html(monkeypatch, "0.18.0")
    user = side.index('class="userbox')
    logout = side.index('action="/logout"')
    note = side.index('class="version-foot"')
    nav_end = side.index("</nav>")
    assert nav_end < user < logout < note
    assert side.count('class="version-foot"') == 1
    assert note > side.index("Ieșire")


@pytest.mark.parametrize("source", ["0.0.0+unknown", "0.18", "v0.18.0"])
def test_the_unknown_hover_is_true_for_both_causes(monkeypatch, source):
    """Eșecul pe care îl previne: titlul spune „fișierul VERSION n-a putut fi citit" și când
    fișierul a fost citit perfect, dar conține `0.18` sau `v0.18.0` — operatorul caută o problemă
    de permisiuni acolo unde era una de format. Titlul trebuie să numească și forma cerută."""
    note = _note(_sidebar_html(monkeypatch, source))
    assert _text(note) == "Versiune necunoscută"
    title = re.search(r'title="([^"]*)"', note)
    assert title, "nota «necunoscută» n-are nicio explicație la hover"
    assert "X.Y.Z" in title.group(1), "titlul nu spune ce formă se așteaptă"
    assert "n-a putut fi citit" not in title.group(1), "titlul acuză o cauză care poate fi alta"


def test_a_beta_note_explains_itself_on_hover(monkeypatch):
    """Eșecul pe care îl previne: „beta" fără nicio explicație. Titlul spune ce înseamnă — și
    lipsește când nu e beta."""
    beta = _note(_sidebar_html(monkeypatch, "0.18.0"))
    assert 'title="Versiune beta (sub 1.0)' in beta
    stable = _note(_sidebar_html(monkeypatch, "1.0.0"))
    assert "title=" not in stable


def test_the_python_and_aggregator_rules_use_the_same_pattern():
    """Eșecul pe care îl previne: cele două părți ale panoului deosebesc altfel «beta» de
    «necunoscută». Regula e scrisă de două ori (Python, TypeScript); expresia e comparată la
    octet, ca divergența să pice un test, nu să apară pe ecran.

    ATENȚIE la ce NU dovedește: compară TEXTUL expresiei, nu motorul care o execută. Steagurile
    (`re.ASCII`) și semantica (cifra din expresie e Unicode în Python, doar 0-9 în JavaScript) nu se văd într-un
    șir; ele le acoperă cazurile din `CASES` (cifre fullwidth și arabo-indice), rulate pe ambele
    părți. Cine scoate `re.ASCII` din `_SEMVER` lasă acest test verde și pică acela."""
    from sentinel.web.jinja import _SEMVER

    ts = VERSION_TS.read_text(encoding="utf-8")
    m = re.search(r"= /(\^.*\$)/\.exec\(version\)", ts)
    assert m, "n-am găsit expresia regulată în aggregator/lib/version.ts"
    assert m.group(1) == _SEMVER.pattern


def test_the_stylesheet_styles_the_class_and_defines_every_variable_it_uses():
    """Eșecul pe care îl previne: șablonul emite `.version-foot`, foaia n-are regula (nota apare
    ca text simplu, fără nicio eroare) sau o scrie cu o variabilă nedefinită (culoarea cade pe cea
    moștenită, tot fără eroare)."""
    css = CSS.read_text(encoding="utf-8")
    found = re.findall(r"\.(version-foot|version-beta)\s*\{([^}]*)\}", css)
    # `.version-foot` mai apare o dată, în banda îngustă, cu `display: none`: aceea nu e regula
    # care o stilează, deci nu trebuie să țină locul uneia lipsă.
    styled = {name for name, body in found if "display: none" not in body}
    assert styled == {"version-foot", "version-beta"}, "foaia nu stilează clasele emise"
    for name, body in found:
        for var in re.findall(r"var\((--[a-z0-9-]+)", body):
            assert re.search(rf"^\s*{re.escape(var)}\s*:", css, flags=re.M), (
                f".{name} folosește {var}, nedefinită în sentinel.css")
