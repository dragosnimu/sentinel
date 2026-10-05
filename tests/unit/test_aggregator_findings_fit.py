"""The aggregator's vulnerability table keeps its identifiers whole AND fits its container.

What goes wrong for the operator if this fails: the CVE column (the one read first) is cut at
its hyphen, ``CVE-2026-`` over ``53362``, on every row that has one (177 of the 200 real
rows on page 1); the KEV date is cut (``2026-`` / ``08-30``) and a fixed version is cut
(``15.6.0-`` / ``canary.59``, which reads as a different version). Making the identifiers
unbreakable is the easy half. An unbreakable identifier does not give way, so the table's
minimum width becomes the sum of the widest identifier of each column: 1240 px on the n8n
instance, against the 1112 px that ``main { max-width: 72rem }`` leaves. The table pokes out
of the page (or, below the viewport width, scrolls it) unless the container is wider. The
page asks for that with ``<main class="wide">`` and ``main.wide { max-width: 100rem }``; every
other page keeps 72rem.

This reads the stylesheet as TEXT, so it runs in a fresh clone with no ``node`` and no
``aggregator/node_modules``. The markup half (what ``findingsPage`` writes, and that no other
page asks for ``wide``) is ``aggregator/tests/findings-fit.test.ts``, which needs node. The
pixel widths are MEASUREMENTS (headless Chrome, rows rebuilt from the production extremes, in
Segoe UI and in Inter) written in the comment above the rules in ``panel.css``: a test cannot
measure them, and one that pretended to would be measuring its own intention.

WHY A CASCADE AND NOT A REGEX. The first version of these checks took the FIRST rule matching
a selector. Appending ``table.findings td { white-space: nowrap }``, ``td.risc { min-width:
15rem }`` or a later padding override left it green, because the regex stopped inside the
older ``table.findings th, table.findings td`` rule or at the first ``td.risc``. What decides
the width is the cascade: the last declaration of the highest specificity that matches the
element. ``_effective`` computes that for the chains of elements the page really writes, over
every rule in the file, in order. It is small and it supports only the selectors this
stylesheet uses; ``test_the_cascade_helper_*`` are its positive controls, because a helper
that parsed nothing would make every assertion below pass.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

CSS_FILE = Path(__file__).resolve().parents[2] / "aggregator" / "public" / "panel.css"


# ---------------------------------------------------------------------------
# A cascade small enough to read, for the properties this table's fit depends on
# ---------------------------------------------------------------------------

class Rule(NamedTuple):
    selectors: tuple[str, ...]
    decls: tuple[tuple[str, str, bool], ...]  # (property, value, important)
    order: int
    media: str | None


def _strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _split_top(text: str, sep: str) -> list[str]:
    """Split on ``sep`` outside parentheses and quotes (``url(data:...;base64,...)``)."""
    out, depth, quote, cur = [], 0, "", []
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _decls(body: str) -> tuple[tuple[str, str, bool], ...]:
    found = []
    for part in _split_top(body, ";"):
        if ":" not in part:
            continue
        name, _, value = part.partition(":")
        value = value.strip()
        important = bool(re.search(r"!\s*important\s*$", value, re.I))
        value = re.sub(r"\s*!\s*important\s*$", "", value, flags=re.I).strip()
        found.append((name.strip().lower(), value, important))
    return tuple(found)


def _parse(css: str) -> list[Rule]:
    """Every style rule, in file order, with the ``@media`` condition it sits under.

    ``@media``/``@supports``/``@layer`` blocks are entered; ``@font-face``/``@keyframes`` are
    skipped (they select nothing)."""
    text = _strip_comments(css)
    rules: list[Rule] = []

    def block_end(start: int) -> int:
        depth, i = 0, start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        raise AssertionError("panel.css has an unclosed block")

    def walk(lo: int, hi: int, media: str | None) -> None:
        i = lo
        while i < hi:
            brace = text.find("{", i, hi)
            if brace < 0:
                return
            prelude = text[i:brace].strip()
            end = block_end(brace)
            if prelude.startswith("@"):
                if re.match(r"@(media|supports|layer)\b", prelude):
                    walk(brace + 1, end, prelude)
            elif prelude:
                sels = tuple(s.strip() for s in _split_top(prelude, ",") if s.strip())
                rules.append(Rule(sels, _decls(text[brace + 1:end]), len(rules), media))
            i = end + 1

    walk(0, len(text), None)
    return rules


def _css() -> str:
    css = CSS_FILE.read_text(encoding="utf-8")
    # Positive control: a stylesheet that lost everything would make every `not in` below pass.
    assert "table {" in _strip_comments(css) and "td.risc" in _strip_comments(css), \
        "panel.css was not read"
    return css


class El(NamedTuple):
    tag: str
    classes: frozenset[str] = frozenset()


def _el(spec: str) -> El:
    """``"td.risc"`` -> El("td", {"risc"})."""
    tag, *classes = spec.split(".")
    return El(tag, frozenset(classes))


_COMPOUND = re.compile(
    r"(?P<tag>\*|[A-Za-z][\w-]*)?(?P<rest>(?:\.[\w-]+|#[\w-]+|\[[^\]]*\]|::?[\w-]+(?:\([^)]*\))?)*)$")


def _compound_matches(compound: str, el: El) -> tuple[int, int, int] | None:
    """Specificity of ``compound`` if it can match ``el``, else ``None``.

    Pseudo-classes and attribute selectors COUNT AS MATCHING: this is a guard, so an
    uncertain rule is assumed to apply (a spurious red is cheap, a spurious green is the bug).
    Pseudo-elements never match the element itself; ``:root`` matches only ``html``."""
    m = _COMPOUND.match(compound)
    assert m, f"selector not understood by the test's cascade: {compound!r}"
    tag, rest = m.group("tag"), m.group("rest") or ""
    ids, classes, tags = 0, 0, 0
    if tag not in (None, "*"):
        if tag != el.tag:
            return None
        tags += 1
    for token in re.findall(r"\.[\w-]+|#[\w-]+|\[[^\]]*\]|::?[\w-]+(?:\([^)]*\))?", rest):
        if token.startswith("."):
            if token[1:] not in el.classes:
                return None
            classes += 1
        elif token.startswith("#"):
            return None  # the page writes no ids on these elements
        elif token.startswith("::"):
            return None
        elif token.startswith(":"):
            if token == ":root" and el.tag != "html":
                return None
            if token in (":before", ":after", ":first-line", ":first-letter"):
                return None
            classes += 1
        else:
            classes += 1
    return (ids, classes, tags)


def _selector_matches(selector: str, chain: list[El]) -> tuple[int, int, int] | None:
    """Does ``selector`` match ``chain[-1]``, with ancestors ``chain[:-1]``?  Descendant and
    child combinators; a sibling combinator is ignored (its left side is dropped), which can
    only make the test stricter."""
    parts = re.split(r"\s*([>+~])\s*|\s+", selector.strip())
    compounds: list[str] = []
    combs: list[str] = []
    pending = " "
    for p in parts:
        if p is None or p == "":
            continue
        if p in (">", "+", "~"):
            pending = p
        else:
            if compounds:
                combs.append(pending)
            compounds.append(p)
            pending = " "
    total = [0, 0, 0]

    def match_from(ci: int, ei: int) -> bool:
        spec = _compound_matches(compounds[ci], chain[ei])
        if spec is None:
            return False
        if ci == 0:
            for k in range(3):
                total[k] += spec[k]
            return True
        comb = combs[ci - 1]
        if comb in ("+", "~"):
            for k in range(3):
                total[k] += spec[k]
            return True
        candidates = [ei - 1] if comb == ">" else list(range(ei - 1, -1, -1))
        saved = total[:]
        for c in candidates:
            if c < 0:
                break
            if match_from(ci - 1, c):
                for k in range(3):
                    total[k] += spec[k]
                return True
            total[:] = saved
        return False

    if not match_from(len(compounds) - 1, len(chain) - 1):
        return None
    return (total[0], total[1], total[2])


def _expand(prop: str, value: str) -> list[tuple[str, str]]:
    """Shorthands that decide this table's width and type size, as longhands."""
    v = value.split()
    if prop == "padding":
        if not v or len(v) > 4:
            return [(prop, value)]
        top, right, bottom, left = {1: (0, 0, 0, 0), 2: (0, 1, 0, 1), 3: (0, 1, 2, 1),
                                    4: (0, 1, 2, 3)}[len(v)]
        return [("padding-top", v[top]), ("padding-right", v[right]),
                ("padding-bottom", v[bottom]), ("padding-left", v[left])]
    if prop == "padding-inline":
        return [("padding-left", v[0]), ("padding-right", v[-1])]
    if prop == "font":
        # `font: 15px/1.5 var(--sans)`: the size is the first token, before any `/`.
        size = next((t.split("/")[0] for t in v if re.match(r"[\d.]+(px|rem|em|%)", t)), None)
        return [("font", value)] + ([("font-size", size)] if size else [])
    return [(prop, value)]


# Viewports the page is read at: a laptop, the operator's window, desktop and ultra-wide monitors. A media
# block counts if its width conditions hold at ANY of them; `(max-width: 40rem)` (phones, where
# the table scrolls in its own box) holds at none and is left out. Other features, such as
# `prefers-color-scheme`, are assumed to apply.
_VIEWPORTS_PX = (1366, 1700, 1920, 2560, 3840)


def _media_applies(media: str | None) -> bool:
    if media is None:
        return True
    conds = re.findall(r"\(\s*(min|max)-width\s*:\s*([\d.]+)\s*(rem|em|px)\s*\)", media)
    if not conds:
        return True

    def holds(vw: int) -> bool:
        for kind, num, unit in conds:
            px = float(num) * (1.0 if unit == "px" else 16.0)
            if (kind == "min" and vw < px) or (kind == "max" and vw > px):
                return False
        return True

    return any(holds(vw) for vw in _VIEWPORTS_PX)


def _winner(rules: list[Rule], chain: list[El], prop: str) -> str | None:
    best: tuple[tuple, str] | None = None
    for rule in rules:
        if not _media_applies(rule.media):
            continue
        specs = [s for s in (_selector_matches(sel, chain) for sel in rule.selectors) if s]
        if not specs:
            continue
        spec = max(specs)
        for name, value, important in rule.decls:
            for p, v in _expand(name, value):
                if p == prop:
                    key = (important, spec, rule.order)
                    if best is None or key >= best[0]:  # `>=`: the last declaration in a rule wins
                        best = (key, v)
    return None if best is None else best[1]


def _effective(rules: list[Rule], chain: list[str], prop: str, *, inherited: bool = False):
    """The value the cascade gives ``prop`` on the last element of ``chain`` (``"td.risc"``
    style specs), or ``None`` when no rule sets it. ``inherited=True`` walks up the ancestors
    the way an inherited property (``white-space``, ``font-size``) does."""
    els = [_el(c) for c in chain]
    last = len(els) - 1 if not inherited else 0
    for k in range(len(els) - 1, last - 1, -1):
        v = _winner(rules, els[:k + 1], prop)
        if v is not None:
            return v
    return None


def _rem(value: str | None, what: str) -> float:
    assert value is not None, f"{what}: no rule sets it"
    m = re.fullmatch(r"([\d.]+)(rem|px)", value.strip())
    assert m, f"{what}: `{value}` is not in rem or px"
    return float(m.group(1)) / (16.0 if m.group(2) == "px" else 1.0)


# The chain the findings page writes: <main class="wide"><table class="findings"><tbody><tr><td>
_PAGE = ["html", "body", "main.wide", "table.findings", "tbody", "tr"]


def _cell(spec: str) -> list[str]:
    return _PAGE + [spec]


# ---------------------------------------------------------------------------
# Positive controls: the helper must see what these tests need it to see
# ---------------------------------------------------------------------------

def test_the_cascade_helper_sees_a_later_or_stronger_rule_not_just_the_first():
    """THE GUARD GOES GREEN WHILE THE TABLE OVERFLOWS AGAIN. Each case below is a way the table
    gets wider than its budget after this file is written: a later rule on the same selector, a
    more specific one, an ``!important``, a desktop ``@media`` block, a sibling selector. If
    the helper misses one, a test that "passes" proves nothing about that edit."""
    base = "td.risc { min-width: 13rem; }\n"

    def risc(extra: str, before: str = "") -> float:
        return _rem(_effective(_parse(before + base + extra), _cell("td.risc"), "min-width"),
                    "min-width")

    assert risc("") == 13
    assert risc("td.risc { min-width: 15rem; }") == 15                       # later, same selector
    assert risc("table.findings td.risc { min-width: 16rem; }") == 16        # more specific
    assert risc("td { min-width: 17rem; }") == 13                            # less specific: loses
    assert risc("td.risc { min-width: 18rem !important; } td.risc { min-width: 1rem; }") == 18
    assert risc("@media (min-width: 60rem) { td.risc { min-width: 19rem; } }") == 19
    assert risc("@media (max-width: 40rem) { td.risc { min-width: 20rem; } }") == 13  # phones only
    assert risc("@media (max-width: 1600px) { td.risc { min-width: 22rem; } }") == 22  # laptops
    assert risc("@media (min-width: 2400px) { td.risc { min-width: 23rem; } }") == 23  # big screens
    assert risc("td.risc { min-width: 24rem; min-width: 25rem; }") == 25     # last in the rule
    assert risc("td.risc:hover { min-width: 21rem; }") == 21                  # pseudo counts
    assert risc("", before="td.risc:hover { min-width: 21rem; }") == 21       # ... even EARLIER:
    assert risc("", before="td.risc[title] { min-width: 26rem; }") == 26      # it is more specific
    # padding: a shorthand on a more specific selector reaches the left/right longhands
    pad = _parse("th, td { padding: .5rem .6rem; }\n"
                 "table.findings th, table.findings td { padding-left: .5rem; padding-right: .5rem; }\n"
                 "table.findings td { padding: 1rem 2rem; }")
    assert _rem(_effective(pad, _cell("td"), "padding-left"), "pl") == 2


def test_the_cascade_helper_inherits_white_space_and_reads_the_real_stylesheet():
    """``white-space: nowrap`` on the TABLE reaches every cell by inheritance; a helper that only
    looked at the cell would miss it. And the helper must find real declarations in the real
    file, or every ``is None`` below would pass on a parse that found nothing."""
    inh = _parse("table.findings { white-space: nowrap; }")
    assert _effective(inh, _cell("td"), "white-space", inherited=True) == "nowrap"
    assert _effective(inh, _cell("td"), "white-space") is None
    rules = _parse(_css())
    assert len(rules) > 100, "panel.css parsed into almost no rules"
    assert _effective(rules, ["html", "body", "main"], "max-width") == "72rem"
    assert _effective(rules, _cell("td.risc"), "min-width") is not None


# ---------------------------------------------------------------------------
# The fit
# ---------------------------------------------------------------------------

def test_the_nowrap_class_the_markup_relies_on_is_defined_in_the_served_stylesheet():
    """THE IDENTIFIERS BREAK AGAIN, SILENTLY. ``findingsPage`` wraps each CVE, KEV date, fixed
    version, installed version and package segment in ``<span class="nowrap">``. A span whose
    class has no effective rule is just a span: nothing fails, the page renders, and
    ``CVE-2026-`` / ``53362`` is back."""
    rules = _parse(_css())
    for chain in (_cell("td") + ["span.nowrap"], _cell("td") + ["span.id.nowrap"]):
        assert _effective(rules, chain, "white-space") == "nowrap", chain


def test_the_table_is_wider_than_prose_and_only_this_page_is():
    """THE TABLE POKES OUT OF THE PAGE, OR EVERY OTHER PAGE QUIETLY GETS WIDER. The nine columns
    of the vulnerability table need 1240 px (n8n, Segoe UI) to 1392 px (Inter) and 1501 px with a
    KEV hit and an estimated CVSS (Inter); ``main`` gives 1112 px. The page opts in with
    ``<main class="wide">`` and the stylesheet gives that class 100rem: 1560 px of content (after the 1.25rem
    side padding, which is pinned too), 59 px to spare in the worst measured case. 96rem would leave it 4 px short. A later
    ``main.wide { max-width: 60rem }`` (or ``!important``) shrinks the room back below the table
    and nothing else changes. The plain ``main`` stays 72rem: the other pages are prose and
    forms, and a width taken from them would be taken from every one of them."""
    rules = _parse(_css())
    assert _rem(_effective(rules, _PAGE[:3], "max-width"), "main.wide max-width") >= 100
    assert _rem(_effective(rules, ["html", "body", "main"], "max-width"), "main max-width") == 72
    # The room is `max-width` MINUS the padding: 100rem with 4rem of padding is not 1560 px.
    for side in ("left", "right"):
        pad = _effective(rules, _PAGE[:3], f"padding-{side}")
        assert _rem(pad, f"main.wide padding-{side}") <= 1.25, (side, pad)


def test_the_table_gives_up_width_in_the_places_that_can_survive_it():
    """THE TABLE POKES OUT OF THE PAGE. These are the concessions the 100rem budget is measured
    with: Risc floor 13rem (not 15), side padding .5rem (not .6). Measured on the n8n worst case
    in Inter, putting one back leaves 37 px (Risc) or 31 px (padding) of the 59 px, and the
    KEV-whole-cell ``nowrap`` leaves 18. Judged by the cascade over the whole file, so a later
    override of either fails here instead of passing unseen."""
    rules = _parse(_css())
    assert _rem(_effective(rules, _cell("td.risc"), "min-width"), "td.risc min-width") <= 13
    for el in ("td", "td.nr", "td.risc", "th"):
        for side in ("left", "right"):
            pad = _effective(rules, _cell(el), f"padding-{side}")
            assert _rem(pad, f"{el} padding-{side}") <= 0.5, (el, side, pad)


def test_the_table_keeps_the_page_type_size():
    """THE TABLE IS SET SMALLER THAN THE PAGE TO BUY BACK WIDTH. At 14.4 px (.9rem) the table was
    4% smaller than the 15 px body, and the installed version under the package name, which
    follows the table's size, smaller with it: a loss of legibility, paid by the operator on
    every row, to cover a width the container now provides. No rule may set a size on the body
    cells, and the body stays 15 px. (``th`` keeps its own .85rem: that is the header, not the
    data.)"""
    rules = _parse(_css())
    assert _effective(rules, ["html", "body"], "font-size") == "15px", "the page body is not 15px"
    td = _cell("td")
    chains = [_PAGE[:4], _PAGE[:5], _PAGE, td, _cell("td.nr"), _cell("td.risc"),
              td + ["span.id"], td + ["span.nowrap"], td + ["span.id.nowrap"], td + ["strong"],
              _cell("td.risc") + ["span.risc-eticheta"]]
    for chain in chains:
        for prop in ("font-size", "font"):
            assert _effective(rules, chain, prop) is None, (chain[-1], prop)


def test_no_rule_forbids_the_fix_column_from_wrapping():
    """THE TABLE LEAVES ITS CONTAINER. Fix is the column that gives: the longest value is 135
    characters, nineteen versions, and the cell may break only between versions. A
    ``white-space: nowrap`` on any element that reaches a cell (the table, a row, the ``td``, the
    Risc cell) makes the column as wide as that value, 775 px on the server. Judged by the
    cascade over the whole file, INCLUDING by inheritance and including rules appended later: the
    first version of this test matched the older ``table.findings th, table.findings td`` rule
    and never saw ``table.findings td { white-space: nowrap }`` appended after it."""
    rules = _parse(_css())
    for el in ("td", "td.nr", "td.risc"):
        ws = _effective(rules, _cell(el), "white-space", inherited=True)
        assert ws not in ("nowrap", "pre"), (el, ws)


PANEL_PAGE = Path(__file__).resolve().parents[2] / "aggregator" / "lib" / "panel-page.ts"


def test_only_the_vulnerability_page_asks_for_the_wide_container():
    """EVERY PANEL PAGE QUIETLY GETS 100rem. ``main.wide`` exists for one table that cannot fit
    72rem. A second page that asks for it (or a ``page()`` that adds it to all) widens prose and
    forms nobody measured. The call sites are read from the source, so this holds in a clone
    without node; ``findings-fit.test.ts`` checks the rendered ``<main>`` of the pages it can
    build, this one checks all of them by name."""
    src = PANEL_PAGE.read_text(encoding="utf-8")
    start = src.index("export function findingsPage")
    end = src.index("\nexport function", start + 1)
    assert src.count('"wide"') == 1, "`\"wide\"` must be written once, by the vulnerability page"
    assert '"wide"' in src[start:end], "the vulnerability page no longer asks for `wide`"
    # `page()` itself must not hard-code the class: the default stays a bare <main>.
    page_fn = src[src.index("function page("):src.index("\n}\n", src.index("function page(")) + 3]
    assert "wide" not in page_fn, page_fn
