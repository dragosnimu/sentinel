"""One design system across three surfaces, and the arithmetic that proves it.

Sentinel shows the operator three separate web surfaces, from two codebases:
the dashboard (`sentinel/web/static/css/sentinel.css`, served on both the
production host and the Ubuntu one), the aggregator panel
(`aggregator/public/panel.css`) and the witness status page
(`aggregator/public/martor.css`). They are meant to look like one product.

Nothing in either codebase notices when they stop. A stylesheet is never
executed, so a colour that drifts, a token that means two different things in
two files, or a foreground that stops being legible on its background produces
no error anywhere — it produces a page that looks slightly wrong to whoever
opens it at 3am, and nobody files that. These tests are the only mechanism that
sees it.

Three failures they prevent, each in operator terms:

  * **The same word meaning two colours.** `--bg-raised` is a card in one file
    and something else in another; someone repaints one surface, the other
    silently stays behind, and two pages that should agree disagree. Caught by
    comparing every token declared in more than one file, per theme.

  * **A colour that cannot be read.** The panel is read on a phone, outdoors,
    by someone who has just been woken up. WCAG AA is arithmetic over the token
    values, so it does not need a browser — and a pair that fails it fails here
    rather than in daylight.

  * **A mark that is no longer the same mark.** The company logo exists in
    three places because three content-security policies differ, not because
    three logos do. Edit one and the other two keep the old geometry, with no
    error: the pages still render, just with two versions of the brand.

Not covered here, deliberately: whether the pages LOOK right. That needs eyes
on a rendered screen. What is covered is everything that can be decided from
the bytes.
"""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

SENTINEL_CSS = REPO / "sentinel" / "web" / "static" / "css" / "sentinel.css"
PANEL_CSS = REPO / "aggregator" / "public" / "panel.css"
MARTOR_CSS = REPO / "aggregator" / "public" / "martor.css"

SURFACES = {
    "sentinel.css": SENTINEL_CSS,
    "panel.css": PANEL_CSS,
    "martor.css": MARTOR_CSS,
}

FAVICON_SVG = REPO / "sentinel" / "web" / "static" / "favicon.svg"
LOGO_SVG = REPO / "aggregator" / "public" / "logo.svg"


# ---------------------------------------------------------------- parsing


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _media_spans(css: str) -> list[tuple[int, int, str]]:
    """Byte spans of every `@media (prefers-color-scheme: …)` block.

    Brace-counted rather than regex-matched to the first `}`: these blocks
    contain nested rules, and a non-greedy match would end at the first one.
    """
    spans = []
    for match in re.finditer(
        r"@media\s*\(\s*prefers-color-scheme\s*:\s*(dark|light)\s*\)\s*\{", css
    ):
        depth, i = 1, match.end()
        while i < len(css) and depth:
            if css[i] == "{":
                depth += 1
            elif css[i] == "}":
                depth -= 1
            i += 1
        assert depth == 0, "unbalanced braces after @media (prefers-color-scheme:)"
        spans.append((match.start(), i, match.group(1)))
    return spans


def _declarations(block: str) -> dict[str, str]:
    out = {}
    for decl in block.split(";"):
        name, sep, value = decl.partition(":")
        name = name.strip()
        if sep and name.startswith("--"):
            out[name] = " ".join(value.split()).lower()
    return out


def _resolve(tokens: dict[str, str]) -> dict[str, str]:
    """Follow `var(--x)` indirection inside one theme's map.

    `--bg: var(--brand-darker)` is how a surface says WHERE its value comes
    from. Comparing the unresolved text would make two files that agree on the
    colour look like they disagree, and vice versa, so the comparison is on
    what the browser would actually paint.
    """
    out = {}
    for name, value in tokens.items():
        seen = 0
        while value.startswith("var(") and seen < 8:
            referenced = value[4:].split(")")[0].strip()
            if referenced not in tokens:
                break
            value = tokens[referenced]
            seen += 1
        out[name] = value
    return out


def _parse(path: Path) -> tuple[str, dict[str, dict[str, str]]]:
    """`(base theme, {theme: {token: resolved value}})` for one stylesheet.

    The base theme is read from `color-scheme` in the top-level `:root`, not
    guessed and not held in a table here. That declaration has a real effect in
    the browser (scrollbars, form controls), so it cannot rot quietly into
    disagreeing with the colours beneath it the way a comment or a list in this
    file could.
    """
    css = _strip_comments(path.read_text(encoding="utf-8"))
    spans = _media_spans(css)

    def theme_at(pos: int) -> str | None:
        for start, end, theme in spans:
            if start <= pos < end:
                return theme
        return None

    base_theme: str | None = None
    by_theme: dict[str | None, dict[str, str]] = {}
    for match in re.finditer(r":root\s*\{([^{}]*)\}", css):
        body = match.group(1)
        theme = theme_at(match.start())
        by_theme.setdefault(theme, {}).update(_declarations(body))
        if theme is None:
            scheme = re.search(r"color-scheme\s*:\s*([^;}]+)", body)
            if scheme:
                base_theme = scheme.group(1).split()[0].strip().lower()

    assert base_theme in ("dark", "light"), (
        f"{path.name}: the top-level `:root` declares no usable `color-scheme`, "
        "so nothing here can tell which theme its colours describe"
    )
    assert None in by_theme, f"{path.name}: no top-level `:root` block"

    base = by_theme[None]
    themes = {base_theme: _resolve(dict(base))}
    for theme, overrides in by_theme.items():
        if theme is None:
            continue
        themes[theme] = _resolve({**base, **overrides})
    return base_theme, themes


PARSED = {name: _parse(path) for name, path in SURFACES.items()}


def _system(theme: str) -> dict[str, str]:
    """Every token the three surfaces define for one theme, merged.

    Safe to merge only because `test_a_shared_token_means_one_colour` proves
    they agree; if that test is red this one's numbers are meaningless, which
    is why it asserts agreement itself rather than trusting the merge.
    """
    merged: dict[str, str] = {}
    for _, themes in PARSED.values():
        for token, value in themes.get(theme, {}).items():
            if token in merged and merged[token] != value:
                raise AssertionError(
                    f"{theme}: `{token}` has two values across surfaces "
                    f"({merged[token]} and {value}); see "
                    "test_a_shared_token_means_one_colour"
                )
            merged[token] = value
    return merged


# ---------------------------------------------------------------- contrast


def _relative_luminance(hex_colour: str) -> float:
    digits = hex_colour.lstrip("#")
    if len(digits) == 3:
        digits = "".join(c * 2 for c in digits)
    assert len(digits) == 6, f"not an opaque hex colour: {hex_colour!r}"
    channels = []
    for i in (0, 2, 4):
        c = int(digits[i : i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a: str, b: str) -> float:
    """WCAG 2.x contrast ratio between two opaque sRGB colours."""
    la, lb = _relative_luminance(a), _relative_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


THRESHOLD = {"text": 4.5, "ui": 3.0}

# (foreground token, RESTING background token, kind, where it is on screen)
#
# `text` means AA body text: 4.5:1. `ui` means a non-text boundary or graphic
# that carries meaning: 3:1 (WCAG 1.4.11). Nothing here is claimed as "large
# text" — the 3:1 relaxation applies from 18.66px bold or 24px regular, and the
# places these tokens are used are mostly below that.
#
# RESTING grounds only. The hovered ones are derived below, and they have to
# be: the first version of this table listed `--bg-hover` for four foregrounds
# and `--accent` for two resting grounds, and missed their intersection —
# which was the one pair that failed, at 4.42:1, under the incident title in
# `incidents.html`. Hand-listing a cross product is how you get a hole exactly
# where nobody thought to look.
#
# Chart FILLS that abut each other with no separator (`.banda-sev-*` in the
# aggregator) are not here. What has to be distinguishable about them is one
# segment from the next, not a segment from the page, and that is asserted by
# `test_the_two_greys_of_the_proportion_band_stay_apart`. Recorded so it is
# not mistaken for an oversight: `--band-alta` #9aa2ae measures 2.46:1 on
# the page ground `--bg` #f8fafc, which is what it actually sits on — the
# band goes straight into `main`, which sets no background. (The figures
# against the real grounds are in the table further down; an earlier draft
# of this comment measured against white, a surface that is not there.) `--high` IS listed, because `.rep-seg` strokes
# every sentinel chart segment with `var(--bg-raised)` — there the card colour
# really is the neighbour.
BASE_PAIRS: list[tuple[str, str, str, str]] = [
    ("--fg", "--bg", "text", "body"),
    ("--fg", "--bg-raised", "text", ".card / .panel / .bara"),
    ("--fg", "--bg-input", "text", "input, select, .btn"),
    ("--fg-muted", "--bg", "text", ".page-sub, .meniu a, th"),
    ("--fg-muted", "--bg-raised", "text", ".kpi-label, .lede, .card-eticheta"),
    ("--fg-muted", "--bg-input", "text", ".filterbar select"),
    ("--fg-dim", "--bg", "text", ".footer"),
    ("--fg-dim", "--bg-raised", "text", ".feed-meta, .kpi-note"),
    ("--accent", "--bg", "text", "a"),
    ("--accent", "--bg-raised", "text", "a inside a card"),
    ("--accent", "--accent-soft", "text", ".badge, .sidenav a.active"),
    ("--bg", "--accent", "text", ".btn-primary, .carte button"),
    ("--bg", "--accent-hover", "text", ".btn-primary:hover"),
    ("--border-lit", "--bg", "ui", ".filtre a"),
    ("--border-lit", "--bg-raised", "ui", ".userbox, .btn, .card"),
    ("--border-lit", "--bg-input", "ui", "input, select border"),
    ("--accent-dim", "--bg-raised", "ui", ".role-owner border"),
    ("--off", "--bg-raised", "ui", ".dot-off, .rep-info"),
    ("--high", "--bg-raised", "ui", ".rep-high"),
    # `--ok` and `--warn` are frozen, but they must still be MEASURED. Left
    # out of this table, their entries in KNOWN_BELOW_AA below were dead code:
    # nothing evaluated them, so a future change making dark `--warn`
    # unreadable would have been caught by nothing at all.
    ("--ok", "--bg", "text", ".pill-ok, .uptime-ok"),
    ("--ok", "--bg-raised", "text", ".kpi-ok, .uptime-ok in a card"),
    ("--warn", "--bg", "text", ".pill-warn, .cov-inline"),
    ("--warn", "--bg-raised", "text", ".kpi-note-warn, .tag-exposed, .role-operator"),
    ("--bad", "--bg", "text", ".pill-bad"),
    ("--bad", "--bg-raised", "text", ".kpi-bad, .uptime-bad"),
    ("--sev-critical", "--bg", "text", ".sev-critical"),
    ("--sev-critical", "--bg-raised", "text", '.carte [role="alert"]'),
    ("--sev-high", "--bg", "text", ".sev-high"),
    ("--sev-medium", "--bg", "text", ".sev-medium"),
    ("--sev-low", "--bg", "text", ".sev-low"),
    ("--trend-up", "--bg-raised", "text", ".t-sus"),
    ("--trend-down", "--bg-raised", "text", ".t-jos"),
]

# Backgrounds that REPLACE a resting one under content that is already there.
#
# A hover repaints the ground, not the text. So every foreground that can sit
# on the resting ground can also end up on the state ground, and owes the same
# ratio there — including combinations nobody would think to write down. The
# cross product is DERIVED here rather than hand-listed for exactly that
# reason; see the note on BASE_PAIRS.
STATE_BACKGROUNDS = {
    "--bg-hover": ("--bg", "--bg-raised", "--bg-input"),
}


def _with_state_backgrounds(
    pairs: list[tuple[str, str, str, str]],
) -> list[tuple[str, str, str, str]]:
    out = {(fg, bg): (kind, where) for fg, bg, kind, where in pairs}
    for state, resting in STATE_BACKGROUNDS.items():
        for fg, bg, kind, where in pairs:
            if bg not in resting:
                continue
            existing = out.get((fg, state))
            # If the same foreground reaches the state ground from two resting
            # ones, keep the STRICTER requirement: a token that is text
            # somewhere and a border somewhere else still owes 4.5:1.
            if existing is None or THRESHOLD[kind] > THRESHOLD[existing[0]]:
                out[(fg, state)] = (kind, f"{where} — hovered")
    return [(fg, bg, kind, where) for (fg, bg), (kind, where) in out.items()]


HOVERED_PAIRS: list[tuple[str, str, str, str]] = _with_state_backgrounds(BASE_PAIRS)

# Pairs that are measured once and NOT fed to the cross product, because the
# thing they sit on is never repainted by a hover.
#
# What makes them static is the ELEMENT, not the token: `.geobar-track` shares
# its `--bg-input` ground with `.btn`, and `.btn` very much does hover — but
# the ranked bars live in a `.panel`, and a panel has no hover state. Running
# them through the derivation would invent a pair that is nowhere on screen
# (`--brand-primary-700` on `--bg-hover` measures 2.93:1) and then need an
# exemption for it, which would be a lie in the exemption list.
#
# They are here at all because the ranked-bar fill was invisible to BOTH
# guards: `PAIRS` could not see it because a gradient is not a token-vs-token
# pair, and the literal-colour lint could not because the gradient is written
# with `var()`. Its dark start measures 3.11:1 against its own track — over
# the 1.4.11 bar for a data graphic by a tenth, which is exactly the kind of
# margin that wants watching rather than remembering.
STATIC_PAIRS: list[tuple[str, str, str, str]] = [
    ("--brand-primary-700", "--bg-input", "ui",
     ".geobar-fill gradient START over .geobar-track"),
    ("--brand-primary", "--bg-input", "ui",
     ".geobar-fill gradient END over .geobar-track"),
]

PAIRS: list[tuple[str, str, str, str]] = HOVERED_PAIRS + STATIC_PAIRS

# Pairs that do NOT meet AA and are shipped anyway, each with the kind it is
# judged by and the ratio measured when it was written down.
#
# `--ok` and `--warn` are frozen by the operator's decision: they are
# semantics, not brand, and this change was not allowed to move them. On the
# light theme they were already below AA for small text before it — #12996a
# measured 3.63:1 on the old #ffffff card and #b57a12 measured 3.65:1 — and the
# background retint moved them by about a tenth, so this is a pre-existing
# defect carried forward, not one introduced here. Fixing it means darkening
# two semantic colours, which is the operator's call and not an agent's.
#
# `--bad` on the hovered row WAS here, at 4.46:1, and is not any more. Kept
# as a note because how it closed is the useful part: the token was
# overloaded. `--bg-hover` meant both "you are hovering" and, through
# `tr.aici`, "you are here" — and the second of those was a 1.047:1 tint
# carrying no other signal, so lightening the token to close the contrast gap
# would have finished off a marker that was already barely there. Giving
# `tr.aici` a left border in `--accent` (and `aria-current`, since a border is
# still only visual) freed the token, `--bg-hover` went to #f3f6fa, and the
# pair closed at 4.503:1. One change, one real defect fixed, one exemption
# gone. Three thousandths of margin, so it stays measured.
#
# Each entry is asserted to be STILL failing. An exemption that has quietly
# become true is a lie the next reader believes, so the list empties itself.
KNOWN_BELOW_AA: list[tuple[str, str, str, str, str]] = [
    ("light", "--ok", "--bg", "text",
     "3.47:1 — .pill-ok, .uptime-ok on the page ground"),
    ("light", "--ok", "--bg-raised", "text",
     "3.63:1 — .pill-ok, .uptime-ok inside a card"),
    ("light", "--ok", "--bg-hover", "text",
     "3.31:1 — the same, on a hovered row"),
    ("light", "--warn", "--bg", "text",
     "3.49:1 — .pill-warn, .cov-inline"),
    ("light", "--warn", "--bg-raised", "text",
     "3.65:1 — .kpi-note-warn, .tag-exposed"),
    ("light", "--warn", "--bg-hover", "text",
     "3.33:1 — the same, on a hovered row"),
]


# ---------------------------------------------------------------- the mark


def _mark_geometry(svg: str) -> tuple:
    """What makes the mark THIS mark: gradient stops, nodes, edges.

    Deliberately not a byte comparison. The three copies differ in ways that
    carry no meaning — one is URL-encoded inside a CSS `url()`, two are files
    with their own comments and their own `viewBox` attributes in a different
    order — and a byte comparison would either fail on all of that or be
    defeated by normalising it away. What is compared is what is drawn.
    """
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)
    stops = tuple(
        (m.group(1), m.group(2).lower())
        for m in re.finditer(
            r"<stop[^>]*offset=['\"]([^'\"]+)['\"][^>]*stop-color=['\"]([^'\"]+)['\"]",
            svg,
        )
    )
    circles = tuple(
        sorted(
            (m.group(1), m.group(2), m.group(3))
            for m in re.finditer(
                r"<circle[^>]*cx=['\"]([^'\"]+)['\"][^>]*cy=['\"]([^'\"]+)['\"]"
                r"[^>]*r=['\"]([^'\"]+)['\"]",
                svg,
            )
        )
    )
    paths = tuple(
        " ".join(m.group(1).split())
        for m in re.finditer(r"<path[^>]*\sd=['\"]([^'\"]+)['\"]", svg)
    )
    return stops, circles, paths


# Every rule that actually PAINTS the mark, and what it must paint it with.
#
# Two mechanisms because two policies: the dashboard's CSP allows
# `img-src 'self' data:` so the bytes ride inside the stylesheet, the
# aggregator's is `img-src 'self'` with no `data:` so it has to be a file.
MARK_USERS: dict[str, list[tuple[str, str]]] = {
    "sentinel.css": [(".brand-mark", "data:image/svg+xml,")],
    "panel.css": [(".marca::before", "/logo.svg"),
                  (".carte::before", "/logo.svg")],
    "martor.css": [(".stack::before", "/logo.svg")],
}


def _rule_body(path: Path, selector: str) -> str | None:
    """The declarations of the rule with exactly this selector, or None."""
    css = _strip_comments(path.read_text(encoding="utf-8"))
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        if " ".join(match.group(1).split()) == selector:
            return match.group(2)
    return None


def _mark_from_stylesheet() -> str:
    """The data: URI in `.brand-mark`, decoded back to SVG."""
    css = SENTINEL_CSS.read_text(encoding="utf-8")
    match = re.search(
        r"\.brand-mark\s*\{[^}]*url\(\"data:image/svg\+xml,([^\"]+)\"\)", css, re.S
    )
    assert match, (
        "`.brand-mark` no longer carries an inline data: URI mark — if it moved "
        "to a file, this test's third source is stale and the comparison below "
        "silently checks two copies instead of three"
    )
    return urllib.parse.unquote(match.group(1))


# ================================================================== tests


def test_every_surface_declares_which_theme_its_root_describes():
    """Without `color-scheme`, a dark page gets the browser's light scrollbars
    and light form controls — a white rectangle down the side of the dashboard
    at night. It is also what every other test here reads to know which theme a
    `:root` block belongs to, so a missing one would make them compare a dark
    palette against a light one and report nonsense."""
    bases = {name: PARSED[name][0] for name in SURFACES}
    assert bases == {
        "sentinel.css": "dark",
        "panel.css": "light",
        "martor.css": "dark",
    }, f"a surface changed which theme it leads with: {bases}"


def test_a_shared_token_means_one_colour():
    """The drift this whole file exists for.

    `--bg-raised` must be the same colour on the dashboard and on the panel, or
    the two pages stop looking like one product and nothing says so. Compared
    per theme and after `var()` resolution, so a file is free to say WHERE its
    value comes from as long as it lands on the same colour.
    """
    disagreements = []
    shared = 0
    for theme in ("dark", "light"):
        seen: dict[str, tuple[str, str]] = {}
        for name, (_, themes) in PARSED.items():
            for token, value in themes.get(theme, {}).items():
                if token in seen:
                    shared += 1
                    other_name, other_value = seen[token]
                    if other_value != value:
                        disagreements.append(
                            f"{theme}: {token} is {other_value} in {other_name} "
                            f"but {value} in {name}"
                        )
                else:
                    seen[token] = (name, value)

    # A comparison over an empty intersection passes for ever. If the surfaces
    # stopped sharing names the test would go green having compared nothing —
    # which is exactly the drift it is here to catch.
    assert shared >= 20, (
        f"only {shared} token comparisons were possible across the three "
        "surfaces; either the shared vocabulary was abandoned or the parse is "
        "broken, and in both cases this test is no longer checking anything"
    )
    assert not disagreements, "\n  ".join(["shared tokens disagree:"] + disagreements)


def test_the_core_vocabulary_exists_on_every_surface():
    """A surface that names its background something of its own is out of the
    system even if every colour happens to match today — the next change to the
    system will not reach it."""
    core = {"--bg", "--bg-raised", "--border", "--fg", "--fg-muted",
            "--sans", "--mono", "--display"}
    for name, (base, themes) in PARSED.items():
        missing = sorted(core - set(themes[base]))
        assert not missing, f"{name}: missing shared tokens {missing}"


def test_the_type_stacks_are_byte_identical_across_surfaces():
    """Three surfaces that agree on colour but not on font render as three
    products. The stacks are long and easy to retype slightly differently, and
    the difference is invisible on a machine that has none of the named
    families installed — which is most of them."""
    for token in ("--sans", "--mono", "--display"):
        values = {name: themes[base][token] for name, (base, themes) in PARSED.items()}
        assert len(set(values.values())) == 1, f"{token} differs: {values}"


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_no_rule_asks_for_a_token_nobody_declares(theme):
    """A renamed token leaves `var(--old)` behind and the browser says nothing:
    the declaration is simply dropped, so a field keeps the browser's default
    white background on a near-black page, or text falls back to black on
    black. It is visible only by looking, and these pages are looked at rarely.
    """
    for name, path in SURFACES.items():
        css = _strip_comments(path.read_text(encoding="utf-8"))
        declared = set(PARSED[name][1].get(theme, PARSED[name][1][PARSED[name][0]]))
        used = {m.group(1) for m in re.finditer(r"var\(\s*(--[a-z0-9-]+)", css)}
        assert used, f"{name}: no var() uses found at all — the scan is broken"
        assert not (used - declared), (
            f"{name} ({theme}): uses tokens nothing declares: "
            f"{sorted(used - declared)}"
        )


def test_the_contrast_arithmetic_is_right():
    """Guard the guard. Every AA claim below is this function's output; if it
    is wrong, the whole table is decoration. Checked against the three ratios
    the WCAG definition fixes exactly, plus one published pair."""
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0, abs=0.01)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.001)
    assert contrast_ratio("#777777", "#ffffff") == pytest.approx(4.48, abs=0.02)
    # Symmetric, and it must not care which argument is the background.
    assert contrast_ratio("#1e88e5", "#050811") == pytest.approx(
        contrast_ratio("#050811", "#1e88e5")
    )


def test_the_pair_table_is_not_empty_and_resolves():
    """A parametrised list that comes out empty is skipped in silence. This
    repository has paid for that once already."""
    assert len(PAIRS) >= 40, f"only {len(PAIRS)} pairs listed"
    for theme in ("dark", "light"):
        tokens = _system(theme)
        for fg, bg, _kind, where in PAIRS:
            assert fg in tokens, f"{theme}: {fg} ({where}) is declared nowhere"
            assert bg in tokens, f"{theme}: {bg} ({where}) is declared nowhere"


def test_the_state_ground_covers_every_surface_the_table_rests_on():
    """The guard against round one's hole must not be able to shrink with it.

    Round one hand-wrote a cross product and missed a cell. Round two replaced
    it with a derivation — and then took the derivation's expectation FROM the
    derivation's own input, one level up from the same defect: narrowing
    `STATE_BACKGROUNDS["--bg-hover"]` to `("--bg",)` shrank the expectation and
    the actual together and left the file green, while five foregrounds
    silently stopped being checked on hover. Two of them, `--accent-dim` and
    `--trend-down`, are the pairs round two's value changes were made to fix.

    So this test compares two things that are written down SEPARATELY:
    `STATE_BACKGROUNDS`, by hand, and the grounds BASE_PAIRS actually rests
    on, read off BASE_PAIRS right here. Narrowing the tuple fails; dropping a
    ground from the table fails; keeping them in step takes a deliberate edit
    in both places, which is the point.

    The comprehension is INLINE and not behind a helper, deliberately. As a
    helper it was a third thing that could be edited: rewriting it to return
    `STATE_BACKGROUNDS["--bg-hover"]` restored the self-reference and left
    this file green — measured, not imagined. Inline, the only way to make
    the comparison trivial is to edit this assertion, and no test defends
    against being deleted.

    If a third layer ever goes on top of this one, give IT an expectation from
    somewhere else again. A derivation whose input is unwatched is a
    hand-written table wearing a hat.

    LIMIT, stated because it is real: "surface" is recognised by the `--bg`
    prefix, this system's naming convention for a ground. `--accent`,
    `--accent-hover` and `--accent-soft` also appear as backgrounds — a button
    fill, a badge fill — and are correctly not surfaces a row hover replaces.
    A ground introduced under some other name, say `--surface-sunken`, would
    not be seen here.
    """
    declared = set(STATE_BACKGROUNDS["--bg-hover"])
    used = {bg for _, bg, _, _ in BASE_PAIRS if bg.startswith("--bg")}
    assert used, (
        "BASE_PAIRS rests on no `--bg*` ground at all — either the table was "
        "gutted or the prefix convention changed, and in both cases nothing "
        "below this line is checking anything"
    )
    assert "--bg-hover" not in used, (
        "BASE_PAIRS lists `--bg-hover` as a ground again. It is derived, not "
        "written: a hand-listed hovered pair is how round one came to be "
        "missing the one that mattered."
    )
    assert declared == used, (
        "the hover ground does not cover the surfaces the table rests on.\n"
        f"  STATE_BACKGROUNDS says: {sorted(declared)}\n"
        f"  BASE_PAIRS rests on:    {sorted(used)}\n"
        "Every surface a control can sit on can be repainted by a hover over "
        "that control, so both lists have to say the same thing."
    )


def test_the_hovered_ground_is_derived_for_every_foreground():
    """The hole that shipped in round one, pinned.

    `--accent` was listed on `--bg` and `--bg-raised`; `--bg-hover` was listed
    for four other foregrounds. Their intersection — an accent link inside a
    hovered table row, which is the incident title on `incidents.html` and the
    primary click target of that page — was in neither list, and measured
    4.42:1 against a 4.5:1 requirement.

    So the derivation is asserted, not just relied on: if `_with_state_
    backgrounds` ever returns its input unchanged, every hovered pair silently
    stops being checked and this file goes green having measured the resting
    state only.
    """
    derived = {(fg, bg) for fg, bg, _, _ in HOVERED_PAIRS} - {
        (fg, bg) for fg, bg, _, _ in BASE_PAIRS
    }
    assert len(derived) >= 12, (
        f"only {len(derived)} hovered pairs were derived from "
        f"{len(BASE_PAIRS)} resting ones — the derivation is not running"
    )
    # Named one by one, not just counted: these three are the pairs whose
    # absence review actually caught, and a count can be satisfied by the
    # wrong twelve.
    for fg in ("--accent", "--accent-dim", "--trend-down"):
        assert (fg, "--bg-hover") in derived, (
            f"{fg} has no hovered pair — it is one of the five that quietly "
            "dropped out when the guard was self-referential"
        )
    # Every foreground that has a resting ground must have the state ground.
    # Safe to read the tuple here: `test_the_state_ground_covers_every_surface_
    # the_table_rests_on` pins it against BASE_PAIRS, so it cannot quietly
    # narrow underneath this.
    surfaces = set(STATE_BACKGROUNDS["--bg-hover"])
    resting_fgs = {fg for fg, bg, _, _ in BASE_PAIRS if bg in surfaces}
    hovered_fgs = {fg for fg, bg, _, _ in HOVERED_PAIRS if bg == "--bg-hover"}
    missing = sorted(resting_fgs - hovered_fgs)
    assert not missing, f"no hovered pair derived for {missing}"


def test_the_stricter_of_two_thresholds_wins_on_a_shared_state_ground():
    """The branch nothing on this page exercises.

    A token that is a border in one place and text in another reaches
    `--bg-hover` from two resting grounds with two different requirements, and
    the derivation has to take 4.5:1, not 3:1. No foreground in the real table
    does that today — measured: 29 candidates, no collision — so the branch is
    correct and never run, which is the state a branch is in just before it is
    wrong. Exercised synthetically, in both input orders, because a
    "keep the stricter" rule that depends on which row came first is not a
    rule.
    """
    ui_first = [
        ("--x", "--bg", "ui", "a border somewhere"),
        ("--x", "--bg-raised", "text", "a label somewhere else"),
    ]
    text_first = list(reversed(ui_first))
    for label, rows in (("ui first", ui_first), ("text first", text_first)):
        derived = {
            (fg, bg): kind for fg, bg, kind, _ in _with_state_backgrounds(rows)
        }
        assert derived[("--x", "--bg-hover")] == "text", (
            f"{label}: the hovered pair was derived as "
            f"{derived[('--x', '--bg-hover')]!r}; a token that carries text "
            "anywhere owes 4.5:1 on every ground it can land on"
        )


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_every_foreground_over_its_background_meets_AA(theme):
    """The panel is read on a phone, outdoors, by someone just woken up. A
    theme that looks right on the author's screen and washes out in daylight is
    the same class of failure as a check that reports success without looking:
    it is fine until the moment it matters."""
    tokens = _system(theme)
    exempt = {(t, fg, bg) for t, fg, bg, _, _ in KNOWN_BELOW_AA}
    failures = []
    for fg, bg, kind, where in PAIRS:
        if (theme, fg, bg) in exempt:
            continue
        ratio = contrast_ratio(tokens[fg], tokens[bg])
        if ratio < THRESHOLD[kind]:
            failures.append(
                f"{theme}: {fg} ({tokens[fg]}) on {bg} ({tokens[bg]}) = "
                f"{ratio:.2f}:1, below {THRESHOLD[kind]}:1 — {where}"
            )
    assert not failures, "\n  ".join(["contrast below WCAG AA:"] + failures)


def test_the_exemption_list_still_has_entries_to_parametrize():
    """A `parametrize` over an empty list collects nothing and reports nothing.

    This repository has shipped that once already. The list legitimately
    shrinks — `--bad` came off it this round when the colour was fixed — so
    the day it reaches zero is a good day, but it must be a NOTICED one: at
    zero, `test_a_known_failing_pair_is_still_failing` stops existing rather
    than passing, and nothing in the output says so.

    If you are here because the list is genuinely empty, delete this test and
    the parametrized one together, on purpose, in the same commit.
    """
    assert KNOWN_BELOW_AA, (
        "KNOWN_BELOW_AA is empty. Either every exempted pair was fixed — in "
        "which case delete this test and test_a_known_failing_pair_is_still_"
        "failing deliberately — or the list was lost, in which case nothing "
        "is checking the six pairs it held."
    )
    # And the pairs it holds must be distinct: a duplicated row would inflate
    # the count while covering the same ground twice.
    rows = [(t, fg, bg) for t, fg, bg, _, _ in KNOWN_BELOW_AA]
    assert len(rows) == len(set(rows)), f"duplicate exemptions: {rows}"


def test_every_exemption_names_a_pair_the_table_actually_measures():
    """The exemption plumbing must be live, not decoration.

    In round one `--ok` and `--warn` were exempted but never appeared in the
    table, so replacing the whole exemption set with `set()` changed nothing:
    the two tokens were not being evaluated in either theme, and a future
    change making dark `--warn` unreadable would have been caught by nothing.
    An exemption for a pair nobody measures is worse than no exemption — it
    reads like coverage.
    """
    measured = {(fg, bg) for fg, bg, _, _ in PAIRS}
    stray = [(fg, bg) for _, fg, bg, _, _ in KNOWN_BELOW_AA
             if (fg, bg) not in measured]
    assert not stray, (
        f"exempted pairs that the table never evaluates: {stray}. Either add "
        "them to BASE_PAIRS or drop the exemption; as written it claims a "
        "check that does not happen."
    )


@pytest.mark.parametrize("theme,fg,bg,kind,note", KNOWN_BELOW_AA)
def test_a_known_failing_pair_is_still_failing(theme, fg, bg, kind, note):
    """The exemption list must empty itself.

    An exemption that has silently become true is worse than no exemption: the
    next reader sees a documented "we know about this" beside a pair that is
    actually fine, and stops trusting the rest of the list. If this fails, the
    colour was fixed — delete the entry.
    """
    tokens = _system(theme)
    ratio = contrast_ratio(tokens[fg], tokens[bg])
    assert ratio < THRESHOLD[kind], (
        f"{fg} on {bg} now measures {ratio:.2f}:1 and meets the {kind} "
        f"threshold of {THRESHOLD[kind]}:1 ({note}). Remove it from "
        "KNOWN_BELOW_AA — an exemption for a defect that no longer exists "
        "teaches the next reader to ignore the list."
    )


def test_the_selected_row_is_marked_by_more_than_a_tint():
    """"Which server am I looking at" has to be answerable across the room.

    Until 22 September 2026 the whole marker was `tr.aici > td { background:
    var(--bg-hover) }` — 1.047:1 against the page. Rendered at 700x420 in the
    light theme it is perceptible on a good screen if you already know which
    row to look at, which is the one situation in which you do not need it. On
    a phone in daylight it is not there at all.

    So the row gets a 3px bar at its edge: a shape, not a tone, which survives
    a washed-out screen and a printer, and which this sheet already uses for
    `.cron-blocare`. The tint stays as an echo — and had to stop being the
    only signal before `--bg-hover` could be lightened to close the last
    contrast exemption, which is why the two changes are one change.

    This asserts the SHAPE exists and takes its colour from a token. The other
    half — that a screen reader is told, because a coloured bar tells it
    nothing — is markup, not CSS, and lives in the aggregator's own suite:
    `tests/rand-selectat.test.ts`.
    """
    body = _rule_body(PANEL_CSS, "tr.aici > td:first-child")
    assert body, (
        "`tr.aici > td:first-child` has no rule. The row that says which "
        "server you are looking at is back to a 1.047:1 background tint and "
        "nothing else."
    )
    border = re.search(r"border-left\s*:\s*([^;]+)", body)
    assert border, "the selected row has no left border — the tint is alone again"
    width = re.search(r"(\d+)px", border.group(1))
    assert width and int(width.group(1)) >= 2, (
        f"the marker is {border.group(1).strip()!r}; a hairline is a tone by "
        "another name"
    )
    assert "var(--" in border.group(1), (
        f"the marker colour is written by hand: {border.group(1).strip()!r}. "
        "It then sits outside every check in this file."
    )
    # And the tint has to still be there: the bar marks the edge, the tint
    # carries the eye across the row.
    tint = _rule_body(PANEL_CSS, "tr.aici > td")
    assert tint and "var(--bg-hover)" in tint, (
        "the selected row lost its background tint; the bar alone marks the "
        "left edge of a row that can be a screen wide"
    )


def test_the_ranked_bar_gradient_is_the_pair_the_table_measures():
    """`STATIC_PAIRS` has to describe the CSS, or it describes nothing.

    The ranked-bar fill was invisible to both guards for two rounds: a
    gradient is not a token-vs-token pair, so `PAIRS` could not see it, and it
    is written with `var()`, so the literal-colour lint could not either. It
    is in `STATIC_PAIRS` now — but a hand-written entry beside a rule that has
    moved on is worse than no entry, because it measures a colour nobody
    paints and reports "ok".

    So the two are compared. Change the gradient, change the track, or empty
    `STATIC_PAIRS`, and this fails.
    """
    fill = _rule_body(SENTINEL_CSS, ".geobar-fill")
    assert fill, "`.geobar-fill` has no rule"
    gradient = re.search(r"linear-gradient\(([^;]*)\)", fill)
    assert gradient, "`.geobar-fill` no longer paints a gradient"
    stops = re.findall(r"var\(\s*(--[a-z0-9-]+)", gradient.group(1))
    assert len(stops) == 2, (
        f"the ranked bar has {len(stops)} tokenised gradient stops, not 2 — "
        "the table below measures exactly two, so anything else is unmeasured"
    )

    track = _rule_body(SENTINEL_CSS, ".geobar-track")
    assert track, "`.geobar-track` has no rule"
    ground = re.search(r"background\s*:\s*var\(\s*(--[a-z0-9-]+)", track)
    assert ground, "`.geobar-track` no longer takes its ground from a token"

    listed = {(fg, bg) for fg, bg, _, _ in STATIC_PAIRS}
    expected = {(stop, ground.group(1)) for stop in stops}
    assert listed == expected, (
        "STATIC_PAIRS does not describe the ranked bar as it is written.\n"
        f"  the stylesheet paints: {sorted(expected)}\n"
        f"  the table measures:    {sorted(listed)}"
    )


def test_the_two_greys_of_the_proportion_band_stay_apart():
    """`info` and `alta` must not be the same grey.

    `severityClass()` in `lib/panel-page.ts` sends every severity it does not
    recognise to `sev-alta`, so one summary can carry an `info` bucket and an
    unknown one at the same time. The proportion band draws them as adjacent
    segments with no separator between them: painted the same colour they read
    as one segment, and the legend shows two identical swatches beside two
    different words. They were briefly collapsed onto `--fg-muted` in round
    one — contrast 1.00 — which is how this test came to exist.

    1.5:1 rather than 3:1 because the requirement here is telling one grey
    from the neighbouring grey, not reading text off them. The two shipped
    values measure 1.83:1, the separation they had before the collapse.

    Against the PAGE, for the record and because the first version of this
    note measured the wrong surface: the band is pushed straight into `main`,
    which sets no background, so the ground is `--bg` and not white. There
    `--band-alta` #9aa2ae is 2.46:1 and `--band-info` #6c7480 is 4.51:1; on
    dark they are 7.77:1 and 4.24:1. `--band-alta` is therefore under 3:1
    against its page on the light theme, as it was at HEAD. It is not in
    `PAIRS` on purpose — a stacked bar owes its reader one segment against the
    next, and its segments abut with no separator — but the number is written
    down here so it is a decision and not an omission.
    """
    for theme in ("dark", "light"):
        tokens = _system(theme)
        info, alta = tokens["--band-info"], tokens["--band-alta"]
        assert info != alta, f"{theme}: both band greys are {info}"
        ratio = contrast_ratio(info, alta)
        assert ratio >= 1.5, (
            f"{theme}: --band-info {info} and --band-alta {alta} are "
            f"{ratio:.2f}:1 apart. Same hue family, so lightness is the only "
            "cue a reader has; below this they merge into one segment."
        )


def test_each_band_segment_points_at_its_own_token():
    """The token values being distinct is not enough — the RULES have to use
    them.

    The round-one regression was at rule level, not token level:
    `.banda-sev-info` and `.banda-sev-alta` were both repointed to
    `var(--fg-muted)`. Six healthy tokens sitting unused in `:root` would keep
    a value-only check green while the band still drew two identical
    segments. And the legend swatch has to follow its own band: a swatch
    showing one colour beside a segment drawn in another is worse than no
    legend, because it is confidently wrong.
    """
    css = _strip_comments(PANEL_CSS.read_text(encoding="utf-8"))
    buckets = ["critical", "high", "medium", "low", "info", "alta"]

    def token_for(selector: str) -> str:
        match = re.search(
            re.escape(selector) + r"\s*\{([^{}]*)\}", css
        )
        assert match, f"no rule `{selector}` in panel.css"
        var = re.search(r"var\(\s*(--[a-z0-9-]+)", match.group(1))
        assert var, (
            f"`{selector}` no longer takes its colour from a token, so the "
            "checks on the token values above do not describe what is drawn"
        )
        return var.group(1)

    bands = {b: token_for(f".banda-sev-{b}") for b in buckets}
    assert len(set(bands.values())) == 6, (
        f"the six band segments use only {len(set(bands.values()))} distinct "
        f"tokens: {bands}"
    )
    for bucket, token in bands.items():
        swatch = token_for(f".leg-pata.banda-sev-{bucket}")
        assert swatch == token, (
            f"the legend swatch for `{bucket}` is {swatch} but the band "
            f"segment is {token} — the legend names the wrong colour"
        )


def test_no_two_segments_of_the_proportion_band_share_a_colour():
    """The same failure, for the other four buckets.

    Every band segment is also named in the legend and in its `<title>`, so a
    collision degrades rather than lies — but a stacked bar whose segments
    cannot be told apart is a bar that shows a total and hides the split,
    which is the one thing it exists to show.
    """
    band = ["--sev-critical", "--sev-high", "--sev-medium", "--sev-low",
            "--band-info", "--band-alta"]
    for theme in ("dark", "light"):
        tokens = _system(theme)
        painted = {}
        for name in band:
            assert name in tokens, f"{theme}: {name} is declared nowhere"
            colour = tokens[name]
            assert colour not in painted, (
                f"{theme}: {name} and {painted[colour]} are both {colour}"
            )
            painted[colour] = name


def test_the_brand_mark_is_the_same_mark_in_all_three_places():
    """Three copies, one logo.

    The dashboard inlines it as a data: URI (its CSP allows `img-src data:`),
    the aggregator serves it as a file (its CSP is `img-src 'self'` with no
    `data:`), and the favicon is a third file. Edit one and the others keep the
    old drawing, with no error anywhere: the pages render, the brand does not
    match itself, and it is caught only by someone putting two tabs side by
    side.
    """
    sources = {
        "sentinel/web/static/favicon.svg": FAVICON_SVG.read_text(encoding="utf-8"),
        "aggregator/public/logo.svg": LOGO_SVG.read_text(encoding="utf-8"),
        "sentinel.css .brand-mark": _mark_from_stylesheet(),
    }
    geometries = {name: _mark_geometry(svg) for name, svg in sources.items()}

    # The extraction must actually find something. A regex that matches nothing
    # makes all three "equal" and the test green for ever.
    for name, (stops, circles, paths) in geometries.items():
        assert len(stops) == 2, f"{name}: found {len(stops)} gradient stops, expected 2"
        assert len(circles) == 7, f"{name}: found {len(circles)} circles, expected 7"
        assert len(paths) == 1, f"{name}: found {len(paths)} paths, expected 1"

    distinct = set(geometries.values())
    assert len(distinct) == 1, (
        "the three copies of the mark draw different things:\n  "
        + "\n  ".join(f"{name}: {geo}" for name, geo in geometries.items())
    )


# Colours written straight into a rule, instead of taken from a token. Each
# entry is (selector pattern, declaration pattern, why it is allowed to stay).
#
# Everything inside `@media print` is exempt as a block and is not listed here:
# paper is white and ink is black whatever the screen theme is.
HAND_WRITTEN_COLOURS = {
    "sentinel.css": [
        (r"^\.avatar$", r"^color: #fff$",
         "white initials on a FIXED brand gradient — the gradient does not "
         "follow the theme, so the text on it cannot either. Unwatched by "
         "the contrast table for the same reason the ranked bar was: a "
         "literal over a gradient is not a token-vs-token pair. Measured by "
         "hand, both ends: white on --brand-primary-700 #1565c0 is 5.75:1, "
         "white on --brand-dark #0a0f1e is 19.09:1"),
    ],
    "panel.css": [
        (r"^\.(leg-pata\.)?g-s[0-5]$", r"^(fill|background): #[0-9a-f]{6}$",
         "the six categorical bands of the stacked chart. Chosen to separate "
         "by LIGHTNESS as well as hue so they survive colour blindness; "
         "re-hueing them for the brand is a separate decision with its own "
         "evidence, and it is not this change"),
    ],
    "martor.css": [],
}


def _print_spans(css: str) -> list[tuple[int, int]]:
    spans = []
    for match in re.finditer(r"@media\s+print\s*\{", css):
        depth, i = 1, match.end()
        while i < len(css) and depth:
            if css[i] == "{":
                depth += 1
            elif css[i] == "}":
                depth -= 1
            i += 1
        spans.append((match.start(), i))
    return spans


def _rules_with_literal_colours(path: Path) -> list[tuple[str, str]]:
    """`(selector, declaration)` for every rule that names a colour directly.

    `:root` blocks are removed first: that is where colours are SUPPOSED to be
    written. What is left is a rule painting something with a value the
    contrast table below never sees.
    """
    css = _strip_comments(path.read_text(encoding="utf-8"))
    css = re.sub(r":root\s*\{[^{}]*\}", "", css)
    skip = _print_spans(css)
    literal = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(")

    found = []
    # A rule is a brace pair with no braces inside it, so `@media` wrappers are
    # skipped by construction and their contents are matched individually.
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        if any(a <= match.start() < b for a, b in skip):
            continue
        selector = " ".join(match.group(1).split())
        for decl in match.group(2).split(";"):
            decl = " ".join(decl.split())
            if decl and literal.search(decl):
                found.append((selector, decl))
    return found


def test_no_rule_paints_with_a_colour_the_contrast_table_never_sees():
    """What makes the table above binding rather than decorative.

    Every AA figure here is computed from the TOKENS. A rule that writes
    `color: #fff` instead of `color: var(--bg)` is invisible to that
    arithmetic: the table stays green while the button it describes is white
    on brand blue at 3.68:1 — which is the exact value this change moved away
    from, and exactly the kind of edit that looks harmless in review.

    The exemptions are matched pattern by pattern and each must still bite, so
    a literal that gets tokenised later fails here until its exemption is
    deleted.
    """
    offenders, unused = [], []
    for name, path in SURFACES.items():
        patterns = HAND_WRITTEN_COLOURS[name]
        hits = [0] * len(patterns)
        for selector, decl in _rules_with_literal_colours(path):
            for index, (sel_re, decl_re, _why) in enumerate(patterns):
                if re.match(sel_re, selector) and re.match(decl_re, decl):
                    hits[index] += 1
                    break
            else:
                offenders.append(f"{name}: `{selector}` has `{decl}`")
        for index, count in enumerate(hits):
            if count == 0:
                unused.append(f"{name}: {patterns[index][0]} / {patterns[index][1]}")

    assert not offenders, "\n  ".join(
        ["a colour is written into a rule instead of coming from a token:"]
        + offenders
    )
    assert not unused, "\n  ".join(
        ["an exemption no longer matches anything — delete it:"] + unused
    )


def test_the_literal_colour_scan_finds_what_it_claims_to():
    """Guard the guard.

    The scan above reports "clean" by finding nothing, which is also what a
    broken regex, a wrong path or an over-eager `:root` strip report. It has to
    be shown finding something: the exemptions are the proof that it does, so
    they must not all be empty at once.
    """
    total = sum(
        len(_rules_with_literal_colours(path)) for path in SURFACES.values()
    )
    assert total >= 10, (
        f"the scan found only {total} literal colours across three "
        "stylesheets. It found 25 when it was written; a number near zero "
        "means the scan stopped working, not that the sheets got cleaner"
    )
    # And it must see a literal that is NOT in any exemption.
    fake = "/* x */\n.demo { color: #ff0000; }\n"
    tmp = _strip_comments(fake)
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", tmp), "the literal pattern is broken"


def test_every_surface_actually_paints_the_mark():
    """The whole feature deleted clean, and both suites stayed green.

    Round one added the company mark to four places — the panel header, the
    panel login card, the witness page and the dashboard sidebar — and shipped
    no test that noticed when they were removed. Deleting all three
    `url("/logo.svg")` declarations from the aggregator left `pass 1072,
    fail 0` and `19 passed`: the mark vanished from every aggregator surface
    and the only thing that would have caught it was somebody opening the
    page.

    The geometry test below compares three DRAWINGS. This one asks whether
    anything still uses them. They are different questions and the second one
    is the one a deletion answers.
    """
    missing = []
    for name, users in MARK_USERS.items():
        path = SURFACES[name]
        for selector, expected in users:
            body = _rule_body(path, selector)
            if body is None:
                missing.append(f"{name}: no rule `{selector}` at all")
                continue
            if "url(" not in body or expected not in body:
                missing.append(
                    f"{name}: `{selector}` no longer loads the mark "
                    f"(expected a url() containing {expected!r})"
                )
    assert not missing, "\n  ".join(
        ["a surface stopped showing the company mark:"] + missing
    )


def test_the_mark_reference_table_is_not_empty():
    """Guard the guard: a table that lost its rows would pass the test above
    by checking nothing, which is the same shape as the defect it replaces."""
    assert sum(len(v) for v in MARK_USERS.values()) >= 4
    assert set(MARK_USERS) == set(SURFACES), (
        "a surface is missing from the mark table — it would then be free to "
        "drop the mark without anything noticing"
    )


def test_the_dashboard_mark_occupies_a_box():
    """`width` and `height` do nothing to a bare inline span.

    `.brand-mark` is a `<span>`. Inside `.brand` its `inline-flex` parent
    blockifies it and the sidebar mark renders, which is why this looked fine.
    On `login.html`, `totp.html` and `error.html` the parent is `.auth-head`,
    a plain `<div>` — the span stays inline, `width`/`height` do not apply,
    and the mark is absent above the wordmark. Silently: an empty span reports
    nothing and leaves no gap to notice.

    The page that asks "is this really your login page?" is the one place the
    mark was missing.
    """
    body = _rule_body(SENTINEL_CSS, ".brand-mark")
    assert body, "`.brand-mark` has no rule"
    match = re.search(r"\bdisplay\s*:\s*([a-z-]+)", body)
    assert match, (
        "`.brand-mark` sets width/height but no `display`. As a bare inline "
        "span on the auth pages that is a zero-size box and the mark does not "
        "render at all."
    )
    assert match.group(1) not in ("inline", "none"), (
        f"`.brand-mark` is `display: {match.group(1)}` — width and height do "
        "not apply, so the auth pages show empty space where the mark is"
    )


def test_the_aggregator_stylesheets_never_reference_a_data_uri():
    """`lib/csp.ts` sets `img-src 'self'` with no `data:`. A mark inlined into
    one of these sheets is refused by the browser and simply does not appear —
    no console error the operator would see, no broken-image icon, just a gap
    where the logo was. The dashboard's policy DOES allow it, which is exactly
    how the wrong idiom gets copied from one file to the other."""
    for name in ("panel.css", "martor.css"):
        css = SURFACES[name].read_text(encoding="utf-8")
        for target in re.findall(r"url\(\s*['\"]?([^'\")]+)", _strip_comments(css)):
            assert not target.strip().lower().startswith("data:"), (
                f"{name} loads a data: URI ({target[:40]}…), which "
                "`img-src 'self'` refuses — the image will be missing, silently"
            )


def test_no_stylesheet_reaches_for_an_external_origin():
    """`default-src 'self'` on the dashboard and `default-src 'none'` on the
    aggregator both refuse it. A CDN font or a remote image would render the
    page subtly wrong with nothing in any log."""
    for name, path in SURFACES.items():
        css = _strip_comments(path.read_text(encoding="utf-8"))
        for target in re.findall(r"url\(\s*['\"]?([^'\")]+)", css):
            target = target.strip().lower()
            assert not target.startswith(("http:", "https:", "//")), (
                f"{name}: url({target[:60]}…) points off-origin"
            )
        assert "@import" not in css, f"{name}: @import can fetch off-origin"
        assert "@font-face" not in css, (
            f"{name}: an @font-face appeared. That is allowed by `font-src "
            "'self'`, but the header of sentinel.css states the cost decision "
            "against shipping one — update it before adding fonts, or the "
            "file explains a choice nobody made."
        )
