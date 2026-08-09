"""Cache-busting for the vendored stylesheet, and why it is not optional.

nginx serves `/static/` with `expires 7d` and `Cache-Control: public,
immutable` — in both vhost templates — and the app sets the same header itself
in `SecurityHeadersMiddleware`. `immutable` tells a browser not to revalidate
even on an explicit reload, so a stylesheet fetched before a deploy stays in
place for a week afterwards.

That is a correctness problem, not a cosmetic one. Every chart on the reports
page is inline SVG whose colours come entirely from classes in `sentinel.css`,
because the CSP forbids inline style. Against a stale sheet each
`<rect class="rep-seg rep-c0">` gets no `fill` and paints black on a near-black
card, and each `<line class="rep-grid">` gets no `stroke` and vanishes: five
empty strips, no console error, indistinguishable from "nothing happened" — the
exact failure the SVG approach was chosen to prevent, arriving through the HTTP
cache instead of through the CSP.

A content digest in the query string is what makes `immutable` safe to keep: the
old URL really is immutable, and new bytes live at a new URL. No operator has to
clear anything.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.web.jinja import STATIC_DIR, asset_digest, asset_url, template_globals

REPO = Path(__file__).resolve().parents[2]

# Any occurrence of the literal prefix, however it is quoted or wrapped: a
# double- or single-quoted attribute, or a CSS `url(...)`. Shared by the lint
# and by the test that proves the lint still bites — a guard with its own
# private copy of the pattern guards a duplicate, not the rule.
BARE_STATIC = re.compile(r"""["'(]/static/""")


def test_the_url_changes_when_the_file_content_changes(tmp_path):
    """The property the whole scheme rests on. A version tag that does not move
    with the bytes is a cache-busting scheme that busts nothing — and it fails
    silently, because the page still renders, just with last week's CSS."""
    f = tmp_path / "sheet.css"
    f.write_bytes(b".rep-c0 { fill: red; }")
    first = asset_digest(f)
    assert first

    f.write_bytes(b".rep-c0 { fill: blue; }")
    second = asset_digest(f)
    assert second
    assert second != first, "the digest did not move with the content"

    # And it is stable for unchanged content: a tag that churns on every render
    # would defeat caching entirely and re-download the sheet on every page.
    assert asset_digest(f) == second


def test_identical_bytes_at_two_paths_hash_the_same():
    """The tag is derived from content, not from an mtime or a counter — so a
    rebuild that rewrites an unchanged file does not invalidate a warm cache."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        a, b = Path(d) / "a.css", Path(d) / "b.css"
        a.write_bytes(b"body{}")
        b.write_bytes(b"body{}")
        assert asset_digest(a) == asset_digest(b)


def test_the_real_stylesheet_url_carries_its_own_digest():
    url = asset_url("css/sentinel.css")
    digest = asset_digest(STATIC_DIR / "css" / "sentinel.css")
    assert digest, "the shipped stylesheet could not be read"
    assert url == f"/static/css/sentinel.css?v={digest}"


def test_an_unreadable_asset_still_gets_a_version_not_a_bare_url():
    """"Unknown" and "fine" are different states. If the file cannot be hashed
    the URL falls back to the release version — weaker, because it only busts on
    a version bump, but it never emits the unversioned URL that would pin a
    browser to last week's CSS for a week."""
    from sentinel import __version__

    assert asset_url("nu-exista.css") == f"/static/nu-exista.css?v={__version__}"


def test_an_asset_outside_the_static_root_is_refused():
    """The argument comes from a template, not from a request — but a helper
    that happily builds a URL for `../../etc/passwd` is one refactor away from
    taking one that does."""
    with pytest.raises(ValueError):
        asset_url("../../../etc/passwd")


def test_asset_url_is_registered_as_a_template_global():
    """`base.html` calls it directly. An environment without it raises
    UndefinedError at render time — a 500 on every authenticated page."""
    assert "asset_url" in template_globals()


def test_no_template_references_a_bare_static_url():
    """One versioned href is not the fix; the rule is. A new template that
    hard-codes `/static/...` reintroduces the same week-long stale-cache window
    for whatever it loads.

    Widened after review, because the first version claimed a rule and enforced
    a corner of it: it walked `glob("*.html")` — flat only, while `pyproject`
    ships `web/templates/**/*.html` — and matched only double-quoted `href=` /
    `src=`. A `url(/static/…)`, a single-quoted attribute, or a template one
    directory down were all invisible to it.
    """
    templates = REPO / "sentinel" / "web" / "templates"
    files = sorted(templates.rglob("*.html"))
    # A lint over an empty file list passes for ever. This repository has paid
    # for that one already.
    assert len(files) >= 10, f"only {len(files)} templates found — the scan is broken"

    offenders = []
    for f in files:
        for lineno, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if BARE_STATIC.search(line):
                offenders.append(f"{f.relative_to(templates)}:{lineno}: {line.strip()[:80]}")
    assert not offenders, (
        "bare /static/ reference — use asset_url() so a deploy is not invisible "
        "for a week behind `Cache-Control: immutable`:\n  " + "\n  ".join(offenders))


def test_the_bare_url_lint_matches_the_shapes_it_claims_to():
    """Guard the guard, against the SHARED pattern.

    The first version of this test compiled its own copy of the regex, so
    narrowing the lint's pattern left it passing — a guard that guards a
    duplicate of the thing it is guarding. Both now use `BARE_STATIC`.
    """
    for shape in ('<link href="/static/css/x.css">',
                  "<link href='/static/css/x.css'>",
                  "<img src='/static/logo.svg'>",
                  "background: url(/static/img/x.png);",
                  '<link href="/static/sub/dir/x.css">'):
        assert BARE_STATIC.search(shape), shape
    # And it must not fire on the versioned call the templates actually use.
    assert not BARE_STATIC.search(
        """<link href="{{ asset_url('css/sentinel.css') }}">""")


def test_the_deploy_really_does_cache_static_immutably():
    """The premise the scheme exists for, pinned where it lives. If this ever
    stops being true, the coupling has changed and the decision deserves
    rereading — so it fails loudly rather than leaving behind a cache-busting
    mechanism nobody can explain."""
    for tmpl in ("deploy/nginx/sentinel.conf.tmpl",
                 "deploy/nginx/sentinel-shared.conf.tmpl"):
        text = (REPO / tmpl).read_text(encoding="utf-8")
        assert "location /static/" in text, tmpl
        block = text.split("location /static/", 1)[1].split("}", 1)[0]
        assert "immutable" in block, tmpl
        assert "expires" in block, tmpl

    # And the app sets it itself, so reaching uvicorn directly is no escape.
    app_src = (REPO / "sentinel" / "web" / "app.py").read_text(encoding="utf-8")
    static_rule = app_src.split('request.url.path.startswith("/static/")', 1)[1][:200]
    assert "immutable" in static_rule
