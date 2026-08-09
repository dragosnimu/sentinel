"""One place that builds the template environment.

The globals registered here are not decoration — `_vuln.html` calls `cve_links`
and `cves_in` directly, so a template rendered in an environment that lacks them
raises `UndefinedError` at render time rather than failing to import. That is a
500 on a page that works perfectly in the app, or a green test suite for
templates that are broken in production. Whichever direction it goes, the cause
is two environments with different globals.

So there is one factory, and both the app and the tests use it.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"


@lru_cache(maxsize=64)
def _digest(path: str, mtime_ns: int, size: int) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:10]
    except OSError:
        return None


def asset_digest(file: Path) -> str | None:
    """Short content hash of a file, or None if it cannot be read.

    Memoised on (path, mtime, size) rather than on the path alone, so editing a
    file invalidates the entry by itself. Caching on the path and clearing on
    restart would be correct in production and quietly wrong everywhere else —
    the sort of difference discovered by somebody wondering why their CSS change
    "didn't deploy".
    """
    try:
        st = file.stat()
    except OSError:
        return None
    return _digest(str(file), st.st_mtime_ns, st.st_size)


def asset_url(relative: str) -> str:
    """A cache-busting URL for a file under `web/static/`.

    THIS IS NOT DECORATION. nginx serves `/static/` with `expires 7d` and
    `Cache-Control: public, immutable` (both vhost templates), and the app sets
    the same header itself in `SecurityHeadersMiddleware`. `immutable` means a
    browser will not revalidate even on an explicit reload — so a stylesheet
    fetched before a deploy stays in place for a week afterwards.

    That is not a cosmetic problem here. Every chart on the reports page is
    inline SVG whose colours come entirely from classes in `sentinel.css`
    (geometry is in presentation attributes, because the CSP forbids inline
    style). Against a stale stylesheet, `<rect class="rep-seg rep-c0">` gets no
    `fill` and paints black on a near-black card, and the axis lines get no
    `stroke` and vanish: five empty strips, no console error, indistinguishable
    from "nothing happened". Exactly the failure the SVG approach was chosen to
    avoid, arriving through the HTTP cache instead of through the CSP.

    A content digest in the query string changes the URL whenever the bytes
    change, which is what makes `immutable` safe to keep: the old URL really is
    immutable, and the new content is at a new one.

    If the file cannot be read, the URL falls back to the release version. That
    is weaker — it only busts on a version bump — but it is honest about what it
    can promise, and it never silently emits an unversioned URL.
    """
    from sentinel import __version__

    rel = relative.lstrip("/")
    candidate = (STATIC_DIR / rel).resolve()
    try:
        candidate.relative_to(STATIC_DIR.resolve())
    except ValueError:
        # A template asking for something outside the static root can only be a
        # mistake; refuse to build a URL for it rather than serve one.
        raise ValueError(f"asset outside the static root: {relative!r}") from None

    return f"/static/{rel}?v={asset_digest(candidate) or __version__}"


def template_globals() -> dict[str, Any]:
    from sentinel import __version__
    from sentinel.intel import links

    return {
        "version": __version__,
        # Vulnerability references. Exposed as callables rather than
        # precomputed per view, because the same CVE is rendered from a
        # findings row, a plan's vulnerability list and an incident title.
        "cve_links": links.cve_links,
        "cves_in": links.cves_in,
        # Cache-busting. A bare `/static/...` href in a template is a bug —
        # see asset_url.
        "asset_url": asset_url,
    }


def build_env() -> Any:
    """A bare Jinja environment with the same configuration the app uses."""
    import jinja2

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.globals.update(template_globals())
    return env
