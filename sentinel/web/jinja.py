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

from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


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
