"""`/static/` must carry the same security headers as every other location.

CONFIRMED finding (audit, 8 Sep 2026), W3: `sentinel-shared.conf.tmpl` included
`security-headers.conf` once, at server scope, before any `location` block.
nginx does not merge `add_header` directives across scopes — a location that
declares its OWN `add_header` (here, `Cache-Control` for the static files)
silently discards every `add_header` inherited from the parent, CSP and HSTS
included. Every file under `/static/` was served with no CSP, no HSTS, no
frame-options: exactly the headers a public dashboard depends on.

Round-3 finding, same day: `sentinel.conf.tmpl` (dedicated mode — port
@@PUBLIC_PORT@@, the mode the Ubuntu host actually runs) had the identical
defect. It went unnoticed the first time because the earlier version of this
test read only `sentinel-shared.conf.tmpl`. Both vhost templates render the
same `/static/` shape, so both are checked here, parametrized, so a fix (or a
regression) in one and not the other fails loudly instead of passing because
the other template happened to be the one under test.

The templates are rendered by `sed` inside `deploy/install.sh`, which this
test does not run — nothing here needs a placeholder resolved, only the
structure of the `location` block, so the templates' literal text is read
directly. Precedent: `tests/security/test_installer_nginx_preexisting.py`
reads `install.sh` and `common.sh` the same way, verbatim.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NGINX_DIR = REPO / "deploy" / "nginx"
SECURITY_HEADERS_INCLUDE = "/etc/nginx/sentinel/security-headers.conf"

# Anchored at line start (after comment-stripping) so a match can only come
# from a real directive, never from the explanatory comment inside the
# `/static/` block that names both of these in prose. `\b` after
# `Cache-Control` keeps the header-name check from also matching a stray
# mention inside a quoted header value elsewhere in the block.
INCLUDE_DIRECTIVE_RE = re.compile(
    r"^\s*include\s+" + re.escape(SECURITY_HEADERS_INCLUDE) + r";", re.M
)
CACHE_CONTROL_DIRECTIVE_RE = re.compile(r"^\s*add_header\s+Cache-Control\b", re.M)

# Both vhost templates carry a `location /static/` with the same
# `add_header Cache-Control` shape. `sentinel-default-deny.conf.tmpl` is the
# fallback vhost with no `/static/` location at all, so it is not part of
# this set — nothing here would apply to it.
TEMPLATES = ["sentinel.conf.tmpl", "sentinel-shared.conf.tmpl"]

pytestmark = pytest.mark.security


def _static_location_block(template_name: str) -> str:
    """The `location /static/ { ... }` block, as shipped.

    Non-greedy up to the first `}`: nothing inside this location nests braces
    (no `if`, no named location), so the first close is the real one. If that
    stops being true the regex fails to match and the test errors loudly
    rather than silently grabbing the wrong span.
    """
    text = (NGINX_DIR / template_name).read_text(encoding="utf-8")
    match = re.search(r"location\s+/static/\s*\{([^{}]*)\}", text)
    assert match, (
        f"no `location /static/ {{ ... }}` block found in {template_name} — "
        "either it was renamed/removed, or it now nests braces and this "
        "test's assumption about the block shape is stale"
    )
    return match.group(1)


def _strip_comment_lines(block: str) -> str:
    """Drop every line that is only a `#` comment.

    The block's own explanatory comment names both `Cache-Control` and
    `include ... security-headers.conf` in prose (see the module docstring
    for why it exists). A substring/`in` check against the raw block matches
    that prose even after the real directive line is deleted — the assertion
    stays green while the header is gone. Stripping comment lines first means
    only an actual directive can satisfy the assertions below.
    """
    return "\n".join(
        line for line in block.splitlines() if not re.match(r"^\s*#", line)
    )


def _https_server_scope(text: str) -> str:
    """Text from the HTTPS server block's `listen` line to its first `location`.

    Scoped this way because `sentinel-shared.conf.tmpl` has a SECOND, plain
    :80 server block (ACME challenge and redirect to HTTPS) ahead of the one
    `/static/` lives in — its own `location /` would otherwise be mistaken
    for the start of the HTTPS block's locations. Matching on `ssl http2`
    rather than a literal port picks the right block in both templates:
    shared listens on the literal `443`, dedicated listens on
    `@@PUBLIC_PORT@@`, a substitution marker, not yet a port number.
    """
    listen = re.search(r"^\s*listen\s+\S+\s+ssl\s+http2;", text, re.M)
    assert listen, "no HTTPS `listen ... ssl http2;` line found — the vhost's TLS listener moved or is gone"
    first_location = re.search(r"^\s*location\b", text[listen.start():], re.M)
    assert first_location, "no `location` directive found after the HTTPS listen line"
    return text[listen.start():listen.start() + first_location.start()]


@pytest.mark.parametrize("template_name", TEMPLATES)
def test_static_location_includes_the_security_headers_file(template_name):
    """The bug, directly: without this `include`, `add_header Cache-Control`
    in this location cancels every server-level `add_header` — CSP, HSTS,
    X-Frame-Options, all of it — for every file `/static/` serves."""
    block = _strip_comment_lines(_static_location_block(template_name))
    assert INCLUDE_DIRECTIVE_RE.search(block), (
        f"{template_name}: location /static/ does not include "
        f"{SECURITY_HEADERS_INCLUDE}; an add_header anywhere in this block "
        "silently drops the security headers inherited from the server block"
    )


@pytest.mark.parametrize("template_name", TEMPLATES)
def test_static_location_still_sets_its_own_cache_control(template_name):
    """The fix must not trade one header loss for another: `/static/` still
    needs its own long-lived Cache-Control, which is WHY it needs its own
    `add_header` in the first place."""
    block = _strip_comment_lines(_static_location_block(template_name))
    assert CACHE_CONTROL_DIRECTIVE_RE.search(block), (
        f"{template_name}: location /static/ no longer sets its own "
        "`add_header Cache-Control` directive — either it lost its "
        "long-lived caching, or the assertion is matching the explanatory "
        "comment instead of a real directive"
    )


@pytest.mark.parametrize("template_name", TEMPLATES)
def test_the_include_path_matches_the_one_used_at_server_scope(template_name):
    """Both includes must name the SAME file. A copy-pasted include pointing
    at a different, non-existent, or stale path would pass the first test
    above while still leaving `/static/` without real headers."""
    text = (NGINX_DIR / template_name).read_text(encoding="utf-8")
    server_scope = _strip_comment_lines(_https_server_scope(text))
    assert INCLUDE_DIRECTIVE_RE.search(server_scope), (
        f"{template_name}: the server-scope include this test compares "
        "against is missing or no longer precedes the first location block"
    )
    block = _strip_comment_lines(_static_location_block(template_name))
    assert INCLUDE_DIRECTIVE_RE.search(block), (
        f"{template_name}: location /static/ does not include "
        f"{SECURITY_HEADERS_INCLUDE} on its own directive line — the "
        "include may be commented out or the path may have drifted from "
        "the one used at server scope"
    )
