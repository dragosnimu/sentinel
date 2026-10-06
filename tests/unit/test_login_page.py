"""The login page tells a stranger nothing, and the form has room to breathe.

Two things the operator asked for on the server's login page, and what goes wrong for them if
each regresses:

* **The text under "Continuă" is gone, and stays gone.** It said the product, the CLI and the
  exact recovery path (`sentinel web --enroll-totp --username <user>`) to anyone who loaded the
  page, before any authentication. Removing the paragraph alone was not enough: the SAME command
  was also reachable at `/login?e=totp_key`, because the `e` parameter proves nothing and anyone
  can type it. Both are pinned here, on what the page RENDERS, not on the presence of a word in
  a file (a Jinja comment that mentions the command is not output).
* **The recovery path is where only someone who knows the password can see it.** `/totp` is
  reached with an accepted password (`pending_session`); the lost-authenticator help lives there,
  with the operator's own account name in the command. A recovery path removed from the login
  page and put nowhere is a locked-out operator reading `sudo` documentation at 3 a.m.
* **The fields are spaced.** Measured in Edge at 1700 px before the change: the password field and
  the "Continuă" button touched (0 px between them), labels sat 6 px above their field, the card
  was 410 px. A test cannot measure pixels — the numbers are in the CSS comment and in the report —
  so what is pinned here is the RULES that produce them: each of these fails if the rule is
  deleted, and the gap between button and field is zero again.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
CSS = ROOT / "sentinel" / "web" / "static" / "css" / "sentinel.css"

# Words that, rendered on a page an unauthenticated visitor can load, describe the product's
# recovery mechanism. Lower-case; compared against the lower-cased render.
LEAK_TOKENS = ("enroll-totp", "sentinel web", "--username", "sudo", "deblocarea se face",
               "al doilea factor")


def _env():
    from sentinel.web.jinja import build_env

    return build_env()


def _login_html(**over) -> str:
    ctx = {"csrf_token": "t", "error": None, "username": "", "domain": "sentinel.example.org",
           "version": "1"}
    ctx.update(over)
    return _env().get_template("login.html").render(**ctx)


def _strip_comments(css: str) -> str:
    return re.sub(r"/[*].*?[*]/", "", css, flags=re.S)


def _rule(selector: str) -> dict[str, str]:
    """Declarations of the rule whose selector list is exactly `selector`; fails loudly if absent."""
    css = _strip_comments(CSS.read_text(encoding="utf-8"))
    for m in re.finditer(r"([^{}]+)[{]([^{}]*)[}]", css):
        if " ".join(m.group(1).split()) == selector:
            return {k.strip(): " ".join(v.split()) for k, _, v in
                    (d.partition(":") for d in m.group(2).split(";")) if k.strip()}
    raise AssertionError(f"no rule with selector {selector!r} in {CSS.name}")


# ---------------------------------------------------------------- the leak


@pytest.mark.parametrize("state", ["empty", "wrong-password", "after-logout", "totp-key-forged"])
def test_the_login_page_renders_no_recovery_path_in_any_state(state):
    """A stranger must learn nothing about the second factor or the CLI from `/login`.

    Eșecul pe care îl previne: textul de sub buton (sau o variantă a lui) revine, ori o stare a
    paginii — eroare de parolă, deconectare, adresa `?e=totp_key` — îl readuce prin altă cale.
    Operatorul și-ar vedea din nou comanda de recuperare servită oricui deschide pagina.
    """
    from sentinel.web.routers import auth

    if state == "empty":
        html = _login_html()
    elif state == "wrong-password":
        html = _login_html(error="Autentificare eșuată.", username="dragos")
    elif state == "after-logout":
        req = SimpleNamespace(query_params={"e": "logout"})
        html = _login_html(error=auth._login_error(req))
    else:
        # Anyone can type this address; it must be exactly as quiet as the page without it.
        req = SimpleNamespace(query_params={"e": "totp_key"})
        err = auth._login_error(req)
        assert err, "positive control: `?e=totp_key` must still produce SOME message"
        html = _login_html(error=err)

    low = html.lower()
    assert "continuă" in low and 'name="password"' in low, "positive control: this is the login form"
    for token in LEAK_TOKENS:
        # The forged `totp_key` page legitimately says the second factor cannot be decrypted;
        # that sentence is the aggregator's own level of disclosure and carries no command.
        if state == "totp-key-forged" and token == "al doilea factor":
            continue
        assert token not in low, f"/login ({state}) renders {token!r} to an unauthenticated visitor"


def test_no_login_error_message_names_the_command():
    """No message the login page can be made to show may carry the recovery command.

    Eșecul pe care îl previne: cineva adaugă o nouă cheie în `_ERROR_MESSAGES` și copiază în ea
    comanda — iar `/login?e=<cheia>` o servește oricui, fiindcă `e` nu dovedește nimic.
    """
    from sentinel.web.routers import auth

    assert auth._ERROR_MESSAGES, "positive control: the table must not be empty"
    for key, message in auth._ERROR_MESSAGES.items():
        low = message.lower()
        assert "enroll-totp" not in low and "sudo" not in low and "sentinel web" not in low, (
            f"`/login?e={key}` is a forgeable URL and its message names the recovery command")


def test_the_login_template_has_no_second_factor_paragraph_left():
    """Belt and braces on the template itself: the old class and its CSS rule are gone.

    Eșecul pe care îl previne: paragraful dispare din HTML dar rămâne ca regulă moartă — iar la
    următoarea „reparație" cineva îl readuce fiindcă stilul „există deja".
    """
    html = _login_html()
    assert "auth-note" not in html
    assert "auth-note" not in CSS.read_text(encoding="utf-8")


# ---------------------------------------------------------------- the recovery path, after the password


def _totp_html(username: str) -> str:
    """Render `/totp` through the REAL route function, so `shlex.quote` is part of what is tested."""
    from sentinel.web.routers import auth

    env = _env()

    class _Templates:
        def TemplateResponse(self, *, request, name, context, status_code=200):  # noqa: N802
            return env.get_template(name).render(**context, version="1")

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(templates=_Templates())))
    session = SimpleNamespace(user_id=1, csrf_token="t")

    async def get_by_id(db, uid):  # noqa: ANN001, ANN202
        return SimpleNamespace(username=username)

    original = auth.users_repo.get_by_id
    auth.users_repo.get_by_id = get_by_id
    try:
        return asyncio.run(auth.totp_form(request, session, db=object()))
    finally:
        auth.users_repo.get_by_id = original


def test_the_totp_page_carries_the_recovery_command_with_the_account_name():
    """After a correct password, a lost authenticator has somewhere to look.

    Eșecul pe care îl previne: ajutorul scos de pe `/login` nu apare nicăieri. Operatorul cu
    telefonul pierdut ar sta la ecranul de cod fără să știe că deblocarea se face pe server.
    """
    html = _totp_html("dragos")
    assert "<details" in html and "Ai pierdut aplicația de autentificare?" in html
    assert "sudo sentinel web --enroll-totp --username dragos" in html
    # Closed by default: someone who HAS the app does not need a shell command under the code field.
    assert re.search(r"<details[^>]* open", html) is None


def test_the_recovery_command_survives_an_account_name_the_shell_would_split():
    """A name with a space or an apostrophe must not produce a command that does something else.

    Eșecul pe care îl previne: `--username o'brien` copiat în terminal deschide un șir
    neterminat; `--username a b` se citește ca doi parametri. Comanda ar spune „reînrolează" și
    n-ar face asta — sau ar reînrola ALT cont.
    """
    spaced = _totp_html("a b")
    assert "--username &#39;a b&#39;" in spaced
    quoted = _totp_html("o'brien")
    # shlex.quote("o'brien") is 'o'"'"'brien' — five quote characters around the apostrophe.
    import shlex

    expected = shlex.quote("o'brien").replace("'", "&#39;").replace('"', "&#34;")
    assert f"--username {expected}" in quoted


def test_an_unknown_account_name_leaves_a_placeholder_not_an_empty_flag():
    """`--username ` followed by nothing is a command that errors with a confusing message."""
    html = _totp_html("")
    assert "--username &lt;utilizator&gt;" in html


# ---------------------------------------------------------------- the spacing rules


def test_the_form_fields_are_wrapped_in_groups_and_the_button_follows_the_last_one():
    """The markup the spacing rules hang on: `.field` groups, then the button.

    Eșecul pe care îl previne: șablonul pierde `.field` (un refactor „simplifică"), iar regulile
    `.field + .field` nu mai potrivesc nimic — formularul revine la câmpurile lipite, fără ca vreun
    test de CSS să observe, fiindcă regulile ar exista în continuare.
    """
    html = _login_html()
    groups = re.findall(r'<div class="field">(.*?)</div>', html, flags=re.S)
    assert len(groups) == 2
    assert 'for="username"' in groups[0] and 'id="username"' in groups[0]
    assert 'for="password"' in groups[1] and 'id="password"' in groups[1]
    assert html.index('class="btn btn-primary btn-block"') > html.index('id="password"')
    assert 'class="auth-form"' in html


def test_the_button_is_separated_from_the_last_field():
    """Before: 0 px between the password field and the button (measured, Edge, 1700 px).

    Eșecul pe care îl previne: butonul lipit de câmpul de parolă. Regula care îl desparte e
    `.auth-form .btn-primary { margin-top }`; ștearsă, spațiul e zero din nou.
    """
    gap = _rule(".auth-form .btn-primary")["margin-top"]
    assert gap.endswith("rem") and float(gap[:-3]) >= 1.5, gap


def test_groups_are_further_apart_than_a_label_is_from_its_own_field():
    """Proximity: label→field smaller than field→next label, or the column reads as uniform rows.

    Eșecul pe care îl previne: ambele spații egale (sau inversate) — eticheta „Parolă" ar părea să
    aparțină câmpului de deasupra ei.
    """
    between = float(_rule(".auth-form .field + .field")["margin-top"][:-3])
    label_bottom = _rule(".auth-form label")["margin"].split()
    inside = float(label_bottom[2][:-3])  # `margin: 0 0 .5rem`
    assert inside > 0, "the label touches its field"
    assert between >= 2 * inside, (between, inside)


def test_the_card_is_wider_than_the_old_410_pixels():
    """The old card was 410 px: 344 px fields on a 1700 px screen.

    Eșecul pe care îl previne: cardul revine la 410 px (sau mai puțin) și câmpurile la 344 px.
    """
    width = _rule(".auth-card")["max-width"]
    assert width.endswith("rem") and float(width[:-3]) >= 27, width
