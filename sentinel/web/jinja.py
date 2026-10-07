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
import re
from datetime import datetime, timezone
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


def ora_filter(tz_name: str | None):
    """Filtrul `ora`: un moment scris în fusul configurat, cu marcajul lui.

    Un filtru, și nu `strftime` scris în fiecare șablon, fiindcă exact aia era
    situația până acum: treizeci de locuri care formatau singure, toate în UTC,
    dintre care patru scriau „UTC" în text și restul nu scriau nimic. Un panou
    care arată `21:15` fără să spună în ce fus e un panou pe care operatorul îl
    compară greșit cu `journalctl`.

    Fusul se leagă la construirea mediului, din `Config`, deci un șablon nu
    poate uita să-l dea și nu poate da altul.
    """
    from sentinel.util import tz

    def ora(moment: Any, pattern: str = tz.SHORT, with_zone: bool = True,
            missing: str = "—") -> str:
        if moment is None:
            return missing
        return tz.fmt(moment, pattern, tz_name=tz_name,
                      with_zone=with_zone, missing=missing)

    return ora


def usd_filter(value: Any) -> str:
    """Filtrul `usd`: o sumă în dolari, scrisă ca să nu mintă prin rotunjire.

    `ai_usage.cost_usd` e `numeric(10,6)`, iar un apel de triaj costă ~0,003 $. Rotunjit la
    două zecimale, primul apel al lunii ar apărea ca „0,00 $" — adică exact ca „nu s-a
    folosit modelul". De sub un cent se scrie „<0,01 $", iar zero rămâne zero.

    `None` (o valoare pe care n-am putut-o citi) NU devine zero: e „—".
    """
    if value is None:
        return "—"
    amount = float(value)
    if amount == 0:
        return "$0.00"
    if amount < 0.005:
        return "<$0.01"
    return f"${amount:.2f}"


def fraction_pct_filter(value: Any) -> str:
    """Filtrul `pct01`: o încredere între 0 și 1 ca procent întreg; lipsa e „—", nu „0%"."""
    if value is None:
        return "—"
    return f"{float(value) * 100:.0f}%"


# Cele cinci acțiuni pe care `triage._clean` le poate stoca în `recommended_action`
# (`sentinel.ai.triage._ACTION_ENUM`; `tests/unit/test_ai_content_badge.py` compară cele două
# liste și pe cea a agregatorului). Copiate aici, nu importate: `triage` trage după el clientul
# de model, iar un panou care randează o pagină nu are de ce să-l încarce.
AI_ACTIONS = ("monitorizează", "blochează", "investighează", "ignoră", "patch")


def ai_action_filter(value: Any) -> str | None:
    """Filtrul `ai_action`: acțiunea sugerată de model, DOAR dacă e una din cele cinci.

    Orice altceva — `unknown` (normalizatorul n-a știut să așeze răspunsul și l-a aruncat), o
    formă cu o secvență de ASCII scrisă literal în locul diacriticii, un obiect sau un număr
    scăpat în blob — devine `None`, iar șablonul OMITE rândul. Nu „—", nu textul: un rând
    „Acțiune sugerată: unknown" sub eticheta „AI content" ar da gunoiul drept părerea modelului
    (pe 6 oct 2026, 94% din verdictele judecate purtau una din aceste forme).

    Comparația e exactă și nu repară nimic: repararea datelor e treaba producătorului, nu a
    afișării. `value in tuple` (nu în `set`) ca un blob cu o listă în loc de șir să nu ridice
    `TypeError` și să dea 500 pe pagina incidentului.
    """
    return value if isinstance(value, str) and value in AI_ACTIONS else None


def zone_label(tz_name: str | None):
    """Globalul `fus_orar`: marcajul fusului în care sunt scrise orele paginii.

    Subsolul din `base.html` a scris „ora serverului: UTC" până pe 28 august
    2026, și era adevărat cât timp fiecare șablon își formata singur momentele,
    în UTC. De când trec toate prin `| ora`, propoziția aia contrazicea fiecare
    oră de deasupra ei — iar un subsol care contrazice pagina e mai rău decât
    niciun subsol: operatorul care compară panoul cu `journalctl` caută în
    fereastra greșită și crede că are motiv.

    Funcție chemată la randare, nu șir calculat la construirea mediului:
    aceeași zonă e `EET` iarna și `EEST` vara, iar un marcaj fixat la pornirea
    procesului ar fi greșit jumătate de an — și greșit TĂCUT, fiindcă orele de
    deasupra lui ar rămâne corecte. Marcajul iese din `util.tz.label`, adică din
    aceeași funcție care îl pune pe fiecare oră de pe pagină; două surse s-ar
    despărți exact în ziua schimbării ceasului.
    """
    from sentinel.util import tz

    def fus_orar(moment: datetime | None = None) -> str:
        return tz.label(moment or datetime.now(timezone.utc), tz_name)

    return fus_orar


# `X.Y.Z`, urmat opțional de `-pre` și `+build`. Aceeași formă o cere `releaseStage` din
# `aggregator/lib/version.ts`; `tests/unit/test_version_label.py` le dă ambelor aceleași cazuri.
# `re.ASCII`: în Python `\d` potrivește orice cifră Unicode (`１`, `٣`), în JavaScript doar `0-9`;
# fără steag, aceeași versiune ar fi „stabilă" aici și „necunoscută" în agregator.
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$", re.ASCII)


def release_stage(version: str) -> str:
    """`beta` (sub 1.0), `stable` (de la 1.0 în sus) sau `unknown` (n-am putut citi versiunea).

    Cuvântul „beta" din bara laterală iese DIN CIFRĂ, nu dintr-un steag scris de mână: operatorul
    a legat cele două („sub 1.0 pentru că e beta"), iar un steag separat ar fi a doua sursă care
    poate minți — în ziua în care `VERSION` devine `1.0.0`, panoul ar continua să spună „beta".

    `unknown` NU e „beta": `sentinel._read_version` cade pe `0.0.0+unknown` când nu găsește
    fișierul `VERSION`, iar 0.0.0 e tehnic sub 1.0. A scrie „beta" peste o versiune pe care n-am
    citit-o ar fi o afirmație fără fapt în spate; panoul spune că nu știe.

    Un sufix `-rc1` îl face tot `beta`: `1.0.0-rc1` e, prin definiția semver, ÎNAINTE de 1.0.0.
    """
    m = _SEMVER.fullmatch(version or "")
    if not m or version.endswith("+unknown"):
        return "unknown"
    return "beta" if int(m.group(1)) < 1 or m.group(4) else "stable"


def template_globals() -> dict[str, Any]:
    from sentinel import __version__
    from sentinel.intel import links
    from sentinel.scan import risk_view

    return {
        "version": __version__,
        # Versiunea din bara laterală, sub utilizator. Un global separat de `version` (cel din
        # subsol): un `version=...` pus în contextul unei pagini îl acoperă pe acela, dar nu pe
        # ăsta, deci bara nu poate arăta altceva decât `VERSION`.
        "release": {"version": __version__, "stage": release_stage(__version__)},
        # Vulnerability references. Exposed as callables rather than
        # precomputed per view, because the same CVE is rendered from a
        # findings row, a plan's vulnerability list and an incident title.
        "cve_links": links.cve_links,
        "cves_in": links.cves_in,
        # Cache-busting. A bare `/static/...` href in a template is a bug —
        # see asset_url.
        "asset_url": asset_url,
        # Semaforul SSVC, în cuvintele lui: numele unei stări e unul singur pe orice
        # ecran (`risk_view.COLOR_STATE_RO`). Un șablon care scrie „roșii" sau „fără date"
        # de mână e felul în care aceeași stare ajunge să aibă trei nume.
        "state_counts": risk_view.counts_ro,
        "state_name": risk_view.state_with_ssvc,
    }


def configure_env(env: Any, tz_name: str | None = None) -> Any:
    """Tot ce face dintr-un mediu Jinja gol mediul pe care îl randează Sentinel.

    UN SINGUR loc, chemat și de `build_env`, și de `web/app.create_app`. Până pe
    28 august 2026 cele două își legau globalele și filtrul fiecare pe cont
    propriu, cu aceleași linii scrise de două ori — deși capul fișierului ăstuia
    promitea deja o singură fabrică. Prima globală adăugată după promisiune a
    ajuns numai în mediul de teste: toate șabloanele randau verde local și
    fiecare pagină cu chenar dădea `UndefinedError`, adică 500, în proces.

    `tz_name` e fusul în care se scrie fiecare moment de pe pagină, și tot el e
    cel pe care îl numește subsolul. Legat aici, o dată, din `Config`: un șablon
    nu poate uita fusul și nu poate folosi altul.
    """
    env.globals.update(template_globals())
    env.filters["ora"] = ora_filter(tz_name)
    env.filters["usd"] = usd_filter
    env.filters["pct01"] = fraction_pct_filter
    env.filters["ai_action"] = ai_action_filter
    env.globals["fus_orar"] = zone_label(tz_name)
    return env


def build_env(tz_name: str | None = None) -> Any:
    """A bare Jinja environment with the same configuration the app uses.

    `tz_name` is what every rendered timestamp is written in. It defaults to
    None, which `sentinel.util.tz.zone` reads as "the host's own zone" — the
    same meaning it has for the quiet hours. The app passes `cfg.timezone`.
    """
    import jinja2

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    return configure_env(env, tz_name)
