"""Panoul web trebuie să poată fi văzut că e stricat.

Eșecul pe care îl previne, trăit pe 25 august 2026: pagina principală s-a
încărcat în 44 952, 59 772, 124 871 și 126 448 de milisecunde. `proxy_read_timeout`
e 60s, deci operatorul a primit `504 Gateway Time-out`. `sentinel-watchdog`
sondează `/healthz`, care răspunde în 13 ms fiindcă nu atinge nimic, și a
raportat `web=up` tot timpul. Nu exista niciun mecanism care SĂ POATĂ observa
defectul — nu unul care a ratat-o, ci unul care măsura altceva.

Testele de aici păzesc două lucruri diferite:

  * pragul e derivat din `proxy_read_timeout`, nu ales, și pică dacă vhostul se
    mută fără el;
  * sonda măsoară exact ce încarcă pagina, iar fiecare ramură a ei raportează
    ceva — inclusiv ramura „n-am putut măsura", care NU are voie să iasă `ok`.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.selfcheck import checks

ROOT = Path(__file__).resolve().parents[2]
NGINX_TEMPLATES = (
    ROOT / "deploy" / "nginx" / "sentinel-shared.conf.tmpl",
    ROOT / "deploy" / "nginx" / "sentinel.conf.tmpl",
)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
def _server_scope_read_timeout(path: Path) -> int:
    """`proxy_read_timeout` care guvernează `location /`, în secunde.

    Citit din vhost, nu dintr-o copie a numărului: o copie ar putea diverge
    exact ca numărul pe care îl păzește. Contează scopul — fișierul conține și
    `proxy_read_timeout 3600s` în `location = /stream`, iar acela e pentru SSE
    și n-are nicio legătură cu pagina principală. `location /` nu-și declară
    unul propriu, deci moștenește pe cel de la nivel de `server`.
    """
    stiva: list[str] = []
    gasite: list[tuple[tuple[str, ...], str]] = []
    for linie in path.read_text(encoding="utf-8").splitlines():
        curat = linie.split("#", 1)[0].strip()
        if not curat:
            continue
        m = re.match(r"^proxy_read_timeout\s+(\S+?);", curat)
        if m:
            gasite.append((tuple(stiva), m.group(1)))
        if curat.endswith("{"):
            stiva.append(curat.split()[0])
        elif curat == "}":
            assert stiva, f"acoladă de închidere fără pereche în {path.name}"
            stiva.pop()
    assert not stiva, f"bloc neînchis în {path.name}: {stiva}"

    la_nivel_de_server = [v for scop, v in gasite if scop == ("server",)]
    assert len(la_nivel_de_server) == 1, (
        f"{len(la_nivel_de_server)} directive `proxy_read_timeout` la nivel de "
        f"`server` în {path.name} (găsite în total: {gasite}); testul nu poate "
        f"ști care guvernează `location /`")
    brut = la_nivel_de_server[0]
    assert re.fullmatch(r"\d+s", brut), (
        f"`proxy_read_timeout {brut}` nu mai e în secunde simple în "
        f"{path.name}; învață testul formatul nginx (`1m`, `500ms`, ...) "
        f"înainte să treacă mai departe")
    return int(brut[:-1])


@pytest.mark.parametrize("tmpl", NGINX_TEMPLATES, ids=lambda p: p.name)
def test_the_threshold_is_the_nginx_proxy_read_timeout(tmpl: Path) -> None:
    """Pragul e valoarea din vhost; dacă vhostul se mută, verificarea se mută cu el.

    Eșecul pe care îl previne: cineva urcă `proxy_read_timeout` la 300s fiindcă
    pagina e lentă, iar constanta din `checks` rămâne 60. Verificarea începe să
    strige `down` peste pagini pe care operatorul le vede perfect, învață
    operatorul să treacă peste roșu, iar când pagina chiar cade nimeni nu se mai
    uită.

    Eșecul simetric: cineva COBOARĂ `proxy_read_timeout` la 20s, verificarea
    rămâne la 60, și o pagină de 45s iese `ok` în timp ce operatorul primește
    504. Adică exact defectul din 25 august, doar cu o verificare verde lângă el.
    """
    din_vhost = _server_scope_read_timeout(tmpl)
    assert checks.DASHBOARD_PROXY_TIMEOUT_S == din_vhost, (
        f"`checks.DASHBOARD_PROXY_TIMEOUT_S` e "
        f"{checks.DASHBOARD_PROXY_TIMEOUT_S}s, iar {tmpl.name} spune "
        f"{din_vhost}s. Cele două trebuie să fie același număr: vhostul decide "
        f"când operatorul primește 504, verificarea doar îl repetă")


def test_the_degraded_band_sits_strictly_below_the_504() -> None:
    """Banda „degradat" trebuie să lase loc, altfel avertizează după eșec.

    Eșecul pe care îl previne: `_DASHBOARD_BUGET = 1.0` — o editare care arată
    nevinovată („de ce să mă plâng înainte să se strice?"). Cu ea, `degraded` și
    `down` coincid, deci nu mai există niciun avertisment ÎNAINTE de 504:
    prima dată când verificarea se colorează, operatorul deja nu mai poate
    deschide pagina. Argumentul pentru jumătate stă la `_DASHBOARD_BUGET`.

    Și celălalt capăt: un buget zero sau negativ ar face fiecare încărcare
    „degradată", inclusiv una de 5 ms.
    """
    assert 0 < checks.DASHBOARD_SLOW_S < checks.DASHBOARD_PROXY_TIMEOUT_S, (
        f"DASHBOARD_SLOW_S={checks.DASHBOARD_SLOW_S}s nu mai e strict între 0 și "
        f"proxy_read_timeout={checks.DASHBOARD_PROXY_TIMEOUT_S}s, deci nu mai "
        f"există bandă de avertizare înaintea lui 504")


# ---------------------------------------------------------------------------
class _Ceas:
    """`time.monotonic` scriptat, ca durata măsurată să nu ceară așteptare reală."""

    def __init__(self, *valori: float) -> None:
        self.valori = list(valori)

    def __call__(self) -> float:
        return self.valori.pop(0) if len(self.valori) > 1 else self.valori[0]


def _incarcare(monkeypatch, *, secunde: float, boom: Exception | None = None):
    """Înlocuiește `page.load` și ceasul, ca sonda să „măsoare" `secunde`."""
    from sentinel.analytics import page

    async def fals(db):  # noqa: ANN001, ANN202
        if boom is not None:
            raise boom
        return {}

    monkeypatch.setattr(page, "load", fals)
    # Se înlocuiește NUMELE `time` din `checks`, nu funcția din modulul `time`:
    # `asyncio.wait_for` își ia ceasul tot de acolo, iar un ceas scriptat sub
    # bucla de evenimente face testul să măsoare altceva decât crede.
    monkeypatch.setattr(checks, "time", SimpleNamespace(monotonic=_Ceas(0.0, secunde)))


def test_a_quick_load_is_reported_ok_with_the_number(monkeypatch) -> None:
    """O pagină sănătoasă trebuie să spună CÂT a durat, nu doar „bine".

    Eșecul pe care îl previne: un `ok` fără cifră nu se poate compara cu cel de
    săptămâna trecută, deci degradarea lentă — cea care a produs pana din 25
    august — trece neobservată până în ziua în care sare pragul.
    """
    _incarcare(monkeypatch, secunde=0.8)
    (r,) = run(checks.check_dashboard_latency(object()))
    assert r.status == "ok"
    assert r.facts["durata_s"] == 0.8
    assert "0.8" in r.detail


def test_a_load_past_half_the_proxy_timeout_is_degraded(monkeypatch) -> None:
    """Peste jumătate din bugetul nginx, operatorul trebuie avertizat.

    Eșecul pe care îl previne: verificarea se aprinde abia la 504. Volumul de pe
    gazdă chiar se dublează de la o zi la alta — 5,6 milioane de rânduri pe 24
    august față de ~28 000 într-o zi obișnuită — deci o pagină la jumătatea
    bugetului e la o singură zi proastă distanță de a nu mai fi vizibilă.
    """
    _incarcare(monkeypatch, secunde=checks.DASHBOARD_SLOW_S + 1)
    (r,) = run(checks.check_dashboard_latency(object()))
    assert r.status == "degraded", (
        f"o încărcare de {checks.DASHBOARD_SLOW_S + 1}s a ieșit {r.status}")
    assert r.facts["prag_s"] == checks.DASHBOARD_SLOW_S


def test_a_load_just_under_the_band_is_still_ok(monkeypatch) -> None:
    """Pragul se aplică unde e scris, nu cu o marjă tăcută pe lângă.

    Eșecul pe care îl previne: `>` scris `>=` sau invers, plus orice conversie
    greșită de unități (milisecunde citite ca secunde). Cu 30 000 în loc de 30,
    invariantul de mai sus trece liniștit, iar pragul REAL devine opt ore și
    jumătate — adică o verificare care nu se aprinde niciodată.
    """
    _incarcare(monkeypatch, secunde=checks.DASHBOARD_SLOW_S - 0.5)
    (r,) = run(checks.check_dashboard_latency(object()))
    assert r.status == "ok"


def test_a_load_that_never_finishes_is_down_and_says_why(monkeypatch) -> None:
    """Când sonda depășește bugetul nginx, verdictul e `down`, nu „nu știu".

    Eșecul pe care îl previne: o sondă care atârnă la nesfârșit blochează rularea
    de autodiagnostic, deci nici celelalte verificări nu mai ajung la operator —
    o pagină lentă ar amuți întregul canal. Și ramura asta e cea în care se ȘTIE
    cel mai sigur că operatorul primește 504, deci ar fi cel mai rău loc pentru
    un `unknown`.
    """
    from sentinel.analytics import page

    async def atarna(db):  # noqa: ANN001, ANN202
        await asyncio.sleep(5)

    monkeypatch.setattr(page, "load", atarna)
    monkeypatch.setattr(checks, "DASHBOARD_PROXY_TIMEOUT_S", 0.05)
    (r,) = run(checks.check_dashboard_latency(object()))
    assert r.status == "down", f"o sondă care nu se termină a ieșit {r.status}"
    assert r.facts["peste_proxy_read_timeout"] is True


def test_a_probe_that_cannot_measure_is_unknown_not_ok(monkeypatch) -> None:
    """„N-am putut măsura" și „e bine" sunt stări diferite.

    Eșecul pe care îl previne: un `except` care întoarce `ok` sau, mai rău, o
    listă goală. Runner-ul reconciliază `selfcheck_state` după cheile emise de o
    rulare, deci o ramură TĂCUTĂ i-ar șterge constatarea roșie de dinainte și
    i-ar arăta operatorului o revenire care nu s-a întâmplat.
    """
    _incarcare(monkeypatch, secunde=0.2, boom=RuntimeError("pool epuizat"))
    rezultate = run(checks.check_dashboard_latency(object()))
    assert len(rezultate) == 1, "ramura de eroare nu a emis cheia"
    (r,) = rezultate
    assert r.status == "unknown", f"o măsurătoare ratată a ieșit {r.status}"
    assert "pool epuizat" in r.detail


def test_a_probe_that_fails_slowly_is_down_not_unknown(monkeypatch) -> None:
    """O interogare oprită de `statement_timeout` NU e „n-am putut măsura".

    Eșecul pe care îl previne, și e cel mai subtil de aici: pool-ul are
    `statement_timeout = 30000`, deci la volum dublu față de azi cea mai grea
    interogare a paginii nu devine lentă — CADE. Operatorul primește o pagină de
    eroare, iar o sondă care tratează orice excepție drept `unknown` ar raporta
    „nu se poate ști" despre singurul lucru care se știe sigur.
    """
    _incarcare(monkeypatch, secunde=checks.DASHBOARD_SLOW_S + 1,
               boom=RuntimeError("canceling statement due to statement timeout"))
    (r,) = run(checks.check_dashboard_latency(object()))
    assert r.status == "down", (
        f"o încărcare care a căzut după {checks.DASHBOARD_SLOW_S + 1}s a ieșit "
        f"{r.status}; operatorul primise deja pagina de eroare")


@pytest.mark.parametrize("scenariu", ["ok", "degradat", "eroare_rapida", "eroare_lenta"])
def test_every_branch_emits_exactly_one_key(monkeypatch, scenariu: str) -> None:
    """Nicio ramură nu are voie să tacă, și toate folosesc aceeași cheie.

    Eșecul pe care îl previne: chei diferite pe ramuri diferite. `selfcheck_state`
    ține constatările pe cheie, deci `web:dashboard:slow` azi și `web:dashboard`
    mâine înseamnă că roșul de ieri nu se mai închide niciodată — rămâne în panou
    ca o constatare pe care nimic n-o mai retrage.
    """
    cazuri = {
        "ok": (0.5, None),
        "degradat": (checks.DASHBOARD_SLOW_S + 1, None),
        "eroare_rapida": (0.5, RuntimeError("x")),
        "eroare_lenta": (checks.DASHBOARD_SLOW_S + 1, RuntimeError("x")),
    }
    secunde, boom = cazuri[scenariu]
    _incarcare(monkeypatch, secunde=secunde, boom=boom)
    rezultate = run(checks.check_dashboard_latency(object()))
    assert [r.key for r in rezultate] == ["web:dashboard"]


def test_the_check_is_registered_in_the_run(monkeypatch) -> None:
    """O verificare nescrisă în `CHECKS` nu rulează niciodată.

    Eșecul pe care îl previne: tot fișierul ăsta trece, `/selfcheck` rămâne
    verde, iar pagina cade la fel ca pe 25 august — fiindcă nimeni n-a chemat
    verificarea.
    """
    assert any(fn is checks.check_dashboard_latency for _, fn in checks.CHECKS), (
        "check_dashboard_latency nu e în CHECKS, deci nu rulează niciodată")


# ---------------------------------------------------------------------------
def test_the_probe_measures_the_same_panels_the_page_renders(monkeypatch) -> None:
    """Sonda și pagina citesc din același loc, altfel sonda măsoară o fantomă.

    Eșecul pe care îl previne: cineva adaugă un panou direct în router. Pagina
    face o interogare în plus, sonda nu știe de ea, iar când exact acel panou
    devine cel care ia pagina jos, `/selfcheck` rămâne verde. E același tipar ca
    `/healthz` — verificarea nu poate vedea defectul prin construcție — doar
    mutat cu un nivel mai adânc, deci mai greu de observat.

    Se verifică pe EFECT: `page.load` întoarce o singură cheie-martor, iar
    contextul șablonului nu are voie să conțină nimic altceva în afară de cele
    patru valori care nu sunt panouri. Un panou luat pe lângă `page.load` apare
    aici ca o cheie în plus.
    """
    from sentinel.analytics import page
    from sentinel.config import Config
    from sentinel.web.routers import dashboard as router

    capturat: dict[str, object] = {}

    class _Sabloane:
        def TemplateResponse(self, *, request, name, context):  # noqa: ANN001, ANN003, N802
            capturat.update(context)
            return "randat"

    class _DB:
        async def healthy(self) -> bool:
            return True

        async def size_bytes(self) -> int:
            return 1024

        async def fetchval(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
            return 30

    async def panouri(db):  # noqa: ANN001, ANN202
        return {"__panou_martor__": "x"}

    monkeypatch.setattr(page, "load", panouri)
    # `_self_status` citește /proc și `os.statvfs`, care nu există pe Windows.
    # Nu e ce păzește testul ăsta, iar `status` e oricum în mulțimea exclusă.
    async def stare(db, cfg):  # noqa: ANN001, ANN202
        return {}
    monkeypatch.setattr(router, "_self_status", stare)
    cerere = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(templates=_Sabloane())),
        state=SimpleNamespace(session=SimpleNamespace(csrf_token="t")),
    )
    run(router.dashboard(request=cerere, user=SimpleNamespace(username="op"),
                         db=_DB(), cfg=Config()))

    fara_panouri = {"user", "csrf_token", "status", "phase_notice"}
    assert set(capturat) - fara_panouri == {"__panou_martor__"}, (
        f"routerul pune în șablon chei care nu vin din `page.load`: "
        f"{sorted(set(capturat) - fara_panouri - {'__panou_martor__'})}. "
        f"Sonda din `check_dashboard_latency` măsoară `page.load`, deci un panou "
        f"luat pe lângă ea nu e măsurat de nimeni")


def test_the_probe_goes_through_page_load(monkeypatch) -> None:
    """Cealaltă jumătate a aceleiași garanții: sonda chiar apelează `page.load`.

    Eșecul pe care îl previne: verificarea își face propria listă de interogări,
    „ca să fie mai ieftină". Din ziua aia cele două liste încep să se despartă,
    tăcut, iar testul de deasupra n-ar prinde-o — el păzește doar routerul.
    """
    from sentinel.analytics import page

    apeluri: list[object] = []

    async def spion(db):  # noqa: ANN001, ANN202
        apeluri.append(db)
        return {}

    monkeypatch.setattr(page, "load", spion)
    santinela = object()
    run(checks.check_dashboard_latency(santinela))
    assert apeluri == [santinela], (
        "sonda nu a trecut prin `page.load`, deci nu măsoară ce încarcă pagina")
