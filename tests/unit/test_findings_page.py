"""Pagina de vulnerabilități, condusă prin aplicația reală.

Middleware real, router real, șabloane Jinja reale; doar baza de date e un
ciot — dar un ciot care chiar filtrează, ordonează și taie felii, fiindcă
altfel nu se poate dovedi ce dovedesc testele de mai jos: că există un drum de
la pagină la rândurile pe care le numără.

Eșecurile pe care le previn, toate văzute sau măsurate:

  * o constatare a cărei categorie nu se poate citi din pagină — operatorul nu
    știe dacă repară gazda sau reconstruiește o imagine;
  * o categorie numărată din rândurile AFIȘATE. Măsurat pe producție la 21
    septembrie 2026: dintre primele 200 de rânduri, 183 `trivy_image`, 17
    `trivy_fs` și zero `dnf`, deși gazda are 477 de constatări deschise pe
    pachetele ei. Coloana ar fi arătat „Sistem de operare" de zero ori pe
    gazda care a cerut funcționalitatea;
  * o categorie numărată corect, dar de neatins: fără filtru și fără pagini,
    rândul 201 n-are niciun drum către ecran (`sentinel/web/static/` nu are
    niciun fișier JavaScript, iar pagina n-avea niciun parametru);
  * un filtru cu lista de scanere goală tratat ca „fără filtru", care ar arăta
    toate cele 1055 de rânduri sub eticheta unei categorii goale;
  * tabelul taie și nu spune, deci orice numărătoare făcută pe pagină iese
    greșită și pare a fi a bazei.
"""

from __future__ import annotations

import contextlib
import html as html_mod
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Config, Secrets
from sentinel.web.security import COOKIE_NAME

SESSION_SECRET = "d" * 64
TOKEN = "test-session-token"
NOW = datetime(2026, 9, 21, 9, 30, tzinfo=timezone.utc)


def _session_row(csrf: str = "csrf-token-value") -> dict:
    return {
        "id": "sess1", "user_id": 1, "pending_totp": False, "csrf_token": csrf,
        "expires_at": NOW + timedelta(hours=8), "created_at": NOW - timedelta(hours=1),
        "last_seen_at": NOW, "ip": "203.0.113.7",
    }


def _user_row() -> dict:
    return {
        "id": 1, "username": "operator", "password_hash": "x", "password_algo": "argon2id",
        "totp_secret": None, "totp_confirmed": True, "totp_last_counter": None,
        "role": "owner", "failed_attempts": 0, "locked_until": None, "disabled": False,
    }


def _finding(**over) -> dict:
    """Un rând `findings` în forma exactă pe care o selectează `list_open`.

    Cheile sunt cele din interogare, nu un subset comod: un ciot care întoarce
    mai puțin decât coloanele cerute ar ascunde un `UndefinedError` din șablon,
    adică chiar felul de defect pentru care există fișierul ăsta.

    Atenție la cât acoperă asta: `{{ r.ceva }}` pe o cheie lipsă ARUNCĂ, dar
    `{% for a in avertismente %}` peste o cheie lipsă nu aruncă — randează
    nimic, tăcut (verificat). Deci blocul de avertismente nu e păzit de
    mecanismul ăsta, ci de testele care cer textul lor în pagină.
    """
    row = {"id": 1, "cve": "CVE-2026-9538", "advisory_id": None, "title": "gravă",
           "severity": "high", "cvss": 8.1, "epss": 0.2, "kev": False, "priority": 70,
           "package": "openssl", "installed_version": "1", "fixed_version": "2",
           "scanner": "dnf", "location": None, "status": "open", "last_seen": NOW,
           "asset_name": None}
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# Recensământul de pe gazda de producție, 21 septembrie 2026
# ---------------------------------------------------------------------------
# dnf 477 (prioritate 35–83) | trivy_image 486 (60–100) | trivy_fs 92 (60–100).
# Intervalele contează: toate constatările de sistem stau SUB pragul de
# prioritate al primelor 200 de rânduri, ceea ce e chiar defectul. Severitatea
# e o funcție de prioritate, deci toate rândurile cu aceeași prioritate au
# aceeași severitate — așa ordinea depinde numai de (prioritate, id), la fel în
# ciot și în interogarea reală, care se departajează pe `f.id DESC`.
def _census_rows() -> list[dict]:
    rows: list[dict] = []
    fid = 0
    for scanner, n, lo, hi, location in (
            ("trivy_image", 486, 60, 100, "mariadb:11.4.7"),
            ("trivy_fs", 92, 60, 100, "html/phpMyAdmin/composer.lock"),
            ("dnf", 477, 35, 83, None)):
        span = hi - lo + 1
        for i in range(n):
            fid += 1
            priority = lo + (i % span)
            rows.append(_finding(id=fid, scanner=scanner, location=location,
                                 priority=priority, package=f"pkg-{fid}",
                                 # Exact una KEV pe scaner, deci una pe
                                 # categorie: pastila 🔥 e singura care se putea
                                 # număra global lângă un tabel filtrat fără ca
                                 # vreun test să observe.
                                 kev=(i == 0),
                                 severity="critical" if priority >= 90 else "high"))
    return rows


class StubDB:
    """Răspunde după un fragment distinctiv din SQL.

    Filtrarea, ordonarea și felia sunt implementate, nu simulate: paginarea și
    filtrul pe categorie sunt chiar ce se verifică, iar un ciot care întoarce
    aceeași listă la orice OFFSET ar face testul de accesibilitate să treacă
    fără ca rândul 201 să fie vreodată atins.

    Ordonarea oglindește numai (prioritate desc, id desc) — atât cât are nevoie
    paginarea. Corpusul e construit ca severitatea și `last_seen` să nu poată
    departaja nimic, deci ordinea reală a bazei coincide cu asta.
    """

    def __init__(self, *, findings: list[dict] | None = None) -> None:
        self.all = list(findings or [])
        self.seen_sql: list[tuple[str, tuple]] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def healthy(self) -> bool:
        return True

    async def size_bytes(self) -> int:
        return 12 * 1024 * 1024

    @staticmethod
    def _filter(rows: list[dict], scanners) -> list[dict]:
        # `or ""` oglindește `coalesce(scanner, '')` din interogare: numărătoarea
        # și filtrul folosesc aceeași formă, altfel un rând fără scaner ar fi
        # numărat într-o pastilă pe care apăsând-o n-ar aduce nimic.
        if scanners is None:
            return rows
        return [r for r in rows if (r["scanner"] or "") in scanners]

    async def fetchrow(self, sql: str, *a: object):
        if "FROM sessions" in sql:
            return _session_row()
        if "FROM users WHERE id" in sql:
            return _user_row()
        return None

    async def fetch(self, sql: str, *a: object):
        self.seen_sql.append((sql, a))
        if "coalesce(scanner, '') AS scanner" in sql:
            return [{"scanner": s, "n": n}
                    for s, n in Counter(r["scanner"] or "" for r in self.all).items()]
        if "GROUP BY severity" in sql:
            scanners = a[0] if "ANY($1::text[])" in sql else None
            rows = self._filter(self.all, scanners)
            return [{"severity": s, "n": n}
                    for s, n in Counter(r["severity"] for r in rows).items()]
        if "FROM findings f LEFT JOIN assets" in sql:
            if "coalesce(f.scanner, '') = ANY($1" in sql:
                scanners, limit, offset = a[0], a[1], a[2]
            else:
                scanners, limit, offset = None, a[0], a[1]
            rows = sorted(self._filter(self.all, scanners),
                          key=lambda r: (-r["priority"], -r["id"]))
            return rows[offset:offset + limit]
        # Un ac de potrivire rămas în urmă e felul în care un ciot începe să
        # răspundă „nimic" la o interogare pe care n-o mai recunoaște, iar
        # testele de deasupra ar citi asta ca pe o pagină goală legitimă. S-a
        # întâmplat chiar în runda asta: `coalesce(...)` a schimbat două
        # tipare. Deci o interogare pe `findings` pe care ciotul n-o cunoaște
        # e o eroare, nu o listă goală.
        assert "findings" not in sql, f"ciotul nu recunoaște interogarea: {sql[:160]}"
        return []

    async def fetchval(self, sql: str, *a: object):
        if "status = 'open' AND kev" in sql:
            scanners = a[0] if "ANY($1::text[])" in sql else None
            return sum(1 for r in self._filter(self.all, scanners) if r["kev"])
        if "schema_version" in sql:
            return 12
        return None

    async def execute(self, sql: str, *a: object) -> str:
        return "UPDATE 1"


@contextlib.contextmanager
def _client(db: StubDB, *, authenticated: bool = True):
    from sentinel.web import app as app_module

    original = app_module.Database
    app_module.Database = lambda _cfg: db          # type: ignore[assignment]
    try:
        cfg = Config()
        cfg.web.domain = "sentinel.example.com"
        secrets = Secrets({"SENTINEL_SESSION_SECRET": SESSION_SECRET})
        app = app_module.create_app(cfg, secrets)
        # https: fiecare cookie pe care îl pune Sentinel are `Secure`, iar un
        # client pe http n-ar trimite sesiunea înapoi și ar arăta ca un bug de
        # autentificare.
        with TestClient(app, base_url="https://testserver") as client:
            if authenticated:
                client.cookies.set(COOKIE_NAME, TOKEN)
            yield client
    finally:
        app_module.Database = original             # type: ignore[assignment]


def _page(db: StubDB, url: str = "/findings") -> str:
    with _client(db) as c:
        r = c.get(url)
    assert r.status_code == 200, r.status_code
    return r.text


def _cell(html: str, needle: str) -> str:
    """Celula „Asociat cu" a rândului care conține `needle`.

    Pe rânduri întregi, o aserțiune „nu apare cuvântul Container" ar putea fi
    satisfăcută de alt rând al tabelului; categoria se citește deci din celula
    rândului cerut.
    """
    rows = [r for r in html.split("<tr") if needle in r]
    assert len(rows) == 1, f"{needle!r} apare în {len(rows)} rânduri, nu în exact unul"
    return rows[0].split("<td")[-1]


def _packages(html: str) -> set[str]:
    """Pachetele din rândurile chiar randate — cum se numără ce a ajuns pe ecran."""
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    return set(re.findall(r"pkg-\d+", body))


def _chip(html: str, label: str) -> str:
    """Ancora pastilei de categorie al cărei text se termină cu `label`."""
    for m in re.finditer(r"<a [^>]*>[^<]*</a>", html, re.S):
        tag = m.group(0)
        if tag.split(">", 1)[1].split("<", 1)[0].strip().endswith(label):
            return tag
    raise AssertionError(f"nicio pastilă pentru {label!r} în pagină")


def _link(html: str, text: str) -> str:
    """URL-ul ancorei al cărei text conține `text`, dezescapat ca în browser."""
    for m in re.finditer(r'<a href="([^"]+)"[^>]*>([^<]*)</a>', html):
        if text in m.group(2):
            return html_mod.unescape(m.group(1))
    raise AssertionError(f"nicio legătură cu textul {text!r} în pagină")


# ---------------------------------------------------------------------------
# Categoria — ce a cerut operatorul
# ---------------------------------------------------------------------------
def test_pagina_spune_pe_ce_sta_fiecare_constatare():
    """Defectul pentru care există funcționalitatea asta: pagina arăta
    `trivy_image` — CUM a fost găsită constatarea — și niciun cuvânt despre PE
    CE stă. Operatorul nu putea deosebi un pachet al gazdei de unul dintr-o
    imagine construită de altcineva, deși cele două se repară complet diferit.
    """
    html = _page(StubDB(findings=[
        _finding(id=1, scanner="dnf", location=None, package="openssl"),
        _finding(id=2, scanner="trivy_image", location="mariadb:11.4.7", package="libxml2"),
        _finding(id=3, scanner="trivy_fs", location="html/phpMyAdmin/composer.lock",
                 package="twig/twig"),
    ]))

    assert "Sistem de operare" in _cell(html, "openssl")
    assert "Container · mariadb:11.4.7" in _cell(html, "libxml2")
    assert "Aplicație · phpMyAdmin (composer.lock)" in _cell(html, "twig/twig")


def test_scanerul_nu_se_pierde_odata_cu_coloana():
    """Numele scanerului e ce leagă un rând de rularea care l-a produs și de
    `scan:last:{scanner}` din autoverificare. Scos din coloană și nepus nicăieri
    altundeva, ar dispărea din pagină cu totul."""
    html = _page(StubDB(findings=[
        _finding(id=2, scanner="trivy_image", location="mariadb:11.4.7", package="libxml2"),
    ]))
    assert 'title="Scaner: trivy_image · mariadb:11.4.7"' in _cell(html, "libxml2")


def test_un_scaner_necunoscut_nu_e_prezentat_ca_una_din_cele_trei():
    """Se vor adăuga scanere. Unul căzut din inerție în „Sistem de operare" ar
    trimite operatorul să caute pe gazdă un pachet care nu e acolo, fără ca
    ceva să spună vreodată că pagina a ghicit."""
    html = _page(StubDB(findings=[
        _finding(id=9, scanner="scaner-nou", location="undeva", package="ceva"),
    ]))
    cell = _cell(html, "ceva")
    assert "Necunoscut" in cell and "scaner-nou" in cell
    assert "Sistem de operare" not in cell
    assert "Container" not in cell and "Aplicație" not in cell


def test_locatia_ostila_ramane_text():
    """`location` e ieșire de scaner: o referință de imagine sau o cale de pe o
    gazdă atacată. Ajunge și în text, și într-un atribut `title`, iar un panou
    de securitate care execută ce i-a scris atacatorul în numele unui fișier ar
    fi cea mai proastă ironie posibilă."""
    hostile = '"><script>alert(1)</script>'
    html = _page(StubDB(findings=[
        _finding(id=7, scanner="trivy_image", location=hostile, package="pachet-ostil"),
    ]))
    assert "<script>alert(1)</script>" not in html
    # Atributul nu e spart: ghilimeaua din `location` nu închide `title=`.
    assert '"><script' not in html
    assert "&lt;script&gt;" in html
    assert "&#34;" in _cell(html, "pachet-ostil") or "&quot;" in _cell(html, "pachet-ostil")


def test_pagina_goala_nu_cade():
    """Starea pe care o vede prima dată orice instalare nouă."""
    assert "Nicio vulnerabilitate deschisă" in _page(StubDB())


# ---------------------------------------------------------------------------
# Categoriile se numără peste tot, și se pot deschide
# ---------------------------------------------------------------------------
def test_categoriile_se_numara_peste_toate_randurile_nu_peste_pagina():
    """Chiar defectul măsurat pe producție: niciunul dintre cele 200 de rânduri
    afișate nu e al sistemului de operare, iar gazda are 477 de constatări
    deschise acolo, 470 dintre ele mari. O numărătoare făcută din rândurile de
    pe ecran ar scrie „0 sistem de operare" pe o gazdă care are cea mai mare
    grămadă exact acolo — și operatorul n-ar avea cum să deosebească asta de
    „n-am putut să ți le arăt".
    """
    html = _page(StubDB(findings=_census_rows()))

    # Premisa testului, verificată în test, nu presupusă: pagina chiar nu are
    # niciun rând de sistem.
    assert "Sistem de operare" not in html.split("<tbody>", 1)[1]
    # Și totuși le numără pe toate.
    assert "477 sistem de operare" in html
    assert "486 container" in html
    assert "92 aplicație" in html


def test_exista_un_drum_de_la_pagina_catre_constatarile_de_sistem():
    """Numărul singur nu e un răspuns: pagina n-are niciun parametru, niciun
    control de sortare și niciun fișier JavaScript, deci fără o legătură
    rândul 201 nu poate fi atins în niciun fel. Testul umblă exact pe drumul
    pe care l-ar urma operatorul — apasă pastila, apoi „înainte" — și cere ca
    TOATE cele 477 de rânduri de sistem să fie ajunse.
    """
    rows = _census_rows()
    asteptate = {f"pkg-{r['id']}" for r in rows if r["scanner"] == "dnf"}
    assert len(asteptate) == 477

    db = StubDB(findings=rows)
    vazute: set[str] = set()
    with _client(db) as c:
        prima = c.get("/findings")
        assert prima.status_code == 200
        url = _link(prima.text, "sistem de operare")
        pasi = 0
        while url is not None:
            pasi += 1
            assert pasi <= 10, "prea multe pagini — legăturile se învârt în cerc"
            r = c.get(url)
            assert r.status_code == 200, url
            vazute |= _packages(r.text)
            try:
                url = _link(r.text, "înainte")
            except AssertionError:
                url = None

    assert pasi == 3, f"477 de rânduri la 200 pe pagină înseamnă 3 pagini, nu {pasi}"
    assert vazute == asteptate


def test_filtrul_arata_numai_categoria_ceruta():
    """Un filtru care lasă să treacă și altceva e mai rău decât niciun filtru:
    operatorul crede că se uită la aplicații și numără containere."""
    html = _page(StubDB(findings=_census_rows()), "/findings?asociat=app")
    body = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert "Aplicație · phpMyAdmin (composer.lock)" in body
    assert "Container" not in body and "Sistem de operare" not in body
    # Numitorul și pastilele descriu acum mulțimea filtrată, nu toată baza.
    assert "92 deschise în „aplicație”" in html


def test_o_categorie_fara_scanere_nu_ajunge_sa_arate_tot():
    """Capcana clasică a filtrului: lista goală de scanere citită ca „fără
    filtru". O gazdă fără constatări de sistem ar arăta atunci toate cele 578
    de rânduri de container și aplicație sub eticheta „sistem de operare"."""
    rows = [r for r in _census_rows() if r["scanner"] != "dnf"]
    html = _page(StubDB(findings=rows), "/findings?asociat=os")
    assert _packages(html) == set()
    assert "Nicio vulnerabilitate deschisă în „sistem de operare”" in html
    # Categoria există și e numărată la zero — altă afirmație decât „nu știu".
    assert "0 sistem de operare" in html


def test_pastila_kev_urmeaza_filtrul_ca_toate_celelalte():
    """Ultima pastilă numărată global lângă un tabel filtrat.

    Pe producție arăta „🔥 2 KEV" lângă „92 deschise în «aplicație»", unde
    categoria aia are zero exploatate activ — adică exact cifrele care nu se
    adună, pentru care există toată schimbarea asta. Pastilele de severitate
    erau acoperite de teste; KEV nu era, fiindcă nicio fixtură nu punea
    `kev=True` pe un rând al paginii.
    """
    db = StubDB(findings=_census_rows())
    assert "🔥 3 KEV" in _page(db), "corpusul trebuie să aibă una pe categorie"
    assert "🔥 1 KEV" in _page(db, "/findings?asociat=app")
    assert "🔥 1 KEV" in _page(db, "/findings?asociat=os")


def test_pastila_categoriei_alese_e_marcata_ca_atare():
    """Care filtru e aplicat e starea nouă principală a paginii.

    Nemarcat, operatorul nu poate spune dacă se uită la o categorie sau la tot
    — și tocmai a apăsat ceva. Două semnale independente, fiindcă unul singur
    se pierde: clasa (fără `pill-off`, deci culoarea accentului) și
    `aria-current`, care e și ce citește un cititor de ecran.
    """
    html = _page(StubDB(findings=_census_rows()), "/findings?asociat=app")
    ales = _chip(html, "aplicație")
    assert 'aria-current="page"' in ales
    assert "pill-off" not in ales

    for alta in ("sistem de operare", "container"):
        chip = _chip(html, alta)
        assert "pill-off" in chip
        assert "aria-current" not in chip


def test_exista_un_drum_inapoi_la_toate_categoriile():
    """Fără ieșire din filtru, singura cale înapoi e ștergerea manuală a
    parametrului din bara de adrese."""
    db = StubDB(findings=_census_rows())
    with _client(db) as c:
        filtrat = c.get("/findings?asociat=app")
        assert filtrat.status_code == 200
        inapoi = c.get(_link(filtrat.text, "toate"))
    assert inapoi.status_code == 200
    assert "rândurile 1–200 din 1055 deschise" in inapoi.text
    assert "în „aplicație”" not in inapoi.text


def test_un_rand_fara_scaner_e_si_numarat_si_deschizabil():
    """Numărătoarea și filtrul trebuie să trateze la fel un `scanner` lipsă.

    Coloana e NOT NULL azi pe ambele gazde, deci nu e o apărare pentru datele
    de acum: e garanția că cele două laturi nu se pot despărți. Dacă
    numărătoarea ar aduna un NULL la „necunoscut" iar filtrul ar căuta
    `scanner = ANY(ARRAY[''])` — care nu potrivește NULL — pastila ar spune 1
    și pagina deschisă din ea ar fi goală.
    """
    db = StubDB(findings=[_finding(id=1, scanner=None, location=None, package="pkg-1")])
    html = _page(db)
    assert "1 necunoscut" in html
    filtrat = _page(db, _link(html, "necunoscut"))
    assert _packages(filtrat) == {"pkg-1"}


def test_o_categorie_ceruta_gresit_nu_trece_drept_toate():
    """Dacă parametrul nu e înțeles, pagina arată tot — dar trebuie s-o SPUNĂ.
    Altfel operatorul citește 1055 de rânduri crezând că sunt o categorie."""
    html = _page(StubDB(findings=_census_rows()), "/findings?asociat=inventat")
    assert "Categorie necunoscută" in html and "inventat" in html
    assert "1055" in html


# ---------------------------------------------------------------------------
# Cât se vede din cât există
# ---------------------------------------------------------------------------
def test_pagina_spune_ce_felie_arata():
    """Producția are 1055 de constatări deschise și tabelul duce 200. Fără
    numitor, operatorul care grupează pe categorii numără 200 și obține un
    total care nu se potrivește cu antetul — iar cifra greșită pare a bazei, nu
    a paginii."""
    from sentinel.web.routers.findings import PAGE_LIMIT

    html = _page(StubDB(findings=_census_rows()))
    assert f"rândurile 1–{PAGE_LIMIT} din 1055 deschise" in html
    assert "pagina 1 din 6" in html


def test_a_doua_pagina_isi_spune_intervalul():
    html = _page(StubDB(findings=_census_rows()), "/findings?pagina=2")
    assert "rândurile 201–400 din 1055 deschise" in html
    assert "pagina 2 din 6" in html


def test_pagina_nu_pretinde_o_taiere_care_nu_s_a_facut():
    """Un „rândurile 1–3 din 3" pe o listă întreagă ar învăța operatorul că
    pagina ascunde mereu ceva, și l-ar face să nu mai creadă avertismentul
    atunci când chiar taie."""
    html = _page(StubDB(findings=[_finding(id=i, package=f"pkg-{i}") for i in range(1, 4)]))
    assert "3 deschise" in html
    assert "rândurile" not in html


def test_o_pagina_de_dupa_sfarsit_o_spune():
    """Tăcerea aici arată exact ca „nu mai e nimic deschis", care e ultima
    concluzie pe care o vrem greșită pe pagina de vulnerabilități."""
    html = _page(StubDB(findings=_census_rows()), "/findings?pagina=99")
    assert "Pagina 99 nu există; ultima e 6." in html
    assert "rândurile 1001–1055 din 1055 deschise" in html


@pytest.mark.parametrize("raw", ["abc", "0", "-2", "２", "1;drop"])
def test_un_numar_de_pagina_neinteles_o_spune(raw):
    """Un parametru nepotrivit nu poate fi ignorat în tăcere: pagina 1 arătată
    în locul paginii cerute e un răspuns la altă întrebare."""
    html = _page(StubDB(findings=_census_rows()), f"/findings?pagina={raw}")
    assert "Număr de pagină neînțeles" in html
    assert "rândurile 1–200 din 1055 deschise" in html


@pytest.mark.parametrize("cifre", [4300, 4301, 9000])
def test_un_numar_de_pagina_urias_nu_darama_pagina(cifre):
    """4301 de cifre în `?pagina=` au fost un 500, nu un mesaj.

    CPython refuză conversia unui întreg de peste 4300 de cifre
    (`max_str_digits`, implicit 4300 pe interpretoarele ambelor gazde), iar
    `isdigit()` lasă șirul să treacă până la `int()`. nginx acceptă linia de
    cerere la 8 kB pe ambele gazde, deci cererea ajunge la aplicație: un URL
    scris de oricine dărâma pagina de vulnerabilități, chiar în funcția scrisă
    ca să curețe parametrul. Lecția despre mulțimea de caractere fusese
    aplicată, cea despre lungime nu.
    """
    html = _page(StubDB(findings=_census_rows()), "/findings?pagina=" + "9" * cifre)
    assert "Număr de pagină neînțeles" in html
    assert "rândurile 1–200 din 1055 deschise" in html


def test_valoarea_neinteleasa_nu_se_intoarce_intreaga_in_pagina():
    """Mesajul citează înapoi ce n-a înțeles; citat întreg, un parametru de
    4,3 kB devine 4,3 kB de panou. Escapat, deci inofensiv — dar un panou de
    securitate n-are de ce să reflecte la lungime ce i-a trimis cineva."""
    from sentinel.web.routers.findings import MAX_ECHO

    html = _page(StubDB(findings=_census_rows()), "/findings?pagina=" + "9" * 5000)
    assert "9" * (MAX_ECHO + 1) not in html
    assert "9" * MAX_ECHO + "…" in html


def test_o_categorie_uriasa_nu_se_intoarce_intreaga_in_pagina():
    from sentinel.web.routers.findings import MAX_ECHO

    html = _page(StubDB(findings=_census_rows()), "/findings?asociat=" + "z" * 5000)
    assert "Categorie necunoscută" in html
    assert "z" * (MAX_ECHO + 1) not in html


def test_ordonarea_pe_care_se_pagineaza_e_totala():
    """Două pagini consecutive n-au voie să arate același rând de două ori și
    să sară peste al treilea.

    `priority`, `severity` și `last_seen` se repetă pe sute de rânduri, iar
    PostgreSQL nu promite nicio ordine între rânduri egale — poate întoarce
    alta la fiecare execuție, deci OFFSET-ul ar decupa din liste diferite și
    ar pierde exact rândurile pentru care a fost adăugat. Ce face ordinea
    totală e coloana unică de la coadă, iar singurul loc în care faptul ăsta
    trăiește e textul interogării: ciotul de mai sus nu poate reproduce
    nedeterminismul bazei, deci se citește interogarea trimisă.
    """
    db = StubDB(findings=_census_rows())
    _page(db, "/findings?pagina=2")
    lista = [s for s, _ in db.seen_sql if "FROM findings f LEFT JOIN assets" in s]
    assert len(lista) == 1, "interogarea de listare n-a fost trimisă o dată"
    ordine = lista[0].split("ORDER BY", 1)[1].split("LIMIT", 1)[0].strip()
    assert ordine.endswith("f.id DESC"), ordine


def test_pagina_cere_sesiune():
    """Lista vulnerabilităților deschise ale gazdei e o hartă de atac; fără
    sesiune, e o hartă publică."""
    with _client(StubDB(), authenticated=False) as c:
        r = c.get("/findings", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


# ---------------------------------------------------------------------------
# Funcțiile pure din router
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind,page,expected", [
    (None, 1, "/findings"),
    ("os", 1, "/findings?asociat=os"),
    ("os", 3, "/findings?asociat=os&pagina=3"),
    (None, 2, "/findings?pagina=2"),
])
def test_legatura_paginii_se_construieste_intreaga(kind, page, expected):
    """O legătură care pierde filtrul aruncă operatorul înapoi în lista
    neasociată exact când apasă «înainte»."""
    from sentinel.web.routers.findings import page_url

    assert page_url(kind, page) == expected


@pytest.mark.parametrize("raw,pages,expected_page,spune", [
    (None, 6, 1, False),
    ("3", 6, 3, False),
    ("6", 6, 6, False),
    ("7", 6, 6, True),
    ("abc", 6, 1, True),
    ("0", 6, 1, True),
    ("  2  ", 6, 2, False),
    # Marginea conversiei: nouă cifre încă se convertesc (și ies dincolo de
    # sfârșit), zece sunt refuzate înainte de conversie. Fără plafonul de
    # lungime, cazul de 4301 de cifre de mai jos ar fi `ValueError`, nu mesaj.
    ("9" * 9, 6, 6, True),
    ("9" * 10, 6, 1, True),
    ("9" * 4301, 6, 1, True),
])
def test_numarul_de_pagina_e_marginit_si_spune_cand_marginește(raw, pages, expected_page, spune):
    from sentinel.web.routers.findings import resolve_page

    page, warning = resolve_page(raw, pages)
    assert page == expected_page
    assert (warning is not None) is spune
