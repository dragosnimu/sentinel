"""Cele trei vhosturi nginx, randate — cu setul RHEL identic octet cu octet cu
ce se randa înainte, și cu cel Debian arătând către un director care există.

Calea `/etc/pki/tls` era scrisă cu mâna în toate trei șabloanele. Pe Ubuntu
directorul nu există deloc, deci certificatul-substituent nu se scria și
`ssl_certificate` arăta către un fișier care n-avea să apară. Reparația e un
marcaj `@@TLS_DIR@@` umplut de instalator.

Reparația asta are exact două feluri de a se strica, și fiecare are testul lui
aici:

  * marcajul e pus în șablon și UITAT din `sed` — atunci fișierul livrat conține
    literalmente `@@TLS_DIR@@`, iar nginx refuză să pornească;
  * substituția schimbă altceva pe drum, pe AlmaLinux, unde nimic n-avea
    nevoie de reparație. Producția rulează AlmaLinux.

Al doilea e păzit cu fișiere-etalon în `tests/fixtures/nginx-rhel/`, generate
din șabloanele DE DINAINTE de schimbare, cu setul de variabile RHEL. Comparația
e pe octeți. Dacă vreodată schimbi deliberat un șablon, etalonul se
regenerează — ideea nu e că nu se schimbă niciodată, ci că o schimbare a ceea
ce primește AlmaLinux e o decizie luată, nu un efect secundar observat mai
târziu.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NGINX_DIR = REPO / "deploy" / "nginx"
GOLDEN_DIR = REPO / "tests" / "fixtures" / "nginx-rhel"
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")

pytestmark = pytest.mark.security

# Setul de variabile cu care s-au generat etaloanele. `@@TLS_DIR@@` primește
# constanta istorică: exact șirul care era scris cu mâna în șablon.
RHEL_VARS = {
    "@@DOMAIN@@": "sentinel.example.com",
    "@@PORT@@": "8787",
    "@@PUBLIC_PORT@@": "8443",
    "@@TLS_DIR@@": "/etc/pki/tls",
}
DEBIAN_VARS = {**RHEL_VARS, "@@TLS_DIR@@": "/etc/ssl"}

TEMPLATES = ["sentinel.conf", "sentinel-shared.conf", "sentinel-default-deny.conf"]


def _render(name: str, variables: dict[str, str]) -> bytes:
    text = (NGINX_DIR / f"{name}.tmpl").read_bytes().decode("utf-8")
    for marker, value in variables.items():
        text = text.replace(marker, value)
    return text.encode("utf-8")


@pytest.mark.parametrize("name", TEMPLATES)
def test_the_rhel_render_is_byte_for_byte_what_it_was(name):
    """Producția rulează AlmaLinux. Un vhost care se schimbă acolo fiindcă s-a
    reparat Ubuntu e cea mai scumpă formă a acestei reparații: se descoperă la
    `nginx -t`, pe gazda care servește site-urile operatorului."""
    golden = (GOLDEN_DIR / name).read_bytes()
    assert _render(name, RHEL_VARS) == golden, (
        f"{name} randat cu variabilele RHEL diferă de etalonul dinainte de "
        f"schimbare ({GOLDEN_DIR / name})")


@pytest.mark.parametrize("name", TEMPLATES)
def test_the_debian_render_points_at_a_directory_that_exists_there(name):
    """`/etc/pki` nu există pe Debian sau Ubuntu. Un `ssl_certificate` care
    arată acolo e un nginx care nu pornește, cu o eroare despre TLS."""
    rendered = _render(name, DEBIAN_VARS).decode("utf-8")
    assert "/etc/ssl/certs/sentinel-selfsigned.crt" in rendered
    assert "/etc/pki" not in rendered


@pytest.mark.parametrize("name", TEMPLATES)
def test_no_marker_survives_the_render(name):
    """Un `@@…@@` rămas în fișierul livrat e o directivă nginx cu o cale
    inventată. Testul acoperă și marcajele care se vor adăuga după acesta."""
    assert "@@" not in _render(name, RHEL_VARS).decode("utf-8")


def _sed_invocation(name: str) -> str:
    """Comanda `sed` care randează CHIAR șablonul ăsta, din install.sh.

    Se caută înapoi de la calea șablonului până la `sed -e` — cele trei randări
    stau în două funcții diferite, iar o căutare în tot fișierul ar declara
    substituit un marcaj pe care doar UNA dintre ele îl umple. Exact așa arată
    bugul: modul dedicated merge, modul shared scrie `@@TLS_DIR@@` în vhost.
    """
    # `${SCRIPT_DIR}/`, ca să nu potrivească mențiunea din comentariul de la
    # începutul fișierului în loc de randarea propriu-zisă.
    needle = f"${{SCRIPT_DIR}}/nginx/{name}.tmpl"
    at = INSTALL.index(needle)
    start = INSTALL.rindex("sed -e", 0, at)
    block = INSTALL[start:at]
    assert block.count("\n") < 12, f"extragerea comenzii sed pentru {name} a luat prea mult"
    return block


@pytest.mark.parametrize("name", TEMPLATES)
def test_every_marker_in_a_template_is_substituted_where_it_is_rendered(name):
    """Eșecul concret pe care îl previne: cineva adaugă un marcaj în șablon și
    uită un `-e` la UNA dintre randări. Fișierul se scrie, `install.sh` iese cu
    0, iar nginx e cel care descoperă `@@TLS_DIR@@/certs/...` — la pasul 33,
    după ce instalarea a schimbat deja gazda."""
    text = (NGINX_DIR / f"{name}.tmpl").read_text(encoding="utf-8")
    markers = sorted(set(re.findall(r"@@[A-Z_]+@@", text)))
    assert markers, f"{name}.tmpl nu mai are niciun marcaj — testul n-ar păzi nimic"
    sed = _sed_invocation(name)
    for marker in markers:
        assert f"s|{marker}|" in sed, \
            f"{marker} apare în {name}.tmpl dar nu e substituit la randarea lui"


@pytest.mark.parametrize("name", TEMPLATES)
def test_the_certificate_lines_stay_in_the_shape_link_certificate_rewrites(name):
    """`link_certificate` înlocuiește liniile cu `sed 's|ssl_certificate .*|…|'`
    după ce certbot emite un certificat real. Dacă randarea schimbă forma
    liniei — indentare, alt nume de directivă, două directive pe un rând —
    substituția nu potrivește, iar gazda păstrează tăcut certificatul
    autosemnat: browserul avertizează, operatorul învață să treacă peste."""
    rendered = _render(name, RHEL_VARS).decode("utf-8")
    for directive in ("ssl_certificate", "ssl_certificate_key"):
        pattern = rf"^    {directive}\s+\S+;$"
        assert re.search(pattern, rendered, re.M), \
            f"{name}: linia {directive} nu mai are forma pe care o rescrie link_certificate"


def test_the_golden_files_are_lf_only():
    """Poarta din deploy.sh refuză pachetul dacă un fișier are CR, iar un etalon
    convertit în tranzit ar face comparația de mai sus să pice pentru un motiv
    care n-are nimic de-a face cu nginx."""
    for name in TEMPLATES:
        assert b"\r" not in (GOLDEN_DIR / name).read_bytes(), f"{name} are CR"
        assert b"\r" not in (NGINX_DIR / f"{name}.tmpl").read_bytes()
