"""Fiecare vulnerabilitate spune pe ce stă: sistem, container sau aplicație.

Operatorul a deschis pagina de vulnerabilități și a spus: „văd o listă fără să
le pot asocia". Datele erau deja acolo — `scanner` și `location` — dar pagina
tipărea numele intern al scanerului (`trivy_image`), care spune cum a fost
găsită constatarea, nu pe ce stă.

Fixturile de aici nu sunt inventate: sunt perechile (scaner, location) măsurate
pe cele două gazde la 21 septembrie 2026, inclusiv cazurile incomode —
`location` NULL pe cele 477 de constatări `dnf`, un nume gol de imagine fără tag
și fără slash (`traefik`, `bet-deploy-bet-alert-worker`), o cale cu spații în ea
(`dragos.nimu/BET calculator/bet-deploy/package-lock.json`) și o referință de
imagine care CONȚINE un slash fără să fie o cale (`snipe/snipe-it:latest`).
"""

from __future__ import annotations

import pytest

from sentinel.scan import os_packages, trivy_fs, trivy_image
from sentinel.scan.subject import (KIND_APP, KIND_CONTAINER, KIND_OS,
                                   KIND_UNKNOWN, categories, describe)

# Fiecare scaner care chiar scrie constatări azi, luat din modulul care îl
# numește, nu retastat aici. Dacă se adaugă o familie de distribuții, numele
# scanerului ei intră automat în listă și testul de mai jos cere ca pagina să
# știe ce să facă cu el.
KNOWN_SCANNERS = sorted({*os_packages.SCANNER_BY_FAMILY.values(),
                         os_packages.UNKNOWN_SCANNER,
                         trivy_fs.SCANNER, trivy_image.SCANNER})


def test_inventarul_de_scanere_nu_e_gol():
    """Un test parametrizat peste o listă goală trece fără să verifice nimic.

    Lista de mai jos vine din constantele altor module; dacă una dintre ele e
    redenumită sau golită, parametrizarea s-ar evapora tăcut și fiecare test
    care o folosește ar raporta succes fără să execute o singură aserțiune.
    """
    assert len(KNOWN_SCANNERS) >= 4
    assert "dnf" in KNOWN_SCANNERS and "apt" in KNOWN_SCANNERS
    assert "trivy_fs" in KNOWN_SCANNERS and "trivy_image" in KNOWN_SCANNERS


@pytest.mark.parametrize("scanner", KNOWN_SCANNERS)
def test_niciun_scaner_activ_nu_cade_in_necunoscut(scanner):
    """Un scaner care chiar produce rânduri, dar pe care clasificarea nu-l
    cunoaște, umple pagina cu „Necunoscut" — adică exact lista neasociată de
    care s-a plâns operatorul, doar cu alt cuvânt în coloană."""
    assert describe(scanner, None).kind != KIND_UNKNOWN


# ---------------------------------------------------------------------------
# Sistem de operare
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scanner", ["dnf", "apt", os_packages.UNKNOWN_SCANNER])
def test_pachetele_gazdei_se_numesc_sistem_de_operare(scanner):
    """Cele 477 de constatări `dnf` de pe producție sunt pachetele gazdei
    însăși, iar reparația lor e `dnf update` în fereastra de mentenanță — altă
    operație decât o reconstrucție de imagine. Confundate, operatorul repornește
    containerul greșit."""
    s = describe(scanner, None)
    assert s.kind == KIND_OS
    assert s.label == "Sistem de operare"


def test_scanerul_de_sistem_ramane_in_detaliu():
    """Coloana nu mai tipărește numele scanerului; dacă nu apare nici în
    `title`, informația a dispărut din pagină, nu s-a mutat."""
    assert describe("dnf", None).detail == "Scaner: dnf"


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("reference", [
    "mariadb:11.4.7",                 # 267 de constatări deschise, deb + go
    "postgres:16-alpine",
    "snipe/snipe-it:latest",          # slash, dar e o referință, nu o cale
    "docker.n8n.io/n8nio/n8n",        # registru + cale + nume, pe gazda Ubuntu
    "bet-deploy-bet-alert-worker",    # nume gol: fără tag, fără slash
    "traefik",
])
def test_containerul_isi_numeste_imaginea_intreaga(reference):
    """Reparația unei constatări de imagine e reconstrucția acelei imagini.
    Referința tăiată (tagul aruncat, registrul aruncat) face ca două imagini
    diferite să arate identic în pagină, iar operatorul reconstruiește alta."""
    s = describe("trivy_image", reference)
    assert s.kind == KIND_CONTAINER
    assert s.label == f"Container · {reference}"
    assert s.detail == f"Scaner: trivy_image · {reference}"


def test_imaginea_cu_slash_nu_e_citita_ca_o_cale():
    """`snipe/snipe-it:latest` are un slash, dar nu e un manifest de aplicație.
    Tratată ca o cale, ar apărea drept „snipe (snipe-it:latest)" — un nume de
    aplicație inexistent, pe care operatorul nu-l poate căuta nicăieri."""
    assert describe("trivy_image", "snipe/snipe-it:latest").label == (
        "Container · snipe/snipe-it:latest")


# ---------------------------------------------------------------------------
# Aplicație
# ---------------------------------------------------------------------------
def test_aplicatia_e_numita_scurt_nu_prin_calea_intreaga():
    """O cale de 56 de caractere într-o coloană de tabel nu e o asociere: e
    aceeași listă necitibilă, mutată. Numele directorului aplicației plus
    fișierul de manifest e ce poate căuta operatorul pe gazdă."""
    s = describe("trivy_fs", "html/phpMyAdmin/composer.lock")
    assert s.kind == KIND_APP
    assert s.label == "Aplicație · phpMyAdmin (composer.lock)"
    # Calea întreagă nu se pierde — se mută în `title`.
    assert s.detail == "Scaner: trivy_fs · html/phpMyAdmin/composer.lock"


def test_calea_cu_spatii_nu_rupe_numele_aplicatiei():
    """Calea reală de pe producție are un spațiu în ea („BET calculator"). O
    despărțire pe spații — sau pe orice altceva decât separatorul de cale — ar
    scoate un nume trunchiat pentru cele 64 de constatări npm de acolo."""
    s = describe("trivy_fs", "dragos.nimu/BET calculator/bet-deploy/package-lock.json")
    assert s.label == "Aplicație · bet-deploy (package-lock.json)"


def test_spatiul_din_chiar_numele_aplicatiei_nu_taie_eticheta():
    """Aceeași cale măsurată, cu manifestul un nivel mai sus.

    Testul de deasupra NU poate prinde o despărțire pe spații: spațiul lui stă
    într-un director strămoș, iar un `location.split()[-1]` naiv ar scoate
    exact aceeași etichetă — verificat, mutația trece netăiată. Aici „BET
    calculator" (nume real de director de pe producție) e chiar componenta care
    ajunge în etichetă, deci o despărțire pe spații ar afișa „calculator", o
    aplicație care nu există pe gazdă.
    """
    s = describe("trivy_fs", "dragos.nimu/BET calculator/package-lock.json")
    assert s.label == "Aplicație · BET calculator (package-lock.json)"


def test_calea_cu_contrabara_nu_ramane_intreaga_in_coloana():
    """Linia `location.replace("\\\\", "/")` din `_app_label`, ținută în viață.

    Nicio fixtură din restul suitei nu duce o contrabară, deci ștergerea liniei
    trecea nevăzută prin 5554 de teste — iar efectul ei e chiar problema pentru
    care există funcția: fără ea, eticheta redevine calea întreagă, de 39 de
    caractere, în coloană. Trivy poate raporta o astfel de cale dintr-o imagine
    de Windows sau dintr-un manifest copiat de pe o stație.
    """
    s = describe("trivy_fs", "C:\\inetpub\\wwwroot\\app\\composer.lock")
    assert s.label == "Aplicație · app (composer.lock)"
    # Calea brută nu se pierde: rămâne verbatim în `title`.
    assert s.detail == "Scaner: trivy_fs · C:\\inetpub\\wwwroot\\app\\composer.lock"


@pytest.mark.parametrize("location,expected", [
    # Calea absolută: componenta goală de la început nu devine numele aplicației.
    ("/var/www/procure360/composer.lock", "Aplicație · procure360 (composer.lock)"),
    # Un singur nivel: nu există director părinte de arătat, deci nu se inventează.
    ("composer.lock", "Aplicație · composer.lock"),
    # Relativă: „.." nu e numele unei aplicații.
    ("../bet-deploy/package-lock.json", "Aplicație · bet-deploy (package-lock.json)"),
    ("./package-lock.json", "Aplicație · package-lock.json"),
])
def test_forme_de_cale_care_nu_trebuie_sa_produca_un_nume_fals(location, expected):
    assert describe("trivy_fs", location).label == expected


# ---------------------------------------------------------------------------
# Ce nu se știe
# ---------------------------------------------------------------------------
def test_un_scaner_nou_nu_e_ghicit_ca_una_din_cele_trei():
    """Se vor adăuga scanere. Unul clasificat din inerție drept „Sistem de
    operare" e mai rău decât unul necunoscut: operatorul ar căuta pachetul pe
    gazdă și n-ar găsi nimic, fără să afle vreodată că pagina a ghicit."""
    s = describe("nessus", "10.30.1.248")
    assert s.kind == KIND_UNKNOWN
    assert "Sistem de operare" not in s.label
    assert "Container" not in s.label and "Aplicație" not in s.label
    # Valorile brute rămân vizibile: sunt singurul lucru pe care se mai poate
    # sprijini cineva când clasificarea nu are un răspuns.
    assert "nessus" in s.label and "10.30.1.248" in s.label


def test_scanerul_lipsa_nu_devine_o_categorie():
    s = describe(None, None)
    assert s.kind == KIND_UNKNOWN
    assert s.label == "Necunoscut · scaner nedeclarat"
    assert s.detail == "Scaner: nedeclarat"


@pytest.mark.parametrize("scanner,location,expected_kind,expected_label", [
    ("trivy_image", None, KIND_CONTAINER, "Container · imagine necunoscută"),
    ("trivy_image", "   ", KIND_CONTAINER, "Container · imagine necunoscută"),
    ("trivy_fs", None, KIND_APP, "Aplicație · cale necunoscută"),
    ("trivy_fs", "///", KIND_APP, "Aplicație · cale necunoscută"),
])
def test_locatia_lipsa_se_spune_nu_se_umple_cu_gol(scanner, location, expected_kind,
                                                   expected_label):
    """„Container · " urmat de nimic se citește ca o eroare de afișare, iar un
    operator care vede asta nu știe dacă lipsește imaginea sau pagina. Categoria
    rămâne cea corectă — scanerul o dă — dar lipsa se scrie cu litere."""
    s = describe(scanner, location)
    assert s.kind == expected_kind
    assert s.label == expected_label


def test_valorile_care_nu_sunt_text_nu_arunca():
    """`scanner` și `location` vin dintr-o bază unde ambele coloane sunt
    nullable și nevalidate. O excepție aici e un 500 pe toată pagina de
    vulnerabilități, nu o celulă goală."""
    s = describe(12345, object())
    assert s.kind == KIND_UNKNOWN
    assert s.label == "Necunoscut · scaner nedeclarat"


# ---------------------------------------------------------------------------
# Numărătoarea pe categorii — peste toate rândurile, nu peste pagină
# ---------------------------------------------------------------------------
# Recensământul deschis de pe gazda de producție, 21 septembrie 2026.
CENSUS = {"dnf": 477, "trivy_image": 486, "trivy_fs": 92}


def test_categoriile_aduna_recensamantul_real():
    """Suma pe categorii trebuie să fie chiar totalul deschis (1055). O
    categorie pierdută pe drum ar face ca pastilele să nu se adune la numărul
    din antet, iar operatorul care descoperă asta nu mai crede nici una, nici
    alta."""
    by_kind = {c.kind: c for c in categories(CENSUS)}
    assert by_kind[KIND_OS].count == 477
    assert by_kind[KIND_CONTAINER].count == 486
    assert by_kind[KIND_APP].count == 92
    assert by_kind[KIND_UNKNOWN].count == 0
    assert sum(c.count for c in categories(CENSUS)) == 1055


def test_categoria_poarta_scanerele_pe_care_le_numara():
    """Filtrul paginii se face pe lista asta. Dacă ea nu e chiar mulțimea
    numărată, pastila spune 477 și tabelul arată altceva."""
    by_kind = {c.kind: c for c in categories({**CENSUS, "apt": 3})}
    assert by_kind[KIND_OS].scanners == ("apt", "dnf")
    assert by_kind[KIND_OS].count == 480
    assert by_kind[KIND_CONTAINER].scanners == ("trivy_image",)
    assert by_kind[KIND_APP].scanners == ("trivy_fs",)


def test_o_categorie_fara_randuri_ramane_in_lista_pe_zero():
    """Gazda Ubuntu n-are decât `trivy_image`. „0 sistem de operare" e o
    măsurătoare; o categorie care dispare din listă e o pagină care tace, și
    tăcerea se citește ca „nu există nimic acolo"."""
    cats = {c.kind: c for c in categories({"trivy_image": 65})}
    assert cats[KIND_OS].count == 0 and cats[KIND_OS].scanners == ()
    assert cats[KIND_APP].count == 0
    assert cats[KIND_CONTAINER].count == 65


def test_un_scaner_neclasificat_se_numara_la_necunoscut_nu_dispare():
    """Un scaner nou nu are voie nici să fie ghicit, nici să se evapore din
    numărătoare: o constatare care nu apare nicăieri e o constatare pe care
    nimeni n-o repară."""
    cats = {c.kind: c for c in categories({"dnf": 10, "nessus": 4})}
    assert cats[KIND_UNKNOWN].count == 4
    assert cats[KIND_UNKNOWN].scanners == ("nessus",)
    assert sum(c.count for c in cats.values()) == 14


def test_scanerul_gol_nu_se_pierde_din_numaratoare():
    """`open_counts_by_scanner` traduce un `scanner` NULL în șirul gol. Trebuie
    să se numere undeva, iar singurul loc onest e „necunoscut"."""
    cats = {c.kind: c for c in categories({"": 2})}
    assert cats[KIND_UNKNOWN].count == 2


def test_ordinea_categoriilor_e_fixa():
    """Ordonate după numere, pastilele s-ar rearanja la fiecare scanare, iar
    operatorul ar căuta de fiecare dată unde s-a mutat categoria lui."""
    assert [c.kind for c in categories(CENSUS)] == [KIND_OS, KIND_CONTAINER,
                                                    KIND_APP, KIND_UNKNOWN]
