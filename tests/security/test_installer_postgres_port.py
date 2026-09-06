"""5432 nu se presupune niciodată — se citește de pe mașină.

Măsurat pe un Ubuntu 24.04.4 curat care rulează deja n8n în Docker: `dpkg -l`
nu arăta niciun pachet `postgresql`, dar `ss -ltn` arăta `0.0.0.0:5432` ȘI
`[::]:5432` în LISTEN — publicate de un container. Instalatorul vechi nu
citea niciodată portul: `sentinel/config.py` avea `database.port = 5432`
implicit, iar `step_postgres` nici măcar nu se uita la el. Două drumuri, și
amândouă rupte:

  1. clusterul nou încearcă să lege 5432, `EADDRINUSE`, iar
     `systemctl enable --now postgresql` pică — instalarea moare la pasul 22;
  2. `pg_createcluster` al Debian-ului alege singur portul liber următor
     (5433), clusterul pornește curat, iar Sentinel se conectează la 5432 —
     baza de date a lui n8n, cu acreditări greșite — și moare mai târziu, la
     pasul 28 (`sentinel migrate`).

Fișierul de față rulează codul LIVRAT din `deploy/lib/common.sh`,
`deploy/lib/distro.sh` și `deploy/install.sh` — nu o reimplementare a lui —
exact ca tests/security/test_installer_debian_paths.py, ale cărui unelte
(`_func`, `_stub`, `_run`) sunt reosite aici neschimbate.

Nicăieri nu se folosește `ss` sau `/proc` reale: mediul de test nu are
niciuna dintre ele (Windows/git-bash). În loc, `port_free`, `port_owner` și
`port_owner_unit` — punctele unde codul livrat ATINGE kernelul — sunt
umbrite cu funcții shell care citesc o stare controlată de test, exact cum
`docker_server_version_as` e testat aiurea în acest fișier prin `docker`
momeală, nu prin daemonul real.

A doua rundă: `pg_ensure_listening` chema DOAR `enable --now`, niciodată
`restart`. Pe un unit deja activ `enable --now` nu face nimic — chiar rândul
din CLAUDE.md despre bug-ul ăsta — deci un `postgresql.conf` rescris de
`--db-port` sub un cluster deja pornit (pachetul Debian pornește clusterul
la pasul 20; pasul 22 îl găsește mereu activ) nu era observat niciodată.
Momeala `systemctl` de mai jos e acum ONESTĂ în privința asta: `enable`
NU repornește un unit deja activ, doar `restart` o face — exact semantica
reală — ca să nu ascundă din nou defectul pe care l-a ascuns prima oară.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DISTRO_SH = REPO / "deploy" / "lib" / "distro.sh"
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
DISTRO = DISTRO_SH.read_text(encoding="utf-8")
COMMON = COMMON_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
_NO_BASH = "bash lipsește din PATH — funcțiile din deploy/ NU au fost rulate."
pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


# ---------------------------------------------------------------------------
# Unelte — copiate neschimbate din test_installer_debian_paths.py
# ---------------------------------------------------------------------------
def _func(source: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _run(script: str, tmp_path: Path, extra_path: Path | None = None,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    path = tmp_path / "harness.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    environ = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        environ["PATH"] = (str(extra_path).replace("\\", "/") + os.pathsep
                           + environ.get("PATH", ""))
    if env:
        environ.update(env)
    return subprocess.run(
        [BASH, str(path).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


def _distro_call(tmp_path: Path, family: str, call: str,
                 extra_path: Path | None = None) -> subprocess.CompletedProcess:
    return _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        f"{call}\n",
        tmp_path, extra_path=extra_path)


def _write_conf(pgconf: Path, port_line: str | None) -> None:
    pgconf.mkdir(parents=True, exist_ok=True)
    body = "listen_addresses = '127.0.0.1'\n"
    if port_line is not None:
        body += port_line + "\n"
    (pgconf / "postgresql.conf").write_text(body, encoding="utf-8", newline="\n")


def _include_dir_guard() -> str:
    """Extrage cele două linii LIVRATE (grep + echo) din corpul lui
    step_postgres, nu o retranscriere — exact motivul pentru care garda veche
    a rămas neverificată."""
    body = _func(INSTALL, "step_postgres")
    start = body.index('grep -qE "^[[:space:]]*include_dir')
    end = body.index('postgresql.conf"\n', start) + len('postgresql.conf"')
    snippet = body[start:end]
    assert "echo \"include_dir = 'conf.d'\"" in snippet
    return snippet


def _conn_check_snippet() -> str:
    """Extrage verificarea finală de conectare (psql -h 127.0.0.1 ...) din
    corpul lui step_postgres — codul LIVRAT, nu o retranscriere."""
    body = _func(INSTALL, "step_postgres")
    start = body.index('local conn_err conn_out')
    end = body.index('(verified)"', start) + len('(verified)"')
    snippet = body[start:end]
    assert 'psql -h 127.0.0.1' in snippet
    return snippet


# ---------------------------------------------------------------------------
# --db-port — refuzat înainte ca postgresql.conf să fie atins
#
# Vechiul regex, `^[0-9]+$`, accepta orice șir de cifre: 0, 70000, un port
# sub 1024 (PostgreSQL nu rulează ca root, deci n-ar lega-o niciodată) — toate
# treceau de validare, iar eșecul apărea abia în step_postgres, DUPĂ ce
# postgresql.conf fusese deja rescris. Verificatorul a măsurat exact asta cu
# `DB_PORT_OVERRIDE=70000`: portul scris în fișier, clusterul oprit, nimic
# repornit pe portul vechi.
#
# Runda 2 a verificatorului a găsit ALTE două găuri, tot cu dovadă măsurată:
# `^[0-9]{1,5}$` accepta zerouri la stânga — "05432" trece de validare, dar
# step_postgres și pg_wait_listening îl compară ca ȘIR cu ce raportează `ss`
# ("5432", niciodată "05432"), deci un port perfect valid ar fi luat drumul
# de restore-and-recover degeaba (măsurat cu `iproute2-6.17.0`: `ss -tlnH
# "sport = :05432"` nu potrivește un socket real ascultând pe 5432). Și
# limita de 5 cifre, luată separat de verificarea de interval, nu era
# niciodată exercitată de o valoare care chiar dă peste cap — testul vechi
# folosea un șir de 20 de nouă care rămâne în afara intervalului și după ce
# `(( ))` îl evaluează, deci era refuzat oricum de verificarea de interval,
# nu de limita de lungime.
#
# Runda 4 a verificatorului a găsit a treia gaură, MĂSURATĂ pe gazda de
# producție (bash 5.1.8 / glibc 2.34 / LANG=en_US.UTF-8): `[0-9]` într-un
# `[[ =~ ]]` acolo e o clasă de colaționare pe LOCALE, nu un interval de
# octeți — admite cifre fullwidth (１２３ …) și indo-arabe (١٢٣ …). Regexul
# le lăsa să treacă, iar `(( 10#$v ... ))` arunca o eroare de sintaxă
# aritmetică pe ele — eroare pe care `||` o citea IDENTIC cu "fals", deci ca
# "nu-i în afara intervalului": ACCEPTED, măsurat cu rc=0 pe gazdă. Blocul
# livrat acum: (1) rulează comparația sub LC_ALL=C într-un subshell, ca
# regexul să însemne exact octeții ASCII, indiferent de LANG-ul procesului
# care pornește instalarea; (2) inversează lanțul — acceptarea cere TOATĂ
# conjuncția `&&` (regex ȘI aritmetică), nu doar absența unui refuz `||` — ca
# o eroare aritmetică să nu mai poată fi confundată cu un "fals" curat.
# Testele de mai jos verifică ambele, separat: seria de valori bune/rele de
# mai jos rulează blocul livrat neatins; cea de sub, cu regexul deliberat
# lărgit ca să simuleze exact gaura de colaționare măsurată pe gazdă, verifică
# doar conjuncția `&&` — proprietatea care nu depinde de locale-ul cu care
# rulează pytest aici (msys), unde cifrele fullwidth oricum n-ar trece de
# `[0-9]`, deci n-ar dovedi nimic despre gazdă.
# ---------------------------------------------------------------------------
def _db_port_validation_snippet() -> str:
    """Extrage blocul de validare LIVRAT din install.sh — funcția
    `_db_port_is_usable` plus `if`-ul care o apelează — nu o retranscriere.
    Poziția lui în fișier (înaintea lui need_root și a pasului 22) e dovedită
    separat, prin index, în
    test_db_port_validation_runs_before_need_root_and_before_step_22."""
    start = INSTALL.index("_db_port_is_usable() {")
    end = INSTALL.index("\nfi\n", start) + len("\nfi")
    snippet = INSTALL[start:end]
    assert "1024" in snippet and "65535" in snippet and "LC_ALL=C" in snippet
    return snippet


@pytest.mark.parametrize("bad_port", [
    "0",                       # cerința explicită: zero nu e niciodată o cerere validă
    "80",                      # sub 1024 — PostgreSQL nu rulează ca root
    "1023",                    # limita de jos, exclusă
    "70000",                   # EXACT valoarea cu care a lucrat verificatorul
    "65536",                   # limita de sus, cu unu peste
    "abc",                     # nenumeric — comportamentul vechi, păstrat
    "05432",                   # zero la stânga — 5432 e valid, dar STRING-ul nu e "5432"
    "01024",                   # aceeași gaură la limita de jos a intervalului
    "99999999999999999999",    # foarte lung — refuzat oricum de verificarea de interval
    "18446744073709557048",    # măsurat: `(( ))` îl evaluează la 5432 — ÎN interval, tăcut
])
def test_db_port_validation_refuses_unusable_values_before_anything_is_written(tmp_path, bad_port):
    """Niciuna dintre valorile astea n-are cum să asculte vreodată pe gazda
    reală. Rulează blocul LIVRAT (nu o reimplementare): dacă refuză, `die` a
    fost apelat înainte ca vreo comandă din script să fi atins un fișier —
    blocul de mai jos nu conține nicio scriere, deci un refuz aici e prin
    construcție un refuz dinainte de orice atingere a lui postgresql.conf."""
    script = (
        'die() { printf "DIE:%s\\n" "$*" >&2; exit 1; }\n'
        f'DB_PORT_OVERRIDE="{bad_port}"\n'
        + _db_port_validation_snippet() + "\n"
        "echo ACCEPTED\n"
    )
    proc = _run(script, tmp_path)
    assert proc.returncode != 0, proc.stdout
    assert "ACCEPTED" not in proc.stdout
    assert "DIE:" in proc.stderr, proc.stderr


@pytest.mark.parametrize("good_port", ["1024", "5432", "5433", "65535"])
def test_db_port_validation_accepts_the_usable_range(tmp_path, good_port):
    """Nicio schimbare de comportament pentru un port pe care clusterul chiar
    poate să-l lege — 5432 și 5433 sunt valorile reale văzute pe gazdele
    existente."""
    script = (
        'die() { printf "DIE:%s\\n" "$*" >&2; exit 1; }\n'
        f'DB_PORT_OVERRIDE="{good_port}"\n'
        + _db_port_validation_snippet() + "\n"
        "echo ACCEPTED\n"
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "ACCEPTED" in proc.stdout


# ---------------------------------------------------------------------------
# Runda 4: conjuncția `&&` refuză, nu doar absența unui refuz `||`.
#
# Nu se poate reproduce local (msys) gaura de colaționare pe care a măsurat-o
# verificatorul pe gazdă: acolo, cifrele fullwidth/indo-arabe NU trec de
# `[0-9]` sub NICIUN locale disponibil aici, deci un test parametrizat cu
# "５４３２" ar ieși verde din motivul GREȘIT — n-ar dovedi nimic despre
# gazdă, exact avertismentul din raport. Ce SE poate dovedi local, și e
# proprietatea care contează independent de locale: dacă o valoare reușește
# totuși să treacă de verificarea de caracter, aritmetica tot refuză, nu
# acceptă tăcut o eroare ca pe un "fals" curat.
#
# `_db_port_is_usable_WIDENED_REGEX` ia funcția LIVRATĂ și-i lărgește DOAR
# regexul (`^[1-9][0-9]{3,4}$` → `^.+$`) — simulează exact gaura măsurată pe
# gazdă, unde caracterul de netrecut ajunge oricum la `(( ))`. Restul
# funcției (LC_ALL=C, subshell-ul, conjuncția `&&`) rămâne NEATINS. Dacă
# blocul livrat ar fi tot cu vechiul `||`, testul ăsta ar arăta ACCEPTED —
# vezi falsificarea din raport, unde exact asta s-a văzut cu forma veche.
# ---------------------------------------------------------------------------
def _db_port_is_usable_widened_regex() -> str:
    """Funcția LIVRATĂ `_db_port_is_usable`, cu regexul de caractere înlocuit
    cu `.+` — simulează gaura de colaționare măsurată pe gazdă (un caracter
    care nu e cifră ASCII, dar trece de verificarea de caracter), ca să
    izoleze proprietatea care nu depinde de locale-ul de aici: conjuncția
    `&&` refuză o valoare pe care aritmetica n-o poate evalua curat."""
    func = _func(INSTALL, "_db_port_is_usable")
    original = '[[ "$v" =~ ^[1-9][0-9]{3,4}$ ]]'
    widened = '[[ "$v" =~ ^.+$ ]]'
    assert original in func, "regexul de caractere nu mai are forma așteptată"
    widened_func = func.replace(original, widened)
    assert widened_func != func and widened in widened_func
    return widened_func


@pytest.mark.parametrize("hole_value", [
    "५४३२",   # cifre Devanagari — orice glif ne-ASCII care ar trece de un `.+`
    "----",   # orice altceva care nu e deloc numeric
])
def test_db_port_arithmetic_rejects_a_value_that_survives_a_widened_character_check(
        tmp_path, hole_value):
    """Dacă VREUN caracter din afara ASCII 0-9 ar reuși cumva să treacă de
    verificarea de caracter (regexul lărgit de mai sus simulează exact asta),
    conjuncția `&&` LIVRATĂ tot refuză: `(( 10#$v ... ))` nu poate evalua
    curat un caracter care nu e cifră, eroarea iese pe stderr, iar funcția
    întoarce fals. Cu forma VECHE (`||`), aceeași eroare era citită ca „nu-i
    în afara intervalului" și valoarea trecea — asta e bug-ul măsurat pe
    gazdă, reprodus aici prin regexul lărgit, nu prin locale."""
    script = (
        'die() { printf "DIE:%s\\n" "$*" >&2; exit 1; }\n'
        + _db_port_is_usable_widened_regex() + "\n"
        f'if _db_port_is_usable "{hole_value}"; then echo ACCEPTED; else echo REJECTED; fi\n'
    )
    proc = _run(script, tmp_path)
    assert "REJECTED" in proc.stdout, \
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "ACCEPTED" not in proc.stdout


def test_db_port_arithmetic_still_accepts_a_real_port_through_the_widened_check(tmp_path):
    """Contra-proba: regexul lărgit nu trebuie să strice și cazul bun — un
    port ASCII real tot trece, fiindcă aritmetica pe el chiar e curată. Fără
    testul ăsta, un `&&` scris greșit ar putea refuza TOTUL, nu doar gaura,
    și n-ar fi prins."""
    script = (
        'die() { printf "DIE:%s\\n" "$*" >&2; exit 1; }\n'
        + _db_port_is_usable_widened_regex() + "\n"
        'if _db_port_is_usable "5432"; then echo ACCEPTED; else echo REJECTED; fi\n'
    )
    proc = _run(script, tmp_path)
    assert "ACCEPTED" in proc.stdout, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"


def test_db_port_validation_runs_before_need_root_and_before_step_22():
    """Nu doar comportamentul, ci și LOCUL lui în fișier: un refuz care ar
    ajunge după `need_root` sau după pasul 22 ar însemna că instalarea a
    apucat deja să ceară privilegii de root sau să scrie ceva pe gazdă
    înainte de a descoperi că portul cerut e inutilizabil."""
    start = INSTALL.index("_db_port_is_usable() {")
    need_root_at = INSTALL.index("\nneed_root\n")
    step22_at = INSTALL.index("run_step 22 postgres")
    assert start < need_root_at < step22_at


# ---------------------------------------------------------------------------
# pg_configured_port — citit de pe mașină, nu presupus
# ---------------------------------------------------------------------------
def test_debian_asks_pg_lsclusters_not_the_config_file(tmp_path):
    """`pg_createcluster` scrie portul ȘI în postgresql.conf, dar
    `pg_lsclusters` e unealta pe care Debian însuși o folosește ca să
    răspundă la întrebarea asta — testul dovedește că el câștigă, nu grep-ul,
    plantând valori DIFERITE în cele două locuri."""
    pgconf = tmp_path / "etc" / "postgresql" / "16" / "main"
    _write_conf(pgconf, "port = 5432")  # valoare veche, greșită, în fișier
    binpath = tmp_path / "bin"
    _stub(binpath, "pg_lsclusters",
          'printf "Ver Cluster Port Status Owner Data-directory Log-file\\n"\n'
          'printf "16  main   5433 online postgres /var/lib/postgresql/16/main log\\n"\n')
    proc = _distro_call(
        tmp_path, "debian",
        f'pg_configured_port "{str(pgconf).replace(chr(92), "/")}"',
        extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "5433"


def test_debian_falls_back_to_the_config_file_without_the_tool(tmp_path):
    """`pg_lsclusters` lipsește de pe un host — nu ar trebui, dar dacă lipsește
    tot trebuie să existe un răspuns, nu o coajă goală care ajunge la 5432."""
    pgconf = tmp_path / "etc" / "postgresql" / "16" / "main"
    _write_conf(pgconf, "port = 5433")
    proc = _distro_call(
        tmp_path, "debian",
        f'pg_configured_port "{str(pgconf).replace(chr(92), "/")}"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "5433"


def test_rhel_reads_the_uncommented_line(tmp_path):
    """Constanta istorică: AlmaLinux nu are pg_lsclusters, deci ramura aia nu
    se atinge niciodată — un singur fișier de citit."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5555")
    proc = _distro_call(
        tmp_path, "rhel", f'pg_configured_port "{str(pgconf).replace(chr(92), "/")}"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "5555"


@pytest.mark.parametrize("port_line", ["#port = 5432", None])
def test_an_unset_or_commented_port_defaults_to_5432(tmp_path, port_line):
    """Comportamentul care păzește gazda AlmaLinux de producție: acolo linia
    `port` e comentată (implicitul din compilare), și tot ce iese de aici
    trebuie să rămână 5432 — fără schimbare de comportament."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, port_line)
    proc = _distro_call(
        tmp_path, "rhel", f'pg_configured_port "{str(pgconf).replace(chr(92), "/")}"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "5432"


# ---------------------------------------------------------------------------
# pg_set_port — scrierea, idempotentă
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("initial,expected_line", [
    ("port = 5432", "port = 5433"),
    ("#port = 5432                # (change requires restart)", "port = 5433"),
])
def test_pg_set_port_replaces_the_existing_line(tmp_path, initial, expected_line):
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, initial)
    proc = _distro_call(
        tmp_path, "rhel",
        f'pg_set_port "{str(pgconf).replace(chr(92), "/")}" 5433')
    assert proc.returncode == 0, proc.stderr
    text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert expected_line in text
    assert text.count("port") == 1, f"linie duplicată: {text!r}"


def test_pg_set_port_appends_when_the_key_is_entirely_absent(tmp_path):
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, None)
    proc = _distro_call(
        tmp_path, "rhel",
        f'pg_set_port "{str(pgconf).replace(chr(92), "/")}" 5433')
    assert proc.returncode == 0, proc.stderr
    assert "port = 5433" in (pgconf / "postgresql.conf").read_text(encoding="utf-8")


def test_pg_set_port_is_idempotent_across_reruns(tmp_path):
    """--force-step 22 rulat de două ori cu ACELAȘI --db-port nu are voie să
    lase două linii `port` — a doua ar câștiga pe ambiguitate, nu pe intenție."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5432")
    call = (f'pg_set_port "{str(pgconf).replace(chr(92), "/")}" 5433; '
            f'pg_set_port "{str(pgconf).replace(chr(92), "/")}" 5433')
    proc = _distro_call(tmp_path, "rhel", call)
    assert proc.returncode == 0, proc.stderr
    text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert text.count("port = 5433") == 1, text


# ---------------------------------------------------------------------------
# pg_pick_free_port
# ---------------------------------------------------------------------------
def _with_port_free_override(occupied: set[int]) -> str:
    """O redefinire a lui port_free, DUPĂ sursă, care nu atinge `ss`."""
    literal = " ".join(str(p) for p in occupied)
    return (
        f'OCCUPIED=({literal})\n'
        'port_free() {\n'
        '    local p="$1" o\n'
        '    for o in "${OCCUPIED[@]}"; do [[ "$o" == "$p" ]] && return 1; done\n'
        '    return 0\n'
        '}\n'
    )


def test_pick_free_port_skips_everything_occupied(tmp_path):
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        + _with_port_free_override({5433, 5434, 5435})
        + 'pg_pick_free_port 5432\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "5436"


def test_pick_free_port_gives_up_rather_than_loop_forever(tmp_path):
    """Fiecare port din fereastra scanată e ocupat: funcția trebuie să
    RENUNȚE (cod de ieșire diferit de zero), nu să întoarcă o valoare
    inventată care s-ar putea nimeri tot ocupată."""
    occupied = set(range(5433, 5433 + 25))
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        + _with_port_free_override(occupied)
        + 'pg_pick_free_port 5432 && echo PICKED || echo GAVE_UP\n'
    )
    proc = _run(script, tmp_path)
    assert "GAVE_UP" in proc.stdout
    assert "PICKED" not in proc.stdout


# ---------------------------------------------------------------------------
# pg_port_owned_by_postgres — proprietate, nu doar "ocupat"
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("unit,expected", [
    ("postgresql.service", True),          # RHEL: o singură unitate
    ("postgresql@16-main.service", True),  # Debian: unitate per-cluster
    ("docker.service", False),             # exact cazul măsurat: un container
    ("", False),                           # necunoscut — NU „presupus al nostru"
])
def test_ownership_is_read_from_the_cgroup_not_guessed(tmp_path, unit, expected):
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        f'port_owner_unit() {{ printf "%s\\n" "{unit}"; }}\n'
        'if pg_port_owned_by_postgres 5432; then echo true; else echo false; fi\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ("true" if expected else "false")


def test_a_process_named_postgres_in_a_docker_scope_is_not_ours(tmp_path):
    """Măsurat pe ținta Ubuntu: procesul care ține 5432 se numește chiar
    "postgres" (o imagine `postgres:16-alpine` cu `--network host`), dar
    cgroup-ul lui e `/system.slice/docker-<id>.scope`, nu un `.service` — sub
    driverul de cgroup al systemd, Docker plasează containerele în `.scope`.

    Rulează lanțul REAL, `cgroup_unit` livrat inclus (nu doar `port_owner_unit`
    momit cu un șir scris de mână ca în testul de mai sus): dacă verificarea
    ar fi ținută de numele procesului, cazul ăsta ar ieși "al nostru" greșit."""
    cgroup_line = "0::/system.slice/docker-4f2a9c1e8b3d6a7e5f0c9b8a7d6e5f4c.scope"
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        f'port_owner_unit() {{ printf "%s" "{cgroup_line}" | cgroup_unit; }}\n'
        # numele procesului e chiar "postgres" — dacă decizia s-ar uita la EL
        # (nu la cgroup), cazul ăsta ar ieși greșit "al nostru".
        'port_owner() { printf "postgres"; }\n'
        'if pg_port_owned_by_postgres 5432; then echo true; else echo false; fi\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "false", \
        "un container cu procesul numit \"postgres\" a fost considerat clusterul nostru"


# ---------------------------------------------------------------------------
# pg_wait_listening — un port „nu mai e liber" nu e dovadă că e AL NOSTRU
# ---------------------------------------------------------------------------
def test_wait_listening_returns_at_once_when_already_owned(tmp_path):
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        'port_free() { return 1; }\n'
        'pg_port_owned_by_postgres() { return 0; }\n'
        'time0=$SECONDS\n'
        'pg_wait_listening 5432 5\n'
        'echo "waited=$((SECONDS - time0))"\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "waited=0" in proc.stdout, proc.stdout


def test_wait_listening_does_not_mistake_a_strangers_port_for_success(tmp_path):
    """ACESTA e testul central al fișierului. Portul e ocupat (nu e liber) TOT
    timpul, dar niciodată de PostgreSQL — exact starea unui container Docker
    care publică 5432. O implementare care verifică doar `! port_free` (fără
    proprietate) ar raporta succes aici, iar Sentinel s-ar conecta la baza de
    date a altcuiva."""
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        'port_free() { return 1; }\n'                 # mereu „ocupat"
        'pg_port_owned_by_postgres() { return 1; }\n'  # niciodată al nostru
        'pg_wait_listening 5432 2\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode != 0, \
        "un port ocupat de altcineva a fost raportat ca ascultat de PostgreSQL"


def test_wait_listening_times_out_when_the_port_stays_free(tmp_path):
    """Portul rămâne liber pentru totdeauna: serviciul chiar n-a pornit, și
    funcția nu are voie să aștepte la infinit sau să inventeze un succes."""
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n"
        'port_free() { return 0; }\n'
        'pg_port_owned_by_postgres() { return 1; }\n'
        'pg_wait_listening 5432 2\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode != 0


# Rundă anterioară avea aici `test_falsified_ownership_check_is_caught`: un
# test care redefinea `pg_wait_listening` STRICAT, local, chiar în test, și
# afirma că varianta stricată reușește. Asta verifică harnașul de test, nu
# codul livrat — nu poate pica niciodată pe o regresie reală, fiindcă
# "varianta stricată" trăiește doar în acest fișier. Falsificarea reală a
# proprietății e deja `test_wait_listening_does_not_mistake_a_strangers_port_
# for_success` de mai sus, care rulează `pg_wait_listening` LIVRATĂ.


# ---------------------------------------------------------------------------
# pg_restore_to — un fișier restaurat nu e o bază de date restaurată
#
# Rundele anterioare rescriau postgresql.conf înapoi pe portul vechi la un
# eșec și se opreau acolo — dovada era o LINIE din fișier, niciodată un socket
# ascultat. Un cluster care nu mai pornea din NICIUN motiv (nu doar portul
# cerut) rămânea oprit sub o configurație care „arăta" corectă. Testele de
# mai jos rulează `pg_restore_to` LIVRATĂ, cu o momeală `systemctl` ONESTĂ:
# `restart` OPREȘTE întâi legarea curentă (fișierul `bound` e golit), apoi o
# reface DOAR dacă portul din postgresql.conf e cel pe care clusterul chiar
# poate să-l lege — spre deosebire de vechea momeală optimistă din alte
# teste ale acestui fișier, care lăsa legarea veche neatinsă indiferent de
# ce se cerea și ar fi ascuns exact defectul ăsta.
# ---------------------------------------------------------------------------
def _honest_restart_stub(binpath: Path, calls: Path, bound: Path, pgconf_posix: str,
                          bindable_port: str) -> None:
    """`restart` OPREȘTE (bound golit) apoi PORNEȘTE doar dacă postgresql.conf
    cere exact `bindable_port` — un restart real nu lasă legarea veche pe loc
    doar pentru că cea nouă a eșuat."""
    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
cur="$(grep -E '^port' "{pgconf_posix}/postgresql.conf" | tail -1 | grep -oE '[0-9]+')"
case "$1" in
    enable)
        [ -s "{bound.as_posix()}" ] && exit 0
        [ "$cur" = "{bindable_port}" ] && printf '%s\\n' "$cur" > "{bound.as_posix()}"
        ;;
    restart)
        : > "{bound.as_posix()}"
        [ "$cur" = "{bindable_port}" ] && printf '%s\\n' "$cur" > "{bound.as_posix()}"
        ;;
esac
exit 0
""")


def _pg_restore_to_harness(tmp_path: Path, *, written_port: str, bindable_port: str
                           ) -> tuple[subprocess.CompletedProcess, Path, Path]:
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, f"port = {written_port}")
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    bound = tmp_path / "bound-port"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound.write_text("", encoding="utf-8", newline="\n")
    _honest_restart_stub(binpath, calls, bound, pgconf_posix, bindable_port)

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        f'pg_restore_to "{pgconf_posix}" 5433 1 && echo RECOVERED || echo FAILED\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    return proc, pgconf, bound


def test_pg_restore_to_confirms_a_real_bind_not_just_the_config_write(tmp_path):
    """5433 e chiar portul pe care clusterul ONEST poate să-l lege — restart
    real, legare reală. Dovada nu e doar `port = 5433` în fișier, ci fișierul
    `bound` (socketul simulat) arătând, la final, chiar 5433."""
    proc, pgconf, bound = _pg_restore_to_harness(
        tmp_path, written_port="5440", bindable_port="5433")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RECOVERED" in proc.stdout, proc.stdout
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5433") == 1
    assert bound.read_text(encoding="utf-8").strip() == "5433"


def test_pg_restore_to_reports_failure_when_the_restart_does_not_rebind(tmp_path):
    """Clusterul e stricat pentru un motiv NELEGAT de port (WAL corupt, disc
    plin) — nici portul vechi nu se mai leagă. `pg_restore_to` trebuie să
    întoarcă eșec, nu succes doar fiindcă a scris fișierul corect: config-ul
    corect și serviciul oprit sunt DOUĂ fapte diferite, iar apelantul are
    nevoie să le distingă ca să nu raporteze o recuperare care n-a avut loc."""
    proc, pgconf, bound = _pg_restore_to_harness(
        tmp_path, written_port="5440", bindable_port="")  # nimic nu se leagă, niciodată
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAILED" in proc.stdout, proc.stdout
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5433") == 1, \
        "fișierul trebuie restaurat chiar dacă legarea reală eșuează"
    assert bound.read_text(encoding="utf-8").strip() == "", \
        "pg_restore_to a raportat succes fără niciun socket ascultat pe portul restaurat"


def test_pg_restore_to_is_a_noop_when_the_cluster_never_left_the_previous_port(tmp_path):
    """Cerința „worth fixing" a raportului rundei 2: când portul cerut
    EXPLICIT era ținut de un străin, calea principală din pg_ensure_listening
    refuză corect să repornească (un străin ține portul și după un restart) —
    deci clusterul nostru poate fi tot timpul, neatins, pe restore_port când
    ajunge aici. `pg_restore_to` nu are voie să-l repornească doar ca să
    confirme ce e deja adevărat: măsurat, o repornire aici înseamnă câteva
    secunde de indisponibilitate a bazei de producție pentru nimic. Momeala e
    ONESTĂ (`_honest_restart_stub`), deci un `restart` care CHIAR a avut loc
    ar apărea în jurnalul `calls` la fel ca în celelalte teste din secțiunea
    asta — absența lui e dovada, nu o presupunere."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5440")  # step_postgres scrisese deja ținta cerută explicit
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    bound = tmp_path / "bound-port"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound.write_text("5433", encoding="utf-8", newline="\n")  # clusterul, NEATINS, tot pe 5433
    _honest_restart_stub(binpath, calls, bound, pgconf_posix, bindable_port="5433")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        f'pg_restore_to "{pgconf_posix}" 5433 1 && echo RECOVERED || echo FAILED\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RECOVERED" in proc.stdout, proc.stdout
    assert "restart" not in calls.read_text(encoding="utf-8"), \
        "clusterul era deja pe portul vechi — o repornire aici e indisponibilitate degeaba"
    assert bound.read_text(encoding="utf-8").strip() == "5433"
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5433") == 1


# ---------------------------------------------------------------------------
# pg_ensure_listening — integrare: repararea reală, capăt la capăt
# ---------------------------------------------------------------------------
def _ensure_listening_harness(tmp_path: Path, *, occupied_at_5432: bool,
                              explicit: str = "") -> tuple[subprocess.CompletedProcess, Path, Path]:
    """Rulează `pg_ensure_listening` LIVRATĂ, cu `systemctl` momeală care
    „pornește" clusterul doar dacă portul curent din postgresql.conf nu e
    5432-ocupat-de-altceva — simulând exact conflictul măsurat: un container
    deja pe 5432, fără niciun pachet postgresql instalat.

    `port_free` și `port_owner_unit` — singurele puncte unde codul livrat
    ar atinge `ss`/`/proc` — sunt umbrite cu funcții shell care citesc
    fișierele de stare scrise mai jos, în loc de kernel.
    """
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5432")
    pgconf_posix = str(pgconf).replace("\\", "/")

    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    listening = tmp_path / "listening-port"
    active = tmp_path / "unit-active"
    calls.write_text("", encoding="utf-8", newline="\n")

    # "1"/"" citit direct de scriptul bash de mai jos — nicio ramificare de
    # text construită din partea Python, ca să nu existe o a doua limbă de
    # citit atunci când ceva nu se potrivește.
    occupied_flag = "1" if occupied_at_5432 else ""

    # ONESTĂ, cerința 3 a rundei a doua: `enable` NU repornește un unit deja
    # activ — exact ca `systemctl` real — doar `restart` recitește
    # postgresql.conf. Niciunul din testele care folosesc harnașul ăsta nu
    # pornesc cu unitatea deja activă (toate simulează o primă instalare), deci
    # onestitatea asta nu le schimbă comportamentul așteptat — doar nu mai
    # ascunde defectul pe care vechea momeală (`enable|restart` tratate identic)
    # l-a ascuns prima oară.
    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
cur="$(grep -E '^port' "{pgconf_posix}/postgresql.conf" | tail -1 | grep -oE '[0-9]+')"
case "$1" in
    enable)
        [ -s "{active.as_posix()}" ] && exit 0   # deja activ: enable --now nu face nimic
        if [[ "$cur" == "5432" && -n "{occupied_flag}" ]]; then
            exit 0   # 5432 e al altcuiva — nu se leagă nimic, port rămâne neascultat
        fi
        printf '%s\\n' "$cur" > "{listening.as_posix()}"
        printf 1 > "{active.as_posix()}"
        ;;
    restart)
        if [[ "$cur" == "5432" && -n "{occupied_flag}" ]]; then
            rm -f "{listening.as_posix()}"
            exit 0
        fi
        printf '%s\\n' "$cur" > "{listening.as_posix()}"
        printf 1 > "{active.as_posix()}"
        ;;
esac
exit 0
""")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'LISTENING_FILE="{listening.as_posix()}"\n'
        f'OCCUPIED_5432="{occupied_flag}"\n'
        'port_free() {\n'
        '    local p="$1"\n'
        '    [[ "$p" == "5432" && -n "$OCCUPIED_5432" ]] && return 1\n'
        '    [[ -f "$LISTENING_FILE" && "$(cat "$LISTENING_FILE")" == "$p" ]] && return 1\n'
        '    return 0\n'
        '}\n'
        'port_owner_unit() {\n'
        '    local p="$1"\n'
        '    if [[ "$p" == "5432" && -n "$OCCUPIED_5432" ]]; then\n'
        '        printf "docker.service"; return\n'
        '    fi\n'
        '    if [[ -f "$LISTENING_FILE" && "$(cat "$LISTENING_FILE")" == "$p" ]]; then\n'
        '        printf "postgresql@16-main.service"\n'
        '    fi\n'
        '}\n'
        'port_owner() { printf "container/other"; }\n'
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        # timeout scurtat la 1s: doar viteza testului, comportamentul livrat
        # e neschimbat — pg_ensure_listening ia asta ca al 4-lea argument opțional.
        f'pg_ensure_listening "{pgconf_posix}" 5432 "{explicit}" 1\n'
        'printf "RESOLVED=%s\\n" "$PG_RESOLVED_PORT"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    return proc, calls, pgconf


def test_a_port_taken_by_something_else_moves_the_cluster_and_verifies(tmp_path):
    """Scenariul întreg măsurat: 5432 e ocupat de altceva decât PostgreSQL
    (`dpkg -l` fără niciun pachet postgresql, `ss` cu 5432 în LISTEN).
    Clusterul trebuie mutat pe un port liber, iar mutarea trebuie DOVEDITĂ —
    nu doar cerută — înainte ca funcția să se întoarcă."""
    proc, calls, pgconf = _ensure_listening_harness(tmp_path, occupied_at_5432=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESOLVED=5433" in proc.stdout, proc.stdout
    conf_text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert "port = 5433" in conf_text
    call_text = calls.read_text(encoding="utf-8")
    assert "enable" in call_text and "restart" in call_text


def test_an_explicit_db_port_conflict_is_refused_not_silently_moved(tmp_path):
    """Cerința 4: `--db-port` explicit care nu poate fi respectat e o EROARE,
    nu o sugestie tăcută de alt port. Un operator care a cerut 5432 pentru un
    motiv anume nu trebuie să afle abia la `sentinel migrate` că a primit alt
    port."""
    proc, calls, pgconf = _ensure_listening_harness(
        tmp_path, occupied_at_5432=True, explicit="1")
    assert proc.returncode != 0, proc.stdout
    assert "restart" not in calls.read_text(encoding="utf-8"), \
        "a încercat să mute portul deși era o cerere explicită"
    conf_text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert "port = 5432" in conf_text, "portul a fost schimbat deși cererea era explicită"


def test_no_conflict_leaves_almalinux_untouched(tmp_path):
    """Nicio schimbare de comportament pe gazda AlmaLinux de producție: 5432 e
    liber, clusterul pornește pe el din prima, și NU se cere niciun `restart`
    și niciun `pg_set_port` — exact ce se întâmpla înainte de reparația asta."""
    proc, calls, pgconf = _ensure_listening_harness(tmp_path, occupied_at_5432=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESOLVED=5432" in proc.stdout, proc.stdout
    call_text = calls.read_text(encoding="utf-8")
    assert "restart" not in call_text, "a repornit deși nu era niciun conflict"
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5432") == 1


def test_a_rerun_after_the_repair_converges_on_the_same_port(tmp_path):
    """Cerința 5: `--force-step 22` a doua oară nu are voie să aleagă alt
    port. postgresql.conf poartă deja rezultatul reparației anterioare
    (5433); clusterul e deja acolo. A doua trecere trebuie să confirme
    5433 din prima încercare, fără să mai repornească nimic."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5433")  # starea LĂSATĂ de o rulare anterioară
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
exit 0
""")
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        # deja ascultă pe 5433, deținut de clusterul nostru — steady state.
        'port_free() { [[ "$1" == "5433" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$1" == "5433" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        # PG_LISTEN_TIMEOUT_S livrat trăiește AFARA funcției, deci nu vine
        # odată cu `_func` — setat aici ca să nu pice pe "unbound variable"
        # sub `set -u`; production o are deja definită la sursă.
        'PG_LISTEN_TIMEOUT_S=15\n'
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        f'pg_ensure_listening "{pgconf_posix}" 5433 ""\n'
        'printf "RESOLVED=%s\\n" "$PG_RESOLVED_PORT"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESOLVED=5433" in proc.stdout, proc.stdout
    assert "restart" not in calls.read_text(encoding="utf-8")


def test_explicit_db_port_restarts_a_cluster_already_active_on_the_old_port(tmp_path):
    """Reproducerea EXACTĂ a verificatorului rundei 1: clusterul e deja ACTIV
    pe 5433 înainte de acest apel — postinst-ul Debian pornește clusterul la
    pasul 20, deci pasul 22 îl găsește mereu pornit — iar operatorul cere
    `--db-port 5440`. `enable --now` pe un unit deja activ nu face nimic
    (chiar exemplul din CLAUDE.md pentru bug-ul ăsta), deci doar un `restart`
    poate face clusterul să observe portul nou din postgresql.conf.

    Codul rundei 1 apela DOAR `enable --now` și murea la primul eșec al lui
    `pg_wait_listening`, fără să încerce vreodată `restart`."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5433")  # configurat ȘI ACTIV deja, dinaintea acestui apel
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound = tmp_path / "bound-port"
    bound.write_text("5433", encoding="utf-8", newline="\n")  # ce ascultă REALMENTE clusterul

    # Momeală onestă: `enable` nu repornește niciodată un unit deja activ
    # (starea de mai sus ÎL arată deja activ pe 5433); doar `restart`
    # recitește postgresql.conf și mută legarea reală.
    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
case "$1" in
    restart)
        cur="$(grep -E '^port' "{pgconf_posix}/postgresql.conf" | tail -1 | grep -oE '[0-9]+')"
        printf '%s\\n' "$cur" > "{bound.as_posix()}"
        ;;
esac
exit 0
""")
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        # step_postgres rescrie postgresql.conf ÎNAINTE să cheme
        # pg_ensure_listening — exact ce (nu) făcea corect runda 1.
        f'pg_set_port "{pgconf_posix}" 5440\n'
        # timeout scurtat la 1s, ca la celelalte teste din secțiunea asta.
        f'pg_ensure_listening "{pgconf_posix}" 5440 "1" 1 5433\n'
        'printf "RESOLVED=%s\\n" "$PG_RESOLVED_PORT"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESOLVED=5440" in proc.stdout, proc.stdout
    assert "restart" in calls.read_text(encoding="utf-8"), \
        "nu a încercat niciodată restart — enable --now nu poate repune un unit deja activ"
    assert bound.read_text(encoding="utf-8").strip() == "5440"
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5440") == 1


def test_explicit_db_port_failure_restores_the_previous_port_line(tmp_path):
    """Cerința 2: dacă tot nu ajunge să asculte pe portul cerut, postgresql.conf
    nu are voie să rămână scris pe un port pe care clusterul NU e — un die()
    care lasă configurația așa e exact bomba cu ceas din CLAUDE.md: clusterul
    s-ar muta acolo singur la următoarea repornire neasociată, cât timp
    sentinel.yaml tot mai zice portul vechi."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5433")
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    _stub(binpath, "systemctl", "exit 0\n")  # nimic nu se leagă vreodată, orice-ar fi
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'port_free() { return 0; }\n'          # 5440 rămâne mereu liber — nimic nu pornește
        'port_owner_unit() { printf ""; }\n'
        'port_owner() { printf ""; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        f'pg_set_port "{pgconf_posix}" 5440\n'
        'pg_ensure_listening '
        f'"{pgconf_posix}" 5440 "1" 1 5433 || true\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode != 0
    text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert "port = 5433" in text, \
        f"portul vechi n-a fost restaurat după eșec: {text!r}"
    assert text.count("port =") == 1, f"linie duplicată după restaurare: {text!r}"
    assert "PostgreSQL is DOWN" in proc.stderr, \
        "port_free() întoarce mereu adevărat aici — restaurarea nu poate lega nimic, " \
        "deci mesajul trebuie să spună răspicat că baza a rămas oprită, nu doar că " \
        "fișierul a fost pus înapoi"


# ---------------------------------------------------------------------------
# Cerința 2 a acestei rapoarte: un fișier restaurat nu e o bază repornită.
# Aceleași două scenarii ca mai sus (pg_restore_to), dar prin
# `pg_ensure_listening` ÎNTREGĂ — dovada care contează pentru operator e
# mesajul die() pe care-l vede, nu funcția izolată.
# ---------------------------------------------------------------------------
def test_explicit_db_port_failure_recovers_the_cluster_onto_the_previous_port(tmp_path):
    """Scenariul din raportul verificatorului, cu o momeală `systemctl` ONESTĂ
    (restart chiar oprește legarea veche înainte s-o refacă — spre deosebire
    de test_step_postgres_die_restores_the_port_when_the_cluster_never_
    rebinds, a cărei momeală ține 5433 legat orice s-ar chema): clusterul e
    deja activ pe 5433, operatorul tastează greșit --db-port 5440, portul nou
    nu se leagă NICIODATĂ, dar 5433 tot poate — deci baza trebuie să rămână
    (sau să redevină) ACCESIBILĂ, nu doar cu fișierul pus la loc."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5440")  # step_postgres a rescris-o deja când apelează
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    bound = tmp_path / "bound-port"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound.write_text("5433", encoding="utf-8", newline="\n")  # activ pe 5433 înainte de acest apel
    _honest_restart_stub(binpath, calls, bound, pgconf_posix, bindable_port="5433")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        f'pg_ensure_listening "{pgconf_posix}" 5440 "1" 1 5433 || true\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode != 0, proc.stdout  # cererea EXPLICITĂ tot eșuează — 5440 n-a mers
    assert "back on the previous port 5433" in proc.stderr, proc.stderr
    assert "DOWN" not in proc.stderr, proc.stderr
    assert bound.read_text(encoding="utf-8").strip() == "5433", \
        "cererea a eșuat, dar clusterul trebuia să rămână ascultat pe portul vechi — " \
        "dovada e un socket, nu doar o linie din postgresql.conf"
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5433") == 1


def test_explicit_db_port_failure_and_recovery_both_fail_says_database_is_down(tmp_path):
    """Contra-exemplul: clusterul nu mai pornește pe NICIUN port — un motiv
    nelegat de --db-port (WAL corupt, disc plin). Mesajul nu are voie să
    sugereze că portul vechi a revenit doar fiindcă fișierul arată corect;
    asta e exact confuzia pe care CLAUDE.md o numește „confirmarea intenției
    în locul efectului"."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5440")
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    bound = tmp_path / "bound-port"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound.write_text("5433", encoding="utf-8", newline="\n")
    _honest_restart_stub(binpath, calls, bound, pgconf_posix, bindable_port="")  # nimic nu se leagă

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        f'pg_ensure_listening "{pgconf_posix}" 5440 "1" 1 5433 || true\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode != 0, proc.stdout
    assert "PostgreSQL is DOWN" in proc.stderr, proc.stderr
    # Fapta observabilă contează, iar aici sunt DOUĂ fapte diferite: fișierul
    # e corect, socketul nu există. Mesajul trebuie să le distingă, nu doar
    # fișierul.
    assert (pgconf / "postgresql.conf").read_text(encoding="utf-8").count("port = 5433") == 1


# ---------------------------------------------------------------------------
# Cerința 3 a raportului rundei 2: al DOILEA drum de moarte din
# pg_ensure_listening — cel fără --db-port explicit, când portul ȚINTĂ e al
# unui străin și pg_pick_free_port mută clusterul singur — apelează
# pg_restore_to la fel ca primul, dar nimic din testele de mai sus nu-l
# rulează: un `test_pg_restore_to_is_wired_into_both_die_paths` bazat pe
# regex vede APELUL, nu dacă REZULTATUL lui ajunge în mesajul die().
# Aceleași două scenarii ca la calea explicită, pe acest drum.
# ---------------------------------------------------------------------------
def _auto_move_failure_harness(tmp_path: Path, *, recovers: bool
                               ) -> tuple[subprocess.CompletedProcess, Path, Path]:
    """5432 e ținut PERMANENT de un străin — un container fără niciun pachet
    postgresql instalat, nu clusterul nostru — deci `pg_pick_free_port` alege
    automat 5433. Clusterul nu poate lega NICIUN port nou (WAL corupt, disc
    plin): 5433 nu se leagă niciodată, indiferent de `recovers`. 5544 e portul
    pe care clusterul chiar rula, sănătos, ÎNAINTE ca acest apel să atingă
    ceva; `recovers` alege dacă acel port vechi mai poate fi legat la
    restaurare sau dacă e stricat și el."""
    pgconf = tmp_path / "pgdata"
    _write_conf(pgconf, "port = 5432")  # ținta pe care step_postgres o dorea
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    bound = tmp_path / "bound-port"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound.write_text("5544", encoding="utf-8", newline="\n")  # activ, sănătos, ÎNAINTE de acest apel
    bindable_port = "5544" if recovers else ""
    _honest_restart_stub(binpath, calls, bound, pgconf_posix, bindable_port)

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() {\n'
        '    [[ "$1" == "5432" ]] && return 1\n'   # străinul ține 5432, PERMANENT
        '    [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1\n'
        '    return 0\n'
        '}\n'
        'port_owner_unit() {\n'
        '    [[ "$1" == "5432" ]] && { printf "docker.service"; return; }\n'
        '    [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"\n'
        '}\n'
        'port_owner() { printf "container/other"; }\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        f'pg_ensure_listening "{pgconf_posix}" 5432 "" 1 5544 || true\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    return proc, calls, bound


def test_auto_move_failure_recovers_the_cluster_onto_the_previous_port(tmp_path):
    """Mutarea automată (fără --db-port) poate eșua la fel de bine ca cea
    explicită — 5432 e al unui străin, 5433 (portul ales automat de
    pg_pick_free_port) nu se leagă NICIODATĂ — iar acest al doilea die()
    trebuie să încerce ACELAȘI drum de recuperare ca primul, nu doar să
    scrie fișierul înapoi și să declare victorie fără niciun socket."""
    proc, calls, bound = _auto_move_failure_harness(tmp_path, recovers=True)
    assert proc.returncode != 0, proc.stdout  # mutarea automată tot a eșuat
    assert "back on the previous port 5544" in proc.stderr, proc.stderr
    assert "DOWN" not in proc.stderr, proc.stderr
    assert bound.read_text(encoding="utf-8").strip() == "5544", \
        "clusterul trebuia să rămână (sau să redevină) ascultat pe portul vechi — " \
        "dovada e un socket, nu doar o linie din postgresql.conf"
    pgconf_text = (tmp_path / "pgdata" / "postgresql.conf").read_text(encoding="utf-8")
    assert pgconf_text.count("port = 5544") == 1, pgconf_text


def test_auto_move_failure_and_recovery_both_fail_says_database_is_down(tmp_path):
    """Contra-exemplul pe același drum: nici portul vechi nu se mai leagă —
    mesajul trebuie să spună răspicat că baza a rămas oprită, nu să sugereze
    o recuperare care n-a avut loc doar fiindcă fișierul arată corect."""
    proc, calls, bound = _auto_move_failure_harness(tmp_path, recovers=False)
    assert proc.returncode != 0, proc.stdout
    assert "PostgreSQL is DOWN" in proc.stderr, proc.stderr
    assert bound.read_text(encoding="utf-8").strip() == "", \
        "niciun socket n-a rămas ascultat — mesajul n-are voie să pretindă recuperare"
    assert bound.read_text(encoding="utf-8").strip() == "", \
        "niciun socket real n-a rămas ascultat, dar testul a găsit unul"


def test_pg_restore_to_is_wired_into_both_die_paths_of_pg_ensure_listening():
    """Firul, nu doar comportamentul dintr-un singur scenariu: `pg_ensure_
    listening` are DOUĂ locuri unde poate muri cu un `restore_port` în mână
    — cererea explicită respinsă, și mutarea automată pe un port liber care
    nici ea nu ajunge să asculte. Ambele trebuie să treacă prin recuperarea
    reală, nu doar unul dintre ele."""
    body = _func(INSTALL, "pg_ensure_listening")
    calls = re.findall(r'pg_restore_to "', body)
    assert len(calls) == 2, \
        f"pg_restore_to e CHEMATĂ de {len(calls)} ori, nu 2 — " \
        "una dintre cele două căi de eșec a rămas cu restaurare doar de fișier"


# ---------------------------------------------------------------------------
# Firul: portul rezolvat de pasul 22 ajunge, neschimbat, în sentinel.yaml
# ---------------------------------------------------------------------------
def test_step_configs_refuses_to_guess_when_postgres_never_ran(tmp_path):
    """Dacă cineva rulează `--from-step 26` pe o gazdă unde pasul 22 n-a scris
    NICIODATĂ un cluster, `database.port` nu are voie să iasă „5432" din
    tăcere — exact modul de eșec pe care CLAUDE.md îl numește. Rulează
    GUARDA reală din `step_configs` (nu doar caută textul ei), oprind-o
    exact acolo unde `pg_confdir` arată spre un director care nu conține
    niciun `postgresql.conf` — cazul unei gazde pe care pasul 22 n-a rulat."""
    missing = tmp_path / "no-such-pgdata"
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="rhel"\n'
        'SCAN_CONTAINERS=false\n'  # trece prima gardă, ca să ajungă la a doua
        f'pg_confdir() {{ printf "%s\\n" "{missing.as_posix()}"; }}\n'
        + _func(INSTALL, "step_configs") + "\n"
        "step_configs\n"
    )
    proc = _run(script, tmp_path)
    assert proc.returncode != 0, proc.stdout
    assert "step 22" in proc.stderr and "postgres" in proc.stderr, proc.stderr
    # Și dovada negativă: garda n-are voie să treacă mai departe și să scrie
    # un sentinel.yaml — chiar dacă ar apuca s-o facă undeva-n /tmp implicit.
    assert not any(tmp_path.rglob("sentinel.yaml"))


def test_the_template_no_longer_hardcodes_5432():
    tmpl = (REPO / "deploy" / "config" / "sentinel.yaml.tmpl").read_text(encoding="utf-8")
    assert "port: @@DB_PORT@@" in tmpl
    assert re.search(r"^\s*port:\s*5432\s*$", tmpl, re.M) is None
    assert "s|@@DB_PORT@@|" in _func(INSTALL, "step_configs")


def test_tuning_conf_no_longer_fixes_the_port():
    """`include_dir 'conf.d'` e adăugat la SFÂRȘITUL lui postgresql.conf, deci
    sentinel-tuning.conf e citit ULTIMUL — o valoare `port` fixă acolo ar
    câștiga peste orice scrie step_postgres direct în postgresql.conf și ar
    anula toată reparația asta în tăcere."""
    tuning = (REPO / "deploy" / "postgres" / "sentinel-tuning.conf").read_text(encoding="utf-8")
    assert re.search(r"^\s*port\s*=", tuning, re.M) is None, \
        "sentinel-tuning.conf fixează din nou portul — ar anula step_postgres"


def test_include_dir_guard_is_idempotent_across_reruns(tmp_path):
    """Garda trebuie să se potrivească cu ce SCRIE mai jos, altfel nu se
    potrivește NICIODATĂ și fiecare `--force-step 22` mai adaugă o copie —
    măsurat pe gazda de producție ca patru linii `include_dir = 'conf.d'`
    identice, la rândurile 826-829. Rulează cele două linii LIVRATE
    (`_include_dir_guard`), de două ori la rând, ca un `--force-step 22`
    repetat."""
    snippet = _include_dir_guard()
    pgconf = tmp_path / "pgdata"
    pgconf.mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text(
        "listen_addresses = '127.0.0.1'\n", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")
    script = (
        "set -euo pipefail\n"
        f'pgconf="{pgconf_posix}"\n'
        + snippet + "\n"
        + snippet + "\n"  # a doua rulare — --force-step 22 repetat
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stderr
    text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert text.count("include_dir") == 1, \
        f"garda a mai adăugat o copie la a doua rulare: {text!r}"


def test_db_port_flag_is_wired_into_the_step():
    """--db-port trebuie să ajungă efectiv în corpul pasului 22, nu doar
    parsat și ignorat — cinci ștergeri separate au lăsat exact așa un flag
    neconectat în trecutul acestui fișier (vezi test_force_step_list.py).

    Asta verifică doar că firul EXISTĂ textual; DECIZIA pe care firul o
    schimbă efectiv — că portul cerut chiar ajunge să fie cel pe care
    ascultă clusterul — e dovedită separat de
    test_step_postgres_restarts_to_pick_up_an_explicit_db_port, care rulează
    pasul 22 LIVRAT până la capăt."""
    assert re.search(r'--db-port\)\s*DB_PORT_OVERRIDE=', INSTALL)
    body = _func(INSTALL, "step_postgres")
    assert "DB_PORT_OVERRIDE" in body
    assert "pg_ensure_listening" in body


# ---------------------------------------------------------------------------
# step_postgres — integrare capăt la capăt, cu --db-port
# ---------------------------------------------------------------------------
def test_step_postgres_restarts_to_pick_up_an_explicit_db_port(tmp_path):
    """Rulează `step_postgres` LIVRAT — nu doar `pg_ensure_listening` izolat —
    pe scenariul măsurat: o primă instalare Debian unde postinst-ul pachetului
    (pasul 20) a pornit deja clusterul pe 5433 înainte ca pasul 22 să ruleze
    vreodată, iar operatorul a cerut `--db-port 5440`. `enable --now` e un
    no-op pe un unit deja activ; runda 1 apela doar atât și murea la
    `pg_wait_listening`, DUPĂ ce postgresql.conf fusese deja rescris — exact
    bomba cu ceas din raportul verificatorului."""
    pgconf = tmp_path / "pgdata"
    (pgconf / "conf.d").mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text("port = 5433\n", encoding="utf-8", newline="\n")
    (pgconf / "pg_hba.conf").write_text("", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")

    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound = tmp_path / "bound-port"
    bound.write_text("5433", encoding="utf-8", newline="\n")  # deja activ, dinainte de pasul 22

    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
case "$1" in
    restart)
        cur="$(grep -E '^port' "{pgconf_posix}/postgresql.conf" | tail -1 | grep -oE '[0-9]+')"
        printf '%s\\n' "$cur" > "{bound.as_posix()}"
        ;;
esac
exit 0
""")
    # sudo: doar înlătură "-u postgres" și execută restul — rolul lui aici
    # e să lase psql-ul momeală să primească argumentele reale.
    _stub(binpath, "sudo", '[ "$1" = "-u" ] && shift 2\nexec "$@"\n')
    _stub(binpath, "createdb", 'exit 0\n')
    # psql momeală: rol și bază de date „există" mereu (nu interesează firul
    # ăsta), iar verificarea finală de conectare succede DOAR dacă portul cu
    # care a fost chemat psql e portul pe care clusterul ASCULTĂ REALMENTE —
    # asta e dovada că step_postgres n-a scris un port pe care nu-l poate
    # atinge.
    _stub(binpath, "psql", f"""
port=""; query=""; prev=""
for a in "$@"; do
    [ "$prev" = "-p" ] && port="$a"
    [ "$prev" = "-tAc" ] && query="$a"
    prev="$a"
done
bound="$(cat "{bound.as_posix()}" 2>/dev/null || echo '')"
case "$query" in
    *pg_roles*|*pg_database*) printf '1\\n'; exit 0 ;;
    "SELECT 1")
        if [ "$port" = "$bound" ]; then printf '1\\n'; exit 0; fi
        exit 1 ;;
esac
cat >/dev/null   # CREATE/ALTER ROLE, primite pe stdin
exit 0
""")
    _stub(binpath, "install", '''
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -D) shift ;;
        -m|-o|-g) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
last=$((${#args[@]} - 1))
mkdir -p "$(dirname "${args[$last]}")"
[ "${#args[@]}" -ge 2 ] && cp "${args[0]}" "${args[$last]}"
exit 0
''')

    script = (
        "set -euo pipefail\n"
        f'SCRIPT_DIR="{(REPO / "deploy").as_posix()}"\n'
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        'declare -A SECRETS=( [SENTINEL_DB_PASSWORD]="testpw123" )\n'
        'DB_PORT_OVERRIDE="5440"\n'
        'PG_LISTEN_TIMEOUT_S=1\n'
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        f'pg_confdir() {{ printf "%s\\n" "{pgconf_posix}"; }}\n'
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        + _func(INSTALL, "step_postgres") + "\n"
        "step_postgres\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    conf_text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert conf_text.count("port = 5440") == 1, conf_text
    assert bound.read_text(encoding="utf-8").strip() == "5440", \
        "clusterul n-a ajuns niciodată să asculte pe portul cerut — enable --now nu poate repune un unit deja activ"
    assert "restart" in calls.read_text(encoding="utf-8")


def test_step_postgres_die_restores_the_port_when_the_cluster_never_rebinds(tmp_path):
    """Firul $pg_port_before -> pg_ensure_listening, dovedit prin PASUL 22
    LIVRAT, nu prin apelul direct al lui pg_ensure_listening cu valoarea dată
    de test (asta face deja test_explicit_db_port_failure_restores_the_
    previous_port_line, și de-asta n-a prins regresia). Dacă cel de-al 5-lea
    argument s-ar pierde pe drum — `pg_ensure_listening ... "" ""` în loc de
    `... "" "$pg_port_before"` — step_postgres tot ar rescrie postgresql.conf
    pe 5440, dar la eșec n-ar mai avea ce restaura: bomba cu ceas din
    CLAUDE.md, clusterul rămas pe 5433 sub un fișier care zice 5440.

    Debian, clusterul deja activ pe 5433 (postinst-ul pachetului, pasul 20),
    operatorul cere --db-port 5440, iar `systemctl` momeală nu leagă
    NICIODATĂ portul nou (nici la enable, nici la restart) — clusterul
    rămâne pe 5433 orice s-ar chema."""
    pgconf = tmp_path / "pgdata"
    (pgconf / "conf.d").mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text("port = 5433\n", encoding="utf-8", newline="\n")
    (pgconf / "pg_hba.conf").write_text("", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")

    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    bound = tmp_path / "bound-port"
    bound.write_text("5433", encoding="utf-8", newline="\n")  # nu se mișcă NICIODATĂ

    # Momeală care nu leagă nimic nicăieri: doar loghează chemarea și iese 0 —
    # exact `systemctl reload nginx` din CLAUDE.md, semnalul trimis, nimic
    # aplicat. bound-port nu e atins de niciun caz.
    _stub(binpath, "systemctl", f"""
printf '%s\\n' "$*" >> "{calls.as_posix()}"
exit 0
""")
    _stub(binpath, "install", '''
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -D) shift ;;
        -m|-o|-g) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
last=$((${#args[@]} - 1))
mkdir -p "$(dirname "${args[$last]}")"
[ "${#args[@]}" -ge 2 ] && cp "${args[0]}" "${args[$last]}"
exit 0
''')

    script = (
        "set -euo pipefail\n"
        f'SCRIPT_DIR="{(REPO / "deploy").as_posix()}"\n'
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        'declare -A SECRETS=( [SENTINEL_DB_PASSWORD]="testpw123" )\n'
        'DB_PORT_OVERRIDE="5440"\n'
        'PG_LISTEN_TIMEOUT_S=1\n'
        f'BOUND_FILE="{bound.as_posix()}"\n'
        'port_free() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && return 1; return 0; }\n'
        'port_owner_unit() { [[ "$(cat "$BOUND_FILE")" == "$1" ]] && printf "postgresql@16-main.service"; }\n'
        'port_owner() { printf "postgres"; }\n'
        f'pg_confdir() {{ printf "%s\\n" "{pgconf_posix}"; }}\n'
        + _func(INSTALL, "pg_restore_to") + "\n"
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        + _func(INSTALL, "step_postgres") + "\n"
        "step_postgres\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "did not come up listening on --db-port 5440" in proc.stderr, proc.stderr
    conf_text = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    assert conf_text == "port = 5433\ninclude_dir = 'conf.d'\n", \
        f"portul dinainte de acest run n-a fost restaurat la eșec: {conf_text!r}"
    # Momeala asta ține 5433 „legat" indiferent ce cheamă systemctl — deci
    # pg_restore_to găsește clusterul deja acolo și raportează recuperare
    # reușită, nu bomba din CLAUDE.md. Cazul „nici portul vechi nu mai
    # revine" e dovedit separat, cu o momeală ONESTĂ (restart chiar oprește
    # legarea veche), de test_pg_restore_to_reports_failure_when_the_
    # restart_does_not_rebind și de test_explicit_db_port_failure_restores_
    # the_previous_port_line de mai sus.
    assert "back on the previous port 5433" in proc.stderr, proc.stderr


def test_connection_check_surfaces_psql_stderr_without_leaking_the_password(tmp_path):
    """Cerința 7: verificarea finală de conectare nu mai aruncă stderr-ul lui
    `psql` la /dev/null și nu mai trimite operatorul doar la `journalctl` —
    ăla e jurnalul SERVERULUI și n-are cum să poarte un refuz de pe partea
    CLIENTULUI. "no pg_hba.conf entry", "password authentication failed" și
    "connection refused" sunt trei reparații diferite; fără text, operatorul
    nu poate ști care. Rulează snippet-ul LIVRAT, nu o retranscriere, și
    verifică — separat — că parola însăși nu ajunge în mesaj."""
    snippet = _conn_check_snippet()
    binpath = tmp_path / "bin"
    _stub(binpath, "psql", '''
printf 'psql: error: connection to server at "127.0.0.1" failed: FATAL:  password authentication failed for user "sentinel"\\n' >&2
exit 1
''')
    # Snippet-ul e corpul unei funcții (folosește `local`), deci trebuie
    # rulat într-una — la fel ca step_postgres în celelalte teste de aici.
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        'pg_port="5432"\n'
        'db_password="s3cr3t-test-only-not-a-real-secret"\n'
        "run_check() {\n"
        + snippet + "\n"
        "}\n"
        "run_check\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode != 0
    assert "password authentication failed" in proc.stderr, proc.stderr
    assert "s3cr3t-test-only-not-a-real-secret" not in proc.stdout
    assert "s3cr3t-test-only-not-a-real-secret" not in proc.stderr


# ---------------------------------------------------------------------------
# -DbPort 0 / --db-port 0 — cei doi wrapperi, aceeași soartă
#
# `[int]$DbPort` implicit 0, iar `if ($DbPort)` e fals pe 0: `-DbPort 0` era
# scăpat tăcut, iar rularea continua ca și cum niciun port n-ar fi fost cerut
# — spre deosebire de deploy.sh, care trimite "0" mai departe și lasă
# install.sh (vezi testele de validare din capul acestui fișier) să-l
# refuze. Zero nu e niciodată o cerere validă, deci ambii wrapperi trebuie
# să REFUZE, nu doar unul.
# ---------------------------------------------------------------------------
DEPLOY_PS1 = REPO / "scripts" / "deploy.ps1"
DEPLOY_SH = REPO / "scripts" / "deploy.sh"
PS = shutil.which("pwsh") or shutil.which("powershell.exe")


@pytest.mark.skipif(PS is None, reason="no PowerShell available")
@pytest.mark.parametrize("bad_port", ["0", "80", "70000"])
def test_deploy_ps1_refuses_a_bad_db_port_before_touching_anything(bad_port):
    """Rulează SCRIPTUL livrat, nu o reimplementare a lui `param()`.
    Validarea PowerShell se întâmplă la LEGAREA parametrilor — înainte ca
    orice linie din corpul scriptului (ssh, sudo, tar) să ruleze — deci un
    -HostName inexistent nu contează aici: niciun apel de rețea nu are cum
    să pornească înaintea refuzului."""
    proc = subprocess.run(
        [PS, "-NoProfile", "-File", str(DEPLOY_PS1), "-HostName", "unused.invalid.example",
         "-DbPort", bad_port],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode != 0, proc.stdout
    assert "DbPort" in proc.stderr, proc.stderr


def test_deploy_ps1_declares_db_port_with_installs_own_range():
    """Verificare structurală, separată de comportament: intervalul din
    `ValidateRange` trebuie să fie EXACT 1024-65535 — cel din blocul de
    validare al lui install.sh (vezi testele de la începutul acestui
    fișier) — ca refuzul lui deploy.ps1 să cadă pe aceleași valori, nu pe un
    interval apropiat dar diferit."""
    text = DEPLOY_PS1.read_text(encoding="utf-8-sig")
    assert re.search(r"\[ValidateRange\(1024,\s*65535\)\]\s*\r?\n\s*\[int\]\$DbPort", text), \
        "ValidateRange lipsește sau nu mai poartă 1024-65535 lângă [int]$DbPort"


def _db_port_forward_line() -> str:
    """Linia LIVRATĂ din deploy.sh care construiește INSTALL_ARGS din
    --db-port — nu o retranscriere."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    match = re.search(
        r'^\[\[ -n "\$DB_PORT"\s*\]\] && INSTALL_ARGS\+=\(--db-port "\$DB_PORT"\)$',
        text, re.M)
    assert match, "linia de forward a --db-port nu mai arată așa în deploy.sh"
    return match.group(0)


def test_deploy_sh_forwards_db_port_zero_unfiltered_for_install_sh_to_refuse():
    """Spre deosebire de vechiul deploy.ps1 (`if ($DbPort)` fals pe 0, cerere
    scăpată tăcut), deploy.sh verifică doar absența șirului (`-n`) — "0" e
    un șir nevid și AJUNGE la install.sh, care acum îl refuză (vezi
    test_db_port_validation_refuses_unusable_values_before_anything_is_
    written[0] mai sus în acest fișier). Rulează linia LIVRATĂ, nu o
    retranscriere, ca dovadă că deploy.sh nu îl scapă tăcut înainte de asta."""
    line = _db_port_forward_line()
    proc = subprocess.run(
        [BASH, "-c", f'DB_PORT="0"; INSTALL_ARGS=(); {line}; '
                      'printf "%s\\n" "${INSTALL_ARGS[@]}"'],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["--db-port", "0"], proc.stdout
