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
