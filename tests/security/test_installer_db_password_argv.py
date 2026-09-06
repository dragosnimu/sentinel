"""Parola bazei de date nu are voie pe argv-ul niciunui proces pe care
`step_postgres` îl pornește.

Măsurat pe gazda de producție: `auditctl -l | grep -c execve` întoarce 7 —
șapte reguli execve încărcate — deci fiecare `execve()` e auditat, argv
inclus. Comentariul de deasupra celor două chemări `psql` din
`step_postgres` susținea că parola nu ajunge pe linia de comandă ("stdin
keeps the password off any command line where `ps` could show it"), dar codul
o punea acolo oricum: `-v pw="$db_password"` e chiar un argument, vizibil lui
`ps` ȘI regulii audit — două din cele șapte reguli sunt prinderi generale
(`-S execve -F auid!=-1 -F key=sentinel_cmd`, în variantă b64 și b32), deci
argv-ul ORICĂRUI proces pornit de un deploy e auditat prin construcție: orice
rulare a vechiului cod ar fi scris parola în audit.log, fără să fie nevoie de
o rulare anume ca dovadă. (O afirmație anterioară de aici, că o rulare din 4
septembrie 2026 a făcut exact asta, nu rezistă și e retrasă: singura
potrivire `pw=`/`70773D` din `audit.log.4` e propriul tipar de căutare al unui
`grep -c` de diagnostic, care s-a potrivit cu propria înregistrare execve;
jurnalul PostgreSQL nu arată niciun `CREATE ROLE`/`ALTER ROLE` în acea
fereastră. Exact tiparul pe care CLAUDE.md îl numește: un grep care s-a
potrivit doar cu el însuși.) Testele de aici dovedesc EFECTUL,
nu comentariul: capturează argv-ul
real primit de fiecare binar pe care `step_postgres` îl cheamă (`psql`,
`sudo`, `createdb`, `systemctl`, `install`) și cer ca parola să nu apară în
niciunul, pentru ambele ramuri — CREATE ROLE (rol inexistent) și ALTER ROLE
(rol existent, rotație de parolă).

Mecanismul livrat: parola ajunge la psql printr-o linie `\\set pw '...'`
pe ACELAȘI stdin ca instrucțiunea SQL, nu prin `-v`. `\\set`-ul psql își
parsează singur argumentul (backslash e caracter de escape într-un argument
între apostrofuri), deci `pg_psql_set_escape` din `deploy/lib/common.sh` face
dublarea de backslash ȘI escaparea apostrofului, ÎN ACEASTĂ ORDINE — inversat,
o parolă cu un backslash chiar înaintea unui apostrof (ex. `a\'b`) e
reconstruită greșit — NU una care doar se termină în backslash, care,
verificat manual pe un `psql` real, se comportă corect indiferent de ordine.
Asta a fost verificat manual, cu un `psql` real (container Docker, nu asumat) — vezi
comentariul funcției. Testele de aici nu au acces la un `psql` real (mediul e
Windows/git-bash), deci nu pot repeta verificarea aia; ele dovedesc doar ce
pot dovedi de aici: (1) parola nu ajunge niciodată pe argv, (2) funcția de
escapare produsă e cea corectă — verificată printr-un decodor Python care
oglindește gramatica `\\set` deja confirmată manual — pentru valori care ar
sparge o escapare naivă: apostrof, backslash, semnul dolarului.
"""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
COMMON = COMMON_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
_NO_BASH = "bash lipsește din PATH — funcțiile din deploy/ NU au fost rulate."
pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


# ---------------------------------------------------------------------------
# Unelte — aceleași ca în test_installer_postgres_port.py (copiate, nu
# importate: fiecare fișier din acest director rulează izolat, la fel cum
# comentariul din acela explică pentru originea lor în test_installer_debian_paths.py).
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


def _run(script: str, tmp_path: Path, extra_path: Path | None = None) -> subprocess.CompletedProcess:
    path = tmp_path / "harness.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    import os
    environ = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        environ["PATH"] = (str(extra_path).replace("\\", "/") + os.pathsep
                           + environ.get("PATH", ""))
    return subprocess.run(
        [BASH, str(path).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


# ---------------------------------------------------------------------------
# pg_psql_set_escape — funcția de escapare, izolat
# ---------------------------------------------------------------------------
def _decode_psql_set_single_quoted(escaped: str) -> tuple[str, str | None]:
    """Model al gramaticii `\\set`-ului psql pentru un argument între
    apostrofuri: backslash escapează fie apostroful, fie el însuși; orice alt
    caracter după backslash rămâne ca atare — ȘI, la fel ca psql-ul real, un
    apostrof NEescapat ÎNCHIDE argumentul chiar acolo, nu la capătul șirului.

    Asta din urmă e ce lipsea aici înainte: decodorul vechi mergea până la
    capăt indiferent, deci un apostrof scăpat neescapat de o escapare
    stricată (exact bug-ul pe care fișierul ăsta trebuie să-l prindă) era
    tratat ca literal și rezultatul se reconstruia corect din întâmplare —
    un `psql` real l-ar fi închis acolo, cu tot ce urmează căzut pe linia de
    comandă ca text nelegat de nimic. Confirmat manual, cu un `psql` real
    (Docker), pentru exact valorile pe care testele de mai jos le rulează
    prin el — nu o presupunere de aici.

    Întoarce (valoare_decodată, rest_după_apostroful_de_închidere); rest e
    None dacă șirul s-a terminat fără niciun apostrof neescapat, adică nimic
    nu l-ar fi închis mai devreme dacă ar fi fost pus el însuși între
    apostrofuri reale."""
    out = []
    i = 0
    while i < len(escaped):
        ch = escaped[i]
        if ch == "\\" and i + 1 < len(escaped):
            out.append(escaped[i + 1])
            i += 2
        elif ch == "'":
            return "".join(out), escaped[i + 1:]
        else:
            out.append(ch)
            i += 1
    return "".join(out), None


@pytest.mark.parametrize("pw", [
    "a'b\\c$d\"e f",              # apostrof, backslash, dolar, ghilimea, spatiu
    "abc\\",                       # backslash chiar inainte de apostroful de inchidere
    "pa$s",                        # doar semnul dolarului
    "trailing\\\\double",          # doi backslash consecutivi in mijloc
    "p\"'\\q",                     # ghilimea + apostrof + backslash-q, lipite
    "a\\'b",                       # backslash urmat imediat de apostrof — vezi testul de falsificare de mai jos
])
def test_set_escape_round_trips_through_psqls_own_quoting_grammar(tmp_path, pw):
    """Dacă escaparea nu dublează backslash-ul ÎNAINTE de a escapa apostroful,
    o parolă cu un backslash chiar înaintea unui apostrof e reconstruită
    GREȘIT de `\\set` — rolul se creează cu exit 0, dar cu o parolă diferită
    de cea cerută, iar autentificarea pică mai târziu, fără nicio legătură
    vizibilă cu această schimbare. Verificat manual, separat, cu un `psql`
    real, că exact acest model de decodare corespunde comportamentului
    serverului (vezi docstring-ul modulului)."""
    escaped = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f"pg_psql_set_escape {_bash_quote(pw)}\n",
        tmp_path,
    )
    assert escaped.returncode == 0, escaped.stderr
    # `pg_psql_set_escape` întoarce doar FRAGMENTUL dintre apostrofuri —
    # apostroful de închidere e adăugat de linia `\set pw '...'` din
    # step_postgres, nu de funcție. Fără el modelat aici, un backslash rămas
    # chiar la capătul fragmentului (bug-ul exact pe care o dublare de
    # backslash ștearsă îl produce) nu are ce să "mănânce" — decodorul îl
    # tratează ca literal, în loc să-l vadă escapând apostroful de închidere
    # real, și reconstruiește parola corect din întâmplare. Adăugăm apostroful
    # real, ca psql, și cerem ca el să închidă argumentul EXACT acolo (rest
    # gol) — nu mai devreme (apostrof neescapat în mijloc) și nu niciodată
    # (backslash agățat de capăt, fără rest deloc).
    decoded, remainder = _decode_psql_set_single_quoted(escaped.stdout + "'")
    assert remainder == "", (
        f"pw={pw!r} escaped={escaped.stdout!r} nu se închide exact la apostroful "
        f"pe care \\set chiar îl adaugă — rest={remainder!r} (None înseamnă că un "
        "backslash agățat de capăt a \"mâncat\" acel apostrof, deci un psql real "
        "ar raporta \"unterminated quoted string\"; un rest nevid înseamnă că "
        "argumentul s-a închis mai devreme, cu un apostrof neescapat în mijloc)"
    )
    assert decoded == pw, (
        f"pw={pw!r} escaped={escaped.stdout!r} nu se reconstruieste la valoarea originala"
    )


def _bash_quote(v: str) -> str:
    """Un literal bash single-quoted pentru orice valoare, ca argument de test
    trecut printr-o linie de shell — NU mecanismul testat, doar modul in care
    acest fisier de test isi transmite propriile fixture-uri catre bash."""
    return "'" + v.replace("'", "'\\''") + "'"


def test_broken_escaping_order_is_caught_by_the_round_trip_not_by_the_exit_code(tmp_path):
    """Falsificare directă: o versiune STRICATĂ (apostroful escapat înaintea
    backslash-ului) e exact eroarea pe care ordinea din comentariul funcției o
    numește — și `CREATE ROLE` tot raportează succes cu ea. Testul de mai sus
    trebuie să o prindă; ăsta dovedește CĂ o prinde, rulând intenționat varianta
    stricată."""
    # Șir RAW, ca backslash-ii de mai jos să ajungă în bash exact cum sunt
    # scriși — aceeași sintaxă ca pg_psql_set_escape livrată, cu cele două
    # linii INVERSATE.
    broken = r"""
pg_psql_set_escape_broken() {
    local v=$1
    v=${v//\'/\\\'}
    v=${v//\\/\\\\}
    printf '%s' "$v"
}
"""
    # backslash urmat imediat de apostrof: escaparea apostrofului introduce UN
    # backslash nou; dacă dublarea de backslash rulează DUPĂ (ordinea gresita),
    # dublează și backslash-ul nou-introdus, care nu mai corespunde la nimic
    # din valoarea originală — exact interacțiunea pe care ordinea corectă
    # (backslash întâi) o evită.
    pw = "a\\'b"
    proc = _run(
        "set -euo pipefail\n"
        + broken
        + f"pg_psql_set_escape_broken {_bash_quote(pw)}\n",
        tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    decoded, _remainder = _decode_psql_set_single_quoted(proc.stdout)
    assert decoded != pw, (
        "varianta STRICATA a reconstruit corect parola — testul de mai sus "
        "nu ar mai distinge o escapare gresita de una corecta"
    )


# ---------------------------------------------------------------------------
# step_postgres — argv-ul FIECĂRUI proces pornit, capturat, nu presupus
# ---------------------------------------------------------------------------
def _step_postgres_harness(tmp_path: Path, *, role_exists: bool, password: str):
    """Rulează `step_postgres` LIVRAT din install.sh, cu momeli pentru
    `psql`, `sudo`, `createdb`, `systemctl` și `install` care lolghează FIECARE
    linie de argv primită (nu doar cele pe care testul se așteaptă să le vadă)
    într-un singur fișier — dacă parola ar ajunge pe linia de comandă a
    ORICĂRUIA dintre ele, ar fi acolo."""
    pgconf = tmp_path / "pgdata"
    (pgconf / "conf.d").mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text("port = 5432\n", encoding="utf-8", newline="\n")
    (pgconf / "pg_hba.conf").write_text("", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")

    binpath = tmp_path / "bin"
    argv_log = tmp_path / "argv.log"
    stdin_log = tmp_path / "psql-stdin.log"
    argv_log.write_text("", encoding="utf-8", newline="\n")

    role_flag = "1" if role_exists else ""

    # sudo: doar înlătură "-u postgres" — argv-ul REAL trimis binarului țintă
    # e cel logat mai jos de fiecare momeală în parte, nu de sudo.
    _stub(binpath, "sudo",
          f'printf "sudo: %s\\n" "$*" >> "{argv_log.as_posix()}"\n'
          '[ "$1" = "-u" ] && shift 2\nexec "$@"\n')

    # psql: loghează argv-ul primit ȘI stdin-ul (separat, ca să nu se confunde
    # cele două canale) — stdin e UNDE parola are voie să călătorească.
    _stub(binpath, "psql", f"""
printf "psql: %s\\n" "$*" >> "{argv_log.as_posix()}"
query=""; prev=""
for a in "$@"; do
    [ "$prev" = "-tAc" ] && query="$a"
    prev="$a"
done
case "$query" in
    *pg_roles*)
        cat >/dev/null
        [ -n "{role_flag}" ] && printf '1\\n'
        exit 0 ;;
    *pg_database*)
        cat >/dev/null
        printf '1\\n'; exit 0 ;;
    "SELECT 1")
        cat >/dev/null
        printf '1\\n'; exit 0 ;;
esac
cat >> "{stdin_log.as_posix()}"
exit 0
""")
    _stub(binpath, "createdb",
          f'printf "createdb: %s\\n" "$*" >> "{argv_log.as_posix()}"\nexit 0\n')
    _stub(binpath, "systemctl",
          f'printf "systemctl: %s\\n" "$*" >> "{argv_log.as_posix()}"\nexit 0\n')
    _stub(binpath, "install", f'''
printf "install: %s\\n" "$*" >> "{argv_log.as_posix()}"
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -D) shift ;;
        -m|-o|-g) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
last=$((${{#args[@]}} - 1))
mkdir -p "$(dirname "${{args[$last]}}")"
[ "${{#args[@]}}" -ge 2 ] && cp "${{args[0]}}" "${{args[$last]}}"
exit 0
''')

    script = (
        "set -euo pipefail\n"
        f'SCRIPT_DIR="{(REPO / "deploy").as_posix()}"\n'
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        f'declare -A SECRETS=( [SENTINEL_DB_PASSWORD]={_bash_quote(password)} )\n'
        'DB_PORT_OVERRIDE=""\n'
        'PG_LISTEN_TIMEOUT_S=1\n'
        f'pg_confdir() {{ printf "%s\\n" "{pgconf_posix}"; }}\n'
        # port-ul e deja "ascultat" — nu ne interesează firul --db-port aici,
        # doar ca step_postgres să ajungă la blocul de rol/parolă.
        'port_free() { return 1; }\n'
        'pg_port_owned_by_postgres() { return 0; }\n'
        + _func(INSTALL, "pg_ensure_listening") + "\n"
        + _func(INSTALL, "step_postgres") + "\n"
        "step_postgres\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    return proc, argv_log, stdin_log


@pytest.mark.parametrize("role_exists", [False, True], ids=["create-role", "alter-role"])
def test_password_never_reaches_argv_of_any_spawned_process(tmp_path, role_exists):
    """Eșecul pe care îl previne: parola scrisă în audit.log la fiecare
    deploy. Rulează AMBELE ramuri — CREATE ROLE (instalare nouă) și ALTER
    ROLE (rotație de parolă, exact ce spune comentariul din
    deploy/lib/common.sh despre --force-step 22+27) — și verifică argv-ul
    logat de FIECARE binar pornit de step_postgres, nu doar de psql."""
    password = "a'b\\c$d\"e f"  # apostrof, backslash, dolar — cerute explicit
    proc, argv_log, stdin_log = _step_postgres_harness(
        tmp_path, role_exists=role_exists, password=password)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    argv_text = argv_log.read_text(encoding="utf-8")
    assert password not in argv_text, (
        f"parola a aparut in argv-ul unui proces pornit de step_postgres:\n{argv_text}"
    )
    # Şi dovada pozitivă: parola chiar a călătorit, doar pe stdin, nu în neant.
    stdin_text = stdin_log.read_text(encoding="utf-8") if stdin_log.exists() else ""
    marker = "\\set pw '"
    marker_at = stdin_text.find(marker)
    assert marker_at != -1, (
        f"nicio linie \\set nu a fost trimisă lui psql pe stdin:\n{stdin_text!r}"
    )
    # Decodăm direct din textul brut care urmează apostroful de deschidere,
    # NU dintr-un grup capturat de o regex lacomă `'(.*)'` — aia ar înghiți
    # orice apostrof neescapat din mijlocul parolei ca și cum ar fi parte din
    # valoare, exact ce ascundea lipsa escapării apostrofului (vezi
    # docstring-ul decoderului mai sus).
    decoded, remainder = _decode_psql_set_single_quoted(stdin_text[marker_at + len(marker):])
    assert decoded == password, (
        f"parola trimisă pe stdin nu se decodează la valoarea cerută: {decoded!r} != {password!r}"
    )
    # Nu ne oprim la "urmează o linie nouă" — asta dovedește doar unde se
    # închide apostroful, nimic despre ce vine DUPĂ. O instrucțiune SQL
    # lipsă cu totul, sau una care a pierdut cotarea `:'pw'` (psql ar citi
    # `:pw` ca literal necotat, nu ca interpolare), ar trece la fel de bine
    # pe lângă `startswith("\n")` — trebuie tot textul rămas pe stdin, nu un
    # prefix al lui.
    expected_tail = (
        "\nALTER ROLE sentinel PASSWORD :'pw';\n"
        if role_exists else
        "\nCREATE ROLE sentinel LOGIN PASSWORD :'pw';\n"
    )
    assert remainder == expected_tail, (
        "stdin-ul de după parolă nu e instrucțiunea SQL așteptată — fie lipsește "
        "CREATE/ALTER ROLE, fie a pierdut cotarea `:'pw'` (ambele raportează exit 0 "
        f"de la psql, dar rolul nu se creează/actualizează cum trebuie): {remainder!r} "
        f"!= {expected_tail!r}"
    )


def test_old_argv_mechanism_is_what_this_guards_against(tmp_path):
    """Falsificare: reintrodu explicit vechiul `-v pw=` (bug-ul măsurat) în
    harness — NU în install.sh — și confirmă că testul de mai sus L-AR FI
    PRINS. Dacă argv-ul nu conține parola nici și-n varianta stricată, testul
    nu verifică nimic."""
    password = "a'b\\c$d\"e f"
    binpath = tmp_path / "bin"
    argv_log = tmp_path / "argv.log"
    argv_log.write_text("", encoding="utf-8", newline="\n")
    _stub(binpath, "psql", f'printf "psql: %s\\n" "$*" >> "{argv_log.as_posix()}"\ncat >/dev/null\nexit 0\n')
    _stub(binpath, "sudo", '[ "$1" = "-u" ] && shift 2\nexec "$@"\n')
    script = (
        "set -euo pipefail\n"
        f'printf "CREATE ROLE sentinel LOGIN PASSWORD :\'pw\';\\n" | '
        f'sudo -u postgres psql -p 5432 -v ON_ERROR_STOP=1 -v pw={_bash_quote(password)} >/dev/null\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stderr
    argv_text = argv_log.read_text(encoding="utf-8")
    assert password in argv_text, (
        "harnasul de test nu mai detecteaza parola pe argv nici in varianta "
        "veche, stricata — testul principal nu ar prinde regresia"
    )
