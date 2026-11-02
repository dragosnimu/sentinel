"""„N-am putut întreba `ss`" nu are voie să se scrie „portul e liber".

`port_free` din `deploy/lib/common.sh` era scris așa:

    ! ss -tlnH "sport = :$1" 2>/dev/null | grep -q . \\
        && ! ss -ulnH "sport = :$1" 2>/dev/null | grep -q .

Codul de ieșire al unei conducte e al ULTIMEI comenzi, deci un `ss` lipsă (127),
unul care refuză argumentul (1) sau unul oprit de politică ajungeau toate la
`grep -q .` fără nicio linie de intrare — adică exact la răspunsul „liber".
Eroarea pleca la /dev/null, iar rc-ul se pierdea în conductă.

Ce se strică pentru operator, în ordinea gravității:

  * `pg_ensure_listening` repornește PostgreSQL-ul de producție fiindcă
    „portul e liber, deci serviciul nu s-a legat", sau îl MUTĂ pe alt port
    fiindcă „portul e ținut de un străin" — o indisponibilitate a bazei sau o
    rescriere de configurație decisă dintr-un ne-fapt;
  * `step_nginx` scoate din funcțiune listener-ul :80 al nginx-ului gazdei;
  * `preflight.sh` tipărește „port 8443 free" pe o gazdă unde nu s-a măsurat
    nimic, iar instalarea pleacă mai departe încrezătoare.

Trei stări, nu două: 0 liber / 1 ocupat / orice altceva necunoscut (2 = `ss`
n-a putut fi întrebat, 3 = argumentul nu e un port canonic și `ss` nu e chemat).
Regula pentru apelanți: liber e `== 0`, ocupat e `== 1`, TOT RESTUL e necunoscut
și se oprește sau se lasă totul neatins.

Fișierul de față rulează codul LIVRAT din `deploy/lib/common.sh`,
`deploy/install.sh` și `deploy/preflight.sh` — nu o reimplementare — cu un `ss`
momeală pe PATH, adică chiar BINARUL pe care codul îl atinge, nu funcția
`port_free` umbrită (aia ar verifica harnașul, nu livrarea). Fiecare momeală `ss`
își notează apelurile, ca „n-a fost chemat niciodată" să fie o observație, nu o
presupunere. Harnașele rulează sub `set -euo pipefail`, ca și scripturile reale:
o funcție care întoarce acum 2 nu are voie să oprească în tăcere un apelant care
o folosea ca boolean.

Argumentele de tip `05432`, `` (gol), `65536` au fost MĂSURATE pe gazda de
producție de reparația anterioară a acestui defect (iproute2-6.17.0): `ss` le
răspunde cu rc 0 despre altceva. Nemăsurat din mașina pe care s-a scris fișierul
(nu are `ss`); testele de aici verifică doar că `ss` nu mai e chemat cu ele.

Uneltele `_func`, `_stub`, `_run` sunt cele din
tests/security/test_installer_postgres_port.py.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
PREFLIGHT_SH = REPO / "deploy" / "preflight.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
COMMON = COMMON_SH.read_text(encoding="utf-8")
PREFLIGHT = PREFLIGHT_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
_NO_BASH = ("bash lipsește din PATH, deci codul LIVRAT nu a fost rulat. "
            "Asta e „neverificat”, nu „în regulă”.")
pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


# ---------------------------------------------------------------------------
# Unelte
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


SS_LISTEN_LINE = "LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*"
SS_UDP_LINE = "UNCONN 0      0            127.0.0.1:5432       0.0.0.0:*"
SS_BAD_PORT_ERR = 'Error: "abc" does not look like a port.'
SS_FAILS = f"printf '%s\\n' '{SS_BAD_PORT_ERR}' >&2\nexit 1\n"


def _ss_stub(tmp_path: Path, body: str) -> tuple[Path, Path]:
    """Momeală `ss` pe PATH care ÎȘI NOTEAZĂ fiecare apel. Întoarce
    (directorul de pus în PATH, jurnalul apelurilor)."""
    binpath = tmp_path / "bin"
    calls = tmp_path / "ss-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    _stub(binpath, "ss", f'printf "%s\\n" "$*" >> "{calls.as_posix()}"\n' + body)
    return binpath, calls


def _planned_ss(tmp_path: Path, plan: str) -> tuple[Path, Path]:
    """`ss` care răspunde după un PLAN, o literă per SONDĂ (per `port_free`):

        E  ambele interogări (tcp, udp) iese 0 fără nicio linie  -> liber
        H  tcp tipărește un LISTEN                               -> ocupat
        F  tcp iese 1 cu o eroare pe stderr                      -> necunoscut

    Sonda care depășește planul primește E. Interogările cu `-p` (cele ale lui
    port_owner / port_owner_unit) nu avansează planul și nu tipăresc nimic.
    Contorul stă în fișier, nu în memorie: fiecare `ss` e un proces nou."""
    plan_file = tmp_path / "ss-plan"
    plan_file.write_text("\n".join(plan.split()) + "\n", encoding="utf-8", newline="\n")
    cnt = tmp_path / "ss-count"
    cnt.write_text("0\n", encoding="utf-8", newline="\n")
    last = tmp_path / "ss-last"
    last.write_text("E\n", encoding="utf-8", newline="\n")
    body = f"""
case "$1" in
    -tlnH)
        n="$(cat "{cnt.as_posix()}")"
        printf '%s\\n' "$((n + 1))" > "{cnt.as_posix()}"
        v="$(sed -n "$((n + 1))p" "{plan_file.as_posix()}")"
        v="${{v:-E}}"
        printf '%s\\n' "$v" > "{last.as_posix()}"
        ;;
    -ulnH) v="$(cat "{last.as_posix()}")" ;;
    *) exit 0 ;;
esac
case "$v" in
    H) printf '%s\\n' '{SS_LISTEN_LINE}' ;;
    F) printf '%s\\n' '{SS_BAD_PORT_ERR}' >&2; exit 1 ;;
esac
exit 0
"""
    return _ss_stub(tmp_path, body)


def _port_free_rc(tmp_path: Path, argument: str, ss_body: str,
                  *, drop_path: bool = False) -> tuple[int, str]:
    """Rulează `port_free` LIVRATĂ cu argumentul dat. Întoarce (rc, apeluri ss)."""
    binpath, calls = _ss_stub(tmp_path, ss_body)
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "rc=0\n"
        f'port_free "{argument}" || rc=$?\n'
        'printf "RC=%d\\n" "$rc"\n'
    )
    if drop_path:
        # PATH fără NIMIC în el: `ss` chiar lipsește. `port_free` nu are voie
        # să folosească nimic în afară de builtins pe lângă `ss`.
        proc = _run(script, tmp_path, env={"PATH": "/nonexistent"})
    else:
        proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("RC="))
    return int(line.split("=")[1]), calls.read_text(encoding="utf-8")


# ===========================================================================
# port_free — trei răspunsuri, nu două
# ===========================================================================
def test_an_ss_that_refuses_the_argument_is_unknown_not_free(tmp_path):
    """`ss` iese cu 1 și scrie pe stderr exact ce se măsoară pe o gazdă cu un
    iproute2 vechi. Vechea conductă `| grep -q .` arunca rc-ul și răspundea
    „liber" — iar pe răspunsul ăla `pg_ensure_listening` repornește baza de
    producție. Aici trebuie să iasă 2 („necunoscut"), nu 0."""
    rc, calls = _port_free_rc(tmp_path, "5432", SS_FAILS)
    assert rc == 2, f"rc={rc} — un ss care a eșuat a fost citit ca răspuns"
    assert calls.strip(), "ss n-a fost chemat deloc; testul n-a măsurat nimic"


def test_a_missing_ss_is_unknown_not_free(tmp_path):
    """`ss` lipsește cu totul din PATH (iproute2 neinstalat — se întâmplă pe
    imagini minimale). Bash întoarce 127, mesajul pleacă la /dev/null, iar
    vechea formă spunea „liber". Un preflight care trece pe gazda aia și un
    installer care repornește PostgreSQL pe ea sunt amândouă clădite pe
    nimic."""
    rc, _ = _port_free_rc(tmp_path, "5432", "exit 0\n", drop_path=True)
    assert rc == 2, f"rc={rc} — un ss inexistent a fost citit ca „nimic nu ascultă”"


def test_a_failing_udp_query_is_unknown_even_when_tcp_was_empty(tmp_path):
    """Întrebarea udp e jumătate din răspuns. Dacă tcp a dat «nimic» și udp a
    eșuat, «liber» ar fi o afirmație despre udp pe care nimeni n-a verificat-o:
    un serviciu care ține portul doar pe udp ar fi raportat ca absent."""
    rc, calls = _port_free_rc(
        tmp_path, "5432",
        'case "$1" in\n'
        '  -tlnH) exit 0 ;;\n'
        f'  -ulnH) printf "%s\\n" \'{SS_BAD_PORT_ERR}\' >&2; exit 1 ;;\n'
        'esac\nexit 0\n')
    assert rc == 2, f"rc={rc} — udp a eșuat și răspunsul a fost totuși «liber»"
    assert calls.count("\n") == 2, f"udp trebuia întrebat: {calls!r}"


def test_a_listening_tcp_socket_is_reported_held(tmp_path):
    """Contra-proba care ține testele de «necunoscut» cinstite: cu un `ss` care
    chiar tipărește un LISTEN, răspunsul rămâne «ocupat» (1). O poartă care ar
    refuza tot ar trece testele de mai sus fără să mai poată deosebi nimic."""
    rc, calls = _port_free_rc(
        tmp_path, "5432", f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n')
    assert rc == 1, f"rc={rc}"
    assert calls.strip()


def test_a_tcp_only_listener_is_held_even_when_the_udp_query_is_empty(tmp_path):
    """Un serviciu care ține portul DOAR pe tcp (cazul PostgreSQL) cu o
    interogare udp goală: «ocupat» vine din tcp, nu din întâmplarea că ambele
    interogări tipăresc la fel. Dacă verdictul tcp s-ar pierde, un cluster
    care ascultă ar fi raportat liber și repornit."""
    rc, _ = _port_free_rc(
        tmp_path, "5432",
        'case "$1" in\n'
        f'  -tlnH) printf "%s\\n" "{SS_LISTEN_LINE}" ;;\n'
        'esac\nexit 0\n')
    assert rc == 1, f"rc={rc} — un listener tcp a fost raportat ca port liber"


def test_a_failing_tcp_query_is_unknown_even_when_udp_would_have_been_empty(tmp_path):
    """Oglinda testului pentru udp: tcp eșuează, udp ar fi răspuns «nimic».
    «Liber» ar fi o afirmație despre tcp — singurul protocol pe care PostgreSQL
    îl folosește — pe care nimeni n-a verificat-o. Se întoarce 2 înainte ca udp
    să mai fie întrebat."""
    rc, _ = _port_free_rc(
        tmp_path, "5432",
        'case "$1" in\n'
        f'  -tlnH) printf "%s\\n" \'{SS_BAD_PORT_ERR}\' >&2; exit 1 ;;\n'
        'esac\nexit 0\n')
    assert rc == 2, f"rc={rc} — tcp a eșuat și răspunsul a fost totuși «liber»"


def test_silence_from_a_working_ss_is_free(tmp_path):
    """Și cealaltă contra-probă: `ss` a rulat, a ieșit cu 0 și n-a tipărit
    nimic — singurul caz în care «liber» e o măsurătoare. Fără el, fiecare port
    ar deveni «necunoscut» și instalarea n-ar mai putea alege niciodată un
    port."""
    rc, calls = _port_free_rc(tmp_path, "5432", "exit 0\n")
    assert rc == 0, f"rc={rc}"
    assert calls.count("\n") == 2, \
        f"tcp ȘI udp trebuie interogate amândouă; apeluri: {calls!r}"


def test_a_udp_only_listener_still_counts_as_held(tmp_path):
    """Interogarea udp nu s-a pierdut la rescriere. Un serviciu care ține
    portul doar pe udp îl ține la fel de real."""
    rc, _ = _port_free_rc(
        tmp_path, "5432",
        'case "$1" in\n'
        '  -tlnH) exit 0 ;;\n'
        f'  -ulnH) printf "%s\\n" "{SS_UDP_LINE}" ;;\n'
        'esac\nexit 0\n')
    assert rc == 1, f"rc={rc} — un listener udp a fost raportat ca port liber"


@pytest.mark.parametrize("argument", [
    "05432",                   # `sport = :05432` nu potrivește NIMIC (măsurat anterior)
    "",                        # `sport = :` potrivește TOT (măsurat anterior)
    "0",                       # nu e un port
    "65536",                   # «liber» fals pentru un ne-port (măsurat anterior)
    "5432x",
    chr(0xFF15) + chr(0xFF14) + chr(0xFF13) + chr(0xFF12),  # cifre fullwidth (U+FF12..U+FF15)
    "18446744073709557048",    # 20 de cifre: `(( ))` îl evaluează la 5432
])
def test_a_non_canonical_port_answers_3_and_never_reaches_ss(tmp_path, argument):
    """Argumentele astea nu sunt întrebări pe care `ss` să le poată răspunde.
    Cel care contează în producție e `05432`: `pg_configured_port` întoarce
    cifrele din postgresql.conf verbatim, iar `ss` răspunde «nimic acolo»
    despre un port pe care PostgreSQL îl servește — adică «liber», adică o
    repornire a bazei sănătoase. Verdictul e 3 ȘI `ss` nu e chemat deloc;
    jurnalul gol e dovada, nu o presupunere."""
    rc, calls = _port_free_rc(
        tmp_path, argument, f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n')
    assert rc == 3, f"rc={rc} pentru {argument!r}"
    assert calls == "", f"ss a fost chemat cu un argument pe care nu-l poate răspunde: {calls!r}"


def test_a_bad_argument_and_a_broken_ss_do_not_share_a_code(tmp_path):
    """`port = 70000` scris de mână în postgresql.conf ajungea, cu un `ss`
    perfect funcțional, la «ss failed or is missing — install iproute2»:
    operatorul instala un pachet care mergea, iar linia stricată rămânea.
    «Valoarea nu e un port» și «unealta n-a putut fi întrebată» ies pe coduri
    DIFERITE, altfel niciun apelant nu le poate spune diferit."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    bad_value, _ = _port_free_rc(a, "70000", "exit 0\n")
    broken_tool, _ = _port_free_rc(b, "5432", SS_FAILS)
    assert bad_value == 3 and broken_tool == 2 and bad_value != broken_tool


def test_a_canonical_port_does_reach_ss(tmp_path):
    """Contra-proba gărzii de argument: un port normal chiar ajunge la `ss`. O
    gardă care ar refuza totul ar face testele de «necunoscut» să treacă
    degeaba."""
    rc, calls = _port_free_rc(tmp_path, "8443", "exit 0\n")
    assert rc == 0
    assert "8443" in calls, f"ss n-a primit portul: {calls!r}"


def test_port_free_without_an_argument_answers_3_instead_of_aborting_under_set_u(tmp_path):
    """Chemată fără argument sub `set -u`, o variantă cu `$1` ar opri tot
    instalatorul cu «unbound variable». Răspunsul cinstit pentru «nu s-a dat
    niciun port» e 3 — un fapt despre apel, nu despre gazdă."""
    binpath, calls = _ss_stub(tmp_path, "exit 0\n")
    proc = _run(
        "set -euo pipefail\nsource ./lib/common.sh\nrc=0\nport_free || rc=$?\n"
        'printf "RC=%d\\n" "$rc"\n', tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RC=3" in proc.stdout, proc.stdout + proc.stderr
    assert calls.read_text(encoding="utf-8") == ""


# ===========================================================================
# Cine o cheamă: nimeni n-o mai citește ca boolean
# ===========================================================================
SHELL_FILES = sorted((REPO / "deploy").rglob("*.sh")) + sorted((REPO / "scripts").rglob("*.sh"))


def _code_lines(path: Path):
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        yield number, line


# Singura formă în care un apelant primește răspunsul: rc-ul capturat într-o
# variabilă, pe același rând. `if port_free`, `! port_free`, `port_free && …`
# citesc 2 și 3 ca «ocupat» sau ca «nu era liber», iar `set -e` oprește un
# `port_free X` simplu pe un 2.
_CAPTURED = {
    "port_free": re.compile(r"\bport_free\s+[^|&;]*\|\|\s*\w+=\$\?"),
    "pg_wait_listening": re.compile(r"\bpg_wait_listening\s+[^|&;]*\|\|\s*\w+=\$\?"),
    "pg_pick_free_port": re.compile(r"\bpg_pick_free_port\s+[^|&;)]*\)\"\s*\|\|\s*\w+=\$\?"),
}
_DEFINITION = {name: re.compile(rf"^{name}\(\)\s*\{{") for name in _CAPTURED}


_MIN_CALLERS = {"port_free": 6, "pg_wait_listening": 4, "pg_pick_free_port": 1}


@pytest.mark.parametrize("name", sorted(_CAPTURED))
def test_no_shipped_caller_reads_a_three_state_probe_as_a_boolean(name):
    """`if port_free X` și `! port_free X` au fost modul în care un «necunoscut»
    devenea «liber» sau «ocupat» fără ca cineva să fi decis asta. Fiecare
    apariție a funcției, în tot deploy/ și scripts/, în afară de definiție,
    trebuie să-și captureze rc-ul (`|| var=$?`). Un apelant nou scris în forma
    veche pică aici, nu pe o gazdă. Numărul de apeluri e verificat și el: o
    listă de apelanți ieșită goală ar trece testul fără să fi privit nimic."""
    seen = 0
    offenders = []
    for path in SHELL_FILES:
        for number, line in _code_lines(path):
            if not re.search(rf"\b{name}\b", line) or _DEFINITION[name].match(line):
                continue
            seen += 1
            if not _CAPTURED[name].search(line):
                offenders.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
    assert seen >= _MIN_CALLERS[name], \
        f"doar {seen} apeluri ale lui {name} găsite — enumerarea s-a stricat"
    assert not offenders, "rc-ul nu e capturat:\n" + "\n".join(offenders)


def _ensure_body() -> str:
    return _func(INSTALL, "pg_ensure_listening")


def test_every_probe_in_pg_ensure_listening_goes_through_pg_probe_or_die():
    """O sondă a cărei variabilă nu trece prin `pg_probe_or_die` cade prin
    toate `if (( prc == 0 ))` de după ea în «portul e ținut de un străin»,
    adică în mutarea clusterului și a doua repornire. Cu o singură ajutătoare
    și un test structural, un apel LIPSĂ e prins aici, nu de o gazdă.

    Sondele sunt cele cu `|| wrc=$?` / `|| prc=$?`; rândul următor de cod
    trebuie să fie apelul, cu aceeași variabilă."""
    lines = [ln for ln in _ensure_body().splitlines() if not ln.lstrip().startswith("#")]
    probes = [i for i, ln in enumerate(lines) if re.search(r"\|\|\s*(wrc|prc)=\$\?", ln)]
    assert len(probes) == 5, f"{len(probes)} sonde, nu 5 — enumerarea sau funcția s-a schimbat"
    for i in probes:
        var = re.search(r"\|\|\s*(wrc|prc)=\$\?", lines[i]).group(1)
        assert re.match(rf'\s*pg_probe_or_die "\${var}" ', lines[i + 1]), \
            f"după sonda {lines[i].strip()!r} urmează {lines[i + 1].strip()!r}"


def test_pg_ensure_listening_compares_no_probe_code_with_2_or_3_itself():
    """Singurul loc care compară un cod de sondă cu 2 sau 3 și moare pe el e
    `pg_probe_or_die`. O comparație `== 2` copiată în `pg_ensure_listening` e
    chiar brațul de dispecerizare care a putut fi șters cu suita verde."""
    body = _ensure_body()
    assert not re.search(r"\b(wrc|prc)\s*==\s*[23]\b", body), \
        "pg_ensure_listening dispecerizează singură un cod de sondă"


# ===========================================================================
# set -e: funcția întoarce acum 2/3, iar apelanții trebuie să rămână în viață
# ===========================================================================
def test_a_bare_port_free_would_abort_under_set_e_which_is_why_callers_capture_the_rc(tmp_path):
    """Documentează capcana, ca testul structural de mai sus să aibă un motiv
    verificabil: sub `set -e`, un `port_free X` simplu pe un `ss` rupt OPREȘTE
    scriptul (rc 2), pe când forma capturată merge mai departe. Fără rândul ăsta
    cineva ar putea «simplifica» capturile fără să vadă ce rupe."""
    binpath, _ = _ss_stub(tmp_path, SS_FAILS)
    bare = _run("set -euo pipefail\nsource ./lib/common.sh\nport_free 5432\necho SURVIVED\n",
                tmp_path, extra_path=binpath)
    assert "SURVIVED" not in bare.stdout and bare.returncode == 2, \
        f"rc={bare.returncode} out={bare.stdout!r}"
    captured = _run(
        "set -euo pipefail\nsource ./lib/common.sh\nrc=0\nport_free 5432 || rc=$?\n"
        "echo SURVIVED rc=$rc\n", tmp_path, extra_path=binpath)
    assert "SURVIVED rc=2" in captured.stdout, captured.stdout + captured.stderr


# ===========================================================================
# pg_wait_listening / pg_pick_free_port
# ===========================================================================
def _call(tmp_path: Path, ss_body: str, call: str, pre: str = "") -> tuple[int, str, float]:
    binpath, _ = _ss_stub(tmp_path, ss_body)
    started = time.monotonic()
    proc = _run(
        "set -euo pipefail\nsource ./lib/common.sh\n" + pre
        + "rc=0\nout=\"$(" + call + ")\" || rc=$?\n"
        'printf "RC=%d\\nOUT=%s\\n" "$rc" "$out"\n',
        tmp_path, extra_path=binpath)
    elapsed = time.monotonic() - started
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rc = int(next(ln for ln in proc.stdout.splitlines() if ln.startswith("RC=")).split("=")[1])
    out = next(ln for ln in proc.stdout.splitlines() if ln.startswith("OUT="))[4:]
    return rc, out, elapsed


def test_wait_listening_answers_2_at_once_when_ss_cannot_be_asked(tmp_path):
    """Cu `ss` rupt, vechea formă (`! port_free && owned`) se învârtea cele 15 s
    și tăcea, iar apelantul citea «PostgreSQL n-a pornit niciodată» — un
    verdict despre bază făcut dintr-un fapt despre `ss`. Acum răspunde 2 la
    PRIMA sondă: nu așteaptă 15 s un răspuns care nu vine."""
    rc, _, elapsed = _call(tmp_path, SS_FAILS, 'pg_wait_listening 5432 15')
    assert rc == 2, f"rc={rc}"
    assert elapsed < 8, f"{elapsed:.1f}s — a sondat în buclă un ss rupt"


def test_wait_listening_answers_3_for_a_value_that_is_not_a_port(tmp_path):
    """`port = 70000` nu devine port așteptând. 3, nu 1: «n-a pornit» trimite
    operatorul la journalctl, «nu e port» la linia din postgresql.conf."""
    rc, _, elapsed = _call(tmp_path, "exit 0\n", 'pg_wait_listening 70000 15')
    assert rc == 3 and elapsed < 8, f"rc={rc} elapsed={elapsed:.1f}"


def test_wait_listening_still_times_out_with_1_on_a_port_nobody_binds(tmp_path):
    """Contra-proba: un `ss` sănătos care nu vede nimic înseamnă «încă nu
    ascultă» (1) după timeout, nu «necunoscut». Fără ea, ramura nouă ar fi
    înghițit răspunsul obișnuit."""
    rc, _, _ = _call(tmp_path, "exit 0\n", 'pg_wait_listening 5432 1')
    assert rc == 1


def test_wait_listening_still_succeeds_when_the_port_is_ours(tmp_path):
    """Contra-proba pentru calea fericită: portul ținut de PostgreSQL-ul nostru
    întoarce 0. Proprietatea (cgroup) e momeală — pe mașina de test nu există
    /proc — dar sonda de port trece prin `ss` real."""
    rc, _, _ = _call(
        tmp_path, f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n',
        'pg_wait_listening 5432 3', pre='pg_port_owned_by_postgres() { return 0; }\n')
    assert rc == 0


def test_wait_listening_does_not_call_a_strangers_port_ours(tmp_path):
    """Un străin pe port NU e succes, nici necunoscut: 1 după timeout."""
    rc, _, _ = _call(
        tmp_path, f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n',
        'pg_wait_listening 5432 1', pre='pg_port_owned_by_postgres() { return 1; }\n')
    assert rc == 1


def test_wait_listening_never_calls_a_free_port_ours(tmp_path):
    """«Ocupat ȘI al nostru» cere ambele. Dacă verificarea de proprietar ar
    putea răspunde singură, un port pe care nu ascultă nimeni (liber, măsurat)
    ar trece drept PostgreSQL-ul nostru de îndată ce proprietarul e interogabil
    — iar apelantul ar lua un cluster care nu a pornit drept pornit."""
    rc, _, _ = _call(tmp_path, "exit 0\n", 'pg_wait_listening 5432 1',
                     pre='pg_port_owned_by_postgres() { return 0; }\n')
    assert rc == 1


def test_pick_free_port_stops_at_the_first_unknown_instead_of_scanning_twenty(tmp_path):
    """Douăzeci de «necunoscut» urmate de «nu am găsit port liber» ar fi o
    căutare care n-a avut loc. Se oprește la prima, cu 2 — iar `ss` e chemat o
    singură dată."""
    binpath, calls = _ss_stub(tmp_path, SS_FAILS)
    proc = _run(
        "set -euo pipefail\nsource ./lib/common.sh\nrc=0\n"
        'out="$(pg_pick_free_port 5432)" || rc=$?\nprintf "RC=%d OUT=[%s]\\n" "$rc" "$out"\n',
        tmp_path, extra_path=binpath)
    assert "RC=2 OUT=[]" in proc.stdout, proc.stdout + proc.stderr
    assert calls.read_text(encoding="utf-8").count("\n") == 1


def test_pick_free_port_skips_held_ports_and_picks_the_first_free_one(tmp_path):
    """Contra-proba: 5433 și 5434 ținute, 5435 liber -> 5435."""
    binpath, _ = _ss_stub(
        tmp_path,
        'case "$*" in\n'
        f'  *5433*|*5434*) printf "%s\\n" "{SS_LISTEN_LINE}" ;;\n'
        'esac\nexit 0\n')
    proc = _run("set -euo pipefail\nsource ./lib/common.sh\npg_pick_free_port 5432\n",
                tmp_path, extra_path=binpath)
    assert proc.returncode == 0 and proc.stdout.strip() == "5435", proc.stdout + proc.stderr


def test_pick_free_port_says_3_when_the_scan_runs_off_the_end_of_the_range(tmp_path):
    """De la 65535 în sus nu mai e nimic de scanat — un fapt despre VALOARE,
    nu despre `ss`. 3, ca apelantul să nu spună «instalează iproute2» pe o
    gazdă sănătoasă."""
    rc, _, _ = _call(tmp_path, "exit 0\n", 'pg_pick_free_port 65535')
    assert rc == 3


# ===========================================================================
# pg_ensure_listening — decizii luate (sau nu) din sonde
# ===========================================================================
def _ensure_funcs() -> str:
    return "\n".join(_func(INSTALL, n) for n in (
        "pg_probe_or_die", "pg_restore_to", "pg_restore_tail", "pg_ensure_listening"))


def _ensure(tmp_path: Path, plan: str, *, port: str = "5432", explicit: str = "",
            restore: str = "", conf_port: str = "5432", owned: bool = False,
            conf_line: str | None = None):
    """Rulează `pg_ensure_listening` LIVRATĂ, cu `ss` real din PATH (momeală
    după PLAN) și `systemctl` momeală care doar își notează apelurile și NU leagă
    nimic — deci orice repornire pe care codul o face e vizibilă ca linie în
    jurnal. Întoarce (proces, [apeluri systemctl], text postgresql.conf)."""
    pgconf = tmp_path / "pgdata"
    pgconf.mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text(
        "listen_addresses = '127.0.0.1'\n" + (conf_line or f"port = {conf_port}") + "\n",
        encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath, _ = _planned_ss(tmp_path, plan)
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    _stub(binpath, "systemctl", f'printf "%s\\n" "$*" >> "{calls.as_posix()}"\nexit 0\n')
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f"pg_port_owned_by_postgres() {{ return {0 if owned else 1}; }}\n"
        'port_owner() { printf "container/other"; }\n'
        + _ensure_funcs() + "\n"
        f'pg_ensure_listening "{pgconf_posix}" "{port}" "{explicit}" 1 "{restore}"\n'
        'printf "RESOLVED=%s\\n" "$PG_RESOLVED_PORT"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    sysc = [ln for ln in calls.read_text(encoding="utf-8").splitlines() if ln]
    conf = (pgconf / "postgresql.conf").read_text(encoding="utf-8")
    return proc, sysc, conf


def _restarts(sysc: list[str]) -> int:
    return sum(1 for ln in sysc if ln.startswith("restart"))


def test_a_broken_ss_stops_pg_ensure_listening_before_it_restarts_anything(tmp_path):
    """Defectul, de la capăt la capăt. Cu `ss` rupt de la început, vechiul cod
    citea «portul e liber», repornea PostgreSQL-ul de producție, apoi — tot
    orbește — îl muta pe alt port. Aici: moare la prima sondă, spune că e
    NECUNOSCUT, jurnalul `systemctl` nu are niciun `restart`, iar
    postgresql.conf rămâne pe 5432."""
    proc, sysc, conf = _ensure(tmp_path, "F F F F F F")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 0, f"a repornit baza pe un port nemăsurat: {sysc}"
    assert "UNKNOWN" in out and "could not determine whether port 5432" in out, out
    assert "port = 5432" in conf and conf.count("port =") == 1, conf
    assert "RESOLVED=" not in proc.stdout, out


def test_a_zero_padded_port_from_postgresql_conf_is_refused_not_restarted(tmp_path):
    """`port = 05432` (scris de mână) ajunge ca «05432» la sondă. `ss` îl
    răspunde cu «nimic acolo» despre un port pe care PostgreSQL îl servește,
    deci vechiul cod repornea un cluster sănătos degeaba. Acum: moare spunând
    că valoarea nu e un port, `ss` nu e chemat, nu se repornește nimic."""
    proc, sysc, _ = _ensure(tmp_path, "E E E E", port="05432", conf_port="05432")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert "not a usable port number" in out and "'05432'" in out, out
    assert "iproute2" not in out, f"a dat vina pe unealtă pentru o valoare greșită: {out}"
    assert _restarts(sysc) == 0, sysc


def test_unknown_at_the_second_probe_does_not_restart(tmp_path):
    """Sonda a doua («e liber? atunci repornesc») e exact locul unde un
    «necunoscut» citit ca «liber» produce indisponibilitatea. Prima sondă
    (așteptarea) vede «liber», a doua nu poate întreba."""
    proc, sysc, conf = _ensure(tmp_path, "E F")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "could not determine" in out, out
    assert _restarts(sysc) == 0, f"repornit pe un răspuns care n-a existat: {sysc}"
    assert "port = 5432" in conf


def test_unknown_after_the_restart_says_the_database_was_restarted(tmp_path):
    """După `systemctl restart`, «n-am putut întreba» NU poate fi urmat de
    «nu s-a repornit nimic»: operatorul ar crede că baza e neatinsă. Mesajul
    spune că a fost repornită o dată și că dacă a revenit e NECUNOSCUT, iar
    configurația nu e «pusă la loc» (clusterul a urmat fișierul)."""
    proc, sysc, _conf = _ensure(tmp_path, "E E F")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 1, sysc
    assert "RESTARTED" in out and "UNKNOWN" in out, out
    assert "issued no restart" not in out, f"afirmă ce contrazice jurnalul systemctl: {out}"


def test_unknown_at_the_free_or_held_probe_does_not_fall_into_the_move(tmp_path):
    """Sonda de după așteptare («liber -> serviciul e stricat» sau «ținut ->
    mut clusterul») e cea din care s-a putut șterge ramura necunoscutului cu
    toată suita verde: un `ss` care se strică exact aici cădea în mutare —
    rescriere de postgresql.conf și a doua repornire. `ss` își revine imediat
    după, deci o mutare chiar ar fi găsit un port liber."""
    proc, sysc, conf = _ensure(tmp_path, "E E E F E E E E")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 1, f"s-a ajuns la mutare / a doua repornire: {sysc}"
    assert "port = 5432" in conf and "5433" not in conf, conf
    assert "could not determine whether port 5432" in out, out
    assert "moving sentinel's cluster" not in out.lower() and "after moving off" not in out, out


def test_unknown_while_picking_a_new_port_moves_nothing(tmp_path):
    """Portul e ținut de un străin (H), iar căutarea unui port liber nu poate
    întreba. Vechiul `|| die "no free port found"` spunea o minciună despre
    căutare; mai grav, un candidat «liber» fals ar fi mutat clusterul. Aici:
    niciun `restart`, fișierul neatins, mesajul spune că e necunoscut."""
    proc, sysc, conf = _ensure(tmp_path, "H H H F")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 0, sysc
    assert "could not determine which ports near 5432 are free" in out, out
    assert "no free port found" not in out, out
    assert "port = 5432" in conf and "5433" not in conf, conf


def test_unknown_after_the_move_says_so_instead_of_reporting_a_failed_bind(tmp_path):
    """După mutare și repornire, un `ss` care nu răspunde nu înseamnă «n-a
    ajuns să asculte pe portul nou» — înseamnă că nu se știe. Mesajul vechi
    («still not listening on …») era o afirmație fără observație."""
    proc, sysc, conf = _ensure(tmp_path, "H H H E F")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert "port = 5433" in conf, conf
    assert _restarts(sysc) == 1, sysc
    assert "could not determine whether port 5433 is listening" in out, out
    assert "RESTARTED" in out and "after moving off" not in out, out


def test_an_ss_that_works_still_moves_the_cluster_off_a_strangers_port(tmp_path):
    """Contra-proba: comportamentul dinainte, cu un `ss` care răspunde. 5432
    ținut de un străin, 5433 liber -> clusterul e mutat și repornit o dată; pe
    5433 `systemctl` momeală nu leagă nimic, deci moare, dar după mutare — nu
    din cauza gărzilor noi."""
    proc, sysc, conf = _ensure(tmp_path, "H H H E E")
    out = proc.stdout + proc.stderr
    assert "port = 5433" in conf and _restarts(sysc) == 1, (sysc, conf, out)
    assert "UNKNOWN" not in out, f"gărzile noi au tras pe un ss sănătos: {out}"
    assert "still not listening on 5433" in out, out


def test_a_healthy_free_port_still_restarts_exactly_once_and_resolves(tmp_path):
    """Contra-proba pentru ramura «liber»: nimic nu ascultă, `ss` răspunde,
    deci repornirea e justificată — o dată. Apoi clusterul «ascultă» (planul:
    a treia sondă vede un LISTEN al nostru) și funcția se întoarce cu portul."""
    proc, sysc, _ = _ensure(tmp_path, "E E H", owned=True)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert _restarts(sysc) == 1, sysc
    assert "RESOLVED=5432" in proc.stdout, out


def test_unknown_while_picking_with_the_range_exhausted_names_the_range_not_ss(tmp_path):
    """De la 65535 în sus nu mai e nimic de scanat. Dacă «a ieșit din interval»
    ar fi spus «ss nu răspunde», operatorul ar căuta un iproute2 stricat pe o
    gazdă sănătoasă, în loc să mute PostgreSQL mai jos."""
    proc, sysc, _conf = _ensure(tmp_path, "H H H", port="65535", conf_port="65535")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "ran past the end of the port range" in out, out
    assert "could not determine" not in out and _restarts(sysc) == 0, (out, sysc)


def test_pick_free_port_exhausted_after_twenty_held_ports_says_none_found(tmp_path):
    """Contra-proba pentru brațul «1»: douăzeci de porturi MĂSURATE ca ținute
    înseamnă «nu am găsit», nu «necunoscut» — mesajul ăsta e adevărat doar
    când căutarea chiar a avut loc."""
    proc, sysc, _ = _ensure(tmp_path, " ".join(["H"] * 23))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "no free port found near 5432" in out, out
    assert "UNKNOWN" not in out and _restarts(sysc) == 0, (out, sysc)


# --- calea --db-port explicită: linia de port se pune la loc, fără repornire --
def test_unknown_with_an_explicit_db_port_puts_the_config_line_back_without_restarting(tmp_path):
    """`--db-port 5440` pe un cluster sănătos pe 5433: pasul 22 a scris deja
    `port = 5440`. Un `ss` care se strică la prima sondă murea cu fișierul pe
    5440 și clusterul pe 5433 — baza se muta singură la prima repornire
    nelegată. Linia se pune la loc ÎNAINTE de moarte (fără repornire), iar
    mesajul citește fișierul înapoi."""
    proc, sysc, conf = _ensure(tmp_path, "F", port="5440", explicit="1",
                               restore="5433", conf_port="5440")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 0, sysc
    assert "port = 5433" in conf and "5440" not in conf, conf
    assert "was put back to 5433" in out, out


def test_unknown_after_a_restart_leaves_the_explicit_port_line_alone(tmp_path):
    """După o repornire clusterul a urmat fișierul (5440). A pune linia la loc
    acum ar fi exact ce desparte fișierul de cluster. Rămâne 5440, iar mesajul
    spune ce scrie în fișier, citit din el."""
    proc, sysc, conf = _ensure(tmp_path, "E E F", port="5440", explicit="1",
                               restore="5433", conf_port="5440")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and _restarts(sysc) == 1, (sysc, out)
    assert "port = 5440" in conf, conf
    assert "postgresql.conf names 5440" in out, out


def test_the_restore_after_a_failed_explicit_port_does_not_restart_on_unknown(tmp_path):
    """Cererea explicită eșuează (5440 nu se leagă), apoi recuperarea nu poate
    întreba `ss`. Vechiul `pg_restore_to` repornea oricum («nu e ascultat»)
    și apoi declara «PostgreSQL is DOWN» fără nicio observație. Acum: o
    singură repornire în total (cea de dinainte), mesajul spune că
    recuperarea n-a repornit nimic și că locul clusterului e NECUNOSCUT."""
    # sonde: 1 așteptare (liber), 2 liber -> restart, 3 așteptare (liber),
    # 4 re-măsurarea nu se face (explicit) -> pg_restore_to: 4 = F
    proc, sysc, conf = _ensure(tmp_path, "E E E F", port="5440", explicit="1",
                               restore="5433", conf_port="5440")
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _restarts(sysc) == 1, f"recuperarea a repornit pe un ss nemăsurabil: {sysc}"
    assert "port = 5433" in conf, conf
    assert "restore issued NO restart" in out and "UNKNOWN" in out, out
    assert "PostgreSQL is DOWN" not in out, out


def _restore_to(tmp_path: Path, plan: str, restore: str, conf_port: str = "5440"):
    pgconf = tmp_path / "pgdata"
    pgconf.mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text(f"port = {conf_port}\n", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")
    binpath, _ = _planned_ss(tmp_path, plan)
    calls = tmp_path / "systemctl-calls.log"
    calls.write_text("", encoding="utf-8", newline="\n")
    _stub(binpath, "systemctl", f'printf "%s\\n" "$*" >> "{calls.as_posix()}"\nexit 0\n')
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\nsource ./lib/distro.sh\n"
        "pg_port_owned_by_postgres() { return 1; }\n"
        + _func(INSTALL, "pg_restore_to") + "\n"
        f'rc=0\npg_restore_to "{pgconf_posix}" "{restore}" 1 || rc=$?\nprintf "RC=%d\\n" "$rc"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    rc = int(next(ln for ln in proc.stdout.splitlines() if ln.startswith("RC=")).split("=")[1])
    sysc = [ln for ln in calls.read_text(encoding="utf-8").splitlines() if ln]
    return rc, sysc, (pgconf / "postgresql.conf").read_text(encoding="utf-8")


def test_pg_restore_to_returns_3_and_writes_nothing_for_a_previous_port_that_is_not_a_port(tmp_path):
    """Un `port = 70000` scris de mână nu se «restaurează»: PostgreSQL refuză
    să pornească pe el. Vechea ordine scria linia ÎNAINTE de sondă și apoi
    spunea că a lăsat-o neatinsă. 3, fișierul neschimbat, nicio repornire."""
    rc, sysc, conf = _restore_to(tmp_path, "E E", "70000")
    assert rc == 3, rc
    assert "70000" not in conf and "port = 5440" in conf, conf
    assert sysc == [], sysc


def test_pg_restore_to_returns_2_without_restarting_when_ss_cannot_be_asked(tmp_path):
    """2 = «n-am putut întreba, deci n-am repornit». Linia e totuși pusă la loc
    (scrierea de fișier nu depinde de `ss`)."""
    rc, sysc, conf = _restore_to(tmp_path, "F", "5433")
    assert rc == 2, rc
    assert sysc == [], sysc
    assert "port = 5433" in conf


def test_pg_restore_to_returns_4_when_ss_fails_only_after_its_own_restart(tmp_path):
    """4 = «am repornit și nu se știe dacă a revenit» — alt fapt decât 2, iar
    mesajul nu are voie să le contopească (unul spune «nu am repornit»)."""
    rc, sysc, _ = _restore_to(tmp_path, "E F", "5433")
    assert rc == 4, rc
    assert sysc == ["restart postgresql"], sysc


def test_pg_restore_to_returns_1_only_when_the_restart_really_did_not_bind(tmp_path):
    """1 («PostgreSQL e jos») cere o OBSERVAȚIE: `ss` a răspuns, după
    repornire, că nu ascultă nimeni."""
    rc, sysc, _ = _restore_to(tmp_path, "E E", "5433")
    assert rc == 1 and sysc == ["restart postgresql"], (rc, sysc)


# ===========================================================================
# pg_probe_or_die — direct
# ===========================================================================
def _probe(tmp_path: Path, rc: str, *, restore: str = "", restarted: str = "0",
           conf_port: str = "5440", probed: str = "5440"):
    pgconf = tmp_path / "pgdata"
    pgconf.mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text(f"port = {conf_port}\n", encoding="utf-8", newline="\n")
    pgconf_posix = str(pgconf).replace("\\", "/")
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\nsource ./lib/distro.sh\n"
        + _func(INSTALL, "pg_probe_or_die") + "\n"
        f'pg_probe_or_die "{rc}" "{probed}" "{pgconf_posix}" "{restore}" "{restarted}"\n'
        'echo RETURNED\n'
    )
    proc = _run(script, tmp_path)
    return proc, (pgconf / "postgresql.conf").read_text(encoding="utf-8")


@pytest.mark.parametrize("rc", ["0", "1"])
def test_pg_probe_or_die_leaves_observations_to_the_caller(tmp_path, rc):
    """0 și 1 sunt observații; ce se face cu ele e decizia apelantului. O
    ajutătoare care ar muri și pe ele ar opri o instalare sănătoasă; una care
    le-ar atinge fișierul ar rescrie configurația pe fiecare sondă."""
    proc, conf = _probe(tmp_path, rc, restore="5433")
    assert proc.returncode == 0 and "RETURNED" in proc.stdout, proc.stdout + proc.stderr
    assert "port = 5440" in conf


@pytest.mark.parametrize("rc", ["2", "3", "4", "127", ""])
def test_pg_probe_or_die_dies_on_everything_that_is_not_0_or_1(tmp_path, rc):
    """Regula e «orice altceva e necunoscut», nu «2 și 3»: un cod 4 de mâine,
    un 127 de la o funcție lipsă sau un rc GOL (capturat greșit; `(( ))` cu
    argument gol dă eroare de sintaxă = 1, care ar citi ca fals) nu au voie să
    treacă drept observație."""
    proc, _ = _probe(tmp_path, rc)
    assert proc.returncode != 0 and "RETURNED" not in proc.stdout, \
        f"rc={rc!r} a trecut drept observație: {proc.stdout + proc.stderr}"


def test_pg_probe_or_die_names_the_value_for_3_and_the_tool_for_2(tmp_path):
    """Două reparații diferite, deci două mesaje: o valoare care nu e port cere
    corectarea liniei din fișier, un `ss` care nu răspunde cere comanda de
    rulat de mână. Fiecare trebuie să NU o pomenească pe cealaltă."""
    p3, _ = _probe(tmp_path / "t3", "3", probed="70000")
    p2, _ = _probe(tmp_path / "t2", "2", probed="5432")
    assert "'70000' is not a usable port number" in p3.stderr and "ss -tlnH" not in p3.stderr
    assert "ss -tlnH 'sport = :5432'" in p2.stderr and "not a usable port" not in p2.stderr


def test_pg_probe_or_die_does_not_write_a_non_port_back_into_the_config(tmp_path):
    """Un port anterior inutilizabil (`70000`) nu se scrie înapoi: ar lăsa un
    fișier pe care PostgreSQL refuză să pornească, sub un mesaj care pretinde
    că linia e neatinsă."""
    proc, conf = _probe(tmp_path, "2", restore="70000")
    assert proc.returncode != 0
    assert "70000" not in conf and "port = 5440" in conf, conf


def test_pg_probe_or_die_does_not_claim_a_restore_when_the_line_already_matched(tmp_path):
    """Pe o rulare FĂRĂ --db-port linia e chiar portul de la intrare: nu e nimic
    de pus la loc. Un mesaj care ar spune «was put back» ar fi o afirmație
    despre un efect care n-a existat."""
    proc, _ = _probe(tmp_path, "2", restore="5433", conf_port="5433", probed="5433")
    assert proc.returncode != 0
    assert "put back" not in proc.stderr and "postgresql.conf names 5433" in proc.stderr, proc.stderr


def test_pg_probe_or_die_says_so_when_putting_the_line_back_did_not_take(tmp_path):
    """Mesajul despre fișier e CITIT din fișier după încercare. Dacă scrierea
    n-a prins (disc plin, fișier doar-citire), «was put back» ar fi o minciună
    spusă exact când operatorul are cea mai mare nevoie de adevăr."""
    pgconf = tmp_path / "pgdata"
    pgconf.mkdir(parents=True, exist_ok=True)
    (pgconf / "postgresql.conf").write_text("port = 5440\n", encoding="utf-8", newline="\n")
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\nsource ./lib/distro.sh\n"
        "pg_set_port() { :; }\n"
        + _func(INSTALL, "pg_probe_or_die") + "\n"
        f'pg_probe_or_die 2 5440 "{str(pgconf).replace(chr(92), "/")}" 5433 0\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode != 0
    assert "did not take, it names 5440" in proc.stderr and "was put back" not in proc.stderr, proc.stderr


@pytest.mark.parametrize("rc,must,must_not", [
    ("0", "confirmed back on the previous port 5433", "DOWN"),
    ("1", "PostgreSQL is DOWN", "UNKNOWN"),
    ("2", "restore issued NO restart", "DOWN"),
    ("3", "'5433' is not a usable port", "WAS restarted"),
    ("4", "WAS restarted onto it, but whether it came up there could not be determined", "NO restart"),
    ("9", "internal: pg_restore_to returned 9", "DOWN"),
])
def test_pg_restore_tail_says_what_each_code_observed_and_no_more(tmp_path, rc, must, must_not):
    """Fiecare cod al lui `pg_restore_to` e un FAPT diferit despre gazdă, iar
    coada die()-ului nu are voie să le contopească: «am repornit și nu se știe»
    (4) nu e «n-am repornit» (2), iar «nu se știe» nu e «PostgreSQL e jos» (1).
    Fraza interzisă e cea pe care o contopire ar fi tipărit."""
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\nsource ./lib/distro.sh\n"
        + _func(INSTALL, "pg_restore_tail") + "\n"
        f"pg_restore_to() {{ return {rc}; }}\n"
        "pg_configured_port() { printf 5440; }\n"
        'pg_restore_tail /x 5433 1\nprintf "%s" "$PG_RESTORE_TAIL"\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert must in proc.stdout, proc.stdout
    assert must_not not in proc.stdout, proc.stdout


def test_pg_probe_or_die_does_not_rewrite_the_line_after_a_restart(tmp_path):
    """După o repornire clusterul a urmat fișierul; a-l «pune la loc» ar fi
    chiar scrierea care desparte fișierul de cluster."""
    proc, conf = _probe(tmp_path, "2", restore="5433", restarted="1")
    assert proc.returncode != 0 and "port = 5440" in conf, conf


# ===========================================================================
# step_nginx — listener-ul :80 nu se scoate din funcțiune pe un ne-fapt
# ===========================================================================
def _nginx_port80_block() -> str:
    """Blocul LIVRAT din `step_nginx` care decide ce se face cu :80, de la
    `local port80_probe=0` până la `fi` de la patru spații."""
    lines = INSTALL.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln == "    local port80_probe=0")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "    fi")
    block = "\n".join(lines[start:end + 1])
    assert "port_free 80" in block and "nginx_disable_default_listener" in block
    return block + "\n"


def _run_port80_block(tmp_path: Path, ss_body: str, *, preexisting: str = "0"):
    binpath, _ = _ss_stub(tmp_path, ss_body)
    touched = tmp_path / "nginx-touched.log"
    touched.write_text("", encoding="utf-8", newline="\n")
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'SNAPSHOT_DIR="{(tmp_path / "snap").as_posix()}"\n'
        f'NGINX_WAS_PREEXISTING="{preexisting}"\n'
        # Tot ce ar ATINGE nginx-ul își notează chemarea; absența unei linii de
        # aici e dovada că nu s-a atins nimic, nu o presupunere.
        f'cp() {{ printf "cp %s\\n" "$*" >> "{touched.as_posix()}"; }}\n'
        f'nginx_default_site() {{ printf "nginx_default_site\\n" >> "{touched.as_posix()}"; '
        'printf "/etc/nginx/nginx.conf\\n"; }\n'
        f'nginx_disable_default_listener() {{ printf "disable\\n" >> "{touched.as_posix()}"; '
        'printf "disabled\\n"; }\n'
        'nginx_listens_on_80() { return 1; }\n'
        "decide() {\n" + _nginx_port80_block() + "}\n"
        "decide\n"
        "echo DECIDED\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    return proc, touched.read_text(encoding="utf-8")


def test_nginx_port80_listener_is_left_alone_when_ss_cannot_be_asked(tmp_path):
    """`! port_free 80` citea un `ss` rupt ca «portul 80 e ocupat» și mergea mai
    departe să scoată din funcțiune listener-ul :80 al nginx-ului — o editare
    reală de configurație pe gazda operatorului, decisă dintr-un ne-fapt. Pe
    «necunoscut» nu se atinge nimic, se spune că e necunoscut, iar blocul
    ajunge la capăt (sub `set -e` un 2 netratat l-ar fi oprit)."""
    proc, touched = _run_port80_block(tmp_path, SS_FAILS)
    out = proc.stdout + proc.stderr
    assert "DECIDED" in proc.stdout, f"blocul s-a oprit la un 2 netratat: {out}"
    assert "could not be determined" in proc.stderr and "UNKNOWN" in proc.stderr, out
    assert touched == "", f"a atins configurația nginx pe un port nemăsurat: {touched!r}"


def test_nginx_port80_listener_is_still_disabled_when_something_really_holds_it(tmp_path):
    """Contra-proba: cu :80 chiar ocupat și un nginx pe care l-am instalat noi,
    comportamentul dinainte rămâne — altfel «nu atinge pe necunoscut» ar fi
    devenit «nu atinge niciodată»."""
    proc, touched = _run_port80_block(
        tmp_path, f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n')
    assert "DECIDED" in proc.stdout, proc.stdout + proc.stderr
    assert "disable" in touched, touched


def test_nginx_port80_preexisting_nginx_is_never_touched_even_when_held(tmp_path):
    """Un nginx care era deja acolo e al operatorului: ocupat + preexistent ->
    avertisment, nimic atins."""
    proc, touched = _run_port80_block(
        tmp_path, f'printf "%s\\n" "{SS_LISTEN_LINE}"\nexit 0\n', preexisting="1")
    assert "Not touching" in proc.stderr and touched == "", (proc.stderr, touched)


def test_nginx_port80_free_port_says_nothing_and_touches_nothing(tmp_path):
    """Contra-proba pentru tăcerea cinstită: :80 liber măsurat -> niciun
    avertisment «necunoscut» (altfel fiecare instalare curată ar urla)."""
    proc, touched = _run_port80_block(tmp_path, "exit 0\n")
    assert "DECIDED" in proc.stdout and touched == "", (proc.stdout, touched)
    assert "UNKNOWN" not in proc.stderr and "could not be determined" not in proc.stderr


# ===========================================================================
# preflight.sh — «nu s-a putut verifica» e o constatare, nu o trecere
# ===========================================================================
def _block(text: str, start_line: str, end_line: str, must_contain: str) -> str:
    """Un bloc LIVRAT, de la un rând exact până la primul `end_line` exact.
    Extragerea e verificată imediat: o felie ruptă ar produce un shell care nu
    rulează, iar una goală ar face fiecare test de mai jos să treacă fără să
    verifice nimic."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln == start_line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == end_line)
    block = "\n".join(lines[start:end + 1])
    assert must_contain in block
    return block + "\n"


def _ports_block() -> str:
    return _block(PREFLIGHT, 'for port in "${SENTINEL_PORTS[@]}"; do', "done", "port_owner_unit")


def _p80_443_block() -> str:
    return _block(PREFLIGHT, "for port in 80 443; do", "done", "liber")


def _certbot_hint_block() -> str:
    return _block(PREFLIGHT, 'owner80="$(port_owner 80)"', "fi", "HTTP-01")


def _preflight_run(tmp_path: Path, block: str, ss_body: str, pre: str = ""):
    binpath, _ = _ss_stub(tmp_path, ss_body)
    script = (
        "set -euo pipefail\nsource ./lib/common.sh\n" + pre + block
        + 'printf "COUNTS %d %d\\n" "$FAIL_COUNT" "$WARN_COUNT"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, "blocul s-a oprit sub set -e:\n" + proc.stdout + proc.stderr
    counts = next(ln for ln in proc.stdout.splitlines() if ln.startswith("COUNTS"))
    _, fails, warns = counts.split()
    return int(fails), int(warns), proc.stdout + proc.stderr


def test_preflight_ports_says_it_could_not_look_instead_of_free(tmp_path):
    """Cu `ss` rupt, preflight-ul tipărea «port 8443 free / port 8787 free /
    port 5432 free» și ieșea cu 0 — trei afirmații despre o gazdă pe care nu se
    măsurase nimic, urmate de o instalare care are nevoie de ACELAȘI `ss`
    mai târziu. Trebuie să fie o constatare blocantă (FAIL_COUNT), fără nicio
    linie de succes."""
    fails, _, out = _preflight_run(tmp_path, _ports_block(), SS_FAILS)
    assert fails >= 3, f"FAIL_COUNT={fails} — porturile n-au fost raportate ca neverificate: {out}"
    assert "port 8443 free" not in out and "[+]" not in out, out
    assert "UNKNOWN" in out and "ss -tlnH" in out, out


def test_preflight_names_a_bad_port_value_instead_of_blaming_iproute2(tmp_path):
    """`--web-port 70000` ajungea în SENTINEL_PORTS, iar preflight-ul pe o
    gazdă cu `ss` bun tipărea «install iproute2». Constatarea numește VALOAREA,
    iar celelalte porturi, care chiar au fost măsurate, rămân raportate normal."""
    fails, _, out = _preflight_run(
        tmp_path, _ports_block(), "exit 0\n", pre="SENTINEL_PORTS=(70000 8787 5432)\n")
    assert fails >= 1 and "70000" in out and "not a usable port number" in out, out
    assert "iproute2" not in out, out
    assert "port 8787 free" in out and "port 5432 free" in out, out


def test_preflight_ports_still_passes_on_a_host_where_nothing_listens(tmp_path):
    """Contra-proba: un `ss` care merge și nu găsește nimic -> trece, ca înainte.
    Fără ea, o poartă scrisă greșit ar transforma orice instalare curată într-un
    refuz."""
    fails, _, out = _preflight_run(tmp_path, _ports_block(), "exit 0\n")
    assert fails == 0 and "port 8443 free" in out, out


def test_preflight_ports_still_fails_on_a_port_a_stranger_holds(tmp_path):
    """Un port chiar ocupat de altcineva rămâne o constatare blocantă, cu portul
    numit — comportamentul dinainte, care nu are voie să se piardă în tri-stare."""
    fails, _, out = _preflight_run(
        tmp_path, _ports_block(),
        'case "$*" in\n'
        f'  *8443*) printf "%s\\n" "{SS_LISTEN_LINE}" ;;\n'
        'esac\nexit 0\n')
    assert fails >= 1 and "8443" in out and "in use" in out, out


def test_preflight_80_and_443_are_not_reported_free_when_ss_cannot_look(tmp_path):
    """Porturile 80/443 sunt informative (`warn`, nu `fail`), dar «liber» spus
    fără măsurătoare trimite operatorul spre webroot pe un port pe care nu l-a
    văzut nimeni."""
    _fails, warns, out = _preflight_run(tmp_path, _p80_443_block(), SS_FAILS)
    assert warns >= 2 and "NECUNOSCUT" in out, out
    assert "liber" not in out.replace("nu liber", ""), f"a spus «liber» fără măsurătoare: {out}"


def test_preflight_80_and_443_still_say_free_when_ss_measured_it(tmp_path):
    """Contra-proba: măsurat și liber -> «liber», fără avertisment."""
    _, warns, out = _preflight_run(tmp_path, _p80_443_block(), "exit 0\n")
    assert warns == 0 and "port 80 liber" in out, out


def test_the_certbot_hint_is_not_given_when_ss_cannot_look(tmp_path):
    """Sfatul «nimic nu ascultă pe :80, deci HTTP-01 nu e disponibil» era dat și
    când `ss` nu putea fi întrebat deloc — pe o gazdă unde nginx ține :80 de
    ani, operatorul era trimis spre DNS-01 sau self-signed pentru nimic."""
    _, warns, out = _preflight_run(tmp_path, _certbot_hint_block(), SS_FAILS)
    assert warns >= 1 and "NECUNOSCUT" in out, out
    assert "nimic nu ascultă pe :80" not in out, out


def test_the_certbot_hint_is_still_given_when_nothing_really_listens(tmp_path):
    """Contra-proba: măsurat liber -> sfatul apare, e util și corect acolo."""
    _, warns, out = _preflight_run(tmp_path, _certbot_hint_block(), "exit 0\n")
    assert warns >= 1 and "nimic nu ascultă pe :80" in out, out


# ---------------------------------------------------------------------------
# Brațele blocului de sfat certbot: fiecare condiție care deosebește un braț
# de vecinul lui trebuie să aibă un test care o vede dispărând.
# ---------------------------------------------------------------------------
NGINX_OWNER_LINE = (
    'LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    '
    'users:(("nginx",pid=1234,fd=6))'
)


def _say(line: str) -> str:
    """Comanda de shell care tipărește `line` (sau nimic, dacă e goală)."""
    return f"printf '%s\\n' '{line}'" if line else ":"


def _ss_by_query(*, tcp: str = "", tcp_owner: str = "", udp: str = "",
                 tcp_fails: bool = False) -> str:
    """O momeală `ss` care răspunde DIFERIT la cele trei întrebări pe care le
    pune blocul: `-tlnH` (port_free, tcp), `-ulnH` (port_free, udp) și
    `-tlnpH` (port_owner). Un singur `ss` care răspunde la fel la toate trei nu
    poate reprezenta exact situațiile în care `port_free` și `port_owner` nu
    sunt de acord — iar în ele stă fiecare condiție de mai jos."""
    return (
        'case "$*" in\n'
        f"  *-tlnpH*) {_say(tcp_owner)} ;;\n"
        f"  *-tlnH*)  {'exit 1' if tcp_fails else _say(tcp)} ;;\n"
        f"  *-ulnH*)  {_say(udp)} ;;\n"
        "esac\nexit 0\n"
    )


@pytest.mark.parametrize("ss_body", [
    pytest.param(_ss_by_query(udp=SS_UDP_LINE), id="listener-udp-pe-80-fara-proprietar-tcp"),
    pytest.param(_ss_by_query(tcp=SS_LISTEN_LINE), id="listener-tcp-pe-80-proprietar-ascuns"),
])
def test_the_certbot_hint_is_not_given_when_80_is_held_but_the_owner_is_unknown(tmp_path, ss_body):
    """`port_owner` întreabă doar tcp și poate rămâne gol pe un :80 ținut (un
    listener doar udp; un proces pe care `ss` nu are voie să-l numească).
    Sfatul «nimic nu ascultă pe :80 … DNS-01 sau self-signed» se bazează pe
    `owner gol`, deci fără condiția `port80_state == 0` ar apărea tocmai pe un
    port pe care cineva ÎL ȚINE, iar operatorul ar renunța la certbot pentru o
    constatare falsă (și WARN_COUNT ar crește)."""
    _, warns, out = _preflight_run(tmp_path, _certbot_hint_block(), ss_body)
    assert "deține :80" in out, f"blocul n-a ajuns la niciun braț cunoscut: {out}"
    assert "nimic nu ascultă pe :80" not in out and "DNS-01 sau self-signed" not in out, out
    assert "NECUNOSCUT" not in out, f"ss a răspuns, deci nu e necunoscut: {out}"
    assert warns == 0, f"WARN_COUNT={warns}: {out}"


def test_the_unknown_arm_is_not_taken_when_the_owner_is_known(tmp_path):
    """Dacă `port_owner` a numit deja nginx, «nu se poate stabili cine deține
    :80» e fals — owner-ul e numit chiar sub ochii operatorului — chiar dacă un
    `port_free` ulterior n-a putut întreba (stare trecătoare). Brațul
    «necunoscut» se ia doar cu owner gol."""
    ss = _ss_by_query(tcp_owner=NGINX_OWNER_LINE, tcp_fails=True)
    _, warns, out = _preflight_run(
        tmp_path, _certbot_hint_block(), ss, pre="nginx() { return 0; }\n")
    assert "nginx deține :80" in out, f"owner-ul numit nu s-a văzut: {out}"
    assert "nu se poate stabili cine deține :80" not in out, out
    assert warns == 0, f"WARN_COUNT={warns}: {out}"


def test_the_nothing_listens_arm_is_not_taken_when_the_owner_is_known(tmp_path):
    """Dacă `port_owner` a numit nginx, «nimic nu ascultă pe :80» e fals chiar
    dacă `port_free` a răspuns «liber» (un listener care a apărut între cele
    două întrebări). Brațul «nimic nu ascultă» cere owner gol ȘI port liber."""
    ss = _ss_by_query(tcp_owner=NGINX_OWNER_LINE)
    _, warns, out = _preflight_run(
        tmp_path, _certbot_hint_block(), ss, pre="nginx() { return 0; }\n")
    assert "nginx deține :80" in out, f"owner-ul numit nu s-a văzut: {out}"
    assert "nimic nu ascultă pe :80" not in out, out
    assert warns == 0, f"WARN_COUNT={warns}: {out}"


def test_an_nginx_owner_gets_the_shared_mode_advice_and_a_failing_nginx_t_fails(tmp_path):
    """Brațul nginx e singurul care poate face preflight-ul să pice pe :80: un
    nginx care deține portul dar al cărui `nginx -t` eșuează înseamnă că modul
    `shared` ar scrie într-un config rupt. Fără el (sau fără `fail`), operatorul
    ar primi sfatul «--nginx-mode shared» pe o gazdă unde nu are voie."""
    ss = _ss_by_query(tcp=SS_LISTEN_LINE, tcp_owner=NGINX_OWNER_LINE)
    fails, _, out = _preflight_run(
        tmp_path, _certbot_hint_block(), ss, pre="nginx() { return 0; }\n")
    assert fails == 0 and "--nginx-mode shared" in out and "nginx -t trece" in out, out
    (tmp_path / "rupt").mkdir()
    fails, _, out = _preflight_run(
        tmp_path / "rupt", _certbot_hint_block(), ss, pre="nginx() { return 1; }\n")
    assert fails == 1 and "nginx -t EȘUEAZĂ" in out and "nginx -t trece" not in out, out


def test_a_non_nginx_owner_gets_the_webroot_advice_and_no_shared_mode_advice(tmp_path):
    """Un alt proprietar al lui :80 (apache2) primește sfatul de webroot/DNS-01,
    numit după el; sfatul «--nginx-mode shared» și verificarea `nginx -t` n-au
    ce căuta acolo — ar trimite operatorul să scrie într-un nginx care nu
    servește portul."""
    apache = ('LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    '
              'users:(("apache2",pid=77,fd=4))')
    ss = _ss_by_query(tcp=SS_LISTEN_LINE, tcp_owner=apache)
    fails, warns, out = _preflight_run(
        tmp_path, _certbot_hint_block(), ss, pre="nginx() { return 1; }\n")
    assert "apache2" in out and "deține :80" in out and "acme-challenge" in out, out
    assert "--nginx-mode shared" not in out and "nginx -t" not in out, out
    assert fails == 0 and warns == 0, f"fails={fails} warns={warns}: {out}"
