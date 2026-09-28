"""Directorul de marcaje de instalare nu mai stă sub arborele deținut de `sentinel`.

Măsurat pe 8 septembrie 2026: `STATE_MARKERS` era
`/var/lib/sentinel/.install-state`, iar `/var/lib/sentinel` e `0750
sentinel:sentinel` (`step_user_and_dirs`, ca să poată scrie `geoip/` și
`cursors/` — starea proprie de rulare). Același bit de scriere pe PĂRINTE îi
dă și dreptul să redenumească `.install-state` din drum și să planteze acolo
propriul `preflight.env` — reprodus într-un namespace Linux, fiindcă
redenumirea cere doar scriere pe director, nu pe fișierul înlocuit.
`resolve_config` din `deploy/install.sh` face `source` peste fișierul ăla ca
root, la FIECARE rulare — deci un `preflight.env` plantat e execuție de cod
arbitrar ca root. La o actualizare, pasul 1 (care ar fi rescris fișierul dintr-o
verificare de încredere) e marcat deja făcut și e sărit, deci nimic nu-l
reîmprospătează înainte de acel `source`.

Reparația are DOUĂ bucăți, nu trei — a treia (o migrare care mută marcajele
vechi în noul director) a fost încercată în trei runde (8-9 septembrie 2026),
fiecare respinsă printr-un ocolire diferit al aceleiași forme: un symlink
plantat la calea veche, un director root-owned redenumit peste calea veche, un
symlink plantat la calea NOUĂ. Fiecare reparație a închis exact ocolirea
rundei anterioare și nici una alta — semn că problema nu era „verificarea nu
e suficient de strictă", ci forma însăși: un proces root luând o decizie de
încredere, din rezultate de `stat`, despre ceva aflat într-un director pe care
un cont mai puțin privilegiat îl poate redenumi ORICÂND, inclusiv între
verificare și folosire. Decizia (13 septembrie 2026, vezi docs/ARHITECTURA.md):
directorul vechi NU se mai citește deloc, de nimic din acest fișier sau din
`install.sh`, migrare sau altfel. Ce era acolo dinainte e tratat ca absent, nu
mutat și nu „spălat" doar fiindcă a fost redenumit — nimic aflat sub un
director scriibil de `sentinel` n-a fost vreodată suficient de încrezător ca
să fie promovat într-unul root-only doar fiindcă a fost mutat.

  * `STATE_MARKERS` mută în afara `SENTINEL_STATE_DIR`, într-un director
    dedicat, creat de instalator ca root, 0700 — nu prin tmpfiles (unitatea
    aia aparține altui scriitor azi). Părintele lui (`/var/lib`) e el însuși
    root-owned, ceea ce închide structural ruta de scriere pe care se sprijineau
    toate cele trei ocoliri, nu doar cazurile deja văzute.
  * un refuz explicit, verificat cu `stat`, înainte de orice `source` peste
    un fișier din acest director — „nu pot verifica" se tratează la fel ca
    „proprietar greșit", niciodată ca „e curat". Rămâne util și fără migrare:
    apără un `$STATE_MARKERS` lăsat mai larg de o versiune veche, nu doar
    conținutul mutat dintr-o migrare care nu mai există.

Costul acceptat, scris ca atare: o gazdă care se actualizează peste această
reparație are markerele „pierdute" (nimic la calea nouă), deci fiecare pas
gardat de marcaj rulează din nou o dată. Fiecare pas e scris să fie sigur la
o rerulare — vezi „Idempotency" din `deploy/lib/common.sh`. SINGURUL loc unde
o rerulare NU e un no-op e faptul (`fact`) `nginx_preexisting`, write-once —
acela are propriul lui mecanism de compatibilitate, testat separat în
`tests/security/test_installer_nginx_preexisting.py`, care citește direct
calea veche (nu o migrare: un `grep`/`head -c` mărginit la o valoare „0"/"1",
niciodată un `source`).

Fiecare test rulează funcțiile LIVRATE din `deploy/lib/common.sh` și
`deploy/install.sh`, nu o reimplementare a lor.
"""
from __future__ import annotations

import os
import re
import shutil
import stat as stat_module
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
COMMON = COMMON_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipsește din PATH — netestat, nu curat")]


def _func(source: str, name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _p(path: Path) -> str:
    """O cale pe care bash-ul din Git Bash o acceptă, indiferent de gazdă."""
    return str(path).replace("\\", "/")


def _write_stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)
    return path


def _run(script: str, tmp_path: Path, extra_path: Path | None = None) -> subprocess.CompletedProcess:
    harness = tmp_path / "harness.sh"
    harness.write_text(script, encoding="utf-8", newline="\n")
    env = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        env["PATH"] = _p(extra_path) + os.pathsep + env.get("PATH", "")
    return subprocess.run(
        [BASH, _p(harness)], cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )


# ---------------------------------------------------------------------------
# Locul — nu mai e sub arborele lui `sentinel`
# ---------------------------------------------------------------------------
def test_state_markers_is_not_defined_from_sentinel_state_dir():
    """Sursa, citită direct: `STATE_MARKERS` nu are voie să deriveze din
    `SENTINEL_STATE_DIR` — acela e `/var/lib/sentinel`, 0750 sentinel:sentinel.
    Falsificat revenind la `STATE_MARKERS="${SENTINEL_STATE_DIR}/.install-state"`.
    """
    match = re.search(r'^STATE_MARKERS="([^"]*)"\s*$', COMMON, re.M)
    assert match, "STATE_MARKERS nu mai e atribuit direct în deploy/lib/common.sh"
    assert "SENTINEL_STATE_DIR" not in match.group(1), (
        f"STATE_MARKERS derivă din SENTINEL_STATE_DIR ({match.group(1)!r}) — "
        f"directorul ăla e scriibil de contul de serviciu")


def test_state_markers_resolves_outside_var_lib_sentinel_at_runtime(tmp_path):
    """Nu doar textul sursă — comportamentul la rulare. Simpla sursare a lui
    `common.sh`, fără nicio suprascriere de mediu, trebuie să pună
    `$STATE_MARKERS` altundeva decât sub `/var/lib/sentinel`."""
    proc = _run('source ./lib/common.sh\nprintf "%s" "$STATE_MARKERS"\n', tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    path = proc.stdout.strip()
    assert not path.startswith("/var/lib/sentinel/"), path
    assert path != "/var/lib/sentinel", path


# ---------------------------------------------------------------------------
# Un harness care redirecteaza un singur SENTINEL_*_DIR e refuzat, nu tacut
# ---------------------------------------------------------------------------
def test_overriding_sentinel_state_dir_alone_is_refused(tmp_path):
    """Un harness care suprascrie `SENTINEL_STATE_DIR` dar uita
    `SENTINEL_INSTALL_STATE_DIR` ar lăsa `STATE_MARKERS` să indice tot spre
    `/var/lib/sentinel-install` REAL de pe mașina care rulează testul — scriind
    marcaje de instalare, ca root, pe gazdă, nu în sandbox-ul harness-ului. Ăsta
    a fost un bug viu în propria suită a acestui repository, la câteva zile după
    ce STATE_MARKERS a încetat să mai fie sub SENTINEL_STATE_DIR. Falsificat
    scoțând blocul `if ... die` din `deploy/lib/common.sh` — testul trebuie să
    vadă `SOURCED_OK`, care e exact ce n-are voie să se întâmple.
    """
    fake_state = tmp_path / "state"
    proc = _run(
        "set -uo pipefail\n"
        f'export SENTINEL_STATE_DIR="{_p(fake_state)}"\n'
        "source ./lib/common.sh\n"
        'echo "SOURCED_OK"\n',
        tmp_path)
    assert proc.returncode != 0, (
        "sursarea a continuat cu SENTINEL_STATE_DIR redirectat singur: "
        + proc.stdout + proc.stderr)
    assert "SOURCED_OK" not in proc.stdout, proc.stdout
    assert "SENTINEL_INSTALL_STATE_DIR is not" in proc.stderr, (
        f"die() n-a spus care variabilă lipsește: {proc.stderr!r}")


def test_overriding_both_sentinel_state_dirs_together_is_accepted(tmp_path):
    """Cazul pozitiv: un harness care redirectează AMBELE variabile (exact ce
    face restul acestei suite) nu trebuie să pice pe garda de mai sus — altfel
    garda ar opri și configurația validă, nu doar pe cea pe jumătate
    redirectată."""
    fake_state = tmp_path / "state"
    fake_install = tmp_path / "install-state"
    proc = _run(
        "set -uo pipefail\n"
        f'export SENTINEL_STATE_DIR="{_p(fake_state)}"\n'
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(fake_install)}"\n'
        "source ./lib/common.sh\n"
        'echo "SOURCED_OK"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SOURCED_OK" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# Verificarea de proprietate — refuz, nu reparație tăcută
# ---------------------------------------------------------------------------
def _stat_stub(directory: Path, *, file_owner: str, parent_owner: str, parent_mode: str,
               fail_on: str | None = None) -> Path:
    """`stat` fals: răspunde diferit după calea interogată, fără să atingă vreun
    fișier real. `%3` e calea; deciziile din `assert_root_owned_state_file` se
    iau din răspunsurile astea, nu din permisiunile reale de pe mașina de test —
    ceea ce contează aici e LOGICA funcției, nu dacă `chmod 0700` chiar prinde pe
    un NTFS montat prin Git Bash.
    """
    body = f'''
fmt="$2"; path="$3"
case "$path" in
    *preflight.env)
        [[ "{fail_on or ""}" == "file" ]] && exit 1
        [[ "$fmt" == "%u" ]] && echo "{file_owner}" && exit 0
        echo 700 ; exit 0 ;;
    *)
        [[ "{fail_on or ""}" == "parent" ]] && exit 1
        [[ "$fmt" == "%u" ]] && echo "{parent_owner}" && exit 0
        echo "{parent_mode}" ; exit 0 ;;
esac
'''
    return _write_stub(directory, "stat", body).parent


def _assert_check(tmp_path: Path, **stub_kwargs) -> subprocess.CompletedProcess:
    stubs = tmp_path / "bin"
    _stat_stub(stubs, **stub_kwargs)
    env_file = tmp_path / "state" / "preflight.env"
    return _run(
        "source ./lib/common.sh\n"
        + _func(COMMON, "assert_root_owned_state_file") + "\n"
        + f'if assert_root_owned_state_file "{_p(env_file)}"; then echo ACCEPTED; else echo REFUSED; fi\n',
        tmp_path, extra_path=stubs)


def test_a_genuinely_root_owned_file_is_accepted(tmp_path):
    """Cazul pozitiv contează la fel de mult: dacă funcția ar respinge orice,
    fiecare instalare reală ar muri la `resolve_config`, iar testele de refuz de
    mai jos n-ar dovedi nimic despre discriminare."""
    proc = _assert_check(tmp_path, file_owner="0", parent_owner="0", parent_mode="700")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ACCEPTED" in proc.stdout, proc.stdout


def test_a_file_not_owned_by_root_is_refused(tmp_path):
    """Cazul confirmat: un `preflight.env` plantat de contul `sentinel` e deținut
    de `sentinel`, nu de root — indiferent cât de restrictiv e directorul care îl
    conține. Falsificat scoțând verificarea proprietarului FIȘIERULUI din
    `assert_root_owned_state_file`."""
    proc = _assert_check(tmp_path, file_owner="1000", parent_owner="0", parent_mode="700")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stdout, proc.stdout


def test_a_parent_directory_not_owned_by_root_is_refused(tmp_path):
    """Fișierul poate fi root, dar dacă DIRECTORUL care-l conține nu e root,
    proprietarul fișierului nu mai dovedește nimic — oricine deține directorul
    poate să-l șteargă și să pună altul cu același nume, deținut de root prin
    `chown` după ce l-a scris. Falsificat scoțând verificarea părintelui."""
    proc = _assert_check(tmp_path, file_owner="0", parent_owner="1000", parent_mode="700")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stdout, proc.stdout


def test_a_parent_directory_looser_than_0700_is_refused(tmp_path):
    """0750 sentinel:sentinel e exact modul care a permis atacul inițial — chiar
    dacă proprietarul PĂRINTELUI ar fi root, un mod mai larg tot lasă alt cont
    din același grup să scrie acolo. Falsificat relaxând comparația la `<= 0700`
    sau scoțând-o cu totul."""
    proc = _assert_check(tmp_path, file_owner="0", parent_owner="0", parent_mode="750")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stdout, proc.stdout


def test_an_unreadable_file_is_refused_not_treated_as_clean(tmp_path):
    """„Nu pot verifica" nu e „e curat" — regula din CLAUDE.md, aplicată aici:
    dacă `stat` însuși eșuează (permisiuni, dispariție cursă), funcția trebuie să
    refuze, nu să treacă mai departe presupunând că totul e în regulă."""
    proc = _assert_check(tmp_path, file_owner="0", parent_owner="0", parent_mode="700",
                         fail_on="file")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# resolve_config chiar cheamă verificarea, înainte de `source`
# ---------------------------------------------------------------------------
def _resolve_config_head() -> str:
    """`resolve_config` până la `source "$env_file"` inclusiv — nu tot corpul.

    Restul funcției cere `ssh_peer_ip`, `NGINX_MODE`, `PUBLIC_PORT` complet
    configurate; niciuna din ele nu contează pentru „a fost chemată verificarea
    înainte de source", care e singurul lucru testat aici.
    """
    body = _func(INSTALL, "resolve_config")
    head, sep, _ = body.partition(
        '    # Safe defaults for anything preflight did not provide')
    assert sep, "resolve_config nu mai are marcajul folosit ca să tai funcția aici"
    return head + "}\n"


def test_resolve_config_dies_before_sourcing_a_non_root_owned_preflight_env(tmp_path):
    """Testul cerut de audit, direct pe `resolve_config`, nu doar pe funcția
    ajutătoare: un `preflight.env` care nu trece verificarea de proprietate nu
    trebuie NICIODATĂ sursat — `die` oprește execuția înainte de acea linie.

    Falsificat scoțând apelul `assert_root_owned_state_file ... || die ...` din
    `resolve_config` — testul trebuie să vadă `SOURCED`, care e exact ce nu are
    voie să se întâmple.
    """
    state = tmp_path / "state"
    state.mkdir()
    env_file = state / "preflight.env"
    env_file.write_text("SOURCED_MARKER=1\n", encoding="utf-8", newline="\n")

    stubs = tmp_path / "bin"
    _stat_stub(stubs, file_owner="1000", parent_owner="0", parent_mode="700")

    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        'ADMIN_IP=""; DOMAIN=""; PUBLIC_PORT=""\n'
        "source ./lib/common.sh\n"
        + _resolve_config_head() + "\n"
        "resolve_config\n"
        'echo "SOURCED=${SOURCED_MARKER:-absent}"\n'
    )
    proc = _run(script, tmp_path, extra_path=stubs)
    assert proc.returncode != 0, (
        "resolve_config a continuat după un preflight.env respins" + proc.stdout)
    assert "SOURCED=1" not in proc.stdout, \
        f"preflight.env a fost sursat deși proprietarul lui a fost respins: {proc.stdout!r}"
    assert "refusing to source" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr



# ---------------------------------------------------------------------------
# ensure_state_markers_dir -- invocarea EXACTA, nu doar rezultatul pe disc
# ---------------------------------------------------------------------------
def test_ensure_state_markers_dir_installs_with_the_exact_mode_owner_group(tmp_path):
    """Verificat pe INVOCARE, nu pe modul directorului de pe disc -- pe Windows,
    fara root real, un chmod 0700 pe NTFS "reuseste" nominal indiferent ce a
    fost cerut, deci un test care doar citeste modul rezultat ar trece si cu
    install -d -m 0755 sau chiar cu un mkdir -p care nu cere deloc 0700.

    id e falsificat sa spuna "sunt root", ca ramura reala (install -d -m
    0700 -o root -g root) sa ruleze; install e falsificat sa-si
    INREGISTREZE argumentele, nu sa faca nimic.

    Falsificat schimband -m 0700 in -m 0755 in ensure_state_markers_dir
    -- testul trebuie sa pice pe linia inregistrata, diferita de cea asteptata.
    """
    stubs = tmp_path / "bin"
    _write_stub(stubs, "id", 'if [[ "$1" == "-u" ]]; then echo 0; else echo root; fi\n')
    log = tmp_path / "install.log"
    _write_stub(stubs, "install", f'printf "%s\\n" "$*" >> "{_p(log)}"\nexit 0\n')

    new_dir = tmp_path / "state"
    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(new_dir)}"\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
    )
    proc = _run(script, tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert calls, "install (calea de root) nu a fost chemat deloc"
    want = f'-d -m 0700 -o root -g root {_p(new_dir)}'
    assert calls[-1] == want, f"invocarea lui install nu e cea exacta: {calls[-1]!r} != {want!r}"


def test_ensure_state_markers_dir_is_never_satisfied_by_a_bare_mkdir(tmp_path):
    """Regresie directa: un mkdir -p fara install -d n-are cum sa forteze
    modul/proprietarul unui director care exista deja mai larg -- dovedit AICI
    prin faptul ca, sub root fals, functia livrata tot cheama install, nu
    doar mkdir. mkdir e falsificat sa iasa cu eroare daca e chemat, ca
    orice apel catre el pe ramura de root sa opreasca testul.

    Falsificat inlocuind ramura de root din ensure_state_markers_dir cu
    mkdir -p "$STATE_MARKERS" -- testul trebuie sa vada iesirea non-zero de
    la mkdir-ul falsificat.
    """
    stubs = tmp_path / "bin"
    _write_stub(stubs, "id", 'if [[ "$1" == "-u" ]]; then echo 0; else echo root; fi\n')
    # install e falsificat separat, sa reuseasca fara sa ceara un utilizator
    # root REAL (masina de test n-are unul) -- altfel un install -o root
    # real ar pica oricum, iar testul n-ar mai dovedi nimic despre mkdir.
    _write_stub(stubs, "install", 'exit 0\n')
    _write_stub(stubs, "mkdir",
                'echo "mkdir was called on the root branch -- must be install -d" >&2\nexit 98\n')

    new_dir = tmp_path / "state"
    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(new_dir)}"\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
    )
    proc = _run(script, tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# ensure_state_markers_dir -- un symlink la calea NOUA nu e urmat
# ---------------------------------------------------------------------------
def _symlink_capable(tmp_path: Path) -> bool:
    """Sonda reala, nu presupunere: pe Windows fara Developer Mode/privilegiu
    SeCreateSymbolicLinkPrivilege, Path.symlink_to ridica OSError
    [WinError 1314] -- verificat direct pe masina asta de dezvoltare, care NU
    are privilegiul. Testul de mai jos se sare (nu trece "din intamplare")
    acolo unde sonda arata ca nu se poate proba nimic."""
    target = tmp_path / "_symprobe_target"
    link = tmp_path / "_symprobe_link"
    target.mkdir()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return False
    return link.is_symlink()


def test_ensure_state_markers_dir_refuses_a_symlink_at_the_new_path(tmp_path):
    """install -d/chmod/chown pe o cale EXISTENTA urmeaza un symlink --
    aplica modul/proprietarul tintei, nu linkului. Daca SENTINEL_INSTALL_STATE_DIR
    ar ajunge vreodata un symlink (plantat inainte ca acest director sa existe),
    ensure_state_markers_dir ar face 0700 root:root peste ORICE arata linkul,
    tacut. Verificat cu un symlink REAL ([[ -L ]], testul care conteaza aici,
    e un builtin bash -- nu poate fi falsificat printr-un stat fals ca restul
    fisierului).

    Falsificat scotand verificarea [[ -L "$STATE_MARKERS" ]] de la inceputul
    lui ensure_state_markers_dir -- testul trebuie sa vada iesire 0 si tinta
    linkului atinsa.
    """
    if not _symlink_capable(tmp_path):
        pytest.skip("mediul asta nu poate crea symlinkuri reale (fara "
                    "SeCreateSymbolicLinkPrivilege) -- netestat, nu trecut")

    target = tmp_path / "elsewhere"
    target.mkdir()
    link_path = tmp_path / "state"
    link_path.symlink_to(target, target_is_directory=True)
    before_mode = None
    try:
        import stat as _st
        before_mode = _st.S_IMODE(target.stat().st_mode)
    except OSError:
        pass

    script = (
        "set -uo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(link_path)}"\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
        'echo "RC=$?"\n'
    )
    proc = _run(script, tmp_path)
    assert "RC=0" not in proc.stdout, (
        f"ensure_state_markers_dir a continuat peste un symlink: {proc.stdout + proc.stderr}")
    assert link_path.is_symlink(), "linkul a fost inlocuit, nu doar refuzat"
    if before_mode is not None:
        import stat as _st
        assert _st.S_IMODE(target.stat().st_mode) == before_mode, (
            "tinta linkului a fost chmod-uita desi functia trebuia sa refuze inainte de asta")


# ---------------------------------------------------------------------------
# Nicio migrare -- decizia de proiectare din 13 septembrie 2026
# ---------------------------------------------------------------------------
# Trei runde (8-9 septembrie 2026) au incercat sa faca sigura o mutare a
# marcajelor vechi in noul director, fiecare respinsa printr-un ocolire diferit
# al aceleiasi forme (symlink la calea veche, director root-owned redenumit
# peste calea veche, symlink la calea NOUA). Reparatia din 13 septembrie 2026
# scoate mecanismul: nimic din deploy/lib/common.sh sau deploy/install.sh nu
# mai citeste calea veche pentru o decizie de incredere. Testele de mai jos
# dovedesc absenta, nu doar o versiune mai stricta a aceleiasi verificari.

def test_migrate_legacy_state_markers_and_its_helpers_no_longer_exist():
    """Functia si fiecare ajutor al ei trebuie sa fi disparut din sursa, nu doar
    sa nu mai fie chemate -- un helper ramas mort e exact genul de cod pe care
    cineva il re-conecteaza peste sase luni fara sa reciteasca istoricul.

    Falsificat lasand definitia lui migrate_legacy_state_markers (sau a
    oricarui ajutor) in deploy/lib/common.sh -- testul trebuie s-o vada.
    """
    removed_symbols = [
        "migrate_legacy_state_markers", "_migrate_legacy_pass",
        "_migrate_legacy_facts", "_legacy_place", "_legacy_finish_move",
        "_legacy_facts_dir_trusted", "_legacy_file_trusted",
        "_LEGACY_ENTRY_NAME_ALLOWED",
    ]
    present = [name for name in removed_symbols
               if re.search(rf"^{re.escape(name)}\s*\(\)", COMMON, re.M)]
    assert present == [], f"functii de migrare inca definite in common.sh: {present}"


def test_main_never_calls_migrate_legacy_state_markers():
    """Chiar daca functia ar reaparea cumva (un revert partial, un copy-paste
    dintr-o ramura veche), main() nu are voie s-o cheme -- testul de mai sus
    apara DEFINITIA, asta apara APELUL, separat."""
    assert "migrate_legacy_state_markers" not in INSTALL, \
        "install.sh inca mentioneaza migrate_legacy_state_markers undeva"


def _logging_stat_stub(bin_dir: Path, log: Path) -> Path:
    """stat real (delegat la binarul de sistem), care in plus scrie fiecare
    cale interogata -- dovada ceruta de verificator: nu "arata curat", ci
    "n-a fost interogat deloc". Foloseste binarul stat real ca sa nu trebuiasca
    reimplementat %u/%F/%a peste tot ce cheama install.sh.
    """
    real_stat = shutil.which("stat")
    assert real_stat, "stat lipseste din PATH -- nu se poate construi sonda"
    body = (
        'printf "%s\n" "$*" >> "' + _p(log) + '"\n'
        'exec "' + _p(Path(real_stat)) + '" "$@"\n'
    )
    return _write_stub(bin_dir, "stat", body).parent


def test_resolve_config_never_stats_the_legacy_path_before_sourcing_preflight_env(tmp_path):
    """Ce ruleaza NECONDITIONAT la inceputul lui main() acum: ensure_state_markers_dir,
    apoi CAPUL lui resolve_config pana la (si incluzand) source-ul lui
    preflight.env — care e singurul loc din ACEA portiune ce cheama binarul
    extern `stat` (`assert_root_owned_state_file`). Proba se opreste inainte
    de restul lui resolve_config, deci nu acopera apelul catre
    nginx_preexisting_resolve: acela citeste calea veche cu `[[ -f ]]`, un
    builtin bash pe care o sonda externa de `stat` nu-l poate vedea oricum,
    indiferent ce s-ar chema acolo — testul asta nu dovedeste nimic despre
    acea functie, doar despre portiunea de dinaintea ei. Proba ceruta de
    verificator, cu o sonda care inregistreaza, nu presupune: fiecare cale
    interogata prin stat, PANA la acel punct, ajunge in jurnal, iar calea
    veche nu are voie sa apara in el, indiferent ce contine.

    Un preflight.env e plantat la calea NOUA anume ca sa oblige `stat` sa fie
    chemat macar o data (altfel un jurnal gol ar "dovedi" orice) — proprietarul
    lui nefiind uid 0 pe masina asta de test, `assert_root_owned_state_file` va
    refuza sa-l surseze, ceea ce e exact comportamentul de refuz testat separat
    in altă parte; aici conteaza doar CE cai a interogat, nu verdictul.

    Falsificat reintroducand un apel la migrate_legacy_state_markers (sau orice
    alt stat pe _LEGACY_STATE_MARKERS) inaintea acestei secvente — testul
    trebuie sa vada calea veche in jurnal.
    """
    legacy_parent = tmp_path / "sentinel_state"
    legacy = legacy_parent / ".install-state"
    legacy.mkdir(parents=True)
    (legacy / "22_postgres").write_text("2026-01-01T00:00:00Z\n", encoding="utf-8", newline="\n")
    (legacy / "preflight.env").write_text("SURICATA_OK=1\n", encoding="utf-8", newline="\n")

    new_dir = tmp_path / "new_state"
    new_dir.mkdir(parents=True)
    (new_dir / "preflight.env").write_text("SURICATA_OK=1\n", encoding="utf-8", newline="\n")

    stubs = tmp_path / "bin"
    log = tmp_path / "stat_calls.log"
    _logging_stat_stub(stubs, log)

    script = (
        "set -uo pipefail\n"
        'export SENTINEL_STATE_DIR="' + _p(legacy_parent) + '"\n'
        'export SENTINEL_INSTALL_STATE_DIR="' + _p(new_dir) + '"\n'
        'ADMIN_IP=""; DOMAIN=""; PUBLIC_PORT=""\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
        + _resolve_config_head() + "\n"
        "resolve_config || true\n"
    )
    proc = _run(script, tmp_path, extra_path=stubs)
    # returncode e irelevant aici (proprietarul planted nu e root, deci
    # resolve_config va da die() — comportamentul testat in alta parte); ce
    # conteaza e jurnalul de cai interogate.

    calls = log.read_text(encoding="utf-8") if log.exists() else ""
    legacy_str = _p(legacy)
    assert legacy_str not in calls, (
        f"calea veche a fost interogata cu stat, desi nicio migrare nu mai exista: {calls!r}")
    # Regresie pe proba insasi: sonda TREBUIE sa fi vazut CEVA (calea noua),
    # altfel "calea veche lipseste din jurnal" ar fi adevarat doar fiindca
    # jurnalul e gol, nu fiindca verificarea a rulat.
    assert calls.strip() != "", (
        "sonda de stat n-a inregistrat niciun apel -- testul n-a dovedit nimic: "
        + proc.stdout + proc.stderr)


def test_a_symlink_planted_at_the_legacy_path_has_no_effect_on_anything(tmp_path):
    """R1, direct: un symlink la calea veche (spre o tinta in afara arborelui
    Sentinel) nu mai e nici urmat, nici macar observat -- nimic nu-l citeste.
    Dovedit cu un symlink REAL, nu cu un stat falsificat, fiindca
    ensure_state_markers_dir (singurul lucru neconditionat rulat acum la
    pornire) nu ia nicio decizie despre calea veche, deci nu exista nimic de
    pacalit prin stat.
    """
    if not _symlink_capable(tmp_path):
        pytest.skip("mediul asta nu poate crea symlinkuri reale (fara "
                    "SeCreateSymbolicLinkPrivilege) -- netestat, nu curat")

    legacy_parent = tmp_path / "sentinel_state"
    legacy_parent.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "secret").write_text("root ALL=(ALL) ALL\n", encoding="utf-8", newline="\n")
    legacy = legacy_parent / ".install-state"
    legacy.symlink_to(victim, target_is_directory=True)

    new_dir = tmp_path / "new_state"
    script = (
        "set -euo pipefail\n"
        'export SENTINEL_STATE_DIR="' + _p(legacy_parent) + '"\n'
        'export SENTINEL_INSTALL_STATE_DIR="' + _p(new_dir) + '"\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
        'echo "RC=$?"\n'
    )
    proc = _run(script, tmp_path)
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert legacy.is_symlink(), "linkul plantat a fost atins"
    assert (victim / "secret").read_text(encoding="utf-8") == "root ALL=(ALL) ALL\n", \
        "continutul tintei linkului a fost modificat -- linkul a fost urmat"
    assert new_dir.exists(), "STATE_MARKERS (calea noua) tot trebuie creat, indiferent de gunoiul de la calea veche"


def test_a_root_owned_directory_renamed_over_the_legacy_path_has_no_effect(tmp_path):
    """R2, direct: un director root-owned (cum ar fi executor/, redenumit de
    sentinel peste calea veche) nu mai capata nicio sansa sa fie confundat cu
    marcaje -- nimic nu se mai uita la ce se numeste sau la ce contine calea
    veche. Nu cere stat falsificat: fara nicio verificare de incredere pe calea
    veche, proprietatea reala de pe disc (uid-ul de test, nu root) nu conteaza
    pentru ce se testeaza aici.
    """
    legacy_parent = tmp_path / "sentinel_state"
    legacy = legacy_parent / ".install-state"
    legacy.mkdir(parents=True)
    (legacy / "audit.jsonl").write_text('{"seq":1}\n', encoding="utf-8", newline="\n")

    new_dir = tmp_path / "new_state"
    script = (
        "set -euo pipefail\n"
        'export SENTINEL_STATE_DIR="' + _p(legacy_parent) + '"\n'
        'export SENTINEL_INSTALL_STATE_DIR="' + _p(new_dir) + '"\n'
        "source ./lib/common.sh\n"
        "ensure_state_markers_dir\n"
        'echo "RC=$?"\n'
    )
    proc = _run(script, tmp_path)
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert (legacy / "audit.jsonl").read_text(encoding="utf-8") == '{"seq":1}\n', \
        "continutul directorului redenumit peste calea veche a fost atins"
    assert new_dir.exists(), "STATE_MARKERS (calea noua) tot trebuie creat"


def test_rollback_purge_still_clears_the_legacy_path_so_no_stale_fact_survives():
    """rollback.sh (testat separat, tests/security/test_rollback_legacy_state_markers.py)
    tot sterge calea veche la --purge -- nu ca sa previna o migrare (nu mai
    exista), ci fiindca nginx_preexisting_resolve din install.sh CHIAR mai
    citeste de-acolo (fapt vechi, sau linia veche din preflight.env) ca ultima
    plasa de siguranta pentru gazdele instalate inainte de 8 septembrie 2026.
    Lasata pe loc, o gazda "curatata" ar reciti un raspuns vechi la urmatoarea
    instalare -- exact promisiunea pe care --purge o face si n-are voie s-o
    calce. Verificat aici doar ca researcher-check al presupunerii, nu ca
    reimplementare a testului dedicat din celalalt fisier."""
    rollback_text = (REPO / "deploy" / "rollback.sh").read_text(encoding="utf-8")
    assert "_LEGACY_STATE_MARKERS" in rollback_text, \
        "rollback.sh nu mai mentioneaza _LEGACY_STATE_MARKERS -- vezi celalalt fisier de test pentru comportament"
