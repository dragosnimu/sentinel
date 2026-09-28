"""Steagul care spunea „nginx era aici dinainte" despre nginx-ul pus de noi.

Măsurat pe VM (192.0.2.134, Ubuntu 24.04.4) pe 26 august 2026:

`step_packages` întreba `pkg_installed nginx || systemctl is-active --quiet
nginx` și, dacă da, adăuga `NGINX_WAS_PREEXISTING=1` în `preflight.env`.
Întrebarea aia are un singur răspuns valid — cel de la PRIMA instalare. De la a
doua încolo nginx e instalat fiindcă **noi** l-am instalat, deci orice re-rulare
a pasului 20 (`--force-step 20`, `--from-step 20`, o reinstalare) scria „era al
operatorului" despre propriul nostru pachet. `resolve_config` citește
`preflight.env` la fiecare rulare, deci de atunci înainte pasul 33 tipărea, la
fiecare deploy, `[!] Not touching nginx.conf — it is yours` despre un fișier
scris de instalator, iar reparația A3 (dezactivarea ascultătorului :80 al
distribuției) nu se mai aplica niciodată.

Reparația: faptul se scrie O DATĂ, într-un fișier de lângă marcaje, și nimic nu
îl mai suprascrie. Cele două direcții contează la fel de mult, și fiecare are
testul ei aici:

  * gazda unde nginx a fost pus de noi trebuie să rămână 0 pentru totdeauna —
    altfel nu ne atingem de o configurație care e a noastră;
  * gazda unde nginx CHIAR era dinainte (producția, AlmaLinux, siturile
    operatorului) trebuie să rămână 1 pentru totdeauna — altfel instalatorul
    capătă dreptul să editeze `nginx.conf`-ul operatorului. Gazdele instalate
    înainte să existe fișierul de fapte au evidența doar în `preflight.env`,
    deci linia veche e în continuare crezută, și e promovată în fapt.

Fiecare test rulează shell-ul LIVRAT din `deploy/install.sh` și
`deploy/lib/common.sh`, nu o rescriere a lui.
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
INSTALL_SH = REPO / "deploy" / "install.sh"
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL = INSTALL_SH.read_text(encoding="utf-8")
COMMON = COMMON_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")

_NO_BASH = (
    "bash lipsește din PATH, deci funcțiile livrate NU au fost rulate. "
    "Asta e „neverificat”, nu „în regulă”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


def _func(source: str, name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _const(name: str) -> str:
    """Linia de atribuire din install.sh, luată ca atare.

    Copiată, nu rescrisă: dacă numele faptului sau cheia pasului 20 se schimbă
    în instalator, testele merg după ele în loc să verifice o constantă moartă.
    """
    match = re.search(rf"^{re.escape(name)}=.*$", INSTALL, re.M)
    assert match, f"{name} nu mai e definit în install.sh"
    return match.group(0)


def _p(path: Path) -> str:
    return str(path).replace("\\", "/")


def _stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _run(script: str, tmp_path: Path, extra_path: Path | None = None,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    harness = tmp_path / "harness.sh"
    harness.write_text(script, encoding="utf-8", newline="\n")
    environ = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        environ["PATH"] = _p(extra_path) + os.pathsep + environ.get("PATH", "")
    if env:
        environ.update(env)
    return subprocess.run(
        [BASH, _p(harness)],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


def _preamble(tmp_path: Path) -> str:
    # SENTINEL_INSTALL_STATE_DIR, not SENTINEL_STATE_DIR: since 2026-09-08
    # markers live in their OWN root-owned directory, no longer nested under
    # SENTINEL_STATE_DIR (/var/lib/sentinel, 0750 sentinel:sentinel — see
    # deploy/lib/common.sh for why that nesting was the vulnerability).
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    return (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        "source ./lib/common.sh\n"
        + _const("NGINX_PREEXISTING_FACT") + "\n"
        + _const("STEP_PACKAGES_KEY") + "\n"
    )


def _markers(tmp_path: Path) -> Path:
    # No `.install-state` subdirectory any more — $STATE_MARKERS IS the
    # dedicated directory now, not a hidden folder inside a shared one.
    return tmp_path / "state"


def _fact_file(tmp_path: Path) -> Path:
    return _markers(tmp_path) / "facts" / "nginx_preexisting"


# ---------------------------------------------------------------------------
# Faptul, în sine
# ---------------------------------------------------------------------------
def test_a_fact_is_written_once_and_no_later_run_can_change_it(tmp_path):
    """Mecanismul pe care se sprijină tot restul. Dacă a doua scriere ar birui,
    reparația ar fi doar o mutare a aceluiași bug într-un fișier nou: pasul 20
    re-rulat ar suprascrie „nu era aici" cu „era", și pasul 33 ar înceta din nou
    să atingă o configurație care e a noastră."""
    proc = _run(
        _preamble(tmp_path)
        + 'echo "PRIMA=$(fact_record_once "$NGINX_PREEXISTING_FACT" 0)"\n'
        + 'echo "A_DOUA=$(fact_record_once "$NGINX_PREEXISTING_FACT" 1)"\n'
        + 'echo "CITIT=$(fact_read "$NGINX_PREEXISTING_FACT")"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PRIMA=0" in proc.stdout, proc.stdout
    assert "A_DOUA=0" in proc.stdout, \
        f"a doua observație a biruit-o pe prima: {proc.stdout!r}"
    assert "CITIT=0" in proc.stdout, proc.stdout
    assert _fact_file(tmp_path).read_text(encoding="utf-8").strip() == "0"


def test_an_unrecorded_fact_is_a_failure_not_an_empty_string(tmp_path):
    """`fact_read` trebuie să deosebească „nu s-a scris niciodată" de „scrie 0".
    Colapsate, apelantul ar citi tăcerea ca pe un răspuns — exact felul în care
    o unealtă de monitorizare începe să mintă."""
    proc = _run(
        _preamble(tmp_path)
        + 'rc=0; fact_read "$NGINX_PREEXISTING_FACT" || rc=$?\n'
        + 'echo "RC=$rc"\n'
        + 'if fact_recorded "$NGINX_PREEXISTING_FACT"; then echo DA; else echo NU; fi\n',
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RC=1" in proc.stdout, proc.stdout
    assert "NU" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# Pasul 20 — observația care are voie o singură dată
# ---------------------------------------------------------------------------
def _nginx_block() -> str:
    """Blocul nginx din `step_packages`, exact octeții livrați.

    Restul pasului instalează pachete și caută un interpretor; nimic din asta nu
    are legătură cu decizia de aici, și n-are cum să ruleze pe mașina de test.
    """
    body = _func(INSTALL, "step_packages")
    head, sep, _ = body.partition('    info "installing base packages')
    assert sep, "step_packages nu mai începe cu blocul nginx; testul ar rula altceva"
    return head + "}\n"


def _run_step_20(tmp_path: Path, *, nginx_present: bool) -> subprocess.CompletedProcess:
    binpath = tmp_path / "bin"
    _stub(binpath, "systemctl", "exit 3\n")   # is-active pentru un serviciu oprit
    return _run(
        _preamble(tmp_path)
        + "NGINX_WAS_PREEXISTING=0\n"
        + f'pkg_installed() {{ [[ "{1 if nginx_present else 0}" == 1 ]]; }}\n'
        + _nginx_block()
        + "step_packages\n"
        + 'echo "FLAG=$NGINX_WAS_PREEXISTING"\n',
        tmp_path, extra_path=binpath)


def test_a_second_step_20_does_not_turn_our_own_nginx_into_the_operators(tmp_path):
    """Defectul măsurat, direct. Prima trecere nu găsește nginx (îl instalăm noi
    imediat după). A doua îl găsește — fiindcă e al nostru. Dacă a doua ar fi
    crezută, pasul 33 n-ar mai scoate din funcțiune ascultătorul :80 al
    distribuției pe nicio gazdă deja instalată, inclusiv producția."""
    first = _run_step_20(tmp_path, nginx_present=False)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "FLAG=0" in first.stdout, first.stdout

    second = _run_step_20(tmp_path, nginx_present=True)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "FLAG=0" in second.stdout, \
        f"a doua rulare a pasului 20 a declarat nginx-ul nostru al operatorului: {second.stdout!r}"
    assert "will not be modified" not in second.stdout, second.stdout


def test_a_host_where_nginx_really_was_there_first_keeps_the_flag_forever(tmp_path):
    """Cealaltă direcție, cea periculoasă. Pe producție nginx servea siturile
    operatorului înainte de Sentinel. Dacă steagul ar cădea vreodată pe 0,
    instalatorul ar comenta `listen 80` din `nginx.conf`-ul lui — adică exact
    dauna colaterală pe care restul instalatorului o evită."""
    first = _run_step_20(tmp_path, nginx_present=True)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "FLAG=1" in first.stdout, first.stdout
    assert "will not be modified" in first.stdout, first.stdout

    second = _run_step_20(tmp_path, nginx_present=True)
    assert "FLAG=1" in second.stdout, second.stdout


def test_step_20_no_longer_writes_the_flag_into_preflight_env(tmp_path):
    """`preflight.env` e rescris cu `>` ori de câte ori rulează pasul 1, deci o
    evidență ținută acolo poate fi ștearsă de alt pas. Dacă pasul 20 ar continua
    să scrie și acolo, ar exista două răspunsuri la aceeași întrebare, iar cel
    greșit ar fi cel care supraviețuiește."""
    env_file = _markers(tmp_path) / "preflight.env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text("SURICATA_OK=1\n", encoding="utf-8", newline="\n")

    proc = _run_step_20(tmp_path, nginx_present=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert env_file.read_text(encoding="utf-8") == "SURICATA_OK=1\n", \
        env_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# resolve_config — de unde vine răspunsul la fiecare rulare
# ---------------------------------------------------------------------------
def _resolve(tmp_path: Path, *, env_lines: str | None = None,
             step20_done: bool = False) -> subprocess.CompletedProcess:
    markers = _markers(tmp_path)
    markers.mkdir(parents=True, exist_ok=True)
    env_file = markers / "preflight.env"
    if env_lines is not None:
        env_file.write_text(env_lines, encoding="utf-8", newline="\n")
    if step20_done:
        (markers / "20_packages").write_text("2026-08-01T00:00:00Z\n",
                                             encoding="utf-8", newline="\n")
    return _run(
        _preamble(tmp_path)
        + _func(INSTALL, "nginx_preexisting_resolve")
        + "\n"
        + f'echo "FLAG=$(nginx_preexisting_resolve "{_p(env_file)}")"\n',
        tmp_path)


def test_the_legacy_line_from_an_older_install_is_still_believed(tmp_path):
    """Migrarea, și partea din ea care poate strica producția. O gazdă instalată
    înainte să existe fișierul de fapte are evidența doar în `preflight.env`.
    Măsurat 28 septembrie 2026, și NU ce spunea o versiune anterioară a
    acestui text: `/var/lib/sentinel-install` nu există pe niciuna dintre
    gazdele vii, deci tier (1) e GOL pe amândouă și tier (2) e calea vie la
    următoarea livrare, nu o ramură adormită. Ambele fapte vechi citesc 0, iar
    `preflight.env` nu mai are deloc cheia NGINX_WAS_PREEXISTING (control
    pozitiv: fișierul are alte șase chei) — deci nicio gazdă nu ajunge azi la
    tier (3). Faptul înregistrat pe producție e totuși greșit: nginx era acolo
    înainte, iar 0-ul a fost scris de regula tăcerii din tier (4); vezi
    comentariul din `deploy/install.sh`. Scenariul testat aici
    rămâne valid pentru o gazdă înghețată între 26 august și 8 septembrie
    2026, a cărei unică evidență e linia veche cu valoarea 1: dacă noul cod
    ar porni de la 0 fiindcă faptul nu e scris încă, pasul 33 ar primi voie
    să editeze `nginx.conf`-ul operatorului la primul deploy de după."""
    proc = _resolve(tmp_path, env_lines="SURICATA_OK=1\nNGINX_WAS_PREEXISTING=1\n",
                    step20_done=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLAG=1" in proc.stdout, proc.stdout


def test_the_legacy_line_is_promoted_so_it_survives_preflight_rewriting_the_file(
        tmp_path):
    """`--force-step 1` rescrie `preflight.env` de la zero. Dacă valoarea ar fi
    doar citită de acolo la fiecare rulare, rularea de după ar pierde-o și gazda
    cu nginx-ul operatorului ar deveni, tăcut, o gazdă cu nginx-ul nostru."""
    first = _resolve(tmp_path, env_lines="NGINX_WAS_PREEXISTING=1\n", step20_done=True)
    assert "FLAG=1" in first.stdout, first.stdout

    # exact ce face preflight.sh: `>` peste fișier
    (_markers(tmp_path) / "preflight.env").write_text(
        "SURICATA_OK=1\n", encoding="utf-8", newline="\n")
    second = _resolve(tmp_path, step20_done=True)
    assert "FLAG=1" in second.stdout, \
        f"faptul s-a pierdut când pasul 1 a rescris preflight.env: {second.stdout!r}"


def test_a_host_past_step_20_with_no_line_is_recorded_as_ours(tmp_path):
    """Tăcerea e și ea o evidență: codul vechi adăuga linia DOAR când găsea
    nginx, deci lipsa ei pe o gazdă care a trecut deja de pasul 20 înseamnă că
    nginx nu era acolo. Scrisă, nu re-dedusă — altfel primul `--force-step 20`
    ar observa nginx-ul nostru și ar înregistra 1, adică chiar bug-ul, întors pe
    ușa migrării."""
    proc = _resolve(tmp_path, env_lines="SURICATA_OK=1\n", step20_done=True)
    assert "FLAG=0" in proc.stdout, proc.stdout
    assert _fact_file(tmp_path).exists(), \
        "nu s-a scris nimic, deci următoarea re-rulare a pasului 20 poate încă să mintă"

    later = _run_step_20(tmp_path, nginx_present=True)
    assert "FLAG=0" in later.stdout, \
        f"un --force-step 20 de după migrare a răsturnat faptul: {later.stdout!r}"


def test_a_first_install_records_nothing_before_step_20_has_looked(tmp_path):
    """`resolve_config` rulează ÎNAINTE de pasul 20. Dacă ar scrie faptul acolo,
    ar îngheța un 0 pe care nimeni nu l-a măsurat — și gazda pe care nginx chiar
    exista ar fi declarată a noastră fix la instalarea unde se putea afla
    adevărul."""
    proc = _resolve(tmp_path, env_lines="SURICATA_OK=1\n", step20_done=False)
    assert "FLAG=0" in proc.stdout, proc.stdout
    assert not _fact_file(tmp_path).exists(), \
        "s-a scris un fapt înainte ca pasul 20 să se uite la gazdă"

    later = _run_step_20(tmp_path, nginx_present=True)
    assert "FLAG=1" in later.stdout, \
        f"observația reală a pasului 20 a fost ignorată: {later.stdout!r}"


def test_a_recorded_fact_beats_a_contradicting_preflight_env(tmp_path):
    """Ordinea surselor. Dacă linia veche ar bate faptul, un `--force-step 20`
    care a apucat să scrie 1 în `preflight.env` înainte de reparație ar rămâne
    otrava permanentă pe care reparația trebuia s-o scoată."""
    fact = _fact_file(tmp_path)
    fact.parent.mkdir(parents=True, exist_ok=True)
    fact.write_text("0\n", encoding="utf-8", newline="\n")
    proc = _resolve(tmp_path, env_lines="NGINX_WAS_PREEXISTING=1\n", step20_done=True)
    assert "FLAG=0" in proc.stdout, proc.stdout


def test_a_malformed_legacy_line_is_not_read_as_a_yes(tmp_path):
    """`NGINX_WAS_PREEXISTING=` gol, sau cu altceva după el, nu e „1". Un `grep`
    prea larg ar transforma o linie stricată într-un „da" permanent, iar ăsta e
    răspunsul care oprește reparația A3."""
    proc = _resolve(tmp_path, env_lines="NGINX_WAS_PREEXISTING=\n", step20_done=True)
    assert "FLAG=0" in proc.stdout, proc.stdout


def test_the_step_20_key_matches_what_run_step_actually_writes(tmp_path):
    """`nginx_preexisting_resolve` întreabă marcajul pasului 20 pe nume. Dacă
    numele n-ar mai corespunde, ramura de migrare n-ar mai fi luată niciodată,
    iar gazdele vechi ar rămâne exact acolo unde erau — fără ca nimic să pice."""
    line = _const("STEP_PACKAGES_KEY")
    key = line.split("=", 1)[1].strip().strip('"')
    match = re.search(r"^\s*run_step\s+(\d+)\s+(\S+)\s", INSTALL, re.M | re.S)
    assert match, "nu mai există linii run_step în install.sh"
    step = re.search(r"^\s*run_step\s+20\s+(\S+)\s", INSTALL, re.M)
    assert step, "pasul 20 nu mai există în install.sh"
    assert key == f"20_{step.group(1)}", \
        f"marcajul pe care îl caută resolve ({key}) nu e cel scris de run_step " \
        f"pentru pasul 20 (20_{step.group(1)})"


# ---------------------------------------------------------------------------
# 13 septembrie 2026 -- migrarea a disparut, fallback-ul vechi tot functioneaza
# ---------------------------------------------------------------------------
def test_resolve_config_points_the_legacy_fallback_at_the_old_path_not_the_new_one(tmp_path):
    """De cand nimic nu mai muta preflight.env vechi in $STATE_MARKERS,
    nginx_preexisting_resolve n-ar mai avea niciodata ce citi la tier (3) daca
    ar primi calea NOUA -- nimeni n-o scrie cu acel format acolo. resolve_config
    trebuie sa-i dea calea VECHE (_LEGACY_STATE_MARKERS/preflight.env), singurul
    loc unde un asemenea fisier mai poate exista.

    Falsificat schimband argumentul inapoi la "$env_file" in resolve_config --
    testul trebuie sa nu mai gaseasca apelul cu calea veche.
    """
    match = re.search(
        r'nginx_preexisting_resolve\s+"\$\{_LEGACY_STATE_MARKERS\}/preflight\.env"',
        INSTALL)
    assert match, (
        "resolve_config nu mai cheama nginx_preexisting_resolve cu calea veche -- "
        "fallback-ul (2)/(3) ar deveni mort cod pe orice gazda reala")


def test_a_legacy_fact_file_at_the_old_location_is_still_honoured(tmp_path):
    """O gazda care a rulat deja codul cu `fact_record_once` (26 august 2026)
    dar n-a mai redeployat de cand marcajele s-au mutat (8 septembrie 2026) are
    faptul scris la VECHEA locatie (${_LEGACY_STATE_MARKERS}/facts/nginx_preexisting),
    nu la cea noua si nu ca linie in preflight.env. Fara acest tier, o gazda ca
    asta ar pierde exact write-once-ul care exista ca sa apere nginx.conf-ul
    operatorului.

    Falsificat scotand blocul care citeste $legacy_fact din nginx_preexisting_resolve
    -- testul trebuie sa vada FLAG=0 (redeductia implicita), nu FLAG=1.
    """
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    legacy_state = tmp_path / "legacy_state"
    legacy_fact = legacy_state / ".install-state" / "facts" / "nginx_preexisting"
    legacy_fact.parent.mkdir(parents=True, exist_ok=True)
    legacy_fact.write_text("1\n", encoding="utf-8", newline="\n")

    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        f'export SENTINEL_STATE_DIR="{_p(legacy_state)}"\n'
        "source ./lib/common.sh\n"
        + _const("NGINX_PREEXISTING_FACT") + "\n"
        + _const("STEP_PACKAGES_KEY") + "\n"
        + _func(INSTALL, "nginx_preexisting_resolve")
        + "\n"
        f'echo "FLAG=$(nginx_preexisting_resolve "{_p(state)}/preflight.env")"\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLAG=1" in proc.stdout, (
        f"faptul de la locatia veche n-a fost citit: {proc.stdout!r}")
    assert (state / "facts" / "nginx_preexisting").read_text(encoding="utf-8").strip() == "1", \
        "faptul citit din locatia veche n-a fost promovat in cea noua"


# ---------------------------------------------------------------------------
# 28 septembrie 2026 — tier (2) nu are voie sa creada orice ii planteaza `sentinel`
# ---------------------------------------------------------------------------
def _resolve_with_legacy_fact(tmp_path: Path, legacy_bytes: bytes, *,
                               step20_done: bool = False
                               ) -> tuple[subprocess.CompletedProcess, Path]:
    """Ruleaza nginx_preexisting_resolve cu faptul VECHI scris exact ca bytes
    la ${_LEGACY_STATE_MARKERS}/facts/nginx_preexisting si preflight.env gol
    (fara linia NGINX_WAS_PREEXISTING), ca sa izoleze strict tier (2) — orice
    FLAG != "0" aici vine din fisierul plantat de `sentinel`, nu din tier (3)
    sau (4).
    """
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    legacy_state = tmp_path / "legacy_state"
    legacy_fact = legacy_state / ".install-state" / "facts" / "nginx_preexisting"
    legacy_fact.parent.mkdir(parents=True, exist_ok=True)
    legacy_fact.write_bytes(legacy_bytes)
    if step20_done:
        (state / "20_packages").write_text("2026-08-01T00:00:00Z\n",
                                            encoding="utf-8", newline="\n")

    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        f'export SENTINEL_STATE_DIR="{_p(legacy_state)}"\n'
        "source ./lib/common.sh\n"
        + _const("NGINX_PREEXISTING_FACT") + "\n"
        + _const("STEP_PACKAGES_KEY") + "\n"
        + _func(INSTALL, "nginx_preexisting_resolve")
        + "\n"
        f'echo "FLAG=$(nginx_preexisting_resolve "{_p(state)}/preflight.env")"\n'
    )
    return _run(script, tmp_path), state


def test_a_symlink_at_the_legacy_fact_path_is_refused_not_followed(tmp_path):
    """Verificare statica pe sursa livrata, nu una dinamica: mediul asta de
    dezvoltare (Windows, fara SeCreateSymbolicLinkPrivilege) nu poate crea un
    symlink real ca sa demonstreze comportamentul la rulare — vezi
    `_symlink_capable` in test_installer_state_markers.py, care se lovește de
    aceeași limitare. `[[ -f ]]` singur URMEAZĂ o legătură și acceptă orice
    fișier obișnuit numit de ea, oriunde ar fi; `sentinel` deține directorul
    și poate planta o astfel de legătură la fel de ușor cum ar planta
    fișierul direct, deci refuzul trebuie să fie explicit în sursă, nu doar
    "de fapt inofensiv fiindcă valoarea tot trece prin regex".

    Falsificat scoțând `&& ! -L "$legacy_fact"` din condiția care păzește
    citirea — testul trebuie să nu mai găsească acea clauză.
    """
    body = _func(INSTALL, "nginx_preexisting_resolve")
    match = re.search(r'-f\s+"\$legacy_fact"\s*&&\s*!\s*-L\s+"\$legacy_fact"', body)
    assert match, (
        "nginx_preexisting_resolve nu mai refuză explicit un symlink la "
        "$legacy_fact -- [[ -f ]] singur urmează legătura și citește orice "
        "fișier obișnuit numit de ea, indiferent unde e")


@pytest.mark.parametrize("legacy_bytes", [
    pytest.param(b"", id="empty"),
    pytest.param(b"2\n", id="out-of-range-digit"),
    pytest.param(b"0 1\n", id="two-values-one-line"),
    pytest.param(b"1;rm\n", id="shell-metacharacter-tail"),
    pytest.param(b"01\n", id="two-characters-no-separator"),
])
def test_a_forged_legacy_fact_value_is_never_promoted(tmp_path, legacy_bytes):
    """`sentinel` deține directorul unde stă acest fișier octet cu octet — nimic
    din el nu are voie să treacă direct în faptul write-once, permanent, decât
    exact "0" sau "1". Fiecare valoare de-aici trebuie să cadă înapoi pe tier
    (4) (nicio linie de fapt VECHE găsită) și, cu pasul 20 marcat gata, faptul
    NOU trebuie scris ca "0" — niciodată valoarea forjată.

    Asta contează mai mult decât pare: valoarea forjată, o dată promovată, e
    `fact_record_once`-uită în directorul root-only PENTRU TOTDEAUNA — falsul
    are nevoie să reușească o singură dată.

    Falsificat lărgind regexul `^[01]$` din `nginx_preexisting_resolve` (de
    exemplu la `^.*$`) — testul trebuie să vadă FLAG diferit de 0, sau faptul
    promovat cu valoarea forjată în loc de "0".
    """
    proc, state = _resolve_with_legacy_fact(tmp_path, legacy_bytes, step20_done=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLAG=0" in proc.stdout, (
        f"valoare forjată {legacy_bytes!r} nu a căzut pe implicit: {proc.stdout!r}")
    fact_file = state / "facts" / "nginx_preexisting"
    assert fact_file.exists(), "faptul n-a fost scris deloc dupa pasul 20"
    assert fact_file.read_text(encoding="utf-8").strip() == "0", (
        f"faptul scris nu e '0' ci {fact_file.read_text(encoding='utf-8')!r} — "
        f"valoarea forjată {legacy_bytes!r} a fost promovată")


def test_a_newline_less_legacy_fact_file_is_read_in_bounded_time(tmp_path):
    """`sentinel` poate redenumi `.install-state` din drum și crea acolo un
    fișier gol de fapte fără NICIUN newline — un `truncate -s` sparse costă
    zero blocuri pe disc, iar `head -1` scanează după un newline care nu vine
    niciodată, deci ar citi până la EOF. Măsurat pe acest sandbox: `head -1`
    pe un sparse de 4 GB durează peste 7 secunde; `head -c 64` pe același
    fișier durează sub o zecime de secundă. Instalatorul rulează asta la
    FIECARE deploy, ca root, pe orice gazdă cu un `.install-state` vechi —
    o linie neterminată ar transforma fiecare deploy într-un blocaj de ore pe
    un fișier suficient de mare.

    Falsificat revenind la `head -1` în `nginx_preexisting_resolve` — testul
    trebuie să vadă timpul depășind pragul (câteva secunde reale pe acest
    sandbox, contra sub-secundă cu fixul).
    """
    import time

    legacy_state = tmp_path / "legacy_state"
    legacy_fact = legacy_state / ".install-state" / "facts" / "nginx_preexisting"
    legacy_fact.parent.mkdir(parents=True, exist_ok=True)
    truncate = shutil.which("truncate")
    assert truncate, "truncate lipsește din PATH — nu se poate construi proba"
    made_sparse = subprocess.run(
        [truncate, "-s", "4G", _p(legacy_fact)],
        capture_output=True, text=True)
    assert made_sparse.returncode == 0, (
        "nu s-a putut crea fișierul sparse de test: " + made_sparse.stderr)
    assert legacy_fact.stat().st_size == 4 * 1024 ** 3, (
        "fișierul de test nu are dimensiunea sparse asteptată — proba insasi e stricata")

    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    script = (
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        f'export SENTINEL_STATE_DIR="{_p(legacy_state)}"\n'
        "source ./lib/common.sh\n"
        + _const("NGINX_PREEXISTING_FACT") + "\n"
        + _const("STEP_PACKAGES_KEY") + "\n"
        + _func(INSTALL, "nginx_preexisting_resolve")
        + "\n"
        f'echo "FLAG=$(nginx_preexisting_resolve "{_p(state)}/preflight.env")"\n'
    )
    started = time.monotonic()
    proc = _run(script, tmp_path)
    elapsed = time.monotonic() - started

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLAG=0" in proc.stdout, (
        f"un fisier gol, fara continut '0'/'1', n-a cazut pe implicit: {proc.stdout!r}")
    assert elapsed < 2.0, (
        f"citirea faptului vechi a durat {elapsed:.2f}s pe un sparse de 4 GB — "
        f"instalatorul ar sta asa la fiecare deploy pe o gazda cu .install-state "
        f"vechi si un fisier suficient de mare")
