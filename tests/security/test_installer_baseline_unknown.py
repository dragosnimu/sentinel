"""„N-am putut măsura” nu are voie să se scrie „nu s-a oprit nimic” și nici „s-a oprit tot”.

`capture_baseline` și `assert_nothing_broken` din `deploy/lib/common.sh` erau scrise așa:

    systemctl ... 2>/dev/null | awk ... | sort > baseline-services.txt || true
    ss -tlnH 2>/dev/null | ... > baseline-ports.txt || true

Un `ss` căzut lăsa un fișier GOL care EXISTĂ, iar fișierul ăla trebuia să însemne și
„nimic nu asculta”, și „n-am putut întreba”. Comparația greșea în ambele sensuri:

  * LA CAPTURĂ: baseline-ul gol e un „totul e bine” permanent (`comm -23` între nimic și
    orice nu găsește nimic pierdut), tipărit ca «baseline captured: 0 services, 0
    listening ports». `install.sh` îl re-captura doar dacă fișierul de servicii lipsea,
    deci unul gol rămânea pe gazdă și otrăvea fiecare rulare de după;
  * LA VERIFICARE: un `ss` căzut lăsa partea „acum” goală, deci FIECARE port din baseline
    părea închis, iar `step_verify_nothing_broken` rula `rollback.sh --yes` automat peste o
    instalare sănătoasă. O măsurătoare ratată distrugea ce nu era stricat.

Trei stări, peste tot: măsurat și bine / măsurat și rău / **n-am putut măsura**. A treia nu e
niciuna din primele două. `assert_nothing_broken` întoarce 0 / 1 / 2 (regula de la
`port_free`: liber e `== 0`, ocupat e `== 1`, TOT RESTUL e necunoscut), iar niciun apelant nu
are voie să transforme 2 într-o acțiune sau într-un succes.

Fișierul de față rulează codul LIVRAT — `deploy/lib/common.sh`, funcțiile extrase din
`deploy/install.sh` și secvența din `deploy/rollback.sh` / `deploy/preflight.sh` — cu
colectori momeală (`systemctl`, `ss`, `docker`) pe PATH, adică chiar BINARELE pe care codul le
atinge. Fiecare momeală își notează apelurile. Harnașele rulează sub `set -euo pipefail`, ca
scripturile reale. Nicio rulare nu atinge `/var/lib/sentinel-install`: harnașul refuză să
pornească dacă `STATE_MARKERS` nu e sub directorul temporar al testului.

Ce NU are mediul ăsta:
  * un `systemctl`/`ss`/`docker` real. Momelile reproduc ce s-a MĂSURAT pe cele două gazde de
    producție (2 nov 2026, doar citire): `ss -tlnH` fără antet, `systemctl list-units
    --no-legend --plain` cu UNIT pe prima coloană, `docker ps --format '{{.Names}}'`;
  * „fără docker pe PATH” e simulat prin umbrirea lui `have` (o funcție), NU prin scoaterea
    binarului: pe o gazdă cu docker real, PATH-ul nu poate fi golit fără să dispară și
    `sort`/`awk`. Ce se dovedește e DECIZIA luată din `have docker`, nu căutarea în PATH.
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
DEPLOY = REPO / "deploy"
COMMON = (DEPLOY / "lib" / "common.sh").read_text(encoding="utf-8")
INSTALL = (DEPLOY / "install.sh").read_text(encoding="utf-8")
ROLLBACK = (DEPLOY / "rollback.sh").read_text(encoding="utf-8")
PREFLIGHT = (DEPLOY / "preflight.sh").read_text(encoding="utf-8")

BASH = shutil.which("bash")
_NO_BASH = ("bash lipsește din PATH, deci codul LIVRAT nu a fost rulat. "
            "Asta e „neverificat”, nu „în regulă”.")
pytestmark = [pytest.mark.security, pytest.mark.skipif(BASH is None, reason=_NO_BASH)]

# Linia de succes a lui assert_nothing_broken — frază întreagă: mesajele de avertisment conțin și
# ele «nothing that was running», iar un test pe prefix ar confunda un avertisment cu un succes.
OK_LINE = "nothing that was running before the deploy has stopped"
DIMS = ("services", "ports", "containers")
TOOL = {"services": "systemctl", "ports": "ss", "containers": "docker"}
# Cum arată, pe rând, fraza din linia „baseline captured” pentru fiecare dimensiune.
PHRASE = {"services": "services", "ports": "listening ports", "containers": "running containers"}

SERVICES_OUT = (
    "sshd.service loaded active running OpenSSH server daemon\n"
    "nginx.service loaded active running A high performance web server\n"
    "sentinel-detect.service loaded active running Sentinel detector"
)
PORTS_OUT = (
    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n"
    "LISTEN 0 511 [::]:80 [::]:*"
)
CONTAINERS_OUT = "web\ndb"


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


class Result:
    """Rezultatul unei rulări. `out` = stdout + stderr (warn/fail scriu pe stderr)."""

    def __init__(self, proc: subprocess.CompletedProcess):
        self.proc = proc
        self.out = proc.stdout + proc.stderr
        self.vars = dict(re.findall(r"^([A-Z_0-9]+)=(.*)$", proc.stdout, re.M))

    @property
    def rc(self) -> int:
        assert "RC" in self.vars, f"harnașul nu a ajuns la RC=:\n{self.out}"
        return int(self.vars["RC"])


class Host:
    """O gazdă falsă: trei colectori pe PATH, un director de stare propriu.

    Fiecare colector își notează apelurile în `calls`, ca «n-a fost chemat niciodată» să fie
    o observație, nu o presupunere. Implicit gazda e sănătoasă."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "state"
        self.sstate = tmp_path / "sstate"
        self.backup = tmp_path / "backup"
        self.calls = tmp_path / "calls.log"
        self.calls.write_text("", encoding="utf-8", newline="\n")
        self.healthy()

    # -- colectori ---------------------------------------------------------
    def set(self, name: str, out: str = "", rc: int = 0, err: str = "") -> None:
        body = f'echo "{name} $*" >> "{self.calls.as_posix()}"\n'
        if err:
            body += f"cat >&2 <<'EOF'\n{err}\nEOF\n"
        if out:
            body += f"cat <<'EOF'\n{out}\nEOF\n"
        body += f"exit {rc}\n"
        _stub(self.bin, name, body)

    def healthy(self) -> None:
        self.set("systemctl", SERVICES_OUT)
        self.set("ss", PORTS_OUT)
        self.set("docker", CONTAINERS_OUT)

    def fail(self, dim: str, rc: int = 1, err: str | None = None) -> None:
        tool = TOOL[dim]
        self.set(tool, rc=rc, err=err if err is not None else f"{tool}: boom ({dim})")

    def passthrough(self, name: str, refuse_when: str) -> None:
        """O momeală pentru o unealtă de sistem (`mv`, `sort`, `mktemp`, `comm`) care REFUZĂ
        când argumentele potrivesc un tipar `case`, altfel cheamă uneltealta reală. PATH-ul
        scriptului începe cu directorul de momeli, deci ce rămâne după primul `:` e PATH-ul
        real."""
        _stub(self.bin, name,
              f'case "$*" in {refuse_when}) echo "{name}: refuzat de test" >&2; exit 1 ;; esac\n'
              f'PATH="${{PATH#*:}}"\nexec {name} "$@"\n')

    def calls_text(self) -> str:
        return self.calls.read_text(encoding="utf-8")

    # -- fișiere de baseline scrise de mână --------------------------------
    def legacy(self, **files: str | None) -> None:
        """Un baseline în forma de DINAINTE: fișiere simple, fără `baseline-state.txt`."""
        self.state.mkdir(parents=True, exist_ok=True)
        for dim, content in files.items():
            if content is not None:
                (self.state / f"baseline-{dim}.txt").write_text(
                    content, encoding="utf-8", newline="\n")

    # -- rulare --------------------------------------------------------------
    def run(self, script: str, *, no_docker: bool = False, env: dict[str, str] | None = None,
            prelude_extra: str = "") -> Result:
        state = self.state.as_posix()
        prelude = (
            "set -euo pipefail\n"
            "source ./lib/common.sh\n"
            # Garda de siguranță: nimic din fișierul ăsta nu are voie să scrie în
            # /var/lib/sentinel-install al mașinii pe care rulează.
            f'case "$STATE_MARKERS" in "{state}"|"{state}"/*) ;; '
            '*) echo "REFUSED: STATE_MARKERS=$STATE_MARKERS" >&2; exit 99 ;; esac\n'
        )
        if no_docker:
            prelude += ('have() { [[ "$1" != docker ]] && command -v "$1" >/dev/null 2>&1; }\n')
        path = self.tmp / "harness.sh"
        path.write_text(prelude + prelude_extra + script, encoding="utf-8", newline="\n")
        environ = {**os.environ, "NO_COLOR": "1",
                   "SENTINEL_INSTALL_STATE_DIR": state,
                   "SENTINEL_STATE_DIR": self.sstate.as_posix(),
                   "SENTINEL_BACKUP_DIR": self.backup.as_posix()}
        environ["PATH"] = self.bin.as_posix() + os.pathsep + environ.get("PATH", "")
        if env:
            environ.update(env)
        proc = subprocess.run(
            [BASH, path.as_posix()], cwd=DEPLOY, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=environ)
        return Result(proc)

    def capture(self, **kw) -> Result:
        return self.run('rc=0; capture_baseline || rc=$?\necho "RC=$rc"\n'
                        'echo "SVC=$BASELINE_SERVICES"\necho "PRT=$BASELINE_PORTS"\n', **kw)

    def assert_(self, when: str = "after install", **kw) -> Result:
        return self.run(f'rc=0; assert_nothing_broken "{when}" || rc=$?\n'
                        'echo "RC=$rc"\necho "UNKNOWN=[$BASELINE_UNKNOWN]"\n'
                        'echo "COMPARED=[$BASELINE_COMPARED]"\n'
                        'echo "COUNTS=$FAIL_COUNT $WARN_COUNT"\n', **kw)

    def record(self) -> str | None:
        path = self.state / "baseline-state.txt"
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def data(self, dim: str) -> str | None:
        path = self.state / f"baseline-{dim}.txt"
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def captured(self, **kw) -> Host:
        """Capturează pe gazda sănătoasă și verifică, ca restul testului să nu stea pe o
        capturare pe care nu s-a uitat nimeni la ea."""
        res = self.capture(**kw)
        assert res.rc == 0, res.out
        assert self.record() == "services=measured\nports=measured\ncontainers=measured\n", res.out
        return self


@pytest.fixture
def host(tmp_path) -> Host:
    return Host(tmp_path)


# ===========================================================================
# capture_baseline
# ===========================================================================
def test_a_healthy_host_is_captured_as_measured_in_all_three_dimensions(host):
    """Contra-proba pentru tot ce urmează: cu colectori care merg, baseline-ul se scrie ca
    înainte (fișiere simple, sortate, o intrare pe linie — formatul pe care `smoke-test.sh` și
    `diff`-ul din docs/DEPANARE.md îl citesc direct), plus înregistrarea că s-a MĂSURAT. O
    capturare care ar marca totul «nemăsurat» ar face testele de mai jos să treacă degeaba."""
    res = host.capture()
    assert res.rc == 0, res.out
    assert host.data("services") == "nginx.service\nsentinel-detect.service\nsshd.service\n"
    assert host.data("ports") == "22\n80\n"
    assert host.data("containers") == "db\nweb\n"
    assert host.record() == "services=measured\nports=measured\ncontainers=measured\n"
    assert "baseline captured: 3 services, 2 listening ports, 2 running containers" in res.out
    assert "[!]" not in res.out, res.out
    assert res.vars["SVC"] == (host.state / "baseline-services.txt").as_posix()
    assert res.vars["PRT"] == (host.state / "baseline-ports.txt").as_posix()
    leftovers = sorted(p.name for p in host.state.iterdir())
    assert leftovers == ["baseline-containers.txt", "baseline-ports.txt",
                         "baseline-services.txt", "baseline-state.txt"], leftovers


@pytest.mark.parametrize("dim", DIMS)
def test_a_collector_that_fails_is_not_captured_and_not_celebrated(host, dim):
    """Un colector care iese cu 1 lăsa un fișier gol care EXISTA, iar funcția tipărea «baseline
    captured: 0 services, 0 listening ports» — un succes pentru o măsurătoare care nu s-a
    făcut. Acum: dimensiunea e înregistrată «unmeasured», fișierul NU există, avertismentul
    numește comanda și motivul real (stderr-ul ei, nu /dev/null), iar linia de succes o
    pomenește doar pe cele măsurate. Se întoarce 2."""
    host.fail(dim, err=f"{TOOL[dim]}: netlink error")
    res = host.capture()
    assert res.rc == 2, res.out
    assert host.data(dim) is None, "dimensiunea nemăsurată a lăsat un fișier (golul care minte)"
    others = [d for d in DIMS if d != dim]
    expected = "".join(f"{d}={'unmeasured' if d == dim else 'measured'}\n" for d in DIMS)
    assert host.record() == expected
    for d in others:
        assert host.data(d), f"dimensiunea sănătoasă {d} s-a pierdut odată cu cea căzută"
    line = next(ln for ln in res.out.splitlines() if "baseline captured:" in ln)
    assert PHRASE[dim] not in line, f"succes tipărit pentru dimensiunea căzută: {line}"
    for d in others:
        assert PHRASE[d] in line, f"dimensiunea măsurată {d} lipsește din: {line}"
    assert f"baseline of {dim} NOT captured" in res.out
    assert f"{TOOL[dim]}: netlink error" in res.out, "motivul real al eșecului s-a pierdut"


def test_all_collectors_failing_prints_no_success_line_and_leaves_no_files(host):
    """Cazul din reproducere: `systemctl`, `ss` și `docker` cad toate. Vechiul cod scria trei
    fișiere goale și tipărea succes. Acum nu rămâne niciun fișier de date, înregistrarea spune
    «unmeasured» de trei ori și nu există NICIO linie «baseline captured»."""
    for dim in DIMS:
        host.fail(dim)
    res = host.capture()
    assert res.rc == 2, res.out
    assert "baseline captured" not in res.out, res.out
    assert [host.data(d) for d in DIMS] == [None, None, None]
    assert host.record() == "services=unmeasured\nports=unmeasured\ncontainers=unmeasured\n"
    assert res.vars["SVC"] == "" and res.vars["PRT"] == ""


def test_a_command_that_is_missing_is_unmeasured_with_its_exit_status(host):
    """`ss` lipsește de pe PATH (iproute2 neinstalat): bash întoarce 127. Vechiul `2>/dev/null
    ... || true` îl înghițea. Statusul și mesajul real trebuie să ajungă în avertisment."""
    host.set("ss", rc=127, err="bash: ss: command not found")
    res = host.capture()
    assert res.rc == 2 and host.data("ports") is None, res.out
    assert "exit 127: bash: ss: command not found" in res.out, res.out


def test_a_failed_recapture_does_not_leave_the_previous_baseline_standing(host):
    """O capturare nouă e afirmația despre gazdă DE ACUM. Dacă `ss` cade la a doua, baseline-ul
    portului de la prima nu rămâne în picioare ca și cum ar descrie același moment: fișierul
    dispare, înregistrarea trece pe «unmeasured»."""
    host.captured()
    host.fail("ports")
    res = host.capture()
    assert res.rc == 2, res.out
    assert host.data("ports") is None
    assert "ports=unmeasured" in host.record()
    assert host.data("services") and host.data("containers")


def test_the_old_record_is_removed_before_any_collector_runs(host):
    """O capturare care moare la jumătate nu are voie să lase înregistrarea celei de dinainte
    în picioare peste date noi. Momeala `ss` notează dacă `baseline-state.txt` există în clipa
    în care e chemată: trebuie să NU existe, deși o capturare completă tocmai a scris unul."""
    host.captured()
    probe = host.tmp / "record-at-ss-time"
    _stub(host.bin, "ss",
          f'echo "ss $*" >> "{host.calls.as_posix()}"\n'
          f'if [ -e "{host.state.as_posix()}/baseline-state.txt" ]; then echo PRESENT; '
          f'else echo ABSENT; fi > "{probe.as_posix()}"\n'
          "echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'\n")
    res = host.capture()
    assert res.rc == 0, res.out
    assert probe.read_text(encoding="utf-8").strip() == "ABSENT"


def test_a_measured_empty_answer_is_recorded_as_measured_not_as_unmeasured(host):
    """Contra-proba pentru distincția pe care se sprijină totul: `docker ps` care iese cu 0 și
    nu tipărește nimic înseamnă «niciun container pornit» — o MĂSURĂTOARE. Fișierul există,
    gol, și înregistrarea spune «measured»; nu e «nemăsurat» și nu avertizează."""
    host.set("docker", out="")
    res = host.capture()
    assert res.rc == 0, res.out
    assert host.data("containers") == ""
    assert "containers=measured" in host.record()
    assert "0 running containers" in res.out and "[!]" not in res.out, res.out
    probe = host.run('baseline_state "$STATE_MARKERS" containers\n')
    assert probe.proc.stdout.strip() == "measured", probe.out


def test_without_docker_the_containers_are_none_and_a_stale_file_is_removed(host):
    """Fără `docker` pe PATH nu există nimic de întrebat și nimic de pierdut: «none», fără
    avertisment. Un fișier de containere rămas de la o capturare veche NU rămâne (ar descrie
    containere care n-au mai fost întrebate), iar `docker` nu e chemat deloc."""
    host.state.mkdir(parents=True)
    (host.state / "baseline-containers.txt").write_text("stale\n", encoding="utf-8", newline="\n")
    res = host.capture(no_docker=True)
    assert res.rc == 0, res.out
    assert host.data("containers") is None
    assert host.record() == "services=measured\nports=measured\ncontainers=none\n"
    assert "docker" not in host.calls_text(), host.calls_text()
    assert "[!]" not in res.out and "no docker on PATH" in res.out, res.out


def test_a_failed_record_write_is_reported_and_celebrated_nowhere(host):
    """Dacă înregistrarea nu poate fi scrisă (`mv` refuză), datele rămân, dar funcția nu
    pretinde succes: avertisment, 2, nicio linie «baseline captured». Fără înregistrare, un
    fișier GOL e citit ca «necunoscut», nu ca «nimic nu rula» (regula pentru baseline-urile
    vechi)."""
    host.passthrough("mv", "*baseline-state*")
    res = host.capture()
    assert res.rc == 2, res.out
    assert host.record() is None
    assert "could not write" in res.out and "baseline captured" not in res.out, res.out
    assert host.data("services"), "datele măsurate trebuiau să rămână"
    hidden = sorted(p.name for p in host.state.iterdir() if p.name.startswith("."))
    assert hidden == [], f"fișier temporar rămas în directorul de stare: {hidden}"


def test_a_state_record_that_cannot_even_get_a_temp_file_is_reported_the_same_way(host):
    """Aceeași ieșire când `mktemp` pentru înregistrare eșuează (disc plin, director fără
    drept de scriere): 2 și avertisment, nu un succes peste un fișier care nu s-a scris."""
    host.passthrough("mktemp", "*baseline-state*")
    res = host.capture()
    assert res.rc == 2 and host.record() is None, res.out
    assert "could not write" in res.out and "baseline captured" not in res.out, res.out


def test_a_temp_file_that_cannot_be_made_for_a_collector_is_unmeasured(host):
    """`baseline_measure` își face un fișier pentru stderr. Dacă `mktemp` pică, nu se poate
    spune nimic despre colector: dimensiunea e «nemăsurată» cu motivul numit, nu «măsurat
    gol»."""
    host.passthrough("mktemp", '""')
    res = host.capture()
    assert res.rc == 2, res.out
    assert [host.data(d) for d in DIMS] == [None, None, None]
    assert "mktemp failed" in res.out, res.out


def test_a_baseline_file_that_cannot_be_moved_into_place_is_unmeasured(host):
    """Fișierul de date se scrie ca `.new` și se mută la locul lui. Dacă mutarea pică, dimensiunea
    nu e măsurată (nu rămâne un `.new` orfan prezentat drept baseline)."""
    host.passthrough("mv", "*baseline-services.txt.new*")
    res = host.capture()
    assert res.rc == 2, res.out
    assert host.data("services") is None
    assert "services=unmeasured" in host.record()
    assert "could not move" in res.out, res.out


def test_a_processing_failure_is_not_recorded_as_a_measured_empty_list(host):
    """`awk` care pică după ce `systemctl` a răspuns bine ar lăsa un fișier gol — iar un fișier
    gol e exact ce se citea ca «nimic nu rula». Conducta e verificată (pipefail + `||`):
    dimensiunea e nemăsurată."""
    _stub(host.bin, "awk", "exit 3\n")
    res = host.capture()
    assert res.rc == 2, res.out
    assert host.data("services") is None and host.data("ports") is None
    assert "could not process or write the output" in res.out, res.out


def test_baseline_measure_reports_an_unwritable_output_and_an_unknown_dimension(host):
    """Cele două ieșiri ale lui `baseline_measure` care nu vin de la un colector: fișierul de
    ieșire nu poate fi scris (aici e un director) și o dimensiune pe care nu o cunoaște. Niciuna
    nu e «măsurat»."""
    res = host.run(
        f'mkdir -p "{host.tmp.as_posix()}/adir"\n'
        f'rc=0; baseline_measure ports "{host.tmp.as_posix()}/adir" || rc=$?\n'
        'echo "RC=$rc"\necho "WHY=$BASELINE_WHY"\n'
        f'rc2=0; baseline_measure bogus "{host.tmp.as_posix()}/x" || rc2=$?\n'
        'echo "RC2=$rc2"\necho "WHY2=$BASELINE_WHY"\n')
    assert res.rc == 1 and "could not write" in res.vars["WHY"], res.out
    assert res.vars["RC2"] == "1" and "unknown dimension" in res.vars["WHY2"], res.out
    assert host.calls_text().strip() == "ss -tlnH",         f"un colector a fost chemat pentru o dimensiune inexistentă: {host.calls_text()!r}"


# ===========================================================================
# baseline_state / baseline_complete — ce valorează un baseline de pe disc
# ===========================================================================
def _state_cases() -> list[tuple[str, str, dict, str | None, str]]:
    """(id, dim, fișiere, înregistrare, așteptat). Înregistrare: None = lipsește, 'DIR' = e un
    director, altfel conținutul."""
    return [
        # baseline-uri VECHI (fără înregistrare) — forma de pe ambele gazde de producție
        ("legacy-nonempty-services", "services", {"services": "a.service\n"}, None, "measured"),
        ("legacy-nonempty-ports", "ports", {"ports": "22\n"}, None, "measured"),
        ("legacy-nonempty-containers", "containers", {"containers": "web\n"}, None, "measured"),
        ("legacy-empty-services", "services", {"services": ""}, None, "legacy-empty"),
        ("legacy-empty-ports", "ports", {"ports": ""}, None, "legacy-empty"),
        ("legacy-empty-containers", "containers", {"containers": ""}, None, "legacy-empty"),
        ("legacy-missing-services", "services", {}, None, "missing"),
        ("legacy-missing-ports", "ports", {}, None, "missing"),
        ("legacy-missing-containers", "containers", {}, None, "none"),
        # înregistrare prezentă
        ("rec-measured", "ports", {"ports": "22\n"}, "ports=measured\n", "measured"),
        ("rec-measured-empty-file", "containers", {"containers": ""}, "containers=measured\n",
         "measured"),
        ("rec-measured-file-gone", "ports", {}, "ports=measured\n", "inconsistent"),
        ("rec-unmeasured", "ports", {}, "ports=unmeasured\n", "unmeasured"),
        ("rec-unmeasured-with-lingering-file", "ports", {"ports": "22\n80\n"},
         "ports=unmeasured\n", "unmeasured"),
        ("rec-none-containers", "containers", {}, "containers=none\n", "none"),
        ("rec-none-for-services", "services", {"services": "a\n"}, "services=none\n",
         "unrecognised"),
        ("rec-without-this-dim", "services", {"services": "a\n"}, "ports=measured\n",
         "unrecognised"),
        ("rec-garbage-value", "services", {"services": "a\n"}, "services=maybe\n",
         "unrecognised"),
        ("rec-empty-value", "services", {"services": "a\n"}, "services=\n", "unrecognised"),
        ("rec-prefix-collision", "services", {"services": "a\n"}, "xservices=measured\n",
         "unrecognised"),
        ("rec-truncated-to-zero-bytes", "services", {"services": "a\n"}, "", "unrecognised"),
        ("rec-is-a-directory", "services", {"services": "a\n"}, "DIR", "unreadable"),
    ]


def test_baseline_state_reads_every_shape_a_baseline_can_have(host):
    """O singură rulare, toate formele. Cele care contează pentru gazdele vii: un baseline de
    dinainte, cu conținut, rămâne «measured» (altfel următorul deploy ar refuza fără motiv); unul
    GOL de dinainte e «legacy-empty» (nu se poate deosebi de o capturare căzută); o înregistrare
    TRUNCHIATĂ la zero octeți NU cade înapoi pe regula veche («are conținut, deci e bun»), pentru
    că ar redeschide exact golul pe care înregistrarea îl închide."""
    cases = _state_cases()
    lines = []
    for cid, dim, files, record, _expected in cases:
        d = host.tmp / "cases" / cid
        d.mkdir(parents=True)
        for fdim, content in files.items():
            (d / f"baseline-{fdim}.txt").write_text(content, encoding="utf-8", newline="\n")
        if record == "DIR":
            (d / "baseline-state.txt").mkdir()
        elif record is not None:
            (d / "baseline-state.txt").write_text(record, encoding="utf-8", newline="\n")
        lines.append(f'echo "{cid}=$(baseline_state "{d.as_posix()}" {dim})"')
    res = host.run("\n".join(lines) + "\n")
    got = dict(re.findall(r"^([a-z0-9-]+)=(.*)$", res.proc.stdout, re.M))
    wrong = {cid: (got.get(cid), exp) for cid, _d, _f, _r, exp in cases if got.get(cid) != exp}
    assert not wrong, f"(obținut, așteptat) pe cazuri: {wrong}\n{res.out}"


def test_baseline_complete_says_when_a_baseline_can_be_compared_against(host):
    """Condiția de la `install.sh` pasul 18 («e nevoie de o capturare nouă?»). Forma de pe
    gazdele de producție (trei fișiere cu conținut, fără înregistrare) e COMPLETĂ: următorul
    deploy nu o re-captură. Una cu servicii goale, una cu o dimensiune «unmeasured» sau lipsă
    nu e: pasul 18 o reia. «containers=none» e completă."""
    cases = {
        "production-shape": (dict(services="a\n", ports="22\n", containers="web\n"), None, True),
        "legacy-services-empty": (dict(services="", ports="22\n", containers="web\n"), None, False),
        "legacy-ports-empty": (dict(services="a\n", ports="", containers="web\n"), None, False),
        "legacy-no-containers-file": (dict(services="a\n", ports="22\n"), None, True),
        "nothing-at-all": ({}, None, False),
        "record-all-measured": (dict(services="a\n", ports="22\n", containers=""),
                                "services=measured\nports=measured\ncontainers=measured\n", True),
        "record-one-unmeasured": (dict(services="a\n", ports="22\n"),
                                  "services=measured\nports=measured\ncontainers=unmeasured\n",
                                  False),
        "record-containers-none": (dict(services="a\n", ports="22\n"),
                                   "services=measured\nports=measured\ncontainers=none\n", True),
    }
    lines = []
    for cid, (files, record, _exp) in cases.items():
        d = host.tmp / "complete" / cid
        d.mkdir(parents=True)
        for fdim, content in files.items():
            (d / f"baseline-{fdim}.txt").write_text(content, encoding="utf-8", newline="\n")
        if record is not None:
            (d / "baseline-state.txt").write_text(record, encoding="utf-8", newline="\n")
        lines.append(f'if baseline_complete "{d.as_posix()}"; then echo "{cid}=yes"; '
                     f'else echo "{cid}=no"; fi')
    res = host.run("\n".join(lines) + "\n")
    got = dict(re.findall(r"^([a-z0-9-]+)=(yes|no)$", res.proc.stdout, re.M))
    wrong = {cid: (got.get(cid), "yes" if exp else "no")
             for cid, (_f, _r, exp) in cases.items() if got.get(cid) != ("yes" if exp else "no")}
    assert not wrong, f"{wrong}\n{res.out}"


# ===========================================================================
# assert_nothing_broken — DIRECȚIA A: un baseline nemăsurat nu e un „totul e bine”
# ===========================================================================
def test_an_unmeasured_capture_is_never_a_permanent_all_clear(host):
    """Reproducerea direcției A. Capturare cu toți colectorii căzuți, apoi colectorii merg din
    nou, iar un serviciu chiar s-a oprit. Vechiul cod: rc 0 și «nothing that was running before
    the deploy has stopped». Acum: 2, fiecare dimensiune cere o capturare, și NICIUN rând de
    succes."""
    for dim in DIMS:
        host.fail(dim)
    assert host.capture().rc == 2
    host.set("systemctl", "sshd.service loaded active running OpenSSH server daemon")
    host.set("ss", PORTS_OUT)
    host.set("docker", CONTAINERS_OUT)
    res = host.assert_()
    assert res.rc == 2, res.out
    assert OK_LINE not in res.out, res.out
    assert res.vars["UNKNOWN"] == "[ services ports containers]", res.out
    assert res.vars["COUNTS"] == "0 3", res.out   # câte unul per dimensiune, nu două
    assert res.vars["COUNTS"].split()[0] == "0", "un necunoscut s-a numărat ca eșec al instalării"
    assert res.out.count("could not be taken when it was recorded") == 3,         "fiecare dimensiune nemăsurată trebuie să-și spună motivul"


@pytest.mark.parametrize("dim", ("services", "ports", "containers"))
def test_a_legacy_empty_file_is_unknown_even_when_every_collector_works(host, dim):
    """Un fișier gol scris de codul de DINAINTE nu se poate deosebi de o capturare căzută. Cu
    colectori sănătoși acum, singura problemă e baseline-ul: rezultatul e 2 cu motivul numit,
    NU «nimic pierdut». (Pe gazdele de producție toate trei au conținut, deci nu sunt în cazul
    ăsta; costul real al regulii e o re-capturare la următorul preflight/pasul 18.)"""
    files = {"services": "sshd.service\n", "ports": "22\n", "containers": "web\n"}
    files[dim] = ""
    host.legacy(**files)
    res = host.assert_()
    assert res.rc == 2, res.out
    assert res.vars["UNKNOWN"] == f"[ {dim}]", res.out
    assert res.vars["COUNTS"] == "0 1", res.out   # un singur avertisment, nu două
    assert "empty and has no record" in res.out, res.out
    assert OK_LINE not in res.out


def test_no_baseline_at_all_is_unknown_for_services_and_ports(host):
    """Fără niciun fișier, nu există cu ce să se compare. Vechiul cod sărea peste dimensiune în
    tăcere și raporta succes; acum serviciile și porturile sunt «necunoscut» (cele două fișiere
    erau create ÎNTOTDEAUNA de codul vechi, deci lipsa lor înseamnă «nu s-a capturat»), iar
    containerele sunt «none» (fișierul lor exista doar cu docker)."""
    host.state.mkdir(parents=True)
    res = host.assert_()
    assert res.rc == 2, res.out
    assert res.vars["UNKNOWN"] == "[ services ports]", res.out
    assert res.vars["COUNTS"] == "0 2", res.out   # câte unul per dimensiune, nu două
    assert "no baseline of services was recorded" in res.out, res.out
    assert OK_LINE not in res.out


def test_an_unusable_record_is_unknown_not_a_pass(host):
    """Înregistrare prezentă dar fără sens (valoare necunoscută): «necunoscut», cu motivul
    numit. Citită ca «nimic de comparat» ar fi tot un fail-open."""
    host.legacy(services="sshd.service\n", ports="22\n", containers="web\n")
    (host.state / "baseline-state.txt").write_text(
        "services=maybe\nports=measured\ncontainers=measured\n", encoding="utf-8", newline="\n")
    res = host.assert_()
    assert res.rc == 2 and res.vars["UNKNOWN"] == "[ services]", res.out
    assert res.vars["COUNTS"] == "0 1", res.out   # un singur avertisment, nu două
    assert "unusable (unrecognised)" in res.out, res.out


# ===========================================================================
# assert_nothing_broken — DIRECȚIA B: o comparație nemăsurabilă nu e o pierdere
# ===========================================================================
@pytest.mark.parametrize("dim", DIMS)
def test_a_collector_that_fails_at_verify_time_is_unknown_not_lost(host, dim):
    """Reproducerea direcției B. Baseline bun, apoi `ss`/`systemctl`/`docker` cade în clipa
    verificării. Vechiul cod lăsa partea «acum» goală, deci FIECARE element din baseline părea
    pierdut: rc 1 și `rollback.sh --yes` peste o instalare sănătoasă. Acum: 2, nicio linie «no
    longer running / now closed / have stopped», niciun eșec numărat, iar comanda pe care
    operatorul o poate rula de mână e CHIAR cea pe care momeala a văzut-o chemată."""
    host.captured()
    before = host.calls_text()
    host.fail(dim, err=f"{TOOL[dim]}: boom now")
    res = host.assert_()
    assert res.rc == 2, res.out
    assert res.vars["UNKNOWN"] == f"[ {dim}]", res.out
    assert not re.search(r"no longer running|now closed|have stopped", res.out), res.out
    assert res.vars["COUNTS"].split()[0] == "0", "un eșec de măsurare s-a numărat ca instalare stricată"
    assert f"{TOOL[dim]}: boom now" in res.out, "motivul real s-a pierdut"
    advised = re.search(r"Run by hand: (.+)$", res.out, re.M).group(1).strip()
    invoked = [ln for ln in host.calls_text()[len(before):].splitlines()
               if ln.startswith(TOOL[dim] + " ")]
    assert invoked, f"colectorul {TOOL[dim]} n-a fost chemat la verificare"
    assert advised.replace("'", "") == invoked[-1], (advised, invoked)


@pytest.mark.parametrize("dim,tweak", [
    ("services", lambda h: h.set("systemctl", "sshd.service loaded active running x")),
    ("ports", lambda h: h.set("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")),
    ("containers", lambda h: h.set("docker", "web")),
])
def test_a_measured_loss_is_still_a_loss(host, dim, tweak):
    """Contra-proba direcției B: cu colectori care MERG și un element care chiar a dispărut,
    răspunsul rămâne 1 și numește ce s-a pierdut. O poartă care ar întoarce 2 la orice nu ar
    mai putea declanșa niciodată rollback-ul pentru o pierdere reală."""
    host.captured()
    tweak(host)
    res = host.assert_()
    assert res.rc == 1, res.out
    assert res.vars["UNKNOWN"] == "[]", res.out
    lost = {"services": "nginx.service", "ports": "80", "containers": "db"}[dim]
    assert lost in res.out, res.out
    assert res.vars["COUNTS"].split()[0] == "1", "o pierdere măsurată trebuie numărată ca eșec"
    assert OK_LINE not in res.out


def test_nothing_lost_is_reported_with_exactly_what_was_compared(host):
    """Cazul curat: 0, linia de succes numește dimensiunile comparate. «Nothing has stopped»
    spus fără să spună peste ce s-a comparat e o afirmație fără obiect."""
    host.captured()
    res = host.assert_()
    assert res.rc == 0, res.out
    assert res.vars["COMPARED"] == "[ services ports containers]"
    assert "compared: services ports containers" in res.out, res.out
    assert "[!]" not in res.out and "[x]" not in res.out, res.out


def test_a_measured_loss_wins_over_an_unknown_dimension(host):
    """O pierdere MĂSURATĂ pe o dimensiune e un fapt, chiar dacă alta n-a putut fi comparată:
    rc 1 (rollback-ul rămâne justificat), iar dimensiunea necomparată e listată oricum."""
    host.captured()
    host.set("systemctl", "sshd.service loaded active running x")
    host.fail("ports")
    res = host.assert_()
    assert res.rc == 1, res.out
    assert res.vars["UNKNOWN"] == "[ ports]", res.out
    assert "nginx.service" in res.out, res.out


def test_sentinels_own_services_moving_during_a_deploy_are_not_a_loss(host):
    """Unitățile `sentinel-*` se mișcă la un deploy și nu sunt obiectul verificării. O lipsă a
    lui `sentinel-detect.service` din starea de acum nu poate declanșa rollback."""
    host.captured()
    host.set("systemctl", "sshd.service loaded active running x\n"
                          "nginx.service loaded active running y")
    res = host.assert_()
    assert res.rc == 0, res.out


def test_the_sentinel_filter_is_anchored_at_the_start_of_the_name(host):
    """Filtrul `sentinel-` e pe PREFIX. Un serviciu al operatorului al cărui nume doar CONȚINE
    «sentinel-» (aici `xsentinel-proxy.service`) care s-a oprit e o pierdere reală — un filtru
    nelegat la început l-ar ascunde."""
    host.legacy(services="sshd.service\nxsentinel-proxy.service\n", ports="22\n", containers="web\n")
    host.set("systemctl", "sshd.service loaded active running x")
    res = host.assert_()
    assert res.rc == 1 and "xsentinel-proxy.service" in res.out, res.out


def test_docker_in_the_baseline_but_gone_now_is_unknown_not_skipped(host):
    """Baseline-ul a măsurat containere, iar acum `have docker` e fals. Vechiul `if have docker
    && [[ -f ... ]]` sărea dimensiunea în tăcere și raporta succes. Nu se poate întreba:
    «necunoscut», cu motivul numit."""
    host.captured()
    res = host.assert_(no_docker=True)
    assert res.rc == 2, res.out
    assert res.vars["UNKNOWN"] == "[ containers]", res.out
    assert "no docker on PATH now" in res.out, res.out
    assert OK_LINE not in res.out


def test_no_docker_at_capture_is_nothing_to_compare_and_stays_a_pass(host):
    """Contra-proba: docker n-a existat la capturare («none»). Nu există container care să se
    piardă, deci verificarea trece, iar linia de succes NU pretinde că a comparat containerele."""
    assert host.capture(no_docker=True).rc == 0
    res = host.assert_()
    assert res.rc == 0, res.out
    assert res.vars["COMPARED"] == "[ services ports]", res.out


# ===========================================================================
# Compatibilitate: baseline-urile de pe gazdele vii
# ===========================================================================
def test_the_production_shaped_baseline_keeps_comparing_exactly_as_before(host):
    """Măsurat pe 2 nov 2026 (doar citire), pe AMBELE gazde: trei fișiere cu conținut, scrise de
    codul vechi, fără `baseline-state.txt`. Citirea nouă le trebuie să le compare ca până acum:
    stare identică -> 0; un serviciu pierdut -> 1. O reclasificare tăcută ar face următorul
    deploy fie să refuze fără motiv, fie să treacă fals."""
    host.legacy(services="nginx.service\nsentinel-detect.service\nsshd.service\n",
                ports="22\n80\n", containers="db\nweb\n")
    same = host.assert_()
    assert same.rc == 0, same.out
    assert same.vars["COMPARED"] == "[ services ports containers]"
    host.set("systemctl", "sshd.service loaded active running x")
    lost = host.assert_()
    assert lost.rc == 1 and "nginx.service" in lost.out, lost.out


def test_a_comparison_that_cannot_sort_or_diff_is_unknown(host):
    """`sort` sau `comm` care pică lăsau fișierul de comparat gol/parțial, iar rezultatul era
    «nimic pierdut» (vechiul `|| true`). Fiecare ieșire are cuvântul ei."""
    host.captured()
    host.passthrough("sort", "*baseline-*")
    res = host.assert_()
    assert res.rc == 2 and "sort failed" in res.out, res.out
    assert OK_LINE not in res.out

    host.passthrough("sort", '"__niciodata__"')
    _stub(host.bin, "comm", "exit 1\n")
    res = host.assert_()
    assert res.rc == 2 and "comm failed" in res.out, res.out
    assert OK_LINE not in res.out


def test_a_comparison_that_cannot_make_a_temp_dir_is_unknown(host):
    """Fără director temporar nu se compară nimic: «necunoscut», nu o trecere."""
    host.captured()
    host.passthrough("mktemp", "-d*|*\" -d\"*")
    res = host.assert_()
    assert res.rc == 2 and "mktemp failed" in res.out, res.out
    assert OK_LINE not in res.out


# ===========================================================================
# step_verify_nothing_broken — NICIUN apelant nu transformă 2 în rollback sau în succes
# ===========================================================================
def _verify_harness(host: Host, assert_body: str) -> Result:
    """`step_verify_nothing_broken` LIVRATĂ, cu un `rollback.sh` fals care NOTEAZĂ apelul."""
    sd = host.tmp / "deploy"
    sd.mkdir(exist_ok=True)
    rb = sd / "rollback.sh"
    log = host.tmp / "rollback.log"
    rb.write_text(f'#!/usr/bin/env bash\necho "ROLLBACK $*" >> "{log.as_posix()}"\nexit 0\n',
                  encoding="utf-8", newline="\n")
    rb.chmod(rb.stat().st_mode | stat.S_IEXEC)
    body = (f'SCRIPT_DIR="{sd.as_posix()}"\nSNAPSHOT_DIR="{host.tmp.as_posix()}/snap"\n'
            f'VPS_WATCHDOG_DIR="{host.tmp.as_posix()}/wd"\nVPS_WATCHDOG_BACKUP_SUFFIX=.pre-adoption\n'
            + assert_body + "\n" + _func(INSTALL, "step_verify_nothing_broken")
            + '\nstep_verify_nothing_broken\necho "RC=0"\n')
    return host.run(body)


def _rollback_calls(host: Host) -> str:
    log = host.tmp / "rollback.log"
    return log.read_text(encoding="utf-8") if log.exists() else ""


def test_step_39_passes_quietly_when_nothing_was_lost(host):
    """Contra-proba: 0 -> la pasul următor, fără rollback și fără oprire."""
    res = _verify_harness(host, "assert_nothing_broken() { return 0; }")
    assert res.proc.returncode == 0 and res.vars.get("RC") == "0", res.out
    assert _rollback_calls(host) == "" and "FATAL" not in res.out


def test_step_39_rolls_back_only_on_a_measured_loss(host):
    """1 înseamnă «s-a pierdut ceva MĂSURAT» — singurul caz în care rollback-ul automat rămâne.
    Verificat prin efect: `rollback.sh` fals a fost chemat, cu `--yes`, și pasul moare."""
    res = _verify_harness(host, "assert_nothing_broken() { return 1; }")
    assert res.proc.returncode == 1, res.out
    assert "ROLLBACK" in _rollback_calls(host) and "--yes" in _rollback_calls(host)
    assert "Rolled back." in res.out
    # Dimensiunea pierdută poate fi alta decât serviciile, iar fișierul de servicii poate să nu
    # existe (nemăsurat): mesajul trimite la toate fișierele, nu la unul care poate lipsi.
    assert "baseline-*.txt" in res.out and "baseline-services.txt" not in res.out, res.out


@pytest.mark.parametrize("verdict", [2, 3, 5, 127, 255])
def test_step_39_never_rolls_back_or_passes_on_anything_but_0_or_1(host, verdict):
    """Orice altceva decât 0 sau 1 e «necunoscut». Vechiul `if ! assert_nothing_broken` îl citea
    ca pierdere și rula `rollback.sh --yes`; ar fi putut fi citit și ca succes. Verificat prin
    efect: `rollback.sh` NU e chemat, pasul NU trece (rc 1, FATAL), iar mesajul spune «could
    not verify» și nu «Rolled back»."""
    res = _verify_harness(host, f"assert_nothing_broken() {{ return {verdict}; }}")
    assert res.proc.returncode == 1 and "RC" not in res.vars, res.out
    assert _rollback_calls(host) == "", "rollback.sh a fost chemat pe o măsurătoare nemăsurată"
    assert "could not verify" in res.out and "Rolled back" not in res.out, res.out


def test_step_39_names_the_exact_commands_for_the_dimensions_that_were_unknown(host):
    """Mesajul oprit trebuie să spună operatorului ce să ruleze de mână — pentru dimensiunile
    necunoscute, nu pentru toate. Cu `BASELINE_UNKNOWN=' ports'`: `ss -tlnH` da, `systemctl`
    nu."""
    res = _verify_harness(host, "assert_nothing_broken() { BASELINE_UNKNOWN=' ports'; return 2; }")
    assert "ss -tlnH" in res.out and "systemctl list-units" not in res.out, res.out
    assert "docker ps" not in res.out, res.out


def test_step_39_with_no_named_dimension_names_all_three_commands(host):
    """Dacă `assert_nothing_broken` a întors necunoscut dar nu a spus care dimensiune, mesajul
    nu rămâne fără comenzi: le dă pe toate trei."""
    res = _verify_harness(host, "assert_nothing_broken() { BASELINE_UNKNOWN=''; return 2; }")
    for cmd in ("systemctl list-units --type=service", "ss -tlnH", "docker ps --format"):
        assert cmd in res.out, (cmd, res.out)


def test_a_failed_ss_through_the_whole_chain_does_not_roll_back_a_healthy_install(host):
    """Direcția B de la un capăt la altul, cu funcțiile LIVRATE: baseline bun, `ss` cade la
    verificare, `rollback.sh` (fals) NU e chemat și pasul se oprește cu «could not verify»."""
    host.captured()
    host.fail("ports")
    res = _verify_harness(host, "")
    assert res.proc.returncode == 1 and "could not verify" in res.out, res.out
    assert _rollback_calls(host) == "", "rollback automat peste o măsurătoare ratată"
    assert "ss -tlnH" in res.out


def test_a_real_loss_through_the_whole_chain_still_rolls_back(host):
    """Contra-proba capătului-la-capăt: același lanț, dar `ss` MERGE și un port chiar s-a închis.
    Rollback-ul se întâmplă."""
    host.captured()
    host.set("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")
    res = _verify_harness(host, "")
    assert res.proc.returncode == 1 and "Rolled back." in res.out, res.out
    assert "ROLLBACK" in _rollback_calls(host)


# ===========================================================================
# step_snapshot — re-capturarea nu se mai satisface cu un fișier gol
# ===========================================================================
def _snapshot_harness(host: Host, *, step19_done: bool) -> Result:
    if step19_done:
        host.state.mkdir(parents=True, exist_ok=True)
        (host.state / "19_user_and_dirs").write_text("2026-01-01T00:00:00Z\n", encoding="utf-8")
    body = (f'SENTINEL_BACKUP_DIR="{host.backup.as_posix()}"\n'
            f'SNAPSHOT_DIR="{host.backup.as_posix()}/snap"\n'
            "snapshot_create() { :; }\nln() { :; }\n"
            + _func(INSTALL, "step_snapshot") + '\nstep_snapshot\necho "RC=0"\n')
    return host.run(body)


def _collector_calls(host: Host) -> int:
    return len([ln for ln in host.calls_text().splitlines() if ln.strip()])


def test_step_18_leaves_a_comparable_baseline_alone(host):
    """Forma de pe gazdele vii (trei fișiere cu conținut, fără înregistrare) e comparabilă: pasul
    18 NU re-capturează, ca baseline-ul luat înainte de modificări să rămână cel din fața lor.
    Dovada e jurnalul momelilor: niciun colector chemat."""
    host.legacy(services="sshd.service\n", ports="22\n", containers="web\n")
    res = _snapshot_harness(host, step19_done=False)
    assert res.vars.get("RC") == "0", res.out
    assert _collector_calls(host) == 0, host.calls_text()
    assert host.record() is None


@pytest.mark.parametrize("shape", ["legacy-empty-services", "legacy-empty-ports", "unmeasured"])
def test_step_18_retakes_a_baseline_that_was_never_really_taken(host, shape):
    """Un `baseline-services.txt` GOL (un `systemctl` căzut la preflight) satisfăcea vechiul
    `[[ -f ... ]]`: nimic nu-l mai lua, iar fiecare rulare de după compara cu nimic. Acum pasul 18
    îl re-ia — dovedit prin efect: colectorii chemați și înregistrarea nouă scrisă."""
    if shape == "legacy-empty-services":
        host.legacy(services="", ports="22\n", containers="web\n")
    elif shape == "legacy-empty-ports":
        host.legacy(services="sshd.service\n", ports="", containers="web\n")
    else:
        host.legacy(services="sshd.service\n", containers="web\n")
        (host.state / "baseline-state.txt").write_text(
            "services=measured\nports=unmeasured\ncontainers=measured\n",
            encoding="utf-8", newline="\n")
    res = _snapshot_harness(host, step19_done=False)
    assert res.vars.get("RC") == "0", res.out
    assert _collector_calls(host) >= 3, host.calls_text()
    assert host.record() == "services=measured\nports=measured\ncontainers=measured\n"
    assert "AFTER an earlier run" not in res.out


def test_step_18_survives_a_capture_that_still_cannot_measure(host):
    """`capture_baseline` întoarce 2 când nu poate măsura; sub `set -e`, un apel gol ar opri
    instalarea chiar la pasul 18, înainte de orice modificare, fără mesaj propriu. Pasul continuă
    (avertismentele sunt ale capturii, iar pasul 39 se oprește pe ce a rămas)."""
    host.legacy(services="", ports="22\n", containers="web\n")
    host.fail("services")
    res = _snapshot_harness(host, step19_done=False)
    assert res.vars.get("RC") == "0", res.out
    assert "baseline of services NOT captured" in res.out, res.out


def test_step_18_says_so_when_it_retakes_the_baseline_after_the_host_was_changed(host):
    """Dacă pasul 19 e deja făcut, o rulare anterioară a modificat gazda: un baseline luat acum
    descrie gazda DE DUPĂ. Un «nothing stopped» de la pasul 39 ar valora doar «de acum încolo».
    Asta se spune, la re-capturare, nu se lasă de dedus."""
    host.legacy(services="", ports="22\n", containers="web\n")
    res = _snapshot_harness(host, step19_done=True)
    assert "AFTER an earlier run" in res.out, res.out
    assert host.record() == "services=measured\nports=measured\ncontainers=measured\n"


# ===========================================================================
# rollback.sh secțiunea 9 — aceeași cinste
# ===========================================================================
def _rollback_section() -> str:
    start = ROLLBACK.index('section "9. Servicii preexistente"')
    end = ROLLBACK.index("# Done here, at the very end")
    return ROLLBACK[start:end]


def _rollback_run(host: Host) -> Result:
    return host.run(_rollback_section() + '\necho "RC=0"\necho "COUNTS=$FAIL_COUNT $WARN_COUNT"\n')


def test_rollback_does_not_print_the_reassuring_line_for_an_unmeasured_baseline(host):
    """Rollback-ul compară cu același baseline. Cu un baseline GOL de la o capturare căzută,
    vechea ramură spunea «nimic nu mai e oprit» (fișierul exista). Acum: avertisment «could not
    verify», nicio linie de succes, fără `fail` (nu e o pierdere dovedită)."""
    host.legacy(services="", ports="22\n", containers="web\n")
    res = _rollback_run(host)
    assert res.vars.get("RC") == "0", res.out
    assert "could not verify" in res.out and "UNKNOWN" in res.out, res.out
    assert OK_LINE not in res.out, res.out
    assert res.vars["COUNTS"] == "0 2", res.out   # 0 eșecuri; 2 avertismente (dimensiunea + rezumatul)
    assert "(services: the warnings above say why)" in res.out, res.out


def test_rollback_with_no_baseline_at_all_says_it_cannot_verify(host):
    """Ramura «nu există baseline» era singura cinstită; acum e un caz al aceleiași reguli, cu
    comanda de rulat de mână. Nu mai ascunde porturile și containerele care ERAU înregistrate
    atunci când lipsea doar fișierul de servicii."""
    host.state.mkdir(parents=True)
    res = _rollback_run(host)
    assert "could not verify" in res.out and "systemctl --failed && ss -tlnp" in res.out, res.out
    assert OK_LINE not in res.out


def test_rollback_still_checks_ports_when_only_the_services_file_is_missing(host):
    """Poarta veche `[[ -f baseline-services.txt ]]` arunca verificarea întreagă dacă lipsea
    doar fișierul de servicii, deși porturile erau înregistrate. Acum porturile se compară: un
    port închis e pierdere (fail)."""
    host.legacy(ports="22\n80\n", containers="web\n")
    host.set("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")
    res = _rollback_run(host)
    assert "ports that were listening" in res.out and "80" in res.out, res.out
    # două `fail`: pierderea măsurată și rezumatul lui rollback.sh
    assert res.vars["COUNTS"].split()[0] == "2", res.out
    assert "no baseline of services was recorded" in res.out, res.out


def test_rollback_reports_a_measured_loss_and_a_clean_host(host):
    """Cele două capete rămân: pierdere măsurată -> «still not running» (fail); gazdă curată ->
    linia de succes cu ce s-a comparat."""
    host.captured()
    clean = _rollback_run(host)
    assert OK_LINE in clean.out and clean.vars["COUNTS"] == "0 0", clean.out
    host.set("systemctl", "sshd.service loaded active running x")
    lost = _rollback_run(host)
    assert "still not running after the rollback" in lost.out, lost.out
    assert lost.vars["COUNTS"].split()[0] == "2", lost.out


def test_rollback_with_a_failing_collector_is_unknown_not_a_failure(host):
    """`ss` căzut în timpul rollback-ului: nu e «ceva încă oprit» (fail), e necunoscut."""
    host.captured()
    host.fail("ports")
    res = _rollback_run(host)
    assert "still not running" not in res.out, res.out
    assert "could not verify" in res.out and "ports" in res.out, res.out
    assert res.vars["COUNTS"].split()[0] == "0"


# ===========================================================================
# preflight.sh — captura nu mai e un apel gol, iar sfatul certbot are subiect
# ===========================================================================
def _preflight_capture_section() -> str:
    start = PREFLIGHT.index('section "Ce rulează deja pe acest server"')
    end = PREFLIGHT.index("running_count=")
    return PREFLIGHT[start:end]


def test_preflight_survives_an_unmeasurable_baseline_and_says_what_follows(host):
    """`capture_baseline` răspunde 2 pentru o dimensiune nemăsurată. Un apel gol sub `set -e` ar
    fi terminat preflight-ul în tăcere. Acum continuă, cu avertismentul capturii (pe dimensiune)
    plus unul al preflight-ului care spune ce urmează la pasul 18 și 39."""
    host.fail("ports")
    res = host.run(_preflight_capture_section() + '\necho "RC=0"\necho "COUNTS=$FAIL_COUNT $WARN_COUNT"\n')
    assert res.vars.get("RC") == "0", "preflight-ul s-a oprit sub set -e:\n" + res.out
    assert "baseline of ports NOT captured" in res.out, res.out
    assert "baseline incomplete" in res.out and "step 39 will stop" in res.out, res.out
    assert res.vars["COUNTS"].split()[1] == "2"


def test_preflight_says_nothing_extra_when_the_baseline_was_taken(host):
    """Contra-proba: capturare completă -> fără «baseline incomplete», fără avertismente."""
    res = host.run(_preflight_capture_section() + '\necho "RC=0"\necho "COUNTS=$FAIL_COUNT $WARN_COUNT"\n')
    assert res.vars.get("RC") == "0" and res.vars["COUNTS"] == "0 0", res.out
    assert "baseline incomplete" not in res.out and "baseline captured" in res.out, res.out


def _block(text: str, start_line: str, end_line: str, must_contain: str) -> str:
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln == start_line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == end_line)
    block = "\n".join(lines[start:end + 1])
    assert must_contain in block
    return block + "\n"


def _hint_run(host: Host, ss_body: str) -> Result:
    _stub(host.bin, "ss", ss_body)
    block = _block(PREFLIGHT, 'owner80="$(port_owner 80)"', "fi", "HTTP-01")
    return host.run(block + 'echo "RC=0"\n', prelude_extra="nginx() { return 0; }\n")


def test_the_certbot_hint_names_a_subject_when_80_is_held_by_an_unnamed_process(host):
    """Un :80 ținut doar pe udp, fără proprietar tcp: ultimul braț tipărea « deține :80. Pentru
    un certificat real…» cu numele gol — o propoziție fără subiect, în singurul loc în care
    operatorul citește cine ține portul."""
    res = _hint_run(host, 'case "$*" in\n  *-ulnH*) echo "UNCONN 0 0 127.0.0.1:80 0.0.0.0:*" ;;\nesac\nexit 0\n')
    assert res.vars.get("RC") == "0", res.out
    assert "un proces pe care ss nu l-a putut numi deține :80" in res.out, res.out
    assert not re.search(r"\[\.\]\s+deține :80", res.out), f"subiect gol: {res.out}"


def test_the_certbot_hint_keeps_a_named_owner_in_its_own_sentence(host):
    """Contra-proba: când `port_owner` a numit procesul, propoziția îl numește pe EL, nu textul
    de rezervă."""
    res = _hint_run(
        host,
        'case "$*" in\n  *-tlnpH*) echo \'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=7,fd=4))\' ;;\n'
        '  *-tlnH*) echo "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*" ;;\nesac\nexit 0\n')
    assert '"httpd",pid=7,fd=4 deține :80' in res.out, res.out
    assert "un proces pe care ss nu l-a putut numi" not in res.out, res.out


# ===========================================================================
# Ramuri care ar fi rămas nesupravegheate (scoase din lista de mutații)
# ===========================================================================
def test_the_command_text_refuses_a_dimension_it_does_not_know(host):
    """Textul comenzii e ce i se spune operatorului să ruleze de mână. Pentru o dimensiune pe
    care n-o cunoaște nu inventează o comandă: iese 1 și nu tipărește nimic."""
    res = host.run('rc=0; out="$(baseline_cmd_text bogus)" || rc=$?\n'
                   'echo "RC=$rc"\necho "OUT=[$out]"\n')
    assert res.rc == 1 and res.vars["OUT"] == "[]", res.out


@pytest.mark.parametrize("scenario", ["healthy", "capture-fails", "verify-fails", "verify-cannot-sort",
                                      "no-docker", "unknown-dimension"])
def test_no_temp_file_is_left_behind(host, scenario):
    """Fiecare capturare și fiecare comparație își fac fișiere temporare (stderr-ul
    colectorului, directorul comparației). O verificare rulată o dată pe minut într-un alt
    context ar umple /tmp; pe calea de eșec, unde curățenia e cel mai ușor de uitat, la fel.
    TMPDIR e un director al testului, iar la sfârșit trebuie să fie gol."""
    tmpdir = host.tmp / "tmpdir"
    tmpdir.mkdir()
    env = {"TMPDIR": tmpdir.as_posix()}
    if scenario == "healthy":
        host.captured(env=env)
        assert host.assert_(env=env).rc == 0
    elif scenario == "capture-fails":
        for dim in DIMS:
            host.fail(dim)
        assert host.capture(env=env).rc == 2
    elif scenario == "verify-fails":
        host.captured(env=env)
        host.fail("ports")
        assert host.assert_(env=env).rc == 2
    elif scenario == "no-docker":
        assert host.capture(env=env, no_docker=True).rc == 0
    elif scenario == "unknown-dimension":
        res = host.run(f'rc=0; baseline_measure bogus "{host.tmp.as_posix()}/x" || rc=$?\n'
                       'echo "RC=$rc"\n', env=env)
        assert res.rc == 1, res.out
    else:
        host.captured(env=env)
        host.passthrough("sort", "*baseline-*")
        assert host.assert_(env=env).rc == 2
    left = sorted(p.name for p in tmpdir.iterdir())
    assert left == [], f"{scenario}: fișiere temporare rămase: {left}"


def test_a_second_capture_does_not_keep_the_first_ones_file_paths(host):
    """`BASELINE_SERVICES`/`BASELINE_PORTS` indică fișierele luate. După o a doua capturare în
    ACELAȘI proces, în care `systemctl` cade, variabila nu mai are voie să arate spre un fișier
    care nu există."""
    flag = host.tmp / "fail-services"
    _stub(host.bin, "systemctl",
          f'if [ -e "{flag.as_posix()}" ]; then echo boom >&2; exit 1; fi\n'
          "echo 'sshd.service loaded active running x'\n")
    res = host.run('capture_baseline > /dev/null\necho "FIRST=$BASELINE_SERVICES"\n'
                   f'touch "{flag.as_posix()}"\n'
                   'rc=0; capture_baseline > /dev/null 2>&1 || rc=$?\n'
                   'echo "SECOND=[$BASELINE_SERVICES]"\necho "RC=$rc"\n')
    assert res.vars["FIRST"].endswith("baseline-services.txt"), res.out
    assert res.rc == 2 and res.vars["SECOND"] == "[]", res.out


def test_a_padded_line_count_does_not_leak_into_the_success_line(host):
    """Pe unele sisteme (BSD, macOS) `wc -l` umple numărul cu spații. Linia de succes trebuie să
    spună «3 services», nu «       3 services»."""
    _stub(host.bin, "wc", 'PATH="${PATH#*:}"\nn="$(wc "$@")"\necho "      $n"\n')
    res = host.capture()
    assert res.rc == 0, res.out
    assert "baseline captured: 3 services, 2 listening ports, 2 running containers" in res.out, res.out


def test_a_second_verdict_does_not_keep_the_first_ones_lists(host):
    """`BASELINE_UNKNOWN` și `BASELINE_COMPARED` sunt globale. A treia verificare dintr-un proces
    (după una cu necunoscut) trebuie să le vadă goale / exacte, nu cumulate: altfel pasul 39 ar
    numi dimensiuni care nu mai sunt necunoscute."""
    host.captured()
    flag = host.tmp / "fail-ports"
    _stub(host.bin, "ss",
          f'if [ -e "{flag.as_posix()}" ]; then echo boom >&2; exit 1; fi\n'
          f"cat <<'EOF'\n{PORTS_OUT}\nEOF\n")
    res = host.run(
        'assert_nothing_broken one > /dev/null 2>&1\n'
        f'touch "{flag.as_posix()}"\n'
        'rc2=0; assert_nothing_broken two > /dev/null 2>&1 || rc2=$?\n'
        'echo "SECOND_UNKNOWN=[$BASELINE_UNKNOWN]"\n'
        f'rm -f "{flag.as_posix()}"\n'
        'rc=0; assert_nothing_broken three > /dev/null 2>&1 || rc=$?\n'
        'echo "RC=$rc"\necho "RC2=$rc2"\n'
        'echo "THIRD_UNKNOWN=[$BASELINE_UNKNOWN]"\necho "THIRD_COMPARED=[$BASELINE_COMPARED]"\n')
    assert res.vars["RC2"] == "2" and res.vars["SECOND_UNKNOWN"] == "[ ports]", res.out
    assert res.rc == 0, res.out
    assert res.vars["THIRD_UNKNOWN"] == "[]", res.out
    assert res.vars["THIRD_COMPARED"] == "[ services ports containers]", res.out


def test_a_record_that_says_measured_while_its_file_is_gone_is_unusable(host):
    """Înregistrarea spune «measured», fișierul a dispărut (șters de mână, disc). Nu e «nimic
    de comparat» și nu e «nimic pierdut»: e o inconsistență, deci necunoscut."""
    host.legacy(services="sshd.service\n", ports="22\n")
    (host.state / "baseline-state.txt").write_text(
        "services=measured\nports=measured\ncontainers=measured\n", encoding="utf-8", newline="\n")
    res = host.assert_()
    assert res.rc == 2 and res.vars["UNKNOWN"] == "[ containers]", res.out
    assert res.vars["COUNTS"] == "0 1", res.out   # un singur avertisment, nu două
    assert "unusable (inconsistent)" in res.out, res.out


def test_a_record_that_is_a_dangling_symlink_is_unusable_not_absent(host):
    """Un `baseline-state.txt` care e un link spre nicăieri nu există pentru `-e`, dar nici nu e
    «lipsă»: dacă gărzii îi lipsește `-L`, cade pe regula veche («are conținut, deci e bun») și
    deploy-ul de după compară cu un baseline despre care nimeni nu știe ce spune. Aici e
    `unreadable`, adică necunoscut.

    ACEST TEST SE SARE fără dreptul de a crea linkuri simbolice (Windows: `WinError 1314`, iar
    `ln -s` din git-bash eșuează la fel), deci pe mașina de dezvoltare Windows `-L` NU are
    observator. În depozit nu există niciun CI care să-l ruleze. A fost rulat doar sub WSL
    (bash 5.2, pytest într-un director propriu): verde cu `-L`, ROȘU fără el. Pe Windows
    rămâne neacoperit, și spus."""
    host.legacy(services="sshd.service\n", ports="22\n", containers="web\n")
    try:
        os.symlink(host.tmp / "nowhere", host.state / "baseline-state.txt")
    except (OSError, NotImplementedError) as err:
        pytest.skip(f"nu pot crea un link simbolic pe această mașină: {err}")
    res = host.run('baseline_state "$STATE_MARKERS" services\n')
    assert res.proc.returncode == 0 and res.proc.stdout.strip() == "unreadable", res.out
    assert not re.search(r"^(sed|cat):", res.out, re.M), res.out


def test_an_unreadable_record_is_its_own_answer_not_an_abort_and_not_a_bare_error(host):
    """Un `baseline-state.txt` care există dar nu se poate citi (aici: un DIRECTOR, care merge
    și pe Windows, spre deosebire de linkul spre nicăieri) făcea `sed` să iasă cu 2, iar sub
    `set -e -o pipefail` funcția murea ÎNAINTE de orice `echo`: apelul direct nu întorcea niciun
    răspuns. Pe căile din producție (`$( … )`, `||`) rămânea doar un `sed: can't read …` gol,
    fără dimensiune și fără consecință. Acum: un cuvânt (`unreadable`, deosebit de «am citit și
    nu spune nimic»), cod 0, nimic pe stderr."""
    host.legacy(services="sshd.service\n", ports="22\n", containers="web\n")
    (host.state / "baseline-state.txt").mkdir()
    res = host.run('baseline_state "$STATE_MARKERS" services\n')
    assert res.proc.returncode == 0, res.out
    assert res.proc.stdout.strip() == "unreadable", res.out
    assert res.proc.stderr == "", res.out


def test_an_unreadable_record_tells_the_operator_which_file_and_why_it_is_unknown(host):
    """Cuvântul `unreadable` ajunge la operator ca un avertisment care NUMEȘTE fișierul și felurile
    în care nu se poate citi; nu «unusable (unrecognised)», care ar trimite omul să caute o
    valoare greșită într-un fișier pe care nimeni nu l-a citit. Verdictul e același (2,
    necunoscut, un avertisment pe dimensiune, nicio linie de succes), fără `sed:`/`cat:` gol."""
    host.legacy(services="sshd.service\n", ports="22\n", containers="web\n")
    (host.state / "baseline-state.txt").mkdir()
    res = host.assert_()
    assert res.rc == 2 and res.vars["UNKNOWN"] == "[ services ports containers]", res.out
    assert res.vars["COUNTS"] == "0 3", res.out
    assert f"{host.state.as_posix()}/baseline-state.txt exists but cannot be read" in res.out, res.out
    assert "unrecognised" not in res.out, res.out
    assert OK_LINE not in res.out, res.out
    assert not re.search(r"^(sed|cat):", res.out, re.M), res.out


def test_a_record_that_cannot_be_written_is_reported_even_when_the_temp_file_exists(host):
    """`mktemp` reușește dar scrierea în fișierul temporar eșuează (disc plin, aici: numele e un
    DIRECTOR, ceea ce eșuează și ca root). O înregistrare trunchiată ar fi mutată la locul ei și
    citită abia mai târziu; aici se spune imediat: avertisment, 2, nicio linie de succes."""
    _stub(host.bin, "mktemp",
          'case "$*" in *baseline-state*) PATH="${PATH#*:}"; exec mktemp -d ;; esac\n'
          'PATH="${PATH#*:}"\nexec mktemp "$@"\n')
    res = host.capture()
    assert res.rc == 2 and host.record() is None, res.out
    assert "could not write" in res.out and "baseline captured" not in res.out, res.out


def test_a_comparison_that_cannot_sort_the_current_state_is_unknown(host):
    """A doua jumătate a comparației: `sort` pe starea de ACUM. Dacă pică doar el, `comm` ar
    primi un fișier lipsă/gol și ar raporta tot baseline-ul ca pierdut (direcția B) sau nimic;
    răspunsul cinstit e «necunoscut»."""
    host.captured()
    host.passthrough("sort", "*/now*")
    res = host.assert_()
    assert res.rc == 2 and "sort failed" in res.out, res.out
    assert not re.search(r"no longer running|now closed|have stopped", res.out), res.out


# ===========================================================================
# scripts/smoke-test.sh — citește aceleași fișiere, direct
# ===========================================================================
SMOKE = (REPO / "scripts" / "smoke-test.sh").read_text(encoding="utf-8")


def _smoke_block(baseline_dir: Path) -> str:
    start = SMOKE.index("baseline_dir=/var/lib/sentinel-install")
    end = SMOKE.index("failed_units=", start)
    block = SMOKE[start:end]
    assert "baseline-ports.txt" in block and "pass " in block, block[:200]
    return block.replace("baseline_dir=/var/lib/sentinel-install",
                         f'baseline_dir="{baseline_dir.as_posix()}"', 1)


def _smoke_run(host: Host) -> str:
    """Blocul «Regresie» din smoke-test.sh, LIVRAT, cu `r` înlocuit de o rulare locală (în
    producție `r` e `ssh … "$@"`) și `pass`/`fail`/`warn` care tipăresc un cuvânt-cheie."""
    script = host.tmp / "smoke.sh"
    script.write_text(
        "set -euo pipefail\n"
        'pass() { echo "PASS $*"; }\nfail() { echo "FAIL $*"; }\nwarn() { echo "WARN $*"; }\n'
        'r() { bash -c "$1"; }\n' + _smoke_block(host.state) + "\n", encoding="utf-8", newline="\n")
    environ = {**os.environ}
    environ["PATH"] = host.bin.as_posix() + os.pathsep + environ.get("PATH", "")
    proc = subprocess.run([BASH, script.as_posix()], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=environ)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout + proc.stderr


def test_smoke_test_does_not_pass_the_ports_when_their_baseline_was_never_taken(host):
    """De când un `ss` căzut nu mai lasă un `baseline-ports.txt` gol, fișierul poate LIPSI în
    timp ce cel de servicii există. `comm` pe un fișier lipsă iese cu eroare, `|| true` o
    înghițea, iar `lost_ports` gol se citea «fiecare port care asculta înainte ascultă încă»:
    un PASS pentru o comparație care n-a avut loc. Acum e un avertisment care spune de ce."""
    host.fail("ports")
    assert host.capture().rc == 2
    host.healthy()
    out = _smoke_run(host)
    assert "WARN no pre-install baseline of listening ports" in out, out
    assert "every port that was listening" not in out, out
    assert "PASS every service that was running" in out, "serviciile măsurate trebuiau comparate"


def test_smoke_test_still_compares_ports_when_their_baseline_exists(host):
    """Contra-proba: cu ambele fișiere, porturile se compară ca înainte — PASS când sunt la loc,
    FAIL când unul s-a închis."""
    host.captured()
    out = _smoke_run(host)
    assert "PASS every port that was listening" in out and "WARN" not in out, out
    host.set("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")
    out = _smoke_run(host)
    assert "FAIL ports closed since the install: 80" in out, out
