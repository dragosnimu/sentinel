"""Smoke-testul nu are voie să spună „nimic pierdut" sau „totul pierdut" despre ce n-a putut măsura.

Secțiunea «Regresie» a `scripts/smoke-test.sh` compară ce rula înainte de instalare cu ce
rulează acum, peste ssh. Avea două feluri de a minți, ambele cu aceeași formă ca baseline-ul din
`deploy/lib/common.sh` (vezi `tests/security/test_installer_baseline_unknown.py`): un răspuns care
n-a venit se citea ca un răspuns gol.

  * **Un ssh căzut se citea PASS.** Comparația era `r "comm -23 BASELINE <(listă acum) | grep -v
    '^sentinel-'" || true`. Dacă ssh se tăia DUPĂ ce `test -f` reușise, `|| true` îl înghițea,
    șirul gol se citea «nimic oprit», iar operatorul primea «fiecare serviciu care rula înainte
    rulează încă» pentru o comparație care nu avusese loc. (`grep -v` iese cu 1 tocmai când
    nimic nu s-a pierdut, deci `|| true` nu putea lipsi.)
  * **Un `ss` căzut se citea pană generală.** Lista de ACUM goală făcea ca fiecare port din
    baseline să pară închis: «ports closed since the install: 22 80 443 …», pe o gazdă sănătoasă.
    Același lucru cu `systemctl`.

Al treilea răspuns nu e niciunul dintre cele două: «n-am putut măsura». Testele de aici cer
asta, și cer și dovada că o comparație a avut loc când spune că a avut: linia PASS poartă numărul
de intrări din baseline comparate, iar un `comm` fără ieșire nu e acea dovadă.

Au fost găsite și măsurate pe drum, pe aceleași linii (vezi `compare_baseline_dim`):
  * pe gazdă, `/var/lib/sentinel-install` e 0700 root:root din 8 sep 2026, deci `test -f` ca
    `sentinel-deploy` întoarce 1 — „nu există baseline" — chiar dacă baseline-ul există;
  * baseline-ul de porturi e scris cu `sort -u` lexical C, iar smoke-testul își sorta lista cu
    `sort -un`: `comm` primea două ordini și raporta porturi care ascultau drept închise.

Ce NU reproduce simularea de aici: un sshd real. `ssh` e o momeală care rulează comanda primită
printr-un `bash -c` local (la fel cum o reinterpretează shell-ul de pe gazdă) și poate fi făcută
să iasă cu 255, ca ssh însuși când conexiunea e refuzată sau tăiată. `sudo` e o momeală care
doar scoate `-n`; ce permisiuni are `sentinel-deploy` pe gazdă nu se vede de aici.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = (ROOT / "scripts" / "smoke-test.sh").read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")

# Ce arată `systemctl list-units --no-legend --plain` și `ss -tlnH`, ca pe gazdele de producție.
SERVICES_NOW = (
    "nginx.service loaded active running A web server\n"
    "sentinel-detect.service loaded active running Sentinel\n"
    "sshd.service loaded active running OpenSSH\n")
PORTS_NOW = (
    "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"
    "LISTEN 0 511 [::]:443 [::]:*\n"
    "LISTEN 0 128 0.0.0.0:10050 0.0.0.0:*\n")
SERVICES_WAS = "nginx.service\nsentinel-detect.service\nsshd.service\n"
# Ordinea lexicală C în care o scrie `capture_baseline`: 10050 înaintea lui 22, 443 înaintea lui 80.
PORTS_WAS = "10050\n22\n443\n80\n"


def _function(name: str) -> str:
    """Funcția TĂIATĂ din scriptul livrat, nu rescrisă."""
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", SMOKE, re.S | re.M)
    assert match, f"{name}() nu a fost găsită în smoke-test.sh"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class Fleet:
    """O gazdă falsă: ssh, sudo, systemctl și ss momeală pe PATH, un director de baseline."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.state = tmp / "state"
        self.state.mkdir()
        self.calls = tmp / "calls.log"
        self.calls.write_text("", encoding="utf-8", newline="\n")
        self.env: dict[str, str] = {}
        (self.state / "baseline-services.txt").write_text(SERVICES_WAS, encoding="utf-8", newline="\n")
        (self.state / "baseline-ports.txt").write_text(PORTS_WAS, encoding="utf-8", newline="\n")
        self.services_out = SERVICES_NOW
        self.ports_out = PORTS_NOW
        self.systemctl_rc = 0
        self.ss_rc = 0
        self.extra: dict[str, str] = {}

    def stub(self, name: str, body: str) -> None:
        """O momeală în plus pe PATH (instalată ultima, deci umbrește una mai veche)."""
        self.extra[name] = body

    def _install_stubs(self) -> None:
        calls = self.calls.as_posix()
        counter = (self.tmp / "ssh.count").as_posix()
        _stub(self.bin, "ssh",
              f'n=$(( $(cat "{counter}" 2>/dev/null || echo 0) + 1 )); echo "$n" > "{counter}"\n'
              f'echo "ssh $n: ${{@: -1}}" >> "{calls}"\n'
              'if [[ -n "${SSH_CUT_AFTER:-}" ]] && (( n > SSH_CUT_AFTER )); then\n'
              "  echo \"Warning: Permanently added 'h' (ED25519) to the list of known hosts.\" >&2\n"
              '  echo "client_loop: send disconnect: Connection reset" >&2; exit 255\n'
              "fi\n"
              'exec bash -c "${@: -1}"\n')
        _stub(self.bin, "sudo",
              'if [[ -n "${SUDO_REFUSES:-}" ]]; then echo "sudo: a password is required" >&2; exit 1; fi\n'
              # fără `-n`, un sudo real ar cere parola; fără terminal, eșuează — iar baseline-ul
              # n-ar mai fi citit. Momeala refuză la fel, ca absența lui `-n` să se vadă.
              '[[ "$1" == -n ]] || { echo "sudo: a password is required" >&2; exit 1; }\n'
              'shift\nexec "$@"\n')
        # Comenzile exacte pe care le cere gazdei: o momeală care răspunde la orice argumente ar
        # lăsa trecut un `--state=running` căzut, adică o listă cu și serviciile oprite.
        for name, want, out, rc, err in (
                ("systemctl", "list-units --type=service --state=running --no-legend --plain",
                 self.services_out, self.systemctl_rc, "Failed to connect to bus"),
                ("ss", "-tlnH", self.ports_out, self.ss_rc, "ss: netlink error")):
            body = (f"echo {name} \"$*\" >> \"{calls}\"\n"
                    f'[[ "$*" == "{want}" ]] || {{ echo "{name}: argumente neașteptate: $*" >&2; exit 2; }}\n')
            if rc:
                body += f"echo '{err}' >&2\nexit {rc}\n"
            else:
                body += f"cat <<'EOF'\n{out}EOF\n"
            _stub(self.bin, name, body)
        for name, body in self.extra.items():
            _stub(self.bin, name, body)

    def run(self, script: str) -> subprocess.CompletedProcess:
        self._install_stubs()
        path = self.tmp / "probe.sh"
        path.write_text(script, encoding="utf-8", newline="\n")
        env = {**os.environ, **self.env}
        env["PATH"] = self.bin.as_posix() + os.pathsep + env.get("PATH", "")
        return subprocess.run([BASH, path.as_posix()], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", env=env, timeout=120)

    def calls_text(self) -> str:
        return self.calls.read_text(encoding="utf-8")


@pytest.fixture
def fleet(tmp_path) -> Fleet:
    return Fleet(tmp_path)


PRELUDE = r"""
set -euo pipefail
PASS=0; FAIL=0; WARN=0
pass() { PASS=$((PASS+1)); printf 'PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf 'WARN %s\n' "$*"; }
HOST=h; USER=u; SSH_OPTS=(-p 22)
"""

# Inițializarea LIVRATĂ, nu una scrisă aici: dacă linia dispare din script, `set -u` trebuie să
# se plângă la sfârșit, iar un harnaș care o pune el însuși ar ascunde exact asta.
_INIT = re.search(r'^REGRESSION_UNMEASURED=""$', SMOKE, re.M)
assert _INIT, "inițializarea lui REGRESSION_UNMEASURED nu mai e în smoke-test.sh"
PRELUDE += _INIT.group(0) + "\n"


def _section(fleet: Fleet) -> str:
    """Secțiunea «Regresie» a scriptului LIVRAT: funcțiile și apelurile ei, nu o copie.

    Fără apelurile din script, testele ar proba funcțiile dar nu și faptul că scriptul le CHEAMĂ:
    o dimensiune scoasă din secțiune ar rămâne nevăzută."""
    start = SMOKE.index("baseline_dir=/var/lib/sentinel-install")
    end = SMOKE.index("failed_units=", start)
    block = SMOKE[start:end].replace("baseline_dir=/var/lib/sentinel-install",
                                     f'baseline_dir="{fleet.state.as_posix()}"', 1)
    assert "compare_baseline_dim services" in block and "compare_baseline_dim ports" in block, block
    return (PRELUDE + _function("measure_remote") + "\n" + _function("baseline_lines") + "\n"
            + _function("compare_baseline_dim") + "\n" + block
            + '\nprintf "CONTOARE %s %s %s\\n" "$PASS" "$WARN" "$FAIL"\n'
              'printf "NEMASURAT [%s]\\n" "$REGRESSION_UNMEASURED"\n')


class Out:
    def __init__(self, proc: subprocess.CompletedProcess):
        self.proc = proc
        self.text = proc.stdout + ("\n[stderr] " + proc.stderr if proc.stderr.strip() else "")
        counts = re.search(r"CONTOARE (\d+) (\d+) (\d+)", proc.stdout)
        assert counts, f"scriptul nu a ajuns la contoare (pass=0 = fișier stricat, nu falsificare); ieșire: {self.text!r}"
        self.passes, self.warns, self.fails = (int(counts.group(i)) for i in (1, 2, 3))
        self.unmeasured = re.search(r"NEMASURAT \[(.*)\]", proc.stdout).group(1).split()

    def lines(self, kind: str) -> list[str]:
        return [ln for ln in self.proc.stdout.splitlines() if ln.startswith(kind + " ")]


def _regression(fleet: Fleet) -> Out:
    out = Out(fleet.run(_section(fleet)))
    assert out.proc.returncode == 0, out.text
    return out


# --- contra-proba: gazda sănătoasă ---------------------------------------------

def test_a_healthy_host_passes_both_and_the_line_says_how_many_were_compared(fleet):
    """Contra-proba pentru tot ce urmează. Dacă o gazdă sănătoasă ar ieși cu avertismente sau cu
    eșec, testele de mai jos ar trece degeaba. Linia PASS poartă numărul de intrări comparate
    (3 servicii, 4 porturi): faptul observabil că o comparație a avut loc, nu un `comm` mut."""
    out = _regression(fleet)
    assert (out.passes, out.warns, out.fails) == (2, 0, 0), out.text
    assert any("still running (3 compared)" in ln for ln in out.lines("PASS")), out.text
    assert any("still is (4 compared)" in ln for ln in out.lines("PASS")), out.text
    assert out.unmeasured == [], out.text


def test_ports_whose_numeric_and_lexical_order_differ_are_not_reported_closed(fleet):
    """Baseline-ul de porturi e scris sortat lexical (10050 22 443 80); lista de acum era sortată
    numeric (22 80 443 10050). `comm` primea două ordini și raporta «ports closed since the
    install: 10050 443» pe o gazdă sănătoasă — cu baseline-ul real de pe producție ar fi fost
    alarma falsă care învață operatorul să nu mai citească raportul."""
    out = _regression(fleet)
    assert out.fails == 0 and not out.lines("FAIL"), out.text
    assert any("every port that was listening" in ln for ln in out.lines("PASS")), out.text


# --- direcția A: ssh căzut nu e PASS ------------------------------------------------

@pytest.mark.parametrize("answered", [0, 1, 2, 3, 4])
def test_a_cut_ssh_connection_is_never_a_pass_for_the_dimension_it_cut(fleet, answered):
    """Conexiunea ssh se taie după `answered` apeluri (în ordine: baseline servicii, servicii
    acum, baseline porturi, porturi acum). Înainte, un `comm` tăiat după `test -f` era înghițit
    de `|| true` și se citea «fiecare serviciu care rula înainte rulează încă» — PASS pentru o
    comparație care nu avusese loc. Acum: o dimensiune are PASS numai dacă AMBELE ei apeluri au
    răspuns (answered // 2 PASS-uri), restul sunt avertismente numite."""
    fleet.env["SSH_CUT_AFTER"] = str(answered)
    out = _regression(fleet)
    assert out.passes == answered // 2, out.text
    assert out.warns == 2 - answered // 2, out.text
    assert out.fails == 0 and not out.lines("FAIL"), out.text
    assert len(out.unmeasured) == 2 - answered // 2, out.text
    # motivul real ajunge la operator: ssh (cod 255) și prima linie de stderr, nu zgomotul de
    # «Permanently added» care vine înaintea ei
    for warning in out.lines("WARN"):
        assert "exit 255" in warning and "Connection reset" in warning, warning
        assert "Permanently added" not in warning, warning
        assert "neither 'nothing was lost' nor 'something was lost'" in warning, warning
        assert "Run by hand:" in warning, warning


def test_an_unanswered_comparison_does_not_end_with_the_green_sentence(fleet):
    """Chiar dacă fiecare avertisment e corect, ultima propoziție a scriptului («Sentinel
    funcționează, nimic altceva nu a fost afectat») îl îngropa: operatorul citește ultimul rând.
    Pentru ce n-a putut fi măsurat nu se știe nici asta, nici contrariul."""
    tail_start = SMOKE.rindex("if [[ -n \"$REGRESSION_UNMEASURED\" ]]; then")
    tail = SMOKE[tail_start:]
    script = (PRELUDE + 'REGRESSION_UNMEASURED=" services ports"\n'
              + "_G=''; _R=''; _Y=''; _B=''; _0=''\nWARN=2\n" + tail)
    proc = fleet.run(script)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "nimic altceva nu a fost afectat" not in proc.stdout, proc.stdout
    assert "services ports" in proc.stdout and "nici „nimic afectat" in proc.stdout, proc.stdout


def test_the_green_sentence_is_still_printed_when_everything_was_compared(fleet):
    """Contra-proba pentru testul de mai sus: cu totul măsurat și nimic pierdut, propoziția
    rămâne — altfel un avertisment inutil ar apărea la fiecare rulare."""
    tail_start = SMOKE.rindex("if [[ -n \"$REGRESSION_UNMEASURED\" ]]; then")
    script = (PRELUDE + "_G=''; _R=''; _Y=''; _B=''; _0=''\nPASS=2\n" + SMOKE[tail_start:])
    proc = fleet.run(script)
    assert proc.returncode == 0 and "nimic altceva nu a fost afectat" in proc.stdout, proc.stdout


# --- direcția B: ss / systemctl căzut nu e o pană generală --------------------------------

def test_a_failed_ss_is_not_reported_as_every_port_closed(fleet):
    """`ss` iese cu 1 la momentul smoke-testului. Lista de acum rămânea goală și FIECARE port din
    baseline apărea «închis»: «ports closed since the install: 10050 22 443 80» pe o gazdă
    sănătoasă, adică o pană generală afirmată pe un răspuns care n-a venit. Acum: un avertisment
    care numește comanda, codul și stderr-ul ei, iar serviciile (măsurate) rămân comparate."""
    fleet.ss_rc = 1
    out = _regression(fleet)
    assert not out.lines("FAIL"), out.text
    assert not any("every port" in ln for ln in out.lines("PASS")), out.text
    assert out.passes == 1 and out.warns == 1 and out.unmeasured == ["ports"], out.text
    warning = out.lines("WARN")[0]
    assert "ss -tlnH" in warning and "exited 1" in warning and "netlink error" in warning, warning


def test_a_failed_systemctl_is_not_reported_as_every_service_stopped(fleet):
    """Aceeași formă pe linia vecină: `systemctl list-units` căzut (ex. fără magistrala D-Bus)
    făcea lista de acum goală, iar smoke-testul striga «services stopped since the install:
    nginx.service sshd.service» despre o gazdă care nu oprise nimic."""
    fleet.systemctl_rc = 1
    out = _regression(fleet)
    assert not out.lines("FAIL"), out.text
    assert out.passes == 1 and out.warns == 1 and out.unmeasured == ["services"], out.text
    assert "Failed to connect to bus" in out.lines("WARN")[0], out.text


# --- baseline-ul însuși ---------------------------------------------------------------

def test_a_missing_ports_baseline_is_a_warning_and_the_services_are_still_compared(fleet):
    """De când un `ss` căzut la captură nu mai lasă un fișier gol, `baseline-ports.txt` poate
    LIPSI în timp ce cel de servicii există. `comm` pe un fișier lipsă iese cu eroare, iar
    `|| true` o făcea «porturile sunt la loc». Acum: avertisment, fără PASS pentru porturi."""
    (fleet.state / "baseline-ports.txt").unlink()
    out = _regression(fleet)
    assert out.passes == 1 and out.warns == 1 and out.fails == 0, out.text
    assert "no pre-install baseline of listening ports" in out.lines("WARN")[0], out.text
    assert out.unmeasured == ["ports"], out.text
    assert any("every service" in ln for ln in out.lines("PASS")), out.text
    assert not any("every port" in ln for ln in out.lines("PASS")), out.text


def test_a_missing_services_baseline_does_not_hide_the_ports_that_were_recorded(fleet):
    """Poarta veche era «dacă lipsește fișierul de servicii, nu mai verifica nimic»: porturile
    înregistrate nu mai erau comparate deloc. Dimensiunile sunt independente."""
    (fleet.state / "baseline-services.txt").unlink()
    out = _regression(fleet)
    assert out.passes == 1 and out.warns == 1, out.text
    assert out.unmeasured == ["services"], out.text
    assert any("every port" in ln for ln in out.lines("PASS")), out.text


def test_a_baseline_that_sudo_cannot_read_is_not_reported_as_missing(fleet):
    """Directorul e 0700 root:root, deci citirea cere `sudo`. Un sudo care refuză (parolă cerută,
    sudoers) întoarce 1, ca un `test -f` pe un fișier lipsă: operatorul ar fi citit «nu există
    baseline» și ar fi căutat un fișier care e acolo. Cele două au mesaje diferite, iar al doilea
    spune de ce."""
    fleet.env["SUDO_REFUSES"] = "1"
    out = _regression(fleet)
    assert out.passes == 0 and out.warns == 2 and not out.lines("FAIL"), out.text
    for warning in out.lines("WARN"):
        assert "could not read the pre-install baseline" in warning, warning
        assert "a password is required" in warning, warning
        assert "no pre-install baseline" not in warning, warning
        assert "Run by hand: sudo cat " in warning, warning


def test_an_empty_baseline_compares_nothing_and_says_so(fleet):
    """Un baseline gol (scris înainte de înregistrări, sau pe un capturator căzut) nu poate fi
    deosebit de «nu rula nimic». Un PASS «fiecare port care asculta ascultă încă (0 compared)»
    ar fi o propoziție adevărată despre nimic; e un avertisment."""
    (fleet.state / "baseline-ports.txt").write_text("", encoding="utf-8", newline="\n")
    out = _regression(fleet)
    assert out.passes == 1 and out.warns == 1 and out.unmeasured == ["ports"], out.text
    assert "is empty" in out.lines("WARN")[0] and "0 compared" not in out.text, out.text
    assert "Check by hand: ss -tlnp" in out.lines("WARN")[0], out.text


def test_a_baseline_with_repeated_lines_is_counted_and_compared_once_each(fleet):
    """Un baseline cu o linie repetată (un fișier editat de mână, două capturi lipite): fără
    deduplicare, `comm` vede al doilea «22» ca fără pereche în lista de acum și raportează un
    port care ascultă drept închis, iar numărul «comparate» ar fi umflat."""
    (fleet.state / "baseline-ports.txt").write_text("22\n22\n80\n", encoding="utf-8", newline="\n")
    out = _regression(fleet)
    assert out.fails == 0 and any("(2 compared)" in ln for ln in out.lines("PASS")), out.text


@pytest.mark.parametrize("was,now,lost", [
    ("a-c.service\nab.service\n", "a-c.service loaded active running x\n", "ab.service"),
    ("a-c.service\nab.service\nzz.service\n",
     "a-c.service loaded active running x\nab.service loaded active running x\n", "zz.service"),
])
def test_the_comparison_does_not_depend_on_the_locale_of_the_machine_running_it(fleet, was, now, lost):
    """Baseline-ul e scris cu `sort` lexical C (`capture_baseline`). Un `sort` local care ține
    cont de locale (en_US ignoră punctuația) pune `ab.service` înaintea lui `a-c.service`, iar
    `comm` — care așteaptă ordinea C — raportează ca pierdut un serviciu care rulează. Momeala
    pentru `sort` se poartă ca acea colație (`-d`) oricând LC_ALL nu e C, deci un `sort` fără
    LC_ALL=C pe oricare parte a comparației se vede."""
    (fleet.state / "baseline-services.txt").write_text(was, encoding="utf-8", newline="\n")
    fleet.services_out = now
    fleet.env["LC_ALL"] = "en_US.UTF-8"
    fleet.stub("sort", 'if [[ "${LC_ALL:-}" != C ]]; then PATH="${PATH#*:}"; exec sort -d "$@"; fi\n'
                       'PATH="${PATH#*:}"\nexec sort "$@"\n')
    out = _regression(fleet)
    fails = out.lines("FAIL")
    assert len(fails) == 1 and fails[0].split(": ", 1)[1].split() == [lost], out.text


# --- ce nu poate fi prelucrat local nu e nici «nimic pierdut», nici «totul pierdut» -----------

def test_a_local_sort_that_fails_on_the_baseline_means_nothing_was_compared(fleet):
    """Prima prelucrare locală (baseline-ul) cade, a doua nu: `was` ar rămâne gol, iar comparația
    ar fi pe un baseline inexistent. Se vede numai dacă momeala cade DOAR la primul apel."""
    counter = (fleet.tmp / "sort.count").as_posix()
    fleet.stub("sort", f'n=$(( $(cat "{counter}" 2>/dev/null || echo 0) + 1 )); echo "$n" > "{counter}"\n'
                       '[[ "$n" != 1 ]] || { echo "sort: boom" >&2; exit 2; }\n'
                       'PATH="${PATH#*:}"\nexec sort "$@"\n')
    out = _regression(fleet)
    assert not any("services" in ln for ln in out.lines("PASS") + out.lines("FAIL")), out.text
    assert any("could not process the services lists locally" in ln for ln in out.lines("WARN")), out.text
    assert "services" in out.unmeasured and not out.lines("FAIL"), out.text


def test_a_local_awk_that_fails_on_the_current_list_means_nothing_was_compared(fleet):
    """A doua prelucrare locală (lista de acum) cade: `now` gol ar face ca tot baseline-ul să
    pară pierdut — aceeași pană generală ca la un `ss` căzut, produsă de data asta local."""
    fleet.stub("awk", 'echo "awk: boom" >&2; exit 2\n')
    out = _regression(fleet)
    assert not out.lines("FAIL") and out.passes == 0 and out.warns == 2, out.text
    assert all("could not process the" in ln for ln in out.lines("WARN")), out.text
    warns = out.lines("WARN")
    assert "Run by hand: systemctl --failed" in warns[0] and "Run by hand: ss -tlnp" in warns[1], warns
    assert out.unmeasured == ["services", "ports"], out.text


def test_a_comm_that_fails_means_nothing_was_compared(fleet):
    """`comm` iese cu eroare (ordine greșită, resursă lipsă): ieșirea lui goală nu e «nimic
    pierdut». Înainte, `|| true` o făcea PASS."""
    fleet.stub("comm", 'echo "comm: file 1 is not in sorted order" >&2; exit 1\n')
    out = _regression(fleet)
    assert out.passes == 0 and out.warns == 2 and not out.lines("FAIL"), out.text
    assert all("comm failed (exit 1)" in ln for ln in out.lines("WARN")), out.text
    warns = out.lines("WARN")
    assert "Run by hand: systemctl --failed" in warns[0] and "Run by hand: ss -tlnp" in warns[1], warns
    assert out.unmeasured == ["services", "ports"], out.text


def test_an_unknown_dimension_is_a_failure_not_a_silent_skip(fleet):
    """Un apel cu un nume de dimensiune greșit (o tastare în script) n-ar compara nimic și n-ar
    spune nimic: secțiunea ar arăta mai scurtă și la fel de verde. Aici cade zgomotos."""
    script = (PRELUDE + _function("measure_remote") + "\n" + _function("baseline_lines") + "\n"
              + _function("compare_baseline_dim") + '\ncompare_baseline_dim bogus "/nu/conteaza"\n'
              'printf "CONTOARE %s %s %s\\n" "$PASS" "$WARN" "$FAIL"\n'
              'printf "NEMASURAT [%s]\\n" "$REGRESSION_UNMEASURED"\n')
    out = Out(fleet.run(script))
    assert out.fails == 1 and "unknown dimension 'bogus'" in out.lines("FAIL")[0], out.text
    assert "ssh" not in fleet.calls_text(), "o dimensiune necunoscută nu are de ce să cheme gazda"


# --- contra-probe: ce e pierdut cu adevărat tot e găsit ----------------------------------------

def test_a_port_that_really_closed_is_still_a_failure(fleet):
    """Reparația nu are voie să tacă și când răspunsul A venit: un port din baseline care nu mai
    ascultă e FAIL, cu numele lui. Altfel avertismentele ar fi singurul lucru pe care smoke-testul
    mai poate spune."""
    (fleet.state / "baseline-ports.txt").write_text("22\n8080\n", encoding="utf-8", newline="\n")
    out = _regression(fleet)
    assert out.fails == 1 and "ports closed since the install: 8080" in out.lines("FAIL")[0], out.text
    assert out.warns == 0, out.text


def test_a_service_that_really_stopped_is_a_failure_but_a_sentinel_unit_is_not(fleet):
    """Un serviciu din baseline care nu mai rulează e FAIL; unitățile `sentinel-*` se mișcă la o
    livrare și nu sunt ce verifică secțiunea (altfel fiecare deploy ar ieși roșu)."""
    (fleet.state / "baseline-services.txt").write_text(
        "mysql.service\nnginx.service\nsentinel-gone.service\nsshd.service\n", encoding="utf-8", newline="\n")
    out = _regression(fleet)
    fails = out.lines("FAIL")
    assert out.fails == 1 and "mysql.service" in fails[0], out.text
    assert "sentinel-gone" not in fails[0] and "nginx.service" not in fails[0], fails[0]


def test_only_sentinel_units_lost_is_a_pass_not_a_failure_and_not_a_silent_skip(fleet):
    """`grep -v '^sentinel-'` iese cu 1 când nu mai rămâne nimic, adică chiar în cazul în care
    nu s-a pierdut nimic ce contează. Filtrul în bash simplu nu are cum să-l confunde cu o
    eroare: se pierde doar o unitate sentinel-*, iar rezultatul e PASS, cu numărul comparat."""
    (fleet.state / "baseline-services.txt").write_text(
        "nginx.service\nsentinel-gone.service\n", encoding="utf-8", newline="\n")
    out = _regression(fleet)
    assert out.passes == 2 and out.fails == 0 and out.warns == 0, out.text
    assert any("(2 compared)" in ln for ln in out.lines("PASS")), out.text


# --- măsurătoarea însăși -------------------------------------------------------------------

def _measure(fleet: Fleet, stdout: str, stderr: str, rc: int, mktemp_fails: bool = False) -> dict[str, str]:
    if mktemp_fails:
        _stub(fleet.bin, "mktemp", 'echo "mktemp: cannot create temp file" >&2; exit 1\n')
    _stub(fleet.bin, "ssh",
          f'echo ssh >> "{fleet.calls.as_posix()}"\n'
          '[[ -z "$STUB_STDOUT" ]] || printf \'%s\\n\' "$STUB_STDOUT"\n'
          '[[ -z "$STUB_STDERR" ]] || printf \'%s\\n\' "$STUB_STDERR" >&2\n'
          'exit "$STUB_RC"\n')
    fleet.env.update(STUB_STDOUT=stdout, STUB_STDERR=stderr, STUB_RC=str(rc))
    script = (PRELUDE + _function("measure_remote") + "\n"
              'rc=0; measure_remote "ignored" || rc=$?\n'
              'printf "RC=%s\\nOUT=[%s]\\nWHY=[%s]\\n" "$rc" "$MEASURE_OUT" "$MEASURE_WHY"\n')
    path = fleet.tmp / "measure.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    env = {**os.environ, **fleet.env}
    env["PATH"] = fleet.bin.as_posix() + os.pathsep + env["PATH"]
    proc = subprocess.run([BASH, path.as_posix()], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return dict(re.findall(r"^(RC|OUT|WHY)=(.*)$", proc.stdout, re.M))


def test_a_command_that_ran_and_printed_nothing_is_a_measurement_not_a_failure(fleet):
    """`r` dădea același șir gol pentru «a rulat și n-are nimic de spus» și pentru «n-a rulat».
    Prima e o măsurătoare (cod 0, fără motiv); a doua nu. Dacă ele s-ar contopi iar, o gazdă
    cu zero rezultate ar fi raportată ca necunoscută, sau — mai rău — invers."""
    got = _measure(fleet, stdout="", stderr="", rc=0)
    assert got == {"RC": "0", "OUT": "[]", "WHY": "[]"}, got


def test_what_a_failed_command_managed_to_print_is_not_a_measurement(fleet):
    """O comandă căzută la mijloc a tipărit deja o parte din listă. Partea aia, tratată ca lista
    întreagă, ar face ca tot ce n-a apucat să apară să pară pierdut."""
    got = _measure(fleet, stdout="22\n80", stderr="ss: boom", rc=7)
    assert got["RC"] == "7" and got["OUT"] == "[]", got
    assert "exited 7" in got["WHY"] and "ss: boom" in got["WHY"], got


def test_the_stderr_file_of_every_measurement_is_removed(fleet):
    """Fiecare măsurătoare își ține stderr-ul într-un fișier temporar; scriptul rulează de zeci
    de ori pe an pe laptopul operatorului. Fără `rm`, /tmp acumulează câte un fișier pe apel,
    iar nimeni nu vede asta până când un `mktemp` eșuează de plin."""
    tmpdir = fleet.tmp / "scratch"
    tmpdir.mkdir()
    fleet.env["TMPDIR"] = tmpdir.as_posix()
    _measure(fleet, stdout="22", stderr="ceva", rc=0)
    _measure(fleet, stdout="", stderr="boom", rc=3)
    assert sorted(p.name for p in tmpdir.iterdir()) == [], list(tmpdir.iterdir())


def test_a_wc_that_pads_its_count_does_not_garble_the_compared_number(fleet):
    """`wc -l` din BSD/macOS tipărește «       3», nu «3». Fără tăierea spațiilor, linia ar
    spune «(       3 compared)» — un număr pe care operatorul nu-l mai poate citi dintr-o
    ochire și un tipar care nu mai e același între mașini."""
    fleet.stub("wc", 'PATH="${PATH#*:}"\nn="$(wc "$@")"\nprintf "       %s\\n" "${n// /}"\n')
    out = _regression(fleet)
    assert any("still running (3 compared)" in ln for ln in out.lines("PASS")), out.text


def test_a_machine_that_cannot_make_a_temp_file_does_not_ask_the_host_at_all(fleet):
    """Fără fișier pentru stderr, `measure_remote` nu are cum să spună DE CE a eșuat o comandă.
    Sub `set -e` un `mktemp` căzut ar fi oprit tot scriptul, la mijlocul raportului, fără o
    linie despre motiv; aici întoarce 1 cu motivul, iar gazda nu e întrebată."""
    got = _measure(fleet, stdout="22", stderr="", rc=0, mktemp_fails=True)
    assert got["RC"] == "1" and "mktemp failed" in got["WHY"], got
    assert "ssh" not in fleet.calls_text(), fleet.calls_text()


def test_ssh_failing_itself_is_told_apart_from_the_command_failing(fleet):
    """255 e ssh însuși (refuzat, tăiat, cheie respinsă); orice altceva e comanda de pe gazdă.
    Remediul e altul: într-un caz verifici rețeaua și cheia, în celălalt comanda."""
    got = _measure(fleet, stdout="", stderr="ssh: connect to host h port 22: Connection refused", rc=255)
    assert got["RC"] == "255" and "exit 255" in got["WHY"] and "Connection refused" in got["WHY"], got


# --- vocabularul ----------------------------------------------------------------------------

def test_the_baseline_comparison_does_not_borrow_the_word_unreadable():
    """În `smoke-test.sh`, `unreadable` e starea lui NGINX_STATE (un `nginx -T` pe care scriptul
    nu l-a putut citi); în `deploy/lib/common.sh` e starea înregistrării baseline-ului. Aceeași
    literă în două înțelesuri ar face ca un grep sau un `case` viitor să prindă ce nu trebuie.
    Aici baseline-ul nu are stare, are un motiv în cuvinte (MEASURE_WHY)."""
    for name in ("measure_remote", "baseline_lines", "compare_baseline_dim"):
        code = [ln for ln in _function(name).splitlines() if not ln.lstrip().startswith("#")]
        assert not any("unreadable" in ln for ln in code), (name, code)
    assert "NGINX_STATE=\"unreadable\"" in SMOKE, "înțelesul vechi trebuie să rămână neatins"
