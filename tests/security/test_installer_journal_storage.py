"""Gazda își pierde tot istoricul de autentificare la fiecare repornire, și
nimeni nu află până când e nevoie de dovezi.

Pe RHEL și derivate `Storage=auto` fără `/var/log/journal` înseamnă jurnal în
`/run`: pe 10 septembrie 2026 producția a repornit după cinci zile și fiecare
`Failed password`, `Accepted publickey` și `Invalid user` din 6-9 septembrie a
dispărut — sursa primară de dovezi a produsului, ștearsă de un implicit de
distribuție. Ubuntu creează directorul din pachet, deci gazda n8n n-a arătat
niciodată defectul și nimic din depozit nu se uitase vreodată într-acolo.

Pasul 41 (`journal_storage`) repară asta, iar testele de aici apără fiecare
proprietate care poate să dispară tăcut din el:

  * pasul chiar rulează, la FIECARE deploy (în `main` și în `ALWAYS_STEPS`) —
    scos din listă, gazda rămâne volatilă și instalarea raportează succes;
  * pe o gazdă care e deja persistentă NU repornește `systemd-journald`, nu
    rescrie nimic și nu golește nimic. O repornire acolo e o schimbare pe care
    n-a cerut-o nimeni, pe demonul care ține chiar canalul de dovezi;
  * jurnalul e mărginit pe AMÂNDOUĂ axele. Fără pragul de mărime, un jurnal
    nemărginit umple partiția pe care stă PostgreSQL și cade baza; fără cel de
    timp, o gazdă tăcută ține la nesfârșit;
  * verificarea e pe EFECT, nu pe cod de ieșire. Dacă toate comenzile ies cu 0
    dar journald tot scrie în `/run`, pasul trebuie să pice zgomotos;
  * poziția colectorului `sshd` supraviețuiește. Flush-ul rescrie
    identificatorul de secvență al fiecărei intrări (măsurat pe AlmaLinux 9.8 /
    systemd 252-67.el9_8.4.alma.1, exact build-ul producției), iar
    `_journal_first_unread` din sentinel/selfcheck/checks.py compară cursorul ca
    ȘIR: fără re-ancorare, fiecare instalare ar fabrica exact critica falsă pe
    care trei runde de muncă tocmai au scos-o.

Fiecare test rulează BLOCUL LIVRAT din `deploy/install.sh`, nu o rescriere a
lui: secțiunea dintre `# --- 41 ---` și separatorul de dinaintea lui `main`,
sursată peste `lib/common.sh` și `lib/distro.sh` reale, cu momeli pe PATH în
locul comenzilor de sistem. Nicio momeală nu atinge o cale reală de sistem.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from shlex import quote as shlex_quote

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "deploy" / "install.sh"
COMMON_SH = REPO / "deploy" / "lib" / "common.sh"
INSTALL = INSTALL_SH.read_text(encoding="utf-8")
COMMON = COMMON_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")

_NO_BASH = (
    "bash lipsește din PATH, deci blocul livrat NU a fost rulat. "
    "Asta e „neverificat”, nu „în regulă”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


def _block() -> str:
    """Secțiunea pasului 41 exact așa cum se livrează.

    Un bloc, nu funcție cu funcție: constantele (`JOURNAL_MAX_USE`,
    `JOURNAL_MAX_USE_BYTES`, pragurile) fac parte din ce se testează, iar
    două dintre funcții sunt scrise pe un singur rând, unde un `^\\}` n-ar avea
    ce potrivi. Aserțiunile de mai jos există fiindcă o extragere care iese
    goală trece testele în tăcere — s-a mai întâmplat în depozitul ăsta.
    """
    match = re.search(r"^# --- 41 -+\n(.*?)^# ={20,}\n", INSTALL, re.S | re.M)
    assert match, "secțiunea pasului 41 nu mai există în deploy/install.sh"
    body = match.group(1)
    assert "step_journal_storage() {" in body
    assert body.count("\n") > 300, f"bloc suspect de scurt: {body.count(chr(10))} linii"
    return body


def _p(path: Path) -> str:
    return str(path).replace("\\", "/")


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# --------------------------------------------------------------------------
# Momelile. Fiecare își scrie chemarea în $CALLS și își ia răspunsul din
# directorul de scenariu ($SCEN), ca un test să descrie o gazdă prin fișiere în
# loc să rescrie momeala.
# --------------------------------------------------------------------------
JOURNALCTL_STUB = r"""
printf 'journalctl %s\n' "$*" >> "$CALLS"
args="$*"
case "$args" in
    *--header*)
        cat "$SCEN/header" 2>/dev/null || true
        exit 0 ;;
    *--flush*)
        # Flush-ul e momentul în care gazda devine persistentă: dacă scenariul
        # a pregătit un antet „de după", îl mută acum.
        [ -f "$SCEN/header.after" ] && cp "$SCEN/header.after" "$SCEN/header"
        exit "$(cat "$SCEN/flush-rc" 2>/dev/null || echo 0)" ;;
    *--output-fields=JOURNAL_NAME*)
        # Raportul de utilizare vine DOAR dacă i se cere chiar unitatea lui
        # journald. Altfel o sondă îndreptată din greșeală spre altă unitate ar
        # primi tot răspunsul ăsta, iar testele de mai jos ar verifica momeala
        # în loc de codul livrat — exact felul de test care trece degeaba.
        case "$args" in
            *"-u systemd-journald"*) cat "$SCEN/usage" 2>/dev/null || true ;;
        esac
        exit 0 ;;
    *--cursor*)
        cat "$SCEN/cursor-at" 2>/dev/null || true
        exit 0 ;;
    *-D*)
        cat "$SCEN/dread" 2>/dev/null || true
        exit 0 ;;
esac
exit 0
"""

SYSTEMCTL_STUB = r"""
printf 'systemctl %s\n' "$*" >> "$CALLS"
case "$*" in
    "show systemd-journald -p NRestarts --value")
        # `journald_restarts` is called exactly twice by the code under test —
        # once for "before", once for "after" — and the SECOND read is the one
        # that is allowed to answer differently, because that is what an
        # automatic restart occurring in between would look like. Counting our
        # own invocations, not the `restart` subcommand below, is what keeps
        # this tied to "how many times did the code ask", the actual question
        # `journald_restart_and_settle` puts to systemd — a scenario asking
        # for a crash loop must show it on the read AFTER the settle window,
        # not conjure it the moment `restart` is merely invoked.
        n="$(cat "$SCEN/nrestarts-reads" 2>/dev/null || echo 0)"
        n=$((n + 1))
        printf '%s' "$n" > "$SCEN/nrestarts-reads"
        if [ "$n" -ge 2 ] && [ -f "$SCEN/nrestarts.after" ]; then
            cat "$SCEN/nrestarts.after"
        else
            cat "$SCEN/nrestarts" 2>/dev/null || echo 0
        fi ;;
    "restart systemd-journald")
        # A `systemctl restart` issued BY US does not move NRestarts — only
        # systemd's own automatic restarts do (`Restart=always`); that is the
        # whole reason `journald_restart_and_settle` reads the counter instead
        # of trusting `is-active`. A stub that bumped the count right here
        # would be answering "did the code call restart", which is provable
        # from $CALLS already, not "did journald crash-loop", which is the one
        # thing this settle check exists to catch.
        exit "$(cat "$SCEN/restart-rc" 2>/dev/null || echo 0)" ;;
    "is-active --quiet systemd-journald")
        exit "$(cat "$SCEN/is-active-rc" 2>/dev/null || echo 0)" ;;
esac
exit 0
"""

INSTALL_STUB = r"""
printf 'install %s\n' "$*" >> "$CALLS"
dst=""; src=""; dir_mode=0
for a in "$@"; do
    case "$a" in
        -d) dir_mode=1 ;;
        -*) ;;
        *) src="$dst"; dst="$a" ;;
    esac
done
if [ "$dir_mode" = 1 ]; then
    mkdir -p "$dst"
else
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
fi
"""

STAT_STUB = r"""
fmt="$2"
case "$fmt" in
    %a)     cat "$SCEN/dirmode"  2>/dev/null || echo 2755 ;;
    %U:%G)  cat "$SCEN/dirowner" 2>/dev/null || echo root:systemd-journal ;;
    %C)     cat "$SCEN/selabel"  2>/dev/null || echo "?" ;;
esac
"""

SUDO_STUB = r"""
# `sudo -u postgres psql …` -> rulează restul, fără -u.
while [ "$1" = "-u" ] || [ "$1" = "-n" ]; do
    [ "$1" = "-u" ] && shift 2 || shift
done
exec "$@"
"""

# Baza, cât e nevoie: rândul `sshd` din collector_cursors și un UPDATE păzit de
# valoarea veche — exact ce face pasul.
PSQL_STUB = r"""
printf 'psql %s\n' "$*" >> "$CALLS"
case "$*" in
    *SELECT\ cursor*)
        cat "$SCEN/db-cursor" 2>/dev/null || true
        exit 0 ;;
esac
sql="$(cat)"
printf '%s\n' "$sql" > "$SCEN/last-sql"
old="$(printf '%s\n' "$sql" | sed -n "s/^\\\\set old '\(.*\)'$/\1/p")"
new="$(printf '%s\n' "$sql" | sed -n "s/^\\\\set new '\(.*\)'$/\1/p")"
have="$(cat "$SCEN/db-cursor" 2>/dev/null || true)"
# Momeala respectă EXACT paza pe care o cere SQL-ul. Dacă instrucțiunea nu mai
# conține `cursor = :'old'`, actualizarea prinde rândul oricare ar fi valoarea
# lui — altfel testul de mai jos ar verifica momeala, nu codul livrat.
guarded=0
case "$sql" in *"cursor = :'old'"*) guarded=1 ;; esac
if [ "$guarded" = 0 ] || [ "$old" = "$have" ]; then
    printf '%s' "$new" > "$SCEN/db-cursor"
    echo 1
else
    echo 0
fi
"""

NOOP_STUB = "exit 0\n"


def _scenario(tmp_path: Path, *, state: str = "runtime",
              state_after_flush: str = "persistent",
              machine_id: str = "abcdef01" "23456789" "abcdef01" "23456789",
              max_use: str = "2147483648",
              journal_name: str = "System Journal",
              db_cursor: str | None = None,
              cursor_at: str | None = None,
              operator_conf: str | None = None,
              extra: dict[str, str] | None = None) -> dict[str, str]:
    """Descrie o gazdă prin fișiere, și întoarce mediul care o pune în joc."""
    scen = tmp_path / "scen"
    scen.mkdir(parents=True, exist_ok=True)
    var_journal = tmp_path / "var" / "log" / "journal"
    run_journal = tmp_path / "run" / "log" / "journal"
    conf_dir = tmp_path / "etc" / "systemd" / "journald.conf.d"
    conf = tmp_path / "etc" / "systemd" / "journald.conf"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(operator_conf if operator_conf is not None else "[Journal]\nAudit=\n",
                    encoding="utf-8", newline="\n")

    mid_file = tmp_path / "machine-id"
    mid_file.write_text(machine_id + "\n", encoding="utf-8", newline="\n")

    def header(where: str) -> str:
        root = var_journal if where == "persistent" else run_journal
        if where == "unknown":
            return ""
        return (f"File path: {_p(root)}/{machine_id}/system.journal\n"
                f"File ID: 1111\nMachine ID: {machine_id}\nBoot ID: 2222\n"
                f"Sequential number ID: 3333\nState: ONLINE\n")

    (scen / "header").write_text(header(state), encoding="utf-8", newline="\n")
    (scen / "header.after").write_text(header(state_after_flush),
                                       encoding="utf-8", newline="\n")
    (scen / "usage").write_text(
        f"__CURSOR=s=1;i=1;b=1;m=1;t=1;x=1\nJOURNAL_NAME={journal_name}\n"
        f"JOURNAL_PATH={_p(var_journal)}/{machine_id}\nMAX_USE={max_use}\n\n",
        encoding="utf-8", newline="\n")
    (scen / "dread").write_text("o intrare de jurnal\n", encoding="utf-8", newline="\n")
    (scen / "nrestarts").write_text("0\n", encoding="utf-8", newline="\n")
    if db_cursor is not None:
        (scen / "db-cursor").write_text(db_cursor, encoding="utf-8", newline="\n")
    if cursor_at is not None:
        (scen / "cursor-at").write_text(f"__CURSOR={cursor_at}\n",
                                        encoding="utf-8", newline="\n")
    for name, content in (extra or {}).items():
        (scen / name).write_text(content, encoding="utf-8", newline="\n")

    # Fișierele de jurnal pe care verificarea de efect le numără: le pune
    # flush-ul pe o gazdă reală, aici le pune scenariul, fiindcă momeala de
    # journalctl nu scrie jurnale.
    if state_after_flush == "persistent":
        d = var_journal / machine_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "system.journal").write_bytes(b"LPKSHHRH")

    return {
        "SCEN": _p(scen),
        "CALLS": _p(tmp_path / "calls.txt"),
        "JOURNAL_DIR": _p(var_journal),
        "JOURNAL_RUNTIME_DIR": _p(run_journal),
        "JOURNALD_CONF": _p(conf),
        "JOURNALD_CONF_DIR": _p(conf_dir),
        "MACHINE_ID_PATH": _p(mid_file),
        "JOURNALD_SETTLE_S": "2",
    }


def _run(tmp_path: Path, env: dict[str, str], script: str,
         with_selinux: bool = False) -> subprocess.CompletedProcess:
    stubs = tmp_path / "bin"
    _stub(stubs, "journalctl", JOURNALCTL_STUB)
    _stub(stubs, "systemctl", SYSTEMCTL_STUB)
    _stub(stubs, "install", INSTALL_STUB)
    _stub(stubs, "stat", STAT_STUB)
    _stub(stubs, "sudo", SUDO_STUB)
    _stub(stubs, "psql", PSQL_STUB)
    _stub(stubs, "sleep", NOOP_STUB)
    if with_selinux:
        _stub(stubs, "selinuxenabled", NOOP_STUB)
        _stub(stubs, "restorecon", "printf 'restorecon %s\\n' \"$*\" >> \"$CALLS\"\n")
        _stub(stubs, "matchpathcon",
              "printf 'matchpathcon %s\\n' \"$*\" >> \"$CALLS\"\n"
              "cat \"$SCEN/policy-label\" 2>/dev/null || true\n")

    harness = tmp_path / "harness.sh"
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    harness.write_text(
        "set -euo pipefail\n"
        f'export SENTINEL_INSTALL_STATE_DIR="{_p(state)}"\n'
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        "DISTRO_FAMILY=rhel\n"
        + _block()
        + "\n" + script + "\n",
        encoding="utf-8", newline="\n")

    environ = {**os.environ, "NO_COLOR": "1", **env}
    environ["PATH"] = _p(tmp_path / "bin") + os.pathsep + environ.get("PATH", "")
    return subprocess.run(
        [BASH, _p(harness)],
        cwd=REPO / "deploy", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


def _calls(tmp_path: Path) -> str:
    f = tmp_path / "calls.txt"
    return f.read_text(encoding="utf-8") if f.exists() else ""


# --------------------------------------------------------------------------
# 1. Pasul chiar rulează
# --------------------------------------------------------------------------
def test_step_41_is_registered_and_runs_on_every_deploy():
    """Scos din lista de pași, gazda rămâne cu jurnal volatil și instalarea
    raportează în continuare succes — adică exact defectul, cu un instalator
    care spune că l-a reparat.

    Și dacă e doar scos din `ALWAYS_STEPS`: pe gazda de producție marcajul e
    pus la prima instalare, deci pasul n-ar mai rula NICIODATĂ pe gazda pentru
    care a fost scris, fără ca cineva să-și amintească `--force-step 41`.
    """
    assert re.search(r"^\s*run_step 41 journal_storage\s+step_journal_storage\s*$",
                     INSTALL, re.M), \
        "pasul 41 nu mai e înregistrat în main() din deploy/install.sh"

    always = re.search(r'^ALWAYS_STEPS="(.*?)"', COMMON, re.S | re.M)
    assert always, "ALWAYS_STEPS nu mai există în deploy/lib/common.sh"
    names = always.group(1).replace("\\\n", " ").split()
    assert "journal_storage" in names, \
        "journal_storage nu mai e în ALWAYS_STEPS, deci un deploy repetat îl sare"


def test_step_41_runs_before_the_notify_step_despite_its_number():
    """Rundă 1: un `die` din pasul 41 pica DUPĂ ce pasul 40 (`notify`) trimisese
    deja „Sentinel installed” pe Telegram — mesajul de succes era minciuna,
    FATAL-ul era adevărul, iar operatorul trebuia să știe să nu-l creadă pe
    primul.

    `run_step` compară `--from-step`/`--force-step` după NUMĂR, nu după unde
    stă apelul în `main`, deci numerele 40/41/42 pot rămâne cele din
    docs/OPERARE.md și din istoricul de comenzi al operatorului în timp ce
    ORDINEA DE RULARE se schimbă — apelul pasului 41 trebuie să fie înaintea
    apelului pasului 40 în text, ca să ruleze înaintea lui.

    O regresie aici — cineva care „ordonează" apelurile din nou după numărul
    lor — reintroduce exact defectul de mai sus, fără ca vreun alt test din
    fișierul ăsta (care rulează doar CORPUL pasului, nu `main`) să-l poată
    vedea.
    """
    call_41 = re.search(r"^\s*run_step 41 journal_storage\s+step_journal_storage\s*$",
                        INSTALL, re.M)
    call_40 = re.search(r"^\s*run_step 40 notify\s+step_notify\s*$", INSTALL, re.M)
    assert call_41, "apelul pasului 41 nu mai e în main()"
    assert call_40, "apelul pasului 40 (notify) nu mai e în main()"
    assert call_41.start() < call_40.start(), (
        "pasul 41 e chemat DUPĂ pasul 40 — un `die` acolo pică după ce "
        "Telegram a primit deja „Sentinel installed”"
    )


# --------------------------------------------------------------------------
# 2. Idempotență: gazda care e deja în regulă nu e atinsă
# --------------------------------------------------------------------------
def test_persistent_host_with_its_own_bounds_is_not_touched(tmp_path):
    """Gazda n8n: are deja `/var/log/journal` și praguri scrise de mână.

    Dacă pasul repornește `systemd-journald` acolo, taie exact demonul prin
    care Sentinel își ia dovezile, la fiecare deploy, pentru nimic — și
    rescrie o configurație pe care a scris-o operatorul.
    """
    env = _scenario(tmp_path, state="persistent",
                    operator_conf="[Journal]\nSystemMaxUse=1G\nMaxRetentionSec=7day\n")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)
    assert "systemctl restart" not in calls, f"a repornit journald degeaba:\n{calls}"
    assert "--flush" not in calls, f"a golit jurnalul degeaba:\n{calls}"
    assert "install " not in calls, f"a scris ceva pe o gazdă în regulă:\n{calls}"
    dropin = Path(env["JOURNALD_CONF_DIR"]) / "10-sentinel.conf"
    assert not dropin.exists(), "a scris un drop-in peste pragurile operatorului"
    assert "SystemMaxUse=1G" in r.stdout


def test_persistent_host_is_never_restarted_even_when_it_needs_bounds(tmp_path):
    """O gazdă Debian proaspătă: persistentă din pachet, dar fără praguri.

    Pragurile trebuie scrise — altfel jurnalul e nemărginit pe partiția bazei —
    dar NU cu prețul unei reporniri a lui journald pe o gazdă care își ține deja
    istoricul. Repornirea se cere operatorului, în text.
    """
    env = _scenario(tmp_path, state="persistent")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)
    assert "systemctl restart" not in calls, f"a repornit journald:\n{calls}"
    assert "--flush" not in calls, f"a golit jurnalul:\n{calls}"
    dropin = Path(env["JOURNALD_CONF_DIR"]) / "10-sentinel.conf"
    assert dropin.exists(), "n-a scris pragurile pe o gazdă nemărginită"
    assert "systemctl restart systemd-journald" in r.stdout + r.stderr, \
        "nu i-a spus operatorului cum se aplică pragurile"


def test_persistent_host_never_enters_the_restart_and_settle_path(tmp_path):
    """Un restraint pe care momeala VECHE de `systemctl` nu-l putea vedea căzând.

    Momeala veche muta `$SCEN/nrestarts` chiar la apelul `restart
    systemd-journald` — legat de SUBCOMANDĂ, nu de câte ori a întrebat codul
    cu adevărat systemd cât e contorul. Asta ar fi lăsat un mutant care intră
    din nou în `journald_restart_and_settle` pe o gazdă deja persistentă să
    arate, doar din fișierul NRestarts, ca și cum nimic nu s-ar fi întâmplat —
    momeala răspundea la „ai chemat restart”, nu la întrebarea pe care
    comentariul pasului o pune systemd-ului. Testul ăsta verifică faptul pe
    care se sprijină și testul de crash-loop (`NRestarts`, citit de DOUĂ ori,
    înainte/după o fereastră de așteptare) nu e nici măcar cerut aici: niciun
    apel `systemctl show systemd-journald -p NRestarts`, niciun `is-active`,
    și contorul de pe disc pus de scenariu rămâne neatins — nu doar cuvântul
    „restart” absent din jurnalul de apeluri.
    """
    env = _scenario(tmp_path, state="persistent")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)
    assert "NRestarts" not in calls, \
        f"a intrat în calea de repornire-și-așteptare pe o gazdă deja persistentă:\n{calls}"
    assert "is-active" not in calls, \
        f"a verificat starea lui journald după o repornire care n-a avut loc:\n{calls}"
    assert (Path(env["SCEN"]) / "nrestarts").read_text(encoding="utf-8") == "0\n", \
        "contorul NRestarts a fost atins deși pasul n-a repornit nimic"


def test_unknown_journal_state_never_restarts_journald(tmp_path):
    """„Nu pot citi” nu e „e volatil”.

    Dacă `journalctl --header` nu răspunde, o repornire a lui journald e o
    schimbare făcută pe ghicite pe demonul de jurnalizare. Pasul trebuie să
    spună că nu știe și să nu atingă nimic.
    """
    env = _scenario(tmp_path, state="unknown")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)
    assert "systemctl restart" not in calls, f"a acționat pe necunoscut:\n{calls}"
    assert "--flush" not in calls
    assert "nu pot citi unde scrie journald" in r.stderr


# --------------------------------------------------------------------------
# 3. Gazda volatilă chiar e reparată, și mărginită pe ambele axe
# --------------------------------------------------------------------------
def test_runtime_host_becomes_persistent_and_bounded(tmp_path):
    """Cazul producției: jurnal în /run, deci fiecare repornire șterge tot ce
    știe gazda despre autentificări."""
    env = _scenario(tmp_path, state="runtime")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = _calls(tmp_path)
    assert "systemctl restart systemd-journald" in calls
    assert "journalctl --flush" in calls
    assert Path(env["JOURNAL_DIR"]).is_dir()
    dropin = Path(env["JOURNALD_CONF_DIR"]) / "10-sentinel.conf"
    assert dropin.exists()
    assert "Storage=persistent" in dropin.read_text(encoding="utf-8")


def test_the_drop_in_is_bounded_by_both_size_and_time(tmp_path):
    """Un prag singur nu ajunge, și fiecare lipsă strică altceva.

    Fără pragul de MĂRIME, un jurnal care crește nemărginit umple partiția pe
    care stă PostgreSQL, și cade baza în care Sentinel ține absolut tot. Fără
    pragul de TIMP, o gazdă tăcută ține la nesfârșit un jurnal care nu ajunge
    niciodată la prag, iar fereastra de dovezi nu mai e previzibilă.

    `MaxFileSec` e verificat pentru că fără el pragul de timp e decorativ:
    retenția șterge FIȘIERE întregi, deci un fișier care acoperă toată
    fereastra nu expiră niciodată.
    """
    env = _scenario(tmp_path, state="runtime")
    r = _run(tmp_path, env, 'journal_dropin_body yes')
    assert r.returncode == 0, r.stderr
    body = r.stdout
    assert re.search(r"^SystemMaxUse=\S+$", body, re.M), "lipsește pragul de mărime"
    assert re.search(r"^MaxRetentionSec=\S+$", body, re.M), "lipsește pragul de timp"
    assert re.search(r"^MaxFileSec=\S+$", body, re.M), \
        "fără MaxFileSec, MaxRetentionSec nu are ce fișiere să expire"
    assert re.search(r"^Storage=persistent$", body, re.M)


def test_operator_bounds_are_never_overwritten(tmp_path):
    """Pragurile scrise de operator sunt un întreg, nu o listă de valori.

    Jumătate din ele înlocuite cu ale noastre e o configurație pe care n-a
    proiectat-o nimeni — de asta, când operatorul a scris fie și un singur
    prag, drop-in-ul conține DOAR linia Storage.
    """
    env = _scenario(tmp_path, state="runtime",
                    operator_conf="[Journal]\nSystemMaxUse=1G\n")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    dropin = (Path(env["JOURNALD_CONF_DIR"]) / "10-sentinel.conf").read_text(encoding="utf-8")
    assert "Storage=persistent" in dropin
    assert "SystemMaxUse" not in dropin, \
        "a scris pragul lui peste cel al operatorului"
    assert "MaxRetentionSec" not in dropin


def test_a_deliberately_volatile_host_is_left_alone(tmp_path):
    """Un instalator care suprascrie tăcut o alegere deliberată o face din nou
    la fiecare deploy, iar operatorul nu află niciodată de ce setarea lui
    pierde de fiecare dată."""
    env = _scenario(tmp_path, state="runtime",
                    operator_conf="[Journal]\nStorage=volatile\n")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)
    assert "systemctl restart" not in calls
    assert "--flush" not in calls
    assert "cere explicit un jurnal volatil" in r.stderr


# --------------------------------------------------------------------------
# 4. Verificarea e pe efect, nu pe cod de ieșire
# --------------------------------------------------------------------------
def test_step_fails_when_journald_did_not_actually_move(tmp_path):
    """TOATE comenzile ies cu 0 și journald tot scrie în /run.

    Ăsta e tiparul din CLAUDE.md — `augenrules --load` care raportează succes
    peste reguli respinse, `reload nginx` care întoarce 0 peste o configurație
    refuzată. Dacă pasul se uită la codul de ieșire în loc de efect, instalarea
    raportează „jurnal persistent" pe o gazdă care își pierde în continuare
    istoricul la fiecare repornire, iar defectul rămâne invizibil.
    """
    env = _scenario(tmp_path, state="runtime", state_after_flush="runtime")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, \
        "pasul a raportat succes deși journald a rămas pe /run:\n" + r.stdout
    assert "journald tot nu scrie" in r.stderr


def test_step_fails_when_journald_ignored_the_size_bound(tmp_path):
    """journald pornit, dar cu plafonul lui implicit de 4 G: configurația n-a
    fost citită.

    Fișierul e pe disc și demonul e pornit — două fapte adevărate care nu spun
    nimic despre ce prag aplică journald. Singurul care spune e ce raportează
    journald însuși, iar 4 G pe o gazdă care ține și baza de date e chiar riscul
    pentru care există pragul.
    """
    env = _scenario(tmp_path, state="runtime", max_use="4294967296")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, "a acceptat un prag mai mare decât cel cerut"
    assert "configurația nu a fost citită" in r.stderr


def test_step_fails_when_journald_reports_no_cap_at_all(tmp_path):
    """journald n-a spus nimic despre plafon după ce tocmai a fost repornit.

    „Nu știu" nu e „în regulă": un jurnal nemărginit pe partiția bazei de date
    nu e o îmbunătățire, deci pasul nu are voie să treacă mai departe raportând
    succes.
    """
    env = _scenario(tmp_path, state="runtime", journal_name="Runtime Journal")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, "a trecut fără să afle plafonul aplicat"
    assert "MAX_USE numeric" in r.stderr


def test_journald_that_crash_loops_is_not_reported_as_started(tmp_path):
    """`is-active` întoarce `active` pe fiecare tur al unei bucle de repornire.

    Un serviciu cu `Restart=always` — și journald are — trece prin `active` de
    fiecare dată când systemd îl ridică la loc. Testul ține gazda care răspunde
    „active" mereu, dar al cărei NRestarts a crescut: pasul trebuie să pice.
    """
    env = _scenario(tmp_path, state="runtime",
                    extra={"nrestarts.after": "7\n"})
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, \
        "a raportat journald pornit deși a repornit singur între timp"
    assert "nu a rămas pornit" in r.stderr


def test_a_manual_restart_that_resets_the_counter_is_healthy(tmp_path):
    """Gazda sănătoasă al cărei journald s-a mai repornit singur mai devreme
    în boot-ul curent — exact situația pe care produsul ăsta există s-o observe.

    O repornire EXPLICITĂ resetează NRestarts la 0 — nu-l lasă neschimbat —
    fiindcă systemd golește contorul la următoarea pornire care nu e automată.
    Producția a văzut asta pe 25 septembrie 2026: `dnf update` a repornit
    journald și contorul a citit 0, nu „neschimbat față de dinainte de update".
    Cu vechea aserțiune `before == after`, `before=3` (trei reporniri automate
    mai devreme) și `after=0` (după repornirea noastră) nu erau egale, deci
    pasul murea pe o gazdă complet sănătoasă și blama drop-in-ul.
    """
    env = _scenario(tmp_path, state="runtime",
                    extra={"nrestarts": "3\n", "nrestarts.after": "0\n"})
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, \
        "a picat pe o gazdă sănătoasă doar fiindcă journald mai repornise " \
        "singur mai devreme în boot:\n" + r.stdout + r.stderr


def test_a_crash_loop_that_happens_to_match_the_prior_count_still_dies(tmp_path):
    """Oglinda testului de mai sus: `before` și `after` egale, dar NU fiindcă
    journald a rămas neatins — fiindcă a intrat într-o buclă de repornire
    ÎN FEREASTRA DE AȘTEPTARE, iar numărul ei de tururi a nimerit peste
    numărul de reporniri automate de dinainte.

    Cu vechea aserțiune `before == after`, `before=2` și `after=2` treceau
    drept „neschimbat", deci pasul raporta jurnal pornit peste o buclă de
    repornire reală. Contorul citit DUPĂ repornirea noastră trebuie să fie
    0 — orice altă valoare e o repornire automată petrecută pe geana noastră,
    indiferent ce era `before`.
    """
    env = _scenario(tmp_path, state="runtime",
                    extra={"nrestarts": "2\n", "nrestarts.after": "2\n"})
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, \
        "a raportat journald pornit peste o buclă de repornire reală doar " \
        "fiindcă numărul ei de tururi a nimerit peste cel de dinainte:\n" + r.stdout
    assert "nu a rămas pornit" in r.stderr


# --------------------------------------------------------------------------
# 5. Poziția colectorului `sshd`
# --------------------------------------------------------------------------
OLD_CURSOR = ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf;"
              "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
              "t=65b1af9bd6aa6;x=1122334455667788")
# Aceeași intrare după flush: se schimbă DOAR identificatorul de secvență.
# Măsurat pe AlmaLinux 9.8 / systemd 252-67.el9_8.4.alma.1.
NEW_CURSOR = ("s=eeeeeeee" "ffffffff" "00000000" "11111111;i=2bf;"
              "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
              "t=65b1af9bd6aa6;x=1122334455667788")
# Altă intrare cu totul: alt număr de secvență, alt moment, alt hash.
OTHER_CURSOR = ("s=eeeeeeee" "ffffffff" "00000000" "11111111;i=9c1;"
                "b=01234567" "89abcdef" "01234567" "89abcdef;m=39aa0011;"
                "t=65b1afffffff0;x=1234567890abcdef")


def test_cursor_is_reanchored_to_the_same_entry_after_the_flush(tmp_path):
    """Fără asta, fiecare instalare fabrică o critică falsă.

    Flush-ul rescrie identificatorul de secvență al fiecărei intrări pe care o
    mută (măsurat pe build-ul exact al producției). `_journal_first_unread` din
    sentinel/selfcheck/checks.py compară cursorul stocat ca ȘIR, deci prima
    autoverificare de după instalare ar găsi poziția colectorului „dispărută",
    ar raporta `state=gone` -> `down`, și ar suna alarma exact de care trei
    runde de muncă tocmai au scăpat.
    """
    env = _scenario(tmp_path, state="runtime",
                    db_cursor=OLD_CURSOR, cursor_at=NEW_CURSOR)
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    stored = (Path(env["SCEN"]) / "db-cursor").read_text(encoding="utf-8")
    assert stored == NEW_CURSOR, f"poziția n-a fost re-ancorată: {stored}"
    assert "re-ancorată pe ACEEAȘI intrare" in r.stdout


def test_cursor_is_never_moved_onto_a_different_entry(tmp_path):
    """Mutarea cursorului înainte peste intrări necitite e o gaură în dovezi,
    și una tăcută.

    Dacă ce urmează după poziția salvată e ALTĂ intrare — jurnal rotit sub un
    colector oprit, poziție chiar pierdută — atunci rescrierea cursorului ar
    face autoverificarea verde peste intrări pe care nu le-a citit nimeni.
    Pasul trebuie să lase rândul neatins și să spună de ce.
    """
    env = _scenario(tmp_path, state="runtime",
                    db_cursor=OLD_CURSOR, cursor_at=OTHER_CURSOR)
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    stored = (Path(env["SCEN"]) / "db-cursor").read_text(encoding="utf-8")
    assert stored == OLD_CURSOR, "a mutat cursorul pe altă intrare"
    assert "ALTĂ intrare" in r.stderr


def test_cursor_untouched_when_the_flush_left_it_valid(tmp_path):
    """Pe o gazdă unde flush-ul nu schimbă nimic, rândul nu se atinge deloc —
    o scriere inutilă în collector_cursors e o cursă cu colectorul care rulează.
    """
    env = _scenario(tmp_path, state="runtime",
                    db_cursor=OLD_CURSOR, cursor_at=OLD_CURSOR)
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "UPDATE" not in (Path(env["SCEN"]) / "last-sql").read_text(encoding="utf-8") \
        if (Path(env["SCEN"]) / "last-sql").exists() else True
    assert "a supraviețuit flush-ului neschimbată" in r.stdout


def test_reanchor_is_guarded_by_the_value_it_read(tmp_path):
    """`sentinel-ingest` rulează în timpul instalării și își scrie singur
    poziția.

    Dacă a avansat între citirea noastră și scrierea noastră, valoarea lui e
    una proaspătă și validă; a o suprascrie cu o poziție mai veche înseamnă a
    citi a doua oară intrări deja procesate. UPDATE-ul e păzit de valoarea
    veche, deci nu atinge niciun rând, iar pasul spune asta.
    """
    env = _scenario(tmp_path, state="runtime",
                    db_cursor=OLD_CURSOR, cursor_at=NEW_CURSOR)
    # Colectorul se mișcă exact între SELECT și UPDATE: momeala de psql
    # răspunde la SELECT cu valoarea veche, dar rândul e deja altul.
    r = _run(tmp_path, env,
             'old="$(sshd_cursor_stored 5432)"\n'
             f'printf %s "{OTHER_CURSOR}" > "$SCEN/db-cursor"\n'
             f'out="$(sshd_cursor_reanchor 5432 "$old" "{NEW_CURSOR}")"\n'
             'echo "affected=[$out]"')
    assert r.returncode == 0, r.stderr
    assert "affected=[0]" in r.stdout, \
        "UPDATE-ul nu e păzit de valoarea citită; ar fi dat înapoi cursorul"
    assert (Path(env["SCEN"]) / "db-cursor").read_text(encoding="utf-8") == OTHER_CURSOR


def test_reanchor_reports_one_row_and_not_the_command_tag(tmp_path):
    """`psql -tA` tipărește ȘI rândul întors, ȘI eticheta comenzii.

    Cu un `UPDATE … RETURNING 1` gol-goluț ieșirea era „1UPDATE1" după ce se
    scoteau spațiile, deci niciodată „1": pasul chiar muta cursorul și apoi îi
    spunea operatorului că nu l-a mutat. Măsurat pe AlmaLinux 9 cu PostgreSQL
    real, cu tot cu rândul rescris în bază.
    """
    env = _scenario(tmp_path, state="runtime", db_cursor=OLD_CURSOR)
    r = _run(tmp_path, env,
             f'out="$(sshd_cursor_reanchor 5432 "{OLD_CURSOR}" "{NEW_CURSOR}")"\n'
             'echo "affected=[$out]"')
    assert r.returncode == 0, r.stderr
    assert "affected=[1]" in r.stdout, \
        "rezultatul UPDATE-ului nu e o singură cifră; poate fi citit în două feluri"
    sql = (Path(env["SCEN"]) / "last-sql").read_text(encoding="utf-8")
    assert "count(*)" in sql, "UPDATE-ul nu mai e împachetat într-un SELECT numărabil"


def test_a_cursor_that_is_not_hex_is_refused(tmp_path):
    """Cifrele nu sunt ASCII sub o localizare UTF-8.

    În `[[ =~ ]]`, `[0-9a-f]` potrivește și cifre fullwidth sau arabo-indice
    când localizarea nu e C — un defect care a mai costat o dată în depozitul
    ăsta. Valoarea asta ajunge în SQL, deci lista albă trebuie să fie chiar
    albă.

    Prima versiune a funcției punea `LC_ALL=C` în fața unui `[[ =~ ]]`, iar
    testul ăsta NU putea s-o vadă dispărând: pe mașina de dezvoltare ștergerea
    lui `LC_ALL=C` lăsa toate cele 25 de teste verzi, adică apărarea exista fără
    nimeni care s-o vadă dispărând. De asta funcția filtrează acum OCTEȚI
    (`tr -dc`), care nu depind de localizare — și de asta testul chiar pică dacă
    filtrul e scos.
    """
    fullwidth = ("s=７９５f11d709064b4eb753f428fdb37f8f;i=2bf;"
                 "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
                 "t=65b1af9bd6aa6;x=1122334455667788")
    env = _scenario(tmp_path, state="runtime")
    r = _run(tmp_path, env,
             f'if journal_cursor_is_wellformed "{fullwidth}"; then echo ACCEPTED; '
             'else echo REFUSED; fi\n'
             f'if journal_cursor_is_wellformed "{OLD_CURSOR}"; then echo REAL-OK; '
             'else echo REAL-REFUSED; fi\n',
             )
    assert r.returncode == 0, r.stderr
    assert "REFUSED" in r.stdout and "ACCEPTED" not in r.stdout, \
        "a acceptat cifre non-ASCII într-o valoare care ajunge în SQL"
    # Controlul pozitiv: lista albă nu e albă pentru că refuză tot.
    assert "REAL-OK" in r.stdout, "lista albă refuză și un cursor journald real"


def test_a_malformed_stored_cursor_is_not_rewritten(tmp_path):
    """Un rând stricat în collector_cursors nu se repară pe ghicite."""
    env = _scenario(tmp_path, state="runtime",
                    db_cursor="not-a-cursor", cursor_at=NEW_CURSOR)
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (Path(env["SCEN"]) / "db-cursor").read_text(encoding="utf-8") == "not-a-cursor"
    assert "nu are forma unui cursor journald" in r.stderr


# --------------------------------------------------------------------------
# 6. SELinux și drepturile directorului
# --------------------------------------------------------------------------
def test_selinux_label_is_verified_against_the_policy_not_the_exit_code(tmp_path):
    """`restorecon` întors cu 0 înseamnă că s-a făcut un apel, nu că eticheta e
    bună.

    Sub `enforcing`, un `/var/log/journal` etichetat greșit e un journald care
    nu poate scrie acolo — iar mesajul care spune DE CE trebuie să existe, nu
    doar eșecul de mai târziu.
    """
    env = _scenario(tmp_path, state="runtime",
                    extra={"selabel": "unconfined_u:object_r:default_t:s0\n",
                           "policy-label": "system_u:object_r:var_log_t:s0\n"})
    r = _run(tmp_path, env, "step_journal_storage", with_selinux=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "restorecon -RF" in _calls(tmp_path)
    assert "politica cere" in r.stderr, "n-a comparat eticheta cu politica"


def test_a_tightened_directory_is_never_widened(tmp_path):
    """O restrângere făcută de operator nu se desface din instalator.

    2755 e definiția systemd pentru directorul ăsta, dar dacă gazda are altceva,
    răspunsul e un avertisment cu motivul — nu un `chmod` care lărgește tăcut
    drepturile pe directorul de jurnale.
    """
    env = _scenario(tmp_path, state="runtime",
                    extra={"dirmode": "2750\n", "dirowner": "root:systemd-journal\n"})
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = _calls(tmp_path)
    assert "chmod" not in calls
    assert "2750" in r.stderr, "n-a spus operatorului ce drepturi are directorul"


def test_step_fails_when_the_persistent_directory_holds_no_journal(tmp_path):
    """journald raportează calea nouă, dar directorul e gol.

    „Demonul spune că scrie acolo" și „acolo chiar există un jurnal" sunt două
    fapte diferite, iar primul singur ar lăsa instalarea să raporteze succes
    peste un director gol — adică peste tot istoricul mutat nicăieri.
    """
    env = _scenario(tmp_path, state="runtime")
    # Flush-ul „reușește", journald raportează persistent, dar nu e niciun
    # fișier de jurnal acolo.
    mid = "abcdef01" "23456789" "abcdef01" "23456789"
    for f in (Path(env["JOURNAL_DIR"]) / mid).glob("*.journal"):
        f.unlink()
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, "a raportat succes peste un director gol"
    assert "niciun fișier de jurnal" in r.stderr


def test_step_fails_when_the_persistent_journal_cannot_be_read(tmp_path):
    """Fișiere pe disc, dar `journalctl -D` nu scoate nicio intrare din ele.

    Fișierele există, journald e pornit, codurile de ieșire sunt 0 — și totuși
    nimeni nu poate citi istoricul din locul unde se presupune că e. Fără
    întrebarea asta, exact starea aia trece drept reparație.
    """
    env = _scenario(tmp_path, state="runtime")
    (Path(env["SCEN"]) / "dread").write_text("", encoding="utf-8", newline="\n")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, "a raportat succes peste un jurnal necitibil"
    assert "nu citește nicio intrare" in r.stderr


def test_step_fails_when_the_flush_left_history_behind_in_run(tmp_path):
    """Flush parțial: o parte din istoric a rămas în /run și moare la repornire.

    E cazul care arată cel mai mult a succes — journald scrie în /var, fișierele
    sunt acolo, se citesc — și totuși o bucată din dovezi e tot volatilă.
    """
    env = _scenario(tmp_path, state="runtime")
    mid = "abcdef01" "23456789" "abcdef01" "23456789"
    leftover = Path(env["JOURNAL_RUNTIME_DIR"]) / mid
    leftover.mkdir(parents=True, exist_ok=True)
    (leftover / "system.journal").write_bytes(b"LPKSHHRH")
    r = _run(tmp_path, env, "step_journal_storage")
    assert r.returncode != 0, "a raportat succes peste un flush incomplet"
    assert "nu a golit" in r.stderr


def test_the_drop_in_is_not_rewritten_when_it_is_already_correct(tmp_path):
    """Un deploy care rescrie un fișier identic minte de două ori.

    `cmp` trăiește în diffutils, care lipsește de pe o imagine RHEL minimă:
    `cmp: command not found` făcea funcția să raporteze „schimbat" de fiecare
    dată, iar al doilea deploy rescria un fișier octet cu octet identic și îl
    avertiza pe operator despre asta. Măsurat pe AlmaLinux 9 curat.
    """
    env = _scenario(tmp_path, state="runtime")
    r = _run(tmp_path, env,
             'body="$(journal_dropin_body yes)"\n'
             'if journal_write_dropin "$body"; then echo FIRST-WROTE; '
             'else echo FIRST-SKIPPED; fi\n'
             'if journal_write_dropin "$body"; then echo SECOND-WROTE; '
             'else echo SECOND-SKIPPED; fi\n')
    assert r.returncode == 0, r.stderr
    assert "FIRST-WROTE" in r.stdout, "n-a scris deloc drop-in-ul"
    assert "SECOND-SKIPPED" in r.stdout, \
        "rescrie un fișier deja identic — detecția de „neschimbat” nu funcționează"


# Formă, verdict așteptat. Fiecare intrare numește ce ar intra în SQL dacă
# lista albă ar ceda pe ea.
_CURSOR_SHAPES = [
    (OLD_CURSOR, "OK", "un cursor journald real"),
    ("", "REFUSED", "rând gol în collector_cursors"),
    ("nu-e-cursor", "REFUSED", "text oarecare"),
    ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf", "REFUSED", "doar două câmpuri"),
    ("i=2bf;s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;"
     "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
     "t=65b1af9bd6aa6;x=1122334455667788", "REFUSED", "șase câmpuri, altă ordine"),
    ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf;"
     "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
     "t=65b1af9bd6aa6;z=1122334455667788", "REFUSED", "ultimul câmp are alt nume"),
    ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf;"
     "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
     "t=65b1af9bd6aa6;x=1122334455667788;q=1", "REFUSED", "un câmp în plus"),
    ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf;"
     "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
     "t=65b1af9bd6aa6;x=", "REFUSED", "câmp gol"),
    ("s=aaaaaaaa" "bbbbbbbb" "cccccccc" "dddddddd;i=2bf;"
     "b=01234567" "89abcdef" "01234567" "89abcdef;m=251e17ba;"
     "t=65b1af9bd6aa6;x=zzz'; DROP TABLE collector_cursors; --",
     "REFUSED", "SQL strecurat în câmpul din coadă"),
]


def test_the_cursor_whitelist_refuses_every_wrong_shape(tmp_path):
    """Valoarea din `collector_cursors` ajunge într-o instrucțiune SQL.

    Lista albă e a doua barieră după citarea lui psql, și e prima care decide
    dacă rândul are voie să fie REPARAT — un rând care nu e un cursor nu se
    mută pe ghicite. Testul trece prin ea fiecare formă greșită măsurabilă, cu
    un control pozitiv în capul listei ca lista albă să nu treacă „verificând"
    prin a refuza tot.

    Numărul de verdicte e verificat explicit: o listă care iese scurtă și e
    sărită în tăcere e chiar felul în care au trecut teste fără dinți aici.
    """
    env = _scenario(tmp_path, state="runtime")
    script = "\n".join(
        f'if journal_cursor_is_wellformed {shlex_quote(value)}; then '
        f'echo "{i} OK"; else echo "{i} REFUSED"; fi'
        for i, (value, _, _) in enumerate(_CURSOR_SHAPES))
    r = _run(tmp_path, env, script)
    assert r.returncode == 0, r.stderr
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    assert len(lines) == len(_CURSOR_SHAPES), \
        f"au ieșit {len(lines)} verdicte pentru {len(_CURSOR_SHAPES)} forme: {lines}"
    for i, (_, want, why) in enumerate(_CURSOR_SHAPES):
        assert lines[i] == f"{i} {want}", \
            f"forma „{why}”: aștept {want}, am primit {lines[i]}"
