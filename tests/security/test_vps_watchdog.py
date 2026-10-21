"""`deploy/vps-watchdog/watchdog.sh` - scriptul REAL, rulat cu fals-uri pe PATH.

Scriptul a trait doar pe gazda de productie, scris de mana, nevazut de nicio
revizie, trimitand pe Telegram sub numele botului Sentinel. Operatorul a primit
"Swap la 99%" ca problema noua si "Swap la 100%" ca rezolvata, intr-o singura
rulare, desi nimic nu se rezolvase. Cercetarea a gasit trei defecte, iar testele
de aici tin cate unul fiecare:

  A. IDENTITATEA unei alerte continea propria masuratoare. Diferenta se facea pe
     randuri intregi, deci fiecare punct procentual dadea o pereche nou/rezolvat.
  B. PRAGURILE ratau evenimentul real si sunau pe urmarile lui. RAM-ul disponibil
     a avut minimul 809 MB, iar pragul era 400 MB (zero esantioane sub el); swap-ul
     a ramas plin ore dupa ce presiunea trecuse. Un swap plin nu e o defectiune,
     paginarea activa este.
  C. NU ERA IN DEPOZIT, desi reporneste containere ca root. Garda de aici: nicio
     gazda reala nu are voie sa ajunga intr-un depozit public.

Fiecare test rulleaza `watchdog.sh` asa cum e livrat. Nu se reimplementeaza logica:
un test care o rescrie dovedeste rescrierea, nu scriptul pe care il ruleaza
timerul. Ce se simuleaza si ce NU are mediul asta:

  * `docker`, `curl`, `df`, `nproc`, `hostname`, `date`, `sleep`, `timeout` sunt
    fals-uri pe PATH, iar `/proc` e un director fabricat (`WATCHDOG_PROC`).
    Formatul real al lui /proc/vmstat si /proc/meminfo e cel din fixture, nu citit
    de pe o gazda: o schimbare de format a nucleului n-ar fi vazuta aici.
  * `timeout` e fals (transmite comanda mai departe): pe Windows `timeout` din
    PATH poate fi un alt program. Testul verifica DOAR ca `docker info` trece prin
    el, nu ca el chiar omoara un docker agatat.
  * Fals-ul de `curl` imita comportamentul real masurat: pe o conexiune cazuta
    scrie singur `000` pe stdout SI iese cu cod nenul.
  * Nu exista Telegram: mesajul e argumentul `text=` primit de fals-ul de curl.
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
WD_DIR = REPO / "deploy" / "vps-watchdog"
SCRIPT = WD_DIR / "watchdog.sh"
SERVICE = WD_DIR / "vps-watchdog.service"
TIMER = WD_DIR / "vps-watchdog.timer"
CONF_EXAMPLE = REPO / "deploy" / "config" / "vps-watchdog.conf.example"

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipseste din PATH")]

# Sintetic, dar cu forma unui token de bot - si garda de secrete din
# test_repo_is_sanitised.py recunoaste forma, nu intentia. De aceea se asambleaza
# la rulare din bucati scurte, nu se scrie ca un literal: o scutire numita ar fi
# fost o gaura permanenta pentru un castig de o linie.
TOKEN = ":".join(["1234567890", "-".join(["SYNTHETIC", "token", "for", "tests", "only", "0000"])])
CHAT = "-1001234567890"
MB = 1024  # kB per MB, pentru /proc/meminfo


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class Run:
    """Rezultatul unei rulari: ce s-a trimis, ce a ramas in stare, ce s-a chemat.

    Totul se citeste AICI, la sfarsitul rularii: directorul de apeluri e refolosit
    de rularea urmatoare, iar un obiect care citeste lenes ar arata mesajele altei
    rulari (asa a iesit o serie de teste "verzi" pe ultima rulare, goale pe celelalte).
    """

    def __init__(self, proc, calls: Path, state: Path):
        self.returncode = proc.returncode
        self.stdout = proc.stdout.decode("utf-8", errors="replace")
        self.stderr = proc.stderr.decode("utf-8", errors="replace")

        def read(name: str) -> str:
            p = calls / name
            return p.read_text(encoding="utf-8") if p.exists() else ""

        files = sorted(calls.glob("send.*"), key=lambda p: int(p.suffix[1:]))
        self.msgs: list[str] = [f.read_text(encoding="utf-8") for f in files]
        sp = state / "problems.state"
        self.state_lines: list[str] = (
            [l for l in sp.read_text(encoding="utf-8").splitlines() if l] if sp.exists() else [])
        self.restarts: list[str] = [l for l in read("restarts.log").splitlines() if l]
        self.timeout_calls: list[str] = [l for l in read("timeout.log").splitlines() if l]
        argv_files = sorted(calls.glob("curl.*.argv"), key=lambda p: int(p.name.split(".")[1]))
        self._argvs = [f.read_text(encoding="utf-8").splitlines() for f in argv_files]
        self._stdins = [f.read_text(encoding="utf-8") for f in sorted(calls.glob("curl.*.stdin"))]

    def curl_argvs(self) -> list[list[str]]:
        return self._argvs

    def curl_stdins(self) -> list[str]:
        return self._stdins

    def domain_urls(self) -> list[str]:
        return [a[-1] for a in self._argvs if "-K" not in a]


class Host:
    """O gazda fabricata: /proc, PATH-ul cu fals-uri, directorul de stare."""

    def __init__(self, root: Path):
        self.root = root
        self.bin = root / "bin"
        self.proc = root / "proc"
        self.state = root / "state"
        self.calls = root / "calls"
        for d in (self.bin, self.proc, self.state, self.calls):
            d.mkdir(parents=True, exist_ok=True)
        self.conf = root / "vps-watchdog.conf"
        self.secrets = root / "secrets.env"
        self.containers = root / "containers.txt"
        self.down = root / "down-domains.txt"
        self.containers.write_text("", encoding="utf-8")
        self.down.write_text("", encoding="utf-8")
        self.secrets.write_text(
            f"TELEGRAM_BOT_TOKEN={TOKEN}\nTELEGRAM_CHAT_ID={CHAT}\n", encoding="utf-8")
        (self.state / ".seeded").write_text("", encoding="utf-8")
        self._write_stubs()
        self.set_proc()

    # -- fals-uri -----------------------------------------------------------
    def _write_stubs(self) -> None:
        b = self.bin
        _stub(b, "hostname", 'echo testhost\n')
        _stub(b, "date", 'echo "$FAKE_NOW"\n')
        _stub(b, "nproc", 'echo 4\n')
        _stub(b, "sleep", 'exit 0\n')
        _stub(b, "df",
              '[ -n "${FAKE_DF_FAIL:-}" ] && { echo "df: cannot read" >&2; exit 1; }\n'
              "printf 'Use%%\\n %s%%\\n' \"$FAKE_DISK\"\n")
        _stub(b, "timeout", 'echo "$*" >> "$CALLS/timeout.log"; shift; exec "$@"\n')
        _stub(b, "docker",
              'case "$1" in\n'
              '  info) exit "${FAKE_DOCKER_INFO_RC:-0}" ;;\n'
              '  ps) cut -d"|" -f1 "$CONTAINERS" ;;\n'
              '  restart) echo "$2" >> "$CALLS/restarts.log"; exit 0 ;;\n'
              '  inspect)\n'
              '    line=$(grep "^$4|" "$CONTAINERS") || exit 1\n'
              '    IFS="|" read -r _n pol status health <<< "$line"\n'
              '    case "$3" in\n'
              '      *RestartPolicy*) echo "$pol" ;;\n'
              '      *State.Health*)  echo "$health" ;;\n'
              '      *State.Status*)  echo "$status" ;;\n'
              '    esac ;;\n'
              'esac\n')
        # `curl`: un apel cu `-K -` e Telegram (URL-ul vine pe stdin); oricare
        # altul e verificarea de domeniu. Un domeniu "cazut" imita curl-ul real:
        # scrie 000 singur pe stdout SI iese cu 7.
        _stub(b, "curl",
              'n=$(( $(cat "$CALLS/curl.n" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$CALLS/curl.n"\n'
              'printf "%s\\n" "$@" > "$CALLS/curl.$n.argv"\n'
              'for a in "$@"; do\n'
              '  if [ "$a" = "-K" ]; then\n'
              '    cat > "$CALLS/curl.$n.stdin"\n'
              '    for t in "$@"; do case "$t" in text=*) printf "%s" "${t#text=}" > "$CALLS/send.$n" ;; esac; done\n'
              '    exit 0\n'
              '  fi\n'
              'done\n'
              'url="${@: -1}"; host="${url#https://}"; host="${host%%/*}"\n'
              'if grep -qxF "$host" "$DOWN"; then printf 000; exit 7; fi\n'
              'printf 200; exit 0\n')

    # -- /proc --------------------------------------------------------------
    def set_proc(self, *, avail_mb: int | None = 4000, swap_total_mb: int = 2047,
                 swap_used_mb: int = 0, pswpin: int | None = 0, pswpout: int | None = 0,
                 load: str | None = "0.10") -> None:
        mem = self.proc / "meminfo"
        if avail_mb is None:
            mem.unlink(missing_ok=True)
        else:
            mem.write_text(
                f"MemTotal:        7865304 kB\nMemFree:          700000 kB\n"
                f"MemAvailable:   {avail_mb * MB} kB\nSwapTotal:      {swap_total_mb * MB} kB\n"
                f"SwapFree:       {(swap_total_mb - swap_used_mb) * MB} kB\n", encoding="utf-8")
        vm = self.proc / "vmstat"
        if pswpin is None:
            vm.unlink(missing_ok=True)
        else:
            vm.write_text(f"nr_free_pages 12345\npswpin {pswpin}\npswpout {pswpout}\n"
                          f"pgmajfault 99\n", encoding="utf-8")
        la = self.proc / "loadavg"
        if load is None:
            la.unlink(missing_ok=True)
        else:
            la.write_text(f"{load} 0.20 0.30 1/500 12345\n", encoding="utf-8")

    # -- stare, conf, containere ---------------------------------------------
    def write_state(self, lines: list[str]) -> None:
        (self.state / "problems.state").write_text(
            "".join(l + "\n" for l in lines), encoding="utf-8")

    def write_conf(self, text: str) -> None:
        self.conf.write_text(text, encoding="utf-8")

    def set_containers(self, rows: list[str]) -> None:
        self.containers.write_text("".join(r + "\n" for r in rows), encoding="utf-8")

    def set_down(self, domains: list[str]) -> None:
        self.down.write_text("".join(d + "\n" for d in domains), encoding="utf-8")

    # -- rulare ----------------------------------------------------------------
    def run(self, *, now: int = 1_000_000, disk: int = 40, env_extra: dict | None = None,
            script: Path = SCRIPT) -> Run:
        for f in self.calls.glob("send.*"):
            f.unlink()
        for name in ("restarts.log", "timeout.log"):
            (self.calls / name).unlink(missing_ok=True)
        for f in self.calls.glob("curl.*"):
            f.unlink()
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        env.update({
            "WATCHDOG_SECRETS": self.secrets.as_posix(),
            "WATCHDOG_CONF": self.conf.as_posix(),
            "WATCHDOG_STATE_DIR": self.state.as_posix(),
            "WATCHDOG_PROC": self.proc.as_posix(),
            "CALLS": self.calls.as_posix(),
            "CONTAINERS": self.containers.as_posix(),
            "DOWN": self.down.as_posix(),
            "FAKE_NOW": str(now),
            "FAKE_DISK": str(disk),
        })
        env.update(env_extra or {})
        proc = subprocess.run([BASH, str(script)], capture_output=True, env=env,
                              cwd=str(self.root), timeout=120)
        return Run(proc, self.calls, self.state)


@pytest.fixture
def host(tmp_path) -> Host:
    return Host(tmp_path / "h")


def _assert_channel_works(tmp_path: Path) -> None:
    """Martorul pozitiv pentru orice "nu s-a trimis nimic": pe o gazda identica,
    o problema NOUA ajunge efectiv la fals-ul de curl. Fara el, un canal rupt
    (token necitit, curl nepornit) ar face ca "zero mesaje" sa treaca oricum."""
    ctl = Host(tmp_path / "control")
    r = ctl.run(disk=99)
    assert r.returncode == 0, r.stderr
    assert len(r.msgs) == 1 and "problema noua" in r.msgs[0] and "Disk /" in r.msgs[0], \
        f"canalul de control nu livreaza: {r.msgs!r} / {r.stderr}"


DISK_90 = "cap:disk|💽 Disk / la 90% (prag 88%)"


# ===========================================================================
# A. Identitatea e cheia, nu randul
# ===========================================================================

def test_a_reading_that_moves_while_the_problem_persists_sends_nothing(host, tmp_path):
    """Operatorul a primit "Swap la 99%" ca problema noua si "Swap la 100%" ca
    rezolvata, in aceeasi rulare, desi nimic nu se rezolvase: diferenta se facea
    pe randuri intregi, iar randul continea masuratoarea. O problema care ramane
    cu alta valoare nu trebuie sa emita NIMIC - dar starea retine valoarea noua,
    ca un "rezolvat" ulterior sa citeze ultima citire reala."""
    host.write_state([DISK_90])
    r = host.run(disk=91)
    assert r.returncode == 0, r.stderr
    assert r.msgs == [], f"o citire schimbata a produs mesaje: {r.msgs!r}"
    assert r.state_lines == ["cap:disk|💽 Disk / la 91% (prag 88%)"]
    _assert_channel_works(tmp_path)


def test_a_problem_that_ends_is_resolved_once_with_its_last_reading(host, tmp_path):
    """Mesajul "rezolvat" trebuie sa spuna CE s-a rezolvat, iar problema nu mai
    exista in rularea curenta: textul vine din starea salvata, nu din rularea de
    acum. Fara textul pastrat, operatorul ar citi un "rezolvat" gol."""
    host.write_state([DISK_90])
    r = host.run(disk=40)
    assert len(r.msgs) == 1, r.msgs
    assert "rezolvat" in r.msgs[0] and "Disk / la 90%" in r.msgs[0]
    assert "problema noua" not in r.msgs[0]
    assert r.state_lines == []
    # a doua rulare, fara problema: nu se mai spune nimic
    assert host.run(disk=40).msgs == []


def test_a_new_problem_is_announced_once_and_not_again_when_it_worsens(host):
    """Prima aparitie anunta; urmatoarele rulari cu valoarea in urcare nu mai
    anunta nimic (altfel fiecare % in plus e un mesaj)."""
    first = host.run(disk=89)
    assert len(first.msgs) == 1 and "problema noua" in first.msgs[0] and "89%" in first.msgs[0]
    assert host.run(disk=93).msgs == []
    assert host.run(disk=97).msgs == []
    assert host.run(disk=97).state_lines == ["cap:disk|💽 Disk / la 97% (prag 88%)"]


def test_two_different_problems_at_once_are_not_confused(host):
    """Una se rezolva si alta apare in aceeasi rulare: fiecare in mesajul ei, cu
    textul ei. Cheile se compara EXACT - `ctr:web:loop` si `ctr:web-2:loop` sunt
    probleme diferite (nu prefix al celeilalte)."""
    host.write_state(["ctr:web:loop|🔁 \"web\" in crash-loop"])
    host.set_containers(["web-2|always|restarting|"])
    r = host.run()
    assert len(r.msgs) == 2, r.msgs
    new = next(m for m in r.msgs if "problema noua" in m)
    res = next(m for m in r.msgs if "rezolvat" in m)
    assert "web-2" in new and "\"web\" in" not in new
    assert "\"web\" in crash-loop" in res and "web-2" not in res


def test_state_written_by_the_previous_version_is_read_without_migration(host, tmp_path):
    """Pe gazda exista deja un problems.state in formatul `cheie|text`. Daca noul
    cod nu l-ar citi, prima rulare ar anunta ca "noua" fiecare problema deja
    cunoscuta - o furtuna de mesaje la livrare."""
    host.write_state([DISK_90, "ctr:web:loop|🔁 \"web\" in crash-loop - auto-fix NU reporneste"])
    host.set_containers(["web|always|restarting|"])
    r = host.run(disk=90)
    assert r.msgs == [], r.msgs
    assert len(r.state_lines) == 2
    _assert_channel_works(tmp_path)


def test_the_retired_swap_percentage_key_disappears_without_a_false_resolved(host, tmp_path):
    """La livrare, starea veche are `cap:swap|Swap la 100%`. Verificarea a fost
    scoasa pe motiv ca un swap plin nu e o defectiune - dar operatorul ar citi
    "rezolvat: Swap la 100%" pe un swap care e inca plin. Cheia retrasa se scoate
    din starea veche in tacere."""
    host.write_state(["cap:swap|🔺 Swap la 100%"])
    host.set_proc(swap_used_mb=2047)
    r = host.run()
    assert r.msgs == [], r.msgs
    assert r.state_lines == []
    _assert_channel_works(tmp_path)


# ===========================================================================
# B1. Pragul de RAM
# ===========================================================================

@pytest.mark.parametrize("avail_mb,fires", [
    (809, True),    # minimul real din 2026-10-20, pe care pragul de 400 MB nu l-a vazut
    (885, True),    # mediana ultimelor ore ale episodului
    (1199, True),
    (1200, False),  # limita: sub prag, nu la prag
    (1642, False),  # minimul de pe 12-19 octombrie: zi normala, nu are voie sa sune
    (2320, False),  # valoarea de acum, dupa ce presiunea a trecut
])
def test_the_809mb_trough_is_seen_and_normal_days_are_not_flagged(host, avail_mb, fires):
    """Pragul era 400 MB; RAM-ul disponibil a coborat la 809 MB si a stat ~1 GB o
    zi intreaga, fara un singur esantion sub prag - watchdog-ul a tacut tocmai in
    evenimentul real. Pragul de 1200 MB il vede, dar nu suna pe minimul zilelor
    normale (1642 MB)."""
    host.set_proc(avail_mb=avail_mb)
    r = host.run()
    assert r.returncode == 0, r.stderr
    if fires:
        assert len(r.msgs) == 1, r.msgs
        assert f"RAM disponibil {avail_mb}MB" in r.msgs[0] and "prag 1200MB" in r.msgs[0]
    else:
        assert r.msgs == [], r.msgs


# ===========================================================================
# B2. Paginarea, nu nivelul de swap
# ===========================================================================

def _series(host: Host, samples: list[tuple[int, int, int]]) -> list[Run]:
    """(timp, pswpin, pswpout) per rulare, un minut intre ele daca testul zice asa."""
    out = []
    for now, pin, pout in samples:
        host.set_proc(pswpin=pin, pswpout=pout)
        out.append(host.run(now=now))
    return out


def test_a_full_swap_that_is_not_moving_is_not_a_problem(host, tmp_path):
    """Swap-ul a ajuns la 99-100% si a ramas asa ore, dupa ce RAM-ul se
    recuperase (vmstat: si=0 so=0). Alerta suna pe aceasta stare statica,
    repetand-o. Un swap plin cu contoare de paginare care nu se misca NU e o
    defectiune si nu are voie sa produca nicio alerta."""
    msgs = []
    for i in range(6):
        host.set_proc(swap_used_mb=2047, pswpin=82_666, pswpout=706_357)
        msgs += host.run(now=1_000_000 + 60 * i).msgs
    assert msgs == [], msgs
    assert host.run(now=1_000_360).state_lines == []
    _assert_channel_works(tmp_path)


def test_the_first_run_has_no_previous_sample_so_no_alert_and_no_rate(host, tmp_path):
    """Dupa instalare nu exista un esantion anterior. Contoarele sunt cumulative
    (zeci de milioane dupa luni de functionare): tratate ca "crestere de la 0",
    prima rulare ar raporta un ritm imens si fals. Trebuie sa taca, sa nu
    pomeneasca niciun ritm, si sa lase un esantion pentru rularea urmatoare."""
    host.set_proc(pswpin=50_000_000, pswpout=80_000_000)
    r = host.run(now=1_000_000)
    assert r.msgs == [], r.msgs
    assert "pagini/s" not in "".join(r.state_lines)
    ring = (host.state / "vmstat.ring").read_text(encoding="utf-8").split("\n")
    assert [l for l in ring if l] == ["1000000 50000000 80000000"]
    _assert_channel_works(tmp_path)


def test_two_runs_a_minute_apart_are_not_enough_history_for_a_verdict(host):
    """Cu un singur interval de 60 s ritmul ar fi o medie pe 60 s: o rafala de o
    secunda ar parea 60 de ori mai mica sau mai mare decat e. Pana la
    PAGING_MIN_SPAN_S (120 s) verificarea e "fara verdict" - nici alerta, nici
    "sanatos"."""
    runs = _series(host, [(1_000_000, 0, 0), (1_000_060, 900_000, 900_000)])
    assert [r.msgs for r in runs] == [[], []]


def test_the_real_event_pages_two_gb_in_a_minute_and_alerts_exactly_once(host):
    """Evenimentul real: ~560 MB scosi pe disc in ~65 s (143 000 de pagini de
    4 KB), apoi liniste. Ritmul pe fereastra variaza la fiecare rulare (1190,
    794, 595, 476 pagini/s) - cu diferenta pe randuri intregi ar fi dat patru
    "noi" si patru "rezolvate". Trebuie: UN mesaj nou cand verdictul apare (a
    treia rulare), tacere cat timp rafala e in fereastra de ~5 minute, UN
    "rezolvat" cand iese din ea."""
    t0 = 1_000_000
    samples = [(t0, 1_000, 5_000), (t0 + 60, 1_000, 148_000)]       # rafala intre ele
    samples += [(t0 + 60 * i, 1_000, 148_000) for i in range(2, 9)]  # apoi nimic
    runs = _series(host, samples)
    kinds = [("new" if any("problema noua" in m for m in r.msgs) else
              "res" if any("rezolvat" in m for m in r.msgs) else "-") for r in runs]
    assert kinds == ["-", "-", "new", "-", "-", "-", "res", "-", "-"], (kinds, [r.msgs for r in runs])
    assert "Paginare swap" in runs[2].msgs[0] and "pagini/s" in runs[2].msgs[0]
    assert "Paginare swap" in runs[6].msgs[0]  # "rezolvat" citeaza alerta, nu un gol


def test_sustained_paging_below_the_threshold_stays_quiet(host):
    """Salturile izolate de 8-15 MB din zilele normale (<= ~13 pagini/s pe 5
    minute) nu au voie sa sune: 50 de pagini/s sustinut, la jumatatea pragului."""
    samples = [(1_000_000 + 60 * i, 3_000 * i, 0) for i in range(12)]  # 50 pagini/s
    assert all(r.msgs == [] for r in _series(host, samples))


def test_paging_just_above_the_threshold_alerts(host):
    """Limita de sus: 120 de pagini/s sustinut, peste pragul de 100, trebuie sa
    sune - un prag pus prea sus ar fi aceeasi tacere pe evenimentul real."""
    samples = [(1_000_000 + 60 * i, 7_200 * i, 0) for i in range(6)]
    runs = _series(host, samples)
    assert any("Paginare swap" in "".join(r.msgs) for r in runs), [r.msgs for r in runs]


def test_a_counter_that_goes_down_is_a_reboot_not_a_negative_rate(host, tmp_path):
    """La repornire contoarele /proc/vmstat revin la 0. Cu istoricul vechi, rata
    ar iesi negativa sau (daca valoarea noua depaseste una veche) o paginare
    imaginara. Istoricul se arunca; nicio alerta, un singur esantion nou."""
    _series(host, [(1_000_000, 900_000, 900_000), (1_000_060, 900_000, 900_000),
                   (1_000_120, 900_000, 900_000)])
    host.set_proc(pswpin=10, pswpout=20)  # dupa repornire
    r = host.run(now=1_000_180)
    assert r.msgs == [], r.msgs
    ring = [l for l in (host.state / "vmstat.ring").read_text(encoding="utf-8").split("\n") if l]
    assert ring == ["1000180 10 20"], ring


def test_a_clock_set_back_discards_the_history(host):
    """Ceasul dat inapoi (NTP) face un esantion sa para din viitor; timpul
    scurs ar iesi negativ sau zero. Istoricul se arunca, nu se imparte la zero."""
    _series(host, [(2_000_000, 0, 0), (2_000_060, 0, 0)])
    r = host.run(now=1_000_000)  # cu ~11 zile in urma
    assert r.returncode == 0 and r.msgs == [], (r.msgs, r.stderr)
    ring = [l for l in (host.state / "vmstat.ring").read_text(encoding="utf-8").split("\n") if l]
    assert len(ring) == 1


def test_history_older_than_the_window_does_not_make_a_verdict(host):
    """Dupa o pauza lunga (timer oprit, gazda suspendata) un esantion de acum o
    ora ar da o medie pe o ora - o rafala s-ar pierde in ea. Esantioanele mai
    vechi decat PAGING_KEEP_S nu mai conteaza: fara verdict, nu "sanatos"."""
    _series(host, [(1_000_000, 0, 0)])
    host.set_proc(pswpin=9_000_000, pswpout=9_000_000)  # ar fi un ritm urias, ignorat
    r = host.run(now=1_003_600)
    assert r.msgs == [], r.msgs


def test_no_verdict_keeps_an_alert_that_was_already_raised(host):
    """Dupa o repornire istoricul lipseste doua minute. O alerta de paginare deja
    data nu are voie sa devina "rezolvata" din lipsa de date: "nu stiu" nu e "e
    bine". Ramane in stare si nu se re-anunta."""
    host.write_state(["cap:paging|📄 Paginare swap ~500 pagini/s (media pe 300s, prag 100/s)"])
    r = host.run()
    assert r.msgs == [], r.msgs
    assert [l.split("|")[0] for l in r.state_lines] == ["cap:paging"]


def test_an_unreadable_vmstat_is_reported_as_unknown_not_as_fine(host, tmp_path):
    """Un /proc/vmstat fara pswpin/pswpout (nucleu schimbat, montare lipsa) nu
    poate fi citit ca "0 pagini/s". Se raporteaza ca NECUNOSCUT."""
    host.set_proc(pswpin=None)
    r = host.run()
    assert len(r.msgs) == 1 and "NECUNOSCUTA" in r.msgs[0] and "paging" in r.msgs[0], r.msgs
    ctl = Host(tmp_path / "ctl")
    assert ctl.run().msgs == []  # martor: aceeasi gazda cu vmstat citibil e tacuta


def test_an_unwritable_history_is_reported_not_silently_blind(host):
    """Daca istoricul nu se poate scrie, fiecare rulare ar fi "prima": watchdog-ul
    ar fi orb la paginare pentru totdeauna, fara nicio alerta. Se raporteaza."""
    (host.state / "vmstat.ring.tmp").mkdir()
    r = host.run()
    assert len(r.msgs) == 1 and "NECUNOSCUTA" in r.msgs[0], (r.msgs, r.stderr)


def test_the_timer_cadence_gives_a_verdict_by_the_third_run():
    """Constantele din script si intervalul din timer sunt legate: istoricul minim
    trebuie atins cu intervalul timerului, iar un esantion de minimul respectiv sa
    nu fi expirat. Un timer mutat la 5 minute ar lasa verificarea de paginare fara
    verdict pentru totdeauna, fara ca vreun test de comportament sa pice."""
    script = SCRIPT.read_text(encoding="utf-8")
    interval = int(re.search(r"^OnUnitActiveSec=(\d+)s\s*$", TIMER.read_text(encoding="utf-8"),
                             re.M).group(1))
    min_span = int(re.search(r"PAGING_MIN_SPAN_S=(\d+)", script).group(1))
    keep = int(re.search(r"PAGING_KEEP_S=(\d+)", script).group(1))
    assert 2 * interval >= min_span, "verdictul n-ar aparea la a treia rulare"
    assert keep >= min_span + interval, "esantionul de minimul necesar ar fi expirat"


# ===========================================================================
# Verificari "nu pot citi" si pragurile ramase
# ===========================================================================

def test_an_unreadable_meminfo_is_unknown_and_keeps_the_prior_state(host, tmp_path):
    """Versiunea veche scria `mem=${mem:-99999}`: un RAM ilizibil devenea 99999 MB,
    adica perfect sanatos. Acum e o problema `unk:mem`, iar o alerta de RAM
    existenta nu devine "rezolvata"."""
    host.write_state(["cap:mem|🧠 RAM disponibil 900MB (prag 1200MB)"])
    host.set_proc(avail_mb=None)
    r = host.run()
    assert len(r.msgs) == 1 and "NECUNOSCUTA" in r.msgs[0], r.msgs
    assert "rezolvat" not in r.msgs[0]
    assert sorted(l.split("|")[0] for l in r.state_lines) == ["cap:mem", "unk:mem"]


def test_an_unreadable_disk_is_unknown_not_zero_percent(host):
    """`disk=${disk:-0}` transforma un `df` esuat in 0% ocupat."""
    r = host.run(env_extra={"FAKE_DF_FAIL": "1"})
    assert len(r.msgs) == 1 and "NECUNOSCUTA" in r.msgs[0] and "disc" in r.msgs[0], r.msgs


def test_an_unreadable_loadavg_is_unknown_not_idle(host):
    """Un load ilizibil era comparat ca 0 in awk: o gazda "fara sarcina"."""
    host.set_proc(load=None)
    r = host.run()
    assert len(r.msgs) == 1 and "NECUNOSCUTA" in r.msgs[0] and "load" in r.msgs[0], r.msgs


def test_high_load_still_alerts_and_normal_load_does_not(host):
    """Verificarea de load (existenta) ramane in functiune: 4 nuclee x 2.0 = 8."""
    host.set_proc(load="9.50")
    r = host.run()
    assert len(r.msgs) == 1 and "Load1 9.50" in r.msgs[0], r.msgs
    host2 = Host(host.root.parent / "h2")
    host2.set_proc(load="7.90")
    assert host2.run().msgs == []


def test_disk_at_the_threshold_alerts_and_below_does_not(host):
    """Verificarea de disc (existenta) ramane in functiune; pragul 88% e inclusiv."""
    assert host.run(disk=87).msgs == []
    r = Host(host.root.parent / "h2").run(disk=88)
    assert len(r.msgs) == 1 and "Disk / la 88%" in r.msgs[0]


# ===========================================================================
# Domenii: din conf, nu din script
# ===========================================================================

def test_health_domains_are_read_from_the_host_conf(host):
    """Domeniile sunt ale unor clienti, iar depozitul e public: scriptul nu are
    niciunul, ele vin din /etc/sentinel/vps-watchdog.conf. Fara conf nu se
    verifica nimic; cu conf se verifica exact cele din lista."""
    host.write_conf('HEALTH_DOMAINS="a.example.org b.example.org"\n')
    r = host.run()
    assert r.domain_urls() == ["https://a.example.org/api/health",
                               "https://b.example.org/api/health"]
    nobody = Host(host.root.parent / "none").run()
    assert nobody.domain_urls() == [], "fara conf, scriptul a verificat domenii din memorie"


def test_a_domain_that_does_not_answer_alerts(host):
    """In versiunea veche `|| echo 000` dubla valoarea in "000000" cand curl
    esua (curl scrie 000 singur si iese cu 7), deci `= 000` nu se potrivea
    NICIODATA: verificarea de domeniu nu putea suna la o cadere reala. Fals-ul de
    aici se comporta ca curl-ul real. Un domeniu care raspunde nu alerteaza."""
    host.write_conf('HEALTH_DOMAINS="up.example.org down.example.org"\n')
    host.set_down(["down.example.org"])
    r = host.run()
    assert len(r.msgs) == 1, r.msgs
    assert "down.example.org nu raspunde" in r.msgs[0] and "up.example.org" not in r.msgs[0]
    assert len(r.domain_urls()) == 2  # martor: amandoua au fost chemate


def test_conf_is_read_as_data_and_never_executed(host, tmp_path):
    """Conf-ul e citit ca root, in fiecare minut. Ca `source`, un `$(...)` din el
    ar rula ca root. Se citesc doar cheile cunoscute, ca text; o valoare cu
    caractere de shell e invalida si e raportata."""
    marker = tmp_path / "executed"
    host.write_conf(f'HEALTH_DOMAINS="x.example.org$(touch {marker.as_posix()})"\n'
                    f'export MEM_AVAIL_MIN_MB=1500 # comentariu\n'
                    f'`touch {marker.as_posix()}`\n')
    r = host.run()
    assert not marker.exists(), "continutul conf-ului a fost EXECUTAT"
    assert any("sys:config:HEALTH_DOMAINS" == l.split("|")[0] for l in r.state_lines), r.state_lines
    assert r.domain_urls() == []
    # `export CHEIE=valoare # comentariu` se citeste: pragul de 1500 e in vigoare
    host.set_proc(avail_mb=1400)
    assert any("RAM disponibil 1400MB" in m for m in host.run().msgs)


def test_an_invalid_threshold_in_the_conf_is_reported_and_the_default_kept(host):
    """O valoare gresita (typo) in conf nu se ignora in tacere: ramane pragul
    implicit, iar operatorul afla de ce nu s-a aplicat ce a scris."""
    host.write_conf("MEM_AVAIL_MIN_MB=lots\n")
    host.set_proc(avail_mb=1100)
    r = host.run()
    texts = "\n".join(r.msgs)
    assert "MEM_AVAIL_MIN_MB din" in texts and "invalid" in texts
    assert "RAM disponibil 1100MB (prag 1200MB)" in texts  # implicitul a ramas


# ===========================================================================
# Telegram: tokenul nu trece prin argv
# ===========================================================================

def test_the_bot_token_never_appears_in_any_argument(host):
    """Tokenul e planul de control al botului. In argv il vede `ps` oricui are un
    cont pe gazda (care gazduieste si site-uri). URL-ul merge pe stdin, spre
    `curl -K -`; chat_id si textul raman argumente."""
    r = host.run(disk=95)
    assert len(r.msgs) == 1
    for argv in r.curl_argvs():
        assert TOKEN not in " ".join(argv), f"tokenul e in argv: {argv}"
    stdin = r.curl_stdins()
    assert len(stdin) == 1 and TOKEN in stdin[0] and "api.telegram.org" in stdin[0]
    assert any(f"chat_id={CHAT}" in a for a in r.curl_argvs()[0])


def test_the_secrets_file_is_parsed_not_sourced(host, tmp_path):
    """secrets.env contine si parola bazei de date si cheia Anthropic. `source`
    l-ar executa; aici se citesc doar cele doua chei Telegram, ca text (si cu
    ghilimele sau CR de la capat de rand, cum le scrie un editor de Windows)."""
    marker = tmp_path / "executed-secrets"
    host.secrets.write_bytes(
        f'SENTINEL_DB_PASSWORD=$(touch {marker.as_posix()})\r\n'
        f'export TELEGRAM_BOT_TOKEN="{TOKEN}"\r\n'
        f"TELEGRAM_CHAT_ID='{CHAT}'\r\n".encode())
    r = host.run(disk=95)
    assert not marker.exists(), "secrets.env a fost EXECUTAT"
    assert len(r.msgs) == 1, (r.msgs, r.stderr)
    assert TOKEN in r.curl_stdins()[0] and f"chat_id={CHAT}" in " ".join(r.curl_argvs()[0])


# ===========================================================================
# Docker: neschimbat, dar fixat
# ===========================================================================

def test_a_dead_docker_daemon_is_reported_and_capacity_checks_still_run(host):
    """Un daemon docker cazut e o problema (`sys:docker`), iar verificarile de
    capacitate ruleaza oricum: au fost dintotdeauna in afara blocului docker,
    iar o mutare gresita le-ar face sa dispara tocmai cand gazda e in necaz."""
    r = host.run(disk=95, env_extra={"FAKE_DOCKER_INFO_RC": "1"})
    assert len(r.msgs) == 1
    assert "Docker daemon nu raspunde" in r.msgs[0] and "Disk / la 95%" in r.msgs[0]


def test_docker_info_is_bounded_by_a_timeout(host):
    """Un daemon agatat face `docker info` sa nu mai termine; scriptul ar sta
    pentru totdeauna, timerul n-ar mai porni o a doua rulare, iar verificarea
    "daemonul nu raspunde" n-ar putea suna niciodata. `docker info` trece prin
    `timeout`. (Limita: nu se dovedeste aici ca timeout-ul real omoara docker.)"""
    r = host.run()
    assert any(l.split()[:3] == ["20", "docker", "info"] for l in r.timeout_calls), r.timeout_calls


def test_an_unhealthy_container_is_restarted_only_on_the_second_consecutive_run(host):
    """Auto-remedierea (neschimbata de aceasta schimbare): un container unhealthy
    cere doua rulari consecutive inainte sa fie repornit."""
    host.set_containers(["api|unless-stopped|running|unhealthy"])
    first = host.run()
    assert first.restarts == [] and any("urmaresc" in m for m in first.msgs), first.msgs
    second = host.run()
    assert second.restarts == ["api"], second.restarts
    assert any("auto-remediere" in m and "(1/3" in m for m in second.msgs), second.msgs


def test_the_excluded_container_is_never_restarted(host):
    """`root-app-1` e exclus din auto-remediere (implicitul livrat, ca pe gazda
    de dinaintea schimbarii): se semnaleaza, nu se reporneste."""
    host.set_containers(["root-app-1|always|exited|"])
    for _ in range(3):
        r = host.run()
        assert r.restarts == [], "un container exclus a fost repornit"
    assert any(l.startswith("ctr:root-app-1:excl|") for l in r.state_lines), r.state_lines


def test_the_exclusion_list_comes_from_the_conf(host):
    """Lista de containere excluse e a gazdei, nu a scriptului: din conf, `api`
    ramane nerepornit, iar implicitul (`root-app-1`) nu mai conteaza. Un conf
    ignorat ar reporni exact containerul pe care operatorul a cerut sa nu fie
    atins."""
    host.set_containers(["api|always|exited|", "root-app-1|always|exited|"])
    host.write_conf('EXCLUDE_AUTOFIX="api"\n')
    r = host.run()
    assert r.restarts == ["root-app-1"], r.restarts
    assert any(l.startswith("ctr:api:excl|") for l in r.state_lines), r.state_lines


def test_auto_fix_can_be_switched_off_from_the_conf(host):
    """AUTO_FIX=0 din conf: containerul cazut se semnaleaza, nu se reporneste."""
    host.set_containers(["api|always|exited|"])
    host.write_conf("AUTO_FIX=0\n")
    r = host.run()
    assert r.restarts == [], r.restarts
    assert any(l.startswith("ctr:api:brk|") for l in r.state_lines), r.state_lines


def test_a_crash_looping_container_is_reported_never_restarted(host):
    """Auto-fix nu reporneste un crash-loop: ar masca cauza."""
    host.set_containers(["worker|always|restarting|"])
    r = host.run()
    assert r.restarts == []
    assert len(r.msgs) == 1 and "crash-loop" in r.msgs[0]


def test_auto_fix_gives_up_after_max_fix_restarts(host):
    """Dupa MAX_FIX=3 reporniri esuate, auto-fix se dezactiveaza si cere
    interventie manuala - nu reporneste la nesfarsit."""
    host.set_containers(["db|always|exited|"])
    restarts = [len(host.run().restarts) for _ in range(5)]
    assert restarts == [1, 1, 1, 0, 0], restarts
    assert (host.state / "fix" / "db.disabled").exists()


def test_the_first_ever_run_announces_the_baseline_and_restarts_nothing(host):
    """Prima rulare absoluta (fara .seeded) scrie baza si trimite UN mesaj de
    activare; nu raporteaza "probleme noi" si nu atinge nimic."""
    (host.state / ".seeded").unlink()
    host.set_containers(["api|unless-stopped|exited|"])
    r = host.run(disk=95)
    assert r.restarts == []
    assert len(r.msgs) == 1 and "watchdog" in r.msgs[0] and "Disk / la 95%" in r.msgs[0]
    assert "problema noua" not in r.msgs[0] and (host.state / ".seeded").exists()


# ===========================================================================
# C. Livrabilul: in depozit, public, fara gazde reale
# ===========================================================================

# Un token cu punct e acceptat daca: ultima eticheta e un sufix de fisier/unitate
# cunoscut, sau e o gazda din lista de mai jos. Orice altceva - adica orice ar
# putea fi un nume de domeniu real - pica testul. Lista se largeste constient,
# cu motiv, nu prin ingustarea tiparului.
ALLOWED_SUFFIXES = {
    "sh": "script", "conf": "fisier de configurare", "env": "secrets.env",
    "ring": "istoricul vmstat", "tmp": "fisier temporar", "state": "problems.state",
    "ustreak": "contor auto-fix", "disabled": "marcaj auto-fix", "attempts": "contor auto-fix",
    "service": "unitate systemd", "timer": "unitate systemd", "target": "tinta systemd",
    "example": "fisier-sablon", "Status": "sablon docker", "Health": "sablon docker",
    "Name": "sablon docker", "py": "fisier de test",
}
# `A-Za-z0-9._` e clasa de caractere din expresia care valideaza listele din conf,
# nu un nume.
ALLOWED_HOSTS = {"api.telegram.org", "A-Za-z0-9._"}
ALLOWED_HOST_SUFFIXES = (".example.org", ".example.com", ".example.net", ".example", ".invalid")
_DOTTED = re.compile(r"\b[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\b")


def _hostlike(text: str) -> list[str]:
    bad = []
    for tok in _DOTTED.findall(text):
        last = tok.rsplit(".", 1)[1]
        if tok in ALLOWED_HOSTS or tok.endswith(ALLOWED_HOST_SUFFIXES):
            continue
        if last in ALLOWED_SUFFIXES or last.isdigit():
            continue
        bad.append(tok)
    return bad


@pytest.mark.parametrize("path", [SCRIPT, SERVICE, TIMER, CONF_EXAMPLE],
                         ids=lambda p: p.name)
def test_no_real_hostname_is_committed_to_the_public_repository(path):
    """Scriptul de pe gazda avea trei domenii reale ale clientilor operatorului
    scrise in el. Depozitul e public: asta ar fi publicat cine sunt clientii.
    Domeniile stau in conf-ul gazdei; in depozit sunt doar nume fictive
    (`*.example.org`). Testul pica la orice token de forma `a.b` care nu e un nume
    de fisier cunoscut sau o gazda fictiva."""
    found = _hostlike(path.read_text(encoding="utf-8"))
    assert found == [], f"{path.name} contine nume care arata a gazda reala: {found}"


def test_the_host_guard_actually_catches_a_domain():
    """Martor pozitiv pentru garda de mai sus: fara el, o garda stricata ar arata
    la fel ca un depozit curat."""
    assert _hostlike('HEALTH_DOMAINS="shop.client-corp.ro"') == ["shop.client-corp.ro"]
    assert _hostlike('x="app.example.org" y=watchdog.sh') == []


def test_the_unit_has_a_start_timeout_in_the_service_section():
    """Un `Type=oneshot` n-are timeout implicit, iar timerul nu porneste o a doua
    instanta cat prima inca ruleaza: o rulare agatata (docker blocat) amuteste
    watchdog-ul pentru totdeauna, fara alerta. `TimeoutStartSec` trebuie sa fie
    in [Service] - in alta sectiune systemd il ignora cu un avertisment in jurnal."""
    section = None
    found = {}
    for line in SERVICE.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        m = re.match(r"^\[(\w+)\]$", s)
        if m:
            section = m.group(1)
        elif s.startswith("TimeoutStartSec="):
            found[section] = s.split("=", 1)[1]
    assert found == {"Service": "300"}, found


def test_shipped_files_are_lf_only_and_the_script_parses():
    """Un CR in shebang ("bad interpreter: bash^M") sau intr-o directiva de unitate
    opreste watchdog-ul fara un mesaj pe canal. Si scriptul trebuie sa treaca
    `bash -n`."""
    for p in (SCRIPT, SERVICE, TIMER, CONF_EXAMPLE):
        assert b"\r" not in p.read_bytes(), f"{p.name} are CR"
    out = subprocess.run([BASH, "-n", str(SCRIPT)], capture_output=True)
    assert out.returncode == 0, out.stderr.decode()
