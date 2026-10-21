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

import datetime as _dt
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
    normale (1642 MB). Alerta vine la a DOUA rulare sub prag (prima e doar o
    proba; vezi testele de histerezis), nu la prima si nu niciodata."""
    host.set_proc(avail_mb=avail_mb)
    first = host.run(now=1_000_000)
    second = host.run(now=1_000_060)   # RAM-ul cere DOUA rulari la rand (sectiunea 5)
    assert first.returncode == 0 and second.returncode == 0, (first.stderr, second.stderr)
    assert first.msgs == [], first.msgs
    if fires:
        assert len(second.msgs) == 1, second.msgs
        assert f"RAM disponibil {avail_mb}MB" in second.msgs[0] and "prag 1200MB" in second.msgs[0]
    else:
        assert second.msgs == [], second.msgs


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
    host.run(now=1_000_000)
    assert any("RAM disponibil 1400MB" in m for m in host.run(now=1_000_060).msgs)


def test_an_invalid_threshold_in_the_conf_is_reported_and_the_default_kept(host):
    """O valoare gresita (typo) in conf nu se ignora in tacere: ramane pragul
    implicit, iar operatorul afla de ce nu s-a aplicat ce a scris."""
    host.write_conf("MEM_AVAIL_MIN_MB=lots\n")
    host.set_proc(avail_mb=1100)
    msgs = host.run(now=1_000_000).msgs + host.run(now=1_000_060).msgs  # RAM: 2 rulari
    texts = "\n".join(msgs)
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
# H. Histerezis pe RAM (sectiunea 5 din antetul scriptului)
# ===========================================================================
#
# Datele de mai jos sunt MASURATE: randuri din `capacity_samples` de pe gazda de
# productie (UTC, 20-21 oct 2026), nu valori inventate. Singurul lucru derivat e
# contorul de paginare din replay-ul rafalei (vezi `_replay`): capacity_samples n-are
# pswpin/pswpout, deci se deduc din variatia lui swap_used_mb la 4 KB/pagina.

# (ora, MemAvailable MB, swap_used MB) - rafala de la 05:41, pe 21 oct, ~31 s intre ele.
BURST = [
    ("05:38:21", 1595, 1484), ("05:38:55", 1592, 1484), ("05:39:29", 1544, 1484),
    ("05:40:05", 1582, 1484), ("05:40:32", 1414, 1484), ("05:41:07", 899, 1746),
    ("05:41:36", 862, 2047), ("05:42:10", 1724, 2047), ("05:42:42", 1304, 2047),
    ("05:43:16", 810, 2047), ("05:43:49", 2164, 2030), ("05:44:19", 2147, 2030),
    ("05:44:51", 2144, 2030), ("05:45:21", 2182, 2030), ("05:45:55", 2171, 2030),
    ("05:46:29", 2202, 2030), ("05:47:02", 2188, 2030), ("05:47:34", 2198, 2030),
    ("05:48:06", 2140, 2030), ("05:48:39", 2164, 2030), ("05:49:11", 2145, 2030),
    ("05:49:45", 2168, 2030),
]
# Episodul real: intrarea (20 oct 10:56-11:03), cateva puncte din interior (la ~53 min
# unul de altul) si iesirea (21 oct 00:34-00:41). Sub 1200 MB 1543 de esantioane la rand.
ENTRY = [(20, "10:56:19", 1254), (20, "10:57:21", 1253), (20, "10:58:30", 1208),
         (20, "10:59:31", 1152), (20, "11:00:32", 1161), (20, "11:01:34", 1170),
         (20, "11:02:39", 1186), (20, "11:03:40", 1169)]
INTERIOR = [(20, h, v) for h, v in [
    ("12:12:52", 985), ("13:05:42", 937), ("13:58:32", 958), ("14:51:42", 1023),
    ("15:44:44", 994), ("16:38:28", 929), ("17:31:55", 948), ("18:25:32", 894),
    ("19:18:50", 882), ("20:11:33", 992), ("21:04:32", 919), ("21:57:53", 915),
    ("22:50:20", 913), ("23:43:12", 902)]]
EXIT = [(21, "00:34:16", 925), (21, "00:35:21", 961), (21, "00:36:26", 952),
        (21, "00:37:31", 956), (21, "00:38:31", 1473), (21, "00:39:32", 1528),
        (21, "00:40:41", 1577), (21, "00:41:41", 1583)]


def _utc(day: int, hms: str) -> int:
    h, m, s = (int(x) for x in hms.split(":"))
    return int(_dt.datetime(2026, 10, day, h, m, s, tzinfo=_dt.timezone.utc).timestamp())


def _replay(host: Host, rows: list[tuple[int, str, int]], *, swap: bool = False) -> list[Run]:
    """O rulare per rand `(zi, ora, MB disponibil)`, la ora lui reala. Cu `swap`,
    randul e `(zi, ora, MB, swap_used)` si contoarele de paginare cresc cu variatia
    swap-ului (derivat, nu masurat); un al cincilea camp, `load1`, se pune in loadavg."""
    pin, pout, last = 50_000_000, 80_000_000, None
    runs = []
    for row in rows:
        day, hms, avail = row[:3]
        if swap:
            used = row[3]
            d = 0 if last is None else used - last
            pout += max(d, 0) * 256
            pin += max(-d, 0) * 256
            last = used
            load = str(row[4]) if len(row) > 4 else "0.10"
            host.set_proc(avail_mb=avail, swap_used_mb=used, pswpin=pin, pswpout=pout, load=load)
        else:
            host.set_proc(avail_mb=avail)
        runs.append(host.run(now=_utc(day, hms)))
    return runs


def _events(runs: list[Run]) -> list[tuple[int, str, str]]:
    """(indicele rularii, 'new'|'res', 'mem'|'paging') pentru fiecare mesaj trimis."""
    out = []
    for i, r in enumerate(runs):
        for m in r.msgs:
            kind = "new" if "problema noua" in m else "res" if "rezolvat" in m else "other"
            for cond, needle in (("mem", "RAM disponibil"), ("paging", "Paginare swap")):
                if needle in m:
                    out.append((i, kind, cond))
    return out


@pytest.mark.parametrize("phase", [0, 1])
def test_the_real_21_oct_burst_gives_at_most_one_pair_per_condition(host, phase):
    """Operatorul a fost trezit de sase mesaje in sapte minute pentru O rafala: RAM-ul
    disponibil a facut 899 -> 1724 -> 810 -> 2164 MB in 2,5 minute si fiecare
    traversare a pragului de 1200 a trimis cate un "nou" sau un "rezolvat". Aici se
    reda rafala reala (esantioane masurate, la cadenta de 60 s a timerului, in
    ambele faze posibile) prin scriptul real: pe fiecare conditie cel mult UN nou si
    cel mult UN rezolvat. Faza 1 e exact secventa pe care a reprodus-o verificatorul."""
    rows = [r for r in BURST[phase::2]]
    runs = _replay(host, [(21, h, a, s) for h, a, s in rows], swap=True)
    ev = _events(runs)
    for cond in ("mem", "paging"):
        assert sum(1 for e in ev if e[1] == "new" and e[2] == cond) <= 1, ev
        assert sum(1 for e in ev if e[1] == "res" and e[2] == cond) <= 1, ev
    assert all(e[1] != "other" for e in ev), ev


def test_ram_is_not_declared_resolved_while_it_is_still_swinging(host):
    """La cadenta nativa a esantioanelor (31 s) rafala are 1724 MB la 05:42:10, 1304
    la 05:42:42 si din nou 810 la 05:43:16. Un "rezolvat" trimis intre ele spune
    operatorului "e bine" cu un minut inainte sa nu mai fie: nou/rezolvat/nou... Se
    rezolva abia dupa ultima cadere. 1304 MB sta in banda moarta (1200-1320): fara
    marja ar conta ca a doua proba "buna" si ar rezolva prea devreme."""
    runs = _replay(host, [(21, h, a) for h, a, _ in BURST])
    ev = [e for e in _events(runs) if e[2] == "mem"]
    last_low = max(i for i, (_, a, _) in enumerate(BURST) if a < 1200)
    assert [e[1] for e in ev] == ["new", "res"], ev
    assert ev[1][0] > last_low, f"rezolvat la rularea {ev[1][0]}, dar ultima cadere e la {last_low}"


def test_a_real_sustained_shortage_is_announced_once_and_resolved_once(host):
    """Histerezisul nu are voie sa devina tacere. Episodul real (13,6 h sub 1200 MB) se
    reda din esantioane masurate: intrarea, cateva puncte din interior, iesirea. Trebuie:
    UN anunt, chiar la a doua proba consecutiva sub prag (nici la prima, nici niciodata);
    nimic cat dureaza; UN rezolvat la a doua proba peste banda moarta, citand ultima
    citire proasta. Daca numaratoarea de confirmare nu ajunge niciodata la 2 (contorul
    pierdut intre rulari), evenimentul real ar trece nevazut."""
    rows = ENTRY + INTERIOR + EXIT
    runs = _replay(host, rows)
    ev = _events(runs)
    first_low = next(i for i, r in enumerate(rows) if r[2] < 1200)
    last_low = max(i for i, r in enumerate(rows) if r[2] < 1200)
    assert [(e[1], e[2]) for e in ev] == [("new", "mem"), ("res", "mem")], ev
    assert ev[0][0] == first_low + 1, f"anuntat la {ev[0][0]}, prima proba sub prag la {first_low}"
    assert ev[1][0] == last_low + 2, f"rezolvat la {ev[1][0]}, ultima proba sub prag la {last_low}"
    assert "RAM disponibil 1161MB" in "".join(runs[ev[0][0]].msgs)
    assert "RAM disponibil 956MB" in "".join(runs[ev[1][0]].msgs)  # ultima citire proasta


# Minutul in care nucleul a chemat oom-killer pe gazda de productie: `containerd invoked
# oom-killer` la 13:42:45 EEST = 10:42:45 UTC, "Killed process (next-server) anon-rss
# 2476940kB". Singurul OOM kill de la 26 sept; `oom_kill` din /proc/vmstat = 1 de la
# pornirea din 18 oct. Esantioane MASURATE din `capacity_samples`: (ora UTC, MemAvailable MB,
# swap_used MB, load1). Orele sunt rotunjite IN SUS la secunda intreaga: o proba la secunda
# S vede un esantion doar daca a fost scris la S sau mai devreme.
OOM_MINUTE = [
    ("10:38:09", 1763, 2047, 2.98), ("10:38:40", 1760, 2047, 4.12), ("10:39:10", 1862, 2047, 4.15),
    ("10:39:41", 1354, 2047, 3.95), ("10:40:19", 1019, 2047, 4.18), ("10:40:45", 497, 2047, 5.30),
    ("10:41:17", 1505, 2047, 5.51), ("10:41:44", 939, 2047, 5.41), ("10:42:23", 85, 2047, 5.74),
    ("10:42:54", 2219, 805, 20.51), ("10:43:21", 3473, 805, 14.35), ("10:43:51", 2818, 805, 10.68),
    ("10:44:21", 3777, 805, 8.77), ("10:44:53", 3498, 805, 6.30), ("10:45:24", 3084, 805, 5.09),
    ("10:45:57", 4536, 805, 4.39), ("10:46:30", 4493, 804, 2.75),
]


def _oom_probes(phase: int) -> list[tuple[int, str, int, int, float]]:
    """Ce vede un timer de 60 s cu proba la secunda `phase` din minut, de la 10:39 la
    10:45: la fiecare proba, ULTIMUL esantion masurat pana atunci (valoarea se tine).
    Ipoteza e a modelului, nu o masuratoare: intre doua esantioane de ~31 s nu stim ce a
    facut RAM-ul; o cadere mai scurta decat ele poate sa nu apara deloc."""
    probes = []
    for minute in range(39, 46):
        hms = f"10:{minute:02d}:{phase:02d}"
        held = [r for r in OOM_MINUTE if r[0] <= hms][-1]
        probes.append((21, hms, held[1], held[2], held[3]))
    return probes


def _ram_events(runs: list[Run]) -> list[tuple[int, str]]:
    return [(i, kind) for i, kind, cond in _events(runs) if cond == "mem"]


def _announced_mb(run: Run) -> int:
    text = "".join(m for m in run.msgs if "RAM disponibil" in m)
    return int(re.search(r"RAM disponibil (\d+)MB", text).group(1))


XFAIL_PHASE_20 = pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="Golul MASURAT al scaparii de adancime: cu proba la secunda 17-22 din minut nicio "
           "proba nu cade pe cele doua esantioane adanci (497 si 85 MB tin ~30 s fiecare), "
           "iar restul seriei arata ca rafala de la 05:41. RAM-ul tace; load-ul vorbeste. "
           "Daca acest test incepe sa treaca, golul s-a inchis: scoate marcajul si corecteaza "
           "sectiunea 5 din antet.")


@pytest.mark.parametrize("phase", [7, 30, 40, pytest.param(20, marks=XFAIL_PHASE_20)])
def test_the_oom_minute_is_announced_with_its_depth_before_the_kernel_kills(host, phase):
    """21 oct, 13:42:45 EEST: nucleul a omorat next-server, iar RAM-ul disponibil
    facuse 1019 -> 497 -> 1505 -> 939 -> 85 MB in doua minute. Cu confirmare de doua rulari
    si nimic altceva, alerta de RAM era un cap-coada: la unele faze ale timerului (20, 30,
    40) operatorul nu auzea NICIUNA din cele doua caderi, la altele (0, 7) auzea doar
    "939 MB", dupa ce trecuse cel mai rau moment. Aici se reda seria MASURATA (inclusiv swap
    si load) prin scriptul real, la faze la care varianta cu confirmare simpla e muta sau
    tarzie, si se cere: un singur "nou" si un singur "rezolvat" pe RAM, anuntul care CITEAZA
    adancimea (sub jumatate din prag, nu 939) si vine inainte de minutul 10:43. Faza 20 e
    golul cunoscut si inca nerezolvat - vezi marcajul xfail."""
    runs = _replay(host, _oom_probes(phase), swap=True)
    ev = _ram_events(runs)
    assert [k for _, k in ev] == ["new", "res"], (phase, ev, [r.msgs for r in runs])
    announced = _announced_mb(runs[ev[0][0]])
    assert announced < 600, f"anuntul citeaza {announced} MB, nu adancimea evenimentului"
    assert 39 + ev[0][0] <= 42, f"anuntat la proba {ev[0][0]}, dupa minutul 10:42"


@pytest.mark.parametrize("phase", [7, 20, 30, 40])
def test_the_oom_minute_never_leaves_the_operator_with_no_message_at_all(host, phase):
    """Chiar si la faza 20, unde alerta de RAM tace, operatorul nu ramane surd: load-ul
    (care nu e intarziat) trece de 2 x 4 nuclee la 10:42:54 si se vede la proba urmatoare.
    Acesta e martorul ca golul fazei 20 e unul de RAM, nu de canal. Seria include load-ul
    MASURAT; fara el (cum a reprodus-o prima oara verificatorul, cu load fix 0,10)
    concluzia 'zero mesaje' ar fi fost adevarata doar pentru ca nimeni nu a pus load-ul."""
    runs = _replay(host, _oom_probes(phase), swap=True)
    news = [m for r in runs for m in r.msgs if "problema noua" in m]
    assert news, f"faza {phase}: niciun mesaj in tot minutul evenimentului"
    assert any("RAM disponibil" in m or "Load1" in m for m in news), news


@pytest.mark.parametrize("avail,fires", [
    (1115, False),   # 21 oct 04:16, un esantion
    (899, False),    # 05:41:07, primul din rafala
    (862, False),    # 05:41:36
    (844, False),    # 09:51:38
    (826, False),    # 09:53:47
    (810, False),    # 05:43:16 - cel mai adanc zgomot scurt
    (809, False),    # minimul episodului lung (20 oct 17:22:53), o citire intr-o suta de ore
    (600, False),    # chiar la limita: NU e sub jumatatea pragului
    (599, True),
    (497, True),     # 21 oct 10:40:45
    (85, True),      # 21 oct 10:42:23
])
def test_only_a_reading_under_half_the_floor_is_announced_without_confirmation(host, avail, fires):
    """Scaparea de adancime trebuie sa separe ce a vazut gazda: zgomotul (cel mai adanc
    810 MB) ramane tacut la prima citire, ca sa nu revina mesajele pe fiecare cadere de o
    jumatate de minut; cele doua caderi ale OOM-ului (497 si 85 MB) se anunta imediat.
    Intre 497 si 809 nu exista niciun esantion in 12,5 zile, deci orice limita de acolo
    desparte datele; jumatatea pragului (600) e la 5% de media geometrica a golului. Daca
    limita urca peste zgomot, revin mesajele; daca coboara sub 497, OOM-ul trece iar nevazut."""
    host.set_proc(avail_mb=avail)
    r = host.run(now=1_000_000)
    assert r.returncode == 0, r.stderr
    counters = (host.state / "hysteresis.state").read_text(encoding="utf-8").strip()
    if fires:
        assert len(r.msgs) == 1 and "problema noua" in r.msgs[0] and f"RAM disponibil {avail}MB" in r.msgs[0], r.msgs
        assert counters == ""
    else:
        assert r.msgs == [], f"{avail} MB anunta la prima citire: {r.msgs}"
        assert counters == "cap:mem|pend|1|1000000"


def test_the_depth_limit_follows_the_floor_set_in_the_conf(host):
    """Limita de adancime e jumatate din prag, nu un 600 fix: pe o gazda cu alta memorie
    (prag 2000 MB in conf) o citire de 999 MB e adanca si 1000 nu e. Un 600 scris in cod ar
    lasa acea gazda fara scapare sau cu una la jumatate de prag gresita."""
    host.write_conf("MEM_AVAIL_MIN_MB=2000\n")
    host.set_proc(avail_mb=1000)
    assert host.run(now=1_000_000).msgs == []
    other = Host(host.root.parent / "deeper")
    other.write_conf("MEM_AVAIL_MIN_MB=2000\n")
    other.set_proc(avail_mb=999)
    r = other.run(now=1_000_000)
    assert len(r.msgs) == 1 and "RAM disponibil 999MB" in r.msgs[0], r.msgs


def test_a_floor_written_with_a_leading_zero_keeps_the_depth_limit_decimal(host):
    """`MEM_AVAIL_MIN_MB=01200` trece validarea, dar in `$(( ))` e octal (= 640): limita de
    adancime ar cobori la 320 MB si 497 MB, citirea care a prefatat un OOM, ar astepta
    confirmarea. `10#` o tine zecimala (jumatate din 1200 = 600)."""
    host.write_conf("MEM_AVAIL_MIN_MB=01200\n")
    host.set_proc(avail_mb=500)
    r = host.run(now=1_000_000)
    assert len(r.msgs) == 1 and "RAM disponibil 500MB" in r.msgs[0], r.msgs


def test_a_deeper_reading_while_the_alert_is_open_does_not_announce_it_again(host):
    """Scaparea de adancime sare peste CONFIRMARE, nu peste identitate: o problema deja
    anuntata care se adanceste (900 -> 85 MB) ramane aceeasi problema si nu produce un al
    doilea "nou" la fiecare rulare. Starea ia citirea noua, mesajul nu se repeta."""
    host.write_state(["cap:mem|🧠 RAM disponibil 900MB (prag 1200MB)"])
    host.set_proc(avail_mb=85)
    for i in range(3):
        r = host.run(now=1_000_000 + 60 * i)
        assert r.msgs == [], f"repetat la rularea {i}: {r.msgs}"
    assert r.state_lines == ["cap:mem|🧠 RAM disponibil 85MB (prag 1200MB)"]


def test_the_first_low_run_leaves_a_counter_for_the_next_run(host):
    """Numaratoarea traieste intre doua procese bash: un contor care nu ajunge pe disc
    face fiecare rulare "prima proba" si alerta de RAM nu mai sosete NICIODATA. Dupa
    prima rulare sub prag fisierul de contoare trebuie sa spuna `pend|1`; dupa anunt,
    contorul dispare."""
    host.set_proc(avail_mb=900)
    host.run(now=1_000_000)
    counters = (host.state / "hysteresis.state").read_text(encoding="utf-8").splitlines()
    assert counters == ["cap:mem|pend|1|1000000"], counters
    r = host.run(now=1_000_060)
    assert len(r.msgs) == 1 and "problema noua" in r.msgs[0]
    assert (host.state / "hysteresis.state").read_text(encoding="utf-8").strip() == ""


def test_two_low_runs_separated_by_a_long_pause_are_not_consecutive(host):
    """Doua probe sub prag la o ora distanta nu sunt "doua rulari la rand": timerul a
    fost oprit sau gazda suspendata. Un contor mai vechi de HYST_STALE_S nu conteaza -
    altfel o proba veche de ore ar confirma o alta, fara nicio dovada ca RAM-ul a
    ramas jos intre ele. Martor: un contor PROASPAT (acum 60 s) anunta de la prima
    rulare."""
    host.set_proc(avail_mb=900)
    (host.state / "hysteresis.state").write_text("cap:mem|pend|1|999940\n", encoding="utf-8")
    assert len(host.run(now=1_000_000).msgs) == 1, "martorul: contorul proaspat trebuia sa confirme"
    other = Host(host.root.parent / "stale")
    other.set_proc(avail_mb=900)
    assert other.run(now=1_000_000).msgs == []
    assert other.run(now=1_003_600).msgs == []          # la o ora: contorul vechi expirat
    assert len(other.run(now=1_003_660).msgs) == 1       # doua rulari la rand de la acel moment


def test_an_alternating_reading_never_confirms_and_a_dip_is_not_a_shortage(host):
    """899 -> 1724 -> 810 -> 2164 (secventa verificatorului) la 60 s: nici o pereche de
    probe consecutive sub prag, deci niciun mesaj de RAM. O cadere de jumatate de
    minut nu e o criza; criza reala (test separat) tine ore."""
    for i, mb in enumerate([899, 1724, 810, 2164, 2147]):
        host.set_proc(avail_mb=mb)
        assert host.run(now=1_000_000 + 60 * i).msgs == [], f"mesaj la proba {i} ({mb} MB)"


def test_a_reading_in_the_dead_band_does_not_resolve_an_open_ram_alert(host):
    """Intre 1200 si 1320 MB o alerta deja data ramane data: 1304 MB (masurat, 21 oct
    05:42:42) e peste prag, dar 16 MB mai jos de 1320 si la o rafala de 810. Fara
    marja, doua citiri de 1304 ar spune "rezolvat". Martor: 1500 MB rezolva dupa doua
    rulari, iar 1304 MB pe o gazda FARA alerta deschisa nu inseamna nimic."""
    host.write_state(["cap:mem|🧠 RAM disponibil 810MB (prag 1200MB)"])
    host.set_proc(avail_mb=1304)
    for i in range(3):
        r = host.run(now=1_000_000 + 60 * i)
        assert r.msgs == [], f"rezolvat din banda moarta la rularea {i}: {r.msgs}"
    assert [l.split("|")[0] for l in r.state_lines] == ["cap:mem"]
    host.set_proc(avail_mb=1500)
    assert host.run(now=1_000_180).msgs == []
    done = host.run(now=1_000_240)
    assert len(done.msgs) == 1 and "rezolvat" in done.msgs[0] and "810MB" in done.msgs[0], done.msgs
    quiet = Host(host.root.parent / "quiet")
    quiet.set_proc(avail_mb=1304)
    assert all(quiet.run(now=1_000_000 + 60 * i).msgs == [] for i in range(3))
    assert quiet.run(now=1_000_200).state_lines == []


def test_an_open_ram_alert_needs_two_consecutive_clear_runs_to_resolve(host):
    """O citire buna izolata intre doua rele nu inchide alerta: bine, rau, bine nu e
    "rezolvat" (altfel fiecare oscilatie ar produce un rezolvat si apoi un nou)."""
    host.write_state(["cap:mem|🧠 RAM disponibil 810MB (prag 1200MB)"])
    msgs = []
    for i, mb in enumerate([2000, 900, 2000, 2000]):
        host.set_proc(avail_mb=mb)
        msgs.append(host.run(now=1_000_000 + 60 * i).msgs)
    assert msgs[:3] == [[], [], []], msgs
    assert len(msgs[3]) == 1 and "rezolvat" in msgs[3][0], msgs


def test_a_threshold_written_with_a_leading_zero_keeps_the_dead_band_right(host):
    """`MEM_AVAIL_MIN_MB=01200` in conf trece validarea (cifre), dar in `$(( ))` bash
    il citeste OCTAL (= 640): banda moarta ar cobori la 704 MB si o alerta deschisa s-ar
    rezolva la 1250 MB, in banda. `10#` o tine zecimala."""
    host.write_conf("MEM_AVAIL_MIN_MB=01200\n")
    host.write_state(["cap:mem|🧠 RAM disponibil 810MB (prag 01200MB)"])
    host.set_proc(avail_mb=1250)
    for i in range(3):
        r = host.run(now=1_000_000 + 60 * i)
        assert r.returncode == 0 and r.msgs == [], (r.msgs, r.stderr)
    assert [l.split("|")[0] for l in r.state_lines] == ["cap:mem"]


def test_the_real_production_state_file_is_read_silently_by_the_new_script(host, tmp_path):
    """Starea reala de pe productie, acum, este exact `cap:swap|🔺 Swap la 98%`: o cheie
    retrasa. Prima rulare a scriptului cu histerezis nu are voie sa scoata niciun mesaj
    - nici "rezolvat: Swap la 98%" (swap-ul nu s-a rezolvat, doar nu mai e verificat),
    nici ceva din lipsa fisierului de contoare. Se ruleaza de CINCI ori: rezolvarea cere
    acum numaratoare, deci o straja scoasa ar putea tacea la prima rulare si vorbi la a
    doua; un test de o singura rulare n-ar vedea-o."""
    (host.state / "problems.state").write_bytes("cap:swap|🔺 Swap la 98%\n".encode("utf-8"))
    host.set_proc(swap_used_mb=2005)
    assert not (host.state / "hysteresis.state").exists()
    for i in range(5):
        r = host.run(now=1_000_000 + 60 * i)
        assert r.returncode == 0, r.stderr
        assert r.msgs == [], f"mesaj la rularea {i}: {r.msgs!r}"
    assert r.state_lines == []
    _assert_channel_works(tmp_path)


def test_an_open_ram_alert_from_the_previous_version_neither_repeats_nor_vanishes(host):
    """Daca versiunea veche lasase `cap:mem` deschis (format `cheie|text`, fara contoare)
    si RAM-ul e inca jos, versiunea noua nu are voie sa-l anunte iar ca "nou" si nici sa-l
    piarda: ramane in stare, cu citirea noua, fara mesaje."""
    host.write_state(["cap:mem|🧠 RAM disponibil 900MB (prag 1200MB)"])
    host.set_proc(avail_mb=870)
    for i in range(3):
        r = host.run(now=1_000_000 + 60 * i)
        assert r.msgs == [], r.msgs
    assert r.state_lines == ["cap:mem|🧠 RAM disponibil 870MB (prag 1200MB)"]


def test_problems_state_keeps_the_old_key_pipe_text_format(host):
    """Fisierul de stare ramane `cheie|text`: copia veche de pe gazda (rollback) si
    orice alt cititor il citesc ca inainte. Contoarele sunt in alt fisier; o coloana in
    plus in problems.state ar rupe citirea lor si ar face prima rulare dupa un
    rollback sa vada alerta drept alta."""
    host.set_proc(avail_mb=900, load="9.50")
    host.run(now=1_000_000)
    r = host.run(now=1_000_060)
    assert sorted(l.split("|")[0] for l in r.state_lines) == ["cap:load", "cap:mem"]
    for line in r.state_lines:
        assert line.count("|") == 1, f"coloana in plus in starea anuntata: {line!r}"
    counters = (host.state / "hysteresis.state").read_text(encoding="utf-8")
    assert counters.strip() == "", counters   # nimic in asteptare dupa anunt


@pytest.mark.parametrize("how", ["tmp_is_a_directory", "clock_unreadable", "counters_path_is_a_directory"])
def test_counters_that_cannot_be_kept_never_silence_the_ram_alert(host, how):
    """Daca contoarele nu se pot scrie (sau ceasul nu se poate citi), "astept inca o
    rulare" s-ar repeta la nesfarsit si alerta de RAM n-ar mai suna NICIODATA, fara nicio
    veste. Atunci se renunta la confirmare - RAM-ul jos se anunta de la prima rulare - si
    se spune ca (`unk:hysteresis`). Cazul invers, tacerea, e cel periculos."""
    host.set_proc(avail_mb=900)
    env = {}
    if how == "tmp_is_a_directory":
        (host.state / "hysteresis.state.tmp").mkdir()
    elif how == "clock_unreadable":
        env = {"FAKE_NOW": "soon"}
    else:
        (host.state / "hysteresis.state").mkdir()
    r = host.run(env_extra=env)
    text = "\n".join(r.msgs)
    assert "RAM disponibil 900MB" in text, (r.msgs, r.stderr)
    assert "contoarele de confirmare" in text, r.msgs
    assert any(l.startswith("unk:hysteresis|") for l in r.state_lines), r.state_lines


@pytest.mark.parametrize("line", [
    "garbage",
    "cap:mem|pend|1",                  # prea putine campuri
    "cap:mem|pend|1|{old}|extra",      # prea multe
    "cap:mem|pend|1junk|{old}",        # numar cu coada
    "cap:mem|pend|1|{old}junk",        # ts cu coada
    "cap:mem|pend|1|{future}",         # din viitor
])
def test_a_damaged_counters_file_can_delay_a_message_but_never_send_one(host, line):
    """Un fisier de contoare stricat poate cel mult sa INTARZIE un anunt cu o rulare;
    nu are voie sa-l produca. Fiecare linie de aici ar fi citita drept "o proba deja
    vazuta" de un parser prea increzator si ar anunta RAM-ul de la prima rulare, pe o
    singura citire. Martorul pozitiv (acelasi continut, valid) e in testul de expirare."""
    (host.state / "hysteresis.state").write_text(
        line.format(old=1_000_000 - 60, future=1_000_000 + 500) + "\n", encoding="utf-8")
    host.set_proc(avail_mb=900)
    first = host.run(now=1_000_000)
    assert first.returncode == 0, first.stderr
    assert first.msgs == [], f"mesaj din contor stricat: {first.msgs}"
    assert not any(l.startswith("unk:") for l in first.state_lines), first.state_lines
    assert len(host.run(now=1_000_060).msgs) == 1


def test_a_failing_diff_engine_changes_nothing_and_says_so(host):
    """Daca motorul de diferente iese cu eroare, iesirea lui goala NU e "nicio problema":
    ar sterge starea si ar trimite "rezolvat" pentru tot ce era deschis. Starea ramane
    octet cu octet, nu se trimite nimic, iar scriptul iese nenul (se vede in
    `systemctl --failed`). Martor: acelasi continut, cu motorul sanatos, schimba starea."""
    state_line = "cap:mem|🧠 RAM disponibil 900MB (prag 1200MB)"
    host.write_state([state_line])
    host.set_proc(avail_mb=870)
    real_awk = subprocess.run([BASH, "-c", "command -v awk"], capture_output=True,
                              text=True).stdout.strip()
    assert real_awk, "nu gasesc awk"
    broken = Host(host.root.parent / "broken")
    broken.write_state([state_line])
    broken.set_proc(avail_mb=870)
    _stub(broken.bin, "awk",
          'case "$*" in *pol=cap:mem*) echo "awk: boom" >&2; exit 2 ;; esac\n'
          f'exec "{real_awk}" "$@"\n')
    before = (broken.state / "problems.state").read_bytes()
    r = broken.run(now=1_000_000)
    assert r.returncode != 0 and "motorul de diferente a esuat" in r.stderr, (r.returncode, r.stderr)
    assert r.msgs == []
    assert (broken.state / "problems.state").read_bytes() == before
    healthy = host.run(now=1_000_000)
    assert healthy.returncode == 0 and healthy.state_lines == ["cap:mem|🧠 RAM disponibil 870MB (prag 1200MB)"]


UNDELAYED = ["disk", "load", "docker", "crash-loop", "domain"]


def _condition(host: Host, case: str, bad: bool) -> dict:
    """Aduce `case` in starea rea/buna; intoarce argumentele pentru `host.run`."""
    kw: dict = {}
    if case == "disk":
        kw["disk"] = 95 if bad else 40
    elif case == "load":
        host.set_proc(load="9.50" if bad else "0.10")
    elif case == "docker":
        kw["env_extra"] = {"FAKE_DOCKER_INFO_RC": "1"} if bad else {}
    elif case == "crash-loop":
        host.set_containers(["worker|always|restarting|"] if bad else [])
    elif case == "domain":
        host.write_conf('HEALTH_DOMAINS="down.example.org"\n')
        host.set_down(["down.example.org"] if bad else [])
    return kw


NEEDLES = {"disk": "Disk / la 95%", "load": "Load1 9.50", "docker": "Docker daemon nu raspunde",
           "crash-loop": "crash-loop", "domain": "down.example.org nu raspunde"}


@pytest.mark.parametrize("case", UNDELAYED)
def test_only_the_ram_check_is_delayed_the_others_speak_at_once(host, case):
    """Decizia per verificare: un minut de intarziere e ieftin pentru un prag de RAM
    (care oscileaza), dar NU pentru un daemon docker cazut, un container in crash-loop
    sau site-ul unui client care nu raspunde - acelea nu sunt masuratori zgomotoase si
    operatorul le vrea repede. Fiecare se anunta la PRIMA rulare si se rezolva la prima
    rulare buna. Un prag de confirmare pus din greseala pe toate ar intarzia tot."""
    r1 = host.run(now=1_000_000, **_condition(host, case, bad=True))
    assert len(r1.msgs) == 1 and "problema noua" in r1.msgs[0] and NEEDLES[case] in r1.msgs[0], r1.msgs
    r2 = host.run(now=1_000_060, **_condition(host, case, bad=False))
    assert len(r2.msgs) == 1 and "rezolvat" in r2.msgs[0] and NEEDLES[case] in r2.msgs[0], r2.msgs


def test_the_hysteresis_window_covers_the_slowest_run_the_unit_allows():
    """Contoarele expira dupa HYST_STALE_S. Unitatea permite unei rulari sa dureze pana la
    TimeoutStartSec (300 s) si timerul porneste urmatoarea la OnUnitActiveSec (60 s) dupa
    aceea: doua rulari terminate pot fi la 360 s una de alta. Daca fereastra e mai scurta
    decat asta, "doua rulari la rand" nu se intampla niciodata si alerta de RAM tace fara
    nicio veste (`unk:hysteresis` acopera contoare ce nu se pot SCRIE, nu contoare EXPIRATE).
    Limita de sus tine "consecutiv" sa nu treaca peste o pauza adevarata: cel mult doua
    cadente peste cel mai lent caz. Cine mareste TimeoutStartSec trebuie sa vina aici."""
    script = SCRIPT.read_text(encoding="utf-8")
    interval = int(re.search(r"^OnUnitActiveSec=(\d+)s\s*$", TIMER.read_text(encoding="utf-8"),
                             re.M).group(1))
    timeout = int(re.search(r"^TimeoutStartSec=(\d+)\s*$", SERVICE.read_text(encoding="utf-8"),
                            re.M).group(1))
    stale = int(re.search(r"HYST_STALE_S=(\d+)", script).group(1))
    assert timeout + interval <= stale <= timeout + 2 * interval, (timeout, interval, stale)


@pytest.mark.parametrize("gap", [200, 360])
def test_a_slow_run_does_not_turn_the_confirmation_into_silence(host, gap):
    """RAM la 900 MB, cu rulari la `gap` secunde una de alta (o rulare lenta - docker
    agatat, curl fara raspuns - o permite unitatea): cu fereastra de 180 s fiecare contor
    expira inainte sa-l vada urmatoarea rulare, numaratoarea ramane la `pend|1` si nu se
    trimite NIMIC, nici macar `unk:hysteresis`. Pe gazda reala asta e teoretic (cel mai lung
    interval masurat: 69 s), dar tocmai sub presiune de RAM rularile se lungesc - 20 s in
    minutul OOM-ului. A doua rulare trebuie sa anunte."""
    host.set_proc(avail_mb=900)
    msgs = [host.run(now=1_000_000 + gap * i).msgs for i in range(4)]
    assert msgs[0] == [], msgs
    assert len(msgs[1]) == 1 and "problema noua" in msgs[1][0], msgs
    assert msgs[2] == [] and msgs[3] == [], msgs


def test_the_baseline_message_says_what_it_is_not_a_phase_label(host):
    """"FAZA 2 activ" nu inseamna nimic pentru cine nu stie istoria scriptului, dar
    ajunge pe telefonul operatorului. Mesajul de pornire trebuie sa spuna ce e: ce
    gazda, ca porneste, cate probleme sunt deschise acum si care."""
    (host.state / ".seeded").unlink()
    r = host.run(disk=95)
    assert len(r.msgs) == 1, r.msgs
    msg = r.msgs[0]
    assert "FAZA" not in msg and "testhost" in msg and "pornit" in msg, msg
    assert "Probleme deschise acum: 1" in msg and "Disk / la 95%" in msg, msg
    assert "FAZA" not in SCRIPT.read_text(encoding="utf-8")


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
