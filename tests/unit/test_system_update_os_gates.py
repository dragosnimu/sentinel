"""Porțile fazelor `reboot`, `os`, `verify` și `preflight` (runda 3): ce refuză, ce dovedește și ce
nu are voie să treacă drept verde. Gazda momeală e `_fake_host.py` (vezi acolo ce NU reproduce).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from _fake_host import NEW_K, OLD_K, FakeHost
from _su_shell import docker_state, posix
from test_system_update_os_verify import baseline, new_host, phase, run
from test_system_update_phases import ctr

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")


def calls(fh: FakeHost) -> str:
    return fh.r("calls.log") if (fh.fh / "calls.log").exists() else ""


def mark(base: str, *names: str) -> None:
    (Path(base) / "phases").mkdir(exist_ok=True)
    for n in names:
        (Path(base) / "phases" / n).write_text("x", encoding="utf-8")


def mark_os_ok(base: str, boot: str = "boot-A") -> None:
    """`os.ok` așa cum îl scrie phase_os: cu boot_id-ul pe care a rulat faza (gazda momeală are `boot-A`)."""
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "os.ok").write_text(f"run=x\nepoch=1\nboot_id={boot}\n", encoding="utf-8", newline="\n")


def reboot_host(tmp_path):
    fh = new_host(tmp_path)
    base = baseline(fh)
    fh.w("nr-rc", "1")
    return fh, base


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------
def test_reboot_is_refused_over_a_half_finished_os_phase_unless_explicitly_overridden(tmp_path):
    """`os.started` fără `os.ok` = tranzacție dnf căzută la jumătate (unitatea ucisă, rezultat lipsă).
    Reboot-ul programat peste ea era «PROGRAMATĂ», cod 0: cea mai proastă clipă pentru o repornire.
    Refuzat, iar ieșirea e un steag pe care operatorul îl tastează (`--ignore-os-state`)."""
    fh, base = reboot_host(tmp_path)
    mark(base, "os.started")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "n-a ajuns la os.ok" in p.stdout and "--ignore-os-state" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)
    assert not (Path(base) / "phases" / "reboot.requested").exists()
    p2 = phase(fh, base, "reboot", "OPT_YES=1; OPT_IGNORE_OS_STATE=1")
    assert p2.returncode == 0 and "--ignore-os-state" in p2.stdout and "PROGRAMATĂ" in p2.stdout, p2.stdout


def test_reboot_after_a_successful_os_phase_is_allowed(tmp_path):
    """Calea normală: `os.ok` prezent -> reboot-ul se programează, cu dovada fișierului de systemd."""
    fh, base = reboot_host(tmp_path)
    mark(base, "os.started", "os.ok")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0 and "os.ok" in p.stdout and "PROGRAMATĂ" in p.stdout, p.stdout


def test_reboot_is_refused_when_os_never_ran_but_updates_were_pending(tmp_path):
    """Baseline-ul avea 3 pachete de actualizat și `os` n-a rulat: un reboot «necesar» (needs-restarting)
    ar repurta gazda pe aceleași pachete vechi."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc", "openssl"])
    base = baseline(fh)
    fh.w("nr-rc", "1")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "n-a rulat" in p.stdout and "shutdown" not in calls(fh), p.stdout


def test_reboot_checks_the_kernel_that_will_boot_not_the_newest_installed(tmp_path):
    """Nucleul care PORNEȘTE e cel din `grubby --default-kernel`. Un test făcut pe «cel mai nou instalat»
    declara bine un reboot spre un nucleu implicit fără fișiere. Cazurile: (a) implicit = vechiul, cel
    nou are fișiere; (b) implicitul nu are fișiere deloc, cel nou are; (c) implicit = cel nou, dar
    fișierele sunt trunchiate. În toate: refuz, nicio comandă shutdown."""
    # (a)
    fh, base = reboot_host(tmp_path)
    mark(base, "os.ok")
    fh.w("kernels", f"{OLD_K}\n{NEW_K}\n")
    fh.set_boot_files(NEW_K)
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "nu e cel mai nou instalat" in p.stdout and "shutdown" not in calls(fh), p.stdout
    # (b)
    tmp_b = tmp_path / "b"
    tmp_b.mkdir()
    fh, base = reboot_host(tmp_b)
    mark(base, "os.ok")
    fh.w("kernels", f"{OLD_K}\n{NEW_K}\n")
    fh.set_boot_files(NEW_K)
    fh.w("grubby", "/boot/vmlinuz-5.14.0-687.54.1.el9_8.x86_64\n")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "5.14.0-687.54.1.el9_8.x86_64) NU poate porni" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)
    # (c)
    tmp_c = tmp_path / "c"
    tmp_c.mkdir()
    fh, base = reboot_host(tmp_c)
    mark(base, "os.ok")
    fh.w("kernels", f"{OLD_K}\n{NEW_K}\n")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")
    (fh.fh / "boot" / f"vmlinuz-{NEW_K}").write_text("tiny", encoding="utf-8")
    (fh.fh / "boot" / f"initramfs-{NEW_K}.img").write_text("i" * 2000, encoding="utf-8")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "doar 4 octeți" in p.stdout and "shutdown" not in calls(fh), p.stdout


def test_reboot_does_not_start_while_dnf_or_rpm_is_running(tmp_path):
    """O repornire peste o tranzacție rpm în curs lasă baza de pachete la jumătate."""
    fh, base = reboot_host(tmp_path)
    mark(base, "os.ok")
    fh.w("pgrep-rc", "0")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "dnf/rpm rulează deja" in p.stdout and "shutdown" not in calls(fh), p.stdout


# ---------------------------------------------------------------------------
# os
# ---------------------------------------------------------------------------
def os_host(tmp_path, *, default_new=True):
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc"])
    fh.upgrade_result(default_new=default_new)
    return fh, baseline(fh)


def test_os_fails_on_a_transaction_that_did_not_end_in_success(tmp_path):
    """dnf iese cu 0 dar istoricul spune `Return-Code: Error`: baza rpm poate fi la jumătate."""
    fh, base = os_host(tmp_path)
    fh.w("history-rc", "Error")
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "Return-Code 'Error'" in p.stdout, p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


def test_os_fails_when_dnf_check_reports_broken_dependencies(tmp_path):
    """Un `dnf check` care raportează dependențe rupte după actualizare nu poate lăsa faza verde."""
    fh, base = os_host(tmp_path)
    fh.w("dnf-check-rc", "1")
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "dnf check raportează" in p.stdout, p.stdout


def test_os_fails_when_the_new_kernel_is_not_the_boot_default(tmp_path):
    """Nucleul nou e instalat, dar `grubby` încă pornește cel vechi: reboot-ul n-ar activa actualizarea."""
    fh, base = os_host(tmp_path, default_new=False)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "NU e cel implicit la pornire" in p.stdout, p.stdout


def test_os_fails_when_the_new_kernel_has_no_initramfs(tmp_path):
    """«Instalat» fără initramfs nu pornește (pe un VPS: consola providerului)."""
    fh, base = os_host(tmp_path)
    fh.set_boot_files(NEW_K, initramfs=False)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "NU poate porni" in p.stdout and "initramfs" in p.stdout, p.stdout


def test_a_failed_second_os_run_does_not_inherit_the_first_runs_ok(tmp_path):
    """`os.ok` de la prima rulare nu are voie să supraviețuiască unei a doua rulări căzute: altfel verify și
    reboot ar vedea «încheiată cu succes» peste o tranzacție care a eșuat."""
    fh, base = os_host(tmp_path)
    assert phase(fh, base, "os").returncode == 0
    assert (Path(base) / "phases" / "os.ok").exists()
    fh.pending(["glibc"])
    fh.w("dnf-mode", "fail")
    assert phase(fh, base, "os").returncode == 1
    assert not (Path(base) / "phases" / "os.ok").exists() and (Path(base) / "phases" / "os.started").exists()


def test_os_closes_the_lock_descriptors_for_dnf(tmp_path):
    """dnf rulează scriptlete rpm care pornesc servicii; unul care moștenește blocarea o ține după ieșire.
    Momeala de dnf notează ce descriptori (10-15) are deschiși când rulează `upgrade`."""
    fh, base = os_host(tmp_path)
    assert phase(fh, base, "os").returncode == 0
    rows = [l for l in calls(fh).splitlines() if l.startswith("fds:")]
    assert rows == ["fds: "], rows


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def with_api(tmp_path) -> FakeHost:
    fh = new_host(tmp_path)
    p = tmp_path / "docker-state.json"
    st = json.loads(p.read_text(encoding="utf-8"))
    st["containers"]["api"] = ctr("api", "web:1", health="healthy", project="p", service="api", image_id="sha256:" + "11" * 32)
    p.write_text(json.dumps(st), encoding="utf-8")
    return fh


def test_verify_catches_a_healthy_container_that_restarts_between_samples(tmp_path):
    """Un container care intră în buclă de repornire e `running`/`healthy` la fiecare citire izolată.
    Verify îl prinde din numărul de reporniri la două eșantioane."""
    fh = with_api(tmp_path)
    base = baseline(fh)
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    st["flap_restart"] = ["api"]
    (tmp_path / "docker-state.json").write_text(json.dumps(st), encoding="utf-8")
    p = phase(fh, base, "verify")
    assert p.returncode == 1 and any(l.startswith("[x]") and "api: se repornește" in l for l in p.stdout.splitlines()), p.stdout


def test_verify_reports_unknown_when_the_boot_id_cannot_be_read(tmp_path):
    """Un boot_id necitibil nu înseamnă «gazda s-a repornit» și nici «n-a făcut-o»: e necunoscut (cod 3)."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    mark(base, "reboot.requested")
    (Path(base) / "phases" / "reboot.requested").write_text("boot_id=boot-A\n", encoding="utf-8")
    p = phase(fh, base, "verify", SU_BOOT_ID_FILE=posix(tmp_path / "nu-exista"))
    assert p.returncode == 3 and "nu pot compara boot_id" in p.stdout, p.stdout


def test_verify_is_not_green_while_a_reboot_is_still_required_or_unknowable(tmp_path):
    """`needs-restarting -r` cu cod 1 = actualizarea nu e încă activă (problemă); cu 127 (comandă lipsă)
    = nu se poate afla (necunoscut). Verify ieșea 0 în ambele cazuri."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    fh.w("nr-rc", "1")
    p = phase(fh, base, "verify")
    assert p.returncode == 1 and any(l.startswith("[x]") and "cere încă un reboot" in l for l in p.stdout.splitlines()), p.stdout
    fh.w("nr-rc", "127")
    p2 = phase(fh, base, "verify")
    assert p2.returncode == 3 and "nu pot spune dacă mai e nevoie de un reboot" in p2.stdout, p2.stdout


def test_verify_does_not_let_a_later_up_to_date_hide_a_failed_container(tmp_path):
    """Raportul fazei containers e un jurnal. `failed` urmat de `up-to-date` (rularea a doua n-a avut ce
    recrea) ieșea «TOTUL DOVEDIT». Rezultatul final al serviciului rămâne `failed` până la un `--retry-failed`
    explicit (`retried`) urmat de un `verified`; un `verified` singur (containerul vechi sănătos) nu-l șterge."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|up-to-date|web:1\n", encoding="utf-8")
    p = phase(fh, base, "verify")
    assert p.returncode == 1 and "p/web: rezultat final din faza containers = failed" in p.stdout, p.stdout
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|verified|web aaaa\n", encoding="utf-8")
    p2 = phase(fh, base, "verify")
    assert p2.returncode == 1 and "p/web: rezultat final din faza containers = failed" in p2.stdout, p2.stdout
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|retried|--retry-failed p\np|web|verified|web aaaa\n", encoding="utf-8")
    p3 = phase(fh, base, "verify")
    assert p3.returncode == 0, p3.stdout


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def test_preflight_wired_through_phase_preflight_refuses_to_overwrite_a_changed_baseline(tmp_path):
    """Garda e probată prin `phase_preflight` însuși (nu doar funcția ei), fără simboluri: cu `os.started`
    în baseline-ul curent un nou preflight nu are voie să-l înlocuiască cu starea de DUPĂ. Nicio
    înregistrare nouă; `--new-baseline` e ieșirea deliberată."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    mark(base, "os.started")
    fh.ctimers = ["container-update-nis2.timer"]
    fh.save_units()
    before = sorted(p.name for p in (tmp_path / "state" / "snapshots").iterdir())
    p = run(fh, f"PHASE=preflight; init_state; BASE='{base}'; phase_preflight")
    assert p.returncode == 1 and "--new-baseline" in p.stdout and "nu înregistrez baseline-ul" in p.stdout, p.stdout
    assert "1 temporizatoare container-update-*" in p.stdout, p.stdout     # raportul e legat de faza reală
    assert sorted(x.name for x in (tmp_path / "state" / "snapshots").iterdir()) == before


def test_preflight_reports_the_weekly_container_update_timers(tmp_path):
    """Actualizarea săptămânală a containerelor are aceeași blocare și, în varianta ei, aceleași etichete
    de rollback. Preflight o raportează (nu schimbă nimic) și spune în ce spațiu lucrează faza asta."""
    fh = new_host(tmp_path)
    fh.ctimers = ["container-update-nis2.timer", "container-update-hub.timer", "container-update-dms.timer"]
    fh.save_units()
    p = run(fh, "PHASE=preflight; init_state; RESULT_FILE=''; pf_note_container_update")
    assert "3 temporizatoare container-update-*" in p.stdout and "rollback/maint-" in p.stdout, p.stdout
    fh.ctimers = []
    fh.save_units()
    p2 = run(fh, "PHASE=preflight; init_state; RESULT_FILE=''; pf_note_container_update")
    assert "niciun temporizator container-update-*" in p2.stdout


# ---------------------------------------------------------------------------
# runda 7: preflight --new-baseline preia eșecurile nerezolvate; un reboot explicat de `os` nu blochează calea documentată
# ---------------------------------------------------------------------------
# Windows (fără simboluri reale) nu poate publica `current` prin `ln -sfn` + `mv -T`: legătura devine un FIȘIER cu ținta. Ce NU dovedește
# simulările astea: atomicitatea publicării (rename pe o legătură simbolică reală) — o probează testul cu simboluri, unde există.
SYMLINK_SHIM = (
    'ln() { printf "%s\\n" "$(command readlink -f "$(dirname "$3")/$2")" > "$3"; }\n'
    'mv() { if [[ "${1:-}" == -T ]]; then shift; command mv -f "$@"; else command mv "$@"; fi; }\n'
    'readlink() { if [[ "${1:-}" == -f && -f "${2:-}" ]]; then cat "$2"; else command readlink "$@"; fi; }\n'
)

CARRY_REPORT = (
    "p|web|failed|web-1\n"
    "p|bet|pull-failed|bet:1\n"
    "p|old|stale-baseline|baseline vechi: rulează aaaa\n"
    "p|ok|failed|x\np|ok|retried|r\np|ok|verified|ok\n"
    "p|ok2|unread|u\n"
)


def new_snapshots(tmp_path: Path, old: str = "B") -> list[Path]:
    return [d for d in (tmp_path / "state" / "snapshots").iterdir() if d.is_dir() and d.name != old]


def test_new_baseline_carries_unresolved_failures_and_the_documented_path_passes_the_reboot_os_caused(tmp_path):
    """Calea documentată după un `stale-baseline`: os -> containers (refuzat) -> `preflight --new-baseline` -> backup -> containers. Două
    lucruri o rupeau. (1) Baseline-ul nou nu citea containers.report-ul celui vechi: fiecare eșec nerezolvat (failed, pull-failed,
    unread) dispărea în tăcere, iar containers și verify ieșeau verzi peste el. Acum se preiau (cu aceeași stare, deci se rezolvă la fel) și se
    tipăresc; `stale-baseline` NU se preia (îl rezolvă baseline-ul nou), iar un serviciu rezolvat (failed -> retried -> verified) nici
    atât. (2) După `os` gazda cere reboot și rulează alt nucleu decât cel implicit: preflight refuza «un reboot e DEJA necesar» pe
    urma propriei actualizări, deci baseline-ul nou nu se putea lua niciodată înainte de reboot."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    mark(base, "os.started", "containers.started")
    mark_os_ok(base)
    (Path(base) / "containers.report").write_text(CARRY_REPORT, encoding="utf-8", newline="\n")
    fh.w("nr-rc", "1")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")            # os a instalat nucleul nou și l-a făcut implicit; încă rulează cel vechi
    p = run(fh, f"PHASE=preflight; init_state; BASE='{base}'; OPT_NEW_BASELINE=1; {SYMLINK_SHIM} phase_preflight")
    assert p.returncode == 0 and "baseline publicat" in p.stdout, p.stdout + p.stderr
    assert "DEJA necesar" not in p.stdout and "îl explică" in p.stdout, p.stdout
    for key, state in (("p/web", "failed"), ("p/bet", "pull-failed")):
        assert f"{key} ({state})" in p.stdout, (key, p.stdout)
    # `p/ok2` n-are niciun container, în nicio stare, în baseline-ul nou (gazda momeală are doar web și bet): episodul lui se închide, nu se preia (decizia ii, runda 11; sensul «absent», runda 12)
    assert "p/ok2 (unread)" not in p.stdout and "p/ok2: serviciul a dispărut din baseline-ul nou" in p.stdout, p.stdout
    assert "p/ok (" not in p.stdout and "p/old (" not in p.stdout and "stale-baseline" in p.stdout     # doar nota «nu se preiau»
    (new,) = new_snapshots(tmp_path)
    lines = (new / "containers.report").read_text(encoding="utf-8").splitlines()
    carried = [l for l in lines if "|episode-closed|" not in l]
    assert sorted(l.split("|")[:3] for l in carried) == [["p", "bet", "pull-failed"], ["p", "web", "failed"]], carried
    assert all("preluat din baseline-ul B" in l for l in carried), carried
    assert [l.split("|")[:3] for l in lines if "|episode-closed|" in l] == [["p", "ok2", "episode-closed"]], lines
    v = phase(fh, posix(new), "verify")
    for key, state in (("p/web", "failed"), ("p/bet", "pull-failed")):
        assert f"{key}: rezultat final din faza containers = {state}" in v.stdout, (key, v.stdout)
    assert v.returncode == 1


def test_a_pending_reboot_is_explained_only_by_a_proven_os_phase_and_an_explicit_new_baseline(tmp_path):
    """Excepția de la «un reboot e DEJA necesar» nu are voie să devină un ocol: cere --new-baseline dat de operator, `os.ok` (dovedit) în
    baseline-ul înlocuit și niciun `reboot.requested`. Fără oricare dintre ele, un reboot în așteptare sau un nucleu implicit diferit rămân
    refuzuri — altfel un reboot lăsat nefăcut dintr-un motiv separat ar trece neobservat. Și e legată de BOOT-ul pe care a rulat `os` (boot_id
    în os.ok): după un reboot, o nevoie nouă de reboot (alt nucleu, alt pachet) nu mai e «urma lui os» și nu se scuză."""
    cases = [
        ("explained", ["os.started"], "boot-A", "OPT_NEW_BASELINE=1", False),
        ("no-flag", ["os.started"], "boot-A", "", True),
        ("os-not-proven", ["os.started"], None, "OPT_NEW_BASELINE=1", True),
        ("no-os-at-all", [], None, "OPT_NEW_BASELINE=1", True),
        ("reboot-already-requested", ["os.started", "reboot.requested"], "boot-A", "OPT_NEW_BASELINE=1", True),
        # runda 8: explicația e legată de boot — `os` a rulat pe ALT boot (gazda a repornit de atunci), sau `os.ok` n-are boot_id (necunoscut != explicat)
        ("os-ran-on-another-boot", ["os.started"], "boot-OLD", "OPT_NEW_BASELINE=1", True),
        ("os-ok-without-boot-id", ["os.started", "os.ok"], None, "OPT_NEW_BASELINE=1", True),
    ]
    for i, (name, marks, os_boot, opts, refused) in enumerate(cases):
        sub = tmp_path / f"c{i}"
        sub.mkdir()
        fh = new_host(sub)
        base = baseline(fh)
        fh.w("nr-rc", "1")
        fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")
        if marks:
            mark(base, *marks)
        if os_boot:
            mark_os_ok(base, os_boot)
        p = run(fh, f"PHASE=preflight; init_state; BASE='{base}'; {opts + ';' if opts else ''} pf_check_pending_reboot; echo FAIL_N=$FAIL_N")
        if refused:
            assert "FAIL_N=2" in p.stdout and "DEJA necesar" in p.stdout and "NU e cel implicit la pornire" in p.stdout, (name, p.stdout)
        else:
            assert "FAIL_N=0" in p.stdout and p.stdout.count("îl explică") == 2 and "DEJA necesar" not in p.stdout, (name, p.stdout)


def test_verify_understands_a_partial_containers_run_after_a_proven_full_one(tmp_path):
    """Un `--only pg` după o rulare completă verde ștergea containers.ok, iar verify/status ieșeau roșii («a pornit dar n-a ajuns la ok») peste o
    actualizare dovedită. Acum rularea parțială are markerele ei: verify cere ca ULTIMA ei să fi ajuns la capăt (altfel a murit la jumătate
    și containers.ok vechi n-o acoperă), iar doar rulări parțiale, fără una completă, nu trec drept «fază încheiată»."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    mark(base, "containers.started", "containers.ok")
    a = phase(fh, base, "verify")
    assert "faza containers: încheiată cu succes dovedit" in a.stdout and "rulare parțială" not in a.stdout and a.returncode == 0, a.stdout
    mark(base, "containers.only.started")
    b = phase(fh, base, "verify")
    assert b.returncode == 1 and "o rulare parțială a fazei containers (--only) a PORNIT după containers.ok și n-a ajuns la capăt" in b.stdout, b.stdout
    mark(base, "containers.only.ok")
    c = phase(fh, base, "verify")
    assert c.returncode == 0 and "rulare parțială" not in c.stdout, c.stdout
    (Path(base) / "phases" / "containers.ok").unlink()
    (Path(base) / "phases" / "containers.started").unlink()
    d = phase(fh, base, "verify")
    assert d.returncode == 1 and "au rulat doar rulări parțiale" in d.stdout, d.stdout


# ---------------------------------------------------------------------------
# runda 8: calea documentată se poate repeta înainte de reboot; după reboot nu mai e nimic de explicat
# ---------------------------------------------------------------------------
def test_a_second_new_baseline_before_the_reboot_passes_and_a_reboot_ends_the_excuse(tmp_path):
    """Calea `os -> containers (refuzat) -> --new-baseline` mergea o singură dată: baseline-ul nou n-are `phases/`, deci un al doilea
    `--new-baseline` (un al doilea stale-baseline, înainte de reboot) vedea «reboot DEJA necesar» fără nicio explicație și era refuzat. Acum
    explicația se preia (os-carried.kv, nu un `os.ok`), legată de boot: al doilea baseline trece, poarta de reboot a celui nou o recunoaște
    (ieșirea documentată: `--phase reboot`), iar după ce gazda a repornit (alt boot) o nouă nevoie de reboot e din nou refuzată."""
    import time

    fh = new_host(tmp_path)
    base = baseline(fh)
    mark(base, "os.started", "containers.started")
    mark_os_ok(base)
    fh.w("nr-rc", "1")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")

    def preflight(b):
        return run(fh, f"PHASE=preflight; init_state; BASE='{b}'; OPT_NEW_BASELINE=1; {SYMLINK_SHIM} phase_preflight")

    p1 = preflight(base)
    assert p1.returncode == 0 and "baseline publicat" in p1.stdout, p1.stdout + p1.stderr
    (b2,) = new_snapshots(tmp_path)
    assert "boot_id=boot-A" in (b2 / "os-carried.kv").read_text(encoding="utf-8") and not (b2 / "phases" / "os.ok").exists()
    time.sleep(1.1)                  # numele snapshotului e secunda curentă
    p2 = preflight(posix(b2))
    assert p2.returncode == 0 and "baseline publicat" in p2.stdout and "DEJA necesar" not in p2.stdout, p2.stdout + p2.stderr
    (b3,) = [d for d in new_snapshots(tmp_path) if d != b2]
    assert (b3 / "os-carried.kv").exists()
    (b3 / "pending.txt").write_text("pkg.x86_64 1.0 repo\n", encoding="utf-8")       # fără explicație, poarta de reboot ar refuza (pachete în așteptare)
    gate = run(fh, f"PHASE=reboot; init_state; BASE='{posix(b3)}'; reboot_os_state_gate; echo FAIL_N=$FAIL_N")
    assert "FAIL_N=0" in gate.stdout and "os-carried.kv" in gate.stdout, gate.stdout
    fh.w("boot_id", "boot-B\n")                                                        # gazda a repornit de atunci
    late = preflight(posix(b3))
    assert late.returncode == 1 and "DEJA necesar" in late.stdout, late.stdout
    gate2 = run(fh, f"PHASE=reboot; init_state; BASE='{posix(b3)}'; reboot_os_state_gate; echo FAIL_N=$FAIL_N")
    assert "FAIL_N=1" in gate2.stdout, gate2.stdout


def test_verify_shows_an_acknowledged_failure_instead_of_hiding_it_or_failing_on_it(tmp_path):
    """`--acknowledge` e decizia operatorului: după ea verify nu mai iese 1 pentru serviciul respectiv (altfel ieșirea ar fi inutilă), dar nici nu
    o ascunde — un `acked` e o linie de avertisment și apare la «Sărit sau eșuat». Un `failed` fără `acked` rămâne roșu."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "containers.report").write_text("p|web|failed|web\n", encoding="utf-8", newline="\n")
    assert phase(fh, base, "verify").returncode == 1
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|acked|recunoscut explicit de operator\n", encoding="utf-8", newline="\n")
    p = phase(fh, base, "verify")
    assert p.returncode == 0, p.stdout
    assert "p/web: recunoscut de operator (--acknowledge), NERESOLVAT în fapt" in p.stdout and "p/web: acked —" in p.stdout, p.stdout
    # Rezultatul spune recunoașterea, nu «TOTUL DOVEDIT» (cod 0: un avertisment nu schimbă codul, ca orice alt avertisment): un verify care ar încheia cu
    # «TOTUL DOVEDIT» peste un serviciu recunoscut ca nerezolvat ar face din decizia unui om o reușită.
    assert "DOVEDIT, cu 1 servicii recunoscute de operator (NERESOLVATE în fapt)" in p.stdout and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    # Un `verified` după recunoaștere NU o șterge (doar `ack-cleared`, scris după un verdict ok): steagul rămâne și verify îl arată în continuare.
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|acked|op\np|web|verified|web\n", encoding="utf-8", newline="\n")
    again = phase(fh, base, "verify")
    assert again.returncode == 0 and "p/web: recunoscut de operator (--acknowledge), NERESOLVAT în fapt" in again.stdout and "TOTUL DOVEDIT" not in again.stdout, again.stdout
    (Path(base) / "containers.report").write_text("p|web|failed|web\np|web|acked|op\np|web|verified|web\np|web|ack-cleared|ok\n", encoding="utf-8", newline="\n")
    cleared = phase(fh, base, "verify")
    assert cleared.returncode == 0 and "recunoscut de operator" not in cleared.stdout and "TOTUL DOVEDIT" in cleared.stdout, cleared.stdout


def new_baseline_preflight(fh: FakeHost, base: str, report: str):
    """`preflight --new-baseline` REAL (take_snapshot pe gazda momeală, carry_forward_sticky din scriptul livrat) peste un containers.report dat."""
    mark(base, "os.started", "containers.started")
    (Path(base) / "containers.report").write_text(report, encoding="utf-8", newline=chr(10))
    p = run(fh, f"PHASE=preflight; init_state; BASE='{base}'; OPT_NEW_BASELINE=1; {SYMLINK_SHIM} phase_preflight")
    assert p.returncode == 0 and "baseline publicat" in p.stdout, p.stdout + p.stderr
    (new,) = new_snapshots(fh.tmp)
    return p, new, (new / "containers.report").read_text(encoding="utf-8").splitlines()


def test_preflight_new_baseline_closes_only_a_service_with_no_container_and_keeps_a_stopped_or_looping_one_red(tmp_path):
    """Decizia operatorului (runda 12): «dispărut» = absent. Pe gazda momeală, măsurată de `take_snapshot` (nu un tsv scris de mână), `p/stopped` are un container
    EXITED, `p/loop` unul RESTARTING, iar `p/ghost` niciunul. Runda 11 închidea toate trei: `--new-baseline` ieșea verde peste un container mort și unul care crapă în
    buclă. Acum doar `p/ghost` (scos din compose) își închide episodul; celelalte două rămân preluate, roșii, cu aceeași stare."""
    fh = new_host(tmp_path)
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    st["containers"]["stopped"] = ctr("stopped", "web:1", state="exited", project="p", service="stopped", image_id="sha256:" + "11" * 32)
    st["containers"]["loop"] = ctr("loop", "web:1", state="restarting", project="p", service="loop", image_id="sha256:" + "11" * 32)
    docker_state(tmp_path, st)
    base = baseline(fh)
    assert {l.split("|")[0]: l.split("|")[6] for l in (Path(base) / "containers.tsv").read_text(encoding="utf-8").splitlines()}["stopped"] == "exited"
    p, new, lines = new_baseline_preflight(fh, base, "p|stopped|failed|s" + chr(10) + "p|loop|failed|l" + chr(10) + "p|ghost|failed|g" + chr(10))
    assert "p/stopped (failed)" in p.stdout and "p/loop (failed)" in p.stdout and "p/ghost (failed)" not in p.stdout, p.stdout
    assert "p/ghost: serviciul a dispărut din baseline-ul nou" in p.stdout and "p/stopped: serviciul a dispărut" not in p.stdout and "p/loop: serviciul a dispărut" not in p.stdout, p.stdout
    assert sorted(l.split("|")[:3] for l in lines if "|episode-closed|" not in l) == [["p", "loop", "failed"], ["p", "stopped", "failed"]], lines
    assert [l.split("|")[:3] for l in lines if "|episode-closed|" in l] == [["p", "ghost", "episode-closed"]], lines
    v = phase(fh, posix(new), "verify")
    assert v.returncode == 1 and "p/stopped: rezultat final din faza containers = failed" in v.stdout and "p/loop: rezultat final din faza containers = failed" in v.stdout, v.stdout


def test_preflight_new_baseline_with_a_measured_but_empty_container_list_closes_nothing_and_says_so(tmp_path):
    """L2 (runda 11), cu măsurarea REALĂ: docker răspunde (`docker info` ok) dar `docker ps -a` nu listează nimic, deci containers.tsv e un fișier măsurat și gol.
    Runda 11 închidea fiecare episod («niciun rând pentru serviciu»): o singură măsurare ciudată ștergea în tăcere toate eșecurile nerezolvate. Acum nu se închide
    nimic, eșecurile se preiau, iar preflight spune în română că lista goală e suspectă."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    docker_state(tmp_path, {"images": {}, "containers": {}, "compose": {}})                 # docker răspunde, dar nu mai listează niciun container
    p, new, lines = new_baseline_preflight(fh, base, "p|web|failed|w" + chr(10) + "p|bet|pull-failed|b" + chr(10))
    assert (new / "containers.tsv").exists() and not (new / "containers.tsv").read_text(encoding="utf-8").strip(), "măsurătoarea nu a produs o listă goală"
    assert "lista containerelor din baseline-ul nou e măsurată, dar GOALĂ" in p.stdout and "o gazdă docker cu lista goală e suspectă" in p.stdout, p.stdout
    assert "p/web (failed)" in p.stdout and "p/bet (pull-failed)" in p.stdout and not any("|episode-closed|" in l for l in lines), p.stdout
    assert sorted(l.split("|")[:3] for l in lines) == [["p", "bet", "pull-failed"], ["p", "web", "failed"]], lines
