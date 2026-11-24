"""Fazele `os`, `reboot`, `verify` și `preflight`, plus baseline-ul, din
`scripts/lib/system-update-*.sh`, rulate pe o gazdă momeală (`_fake_host.py`; vezi acolo ce NU
reproduce). Baseline-ul se ia cu `take_snapshot` REAL pe gazda momeală sănătoasă, apoi fiecare test
strică doar ce vrea să arate.

Fiecare test numește, în docstring, ce se strică pentru operator dacă codul greșește.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from _fake_host import NEW_K, OLD_K, FakeHost
from _su_shell import BASH, docker_state, host_run, posix
from test_system_update_phases import ctr

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")


def healthy_docker(tmp: Path) -> None:
    docker_state(tmp, {"images": {"web:1": {"id": "sha256:" + "11" * 32, "digests": 1},
                                  "bet:1": {"id": "sha256:" + "22" * 32, "digests": 0}},
                       "containers": {
                           "web": ctr("web", "web:1", health="healthy", project="p", service="web", image_id="sha256:" + "11" * 32),
                           "bet-calculator": ctr("bet-calculator", "bet:1", health="unhealthy", project="p", service="bet", image_id="sha256:" + "22" * 32)},
                       "compose": {}})


def run(fh: FakeHost, body: str, **env: str):
    bindir, e = fh.install()
    e.update(env)
    return host_run(fh.tmp, body, bindir, **e)


def baseline(fh: FakeHost) -> str:
    """Baseline REAL, luat cu take_snapshot pe gazda momeală (sănătoasă la acest moment)."""
    base = posix(fh.tmp / "state" / "snapshots" / "B")
    p = run(fh, f"PHASE=preflight; init_state; RESULT_FILE=''; mkdir -p '{base}'; n=$(take_snapshot '{base}'); echo UNKNOWN=$n; : > '{base}/COMPLETE'")
    why = {f.name: f.read_text(encoding="utf-8") for f in Path(base).glob("*.unknown")}
    assert "UNKNOWN=0" in p.stdout, (p.stdout, p.stderr, why)
    (fh.tmp / "state" / "backup.manifest").write_text(f"epoch={int(time.time())}\nrun=x\n", encoding="utf-8")
    return base


def phase(fh: FakeHost, base: str, name: str, opts: str = "", **env: str):
    return run(fh, f"PHASE={name}; init_state; BASE='{base}'; {opts + ';' if opts else ''} phase_{name}", SU_WAIT_S="1", **env)


def new_host(tmp: Path) -> FakeHost:
    healthy_docker(tmp)
    return FakeHost(tmp)


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------
def test_baseline_records_what_it_measured_and_marks_what_it_could_not(tmp_path):
    """Un `rpm -qa` căzut lăsa un fișier gol care exista și însemna «niciun pachet»; comparația de
    după vedea apoi totul «schimbat» sau nimic. Măsurătoarea căzută devine `<fișier>.unknown` cu
    motivul, iar cele reușite sunt fișiere reale — inclusiv serviciile pornite dar `disabled`."""
    fh = new_host(tmp_path)
    base = Path(baseline(fh))
    assert (base / "rpm-qa.txt").read_text(encoding="utf-8").count("\n") == 60
    assert "bet-calculator|p|bet|bet:1" in (base / "containers.tsv").read_text(encoding="utf-8")
    assert (base / "failed-units.txt").read_text(encoding="utf-8").split() == ["dnf-makecache.service"]
    assert "php82-php-fpm.service" in (base / "disabled-running.txt").read_text(encoding="utf-8")
    assert "nginx.service" in (base / "services.txt").read_text(encoding="utf-8")
    assert "php82-php-fpm.service" not in (base / "services.txt").read_text(encoding="utf-8")
    assert "a.example.ro|200" in (base / "http.tsv").read_text(encoding="utf-8")
    broken = tmp_path / "b"
    broken.mkdir()
    fh2 = new_host(broken)
    fh2.w("rpm-now", "x\n")          # sub minimul unei gazde reale: nu e o măsurătoare
    p = run(fh2, f"PHASE=preflight; init_state; mkdir -p '{posix(broken / 'snap')}'; take_snapshot '{posix(broken / 'snap')}'")
    assert p.stdout.strip().endswith("1"), p.stdout
    assert (broken / "snap" / "rpm-qa.txt.unknown").exists() and not (broken / "snap" / "rpm-qa.txt").exists()


# ---------------------------------------------------------------------------
# os
# ---------------------------------------------------------------------------
def test_os_proves_a_real_upgrade_by_its_effects(tmp_path):
    """Succesul `os` e dovedit din efect: o tranzacție nouă cu Return-Code Success, pachete schimbate
    în rpm, nucleul nou instalat, implicit la pornire și cu fișierele lui pe disc, nimic rămas de
    actualizat. Doar atunci se scrie `os.ok`."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc", "openssl"])
    fh.upgrade_result()
    base = baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    for fragment in ("încheiată cu Success", "pachete diferă față de baseline", f"nucleu nou instalat: {OLD_K} -> {NEW_K}",
                     "nucleul nou e cel implicit", "fișierele de pornire ale nucleului nou există", "nu a rămas nimic de actualizat", "nginx -t: configurația e validă"):
        assert fragment in p.stdout, (fragment, p.stdout)
    assert (Path(base) / "phases" / "os.ok").exists() and (Path(base) / "phases" / "os.started").exists()
    # runda 8: os.ok poartă boot-ul pe care a rulat faza (explicația «reboot-ul îl cere os» e legată de el)
    assert "boot_id=boot-A" in (Path(base) / "phases" / "os.ok").read_text(encoding="utf-8")


def test_os_ending_unknown_does_not_write_os_ok(tmp_path):
    """Istoricul dnf nu poate fi citit după upgrade: faza iese 3 («necunoscut»), dar scria totuși `os.ok`,
    iar poarta de reboot spunea «succes dovedit» peste ceva ce n-a putut fi măsurat. `os.ok` doar la ieșire 0."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc", "openssl"])
    fh.upgrade_result()
    base = baseline(fh)
    fh.w("history-fail", "1")
    p = phase(fh, base, "os")
    assert p.returncode == 3 and "nu pot citi istoricul dnf" in p.stdout, p.stdout
    assert (Path(base) / "phases" / "os.started").exists() and not (Path(base) / "phases" / "os.ok").exists()
    r = phase(fh, base, "reboot", "OPT_YES=1")
    assert "succes dovedit" not in r.stdout, r.stdout


def test_os_does_not_believe_a_zero_exit_that_changed_nothing(tmp_path):
    """Exact tiparul «operație nulă cu cod 0»: dnf iese cu 0, dar istoricul n-are tranzacție nouă și
    pachetele cerute rămân. Operatorul ar fi crezut sistemul actualizat; faza e roșie și nu scrie os.ok."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc"])
    fh.w("dnf-mode", "noop")
    base = baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1, p.stdout
    assert "n-are nicio tranzacție nouă" in p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


def test_a_wholesale_dnf_failure_still_reports_what_is_left(tmp_path):
    """Când dnf cade întreg (un depozit nu răspunde) rămân 342 de pachete. Raportul `ce a rămas`
    se pierdea cu cod 141: `| head -n 15` închidea conducta sub pipefail, iar faza murea fără
    rezultat tocmai când operatorul avea cea mai mare nevoie de el."""
    fh = new_host(tmp_path)
    fh.pending([f"pkg{i}" for i in range(342)], long=True)
    fh.w("dnf-mode", "fail")
    base = baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1, p.stdout
    assert "dnf upgrade a ieșit cu 1" in p.stdout and "au rămas 342 pachete" in p.stdout
    assert len([l for l in p.stdout.splitlines() if l.startswith("    pkg")]) == 15
    assert "REZULTAT os: EȘEC" in p.stdout
    assert (Path(base) / "phases" / "os.started").exists() and not (Path(base) / "phases" / "os.ok").exists()


def test_rerunning_os_after_success_is_a_proven_noop_not_a_failure(tmp_path):
    """Lista de actualizări din baseline e veche după prima rulare. O a doua rulare, când nu mai e
    nimic de făcut, ieșea roșie («dnf a ieșit cu 0 dar istoricul n-are nicio tranzacție nouă») — o
    alarmă falsă care învață operatorul să nu mai creadă faza."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core", "glibc"])
    fh.upgrade_result()
    base = baseline(fh)
    assert phase(fh, base, "os").returncode == 0
    fh.w("dnf-mode", "noop")
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "no-op dovedit" in p.stdout
    assert (Path(base) / "phases" / "os.ok").exists()


def test_os_refuses_without_a_backup_and_never_calls_dnf_upgrade(tmp_path):
    """Poarta de backup: fără un backup proaspăt al bazelor, `os` (care actualizează mariadb) nu
    atinge nimic — jurnalul dnf nu conține niciun `upgrade`."""
    fh = new_host(tmp_path)
    fh.pending(["mariadb-server"])
    base = baseline(fh)
    (tmp_path / "state" / "backup.manifest").unlink()
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "no-manifest" in p.stdout
    assert "upgrade" not in fh.r("calls.log") if (fh.fh / "calls.log").exists() else True
    assert not (Path(base) / "phases" / "os.started").exists()


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------
def reboot_ready(tmp_path) -> tuple[FakeHost, str]:
    fh = new_host(tmp_path)
    base = baseline(fh)
    fh.w("nr-rc", "1")
    return fh, base


def test_reboot_is_scheduled_only_when_the_scheduled_file_proves_it(tmp_path):
    """`shutdown -r +1` iese cu 0 chiar când n-a programat nimic (alt shutdown deja în curs, dbus
    căzut). Dovada e fișierul pe care îl scrie systemd, cu MODE=reboot. Cererea se înregistrează cu
    boot_id-ul curent, ca verify să poată dovedi că repornirea a avut loc."""
    fh, base = reboot_ready(tmp_path)
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "PROGRAMATĂ" in p.stdout and "shutdown -r +1" in fh.r("calls.log")
    assert "boot_id=boot-A" in (Path(base) / "phases" / "reboot.requested").read_text(encoding="utf-8")


def test_reboot_that_scheduled_nothing_is_a_failure_and_leaves_no_request(tmp_path):
    """shutdown cu cod 0 dar fără fișierul de programare: NU s-a programat nimic. Un marcaj
    `reboot.requested` rămas ar face verify să aștepte o repornire care nu vine."""
    fh, base = reboot_ready(tmp_path)
    fh.w("shutdown-mode", "noeffect")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "NU s-a programat nimic" in p.stdout
    assert not (Path(base) / "phases" / "reboot.requested").exists()


def test_reboot_is_skipped_when_not_needed_refused_without_yes_and_on_unknown(tmp_path):
    """«Numai dacă e nevoie»: needs-restarting spune nu și nucleul care rulează e cel implicit ->
    nimic de făcut, shutdown nu se cheamă. Fără --yes nu pornește. Un needs-restarting care nu
    răspunde (127) NU e «nu e nevoie»: refuz, nu ghicesc."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0 and "nu e nevoie de reboot" in p.stdout
    assert not (fh.fh / "calls.log").exists() or "shutdown" not in fh.r("calls.log")
    assert phase(fh, base, "reboot").returncode == 1
    fh.w("nr-rc", "127")
    p3 = phase(fh, base, "reboot", "OPT_YES=1")
    assert p3.returncode == 1 and "nu pot afla dacă e nevoie de reboot" in p3.stdout


def test_reboot_refuses_a_kernel_that_could_not_boot(tmp_path):
    """Un nucleu implicit fără initramfs nu pornește; pe un VPS asta înseamnă consola providerului.
    Reboot-ul nu se programează."""
    fh, base = reboot_ready(tmp_path)
    fh.w("kernels", f"{OLD_K}\n{NEW_K}\n")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")
    fh.set_boot_files(NEW_K, initramfs=False)
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "NU poate porni" in p.stdout
    assert not (fh.fh / "calls.log").exists() or "shutdown" not in fh.r("calls.log")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def test_verify_is_green_when_nothing_is_worse_than_the_baseline(tmp_path):
    """bet-calculator era unhealthy și dnf-makecache.service eșuat ÎNAINTE de orice schimbare: un
    verify care cere «tot verde» ar fi roșu azi, iar operatorul ar învăța să nu-l mai citească. Aici
    ambele apar ca «rău și la baseline», iar rezultatul e verde."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    p = phase(fh, base, "verify")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "TOTUL DOVEDIT" in p.stdout
    assert "eșuată și la baseline" in p.stdout and "bet-calculator" in p.stdout


def test_verify_reports_every_kind_of_regression_by_name(tmp_path):
    """Tot ce poate merge prost după o actualizare, într-o singură rulare: nucleul care rulează nu e
    cel de la pornire, faza os a murit la jumătate, un serviciu e jos, altul se repornește în buclă, o
    unitate nouă e eșuată, un container e oprit, un vhost dă 502, un serviciu pornit dar `disabled` nu
    mai rulează (php82-php-fpm), regulile auditd s-au împuținat, un temporizator a dispărut, iar
    reboot-ul cerut n-a avut loc. Fiecare e numit; nimic nu e «ok» prin tăcere."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "os.started").write_text("x", encoding="utf-8")
    (Path(base) / "phases" / "reboot.requested").write_text("boot_id=boot-A\n", encoding="utf-8")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")
    fh.units["sshd.service"]["state"] = "inactive"
    fh.units["foo.service"] = {"state": "failed", "enabled": "static", "restarts": 0, "enter": 0}
    fh.units["php82-php-fpm.service"]["state"] = "inactive"
    fh.flap = ["nginx.service"]
    fh.timers["vps-watchdog.timer"] = "inactive"
    fh.save_units()
    fh.http("a.example.ro", "502")
    fh.w("audit-rules", "20")
    state = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    state["containers"]["web"]["state"] = "exited"
    docker_state(tmp_path, state)
    p = phase(fh, base, "verify")
    assert p.returncode == 1, p.stdout
    out = p.stdout
    for fragment in ("faza os a PORNIT dar n-a ajuns la os.ok", "boot_id e același", "dar implicit la pornire",
                     "sshd.service: nu e activ", "nginx.service: se repornește", "unitate eșuată NOUĂ față de baseline: foo.service",
                     "web: exited", "a.example.ro: HTTP 502", "php82-php-fpm.service: NU rulează", "audit_sentinel_rules: 31 -> 20",
                     "temporizatorul vps-watchdog.timer nu mai e activ"):
        # fiecare e o PROBLEMĂ ([x]), nu doar menționat: `[.]` sau `[!]` cu același text ar lăsa verify verde
        assert any(l.startswith("[x]") and fragment in l for l in out.splitlines()), (fragment, out)
    assert "bet-calculator: x" not in out and "dnf-makecache.service" not in out.split("Mai rău decât la baseline:")[1].split("Rău și la baseline")[0]


def test_verify_after_a_real_update_and_reboot_is_green_and_lists_the_changes(tmp_path):
    """Calea fericită completă: os și containers încheiate cu `.ok`, reboot cerut și efectuat (boot_id
    schimbat), nucleul nou rulează și e cel implicit. Verde, cu ce s-a schimbat scris."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core"])
    fh.upgrade_result()
    base = baseline(fh)
    (Path(base) / "phases").mkdir(exist_ok=True)
    for f in ("os.started", "os.ok", "containers.started", "containers.ok"):
        (Path(base) / "phases" / f).write_text("x", encoding="utf-8")
    (Path(base) / "phases" / "reboot.requested").write_text("boot_id=boot-A\n", encoding="utf-8")
    fh.w("rpm-now", Path(fh.fh / "rpm-after").read_text(encoding="utf-8"))
    fh.w("kernels", f"{OLD_K}\n{NEW_K}\n")
    fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n")
    fh.w("uname", NEW_K + "\n")
    fh.w("boot_id", "boot-B\n")
    p = phase(fh, base, "verify")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "gazda s-a repornit" in p.stdout and f"nucleu: {OLD_K} -> {NEW_K}" in p.stdout


def test_verify_without_os_ok_does_not_read_as_a_successful_update(tmp_path):
    """Un `os` mort (unitatea ucisă, rezultat lipsă) lasă doar `os.started`. Un verify rulat apoi
    ieșea «TOTUL DOVEDIT» pe un sistem neactualizat. Acum faza neterminată e o problemă numită; iar
    când `os` n-a rulat deloc și baseline-ul avea pachete de actualizat, verify o spune."""
    fh = new_host(tmp_path)
    fh.pending(["kernel-core"])
    base = baseline(fh)
    p = phase(fh, base, "verify")
    assert p.returncode == 1 and "faza os n-a rulat deloc" in p.stdout
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "os.started").write_text("x", encoding="utf-8")
    p2 = phase(fh, base, "verify")
    assert p2.returncode == 1 and "a PORNIT dar n-a ajuns la os.ok" in p2.stdout


def test_verify_reports_unknown_not_green_when_the_baseline_could_not_measure(tmp_path):
    """Un http.tsv nemăsurat la baseline nu e «niciun vhost de verificat»: e necunoscut (cod 3), nu
    verde."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "http.tsv").unlink()
    (Path(base) / "http.tsv.unknown").write_text("cod=1\n", encoding="utf-8")
    p = phase(fh, base, "verify")
    assert p.returncode == 3 and "NECUNOSCUT" in p.stdout


def test_status_exit_code_is_a_verdict_not_a_listing(tmp_path):
    """`status` ieșea mereu cu 0, deci lansatorul tipărea «totul dovedit» peste un os eșuat sau
    încă în curs. Acum: 1 când o fază a eșuat sau a pornit fără `.ok`, 3 când ultimul rezultat e
    necunoscut, 0 numai când nimic nu e neterminat."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / "backup-20261119T000000Z-1.result").write_text("phase=backup\nstatus=ok\nrc=0\nfinished=1\n", encoding="utf-8")
    assert phase(fh, base, "status").returncode == 0
    (runs / "os-20261119T000001Z-1.result").write_text("phase=os\nstatus=fail\nrc=1\nfinished=1\nbad=dnf a eșuat\n", encoding="utf-8")
    p = phase(fh, base, "status")
    assert p.returncode == 1 and "dnf a eșuat" in p.stdout
    (runs / "os-20261119T000001Z-1.result").write_text("phase=os\nstatus=ok\nrc=0\nfinished=1\n", encoding="utf-8")
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "os.started").write_text("x", encoding="utf-8")
    assert phase(fh, base, "status").returncode == 1
    (Path(base) / "phases" / "os.started").unlink()
    (runs / "verify-20261119T000002Z-1.result").write_text("phase=verify\nstatus=unknown\nrc=3\nfinished=1\n", encoding="utf-8")
    assert phase(fh, base, "status").returncode == 3


def test_status_reads_the_partial_containers_run_markers_like_verify_does(tmp_path):
    """`containers --only pg` care a PORNIT (`containers.only.started`) și n-a ajuns la `containers.only.ok` a murit sau a eșuat la jumătate;
    verify o vedea, dar `status` citea doar `containers.started`/`.ok` și ieșea 0 «nimic eșuat sau neterminat» peste ea. Acum: cod 1, cu motivul;
    cu marcajul de reușită, status revine la 0."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    assert phase(fh, base, "status").returncode == 0
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "containers.only.started").write_text("x", encoding="utf-8")
    p = phase(fh, base, "status")
    assert p.returncode == 1 and "rulare parțială a fazei containers (--only) a PORNIT" in p.stdout, p.stdout
    (Path(base) / "phases" / "containers.only.ok").write_text("x", encoding="utf-8")
    assert phase(fh, base, "status").returncode == 0


def test_status_ignores_a_dry_run_result_but_shows_it_labelled(tmp_path):
    """`containers --dry-run` scrie un rezultat ca orice fază, iar `status` citea ultimul: o simulare roșie (un eșec nerezolvat, un serviciu stale)
    întorcea verdictul în EȘEC peste o fază care ieșise verde în serios, și invers. Simularea (`dry_run=1`) iese din verdict; apare doar ca o
    linie etichetată, dacă e mai nouă decât ultimul rezultat REAL. Un rezultat vechi, fără câmpul `dry_run`, rămâne real."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    runs = tmp_path / "state" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / "containers-20261119T000000Z-1.result").write_text("phase=containers\nstatus=ok\nrc=0\nfinished=1\n", encoding="utf-8")
    (runs / "containers-20261119T000001Z-2.result").write_text("phase=containers\nstatus=fail\nrc=1\nfinished=1\nfail=1\ndry_run=1\nbad=stale\n", encoding="utf-8")
    p = phase(fh, base, "status")
    assert p.returncode == 0 and "simulare (--dry-run, NU intră în verdict): fail rc=1" in p.stdout, p.stdout
    assert "x stale" not in p.stdout
    (runs / "containers-20261119T000002Z-3.result").write_text("phase=containers\nstatus=fail\nrc=1\nfinished=1\nfail=1\ndry_run=0\nbad=real\n", encoding="utf-8")
    q = phase(fh, base, "status")
    assert q.returncode == 1 and "x real" in q.stdout, q.stdout          # un eșec REAL rămâne verdict


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("what, setup, fragment", [
    ("dnf_running", lambda fh: fh.w("pgrep-rc", "0"), "dnf/rpm rulează deja"),
    ("reboot_pending", lambda fh: fh.w("nr-rc", "1"), "un reboot e DEJA necesar"),
    ("reboot_unknown", lambda fh: fh.w("nr-rc", "127"), "nu pot afla dacă un reboot e în așteptare"),
    ("kernel_mismatch", lambda fh: fh.w("grubby", f"/boot/vmlinuz-{NEW_K}\n"), "NU e cel implicit la pornire"),
    ("repo_down", lambda fh: fh.w("makecache-rc", "1"), "dnf makecache --refresh a eșuat"),
])
def test_preflight_refuses_and_records_no_baseline(tmp_path, what, setup, fragment):
    """Preflight refuză, nu ghicește: dnf deja pornit, un reboot în așteptare (sau care nu se poate
    afla), un nucleu implicit diferit de cel care rulează, un depozit care nu răspunde (remi-modular a
    dat timeout pe gazdă; `skip_if_unavailable=False` ar face `dnf upgrade` să cadă întreg la mijlocul
    ferestrei). Cât timp există un motiv de refuz NU se înregistrează baseline."""
    fh = new_host(tmp_path)
    setup(fh)
    p = run(fh, "PHASE=preflight; init_state; phase_preflight")
    assert p.returncode == 1, p.stdout + p.stderr
    assert fragment in p.stdout, p.stdout
    assert "nu înregistrez baseline-ul" in p.stdout
    snaps = tmp_path / "state" / "snapshots"
    assert not snaps.exists() or not any(snaps.iterdir())


def _symlinks_work(tmp: Path) -> bool:
    r = subprocess.run([BASH, "-c", f"cd '{posix(tmp)}' && mkdir -p t && ln -s t l && [ -L l ]"], capture_output=True)
    return r.returncode == 0


def test_preflight_publishes_a_baseline_and_a_second_one_cannot_overwrite_changes(tmp_path):
    """Preflight curat publică baseline-ul (current -> snapshot, cu COMPLETE) și avertizează pentru
    serviciile pornite dar `disabled`. Un al doilea preflight, după ce `os` a pornit, ar înlocui
    martorul cu starea de DUPĂ: refuzat, cu --new-baseline ca ieșire deliberată."""
    if not _symlinks_work(tmp_path):
        pytest.skip("simboluri reale indisponibile în acest bash (Windows fără mod dezvoltator): publicarea atomică a baseline-ului nu se poate proba aici")
    fh = new_host(tmp_path)
    p = run(fh, "PHASE=preflight; init_state; phase_preflight")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "baseline publicat" in p.stdout and "php82-php-fpm.service" in p.stdout
    cur = tmp_path / "state" / "current"
    assert (cur / "COMPLETE").exists()
    (cur / "phases").mkdir(exist_ok=True)
    (cur / "phases" / "os.started").write_text("x", encoding="utf-8")
    p2 = run(fh, "PHASE=preflight; init_state; phase_preflight")
    assert p2.returncode == 1 and "--new-baseline" in p2.stdout


def test_verify_keeps_a_recreated_service_in_the_summary_after_a_noop_rerun(tmp_path):
    """Raportul `containers.report` e cumulativ. O a doua rulare care n-a mai avut ce face scrie
    `up-to-date`; asta nu are voie să șteargă din rezumat faptul că serviciul a fost recreat prima dată,
    iar un `failed` rezolvat prin `--retry-failed` (`retried`) și apoi `recreated` trebuie să arate ultimul rezultat."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "containers.report").write_text(
        "p|web|recreated|aaaaaaaaaaaa -> bbbbbbbbbbbb\np|web|up-to-date|postgres\n"
        "p|bet|failed|bet-calculator\np|bet|retried|--retry-failed p\np|bet|recreated|cccccccccccc -> dddddddddddd\n", encoding="utf-8")
    p = phase(fh, base, "verify")
    assert "p/web: recreat aaaaaaaaaaaa -> bbbbbbbbbbbb" in p.stdout
    assert "p/bet: recreat cccccccccccc -> dddddddddddd" in p.stdout
    assert "p/bet: failed" not in p.stdout


def test_verify_does_not_let_a_later_line_hide_a_sticky_containers_failure(tmp_path):
    """verify citea ultima linie a serviciului din containers.report: un `failed`/`pull-failed`/`build-failed` urmat de
    `skip-unreadable`, de un `verified` al containerului vechi sau de un `recreated` fără `--retry-failed` dispărea
    din rezumat, iar verify-ul ieșea verde peste un serviciu rămas picat. Rezultatul vine din aceeași reducere ca
    în faza containers (su_report_final); doar un eșec rezolvat prin succesul lui specific dispare."""
    fh = new_host(tmp_path)
    base = baseline(fh)
    (Path(base) / "containers.report").write_text(
        "p|a|failed|x\np|a|skip-unreadable|nu pot citi\n"
        "p|b|pull-failed|i\np|b|verified|ok\n"
        "p|c|build-failed|b\np|c|skip-not-requested|n\n"
        "p|d|tag-failed|t\np|d|recreated|1 -> 2\n"
        "p|e|unread|u\np|e|skip-not-requested|n\n"
        "p|ok|failed|x\np|ok|retried|r\np|ok|verified|ok\n", encoding="utf-8")
    p = phase(fh, base, "verify")
    for key, state in (("p/a", "failed"), ("p/b", "pull-failed"), ("p/c", "build-failed"), ("p/d", "tag-failed"), ("p/e", "unread")):
        assert f"{key}: rezultat final din faza containers = {state}" in p.stdout, (key, p.stdout)
    assert "p/ok: rezultat final" not in p.stdout
    assert p.returncode == 1, p.stdout
