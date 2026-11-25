"""Calea apt (Debian/Ubuntu) a lui `scripts/system-update.sh` și a fișierelor `scripts/lib/system-update-*.sh`:
detectarea gestionarului, refuzul pe o gazdă necunoscută, faza `os` cu dovezile ei de efect, `reboot`,
`verify` și `preflight`. Gazda momeală e `_fake_apt.py` (formele de ieșire măsurate pe n8n.srv1051579.hstgr.cloud,
Ubuntu 24.04, pe 24 nov 2026, doar citire; vezi acolo ce NU reproduce). Calea dnf are testele ei, neschimbate.

Fiecare test numește, în docstring, ce se strică pentru operator dacă codul greșește.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from _fake_apt import NEW_K, OLD_K, RUN_K, FakeAptHost, grub_cfg, sim_text
from _fake_host import FakeHost
from _su_shell import lib_table, posix
from test_system_update_os_verify import _symlinks_work, baseline, healthy_docker, phase, run

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")


def new_apt(tmp: Path) -> FakeAptHost:
    healthy_docker(tmp)
    return FakeAptHost(tmp)


def apt_baseline(fh: FakeHost, manager: str | None = "apt") -> str:
    """Baseline REAL (take_snapshot pe gazda apt sănătoasă) + `pkgmgr.kv`, ca la preflight (record_pkgmgr)."""
    base = baseline(fh)
    if manager:
        (Path(base) / "pkgmgr.kv").write_text(f"manager={manager}\nos_id=ubuntu\nos_id_like=debian\n", encoding="utf-8")
    return base


def calls(fh: FakeHost) -> str:
    p = fh.fh / "calls.log"
    return p.read_text(encoding="utf-8") if p.exists() else ""


def real_upgrades(fh: FakeHost) -> list[str]:
    """Apelurile `apt-get` care SCHIMBĂ pachete (nu `update`, nu `-s`, nu `check`)."""
    return [ln for ln in calls(fh).splitlines() if ln.startswith("apt-get ") and "dist-upgrade" in ln and " -s " not in ln]


# ---------------------------------------------------------------------------
# decizii pure
# ---------------------------------------------------------------------------
def test_package_manager_family_comes_from_os_release_and_never_guesses():
    """Dacă familia se alege greșit, scriptul rulează `dnf` pe un Ubuntu (ori `apt-get` pe un Alma) peste o gazdă de
    producție. Ubuntu/Debian -> apt, Alma/RHEL/Rocky -> dnf; SUSE, Alpine, un ID gol, ori o gazdă care se
    declară în AMBELE familii -> `unknown` (refuz), nu «cel mai apropiat»."""
    t = lib_table([
        ("ubuntu", "su_pkgmgr_family ubuntu debian"),
        ("debian", "su_pkgmgr_family debian ''"),
        ("mint", "su_pkgmgr_family linuxmint 'ubuntu debian'"),
        ("alma", "su_pkgmgr_family almalinux 'rhel centos fedora'"),
        ("rocky", "su_pkgmgr_family rocky 'rhel centos fedora'"),
        ("suse", "su_pkgmgr_family sles 'suse opensuse'"),
        ("alpine", "su_pkgmgr_family alpine ''"),
        ("empty", "su_pkgmgr_family '' ''"),
        ("both", "su_pkgmgr_family weird 'debian rhel'"),
    ])
    assert t == {"ubuntu": "apt", "debian": "apt", "mint": "apt", "alma": "dnf", "rocky": "dnf",
                 "suse": "unknown", "alpine": "unknown", "empty": "unknown", "both": "unknown"}


def test_package_manager_needs_the_binary_not_only_the_family():
    """os-release spune Ubuntu, dar `apt-get` lipsește (imagine trunchiată): a «folosi dnf în loc» ar rula comenzi pe care
    nimeni nu le-a ales. Două surse care nu se potrivesc dau `no-binary` (refuz), niciodată alegerea celeilalte."""
    t = lib_table([
        ("apt_ok", "su_pkgmgr_decide apt 0 1"), ("apt_nobin", "su_pkgmgr_decide apt 1 0"),
        ("dnf_ok", "su_pkgmgr_decide dnf 1 0"), ("dnf_nobin", "su_pkgmgr_decide dnf 0 1"),
        ("unknown", "su_pkgmgr_decide unknown 1 1"),
    ])
    assert t == {"apt_ok": "apt", "apt_nobin": "no-binary", "dnf_ok": "dnf", "dnf_nobin": "no-binary", "unknown": "unknown"}


SIM = (sim_text([("systemd", "255.4-1", "255.5-1"), ("libc6", "2.39-1", "2.39-2")], new=[f"linux-image-{NEW_K}"],
                removes=["old-lib"], kept=["cloud-init", "other-pkg"]))


def test_simulation_is_read_by_its_inst_remv_and_kept_back_lines():
    """Citirea simulării decide DOUĂ lucruri periculoase: dacă upgrade-ul ar șterge pachete (linii `Remv`) și dacă aduce un
    nucleu nou (`Inst linux-image-<versiune>`). Un parser care numără greșit ar lăsa un `dist-upgrade` să șteargă un
    pachet, ori ar raporta «niciun nucleu nou» peste unul care urmează să fie instalat. «kept back» ≠ de actualizat."""
    sample = posix(Path(__file__).with_name("_apt_sim_sample.txt"))
    Path(sample).write_text(SIM, encoding="utf-8", newline="\n")
    t = lib_table([
        ("inst", f"su_apt_sim_names Inst < '{sample}' | tr '\\n' ' '"),
        ("remv", f"su_apt_sim_names Remv < '{sample}' | tr '\\n' ' '"),
        ("kept", f"su_apt_kept_back < '{sample}' | tr '\\n' ' '"),
        ("kernel", f"su_apt_kernel_pending < '{sample}' && echo yes || echo no"),
        ("nokernel", f"su_apt_kernel_pending < <(printf 'Inst systemd [1] (2 x)\\n') && echo yes || echo no"),
    ])
    Path(sample).unlink()
    assert t["inst"] == f"libc6 linux-image-{NEW_K} systemd "
    assert t["remv"] == "old-lib "
    assert t["kept"] == "cloud-init other-pkg "
    assert t["kernel"] == "yes" and t["nokernel"] == "no"


def test_grub_default_is_the_first_toplevel_entry_and_unknown_otherwise():
    """Pe Ubuntu nu există `grubby`: nucleul care pornește se citește din grub.cfg. Prima intrare de nivel superior, NU
    cele din submeniul «Advanced options» (care le listează pe toate, vechi). Dacă GRUB_DEFAULT nu e 0 (saved, un id),
    NU știm ce nucleu pornește, iar scriptul o spune în loc să afirme că «nucleul nou e implicit»."""
    cfg = Path(__file__).with_name("_grub_sample.cfg")
    cfg.write_text(grub_cfg(NEW_K, [RUN_K, OLD_K]), encoding="utf-8", newline="\n")
    nolinux = Path(__file__).with_name("_grub_nolinux.cfg")
    nolinux.write_text("menuentry 'Ubuntu' {\n\trecordfail\n}\nsubmenu 'Advanced' {\n\tmenuentry 'x' {\n\t\tlinux /vmlinuz-1\n\t}\n}\n", encoding="utf-8", newline="\n")
    try:
        t = lib_table([
            ("first", f"su_apt_grub_default_kernel < '{posix(cfg)}'"),
            ("no_linux_in_first", f"su_apt_grub_default_kernel < '{posix(nolinux)}' && echo found || echo none"),
            ("zero", "su_grub_default_is_first 0 && echo yes || echo no"),
            ("quoted0", "su_grub_default_is_first '\"0\"' && echo yes || echo no"),
            ("unset", "su_grub_default_is_first '' && echo yes || echo no"),
            ("saved", "su_grub_default_is_first saved && echo yes || echo no"),
            ("one", "su_grub_default_is_first 1 && echo yes || echo no"),
        ])
    finally:
        cfg.unlink()
        nolinux.unlink()
    assert t["first"] == f"/boot/vmlinuz-{NEW_K}"
    assert t["no_linux_in_first"] == "none"
    assert (t["zero"], t["quoted0"], t["unset"], t["saved"], t["one"]) == ("yes", "yes", "yes", "no", "no")


def test_package_states_flag_everything_dpkg_left_unfinished():
    """`apt-get` poate ieși cu 0 și lăsa un pachet despachetat dar neconfigurat (`iU`, `iF`). Doar `ii`/`hi` sunt
    instalate stabil; `rc` (scos, configurația rămasă) și `un`/`pn` sunt stabile și NU intră în lista de pachete a
    comparației. Dacă `iF` ar fi socotit stabil, o actualizare cu systemd configurat pe jumătate ar ieși «dovedită»."""
    states = "ii |a\nhi |b\nrc |c\nun |d\npn |e\niF |systemd\niU |libc6\nii R|f\nri |g\n"
    p = Path(__file__).with_name("_states_sample.txt")
    p.write_text(states, encoding="utf-8", newline="\n")
    pk = Path(__file__).with_name("_pkgs_sample.txt")
    pk.write_text("ii |a=1\nhi |b=2\nrc |c=3\niF |systemd=4\n", encoding="utf-8", newline="\n")
    try:
        t = lib_table([
            ("unclean", f"su_apt_unclean < '{posix(p)}' | tr '\\n' ' '"),
            ("list", f"su_apt_pkglist < '{posix(pk)}' | tr '\\n' ' '"),
        ])
    finally:
        p.unlink()
        pk.unlink()
    assert t["unclean"] == "iF |systemd iU |libc6 ii R|f ri |g "
    assert t["list"] == "a=1 b=2 "


@pytest.mark.parametrize("exists, hook, expected", [("1", "1", "yes"), ("1", "0", "yes"), ("0", "1", "no"), ("0", "0", "unknown")])
def test_reboot_required_absent_proves_nothing_without_the_hook(exists, hook, expected):
    """`/var/run/reboot-required` PREZENT = reboot necesar. ABSENT dovedește «nu» doar dacă cârligul care l-ar fi scris
    (update-notifier-common) există; pe un Debian de bază absența nu înseamnă nimic. Dacă «lipsă» s-ar citi ca «nu e nevoie»,
    operatorul ar sări peste un reboot al unui nucleu nou fără să afle."""
    assert lib_table([("r", f"su_apt_reboot_state {exists} {hook}")])["r"] == expected


@pytest.mark.parametrize("before, after, last, expected", [
    ("25", "26", "ok", "new-ok"), ("25", "25", "ok", "none"), ("25", "26", "unfinished", "new-unfinished"),
    ("25", "26", "error", "new-error"), ("", "26", "ok", "unknown"), ("25", "", "ok", "unknown"), ("25", "3", "ok", "unknown"),
    ("25", "26", "?", "unknown"),
])
def test_history_log_verdict(before, after, last, expected):
    """history.log e dovada că apt a lucrat: un bloc NOU, încheiat, fără `Error:`. Un jurnal necitibil sau rotit între cele
    două citiri e «necunoscut», nu «niciun bloc nou» (care ar da «no-op dovedit») și nu «bloc nou»."""
    assert lib_table([("r", f"su_apt_history_verdict '{before}' '{after}' '{last}'")])["r"] == expected


# ---------------------------------------------------------------------------
# detectare și refuz
# ---------------------------------------------------------------------------
def test_unknown_distribution_is_refused_before_anything_is_touched(tmp_path):
    """O gazdă SUSE (nici dnf, nici apt) nu are voie să primească comenzi alese «pe aproape»: preflight iese 1 cu un mesaj
    care numește de ce, nu cheamă niciun gestionar de pachete și nu scrie niciun baseline."""
    fh = new_apt(tmp_path)
    fh.w("os-release", 'NAME="SLES"\nID="sles"\nID_LIKE="suse opensuse"\n')
    p = run(fh, "PHASE=preflight; init_state; phase_preflight")
    assert p.returncode == 1, p.stdout + p.stderr
    assert "nu pot stabili gestionarul de pachete" in p.stdout and "ID=sles" in p.stdout
    assert "apt-get" not in calls(fh) and "dpkg" not in calls(fh)
    snaps = tmp_path / "state" / "snapshots"
    assert not snaps.exists() or not any(snaps.iterdir())


@pytest.mark.skipif(shutil.which("dnf") is not None, reason="gazda de test are un dnf real: «lipsă» nu se poate reproduce")
def test_family_without_its_binary_is_refused(tmp_path):
    """os-release spune AlmaLinux, dar pe gazdă nu există `dnf` (doar apt): refuz, nu «folosesc apt că e acolo»."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    before = calls(fh)
    fh.w("os-release", 'ID="almalinux"\nID_LIKE="rhel centos fedora"\n')
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "binarul gestionarului lipsește" in p.stdout, p.stdout
    assert calls(fh) == before, "nicio comandă apt după refuz"


def test_every_phase_that_touches_packages_refuses_an_unknown_distribution(tmp_path):
    """Nu doar preflight: `os`, `reboot` și `verify` pornesc independent, de pe un baseline vechi. Fiecare cere gestionarul
    detectat, ca o gazdă migrată (ori un os-release șters) să nu primească comenzi dnf peste un baseline apt."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("os-release", 'ID="arch"\n')
    for ph, opts in (("os", ""), ("reboot", "OPT_YES=1"), ("verify", "")):
        p = phase(fh, base, ph, opts)
        assert p.returncode == 1 and "nu pot stabili gestionarul de pachete" in p.stdout, (ph, p.stdout)
    assert real_upgrades(fh) == [] and "shutdown" not in calls(fh)


def test_a_baseline_is_judged_only_by_the_manager_that_took_it(tmp_path):
    """Un baseline fără `pkgmgr.kv` (luat înainte de apt) se acceptă DOAR pe dnf; unul luat cu dnf nu se judecă pe o gazdă apt.
    Altfel `verify` ar compara `rpm-qa.txt` cu o listă dpkg (sau ar lipsi) și ar spune «nimic schimbat»."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh, manager=None)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "n-are pkgmgr.kv" in p.stdout, p.stdout
    (Path(base) / "pkgmgr.kv").write_text("manager=dnf\n", encoding="utf-8")
    q = phase(fh, base, "os")
    assert q.returncode == 1 and "a fost luat cu dnf" in q.stdout, q.stdout
    assert real_upgrades(fh) == [] and not (Path(base) / "phases" / "os.started").exists()
    dnf_dir = tmp_path / "d"
    dnf_dir.mkdir()
    healthy_docker(dnf_dir)
    dnf_host = FakeHost(dnf_dir)
    dbase = baseline(dnf_host)
    (Path(dbase) / "pkgmgr.kv").write_text("manager=apt\n", encoding="utf-8")
    r = phase(dnf_host, dbase, "verify")
    assert r.returncode == 1 and "a fost luat cu apt" in r.stdout, r.stdout


def test_snapshot_records_the_manager_and_uses_dpkg_files(tmp_path):
    """Baseline-ul trebuie să conțină exact ce poate fi comparat mai târziu: lista dpkg (nu `rpm-qa.txt`), nucleul INSTALAT
    (nu cele 25 de intrări `deinstall … config-files` ale gazdei), lista în așteptare din simulare și gestionarul în
    `pkgmgr.kv`. Fără ele, `verify` ar număra «pachete schimbate» față de un fișier care nu există."""
    fh = new_apt(tmp_path)
    base = Path(apt_baseline(fh))
    assert (base / "dpkg-list.txt").exists() and not (base / "rpm-qa.txt").exists()
    lst = (base / "dpkg-list.txt").read_text(encoding="utf-8")
    assert "systemd=255.4-1" in lst and "cloud-init=25.1-0ubuntu1" in lst, "un pachet pe hold (`hi`) e instalat"
    assert "linux-image-6.8.0-146-generic" not in lst, "`rc` (config-files) nu e instalat"
    pending = (base / "pending.txt").read_text(encoding="utf-8").split()
    assert pending == sorted([f"linux-image-{NEW_K}", "systemd"]), pending
    kv = (base / "kernel.kv").read_text(encoding="utf-8")
    assert f"default=/boot/vmlinuz-{RUN_K}" in kv and f"newest={RUN_K}" in kv and f"running={RUN_K}" in kv, kv
    r = run(fh, f"init_state; record_pkgmgr '{posix(base)}'")
    assert r.returncode == 0, r.stderr
    assert (base / "pkgmgr.kv").read_text(encoding="utf-8") == "manager=apt\nos_id=ubuntu\nos_id_like=debian\n"


def test_newest_installed_kernel_ignores_removed_kernels_and_other_flavours(tmp_path):
    """Pe gazdă, `dpkg-query 'linux-image-[0-9]*'` listează 25 de nuclee `deinstall … config-files`. Dacă unul scos (mai nou ca
    număr) ar fi socotit «cel mai nou instalat», faza `os` ar raporta un nucleu care nu există, iar reboot-ul ar cere un
    initrd inexistent. Se ia doar ce e instalat, din aceeași variantă (`-generic`) cu nucleul care rulează."""
    fh = new_apt(tmp_path)
    with open(fh.fh / "dpkg-status", "a", encoding="utf-8", newline="\n") as f:
        f.write("rc |linux-image-6.8.0-999-generic|9\nii |linux-image-6.9.0-1-aws|9\nii |linux-image-6.8.0-5-generic|5\n")
    p = run(fh, "init_state; newest_installed_kernel")
    assert p.returncode == 0 and p.stdout.strip() == RUN_K, (p.stdout, p.stderr)


# ---------------------------------------------------------------------------
# os
# ---------------------------------------------------------------------------
def test_os_proves_an_apt_upgrade_by_its_effects(tmp_path):
    """Succesul `os` pe apt nu e codul 0 al lui apt-get: e un bloc nou și încheiat în history.log, pachete schimbate în baza
    dpkg față de baseline, nimic rămas de instalat în simulare, `dpkg --audit` curat, nicio stare nestabilă, `apt-get check`
    curat, nucleul nou INSTALAT, implicit în grub.cfg și cu vmlinuz + initrd pe disc, hold-ul neatins. Comanda e exact cea
    gândită: listele reîmprospătate ÎNAINTE de simulare, `--no-remove`, fișierele de configurare păstrate, frontend neinteractiv,
    needrestart doar în modul listă, blocarea dpkg așteptată."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    for fragment in ("history.log: tranzacție nouă, încheiată", "pachete diferă față de baseline în baza dpkg",
                     "apt-get -s dist-upgrade: nu a rămas nimic de instalat", "dpkg --audit: niciun pachet",
                     "toate pachetele sunt într-o stare stabilă", "apt-get check: nicio dependență ruptă",
                     f"nucleu nou instalat: {RUN_K} -> {NEW_K}", "nucleul nou e cel implicit la pornire (grub)",
                     f"vmlinuz și initrd.img-{NEW_K}", "pachetele pe hold au rămas neatinse", "cloud-init=25.1-0ubuntu1"):
        assert fragment in p.stdout, (fragment, p.stdout)
    assert (Path(base) / "phases" / "os.ok").exists() and (Path(base) / "phases" / "os.started").exists()
    log = calls(fh)
    u = log.index("apt-get update")      # simularea din baseline e DINAINTE de `update`: ordinea se judecă de la update încolo
    assert u < log.index("apt-get -s dist-upgrade", u) < log.index("apt-get -y")
    up = real_upgrades(fh)
    assert len(up) == 1 and up[0] == ("apt-get -y --no-remove -o DPkg::Lock::Timeout=77 -o Dpkg::Options::=--force-confdef "
                                      "-o Dpkg::Options::=--force-confold dist-upgrade"), up
    assert "env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l" in log
    for forbidden in ("apt-mark unhold", "apt-mark hold", "allow-change-held", "allow-downgrades", "autoremove", "apt-get upgrade", "apt-get -y upgrade"):
        assert forbidden not in log, forbidden


def test_os_rerun_after_success_is_a_proven_noop(tmp_path):
    """A doua rulare, când nu mai e nimic de instalat: apt iese cu 0, history.log n-are bloc nou, iar asta e «no-op dovedit»,
    nu un eșec. Fără ramura asta, operatorul care repetă faza ar vedea roșu peste o gazdă la zi."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    assert phase(fh, base, "os").returncode == 0
    fh.w("apt-mode", "noop")
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "no-op dovedit" in p.stdout


def test_os_does_not_believe_a_zero_exit_that_changed_nothing(tmp_path):
    """`apt-get` iese cu 0 și nu face nimic (operație nulă: alt proces a ținut blocarea și a plecat, un depozit pinuit): simularea
    avea pachete, dar history.log n-are niciun bloc nou și baza dpkg e neschimbată. Operatorul ar fi crezut sistemul la zi; faza
    e roșie și nu scrie os.ok."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", "noop")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1, p.stdout
    assert "history.log n-are niciun bloc nou" in p.stdout and "baza dpkg n-are niciun pachet schimbat" in p.stdout
    assert "au rămas 2 pachete de actualizat" in p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


@pytest.mark.parametrize("mode, fragments", [
    ("half0", ["apt-get a ieșit cu 0", "dpkg --audit raportează pachete neterminate", "stare nestabilă", "systemd"]),
    ("half", ["apt-get dist-upgrade a ieșit cu 100", "ultimul bloc conține o linie Error:", "dpkg --audit raportează"]),
])
def test_half_configured_dpkg_is_red_even_when_apt_exits_zero(tmp_path, mode, fragments):
    """Exact tiparul «intenție în loc de efect»: apt-get iese cu 0, dar dpkg a lăsat `systemd` despachetat și neconfigurat. Un
    upgrade «reușit» cu systemd la jumătate nu mai pornește după reboot. `dpkg --audit`, starea pachetelor din baza dpkg și
    history.log sunt observatori independenți de codul de ieșire; faza e roșie, fără os.ok."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", mode)
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1, p.stdout
    for fragment in fragments:
        assert fragment in p.stdout, (fragment, p.stdout)
    assert not (Path(base) / "phases" / "os.ok").exists()


def test_os_refuses_a_dist_upgrade_that_would_remove_packages(tmp_path):
    """`dist-upgrade` (necesar pentru nucleul nou) poate ȘTERGE pachete ca să rezolve conflicte. O linie `Remv` în simulare
    oprește faza ÎNAINTE de orice schimbare: nu se marchează `os.started`, nu se rulează upgrade-ul, operatorul decide."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.set_sim([("systemd", "255.4-1", "255.5-1")], removes=["important-lib"])
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "ar ȘTERGE pachete: important-lib" in p.stdout, p.stdout
    assert real_upgrades(fh) == [] and not (Path(base) / "phases" / "os.started").exists()


def test_os_refuses_when_the_simulation_cannot_be_read(tmp_path):
    """Dacă `apt-get -s dist-upgrade` pică, nu știm dacă upgrade-ul șterge ceva. «Nu știu» nu e «nimic de șters»: refuz înainte de
    orice schimbare."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("sim-rc", "100")
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "nu știu ce ar face upgrade-ul" in p.stdout, p.stdout
    assert real_upgrades(fh) == [] and not (Path(base) / "phases" / "os.started").exists()


def test_os_does_not_upgrade_on_partial_package_lists(tmp_path):
    """Un depozit căzut face `apt-get update` să iasă cu 0 și să tipărească doar `Err:`/«W: Failed to fetch». Un upgrade pe liste
    parțiale ar ține pachetele din acel depozit la versiunea veche și ar raporta succes. Ieșirea se citește, nu doar codul."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("apt-update-mode", "err")
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "nu rulez upgrade-ul pe liste parțiale" in p.stdout and "Err:3" in p.stdout, p.stdout
    assert real_upgrades(fh) == [] and not (Path(base) / "phases" / "os.started").exists()


def test_os_waits_for_the_dpkg_lock_and_retries_update_on_the_lists_lock(tmp_path):
    """`unattended-upgrades` pornește zilnic (apt-daily-upgrade.timer, ore aleatorii) și ține blocările apt. Două mecanisme DIFERITE, ca în apt 2.8.4:
    `dist-upgrade` primește `-o DPkg::Lock::Timeout` (blocarea dpkg se așteaptă), iar `apt-get update` ia blocarea listelor FĂRĂ timeout și iese imediat —
    de aceea scriptul îl REÎNCEARCĂ, mărginit, doar pe eroarea de blocare a listelor. Momeala reproduce ambele: fără opțiune dist-upgrade iese 100, iar
    update iese 100 oricâte opțiuni ar avea cât lista e ținută."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("lock-held-n", "1")
    fh.w("lists-lock-n", "2")
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    log = calls(fh)
    updates = [ln for ln in log.splitlines() if ln.startswith("apt-get update")]
    assert len(updates) == 3, updates                      # două respinse de blocarea listelor, a treia trece
    assert all("DPkg::Lock::Timeout" not in ln for ln in updates), "opțiunea nu se aplică blocării listelor: nu pretindem că ar aștepta"
    assert "waited-for-lock dist-upgrade" in log


def test_os_gives_up_on_the_lists_lock_after_the_bounded_retries(tmp_path):
    """Dacă blocarea listelor nu se eliberează în SU_APT_LOCK_TIMEOUT_S, faza refuză curat (roșu, nimic schimbat): nu așteaptă la nesfârșit și nu
    rulează upgrade-ul pe liste vechi."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("lists-lock-n", "999")
    p = phase(fh, base, "os", SU_APT_LOCK_TIMEOUT_S="3")
    assert p.returncode == 1 and "Could not get lock /var/lib/apt/lists/lock" in p.stdout, p.stdout
    assert len([ln for ln in calls(fh).splitlines() if ln.startswith("apt-get update")]) == 4     # prima + 3 reîncercări
    assert real_upgrades(fh) == [] and not (Path(base) / "phases" / "os.started").exists()


def test_a_failed_update_that_is_not_a_lock_error_is_not_retried(tmp_path):
    """Un depozit căzut nu se vindecă prin reîncercare în buclă: reîncercarea e DOAR pentru eroarea de blocare a listelor. Un update care iese 100 din alt
    motiv se raportează o singură dată."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("apt-update-mode", "hard-fail")
    p = phase(fh, base, "os")
    assert p.returncode == 1, p.stdout
    assert len([ln for ln in calls(fh).splitlines() if ln.startswith("apt-get update")]) == 1


def idle_check(fh, **env):
    return run(fh, "init_state; pf_check_apt_idle; echo FAIL_N=$FAIL_N", SU_APT_IDLE_WAIT_S="2", **env)


def test_idle_check_ignores_the_permanent_shutdown_helper_and_an_idle_packagekit(tmp_path):
    """PROVAT pe gazdă: `unattended-upgrade-shutdown --wait-for-signal` (pid 829) rulează de 37 de zile fără nicio blocare, iar packagekitd rămâne ~5 min după
    fiecare `apt-get update` fără blocări. O verificare pe NUME de proces le socotea «apt rulează»: preflight, os și reboot așteptau 300 s și ieșeau 1 de fiecare
    dată, cu vina pusă pe unattended-upgrades. Gazda momeală are exact acele linii de proces (`procs`): idle înseamnă că nicio blocare nu e ținută."""
    fh = new_apt(tmp_path)
    assert "unattended-upgr" in fh.r("procs") and "packagekitd" in fh.r("procs")
    p = idle_check(fh)
    assert p.returncode == 0 and "FAIL_N=0" in p.stdout and "nicio tranzacție apt/dpkg nu rulează" in p.stdout, p.stdout + p.stderr


def test_idle_check_is_busy_while_the_dpkg_lock_is_held_and_names_the_holder(tmp_path):
    """Un `apt-get` real care ține blocarea dpkg-frontend (lslocks o arată): faza așteaptă mărginit și apoi refuză, cu numele și pid-ul celui care o ține,
    nu cu o presupunere despre unattended-upgrades."""
    fh = new_apt(tmp_path)
    fh.w("lock-busy-n", "999")
    p = idle_check(fh)
    assert "FAIL_N=1" in p.stdout and "apt-get (pid 4242) ține /var/lib/dpkg/lock-frontend" in p.stdout, p.stdout + p.stderr


def test_idle_check_is_busy_while_an_apt_daily_unit_is_running(tmp_path):
    """Între două blocări (descărcare, pauză între pachete) unitatea apt-daily-upgrade.service încă lucrează: `activating` înseamnă ocupat, chiar dacă
    nicio blocare nu e ținută în clipa citirii."""
    fh = new_apt(tmp_path)
    fh.units["apt-daily-upgrade.service"] = {"state": "activating", "enabled": "static", "restarts": 0, "enter": 0}
    fh.save_units()
    p = idle_check(fh)
    assert "FAIL_N=1" in p.stdout and "unitatea apt-daily-upgrade.service e activating" in p.stdout, p.stdout + p.stderr


def test_idle_check_does_not_read_an_unreadable_lock_table_as_idle(tmp_path):
    """Dacă `lslocks` iese cu eroare, NU știm că nimeni nu ține blocarea: roșu «nu pot afla», nu «liber»."""
    fh = new_apt(tmp_path)
    fh.w("lslocks-rc", "1")
    p = idle_check(fh)
    assert "FAIL_N=1" in p.stdout and "nu pot afla dacă o tranzacție apt/dpkg rulează" in p.stdout, p.stdout + p.stderr


def test_os_waits_for_a_running_apt_and_refuses_when_it_never_ends(tmp_path):
    """Un `unattended-upgrade` care încă lucrează: faza așteaptă (mărginit) să se termine și apoi merge; dacă nu se termină în
    timp, refuză FĂRĂ să atingă nimic. Nu pornește a doua tranzacție peste prima, nici nu așteaptă la nesfârșit."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("lock-busy-n", "3")
    p = phase(fh, base, "os")
    assert p.returncode == 0 and "apt/dpkg s-au liniștit după 3s" in p.stdout, p.stdout
    b_dir = tmp_path / "b"
    b_dir.mkdir()
    fh2 = new_apt(b_dir)
    base2 = apt_baseline(fh2)
    fh2.w("lock-busy-n", "999")
    before2 = calls(fh2)
    q = phase(fh2, base2, "os", SU_APT_IDLE_WAIT_S="3")
    assert q.returncode == 1 and "apt/dpkg rulează încă după 3s" in q.stdout, q.stdout
    assert calls(fh2) == before2 and not (Path(base2) / "phases" / "os.started").exists()


def test_held_packages_are_left_untouched_and_a_change_is_red(tmp_path):
    """`cloud-init` e pe hold pe gazdă (decizia operatorului). `apt-get` nu are voie să-l schimbe, iar scriptul nu are voie să
    deblocheze nimic. Faza dovedește că lista și versiunile pachetelor ținute sunt aceleași după; dacă un upgrade îl atinge,
    e roșu — nu «upgrade reușit»."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", "touch-hold")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "pachetele pe hold s-au schimbat" in p.stdout and "cloud-init=25.2-0ubuntu1" in p.stdout, p.stdout
    assert "apt-mark unhold" not in calls(fh)


def test_new_kernel_that_is_not_the_boot_default_is_red(tmp_path):
    """Nucleul nou e instalat, dar `update-grub` n-a rulat: grub.cfg arată tot nucleul vechi. Un reboot ar porni nucleul vechi,
    iar operatorul ar crede că a trecut la cel nou. Implicitul se citește din grub.cfg, nu se presupune din «dpkg a zis»."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", "no-grub")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and f"NU e cel implicit la pornire (grub spune /boot/vmlinuz-{RUN_K})" in p.stdout, p.stdout


def test_new_kernel_without_its_initrd_is_red(tmp_path):
    """Un nucleu «instalat» al cărui `initrd.img-<versiune>` lipsește nu pornește (pe un VPS: doar consola providerului).
    Fișierul NUMIT în stilul Debian (nu `initramfs-….img`) trebuie să existe, de mărime credibilă."""
    fh = new_apt(tmp_path)
    (fh.fh / "no-initrd").write_text("x", encoding="utf-8")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and f"initrd.img-{NEW_K} lipsește" in p.stdout, p.stdout


def test_default_kernel_that_cannot_be_determined_is_unknown_not_fine(tmp_path):
    """Cu `GRUB_DEFAULT=saved` (sau un id) prima intrare din grub.cfg nu e nucleul care pornește. Scriptul NU știe, și o spune
    (ieșire 3, fără os.ok) — nu declară «nucleul nou e implicit»."""
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    fh.w("default-grub", "GRUB_DEFAULT=saved\n")
    p = phase(fh, base, "os")
    assert p.returncode == 3, p.stdout
    assert "GRUB_DEFAULT=saved" in p.stdout or "nu pot citi nucleul implicit" in p.stdout
    assert "nucleul nou e cel implicit" not in p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------
def reboot_ready(tmp_path) -> tuple[FakeAptHost, str]:
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    (Path(base) / "phases").mkdir(exist_ok=True)
    (Path(base) / "phases" / "os.ok").write_text("x", encoding="utf-8")
    return fh, base


def test_reboot_is_scheduled_when_reboot_required_exists(tmp_path):
    """Pe apt nu există `needs-restarting`: nevoia de reboot e fișierul /var/run/reboot-required (cu pachetele în .pkgs).
    Prezent -> reboot programat, dovedit de fișierul scris de systemd, nu de codul lui shutdown."""
    fh, base = reboot_ready(tmp_path)
    fh.w("reboot-required", "*** System restart required ***\n")
    fh.w("reboot-required.pkgs", "linux-image-6.8.0-149-generic\nlibc6\n")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "PROGRAMATĂ" in p.stdout and "/var/run/reboot-required cere reboot" in p.stdout
    assert "shutdown -r +1" in calls(fh)


def test_reboot_is_skipped_when_the_hook_proves_nothing_is_pending(tmp_path):
    """Fișier absent ȘI cârligul update-notifier-common prezent = «nu e nevoie» dovedit; nucleul care rulează e cel implicit.
    shutdown nu se cheamă."""
    fh, base = reboot_ready(tmp_path)
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0 and "nu e nevoie de reboot" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)


def test_reboot_refuses_to_guess_when_absence_of_the_file_proves_nothing(tmp_path):
    """Debian de bază n-are cârligul care scrie /var/run/reboot-required: fișierul lipsește ORICE ar fi. A citi asta ca «nu e
    nevoie» ar lăsa un nucleu nou neactivat. Refuz, nu ghicesc (--force e ieșirea explicită)."""
    fh, base = reboot_ready(tmp_path)
    (fh.fh / "notify-hook").unlink()
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "nu pot afla dacă e nevoie de reboot" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)


def test_reboot_refuses_a_default_kernel_whose_initrd_is_missing(tmp_path):
    """Nucleul implicit (grub.cfg) fără `initrd.img-<versiune>` nu pornește: reboot-ul nu se programează."""
    fh, base = reboot_ready(tmp_path)
    fh.w("reboot-required", "x\n")
    fh.w("grub.cfg", grub_cfg(NEW_K, [RUN_K]))
    (fh.fh / "boot" / f"vmlinuz-{NEW_K}").write_text("k" * 2000, encoding="utf-8")
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 1 and "NU poate porni" in p.stdout and f"initrd.img-{NEW_K} lipsește" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
def after_os_and_reboot(tmp_path) -> tuple[FakeAptHost, str]:
    fh = new_apt(tmp_path)
    base = apt_baseline(fh)
    assert phase(fh, base, "os").returncode == 0
    (Path(base) / "phases" / "reboot.requested").write_text("boot_id=boot-A\n", encoding="utf-8")
    return fh, base


def test_verify_after_an_apt_update_and_reboot_is_green_and_lists_the_changes(tmp_path):
    """Calea completă pe apt: os încheiat, reboot efectuat (boot_id schimbat, reboot-required dispărut), nucleul nou rulează și e
    cel implicit. Verde, cu ce s-a schimbat scris — compararea pachetelor se face față de `dpkg-list.txt`."""
    fh, base = after_os_and_reboot(tmp_path)
    for f in ("reboot-required", "reboot-required.pkgs"):
        (fh.fh / f).unlink()
    fh.w("uname", NEW_K + "\n")
    fh.w("boot_id", "boot-B\n")
    p = phase(fh, base, "verify")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "gazda s-a repornit" in p.stdout and f"nucleu: {RUN_K} -> {NEW_K}" in p.stdout
    assert "pachete instalate sau actualizate față de baseline" in p.stdout


def test_verify_is_red_while_reboot_required_still_exists(tmp_path):
    """După «repornire», /var/run/reboot-required încă există: actualizarea nu e activă (reboot anulat, ori altă actualizare a cerut
    unul nou). Verify nu are voie să iasă verde."""
    fh, base = after_os_and_reboot(tmp_path)
    fh.w("uname", NEW_K + "\n")
    fh.w("boot_id", "boot-B\n")
    p = phase(fh, base, "verify")
    assert p.returncode == 1 and "/var/run/reboot-required cere încă un reboot" in p.stdout, p.stdout


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def _busy(fh):
    fh.w("lock-busy-n", "999")


@pytest.mark.parametrize("what, setup, fragment", [
    ("apt_running", _busy, "apt/dpkg rulează încă după"),
    ("reboot_pending", lambda fh: fh.w("reboot-required", "x\n"), "un reboot e DEJA necesar"),
    ("reboot_unknown", lambda fh: (fh.fh / "notify-hook").unlink(), "nu pot afla dacă un reboot e în așteptare"),
    ("kernel_mismatch", lambda fh: fh.w("grub.cfg", grub_cfg(NEW_K, [RUN_K])), "NU e cel implicit la pornire"),
    ("default_unknown", lambda fh: fh.w("default-grub", "GRUB_DEFAULT=saved\n"), "nu pot citi nucleul implicit"),
    ("repo_down", lambda fh: fh.w("apt-update-mode", "err"), "apt-get update a eșuat sau a raportat depozite căzute"),
])
def test_apt_preflight_refuses_and_records_no_baseline(tmp_path, what, setup, fragment):
    """Aceeași regulă ca pe dnf, cu faptele apt: un apt/unattended-upgrades care nu se termină, un reboot deja necesar (exact starea
    n8n.srv1051579.hstgr.cloud azi: reboot-required din 14 nov), un nucleu implicit diferit de cel care rulează, un GRUB_DEFAULT pe
    care nu-l putem citi, un depozit căzut (ieșire 0 cu `Err:`). Cât timp există un motiv de refuz NU se înregistrează baseline."""
    fh = new_apt(tmp_path)
    setup(fh)
    p = run(fh, "PHASE=preflight; init_state; phase_preflight", SU_APT_IDLE_WAIT_S="2")
    assert p.returncode == 1, p.stdout + p.stderr
    assert fragment in p.stdout, p.stdout
    assert "nu înregistrez baseline-ul" in p.stdout
    snaps = tmp_path / "state" / "snapshots"
    assert not snaps.exists() or not any(snaps.iterdir())


def test_apt_preflight_publishes_a_baseline_that_records_the_manager(tmp_path):
    """Preflight curat pe apt publică baseline-ul cu `pkgmgr.kv` (apt, ubuntu) și fișierele dpkg. Fără el, os/verify n-ar putea
    refuza un baseline luat cu alt gestionar."""
    if not _symlinks_work(tmp_path):
        pytest.skip("simboluri reale indisponibile în acest bash: publicarea atomică a baseline-ului nu se poate proba aici")
    fh = new_apt(tmp_path)
    p = run(fh, "PHASE=preflight; init_state; phase_preflight")
    assert p.returncode == 0, p.stdout + p.stderr
    cur = tmp_path / "state" / "current"
    assert (cur / "pkgmgr.kv").read_text(encoding="utf-8").startswith("manager=apt\n")
    assert (cur / "dpkg-list.txt").exists()


# ---------------------------------------------------------------------------
# history.log și hold-uri: teste care aveau mutanți nedetectați
# ---------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("lslocks") is not None, reason="gazda de test are un lslocks real: «lipsă» nu se poate reproduce")
def test_idle_check_without_lslocks_is_unknown_not_idle(tmp_path):
    """Fără `lslocks` (util-linux, prezent pe orice Debian/Ubuntu) scriptul nu poate citi blocările. «Nu pot citi» nu e «nimeni nu ține blocarea»: roșu,
    cu motivul, nu o pornire peste o tranzacție care poate rula."""
    from _su_shell import host_run
    fh = new_apt(tmp_path)
    bindir, env = fh.install()
    (bindir / "lslocks").unlink()
    env["SU_APT_IDLE_WAIT_S"] = "2"
    p = host_run(tmp_path, "init_state; pf_check_apt_idle; echo FAIL_N=$FAIL_N", bindir, **env)
    assert "FAIL_N=1" in p.stdout and "lslocks (util-linux) lipsește" in p.stdout, p.stdout + p.stderr


def test_history_last_block_state_is_read_from_the_file(tmp_path):
    """Starea ULTIMULUI bloc din history.log: `ok` doar cu End-Date și fără Error:. Un bloc fără End-Date înseamnă că apt a murit după ce a început; dacă
    funcția ar tipări `ok` pentru el, o tranzacție întreruptă ar trece drept dovedită."""
    fh = new_apt(tmp_path)
    cases = {
        "ok": FakeAptHost.block("Upgrade: a:amd64 (1, 2)"),
        "unfinished": FakeAptHost.block("Upgrade: a:amd64 (1, 2)", ended=False),
        "error": FakeAptHost.block("Upgrade: a:amd64 (1, 2)", error="Sub-process /usr/bin/dpkg returned an error code (1)"),
        "?": "",
    }
    # un bloc VECHI încheiat urmat de unul întrerupt: contează ultimul
    cases["unfinished-after-ok"] = FakeAptHost.block("Upgrade: x (1, 2)") + FakeAptHost.block("Upgrade: b (1, 2)", ended=False)
    for want, text in cases.items():
        fh.w("history.log", text)
        p = run(fh, "init_state; apt_history_last_state")
        assert p.returncode == 0, p.stderr
        assert p.stdout.strip() == want.split("-")[0], (want, p.stdout)


def test_os_is_red_when_the_history_block_has_no_end_date(tmp_path):
    """apt-get iese cu 0, dar blocul din history.log n-are End-Date (procesul a murit în mijlocul tranzacției, iar un wrapper a ascuns codul): nu e o
    tranzacție dovedită. Faza e roșie, fără os.ok."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", "unfinished")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "n-are End-Date" in p.stdout, p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


def test_a_hold_removed_during_the_upgrade_is_red(tmp_path):
    """Upgrade-ul (sau un script postinst) a ȘTERS hold-ul lui cloud-init: `apt-mark showhold` e acum gol. O comparație care acceptă o listă goală «după» ar
    spune «niciun pachet pe hold» peste o decizie a operatorului pe care tocmai a anulat-o cineva. Lista de dinainte trebuie să fie IDENTICĂ."""
    fh = new_apt(tmp_path)
    fh.w("apt-mode", "unhold")
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 1 and "pachetele pe hold s-au schimbat" in p.stdout and "cloud-init=25.1-0ubuntu1" in p.stdout, p.stdout
    assert not (Path(base) / "phases" / "os.ok").exists()


def test_either_reboot_hook_proves_that_a_missing_file_means_no(tmp_path):
    """Pe Debian de bază nu există update-notifier-common, dar pachetul unattended-upgrades pune /etc/kernel/postinst.d/unattended-upgrades, care scrie același
    fișier. Absența fișierului dovedește «nu e nevoie» cu ORICARE dintre cârlige; fără niciunul rămâne «necunoscut» (testul de refuz de mai sus)."""
    fh, base = reboot_ready(tmp_path)
    (fh.fh / "notify-hook").unlink()
    fh.put_ua_hook()
    p = phase(fh, base, "reboot", "OPT_YES=1")
    assert p.returncode == 0 and "nu e nevoie de reboot" in p.stdout, p.stdout
    assert "shutdown" not in calls(fh)


# ---------------------------------------------------------------------------
# Lacune închise după runda 2 (cinci mutanți aplicați împreună au trecut verzi)
# ---------------------------------------------------------------------------
APT_LOCK_PATHS = ["/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"]


@pytest.mark.parametrize("path", APT_LOCK_PATHS)
def test_idle_check_is_busy_on_each_of_the_four_apt_locks(tmp_path, path):
    """apt și dpkg iau blocări DIFERITE în faze diferite: `apt-get update` ține /var/lib/apt/lists/lock, descărcarea ține /var/cache/apt/archives/lock, dpkg ține
    lock-frontend și lock. Dacă scriptul ar citi doar una, o actualizare pornită în mijlocul unui `apt-get update` (sau al unei descărcări) ar trece drept «liber»
    și s-ar bate cu el. Fiecare dintre cele patru, ținută singură, înseamnă ocupat."""
    fh = new_apt(tmp_path)
    fh.w("lock-busy-paths", path + "\n")
    fh.w("lock-busy-n", "999")
    p = idle_check(fh)
    assert "FAIL_N=1" in p.stdout and f"ține {path}" in p.stdout, p.stdout + p.stderr


@pytest.mark.parametrize("unit", ["apt-daily.service", "apt-daily-upgrade.service"])
def test_idle_check_is_busy_while_either_apt_daily_unit_is_activating(tmp_path, unit):
    """`apt-daily.service` (apt-get update planificat) și `apt-daily-upgrade.service` (unattended-upgrade) pornesc ambele tranzacții apt, cu pauze între blocări.
    Ținute în `activating`, ocupat înseamnă ocupat pentru AMBELE; un set de unități din care lipsește una ar lăsa o fereastră în care scriptul pornește peste ea."""
    fh = new_apt(tmp_path)
    fh.units[unit] = {"state": "activating", "enabled": "static", "restarts": 0, "enter": 0}
    fh.save_units()
    p = idle_check(fh)
    assert "FAIL_N=1" in p.stdout and f"unitatea {unit} e activating" in p.stdout, p.stdout + p.stderr


def test_an_old_error_block_does_not_poison_a_later_clean_block(tmp_path):
    """history.log păstrează luni de blocuri. Un bloc VECHI cu `Error:` (o actualizare de acum o lună care a picat) urmat de blocuri curate NU înseamnă că
    ultima tranzacție a eșuat: starea e a ULTIMULUI bloc. Dacă steagul de eroare nu se resetează la fiecare `Start-Date`, fiecare `os` de după un singur
    eșec vechi ar ieși roșu «history.log: ultimul bloc conține Error:», pe totdeauna, peste o actualizare perfectă."""
    fh = new_apt(tmp_path)
    old_then_clean = (FakeAptHost.block("Upgrade: a:amd64 (1, 2)", error="Sub-process /usr/bin/dpkg returned an error code (1)")
                      + FakeAptHost.block("Upgrade: b:amd64 (1, 2)"))
    fh.w("history.log", old_then_clean)
    p = run(fh, "init_state; apt_history_last_state")
    assert p.returncode == 0 and p.stdout.strip() == "ok", (p.stdout, p.stderr)


def test_os_goes_green_over_a_history_that_starts_with_an_old_error_block(tmp_path):
    """Același tipar, cap-coadă: istoricul gazdei are un bloc vechi cu eroare, apoi unul curat; `os` adaugă un bloc nou, încheiat. Rezultatul trebuie să fie
    verde (și os.ok scris), nu roșu din cauza unei erori din urmă cu o lună."""
    fh = new_apt(tmp_path)
    fh.w("history.log", FakeAptHost.block("Upgrade: a:amd64 (1, 2)", error="Sub-process /usr/bin/dpkg returned an error code (1)")
         + FakeAptHost.block("Upgrade: b:amd64 (1, 2)"))
    base = apt_baseline(fh)
    p = phase(fh, base, "os")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "history.log: tranzacție nouă, încheiată" in p.stdout
    assert (Path(base) / "phases" / "os.ok").exists()


def test_the_baseline_directory_written_by_preflight_records_the_manager(tmp_path):
    """Fără `pkgmgr.kv` în baseline, `os`/`reboot`/`verify` nu pot refuza un baseline luat cu alt gestionar, iar un baseline apt fără el e refuzat ca «vechi».
    Testul de publicare prin `current` se sare fără simboluri reale; acesta citește DIRECTORUL de snapshot pe care îl scrie preflight (snapshots/<ora>/), deci
    rulează oriunde. Cât de departe ajunge publicarea (ln/mv -T) nu contează: fișierul se scrie ÎNAINTE de orice măsurătoare."""
    fh = new_apt(tmp_path)
    p = run(fh, "PHASE=preflight; init_state; phase_preflight")
    snaps = [d for d in (tmp_path / "state" / "snapshots").iterdir() if d.is_dir()]
    assert snaps, (p.returncode, p.stdout, p.stderr)
    kv = [d / "pkgmgr.kv" for d in snaps if (d / "pkgmgr.kv").exists()]
    assert len(kv) == 1, (snaps, p.stdout, p.stderr)
    assert kv[0].read_text(encoding="utf-8") == "manager=apt\nos_id=ubuntu\nos_id_like=debian\n"
    assert (kv[0].parent / "dpkg-list.txt").exists(), "fișierele dpkg ale aceluiași snapshot"


def test_every_apt_get_update_asks_for_error_mode_any(tmp_path):
    """Un depozit căzut face `apt-get update` să iasă cu 0 în modul implicit, iar scriptul nu l-ar vedea decât din text. `-o APT::Update::Error-Mode=any` cere
    apt-ului însuși să iasă nenul la ORICE eroare: a doua plasă, independentă de grep. Comanda ÎNREGISTRATĂ trebuie să o poarte, atât din preflight, cât și din os."""
    fh = new_apt(tmp_path)
    run(fh, "init_state; pf_check_repos")
    updates = [ln for ln in calls(fh).splitlines() if ln.startswith("apt-get update")]
    assert len(updates) == 1 and "-o APT::Update::Error-Mode=any" in updates[0], updates
    fh2_dir = tmp_path / "os"
    fh2_dir.mkdir()
    fh2 = new_apt(fh2_dir)
    base = apt_baseline(fh2)
    assert phase(fh2, base, "os").returncode == 0
    updates2 = [ln for ln in calls(fh2).splitlines() if ln.startswith("apt-get update")]
    assert len(updates2) == 1 and "-o APT::Update::Error-Mode=any" in updates2[0], updates2
