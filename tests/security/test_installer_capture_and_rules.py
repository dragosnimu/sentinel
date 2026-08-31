"""Trei pași care raportau succes fără să se uite la rezultat, măsurați pe un
Ubuntu 24.04.4 real (10.30.1.134, suricata 7.0.3, nginx 1.24, auditd 3.1.2).

Ce s-a văzut pe mașină, în ordinea în care s-a văzut:

  * **pasul 35** scria `/etc/default/suricata` la fiecare deploy, iar
    `systemctl show suricata -p EnvironmentFiles` nu tipărea NIMIC: unitatea
    Debian nu citește fișierul acela. Demonul pornea cu `--af-packet` gol, deci
    lua interfața din `suricata.yaml` — `eth0`, pe o gazdă a cărei placă e
    `enp0s3` — pica la deschiderea socketului, systemd îl repornea la fiecare
    2m20s, iar `eve.json`, `fast.log` și `stats.log` stăteau toate la 0 OCTEȚI.
    Pasul tipărea `[+] Suricata running (IDS on enp0s3, MemoryMax=1G)`;
  * **pasul 33** căuta `listen 80;` în `/etc/nginx/nginx.conf`, unde pe Ubuntu
    nu există niciun `listen` activ (doar exemple comentate la liniile 73 și
    79). Ascultătorul real e în `sites-enabled/default` și scrie
    `listen 80 default_server;`, pe care tiparul nu-l prinde nici el. `sed`
    ieșea cu 0 fără să schimbe nimic, iar pasul anunța „:80 listener commented
    out";
  * **pasul 37** tipărea `[!] augenrules failed: …` și, două rânduri mai jos,
    `[+] auditd rules installed and confirmed loaded`. Verificarea era pe CHEIE:
    `-a never,exit -F dir=/var/lib/docker` e respinsă pe o gazdă fără docker,
    `auditctl -R` se oprește acolo, și cele două reguli de suprimare de după ea
    nu se încarcă — invizibil, fiindcă regulile de suprimare n-au cheie deloc.
    Măsurat: 27 din 30 de reguli în nucleu, raportate ca „confirmed loaded".

Fiecare test de mai jos rulează funcția LIVRATĂ din `deploy/install.sh` sau din
`deploy/lib/distro.sh`, cu unelte-momeală pe PATH, și se uită la ce a ieșit.
Aserțiunile pe familia `rhel` compară cu constanta istorică — exact ce se scria
înainte de schimbare — fiindcă producția rulează AlmaLinux.
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
DISTRO_SH = REPO / "deploy" / "lib" / "distro.sh"
INSTALL_SH = REPO / "deploy" / "install.sh"
DISTRO = DISTRO_SH.read_text(encoding="utf-8")
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")

_NO_BASH = (
    "bash lipsește din PATH, deci funcțiile livrate NU au fost rulate. "
    "Asta e „neverificat”, nu „în regulă”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]


# ---------------------------------------------------------------------------
# Unelte pentru rulat shell-ul livrat
# ---------------------------------------------------------------------------
def _func(source: str, name: str) -> str:
    """Funcția așa cum se livrează, nu o copie a ei."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> Path:
    """O comandă-momeală, executabilă, prima pe PATH."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _p(path: Path) -> str:
    """Cale pe care o înțelege bash-ul, și pe Windows."""
    return str(path).replace("\\", "/")


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


def _distro_call(tmp_path: Path, family: str, call: str,
                 extra_path: Path | None = None) -> subprocess.CompletedProcess:
    return _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        f"{call}\n",
        tmp_path, extra_path=extra_path)


# ===========================================================================
# B2 — Suricata: setările trebuie să ajungă în procesul care rulează
# ===========================================================================
def _suricata_harness(
        tmp_path: Path, *, family: str = "debian", argv: str | None,
        host_ifaces: tuple[str, ...] = ("lo", "enp0s3"),
        dump_home_net: str | None = "[10.30.1.134]",
        eve_bytes: int = 0, eve_grows: bool = False,
        want_iface: str = "enp0s3", want_ip: str = "10.30.1.134",
        bpf_file: str = "") -> subprocess.CompletedProcess:
    """Rulează `suricata_report_effect` LIVRATĂ peste un proces inventat.

    `argv` e ce va găsi funcția în cmdline-ul procesului urmărit de systemd;
    `None` înseamnă „nu rulează nimic sub unitate".

    `eve_grows` face ca `sleep`-ul momeală să adauge octeți în eve.json — adică
    exact fenomenul pe care pasul are voie să-l numească „captează".
    """
    binpath = tmp_path / "bin"
    proc = tmp_path / "proc"
    eve = tmp_path / "eve.json"
    eve.write_bytes(b"x" * eve_bytes)

    pid = "4242"
    if argv is not None:
        (proc / pid).mkdir(parents=True)
        (proc / pid / "cmdline").write_bytes(
            b"\0".join(a.encode() for a in argv.split(" ")) + b"\0")
    else:
        proc.mkdir(parents=True)

    _stub(binpath, "systemctl", f"""
case "$*" in
    *MainPID*) printf '%s\\n' "{pid if argv is not None else 0}" ;;
    *PIDFile*) printf '/run/suricata.pid\\n' ;;
esac
exit 0
""")
    _stub(binpath, "ip", f"""
if [[ "$*" == *"link show"* ]]; then
    for known in {' '.join(host_ifaces)}; do
        [[ "${{*: -1}}" == "$known" ]] && exit 0
    done
    exit 1
fi
exit 0
""")
    dump = ("" if dump_home_net is None
            else f"printf 'vars.address-groups.HOME_NET = {dump_home_net}\\n'")
    _stub(binpath, "suricata", f"""
if [[ "$*" == *--dump-config* ]]; then
    {dump or 'true'}
    exit 0
fi
exit 0
""")
    # `sleep` momeală: instantaneu, și — dacă i se cere — face eve.json să
    # crească. Fără el fiecare test care așteaptă degeaba ar costa secunde.
    grow = 'printf "alert\\n" >> "$FAKE_EVE"' if eve_grows else "true"
    _stub(binpath, "sleep", f'{grow}\nexit 0\n')

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        f'SURICATA_PROC_DIR="{_p(proc)}"\n'
        'SURICATA_YAML=/etc/suricata/suricata.yaml\n'
        f'SURICATA_EVE="{_p(eve)}"\n'
        # Fereastra livrată e de 210 s; aici e scurtată. Valoarea livrată e
        # pinuită separat, mai jos.
        "SURICATA_CAPTURE_WAIT_S=10\n"
        + _func(INSTALL, "suricata_running_argv") + "\n"
        + _func(INSTALL, "suricata_argv_iface") + "\n"
        + _func(INSTALL, "suricata_effective_home_net") + "\n"
        + _func(INSTALL, "suricata_eve_size") + "\n"
        + _func(INSTALL, "suricata_report_effect") + "\n"
        f'suricata_report_effect "{want_iface}" "{want_ip}" "{bpf_file}" '
        f'"{eve_bytes}"\n'
    )
    return _run(script, tmp_path, extra_path=binpath,
                env={"FAKE_EVE": _p(eve)})


GOOD_ARGV = ("/usr/bin/suricata -D -c /etc/suricata/suricata.yaml "
             "--pidfile /run/suricata.pid --af-packet=enp0s3 "
             "--set vars.address-groups.HOME_NET=[10.30.1.134]")

# Exact ce rula pe VM: argv-ul împachetat de Debian, fără nimic din ce scrisese
# instalatorul în /etc/default/suricata.
MEASURED_BROKEN_ARGV = ("/usr/bin/suricata -D --af-packet "
                        "-c /etc/suricata/suricata.yaml "
                        "--pidfile /run/suricata.pid")


def test_the_capture_interface_is_read_from_the_running_command_line(tmp_path):
    """Interfața raportată trebuie să vină din procesul care rulează. Pe VM,
    unitatea cerea una și procesul folosea alta, iar pasul o tipărea pe a
    noastră fiindcă o avea în variabilă."""
    proc = _run(
        "set -euo pipefail\n"
        + _func(INSTALL, "suricata_argv_iface") + "\n"
        f'suricata_argv_iface "{GOOD_ARGV}"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "enp0s3"


def test_a_bare_af_packet_names_no_interface_and_admits_it(tmp_path):
    """`--af-packet` fără valoare NU e „interfața implicită", e „ia lista din
    suricata.yaml" — și lista aia e exemplul din pachet, `eth0`. Dacă funcția ar
    întoarce ceva aici, pasul ar avea din nou un nume de interfață de tipărit
    peste o gazdă care nu captează nimic."""
    proc = _run(
        "set -euo pipefail\n"
        + _func(INSTALL, "suricata_argv_iface") + "\n"
        f'if suricata_argv_iface "{MEASURED_BROKEN_ARGV}"; then echo FOUND; '
        'else echo NONE; fi\n',
        tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "NONE"


def test_the_step_does_not_report_an_interface_the_process_was_never_given(tmp_path):
    """ĂSTA e defectul măsurat. Cu argv-ul real de pe VM, pasul nu are voie să
    tipărească „IDS on enp0s3": procesul nu primise nicio interfață, captura era
    zero, iar operatorul a citit o linie verde timp de o zi."""
    proc = _suricata_harness(tmp_path, argv=MEASURED_BROKEN_ARGV)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, f"linie de succes peste o captură inexistentă: {proc.stdout!r}"
    assert "names NO interface" in proc.stderr
    assert "enp0s3" not in proc.stdout


def test_a_home_net_without_this_host_is_reported_instead_of_celebrated(tmp_path):
    """Fără IP-ul public în HOME_NET, regulile `EXTERNAL_NET -> HOME_NET` — adică
    aproape tot setul ET Open — nu se potrivesc niciodată. IDS-ul rulează, costă
    RAM, și nu poate produce nicio alertă de atac din exterior."""
    proc = _suricata_harness(
        tmp_path, argv=GOOD_ARGV,
        dump_home_net="[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
        want_ip="203.0.113.9", eve_grows=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "does not contain 203.0.113.9" in proc.stderr


def test_home_net_that_cannot_be_read_is_unknown_not_fine(tmp_path):
    """Dacă `suricata --dump-config` nu răspunde, nu știm dacă regulile pot
    potrivi. „Nu știu" și „e bine" sunt stări diferite, iar colapsarea lor e
    fix felul în care o unealtă de monitorizare minte."""
    proc = _suricata_harness(tmp_path, argv=GOOD_ARGV, dump_home_net=None,
                             eve_grows=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "UNKNOWN" in proc.stderr


def test_an_interface_that_is_not_on_this_host_is_named(tmp_path):
    """`--af-packet=eth0` pe o gazdă cu enp0s3 e exact ce făcea suricata.yaml.
    Procesul pornește, systemd îl repornește la fiecare două minute, și
    `is-active` prinde faza `active` de fiecare dată."""
    argv = GOOD_ARGV.replace("--af-packet=enp0s3", "--af-packet=eth0")
    proc = _suricata_harness(tmp_path, argv=argv, want_iface="eth0",
                             eve_grows=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "not an interface on this host" in proc.stderr


def test_a_missing_bpf_exclusion_is_reported(tmp_path):
    """Fără `-F`, fluxul dominant pe care preflight-ul l-a găsit intră în
    inspecție și în eve.json. Pe gazda operatorului asta e drumul cel mai scurt
    către un disc plin — iar discul plin oprește tot agentul, nu doar IDS-ul."""
    proc = _suricata_harness(tmp_path, argv=GOOD_ARGV, eve_grows=True,
                             bpf_file="/etc/suricata/capture-filter.bpf")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "capture-filter.bpf is not on its command line" in proc.stderr


def test_no_process_under_the_unit_is_not_reported_as_running(tmp_path):
    """`systemctl is-active` spunea `active` pe gazda unde demonul murea și
    renăștea. Aici se citește PID-ul urmărit de systemd; zero înseamnă că nu
    captează nimeni, oricât de verde ar fi unitatea."""
    proc = _suricata_harness(tmp_path, argv=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "no process is running under its unit" in proc.stderr


def test_an_eve_json_that_never_grows_is_not_called_capturing(tmp_path):
    """Trei fișiere de 0 octeți sunt exact dovada că nu s-a captat nimic.
    Configurația poate fi perfectă și captura să nu existe — un BPF care exclude
    tot, o placă în alt namespace, un AppArmor care refuză socketul."""
    proc = _suricata_harness(tmp_path, argv=GOOD_ARGV, eve_grows=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, f"succes fără niciun octet captat: {proc.stdout!r}"
    assert "capture is NOT confirmed" in proc.stderr


def test_eve_json_growing_is_what_earns_the_success_line(tmp_path):
    """Cealaltă jumătate. Un pas care nu spune niciodată „merge" e la fel de
    inutil ca unul care spune mereu: operatorul n-ar mai avea de unde ști că
    IDS-ul chiar funcționează pe gazda unde funcționează."""
    proc = _suricata_harness(tmp_path, argv=GOOD_ARGV, eve_grows=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "eve.json growing" in proc.stdout
    assert "capturing on enp0s3" in proc.stdout
    assert proc.stderr.strip() == "", f"a avertizat degeaba: {proc.stderr!r}"


def test_the_shipped_capture_window_covers_a_real_rule_load():
    """Suricata se demonizează imediat și abia apoi încarcă ~46k reguli; pe VM
    au trecut 2m20s până au pornit firele de captură. O fereastră mai scurtă
    decât atât ar avertiza la FIECARE instalare sănătoasă, iar un avertisment
    care apare mereu e un avertisment pe care nimeni nu-l mai citește."""
    match = re.search(r"^SURICATA_CAPTURE_WAIT_S=(\d+)$", INSTALL, re.M)
    assert match, "fereastra de așteptare a dispărut din install.sh"
    assert int(match.group(1)) >= 150, \
        f"fereastra de {match.group(1)}s e mai scurtă decât încărcarea regulilor"


# --- mecanismul: drop-in-ul care livrează OPTIONS --------------------------
def _dropin(tmp_path: Path, family: str, *, suricata_on_path: bool = True,
            pidfile: str = "/run/suricata.pid") -> subprocess.CompletedProcess:
    binpath = tmp_path / "bin"
    binpath.mkdir(parents=True, exist_ok=True)
    if suricata_on_path:
        _stub(binpath, "suricata", "exit 0\n")
    _stub(binpath, "systemctl", f"printf '%s\\n' '{pidfile}'\nexit 0\n")
    return _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        f'DISTRO_FAMILY="{family}"\n'
        "SURICATA_YAML=/etc/suricata/suricata.yaml\n"
        + _func(INSTALL, "suricata_dropin_body") + "\n"
        "suricata_dropin_body || echo '<<no-override>>'\n",
        tmp_path, extra_path=binpath)


# Constanta istorică: exact ce scria pasul 35 în drop-in înainte de schimbare.
RHEL_DROPIN_BEFORE = "[Service]\nMemoryMax=1G\nRestart=on-failure\nRestartSec=5\n"


def test_the_rhel_dropin_is_byte_for_byte_what_it_was(tmp_path):
    """Non-regresie, și e cea care contează: producția e AlmaLinux, unde
    unitatea împachetată chiar citește `/etc/sysconfig/suricata`. Dacă
    schimbarea asta ar suprascrie și acolo `ExecStart`, un IDS care merge de
    luni de zile s-ar rescrie sub el la primul deploy."""
    proc = _dropin(tmp_path, "rhel")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == RHEL_DROPIN_BEFORE, proc.stdout
    assert "ExecStart" not in proc.stdout


def test_the_debian_dropin_supplies_the_environment_file_the_unit_lacks(tmp_path):
    """Cauza lui B2. `systemctl show suricata -p EnvironmentFiles` nu tipărea
    nimic pe Ubuntu: fișierul se scria și nu-l citea nimeni. Fără linia asta,
    OPTIONS rămâne o notiță pe disc."""
    proc = _dropin(tmp_path, "debian")
    assert proc.returncode == 0, proc.stderr
    assert "EnvironmentFile=-/etc/default/suricata" in proc.stdout
    # `ExecStart=` gol înainte, altfel systemd ADAUGĂ o a doua comandă în loc
    # s-o înlocuiască pe cea împachetată.
    assert re.search(r"^ExecStart=$", proc.stdout, re.M), proc.stdout
    assert re.search(r"^ExecStart=\S*suricata -D -c /etc/suricata/suricata\.yaml "
                     r"--pidfile /run/suricata\.pid \$OPTIONS$", proc.stdout, re.M), \
        proc.stdout
    # Și partea comună nu s-a pierdut pe drum.
    assert "MemoryMax=1G" in proc.stdout


def test_the_debian_dropin_takes_the_pidfile_from_the_installed_unit(tmp_path):
    """Un `--pidfile` care nu e cel din `PIDFile=` face systemd să abandoneze un
    serviciu `Type=forking` care pornise perfect. Valoarea se citește de la
    unitate, nu se scrie cu mâna aici."""
    proc = _dropin(tmp_path, "debian", pidfile="/run/suricata/suricata.pid")
    assert proc.returncode == 0, proc.stderr
    assert "--pidfile /run/suricata/suricata.pid $OPTIONS" in proc.stdout


def test_no_execstart_is_written_when_the_binary_cannot_be_found(tmp_path):
    """Un `ExecStart=` cu binar gol face unitatea imposibil de pornit. Asta ar fi
    mai rău decât defectul: nu un IDS care se uită în altă parte, ci niciun IDS
    — și pasul trebuie să spună asta, nu să scrie linia oricum."""
    proc = _dropin(tmp_path, "debian", suricata_on_path=False)
    assert "<<no-override>>" in proc.stdout, proc.stdout
    assert "ExecStart" not in proc.stdout
    assert "MemoryMax=1G" in proc.stdout


# --- mecanismul: repornirea, fiindcă `enable --now` e operație nulă ---------
def _needs_restart(tmp_path: Path, argv: str | None, want: str
                   ) -> subprocess.CompletedProcess:
    binpath = tmp_path / "bin"
    proc_dir = tmp_path / "proc"
    pid = "77"
    if argv is not None:
        (proc_dir / pid).mkdir(parents=True)
        (proc_dir / pid / "cmdline").write_bytes(
            b"\0".join(a.encode() for a in argv.split(" ")) + b"\0")
    else:
        proc_dir.mkdir(parents=True)
    _stub(binpath, "systemctl",
          f"printf '%s\\n' '{pid if argv is not None else 0}'\nexit 0\n")
    return _run(
        "set -euo pipefail\n"
        f'SURICATA_PROC_DIR="{_p(proc_dir)}"\n'
        + _func(INSTALL, "suricata_running_argv") + "\n"
        + _func(INSTALL, "suricata_needs_restart") + "\n"
        f'if reason="$(suricata_needs_restart "{want}")"; then\n'
        '    printf "RESTART: %s\\n" "$reason"\n'
        "else\n"
        '    printf "LEAVE\\n"\n'
        "fi\n",
        tmp_path, extra_path=binpath)


def test_a_suricata_still_running_the_previous_argv_is_restarted(tmp_path):
    """`systemctl enable --now` peste un serviciu deja pornit e o operație nulă
    — e chiar exemplul din CLAUDE.md. Procesul rămâne pe argv-ul deploy-ului
    anterior, jurnalul spune „enabled", și noile setări nu ajung nicăieri."""
    proc = _needs_restart(tmp_path, MEASURED_BROKEN_ARGV,
                          "--af-packet=enp0s3 --set vars.address-groups.HOME_NET=[10.30.1.134]")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("RESTART:"), proc.stdout


def test_a_suricata_already_running_these_options_is_left_alone(tmp_path):
    """Cealaltă jumătate. O repornire necondiționată ar reîncărca 46k de reguli
    și ar lăsa gazda fără IDS două minute la fiecare rulare a instalatorului,
    inclusiv la cele care nu schimbă nimic."""
    proc = _needs_restart(tmp_path, GOOD_ARGV, "--af-packet=enp0s3")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "LEAVE", proc.stdout


def test_a_unit_with_no_process_is_restarted_rather_than_assumed_fine(tmp_path):
    """„Nu pot citi argv-ul" nu e „e în regulă". Dacă nu rulează nimic sub
    unitate, pasul repornește; tăcerea aici ar lăsa gazda fără IDS."""
    proc = _needs_restart(tmp_path, None, "--af-packet=enp0s3")
    assert proc.stdout.startswith("RESTART:"), proc.stdout


# ===========================================================================
# A3 — nginx: ascultătorul :80 al distribuției e în alt fișier pe Debian
# ===========================================================================
@pytest.mark.parametrize("family,expected", [
    # Constanta istorică pentru rhel: exact fișierul pe care îl edita `sed`.
    ("rhel", "/etc/nginx/nginx.conf"),
    ("debian", "/etc/nginx/sites-enabled/default"),
])
def test_the_distribution_default_site_is_a_different_file_per_family(
        tmp_path, family, expected):
    """Pe Ubuntu `sed` rula peste `/etc/nginx/nginx.conf`, care n-are niciun
    `listen` activ. Dacă altceva ține portul 80, nginx refuză să pornească —
    și eroarea arată ca un bug al Sentinelului, nu ca un conflict de port."""
    proc = _distro_call(tmp_path, family, "nginx_default_site")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


def test_the_debian_default_site_is_disabled_by_removing_the_symlink(tmp_path):
    """Situl implicit al pachetului e un symlink către sites-available. Ștergerea
    lui dezactivează situl și lasă fișierul intact, deci revenirea e un `ln -s`.
    Un `sed` în conffile-ul pachetului ar fi supraviețuit prost primului
    `apt upgrade`."""
    etc = tmp_path / "etc" / "nginx"
    (etc / "sites-available").mkdir(parents=True)
    (etc / "sites-enabled").mkdir(parents=True)
    real = etc / "sites-available" / "default"
    real.write_text("server {\n\tlisten 80 default_server;\n}\n",
                    encoding="utf-8", newline="\n")
    link = etc / "sites-enabled" / "default"
    link.write_text(real.read_text(encoding="utf-8"), encoding="utf-8",
                    newline="\n")

    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        + _func(DISTRO, "nginx_disable_default_listener").replace(
            "$(nginx_default_site)", f'"{_p(link)}"') + "\n"
        "nginx_disable_default_listener\n",
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not link.exists(), "situl implicit e încă activ"
    assert real.exists(), "s-a șters fișierul din sites-available, nu doar legătura"
    assert "ln -s" in proc.stdout, "nu s-a spus cum se pune la loc"


def test_disabling_the_default_site_leaves_the_operators_own_vhosts_alone(tmp_path):
    """Steagul `NGINX_WAS_PREEXISTING` rămâne 0 pe o gazdă unde nginx a fost pus
    de noi — inclusiv dacă operatorul și-a adăugat între timp propriile situri.
    Zero îi dă pasului 33 voie să dezactiveze situl implicit AL PACHETULUI, și
    numai pe acela; dacă ar mătura `sites-enabled/`, deploy-ul următor i-ar
    stinge operatorului siturile fără să spună nimic."""
    etc = tmp_path / "etc" / "nginx"
    (etc / "sites-available").mkdir(parents=True)
    (etc / "sites-enabled").mkdir(parents=True)
    default = etc / "sites-enabled" / "default"
    default.write_text("server {\n\tlisten 80 default_server;\n}\n",
                       encoding="utf-8", newline="\n")
    mine = etc / "sites-enabled" / "magazinul-meu"
    mine.write_text("server {\n\tlisten 80;\n\tserver_name magazin.example;\n}\n",
                    encoding="utf-8", newline="\n")

    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="debian"\n'
        + _func(DISTRO, "nginx_disable_default_listener").replace(
            "$(nginx_default_site)", f'"{_p(default)}"') + "\n"
        "nginx_disable_default_listener\n",
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not default.exists(), "situl implicit al pachetului e încă activ"
    assert mine.exists(), "s-a dezactivat un vhost al operatorului"
    assert "magazin.example" in mine.read_text(encoding="utf-8")


# Constanta istorică: rezultatul exact al `sed`-ului livrat pe un nginx.conf
# de tip RHEL, așa cum arăta înainte de schimbare.
RHEL_NGINX_CONF_BEFORE = """\
server {
    listen       80;
    listen       [::]:80;
    server_name  _;
}
"""
RHEL_NGINX_CONF_AFTER = """\
server {
    # SENTINEL-DISABLED listen       80;
    # SENTINEL-DISABLED listen       [::]:80;
    server_name  _;
}
"""


def test_the_rhel_edit_is_byte_for_byte_what_it_was(tmp_path):
    """Non-regresie pe AlmaLinux. Blocul :80 e chiar în `nginx.conf` acolo, iar
    comentarea lui e ce se întâmplă azi în producție; dacă rezultatul se schimbă
    cu un octet, operatorul are altceva în fișier decât avea ieri."""
    conf = tmp_path / "nginx.conf"
    conf.write_text(RHEL_NGINX_CONF_BEFORE, encoding="utf-8", newline="\n")
    body = _func(DISTRO, "nginx_disable_default_listener").replace(
        "$(nginx_default_site)", f'"{_p(conf)}"')
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/distro.sh\n"
        'DISTRO_FAMILY="rhel"\n'
        + body + "\n"
        "nginx_disable_default_listener\n"
        # A doua oară: marcajul trebuie să oprească dubla comentare.
        "nginx_disable_default_listener\n",
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert conf.read_text(encoding="utf-8") == RHEL_NGINX_CONF_AFTER, \
        conf.read_text(encoding="utf-8")


def _listens_on_80(tmp_path: Path, dump: str | None,
                   nginx_present: bool = True) -> int:
    binpath = tmp_path / "bin"
    binpath.mkdir(parents=True, exist_ok=True)
    if nginx_present:
        if dump is None:
            _stub(binpath, "nginx", "exit 1\n")
        else:
            dumpfile = tmp_path / "dump.conf"
            dumpfile.write_text(dump, encoding="utf-8", newline="\n")
            _stub(binpath, "nginx", f'cat "{_p(dumpfile)}"\nexit 0\n')
    else:
        # PATH gol în față: `have nginx` trebuie să eșueze, deci nu se poate
        # pune un PATH real în spate.
        pass
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        + _func(INSTALL, "nginx_listens_on_80") + "\n"
        "rc=0\n"
        "nginx_listens_on_80 || rc=$?\n"
        'printf "%s\\n" "$rc"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return int(proc.stdout.strip())


# Exact liniile 22-23 din /etc/nginx/sites-enabled/default de pe VM.
UBUNTU_DEFAULT_SITE = """\
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name _;
}
"""


def test_a_default_server_listen_is_recognised_as_a_listener(tmp_path):
    """Tiparul vechi cerea `listen 80;` simplu. Pe Ubuntu scrie
    `listen 80 default_server;`, deci nu se potrivea, iar pasul raporta portul
    ca eliberat peste un nginx care încă îl cerea."""
    assert _listens_on_80(tmp_path, UBUNTU_DEFAULT_SITE) == 0


@pytest.mark.parametrize("line", [
    "    listen 80;",
    "    listen [::]:80 default_server;",
    "    listen 0.0.0.0:80;",
    "    listen *:80 ssl;",
])
def test_every_shape_of_a_port_80_listener_is_seen(tmp_path, line):
    """nginx acceptă mai multe scrieri pentru același port. Una scăpată
    înseamnă un pas care spune „:80 eliberat" peste o gazdă unde nginx va
    refuza să pornească."""
    assert _listens_on_80(tmp_path, "server {\n%s\n}\n" % line) == 0


@pytest.mark.parametrize("line", [
    "    listen 8080;",
    "    listen 8000 ssl;",
    "    listen 127.0.0.1:8081;",
])
def test_another_port_is_not_mistaken_for_80(tmp_path, line):
    """Cealaltă jumătate: dacă orice `listen` ar fi luat drept :80, pasul ar
    avertiza la fiecare instalare — inclusiv pe gazda unde totul e în regulă —
    iar avertismentul ar fi ignorat exact când e adevărat."""
    assert _listens_on_80(tmp_path, "server {\n%s\n}\n" % line) == 1


def test_an_nginx_that_will_not_dump_its_config_is_unknown_not_free(tmp_path):
    """A treia stare, și motivul pentru care funcția întoarce un cod și nu un
    boolean. Un `nginx -T` care pică peste o configurație invalidă nu tipărește
    niciun `listen` — iar „n-am găsit" ar deveni „portul e liber"."""
    assert _listens_on_80(tmp_path, None) == 2


def test_the_step_reads_all_three_outcomes(tmp_path):
    """Dacă pasul 33 ar trata doar 0 și 1, starea „nu se știe" ar cădea tăcut pe
    ramura de succes — care e exact tiparul pe care fișierul ăsta îl vânează."""
    body = _func(INSTALL, "step_nginx")
    assert "nginx_listens_on_80" in body
    for outcome in ("0)", "1)", "2)"):
        assert outcome in body, f"pasul 33 nu tratează rezultatul {outcome}"
    assert "UNKNOWN" in body


# ===========================================================================
# Pasul 37 — se numără REGULILE, nu cheile
# ===========================================================================
SYNTHETIC_RULES = """\
# Un set mic, ca numerele să fie verificabile cu ochiul.
-w @@FILE_PASSWD@@ -p wa -k sentinel_identity
-w @@FILE_SHADOW@@ -p wa -k sentinel_identity
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -F auid>=1000 -F auid!=unset -k sentinel_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -F auid>=1000 -F auid!=unset -k sentinel_exec
-b 8192
--backlog_wait_time 60000
-a never,exit -F dir=@@DIR_CHURN@@
-a never,exit -F dir=@@DIR_SELF@@
"""

ALL_LOADED = """\
-w @@FILE_PASSWD@@ -p wa -k sentinel_identity
-w @@FILE_SHADOW@@ -p wa -k sentinel_identity
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -F auid>=1000 -F auid!=-1 -F key=sentinel_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -F auid>=1000 -F auid!=-1 -F key=sentinel_exec
-a never,exit -F dir=@@DIR_CHURN@@
-a never,exit -F dir=@@DIR_SELF@@
"""

# Directoarele pe care le numesc regulile `never` din setul de mai sus.
#
# Nu `/var/lib/docker` și `/opt/sentinel`: pe mașina care rulează testele
# niciunul nu există, iar de la reparația din 26 august o regulă `-F dir=` cu
# calea absentă e ȚINUTĂ AFARĂ din fișierul instalat. Un test care ar depinde de
# ce are din întâmplare mașina de test ar trece sau ar pica după gazdă — exact
# felul de test care nu păzește nimic.
DIR_CHURN = "@@DIR_CHURN@@"   # tine locul lui /var/lib/docker
DIR_SELF = "@@DIR_SELF@@"     # tine locul lui /opt/sentinel

# Doua `-w` sintetice, pentru acelasi motiv: `/etc/passwd`/`/etc/shadow`
# hardcodate ar fi existat sau nu dupa cum se intampla sa arate MASINA care
# ruleaza suita (nu exista pe masina asta de dezvoltare), iar de cand
# `audit_rules_for_this_host` filtreaza si liniile `-w` cu cale absenta -- nu
# doar `-F dir=` -- un test care ar depinde de asta ar trece sau ar pica dupa
# gazda, exact felul de test care nu pazeste nimic.
FILE_PASSWD = "@@FILE_PASSWD@@"   # tine locul lui /etc/passwd
FILE_SHADOW = "@@FILE_SHADOW@@"   # tine locul lui /etc/shadow


def _dir_map(tmp_path: Path) -> dict[str, Path]:
    return {DIR_CHURN: tmp_path / "churn", DIR_SELF: tmp_path / "self",
            FILE_PASSWD: tmp_path / "passwd", FILE_SHADOW: tmp_path / "shadow"}


def _materialize(tmp_path: Path, token: str) -> None:
    """Face sa existe pe disc calea din spatele unui token.

    Director pentru `@@DIR_*@@` (asa cum verifica un `-F dir=`), fisier gol
    pentru `@@FILE_*@@` (asa cum verifica un `-w`) -- nucleul cere doar ca
    inode-ul sa existe, nu un anume tip, dar testele trebuie sa poata simula pe
    oricare din cele doua sintaxe independent una de alta.
    """
    path = _dir_map(tmp_path)[token]
    if token.startswith("@@FILE_"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    else:
        path.mkdir(parents=True, exist_ok=True)


def _expand(text: str, tmp_path: Path) -> str:
    for token, path in _dir_map(tmp_path).items():
        text = text.replace(token, _p(path))
    return text


HEALTHY_STATUS = ("enabled 1\nfailure 1\npid 31813\nrate_limit 0\n"
                  "backlog_limit 8192\nlost 0\nbacklog 0\n"
                  "backlog_wait_time 60000\nbacklog_wait_time_actual 0\n")


def _audit_harness(tmp_path: Path, *, rules: str = SYNTHETIC_RULES,
                   loaded: str = ALL_LOADED, status: str = HEALTHY_STATUS,
                   augen_out: str = "", augen_rc: int = 0,
                   tools_present: bool = True,
                   present: tuple[str, ...] = (DIR_CHURN, DIR_SELF, FILE_PASSWD, FILE_SHADOW),
                   ) -> subprocess.CompletedProcess:
    """Rulează `install_audit_rules` LIVRATĂ, cu `augenrules` și `auditctl`
    momeală. `loaded` e exact ce răspunde `auditctl -l` — în forma în care o
    scrie NUCLEUL, cu `auid!=-1` și `-F key=`, nu în forma din fișier."""
    binpath = tmp_path / "bin"
    scriptdir = tmp_path / "deploy"
    (scriptdir / "audit").mkdir(parents=True)
    # Doar căile din `present` există; celelalte sunt exact cazul măsurat pe
    # VM — calea lipsă pentru care nucleul refuză regula, indiferent dacă e un
    # `-F dir=` sau un `-w`.
    for token in present:
        _materialize(tmp_path, token)
    (scriptdir / "audit" / "sentinel.rules").write_text(
        _expand(rules, tmp_path), encoding="utf-8", newline="\n")

    loadedfile = tmp_path / "loaded.txt"
    loadedfile.write_text(_expand(loaded, tmp_path), encoding="utf-8", newline="\n")
    statusfile = tmp_path / "status.txt"
    statusfile.write_text(status, encoding="utf-8", newline="\n")

    if tools_present:
        _stub(binpath, "augenrules",
              f"printf '%s' \"$AUGEN_OUT\"\nexit {augen_rc}\n")
        _stub(binpath, "auditctl", f"""
case "${{1:-}}" in
    -l) cat "{_p(loadedfile)}" ;;
    -s) cat "{_p(statusfile)}" ;;
esac
exit 0
""")
    else:
        binpath.mkdir(parents=True, exist_ok=True)

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'SCRIPT_DIR="{_p(scriptdir)}"\n'
        f'AUDITD_RULES_DEST="{_p(tmp_path / "installed.rules")}"\n'
        "AUDITD_LOG_PATH=/var/log/audit/audit.log\n"
        # `install_audit_rules` plants the two functionality-05 baits before it
        # stages anything. None of the tests in THIS section are about them, so
        # they get redirected under tmp_path — otherwise every one of these
        # would try to write into the real /root of the machine running the
        # suite.
        f'CANARY_PGPASS_PATH="{_p(tmp_path / "root" / ".pgpass")}"\n'
        f'CANARY_AWS_CREDS_PATH="{_p(tmp_path / "root" / ".aws" / "credentials")}"\n'
        f'CANARY_STATE_PATH="{_p(tmp_path / "etc-sentinel" / "canary-state")}"\n'
        + _func(INSTALL, "_canary_content") + "\n"
        + _func(INSTALL, "install_canary_baits") + "\n"
        + _func(INSTALL, "audit_rule_signatures") + "\n"
        + _func(INSTALL, "audit_rules_for_this_host") + "\n"
        + _func(INSTALL, "install_audit_rules") + "\n"
        "install_audit_rules\n"
    )
    # PATH-ul momeală trebuie să vină primul, dar `awk`, `sort`, `uniq` și
    # `grep` reale rămân în spate.
    return _run(script, tmp_path, extra_path=binpath,
                env={"AUGEN_OUT": augen_out})


def test_all_rules_in_the_kernel_and_a_live_daemon_earn_the_success_line(tmp_path):
    """Cazul bun, întâi. Un pas care nu spune niciodată „e în regulă" nu ajută
    pe nimeni să afle că gazda unde chiar merge chiar merge."""
    proc = _audit_harness(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "all 6 rules" in proc.stdout, proc.stdout
    assert "pid 31813" in proc.stdout
    assert proc.stderr.strip() == "", proc.stderr


def test_a_rejected_rule_beside_a_loaded_one_with_the_same_key_is_counted(tmp_path):
    """Verificarea pe CHEIE nu putea vedea asta: `sentinel_exec` e în nucleu
    fiindcă una din cele două reguli s-a încărcat, deci cheia era „prezentă" și
    pasul spunea „confirmed loaded" peste o detecție pe jumătate oarbă."""
    partial = "\n".join(
        l for l in ALL_LOADED.splitlines() if "/usr/bin/curl" not in l) + "\n"
    proc = _audit_harness(tmp_path, loaded=partial)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, f"succes peste o regulă lipsă: {proc.stdout!r}"
    assert "key sentinel_exec: 1 of 2 in the kernel" in proc.stderr, proc.stderr
    assert "5/6" in proc.stderr, proc.stderr


def test_a_keyless_suppression_rule_that_did_not_load_is_reported(tmp_path):
    """Defectul măsurat pe VM. `auditctl -R` se oprește la prima regulă pe care
    n-o poate adăuga, iar `-F dir=/var/lib/docker` e respinsă pe o gazdă fără
    docker. Regulile de după ea nu se încarcă, n-au cheie, și verificarea pe
    chei n-avea cum să le vadă — Sentinel ajunge să-și auditeze propriile
    scrieri, ceea ce e și zgomot, și buclă de reacție."""
    without = "\n".join(
        l for l in ALL_LOADED.splitlines() if DIR_SELF not in l) + "\n"
    proc = _audit_harness(tmp_path, loaded=without)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert f"dir {_p(_dir_map(tmp_path)[DIR_SELF])}: 0 of 1 in the kernel" \
        in proc.stderr, proc.stderr


def test_no_change_on_its_own_is_not_reported_as_a_failure(tmp_path):
    """Al doilea deploy pe aceeași gazdă generează un `audit.rules` identic, iar
    `augenrules` spune „No change" și încarcă mai departe. Raportat ca eșec, e o
    linie roșie la fiecare rulare — și operatorul se învață s-o sară exact acolo
    unde apare cea adevărată."""
    proc = _audit_harness(
        tmp_path,
        augen_out="/usr/sbin/augenrules: No change\n" + HEALTHY_STATUS,
        augen_rc=0)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" in proc.stdout, proc.stdout + proc.stderr
    assert proc.stderr.strip() == "", proc.stderr


def test_the_no_rules_line_auditctl_always_prints_is_not_a_failure(tmp_path):
    """Măsurat pe VM pe 27 august 2026, în deploy-ul de verificare: `auditctl -D`
    tipărește `No rules` pe stdout de FIECARE dată, inclusiv în rularea în care
    tocmai ștersese 29 de reguli, iar `augenrules --load` îl rulează înainte de
    `auditctl -R`. Cât timp mai exista și o eroare adevărată alături, linia asta
    n-a fost observată. Singură, ea transformă gazda perfect sănătoasă într-un
    `[!] augenrules did not load the whole file: No rules` la fiecare deploy —
    adică exact roșul permanent pe care operatorul se învață să-l sară."""
    proc = _audit_harness(
        tmp_path,
        augen_out="/usr/sbin/augenrules: No change\nNo rules\n" + HEALTHY_STATUS,
        augen_rc=0)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" in proc.stdout, proc.stdout + proc.stderr
    assert proc.stderr.strip() == "", proc.stderr


def test_a_real_error_next_to_the_no_rules_line_still_gets_through(tmp_path):
    """Cealaltă jumătate a filtrului de zgomot. Dacă tăierea ar înghiți și
    eroarea, am fi înlocuit un roșu fals cu o tăcere falsă — iar tăcerea e mai
    rea, fiindcă nimeni n-o observă niciodată."""
    proc = _audit_harness(
        tmp_path,
        augen_out=("No rules\n"
                   "Error sending add rule data request (No such file or directory)\n"
                   "There was an error in line 34 of /etc/audit/audit.rules\n"),
        augen_rc=1)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "Error sending add rule data request" in proc.stderr, proc.stderr
    assert "No rules" not in proc.stderr, \
        "zgomotul e încă prezentat ca parte din eroare"


def test_a_real_rejection_from_augenrules_is_still_reported(tmp_path):
    """Cealaltă jumătate a filtrului. Dacă filtrarea zgomotului ar înghiți și
    eroarea, am fi înlocuit un raport contradictoriu cu unul tăcut — iar tăcerea
    e mai rea."""
    proc = _audit_harness(
        tmp_path,
        augen_out=("/usr/sbin/augenrules: No change\n"
                   "Error sending add rule data request (No such file or directory)\n"
                   "There was an error in line 34 of /etc/audit/audit.rules\n"),
        augen_rc=1)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "Error sending add rule data request" in proc.stderr
    assert "No change" not in proc.stderr, \
        "notița benignă e încă prezentată ca parte din eroare"


def test_rules_in_the_kernel_are_not_called_loaded_when_auditd_is_dead(tmp_path):
    """`auditctl -l` citește NUCLEUL, iar regulile din nucleu supraviețuiesc
    demonului care le-a cerut. „confirmed loaded" s-a tipărit pe o gazdă unde
    auditd era mort: regulile erau acolo, nimic nu scria în audit.log, și fiecare
    detecție `host.*` citea un fișier gol."""
    dead = HEALTHY_STATUS.replace("pid 31813", "pid 0")
    proc = _audit_harness(tmp_path, status=dead)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "no auditd daemon is running" in proc.stderr


def test_auditing_disabled_in_the_kernel_is_reported(tmp_path):
    """`enabled 0` înseamnă că nucleul nu evaluează nicio regulă, oricâte ar fi
    încărcate. E o stare la care se ajunge cu o singură comandă și pe care nimic
    altceva n-o observă."""
    off = HEALTHY_STATUS.replace("enabled 1", "enabled 0")
    proc = _audit_harness(tmp_path, status=off)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "not enabled" in proc.stderr


def test_a_backlog_smaller_than_asked_for_is_reported(tmp_path):
    """`-b` nu apare niciodată în `auditctl -l`, deci înainte nu se verifica
    deloc. Cu un backlog mai mic, nucleul ARUNCĂ înregistrări exact în minutul
    aglomerat — iar o înregistrare aruncată arată identic cu o comandă care n-a
    fost rulată niciodată."""
    small = HEALTHY_STATUS.replace("backlog_limit 8192", "backlog_limit 320")
    proc = _audit_harness(tmp_path, status=small)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "backlog_limit is 320 in the kernel, not 8192" in proc.stderr


def test_the_step_never_prints_success_beside_failure(tmp_path):
    """Defectul de raportare, direct: `[!] augenrules failed` urmat imediat de
    `[+] auditd rules installed and confirmed loaded`. Două afirmații opuse, una
    după alta, și operatorul o crede pe a doua."""
    partial = "\n".join(
        l for l in ALL_LOADED.splitlines() if DIR_SELF not in l) + "\n"
    proc = _audit_harness(
        tmp_path, loaded=partial,
        augen_out="Error sending add rule data request (No such file or directory)\n",
        augen_rc=1)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, \
        f"un [+] a apărut lângă un [!]:\nSTDOUT{proc.stdout!r}\nSTDERR{proc.stderr!r}"
    assert proc.stderr.count("[!]") == 1, \
        f"verdictul e împrăștiat pe mai multe linii contradictorii: {proc.stderr!r}"


def test_a_host_without_auditctl_says_nothing_loaded_them(tmp_path):
    """Fără `auditctl`/`augenrules` fișierul ajunge pe disc și nimic nu-l
    încarcă. Un fișier pe disc nu e dovadă că a fost încărcat."""
    proc = _audit_harness(tmp_path, tools_present=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "NOTHING loaded them" in proc.stderr


def test_the_signatures_survive_the_kernels_rewriting(tmp_path):
    """Aserțiunea de fond: nucleul rescrie ce i se dă. `-F a1&07000` se întoarce
    `-F a1&0xE00`, `auid!=unset` se întoarce `auid!=-1`, iar cheia unei reguli
    de syscall se întoarce `-F key=` în loc de `-k`. O comparație pe text ar
    raporta TOATE regulile de syscall ca lipsă, la fiecare instalare."""
    written = ("-a always,exit -F arch=b64 -S chmod,fchmod -F a1&07000 "
               "-F auid>=1000 -F auid!=unset -k sentinel_suid\n")
    echoed = ("-a always,exit -F arch=b64 -S chmod,fchmod -F a1&0xE00 "
              "-F auid>=1000 -F auid!=-1 -F key=sentinel_suid\n")
    src = tmp_path / "in.txt"
    both = tmp_path / "out.txt"
    src.write_text(written, encoding="utf-8", newline="\n")
    both.write_text(echoed, encoding="utf-8", newline="\n")
    proc = _run(
        "set -euo pipefail\n"
        + _func(INSTALL, "audit_rule_signatures") + "\n"
        f'audit_rule_signatures < "{_p(src)}"\n'
        f'audit_rule_signatures < "{_p(both)}"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.split()
    assert proc.stdout.strip().splitlines() == ["key sentinel_suid",
                                               "key sentinel_suid"], lines


def test_the_shipped_rules_file_is_fully_recognised(tmp_path):
    """O listă parametrizată ieșită goală trece tăcut — s-a mai întâmplat aici.
    Dacă vreo linie din `sentinel.rules` nu produce o semnătură, ea nu e
    verificată deloc, iar pasul ar număra „toate încărcate" dintr-un set mai mic
    decât fișierul."""
    rules = REPO / "deploy" / "audit" / "sentinel.rules"
    proc = _run(
        "set -euo pipefail\n"
        + _func(INSTALL, "audit_rule_signatures") + "\n"
        f'audit_rule_signatures < "{_p(rules)}"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stderr
    sigs = proc.stdout.strip().splitlines()
    assert sigs, "nicio semnătură: fișierul de reguli n-a fost citit deloc"
    assert not [s for s in sigs if s.startswith("unchecked ")], \
        [s for s in sigs if s.startswith("unchecked ")]
    # 32 de reguli + 2 opțiuni, măsurat pe fișierul livrat (30 + cele 2 momeli
    # din funcționalitatea 05).
    assert len([s for s in sigs if not s.startswith("option ")]) == 32, sigs


# ===========================================================================
# Pasul 37 — o regulă `-F dir=` cu calea absentă nu mai ia cu ea restul
# ===========================================================================
# Măsurat pe VM (10.30.1.134) pe 26 august 2026, ÎNAINTE de reparație:
#
#   * `-a never,exit -F dir=/nonexistent` e refuzată de nucleu cu
#     „Error sending add rule data request (No such file or directory)";
#   * `auditctl -R` — pe care `augenrules --load` îl rulează — SE OPREȘTE acolo:
#     cu regula rea pe linia 1, cea de pe linia 2 nu ajunge în nucleu; cu regula
#     rea pe linia 2, cea de pe linia 1 ajunge. Se pierde tot ce e DUPĂ ea;
#   * `-w /nonexistent -p wa -k x` se încarcă FĂRĂ probleme (rc=0, apare în
#     `auditctl -l`). Doar `-F dir=` cere calea;
#   * o regulă `-F dir=` deja încărcată DISPARE din `auditctl -l` în clipa în
#     care directorul e șters, și nu revine când e recreat.
def _installed(tmp_path: Path) -> str:
    return (tmp_path / "installed.rules").read_text(encoding="utf-8")


def test_a_missing_directory_no_longer_takes_the_rules_after_it_down(tmp_path):
    """Defectul măsurat: pe o gazdă fără docker, `-F dir=/var/lib/docker` e
    refuzată, `auditctl -R` se oprește la ea, și cele două suprimări de după ea
    — /opt/sentinel și /var/lib/sentinel — nu mai ajung în nucleu. Sentinel își
    auditează atunci propriile scrieri: și zgomot, și buclă de reacție."""
    proc = _audit_harness(tmp_path, present=(DIR_SELF, FILE_PASSWD, FILE_SHADOW))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    installed = _installed(tmp_path)
    churn = _p(_dir_map(tmp_path)[DIR_CHURN])
    selfd = _p(_dir_map(tmp_path)[DIR_SELF])
    assert churn not in installed, \
        "regula cu directorul absent a ajuns în fișierul instalat; nucleul o refuză"
    assert f"-a never,exit -F dir={selfd}" in installed, \
        "regula de DUPĂ cea refuzată lipsește — exact pierderea măsurată pe VM"


def test_the_rule_left_out_is_named_not_silent(tmp_path):
    """„Nu s-a putut" și „nu era nevoie" sunt stări diferite. O regulă tăiată
    tăcut înseamnă un operator care crede că suprimarea e activă și se întreabă
    de ce i se umple jurnalul."""
    proc = _audit_harness(tmp_path, present=(DIR_SELF, FILE_PASSWD, FILE_SHADOW))
    churn = _p(_dir_map(tmp_path)[DIR_CHURN])
    assert churn in proc.stdout, \
        f"regula lăsată afară nu e numită nicăieri: {proc.stdout!r}"
    assert "--force-step 37" in proc.stdout, "nu se spune cum se pune la loc"


def test_the_count_is_taken_from_what_was_offered_to_the_kernel(tmp_path):
    """Dacă numărătoarea ar rămâne pe fișierul LIVRAT, regula pe care gazda asta
    n-o poate ține ar fi raportată la fiecare deploy ca „lipsă din nucleu" — un
    roșu permanent pentru o stare corectă, adică fix genul de avertisment pe care
    operatorul se învață să-l sară."""
    without_churn = "\n".join(
        l for l in ALL_LOADED.splitlines() if DIR_CHURN not in l) + "\n"
    proc = _audit_harness(tmp_path, loaded=without_churn, present=(DIR_SELF, FILE_PASSWD, FILE_SHADOW))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "all 5 rules" in proc.stdout, proc.stdout + proc.stderr
    assert proc.stderr.strip() == "", proc.stderr


def test_a_watch_on_a_path_that_does_not_exist_is_dropped_and_named(tmp_path):
    """Corectat in runda 2, dupa o gazda reala. MASURAT pe AlmaLinux 9.8
    (nucleu 5.14, auditctl 3.1.5): `-w /nu/exista -p wa` SI `-w /nu/exista -p r`
    sunt REFUZATE de nucleu, byte cu byte aceeasi eroare ca `-F dir=`. Testul
    asta inlocuieste unul care afirma opusul -- masurat doar pe Ubuntu -- si
    care ar fi trecut, vacuu, langa un filtru care nu mai filtra deloc `-w`.

    Regula de DUPA cea absenta trebuie sa supravietuiasca: `auditctl -R` se
    opreste la prima linie refuzata, iar cele doua momeli din functionalitatea
    05 stau chiar inaintea `sentinel_cmd` si a celor doua suprimari `never,exit`
    -- un `-w` nefiltrat ar fi luat cu el tot ce urmeaza.
    """
    rules = ("-w /nu-exista-nicaieri -p wa -k sentinel_webroot\n"
             "-a never,exit -F dir=" + DIR_SELF + "\n")
    loaded = "-a never,exit -F dir=" + DIR_SELF + "\n"
    proc = _audit_harness(tmp_path, rules=rules, loaded=loaded,
                          present=(DIR_SELF,))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    installed = _installed(tmp_path)
    assert "/nu-exista-nicaieri" not in installed, \
        "un watch pe o cale absenta a ajuns in fisierul instalat; nucleul il refuza"
    assert f"-a never,exit -F dir={_p(_dir_map(tmp_path)[DIR_SELF])}" in installed, \
        "regula de DUPA cea absenta a fost pierduta odata cu ea"
    assert "[+]" not in proc.stdout, proc.stdout
    assert "/nu-exista-nicaieri" in proc.stderr, \
        "watch-ul scos afara nu e numit nicaieri"
    assert "the path it names does not exist here" in proc.stderr, proc.stderr


def test_a_dropped_rule_that_is_not_a_suppression_is_in_the_verdict(tmp_path):
    """O regula `always` pentru un director absent e o DETECTIE pe care gazda
    n-o are, nu zgomot pe care nu-l are. Cele doua nu au voie sa se raporteze la
    fel: una e o nota, cealalta e o gaura."""
    rules = ("-w " + FILE_PASSWD + " -p wa -k sentinel_identity\n"
             "-a always,exit -F dir=" + DIR_CHURN + " -F perm=wa -k sentinel_webroot\n")
    loaded = "-w " + FILE_PASSWD + " -p wa -k sentinel_identity\n"
    proc = _audit_harness(tmp_path, rules=rules, loaded=loaded, present=(FILE_PASSWD,))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, proc.stdout
    assert "NOT installed, the path it names does not exist here" in proc.stderr, proc.stderr


def test_a_host_where_every_directory_exists_keeps_the_shipped_file_byte_for_byte(
        tmp_path):
    """Non-regresie pentru productie. AlmaLinux ARE docker (9 containere) SI
    ambele momeli plantate la fiecare deploy, deci toate caile astea exista
    acolo, iar fisierul instalat trebuie sa fie identic cu cel livrat: filtrul
    n-are voie sa schimbe nimic pe gazda unde nu e nimic de filtrat.

    Acopera si liniile `-w`, nu doar `-F dir=`: de cand runda 2 a aratat ca
    nucleul refuza si un `-w` pe o cale absenta, o regresie care ar redeveni
    dependenta de ce are din intamplare masina de test trebuie prinsa aici,
    la fel ca la `-F dir=`.
    """
    shipped = (REPO / "deploy" / "audit" / "sentinel.rules").read_text(
        encoding="utf-8")
    dirs = sorted(set(re.findall(r"-F dir=(\S+)", shipped)))
    watches = sorted(set(re.findall(r"^-w\s+(\S+)", shipped, re.M)))
    assert dirs, "fisierul livrat nu mai are reguli `-F dir=`; testul n-ar pazi nimic"
    assert watches, "fisierul livrat nu mai are reguli `-w`; testul n-ar pazi nimic"

    # Fiecare director din fisierul livrat primeste o cale care CHIAR exista pe
    # masina asta. Substitutia e generata din fisier, deci o regula `dir=` noua
    # nu poate scapa neacoperita.
    rewritten = shipped
    for i, d in enumerate(dirs):
        real = tmp_path / f"d{i}"
        real.mkdir()
        rewritten = rewritten.replace("-F dir=" + d, "-F dir=" + _p(real))

    # Fiecare cale de `-w`, la fel, dar rescrisa LINIE CU LINIE, nu printr-un
    # `.replace()` global: `/etc/sudoers` e prefix literal al lui
    # `/etc/sudoers.d`, iar o inlocuire globala ar fi lovit ambele cai pentru
    # un singur token. Nucleul cere doar ca inode-ul sa existe, nu un anume
    # tip, deci un fisier gol e suficient chiar si pentru o cale care in
    # productie e un director.
    out_lines = []
    seen: dict[str, str] = {}
    counter = 0
    for line in rewritten.splitlines(keepends=True):
        m = re.match(r"^(-w\s+)(\S+)(.*)$", line, re.S)
        if m:
            old_path = m.group(2)
            if old_path not in seen:
                real = tmp_path / f"w{counter}"
                counter += 1
                real.write_text("", encoding="utf-8")
                seen[old_path] = _p(real)
            line = m.group(1) + seen[old_path] + m.group(3)
        out_lines.append(line)
    rewritten = "".join(out_lines)

    src = tmp_path / "in.rules"
    dest = tmp_path / "kept.rules"
    src.write_text(rewritten, encoding="utf-8", newline='\n')
    proc = _run(
        "set -euo pipefail\n"
        + _func(INSTALL, "audit_rules_for_this_host") + "\n"
        f'audit_rules_for_this_host "{_p(dest)}" < "{_p(src)}"\n',
        tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout == "", f"s-a taiat ceva desi toate caile exista: {proc.stdout!r}"
    assert dest.read_text(encoding="utf-8") == rewritten, \
        "fisierul instalat difera de cel livrat pe o gazda unde nu e nimic de filtrat"


# ===========================================================================
# Pasul 35 — acum în ALWAYS_STEPS, deci rulează la FIECARE deploy
# ===========================================================================
def _suricata_step(tmp_path: Path, *, test_rc: int = 0,
                   needs_restart: bool = True,
                   stats_status: int = 1) -> subprocess.CompletedProcess:
    """Rulează `step_suricata` LIVRATĂ, cu binare momeală și cu cele două căi din
    /etc mutate în tmp. `systemctl` își scrie argumentele într-un fișier, ca
    întrebarea „a fost repornit demonul?" să aibă un răspuns observat, nu unul
    dedus din codul de ieșire.

    `stats_status` momește rezultatul editării stats.log — 1 (deja dezactivat)
    implicit, ca testele scrise înainte de acea schimbare să vadă exact
    decizia de repornire pe care o verificau: cea luată din argv, nu din
    stats.log."""
    binpath = tmp_path / "bin"
    calls = tmp_path / "systemctl-calls.txt"
    defaults = tmp_path / "default-suricata"
    dropin_dir = tmp_path / "dropin"
    logdir = tmp_path / "log-suricata"

    _stub(binpath, "systemctl", 'echo "$*" >> "' + _p(calls) + '"\nexit 0\n')
    _stub(binpath, "suricata-update", "exit 0\n")
    # `install -d -m 0750` nu poate pune modul pe mașina asta (același motiv
    # pentru care testul din test_installer_external_tools.py e sărit). Momeala
    # face partea care contează aici — creează directorul — și lasă modul în
    # pace; testul ăsta se uită la repornirea demonului, nu la permisiuni.
    _stub(binpath, "install", """
dirs=()
while [ $# -gt 0 ]; do
    case "$1" in
        -d) shift ;;
        -m|-o|-g) shift 2 ;;
        *) dirs+=("$1"); shift ;;
    esac
done
mkdir -p "${dirs[@]}"
exit 0
""")
    _stub(binpath, "suricata", f"exit {test_rc}\n")
    _stub(binpath, "ip", """
case "$*" in
    *"route show default"*) echo "default via 10.30.1.1 dev enp0s3 proto dhcp" ;;
    *"addr show"*)          echo "2: enp0s3 inet 203.0.113.9/24 scope global enp0s3" ;;
esac
exit 0
""")

    body = _func(INSTALL, "step_suricata") \
        .replace("/etc/systemd/system/suricata.service.d", _p(dropin_dir)) \
        .replace("/var/log/suricata", _p(logdir))

    restart_stub = ("suricata_needs_restart() { printf 'stubul cere repornire'; return 0; }"
                    if needs_restart else
                    "suricata_needs_restart() { return 1; }")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        "SURICATA_OK=1\n"
        "BPF_HINT=\n"
        f'SURICATA_YAML="{_p(tmp_path / "suricata.yaml")}"\n'
        + body + "\n"
        # Momelile vin DUPĂ corpul livrat, ca să bată definițiile din distro.sh
        # și install.sh pe care testul ăsta nu le are în vizor.
        "pkg_install() { return 0; }\n"
        "suricata_pkg() { echo suricata; }\n"
        'suricata_defaults_file() { echo "' + _p(defaults) + '"; }\n'
        "suricata_dropin_body() { echo '[Service]'; }\n"
        + restart_stub + "\n"
        "suricata_eve_size() { echo 0; }\n"
        "suricata_report_effect() { echo REPORT-RAN; }\n"
        f"suricata_disable_stats_output() {{ printf 'stats stub status={stats_status}'; return {stats_status}; }}\n"
        "suricata_stats_size() { echo 0; }\n"
        "suricata_report_stats_effect() { echo STATS-REPORT-RAN; }\n"
        "step_suricata\n"
        'echo "STEP-RC=$?"\n'
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    proc.calls = calls.read_text(encoding="utf-8") if calls.exists() else ""  # type: ignore[attr-defined]
    return proc


def test_the_stats_effect_is_checked_on_every_deploy_not_only_when_it_changed(tmp_path):
    """Un `stats.log` reînviat de un upgrade de pachet e prins la deploy-ul următor.

    Pana pe care o previne: `dnf`/`apt` pot restaura `suricata.yaml` la varianta
    împachetată printr-o fuziune de conffile, deci `enabled: yes` se poate
    întoarce fără ca nimeni s-o ceară. Dacă verificarea de efect ar rula numai
    la deploy-ul care TOCMAI a editat fișierul (`stats_status == 0`), atunci
    exact deploy-ul de după restaurare — singurul care ar fi putut s-o observe —
    ar tăcea, iar cei 120 MB/zi s-ar întoarce nevăzuți.

    Măsurat de verificator pe 30 august 2026: mutarea apelului înapoia acelei
    condiții lăsa TOATĂ suita verde. Invariantul era corect implementat și
    nepăzit de nimic, adică la o refactorizare distanță de a se pierde.

    Se verifică pe toate cele trei stări pe care le poate întoarce editarea, nu
    doar pe cea comodă: tocmai dezactivat, deja dezactivat, formă nerecunoscută.
    """
    for stats_status in (0, 1, 2):
        proc = _suricata_step(tmp_path, stats_status=stats_status)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "STATS-REPORT-RAN" in proc.stdout, (
            f"cu stats_status={stats_status} nu s-a verificat efectul asupra "
            f"lui stats.log: {proc.stdout!r}")


def test_a_rejected_suricata_config_does_not_abort_the_rest_of_the_deploy(tmp_path):
    """Pasul 35 e în ALWAYS_STEPS de pe 26 august, deci rulează la fiecare
    deploy. Un `die` aici ar opri rularea ÎNAINTE de pasul 37 (regulile auditd),
    înainte de proba de fum și înainte ca pasul 40 să-i spună ceva operatorului:
    un set de reguli IDS stricat ar lua cu el toată livrarea."""
    proc = _suricata_step(tmp_path, test_rc=1)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "STEP-RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert "rejected this configuration" in proc.stderr, proc.stderr


def test_a_rejected_suricata_config_does_not_restart_the_running_daemon(tmp_path):
    """Ce rulează acum a pornit dintr-o configurație care a trecut. Repornirea
    peste una care tocmai a picat transformă un avertisment în pană de IDS."""
    proc = _suricata_step(tmp_path, test_rc=1)
    # Fără astea două, un pas care ar muri înainte de `suricata -T` ar lăsa
    # fișierul de apeluri gol și testul ar trece fără să fi verificat nimic.
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "rejected this configuration" in proc.stderr, proc.stderr
    assert "restart" not in proc.calls, \
        f"demonul a fost repornit peste o configurație respinsă: {proc.calls!r}"
    assert "REPORT-RAN" not in proc.stdout, \
        "s-a raportat starea capturii lângă un avertisment de configurație respinsă"


def test_a_repeated_deploy_does_not_bounce_the_ids_for_nothing(tmp_path):
    """Cealaltă jumătate a intrării în ALWAYS_STEPS. Dacă pasul ar reporni
    necondiționat, fiecare deploy ar lăsa gazda fără IDS cât se reîncarcă 46k de
    reguli — inclusiv deploy-urile care nu schimbă nimic, care acum sunt
    majoritatea."""
    proc = _suricata_step(tmp_path, test_rc=0, needs_restart=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restart" not in proc.calls, \
        f"IDS-ul a fost repornit degeaba: {proc.calls!r}"
    assert "already runs with these options" in proc.stdout, proc.stdout
    assert "REPORT-RAN" in proc.stdout, "efectul nu mai e verificat deloc"


def test_a_config_that_passes_still_reaches_the_restart(tmp_path):
    """Dacă `suricata -T` ar fi devenit o poartă prin care nu trece nimic,
    reparația din 25 august n-ar mai ajunge niciodată în procesul care rulează —
    și ăsta e chiar motivul pentru care pasul a intrat în ALWAYS_STEPS."""
    proc = _suricata_step(tmp_path, test_rc=0, needs_restart=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restart suricata" in proc.calls, proc.calls
    assert "REPORT-RAN" in proc.stdout, proc.stdout


def test_disabling_stats_forces_a_restart_even_when_argv_is_unchanged(tmp_path):
    """Dezactivarea stats.log e o schimbare în FIȘIER, nu în argv — verificarea
    pe linia de comandă (`suricata_needs_restart`) n-o poate vedea singură.
    Fără un motiv separat de repornire aici, demonul ar continua să scrie
    stats.log sub configurația VECHE la nesfârșit: exact `systemctl enable
    --now` peste un serviciu deja pornit din CLAUDE.md, aplicat unei schimbări
    de fișier în loc de uneia de linie de comandă."""
    proc = _suricata_step(tmp_path, test_rc=0, needs_restart=False, stats_status=0)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restart suricata" in proc.calls, proc.calls


def test_an_unrecognised_stats_shape_does_not_force_a_restart_on_its_own(tmp_path):
    """Cealaltă jumătate. Dacă editarea n-a schimbat nimic (fișier nerecunoscut,
    deja dezactivat, sau lipsă), o repornire pornită din motivul ăsta n-ar face
    decât să lase gazda fără IDS 2-3 minute pentru absolut niciun efect."""
    proc = _suricata_step(tmp_path, test_rc=0, needs_restart=False, stats_status=2)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restart" not in proc.calls, \
        f'repornire fără motiv real, doar din starea „nerecunoscut": {proc.calls!r}'


# ===========================================================================
# B3 — stats.log: o singură linie, editată o singură dată
# ===========================================================================
# Un suricata.yaml de test cu TREI apariții ale cuvântului „stats" — exact cât
# poartă un fișier împachetat real:
#   * blocul de la nivelul de sus (contorul intern, `interval:`, fără
#     `filename:`) — NU trebuie atins, altfel `stats` din eve.json ar tăcea și
#     el, ceea ce task-ul interzice explicit;
#   * `- stats:` cuibărit în `types:` al `eve-log` (fără `filename:` nici el);
#   * `- stats:` din `outputs:`, singurul cu `filename: stats.log` — ăsta e
#     singura țintă.
STATS_YAML = """\
stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - stats:
            totals: yes
            threads: no
  - stats:
      enabled: {value}
      filename: stats.log
      append: yes
      totals: yes
      threads: no
"""


def _disable_stats(tmp_path: Path, yaml_text: str) -> tuple[int, str, str]:
    """Rulează `suricata_disable_stats_output` LIVRATĂ peste un suricata.yaml de
    test. Întoarce (cod, mesaj, conținutul fișierului DUPĂ rulare) — codul pe
    stderr, separat de mesaj, ca să nu se amestece."""
    yaml_path = tmp_path / "suricata.yaml"
    yaml_path.write_text(yaml_text, encoding="utf-8", newline="\n")
    script = (
        "set -euo pipefail\n"
        f'SURICATA_YAML="{_p(yaml_path)}"\n'
        + _func(INSTALL, "suricata_disable_stats_output") + "\n"
        "rc=0\n"
        'msg="$(suricata_disable_stats_output)" || rc=$?\n'
        'printf "%s" "$msg"\n'
        'printf "RC=%s\\n" "$rc" >&2\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rc_lines = [l for l in proc.stderr.splitlines() if l.startswith("RC=")]
    assert rc_lines, proc.stderr
    rc = int(rc_lines[0].split("=")[1])
    return rc, proc.stdout, yaml_path.read_text(encoding="utf-8")


def test_stats_output_is_disabled_and_marked(tmp_path):
    """Cazul măsurat pe gazdă: `enabled: yes` sub `filename: stats.log`. Fără
    editarea asta, fișierul de 120 MB/zi rămâne exact așa cum a scris pachetul
    — ceea ce a și făcut, până acum."""
    rc, msg, after = _disable_stats(tmp_path, STATS_YAML.format(value="yes"))
    assert rc == 0, msg
    assert "disabled stats.log output" in msg
    assert "enabled: no  # SENTINEL-DISABLED" in after
    assert after.count("filename: stats.log") == 1
    # Vecinii nu s-au mișcat.
    assert "enabled: yes\n  interval: 8" in after, "blocul de contoare interne a fost atins"
    assert "- fast:\n      enabled: yes" in after, "output-ul fast a fost atins"
    assert "- eve-log:\n      enabled: yes" in after, "output-ul eve-log a fost atins"
    assert "- stats:\n            totals: yes" in after, \
        "stats-ul cuibărit în types-ul eve-log a fost atins"


def test_a_second_run_is_idempotent_and_does_not_double_mark(tmp_path):
    """A doua rulare pe fișierul deja editat nu are voie să mai scrie nimic —
    altfel fiecare deploy ar adăuga câte un comentariu nou pe aceeași linie."""
    rc1, msg1, after1 = _disable_stats(tmp_path, STATS_YAML.format(value="yes"))
    assert rc1 == 0, msg1
    rc2, msg2, after2 = _disable_stats(tmp_path, after1)
    assert rc2 == 1, msg2
    assert after2 == after1, "a doua rulare a schimbat un fișier deja dezactivat"
    assert after1.count("SENTINEL-DISABLED") == 1


def test_an_operators_own_disabled_line_is_left_exactly_as_written(tmp_path):
    """Dacă operatorul a pus deja `enabled: no`, fără comentariul nostru, linia
    rămâne a lui — nu i-o „adoptăm" adăugând comentariul peste ea."""
    yaml_text = STATS_YAML.format(value="no")
    rc, msg, after = _disable_stats(tmp_path, yaml_text)
    assert rc == 1, msg
    assert after == yaml_text
    assert "SENTINEL-DISABLED" not in after


def test_a_removed_stats_output_is_reported_not_guessed_at(tmp_path):
    """Dacă operatorul a scos complet output-ul, nu mai există ce dezactiva —
    și pasul trebuie s-o spună, nu s-o treacă sub tăcere ca „succes"."""
    without = STATS_YAML.format(value="yes").replace(
        "  - stats:\n      enabled: yes\n      filename: stats.log\n"
        "      append: yes\n      totals: yes\n      threads: no\n", "")
    assert "filename: stats.log" not in without, "montajul testului nu a scos blocul"
    rc, msg, after = _disable_stats(tmp_path, without)
    assert rc == 2, msg
    assert 'no "filename: stats.log"' in msg
    assert after == without


def test_two_stats_log_outputs_are_left_alone_as_ambiguous(tmp_path):
    """Două linii `filename: stats.log` înseamnă că nu se știe care e cea
    reală — o editare la întâmplare ar putea schimba output-ul greșit."""
    doubled = STATS_YAML.format(value="yes") + (
        "  - stats:\n      enabled: yes\n      filename: stats.log\n"
        "      append: yes\n      totals: yes\n      threads: no\n")
    rc, msg, after = _disable_stats(tmp_path, doubled)
    assert rc == 2, msg
    assert "expected exactly 1" in msg
    assert after == doubled


def test_a_reordered_block_is_not_guessed_at(tmp_path):
    """Dacă `enabled:` nu mai e imediat deasupra lui `filename: stats.log` —
    fișierul a fost rescris altfel decât ce știe editarea asta să recunoască —
    pasul lasă blocul în pace în loc să ghicească ce linie să schimbe."""
    reordered = STATS_YAML.format(value="yes").replace(
        "      enabled: yes\n      filename: stats.log\n",
        "      filename: stats.log\n      enabled: yes\n")
    rc, msg, after = _disable_stats(tmp_path, reordered)
    assert rc == 2, msg
    assert "not a plain" in msg
    assert after == reordered


def test_a_missing_suricata_yaml_is_unknown_not_fine(tmp_path):
    """Fără fișier, nu e nimic de dezactivat — și codul 2 (necunoscut) e
    obligatoriu aici, nu 0 sau 1, care ar însemna ambele „stats.log e tratat"."""
    missing = tmp_path / "does-not-exist.yaml"
    script = (
        "set -euo pipefail\n"
        f'SURICATA_YAML="{_p(missing)}"\n'
        + _func(INSTALL, "suricata_disable_stats_output") + "\n"
        "rc=0\n"
        "suricata_disable_stats_output || rc=$?\n"
        'printf "RC=%s" "$rc"\n'
    )
    proc = _run(script, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RC=2" in proc.stdout, proc.stdout


def _stats_effect(tmp_path: Path, *, grows: bool,
                  before_bytes: int = 500) -> subprocess.CompletedProcess:
    """Rulează `suricata_report_stats_effect` LIVRATĂ. `sleep` momeală face
    fișierul să crească DOAR dacă i se cere — proba pentru „nu mai crește"
    trebuie să vină din octeți reali, nu dintr-o linie din yaml necitită de
    nimeni altcineva în acest test."""
    binpath = tmp_path / "bin"
    stats = tmp_path / "stats.log"
    stats.write_bytes(b"x" * before_bytes)
    grow = f'printf x >> "{_p(stats)}"' if grows else "true"
    _stub(binpath, "sleep", f"{grow}\nexit 0\n")
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'SURICATA_STATS="{_p(stats)}"\n'
        "SURICATA_STATS_WAIT_S=10\n"
        "SURICATA_YAML=/etc/suricata/suricata.yaml\n"
        + _func(INSTALL, "suricata_stats_size") + "\n"
        + _func(INSTALL, "suricata_report_stats_effect") + "\n"
        f'suricata_report_stats_effect "{before_bytes}"\n'
    )
    return _run(script, tmp_path, extra_path=binpath)


def test_a_stats_log_that_keeps_growing_after_being_disabled_is_reported(tmp_path):
    """Faptul, nu intenția: dacă `enabled: no` e scris și fișierul tot crește,
    editarea n-a avut efect — un restart care n-a prins, sau altceva scrie
    acolo — și un `[+]` aici ar fi exact minciuna pe care CLAUDE.md o
    interzice."""
    proc = _stats_effect(tmp_path, grows=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout, proc.stdout
    assert "STILL being written" in proc.stderr, proc.stderr


def test_a_stats_log_that_stays_flat_earns_the_success_line(tmp_path):
    """Cealaltă jumătate: fără proba asta, „am scris enabled: no" ar fi tot ce
    ar dovedi vreodată pasul — fix fișierul pe disc care nu dovedește
    încărcarea, din CLAUDE.md."""
    proc = _stats_effect(tmp_path, grows=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "the output is off" in proc.stdout, proc.stdout
    assert proc.stderr.strip() == "", proc.stderr


def test_sentinels_own_suppressions_come_before_any_third_party_one():
    """Filtrul de la instalare se uită la gazdă o singură dată. Un director care
    dispare ÎNTRE deploy-uri — docker dezinstalat — face nucleul să refuze regula
    la următoarea pornire, iar `auditctl -R` se oprește acolo și duce cu el tot
    ce urmează. Măsurat pe VM: o regulă `-F dir=` deja încărcată dispare din
    `auditctl -l` în clipa în care directorul e șters. Cu suprimările proprii ale
    Sentinelului puse întâi, un director străin care se evaporă costă doar el
    însuși; puse după, ar costa exact ce a costat și prima oară — Sentinel își
    auditează propriile scrieri până la deploy-ul următor."""
    rules = (REPO / "deploy" / "audit" / "sentinel.rules").read_text(encoding="utf-8")
    dirs = re.findall(r"^-a\s+never,exit\s+-F\s+dir=(\S+)\s*$", rules, re.M)
    assert dirs, "nu mai există reguli `never` cu `dir=`; testul n-ar păzi nimic"

    ours = [d for d in dirs if d in ("/opt/sentinel", "/var/lib/sentinel")]
    assert len(ours) == 2, f"suprimările proprii ale Sentinelului lipsesc: {dirs}"

    last_ours = max(dirs.index(d) for d in ours)
    theirs = [d for d in dirs if d not in ours]
    for d in theirs:
        assert dirs.index(d) > last_ours, \
            f"{d} e înaintea suprimărilor Sentinelului; dacă dispare, le ia cu el"


# ===========================================================================
# Funcționalitatea 05 — momelile (`install_canary_baits`)
# ===========================================================================
def _canary_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Cele trei căi pe care le folosește orice test din secțiunea asta, toate
    sub `tmp_path` — inclusiv fișierul de stare, ca niciun test să nu scrie
    sub /etc/sentinel de pe mașina care rulează suita."""
    return (tmp_path / "root" / ".pgpass",
            tmp_path / "root" / ".aws" / "credentials",
            tmp_path / "etc-sentinel" / "canary-state")


def _canary_step(tmp_path: Path, foreign_name: str,
                  extra_path: Path | None = None) -> subprocess.CompletedProcess:
    """O singură trecere prin `install_canary_baits` LIVRATĂ, peste orice a mai
    rămas pe disc din trecerile anterioare pe același `tmp_path` — inclusiv
    fișierul de stare, exact ca între două deploy-uri reale pe aceeași gazdă.
    """
    pgpass, aws, state = _canary_paths(tmp_path)
    foreign = tmp_path / foreign_name
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'CANARY_PGPASS_PATH="{_p(pgpass)}"\n'
        f'CANARY_AWS_CREDS_PATH="{_p(aws)}"\n'
        f'CANARY_STATE_PATH="{_p(state)}"\n'
        + _func(INSTALL, "_canary_content") + "\n"
        + _func(INSTALL, "install_canary_baits") + "\n"
        f'install_canary_baits "{_p(foreign)}"\n'
    )
    return _run(script, tmp_path, extra_path=extra_path)


def _canary_harness(tmp_path: Path, *, pre_pgpass: str | None = None,
                    pre_aws: str | None = None
                    ) -> tuple[subprocess.CompletedProcess, Path, Path, Path, Path]:
    """Rulează `install_canary_baits` LIVRATĂ o singură dată. Întoarce și calea
    fișierului de stare, ca testele care simulează un al doilea deploy s-o
    poată citi sau șterge între trecere."""
    pgpass, aws, state = _canary_paths(tmp_path)
    if pre_pgpass is not None:
        pgpass.parent.mkdir(parents=True, exist_ok=True)
        pgpass.write_text(pre_pgpass, encoding="utf-8", newline="\n")
    if pre_aws is not None:
        aws.parent.mkdir(parents=True, exist_ok=True)
        aws.write_text(pre_aws, encoding="utf-8", newline="\n")
    proc = _canary_step(tmp_path, "foreign.txt")
    return proc, pgpass, aws, tmp_path / "foreign.txt", state


def _state_sizes(state: Path) -> dict[str, str]:
    return dict(line.split() for line in state.read_text(encoding="utf-8").splitlines() if line)


def test_a_missing_bait_is_planted_with_the_marker(tmp_path):
    """Prima instalare: fișierul nu există, deci trebuie creat, cu conținutul
    fals și marcajul care rămâne în el pentru un om, nu pentru clasificare —
    și dimensiunea lui trebuie înregistrată în starea de canar, altfel al
    doilea deploy n-are cu ce compara."""
    proc, pgpass, aws, foreign, state = _canary_harness(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert pgpass.exists() and aws.exists()
    assert "sentinel-canary" in pgpass.read_text(encoding="utf-8")
    assert "sentinel-canary" in aws.read_text(encoding="utf-8")
    assert foreign.read_text(encoding="utf-8").strip() == "", \
        "ambele momeli sunt ale noastre, nu ar trebui raportată nicio coliziune"
    assert "bait planted" in proc.stdout, proc.stdout

    recorded = _state_sizes(state)
    assert recorded.get(_p(pgpass)) == str(pgpass.stat().st_size), \
        f"mărimea plantată pentru {pgpass} nu a fost înregistrată corect: {recorded}"
    assert recorded.get(_p(aws)) == str(aws.stat().st_size), \
        f"mărimea plantată pentru {aws} nu a fost înregistrată corect: {recorded}"


def test_the_content_is_not_shaped_like_a_real_secret(tmp_path):
    """Cerut explicit: dacă momeala e exfiltrată, conținutul nu are voie să fie
    confundat de operator cu o credențială reală. Nicio formă de cheie/hash —
    aceeași gardă de formă ca `test_repo_is_sanitised`."""
    proc, pgpass, aws, _, _state = _canary_harness(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for f in (pgpass, aws):
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"[0-9a-fA-F]{32,}", text), \
            f"{f}: arată a hexazecimal generat, poate fi confundat cu un secret real"
        assert not re.search(r"(?=[A-Za-z0-9+/_-]{32,})(?=[a-z]*[A-Z])(?=[A-Za-z]*[0-9])"
                             r"[A-Za-z0-9+/_-]{32,}", text), \
            f"{f}: arată a base64/base64url generat"


def test_a_repeat_deploy_leaves_an_unedited_bait_untouched(tmp_path):
    """Al doilea deploy dintr-o instalare normală: momeala plantată la primul
    rulaj trebuie regăsită la a doua trecere prin MĂRIME, nu prin conținut
    citit din nou — dacă ar fi raportată drept coliziune aici, o gazdă
    nemodificată ar pierde urmărirea de nucleu la fiecare livrare."""
    proc1, pgpass, aws, _, state = _canary_harness(tmp_path)
    assert proc1.returncode == 0, proc1.stdout + proc1.stderr
    original_pgpass = pgpass.read_text(encoding="utf-8")
    original_aws = aws.read_text(encoding="utf-8")

    proc2 = _canary_step(tmp_path, "foreign2.txt")
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    assert pgpass.read_text(encoding="utf-8") == original_pgpass
    assert aws.read_text(encoding="utf-8") == original_aws
    assert proc2.stdout.count("left untouched") == 2, proc2.stdout
    assert (tmp_path / "foreign2.txt").read_text(encoding="utf-8").strip() == "", \
        "o momeală neatinsă a fost raportată drept străină la al doilea deploy"


def test_a_repeat_deploy_never_reads_the_bait_content(tmp_path):
    """Incidentul 65237 (31 august 2026): `install_canary_baits` deschidea
    momeala cu `grep -qF "sentinel-canary" "$path"` ca s-o clasifice, iar asta
    declanșa regula `sentinel_bait -p r` la fiecare livrare de după prima —
    un `critical` fals, emis de instalator împotriva lui însuși, pe conturi
    care nu au făcut nimic. Testul dovedește efectul, nu intenția: dacă
    funcția ar mai invoca `grep` vreodată, comanda-momeală de mai jos ar
    prinde apelul."""
    binpath = tmp_path / "bin"
    marker = tmp_path / "grep_was_called"
    _stub(binpath, "grep", f'''
printf "called with: %s\\n" "$*" >> "{_p(marker)}"
exit 1
''')

    proc1 = _canary_step(tmp_path, "foreign1.txt", extra_path=binpath)
    assert proc1.returncode == 0, proc1.stdout + proc1.stderr
    assert not marker.exists(), \
        "install_canary_baits a citit conținutul momelii la PLANTARE: " + \
        (marker.read_text(encoding="utf-8") if marker.exists() else "")

    proc2 = _canary_step(tmp_path, "foreign2.txt", extra_path=binpath)
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    assert not marker.exists(), \
        "install_canary_baits a invocat grep la al doilea deploy -- exact citirea " \
        "care a produs incidentul 65237: " + \
        (marker.read_text(encoding="utf-8") if marker.exists() else "")


def test_an_operator_edit_that_keeps_the_planted_size_is_left_untouched(tmp_path):
    """Cerința D1: operatorul a editat conținutul păstrându-i lungimea (de
    exemplu a schimbat parola falsă cu alta la fel de lungă). Clasificarea se
    face STRICT pe mărime, dinadins ca să nu mai citească fișierul — o editare
    care păstrează mărimea trebuie tot lăsată în pace, nu rescrisă și nu
    raportată drept coliziune."""
    proc1, pgpass, aws, _, state = _canary_harness(tmp_path)
    assert proc1.returncode == 0, proc1.stdout + proc1.stderr

    original = pgpass.read_text(encoding="utf-8")
    # swapcase() păstrează exact numărul de octeți (ASCII), deci conținutul e
    # vizibil diferit fără să mute mărimea de pe care se face clasificarea.
    edited = original.swapcase()
    assert len(edited.encode("utf-8")) == len(original.encode("utf-8"))
    pgpass.write_text(edited, encoding="utf-8", newline="\n")

    proc2 = _canary_step(tmp_path, "foreign2.txt")
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    assert pgpass.read_text(encoding="utf-8") == edited, "editarea operatorului a fost rescrisă"
    assert "left untouched" in proc2.stdout, proc2.stdout
    assert _p(pgpass) not in (tmp_path / "foreign2.txt").read_text(encoding="utf-8").splitlines(), \
        "o editare de aceeași mărime a fost raportată drept coliziune"


def test_an_operator_edit_that_changes_the_size_loses_the_watch_but_not_the_content(tmp_path):
    """Ce NU acoperă mărimea (documentat și în docs/OPERARE.md): o editare care
    schimbă lungimea fișierului nu mai poate fi deosebită, prin metadate, de
    un fișier real pus acolo din greșeală -- așa că instalatorul o tratează ca
    pe orice cale străină: avertizează, scoate urmărirea de nucleu, dar NU
    rescrie niciodată conținutul. Vizibil, nu tăcut -- exact direcția de eșec
    cerută."""
    proc1, pgpass, aws, _, state = _canary_harness(tmp_path)
    assert proc1.returncode == 0, proc1.stdout + proc1.stderr

    edited = pgpass.read_text(encoding="utf-8") + "extra line appended by the operator\n"
    pgpass.write_text(edited, encoding="utf-8", newline="\n")

    proc2 = _canary_step(tmp_path, "foreign2.txt")
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    assert pgpass.read_text(encoding="utf-8") == edited, "conținutul editat a fost atins"
    assert _p(pgpass) in (tmp_path / "foreign2.txt").read_text(encoding="utf-8").splitlines(), \
        "mărimea schimbată nu a fost raportată drept nesigură"
    assert "NOT planted" in proc2.stderr, proc2.stderr


def test_a_bait_with_no_state_record_is_treated_as_foreign_and_never_overwritten(tmp_path):
    """Ceva ocupă deja calea și nu există nicio înregistrare de stare pentru
    ea -- poate un `.pgpass` real, poate propria momeală de dinainte ca acest
    fișier de stare să existe. Instalatorul nu are voie nici s-o suprascrie,
    nici să pretindă tăcut că a plantat o momeală acolo: raportează calea ca
    „străină", ca apelantul să scoată urmărirea de nucleu de pe ea."""
    real = "127.0.0.1:5432:*:sentinel:S3cr3tRealPassw0rd\n"
    proc, pgpass, aws, foreign, state = _canary_harness(tmp_path, pre_pgpass=real)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert pgpass.read_text(encoding="utf-8") == real, "conținutul real a fost atins"
    assert _p(pgpass) in foreign.read_text(encoding="utf-8").splitlines(), \
        "calea ocupată de conținut fără înregistrare nu a fost raportată apelantului"
    assert "NOT planted" in proc.stderr, proc.stderr


def test_a_host_restored_from_backup_loses_the_state_and_the_watch_not_silently(tmp_path):
    """Direcția de eșec cerută explicit: o gazdă restaurată dintr-un backup
    dinainte ca acest fișier de stare să existe își pierde propria momeală din
    evidență. Consecința trebuie să fie un avertisment și o regulă nearmată --
    vizibil în ieșirea deploy-ului -- niciodată o citire tăcută a conținutului
    ca să recupereze clasificarea."""
    proc1, pgpass, aws, _, state = _canary_harness(tmp_path)
    assert proc1.returncode == 0, proc1.stdout + proc1.stderr
    original_pgpass = pgpass.read_text(encoding="utf-8")

    state.unlink()  # exact ce lasă în urmă o restaurare dintr-un backup vechi

    proc2 = _canary_step(tmp_path, "foreign2.txt")
    assert proc2.returncode == 0, proc2.stdout + proc2.stderr
    assert pgpass.read_text(encoding="utf-8") == original_pgpass, \
        "conținutul propriei momele a fost atins după pierderea stării"
    foreign2 = (tmp_path / "foreign2.txt").read_text(encoding="utf-8").splitlines()
    assert _p(pgpass) in foreign2 and _p(aws) in foreign2, \
        "starea lipsă trebuia să claseze AMBELE momeli drept fără evidență, nu doar una"
    assert "NOT planted" in proc2.stderr, proc2.stderr


def test_the_foreign_bait_path_is_dropped_from_the_installed_rules(tmp_path):
    """Efectul, nu doar avertismentul: linia `-w` pentru o cale fără
    înregistrare de stare nu are voie să ajungă în fișierul instalat, altfel
    nucleul ar supraveghea conținut nesigur sub eticheta unei momele."""
    real = "127.0.0.1:5432:*:sentinel:S3cr3tRealPassw0rd\n"
    pgpass = tmp_path / "root" / ".pgpass"
    aws = tmp_path / "root" / ".aws" / "credentials"
    state = tmp_path / "etc-sentinel" / "canary-state"
    pgpass.parent.mkdir(parents=True, exist_ok=True)
    pgpass.write_text(real, encoding="utf-8", newline="\n")

    binpath = tmp_path / "bin"
    scriptdir = tmp_path / "deploy"
    (scriptdir / "audit").mkdir(parents=True)
    rules = (f"-w {_p(pgpass)} -p r -k sentinel_bait\n"
             f"-w {_p(aws)} -p r -k sentinel_bait\n"
             "-b 8192\n--backlog_wait_time 60000\n")
    (scriptdir / "audit" / "sentinel.rules").write_text(rules, encoding="utf-8", newline="\n")
    _stub(binpath, "augenrules", "exit 0\n")
    _stub(binpath, "auditctl", f"""
case "${{1:-}}" in
    -l) : ;;
    -s) printf '{HEALTHY_STATUS}' ;;
esac
exit 0
""")

    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'CANARY_PGPASS_PATH="{_p(pgpass)}"\n'
        f'CANARY_AWS_CREDS_PATH="{_p(aws)}"\n'
        f'CANARY_STATE_PATH="{_p(state)}"\n'
        f'SCRIPT_DIR="{_p(scriptdir)}"\n'
        f'AUDITD_RULES_DEST="{_p(tmp_path / "installed.rules")}"\n'
        "AUDITD_LOG_PATH=/var/log/audit/audit.log\n"
        + _func(INSTALL, "_canary_content") + "\n"
        + _func(INSTALL, "install_canary_baits") + "\n"
        + _func(INSTALL, "audit_rule_signatures") + "\n"
        + _func(INSTALL, "audit_rules_for_this_host") + "\n"
        + _func(INSTALL, "install_audit_rules") + "\n"
        "install_audit_rules\n"
    )
    proc = _run(script, tmp_path, extra_path=binpath)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    installed = (tmp_path / "installed.rules").read_text(encoding="utf-8")
    assert _p(pgpass) not in installed, (
        "o cale fără înregistrare de stare a ajuns totuși în fișierul instalat "
        "pentru nucleu:\n" + installed)
    assert _p(aws) in installed, "momeala fără coliziune nu are voie să dispară odată cu cealaltă"


def test_baits_are_planted_before_the_rules_are_staged(tmp_path):
    """`-w` cere ca fișierul să existe la ÎNCĂRCARE. Regulile trebuie scrise
    DUPĂ ce momelile au fost plantate, altfel nucleul refuză exact regula pe
    care funcționalitatea asta o adaugă.

    Comparat pe APELURI reale, nu pe orice apariție a numelui — un comentariu
    care menționează cealaltă funcție, scris mai sus din întâmplare, ar trece
    verificarea fără să spună nimic despre ordinea în care rulează codul.
    """
    body = _func(INSTALL, "install_audit_rules")
    call = re.search(r"^\s*install_canary_baits\b", body, re.M)
    stage = re.search(r'audit_rules_for_this_host\s+"\$staged"', body)
    assert call and stage, "una dintre cele două invocări a dispărut din pas"
    assert call.start() < stage.start(), \
        "momelile se plantează după ce fișierul de reguli a fost deja pregătit"
