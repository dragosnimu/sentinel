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
-w /etc/passwd -p wa -k sentinel_identity
-w /etc/shadow -p wa -k sentinel_identity
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -F auid>=1000 -F auid!=unset -k sentinel_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -F auid>=1000 -F auid!=unset -k sentinel_exec
-b 8192
--backlog_wait_time 60000
-a never,exit -F dir=/var/lib/docker
-a never,exit -F dir=/opt/sentinel
"""

ALL_LOADED = """\
-w /etc/passwd -p wa -k sentinel_identity
-w /etc/shadow -p wa -k sentinel_identity
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/nc -F auid>=1000 -F auid!=-1 -F key=sentinel_exec
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/curl -F auid>=1000 -F auid!=-1 -F key=sentinel_exec
-a never,exit -F dir=/var/lib/docker
-a never,exit -F dir=/opt/sentinel
"""

HEALTHY_STATUS = ("enabled 1\nfailure 1\npid 31813\nrate_limit 0\n"
                  "backlog_limit 8192\nlost 0\nbacklog 0\n"
                  "backlog_wait_time 60000\nbacklog_wait_time_actual 0\n")


def _audit_harness(tmp_path: Path, *, rules: str = SYNTHETIC_RULES,
                   loaded: str = ALL_LOADED, status: str = HEALTHY_STATUS,
                   augen_out: str = "", augen_rc: int = 0,
                   tools_present: bool = True) -> subprocess.CompletedProcess:
    """Rulează `install_audit_rules` LIVRATĂ, cu `augenrules` și `auditctl`
    momeală. `loaded` e exact ce răspunde `auditctl -l` — în forma în care o
    scrie NUCLEUL, cu `auid!=-1` și `-F key=`, nu în forma din fișier."""
    binpath = tmp_path / "bin"
    scriptdir = tmp_path / "deploy"
    (scriptdir / "audit").mkdir(parents=True)
    (scriptdir / "audit" / "sentinel.rules").write_text(
        rules, encoding="utf-8", newline="\n")

    loadedfile = tmp_path / "loaded.txt"
    loadedfile.write_text(loaded, encoding="utf-8", newline="\n")
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
        + _func(INSTALL, "audit_rule_signatures") + "\n"
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
        l for l in ALL_LOADED.splitlines() if "/opt/sentinel" not in l) + "\n"
    proc = _audit_harness(tmp_path, loaded=without)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[+]" not in proc.stdout
    assert "dir /opt/sentinel: 0 of 1 in the kernel" in proc.stderr, proc.stderr


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
        l for l in ALL_LOADED.splitlines() if "/opt/sentinel" not in l) + "\n"
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
    # 30 de reguli + 2 opțiuni, măsurat pe fișierul livrat.
    assert len([s for s in sigs if not s.startswith("option ")]) == 30, sigs
