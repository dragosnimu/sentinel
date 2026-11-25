"""Gazda momeală pentru testele fazelor `os`, `reboot`, `verify`, `preflight` și ale baseline-ului.
Nu e fișier de teste.

O singură clasă, `FakeHost`, scrie în `tmp/fh/` starea (fișiere simple + `systemctl.json`) și în
`tmp/bin/` momelile pentru dnf, rpm, needs-restarting, grubby, uname, nginx, curl, pgrep, df, shutdown,
auditctl, nft, runuser, mysqladmin și systemctl. Momelile NOTEAZĂ apelurile (`fh/calls.log`) — testele
„nu atinge nimic" citesc jurnalul. Valorile implicite descriu o gazdă SĂNĂTOASĂ, ca baseline-ul luat
cu `take_snapshot` pe ea să fie unul real, iar fiecare test strică DOAR ce vrea să arate.

Ce NU reproduce: dnf-ul, systemd-ul, nucleul. Formele de ieșire sunt cele MĂSURATE pe gazdă (19 nov
2026): `dnf history list`/`info`, `dnf check-update` (cod 100), `needs-restarting -r` (cod 1 = reboot),
`systemctl list-units --plain`, `grubby --default-kernel`. Un `dnf upgrade` momeală aplică efectul
SCRIPTAT în `dnf-mode`, nu unul dedus: `ok` (schimbă pachetele, nucleul, istoricul), `noop` (iese cu 0 și
nu schimbă nimic) sau `fail` (iese cu 1 și nu schimbă nimic).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from _su_shell import FAKE_DOCKER_PY, make_bin, posix, write_exec
import sys

OLD_K = "5.14.0-687.57.1.el9_8.x86_64"
NEW_K = "5.14.0-741.22.1.el9_9.x86_64"

SYSTEMCTL_PY = Path(__file__).with_name("_fake_systemctl.py")


class FakeHost:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.fh = tmp / "fh"
        self.fh.mkdir(exist_ok=True)
        (self.fh / "boot").mkdir(exist_ok=True)
        (self.fh / "http").mkdir(exist_ok=True)
        self.units = {
            "nginx.service": {"state": "active", "enabled": "enabled", "restarts": 0, "enter": 100},
            "sshd.service": {"state": "active", "enabled": "enabled", "restarts": 0, "enter": 90},
            "docker.service": {"state": "active", "enabled": "enabled", "restarts": 0, "enter": 80},
            "sentinel-web.service": {"state": "active", "enabled": "enabled", "restarts": 0, "enter": 110},
            "sentinel-detect.service": {"state": "active", "enabled": "enabled", "restarts": 0, "enter": 111},
            "php82-php-fpm.service": {"state": "active", "enabled": "disabled", "restarts": 0, "enter": 120},
            "dnf-makecache.service": {"state": "failed", "enabled": "static", "restarts": 0, "enter": 0},
        }
        self.timers = {"sentinel-health.timer": "active", "vps-watchdog.timer": "active"}
        self.flap: list[str] = []
        self.ctimers: list[str] = []
        self.save_units()
        self.w("rpm-now", "".join(f"pkg{i}-1.0-1.el9.x86_64\n" for i in range(60)))
        self.w("kernels", OLD_K + "\n")
        self.w("grubby", f"/boot/vmlinuz-{OLD_K}\n")
        self.w("uname", OLD_K + "\n")
        self.w("pending", "")
        self.w("history-id", "63\n")
        self.w("dnf-mode", "ok")
        self.w("nr-rc", "0")
        self.w("nginx-rc", "0")
        self.w("makecache-rc", "0")
        self.w("dnf-check-rc", "0")
        self.w("pgrep-rc", "1")
        self.w("shutdown-mode", "ok")
        self.w("boot_id", "boot-A\n")
        self.w("audit-rules", "31")
        self.w("nft-tables", "table inet sentinel\n")
        for name in ("a.example.ro", "b.example.ro"):
            self.w(f"http/{name}", "200")
        self.w("http/sentinel-web", "200")
        self.w("boot_files", "present")
        self.w("os-release", 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.7"\n')
        self.set_boot_files(OLD_K)

    # -- stare ---------------------------------------------------------------
    def w(self, name: str, text: str) -> None:
        (self.fh / name).write_text(text, encoding="utf-8", newline="\n")

    def r(self, name: str) -> str:
        return (self.fh / name).read_text(encoding="utf-8")

    def save_units(self) -> None:
        self.w("systemctl.json", json.dumps({"units": self.units, "timers": self.timers, "flap": self.flap, "ctimers": self.ctimers}))

    def set_boot_files(self, kernel: str, *, initramfs: bool = True) -> None:
        (self.fh / "boot" / f"vmlinuz-{kernel}").write_text("k" * 2000, encoding="utf-8")
        ini = self.fh / "boot" / f"initramfs-{kernel}.img"
        if initramfs:
            ini.write_text("i" * 2000, encoding="utf-8")
        elif ini.exists():
            ini.unlink()

    def pending(self, names: list[str], *, long: bool = False) -> None:
        """`long`: linii lungi, ca ieșirea (342 de linii pe gazdă) să depășească tamponul conductei
        (64 KB) și un `| head` să închidă conducta cât producătorul mai scrie — altfel SIGPIPE nu se
        poate provoca."""
        repo = "baseos-" + "x" * 240 if long else "baseos"
        pad = "-" + "n" * 200 if long else ""     # nume lungi: ieșirea lui awk (nu doar a lui dnf) depășește tamponul
        self.w("pending", "".join(f"{n}{pad}.x86_64    1.2-3.el9    {repo}\n" for n in names))

    def upgrade_result(self, *, new_kernel: bool = True, default_new: bool = True) -> None:
        """Ce schimbă un `dnf upgrade` reușit: pachete noi, nucleu nou (opțional), tranzacția #64."""
        self.w("rpm-after", "".join(f"pkg{i}-2.0-1.el9.x86_64\n" for i in range(60)))
        self.w("kernels-after", (OLD_K + "\n" + NEW_K + "\n") if new_kernel else OLD_K + "\n")
        self.w("grubby-after", f"/boot/vmlinuz-{NEW_K}\n" if (new_kernel and default_new) else f"/boot/vmlinuz-{OLD_K}\n")
        if new_kernel:
            self.set_boot_files(NEW_K)

    def http(self, name: str, code: str) -> None:
        self.w(f"http/{name}", code)

    # -- momelile ------------------------------------------------------------
    def install(self, extra_env: dict | None = None) -> tuple[Path, dict]:
        fh = posix(self.fh)
        shims = {
            "dnf": r'''
args="$*"
echo "dnf $args" >> "$FH/calls.log"
case "$args" in
  "upgrade --refresh -y")
    # descriptorii de blocare (10-15) deschiși în dnf: un copil al lui dnf i-ar moșteni
    exec 3>&2 2>/dev/null; open=""; for n in 10 11 12 13 14 15; do true >&$n && open+="$n "; done; exec 2>&3 3>&-; echo "fds: $open" >> "$FH/calls.log"
    case "$(cat "$FH/dnf-mode")" in
      ok) cp "$FH/rpm-after" "$FH/rpm-now"; cp "$FH/kernels-after" "$FH/kernels"; cp "$FH/grubby-after" "$FH/grubby"
          : > "$FH/pending"; echo $(( $(cat "$FH/history-id") + 1 )) > "$FH/history-id"; echo "Complete!"; exit 0 ;;
      noop) echo "Nothing to do."; exit 0 ;;
      fail) echo "Error: Failed to download metadata for repo 'remi-modular'" >&2; exit 1 ;;
    esac ;;
  *check-update*) if [[ -s "$FH/pending" ]]; then cat "$FH/pending"; exit 100; fi; exit 0 ;;
  "history list") [[ -e "$FH/history-fail" ]] && { echo "Error: cannot open history db" >&2; exit 1; }
    printf 'ID     | Command line             | Date and time    | Action(s)      | Altered\n-------------------------------------------------------------------------------\n'
    printf '    %s | update                   | 2026-11-17 22:04 | Upgrade        |    1   \n' "$(cat "$FH/history-id")"
    # istoric lung (>64 KB): `dnf history list | awk '... exit'` ar închide conducta cât dnf mai scrie
    i=0; while (( i < 1500 )); do printf '    0 | filler filler filler filler filler filler filler filler filler filler filler filler\n'; i=$((i+1)); done ;;
  "history info "*) echo "Transaction ID : ${3}"; echo "Return-Code    : $(cat "$FH/history-rc" 2>/dev/null || echo Success)"; echo "Packages Altered:" ;;
  check) exit "$(cat "$FH/dnf-check-rc")" ;;
  "-q makecache --refresh") exit "$(cat "$FH/makecache-rc")" ;;
  *) echo "fake dnf: $args" >&2; exit 99 ;;
esac
''',
            "rpm": r'''
case "$*" in
  "-qa --qf %{NEVRA}\n") sort "$FH/rpm-now" ;;
  "-q kernel-core --qf %{VERSION}-%{RELEASE}.%{ARCH}\n") cat "$FH/kernels" ;;
  "-q --qf %{NAME}-%{VERSION}\n docker-ce") echo docker-ce-27 ;;
  *) echo "fake rpm: $*" >&2; exit 99 ;;
esac
''',
            "needs-restarting": r'''
case "$1" in
  -r) rc="$(cat "$FH/nr-rc")"; [[ "$rc" == 127 ]] && { echo "needs-restarting: command error" >&2; exit 127; }
      [[ "$rc" == 1 ]] && echo "Core libraries or services have been updated since boot-up:" || echo "No core libraries or services have been updated since boot-up-up."; exit "$rc" ;;
  -s) cat "$FH/nr-services" 2>/dev/null; exit 0 ;;
esac
''',
            "grubby": 'cat "$FH/grubby"\n',
            "uname": '[[ "${1:-}" == -r ]] && { cat "$FH/uname"; exit 0; }; exec /usr/bin/uname "$@"\n',
            "nginx": r'''
case "$1" in
  -t) rc="$(cat "$FH/nginx-rc")"; [[ "$rc" == 0 ]] && echo "nginx: configuration file test is successful" >&2 || echo "nginx: [emerg] bad config" >&2; exit "$rc" ;;
  -T) printf 'server {\n  server_name a.example.ro;\n}\nserver {\n  server_name b.example.ro;\n}\n' ;;
esac
''',
            "curl": r'''
name=""; url=""
while [[ $# -gt 0 ]]; do case "$1" in --resolve) name="${2%%:*}"; shift 2;; -w|-o|--max-time) shift 2;; -*) shift;; *) url="$1"; shift;; esac; done
[[ -n "$name" ]] || name="sentinel-web"
printf '%s' "$(cat "$FH/http/$name" 2>/dev/null || echo 000)"
''',
            "pgrep": 'rc="$(cat "$FH/pgrep-rc")"; [[ "$rc" == 0 ]] && echo "4242 dnf"; exit "$rc"\n',
            "df": r'''
if [[ "$*" == *"/boot"* ]]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/sda2 1000000 200000 800000 20%% /boot\n'
else printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/sda3 200000000 130000000 70000000 65%% /\n'; fi
''',
            "shutdown": r'''
echo "shutdown $*" >> "$FH/calls.log"
[[ "$(cat "$FH/shutdown-mode")" == ok ]] && printf 'USEC=1\nWARN_WALL=1\nMODE=reboot\n' > "$SU_SHUTDOWN_SCHEDULED"
exit 0
''',
            "auditctl": r'''n="$(cat "$FH/audit-rules")"; i=0; while (( i < n )); do echo "-w /x -p wa -k sentinel_$i"; i=$((i+1)); done; echo "-a never,exit -S all"''' + "\n",
            "nft": 'cat "$FH/nft-tables"\n',
            "runuser": "exit 0\n",
            "mysqladmin": 'echo "mysqld is alive"\n',
            "systemctl": f'exec "{posix(sys.executable)}" "{posix(SYSTEMCTL_PY)}" "$@"\n',
        }
        bindir = make_bin(self.tmp, shims, docker=True)
        env = {"FH": fh, "SU_BOOT_DIR": posix(self.fh / "boot"), "SU_BOOT_ID_FILE": posix(self.fh / "boot_id"),
               "SU_SHUTDOWN_SCHEDULED": posix(self.fh / "scheduled"), "FAKE_SYSTEMCTL_STATE": posix(self.fh / "systemctl.json"),
               "SU_OS_RELEASE": posix(self.fh / "os-release")}
        env.update(extra_env or {})
        return bindir, env
