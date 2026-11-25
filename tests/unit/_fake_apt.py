"""Gazda momeală Debian/Ubuntu (apt) pentru testele fazelor `os`, `reboot`, `verify` și `preflight`
pe apt. Nu e fișier de teste.

`FakeAptHost` moștenește `FakeHost` (aceleași momeli pentru docker, systemctl, nginx, curl, df, shutdown,
auditctl, nft...) și ÎNLOCUIEȘTE ce ține de dnf: `dnf`, `rpm`, `needs-restarting` și `grubby` sunt ȘTERSE din
`bin/` (o apelare rătăcită a lui dnf pe o gazdă apt devine «command not found», nu o momeală tăcută), iar
`apt-get`, `dpkg`, `dpkg-query`, `apt-mark` și `pgrep` sunt momeli scrise aici (`python _fake_apt.py <comandă> ...`).

Formele de ieșire sunt cele MĂSURATE pe n8n.srv1051579.hstgr.cloud (Ubuntu 24.04, apt 2.8.4) pe 24 nov 2026, doar citire:
`apt-get -s dist-upgrade` (liniile `Inst`, secțiunile «NEW packages» / «kept back», cloud-init ținut), `dpkg-query -W -f`
cu `${db:Status-Abbrev}` (cu spațiu la coadă: `ii `), `linux-image-*` cu intrări `deinstall … config-files`,
`/boot/grub/grub.cfg` cu `menuentry 'Ubuntu'` și `linux /vmlinuz-…`, `/var/log/apt/history.log` cu blocuri
`Start-Date`/`End-Date`, `/var/run/reboot-required(.pkgs)`.

Ce NU reproduce: apt-ul, dpkg-ul și GRUB-ul reale. Efectul unui `apt-get dist-upgrade` e cel SCRIPTAT în `apt-mode`:
  ok          aplică upgrade-ul (pachete, nucleu nou, grub.cfg, history, reboot-required), iese 0
  noop        iese 0 și nu schimbă nimic
  fail        iese 100 fără să schimbe pachetele
  half        aplică, lasă `systemd` în starea `iF ` (configurat pe jumătate), scrie `Error:` în history, iese 100
  half0       aplică, lasă `systemd` în `iF `, history FĂRĂ eroare, iese 0 (apt zice «bine», dpkg-ul nu e)
  no-grub     aplică, dar grub.cfg NU se regenerează (nucleul nou nu e cel implicit), iese 0
  touch-hold  aplică ȘI schimbă versiunea lui cloud-init (pachetul ținut), iese 0
  unhold      aplică ȘI scoate hold-ul lui cloud-init (apt-mark showhold devine gol), iese 0
  unfinished  aplică, dar blocul din history.log n-are End-Date (apt a murit după dpkg), iese 0
Blocări (stare scriptată, ca în realitate):
  `lock-busy-n`    de câte ori `lslocks` arată blocarea dpkg ținută (apoi dispare) — ce citește scriptul ca «apt rulează»;
  `lock-held-n`    `apt-get dist-upgrade` FĂRĂ `-o DPkg::Lock::Timeout=…` iese 100 cu «Could not get lock»; cu opțiunea așteaptă;
  `lists-lock-n`   `apt-get update` iese 100 IMEDIAT cât contorul e peste 0, cu sau fără opțiuni (apt 2.8.4 ia blocarea listelor fără timeout).
`procs` = procesele de pe gazda reală (pid 829 `unattended-upgrade-shutdown`, packagekitd idle): `pgrep` le potrivește ca cel real, pe nume.
Un `apt-get` fără DEBIAN_FRONTEND=noninteractive sau fără `--force-confold`+`--force-confdef` iese 1 (în realitate
ar aștepta la un prompt pe care o unitate detașată nu-l poate citi).
"""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path

from _fake_host import FakeHost
from _su_shell import posix, write_exec

HERE = Path(__file__).resolve()

OLD_K = "6.8.0-147-generic"
RUN_K = "6.8.0-149-generic"      # nucleul care RULEAZĂ pe gazda sănătoasă
NEW_K = "6.8.0-151-generic"
NOW_STAMP = "2026-11-24  09:00:00"


def grub_cfg(first: str, others: list[str]) -> str:
    def entry(k: str, ind: str = "") -> str:
        return f"{ind}\tlinux\t/vmlinuz-{k} root=UUID=d36f ro console=tty0\n"
    out = "### BEGIN /etc/grub.d/10_linux ###\n"
    out += "menuentry 'Ubuntu' --class ubuntu {\n\trecordfail\n" + entry(first) + "\tinitrd\t/initrd.img-" + first + "\n}\n"
    out += "submenu 'Advanced options for Ubuntu' {\n"
    for k in [first] + others:
        out += f"\tmenuentry 'Ubuntu, with Linux {k}' {{\n" + entry(k, "\t") + "\t}\n"
    out += "}\n### END /etc/grub.d/10_linux ###\n"
    return out


def sim_text(inst: list[tuple[str, str, str]], new: list[str] = (), removes: list[str] = (), kept: list[str] = ()) -> str:
    out = "Reading package lists...\nBuilding dependency tree...\nReading state information...\nCalculating upgrade...\n"
    if new:
        out += "The following NEW packages will be installed:\n  " + " ".join(new) + "\n"
    if kept:
        out += "The following packages have been kept back:\n  " + " ".join(kept) + "\n"
    if inst:
        out += "The following packages will be upgraded:\n  " + " ".join(n for n, _, _ in inst) + "\n"
    out += f"{len(inst)} upgraded, {len(new)} newly installed, {len(removes)} to remove and {len(kept)} not upgraded.\n"
    for n, old, nw in inst:
        out += f"Inst {n} [{old}] ({nw} Ubuntu:24.04/noble-updates [amd64])\n"
    for n in new:
        out += f"Inst {n} (6.8.0-151.151 Ubuntu:24.04/noble-updates [amd64])\n"
    for n in removes:
        out += f"Remv {n} [1.0]\n"
    return out



class FakeAptHost(FakeHost):
    def __init__(self, tmp: Path):
        super().__init__(tmp)
        self.units.pop("dnf-makecache.service", None)
        self.units["motd-news.service"] = {"state": "failed", "enabled": "static", "restarts": 0, "enter": 0}
        self.units.pop("php82-php-fpm.service", None)
        self.save_units()
        self.w("os-release", 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n')
        self.w("uname", RUN_K + "\n")
        rows = [f"ii |pkg{i}|1.0" for i in range(60)]
        rows += [f"ii |linux-image-{OLD_K}|6.8.0-147.147", f"ii |linux-image-{RUN_K}|6.8.0-149.149",
                 "rc |linux-image-6.8.0-146-generic|6.8.0-146.146", "hi |cloud-init|25.1-0ubuntu1",
                 "ii |systemd|255.4-1", "ii |docker-ce|5:27.0"]
        self.w("dpkg-status", "\n".join(rows) + "\n")
        self.w("holds", "cloud-init\n")
        self.w("apt-mode", "ok")
        self.w("apt-update-mode", "ok")
        self.w("apt-check-rc", "0")
        # Procesele REALE de pe n8n.srv1051579.hstgr.cloud (24 nov 2026): `unattended-upgrade-shutdown` stă pornit de 37 de zile (pid 829) FĂRĂ nicio blocare,
        # iar packagekitd rămâne ~5 min după fiecare `apt-get update`, tot fără blocări. O potrivire pe NUME le vede pe amândouă ca «apt rulează».
        self.w("procs", "829|unattended-upgr|/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal\n"
                        "31337|packagekitd|/usr/libexec/packagekitd\n900|dockerd|/usr/bin/dockerd -H fd://\n")
        self.w("lock-busy-n", "0")      # de câte ori `lslocks` mai arată blocarea dpkg ținută (apoi dispare)
        self.w("lock-held-n", "0")      # de câte ori `apt-get dist-upgrade` mai găsește blocarea dpkg ținută
        self.w("lists-lock-n", "0")     # de câte ori `apt-get update` mai găsește blocarea listelor ținută (fără timeout, ca apt 2.8.4)
        self.w("sim-rc", "0")
        self.set_sim([("systemd", "255.4-1", "255.5-1")], new=[f"linux-image-{NEW_K}"], kept=["cloud-init"])
        self.w("grub.cfg", grub_cfg(RUN_K, [OLD_K]))
        self.w("default-grub", 'GRUB_DEFAULT=0\nGRUB_TIMEOUT_STYLE=hidden\n')
        self.w("history.log", self.block("Upgrade: tzdata:amd64 (1, 2)"))
        self.w("notify-hook", "#!/bin/sh\nexit 0\n")
        (self.fh / "notify-hook").chmod(0o755)
        # al doilea scriitor al lui reboot-required (/etc/kernel/postinst.d/unattended-upgrades) lipsește implicit: `put_ua_hook()` îl pune
        self.set_boot_files(RUN_K)
        self.set_boot_files(OLD_K)
        self.w("grub-after", grub_cfg(NEW_K, [RUN_K, OLD_K]))
        self.w("dpkg-after-extra", f"ii |linux-image-{NEW_K}|6.8.0-151.151\n")

    # -- stare ---------------------------------------------------------
    def set_boot_files(self, kernel: str, *, initramfs: bool = True) -> None:
        (self.fh / "boot" / f"vmlinuz-{kernel}").write_text("k" * 2000, encoding="utf-8")
        ini = self.fh / "boot" / f"initrd.img-{kernel}"
        if initramfs:
            ini.write_text("i" * 2000, encoding="utf-8")
        elif ini.exists():
            ini.unlink()

    def put_ua_hook(self) -> None:
        self.w("ua-hook", "#!/bin/sh\nexit 0\n")
        (self.fh / "ua-hook").chmod(0o755)

    def set_sim(self, inst, new=(), removes=(), kept=()):
        self.w("apt-sim", sim_text(list(inst), list(new), list(removes), list(kept)))

    @staticmethod
    def block(body: str, *, ended: bool = True, error: str = "") -> str:
        return (f"\nStart-Date: {NOW_STAMP}\nCommandline: apt-get dist-upgrade\n{body}\n"
                + (f"Error: {error}\n" if error else "") + (f"End-Date: {NOW_STAMP}\n" if ended else ""))

    def install(self, extra_env: dict | None = None):
        bindir, env = super().install(extra_env)
        for gone in ("dnf", "rpm", "needs-restarting", "grubby"):
            p = bindir / gone
            if p.exists():
                p.unlink()
        for name in ("apt-get", "dpkg", "dpkg-query", "apt-mark", "pgrep", "lslocks"):
            write_exec(bindir / name, f'#!/usr/bin/env bash\nexec "{posix(sys.executable)}" "{posix(HERE)}" {name} "$@"\n')
        env.update({
            "SU_APT_HISTORY": posix(self.fh / "history.log"), "SU_REBOOT_REQUIRED": posix(self.fh / "reboot-required"),
            "SU_REBOOT_HOOKS": posix(self.fh / "notify-hook") + " " + posix(self.fh / "ua-hook"), "SU_GRUB_CFG": posix(self.fh / "grub.cfg"),
            "SU_GRUB_DEFAULT_FILES": posix(self.fh / "default-grub"),
            "SU_APT_IDLE_WAIT_S": "20", "SU_APT_IDLE_STEP_S": "0", "SU_APT_LOCK_TIMEOUT_S": "77",
        })
        env.update(extra_env or {})
        return bindir, env



# ---------------------------------------------------------------------------
# Momelile propriu-zise (rulate ca `python _fake_apt.py <comandă> ...`)
# ---------------------------------------------------------------------------
def _main(argv: list[str]) -> int:
    fh = Path(os.environ["FH"])

    def rd(name: str, default: str = "") -> str:
        p = fh / name
        return p.read_text(encoding="utf-8") if p.exists() else default

    def wr(name: str, text: str) -> None:
        (fh / name).write_text(text, encoding="utf-8", newline="\n")

    def log(line: str) -> None:
        with open(fh / "calls.log", "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")

    def status_rows() -> list[list[str]]:
        return [ln.split("|", 2) for ln in rd("dpkg-status").splitlines() if ln.strip()]

    sys.stdout.reconfigure(newline="\n", encoding="utf-8")
    cmd, args = argv[0], argv[1:]
    joined = " ".join(args)

    if cmd == "pgrep":     # -x -a PATTERN, ca pgrep real: potrivire exactă pe numele procesului (comm), tipărește «pid linia-de-comandă»
        import re
        pat = [a for a in args if not a.startswith("-")][0]
        hit = [r for r in (ln.split("|", 2) for ln in rd("procs").splitlines() if ln) if re.fullmatch(pat, r[1])]
        for pid, _, cl in hit:
            print(f"{pid} {cl}")
        return 0 if hit else 1

    if cmd == "lslocks":   # -n -o COMMAND,PID,PATH
        for pid, comm, _ in (ln.split("|", 2) for ln in rd("procs").splitlines() if ln):
            if comm == "dockerd":
                print(f"{comm:<16} {pid} /var/lib/docker/network/files/local-kv.db")
        print("cron            115525 /run/crond.pid")
        busy = int(rd("lock-busy-n", "0") or 0)
        if busy > 0:
            wr("lock-busy-n", str(busy - 1))
            # `lock-busy-paths` (o cale pe linie) alege ce blocare apare ținută; implicit, cele două ale dpkg
            for path in (rd("lock-busy-paths") or "/var/lib/dpkg/lock-frontend\n/var/lib/dpkg/lock\n").split():
                print(f"apt-get            4242 {path}")
        return int(rd("lslocks-rc", "0") or 0)

    if cmd == "apt-mark":
        log(f"apt-mark {joined}")
        if joined == "showhold":
            sys.stdout.write(rd("holds"))
            return 0
        print(f"fake apt-mark: {joined}", file=sys.stderr)
        return 99

    if cmd == "dpkg":
        log(f"dpkg {joined}")
        if args == ["--audit"]:
            bad = [r for r in status_rows() if r[0].strip() not in ("ii", "hi", "rc", "un", "pn")]
            forced = rd("audit-force")
            if forced:
                sys.stdout.write(forced)
            elif bad:
                print("The following packages are only half configured, probably due to problems\n"
                      "configuring them the first time.  The configuration should be retried using\n"
                      "dpkg --configure <package> or the configure menu option in dselect:")
                for st, name, _ in bad:
                    print(f" {name}   half-configured")
            return int(rd("audit-rc", "0") or 0)
        print(f"fake dpkg: {joined}", file=sys.stderr)
        return 99

    if cmd == "dpkg-query":
        fmt = next((a[3:] for a in args if a.startswith("-f=")), "")
        rest = [a for a in args if not a.startswith("-")]
        rows = status_rows()
        if fmt == "${db:Status-Abbrev}|${binary:Package}=${Version}\\n":
            for st, name, ver in rows:
                print(f"{st}|{name}={ver}")
        elif fmt == "${db:Status-Abbrev}|${Package}|${Version}\\n":
            for st, name, ver in rows:
                if any(fnmatch.fnmatch(name, pat) for pat in rest):
                    print(f"{st}|{name}|{ver}")
        elif fmt == "${db:Status-Abbrev}|${binary:Package}\\n":
            for st, name, _ in rows:
                print(f"{st}|{name}")
        elif fmt == "${Package}=${Version}\\n":
            hit = [r for r in rows if r[1] == (rest[0] if rest else "")]
            if not hit:
                print(f"dpkg-query: no packages found matching {rest}", file=sys.stderr)
                return 1
            print(f"{hit[0][1]}={hit[0][2]}")
        elif fmt == "${Package}-${Version}\\n":
            hit = [r for r in rows if r[1] == (rest[0] if rest else "")]
            if not hit:
                return 1
            print(f"{hit[0][1]}-{hit[0][2]}")
        else:
            print(f"fake dpkg-query: {joined!r}", file=sys.stderr)
            return 99
        return 0

    if cmd != "apt-get":
        return 99

    log(f"apt-get {joined}")
    if args[:2] == ["-s", "dist-upgrade"]:
        sys.stdout.write(rd("apt-sim"))
        return int(rd("sim-rc", "0") or 0)
    if args and args[0] == "check":
        rc = int(rd("apt-check-rc", "0") or 0)
        print("Reading package lists...\nBuilding dependency tree...")
        if rc:
            print("E: Unmet dependencies. Try 'apt --fix-broken install'.")
        return rc

    def take_lock() -> int | None:
        held = int(rd("lock-held-n", "0") or 0)
        if held > 0:
            if not any(a.startswith("DPkg::Lock::Timeout=") for a in args):
                print("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)", file=sys.stderr)
                return 100
            log("waited-for-lock " + (args[0] if args[0] != "-y" else "dist-upgrade"))
            wr("lock-held-n", str(held - 1))
        return None

    if "update" in args:
        lists = int(rd("lists-lock-n", "0") or 0)
        if lists > 0:      # blocarea listelor se ia FĂRĂ timeout: nicio opțiune nu ajută, apt iese imediat
            wr("lists-lock-n", str(lists - 1))
            print("E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\n"
                  "E: Unable to lock directory /var/lib/apt/lists/", file=sys.stderr)
            return 100
        mode = rd("apt-update-mode", "ok")
        if mode == "ok":
            print("Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nReading package lists...")
            return 0
        if mode == "err":    # exact cazul care păcălește codul de ieșire: depozit căzut, ieșire 0
            print("Err:3 http://repo.example/x noble InRelease\n  Temporary failure resolving 'repo.example'\nReading package lists...\n"
                  "W: Failed to fetch http://repo.example/x/dists/noble/InRelease  Temporary failure resolving 'repo.example'\n"
                  "W: Some index files failed to download. They have been ignored, or old ones used instead.")
            return 0
        if mode == "hard-fail":
            print("E: The repository 'http://repo.example/x noble Release' does not have a Release file.", file=sys.stderr)
            return 100
        print("E: Could not get lock /var/lib/apt/lists/lock", file=sys.stderr)
        return 100

    if "dist-upgrade" in args:
        lk = take_lock()
        if lk:
            return lk
        if os.environ.get("DEBIAN_FRONTEND") != "noninteractive":
            print("debconf: unable to initialize frontend: Dialog (would hang on a prompt)", file=sys.stderr)
            return 1
        if "Dpkg::Options::=--force-confold" not in args or "Dpkg::Options::=--force-confdef" not in args:
            print("Configuration file '/etc/x.conf' ==> Modified (by you or by a script) ... *** x.conf (Y/I/N/O/D/Z) [default=N] ?", file=sys.stderr)
            return 1
        log(f"env DEBIAN_FRONTEND={os.environ.get('DEBIAN_FRONTEND')} NEEDRESTART_MODE={os.environ.get('NEEDRESTART_MODE')}")
        mode = rd("apt-mode", "ok")
        if mode == "noop":
            print("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
            return 0
        if mode == "fail":
            print("E: Sub-process /usr/bin/dpkg returned an error code (1)", file=sys.stderr)
            return 100
        rows = status_rows()
        out = []
        for st, name, ver in rows:
            if name.startswith("pkg"):
                ver = "2.0"
            if name == "systemd":
                ver = "255.5-1"
                if mode in ("half", "half0"):
                    st = "iF "
            if name == "cloud-init" and mode == "touch-hold":
                ver = "25.2-0ubuntu1"
            out.append(f"{st}|{name}|{ver}")
        out += rd("dpkg-after-extra").splitlines()
        wr("dpkg-status", "\n".join(out) + "\n")
        if mode == "unhold":
            wr("holds", "")
        if mode != "no-grub":
            wr("grub.cfg", rd("grub-after"))
        wr("reboot-required", "*** System restart required ***\n")
        wr("reboot-required.pkgs", f"linux-image-{NEW_K}\nsystemd\n")
        (fh / "boot" / f"vmlinuz-{NEW_K}").write_text("k" * 2000, encoding="utf-8")
        if (fh / "no-initrd").exists():
            pass
        else:
            (fh / "boot" / f"initrd.img-{NEW_K}").write_text("i" * 2000, encoding="utf-8")
        err = "Sub-process /usr/bin/dpkg returned an error code (1)" if mode == "half" else ""
        with open(fh / "history.log", "a", encoding="utf-8", newline="\n") as f:
            f.write(f"\nStart-Date: {NOW_STAMP}\nCommandline: apt-get dist-upgrade\nUpgrade: systemd:amd64 (255.4-1, 255.5-1)\n"
                    + (f"Error: {err}\n" if err else "") + ("" if mode == "unfinished" else f"End-Date: {NOW_STAMP}\n"))
        wr("apt-sim", "Reading package lists...\nBuilding dependency tree...\nCalculating upgrade...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
        print("Setting up systemd ...")
        return 100 if mode == "half" else 0

    print(f"fake apt-get: {joined}", file=sys.stderr)
    return 99


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
