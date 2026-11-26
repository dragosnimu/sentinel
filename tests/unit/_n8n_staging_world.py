"""Lumea momeală pentru testele `scripts/n8n-staging.sh` și `scripts/lib/n8n-staging-host.sh`. Nu e fișier de teste.

Rulează codul LIVRAT (`scripts/lib/n8n-staging-host.sh`), într-un bash, cu un `docker` momeală (`_fake_n8n_docker.py`) și cu
lucruri REALE acolo unde se poate: volumul de producție e un director adevărat, baza e un fișier SQLite adevărat în modul WAL, cu
rânduri care există DOAR în -wal (un `cp` al fișierului principal le-ar pierde) și cu o conexiune deschisă cât rulează scriptul
(«producția rămâne pornită»); `tar`, `find`, `comm`, `cmp`, `stat`, `chown`, `du`, `mktemp` sunt cele ale sistemului.

Ce NU are mediul ăsta, și ce înseamnă pentru ce dovedesc testele:
  * un docker real: nu se dovedește că `--internal` taie TCP/DNS (momeala MODELEAZĂ asta; vezi `_fake_n8n_docker.py`), nici că
    gazda poate ajunge la IP-ul containerului din rețeaua internă, nici formele reale de `docker inspect` pe 29.x;
  * `df`: o momeală (spațiul liber e un număr scriptat); `curl`: o momeală (codul /healthz e scriptat, în `fh/health`);
  * un proprietar real al fișierelor (uid 1000 pe gazdă): `chown` aici e un no-op către propriul utilizator;
  * dimensiunea: o bază de 9,6 GB, un integrity_check de minute, un `tar` care vede jurnalul de evenimente schimbându-se.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from _su_shell import BASH, posix, write_exec

ROOT = Path(__file__).resolve().parents[2]
HOST_LIB = ROOT / "scripts" / "lib" / "n8n-staging-host.sh"
LAUNCHER = ROOT / "scripts" / "n8n-staging.sh"
FAKE_DOCKER_PY = Path(__file__).with_name("_fake_n8n_docker.py")

LABEL = "ro.cryptoitdata.n8n-staging"
IMAGE_FOR = "docker.n8n.io/n8nio/n8n:{}"
PROD = "root-n8n-1"
# Valori-momeală cu aspect de secret: testele caută EXACT aceste șiruri în tot ce tipărește scriptul și în tot ce primește docker.
SECRETS = {"TWILIO_AUTH_TOKEN": "SECRET_TWILIO_8f3a2c91", "ELEVENLABS_API_KEY": "SECRET_ELEVEN_77d0e1aa"}
PROD_ENV = [
    "PATH=/usr/local/sbin:/usr/bin", "NODE_VERSION=22.0.1", "NODE_ENV=production", "N8N_RELEASE_TYPE=stable",
    *[f"{k}={v}" for k, v in SECRETS.items()],
    "N8N_HOST=n8n.srv1051579.hstgr.cloud", "N8N_PORT=5678", "N8N_PROTOCOL=https", "WEBHOOK_URL=https://n8n.srv1051579.hstgr.cloud/",
    "EXECUTIONS_TIMEOUT=3600", "N8N_DEFAULT_BINARY_DATA_MODE=filesystem", "GENERIC_TIMEZONE=Europe/Bucharest",
]
IMAGE_ENV = ["PATH=/usr/local/sbin:/usr/bin", "NODE_VERSION=22.0.1", "NODE_ENV=production", "N8N_RELEASE_TYPE=stable"]
PROD_IMAGE_ID = "sha256:" + "2b" * 32
PROD_STARTED = "2026-11-25T04:53:40.010836779Z"
ROWS = 5
# Pe Windows (MSYS), `stat -c %a` maschează modul cu umask-ul PROCESULUI curent, iar `chmod` pe NTFS nu face nimic real: cu umask 022
# orice fișier arată 644, cu 077 arată 600. Verificarea «fișierul de mediu are 600» a bibliotecii ar fi deci mereu roșie pe stația
# operatorului. Aici, doar pe Windows, scriptul rulează sub umask 077: verificarea e atunci o formalitate, iar dovada reală a lui
# 0600 e pe Linux (unde `mktemp` creează 0600 și `stat` citește modul adevărat). Pe Linux prefixul e gol.
UMASK_PREFIX = "umask 077; " if os.name == "nt" else ""


class Result:
    def __init__(self, proc: subprocess.CompletedProcess):
        self.rc = proc.returncode
        self.out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


class World:
    def __init__(self, tmp: Path, *, rows: int = ROWS):
        self.tmp = tmp
        self.vols = tmp / "vols"
        self.data = self.vols / "n8n_data" / "_data"
        self.files = tmp / "local-files"
        self.run_dir = tmp / "run"
        self.fh = tmp / "fh"
        self.bin = tmp / "bin"
        self.state_path = tmp / "state.json"
        self.log_path = tmp / "docker.log"
        for d in (self.data, self.files, self.run_dir, self.fh, self.bin):
            d.mkdir(parents=True, exist_ok=True)
        self.rows = rows
        self.prod_con: sqlite3.Connection | None = None
        self._make_prod_volume()
        self._make_state()
        self._make_shims()

    # -- volumul de producție, cu o bază REALĂ în WAL ---------------------------------------------------------------
    def _make_prod_volume(self) -> None:
        (self.data / "config").write_text('{"encryptionKey":"KEY_ONLY_IN_CONFIG_FILE"}\n', encoding="utf-8", newline="\n")
        (self.data / "crash.journal").write_text("", encoding="utf-8")
        (self.data / "n8nEventLog.log").write_text("{}\n" * 20, encoding="utf-8", newline="\n")
        (self.data / "nodes" / "node_modules" / "n8n-nodes-basecamp").mkdir(parents=True)
        (self.data / "nodes" / "node_modules" / "n8n-nodes-basecamp" / "package.json").write_text("{}", encoding="utf-8")
        # un fișier cu NUMELE bazei, dar mai adânc: trebuie copiat (excluderea e doar pentru baza de la rădăcină)
        nested = self.data / "nodes" / "node_modules" / "n8n-nodes-basecamp" / "database.sqlite"
        nested.write_text("nu e baza n8n", encoding="utf-8")
        db = self.data / "database.sqlite"
        con = sqlite3.connect(db)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("CREATE TABLE workflow_entity (id TEXT PRIMARY KEY, name TEXT)")
        con.execute("CREATE TABLE other_entity (a INTEGER, b TEXT)")
        con.execute("CREATE INDEX idx_other ON other_entity(b)")
        con.execute("CREATE TABLE checked_entity (a INTEGER CHECK (a > 0))")
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")      # schema în fișierul principal...
        con.executemany("INSERT INTO workflow_entity VALUES (?, ?)", [(str(i), f"wf{i}") for i in range(self.rows)])
        con.commit()                                          # ...rândurile DOAR în -wal
        self.prod_con = con

    def close(self) -> None:
        if self.prod_con is not None:
            self.prod_con.close()
            self.prod_con = None

    def violate_check_in_prod(self) -> None:
        """Un rând care încalcă un CHECK, scris cu verificarea oprită: baza se citește fără erori, dar `PRAGMA integrity_check` NU întoarce «ok»
        (întoarce o listă de probleme) — cealaltă formă de eșec decât o pagină stricată, care face integrity_check să ridice o excepție."""
        con = self.prod_con
        assert con is not None
        con.execute("PRAGMA ignore_check_constraints=ON")
        con.execute("INSERT INTO checked_entity VALUES (-1)")
        con.execute("PRAGMA ignore_check_constraints=OFF")
        con.commit()

    def corrupt_prod_index(self) -> None:
        """Strică o pagină a indexului lui `other_entity`: copia ei va avea integrity_check pe roșu, fără ca `workflow_entity` să se atingă."""
        con = self.prod_con
        assert con is not None
        con.executemany("INSERT INTO other_entity VALUES (?, ?)", [(i, "x" * 50 + str(i)) for i in range(2000)])
        con.commit()
        root = con.execute("SELECT rootpage FROM sqlite_master WHERE name='idx_other'").fetchone()[0]
        page = con.execute("PRAGMA page_size").fetchone()[0]
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        con.close()
        self.prod_con = None
        with open(self.data / "database.sqlite", "r+b") as fh:
            fh.seek(root * page - 200)          # coada paginii-rădăcină a indexului (pagina N ocupă [(N-1)*page, N*page)): acolo stau celulele
            fh.write(b"\xff" * 200)

    # -- starea docker ---------------------------------------------------------------------------------------------
    def _make_state(self) -> None:
        stage_root = self.vols
        self.state = {
            "containers": {PROD: {
                "id": "a" * 64, "state": "running", "restart": 0, "started": PROD_STARTED, "image_id": PROD_IMAGE_ID,
                "labels": {}, "env": PROD_ENV, "network": "root_default", "reads": 0, "ports": {"5678/tcp": [{"HostPort": "5678"}]},
                "mounts": [
                    {"dst": "/files", "type": "bind", "name": "", "src": posix(self.files), "rw": True},
                    {"dst": "/home/node/.n8n", "type": "volume", "name": "n8n_data", "src": posix(self.data), "rw": True},
                ]}},
            "volumes": {"n8n_data": {"labels": {}, "mountpoint": posix(self.data)},
                        "traefik_data": {"labels": {}, "mountpoint": posix(self.vols / "traefik_data" / "_data")}},
            "networks": {"root_default": {"internal": False, "labels": {}}, "bridge": {"internal": False, "labels": {}}},
            "images": {PROD_IMAGE_ID: {"id": PROD_IMAGE_ID, "env": IMAGE_ENV}},
            "known_pulls": [IMAGE_FOR.format("3.0.1")],
            "vol_root": posix(stage_root),
            "ip": "172.30.0.2",
            "logs": "",
        }
        self.save()

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def load(self) -> dict:
        self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        return self.state

    def docker_log(self) -> list[list[str]]:
        if not self.log_path.exists():
            return []
        return [l.split("\t") for l in self.log_path.read_text(encoding="utf-8").splitlines() if l]

    def docker_lines(self) -> list[str]:
        return [" ".join(a) for a in self.docker_log()]

    def object_keys(self) -> tuple:
        s = self.load()
        return (tuple(sorted(s["containers"])), tuple(sorted(s["volumes"])), tuple(sorted(s["networks"])))

    # -- momelile ------------------------------------------------------------------------------------------------
    def _make_shims(self) -> None:
        # fără conversia automată de căi MSYS a argumentelor (`-v /c/x:/files:ro` ar deveni altceva); momeala își convertește singură căile
        write_exec(self.bin / "docker", f'#!/usr/bin/env bash\nexport MSYS2_ARG_CONV_EXCL="*"\nexec "{posix(sys.executable)}" "{posix(FAKE_DOCKER_PY)}" "$@"\n')
        write_exec(self.bin / "python3", f'#!/usr/bin/env bash\nexec "{posix(sys.executable)}" "$@"\n')
        (self.fh / "avail").write_text("900000000000\n", encoding="utf-8")
        (self.fh / "health").write_text("200\n", encoding="utf-8")
        write_exec(self.bin / "df", '#!/usr/bin/env bash\nprintf "Avail\\n%s\\n" "$(cat "$FH/avail")"\n')
        write_exec(self.bin / "curl", (
            '#!/usr/bin/env bash\n'
            'for a in "$@"; do last="$a"; done; echo "$last" >> "$FH/curl.log"\n'
            'f="$FH/health"; code="$(head -n 1 "$f")"\n'
            'if [ "$(wc -l < "$f")" -gt 1 ]; then tail -n +2 "$f" > "$f.tmp"; mv "$f.tmp" "$f"; fi\n'
            'printf "%s" "$code"\n'))
        # `nice`/`ionice` momeală: notează că au fost chemate (și cu ce) și apoi execută comanda; testele văd astfel că backup-ul chiar rulează sub ele
        # (loghează doar clasa/prioritatea și numele programului: argumentul lui python3 e cod pe zeci de linii)
        write_exec(self.bin / "nice", '#!/usr/bin/env bash\necho "nice $1 $2 prog=$3" >> "$FH/prio.log"\nshift 2\nexec "$@"\n')
        write_exec(self.bin / "ionice", '#!/usr/bin/env bash\necho "ionice $1 prog=$2 $3 $4 $5" >> "$FH/prio.log"\nshift 1\nexec "$@"\n')

    def prio_log(self) -> list[str]:
        p = self.fh / "prio.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def run_closing_pipe(self, trigger: str, *args: str, **env_extra: str) -> tuple[int, bool]:
        """Rulează scriptul cu stdout ȘI stderr pe aceeași conductă (ca prin ssh) pe care cititorul o ÎNCHIDE de îndată ce citește o linie cu
        `trigger`: cum arată o conexiune ssh căzută la mijlocul unei rulări. Întoarce (cod de ieșire, a fost văzută linia). Orice scriere
        ulterioară a scriptului primește SIGPIPE/EPIPE."""
        proc = subprocess.Popen([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", posix(HOST_LIB), *args],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=self.env(**env_extra))
        seen = False
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            if trigger in raw.decode("utf-8", "replace"):
                seen = True
                break
        proc.stdout.close()
        return proc.wait(timeout=600), seen

    def set_free(self, value: str) -> None:
        (self.fh / "avail").write_text(value + "\n", encoding="utf-8")

    def set_health(self, *codes: str) -> None:
        (self.fh / "health").write_text("\n".join(codes) + "\n", encoding="utf-8")

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            PATH=f"{posix(self.bin)}{os.pathsep}{env['PATH']}",
            FH=posix(self.fh), FAKE_N8N_STATE=posix(self.state_path), FAKE_N8N_LOG=posix(self.log_path),
            N8N_STAGING_POLL_S="0", N8N_STAGING_STABLE_SAMPLES="4", N8N_STAGING_HEALTH_TRIES="3",
            N8N_STAGING_TMPDIR=posix(self.run_dir), FAKE_N8N_BASH=str(BASH),
        )
        env.update(extra)
        return env

    def run(self, *args: str, shell_args: tuple[str, ...] = (), **env_extra: str) -> Result:
        """Rulează scriptul ca pe gazdă: `bash n8n-staging-host.sh ARGS`."""
        proc = subprocess.run([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", *shell_args, posix(HOST_LIB), *args],
                              capture_output=True, env=self.env(**env_extra), timeout=600)
        return Result(proc)

    def run_sourced(self, body: str, **env_extra: str) -> Result:
        """Încarcă biblioteca (garda o împiedică să pornească `main`) și rulează `body`; pentru a înlocui o funcție sau a chema una singură."""
        proc = subprocess.run([BASH, "-c", f"{UMASK_PREFIX}source '{posix(HOST_LIB)}'\n{body}\n"],
                              capture_output=True, env=self.env(**env_extra), timeout=600)
        return Result(proc)

    def up(self, version: str = "3.0.1", **env_extra: str) -> Result:
        return self.run("up", "--version", version, **env_extra)

    def env_files_left(self) -> list[Path]:
        return sorted(self.run_dir.glob("n8n-staging-*"))
