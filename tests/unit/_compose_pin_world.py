"""Lumea momeală pentru testele `scripts/compose-pin.sh` și `scripts/lib/compose-pin-host.sh`. Nu e fișier de teste.

Rulează codul LIVRAT (`scripts/lib/compose-pin-host.sh`), într-un bash, cu un `docker` momeală (`_fake_compose_docker.py`) și cu lucruri
REALE acolo unde se poate: fișierul compose e un fișier adevărat pe disc (octeții lui se compară cu sha256), `sha256sum`, `date`, `mktemp`,
`awk`, `sort` sunt cele ale sistemului, iar `python3` e cel care rulează testele. Forma fișierului reproduce gazda măsurată read-only pe
26 noiembrie 2026 (`image: "traefik"` citat, `image: docker.n8n.io/n8nio/n8n` simplu, `qpdf-api` cu `build:` ȘI `image: qpdf-api:latest`).

Ce NU are mediul ăsta, și ce înseamnă pentru ce dovedesc testele:
  * un compose real: `docker compose config` e modelat (yaml -> JSON citit de pe disc, la fiecare apel); normalizările lui reale nu sunt;
  * un proprietar real al fișierelor (root): modul 0600 al copiei de rezervă și păstrarea proprietarului sunt dovedite doar pe Linux
    (pe Windows, `chmod` pe NTFS nu face nimic și verificările de mod sunt sărite de program);
  * un registry real: `docker pull` e momeală (`known_pulls`).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from _su_shell import BASH, posix, write_exec

ROOT = Path(__file__).resolve().parents[2]
HOST_LIB = ROOT / "scripts" / "lib" / "compose-pin-host.sh"
LAUNCHER = ROOT / "scripts" / "compose-pin.sh"
FAKE_DOCKER_PY = Path(__file__).with_name("_fake_compose_docker.py")

SECRETS = {"TWILIO_AUTH_TOKEN": "SECRET_TWILIO_8f3a2c91", "ELEVENLABS_API_KEY": "SECRET_ELEVEN_77d0e1aa"}
TRAEFIK_ID = "sha256:" + "01" * 32
N8N_ID = "sha256:" + "2b" * 32
N8N_NEW_ID = "sha256:" + "17" * 32
TRAEFIK_NEW_ID = "sha256:" + "aa" * 32
QPDF_ID = "sha256:" + "99" * 32
N8N_DIGEST = "sha256:" + "c3" * 32
UMASK_PREFIX = "umask 077; " if os.name == "nt" else ""

# `Config.Image` al containerelor de pe gazdă (măsurat read-only pe 26 noiembrie 2026): numele cu care le-a creat compose, înainte de orice pin
CONFIG_IMAGE = {"traefik": "traefik", "n8n": "docker.n8n.io/n8nio/n8n", "qpdf-api": "qpdf-api:latest"}

COMPOSE = f"""services:
  traefik:
    image: "traefik"   # citat, cu comentariu
    restart: always
    command:
      - "--api.insecure=false"
    ports:
      - "80:80"
  qpdf-api:
    build:
      context: .
      dockerfile: Dockerfile.qpdf
    image: qpdf-api:latest
    restart: always
  n8n:
    image: docker.n8n.io/n8nio/n8n
    restart: always
    labels:
      - "traefik.enable=true"
    environment:
      - TWILIO_AUTH_TOKEN={SECRETS['TWILIO_AUTH_TOKEN']}
      - ELEVENLABS_API_KEY={SECRETS['ELEVENLABS_API_KEY']}
volumes:
  n8n_data:
    external: true
"""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def msys(p: Path) -> str:
    """Calea ca o vede bash pe gazdă: absolută, cu `/`. Pe Windows, `C:/x` devine `/c/x` (MSYS), ca la momeala docker n8n."""
    s = p.resolve().as_posix()
    if os.name == "nt" and len(s) > 2 and s[1] == ":":
        return "/" + s[0].lower() + s[2:]
    return s


class Result:
    def __init__(self, proc: subprocess.CompletedProcess):
        self.rc = proc.returncode
        self.out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


class World:
    def __init__(self, tmp: Path, *, text: str = COMPOSE, crlf: bool = False, name: str = "docker-compose.yml"):
        self.tmp = tmp
        self.dir = tmp / "srv"
        self.bin = tmp / "bin"
        self.work = tmp / "work"
        for d in (self.dir, self.bin, self.work):
            d.mkdir(parents=True, exist_ok=True)
        self.file = self.dir / name
        data = text.replace("\n", "\r\n") if crlf else text
        self.file.write_bytes(data.encode("utf-8"))
        self.state_path = tmp / "state.json"
        self.log_path = tmp / "docker.log"
        self.fpath = msys(self.file)
        self._make_shims()          # înaintea stării: `sync_hash_labels` cheamă `docker`, care trebuie să fie momeala
        self._make_state()

    @property
    def original(self) -> bytes:
        return self.file.read_bytes()

    def _container(self, service: str, image_id: str, chash: str = "") -> dict:
        return {"id": (service[0] * 64)[:64], "config_image": CONFIG_IMAGE.get(service, service), "state": "running", "started": "2026-11-25T04:53:40.010836779Z", "restart": 0, "image_id": image_id,
                "labels": {"com.docker.compose.project": "root", "com.docker.compose.service": service,
                          "com.docker.compose.project.config_files": self.fpath, "com.docker.compose.config-hash": chash}}

    def _make_state(self) -> None:
        self.state = {
            "project": "root",
            "containers": {
                "root-traefik-1": self._container("traefik", TRAEFIK_ID),
                "root-n8n-1": self._container("n8n", N8N_ID),
                "root-qpdf-api-1": self._container("qpdf-api", QPDF_ID),
            },
            "images": {
                TRAEFIK_ID: {"id": TRAEFIK_ID, "digests": ["traefik@sha256:" + "00" * 32]},
                N8N_ID: {"id": N8N_ID, "digests": ["docker.n8n.io/n8nio/n8n@sha256:" + N8N_DIGEST.split(":")[1]]},
                QPDF_ID: {"id": QPDF_ID, "digests": []},
                # eticheta (latest) a numelui cu care au fost create containerele: arată imaginea care RULEAZĂ (altfel faza containers ar vedea eticheta mutată)
                "traefik": {"id": TRAEFIK_ID, "digests": ["traefik@sha256:" + "00" * 32]},
                "docker.n8n.io/n8nio/n8n": {"id": N8N_ID, "digests": ["docker.n8n.io/n8nio/n8n@sha256:" + N8N_DIGEST.split(":")[1]]},
                "qpdf-api:latest": {"id": QPDF_ID, "digests": []},
            },
            "known_pulls": {
                "traefik:v3.8.0": TRAEFIK_ID,
                "traefik:v3.9.0": TRAEFIK_NEW_ID,
                "docker.n8n.io/n8nio/n8n:2.49.5": N8N_ID,
                "docker.n8n.io/n8nio/n8n:2.49.7": N8N_NEW_ID,
                f"docker.n8n.io/n8nio/n8n@{N8N_DIGEST}": N8N_ID,
            },
            "interp": {},
            "hooks": [],
        }
        self.save()
        # hash-urile de pe containere = ce ar da fișierul de acum (ca după un `up` reușit)
        self.sync_hash_labels()

    def file_hashes(self) -> dict[str, str]:
        """`docker compose config --hash '*'` pe fișierul de ACUM (momeala o calculează din ce citește de pe disc)."""
        out = subprocess.run([BASH, "-c", f'docker compose -p root -f "{self.fpath}" config --hash "*"'], capture_output=True, env=self.env(FAKE_CPIN_LOG=""))
        self.load()
        self.state["calls"] = {}                      # o măsurare a testului nu e un apel al scriptului (contoarele hook-urilor)
        self.save()
        return dict(l.split(" ") for l in out.stdout.decode().splitlines() if l)

    def container(self, name: str) -> dict:
        return self.load()["containers"][name]

    def sync_hash_labels(self) -> None:
        """Pune pe containere `config-hash`-ul pe care l-ar da fișierul ACUM (starea unei gazde la zi)."""
        hashes = self.file_hashes()
        self.load()
        for c in self.state["containers"].values():
            c["labels"]["com.docker.compose.config-hash"] = hashes.get(c["labels"]["com.docker.compose.service"], "")
        self.state["calls"] = {}                      # măsurarea de pornire nu e un apel al scriptului: nici în contoare, nici în jurnal
        self.save()
        self.log_path.unlink(missing_ok=True)

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def load(self) -> dict:
        self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        return self.state

    def patch(self, **kv) -> None:
        self.load()
        self.state.update(kv)
        self.save()

    def add_hook(self, **hook) -> None:
        self.load()
        self.state["hooks"].append(hook)
        self.save()

    def docker_lines(self) -> list[str]:
        if not self.log_path.exists():
            return []
        return [" ".join(l.split("\t")) for l in self.log_path.read_text(encoding="utf-8").splitlines() if l]

    def _make_shims(self) -> None:
        write_exec(self.bin / "docker", f'#!/usr/bin/env bash\nexport MSYS2_ARG_CONV_EXCL="*"\nexec "{posix(sys.executable)}" "{posix(FAKE_DOCKER_PY)}" "$@"\n')
        write_exec(self.bin / "python3", f'#!/usr/bin/env bash\nexec "{posix(sys.executable)}" "$@"\n')

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(os.environ)
        env.update(PATH=f"{posix(self.bin)}{os.pathsep}{env['PATH']}", FAKE_CPIN_STATE=posix(self.state_path),
                   FAKE_CPIN_LOG=posix(self.log_path), COMPOSE_PIN_TMPDIR=posix(self.work),
                   COMPOSE_PIN_STABLE_S="0", COMPOSE_PIN_POLL_S="0", COMPOSE_PIN_WAIT_S="3")
        env.update(extra)
        return env

    def run(self, *args: str, **env_extra: str) -> Result:
        """Rulează scriptul ca pe gazdă: `bash compose-pin-host.sh ARGS`."""
        proc = subprocess.run([BASH, "-c", UMASK_PREFIX + 'exec bash "$@"', "bash", posix(HOST_LIB), *args],
                              capture_output=True, env=self.env(**env_extra), timeout=300)
        return Result(proc)

    def run_sourced(self, body: str, **env_extra: str) -> Result:
        """Încarcă biblioteca (garda o împiedică să pornească `main`) și rulează `body`: pentru a chema programul python cu o PREFAȚĂ care
        strică un pas (ex. `tempfile.mkstemp`), fiindcă între prima verificare de sumă și `rename` nu e nicio comandă docker în care să se poată
        strecura o modificare."""
        script = UMASK_PREFIX + f'source "{posix(HOST_LIB)}"\n{body}\n'
        proc = subprocess.run([BASH, "-c", script], capture_output=True, env=self.env(**env_extra), timeout=300)
        return Result(proc)

    def recreate(self, *services: str, extra: tuple[str, ...] = (), **env_extra: str) -> Result:
        return self.run("recreate", "--file", self.fpath, "--service", ",".join(services), *extra, **env_extra)

    def restore(self, *extra: str, **env_extra: str) -> Result:
        return self.run("restore", "--file", self.fpath, *extra, **env_extra)

    def pin(self, *pins: str, extra: tuple[str, ...] = (), file: str | None = None, **env_extra: str) -> Result:
        args = ["pin", "--file", file or self.fpath]
        for p in pins:
            args += ["--pin", p]
        return self.run(*args, *extra, **env_extra)

    def show(self, **env_extra: str) -> Result:
        return self.run("show", "--file", self.fpath, **env_extra)

    def leftovers(self) -> list[str]:
        """Tot ce a rămas lângă fișier în afară de el însuși și de copiile de rezervă, plus directoarele temporare ale scriptului."""
        names = [p.name for p in self.dir.iterdir() if p.name != self.file.name and ".pin-bak-" not in p.name]
        return names + [p.name for p in self.work.iterdir()]

    def backups(self) -> list[Path]:
        return sorted(p for p in self.dir.glob(self.file.name + ".pin-bak-*") if not p.name.endswith(".sums"))

    def sums_files(self) -> list[Path]:
        """Înregistrările COPIE.sums (suma de dinainte și suma pe care o are fișierul scris de unealtă)."""
        return sorted(self.dir.glob(self.file.name + ".pin-bak-*.sums"))
