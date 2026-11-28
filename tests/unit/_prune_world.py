"""Lumea momeală pentru `scripts/docker-prune-buildcache.sh` și `scripts/lib/docker-prune-buildcache-host.sh`. Nu e fișier de teste.

Rulează codul LIVRAT: lansatorul, în `bash`, cu un `ssh` momeală care EXECUTĂ de-adevărat comanda primită (cu stdin-ul lansatorului, deci
biblioteca de pe gazdă rulează întreagă), un `sudo` care sare peste `-n`, și `docker`/`curl`/`df` momeală (`_fake_prune_tools.py`) peste o
stare JSON. `awk`, `sed`, `sort`, `comm`, `tail`, `grep` sunt cele reale.

Ce NU are mediul ăsta: un docker, un daemon BuildKit, un ssh sau un sudo reale; un `df` real (momeala dă numere scriptate); Python-ul
gazdei (3.9; aici rulează Python-ul stației). Formele de ieșire ale lui docker sunt cele citite pe gazdă pe 28 nov 2026 (doar citire).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from _su_shell import BASH, posix, write_exec

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts" / "docker-prune-buildcache.sh"
HOST_LIB = ROOT / "scripts" / "lib" / "docker-prune-buildcache-host.sh"
FAKE_TOOLS_PY = Path(__file__).with_name("_fake_prune_tools.py")

SSH = """#!/usr/bin/env bash
cmd="${@: -1}"
echo "** WARNING: connection is not using a post-quantum key exchange algorithm." >&2
printf '%s\\n' "$cmd" >> "$FAKE_SSH_LOG"
if [[ "$cmd" == *"-- snapshot" ]]; then
    n=$(( $(cat "$FAKE_SSH_COUNT" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_SSH_COUNT"
    if [[ "$n" == "${FAKE_SSH_FAIL_SNAPSHOT_N:-}" ]]; then echo "ssh: connection reset" >&2; exit 255; fi
    if [[ "$n" == "${FAKE_SSH_TRUNCATE_SNAPSHOT_N:-}" ]]; then bash -c "$cmd" | head -n 5; exit 0; fi
fi
if [[ -n "${FAKE_SSH_SED:-}" && "$cmd" == *"-- snapshot" && "$n" == "${FAKE_SSH_SED_N:-}" ]]; then bash -c "$cmd" | sed -E "$FAKE_SSH_SED"; exit 0; fi
if [[ -n "${FAKE_SSH_FAIL_ON:-}" && "$cmd" == *"$FAKE_SSH_FAIL_ON"* ]]; then echo "ssh: connection reset" >&2; exit 255; fi
out="$(bash -c "$cmd")"; rc=$?
printf '%s\\n' "$out"
if [[ "$cmd" == *"-- snapshot" && "$n" == "${FAKE_SSH_HOOK_N:-}" ]]; then bash -c "$FAKE_SSH_HOOK"; fi
exit $rc
"""
SUDO = """#!/usr/bin/env bash
if [[ -n "${FAKE_SUDO_REFUSE:-}" ]]; then echo "sudo: a password is required" >&2; exit 1; fi
[[ "${1:-}" == -n ]] && shift
exec "$@"
"""

IMG = lambda n: "sha256:" + format(n, "02x") * 32  # noqa: E731


def default_state() -> dict:
    """Cinci intrări eliberabile (suma 95923809987 B, ca măsurat pe gazdă), nicio intrare în uz; 5 imagini, din care 2 rollback/*:prev
    și una dangling; 3 volume, unul nefolosit."""
    sizes = [40_000_000_000, 30_000_000_000, 15_000_000_000, 10_000_000_000, 923_809_987]
    return {
        "daemon": "up", "server": "29.9.1", "root": "/var/lib/docker", "buildx": "present",
        "builders": [{"Name": "default", "Driver": "docker", "Current": True}],
        "cache": [{"ID": f"entry{i:04d}", "InUse": False, "Shared": False, "Size": s} for i, s in enumerate(sizes)],
        "images": [[IMG(1), "app/web:1.0"], [IMG(2), "rollback/web:prev"], [IMG(3), "rollback/api:prev"],
                   [IMG(4), "<none>:<none>"], [IMG(5), "postgres:16"]],
        "volumes": ["n8n-compose_n8n_data", "pgdata", "sentinel_state"],
        "df": {"size": 208_172_843_008, "used": 153_426_657_280, "avail": 44_097_007_616},
        "prune_mode": "normal", "curl_mode": "ok",
        "victim_images": [IMG(4), "rollback/web:prev"], "victim_volumes": ["n8n-compose_n8n_data"],
    }


class PruneWorld:
    def __init__(self, tmp: Path, state: dict | None = None, *, with_docker: bool = True):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.state_path = tmp / "state.json"
        self.state = state or default_state()
        self.save()
        for name in ("docker", "curl", "df"):
            if name == "docker" and not with_docker:
                continue
            write_exec(self.bin / name, f'#!/usr/bin/env bash\nexec "{posix(sys.executable)}" "{posix(FAKE_TOOLS_PY)}" {name} "$@"\n')
        # `python3` din PATH-ul unui Windows e adesea ștampila Microsoft Store; gazda are python3 real.
        write_exec(self.bin / "python3", f'#!/usr/bin/env bash\nexec "{posix(sys.executable)}" "$@"\n')
        write_exec(self.bin / "ssh", SSH)
        write_exec(self.bin / "sudo", SUDO)
        (tmp / "k").write_text("x", encoding="utf-8")
        self.with_docker = with_docker

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def load(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(os.environ)
        path = env["PATH"]
        if not self.with_docker:
            # Un docker REAL pe stația de dezvoltare ar face «docker lipsește» imposibil de simulat: scoatem directoarele care îl au.
            keep = [d for d in path.split(os.pathsep) if not (Path(d, "docker").exists() or Path(d, "docker.exe").exists())]
            path = os.pathsep.join(keep)
        env["PATH"] = f"{self.bin}{os.pathsep}{path}"
        env.update(FAKE_PRUNE_STATE=posix(self.state_path), FAKE_PRUNE_LOG=posix(self.tmp / "tools.log"),
                   FAKE_SSH_LOG=posix(self.tmp / "ssh.log"), FAKE_SSH_COUNT=posix(self.tmp / "ssh.count"), HOME=posix(self.tmp))
        env.update(extra)
        return env

    def run(self, *args: str, stdin: bytes = b"", launcher: Path = LAUNCHER, **env_extra: str):
        base = ["--host", "h.example.invalid", "--user", "dragos", "--port", "2222", "--key", posix(self.tmp / "k")]
        proc = subprocess.run([BASH, posix(launcher), *base, *args], input=stdin, capture_output=True,
                              env=self.env(**env_extra), timeout=300)
        out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
        return proc.returncode, out

    def ssh_log(self) -> list[str]:
        p = self.tmp / "ssh.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def tool_log(self) -> list[str]:
        p = self.tmp / "tools.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def prune_calls(self) -> list[str]:
        return [ln for ln in self.tool_log() if "prune" in ln]
