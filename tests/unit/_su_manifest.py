"""Un `backup.manifest` REAL pentru testele de poartă. Nu e fișier de teste."""

from __future__ import annotations

import gzip
import hashlib
import time
from pathlib import Path


def write_manifest(tmp: Path, entries: list[tuple[str, str, str]], *, epoch: int | None = None, tamper: str = "") -> Path:
    """Fișiere .sql.gz în tmp/state/dumps/D1, cu suma și mărimea din manifest.

    `entries` = (stare, nume, fel). `tamper`: `-nume` șterge fișierul, `nume` îl modifică (un octet în plus).
    Poarta fazelor verifică fișierele la momentul ei, nu doar manifestul — de aceea fișierele există de-adevărat.
    """
    dumps = tmp / "state" / "dumps" / "D1"
    dumps.mkdir(parents=True, exist_ok=True)
    lines = [f"epoch={int(time.time()) if epoch is None else epoch}", "run=x", f"dir={dumps.as_posix()}"]
    for status, name, kind in entries:
        if status == "ok":
            f = dumps / f"{name}.sql.gz"
            f.write_bytes(gzip.compress(b"-- dump " + name.encode() + b"\n" * 50))
            lines.append(f"ok|{name}|{kind}|600|{hashlib.sha256(f.read_bytes()).hexdigest()}|{f.stat().st_size}")
            if tamper == f"-{name}":
                f.unlink()
            elif tamper == name:
                f.write_bytes(f.read_bytes() + b"x")
            elif tamper == f"~{name}":                       # aceeași mărime, alt conținut
                f.write_bytes(bytes((b ^ 0x55) for b in f.read_bytes()))
        else:
            lines.append(f"{status}|{name}|{kind}|0|-")
    (tmp / "state").mkdir(exist_ok=True)
    manifest = tmp / "state" / "backup.manifest"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return manifest
