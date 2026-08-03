"""Sentinel — autonomous cybersecurity agent for a single Linux server."""

from __future__ import annotations

from pathlib import Path

__all__ = ["__version__"]


def _read_version() -> str:
    # VERSION sits at the repo root in development and next to the installed
    # package on the server. Try both before falling back.
    for candidate in (
        Path(__file__).resolve().parent.parent / "VERSION",
        Path("/opt/sentinel/VERSION"),
    ):
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return "0.0.0+unknown"


__version__ = _read_version()
