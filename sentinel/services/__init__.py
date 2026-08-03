"""Thin systemd entrypoints.

Each module here exposes `main() -> int` and is invoked by `sentinel <name>` via
the CLI dispatcher. Keeping them thin means the daemon lifecycle lives in one
place and the logic stays testable without starting a process.
"""
