"""Momeala de `systemctl` pentru `_fake_host.py`. Nu e fișier de teste.

Starea: JSON cu `units` (nume -> {state: active|inactive|failed, enabled: enabled|disabled|static,
restarts, enter}), `timers` (nume -> stare) și `flap` (unitățile al căror NRestarts crește la FIECARE
`show` — o buclă de repornire). Orice comandă necunoscută iese cu 99.
"""

from __future__ import annotations

import json
import os
import sys

sys.stdout.reconfigure(newline="\n", encoding="utf-8")
PATH = os.environ["FAKE_SYSTEMCTL_STATE"]


def load() -> dict:
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save(st: dict) -> None:
    with open(PATH, "w", encoding="utf-8") as fh:
        json.dump(st, fh)


def line(name: str, active: str, sub: str) -> str:
    return f"{name} loaded {active} {sub} desc"


def main() -> int:
    a = sys.argv[1:]
    st = load()
    units, timers = st["units"], st["timers"]
    if a and a[0] == "--failed":
        for n, u in units.items():
            if u["state"] == "failed":
                print("● " + line(n, "failed", "failed"))
        return 0
    cmd, rest = a[0], a[1:]
    if cmd == "list-units":
        flags = " ".join(rest)
        if "system-update-" in flags:
            return 0
        if "--type=service" in rest and "--state=running" in rest:
            for n, u in units.items():
                if u["state"] == "active":
                    print(line(n, "active", "running"))
        elif "--type=timer" in rest and "--state=active" in rest:
            for n, s in timers.items():
                if s == "active":
                    print(line(n, "active", "waiting"))
        elif "--all" in rest:
            for n, u in units.items():
                print(line(n, u["state"], "running" if u["state"] == "active" else "dead"))
            for n, s in timers.items():
                print(line(n, s, "waiting"))
        else:
            print(f"fake systemctl: {a}", file=sys.stderr)
            return 99
        return 0
    if cmd == "list-unit-files":
        want = [x.split("=", 1)[1] for x in rest if x.startswith("--state=")]
        names = [x for x in rest if not x.startswith("--")]
        for n, u in units.items():
            if want and u["enabled"] in want:
                print(f"{n} {u['enabled']} enabled")
            elif names and n in names:
                print(f"{n} {u['enabled']} enabled")
        return 0
    if cmd == "list-timers":
        for n in st.get("ctimers", []):
            print(f"Sun 2026-11-22 04:30:00 EET 2 days left - - {n} {n[:-6]}.service")
        return 0
    if cmd == "is-active":
        quiet = "--quiet" in rest
        name = [x for x in rest if not x.startswith("--")][0]
        state = units.get(name, {}).get("state", timers.get(name, "inactive"))
        if not quiet:
            print(state)       # systemctl is-active tipărește starea și când e activ
        return 0 if state == "active" else 3
    if cmd == "show":
        props = []
        value = "--value" in rest
        i = 0
        while i < len(rest):
            if rest[i] == "-p":
                props.append(rest[i + 1])
                i += 2
            else:
                i += 1
        name = [x for x in rest if not x.startswith("-") and x not in props][-1]
        u = units.get(name)
        if u is None:
            u = {"state": timers.get(name, "inactive"), "restarts": 0, "enter": 0}
        if name in st.get("flap", []):
            u["restarts"] = u.get("restarts", 0) + 1
            units[name] = u
            save(st)
        vals = {"ActiveState": "active" if u["state"] == "active" else u["state"], "NRestarts": str(u.get("restarts", 0)),
                "ActiveEnterTimestampMonotonic": str(u.get("enter", 0)), "MainPID": "0"}
        for p in props:
            print(vals[p] if value else f"{p}={vals[p]}")
        return 0
    print(f"fake systemctl: {a}", file=sys.stderr)
    return 99


if __name__ == "__main__":
    sys.exit(main())
