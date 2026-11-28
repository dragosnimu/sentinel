"""Momelile `docker`, `curl` și `df` pentru testele `scripts/docker-prune-buildcache.sh`. Nu e fișier de teste.

Starea gazdei e un JSON (FAKE_PRUNE_STATE); fiecare apel e notat în FAKE_PRUNE_LOG, ca testele care promit «nu șterge decât cache-ul de
build» să citească JURNALUL de apeluri, nu codul de ieșire. Apelat din scripturile-înveliș din `_prune_world.py`: argv[1] = numele
uneltei, restul = argumentele ei.

Modurile lui `prune_mode` (cheia din stare) modelează ce poate face un prune în realitate:
  normal        șterge intrările care nu sunt în uz, tipărește «Total:», eliberează spațiu pe disc
  noop          tipărește «Total:  0B» și iese cu 0, dar nu șterge nimic (exact forma unui prune care n-a făcut nimic)
  partial_ok    șterge jumătate din intrările eliberabile și iese cu 0 (un prune care a făcut doar o parte, fără să spună)
  partial_fail  șterge jumătate din intrările eliberabile și iese cu 1
  overreach     ca `docker system prune -a --volumes`: șterge intrările, imaginile din `victim_images` și volumele din `victim_volumes`
  parallel      șterge ce se poate ȘI apare o intrare nouă de cache, o imagine nouă (un build în paralel)
  fail          iese cu 1 fără să șteargă nimic

Ce NU modelează: formatul real al lui `docker buildx ls --format json` dincolo de câmpurile pe care le citește biblioteca (Name, Driver,
Current), nici `GET /system/df` dincolo de BuildCache[].ID/InUse/Size. Forma reală a fost citită pe gazdă (doar citire) pe 28 nov 2026.
"""

from __future__ import annotations

import json
import os
import sys


def load() -> dict:
    with open(os.environ["FAKE_PRUNE_STATE"], encoding="utf-8") as fh:
        return json.load(fh)


def save(st: dict) -> None:
    with open(os.environ["FAKE_PRUNE_STATE"], "w", encoding="utf-8") as fh:
        json.dump(st, fh)


def log(line: str) -> None:
    with open(os.environ["FAKE_PRUNE_LOG"], "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def human(n: int) -> str:
    return "%.2fGB" % (n / 1e9)


def do_prune(st: dict, mode: str) -> int:
    busy = set(st.get("busy_during_prune", []))     # ajung în uz în timp ce prune rulează (un build pornit): prune le lasă
    reclaimable = [e for e in st["cache"] if not e["InUse"] and not e["Shared"] and e["ID"] not in busy]
    if mode == "fail":
        print("Error response from daemon: prune cache failed", file=sys.stderr)
        return 1
    if mode == "noop":
        print("Total:\t0B")
        return 0
    victims = reclaimable[: len(reclaimable) // 2] if mode in ("partial_fail", "partial_ok") else reclaimable
    gone = {e["ID"] for e in victims}
    freed = sum(e["Size"] for e in victims)
    st["cache"] = [dict(e, InUse=True) if e["ID"] in busy else e for e in st["cache"] if e["ID"] not in gone]
    st["df"]["used"] -= freed
    st["df"]["avail"] += freed
    if st.get("drop_shared_during_prune"):
        st["cache"] = [e for e in st["cache"] if not e["Shared"]]
    if "images_after_prune" in st:
        st["images"] = st["images_after_prune"]
    if mode == "overreach":
        v_img = set(st.get("victim_images", []))
        st["images"] = [i for i in st["images"] if i[0] not in v_img and i[1] not in v_img]
        v_vol = set(st.get("victim_volumes", []))
        st["volumes"] = [v for v in st["volumes"] if v not in v_vol]
    if mode == "parallel":
        st["cache"].append({"ID": "newbuild0001", "InUse": True, "Shared": False, "Size": 1234567})
        st["images"].append(["sha256:" + "ee" * 32, "app/new:build"])
    save(st)
    print("Deleted build cache objects:")
    for e in victims:
        print(e["ID"])
    print("Total:\t" + human(freed))
    return 1 if mode == "partial_fail" else 0


def docker(args: list[str]) -> int:
    st = load()
    log("docker " + " ".join(args))
    if args[:1] == ["version"]:
        if st.get("daemon") == "down":
            print("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", file=sys.stderr)
            return 1
        print(st["server"])
        return 0
    if args[:2] == ["buildx", "version"]:
        if st["buildx"] == "absent":
            print("docker: 'buildx' is not a docker command.", file=sys.stderr)
            return 1
        print("github.com/docker/buildx v0.38.0 0dbe87f")
        return 0
    if args[:2] == ["buildx", "ls"]:
        if st["buildx"] == "absent":
            print("docker: 'buildx' is not a docker command.", file=sys.stderr)
            return 1
        for b in st["builders"]:
            print(json.dumps({"Current": b["Current"], "Driver": b["Driver"], "Dynamic": False, "Name": b["Name"],
                              "Nodes": [{"Endpoint": "default", "GCPolicy": [{"all": False}]}]}))
        return 0
    if args[:1] == ["info"]:
        print(st["root"])
        return 0
    if args[:2] == ["image", "ls"]:
        for iid, ref in st["images"]:
            print(f"{iid} {ref}")
        return 0
    if args[:2] == ["volume", "ls"]:
        for v in st["volumes"]:
            print(v)
        return 0
    if args == ["builder", "prune", "-a", "-f"]:
        return do_prune(st, st.get("prune_mode", "normal"))
    # Tot ce urmează sunt formele pe care prune-ul acestui script NU are voie să le folosească: modelează ce ar face dacă cineva le-ar chema.
    if args[:2] in (["system", "prune"], ["image", "prune"], ["volume", "prune"], ["buildx", "prune"], ["builder", "prune"]):
        return do_prune(st, "overreach")
    print("fake docker: apel neașteptat: " + " ".join(args), file=sys.stderr)
    return 99


def curl(args: list[str]) -> int:
    st = load()
    log("curl " + " ".join(args))
    mode = st.get("curl_mode", "ok")
    if mode == "fail":
        print("curl: (7) Couldn't connect to server", file=sys.stderr)
        return 7
    if mode == "garbage":
        print("{}")
        return 0
    if mode == "not_json":
        print("<html>502</html>")
        return 0
    print(json.dumps({"LayersSize": 1, "Images": [], "BuildCache": st["cache"] or None}))
    return 0


def df(args: list[str]) -> int:
    st = load()
    log("df " + " ".join(args))
    print("1B-blocks         Used        Avail")
    d = st["df"]
    print(f"{d['size']} {d['used']} {d['avail']}")
    return 0


if __name__ == "__main__":
    sys.exit({"docker": docker, "curl": curl, "df": df}[sys.argv[1]](sys.argv[2:]))
