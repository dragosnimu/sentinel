"""Momeala de `docker` pentru testele scripturilor `system-update-*.sh`. Nu e fișier de teste.

Ține starea într-un JSON (`FAKE_DOCKER_STATE`) și notează fiecare invocare (argv separat prin
TAB) în `FAKE_DOCKER_LOG`. Cunoaște DOAR comenzile și formatele `-f` pe care le folosește codul;
orice altceva iese cu 99 și mesaj — o comandă nouă din script pică testele, nu trece pe lângă ele.

Efectele sunt SCRIPTATE în stare, nu deduse: `build_effect`, `pull_effect`, `up_effect` spun ce
face fiecare comandă când e chemată (imagine nouă / aceeași / eșec / recreare reală sau nu).
Asta e ce permite unui test să înfățișeze un `up` care iese cu 0 și NU recreează nimic.

state = {
  "images":     {ref_or_id: {"id": "sha256:..", "created": iso, "digests": n}},
  "containers": {name: {"id", "image_id", "config_image", "state", "health"|None, "restart", "started",
                         "created", "policy", "entrypoint": [], "cmd": [], "labels": {}, "exec": {"text": str, "rc": int}}},
  "compose":    {project: {"config": {json compose config}, "hashes": {svc: h}}},
  "build_effect": {svc: {"rc": 0, "new_id": "sha256:.."}},
  "pull_effect":  {ref: {"rc": 0, "new_id": "sha256:.." | null}},
  "up_effect":    {svc: "recreate" | "noop"},
  "up_image":     {svc: id}   (opțional: `compose up` recreează serviciul, dar pe imaginea `id`, nu pe cea de pe etichetă — un redeploy străin în fereastra tag->up)
  "up_rc":        {svc: n}   (opțional: `compose up` face efectul din up_effect, dar iese cu n — ca un `up` care recreează și cade apoi)
  "tag_effect":   "fail" | "wrong"   (opțional: `docker tag` iese 1 / iese 0 dar pune altă imagine),
  build_effect[svc]["drop"]: true    (opțional: build iese 0, dar imaginea serviciului dispare din stare)
  "swap_on_pull": {ref: {"container": name, "image_id": id}}  (opțional: un `docker pull` pe `ref` mută, în timpul lui, containerul pe altă
                  imagine — ca un redeploy făcut de altcineva între clasificare și etichetare)
  "now": iso
}
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

# Pe Windows print() ar scrie CRLF, iar `read -r` din script ar citi nume cu CR la coada.
sys.stdout.reconfigure(newline="\n")
sys.stderr.reconfigure(newline="\n")
STATE_PATH = os.environ["FAKE_DOCKER_STATE"]
LOG_PATH = os.environ.get("FAKE_DOCKER_LOG")


def load() -> dict:
    with open(STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")


def die(msg: str) -> None:
    sys.stderr.write(f"fake docker: {msg}\n")
    sys.exit(99)


def find_container(state: dict, key: str) -> tuple[str, dict] | None:
    for name, c in state["containers"].items():
        if key in (name, c.get("id")):
            return name, c
    return None


def render(fmt: str, name: str, c: dict) -> str:
    """Un subset de șabloane Go: exact câmpurile pe care le cere codul."""
    out = fmt
    health = c.get("health")
    out = out.replace("{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", health if health else "none")
    out = re.sub(r"\{\{range \.Config\.Entrypoint\}\}\{\{\.\}\} \{\{end\}\}", "".join(a + " " for a in c.get("entrypoint", [])), out)
    out = re.sub(r"\{\{range \.Config\.Cmd\}\}\{\{\.\}\} \{\{end\}\}", "".join(a + " " for a in c.get("cmd", [])), out)
    out = re.sub(r'\{\{index \.Config\.Labels "([^"]+)"\}\}', lambda m: c.get("labels", {}).get(m.group(1), ""), out)
    table = {
        "{{.State.Status}}": c["state"],
        "{{.Config.Image}}": c["config_image"],
        "{{.Image}}": c["image_id"],
        "{{.Created}}": c.get("created", "2026-01-01T00:00:00Z"),
        "{{.Name}}": "/" + name,
        "{{.RestartCount}}": str(c.get("restart", 0)),
        "{{.State.StartedAt}}": c.get("started", "2026-01-01T00:00:00Z"),
        "{{.HostConfig.RestartPolicy.Name}}": c.get("policy", "unless-stopped"),
        "{{.Id}}": c.get("id", name),
    }
    for k, v in table.items():
        out = out.replace(k, v)
    if "{{" in out:
        die(f"șablon inspect necunoscut: {out}")
    return out


def set_tag_id(state: dict, ref: str, new_id: str, digests: int) -> None:
    """Ca docker real: eticheta se mută pe imaginea nouă, iar cea veche RĂMÂNE (acum fără etichetă),
    adresabilă după ID — de aceea `docker tag <id-vechi> rollback/...` funcționează după un build."""
    old = state["images"].get(ref)
    if old and old["id"] and old["id"] != new_id:
        state["images"].setdefault(old["id"], dict(old))
    img = state["images"].setdefault(ref, {"id": "", "created": now_iso(), "digests": digests})
    img["id"] = new_id
    img["created"] = now_iso()


def cmd_inspect(state: dict, args: list[str]) -> int:
    if args[0] != "-f":
        die("inspect fără -f")
    fmt, key = args[1], args[2]
    found = find_container(state, key)
    if not found:
        sys.stderr.write(f"Error: No such object: {key}\n")
        return 1
    name, c = found
    out = render(fmt, name, c)
    # `flap_restart`: fiecare citire arată un RestartCount mai mare (un container în buclă).
    if state.get("flap_restart") and name in state["flap_restart"] and "{{.RestartCount}}" in fmt:
        c["restart"] = c.get("restart", 0) + 1
        save(state)
    print(out)
    return 0


def cmd_image_inspect(state: dict, args: list[str]) -> int:
    fmt = None
    if args[0] == "-f":
        fmt, args = args[1], args[2:]
    key = args[0]
    img = state["images"].get(key)
    if img is None:
        for v in state["images"].values():
            if v["id"] == key:
                img = v
                break
    if img is None:
        sys.stderr.write(f"Error: No such image: {key}\n")
        return 1
    if fmt is None:
        print(json.dumps([img]))
    elif fmt == "{{.Id}}":
        print(img["id"])
    elif fmt == "{{.Created}}":
        print(img.get("created", "2026-01-01T00:00:00Z"))
    elif fmt == "{{len .RepoDigests}}":
        print(img.get("digests", 0))
    else:
        die(f"image inspect cu format necunoscut {fmt}")
    return 0


def cmd_ps(state: dict, args: list[str]) -> int:
    if "--format" not in args:      # `docker ps -a -q`
        for name, c in state["containers"].items():
            print(c.get("id", name))
        return 0
    fmt = args[args.index("--format") + 1]
    for name, c in state["containers"].items():
        row = fmt
        row = row.replace("{{.ID}}", c.get("id", name)).replace("{{.Names}}", name)
        row = row.replace('{{.Label "com.docker.compose.project"}}', c.get("labels", {}).get("com.docker.compose.project", ""))
        row = row.replace('{{.Label "com.docker.compose.service"}}', c.get("labels", {}).get("com.docker.compose.service", ""))
        if "{{" in row:
            die(f"ps cu format necunoscut {fmt}")
        print(row)
    return 0


def cmd_compose(state: dict, args: list[str]) -> int:
    project = args[args.index("-p") + 1]
    comp = state["compose"].get(project)
    if comp is None:
        sys.stderr.write(f"no such project {project}\n")
        return 1
    i = 0
    while i < len(args) and args[i] in ("-p", "--project-directory", "-f"):
        i += 2
    verb, rest = args[i], args[i + 1:]
    if verb == "config":
        if rest[:2] == ["--format", "json"]:
            print(json.dumps(comp["config"]))
        elif rest[0] == "--hash":
            print(f"{rest[1]} {comp['hashes'][rest[1]]}")
        else:
            die(f"compose config {rest}")
        return 0
    if verb == "build":
        svcs = [a for a in rest if not a.startswith("--")]
        rc = 0
        for s in svcs:
            eff = state.get("build_effect", {}).get(s, {"rc": 0, "new_id": None})
            if eff["rc"] != 0:
                rc = eff["rc"]
                continue
            if eff.get("new_id"):
                ref = comp["config"]["services"][s].get("image") or f"{project}-{s}"
                for name, c in state["containers"].items():
                    if c["labels"].get("com.docker.compose.service") == s and c["labels"].get("com.docker.compose.project") == project:
                        ref = c["config_image"]
                set_tag_id(state, ref, eff["new_id"], 0)
                state["images"][ref]["created"] = now_iso()
            if eff.get("drop"):      # build care iese 0, dar imaginea nu se mai poate citi după el
                for name, c in state["containers"].items():
                    if c["labels"].get("com.docker.compose.service") == s and c["labels"].get("com.docker.compose.project") == project:
                        state["images"].pop(c["config_image"], None)
        save(state)
        return rc
    if verb == "up":
        svcs = [a for a in rest if not a.startswith("-")]
        if not svcs:
            die("`up` fără servicii numite — ar recrea tot proiectul")
        up_rc = next((state.get("up_rc", {}).get(s, 0) for s in svcs if state.get("up_rc", {}).get(s, 0)), 0)
        for s in svcs:
            effect = state.get("up_effect", {}).get(s, "recreate")
            if effect not in ("recreate", "recreate_old_created", "recreate_starting", "recreate_unhealthy"):
                continue
            for name, c in state["containers"].items():
                if c["labels"].get("com.docker.compose.service") == s and c["labels"].get("com.docker.compose.project") == project:
                    # `up_image`: un redeploy făcut de altcineva chiar în fereastra dintre `tag` și `up` — containerul rezultat rulează ALTĂ imagine decât
                    # cea pe care o numește eticheta (efect scriptat, ca `swap_on_pull`, dar în `up`).
                    c["image_id"] = state.get("up_image", {}).get(s) or state["images"][c["config_image"]]["id"]
                    if effect != "recreate_old_created":      # `recreate_old_created`: ID nou, dar containerul NU e recreat acum
                        c["created"] = now_iso()
                    c["started"] = now_iso()
                    c["state"] = "running"
                    if effect == "recreate_starting":     # nu iese niciodată din `starting`
                        c["health"] = "starting"
                    elif effect == "recreate_unhealthy":  # pornește, dar healthcheck-ul pică
                        c["health"] = "unhealthy"
        save(state)
        return up_rc
    if verb == "ps":
        svc = rest[-1]
        for name, c in state["containers"].items():
            if c["labels"].get("com.docker.compose.service") == svc and c["labels"].get("com.docker.compose.project") == project:
                print(c.get("id", name))
        return 0
    die(f"compose {verb}")
    return 99


def main() -> int:
    argv = sys.argv[1:]
    if LOG_PATH:
        with open(LOG_PATH, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("\t".join(argv) + "\n")
    state = load()
    cmd, args = argv[0], argv[1:]
    if cmd == "info":
        print("27.0.0")
        return 0
    if cmd == "version":
        print("27.0.0")
        return 0
    if cmd == "inspect":
        return cmd_inspect(state, args)
    if cmd == "image" and args[0] == "inspect":
        return cmd_image_inspect(state, args[1:])
    if cmd == "ps":
        return cmd_ps(state, args)
    if cmd == "compose":
        if args and args[0] == "version":
            print("5.6.0")
            return 0
        if args and args[0] == "ls":
            return 0
        return cmd_compose(state, args)
    if cmd == "tag":
        src, dst = args
        img = state["images"].get(src) or next((v for v in state["images"].values() if v["id"] == src), None)
        if img is None:
            sys.stderr.write(f"no such image {src}\n")
            return 1
        mode = state.get("tag_effect")      # "fail": docker tag iese 1; "wrong": iese 0 dar eticheta arată altă imagine
        if mode == "fail":
            sys.stderr.write("Error response from daemon: tag failed\n")
            return 1
        if mode == "wrong":
            img = {"id": "sha256:" + "ee" * 32, "digests": 0}
        state["images"][dst] = dict(img)
        save(state)
        return 0
    if cmd == "pull":
        ref = args[-1]
        eff = state.get("pull_effect", {}).get(ref, {"rc": 0, "new_id": None})
        if eff["rc"] == 0 and eff.get("new_id"):
            set_tag_id(state, ref, eff["new_id"], 1)
            save(state)
        swap = state.get("swap_on_pull", {}).get(ref)
        if swap:
            state["containers"][swap["container"]]["image_id"] = swap["image_id"]
            save(state)
        return eff["rc"]
    if cmd == "exec":
        found = find_container(state, args[0])
        if not found or found[1].get("exec") is None:
            sys.stderr.write("exec: container fără dump scriptat\n")
            return 1
        ex = found[1]["exec"]
        sys.stdout.write(ex["text"])
        return ex.get("rc", 0)
    die(f"comandă necunoscută: {argv}")
    return 99


if __name__ == "__main__":
    sys.exit(main())
