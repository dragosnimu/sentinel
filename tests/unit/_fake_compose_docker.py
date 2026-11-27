"""Momeala de `docker` pentru testele `scripts/compose-pin.sh`. Nu e fișier de teste.

Ține starea într-un JSON (`FAKE_CPIN_STATE`) și notează fiecare invocare (argv separat prin TAB) în `FAKE_CPIN_LOG`. Cunoaște DOAR
comenzile și formatele `--format` pe care le folosește scriptul, potrivite EXACT; orice altceva iese cu 99 (deci un `docker compose up`,
`restart`, `rm`, `stop` sau `run` strecurat în script pică testele, nu trece pe lângă ele).

Ce MODELEAZĂ (nu scriptează): `docker compose config` CITEȘTE FIȘIERUL de pe disc în momentul apelului (yaml -> JSON, cu `${VAR}` din
`interp`), deci o editare greșită a fișierului se vede în JSON-ul de după; `--hash` e sha256 al configurației serviciului. Ce NU
reproduce: un compose real (normalizarea valorilor, `include`, profile, `.env`), un daemon real, un registry. Formele `ps`/`inspect` sunt
cele ale lui docker 29 măsurate pe gazdă read-only pe 26 noiembrie 2026, nu garantate.

state = {
  "project": "root",
  "containers": {name: {"id","state","started","restart","image_id","labels": {k: v}}},
  "images": {ref_sau_id: {"id": "sha256:..", "digests": [..]}},
  "known_pulls": {ref: id_imagine},     (un pull pe altceva iese 1 cu «manifest unknown»)
  "pull_error": str,                    (un pull care eșuează cu ACEST mesaj, pentru orice ref)
  "interp": {"VAR": "valoare"},
  "compose_fail": bool,                 (`docker compose config` iese 1 cu un mesaj care CITEAZĂ o valoare secretă)
  "fail_if_contains": str,              (la fel, dar doar când fișierul conține șirul: compose care nu mai poate citi fișierul EDITAT)
  "hash_unsupported": bool,
  "tamper": {"if_contains": str, "service": s, "set": {câmp: valoare}},   (JSON-ul iese cu un câmp schimbat dacă fișierul conține șirul)
  "hooks": [{"on": "pull" | "config-json:N" | "config-hash:N", "action": "append", "path": p, "text": t, "glob": bool}
            | {"on": ..., "action": "container", "name": n, "field": "restart"}],
  "pull_digests": false                 (imaginile trase nu au RepoDigests: ca una venită doar local)
  "config_hash_fail_on_call": n         (al n-lea apel `config --hash` din stare iese 1: o măsurare picată DUPĂ up)
  "up_killed": bool                     (up iese 137 fără să facă nimic: omorât/întrerupt)
  "up_effect": "noop",                  (`up` iese 0 și NU recreează nimic); "up_rc": n; "up_remove": bool (după up nu mai există container);
  "up_stale_label": bool (containerul nou poartă un hash vechi); "up_image": id (rulează altă imagine); "up_health": "healthy"|"starting"|"unhealthy";
  "flap_new_after_reads": n (containerul recreat repornește la a n-a citire de eșantion)
  "calls": {eveniment: n}
}
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sys

sys.stdout.reconfigure(newline="\n")
sys.stderr.reconfigure(newline="\n")
STATE_PATH = os.environ.get("FAKE_CPIN_STATE", "")
LOG_PATH = os.environ.get("FAKE_CPIN_LOG")
SECRET_IN_ERROR = "SECRET_TWILIO_8f3a2c91"

F_NAMES = "{{.Names}}"
F_PROJECT = '{{.Label "com.docker.compose.project"}}'
F_STATUS = "{{.State.Status}}"
F_IMAGE = "{{.Image}}"
F_FP = "{{.Id}} {{.State.StartedAt}} {{.RestartCount}} {{.Image}}"
F_HASHLABEL = '{{index .Config.Labels "com.docker.compose.config-hash"}}'
F_IMGID = "{{.Id}}"
F_DIGESTS = "{{range .RepoDigests}}{{.}} {{end}}"
F_SAMPLE = "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.Image}}|{{.Created}}"
F_ID = "{{.Id}}"
F_CFGIMAGE = "{{.Config.Image}}"
F_NDIGESTS = "{{len .RepoDigests}}"


def native(p: str) -> str:
    if os.name == "nt" and re.match(r"^/[A-Za-z]/", p):
        return p[1].upper() + ":" + p[2:]
    return p


def load() -> dict:
    with open(STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def die(msg: str) -> int:
    sys.stderr.write(f"fake compose docker: {msg}\n")
    sys.exit(99)


def fire_hooks(state: dict, event: str) -> None:
    state.setdefault("calls", {})
    state["calls"][event.split(":")[0]] = state["calls"].get(event.split(":")[0], 0) + 1
    n = state["calls"][event.split(":")[0]]
    for hook in state.get("hooks", []):
        if hook["on"] not in (event.split(":")[0], f"{event.split(':')[0]}:{n}"):
            continue
        if hook["action"] == "append":
            targets = glob.glob(native(hook["path"]) + "*") if hook.get("glob") else [native(hook["path"])]
            for t in targets:
                with open(t, "ab") as fh:
                    fh.write(hook["text"].encode("utf-8"))
        elif hook["action"] == "container":
            c = state["containers"][hook["name"]]
            if hook["field"] == "restart":
                c["restart"] += 1
            else:
                die(f"hook container: câmp necunoscut {hook['field']}")
    save(state)


def service_hash(service: dict) -> str:
    return hashlib.sha256(json.dumps(service, sort_keys=True).encode("utf-8")).hexdigest()


def render_config(state: dict, path: str) -> dict | None:
    import yaml

    with open(native(path), "rb") as fh:
        raw = fh.read().decode("utf-8")
    if state.get("compose_fail") or (state.get("fail_if_contains") and state["fail_if_contains"] in raw):
        sys.stderr.write(f"error while interpolating services.n8n.environment: invalid value {SECRET_IN_ERROR}\n")
        return None
    text = re.sub(r"\$\{([A-Za-z_]+)\}", lambda m: state.get("interp", {}).get(m.group(1), ""), raw)
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        sys.stderr.write("yaml: parse error\n")
        return None
    cfg = {"name": state["project"], "services": doc.get("services") or {}}
    for key in ("networks", "volumes"):
        if key in doc:
            cfg[key] = doc[key]
    tamper = state.get("tamper")
    if tamper and tamper["if_contains"] in raw:
        cfg["services"][tamper["service"]].update(tamper["set"])
    return cfg


def main() -> int:
    argv = sys.argv[1:]
    if LOG_PATH:
        with open(LOG_PATH, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("\t".join(argv) + "\n")
    state = load()
    cmd, args = argv[0], argv[1:]
    if cmd == "version":
        print("29.0.0")
        return 0
    if cmd == "ps":
        return do_ps(state, args)
    if cmd == "container" and args[0] == "inspect":
        return do_container_inspect(state, args[1:])
    if cmd == "image" and args[0] == "inspect":
        return do_image_inspect(state, args[1:])
    if cmd == "pull":
        return do_pull(state, args)
    if cmd == "compose":
        return do_compose(state, args)
    return die(f"comandă necunoscută: {argv}")


def do_ps(state: dict, args: list[str]) -> int:
    assert args[0] == "-a", args
    rest = args[1:]
    filters = []
    while rest and rest[0] == "--filter":
        assert rest[1].startswith("label="), rest
        k, _, v = rest[1][len("label="):].partition("=")
        filters.append((k, v))
        rest = rest[2:]
    assert rest[0] == "--format" and len(rest) == 2, rest
    fmt = rest[1]
    for name, c in state["containers"].items():
        if all(c["labels"].get(k) == v for k, v in filters):
            if fmt == F_NAMES:
                print(name)
            elif fmt == F_PROJECT:
                print(c["labels"].get("com.docker.compose.project", ""))
            else:
                return die(f"ps: format necunoscut {fmt!r}")
    return 0


def do_container_inspect(state: dict, args: list[str]) -> int:
    assert args[0] == "--format", args
    fmt, name = args[1], args[2]
    c = state["containers"].get(name)
    if c is None:
        sys.stderr.write(f"Error response from daemon: No such container: {name}\n")
        return 1
    if fmt == F_STATUS:
        print(c["state"])
    elif fmt == F_IMAGE:
        print(c["image_id"])
    elif fmt == F_FP:
        print(f"{c['id']} {c['started']} {c['restart']} {c['image_id']}")
    elif fmt == F_HASHLABEL:
        print(c["labels"].get("com.docker.compose.config-hash", ""))
    elif fmt == F_ID:
        print(c["id"])
    elif fmt == F_CFGIMAGE:
        print(c.get("config_image", ""))
    elif fmt == F_SAMPLE:
        c["reads"] = c.get("reads", 0) + 1
        flap = state.get("flap_new_after_reads")
        if flap and c.get("recreated") and c["reads"] >= flap:
            c["restart"] += 1
            c["started"] = f"2026-11-26T12:00:{c['reads']:02d}.000000000Z"
        state["containers"][name] = c
        save(state)
        print(f"{c['state']}|{c.get('health', 'none')}|{c['restart']}|{c['started']}|{c['image_id']}|{c.get('created', '-')}")
    else:
        return die(f"container inspect: format necunoscut {fmt!r}")
    return 0


def do_image_inspect(state: dict, args: list[str]) -> int:
    assert args[0] == "--format", args
    fmt, ref = args[1], args[2]
    img = state["images"].get(ref) or next((v for v in state["images"].values() if v["id"] == ref), None)
    if img is None:
        sys.stderr.write(f"Error response from daemon: No such image: {ref}\n")
        return 1
    if fmt == F_IMGID:
        print(img["id"])
    elif fmt == F_NDIGESTS:
        print(len(img.get("digests", [])))
    elif fmt == F_DIGESTS:
        sys.stdout.write("".join(d + " " for d in img.get("digests", [])) + "\n")
    else:
        return die(f"image inspect: format necunoscut {fmt!r}")
    return 0


def do_pull(state: dict, args: list[str]) -> int:
    assert args[0] == "-q" and len(args) == 2, args
    ref = args[1]
    fire_hooks(state, "pull")
    state = load()
    if state.get("pull_error"):
        sys.stderr.write(state["pull_error"] + "\n")
        return 1
    if ref not in state.get("known_pulls", {}):
        sys.stderr.write(f"Error response from daemon: manifest for {ref} not found: manifest unknown\n")
        return 1
    new_id = state["known_pulls"][ref]
    # o imagine trasă dintr-un registru are RepoDigests (`pull_digests: false` o face să nu aibă, ca una construită local)
    digests = [ref.split("@")[0].rsplit(":", 1)[0] + "@sha256:" + new_id.split(":")[1]] if state.get("pull_digests", True) else []
    state["images"].setdefault(ref, {"id": new_id, "digests": digests})
    save(state)
    print(new_id)
    return 0


def do_up(state: dict, project: str, path: str, rest: list[str]) -> int:
    """`up -d --no-deps --no-build --force-recreate SVC...`: SINGURA formă acceptată (orice altă formă, mai ales fără --no-deps, ar atinge tot proiectul)."""
    assert rest[:4] == ["-d", "--no-deps", "--no-build", "--force-recreate"] and len(rest) > 4, rest
    cfg = render_config(load(), path)
    if cfg is None:
        return 1
    fire_hooks(state, "up")
    state = load()
    # ce avea scriptul pe stdout în clipa în care a fost chemat `up` (testul îl redirectează într-un fișier): dovada de ORDINE pentru marcajul UP_RAN
    outfile = os.environ.get("FAKE_CPIN_OUTFILE")
    if outfile and os.path.exists(native(outfile)):
        with open(native(outfile), encoding="utf-8", errors="replace") as fh:
            state["out_at_up"] = fh.read()
        save(state)
    if state.get("up_killed"):
        sys.stderr.write("simulat: up omorât înainte să facă ceva\n")
        return 137
    for svc in rest[4:]:
        for name, c in state["containers"].items():
            if c["labels"].get("com.docker.compose.service") != svc or c["labels"].get("com.docker.compose.project") != project:
                continue
            if state.get("up_effect") == "noop":
                continue
            n = state.get("up_count", 0) + 1
            state["up_count"] = n
            image_ref = cfg["services"][svc]["image"]
            c["id"] = f"{n:02x}" * 32
            c["created"] = f"2026-11-26T12:00:{n:02d}.000000000Z"
            c["started"] = c["created"]
            c["restart"] = 0
            c["reads"] = 0
            c["recreated"] = True
            c["state"] = "running"
            c["health"] = state.get("up_health", "none")
            c["image_id"] = state.get("up_image") or state["images"][image_ref]["id"]
            c["labels"]["com.docker.compose.config-hash"] = "STALE" if state.get("up_stale_label") else service_hash(cfg["services"][svc])
    if state.get("up_remove"):
        for name in [n for n, c in state["containers"].items() if c["labels"].get("com.docker.compose.service") in rest[4:]]:
            del state["containers"][name]
    save(state)
    sys.stderr.write(f"Container up (stderr simulat; poate cita {SECRET_IN_ERROR})\n")
    return state.get("up_rc", 0)


def do_compose(state: dict, args: list[str]) -> int:
    assert args[0] == "-p" and args[2] == "-f", args
    if args[4] == "up":
        return do_up(state, args[1], args[3], args[5:])
    assert args[4] == "config", args
    project, path, rest = args[1], args[3], args[5:]
    if project != state["project"]:
        sys.stderr.write("no configuration file provided\n")
        return 1
    if rest == ["--format", "json"]:
        fire_hooks(state, "config-json")
        cfg = render_config(load(), path)
        if cfg is None:
            return 1
        print(json.dumps(cfg))
        return 0
    if rest == ["--hash", "*"]:
        if state.get("hash_unsupported"):
            sys.stderr.write("unknown flag: --hash\n")
            return 1
        fire_hooks(state, "config-hash")
        state = load()
        if state.get("config_hash_fail_on_call") and state["calls"].get("config-hash") == state["config_hash_fail_on_call"]:
            sys.stderr.write("simulat: --hash eșuează la acest apel\n")
            return 1
        cfg = render_config(load(), path)
        if cfg is None:
            return 1
        for name in sorted(cfg["services"]):
            print(f"{name} {service_hash(cfg['services'][name])}")
        return 0
    return die(f"compose config: argumente necunoscute {rest}")


if __name__ == "__main__":
    sys.exit(main())
