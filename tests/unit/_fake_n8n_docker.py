"""Momeala de `docker` pentru testele `scripts/n8n-staging.sh`. Nu e fișier de teste.

Ține starea într-un JSON (`FAKE_N8N_STATE`) și notează fiecare invocare (argv separat prin TAB) în `FAKE_N8N_LOG`.
Cunoaște DOAR comenzile și formatele `--format` pe care le folosește scriptul, potrivite EXACT; orice altceva iese cu 99 —
o comandă sau un șablon nou din script pică testele, nu trece pe lângă ele.

Ce MODELEAZĂ (nu scriptează): ieșirea din rețea. O probă (`docker run --entrypoint node` sau `docker exec ... node -e`) vede
TCP/DNS «open» dacă și numai dacă containerul e atașat la o rețea care NU e `--internal`. De aceea un script care uită
`--internal` pică testele fără ca vreun test să-i fi spus asta. `probe_run`/`probe_exec` simulează un nucleu/docker care scapă
pachete deși rețeaua e internă; `mode: "garbage"` simulează o probă care nu rulează deloc (nu e «blocat», e necunoscut).

Ce NU reproduce: un docker real, iptables, DNS-ul încorporat al lui docker, un daemon care refuză. Formele de ieșire (liniile
`{{println}}`, linia goală de la coadă) sunt cele ale lui docker 29 măsurate pe gazdă read-only, nu garantate.

state = {
  "containers": {name: {"id", "state", "restart", "started", "image_id", "labels": {}, "env": [..], "network": name,
                        "mounts": [{"dst","type","name","src","rw"}], "ports": {}, "reads": 0}},
  "volumes":  {name: {"labels": {}, "mountpoint": path}},
  "networks": {name: {"internal": bool, "labels": {}}},
  "images":   {ref_or_id: {"id": "sha256:..", "env": [..]}},
  "known_pulls": [ref, ..]                  (un pull pe altceva iese 1)
  "vol_root": path                          (unde `volume create` face directoare)
  "ip": "172.30.0.2"
  "probe_run" / "probe_exec": {"mode": "model" | "garbage", "tcp": bool, "dns": bool}   (vezi egress_lines)
  "rm_noop": bool                           (`docker rm -f` iese 0 și NU șterge)
  "create_rc": n, "create_stderr": str      (`docker create` eșuat, cu mesajul dat)
  "create_mutate": {...}                    (vezi apply_create_mutation: containerul creat iese cu o formă greșită)
  "gateway_ports": {"80": "open", ...}      (ce raportează proba pentru gateway-ul bridge-ului)
  "release_type": "rc" | null               (N8N_RELEASE_TYPE al imaginii trase; null = nu îl declară)
  "prod_fp_unreadable": bool                (docker inspect pe producție, formatul amprentei, iese 1)
  "start_effect": "run" | "exit"            (`exit`: pornește și iese imediat)
  "restart_after_reads": n                  (a n-a citire de eșantion arată un RestartCount mai mare + alt StartedAt)
  "exit_after_reads": n                     (a n-a citire de eșantion arată «exited»)
  "logs": str
  "mutate_prod_on": "network create", "mutate_prod": "restart_count" | "started_at" | "id" | "image"
  "daemon_down": bool
}
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.stdout.reconfigure(newline="\n")
sys.stderr.reconfigure(newline="\n")
STATE_PATH = os.environ["FAKE_N8N_STATE"]
LOG_PATH = os.environ.get("FAKE_N8N_LOG")
LABEL = "ro.cryptoitdata.n8n-staging"

F_FP = "{{.Id}} {{.State.StartedAt}} {{.RestartCount}} {{.Image}}"
F_STATUS = "{{.State.Status}}"
F_MOUNTS = "{{range .Mounts}}{{.Destination}}|{{.Type}}|{{.Name}}|{{.Source}}|{{.RW}}{{println}}{{end}}"
F_IMAGE = "{{.Image}}"
F_JSON_ENV = "{{json .Config.Env}}"
F_NETMODE = "{{.HostConfig.NetworkMode}}"
F_PORTS = "{{json .HostConfig.PortBindings}}"
F_CLABEL = '{{index .Config.Labels "%s"}}' % LABEL
F_VLABEL = '{{index .Labels "%s"}}' % LABEL
F_NETS = "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}}{{println}}{{end}}"
F_SAMPLE = "{{.State.Status}} {{.RestartCount}} {{.State.StartedAt}}"
F_IMAGEREF = "{{.Config.Image}}"
F_LIMITS = "{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}"
F_GATEWAY = "{{range .IPAM.Config}}{{.Gateway}}{{end}}"


def native(p: str) -> str:
    """Pe Windows, bash vorbește în căi MSYS (`/c/Users/..`), iar Python în căi native (`C:/Users/..`). Starea ține căi native."""
    if os.name == "nt" and re.match(r"^/[A-Za-z]/", p):
        return p[1].upper() + ":" + p[2:]
    return p


def msys(p: str) -> str:
    """Invers: ce tipărește `docker` către bash (ca pe gazdă, o cale care începe cu `/`)."""
    if os.name == "nt" and re.match(r"^[A-Za-z]:[\/]", p):
        return "/" + p[0].lower() + p[2:].replace(chr(92), "/")
    return p


def load() -> dict:
    with open(STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def die(msg: str) -> int:
    sys.stderr.write(f"fake n8n docker: {msg}\n")
    sys.exit(99)


def no_such(kind: str, name: str) -> int:
    sys.stderr.write(f"Error response from daemon: No such {kind}: {name}\n")
    return 1


def fmt_arg(args: list[str]) -> tuple[str | None, list[str]]:
    rest = list(args)
    fmt = None
    for flag in ("--format", "-f"):
        if flag in rest:
            i = rest.index(flag)
            fmt = rest[i + 1]
            del rest[i:i + 2]
    return fmt, rest


def filter_arg(args: list[str]) -> tuple[str | None, list[str]]:
    rest = list(args)
    flt = None
    if "--filter" in rest:
        i = rest.index("--filter")
        flt = rest[i + 1]
        del rest[i:i + 2]
    return flt, rest


def has_label(labels: dict, flt: str | None) -> bool:
    if flt is None:
        return True
    assert flt.startswith("label="), flt
    key = flt[len("label="):]
    return key.partition("=")[0] in labels


def render_container(state: dict, name: str, c: dict, fmt: str) -> str:
    if fmt == F_FP:
        if state.get("prod_fp_unreadable") and name == "root-n8n-1":
            sys.stderr.write("Error response from daemon: simulated unreadable inspect\n")
            sys.exit(1)
        return f"{c['id']} {c['started']} {c['restart']} {c['image_id']}"
    if fmt == F_IMAGEREF:
        return c.get("image_ref", "")
    if fmt == F_LIMITS:
        return f"{c.get('nano_cpus', 0)} {c.get('memory', 0)}"
    if fmt == F_STATUS:
        return c["state"]
    if fmt == F_IMAGE:
        return c["image_id"]
    if fmt == F_JSON_ENV:
        return json.dumps(c["env"])
    if fmt == F_NETMODE:
        return c["network"] or "default"
    if fmt == F_PORTS:
        return json.dumps(c.get("ports") or {})
    if fmt == F_CLABEL:
        return c["labels"].get(LABEL, "")
    if fmt == F_MOUNTS:
        return "".join(f"{m['dst']}|{m['type']}|{m['name']}|{msys(m["src"])}|{'true' if m['rw'] else 'false'}\n" for m in c["mounts"])
    if fmt == F_NETS:
        if c["state"] != "running" or not c["network"]:
            return ""
        nets = c.get("extra_networks", []) + [c.get("reported_network") or c["network"]]
        return "".join(f"{n} {state.get('ip', '172.30.0.2')}\n" for n in nets)
    if fmt == F_SAMPLE:
        c["reads"] = c.get("reads", 0) + 1
        ra, ea = state.get("restart_after_reads"), state.get("exit_after_reads")
        if ra and c["reads"] >= ra and name == "n8n-staging":
            c["restart"] = 1
            c["started"] = "2026-11-25T10:00:09.000000000Z"
        if ea and c["reads"] >= ea and name == "n8n-staging":
            c["state"] = "exited"
        save(state)
        return f"{c['state']} {c['restart']} {c['started']}"
    return die(f"container inspect: șablon necunoscut {fmt!r}")


def egress_lines(state: dict, internal: bool, phase: str, gateway: str = "-") -> str:
    """`phase`: «run» (containerul de probă dinainte de pornire) sau «exec» (din containerul pornit). Fiecare fază poate fi
    stricată separat prin `probe_<phase>` = {"mode": "garbage" | "model", "tcp": bool, "dns": bool} (tcp/dns: forțează «open»).
    Liniile GW<port> raportează gateway-ul bridge-ului: `gateway_ports` = {"80": "open" | "refused" | "blocked" | "unknown"}, implicit
    «refused» (gazda răspunde, nimic nu ascultă); fără gateway (`-`) toate sunt «unknown», ca în proba reală."""
    cfg = state.get(f"probe_{phase}", {})
    if cfg.get("mode") == "garbage":
        return "boom: node nu rulează\n"
    tcp = "open" if (not internal or cfg.get("tcp")) else "blocked"
    dns = "open" if (not internal or cfg.get("dns")) else "blocked"
    lines = [f"DNS={dns}", "SELF=ok", f"TCP={tcp}"]
    for port in ("80", "443", "8443", "5678"):
        status = "unknown" if gateway == "-" else state.get("gateway_ports", {}).get(port, "refused")
        lines.append(f"GW{port}={status}")
    return "\n".join(sorted(lines)) + "\n"


def maybe_mutate_prod(state: dict, argv: list[str]) -> None:
    trig = state.get("mutate_prod_on")
    if trig and " ".join(argv).startswith(trig):
        p = state["containers"]["root-n8n-1"]
        how = state.get("mutate_prod", "restart_count")
        if how == "restart_count":
            p["restart"] += 1
        elif how == "started_at":
            p["started"] = "2026-11-25T11:11:11.000000000Z"
        elif how == "id":
            p["id"] = "f" * 64
        elif how == "image":
            p["image_id"] = "sha256:" + "9" * 64
        elif how == "unreadable":      # amprenta nu se mai poate citi (docker inspect eșuează) de acum încolo
            state["prod_fp_unreadable"] = True
        else:
            die(f"mutate_prod necunoscut: {how}")
        state["mutate_prod_on"] = None
        save(state)


def file_mode(path: str) -> str | None:
    """Modul octal al unui fișier. Pe Linux: `stat` direct, deci modul ADEVĂRAT (testul de 0600 are acolo dinți). Pe Windows (MSYS) `stat`
    maschează cu umask-ul procesului și `chmod` nu face nimic pe NTFS: citirea sub umask 077 e o formalitate, nu o dovadă (vezi
    _n8n_staging_world.UMASK_PREFIX)."""
    import subprocess
    cmd = [os.environ.get("FAKE_N8N_BASH", "bash"), "-c", 'umask 077; stat -c %a "$0"', path] if os.name == "nt" else ["stat", "-c", "%a", path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def main() -> int:
    argv = sys.argv[1:]
    if LOG_PATH:
        with open(LOG_PATH, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("\t".join(argv) + "\n")
    state = load()
    if state.get("daemon_down"):
        sys.stderr.write("Cannot connect to the Docker daemon\n")
        return 1
    cmd, args = argv[0], argv[1:]
    rc = dispatch(state, cmd, args, argv)
    state = load()
    maybe_mutate_prod(state, argv)
    return rc


def dispatch(state: dict, cmd: str, args: list[str], argv: list[str]) -> int:
    if cmd == "version":
        print("29.0.0")
        return 0
    if cmd == "ps":
        flt, rest = filter_arg(args)
        assert rest == ["-a", "--format", "{{.Names}}"], rest
        for n, c in state["containers"].items():
            if has_label(c["labels"], flt):
                print(n)
        return 0
    if cmd in ("volume", "network") and args[0] == "ls":
        flt, rest = filter_arg(args[1:])
        assert rest == ["--format", "{{.Name}}"], rest
        for n, o in state["volumes" if cmd == "volume" else "networks"].items():
            if has_label(o["labels"], flt):
                print(n)
        return 0
    if cmd == "container" and args[0] == "inspect":
        fmt, rest = fmt_arg(args[1:])
        name = rest[0]
        c = state["containers"].get(name)
        if c is None:
            return no_such("container", name)
        out = render_container(state, name, c, fmt or die("container inspect fără --format"))
        print(out)
        return 0
    if cmd == "volume" and args[0] == "inspect":
        fmt, rest = fmt_arg(args[1:])
        v = state["volumes"].get(rest[0])
        if v is None:
            return no_such("volume", rest[0])
        print(msys(v["mountpoint"]) if fmt == "{{.Mountpoint}}" else v["labels"].get(LABEL, "") if fmt == F_VLABEL else die(f"volume inspect {fmt!r}"))
        return 0
    if cmd == "network" and args[0] == "inspect":
        fmt, rest = fmt_arg(args[1:])
        n = state["networks"].get(rest[0])
        if n is None:
            return no_such("network", rest[0])
        if fmt == "{{.Internal}}":
            print("true" if n["internal"] else "false")
        elif fmt == F_VLABEL:
            print(n["labels"].get(LABEL, ""))
        elif fmt == F_GATEWAY:
            print(n.get("gateway", "172.30.0.1"))
        else:
            die(f"network inspect {fmt!r}")
        return 0
    if cmd == "image" and args[0] == "inspect":
        fmt, rest = fmt_arg(args[1:])
        img = state["images"].get(rest[0]) or next((v for v in state["images"].values() if v["id"] == rest[0]), None)
        if img is None:
            return no_such("image", rest[0])
        print(json.dumps(img["env"]) if fmt == F_JSON_ENV else img["id"] if fmt == "{{.Id}}" else die(f"image inspect {fmt!r}"))
        return 0
    if cmd == "pull":
        assert args[0] == "-q", args
        ref = args[1]
        if ref not in state.get("known_pulls", []):
            sys.stderr.write(f"Error response from daemon: manifest for {ref} not found\n")
            return 1
        env = ["PATH=/new", "NODE_VERSION=24"]
        if state.get("release_type", "stable") is not None:      # `release_type: null` = imaginea nu declară deloc N8N_RELEASE_TYPE
            env.append("N8N_RELEASE_TYPE=" + state.get("release_type", "stable"))
        state["images"].setdefault(ref, {"id": "sha256:" + "5" * 64, "env": env})
        save(state)
        print("sha256:" + "5" * 64)
        return 0
    if cmd == "network" and args[0] == "create":
        internal = False
        labels = {}
        rest = args[1:]
        i = 0
        names = []
        while i < len(rest):
            if rest[i] == "--label":
                k, _, v = rest[i + 1].partition("=")
                labels[k] = v
                i += 2
            elif rest[i] == "--internal":
                internal = True
                i += 1
            elif rest[i].startswith("-"):
                return die(f"network create: opțiune necunoscută {rest[i]}")
            else:
                names.append(rest[i])
                i += 1
        assert len(names) == 1, names
        state["networks"][names[0]] = {"internal": internal, "labels": labels}
        save(state)
        print("n" * 64)
        return 0
    if cmd == "volume" and args[0] == "create":
        assert args[1] == "--label", args
        k, _, v = args[2].partition("=")
        name = args[3]
        mp = os.path.join(native(state["vol_root"]), name, "_data").replace(chr(92), "/")
        os.makedirs(mp, exist_ok=True)
        state["volumes"][name] = {"labels": {k: v}, "mountpoint": mp}
        save(state)
        print(name)
        return 0
    if cmd in ("volume", "network") and args[0] == "rm":
        name = args[1]
        coll = state["volumes" if cmd == "volume" else "networks"]
        if name not in coll:
            return no_such(cmd, name)
        for cn, c in state["containers"].items():
            if (cmd == "network" and c["network"] == name) or (cmd == "volume" and any(m["name"] == name for m in c["mounts"])):
                sys.stderr.write(f"Error response from daemon: {cmd} {name} is in use by container {cn}\n")
                return 1
        del coll[name]
        save(state)
        print(name)
        return 0
    if cmd == "rm":
        assert args[0] == "-f", args
        name = args[1]
        if name not in state["containers"]:
            return no_such("container", name)
        if state.get("rm_noop"):
            return 0
        del state["containers"][name]
        save(state)
        print(name)
        return 0
    if cmd == "run":
        return do_run(state, args)
    if cmd == "create":
        return do_create(state, args)
    if cmd == "start":
        c = state["containers"].get(args[0])
        if c is None:
            return no_such("container", args[0])
        c["state"] = "exited" if state.get("start_effect") == "exit" else "running"
        c["started"] = "2026-11-25T10:00:00.000000000Z"
        save(state)
        print(args[0])
        return 0
    if cmd == "exec":
        c = state["containers"].get(args[0])
        if c is None or c["state"] != "running":
            sys.stderr.write(f"Error response from daemon: container {args[0]} is not running\n")
            return 1
        assert args[1:3] == ["node", "-e"], args
        internal = state["networks"][c["network"]]["internal"]
        sys.stdout.write(egress_lines(state, internal, "exec", args[-1]))
        return 0
    if cmd == "logs":
        assert args[0] == "--tail", args
        if args[2] not in state["containers"]:
            return no_such("container", args[2])
        sys.stdout.write(state.get("logs", ""))
        return 0
    return die(f"comandă necunoscută: {argv}")


def do_run(state: dict, args: list[str]) -> int:
    """Doar forma probei: --rm --name N --network NET --label L --cpus C --memory M --memory-swap M --entrypoint node IMAGE -e JS a b c gateway."""
    assert args[0] == "--rm", args
    opts = {}
    i = 1
    while args[i].startswith("--"):
        opts[args[i]] = args[i + 1]
        i += 2
    image = args[i]
    assert opts.get("--entrypoint") == "node" and args[i + 1] == "-e", args
    net = state["networks"].get(opts.get("--network"))
    if net is None:
        sys.stderr.write("docker: Error response from daemon: network not found\n")
        return 125
    if image not in state["images"]:
        sys.stderr.write("Unable to find image\n")
        return 125
    sys.stdout.write(egress_lines(state, net["internal"], "run", args[-1]))
    return 0


def mem_bytes(text: str | None) -> int:
    if not text:
        return 0
    unit = {"m": 1024 ** 2, "g": 1024 ** 3}[text[-1]]
    return int(text[:-1]) * unit


def apply_create_mutation(state: dict, c: dict) -> None:
    """`create_mutate`: ce se strică în containerul creat, ca testele să vadă verificările containerului refuzând. Chei: `mounts_add` (listă de
    montări), `files_rw` (/files apare read-write), `ports` (porturi publicate), `network` (rețeaua în care a fost pus), `labels` (înlocuiește
    etichetele), `reported_network` (rețeaua pe care o raportează după pornire), `extra_networks`, `no_limits`, `data_volume` (volumul montat la
    /home/node/.n8n)."""
    m = state.get("create_mutate") or {}
    for k in m:
        if k not in ("mounts_add", "files_rw", "ports", "network", "labels", "reported_network", "extra_networks", "no_limits", "data_volume"):
            die(f"create_mutate: cheie necunoscută {k}")
    c["mounts"] += m.get("mounts_add", [])
    for mount in c["mounts"]:
        if m.get("files_rw") and mount["dst"] == "/files":
            mount["rw"] = True
        if m.get("data_volume") and mount["dst"] == "/home/node/.n8n":
            mount["name"] = m["data_volume"]
    if "ports" in m:
        c["ports"] = m["ports"]
    if "network" in m:
        c["network"] = m["network"]
    if "labels" in m:
        c["labels"] = m["labels"]
    for key in ("reported_network", "extra_networks"):
        if key in m:
            c[key] = m[key]
    if m.get("no_limits"):
        c["nano_cpus"], c["memory"] = 0, 0


def do_create(state: dict, args: list[str]) -> int:
    opts: dict = {"mounts": [], "labels": {}}
    i = 0
    while i < len(args) - 1:
        a = args[i]
        if a == "--label":
            k, _, v = args[i + 1].partition("=")
            opts["labels"][k] = v
            i += 2
        elif a == "-v":
            opts["mounts"].append(args[i + 1])
            i += 2
        elif a in ("--name", "--network", "--restart", "--env-file", "--cpus", "--memory", "--memory-swap"):
            opts[a] = args[i + 1]
            i += 2
        else:
            return die(f"create: opțiune necunoscută {a}")
    image = args[-1]
    state["last_env_file"] = opts.get("--env-file")
    save(state)
    if state.get("create_rc"):
        sys.stderr.write(state.get("create_stderr", "create failed") + "\n")
        return state["create_rc"]
    env_path = opts["--env-file"]
    with open(native(env_path), encoding="utf-8") as fh:
        env = [l.rstrip("\n") for l in fh if l.strip()]
    mode = file_mode(env_path)
    mounts = []
    for m in opts["mounts"]:
        parts = m.split(":")
        src, dst = parts[0], parts[1]
        ro = len(parts) > 2 and parts[2] == "ro"
        if src.startswith("/"):
            mounts.append({"dst": dst, "type": "bind", "name": "", "src": native(src), "rw": not ro})
        else:
            mp = state["volumes"][src]["mountpoint"]
            mounts.append({"dst": dst, "type": "volume", "name": src, "src": mp, "rw": not ro})
    name = opts["--name"]
    state["containers"][name] = {
        "id": "c" * 64, "state": "created", "restart": 0, "started": "0001-01-01T00:00:00Z",
        "image_id": state["images"][image]["id"], "labels": opts["labels"], "env": env,
        "network": opts["--network"], "mounts": mounts, "ports": {}, "reads": 0,
        "env_file": env_path, "env_file_mode": mode, "restart_policy": opts["--restart"],
        "image_ref": image, "nano_cpus": int(float(opts["--cpus"]) * 1_000_000_000) if "--cpus" in opts else 0,
        "memory": mem_bytes(opts.get("--memory")),
    }
    apply_create_mutation(state, state["containers"][name])
    save(state)
    print("c" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
