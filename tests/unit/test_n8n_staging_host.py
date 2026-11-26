"""`scripts/lib/n8n-staging-host.sh` — copia de aruncat a n8n-ului de producție, izolată de rețea.

Eșecul pe care îl are de prevenit tot fișierul: o copie a instanței de producție care ajunge pe internet face apeluri REALE
(Twilio către debitori, WhatsApp, e-mail) din workflow-uri active, iar o copie stricată (bază veche, cheie de criptare greșită)
«dovedește» un upgrade pe care producția nu-l va avea. Fiecare test spune în docstring ce se strică pentru operator.

Rulează codul LIVRAT într-un bash, cu `docker` momeală care MODELEAZĂ ieșirea din rețea (vezi `_fake_n8n_docker.py`) și cu o bază
SQLite REALĂ în modul WAL (vezi `_n8n_staging_world.py`). Ce NU dovedește: un docker real, iptables, DNS-ul lui docker, accesul
gazdei la IP-ul din rețeaua internă, un integrity_check pe 9,6 GB. Un `up` complet durează ~40 s pe Windows (fiecare apel docker e
un proces), de aceea o singură rulare reușită e împărțită între mai multe aserțiuni.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from _n8n_staging_world import (HOST_LIB, LABEL, PROD, PROD_STARTED, SECRETS, ROWS, World, IMAGE_FOR)
from _su_shell import BASH, posix, write_exec

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

STAGE = "n8n-staging"
STAGE_VOL = "n8n_staging_data"
STAGE_NET = "n8n-staging-net"
SECRET_VALUES = list(SECRETS.values())


# ------------------------------------------------------------------------------------------------------------------------
# ajutoare
# ------------------------------------------------------------------------------------------------------------------------

def mutating(w: World) -> list[list[str]]:
    """Apelurile docker care SCHIMBĂ ceva (inclusiv un pull): cele pe care un refuz de preflight nu are voie să le facă."""
    out = []
    for a in w.docker_log():
        if a[0] in ("create", "start", "rm", "run", "exec", "pull"):
            out.append(a)
        elif a[0] in ("volume", "network") and len(a) > 1 and a[1] in ("create", "rm"):
            out.append(a)
    return out


def touches_prod(w: World) -> list[list[str]]:
    """Apeluri care ating producția în alt fel decât prin citire: orice verb ≠ inspect pe root-n8n-1/n8n_data/root_default, un mount al
    volumului de producție, sau `docker compose`."""
    bad = []
    for a in w.docker_log():
        joined = " ".join(a)
        if a[0] == "compose" or "docker compose" in joined:
            bad.append(a)
        elif a[:2] == ["container", "inspect"] and a[2] == PROD:
            continue
        elif a[:2] == ["volume", "inspect"] and a[2] == "n8n_data":
            continue
        elif any(x in (PROD, "n8n_data", "root_default") for x in a) or "n8n_data:" in joined:
            bad.append(a)
    return bad


def add_container(w: World, name: str, labels: dict | None = None, *, state: str = "running", network: str = "root_default",
                  mounts: list | None = None) -> None:
    w.load()
    w.state["containers"][name] = {"id": "d" * 64, "state": state, "restart": 0, "started": "2026-11-25T01:00:00.000000000Z",
                                   "image_id": "sha256:" + "1" * 64, "labels": labels or {}, "env": [], "network": network,
                                   "mounts": mounts or [], "ports": {}, "reads": 0}
    w.save()


def add_volume(w: World, name: str, labels: dict | None = None) -> None:
    w.load()
    mp = (w.vols / name / "_data")
    mp.mkdir(parents=True, exist_ok=True)
    w.state["volumes"][name] = {"labels": labels or {}, "mountpoint": posix(mp)}
    w.save()


def add_network(w: World, name: str, labels: dict | None = None, internal: bool = True) -> None:
    w.load()
    w.state["networks"][name] = {"internal": internal, "labels": labels or {}}
    w.save()


def patch_state(w: World, **kw) -> None:
    w.load()
    w.state.update(kw)
    w.save()


def assert_no_secret(w: World, res) -> None:
    """Nicio valoare de mediu în ieșirea scriptului și în NICIUN argument dat lui docker (argv se vede în `ps`)."""
    blob = res.out + "\n".join(" ".join(a) for a in w.docker_log())
    for v in SECRET_VALUES:
        assert v not in blob, f"valoarea de mediu {v!r} a ajuns în ieșire sau în argv docker"


def assert_env_file_gone(w: World) -> None:
    """Fișierul de mediu (secretele în clar) nu mai există, iar testul chiar l-a văzut creat (control pozitiv: fără el, «a dispărut»
    ar fi adevărat și pentru un script care nu l-a scris niciodată)."""
    w.load()
    path = w.state.get("last_env_file")
    assert path, "scenariul nu a ajuns să creeze containerul: nu are ce șterge, testul n-ar dovedi nimic"
    assert not Path(path).exists(), f"fișierul de mediu {path} a rămas pe disc"
    assert w.env_files_left() == [], w.env_files_left()


@pytest.fixture
def w(tmp_path):
    world = World(tmp_path)
    yield world
    world.close()


@pytest.fixture(scope="module")
def happy(tmp_path_factory):
    """O singură rulare `up` reușită, cu producția pornită (conexiune SQLite deschisă) și /files montat în producție."""
    world = World(tmp_path_factory.mktemp("happy"))
    prod_files_before = sorted(p.relative_to(world.data).as_posix() for p in world.data.rglob("*") if p.is_file())
    res = world.up()
    yield world, res, prod_files_before
    world.close()


# ------------------------------------------------------------------------------------------------------------------------
# argumente: versiunea e singura valoare liberă care ajunge în script
# ------------------------------------------------------------------------------------------------------------------------

BAD_VERSIONS = ["latest", "3.0", "3", "3.0.1.2", "v3.0.1", "3.0.x", "3.0.1-rc1", "3.0.1;reboot", "3.0.1 && id", "$(id)", "`id`",
                "3.0.$((1))", "-1.0.0", "3.0.1/../x", " 3.0.1", "3.0.1 ", "", "1" * 40 + ".0.0"]


@pytest.mark.parametrize("bad", BAD_VERSIONS)
def test_a_version_that_is_not_plain_numbers_never_reaches_docker(w, bad):
    """O versiune ajunge în numele unei imagini și în comenzi rulate ca root. `latest` ar «încerca» upgrade-ul pe o țintă nefixată, iar
    un `;` sau `$(...)` ar fi cod pe gazda de producție (aceeași clasă ca un port care a ajuns în aritmetica bash din smoke-test.sh).
    Refuzat cu 2 înainte de ORICE apel docker."""
    res = w.run("up", "--version", bad)
    assert res.rc == 2, res.out
    assert w.docker_log() == [], w.docker_log()


@pytest.mark.parametrize("bad", ["3.0.1\n", "3.0.1\nlatest", "3.0.1\r", "３.０.１", "٣.٠.١"])
def test_is_semver_rejects_newlines_and_non_ascii_digits_that_a_command_line_cannot_carry_on_windows(bad):
    """Un argument cu newline nu poate fi trimis de pe Windows prin argv (se taie), deci cazurile astea se verifică direct pe funcția care
    decide, cu valoarea trecută prin mediu. Un `$` care ar potrivi înaintea unui newline final sau un `[0-9]` care ar primi alte cifre
    ar lăsa să treacă `3.0.1` urmat de o a doua linie (comandă, în alt context)."""
    env = {**os.environ, "V": bad}
    r = subprocess.run([BASH, "-c", f"source '{posix(HOST_LIB)}'; if is_semver \"$V\"; then echo ACCEPTED; else echo rejected; fi"],
                       capture_output=True, env=env, text=True, encoding="utf-8")
    assert r.stdout.strip() == "rejected", (bad, r.stdout, r.stderr)


def test_is_semver_accepts_a_plain_version():
    """Control pozitiv pentru testul de mai sus: o versiune obișnuită trece (altfel «rejected» ar fi adevărat pentru orice)."""
    env = {**os.environ, "V": "3.0.12"}
    r = subprocess.run([BASH, "-c", f"source '{posix(HOST_LIB)}'; if is_semver \"$V\"; then echo ACCEPTED; else echo rejected; fi"],
                       capture_output=True, env=env, text=True)
    assert r.stdout.strip() == "ACCEPTED", r.stdout + r.stderr


@pytest.mark.parametrize("argv", [(), ("up",), ("up", "--version"), ("up", "3.0.1"), ("up", "--version", "3.0.1", "--force"),
                                  ("down", "--all"), ("status", "x"), ("logs", "--tail"), ("logs", "--tail", "abc"), ("logs", "--tail", "123456"),
                                  ("logs", "200"), ("restart",), ("UP", "--version", "3.0.1")])
def test_unknown_or_malformed_subcommands_are_refused_before_docker(w, argv):
    """Un `down --all` sau un `up` fără versiune nu trebuie să «ghicească» ce voia operatorul: ieșire 2, nimic atins."""
    res = w.run(*argv)
    assert res.rc == 2, res.out
    assert w.docker_log() == []


def test_a_plain_version_passes_validation_and_reaches_the_preflight(w):
    """Control pozitiv pentru testele de mai sus: o versiune corectă NU e refuzată cu 2 (altfel toate refuzurile ar fi verzi pentru
    un script care refuză tot). O versiune care nu există în registru se oprește la pull, înainte să existe vreun obiect."""
    res = w.up("3.0.9")
    assert res.rc == 1 and "nu pot descărca" in res.out, res.out
    assert any(a[0] == "pull" for a in w.docker_log())
    assert not [a for a in mutating(w) if a[0] != "pull"], mutating(w)


# ------------------------------------------------------------------------------------------------------------------------
# preflight: refuz fără să creez nimic
# ------------------------------------------------------------------------------------------------------------------------

def _prod_stopped(w): w.load(); w.state["containers"][PROD]["state"] = "exited"; w.save()
def _prod_absent(w): w.load(); del w.state["containers"][PROD]; w.save()
def _data_volume_missing(w): w.load(); del w.state["volumes"]["n8n_data"]; w.save()
def _prod_mounts_other_volume(w): w.load(); w.state["containers"][PROD]["mounts"][1]["name"] = "outro_volum"; w.save()
def _leftover_container(w): add_container(w, STAGE)
def _leftover_volume(w): add_volume(w, STAGE_VOL)
def _leftover_network(w): add_network(w, STAGE_NET)
def _leftover_probe(w): add_container(w, "n8n-staging-probe")
def _leftover_labelled_other_name(w): add_volume(w, "ceva_vechi", {LABEL: "1"})
def _no_database(w): w.close(); (w.data / "database.sqlite").rename(w.data / "database.sqlite.bak")
def _daemon_down(w): patch_state(w, daemon_down=True)
def _disk_unreadable(w): w.set_free("n/a")
def _disk_short(w): w.set_free("1000")


PREFLIGHT_REFUSALS = [
    ("prod oprit", _prod_stopped, 1, "nu rulează"),
    ("prod lipsește", _prod_absent, 1, "nu există"),
    ("volumul n8n_data lipsește", _data_volume_missing, 1, "lipsește"),
    ("prod montează alt volum", _prod_mounts_other_volume, 1, "nu montează volumul"),
    ("containerul de staging există", _leftover_container, 1, "există deja"),
    ("volumul de staging există", _leftover_volume, 1, "există deja"),
    ("rețeaua de staging există", _leftover_network, 1, "există deja"),
    ("containerul de probă a rămas", _leftover_probe, 1, "există deja"),
    ("obiect cu eticheta, sub alt nume", _leftover_labelled_other_name, 1, "există deja"),
    ("fără database.sqlite", _no_database, 1, "database.sqlite"),
    ("daemon docker căzut", _daemon_down, 3, "daemonul docker"),
    ("spațiul liber nu se poate măsura", _disk_unreadable, 3, "NECUNOSCUT"),
    ("spațiu liber sub 3x", _disk_short, 1, "insuficient"),
]


@pytest.mark.parametrize("name,break_it,rc,needle", PREFLIGHT_REFUSALS, ids=[p[0] for p in PREFLIGHT_REFUSALS])
def test_a_preflight_refusal_creates_nothing(w, name, break_it, rc, needle):
    """Operatorul rulează `up` pe o gazdă care nu e în starea așteptată (prod oprit, rămășițe dintr-o rulare veche, disc aproape plin,
    docker căzut). Scriptul refuză și NU lasă nimic în urmă: niciun pull, container, volum sau rețea, nicio schimbare în starea docker.
    «Unknown» (nu pot măsura discul, nu răspunde docker) iese cu 3, nu e confundat cu «e bine»."""
    break_it(w)
    before = w.object_keys()
    res = w.up()
    assert res.rc == rc, res.out
    assert needle in res.out, res.out
    assert mutating(w) == [], mutating(w)
    assert w.object_keys() == before
    assert w.env_files_left() == []


def _du_bytes(path: Path) -> int:
    out = subprocess.run([BASH, "-c", f"du -sb -- '{posix(path)}'"], capture_output=True, text=True).stdout
    return int(out.split()[0])


def test_the_disk_threshold_is_exactly_three_times_the_volume(w):
    """«Cel puțin 3x» e pragul: cu 3x - 1 octeți liberi refuză, cu exact 3x trece de preflight. Un `<=` în loc de `<` (sau 2x în loc de
    3x) ar lăsa gazda fără loc în mijlocul copierii, cu un volum de staging pe jumătate scris."""
    size = _du_bytes(w.data)
    w.set_free(str(3 * size - 1))
    short = w.up()
    assert short.rc == 1 and "insuficient" in short.out, short.out
    assert mutating(w) == []
    w.set_free(str(3 * size))
    patch_state(w, known_pulls=[])         # trece de preflight și se oprește la pull, fără să mai copieze nimic
    enough = w.up()
    assert "preflight:" in enough.out and "insuficient" not in enough.out, enough.out
    assert "nu pot descărca" in enough.out


# ------------------------------------------------------------------------------------------------------------------------
# calea fericită: ce există după `up`, și ce n-a fost atins
# ------------------------------------------------------------------------------------------------------------------------

def test_a_successful_up_ends_with_proof_a_tunnel_and_exit_zero(happy):
    """Operatorul trebuie să primească, la final, dovezile (izolare, health, stabilitate) și adresa pentru tunel; un `0` fără ele n-ar
    spune dacă copia merge."""
    w, res, _ = happy
    assert res.rc == 0, res.out
    for needle in ("TCP spre 1.1.1.1:443 și DNS pentru example.com CAD amândouă", "/healthz a răspuns 200", "stabil: 4 eșantioane identice",
                   "TOT DOVEDIT", "N8N_STAGING_IP=172.30.0.2", "-L 5679:172.30.0.2:5678", "http://localhost:5679/", "integrity_check=ok"):
        assert needle in res.out, (needle, res.out)
    # /healthz s-a cerut pe adresa containerului, nu pe localhost
    assert "http://172.30.0.2:5678/healthz" in (w.fh / "curl.log").read_text(encoding="utf-8")


def test_the_staging_container_has_the_shape_that_makes_it_safe(happy):
    """Un port publicat sau o a doua rețea ar face copia accesibilă (și capabilă să iasă) în alt fel decât tunelul. Containerul trebuie
    să fie pe UN singur network (cel intern), fără porturi, cu eticheta pe toate cele trei obiecte, fără alt label (nici traefik), cu
    /files DOAR-CITIRE și cu volumul NOU de date, nu cel de producție."""
    w, res, _ = happy
    s = w.load()
    c = s["containers"][STAGE]
    assert c["network"] == STAGE_NET and not c.get("extra_networks")
    assert c["ports"] == {}
    assert c["labels"] == {LABEL: "1"}
    assert s["networks"][STAGE_NET]["internal"] is True and s["networks"][STAGE_NET]["labels"] == {LABEL: "1"}
    assert s["volumes"][STAGE_VOL]["labels"] == {LABEL: "1"}
    assert c["restart_policy"] == "no"
    mounts = {m["dst"]: m for m in c["mounts"]}
    assert mounts["/home/node/.n8n"]["name"] == STAGE_VOL
    assert mounts["/files"]["rw"] is False and mounts["/files"]["type"] == "bind"
    assert set(mounts) == {"/home/node/.n8n", "/files"}
    create = next(a for a in w.docker_log() if a[0] == "create")
    assert not {"-p", "--publish", "-P", "--network-alias", "--add-host", "--privileged"} & set(create)
    assert create.count("--network") == 1 and create.count("--label") == 1
    assert create[-1] == IMAGE_FOR.format("3.0.1")
    assert "/files: montat DOAR-CITIRE" in res.out


def test_isolation_is_proven_before_n8n_starts_and_again_from_inside(happy):
    """n8n activează workflow-urile în clipa în care pornește. Dacă prima dovadă de izolare ar veni DUPĂ `start`, ar exista o fereastră în
    care un workflow cu Twilio ar suna deja. Ordinea în jurnalul docker: rețea creată -> probă pe rețea -> create -> start -> probă din
    container."""
    w, _, _ = happy
    verbs = [(a[0], a[1] if len(a) > 1 else "") for a in w.docker_log()]
    i_net = verbs.index(("network", "create"))
    i_run = next(i for i, v in enumerate(verbs) if v[0] == "run")
    i_create = next(i for i, v in enumerate(verbs) if v[0] == "create")
    i_start = next(i for i, v in enumerate(verbs) if v[0] == "start")
    i_exec = next(i for i, v in enumerate(verbs) if v[0] == "exec")
    assert i_net < i_run < i_create < i_start < i_exec, verbs


def test_the_copied_database_contains_rows_that_only_a_consistent_copy_has(happy):
    """Producția rămâne pornită, iar rândurile recente stau în -wal. Un `cp` al lui database.sqlite le-ar pierde FĂRĂ nicio eroare, iar
    n8n ar porni pe o listă de workflow-uri veche. Aici baza de producție are toate cele ROWS rânduri DOAR în -wal, cu o conexiune
    deschisă; copia le are pe toate."""
    w, _, _ = happy
    import sqlite3
    copy = Path(w.load()["volumes"][STAGE_VOL]["mountpoint"]) / "database.sqlite"
    con = sqlite3.connect(copy)
    try:
        assert con.execute("SELECT count(*) FROM workflow_entity").fetchone()[0] == ROWS
        assert con.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    finally:
        con.close()
    assert not (copy.parent / "database.sqlite-wal").exists() and not (copy.parent / "database.sqlite-shm").exists()


def test_the_rest_of_the_volume_is_copied_with_the_encryption_key(happy):
    """Fără fișierul `config` identic, toate credențialele din copie (Twilio, Gmail) sunt ilizibile și workflow-urile pică la prima
    rulare; fără `nodes/`, cele 3 pachete comunitare lipsesc. `crash.journal` (marcajul «n8n rulează» al producției) NU se copiază: ar
    face instanța nouă să creadă că a căzut. Un fișier numit database.sqlite, dar mai adânc în arbore, e un fișier obișnuit și se copiază."""
    w, _, _ = happy
    dst = Path(w.load()["volumes"][STAGE_VOL]["mountpoint"])
    assert (dst / "config").read_bytes() == (w.data / "config").read_bytes()
    assert (dst / "nodes" / "node_modules" / "n8n-nodes-basecamp" / "package.json").exists()
    assert (dst / "nodes" / "node_modules" / "n8n-nodes-basecamp" / "database.sqlite").read_text(encoding="utf-8") == "nu e baza n8n"
    assert (dst / "n8nEventLog.log").exists()
    assert not (dst / "crash.journal").exists()


def test_production_is_untouched_by_a_successful_up(happy):
    """Aceeași invariantă ca pe gazdă: niciun apel docker nu atinge root-n8n-1, n8n_data sau root_default altfel decât prin citire, nu
    se montează volumul de producție, nu există `docker compose`, iar amprenta producției e aceeași. Fișierele din volumul de producție
    sunt aceleași (nimic nou scris acolo)."""
    w, res, files_before = happy
    assert touches_prod(w) == [], touches_prod(w)
    s = w.load()
    p = s["containers"][PROD]
    assert (p["id"], p["started"], p["restart"], p["state"]) == ("a" * 64, PROD_STARTED, 0, "running")
    files_after = sorted(x.relative_to(w.data).as_posix() for x in w.data.rglob("*") if x.is_file())
    assert files_after == files_before
    assert "PRODUCȚIA S-A SCHIMBAT" not in res.out


def test_the_environment_is_derived_from_production_with_overrides_and_without_the_old_images_defaults(happy):
    """Containerul trebuie să aibă secretele de producție (altfel workflow-urile n-au chei) dar adresele de tunel, nu cele publice (altfel
    linkurile și cookie-urile duc la producție), iar variabilele puse de IMAGINEA veche (PATH, NODE_VERSION, N8N_RELEASE_TYPE) NU se
    copiază: ar suprascrie ce aduce imaginea nouă."""
    w, res, _ = happy
    env = dict(e.partition("=")[::2] for e in w.load()["containers"][STAGE]["env"])
    for k, v in SECRETS.items():
        assert env[k] == v
    assert env["EXECUTIONS_TIMEOUT"] == "3600" and env["N8N_DEFAULT_BINARY_DATA_MODE"] == "filesystem"
    assert env["N8N_HOST"] == "localhost" and env["N8N_PROTOCOL"] == "http" and env["WEBHOOK_URL"] == "http://localhost:5679/"
    assert env["N8N_EDITOR_BASE_URL"] == "http://localhost:5679" and env["N8N_SECURE_COOKIE"] == "false"
    assert env["N8N_LISTEN_ADDRESS"] == "0.0.0.0" and env["N8N_PROXY_HOPS"] == "0"
    for k in ("PATH", "NODE_VERSION", "NODE_ENV", "N8N_RELEASE_TYPE"):
        assert k not in env, k
    assert len([e for e in w.load()["containers"][STAGE]["env"] if e.startswith("N8N_HOST=")]) == 1
    assert "n8n.srv1051579" not in "".join(w.load()["containers"][STAGE]["env"]).replace("EXECUTIONS", "")


def test_no_environment_value_is_printed_and_the_env_file_is_root_only_and_gone(happy):
    """Secretele din mediu nu au voie în ieșire, în jurnal sau în argv-ul lui docker (se vede în `ps` și în jurnalul de audit). Fișierul
    de mediu are modul 0600 când docker îl citește și nu mai există după. (Pe Windows modul se judecă sub umask 077 — vezi
    _n8n_staging_world.UMASK_PREFIX; dovada reală e pe Linux.)"""
    w, res, _ = happy
    assert_no_secret(w, res)
    assert_env_file_gone(w)
    assert w.load()["containers"][STAGE]["env_file_mode"] == "600"


def test_the_log_excerpt_shows_migrations_and_errors_and_hides_values(tmp_path):
    """Operatorul decide dacă upgrade-ul a mers după liniile de migrare și de eroare. Se arată; o valoare de mediu citată de n8n într-o
    eroare nu se arată."""
    w = World(tmp_path)
    try:
        patch_state(w, logs=("Starting n8n\nMigration \"AddWorkflowVersion1\" has been executed successfully\n"
                             f"Error: cannot reach host with key {SECRETS['TWILIO_AUTH_TOKEN']}\nready\n"))
        res = w.up()
        assert res.rc == 0, res.out
        assert 'Migration "AddWorkflowVersion1" has been executed successfully' in res.out
        assert "cannot reach host with key ***" in res.out
        assert_no_secret(w, res)
    finally:
        w.close()


def test_without_a_files_mount_in_production_nothing_is_mounted_and_it_says_so(tmp_path):
    """Dacă producția nu montează /files, copia nu inventează o montare (și nu monta nimic din gazdă în staging). Mesajul spune ce s-a ales."""
    w = World(tmp_path)
    try:
        w.load()
        w.state["containers"][PROD]["mounts"] = [m for m in w.state["containers"][PROD]["mounts"] if m["dst"] != "/files"]
        w.save()
        res = w.up()
        assert res.rc == 0, res.out
        assert "nu montez nimic" in res.out
        assert {m["dst"] for m in w.load()["containers"][STAGE]["mounts"]} == {"/home/node/.n8n"}
    finally:
        w.close()


# ------------------------------------------------------------------------------------------------------------------------
# izolarea: dovedită prin efect, cu ieșire 5 și container șters când pică
# ------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("leak", [{"tcp": True}, {"dns": True}], ids=["tcp", "dns"])
def test_egress_before_start_stops_everything_and_n8n_never_runs(w, leak):
    """Dacă rețeaua internă lasă să treacă TCP sau DNS (docker/nucleu greșit), n8n NU trebuie să pornească deloc: ar activa workflow-urile
    cu Twilio pe o rețea cu ieșire. Ieșire 5; niciun `create`/`start`."""
    patch_state(w, probe_run=leak)
    res = w.up()
    assert res.rc == 5, res.out
    assert "IEȘIRE DIN REȚEAUA" in res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start", "exec")]
    assert STAGE not in w.load()["containers"]


@pytest.mark.parametrize("leak", [{"tcp": True}, {"dns": True}], ids=["tcp", "dns"])
def test_egress_seen_from_inside_the_running_container_removes_it_and_exits_nonzero(w, leak):
    """Proba de dinaintea pornirii a trecut, dar din interiorul containerului pornit TCP sau DNS iese. Containerul se șterge IMEDIAT
    (workflow-urile active ar suna debitori), ieșire 5, iar fișierul de mediu nu rămâne."""
    patch_state(w, probe_exec=leak)
    res = w.up()
    assert res.rc == 5, res.out
    assert "IEȘIRE DIN CONTAINERUL" in res.out
    assert STAGE not in w.load()["containers"], "containerul cu ieșire a rămas"
    assert ["rm", "-f", STAGE] in w.docker_log()
    assert_env_file_gone(w)
    assert_no_secret(w, res)


def test_a_probe_that_cannot_run_is_unknown_not_isolated_before_start(w):
    """O probă care nu produce rezultat (node lipsește, ieșire ciudată) nu dovedește izolarea: «nu știu» nu e «blocat». Ieșire 3, n8n nu pornește."""
    patch_state(w, probe_run={"mode": "garbage"})
    res = w.up()
    assert res.rc == 3, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_a_probe_that_cannot_run_inside_the_running_container_removes_it(w):
    """Aceeași regulă după pornire: dacă din containerul care RULEAZĂ proba nu dă rezultat, izolarea nu e dovedită și containerul nu are
    voie să rămână pornit. Șters, ieșire 3."""
    patch_state(w, probe_exec={"mode": "garbage"})
    res = w.up()
    assert res.rc == 3, res.out
    assert STAGE not in w.load()["containers"]
    assert_env_file_gone(w)


def test_a_network_that_is_not_internal_stops_the_run_before_any_probe(w):
    """`docker network create --internal` e intenția; `Internal=true` citit înapoi e efectul. O rețea creată fără el (o versiune de docker
    care ignoră opțiunea, un alias) oprește rularea înainte de orice container."""
    w.load()
    # un `network create` care ignoră --internal: simulat prin pre-crearea rețelei NU merge (preflight ar refuza); se înlocuiește funcția de creare
    res = w.run_sourced('docker() { if [[ "$1 $2" == "network create" ]]; then command docker network create --label "$LABEL_KEY=1" "$STAGING_NET"; else command docker "$@"; fi; }\n'
                        'main up --version 3.0.1')
    assert res.rc == 1 and "NU e internă" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("run", "create", "start")]


def test_a_container_that_exits_before_the_probe_is_kept_for_its_log_and_never_called_isolated(w):
    """O migrare care strică pornirea face containerul să iasă imediat. Atunci nu există nimic care să ruleze (deci nu e ieșire), iar
    jurnalul cu cauza e tot ce are operatorul: containerul rămâne oprit, jurnalul se arată, ieșire 1 (nu 0, nu 5)."""
    patch_state(w, start_effect="exit", logs="Error: Migration \"X\" failed: SQLITE_CONSTRAINT\n")
    res = w.up()
    assert res.rc == 1, res.out
    assert "SQLITE_CONSTRAINT" in res.out
    assert STAGE in w.load()["containers"]
    assert_env_file_gone(w)


def test_a_started_container_whose_isolation_was_never_proven_does_not_survive_an_abnormal_exit(w):
    """Dacă scriptul moare (ssh căzut, SIGTERM) între `start` și proba din container, containerul nu are voie să rămână pornit pe o rețea
    nedovedită. Trap-ul de ieșire îl șterge; aici ieșirea e simulată cu `exit 7`."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    add_network(w, STAGE_NET, {LABEL: "1"})
    res = w.run_sourced('STAGING_CREATED=1; EGRESS_PROVEN=0; PROD_FP_BEFORE="$(prod_fp)"; trap on_exit EXIT; exit 7')
    assert res.rc == 7, res.out
    assert STAGE not in w.load()["containers"]


def test_a_proven_container_is_left_alone_by_the_exit_trap(w):
    """Contrapartida: după ce izolarea e dovedită, o ieșire cu cod nenul NU șterge containerul (operatorul vrea să-i citească jurnalul)."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    add_network(w, STAGE_NET, {LABEL: "1"})
    res = w.run_sourced('STAGING_CREATED=1; EGRESS_PROVEN=1; PROD_FP_BEFORE="$(prod_fp)"; trap on_exit EXIT; exit 7')
    assert res.rc == 7, res.out
    assert STAGE in w.load()["containers"]


NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="fără node: proba JS nu se poate rula")
def test_the_probe_script_runs_under_real_node_and_classifies_open_closed_and_unknown(tmp_path):
    """Proba e JavaScript pe care momeala docker nu-l execută: o greșeală de sintaxă ar face fiecare `up` să iasă cu 3 (sau, mai rău, o
    clasificare greșită ar numi «blocat» o conexiune care a trecut). Aici rulează sub node REAL: o conexiune acceptată sau REFUZATĂ
    înseamnă «open» (a răspuns cineva), un nume care nu se rezolvă înseamnă «blocat», iar `egress_verdict` din bibliotecă transformă
    ieșirea în `open`/`closed`/`unknown`. Ținta e 127.0.0.1, nu internetul."""
    import socket
    js = subprocess.run([BASH, "-c", f"source '{posix(HOST_LIB)}'; printf '%s' \"$PROBE_JS\""], capture_output=True, text=True, encoding="utf-8").stdout
    assert "require('net')" in js
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        def run(host, p, name, gateway="-"):
            r = subprocess.run([NODE, "-e", js, host, str(p), name, gateway], capture_output=True, text=True, timeout=90)
            return r.stdout
        accepted = run("127.0.0.1", port, "localhost")
        refused = run("127.0.0.1", closed_port, "nume-care-nu-exista.invalid")
        with_gateway = run("127.0.0.1", port, "localhost", "127.0.0.1")
    finally:
        srv.close()

    def verdict(text):
        # prin mediu, nu prin argv: un argument cu newline-uri e tăiat la primul pe Windows și «accepted» ar trece din motiv greșit
        env = {**os.environ, "PROBE_TEXT": text}
        return subprocess.run([BASH, "-c", f"source '{posix(HOST_LIB)}'; egress_verdict \"$PROBE_TEXT\""], capture_output=True, text=True, env=env).stdout.strip()

    core = lambda text: sorted(l for l in text.split() if not l.startswith("GW"))      # liniile GW* sunt informative, nu intră în verdict
    gw = lambda text: sorted(l for l in text.split() if l.startswith("GW"))
    assert core(accepted) == ["DNS=open", "SELF=ok", "TCP=open"], accepted
    assert gw(accepted) == ["GW443=unknown", "GW5678=unknown", "GW80=unknown", "GW8443=unknown"], accepted      # fără gateway: «unknown», nu «blocat»
    assert verdict(accepted) == "open"
    # cu un gateway real (127.0.0.1), fiecare dintre cele patru porturi e raportat, ca open sau refused (aici nimic nu e blocat)
    assert [l.split("=")[0] for l in gw(with_gateway)] == ["GW443", "GW5678", "GW80", "GW8443"], with_gateway
    assert all(l.split("=")[1] in ("open", "refused") for l in gw(with_gateway)), with_gateway
    assert core(refused) == ["DNS=blocked", "SELF=ok", "TCP=open"], refused      # refuzată = a răspuns cineva
    assert verdict(refused) == "open"
    assert verdict("DNS=blocked\nSELF=ok\nTCP=blocked\n") == "closed"
    assert verdict("DNS=blocked\nTCP=blocked\n") == "unknown"                              # fără controlul SELF
    assert verdict("DNS=blocked\nSELF=ok\nTCP=unknown\n") == "unknown"
    assert verdict("") == "unknown" and verdict("TIMEOUT") == "unknown"
    assert verdict("DNS=blocked\nSELF=ok\nTCP=blocked\nTCP=open\n") == "open"
    assert verdict("DNS=blocked\nSELF=ok\nTCP=blocked\nGW80=open\nGW443=open\n") == "closed"      # gateway-ul deschis nu schimbă verdictul de ieșire


# ------------------------------------------------------------------------------------------------------------------------
# baza de date: copie consistentă, două dovezi
# ------------------------------------------------------------------------------------------------------------------------

def test_a_plain_file_copy_of_the_live_database_is_refused_by_the_row_count(w):
    """Dacă cineva «simplifică» copia la un `cp`, copia pierde rândurile din -wal. Dovada pe numărul de rânduri trebuie să refuze, iar
    n8n să NU pornească pe o bază veche."""
    res = w.run_sourced('db_backup() { cp "$1/database.sqlite" "$2/database.sqlite"; echo "5 5"; }\nmain up --version 3.0.1')
    assert res.rc == 1, res.out
    assert "NU coincide" in res.out or "workflow_entity" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]
    assert "n8n NU pornește" in res.out


def test_a_copy_with_a_missing_row_is_refused(w):
    """Copia are cu un workflow mai puțin decât producția (copie întreruptă, tăiată): numărul din workflow_entity nu coincide, refuz."""
    body = ('db_backup() { local c; c="$(python3 -c "$SQLITE_PY" backup "$1/database.sqlite" "$2/database.sqlite")"; '
            'python3 -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\\"DELETE FROM workflow_entity WHERE id=\'0\'\\"); c.commit(); c.close()" "$2/database.sqlite"; echo "$c"; }\n'
            'main up --version 3.0.1')
    res = w.run_sourced(body)
    assert res.rc == 1, res.out
    assert f"producție={ROWS} copie={ROWS - 1}" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_a_production_that_changed_during_the_copy_cannot_be_proven_and_is_refused(w):
    """Dacă numărul de rânduri din producție diferă între dinaintea și după backup, nu se poate spune ce conține «instantaneul». Refuz cu
    mesaj clar (rerulează), nu o comparație cu un număr ales la întâmplare."""
    body = ('db_backup() { python3 -c "$SQLITE_PY" backup "$1/database.sqlite" "$2/database.sqlite" >/dev/null; echo "5 6"; }\nmain up --version 3.0.1')
    res = w.run_sourced(body)
    assert res.rc == 1, res.out
    assert "și-a schimbat workflow_entity în timpul copierii" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_a_copy_that_fails_integrity_check_is_refused(tmp_path):
    """O bază de producție cu o pagină stricată se copiază bit cu bit; numărul de rânduri din workflow_entity poate fi corect, dar copia e
    stricată. `PRAGMA integrity_check` pe copie trebuie să refuze înainte să pornească n8n pe ea."""
    w = World(tmp_path)
    try:
        w.corrupt_prod_index()
        res = w.up()
        assert res.rc == 1, res.out
        assert "integrity_check" in res.out and "backup-ul online al bazei a eșuat" not in res.out, res.out
        assert "n8n NU pornește" in res.out
        assert not [a for a in w.docker_log() if a[0] in ("create", "start")]
    finally:
        w.close()


def test_a_copy_whose_integrity_check_lists_problems_is_refused(w):
    """A doua formă de «copie stricată»: baza se deschide fără erori, dar `PRAGMA integrity_check` întoarce o LISTĂ de probleme în loc de
    exact «ok» (aici, un rând care încalcă un CHECK). Doar «ok» trece; orice altceva refuză, cu problema citată."""
    w.violate_check_in_prod()
    res = w.up()
    assert res.rc == 1, res.out
    assert "integrity_check pe copie NU e «ok»: CHECK constraint failed in checked_entity" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_a_database_failure_leaves_labelled_objects_for_down_and_no_env_file(w):
    """Un eșec la copierea bazei lasă rețeaua și volumul (cu eticheta), ca `down` să le curețe și ca operatorul să nu aibă obiecte
    fără etichetă pe gazdă; nu lasă niciun fișier de mediu (n-a apucat să existe)."""
    res = w.run_sourced('db_backup() { echo "5 5"; }\nmain up --version 3.0.1')
    assert res.rc != 0
    s = w.load()
    assert s["volumes"][STAGE_VOL]["labels"] == {LABEL: "1"} and s["networks"][STAGE_NET]["labels"] == {LABEL: "1"}
    assert STAGE not in s["containers"]
    assert w.env_files_left() == []


# ------------------------------------------------------------------------------------------------------------------------
# stabilitate: o probă «rulează» nu dovedește nimic
# ------------------------------------------------------------------------------------------------------------------------

def test_a_restart_inside_the_stability_window_fails_the_run(w):
    """O singură probă «running» a ascuns o buclă de crash (containerul trece prin `running` la fiecare repornire). Fereastra cere
    eșantioane IDENTICE (același StartedAt, RestartCount 0): o repornire în fereastră e eșec, cu jurnalul la vedere. Fișierul de mediu
    nu rămâne nici pe calea asta."""
    patch_state(w, restart_after_reads=3, logs="Error: out of memory\n")
    res = w.up()
    assert res.rc == 1, res.out
    assert "NU e stabil" in res.out and "out of memory" in res.out, res.out
    assert "TOT DOVEDIT" not in res.out
    assert_env_file_gone(w)
    assert_no_secret(w, res)


def test_a_container_that_stops_inside_the_window_fails_the_run(w):
    """Un container care iese în fereastră (nu doar repornit) e tot instabil: eșantionul «exited» diferă de «running»."""
    patch_state(w, exit_after_reads=3)
    res = w.up()
    assert res.rc == 1 and "NU e stabil" in res.out, res.out


def test_a_health_check_that_never_answers_200_fails_with_the_log(w):
    """Containerul rulează dar n8n nu răspunde (migrare blocată): după numărul de încercări, eșec, cu jurnalul (migrări + erori). Nu se
    declară «TOT DOVEDIT» pe un proces viu care nu servește nimic."""
    w.set_health("000")
    patch_state(w, logs="Migration \"Big\" started\nError: database is locked\n")
    res = w.up()
    assert res.rc == 1, res.out
    assert "n-a răspuns 200" in res.out and "database is locked" in res.out and 'Migration "Big" started' in res.out
    assert "TOT DOVEDIT" not in res.out
    assert_env_file_gone(w)


def test_health_that_fails_at_the_end_of_the_window_fails_the_run(w):
    """Un /healthz 200 la început nu garantează nimic după 30 s: dacă la capătul ferestrei nu mai răspunde 200, eșec."""
    w.set_health("200", "500")
    res = w.up()
    assert res.rc == 1 and "nu mai răspunde 200" in res.out, res.out


# ------------------------------------------------------------------------------------------------------------------------
# mediul și secretele pe căile de eșec
# ------------------------------------------------------------------------------------------------------------------------

def test_a_docker_create_error_that_quotes_the_environment_is_scrubbed_and_the_env_file_removed(w):
    """`docker create` poate cita o valoare din --env-file în mesajul de eroare. Mesajul se arată operatorului, dar cu valorile înlocuite
    cu ***; fișierul de mediu se șterge pe calea de eșec; nu rămâne niciun obiect de container."""
    patch_state(w, create_rc=125, create_stderr=f"Error response from daemon: invalid env entry TWILIO_AUTH_TOKEN={SECRETS['TWILIO_AUTH_TOKEN']}")
    res = w.up()
    assert res.rc == 1, res.out
    assert "TWILIO_AUTH_TOKEN=***" in res.out
    assert "mesajul de mai sus are valorile de mediu înlocuite" in res.out, res.out      # aici ESTE un mesaj mai sus
    assert_no_secret(w, res)
    assert_env_file_gone(w)
    assert STAGE not in w.load()["containers"]


def test_xtrace_cannot_leak_values_even_when_the_operator_runs_the_script_with_bash_x(w):
    """`bash -x` (sau `set -x` moștenit) tipărește fiecare atribuire, inclusiv `N8N_SCRUB_JSON=[...secrete...]`, pe care filtrul o primește
    din mediul containerului. Scriptul își pornește execuția cu `set +x`; cu `-x` în linia de comandă valorile tot nu apar. Controlul
    pozitiv: aceeași rulare cu xtrace ARĂTÂND atribuirea (o declarație la fel de nesecretă) dovedește că `-x` chiar tipărește aici."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = [f"{k}={v}" for k, v in SECRETS.items()]
    w.state["logs"] = "linie\n"
    w.save()
    res = w.run("logs", "--tail", "5", shell_args=("-x",))
    assert res.rc == 0 and "linie" in res.out, res.out
    assert_no_secret(w, res)
    # control pozitiv: fără `set +x`, xtrace-ul din bash ar fi tipărit atribuirea cu valorile
    probe = w.run_sourced("set -x; V=\"$(docker container inspect n8n-staging --format '{{json .Config.Env}}')\"; N8N_SCRUB_JSON=\"$V\" true")
    assert SECRETS["TWILIO_AUTH_TOKEN"] in probe.out, probe.out


def test_an_environment_entry_with_a_newline_is_refused_not_mangled(w):
    """O valoare pe mai multe linii (o cheie privată) ar sparge fișierul de mediu în intrări false, iar docker ar da un container cu
    mediul greșit. Refuz clar, fără a tipări valoarea."""
    w.load()
    w.state["containers"][PROD]["env"] = w.state["containers"][PROD]["env"] + ["PRIVATE_KEY=-----BEGIN\nSECRET_PEM_LINE"]
    w.save()
    res = w.up()
    assert res.rc == 1, res.out
    assert "PRIVATE_KEY" in res.out and "SECRET_PEM_LINE" not in res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]
    assert w.env_files_left() == []


# ------------------------------------------------------------------------------------------------------------------------
# invariantul: producția nu s-a schimbat
# ------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("how", ["restart_count", "started_at", "id", "image"])
def test_a_change_to_production_during_a_subcommand_fails_loudly_whatever_field_changed(w, how):
    """Dacă producția repornește (RestartCount, StartedAt), e înlocuită (ID) sau schimbă imaginea cât rulează scriptul, operatorul trebuie
    să afle LA FIEL de tare, oricare ar fi câmpul — chiar dacă subcomanda însăși a reușit. Ieșire 4 și mesaj, nu 0."""
    patch_state(w, mutate_prod_on="volume ls", mutate_prod=how)
    res = w.run("down")
    assert res.rc == 4, res.out
    assert "PRODUCȚIA S-A SCHIMBAT" in res.out


def test_a_change_to_production_wins_over_a_successful_up(tmp_path):
    """Un `up` care a mers până la capăt dar în timpul căruia producția a repornit NU poate ieși cu 0: operatorul ar citi «TOT DOVEDIT» și
    ar presupune că producția n-a fost atinsă. Ieșire 4."""
    w = World(tmp_path)
    try:
        patch_state(w, mutate_prod_on="network create", mutate_prod="restart_count")
        res = w.up()
        assert "TOT DOVEDIT" in res.out
        assert res.rc == 4 and "PRODUCȚIA S-A SCHIMBAT" in res.out, res.out
    finally:
        w.close()


def test_a_change_to_production_wins_over_an_ordinary_failure_too(w):
    """Dacă `up` eșuează (aici: versiunea nu există în registru, ieșire 1) ȘI producția a repornit între timp, operatorul nu are voie să vadă
    doar «eșuat»: că producția s-a schimbat e mai grav decât orice refuz, deci ieșirea e tot 4."""
    patch_state(w, mutate_prod_on="pull", mutate_prod="started_at")
    res = w.up("3.0.9")
    assert res.rc == 4, res.out
    assert "nu pot descărca" in res.out and "PRODUCȚIA S-A SCHIMBAT" in res.out


def test_a_change_to_production_is_also_reported_by_the_read_only_subcommands(w):
    """`status` e doar citire, dar invariantul e pe fiecare subcomandă: dacă producția s-a schimbat cât rula, se spune."""
    patch_state(w, mutate_prod_on="volume ls", mutate_prod="id")
    res = w.run("status")
    assert res.rc == 4, res.out


def test_status_and_logs_do_not_change_anything(w):
    """`status` și `logs` sunt doar citire: niciun apel docker care schimbă ceva, nicio atingere a producției."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET, mounts=[])
    add_network(w, STAGE_NET, {LABEL: "1"})
    add_volume(w, STAGE_VOL, {LABEL: "1"})
    w.run("status")
    w.run("logs", "--tail", "10")
    assert mutating(w) == []
    assert touches_prod(w) == []


def test_the_source_never_invokes_docker_compose():
    """`docker compose` în /root ar putea recrea producția. Nu există în cod ca invocare (comentariile care spun «nu» sunt altceva)."""
    code = [l for l in HOST_LIB.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#")]
    assert not [l for l in code if re.search(r"docker[ -]compose|\bcompose\s+(up|down|restart|stop|rm)", l)]


# ------------------------------------------------------------------------------------------------------------------------
# status / logs
# ------------------------------------------------------------------------------------------------------------------------

def test_status_with_nothing_created_says_so_and_is_not_an_error(w):
    """«Nu există staging» e o stare cunoscută, nu o eroare: cod 0, mesaj clar."""
    res = w.run("status")
    assert res.rc == 0 and "nu există staging" in res.out, res.out


def test_status_of_a_partial_staging_is_not_green(w):
    """După un `up` întrerupt rămân rețeaua și volumul, fără container. `status` nu poate spune «bine»: cod 1 și trimite la `down`."""
    add_network(w, STAGE_NET, {LABEL: "1"})
    add_volume(w, STAGE_VOL, {LABEL: "1"})
    res = w.run("status")
    assert res.rc == 1 and "PARȚIAL" in res.out, res.out


def test_status_of_a_running_healthy_staging_prints_the_address(tmp_path):
    """Un `status` pe o copie sănătoasă dă adresa de tunel; unul pe o copie al cărei /healthz nu mai răspunde dă cod 1."""
    w = World(tmp_path)
    try:
        assert w.up().rc == 0
        ok = w.run("status")
        assert ok.rc == 0 and "N8N_STAGING_IP=172.30.0.2" in ok.out, ok.out
        w.set_health("503")
        sick = w.run("status")
        assert sick.rc == 1 and "healthz nu răspunde 200" in sick.out, sick.out
    finally:
        w.close()


def test_logs_are_scrubbed_of_environment_values(w):
    """Un jurnal n8n poate cita o valoare de mediu într-o eroare; `logs` îl arată, dar fără valorile din mediul containerului."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = [f"{k}={v}" for k, v in SECRETS.items()]
    w.state["logs"] = f"retrying with {SECRETS['TWILIO_AUTH_TOKEN']} and {SECRETS['ELEVENLABS_API_KEY']}\nlinie obișnuită\n"
    w.save()
    res = w.run("logs", "--tail", "50")
    assert res.rc == 0, res.out
    assert "retrying with *** and ***" in res.out and "linie obișnuită" in res.out
    assert_no_secret(w, res)


def _encoded_logs(w: World, env: list, log: str):
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = env
    w.state["logs"] = log
    w.save()
    return w.run("logs", "--tail", "50")



def _lines(res) -> list:
    """Liniile de jurnal din ieșirea lui `logs`, fără mesajele `[.]` ale scriptului (amprenta producției etc.)."""
    return [l for l in res.out.splitlines() if not l.startswith("[")]


EMAIL = "ana.popescu@firma-test.ro"
BS = chr(92)        # backslash, construit aici ca să nu depindă de cum se citesc secvențele `\u`/`\/` în sursă


def test_an_email_that_n8n_logs_url_encoded_is_not_printed(w):
    """Un jurnal n8n citează adesea o adresă din mediu într-un URL (`?email=ana%40firma.ro`) sau într-un corp de formular. Fără formele
    codificate, `logs` ar fi tipărit pe terminalul operatorului o adresă pe care o credea mascată."""
    res = _encoded_logs(w, [f"NOTIFY_EMAIL={EMAIL}"], f"GET /hook?email={EMAIL.replace('@', '%40')} 500\nlinie obișnuită\n")
    assert res.rc == 0, res.out
    assert "GET /hook?email=*** 500" in res.out and "linie obișnuită" in res.out, res.out
    assert "%40" not in res.out and "popescu" not in res.out, res.out


def test_a_lowercase_hex_percent_encoding_is_masked(w):
    """Unii clienți emit `%2b`, nu `%2B`: un telefon `+40…` trimis așa într-un URL ar fi rămas în clar în `logs`."""
    res = _encoded_logs(w, ["CONTACT_PHONE=+40712345678"], "to=%2b40712345678 ok\nto=%2B40712345678 ok\nto=+40712345678 ok\n")
    assert res.rc == 0, res.out
    assert res.out.count("to=*** ok") == 3, res.out
    assert "40712345678" not in res.out, res.out


def test_hex_case_is_free_per_digit_not_only_all_lower_or_all_upper(w):
    """Nu doar `%c4%83` și `%C4%83`: un client poate scrie `%C3%b1` (cifre mari și mici în aceeași secvență). O formă doar-toate-mici/
    toate-mari ar fi lăsat «Muñoz-Băs» în clar în `logs`, în exact acest caz."""
    res = _encoded_logs(w, ["OWNER=Muñoz-Băs"], "a=Mu%C3%b1oz-B%c4%83s\nb=Mu%c3%B1oz-B%C4%83s\nc=Mu%c3%b1oz-B%c4%83s\n")
    assert res.rc == 0, res.out
    assert res.out.count("=***") == 3 and "oz" not in res.out and "%" not in res.out, res.out


def test_a_plus_prefixed_phone_logged_as_percent_2b_is_masked(w):
    """Un telefon `+40…` într-un query string apare ca `%2B40…` (plusul ar însemna spațiu): fără forma codificată ajungea în clar."""
    res = _encoded_logs(w, ["CONTACT_PHONE=+40712345678"], "GET /sms?to=%2B40712345678 200\n")
    assert res.rc == 0 and "GET /sms?to=*** 200" in res.out, res.out
    assert "40712345678" not in res.out, res.out


def test_a_value_with_a_space_logged_with_plus_or_percent_20_is_masked(w):
    """Un corp `application/x-www-form-urlencoded` scrie spațiul ca `+`, nu ca `%20`: o valoare cu spațiu apărea în clar."""
    res = _encoded_logs(w, ["SIGNATURE=Echipa de suport"], "body=Echipa+de+suport&b=1\nbody=Echipa%20de%20suport&b=1\nbody=Echipa de+suport&b=1\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["body=***&b=1"] * 3, res.out


def test_node_encode_uri_component_form_is_masked(w):
    """n8n e Node: `encodeURIComponent` lasă `! ' ( ) * ~` neescapate, deci `P@ss!word(1)*x~y'z` apare ca `P%40ss!word(1)*x~y'z`, nu ca
    `P%40ss%21word...` (forma Python). Cu o listă de codificatoare Python, o parolă SMTP logată așa rămânea în clar în `logs`."""
    secret = "P@ss!word(1)*x~y'z"
    res = _encoded_logs(w, [f"SMTP_PASS={secret}"], "auth=P%40ss!word(1)*x~y'z end\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["auth=*** end"], res.out


def test_url_search_params_form_is_masked(w):
    """`URLSearchParams` (corpuri de formular din Node) scrie `*` literal, `~` ca `%7E`, `( )` ca `%28 %29`, `!` ca `%21` și spațiul ca `+`:
    `P%40ss%21word%281%29*x%7Ey+z`. O parolă cu spațiu logată așa ar fi rămas în clar în `logs`."""
    res = _encoded_logs(w, ["SMTP_PASS=P@ss!word(1)*x~y z"], "body=P%40ss%21word%281%29*x%7Ey+z&b=1\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["body=***&b=1"], res.out


def test_json_escaped_forms_of_a_secret_are_masked(w):
    """O eroare n8n serializată ca JSON scrie `/` ca `\\/` și `"` ca `\\"`, iar «ă» ca `\\u0103` sau direct: un secret cu aceste caractere
    ar fi rămas în clar în `logs`. Inclusiv `\\\\` pentru backslash și `\\n`/`\\t` pentru caractere de control, cu hex mic sau mare."""
    secret = 'https://hooks.example.ro/t/a"b'
    log = (f'{{"url":"https:{BS}/{BS}/hooks.example.ro{BS}/t{BS}/a{BS}"b"}}\n'
           + '{"url":"https://hooks.example.ro/t/a' + BS + '"b"}\n'
           + "https%3A%2F%2Fhooks.example.ro%2Ft%2Fa%22b\n")
    res = _encoded_logs(w, [f"WEBHOOK_SECRET={secret}"], log)
    assert res.rc == 0, res.out
    assert "hooks.example.ro" not in res.out, res.out
    assert res.out.count("***") == 3, res.out
    # «ă» ca ă (nu are variantă cu litere hex), «ñ» ca ñ și ñ (hex mare și mic)
    res = _encoded_logs(w, ["OWNER=Ionel Băs Muñoz"], f'a "Ionel B{BS}u0103s Mu{BS}u00F1oz" b\nc "Ionel B{BS}u0103s Mu{BS}u00f1oz"\n"Ionel Băs Muñoz"\n')
    assert res.out.count("***") == 3 and "Ionel" not in res.out and "u0103" not in res.out and "oz" not in res.out, res.out
    # backslash și caractere de control într-o valoare (cheie PEM scurtă, parolă cu backslash)
    res = _encoded_logs(w, [f"PEM=line1{BS}x\nline2\tend"], f'{{"k":"line1{BS}{BS}x{BS}nline2{BS}tend"}}\n')
    assert _lines(res) == ['{"k":"***"}'], res.out


def test_a_non_bmp_character_logged_as_a_surrogate_pair_is_masked(w):
    """Un caracter din afara BMP (emoji într-o parolă) e scris de `JSON.stringify` ca pereche `\\ud83d\\ude00`, nu ca `\\u1f600`; octeții lui
    UTF-8 în URL sunt `%F0%9F%98%80`. Fără perechea surogat, parola ar fi rămas în clar în `logs`."""
    res = _encoded_logs(w, ["EMOJI_PASS=key😀value"],
                        f"a key{BS}ud83d{BS}ude00value\nb key{BS}uD83D{BS}uDE00value\nc key%F0%9F%98%80value\nd key%f0%9f%98%80value\ne key😀value\n")
    assert res.rc == 0, res.out
    assert res.out.count("***") == 5 and "key" not in res.out and "ud83d" not in res.out.lower(), res.out


def test_encodings_can_be_mixed_inside_one_value(w):
    """Un URL poate avea o valoare codificată parțial (`a\\/b+c%40d\\"e`: JSON pentru `/` și `"`, formular pentru spațiu, procent pentru `@`).
    Un tipar per codificator ar rata amestecul; aici fiecare caracter își alege forma, deci secretul nu rămâne în clar."""
    secret = 'a/b c@d"e-secret'
    res = _encoded_logs(w, [f"MIXED={secret}"],
                        f'x a{BS}/b+c%40d{BS}"e-secret y\nx a/b%20c@d{BS}"e-secret y\nx a%2Fb c%40d"e-secret y\n')
    assert res.rc == 0, res.out
    assert _lines(res) == ["x *** y"] * 3, res.out


def test_an_allowlisted_value_stays_readable_even_in_encoded_form(w):
    """Formele codificate se adaugă DOAR pentru valorile deja hotărâte secrete: `N8N_HOST` și `TZ` sunt configurație nesecretă și operatorul
    are nevoie să le vadă în jurnal, brute și codificate. O expansiune aplicată înainte de lista de chei le-ar fi mascat."""
    res = _encoded_logs(w, ["N8N_HOST=ops@staging.example.ro", "TZ=Europe/Bucharest", f"NOTIFY_EMAIL={EMAIL}"],
                        "host=ops%40staging.example.ro ops@staging.example.ro tz=Europe%2FBucharest Europe/Bucharest "
                        "mail=ana.popescu%40firma-test.ro\n")
    assert res.rc == 0, res.out
    assert _lines(res) == [("host=ops%40staging.example.ro ops@staging.example.ro tz=Europe%2FBucharest Europe/Bucharest mail=***")], res.out


def test_true_false_and_short_values_are_never_masked_in_any_form(w):
    """`true`/`false` și valorile de sub 4 caractere nu sunt secrete: mascate, jurnalul ar deveni ilizibil («enabled=***», «port ***»), iar
    forma codificată a unei valori de 3 caractere ar potrivi zgomot peste tot."""
    res = _encoded_logs(w, ["FLAG=true", "OTHER=FALSE", "SHORT=ab1", "BLANK=", f"NOTIFY_EMAIL={EMAIL}"],
                        "enabled=true off=false FALSE ab1 %61b1 x\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["enabled=true off=false FALSE ab1 %61b1 x"], res.out


def test_overlapping_secrets_leave_no_residue_in_any_form(w):
    """Două secrete care se suprapun (`ab/cd/ef` și `b/cd`): dacă cel scurt e încercat primul, din `ab/cd/ef` rămâne `a***/ef`, adică
    fragmente din celălalt secret în clar în `logs`. Verificat pe forma brută, procent (`%2F`, hex mic) și JSON (`\\/`)."""
    log = f"1 ab/cd/ef 2\n3 ab%2Fcd%2Fef 4\n5 ab{BS}/cd{BS}/ef 6\n7 b/cd 8\n9 b%2fcd 10\n"
    res = _encoded_logs(w, ["SHORT=b/cd", "LONG=ab/cd/ef"], log)
    assert res.rc == 0, res.out
    assert _lines(res) == ["1 *** 2", "3 *** 4", "5 *** 6", "7 *** 8", "9 *** 10"], res.out


def test_a_secret_that_is_a_prefix_of_another_does_not_leave_the_tail(w):
    """`abcdef-secret` și prefixul lui `abcd`: dacă prefixul se maschează primul, rămâne `***ef-secret`, adică coada celuilalt secret în
    clar. Ordinea în care secretele apar în mediu nu are voie să conteze (aici cel scurt e primul)."""
    res = _encoded_logs(w, ["SHORT=abcd", "LONG=abcdef-secret"], "t abcdef-secret t\nu abcd u\n")
    assert _lines(res) == ["t *** t", "u *** u"], res.out


def test_partially_overlapping_secrets_are_masked_as_one_span(w):
    """`ab/cd/ef` și `cd/ef/gh` într-un jurnal `ab/cd/ef/gh`: după ce primul secret e înlocuit, al doilea nu mai are pe ce să se potrivească și
    rămâne `***/gh` în clar. Intervalele potrivite se unesc înainte de înlocuire, în oricare ordine a secretelor."""
    for env in (["A=ab/cd/ef", "B=cd/ef/gh"], ["B=cd/ef/gh", "A=ab/cd/ef"]):
        res = _encoded_logs(w, env, f"x ab/cd/ef/gh y\nx ab%2Fcd%2Fef%2Fgh y\nx ab{BS}/cd{BS}/ef{BS}/gh y\n")
        assert _lines(res) == ["x *** y"] * 3, (env, res.out)


def test_a_value_with_a_lone_surrogate_does_not_hide_the_log_nor_other_secrets(w):
    """O valoare cu un surogat singur (nu se poate codifica în UTF-8) nu are voie să prăbușească filtrul: ar ascunde tot jurnalul de
    operator, iar alte valori ar rămâne nefiltrate dacă s-ar tipări brut. Filtrul merge mai departe și maschează restul."""
    res = _encoded_logs(w, ["BAD=ab\ud800cd-bad", f"NOTIFY_EMAIL={EMAIL}"], "mail=ana.popescu%40firma-test.ro ok\n")
    assert res.rc == 0 and _lines(res) == ["mail=*** ok"], res.out


def test_a_secret_that_starts_inside_a_false_start_is_still_found_and_the_longest_form_wins(w):
    """Filtrul alege pozițiile de început cu un regex scurt, apoi verifică tot secretul. (1) `abab-key` în `ababab-key`: primul început (0)
    pică, iar al doilea (2) e în interiorul potrivirii de prefix a primului: dacă după un prefix se sare peste el, `ab` + secretul rămân
    în clar. (2) un secret care se termină în backslash, în jurnal ca JSON `\\\\`: dacă se ia prima formă (un backslash), rămâne un backslash
    pe lângă `***`; se ia cea mai lungă."""
    res = _encoded_logs(w, ["PASS=abab-key"], "t ababab-key t\n")
    assert _lines(res) == ["t ab*** t"], res.out
    res = _encoded_logs(w, ["PASS=abc-" + BS], "t abc-" + BS + BS + " t\nu abc-" + BS + " u\n")
    assert _lines(res) == ["t *** t", "u *** u"], res.out


def test_two_occurrences_of_a_secret_ending_in_a_backslash_back_to_back_leave_no_residue(tmp_path):
    """Pentru un secret care se termină în backslash, forma lungă (JSON `\\\\`) înghite primul backslash al unei a doua apariții lipite de
    prima; dacă după o potrivire căutarea reia de la sfârșitul celei mai lungi, a doua apariție nu mai are început și cade în clar
    (`***key9\\` în loc de nimic). Se maschează până la cea mai lungă potrivire, dar căutarea reia de la prima."""
    t, out = _run_scrub(BS + "key9" + BS, "x " + BS + "key9" + BS + BS + "key9" + BS + " y\n")
    assert out == "x *** y\n", out
    t, out = _run_scrub("ab-key" + BS, "x ab-key" + BS + BS + "u0061b-key" + BS + " y\n")
    assert out == "x *** y\n", out


def test_node_inspect_escaped_single_quote_is_masked(w):
    """`util.inspect` pune un șir cu ghilimele simple și duble în apostrofuri și scrie apostroful din valoare ca backslash + apostrof:
    `'O\\'Brien-key9'`. Fără forma asta, un secret cu apostrof ajungea în clar în `logs` când n8n loga un obiect cu `console.log`."""
    log = "obj { who: 'O" + BS + "'Brien-key9' } and O'Brien-key9 and O%27Brien-key9\n"
    res = _encoded_logs(w, ["OWNER=O'Brien-key9"], log)
    assert res.rc == 0, res.out
    assert _lines(res) == ["obj { who: '***' } and *** and ***"], res.out


def test_node_inspect_hex_escapes_of_control_and_latin1_characters_are_masked(w):
    """`util.inspect` scrie caracterele de control și cele sub 0x100 ca `\\xNN` (`\\x01`, `\\x7F`, `\\xF1`), cu hex mic sau mare. Un secret
    cu un caracter de control (cheie lipită dintr-un terminal) sau cu `ñ` rămânea în clar în `logs` când n8n loga obiectul."""
    secret = "ab" + chr(1) + "cd" + chr(0x7F) + "ef-Mu" + chr(0xF1) + "oz"
    log = (f"v1 ab{BS}x01cd{BS}x7Fef-Mu{BS}xF1oz end\n"
           f"v2 ab{BS}x01cd{BS}x7fef-Mu{BS}xf1oz end\n"
           f"v3 ab{BS}x01cd{BS}x7Fef-Mu{BS}xf1oz end\n")
    res = _encoded_logs(w, [f"RAW={secret}"], log)
    assert res.rc == 0, res.out
    assert _lines(res) == ["v1 *** end", "v2 *** end", "v3 *** end"], res.out


def test_legacy_escape_percent_u_form_is_masked_for_characters_above_ff(w):
    """`escape()` din Node (vechi, încă în codul unor noduri n8n) scrie `ă` ca `%u0103` și `ț` ca `%u021B`, nu ca `%C4%83`: un nume sau o
    parolă cu diacritice logate așa rămâneau în clar în `logs`. Hex mic sau mare, iar un caracter din afara BMP e pereche `%uD83D%uDE00`."""
    res = _encoded_logs(w, ["OWNER=Ionel-Băs-ț"], "a Ionel-B%u0103s-%u021B z\nb Ionel-B%u0103s-%u021b z\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["a *** z", "b *** z"], res.out
    res = _encoded_logs(w, ["EMOJI_PASS=key😀value"], "a key%uD83D%uDE00value z\nb key%ud83d%ude00value z\n")
    assert _lines(res) == ["a *** z", "b *** z"], res.out


def test_legacy_escape_percent_xx_of_the_latin1_byte_is_masked_for_0x80_to_0xff(w):
    """`escape("ñ")` e `%F1` (octetul Latin-1), nu `%C3%B1` (UTF-8): un secret cu `ñ` sau `é` logat așa rămânea în clar în `logs`."""
    res = _encoded_logs(w, ["OWNER=Muñoz-Café"], "a Mu%F1oz-Caf%E9 z\nb Mu%f1oz-Caf%e9 z\nc Mu%C3%B1oz-Caf%C3%A9 z\n")
    assert res.rc == 0, res.out
    assert _lines(res) == ["a *** z", "b *** z", "c *** z"], res.out


def _scrub_program() -> str:
    """Textul lui SCRUB_PY, exact cum e livrat în bibliotecă."""
    src = HOST_LIB.read_text(encoding="utf-8")
    m = re.search(r"read -r -d '' SCRUB_PY <<'PY' \|\| true\n(.*?)\nPY\n", src, re.S)
    assert m, "nu găsesc SCRUB_PY în bibliotecă"
    return m.group(1)


def _run_scrub(secret: str, log: str, timeout: float = 30.0):
    """Rulează filtrul real pe `log` cu un singur secret. Un tipar care revine la timp exponențial cade pe `timeout`, nu agață testul.
    `-W error`: un avertisment de sintaxă din program (o secvență de escapare nevalidă într-un docstring) ar face filtrul să cadă."""
    env = dict(os.environ, N8N_SCRUB_JSON=json.dumps(["K=" + secret]), PYTHONIOENCODING="utf-8")
    t0 = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, "-W", "error", "-c", _scrub_program()], input=log.encode(), capture_output=True,
                              env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        pytest.fail(f"filtrul n-a terminat în {timeout:.0f} s (timp exponențial pe un șir de backslash-uri?)")
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    return time.monotonic() - t0, proc.stdout.decode("utf-8")


def test_a_long_run_of_backslashes_in_the_log_does_not_make_the_filter_take_minutes(tmp_path):
    """Un backslash dintr-un secret se potrivește ca `\\` sau `\\\\` (JSON): un regex peste tot secretul parcurge un șir de backslash-uri în
    exponențial de multe feluri (~25 de backslash-uri în jurnal, secretul absent = 43 s; 28 = peste un minut). Un jurnal cu un șir lung de
    backslash-uri (un JSON escapat de mai multe ori, un traseu Windows) ar fi blocat `logs` și fiecare `up` la capăt, fără nicio eroare.
    Aici: secret de 40 de backslash-uri, absent într-un șir de 39 (nimic de mascat), prezent într-unul de 48 și de 3000, sub 2,5 s fiecare."""
    secret = BS * 40
    t, out = _run_scrub(secret, "x " + BS * 39 + " y\n")
    assert out == "x " + BS * 39 + " y\n", out
    assert t < 2.5, f"absent: {t:.1f} s"
    t, out = _run_scrub(secret, "x " + BS * 48 + " y\n")
    assert out == "x *** y\n", out
    assert t < 2.5, f"prezent (48): {t:.1f} s"
    t, out = _run_scrub(secret, "x " + BS * 3000 + " y\n")
    assert out.startswith("x ***") and out.endswith(" y\n") and BS * 40 not in out, out[:80]
    assert t < 2.5, f"prezent (3000): {t:.1f} s"


def test_repeated_backslash_quote_pairs_do_not_make_the_filter_take_minutes(tmp_path):
    """Același eșec pe altă cale: `\\"` apare în secret ca backslash + ghilimea, iar în jurnal `\\\\"` se parcurge în două feluri; 26 de perechi
    la rând, cu sfârșitul secretului lipsă din jurnal, dădeau 38 s (2^26 de încercări), iar 30 de perechi ore."""
    secret = (BS + '"') * 30 + "Q"
    log_absent = "x " + (BS + BS + '"') * 30 + "z y\n"
    t, out = _run_scrub(secret, log_absent)
    assert out == log_absent and t < 2.5, f"{t:.1f} s"
    t, out = _run_scrub(secret, "x " + (BS + BS + '"') * 30 + "Q y\n")
    assert out == "x *** y\n" and t < 2.5, f"{t:.1f} s: {out[:60]}"


def _python_that_crashes_on_the_scrub_program(w: World) -> None:
    """Înlocuiește `python3` din momeli cu unul care pică DOAR pe programul de filtrare (îl recunoaște după variabila N8N_SCRUB_JSON din
    codul lui) și în rest e python-ul real. Simulare: pică înainte de orice citire, ca o excepție la început; nu reproduce o excepție
    reală din interiorul filtrului."""
    real = posix(sys.executable)
    write_exec(w.bin / "python3", f'#!/usr/bin/env bash\ncase "$2" in *N8N_SCRUB_JSON*) echo "Traceback: boom" >&2; exit 1;; esac\nexec "{real}" "$@"\n')


def test_logs_hides_the_log_when_the_scrub_crashes(w):
    """Dacă filtrul pică (orice cauză), `logs` nu are voie să tipărească jurnalul brut: ieșire 3 («necunoscut»), niciun secret în ieșire."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = [f"{k}={v}" for k, v in SECRETS.items()]
    w.state["logs"] = f"retrying with {SECRETS['TWILIO_AUTH_TOKEN']}\nlinie obișnuită\n"
    w.save()
    _python_that_crashes_on_the_scrub_program(w)
    res = w.run("logs", "--tail", "50")
    assert res.rc == 3 and "nu pot filtra jurnalul" in res.out, res.out
    assert "linie obișnuită" not in res.out
    assert_no_secret(w, res)


@pytest.mark.parametrize("fn", ["show_log_excerpt", "show_progress 30"])
def test_the_wait_helpers_hide_the_log_when_the_scrub_crashes(w, fn):
    """`show_log_excerpt` (cauza unui timeout) și `show_progress` (progresul la așteptare) tipăresc linii de jurnal în mijlocul unui `up`:
    dacă filtrul pică, ele trebuie să înlocuiască jurnalul cu «jurnal ascuns», nu să-l tipărească brut. ȘI trebuie să SPUNĂ asta: sub titlurile
    «migrările bazei» și «linii de eroare» un jurnal ascuns lăsat gol se citește, la capătul unui `up` reușit, ca «nicio eroare»."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = [f"{k}={v}" for k, v in SECRETS.items()]
    w.state["logs"] = f"Error: retrying with {SECRETS['TWILIO_AUTH_TOKEN']} migration x\n"
    w.save()
    ok = w.run_sourced(fn)       # control pozitiv: cu filtrul întreg comanda ARATĂ linia (mascată); altfel «nu apare» n-ar dovedi nimic
    assert "retrying with ***" in ok.out, ok.out
    assert "jurnal ascuns" not in ok.out and "NU știu" not in ok.out, ok.out
    _python_that_crashes_on_the_scrub_program(w)
    res = w.run_sourced(fn)
    assert "retrying" not in res.out, res.out
    assert_no_secret(w, res)
    assert "jurnal ascuns: filtrarea a eșuat" in res.out, res.out        # operatorul e anunțat, nu doar scutit de linii
    if fn != "show_log_excerpt":
        # și a doua linie: fără ea, un `if false` în loc de `log_is_hidden` ar lăsa doar placeholderul (trecut prin awk) și testul ar tăcea
        assert "liniile nu se tipăresc nefiltrate; nu știu ce spun" in res.out, res.out
    if fn == "show_log_excerpt":
        # câte un mesaj sub FIECARE titlu, nu un titlu gol urmat de altul
        assert res.out.count("jurnal ascuns: filtrarea a eșuat") == 2, res.out
        mig, err = res.out.index("migrările bazei"), res.out.index("linii de eroare")
        assert mig < res.out.index("NU știu dacă există migrări") < err < res.out.index("NU știu dacă există erori"), res.out


def test_the_log_excerpt_says_so_when_the_scrub_cannot_read_the_environment_values(w):
    """A treia cale spre un jurnal ascuns: nu e nicio valoare de mediu de citit (containerul a dispărut, nu e fișier de mediu), iar
    `scrub_stream` iese 0 cu «text ascuns». Excerptul trece acel text prin `grep migrat`/`grep error` și rămânea cu două titluri goale."""
    res = w.run_sourced("show_log_excerpt")
    assert res.out.count("text ascuns: nu pot citi valorile de mediu") == 2, res.out
    assert "NU știu dacă există migrări" in res.out and "NU știu dacă există erori" in res.out, res.out


def test_a_docker_create_error_that_cannot_be_scrubbed_is_not_described_as_scrubbed(w):
    """Dacă filtrul pică în timp ce se arată eroarea lui `docker create`, nu există niciun mesaj «mai sus»: textul `mesajul de mai sus are
    valorile înlocuite cu ***` ar trimite operatorul să caute ceva ce nu s-a tipărit. Se spune pe față că mesajul docker nu se arată, iar
    valoarea din el nu apare nicăieri."""
    patch_state(w, create_rc=125, create_stderr=f"Error response from daemon: invalid env entry TWILIO_AUTH_TOKEN={SECRETS['TWILIO_AUTH_TOKEN']}")
    _python_that_crashes_on_the_scrub_program(w)
    res = w.up()
    assert res.rc == 1, res.out
    assert "mesajul lui docker NU se arată" in res.out and "jurnal ascuns: filtrarea a eșuat" in res.out, res.out
    assert "mesajul de mai sus" not in res.out, res.out
    assert_no_secret(w, res)
    assert_env_file_gone(w)
    assert STAGE not in w.load()["containers"]


def test_logs_without_a_container_is_a_refusal(w):
    """Fără container nu există jurnal: refuz clar, nu o ieșire goală cu 0."""
    res = w.run("logs")
    assert res.rc == 1, res.out


# ------------------------------------------------------------------------------------------------------------------------
# down: doar ce poartă eticheta
# ------------------------------------------------------------------------------------------------------------------------

def _staging_trio(w: World, *, container_label=True, volume_label=True, network_label=True) -> None:
    add_container(w, STAGE, {LABEL: "1"} if container_label else {}, network=STAGE_NET)
    add_volume(w, STAGE_VOL, {LABEL: "1"} if volume_label else {})
    add_network(w, STAGE_NET, {LABEL: "1"} if network_label else {})


def test_down_removes_container_then_volume_then_network_and_proves_each_is_gone(w):
    """`down` șterge în ordinea care merge (o rețea cu puncte finale active nu se poate șterge, un volum folosit nu se poate șterge) și
    arată pentru fiecare obiect că a DISPĂRUT, nu doar că `rm` a ieșit cu 0. Producția nu se atinge."""
    _staging_trio(w)
    res = w.run("down")
    assert res.rc == 0, res.out
    order = [(a[0], a[1]) if a[0] in ("volume", "network") else (a[0],) for a in w.docker_log() if a[0] == "rm" or (a[0] in ("volume", "network") and a[1] == "rm")]
    assert order == [("rm",), ("volume", "rm"), ("network", "rm")], order
    assert "container n8n-staging: șters și dovedit că a dispărut" in res.out
    assert w.object_keys() == ((PROD,), ("n8n_data", "traefik_data"), ("bridge", "root_default"))
    assert touches_prod(w) == []


@pytest.mark.parametrize("which", ["container_label", "volume_label", "network_label"])
def test_down_refuses_everything_when_one_target_lacks_the_label(w, which):
    """Un obiect cu numele nostru dar FĂRĂ etichetă nu e al scriptului (poate fi al operatorului). `down` refuză și nu șterge NIMIC — nici
    obiectele care poartă eticheta — ca să nu lase o stare pe jumătate ștearsă."""
    _staging_trio(w, **{which: False})
    before = w.object_keys()
    res = w.run("down")
    assert res.rc == 1 and "NU poartă eticheta" in res.out, res.out
    assert w.object_keys() == before
    assert not [a for a in w.docker_log() if a[0] == "rm" or a[1:2] == ["rm"]]


@pytest.mark.parametrize("name", [STAGE, "alt-container"], ids=["our-name", "another-name"])
def test_down_refuses_a_label_with_another_value(w, name):
    """Eticheta cu altă valoare decât 1 nu e a noastră: refuz, nimic șters — fie că obiectul poartă numele nostru, fie că a fost găsit doar
    după etichetă (un alt nume): al doilea drum are propria verificare a valorii."""
    _staging_trio(w)
    add_container(w, name, {LABEL: "0"}, network=STAGE_NET)      # pe numele nostru, suprascrie containerul etichetat corect
    before = w.object_keys()
    res = w.run("down")
    assert res.rc == 1, res.out
    assert w.object_keys() == before


def test_down_never_deletes_a_production_object_even_if_it_carries_the_label(w):
    """O etichetă pusă din greșeală pe containerul de producție ar face din el o țintă. Lista de refuz (root-n8n-1, n8n_data, root_default)
    nu se negociază: refuz, producția rămâne."""
    w.load()
    w.state["containers"][PROD]["labels"] = {LABEL: "1"}
    w.save()
    res = w.run("down")
    assert res.rc == 1 and "din producție" in res.out, res.out
    assert PROD in w.load()["containers"]
    assert not [a for a in w.docker_log() if a[0] == "rm"]


def test_down_reports_a_removal_that_docker_claimed_but_did_not_do(w):
    """`docker rm -f` poate ieși cu 0 fără să șteargă (a mai fost cazul cu `reload`/`enable --now`). `down` verifică în lista docker că
    obiectul a dispărut; altfel iese cu 1, nu cu 0."""
    _staging_trio(w)
    patch_state(w, rm_noop=True)
    res = w.run("down")
    assert res.rc == 1 and "încă există după ștergere" in res.out, res.out


def test_down_with_nothing_to_remove_removes_nothing(w):
    """Un `down` pe o gazdă curată e un nu-fac-nimic cu cod 0, fără apeluri de ștergere."""
    res = w.run("down")
    assert res.rc == 0 and "nimic de șters" in res.out, res.out
    assert mutating(w) == []


def test_down_removes_a_leftover_probe_container_that_blocks_the_network(w):
    """Dacă proba (`--rm`) a rămas după o întrerupere, ține rețeaua ocupată și `network rm` ar pica. Poartă eticheta, deci `down` o șterge
    primul."""
    _staging_trio(w)
    add_container(w, "n8n-staging-probe", {LABEL: "1"}, network=STAGE_NET)
    res = w.run("down")
    assert res.rc == 0, res.out
    assert w.object_keys()[0] == (PROD,)


def test_after_down_a_new_up_is_possible(tmp_path):
    """Ciclul complet: `up`, `down`, `up` din nou — dacă `down` ar lăsa ceva, al doilea `up` ar refuza («există deja»)."""
    w = World(tmp_path)
    try:
        assert w.up().rc == 0
        assert w.run("down").rc == 0
        again = w.up()
        assert again.rc == 0, again.out
    finally:
        w.close()


# ========================================================================================================================
# Runda 2
# ========================================================================================================================

# ------------------------------------------------------------------------------------------------------------------------
# conducta ruptă: ssh cade la mijlocul unei rulări
# ------------------------------------------------------------------------------------------------------------------------

PIPE_CASES = [
    ("between-start-and-probe-egress", "pornesc n8n-staging", {"probe_exec": {"tcp": True}}),
    ("during-probe-egress", "dovedesc izolarea din interiorul", {"probe_exec": {"dns": True}}),
    ("between-start-and-probe-unknown", "pornesc n8n-staging", {"probe_exec": {"mode": "garbage"}}),
    ("during-probe-unknown", "dovedesc izolarea din interiorul", {"probe_exec": {"mode": "garbage"}}),
]


@pytest.mark.parametrize("name,trigger,probe", PIPE_CASES, ids=[c[0] for c in PIPE_CASES])
def test_a_dropped_ssh_connection_never_leaves_an_unproven_container_running(w, name, trigger, probe):
    """Când ssh cade, următorul `printf` primea SIGPIPE: bash murea, trap-ul de ieșire pornea cu $?=0, cădea la primul mesaj, iar un container
    cu ieșire la internet (sau cu izolare nedovedită) rămânea pornit și cu workflow-urile active (măsurat de verificator: ieșire 141,
    containerul exista, `rm -f` nechemat). Aici cititorul ÎNCHIDE conducta (stdout+stderr, ca prin ssh) de îndată ce vede linia-declanșator,
    la mijlocul rulării: între `start` și proba din container, sau chiar în timpul ei, cu ieșire văzută sau cu probă care nu rulează.
    Containerul trebuie să dispară oricum, iar fișierul de mediu la fel."""
    patch_state(w, **probe)
    rc, seen = w.run_closing_pipe(trigger, "up", "--version", "3.0.1")
    assert seen, "linia-declanșator n-a apărut: testul n-a închis conducta la momentul dorit"
    assert rc not in (0, 141), rc
    assert STAGE not in w.load()["containers"], "containerul cu izolare nedovedită a rămas după ce conducta s-a rupt"
    assert ["rm", "-f", STAGE] in w.docker_log()
    assert_env_file_gone(w)


def test_a_dropped_ssh_connection_does_not_remove_a_container_whose_isolation_was_proven(w):
    """Control pozitiv pentru testul de mai sus: cu proba CURATĂ, o conductă ruptă în aceeași clipă nu șterge nimic (un container dovedit nu
    e o problemă), deci ștergerea din testele cu ieșire vine din izolarea nedovedită, nu din conducta ruptă în sine."""
    rc, seen = w.run_closing_pipe("pornesc n8n-staging", "up", "--version", "3.0.1")
    assert seen
    s = w.load()
    assert STAGE in s["containers"] and s["containers"][STAGE]["state"] == "running", s["containers"].get(STAGE)
    assert ["rm", "-f", STAGE] not in w.docker_log()


# ------------------------------------------------------------------------------------------------------------------------
# verificările containerului creat și ale celui pornit: fiecare trebuie văzută refuzând
# ------------------------------------------------------------------------------------------------------------------------

SHAPE_CASES = [
    ("prod-volume-mounted", {"mounts_add": [{"dst": "/extra", "type": "volume", "name": "n8n_data", "src": "/x", "rw": True}]}, "VOLUMUL DE PRODUCȚIE"),
    ("files-read-write", {"files_rw": True}, "READ-WRITE"),
    ("published-ports", {"ports": {"5678/tcp": [{"HostPort": "5678"}]}}, "publică porturi"),
    ("wrong-network", {"network": "bridge"}, "nu pe n8n-staging-net"),
    ("missing-label", {"labels": {}}, "n-are eticheta"),
    ("wrong-data-volume", {"data_volume": "altceva"}, "nu e volumul"),
    ("no-resource-limits", {"no_limits": True}, "limite de CPU"),
]


@pytest.mark.parametrize("name,mutate,needle", SHAPE_CASES, ids=[c[0] for c in SHAPE_CASES])
def test_a_created_container_with_the_wrong_shape_is_refused_before_it_starts(w, name, mutate, needle):
    """Verificarea formei containerului creat e ultima barieră înainte de `start`: un volum de producție montat (workflow-urile ar scrie în el),
    /files read-write (ar modifica fișierele de producție), un port publicat (copia ar fi accesibilă din afară), altă rețea, fără etichetă (`down`
    nu l-ar mai găsi) sau fără limite (ar lua procesorul producției). Fiecare caz: refuz cu 1 și mesajul lui, niciun `start`, fișierul de mediu șters."""
    patch_state(w, create_mutate=mutate)
    res = w.up()
    assert res.rc == 1 and needle in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] == "start"], "containerul cu forma greșită a pornit"
    assert w.load()["containers"][STAGE]["state"] != "running"
    assert_env_file_gone(w)


@pytest.mark.parametrize("name,mutate,needle", [
    ("extra-network", {"extra_networks": ["bridge"]}, "2 rețele"),
    ("wrong-network-name", {"reported_network": "bridge"}, 'pe rețeaua "bridge"'),
], ids=["extra-network", "wrong-network-name"])
def test_a_started_container_on_an_extra_or_wrong_network_is_removed(w, name, mutate, needle):
    """După pornire, containerul trebuie să fie pe EXACT o rețea, cea internă. O a doua rețea (poate cu ieșire) sau alt nume contrazice tot ce s-a
    dovedit: refuz cu 1, mesajul spune ce a găsit, iar containerul NU rămâne pornit."""
    patch_state(w, create_mutate=mutate)
    res = w.up()
    assert res.rc == 1 and "forma rețelei" in res.out and needle in res.out, res.out
    assert STAGE not in w.load()["containers"]
    assert ["rm", "-f", STAGE] in w.docker_log()
    assert "TOT DOVEDIT" not in res.out


def _tar_shim(w: World, action: str) -> None:
    """Un `tar` care face treaba reală și apoi, la EXTRAGERE (-xpf), strică copia: `nice`/`ionice` execută binarul din PATH, deci o funcție bash n-ar fi chemată."""
    from _su_shell import write_exec
    write_exec(w.bin / "tar", f'#!/usr/bin/env bash\n/usr/bin/tar "$@"\nrc=$?\nif [[ "$*" == *-xpf* ]]; then {action}; fi\nexit $rc\n')


def test_an_encryption_key_that_differs_in_the_copy_is_refused(w):
    """Dacă fișierul `config` din copie diferă de cel din producție, toate credențialele din copie (Twilio, Gmail) sunt ilizibile, iar
    workflow-urile pică la prima rulare fără nicio eroare de copiere. Refuz, n8n nu pornește."""
    _tar_shim(w, 'printf x >> "$2/config"')
    res = w.up()
    assert res.rc == 1 and "config din copie diferă" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_a_file_missing_from_the_volume_copy_is_refused(w):
    """Un pachet comunitar (nodes/) sau un fișier din volum care nu ajunge în copie face un workflow să pice cu «node not installed», în
    staging și doar acolo. Copierea e dovedită pe efect (listă cu lista), nu după codul de ieșire al lui tar: refuz, cu numele lipsă."""
    _tar_shim(w, 'rm -f "$2/nodes/node_modules/n8n-nodes-basecamp/package.json"')
    res = w.up()
    assert res.rc == 1 and "lipsesc fișiere" in res.out and "package.json" in res.out, res.out
    assert not [a for a in w.docker_log() if a[0] in ("create", "start")]


def test_an_unreadable_production_fingerprint_at_exit_is_not_success(w):
    """Dacă la ieșire amprenta producției nu se mai poate citi (docker nu răspunde pe ea), scriptul nu poate dovedi că producția n-a fost atinsă:
    «necunoscut» (3), nu 0. Altfel un `down` ar ieși «curat» fără nicio dovadă."""
    patch_state(w, mutate_prod_on="volume ls", mutate_prod="unreadable")
    res = w.run("down")
    assert res.rc == 3 and "nu pot reciti amprenta" in res.out, res.out


def test_the_scrub_fallback_hides_text_instead_of_printing_it_raw_when_values_cannot_be_read(w):
    """Dacă filtrul n-are de unde afla valorile de mediu (nu există container, nu există fișier de mediu), «n-am putut filtra» NU înseamnă «nu e
    nimic de filtrat»: textul se ascunde, nu se tipărește brut."""
    res = w.run_sourced('echo "linie cu TOKEN_ABC_123" | scrub_stream')
    assert "text ascuns" in res.out and "TOKEN_ABC_123" not in res.out, res.out


def test_log_masking_keeps_ports_booleans_and_our_own_overrides_readable(w):
    """Jurnalul arăta «n8n ready on ***, port ***» și «enabled=***»: valori nesecrete (cifre, true/false, suprascrierile puse de script) erau
    mascate fiindcă coincid cu o valoare de mediu, iar operatorul nu mai putea citi nimic. Acestea rămân vizibile; orice altă valoare, inclusiv
    secretele, rămâne mascată."""
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = [f"{k}={v}" for k, v in SECRETS.items()] + [
        "EXECUTIONS_TIMEOUT=3600", "N8N_PORT=5678", "N8N_HOST=localhost", "N8N_SECURE_COOKIE=false", "MAX_RETRIES_PER_DEBTOR=3",
        "GENERIC_TIMEZONE=Europe/Bucharest", "FEATURE_ENABLED=true", "FEATURE_DISABLED=FALSE"]
    w.state["logs"] = (f"n8n ready on localhost, port 5678 timeout 3600 enabled=true cookie=false retries 3 off=FALSE tz Europe/Bucharest "
                       f"key {SECRETS['TWILIO_AUTH_TOKEN']} and {SECRETS['ELEVENLABS_API_KEY']}\n")
    w.save()
    res = w.run("logs", "--tail", "5")
    assert res.rc == 0, res.out
    assert "n8n ready on localhost, port 5678 timeout 3600 enabled=true cookie=false retries 3 off=FALSE tz Europe/Bucharest" in res.out, res.out
    assert "key *** and ***" in res.out
    assert_no_secret(w, res)


def _logs_with_env(w: World, env: list[str], log: str) -> str:
    add_container(w, STAGE, {LABEL: "1"}, network=STAGE_NET)
    w.load()
    w.state["containers"][STAGE]["env"] = env
    w.state["logs"] = log + "\n"
    w.save()
    res = w.run("logs", "--tail", "5")
    assert res.rc == 0, res.out
    return res.out


def test_numeric_secrets_are_masked_because_the_decision_is_by_key_not_by_value_shape(w):
    """Prod are CALLMEBOT_APIKEY (cheile CallMeBot sunt numerice) și YOUR_WHATSAPP_NUMBER (doar cifre, fără +). Un filtru care scutea valorile
    «doar cifre» a lăsat să treacă în terminal și în fișierul `tee` `phone=40722000111&apikey=4815162 failed`, când un workflow cu CallMeBot
    pica pe DNS și n8n loga URL-ul. Se decide după CHEIE: orice cheie care nu e pe lista nesecretă se maschează, oricum ar arăta valoarea
    (aici 7 cifre și 11 cifre), iar N8N_PORT rămâne lizibil."""
    out = _logs_with_env(w, ["CALLMEBOT_APIKEY=4815162", "YOUR_WHATSAPP_NUMBER=40722000111", "N8N_PORT=5678"],
                         "GET http://api.callmebot.com/whatsapp.php?phone=40722000111&apikey=4815162 failed on port 5678")
    assert "phone=***&apikey=*** failed on port 5678" in out, out
    assert "40722000111" not in out and "4815162" not in out


def test_a_value_shared_with_a_listed_key_is_still_masked_when_an_unlisted_key_holds_it(w):
    """Partea secretă câștigă: dacă valoarea unei chei nesecrete (N8N_PAYLOAD_SIZE_MAX=64000) apare ȘI sub o cheie nelistată (un PIN), ea se
    maschează peste tot. Altfel ar ajunge în clar exact prin coincidență. Valoarea unei chei listate pe care nu o deține nimeni altcineva
    (EXECUTIONS_TIMEOUT, prefix listat) rămâne lizibilă."""
    out = _logs_with_env(w, ["N8N_PAYLOAD_SIZE_MAX=64000", "LEGACY_PIN=64000", "EXECUTIONS_TIMEOUT=3600", "N8N_HOST=localhost"],
                         "payload 64000 timeout 3600 host localhost pin 64000")
    assert "payload *** timeout 3600 host localhost pin ***" in out, out


def test_allowlisted_config_keys_stay_readable_and_unknown_keys_are_masked(w):
    """Lista numită de chei nesecrete (N8N_PORT, N8N_PROTOCOL, TZ, NODE_ENV, N8N_LOG_LEVEL, EXECUTIONS_*, N8N_RELEASE_TYPE...) rămâne vizibilă;
    o cheie necunoscută cu o valoare de aceeași formă (aici un nume) se maschează."""
    out = _logs_with_env(w, ["N8N_PROTOCOL=http", "TZ=Europe/Bucharest", "NODE_ENV=production", "N8N_LOG_LEVEL=debug",
                             "EXECUTIONS_DATA_MAX_AGE=336", "N8N_RELEASE_TYPE=stable", "COMPANY_NAME=Acme-Recuperari"],
                         "http Europe/Bucharest production debug 336 stable Acme-Recuperari")
    assert "http Europe/Bucharest production debug 336 stable ***" in out, out


# ------------------------------------------------------------------------------------------------------------------------
# praguri și limite: argumente validate, implicite, efectul lor
# ------------------------------------------------------------------------------------------------------------------------

THRESHOLD_BAD = ([("--health-timeout", v) for v in ("59", "7201", "abc", "", "60;id", "-60", "1e3", "60x", "999999")]
                  + [("--cpus", v) for v in ("0", "0.24", "2.01", "3", "1.234", "-1", "1;id", "abc", "", "10")]
                  + [("--memory", v) for v in ("100m", "511m", "7g", "6145m", "3", "3gb", "1e3m", "g", "99999m", "3G", "")])


@pytest.mark.parametrize("flag,bad", THRESHOLD_BAD, ids=[f"{f}={v or 'empty'}" for f, v in THRESHOLD_BAD])
def test_threshold_flags_are_validated_on_the_host_before_any_docker_call(w, flag, bad):
    """Pragurile ajung pe gazdă ca argumente (sudo curăță mediul) și intră în aritmetică și în `docker create`: o valoare nevalidată e cod sau o
    limită absurdă. Refuz cu 2 înainte de orice apel docker (la fel și în lansator)."""
    res = w.run("up", "--version", "3.0.1", flag, bad)
    assert res.rc == 2, res.out
    assert w.docker_log() == []


def test_the_validators_accept_exactly_the_documented_range(w):
    """Limitele intervalelor: 60-7200 s, 0.25-2 procesoare, 512m-6g. Un `>` în loc de `>=` sau un interval lărgit ar lăsa pe gazdă o limită
    care ia procesorul producției sau o așteptare de zile."""
    body = '''
for v in 60 61 7200 3600; do valid_health_timeout "$v" && echo "ACC-T-$v" || echo "REJ-T-$v"; done
for v in 59 7201 0 ""; do valid_health_timeout "$v" && echo "ACC-T-$v" || echo "REJ-T-$v"; done
for v in 0.25 0.5 1 1.5 2 2.00 1.05 .5; do valid_cpus "$v" && echo "ACC-C-$v" || echo "REJ-C-$v"; done
for v in 0.24 2.01 2.5 3 0 0.1; do valid_cpus "$v" && echo "ACC-C-$v" || echo "REJ-C-$v"; done
for v in 512m 1024m 3g 6g 6144m 02g; do valid_memory "$v" && echo "ACC-M-$v" || echo "REJ-M-$v"; done
for v in 511m 6145m 7g 0g 100m; do valid_memory "$v" && echo "ACC-M-$v" || echo "REJ-M-$v"; done
'''
    res = w.run_sourced(body)
    got = {l.split("-", 1)[1]: l.split("-", 1)[0] for l in res.out.split() if l.startswith(("ACC-", "REJ-"))}
    expect_ok = ["T-60", "T-61", "T-7200", "T-3600", "C-0.25", "C-0.5", "C-1", "C-1.5", "C-2", "C-2.00", "C-1.05", "M-512m", "M-1024m", "M-3g", "M-6g", "M-6144m", "M-02g"]
    expect_no = ["T-59", "T-7201", "T-0", "C-0.24", "C-2.01", "C-2.5", "C-3", "C-0", "C-0.1", "C-.5", "M-511m", "M-6145m", "M-7g", "M-0g", "M-100m"]
    assert [k for k in expect_ok if got.get(k) != "ACC"] == [], res.out
    assert [k for k in expect_no if got.get(k) != "REJ"] == [], res.out


def test_the_defaults_and_the_given_values_reach_the_script(w):
    """Implicit: 20 min de așteptare (nu ~4 min, cât era înainte, nereglabil), 1 procesor, 3 GB. Cu argumente, valorile date; numărul de
    încercări se deduce din --health-timeout și din pasul de interogare."""
    body_default = 'cmd_up() { echo "RESULT T=$HEALTH_TIMEOUT_S TRIES=$HEALTH_TRIES CPUS=$CPUS MEM=$MEMORY"; }\nmain up --version 3.0.1'
    default = w.run_sourced(body_default, N8N_STAGING_POLL_S="2", N8N_STAGING_HEALTH_TRIES="")
    assert "RESULT T=1200 TRIES=600 CPUS=1 MEM=3g" in default.out, default.out
    given = w.run_sourced(body_default.replace("main up --version 3.0.1", "main up --version 3.0.1 --health-timeout 3600 --cpus 0.5 --memory 2048m"),
                          N8N_STAGING_POLL_S="2", N8N_STAGING_HEALTH_TRIES="")
    assert "RESULT T=3600 TRIES=1800 CPUS=0.5 MEM=2048m" in given.out, given.out


def test_the_container_and_the_probe_run_with_limits_and_the_backup_runs_at_low_priority(happy):
    """Gazda are 2 procesoare și 7,9 GB, iar producția rulează pe ea fără limite: containerul de staging și cel de probă au --cpus/--memory
    (citite înapoi din container: NanoCpus și Memory nenule), iar backup-ul, integrity_check și cele două `tar` rulează sub ionice/nice."""
    w, res, _ = happy
    create = next(a for a in w.docker_log() if a[0] == "create")
    probe = next(a for a in w.docker_log() if a[0] == "run")
    for argv in (create, probe):
        i = argv.index("--cpus")
        assert argv[i:i + 6] == ["--cpus", "1", "--memory", "3g", "--memory-swap", "3g"], argv[:20]
    c = w.load()["containers"][STAGE]
    assert c["nano_cpus"] == 1_000_000_000 and c["memory"] == 3 * 1024 ** 3
    log = w.prio_log()
    for prog in ("python3", "tar"):
        assert len([l for l in log if l.startswith("nice -n 19") and l.endswith(f"prog={prog}")]) == 2, (prog, log)
        assert len([l for l in log if l.startswith("ionice -c3 ") and l.endswith(f" {prog}")]) == 2, (prog, log)
    assert "limite pentru container și probă: --cpus 1 --memory 3g" in res.out


def test_the_operators_limits_and_the_gateway_and_release_warnings_in_one_run(tmp_path):
    """O singură rulare completă cu valori date de operator: --cpus/--memory ajung în container și în probă (și se citesc înapoi); gateway-ul
    cu 80 deschis dă un avertisment vizibil FĂRĂ să refuze (DNS blocat: URL-urile cu nume nu merg); o imagine
    `rc` dă avertisment, dar `up` merge până la capăt."""
    w = World(tmp_path)
    try:
        patch_state(w, gateway_ports={"80": "open", "443": "refused", "8443": "open", "5678": "refused"}, release_type="rc")
        res = w.run("up", "--version", "3.0.1", "--cpus", "0.5", "--memory", "2g", "--health-timeout", "60")
        assert res.rc == 0, res.out
        create = next(a for a in w.docker_log() if a[0] == "create")
        i = create.index("--cpus")
        assert create[i:i + 6] == ["--cpus", "0.5", "--memory", "2g", "--memory-swap", "2g"]
        assert w.load()["containers"][STAGE]["nano_cpus"] == 500_000_000
        assert "ATENȚIE: din container se ajunge la 172.30.0.1 pe portul 80" in res.out, res.out
        assert "80=open 443=refused 8443=open 5678=refused" in res.out
        assert "ATENȚIE: imaginea docker.n8n.io/n8nio/n8n:3.0.1 declară N8N_RELEASE_TYPE=rc" in res.out
        assert "TOT DOVEDIT" in res.out
    finally:
        w.close()


# ------------------------------------------------------------------------------------------------------------------------
# gateway și tipul versiunii
# ------------------------------------------------------------------------------------------------------------------------

def test_a_gateway_that_answers_on_no_web_port_is_reported_without_a_warning(happy):
    """Gateway-ul bridge-ului (adresa gazdei) se raportează pe cele patru porturi, la ambele probe, iar când 80 și 443 NU răspund nu se
    avertizează: un avertisment mereu aprins s-ar citi ca zgomot."""
    w, res, _ = happy
    assert res.out.count("80=refused 443=refused 8443=refused 5678=refused") == 2, res.out
    assert "din container se ajunge la" not in res.out


@pytest.mark.parametrize("port", ["80", "443"])
def test_an_open_web_port_on_the_gateway_warns_prominently_and_does_not_refuse(tmp_path, port):
    """traefik publică 80/443 pe gazdă și rutează spre webhook-urile n8n de PRODUCȚIE: un workflow care apelează direct un IP ar putea lovi
    producția. Avertisment vizibil, dar `up` continuă (DNS blocat, deci URL-urile cu nume nu merg)."""
    w = World(tmp_path)
    try:
        patch_state(w, gateway_ports={port: "open"})
        res = w.up()
        assert res.rc == 0, res.out
        assert "ATENȚIE: din container se ajunge la 172.30.0.1" in res.out and "traefik" in res.out, res.out
        assert f"{port}=open" in res.out
    finally:
        w.close()


@pytest.mark.parametrize("rt,needle,warns", [
    ("rc", "N8N_RELEASE_TYPE=rc, nu «stable»", True),
    ("stable", "imaginea declară N8N_RELEASE_TYPE=stable", False),
    (None, "nu declară un N8N_RELEASE_TYPE lizibil", True),
    ("rc;id", "nu declară un N8N_RELEASE_TYPE lizibil", True),
], ids=["rc", "stable", "absent", "garbage"])
def test_the_images_release_type_is_printed_and_anything_but_stable_warns(w, rt, needle, warns):
    """`n8n:3.0.1` declară N8N_RELEASE_TYPE=rc: operatorul ar fi încercat upgrade-ul pe o versiune de testare fără să știe. Tipul declarat se
    tipărește după pull; orice în afară de «stable» (inclusiv absent sau ciudat) dă avertisment. O valoare cu caractere străine nu se tipărește brută."""
    ref = IMAGE_FOR.format("3.0.1")
    w.load()
    w.state["images"][ref] = {"id": "sha256:" + "7" * 64, "env": ["PATH=/x"] + ([f"N8N_RELEASE_TYPE={rt}"] if rt else [])}
    w.save()
    res = w.run_sourced(f"report_release_type {ref}")
    assert needle in res.out, res.out
    assert ("ATENȚIE" in res.out or "nu declară" in res.out) == warns
    assert "rc;id" not in res.out


# ------------------------------------------------------------------------------------------------------------------------
# așteptarea healthz: progres, expirare, cauza
# ------------------------------------------------------------------------------------------------------------------------

def test_the_wait_prints_scrubbed_progress_and_says_the_container_is_still_running_at_timeout(w):
    """O migrare de zeci de minute pe o bază de 9,6 GB nu trebuie să arate ca un blocaj, nici la timeout ca un eșec ambiguu. Cât așteaptă, se
    tipăresc ultimele linii din jurnal (cu valorile de mediu mascate), iar la expirare mesajul spune că n8n ÎNCĂ RULEAZĂ (probabil migrează)
    și ce să faca operatorul."""
    w.set_health("000")
    patch_state(w, logs=f"Migration 17/120 in progress for key {SECRETS['TWILIO_AUTH_TOKEN']}\n")
    res = w.up(N8N_STAGING_PROGRESS_EVERY="1")
    assert res.rc == 1, res.out
    assert "încă aștept" in res.out and "Migration 17/120 in progress for key ***" in res.out, res.out
    assert "ÎNCĂ RULEAZĂ" in res.out and "probabil încă migrează" in res.out
    assert "TOT DOVEDIT" not in res.out
    assert_no_secret(w, res)
    assert STAGE in w.load()["containers"], "containerul care încă migrează nu trebuie șters la expirarea așteptării"


def test_a_container_that_dies_during_the_wait_is_reported_as_dead(w):
    """Un container care iese cât se așteaptă /healthz nu «migrează»: mesajul spune că a MURIT, nu «încă rulează», și arată jurnalul."""
    w.set_health("000")
    patch_state(w, exit_after_reads=2, logs="Error: SQLITE_CORRUPT: database disk image is malformed\n")
    res = w.up()
    assert res.rc == 1 and "a MURIT, nu migrează" in res.out and "SQLITE_CORRUPT" in res.out, res.out
    assert "ÎNCĂ RULEAZĂ" not in res.out


def test_a_container_that_dies_just_as_the_wait_expires_is_reported_as_dead(w):
    """Aceeași deosebire la expirare: timpul a trecut, dar containerul a murit între ultima interogare și final. Mesajul trebuie să spună că a
    MURIT, nu să-l lase pe operator să aștepte o migrare care nu mai există."""
    w.set_health("000")
    patch_state(w, exit_after_reads=4, logs="Error: out of memory\n")          # 3 încercări citesc starea, a patra e cea de după expirare
    res = w.up()
    assert res.rc == 1 and "a MURIT între timp" in res.out and "out of memory" in res.out, res.out
    assert "ÎNCĂ RULEAZĂ" not in res.out


# ------------------------------------------------------------------------------------------------------------------------
# down și imaginea trasă
# ------------------------------------------------------------------------------------------------------------------------

def test_down_says_the_pulled_image_stays_and_gives_the_exact_command(w):
    """`up` trage o imagine de ~1,3 GB care rămâne pe gazdă după `down`. Operatorul trebuie să afle asta și să primească comanda EXACTĂ (cu
    versiunea), dar scriptul NU o șterge singur (nicio comandă `image rm` în jurnalul docker)."""
    _staging_trio(w)
    w.load()
    w.state["containers"][STAGE]["image_ref"] = IMAGE_FOR.format("3.0.1")
    w.save()
    res = w.run("down")
    assert res.rc == 0, res.out
    assert "docker image rm docker.n8n.io/n8nio/n8n:3.0.1" in res.out and "RĂMÂNE pe gazdă" in res.out, res.out
    assert not [a for a in w.docker_log() if a[:2] == ["image", "rm"]]


def test_down_with_nothing_to_remove_still_names_the_image_command(w):
    """Chiar dacă n-a mai rămas nimic de șters (containerul a dispărut deja), imaginea trasă poate fi încă pe gazdă: mesajul spune cum se vede
    și cum se scoate."""
    res = w.run("down")
    assert res.rc == 0 and "docker image rm docker.n8n.io/n8nio/n8n:X.Y.Z" in res.out and "RĂMÂNE pe gazdă" in res.out, res.out
