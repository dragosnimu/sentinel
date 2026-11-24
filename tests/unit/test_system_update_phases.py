"""Fazele `backup`, `containers` și firul de detașare din `scripts/lib/system-update-host.sh`,
rulate cu momeli pe PATH (vezi `_su_shell.py` pentru ce NU dovedește mediul ăsta).

Fiecare test numește, în docstring, ce se strică pentru operator dacă codul greșește.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from _su_manifest import write_manifest
from _su_shell import (BASH, HOST_SH, docker_log, docker_state, env_for, host_run, make_bin, posix,
                       run_bash)

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

PG_HEAD = "--\n-- PostgreSQL database cluster dump\n--\n\n\\restrict 8VaY\n\n"
PG_TAIL = "\\unrestrict phQdbcKpc3\n\n--\n-- PostgreSQL database cluster dump complete\n--\n\n"
MARIA_HEAD = "/*M!999999\\- enable the sandbox mode */\n-- MariaDB dump 10.19-11.4.7-MariaDB\n"
MARIA_TAIL = "\n-- Dump completed on 2026-11-19 18:12:24\n"
FILLER = "INSERT INTO t VALUES (1, 'x');\n" * 40

PG_OK = PG_HEAD + FILLER + PG_TAIL
PG_TRUNCATED = PG_HEAD + FILLER[:-30]
MARIA_OK = MARIA_HEAD + FILLER + MARIA_TAIL

OLD_APP, NEW_APP = "sha256:" + "a1" * 32, "sha256:" + "b2" * 32
OLD_PG, NEW_PG = "sha256:" + "c3" * 32, "sha256:" + "d4" * 32
OLD_R, NEW_R = "sha256:" + "e5" * 32, "sha256:" + "f6" * 32


def ctr(name, image, *, state="running", health=None, entry=(), cmd=(), text=None, rc=0, project="", service="",
        image_id="sha256:" + "00" * 32, labels=None):
    lab = {"com.docker.compose.project": project, "com.docker.compose.service": service}
    lab.update(labels or {})
    return {"id": name, "image_id": image_id, "config_image": image, "state": state, "health": health,
            "restart": 0, "started": "2026-11-17T00:00:00Z", "created": "2026-11-17T00:00:00Z",
            "policy": "unless-stopped", "entrypoint": list(entry), "cmd": list(cmd), "labels": lab,
            "exec": None if text is None else {"text": text, "rc": rc}}


def systemctl_shim(active=("postgresql.service", "mariadb.service"), installed=None):
    installed = installed if installed is not None else active
    return (
        'case "$1" in\n'
        "  is-active) shift; q=0; [[ \"${1:-}\" == --quiet ]] && { q=1; shift; }\n"
        f'    case "$1" in {"|".join(active) or "NONE_"}) exit 0;; *) [[ $q == 1 ]] || echo inactive; exit 3;; esac ;;\n'
        "  list-unit-files)\n"
        f'    case "$2" in {"|".join(installed) or "NONE_"}) echo "$2 enabled enabled";; esac; exit 0 ;;\n'
        "  *) echo \"fake systemctl: $*\" >&2; exit 99 ;;\n"
        "esac\n"
    )


def backup_env(tmp: Path, *, srv_age_s: int = 3600, host_pg=PG_OK, host_maria=MARIA_OK,
               active=("postgresql.service", "mariadb.service")):
    state_file = tmp / "last-success"
    state_file.write_text("x", encoding="utf-8")
    t = time.time() - srv_age_s
    os.utime(state_file, (t, t))
    (tmp / "host-pg.sql").write_text(host_pg, encoding="utf-8", newline="\n")
    (tmp / "host-maria.sql").write_text(host_maria, encoding="utf-8", newline="\n")
    extra = {
        "systemctl": systemctl_shim(active=active),
        "runuser": f'cat "{posix(tmp / "host-pg.sql")}"\n',
        "mysqldump": f'cat "{posix(tmp / "host-maria.sql")}"\n',
    }
    bindir = make_bin(tmp, extra, docker=True)
    return bindir, {"SU_SRV_BACKUP_STATE": posix(state_file)}


def run_backup(tmp: Path, containers: dict, **kw):
    bindir, envx = backup_env(tmp, **kw)
    docker_state(tmp, {"images": {}, "containers": containers, "compose": {}})
    proc = host_run(tmp, "PHASE=backup; init_state; phase_backup", bindir, **envx)
    manifest = tmp / "state" / "backup.manifest"
    lines = manifest.read_text(encoding="utf-8").splitlines() if manifest.exists() else []
    rows = {l.split("|")[1]: l.split("|") for l in lines if "|" in l}
    return proc, rows, tmp / "state" / "dumps"


def dump_files(dumps: Path) -> set[str]:
    return {p.name for d in dumps.iterdir() for p in d.iterdir()} if dumps.exists() else set()


def standard_containers():
    return {
        "nis2-db": ctr("nis2-db", "postgres:16-alpine", entry=["docker-entrypoint.sh"], cmd=["postgres"], text=PG_OK),
        "nis2-backup": ctr("nis2-backup", "postgres:16-alpine", entry=["sh", "-c", "while true; do pg_dump | gzip; done"], text="NU TREBUIE CHEMAT"),
        "snipeit-db": ctr("snipeit-db", "mariadb:11.4.7", entry=["docker-entrypoint.sh"], cmd=["mariadbd"], text=MARIA_OK),
        "dms-app-1": ctr("dms-app-1", "dms-app", cmd=["uvicorn", "app:app"]),
    }


def test_backup_verifies_every_dump_and_skips_the_backup_sidecars(tmp_path):
    """Faza de backup dă operatorului ce a promis: un dump COMPLET pentru fiecare bază (containere
    și baza de pe gazdă), cu mărimile la vedere, și nu cere dump unui sidecar (`nis2-backup` are
    imaginea postgres dar nu e server). Dacă un dump bun ar fi raportat eșuat, sau un sidecar
    ar fi dump-uit, faza ar fi roșie de la prima rulare reală."""
    proc, rows, dumps = run_backup(tmp_path, standard_containers())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert {k: v[0] for k, v in rows.items()} == {
        "nis2-db": "ok", "snipeit-db": "ok", "host-postgres": "ok", "host-mariadb": "ok", "nis2-backup": "skip"}
    assert dump_files(dumps) >= {"nis2-db.sql.gz", "snipeit-db.sql.gz", "host-postgres.sql.gz", "host-mariadb.sql.gz", "MANIFEST"}
    assert "nis2-backup.sql.gz" not in dump_files(dumps)
    assert "MiB" in proc.stdout


def test_backup_refuses_a_truncated_dump_even_when_the_command_exited_zero(tmp_path):
    """`docker exec … | gzip` poate ieși cu 0 după un dump tăiat la jumătate (disc plin, conexiune
    căzută). Un backup care crede codul de ieșire ar lăsa operatorul să actualizeze peste o bază
    «salvată» în care lipsește coada. Dump-ul tăiat devine `.INCOMPLETE` (nu rămâne sub numele
    bun), faza e roșie, iar CELELALTE baze se descarcă oricum — operatorul vede toate problemele."""
    c = standard_containers()
    c["nis2-db"]["exec"] = {"text": PG_TRUNCATED, "rc": 0}
    proc, rows, dumps = run_backup(tmp_path, c)
    assert proc.returncode == 1, proc.stdout
    assert rows["nis2-db"][0] == "failed" and "trunchiat" in rows["nis2-db"][4]
    files = dump_files(dumps)
    assert "nis2-db.sql.gz.INCOMPLETE" in files and "nis2-db.sql.gz" not in files
    assert rows["snipeit-db"][0] == "ok" and "snipeit-db.sql.gz" in files


def test_backup_fails_on_nonzero_exit_empty_output_and_a_stopped_database(tmp_path):
    """Trei moduri în care un dump lipsește fără zgomot: comanda iese nenul cu text parțial,
    iese cu 0 fără să tipărească nimic, ori containerul bazei e oprit și nici nu se încearcă.
    Fiecare trebuie să fie un `failed` NUMIT, nu o bază pur și simplu absentă din raport."""
    c = standard_containers()
    c["nis2-db"]["exec"] = {"text": PG_OK, "rc": 1}
    c["snipeit-db"]["exec"] = {"text": "", "rc": 0}
    c["oferte-db-1"] = ctr("oferte-db-1", "postgres:16-alpine", state="exited", entry=["docker-entrypoint.sh"], cmd=["postgres"], text=PG_OK)
    proc, rows, dumps = run_backup(tmp_path, c)
    assert proc.returncode == 1
    assert {n: rows[n][0] for n in ("nis2-db", "snipeit-db", "oferte-db-1")} == {
        "nis2-db": "failed", "snipeit-db": "failed", "oferte-db-1": "failed"}
    assert "oferte-db-1.sql.gz" not in dump_files(dumps)


def test_backup_unclear_database_image_is_a_failure_not_a_skip(tmp_path):
    """O imagine de Postgres cu o comandă proprie nu se poate clasifica; «nu pot decide» tratat
    ca «nu e bază» ar lăsa o bază reală fără dump, tăcut."""
    c = standard_containers()
    c["x-db"] = ctr("x-db", "postgres:16", entry=["/custom-start.sh"], cmd=["run"])
    proc, rows, _ = run_backup(tmp_path, c)
    assert proc.returncode == 1 and rows["x-db"][0] == "failed"


def test_backup_stops_when_the_daily_file_backup_is_stale_unless_told_otherwise(tmp_path):
    """Dump-urile acoperă doar bazele; vaultwarden e SQLite și stă în backup-ul zilnic. Cu acela
    vechi de 30 h, o actualizare ar porni fără nicio copie a seifului de parole."""
    proc, _, _ = run_backup(tmp_path, standard_containers(), srv_age_s=30 * 3600)
    assert proc.returncode == 1 and "backup-ul zilnic" in proc.stdout
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    bindir, envx = backup_env(tmp2, srv_age_s=30 * 3600)
    docker_state(tmp2, {"images": {}, "containers": standard_containers(), "compose": {}})
    proc2 = host_run(tmp2, "PHASE=backup; OPT_STALE_OK=1; init_state; phase_backup", bindir, **envx)
    assert proc2.returncode == 0, proc2.stdout


def test_backup_gate_blocks_a_database_that_appeared_after_the_backup(tmp_path):
    """Un backup făcut ieri nu acoperă baza pornită azi. Poarta fazelor `os`/`containers` cere
    dump pentru FIECARE bază care există acum; altfel ai recrea un container de bază de date
    fără nicio copie a ei."""
    proc, _, _ = run_backup(tmp_path, standard_containers())
    assert proc.returncode == 0
    c = standard_containers()
    c["new-db"] = ctr("new-db", "postgres:16-alpine", entry=["docker-entrypoint.sh"], cmd=["postgres"], text=PG_OK)
    docker_state(tmp_path, {"images": {}, "containers": c, "compose": {}})
    bindir = tmp_path / "bin"
    proc2 = host_run(tmp_path, "PHASE=os; init_state; require_backup_gate", bindir)
    assert proc2.returncode == 1 and "missing:new-db" in proc2.stdout
    proc3 = host_run(tmp_path, "PHASE=os; init_state; require_backup_gate", bindir, SU_BACKUP_MAX_AGE_S="0")
    assert proc3.returncode == 1 and "stale" in proc3.stdout


# ---------------------------------------------------------------------------
# containers
# ---------------------------------------------------------------------------
def containers_fixture(tmp: Path, *, ctx_clean: bool, tag_moved: bool = False, pull=None, build=None,
                       up_effect="recreate", extra_images=None, no_image=False, pg_label_hash="H-db", flap=None, app_label_hash="H-app", two_pull=False):
    """Două proiecte: `clin` (aplicație construită local) și `pg` (imagine din registru)."""
    ctx = tmp / "ctx"
    ctx.mkdir()
    (ctx / "app.py").write_text("print(1)\n", encoding="utf-8")
    for p in ("clin.yml", "pg.yml"):
        (tmp / p).write_text("services: {}\n", encoding="utf-8")
    created = "2099-01-01T00:00:00Z" if ctx_clean else "2026-01-01T00:00:00Z"
    app_ref = "clin-app" if no_image else "clin-app:latest"   # fără `image:`, compose numește imaginea <proiect>-<serviciu>
    images = {
        app_ref: {"id": OLD_APP, "created": created, "digests": 0},
        "postgres:16-alpine": {"id": NEW_PG if tag_moved else OLD_PG, "created": "2026-10-01T00:00:00Z", "digests": 2},
    }
    images.update(extra_images or {})
    lab = lambda p, s, f: {"com.docker.compose.project": p, "com.docker.compose.service": s,
                           "com.docker.compose.project.working_dir": posix(tmp), "com.docker.compose.project.config_files": posix(tmp / f),
                           "com.docker.compose.config-hash": "H-" + s}
    containers = {
        "clin-app": ctr("clin-app", app_ref, health="healthy", project="clin", service="app", image_id=OLD_APP, labels={**lab("clin", "app", "clin.yml"), "com.docker.compose.config-hash": app_label_hash}),
        "pg-db": ctr("pg-db", "postgres:16-alpine", entry=["docker-entrypoint.sh"], cmd=["postgres"], health="healthy", project="pg", service="db", image_id=OLD_PG, labels={**lab("pg", "db", "pg.yml"), "com.docker.compose.config-hash": pg_label_hash}),
    }
    if two_pull:      # un al doilea serviciu din `pg`, cu imagine din registru (redis), pentru «un pull eșuat oprește proiectul»
        images["redis:7"] = {"id": OLD_R, "created": "2026-10-01T00:00:00Z", "digests": 1}
        containers["pg-db2"] = ctr("pg-db2", "redis:7", health="healthy", project="pg", service="db2", image_id=OLD_R,
                                   labels={**lab("pg", "db2", "pg.yml"), "com.docker.compose.config-hash": "H-db2"})
    state = {
        "images": images, "containers": containers,
        "compose": {
            "clin": {"config": {"services": {"app": ({} if no_image else {"image": "clin-app:latest"}) | {"build": {"context": posix(ctx)}}}}, "hashes": {"app": "H-app"}},
            "pg": {"config": {"services": {"db": {"image": "postgres:16-alpine"}, **({"db2": {"image": "redis:7"}} if two_pull else {})}},
                   "hashes": {"db": "H-db", "db2": "H-db2"}},
        },
        "build_effect": build or {}, "pull_effect": pull or {}, "up_effect": {"app": up_effect, "db": up_effect, "db2": up_effect},
        "flap_restart": flap or [],
    }
    docker_state(tmp, state)
    base = tmp / "state" / "snapshots" / "B"
    base.mkdir(parents=True)
    tag_pg = NEW_PG if tag_moved else OLD_PG
    (base / "containers.tsv").write_text(
        f"clin-app|clin|app|{app_ref}|{OLD_APP}|{OLD_APP}|running|healthy|unless-stopped|0|2026-11-17T00:00:00Z\n"
        f"pg-db|pg|db|postgres:16-alpine|{OLD_PG}|{tag_pg}|running|healthy|unless-stopped|0|2026-11-17T00:00:00Z\n",
        encoding="utf-8", newline="\n")
    if two_pull:
        with open(base / "containers.tsv", "a", encoding="utf-8", newline="\n") as fh:
            fh.write(f"pg-db2|pg|db2|redis:7|{OLD_R}|{OLD_R}|running|healthy|unless-stopped|0|2026-11-17T00:00:00Z" + chr(10))
    (base / "COMPLETE").write_text("", encoding="utf-8")
    write_manifest(tmp, [("ok", "pg-db", "postgres")])
    return base


def run_containers(tmp: Path, base: Path, opts: str = ""):
    bindir = make_bin(tmp, {"systemctl": systemctl_shim(active=(), installed=())}, docker=True)
    body = f"PHASE=containers; init_state; BASE='{posix(base)}'; {opts + ';' if opts else ''} phase_containers"
    return host_run(tmp, body, bindir, SU_MIN_FREE_GB="0")


def verbs(tmp: Path) -> list[str]:
    out = []
    for argv in docker_log(tmp):
        if argv[0] == "compose":
            i = 1
            while argv[i] in ("-p", "--project-directory", "-f"):
                i += 2
            out.append("compose " + argv[i])
        else:
            out.append(argv[0] + (" " + argv[1] if argv[0] == "image" else ""))
    return out


MUTATING = {"tag", "pull", "compose build", "compose up"}


def test_dry_run_changes_nothing_and_says_why_a_build_is_refused(tmp_path):
    """`containers --dry-run` e fereastra prin care operatorul vede ce s-ar întâmpla ÎNAINTE să
    pornească ceva. Dacă ar trage o imagine, ar muta o etichetă (iar planul de a doua zi ar
    arăta «etichetă mutată» pentru tot) — deci jurnalul de docker nu are voie să conțină nicio
    comandă care schimbă ceva. Și trebuie să spună DE CE codul de pe disc nu se reconstruiește."""
    base = containers_fixture(tmp_path, ctx_clean=False)
    proc = run_containers(tmp_path, base, "OPT_DRY_RUN=1; OPT_REBUILD=all")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (set(verbs(tmp_path)) & MUTATING), verbs(tmp_path)
    assert "skip-drift" in proc.stdout and "app.py" in proc.stdout and "--accept-drift clin" in proc.stdout
    assert "pull postgres:16-alpine" in proc.stdout


def test_rebuild_is_opt_in_and_never_the_default(tmp_path):
    """Fără --rebuild, aplicațiile proprii nu se ating nici când contextul e curat: ce rulează
    nu se schimbă dintr-un motiv pe care operatorul nu l-a cerut."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    proc = run_containers(tmp_path, base)
    assert proc.returncode == 0, proc.stdout
    assert "skip-not-requested" in proc.stdout
    assert "compose build" not in verbs(tmp_path)


def test_recreate_targets_named_services_and_proves_the_new_image_is_running(tmp_path):
    """`up -d` pe tot proiectul ar recrea și serviciile cărora nu le-am cerut nimic (cele cu
    eticheta mutată). Recrearea e doar pe serviciile numite, după un rollback-tag, iar succesul
    se judecă din ID-ul de imagine al containerului, nu din codul lui compose."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    log = docker_log(tmp_path)
    ups = [a for a in log if a[0] == "compose" and "up" in a]
    assert ups and all(a[-1] in ("app", "db") and "--no-deps" in a and "--no-build" in a for a in ups)
    order = verbs(tmp_path)
    # rollback-tag-ul vine DUPĂ build (un build eșuat nu atinge nimic) și ÎNAINTE de `up`
    assert order.index("compose build") < order.index("tag") < order.index("compose up")
    assert any(a[:1] == ["tag"] and a[2] == "rollback/maint-b/clin-app:prev" for a in log)
    assert "healthy, stabil 0s" in proc.stdout
    report = (base / "containers.report").read_text(encoding="utf-8")
    assert "clin|app|recreated" in report and "pg|db|recreated" in report


def test_a_compose_up_that_exits_zero_but_recreates_nothing_is_a_failure(tmp_path):
    """Exact tiparul `systemctl enable --now` pe un serviciu deja pornit: operație nulă, cod 0,
    procesul rulează codul vechi. Containerul care rulează încă ID-ul vechi de imagine NU
    e «actualizat», oricât ar spune compose."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}}, up_effect="noop")
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin")
    assert proc.returncode == 1, proc.stdout
    assert "recrearea NU a avut loc" in proc.stdout
    assert "rollback: docker tag rollback/maint-b/clin-app:prev" in proc.stdout


def test_a_failed_build_leaves_every_container_untouched_and_says_so(tmp_path):
    """Dacă `build --pull` cade (registru, Dockerfile stricat), containerul vechi trebuie să
    rămână cum era; faza dovedește asta (ID-urile de imagine = baseline), nu o presupune."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 1, "new_id": None}})
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin")
    assert proc.returncode == 1
    assert "compose up" not in verbs(tmp_path)
    assert "rulează neschimbate" in proc.stdout


def test_moved_tag_is_held_and_never_pulled_or_recreated(tmp_path):
    """Cazul snipeit-app-1: eticheta arată altă imagine decât cea care rulează. A trage și a
    recrea ar sări peste versiunile dintre ele; serviciul e SĂRIT cu motivul scris."""
    base = containers_fixture(tmp_path, ctx_clean=True, tag_moved=True)
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert proc.returncode == 0, proc.stdout
    assert "hold-moved-tag" in proc.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)
    assert "pg|db|hold-moved-tag" in (base / "containers.report").read_text(encoding="utf-8")


def test_local_only_image_is_skipped_with_a_reason(tmp_path):
    """cryptoitdata-hub:latest n-a venit dintr-un registru: `docker pull` l-ar căuta pe Docker
    Hub sub un nume pe care îl poate publica oricine."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    state = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    state["images"]["postgres:16-alpine"]["digests"] = 0
    docker_state(tmp_path, state)
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert "skip-local" in proc.stdout and "pull" not in verbs(tmp_path)


def test_failed_pull_is_not_reported_as_up_to_date(tmp_path):
    """Registru inaccesibil: `docker pull` iese nenul și nu schimbă nimic. «Imaginea locală e
    cea care rulează» nu înseamnă «la zi» — n-am aflat. Operatorul ar crede patch-ul aplicat."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert proc.returncode == 1, proc.stdout
    assert "NU declar" in proc.stdout and "e la zi" not in proc.stdout
    assert "compose up" not in verbs(tmp_path)


def test_pull_with_nothing_new_recreates_nothing(tmp_path):
    """Imaginea trasă e cea care rulează deja: nu se recreează nimic (nicio întrerupere
    degeaba), iar rezultatul e `la zi` DOVEDIT prin ID, nu presupus."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert proc.returncode == 0 and "e la zi" in proc.stdout
    assert "compose up" not in verbs(tmp_path)


def test_accepted_drift_builds_and_says_it_is_building_unreviewed_code(tmp_path):
    """`--accept-drift clin` e decizia operatorului că a citit codul de pe disc; build-ul pornește,
    dar cu avertisment explicit, ca raportul să arate că ce s-a livrat nu e ce rula."""
    base = containers_fixture(tmp_path, ctx_clean=False, build={"app": {"rc": 0, "new_id": NEW_APP}})
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin; OPT_ACCEPT_DRIFT=clin; OPT_ONLY=clin")
    assert proc.returncode == 0, proc.stdout
    assert "acceptat de operator" in proc.stdout and "compose build" in verbs(tmp_path)


# ---------------------------------------------------------------------------
# argumente, baseline, detașare
# ---------------------------------------------------------------------------
def _host(tmp_path: Path, *args: str, env_extra=None):
    bindir = make_bin(tmp_path, {}, docker=True)
    (tmp_path / "state").mkdir(exist_ok=True)
    env = env_for(tmp_path, bindir, **(env_extra or {}))
    return subprocess.run([BASH, posix(HOST_SH), *args], capture_output=True, env=env, timeout=60)


def test_accept_drift_refuses_all_and_unknown_flags_are_refused_before_touching_anything(tmp_path):
    """«Accept tot codul necitit de nimeni» nu încape într-un cuvânt; un `--accept-drift all`
    scris din reflex ar anula tocmai poarta. Un steag necunoscut (sau al altei faze) iese cu 2,
    nu e ignorat: un steag ignorat e o decizie pe care operatorul crede că a luat-o."""
    p = _host(tmp_path, "containers", "--accept-drift", "all")
    assert p.returncode == 2 and b"all" in p.stderr
    assert _host(tmp_path, "os", "--rebuild", "x").returncode == 2
    assert _host(tmp_path, "verify", "--gap", "abc").returncode == 2
    assert _host(tmp_path, "nu-exista").returncode == 2
    assert docker_log(tmp_path) == []


@pytest.mark.parametrize("opt", ["--rebuild", "--accept-drift", "--only", "--retry-failed"])
def test_a_list_option_refuses_another_option_as_its_value_before_touching_anything(tmp_path, opt):
    """`containers --rebuild --dry-run` se parsa ca --rebuild cu valoarea `--dry-run` și OPT_DRY_RUN=0: o simulare scrisă
    greșit devenea o rulare în serios. Valoarea unei liste nu poate începe cu `-`: ieșire 2, mesaj numit, niciun
    docker, nicio stare creată."""
    p = _host(tmp_path, "containers", opt, "--dry-run")
    assert p.returncode == 2 and "nu o altă opțiune" in p.stderr.decode("utf-8", "replace") and opt.encode() in p.stderr, p.stderr
    assert docker_log(tmp_path) == [] and not (tmp_path / "state" / "snapshots").exists()
    q = _host(tmp_path, "containers", opt, "-x")
    assert q.returncode == 2, q.stderr


def test_a_second_preflight_cannot_overwrite_a_baseline_that_has_changes_on_top(tmp_path):
    """Un preflight rulat din reflex DUPĂ `os` ar înlocui baseline-ul cu starea de după; verify
    ar compara apoi starea cu ea însăși și ar raporta «totul la fel». `.started` (nu `.ok`):
    o fază eșuată la jumătate a schimbat deja ceva."""
    base = tmp_path / "base"
    (base / "phases").mkdir(parents=True)
    bindir = make_bin(tmp_path, {})
    clean = host_run(tmp_path, f"BASE='{posix(base)}'; baseline_overwrite_markers", bindir)
    assert clean.stdout.strip() == ""
    (base / "phases" / "os.started").write_text("x", encoding="utf-8")
    (base / "phases" / "reboot.requested").write_text("x", encoding="utf-8")
    dirty = host_run(tmp_path, f"BASE='{posix(base)}'; baseline_overwrite_markers", bindir)
    assert dirty.stdout.split() == ["os.started", "reboot.requested"]
    (base / "phases" / "os.started").unlink()
    (base / "phases" / "os.ok").write_text("x", encoding="utf-8")
    only_ok = host_run(tmp_path, f"BASE='{posix(base)}'; baseline_overwrite_markers", bindir)
    assert only_ok.stdout.split() == ["reboot.requested"]
    # o rulare PARȚIALĂ a fazei containers (--only) schimbă și ea gazda: markerul ei trebuie să protejeze baseline-ul la fel ca `containers.started`
    (base / "phases" / "reboot.requested").unlink()
    (base / "phases" / "containers.only.started").write_text("x", encoding="utf-8")
    partial = host_run(tmp_path, f"BASE='{posix(base)}'; baseline_overwrite_markers", bindir)
    assert partial.stdout.split() == ["containers.only.started"], partial.stdout


def _fake_systemd_run(tmp_path: Path, mode: str) -> dict:
    body = (
        'echo "$@" >> "$FAKE_SR_LOG"\n'
        'unit=""; log=""; rid=""; st=""\n'
        'while [[ $# -gt 0 ]]; do case "$1" in\n'
        '  --unit) unit="$2"; shift 2;; --setenv=SU_RUN_ID=*) rid="${1#--setenv=SU_RUN_ID=}"; shift;; --setenv=SU_STATE=*) st="${1#--setenv=SU_STATE=}"; shift;;\n'
        '  -p) [[ "$2" == StandardOutput=append:* ]] && log="${2#StandardOutput=append:}"; shift 2;;\n'
        '  --collect|--quiet|--setenv=*|--working-directory=*) shift;; *) break;; esac; done\n'
        'case "$FAKE_SR_MODE" in\n'
        '  real) SU_DETACHED=1 SU_RUN_ID="$rid" SU_STATE="$st" "$@" >> "$log" 2>&1 || true ;;\n'
        '  rc3) echo "[?] ceva necunoscut" >> "$log"; printf "phase=os\\nrc=3\\nstatus=unknown\\n" > "$st/runs/os-$rid.result" ;;\n'
        '  noresult) echo "pornit si mort" >> "$log" ;;\n'
        '  badrc) printf "phase=os\\nrc=banana\\n" > "$st/runs/os-$rid.result" ;;\n'
        'esac\nexit 0\n'
    )
    return {"systemd-run": body, "systemctl": 'case "$1 $2 $3" in "show -p ActiveState") echo inactive;; *) exit 99;; esac\n'}


def _detached(tmp_path: Path, mode: str):
    bindir = make_bin(tmp_path, _fake_systemd_run(tmp_path, mode), docker=True)
    (tmp_path / "state").mkdir(exist_ok=True)
    env = env_for(tmp_path, bindir, FAKE_SR_MODE=mode, FAKE_SR_LOG=posix(tmp_path / "sr.log"))
    proc = subprocess.run([BASH, posix(HOST_SH), "os"], capture_output=True, env=env, timeout=60)
    return proc, proc.stdout.decode("utf-8", "replace"), (tmp_path / "sr.log").read_text(encoding="utf-8") if (tmp_path / "sr.log").exists() else ""


def test_detached_phase_follows_a_log_file_not_a_pipe_and_returns_the_recorded_code(tmp_path):
    """Dacă sesiunea ssh cade în mijlocul `dnf upgrade`, o conductă ruptă dă SIGPIPE tranzacției
    rpm și lasă baza de pachete la jumătate. Unitatea trebuie să scrie într-un FIȘIER (nu
    `--pipe`/`--wait`), iar sesiunea să returneze codul din fișierul de rezultat — aici, `os` fără
    baseline moare cu motivul în jurnal și cu cod 1."""
    proc, out, sr = _detached(tmp_path, "real")
    assert proc.returncode == 1, out
    assert "StandardOutput=append:" in sr and "--pipe" not in sr and "--wait" not in sr
    assert "/usr/bin/bash" in sr
    assert "nu există un baseline complet" in out


def test_detached_phase_reports_unknown_when_the_unit_ends_without_a_result(tmp_path):
    """O unitate ucisă (OOM, kill -9) nu scrie niciun rezultat. Tăcerea nu e «reușit»: firul
    din sesiune iese cu 3 și spune că starea e NECUNOSCUTĂ."""
    proc, out, _ = _detached(tmp_path, "noresult")
    assert proc.returncode == 3 and "FĂRĂ să scrie un rezultat" in out and "pornit si mort" in out


def test_detached_phase_propagates_the_unknown_code_and_rejects_an_unreadable_result(tmp_path):
    """Codul 3 al fazei trebuie să ajungă la operator ca 3, nu ca 0 sau 1; un fișier de rezultat
    cu un cod necitibil e tot «necunoscut»."""
    proc, out, _ = _detached(tmp_path, "rc3")
    assert proc.returncode == 3 and "ceva necunoscut" in out
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    proc2, out2, _ = _detached(tmp2, "badrc")
    assert proc2.returncode == 3 and "cod citibil" in out2


# ---------------------------------------------------------------------------
# runda 2: servicii fără `image:`, rulare repetată, dovezile care lipseau
# ---------------------------------------------------------------------------
def test_rebuild_builds_a_service_that_has_no_image_key(tmp_path):
    """8 servicii de pe gazdă au `build:` și nu au `image:` (bet-deploy, dms, nis2, omnishop,
    procure360). Parsarea cu tab ca delimitator prăbușea câmpul gol: contextul ajungea în câmpul
    imaginii, serviciul părea «fără build», `--rebuild` nu făcea nimic și faza ieșea «totul dovedit».
    Aici serviciul fără `image:` trebuie reconstruit și recreat de-adevărat."""
    base = containers_fixture(tmp_path, ctx_clean=True, no_image=True, build={"app": {"rc": 0, "new_id": NEW_APP}})
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "compose build" in verbs(tmp_path) and "healthy, stabil 0s" in proc.stdout
    assert "skip-not-requested" not in proc.stdout


def test_rerunning_containers_after_success_is_a_proven_noop(tmp_path):
    """Aceeași baseline, a doua rulare (după un eșec într-un alt proiect, de pildă). Containerele deja
    actualizate rulează alt ID decât în baseline: decizia luată din baseline cerea o recreare fără
    efect, `up` era operație nulă, verificarea «creat după începutul rulării» declara eșec pe un
    container sănătos, tipărea un rollback pentru el și se oprea. Și eticheta de rollback ajungea să
    arate imaginea NOUĂ, adică originalul se pierdea. Acum: nimic de recreat, rollback-ul neatins,
    raportul păstrează ce s-a făcut prima dată."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    first = run_containers(tmp_path, base, "OPT_REBUILD=clin")
    assert first.returncode == 0, first.stdout
    ups_before = [a for a in docker_log(tmp_path) if a[0] == "compose" and "up" in a]
    assert len(ups_before) == 2
    second = run_containers(tmp_path, base, "OPT_REBUILD=clin")
    assert second.returncode == 0, second.stdout + second.stderr
    assert len([a for a in docker_log(tmp_path) if a[0] == "compose" and "up" in a]) == 2      # niciun `up` nou
    assert "mai vechi decât" not in second.stdout and "rollback:" not in second.stdout
    state = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    assert state["images"]["rollback/maint-b/clin-app:prev"]["id"] == OLD_APP
    assert state["images"]["rollback/maint-b/pg-db:prev"]["id"] == OLD_PG
    report = (base / "containers.report").read_text(encoding="utf-8")
    assert "clin|app|recreated" in report and "pg|db|recreated" in report and "verified" in report


def test_a_container_that_was_not_recreated_now_is_a_failure_even_with_the_new_image_id(tmp_path):
    """Imaginea nouă poate apărea în `docker inspect` fără ca containerul să fie recreat de acest `up`
    (recreat de altcineva mai devreme). «Creat după începutul rulării» e a doua dovadă, independentă de
    ID-ul de imagine: fără ea, o recreare care n-a avut loc acum s-ar număra drept reușită."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}}, up_effect="recreate_old_created")
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert proc.returncode == 1 and "mai vechi decât această rulare" in proc.stdout


def test_a_container_that_restarts_between_two_samples_is_not_stable(tmp_path):
    """Un container recreat care intră în buclă de repornire trece prin `running` și `healthy` la
    fiecare ciclu: o verificare făcută o dată îl declară sănătos. Al doilea eșantion (același număr de
    reporniri) e ce îl prinde."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}}, flap=["clin-app"])
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert proc.returncode == 1 and "flapping" in proc.stdout


def test_containers_refuses_to_start_without_a_fresh_backup(tmp_path):
    """Poarta de backup: fără un backup recent al bazelor, `containers` nu atinge nimic (jurnalul de
    docker n-are nicio comandă care schimbă ceva). O poartă deconectată ar recrea containere de baze
    de date fără nicio copie a datelor."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    (tmp_path / "state" / "backup.manifest").unlink()
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert proc.returncode == 1 and "no-manifest" in proc.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)
    assert not (base / "phases" / "containers.started").exists()


@pytest.mark.parametrize("label_hash, fragment", [("OLD-HASH", "configurația compose a serviciului s-a schimbat"),
                                                  ("", "configurația compose a serviciului s-a schimbat")])
def test_a_changed_or_unreadable_compose_config_holds_the_service(tmp_path, label_hash, fragment):
    """`up` aplică și fișierul compose editat de la crearea containerului: o schimbare nerevizuită ar
    ajunge în producție odată cu imaginea. Un hash care nu se poate compara (eticheta lipsește) NU e «n-a
    schimbat»: tot reținut, cu `--accept-drift` ca ieșire deliberată, numită pe proiect."""
    base = containers_fixture(tmp_path, ctx_clean=True, pg_label_hash=label_hash,
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    proc = run_containers(tmp_path, base, "OPT_ONLY=pg")
    assert proc.returncode == 0 and "hold-config-drift" in proc.stdout and fragment in proc.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    base2 = containers_fixture(tmp2, ctx_clean=True, pg_label_hash=label_hash, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    proc2 = run_containers(tmp2, base2, "OPT_ONLY=pg; OPT_ACCEPT_DRIFT=pg")
    assert proc2.returncode == 0 and "compose up" in verbs(tmp2)


def test_a_changed_compose_config_makes_a_build_drift(tmp_path):
    """Aceeași regulă pentru aplicațiile construite: fișierul compose schimbat face contextul «drift»
    chiar dacă sursa e curată."""
    base = containers_fixture(tmp_path, ctx_clean=True, app_label_hash="OLD-HASH", build={"app": {"rc": 0, "new_id": NEW_APP}})
    proc = run_containers(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert "skip-drift" in proc.stdout and "compose build" not in verbs(tmp_path)


# ---------------------------------------------------------------------------
# runda 5: follow_run nu socotește o citire goală a stării drept «unitate încheiată»
# ---------------------------------------------------------------------------
SEQ_SYSTEMCTL = (
    'f="$FAKE_SEQ"; c="$f.n"; n=0; [[ -f "$c" ]] && n="$(cat "$c")"; n=$((n + 1)); echo "$n" > "$c"\n'
    'line="$(sed -n "${n}p" "$f")"; [[ -n "$line" ]] || line="$(tail -n 1 "$f")"\n'
    'case "$line" in\n'
    '  ERR) exit 1 ;;\n'                                     # systemctl nu răspunde (daemon-reexec)
    '  EMPTY) exit 0 ;;\n'                                   # răspunde cu nimic
    '  DONE) printf "rc=0\n" > "$FAKE_RESULT"; echo active ;;\n'      # unitatea scrie rezultatul și încă apare activă
    '  *) echo "$line" ;;\n'
    'esac\n'
)


def _follow(tmp_path: Path, seq: list[str], **env):
    bindir = make_bin(tmp_path, {"systemctl": SEQ_SYSTEMCTL}, docker=True)
    (tmp_path / "seq").write_text("\n".join(seq) + "\n", encoding="utf-8", newline="\n")
    (tmp_path / "unit.log").write_text("", encoding="utf-8")
    result = tmp_path / "unit.result"
    body = (f"follow_run u.service '{posix(tmp_path / 'unit.log')}' '{posix(result)}' && rc=0 || rc=$?; "
            f"echo \"RC=$rc\"; echo \"CALLS=$(cat '{posix(tmp_path / 'seq.n')}')\"")
    t0 = time.time()
    proc = host_run(tmp_path, body, bindir, FAKE_SEQ=posix(tmp_path / "seq"), FAKE_RESULT=posix(result),
                    SU_FOLLOW_CONFIRM_S="0", **env)
    return proc.stdout, time.time() - t0


def test_follow_run_waits_through_an_empty_or_failed_state_read_while_the_unit_is_active(tmp_path):
    """Pe gazda reală, scriptletul pachetului systemd a rulat `systemctl daemon-reexec` în mijlocul tranzacției
    dnf: `systemctl show -p ActiveState` a întors gol/eroare o clipă, bucla a socotit unitatea încheiată,
    a tipărit «s-a încheiat FĂRĂ să scrie un rezultat» și a ieșit 3 peste o actualizare care a terminat apoi
    cu 0. O citire goală sau eșuată înseamnă «necitit», adică se așteaptă."""
    out, _ = _follow(tmp_path, ["active", "EMPTY", "ERR", "ERR", "active", "DONE"])
    assert "RC=0" in out and "[?]" not in out and "CALLS=6" in out, out


def test_follow_run_does_not_end_the_unit_on_a_single_inactive_read(tmp_path):
    """În fereastra reexec-ului systemd poate răspunde o clipă `inactive` pentru o unitate vie. O singură
    citire nu încheie unitatea: trebuie două la rând; una izolată e urmată de «activ» și așteptarea continuă."""
    out, _ = _follow(tmp_path, ["active", "inactive", "active", "failed", "active", "DONE"])
    assert "RC=0" in out and "[?]" not in out and "CALLS=6" in out, out


def test_follow_run_still_reports_unknown_when_the_unit_really_ended_without_a_result(tmp_path):
    """Pragul nou nu are voie să ascundă o unitate ucisă (OOM, kill -9): două citiri `inactive`/`failed` la rând
    și niciun rezultat => ieșire 3 («necunoscut», nu «reușit»)."""
    for i, seq in enumerate((["active", "inactive", "inactive"], ["active", "failed", "inactive"])):
        sub = tmp_path / f"s{i}"
        sub.mkdir()
        out, _ = _follow(sub, seq)
        assert "RC=3" in out and "FĂRĂ să scrie un rezultat" in out, (seq, out)


def test_follow_run_keeps_waiting_while_the_unit_is_deactivating(tmp_path):
    """`deactivating` = procesul iese acum, iar trap-ul lui EXIT scrie `.result`: unitatea nu e încheiată.
    Cât timp nu apare, sesiunea nu declară nimic."""
    out, _ = _follow(tmp_path, ["active", "deactivating", "deactivating", "DONE"], SU_FOLLOW_UNREADABLE_S="0")    # 0: «necitit» ar ceda imediat
    assert "RC=0" in out and "[?]" not in out, out


def test_follow_run_gives_up_as_unknown_after_a_bounded_unreadable_wait(tmp_path):
    """Dacă unitatea dispare iar `systemctl` nu mai răspunde niciodată, sesiunea nu stă la nesfârșit și nici nu
    pretinde că unitatea s-a încheiat: după SU_FOLLOW_UNREADABLE_S secunde de stare necitibilă iese 3, cu
    un mesaj care spune că starea nu poate fi citită (nu «a scris fără rezultat»)."""
    out, took = _follow(tmp_path, ["EMPTY"], SU_FOLLOW_S="1", SU_FOLLOW_UNREADABLE_S="2")
    assert "RC=3" in out and "nu pot citi starea unității" in out and "FĂRĂ să scrie" not in out, out
    assert 1.5 <= took < 30, took


def test_follow_run_bounds_alternating_inactive_and_unreadable_reads(tmp_path):
    """Citiri care alternează `inactive` și goale își resetau reciproc contoarele (două `inactive` la rând nu apăreau niciodată,
    iar fereastra «necitit» se închidea la fiecare `inactive`): sesiunea ssh stătea la nesfârșit peste o unitate dispărută,
    fără să spună nimic. Fereastra e una, măsurată de la prima citire care nu e «activă»: după SU_FOLLOW_UNREADABLE_S iese 3."""
    out, took = _follow(tmp_path, ["active"] + ["inactive", "EMPTY"] * 20, SU_FOLLOW_S="1", SU_FOLLOW_UNREADABLE_S="2")
    # Două mesaje la fel de corecte, după CITIREA pe care trece fereastra de 2 s (măsurată în secunde întregi): ramura `inactive` («nu a revenit la») sau
    # ramura necitit («nu pot citi starea»). Testul pretindea una (rezultat de ceas, ~1 din 5 rulări pica); contează codul 3, o stare numită NECUNOSCUTĂ
    # (nu «reușit») și lipsa mesajului «a scris fără rezultat», pe care o unitate care alternează nu l-a confirmat de două ori.
    assert "RC=3" in out and "NECUNOSCUTĂ" in out and ("nu a revenit la" in out or "nu pot citi starea unității" in out) and "FĂRĂ să scrie" not in out, out
    calls = int(out.split("CALLS=")[1].split()[0])
    assert calls <= 12 and took < 15, (calls, took)


def test_follow_run_forgets_an_earlier_blip_once_the_unit_is_read_active_again(tmp_path):
    """Două clipiri `inactive` despărțite de citiri «active» nu fac o unitate dispărută: fereastra «necitit» se închide la o citire activă și
    se deschide din nou la următoarea clipire. Fără resetare (`unread_since=0` la o citire activă), clipirea a doua era măsurată de la prima,
    trecea de SU_FOLLOW_UNREADABLE_S și sesiunea declara «NECUNOSCUT» (cod 3) peste o actualizare dnf care mergea, cu unitatea activă
    între clipiri, și termina cu 0."""
    out, took = _follow(tmp_path, ["active", "inactive", "active", "active", "active", "inactive", "DONE"],
                        SU_FOLLOW_S="1", SU_FOLLOW_UNREADABLE_S="2")
    assert "RC=0" in out and "[?]" not in out and "CALLS=7" in out, out
    assert took >= 3, took           # citirile active au consumat cu adevărat mai mult decât fereastra: controlul că testul poate cădea
