"""Faza `containers` ca VERDICT despre starea de acum, nu ca jurnal de acțiuni (runda 3).

Rulează `scripts/lib/system-update-containers.sh` cu momeala de docker (`_fake_docker.py`; vezi
`_su_shell.py` pentru ce NU dovedește). Fiecare test numește ce se strică pentru operator.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from _su_shell import LIB_SH, docker_log, host_run, make_bin, posix, run_bash
from test_system_update_phases import (MUTATING, NEW_APP, NEW_PG, NEW_R, OLD_APP, OLD_PG, OLD_R, containers_fixture,
                                       systemctl_shim, verbs)

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")


def run_c(tmp: Path, base: Path, opts: str = "", **env: str):
    bindir = make_bin(tmp, {"systemctl": systemctl_shim(active=(), installed=())}, docker=True)
    body = f"PHASE=containers; init_state; BASE='{posix(base)}'; {opts + ';' if opts else ''} phase_containers"
    return host_run(tmp, body, bindir, **{"SU_MIN_FREE_GB": "0", **env})


def set_state(tmp: Path, **changes) -> None:
    p = tmp / "docker-state.json"
    st = json.loads(p.read_text(encoding="utf-8"))
    st.update(changes)
    p.write_text(json.dumps(st), encoding="utf-8")


def ok_marker(base: Path) -> bool:
    return (base / "phases" / "containers.ok").exists()


STICKY = {"failed", "build-failed", "pull-failed", "tag-failed", "unread"}


def unresolved(base: Path) -> list[str]:
    """Serviciile rămase într-o stare lipicioasă (reducerea su_report_final). Rulările cu `--only` nu scriu containers.ok
    (N6), deci «s-a rezolvat» se citește din rezultatul final, nu din marker."""
    proc = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(base / 'containers.report')}'")
    assert proc.returncode == 0, proc.stderr
    return [l for l in proc.stdout.splitlines() if l.split("|")[1] in STICKY]


def test_a_rerun_does_not_turn_a_failed_service_into_up_to_date(tmp_path):
    """Rularea 1 recreează pg-db, el intră în buclă de repornire, ieșire 1. Rularea 2, fără nicio
    reparație: imaginea trasă e cea care rulează deja, deci serviciul părea «la zi», `check_container`
    nu mai rula, rezumatul lăsa `up-to-date` să șteargă `failed`, iar faza ieșea «TOTUL DOVEDIT» și scria
    containers.ok peste un container care se repornește. Acum rezultatul e o verdict pe starea CURENTĂ a
    fiecărui serviciu atins: se re-verifică sănătatea și stabilitatea, iar doar o verificare nouă,
    reușită, înlocuiește eșecul."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}}, flap=["pg-db"])
    first = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert first.returncode == 1 and "flapping" in first.stdout, first.stdout
    second = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert second.returncode == 1, second.stdout
    assert "e la zi" not in second.stdout and "TOTUL DOVEDIT" not in second.stdout
    assert "--retry-failed pg" in second.stdout          # runda 4: neatins, cere reîncercare explicită
    retried = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")      # încă stricat: re-verificarea îl prinde
    assert retried.returncode == 1 and "re-verific starea" in retried.stdout and "flapping" in retried.stdout, retried.stdout
    set_state(tmp_path, flap_restart=[])            # reparat
    third = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert third.returncode == 0, third.stdout
    assert "pg|db|verified" in (base / "containers.report").read_text(encoding="utf-8")
    assert not unresolved(base)


def test_an_unhealthy_recreate_is_not_forgiven_by_a_rerun_either(tmp_path):
    """Același tipar pentru sănătate: după recreare healthcheck-ul pică (baseline: healthy). La a doua
    rulare containerul rulează deja imaginea nouă — «la zi» — dar e unhealthy. Verdictul trebuie să rămână
    roșu până când starea CURENTĂ se vindecă."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    first = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert first.returncode == 1 and "verdict worse" in first.stdout, first.stdout
    second = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert second.returncode == 1 and "e la zi" not in second.stdout, second.stdout
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    st["containers"]["pg-db"]["health"] = "healthy"
    (tmp_path / "docker-state.json").write_text(json.dumps(st), encoding="utf-8")
    third = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert third.returncode == 0 and not unresolved(base), third.stdout


def test_a_failed_outcome_in_an_untouched_project_still_blocks_containers_ok(tmp_path):
    """Un `failed` de la o rulare anterioară, într-un proiect pe care rularea de acum nu-l procesează
    (--only alt proiect), nu dispare: containers.ok rămâne nescris, cu motivul numit."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}}, flap=["pg-db"],
                              build={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    p = run_c(tmp_path, base, "OPT_ONLY=clin; OPT_REBUILD=clin")
    assert p.returncode == 1 and "NEREZOLVAT" in p.stdout and "pg/db" in p.stdout
    full_run_stays_red(tmp_path, base, "OPT_REBUILD=clin")      # singura rulare care ar putea scrie markerul: acoperă ambele proiecte


def test_only_with_no_matching_project_is_an_error_not_a_green_noop(tmp_path):
    """`--only prject-cu-typo` itera proiectele, nu potrivea niciunul și ieșea 0 cu containers.ok scris:
    «nimic de făcut» tipărit pentru o greșeală de scriere. Acum: ieșire 1, mesaj cu proiectele cunoscute,
    nicio blocare luată, nicio comandă care schimbă ceva."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    for only in ("nu-exista", "pg,nu-exista"):
        p = run_c(tmp_path, base, f"OPT_ONLY={only}")
        assert p.returncode == 1 and "niciun proiect compose cu numele ăsta" in p.stdout and "clin" in p.stdout, p.stdout
        assert not (set(verbs(tmp_path)) & MUTATING)
        assert not (base / "phases" / "containers.started").exists()


def test_a_failed_pull_stops_the_whole_project_even_when_another_service_could_be_updated(tmp_path):
    """Jumătate de proiect pe imagini noi și jumătate pe vechi nu e o stare pe care a cerut-o cineva.
    `db` ar avea o imagine nouă, `db2` nu poate fi tras: niciun `up` în proiect."""
    base = containers_fixture(tmp_path, ctx_clean=True, two_pull=True,
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 1, "new_id": None}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "NU declar" in p.stdout, p.stdout
    assert "compose up" not in verbs(tmp_path)


def test_a_container_that_never_leaves_starting_fails_within_the_bounded_wait(tmp_path):
    """Un container care rămâne `starting` nu e «sănătos după un timp»: așteptarea e mărginită, iar
    depășirea ei e eșec (altfel faza ar iesi verde peste un serviciu care nu pornește)."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_starting",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg", SU_HEALTH_TIMEOUT_S="1")
    assert p.returncode == 1 and "încă 'starting'" in p.stdout, p.stdout


def test_the_health_verdict_after_a_recreate_is_enforced(tmp_path):
    """După recreare containerul pornește dar healthcheck-ul pică (baseline healthy): «rulează» nu
    ajunge. Rezultat: eșec numit, cu comanda de rollback."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "verdict worse" in p.stdout and "rollback: docker tag rollback/maint-b/pg-db:prev" in p.stdout


def test_rollback_tags_live_in_their_own_namespace(tmp_path):
    """Actualizarea săptămânală (container-update.sh) pune `rollback/<proiect>-<serviciu>:prev`. Dacă
    ambele scriu aceeași etichetă, a doua rulare pierde imaginea veche a primei. Aici: spațiu separat,
    `rollback/maint-<baseline>/…`; eticheta celeilalte nu se atinge."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, images={**json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))["images"],
                                "rollback/pg-db:prev": {"id": "sha256:" + "99" * 32, "digests": 0}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 0, p.stdout
    images = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))["images"]
    assert images["rollback/maint-b/pg-db:prev"]["id"] == OLD_PG
    assert images["rollback/pg-db:prev"]["id"] == "sha256:" + "99" * 32


def test_a_failed_build_on_a_rerun_compares_with_the_state_before_this_run(tmp_path):
    """La o rulare repetată containerele deja actualizate rulează legitim alt ID decât în baseline.
    «Containerele rulează neschimbate» se judecă față de starea de DINAINTEA rulării, nu față de
    baseline: altfel un build eșuat striga «imaginea s-a schimbat» pe ce n-a atins."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin").returncode == 0
    set_state(tmp_path, build_effect={"app": {"rc": 1, "new_id": None}})
    p = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert "rulează neschimbate" in p.stdout and "imaginea s-a schimbat" not in p.stdout, p.stdout


def test_long_commands_do_not_inherit_the_lock_descriptors(tmp_path):
    """dnf rulează scriptlete care pornesc servicii; un daemon care moștenește descriptorul de blocare îl
    ține după ce faza a ieșit, iar rulările următoare ar spune «în curs» la nesfârșit. `docker pull`,
    `build` și `up` (ca și `dnf upgrade`) trec prin `nolock`: momeala notează descriptorii 10-15 deschiși."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    p = run_c(tmp_path, base, "OPT_REBUILD=clin")
    assert p.returncode == 0, p.stdout
    rows = [l for l in (tmp_path / "docker-fds.log").read_text(encoding="utf-8").splitlines()
            if l.startswith("pull") or " build " in l or " up " in l]
    assert len(rows) >= 3, rows
    assert all(l.endswith("|") for l in rows), rows


# ---------------------------------------------------------------------------
# Runda 4: rerulările nu au voie să repună imaginea care a picat, nici să șteargă eșecuri
# ---------------------------------------------------------------------------
RB_TAG = "rollback/maint-b/pg-db:prev"
NEWER_PG = "sha256:" + "cd" * 32


def images_of(tmp: Path) -> dict:
    return json.loads((tmp / "docker-state.json").read_text(encoding="utf-8"))["images"]


def last_report(base: Path, key: str) -> str:
    """Rezultatul FINAL al serviciului (reducerea su_report_final, aceeași pe care o citesc faza și verify), nu ultima
    linie brută: jurnalul primește și evenimente (`read-ok`, `retried`, `pulled`...) care nu sunt rezultate."""
    proc = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(base / 'containers.report')}'")
    assert proc.returncode == 0, proc.stderr
    want = key.replace("|", "/") + "|"
    rows = [l for l in proc.stdout.splitlines() if l.startswith(want)]
    return rows[0].split("|")[1] if rows else ""


def failed_recreate(tmp_path):
    """Rularea 1: pg-db recreat pe imaginea nouă, iese unhealthy -> `failed`."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db") == "failed"
    return base


def test_a_plain_rerun_leaves_a_failed_service_untouched_and_red(tmp_path):
    """Un serviciu recreat și picat ar fi fost re-tras și recreat la rularea următoare, punând la loc
    exact imaginea rea (peste un rollback făcut de operator în pauză). Rularea simplă nu mai atinge nimic
    din el: niciun pull, tag, up; ieșire 1, `failed` rămâne rezultatul final, containers.ok lipsește."""
    base = failed_recreate(tmp_path)
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1, p.stdout
    assert not (set(verbs(tmp_path)[mark:]) & MUTATING), verbs(tmp_path)[mark:]
    assert "--retry-failed pg" in p.stdout and "TOTUL DOVEDIT" not in p.stdout
    assert last_report(base, "pg|db") == "failed"


def test_a_manual_rollback_does_not_turn_green_without_an_explicit_retry(tmp_path):
    """Operatorul readuce pg-db la imaginea veche (sănătoasă) și rulează din nou faza. Containerul e
    sănătos, deci o re-verificare ar fi scris `verified` și faza ar fi ieșit verde fără ca cineva să fi
    cerut ceva; sau, mai rău, ar fi tras din nou imaginea rea. Acum: roșu, neatins, până la --retry-failed;
    cu el, retry-ul reușit și verificat dă verde și eticheta de rollback rămâne pe imaginea originală."""
    base = failed_recreate(tmp_path)
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    st["containers"]["pg-db"].update(image_id=OLD_PG, health="healthy")        # rollback manual
    st["up_effect"] = {"app": "recreate", "db": "recreate", "db2": "recreate"}  # imaginea nouă acum se comportă
    (tmp_path / "docker-state.json").write_text(json.dumps(st), encoding="utf-8")
    mark = len(verbs(tmp_path))
    plain = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert plain.returncode == 1 and not (set(verbs(tmp_path)[mark:]) & MUTATING), plain.stdout
    assert last_report(base, "pg|db") == "failed"
    retry = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 0, retry.stdout
    assert last_report(base, "pg|db") == "recreated" and not unresolved(base)
    assert images_of(tmp_path)[RB_TAG]["id"] == OLD_PG


def test_retry_failed_must_name_a_known_project(tmp_path):
    """`--retry-failed pgg` (typo) nu potrivea nimic și faza mergea mai departe ca și cum cererea de
    reîncercare n-ar fi existat: serviciul eșuat rămânea în tăcere nereîncercat. Acum e eroare, ca la --only."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    p = run_c(tmp_path, base, "OPT_RETRY_FAILED=pgg")
    assert p.returncode == 1 and "--retry-failed pgg: niciun proiect" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)


def test_rerun_never_retags_the_rollback_tag_with_the_failed_image(tmp_path):
    """Eticheta de rollback se suprascria cu imaginea picată la o rerulare cu retry: imaginea originală
    rămânea fără etichetă, iar primul `docker image prune` (de mână — pe gazdă nu rulează niciun timer) o șterge —
    rollback-ul dispărea exact când era nevoie. Prima scriere câștigă: eticheta arată mereu imaginea de
    dinainte de mentenanță (verificat după ID)."""
    base = failed_recreate(tmp_path)
    assert images_of(tmp_path)[RB_TAG]["id"] == OLD_PG
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    st["containers"]["pg-db"]["health"] = "healthy"        # operatorul a reparat cauza; NEW_PG încă rulează
    st["up_effect"] = {"app": "recreate", "db": "recreate", "db2": "recreate"}
    st["pull_effect"] = {"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}      # apare o imagine și mai nouă
    (tmp_path / "docker-state.json").write_text(json.dumps(st), encoding="utf-8")
    p = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert p.returncode == 0, p.stdout
    assert "compose up" in verbs(tmp_path)
    assert images_of(tmp_path)[RB_TAG]["id"] == OLD_PG, images_of(tmp_path)[RB_TAG]


def test_a_rollback_tag_pointing_elsewhere_blocks_the_recreate(tmp_path):
    """Dacă eticheta de rollback există dar nu arată imaginea de dinainte de mentenanță, n-o suprascriem
    și nu recreăm: altfel operatorul ar crede că are rollback pe imaginea originală, iar el ar duce
    la alt lucru."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    other = "sha256:" + "99" * 32
    set_state(tmp_path, images={**images_of(tmp_path), RB_TAG: {"id": other, "digests": 0}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "n-o suprascriu" in p.stdout, p.stdout
    assert "compose up" not in verbs(tmp_path) and images_of(tmp_path)[RB_TAG]["id"] == other


def test_a_pull_that_fails_twice_is_never_overwritten_by_verified(tmp_path):
    """Pull-ul pica a doua oară, dar containerul vechi era sănătos: re-verificarea scria `verified`
    PESTE `pull-failed`, iar un `--only clin` ulterior ieșea verde cu patch-ul netras. Doar un pull
    reușit are voie să curețe `pull-failed`."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    for _ in range(2):
        assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
        assert last_report(base, "pg|db") == "pull-failed", (base / "containers.report").read_text(encoding="utf-8")
        assert report_actions(base, "pg|db")[-1] == "pull-failed", report_actions(base, "pg|db")     # nicio `verified` scrisă după el
    p = run_c(tmp_path, base, "OPT_ONLY=clin; OPT_REBUILD=clin")
    assert p.returncode == 1 and "NEREZOLVAT" in p.stdout and "pg/db (pull-failed)" in p.stdout, p.stdout
    full_run_stays_red(tmp_path, base, "OPT_REBUILD=clin")      # pg/db trage din nou (și pică din nou), clin se reconstruiește: tot roșu
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})   # registrul revine
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 0
    assert last_report(base, "pg|db") == "recreated"


def test_a_failed_build_is_recorded_and_blocks_a_later_only_run(tmp_path):
    """Un build eșuat nu lăsa nicio urmă în raport: `--only pg` imediat după ieșea verde și scria
    containers.ok, cu aplicația nereconstruită. Acum `build-failed` e rezultatul final al serviciului,
    roșu în faza containers și în verify, până când un build reușit îl înlocuiește."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 1, "new_id": None}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin").returncode == 1
    assert last_report(base, "clin|app") == "build-failed"
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "NEREZOLVAT" in p.stdout and "clin/app (build-failed)" in p.stdout, p.stdout
    full_run_stays_red(tmp_path, base)             # fără --rebuild: build-failed nu se șterge, iar rularea completă nu scrie markerul
    set_state(tmp_path, build_effect={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin").returncode == 0
    assert last_report(base, "clin|app") == "recreated" and ok_marker(base)


# ---------------------------------------------------------------------------
# Runda 5: eșecurile sunt STĂRI lipicioase; un singur loc le reduce (su_report_final)
# ---------------------------------------------------------------------------
def report_actions(base: Path, key: str) -> list[str]:
    rows = [l for l in (base / "containers.report").read_text(encoding="utf-8").splitlines() if l.startswith(key + "|")]
    return [r.split("|")[2] for r in rows]


def edit_state(tmp: Path, fn) -> None:
    p = tmp / "docker-state.json"
    st = json.loads(p.read_text(encoding="utf-8"))
    fn(st)
    p.write_text(json.dumps(st), encoding="utf-8")


def test_a_failed_service_whose_container_is_gone_stays_failed_and_red(tmp_path):
    """Un serviciu `failed` cu containerul dispărut (ramura «niciun container după up») era citit ÎNAINTE de
    reținere: `docker inspect` pica, `skip-unreadable` înlocuia `failed`, iar o rulare simplă ieșea 0
    «TOTUL DOVEDIT» și scria containers.ok cu un serviciu care nu există. Acum reținerea vine prima, iar
    chiar și cu --retry-failed (containerul tot lipsește) `failed` rămâne în rezultat și faza e roșie."""
    base = containers_fixture(tmp_path, ctx_clean=True, two_pull=True, flap=["pg-db2"],
                              pull={"redis:7": {"rc": 0, "new_id": NEW_R}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db2") == "failed"
    edit_state(tmp_path, lambda st: st["containers"].pop("pg-db2"))
    plain = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert plain.returncode == 1 and "TOTUL DOVEDIT" not in plain.stdout and "--retry-failed pg" in plain.stdout, plain.stdout
    assert "NU îl trag și NU îl recreez" in plain.stdout and "skip-unreadable" not in plain.stdout, plain.stdout    # reținut, nu «ilizibil»
    retry = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "NEREZOLVAT" in retry.stdout and "pg/db2 (failed)" in retry.stdout, retry.stdout


def test_a_pull_failure_during_retry_failed_does_not_release_the_hold(tmp_path):
    """Operatorul a readus manual pg-db la imaginea veche și cere --retry-failed, dar registrul nu răspunde:
    `pull-failed` înlocuia `failed`, deci rularea simplă următoare nu mai ținea serviciul, trăgea imaginea
    rea și o recrea peste rollback-ul operatorului. Acum `failed` rămâne reținut până la un --retry-failed
    care chiar reușește (și e verificat)."""
    base = failed_recreate(tmp_path)

    def manual_rollback(st):
        st["containers"]["pg-db"].update(image_id=OLD_PG, health="healthy")
        st["pull_effect"] = {"postgres:16-alpine": {"rc": 1, "new_id": None}}
        st["up_effect"] = {"app": "recreate", "db": "recreate", "db2": "recreate"}
    edit_state(tmp_path, manual_rollback)
    retry = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "NU declar" in retry.stdout, retry.stdout
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})      # registrul revine
    mark = len(verbs(tmp_path))
    plain = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert plain.returncode == 1 and not (set(verbs(tmp_path)[mark:]) & MUTATING), (plain.stdout, verbs(tmp_path)[mark:])
    assert "--retry-failed pg" in plain.stdout
    final = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")        # control: retry-ul reușit rezolvă
    assert final.returncode == 0 and not unresolved(base), final.stdout


def test_a_build_failed_is_not_erased_by_a_later_run_without_rebuild(tmp_path):
    """Build-ul pică, iar o rulare următoare fără --rebuild punea `skip-not-requested`, re-verifica containerul
    vechi (sănătos) și scria `verified` peste `build-failed`: faza ieșea verde cu aplicația nereconstruită.
    Doar un build reușit (--rebuild) urmat de verificare îl rezolvă."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 1, "new_id": None}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin").returncode == 1
    plain = run_c(tmp_path, base, "OPT_ONLY=clin")
    assert plain.returncode == 1 and "NEREZOLVAT" in plain.stdout and "clin/app (build-failed)" in plain.stdout, plain.stdout
    assert "--rebuild clin" in plain.stdout
    set_state(tmp_path, build_effect={"app": {"rc": 0, "new_id": NEW_APP}})
    fixed = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert fixed.returncode == 0 and not unresolved(base), fixed.stdout


def test_a_pull_failed_is_not_erased_by_a_skip_followed_by_a_health_check(tmp_path):
    """Pull-ul pică; la rularea următoare configurația compose s-a schimbat (`hold-config-drift`), serviciul
    nu se mai trage, dar e re-verificat (atins) și iese `verified` — peste `pull-failed`, deși nimic n-a fost
    tras. Doar un pull REUȘIT îl rezolvă."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"]["labels"].update({"com.docker.compose.config-hash": "ALT-HASH"}))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert "hold-config-drift" in p.stdout
    assert p.returncode == 1 and "pg/db (pull-failed)" in p.stdout, p.stdout
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"]["labels"].update({"com.docker.compose.config-hash": "H-db"}))
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 0 and not unresolved(base)


def test_a_failed_build_is_not_reverified_as_healthy_in_the_same_run(tmp_path):
    """Un serviciu deja actualizat (atins) al cărui build pică acum: re-verificarea containerului vechi,
    sănătos, ar scrie `verified` imediat după `build-failed` și ar face din «build eșuat» o linie de
    jurnal obișnuită. `unresolved` îl scutește de re-verificare în rularea asta."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin").returncode == 0
    set_state(tmp_path, build_effect={"app": {"rc": 1, "new_id": None}})
    p = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert p.returncode == 1 and "build-failed în rularea asta" in p.stdout, p.stdout
    assert report_actions(base, "clin|app")[-1] == "build-failed", report_actions(base, "clin|app")


def test_retry_failed_names_one_project_and_leaves_a_failed_service_in_another_held(tmp_path):
    """`--retry-failed pg` eliberează DOAR proiectul pg. Un `failed` din clin, cu --rebuild clin cerut în
    aceeași comandă, trebuie să rămână reținut: dacă orice valoare ar elibera toate proiectele, aplicația
    clin ar fi reconstruită și recreată peste rollback-ul operatorului."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy",
                              build={"app": {"rc": 0, "new_id": NEW_APP}}, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_KEEP_GOING=1").returncode == 1
    assert last_report(base, "clin|app") == "failed" and last_report(base, "pg|db") == "failed"

    def repaired(st):
        for c in st["containers"].values():
            c["health"] = "healthy"
        st["up_effect"] = {"app": "recreate", "db": "recreate", "db2": "recreate"}
    edit_state(tmp_path, repaired)
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_KEEP_GOING=1; OPT_RETRY_FAILED=pg")
    assert "compose build" not in verbs(tmp_path)[mark:], verbs(tmp_path)[mark:]
    assert p.returncode == 1 and "clin/app: rezultatul final sub această baseline e failed" in p.stdout, p.stdout
    assert "pg/db (" not in p.stdout and "pg/db: rezultatul final" not in p.stdout, p.stdout        # pg a fost eliberat și verificat
    assert not ok_marker(base)
    done = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_RETRY_FAILED=clin")      # control: numit explicit, se rezolvă
    assert done.returncode == 0 and ok_marker(base), done.stdout


def test_dry_run_with_retry_failed_does_not_claim_proof_over_an_unresolved_failure(tmp_path):
    """`--dry-run --retry-failed` pe un serviciu rămas `failed` tipărea «TOTUL DOVEDIT» și ieșea 0: o
    simulare care nu a schimbat nimic declara dovedit ce era încă picat. Acum iese 1 și numește eșecul;
    jurnalul rămâne neatins."""
    base = failed_recreate(tmp_path)
    before = (base / "containers.report").read_bytes()
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_DRY_RUN=1; OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    assert "NEREZOLVAT" in p.stdout and "pg/db (failed)" in p.stdout and "dry-run" in p.stdout
    assert not (set(verbs(tmp_path)[mark:]) & MUTATING)
    assert (base / "containers.report").read_bytes() == before


def test_rollback_hint_names_the_image_of_a_service_without_an_image_key(tmp_path):
    """Un serviciu cu `build:` și fără `image:` (8 pe gazdă) picat la o re-verificare tipărea
    `docker tag rollback/… ` fără țintă: comanda de rollback copiată de operator n-ar fi mers. Numele vine
    din containerul însuși (Config.Image), apoi din numele implicit compose."""
    base = containers_fixture(tmp_path, ctx_clean=True, no_image=True, up_effect="recreate_unhealthy",
                              build={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin").returncode == 1
    retry = run_c(tmp_path, base, "OPT_ONLY=clin; OPT_RETRY_FAILED=clin")          # fără --rebuild: doar re-verificare
    assert retry.returncode == 1 and "re-verific starea" in retry.stdout, retry.stdout
    assert "rollback: docker tag rollback/maint-b/clin-app:prev clin-app &&" in retry.stdout, retry.stdout


def failing_build_refuses_disk(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    return base, "OPT_REBUILD=clin; OPT_ONLY=clin", {"SU_MIN_FREE_GB": "999999999"}, lambda: None


def failing_unreadable_after_build(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP, "drop": True}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})

    def fix():
        edit_state(tmp, lambda st: (st["images"].update({"clin-app:latest": {"id": OLD_APP, "created": "2099-01-01T00:00:00Z", "digests": 0}}),
                                    st.update(build_effect={"app": {"rc": 0, "new_id": NEW_APP}})))
    return base, "OPT_REBUILD=clin; OPT_ONLY=clin", {}, fix


def failing_tag_elsewhere(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp, images={**images_of(tmp), RB_TAG: {"id": "sha256:" + "99" * 32, "digests": 0}})
    return base, "OPT_ONLY=pg", {}, lambda: set_state(tmp, images={**images_of(tmp), RB_TAG: {"id": OLD_PG, "digests": 0}})


def failing_tag_command(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp, tag_effect="fail")
    return base, "OPT_ONLY=pg", {}, lambda: edit_state(tmp, lambda st: st.pop("tag_effect"))


def failing_tag_wrong_image(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp, tag_effect="wrong")
    return base, "OPT_ONLY=pg", {}, lambda: edit_state(tmp, lambda st: (st.pop("tag_effect"), st["images"].pop(RB_TAG)))


def failing_pull_aborts_project(tmp: Path):
    base = containers_fixture(tmp, ctx_clean=True, two_pull=True,
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 1, "new_id": None}})
    return base, "OPT_ONLY=pg", {}, lambda: set_state(tmp, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 0, "new_id": NEW_R}})


# (scenariu, proiectul rulat apoi ca să se vadă dacă eșecul a rămas, cheia care trebuie să rămână roșie, starea ei)
UNRECORDED_RETURNS = [
    (failing_build_refuses_disk, "pg", "clin/app", "build-failed"),
    (failing_unreadable_after_build, "pg", "clin/app", "build-failed"),
    (failing_tag_elsewhere, "clin", "pg/db", "tag-failed"),
    (failing_tag_command, "clin", "pg/db", "tag-failed"),
    (failing_tag_wrong_image, "clin", "pg/db", "tag-failed"),
    (failing_pull_aborts_project, "clin", "pg/db", "pull-failed"),
]


@pytest.mark.parametrize("scenario,other,key,state", UNRECORDED_RETURNS, ids=[u[0].__name__ for u in UNRECORDED_RETURNS])
def test_every_failure_return_in_execute_changes_leaves_the_service_red(tmp_path, scenario, other, key, state):
    """Întoarcerile cu 1 din execute_changes (spațiu insuficient înainte de build, imagine ilizibilă după build,
    eticheta de rollback greșită sau netrasă, pull eșuat la alt serviciu) NU scriau nimic în jurnal: o rulare
    ulterioară `--only` pe alt proiect ieșea verde și scria containers.ok, deși un serviciu rămăsese cu eticheta
    mutată (pull-ul a mutat-o) și containerul pe imaginea veche. Acum fiecare lasă starea lui lipicioasă."""
    base, opts, env, fix = scenario(tmp_path)
    first = run_c(tmp_path, base, opts, **env)
    assert first.returncode == 1, first.stdout
    later = run_c(tmp_path, base, f"OPT_ONLY={other}")
    assert later.returncode == 1 and "NEREZOLVAT" in later.stdout and f"{key} ({state})" in later.stdout, later.stdout
    full_run_stays_red(tmp_path, base)     # un `--only` peste un proiect din două nu scrie markerul oricum; o rulare completă ar putea
    fix()                                  # control: repară cauza, iar același proiect iese verde
    again = run_c(tmp_path, base, opts)
    assert again.returncode == 0 and not unresolved(base), again.stdout


def project_without_labels(tmp: Path):
    gone = {}

    def hide(st):
        gone.update(st["containers"].pop("pg-db"))
    edit_state(tmp, hide)
    return lambda: edit_state(tmp, lambda st: st["containers"].update({"pg-db": gone}))


def project_without_compose_config(tmp: Path):
    gone = {}

    def hide(st):
        gone.update(st["compose"].pop("pg"))
    edit_state(tmp, hide)
    return lambda: edit_state(tmp, lambda st: st["compose"].update({"pg": gone}))


def project_with_unparseable_config(tmp: Path):
    saved = {}

    def hide(st):
        saved.update(st["compose"]["pg"])
        st["compose"]["pg"] = {"config": {"services": {"db": "nu-e-un-obiect"}}, "hashes": {}}
    edit_state(tmp, hide)
    return lambda: edit_state(tmp, lambda st: st["compose"].update({"pg": saved}))


@pytest.mark.parametrize("breaker,message", [
    (project_without_labels, "nu pot citi etichetele compose"),
    (project_without_compose_config, "docker compose config a eșuat"),
    (project_with_unparseable_config, "nu pot citi serviciile din config"),
], ids=["labels", "compose-config", "services-parse"])
def test_a_project_that_cannot_be_read_stays_red_for_later_runs(tmp_path, breaker, message):
    """Etichetele compose, `docker compose config` sau parsarea serviciilor pică: process_project întorcea 1 fără
    nicio urmă în jurnal, iar un `--only` pe alt proiect (ori o rulare ulterioară) ieșea verde peste un proiect
    care nu fusese atins deloc. Acum fiecare serviciu al proiectului rămâne `unread` până când configurația lui
    se citește."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    restore = breaker(tmp_path)
    first = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert first.returncode == 1 and message in first.stdout, first.stdout
    later = run_c(tmp_path, base, "OPT_ONLY=clin")
    assert later.returncode == 1 and "NEREZOLVAT" in later.stdout and "pg/db (unread)" in later.stdout, later.stdout
    full_run_stays_red(tmp_path, base)
    restore()
    again = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert again.returncode == 0 and not unresolved(base), again.stdout


def test_retry_failed_is_parsed_into_its_own_variable_and_only_for_containers(tmp_path):
    """`--retry-failed` parsat în OPT_ONLY ar fi restrâns rularea la acel proiect fără să elibereze nimic (iar
    --only ar fi eliberat serviciile eșuate): reținerea ar fi fost ocolită sau cererea ignorată în tăcere.
    Se verifică variabilele după parse_args, și că fazele care nu o cunosc o refuză cu 2."""
    bindir = make_bin(tmp_path, {})
    p = host_run(tmp_path, 'PHASE=containers; parse_args --only a --retry-failed b,c; echo "RETRY=[$OPT_RETRY_FAILED] ONLY=[$OPT_ONLY]"', bindir)
    assert p.returncode == 0 and "RETRY=[b,c] ONLY=[a]" in p.stdout, p.stdout + p.stderr
    q = host_run(tmp_path, 'PHASE=containers; parse_args --retry-failed b; echo "RETRY=[$OPT_RETRY_FAILED] ONLY=[$OPT_ONLY]"', bindir)
    assert "RETRY=[b] ONLY=[]" in q.stdout, q.stdout
    r = host_run(tmp_path, "PHASE=os; parse_args --retry-failed b", bindir)
    assert r.returncode == 2 and "nu se aplică fazei os" in r.stderr, r.stderr


def test_a_pull_failed_is_resolved_by_a_successful_pull_that_finds_nothing_new(tmp_path):
    """Pull-ul pică (registrul nu răspunde); la rularea următoare registrul răspunde, dar nu e nimic nou: containerul rulează deja
    imaginea din baseline. Un pull REUȘIT urmat de o verificare sănătoasă rezolvă `pull-failed` chiar și fără recreare — altfel serviciul
    rămânea roșu până la un baseline nou. (Varianta «operatorul a adus containerul pe imaginea nouă de mână» nu mai e o ieșire: o imagine
    pe care nici baseline-ul, nici mentenanța n-au pus-o e baseline vechi — vezi testele `stale-baseline`.)"""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db") == "pull-failed"
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})        # registrul revine; nimic nou
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 0 and not unresolved(base) and "NEREZOLVAT" not in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)[mark:]) & {"tag", "compose up", "compose build"}) and last_report(base, "pg|db") == "verified"


# ---------------------------------------------------------------------------
# Runda 6
# ---------------------------------------------------------------------------
def tsv_append(base: Path, line: str) -> None:
    with open(base / "containers.tsv", "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")


def compose_builds(tmp: Path) -> list[list[str]]:
    return [a for a in docker_log(tmp) if a[0] == "compose" and "build" in a]


@pytest.mark.parametrize("flag,opt", [("--rebuild", "OPT_REBUILD"), ("--accept-drift", "OPT_ACCEPT_DRIFT")])
def test_rebuild_and_accept_drift_must_name_known_projects(tmp_path, flag, opt):
    """`--rebuild clinn` (typo) nu potrivea niciun proiect: nimic nu se reconstruia, faza ieșea 0 «TOTUL DOVEDIT» și
    operatorul credea că aplicația a fost reconstruită; `--accept-drift` cu un nume greșit lăsa codul diferit
    neacceptat, tot în tăcere. Ca la --only: eroare numită, ieșire 1, înainte de blocări și de orice atingere."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    p = run_c(tmp_path, base, f"{opt}=clinn")
    assert p.returncode == 1 and f"{flag} clinn: niciun proiect compose" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)
    assert not (base / "phases" / "containers.started").exists()
    q = run_c(tmp_path, base, f"{opt}=clin,clinn")           # o singură greșeală dintr-o listă oprește totul
    assert q.returncode == 1 and f"{flag} clinn:" in q.stdout, q.stdout


def test_rebuild_all_is_a_keyword_not_a_project_name(tmp_path):
    """`--rebuild all` e cuvântul-cheie documentat; validarea numelor nu are voie să-l refuze (ar bloca reconstruirea
    tuturor aplicațiilor cu un mesaj «niciun proiect numit all»)."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    p = run_c(tmp_path, base, "OPT_REBUILD=all; OPT_DRY_RUN=1")
    assert p.returncode == 0 and "niciun proiect compose" not in p.stdout, p.stdout


def add_worker_sharing_the_context(tmp: Path, *, worker_created: str) -> None:
    """clin/worker: același context de build ca clin/app, imagine proprie, de altă vârstă (ca nis2 api/worker)."""
    old_w = "sha256:" + "77" * 32

    def add(st):
        st["images"]["clin-worker:latest"] = {"id": old_w, "created": worker_created, "digests": 0}
        c = json.loads(json.dumps(st["containers"]["clin-app"]))
        c.update(id="clin-worker", image_id=old_w, config_image="clin-worker:latest")
        c["labels"].update({"com.docker.compose.service": "worker", "com.docker.compose.config-hash": "H-worker"})
        st["containers"]["clin-worker"] = c
        svc = {"image": "clin-worker:latest", "build": dict(st["compose"]["clin"]["config"]["services"]["app"]["build"])}
        st["compose"]["clin"]["config"]["services"]["worker"] = svc
        st["compose"]["clin"]["hashes"]["worker"] = "H-worker"
        st["up_effect"]["worker"] = "recreate"
    edit_state(tmp, add)


def test_two_services_sharing_a_build_context_are_judged_against_their_own_image(tmp_path):
    """nis2 api (imagine nouă, 0 fișiere mai noi) și worker (imagine mai veche, 2 fișiere mai noi) au același context. Faptele
    se măsurau o dată, pe primul serviciu, și se păstrau pe context: worker moștenea «curat» și era reconstruit cu --rebuild,
    fără --accept-drift, livrând cod pe care nimeni nu-l citise. Acum fiecare serviciu se judecă față de imaginea LUI."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}})
    add_worker_sharing_the_context(tmp_path, worker_created="2026-01-01T00:00:00Z")
    tsv_append(base, f"clin-worker|clin|worker|clin-worker:latest|{'sha256:' + '77' * 32}|{'sha256:' + '77' * 32}|running|healthy|unless-stopped|0|2026-11-17T00:00:00Z")
    p = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert "clin/worker: sărit (skip-drift)" in p.stdout, p.stdout
    built = [a for a in compose_builds(tmp_path)]
    assert built and "app" in built[0] and "worker" not in built[0], built


def test_a_stale_baseline_refuses_the_rebuild_before_anything_changes(tmp_path):
    """oferte api/worker și dms app au fost redeployate după baseline. `--rebuild` ar fi pus eticheta de rollback pe imaginea
    DIN baseline, iar comanda de rollback tipărită ar fi anulat acel deploy (iar dacă imaginea veche era curățată de
    prune, eticheta rămânea tag-failed pe vecie). Acum: proiectul e refuzat (`stale-baseline`), roșu, înainte de build/tag/up, cu
    calea spre un baseline nou; și rămâne roșu pentru rulările următoare."""
    base = containers_fixture(tmp_path, ctx_clean=True, build={"app": {"rc": 0, "new_id": NEW_APP}},
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    foreign = "sha256:" + "55" * 32
    edit_state(tmp_path, lambda st: (st["images"].update({"redeployed:x": {"id": foreign, "created": "2099-01-01T00:00:00Z", "digests": 0}}),
                                     st["containers"]["clin-app"].update(image_id=foreign)))
    p = run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert p.returncode == 1 and "baseline-ul e vechi" in p.stdout and "--phase preflight --new-baseline" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING), verbs(tmp_path)
    assert last_report(base, "clin|app") == "stale-baseline"
    later = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert later.returncode == 1 and "clin/app (stale-baseline)" in later.stdout, later.stdout
    # control: același container, dar baseline-ul NOU îl știe (preflight --new-baseline) => se reconstruiește normal
    fresh = tmp_path / "state" / "snapshots" / "B2"
    shutil.copytree(base, fresh)
    (fresh / "containers.report").unlink()
    shutil.rmtree(fresh / "phases")
    tsv = (fresh / "containers.tsv").read_text(encoding="utf-8").replace(f"|{OLD_APP}|{OLD_APP}|", f"|{foreign}|{foreign}|")
    (fresh / "containers.tsv").write_text(tsv, encoding="utf-8", newline="\n")
    ok = run_c(tmp_path, fresh, "OPT_REBUILD=clin; OPT_ONLY=clin")
    assert ok.returncode == 0 and "compose build" in verbs(tmp_path), ok.stdout


def test_a_stale_baseline_on_a_pulled_service_refuses_the_recreate_and_the_rollback_tag(tmp_path):
    """Același risc la un serviciu cu imagine din registru: pg-db a fost redeployat după baseline, iar pull-ul aduce o imagine
    nouă. Recrearea ar fi pus eticheta de rollback pe imaginea veche din baseline. Se refuză la clasificare, înainte de `pull`, `tag` și `up`."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    foreign = "sha256:" + "66" * 32
    edit_state(tmp_path, lambda st: (st["images"].update({"redeployed:pg": {"id": foreign, "created": "2026-10-01T00:00:00Z", "digests": 1}}),
                                     st["containers"]["pg-db"].update(image_id=foreign)))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "baseline-ul e vechi" in p.stdout, p.stdout
    assert "tag" not in verbs(tmp_path) and "compose up" not in verbs(tmp_path) and "pull" not in verbs(tmp_path), verbs(tmp_path)
    assert last_report(base, "pg|db") == "stale-baseline"


def test_retry_failed_on_a_built_service_without_rebuild_reverifies_and_goes_green(tmp_path):
    """Rularea tipărea «--retry-failed clin» ca singurul drum spre verde, dar la o aplicație construită local reîncercarea
    scria `retried`, apoi `skip-not-requested` (care dezarmează), apoi `verified` — iar serviciul rămânea roșu oricât
    ar fi repetat operatorul comanda din mesaj. Acum comanda din mesaj, cuvânt cu cuvânt, re-verifică containerul de
    acum și, dacă e sănătos și stabil, rezolvă `failed`."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy", build={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_REBUILD=clin; OPT_ONLY=clin").returncode == 1
    plain = run_c(tmp_path, base, "OPT_ONLY=clin")
    assert plain.returncode == 1 and "--retry-failed clin" in plain.stdout
    edit_state(tmp_path, lambda st: (st["containers"]["clin-app"].update(health="healthy"),
                                     st.update(up_effect={"app": "recreate", "db": "recreate", "db2": "recreate"})))
    mark = len(verbs(tmp_path))
    fixed = run_c(tmp_path, base, "OPT_ONLY=clin; OPT_RETRY_FAILED=clin")        # exact comanda din mesaj
    assert fixed.returncode == 0, fixed.stdout
    assert not (set(verbs(tmp_path)[mark:]) & MUTATING), verbs(tmp_path)[mark:]     # fără rebuild: doar re-verificare
    assert last_report(base, "clin|app") == "verified" and not unresolved(base)


def new_baseline_like_preflight(tmp: Path, base: Path, running: dict[str, str], *, tags: dict[str, str] | None = None,
                                health: dict[str, str] | None = None, states: dict[str, str] | None = None, name: str = "B2",
                                drop: set[str] | None = None, raw_tsv: bytes | None = None) -> Path:
    """Un baseline NOU, ca `preflight --new-baseline`: copia lui `base` cu ID-urile care rulează acum (`running`: serviciu -> ID) și cu
    eșecurile nerezolvate PRELUATE de `carry_forward_sticky` (funcția reală din system-update-host.sh), fără jurnalul vechi.
    `tags`: ID-ul pe care arată ACUM eticheta serviciului (implicit același cu cel care rulează, ca la un preflight real fără pull intermediar);
    `health` / `states`: sănătatea și starea măsurate acum (un preflight real le citește din container, nu le copiază din baseline-ul vechi).
    `raw_tsv`: conținutul EXACT al lui containers.tsv (de pildă `b""`: docker a răspuns, dar n-a listat nimic), în loc de copia prelucrată."""
    fresh = tmp / "state" / "snapshots" / name
    shutil.copytree(base, fresh)
    for junk in ("containers.report", "containers.owned", "containers.episode", "os-carried.kv"):
        (fresh / junk).unlink(missing_ok=True)
    shutil.rmtree(fresh / "phases", ignore_errors=True)
    tsv = (base / "containers.tsv").read_text(encoding="utf-8").splitlines()
    out = []
    for line in tsv:
        f = line.split("|")
        if f[2] in (drop or set()):      # serviciul nu mai are niciun container în baseline-ul nou (scos / proiect dispărut)
            continue
        if f[2] in running:
            f[4] = f[5] = running[f[2]]
        if f[2] in (tags or {}):
            f[5] = tags[f[2]]
        if f[2] in (health or {}):
            f[7] = health[f[2]]
        if f[2] in (states or {}):
            f[6] = states[f[2]]
        out.append("|".join(f))
    (fresh / "containers.tsv").write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    if raw_tsv is not None:
        (fresh / "containers.tsv").write_bytes(raw_tsv)
    bindir = make_bin(tmp, {}, docker=True)
    p = host_run(tmp, f"carry_forward_sticky '{posix(base)}' '{posix(fresh)}'", bindir)
    assert p.returncode == 0, p.stdout + p.stderr
    (tmp / "carry.out").write_text(p.stdout, encoding="utf-8")       # ce a tipărit preflight: indiciile pe care le citește operatorul
    return fresh


def test_a_tag_failed_service_moved_by_hand_is_held_and_resolved_through_a_new_baseline(tmp_path):
    """Eticheta de rollback pică, apoi operatorul aduce de mână containerul pe imaginea nouă și rulează din nou. Rularea citea `pulled` din
    jurnal drept proprietate și punea eticheta pe imaginea din BASELINE (rollback peste mutarea lui, și peste orice deploy intermediar,
    necunoscut). Acum d4d4 nu e nici în baseline, nici pusă de noi: rămâne `stale-baseline` (peste `tag-failed`, care se preia), nimic
    atins. Ieșirea e un baseline nou: preia `tag-failed`, iar rularea pe el pune eticheta pe imaginea care rula la ÎNCEPUTUL lui (d4d4),
    o dovedește și scrie `verified` — fără recreare."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, tag_effect="fail")
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db") == "tag-failed"
    edit_state(tmp_path, lambda st: (st.pop("tag_effect"), st["containers"]["pg-db"].update(image_id=NEW_PG),
                                     st["images"].update({"old-pg": {"id": OLD_PG, "created": "2026-10-01T00:00:00Z", "digests": 2}}),
                                     st.update(pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})))
    mark = len(verbs(tmp_path))
    held = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert held.returncode == 1 and "baseline-ul e vechi" in held.stdout, held.stdout
    assert not mutating_since(tmp_path, mark) and "rollback/maint-b/pg-db:prev" not in images_of(tmp_path)
    assert last_report(base, "pg|db") == "stale-baseline"
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG})
    assert "|tag-failed|" in (fresh / "containers.report").read_text(encoding="utf-8")
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg")
    assert p.returncode == 0, p.stdout
    assert "compose up" not in verbs(tmp_path)[mark:]
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == NEW_PG
    assert report_actions(fresh, "pg|db")[-2:] == ["tagged", "verified"], report_actions(fresh, "pg|db")
    assert last_report(fresh, "pg|db") == "verified" and not unresolved(fresh)


def test_a_compose_up_that_recreates_and_then_exits_nonzero_turns_the_run_red(tmp_path):
    """`docker compose up` poate recrea serviciul și totuși ieși cu cod nenul (un serviciu dependent, un timeout). Fixează
    comportamentul de acum: rularea iese 1 (operatorul citește), containers.ok nu se scrie, iar jurnalul spune `recreated`
    pentru că starea containerului — imaginea nouă, sănătos, stabil — S-A DOVEDIT."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, up_rc={"db": 1})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "docker compose up a ieșit cu 1" in p.stdout, p.stdout
    assert last_report(base, "pg|db") == "recreated"


def test_containers_ok_needs_every_project_processed_not_just_the_one_named_by_only(tmp_path):
    """`--only pg` procesa un proiect din două, ieșea 0 «TOTUL DOVEDIT» și scria containers.ok: verify citea apoi faza
    `containers` ca încheiată, deși `clin` nu fusese privit. Markerul se scrie doar la o rulare care a procesat TOATE
    proiectele (și n-a lăsat nimic nerezolvat)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    a = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert a.returncode == 0 and not ok_marker(base) and "containers.ok NU s-a scris" in a.stdout, a.stdout
    b = run_c(tmp_path, base, "OPT_ONLY=clin")
    assert b.returncode == 0 and not ok_marker(base), b.stdout
    both = run_c(tmp_path, base, "OPT_ONLY=pg,clin")
    assert both.returncode == 0 and ok_marker(base), both.stdout
    (base / "phases" / "containers.ok").unlink()
    full = run_c(tmp_path, base)
    assert full.returncode == 0 and ok_marker(base), full.stdout


# ---------------------------------------------------------------------------
# Runda 7: proprietatea asupra imaginii e un FAPT înregistrat, nu o deducție din jurnal
# ---------------------------------------------------------------------------
FOREIGN_PG = "sha256:" + "66" * 32


def redeploy_pg_after_baseline(tmp: Path, foreign: str = FOREIGN_PG) -> None:
    """Cineva a făcut redeploy DUPĂ baseline: containerul ȘI eticheta pg sunt pe o imagine pe care baseline-ul n-o știe. Imaginea veche
    rămâne în Docker, fără etichetă (adresabilă după ID), ca după un `docker pull` real."""
    edit_state(tmp, lambda st: (st["images"].update({"postgres:16-alpine": {"id": foreign, "created": "2026-11-20T00:00:00Z", "digests": 2},
                                                    "old-pg": {"id": OLD_PG, "created": "2026-10-01T00:00:00Z", "digests": 2}}),
                                st["containers"]["pg-db"].update(image_id=foreign)))


def mutating_since(tmp: Path, mark: int) -> set[str]:
    return set(verbs(tmp)[mark:]) & MUTATING


def full_run_stays_red(tmp: Path, base: Path, opts: str = ""):
    """O rulare FĂRĂ --only: singura care ar PUTEA scrie containers.ok. `not ok_marker` după un `--only` peste un singur proiect din
    două era adevărat oricum (rularea parțială nu scrie markerul), deci nu dovedea că eșecul nerezolvat îl blochează."""
    p = run_c(tmp, base, opts)
    assert p.returncode == 1 and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    assert not ok_marker(base)
    return p


def test_a_pull_that_finds_nothing_new_never_makes_a_foreign_image_ours(tmp_path):
    """Secvența exactă din runda 6: baseline pg-db pe c3c3, apoi un redeploy pune containerul și eticheta pe 6666. Rularea 1 `--only pg`
    (registrul n-are nimic nou) ieșea 0 «TOTUL DOVEDIT» și scria `pulled 666666666666`; rularea 2 (registrul are d4d4) citea acel rând ca
    proprietate, punea eticheta de rollback pe imaginea din BASELINE și recrea 6666 -> d4d4: comanda de rollback tipărită ar fi anulat
    redeploy-ul. Acum rezultatul e `stale-baseline` încă de la clasificare, în ambele rulări: niciun pull, tag, up; fără etichetă de
    rollback; fără `pulled`/`tagged`/`recreated`/`verified` în jurnal; containerul rămâne pe imaginea străină."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    redeploy_pg_after_baseline(tmp_path)
    one = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert one.returncode == 1 and "TOTUL DOVEDIT" not in one.stdout and "baseline-ul e vechi" in one.stdout, one.stdout
    assert "--phase preflight --new-baseline" in one.stdout
    assert not (set(verbs(tmp_path)) & MUTATING), verbs(tmp_path)
    assert last_report(base, "pg|db") == "stale-baseline"
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})        # registrul are acum d4d4
    mark = len(verbs(tmp_path))
    two = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert two.returncode == 1 and "baseline-ul e vechi" in two.stdout, two.stdout
    assert not mutating_since(tmp_path, mark), verbs(tmp_path)[mark:]
    assert RB_TAG not in images_of(tmp_path)
    acts = report_actions(base, "pg|db")
    assert not ({"pulled", "tagged", "recreated", "verified", "up-to-date"} & set(acts)), acts
    assert last_report(base, "pg|db") == "stale-baseline"
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    assert st["containers"]["pg-db"]["image_id"] == FOREIGN_PG
    assert not (base / "containers.owned").exists()


def test_a_full_run_with_a_stale_pull_service_is_red_and_never_writes_containers_ok(tmp_path):
    """Rularea completă (fără --only) cu un serviciu cu baseline vechi ieșea 0 și scria containers.ok, fără niciun avertisment: verify
    citea apoi faza ca «încheiată cu succes dovedit» peste un container pe care nimeni nu l-a verificat sub acest baseline. Acum iese
    1, numește serviciul, nu atinge nimic din el și nu scrie markerul."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    redeploy_pg_after_baseline(tmp_path)
    p = full_run_stays_red(tmp_path, base)
    assert "pg/db: baseline-ul e vechi" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING), verbs(tmp_path)
    assert last_report(base, "pg|db") == "stale-baseline"


def test_a_stale_build_service_is_held_even_without_rebuild(tmp_path):
    """oferte/dms (aplicații construite local) redeployate după baseline: fără --rebuild rularea ieșea 0 cu un simplu avertisment în
    jurnal, iar containers.ok se scria. Un serviciu de ORICE fel cu baseline vechi e ținut și roșu."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    foreign = "sha256:" + "55" * 32
    edit_state(tmp_path, lambda st: (st["images"].update({"redeployed:x": {"id": foreign, "created": "2099-01-01T00:00:00Z", "digests": 0}}),
                                     st["containers"]["clin-app"].update(image_id=foreign)))
    p = full_run_stays_red(tmp_path, base, "OPT_KEEP_GOING=1")      # fără --keep-going rularea s-ar opri la clin: markerul n-ar fi fost scris oricum
    assert "clin/app: baseline-ul e vechi" in p.stdout, p.stdout
    assert last_report(base, "clin|app") == "stale-baseline"
    assert not ({"compose build", "compose up", "tag"} & set(verbs(tmp_path))), verbs(tmp_path)       # (`pull` e al lui pg, procesat cu --keep-going)
    assert all(a[:2] != ["pull", "-q"] or a[-1] == "postgres:16-alpine" for a in docker_log(tmp_path)), docker_log(tmp_path)


def test_a_hand_move_after_the_refusal_does_not_make_the_service_ours(tmp_path):
    """După refuz, operatorul mută containerul de mână pe imaginea cea mai nouă (d4d4) și rulează din nou. Rularea citea `pulled d4d4`
    din jurnal drept proprietate, punea eticheta de rollback pe imaginea din baseline și scria `verified`: rollback-ul ar fi anulat
    redeploy-ul intermediar. Acum d4d4 nu e nici în baseline, nici văzută rulând după un `up` al nostru: rămâne roșu, fără etichetă.
    Abia readusă pe imaginea din baseline, starea se rezolvă singură (owned-ok) și rularea merge normal, cu eticheta pe imaginea care
    chiar rula atunci."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    redeploy_pg_after_baseline(tmp_path)
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    edit_state(tmp_path, lambda st: (st["images"].update({"postgres:16-alpine": {"id": NEW_PG, "created": "2026-11-21T00:00:00Z", "digests": 2}}),
                                     st["containers"]["pg-db"].update(image_id=NEW_PG)))              # mutarea de mână
    mark = len(verbs(tmp_path))
    moved = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert moved.returncode == 1 and "baseline-ul e vechi" in moved.stdout, moved.stdout
    assert not mutating_since(tmp_path, mark) and RB_TAG not in images_of(tmp_path)
    assert last_report(base, "pg|db") == "stale-baseline"
    # operatorul readuce imaginea din baseline (eticheta registrului rămâne pe d4d4 = «nimic de recreat» nu e adevărat: e ceva nou)
    edit_state(tmp_path, lambda st: (st["images"].update({"postgres:16-alpine": {"id": OLD_PG, "created": "2026-10-01T00:00:00Z", "digests": 2}}),
                                     st["containers"]["pg-db"].update(image_id=OLD_PG),
                                     st.update(pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})))
    back = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert back.returncode == 0, back.stdout
    assert last_report(base, "pg|db") == "recreated" and not unresolved(base)
    assert images_of(tmp_path)[RB_TAG]["id"] == OLD_PG


def test_an_image_we_landed_is_ours_but_a_later_foreign_deploy_is_not(tmp_path):
    """Ce a pus mentenanța însăși (recrearea dovedită pe d4d4) nu e «străin» la rulările următoare, altfel fiecare rerulare ar fi refuzată.
    Dar «a noastră» e imaginea CONCRETĂ văzută rulând după `up`: un redeploy ulterior pe altă imagine e baseline vechi, iar eticheta de
    rollback rămâne pe imaginea de dinainte de prima noastră schimbare (prev), nu se mută pe imaginea intermediară."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 0
    owned = (base / "containers.owned").read_text(encoding="utf-8").splitlines()
    assert f"pg|db|prev|{OLD_PG}" in owned and f"pg|db|landed|{NEW_PG}" in owned, owned
    again = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert again.returncode == 0 and "baseline-ul e vechi" not in again.stdout, again.stdout
    redeploy_pg_after_baseline(tmp_path)
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "baseline-ul e vechi" in p.stdout, p.stdout
    assert not mutating_since(tmp_path, mark)
    assert images_of(tmp_path)[RB_TAG]["id"] == OLD_PG
    assert last_report(base, "pg|db") == "stale-baseline"


def test_the_rollback_target_is_recorded_before_the_tag_is_attempted(tmp_path):
    """Ținta rollback-ului e imaginea pe care containerul o rula în clipa în care scriptul era pe cale să-l schimbe, scrisă ca fapt (`prev`)
    ÎNAINTE de `tag` și `up`. Dacă `docker tag` pică, faptul există oricum: rularea următoare etichetează aceeași imagine, nu una
    dedusă din ce se vede atunci."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, tag_effect="fail")
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert "compose up" not in verbs(tmp_path) and RB_TAG not in images_of(tmp_path)
    assert f"pg|db|prev|{OLD_PG}" in (base / "containers.owned").read_text(encoding="utf-8").splitlines()
    assert last_report(base, "pg|db") == "tag-failed"


def test_a_dry_run_reports_a_stale_service_red_and_writes_nothing(tmp_path):
    """`--dry-run` e fereastra prin care operatorul vede, înainte de orice, ce nu va merge. Un serviciu cu baseline vechi iese 1 cu mesajul
    și calea de ieșire, dar nu scrie nimic (nici în jurnal, nici în containers.owned)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    redeploy_pg_after_baseline(tmp_path)
    before = (base / "containers.report").read_bytes() if (base / "containers.report").exists() else b""
    p = run_c(tmp_path, base, "OPT_DRY_RUN=1")
    assert p.returncode == 1 and "pg/db: baseline-ul e vechi" in p.stdout and "--phase preflight --new-baseline" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING)
    assert not (base / "containers.owned").exists()
    assert ((base / "containers.report").read_bytes() if (base / "containers.report").exists() else b"") == before


def test_a_partial_run_keeps_a_proven_containers_ok_and_a_full_run_resets_it(tmp_path):
    """După o rulare completă verde, un `--only pg` ștergea containers.ok (`.started` îl șterge), iar verify/status ieșeau roșii
    «a pornit dar n-a ajuns la containers.ok» peste o actualizare dovedită. Acum rularea parțială își ține propria pereche de markere:
    containers.ok rămâne; dacă rularea parțială NU ajunge la capăt, markerul ei lipsește (verify o vede); o rulare completă pornește de
    la zero (markerele parțiale dispar)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base).returncode == 0 and ok_marker(base)
    ph = base / "phases"
    only = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert only.returncode == 0 and ok_marker(base) and (ph / "containers.only.started").exists() and (ph / "containers.only.ok").exists(), only.stdout
    set_state(tmp_path, flap_restart=["pg-db"])
    bad = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert bad.returncode == 1 and ok_marker(base), bad.stdout
    assert (ph / "containers.only.started").exists() and not (ph / "containers.only.ok").exists()     # încheiată NU: verify o vede
    set_state(tmp_path, flap_restart=[])
    assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg").returncode == 0 and (ph / "containers.only.ok").exists()
    full = run_c(tmp_path, base)
    assert full.returncode == 0 and ok_marker(base), full.stdout
    assert not (ph / "containers.only.started").exists() and not (ph / "containers.only.ok").exists()


def test_the_dry_run_note_about_a_moved_tag_compares_the_tag_of_now(tmp_path):
    """`NB: eticheta … arată deja o imagine construită după pornirea containerului` se tipărea comparând eticheta din BASELINE cu ce
    rulează acum: pentru un serviciu a cărui etichetă a fost mutată (build) după baseline tăcea, iar pentru una a cărei etichetă fusese
    «înainte» la baseline dar a revenit minția. Acum se compară eticheta de ACUM cu imaginea care rulează, și mesajul numește ambele ID-uri."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    edit_state(tmp_path, lambda st: st["images"].update({"clin-app:latest": {"id": NEW_APP, "created": "2099-01-01T00:00:00Z", "digests": 0},
                                                         "old-app": {"id": OLD_APP, "created": "2099-01-01T00:00:00Z", "digests": 0}}))
    moved = run_c(tmp_path, base, "OPT_DRY_RUN=1; OPT_REBUILD=clin; OPT_ONLY=clin")
    assert f"NB: eticheta clin-app:latest arată acum imaginea {NEW_APP[7:19]}, iar containerul rulează {OLD_APP[7:19]}" in moved.stdout, moved.stdout
    # baseline-ul a văzut eticheta «înainte» (snipeit-app), dar între timp a revenit pe ce rulează: nu mai e nimic de spus
    sub = tmp_path / "b"
    sub.mkdir()
    base2 = containers_fixture(sub, ctx_clean=True)
    tsv = (base2 / "containers.tsv").read_text(encoding="utf-8").replace(f"|{OLD_APP}|{OLD_APP}|", f"|{OLD_APP}|{NEW_APP}|")
    (base2 / "containers.tsv").write_text(tsv, encoding="utf-8", newline="\n")
    quiet = run_c(sub, base2, "OPT_DRY_RUN=1; OPT_REBUILD=clin; OPT_ONLY=clin")
    assert "NB: eticheta" not in quiet.stdout and "build din" in quiet.stdout, quiet.stdout


def test_a_container_changed_between_classification_and_tagging_is_neither_tagged_nor_recreated(tmp_path):
    """Între clasificare și etichetare au trecut pull-uri și build-uri (minute). Dacă cineva redeployează serviciul în fereastra aia, eticheta
    de rollback pusă pe imaginea citită la clasificare ar anula deploy-ul lui, iar `up` ar recrea peste el. Faptul se citește din nou
    chiar înainte de `tag`: containerul rulează altceva decât ce s-a clasificat => nicio etichetă, niciun `up`, `tag-failed` cu motivul numit."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, swap_on_pull={"postgres:16-alpine": {"container": "pg-db", "image_id": FOREIGN_PG}})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "l-a schimbat altcineva între timp" in p.stdout, p.stdout
    assert "tag" not in verbs(tmp_path) and "compose up" not in verbs(tmp_path), verbs(tmp_path)
    assert RB_TAG not in images_of(tmp_path) and last_report(base, "pg|db") == "tag-failed"
    owned = (base / "containers.owned").read_text(encoding="utf-8").splitlines() if (base / "containers.owned").exists() else []
    assert not [l for l in owned if "|prev|" in l or "|landed|" in l], owned      # (`pulled` e un fapt despre pull-ul făcut, scris înainte; `prev`/`landed` ar însemna tag/up)


# ---------------------------------------------------------------------------
# Runda 8: un eșec preluat într-un baseline nou are o ieșire care funcționează, iar ce îl rezolvă nu e mai blând decât ce l-a produs
# ---------------------------------------------------------------------------
def hint_values(stdout: str, flag: str) -> set[str]:
    """Valorile pe care mesajele le dau lui `flag` (fără substituenții «PROIECT»/«PROIECT/SERVICIU»): comanda din indiciu, ca operatorul s-o copieze.
    Testele de ieșire urmează TEXTUL tipărit, nu o valoare scrisă de mână în test — un indiciu care numește altceva decât ce funcționează pică aici."""
    return {m for m in re.findall(re.escape(flag) + r" ([A-Za-z0-9_./,-]+)", stdout) if m not in ("PROIECT", "PROIECT/SERVICIU")}


def failed_pg(tmp_path, **fx):
    """pg-db recreat pe imaginea nouă și picat (unhealthy) -> `failed`; `fx` trece mai departe la containers_fixture (de pildă two_pull)."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}}, **fx)
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db") == "failed"
    return base


def test_a_carried_failed_is_not_resolved_by_a_new_baseline_taken_while_the_service_was_still_broken(tmp_path):
    """Secvența exactă din runda 7: recrearea pică (unhealthy) -> `failed`; operatorul ia un baseline nou CÂT containerul e încă unhealthy, deci
    baseline-ul nou are sănătatea «unhealthy». `--retry-failed pg` (comanda din indiciu) verifica față de el: «stabil, dar unhealthy — ca la
    baseline», `failed` se rezolva, faza ieșea 0 «TOTUL DOVEDIT» și scria containers.ok peste un container încă stricat. Acum eșecul preluat
    poartă sănătatea de DINAINTE de eșec (healthy): unhealthy rămâne `failed` și roșu; abia un container sănătos îl rezolvă."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert "pg|db|B|base_health|healthy" in (fresh / "containers.episode").read_text(encoding="utf-8").splitlines()
    plain = run_c(tmp_path, fresh, "OPT_ONLY=pg")
    assert plain.returncode == 1 and hint_values(plain.stdout, "--retry-failed") == {"pg"}, plain.stdout
    retry = run_c(tmp_path, fresh, f"OPT_ONLY=pg; OPT_RETRY_FAILED={next(iter(hint_values(plain.stdout, '--retry-failed')))}")
    assert retry.returncode == 1 and "TOTUL DOVEDIT" not in retry.stdout and "stabil, dar unhealthy" not in retry.stdout, retry.stdout
    assert "sănătatea de dinainte de eșec (healthy)" in retry.stdout, retry.stdout
    assert last_report(fresh, "pg|db") == "failed" and unresolved(fresh)
    full = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert full.returncode == 1 and not ok_marker(fresh), full.stdout
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))       # control: un container sănătos îl rezolvă
    fixed = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert fixed.returncode == 0 and ok_marker(fresh) and not unresolved(fresh), fixed.stdout


def test_the_health_before_the_failure_survives_a_chain_of_new_baselines(tmp_path):
    """Un al doilea `--new-baseline` (încă unhealthy) nu are voie să înlocuiască sănătatea de dinainte de eșec cu cea din primul baseline nou:
    se preia mai departe cea originală, altfel lanțul B -> B2 -> B3 ar fi rezolvat `failed` în B3 la fel ca înainte de repararea din runda 8."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    assert "pg|db|B|base_health|healthy" in (b3 / "containers.episode").read_text(encoding="utf-8").splitlines()
    retry = run_c(tmp_path, b3, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and last_report(b3, "pg|db") == "failed", retry.stdout


@pytest.mark.parametrize("sibling", [False, True], ids=["project-gone", "project-keeps-a-running-sibling"])
def test_a_carried_failure_of_a_service_with_no_container_at_all_is_closed_by_the_new_baseline_without_an_acknowledge(tmp_path, sibling):
    """REESCRIS în runda 12 (decizia operatorului: «dispărut» = absent, nu «nu rulează»). Serviciul `failed` a fost SCOS din compose până la baseline-ul nou: niciun
    container al lui, în nicio stare. Nu e în lista lui de proiecte (`--retry-failed pg` era refuzat), ori e sărit ca `skip-not-running`; singura ieșire era
    `--acknowledge`, iar un al treilea baseline îl prelua iar. Carry-ul închide episodul singur (`episode-closed` în jurnal): rularea simplă iese verde fără nicio
    comandă, și cu un frate care încă rulează în proiect. Varianta cu containerul OPRIT (versiunea din runda 11 închidea și ea) e acum testul de mai jos: rămâne roșu."""
    base = failed_pg(tmp_path, two_pull=sibling)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, drop={"db"})
    assert any(l.startswith("pg|db|episode-closed|[episod=B] ") for l in (fresh / "containers.report").read_text(encoding="utf-8").splitlines())
    assert not unresolved(fresh) and not final_of(fresh, "pg/db", "acked")
    plain = run_c(tmp_path, fresh)
    assert plain.returncode == 0 and ok_marker(fresh) and "TOTUL DOVEDIT" in plain.stdout and "NERESOLVAT" not in plain.stdout, plain.stdout
    assert "acked" not in report_actions(fresh, "pg|db")
    if not sibling:
        retry = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
        assert retry.returncode == 1 and "niciun proiect compose cu numele ăsta" in retry.stdout and "--phase preflight --new-baseline" in retry.stdout, retry.stdout


def test_acknowledge_refuses_a_key_with_nothing_unresolved_and_writes_nothing(tmp_path):
    """`--acknowledge pg/dbb` (typo) sau un serviciu sănătos nu are voie să scrie un `acked` care să arate ca o decizie: faza se oprește înainte de
    orice scriere, cu numele cheii. Un dry-run descrie ce ar recunoaște, dar nu scrie și rămâne roșu."""
    base = failed_pg(tmp_path)
    before = (base / "containers.report").read_bytes()
    typo = run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/dbb")
    assert typo.returncode == 1 and "--acknowledge pg/dbb: serviciul n-are nicio stare lipicioasă" in typo.stdout, typo.stdout
    healthy = run_c(tmp_path, base, "OPT_ACKNOWLEDGE=clin/app")
    assert healthy.returncode == 1 and "--acknowledge clin/app: serviciul n-are nicio stare" in healthy.stdout, healthy.stdout
    assert (base / "containers.report").read_bytes() == before
    dry = run_c(tmp_path, base, "OPT_DRY_RUN=1; OPT_ACKNOWLEDGE=pg/db")
    assert dry.returncode == 1 and "dry-run: nu scriu nimic" in dry.stdout and (base / "containers.report").read_bytes() == before, dry.stdout


def test_acknowledge_never_clears_a_stale_baseline(tmp_path):
    """`stale-baseline` se rezolvă printr-un baseline nou sau readucerea containerului, nu prin recunoaștere: un `acked` peste el ar fi fost
    rescris de clasificarea din aceeași rulare, dar ar fi lăsat în jurnal o «decizie» care n-a decis nimic. Cheia e refuzată, cu motivul."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    redeploy_pg_after_baseline(tmp_path)
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "stale-baseline"
    p = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db")
    assert p.returncode == 1 and "stale-baseline nu se recunoaște" in p.stdout and "acked" not in report_actions(base, "pg|db"), p.stdout


def pull_failed_after_our_own_pull_moved_the_tag(tmp: Path, *, tag_now: str):
    """pg-db trage NEW_PG (eticheta se mută, containerul rămâne pe OLD_PG), pg-db2 pică la pull: tot proiectul oprit, ambele `pull-failed`. Baseline
    nou luat acum: containerul rulează încă OLD_PG, eticheta arată `tag_now`. Registrul funcționează la rularea următoare."""
    base = containers_fixture(tmp, ctx_clean=True, two_pull=True,
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 1, "new_id": None}})
    assert run_c(tmp, base, "OPT_ONLY=pg").returncode == 1
    assert last_report(base, "pg|db") == "pull-failed" and last_report(base, "pg|db2") == "pull-failed"
    assert f"pg|db|pulled|{NEW_PG}|{OLD_PG}" in (base / "containers.owned").read_text(encoding="utf-8").splitlines()
    fresh = new_baseline_like_preflight(tmp, base, {}, tags={"db": tag_now})
    set_state(tmp, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 0, "new_id": None}})
    return fresh


def test_a_carried_pull_failed_whose_tag_was_moved_by_our_own_pull_is_retried_not_held_forever(tmp_path):
    """Pull-ul nostru mută eticheta pe imaginea nouă, apoi alt serviciu din proiect pică la pull și proiectul se oprește: containerul rămâne pe
    imaginea veche. Baseline-ul nou vedea «eticheta ≠ ce rulează» (hold-moved-tag) la FIECARE rulare, iar indiciul pull-failed («rulează din nou»)
    nu avea cum s-o ridice. Acum faptul `pulled` (scris la pull, preluat odată cu eșecul) recunoaște eticheta ca mutată de noi: rularea numită în
    indiciu recreează pg-db, rezolvă ambele `pull-failed`, iar eticheta de rollback a baseline-ului nou arată imaginea de dinainte."""
    fresh = pull_failed_after_our_own_pull_moved_the_tag(tmp_path, tag_now=NEW_PG)
    carried = (tmp_path / "carry.out").read_text(encoding="utf-8")
    proj = hint_values(carried, "--only")
    assert proj == {"pg"}, carried
    p = run_c(tmp_path, fresh, f"OPT_ONLY={next(iter(proj))}")
    assert p.returncode == 0 and "(hold-moved-tag)" not in p.stdout, p.stdout
    assert last_report(fresh, "pg|db") == "recreated" and last_report(fresh, "pg|db2") == "verified" and not unresolved(fresh), p.stdout
    st = json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))
    assert st["containers"]["pg-db"]["image_id"] == NEW_PG
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG


def test_a_tag_moved_by_someone_else_is_still_held_after_a_new_baseline(tmp_path):
    """Control pentru testul de mai sus: scutirea e DOAR pentru ID-ul exact pe care l-a tras mentenanța. Dacă baseline-ul nou vede eticheta pe ALT
    ID (cineva a tras altceva între timp), `hold-moved-tag` rămâne: o recreare ar sări peste versiunile dintre ele (migrări la pornire)."""
    fresh = pull_failed_after_our_own_pull_moved_the_tag(tmp_path, tag_now=NEWER_PG)
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg")
    assert "hold-moved-tag" in p.stdout and p.returncode == 1, p.stdout
    assert "compose up" not in verbs(tmp_path) and last_report(fresh, "pg|db") == "pull-failed", verbs(tmp_path)


def test_a_stale_service_holds_its_pullable_sibling_too(tmp_path):
    """dms pe gazdă: `app` rulează o imagine de după baseline (stale), `db` (pgvector) are un pull de făcut. `refuse=1` ține TOT proiectul; fără el,
    db era tras, etichetat și recreat în timp ce app rămânea necunoscut — nicio rulare de dinainte n-avea un frate cu pull, deci nimeni nu vedea.
    Nimic mutator în refuz; controlul: cu app readus pe imaginea din baseline, același frate chiar e tras și recreat (fixture-ul nu e stricat)."""
    base = containers_fixture(tmp_path, ctx_clean=True, two_pull=True, pull={"redis:7": {"rc": 0, "new_id": NEW_R}})
    redeploy_pg_after_baseline(tmp_path)
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "pg/db: baseline-ul e vechi" in p.stdout and "pg: refuzat" in p.stdout, p.stdout
    assert not (set(verbs(tmp_path)) & MUTATING), verbs(tmp_path)
    assert not ({"pulled", "tagged", "recreated"} & set(report_actions(base, "pg|db2"))), report_actions(base, "pg|db2")
    assert "rollback/maint-b/pg-db2:prev" not in images_of(tmp_path)
    edit_state(tmp_path, lambda st: (st["images"].update({"postgres:16-alpine": {"id": OLD_PG, "created": "2026-10-01T00:00:00Z", "digests": 2}}),
                                     st["containers"]["pg-db"].update(image_id=OLD_PG)))
    ok = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert ok.returncode == 0 and last_report(base, "pg|db2") == "recreated", ok.stdout


def test_a_failed_service_hold_does_not_hide_a_redeploy_nor_let_its_sibling_through(tmp_path):
    """db `failed` și redeployat de altcineva după baseline, db2 cu un pull de făcut: reținerea lui `failed` venea ÎNAINTEA verificării proprietății,
    deci rularea simplă trăgea, etichetaba și recrea db2 fără să spună «baseline-ul e vechi». Apoi, după ce operatorul readuce containerul pe
    imaginea pusă de noi, `stale-baseline` (afișat peste `failed`) nu are voie să facă reținerea lui `failed` să dispară: rularea următoare ar fi
    tras și recreat peste un `failed` nerezolvat."""
    base = containers_fixture(tmp_path, ctx_clean=True, two_pull=True, up_effect="recreate_unhealthy",
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "failed"
    edit_state(tmp_path, lambda st: (st["containers"]["pg-db"].update(image_id=FOREIGN_PG), st.update(pull_effect={"redis:7": {"rc": 0, "new_id": NEW_R}})))
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "pg/db: baseline-ul e vechi" in p.stdout, p.stdout
    assert not mutating_since(tmp_path, mark), verbs(tmp_path)[mark:]
    assert last_report(base, "pg|db") == "stale-baseline"
    assert "rollback/maint-b/pg-db2:prev" not in images_of(tmp_path)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(image_id=NEW_PG))        # operatorul readuce imaginea pusă de noi
    mark = len(verbs(tmp_path))
    held = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert held.returncode == 1 and last_report(base, "pg|db") == "failed", held.stdout
    log = docker_log(tmp_path)[mark:]          # frații trec (un `failed` nu refuză proiectul), dar `db` însuși nu se trage și nu se recreează
    assert ["pull", "-q", "postgres:16-alpine"] not in log and not [a for a in log if "up" in a and a[-1] == "db"], log


def test_a_foreign_image_in_the_tag_to_up_window_is_not_recorded_as_landed(tmp_path):
    """Un redeploy străin în fereastra dintre `tag` și `up`: containerul iese din `up` pe ALTĂ imagine decât cea voită. `landed` înseamnă «imaginea
    VOITĂ am văzut-o rulând»: dacă s-ar scrie orice rulează după `up`, imaginea străină ar deveni «a noastră» și o reîncercare ar recrea peste
    ea, anulând deploy-ul. Acum nu se scrie niciun `landed`, iar `--retry-failed` e ținut ca baseline vechi (nimic mutator)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    set_state(tmp_path, up_image={"db": FOREIGN_PG})
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "nu cea așteptată" in p.stdout, p.stdout
    owned = (base / "containers.owned").read_text(encoding="utf-8").splitlines()
    assert f"pg|db|prev|{OLD_PG}" in owned and not [l for l in owned if "|landed|" in l], owned
    set_state(tmp_path, up_image={})
    mark = len(verbs(tmp_path))
    retry = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "baseline-ul e vechi" in retry.stdout, retry.stdout
    assert not mutating_since(tmp_path, mark), verbs(tmp_path)[mark:]


def test_a_service_with_no_recorded_rollback_target_and_not_on_the_baseline_image_is_not_given_a_guessed_one(tmp_path):
    """Containerul rulează o imagine pe care am pus-o noi (`landed`), dar faptul `prev` lipsește din containers.owned (fișier pierdut, scriere căzută).
    Ținta rollback-ului n-are voie ghicită din ce rulează acum — ar putea fi chiar imaginea picată: nicio etichetă, niciun `up`, `tag-failed` cu
    motivul numit."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}})
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(image_id=NEW_PG))
    (base / "containers.owned").write_text(f"pg|db|landed|{NEW_PG}\n", encoding="utf-8", newline="\n")
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and "nu există o imagine «de dinainte de mentenanță» înregistrată" in p.stdout, p.stdout
    assert "tag" not in verbs(tmp_path) and "compose up" not in verbs(tmp_path), verbs(tmp_path)
    assert RB_TAG not in images_of(tmp_path) and last_report(base, "pg|db") == "tag-failed"


def test_a_dry_run_result_is_marked_dry_in_the_result_file(tmp_path):
    """`containers --dry-run` scrie runs/containers-<id>.result ca orice fază, iar `status` citea ultimul rezultat: o simulare roșie întorcea
    verdictul în EȘEC peste o fază verde în serios. Rezultatul își declară natura (`dry_run=1`); o rulare în serios, nu."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    redeploy_pg_after_baseline(tmp_path)
    assert run_c(tmp_path, base, "OPT_DRY_RUN=1").returncode == 1
    (result,) = (tmp_path / "state" / "runs").glob("containers-*.result")
    text = result.read_text(encoding="utf-8")
    assert "dry_run=1" in text and "rc=1" in text, text
    result.unlink()
    run_c(tmp_path, base, "OPT_ONLY=pg")
    (real,) = (tmp_path / "state" / "runs").glob("containers-*.result")
    assert "dry_run=0" in real.read_text(encoding="utf-8")


def test_acknowledge_is_parsed_with_project_service_keys_and_follows_the_list_rules(tmp_path):
    """`--acknowledge` are valori `proiect/serviciu`. Aceleași reguli B1 ca la liste: o valoare care începe cu `-` (`--acknowledge --dry-run`
    ar porni rularea în serios, cu `--dry-run` drept valoare), una fără `/`, cu `;` sau cu o cheie goală sunt refuzate cu 2, înainte de orice
    atingere; fazele care nu-l cunosc îl refuză."""
    bindir = make_bin(tmp_path, {})
    ok = host_run(tmp_path, 'PHASE=containers; parse_args --only a --acknowledge pg/db,clin/app; echo "ACK=[$OPT_ACKNOWLEDGE] ONLY=[$OPT_ONLY]"', bindir)
    assert ok.returncode == 0 and "ACK=[pg/db,clin/app] ONLY=[a]" in ok.stdout, ok.stdout + ok.stderr
    loop = ('PHASE=containers; for v in --dry-run -a/b pg pg/ /db pg/db,x "pg/db;x" "pg/db,,a/b" ""; do '
            'rc=0; ( parse_args --acknowledge "$v" ) 2> /dev/null || rc=$?; echo "[$v]=$rc"; done; rc=0; (parse_args --acknowledge) 2> /dev/null || rc=$?; echo "[missing]=$rc"')
    bad = host_run(tmp_path, loop, bindir)
    for v in ("--dry-run", "-a/b", "pg", "pg/", "/db", "pg/db,x", "pg/db;x", "pg/db,,a/b", "", "missing"):
        assert f"[{v}]=2" in bad.stdout, (v, bad.stdout)
    os_ = host_run(tmp_path, "PHASE=os; parse_args --acknowledge a/b", bindir)
    assert os_.returncode == 2 and "nu se aplică fazei os" in os_.stderr, os_.stderr


# ---------------------------------------------------------------------------
# Runda 9: un eșec preluat poartă EPISODUL lui (intrările față de care a fost judecat), iar ce îl rezolvă e o singură funcție
# ---------------------------------------------------------------------------
def tsv_edit(base: Path, fn) -> None:
    rows = [l.split("|") for l in (base / "containers.tsv").read_text(encoding="utf-8").splitlines()]
    fn(rows)
    (base / "containers.tsv").write_text("".join("|".join(r) + "\n" for r in rows), encoding="utf-8", newline="\n")


def episode_lines(base: Path) -> list[str]:
    f = base / "containers.episode"
    return f.read_text(encoding="utf-8").splitlines() if f.exists() else []


def final_of(base: Path, key: str, mode: str = "") -> list[str]:
    out = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(base / 'containers.report')}' {mode}").stdout.splitlines()
    return [l for l in out if l.startswith(key + "|")]


def test_f1_a_carried_failed_with_a_starting_baseline_is_not_resolved_over_an_unhealthy_container(tmp_path):
    """F1 (runda 8): `su_stricter_health` punea `starting` sub `unhealthy`, dar `su_container_verdict` îl socotește pe `starting` mai exigent: cu sănătatea
    preluată `starting`, `--retry-failed` rezolva eșecul peste un container încă unhealthy și scria containers.ok. Acum același `su_container_verdict`
    judecă episodul: (starting -> unhealthy) e `worse`, eșecul rămâne roșu; abia un container healthy îl rezolvă."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy", pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}})
    tsv_edit(base, lambda rows: [r.__setitem__(7, "starting") for r in rows if r[0] == "pg-db"])
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "failed"
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert "pg|db|B|base_health|starting" in episode_lines(fresh), episode_lines(fresh)
    retry = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "TOTUL DOVEDIT" not in retry.stdout, retry.stdout
    assert "față de sănătatea de dinainte de eșec (starting) verdictul e worse" in retry.stdout, retry.stdout
    assert last_report(fresh, "pg|db") == "failed" and unresolved(fresh)
    assert "|failed|[episod=B] pg-db" in (fresh / "containers.report").read_text(encoding="utf-8")      # o reîncercare care pică din nou rămâne în episodul preluat
    full = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert full.returncode == 1 and not ok_marker(fresh), full.stdout
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    fixed = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert fixed.returncode == 0 and ok_marker(fresh) and not unresolved(fresh), fixed.stdout


def test_a_carried_failed_is_judged_by_the_new_baseline_too_not_only_by_its_episode(tmp_path):
    """Două judecăți, aceeași funcție: episodul ȘI baseline-ul nou. Episodul spune `none` (serviciul n-avea healthcheck când a picat), baseline-ul nou
    `healthy` (are acum), iar containerul de acum nu mai are healthcheck: față de episod e `ok`, față de baseline e `unknown` (nu mai putem spune nimic
    despre sănătate). Un verdict doar din episod ar rezolva `failed` peste un container pe care nu-l mai poate judeca nimeni (mutația V4)."""
    base = failed_pg(tmp_path)
    tsv_edit(base, lambda rows: [r.__setitem__(7, "none") for r in rows if r[0] == "pg-db"])
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "healthy"})
    assert "pg|db|B|base_health|none" in episode_lines(fresh), episode_lines(fresh)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health=None))
    retry = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "verdict unknown" in retry.stdout, retry.stdout
    assert last_report(fresh, "pg|db") == "failed" and unresolved(fresh)


def test_f2_a_chain_of_three_baselines_keeps_the_episode_the_failure_was_judged_under_not_a_resolved_one(tmp_path):
    """F2 (runda 8): `carry_forward_sticky` prefera o linie `carried` veche, a unui episod deja REZOLVAT, în fața sănătății față de care eșecul de acum
    a fost judecat; mutația «folosește doar sănătatea preluată» (V4) trecea de tot fișierul. Lanț B -> B2 -> B3: în B, db e unhealthy și pull-ul pică
    (episodul B: unhealthy); în B2 serviciul se repară, pull-ul reușește (episodul B se rezolvă); tot în B2 o recreare pică (episod NOU, B2: healthy).
    B3 are db încă unhealthy: preia episodul B2 (healthy), nu înregistrările lui B. Cu `unhealthy` în loc de `healthy`, același-rău ar fi rezolvat eșecul."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    tsv_edit(base, lambda rows: [r.__setitem__(7, "unhealthy") for r in rows if r[0] == "pg-db"])
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "pull-failed"
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    b2 = new_baseline_like_preflight(tmp_path, base, {}, health={"db": "healthy"})
    assert "pg|db|B|base_health|unhealthy" in episode_lines(b2)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    resolved = run_c(tmp_path, b2, "")
    assert resolved.returncode == 0 and last_report(b2, "pg|db") == "verified" and not unresolved(b2), resolved.stdout
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    assert run_c(tmp_path, b2, "").returncode == 1 and last_report(b2, "pg|db") == "failed"
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    eps = [l for l in episode_lines(b3) if l.startswith("pg|db|")]
    assert "pg|db|B2|base_health|healthy" in eps and not [l for l in eps if l.startswith("pg|db|B|")], eps
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    retry = run_c(tmp_path, b3, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and last_report(b3, "pg|db") == "failed" and unresolved(b3), retry.stdout
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))        # control: containerul sănătos îl rezolvă
    fixed = run_c(tmp_path, b3, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert fixed.returncode == 0 and not unresolved(b3), fixed.stdout


def test_a_chain_keeps_the_original_episode_id_and_records_unchanged(tmp_path):
    """Un lanț B -> B2 -> B3 pentru ACELAȘI eșec nerezolvat păstrează episodul original (ID-ul `B`, aceleași înregistrări, copiate ca atare): dacă B3 l-ar
    rescrie ca «episodul lui B2», sănătatea ar fi cea măsurată cât serviciul era deja stricat."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    assert [l for l in episode_lines(b3) if l.startswith("pg|db|")] == [l for l in episode_lines(b2) if l.startswith("pg|db|")]
    assert "[episod=B] preluat din baseline-ul B2" in (b3 / "containers.report").read_text(encoding="utf-8")
    assert f"pg|db|B|prev|{OLD_PG}" in episode_lines(b3)


def acknowledged_unhealthy_built_service(tmp_path):
    """clin/app (construit local) `failed`, preluat într-un baseline nou cât e încă unhealthy, apoi recunoscut de operator într-o rulare COMPLETĂ (proiectul
    clin se procesează: aplicația construită, fără --rebuild, ar scrie `skip-not-requested`)."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    (base / "containers.report").write_text("clin|app|failed|clin-app\n", encoding="utf-8", newline="\n")
    edit_state(tmp_path, lambda st: st["containers"]["clin-app"].update(health="unhealthy"))
    b2 = new_baseline_like_preflight(tmp_path, base, {}, health={"app": "unhealthy"})
    p = run_c(tmp_path, b2, "OPT_ACKNOWLEDGE=clin/app")
    return b2, p


def test_f3_an_acknowledged_service_stays_acked_when_its_project_is_still_processed(tmp_path):
    """F3 (runda 8): `acked` era înlocuit în aceeași rulare de `skip-not-requested` (aplicație construită), `skip-not-running` sau un `hold-*`, iar verify
    nu mai arăta nimic și faza ieșea verde fără un cuvânt despre recunoaștere. Acum serviciul recunoscut nu se atinge în rularea aceea, `acked` rămâne rezultatul
    lui final (și în rulările următoare, în fața oricărui skip/hold), iar verify îl arată ca avertisment cu cheia serviciului."""
    b2, p = acknowledged_unhealthy_built_service(tmp_path)
    assert p.returncode == 0, p.stdout
    assert final_of(b2, "clin/app")[0].startswith("clin/app|acked|") and "skip-not-requested" not in (b2 / "containers.report").read_text(encoding="utf-8").split("acked")[-1]
    bindir = make_bin(tmp_path, {}, docker=True)
    v = host_run(tmp_path, f"PHASE=verify; BASE='{posix(b2)}'; verify_summary", bindir)
    assert "clin/app: recunoscut de operator (--acknowledge), NERESOLVAT în fapt" in v.stdout, v.stdout
    assert "clin/app: acked" in v.stdout.split("Sărit sau eșuat")[-1], v.stdout
    again = run_c(tmp_path, b2, "")
    assert again.returncode == 0 and final_of(b2, "clin/app")[0].startswith("clin/app|acked|"), again.stdout


def test_f7_the_phase_always_prints_the_acknowledged_but_unresolved_warning(tmp_path):
    """F7 (runda 8): niciun test nu asserta avertismentul fazei «recunoscut de operator, NERESOLVAT în fapt»; ștergerea lui (mutația V13) trecea tot fișierul.
    Fără el, o rulare verde ar spune «TOTUL DOVEDIT» peste un serviciu pe care operatorul l-a recunoscut ca nerezolvat. Se tipărește cu cheia serviciului la
    FIECARE rulare (și simulare), nu doar la cea care a scris `acked`."""
    b2, _ = acknowledged_unhealthy_built_service(tmp_path)
    for opts in ("", "OPT_DRY_RUN=1", "OPT_ONLY=pg"):
        p = run_c(tmp_path, b2, opts)
        assert "clin/app: recunoscut de operator, NERESOLVAT în fapt" in p.stdout, (opts, p.stdout)


def test_status_shows_every_acknowledged_service_as_a_warning_with_its_key(tmp_path):
    """`status` nu pomenea nicio recunoaștere: după un `--acknowledge`, «nimic eșuat sau neterminat» ar fi arătat verde peste un serviciu nerezolvat.
    Acum linia (avertisment, cu cheia) apare mereu; verdictul nu se schimbă (o recunoaștere e o decizie, nu un eșec nou)."""
    b2, _ = acknowledged_unhealthy_built_service(tmp_path)
    bindir = make_bin(tmp_path, {"systemctl": systemctl_shim(active=(), installed=())}, docker=True)
    p = host_run(tmp_path, f"PHASE=status; init_state; BASE='{posix(b2)}'; phase_status", bindir)
    assert "[!] clin/app: recunoscut de operator (--acknowledge), NERESOLVAT în fapt" in p.stdout, p.stdout + p.stderr


def pulled_by_us_then_foreign_redeploy(tmp: Path):
    """B: pull-ul nostru mută eticheta pg pe NEW_PG (containerul rulează OLD_PG), redis pică la pull -> ambele `pull-failed`. Apoi altcineva redeployează
    pg-db pe FOREIGN_PG (eticheta rămâne pe NEW_PG) și se ia un baseline nou: eticheta = ce am tras noi, dar containerul nu mai rulează ce rula atunci."""
    base = containers_fixture(tmp, ctx_clean=True, two_pull=True,
                              pull={"postgres:16-alpine": {"rc": 0, "new_id": NEW_PG}, "redis:7": {"rc": 1, "new_id": None}})
    assert run_c(tmp, base, "OPT_ONLY=pg").returncode == 1
    edit_state(tmp, lambda st: (st["containers"]["pg-db"].update(image_id=FOREIGN_PG),
                                st["images"].update({"hotfix:pinned": {"id": FOREIGN_PG, "created": "2026-11-20T00:00:00Z", "digests": 0}})))
    fresh = new_baseline_like_preflight(tmp, base, {"db": FOREIGN_PG}, tags={"db": NEW_PG})
    set_state(tmp, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}, "redis:7": {"rc": 0, "new_id": None}})
    return fresh


def test_f4_the_moved_tag_exemption_needs_the_container_to_still_run_what_it_ran_at_our_pull(tmp_path):
    """F4 (runda 8): scutirea `pulled` verifica doar că ID-ul etichetei din baseline e unul tras de noi. Un redeploy străin (pg-db rulează altceva) urmat de
    un baseline nou lăsa eticheta pe ce trăsesem noi, iar `hold-moved-tag` era ocolit: mentenanța recrea peste deploy-ul străin. Acum scutirea cere și ca
    imaginea care rulează să fie cea înregistrată la pull: aici nu e, deci `hold-moved-tag` și nimic mutator."""
    fresh = pulled_by_us_then_foreign_redeploy(tmp_path)
    assert f"pg|db|B|pulled|{NEW_PG}|{OLD_PG}" in episode_lines(fresh), episode_lines(fresh)
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg")
    assert p.returncode == 1 and "hold-moved-tag" in p.stdout, p.stdout
    assert not mutating_since(tmp_path, mark) - {"pull"} and "compose up" not in verbs(tmp_path)[mark:], verbs(tmp_path)[mark:]     # frații trag (hold e pe serviciu); pg-db nu se recreează
    assert last_report(fresh, "pg|db") == "pull-failed" and json.loads((tmp_path / "docker-state.json").read_text(encoding="utf-8"))["containers"]["pg-db"]["image_id"] == FOREIGN_PG


def test_f5_a_retried_carried_failure_rolls_back_to_the_image_before_our_change_not_the_failed_one(tmp_path):
    """F5 (runda 8): carry-ul nu purta `prev`. La reîncercarea unui `failed` preluat, containerul rulează imaginea picată (e și cea din baseline-ul nou), deci
    eticheta de rollback a baseline-ului nou ajungea pe ea, iar indiciul tipărit ducea operatorul tocmai pe imaginea care a picat — contra antetului
    modulului. Acum eticheta pleacă de la `prev` din episod (OLD_PG), iar indiciul o numește și arată ce imagine indică."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert f"pg|db|B|prev|{OLD_PG}" in episode_lines(fresh)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}})
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and last_report(fresh, "pg|db") == "failed", p.stdout
    tags = images_of(tmp_path)
    assert tags["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG != NEW_PG, tags
    assert f"rollback: docker tag rollback/maint-b2/pg-db:prev" in p.stdout and f"eticheta arată {OLD_PG[7:19]}" in p.stdout, p.stdout


def test_f5_a_retry_without_recreate_still_tags_the_episode_prev_so_the_printed_hint_points_at_a_real_tag(tmp_path):
    """Aplicație construită, recreată și picată; baseline nou; `--retry-failed` fără `--rebuild` doar RE-VERIFICĂ (nu recreează, deci nu trece prin pasul de
    tag din execute_changes). Dacă verificarea pică, indiciul de rollback ar trimite la o etichetă a baseline-ului nou care nu există. Acum eticheta se
    pune pe `prev` din episod înainte de re-verificare, iar indiciul numește o etichetă care există și arată imaginea de dinainte."""
    base = containers_fixture(tmp_path, ctx_clean=True, up_effect="recreate_unhealthy", build={"app": {"rc": 0, "new_id": NEW_APP}})
    assert run_c(tmp_path, base, "OPT_ONLY=clin; OPT_REBUILD=clin").returncode == 1 and last_report(base, "clin|app") == "failed"
    fresh = new_baseline_like_preflight(tmp_path, base, {"app": NEW_APP}, health={"app": "unhealthy"})
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, fresh, "OPT_ONLY=clin; OPT_RETRY_FAILED=clin")
    assert p.returncode == 1 and last_report(fresh, "clin|app") == "failed" and not mutating_since(tmp_path, mark) - {"tag"}, p.stdout
    assert images_of(tmp_path)["rollback/maint-b2/clin-app:prev"]["id"] == OLD_APP, images_of(tmp_path).keys()
    assert "rollback: docker tag rollback/maint-b2/clin-app:prev" in p.stdout and f"eticheta arată {OLD_APP[7:19]}" in p.stdout, p.stdout


def test_f5_a_carried_failure_with_no_recorded_prev_gets_no_guessed_rollback_target(tmp_path):
    """Defensiv: episodul unui `failed` preluat fără `prev` (înregistrare pierdută). Containerul rulează imaginea picată: «imaginea de acum» ar fi ținta
    greșită. Nicio etichetă, niciun `up`, `tag-failed` cu motivul numit — ca la un serviciu fără țintă de rollback în baseline-ul obișnuit."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "healthy"})
    keep = [l for l in episode_lines(fresh) if "|prev|" not in l]
    (fresh / "containers.episode").write_text("\n".join(keep) + "\n", encoding="utf-8", newline="\n")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}})
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and "nu are înregistrată imaginea de dinainte de schimbare" in p.stdout, p.stdout
    assert not mutating_since(tmp_path, mark) - {"pull"} and "rollback/maint-b2/pg-db:prev" not in images_of(tmp_path), verbs(tmp_path)[mark:]
    assert "tag" not in verbs(tmp_path)[mark:] and "compose up" not in verbs(tmp_path)[mark:]
    assert [l.split("|")[1] for l in final_of(fresh, "pg/db", "all")] == ["failed", "tag-failed"], final_of(fresh, "pg/db", "all")


def test_a_carried_failure_with_no_recorded_health_cannot_be_resolved_by_a_retry(tmp_path):
    """Lipsa sănătății din episod (fișier pierdut) nu e «sănătos»: `--retry-failed` peste un container perfect sănătos nu rezolvă eșecul, cu motivul numit,
    iar ieșirea rămâne `--acknowledge`. «Necunoscut» și «bine» nu se confundă."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "healthy"})
    keep = [l for l in episode_lines(fresh) if "|base_health|" not in l]
    (fresh / "containers.episode").write_text("\n".join(keep) + "\n", encoding="utf-8", newline="\n")
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and "fără sănătatea de dinainte de eșec înregistrată" in p.stdout and unresolved(fresh), p.stdout


def test_f6_acknowledge_clears_the_other_states_but_never_a_stale_baseline_beside_them(tmp_path):
    """F6 (runda 8): `--acknowledge` pe un serviciu cu `stale-baseline` ȘI altă stare lipicioasă (failed) le ștergea pe amândouă, deci un redeploy de după
    baseline dispărea din rezultat. Acum `failed` se șterge, `stale-baseline` rămâne (în jurnal, în rezultatul final, în refuzul proiectului: nimic mutator,
    fără containers.ok), iar recunoașterea se vede în continuare. Singură, tot e refuzată (testul de mai sus)."""
    base = failed_pg(tmp_path, two_pull=True)
    edit_state(tmp_path, lambda st: (st["containers"]["pg-db"].update(image_id=FOREIGN_PG), st.update(pull_effect={"redis:7": {"rc": 0, "new_id": NEW_R}})))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "stale-baseline"
    mark = len(verbs(tmp_path))
    p = run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db")
    assert p.returncode == 1 and not ok_marker(base), p.stdout
    assert not mutating_since(tmp_path, mark), verbs(tmp_path)[mark:]
    every = final_of(base, "pg/db", "all")
    assert [l.split("|")[1] for l in every] == ["stale-baseline"], every
    assert final_of(base, "pg/db", "acked") and "RĂMÂNE" in p.stdout and "pg/db: recunoscut de operator, NERESOLVAT în fapt" in p.stdout, p.stdout


def test_f6_acknowledge_of_a_project_not_processed_in_the_run_still_keeps_its_stale_baseline(tmp_path):
    """F6, partea fără rescriere: `--only clin --acknowledge pg/db` nu procesează proiectul pg, deci nimic nu rescrie `stale-baseline` în rularea aceea.
    Dacă recunoașterea ar șterge-o, redeploy-ul de după baseline ar dispărea din rezultat până la o rulare viitoare pe pg (iar verify l-ar fi văzut verde).
    Rămâne în jurnal: o spune reducerea (`acked` nu o șterge), nu clasificarea."""
    base = failed_pg(tmp_path, two_pull=True)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(image_id=FOREIGN_PG))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "stale-baseline"
    p = run_c(tmp_path, base, "OPT_ONLY=clin; OPT_ACKNOWLEDGE=pg/db")
    assert p.returncode == 1 and "RĂMÂNE" in p.stdout, p.stdout
    assert [l.split("|")[1] for l in final_of(base, "pg/db", "all")] == ["stale-baseline"], final_of(base, "pg/db", "all")
    assert final_of(base, "pg/db", "acked")


# ---------------------------------------------------------------------------
# Runda 10: recunoașterea e un steag durabil; un eșec preluat se rezolvă la ok SAU same-bad; rollback-ul urmează ce a rulat înainte de schimbare
# ---------------------------------------------------------------------------
def acked_pg(tmp_path, *, ack_run_opts="OPT_ACKNOWLEDGE=pg/db"):
    """pg-db `failed` (episodul B: healthy), baseline nou B2 cât e încă unhealthy, apoi `--acknowledge pg/db` (registrul nu are nimic nou)."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    p = run_c(tmp_path, b2, ack_run_opts)
    assert p.returncode == 0 and final_of(b2, "pg/db", "acked"), p.stdout
    return b2, p


def test_n15_an_acknowledgement_survives_a_transient_compose_failure_and_the_next_plain_run_does_not_say_all_proven(tmp_path):
    """N15 (runda 9): `--acknowledge pg/db`, apoi O SINGURĂ rulare în care `docker compose config` pică (`unread`), apoi o rulare simplă. `read-ok` șterge
    `unread`, dar `acked` era ultimul rezultat și `unread` îl ștersese: rularea simplă ieșea 0 «TOTUL DOVEDIT», fără niciun cuvânt despre un serviciu pe care
    operatorul îl recunoscuse ca nerezolvat (și încă unhealthy). Acum steagul rămâne: linia «recunoscut de operator, NERESOLVAT în fapt» apare la fiecare rulare,
    iar rezultatul spune «DOVEDIT, cu 1 servicii recunoscute de operator», nu «TOTUL DOVEDIT»."""
    b2, _ = acked_pg(tmp_path)
    restore = project_without_compose_config(tmp_path)
    broken = run_c(tmp_path, b2, "OPT_KEEP_GOING=1")
    assert broken.returncode == 1 and "docker compose config a eșuat" in broken.stdout, broken.stdout
    assert "pg/db: recunoscut de operator, NERESOLVAT în fapt" in broken.stdout, broken.stdout          # și când rularea e roșie
    assert final_of(b2, "pg/db")[0].startswith("pg/db|unread|") and final_of(b2, "pg/db", "acked"), final_of(b2, "pg/db")
    restore()
    plain = run_c(tmp_path, b2, "")
    assert plain.returncode == 0 and "TOTUL DOVEDIT" not in plain.stdout, plain.stdout
    assert "REZULTAT containers: DOVEDIT, cu 1 servicii recunoscute de operator (NERESOLVATE în fapt)" in plain.stdout, plain.stdout
    assert "pg/db: recunoscut de operator, NERESOLVAT în fapt" in plain.stdout and ok_marker(b2), plain.stdout
    assert final_of(b2, "pg/db")[0].startswith("pg/db|acked|") and final_of(b2, "pg/db", "acked"), final_of(b2, "pg/db")
    bindir = make_bin(tmp_path, {}, docker=True)
    v = host_run(tmp_path, f"PHASE=verify; BASE='{posix(b2)}'; verify_summary", bindir)
    assert "pg/db: recunoscut de operator (--acknowledge), NERESOLVAT în fapt" in v.stdout, v.stdout


def test_n10_an_acknowledgement_survives_a_newer_image_that_lands_as_unhealthy_as_the_baseline(tmp_path):
    """N10 (runda 9): serviciul recunoscut (unhealthy în baseline-ul B2) primește o imagine mai nouă care aterizează la fel de unhealthy (`same-bad` față de
    B2). Verificarea trece (nu e mai rău decât baseline-ul), dar `recreated` îl înlocuia pe `acked`: avertismentul dispărea și rularea ieșea «TOTUL DOVEDIT»
    peste un serviciu încă stricat. Față de sănătatea de DINAINTE de eșec (healthy) e `worse`, deci recunoașterea rămâne (se șterge doar la ok față de
    ambele). Eticheta de rollback a recrearii pleacă de la `prev` din episod (OLD), nu de la imaginea picată care rula."""
    base = failed_pg(tmp_path, two_pull=True)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}, "redis:7": {"rc": 0, "new_id": NEW_R}},
              up_effect={"db": "recreate_unhealthy", "db2": "recreate", "app": "recreate"})
    assert run_c(tmp_path, b2, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and final_of(b2, "pg/db", "acked")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}, "redis:7": {"rc": 0, "new_id": None}})
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    assert "recreated" in report_actions(b2, "pg|db") and "ack-cleared" not in report_actions(b2, "pg|db"), report_actions(b2, "pg|db")
    assert final_of(b2, "pg/db")[0].startswith("pg/db|acked|") and final_of(b2, "pg/db", "acked"), final_of(b2, "pg/db")
    assert "recunoașterea operatorului RĂMÂNE" in p.stdout and "pg/db: recunoscut de operator, NERESOLVAT în fapt" in p.stdout, p.stdout
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG != NEW_PG, images_of(tmp_path).keys()
    bindir = make_bin(tmp_path, {}, docker=True)
    v = host_run(tmp_path, f"PHASE=verify; BASE='{posix(b2)}'; verify_summary", bindir)
    assert "recunoscut" in v.stdout, v.stdout


def test_an_acknowledgement_is_cleared_only_by_a_healthy_service_judged_ok_against_both_the_episode_and_the_baseline(tmp_path):
    """Rezolvarea reală: după `--acknowledge`, serviciul revine sănătos. O rulare care îl re-verifică îl găsește `ok` față de sănătatea de dinainte de eșec
    (healthy) ȘI față de baseline-ul B2 (unhealthy -> healthy), scrie `ack-cleared`, iar rezultatul devine «TOTUL DOVEDIT». Fără această cale recunoașterea
    ar rămâne pe veci peste un serviciu reparat, și un avertisment care nu dispare niciodată învață operatorul să nu-l mai citească."""
    b2, _ = acked_pg(tmp_path)
    still = run_c(tmp_path, b2, "")
    assert still.returncode == 0 and "TOTUL DOVEDIT" not in still.stdout and final_of(b2, "pg/db", "acked"), still.stdout        # încă unhealthy: rămâne
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    fixed = run_c(tmp_path, b2, "")
    assert fixed.returncode == 0 and "TOTUL DOVEDIT" in fixed.stdout and "DOVEDIT, cu" not in fixed.stdout, fixed.stdout
    assert not final_of(b2, "pg/db", "acked") and final_of(b2, "pg/db")[0].startswith("pg/db|verified|"), final_of(b2, "pg/db")
    assert "ack-cleared" in report_actions(b2, "pg|db") and "pg/db: recunoscut de operator, NERESOLVAT în fapt" not in fixed.stdout, fixed.stdout
    again = run_c(tmp_path, b2, "")
    assert again.returncode == 0 and "TOTUL DOVEDIT" in again.stdout and not final_of(b2, "pg/db", "acked"), again.stdout


def test_n1_a_service_that_was_unhealthy_before_any_maintenance_resolves_a_carried_pull_failure_without_an_acknowledge(tmp_path):
    """N1 (runda 9): bet-calculator — unhealthy ÎNAINTE de orice mentenanță. Un pull pierde un singur apel de rețea (`pull-failed`), apoi se ia un baseline nou
    (tot unhealthy). Cu judecata `ok`-only, episodul (unhealthy -> unhealthy = same-bad) nu rezolva niciodată: singura ieșire era `--acknowledge`, deși
    registrul revenise și serviciul era exact ca înainte. Aceeași regulă ca la baseline-ul original (ok sau same-bad): rularea simplă îl rezolvă, cu linia
    care spune de ce. Controlul de mai jos (F1/F2) rămâne roșu: `worse` nu rezolvă."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    tsv_edit(base, lambda rows: [r.__setitem__(7, "unhealthy") for r in rows if r[0] == "pg-db"])
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1 and last_report(base, "pg|db") == "pull-failed"
    b2 = new_baseline_like_preflight(tmp_path, base, {}, health={"db": "unhealthy"})
    assert "pg|db|B|base_health|unhealthy" in episode_lines(b2), episode_lines(b2)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and ok_marker(b2) and not unresolved(b2) and "TOTUL DOVEDIT" in p.stdout, p.stdout
    assert "față de sănătatea de dinainte de eșec (unhealthy) verdictul e same-bad" in p.stdout, p.stdout
    assert last_report(b2, "pg|db") == "verified" and not final_of(b2, "pg/db", "acked")


def test_x4_a_worse_service_is_never_resolved_by_the_same_bad_rule(tmp_path):
    """Cealaltă direcție a mutației X4 (judecata care acceptă și `worse`): sănătatea de dinainte de eșec `healthy`, baseline-ul nou luat cât serviciul e
    `unhealthy`, container încă unhealthy (same-bad față de baseline-ul nou, `worse` față de episod). Un eșec preluat rezolvat aici ar scrie containers.ok peste
    un serviciu pe care nimeni nu l-a reparat (runda 7). Rămâne `failed`, cu verdictul numit și ieșirea cu cheia reală."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    retry = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert retry.returncode == 1 and "verdictul e worse, nici ok, nici same-bad" in retry.stdout, retry.stdout
    assert "--phase containers --acknowledge pg/db" in retry.stdout.split("verdictul e worse")[1].splitlines()[0], retry.stdout
    assert last_report(fresh, "pg|db") == "failed" and not ok_marker(fresh)


def n11_scenario(tmp_path, *, drop_prev: bool = False, drop_landed: bool = False):
    """B: OLD -> NEW pică (landed NEW). Un om pune X (healthy). Baseline nou B2 cu X. `--retry-failed pg` trage NEWER, care aterizează unhealthy."""
    base = failed_pg(tmp_path)
    x = FOREIGN_PG
    edit_state(tmp_path, lambda st: (st["containers"]["pg-db"].update(image_id=x, health="healthy"),
                                     st["images"].update({"hotfix:pinned": {"id": x, "created": "2026-11-20T00:00:00Z", "digests": 0},
                                                          "postgres:16-alpine": {"id": x, "created": "2026-11-20T00:00:00Z", "digests": 2}})))
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": x}, health={"db": "healthy"})
    assert f"pg|db|B|landed|{NEW_PG}" in episode_lines(b2) and f"pg|db|B|prev|{OLD_PG}" in episode_lines(b2), episode_lines(b2)
    keep = [l for l in episode_lines(b2) if not (drop_prev and "|prev|" in l) and not (drop_landed and "|landed|" in l)]
    (b2 / "containers.episode").write_text("\n".join(keep) + "\n", encoding="utf-8", newline="\n")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    p = run_c(tmp_path, b2, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    return b2, p, x


@pytest.mark.parametrize("drop_prev", [False, True], ids=["episode-with-prev", "episode-without-prev"])
def test_n11_a_retry_after_a_human_deploy_rolls_back_to_what_ran_right_before_not_to_the_old_prev(tmp_path, drop_prev):
    """N11 (runda 9): OLD -> NEW pică; un om pune X; se ia un baseline nou (X rulează); `--retry-failed` trage NEWER, care aterizează unhealthy. Eticheta de
    rollback mergea pe `prev` din episod (OLD) — o imagine pe care un om a scos-o deliberat — iar indiciul tipărit ar fi dat operatorului o comandă care
    anulează deploy-ul lui X. Acum se citește imaginea de pe container ÎNAINTE: X nu e între cele pe care eșecul le-a pus (`landed` = NEW), deci cineva a
    schimbat-o și ținta e X (cu sau fără `prev` înregistrat). Indiciul numește id-ul lui X, iar eticheta arată într-adevăr X."""
    b2, p, x = n11_scenario(tmp_path, drop_prev=drop_prev)
    assert p.returncode == 1 and last_report(b2, "pg|db") == "failed", p.stdout
    tag = images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"]
    assert tag == x != OLD_PG, (tag, x)
    assert "rollback: docker tag rollback/maint-b2/pg-db:prev" in p.stdout and f"eticheta arată {x[7:19]}" in p.stdout, p.stdout
    assert f"pg|db|prev|{x}" in (b2 / "containers.owned").read_text(encoding="utf-8").splitlines()


def test_an_episode_with_no_landed_fact_keeps_the_old_rule_and_does_not_guess_that_someone_changed_the_image(tmp_path):
    """Un episod fără niciun `landed` (înregistrare pierdută, ori eșec fără recreare) nu poate spune dacă imaginea care rulează e cea picată: nu o declar
    «schimbată de altcineva» (ar eticheta imaginea picată drept rollback). Rămâne regula veche: ținta e `prev` din episod."""
    b2, p, x = n11_scenario(tmp_path, drop_landed=True)
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG, p.stdout


def test_the_rollback_hint_names_the_missing_tag_instead_of_a_command_when_no_tag_was_ever_put(tmp_path):
    """Ramura `NU există eticheta` a lui rollback_hint e ATINSĂ: un `pull-failed` rezolvat de un pull care nu găsește nimic nou re-verifică serviciul (fără
    recreare, deci fără pasul de tag), iar containerul e acum unhealthy față de un baseline healthy -> `failed`, cu eticheta de rollback încă neexistentă.
    Indiciul nu are voie să tipărească o comandă `docker tag` spre o etichetă care n-a fost pusă (ar da peste nimic, sau peste altă imagine): spune că nu există
    nicio țintă dovedită."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    (base / "containers.report").write_text("pg|db|pull-failed|registru căzut\n", encoding="utf-8", newline="\n")
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    p = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert p.returncode == 1 and last_report(base, "pg|db") == "failed", p.stdout
    assert f"rollback: NU există eticheta {RB_TAG}" in p.stdout and "rollback: docker tag" not in p.stdout, p.stdout
    assert RB_TAG not in images_of(tmp_path)


def test_the_retry_failed_message_for_a_project_that_is_gone_names_the_new_baseline_exit_and_no_placeholder(tmp_path):
    """REESCRIS în runda 12. `--retry-failed pg` peste un proiect care nu mai are NICIUN container la baseline (scos din compose): mesajul spunea `--acknowledge
    PROIECT/SERVICIU` (substituentul). Episodul unui serviciu absent se închide la baseline-ul nou; mesajul numește acea ieșire, iar jurnalul de acum nu mai are
    nimic de recunoscut."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, drop={"db"})
    p = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and "--phase preflight --new-baseline" in p.stdout and "PROIECT/SERVICIU" not in p.stdout, p.stdout
    assert "nicio stare lipicioasă nerezolvată în jurnal" in p.stdout, p.stdout
    assert "scos din compose" in p.stdout, p.stdout


def test_the_retry_failed_message_for_a_project_whose_containers_only_stopped_does_not_promise_that_a_new_baseline_closes_it(tmp_path):
    """Runda 12: proiectul `pg` n-are niciun container care RULEAZĂ la baseline (`db` e oprit), deci `--retry-failed pg` e refuzat ca nume necunoscut — dar episodul NU
    s-a închis (un container oprit nu e «dispărut»). Textul din runda 11 promitea că «un baseline nou îi închide episoadele»: operatorul ar fi luat unul și ar fi
    găsit eșecul tot acolo. Mesajul spune că un baseline nou NU închide un serviciu oprit și numește ieșirile reale: `--acknowledge` cu cheia reală."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, states={"db": "exited"}, drop={"app"})
    p = run_c(tmp_path, fresh, "OPT_RETRY_FAILED=pg")
    assert p.returncode == 1 and "niciun proiect compose cu numele ăsta" in p.stdout, p.stdout
    assert "un baseline nou NU le închide" in p.stdout and "--phase containers --acknowledge pg/db" in p.stdout and "PROIECT/SERVICIU" not in p.stdout, p.stdout


def test_a_carried_failure_with_no_recorded_health_names_the_acknowledge_exit_with_the_real_key(tmp_path):
    """`-` în episod (sănătate neînregistrată) lasă `--acknowledge` ca singură ieșire: mesajul o numește cu cheia reală, nu «--acknowledge» gol."""
    base = failed_pg(tmp_path)
    fresh = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "healthy"})
    keep = [l for l in episode_lines(fresh) if "|base_health|" not in l]
    (fresh / "containers.episode").write_text("\n".join(keep) + "\n", encoding="utf-8", newline="\n")
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    p = run_c(tmp_path, fresh, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert "--phase containers --acknowledge pg/db" in p.stdout.split("fără sănătatea de dinainte de eșec înregistrată")[1].splitlines()[0], p.stdout


def test_an_acknowledgement_is_carried_into_a_new_baseline_with_its_episode_and_a_cleared_one_is_not(tmp_path):
    """Un baseline nou nu are voie să uite o recunoaștere: ea preia episodul (sănătatea de dinainte de eșec, `prev`, `landed`) și rămâne în picioare, așa
    că după un `--new-baseline` serviciul tot nu e «TOTUL DOVEDIT» până nu e ok față de ea. Un steag deja coborât (`ack-cleared`) nu are linie vie și nu
    se preia. O recunoaștere a unui eșec produs în baseline-ul care se înlocuiește primește episodul acestuia (scris acum din faptele lui)."""
    b2, _ = acked_pg(tmp_path)                                  # recunoaștere pe episodul B (eșecul din baseline-ul B), luată în B2
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    assert any("|acked|[episod=B] preluat din baseline-ul B2" in l for l in (b3 / "containers.report").read_text(encoding="utf-8").splitlines()), (b3 / "containers.report").read_text(encoding="utf-8")
    assert f"pg|db|B|prev|{OLD_PG}" in episode_lines(b3) and f"pg|db|B|landed|{NEW_PG}" in episode_lines(b3) and "pg|db|B|base_health|healthy" in episode_lines(b3), episode_lines(b3)
    assert final_of(b3, "pg/db", "acked") and not unresolved(b3)
    p = run_c(tmp_path, b3, "")
    assert p.returncode == 0 and "TOTUL DOVEDIT" not in p.stdout and "pg/db: recunoscut de operator, NERESOLVAT în fapt" in p.stdout, p.stdout
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    assert run_c(tmp_path, b3, "").returncode == 0 and not final_of(b3, "pg/db", "acked")
    b4 = new_baseline_like_preflight(tmp_path, b3, {"db": NEW_PG}, health={"db": "healthy"}, name="B4")
    assert not final_of(b4, "pg/db", "acked")                  # steagul coborât nu se preia


def test_an_acknowledgement_of_a_failure_made_in_this_baseline_gets_that_baselines_episode_and_survives_a_new_baseline(tmp_path):
    """`failed` produs în B (fără episod preluat), recunoscut în B: linia `acked` poartă episodul B (numele baseline-ului acum), iar la `--new-baseline` se
    scriu episodul (din faptele lui B: sănătatea, `prev`, `landed`) și steagul, ca și pentru un eșec preluat."""
    base = failed_pg(tmp_path)
    assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db").returncode == 0
    assert "pg|db|acked|[episod=B] recunoscut explicit" in (base / "containers.report").read_text(encoding="utf-8"), (base / "containers.report").read_text(encoding="utf-8")
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert final_of(b2, "pg/db", "acked") and "pg|db|B|base_health|healthy" in episode_lines(b2) and f"pg|db|B|landed|{NEW_PG}" in episode_lines(b2), episode_lines(b2)


def test_the_status_verdict_line_counts_the_acknowledged_services(tmp_path):
    """`status` ieșea cu «nimic eșuat sau neterminat» peste un serviciu recunoscut ca nerezolvat: linia de verdict numește acum și recunoașterile (codul rămâne 0,
    ca la orice avertisment)."""
    b2, _ = acked_pg(tmp_path)
    bindir = make_bin(tmp_path, {"systemctl": systemctl_shim(active=(), installed=())}, docker=True)
    p = host_run(tmp_path, f"PHASE=status; init_state; BASE='{posix(b2)}'; phase_status", bindir)
    assert "VERDICT status: nimic eșuat sau neterminat, cu 1 servicii recunoscute de operator (NERESOLVATE în fapt)" in p.stdout, p.stdout + p.stderr


def test_a_pull_that_fails_again_on_a_carried_pull_failure_names_the_acknowledge_exit_with_the_real_key(tmp_path):
    """Un `pull-failed` rămas `pull-failed` (pull-ul pică și la a doua rulare) e un rezultat încă nerezolvat: mesajul spunea doar «nu-l marchez verificat», fără nicio
    ieșire. Acum numește rularea care îl rezolvă ȘI `--acknowledge` cu cheia reală, copiabilă (serviciul poate să nu mai aibă ce trage)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    again = run_c(tmp_path, base, "OPT_ONLY=pg")
    assert again.returncode == 1 and last_report(base, "pg|db") == "pull-failed", again.stdout
    line = [l for l in again.stdout.splitlines() if "pull-failed în rularea asta" in l]
    assert line and "--phase containers --acknowledge pg/db" in line[0] and "--phase containers --only pg" in line[0], again.stdout


@pytest.mark.parametrize("state", ["failed", "build-failed", "pull-failed", "tag-failed", "unread"])
def test_every_carried_sticky_state_prints_an_acknowledge_exit_that_works_from_the_printed_text(tmp_path, state):
    """După un `--new-baseline`, fiecare stare lipicioasă preluată (în afară de stale-baseline) are în textul tipărit de preflight o ieșire `--acknowledge`
    cu cheia reală; comanda COPIATĂ din text (nu una scrisă în test) o duce la `acked`, fără containers.ok blocat, iar rezultatul spune recunoașterea.
    Un indiciu care numește altă cheie decât cea care funcționează lasă operatorul fără ieșire."""
    base = containers_fixture(tmp_path, ctx_clean=True)
    (base / "containers.report").write_text(f"pg|db|{state}|{state} dintr-o rulare anterioară\n", encoding="utf-8", newline="\n")
    fresh = new_baseline_like_preflight(tmp_path, base, {})
    carried = (tmp_path / "carry.out").read_text(encoding="utf-8")
    keys = hint_values(carried, "--acknowledge")
    assert keys == {"pg/db"}, carried
    p = run_c(tmp_path, fresh, f"OPT_ACKNOWLEDGE={next(iter(keys))}")
    assert p.returncode == 0 and ok_marker(fresh) and not unresolved(fresh), p.stdout
    assert [l.split("|")[1] for l in final_of(fresh, "pg/db")] == ["acked"] and "DOVEDIT, cu 1 servicii recunoscute de operator" in p.stdout, p.stdout


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Runda 11: episodul nu mai e o copie înghețată. O recunoaștere acoperă doar episodul ei (F1); faptele mentenanței se adună în episod (F2); un serviciu dispărut își
# închide episodul; recunoașterea se șterge după regula rezolvării; o recunoaștere din baseline-ul eșecului ține cât starea e cea recunoscută.
# ---------------------------------------------------------------------------------------------------------------------------------------------

def verify_proc(tmp: Path, base: Path):
    return host_run(tmp, f"PHASE=verify; BASE='{posix(base)}'; verify_summary; finish", make_bin(tmp, {}, docker=True))


def verify_rc(tmp: Path, base: Path) -> int:
    return verify_proc(tmp, base).returncode


def status_rc(tmp: Path, base: Path) -> int:
    bindir = make_bin(tmp, {"systemctl": systemctl_shim(active=(), installed=())}, docker=True)
    return host_run(tmp, f"PHASE=status; init_state; BASE='{posix(base)}'; phase_status", bindir).returncode


def owned_lines(base: Path) -> list[str]:
    f = base / "containers.owned"
    return f.read_text(encoding="utf-8").splitlines() if f.exists() else []


def a_new_unacknowledged_failure(tmp: Path, b2: Path, kind: str) -> None:
    """Un eșec NOU (episodul B2) al serviciului pe care operatorul l-a recunoscut pentru episodul B. `pull-failed` și `tag-failed` vin dintr-o rulare reală;
    `build-failed` e scris ca report_line îl scrie (fără prefix): un build real ar cere un al doilea serviciu construit sub recunoaștere."""
    if kind == "pull-failed":
        set_state(tmp, pull_effect={"postgres:16-alpine": {"rc": 1, "new_id": None}})
        assert run_c(tmp, b2, "").returncode == 1
    elif kind == "tag-failed":
        set_state(tmp, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, tag_effect="fail")
        assert run_c(tmp, b2, "OPT_ONLY=pg").returncode == 1          # tag_effect rămâne: defectul persistă, altfel o rulare plină l-ar rezolva legitim
    else:
        with open(b2 / "containers.report", "a", encoding="utf-8", newline="\n") as fh:
            fh.write("pg|db|build-failed|build --pull cod 1\n")
    assert final_of(b2, "pg/db")[0].startswith(f"pg/db|{kind}|"), final_of(b2, "pg/db")


@pytest.mark.parametrize("kind", ["pull-failed", "tag-failed", "build-failed"])
def test_f1_an_old_acknowledgement_never_covers_a_new_failure_after_a_new_baseline(tmp_path, kind):
    """F1 / A7 (runda 10): `--acknowledge pg/db` pentru episodul B, apoi un eșec NOU (B2) al aceluiași serviciu, apoi `--new-baseline`. Carry-ul scria stările înaintea
    recunoașterilor, iar `acked` îi ștergea pe TOATE: containers, verify și status ieșeau verzi (rc 0) peste un eșec pe care nimeni nu-l recunoscuse, iar preflight nu-l
    pomenea ca nerezolvat. Acum recunoașterea acoperă doar episodul B: eșecul din B2 rămâne roșu în containers, verify și status, iar preflight îl listează."""
    b2, _ = acked_pg(tmp_path)
    a_new_unacknowledged_failure(tmp_path, b2, kind)
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    carried = (tmp_path / "carry.out").read_text(encoding="utf-8")
    assert f"rezultat NEREZOLVAT preluat în baseline-ul nou: pg/db ({kind})" in carried, carried
    report = (b3 / "containers.report").read_text(encoding="utf-8").splitlines()
    assert any(f"|{kind}|[episod=B2] preluat" in l for l in report) and any("|acked|[episod=B] preluat" in l for l in report), report
    assert final_of(b3, "pg/db")[0].startswith(f"pg/db|{kind}|") and any(l.startswith(f"pg/db|{kind}|") for l in unresolved(b3)), final_of(b3, "pg/db")
    assert final_of(b3, "pg/db", "acked"), "recunoașterea episodului B rămâne vie, dar nu acoperă eșecul din B2"
    only = run_c(tmp_path, b3, "OPT_ONLY=clin")
    assert only.returncode == 1 and "rezultat NEREZOLVAT" in only.stdout and not ok_marker(b3), only.stdout
    full = run_c(tmp_path, b3, "")
    assert full.returncode == 1 and not ok_marker(b3) and "TOTUL DOVEDIT" not in full.stdout, full.stdout
    assert verify_rc(tmp_path, b3) == 1 and status_rc(tmp_path, b3) == 1


def test_f1_the_exact_line_order_the_carry_writes_is_what_the_reducer_is_tested_with(tmp_path):
    """Testul de mai sus trece prin carry-ul real; acesta fixează ce scrie el: recunoașterile PRIMELE, apoi stările (ca o stare vie a aceluiași episod, venită după
    recunoaștere, să nu fie ștearsă de ea). Un carry care ar scrie stările întâi ar șterge, în episodul B, un `failed` produs DUPĂ recunoaștere."""
    base = failed_pg(tmp_path)
    assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db").returncode == 0
    with open(base / "containers.report", "a", encoding="utf-8", newline="\n") as fh:
        fh.write("pg|db|failed|pg-db\n")                                 # s-a înrăutățit PESTE ce s-a recunoscut (același episod, B)
    assert final_of(base, "pg/db")[0] == "pg/db|failed|pg-db"
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    lines = (b2 / "containers.report").read_text(encoding="utf-8").splitlines()
    ack_at = next(i for i, l in enumerate(lines) if "|acked|" in l)
    state_at = next(i for i, l in enumerate(lines) if "|failed|" in l)
    assert ack_at < state_at, lines
    assert final_of(b2, "pg/db")[0].startswith("pg/db|failed|") and unresolved(b2), final_of(b2, "pg/db")
    assert run_c(tmp_path, b2, "OPT_ONLY=clin").returncode == 1


def acked_unhealthy_in_its_own_baseline(tmp_path):
    """`failed` în B (unhealthy după recreare), recunoscut în B, în aceeași rulare nimic nou de tras."""
    base = failed_pg(tmp_path)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    ack = run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db")
    assert ack.returncode == 0 and ok_marker(base) and final_of(base, "pg/db", "acked"), ack.stdout
    return base


def test_finding5_a_plain_run_after_an_acknowledgement_in_the_same_baseline_does_not_reraise_failed_while_the_state_is_the_acknowledged_one(tmp_path):
    """Finding 5 (runda 10): `failed` în B, `--acknowledge` în B, apoi următoarea rulare simplă în B cu serviciul încă unhealthy: verdictul față de baseline (healthy) e
    `worse`, deci verificarea scria iar `failed` — roșu, fără containers.ok, verify/status 1 — peste o stare pe care operatorul o acceptase. Acum starea de la
    `--acknowledge` se înregistrează (`ackstate`), iar cât serviciul nu e mai rău decât ea, nimic nu se redeschide: rc 0, containers.ok rămâne, verify și status 0,
    «DOVEDIT, cu 1 servicii recunoscute». Mai rău decât starea recunoscută (oprit) e roșu din nou."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    assert "pg|db|ackstate|pg-db|unhealthy" in owned_lines(base), owned_lines(base)
    before = report_actions(base, "pg|db").count("failed")
    for _ in range(2):
        plain = run_c(tmp_path, base, "")
        assert plain.returncode == 0 and ok_marker(base) and "TOTUL DOVEDIT" not in plain.stdout, plain.stdout
        assert "DOVEDIT, cu 1 servicii recunoscute de operator" in plain.stdout and "nu mai rău decât starea pe care a recunoscut-o operatorul" in plain.stdout, plain.stdout
        assert report_actions(base, "pg|db").count("failed") == before and final_of(base, "pg/db", "acked"), report_actions(base, "pg|db")
        assert verify_rc(tmp_path, base) == 0 and status_rc(tmp_path, base) == 0
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="exited"))             # mai rău decât ce s-a recunoscut
    worse = run_c(tmp_path, base, "", SU_HEALTH_TIMEOUT_S="1", SU_POLL_S="1")
    assert worse.returncode == 1 and not ok_marker(base) and final_of(base, "pg/db")[0].startswith("pg/db|failed|"), worse.stdout
    assert verify_rc(tmp_path, base) == 1 and status_rc(tmp_path, base) == 1


def test_finding5_a_service_that_heals_in_the_baseline_it_was_acknowledged_in_clears_the_acknowledgement_without_a_warning(tmp_path):
    """Finding 5, a doua jumătate: serviciul recunoscut în B se vindecă (healthy) în B. Episodul recunoașterii e B însuși, iar sănătatea lui se știa doar din
    containers.episode (care nu are un episod B) — deci era `-` și recunoașterea RĂMÂNEA pe veci cu mesajul «RĂMÂNE … acum running/healthy» peste un serviciu
    sănătos. Acum episodul baseline-ului curent se judecă față de sănătatea lui din containers.tsv: ok -> `ack-cleared`, «TOTUL DOVEDIT», fără avertisment."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    for i in range(2):
        p = run_c(tmp_path, base, "")
        assert p.returncode == 0 and "TOTUL DOVEDIT" in p.stdout and "RĂMÂNE" not in p.stdout and "recunoscut de operator, NERESOLVAT" not in p.stdout, p.stdout
    assert "ack-cleared" in report_actions(base, "pg|db") and not final_of(base, "pg/db", "acked")
    assert verify_rc(tmp_path, base) == 0 and "recunoscut" not in host_run(tmp_path, f"PHASE=verify; BASE='{posix(base)}'; verify_summary", make_bin(tmp_path, {}, docker=True)).stdout


def test_finding5_a_failure_after_the_acknowledgement_in_the_same_episode_stays_red_through_a_new_baseline(tmp_path):
    """Serviciul recunoscut în B se înrăutățește (oprit) tot în B: `failed` nou, același episod. După `--new-baseline` (containerul pornit iar, unhealthy), eșecul rămâne
    roșu: recunoașterea nu-l acoperă, fiindcă a venit DUPĂ ea (carry-ul scrie `acked` înaintea stărilor)."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="exited"))
    assert run_c(tmp_path, base, "", SU_HEALTH_TIMEOUT_S="1", SU_POLL_S="1").returncode == 1
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="running", health="unhealthy"))
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert final_of(b2, "pg/db")[0].startswith("pg/db|failed|") and final_of(b2, "pg/db", "acked") and unresolved(b2)


@pytest.mark.parametrize("what", ["episode-file-missing", "episode-health-missing"])
def test_an_unrecorded_episode_health_never_clears_an_acknowledgement(tmp_path, what):
    """V6: «sănătate neînregistrată» (`-`) nu e «sănătos». O recunoaștere preluată dintr-un baseline al cărui containers.episode lipsește (ori n-are base_health) nu se
    poate judeca: chiar cu serviciul healthy acum, ea RĂMÂNE (cu avertisment), iar rezultatul spune «DOVEDIT, cu 1 recunoscut», nu «TOTUL DOVEDIT» — altfel o
    înregistrare pierdută ar șterge în tăcere decizia operatorului."""
    b2, _ = acked_pg(tmp_path)
    if what == "episode-file-missing":
        (b2 / "containers.episode").unlink()
    else:
        (b2 / "containers.episode").write_text("\n".join(l for l in episode_lines(b2) if "|base_health|" not in l) + "\n", encoding="utf-8", newline="\n")
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and "recunoașterea operatorului RĂMÂNE" in p.stdout and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    assert final_of(b2, "pg/db", "acked") and "ack-cleared" not in report_actions(b2, "pg|db")


def test_an_acknowledged_service_that_was_unhealthy_before_any_maintenance_ends_exactly_like_its_unacknowledged_twin(tmp_path):
    """I1 (runda 10): pg-db era unhealthy ÎNAINTE de orice mentenanță; pull-ul pierde un apel (`pull-failed`); baseline nou (tot unhealthy). Varianta nerecunoscută iese
    «TOTUL DOVEDIT» (N1: same-bad rezolvă). Varianta recunoscută rămânea pe veci «DOVEDIT, cu 1 recunoscut» cu «RĂMÂNE» la fiecare rulare, deși serviciul e exact ca
    înainte: recunoașterea pedepsea. Acum se șterge după aceeași regulă (ok sau same-bad față de episod ȘI baseline)."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    tsv_edit(base, lambda rows: [r.__setitem__(7, "unhealthy") for r in rows if r[0] == "pg-db"])
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    b2 = new_baseline_like_preflight(tmp_path, base, {}, health={"db": "unhealthy"})
    assert run_c(tmp_path, b2, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and final_of(b2, "pg/db", "acked")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and "TOTUL DOVEDIT" in p.stdout and "RĂMÂNE" not in p.stdout, p.stdout
    assert "ack-cleared" in report_actions(b2, "pg|db") and not final_of(b2, "pg/db", "acked") and ok_marker(b2)
    assert run_c(tmp_path, b2, "").returncode == 0 and verify_rc(tmp_path, b2) == 0


def test_v3_the_acknowledgement_is_also_cleared_on_the_recreate_path(tmp_path):
    """V3: ack_clear_if_resolved e chemat și după o RECREARE (execute_changes), nu doar la re-verificare. Serviciul recunoscut primește o imagine mai nouă care aterizează
    sănătoasă: verdict ok față de episod și baseline, deci `ack-cleared`. Fără apelul de pe calea recrearii, recunoașterea ar rămâne peste un serviciu reparat
    tocmai de rularea care l-a recreat."""
    b2, _ = acked_pg(tmp_path)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate", "app": "recreate"})
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))        # recrearea păstrează sănătatea din fake: imaginea nouă aterizează sănătoasă
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and "recreated" in report_actions(b2, "pg|db"), p.stdout
    assert "ack-cleared" in report_actions(b2, "pg|db") and not final_of(b2, "pg/db", "acked") and "TOTUL DOVEDIT" in p.stdout, p.stdout


def test_v2_an_acknowledgement_written_without_an_episode_prefix_is_carried_under_the_baseline_it_was_written_in(tmp_path):
    """V2 / A2: o linie `acked` fără `[episod=ID]` (scrisă de un cod mai vechi, sau de mână) are episodul `-`. Carry-ul o mapează la baseline-ul în care stă (B) și îi
    scrie episodul din faptele lui B; altfel ar scrie înregistrări sub episodul literal `-`, iar recunoașterea n-ar mai avea nicio sănătate de judecat."""
    base = failed_pg(tmp_path)
    with open(base / "containers.report", "a", encoding="utf-8", newline="\n") as fh:
        fh.write("pg|db|acked|recunoscut explicit de operator (--acknowledge pg/db); erau nerezolvate: failed (pg-db)\n")
    assert final_of(base, "pg/db", "ackeps") == ["pg/db|-"] and not unresolved(base)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    assert "pg|db|acked|[episod=B] preluat din baseline-ul B:" in "\n".join((b2 / "containers.report").read_text(encoding="utf-8").splitlines())
    assert "pg|db|B|base_health|healthy" in episode_lines(b2) and not any("|-|" in l for l in episode_lines(b2)), episode_lines(b2)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    assert "TOTUL DOVEDIT" in run_c(tmp_path, b2, "").stdout


@pytest.mark.parametrize("acked_first", [False, True], ids=["failed-only", "acknowledged"])
def test_a_service_with_no_container_at_all_in_the_new_baseline_closes_its_episode_and_its_acknowledgement(tmp_path, acked_first):
    """Decizia (ii) (runda 10, A4), cu sensul din runda 12: serviciul `failed` (ori recunoscut) a fost SCOS din compose înainte de baseline-ul nou — niciun container
    al lui, în nicio stare. Episodul și recunoașterea rămâneau pe veci: «NERESOLVAT» la fiecare rulare, `.episode` preluat la fiecare baseline, iar `--acknowledge`
    refuzat («nimic de recunoscut») după ce se șterseseră stările. Acum carry-ul închide episodul: o linie `episode-closed` cu prefixul lui ȘI cu MOTIVUL (G7: o
    ștergere fără motiv e o ștergere tăcută), nicio stare, nicio recunoaștere, nicio înregistrare de episod preluată — și nicio avertizare «NERESOLVAT»; containers,
    verify și status ies verzi."""
    base = failed_pg(tmp_path)
    if acked_first:
        assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db").returncode == 0
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, drop={"db"})
    out = (tmp_path / "carry.out").read_text(encoding="utf-8")
    reason = "niciun container al lui în baseline-ul nou, în nicio stare"
    assert "serviciul a dispărut din baseline-ul nou" in out and "episodul B s-a închis" in out and reason in out, out
    assert "NEREZOLVAT preluat" not in out and "recunoaștere a operatorului preluată" not in out, out
    lines = (b2 / "containers.report").read_text(encoding="utf-8").splitlines()
    closed = [l for l in lines if l.startswith("pg|db|episode-closed|[episod=B] serviciul a dispărut din baseline-ul")]
    assert len(closed) == 1 and f"({reason})" in closed[0] and "episodul B s-a închis" in closed[0], lines
    assert not any(l.split("|")[2] in STICKY | {"acked"} for l in lines if l.startswith("pg|db|")), lines
    assert not episode_lines(b2) and not final_of(b2, "pg/db") and not unresolved(b2)
    plain = run_c(tmp_path, b2, "")
    assert plain.returncode == 0 and "TOTUL DOVEDIT" in plain.stdout and "NERESOLVAT" not in plain.stdout and ok_marker(b2), plain.stdout
    assert verify_rc(tmp_path, b2) == 0 and status_rc(tmp_path, b2) == 0
    b3 = new_baseline_like_preflight(tmp_path, b2, {}, name="B3", drop={"db"})
    assert not episode_lines(b3) and not final_of(b3, "pg/db") and "NEREZOLVAT preluat" not in (tmp_path / "carry.out").read_text(encoding="utf-8")


NOT_RUNNING_STATES = ["restarting", "exited", "paused", "created", "dead"]
NOTHING_TO_PULL = {"postgres:16-alpine": {"rc": 0, "new_id": None}}


@pytest.mark.parametrize("acked_first", [False, True], ids=["failed-only", "acknowledged"])
@pytest.mark.parametrize("state", NOT_RUNNING_STATES)
def test_a_service_whose_container_still_exists_in_any_state_is_not_gone_and_its_failure_is_never_proven(tmp_path, state, acked_first):
    """L1 (runda 11, BLOCANT, decizia operatorului: «dispărut» = absent). `pg-db` a picat după recreare; baseline-ul nou prinde containerul într-o stare care nu e
    `running` — `restarting` (în buclă), `exited`, `paused`, `created` ori `dead`. Runda 11 le citea ca «a dispărut» și închidea episodul: containers, verify și status
    ieșeau 0 «TOTUL DOVEDIT» peste un container care CRAPĂ în buclă sau e mort, fără o linie despre el. Orice rând al serviciului, în orice stare, preia episodul ca
    înainte: eșecul rămâne roșu (cod 1, fără containers.ok, verify și status 1, niciun «TOTUL DOVEDIT»); o recunoaștere a operatorului se preia și ea («DOVEDIT, cu 1
    servicii recunoscute», niciodată «TOTUL DOVEDIT»). Nicio linie `episode-closed`, iar faptele episodului (sănătatea de dinainte, `prev`) rămân."""
    base = failed_pg(tmp_path)
    if acked_first:
        assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db").returncode == 0
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"}, states={"db": state})
    out = (tmp_path / "carry.out").read_text(encoding="utf-8")
    lines = (b2 / "containers.report").read_text(encoding="utf-8").splitlines()
    assert not any("|episode-closed|" in l for l in lines) and "serviciul a dispărut" not in out and "s-a închis" not in out, (out, lines)
    assert "pg|db|B|base_health|healthy" in episode_lines(b2) and f"pg|db|B|prev|{OLD_PG}" in episode_lines(b2), episode_lines(b2)
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    plain = run_c(tmp_path, b2, "")
    assert "TOTUL DOVEDIT" not in plain.stdout, plain.stdout
    if acked_first:
        assert "recunoaștere a operatorului preluată în baseline-ul nou: pg/db" in out and final_of(b2, "pg/db", "acked"), out
        assert plain.returncode == 0 and "DOVEDIT, cu 1 servicii recunoscute de operator" in plain.stdout, plain.stdout
    else:
        assert "rezultat NEREZOLVAT preluat în baseline-ul nou: pg/db (failed)" in out and final_of(b2, "pg/db")[0].startswith("pg/db|failed|"), out
        assert plain.returncode == 1 and not ok_marker(b2) and unresolved(b2), plain.stdout
        v = verify_proc(tmp_path, b2)
        assert v.returncode == 1 and "TOTUL DOVEDIT" not in v.stdout and status_rc(tmp_path, b2) == 1, v.stdout


@pytest.mark.parametrize("acked_first", [False, True], ids=["failed-only", "acknowledged"])
@pytest.mark.parametrize("form", [b"", b"\n"], ids=["zero-bytes", "one-blank-line"])
def test_a_measured_but_empty_container_list_is_unknown_not_everything_gone_and_says_so(tmp_path, form, acked_first):
    """L2 (runda 11) / G8. `docker ps -a` a răspuns, dar baseline-ul nou nu listează NICIUN container (un daemon abia repornit, un listing parțial). Runda 11 citea
    «niciun rând pentru serviciu» drept «a dispărut» și închidea TOATE episoadele: o singură măsurare ciudată ștergea, în tăcere, fiecare eșec nerezolvat, iar
    `--new-baseline` ieșea verde. O gazdă docker cu lista goală e suspectă, nu dovadă: nu se închide nimic, eșecul (ori recunoașterea) rămâne preluat, iar carry-ul o
    SPUNE în română. Atât un fișier de 0 octeți cât și unul cu o linie goală (un rând gol nu e o listă) sunt «goale»."""
    base = failed_pg(tmp_path)
    if acked_first:
        assert run_c(tmp_path, base, "OPT_ONLY=pg; OPT_ACKNOWLEDGE=pg/db").returncode == 0
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, raw_tsv=form)
    out = (tmp_path / "carry.out").read_text(encoding="utf-8")
    lines = (b2 / "containers.report").read_text(encoding="utf-8").splitlines()
    assert "pg/db: lista containerelor din baseline-ul nou e măsurată, dar GOALĂ (docker n-a întors niciun container)" in out and "nu închid episodul B" in out, out
    assert not any("|episode-closed|" in l for l in lines) and "serviciul a dispărut din baseline-ul nou" not in out and "s-a închis" not in out, (out, lines)
    assert "pg|db|B|base_health|healthy" in episode_lines(b2), episode_lines(b2)
    if acked_first:
        assert final_of(b2, "pg/db", "acked") and "recunoaștere a operatorului preluată în baseline-ul nou: pg/db" in out, out
    else:
        assert final_of(b2, "pg/db")[0].startswith("pg/db|failed|") and unresolved(b2), final_of(b2, "pg/db")
        v = verify_proc(tmp_path, b2)
        assert v.returncode == 1 and "TOTUL DOVEDIT" not in v.stdout and status_rc(tmp_path, b2) == 1, v.stdout


@pytest.mark.parametrize("acked", [False, True], ids=["failed-only", "acknowledged"])
def test_l3_a_failure_carried_through_a_baseline_where_the_container_was_exited_stays_red_and_rolls_back_to_the_last_good_image(tmp_path, acked):
    """L3 (runda 11). `pg-db`: OLD -> NEW pică (episodul B). Baseline B2 prinde containerul OPRIT; operatorul îl pornește iar, tot pe imaginea picată NEW (unhealthy);
    baseline B3; apoi mentenanța trage NEWER. Runda 11 închidea episodul la B2, deci în B3 NEW părea o imagine «a nimănui» și primea eticheta de rollback: indiciul
    ducea operatorul pe imaginea care a picat, iar rularea ieșea «TOTUL DOVEDIT». Acum episodul traversează B2 (oprit), iar în B3 eticheta arată OLD, ultima imagine
    care a mers — nu NEW — și nicio rulare nu spune «TOTUL DOVEDIT». Nerecunoscut: rularea simplă rămâne roșie (reținută), `--retry-failed pg` aterizează NEWER
    unhealthy și rămâne roșie; recunoscut: «DOVEDIT, cu 1 servicii recunoscute»."""
    base = failed_pg(tmp_path)
    if acked:
        set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
        assert run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db").returncode == 0
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"}, states={"db": "exited"})
    assert not any("|episode-closed|" in l for l in (b2 / "containers.report").read_text(encoding="utf-8").splitlines())
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, states={"db": "running"}, name="B3")
    assert f"pg|db|B|prev|{OLD_PG}" in episode_lines(b3) and f"pg|db|B|landed|{NEW_PG}" in episode_lines(b3), episode_lines(b3)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    if acked:
        p = run_c(tmp_path, b3, "")
        assert p.returncode == 0 and "TOTUL DOVEDIT" not in p.stdout and "DOVEDIT, cu 1 servicii recunoscute de operator" in p.stdout, p.stdout
    else:
        held = run_c(tmp_path, b3, "")
        assert held.returncode == 1 and "TOTUL DOVEDIT" not in held.stdout and not ok_marker(b3), held.stdout
        p = run_c(tmp_path, b3, "OPT_RETRY_FAILED=pg")
        assert p.returncode == 1 and "TOTUL DOVEDIT" not in p.stdout and not ok_marker(b3), p.stdout
    assert images_of(tmp_path)["rollback/maint-b3/pg-db:prev"]["id"] == OLD_PG != NEW_PG, {k: v["id"][7:19] for k, v in images_of(tmp_path).items() if k.startswith("rollback/")}


def test_a_baseline_whose_container_list_was_not_measured_does_not_close_any_episode(tmp_path):
    """«N-am putut măsura» nu e «a dispărut»: un baseline fără lista containerelor (containers.tsv.unknown) nu are voie să închidă episoade, altfel o măsurare ratată ar
    șterge în tăcere un eșec nerezolvat. Eșecul se preia ca înainte."""
    base = failed_pg(tmp_path)
    fresh = tmp_path / "state" / "snapshots" / "BU"
    fresh.mkdir(parents=True)
    (fresh / "containers.tsv.unknown").write_text("docker ps a eșuat\n", encoding="utf-8")
    p = host_run(tmp_path, f"carry_forward_sticky '{posix(base)}' '{posix(fresh)}'", make_bin(tmp_path, {}, docker=True))
    assert p.returncode == 0 and "NEREZOLVAT preluat" in p.stdout and "s-a închis" not in p.stdout, p.stdout
    assert "|failed|[episod=B] preluat" in (fresh / "containers.report").read_text(encoding="utf-8") and "pg|db|B|base_health|healthy" in episode_lines(fresh)


def test_a_container_list_beside_an_unmeasured_marker_is_still_unmeasured_and_closes_nothing(tmp_path):
    """G9 (runda 12). Marcajul `containers.tsv.unknown` spune «măsurătoarea a eșuat»; un `containers.tsv` rămas lângă el (o scriere parțială, o copie veche) nu are voie
    să-l contrazică: `snap_measure` le ține azi exclusive, dar garda din carry nu se bazează pe asta. Dacă marcajul nu e consultat, o listă fără rândul serviciului
    ar fi citită drept «a dispărut» și ar închide în tăcere un eșec nerezolvat, exact ce face «n-am putut măsura» să nu fie «a dispărut»."""
    base = failed_pg(tmp_path)
    fresh = tmp_path / "state" / "snapshots" / "BU2"
    fresh.mkdir(parents=True)
    (fresh / "containers.tsv").write_text("clin-app|clin|app|a:1|sha256:aa|sha256:aa|running|healthy|no|0|2026-11-17T00:00:00Z" + chr(10), encoding="utf-8", newline=chr(10))
    (fresh / "containers.tsv.unknown").write_text("docker ps a eșuat" + chr(10), encoding="utf-8", newline=chr(10))
    p = host_run(tmp_path, f"carry_forward_sticky '{posix(base)}' '{posix(fresh)}'", make_bin(tmp_path, {}, docker=True))
    assert p.returncode == 0 and "NEREZOLVAT preluat" in p.stdout and "s-a închis" not in p.stdout, p.stdout
    assert "|failed|[episod=B] preluat" in (fresh / "containers.report").read_text(encoding="utf-8") and not any("|episode-closed|" in l for l in (fresh / "containers.report").read_text(encoding="utf-8").splitlines())


def test_f2_a_retry_that_lands_a_new_failed_image_adds_it_to_the_carried_episode_and_the_next_retry_rolls_back_to_the_original(tmp_path):
    """F2 / R2 (runda 10): B: OLD -> NEW pică. B2 (NEW rulează, unhealthy): `--retry-failed` trage NEWER, care aterizează unhealthy — fără niciun om între ele. B3: NEWER
    rulează; `--retry-failed` trage NEWEST. Episodul era copiat ca atare (landed = {NEW}), deci NEWER părea «pusă de altcineva» și primea eticheta de rollback: indiciul
    ducea operatorul pe imaginea care a picat. Acum landed se adună între baseline-uri ({NEW, NEWER}), iar ținta rămâne OLD (ultima care a mers)."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    assert run_c(tmp_path, b2, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg").returncode == 1
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEWER_PG}, health={"db": "unhealthy"}, name="B3")
    assert {f"pg|db|B|landed|{NEW_PG}", f"pg|db|B|landed|{NEWER_PG}", f"pg|db|B|prev|{OLD_PG}", "pg|db|B|base_health|healthy"} <= set(episode_lines(b3)), episode_lines(b3)
    newest = "sha256:" + "ef" * 32
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": newest}})
    p = run_c(tmp_path, b3, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg")
    assert p.returncode == 1, p.stdout
    tag = images_of(tmp_path)["rollback/maint-b3/pg-db:prev"]["id"]
    assert tag == OLD_PG != NEWER_PG and f"eticheta arată {OLD_PG[7:19]}" in p.stdout, (tag, p.stdout)


def test_f2_a_human_deploy_between_runs_stays_the_rollback_target_through_a_second_baseline(tmp_path):
    """N11 prelungit: după `prev` = X (deploy de om între rulări) în B2, episodul preluat în B3 poartă `prev` = X (cel mai nou), nu OLD: altfel un al doilea eșec ar
    trimite operatorul pe imaginea pe care un om a scos-o deliberat."""
    b2, p, x = n11_scenario(tmp_path)
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == x
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEWER_PG}, health={"db": "unhealthy"}, name="B3")
    assert f"pg|db|B|prev|{x}" in episode_lines(b3) and f"pg|db|B|prev|{OLD_PG}" not in episode_lines(b3), episode_lines(b3)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": "sha256:" + "ef" * 32}})
    assert run_c(tmp_path, b3, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg").returncode == 1
    assert images_of(tmp_path)["rollback/maint-b3/pg-db:prev"]["id"] == x


@pytest.mark.parametrize("variant", ["truncated", "too-short"])
def test_f2_a_truncated_landed_id_is_still_the_failed_image_and_a_unreadable_one_is_no_information(tmp_path, variant):
    """R3 (runda 10): `landed` trunchiat în episod (editare, câmp tăiat) nu potrivea ID-ul întreg citit din container, deci imaginea picată NEW părea «schimbată de
    altcineva» și primea eticheta de rollback. Un prefix de cel puțin 12 cifre hex o potrivește (ținta rămâne OLD); un câmp prea scurt nu spune nimic — nu e nici «picată»,
    nici «schimbată» — și se aplică regula veche (`prev` din episod): în NICIUN caz NEW nu ajunge sub eticheta de rollback."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    cut = NEW_PG[:30] if variant == "truncated" else NEW_PG[:12]
    text = (b2 / "containers.episode").read_text(encoding="utf-8").replace(f"landed|{NEW_PG}", f"landed|{cut}")
    assert cut in text
    (b2 / "containers.episode").write_text(text, encoding="utf-8", newline="\n")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    assert run_c(tmp_path, b2, "OPT_ONLY=pg; OPT_RETRY_FAILED=pg").returncode == 1
    assert images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"] == OLD_PG != NEW_PG


def test_finding5_a_service_worse_than_the_acknowledged_state_is_red_again_while_the_same_state_is_not(tmp_path):
    """Finding 5, «mai rău decât ce s-a recunoscut»: operatorul recunoaște `failed` când serviciul e HEALTHY (a trecut singur), apoi serviciul devine unhealthy în aceeași
    baseline. Față de baseline (healthy) e `worse`, dar și față de starea recunoscută (healthy) e `worse`: nu există nicio stare acceptată care să-l acopere, deci `failed`,
    roșu, fără containers.ok. Fără acest test, mutația «orice stare e acceptată de recunoaștere» trecea (un container oprit pică înainte de verdict, în wait_settled)."""
    base = failed_pg(tmp_path)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": None}})
    assert run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and "pg|db|ackstate|pg-db|healthy" in owned_lines(base), owned_lines(base)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    p = run_c(tmp_path, base, "")
    assert p.returncode == 1 and not ok_marker(base) and "verdict worse" in p.stdout, p.stdout
    assert final_of(base, "pg/db")[0].startswith("pg/db|failed|") and verify_rc(tmp_path, base) == 1


def test_finding5_a_recreate_that_lands_in_the_acknowledged_state_does_not_reopen_the_failure(tmp_path):
    """Calea recrearii a lui finding 5 (execute_changes, nu doar re-verificarea): după `--acknowledge` în baseline-ul eșecului (serviciu unhealthy), o imagine mai nouă
    aterizează la fel de unhealthy. Nu e mai rău decât ce s-a recunoscut: nicio linie `failed` nouă, rc 0, recunoașterea rămâne («DOVEDIT, cu 1 recunoscut»)."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    before = report_actions(base, "pg|db").count("failed")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    p = run_c(tmp_path, base, "")
    assert p.returncode == 0 and "recreated" in report_actions(base, "pg|db"), p.stdout
    assert report_actions(base, "pg|db").count("failed") == before and final_of(base, "pg/db", "acked"), report_actions(base, "pg|db")
    assert "DOVEDIT, cu 1 servicii recunoscute de operator" in p.stdout and "nu mai rău decât starea pe care a recunoscut-o operatorul" in p.stdout, p.stdout


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Runda 12: starea recunoscută (`ackstate`) se scrie în clipa `--acknowledge` (S1); ultimul fapt câștigă, iar o stare nereprezentabilă (`-`) acoperă una veche; fapte
# de episod care trebuie să se adune (P1) sau să nu se inventeze (P2); `landed` al episodului recunoscut hotărăște ținta rollback-ului (R3).
# ---------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("variant", ["only-another-project", "an-earlier-project-stops-the-run"])
def test_s1_the_acknowledged_state_is_recorded_when_the_acknowledgement_is_accepted_even_if_the_run_never_reaches_the_project(tmp_path, variant):
    """S1 (runda 11). `--acknowledge pg/db` era scris în jurnal imediat, dar starea recunoscută (`ackstate`) doar când rularea CLASIFICA proiectul `pg`: cu
    `--only clin`, ori cu un proiect anterior care pică și oprește rularea înainte de `pg`, nu se scria nimic. Următoarea rulare simplă judeca serviciul față de
    baseline (healthy), îl găsea unhealthy (`worse`) și redeschidea `failed` — roșu, fără containers.ok — peste o stare pe care operatorul tocmai o acceptase. Acum starea
    se scrie la acceptarea cheii, indiferent de ordine: următoarea rulare iese 0 «DOVEDIT, cu 1 servicii recunoscute», fără un `failed` nou."""
    base = failed_pg(tmp_path)
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    if variant == "only-another-project":
        ack = run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db; OPT_ONLY=clin")
        assert ack.returncode == 0, ack.stdout
    else:
        saved: dict = {}
        edit_state(tmp_path, lambda st: saved.update(st["compose"].pop("clin")))           # `clin` nu mai poate fi citit: pică ÎNAINTEA lui `pg`, iar rularea se oprește
        ack = run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db")
        assert ack.returncode == 1 and "mă opresc după primul proiect eșuat (clin)" in ack.stdout, ack.stdout
        edit_state(tmp_path, lambda st: st["compose"].update({"clin": saved}))
    assert "pg|db|ackstate|pg-db|unhealthy" in owned_lines(base), owned_lines(base)
    before = report_actions(base, "pg|db").count("failed")
    plain = run_c(tmp_path, base, "")
    assert plain.returncode == 0 and "TOTUL DOVEDIT" not in plain.stdout and "DOVEDIT, cu 1 servicii recunoscute de operator" in plain.stdout, plain.stdout
    assert report_actions(base, "pg|db").count("failed") == before and final_of(base, "pg/db", "acked"), report_actions(base, "pg|db")
    assert verify_rc(tmp_path, base) == 0 and status_rc(tmp_path, base) == 0


def acked_then_cleared(tmp_path):
    """`failed` în B, `--acknowledge` cu pg-db unhealthy (ackstate unhealthy), apoi serviciul se vindecă și o rulare șterge recunoașterea (`ack-cleared`)."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    assert "pg|db|ackstate|pg-db|unhealthy" in owned_lines(base)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    p = run_c(tmp_path, base, "")
    assert p.returncode == 0 and "ack-cleared" in report_actions(base, "pg|db") and not final_of(base, "pg/db", "acked"), p.stdout
    return base


def test_a2_a_cleared_acknowledgement_leaves_no_accepted_state_behind_for_a_later_real_failure(tmp_path):
    """A2 (runda 11, cea mai periculoasă). Recunoaștere cu serviciul unhealthy (`ackstate` = unhealthy), serviciul se vindecă, recunoașterea se șterge. Mai târziu o
    imagine nouă aterizează unhealthy: față de baseline (healthy) e `worse`, deci trebuie să fie roșu. `ackstate` rămânea însă în containers.owned, iar verificarea îl
    folosea FĂRĂ să mai fie o recunoaștere în picioare: «nu mai rău decât starea pe care a recunoscut-o operatorul» — o recreare stricată ieșea verde, cu un
    avertisment pe care nu-l mai citește nimeni. Starea recunoscută se folosește doar cât recunoașterea e în picioare."""
    base = acked_then_cleared(tmp_path)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    p = run_c(tmp_path, base, "")
    assert p.returncode == 1 and "verdict worse" in p.stdout and "nu mai rău decât starea pe care a recunoscut-o operatorul" not in p.stdout, p.stdout
    assert final_of(base, "pg/db")[0].startswith("pg/db|failed|") and not ok_marker(base), final_of(base, "pg/db")


def test_a3_the_last_acknowledged_state_wins_when_a_service_is_acknowledged_twice_in_one_baseline(tmp_path):
    """A3 (runda 11). Prima recunoaștere cu serviciul unhealthy, apoi vindecare și ștergere; un eșec nou în același baseline; a doua recunoaștere cu serviciul HEALTHY
    (`ackstate` = healthy, scris DUPĂ cel unhealthy). Dacă verificarea citea PRIMUL fapt, serviciul care redevine unhealthy ar fi «starea recunoscută» (cea veche) și
    ar ieși verde; cu ULTIMUL fapt, healthy e starea recunoscută, iar unhealthy e `worse`: roșu."""
    base = acked_then_cleared(tmp_path)
    with open(base / "containers.report", "a", encoding="utf-8", newline="\n") as fh:
        fh.write("pg|db|failed|pg-db\n")                                    # un eșec nou, același baseline (episodul B)
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    assert run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db").returncode == 0
    states = [l for l in owned_lines(base) if l.startswith("pg|db|ackstate|")]
    assert states == ["pg|db|ackstate|pg-db|unhealthy", "pg|db|ackstate|pg-db|healthy"], states
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    p = run_c(tmp_path, base, "")
    assert p.returncode == 1 and "verdict worse" in p.stdout and not ok_marker(base), p.stdout
    assert final_of(base, "pg/db")[0].startswith("pg/db|failed|"), final_of(base, "pg/db")


def test_a1_an_acknowledgement_given_while_the_container_is_down_records_no_state_and_never_inherits_an_older_one(tmp_path):
    """A1 (runda 11) + varianta cu stare veche. Starea recunoscută se scrie doar pentru `running` cu healthy|unhealthy|none; orice altceva (aici: oprit) se scrie ca `-`
    («nu știu»), NU ca numele clasei (`down`, `starting`...), care ar deveni o «stare acceptată» cu sens necontrolat. Iar `-` acoperă un fapt mai vechi: după o
    recunoaștere ștearsă (ackstate unhealthy) și un eșec nou recunoscut cât containerul e oprit, serviciul repornit unhealthy nu are voie să fie judecat după
    recunoașterea de dinainte — starea acestei recunoașteri nu se știe, deci se judecă față de baseline: `worse`, roșu."""
    base = acked_then_cleared(tmp_path)
    with open(base / "containers.report", "a", encoding="utf-8", newline="\n") as fh:
        fh.write("pg|db|failed|pg-db\n")
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="exited"))
    assert run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db").returncode == 0
    states = [l for l in owned_lines(base) if l.startswith("pg|db|ackstate|")]
    assert states == ["pg|db|ackstate|pg-db|unhealthy", "pg|db|ackstate|pg-db|-"], states
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="running", health="unhealthy"))
    p = run_c(tmp_path, base, "")
    assert p.returncode == 1 and "verdict worse" in p.stdout and "nu mai rău decât starea pe care a recunoscut-o operatorul" not in p.stdout, p.stdout


def test_a1_a_state_that_could_not_be_recorded_is_no_state_at_all_not_a_state_that_accepts_anything(tmp_path):
    """A1, a doua jumătate. Recunoaștere dată cât containerul e oprit: starea recunoscută e `-` («nu știu»). Dacă `-` s-ar citi ca o stare, verdictul față de ea ar fi `ok`
    pentru un container fără healthcheck (la o stare necunoscută nu se poate spune «mai rău»): serviciul repornit FĂRĂ healthcheck, cu baseline-ul healthy (verdict `unknown`
    față de baseline — nu se poate compara), ar fi trecut ca «starea recunoscută» și ar fi ieșit verde peste un container pe care nimeni nu l-a putut judeca.
    Corect: nicio stare recunoscută, deci verdictul `unknown` față de baseline rămâne roșu."""
    base = failed_pg(tmp_path)
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="exited"))
    assert run_c(tmp_path, base, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and "pg|db|ackstate|pg-db|-" in owned_lines(base), owned_lines(base)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(state="running", health=None))       # revine fără healthcheck; baseline-ul era healthy
    p = run_c(tmp_path, base, "")
    assert p.returncode == 1 and "verdict unknown" in p.stdout and "nu mai rău decât starea pe care a recunoscut-o operatorul" not in p.stdout, p.stdout
    assert not ok_marker(base) and final_of(base, "pg/db")[0].startswith("pg/db|failed|"), final_of(base, "pg/db")


def test_s2_the_message_that_clears_an_acknowledgement_states_the_verdict_it_actually_reached(tmp_path):
    """S2 (runda 11). `[+] … verificat sănătos față de ambele judecăți` apărea și când recunoașterea se șterge prin `same-bad` peste un serviciu ÎNCĂ unhealthy
    (era unhealthy și înainte de orice mentenanță, I1): operatorul citea «sănătos» despre un container stricat. Acum textul spune verdictul real: `ok` -> «serviciul e
    sănătos»; `same-bad` -> «încă unhealthy, dar nu mai rău decât era înainte de eșec» și «NU e sănătos», iar linia `ack-cleared` din jurnal poartă același verdict."""
    base = containers_fixture(tmp_path, ctx_clean=True, pull={"postgres:16-alpine": {"rc": 1, "new_id": None}})
    tsv_edit(base, lambda rows: [r.__setitem__(7, "unhealthy") for r in rows if r[0] == "pg-db"])
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="unhealthy"))
    assert run_c(tmp_path, base, "OPT_ONLY=pg").returncode == 1
    b2 = new_baseline_like_preflight(tmp_path, base, {}, health={"db": "unhealthy"})
    assert run_c(tmp_path, b2, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and final_of(b2, "pg/db", "acked")
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 0 and "ack-cleared" in report_actions(b2, "pg|db"), p.stdout
    assert "verificat sănătos" not in p.stdout and "verdict same-bad: serviciul e încă unhealthy" in p.stdout and "NU e «sănătos»" in p.stdout, p.stdout
    line = [l for l in (b2 / "containers.report").read_text(encoding="utf-8").splitlines() if "|ack-cleared|" in l][0]
    assert "verdict same-bad" in line and "verdict ok" not in line, line


def test_s2_a_healed_service_clears_its_acknowledgement_with_a_message_that_says_ok(tmp_path):
    """S2, controlul: când serviciul recunoscut s-a vindecat de-a binelea (healthy), mesajul de ștergere spune verdictul `ok` și «sănătos» — nu `same-bad`. Fără acest
    control, un text care ar spune mereu «same-bad» (sau mereu «sănătos») ar trece primul test de mai sus."""
    base = acked_unhealthy_in_its_own_baseline(tmp_path)
    edit_state(tmp_path, lambda st: st["containers"]["pg-db"].update(health="healthy"))
    p = run_c(tmp_path, base, "")
    assert p.returncode == 0 and "verdict ok față de episod și față de baseline: serviciul e sănătos" in p.stdout and "same-bad: serviciul e încă unhealthy" not in p.stdout, p.stdout
    line = [l for l in (base / "containers.report").read_text(encoding="utf-8").splitlines() if "|ack-cleared|" in l][0]
    assert line.startswith("pg|db|ack-cleared|verdict ok "), line


def test_p1_a_pull_made_in_a_replaced_baseline_is_folded_into_the_carried_episode(tmp_path):
    """P1 (runda 11). Eticheta mutată de pull-ul mentenanței nu e «mutată de altcineva» (scutirea hold-moved-tag) — iar faptul `pulled` trebuie să treacă prin FIECARE
    baseline nou. B: pg-db trage NEW (eticheta se mută), pg-db2 pică: ambele `pull-failed`, containerul rămâne pe OLD. B2 (preia episodul): o nouă rulare trage NEWER
    (eticheta se mută din nou), pg-db2 pică iar. B3: eticheta arată NEWER, containerul rulează OLD. Fără împătura `pulled` din containers.owned al lui B2 în
    episod, NEWER n-ar fi în episod și rularea ar rămâne `hold-moved-tag` pe veci, deși mutarea e a noastră."""
    b2 = pull_failed_after_our_own_pull_moved_the_tag(tmp_path, tag_now=NEW_PG)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}, "redis:7": {"rc": 1, "new_id": None}})
    assert run_c(tmp_path, b2, "OPT_ONLY=pg").returncode == 1
    assert f"pg|db|pulled|{NEWER_PG}|{OLD_PG}" in owned_lines(b2), owned_lines(b2)
    b3 = new_baseline_like_preflight(tmp_path, b2, {}, tags={"db": NEWER_PG}, name="B3")
    assert f"pg|db|B|pulled|{NEWER_PG}|{OLD_PG}" in episode_lines(b3) and f"pg|db|B|pulled|{NEW_PG}|{OLD_PG}" in episode_lines(b3), episode_lines(b3)
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}, "redis:7": {"rc": 0, "new_id": None}})
    p = run_c(tmp_path, b3, "OPT_ONLY=pg")
    assert p.returncode == 0 and "(hold-moved-tag)" not in p.stdout and not unresolved(b3), p.stdout


def test_p2_an_episode_without_a_recorded_prev_is_never_given_one_by_a_later_baseline(tmp_path):
    """P2 (runda 11). `prev` e imaginea de dinainte de schimbarea noastră, scrisă ÎNAINTE de tag/up. Un episod care n-are niciunul (faptul nu s-a putut scrie) nu are
    voie să primească unul de la un baseline următor, doar fiindcă containers.owned al acestuia are un `prev` al LUI: ar fi altă imagine, altă schimbare, iar o
    reîncercare ar lua-o drept «ultima care a mers» — ținta unui rollback pe care nimeni nu l-a dovedit. Lipsa rămâne lipsă (reîncercarea refuză să ghicească)."""
    base = failed_pg(tmp_path)
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": NEW_PG}, health={"db": "unhealthy"})
    (b2 / "containers.episode").write_text("\n".join(l for l in episode_lines(b2) if "|prev|" not in l) + "\n", encoding="utf-8", newline="\n")
    with open(b2 / "containers.owned", "a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"pg|db|prev|{FOREIGN_PG}\n")                              # un `prev` al baseline-ului B2, nu al episodului B
    b3 = new_baseline_like_preflight(tmp_path, b2, {"db": NEW_PG}, health={"db": "unhealthy"}, name="B3")
    assert "pg|db|B|base_health|healthy" in episode_lines(b3), episode_lines(b3)
    assert not any("|prev|" in l for l in episode_lines(b3)), episode_lines(b3)


def test_r3_the_landed_images_of_an_acknowledged_episode_decide_whether_somebody_changed_the_image_since(tmp_path):
    """R3 (runda 11). Episodul B (OLD -> NEW pică, `landed` = NEW) e RECUNOSCUT; apoi un om pune X (healthy) și se ia un baseline nou; următoarea rulare trage NEWER, care
    aterizează unhealthy. X nu e între imaginile pe care eșecul le-a pus, deci cineva a schimbat imaginea și ținta rollback-ului e X (cum la `--retry-failed`, N11), nu OLD
    — o imagine pe care omul a scos-o deliberat. Dacă `landed` al episodului recunoscut nu e încărcat, regula nu vede nicio imagine «picată» și cade pe `prev` (OLD)."""
    base = failed_pg(tmp_path)
    x = FOREIGN_PG
    edit_state(tmp_path, lambda st: (st["containers"]["pg-db"].update(image_id=x, health="healthy"),
                                     st["images"].update({"hotfix:pinned": {"id": x, "created": "2026-11-20T00:00:00Z", "digests": 0},
                                                          "postgres:16-alpine": {"id": x, "created": "2026-11-20T00:00:00Z", "digests": 2}})))
    b2 = new_baseline_like_preflight(tmp_path, base, {"db": x}, health={"db": "healthy"})
    assert f"pg|db|B|landed|{NEW_PG}" in episode_lines(b2) and f"pg|db|B|prev|{OLD_PG}" in episode_lines(b2), episode_lines(b2)
    set_state(tmp_path, pull_effect=NOTHING_TO_PULL)
    assert run_c(tmp_path, b2, "OPT_ACKNOWLEDGE=pg/db").returncode == 0 and final_of(b2, "pg/db", "acked")
    set_state(tmp_path, pull_effect={"postgres:16-alpine": {"rc": 0, "new_id": NEWER_PG}}, up_effect={"db": "recreate_unhealthy", "app": "recreate"})
    p = run_c(tmp_path, b2, "")
    assert p.returncode == 1 and "TOTUL DOVEDIT" not in p.stdout, p.stdout
    tag = images_of(tmp_path)["rollback/maint-b2/pg-db:prev"]["id"]
    assert tag == x != OLD_PG, (tag[7:19], x[7:19])
