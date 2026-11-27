"""Pasul următor tipărit de `pin`, EXECUTAT: o familie de teste care face ce spune `COMPOSE_PIN_NEXT` și cere ca ceea ce se spune să fie adevărat.

De ce există: de două ori sfatul tipărit operatorului a promis ceva ce comanda următoare refuza (un pin flotant «recreate»-abil care nu era; un
rollback tipărit după un refuz). Aici nu se compară șiruri: (1) se rulează comanda sfătuită în aceeași lume (`recreate`) și se cere să iasă cu 0 și
să închidă drift-ul; (2) când sfatul e `explain` (nimic de rulat), se cere ca `recreate` să REFUZE cu adevărat, și ca alternativele numite să funcționeze;
(3) pentru o versiune nouă, sfatul `--accept-drift` se judecă față de FAZA REALĂ `containers` (system-update-containers.sh, cu su_pull_decision și
cfg_hash_changed reale), cu fișierul compose care chiar numește o altă imagine.

Ce NU dovedește: un compose, un registry sau o gazdă reale; în harnașul system-update, hash-ul de configurație al containerului e modelat (`up` îl aliniază la
hash-ul serviciului din fișier, ca un compose real), nu măsurat; numele proiectelor diferă între lumi (`root` aici, `pg` în fixture), semantica e aceeași.
"""

from __future__ import annotations

import json
import re
import shutil

import pytest

from _compose_pin_world import N8N_ID, TRAEFIK_ID, World
from test_system_update_containers_state import edit_state
from test_system_update_phases import MUTATING, OLD_PG, containers_fixture, run_containers, verbs

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

TRAEFIK_PIN = "traefik=traefik:v3.8.0"
N8N_UP = "n8n=docker.n8n.io/n8nio/n8n:2.49.7"
ALLOW_VERSION = ("--allow-version-change",)


def nexts(out: str) -> list[tuple[str, ...]]:
    return [tuple(l.removeprefix("COMPOSE_PIN_NEXT=").split()) for l in out.splitlines() if l.startswith("COMPOSE_PIN_NEXT=")]


def drift_closed(w: World, service: str) -> bool:
    section = w.show().out.split(f"{service}: ")[1].split("\n[")[0]
    return "config-hash : la zi" in section


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def test_pure_pin_advice_is_executable_and_closes_the_drift(w):
    """Pin pur pe o versiune întreagă: sfatul e `recreate traefik`, iar rulat chiar iese cu 0 și `show` vede drift-ul închis."""
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0 and nexts(r.out) == [("recreate", "traefik")], r.out
    assert not drift_closed(w, "traefik")
    ex = w.recreate("traefik")
    assert ex.rc == 0, ex.out
    assert drift_closed(w, "traefik")


def test_floating_pin_is_explained_not_advised_and_recreate_really_refuses(w):
    """Un pin flotant (cu --allow-floating-tag) NU e eligibil pentru `recreate`: poarta cere un serviciu fixat. Sfatul trebuie să fie o explicație, nu o
    comandă care iese cu 1; iar poarta chiar refuză (același predicat, nu două liste). Explicația numește alternativele, care funcționează."""
    w.load()
    w.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w.save()
    r = w.pin("traefik=traefik:v3.8", extra=("--allow-floating-tag",))
    assert r.rc == 0, r.out
    assert nexts(r.out) == [("explain", "traefik", "floating")], r.out
    assert "pin FLOTANT" in r.out and "recreate` va REFUZA" in r.out and "Nu există nicio comandă de rulat" in r.out
    refusal = w.recreate("traefik")
    assert refusal.rc == 1 and "nu e fixată" in refusal.out and "etichetă flotantă" in refusal.out, refusal.out
    # alternativa 1, executată: re-fixarea pe o versiune întreagă (aceeași imagine) face din el un pin pur, iar recreate se aplică
    again = w.pin(TRAEFIK_PIN)
    assert again.rc == 0 and nexts(again.out) == [("recreate", "traefik")], again.out
    assert w.recreate("traefik").rc == 0 and drift_closed(w, "traefik")


def test_floating_pin_alternative_restore_works_with_the_backup_the_advice_names(w):
    """Alternativa 2 a explicației: `restore` cu copia numită în sfat readuce fișierul de dinainte de pinul flotant."""
    original = w.original
    w.load()
    w.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w.save()
    r = w.pin("traefik=traefik:v3.8", extra=("--allow-floating-tag",))
    backup = re.search(r"restore --file \S+ --backup (\S+pin-bak-\d{8}T\d{6}Z(?:-\d)?)", r.out)
    assert backup, r.out
    path = backup.group(1)
    if path[1:3] == ":/":       # pe Windows, MSYS convertește argumentele către python.exe în `C:/...`; gazda reală tipărește calea cu care a fost chemată
        path = "/" + path[0].lower() + path[2:]
    ex = w.restore("--backup", path)
    assert ex.rc == 0 and w.original == original, ex.out


AGREEMENT = ["clean", "floating", "stopped", "no_label"]


@pytest.mark.parametrize("scenario", AGREEMENT)
def test_pin_advises_recreate_exactly_when_recreate_would_accept(tmp_path, scenario):
    """Același predicat pentru poarta lui `recreate` și pentru sfatul lui `pin`: pentru fiecare stare, `pin` sfătuiește `recreate` DOAR dacă `recreate` (în
    planul lui, fără să atingă nimic) chiar acceptă, și invers. Starea de după pin e cea reală (fișierul scris, imaginea trasă, containerul de acum)."""
    w = World(tmp_path)
    ref, extra = "traefik:v3.8.0", ()
    w.load()
    if scenario == "floating":
        ref, extra = "traefik:v3.8", ("--allow-floating-tag",)
        w.state["known_pulls"][ref] = TRAEFIK_ID
    if scenario == "stopped":
        w.state["containers"]["root-traefik-1"]["state"] = "exited"
    if scenario == "no_label":
        w.state["containers"]["root-traefik-1"]["labels"]["com.docker.compose.config-hash"] = ""
    w.save()
    r = w.pin(f"traefik={ref}", extra=extra)
    assert r.rc == 0, r.out
    advised = ("recreate", "traefik") in nexts(r.out)
    plan = w.recreate("traefik", extra=("--plan",))
    assert advised == (plan.rc == 0), f"sfat={advised}, dar recreate --plan a ieșit cu {plan.rc}: {plan.out}"
    assert advised == (scenario == "clean")
    if not advised:
        assert any(n[0] == "explain" and n[1] == "traefik" for n in nexts(r.out)), "nimic de rulat înseamnă o explicație, nu tăcere"


# ---------------------------------------------------------------------------------------------------------------
# versiune nouă: sfatul față de FAZA REALĂ containers, cu fișierul care numește altă imagine
# ---------------------------------------------------------------------------------------------------------------

NEW_REF = "postgres:16.4-alpine"
NEWVER = "sha256:" + "ab" * 32


def real_phase(tmp, *, new_id: str, digests: int, moved_tag: bool, accept: bool, baseline_row=None):
    """FAZA REALĂ `containers` pe un proiect al cărui fișier compose numește acum NEW_REF (altă imagine decât cea cu care a fost creat containerul), cu hash de
    configurație în urmă. `accept` = rulat cu --accept-drift."""
    tmp.mkdir()
    base = containers_fixture(tmp, ctx_clean=True, tag_moved=moved_tag, pg_label_hash="OLD-HASH",
                              extra_images={NEW_REF: {"id": new_id, "created": "2026-11-20T00:00:00Z", "digests": digests}},
                              pull={NEW_REF: {"rc": 0, "new_id": new_id}})
    edit_state(tmp, lambda st: st["compose"]["pg"]["config"]["services"]["db"].update({"image": NEW_REF}))
    if baseline_row is not None:           # ce știa baseline-ul despre containerul pg-db: (câmp, valoare nouă) în containers.tsv
        tsv = base / "containers.tsv"
        rows = [l.split("|") for l in tsv.read_text(encoding="utf-8").splitlines()]
        for r in rows:
            if r[0] == "pg-db":
                r[baseline_row[0]] = baseline_row[1]
        tsv.write_text("\n".join("|".join(r) for r in rows) + "\n", encoding="utf-8", newline="\n")
    proc = run_containers(tmp, base, "OPT_ONLY=pg" + ("; OPT_ACCEPT_DRIFT=pg" if accept else ""))
    state = json.loads((tmp / "docker-state.json").read_text(encoding="utf-8"))
    return proc, state


@pytest.mark.parametrize("scenario", ["clean", "moved_tag", "local_only", "bare_id", "stopped"])
def test_version_change_advice_agrees_with_the_real_containers_phase(tmp_path, scenario):
    """Pentru o versiune nouă, `pin` sfătuiește `--accept-drift <proiect>` DOAR dacă faza reală chiar recreează serviciul cu el. Se rulează faza reală, fără
    și cu --accept-drift, pe un fișier care numește altă imagine (fixture-ul din prima variantă folosea aceeași etichetă înainte și după: dovedea mai puțin
    decât pretindea). Cazuri: curat (se aplică), eticheta numelui de creare mutată (hold-moved-tag, și cu accept), imagine fără RepoDigests (skip-local), numele de creare ca ID
    gol (skip-bare-id) și serviciu care nu rula (skip-not-running): ultimele două sunt cele pe care predicatul le oglindește și fără de care ar sfătui greșit."""
    moved, digests = scenario == "moved_tag", 0 if scenario == "local_only" else 2
    # ce știe BASELINE-ul despre pg-db (câmpurile din containers.tsv): numele de creare ca ID gol (skip-bare-id) sau starea «nu rula» (skip-not-running)
    row = {"bare_id": (3, "6cd5a2fc29fe"), "stopped": (6, "exited")}.get(scenario)
    held, _ = real_phase(tmp_path / "held", new_id=NEWVER, digests=digests, moved_tag=moved, accept=False, baseline_row=row)
    if scenario == "stopped":
        # un container care nu rula la baseline nu face proiectul vizibil faței: faza refuză proiectul («niciun proiect compose cu numele ăsta în baseline») și nu atinge nimic
        assert "niciun proiect compose" in held.stdout and not (set(verbs(tmp_path / "held")) & MUTATING), held.stdout
    else:
        assert held.returncode == 0 and not (set(verbs(tmp_path / "held")) & MUTATING), held.stdout
    assert scenario == "stopped" or any(k in held.stdout for k in ("hold-config-drift", "hold-moved-tag", "skip-local", "skip-bare-id", "skip-not-running")), "faza nu reține serviciul fără --accept-drift: testul ar fi gol"
    applied, state = real_phase(tmp_path / "accepted", new_id=NEWVER, digests=digests, moved_tag=moved, accept=True, baseline_row=row)
    assert applied.returncode == (1 if scenario == "stopped" else 0), applied.stdout
    phase_recreates = "compose up" in verbs(tmp_path / "accepted")
    assert phase_recreates == (scenario == "clean"), f"faza reală s-a comportat altfel decât se aștepta pentru {scenario}: {applied.stdout}"
    if phase_recreates:
        pulled = [v for v in verbs(tmp_path / "accepted") if v == "pull"]
        assert pulled, "nu a tras imaginea nouă"
        c = state["containers"]["pg-db"]
        assert c["image_id"] == NEWVER, "containerul recreat nu rulează imaginea pe care o numește fișierul"
        assert c["labels"]["com.docker.compose.config-hash"] == "H-db", "eticheta de hash nu s-a aliniat (modelat în momeală, ca un compose real)"

    w = World(tmp_path / "w")
    if moved:
        w.load()
        w.state["images"]["docker.n8n.io/n8nio/n8n"]["id"] = "sha256:" + "cd" * 32       # eticheta numelui de creare a fost mutată de altcineva
        w.save()
    if scenario == "local_only":
        w.patch(pull_digests=False)
    if scenario == "bare_id":
        w.load()
        w.state["containers"]["root-n8n-1"]["config_image"] = "6cd5a2fc29fe"            # creat dintr-un ID de imagine gol: nu există o etichetă de tras
        w.state["images"]["6cd5a2fc29fe"] = {"id": N8N_ID, "digests": []}               # ca la docker real, un ID gol se rezolvă la imaginea care rulează
        w.save()
    if scenario == "stopped":
        w.load()
        w.state["containers"]["root-n8n-1"]["state"] = "exited"
        w.save()
    out = w.pin(N8N_UP, extra=ALLOW_VERSION).out
    advised = ("accept-drift", "root", "n8n") in nexts(out)
    assert advised == phase_recreates, f"sfatul ({advised}) nu e ce face faza reală ({phase_recreates}): {out}"
    assert ("recreate", "n8n") not in nexts(out), "pentru o versiune nouă, `recreate` n-are voie să fie sfătuit"
    if not advised:
        assert any(n[:2] == ("explain", "n8n") for n in nexts(out)) and "Nu există nicio comandă de rulat" in out, out


def test_pure_pin_with_a_changed_ref_is_up_to_date_in_the_real_phase_so_recreate_is_the_only_way_out(tmp_path):
    """Pin pur: fișierul numește altă etichetă, dar pe ACEEAȘI imagine. Faza reală cu --accept-drift trage, vede aceeași imagine și nu recreează nimic, deci
    drift-ul n-ar dispărea niciodată: de aceea sfatul pentru un pin pur e `recreate`, nu `--accept-drift`."""
    held, _ = real_phase(tmp_path / "held", new_id=OLD_PG, digests=2, moved_tag=False, accept=False)
    assert "hold-config-drift" in held.stdout
    applied, state = real_phase(tmp_path / "accepted", new_id=OLD_PG, digests=2, moved_tag=False, accept=True)
    assert applied.returncode == 0 and "compose up" not in verbs(tmp_path / "accepted"), applied.stdout
    assert state["containers"]["pg-db"]["labels"]["com.docker.compose.config-hash"] == "OLD-HASH", "eticheta a rămas veche: drift permanent"
    w = World(tmp_path / "w")
    r = w.pin(TRAEFIK_PIN)
    assert nexts(r.out) == [("recreate", "traefik")] and "--accept-drift NU ajută" in r.out
