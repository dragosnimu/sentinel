"""`scripts/lib/compose-pin-host.sh` — `recreate`, `restore`, etichetele flotante, pasul următor după un pin și gardele de scriere.

Rulează codul LIVRAT cu `docker` momeală (`_fake_compose_docker.py`: `up --force-recreate` MODELEAZĂ compose-ul real, adică noul container
poartă hash-ul pe care îl dă fișierul) și, pentru legătura cu faza `containers` din `system-update`, rulează FAZA REALĂ
(`scripts/lib/system-update-containers.sh`) prin harnașul testelor ei. Ce NU dovedește: un compose real (recrearea reală a unui container, un
healthcheck real, un daemon real); fiecare test numește eșecul pe care îl previne, iar bug-ul reintrodus în script îl face să pice.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from _compose_pin_world import COMPOSE, HOST_LIB, LAUNCHER, N8N_ID, SECRETS, TRAEFIK_ID, UMASK_PREFIX, World, sha
from _su_shell import BASH, posix

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

TRAEFIK_PIN = "traefik=traefik:v3.8.0"
N8N_PIN = "n8n=docker.n8n.io/n8nio/n8n:2.49.5"
N8N_UP = "n8n=docker.n8n.io/n8nio/n8n:2.49.7"


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


@pytest.fixture
def pinned(tmp_path):
    """Gazda DUPĂ un pin pur al lui traefik: fișierul fixează, containerul poartă încă hash-ul vechi (driftul pe care îl creează un pin)."""
    world = World(tmp_path)
    r = world.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    world.log_path.unlink()
    return world


def ups(w: World) -> list[str]:
    return [l for l in w.docker_lines() if " up " in l]


def no_secrets(w: World, out: str) -> None:
    for value in SECRETS.values():
        assert value not in out and value not in "\n".join(w.docker_lines())


# ---------------------------------------------------------------------------------------------------------------
# etichete flotante
# ---------------------------------------------------------------------------------------------------------------

FLOATING = ["traefik:stable", "traefik:v3", "traefik:v3.8", "traefik:3.8", "traefik:beta", "traefik:next", "traefik:16-alpine", "traefik:20261101"]


@pytest.mark.parametrize("ref", FLOATING)
def test_floating_tag_is_refused_without_the_flag(w, ref):
    """`stable`, `v3`, `v3.8`, `16-alpine`, `beta`, `next` pot fi mutate de registru: un «pin» pe ele lasă upgrade-ul major în aceeași ușă pe
    care operatorul credea că a închis-o. Se refuză cu 2, înainte de orice docker."""
    r = w.pin(f"traefik={ref}")
    assert r.rc == 2 and "FLOTANTĂ" in r.out and "--allow-floating-tag" in r.out, r.out
    assert w.docker_lines() == [] and w.original == COMPOSE.encode() and w.backups() == []


@pytest.mark.parametrize("ref", ["traefik:v3.8.0", "traefik:3.8.0-alpine", "traefik:v3.8.0.1", "traefik:3.8.0_rc1"])
def test_full_versions_are_accepted(w, ref):
    """Contrarul: o versiune întreagă (cu `v` și sufix) e un pin real și nu se refuză ca flotantă."""
    w.load()
    w.state["known_pulls"][ref] = TRAEFIK_ID
    w.save()
    r = w.pin(f"traefik={ref}")
    assert r.rc == 0, r.out
    assert f"image: \"{ref}\"".encode() in w.original


def test_allow_floating_tag_writes_but_warns_it_is_not_a_real_pin(w):
    """Cu --allow-floating-tag operatorul alege conștient o etichetă mutabilă; scriptul o scrie, dar spune că nu e un pin real."""
    w.load()
    w.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w.save()
    r = w.pin("traefik=traefik:v3.8", extra=("--allow-floating-tag",))
    assert r.rc == 0 and "FLOTANTĂ" in r.out and "NU e un pin real" in r.out, r.out
    assert b'image: "traefik:v3.8"' in w.original


def test_show_classifies_floating_tags_as_not_pinned(tmp_path):
    """Un serviciu pe `traefik:v3` nu e fixat; dacă `show` l-ar raporta FIXAT, operatorul ar crede că ușa e închisă."""
    w = World(tmp_path, text=COMPOSE.replace('image: "traefik"', 'image: "traefik:v3"'))
    r = w.show()
    assert r.rc == 0, r.out
    assert "traefik: NEFIXAT" in r.out and "etichetă flotantă (v3) — NEFIXAT" in r.out
    assert "traefik: FIXAT" not in r.out


# ---------------------------------------------------------------------------------------------------------------
# show: drift, și un container oprit
# ---------------------------------------------------------------------------------------------------------------

def test_show_reports_config_hash_drift_per_container(pinned):
    """După un pin, faza containers va ține serviciul ca hold-config-drift: `show` trebuie să arate drift-ul înainte, nu abia când mentenanța
    refuză. Serviciile fără drift se arată «la zi»."""
    r = pinned.show()
    assert r.rc == 0, r.out
    traefik = r.out.split("traefik: ")[1].split("[")[0]
    assert "config-hash : DRIFT" in traefik and "hold-config-drift" in traefik
    n8n = r.out.split("n8n: ")[1].split("[")[0]
    assert "config-hash : la zi" in n8n


def test_stopped_container_is_called_stopped_not_running(w):
    """Un container oprit nu «rulează» nimic: mesajul «imaginea care rulează» ar minți. Se spune «imaginea containerului (oprit: …)»."""
    w.load()
    w.state["containers"]["root-traefik-1"]["state"] = "exited"
    w.save()
    ok = w.pin(TRAEFIK_PIN)
    assert ok.rc == 0 and "EXACT imaginea containerului (oprit: exited)" in ok.out and "EXACT imaginea care rulează acum" not in ok.out, ok.out
    w2_text = COMPOSE
    bad = World(w.tmp / "second", text=w2_text)
    bad.load()
    bad.state["containers"]["root-traefik-1"]["state"] = "exited"
    bad.save()
    r = bad.pin("traefik=traefik:v3.9.0")
    assert r.rc == 1 and "NU este imaginea containerului (oprit: exited)" in r.out and "NU este imaginea care rulează" not in r.out, r.out


# ---------------------------------------------------------------------------------------------------------------
# recreate
# ---------------------------------------------------------------------------------------------------------------

def test_recreate_restarts_only_the_named_service_on_the_same_image_and_closes_the_drift(pinned):
    """Fără `recreate`, un pin pur lasă serviciul în hold-config-drift pe vecie. Efectul de dovedit nu e «up a ieșit cu 0», ci: container NOU,
    aceeași imagine, eticheta de hash = hash-ul fișierului (deci `show` zice «la zi»), iar celelalte containere neatinse."""
    n8n_before = dict(pinned.container("root-n8n-1"))
    old_id = pinned.container("root-traefik-1")["id"]
    r = pinned.recreate("traefik")
    assert r.rc == 0, r.out
    assert "DOVEDIT: traefik rulează pe imaginea fixată, cu config-hash la zi" in r.out
    new = pinned.container("root-traefik-1")
    assert new["id"] != old_id and new["image_id"] == TRAEFIK_ID
    assert new["labels"]["com.docker.compose.config-hash"] == pinned.file_hashes()["traefik"]
    assert pinned.container("root-n8n-1") == n8n_before, "un container nenumit a fost atins"
    assert ups(pinned) == [f"compose -p root -f {pinned.fpath} up -d --no-deps --no-build --force-recreate traefik"]
    assert "config-hash : la zi" in pinned.show().out.split("traefik: ")[1].split("[")[0], "după recreate, show trebuie să vadă drift-ul închis"
    assert pinned.leftovers() == []


def test_recreate_plan_changes_nothing_and_says_what_will_stop(pinned):
    """Confirmarea cere să se vadă ce se oprește ÎNAINTE de «da»; planul nu rulează `up`."""
    r = pinned.recreate("traefik", extra=("--plan",))
    assert r.rc == 0, r.out
    assert "va fi OPRIT și recreat pe aceeași imagine" in r.out and "root-traefik-1" in r.out
    assert re.search(r"^COMPOSE_PIN_FILE_SHA256=[0-9a-f]{64}$", r.out, re.M)
    assert ups(pinned) == []


def test_recreate_is_bound_to_the_planned_file_sum(pinned):
    """«da»-ul acoperă ce a văzut operatorul: dacă fișierul s-a schimbat după plan (alt hash, alte servicii cu drift), nu se repornește nimic."""
    r = pinned.recreate("traefik", extra=("--expect-sha256", "0" * 64))
    assert r.rc == 1 and "de când ai văzut planul" in r.out and ups(pinned) == []
    plan = pinned.recreate("traefik", extra=("--plan",))
    h = re.search(r"COMPOSE_PIN_FILE_SHA256=([0-9a-f]{64})", plan.out).group(1)
    assert h == sha(pinned.original)
    assert pinned.recreate("traefik", extra=("--expect-sha256", h)).rc == 0


def test_recreate_handles_several_services(tmp_path):
    """Doi serviciile fixate se repornesc într-o singură comandă numită, iar qpdf-api (construit local) rămâne neatins."""
    w = World(tmp_path)
    assert w.pin(TRAEFIK_PIN, N8N_PIN).rc == 0
    w.log_path.unlink()
    qpdf = dict(w.container("root-qpdf-api-1"))
    r = w.recreate("traefik", "n8n")
    assert r.rc == 0, r.out
    assert len(ups(w)) == 1 and ups(w)[0].endswith("--force-recreate traefik n8n")
    assert w.container("root-qpdf-api-1") == qpdf


def refusal_cases():
    yield "unknown_service", lambda w: None, ("nope",), "nu există în configurația compose", 1
    yield "build_service", lambda w: None, ("qpdf-api",), "construit local", 1
    yield "not_pinned_in_file", lambda w: None, ("n8n",), "nu e fixată", 1


@pytest.mark.parametrize("name,setup,services,why,rc", list(refusal_cases()), ids=[c[0] for c in refusal_cases()])
def test_recreate_refuses_what_it_must_not_touch(pinned, name, setup, services, why, rc):
    """Un serviciu inexistent, construit local (build: se reface cu --rebuild) sau nefixat în fișier nu e treaba lui `recreate`: fiecare se
    refuză, fără `up`."""
    r = pinned.recreate(*services)
    assert r.rc == rc and why in r.out, r.out
    assert ups(pinned) == []


def test_recreate_refuses_a_service_without_drift(pinned):
    """A doua rulare (sau un serviciu deja la zi) n-are ce recrea: o repornire fără motiv e o întrerupere fără câștig."""
    assert pinned.recreate("traefik").rc == 0
    pinned.log_path.unlink()
    r = pinned.recreate("traefik")
    assert r.rc == 1 and "nu are drift" in r.out and ups(pinned) == []


def test_recreate_refuses_a_stopped_or_missing_container(pinned):
    """`recreate` nu pornește ce a oprit cineva și nu creează servicii: un container oprit sau lipsă se refuză."""
    pinned.load()
    pinned.state["containers"]["root-traefik-1"]["state"] = "exited"
    pinned.save()
    r = pinned.recreate("traefik")
    assert r.rc == 1 and "nu rulează (exited)" in r.out and ups(pinned) == []
    pinned.load()
    del pinned.state["containers"]["root-traefik-1"]
    pinned.save()
    r = pinned.recreate("traefik")
    assert r.rc == 1 and "niciun container" in r.out and ups(pinned) == []


def test_recreate_refuses_a_version_change_and_points_to_system_update(tmp_path):
    """O versiune nouă pusă prin `recreate` ar rula în afara evidenței system-update (imaginea nu e a baseline-ului, nici înregistrată): faza
    containers ar ține apoi tot proiectul ca stale-baseline. `recreate` refuză și numește calea."""
    w = World(tmp_path)
    assert w.pin(N8N_UP, extra=("--allow-version-change",)).rc == 0
    w.log_path.unlink()
    r = w.recreate("n8n")
    assert r.rc == 1 and "SCHIMBARE DE VERSIUNE" in r.out and "--accept-drift root" in r.out and "stale-baseline" in r.out, r.out
    assert ups(w) == [] and w.container("root-n8n-1")["image_id"] == N8N_ID


def test_recreate_refuses_when_the_pinned_image_is_not_local(pinned):
    """`up --no-build` nu e `--pull never`: dacă imaginea nu e pe disc, compose ar trage-o în mijlocul repornirii. Se refuză înainte."""
    pinned.load()
    del pinned.state["images"]["traefik:v3.8.0"]
    pinned.save()
    r = pinned.recreate("traefik")
    assert r.rc == 1 and "nu există local" in r.out and ups(pinned) == []


def test_recreate_cannot_judge_drift_without_a_label(pinned):
    """Un container fără etichetă de hash nu spune nimic despre drift: «necunoscut» (3), nu «repornește»."""
    pinned.load()
    pinned.state["containers"]["root-traefik-1"]["labels"]["com.docker.compose.config-hash"] = ""
    pinned.save()
    r = pinned.recreate("traefik")
    assert r.rc == 3 and "NECUNOSCUT" in r.out and ups(pinned) == []


PROOF_FAILURES = [
    ("up_noop", {"up_effect": "noop"}, "ACELAȘI container"),
    ("stale_label", {"up_stale_label": True}, "drift-ul NU s-a închis"),
    ("wrong_image", {"up_image": "sha256:" + "ee" * 32}, "nu imaginea cerută"),
    ("unhealthy", {"up_health": "unhealthy"}, "după recreare e running/unhealthy"),
    ("starting_forever", {"up_health": "starting"}, "încă \"starting\""),
    ("flapping", {"flap_new_after_reads": 2}, "nu e stabil"),
    ("container_gone", {"up_remove": True}, "niciun container după up"),
]


@pytest.mark.parametrize("name,knobs,why", PROOF_FAILURES, ids=[p[0] for p in PROOF_FAILURES])
def test_recreate_failure_is_loud_exact_rollback_and_no_silent_rollback(pinned, name, knobs, why):
    """`up` ieșit cu 0 nu dovedește nimic: containerul poate fi același, pe altă imagine, cu hash vechi, nesănătos sau în buclă. Fiecare e
    eșec (1) cu comenzile exacte de rollback, iar scriptul NU face rollback singur peste un serviciu care rulează (fișierul rămâne cum e, o
    singură comandă `up`)."""
    pinned.patch(**knobs)
    before = pinned.original
    r = pinned.recreate("traefik")
    assert r.rc == 1, r.out
    assert why in r.out, r.out
    assert "RECREAREA NU E DOVEDITĂ" in r.out and "restore --file" in r.out and "--force-recreate traefik" in r.out
    assert pinned.original == before and len(ups(pinned)) == 1, "a făcut rollback singur"
    no_secrets(pinned, r.out)


def test_recreate_accepts_a_healthy_container_with_a_healthcheck(pinned):
    """Un serviciu cu healthcheck e dovedit doar când e `healthy`; `healthy` trebuie să treacă (altfel proba ar refuza orice serviciu cu healthcheck)."""
    pinned.patch(up_health="healthy")
    r = pinned.recreate("traefik")
    assert r.rc == 0 and "healthy" in r.out, r.out


def test_recreate_up_error_text_is_not_printed(pinned):
    """`docker compose up` poate cita valori din configurație în erori; se tipărește doar codul, iar ce contează e starea de după."""
    pinned.patch(up_rc=1)
    r = pinned.recreate("traefik")
    assert "ieșit cu 1" in r.out and "mesajul nu se tipărește" in r.out
    no_secrets(pinned, r.out)


def test_recreate_reports_a_container_it_was_not_asked_to_touch(pinned):
    """`--no-deps` n-are voie să atingă alte containere; dacă amprenta unuia nenumit se schimbă, e 4 și nu se trece cu vederea."""
    pinned.add_hook(on="up", action="container", name="root-n8n-1", field="restart")
    r = pinned.recreate("traefik")
    assert r.rc == 4 and "nu l-am numit" in r.out, r.out


# ---------------------------------------------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------------------------------------------

def test_restore_puts_the_backup_back_and_proves_it(pinned):
    """Operatorul vrea înapoi fișierul de dinainte de pin: octeții identici (suma), dovediți, fără să atingă containerele."""
    r = pinned.restore()
    assert r.rc == 0, r.out
    assert pinned.original == COMPOSE.encode() and "restaurat și DOVEDIT" in r.out and sha(COMPOSE.encode()) in r.out
    assert "containerele proiectului sunt neatinse" in r.out and ups(pinned) == []


def test_restore_refuses_when_the_file_changed_since_the_tool_wrote_it(pinned):
    """Restaurarea oarbă ar șterge modificarea altcuiva (sau o a doua editare legitimă): refuză cât fișierul nu mai are suma scrisă de unealtă;
    --force e decizia operatorului."""
    edited = pinned.original + b"# editat de operator\n"
    pinned.file.write_bytes(edited)
    r = pinned.restore()
    assert r.rc == 1 and "s-a schimbat după ce l-a scris unealta" in r.out and pinned.original == edited
    forced = pinned.restore("--force")
    assert forced.rc == 0 and pinned.original == COMPOSE.encode()


def test_restore_never_uses_a_damaged_backup_even_with_force(pinned):
    """O copie care nu mai are suma de dinainte e mai rea decât niciuna: nu se pune peste fișier, nici cu --force."""
    pinned.backups()[0].write_bytes(b"corupt\n")
    before = pinned.original
    for extra in ((), ("--force",)):
        r = pinned.restore(*extra)
        assert r.rc == 1 and "nu mai are suma înregistrată" in r.out and pinned.original == before


def test_restore_without_the_record_needs_force(pinned):
    """Fără înregistrarea .sums nu se știe ce a scris unealta: refuz fără --force."""
    pinned.sums_files()[0].unlink()
    r = pinned.restore()
    assert r.rc == 1 and "lipsește înregistrarea" in r.out and pinned.original != COMPOSE.encode()
    assert pinned.restore("--force").rc == 0 and pinned.original == COMPOSE.encode()


def test_restore_plan_writes_nothing_and_is_bound_to_the_sum(pinned):
    """Planul nu restaurează; scrierea cere suma din plan, altfel «da»-ul ar acoperi un fișier pe care operatorul nu l-a văzut."""
    plan = pinned.restore("--plan")
    assert plan.rc == 0 and pinned.original != COMPOSE.encode()
    h = re.search(r"COMPOSE_PIN_FILE_SHA256=([0-9a-f]{64})", plan.out).group(1)
    assert h == sha(pinned.original)
    assert pinned.restore("--expect-sha256", "1" * 64).rc == 1 and pinned.original != COMPOSE.encode()
    assert pinned.restore("--expect-sha256", h).rc == 0 and pinned.original == COMPOSE.encode()


def test_restore_with_an_explicit_backup_and_with_none_at_all(pinned):
    """`--backup` numește copia exactă (cea tipărită de pin); fără nicio copie, refuzul spune asta."""
    name = pinned.backups()[0]
    assert pinned.restore("--backup", pinned.fpath + name.name[len(pinned.file.name):]).rc == 0
    for p in list(pinned.dir.glob("*.pin-bak-*")):
        p.unlink()
    r = pinned.restore()
    assert r.rc == 1 and "nu există nicio copie de rezervă" in r.out


def test_restore_after_recreate_reports_the_reversed_drift(pinned):
    """După pin + recreate, containerul poartă hash-ul fișierului fixat; un restore pune fișierul vechi și drift-ul se inversează. Scriptul îl
    măsoară și îl spune, în loc să lase faza containers să-l reție fără explicații."""
    assert pinned.recreate("traefik").rc == 0
    r = pinned.restore()
    assert r.rc == 0, r.out
    assert "traefik: root-traefik-1 are drift față de fișierul restaurat" in r.out, r.out


# ---------------------------------------------------------------------------------------------------------------
# gardele de scriere din program, atinse prin prefață (fără o comandă docker între ele nu se poate strecura nimic)
# ---------------------------------------------------------------------------------------------------------------

def run_edit_write(w: World, pre: str) -> tuple[object, str]:
    w.log_path.unlink(missing_ok=True)
    body = (f'F="{w.fpath}"; J="{posix(w.work)}/j0.json"; BAK="$F.pin-bak-TEST"\n'
            f'docker compose -p root -f "$F" config --format json > "$J"\n'
            'H="$(sha256sum "$F" | cut -d" " -f1)"\n'
            'python3 -c "${PRE}"$\'\\n\'"${PIN_PY}" edit write "$F" "$J" "$BAK" "$H" traefik=traefik:v3.8.0\n')
    r = w.run_sourced(body, PRE=pre, TARGET=posix(w.file))
    return r, body


def test_second_hash_guard_before_rename_stops_a_late_edit(w):
    """Cineva scrie fișierul DUPĂ prima verificare de sumă și înainte de `rename` (fereastra temporarului): garda a doua trebuie să refuze,
    să șteargă temporarul, copia și înregistrarea și să lase modificarea lui intactă."""
    pre = ("import os, tempfile\n_o = tempfile.mkstemp\n"
           "def _m(*a, **k):\n    r = _o(*a, **k)\n    open(os.environ['TARGET'], 'ab').write(b'# editor tarziu\\n')\n    return r\n"
           "tempfile.mkstemp = _m\n")
    r, _ = run_edit_write(w, pre)
    assert r.rc == 1 and "chiar înainte de scriere" in r.out, r.out
    assert w.original == COMPOSE.encode() + b"# editor tarziu\n"
    assert [p.name for p in w.dir.iterdir()] == [w.file.name], "au rămas temporare, copii sau înregistrări"


def test_failed_temp_file_removes_the_backup_it_just_made(w):
    """Dacă temporarul nu se poate crea, copia de rezervă proaspăt făcută nu are voie să rămână ca o «urmă» a unei schimbări care n-a avut loc
    (sau trebuie raportată): aici se șterge, iar fișierul rămâne neschimbat."""
    pre = ("import tempfile\ndef _m(*a, **k):\n    raise OSError('simulat')\ntempfile.mkstemp = _m\n")
    r, _ = run_edit_write(w, pre)
    assert r.rc == 1 and "nu pot crea fișierul temporar" in r.out, r.out
    assert w.original == COMPOSE.encode()
    assert [p.name for p in w.dir.iterdir()] == [w.file.name]


# ---------------------------------------------------------------------------------------------------------------
# citarea comenzii ssh a lansatorului: un observator care nu depinde de validare
# ---------------------------------------------------------------------------------------------------------------

def test_launcher_quotes_every_remote_argument_independently_of_validation():
    """Validarea lansatorului refuză orice caracter special, deci `printf %q` nu are cum să fie observat printr-o rulare normală. Aici se
    cheamă funcția de citare direct, cu valori pe care validarea le-ar refuza: după ce shell-ul gazdei re-parsează șirul, argumentele trebuie
    să fie EXACT cele date (un `;` sau un `$(...)` necitat ar fi o comandă, nu text)."""
    hostile = ["/srv/a b;echo INJECTED", "x=$(echo INJECTED)", "a'b\"c", "`echo INJECTED`", "--pin", "t=t:1 && echo INJECTED"]
    # valorile ajung în bash prin stdin (NUL-separate): pe Windows, linia de comandă a unui proces ar strica ghilimelele înainte să le vadă bash
    script = (UMASK_PREFIX + f'mapfile -d "" -t vals\nsource "{posix(LAUNCHER)}"\ncmd="$(build_remote_cmd pin "${{vals[@]}}")"\n'
              'printf "%s\\n" "$cmd"\neval "set -- ${cmd#sudo -n bash -s -- pin }"\nprintf "%s\\0" "$@"\n')
    proc = subprocess.run([BASH, "-c", script], input="\0".join(hostile).encode("utf-8") + b"\0", capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    out = proc.stdout.decode("utf-8")
    cmdline, _, rest = out.partition("\n")
    assert cmdline.startswith("sudo -n bash -s -- pin ")
    assert rest.split("\0")[:-1] == hostile, "argumentele nu au ajuns întregi după re-parsare: citarea lipsește sau e greșită"


# ---------------------------------------------------------------------------------------------------------------
# marcajul COMPOSE_PIN_UP_RAN=1 și verdictul unic
# ---------------------------------------------------------------------------------------------------------------

UP_RAN = "COMPOSE_PIN_UP_RAN=1"


def test_up_ran_marker_is_printed_exactly_when_up_was_started(pinned):
    """Lansatorul tipărește un rollback doar dacă gazda spune că `docker compose up` a pornit. Marcajul trebuie să existe când up a rulat (succes, eșec de
    verificare, up ieșit nenul) și să LIPSEASCĂ la refuz, la «nu are drift» și la plan: acolo nimic nu s-a atins și un rollback ar strica."""
    plan = pinned.recreate("traefik", extra=("--plan",))
    assert UP_RAN not in plan.out
    refused = pinned.recreate("nope")
    assert refused.rc == 1 and UP_RAN not in refused.out
    ok = pinned.recreate("traefik")
    assert ok.rc == 0 and ok.out.count(UP_RAN) == 1
    again = pinned.recreate("traefik")
    assert again.rc == 1 and "nu are drift" in again.out and UP_RAN not in again.out


def test_up_ran_marker_is_present_when_verification_fails_and_when_up_exits_nonzero(pinned):
    """Marcajul nu depinde de rezultat: și un up care a recreat greșit, și unul ieșit cu cod nenul, au pornit ceva pe gazdă."""
    pinned.patch(up_stale_label=True)
    r = pinned.recreate("traefik")
    assert r.rc == 1 and r.out.count(UP_RAN) == 1


def test_a_nonzero_up_with_proven_effect_gives_one_coherent_verdict(pinned):
    """`up` ieșit cu 1 dar efect dovedit (container nou, imagine, hash, stabil): operatorul trebuie să primească UN verdict, nu un «[x] up a ieșit cu 1»
    urmat de un «DOVEDIT» care îl contrazice. Fără rânduri de eroare, un singur DOVEDIT, cu avertismentul în el; ieșire 0."""
    pinned.patch(up_rc=1)
    r = pinned.recreate("traefik")
    assert r.rc == 0, r.out
    assert "[x]" not in r.out, r.out
    assert r.out.count("DOVEDIT:") == 1 and "ATENȚIE: docker compose up a ieșit cu 1" in r.out and "mesajul nu se tipărește" in r.out
    no_secrets(pinned, r.out)


def test_a_failed_proof_after_a_nonzero_up_is_one_failure_that_names_the_up_code(pinned):
    """Același lucru în sens invers: eșec de verificare + up nenul = un singur verdict de eșec care numește codul, nu două povești."""
    pinned.patch(up_rc=2, up_stale_label=True)
    r = pinned.recreate("traefik")
    assert r.rc == 1 and r.out.count("RECREAREA NU E DOVEDITĂ") == 1 and "docker compose up a ieșit cu 2" in r.out
    assert "DOVEDIT:" not in r.out


def test_up_ran_marker_is_already_on_stdout_when_up_is_invoked_even_if_up_is_killed(pinned):
    """Dacă `up` cade, e omorât sau agață, marcajul trebuie să fi fost deja emis: un marcaj tipărit DUPĂ up n-ar exista tocmai când contează (lansatorul n-ar ști că up a
    pornit). Dovada e de ORDINE: momeala `up` citește ce avea scriptul pe stdout în clipa chemării, iar marcajul trebuie să fie acolo."""
    out = pinned.tmp / "host-out.txt"
    pinned.patch(up_killed=True)
    script = UMASK_PREFIX + 'bash "$0" "$@" > "$OUT" 2>&1'
    proc = subprocess.run([BASH, "-c", script, posix(HOST_LIB), "recreate", "--file", pinned.fpath, "--service", "traefik"],
                          env=pinned.env(FAKE_CPIN_OUTFILE=posix(out), OUT=posix(out)), capture_output=True, timeout=300)
    text = out.read_text(encoding="utf-8", errors="replace")
    assert proc.returncode == 1 and text.count(UP_RAN) == 1, text
    assert UP_RAN in pinned.load()["out_at_up"], "marcajul nu era încă pe stdout când a fost chemat `up`"
