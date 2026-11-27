"""`scripts/lib/compose-pin-host.sh` — fixarea imaginilor dintr-un fișier docker-compose, pe gazdă.

Rulează codul LIVRAT într-un bash, cu `docker` momeală (`_fake_compose_docker.py`, care CITEȘTE fișierul de pe disc la fiecare
`docker compose config`) și cu fișiere reale; vezi `_compose_pin_world.py` pentru ce NU dovedește mediul ăsta (un compose real, root,
un registry, modul/proprietarul pe Windows).

Fiecare test își numește în docstring eșecul pe care îl previne, în termeni de ce se strică pentru operator, și a fost falsificat:
bug-ul reintrodus în script face testul să pice (tabelul e în raportul predării).
"""

from __future__ import annotations

import os
import re
import shutil
import stat

import pytest

from _compose_pin_world import (COMPOSE, N8N_DIGEST, N8N_ID, N8N_NEW_ID, SECRETS, TRAEFIK_ID, TRAEFIK_NEW_ID, World, sha)

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")
LINUX_ONLY = pytest.mark.skipif(os.name == "nt", reason="chmod/chown pe NTFS nu fac nimic real; verificarea de mod/proprietar se dovedește doar pe Linux")

TRAEFIK_PIN = "traefik=traefik:v3.8.0"
N8N_PIN = "n8n=docker.n8n.io/n8nio/n8n:2.49.5"
ALLOWED_DOCKER = ("version", "ps ", "container inspect", "image inspect", "pull -q", "compose -p root -f")


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def no_secrets(w: World, out: str) -> None:
    for value in SECRETS.values():
        assert value not in out, "o valoare de mediu a ajuns în ieșire"
        assert value not in "\n".join(w.docker_lines()), "o valoare de mediu a ajuns într-o comandă docker"


def only_read_and_pull(w: World) -> None:
    """Nicio comandă care schimbă containerele (up/restart/rm/stop/run/create): doar citire și pull."""
    for line in w.docker_lines():
        assert line.startswith(ALLOWED_DOCKER), line
        assert not re.search(r"compose .* (up|restart|down|stop|rm|create|pull)\b", line), line


def pulls(w: World) -> list[str]:
    return [l for l in w.docker_lines() if l.startswith("pull")]


# ---------------------------------------------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------------------------------------------

def test_show_reports_each_service_and_changes_nothing(w):
    """Operatorul vrea să vadă, înainte de orice, ce e fixat și ce nu (și că n-are build). Dacă `show` ar scrie, ar trage sau ar tipări
    mediul, citirea «inofensivă» ar deveni prima schimbare pe gazdă."""
    before = w.original
    r = w.show()
    assert r.rc == 0, r.out
    assert "traefik: NEFIXAT" in r.out and "n8n: NEFIXAT" in r.out
    assert re.search(r"qpdf-api: construit local — nu se fixează aici\n\s+image scris : qpdf-api:latest\n\s+build\s+: da", r.out)
    assert "qpdf-api: NEFIXAT" not in r.out, "un serviciu construit local nu e o problemă de fixat: nu se raportează ca eșec permanent"
    assert f"imagine {N8N_ID}" in r.out and "docker.n8n.io/n8nio/n8n@sha256:" + N8N_DIGEST.split(":")[1] in r.out
    assert "3 servicii: 0 fixate, 1 construite local, 2 nefixate" in r.out
    assert w.original == before and w.backups() == [] and w.leftovers() == []
    assert pulls(w) == []
    only_read_and_pull(w)
    no_secrets(w, r.out)


def test_show_recognises_tags_and_digests_as_pinned_and_latest_as_not(tmp_path):
    """Un serviciu pe `:latest` explicit, pe etichetă goală sau pe un digest scurt NU e fixat; o etichetă nelatest sau un digest întreg e.
    Dacă `show` ar număra `:latest` ca fixat, operatorul ar crede că ușa e închisă."""
    text = (COMPOSE.replace('image: "traefik"', "image: traefik:latest")
            .replace("image: docker.n8n.io/n8nio/n8n\n", f"image: docker.n8n.io/n8nio/n8n@{N8N_DIGEST}\n")
            .replace("image: qpdf-api:latest", "image: qpdf-api:v1"))
    w = World(tmp_path, text=text)
    r = w.show()
    assert r.rc == 0, r.out
    assert "traefik: NEFIXAT" in r.out and "n8n: FIXAT" in r.out
    assert "qpdf-api: construit local" in r.out, "build: bate eticheta: un serviciu construit local nu se raportează ca fixat"
    assert "1 fixate, 1 construite local, 1 nefixate" in r.out


# ---------------------------------------------------------------------------------------------------------------
# pin pur: efectul pe fișier
# ---------------------------------------------------------------------------------------------------------------

PRESERVE = [
    ("quoted_with_comment", COMPOSE, b'    image: "traefik"   # citat, cu comentariu', b'    image: "traefik:v3.8.0"   # citat, cu comentariu'),
    ("single_quotes", COMPOSE.replace('image: "traefik"', "image: 'traefik'"), b"    image: 'traefik'   # citat, cu comentariu", b"    image: 'traefik:v3.8.0'   # citat, cu comentariu"),
    ("extra_spaces_and_trailing_blanks", COMPOSE.replace('image: "traefik"   #', "image:    traefik   #"), b"    image:    traefik   # citat, cu comentariu", b"    image:    traefik:v3.8.0   # citat, cu comentariu"),
    ("diacritics_in_comment", COMPOSE.replace("citat, cu comentariu", "șuruburi și țevi"), "    image: \"traefik\"   # șuruburi și țevi".encode(), "    image: \"traefik:v3.8.0\"   # șuruburi și țevi".encode()),
    ("no_final_newline", COMPOSE.rstrip("\n"), b'    image: "traefik"   # citat, cu comentariu', b'    image: "traefik:v3.8.0"   # citat, cu comentariu'),
]


@pytest.mark.parametrize("name,text,old,new", PRESERVE, ids=[p[0] for p in PRESERVE])
def test_pure_pin_changes_only_the_image_value_byte_for_byte(tmp_path, name, text, old, new):
    """Fișierul compose al producției are comentarii, ghilimele și spații pe care operatorul le-a ales; un pin care le rescrie (sau care
    atinge altă linie) face dintr-o schimbare de o linie un diff pe tot fișierul și ascunde ce s-a schimbat de fapt."""
    w = World(tmp_path, text=text)
    before = w.original
    assert old in before
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert w.original == before.replace(old, new), "s-a atins altceva decât valoarea image: a serviciului"
    assert len(w.original) - len(before) == len(new) - len(old)
    assert len(w.backups()) == 1 and w.backups()[0].read_bytes() == before, "copia de rezervă nu e identică cu originalul"
    assert w.leftovers() == []
    only_read_and_pull(w)
    assert pulls(w) == ["pull -q traefik:v3.8.0"]


def test_crlf_file_stays_crlf(tmp_path):
    """Un fișier editat pe Windows are CRLF. Un pin care normalizează sfârșiturile de linie schimbă fiecare linie a fișierului."""
    w = World(tmp_path, crlf=True)
    before = w.original
    assert before.count(b"\r\n") == before.count(b"\n") > 10
    r = w.pin(TRAEFIK_PIN, N8N_PIN)
    assert r.rc == 0, r.out
    after = w.original
    assert after.count(b"\r\n") == after.count(b"\n") == before.count(b"\n"), "CRLF-ul s-a pierdut sau s-a amestecat"
    assert after == (before.replace(b'image: "traefik"', b'image: "traefik:v3.8.0"')
                     .replace(b"image: docker.n8n.io/n8nio/n8n\r\n", b"image: docker.n8n.io/n8nio/n8n:2.49.5\r\n"))
    assert w.backups()[0].read_bytes() == before


def test_digest_reference_is_accepted_and_written(w):
    """Un digest e cel mai strict pin; dacă scriptul l-ar refuza (sau l-ar scrie cu `:` în față), operatorul n-ar avea cum să-l ceară."""
    ref = f"docker.n8n.io/n8nio/n8n@{N8N_DIGEST}"
    r = w.pin(f"n8n={ref}")
    assert r.rc == 0, r.out
    assert f"image: {ref}\n".encode() in w.original
    assert pulls(w) == [f"pull -q {ref}"]


@LINUX_ONLY
def test_mode_owner_and_backup_permissions(tmp_path):
    """Fișierul compose are secrete: un pin care îl recreează cu 0644 (sau o copie de rezervă lizibilă de oricine) le-ar scoate din
    root-only."""
    w = World(tmp_path)
    w.file.chmod(0o640)
    st0 = w.file.stat()
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    st1 = w.file.stat()
    assert stat.S_IMODE(st1.st_mode) == 0o640 and (st1.st_uid, st1.st_gid) == (st0.st_uid, st0.st_gid)
    assert stat.S_IMODE(w.backups()[0].stat().st_mode) == 0o600
    assert "0600" in r.out


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0, reason="proprietarul se poate schimba doar ca root (ca pe gazdă); rulat ca root în WSL")
def test_owner_of_the_file_is_preserved_when_run_as_root(tmp_path):
    """Pe gazdă scriptul rulează ca root, iar fișierul poate aparține altcuiva: un `rename` al unui temporar proaspăt l-ar face
    proprietatea lui root și ar schimba cine îl poate citi."""
    w = World(tmp_path)
    os.chown(w.file, 12345, 23456)
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    st = w.file.stat()
    assert (st.st_uid, st.st_gid) == (12345, 23456)


def test_output_has_diff_backup_path_and_exact_rollback_command(w):
    """Operatorul trebuie să poată reveni fără să citească scriptul: diff-ul doar pe liniile image:, calea copiei și comanda exactă."""
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    backup = str(w.backups()[0].name)
    assert '-    image: "traefik"   # citat, cu comentariu' in r.out and '+    image: "traefik:v3.8.0"   # citat, cu comentariu' in r.out
    assert re.search(r"^@@ -3 \+3 @@$", r.out, re.M)
    assert backup in r.out
    assert re.search(rf"sudo cp -- \S*{re.escape(backup)} \S+docker-compose\.yml && sudo sha256sum", r.out)
    assert sha(w.backups()[0].read_bytes()) in r.out, "comanda de rollback nu spune ce sumă trebuie să dea fișierul după"
    assert "n8n" not in r.out.split("diferența")[1].split("scris atomic")[0], "diff-ul a atins alt serviciu"


def test_pure_pin_says_nothing_is_recreated_now_and_leaves_containers_alone(w):
    """Un pin pur trebuie să poată fi făcut într-o zi de producție: dacă ar atinge un container, ar fi o întrerupere. Se dovedește și
    prin amprentă, nu doar prin comenzile lipsă."""
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert "containerele proiectului sunt neatinse" in r.out
    assert "imaginea care rulează NU se schimbă" in r.out
    only_read_and_pull(w)


def test_config_hash_change_is_measured_and_reported_as_recreate(w):
    """Schimbarea șirului image: schimbă config-hash-ul, deci un `up` recreează containerul chiar cu aceeași imagine. Dacă scriptul
    n-ar spune asta, o mentenanță «fără schimbări» ar produce o întrerupere neanunțată."""
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert re.search(r"traefik: config-hash \w{8}… → \w{8}…, iar containerul poartă hash-ul vechi: faza .*hold-config-drift pentru traefik", r.out)
    assert "COMPOSE_PIN_NEXT=recreate traefik" in r.out
    assert "n8n: config-hash" not in r.out, "n8n n-a fost atins, nu are ce raporta"


def test_config_hash_equal_to_container_label_is_reported_as_no_recreate(w):
    """Contrarul: dacă hash-ul nou e egal cu eticheta containerului, scriptul nu are voie să sperie operatorul cu o recreare care nu vine.
    (Gazda aduce containerul la hash-ul fișierului fixat, apoi fișierul revine la originalul cu `latest`.)"""
    original = w.original
    assert w.pin(TRAEFIK_PIN).rc == 0
    w.sync_hash_labels()
    w.file.write_bytes(original)
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert "traefik: config-hash-ul nou e egal cu cel al containerului" in r.out
    assert "COMPOSE_PIN_NEXT" not in r.out and "hold-config-drift" not in r.out


def test_unmeasurable_config_hash_is_stated_not_assumed(w):
    """Un compose fără `--hash` nu poate spune ce va recrea `up`; scriptul trebuie să zică «nu știu», nu «nu recreează»."""
    w.patch(hash_unsupported=True)
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert "nu știu ce va face faza containers" in r.out and "COMPOSE_PIN_NEXT" not in r.out


# ---------------------------------------------------------------------------------------------------------------
# pin pur contra versiune diferită
# ---------------------------------------------------------------------------------------------------------------

def test_tag_that_is_not_the_running_image_is_refused_without_the_flag(w):
    """`traefik:v3.9.0` nu e imaginea care rulează: scris în fișier, ar fi un upgrade deghizat în pin, aplicat de următoarea mentenanță.
    Pin-ul pur trebuie să refuze, să nu scrie nimic și să nu lase nicio copie."""
    before = w.original
    r = w.pin("traefik=traefik:v3.9.0")
    assert r.rc == 1, r.out
    assert "NU este imaginea care rulează" in r.out and TRAEFIK_ID in r.out and TRAEFIK_NEW_ID in r.out
    assert "--allow-version-change" in r.out
    assert w.original == before and w.backups() == [] and w.leftovers() == []


def test_allow_version_change_writes_and_states_nothing_is_recreated_now(w):
    """Cu --allow-version-change operatorul cere explicit altă versiune; scriptul trebuie să spună că NIMIC nu se recreează acum și că
    schimbarea o aplică system-update.sh --phase containers, ca să nu creadă că upgrade-ul s-a făcut (sau că nu se va face)."""
    r = w.pin("n8n=docker.n8n.io/n8nio/n8n:2.49.7", extra=("--allow-version-change",))
    assert r.rc == 0, r.out
    assert b"image: docker.n8n.io/n8nio/n8n:2.49.7\n" in w.original
    assert "VERSIUNE DIFERITĂ" in r.out and N8N_NEW_ID in r.out
    assert "NIMIC nu e recreat acum" in r.out
    assert "va REȚINE n8n (hold-config-drift)" in r.out and "--accept-drift root" in r.out and "COMPOSE_PIN_NEXT=accept-drift root n8n" in r.out
    assert "COMPOSE_PIN_NEXT=recreate" not in r.out, "pentru o versiune nouă, `recreate` ar pune imaginea în afara evidenței system-update"
    assert "pin pur" not in r.out
    only_read_and_pull(w)
    assert w.load()["containers"]["root-n8n-1"]["image_id"] == N8N_ID


def test_allow_version_change_with_same_image_is_still_a_pure_pin(w):
    """Flag-ul permite o versiune diferită, nu o cere: dacă eticheta e chiar imaginea care rulează, mesajul trebuie să rămână cel
    al pin-ului pur, nu o falsă «versiune schimbată»."""
    r = w.pin(N8N_PIN, extra=("--allow-version-change",))
    assert r.rc == 0, r.out
    assert "pin pur" in r.out and "VERSIUNE" not in r.out


def test_pure_pin_of_a_service_without_container_cannot_be_proven(w):
    """Fără container, «nu schimbă ce rulează» nu are față de ce să se verifice: nu e «bine», e «necunoscut» (3), și nu se scrie nimic."""
    w.load()
    del w.state["containers"]["root-traefik-1"]
    w.save()
    before = w.original
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 3, r.out
    assert "NECUNOSCUT" in r.out and w.original == before and w.backups() == []
    r2 = w.pin(TRAEFIK_PIN, extra=("--allow-version-change",))
    assert r2.rc == 0, r2.out


def test_unknown_manifest_is_a_refusal_and_a_network_failure_is_unknown(w):
    """«Eticheta nu există» e un refuz (1), dar «registry-ul n-a răspuns» nu spune nimic despre etichetă: 3. Amestecate, un timeout ar
    fi raportat operatorului ca «eticheta ta e greșită»."""
    r = w.pin("traefik=traefik:v9.9.9")
    assert r.rc == 1 and "nu poate fi tras" in r.out, r.out
    w.patch(pull_error="Error response from daemon: Get https://registry: dial tcp: i/o timeout")
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 3 and "NECUNOSCUT" in r.out, r.out
    assert w.original == COMPOSE.encode() and w.backups() == []


# ---------------------------------------------------------------------------------------------------------------
# refuzuri înainte de orice rețea sau scriere
# ---------------------------------------------------------------------------------------------------------------

BAD_REFS = ["traefik:latest", "traefik:LATEST", "traefik", "traefik:", "traefik@sha256:abc", "Traefik:v3", "traefik:v3;id", "traefik:v3 v4", "traefik@sha256:" + "z" * 64]


@pytest.mark.parametrize("ref", BAD_REFS)
def test_unpinned_or_malformed_reference_is_refused_before_any_docker_call(w, ref):
    """`traefik:latest`, `traefik` și `traefik:` înseamnă toate `latest`: un «pin» care nu fixează nimic ar liniști operatorul fără să-l
    protejeze. Se refuză cu 2, înainte de orice docker (nici pull)."""
    r = w.pin(f"traefik={ref}")
    assert r.rc == 2, r.out
    assert w.docker_lines() == [] and w.original == COMPOSE.encode() and w.backups() == []


def test_unknown_service_and_build_service_are_refused_without_pulling(w):
    """Un nume de serviciu greșit nu are voie să scrie nimic, iar un serviciu cu build: (qpdf-api) se construiește local: o etichetă pe
    el ar fixa numele pe care îl produce build-ul, nu ce trage pull-ul. Ambele se refuză înainte de pull."""
    r = w.pin("traefk=traefik:v3.8.0")
    assert r.rc == 1 and "nu există în configurația compose" in r.out and "traefik" in r.out, r.out
    r = w.pin("qpdf-api=qpdf-api:1.0.0")
    assert r.rc == 1 and "build:" in r.out and "construiește local" in r.out, r.out
    assert pulls(w) == [] and w.original == COMPOSE.encode() and w.backups() == []


def _variant(text_edit):
    return COMPOSE if text_edit is None else text_edit(COMPOSE)


AMBIGUOUS = [
    ("anchor", lambda t: "x-base: &base\n  restart: always\n" + t, "ancoră"),
    ("merge_key", lambda t: t.replace("    restart: always\n    command:", "    <<: {restart: always}\n    command:"), "îmbinare"),
    ("extends", lambda t: t.replace("    command:\n", "    extends:\n      service: n8n\n    command:\n"), "extends"),
    ("include", lambda t: "include:\n  - other.yml\n" + t, "include"),
    ("service_key_twice", lambda t: t.replace("  qpdf-api:", '  traefik:\n    image: traefik\n  qpdf-api:'), "apare de 2 ori"),
    ("two_image_lines", lambda t: t.replace('    image: "traefik"   # citat, cu comentariu\n', '    image: "traefik"\n    image: "traefik"\n'), "2 linii"),
    ("flow_style_service", lambda t: re.sub(r"  traefik:\n(?:    .*\n|\n)*?(?=  qpdf-api:)", "  traefik: {image: traefik, restart: always}\n", t), "forma simplă"),
    ("block_scalar_value", lambda t: t.replace('    image: "traefik"   # citat, cu comentariu\n', "    image: >-\n      traefik\n"), "formă neobișnuită"),
    ("no_image_line", lambda t: t.replace('    image: "traefik"   # citat, cu comentariu\n', ""), "0 linii"),
]


@pytest.mark.parametrize("name,edit,why", AMBIGUOUS, ids=[a[0] for a in AMBIGUOUS])
def test_ambiguous_layouts_are_refused_not_guessed(tmp_path, name, edit, why):
    """Ancore, îmbinări, `extends`, `include`, un serviciu scris de două ori sau inline, două linii image:, o valoare pe bloc sau lipsa ei:
    în fiecare, linia pe care o văd NU e sigur imaginea pe care o vede compose. A ghici ar scrie într-un loc greșit și ar raporta succes."""
    w = World(tmp_path, text=edit(COMPOSE))
    before = w.original
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1, r.out
    assert why in r.out, r.out
    assert w.original == before and w.backups() == [] and w.leftovers() == []
    assert pulls(w) == [], "a tras o imagine înainte să știe că nu poate edita"


def test_image_set_through_a_variable_is_refused(tmp_path):
    """`image: ${REG}/traefik`: valoarea reală e în mediu, nu în fișier. Un pin care ar scrie peste variabilă ar rupe tăcut un deploy
    care o folosește în alt loc."""
    w = World(tmp_path, text=COMPOSE.replace('image: "traefik"', "image: ${REG}/traefik"))
    w.patch(interp={"REG": "docker.io"})
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1 and "variabilă" in r.out, r.out
    assert w.backups() == [] and pulls(w) == []


def test_file_value_that_compose_reads_differently_is_refused(tmp_path):
    """Dacă ce vede compose pentru serviciu nu e ce scrie linia pe care am găsit-o (altă sursă, un override), editarea ar schimba un
    loc fără efect și ar raporta «fixat»."""
    w = World(tmp_path)
    w.patch(tamper={"if_contains": "services:", "service": "traefik", "set": {"image": "altceva:1"}})
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1 and "compose o vede ca altceva:1" in r.out, r.out
    assert w.original == COMPOSE.encode() and w.backups() == []


@LINUX_ONLY
def test_symlinked_compose_file_is_refused(tmp_path):
    """`rename` peste o legătură simbolică ar înlocui legătura, nu fișierul pe care îl citește compose."""
    w = World(tmp_path)
    link = w.dir / "link.yml"
    link.symlink_to(w.file)
    r = w.pin(TRAEFIK_PIN, file=str(link).replace("\\", "/"))
    assert r.rc == 1 and "legătură simbolică" in r.out, r.out


USAGE = [
    (["pin", "--file", "rel/docker-compose.yml", "--pin", TRAEFIK_PIN], "--file refuzat"),
    (["pin", "--file", "/etc/../root/x.yml", "--pin", TRAEFIK_PIN], "--file refuzat"),
    (["pin", "--file", "/srv/x y.yml", "--pin", TRAEFIK_PIN], "--file refuzat"),
    (["pin", "--file", "/srv/x.yml"], "cel puțin un --pin"),
    (["pin", "--file", "/srv/x.yml", "--pin", "traefik"], "SERVICIU=REF"),
    (["pin", "--file", "/srv/x.yml", "--pin", "tra efik=traefik:v3"], "nume de serviciu invalid"),
    (["pin", "--file", "/srv/x.yml", "--pin", TRAEFIK_PIN, "--pin", "traefik=traefik:v3.9.0"], "apare în două"),
    (["pin", "--file", "/srv/x.yml", "--pin", TRAEFIK_PIN, "--expect-sha256", "abc"], "64 de cifre"),
    (["show"], "lipsește --file"),
    (["show", "--file", "/srv/x.yml", "--pin", TRAEFIK_PIN], "doar pentru pin"),
    (["show", "--file", "/srv/x.yml", "--allow-version-change"], "doar pentru pin"),
    (["frobnicate"], "subcomandă necunoscută"),
    (["pin", "--file", "/srv/x.yml", "--wat", "1"], "argument necunoscut"),
    (["pin", "--file"], "cere o valoare"),
]


@pytest.mark.parametrize("args,why", USAGE, ids=[u[1] + str(i) for i, u in enumerate(USAGE)])
def test_bad_arguments_exit_2_without_touching_docker(w, args, why):
    """Un argument greșit trebuie să iasă cu 2 (nu 0, nu 1) înainte de orice docker; altfel un script automat ar crede că s-a refuzat
    ceva real, sau mai rău, că s-a reușit."""
    r = w.run(*args)
    assert r.rc == 2, r.out
    assert why in r.out, r.out
    assert w.docker_lines() == []


# ---------------------------------------------------------------------------------------------------------------
# siguranța scrierii
# ---------------------------------------------------------------------------------------------------------------

def test_file_changed_between_read_and_write_is_refused(w):
    """Cineva (sau o altă mentenanță) editează fișierul în timp ce pull-ul rulează. Fără garda de sumă, scriptul ar scrie peste
    modificarea lui, pe baza unei citiri vechi."""
    w.add_hook(on="pull", action="append", path=w.fpath, text="# adăugat de altcineva\n")
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1 and "s-a schimbat" in r.out, r.out
    after = w.original
    assert after == COMPOSE.encode() + "# adăugat de altcineva\n".encode(), "modificarea altcuiva a fost pierdută sau fișierul a fost rescris"
    assert b'image: "traefik"' in after and w.backups() == []


def test_plan_writes_nothing_and_apply_is_bound_to_the_planned_sum(w):
    """Confirmarea operatorului e despre fișierul PE CARE L-A VĂZUT. Planul nu scrie nimic; scrierea cu suma din plan refuză dacă
    fișierul e altul, altfel «da»-ul ar fi acoperit o modificare pe care nu a văzut-o."""
    plan = w.pin(TRAEFIK_PIN, extra=("--plan",))
    assert plan.rc == 0, plan.out
    planned = re.search(r"^COMPOSE_PIN_FILE_SHA256=([0-9a-f]{64})$", plan.out, re.M)
    assert planned and planned.group(1) == sha(COMPOSE.encode())
    assert w.original == COMPOSE.encode() and w.backups() == []
    stale = w.pin(TRAEFIK_PIN, extra=("--expect-sha256", "0" * 64))
    assert stale.rc == 1 and "de când l-ai văzut" in stale.out and w.original == COMPOSE.encode() and w.backups() == []
    assert pulls(w) == ["pull -q traefik:v3.8.0"] * 1 + [], "refuzul pe sumă trebuie să vină înainte de al doilea pull"
    good = w.pin(TRAEFIK_PIN, extra=("--expect-sha256", planned.group(1)))
    assert good.rc == 0, good.out
    assert b"traefik:v3.8.0" in w.original


def test_failed_proof_restores_the_backup_and_proves_the_restore(w):
    """Compose citește fișierul editat și vede ALTĂ configurație decât cea de dinainte, în afara liniei image: (aici, restart-ul lui n8n
    se schimbă). Fără proba pe tot JSON-ul, pin-ul ar rămâne scris și ar raporta succes; trebuie să pună copia la loc, să DOVEDEASCĂ
    restaurarea (suma) și să iasă cu 1."""
    w.patch(tamper={"if_contains": "traefik:v3.8.0", "service": "n8n", "set": {"restart": "VALOARE_CARE_NU_TREBUIE_TIPARITA"}})
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1, r.out
    assert "diferă după editare" in r.out and "config.services.n8n.restart" in r.out
    assert "restaurat și DOVEDIT" in r.out and sha(COMPOSE.encode()) in r.out
    assert w.original == COMPOSE.encode(), "fișierul n-a fost readus la octeții de dinainte"
    assert len(w.backups()) == 1
    assert "VALOARE_CARE_NU_TREBUIE_TIPARITA" not in r.out, "ieșirea a tipărit VALOAREA, nu doar calea"
    assert w.leftovers() == []


def test_proof_failure_on_other_service_image_is_also_caught(w):
    """Aceeași probă acoperă și «a schimbat imaginea altui serviciu»: dacă s-ar verifica doar imaginea țintă, un editor care atinge și
    linia lui n8n ar trece."""
    w.patch(tamper={"if_contains": "traefik:v3.8.0", "service": "n8n", "set": {"image": "docker.n8n.io/n8nio/n8n:3.0.1"}})
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1 and "config.services.n8n.image" in r.out and w.original == COMPOSE.encode()


def test_target_image_not_applied_is_a_failed_proof(w):
    """Compose vede în continuare imaginea veche (editarea n-a prins): `image` trebuie să fie CEA CERUTĂ în JSON-ul de după; altfel
    scriptul ar raporta «fixat» pentru un fișier pe care compose îl citește ca înainte."""
    w.patch(tamper={"if_contains": "traefik:v3.8.0", "service": "traefik", "set": {"image": "traefik"}})
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1 and "image-ul lui traefik nu e cel cerut" in r.out, r.out
    assert w.original == COMPOSE.encode()


def test_unproven_restore_is_loud_and_never_copies_a_damaged_backup(w):
    """Dacă și copia de rezervă s-a stricat între timp, restaurarea NU e dovedită: scriptul trebuie să zică asta tare și să nu pună peste
    fișier o copie cu altă sumă (ar înlocui o stare cunoscută cu una necunoscută)."""
    w.patch(tamper={"if_contains": "traefik:v3.8.0", "service": "n8n", "set": {"restart": "no"}})
    w.add_hook(on="config-json:2", action="append", path=str(w.file).replace("\\", "/") + ".pin-bak-", glob=True, text="# corupt\n")
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 1, r.out
    assert "RESTAURAREA NU E DOVEDITĂ" in r.out and "cp --" in r.out and sha(COMPOSE.encode()) in r.out
    assert b"traefik:v3.8.0" in w.original, "scriptul a pus peste fișier o copie de rezervă cu altă sumă"
    assert b"# corupt" not in w.original


def test_compose_unreadable_after_edit_is_unknown_and_restores(w):
    """După editare compose nu mai poate citi configurația: nu se poate dovedi nimic, deci NU e «bine» (3), iar fișierul se pune la loc.
    Mesajul lui compose (care aici citează un secret) nu are voie să ajungă în ieșire."""
    w.patch(fail_if_contains="traefik:v3.8.0")
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 3, r.out
    assert "restaurat și DOVEDIT" in r.out and w.original == COMPOSE.encode()
    no_secrets(w, r.out)


def test_container_changed_during_run_is_reported_with_exit_4(w):
    """Scriptul nu recreează nimic, deci dacă amprenta unui container se schimbă în timpul rulării, ceva din afară a atins producția
    (sau scriptul a făcut ce nu are voie): se spune tare, cu 4, nu se trece cu vederea."""
    w.add_hook(on="config-json:2", action="container", name="root-n8n-1", field="restart")
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 4, r.out
    assert "s-a schimbat în timpul rulării" in r.out


# ---------------------------------------------------------------------------------------------------------------
# idempotență, secrete, curățenie
# ---------------------------------------------------------------------------------------------------------------

def test_pinning_the_value_already_written_is_a_no_op_success(w):
    """A doua rulare (sau o rulare repetată după un ssh căzut) nu are voie să facă o a doua copie, să tragă din nou sau să dea eroare:
    «deja fixat» e succes, nu muncă."""
    assert w.pin(TRAEFIK_PIN).rc == 0
    after_first, backups = w.original, w.backups()
    w.log_path.unlink()
    r = w.pin(TRAEFIK_PIN)
    assert r.rc == 0, r.out
    assert "COMPOSE_PIN_NOOP=1" in r.out and "nimic de făcut" in r.out
    assert w.original == after_first and w.backups() == backups
    assert pulls(w) == []


def test_partial_noop_only_edits_what_differs(w):
    """Două pin-uri, unul deja scris: doar celălalt se schimbă, iar diff-ul îl arată numai pe el."""
    assert w.pin(TRAEFIK_PIN).rc == 0
    r = w.pin(TRAEFIK_PIN, N8N_PIN)
    assert r.rc == 0, r.out
    assert "traefik: traefik:v3.8.0 e deja scris" in r.out
    assert b"image: docker.n8n.io/n8nio/n8n:2.49.5" in w.original and w.original.count(b"traefik:v3.8.0") == 1
    assert len(w.backups()) == 2
    assert pulls(w)[-1] == "pull -q docker.n8n.io/n8nio/n8n:2.49.5" and pulls(w).count("pull -q traefik:v3.8.0") == 1


def test_no_environment_value_is_ever_printed(tmp_path):
    """JSON-ul `docker compose config` are secretele din `environment`. În ieșire, în argv-ul docker sau pe disc (directorul temporar) nu
    are voie să ajungă nicio valoare, nici pe calea de succes, nici la refuz, nici la un compose care eșuează cu un mesaj ce citează una."""
    for build in (lambda w: w.show(), lambda w: w.pin(TRAEFIK_PIN), lambda w: w.pin("traefik=traefik:v3.9.0"),
                  lambda w: (w.patch(compose_fail=True), w.show())[1],
                  lambda w: (w.patch(tamper={"if_contains": "traefik:v3.8.0", "service": "n8n", "set": {"restart": "no"}}), w.pin(TRAEFIK_PIN))[1]):
        w = World(tmp_path / f"w{abs(hash(build)) % 10**6}")
        r = build(w)
        no_secrets(w, r.out)
        assert w.leftovers() == [], "au rămas fișiere temporare (JSON-ul de config) pe disc"


def test_compose_error_message_is_not_echoed(w):
    """Mesajul lui `docker compose config` poate cita valori din configurație; scriptul tipărește doar codul."""
    w.patch(compose_fail=True)
    r = w.show()
    assert r.rc == 3 and "mesajul nu se tipărește" in r.out, r.out
    assert "invalid value" not in r.out


def test_project_is_taken_from_the_containers_created_from_the_file(w):
    """Numele proiectului trebuie să fie al containerelor create din ACEST fișier (aici `root`, ca pe gazdă); un nume ghicit din director
    ar face `docker compose -p` să citească alt proiect decât cel care rulează."""
    w.show()
    assert any("-p root " in l for l in w.docker_lines())
    w.load()
    w.state["containers"]["root-n8n-1"]["labels"]["com.docker.compose.project"] = "altul"
    w.save()
    r = w.show()
    assert r.rc == 3 and "mai multe proiecte" in r.out, r.out
