"""`scripts/docker-prune-buildcache.sh` și biblioteca de pe gazdă, rulate ca lanț întreg (lansator -> ssh -> `sudo -n bash -s` ->
docker/curl/df momeală). Fiecare test spune în docstring ce se strică pentru operator dacă regula pică; toate au fost falsificate
(bug reintrodus, test roșu, bug scos).

Ce NU dovedește: un docker, un BuildKit, un ssh sau un sudo reale. Vezi `_prune_world.py`.
"""

from __future__ import annotations

import shutil

import pytest

from _prune_world import HOST_LIB, IMG, LAUNCHER, ROOT, PruneWorld, default_state

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

TOTAL = 95_923_809_987
SNAP = "sudo -n bash -s -- snapshot"
PRUNE = "sudo -n bash -s -- prune"


@pytest.fixture
def w(tmp_path):
    return PruneWorld(tmp_path)


def mutate(w: PruneWorld, **kw):
    w.state.update(kw)
    w.save()


# ---------------------------------------------------------------- dry-run, confirmare, domeniu

def test_dry_run_reports_exact_numbers_and_deletes_nothing(w):
    """Operatorul rulează --dry-run ca să vadă ce câștigă. Dacă el șterge, «doar raportează» a fost o minciună pe un server de producție;
    dacă raportează numere rotunjite, nu poate compara cu ce vede după."""
    rc, out = w.run("--dry-run")
    assert rc == 0, out
    assert w.prune_calls() == [], w.tool_log()
    assert w.load()["cache"] == w.state["cache"]
    assert f"({TOTAL} B)" in out and "5 intrări" in out, out
    assert w.ssh_log() == ["echo conectat", "sudo -n true", SNAP], w.ssh_log()


def test_without_yes_nothing_is_deleted_unless_the_operator_types_da(w):
    """Un script care șterge 87 GB fără să întrebe, sau care socotește un stdin închis drept «da», șterge când operatorul a vrut doar să
    vadă. Răspunsul gol, «nu» sau stdin închis = refuz (1), fără prune."""
    for answer in (b"", b"nu\n", b"DA\n", b"da, dar\n"):
        rc, out = w.run(stdin=answer)
        assert rc == 1 and "anulat" in out, (answer, rc, out)
        assert w.prune_calls() == [], answer
    rc, out = w.run(stdin=b"da\n")
    assert rc == 0, out
    assert len(w.prune_calls()) == 1


def test_a_real_run_frees_the_cache_and_proves_it_with_exact_bytes(w):
    """Efectul trebuie MĂSURAT: octeții eliberați sunt suma intrărilor care existau și nu mai există, nu ce a tipărit prune. Și lanțul de
    comenzi ssh e exact cel așteptat (măsurare, prune, măsurare), fără nimic lăsat pe gazdă."""
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert f"eliberat: 5 intrări, 95.92 GB ({TOTAL} B)" in out, out
    assert w.load()["cache"] == []
    assert w.ssh_log() == ["echo conectat", "sudo -n true", SNAP, PRUNE, SNAP], w.ssh_log()
    assert "+95923809987 B" in out                      # df, doar context
    assert "toate cele 5 de dinainte există și după" in out and "rollback/*: 2 înainte, 2 după" in out


def test_only_the_build_cache_command_reaches_docker(w):
    """Domeniul: `docker system prune`, `image prune`, `volume prune` sau `buildx prune` ar șterge imagini (rollback/*:prev) sau volume
    (datele n8n). Jurnalul momelii trebuie să arate EXACT un prune, `docker builder prune -a -f`, și niciun verb care șterge altceva."""
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert w.prune_calls() == ["docker builder prune -a -f"], w.prune_calls()
    # Lista albă: orice apel în afara ei (rm, kill, stop, network, container, system, image/volume prune) e un apel care nu are ce căuta aici.
    allowed = ("docker version", "docker buildx version", "docker buildx ls", "docker info", "docker image ls", "docker volume ls",
               "docker builder prune -a -f", "curl ", "df ")
    assert w.tool_log(), "jurnalul momelii e gol: lista albă ar trece peste nimic"
    for line in w.tool_log():
        assert line.startswith(allowed), line


def test_a_prune_that_reaches_images_or_volumes_exits_4_and_names_them(w):
    """Dacă prune-ul (sau altceva, în paralel) a luat o imagine dangling, o imagine rollback/*:prev sau volumul n8n, operatorul trebuie
    să afle imediat și cu numele, nu dintr-un deploy care pică mai târziu. Cod 4, nu «gata»."""
    mutate(w, prune_mode="overreach")
    rc, out = w.run("--yes")
    assert rc == 4, out
    assert "rollback/web:prev" in out and "n8n-compose_n8n_data" in out and IMG(4) in out, out
    assert "O IMAGINE, O ETICHETĂ SAU UN VOLUM A DISPĂRUT" in out


def test_a_volume_lost_alone_is_enough_for_exit_4(w):
    """Datele n8n stau într-un volum. Dacă prune (sau altceva, în paralel) a luat volumul și toate imaginile sunt intacte, operatorul pierde
    datele fără nicio alarmă, dacă garda pe volume depinde de cea pe imagini. Pierderea unui volum singură dă cod 4, cu numele lui."""
    mutate(w, prune_mode="overreach", victim_images=[])
    rc, out = w.run("--yes")
    assert rc == 4 and "n8n-compose_n8n_data" in out, out


def test_images_that_appear_in_parallel_are_reported_not_punished(w):
    """Un build sau un deploy în paralel creează imagini și intrări de cache noi. Să le numim «greșeală» ar face scriptul să cadă de
    fiecare dată când gazda e activă; operatorul ar învăța să-l ignore."""
    mutate(w, prune_mode="parallel")
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert "noi apărute între măsurători: 1" in out and "au APĂRUT între cele două măsurători" in out, out


# ---------------------------------------------------------------- efect

def test_a_prune_that_exits_zero_but_removed_nothing_is_a_failure(w):
    """Forma exactă a bug-ului-tipar al depozitului: prune iese cu 0 și tipărește «Total: 0B», iar cache-ul rămâne. Raportul «gata» ar fi
    confirmat intenția, nu efectul."""
    mutate(w, prune_mode="noop")
    rc, out = w.run("--yes")
    assert rc == 1, out
    assert "NU s-a micșorat" in out
    assert "efectul e dovedit" not in out


def test_a_nonzero_prune_fails_even_if_part_of_the_cache_went(w):
    """Un prune căzut la jumătate eliberează ceva, dar a EȘUAT: exit 0 ar ascunde că restul nu s-a șters."""
    mutate(w, prune_mode="partial_fail")
    rc, out = w.run("--yes")
    assert rc == 1, out
    assert "cod nenul" in out


def test_entries_that_stay_because_they_are_in_use_are_reported(w):
    """Un build în curs ține intrări folosite; docker nu le șterge. Operatorul trebuie să afle câte și cât au rămas, nu să creadă că
    discul s-a golit complet. Aceasta NU e o eroare."""
    w.state["cache"].append({"ID": "busy0001", "InUse": True, "Shared": False, "Size": 5_000_000})
    w.state["cache"].append({"ID": "busy0002", "InUse": True, "Shared": False, "Size": 7_000_000})
    w.save()
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert "au rămas 2 intrări în uz" in out and "(12000000 B)" in out, out
    assert [e["ID"] for e in w.load()["cache"]] == ["busy0001", "busy0002"]


def test_an_empty_cache_exits_zero_and_says_so_without_asking(w):
    """Cache gol: nimic de făcut. Nu se pune nicio întrebare și nu se rulează prune (un exit 1 aici ar speria operatorul fără motiv)."""
    mutate(w, cache=[])
    rc, out = w.run()
    assert rc == 0 and "deja gol" in out, out
    assert w.prune_calls() == []


def test_a_cache_that_is_entirely_in_use_is_not_a_failure_and_not_pruned(w):
    """Toate intrările în uz = nimic de eliberat acum. Prune nu se rulează, iar mesajul spune de ce, ca operatorul să încerce mai târziu."""
    for e in w.state["cache"]:
        e["InUse"] = True
    w.save()
    rc, out = w.run("--yes")
    assert rc == 0 and "sunt în uz" in out, out
    assert w.prune_calls() == []


# ---------------------------------------------------------------- builderi

def test_a_current_builder_that_is_not_the_default_is_refused_before_pruning(w):
    """Dacă root are ca builder curent unul docker-container, `docker builder prune` ar curăța cache-ul LUI, nu pe cel măsurat: exit 0
    pe cache neatins sau, mai rău, ștergerea cache-ului unui CI. Refuz (1) înainte de orice ștergere."""
    mutate(w, builders=[{"Name": "default", "Driver": "docker", "Current": False},
                        {"Name": "ci", "Driver": "docker-container", "Current": True}])
    rc, out = w.run("--yes")
    assert rc == 1 and "REFUZ" in out and "«ci»" in out, out
    assert w.prune_calls() == []


def test_extra_builders_are_named_and_never_touched(w):
    """Cache-ul altui builder nu e acoperit de prune pe builderul implicit. Dacă scriptul tace, operatorul crede că tot cache-ul e curat;
    dacă îl șterge, depășește domeniul cerut. Îl numește și spune comanda de mână."""
    w.state["builders"].append({"Name": "ci", "Driver": "docker-container", "Current": False})
    w.save()
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert "ci" in out and "NU e atins" in out and "docker buildx prune --builder NUME" in out, out
    assert w.prune_calls() == ["docker builder prune -a -f"]


def test_a_host_without_the_buildx_plugin_still_works(w):
    """Pe o gazdă fără pluginul buildx operatorul ar primi o eroare de măsurare («n-am putut citi builderii», cod 3) și n-ar putea curăța
    deloc cache-ul, deși nu există alți builderi de care să se ferească. Lipsa pluginului e raportată ca atare, iar curățarea merge."""
    mutate(w, buildx="absent", builders=[])
    rc, out = w.run("--yes")
    assert rc == 0 and "buildx lipsește" in out, out


# ---------------------------------------------------------------- erori

def test_a_stopped_docker_daemon_is_a_clear_refusal_with_its_own_message_shown(w):
    """Daemon oprit: operatorul trebuie să vadă CE a spus docker (nu stderr la /dev/null) și să știe că nu s-a șters nimic. Cod 1."""
    mutate(w, daemon="down")
    rc, out = w.run("--yes")
    assert rc == 1, out
    assert "Cannot connect to the Docker daemon" in out and "daemonul docker nu răspunde" in out, out
    assert w.prune_calls() == []


def test_docker_not_installed_is_reported_as_such(tmp_path):
    """«docker lipsește» și «daemonul e oprit» cer remedii diferite; o confuzie le trimite pe operator pe pista greșită."""
    w = PruneWorld(tmp_path, with_docker=False)
    rc, out = w.run("--yes")
    assert rc == 1 and "docker nu e instalat" in out, out


def test_sudo_refused_is_a_clear_error_and_runs_nothing(w):
    """Contul fără `sudo -n` fără parolă: mesajul trebuie să numească sudo și contul, iar nimic nu rulează."""
    rc, out = w.run("--yes", FAKE_SUDO_REFUSE="1")
    assert rc == 1 and "sudo" in out and "dragos" in out, out
    assert w.tool_log() == []


@pytest.mark.parametrize("mode", ["fail", "garbage", "not_json"])
def test_an_unreadable_cache_answer_is_unknown_not_empty(w, mode):
    """Un API care n-a răspuns, a dat `{}` sau HTML ar arăta, tratat greșit, ca «cache gol» și ar ieși cu 0 («nimic de făcut»). Necunoscutul
    e cod 3, cu mesajul gazdei, nu «bine»."""
    mutate(w, curl_mode=mode)
    rc, out = w.run("--yes")
    assert rc == 3, (mode, rc, out)
    assert "deja gol" not in out and w.prune_calls() == []


def test_a_truncated_measurement_is_unknown(w):
    """Un ssh tăiat în mijlocul măsurării lasă un fișier care arată parțial bine (mai puține intrări). Fără SNAPSHOT_END și fără numărul
    de intrări potrivit, răspunsul nu se folosește: cod 3, nu un «eliberat» calculat pe jumătate de listă."""
    rc, out = w.run("--yes", FAKE_SSH_TRUNCATE_SNAPSHOT_N="1")
    assert rc == 3 and "trunchiat" in out, out
    assert w.prune_calls() == []


def test_when_the_after_measurement_fails_success_is_not_claimed(w):
    """Prune a rulat, dar nu putem verifica: efectul NU e dovedit. Exit 0 ar fi aici exact «intenția în loc de efect». Truncheat = 3."""
    rc, out = w.run("--yes", FAKE_SSH_TRUNCATE_SNAPSHOT_N="2")
    assert rc == 3 and "NU pot dovedi efectul" in out, out
    assert len(w.prune_calls()) == 1


def test_ssh_dropping_during_the_prune_is_255_with_an_unknown_result(w):
    """Dacă ssh cade în timpul prune, rezultatul e necunoscut; scriptul nu are voie să spună «nimic nu s-a întâmplat»: 255 și sfatul de
    a rula --dry-run."""
    rc, out = w.run("--yes", FAKE_SSH_FAIL_ON="-- prune")
    assert rc == 255 and "NECUNOSCUT" in out, out


# ---------------------------------------------------------------- argumente și transport

@pytest.mark.parametrize("args", [
    ["--host", "-oProxyCommand=id"], ["--host", "a b"], ["--host", "h;id"], ["--port", "0"], ["--port", "70000"], ["--port", "22;id"],
    ["--user", "A;id"], ["--frobnicate"], ["--dry-run", "--yes"], ["--host"],
])
def test_bad_arguments_are_refused_before_any_connection(w, args):
    """`--host -oProxyCommand=...` ar rula o comandă pe stația operatorului; un port cu `;` ajungea în aritmetica bash. Cod 2, jurnal ssh gol."""
    import subprocess
    from _su_shell import BASH, posix
    base = ["--key", posix(w.tmp / "k")]
    if "--host" not in args[:1]:
        base += ["--host", "h.example.invalid"]
    proc = subprocess.run([BASH, posix(LAUNCHER), *base, *args], capture_output=True, env=w.env(), timeout=60)
    assert proc.returncode == 2, proc.stderr
    assert w.ssh_log() == []


def test_a_host_script_with_crlf_is_refused_before_it_is_sent(tmp_path):
    """Un CR în biblioteca trimisă devine `bad interpreter: bash^M` pe gazdă. Refuzat local, cu cod 2, înainte de orice conexiune."""
    w = PruneWorld(tmp_path)
    (tmp_path / "scripts" / "lib").mkdir(parents=True)
    shutil.copy(LAUNCHER, tmp_path / "scripts" / "docker-prune-buildcache.sh")
    lib = tmp_path / "scripts" / "lib" / "docker-prune-buildcache-host.sh"
    lib.write_bytes(HOST_LIB.read_bytes().replace(b"\n", b"\r\n"))
    rc, out = w.run("--dry-run", launcher=tmp_path / "scripts" / "docker-prune-buildcache.sh")
    assert rc == 2 and "CR" in out, out
    assert w.ssh_log() == []


def test_the_scripts_are_lf_only_and_pass_bash_n():
    """Un CR în lansator sau în bibliotecă strică scriptul pe gazdă sau în Git Bash; verificat pe octeți."""
    import subprocess
    from _su_shell import BASH, posix
    for p in (LAUNCHER, HOST_LIB):
        assert b"\r" not in p.read_bytes(), p
        assert subprocess.run([BASH, "-n", posix(p)]).returncode == 0, p


# ---------------------------------------------------------------- round 2

def with_images_after(w, images):
    w.state["images_after_prune"] = images
    w.save()


def test_a_retag_by_a_parallel_rebuild_is_not_a_lost_image(w):
    """O reconstruire în paralel (nis2-api, nis2-worker) mută `app:latest` pe un ID nou; vechiul ID rămâne ca <none>:<none>. Nu s-a pierdut
    nimic. O alarmă cod 4 aici ar fi falsă la fiecare build al zilei, iar operatorul ar învăța să ignore exact alarma care contează."""
    with_images_after(w, [[IMG(1), "<none>:<none>"], [IMG(9), "app/web:1.0"], [IMG(2), "rollback/web:prev"], [IMG(3), "rollback/api:prev"],
                          [IMG(4), "<none>:<none>"], [IMG(5), "postgres:16"]])
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert "DISPĂRUTE" not in out and "ID-uri de imagine noi apărute între măsurători: 1" in out, out


def test_losing_an_image_id_alone_is_exit_4(w):
    """Un ID de imagine (aici una dangling) care dispare fără ca vreo etichetă să se piardă e tot o pierdere: un `image prune` care ia doar
    imaginile dangling nu trebuie să treacă drept «bine» fiindcă etichetele sunt intacte."""
    with_images_after(w, [i for i in w.state["images"] if i[0] != IMG(4)])
    rc, out = w.run("--yes")
    assert rc == 4 and IMG(4) in out and "etichete de imagine (care trebuie să ducă la o imagine): toate" in out, out


def test_losing_an_image_ref_alone_is_exit_4(w):
    """O etichetă (`app/web:1.0`) care nu mai duce la nicio imagine, deși ID-ul a rămas ca <none>, înseamnă că imaginea de producție a fost
    dezetichetată: containerul următor nu pornește. Cod 4, cu eticheta numită."""
    with_images_after(w, [[IMG(1), "<none>:<none>"]] + [i for i in w.state["images"] if i[0] != IMG(1)])
    rc, out = w.run("--yes")
    assert rc == 4 and "app/web:1.0" in out and "ID-uri de imagine (și dangling): toate" in out, out


def add_shared(w):
    w.state["cache"] += [{"ID": "shared0001", "InUse": False, "Shared": True, "Size": 5_000_000_000},
                         {"ID": "shared0002", "InUse": False, "Shared": True, "Size": 3_912_850_978}]
    w.save()


def test_shared_entries_are_not_counted_as_freed_or_reclaimable(w):
    """Straturile partajate cu imagini (Shared) rămân după prune; docker nu le numără ca RECLAIMABLE. Dacă scriptul le adună la «eliberat»,
    operatorul crede că a recuperat 8,9 GB care sunt tot pe disc (pe gazdă: 95,92 GB total, dar doar 87,01 GB eliberabili)."""
    add_shared(w)
    rc, out = w.run("--dry-run")
    assert rc == 0 and f"eliberabile: 5, 95.92 GB ({TOTAL} B)" in out and "partajate cu imagini: 2 (8912850978 B)" in out, out
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert f"eliberat: 5 intrări, 95.92 GB ({TOTAL} B)" in out, out
    assert "au rămas 2 intrări partajate cu imagini" in out and "build pornit" not in out, out
    assert sorted(e["ID"] for e in w.load()["cache"]) == ["shared0001", "shared0002"]


def test_a_cache_with_only_shared_and_in_use_entries_has_nothing_to_free(w):
    """Doar intrări partajate sau în uz: prune n-ar șterge nimic. A-l rula și a raporta «NU s-a micșorat» (cod 1) ar înfricoșa operatorul
    pentru un cache care e, de fapt, în starea în care docker îl lasă."""
    for e in w.state["cache"]:
        e["Shared"] = True
    w.save()
    rc, out = w.run("--yes")
    assert rc == 0 and "nimic de eliberat acum" in out and "5 sunt partajate" in out, out
    assert w.prune_calls() == []


def test_a_prune_that_exits_zero_but_leaves_most_of_the_cache_is_partial_not_proven(w):
    """Un prune care a șters doar o parte și a ieșit cu 0 nu are voie să se încheie cu «gata: efectul e dovedit»: operatorul ar crede discul
    curățat. Verdict: PARȚIAL, cod 1, cu ce a rămas."""
    mutate(w, prune_mode="partial_ok")
    rc, out = w.run("--yes")
    assert rc == 1 and "PARȚIAL: au rămas 3 intrări eliberabile" in out, out
    assert "efectul e dovedit" not in out


def test_entries_that_became_in_use_during_the_prune_are_explained_not_partial(w):
    """Un build pornit în timpul prune ia în folosință o intrare eliberabilă; docker are dreptate să o țină. Să o numim PARȚIAL ar da cod 1
    la fiecare rulare pe o gazdă activă."""
    mutate(w, busy_during_prune=["entry0000"])
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert "eliberat: 4 intrări" in out and "au ajuns între timp în uz sau partajate" in out and "PARȚIAL" not in out, out


def test_ssh_dropping_during_the_first_measurement_is_255_and_runs_nothing(w):
    """Dacă ssh cade chiar la prima măsurare, scriptul n-are nicio stare: trebuie să iasă cu 255, nu cu 0 («totul bine») și să nu ruleze
    prune pe o gazdă pe care nu a văzut-o."""
    rc, out = w.run("--yes", FAKE_SSH_FAIL_SNAPSHOT_N="1")
    assert rc == 255, out
    assert w.prune_calls() == []


@pytest.mark.parametrize("sed,why", [
    ("/^BCENTRY entry0001 /d", "numărul de intrări declarat nu se potrivește cu cele primite"),
    ("/^DF /d", "lipsește linia df"),
    ("/^DOCKER_SERVER=/d", "lipsește versiunea serverului"),
    ("s/^(BCENTRY [^ ]+ [01] [0-9]+) [01]$/\\1/", "o intrare fără câmpul Shared"),
])
def test_an_incomplete_measurement_is_unknown_not_a_basis_for_deleting(w, sed, why):
    """Un răspuns al gazdei care pare întreg, dar nu e (vezi parametrul), ar da un «eliberat» calculat pe jumătate din date sau ar socoti o intrare
    partajată drept eliberabilă. Cod 3, fără prune."""
    rc, out = w.run("--yes", FAKE_SSH_SED=sed, FAKE_SSH_SED_N="1")
    assert rc == 3 and "NU e «bine»" in out, (why, rc, out)
    assert w.prune_calls() == []


def test_what_changed_while_the_operator_was_deciding_is_not_blamed_on_prune(w, tmp_path):
    """Operatorul citește planul un minut; între timp un build își șterge o intrare. Dacă măsurătoarea «înainte» rămâne cea de dinainte de
    întrebare, intrarea aceea ar fi numărată ca eliberată de prune, iar «eliberat» ar fi umflat. Măsurătoarea se reia după «da»."""
    import sys
    from _su_shell import posix
    hook = tmp_path / "hook.py"
    hook.write_text("import json,os\np=os.environ['FAKE_PRUNE_STATE']\nst=json.load(open(p))\n"
                    "st['cache']=[e for e in st['cache'] if e['ID']!='entry0000']\njson.dump(st,open(p,'w'))\n", encoding="utf-8")
    rc, out = w.run(stdin=b"da\n", FAKE_SSH_HOOK_N="1", FAKE_SSH_HOOK=f'"{posix(sys.executable)}" "{posix(hook)}"')
    assert rc == 0, out
    assert "măsurătoare reluată după confirmare" in out and "eliberat: 4 intrări" in out, out


def test_the_ssh_key_exchange_warning_is_not_repeated_for_every_probe(w):
    """Avertismentul ssh despre schimbul de chei se tipărea la fiecare sondă (de două ori într-o rulare); operatorul învață să nu mai
    citească stderr, exact locul unde ajunge un mesaj real."""
    rc, out = w.run("--dry-run")
    assert rc == 0 and "post-quantum" not in out, out


def test_shared_entries_that_vanish_are_not_added_to_the_freed_total(w):
    """Dacă o intrare partajată cu o imagine dispare între măsurători (o imagine ștearsă în paralel), ea nu a fost «eliberată de prune» și docker
    nu o numără la RECLAIMABLE. Adunată la total, ar umfla cifra pe care operatorul o raportează mai departe cu 8,9 GB."""
    add_shared(w)
    mutate(w, drop_shared_during_prune=True)
    rc, out = w.run("--yes")
    assert rc == 0, out
    assert f"eliberat: 5 intrări, 95.92 GB ({TOTAL} B)" in out and "2 intrări care erau în uz sau partajate" in out, out
