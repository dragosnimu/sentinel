"""Deciziile pure din `scripts/lib/system-update-lib.sh`.

Fiecare test numește, în docstring, ce se strică pentru operator dacă decizia greșește.
Rulează funcțiile LIVRATE într-un singur bash pe test (tabel de cazuri), nu o copie.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from _su_shell import lib_table, rc_of

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

# Coada unui pg_dumpall 16 REAL, măsurată pe gazdă (19 nov 2026): `\unrestrict` ÎNAINTEA
# marcajului, apoi `--` și linii goale DUPĂ el.
PG_TAIL = "\\unrestrict phQdbcKpc3\n\n--\n-- PostgreSQL database cluster dump complete\n--\n\n"
PG_HEAD = "--\n-- PostgreSQL database cluster dump\n--\n\n\\restrict 8VaY\n\nSET default_tr\n"
MARIA_HEAD = "/*M!999999\\- enable the sandbox mode */\n-- MariaDB dump 10.19-11.4.7-MariaDB, for debian-linux-gnu\n"
MARIA_TAIL = "/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;\n\n-- Dump completed on 2026-11-19 18:12:24\n"


def _tail_ok(kind: str, text: str) -> bool:
    return rc_of(f"su_dump_tail_ok {kind}", text) == 0


def _head_ok(kind: str, text: str) -> bool:
    return rc_of(f"su_dump_header_ok {kind}", text) == 0


def test_dump_tail_accepts_a_real_pg_dumpall_ending_and_rejects_truncation():
    """Un `tail -n 1 | grep complete` ar fi respins FIECARE dump pg_dumpall sănătos (marcajul
    nu e ultima linie), iar backup-ul ar fi raportat «eșec» pe toate bazele, adică operatorul
    ar învăța să ignore faza care îi apără datele. În sens invers, un dump tăiat la mijloc
    (docker exec căzut, disc plin) NU are voie să treacă drept complet."""
    assert _tail_ok("postgres", "INSERT INTO t VALUES (1);\n" + PG_TAIL)
    assert not _tail_ok("postgres", "INSERT INTO t VALUES (1);\nINSERT INTO t VALUES (2")
    assert not _tail_ok("postgres", "")
    # marcajul urmat de conținut: nu e sfârșitul dump-ului
    assert not _tail_ok("postgres", PG_TAIL + "INSERT INTO t VALUES (9);\n")
    assert _tail_ok("mariadb", MARIA_TAIL)
    assert not _tail_ok("mariadb", "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\nINSERT INTO t VALUES (1)")
    # un marcaj de MariaDB nu încheie un dump de Postgres
    assert not _tail_ok("postgres", MARIA_TAIL)


def test_dump_header_is_required_at_the_start():
    """Un fișier care se termină corect dar nu începe ca un dump (alt conținut, ieșire de
    eroare scrisă în loc) nu e un dump. Antetul și coada sunt două dovezi independente."""
    assert _head_ok("postgres", PG_HEAD)
    assert _head_ok("mariadb", MARIA_HEAD)
    assert not _head_ok("postgres", "psql: error: connection refused\n")
    assert not _head_ok("mariadb", PG_HEAD)
    assert rc_of("su_dump_header_ok nesuportat", "x") == 2


def test_health_verdict_is_relative_to_the_baseline_not_to_green():
    """bet-calculator era unhealthy ÎNAINTE de orice schimbare. Un verify care cere «tot
    healthy» ar fi roșu azi indiferent ce facem, iar operatorul ar învăța să nu-l mai citească;
    unul care compară cu baseline-ul spune «la fel de rău ca înainte» și prinde ce S-A STRICAT."""
    cases = {
        "same_bad": "su_container_verdict running unhealthy running unhealthy",
        "broke": "su_container_verdict running healthy running unhealthy",
        "down": "su_container_verdict running healthy exited ''",
        "restarting": "su_container_verdict running healthy restarting ''",
        "gone": "su_container_verdict running none missing none",
        "fine": "su_container_verdict running healthy running healthy",
        "nohc_fine": "su_container_verdict running none running none",
        "improved": "su_container_verdict running unhealthy running healthy",
        "was_down": "su_container_verdict exited none running unhealthy",
        "starting": "su_container_verdict running healthy running starting",
        "lost_healthcheck": "su_container_verdict running healthy running none",
    }
    got = lib_table(list(cases.items()))
    assert got == {
        "same_bad": "same-bad", "broke": "worse", "down": "worse", "restarting": "worse",
        "gone": "worse", "fine": "ok", "nohc_fine": "ok", "improved": "ok", "was_down": "skip",
        "starting": "pending", "lost_healthcheck": "unknown",
    }


def test_flap_verdict_needs_two_identical_samples():
    """Un serviciu în buclă de repornire trece prin `active` la fiecare ciclu: o verificare
    făcută o singură dată îl declară sănătos. Două eșantioane cu ACELAȘI număr de reporniri și
    același moment de intrare în starea activă sunt ce dovedește că a rămas pornit."""
    got = lib_table([
        ("stable", "su_flap_verdict 'active|0|100' 'active|0|100' active"),
        ("looping", "su_flap_verdict 'active|3|100' 'active|4|160' active"),
        ("restarted_once", "su_flap_verdict 'active|0|100' 'active|0|170' active"),
        ("died", "su_flap_verdict 'active|0|100' 'failed|0|100' active"),
        ("ctr_stable", "su_flap_verdict 'running|0|T1' 'running|0|T1' running"),
        ("ctr_wrong_up", "su_flap_verdict 'running|0|T1' 'running|0|T1' active"),
    ])
    assert got == {"stable": "stable", "looping": "flapping", "restarted_once": "flapping",
                   "died": "down", "ctr_stable": "stable", "ctr_wrong_up": "down"}


def test_db_classification_follows_what_runs_not_the_image_name():
    """Pe gazdă `nis2-backup` și `oferte-backup` au imaginea postgres:16-alpine, ca bazele,
    dar rulează `sh -c 'pg_dump … | gzip'`. O regulă «imagine postgres = bază» le-ar cere
    dump-uri, ar eșua, iar faza de backup ar fi roșie de la prima rulare; invers, o bază cu
    imagine proprie ar rămâne FĂRĂ dump, tăcut. Un caz neclar e `unclear` (eșec), nu «nu e bază»."""
    got = lib_table([
        ("pg", "su_classify_db postgres:16-alpine docker-entrypoint.sh postgres"),
        ("pgvector", "su_classify_db pgvector/pgvector:pg16 docker-entrypoint.sh postgres"),
        ("maria", "su_classify_db mariadb:11.4.7 docker-entrypoint.sh mariadbd"),
        ("sidecar_sh_c", "su_classify_db postgres:16-alpine sh -c 'while true; do pg_dump -h db x | gzip; done'"),
        ("sidecar_script", "su_classify_db postgres:16-alpine sh /backup.sh"),
        ("sidecar_port_registry", "su_classify_db registry:5000/postgres:16 sh -c x"),
        ("custom_image_runs_postgres", "su_classify_db registry.local/acme/db:1 postgres -c fsync=on"),
        ("custom_entrypoint", "su_classify_db postgres:16 /custom-start.sh run"),
        ("app", "su_classify_db dms-app uvicorn app:app"),
        ("exporter", "su_classify_db mysql-exporter /bin/mysqld_exporter"),
        ("no_argv", "su_classify_db nginx:1"),
    ])
    assert got == {"pg": "postgres", "pgvector": "postgres", "maria": "mariadb",
                   "sidecar_sh_c": "sidecar", "sidecar_script": "sidecar", "sidecar_port_registry": "sidecar",
                   "custom_image_runs_postgres": "postgres", "custom_entrypoint": "unclear",
                   "app": "other", "exporter": "other", "no_argv": "other"}


def gate_out(path, now, *dbs, max_age=43200):
    from _su_shell import lib_table, posix
    return lib_table([("r", f"su_backup_gate '{posix(path)}' {now} {max_age} {' '.join(dbs)} | tr '\\n' ' '")])["r"].split()


def test_backup_gate_requires_fresh_and_covering_and_ok(tmp_path):
    """«Există un backup» nu ajunge ca să pornești dnf sau să recreezi o bază: trebuie să fie recent, să
    acopere FIECARE bază care există acum (una apărută după backup n-are dump) și să nu fie un dump eșuat.
    Fără asta, o actualizare pornește peste date nesalvate."""
    import time

    from _su_manifest import write_manifest

    now = int(time.time())
    good = write_manifest(tmp_path, [("ok", "nis2-db", "postgres"), ("ok", "snipeit-db", "mariadb")])
    assert gate_out(good, now, "nis2-db", "snipeit-db") == []
    assert gate_out(good, now, "nis2-db", "new-db") == ["missing:new-db"]
    assert gate_out(write_manifest(tmp_path, [("ok", "nis2-db", "postgres")], epoch=now - 99999), now, "nis2-db") == ["stale"]
    assert gate_out(write_manifest(tmp_path, [("failed", "nis2-db", "postgres")]), now, "nis2-db") == ["failed:nis2-db"]
    assert gate_out(write_manifest(tmp_path, [("ok", "nis2-db", "postgres")], epoch=now + 99999), now, "nis2-db") == ["stale"]
    assert gate_out(tmp_path / "nu-exista", now, "nis2-db") == ["no-manifest"]


def test_backup_gate_matches_the_name_field_exactly_not_the_kind_column(tmp_path):
    """`grep -F "|postgres|"` potrivea și coloana «fel»: un container numit `postgres` sau `mariadb` trecea
    poarta cu dump-ul lipsă sau eșuat, doar fiindcă un ALT dump avea felul `postgres`."""
    import time

    from _su_manifest import write_manifest

    now = int(time.time())
    m = write_manifest(tmp_path, [("ok", "nis2-db", "postgres"), ("failed", "other", "mariadb")])
    assert gate_out(m, now, "postgres") == ["missing:postgres"]
    assert gate_out(m, now, "mariadb") == ["missing:mariadb"]
    assert gate_out(m, now, "other") == ["failed:other"]


def test_backup_gate_checks_the_dump_files_at_gate_time_not_just_the_manifest(tmp_path):
    """Manifestul e o declarație. Între backup și actualizare un dump poate fi șters, trunchiat sau
    înlocuit: poarta recitește fișierul — există, are mărimea și suma din manifest."""
    import time

    from _su_manifest import write_manifest

    now = int(time.time())
    entries = [("ok", "nis2-db", "postgres")]
    assert gate_out(write_manifest(tmp_path, entries, tamper="-nis2-db"), now, "nis2-db") == ["file-missing:nis2-db"]
    assert gate_out(write_manifest(tmp_path, entries, tamper="nis2-db"), now, "nis2-db") == ["file-changed:nis2-db"]
    # aceeași mărime, alt conținut: doar suma îl prinde
    assert gate_out(write_manifest(tmp_path, entries, tamper="~nis2-db"), now, "nis2-db") == ["file-changed:nis2-db"]
    assert gate_out(write_manifest(tmp_path, entries), now, "nis2-db") == []


def test_report_final_is_a_verdict_on_the_current_state_not_a_log(tmp_path):
    """Raportul fazei containers e un jurnal de acțiuni. Rezultatul final al unui serviciu: `recreated` și
    `verified` înlocuiesc stările obișnuite; `up-to-date` NU înlocuiește nimic; iar un eșec (vezi testul
    următor) nu dispare — altfel un eșec de la o rulare anterioară ieșea din rezumat fără ca cineva să fi
    vindecat containerul."""
    from _su_shell import lib_table, posix

    report = tmp_path / "r.txt"
    report.write_text("\n".join([
        "p|a|failed|x", "p|a|up-to-date|y",                  # eșecul rămâne
        "p|c|recreated|1 -> 2", "p|c|up-to-date|z",          # schimbarea rămâne
        "p|d|hold-moved-tag|t", "p|d|up-to-date|z",          # reținerea rămâne
        "p|e|pull-failed|i", "p|e|up-to-date|z", "p|e|failed|f",
        "p|g|recreated|1 -> 2", "p|g|read-ok|r",             # citirea configurației nu șterge schimbarea
    ]) + "\n", encoding="utf-8", newline="\n")
    out = lib_table([("r", f"su_report_final '{posix(report)}' | tr '\n' ';'")])["r"]
    assert out == "p/a|failed|x;p/c|recreated|1 -> 2;p/d|hold-moved-tag|t;p/e|failed|f;p/g|recreated|1 -> 2;"
    assert lib_table([("r", f"su_report_final '{posix(tmp_path / 'lipsa')}' | wc -l")])["r"].strip() == "0"


# (nume, linii de raport, rezultat final așteptat «acțiune» sau «acțiune|detaliu»)
STICKY_CASES = [
    # failed: doar --retry-failed (retried) urmat de verificare îl șterge
    ("failed-vs-skip-unreadable", ["failed|x", "skip-unreadable|c"], "failed|x"),
    ("failed-vs-hold-skip-notreq", ["failed|x", "hold-failed|h", "skip-not-requested|n", "skip-no-context|n"], "failed|x"),
    ("failed-vs-verified-alone", ["failed|x", "verified|ok"], "failed|x"),
    ("failed-vs-recreated-alone", ["failed|x", "recreated|1 -> 2"], "failed|x"),
    ("failed-retried-verified", ["failed|x", "retried|r", "verified|ok"], "verified|ok"),
    ("failed-retried-up-to-date-verified", ["failed|x", "retried|r", "up-to-date|u", "verified|ok"], "verified|ok"),
    ("failed-retried-recreated", ["failed|x", "retried|r", "pulled|p", "tagged|t", "recreated|1 -> 2"], "recreated|1 -> 2"),
    ("failed-retried-skip-verified", ["failed|x", "retried|r", "skip-not-requested|n", "verified|ok"], "failed|x"),
    ("failed-retried-pullfail-keeps-failed", ["failed|x", "retried|r", "pull-failed|i"], "failed|x"),
    ("failed-retried-pullfail-verified", ["failed|x", "retried|r", "pull-failed|i", "verified|ok"], "failed|x"),
    # pull-failed: doar un pull reușit urmat de verificare
    ("pull-failed-vs-verified-alone", ["pull-failed|i", "verified|ok"], "pull-failed|i"),
    ("pull-failed-vs-skip", ["pull-failed|i", "hold-config-drift|c", "verified|ok"], "pull-failed|i"),
    ("pull-failed-pulled-verified", ["pull-failed|i", "pulled|p", "up-to-date|u", "verified|ok"], "verified|ok"),
    ("pull-failed-pulled-skip-verified", ["pull-failed|i", "pulled|p", "skip-drift|d", "verified|ok"], "pull-failed|i"),
    ("pull-failed-pulled-recreated", ["pull-failed|i", "pulled|p", "tagged|t", "recreated|1 -> 2"], "recreated|1 -> 2"),
    ("pull-failed-pulled-then-tag-failed", ["pull-failed|i", "pulled|p", "tag-failed|g", "recreated|1 -> 2"], "pull-failed|i"),
    # build-failed: doar un build reușit (--rebuild) urmat de verificare
    ("build-failed-vs-notreq-verified", ["build-failed|b", "skip-not-requested|n", "verified|ok"], "build-failed|b"),
    ("build-failed-built-recreated", ["build-failed|b", "built|b", "tagged|t", "recreated|1 -> 2"], "recreated|1 -> 2"),
    ("build-failed-built-verified", ["build-failed|b", "built|b", "verified|ok"], "verified|ok"),
    ("build-failed-vs-pulled-recreated", ["build-failed|b", "pulled|p", "recreated|1 -> 2"], "build-failed|b"),
    # tag-failed și unread
    ("tag-failed-vs-recreated-alone", ["tag-failed|g", "recreated|1 -> 2"], "tag-failed|g"),
    ("tag-failed-tagged-recreated", ["tag-failed|g", "tagged|t", "recreated|1 -> 2"], "recreated|1 -> 2"),
    # runda 7: stale-baseline se ține până când faptul încetează să fie adevărat (owned-ok, direct); nimic altceva nu-l șterge
    ("stale-vs-skip-verified", ["stale-baseline|s", "skip-not-requested|n", "verified|ok"], "stale-baseline|s"),
    ("stale-vs-recreated-pulled", ["stale-baseline|s", "pulled|p", "tagged|t", "recreated|1 -> 2"], "stale-baseline|s"),
    ("stale-owned-ok", ["stale-baseline|s", "owned-ok|o", "up-to-date|z"], "up-to-date|z"),
    ("stale-owned-ok-then-stale-again", ["stale-baseline|s", "owned-ok|o", "stale-baseline|t"], "stale-baseline|t"),
    ("stale-shown-before-other-failures", ["tag-failed|g", "stale-baseline|s", "failed|x"], "stale-baseline|s"),
    ("pull-failed-survives-owned-ok", ["pull-failed|i", "owned-ok|o", "verified|ok"], "pull-failed|i"),
    ("unread-vs-skip", ["unread|u", "skip-not-requested|n", "verified|ok"], "unread|u"),
    ("unread-read-ok", ["unread|u", "read-ok|r", "up-to-date|z"], "up-to-date|z"),
    # un eșec nou după succes se așază peste; detaliul cu `|` se păstrează
    ("fail-again-after-clear", ["failed|x", "retried|r", "verified|ok", "failed|y|z"], "failed|y|z"),
    ("two-flags-failed-shown-first", ["pull-failed|i", "failed|x"], "failed|x"),
    ("two-flags-clear-one", ["pull-failed|i", "failed|x", "pulled|p", "verified|ok"], "failed|x"),
    # runda 6: succesul ALTEI stări dezarmează (un serviciu nu e și trasat, și construit); tagged face parte din orice drum
    ("pull-failed-pulled-built-verified", ["pull-failed|i", "pulled|p", "built|b", "verified|ok"], "pull-failed|i"),
    ("build-failed-built-pulled-verified", ["build-failed|b", "built|b", "pulled|p", "verified|ok"], "build-failed|b"),
    ("pull-failed-pulled-retried-verified", ["pull-failed|i", "pulled|p", "retried|r", "verified|ok"], "pull-failed|i"),
    ("failed-retried-read-ok-verified", ["failed|x", "retried|r", "read-ok|r", "verified|ok"], "failed|x"),
    ("tag-failed-tagged-pulled-verified", ["tag-failed|g", "tagged|t", "pulled|p", "verified|ok"], "tag-failed|g"),
    ("pull-failed-pulled-tagged-verified", ["pull-failed|i", "pulled|p", "tagged|t", "verified|ok"], "verified|ok"),
    ("tag-failed-pulled-tagged-verified", ["tag-failed|g", "pulled|p", "tagged|t", "verified|ok"], "verified|ok"),
    ("failed-retried-built-tagged-recreated", ["failed|x", "retried|r", "built|b", "tagged|t", "recreated|1 -> 2"], "recreated|1 -> 2"),
]


def test_sticky_failures_are_cleared_only_by_their_own_success_followed_by_a_check(tmp_path):
    """Un `failed`/`pull-failed`/`build-failed`/`tag-failed`/`unread` din faza containers era înlocuit de ORICE
    linie ulterioară (`skip-unreadable`, `hold-*`, `skip-not-requested`, un `verified` al containerului vechi):
    o rulare ulterioară `--only` ieșea «TOTUL DOVEDIT» și scria containers.ok peste un serviciu rămas picat.
    Acum rezultatul final se reduce într-un singur loc, iar o stare lipicioasă se șterge doar prin succesul
    ei specific (retried / pulled / built / tagged), urmat de o verificare; orice altceva între ele dezarmează."""
    from _su_shell import LIB_SH, lib_table, posix, run_bash

    # UN fișier de raport, câte un «serviciu» (= numele cazului) pe caz, UN apel: o comandă `bash -c` cu un tabel de 40 de cazuri cu
    # căi lungi trece de limita liniei de comandă din Windows, iar tăierea ei ca un citat neînchis lăsa ultimele cazuri nerulate.
    rep = tmp_path / "all.txt"
    rep.write_text("".join(f"p|{name}|{l}\n" for name, lines, _ in STICKY_CASES for l in lines), encoding="utf-8", newline="\n")
    proc = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}'")
    assert proc.returncode == 0, proc.stderr
    got = {}
    for line in proc.stdout.splitlines():
        key, _, rest = line.partition("|")
        got[key.split("/", 1)[1]] = rest
    for name, _, want in STICKY_CASES:
        assert got.get(name, "") == want, (name, got.get(name), want)
    assert [lib_table([("s", f"su_is_sticky {st} && echo y || echo n")])["s"] for st in
            ("failed", "pull-failed", "build-failed", "tag-failed", "unread", "stale-baseline", "verified", "skip-drift", "hold-failed", "")] == ["y", "y", "y", "y", "y", "y", "n", "n", "n", "n"]


def test_age_state_treats_a_missing_timestamp_as_missing_not_fresh():
    """Un `stat` care n-a putut citi fișierul backup-ului zilnic dă un text gol; gol nu e
    «proaspăt»."""
    got = lib_table([
        ("fresh", "su_age_state 1000 1100 500"),
        ("stale", "su_age_state 1000 9000 500"),
        ("missing", "su_age_state '' 9000 500"),
        ("junk", "su_age_state 'stat: cannot' 9000 500"),
    ])
    assert got == {"fresh": "fresh", "stale": "stale", "missing": "missing", "junk": "missing"}


def test_pull_decision_never_pulls_what_it_cannot_vouch_for():
    """snipeit-app-1 rulează imaginea din august, eticheta arată una din octombrie: un `up`
    ar sări peste toate versiunile dintre ele (migrări la pornire). cryptoitdata-hub:latest nu a
    venit niciodată dintr-un registru: un pull l-ar căuta pe Docker Hub sub un nume pe care îl
    poate deține oricine. Un ID gol nu are etichetă de tras. Fiecare caz se sare CU MOTIV."""
    got = lib_table([
        ("pull", "su_pull_decision postgres:16-alpine yes 2 sha256:aaa sha256:aaa"),
        ("moved_tag", "su_pull_decision snipe/snipe-it:latest yes 3 sha256:old sha256:new"),
        ("local", "su_pull_decision cryptoitdata-hub:latest yes 0 sha256:aaa sha256:aaa"),
        ("bare_id", "su_pull_decision 6cd5a2fc29fe yes 2 sha256:aaa sha256:aaa"),
        ("bare_sha", "su_pull_decision sha256:6cd5a2fc29febffae95c yes 2 a a"),
        ("no_image", "su_pull_decision x:1 no 2 a a"),
        ("digests_unreadable", "su_pull_decision x:1 yes '?' a a"),
        ("tag_unknown", "su_pull_decision x:1 yes 2 sha256:aaa ''"),
    ])
    assert got == {"pull": "pull", "moved_tag": "hold-moved-tag", "local": "skip-local",
                   "bare_id": "skip-bare-id", "bare_sha": "skip-bare-id", "no_image": "skip-no-image",
                   "digests_unreadable": "skip-unknown", "tag_unknown": "hold-moved-tag"}


def test_pull_result_does_not_read_a_failed_pull_as_up_to_date():
    """Un registru căzut face `docker pull` să iasă nenul fără să schimbe nimic. «Imaginea
    locală e cea care rulează» ar suna a «la zi» — dar n-am aflat dacă există o versiune
    nouă. Operatorul ar crede că patch-ul de securitate e aplicat."""
    got = lib_table([
        ("failed_same", "su_pull_result 1 sha256:a sha256:a"),
        ("failed_diff", "su_pull_result 1 sha256:a sha256:b"),
        ("ok_no_id", "su_pull_result 0 sha256:a ''"),
        ("same", "su_pull_result 0 sha256:a sha256:a"),
        ("new", "su_pull_result 0 sha256:a sha256:b"),
    ])
    assert got == {"failed_same": "pull-failed", "failed_diff": "pull-failed", "ok_no_id": "pull-failed",
                   "same": "up-to-date", "new": "recreate"}


def test_drift_verdict_and_build_decision_gate_unreviewed_code():
    """`docker compose build` livrează CE E PE DISC în clipa asta. oferte-app a fost construit
    azi la 14:34 și dms-app la 12:26: dacă cineva a modificat sursa de atunci, o reconstruire
    «cu bază proaspătă» livrează cod pe care nimeni nu l-a revizuit. Orice pozitiv e `drift`;
    «nu știu» e `unknown`, nu `clean`; fără --rebuild nu se construiește nimic; `all` nu
    acceptă drift."""
    got = lib_table([
        ("clean", "su_drift_verdict 0 0 no"),
        ("clean_norepo", "su_drift_verdict 0 norepo norepo"),
        ("newer_files", "su_drift_verdict 3 0 no"),
        ("dirty", "su_drift_verdict 0 2 no"),
        ("head_newer", "su_drift_verdict 0 0 yes"),
        ("unknown_find", "su_drift_verdict '?' 0 no"),
        ("unknown_git", "su_drift_verdict 0 '?' '?'"),
        ("drift_beats_unknown", "su_drift_verdict '?' 4 no"),
        ("not_requested", "su_build_decision clinica '' '' clean"),
        ("other_project", "su_build_decision clinica oferte '' clean"),
        ("build", "su_build_decision clinica clinica '' clean"),
        ("all", "su_build_decision clinica all '' clean"),
        ("drift_refused", "su_build_decision clinica clinica '' drift"),
        ("drift_accepted", "su_build_decision clinica clinica clinica drift"),
        ("unknown_refused", "su_build_decision clinica all '' unknown"),
        ("accept_all_is_not_a_blanket", "su_build_decision clinica all all drift"),
    ])
    assert got == {
        "clean": "clean", "clean_norepo": "clean", "newer_files": "drift", "dirty": "drift",
        "head_newer": "drift", "unknown_find": "unknown", "unknown_git": "unknown", "drift_beats_unknown": "drift",
        "not_requested": "skip-not-requested", "other_project": "skip-not-requested", "build": "build",
        "all": "build", "drift_refused": "skip-drift", "drift_accepted": "build-accepted-drift",
        "unknown_refused": "skip-unknown", "accept_all_is_not_a_blanket": "skip-drift",
    }


def test_http_and_probe_verdicts_compare_to_baseline_and_keep_unknown_apart():
    """Un vhost care dădea 502 la baseline (container jos dinainte) nu e «stricat de update»;
    unul care dădea 200 și acum nu răspunde, da. Un curl care nu s-a putut rula e `unknown`,
    nu 000 și nu «ok». Aceeași regulă pentru regulile auditd încărcate: mai puține decât la
    baseline = Sentinel a pierdut din ce vede."""
    got = lib_table([
        ("ok", "su_http_verdict 200 301"),
        ("worse_000", "su_http_verdict 200 000"),
        ("worse_502", "su_http_verdict 200 502"),
        ("same_bad", "su_http_verdict 502 502"),
        ("same_bad_000", "su_http_verdict 000 000"),
        ("fixed", "su_http_verdict 502 200"),
        ("no_answer", "su_http_verdict 200 ''"),
        ("no_base", "su_http_verdict '' 200"),
        ("p_fewer", "su_probe_verdict 31 20"),
        ("p_same", "su_probe_verdict 31 31"),
        ("p_more", "su_probe_verdict 31 40"),
        ("p_table_lost", "su_probe_verdict yes no"),
        ("p_table_ok", "su_probe_verdict yes yes"),
        ("p_unknown_now", "su_probe_verdict 31 unknown"),
        ("p_unknown_base", "su_probe_verdict unknown 31"),
        ("p_na", "su_probe_verdict na yes"),
    ])
    assert got == {"ok": "ok", "worse_000": "worse", "worse_502": "worse", "same_bad": "same-bad",
                   "same_bad_000": "same-bad", "fixed": "ok", "no_answer": "unknown", "no_base": "unknown",
                   "p_fewer": "worse", "p_same": "ok", "p_more": "ok", "p_table_lost": "worse",
                   "p_table_ok": "ok", "p_unknown_now": "unknown", "p_unknown_base": "unknown", "p_na": "na"}


def test_exit_code_contracts_never_turn_unknown_into_fine():
    """`needs-restarting` lipsă (127) sau `dnf check-update` cu depozit căzut (1) nu sunt «nu e
    nevoie de reboot» și «nu a rămas nimic»: sunt «nu știu»."""
    got = lib_table([
        ("rb0", "su_reboot_needed_from_rc 0"), ("rb1", "su_reboot_needed_from_rc 1"),
        ("rb127", "su_reboot_needed_from_rc 127"), ("rb_empty", "su_reboot_needed_from_rc ''"),
        ("cu0", "su_check_update_state 0"), ("cu100", "su_check_update_state 100"),
        ("cu1", "su_check_update_state 1"), ("cu127", "su_check_update_state 127"),
    ])
    assert got == {"rb0": "no", "rb1": "yes", "rb127": "unknown", "rb_empty": "unknown",
                   "cu0": "none", "cu100": "pending", "cu1": "error", "cu127": "error"}


def test_kernel_matches_default_compares_the_running_kernel_to_the_boot_default():
    """Verify care compară cu «nucleul cel mai nou instalat» ar declara bine o gazdă care
    n-a repornit niciodată. Ce contează: nucleul care RULEAZĂ e cel pe care îl va porni gazda."""
    run = "5.14.0-741.22.1.el9_9.x86_64"
    assert rc_of(f"su_kernel_matches_default {run} /boot/vmlinuz-{run}") == 0
    assert rc_of(f"su_kernel_matches_default 5.14.0-687.57.1.el9_8.x86_64 /boot/vmlinuz-{run}") == 1
    assert rc_of(f"su_kernel_matches_default '' /boot/vmlinuz-{run}") == 2
    assert rc_of(f"su_kernel_matches_default {run} ''") == 2


def test_vhost_names_keep_only_probeable_literals():
    """`server_name _`, regexurile și wildcard-urile nu se pot proba cu `--resolve`; trecute
    ca nume ar da 000 la baseline și «la fel» după, adică o sondă care nu verifică nimic."""
    conf = (
        "server {\n  server_name  a.example.ro www.a.example.ro;\n}\n"
        "server {\n  server_name _;\n}\n"
        'server {\n  server_name "~^[a-z0-9-]{1,40}\\.preview\\.example\\.eu$";\n}\n'
        "server {\n  server_name *.wild.example.eu b.example.eu;\n}\n"
        "# server_name commented.example.ro;\n"
    )
    got = lib_table([("n", f"printf '%s' '{conf}' | su_vhost_names | tr '\\n' ' '")])
    assert got["n"].split() == ["a.example.ro", "b.example.eu", "www.a.example.ro"]


def test_every_comm_call_in_the_update_scripts_forces_the_c_locale():
    """`sort` era cu LC_ALL=C, `comm` nu: pe gazdă (19 nov 2026) `comm` a răspuns «file 1 is not
    in sorted order» și a întors o intersecție trunchiată — lista serviciilor care trebuie să
    fie sus nu avea docker și mariadb, deci verify nu le-ar fi cerut după reboot. Verificat pe
    text (pe Windows locale-ul nu se poate provoca): fiecare apel `comm` poartă LC_ALL=C, iar
    numărul de apeluri e verificat ca o listă goală să nu treacă fără să fi privit nimic."""
    import re
    from _su_shell import LIB_DIR

    seen, bad = 0, []
    for path in sorted(LIB_DIR.glob("system-update-*.sh")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for m in re.finditer(r"(?<![\w-])comm\s+-\d+(?=\s)", line):
                seen += 1
                if "LC_ALL=C comm" not in line[max(0, m.start() - 12): m.end()]:
                    bad.append(f"{path.name}:{n}")
    assert seen >= 4, f"am găsit doar {seen} apeluri comm — scanarea nu mai vede nimic"
    assert not bad, bad


def unguarded_head(line: str) -> bool:
    """Linia are `| head` fără `|| true` care să-i aparțină. `|| true` trebuie să vină DUPĂ `head`, pe aceeași
    conductă/grup: dacă între ele se închide o substituție (`)`), garda aparține altei comenzi."""
    idx = line.find("| head")
    if idx < 0:
        return False
    tail = line[idx:]
    guard = tail.find("|| true")
    if guard < 0:
        return True
    return ")" in tail[:guard]


def test_the_head_guard_checker_looks_at_the_pipeline_not_the_whole_line():
    """O verificare pe «linia conține `|| true`» lăsa să treacă `a=$(x | head -n 1); b=$(y || true)`: garda
    e a altei comenzi, iar `| head` rămânea neprotejat. Verificatorul cere garda DUPĂ head, înainte de orice
    închidere de substituție."""
    assert not unguarded_head('x="$(grep -F a f | head -n 1 || true)"')
    assert not unguarded_head('h="$({ gzip -dc "$f" | head -n 30; } || true)"')
    assert not unguarded_head("r=\"$(a | awk 'NF' | head -n 12 | tr ' ' ' ' || true)\"")
    assert unguarded_head('x="$(grep -F a f | head -n 1)"')
    assert unguarded_head('a="$(x | head -n 1)"; b="$(y || true)"')
    assert unguarded_head('printf "%s" "$out" | awk NF | head -n 15')
    assert not unguarded_head("printf x | wc -l")


def test_no_unguarded_head_after_a_pipe_in_the_update_scripts():
    """Sub `set -o pipefail`, `producător | head -n N` iese cu 141 (SIGPIPE) când producătorul mai scrie după ce
    `head` a plecat — măsurat pe gazdă la `dnf … | head -n 15` (5 rulări din 6), exact când dnf căzuse întreg
    și raportul «ce a rămas» era ce conta. Rezultatul se pierdea fără mesaj. Verificat pe text (SIGPIPE nu se
    poate provoca determinist pe Windows): orice `| head` din cod are garda lui `|| true`, ori conducta se
    rescrie cu `awk … exit` / expansiune de parametri."""
    from _su_shell import LIB_DIR

    seen, bad = 0, []
    for path in sorted(LIB_DIR.glob("system-update-*.sh")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#") or "| head" not in line:
                continue
            seen += 1
            if unguarded_head(line):
                bad.append(f"{path.name}:{n}: {line.strip()[:90]}")
    assert seen >= 3, f"am găsit doar {seen} apeluri `| head` — scanarea nu mai vede nimic"
    assert not bad, bad


def test_image_ownership_tells_a_stale_baseline_from_an_image_this_maintenance_landed(tmp_path):
    """oferte api/worker și dms app au fost redeployate după baseline: rulează o imagine pe care baseline-ul n-o știe. Dacă
    orice imagine diferită de baseline ar fi «a noastră», o etichetă de rollback pe imaginea din baseline ar anula acel deploy
    fără ca nimeni să afle; dacă doar imaginea din baseline ar fi «a noastră», fiecare rulare repetată (după un eșec) ar fi
    refuzată. A noastră = baseline, sau o imagine VĂZUTĂ RULÂND după un `up` al nostru (`landed` în containers.owned, pentru ACEL
    serviciu, ID complet). Nici o linie `pulled`/`built`/`recreated` din jurnal, nici `prev`, nici un prefix de 12 caractere
    potrivit din întâmplare nu fac o imagine străină «a noastră»."""
    from _su_shell import lib_table, posix

    owned = tmp_path / "o.txt"
    d4 = "sha256:" + "d4" * 32
    owned.write_text("\n".join([f"p|s|landed|{d4}", f"p|s|prev|sha256:{'a1' * 32}", f"p|other|landed|sha256:{'e5' * 32}",
                               f"q|s|landed|sha256:{'f6' * 32}"]) + "\n", encoding="utf-8", newline="\n")
    report = tmp_path / "r.txt"      # un jurnal cu exact liniile care înainte «dovedeau» proprietatea
    report.write_text("\n".join(["p|s|pulled|pg:16 b2b2b2b2b2b2", "p|s|built|x c3c3c3c3c3c3", "p|s|recreated|a1a1a1a1a1a1 -> 666666666666"]) + "\n",
                      encoding="utf-8", newline="\n")
    base = "sha256:" + "a1" * 32
    prefix_twin = d4[:19] + "ff" * 26                # aceleași 12 caractere ca landed, alt ID
    cases = [(name, f"su_image_is_ours {run} {base} '{posix(owned)}' p s && echo y || echo n")
             for name, run in (("base", base), ("landed", d4), ("pulled-only", "sha256:" + "b2" * 32), ("built-only", "sha256:" + "c3" * 32),
                               ("recreated-target-in-report-only", "sha256:" + "66" * 32), ("other-service", "sha256:" + "e5" * 32),
                               ("other-project", "sha256:" + "f6" * 32), ("foreign", "sha256:" + "99" * 32), ("prefix-twin", prefix_twin))]
    cases.append(("report-is-not-ownership", f"su_image_is_ours sha256:{'66' * 32} {base} '{posix(report)}' p s && echo y || echo n"))
    cases.append(("no-owned-file", f"su_image_is_ours sha256:{'99' * 32} {base} '{posix(tmp_path / 'lipsa')}' p s && echo y || echo n"))
    cases.append(("empty-run", f"su_image_is_ours '' {base} '{posix(owned)}' p s && echo y || echo n"))
    got = lib_table(cases)
    assert got == {"base": "y", "landed": "y", "pulled-only": "n", "built-only": "n", "recreated-target-in-report-only": "n", "other-service": "n",
                   "other-project": "n", "foreign": "n", "prefix-twin": "n", "report-is-not-ownership": "n", "no-owned-file": "n", "empty-run": "n"}, got


def test_sticky_hints_name_the_exits_that_exist(tmp_path):
    """Un mesaj care trimite operatorul la o comandă care nu rezolvă nimic îl face să repete la nesfârșit (retry fără
    --rebuild, tag-failed care cere o recreare ce nu mai vine, pull-failed oprit de hold-config-drift). Textele numesc
    ieșirea reală: --retry-failed fără --rebuild, rularea din nou cu --only, --accept-drift, baseline nou."""
    from _su_shell import lib_table

    got = lib_table([(st, f"su_sticky_hint {st} pg") for st in ("failed", "pull-failed", "tag-failed", "stale-baseline")])
    assert "--retry-failed pg" in got["failed"] and "fără --rebuild" in got["failed"]
    assert "--accept-drift pg" in got["pull-failed"]
    assert "--only pg" in got["tag-failed"]
    assert "--phase preflight --new-baseline" in got["stale-baseline"] and "--phase containers" in got["stale-baseline"]


def test_report_final_all_lists_every_unresolved_state_of_a_service_not_only_the_first(tmp_path):
    """`stale-baseline` se afișează primul, deci ascunde un `tag-failed` încă nerezolvat al aceluiași serviciu. Un baseline nou preia
    eșecurile nerezolvate; dacă ar citi doar rezultatul afișat, ar pierde în tăcere tocmai eșecul de sub `stale-baseline`. Cu `all` se
    văd toate (în ordinea de prioritate); fără `all` rămâne o singură linie pe serviciu, ca până acum."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    rep.write_text("p|s|tag-failed|g" + chr(10) + "p|s|stale-baseline|st" + chr(10) + "p|s|pull-failed|pf" + chr(10) + "p|ok|failed|x" + chr(10) + "p|ok|retried|r" + chr(10) + "p|ok|verified|v" + chr(10),
                   encoding="utf-8", newline=chr(10))
    one = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}'")
    every = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' all")
    assert one.stdout.splitlines() == ["p/s|stale-baseline|st", "p/ok|verified|v"], one.stdout
    assert every.stdout.splitlines() == ["p/s|stale-baseline|st", "p/s|pull-failed|pf", "p/s|tag-failed|g", "p/ok|verified|v"], every.stdout


# ---------------------------------------------------------------------------
# Runda 8
# ---------------------------------------------------------------------------
def test_su_container_verdict_is_the_only_health_judge(tmp_path):
    """Runda 8 avea DOUĂ clasamente de sănătate care nu se puneau de acord: `su_stricter_health` punea `starting` sub `unhealthy`, iar
    `su_container_verdict` îl tratează pe `starting` ca mai exigent decât `unhealthy` — cu sănătatea preluată `starting`, `--retry-failed` rezolva un
    eșec peste un container încă `unhealthy`. Acum judecata e UNA: nicio funcție din scripturi în afară de `su_health_class` nu are «health» în nume
    (un clasament nou ar apărea aici), `su_stricter_health` și ordinea lui nu mai există, iar `check_container` judecă episodul tot cu
    `su_container_verdict` (a doua apelare, peste sănătatea din episod)."""
    import re

    lib = Path(__file__).resolve().parents[2] / "scripts" / "lib"
    names, text = set(), {}
    for f in ("system-update-lib.sh", "system-update-host.sh", "system-update-containers.sh", "system-update-verify.sh"):
        text[f] = (lib / f).read_text(encoding="utf-8")
        names |= set(re.findall(r"^(\w*health\w*)\(\)", text[f], re.M))
    assert names == {"su_health_class"}, names
    assert not [f for f, t in text.items() if "stricter" in t or "_su_hrank" in t], "un al doilea clasament de sănătate a reapărut"
    body = text["system-update-containers.sh"].split("check_container() {", 1)[1].split(chr(10) + "}" + chr(10), 1)[0]
    assert body.count("su_container_verdict") >= 2, "check_container nu mai judecă episodul cu aceeași funcție"
    assert "ev=\"$(su_container_verdict running \"$eh\"" in body


def test_an_episode_is_read_from_the_live_journal_line_and_never_from_a_resolved_one(tmp_path):
    """Runda 8 prefera o linie `carried` veche, a unui episod deja REZOLVAT, în fața sănătății față de care eșecul de acum a fost judecat cu adevărat.
    Acum episodul e ID-ul din chiar linia vie a jurnalului (`[episod=ID] `): un episod rezolvat (failed -> retried -> verified) nu mai are nicio linie
    vie, deci înregistrările lui nu se mai preiau, iar un eșec NOU al aceluiași serviciu (fără prefix) are alt episod."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    lines = ["p|live|failed|[episod=B] preluat din baseline-ul B: x",
             "p|resolved|failed|[episod=B] preluat din baseline-ul B: x", "p|resolved|retried|r", "p|resolved|verified|v",
             "p|refailed|failed|[episod=B] preluat din baseline-ul B: x", "p|refailed|retried|r", "p|refailed|verified|v", "p|refailed|failed|nou",
             "p|two|failed|[episod=B] x", "p|two|pull-failed|[episod=C] y", "p|plain|failed|x"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    cmds = [(k, f"su_state_episodes '{posix(rep)}' p {k} | tr '\n' ' '") for k in ("live", "resolved", "refailed", "two", "plain")]
    cmds += [("of", "su_episode_of '[episod=B2.x] preluat'"), ("of-none", "su_episode_of 'preluat din baseline-ul B'"),
             ("strip", "su_episode_strip '[episod=B2] preluat din B: det | cu bară'"), ("strip-none", "su_episode_strip 'fără prefix'")]
    from _su_shell import lib_table

    got = {k: v.strip() for k, v in lib_table(cmds).items()}
    assert got["live"] == "failed|B" and got["resolved"] == "" and got["refailed"] == "" and got["plain"] == "", got
    assert sorted(got["two"].split()) == ["failed|B", "pull-failed|C"], got
    assert got["of"] == "B2.x" and got["of-none"] == "" and got["strip"] == "preluat din B: det | cu bară" and got["strip-none"] == "fără prefix", got


def test_an_acknowledge_clears_the_sticky_states_but_not_stale_baseline_and_is_not_an_automatic_success(tmp_path):
    """`acked` (scris doar de `--acknowledge`) șterge stările lipicioase ale serviciului (`failed` + `pull-failed` + `tag-failed` deodată, fără o reușită
    specifică) — dar NU `stale-baseline` (vezi testul de mai jos) — și nu rezolvă ce vine DUPĂ el: un eșec nou după `acked` e o stare nouă, afișată
    deasupra recunoașterii. Operatorul nu rămâne cu un «dovedit» fals: recunoașterea rămâne în modul `acked` cât eșecul nou e încă activ."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    lines = ["p|a|failed|x", "p|a|pull-failed|y", "p|a|tag-failed|z", "p|a|acked|op",
             "p|b|failed|x", "p|b|acked|op", "p|b|pull-failed|again",
             "p|c|failed|x", "p|c|skip-not-running|gone"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    out = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' all").stdout.splitlines()
    assert out == ["p/a|acked|op", "p/b|pull-failed|again", "p/c|failed|x"], out
    acked = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' acked").stdout.splitlines()
    assert acked == ["p/a|acked|op", "p/b|acked|op"], acked


def test_acked_is_a_durable_flag_that_no_other_event_clears_only_ack_cleared_does(tmp_path):
    """Runda 9 (N10, N15): `acked` era ultimul rezultat al serviciului, deci îl înlocuia orice eveniment de după el — un `unread` trecător urmat de
    `read-ok` (compose care nu se citește o singură dată) sau o recreare `recreated`/`verified` — și rularea următoare ieșea «TOTUL DOVEDIT» peste un
    serviciu pe care operatorul îl recunoscuse ca nerezolvat. Acum steagul e SEPARAT de ultimul rezultat: nicio altă linie nu-l coboară (nici skip/hold/
    up-to-date, nici unread/read-ok, nici verified/recreated, nici un eșec nou), iar `ack-cleared` — scris doar după un verdict ok — îl coboară și lasă
    rezultatul final să fie ce a venit de fapt."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    lines = ["p|a|failed|x", "p|a|acked|op", "p|a|skip-not-requested|r",
             "p|b|failed|x", "p|b|acked|op", "p|b|skip-not-running|gone",
             "p|c|failed|x", "p|c|acked|op", "p|c|hold-moved-tag|t", "p|c|up-to-date|u",
             "p|d|failed|x", "p|d|acked|op", "p|d|verified|ok", "p|d|recreated|1 -> 2",
             "p|e|failed|x", "p|e|acked|op", "p|e|pull-failed|nou", "p|e|skip-drift|d",
             "p|f|failed|x", "p|f|stale-baseline|s", "p|f|acked|op", "p|f|hold-failed|h",
             "p|g|stale-baseline|s", "p|g|acked|op",
             "p|h|failed|x", "p|h|acked|op", "p|h|unread|u", "p|h|read-ok|r",                 # N15: compose ilizibil o dată, apoi citit
             "p|i|failed|x", "p|i|acked|op", "p|i|ack-cleared|ok", "p|i|verified|ok",          # coborât de un verdict ok
             "p|j|failed|x", "p|j|acked|op", "p|j|ack-cleared|ok", "p|j|failed|iar"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    one = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}'").stdout.splitlines()
    assert one == ["p/a|acked|op", "p/b|acked|op", "p/c|acked|op", "p/d|acked|op", "p/e|pull-failed|nou", "p/f|stale-baseline|s", "p/g|stale-baseline|s",
                   "p/h|acked|op", "p/i|verified|ok", "p/j|failed|iar"], one
    acked = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' acked").stdout.splitlines()
    assert acked == ["p/a|acked|op", "p/b|acked|op", "p/c|acked|op", "p/d|acked|op", "p/e|acked|op", "p/f|acked|op", "p/g|acked|op", "p/h|acked|op"], acked
    every = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' all").stdout.splitlines()
    assert "p/f|failed|x" not in every and "p/f|stale-baseline|s" in every, every     # `failed` s-a șters, stale-baseline a rămas


def test_an_acknowledgement_is_recorded_per_episode_and_a_cleared_one_has_no_live_episode(tmp_path):
    """O recunoaștere se leagă de episodul eșecului (`[episod=ID] `): un baseline nou preia episoadele VII (carry_forward_sticky), iar judecata de la
    rularea următoare se face față de sănătatea din ele. `ackeps` le listează; o linie fără prefix e `-` (nu se poate judeca, deci nu se șterge singură);
    un steag coborât nu are niciun episod viu, ca să nu se preia într-un baseline nou. O1 (runda 11): steagul coborât (`ack-cleared`) trebuie să ia cu el și LISTA
    de episoade: altfel o recunoaștere nouă (episodul C) ar moșteni episodul B, deja șters, iar carry-ul l-ar preda mai departe ca «recunoscut» — un eșec din B pe
    care operatorul nu l-a mai recunoscut niciodată ar rămâne acoperit."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    lines = ["p|a|failed|[episod=B] x", "p|a|acked|[episod=B] op", "p|a|pull-failed|[episod=C] y", "p|a|acked|[episod=C] op2",
             "p|b|failed|x", "p|b|acked|op",
             "p|c|failed|x", "p|c|acked|[episod=B] op", "p|c|ack-cleared|ok",
             "p|d|failed|[episod=B] x", "p|d|acked|[episod=B] op", "p|d|ack-cleared|ok", "p|d|failed|[episod=C] y", "p|d|acked|[episod=C] op2"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    eps = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' ackeps").stdout.splitlines()
    assert eps == ["p/a|B", "p/a|C", "p/b|-", "p/d|C"], eps          # `d`: B recunoscut, coborât, apoi C recunoscut: doar C e viu
    only = run_bash(f"source '{posix(LIB_SH)}'; su_ack_episodes '{posix(rep)}' p a | tr '\n' ' '").stdout
    assert only.strip() == "B C", only


def test_the_two_episode_judges_differ_on_same_bad_and_never_accept_worse(tmp_path):
    """Mutația X4: un eșec preluat se rezolvă la `ok` ȘI `same-bad` (un serviciu unhealthy ÎNAINTE de orice mentenanță, a pierdut un pull o dată, e înapoi
    în starea de dinainte — judecata `ok`-only îl bloca pe `--acknowledge`), dar niciodată la `worse`/`pending`/`unknown`/`skip`. O recunoaștere a operatorului
    se șterge după ACEEAȘI regulă (runda 11): ok sau same-bad față de ambele judecăți, niciodată worse/pending/unknown/skip — altfel un serviciu recunoscut care era
    deja unhealthy înainte de orice mentenanță ar rămâne pe veci «NERESOLVAT», pe când varianta nerecunoscută iese «TOTUL DOVEDIT» (N1)."""
    from _su_shell import lib_table

    got = lib_table([(v, f"su_episode_resolves {v} && echo yes || echo no") for v in ("ok", "same-bad", "worse", "pending", "unknown", "skip", "")]
                    + [(f"{a}/{b}", f"su_ack_clears {a} {b} && echo yes || echo no") for a, b in (("ok", "ok"), ("same-bad", "ok"), ("ok", "same-bad"), ("worse", "ok"), ("ok", "unknown"))])
    got = {k: v.strip() for k, v in got.items()}
    assert [got[v] for v in ("ok", "same-bad")] == ["yes", "yes"], got
    assert [got[v] for v in ("worse", "pending", "unknown", "skip", "")] == ["no"] * 5, got
    assert [got[k] for k in ("ok/ok", "same-bad/ok", "ok/same-bad")] == ["yes"] * 3, got
    assert [got[k] for k in ("worse/ok", "ok/unknown")] == ["no"] * 2, got


def test_acked_is_final_against_skip_and_hold_events_and_is_never_cleared_over_a_stale_baseline(tmp_path):
    """Runda 8: un `acked` era înlocuit în aceeași rulare de `skip-not-requested`, `skip-not-running` sau `hold-*` (proiectul se procesa în continuare),
    iar verify nu mai arăta nimic și faza ieșea verde. Rămâne rezultatul final în fața oricărui skip*/hold*/up-to-date (și, din runda 10, a oricărei
    reușite: vezi testul steagului durabil). Nu șterge `stale-baseline` (nici singur, nici alături de altă stare). Modul `acked` îl listează chiar și când
    `stale-baseline` e rezultatul afișat."""
    from _su_shell import LIB_SH, posix, run_bash

    rep = tmp_path / "r.txt"
    lines = ["p|f|failed|x", "p|f|stale-baseline|s", "p|f|acked|op", "p|f|hold-failed|h",
             "p|g|stale-baseline|s", "p|g|acked|op",
             "p|h|failed|x", "p|h|acked|op", "p|h|skip-not-requested|r", "p|h|hold-moved-tag|t", "p|h|up-to-date|u"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    one = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}'").stdout.splitlines()
    assert one == ["p/f|stale-baseline|s", "p/g|stale-baseline|s", "p/h|acked|op"], one
    acked = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' acked").stdout.splitlines()
    assert acked == ["p/f|acked|op", "p/g|acked|op", "p/h|acked|op"], acked
    every = run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' all").stdout.splitlines()
    assert "p/f|failed|x" not in every and "p/f|stale-baseline|s" in every, every     # `failed` s-a șters, stale-baseline a rămas


def test_every_sticky_hint_but_stale_baseline_names_the_acknowledge_exit_with_the_real_key(tmp_path):
    """Un eșec preluat într-un baseline nou poate să nu mai aibă un container de re-verificat (serviciul a căzut sau a fost scos): fiecare mesaj
    lipicios, în afară de `stale-baseline` (care se rezolvă prin baseline nou), numește ieșirea `--acknowledge PROIECT/SERVICIU` cu cheia REALĂ,
    nu un substituent; `pull-failed` numește și comanda rulării (`--only`), nu doar «rulează din nou»."""
    from _su_shell import lib_table

    states = ("failed", "build-failed", "pull-failed", "tag-failed", "unread", "stale-baseline")
    got = lib_table([(st, f"su_sticky_hint {st} pg db") for st in states])
    for st in states[:-1]:
        assert "--acknowledge pg/db" in got[st], (st, got[st])
    assert "--acknowledge" not in got["stale-baseline"]
    assert "--phase containers --only pg" in got["pull-failed"]


def _final(rep, mode=""):
    from _su_shell import LIB_SH, posix, run_bash

    return run_bash(f"source '{posix(LIB_SH)}'; su_report_final '{posix(rep)}' {mode}").stdout.splitlines()


@pytest.mark.parametrize("order", ["state-then-ack", "ack-then-state"])
@pytest.mark.parametrize("state", ["pull-failed", "build-failed", "tag-failed", "failed", "unread"])
def test_an_acknowledgement_covers_only_the_episode_it_names_in_any_line_order(tmp_path, state, order):
    """Runda 10 (A7): o recunoaștere dată pentru episodul B acoperea ȘI un eșec NOU al aceluiași serviciu (episodul B2), dacă linia lui sta înaintea `acked` în jurnal
    — exact ordinea în care o scria carry_forward_sticky (stările întâi, recunoașterile după). Operatorul recunoscuse un eșec vechi; unul nou, nerecunoscut, ieșea
    «DOVEDIT, cu 1 recunoscut» și verify/status verzi. Acum `acked` acoperă doar episodul numit: eșecul din B2 rămâne roșu în ORICE ordine."""
    rep = tmp_path / "B3" / "r.txt"
    rep.parent.mkdir()
    pair = [f"p|a|{state}|[episod=B2] nou, nerecunoscut", "p|a|acked|[episod=B] preluat: recunoscut"]
    lines = pair if order == "state-then-ack" else pair[::-1]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    assert _final(rep) == [f"p/a|{state}|[episod=B2] nou, nerecunoscut"], _final(rep)
    assert _final(rep, "ackeps") == ["p/a|B"], "recunoașterea vie rămâne (încă acoperă episodul B)"


def test_an_acknowledgement_clears_a_state_of_its_own_episode_but_not_one_written_after_it(tmp_path):
    """În ACELAȘI episod ordinea contează: `failed` apoi `acked` (episodul B) -> recunoscut; `acked` apoi un `failed` nou al aceluiași episod (serviciul s-a înrăutățit
    peste ce s-a recunoscut) -> roșu. O linie fără prefix e episodul baseline-ului fișierului (aici directorul `B`), deci recunoașterea `[episod=B]` o acoperă."""
    rep = tmp_path / "B" / "r.txt"
    rep.parent.mkdir()
    lines = ["p|a|failed|x", "p|a|acked|[episod=B] op",
             "p|b|acked|[episod=B] op", "p|b|failed|iar, după recunoaștere",
             "p|c|failed|x", "p|c|acked|[episod=B2] op al altui episod"]
    rep.write_text(chr(10).join(lines) + chr(10), encoding="utf-8", newline=chr(10))
    assert _final(rep) == ["p/a|acked|op", "p/b|failed|iar, după recunoaștere", "p/c|failed|x"], _final(rep)


def test_an_episode_closed_line_is_only_a_journal_entry_and_never_a_result(tmp_path):
    """`episode-closed` (scris de carry_forward_sticky pentru un serviciu dispărut) nu are voie să devină rezultatul final al serviciului (ar arăta în verify ca un skip
    necunoscut) și nu atinge nicio stare: e doar urma deciziei de a închide episodul."""
    rep = tmp_path / "B2" / "r.txt"
    rep.parent.mkdir()
    rep.write_text("p|a|episode-closed|[episod=B] a dispărut\np|b|failed|x\np|b|episode-closed|[episod=B] a dispărut\n", encoding="utf-8", newline=chr(10))
    assert _final(rep) == ["p/b|failed|x"], _final(rep)


def test_image_ids_compare_full_or_by_a_prefix_of_at_least_twelve_hex_digits(tmp_path):
    """R3 (runda 10): un `landed` trunchiat în episod nu potrivea ID-ul întreg citit din container, deci imaginea picată părea «schimbată de altcineva» și primea
    eticheta de rollback. Egal sau prefix de cel puțin 12 cifre hex potrivește; sub 12, ne-hex ori gol nu potrivește nimic."""
    from _su_shell import lib_table

    full = "sha256:" + "ab" * 32
    cases = {
        "same": (full, full), "trunc23": (full[:30], full), "trunc-bare": ("ab" * 6, full), "reverse": (full, full[:30]),
        "short11": ("ab" * 5 + "a", full), "other": ("sha256:" + "cd" * 32, full), "empty": ("", full), "nonhex": ("sha256:zz" * 4, full),
        "both-empty": ("", ""),
    }
    got = lib_table([(k, f"su_image_id_same '{a}' '{b}' && echo yes || echo no") for k, (a, b) in cases.items()])
    got = {k: v.strip() for k, v in got.items()}
    assert [got[k] for k in ("same", "trunc23", "trunc-bare", "reverse")] == ["yes"] * 4, got
    assert [got[k] for k in ("short11", "other", "empty", "nonhex", "both-empty")] == ["no"] * 5, got


# ---------------------------------------------------------------------------------------------------------------------------------------------
# Runda 12 (B1): textele pentru operator nu EXECUTĂ nimic. O comandă între ghilimele-oblice (backtick) într-un `echo "..."` rulează ca substituție.
# ---------------------------------------------------------------------------------------------------------------------------------------------

DECOY_WORDS = ("ok", "same-bad", "worse", "acked", "all", "failed", "running", "stale-baseline")


def _hints_run(tmp_path):
    """Randează fiecare indiciu lipicios și `su_ack_hint` într-un bash cu momeli pe PATH sub numele cuvintelor-regulă (`ok`, `worse`...), fiecare notându-și rularea."""
    from _su_shell import LIB_SH, env_for, make_bin, posix, run_bash

    marks = tmp_path / "marks"
    marks.mkdir()
    bindir = make_bin(tmp_path, {w: f'touch "$DECOY_MARK/{w}"\n' for w in DECOY_WORDS})
    env = env_for(tmp_path, bindir, DECOY_MARK=posix(marks))
    states = ("failed", "build-failed", "pull-failed", "tag-failed", "unread", "stale-baseline", "bogus")
    script = f"source '{posix(LIB_SH)}'\n" + "".join(
        f"printf 'H %s=%s\\n' '{st}' \"$(su_sticky_hint {st} pg db)\"\n" for st in states) + "printf 'H ack=%s\\n' \"$(su_ack_hint pg db)\"\n"
    proc = run_bash(script, env)
    got = {}
    for line in proc.stdout.splitlines():
        if line.startswith("H "):
            k, _, v = line[2:].partition("=")
            got[k] = v
    return proc, got, sorted(x.name for x in marks.iterdir())


def test_the_sticky_hints_print_their_rule_words_literally_and_never_run_a_command_named_like_one(tmp_path):
    """B1 (runda 11): indiciul lui `failed` avea `ok`, `same-bad` și `worse` între ghilimele-oblice într-un `echo "..."`: bash le EXECUTA ca substituții. Operatorul citea
    «verdictul e , nu doar ...; nu rezolvă» — fără cuvintele care spun CE rezolvă un eșec preluat — iar un executabil `ok` sau `worse` din PATH rula, ca root, la fiecare
    indiciu tipărit. Momelile din PATH nu au voie să ruleze (niciun marcaj), stderr rămâne gol (un «command not found» ar fi dovada unei substituții), iar cuvintele
    stau acolo, literal. Un indiciu fără regula lui («ok» sau «same-bad» rezolvă, «worse» nu) trimite operatorul să repete o comandă care nu poate reuși."""
    proc, got, marks = _hints_run(tmp_path)
    assert proc.returncode == 0 and set(got) == {"failed", "build-failed", "pull-failed", "tag-failed", "unread", "stale-baseline", "bogus", "ack"}, (proc.stdout, proc.stderr)
    assert marks == [], f"un indiciu a RULAT comenzi: {marks}"
    assert proc.stderr == "", proc.stderr
    assert "«ok» sau «same-bad»" in got["failed"] and "«worse» nu rezolvă" in got["failed"] and "same-bad (era la fel de rău" not in got["failed"], got["failed"]
    assert "(era la fel de rău înainte de orice mentenanță" in got["failed"], got["failed"]
    assert "«acked»" in got["ack"] and "--acknowledge pg/db" in got["ack"], got["ack"]
    assert "`" not in "".join(got.values()), got


def _backtick_scanner_cases():
    return [
        ('echo "a `b` c"\n', True), ("echo 'a `b` c'\n", False), ('# "a `b`\necho x\n', False), ("cat <<'EOF'\n`x` \"\nEOF\n", False),
        ('cat <<EOF\n`x`\nEOF\n', True), ('x="$(printf \'`z`\')"\n', False), ('x="$(echo "`z`")"\n', True), ('echo "multi\nline `bad`"\n', True),
        ('echo "esc \\`ok\\`"\n', False), ("a=1 # it's `fine`\n", False), ('echo "${#arr[@]} `bad`"\n', True),
    ]


def backticks_inside_double_quotes(src: str) -> list[int]:
    """Liniile (1-based) cu un backtick ÎNTRE ghilimele duble (inclusiv întinse pe mai multe linii, ori într-un heredoc nepus între ghilimele simple). Un scanner de
    ghilimele, nu un grep: backtick-ul dintr-un comentariu, dintr-un șir cu ghilimele simple, dintr-un heredoc `<<'EOF'` sau dintr-un awk între ghilimele simple e text, nu comandă."""
    import re

    lines = src.split("\n")
    hits: set[int] = set()
    k = 0
    while k < len(lines):
        m = re.search(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_]\w*)\1", lines[k])
        if m and not lines[k].lstrip().startswith("#"):
            quoted, delim = bool(m.group(1)), m.group(2)
            j = k + 1
            while j < len(lines) and lines[j].strip() != delim:
                if not quoted and "`" in lines[j]:
                    hits.add(j + 1)
                lines[j] = ""
                j += 1
            assert j < len(lines), f"heredoc {delim!r} de la linia {k + 1} n-are terminator: scanerul s-a desincronizat"
            k = j
        k += 1
    s = "\n".join(lines)
    stack: list[list] = []                       # ["dq"] sau ["cmd", adâncimea parantezelor]
    i, n, line = 0, len(s), 1
    while i < n:
        c = s[i]
        top = stack[-1][0] if stack else "none"
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "\\":
            line += 1 if s[i + 1:i + 2] == "\n" else 0
            i += 2
            continue
        if top == "dq":
            if c == '"':
                stack.pop()
            elif c == "`":
                hits.add(line)
            elif c == "$" and s[i + 1:i + 2] == "(":
                stack.append(["cmd", 1])
                i += 1
            i += 1
            continue
        if c == "'":
            j = s.index("'", i + 1)
            line += s.count("\n", i, j)
            i = j + 1
            continue
        if c == "$" and s[i + 1:i + 2] == "'":
            j = i + 2
            while s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            line += s.count("\n", i, j)
            i = j + 1
            continue
        if c == '"':
            stack.append(["dq"])
        elif c == "`":
            j = s.index("`", i + 1)
            line += s.count("\n", i, j)
            i = j
        elif c == "#" and (i == 0 or s[i - 1] in " \t\n;|&("):
            while i < n and s[i] != "\n":
                i += 1
            continue
        elif c == "$" and s[i + 1:i + 2] == "(":
            stack.append(["cmd", 1])
            i += 1
        elif top == "cmd" and c == "(":
            stack[-1][1] += 1
        elif top == "cmd" and c == ")":
            stack[-1][1] -= 1
            if stack[-1][1] == 0:
                stack.pop()
        i += 1
    assert not stack, f"scanerul s-a desincronizat: contexte deschise la sfârșit ({stack})"
    return sorted(hits)


def test_the_backtick_scanner_tells_text_from_a_command_so_an_empty_audit_means_something():
    """Controlul pozitiv al auditului de mai jos: un audit care întoarce «nicio problemă» trebuie să fi fost în stare să găsească una. Fiecare caz e o formă reală din
    scripturi (comentariu, șir cu ghilimele simple, heredoc citat, awk) ori defectul însuși (backtick între ghilimele duble, pe una sau mai multe linii)."""
    for src, bad in _backtick_scanner_cases():
        assert bool(backticks_inside_double_quotes(src)) is bad, (src, backticks_inside_double_quotes(src))


def test_no_operator_text_in_the_update_scripts_has_a_backtick_inside_double_quotes():
    """B1, auditul (runda 12): fiecare `echo`/`printf`/`say_*` din cele șase scripturi care ar pune un cuvânt între ghilimele-oblice într-un șir cu ghilimele duble ar
    EXECUTA cuvântul (și ar tăia din mesaj exact regula pe care operatorul o citește). Aici un backtick între ghilimele duble e o greșeală, oriunde: comentariile,
    șirurile cu ghilimele simple, heredoc-urile citate și programele awk le pot purta liber. Numărul de scripturi e verificat, ca o listă goală să nu treacă fără să fi privit nimic."""
    from _su_shell import LAUNCHER, LIB_DIR

    files = [LAUNCHER, *sorted(LIB_DIR.glob("system-update-*.sh"))]
    assert len(files) == 6, [f.name for f in files]
    bad = {f.name: backticks_inside_double_quotes(f.read_bytes().decode("utf-8")) for f in files}
    assert not any(bad.values()), bad
