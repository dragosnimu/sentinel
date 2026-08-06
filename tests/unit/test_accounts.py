"""Auditul conturilor: /etc/passwd ca stare, nu ca eveniment.

Regulile bazate pe evenimente pot fi ocolite — un atacator care a ajuns root
oprește auditd, își adaugă contul, îl repornește. Verificarea de aici se uită la
ce E în fișier, nu la ce s-a raportat, deci supraviețuiește manevrei ăsteia.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from sentinel.detect import accounts as ac

NORMAL = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nginx:x:990:990:Nginx web server:/var/lib/nginx:/sbin/nologin
dragos:x:1000:1000::/home/dragos:/bin/bash
"""

WITH_SECOND_ROOT = NORMAL + "backdoor:x:0:0::/root:/bin/bash\n"
WITH_NEW_LOGIN = NORMAL + "support:x:1001:1001::/home/support:/bin/bash\n"
WITH_NEW_SERVICE = NORMAL + "redis:x:991:991::/var/lib/redis:/sbin/nologin\n"
# Contul de serviciu care capătă shell interactiv: același nume, altă intenție.
NGINX_GETS_SHELL = NORMAL.replace("nginx:x:990:990:Nginx web server:/var/lib/nginx:/sbin/nologin",
                                  "nginx:x:990:990:Nginx web server:/var/lib/nginx:/bin/bash")


def run(c):
    return asyncio.run(c)


class _DB:
    """Ține cheile pe dimensiuni, ca stubul să nu amestece conturile cu starea
    fișierelor — prima variantă o făcea, și a produs un eșec care arăta ca un
    bug în cod și era în test."""

    def __init__(self, known: set[str] | None = None):
        self.by_dim: dict[str, set[str]] = {ac.DIM_ACCOUNT: set(), ac.DIM_FILE: set()}
        for k in (known or ()):
            dim = ac.DIM_FILE if k.startswith("/etc/") else ac.DIM_ACCOUNT
            self.by_dim[dim].add(k)
        self.written: dict[str, set[str]] = {ac.DIM_ACCOUNT: set(), ac.DIM_FILE: set()}

    async def fetch(self, sql, *a):
        return [{"key": k} for k in self.by_dim.get(a[0], set())]

    async def execute(self, sql, *a):
        self.written.setdefault(a[0], set()).add(a[1])


def _with_passwd(monkeypatch, text: str, *, shadow: str | None = "1000:900"):
    monkeypatch.setattr(ac, "_read_passwd",
                        lambda path=ac.PASSWD: ac._read_passwd.__wrapped__(text)
                        if hasattr(ac._read_passwd, "__wrapped__") else _parse(text))
    monkeypatch.setattr(ac, "_file_state", lambda p: shadow)


def _parse(text: str):
    out = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 7:
            out.append({"name": p[0], "uid": int(p[2]), "gid": p[3],
                        "home": p[5], "shell": p[6]})
    return out


def _sigs(text: str) -> set[str]:
    return {ac._signature(a) for a in _parse(text)}


# --- al doilea root: absolut, nu învățat ----------------------------------
def test_a_second_uid0_account_is_critical_even_on_the_first_run(monkeypatch):
    """Un Linux standard are exact un cont cu uid 0. Regula asta nu are nevoie
    de linie de bază fiindcă nu întreabă „am mai văzut asta?", ci „câți root
    sunt?" — iar răspunsul corect e mereu unu."""
    _with_passwd(monkeypatch, WITH_SECOND_ROOT)
    specs = run(ac.account_state_audit(_DB(), 0))
    uid0 = [s for s in specs if s.rule_id == "intrusion.uid0_account"]
    assert len(uid0) == 1
    assert uid0[0].severity == "critical"
    assert "backdoor" in uid0[0].title
    assert uid0[0].evidence["found_on_first_run"] is True


def test_a_single_root_produces_nothing(monkeypatch):
    _with_passwd(monkeypatch, NORMAL)
    specs = run(ac.account_state_audit(_DB(), 0))
    assert not [s for s in specs if s.rule_id == "intrusion.uid0_account"]


def test_the_first_run_warns_that_the_account_may_predate_sentinel(monkeypatch):
    """Dacă Sentinel se instalează pe un server deja compromis, contul e acolo
    dinainte. A spune „a apărut acum" ar fi o minciună utilă atacatorului."""
    _with_passwd(monkeypatch, WITH_SECOND_ROOT)
    s = run(ac.account_state_audit(_DB(), 0))[0]
    assert "anterior instalării" in s.summary


# --- conturi noi: nevoie de linie de bază ---------------------------------
def test_the_first_run_records_the_baseline_silently(monkeypatch):
    """Alternativa ar fi o alertă pentru fiecare cont de sistem al distribuției,
    în prima secundă de rulare."""
    _with_passwd(monkeypatch, NORMAL)
    db = _DB()
    specs = run(ac.account_state_audit(db, 0))
    assert not [s for s in specs if s.rule_id == "intrusion.new_account"]
    assert db.written[ac.DIM_ACCOUNT] == _sigs(NORMAL)


def test_a_new_account_with_a_login_shell_is_critical(monkeypatch):
    _with_passwd(monkeypatch, WITH_NEW_LOGIN)
    specs = run(ac.account_state_audit(_DB(_sigs(NORMAL)), 0))
    new = [s for s in specs if s.rule_id == "intrusion.new_account"]
    assert len(new) == 1
    assert new[0].severity == "critical"
    assert new[0].evidence["can_login"] is True
    assert "support" in new[0].title


def test_a_new_service_account_is_high_not_critical(monkeypatch):
    """Fără shell de login nu se poate autentifica direct. Rămâne o alertă —
    poate rula prin cron sau systemd — dar la o severitate care nu diluează
    alerta pentru un cont care chiar poate intra."""
    _with_passwd(monkeypatch, WITH_NEW_SERVICE)
    specs = run(ac.account_state_audit(_DB(_sigs(NORMAL)), 0))
    new = [s for s in specs if s.rule_id == "intrusion.new_account"]
    assert len(new) == 1
    assert new[0].severity == "high"
    assert new[0].evidence["can_login"] is False


def test_a_service_account_gaining_a_shell_is_detected(monkeypatch):
    """Semnătura include shell-ul dinadins. `nginx` care capătă `/bin/bash` e
    același nume și altă intenție — o comparație doar pe nume ar rata-o."""
    _with_passwd(monkeypatch, NGINX_GETS_SHELL)
    specs = run(ac.account_state_audit(_DB(_sigs(NORMAL)), 0))
    new = [s for s in specs if s.rule_id == "intrusion.new_account"]
    assert any(s.evidence["account"] == "nginx" and s.evidence["can_login"]
               for s in new)


def test_an_unchanged_passwd_is_silent(monkeypatch):
    _with_passwd(monkeypatch, NORMAL)
    specs = run(ac.account_state_audit(_DB(_sigs(NORMAL)), 0))
    assert [s for s in specs if s.rule_id == "intrusion.new_account"] == []


def test_an_unreadable_passwd_does_not_invent_an_alert(monkeypatch):
    """Tăcerea e mai bună decât o alertă falsă: dacă nu putem citi, nu știm."""
    monkeypatch.setattr(ac, "_read_passwd", lambda path=ac.PASSWD: [])
    assert run(ac.account_state_audit(_DB(), 0)) == []


# --- /etc/shadow: se vede că s-a schimbat, nu ce ---------------------------
def test_shadow_change_is_reported_without_claiming_to_know_what(monkeypatch):
    """E 0640 root:shadow și serviciul rulează ca sentinel. Alerta trebuie să
    spună limita, altfel operatorul crede că știm mai mult decât știm."""
    _with_passwd(monkeypatch, NORMAL, shadow="2000:950")
    db = _DB(_sigs(NORMAL) | {"/etc/shadow:1000:900"})
    specs = run(ac.account_state_audit(db, 0))
    sh = [s for s in specs if s.rule_id == "intrusion.shadow_changed"]
    assert len(sh) == 1
    assert sh[0].severity == "high"
    assert "nu ce anume" in sh[0].summary


def test_shadow_unchanged_is_silent(monkeypatch):
    _with_passwd(monkeypatch, NORMAL, shadow="1000:900")
    db = _DB(_sigs(NORMAL) | {"/etc/shadow:1000:900"})
    assert [s for s in run(ac.account_state_audit(db, 0))
            if s.rule_id == "intrusion.shadow_changed"] == []


def test_shadow_first_observation_is_silent(monkeypatch):
    """Prima citire nu are cu ce compara."""
    _with_passwd(monkeypatch, NORMAL, shadow="1000:900")
    assert [s for s in run(ac.account_state_audit(_DB(_sigs(NORMAL)), 0))
            if s.rule_id == "intrusion.shadow_changed"] == []


# --- parsarea -------------------------------------------------------------
def test_passwd_parsing_handles_real_shapes(tmp_path):
    f = tmp_path / "passwd"
    f.write_text("# comentariu\n"
                 "root:x:0:0:root:/root:/bin/bash\n"
                 "stricat:x:nu-e-numar:0::/:/bin/sh\n"
                 "prea:scurt:1\n"
                 "gol::999:999::/nonexistent:/usr/sbin/nologin\n",
                 encoding="utf-8")
    parsed = ac._read_passwd(str(f))
    assert [a["name"] for a in parsed] == ["root", "gol"]


def test_the_rule_is_registered():
    from sentinel.detect.rules import RULES
    assert "account_state_audit" in {r.__name__ for r in RULES}
    assert "account_created" in {r.__name__ for r in RULES}
